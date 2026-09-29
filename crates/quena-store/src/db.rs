use crate::Result;
use crossbeam_channel::{Receiver, Sender};
use parking_lot::Mutex;
use quena_model::{SessionDetail, SessionId};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

enum Op {
    Put(Arc<SessionDetail>),
    Delete(Vec<SessionId>),
    Clear,
    Flush(Sender<()>),
    Close(Sender<()>),
}

/// SQLite session database with a write-behind thread.
pub struct Db {
    tx: Sender<Op>,
    reader: Mutex<Connection>,
    /// Written but not yet committed.
    pending: Arc<Mutex<HashMap<SessionId, Option<Arc<SessionDetail>>>>>,
}

fn configure(c: &Connection) -> rusqlite::Result<()> {
    c.pragma_update(None, "journal_mode", "WAL")?;
    c.pragma_update(None, "synchronous", "NORMAL")?;
    c.busy_timeout(Duration::from_secs(5))?;
    Ok(())
}

pub(crate) fn encode(d: &SessionDetail) -> Vec<u8> {
    rmp_serde::to_vec_named(d).expect("serialize session")
}

pub(crate) fn decode(b: &[u8]) -> Option<SessionDetail> {
    rmp_serde::from_slice(b).map_err(|e| tracing::warn!("corrupt session row: {e}")).ok()
}

impl Db {
    pub fn open(path: &Path) -> Result<Db> {
        let w = Connection::open(path)?;
        configure(&w)?;
        w.execute_batch(
            "CREATE TABLE IF NOT EXISTS sessions (id INTEGER PRIMARY KEY, detail BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);",
        )?;
        let r = Connection::open(path)?;
        configure(&r)?;
        let (tx, rx) = crossbeam_channel::unbounded();
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let p2 = pending.clone();
        std::thread::Builder::new().name("quena-db".into()).spawn(move || writer(w, rx, p2)).expect("spawn db writer");
        Ok(Db { tx, reader: Mutex::new(r), pending })
    }

    pub fn put(&self, d: Arc<SessionDetail>) {
        self.pending.lock().insert(d.summary.id, Some(d.clone()));
        let _ = self.tx.send(Op::Put(d));
    }

    pub fn delete(&self, ids: Vec<SessionId>) {
        {
            let mut p = self.pending.lock();
            for id in &ids {
                p.insert(*id, None);
            }
        }
        let _ = self.tx.send(Op::Delete(ids));
    }

    pub fn clear(&self) {
        self.pending.lock().clear();
        let _ = self.tx.send(Op::Clear);
    }

    pub fn flush(&self) {
        let (tx, rx) = crossbeam_channel::bounded(1);
        if self.tx.send(Op::Flush(tx)).is_ok() {
            let _ = rx.recv_timeout(Duration::from_secs(30));
        }
    }

    pub fn close(&self) {
        let (tx, rx) = crossbeam_channel::bounded(1);
        if self.tx.send(Op::Close(tx)).is_ok() {
            let _ = rx.recv_timeout(Duration::from_secs(30));
        }
    }

    pub fn get(&self, id: SessionId) -> Result<Option<SessionDetail>> {
        if let Some(p) = self.pending.lock().get(&id) {
            return Ok(p.as_ref().map(|d| (**d).clone()));
        }
        let c = self.reader.lock();
        let row: Option<Vec<u8>> =
            c.query_row("SELECT detail FROM sessions WHERE id = ?1", params![id as i64], |r| r.get(0)).optional()?;
        Ok(row.and_then(|b| decode(&b)))
    }

    pub fn for_each(&self, mut f: impl FnMut(SessionDetail)) -> Result<()> {
        let c = self.reader.lock();
        let mut st = c.prepare("SELECT detail FROM sessions ORDER BY id")?;
        let mut rows = st.query([])?;
        while let Some(r) = rows.next()? {
            let b: Vec<u8> = r.get(0)?;
            if let Some(d) = decode(&b) {
                f(d);
            }
        }
        Ok(())
    }

    pub fn count(path: &Path) -> Result<u64> {
        let c = Connection::open(path)?;
        let n: i64 = c.query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))?;
        Ok(n as u64)
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        self.flush();
    }
}

fn writer(mut c: Connection, rx: Receiver<Op>, pending: Arc<Mutex<HashMap<SessionId, Option<Arc<SessionDetail>>>>>) {
    let mut batch: Vec<Op> = Vec::new();
    loop {
        let first = match rx.recv() {
            Ok(op) => op,
            Err(_) => return,
        };
        batch.push(first);
        // Collect a batch (≤ 2000 ops or 50 ms).
        let deadline = std::time::Instant::now() + Duration::from_millis(50);
        while batch.len() < 2000 {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match rx.recv_timeout(left) {
                Ok(op) => {
                    let barrier = matches!(op, Op::Flush(_) | Op::Close(_));
                    batch.push(op);
                    if barrier {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let mut acks = Vec::new();
        let mut close = None;
        let mut committed: Vec<(SessionId, Option<Arc<SessionDetail>>)> = Vec::new();
        let res = (|| -> rusqlite::Result<()> {
            let tx = c.transaction()?;
            {
                let mut put = tx.prepare_cached("INSERT OR REPLACE INTO sessions (id, detail) VALUES (?1, ?2)")?;
                let mut del = tx.prepare_cached("DELETE FROM sessions WHERE id = ?1")?;
                for op in batch.drain(..) {
                    match op {
                        Op::Put(d) => {
                            put.execute(params![d.summary.id as i64, encode(&d)])?;
                            committed.push((d.summary.id, Some(d)));
                        }
                        Op::Delete(ids) => {
                            for id in ids {
                                del.execute(params![id as i64])?;
                                committed.push((id, None));
                            }
                        }
                        Op::Clear => {
                            tx.execute("DELETE FROM sessions", [])?;
                        }
                        Op::Flush(a) => acks.push(a),
                        Op::Close(a) => close = Some(a),
                    }
                }
            }
            tx.commit()
        })();
        if let Err(e) = res {
            tracing::error!("session db write failed: {e}");
        }
        {
            // Drop pending entries that are now committed (unless superseded meanwhile).
            let mut p = pending.lock();
            for (id, d) in committed {
                if let Some(cur) = p.get(&id) {
                    let same = match (cur, &d) {
                        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                        (None, None) => true,
                        _ => false,
                    };
                    if same {
                        p.remove(&id);
                    }
                }
            }
        }
        for a in acks {
            let _ = a.send(());
        }
        if let Some(a) = close {
            drop(c);
            let _ = a.send(());
            return;
        }
    }
}
