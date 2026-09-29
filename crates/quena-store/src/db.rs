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

pub(crate) fn encode(d: &SessionDetail) -> std::result::Result<Vec<u8>, rmp_serde::encode::Error> {
    rmp_serde::to_vec_named(d)
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

    /// Visit all stored sessions. Undecodable rows are skipped (logged); a damaged
    /// table ends the scan with what could be read instead of failing the load.
    pub fn for_each(&self, mut f: impl FnMut(SessionDetail)) -> Result<()> {
        let c = self.reader.lock();
        let mut st = c.prepare("SELECT id, detail FROM sessions ORDER BY id")?;
        let mut rows = st.query([])?;
        let mut skipped = 0u64;
        loop {
            let r = match rows.next() {
                Ok(Some(r)) => r,
                Ok(None) => break,
                Err(e) => {
                    tracing::error!("session db damaged, stopping the scan: {e}");
                    break;
                }
            };
            match r.get::<_, Vec<u8>>(1) {
                Ok(b) => match decode(&b) {
                    Some(d) => f(d),
                    None => skipped += 1,
                },
                Err(e) => {
                    tracing::warn!(id = r.get::<_, i64>(0).ok(), "unreadable session row: {e}");
                    skipped += 1;
                }
            }
        }
        if skipped > 0 {
            tracing::warn!(skipped, "skipped unreadable session rows");
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

/// One row change, flattened from [`Op`] (kept for a retry when a write fails).
#[derive(Clone)]
enum Change {
    Put(Arc<SessionDetail>),
    Delete(SessionId),
    Clear,
}

fn apply(c: &mut Connection, changes: &[Change]) -> rusqlite::Result<()> {
    let tx = c.transaction()?;
    {
        let mut put = tx.prepare_cached("INSERT OR REPLACE INTO sessions (id, detail) VALUES (?1, ?2)")?;
        let mut del = tx.prepare_cached("DELETE FROM sessions WHERE id = ?1")?;
        for ch in changes {
            match ch {
                Change::Put(d) => {
                    let b = encode(d).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
                    put.execute(params![d.summary.id as i64, b])?;
                }
                Change::Delete(id) => {
                    del.execute(params![*id as i64])?;
                }
                Change::Clear => {
                    tx.execute("DELETE FROM sessions", [])?;
                }
            }
        }
    }
    tx.commit()
}

/// Drop changes superseded by a later change of the same id (or a later clear).
fn compact(changes: Vec<Change>) -> Vec<Change> {
    let start = changes.iter().rposition(|c| matches!(c, Change::Clear)).unwrap_or(0);
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<Change> = changes
        .into_iter()
        .skip(start)
        .rev()
        .filter(|c| match c {
            Change::Put(d) => seen.insert(d.summary.id),
            Change::Delete(id) => seen.insert(*id),
            Change::Clear => true,
        })
        .collect();
    out.reverse();
    out
}

/// Remove pending entries that are now committed (unless superseded meanwhile).
fn settle(pending: &Mutex<HashMap<SessionId, Option<Arc<SessionDetail>>>>, done: &[Change]) {
    let mut p = pending.lock();
    for ch in done {
        let (id, d) = match ch {
            Change::Put(d) => (d.summary.id, Some(d)),
            Change::Delete(id) => (*id, None),
            Change::Clear => continue,
        };
        if let Some(cur) = p.get(&id) {
            let same = match (cur, d) {
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

/// Failed batches are retried after this long (doubling up to `MAX_RETRY_DELAY`).
const RETRY_DELAY: Duration = Duration::from_millis(500);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

fn writer(mut c: Connection, rx: Receiver<Op>, pending: Arc<Mutex<HashMap<SessionId, Option<Arc<SessionDetail>>>>>) {
    let mut batch: Vec<Op> = Vec::new();
    // Changes of failed writes; they stay readable from `pending` meanwhile.
    let mut retry: Vec<Change> = Vec::new();
    let mut failures = 0u32;
    let mut disconnected = false;
    loop {
        if retry.is_empty() {
            match rx.recv() {
                Ok(op) => batch.push(op),
                Err(_) => return,
            }
        } else {
            let delay = RETRY_DELAY.saturating_mul(1 << failures.min(6)).min(MAX_RETRY_DELAY);
            match rx.recv_timeout(delay) {
                Ok(op) => batch.push(op),
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => disconnected = true,
            }
        }
        // Collect a batch (≤ 2000 ops or 50 ms).
        let deadline = std::time::Instant::now() + Duration::from_millis(50);
        while !batch.is_empty() && batch.len() < 2000 && !matches!(batch.last(), Some(Op::Flush(_) | Op::Close(_))) {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match rx.recv_timeout(left) {
                Ok(op) => batch.push(op),
                Err(_) => break,
            }
        }
        let mut acks = Vec::new();
        let mut close = None;
        let mut changes = std::mem::take(&mut retry);
        for op in batch.drain(..) {
            match op {
                Op::Put(d) => changes.push(Change::Put(d)),
                Op::Delete(ids) => changes.extend(ids.into_iter().map(Change::Delete)),
                Op::Clear => changes.push(Change::Clear),
                Op::Flush(a) => acks.push(a),
                Op::Close(a) => close = Some(a),
            }
        }
        if !changes.is_empty() {
            match apply(&mut c, &changes) {
                Ok(()) => {
                    failures = 0;
                    settle(&pending, &changes);
                }
                Err(e) => {
                    failures += 1;
                    let changes = compact(changes);
                    tracing::error!(changes = changes.len(), attempt = failures, "session db write failed, keeping the changes in memory: {e}");
                    // After repeated failures, isolate rows that fail on their own (e.g. too
                    // big) so they don't block everything else; they stay in `pending`.
                    if failures >= 3 {
                        let mut ok = 0usize;
                        let mut failed = Vec::new();
                        for ch in changes {
                            if apply(&mut c, std::slice::from_ref(&ch)).is_ok() {
                                ok += 1;
                                settle(&pending, std::slice::from_ref(&ch));
                            } else {
                                failed.push(ch);
                            }
                        }
                        if ok > 0 {
                            if !failed.is_empty() {
                                tracing::error!(rows = failed.len(), "session rows cannot be written; kept in memory for this run only");
                            }
                            failures = 0;
                        } else {
                            retry = failed;
                        }
                    } else {
                        retry = changes;
                    }
                }
            }
        }
        for a in acks {
            let _ = a.send(());
        }
        if close.is_some() || disconnected {
            if !retry.is_empty() {
                tracing::error!(changes = retry.len(), "session db closed with unwritten changes");
            }
            drop(c);
            if let Some(a) = close {
                let _ = a.send(());
            }
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_each_skips_corrupt_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sqlite");
        let db = Db::open(&path).unwrap();
        let mut d = SessionDetail::default();
        d.summary.id = 1;
        db.put(Arc::new(d.clone()));
        d.summary.id = 3;
        db.put(Arc::new(d));
        db.flush();
        let c = Connection::open(&path).unwrap();
        c.execute("INSERT INTO sessions (id, detail) VALUES (2, x'c1c1c1')", []).unwrap();
        // Garbage msgpack and a wrong column type.
        c.execute("INSERT INTO sessions (id, detail) VALUES (4, 42)", []).unwrap();
        let mut ids = vec![];
        db.for_each(|d| ids.push(d.summary.id)).unwrap();
        assert_eq!(ids, vec![1, 3]);
    }

    #[test]
    fn failed_write_keeps_pending_and_retries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sqlite");
        let db = Db::open(&path).unwrap();
        // Make writes fail: a trigger that aborts every insert.
        let c = Connection::open(&path).unwrap();
        c.execute_batch("CREATE TRIGGER nope BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT, 'disk says no'); END;").unwrap();
        let mut d = SessionDetail::default();
        d.summary.id = 7;
        db.put(Arc::new(d));
        db.flush();
        assert!(db.get(7).unwrap().is_some(), "entry lost after a failed write");
        c.execute_batch("DROP TRIGGER nope;").unwrap();
        // Retried on the next round.
        let t0 = std::time::Instant::now();
        while Db::count(&path).unwrap() == 0 && t0.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(Db::count(&path).unwrap(), 1);
    }

    #[test]
    fn recovery_never_deletes_unreadable_capture() {
        let root = tempfile::tempdir().unwrap();
        let bad = root.path().join("bad");
        std::fs::create_dir_all(&bad).unwrap();
        std::fs::write(bad.join("capture.lock"), "0").unwrap();
        std::fs::write(bad.join("session.sqlite"), vec![0xabu8; 8192]).unwrap();
        let empty = root.path().join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        std::fs::write(empty.join("capture.lock"), "0").unwrap();
        drop(Db::open(&empty.join("session.sqlite")).unwrap());
        let found = crate::find_recoverable(root.path());
        assert!(found.is_empty());
        assert!(bad.join("session.sqlite").exists(), "damaged capture was deleted");
        assert!(!empty.exists(), "empty capture should be cleaned up");
    }
}
