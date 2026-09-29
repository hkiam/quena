//! Recorder: writes body chunks to the store on dedicated threads so that
//! disk I/O never runs on the forwarding runtime (PLAN.md §2.1). Queues are
//! bounded; when a queue is full the chunk is counted but not stored and the
//! body is marked truncated ("Traffic forwarding > Recording").

use bytes::Bytes;
use crossbeam_channel::{Receiver, Sender, TrySendError};
use quena_body::{Body, BodyWriter};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub type RecKey = u64;
pub type OnDone = Box<dyn FnOnce(Body, bool) + Send>;

enum Msg {
    Open { key: RecKey, writer: BodyWriter, done: OnDone },
    Chunk { key: RecKey, data: Bytes },
    End { key: RecKey, dropped: u64, aborted: bool },
}

struct Inner {
    workers: Vec<Sender<Msg>>,
    next: AtomicU64,
    lossless: AtomicBool,
    dropped: parking_lot::Mutex<HashMap<RecKey, u64>>,
}

#[derive(Clone)]
pub struct Recorder(Arc<Inner>);

impl Recorder {
    pub fn new(threads: usize) -> Recorder {
        let mut workers = Vec::new();
        for i in 0..threads.max(1) {
            let (tx, rx) = crossbeam_channel::bounded::<Msg>(16 * 1024);
            std::thread::Builder::new().name(format!("quena-rec-{i}")).spawn(move || worker(rx)).expect("spawn recorder");
            workers.push(tx);
        }
        Recorder(Arc::new(Inner { workers, next: AtomicU64::new(1), lossless: AtomicBool::new(false), dropped: Default::default() }))
    }

    pub fn set_lossless(&self, on: bool) {
        self.0.lossless.store(on, Ordering::Relaxed);
    }

    fn tx(&self, key: RecKey) -> &Sender<Msg> {
        &self.0.workers[(key as usize) % self.0.workers.len()]
    }

    /// Start recording into `writer`; `done` runs on the recorder thread once complete.
    pub fn open(&self, writer: BodyWriter, done: OnDone) -> RecKey {
        let key = self.0.next.fetch_add(1, Ordering::Relaxed);
        // Open must never be dropped.
        let _ = self.tx(key).send(Msg::Open { key, writer, done });
        key
    }

    pub fn chunk(&self, key: RecKey, data: Bytes) {
        let len = data.len() as u64;
        if self.0.lossless.load(Ordering::Relaxed) {
            let _ = self.tx(key).send(Msg::Chunk { key, data });
            return;
        }
        match self.tx(key).try_send(Msg::Chunk { key, data }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                *self.0.dropped.lock().entry(key).or_default() += len;
            }
        }
    }

    pub fn end(&self, key: RecKey, aborted: bool) {
        let dropped = self.0.dropped.lock().remove(&key).unwrap_or(0);
        let _ = self.tx(key).send(Msg::End { key, dropped, aborted });
    }
}

fn worker(rx: Receiver<Msg>) {
    let mut open: HashMap<RecKey, (BodyWriter, OnDone)> = HashMap::new();
    while let Ok(m) = rx.recv() {
        match m {
            Msg::Open { key, writer, done } => {
                open.insert(key, (writer, done));
            }
            Msg::Chunk { key, data } => {
                if let Some((w, _)) = open.get_mut(&key) {
                    if let Err(e) = w.write(&data) {
                        tracing::warn!(target: "quena::proxy", "recording failed: {e}");
                        w.add_dropped(data.len() as u64);
                    }
                }
            }
            Msg::End { key, dropped, aborted } => {
                if let Some((mut w, done)) = open.remove(&key) {
                    w.add_dropped(dropped);
                    let body = w.finish();
                    done(body, aborted);
                }
            }
        }
    }
}
