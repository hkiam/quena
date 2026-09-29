//! Ring buffer behind the Log tab, fed by a tracing layer.

use parking_lot::Mutex;
use serde::Serialize;
use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    pub seq: u64,
    pub time: i64,
    pub level: String,
    pub target: String,
    pub message: String,
}

pub struct LogBuffer {
    entries: Mutex<VecDeque<LogEntry>>,
    seq: AtomicU64,
    cap: usize,
}

impl LogBuffer {
    pub fn new(cap: usize) -> Arc<LogBuffer> {
        Arc::new(LogBuffer { entries: Mutex::new(VecDeque::new()), seq: AtomicU64::new(0), cap })
    }

    pub fn push(&self, level: &str, target: &str, message: String) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let e = LogEntry { seq, time: quena_model::now_us(), level: level.into(), target: target.into(), message };
        let mut q = self.entries.lock();
        q.push_back(e);
        while q.len() > self.cap {
            q.pop_front();
        }
    }

    pub fn last_seq(&self) -> u64 {
        self.seq.load(Ordering::Relaxed)
    }

    pub fn since(&self, seq: u64) -> Vec<LogEntry> {
        self.entries.lock().iter().filter(|e| e.seq > seq).cloned().collect()
    }

    pub fn clear(&self) {
        self.entries.lock().clear();
    }
}

pub struct LogLayer(pub Arc<LogBuffer>);

struct MsgVisitor(String);
impl Visit for MsgVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.0, "{value:?}");
        } else {
            let _ = write!(self.0, " {}={value:?}", field.name());
        }
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.0.push_str(value);
        } else {
            let _ = write!(self.0, " {}={value}", field.name());
        }
    }
}

impl<S: Subscriber> Layer<S> for LogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let ours = meta.target().starts_with("quena");
        let lvl = *meta.level();
        if !(lvl <= Level::WARN || (ours && lvl <= Level::INFO)) {
            return;
        }
        let mut v = MsgVisitor(String::new());
        event.record(&mut v);
        self.0.push(lvl.as_str(), meta.target(), v.0);
    }
}
