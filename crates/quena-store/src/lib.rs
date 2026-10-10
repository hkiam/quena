//! Capture store.
//!
//! A *capture* is a directory holding everything recorded in one Quena
//! session list:
//!
//! ```text
//! <capture>/
//!   session.sqlite   session details (heads, timers, flags, body refs)
//!   blobs/           raw bodies (append-only files)
//!   cache/           derived bodies (decoded, pretty)
//!   capture.lock     pid of the owning process (crash recovery)
//! ```
//!
//! Sessions in flight live in memory ([`LiveSession`]); finished sessions are
//! written behind to SQLite and only a small LRU of details stays in memory.

mod db;

use parking_lot::{Mutex, RwLock};
use quena_body::{Body, BodyConfig, BodyStore};
use quena_index::SessionIndex;
use quena_model::{SessionDetail, SessionId, SessionKind, SessionState, SessionSummary, now_us};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// A process-wide unique numbering token ([`Capture::numbering`]).
fn new_numbering() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}
use std::sync::{Arc, Weak};

pub use db::Db;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// How long a finished session waits for body recordings that are still running before it
/// is persisted anyway (a recording that never ends must not keep a session live forever).
const FINISH_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Default)]
struct FinishState {
    /// Body recordings still writing into this session.
    pending: u32,
    /// `finish` was called.
    requested: bool,
    /// Persisted (at most once).
    done: bool,
}

/// A session in flight (or any session opened for inspection).
pub struct LiveSession {
    pub id: SessionId,
    detail: RwLock<SessionDetail>,
    request_body: RwLock<Body>,
    response_body: RwLock<Body>,
    capture: Weak<Capture>,
    fin: Mutex<FinishState>,
}

/// Ends a session as aborted if it is dropped before the session was finished — the client
/// went away (hyper drops the handler future), a task panicked, or an error path forgot to
/// finish it. Without this such sessions would stay "in flight" forever.
/// [`disarm`](AbortOnDrop::disarm) it when another owner (a streaming body, a tunnel pump)
/// takes over finishing the session.
pub struct AbortOnDrop {
    live: Arc<LiveSession>,
    reason: &'static str,
    armed: bool,
}

impl AbortOnDrop {
    pub fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if !self.armed || self.live.fin.lock().requested {
            return;
        }
        let reason = self.reason;
        let panicking = std::thread::panicking();
        self.live.update(|d| {
            if !d.summary.state.is_final() {
                d.summary.state = SessionState::Aborted;
                d.summary.flags |= quena_model::flags::CLIENT_ABORTED;
                d.error.get_or_insert_with(|| if panicking { format!("{reason} (internal error)") } else { reason.to_string() });
            }
        });
        self.live.finish();
    }
}

/// Keeps a session from being persisted while one of its bodies is still being recorded.
/// Dropping the guard releases it (also when the recording is abandoned).
pub struct BodyHold(Arc<LiveSession>);

impl Drop for BodyHold {
    fn drop(&mut self) {
        let go = {
            let mut f = self.0.fin.lock();
            f.pending = f.pending.saturating_sub(1);
            if f.pending == 0 && f.requested && !f.done {
                f.done = true;
                true
            } else {
                false
            }
        };
        if go {
            self.0.persist();
        }
    }
}

impl LiveSession {
    pub fn detail(&self) -> SessionDetail {
        let mut d = self.detail.read().clone();
        d.request_body = self.request_body.read().to_ref();
        d.response_body = self.response_body.read().to_ref();
        d
    }

    pub fn summary(&self) -> SessionSummary {
        self.detail.read().summary.clone()
    }

    pub fn state(&self) -> SessionState {
        self.detail.read().summary.state
    }

    pub fn request_body(&self) -> Body {
        self.request_body.read().clone()
    }

    pub fn response_body(&self) -> Body {
        self.response_body.read().clone()
    }

    pub fn set_request_body(&self, b: Body) {
        *self.request_body.write() = b;
    }

    pub fn set_response_body(&self, b: Body) {
        *self.response_body.write() = b;
    }

    /// Mutate the detail; refreshes the summary and publishes it to the index.
    pub fn update(&self, f: impl FnOnce(&mut SessionDetail)) {
        let summary = {
            let mut d = self.detail.write();
            f(&mut d);
            d.request_body = self.request_body.read().to_ref_light();
            d.response_body = self.response_body.read().to_ref_light();
            d.refresh_summary();
            d.summary.request_body_len = self.request_body.read().wire_len();
            d.summary.response_body_len = self.response_body.read().wire_len();
            d.summary.clone()
        };
        if let Some(c) = self.capture.upgrade() {
            c.index.upsert(summary);
        }
    }

    /// Refresh body sizes in the list (called by the UI ticker for live sessions).
    pub fn refresh_sizes(&self) -> bool {
        let req = self.request_body.read().wire_len();
        let resp = self.response_body.read().wire_len();
        let changed = {
            let mut d = self.detail.write();
            let changed = d.summary.request_body_len != req || d.summary.response_body_len != resp;
            d.summary.request_body_len = req;
            d.summary.response_body_len = resp;
            changed
        };
        if changed {
            if let Some(c) = self.capture.upgrade() {
                c.index.update(self.id, |s| {
                    s.request_body_len = req;
                    s.response_body_len = resp;
                });
            }
        }
        changed
    }

    /// Guard that aborts and finishes the session if it is dropped unfinished.
    pub fn abort_on_drop(self: &Arc<Self>, reason: &'static str) -> AbortOnDrop {
        AbortOnDrop { live: self.clone(), reason, armed: true }
    }

    /// A body recording starts; the session is not persisted before the guard is dropped.
    pub fn hold(self: &Arc<Self>) -> BodyHold {
        self.fin.lock().pending += 1;
        BodyHold(self.clone())
    }

    /// Session finished: persist and drop from the live set, once all body recordings
    /// have completed (or after [`FINISH_GRACE`]).
    pub fn finish(self: &Arc<Self>) {
        let (go, wait) = {
            let mut f = self.fin.lock();
            f.requested = true;
            if f.done {
                (false, false)
            } else if f.pending == 0 {
                f.done = true;
                (true, false)
            } else {
                (false, true)
            }
        };
        if go {
            self.persist();
        } else if wait {
            if let Some(c) = self.capture.upgrade() {
                c.finish_later(self.clone());
            }
        }
    }

    /// Persist now, even if recordings are still pending (grace period expired).
    fn force_finish(&self) {
        let go = {
            let mut f = self.fin.lock();
            let go = !f.done;
            f.done = true;
            go
        };
        if go {
            tracing::warn!(target: "quena::store", "session {}: body recording did not finish in time; saved without waiting", self.id);
            self.persist();
        }
    }

    fn persist(&self) {
        if let Some(c) = self.capture.upgrade() {
            c.finish(self.id);
        }
    }
}

/// Extension to avoid cloning inline data on every summary update.
trait LightRef {
    fn to_ref_light(&self) -> quena_model::BodyRef;
}
impl LightRef for Body {
    fn to_ref_light(&self) -> quena_model::BodyRef {
        quena_model::BodyRef::Blob {
            id: self.id(),
            len: self.len(),
            wire_len: self.wire_len(),
            truncated: self.is_truncated(),
            complete: self.is_complete(),
        }
    }
}

struct Lru {
    map: HashMap<SessionId, Arc<SessionDetail>>,
    order: VecDeque<SessionId>,
    cap: usize,
}

impl Lru {
    fn get(&mut self, id: SessionId) -> Option<Arc<SessionDetail>> {
        self.map.get(&id).cloned()
    }
    fn put(&mut self, d: Arc<SessionDetail>) {
        let id = d.summary.id;
        if self.map.insert(id, d).is_none() {
            self.order.push_back(id);
            while self.order.len() > self.cap {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }
    fn remove(&mut self, id: SessionId) {
        self.map.remove(&id);
    }
    fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }
}

pub struct Capture {
    pub dir: PathBuf,
    pub bodies: Arc<BodyStore>,
    pub index: Arc<SessionIndex>,
    db: Db,
    live: RwLock<HashMap<SessionId, Arc<LiveSession>>>,
    cache: Mutex<Lru>,
    next_id: AtomicU64,
    /// Identifies the current numbering (unique in the process): it changes when numbering
    /// restarts, so session ids remembered earlier can be told apart from reused ones.
    numbering: AtomicU64,
    temporary: bool,
    /// Sessions waiting for their body recordings (see [`LiveSession::finish`]).
    deferred: Mutex<Option<std::sync::mpsc::Sender<(Arc<LiveSession>, std::time::Instant)>>>,
    /// Held while finished sessions are changed or removed, so a change never brings back a
    /// session removed meanwhile.
    edits: Mutex<()>,
}

/// A previous capture that was not closed cleanly.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverableCapture {
    pub dir: PathBuf,
    pub sessions: u64,
    pub modified: Option<i64>,
}

thread_local! {
    /// The archive an import on this thread loads (its sessions' source).
    static IMPORT_LABEL: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Run `f` with sessions inserted on this thread marked as loaded from `label`.
pub fn with_import_label<R>(label: &str, f: impl FnOnce() -> R) -> R {
    let before = IMPORT_LABEL.with(|l| l.replace(Some(label.to_string())));
    let r = f();
    IMPORT_LABEL.with(|l| *l.borrow_mut() = before);
    r
}

impl Capture {
    /// Open (or create) a capture directory.
    pub fn open(dir: impl Into<PathBuf>, body_cfg: BodyConfig, temporary: bool) -> Result<Arc<Capture>> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("capture.lock"), std::process::id().to_string())?;
        let bodies = BodyStore::open(&dir, body_cfg)?;
        let db = Db::open(&dir.join("session.sqlite"))?;
        let index = SessionIndex::new();
        let cap = Arc::new(Capture {
            dir,
            bodies,
            index,
            db,
            live: RwLock::new(HashMap::new()),
            cache: Mutex::new(Lru { map: HashMap::new(), order: VecDeque::new(), cap: 4096 }),
            next_id: AtomicU64::new(1),
            numbering: AtomicU64::new(new_numbering()),
            temporary,
            deferred: Mutex::new(None),
            edits: Mutex::new(()),
        });
        cap.load_existing()?;
        Ok(cap)
    }

    fn load_existing(&self) -> Result<()> {
        let mut max_id = 0;
        let mut max_body = 0;
        self.db.for_each(|d| {
            max_id = max_id.max(d.summary.id);
            for b in [&d.request_body, &d.response_body] {
                if let quena_model::BodyRef::Inline { id, .. } | quena_model::BodyRef::Blob { id, .. } = b {
                    max_body = max_body.max(*id);
                }
            }
            let mut s = d.summary.clone();
            // Captures of older versions have no grouping keys yet.
            if s.conn == 0 {
                s.conn = d.connection.client_conn_id.unwrap_or(0);
            }
            if s.trace.is_empty() {
                s.trace = quena_model::correlation::trace_id(&d.request.headers);
            }
            if s.session.is_empty() {
                s.session = quena_model::correlation::session_key(&d.request.headers);
            }
            if s.via.is_empty() {
                s.via = d.via();
            }
            if !s.state.is_final() {
                s.state = SessionState::Aborted;
            }
            self.index.upsert(s);
        })?;
        self.next_id.store(max_id.saturating_add(1), Ordering::Relaxed);
        self.bodies.bump_id(max_body);
        self.index.tick();
        Ok(())
    }

    pub fn is_temporary(&self) -> bool {
        self.temporary
    }

    pub fn next_id(&self) -> SessionId {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Reset numbering (restarts at 1 after clearing).
    pub fn reset_numbering(&self) {
        self.next_id.store(1, Ordering::Relaxed);
        self.numbering.store(new_numbering(), Ordering::Relaxed);
    }

    /// The current numbering: equal values mean that the same ids name the same sessions.
    pub fn numbering(&self) -> u64 {
        self.numbering.load(Ordering::Relaxed)
    }

    /// Start a new session; it is visible in the list immediately.
    pub fn begin(self: &Arc<Self>, kind: SessionKind, init: impl FnOnce(&mut SessionDetail)) -> Arc<LiveSession> {
        let id = self.next_id();
        let mut d = SessionDetail::default();
        d.summary.id = id;
        d.summary.kind = kind;
        d.summary.started_at = now_us();
        init(&mut d);
        d.refresh_summary();
        let live = Arc::new(LiveSession {
            id,
            detail: RwLock::new(d.clone()),
            request_body: RwLock::new(Body::empty()),
            response_body: RwLock::new(Body::empty()),
            capture: Arc::downgrade(self),
            fin: Mutex::new(FinishState::default()),
        });
        self.live.write().insert(id, live.clone());
        self.index.upsert(d.summary);
        live
    }

    /// Insert a complete session (import, composer result…).
    pub fn insert(self: &Arc<Self>, mut d: SessionDetail, req: Body, resp: Body) -> SessionId {
        let id = self.next_id();
        d.summary.id = id;
        if let Some(label) = IMPORT_LABEL.with(|l| l.borrow().clone()) {
            d.summary.archive = label;
        }
        d.request_body = req.to_ref();
        d.response_body = resp.to_ref();
        let mut sum_req = d.request_body.wire_len();
        let mut sum_resp = d.response_body.wire_len();
        d.refresh_summary();
        if sum_req == 0 {
            sum_req = req.wire_len();
        }
        if sum_resp == 0 {
            sum_resp = resp.wire_len();
        }
        d.summary.request_body_len = sum_req;
        d.summary.response_body_len = sum_resp;
        self.index.upsert(d.summary.clone());
        let d = Arc::new(d);
        self.cache.lock().put(d.clone());
        self.db.put(d);
        id
    }

    pub fn live(&self, id: SessionId) -> Option<Arc<LiveSession>> {
        self.live.read().get(&id).cloned()
    }

    pub fn live_sessions(&self) -> Vec<Arc<LiveSession>> {
        self.live.read().values().cloned().collect()
    }

    /// Force-persist `live` after the grace period unless its recordings finish first.
    /// One background thread serves all deferred sessions (deadlines are FIFO).
    fn finish_later(&self, live: Arc<LiveSession>) {
        let deadline = std::time::Instant::now() + FINISH_GRACE;
        let mut tx = self.deferred.lock();
        if tx.as_ref().is_none_or(|t| t.send((live.clone(), deadline)).is_err()) {
            let (t, rx) = std::sync::mpsc::channel::<(Arc<LiveSession>, std::time::Instant)>();
            let spawned = std::thread::Builder::new().name("quena-finish".into()).spawn(move || {
                while let Ok((l, at)) = rx.recv() {
                    let now = std::time::Instant::now();
                    if at > now {
                        std::thread::sleep(at - now);
                    }
                    l.force_finish();
                }
            });
            if spawned.is_err() {
                live.force_finish();
                return;
            }
            let _ = t.send((live, deadline));
            *tx = Some(t);
        }
    }

    fn finish(&self, id: SessionId) {
        // Not at the same time as `remove`: a session removed meanwhile stays removed.
        let _edits = self.edits.lock();
        let Some(live) = self.live.read().get(&id).cloned() else { return };
        let mut d = live.detail();
        d.refresh_summary();
        d.summary.request_body_len = live.request_body().wire_len();
        d.summary.response_body_len = live.response_body().wire_len();
        self.index.upsert(d.summary.clone());
        let d = Arc::new(d);
        // In the cache before it leaves the live table: `detail` always finds the session.
        self.cache.lock().put(d.clone());
        self.live.write().remove(&id);
        self.db.put(d);
    }

    /// Full detail of a session (live or persisted).
    pub fn detail(&self, id: SessionId) -> Option<SessionDetail> {
        if let Some(l) = self.live(id) {
            return Some(l.detail());
        }
        // The cache's guard ends here: the index is asked without it (a list filter reads
        // details while it holds the index).
        let hit = self.cache.lock().get(id);
        if let Some(d) = hit {
            let mut d = (*d).clone();
            if let Some(s) = self.index.get(id) {
                d.summary = s; // marks/comments live in the index
            }
            return Some(d);
        }
        let d = self.db.get(id).ok().flatten()?;
        let d = Arc::new(d);
        self.cache.lock().put(d.clone());
        let mut d = (*d).clone();
        if let Some(s) = self.index.get(id) {
            d.summary = s;
        }
        Some(d)
    }

    /// [`Capture::detail`] as stored, without the summary from the index (marks and comments
    /// may be older): safe to call while the index is busy, e.g. from a list filter.
    pub fn detail_stored(&self, id: SessionId) -> Option<SessionDetail> {
        if let Some(l) = self.live(id) {
            return Some(l.detail());
        }
        let hit = self.cache.lock().get(id);
        if let Some(d) = hit {
            return Some((*d).clone());
        }
        let d = Arc::new(self.db.get(id).ok().flatten()?);
        self.cache.lock().put(d.clone());
        Some((*d).clone())
    }

    /// [`Capture::detail_stored`] that leaves the detail cache as it is (reading many sessions
    /// once, e.g. for statistics, would push out the ones the inspector needs).
    pub fn detail_peek(&self, id: SessionId) -> Option<SessionDetail> {
        if let Some(l) = self.live(id) {
            return Some(l.detail());
        }
        let hit = self.cache.lock().get(id);
        if let Some(d) = hit {
            return Some((*d).clone());
        }
        self.db.get(id).ok().flatten()
    }

    /// [`Capture::bodies_of`] without the index (see [`Capture::detail_stored`]).
    pub fn bodies_stored(&self, id: SessionId) -> Option<(SessionDetail, Body, Body)> {
        if let Some(l) = self.live(id) {
            return Some((l.detail(), l.request_body(), l.response_body()));
        }
        let d = self.detail_stored(id)?;
        let (a, b) = (self.bodies.open_ref(&d.request_body), self.bodies.open_ref(&d.response_body));
        Some((d, a, b))
    }

    /// Bodies of a session.
    pub fn bodies_of(&self, id: SessionId) -> Option<(Body, Body)> {
        if let Some(l) = self.live(id) {
            return Some((l.request_body(), l.response_body()));
        }
        let d = self.detail(id)?;
        Some((self.bodies.open_ref(&d.request_body), self.bodies.open_ref(&d.response_body)))
    }

    /// Persist UI-level changes (mark, comment) of a finished session.
    pub fn update_summary(&self, id: SessionId, f: impl Fn(&mut SessionSummary)) {
        if let Some(l) = self.live(id) {
            l.update(|d| f(&mut d.summary));
            return;
        }
        self.index.update(id, &f);
        if let Some(mut d) = self.detail(id) {
            f(&mut d.summary);
            let d = Arc::new(d);
            self.cache.lock().put(d.clone());
            self.db.put(d);
        }
    }

    /// Replace a finished session's detail (e.g. after tampering or re-import).
    pub fn replace_detail(&self, d: SessionDetail) {
        self.index.upsert(d.summary.clone());
        let d = Arc::new(d);
        self.cache.lock().remove(d.summary.id);
        self.cache.lock().put(d.clone());
        self.db.put(d);
    }

    /// Change a finished session that is still there (else `false`).
    pub fn update_detail(&self, id: SessionId, f: impl FnOnce(&mut SessionDetail)) -> bool {
        let _edits = self.edits.lock();
        if self.index.get(id).is_none() {
            return false;
        }
        let Some(mut d) = self.detail(id) else { return false };
        f(&mut d);
        d.refresh_summary();
        self.replace_detail(d);
        true
    }

    /// Remove sessions and their bodies.
    pub fn remove(&self, ids: &HashSet<SessionId>) {
        let _edits = self.edits.lock();
        let removed = self.index.remove(ids);
        let mut bodies = Vec::new();
        for id in &removed {
            if let Some((a, b)) = self.bodies_of(*id) {
                bodies.push(a);
                bodies.push(b);
            }
            self.live.write().remove(id);
            self.cache.lock().remove(*id);
        }
        self.db.delete(removed);
        for b in bodies {
            self.bodies.delete(&b);
        }
    }

    /// Remove everything (keeps in-flight sessions running but hidden).
    pub fn clear(&self) {
        let _edits = self.edits.lock();
        self.index.clear();
        self.cache.lock().clear();
        let live_ids: Vec<SessionId> = self.live.read().keys().copied().collect();
        self.db.clear();
        if live_ids.is_empty() {
            self.bodies.clear();
        }
        self.live.write().clear();
    }

    pub fn flush(&self) {
        self.db.flush();
    }

    pub fn session_count(&self) -> usize {
        self.index.len()
    }

    /// Mark as closed cleanly; delete if temporary.
    pub fn close(&self, delete_if_temp: bool) {
        self.db.flush();
        let _ = std::fs::remove_file(self.dir.join("capture.lock"));
        if self.temporary && delete_if_temp {
            self.db.close();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

fn pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        unsafe extern "C" {
            fn kill(pid: i32, sig: i32) -> i32;
        }
        unsafe { kill(pid as i32, 0) == 0 }
    }
    #[cfg(windows)]
    {
        unsafe extern "system" {
            fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut std::ffi::c_void;
            fn GetExitCodeProcess(h: *mut std::ffi::c_void, code: *mut u32) -> i32;
            fn CloseHandle(h: *mut std::ffi::c_void) -> i32;
        }
        const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
        const STILL_ACTIVE: u32 = 259;
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return false;
            }
            let mut code = 0u32;
            let ok = GetExitCodeProcess(h, &mut code) != 0 && code == STILL_ACTIVE;
            CloseHandle(h);
            ok
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        false
    }
}

/// Find temporary captures that were not closed cleanly.
pub fn find_recoverable(captures_root: &Path) -> Vec<RecoverableCapture> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(captures_root) else { return out };
    for e in rd.flatten() {
        let dir = e.path();
        let lock = dir.join("capture.lock");
        let Ok(pid) = std::fs::read_to_string(&lock) else { continue };
        let pid: u32 = pid.trim().parse().unwrap_or(0);
        if pid == std::process::id() || (pid != 0 && pid_alive(pid)) {
            continue;
        }
        let db = dir.join("session.sqlite");
        // No database at all: nothing was ever recorded. A database that cannot be
        // counted may be damaged but still hold sessions – never delete it here.
        let sessions = if !db.exists() {
            0
        } else {
            match Db::count(&db) {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(dir = %dir.display(), "capture left behind by a crash cannot be read, leaving it alone: {e}");
                    continue;
                }
            }
        };
        let modified = std::fs::metadata(&db)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64);
        if sessions == 0 {
            let _ = std::fs::remove_dir_all(&dir);
            continue;
        }
        out.push(RecoverableCapture { dir, sessions, modified });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use quena_model::{RequestHead, ResponseHead};

    #[test]
    fn finish_waits_for_pending_body_recordings() {
        let dir = tempfile::tempdir().unwrap();
        let cap = Capture::open(dir.path().join("cap"), BodyConfig::default(), true).unwrap();
        let s = cap.begin(SessionKind::Http, |d| {
            d.request = RequestHead { method: "POST".into(), url: "http://a/x".into(), ..Default::default() };
        });
        let hold = s.hold();
        // The response is complete before the request body recording finished.
        s.finish();
        assert!(cap.live(s.id).is_some(), "persisted before the request body was recorded");
        let mut w = cap.bodies.writer();
        w.write(b"late request body").unwrap();
        s.set_request_body(w.finish());
        drop(hold);
        assert!(cap.live(s.id).is_none());
        let (req, _) = cap.bodies_of(s.id).unwrap();
        assert_eq!(req.read_range(0, 100).unwrap(), b"late request body");
        // A second finish is a no-op.
        s.finish();
    }

    #[test]
    fn lifecycle_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cap");
        {
            let cap = Capture::open(&path, BodyConfig::default(), true).unwrap();
            let s = cap.begin(SessionKind::Http, |d| {
                d.request = RequestHead { method: "GET".into(), url: "http://a/x".into(), ..Default::default() };
            });
            let mut w = cap.bodies.writer();
            w.write(b"hello").unwrap();
            s.set_response_body(w.finish());
            s.update(|d| {
                d.response = Some(ResponseHead { status: 200, reason: "OK".into(), ..Default::default() });
                d.summary.state = SessionState::Done;
            });
            s.finish();
            cap.index.tick();
            assert_eq!(cap.index.view_len(), 1);
            let d = cap.detail(s.id).unwrap();
            assert_eq!(d.summary.status, 200);
            cap.update_summary(s.id, |x| x.comment = "hi".into());
            cap.flush();
            // Simulate crash: do not close.
        }
        let cap = Capture::open(&path, BodyConfig::default(), true).unwrap();
        assert_eq!(cap.index.view_len(), 1);
        let d = cap.detail(1).unwrap();
        assert_eq!(d.summary.comment, "hi");
        let (_, resp) = cap.bodies_of(1).unwrap();
        assert_eq!(resp.read_range(0, 100).unwrap(), b"hello");
        assert_eq!(cap.next_id(), 2);
        cap.remove(&[1].into_iter().collect());
        cap.flush();
        assert_eq!(cap.index.view_len(), 0);
        assert!(cap.detail(1).is_none());
    }
}
