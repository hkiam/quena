//! Job manager.
//!
//! Everything that may take longer than a few milliseconds runs as a job on a
//! dedicated worker pool – never on the proxy runtime and never on the UI
//! thread. Jobs have a key for de-duplication, a priority, progress and a
//! cancel flag.

use crossbeam_channel::{Receiver, Sender, select};
use parking_lot::Mutex;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub type JobId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Priority {
    /// Triggered by a user interaction and blocking visible content.
    Interactive,
    /// Everything else (exports, indexing of invisible sessions …).
    Background,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum JobStatus {
    Queued,
    Running,
    Done,
    Failed,
    Cancelled,
}

#[derive(Debug)]
pub struct JobState {
    pub id: JobId,
    pub key: String,
    pub title: String,
    pub priority: Priority,
    done: AtomicU64,
    total: AtomicU64,
    cancel: AtomicBool,
    status: Mutex<JobStatus>,
    error: Mutex<Option<String>>,
    started: Mutex<Option<Instant>>,
    finished: Mutex<Option<Instant>>,
    /// Whether the job should be listed in the UI.
    pub visible: bool,
}

impl JobState {
    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
    pub fn set_progress(&self, done: u64, total: u64) {
        self.done.store(done, Ordering::Relaxed);
        self.total.store(total, Ordering::Relaxed);
    }
    pub fn status(&self) -> JobStatus {
        *self.status.lock()
    }
    pub fn snapshot(&self) -> JobInfo {
        let started = *self.started.lock();
        let finished = *self.finished.lock();
        JobInfo {
            id: self.id,
            key: self.key.clone(),
            title: self.title.clone(),
            status: self.status(),
            done: self.done.load(Ordering::Relaxed),
            total: self.total.load(Ordering::Relaxed),
            error: self.error.lock().clone(),
            elapsed_ms: started.map(|s| finished.unwrap_or_else(Instant::now).duration_since(s).as_millis() as u64),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct JobInfo {
    pub id: JobId,
    pub key: String,
    pub title: String,
    pub status: JobStatus,
    pub done: u64,
    pub total: u64,
    pub error: Option<String>,
    pub elapsed_ms: Option<u64>,
}

/// Handle passed to a running job.
#[derive(Clone)]
pub struct JobCtx(Arc<JobState>);

impl JobCtx {
    pub fn cancelled(&self) -> bool {
        self.0.cancelled()
    }
    pub fn progress(&self, done: u64, total: u64) {
        self.0.set_progress(done, total)
    }
    pub fn id(&self) -> JobId {
        self.0.id
    }
    pub fn state(&self) -> &Arc<JobState> {
        &self.0
    }
}

type Work = Box<dyn FnOnce(&JobCtx) -> Result<(), String> + Send>;

struct Task {
    state: Arc<JobState>,
    work: Work,
}

#[derive(Default)]
struct Registry {
    jobs: HashMap<JobId, Arc<JobState>>,
    by_key: HashMap<String, JobId>,
    order: Vec<JobId>,
}

/// Why [`JobManager::wait`] returned without a final state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WaitError {
    /// No job with this id (never submitted, or already removed).
    UnknownJob,
    /// The job had not finished when the timeout passed.
    Timeout,
}

impl std::fmt::Display for WaitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            WaitError::UnknownJob => "unknown job",
            WaitError::Timeout => "timed out",
        })
    }
}

impl std::error::Error for WaitError {}

pub struct JobManager {
    next: AtomicU64,
    reg: Mutex<Registry>,
    hi: Sender<Task>,
    lo: Sender<Task>,
    /// Incremented on every state change (cheap change detection for the UI ticker).
    generation: Arc<AtomicU64>,
    keep_finished: usize,
}

impl JobManager {
    /// `workers` threads; at least one worker only takes interactive jobs so
    /// long background jobs can never starve interactive ones.
    pub fn new(workers: usize) -> Arc<JobManager> {
        let (hi_tx, hi_rx) = crossbeam_channel::unbounded::<Task>();
        let (lo_tx, lo_rx) = crossbeam_channel::unbounded::<Task>();
        let generation = Arc::new(AtomicU64::new(0));
        let workers = workers.max(2);
        for i in 0..workers {
            let hi = hi_rx.clone();
            let lo = lo_rx.clone();
            let generation = generation.clone();
            let interactive_only = i == 0;
            std::thread::Builder::new()
                .name(format!("quena-job-{i}"))
                .spawn(move || worker(hi, lo, interactive_only, generation))
                .expect("spawn job worker");
        }
        Arc::new(JobManager {
            next: AtomicU64::new(1),
            reg: Mutex::new(Registry::default()),
            hi: hi_tx,
            lo: lo_tx,
            generation,
            keep_finished: 200,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    /// Submit a job. If a job with the same key is queued or running, its id
    /// is returned instead (de-duplication).
    pub fn submit<F>(&self, key: impl Into<String>, title: impl Into<String>, priority: Priority, visible: bool, f: F) -> JobId
    where
        F: FnOnce(&JobCtx) -> Result<(), String> + Send + 'static,
    {
        let key = key.into();
        let mut reg = self.reg.lock();
        if let Some(id) = reg.by_key.get(&key) {
            if let Some(j) = reg.jobs.get(id) {
                if matches!(j.status(), JobStatus::Queued | JobStatus::Running) {
                    return *id;
                }
            }
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let state = Arc::new(JobState {
            id,
            key: key.clone(),
            title: title.into(),
            priority,
            done: AtomicU64::new(0),
            total: AtomicU64::new(0),
            cancel: AtomicBool::new(false),
            status: Mutex::new(JobStatus::Queued),
            error: Mutex::new(None),
            started: Mutex::new(None),
            finished: Mutex::new(None),
            visible,
        });
        reg.jobs.insert(id, state.clone());
        reg.by_key.insert(key, id);
        reg.order.push(id);
        self.gc(&mut reg);
        drop(reg);
        let task = Task { state, work: Box::new(f) };
        let tx = if priority == Priority::Interactive { &self.hi } else { &self.lo };
        let _ = tx.send(task);
        self.generation.fetch_add(1, Ordering::Relaxed);
        id
    }

    fn gc(&self, reg: &mut Registry) {
        let finished: Vec<JobId> = reg
            .order
            .iter()
            .copied()
            .filter(|id| reg.jobs.get(id).is_some_and(|j| !matches!(j.status(), JobStatus::Queued | JobStatus::Running)))
            .collect();
        if finished.len() > self.keep_finished {
            let drop_n = finished.len() - self.keep_finished;
            for id in &finished[..drop_n] {
                if let Some(j) = reg.jobs.remove(id) {
                    if reg.by_key.get(&j.key) == Some(id) {
                        reg.by_key.remove(&j.key);
                    }
                }
            }
            reg.order.retain(|id| reg.jobs.contains_key(id));
        }
    }

    /// Block until job `id` has finished (done, failed or cancelled) or `timeout` passed;
    /// its final state. A timeout too large for the clock means no deadline.
    pub fn wait(&self, id: JobId, timeout: Duration) -> Result<JobInfo, WaitError> {
        let job = self.get(id).ok_or(WaitError::UnknownJob)?;
        let until = Instant::now().checked_add(timeout);
        loop {
            if matches!(job.status(), JobStatus::Done | JobStatus::Failed | JobStatus::Cancelled) {
                return Ok(job.snapshot());
            }
            if until.is_some_and(|u| Instant::now() >= u) {
                return Err(WaitError::Timeout);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn get(&self, id: JobId) -> Option<Arc<JobState>> {
        self.reg.lock().jobs.get(&id).cloned()
    }

    pub fn by_key(&self, key: &str) -> Option<Arc<JobState>> {
        let reg = self.reg.lock();
        reg.by_key.get(key).and_then(|id| reg.jobs.get(id)).cloned()
    }

    pub fn cancel(&self, id: JobId) -> bool {
        if let Some(j) = self.get(id) {
            j.cancel();
            self.generation.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Cancel all jobs whose key starts with `prefix` (e.g. "search:" on new input).
    pub fn cancel_prefix(&self, prefix: &str) {
        for j in self.reg.lock().jobs.values() {
            if j.key.starts_with(prefix) && matches!(j.status(), JobStatus::Queued | JobStatus::Running) {
                j.cancel();
            }
        }
        self.generation.fetch_add(1, Ordering::Relaxed);
    }

    /// Visible jobs, newest first: running/queued plus recently finished.
    pub fn list(&self) -> Vec<JobInfo> {
        let reg = self.reg.lock();
        reg.order
            .iter()
            .rev()
            .filter_map(|id| reg.jobs.get(id))
            .filter(|j| j.visible)
            .take(50)
            .map(|j| j.snapshot())
            .collect()
    }

    pub fn active_count(&self) -> usize {
        self.reg
            .lock()
            .jobs
            .values()
            .filter(|j| j.visible && matches!(j.status(), JobStatus::Queued | JobStatus::Running))
            .count()
    }
}

fn worker(hi: Receiver<Task>, lo: Receiver<Task>, interactive_only: bool, generation: Arc<AtomicU64>) {
    loop {
        // Prefer interactive work.
        let task = match hi.try_recv() {
            Ok(t) => t,
            Err(_) if interactive_only => match hi.recv() {
                Ok(t) => t,
                Err(_) => return,
            },
            Err(_) => select! {
                recv(hi) -> t => match t { Ok(t) => t, Err(_) => return },
                recv(lo) -> t => match t { Ok(t) => t, Err(_) => return },
            },
        };
        run(task, &generation);
    }
}

fn run(task: Task, generation: &AtomicU64) {
    let st = task.state;
    if st.cancelled() {
        *st.status.lock() = JobStatus::Cancelled;
        generation.fetch_add(1, Ordering::Relaxed);
        return;
    }
    *st.status.lock() = JobStatus::Running;
    *st.started.lock() = Some(Instant::now());
    generation.fetch_add(1, Ordering::Relaxed);
    let ctx = JobCtx(st.clone());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (task.work)(&ctx)));
    let status = match result {
        Ok(Ok(())) if st.cancelled() => JobStatus::Cancelled,
        Ok(Ok(())) => JobStatus::Done,
        Ok(Err(_)) if st.cancelled() => JobStatus::Cancelled,
        Ok(Err(e)) => {
            *st.error.lock() = Some(e);
            JobStatus::Failed
        }
        Err(p) => {
            let msg = p
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "panic".into());
            tracing::error!(job = st.id, "job panicked: {msg}");
            *st.error.lock() = Some(format!("internal error: {msg}"));
            JobStatus::Failed
        }
    };
    *st.status.lock() = status;
    *st.finished.lock() = Some(Instant::now());
    generation.fetch_add(1, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wait(m: &JobManager, id: JobId) -> JobStatus {
        m.wait(id, Duration::from_millis(2500)).expect("timeout").status
    }

    #[test]
    fn runs_and_dedups() {
        let m = JobManager::new(2);
        let a = m.submit("k", "t", Priority::Background, true, |_| {
            std::thread::sleep(Duration::from_millis(50));
            Ok(())
        });
        let b = m.submit("k", "t", Priority::Background, true, |_| Ok(()));
        assert_eq!(a, b);
        assert_eq!(wait(&m, a), JobStatus::Done);
    }

    #[test]
    fn wait_unknown_timeout_and_unbounded() {
        let m = JobManager::new(1);
        assert_eq!(m.wait(9999, Duration::from_millis(10)).unwrap_err(), WaitError::UnknownJob);
        let slow = m.submit("slow", "t", Priority::Background, true, |ctx| {
            while !ctx.cancelled() {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(())
        });
        assert_eq!(m.wait(slow, Duration::from_millis(30)).unwrap_err(), WaitError::Timeout);
        m.cancel(slow);
        // A timeout beyond the clock's range is no deadline, not a panic.
        let quick = m.submit("quick", "t", Priority::Background, true, |_| Ok(()));
        assert_eq!(m.wait(quick, Duration::MAX).unwrap().status, JobStatus::Done);
    }

    #[test]
    fn cancel_and_panic() {
        let m = JobManager::new(2);
        let a = m.submit("c", "t", Priority::Interactive, true, |ctx| {
            while !ctx.cancelled() {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err("stopped".into())
        });
        std::thread::sleep(Duration::from_millis(20));
        m.cancel(a);
        assert_eq!(wait(&m, a), JobStatus::Cancelled);
        let p = m.submit("p", "t", Priority::Interactive, true, |_| panic!("boom"));
        assert_eq!(wait(&m, p), JobStatus::Failed);
        assert!(m.get(p).unwrap().snapshot().error.unwrap().contains("boom"));
    }

    #[test]
    fn interactive_not_starved() {
        let m = JobManager::new(2);
        // Fill background with long jobs.
        for i in 0..4 {
            m.submit(format!("bg{i}"), "bg", Priority::Background, false, |ctx| {
                while !ctx.cancelled() {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Ok(())
            });
        }
        let t = Instant::now();
        let i = m.submit("fast", "fast", Priority::Interactive, false, |_| Ok(()));
        assert_eq!(wait(&m, i), JobStatus::Done);
        assert!(t.elapsed() < Duration::from_millis(500));
        m.cancel_prefix("bg");
    }
}
