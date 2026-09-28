//! Application facade (PLAN.md §3): everything the UI can do goes through
//! [`AppCore`]. The Tauri shell is a thin binding on top; headless tests and a
//! future CLI use the same API.

pub mod bodies;
pub mod dto;
pub mod find;
pub mod logbuf;
pub mod mock;
pub mod settings;
pub mod stats;

use anyhow::{Context, Result, anyhow};
use dto::*;
use logbuf::LogBuffer;
use parking_lot::{Mutex, RwLock};
use piper_index::{RowWindow, Sort};
use piper_jobs::{JobId, JobManager};
use piper_model::{MarkColor, SessionId};
use piper_query::quickexec::{self, Command};
use piper_query::{Filter, FilterSettings};
use piper_store::Capture;
use serde::Serialize;
use settings::Settings;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub use piper_jobs::JobInfo;

/// Receives events for the UI (implemented by the Tauri shell).
pub trait EventSink: Send + Sync {
    fn emit(&self, event: &str, payload: serde_json::Value);
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub data: PathBuf,
    pub captures: PathBuf,
    pub settings: PathBuf,
}

impl Paths {
    pub fn default_paths() -> Paths {
        let data = std::env::var_os("PIPER_DATA_DIR")
            .map(PathBuf::from)
            .or_else(|| dirs::data_dir().map(|d| d.join("Piper")))
            .unwrap_or_else(|| PathBuf::from(".piper"));
        Paths::at(data)
    }
    pub fn at(data: PathBuf) -> Paths {
        Paths { captures: data.join("captures"), settings: data.join("settings.json"), data }
    }
}

/// Extension point for the capture engine (proxy). Installed by the shell.
pub trait CaptureEngine: Send + Sync {
    fn start(&self, core: &Arc<AppCore>) -> Result<()>;
    fn stop(&self, core: &Arc<AppCore>) -> Result<()>;
    fn status(&self) -> EngineStatus;
    /// Settings changed (restart listeners if needed).
    fn reconfigure(&self, _core: &Arc<AppCore>) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EngineStatus {
    pub capturing: bool,
    pub listen: Vec<String>,
    pub system_proxy: bool,
    pub decrypting: bool,
    pub upstream: Option<String>,
    pub error: Option<String>,
    pub breakpoints: Vec<String>,
    pub paused: usize,
    pub autoresponder: bool,
}

pub struct AppCore {
    pub paths: Paths,
    settings: RwLock<Settings>,
    capture: RwLock<Arc<Capture>>,
    pub jobs: Arc<JobManager>,
    pub log: Arc<LogBuffer>,
    sink: RwLock<Option<Arc<dyn EventSink>>>,
    engine: RwLock<Option<Arc<dyn CaptureEngine>>>,
    filters: RwLock<FilterSettings>,
    quick_filter: RwLock<String>,
    pub(crate) mock: Mutex<Option<mock::MockHandle>>,
    pub(crate) searches: Mutex<std::collections::HashMap<JobId, Arc<Mutex<SearchResult>>>>,
    pub(crate) finds: Mutex<std::collections::HashMap<JobId, Arc<Mutex<find::FindResult>>>>,
    started: Instant,
}

impl AppCore {
    /// Create the core with a fresh temporary capture.
    pub fn new(paths: Paths, log: Arc<LogBuffer>) -> Result<Arc<AppCore>> {
        std::fs::create_dir_all(&paths.captures).context("create data dir")?;
        let settings = Settings::load(&paths.settings);
        let capture = Self::new_temp_capture(&paths, &settings)?;
        let core = Arc::new(AppCore {
            paths,
            settings: RwLock::new(settings),
            capture: RwLock::new(capture),
            jobs: JobManager::new(std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(2, 8)),
            log,
            sink: RwLock::new(None),
            engine: RwLock::new(None),
            filters: RwLock::new(FilterSettings::default()),
            quick_filter: RwLock::new(String::new()),
            mock: Mutex::new(None),
            searches: Mutex::new(Default::default()),
            finds: Mutex::new(Default::default()),
            started: Instant::now(),
        });
        Ok(core)
    }

    fn new_temp_capture(paths: &Paths, settings: &Settings) -> Result<Arc<Capture>> {
        let now = time::OffsetDateTime::now_utc();
        let name = format!(
            "{:04}{:02}{:02}-{:02}{:02}{:02}-{}",
            now.year(),
            now.month() as u8,
            now.day(),
            now.hour(),
            now.minute(),
            now.second(),
            std::process::id()
        );
        Ok(Capture::open(paths.captures.join(name), settings.bodies.to_config(), true)?)
    }

    pub fn set_sink(&self, sink: Arc<dyn EventSink>) {
        *self.sink.write() = Some(sink);
    }

    pub fn set_engine(&self, e: Arc<dyn CaptureEngine>) {
        *self.engine.write() = Some(e);
    }

    pub fn engine(&self) -> Option<Arc<dyn CaptureEngine>> {
        self.engine.read().clone()
    }

    pub fn emit(&self, event: &str, payload: impl Serialize) {
        if let Some(s) = self.sink.read().as_ref() {
            match serde_json::to_value(payload) {
                Ok(v) => s.emit(event, v),
                Err(e) => tracing::error!("event {event}: {e}"),
            }
        }
    }

    pub fn capture(&self) -> Arc<Capture> {
        self.capture.read().clone()
    }

    pub fn settings(&self) -> Settings {
        self.settings.read().clone()
    }

    pub fn update_settings(self: &Arc<Self>, s: Settings) -> Result<()> {
        let old = std::mem::replace(&mut *self.settings.write(), s.clone());
        s.save(&self.paths.settings).context("save settings")?;
        self.capture().bodies.set_config(s.bodies.to_config());
        if old.proxy != s.proxy || old.https != s.https {
            if let Some(e) = self.engine() {
                e.reconfigure(self)?;
            }
        }
        Ok(())
    }

    /// Update only the opaque UI preferences.
    pub fn save_ui_prefs(&self, ui: serde_json::Value) -> Result<()> {
        let mut s = self.settings.write();
        s.ui = ui;
        s.save(&self.paths.settings).context("save settings")?;
        Ok(())
    }

    // ---------------------------------------------------------------- ticker

    /// Start the UI ticker (coalesces index changes, jobs, status, log; R5).
    pub fn start_ticker(self: &Arc<Self>) {
        let core = Arc::downgrade(self);
        std::thread::Builder::new()
            .name("piper-ticker".into())
            .spawn(move || {
                let mut last_jobs_gen = u64::MAX;
                let mut last_jobs = Instant::now();
                let mut last_status: Option<StatusDto> = None;
                let mut last_status_t = Instant::now() - Duration::from_secs(1);
                let mut last_log = 0u64;
                let mut last_trim = Instant::now();
                loop {
                    std::thread::sleep(Duration::from_millis(33));
                    let Some(core) = core.upgrade() else { return };
                    let cap = core.capture();
                    for l in cap.live_sessions() {
                        l.refresh_sizes();
                    }
                    if cap.index.tick() {
                        core.emit("list", ListEvent { version: cap.index.version(), total: cap.index.view_len(), count: cap.index.len() });
                    }
                    let g = core.jobs.generation();
                    if g != last_jobs_gen && last_jobs.elapsed() >= Duration::from_millis(100) {
                        last_jobs_gen = g;
                        last_jobs = Instant::now();
                        core.emit("jobs", core.jobs.list());
                    }
                    if last_status_t.elapsed() >= Duration::from_millis(250) {
                        last_status_t = Instant::now();
                        let st = core.status();
                        if last_status.as_ref() != Some(&st) {
                            core.emit("status", &st);
                            last_status = Some(st);
                        }
                    }
                    let seq = core.log.last_seq();
                    if seq != last_log {
                        let entries = core.log.since(last_log);
                        last_log = seq;
                        core.emit("log", entries);
                    }
                    if last_trim.elapsed() >= Duration::from_secs(1) {
                        last_trim = Instant::now();
                        let keep = core.settings.read().keep_sessions;
                        if keep > 0 {
                            let ids = cap.index.ids_beyond(keep);
                            if !ids.is_empty() {
                                let set: HashSet<SessionId> = ids.into_iter().filter(|id| cap.live(*id).is_none()).collect();
                                cap.remove(&set);
                            }
                        }
                    }
                }
            })
            .expect("spawn ticker");
    }

    pub fn status(&self) -> StatusDto {
        let cap = self.capture();
        let engine = self.engine().map(|e| e.status()).unwrap_or_default();
        let stats = cap.bodies.stats();
        StatusDto {
            engine,
            sessions: cap.index.len(),
            visible: cap.index.view_len(),
            jobs_active: self.jobs.active_count(),
            used_bytes: stats.used_bytes,
            free_bytes: stats.free_bytes,
            recording_suspended: stats.recording_suspended,
            filter_active: self.filters.read().enabled || !self.quick_filter.read().is_empty(),
            capture_dir: cap.dir.display().to_string(),
            uptime_s: self.started.elapsed().as_secs(),
            mock_running: self.mock.lock().is_some(),
        }
    }

    // --------------------------------------------------------------- capture

    pub fn start_capture(self: &Arc<Self>) -> Result<()> {
        match self.engine() {
            Some(e) => e.start(self),
            None => Err(anyhow!("no capture engine installed")),
        }
    }

    pub fn stop_capture(self: &Arc<Self>) -> Result<()> {
        match self.engine() {
            Some(e) => e.stop(self),
            None => Ok(()),
        }
    }

    pub fn toggle_capture(self: &Arc<Self>) -> Result<bool> {
        let on = self.engine().map(|e| e.status().capturing).unwrap_or(false);
        if on {
            self.stop_capture()?;
        } else {
            self.start_capture()?;
        }
        Ok(!on)
    }

    // ------------------------------------------------------------------ list

    pub fn rows(&self, start: usize, count: usize) -> RowWindow {
        self.capture().index.window(start, count.min(2000))
    }

    pub fn view_ids(&self, start: usize, count: usize) -> Vec<SessionId> {
        self.capture().index.view_ids(start, count)
    }

    pub fn position_of(&self, id: SessionId) -> Option<usize> {
        self.capture().index.position(id)
    }

    pub fn set_sort(&self, s: Sort) {
        self.capture().index.set_sort(s);
    }

    pub fn filters(&self) -> FilterSettings {
        self.filters.read().clone()
    }

    pub fn set_filters(&self, f: FilterSettings) -> Result<()> {
        *self.filters.write() = f;
        self.apply_filter()
    }

    fn apply_filter(&self) -> Result<()> {
        let mut fs = self.filters.read().clone();
        let quick = self.quick_filter.read().clone();
        if !quick.is_empty() {
            fs.expression = if fs.enabled && !fs.expression.trim().is_empty() {
                format!("({}) and ({quick})", fs.expression)
            } else {
                quick
            };
            if !fs.enabled {
                // Only the QuickExec expression applies.
                fs = FilterSettings { enabled: true, expression: fs.expression, ..Default::default() };
            }
        }
        let f = Filter::compile(&fs).map_err(|e| anyhow!("filter: {e}"))?;
        self.capture().index.set_filter(f);
        Ok(())
    }

    pub fn remove(&self, ids: Vec<SessionId>) {
        let cap = self.capture();
        cap.remove(&ids.into_iter().collect());
    }

    pub fn remove_all(&self) {
        let cap = self.capture();
        cap.clear();
        cap.reset_numbering();
        self.emit("list", ListEvent { version: cap.index.version(), total: 0, count: 0 });
    }

    pub fn remove_except(&self, keep: Vec<SessionId>) {
        let cap = self.capture();
        let keep: HashSet<SessionId> = keep.into_iter().collect();
        let ids: HashSet<SessionId> = cap.index.find_all(|s| !keep.contains(&s.id)).into_iter().collect();
        cap.remove(&ids);
    }

    pub fn mark(&self, ids: Vec<SessionId>, color: Option<MarkColor>) {
        let cap = self.capture();
        for id in ids {
            cap.update_summary(id, |s| s.color = color);
        }
    }

    pub fn comment(&self, ids: Vec<SessionId>, text: String) {
        let cap = self.capture();
        for id in ids {
            cap.update_summary(id, |s| s.comment = text.clone());
        }
    }

    pub fn detail(&self, id: SessionId) -> Option<DetailDto> {
        let cap = self.capture();
        let d = cap.detail(id)?;
        let (req_body, resp_body) = cap.bodies_of(id)?;
        Some(DetailDto::build(d, &req_body, &resp_body))
    }

    // ------------------------------------------------------------- quickexec

    pub fn quickexec(self: &Arc<Self>, input: &str) -> QuickExecResult {
        let cmd = match quickexec::parse(input) {
            Ok(c) => c,
            Err(e) => return QuickExecResult::error(e.msg),
        };
        let cap = self.capture();
        match cmd {
            Command::Select(e) => {
                let ids = cap.index.find(|s| e.eval(s));
                let n = ids.len();
                QuickExecResult { select: Some(ids), message: Some(format!("{n} session(s) selected")), ..Default::default() }
            }
            Command::Filter(expr) => {
                *self.quick_filter.write() = expr.clone();
                match self.apply_filter() {
                    Ok(()) if expr.is_empty() => QuickExecResult::msg("Filter removed"),
                    Ok(()) => QuickExecResult::msg(format!("Filter: {expr}")),
                    Err(e) => QuickExecResult::error(e.to_string()),
                }
            }
            Command::Clear => {
                self.remove_all();
                QuickExecResult::msg("All sessions removed")
            }
            Command::KeepOnly(e) => {
                let ids: HashSet<SessionId> = cap.index.find_all(|s| !e.eval(s)).into_iter().collect();
                let n = ids.len();
                cap.remove(&ids);
                QuickExecResult::msg(format!("{n} session(s) removed"))
            }
            Command::Tail(n) => {
                let ids: HashSet<SessionId> = cap.index.ids_beyond(n).into_iter().collect();
                let removed = ids.len();
                cap.remove(&ids);
                QuickExecResult::msg(format!("{removed} session(s) removed"))
            }
            Command::Help => QuickExecResult { message: Some(quickexec::HELP.into()), action: Some("help".into()), ..Default::default() },
            Command::Dump => QuickExecResult { action: Some("dump".into()), ..Default::default() },
            Command::Capture(on) => {
                let r = if on { self.start_capture() } else { self.stop_capture() };
                match r {
                    Ok(()) => QuickExecResult::msg(if on { "Capturing" } else { "Capture stopped" }),
                    Err(e) => QuickExecResult::error(e.to_string()),
                }
            }
            // Breakpoints and Go are handled by the capture engine (M8).
            other => QuickExecResult { action: Some(format!("{other:?}")), engine_command: Some(input.to_string()), ..Default::default() },
        }
    }

    // ------------------------------------------------------------------ jobs

    pub fn cancel_job(&self, id: JobId) -> bool {
        self.jobs.cancel(id)
    }

    /// Clean shutdown.
    pub fn shutdown(self: &Arc<Self>) {
        let _ = self.stop_capture();
        mock::stop(self);
        let keep = self.settings.read().keep_captures;
        self.capture().close(!keep);
    }

    /// Replace the current capture (open recovered/other capture).
    pub fn switch_capture(&self, cap: Arc<Capture>) {
        let old = std::mem::replace(&mut *self.capture.write(), cap);
        old.close(!self.settings.read().keep_captures);
        let _ = self.apply_filter();
        let cap = self.capture();
        cap.index.tick();
        self.emit("list", ListEvent { version: cap.index.version() + 1, total: cap.index.view_len(), count: cap.index.len() });
    }

    pub fn recoverable_captures(&self) -> Vec<piper_store::RecoverableCapture> {
        let current = self.capture().dir.clone();
        piper_store::find_recoverable(&self.paths.captures).into_iter().filter(|c| c.dir != current).collect()
    }

    pub fn recover_capture(&self, dir: PathBuf) -> Result<()> {
        let cfg = self.settings.read().bodies.to_config();
        let cap = Capture::open(dir, cfg, true)?;
        self.switch_capture(cap);
        Ok(())
    }

    pub fn discard_capture(&self, dir: PathBuf) -> Result<()> {
        if !dir.starts_with(&self.paths.captures) || dir == self.capture().dir {
            return Err(anyhow!("refusing to delete {}", dir.display()));
        }
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
}

/// Initialise tracing (stderr + Log tab). Returns the log buffer.
pub fn init_tracing() -> Arc<LogBuffer> {
    use tracing_subscriber::prelude::*;
    let buf = LogBuffer::new(10_000);
    let filter = tracing_subscriber::EnvFilter::try_from_env("PIPER_LOG").unwrap_or_else(|_| "info,piper=debug".into());
    let _ = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr).with_filter(filter))
        .with(logbuf::LogLayer(buf.clone()))
        .try_init();
    buf
}

impl AppCore {
    /// Remove all sessions matching an expression (toolbar "Remove" menu).
    pub fn remove_where(&self, expr: &str) -> Result<usize> {
        let e = piper_query::expr::parse(expr).map_err(|e| anyhow!("{e}"))?;
        let cap = self.capture();
        let ids: HashSet<SessionId> = cap.index.find_all(|s| e.eval(s) && cap.live(s.id).is_none()).into_iter().collect();
        let n = ids.len();
        cap.remove(&ids);
        Ok(n)
    }

    /// Summaries for a set of sessions (Timeline, copy …); at most 5000.
    pub fn summaries(&self, ids: &[SessionId]) -> Vec<piper_model::SessionSummary> {
        let cap = self.capture();
        ids.iter().take(5000).filter_map(|id| cap.index.get(*id)).collect()
    }
}
