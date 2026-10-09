//! Application facade: everything the UI can do goes through
//! [`AppCore`]. The Tauri shell is a thin binding on top; headless tests and a
//! future CLI use the same API.

pub mod archive;
pub mod auth;
pub mod autosave;
pub mod bodies;
pub mod capdiff;
pub mod collections;
pub mod ws;
pub mod compose;
pub mod diagnostics;
pub mod mcp_setup;
pub mod dto;
pub mod engine;
pub mod find;
pub mod grpc;
pub mod launch;
pub mod llm;
pub mod logbuf;
pub mod mock;
pub mod mockgen;
pub mod msgpack;
pub mod navigator;
pub mod multipart;
pub mod pac;
pub mod plugins;
pub mod protobuf;
pub mod rewrite;
pub mod rules;
pub mod sanitize;
pub mod settings;
pub mod socketio;
pub mod stats;
pub mod structure;

use anyhow::{Context, Result, anyhow};
use dto::*;
use logbuf::LogBuffer;
use parking_lot::{Mutex, RwLock};
use quena_index::{RowWindow, Sort};
use quena_jobs::{JobId, JobManager};
use quena_model::{MarkColor, SessionId};
use quena_query::quickexec::{self, Command};
use quena_query::{Filter, FilterSettings};
use quena_store::Capture;
use serde::Serialize;
use settings::Settings;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub use quena_jobs::{JobInfo, JobStatus, WaitError};

#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionTimers {
    pub id: SessionId,
    pub timers: quena_model::Timers,
}

/// Receives events for the UI (implemented by the Tauri shell).
pub trait EventSink: Send + Sync {
    fn emit(&self, event: &str, payload: serde_json::Value);
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub data: PathBuf,
    pub captures: PathBuf,
    pub settings: PathBuf,
    /// Machine code of compiled plugins (may be shared by several instances).
    pub plugin_cache: PathBuf,
}

impl Paths {
    pub fn default_paths() -> Paths {
        let data = std::env::var_os("QUENA_DATA_DIR")
            .map(PathBuf::from)
            .or_else(Self::portable_dir)
            .or_else(|| dirs::data_dir().map(|d| d.join("Quena")))
            .unwrap_or_else(|| PathBuf::from(".quena"));
        Paths::at(data)
    }

    /// Portable mode: a `quena-data` folder (or `portable` marker file)
    /// next to the executable keeps all data beside the app (USB stick, Windows portable zip).
    fn portable_dir() -> Option<PathBuf> {
        let exe = std::env::current_exe().ok()?;
        let dir = exe.parent()?;
        let data = dir.join("quena-data");
        if data.is_dir() || dir.join("portable").exists() {
            let _ = std::fs::create_dir_all(&data);
            return Some(data);
        }
        None
    }

    pub fn is_portable(&self) -> bool {
        Self::portable_dir().is_some_and(|d| d == self.data)
    }
    pub fn at(data: PathBuf) -> Paths {
        Paths { captures: data.join("captures"), settings: data.join("settings.json"), plugin_cache: data.join("plugin-cache"), data }
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
    /// The active capture was replaced (recover, open …).
    fn capture_changed(&self, _core: &Arc<AppCore>) {}
    /// Clean shutdown (restore system proxy …).
    fn shutdown(&self, _core: &Arc<AppCore>) {}
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
    /// Rewrite rules change real traffic.
    pub rewrite: bool,
    /// Listeners besides the proxy port while capturing (reverse proxy entries, SOCKS,
    /// transparent): listening, or why not.
    pub listeners: Vec<quena_proxy::listener::ListenerStatus>,
}

pub struct AppCore {
    pub paths: Paths,
    settings: RwLock<Settings>,
    capture: RwLock<Arc<Capture>>,
    pub jobs: Arc<JobManager>,
    pub log: Arc<LogBuffer>,
    sink: RwLock<Option<Arc<dyn EventSink>>>,
    engine: RwLock<Option<Arc<dyn CaptureEngine>>>,
    pub(crate) proxy_engine: RwLock<Option<Arc<engine::ProxyEngine>>>,
    pub rules: Option<Arc<rules::Rules>>,
    pub(crate) plugin_host: RwLock<Option<Arc<quena_plugin_host::PluginHost>>>,
    /// Plugin loading has finished (successfully or not); see `plugins_ready`.
    pub(crate) plugins_done: std::sync::atomic::AtomicBool,
    filters: RwLock<FilterSettings>,
    quick_filter: RwLock<String>,
    /// The navigator's group or path the list is narrowed to.
    scope: RwLock<Option<navigator::NavScope>>,
    /// The filters without the scope (the navigator lists what they let through).
    base_filter: RwLock<Arc<quena_query::Filter>>,
    group: RwLock<quena_index::GroupBy>,
    pub(crate) mock: Mutex<Option<mock::MockHandle>>,
    pub(crate) searches: Mutex<std::collections::HashMap<JobId, Arc<Mutex<SearchResult>>>>,
    /// Charset per body id (decoded prefix examined once).
    pub(crate) charsets: Mutex<std::collections::HashMap<u64, &'static quena_body::text::Encoding>>,
    pub(crate) finds: Mutex<std::collections::HashMap<JobId, Arc<Mutex<find::FindResult>>>>,
    /// Last diagnostics report (JSON) and the generation of the latest run.
    pub(crate) diag_report: Mutex<diagnostics::DiagSlot>,
    /// Protobuf schemas (`.proto` files, reflection), compiled when needed.
    pub(crate) protobuf: protobuf::Schemas,
    pub(crate) autosave: Mutex<autosave::State>,
    /// LLM prices with the stamps (time, size) of their files.
    #[allow(clippy::type_complexity)]
    pub(crate) llm_prices: Mutex<Option<((Option<(Option<std::time::SystemTime>, u64)>, Option<(Option<std::time::SystemTime>, u64)>), Arc<llm::PriceList>)>>,
    /// Archives loaded into the list: (file name, capture numbering, session ids).
    pub(crate) imports: Mutex<Vec<(String, u64, Vec<SessionId>)>>,
    started: Instant,
    shut_down: std::sync::atomic::AtomicBool,
    /// Serializes starting and stopping the capture (the startup thread and the UI can race).
    capture_switch: Mutex<()>,
}

impl AppCore {
    /// Create the core with a fresh temporary capture.
    pub fn new(paths: Paths, log: Arc<LogBuffer>) -> Result<Arc<AppCore>> {
        std::fs::create_dir_all(&paths.captures).context("create data dir")?;
        let settings = Settings::load(&paths.settings);
        let capture = Self::new_temp_capture(&paths, &settings)?;
        let rules = rules::Rules::new(&paths.data);
        archive::clean_dropped_at_startup(&paths.data);
        let core = Arc::new(AppCore {
            paths,
            settings: RwLock::new(settings),
            capture: RwLock::new(capture),
            jobs: JobManager::new(std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(2, 8)),
            log,
            sink: RwLock::new(None),
            engine: RwLock::new(None),
            proxy_engine: RwLock::new(None),
            rules: Some(rules),
            plugin_host: RwLock::new(None),
            plugins_done: std::sync::atomic::AtomicBool::new(false),
            capture_switch: Mutex::new(()),
            filters: RwLock::new(FilterSettings::default()),
            quick_filter: RwLock::new(String::new()),
            scope: RwLock::new(None),
            base_filter: RwLock::new(Arc::new(quena_query::Filter::all())),
            group: RwLock::new(Default::default()),
            mock: Mutex::new(None),
            searches: Mutex::new(Default::default()),
            charsets: Mutex::new(Default::default()),
            finds: Mutex::new(Default::default()),
            diag_report: Mutex::new(Default::default()),
            protobuf: protobuf::Schemas::default(),
            autosave: Mutex::new(Default::default()),
            llm_prices: Mutex::new(None),
            imports: Mutex::new(Vec::new()),
            started: Instant::now(),
            shut_down: std::sync::atomic::AtomicBool::new(false),
        });
        if let Some(r) = &core.rules {
            r.attach(&core);
        }
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

    /// Replace the settings. `sanitize` (the last options of the sanitized export) belongs to
    /// the core: the export writes it, and a caller's copy may be older, so it is kept.
    pub fn update_settings(self: &Arc<Self>, mut s: Settings) -> Result<()> {
        {
            // Checked when the entries or the ports they must not take change.
            let cur = self.settings.read();
            if s.host_remap != cur.host_remap {
                s.host_remap.validate().map_err(|e| anyhow!("{e}"))?;
            }
            if s.reverse_proxy != cur.reverse_proxy
                || s.socks != cur.socks
                || s.transparent != cur.transparent
                || s.proxy.port != cur.proxy.port
                || (s.mcp.enabled, s.mcp.port) != (cur.mcp.enabled, cur.mcp.port)
            {
                s.validate_ports().map_err(|e| anyhow!("{e}"))?;
            }
        }
        let old = {
            let mut cur = self.settings.write();
            s.sanitize = cur.sanitize.clone();
            std::mem::replace(&mut *cur, s.clone())
        };
        s.save(&self.paths.settings).context("save settings")?;
        self.capture().bodies.set_config(s.bodies.to_config());
        if old.proxy != s.proxy
            || old.reverse_proxy != s.reverse_proxy
            || old.socks != s.socks
            || old.transparent != s.transparent
            || old.host_remap != s.host_remap
            || old.https != s.https
            || old.throttle_kbps != s.throttle_kbps
            || old.throttle_latency_ms != s.throttle_latency_ms
        {
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
            .name("quena-ticker".into())
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
                        core.autosave_tick();
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
            // Rounded to 64 MB: the exact value changes with every write, which would send a
            // status event (and re-render the toolbar and status bar) four times a second.
            free_bytes: stats.free_bytes.map(|b| b & !((64u64 << 20) - 1)),
            recording_suspended: stats.recording_suspended,
            filter_active: self.filters.read().enabled || !self.quick_filter.read().is_empty(),
            capture_dir: cap.dir.display().to_string(),
            uptime_s: self.started.elapsed().as_secs(),
            mock_running: self.mock.lock().is_some(),
        }
    }

    // --------------------------------------------------------------- capture

    pub fn start_capture(self: &Arc<Self>) -> Result<()> {
        let _g = self.capture_switch.lock();
        if self.engine().is_some_and(|e| e.status().capturing) {
            return Ok(());
        }
        self.start_capture_locked()
    }

    fn start_capture_locked(self: &Arc<Self>) -> Result<()> {
        match self.engine() {
            Some(e) => e.start(self),
            None => Err(anyhow!("no capture engine installed")),
        }
    }

    pub fn stop_capture(self: &Arc<Self>) -> Result<()> {
        let _g = self.capture_switch.lock();
        self.stop_capture_locked()
    }

    fn stop_capture_locked(self: &Arc<Self>) -> Result<()> {
        match self.engine() {
            Some(e) => e.stop(self),
            None => Ok(()),
        }
    }

    pub fn toggle_capture(self: &Arc<Self>) -> Result<bool> {
        let _g = self.capture_switch.lock();
        let on = self.engine().map(|e| e.status().capturing).unwrap_or(false);
        if on {
            self.stop_capture_locked()?;
        } else {
            self.start_capture_locked()?;
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

    /// "Group by" of the session list (kept when the capture is replaced).
    pub fn set_group(&self, by: quena_index::GroupBy) {
        *self.group.write() = by;
        self.capture().index.set_group(by);
    }

    /// Collapse or expand the group of a session; the new state (`None`: no group).
    pub fn toggle_group(&self, id: SessionId) -> Option<bool> {
        self.capture().index.toggle_group(id)
    }

    pub fn collapse_groups(&self, collapse: bool) {
        self.capture().index.collapse_all(collapse);
    }

    /// The sessions of a session's group (for "Select group").
    pub fn group_ids(&self, id: SessionId) -> Vec<SessionId> {
        self.capture().index.group_ids(id)
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
        self.capture().index.set_filter(self.scoped(f));
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
        // The report refers to session ids that restart now.
        self.diag_reset();
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
        let mut dto = DetailDto::build(d, &req_body, &resp_body);
        self.add_plugin_candidates(&mut dto, &req_body, &resp_body);
        Some(dto)
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
            Command::BreakRequest(t) | Command::BreakResponse(t) | Command::BreakStatus(t) | Command::BreakMethod(t)
                if self.rules.is_none() =>
            {
                let _ = t;
                QuickExecResult::error("breakpoints unavailable")
            }
            Command::BreakRequest(t) => self.set_bp(|b| b.request_url = target_text(&t), "bpu"),
            Command::BreakResponse(t) => self.set_bp(|b| b.response_url = target_text(&t), "bpafter"),
            Command::BreakStatus(t) => self.set_bp(
                |b| {
                    b.status = match t {
                        quickexec::BreakTarget::Status(s) => Some(s),
                        _ => None,
                    }
                },
                "bps",
            ),
            Command::BreakMethod(t) => self.set_bp(
                |b| {
                    b.method = match t {
                        quickexec::BreakTarget::Method(m) => Some(m),
                        _ => None,
                    }
                },
                "bpv",
            ),
            Command::Go => {
                let n = self.rules.as_ref().map(|r| r.go_all()).unwrap_or(0);
                QuickExecResult::msg(format!("Resumed {n} session(s)"))
            }
        }
    }

    fn set_bp(&self, f: impl FnOnce(&mut rules::BreakpointState), name: &str) -> QuickExecResult {
        let Some(r) = &self.rules else { return QuickExecResult::error("breakpoints unavailable") };
        r.update_breakpoints(f);
        let labels = r.breakpoints().labels();
        QuickExecResult::msg(if labels.is_empty() { format!("{name}: breakpoints cleared") } else { format!("Breakpoints: {}", labels.join(", ")) })
    }

    // ------------------------------------------------------------------ jobs

    pub fn cancel_job(&self, id: JobId) -> bool {
        self.jobs.cancel(id)
    }

    /// Clean shutdown.
    pub fn shutdown(self: &Arc<Self>) {
        // Idempotent: window close, RunEvent::Exit and signals may all call this.
        if self.shut_down.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let _ = self.stop_capture();
        if let Some(e) = self.engine() {
            e.shutdown(self);
        }
        mock::stop(self);
        let keep = self.settings.read().keep_captures;
        self.capture().close(!keep);
    }

    /// Replace the current capture (open recovered/other capture).
    pub fn switch_capture(self: &Arc<Self>, cap: Arc<Capture>) {
        self.install_plugin_decoders(&cap);
        let old = std::mem::replace(&mut *self.capture.write(), cap);
        old.close(!self.settings.read().keep_captures);
        self.diag_reset();
        // A group or path of the old capture means nothing in the new one.
        if self.scope.write().take().is_some() {
            self.emit("scope", serde_json::Value::Null);
        }
        let _ = self.apply_filter();
        let cap = self.capture();
        cap.index.set_group(*self.group.read());
        cap.index.tick();
        self.emit("list", ListEvent { version: cap.index.version() + 1, total: cap.index.view_len(), count: cap.index.len() });
        if let Some(e) = self.engine() {
            e.capture_changed(self);
        }
    }

    /// Delete all crashed captures (recovery dialog "Discard all").
    pub fn discard_all_captures(&self) -> usize {
        let list = self.recoverable_captures();
        let n = list.len();
        for c in list {
            let _ = self.discard_capture(c.dir);
        }
        n
    }

    pub fn recoverable_captures(&self) -> Vec<quena_store::RecoverableCapture> {
        let current = self.capture().dir.clone();
        quena_store::find_recoverable(&self.paths.captures).into_iter().filter(|c| c.dir != current).collect()
    }

    pub fn recover_capture(self: &Arc<Self>, dir: PathBuf) -> Result<()> {
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
/// Copy a state file that failed to parse next to itself (`name.corrupt-<unix time>`), so a
/// later save does not destroy the user's data. Returns the backup's file name.
pub(crate) fn keep_corrupt(path: &std::path::Path) -> String {
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(format!(".corrupt-{ts}"));
    let aside = path.with_file_name(&name);
    match std::fs::copy(path, &aside) {
        Ok(_) => name.to_string_lossy().into_owned(),
        Err(e) => format!("(copy failed: {e})"),
    }
}

pub fn init_tracing() -> Arc<LogBuffer> {
    use tracing_subscriber::prelude::*;
    let buf = LogBuffer::new(10_000);
    let filter = tracing_subscriber::EnvFilter::try_from_env("QUENA_LOG").unwrap_or_else(|_| "info,quena=debug".into());
    let _ = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr).with_filter(filter))
        .with(logbuf::LogLayer(buf.clone()))
        .try_init();
    buf
}

impl AppCore {
    /// Remove all sessions matching an expression (toolbar "Remove" menu).
    pub fn remove_where(&self, expr: &str) -> Result<usize> {
        let e = quena_query::expr::parse(expr).map_err(|e| anyhow!("{e}"))?;
        let cap = self.capture();
        let ids: HashSet<SessionId> = cap.index.find_all(|s| e.eval(s) && cap.live(s.id).is_none()).into_iter().collect();
        let n = ids.len();
        cap.remove(&ids);
        Ok(n)
    }

    /// Summaries for a set of sessions (Timeline, copy …); at most 5000.
    pub fn summaries(&self, ids: &[SessionId]) -> Vec<quena_model::SessionSummary> {
        let cap = self.capture();
        ids.iter().take(5000).filter_map(|id| cap.index.get(*id)).collect()
    }

    /// Timers of sessions for the waterfall (at most 500).
    pub fn timers(&self, ids: &[SessionId]) -> Vec<SessionTimers> {
        let cap = self.capture();
        ids.iter().take(500).filter_map(|id| cap.detail(*id).map(|d| SessionTimers { id: *id, timers: d.timers })).collect()
    }
}

fn target_text(t: &quickexec::BreakTarget) -> Option<String> {
    match t {
        quickexec::BreakTarget::UrlContains(u) => Some(u.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod settings_tests {
    use super::*;

    #[test]
    fn update_settings_keeps_the_sanitize_options_of_the_core() {
        let dir = tempfile::tempdir().unwrap();
        let core = AppCore::new(Paths::at(dir.path().to_path_buf()), logbuf::LogBuffer::new(10)).unwrap();
        // A UI copy taken before an export ...
        let stale = core.settings();
        // ... the export remembers its options ...
        core.settings.write().sanitize.format = "har".into();
        // ... and saving the stale copy does not bring the old ones back.
        core.update_settings(stale).unwrap();
        assert_eq!(core.settings().sanitize.format, "har");
    }
}
