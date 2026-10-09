//! The dedicated-thread QuickJS worker that runs the user's rules script.

use crate::{LogLine, RequestDecision, RequestInfo, ResponseDecision, ResponseInfo, SessionMeta};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::oneshot;

const PRELUDE: &str = include_str!("prelude.js");
const MEMORY_LIMIT: usize = 64 * 1024 * 1024;
const HOOK_BUDGET_US: u64 = 250_000; // 250 ms per hook
const LOAD_BUDGET_US: u64 = 2_000_000; // 2 s for top-level script + onBoot
const NO_DEADLINE: u64 = u64::MAX;
const MAX_LOG_LINES: usize = 2000;
const QUEUE_BOUND: usize = 256;
/// Longest a request waits for the script (queueing + hook). After that it passes through
/// unchanged, so a slow script degrades to "no rules" instead of stalling traffic.
const HOOK_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

fn now_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

enum Cmd {
    Load { source: String, reply: oneshot::Sender<Result<LoadInfo, String>> },
    Request { input: String, reply: oneshot::Sender<Result<String, String>> },
    Response { input: String, reply: oneshot::Sender<Result<String, String>> },
    Complete { input: String },
    Ws { input: String, reply: oneshot::Sender<Result<String, String>> },
    Menu { index: usize, input: String, reply: oneshot::Sender<Result<String, String>> },
    Shutdown,
}

/// What a successful load reports about the script: which hooks it defines, the
/// menu commands it registered, and the Custom-column title (if any).
#[derive(Debug, Clone, Default)]
pub struct LoadInfo {
    pub has_request: bool,
    pub has_response: bool,
    pub has_complete: bool,
    pub has_ws: bool,
    pub menus: Vec<String>,
    pub column: Option<String>,
}

/// A WebSocket message for `onWebSocketMessage`.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WsMessage {
    pub id: u64,
    pub url: String,
    /// `up` (client → server) or `down`.
    pub direction: String,
    pub is_binary: bool,
    /// The text of a text message (binary messages have none).
    pub text: Option<String>,
    pub size: usize,
}

/// What the script decided about a WebSocket message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsDecision {
    Forward,
    Replace(String),
    Drop,
}

/// A running rules script. Cheap to clone (shares the worker).
#[derive(Clone)]
pub struct ScriptEngine {
    tx: SyncSender<Cmd>,
    logs: Arc<Mutex<VecDeque<LogLine>>>,
    loaded: Arc<AtomicBool>,
    last_error: Arc<Mutex<Option<String>>>,
    /// Which hooks the current script actually defines, so callers can skip the
    /// marshalling + dispatch for hooks that aren't there.
    has_request: Arc<AtomicBool>,
    has_response: Arc<AtomicBool>,
    has_complete: Arc<AtomicBool>,
    has_ws: Arc<AtomicBool>,
    /// False once the worker thread has exited/panicked. Prevents hooks from
    /// dispatching to a dead worker (whose reply would never arrive).
    alive: Arc<AtomicBool>,
    /// Menu commands the script registered via `Quena.registerMenu`.
    menus: Arc<Mutex<Vec<String>>>,
    /// Title for the script's Custom column via `Quena.registerColumn`.
    column: Arc<Mutex<Option<String>>>,
}

impl ScriptEngine {
    /// Spawn the worker thread. The engine starts empty (no hooks) until
    /// [`ScriptEngine::load`] is called.
    pub fn new() -> ScriptEngine {
        // Bounded queue: under a flood, request/response hooks fall back to the
        // default decision (pass-through) instead of queuing without bound.
        let (tx, rx) = std::sync::mpsc::sync_channel::<Cmd>(QUEUE_BOUND);
        let logs: Arc<Mutex<VecDeque<LogLine>>> = Arc::new(Mutex::new(VecDeque::new()));
        let worker_logs = logs.clone();
        let alive = Arc::new(AtomicBool::new(true));
        let worker_alive = alive.clone();
        std::thread::Builder::new()
            .name("quena-script".into())
            .spawn(move || worker(rx, worker_logs, worker_alive))
            .expect("spawn script worker");
        ScriptEngine {
            tx,
            logs,
            loaded: Arc::new(AtomicBool::new(false)),
            last_error: Arc::new(Mutex::new(None)),
            has_request: Arc::new(AtomicBool::new(false)),
            has_response: Arc::new(AtomicBool::new(false)),
            has_complete: Arc::new(AtomicBool::new(false)),
            has_ws: Arc::new(AtomicBool::new(false)),
            alive,
            menus: Arc::new(Mutex::new(Vec::new())),
            column: Arc::new(Mutex::new(None)),
        }
    }

    /// Menu commands the current script registered (empty if none).
    pub fn menus(&self) -> Vec<String> {
        self.menus.lock().clone()
    }

    /// Title of the script's Custom column, if it registered one.
    pub fn column_title(&self) -> Option<String> {
        self.column.lock().clone()
    }

    /// Run a registered menu command over the given sessions (JSON array). Returns
    /// the handler's returned actions as JSON (`[]` if none / on error).
    pub async fn run_menu(&self, index: usize, sessions_json: String) -> Result<String, String> {
        if !self.is_loaded() {
            return Err("no script loaded".into());
        }
        let (reply, rx) = oneshot::channel();
        if self.tx.try_send(Cmd::Menu { index, input: sessions_json, reply }).is_err() {
            return Err("script worker is busy".into());
        }
        rx.await.unwrap_or_else(|_| Err("script worker did not reply".into()))
    }

    /// Whether the current script defines `onBeforeRequest`.
    pub fn has_request_hook(&self) -> bool {
        self.has_request.load(Ordering::Relaxed)
    }
    /// Whether the current script defines `onBeforeResponse`.
    pub fn has_response_hook(&self) -> bool {
        self.has_response.load(Ordering::Relaxed)
    }
    /// Whether the current script defines `onSessionComplete`.
    pub fn has_complete_hook(&self) -> bool {
        self.has_complete.load(Ordering::Relaxed)
    }
    /// Whether the current script defines `onWebSocketMessage`.
    pub fn has_ws_hook(&self) -> bool {
        self.has_ws.load(Ordering::Relaxed)
    }

    /// Whether a script is currently loaded and error-free (and the worker is alive).
    pub fn is_loaded(&self) -> bool {
        self.loaded.load(Ordering::Relaxed) && self.alive.load(Ordering::Relaxed)
    }

    /// The last load error, if the current script failed to compile/boot.
    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().clone()
    }

    /// Recent `console.*` output (oldest first).
    pub fn logs(&self) -> Vec<LogLine> {
        self.logs.lock().iter().cloned().collect()
    }

    pub fn clear_logs(&self) {
        self.logs.lock().clear();
    }

    /// Compile and boot a script (hot reload). Replaces any previous script.
    pub async fn load(&self, source: String) -> Result<(), String> {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(Cmd::Load { source, reply }).is_err() {
            return Err("script worker is gone".into());
        }
        let res = rx.await.unwrap_or_else(|_| Err("script worker did not reply".into()));
        match &res {
            Ok(info) => {
                self.loaded.store(true, Ordering::Relaxed);
                self.has_request.store(info.has_request, Ordering::Relaxed);
                self.has_response.store(info.has_response, Ordering::Relaxed);
                self.has_complete.store(info.has_complete, Ordering::Relaxed);
                self.has_ws.store(info.has_ws, Ordering::Relaxed);
                *self.menus.lock() = info.menus.clone();
                *self.column.lock() = info.column.clone();
                *self.last_error.lock() = None;
            }
            Err(e) => {
                self.loaded.store(false, Ordering::Relaxed);
                self.has_request.store(false, Ordering::Relaxed);
                self.has_response.store(false, Ordering::Relaxed);
                self.has_complete.store(false, Ordering::Relaxed);
                self.has_ws.store(false, Ordering::Relaxed);
                self.menus.lock().clear();
                *self.column.lock() = None;
                *self.last_error.lock() = Some(e.clone());
            }
        }
        res.map(|_| ())
    }

    /// Run `onBeforeRequest`. Returns the default decision if no script/hook.
    pub async fn on_request(&self, info: &RequestInfo) -> RequestDecision {
        if !self.is_loaded() || !self.has_request_hook() {
            return RequestDecision::default();
        }
        let input = serde_json::to_string(&ReqInput::from(info)).unwrap_or_default();
        let (reply, rx) = oneshot::channel();
        if self.tx.try_send(Cmd::Request { input, reply }).is_err() {
            // Queue full or worker gone: don't block forwarding, pass through.
            return RequestDecision::default();
        }
        match tokio::time::timeout(HOOK_WAIT, rx).await {
            Ok(Ok(Ok(json))) => parse_req_result(&json),
            Err(_) => {
                tracing::warn!(target: "quena::script", "onBeforeRequest did not answer within {} s; request passed through unchanged", HOOK_WAIT.as_secs());
                RequestDecision::default()
            }
            _ => RequestDecision::default(),
        }
    }

    /// Run `onBeforeResponse`. Returns the default decision if no script/hook.
    pub async fn on_response(&self, info: &ResponseInfo) -> ResponseDecision {
        if !self.is_loaded() || !self.has_response_hook() {
            return ResponseDecision::default();
        }
        let input = serde_json::to_string(&RespInput::from(info)).unwrap_or_default();
        let (reply, rx) = oneshot::channel();
        if self.tx.try_send(Cmd::Response { input, reply }).is_err() {
            return ResponseDecision::default();
        }
        match tokio::time::timeout(HOOK_WAIT, rx).await {
            Ok(Ok(Ok(json))) => parse_resp_result(&json),
            Err(_) => {
                tracing::warn!(target: "quena::script", "onBeforeResponse did not answer within {} s; response passed through unchanged", HOOK_WAIT.as_secs());
                ResponseDecision::default()
            }
            _ => ResponseDecision::default(),
        }
    }

    /// Run `onWebSocketMessage` for one message (`None` for `text`: binary). Unchanged when
    /// the script has no such hook, is busy or does not answer in time.
    pub async fn on_ws_message(&self, msg: &WsMessage) -> WsDecision {
        if !self.is_loaded() || !self.has_ws_hook() {
            return WsDecision::Forward;
        }
        let input = serde_json::to_string(msg).unwrap_or_default();
        let (reply, rx) = oneshot::channel();
        if self.tx.try_send(Cmd::Ws { input, reply }).is_err() {
            return WsDecision::Forward;
        }
        match tokio::time::timeout(HOOK_WAIT, rx).await {
            Ok(Ok(Ok(json))) => {
                let v: serde_json::Value = match serde_json::from_str(&json) {
                    Ok(v) => v,
                    Err(e) => {
                        // E.g. a text with a lone surrogate (`"\ud800"`), which is no UTF-8.
                        tracing::warn!(target: "quena::script", "onWebSocketMessage: the changed message cannot be used ({e}); message passed through unchanged");
                        return WsDecision::Forward;
                    }
                };
                match v.get("action").and_then(|a| a.as_str()) {
                    Some("drop") => WsDecision::Drop,
                    Some("replace") => v.get("text").and_then(|t| t.as_str()).map(|t| WsDecision::Replace(t.to_string())).unwrap_or(WsDecision::Forward),
                    _ => WsDecision::Forward,
                }
            }
            Err(_) => {
                tracing::warn!(target: "quena::script", "onWebSocketMessage did not answer within {} s; message passed through unchanged", HOOK_WAIT.as_secs());
                WsDecision::Forward
            }
            _ => WsDecision::Forward,
        }
    }

    /// Fire `onSessionComplete` (best effort, no reply).
    pub fn on_complete(&self, summary: serde_json::Value) {
        if !self.is_loaded() || !self.has_complete_hook() {
            return;
        }
        let input = summary.to_string();
        let _ = self.tx.try_send(Cmd::Complete { input });
    }
}

impl Default for ScriptEngine {
    fn default() -> Self {
        ScriptEngine::new()
    }
}

impl Drop for ScriptEngine {
    fn drop(&mut self) {
        // Only the last handle shutting down matters; a failed send is fine.
        if Arc::strong_count(&self.loaded) == 1 {
            let _ = self.tx.try_send(Cmd::Shutdown);
        }
    }
}

// ------------------------------------------------------------ worker thread

fn worker(rx: Receiver<Cmd>, logs: Arc<Mutex<VecDeque<LogLine>>>, alive: Arc<AtomicBool>) {
    // Clear `alive` on any exit — clean return or panic unwind — so hooks stop
    // dispatching to a worker that can no longer reply.
    struct AliveGuard(Arc<AtomicBool>);
    impl Drop for AliveGuard {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Relaxed);
        }
    }
    let _alive = AliveGuard(alive);

    use rquickjs::Runtime;
    let rt = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(target: "quena", "script runtime init failed: {e}");
            return;
        }
    };
    rt.set_memory_limit(MEMORY_LIMIT);
    // Deadlines are monotonic (µs since `base`), so an NTP/clock adjustment can
    // neither let a script run past its budget nor interrupt it early.
    let base = Instant::now();
    let deadline = Arc::new(AtomicU64::new(NO_DEADLINE));
    {
        let deadline = deadline.clone();
        rt.set_interrupt_handler(Some(Box::new(move || base.elapsed().as_micros() as u64 > deadline.load(Ordering::Relaxed))));
    }

    // The context is rebuilt on each Load so hot reload starts from a clean slate.
    let mut ctx: Option<rquickjs::Context> = None;

    for cmd in rx {
        match cmd {
            Cmd::Load { source, reply } => {
                match rebuild_and_load(&rt, &logs, &source, &deadline, base) {
                    Ok(c) => {
                        let info = probe_load(&c);
                        ctx = Some(c);
                        let _ = reply.send(Ok(info));
                    }
                    Err(e) => {
                        ctx = None;
                        let _ = reply.send(Err(e));
                    }
                }
            }
            // The caller gave up waiting (HOOK_WAIT): don't run a stale hook.
            Cmd::Request { reply, .. } | Cmd::Response { reply, .. } | Cmd::Ws { reply, .. } if reply.is_closed() => {}
            Cmd::Ws { input, reply } => {
                let out = dispatch(&ctx, &deadline, base, "__dispatchWs", &input);
                let _ = reply.send(out);
            }
            Cmd::Request { input, reply } => {
                let out = dispatch(&ctx, &deadline, base, "__dispatchRequest", &input);
                let _ = reply.send(out);
            }
            Cmd::Response { input, reply } => {
                let out = dispatch(&ctx, &deadline, base, "__dispatchResponse", &input);
                let _ = reply.send(out);
            }
            Cmd::Complete { input } => {
                let _ = dispatch(&ctx, &deadline, base, "__dispatchComplete", &input);
            }
            Cmd::Menu { index, input, reply } => {
                let out = dispatch_menu(&ctx, &deadline, base, index, &input);
                let _ = reply.send(out);
            }
            Cmd::Shutdown => break,
        }
    }
}

/// Probe which hooks, menus and Custom column the loaded script registered.
fn probe_load(ctx: &rquickjs::Context) -> LoadInfo {
    ctx.with(|cx| {
        let is_fn = |name: &str| cx.globals().get::<_, rquickjs::Function>(name).is_ok();
        let menus: Vec<String> = cx
            .globals()
            .get::<_, rquickjs::Function>("__menus")
            .ok()
            .and_then(|f| f.call::<_, String>(()).ok())
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let column: Option<String> = cx
            .globals()
            .get::<_, rquickjs::Function>("__columnTitle")
            .ok()
            .and_then(|f| f.call::<_, Option<String>>(()).ok())
            .flatten();
        LoadInfo {
            has_request: is_fn("onBeforeRequest"),
            has_response: is_fn("onBeforeResponse"),
            has_complete: is_fn("onSessionComplete"),
            has_ws: is_fn("onWebSocketMessage"),
            menus,
            column,
        }
    })
}

/// Build a fresh context, install host + prelude + user source + boot it.
fn rebuild_and_load(
    rt: &rquickjs::Runtime,
    logs: &Arc<Mutex<VecDeque<LogLine>>>,
    source: &str,
    deadline: &Arc<AtomicU64>,
    base: Instant,
) -> Result<rquickjs::Context, String> {
    let c = rquickjs::Context::full(rt).map_err(|e| format!("context: {e}"))?;
    install_host(&c, logs)?;
    deadline.store(base.elapsed().as_micros() as u64 + LOAD_BUDGET_US, Ordering::Relaxed);
    let r = c.with(|cx| -> Result<(), String> {
        cx.eval::<(), _>(PRELUDE).map_err(|e| js_err(&cx, e))?;
        cx.eval::<(), _>(source.as_bytes()).map_err(|e| js_err(&cx, e))?;
        let boot: rquickjs::Function = cx.globals().get("__boot").map_err(|e| e.to_string())?;
        boot.call::<_, ()>(()).map_err(|e| js_err(&cx, e))?;
        Ok(())
    });
    deadline.store(NO_DEADLINE, Ordering::Relaxed);
    r.map(|_| c)
}

fn dispatch(ctx: &Option<rquickjs::Context>, deadline: &Arc<AtomicU64>, base: Instant, func: &str, input: &str) -> Result<String, String> {
    let Some(c) = ctx else { return Err("no script loaded".into()) };
    deadline.store(base.elapsed().as_micros() as u64 + HOOK_BUDGET_US, Ordering::Relaxed);
    let out = c.with(|cx| -> Result<String, String> {
        let f: rquickjs::Function = cx.globals().get(func).map_err(|e| e.to_string())?;
        let s: String = f.call((input.to_string(),)).map_err(|e| js_err(&cx, e))?;
        Ok(s)
    });
    deadline.store(NO_DEADLINE, Ordering::Relaxed);
    out
}

fn dispatch_menu(ctx: &Option<rquickjs::Context>, deadline: &Arc<AtomicU64>, base: Instant, index: usize, input: &str) -> Result<String, String> {
    let Some(c) = ctx else { return Err("no script loaded".into()) };
    deadline.store(base.elapsed().as_micros() as u64 + HOOK_BUDGET_US, Ordering::Relaxed);
    let out = c.with(|cx| -> Result<String, String> {
        let f: rquickjs::Function = cx.globals().get("__runMenu").map_err(|e| e.to_string())?;
        let s: String = f.call((index as u32, input.to_string())).map_err(|e| js_err(&cx, e))?;
        Ok(s)
    });
    deadline.store(NO_DEADLINE, Ordering::Relaxed);
    out
}

fn install_host(ctx: &rquickjs::Context, logs: &Arc<Mutex<VecDeque<LogLine>>>) -> Result<(), String> {
    let logs = logs.clone();
    ctx.with(|cx| -> Result<(), String> {
        let logs2 = logs.clone();
        let log_fn = rquickjs::Function::new(cx.clone(), move |level: String, message: String| {
            let mut l = logs2.lock();
            if l.len() >= MAX_LOG_LINES {
                l.pop_front();
            }
            l.push_back(LogLine { level, message, ts_us: now_us() });
        })
        .map_err(|e| e.to_string())?;
        cx.globals().set("__log", log_fn).map_err(|e| e.to_string())?;
        Ok(())
    })
}

fn js_err(cx: &rquickjs::Ctx, e: rquickjs::Error) -> String {
    if let rquickjs::Error::Exception = e {
        let exc = cx.catch();
        if let Some(ex) = exc.as_exception() {
            let msg = ex.message().unwrap_or_default();
            let stack = ex.stack().unwrap_or_default();
            return if stack.is_empty() { msg } else { format!("{msg}\n{stack}") };
        }
        return format!("{:?}", exc);
    }
    e.to_string()
}

// ------------------------------------------------------------ marshalling

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReqInput<'a> {
    id: u64,
    method: &'a str,
    url: &'a str,
    host: &'a str,
    path: &'a str,
    process: &'a str,
    client_ip: &'a str,
    headers: &'a [(String, String)],
}

impl<'a> From<&'a RequestInfo> for ReqInput<'a> {
    fn from(r: &'a RequestInfo) -> Self {
        ReqInput {
            id: r.id,
            method: &r.method,
            url: &r.url,
            host: &r.host,
            path: &r.path,
            process: &r.process,
            client_ip: &r.client_ip,
            headers: &r.headers,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RespInput<'a> {
    id: u64,
    url: &'a str,
    status: u16,
    reason: &'a str,
    headers: &'a [(String, String)],
}

impl<'a> From<&'a ResponseInfo> for RespInput<'a> {
    fn from(r: &'a ResponseInfo) -> Self {
        RespInput { id: r.id, url: &r.url, status: r.status, reason: &r.reason, headers: &r.headers }
    }
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ReqResult {
    action: String,
    comment: Option<String>,
    color: Option<String>,
    #[serde(default)]
    custom: Option<String>,
    #[serde(default)]
    flags: Vec<(String, String)>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    headers: Option<Vec<(String, String)>>,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    resp_headers: Option<Vec<(String, String)>>,
    #[serde(default)]
    resp_body: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RespResult {
    action: String,
    comment: Option<String>,
    color: Option<String>,
    #[serde(default)]
    custom: Option<String>,
    #[serde(default)]
    flags: Vec<(String, String)>,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    headers: Option<Vec<(String, String)>>,
}

fn meta_of(comment: Option<String>, color: Option<String>, custom: Option<String>, flags: Vec<(String, String)>) -> SessionMeta {
    SessionMeta { comment, color, custom, flags }
}

fn parse_req_result(json: &str) -> RequestDecision {
    let r: ReqResult = serde_json::from_str(json).unwrap_or_default();
    let meta = meta_of(r.comment, r.color, r.custom, r.flags);
    match r.action.as_str() {
        "abort" => RequestDecision::Abort { meta },
        "respond" => RequestDecision::Respond {
            status: r.status.unwrap_or(200),
            headers: r.resp_headers.unwrap_or_default(),
            body: r.resp_body.unwrap_or_default(),
            meta,
        },
        _ => RequestDecision::Continue { method: r.method, url: r.url, headers: r.headers, meta },
    }
}

fn parse_resp_result(json: &str) -> ResponseDecision {
    let r: RespResult = serde_json::from_str(json).unwrap_or_default();
    let meta = meta_of(r.comment, r.color, r.custom, r.flags);
    match r.action.as_str() {
        "abort" => ResponseDecision::Abort { meta },
        _ => ResponseDecision::Continue { status: r.status, headers: r.headers, meta },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap()
    }

    #[test]
    fn websocket_messages() {
        rt().block_on(async {
            let e = ScriptEngine::new();
            let msg = |dir: &str, text: Option<&str>| WsMessage { id: 1, url: "wss://x/ws".into(), direction: dir.into(), is_binary: text.is_none(), text: text.map(str::to_string), size: 3 };
            // No hook: nothing happens.
            e.load("function onBeforeRequest(s) {}".into()).await.unwrap();
            assert!(!e.has_ws_hook());
            assert_eq!(e.on_ws_message(&msg("up", Some("abc"))).await, WsDecision::Forward);
            e.load(
                r#"function onWebSocketMessage(m) {
                    if (m.isBinary) { if (m.size > 2) m.drop(); return; }
                    if (m.direction === 'down') m.text = m.text.toUpperCase();
                    if (m.text === 'bye') m.drop();
                }"#
                .into(),
            )
            .await
            .unwrap();
            assert!(e.has_ws_hook());
            assert_eq!(e.on_ws_message(&msg("down", Some("abc"))).await, WsDecision::Replace("ABC".into()));
            assert_eq!(e.on_ws_message(&msg("up", Some("abc"))).await, WsDecision::Forward);
            assert_eq!(e.on_ws_message(&msg("up", Some("bye"))).await, WsDecision::Drop);
            assert_eq!(e.on_ws_message(&msg("up", None)).await, WsDecision::Drop);
            // A failing hook passes the message unchanged.
            e.load("function onWebSocketMessage(m) { throw new Error('x'); }".into()).await.unwrap();
            assert_eq!(e.on_ws_message(&msg("up", Some("abc"))).await, WsDecision::Forward);
        });
    }

    #[test]
    fn rewrites_request_headers_and_url() {
        rt().block_on(async {
            let e = ScriptEngine::new();
            e.load(
                r#"
                function onBeforeRequest(s) {
                    s.requestHeaders.set('X-Quena', 'yes');
                    if (s.host === 'ads.example.com') s.abort();
                    if (s.path === '/old') s.redirect('http://example.com/new');
                    s.comment('seen');
                }
                "#
                .into(),
            )
            .await
            .unwrap();

            let info = RequestInfo {
                id: 1,
                method: "GET".into(),
                url: "http://example.com/old".into(),
                host: "example.com".into(),
                path: "/old".into(),
                headers: vec![("Host".into(), "example.com".into())],
                ..Default::default()
            };
            match e.on_request(&info).await {
                RequestDecision::Continue { url, headers, meta, .. } => {
                    assert_eq!(url.as_deref(), Some("http://example.com/new"));
                    let h = headers.expect("headers changed");
                    assert!(h.iter().any(|(n, v)| n == "X-Quena" && v == "yes"));
                    assert_eq!(meta.comment.as_deref(), Some("seen"));
                }
                other => panic!("expected continue, got {other:?}"),
            }
        });
    }

    #[test]
    fn abort_and_respond() {
        rt().block_on(async {
            let e = ScriptEngine::new();
            e.load(
                r#"
                function onBeforeRequest(s) {
                    if (s.host === 'ads.example.com') { s.abort(); return; }
                    if (s.path === '/mock') s.respond(418, "teapot", {'Content-Type':'text/plain'});
                }
                "#
                .into(),
            )
            .await
            .unwrap();

            let ad = RequestInfo { host: "ads.example.com".into(), ..Default::default() };
            assert!(matches!(e.on_request(&ad).await, RequestDecision::Abort { .. }));

            let mock = RequestInfo { host: "x".into(), path: "/mock".into(), ..Default::default() };
            match e.on_request(&mock).await {
                RequestDecision::Respond { status, body, headers, .. } => {
                    assert_eq!(status, 418);
                    assert_eq!(body, "teapot");
                    assert!(headers.iter().any(|(n, _)| n == "Content-Type"));
                }
                other => panic!("expected respond, got {other:?}"),
            }
        });
    }

    #[test]
    fn response_hook_and_error_isolation() {
        rt().block_on(async {
            let e = ScriptEngine::new();
            e.load(
                r#"
                function onBeforeResponse(s) {
                    s.responseHeaders.remove('Set-Cookie');
                    s.responseHeaders.set('X-Frame-Options', 'DENY');
                }
                "#
                .into(),
            )
            .await
            .unwrap();
            let info = ResponseInfo {
                id: 2,
                status: 200,
                headers: vec![("Set-Cookie".into(), "a=b".into()), ("Server".into(), "nginx".into())],
                ..Default::default()
            };
            match e.on_response(&info).await {
                ResponseDecision::Continue { headers, .. } => {
                    let h = headers.expect("headers changed");
                    assert!(!h.iter().any(|(n, _)| n.eq_ignore_ascii_case("Set-Cookie")));
                    assert!(h.iter().any(|(n, v)| n == "X-Frame-Options" && v == "DENY"));
                }
                other => panic!("expected continue, got {other:?}"),
            }
        });
    }

    #[test]
    fn compile_error_is_reported() {
        rt().block_on(async {
            let e = ScriptEngine::new();
            let r = e.load("function ( { syntax error".into()).await;
            assert!(r.is_err());
            assert!(!e.is_loaded());
            assert!(e.last_error().is_some());
        });
    }

    #[test]
    fn register_menu_and_column() {
        rt().block_on(async {
            let e = ScriptEngine::new();
            e.load(
                r#"
                function onBoot() {
                    Quena.registerColumn('Server', function (s) { return s.responseHeaders.get('Server') || ''; });
                    Quena.registerMenu('Tag', function (sessions) {
                        return sessions.map(function (s) { return { id: s.id, comment: 'tagged', color: 'green' }; });
                    });
                }
                function onBeforeResponse(s) {}
                "#
                .into(),
            )
            .await
            .unwrap();
            assert_eq!(e.menus(), vec!["Tag".to_string()]);
            assert_eq!(e.column_title().as_deref(), Some("Server"));

            // Run the menu over two sessions; the handler returns updates.
            let ctx = serde_json::json!([
                {"id": 1, "method": "GET", "url": "http://a/", "status": 200, "host": "a"},
                {"id": 2, "method": "GET", "url": "http://b/", "status": 200, "host": "b"}
            ])
            .to_string();
            let out = e.run_menu(0, ctx).await.unwrap();
            let actions: Vec<crate::MenuAction> = serde_json::from_str(&out).unwrap();
            assert_eq!(actions.len(), 2);
            assert_eq!(actions[0].id, 1);
            assert_eq!(actions[0].comment.as_deref(), Some("tagged"));
            assert_eq!(actions[1].color.as_deref(), Some("green"));

            // registerColumn fn fills the Custom column at response time.
            let info = ResponseInfo {
                id: 1,
                status: 200,
                headers: vec![("Server".into(), "nginx".into())],
                ..Default::default()
            };
            match e.on_response(&info).await {
                ResponseDecision::Continue { meta, .. } => assert_eq!(meta.custom.as_deref(), Some("nginx")),
                other => panic!("expected continue, got {other:?}"),
            }
        });
    }

    #[test]
    fn hook_presence_is_detected() {
        rt().block_on(async {
            let e = ScriptEngine::new();
            e.load("function onBeforeResponse(s){}".into()).await.unwrap();
            assert!(e.is_loaded());
            assert!(!e.has_request_hook());
            assert!(e.has_response_hook());
            assert!(!e.has_complete_hook());
            // A script with no hooks still loads (e.g. only helper defs / onBoot).
            e.load("function onBoot(){}".into()).await.unwrap();
            assert!(!e.has_request_hook() && !e.has_response_hook() && !e.has_complete_hook());
            // on_request short-circuits to the default when there is no request hook.
            let info = RequestInfo { method: "GET".into(), ..Default::default() };
            assert!(matches!(e.on_request(&info).await, RequestDecision::Continue { method: None, url: None, headers: None, .. }));
        });
    }

    #[test]
    fn infinite_loop_is_interrupted() {
        rt().block_on(async {
            let e = ScriptEngine::new();
            e.load("function onBeforeRequest(s){ while(true){} }".into()).await.unwrap();
            let info = RequestInfo { method: "GET".into(), ..Default::default() };
            // Should return (default decision) rather than hang forever.
            let d = e.on_request(&info).await;
            assert!(matches!(d, RequestDecision::Continue { .. }));
        });
    }

    #[test]
    fn console_log_captured() {
        rt().block_on(async {
            let e = ScriptEngine::new();
            e.load("console.log('hello', 1, {a:2}); function onBoot(){ console.warn('booted'); }".into())
                .await
                .unwrap();
            let logs = e.logs();
            assert!(logs.iter().any(|l| l.message.contains("hello 1")));
            assert!(logs.iter().any(|l| l.level == "warn" && l.message == "booted"));
        });
    }
}
