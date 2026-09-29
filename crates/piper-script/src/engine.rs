//! The dedicated-thread QuickJS worker that runs the user's rules script.

use crate::{LogLine, RequestDecision, RequestInfo, ResponseDecision, ResponseInfo, SessionMeta};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use tokio::sync::oneshot;

const PRELUDE: &str = include_str!("prelude.js");
const MEMORY_LIMIT: usize = 64 * 1024 * 1024;
const HOOK_BUDGET_US: u64 = 250_000; // 250 ms per hook
const LOAD_BUDGET_US: u64 = 2_000_000; // 2 s for top-level script + onBoot
const NO_DEADLINE: u64 = u64::MAX;
const MAX_LOG_LINES: usize = 2000;

fn now_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

enum Cmd {
    Load { source: String, reply: oneshot::Sender<Result<(), String>> },
    Request { input: String, reply: oneshot::Sender<Result<String, String>> },
    Response { input: String, reply: oneshot::Sender<Result<String, String>> },
    Complete { input: String },
    Shutdown,
}

/// A running rules script. Cheap to clone (shares the worker).
#[derive(Clone)]
pub struct ScriptEngine {
    tx: Sender<Cmd>,
    logs: Arc<Mutex<VecDeque<LogLine>>>,
    loaded: Arc<AtomicBool>,
    last_error: Arc<Mutex<Option<String>>>,
}

impl ScriptEngine {
    /// Spawn the worker thread. The engine starts empty (no hooks) until
    /// [`ScriptEngine::load`] is called.
    pub fn new() -> ScriptEngine {
        let (tx, rx) = std::sync::mpsc::channel::<Cmd>();
        let logs: Arc<Mutex<VecDeque<LogLine>>> = Arc::new(Mutex::new(VecDeque::new()));
        let worker_logs = logs.clone();
        std::thread::Builder::new()
            .name("piper-script".into())
            .spawn(move || worker(rx, worker_logs))
            .expect("spawn script worker");
        ScriptEngine { tx, logs, loaded: Arc::new(AtomicBool::new(false)), last_error: Arc::new(Mutex::new(None)) }
    }

    /// Whether a script is currently loaded and error-free.
    pub fn is_loaded(&self) -> bool {
        self.loaded.load(Ordering::Relaxed)
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
            Ok(()) => {
                self.loaded.store(true, Ordering::Relaxed);
                *self.last_error.lock() = None;
            }
            Err(e) => {
                self.loaded.store(false, Ordering::Relaxed);
                *self.last_error.lock() = Some(e.clone());
            }
        }
        res
    }

    /// Run `onBeforeRequest`. Returns the default decision if no script/hook.
    pub async fn on_request(&self, info: &RequestInfo) -> RequestDecision {
        if !self.is_loaded() {
            return RequestDecision::default();
        }
        let input = serde_json::to_string(&ReqInput::from(info)).unwrap_or_default();
        let (reply, rx) = oneshot::channel();
        if self.tx.send(Cmd::Request { input, reply }).is_err() {
            return RequestDecision::default();
        }
        match rx.await {
            Ok(Ok(json)) => parse_req_result(&json),
            _ => RequestDecision::default(),
        }
    }

    /// Run `onBeforeResponse`. Returns the default decision if no script/hook.
    pub async fn on_response(&self, info: &ResponseInfo) -> ResponseDecision {
        if !self.is_loaded() {
            return ResponseDecision::default();
        }
        let input = serde_json::to_string(&RespInput::from(info)).unwrap_or_default();
        let (reply, rx) = oneshot::channel();
        if self.tx.send(Cmd::Response { input, reply }).is_err() {
            return ResponseDecision::default();
        }
        match rx.await {
            Ok(Ok(json)) => parse_resp_result(&json),
            _ => ResponseDecision::default(),
        }
    }

    /// Fire `onSessionComplete` (best effort, no reply).
    pub fn on_complete(&self, summary: serde_json::Value) {
        if !self.is_loaded() {
            return;
        }
        let input = summary.to_string();
        let _ = self.tx.send(Cmd::Complete { input });
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
            let _ = self.tx.send(Cmd::Shutdown);
        }
    }
}

// ------------------------------------------------------------ worker thread

fn worker(rx: Receiver<Cmd>, logs: Arc<Mutex<VecDeque<LogLine>>>) {
    use rquickjs::Runtime;
    let rt = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(target: "piper", "script runtime init failed: {e}");
            return;
        }
    };
    rt.set_memory_limit(MEMORY_LIMIT);
    let deadline = Arc::new(AtomicU64::new(NO_DEADLINE));
    {
        let deadline = deadline.clone();
        rt.set_interrupt_handler(Some(Box::new(move || now_us() > deadline.load(Ordering::Relaxed))));
    }

    // The context is rebuilt on each Load so hot reload starts from a clean slate.
    let mut ctx: Option<rquickjs::Context> = None;

    for cmd in rx {
        match cmd {
            Cmd::Load { source, reply } => {
                match rebuild_and_load(&rt, &logs, &source, &deadline) {
                    Ok(c) => {
                        ctx = Some(c);
                        let _ = reply.send(Ok(()));
                    }
                    Err(e) => {
                        ctx = None;
                        let _ = reply.send(Err(e));
                    }
                }
            }
            Cmd::Request { input, reply } => {
                let out = dispatch(&ctx, &deadline, "__dispatchRequest", &input);
                let _ = reply.send(out);
            }
            Cmd::Response { input, reply } => {
                let out = dispatch(&ctx, &deadline, "__dispatchResponse", &input);
                let _ = reply.send(out);
            }
            Cmd::Complete { input } => {
                let _ = dispatch(&ctx, &deadline, "__dispatchComplete", &input);
            }
            Cmd::Shutdown => break,
        }
    }
}

/// Build a fresh context, install host + prelude + user source + boot it.
fn rebuild_and_load(
    rt: &rquickjs::Runtime,
    logs: &Arc<Mutex<VecDeque<LogLine>>>,
    source: &str,
    deadline: &Arc<AtomicU64>,
) -> Result<rquickjs::Context, String> {
    let c = rquickjs::Context::full(rt).map_err(|e| format!("context: {e}"))?;
    install_host(&c, logs)?;
    deadline.store(now_us() + LOAD_BUDGET_US, Ordering::Relaxed);
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

fn dispatch(ctx: &Option<rquickjs::Context>, deadline: &Arc<AtomicU64>, func: &str, input: &str) -> Result<String, String> {
    let Some(c) = ctx else { return Err("no script loaded".into()) };
    deadline.store(now_us() + HOOK_BUDGET_US, Ordering::Relaxed);
    let out = c.with(|cx| -> Result<String, String> {
        let f: rquickjs::Function = cx.globals().get(func).map_err(|e| e.to_string())?;
        let s: String = f.call((input.to_string(),)).map_err(|e| js_err(&cx, e))?;
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
    flags: Vec<(String, String)>,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    headers: Option<Vec<(String, String)>>,
}

fn meta_of(comment: Option<String>, color: Option<String>, flags: Vec<(String, String)>) -> SessionMeta {
    SessionMeta { comment, color, flags }
}

fn parse_req_result(json: &str) -> RequestDecision {
    let r: ReqResult = serde_json::from_str(json).unwrap_or_default();
    let meta = meta_of(r.comment, r.color, r.flags);
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
    let meta = meta_of(r.comment, r.color, r.flags);
    match r.action.as_str() {
        "abort" => ResponseDecision::Abort { meta },
        _ => ResponseDecision::Continue { status: r.status, headers: r.headers, meta },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().build().unwrap()
    }

    #[test]
    fn rewrites_request_headers_and_url() {
        rt().block_on(async {
            let e = ScriptEngine::new();
            e.load(
                r#"
                function onBeforeRequest(s) {
                    s.requestHeaders.set('X-Piper', 'yes');
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
                    assert!(h.iter().any(|(n, v)| n == "X-Piper" && v == "yes"));
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
