//! The forwarding pipeline: record → hooks → upstream → record → client.

use crate::body::{BoxError, Prefixed, ProxyBody, StoredStream, Tee, TeeTimes, empty, full};
use crate::connector::{ConnInfo, Connector};
use crate::hooks::{Mode, RequestAction, ResponseAction, ResponseHeadAction, SessionView};
use crate::util::{HOP_BY_HOP, title_case};
use crate::{ProxyConfig, Shared, host_matches};
use bytes::Bytes;
use http::{HeaderName, HeaderValue, Request, Response, StatusCode, Version};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::capture_connection;
use hyper_util::rt::TokioExecutor;
use quena_body::Body as StoredBody;
use quena_model::*;
use quena_store::LiveSession;
use quena_tls::ClientConfigs;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// Pooled upstream clients.
pub struct Upstream {
    pub client: Client<Connector, ProxyBody>,
    /// For requests that must use HTTP/1.1 or HTTP/2 (Composer); own pools, so a pooled
    /// connection of the other version is never reused for them.
    pub http1: Client<Connector, ProxyBody>,
    pub http2: Client<Connector, ProxyBody>,
}

impl Upstream {
    pub fn new(cfg: Arc<ProxyConfig>, tls: Arc<ClientConfigs>) -> Upstream {
        let builder = || {
            let mut b = Client::builder(TokioExecutor::new());
            b.pool_idle_timeout(Duration::from_secs(90))
                .pool_max_idle_per_host(32)
                .http1_allow_spaces_after_header_name_in_responses(true)
                .http1_allow_obsolete_multiline_headers_in_responses(true)
                .http1_ignore_invalid_headers_in_responses(true)
                .http1_max_headers(1000)
                .pool_timer(hyper_util::rt::TokioTimer::new())
                .http1_preserve_header_case(true)
                .http1_title_case_headers(false)
                .set_host(true);
            b
        };
        let http1 = builder().build(Connector { cfg: cfg.clone(), tls: tls.clone(), force_h2: Some(false) });
        let http2 = builder().http2_only(true).http2_adaptive_window(true).build(Connector { cfg: cfg.clone(), tls: tls.clone(), force_h2: Some(true) });
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(32)
            // Real servers send sloppy heads; accept what browsers accept instead of a 502.
            .http1_allow_spaces_after_header_name_in_responses(true)
            .http1_allow_obsolete_multiline_headers_in_responses(true)
            .http1_ignore_invalid_headers_in_responses(true)
            .http1_max_headers(1000)
            // Reap idle pooled connections in the background, not only on checkout.
            .pool_timer(hyper_util::rt::TokioTimer::new())
            .http1_preserve_header_case(true)
            .http1_title_case_headers(false)
            .http2_adaptive_window(true)
            .retry_canceled_requests(true)
            .set_host(true)
            .build(Connector { cfg, tls, force_h2: None });
        Upstream { client, http1, http2 }
    }
}

/// Per client-connection context.
pub struct ConnCtx {
    pub shared: Arc<Shared>,
    pub conn_id: u64,
    pub client_addr: SocketAddr,
    pub remote: bool,
    pub process: tokio::sync::watch::Receiver<Option<Option<ProcessInfo>>>,
    /// "http" or "https" for origin-form requests on this connection.
    pub scheme: &'static str,
    /// CONNECT target for requests inside a decrypted tunnel.
    pub authority: Option<String>,
    pub client_tls: Option<TlsInfo>,
    pub connected_at: i64,
    pub decrypted: bool,
    /// Per-connection dedicated upstream clients for authenticated hosts
    /// (connection pinning – never shared with another client connection).
    pub auth_clients: parking_lot::Mutex<std::collections::HashMap<(String, u16), Arc<hyper_util::client::legacy::Client<crate::connector::Connector, ProxyBody>>>>,
    /// Set on a reverse proxy port: every request goes to this route's targets.
    pub reverse: Option<Arc<crate::reverse::ReverseRoute>>,
    /// The listener besides the proxy port the connection came in on (Via column).
    pub via: Option<String>,
}

impl ConnCtx {
    pub async fn process(&self) -> Option<ProcessInfo> {
        if self.remote {
            return Some(ProcessInfo { pid: 0, name: format!("remote:{}", self.client_addr.ip().to_canonical()) });
        }
        let mut rx = self.process.clone();
        if rx.borrow().is_none() {
            let _ = tokio::time::timeout(Duration::from_millis(60), rx.changed()).await;
        }
        rx.borrow().clone().flatten()
    }
}

fn is_h1(v: Version) -> bool {
    v == Version::HTTP_11 || v == Version::HTTP_10 || v == Version::HTTP_09
}

fn version_of(v: Version) -> HttpVersion {
    match v {
        Version::HTTP_09 => HttpVersion::Http09,
        Version::HTTP_10 => HttpVersion::Http10,
        Version::HTTP_2 => HttpVersion::Http2,
        Version::HTTP_3 => HttpVersion::Http3,
        _ => HttpVersion::Http11,
    }
}

pub fn record_headers(h: &http::HeaderMap, h1: bool) -> Headers {
    let mut out = Headers::new();
    for (k, v) in h {
        let name = if h1 { title_case(k.as_str()) } else { k.as_str().to_string() };
        out.push_bytes(&name, v.as_bytes());
    }
    out
}

fn to_header_map(h: &Headers, skip_hop: bool, keep_upgrade: bool) -> http::HeaderMap {
    let mut m = http::HeaderMap::with_capacity(h.len());
    let connection_tokens: Vec<String> = h
        .get_all("connection")
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    for (k, v) in h.iter() {
        let lk = k.to_ascii_lowercase();
        if lk.starts_with(':') {
            continue;
        }
        if skip_hop {
            let upgrade_hdr = keep_upgrade && (lk == "upgrade" || lk == "connection");
            if !upgrade_hdr && (HOP_BY_HOP.contains(&lk.as_str()) || (connection_tokens.contains(&lk) && lk != "upgrade")) {
                continue;
            }
        }
        let (Ok(name), Ok(val)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_bytes(&string_to_latin1(v))) else {
            continue;
        };
        m.append(name, val);
    }
    m
}

/// Absolute URL of an incoming proxy request.
fn absolute_url(req: &Request<Incoming>, ctx: &ConnCtx) -> Option<String> {
    let uri = req.uri();
    if let (Some(s), Some(a)) = (uri.scheme_str(), uri.authority()) {
        let pq = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        return Some(format!("{s}://{a}{pq}"));
    }
    let authority = uri
        .authority()
        .map(|a| a.to_string())
        .or_else(|| req.headers().get(http::header::HOST).and_then(|h| h.to_str().ok()).map(|s| s.to_string()))
        .or_else(|| ctx.authority.clone())?;
    let pq = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    // Strip default ports for readability.
    let authority = match (ctx.scheme, authority.strip_suffix(":443"), authority.strip_suffix(":80")) {
        ("https", Some(a), _) => a.to_string(),
        ("http", _, Some(a)) => a.to_string(),
        _ => authority,
    };
    Some(format!("{}://{authority}{pq}", ctx.scheme))
}

/// Upper bound for waiting on an upstream response head. Generous on purpose: long-polling
/// endpoints legitimately hold requests for minutes; this only ends true hangs.
pub(crate) const RESPONSE_HEAD_TIMEOUT: Duration = Duration::from_secs(600);

fn is_self_target(shared: &Shared, url: &str) -> bool {
    let Ok(u) = url.parse::<http::Uri>() else { return false };
    let host = u.host().unwrap_or("").trim_matches(['[', ']']).to_ascii_lowercase();
    if host == "quena.cert" || host == "quena" || host == "ipv4.quena" {
        return true;
    }
    // 0.0.0.0 / :: on our port reach the listener too.
    if (host == "0.0.0.0" || host == "::") && shared.listen.read().iter().any(|a| Some(a.port()) == u.port_u16()) {
        return true;
    }
    let port = u.port_u16().unwrap_or(if u.scheme_str() == Some("https") { 443 } else { 80 });
    let listen = shared.listen.read();
    listen.iter().any(|a| a.port() == port) && (crate::util::is_loopback_host(&host) || quena_platform::local_addresses().iter().any(|(_, ip)| *ip == host))
}

fn error_response(status: StatusCode, msg: &str) -> Response<ProxyBody> {
    let body = format!(
        "<!doctype html><html><head><title>Quena Error</title></head><body style=\"font-family:system-ui;margin:2em\">\
         <h2>[Quena] {}</h2><pre style=\"white-space:pre-wrap\">{}</pre></body></html>",
        status.canonical_reason().unwrap_or(""),
        html_escape(msg)
    );
    let mut r = Response::new(full(body));
    *r.status_mut() = status;
    r.headers_mut().insert(http::header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    r.headers_mut().insert("x-quena-error", HeaderValue::from_static("1"));
    r.headers_mut().insert(http::header::CACHE_CONTROL, HeaderValue::from_static("no-cache, must-revalidate"));
    r
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn headers_only(cfg: &ProxyConfig, host: &str, ct: Option<&str>) -> bool {
    host_matches(&cfg.headers_only_hosts, host) || ct.is_some_and(|ct| cfg.headers_only_types.iter().any(|t| ct.to_ascii_lowercase().contains(t.as_str())))
}

/// Largest body held back completely (breakpoints, rules that edit bodies, automatic
/// authentication, "Stream" off). Larger bodies fail the session with a clear message
/// instead of filling the disk while the peer waits.
const MAX_BUFFERED_BODY: u64 = 512 << 20;

/// Read a body completely into the store (lossless, bypasses the recorder queue).
pub(crate) async fn buffer_body<B>(shared: &Shared, mut body: B) -> Result<(StoredBody, bool), BoxError>
where
    B: http_body::Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    let cap = shared.capture();
    let mut w = cap.bodies.writer_with_limit(u64::MAX);
    let mut aborted = false;
    loop {
        match body.frame().await {
            Some(Ok(f)) => {
                if let Some(d) = f.data_ref() {
                    tokio::task::block_in_place(|| w.write(d)).map_err(|e| Box::new(e) as BoxError)?;
                    if w.body().len() > MAX_BUFFERED_BODY {
                        return Err(format!("the body is larger than {} MB and cannot be held back completely (breakpoint, rule, authentication or Stream off)", MAX_BUFFERED_BODY >> 20).into());
                    }
                }
            }
            Some(Err(e)) => {
                let e: BoxError = e.into();
                tracing::debug!("body read aborted: {e}");
                aborted = true;
                break;
            }
            None => break,
        }
    }
    Ok((w.finish(), aborted))
}

/// A hold-back gives up after this long and forwards what it has, then the rest as it comes:
/// a slow or progressive body must not stall the peer behind a rule that edits bodies.
const HOLD_BACK_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// All bodies held back at the same time share this much memory; beyond it a body streams
/// unchanged (many large matching responses in parallel must not exhaust memory).
const HOLD_BACK_BUDGET: u64 = 256 << 20;
static HELD_BACK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Bytes of one hold-back counted in [`HELD_BACK`] (released when it ends).
struct HeldBytes(u64);

impl HeldBytes {
    fn add(&mut self, n: u64) -> bool {
        self.0 += n;
        HELD_BACK.fetch_add(n, Ordering::Relaxed) + n <= HOLD_BACK_BUDGET
    }
}

impl Drop for HeldBytes {
    fn drop(&mut self) {
        HELD_BACK.fetch_sub(self.0, Ordering::Relaxed);
    }
}

pub(crate) enum HeldBack<B> {
    /// The whole body, in the store (and whether the peer aborted it).
    Complete(StoredBody, bool),
    /// Too large or too slow: the frames read so far in front of the rest, and why.
    GaveUp(Prefixed<B>, String),
}

/// Read a body for a hook that only wants it when it is small: up to `limit` bytes within
/// [`HOLD_BACK_WAIT`] (in memory), else hand it back for streaming.
pub(crate) async fn hold_back<B>(shared: &Shared, mut body: Prefixed<B>, limit: u64) -> Result<HeldBack<B>, BoxError>
where
    B: http_body::Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    let deadline = tokio::time::Instant::now() + HOLD_BACK_WAIT;
    let mut frames = std::collections::VecDeque::new();
    let mut len = 0u64;
    let mut held = HeldBytes(0);
    let mut aborted = false;
    loop {
        let frame = match tokio::time::timeout_at(deadline, body.frame()).await {
            Ok(f) => f,
            Err(_) => return Ok(HeldBack::GaveUp(body.unread(frames), format!("not complete within {} s", HOLD_BACK_WAIT.as_secs()))),
        };
        match frame {
            Some(Ok(f)) => {
                let n = f.data_ref().map_or(0, |d| d.len() as u64);
                len += n;
                frames.push_back(f);
                if len > limit {
                    return Ok(HeldBack::GaveUp(body.unread(frames), format!("larger than {} KiB", limit >> 10)));
                }
                if !held.add(n) {
                    return Ok(HeldBack::GaveUp(body.unread(frames), format!("not held back: {} MiB are held back already", HOLD_BACK_BUDGET >> 20)));
                }
            }
            Some(Err(e)) => {
                tracing::debug!("body read aborted: {e}");
                aborted = true;
                break;
            }
            None => break,
        }
    }
    let mut w = shared.capture().bodies.writer_with_limit(u64::MAX);
    for f in &frames {
        if let Some(d) = f.data_ref() {
            tokio::task::block_in_place(|| w.write(d)).map_err(|e| Box::new(e) as BoxError)?;
        }
    }
    Ok(HeldBack::Complete(w.finish(), aborted))
}

/// Say in the session why a body a rule wanted was forwarded unchanged.
fn note_gave_up(live: &LiveSession, part: &str, why: &str) {
    let text = format!("{part} body {why}; forwarded unchanged");
    live.update(move |d| {
        d.extra_flags.retain(|(k, _)| k != "x-quena-held-back");
        d.extra_flags.push(("x-quena-held-back".into(), text));
    });
}

/// Entry point for every proxied request.
pub async fn handle(ctx: Arc<ConnCtx>, mut req: Request<Incoming>) -> Result<Response<ProxyBody>, Infallible> {
    let shared = ctx.shared.clone();
    // On a reverse proxy port every request goes to the route's target; how the client
    // addressed Quena is kept for the response headers that name the target.
    let (url, reverse) = match &ctx.reverse {
        Some(r) => {
            let (url, routed) = r.upstream_url(req.uri());
            (url, Some(ReverseOut { route: r.clone(), client_origin: crate::reverse::client_origin(&req, ctx.scheme, r.port), routed }))
        }
        None => {
            let Some(url) = absolute_url(&req, &ctx) else {
                return Ok(crate::landing::serve(&shared, &req));
            };
            if is_self_target(&shared, &url) {
                return Ok(crate::landing::serve(&shared, &req));
            }
            (url, None)
        }
    };
    let cfg = shared.cfg();
    // Host remapping: without "keep host" the request is addressed to the target.
    let remapped = url.parse::<http::Uri>().ok().and_then(|u| {
        let https = matches!(u.scheme_str(), Some("https" | "wss"));
        cfg.remap(u.host()?, u.port_u16().unwrap_or(if https { 443 } else { 80 }))
    });
    let url = match &remapped {
        Some(r) if !r.keep_host => crate::remap::rewrite_url(&url, r).unwrap_or(url),
        Some(r) if r.scheme.is_some() => crate::remap::rescheme_url(&url, r).unwrap_or(url),
        _ => url,
    };
    let capture = shared.capture();
    let now = now_us();
    let h1 = is_h1(req.version());
    let mut head = RequestHead { method: req.method().to_string(), url: url.clone(), version: version_of(req.version()), headers: record_headers(req.headers(), h1) };
    if let Some(r) = &reverse {
        r.prepare_request(&mut head, &ctx, &req);
    }
    if let Some(r) = remapped.as_ref().filter(|r| !r.keep_host) {
        if head.headers.get("host").is_some() {
            head.headers.set("host", r.authority(url.starts_with("https://") || url.starts_with("wss://")));
        }
    }
    let process = ctx.process().await;
    let client_ip = ctx.client_addr.ip().to_canonical().to_string();
    let live = capture.begin(SessionKind::Http, |d| {
        d.request = head.clone();
        d.process = process.clone();
        d.connection.client_addr = Some(ctx.client_addr.to_string());
        d.connection.client_conn_id = Some(ctx.conn_id);
        d.connection.client_tls = ctx.client_tls.clone();
        d.timers.client_connected = Some(ctx.connected_at);
        d.timers.client_begin_request = Some(now);
        d.timers.got_request_headers = Some(now);
        d.summary.client_ip = client_ip.clone();
        d.summary.state = SessionState::SendingRequest;
        if ctx.decrypted {
            d.summary.flags |= flags::DECRYPTED;
        }
        if ctx.remote {
            d.summary.flags |= flags::REMOTE_CLIENT;
        }
        if let Some(v) = &ctx.via {
            d.extra_flags.push((crate::reverse::FLAG.into(), v.clone()));
        }
        if let Some(r) = &remapped {
            d.extra_flags.push((crate::remap::FLAG.into(), r.note.clone()));
        }
    });
    // Client gone (hyper drops this future), panic, or a forgotten path: end the session.
    let mut guard = live.abort_on_drop("the client closed the connection before the session completed");
    let view = SessionView { id: live.id, live: live.clone(), process: process.as_ref().map(|p| p.display()).unwrap_or_default(), client_ip };
    let hooks = shared.hooks();
    let upgrade_req = req.headers().get(http::header::UPGRADE).is_some() && h1;
    let client_upgrade = if upgrade_req { Some(hyper::upgrade::on(&mut req)) } else { None };
    let (_parts, incoming) = req.into_parts();

    // --- request body: stream through the tee, or buffer for the hook
    let mode = hooks.request_mode(&view, &head);
    let mut source = Some(Prefixed::new(incoming));
    let mut buffered_req: Option<StoredBody> = None;
    if mode == Mode::Buffer {
        // Buffering is not pausing: a breakpoint sets its own state when it holds the request.
        live.update(|d| d.summary.state = SessionState::SendingRequest);
        let src = source.take().expect("request body");
        let r = match hooks.request_hold_limit(&view, &head) {
            Some(limit) => hold_back(&shared, src, limit).await,
            None => buffer_body(&shared, src).await.map(|(b, a)| HeldBack::Complete(b, a)),
        };
        match r {
            Ok(HeldBack::Complete(b, _)) => {
                live.set_request_body(b.clone());
                live.update(|d| d.timers.client_done_request = Some(now_us()));
                buffered_req = Some(b);
            }
            Ok(HeldBack::GaveUp(p, why)) => {
                note_gave_up(&live, "request", &why);
                source = Some(p);
            }
            Err(e) => {
                finish_error(&live, &format!("reading the request body failed: {e}"));
                return Ok(error_response(StatusCode::BAD_REQUEST, &e.to_string()));
            }
        }
    }
    let req_body_src: Option<ProxyBody> = if let Some(incoming) = source {
        let writer = if headers_only(&cfg, &url_host(&url), head.headers.get("content-type")) { capture.bodies.writer_with_limit(0) } else { capture.bodies.writer() };
        live.set_request_body(writer.body().clone());
        let times = Arc::new(TeeTimes::default());
        let l2 = live.clone();
        let t2 = times.clone();
        let hold = live.hold();
        let key = shared.recorder.open(
            live.id,
            writer,
            Box::new(move |b, _aborted| {
                let _hold = hold;
                l2.set_request_body(b);
                let last = t2.last.load(Ordering::Relaxed);
                l2.update(|d| d.timers.client_done_request = Some(if last > 0 { last } else { now_us() }));
            }),
        );
        Some(Tee::new(incoming, shared.recorder.clone(), key, times).boxed())
    } else {
        None
    };

    // --- request hook
    let action = hooks.on_request(view.clone(), head.clone(), buffered_req.clone()).await;
    let (head, body): (RequestHead, ProxyBody) = match action {
        RequestAction::Abort => {
            live.update(|d| {
                d.summary.state = SessionState::Aborted;
                d.error = Some("aborted by rule".into());
            });
            live.finish();
            // Closing without a response: hyper turns an error into a connection reset.
            return Ok(error_response(StatusCode::BAD_GATEWAY, "Request aborted by Quena rule"));
        }
        RequestAction::Respond { head: rh, body, delay_ms } => {
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            // Drain the request body so it gets recorded.
            if let Some(b) = req_body_src {
                tokio::spawn(async move {
                    let mut b = b;
                    while let Some(Ok(_)) = b.frame().await {}
                });
            }
            return Ok(respond_locally(&shared, &live, &view, rh, body, reverse.as_ref()));
        }
        RequestAction::Forward { head: new_head, body: new_body, delay_ms } => {
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            let tampered = new_head.is_some() || new_body.is_some();
            let head = match new_head {
                Some(h) => {
                    let h2 = h.clone();
                    live.update(move |d| d.request = h2);
                    h
                }
                None => head,
            };
            let body = match (new_body, buffered_req, req_body_src) {
                (Some(b), _, _) => {
                    live.set_request_body(b.clone());
                    StoredStream::new(b).boxed()
                }
                (None, Some(b), _) => StoredStream::new(b).boxed(),
                (None, None, Some(src)) => src,
                (None, None, None) => empty(),
            };
            if tampered {
                live.update(|d| d.summary.flags |= flags::TAMPERED);
            }
            (head, body)
        }
    };

    // --- upstream
    let upgrade = upgrade_req && client_upgrade.is_some();
    let host_only = url_host(&head.url);
    let use_auth = !upgrade && cfg.auto_auth && (cfg.auth_applies(&host_only) || cfg.auto_auth_upstream);
    let resp = if use_auth {
        // Buffer the request body so it can be replayed on the authenticated leg.
        match buffer_body(&shared, body).await {
            Ok((buffered, _)) => {
                live.set_request_body(buffered.clone());
                live.update(|d| d.summary.state = SessionState::AwaitingResponse);
                let mut legs = 1u16;
                let sent = now_us();
                let r = crate::auth::send_with_auth(&shared, &ctx, &head, buffered, &mut |n| legs = legs.max(n as u16)).await;
                match r {
                    Ok(resp) => {
                        record_response_head(&live, &resp, sent, None);
                        if legs > 1 {
                            live.update(move |d| {
                                d.summary.flags |= flags::REPLAYED; // reuse until a dedicated AUTH flag
                                if d.summary.custom.is_empty() {
                                    d.summary.custom = format!("auth {legs} legs");
                                }
                            });
                        }
                        resp
                    }
                    Err(e) => {
                        let msg = format!("The connection to '{host_only}' failed.\nError: {e}");
                        let resp = error_response(StatusCode::BAD_GATEWAY, &msg);
                        record_synthetic_response(&shared, &live, &resp, msg.clone());
                        return Ok(resp);
                    }
                }
            }
            Err(e) => {
                finish_error(&live, &format!("reading the request body failed: {e}"));
                return Ok(error_response(StatusCode::BAD_REQUEST, &e.to_string()));
            }
        }
    } else {
        match send_upstream(&shared, &live, &head, body, upgrade).await {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("The connection to '{}' failed.\nError: {e}", url_host(&head.url));
                let resp = error_response(StatusCode::BAD_GATEWAY, &msg);
                record_synthetic_response(&shared, &live, &resp, msg.clone());
                return Ok(resp);
            }
        }
    };

    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        if let Some(cu) = client_upgrade {
            guard.disarm(); // the WebSocket pump finishes the session
            return Ok(crate::tunnel::websocket(&shared, &live, &view, resp, cu));
        }
    }
    Ok(deliver_response(&shared, &live, &view, &head, resp, &mut guard, reverse.as_ref()).await)
}

/// Reverse proxy handling of one request: the route and how the client addressed Quena.
struct ReverseOut {
    route: Arc<crate::reverse::ReverseRoute>,
    client_origin: String,
    /// The target the request went to (path routes).
    routed: crate::reverse::Routed,
}

impl ReverseOut {
    /// Host and forwarding headers of the request sent to the target.
    fn prepare_request(&self, head: &mut RequestHead, ctx: &ConnCtx, req: &Request<Incoming>) {
        let route = &self.route;
        let client_host = self.client_origin.split_once("://").map(|(_, h)| h.to_string()).unwrap_or_default();
        // Names as the client's HTTP version records them (Title-Case for HTTP/1).
        let h1 = is_h1(req.version());
        let name = |n: &str| if h1 { title_case(n) } else { n.to_string() };
        if route.preserve_host {
            // HTTP/2 clients send `:authority` only; the target still needs a Host.
            if head.headers.get("host").is_none() {
                head.headers.push(name("host"), client_host.clone());
            }
        } else if head.headers.get("host").is_some() {
            head.headers.set("host", self.routed.target.authority.clone());
        }
        if route.forwarded_headers {
            let ip = ctx.client_addr.ip().to_canonical().to_string();
            let xff = match head.headers.get("x-forwarded-for") {
                Some(prev) => format!("{prev}, {ip}"),
                None => ip,
            };
            for (n, v) in [("x-forwarded-for", xff), ("x-forwarded-proto", ctx.scheme.to_string()), ("x-forwarded-host", client_host)] {
                head.headers.remove(n);
                head.headers.push(name(n), v);
            }
        }
    }

    /// Point response headers that name the target back to Quena; note it in the session.
    fn apply(&self, live: &LiveSession, headers: &mut http::HeaderMap) {
        let notes = self.route.rewrite_response(headers, &self.client_origin, &self.routed);
        if !notes.is_empty() {
            let text = notes.join("; ");
            live.update(move |d| {
                d.extra_flags.retain(|(k, _)| k != crate::reverse::REWRITE_FLAG);
                d.extra_flags.push((crate::reverse::REWRITE_FLAG.into(), text));
            });
        }
    }
}

fn url_host(url: &str) -> String {
    split_url(url, "GET").0
}

pub(crate) fn url_host_pub(url: &str) -> String {
    url_host(url)
}

pub(crate) fn to_header_map_pub(h: &Headers, skip_hop: bool, keep_upgrade: bool) -> http::HeaderMap {
    to_header_map(h, skip_hop, keep_upgrade)
}

/// Send a request upstream and record connection details and the response head.
pub(crate) async fn send_upstream(
    shared: &Arc<Shared>,
    live: &Arc<LiveSession>,
    head: &RequestHead,
    body: ProxyBody,
    upgrade: bool,
) -> Result<Response<Incoming>, String> {
    send_upstream_as(shared, live, head, body, upgrade, None).await
}

/// [`send_upstream`] with the HTTP version forced (`Some(true)`: HTTP/2, `Some(false)`: HTTP/1.1).
pub(crate) async fn send_upstream_as(
    shared: &Arc<Shared>,
    live: &Arc<LiveSession>,
    head: &RequestHead,
    body: ProxyBody,
    upgrade: bool,
    force_h2: Option<bool>,
) -> Result<Response<Incoming>, String> {
    let uri: http::Uri = head.url.parse().map_err(|e| format!("invalid URL {}: {e}", head.url))?;
    let mut req = Request::builder()
        .method(http::Method::from_bytes(head.method.as_bytes()).map_err(|e| e.to_string())?)
        .uri(uri)
        .version(if force_h2 == Some(true) { Version::HTTP_2 } else { Version::HTTP_11 })
        .body(body)
        .map_err(|e| e.to_string())?;
    *req.headers_mut() = to_header_map(&head.headers, true, upgrade);
    let captured = capture_connection(&mut req);
    live.update(|d| {
        d.timers.server_connect_start = Some(now_us());
        d.summary.state = SessionState::AwaitingResponse;
    });
    let up = shared.upstream();
    let client = match force_h2 {
        Some(true) => &up.http2,
        Some(false) => &up.http1,
        None => &up.client,
    };
    let sent = now_us();
    let result = match tokio::time::timeout(RESPONSE_HEAD_TIMEOUT, client.request(req)).await {
        Ok(r) => r,
        Err(_) => return Err(format!("no response from the server within {} s", RESPONSE_HEAD_TIMEOUT.as_secs())),
    };
    // Connection metadata (also available on errors after connecting).
    let mut ext = http::Extensions::new();
    if let Some(c) = captured.connection_metadata().as_ref() {
        c.get_extras(&mut ext);
    }
    let info = ext.get::<ConnInfo>().cloned();
    let resp = result.map_err(|e| {
        let mut msg = e.to_string();
        let mut src = std::error::Error::source(&e);
        while let Some(s) = src {
            msg.push_str(&format!(": {s}"));
            src = s.source();
        }
        msg
    })?;
    record_response_head(live, &resp, sent, info.as_ref());
    Ok(resp)
}

/// Record an upstream response head + connection timings into the session.
pub(crate) fn record_response_head(live: &Arc<LiveSession>, resp: &Response<Incoming>, sent: i64, info: Option<&ConnInfo>) {
    let got = now_us();
    let h1 = is_h1(resp.version());
    let reason = resp
        .extensions()
        .get::<hyper::ext::ReasonPhrase>()
        .map(|r| String::from_utf8_lossy(r.as_bytes()).into_owned())
        .unwrap_or_else(|| resp.status().canonical_reason().unwrap_or("").to_string());
    let rh = ResponseHead { status: resp.status().as_u16(), reason, version: version_of(resp.version()), headers: record_headers(resp.headers(), h1) };
    let info = info.cloned();
    live.update(move |d| {
        if let Some(i) = &info {
            let reused = i.used.swap(true, Ordering::Relaxed);
            d.connection.server_addr = Some(i.server_addr.clone());
            d.connection.server_conn_reused = reused;
            d.connection.gateway = i.gateway.clone();
            d.connection.server_tls = i.tls.clone();
            if let Some(w) = i.tls.as_ref().and_then(|t| t.warning.clone())
                && !d.extra_flags.iter().any(|(k, _)| k == quena_model::CERT_FLAG)
            {
                d.extra_flags.push((quena_model::CERT_FLAG.into(), w));
            }
            if !reused {
                d.timers.dns_ms = Some(i.dns_ms);
                d.timers.tcp_connect_ms = Some(i.tcp_ms);
                d.timers.tls_handshake_ms = if i.tls.is_some() { Some(i.tls_ms) } else { None };
                d.timers.server_connect_start = Some(i.connect_start);
                d.timers.server_connected = Some(i.connected_at);
            }
        }
        d.timers.server_begin_request = Some(sent);
        d.timers.server_got_first_byte = Some(got);
        d.timers.got_response_headers = Some(got);
        d.response = Some(rh);
        d.summary.state = SessionState::ReceivingResponse;
    });
}

/// Stream (or buffer) the upstream response to the client while recording it.
async fn deliver_response(
    shared: &Arc<Shared>,
    live: &Arc<LiveSession>,
    view: &SessionView,
    req_head: &RequestHead,
    resp: Response<Incoming>,
    guard: &mut quena_store::AbortOnDrop,
    reverse: Option<&ReverseOut>,
) -> Response<ProxyBody> {
    let cfg = shared.cfg();
    let hooks = shared.hooks();
    let (mut parts, incoming) = resp.into_parts();
    let mut resp_head = live.detail().response.unwrap_or_default();
    // Head-only script hook — runs in both streaming and buffering modes, but only
    // when a script is actually active (avoids per-response clones otherwise).
    match if hooks.wants_response_head(view) {
        hooks.on_response_head(view.clone(), resp_head.clone()).await
    } else {
        ResponseHeadAction::Continue
    } {
        ResponseHeadAction::Continue => {}
        ResponseHeadAction::Replace(h) => {
            // Apply to the outgoing http parts too, since the streaming path
            // sends `parts` verbatim to the client (not `resp_head`).
            parts.status = StatusCode::from_u16(h.status).unwrap_or(parts.status);
            parts.headers = to_header_map(&h.headers, true, false);
            resp_head = h.clone();
            live.update(move |d| {
                d.response = Some(h);
                d.summary.flags |= flags::TAMPERED;
            });
        }
        ResponseHeadAction::Abort => {
            finish_error(live, "aborted by script");
            return error_response(StatusCode::BAD_GATEWAY, "Response aborted in Quena");
        }
    }
    // Bandwidth simulation: an optional fixed latency before the response, and a
    // byte-rate cap applied to the streamed body.
    if cfg.throttle_latency_ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(cfg.throttle_latency_ms)).await;
    }
    let throttle = |b: ProxyBody| -> ProxyBody {
        if cfg.throttle_bps > 0 {
            crate::body::Throttle::new(b, cfg.throttle_bps).boxed()
        } else {
            b
        }
    };
    let mut mode = hooks.response_mode(view, req_head, &resp_head);
    // Event streams never end; buffering them would only stall the client.
    let endless = resp_head.headers.get("content-type").is_some_and(|ct| ct.to_ascii_lowercase().starts_with("text/event-stream"));
    let mut source = Some(Prefixed::new(incoming));
    let mut held = None;
    if mode == Mode::Buffer
        && cfg.stream
        && let Some(limit) = hooks.response_hold_limit(view, req_head, &resp_head)
    {
        match hold_back(shared, source.take().expect("response body"), limit).await {
            Ok(HeldBack::Complete(b, aborted)) => held = Some((b, aborted)),
            Ok(HeldBack::GaveUp(p, why)) => {
                note_gave_up(live, "response", &why);
                source = Some(p);
                mode = Mode::Stream;
            }
            Err(e) => {
                finish_error(live, &e.to_string());
                return error_response(StatusCode::BAD_GATEWAY, &e.to_string());
            }
        }
    }
    if mode == Mode::Buffer || (!cfg.stream && !endless) {
        let buffered = match held {
            Some(v) => Ok(v),
            None => buffer_body(shared, source.take().expect("response body")).await,
        };
        let (body, aborted) = match buffered {
            Ok(v) => v,
            Err(e) => {
                finish_error(live, &e.to_string());
                return error_response(StatusCode::BAD_GATEWAY, &e.to_string());
            }
        };
        live.set_response_body(body.clone());
        live.update(|d| d.timers.server_done_response = Some(now_us()));
        let (head, body) = if mode == Mode::Buffer {
            match hooks.on_response(view.clone(), resp_head.clone(), body.clone()).await {
                ResponseAction::Continue => (resp_head, body),
                ResponseAction::Replace { head, body: nb } => {
                    let b = nb.unwrap_or(body);
                    live.set_response_body(b.clone());
                    let h2 = head.clone();
                    live.update(move |d| {
                        d.response = Some(h2);
                        d.summary.flags |= flags::TAMPERED;
                    });
                    (head, b)
                }
                ResponseAction::Abort => {
                    finish_error(live, "aborted at breakpoint");
                    return error_response(StatusCode::BAD_GATEWAY, "Response aborted in Quena");
                }
            }
        } else {
            (resp_head, body)
        };
        let len = body.len();
        let mut out = build_client_response(&head, throttle(StoredStream::new(body).boxed()), Some(len));
        if let Some(r) = reverse {
            r.apply(live, out.headers_mut());
        }
        live.update(|d| {
            d.summary.state = if aborted { SessionState::Aborted } else { SessionState::Done };
            d.timers.client_begin_response = Some(now_us());
            d.timers.client_done_response = Some(now_us());
        });
        live.finish();
        hooks.on_complete(view);
        return out;
    }
    // Streaming.
    let capture = shared.capture();
    let ct = resp_head.headers.get("content-type").map(|s| s.to_string());
    let writer = if headers_only(&cfg, &url_host(&req_head.url), ct.as_deref()) { capture.bodies.writer_with_limit(0) } else { capture.bodies.writer() };
    live.set_response_body(writer.body().clone());
    let times = Arc::new(TeeTimes::default());
    let l2 = live.clone();
    let t2 = times.clone();
    let hooks2 = hooks.clone();
    let view2 = view.clone();
    let expected = parts.headers.get(http::header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
    let hold = live.hold();
    let key = shared.recorder.open(
        live.id,
        writer,
        Box::new(move |b, aborted| {
            let wire = b.wire_len();
            l2.set_response_body(b);
            let last = t2.last.load(Ordering::Relaxed);
            let end = if last > 0 { last } else { now_us() };
            let incomplete = expected.is_some_and(|e| wire < e);
            l2.update(|d| {
                d.timers.server_done_response = Some(end);
                d.timers.client_done_response = Some(end);
                if aborted || incomplete {
                    d.summary.state = SessionState::Aborted;
                    d.summary.flags |= flags::CLIENT_ABORTED;
                    if d.error.is_none() {
                        d.error = Some(match expected {
                            Some(e) => format!("connection closed after {wire} of {e} bytes"),
                            None => format!("connection closed after {wire} bytes"),
                        });
                    }
                } else {
                    d.summary.state = SessionState::Done;
                }
            });
            // Release our own hold first, so finish only waits for other bodies.
            drop(hold);
            l2.finish();
            hooks2.on_complete(&view2);
        }),
    );
    if let Some(r) = reverse {
        r.apply(live, &mut parts.headers);
    }
    // From here the streaming body (its recorder callback) finishes the session.
    guard.disarm();
    live.update(|d| d.timers.client_begin_response = Some(now_us()));
    let incoming = source.take().expect("response body");
    let body = throttle(Tee::new(incoming, shared.recorder.clone(), key, times).boxed());
    let mut out = Response::from_parts(parts, body);
    strip_hop_by_hop(out.headers_mut());
    out
}

fn strip_hop_by_hop(h: &mut http::HeaderMap) {
    let tokens: Vec<String> = h
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .collect();
    for t in tokens {
        if let Ok(n) = HeaderName::from_bytes(t.as_bytes()) {
            h.remove(n);
        }
    }
    for n in HOP_BY_HOP {
        h.remove(*n);
    }
}

pub(crate) fn build_client_response(head: &ResponseHead, body: ProxyBody, len: Option<u64>) -> Response<ProxyBody> {
    let mut r = Response::new(body);
    *r.status_mut() = StatusCode::from_u16(head.status).unwrap_or(StatusCode::OK);
    *r.headers_mut() = to_header_map(&head.headers, true, false);
    if let Some(len) = len {
        if !(head.status == 204 || head.status == 304 || (100..200).contains(&head.status)) {
            r.headers_mut().insert(http::header::CONTENT_LENGTH, HeaderValue::from(len));
        }
    }
    if !head.reason.is_empty() && Some(head.reason.as_str()) != r.status().canonical_reason() {
        if let Ok(rp) = hyper::ext::ReasonPhrase::try_from(head.reason.clone().into_bytes()) {
            r.extensions_mut().insert(rp);
        }
    }
    r
}

fn respond_locally(shared: &Arc<Shared>, live: &Arc<LiveSession>, view: &SessionView, head: ResponseHead, body: StoredBody, reverse: Option<&ReverseOut>) -> Response<ProxyBody> {
    // A HEAD response announces the length of the body a GET would get (a recorded
    // Content-Length); it never has a body of its own, so 0 would be wrong.
    let head_request = live.detail().request.method.eq_ignore_ascii_case("HEAD");
    let len = body.len();
    let out_len = if head_request && len == 0 && head.headers.get("content-length").is_some() { None } else { Some(len) };
    let mut out = build_client_response(&head, StoredStream::new(body.clone()).boxed(), out_len);
    if let Some(r) = reverse {
        r.apply(live, out.headers_mut());
    }
    live.set_response_body(body);
    let h2 = head.clone();
    live.update(move |d| {
        let now = now_us();
        d.response = Some(h2);
        d.summary.flags |= flags::AUTO_RESPONDED;
        d.summary.state = SessionState::Done;
        d.timers.got_response_headers = Some(now);
        d.timers.client_begin_response = Some(now);
        d.timers.client_done_response = Some(now);
    });
    live.finish();
    shared.hooks().on_complete(view);
    out
}

fn record_synthetic_response(shared: &Arc<Shared>, live: &Arc<LiveSession>, resp: &Response<ProxyBody>, error: String) {
    let head = ResponseHead {
        status: resp.status().as_u16(),
        reason: resp.status().canonical_reason().unwrap_or("").into(),
        version: HttpVersion::Http11,
        headers: record_headers(resp.headers(), true),
    };
    let body = shared.capture().bodies.store_bytes(error.as_bytes());
    live.set_response_body(body);
    live.update(|d| {
        let now = now_us();
        d.response = Some(head);
        d.error = Some(error.lines().last().unwrap_or("").to_string());
        d.summary.state = SessionState::Done;
        d.summary.flags |= flags::SERVER_ABORTED;
        d.timers.client_done_response = Some(now);
    });
    live.finish();
}

fn finish_error(live: &Arc<LiveSession>, msg: &str) {
    live.update(|d| {
        d.summary.state = SessionState::Aborted;
        d.error = Some(msg.to_string());
        d.timers.client_done_response = Some(now_us());
    });
    live.finish();
}

// ----------------------------------------------------------------- execute

/// Options for requests issued by Quena itself (Composer, Replay).
#[derive(Debug, Clone, Default)]
pub struct ExecuteOptions {
    pub flags: u32,
    pub comment: Option<String>,
    /// Run the request through the interceptor (breakpoints, AutoResponder).
    pub hooks: bool,
    /// Force the HTTP version: `Some(true)` HTTP/2, `Some(false)` HTTP/1.1, `None` as usual.
    pub force_h2: Option<bool>,
}

/// Issue a request from Quena (Composer/Replay) and record it as a new session.
pub async fn execute(shared: Arc<Shared>, head: RequestHead, body: StoredBody, opts: ExecuteOptions) -> SessionId {
    execute_with(shared, head, body, opts, |_| {}).await
}

/// Like [`execute`], calling `started` with the session id as soon as the session exists.
pub async fn execute_with(shared: Arc<Shared>, head: RequestHead, body: StoredBody, opts: ExecuteOptions, started: impl FnOnce(SessionId) + Send) -> SessionId {
    let capture = shared.capture();
    let now = now_us();
    let live = capture.begin(SessionKind::Http, |d| {
        d.request = head.clone();
        d.process = Some(ProcessInfo { pid: std::process::id(), name: "quena".into() });
        d.timers.client_begin_request = Some(now);
        d.timers.got_request_headers = Some(now);
        d.timers.client_done_request = Some(now);
        d.summary.flags |= opts.flags;
        d.summary.state = SessionState::SendingRequest;
        if let Some(c) = &opts.comment {
            d.summary.comment = c.clone();
        }
    });
    live.set_request_body(body.clone());
    live.update(|_| {});
    let mut guard = live.abort_on_drop("the request was cancelled before it completed");
    let id = live.id;
    started(id);
    let view = SessionView { id, live: live.clone(), process: "quena".into(), client_ip: String::new() };
    let hooks = shared.hooks();
    let (head, body) = if opts.hooks {
        match hooks.on_request(view.clone(), head.clone(), Some(body.clone())).await {
            RequestAction::Abort => {
                finish_error(&live, "aborted by rule");
                return id;
            }
            RequestAction::Respond { head: rh, body, .. } => {
                let _ = respond_locally(&shared, &live, &view, rh, body, None);
                return id;
            }
            RequestAction::Forward { head: h, body: b, delay_ms } => {
                if delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                (h.unwrap_or(head), b.unwrap_or(body))
            }
        }
    } else {
        (head, body)
    };
    match send_upstream_as(&shared, &live, &head, StoredStream::new(body).boxed(), false, opts.force_h2).await {
        Ok(resp) => {
            let r = deliver_response(&shared, &live, &view, &head, resp, &mut guard, None).await;
            // Consume the body so it gets recorded.
            let mut b = r.into_body();
            while let Some(f) = b.frame().await {
                if f.is_err() {
                    break;
                }
            }
        }
        Err(e) => {
            let msg = format!("The connection to '{}' failed.\nError: {e}", url_host(&head.url));
            let resp = error_response(StatusCode::BAD_GATEWAY, &msg);
            record_synthetic_response(&shared, &live, &resp, msg);
        }
    }
    id
}

#[cfg(test)]
mod hold_back_tests {
    use super::*;

    #[test]
    fn held_bytes_are_counted_and_released() {
        let before = HELD_BACK.load(Ordering::Relaxed);
        {
            let mut h = HeldBytes(0);
            assert!(h.add(10));
            assert!(h.add(20));
            assert_eq!(HELD_BACK.load(Ordering::Relaxed), before + 30);
            // Beyond the budget the add reports it (the bytes are still counted until drop).
            assert!(!h.add(HOLD_BACK_BUDGET));
        }
        assert_eq!(HELD_BACK.load(Ordering::Relaxed), before);
    }
}
