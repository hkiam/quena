//! Client connections: HTTP/1.1 server, CONNECT, HTTPS interception.

use crate::Shared;
use crate::body::{ProxyBody, full};
use crate::forward::{self, ConnCtx};
use crate::tunnel;
use crate::util::split_host_port;
use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use quena_model::*;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::watch;

/// A client must deliver a complete request head within this time (slowloris guard). hyper
/// applies it to idle keep-alive connections as well, so idle client connections close.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Handshake with the client after its ClientHello (it may stall or never finish).
const CLIENT_TLS_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn handle_client(
    shared: Arc<Shared>,
    stream: TcpStream,
    peer: SocketAddr,
    listener: Option<Arc<crate::listener::Listener>>,
) {
    use crate::listener::Listener;
    let cfg = shared.cfg();
    let allowed = match &listener {
        Some(l) => cfg.client_allowed_with(peer.ip(), l.allow_remote()),
        None => cfg.client_allowed(peer.ip()),
    };
    if !allowed {
        tracing::warn!(target: "quena::proxy", "rejected connection from {} (not in the remote allowlist)", peer.ip().to_canonical());
        return;
    }
    let _ = stream.set_nodelay(true);
    let remote = !peer.ip().to_canonical().is_loopback();
    let local_port = stream.local_addr().map(|a| a.port()).unwrap_or(cfg.port);
    let (ptx, prx) = watch::channel(None);
    if remote {
        let _ = ptx.send(Some(None));
    } else {
        let s2 = shared.clone();
        tokio::task::spawn_blocking(move || {
            let p = s2.process.lookup(peer.port(), local_port);
            let _ = ptx.send(Some(p));
        });
    }
    let ctx = Arc::new(ConnCtx {
        shared: shared.clone(),
        conn_id: shared.conn_ids.fetch_add(1, Ordering::Relaxed),
        client_addr: peer,
        remote,
        process: prx,
        scheme: "http",
        authority: None,
        client_tls: None,
        connected_at: now_us(),
        decrypted: false,
        auth_clients: parking_lot::Mutex::new(std::collections::HashMap::new()),
        reverse: match listener.as_deref() {
            Some(Listener::Reverse(r)) => Some(r.clone()),
            _ => None,
        },
        via: listener.as_ref().map(|l| l.name()),
    });
    match listener.as_deref() {
        None => serve_h1(ctx, stream).await,
        Some(Listener::Reverse(_)) => crate::reverse::serve(ctx, stream).await,
        Some(Listener::Socks(_)) => crate::socks::serve(ctx, stream).await,
        Some(Listener::Transparent(_)) => crate::transparent::serve(ctx, stream).await,
    }
}

/// How a tunnel session came about, for its text.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum TunnelKind {
    Connect,
    Socks,
    Transparent,
}

impl TunnelKind {
    fn label(self) -> &'static str {
        match self {
            TunnelKind::Connect => "CONNECT tunnel",
            TunnelKind::Socks => "SOCKS connection",
            TunnelKind::Transparent => "transparently redirected connection",
        }
    }
}

/// Record a tunnel session (CONNECT, SOCKS, transparent) to `target` and reply nothing yet;
/// [`tunnel_or_intercept`] finishes it.
pub(crate) async fn begin_tunnel(
    ctx: &ConnCtx,
    target: &str,
    headers: Headers,
) -> (Arc<quena_store::LiveSession>, Option<ProcessInfo>) {
    let shared = ctx.shared.clone();
    let capture = shared.capture();
    let process = ctx.process().await;
    let now = now_us();
    let head = RequestHead {
        method: "CONNECT".into(),
        url: target.to_string(),
        version: HttpVersion::Http11,
        headers,
    };
    let live = capture.begin(SessionKind::Tunnel, |d| {
        d.request = head;
        d.process = process.clone();
        d.connection.client_addr = Some(ctx.client_addr.to_string());
        d.connection.client_conn_id = Some(ctx.conn_id);
        d.timers.client_connected = Some(ctx.connected_at);
        d.timers.client_begin_request = Some(now);
        d.timers.got_request_headers = Some(now);
        d.timers.client_done_request = Some(now);
        d.summary.client_ip = ctx.client_addr.ip().to_canonical().to_string();
        d.summary.state = SessionState::ReceivingResponse;
        if ctx.remote {
            d.summary.flags |= flags::REMOTE_CLIENT;
        }
        if let Some(v) = &ctx.via {
            d.extra_flags
                .push((quena_model::VIA_FLAG.into(), v.clone()));
        }
    });
    let mut rh = Headers::new();
    // PAC evaluation may block (script, DNS): keep it off the async workers.
    let gateway = crate::resolve_upstream(&shared.cfg(), target.to_string()).await;
    rh.push(
        "Quena-Gateway",
        gateway
            .map(|(h, p)| format!("{h}:{p}"))
            .unwrap_or_else(|| "Direct".into()),
    );
    live.update(|d| {
        d.response = Some(ResponseHead {
            status: 200,
            reason: "Connection Established".into(),
            version: HttpVersion::Http11,
            headers: rh,
        });
        d.timers.got_response_headers = Some(now_us());
    });
    (live, process)
}

/// Run a tunnel that a SOCKS or transparent client opened: decrypt, record plain HTTP, or
/// pass it through; the session ends with it.
pub(crate) async fn run_tunnel<S>(
    ctx: Arc<ConnCtx>,
    live: Arc<quena_store::LiveSession>,
    process: Option<ProcessInfo>,
    io: S,
    host: String,
    port: u16,
    kind: TunnelKind,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let _guard = live.abort_on_drop("the tunnel ended unexpectedly");
    let target = crate::util::join_host_port(&host, port);
    let proc_name = process.map(|p| p.display()).unwrap_or_default();
    let f: Pin<Box<dyn std::future::Future<Output = ()> + Send>> = Box::pin(tunnel_or_intercept(
        ctx, live, io, host, port, target, proc_name, kind,
    ));
    f.await
}

/// Bytes a client sent before its first request was parsed, kept so that a request hyper
/// rejects as malformed can still be shown as a session.
const MALFORMED_KEEP: usize = 16 * 1024;

struct FirstBytes<S> {
    inner: S,
    seen: Arc<parking_lot::Mutex<Vec<u8>>>,
    /// Cleared as soon as a request was parsed (only the first request is of interest).
    active: Arc<std::sync::atomic::AtomicBool>,
}

impl<S: AsyncRead + Unpin> AsyncRead for FirstBytes<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if self.active.load(Ordering::Relaxed) {
            let new = &buf.filled()[before..];
            let mut seen = self.seen.lock();
            let room = MALFORMED_KEEP.saturating_sub(seen.len());
            seen.extend_from_slice(&new[..new.len().min(room)]);
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FirstBytes<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Record a request the HTTP parser rejected (hyper answered it with 400/431 itself).
fn record_malformed(ctx: &ConnCtx, raw: Vec<u8>, err: &hyper::Error) {
    let text = String::from_utf8_lossy(&raw[..raw.len().min(512)]).into_owned();
    let mut words = text.split_whitespace();
    let method: String = words.next().unwrap_or("?").chars().take(16).collect();
    let target: String = words.next().unwrap_or("").chars().take(2048).collect();
    let status = if err.is_parse_too_large() { 431 } else { 400 };
    let now = now_us();
    let capture = ctx.shared.capture();
    let live = capture.begin(SessionKind::Http, |d| {
        d.request = RequestHead {
            method,
            url: if target.is_empty() {
                "(malformed request)".into()
            } else {
                target
            },
            version: HttpVersion::Http11,
            headers: Headers::new(),
        };
        d.connection.client_addr = Some(ctx.client_addr.to_string());
        d.connection.client_conn_id = Some(ctx.conn_id);
        d.timers.client_connected = Some(ctx.connected_at);
        d.timers.client_begin_request = Some(now);
        d.summary.client_ip = ctx.client_addr.ip().to_canonical().to_string();
    });
    live.set_request_body(capture.bodies.store_bytes(&raw));
    let msg = format!("malformed request, rejected before forwarding: {err}");
    live.update(move |d| {
        d.response = Some(ResponseHead {
            status,
            reason: if status == 431 {
                "Request Header Fields Too Large".into()
            } else {
                "Bad Request".into()
            },
            version: HttpVersion::Http11,
            headers: Headers::new(),
        });
        d.summary.state = SessionState::Aborted;
        d.error = Some(msg);
        d.timers.client_done_response = Some(now_us());
    });
    live.finish();
}

pub(crate) async fn serve_h1<I>(ctx: Arc<ConnCtx>, io: I)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let active = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let io = FirstBytes {
        inner: io,
        seen: seen.clone(),
        active: active.clone(),
    };
    let c2 = ctx.clone();
    let (a2, s2) = (active.clone(), seen.clone());
    let svc = service_fn(move |req: Request<Incoming>| {
        let ctx = c2.clone();
        if a2.swap(false, Ordering::Relaxed) {
            // A request was parsed: the raw bytes are not needed any more.
            *s2.lock() = Vec::new();
        }
        async move {
            if req.method() == http::Method::CONNECT && ctx.reverse.is_some() {
                // A reverse proxy port forwards to its target only; it is no general proxy.
                Ok(text(
                    StatusCode::METHOD_NOT_ALLOWED,
                    "CONNECT is not supported on a Quena reverse proxy port\n",
                ))
            } else if req.method() == http::Method::CONNECT {
                // Boxed as `dyn Future + Send` to break the type recursion
                // (CONNECT → intercept → serve_h1 → CONNECT).
                connect(ctx, req).await
            } else {
                forward::handle(ctx, req).await
            }
        }
    });
    let mut closing = ctx.shared.closing.subscribe();
    let conn = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .preserve_header_case(true)
        .keep_alive(true)
        .max_buf_size(1 << 20)
        .serve_connection(TokioIo::new(io), svc)
        .with_upgrades();
    tokio::pin!(conn);
    // Capture stopped: finish the request in flight, then close the connection.
    let r = tokio::select! {
        r = conn.as_mut() => r,
        _ = closing.changed() => {
            conn.as_mut().graceful_shutdown();
            conn.await
        }
    };
    if let Err(e) = r {
        tracing::debug!(target: "quena::proxy", "client connection {}: {e}", ctx.client_addr);
        // The very first request could not be parsed: make it visible in the session list.
        if (e.is_parse() || e.is_parse_too_large()) && active.load(Ordering::Relaxed) {
            let raw = std::mem::take(&mut *seen.lock());
            if !raw.is_empty() {
                record_malformed(&ctx, raw, &e);
            }
        }
    }
}

type RespFuture =
    Pin<Box<dyn std::future::Future<Output = Result<Response<ProxyBody>, Infallible>> + Send>>;

fn connect(ctx: Arc<ConnCtx>, req: Request<Incoming>) -> RespFuture {
    Box::pin(connect_inner(ctx, req))
}

async fn connect_inner(
    ctx: Arc<ConnCtx>,
    mut req: Request<Incoming>,
) -> Result<Response<ProxyBody>, Infallible> {
    let target = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_else(|| req.uri().to_string());
    let (host, port) = split_host_port(&target, 443);
    let (live, process) =
        begin_tunnel(&ctx, &target, forward::record_headers(req.headers(), true)).await;
    let on_upgrade = hyper::upgrade::on(&mut req);
    let proc_name = process.map(|p| p.display()).unwrap_or_default();
    tokio::spawn(async move {
        // Ends the tunnel session if this task is dropped or panics before finishing it.
        let _guard = live.abort_on_drop("the tunnel ended unexpectedly");
        match on_upgrade.await {
            Ok(up) => {
                let f: Pin<Box<dyn std::future::Future<Output = ()> + Send>> =
                    Box::pin(tunnel_or_intercept(
                        ctx,
                        live,
                        TokioIo::new(up),
                        host,
                        port,
                        target,
                        proc_name,
                        TunnelKind::Connect,
                    ));
                f.await
            }
            Err(e) => {
                live.update(|d| {
                    d.summary.state = SessionState::Aborted;
                    d.error = Some(format!("upgrade failed: {e}"));
                });
                live.finish();
            }
        }
    });
    let mut resp = Response::new(crate::body::empty());
    *resp.status_mut() = StatusCode::OK;
    if let Ok(rp) = hyper::ext::ReasonPhrase::try_from(b"Connection Established".to_vec()) {
        resp.extensions_mut().insert(rp);
    }
    Ok(resp)
}

/// Replays already-read bytes before reading from the inner stream.
pub struct Prefixed<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Prefixed {
            prefix,
            pos: 0,
            inner,
        }
    }
    /// The first byte still to be read from the prefix.
    pub fn peek_first(&self) -> Option<u8> {
        self.prefix.get(self.pos).copied()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.remaining());
            let start = self.pos;
            buf.put_slice(&self.prefix[start..start + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn tunnel_body(shared: &Shared, text: String) -> quena_body::Body {
    shared.capture().bodies.store_bytes(text.as_bytes())
}

async fn tunnel_or_intercept<S>(
    ctx: Arc<ConnCtx>,
    live: Arc<quena_store::LiveSession>,
    mut io: S,
    host: String,
    port: u16,
    target: String,
    process: String,
    kind: TunnelKind,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let label = kind.label();
    let shared = ctx.shared.clone();
    let mut first = [0u8; 1];
    // TLS (443) clients speak first. On other ports the server may speak first (SMTP,
    // IMAP, FTP, databases): if the client stays silent briefly, just pass the tunnel through.
    let wait = if port == 443 {
        Duration::from_secs(60)
    } else {
        Duration::from_secs(1)
    };
    let n = match tokio::time::timeout(wait, io.read(&mut first)).await {
        Ok(Ok(n)) => n,
        Ok(Err(_)) => 0,
        Err(_) if port != 443 => {
            live.set_response_body(tunnel_body(&shared, format!("This is a {label} to {target}.\nThe client did not speak first (server-first protocol); it is passed through.\n")));
            live.update(|_| {});
            tunnel::raw(&shared, &live, io, &host, port).await;
            return;
        }
        Err(_) => 0,
    };
    if n == 0 {
        live.update(|d| {
            d.summary.state = SessionState::Done;
            d.timers.client_done_response = Some(now_us());
        });
        live.finish();
        return;
    }
    let is_tls = first[0] == 0x16;
    // SOCKS and transparent clients send plain HTTP straight into the tunnel (port 80):
    // record it like proxied requests instead of passing it through.
    let mut seen = first[..n].to_vec();
    if kind != TunnelKind::Connect
        && !is_tls
        && first[0].is_ascii_uppercase()
        && looks_like_http(&mut io, &mut seen).await
    {
        live.set_response_body(tunnel_body(&shared, format!("This is a {label} to {target}.\nIt carries plain HTTP; the requests are recorded as their own sessions.\n")));
        live.update(|d| {
            d.summary.state = SessionState::Done;
            d.timers.client_done_response = Some(now_us());
        });
        live.finish();
        let inner = Arc::new(ConnCtx {
            shared: shared.clone(),
            conn_id: ctx.conn_id,
            client_addr: ctx.client_addr,
            remote: ctx.remote,
            process: ctx.process.clone(),
            scheme: "http",
            authority: Some(if port == 80 {
                host.clone()
            } else {
                target.clone()
            }),
            client_tls: None,
            connected_at: ctx.connected_at,
            decrypted: false,
            auth_clients: parking_lot::Mutex::new(std::collections::HashMap::new()),
            reverse: None,
            via: ctx.via.clone(),
        });
        serve_h1(inner, Prefixed::new(seen, io)).await;
        return;
    }
    pass_on(
        ctx,
        live,
        Prefixed::new(seen, io),
        host,
        port,
        target,
        process,
        kind,
    )
    .await
}

/// Whether the client starts an HTTP/1 request (`METHOD /…` or `METHOD http…`); reads up to
/// a few more bytes into `seen`.
async fn looks_like_http<S: AsyncRead + Unpin>(io: &mut S, seen: &mut Vec<u8>) -> bool {
    let read = tokio::time::timeout(Duration::from_secs(5), async {
        let mut b = [0u8; 1];
        while seen.len() < 12 && !seen.contains(&b' ') {
            if io.read(&mut b).await.ok()? == 0 {
                return None;
            }
            seen.push(b[0]);
        }
        if let Some(sp) = seen.iter().position(|c| *c == b' ') {
            if seen.len() == sp + 1 && io.read(&mut b).await.ok()? == 1 {
                seen.push(b[0]);
            }
        }
        Some(())
    })
    .await;
    if !matches!(read, Ok(Some(()))) {
        return false;
    }
    let Some(sp) = seen.iter().position(|c| *c == b' ') else {
        return false;
    };
    (3..=7).contains(&sp)
        && seen[..sp].iter().all(|c| c.is_ascii_uppercase())
        && matches!(seen.get(sp + 1), Some(b'/' | b'h' | b'*'))
}

/// TLS: decrypt when allowed; anything else: pass through.
#[allow(clippy::too_many_arguments)]
async fn pass_on<S>(
    ctx: Arc<ConnCtx>,
    live: Arc<quena_store::LiveSession>,
    io: Prefixed<S>,
    host: String,
    port: u16,
    target: String,
    process: String,
    kind: TunnelKind,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let shared = ctx.shared.clone();
    let cfg = shared.cfg();
    let label = kind.label();
    let first = io.peek_first().unwrap_or(0);
    let ca = shared.ca.read().clone();
    let is_tls = first == 0x16;
    if is_tls && ca.is_some() && cfg.decrypt_host(&host, &process, ctx.remote) {
        intercept(ctx, live, io, host, port, target, ca.unwrap(), kind).await;
    } else {
        let why = if !is_tls {
            "Traffic in this tunnel is not TLS; it is passed through."
        } else if !cfg.decrypt {
            "HTTPS decryption is disabled (Capture → HTTPS Settings…)."
        } else if ca.is_none() {
            "No root certificate is available."
        } else {
            "This host is excluded from decryption."
        };
        live.set_response_body(tunnel_body(
            &shared,
            format!("This is a {label} to {target}.\n{why}\n"),
        ));
        live.update(|_| {});
        tunnel::raw(&shared, &live, io, &host, port).await;
    }
}

/// A client TLS connection Quena terminated with a certificate from its root CA.
pub(crate) struct AcceptedTls<S> {
    pub stream: tokio_rustls::server::TlsStream<S>,
    pub info: TlsInfo,
    pub cert_host: String,
    pub alpn_offered: Vec<String>,
}

/// Run the TLS handshake with a client: the certificate names the SNI host, else
/// `fallback_host`; HTTP/2 is offered when the client offers it and the host allows it.
pub(crate) async fn accept_tls<S>(
    shared: &Shared,
    io: S,
    fallback_host: &str,
    ca: Arc<quena_tls::CertAuthority>,
) -> Result<AcceptedTls<S>, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let cfg = shared.cfg();
    let acceptor = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), io);
    let start = match tokio::time::timeout(std::time::Duration::from_secs(30), acceptor).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(format!("invalid TLS ClientHello: {e}")),
        Err(_) => return Err("timeout waiting for the TLS ClientHello".into()),
    };
    let hello = start.client_hello();
    let sni = hello.server_name().map(|s| s.to_string());
    let offers_h2 = hello
        .alpn()
        .map(|mut a| a.any(|p| p == b"h2"))
        .unwrap_or(false);
    let alpn_offered: Vec<String> = hello
        .alpn()
        .map(|a| a.map(|p| String::from_utf8_lossy(p).into_owned()).collect())
        .unwrap_or_default();
    let cert_host = sni.clone().unwrap_or_else(|| fallback_host.to_string());
    let allow_h2 = offers_h2 && cfg.h2_host(&cert_host);
    let server_cfg = ca
        .server_config(&cert_host, allow_h2)
        .map_err(|e| format!("certificate generation failed: {e}"))?;
    let tls = match tokio::time::timeout(CLIENT_TLS_TIMEOUT, start.into_stream(server_cfg)).await {
        Err(_) => {
            return Err(format!(
                "TLS handshake with the client timed out after {}s",
                CLIENT_TLS_TIMEOUT.as_secs()
            ));
        }
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            tracing::info!(target: "quena::proxy", "{cert_host}: client rejected the interception certificate ({e})");
            return Err(format!(
                "TLS handshake with the client failed: {e}.\nThe client probably does not trust the Quena root certificate (Capture → HTTPS Settings… → Trust root certificate), or it pins certificates for {cert_host}."
            ));
        }
    };
    let (_, sconn) = tls.get_ref();
    let alpn = sconn
        .alpn_protocol()
        .map(|a| String::from_utf8_lossy(a).into_owned());
    let info = TlsInfo {
        version: sconn
            .protocol_version()
            .map(|v| format!("{v:?}").replace("TLSv1_", "TLS 1."))
            .unwrap_or_default(),
        cipher: sconn
            .negotiated_cipher_suite()
            .map(|c| format!("{:?}", c.suite()))
            .unwrap_or_default(),
        sni,
        alpn,
        server_chain_pem: vec![],
    };
    Ok(AcceptedTls {
        stream: tls,
        info,
        cert_host,
        alpn_offered,
    })
}

#[allow(clippy::too_many_arguments)]
async fn intercept<S>(
    ctx: Arc<ConnCtx>,
    live: Arc<quena_store::LiveSession>,
    io: S,
    host: String,
    port: u16,
    target: String,
    ca: Arc<quena_tls::CertAuthority>,
    kind: TunnelKind,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let shared = ctx.shared.clone();
    let AcceptedTls {
        stream: tls,
        info: tinfo,
        cert_host,
        alpn_offered,
    } = match accept_tls(&shared, io, &host, ca).await {
        Ok(a) => a,
        Err(e) => return fail_tunnel(&live, e),
    };
    let info = format!(
        "This is a {} to {target}. Quena decrypted the HTTPS traffic inside it.\n\n\
         Client TLS handshake\n  Version: {}\n  Cipher: {}\n  SNI: {}\n  ALPN offered: {}\n  ALPN selected: {}\n",
        kind.label(),
        tinfo.version,
        tinfo.cipher,
        tinfo.sni.as_deref().unwrap_or("(none)"),
        if alpn_offered.is_empty() {
            "(none)".into()
        } else {
            alpn_offered.join(", ")
        },
        tinfo.alpn.as_deref().unwrap_or("(none)")
    );
    live.set_response_body(tunnel_body(&shared, info));
    let t2 = tinfo.clone();
    live.update(move |d| {
        d.summary.state = SessionState::Done;
        d.summary.flags |= flags::DECRYPTED;
        d.connection.client_tls = Some(t2);
        d.timers.client_done_response = Some(now_us());
    });
    live.finish();

    let authority = if port == 443 {
        cert_host.clone()
    } else {
        format!("{cert_host}:{port}")
    };
    let h2 = tinfo.alpn.as_deref() == Some("h2");
    let inner = Arc::new(ConnCtx {
        shared: shared.clone(),
        conn_id: ctx.conn_id,
        client_addr: ctx.client_addr,
        remote: ctx.remote,
        process: ctx.process.clone(),
        scheme: "https",
        authority: Some(authority),
        client_tls: Some(tinfo),
        connected_at: ctx.connected_at,
        decrypted: true,
        auth_clients: parking_lot::Mutex::new(std::collections::HashMap::new()),
        reverse: None,
        via: ctx.via.clone(),
    });
    serve_decrypted(inner, tls, h2).await;
}

/// Serve the requests of a decrypted client connection (HTTP/2 or HTTP/1).
pub(crate) async fn serve_decrypted<S>(inner: Arc<ConnCtx>, tls: S, h2: bool)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let shared = inner.shared.clone();
    if h2 {
        let c2 = inner.clone();
        let svc = service_fn(move |req: Request<Incoming>| forward::handle(c2.clone(), req));
        let mut closing = shared.closing.subscribe();
        let conn = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            // Detect dead h2 clients (sleeping laptops, dropped Wi-Fi).
            .keep_alive_interval(Some(Duration::from_secs(30)))
            .keep_alive_timeout(Duration::from_secs(20))
            // No RFC 8441 (WebSocket over HTTP/2): without the extended CONNECT setting,
            // browsers open WebSockets on a separate HTTP/1.1 connection, which Quena
            // records frame by frame. Tunnelling them through h2 streams is not supported.
            .max_concurrent_streams(250)
            .serve_connection(TokioIo::new(tls), svc);
        tokio::pin!(conn);
        let r = tokio::select! {
            r = conn.as_mut() => r,
            _ = closing.changed() => {
                conn.as_mut().graceful_shutdown();
                conn.await
            }
        };
        if let Err(e) = r {
            tracing::debug!(target: "quena::proxy", "h2 client connection: {e}");
        }
    } else {
        serve_h1(inner, tls).await;
    }
}

fn fail_tunnel(live: &Arc<quena_store::LiveSession>, msg: String) {
    live.update(|d| {
        d.summary.state = SessionState::Aborted;
        d.error = Some(msg);
        d.timers.client_done_response = Some(now_us());
    });
    live.finish();
}

fn text(status: StatusCode, s: &str) -> Response<ProxyBody> {
    let mut r = Response::new(full(s.to_string()));
    *r.status_mut() = status;
    r
}
