//! Client connections: HTTP/1.1 server, CONNECT, HTTPS interception.

use crate::Shared;
use crate::body::{ProxyBody, full};
use crate::forward::{self, ConnCtx};
use crate::tunnel;
use crate::util::split_host_port;
use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use piper_model::*;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::watch;

pub async fn handle_client(shared: Arc<Shared>, stream: TcpStream, peer: SocketAddr) {
    let cfg = shared.cfg();
    if !cfg.client_allowed(peer.ip()) {
        tracing::warn!(target: "piper::proxy", "rejected connection from {} (not in the remote allowlist)", peer.ip().to_canonical());
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
    });
    serve_h1(ctx, stream).await;
}

pub(crate) async fn serve_h1<I>(ctx: Arc<ConnCtx>, io: I)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let c2 = ctx.clone();
    let svc = service_fn(move |req: Request<Incoming>| {
        let ctx = c2.clone();
        async move {
            if req.method() == http::Method::CONNECT {
                // Boxed as `dyn Future + Send` to break the type recursion
                // (CONNECT → intercept → serve_h1 → CONNECT).
                connect(ctx, req).await
            } else {
                forward::handle(ctx, req).await
            }
        }
    });
    let r = hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .keep_alive(true)
        .max_buf_size(1 << 20)
        .serve_connection(TokioIo::new(io), svc)
        .with_upgrades()
        .await;
    if let Err(e) = r {
        tracing::debug!(target: "piper::proxy", "client connection {}: {e}", ctx.client_addr);
    }
}

type RespFuture = Pin<Box<dyn std::future::Future<Output = Result<Response<ProxyBody>, Infallible>> + Send>>;

fn connect(ctx: Arc<ConnCtx>, req: Request<Incoming>) -> RespFuture {
    Box::pin(connect_inner(ctx, req))
}

async fn connect_inner(ctx: Arc<ConnCtx>, mut req: Request<Incoming>) -> Result<Response<ProxyBody>, Infallible> {
    let shared = ctx.shared.clone();
    let target = req.uri().authority().map(|a| a.to_string()).unwrap_or_else(|| req.uri().to_string());
    let (host, port) = split_host_port(&target, 443);
    let capture = shared.capture();
    let process = ctx.process().await;
    let now = now_us();
    let head = RequestHead {
        method: "CONNECT".into(),
        url: target.clone(),
        version: HttpVersion::Http11,
        headers: forward::record_headers(req.headers(), true),
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
    });
    let mut rh = Headers::new();
    rh.push("Piper-Gateway", shared.cfg().upstream_for(&target).map(|(h, p)| format!("{h}:{p}")).unwrap_or_else(|| "Direct".into()));
    live.update(|d| {
        d.response = Some(ResponseHead { status: 200, reason: "Connection Established".into(), version: HttpVersion::Http11, headers: rh });
        d.timers.got_response_headers = Some(now_us());
    });
    let on_upgrade = hyper::upgrade::on(&mut req);
    let proc_name = process.map(|p| p.display()).unwrap_or_default();
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(up) => {
                let f: Pin<Box<dyn std::future::Future<Output = ()> + Send>> = Box::pin(tunnel_or_intercept(ctx, live, TokioIo::new(up), host, port, target, proc_name));
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
        Prefixed { prefix, pos: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
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
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn tunnel_body(shared: &Shared, text: String) -> piper_body::Body {
    shared.capture().bodies.store_bytes(text.as_bytes())
}

async fn tunnel_or_intercept<S>(
    ctx: Arc<ConnCtx>,
    live: Arc<piper_store::LiveSession>,
    mut io: S,
    host: String,
    port: u16,
    target: String,
    process: String,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let shared = ctx.shared.clone();
    let cfg = shared.cfg();
    let mut first = [0u8; 1];
    let n = match tokio::time::timeout(std::time::Duration::from_secs(60), io.read(&mut first)).await {
        Ok(Ok(n)) => n,
        _ => 0,
    };
    if n == 0 {
        live.update(|d| {
            d.summary.state = SessionState::Done;
            d.timers.client_done_response = Some(now_us());
        });
        live.finish();
        return;
    }
    let io = Prefixed::new(first[..n].to_vec(), io);
    let ca = shared.ca.read().clone();
    let is_tls = first[0] == 0x16;
    if is_tls && ca.is_some() && cfg.decrypt_host(&host, &process, ctx.remote) {
        intercept(ctx, live, io, host, port, target, ca.unwrap()).await;
    } else {
        let why = if !is_tls {
            "Traffic in this tunnel is not TLS; it is passed through."
        } else if !cfg.decrypt {
            "HTTPS decryption is disabled (Tools → Options → HTTPS)."
        } else if ca.is_none() {
            "No root certificate is available."
        } else {
            "This host is excluded from decryption."
        };
        live.set_response_body(tunnel_body(&shared, format!("This is a CONNECT tunnel to {target}.\n{why}\n")));
        live.update(|_| {});
        tunnel::raw(&shared, &live, io, &host, port).await;
    }
}

async fn intercept<S>(ctx: Arc<ConnCtx>, live: Arc<piper_store::LiveSession>, io: S, host: String, port: u16, target: String, ca: Arc<piper_tls::CertAuthority>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let shared = ctx.shared.clone();
    let cfg = shared.cfg();
    let acceptor = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), io);
    let start = match tokio::time::timeout(std::time::Duration::from_secs(30), acceptor).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return fail_tunnel(&live, format!("invalid TLS ClientHello: {e}")),
        Err(_) => return fail_tunnel(&live, "timeout waiting for the TLS ClientHello".into()),
    };
    let hello = start.client_hello();
    let sni = hello.server_name().map(|s| s.to_string());
    let offers_h2 = hello.alpn().map(|mut a| a.any(|p| p == b"h2")).unwrap_or(false);
    let alpn_offered: Vec<String> = hello.alpn().map(|a| a.map(|p| String::from_utf8_lossy(p).into_owned()).collect()).unwrap_or_default();
    let cert_host = sni.clone().unwrap_or_else(|| host.clone());
    let allow_h2 = offers_h2 && cfg.h2_host(&cert_host);
    let server_cfg = match ca.server_config(&cert_host, allow_h2) {
        Ok(c) => c,
        Err(e) => return fail_tunnel(&live, format!("certificate generation failed: {e}")),
    };
    let tls = match start.into_stream(server_cfg).await {
        Ok(t) => t,
        Err(e) => {
            let msg = format!(
                "TLS handshake with the client failed: {e}.\nThe client probably does not trust the Piper root certificate (Tools → HTTPS → Trust root certificate), or it pins certificates for {cert_host}."
            );
            tracing::info!(target: "piper::proxy", "{cert_host}: client rejected the interception certificate ({e})");
            return fail_tunnel(&live, msg);
        }
    };
    let (_, sconn) = tls.get_ref();
    let alpn = sconn.alpn_protocol().map(|a| String::from_utf8_lossy(a).into_owned());
    let tinfo = TlsInfo {
        version: sconn.protocol_version().map(|v| format!("{v:?}").replace("TLSv1_", "TLS 1.")).unwrap_or_default(),
        cipher: sconn.negotiated_cipher_suite().map(|c| format!("{:?}", c.suite())).unwrap_or_default(),
        sni: sni.clone(),
        alpn: alpn.clone(),
        server_chain_pem: vec![],
    };
    let info = format!(
        "This is a CONNECT tunnel to {target}. Piper decrypted the HTTPS traffic inside it.\n\n\
         Client TLS handshake\n  Version: {}\n  Cipher: {}\n  SNI: {}\n  ALPN offered: {}\n  ALPN selected: {}\n",
        tinfo.version,
        tinfo.cipher,
        sni.as_deref().unwrap_or("(none)"),
        if alpn_offered.is_empty() { "(none)".into() } else { alpn_offered.join(", ") },
        alpn.as_deref().unwrap_or("(none)")
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

    let authority = if port == 443 { cert_host.clone() } else { format!("{cert_host}:{port}") };
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
    });
    if alpn.as_deref() == Some("h2") {
        let c2 = inner.clone();
        let svc = service_fn(move |req: Request<Incoming>| forward::handle(c2.clone(), req));
        let r = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .enable_connect_protocol()
            .max_concurrent_streams(250)
            .serve_connection(TokioIo::new(tls), svc)
            .await;
        if let Err(e) = r {
            tracing::debug!(target: "piper::proxy", "h2 client connection: {e}");
        }
    } else {
        serve_h1(inner, tls).await;
    }
}

fn fail_tunnel(live: &Arc<piper_store::LiveSession>, msg: String) {
    live.update(|d| {
        d.summary.state = SessionState::Aborted;
        d.error = Some(msg);
        d.timers.client_done_response = Some(now_us());
    });
    live.finish();
}

#[allow(dead_code)]
fn text(status: StatusCode, s: &str) -> Response<ProxyBody> {
    let mut r = Response::new(full(s.to_string()));
    *r.status_mut() = status;
    r
}
