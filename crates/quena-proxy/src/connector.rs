//! Upstream connector: TCP (+DNS timing), optional upstream proxy (CONNECT
//! for HTTPS, absolute-form for HTTP), TLS with per-host verification/ALPN.

use crate::ProxyConfig;
use crate::body::BoxError;
use hyper::Uri;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;
use quena_model::TlsInfo;
use quena_tls::ClientConfigs;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

/// Connection metadata attached to pooled connections.
#[derive(Clone, Debug)]
pub struct ConnInfo {
    pub server_addr: String,
    pub dns_ms: u32,
    pub tcp_ms: u32,
    pub tls_ms: u32,
    pub tls: Option<TlsInfo>,
    pub gateway: Option<String>,
    /// Set after the first request used this connection (reuse detection).
    pub used: Arc<AtomicBool>,
    pub connect_start: i64,
    pub connected_at: i64,
}

pub enum Stream {
    Plain(TokioIo<TcpStream>),
    Tls(Box<TokioIo<TlsStream<TcpStream>>>),
}

pub struct MaybeTls {
    stream: Stream,
    proxied: bool,
    h2: bool,
    info: ConnInfo,
}

impl Connection for MaybeTls {
    fn connected(&self) -> Connected {
        let mut c = Connected::new().proxy(self.proxied).extra(self.info.clone());
        if self.h2 {
            c = c.negotiated_h2();
        }
        c
    }
}

impl hyper::rt::Read for MaybeTls {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: hyper::rt::ReadBufCursor<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.get_mut().stream {
            Stream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Tls(s) => Pin::new(&mut **s).poll_read(cx, buf),
        }
    }
}

impl hyper::rt::Write for MaybeTls {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match &mut self.get_mut().stream {
            Stream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Stream::Tls(s) => Pin::new(&mut **s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.get_mut().stream {
            Stream::Plain(s) => Pin::new(s).poll_flush(cx),
            Stream::Tls(s) => Pin::new(&mut **s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.get_mut().stream {
            Stream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Tls(s) => Pin::new(&mut **s).poll_shutdown(cx),
        }
    }
    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[std::io::IoSlice<'_>]) -> Poll<std::io::Result<usize>> {
        match &mut self.get_mut().stream {
            Stream::Plain(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Stream::Tls(s) => Pin::new(&mut **s).poll_write_vectored(cx, bufs),
        }
    }
    fn is_write_vectored(&self) -> bool {
        match &self.stream {
            Stream::Plain(s) => s.is_write_vectored(),
            Stream::Tls(s) => s.is_write_vectored(),
        }
    }
}

#[derive(Clone)]
pub struct Connector {
    pub cfg: Arc<ProxyConfig>,
    pub tls: Arc<ClientConfigs>,
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// getaddrinfo can block for a long time on broken resolvers.
const DNS_TIMEOUT: Duration = Duration::from_secs(10);
/// Reply of an upstream proxy to our CONNECT.
const PROXY_CONNECT_REPLY_TIMEOUT: Duration = Duration::from_secs(20);

/// Addresses Quena itself listens on (set by the proxy on start); used to refuse
/// connections that would loop back into Quena.
static SELF_ADDRS: parking_lot::RwLock<Vec<std::net::SocketAddr>> = parking_lot::RwLock::new(Vec::new());

pub(crate) fn add_self_addrs(addrs: &[std::net::SocketAddr]) {
    SELF_ADDRS.write().extend_from_slice(addrs);
}

pub(crate) fn remove_self_addrs(addrs: &[std::net::SocketAddr]) {
    SELF_ADDRS.write().retain(|a| !addrs.contains(a));
}

/// Whether connecting to `a` would reach Quena's own listener (a request loop).
pub(crate) fn is_self_addr(a: &std::net::SocketAddr) -> bool {
    let own = SELF_ADDRS.read();
    if !own.iter().any(|o| o.port() == a.port()) {
        return false;
    }
    let ip = a.ip().to_canonical();
    if ip.is_loopback() || ip.is_unspecified() || own.iter().any(|o| o.ip().to_canonical() == ip) {
        return true;
    }
    let s = ip.to_string();
    quena_platform::local_addresses().iter().any(|(_, l)| *l == s)
}

fn loop_error(host: &str, port: u16) -> std::io::Error {
    std::io::Error::other(format!("{host}:{port} is Quena itself; refusing to forward the request to avoid a loop"))
}

/// Open a TCP connection with DNS/connect timing.
pub async fn tcp_connect(host: &str, port: u16) -> std::io::Result<(TcpStream, u32, u32, String)> {
    let t0 = Instant::now();
    let addrs: Vec<std::net::SocketAddr> = match tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host((host.trim_matches(['[', ']']), port))).await {
        Ok(r) => r?.collect(),
        Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, format!("DNS lookup for {host} timed out after {}s", DNS_TIMEOUT.as_secs()))),
    };
    let dns_ms = t0.elapsed().as_millis() as u32;
    if addrs.is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, format!("no address for {host}")));
    }
    if addrs.iter().any(is_self_addr) {
        return Err(loop_error(host, port));
    }
    let t1 = Instant::now();
    // Happy Eyeballs (RFC 8305, simplified): alternate families, start the next
    // attempt after 250 ms if the previous one has not succeeded yet.
    let v4: Vec<_> = addrs.iter().filter(|a| a.is_ipv4()).copied().collect();
    let v6: Vec<_> = addrs.iter().filter(|a| a.is_ipv6()).copied().collect();
    let mut ordered = Vec::new();
    for i in 0..v4.len().max(v6.len()) {
        if let Some(a) = v4.get(i) {
            ordered.push(*a);
        }
        if let Some(a) = v6.get(i) {
            ordered.push(*a);
        }
    }
    let mut set = tokio::task::JoinSet::new();
    let mut errors: Vec<String> = Vec::new();
    let mut next = 0usize;
    loop {
        if next < ordered.len() {
            let a = ordered[next];
            next += 1;
            set.spawn(async move { (a, tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(a)).await) });
        }
        if set.is_empty() {
            break;
        }
        let delay = if next < ordered.len() { Duration::from_millis(250) } else { CONNECT_TIMEOUT + Duration::from_secs(1) };
        tokio::select! {
            r = set.join_next() => match r {
                Some(Ok((a, Ok(Ok(s))))) => {
                    set.abort_all();
                    let _ = s.set_nodelay(true);
                    return Ok((s, dns_ms, t1.elapsed().as_millis() as u32, a.to_string()));
                }
                Some(Ok((a, Ok(Err(e))))) => errors.push(format!("{a}: {e}")),
                Some(Ok((a, Err(_)))) => errors.push(format!("{a}: timed out")),
                Some(Err(_)) | None => {}
            },
            _ = tokio::time::sleep(delay) => {}
        }
    }
    Err(std::io::Error::other(format!("connect failed ({})", errors.join("; "))))
}

/// Establish a CONNECT tunnel through an upstream proxy.
pub async fn connect_via_proxy(s: &mut TcpStream, host: &str, port: u16) -> std::io::Result<()> {
    match tokio::time::timeout(PROXY_CONNECT_REPLY_TIMEOUT, connect_via_proxy_inner(s, host, port)).await {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, format!("upstream proxy did not answer the CONNECT within {}s", PROXY_CONNECT_REPLY_TIMEOUT.as_secs()))),
    }
}

async fn connect_via_proxy_inner(s: &mut TcpStream, host: &str, port: u16) -> std::io::Result<()> {
    let target = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
    let req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: Keep-Alive\r\nUser-Agent: Quena\r\n\r\n");
    s.write_all(req.as_bytes()).await?;
    let mut buf = Vec::with_capacity(512);
    let mut b = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if buf.len() > 16 * 1024 {
            return Err(std::io::Error::other("upstream proxy response too large"));
        }
        let n = s.read(&mut b).await?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "upstream proxy closed the connection"));
        }
        buf.push(b[0]);
    }
    let head = String::from_utf8_lossy(&buf);
    let status = head.split_whitespace().nth(1).unwrap_or("");
    if status != "200" {
        let line = head.lines().next().unwrap_or("").to_string();
        return Err(std::io::Error::other(format!("upstream proxy refused CONNECT: {line}")));
    }
    Ok(())
}

pub fn tls_info(conn: &rustls::ClientConnection, sni: &str) -> TlsInfo {
    TlsInfo {
        version: conn.protocol_version().map(|v| format!("{v:?}").replace('_', ".").replace("TLSv", "TLS ")).unwrap_or_default(),
        cipher: conn.negotiated_cipher_suite().map(|c| format!("{:?}", c.suite())).unwrap_or_default(),
        sni: Some(sni.to_string()),
        alpn: conn.alpn_protocol().map(|a| String::from_utf8_lossy(a).into_owned()),
        server_chain_pem: conn.peer_certificates().map(|c| c.iter().map(|d| quena_tls::der_to_pem(d.as_ref())).collect()).unwrap_or_default(),
    }
}

impl tower_service::Service<Uri> for Connector {
    type Response = MaybeTls;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<MaybeTls, BoxError>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let cfg = self.cfg.clone();
        let tls = self.tls.clone();
        Box::pin(async move {
            let https = uri.scheme_str() == Some("https") || uri.scheme_str() == Some("wss");
            let host = uri.host().ok_or("URI without host")?.trim_matches(['[', ']']).to_string();
            let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
            let connect_start = quena_model::now_us();
            let upstream = crate::resolve_upstream(&cfg, format!("{host}:{port}")).await;
            let (mut tcp, dns_ms, tcp_ms, server_addr, gateway) = match &upstream {
                Some((ph, pp)) => {
                    let (s, d, t, a) = tcp_connect(ph, *pp).await.map_err(|e| format!("upstream proxy {ph}:{pp}: {e}"))?;
                    (s, d, t, a, Some(format!("{ph}:{pp}")))
                }
                None => {
                    let (s, d, t, a) = tcp_connect(&host, port).await?;
                    (s, d, t, a, None)
                }
            };
            let info = |tls_ms, tls: Option<TlsInfo>| ConnInfo {
                server_addr: server_addr.clone(),
                dns_ms,
                tcp_ms,
                tls_ms,
                tls,
                gateway: gateway.clone(),
                used: Arc::new(AtomicBool::new(false)),
                connect_start,
                connected_at: quena_model::now_us(),
            };
            if !https {
                return Ok(MaybeTls { stream: Stream::Plain(TokioIo::new(tcp)), proxied: upstream.is_some(), h2: false, info: info(0, None) });
            }
            if upstream.is_some() {
                connect_via_proxy(&mut tcp, &host, port).await?;
            }
            let t = Instant::now();
            let h2 = cfg.h2_host(&host);
            let config = tls.for_host(&host, cfg.insecure_host(&host), h2, quena_query::glob_match);
            let name = quena_tls::server_name(&host)?;
            let s = tokio::time::timeout(CONNECT_TIMEOUT, tokio_rustls::TlsConnector::from(config).connect(name, tcp))
                .await
                .map_err(|_| "TLS handshake timed out")?
                .map_err(|e| format!("TLS handshake with {host} failed: {e}"))?;
            let tls_ms = t.elapsed().as_millis() as u32;
            let (_, conn) = s.get_ref();
            let negotiated_h2 = conn.alpn_protocol() == Some(b"h2");
            let ti = tls_info(conn, &host);
            Ok(MaybeTls { stream: Stream::Tls(Box::new(TokioIo::new(s))), proxied: false, h2: negotiated_h2, info: info(tls_ms, Some(ti)) })
        })
    }
}
