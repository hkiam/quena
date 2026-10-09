//! Quena capture engine.
//!
//! * explicit forward proxy (HTTP/1.1, CONNECT) on 127.0.0.1:8866
//! * HTTPS interception with on-the-fly certificates (ALPN h2/http1.1)
//! * upstream chaining (system/manual proxy), per-host TLS options
//! * every exchange is recorded into a [`Capture`] while being streamed;
//!   recording never blocks forwarding (bounded recorder queues)
//! * hook points ([`Interceptor`]) for AutoResponder, breakpoints and scripts
//! * optional extra listeners ([`listener`]): reverse proxy ports that forward to fixed
//!   targets ([`reverse`]), a SOCKS5 port and a port for transparently redirected traffic

mod body;
mod conn;
mod connector;
mod forward;
pub mod auth;
pub mod grpc_client;
pub mod hooks;
mod landing;
pub mod listener;
mod recorder;
pub mod remap;
pub mod reverse;
mod socks;
mod transparent;
mod tunnel;
pub mod wsframe;
pub mod util;

pub use body::{BoxError, ProxyBody, empty, full};
pub use connector::cert_warning;
pub use forward::{ExecuteOptions, Upstream, execute, execute_with};
pub use hooks::{Interceptor, NoInterceptor, RequestAction, ResponseAction, ResponseHeadAction, SessionView};
pub use auth::{CredentialResolver, NoCredentials};

/// Resolves the upstream proxy for a host (implemented by the app via PAC).
pub trait UpstreamResolver: Send + Sync + std::fmt::Debug {
    /// Upstream `host:port` for the request target `host_port`, or `None` for direct.
    fn upstream_for(&self, host_port: &str) -> Option<(String, u16)>;
}
pub use quena_auth::Scheme;

use parking_lot::RwLock;
use quena_store::Capture;
use quena_tls::{CertAuthority, ClientConfigs};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("cannot listen on {0}: {1}")]
    Bind(String, std::io::Error),
    #[error("{0}")]
    Other(String),
}

/// Which clients' HTTPS traffic is decrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum DecryptScope {
    #[default]
    All,
    Browsers,
    NonBrowsers,
    Remote,
}

/// Runtime configuration of the proxy (derived from the app settings).
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub port: u16,
    pub allow_remote: bool,
    /// Allowed remote networks; empty = private ranges.
    pub remote_allowlist: Vec<util::Cidr>,
    pub decrypt: bool,
    pub decrypt_scope: DecryptScope,
    pub skip_decryption: Vec<String>,
    pub ignore_cert_errors: bool,
    pub ignore_cert_errors_hosts: Vec<String>,
    /// Sessions whose server certificate expires within this many days are flagged (0: never).
    pub cert_warn_days: u32,
    pub enable_http2: bool,
    pub http2_downgrade_hosts: Vec<String>,
    pub upstream: Option<(String, u16)>,
    pub upstream_bypass: Vec<String>,
    /// Proxy auto-config resolver. When set it decides the upstream per host
    /// (PAC support); `upstream` is the static fallback.
    pub pac: Option<Arc<dyn UpstreamResolver>>,
    /// Stream responses (true) or buffer them completely first ("Stream" off).
    pub stream: bool,
    pub headers_only_hosts: Vec<String>,
    pub headers_only_types: Vec<String>,
    pub lossless: bool,
    /// Automatic authentication (401/407) with the developer's credentials.
    pub auto_auth: bool,
    /// Hosts for which auto-auth runs (empty = all).
    pub auto_auth_hosts: Vec<String>,
    /// Also answer 407 from the upstream proxy.
    pub auto_auth_upstream: bool,
    /// Preferred scheme order.
    pub auth_prefer: Vec<quena_auth::Scheme>,
    /// Simulated bandwidth cap in bytes/s for responses (0 = unlimited).
    pub throttle_bps: u64,
    /// Extra latency added before each response, in milliseconds.
    pub throttle_latency_ms: u64,
    /// Reverse proxy ports (listening while the proxy runs).
    pub reverse: Vec<reverse::ReverseRoute>,
    /// SOCKS5/4 port (listening while the proxy runs).
    pub socks: Option<listener::ExtraPort>,
    /// Port for transparently redirected traffic (listening while the proxy runs).
    pub transparent: Option<listener::ExtraPort>,
    /// Host remapping: connections to these hosts go elsewhere.
    pub host_remap: Vec<remap::HostRemap>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            port: 8866,
            allow_remote: false,
            remote_allowlist: vec![],
            decrypt: false,
            decrypt_scope: DecryptScope::All,
            skip_decryption: vec![],
            ignore_cert_errors: false,
            ignore_cert_errors_hosts: vec![],
            cert_warn_days: 30,
            enable_http2: true,
            http2_downgrade_hosts: vec![],
            upstream: None,
            upstream_bypass: vec![],
            pac: None,
            stream: true,
            headers_only_hosts: vec![],
            headers_only_types: vec![],
            lossless: false,
            auto_auth: false,
            auto_auth_hosts: vec![],
            auto_auth_upstream: false,
            auth_prefer: vec![quena_auth::Scheme::Negotiate, quena_auth::Scheme::Ntlm, quena_auth::Scheme::Basic],
            throttle_bps: 0,
            throttle_latency_ms: 0,
            reverse: vec![],
            socks: None,
            transparent: None,
            host_remap: vec![],
        }
    }
}

/// Resolve the upstream proxy for `host_port` from an async context. When a PAC
/// script is in play the (possibly blocking) evaluation is moved to the blocking
/// pool so it never stalls a proxy worker thread; the static/no-PAC case stays
/// inline and cheap.
pub(crate) async fn resolve_upstream(cfg: &Arc<ProxyConfig>, host_port: String) -> Option<(String, u16)> {
    if !cfg.uses_pac() {
        return cfg.upstream_for(&host_port);
    }
    let cfg = cfg.clone();
    tokio::task::spawn_blocking(move || cfg.upstream_for(&host_port)).await.unwrap_or(None)
}

/// Host patterns: globs (`*.example.com`, `10.1.*`), a domain with its subdomains
/// (`*.corp` also matches `corp`), address ranges (`169.254/16`, `10.0.0.0/8`) and, as in
/// Windows' proxy exceptions, `<local>` for names without a dot (`intranet`, `appserver`).
pub fn host_matches(list: &[String], host: &str) -> bool {
    let h = quena_query::host_without_port(host).trim_matches(['[', ']']).to_ascii_lowercase();
    let ip: Option<IpAddr> = h.parse().ok();
    list.iter().any(|p| {
        quena_query::glob_match(p, &h)
            || (p.starts_with("*.") && h.eq_ignore_ascii_case(&p[2..]))
            || (p.eq_ignore_ascii_case("<local>") && ip.is_none() && !h.is_empty() && !h.contains('.'))
            || (p.contains('/') && ip.is_some_and(|ip| util::Cidr::parse(p).is_some_and(|c| c.contains(ip))))
    })
}

impl ProxyConfig {
    pub fn decrypt_host(&self, host: &str, process: &str, remote: bool) -> bool {
        if !self.decrypt || host_matches(&self.skip_decryption, host) {
            return false;
        }
        match self.decrypt_scope {
            DecryptScope::All => true,
            DecryptScope::Browsers => quena_query::is_browser(process),
            DecryptScope::NonBrowsers => !quena_query::is_browser(process),
            DecryptScope::Remote => remote,
        }
    }
    pub fn insecure_host(&self, host: &str) -> bool {
        self.ignore_cert_errors || host_matches(&self.ignore_cert_errors_hosts, host)
    }
    pub fn h2_host(&self, host: &str) -> bool {
        self.enable_http2 && !host_matches(&self.http2_downgrade_hosts, host)
    }
    pub fn upstream_for(&self, host: &str) -> Option<(String, u16)> {
        let h = quena_query::host_without_port(host);
        if util::is_loopback_host(h) || host_matches(&self.upstream_bypass, host) {
            return None;
        }
        if let Some(pac) = &self.pac {
            return pac.upstream_for(host);
        }
        self.upstream.clone()
    }
    /// True when a PAC script decides the upstream (evaluation may block briefly
    /// on the first request per host, so callers on the async runtime should use
    /// [`resolve_upstream`] instead of calling [`upstream_for`] directly).
    pub fn uses_pac(&self) -> bool {
        self.pac.is_some()
    }
    /// Whether auto-auth applies to `host` (server 401 case).
    pub fn auth_applies(&self, host: &str) -> bool {
        self.auto_auth && (self.auto_auth_hosts.is_empty() || host_matches(&self.auto_auth_hosts, host))
    }

    /// Where a connection to `host:port` goes instead (host remapping).
    pub fn remap(&self, host: &str, port: u16) -> Option<remap::Remapped> {
        if self.host_remap.is_empty() {
            return None;
        }
        remap::lookup(&self.host_remap, host, port)
    }

    /// The extra listeners this configuration asks for.
    pub fn listeners(&self) -> Vec<listener::Listener> {
        let mut out: Vec<listener::Listener> = self.reverse.iter().map(|r| listener::Listener::Reverse(Arc::new(r.clone()))).collect();
        if let Some(p) = self.socks {
            out.push(listener::Listener::Socks(p));
        }
        if let Some(p) = self.transparent {
            out.push(listener::Listener::Transparent(p));
        }
        out
    }

    pub fn client_allowed(&self, ip: IpAddr) -> bool {
        self.client_allowed_with(ip, self.allow_remote)
    }

    /// Like [`ProxyConfig::client_allowed`] for a listener with its own remote switch.
    pub fn client_allowed_with(&self, ip: IpAddr, allow_remote: bool) -> bool {
        if ip.is_loopback() || ip.to_canonical().is_loopback() {
            return true;
        }
        if !allow_remote {
            return false;
        }
        let ip = ip.to_canonical();
        if self.remote_allowlist.is_empty() {
            return util::is_private(ip);
        }
        self.remote_allowlist.iter().any(|c| c.contains(ip))
    }
}

/// Shared state of a running proxy.
/// Upper bound for simultaneous client connections (the engine raises the process
/// descriptor limit well above this at startup).
pub const MAX_CLIENT_CONNECTIONS: usize = 4096;
static LAST_LIMIT_WARN: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

pub struct Shared {
    pub capture: RwLock<Arc<Capture>>,
    pub cfg: RwLock<Arc<ProxyConfig>>,
    pub ca: RwLock<Option<Arc<CertAuthority>>>,
    pub tls_clients: Arc<ClientConfigs>,
    pub recorder: recorder::Recorder,
    pub process: quena_platform::ProcessLookup,
    pub hooks: RwLock<Arc<dyn Interceptor>>,
    pub creds: RwLock<Arc<dyn CredentialResolver>>,
    pub upstream: RwLock<Arc<Upstream>>,
    pub listen: RwLock<Vec<SocketAddr>>,
    pub conn_ids: std::sync::atomic::AtomicU64,
    /// Caps concurrent client connections so a flood (or a proxy loop) cannot exhaust
    /// file descriptors; excess connections are closed right away.
    pub conn_limit: Arc<tokio::sync::Semaphore>,
    /// Bumped by `Proxy::stop`: open client connections, tunnels and WebSockets finish
    /// what is in flight and close, so a stopped capture records nothing more.
    pub closing: tokio::sync::watch::Sender<u64>,
}

impl Shared {
    pub fn capture(&self) -> Arc<Capture> {
        self.capture.read().clone()
    }
    pub fn cfg(&self) -> Arc<ProxyConfig> {
        self.cfg.read().clone()
    }
    pub fn upstream(&self) -> Arc<Upstream> {
        self.upstream.read().clone()
    }
    pub fn hooks(&self) -> Arc<dyn Interceptor> {
        self.hooks.read().clone()
    }
    pub fn creds(&self) -> Arc<dyn CredentialResolver> {
        self.creds.read().clone()
    }
}

/// The capture engine. Owns a tokio runtime dedicated to forwarding (R7).
pub struct Proxy {
    pub shared: Arc<Shared>,
    rt: tokio::runtime::Runtime,
    stop: RwLock<Option<watch::Sender<bool>>>,
    /// Reverse proxy listeners that run, and the state of every configured one.
    extra: parking_lot::Mutex<Vec<listener::Running>>,
    extra_status: RwLock<Vec<listener::ListenerStatus>>,
}

impl Proxy {
    pub fn new(capture: Arc<Capture>, cfg: ProxyConfig, ca: Option<Arc<CertAuthority>>) -> Result<Arc<Proxy>, ProxyError> {
        quena_tls::init();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .thread_name("quena-proxy")
            .worker_threads(std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(2, 8))
            .enable_all()
            .build()
            .map_err(|e| ProxyError::Other(e.to_string()))?;
        let tls_clients = Arc::new(ClientConfigs::new().map_err(|e| ProxyError::Other(e.to_string()))?);
        let cfg = Arc::new(cfg);
        let upstream = {
            let _g = rt.enter();
            Arc::new(Upstream::new(cfg.clone(), tls_clients.clone()))
        };
        let shared = Arc::new(Shared {
            capture: RwLock::new(capture),
            cfg: RwLock::new(cfg),
            ca: RwLock::new(ca),
            tls_clients,
            recorder: recorder::Recorder::new(2),
            process: quena_platform::ProcessLookup::new(),
            hooks: RwLock::new(Arc::new(NoInterceptor)),
            creds: RwLock::new(Arc::new(NoCredentials)),
            upstream: RwLock::new(upstream),
            listen: RwLock::new(vec![]),
            // Unique across runs, so a recovered capture and new traffic never share a
            // connection id (the list groups by it).
            conn_ids: std::sync::atomic::AtomicU64::new(conn_id_base()),
            conn_limit: Arc::new(tokio::sync::Semaphore::new(MAX_CLIENT_CONNECTIONS)),
            closing: tokio::sync::watch::channel(0).0,
        });
        Ok(Arc::new(Proxy { shared, rt, stop: RwLock::new(None), extra: parking_lot::Mutex::new(vec![]), extra_status: RwLock::new(vec![]) }))
    }

    pub fn runtime(&self) -> &tokio::runtime::Runtime {
        &self.rt
    }

    pub fn is_running(&self) -> bool {
        self.stop.read().is_some()
    }

    pub fn listen_addrs(&self) -> Vec<SocketAddr> {
        self.shared.listen.read().clone()
    }

    /// Start listening. Tries the configured port first, then the next free ones.
    pub fn start(&self) -> Result<Vec<SocketAddr>, ProxyError> {
        if self.is_running() {
            return Ok(self.listen_addrs());
        }
        let cfg = self.shared.cfg();
        let (tx, rx) = watch::channel(false);
        let mut addrs = Vec::new();
        let mut last_err = None;
        for port in cfg.port..cfg.port.saturating_add(20) {
            match self.bind_pair(port, cfg.allow_remote) {
                Ok(listeners) => {
                    if port != cfg.port {
                        tracing::warn!(target: "quena::proxy", "port {} is in use, listening on {port} instead", cfg.port);
                    }
                    for l in listeners {
                        addrs.push(l.local_addr().map_err(|e| ProxyError::Other(e.to_string()))?);
                        let _ = self.spawn_accept(l, rx.clone(), None);
                    }
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        if addrs.is_empty() {
            let (a, e) = last_err.unwrap_or(("?".into(), std::io::Error::other("no address")));
            return Err(ProxyError::Bind(a, e));
        }
        *self.shared.listen.write() = addrs.clone();
        connector::add_self_addrs(&addrs);
        *self.stop.write() = Some(tx);
        tracing::info!(target: "quena::proxy", "listening on {}", addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", "));
        self.sync_listeners(&cfg.listeners());
        Ok(addrs)
    }

    /// Bind `port` on IPv4 and IPv6 (loopback, or all interfaces). An IPv6 listener that
    /// is unavailable is left out; the port being taken is an error.
    fn bind_pair(&self, port: u16, remote: bool) -> Result<Vec<TcpListener>, (String, std::io::Error)> {
        let bind: Vec<SocketAddr> = if remote {
            vec![SocketAddr::from(([0, 0, 0, 0], port)), SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port))]
        } else {
            vec![SocketAddr::from(([127, 0, 0, 1], port)), SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port))]
        };
        let mut listeners: Vec<TcpListener> = Vec::new();
        for a in &bind {
            // Port 0: IPv6 takes the port IPv4 got, so both addresses share one port.
            let mut a = *a;
            if port == 0 {
                if let Some(p) = listeners.first().and_then(|l| l.local_addr().ok()) {
                    a.set_port(p.port());
                }
            }
            let a = &a;
            let l = self.rt.block_on(async {
                let sock = if a.is_ipv4() { tokio::net::TcpSocket::new_v4()? } else { tokio::net::TcpSocket::new_v6()? };
                sock.set_reuseaddr(true)?;
                #[cfg(unix)]
                if a.is_ipv6() {
                    // Keep IPv6 listener IPv6-only so both binds succeed.
                    let _ = set_v6only(&sock);
                }
                sock.bind(*a)?;
                sock.listen(1024)
            });
            match l {
                Ok(l) => listeners.push(l),
                Err(e) if a.is_ipv6() && (port == 0 || e.kind() != std::io::ErrorKind::AddrInUse) => {
                    tracing::debug!("IPv6 listener unavailable: {e}");
                }
                Err(e) => return Err((a.to_string(), e)),
            }
        }
        if listeners.is_empty() {
            return Err(("?".into(), std::io::Error::other("no address")));
        }
        Ok(listeners)
    }

    /// State of the extra listeners (reverse proxy, SOCKS, transparent) while running.
    pub fn listener_status(&self) -> Vec<listener::ListenerStatus> {
        self.extra_status.read().clone()
    }

    /// Run exactly `wanted`: unchanged listeners keep running, changed or removed ones
    /// stop, new ones start. A port that cannot be bound is reported in
    /// [`Proxy::listener_status`]; it never stops the main listener or the others.
    fn sync_listeners(&self, wanted: &[listener::Listener]) {
        let mut running = self.extra.lock();
        let mut stopped = Vec::new();
        running.retain_mut(|r| {
            let keep = wanted.iter().any(|n| n == r.listener.as_ref());
            if !keep {
                let _ = r.stop.send(true);
                connector::remove_self_addrs(&r.addrs);
                stopped.append(&mut r.tasks);
                tracing::info!(target: "quena::proxy", "{} stopped (port {})", r.listener.name(), r.listener.port());
            }
            keep
        });
        // The accept loops close their sockets when they end: wait, so a changed entry
        // can bind the same port again right away.
        self.rt.block_on(async {
            for t in stopped {
                let _ = tokio::time::timeout(std::time::Duration::from_secs(2), t).await;
            }
        });
        let mut status = Vec::new();
        for l in wanted {
            let mut st = listener::ListenerStatus { id: l.id(), kind: l.kind(), name: l.name(), port: l.port(), target: l.target(), listen: vec![], error: None };
            if let Some(r) = running.iter().find(|r| r.listener.as_ref() == l) {
                st.listen = r.addrs.iter().map(|a| a.to_string()).collect();
                status.push(st);
                continue;
            }
            let main_port = self.shared.listen.read().first().map(|a| a.port());
            let bound = if main_port == Some(l.port()) {
                Err(format!("port {} is the proxy port", l.port()))
            } else {
                self.bind_pair(l.port(), l.allow_remote()).map_err(|(a, e)| format!("cannot listen on {a}: {e}"))
            };
            match bound {
                Ok(listeners) => {
                    let (tx, rx) = watch::channel(false);
                    let l = Arc::new(l.clone());
                    let mut addrs = Vec::new();
                    let mut tasks = Vec::new();
                    for sock in listeners {
                        if let Ok(a) = sock.local_addr() {
                            addrs.push(a);
                        }
                        tasks.push(self.spawn_accept(sock, rx.clone(), Some(l.clone())));
                    }
                    connector::add_self_addrs(&addrs);
                    tracing::info!(target: "quena::proxy", "{}: {} → {}", l.name(), addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", "), l.target());
                    st.listen = addrs.iter().map(|a| a.to_string()).collect();
                    running.push(listener::Running { listener: l, addrs, stop: tx, tasks });
                }
                Err(e) => {
                    tracing::warn!(target: "quena::proxy", "{}: {e}", l.name());
                    st.error = Some(e);
                }
            }
            status.push(st);
        }
        *self.extra_status.write() = status;
    }

    fn spawn_accept(&self, l: TcpListener, mut stop: watch::Receiver<bool>, route: Option<Arc<listener::Listener>>) -> tokio::task::JoinHandle<()> {
        let shared = self.shared.clone();
        self.rt.spawn(async move {
            loop {
                tokio::select! {
                    r = l.accept() => match r {
                        Ok((s, peer)) => match shared.conn_limit.clone().try_acquire_owned() {
                            Ok(permit) => {
                                let shared = shared.clone();
                                let route = route.clone();
                                tokio::spawn(async move {
                                    let _permit = permit;
                                    conn::handle_client(shared, s, peer, route).await
                                });
                            }
                            Err(_) => {
                                drop(s);
                                let now = quena_model::now_us();
                                let last = LAST_LIMIT_WARN.load(std::sync::atomic::Ordering::Relaxed);
                                if now - last > 5_000_000 {
                                    LAST_LIMIT_WARN.store(now, std::sync::atomic::Ordering::Relaxed);
                                    tracing::warn!(target: "quena::proxy", "more than {MAX_CLIENT_CONNECTIONS} client connections; refusing new ones");
                                }
                            }
                        },
                        Err(e) => {
                            tracing::warn!(target: "quena::proxy", "accept failed: {e}");
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        }
                    },
                    _ = stop.changed() => break,
                }
            }
        })
    }

    pub fn stop(&self) {
        self.shared.closing.send_modify(|g| *g += 1);
        if let Some(tx) = self.stop.write().take() {
            let _ = tx.send(true);
            tracing::info!(target: "quena::proxy", "stopped listening");
        }
        let mut listen = self.shared.listen.write();
        connector::remove_self_addrs(&listen);
        listen.clear();
        drop(listen);
        self.sync_listeners(&[]);
    }

    /// Apply a new configuration. Restarts listeners if the listen settings changed.
    pub fn reconfigure(&self, cfg: ProxyConfig) -> Result<(), ProxyError> {
        let old = self.shared.cfg();
        let restart = self.is_running() && (old.port != cfg.port || old.allow_remote != cfg.allow_remote);
        let cfg = Arc::new(cfg);
        *self.shared.cfg.write() = cfg.clone();
        let up = {
            let _g = self.rt.enter();
            Arc::new(Upstream::new(cfg, self.shared.tls_clients.clone()))
        };
        *self.shared.upstream.write() = up;
        if restart {
            self.stop();
            self.start()?;
        } else if self.is_running() {
            self.sync_listeners(&self.shared.cfg().listeners());
        }
        Ok(())
    }

    pub fn set_capture(&self, c: Arc<Capture>) {
        *self.shared.capture.write() = c;
    }

    pub fn set_ca(&self, ca: Option<Arc<CertAuthority>>) {
        *self.shared.ca.write() = ca;
    }

    pub fn set_interceptor(&self, i: Arc<dyn Interceptor>) {
        *self.shared.hooks.write() = i;
    }

    pub fn set_credential_resolver(&self, r: Arc<dyn CredentialResolver>) {
        *self.shared.creds.write() = r;
    }
}

#[cfg(unix)]
fn set_v6only(sock: &tokio::net::TcpSocket) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let fd = sock.as_raw_fd();
    let on: LibcInt = 1;
    let r = unsafe { setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on as *const _ as *const _, std::mem::size_of::<LibcInt>() as u32) };
    if r == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

#[cfg(unix)]
type LibcInt = i32;
#[cfg(target_os = "macos")]
const IPV6_V6ONLY: i32 = 27;
#[cfg(all(unix, not(target_os = "macos")))]
const IPV6_V6ONLY: i32 = 26;
#[cfg(unix)]
const IPPROTO_IPV6: i32 = 41;
#[cfg(unix)]
unsafe extern "C" {
    fn setsockopt(socket: i32, level: i32, name: i32, value: *const std::ffi::c_void, option_len: u32) -> i32;
}

/// First connection id of this run: the start time in seconds, shifted so the ids of
/// different runs do not overlap (2^20 connections per second between two starts). Stays
/// below 2^53, so the UI (JavaScript numbers) shows it exactly.
fn conn_id_base() -> u64 {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    (secs << 20) | 1
}
