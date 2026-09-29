//! Piper capture engine (PLAN.md §8/§9, §2.1).
//!
//! * explicit forward proxy (HTTP/1.1, CONNECT) on 127.0.0.1:8866
//! * HTTPS interception with on-the-fly certificates (ALPN h2/http1.1)
//! * upstream chaining (system/manual proxy), per-host TLS options
//! * every exchange is recorded into a [`Capture`] while being streamed;
//!   recording never blocks forwarding (bounded recorder queues)
//! * hook points ([`Interceptor`]) for AutoResponder, breakpoints and scripts

mod body;
mod conn;
mod connector;
mod forward;
pub mod auth;
pub mod hooks;
mod landing;
mod recorder;
mod tunnel;
pub mod wsframe;
pub mod util;

pub use body::{BoxError, ProxyBody, empty, full};
pub use forward::{ExecuteOptions, Upstream, execute, execute_with};
pub use hooks::{Interceptor, NoInterceptor, RequestAction, ResponseAction, ResponseHeadAction, SessionView};
pub use auth::{CredentialResolver, NoCredentials};

/// Resolves the upstream proxy for a host (implemented by the app via PAC).
pub trait UpstreamResolver: Send + Sync + std::fmt::Debug {
    /// Upstream `host:port` for the request target `host_port`, or `None` for direct.
    fn upstream_for(&self, host_port: &str) -> Option<(String, u16)>;
}
pub use piper_auth::Scheme;

use parking_lot::RwLock;
use piper_store::Capture;
use piper_tls::{CertAuthority, ClientConfigs};
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
    pub enable_http2: bool,
    pub http2_downgrade_hosts: Vec<String>,
    pub upstream: Option<(String, u16)>,
    pub upstream_bypass: Vec<String>,
    /// Proxy auto-config resolver. When set it decides the upstream per host
    /// (Fiddler's PAC support); `upstream` is the static fallback.
    pub pac: Option<Arc<dyn UpstreamResolver>>,
    /// Stream responses (true) or buffer them completely first (Fiddler "Stream" off).
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
    pub auth_prefer: Vec<piper_auth::Scheme>,
    /// Simulated bandwidth cap in bytes/s for responses (0 = unlimited).
    pub throttle_bps: u64,
    /// Extra latency added before each response, in milliseconds.
    pub throttle_latency_ms: u64,
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
            auth_prefer: vec![piper_auth::Scheme::Negotiate, piper_auth::Scheme::Ntlm, piper_auth::Scheme::Basic],
            throttle_bps: 0,
            throttle_latency_ms: 0,
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

pub fn host_matches(list: &[String], host: &str) -> bool {
    let h = piper_query::host_without_port(host).trim_matches(['[', ']']).to_ascii_lowercase();
    list.iter().any(|p| piper_query::glob_match(p, &h) || (p.starts_with("*.") && h == p[2..]))
}

impl ProxyConfig {
    pub fn decrypt_host(&self, host: &str, process: &str, remote: bool) -> bool {
        if !self.decrypt || host_matches(&self.skip_decryption, host) {
            return false;
        }
        match self.decrypt_scope {
            DecryptScope::All => true,
            DecryptScope::Browsers => piper_query::is_browser(process),
            DecryptScope::NonBrowsers => !piper_query::is_browser(process),
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
        let h = piper_query::host_without_port(host);
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

    pub fn client_allowed(&self, ip: IpAddr) -> bool {
        if ip.is_loopback() || ip.to_canonical().is_loopback() {
            return true;
        }
        if !self.allow_remote {
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
pub struct Shared {
    pub capture: RwLock<Arc<Capture>>,
    pub cfg: RwLock<Arc<ProxyConfig>>,
    pub ca: RwLock<Option<Arc<CertAuthority>>>,
    pub tls_clients: Arc<ClientConfigs>,
    pub recorder: recorder::Recorder,
    pub process: piper_platform::ProcessLookup,
    pub hooks: RwLock<Arc<dyn Interceptor>>,
    pub creds: RwLock<Arc<dyn CredentialResolver>>,
    pub upstream: RwLock<Arc<Upstream>>,
    pub listen: RwLock<Vec<SocketAddr>>,
    pub conn_ids: std::sync::atomic::AtomicU64,
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
}

impl Proxy {
    pub fn new(capture: Arc<Capture>, cfg: ProxyConfig, ca: Option<Arc<CertAuthority>>) -> Result<Arc<Proxy>, ProxyError> {
        piper_tls::init();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .thread_name("piper-proxy")
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
            process: piper_platform::ProcessLookup::new(),
            hooks: RwLock::new(Arc::new(NoInterceptor)),
            creds: RwLock::new(Arc::new(NoCredentials)),
            upstream: RwLock::new(upstream),
            listen: RwLock::new(vec![]),
            conn_ids: std::sync::atomic::AtomicU64::new(1),
        });
        Ok(Arc::new(Proxy { shared, rt, stop: RwLock::new(None) }))
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
            let bind: Vec<SocketAddr> = if cfg.allow_remote {
                vec![SocketAddr::from(([0, 0, 0, 0], port)), SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port))]
            } else {
                vec![SocketAddr::from(([127, 0, 0, 1], port)), SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port))]
            };
            let mut listeners = Vec::new();
            let mut ok = true;
            for a in &bind {
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
                    Err(e) if a.is_ipv6() && e.kind() != std::io::ErrorKind::AddrInUse => {
                        tracing::debug!("IPv6 listener unavailable: {e}");
                    }
                    Err(e) => {
                        last_err = Some((a.to_string(), e));
                        ok = false;
                        break;
                    }
                }
            }
            if ok && !listeners.is_empty() {
                if port != cfg.port {
                    tracing::warn!(target: "piper::proxy", "port {} is in use, listening on {port} instead", cfg.port);
                }
                for l in listeners {
                    addrs.push(l.local_addr().map_err(|e| ProxyError::Other(e.to_string()))?);
                    self.spawn_accept(l, rx.clone());
                }
                break;
            }
        }
        if addrs.is_empty() {
            let (a, e) = last_err.unwrap_or(("?".into(), std::io::Error::other("no address")));
            return Err(ProxyError::Bind(a, e));
        }
        *self.shared.listen.write() = addrs.clone();
        *self.stop.write() = Some(tx);
        tracing::info!(target: "piper::proxy", "listening on {}", addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", "));
        Ok(addrs)
    }

    fn spawn_accept(&self, l: TcpListener, mut stop: watch::Receiver<bool>) {
        let shared = self.shared.clone();
        self.rt.spawn(async move {
            loop {
                tokio::select! {
                    r = l.accept() => match r {
                        Ok((s, peer)) => {
                            let shared = shared.clone();
                            tokio::spawn(async move { conn::handle_client(shared, s, peer).await });
                        }
                        Err(e) => {
                            tracing::warn!(target: "piper::proxy", "accept failed: {e}");
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        }
                    },
                    _ = stop.changed() => break,
                }
            }
        });
    }

    pub fn stop(&self) {
        if let Some(tx) = self.stop.write().take() {
            let _ = tx.send(true);
            tracing::info!(target: "piper::proxy", "stopped listening");
        }
        self.shared.listen.write().clear();
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
