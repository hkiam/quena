//! Capture engine: the proxy plus system integration (system proxy,
//! upstream detection, root CA management).

use crate::settings::{DecryptScope as SDecryptScope, Settings};
use crate::{AppCore, CaptureEngine, EngineStatus};
use anyhow::{Context, Result, anyhow};
use parking_lot::{Mutex, RwLock};
use quena_proxy::util::{Cidr, split_host_port, split_list};
use quena_proxy::{DecryptScope, Proxy, ProxyConfig, UpstreamResolver};
use quena_tls::CertAuthority;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;

pub struct ProxyEngine {
    pub proxy: Arc<Proxy>,
    ca: RwLock<Option<Arc<CertAuthority>>>,
    data_dir: PathBuf,
    state: Mutex<State>,
    rules: RwLock<Option<Arc<crate::rules::Rules>>>,
    /// Currently loaded PAC resolver (cached; rebuilt only when the source changes).
    pac: Mutex<Option<Arc<crate::pac::PacResolver>>>,
}

#[derive(Default)]
struct State {
    system_proxy: bool,
    upstream: Option<String>,
    error: Option<String>,
    /// System proxy found before Quena took over (used as upstream).
    detected_upstream: Option<(String, u16)>,
    /// That proxy's exceptions: hosts the system reached directly, so Quena does too.
    detected_bypass: Vec<String>,
    pac_url: Option<String>,
}

/// Exceptions Quena writes into the system proxy settings while capturing. macOS and Linux
/// keep their usual defaults (Bonjour names, link-local addresses). Windows gets none: the
/// system default there is empty, and `<local>` ("bypass for local addresses") would let
/// intranet and VPN hosts without a dot pass Quena unseen.
fn system_bypass() -> Vec<String> {
    if cfg!(windows) {
        vec![]
    } else {
        vec!["*.local".into(), "169.254/16".into()]
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaInfo {
    pub exists: bool,
    pub trusted: bool,
    pub sha256: String,
    pub path: String,
    pub pem: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub port: u16,
    pub allow_remote: bool,
    pub listening: bool,
    pub addresses: Vec<(String, String)>,
    pub ca_sha256: Option<String>,
}

fn backup_path(data: &std::path::Path) -> PathBuf {
    data.join("system-proxy-backup.json")
}

/// A panic on the main thread ends the app without the normal shutdown: restore the
/// system proxy first, so the machine is not left pointing at a proxy that is gone.
/// Panics on worker threads are caught and do not end the app, so they leave it alone.
pub fn install_panic_hook(data: &std::path::Path) {
    let backup = backup_path(data);
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if std::thread::current().name() == Some("main") && backup.exists() {
            let _ = quena_platform::restore_system_proxy(&backup);
        }
        prev(info);
    }));
}

pub fn proxy_config(s: &Settings, detected: Option<(String, u16)>, system_bypass: &[String], pac: Option<Arc<dyn UpstreamResolver>>) -> ProxyConfig {
    let mut upstream_bypass = split_list(&s.proxy.upstream_bypass);
    let upstream = if !s.proxy.manual_upstream.trim().is_empty() {
        let (h, p) = split_host_port(s.proxy.manual_upstream.trim(), 8080);
        Some((h, p))
    } else if s.proxy.use_system_upstream {
        // Hosts the system proxy's exceptions sent direct go direct from Quena too (Quena
        // sets its own, shorter exceptions, so it now sees these hosts).
        if detected.is_some() {
            upstream_bypass.extend(system_bypass.iter().map(|b| b.trim().to_string()).filter(|b| !b.is_empty()));
        }
        detected
    } else {
        None
    };
    ProxyConfig {
        port: s.proxy.port,
        allow_remote: s.proxy.allow_remote,
        remote_allowlist: Cidr::parse_list(&s.proxy.remote_allowlist),
        decrypt: s.https.decrypt,
        decrypt_scope: match s.https.scope {
            SDecryptScope::All => DecryptScope::All,
            SDecryptScope::Browsers => DecryptScope::Browsers,
            SDecryptScope::NonBrowsers => DecryptScope::NonBrowsers,
            SDecryptScope::Remote => DecryptScope::Remote,
        },
        skip_decryption: split_list(&s.https.skip_decryption),
        ignore_cert_errors: s.https.ignore_cert_errors,
        ignore_cert_errors_hosts: split_list(&s.https.ignore_cert_errors_hosts),
        enable_http2: s.https.enable_http2,
        http2_downgrade_hosts: split_list(&s.https.http2_downgrade_hosts),
        upstream,
        upstream_bypass,
        pac,
        stream: s.stream,
        headers_only_hosts: split_list(&s.headers_only_hosts),
        headers_only_types: split_list(&s.headers_only_types),
        lossless: s.lossless_recording,
        auto_auth: s.auth.enabled,
        auto_auth_hosts: split_list(&s.auth.hosts),
        auto_auth_upstream: s.auth.upstream,
        auth_prefer: parse_prefer(&s.auth.prefer),
        throttle_bps: s.throttle_kbps.saturating_mul(1000) / 8,
        throttle_latency_ms: s.throttle_latency_ms,
        reverse: s
            .reverse_proxy
            .active()
            .filter_map(|e| e.to_route().map_err(|err| tracing::warn!(target: "quena", "reverse proxy {err}")).ok())
            .collect(),
        socks: s.socks.to_port(),
        transparent: s.transparent.to_port(),
    }
}

fn parse_prefer(s: &str) -> Vec<quena_proxy::Scheme> {
    let mut out = Vec::new();
    for t in s.split([';', ',', ' ']).map(|t| t.trim().to_ascii_lowercase()) {
        match t.as_str() {
            "negotiate" | "kerberos" => out.push(quena_proxy::Scheme::Negotiate),
            "ntlm" => out.push(quena_proxy::Scheme::Ntlm),
            "basic" => out.push(quena_proxy::Scheme::Basic),
            _ => {}
        }
    }
    if out.is_empty() {
        out = vec![quena_proxy::Scheme::Negotiate, quena_proxy::Scheme::Ntlm, quena_proxy::Scheme::Basic];
    }
    out
}

impl ProxyEngine {
    pub fn new(core: &Arc<AppCore>) -> Result<Arc<ProxyEngine>> {
        let data = core.paths.data.clone();
        // Browsers open many connections; the default soft limit (256 on macOS) is too low.
        if let Some(n) = quena_platform::raise_fd_limit(2 * quena_proxy::MAX_CLIENT_CONNECTIONS as u64 + 1024) {
            tracing::debug!(target: "quena", "open-file limit {n}");
        }
        // Crash recovery: a previous run left the system proxy pointing to us.
        match quena_platform::restore_system_proxy(&backup_path(&data)) {
            Ok(true) => tracing::warn!(target: "quena", "restored the system proxy left over by a previous run"),
            Ok(false) => {}
            Err(e) => tracing::error!(target: "quena", "restoring the system proxy failed: {e}"),
        }
        let s = core.settings();
        let ca = if s.https.decrypt || data.join(quena_tls::CA_CERT_FILE).exists() {
            Some(Arc::new(CertAuthority::load_or_create(&data).context("root CA")?))
        } else {
            None
        };
        let detected = detect_upstream(s.proxy.port);
        // The PAC file (possibly a download) is loaded by the first `apply`, i.e. when
        // capturing starts on its background thread, not while the app is starting up.
        let pac_slot: Mutex<Option<Arc<crate::pac::PacResolver>>> = Mutex::new(None);
        let proxy = Proxy::new(core.capture(), proxy_config(&s, detected.0.clone(), &detected.2, None), ca.clone()).map_err(|e| anyhow!("{e}"))?;
        proxy.shared.recorder.set_lossless(s.lossless_recording);
        if let Some(r) = &core.rules {
            proxy.set_interceptor(r.clone());
        }
        proxy.set_credential_resolver(Arc::new(crate::auth::AppCredentials::new(core.clone())));
        let e = Arc::new(ProxyEngine {
            proxy,
            ca: RwLock::new(ca),
            data_dir: data,
            state: Mutex::new(State { detected_upstream: detected.0, pac_url: detected.1, detected_bypass: detected.2, ..Default::default() }),
            rules: RwLock::new(core.rules.clone()),
            pac: pac_slot,
        });
        e.apply_client_certs(&s);
        Ok(e)
    }

    fn ensure_ca(&self) -> Result<Arc<CertAuthority>> {
        if let Some(c) = self.ca.read().clone() {
            return Ok(c);
        }
        let ca = Arc::new(CertAuthority::load_or_create(&self.data_dir)?);
        *self.ca.write() = Some(ca.clone());
        self.proxy.set_ca(Some(ca.clone()));
        Ok(ca)
    }

    pub fn ca_info(&self) -> CaInfo {
        match self.ca.read().clone() {
            Some(ca) => CaInfo {
                exists: true,
                trusted: quena_platform::is_root_ca_trusted(&ca.cert_path()),
                sha256: ca.sha256_fingerprint(),
                path: ca.cert_path().display().to_string(),
                pem: ca.cert_pem().to_string(),
            },
            None => CaInfo { exists: false, trusted: false, sha256: String::new(), path: String::new(), pem: String::new() },
        }
    }

    /// Install the root CA into the user's trust store (OS asks for confirmation).
    pub fn ca_trust(&self) -> Result<CaInfo> {
        let ca = self.ensure_ca()?;
        quena_platform::install_root_ca(&ca.cert_path()).map_err(|e| anyhow!("{e}"))?;
        tracing::info!(target: "quena", "root certificate trusted");
        Ok(self.ca_info())
    }

    pub fn ca_remove(&self) -> Result<CaInfo> {
        if let Some(ca) = self.ca.read().clone() {
            quena_platform::remove_root_ca(&ca.cert_path(), &ca.sha1_fingerprint()).map_err(|e| anyhow!("{e}"))?;
            tracing::info!(target: "quena", "root certificate removed from the trust store");
        }
        Ok(self.ca_info())
    }

    /// Create a new CA (the old one should be removed from the trust store first).
    pub fn ca_regenerate(&self) -> Result<CaInfo> {
        let ca = Arc::new(CertAuthority::regenerate(&self.data_dir)?);
        *self.ca.write() = Some(ca.clone());
        self.proxy.set_ca(Some(ca));
        Ok(self.ca_info())
    }

    pub fn ca_export(&self, path: PathBuf, der: bool) -> Result<()> {
        let ca = self.ensure_ca()?;
        if der {
            std::fs::write(path, ca.cert_der())?;
        } else {
            std::fs::write(path, ca.cert_pem())?;
        }
        Ok(())
    }

    pub fn device_info(&self, core: &AppCore) -> DeviceInfo {
        let s = core.settings();
        let listen = self.proxy.listen_addrs();
        DeviceInfo {
            port: listen.first().map(|a| a.port()).unwrap_or(s.proxy.port),
            allow_remote: s.proxy.allow_remote,
            listening: !listen.is_empty(),
            addresses: quena_platform::local_addresses(),
            ca_sha256: self.ca.read().as_ref().map(|c| c.sha256_fingerprint()),
        }
    }

    fn apply(&self, core: &Arc<AppCore>) -> Result<()> {
        let s = core.settings();
        // HTTPS clients of a reverse proxy port get certificates from the root CA too.
        let reverse_tls = s.reverse_proxy.active().any(|e| e.client_protocol != crate::settings::ClientProtocol::Http);
        if s.https.decrypt || reverse_tls {
            self.ensure_ca()?;
        }
        let (detected, system_pac, detected_bypass) = {
            let st = self.state.lock();
            (st.detected_upstream.clone(), st.pac_url.clone(), st.detected_bypass.clone())
        };
        let pac = resolve_pac(&self.pac, &s, system_pac.as_deref());
        let cfg = proxy_config(&s, detected, &detected_bypass, pac);
        self.state.lock().upstream = cfg.upstream.as_ref().map(|(h, p)| format!("{h}:{p}"));
        self.proxy.shared.recorder.set_lossless(s.lossless_recording);
        self.apply_client_certs(&s);
        self.proxy.reconfigure(cfg).map_err(|e| anyhow!("{e}"))
    }

    /// Load client certificates (mTLS) from the configured PEM files into the
    /// upstream TLS clients. Called on every (re)configure.
    fn apply_client_certs(&self, s: &Settings) {
        let tls = &self.proxy.shared.tls_clients;
        tls.clear_client_certs();
        for c in &s.https.client_certs {
            if c.host.trim().is_empty() || c.cert_path.trim().is_empty() {
                continue;
            }
            let chain = match std::fs::read_to_string(&c.cert_path) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(target: "quena", "client cert {} unreadable: {e}", c.cert_path);
                    continue;
                }
            };
            let key_path = if c.key_path.trim().is_empty() { &c.cert_path } else { &c.key_path };
            let key = match std::fs::read_to_string(key_path) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(target: "quena", "client key {key_path} unreadable: {e}");
                    continue;
                }
            };
            if let Err(e) = tls.add_client_cert(&c.host, &chain, &key) {
                tracing::warn!(target: "quena", "client cert for {} rejected: {e}", c.host);
            }
        }
    }
}

/// Read the current system proxy (before Quena overrides it).
/// Decide the effective PAC source and (re)build the resolver, caching it so the
/// engine is only recompiled when the source URL/path changes. A manual upstream
/// proxy disables PAC (the static upstream wins).
fn resolve_pac(
    slot: &Mutex<Option<Arc<crate::pac::PacResolver>>>,
    s: &Settings,
    system_pac: Option<&str>,
) -> Option<Arc<dyn UpstreamResolver>> {
    if !s.proxy.manual_upstream.trim().is_empty() {
        *slot.lock() = None;
        return None;
    }
    let manual = s.proxy.pac_url.trim();
    let location = if !manual.is_empty() {
        Some(manual.to_string())
    } else if s.proxy.use_system_pac {
        system_pac.map(|p| p.to_string())
    } else {
        None
    };
    let Some(location) = location else {
        *slot.lock() = None;
        return None;
    };
    if let Some(cur) = slot.lock().as_ref() {
        if cur.source_id == location {
            return Some(cur.clone() as Arc<dyn UpstreamResolver>);
        }
    }
    let source = match crate::pac::load_pac_source(&location) {
        Ok(src) => src,
        Err(e) => {
            tracing::warn!(target: "quena", "PAC load from {location} failed: {e}; using direct/static upstream");
            *slot.lock() = None;
            return None;
        }
    };
    let resolver = crate::pac::PacResolver::new(location.clone(), &source);
    if let Some(err) = resolver.error() {
        tracing::warn!(target: "quena", "PAC script {location} is invalid: {err}; using direct/static upstream");
        *slot.lock() = None;
        return None;
    }
    tracing::info!(target: "quena", "PAC loaded from {location}");
    *slot.lock() = Some(resolver.clone());
    Some(resolver as Arc<dyn UpstreamResolver>)
}

fn detect_upstream(own_port: u16) -> (Option<(String, u16)>, Option<String>, Vec<String>) {
    match quena_platform::system_proxy() {
        Ok(p) if p.points_to(own_port) => (None, None, vec![]),
        Ok(p) => {
            let up = p.https.clone().or(p.http.clone());
            if let Some((h, port)) = &up {
                tracing::info!(target: "quena", "upstream gateway detected: {h}:{port}");
            }
            if let Some(pac) = &p.pac_url {
                tracing::info!(target: "quena", "the system uses a proxy auto-config script ({pac}); Quena will evaluate it when \"use system PAC\" is enabled");
            }
            (up, p.pac_url, p.exceptions)
        }
        Err(e) => {
            tracing::debug!("system proxy detection failed: {e}");
            (None, None, vec![])
        }
    }
}

impl CaptureEngine for ProxyEngine {
    fn start(&self, core: &Arc<AppCore>) -> Result<()> {
        self.apply(core)?;
        let addrs = match self.proxy.start() {
            Ok(a) => a,
            Err(e) => {
                self.state.lock().error = Some(e.to_string());
                return Err(anyhow!("{e}"));
            }
        };
        self.state.lock().error = None;
        let s = core.settings();
        if s.proxy.act_as_system_proxy {
            let port = addrs[0].port();
            match quena_platform::set_system_proxy(port, &system_bypass(), &backup_path(&self.data_dir)) {
                Ok(()) => self.state.lock().system_proxy = true,
                Err(e) => {
                    // Some services may already point to us: undo the partial change.
                    let _ = quena_platform::restore_system_proxy(&backup_path(&self.data_dir));
                    tracing::warn!(target: "quena", "could not set the system proxy: {e} – configure clients to use 127.0.0.1:{port} manually");
                    self.state.lock().error = Some(format!("system proxy: {e}"));
                }
            }
        }
        Ok(())
    }

    fn stop(&self, _core: &Arc<AppCore>) -> Result<()> {
        let was_system = std::mem::take(&mut self.state.lock().system_proxy);
        if was_system {
            if let Err(e) = quena_platform::restore_system_proxy(&backup_path(&self.data_dir)) {
                tracing::error!(target: "quena", "restoring the system proxy failed: {e}");
                self.state.lock().error = Some(format!("restore system proxy: {e}"));
            }
        }
        self.proxy.stop();
        Ok(())
    }

    fn status(&self) -> EngineStatus {
        let st = self.state.lock();
        let cfg = self.proxy.shared.cfg();
        EngineStatus {
            capturing: self.proxy.is_running(),
            listen: self.proxy.listen_addrs().iter().map(|a| a.to_string()).collect(),
            system_proxy: st.system_proxy,
            decrypting: cfg.decrypt && self.ca.read().is_some(),
            upstream: st.upstream.clone(),
            error: st.error.clone(),
            breakpoints: self.rules.read().as_ref().map(|r| r.breakpoints().labels()).unwrap_or_default(),
            paused: self.rules.read().as_ref().map(|r| r.paused().len()).unwrap_or(0),
            autoresponder: self.rules.read().as_ref().is_some_and(|r| r.autoresponder_active()),
            rewrite: self.rules.read().as_ref().is_some_and(|r| r.rewrite.active()),
            listeners: self.proxy.listener_status(),
        }
    }

    fn reconfigure(&self, core: &Arc<AppCore>) -> Result<()> {
        let was_running = self.proxy.is_running();
        let old_port = self.proxy.listen_addrs().first().map(|a| a.port());
        self.apply(core)?;
        // Port changed while acting as system proxy: point the OS to the new port.
        let new_port = self.proxy.listen_addrs().first().map(|a| a.port());
        if was_running && old_port != new_port && self.state.lock().system_proxy {
            if let Some(p) = new_port {
                let _ = quena_platform::set_system_proxy(p, &system_bypass(), &backup_path(&self.data_dir));
            }
        }
        Ok(())
    }

    fn capture_changed(&self, core: &Arc<AppCore>) {
        self.proxy.set_capture(core.capture());
    }

    fn shutdown(&self, core: &Arc<AppCore>) {
        let _ = self.stop(core);
    }
}

pub fn pac_url(e: &ProxyEngine) -> Option<String> {
    e.state.lock().pac_url.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_exceptions_go_direct() {
        let mut s = Settings::default();
        let corp = Some(("proxy.corp".to_string(), 8080));
        let exc = vec!["<local>".to_string(), "*.corp.example".to_string(), " ".to_string()];
        let cfg = proxy_config(&s, corp.clone(), &exc, None);
        assert_eq!(cfg.upstream_for("appserver:80"), None);
        assert_eq!(cfg.upstream_for("wiki.corp.example:443"), None);
        assert_eq!(cfg.upstream_for("example.com:443"), corp);
        // A manual upstream comes with its own bypass list.
        s.proxy.manual_upstream = "gw.example:3128".into();
        let cfg = proxy_config(&s, corp, &exc, None);
        assert_eq!(cfg.upstream_for("appserver:80"), Some(("gw.example".to_string(), 3128)));
    }

    #[test]
    fn windows_keeps_local_addresses_in_capture() {
        let b = system_bypass();
        assert!(!b.iter().any(|e| e == "<local>"));
        assert_eq!(b.is_empty(), cfg!(windows));
    }
}
