//! Capture engine: the proxy plus system integration (system proxy,
//! upstream detection, root CA management).

use crate::settings::{DecryptScope as SDecryptScope, Settings};
use crate::{AppCore, CaptureEngine, EngineStatus};
use anyhow::{Context, Result, anyhow};
use parking_lot::{Mutex, RwLock};
use piper_proxy::util::{Cidr, split_host_port, split_list};
use piper_proxy::{DecryptScope, Proxy, ProxyConfig};
use piper_tls::CertAuthority;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;

pub struct ProxyEngine {
    pub proxy: Arc<Proxy>,
    ca: RwLock<Option<Arc<CertAuthority>>>,
    data_dir: PathBuf,
    state: Mutex<State>,
    rules: RwLock<Option<Arc<crate::rules::Rules>>>,
}

#[derive(Default)]
struct State {
    system_proxy: bool,
    upstream: Option<String>,
    error: Option<String>,
    /// System proxy found before Piper took over (used as upstream).
    detected_upstream: Option<(String, u16)>,
    pac_url: Option<String>,
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

pub fn proxy_config(s: &Settings, detected: Option<(String, u16)>) -> ProxyConfig {
    let upstream = if !s.proxy.manual_upstream.trim().is_empty() {
        let (h, p) = split_host_port(s.proxy.manual_upstream.trim(), 8080);
        Some((h, p))
    } else if s.proxy.use_system_upstream {
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
        upstream_bypass: split_list(&s.proxy.upstream_bypass),
        stream: s.stream,
        headers_only_hosts: split_list(&s.headers_only_hosts),
        headers_only_types: split_list(&s.headers_only_types),
        lossless: s.lossless_recording,
    }
}

impl ProxyEngine {
    pub fn new(core: &Arc<AppCore>) -> Result<Arc<ProxyEngine>> {
        let data = core.paths.data.clone();
        // Crash recovery: a previous run left the system proxy pointing to us.
        match piper_platform::restore_system_proxy(&backup_path(&data)) {
            Ok(true) => tracing::warn!(target: "piper", "restored the system proxy left over by a previous run"),
            Ok(false) => {}
            Err(e) => tracing::error!(target: "piper", "restoring the system proxy failed: {e}"),
        }
        let s = core.settings();
        let ca = if s.https.decrypt || data.join(piper_tls::CA_CERT_FILE).exists() {
            Some(Arc::new(CertAuthority::load_or_create(&data).context("root CA")?))
        } else {
            None
        };
        let detected = detect_upstream(s.proxy.port);
        let proxy = Proxy::new(core.capture(), proxy_config(&s, detected.0.clone()), ca.clone()).map_err(|e| anyhow!("{e}"))?;
        proxy.shared.recorder.set_lossless(s.lossless_recording);
        if let Some(r) = &core.rules {
            proxy.set_interceptor(r.clone());
        }
        let e = Arc::new(ProxyEngine {
            proxy,
            ca: RwLock::new(ca),
            data_dir: data,
            state: Mutex::new(State { detected_upstream: detected.0, pac_url: detected.1, ..Default::default() }),
            rules: RwLock::new(core.rules.clone()),
        });
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
                trusted: piper_platform::is_root_ca_trusted(&ca.cert_path()),
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
        piper_platform::install_root_ca(&ca.cert_path()).map_err(|e| anyhow!("{e}"))?;
        tracing::info!(target: "piper", "root certificate trusted");
        Ok(self.ca_info())
    }

    pub fn ca_remove(&self) -> Result<CaInfo> {
        if let Some(ca) = self.ca.read().clone() {
            piper_platform::remove_root_ca(&ca.cert_path(), &ca.sha1_fingerprint()).map_err(|e| anyhow!("{e}"))?;
            tracing::info!(target: "piper", "root certificate removed from the trust store");
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
            addresses: piper_platform::local_addresses(),
            ca_sha256: self.ca.read().as_ref().map(|c| c.sha256_fingerprint()),
        }
    }

    fn apply(&self, core: &Arc<AppCore>) -> Result<()> {
        let s = core.settings();
        if s.https.decrypt {
            self.ensure_ca()?;
        }
        let detected = self.state.lock().detected_upstream.clone();
        let cfg = proxy_config(&s, detected);
        self.state.lock().upstream = cfg.upstream.as_ref().map(|(h, p)| format!("{h}:{p}"));
        self.proxy.shared.recorder.set_lossless(s.lossless_recording);
        self.proxy.reconfigure(cfg).map_err(|e| anyhow!("{e}"))
    }
}

/// Read the current system proxy (before Piper overrides it).
fn detect_upstream(own_port: u16) -> (Option<(String, u16)>, Option<String>) {
    match piper_platform::system_proxy() {
        Ok(p) if p.points_to(own_port) => (None, None),
        Ok(p) => {
            let up = p.https.clone().or(p.http.clone());
            if let Some((h, port)) = &up {
                tracing::info!(target: "piper", "upstream gateway detected: {h}:{port}");
            }
            if let Some(pac) = &p.pac_url {
                tracing::warn!(target: "piper", "the system uses a proxy auto-config script ({pac}); PAC evaluation is not supported yet – set a manual upstream proxy if needed");
            }
            (up, p.pac_url)
        }
        Err(e) => {
            tracing::debug!("system proxy detection failed: {e}");
            (None, None)
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
            let bypass: Vec<String> = vec!["*.local".into(), "169.254/16".into()];
            match piper_platform::set_system_proxy(port, &bypass, &backup_path(&self.data_dir)) {
                Ok(()) => self.state.lock().system_proxy = true,
                Err(e) => {
                    tracing::warn!(target: "piper", "could not set the system proxy: {e} – configure clients to use 127.0.0.1:{port} manually");
                    self.state.lock().error = Some(format!("system proxy: {e}"));
                }
            }
        }
        Ok(())
    }

    fn stop(&self, _core: &Arc<AppCore>) -> Result<()> {
        let was_system = std::mem::take(&mut self.state.lock().system_proxy);
        if was_system {
            if let Err(e) = piper_platform::restore_system_proxy(&backup_path(&self.data_dir)) {
                tracing::error!(target: "piper", "restoring the system proxy failed: {e}");
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
                let _ = piper_platform::set_system_proxy(p, &["*.local".into(), "169.254/16".into()], &backup_path(&self.data_dir));
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
