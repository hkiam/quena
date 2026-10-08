//! Start a browser or a terminal whose traffic goes through Quena, without touching the
//! system proxy: the browser gets its own profile with Quena as proxy (and, for Chromium,
//! Quena's certificates accepted by key), the terminal's environment names Quena as proxy and
//! its root certificate for the usual tools.

use crate::AppCore;
use anyhow::{Context, Result, anyhow};
use quena_platform::launch::{Browser, BrowserFamily};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Command line of a Chromium browser with its own profile and Quena as proxy.
pub fn chromium_args(profile: &Path, port: u16, spki: &str, url: Option<&str>) -> Vec<String> {
    let mut a = vec![
        format!("--user-data-dir={}", profile.display()),
        format!("--proxy-server=127.0.0.1:{port}"),
        // Also send localhost through Quena (Chromium bypasses it by default).
        "--proxy-bypass-list=<-loopback>".to_string(),
        // Accept certificates that chain to Quena's root, identified by its key; only with
        // its own profile (--user-data-dir), so the user's normal browser is not affected.
        format!("--ignore-certificate-errors-spki-list={spki}"),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        "--new-window".to_string(),
    ];
    a.push(url.unwrap_or("about:blank").to_string());
    a
}

/// Firefox preferences (`user.js`) for a profile that uses Quena.
pub fn firefox_prefs(port: u16) -> String {
    let prefs: [(&str, String); 11] = [
        ("network.proxy.type", "1".into()),
        ("network.proxy.http", "\"127.0.0.1\"".into()),
        ("network.proxy.http_port", port.to_string()),
        ("network.proxy.ssl", "\"127.0.0.1\"".into()),
        ("network.proxy.ssl_port", port.to_string()),
        ("network.proxy.no_proxies_on", "\"\"".into()),
        ("network.proxy.allow_hijacking_localhost", "true".into()),
        // Trust the roots of the system store (where "Trust root certificate" puts Quena's).
        ("security.enterprise_roots.enabled", "true".into()),
        ("browser.shell.checkDefaultBrowser", "false".into()),
        ("browser.aboutwelcome.enabled", "false".into()),
        ("datareporting.policy.dataSubmissionPolicyBypassNotification", "true".into()),
    ];
    prefs.iter().map(|(k, v)| format!("user_pref(\"{k}\", {v});\n")).collect()
}

/// Command line of Firefox with its own profile.
pub fn firefox_args(profile: &Path, url: Option<&str>) -> Vec<String> {
    vec!["-profile".into(), profile.display().to_string(), "-no-remote".into(), "-new-instance".into(), url.unwrap_or("about:blank").to_string()]
}

/// Environment of a terminal that uses Quena. `bundle`: system roots plus Quena's, for the
/// variables that replace a tool's trust store; without it only additive ones are set.
pub fn terminal_env(port: u16, quena_ca: &Path, bundle: Option<&Path>) -> Vec<(String, String)> {
    let proxy = format!("http://127.0.0.1:{port}");
    let mut env = Vec::new();
    for k in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
        env.push((k.to_string(), proxy.clone()));
        env.push((k.to_ascii_lowercase(), proxy.clone()));
    }
    env.push(("QUENA_PROXY".into(), proxy));
    // Node.js adds these roots to its own.
    env.push(("NODE_EXTRA_CA_CERTS".into(), quena_ca.display().to_string()));
    if let Some(b) = bundle {
        let b = b.display().to_string();
        for k in ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "AWS_CA_BUNDLE", "PIP_CERT", "CARGO_HTTP_CAINFO"] {
            env.push((k.to_string(), b.clone()));
        }
    }
    env
}

/// A browser found on this machine, for the UI.
pub type BrowserInfo = Browser;

impl AppCore {
    /// The browsers that can be started with Quena.
    pub fn browsers(&self) -> Vec<BrowserInfo> {
        quena_platform::launch::find_browsers()
    }

    /// Start capturing if needed and return Quena's proxy port.
    fn capture_port(self: &Arc<Self>) -> Result<u16> {
        self.start_capture()?;
        let engine = self.proxy_engine()?;
        let addrs = engine.proxy.listen_addrs();
        addrs.iter().find(|a| a.is_ipv4()).or(addrs.first()).map(|a| a.port()).ok_or_else(|| anyhow!("the proxy is not listening"))
    }

    /// Start `kind` (from [`AppCore::browsers`]) with its own Quena profile.
    pub fn launch_browser(self: &Arc<Self>, kind: &str, url: Option<&str>) -> Result<Browser> {
        let b = self.browsers().into_iter().find(|b| b.kind == kind).ok_or_else(|| anyhow!("{kind}: browser not found"))?;
        let port = self.capture_port()?;
        let profile = self.paths.data.join("browser-profiles").join(&b.kind);
        std::fs::create_dir_all(&profile).with_context(|| profile.display().to_string())?;
        let args = match b.family {
            BrowserFamily::Chromium => {
                let ca = self.proxy_engine()?.ensure_ca()?;
                chromium_args(&profile, port, &ca.spki_sha256_base64(), url)
            }
            BrowserFamily::Firefox => {
                std::fs::write(profile.join("user.js"), firefox_prefs(port)).context("Firefox profile")?;
                firefox_args(&profile, url)
            }
        };
        quena_platform::launch::launch_detached(&b.exe, &args, &[]).map_err(|e| anyhow!("{e}"))?;
        tracing::info!(target: "quena", "started {} with Quena as proxy (port {port})", b.name);
        Ok(b)
    }

    /// Open a terminal whose tools use Quena (proxy variables and root certificate).
    pub fn open_terminal(self: &Arc<Self>) -> Result<()> {
        let port = self.capture_port()?;
        let ca = self.proxy_engine()?.ensure_ca()?;
        let ca_path = ca.cert_path();
        let bundle = quena_platform::launch::system_ca_pem().map(|system| -> Result<PathBuf> {
            let p = self.paths.data.join("quena-ca-bundle.pem");
            std::fs::write(&p, format!("{system}\n{}", ca.cert_pem())).context("CA bundle")?;
            Ok(p)
        });
        let bundle = bundle.transpose()?;
        let env = terminal_env(port, &ca_path, bundle.as_deref());
        quena_platform::launch::open_terminal(&env, &self.paths.data.join("terminal")).map_err(|e| anyhow!("{e}"))?;
        tracing::info!(target: "quena", "opened a terminal that uses Quena (port {port})");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chromium_uses_its_own_profile_and_quena() {
        let a = chromium_args(Path::new("/data/browser-profiles/chrome"), 8866, "AbC=", Some("https://example.com"));
        assert!(a.contains(&"--user-data-dir=/data/browser-profiles/chrome".to_string()));
        assert!(a.contains(&"--proxy-server=127.0.0.1:8866".to_string()));
        assert!(a.contains(&"--ignore-certificate-errors-spki-list=AbC=".to_string()));
        assert_eq!(a.last().unwrap(), "https://example.com");
        assert_eq!(chromium_args(Path::new("/p"), 1, "x", None).last().unwrap(), "about:blank");
    }

    #[test]
    fn firefox_prefs_name_the_port() {
        let p = firefox_prefs(9000);
        assert!(p.contains("user_pref(\"network.proxy.http_port\", 9000);"));
        assert!(p.contains("user_pref(\"network.proxy.type\", 1);"));
        assert!(p.lines().all(|l| l.starts_with("user_pref(\"") && l.ends_with(");")), "{p}");
    }

    #[test]
    fn terminal_env_replaces_trust_stores_only_with_a_bundle() {
        let ca = Path::new("/d/quena-root-ca.pem");
        let get = |env: &[(String, String)], k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        let e = terminal_env(8866, ca, None);
        assert_eq!(get(&e, "HTTPS_PROXY").as_deref(), Some("http://127.0.0.1:8866"));
        assert_eq!(get(&e, "https_proxy").as_deref(), Some("http://127.0.0.1:8866"));
        assert_eq!(get(&e, "NODE_EXTRA_CA_CERTS").as_deref(), Some("/d/quena-root-ca.pem"));
        assert_eq!(get(&e, "SSL_CERT_FILE"), None);
        let e = terminal_env(8866, ca, Some(Path::new("/d/bundle.pem")));
        assert_eq!(get(&e, "SSL_CERT_FILE").as_deref(), Some("/d/bundle.pem"));
        assert_eq!(get(&e, "REQUESTS_CA_BUNDLE").as_deref(), Some("/d/bundle.pem"));
    }
}
