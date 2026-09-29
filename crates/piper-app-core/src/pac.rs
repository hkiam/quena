//! PAC (proxy auto-config) integration: fetch a PAC script and expose it to the
//! proxy as an [`UpstreamResolver`]. Evaluation itself lives in `piper-script`.

use anyhow::{anyhow, Result};
use piper_proxy::UpstreamResolver;
use piper_script::PacEngine;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

/// Wraps a compiled PAC engine so the proxy can resolve upstreams per host.
pub struct PacResolver {
    engine: Arc<PacEngine>,
    /// The URL/path the PAC was loaded from (used to detect changes).
    pub source_id: String,
}

impl PacResolver {
    pub fn new(source_id: String, source: &str) -> Arc<PacResolver> {
        Arc::new(PacResolver { engine: Arc::new(PacEngine::new(source)), source_id })
    }

    pub fn error(&self) -> Option<String> {
        self.engine.error().map(|s| s.to_string())
    }
}

impl std::fmt::Debug for PacResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacResolver").field("source", &self.source_id).finish()
    }
}

impl UpstreamResolver for PacResolver {
    fn upstream_for(&self, host_port: &str) -> Option<(String, u16)> {
        self.engine.upstream_for(host_port)
    }
}

/// Load a PAC script from a `file://` URL, `http://` URL, or a local file path.
/// `https://` is not fetched here (provide a downloaded file instead).
pub fn load_pac_source(loc: &str) -> Result<String> {
    let loc = loc.trim();
    if let Some(path) = loc.strip_prefix("file://") {
        return Ok(std::fs::read_to_string(path)?);
    }
    if loc.starts_with("http://") {
        return http_get(loc);
    }
    if loc.starts_with("https://") {
        return Err(anyhow!("https:// PAC URLs are not fetched automatically; download the file and set its path"));
    }
    Ok(std::fs::read_to_string(loc)?)
}

fn http_get(url: &str) -> Result<String> {
    let rest = &url["http://".len()..];
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(80)),
        None => (authority.to_string(), 80u16),
    };
    let mut stream = TcpStream::connect((host.as_str(), port))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: Piper\r\n\r\n");
    stream.write_all(req.as_bytes())?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    let idx = buf.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| anyhow!("malformed HTTP response"))?;
    let head = &buf[..idx];
    let status_line = head.split(|&b| b == b'\n').next().unwrap_or(&[]);
    let status = String::from_utf8_lossy(status_line);
    if !status.contains(" 200") {
        return Err(anyhow!("PAC fetch failed: {}", status.trim()));
    }
    Ok(String::from_utf8_lossy(&buf[idx + 4..]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use piper_proxy::UpstreamResolver;

    #[test]
    fn resolver_selects_upstream_per_host() {
        let src = r#"
            function FindProxyForURL(url, host) {
                if (isPlainHostName(host)) return "DIRECT";
                if (shExpMatch(host, "*.corp.example")) return "PROXY gw.corp.example:8080";
                return "DIRECT";
            }
        "#;
        let r = PacResolver::new("inline".into(), src);
        assert!(r.error().is_none());
        assert_eq!(r.upstream_for("intranet:80"), None);
        assert_eq!(r.upstream_for("app.corp.example:443"), Some(("gw.corp.example".into(), 8080)));
        assert_eq!(r.upstream_for("example.org:443"), None);
    }

    #[test]
    fn loads_pac_from_file_and_file_url() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.pac");
        std::fs::write(&path, "function FindProxyForURL(u,h){return 'DIRECT';}").unwrap();
        let by_path = load_pac_source(path.to_str().unwrap()).unwrap();
        assert!(by_path.contains("FindProxyForURL"));
        let by_url = load_pac_source(&format!("file://{}", path.display())).unwrap();
        assert_eq!(by_path, by_url);
    }

    #[test]
    fn https_pac_is_rejected_with_guidance() {
        let err = load_pac_source("https://proxy.example/proxy.pac").unwrap_err().to_string();
        assert!(err.contains("https"));
    }
}
