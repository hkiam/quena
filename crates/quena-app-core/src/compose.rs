//! Replay (R / Shift+R / U) and Composer.

use crate::AppCore;
use crate::engine::ProxyEngine;
use anyhow::{Result, anyhow};
use quena_model::*;
use quena_proxy::ExecuteOptions;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ReplayOptions {
    /// Remove conditional headers ("Replay Unconditionally").
    pub unconditional: bool,
    /// Number of times to replay each request.
    pub count: u32,
    /// Stop at a request breakpoint (Reissue and Edit).
    pub breakpoint: bool,
    /// Run sequentially (one after the other) instead of in parallel.
    pub sequential: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComposeRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub version: Option<HttpVersion>,
    /// Header lines (`Name: value`).
    pub headers: String,
    /// Body text (ignored when `body_from_session` or `body_file` is set).
    #[serde(default)]
    pub body: String,
    /// Charset the body text was shown in (loaded from a session); the text is encoded in
    /// the charset the Content-Type declares, else in this one, else UTF-8
    /// (`quena_body::text::encode_edited`).
    #[serde(default)]
    pub body_charset: Option<String>,
    #[serde(default)]
    pub body_from_session: Option<SessionId>,
    #[serde(default)]
    pub body_file: Option<String>,
    /// Recompute Content-Length (Composer option "Fix Content-Length").
    #[serde(default = "yes")]
    pub fix_content_length: bool,
    #[serde(default)]
    pub breakpoint: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ParsedRequest {
    pub method: String,
    pub url: String,
    pub version: String,
    pub headers: String,
    pub body: String,
}

/// Parse a raw HTTP request (Composer "Raw" tab).
pub fn parse_raw_request(raw: &str) -> Result<ParsedRequest> {
    let raw = raw.replace("\r\n", "\n");
    let (head, body) = match raw.find("\n\n") {
        Some(i) => (&raw[..i], &raw[i + 2..]),
        None => (raw.as_str(), ""),
    };
    let mut lines = head.lines();
    let first = lines.next().ok_or_else(|| anyhow!("empty request"))?;
    let mut parts = first.split_whitespace();
    let method = parts.next().ok_or_else(|| anyhow!("missing method"))?.to_string();
    let mut url = parts.next().ok_or_else(|| anyhow!("missing URL"))?.to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();
    let headers: Vec<&str> = lines.collect();
    if url.starts_with('/') {
        let host = headers
            .iter()
            .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("host")).map(|(_, v)| v.trim().to_string()))
            .ok_or_else(|| anyhow!("relative URL needs a Host header"))?;
        url = format!("http://{host}{url}");
    }
    Ok(ParsedRequest { method, url, version, headers: headers.join("\n"), body: body.to_string() })
}

/// Parse a `curl` command line into a Composer-ready request.
pub fn parse_curl(cmd: &str) -> Result<ParsedRequest> {
    let c = quena_formats::curl::parse(cmd).map_err(|e| anyhow!("{e}"))?;
    let headers = c.headers.iter().map(|(n, v)| format!("{n}: {v}")).collect::<Vec<_>>().join("\n");
    Ok(ParsedRequest { method: c.method, url: c.url, version: "HTTP/1.1".into(), headers, body: c.body })
}

fn parse_header_lines(s: &str) -> Headers {
    let mut h = Headers::new();
    for line in s.lines() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            h.push(k.trim(), v.trim_start());
        }
    }
    h
}

impl AppCore {
    fn proxy_engine(&self) -> Result<Arc<ProxyEngine>> {
        self.proxy_engine.read().clone().ok_or_else(|| anyhow!("capture engine not available"))
    }

    pub fn set_proxy_engine(&self, e: Arc<ProxyEngine>) {
        *self.proxy_engine.write() = Some(e.clone());
        self.set_engine(e);
    }

    /// Replay sessions. Returns immediately; new sessions appear in the list.
    pub fn replay(self: &Arc<Self>, ids: Vec<SessionId>, o: ReplayOptions) -> Result<usize> {
        let engine = self.proxy_engine()?;
        let cap = self.capture();
        let mut jobs = Vec::new();
        for id in ids {
            let Some(d) = cap.detail(id) else { continue };
            if d.summary.kind == SessionKind::Tunnel || d.request.method.eq_ignore_ascii_case("CONNECT") {
                continue;
            }
            let Some((req_body, _)) = cap.bodies_of(id) else { continue };
            let mut head = d.request.clone();
            if o.unconditional {
                for h in ["if-modified-since", "if-none-match", "if-match", "if-unmodified-since", "if-range"] {
                    head.headers.remove(h);
                }
            }
            if head.version == HttpVersion::Http2 {
                head.version = HttpVersion::Http11;
            }
            head.headers.0.retain(|(k, _)| !k.starts_with(':'));
            if head.headers.get("host").is_none() {
                let (host, _) = split_url(&head.url, &head.method);
                head.headers.0.insert(0, ("Host".into(), host));
            }
            jobs.push((id, head, req_body));
        }
        let n = jobs.len();
        let count = o.count.max(1);
        let shared = engine.proxy.shared.clone();
        let sequential = o.sequential || count > 1;
        let rt = engine.proxy.runtime().handle().clone();
        rt.spawn(async move {
            let mut handles = Vec::new();
            for _ in 0..count {
                for (orig, head, body) in &jobs {
                    let opts = ExecuteOptions {
                        flags: flags::REPLAYED | if o.breakpoint { flags::BREAKPOINTED } else { 0 },
                        comment: Some(format!("Replay of #{orig}")),
                        hooks: true,
                    };
                    let f = quena_proxy::execute(shared.clone(), head.clone(), body.clone(), opts);
                    if sequential {
                        f.await;
                    } else {
                        handles.push(tokio::spawn(f));
                    }
                }
            }
            for h in handles {
                let _ = h.await;
            }
        });
        Ok(n * count as usize)
    }

    /// Execute a Composer request. Returns the new session id.
    pub fn compose(self: &Arc<Self>, r: ComposeRequest) -> Result<SessionId> {
        let engine = self.proxy_engine()?;
        let cap = self.capture();
        let url = r.url.trim().to_string();
        let uri: http_uri::Uri = url.parse().map_err(|e| anyhow!("invalid URL: {e}"))?;
        if uri.scheme.is_none() || uri.authority.is_empty() {
            return Err(anyhow!("the URL must be absolute (http:// or https://)"));
        }
        let mut headers = parse_header_lines(&r.headers);
        let body = if let Some(id) = r.body_from_session {
            cap.bodies_of(id).map(|(b, _)| b).ok_or_else(|| anyhow!("session #{id} not found"))?
        } else if let Some(f) = &r.body_file {
            // Stream the file into the store (large files are fine).
            let mut w = cap.bodies.writer_with_limit(u64::MAX);
            let mut file = std::fs::File::open(f)?;
            let mut buf = vec![0u8; 1 << 20];
            loop {
                use std::io::Read;
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                w.write(&buf[..n])?;
            }
            w.finish()
        } else {
            let (bytes, content_type) = quena_body::text::encode_edited(&r.body, headers.get("content-type"), r.body_charset.as_deref());
            if let Some(ct) = content_type {
                headers.set("Content-Type", ct);
            }
            cap.bodies.store_bytes(&bytes)
        };
        if r.fix_content_length {
            headers.remove("transfer-encoding");
            if body.len() > 0 || !matches!(r.method.to_ascii_uppercase().as_str(), "GET" | "HEAD" | "DELETE" | "OPTIONS") {
                headers.set("Content-Length", body.len().to_string());
            } else {
                headers.remove("content-length");
            }
        }
        if headers.get("host").is_none() {
            headers.0.insert(0, ("Host".into(), uri.authority.clone()));
        }
        let head = RequestHead { method: r.method.trim().to_ascii_uppercase(), url, version: HttpVersion::Http11, headers };
        let shared = engine.proxy.shared.clone();
        let opts = ExecuteOptions { flags: flags::COMPOSED | if r.breakpoint { flags::BREAKPOINTED } else { 0 }, comment: None, hooks: true };
        let rt = engine.proxy.runtime().handle().clone();
        let (tx, rx) = std::sync::mpsc::channel();
        rt.spawn(async move {
            let id = quena_proxy::execute_with(shared, head, body, opts, move |id| {
                let _ = tx.send(id);
            })
            .await;
            let _ = id;
        });
        rx.recv_timeout(std::time::Duration::from_secs(5)).map_err(|_| anyhow!("composer request did not start"))
    }
}

/// Minimal URL splitting (avoid pulling in a URL crate).
mod http_uri {
    pub struct Uri {
        pub scheme: Option<String>,
        pub authority: String,
    }
    impl std::str::FromStr for Uri {
        type Err = String;
        fn from_str(s: &str) -> Result<Self, String> {
            let (scheme, rest) = match s.split_once("://") {
                Some((sc, r)) if sc == "http" || sc == "https" => (Some(sc.to_string()), r),
                Some((sc, _)) => return Err(format!("unsupported scheme {sc}")),
                None => (None, s),
            };
            let authority = rest.split(['/', '?', '#']).next().unwrap_or("").to_string();
            if authority.contains(' ') {
                return Err("space in host".into());
            }
            Ok(Uri { scheme, authority })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_parse() {
        let p = parse_raw_request("POST /api HTTP/1.1\r\nHost: a.b\r\nContent-Type: text/plain\r\n\r\nhello").unwrap();
        assert_eq!(p.url, "http://a.b/api");
        assert_eq!(p.method, "POST");
        assert_eq!(p.body, "hello");
        assert!(p.headers.contains("Content-Type"));
    }
}
