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
    /// At most this many at a time (0: all at once for a single round, one at a time for
    /// repeats; capped at [`MAX_PARALLEL`]).
    pub parallel: u32,
}

/// Most redirects the Composer follows.
pub const MAX_REDIRECTS: usize = 10;

/// `location` of a response to `base` as an absolute URL.
pub fn resolve_location(base: &str, location: &str) -> Option<String> {
    let loc = location.trim();
    if loc.is_empty() {
        return None;
    }
    if loc.starts_with("http://") || loc.starts_with("https://") {
        return Some(loc.to_string());
    }
    let (scheme, rest) = base.split_once("://")?;
    let (authority, path) = rest.find('/').map(|i| (&rest[..i], &rest[i..])).unwrap_or((rest, "/"));
    let path = path.split('#').next().unwrap_or(path);
    Some(if let Some(l) = loc.strip_prefix("//") {
        format!("{scheme}://{l}")
    } else if loc.starts_with('/') {
        format!("{scheme}://{authority}{loc}")
    } else if loc.starts_with('?') {
        format!("{scheme}://{authority}{}{loc}", path.split('?').next().unwrap_or(path))
    } else {
        let dir = path.split('?').next().unwrap_or(path);
        let dir = &dir[..dir.rfind('/').map_or(0, |i| i + 1)];
        format!("{scheme}://{authority}{}{loc}", if dir.is_empty() { "/" } else { dir })
    })
}

/// Most repeats of one replay, and most requests in flight at once.
pub const MAX_REPEAT: u32 = 100_000;
pub const MAX_PARALLEL: u32 = 100;

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
    /// Follow redirects (3xx with `Location`), each as its own session, up to [`MAX_REDIRECTS`].
    #[serde(default)]
    pub follow_redirects: bool,
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

/// `host[:port]` of an absolute URL.
fn authority_of(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    Some(rest.split(['/', '?', '#']).next().unwrap_or(rest).to_ascii_lowercase())
}

fn parse_header_lines(s: &str) -> Headers {
    let mut h = Headers::new();
    for line in s.lines() {
        let line = line.trim_end_matches('\r');
        // `#` turns a header off (the Composer's header table).
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            h.push(k.trim(), v.trim_start());
        }
    }
    h
}

impl AppCore {
    pub(crate) fn proxy_engine(&self) -> Result<Arc<ProxyEngine>> {
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
        let count = o.count.clamp(1, MAX_REPEAT);
        let shared = engine.proxy.shared.clone();
        let at_once = if o.sequential {
            1
        } else if o.parallel > 0 {
            o.parallel.min(MAX_PARALLEL) as usize
        } else if count > 1 {
            1
        } else {
            n.clamp(1, MAX_PARALLEL as usize)
        };
        // Stop ends the replays running (requests in flight finish).
        let generation = self.replay_generation.load(std::sync::atomic::Ordering::SeqCst);
        let core = Arc::downgrade(self);
        let current = move || core.upgrade().is_some_and(|c| c.replay_generation.load(std::sync::atomic::Ordering::SeqCst) == generation);
        let rt = engine.proxy.runtime().handle().clone();
        rt.spawn(async move {
            let slots = Arc::new(tokio::sync::Semaphore::new(at_once));
            let mut handles = Vec::new();
            'rounds: for _ in 0..count {
                for (orig, head, body) in &jobs {
                    if !current() {
                        break 'rounds;
                    }
                    let Ok(permit) = slots.clone().acquire_owned().await else { break 'rounds };
                    let opts = ExecuteOptions {
                        flags: flags::REPLAYED | if o.breakpoint { flags::BREAKPOINTED } else { 0 },
                        comment: Some(format!("Replay of #{orig}")),
                        hooks: true,
                        force_h2: None,
                    };
                    let f = quena_proxy::execute(shared.clone(), head.clone(), body.clone(), opts);
                    handles.push(tokio::spawn(async move {
                        f.await;
                        drop(permit);
                    }));
                    // Finished tasks need not be kept (100 000 repeats).
                    if handles.len() > 4 * MAX_PARALLEL as usize {
                        handles.retain(|h| !h.is_finished());
                    }
                }
            }
            for h in handles {
                let _ = h.await;
            }
        });
        Ok(n * count as usize)
    }

    /// Stop the running replays (requests in flight finish).
    pub fn replay_stop(&self) {
        self.replay_generation.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
        // A chosen version is forced; without one the connection decides (ALPN), as for proxied traffic.
        let (version, force_h2) = match r.version {
            None => (HttpVersion::Http11, None),
            Some(HttpVersion::Http2) => (HttpVersion::Http2, Some(true)),
            Some(HttpVersion::Http3) => return Err(anyhow!("HTTP/3 is not supported; choose HTTP/1.1 or HTTP/2")),
            // HTTP/1.0 (or older) goes out as HTTP/1.1, and the session says so.
            Some(_) => (HttpVersion::Http11, Some(false)),
        };
        let head = RequestHead { method: r.method.trim().to_ascii_uppercase(), url, version, headers };
        let shared = engine.proxy.shared.clone();
        let opts = ExecuteOptions { flags: flags::COMPOSED | if r.breakpoint { flags::BREAKPOINTED } else { 0 }, comment: None, hooks: true, force_h2 };
        let rt = engine.proxy.runtime().handle().clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let follow = r.follow_redirects;
        let core = Arc::downgrade(self);
        rt.spawn(async move {
            let first = head.clone();
            let mut id = quena_proxy::execute_with(shared.clone(), head, body, opts, move |id| {
                let _ = tx.send(id);
            })
            .await;
            if !follow {
                return;
            }
            let mut req = first;
            for hop in 1..=MAX_REDIRECTS {
                let Some(core) = core.upgrade() else { return };
                let Some(d) = core.capture().detail(id) else { return };
                let Some(resp) = d.response else { return };
                if !matches!(resp.status, 301 | 302 | 303 | 307 | 308) {
                    return;
                }
                let Some(next) = resp.headers.get("location").and_then(|l| resolve_location(&req.url, l)) else { return };
                let same_host = authority_of(&next) == authority_of(&req.url);
                // 303 (except for HEAD), and 301/302 after a POST, become a GET without a body
                // (as browsers do); otherwise method and body stay.
                let keep_body = match resp.status {
                    303 => req.method == "HEAD",
                    301 | 302 => req.method != "POST",
                    _ => true,
                };
                let mut headers = req.headers.clone();
                headers.remove("host");
                if !same_host {
                    for h in ["authorization", "cookie", "proxy-authorization"] {
                        headers.remove(h);
                    }
                }
                let body = if keep_body {
                    core.capture().bodies_of(id).map(|(b, _)| b).unwrap_or_else(|| core.capture().bodies.store_bytes(b""))
                } else {
                    for h in ["content-length", "content-type", "transfer-encoding", "content-encoding"] {
                        headers.remove(h);
                    }
                    core.capture().bodies.store_bytes(b"")
                };
                if let Some(a) = authority_of(&next) {
                    headers.0.insert(0, ("Host".into(), a));
                }
                req = RequestHead { method: if keep_body { req.method.clone() } else { "GET".into() }, url: next, version: req.version, headers };
                let opts = ExecuteOptions { flags: flags::COMPOSED, comment: Some(format!("Redirect {hop} from #{id}")), hooks: true, force_h2 };
                drop(core);
                id = quena_proxy::execute_with(shared.clone(), req.clone(), body, opts, |_| {}).await;
            }
        });
        rx.recv_timeout(std::time::Duration::from_secs(5)).map_err(|_| anyhow!("composer request did not start"))
    }
}

impl AppCore {
    /// Wait until a session is done, aborted or paused at a breakpoint (or gone). `false`
    /// when `timeout` passed first.
    pub fn wait_session(&self, id: SessionId, timeout: std::time::Duration) -> bool {
        let until = std::time::Instant::now() + timeout;
        loop {
            match self.capture().index.get(id) {
                Some(s) if s.state.is_final() || s.state.is_breakpoint() => return true,
                None => return true,
                _ => {}
            }
            if std::time::Instant::now() >= until {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
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

    #[test]
    fn locations_resolve() {
        let b = "https://a.example.com/x/y/z?q=1";
        assert_eq!(resolve_location(b, "https://b.example.com/").unwrap(), "https://b.example.com/");
        assert_eq!(resolve_location(b, "//c.example.com/p").unwrap(), "https://c.example.com/p");
        assert_eq!(resolve_location(b, "/root").unwrap(), "https://a.example.com/root");
        assert_eq!(resolve_location(b, "next").unwrap(), "https://a.example.com/x/y/next");
        assert_eq!(resolve_location(b, "?page=2").unwrap(), "https://a.example.com/x/y/z?page=2");
        assert_eq!(resolve_location("http://h:8080", "a").unwrap(), "http://h:8080/a");
        assert!(resolve_location(b, " ").is_none());
        assert_eq!(parse_header_lines("A: 1\n# B: 2\n  #C: 3\nD: 4").0.len(), 2, "`#` lines are off");
    }
}
