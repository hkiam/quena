//! Reverse proxy: extra listeners that forward every request to one fixed origin.
//!
//! A client that cannot use a proxy (a backend calling an API, a container, a webhook
//! sender, a gRPC client) talks to `localhost:<port>` as if it were the server; Quena
//! forwards to the target and records the exchange like any other session. HTTPS clients
//! get a certificate from the Quena root CA; cleartext HTTP/2 (h2c, gRPC without TLS) is
//! recognised by its preface.

use crate::ProxyConfig;
use crate::conn::{Prefixed, serve_decrypted, serve_h1};
use crate::forward::ConnCtx;
use http::HeaderValue;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// Session flag naming the listener a session came through.
pub const FLAG: &str = quena_model::VIA_FLAG;
/// Session flag listing the response headers changed on the way to the client.
pub const REWRITE_FLAG: &str = "x-quena-reverse-rewrite";

/// What a reverse proxy port accepts from clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum ClientProtocol {
    /// TLS when the client starts with a handshake, else plain HTTP (and h2c).
    #[default]
    Auto,
    Http,
    Https,
}

/// Where requests go: an origin and a base path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// "http" or "https".
    pub scheme: &'static str,
    /// `host` or `host:port` (without the scheme's default port).
    pub authority: String,
    /// Prefix put in front of the forwarded path: `""` or `/api` (no trailing slash).
    pub base_path: String,
}

impl Target {
    pub fn parse(url: &str) -> Result<Target, String> {
        let (scheme, authority, base_path) = parse_target(url)?;
        Ok(Target {
            scheme,
            authority,
            base_path,
        })
    }
    /// `scheme://authority`.
    pub fn origin(&self) -> String {
        format!("{}://{}", self.scheme, self.authority)
    }
    fn default_port(&self) -> u16 {
        if self.scheme == "https" { 443 } else { 80 }
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.origin(), self.base_path)
    }
}

/// Requests whose path starts with `prefix` go to their own target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRoute {
    /// `/auth`, `/api/v2/` …
    pub prefix: String,
    pub target: Target,
    /// Drop the prefix from the forwarded path (`/auth/login` → `<target>/login`).
    pub strip_prefix: bool,
}

impl PathRoute {
    /// Whether the request path (without query) is inside the prefix.
    fn matches(&self, path: &str) -> bool {
        let p = self.prefix.trim_end_matches('/');
        if p.is_empty() {
            return true;
        }
        path == p
            || path
                .strip_prefix(p)
                .is_some_and(|rest| rest.starts_with('/'))
    }
}

/// One reverse proxy entry: a local port, the target it forwards to and, optionally, other
/// targets for some paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReverseRoute {
    pub id: String,
    pub name: String,
    pub port: u16,
    /// Listen on all interfaces (clients still have to pass the remote allowlist).
    pub allow_remote: bool,
    pub client_protocol: ClientProtocol,
    /// Requests no path route takes.
    pub target: Target,
    /// Path routes; the longest matching prefix wins.
    pub paths: Vec<PathRoute>,
    /// Send the client's `Host` instead of the target's.
    pub preserve_host: bool,
    /// Certificate name for TLS clients that send no SNI.
    pub tls_host: String,
    /// Point `Location`/`Content-Location` headers that name the target back to Quena.
    pub rewrite_location: bool,
    /// Drop the `Domain` attribute of `Set-Cookie`, so cookies stick to Quena's host.
    pub rewrite_cookie_domain: bool,
    /// Add `X-Forwarded-For`, `-Proto` and `-Host`.
    pub forwarded_headers: bool,
}

/// The target a request went to, and the client-side path prefix that stands for the
/// target's base path (the stripped path prefix, else empty).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Routed {
    pub target: Target,
    pub mount: String,
}

/// Split a target URL into scheme, authority (default port removed) and base path.
pub fn parse_target(url: &str) -> Result<(&'static str, String, String), String> {
    let url = url.trim();
    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = url.strip_prefix("http://") {
        ("http", r)
    } else if url.contains("://") {
        return Err(format!(
            "{url}: only http:// and https:// targets are supported"
        ));
    } else {
        return Err(format!(
            "{url}: the target needs a scheme (http:// or https://)"
        ));
    };
    let (authority, path) = match rest.find(['/', '?', '#']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(format!("{url}: the target needs a host (and no user name)"));
    }
    let uri: http::uri::Authority = authority.parse().map_err(|e| format!("{url}: {e}"))?;
    if uri.host().is_empty() {
        return Err(format!("{url}: the target needs a host"));
    }
    let default = if scheme == "https" { 443 } else { 80 };
    let authority = match uri.port_u16() {
        Some(p) if p == default => uri.host().to_string(),
        _ => uri.as_str().to_ascii_lowercase(),
    };
    let path = path
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .trim_end_matches('/')
        .to_string();
    Ok((scheme, authority, path))
}

/// A path prefix of a path route: starts with `/`, no query.
pub fn parse_prefix(prefix: &str) -> Result<String, String> {
    let p = prefix.trim();
    if !p.starts_with('/') || p.contains(['?', '#', ' ']) {
        return Err(format!("{p}: a path prefix starts with / and has no query"));
    }
    Ok(p.to_string())
}

impl ReverseRoute {
    /// The default target as configured, with ` (+N paths)` when there are path routes.
    pub fn describe(&self) -> String {
        match self.paths.len() {
            0 => self.target.to_string(),
            1 => format!("{} (+1 path)", self.target),
            n => format!("{} (+{n} paths)", self.target),
        }
    }

    /// Upstream URL for a request target (`/path?query`, or an absolute URL a client sent
    /// anyway: only its path and query count), and where it went.
    pub fn upstream_url(&self, uri: &http::Uri) -> (String, Routed) {
        let path = uri.path();
        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
        let best = self
            .paths
            .iter()
            .filter(|r| r.matches(&path))
            .max_by_key(|r| r.prefix.trim_end_matches('/').len());
        let (target, mount, rest) = match best {
            Some(r) if r.strip_prefix => {
                let p = r.prefix.trim_end_matches('/');
                let rest = &path[p.len()..];
                (
                    &r.target,
                    p.to_string(),
                    if rest.is_empty() {
                        "/".to_string()
                    } else {
                        rest.to_string()
                    },
                )
            }
            Some(r) => (&r.target, String::new(), path),
            None => (&self.target, String::new(), path),
        };
        let url = format!("{}{}{rest}{query}", target.origin(), target.base_path);
        (
            url,
            Routed {
                target: target.clone(),
                mount,
            },
        )
    }

    /// Whether the route accepts this client address.
    pub fn client_allowed(&self, cfg: &ProxyConfig, ip: std::net::IpAddr) -> bool {
        cfg.client_allowed_with(ip, self.allow_remote)
    }

    /// Change response headers for the client (see [`ReverseRoute::rewrite_location`],
    /// [`ReverseRoute::rewrite_cookie_domain`]). `client_origin` is how the client
    /// addressed Quena (`http://localhost:8080`). Returns what was changed.
    pub fn rewrite_response(
        &self,
        headers: &mut http::HeaderMap,
        client_origin: &str,
        routed: &Routed,
    ) -> Vec<String> {
        let mut notes = Vec::new();
        if self.rewrite_location {
            for name in [http::header::LOCATION, http::header::CONTENT_LOCATION] {
                let Some(v) = headers.get(&name).and_then(|v| v.to_str().ok()) else {
                    continue;
                };
                if let Some(new) = client_location(v, client_origin, routed) {
                    if let Ok(hv) = HeaderValue::from_str(&new) {
                        notes.push(format!(
                            "{}: {v} → {new}",
                            crate::util::title_case(name.as_str())
                        ));
                        headers.insert(name, hv);
                    }
                }
            }
        }
        if self.rewrite_cookie_domain {
            let cookies: Vec<HeaderValue> = headers
                .get_all(http::header::SET_COOKIE)
                .iter()
                .cloned()
                .collect();
            if cookies
                .iter()
                .any(|c| c.to_str().is_ok_and(|s| cookie_domain(s).is_some()))
            {
                headers.remove(http::header::SET_COOKIE);
                for c in cookies {
                    let out = match c.to_str() {
                        Ok(s) => match cookie_domain(s) {
                            Some(d) => {
                                let stripped = strip_cookie_domain(s);
                                notes.push(format!("Set-Cookie: Domain={d} removed"));
                                HeaderValue::from_str(&stripped).unwrap_or(c)
                            }
                            None => c,
                        },
                        Err(_) => c,
                    };
                    headers.append(http::header::SET_COOKIE, out);
                }
            }
        }
        notes
    }
}

/// `Location` value as the client has to see it, or `None` to leave it unchanged: a URL on
/// the target (inside its base path) moves to the client's origin and mount.
fn client_location(v: &str, client_origin: &str, routed: &Routed) -> Option<String> {
    let (target, mount) = (&routed.target, routed.mount.as_str());
    if v.starts_with('/') && !v.starts_with("//") {
        // An absolute path on the target: drop the base path, add the mount.
        if target.base_path.is_empty() && mount.is_empty() {
            return None;
        }
        let rest = if target.base_path.is_empty() {
            v
        } else {
            strip_base(v, &target.base_path)?
        };
        let out = format!("{mount}{rest}");
        return (out != v).then_some(out);
    }
    let lower = v.to_ascii_lowercase();
    let origins = [
        target.origin(),
        format!("{}:{}", target.origin(), target.default_port()),
    ];
    for o in &origins {
        if let Some(rest) = lower.strip_prefix(o.as_str()) {
            if !(rest.is_empty() || rest.starts_with(['/', '?', '#'])) {
                continue;
            }
            let rest = &v[o.len()..];
            let rest = if target.base_path.is_empty() {
                Some(rest)
            } else {
                strip_base(rest, &target.base_path)
            }?;
            let rest = if rest.is_empty() { "/" } else { rest };
            return Some(format!("{client_origin}{mount}{rest}"));
        }
    }
    None
}

/// `path` without the leading `base` (`/api/x` → `/x`), or `None` when it is outside it.
fn strip_base<'a>(path: &'a str, base: &str) -> Option<&'a str> {
    let rest = path.strip_prefix(base)?;
    if rest.is_empty() {
        Some("/")
    } else if rest.starts_with(['/', '?', '#']) {
        Some(rest)
    } else {
        None
    }
}

fn cookie_domain(cookie: &str) -> Option<String> {
    cookie.split(';').skip(1).find_map(|a| {
        let (k, v) = a.split_once('=')?;
        k.trim()
            .eq_ignore_ascii_case("domain")
            .then(|| v.trim().to_string())
    })
}

fn strip_cookie_domain(cookie: &str) -> String {
    let mut parts = cookie.split(';');
    let mut out = parts.next().unwrap_or("").to_string();
    for a in parts {
        let is_domain = a
            .split_once('=')
            .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("domain"));
        if !is_domain {
            out.push(';');
            out.push_str(a);
        }
    }
    out
}

/// The HTTP/2 connection preface (cleartext HTTP/2 starts with it, h2c with prior knowledge).
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// A client must say something within this time.
const FIRST_BYTES_TIMEOUT: Duration = Duration::from_secs(30);

/// Serve one client connection on a reverse proxy port.
pub(crate) async fn serve(ctx: Arc<ConnCtx>, mut stream: TcpStream) {
    let route = ctx.reverse.clone().expect("reverse route");
    // Read until the protocol is clear: a TLS record, the h2 preface or anything else.
    let mut first = Vec::with_capacity(H2_PREFACE.len());
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(FIRST_BYTES_TIMEOUT, async {
        loop {
            let want = if first.first() == Some(&H2_PREFACE[0]) {
                H2_PREFACE.len()
            } else {
                1
            };
            if first.len() >= want || (!first.is_empty() && !H2_PREFACE.starts_with(&first)) {
                return Ok(());
            }
            let n = stream.read(&mut buf[..want - first.len()]).await?;
            if n == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
            }
            first.extend_from_slice(&buf[..n]);
        }
    })
    .await;
    if !matches!(read, Ok(Ok(()))) {
        return;
    }
    let is_tls = first[0] == 0x16;
    let io = Prefixed::new(first.clone(), stream);
    match (is_tls, route.client_protocol) {
        (true, ClientProtocol::Auto | ClientProtocol::Https) => serve_tls(ctx, io).await,
        (false, ClientProtocol::Https) => {
            tracing::warn!(target: "quena::proxy", "reverse proxy {} (port {}): {} sent plain HTTP, but the entry expects HTTPS", route.name, route.port, ctx.client_addr);
            let msg = format!(
                "This Quena reverse proxy port expects HTTPS: use https://…:{}/\n",
                route.port
            );
            let mut io = io;
            let _ = tokio::io::AsyncWriteExt::write_all(
                &mut io,
                format!("HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{msg}", msg.len()).as_bytes(),
            )
            .await;
            // Close the sending side, then read what the client sent: closing with unread
            // bytes makes Windows reset the connection, and the client loses the answer.
            let _ = tokio::io::AsyncWriteExt::shutdown(&mut io).await;
            let mut sink = [0u8; 4096];
            let _ = tokio::time::timeout(Duration::from_secs(2), async {
                while matches!(io.read(&mut sink).await, Ok(n) if n > 0) {}
            })
            .await;
        }
        (_, _) if first == H2_PREFACE => serve_h2c(ctx, io).await,
        _ => serve_h1(ctx, io).await,
    }
}

async fn serve_tls(ctx: Arc<ConnCtx>, io: Prefixed<TcpStream>) {
    let route = ctx.reverse.clone().expect("reverse route");
    let shared = ctx.shared.clone();
    let Some(ca) = shared.ca.read().clone() else {
        tracing::warn!(target: "quena::proxy", "reverse proxy {} (port {}): a client speaks TLS, but there is no root certificate (Capture → HTTPS Settings…)", route.name, route.port);
        return;
    };
    let accepted = match crate::conn::accept_tls(&shared, io, &route.tls_host, ca).await {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(target: "quena::proxy", "reverse proxy {} (port {}): TLS with {} failed: {e}", route.name, route.port, ctx.client_addr);
            return;
        }
    };
    let inner = Arc::new(ConnCtx {
        shared: shared.clone(),
        conn_id: ctx.conn_id,
        client_addr: ctx.client_addr,
        remote: ctx.remote,
        process: ctx.process.clone(),
        scheme: "https",
        authority: None,
        client_tls: Some(accepted.info.clone()),
        connected_at: ctx.connected_at,
        decrypted: true,
        auth_clients: parking_lot::Mutex::new(std::collections::HashMap::new()),
        reverse: Some(route),
        via: ctx.via.clone(),
    });
    serve_decrypted(
        inner,
        accepted.stream,
        accepted.info.alpn.as_deref() == Some("h2"),
    )
    .await;
}

async fn serve_h2c(ctx: Arc<ConnCtx>, io: Prefixed<TcpStream>) {
    let c2 = ctx.clone();
    let svc = hyper::service::service_fn(move |req| crate::forward::handle(c2.clone(), req));
    let mut closing = ctx.shared.closing.subscribe();
    let conn = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .keep_alive_interval(Some(Duration::from_secs(30)))
        .keep_alive_timeout(Duration::from_secs(20))
        .max_concurrent_streams(250)
        .serve_connection(TokioIo::new(io), svc);
    tokio::pin!(conn);
    let r = tokio::select! {
        r = conn.as_mut() => r,
        _ = closing.changed() => {
            conn.as_mut().graceful_shutdown();
            conn.await
        }
    };
    if let Err(e) = r {
        tracing::debug!(target: "quena::proxy", "h2c client connection {}: {e}", ctx.client_addr);
    }
}

/// The client-facing origin of a request on a reverse proxy port, from its `Host`
/// (HTTP/1) or `:authority` (HTTP/2).
pub(crate) fn client_origin<B>(req: &http::Request<B>, scheme: &str, port: u16) -> String {
    let authority = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .or_else(|| {
            req.headers()
                .get(http::header::HOST)
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| format!("localhost:{port}"));
    format!("{scheme}://{authority}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(target: &str) -> ReverseRoute {
        ReverseRoute {
            id: "1".into(),
            name: "api".into(),
            port: 8080,
            allow_remote: false,
            client_protocol: ClientProtocol::Auto,
            target: Target::parse(target).unwrap(),
            paths: vec![],
            preserve_host: false,
            tls_host: "localhost".into(),
            rewrite_location: true,
            rewrite_cookie_domain: true,
            forwarded_headers: false,
        }
    }

    fn path(prefix: &str, target: &str, strip: bool) -> PathRoute {
        PathRoute {
            prefix: prefix.into(),
            target: Target::parse(target).unwrap(),
            strip_prefix: strip,
        }
    }

    fn url(r: &ReverseRoute, u: &str) -> String {
        r.upstream_url(&u.parse().unwrap()).0
    }

    #[test]
    fn targets_are_parsed() {
        assert_eq!(
            parse_target("https://api.example.com").unwrap(),
            ("https", "api.example.com".into(), "".into())
        );
        assert_eq!(
            parse_target("https://api.example.com:443/v1/").unwrap(),
            ("https", "api.example.com".into(), "/v1".into())
        );
        assert_eq!(
            parse_target("http://LOCALHOST:3000/a/b?x=1").unwrap(),
            ("http", "localhost:3000".into(), "/a/b".into())
        );
        assert_eq!(
            parse_target("http://[::1]:8080").unwrap(),
            ("http", "[::1]:8080".into(), "".into())
        );
        assert!(parse_target("api.example.com").is_err());
        assert!(parse_target("ftp://x").is_err());
        assert!(parse_target("https://").is_err());
        assert!(parse_target("https://user@host").is_err());
        assert!(parse_prefix("/auth").is_ok());
        assert!(parse_prefix("auth").is_err());
        assert!(parse_prefix("/a?b").is_err());
    }

    #[test]
    fn upstream_url_adds_the_base_path() {
        let r = route("https://api.example.com/v1");
        assert_eq!(
            url(&r, "/users?id=2"),
            "https://api.example.com/v1/users?id=2"
        );
        assert_eq!(
            url(&r, "http://localhost:8080/x"),
            "https://api.example.com/v1/x"
        );
        let r = route("http://localhost:3000");
        assert_eq!(url(&r, "/"), "http://localhost:3000/");
    }

    #[test]
    fn the_longest_path_prefix_wins() {
        let mut r = route("http://web:3000");
        r.paths = vec![
            path("/api", "http://api:8000", false),
            path("/api/v2/", "http://v2:9000/base", true),
            path("/auth", "https://sso.example.com", true),
        ];
        assert_eq!(url(&r, "/index.html"), "http://web:3000/index.html");
        assert_eq!(url(&r, "/api/users?x=1"), "http://api:8000/api/users?x=1");
        assert_eq!(url(&r, "/api"), "http://api:8000/api");
        assert_eq!(url(&r, "/api/v2/items"), "http://v2:9000/base/items");
        assert_eq!(url(&r, "/api/v2"), "http://v2:9000/base/");
        assert_eq!(url(&r, "/auth/login"), "https://sso.example.com/login");
        // A prefix matches whole path segments only.
        assert_eq!(url(&r, "/apiary"), "http://web:3000/apiary");
        let (_, routed) = r.upstream_url(&"/auth/login".parse().unwrap());
        assert_eq!(routed.mount, "/auth");
        assert_eq!(routed.target.authority, "sso.example.com");
    }

    fn loc(r: &ReverseRoute, req: &str, v: &str) -> Option<String> {
        let (_, routed) = r.upstream_url(&req.parse().unwrap());
        client_location(v, "http://localhost:8080", &routed)
    }

    #[test]
    fn locations_point_back_to_the_client() {
        let r = route("https://api.example.com/v1");
        assert_eq!(
            loc(&r, "/", "https://api.example.com/v1/login?a=1").as_deref(),
            Some("http://localhost:8080/login?a=1")
        );
        assert_eq!(
            loc(&r, "/", "https://API.example.com:443/v1").as_deref(),
            Some("http://localhost:8080/")
        );
        assert_eq!(loc(&r, "/", "/v1/next").as_deref(), Some("/next"));
        // Outside the base path, another host or a look-alike host: unchanged.
        assert_eq!(loc(&r, "/", "https://api.example.com/other"), None);
        assert_eq!(loc(&r, "/", "https://sso.example.com/v1/x"), None);
        assert_eq!(loc(&r, "/", "https://api.example.com.evil/v1/x"), None);
        assert_eq!(loc(&r, "/", "/other"), None);
        let r = route("http://localhost:3000");
        assert_eq!(
            loc(&r, "/", "http://localhost:3000/a").as_deref(),
            Some("http://localhost:8080/a")
        );
        assert_eq!(loc(&r, "/", "/a"), None);
    }

    #[test]
    fn locations_of_a_stripped_path_route_keep_its_prefix() {
        let mut r = route("http://web:3000");
        r.paths = vec![path("/auth", "https://sso.example.com", true)];
        assert_eq!(
            loc(&r, "/auth/login", "https://sso.example.com/done").as_deref(),
            Some("http://localhost:8080/auth/done")
        );
        assert_eq!(
            loc(&r, "/auth/login", "/done").as_deref(),
            Some("/auth/done")
        );
        // The default target is not affected.
        assert_eq!(
            loc(&r, "/x", "http://web:3000/y").as_deref(),
            Some("http://localhost:8080/y")
        );
    }

    #[test]
    fn cookie_domains_are_removed() {
        let r = route("https://api.example.com");
        let (_, routed) = r.upstream_url(&"/".parse().unwrap());
        let mut h = http::HeaderMap::new();
        h.append(
            http::header::SET_COOKIE,
            HeaderValue::from_static("a=1; Domain=.example.com; Path=/; HttpOnly"),
        );
        h.append(
            http::header::SET_COOKIE,
            HeaderValue::from_static("b=2; Path=/"),
        );
        h.insert(
            http::header::LOCATION,
            HeaderValue::from_static("https://api.example.com/x"),
        );
        let notes = r.rewrite_response(&mut h, "http://localhost:8080", &routed);
        let cookies: Vec<_> = h
            .get_all(http::header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert_eq!(cookies, vec!["a=1; Path=/; HttpOnly", "b=2; Path=/"]);
        assert_eq!(
            h.get(http::header::LOCATION).unwrap(),
            "http://localhost:8080/x"
        );
        assert_eq!(notes.len(), 2, "{notes:?}");
    }
}
