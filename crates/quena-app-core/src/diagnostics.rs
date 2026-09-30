//! Diagnostics: runs an analyzer plugin (e.g. `webdiag`) over the visible sessions or a
//! selection and keeps the last report.
//!
//! The host builds one record per session (plugins/webdiag/REPORT.md): allow-listed headers
//! with secrets redacted, sizes, timers, connection data and fingerprints of the decoded
//! bodies. Credentials in the redacted headers (`Authorization`, `Cookie`, `Set-Cookie`,
//! the `*-Authenticate` challenges) never reach the plugin; in the session URL, `Location`
//! and `Referer` the user info, the values of sensitive query/fragment parameters and every
//! other parameter value longer than 64 bytes are replaced by their size (OData `$` system
//! options are only subject to the name rule). URL paths are passed unchanged.

use crate::AppCore;
use anyhow::{Result, anyhow};
use quena_body::Body;
use quena_jobs::{JobCtx, JobId, Priority};
use quena_model::{Headers, Micros, SessionDetail, SessionId, SessionKind};
use quena_plugin_host::{AnalyzerSession, AnalyzerTimers, PluginKind};
use quena_store::Capture;
use serde::Serialize;
use std::io::Read;
use std::sync::Arc;

/// Sessions per `push`.
pub const BATCH: usize = 2000;
/// Largest decoded request body that gets a fingerprint.
pub const REQUEST_HASH_LIMIT: u64 = 1 << 20;
/// Largest decoded response body that gets a fingerprint.
pub const RESPONSE_HASH_LIMIT: u64 = 8 << 20;
/// Decoding stops here when only the decoded size is still wanted (decompression bombs);
/// a larger decoded size is reported as this lower bound (REPORT.md).
pub const DECODED_COUNT_LIMIT: u64 = 256 << 20;
/// Longest URL / header value passed to an analyzer; longer values are cut and marked.
pub const FIELD_LIMIT: usize = 8 << 10;
/// Headers per direction passed to an analyzer (further ones are dropped).
pub const HEADER_COUNT_LIMIT: usize = 256;
/// Approximate size limit of one `push` batch (besides [`BATCH`] sessions).
pub const BATCH_BYTES: usize = 16 << 20;
/// Query/fragment parameter values longer than this are replaced by their size.
pub const URL_VALUE_LIMIT: usize = 64;

/// Headers passed to analyzers (lower case); everything else is dropped.
pub const HEADER_ALLOW_LIST: &[&str] = &[
    "accept-encoding",
    "access-control-allow-origin",
    "access-control-max-age",
    "access-control-request-method",
    "age",
    "authorization",
    "cache-control",
    "connection",
    "content-encoding",
    "content-length",
    "content-type",
    "cookie",
    "etag",
    "expires",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "keep-alive",
    "last-modified",
    "location",
    "odata-version",
    "origin",
    "pragma",
    "prefer",
    "proxy-authenticate",
    "proxy-authorization",
    "range",
    "content-range",
    "referer",
    "request-id",
    "retry-after",
    "set-cookie",
    "soapaction",
    "strict-transport-security",
    "traceparent",
    "transfer-encoding",
    "vary",
    "www-authenticate",
    "x-correlation-id",
    "x-http-method-override",
    "x-ms-request-id",
    "x-request-id",
];

// ------------------------------------------------------------------ redaction

/// `token` characters of RFC 9110 (header names, auth schemes, parameter names).
fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Plausible authentication scheme name (`Bearer`, `AWS4-HMAC-SHA256` …).
fn is_scheme(s: &str) -> bool {
    s.len() <= 32 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') && s.bytes().any(|b| b.is_ascii_alphabetic())
}

/// Schemes that are recognised even without credentials after them.
const KNOWN_SCHEMES: &[&str] = &["basic", "bearer", "digest", "negotiate", "ntlm", "kerberos", "hoba", "mutual", "hawk", "oauth", "token", "dpop"];

fn bytes(n: usize) -> String {
    format!("<{n} bytes>")
}

/// `Authorization` / `Proxy-Authorization`: scheme plus the credential size.
pub fn redact_authorization(v: &str) -> String {
    let v = v.trim();
    if v.is_empty() {
        return String::new();
    }
    match v.split_once(|c: char| c.is_ascii_whitespace()) {
        Some((scheme, rest)) if is_scheme(scheme) => {
            let rest = rest.trim();
            if rest.is_empty() { scheme.to_string() } else { format!("{scheme} {}", bytes(rest.len())) }
        }
        None if is_scheme(v) && KNOWN_SCHEMES.contains(&v.to_ascii_lowercase().as_str()) => v.to_string(),
        // No recognisable scheme: the whole value may be the secret.
        _ => bytes(v.len()),
    }
}

/// Split at commas outside quoted strings.
fn split_commas(v: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut start, mut quoted, mut escaped) = (0, false, false);
    for (i, c) in v.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ',' if !quoted => {
                out.push(&v[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&v[start..]);
    out
}

/// `name=value` auth parameter → `name` (a token68 like `abc==` is no parameter).
fn param_name(s: &str) -> Option<&str> {
    let (name, value) = s.split_once('=')?;
    let name = name.trim_end();
    (is_token(name) && !value.trim().is_empty() && !value.trim().bytes().all(|b| b == b'=')).then_some(name)
}

/// `WWW-Authenticate` / `Proxy-Authenticate`: scheme and parameter names of every
/// challenge; token68 values (e.g. a Negotiate token) become `<n bytes>`.
pub fn redact_authenticate(v: &str) -> String {
    // (scheme, token size, parameter names)
    let mut challenges: Vec<(String, Option<usize>, Vec<String>)> = Vec::new();
    for item in split_commas(v).into_iter().map(str::trim).filter(|s| !s.is_empty()) {
        if let Some(name) = param_name(item) {
            match challenges.last_mut() {
                Some(c) => c.2.push(name.to_string()),
                None => challenges.push((String::new(), None, vec![name.to_string()])),
            }
            continue;
        }
        let (scheme, rest) = match item.split_once(|c: char| c.is_ascii_whitespace()) {
            Some((s, r)) => (s, r.trim()),
            None => (item, ""),
        };
        if !is_scheme(scheme) {
            challenges.push((bytes(item.len()), None, vec![]));
            continue;
        }
        let mut c = (scheme.to_string(), None, vec![]);
        if !rest.is_empty() {
            match param_name(rest) {
                Some(name) => c.2.push(name.to_string()),
                None => c.1 = Some(rest.len()),
            }
        }
        challenges.push(c);
    }
    challenges
        .into_iter()
        .map(|(scheme, token, params)| {
            let mut s = scheme;
            if let Some(n) = token {
                s.push(' ');
                s.push_str(&bytes(n));
            }
            if !params.is_empty() {
                if !s.is_empty() {
                    s.push(' ');
                }
                s.push_str(&params.join(", "));
            }
            s
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// `Cookie`: names only; a pair without `=` is a value (RFC 6265bis) and becomes `<n bytes>`.
pub fn redact_cookie(v: &str) -> String {
    v.split(';')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(|c| match c.split_once('=') {
            Some((n, _)) => n.trim().to_string(),
            None => bytes(c.len()),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// `Set-Cookie` attributes that are passed verbatim (lower case).
const COOKIE_ATTRS: &[&str] = &["path", "domain", "expires", "max-age", "secure", "httponly", "samesite", "partitioned", "priority"];

/// Whether `s` (after a comma) starts a new `name=value` cookie. A comma inside an
/// `Expires` date is followed by a day number and a space (`Wed, 21 Oct …`), no token `=`.
fn starts_cookie(s: &str) -> bool {
    s.split_once('=').is_some_and(|(n, _)| is_token(n.trim()))
}

/// One cookie: `name=<n bytes>`, known attributes verbatim, anything else by its size.
fn redact_one_set_cookie(v: &str) -> String {
    let mut parts = v.split(';');
    let pair = parts.next().unwrap_or("").trim();
    let (name, value) = pair.split_once('=').unwrap_or(("", pair));
    let mut out = format!("{}={}", name.trim(), bytes(value.trim().len()));
    for a in parts.map(str::trim).filter(|a| !a.is_empty()) {
        let (n, val) = match a.split_once('=') {
            Some((n, v)) => (n.trim(), Some(v.trim())),
            None => (a, None),
        };
        out.push_str("; ");
        if COOKIE_ATTRS.contains(&n.to_ascii_lowercase().as_str()) {
            out.push_str(a);
        } else {
            match val {
                Some(v) if is_token(n) => out.push_str(&format!("{n}={}", bytes(v.len()))),
                _ => out.push_str(&bytes(a.len())),
            }
        }
    }
    out
}

/// `Set-Cookie`: `name=<n bytes>` plus the known attributes (Path, Domain, Expires,
/// Max-Age, Secure, HttpOnly, SameSite, Partitioned, Priority) verbatim; unknown attributes
/// become `name=<n bytes>`. A value carrying several cookies (joined with a line break or
/// folded with `, ` by HAR exporters and intermediaries) has each of them redacted.
pub fn redact_set_cookie(v: &str) -> String {
    v.split('\n')
        .map(|line| {
            let mut cookies: Vec<&str> = Vec::new();
            let mut start = 0;
            for (i, _) in line.match_indices(',') {
                if starts_cookie(&line[i + 1..]) {
                    cookies.push(&line[start..i]);
                    start = i + 1;
                }
            }
            cookies.push(&line[start..]);
            cookies.into_iter().map(redact_one_set_cookie).collect::<Vec<_>>().join(", ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Query/fragment parameter names whose values are secrets (lower case, exact).
const SECRET_PARAMS: &[&str] = &[
    "auth", "code", "state", "nonce", "sig", "key", "sid", "otp", // OAuth, signed URLs, sessions
    "se", "sp", "sv", "sr", "st", "spr", "srt", "ss", "si", "sdd", "skoid", "sktid", "skt", "ske", "sks", "skv", // Azure SAS
];
/// Parameter names that contain one of these (lower case) carry secrets, e.g. `access_token`,
/// `id_token`, `refresh_token`, `client_secret`, `SAMLResponse`, `X-Goog-Credential`.
const SECRET_PARAM_PARTS: &[&str] =
    &["token", "password", "passwd", "secret", "signature", "apikey", "api_key", "api-key", "session", "credential", "jwt", "assertion", "samlresponse", "samlrequest", "ticket"];
/// Parameter name prefixes that carry secrets (AWS / GCS signed URLs).
const SECRET_PARAM_PREFIXES: &[&str] = &["x-amz-", "x-goog-"];

/// Percent-decoding (and `+` → space) of a parameter name, for matching only.
fn decode_param(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => match std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                Some(x) => {
                    out.push(x);
                    i += 2;
                }
                None => out.push(b'%'),
            },
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn secret_param(name: &str) -> bool {
    let n = decode_param(name).trim().to_ascii_lowercase();
    SECRET_PARAMS.contains(&n.as_str()) || SECRET_PARAM_PARTS.iter().any(|p| n.contains(p)) || SECRET_PARAM_PREFIXES.iter().any(|p| n.starts_with(p))
}

/// `<n bytes>`, percent-encoded so the URL stays valid (it decodes to `<n bytes>`).
fn url_bytes(n: usize) -> String {
    format!("%3C{n}%20bytes%3E")
}

/// `a=1&b=2` with sensitive or long values replaced by their size.
fn redact_params(q: &str) -> String {
    q.split('&')
        .map(|p| match p.split_once('=') {
            Some((name, value)) => {
                if name.len() > URL_VALUE_LIMIT {
                    url_bytes(p.len())
                } else if !value.is_empty() && (secret_param(name) || (value.len() > URL_VALUE_LIMIT && !decode_param(name).starts_with('$'))) {
                    format!("{name}={}", url_bytes(value.len()))
                } else {
                    p.to_string()
                }
            }
            None if p.len() > URL_VALUE_LIMIT => url_bytes(p.len()),
            None => p.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Whether `url` starts with a scheme and `://` (`^[A-Za-z][A-Za-z0-9+.-]*://`).
pub fn has_scheme(url: &str) -> bool {
    let Some(i) = url.find("://") else { return false };
    let s = &url[..i];
    s.bytes().next().is_some_and(|b| b.is_ascii_alphabetic()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"+.-".contains(&b))
}

/// A URL (absolute or relative) with the user info, sensitive query/fragment values
/// (tokens, codes, signatures, keys, passwords, sessions …) and every other parameter value
/// longer than [`URL_VALUE_LIMIT`] bytes replaced by `%3Cn%20bytes%3E` (`<n bytes>`, `n` =
/// encoded length). OData system options (`$filter`, `$select` …) are only subject to the
/// name rule. Scheme, host, port and path are kept.
pub fn redact_url(url: &str) -> String {
    let (rest, fragment) = match url.split_once('#') {
        Some((r, f)) => (r, Some(f)),
        None => (url, None),
    };
    let (base, query) = match rest.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (rest, None),
    };
    let mut out = String::with_capacity(url.len());
    match base.find("://").filter(|_| has_scheme(base)) {
        Some(i) => {
            let after = &base[i + 3..];
            let auth_end = after.find('/').unwrap_or(after.len());
            let authority = &after[..auth_end];
            out.push_str(&base[..i + 3]);
            match authority.rsplit_once('@') {
                Some((userinfo, host)) => {
                    out.push_str(&url_bytes(userinfo.len()));
                    out.push('@');
                    out.push_str(host);
                }
                None => out.push_str(authority),
            }
            out.push_str(&after[auth_end..]);
        }
        None => out.push_str(base),
    }
    if let Some(q) = query {
        out.push('?');
        out.push_str(&redact_params(q));
    }
    if let Some(f) = fragment {
        out.push('#');
        if f.contains('=') {
            out.push_str(&redact_params(f));
        } else if f.len() > URL_VALUE_LIMIT {
            out.push_str(&url_bytes(f.len()));
        } else {
            out.push_str(f);
        }
    }
    out
}

/// Cut `s` to [`FIELD_LIMIT`] bytes (at a char boundary, before a split `%XX` escape in a
/// URL) and mark the cut with `…<truncated n bytes>` (percent-encoded for URLs).
fn cap_field(mut s: String, url: bool) -> String {
    if s.len() <= FIELD_LIMIT {
        return s;
    }
    let mut end = FIELD_LIMIT;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    if url && let Some(p) = s[end.saturating_sub(2)..end].find('%') {
        end = end.saturating_sub(2) + p;
    }
    let cut = s.len() - end;
    s.truncate(end);
    if url {
        s.push_str(&format!("%E2%80%A6%3Ctruncated%20{cut}%20bytes%3E"));
    } else {
        s.push_str(&format!("…<truncated {cut} bytes>"));
    }
    s
}

/// Allow-listed headers in wire order (at most [`HEADER_COUNT_LIMIT`]), secrets redacted,
/// values cut to [`FIELD_LIMIT`] (REPORT.md).
pub fn redact_headers(h: &Headers) -> Vec<(String, String)> {
    h.iter()
        .filter_map(|(name, value)| {
            let lower = name.to_ascii_lowercase();
            if !HEADER_ALLOW_LIST.contains(&lower.as_str()) {
                return None;
            }
            let value = match lower.as_str() {
                "authorization" | "proxy-authorization" => redact_authorization(value),
                "www-authenticate" | "proxy-authenticate" => redact_authenticate(value),
                "cookie" => redact_cookie(value),
                "set-cookie" => redact_set_cookie(value),
                "location" | "referer" => redact_url(value),
                _ => value.to_string(),
            };
            Some((name.to_string(), cap_field(value, false)))
        })
        .take(HEADER_COUNT_LIMIT)
        .collect()
}

/// Approximate size of a record in a batch (strings dominate).
pub fn record_bytes(r: &AnalyzerSession) -> usize {
    let h: usize = r.request_headers.iter().chain(&r.response_headers).map(|(n, v)| n.len() + v.len() + 16).sum();
    256 + r.url.len() + r.method.len() + r.host.len() + r.content_type.len() + r.process.len() + r.error.as_ref().map_or(0, |e| e.len()) + h
}

// ------------------------------------------------------------------ bodies

/// FNV-1a, 64 bit.
#[derive(Clone, Copy)]
pub struct Fnv1a(u64);

impl Default for Fnv1a {
    fn default() -> Self {
        Fnv1a(0xcbf2_9ce4_8422_2325)
    }
}

impl Fnv1a {
    pub fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.0 ^= b as u64;
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    pub fn finish(self) -> u64 {
        self.0
    }
}

pub fn fnv1a(data: &[u8]) -> u64 {
    let mut h = Fnv1a::default();
    h.update(data);
    h.finish()
}

/// Decoded size and fingerprint of a body: (decoded bytes, FNV-1a of the decoded bytes if
/// they are not empty and at most `hash_limit`). With `need_len` false, decoding stops as
/// soon as the fingerprint is out of reach. Undecodable bodies get no fingerprint.
pub fn body_fingerprint(body: &Body, content_encoding: Option<&str>, hash_limit: u64, need_len: bool, cancelled: &dyn Fn() -> bool) -> (u64, Option<u64>) {
    if body.is_empty() {
        return (0, None);
    }
    let encodings = match content_encoding.map(quena_body::decode::parse_encodings) {
        None => vec![],
        Some(Ok(e)) => e,
        Some(Err(_)) => return (body.len(), None),
    };
    if encodings.is_empty() && body.len() > hash_limit {
        return (body.len(), None);
    }
    let mut reader = quena_body::decode::decoding_reader(Box::new(body.stream(0, false)), &encodings);
    let mut h = Fnv1a::default();
    let mut n = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        if cancelled() {
            return (n, None);
        }
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(k) => {
                if n + k as u64 <= hash_limit {
                    h.update(&buf[..k]);
                }
                n += k as u64;
                if n > hash_limit && (!need_len || n >= DECODED_COUNT_LIMIT) {
                    return (if need_len { n } else { 0 }, None);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            // Truncated or corrupt stream: report what was decoded, no fingerprint.
            Err(_) => return (if n == 0 { body.len() } else { n }, None),
        }
    }
    (n, (n > 0 && n <= hash_limit).then(|| h.finish()))
}

// ------------------------------------------------------------------ records

fn us(t: Option<Micros>) -> Option<u64> {
    t.filter(|t| *t >= 0).map(|t| t as u64)
}

fn kind_name(k: SessionKind) -> &'static str {
    match k {
        SessionKind::Tunnel => "tunnel",
        SessionKind::WebSocket => "websocket",
        SessionKind::Http | SessionKind::Synthetic => "http",
    }
}

/// The analyzer record of one session (`req`/`resp`: its stored bodies).
pub fn build_record(d: &SessionDetail, req: &Body, resp: &Body, cancelled: &dyn Fn() -> bool) -> AnalyzerSession {
    let s = &d.summary;
    let t = &d.timers;
    let empty = Headers::new();
    let resp_headers = d.response.as_ref().map(|r| &r.headers).unwrap_or(&empty);
    // Tunnels keep their authority form (`host:port`).
    let url = if s.kind == SessionKind::Tunnel {
        d.request.url.clone()
    } else {
        redact_url(&if has_scheme(&d.request.url) { d.request.url.clone() } else { s.full_url() })
    };
    let url = cap_field(url, true);
    let (_, req_hash) = body_fingerprint(req, d.request.headers.get("content-encoding"), REQUEST_HASH_LIMIT, false, cancelled);
    let (resp_decoded, resp_hash) = body_fingerprint(resp, resp_headers.get("content-encoding"), RESPONSE_HASH_LIMIT, true, cancelled);
    AnalyzerSession {
        id: s.id,
        kind: kind_name(s.kind).into(),
        started: us(Some(s.started_at)).unwrap_or(0),
        duration_ms: s.duration_ms,
        method: d.request.method.clone(),
        url,
        host: s.host.clone(),
        version: d.request.version.as_str().into(),
        status: d.response.as_ref().map(|r| r.status).unwrap_or(0),
        error: d.error.clone().map(|e| cap_field(e, false)),
        request_bytes: d.request_body.wire_len().max(s.request_body_len),
        response_bytes: d.response_body.wire_len().max(s.response_body_len),
        response_decoded_bytes: resp_decoded,
        content_type: s.content_type.clone(),
        request_headers: redact_headers(&d.request.headers),
        response_headers: redact_headers(resp_headers),
        timers: AnalyzerTimers {
            client_begin_request: us(t.client_begin_request),
            client_done_request: us(t.client_done_request),
            server_connect_start: us(t.server_connect_start),
            server_connected: us(t.server_connected),
            server_begin_request: us(t.server_begin_request),
            server_done_request: us(t.server_done_request),
            server_got_first_byte: us(t.server_got_first_byte),
            server_done_response: us(t.server_done_response),
            client_done_response: us(t.client_done_response),
            dns_ms: t.dns_ms,
            tcp_connect_ms: t.tcp_connect_ms,
            tls_handshake_ms: t.tls_handshake_ms,
        },
        client_connection: d.connection.client_conn_id,
        server_connection_reused: d.connection.server_conn_reused,
        tls_version: d.connection.server_tls.as_ref().map(|t| t.version.clone()).filter(|v| !v.is_empty()),
        process: s.process.clone(),
        request_body_hash: req_hash,
        response_body_hash: resp_hash,
    }
}

/// Record of a session in a capture (`None` if it was removed meanwhile).
pub fn record_of(cap: &Capture, id: SessionId, cancelled: &dyn Fn() -> bool) -> Option<AnalyzerSession> {
    let d = cap.detail(id)?;
    let (req, resp) = cap.bodies_of(id)?;
    Some(build_record(&d, &req, &resp, cancelled))
}

/// Scope of a run: the selection (`ids`, if not empty) or the visible sessions, sorted by
/// start (ties keep the view / selection order). Returns (ids, `"selection"` | `"visible"`).
/// Narrows the analysed sessions to processes and/or target hosts (empty = no restriction).
/// A host entry `*.example.com` also matches its subdomains.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DiagFilter {
    pub processes: Vec<String>,
    pub hosts: Vec<String>,
}

impl DiagFilter {
    pub fn is_empty(&self) -> bool {
        self.processes.is_empty() && self.hosts.is_empty()
    }
    fn host_matches(pattern: &str, host: &str) -> bool {
        // Hosts in the list may carry a port; patterns match with or without it.
        let bare = |h: &str| h.rsplit_once(':').filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit())).map(|(h, _)| h.to_string()).unwrap_or_else(|| h.to_string());
        let (p, h) = (pattern.to_ascii_lowercase(), host.to_ascii_lowercase());
        match p.strip_prefix("*.") {
            Some(domain) => {
                let hb = bare(&h);
                hb == domain || hb.ends_with(&format!(".{domain}"))
            }
            None => h == p || bare(&h) == p,
        }
    }
    pub fn matches(&self, s: &quena_model::SessionSummary) -> bool {
        (self.processes.is_empty() || self.processes.iter().any(|p| p == &s.process))
            && (self.hosts.is_empty() || self.hosts.iter().any(|p| Self::host_matches(p, &s.host)))
    }
}

/// Sessions to analyse, in start order: the given ids (selection) or the visible list,
/// narrowed by `filter`.
pub fn scope_ids(cap: &Capture, ids: Option<Vec<SessionId>>, filter: &DiagFilter) -> (Vec<SessionId>, &'static str) {
    let mut rows: Vec<(Micros, SessionId)> = Vec::new();
    let kind = match ids.filter(|i| !i.is_empty()) {
        Some(ids) => {
            let mut seen = std::collections::HashSet::new();
            rows.extend(
                ids.into_iter().filter(|id| seen.insert(*id)).filter_map(|id| cap.index.get(id)).filter(|s| filter.matches(s)).map(|s| (s.started_at, s.id)),
            );
            "selection"
        }
        None => {
            cap.index.for_each_view(|s| {
                if filter.matches(s) {
                    rows.push((s.started_at, s.id))
                }
            });
            "visible"
        }
    };
    rows.sort_by_key(|r| r.0);
    (rows.into_iter().map(|r| r.1).collect(), kind)
}

/// Processes and hosts of the visible sessions with their counts (most first), for choosing
/// the scope of an analysis.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagScopeOptions {
    pub processes: Vec<(String, u64)>,
    pub hosts: Vec<(String, u64)>,
}

pub fn scope_options(cap: &Capture) -> DiagScopeOptions {
    let mut procs: std::collections::HashMap<String, u64> = Default::default();
    let mut hosts: std::collections::HashMap<String, u64> = Default::default();
    cap.index.for_each_view(|s| {
        *procs.entry(s.process.clone()).or_default() += 1;
        if !s.host.is_empty() {
            *hosts.entry(s.host.clone()).or_default() += 1;
        }
    });
    let top = |m: std::collections::HashMap<String, u64>| {
        let mut v: Vec<(String, u64)> = m.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.truncate(500);
        v
    };
    DiagScopeOptions { processes: top(procs), hosts: top(hosts) }
}

/// Add the host's `scope` and `generatedAt` to a report.
pub fn finish_report(report: &str, scope: &str, sessions: usize, filter: &DiagFilter, generated_at: Micros) -> Result<String> {
    let mut v: serde_json::Value = serde_json::from_str(report).map_err(|e| anyhow!("analyzer report is not valid JSON: {e}"))?;
    let o = v.as_object_mut().ok_or_else(|| anyhow!("analyzer report is not a JSON object"))?;
    o.insert("scope".into(), serde_json::json!({ "kind": scope, "sessions": sessions, "processes": filter.processes, "hosts": filter.hosts }));
    o.insert("generatedAt".into(), serde_json::json!(generated_at));
    Ok(serde_json::to_string(&v)?)
}

// ------------------------------------------------------------------ AppCore

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiagAnalyzer {
    pub index: u16,
    pub id: String,
    pub name: String,
    pub title: String,
    pub version: String,
}

impl AppCore {
    fn plugin_host_or_err(&self) -> Result<Arc<quena_plugin_host::PluginHost>> {
        self.plugin_host.read().clone().ok_or_else(|| anyhow!("plugin host not available"))
    }

    /// Enabled, loaded analyzer plugins.
    pub fn diag_analyzers(&self) -> Vec<DiagAnalyzer> {
        self.plugins()
            .into_iter()
            .filter(|p| p.kind == PluginKind::Analyzer && p.enabled && p.error.is_none())
            .map(|p| DiagAnalyzer { index: p.index, id: p.id, name: p.name, title: p.tab, version: p.version })
            .collect()
    }

    /// Profiles and default options of an analyzer (JSON, see REPORT.md).
    pub fn diag_describe(&self, index: u16, lang: &str) -> Result<String> {
        self.plugin_host_or_err()?.describe(index, lang)
    }

    /// Processes and hosts of the visible sessions, for the scope of an analysis.
    pub fn diag_scope_options(&self) -> DiagScopeOptions {
        scope_options(&self.capture())
    }

    /// Start a diagnostics run as a background job over the selection (`ids`) or the visible
    /// sessions. When done, the report is kept ([`diag_report`](Self::diag_report)) and
    /// `diag-report` is emitted; a failing plugin fails the job. A new run cancels a running
    /// one; only the latest run (and none started before a reset, see
    /// [`diag_reset`](Self::diag_reset)) can store its report.
    pub fn diag_run(self: &Arc<Self>, index: u16, options: String, ids: Option<Vec<SessionId>>, filter: DiagFilter) -> Result<JobId> {
        let host = self.plugin_host_or_err()?;
        if !self.diag_analyzers().iter().any(|a| a.index == index) {
            return Err(anyhow!("analyzer {index} is not available"));
        }
        let cap = self.capture();
        let (ids, scope) = scope_ids(&cap, ids, &filter);
        if ids.is_empty() {
            return Err(anyhow!("no sessions in the chosen scope"));
        }
        let generation = self.diag_report.lock().begin();
        let core = Arc::downgrade(self);
        self.jobs.cancel_prefix("diag:");
        let key = format!("diag:{}", quena_model::now_us());
        Ok(self.jobs.submit(key, "Diagnostics", Priority::Background, true, move |ctx: &JobCtx| {
            let total = ids.len();
            let mut pos = 0usize;
            let cancelled = || ctx.cancelled();
            // Sessions removed meanwhile are skipped; an empty batch means the end.
            let mut next = || -> Option<Vec<AnalyzerSession>> {
                let mut batch = Vec::with_capacity(BATCH.min(total - pos));
                let mut size = 0usize;
                while pos < total && batch.len() < BATCH && size < BATCH_BYTES && !ctx.cancelled() {
                    if let Some(r) = record_of(&cap, ids[pos], &cancelled) {
                        size += record_bytes(&r);
                        batch.push(r);
                    }
                    pos += 1;
                    if pos.is_multiple_of(256) {
                        ctx.progress(pos as u64, total as u64);
                    }
                }
                ctx.progress(pos as u64, total as u64);
                (!batch.is_empty()).then_some(batch)
            };
            // Interrupts the plugin in flight when the job is cancelled.
            let state = ctx.state().clone();
            let report = host.analyze_interruptible(index, &options, &mut next, Arc::new(move || state.cancelled())).map_err(|e| format!("{e:#}"))?;
            let report = finish_report(&report, scope, total, &filter, quena_model::now_us()).map_err(|e| format!("{e:#}"))?;
            let Some(core) = core.upgrade() else { return Ok(()) };
            core.diag_store(generation, report, &cancelled);
            Ok(())
        }))
    }

    /// Keep the report of run `generation` and emit `diag-report` — unless the run was
    /// cancelled or superseded (a newer run or a reset). Checked under the report lock, so a
    /// stale run can never overwrite a newer report. Returns whether it was stored.
    pub(crate) fn diag_store(&self, generation: u64, report: String, cancelled: &dyn Fn() -> bool) -> bool {
        {
            let mut slot = self.diag_report.lock();
            if slot.generation != generation || cancelled() {
                return false;
            }
            slot.report = Some(Arc::new(report));
        }
        self.emit("diag-report", serde_json::Value::Null);
        true
    }

    /// Forget the report and cancel running analyses (the sessions it refers to are gone:
    /// "Remove all", another capture). Runs started before cannot store afterwards.
    pub fn diag_reset(&self) {
        {
            let mut slot = self.diag_report.lock();
            slot.generation += 1;
            slot.report = None;
        }
        self.jobs.cancel_prefix("diag:");
        self.emit("diag-report", serde_json::Value::Null);
    }

    /// The last diagnostics report (JSON).
    pub fn diag_report(&self) -> Option<Arc<String>> {
        self.diag_report.lock().report.clone()
    }
}

/// The last report and the generation of the latest run / reset (only that run may store).
#[derive(Default)]
pub(crate) struct DiagSlot {
    report: Option<Arc<String>>,
    generation: u64,
}

impl DiagSlot {
    /// A new run: supersedes all earlier ones.
    fn begin(&mut self) -> u64 {
        self.generation += 1;
        self.generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quena_model::{ConnectionInfo, HttpVersion, RequestHead, ResponseHead, SessionSummary, Timers, TlsInfo};

    fn headers(list: &[(&str, &str)]) -> Headers {
        let mut h = Headers::new();
        for (n, v) in list {
            h.push(*n, *v);
        }
        h
    }

    #[test]
    fn authorization_keeps_scheme_and_size() {
        let token = "x".repeat(812);
        assert_eq!(redact_authorization(&format!("Bearer {token}")), "Bearer <812 bytes>");
        assert_eq!(redact_authorization("Basic dXNlcjpwYXNz"), "Basic <12 bytes>");
        assert_eq!(redact_authorization("Negotiate  YIIGhgYGKwYBBQUCoIIGejCCBnag== "), "Negotiate <30 bytes>");
        assert_eq!(redact_authorization("NTLM TlRMTVNTUAABAAAAl4II4g=="), "NTLM <24 bytes>");
        assert_eq!(redact_authorization(r#"Digest username="bob", realm="x", response="abc""#), "Digest <41 bytes>");
        assert_eq!(redact_authorization("Bearer"), "Bearer");
        assert_eq!(redact_authorization(""), "");
        // No scheme: the value itself may be the secret.
        assert_eq!(redact_authorization("sk-live-1234567890"), "<18 bytes>");
        assert_eq!(redact_authorization("eyJhbGciOi.eyJzdWIi.sig"), "<23 bytes>");
        assert_eq!(redact_authorization("abc.def ghi"), "<11 bytes>");
    }

    #[test]
    fn authenticate_keeps_schemes_and_parameter_names() {
        assert_eq!(redact_authenticate(&format!("Negotiate {}", "A".repeat(1320))), "Negotiate <1320 bytes>");
        assert_eq!(redact_authenticate(r#"Bearer realm="api", error="invalid_token", error_description="The token expired""#), "Bearer realm, error, error_description");
        assert_eq!(redact_authenticate("Negotiate, NTLM"), "Negotiate, NTLM");
        assert_eq!(redact_authenticate(r#"Basic realm="a, b", charset="UTF-8", Negotiate"#), "Basic realm, charset, Negotiate");
        assert_eq!(redact_authenticate("NTLM TlRMTVNTUAACAAAADAAMADgAAAA="), "NTLM <28 bytes>");
        assert_eq!(redact_authenticate(r#"Digest realm="x", nonce="secret-nonce", qop="auth""#), "Digest realm, nonce, qop");
        assert_eq!(redact_authenticate(""), "");
    }

    #[test]
    fn cookies_keep_names_only() {
        assert_eq!(redact_cookie("a=1; b=secret; sid=xyz"), "a; b; sid");
        // A pair without `=` is a value (RFC 6265bis), not a name.
        assert_eq!(redact_cookie(" theme=dark ;; flag"), "theme; <4 bytes>");
        assert_eq!(redact_cookie("sessiontoken-abc123; theme=dark"), "<19 bytes>; theme");
        assert_eq!(redact_set_cookie("sid=abcdef; Path=/; HttpOnly; Secure; SameSite=Lax"), "sid=<6 bytes>; Path=/; HttpOnly; Secure; SameSite=Lax");
        assert_eq!(redact_set_cookie("token=; Max-Age=0"), "token=<0 bytes>; Max-Age=0");
        assert_eq!(redact_set_cookie("a=b=c"), "a=<3 bytes>");
        assert_eq!(redact_set_cookie("lonely"), "=<6 bytes>");
    }

    #[test]
    fn set_cookie_with_several_cookies_redacts_each() {
        // Folded with ", " (HAR exporters, intermediaries) and joined with line breaks.
        assert_eq!(redact_set_cookie("a=1; Path=/, sid=SECRET123; Path=/; HttpOnly"), "a=<1 bytes>; Path=/, sid=<9 bytes>; Path=/; HttpOnly");
        assert_eq!(redact_set_cookie("a=1; Path=/\nsid=SECRET123; Path=/"), "a=<1 bytes>; Path=/\nsid=<9 bytes>; Path=/");
        // The comma of an Expires date does not start a cookie.
        assert_eq!(
            redact_set_cookie("a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure, b=22; expires=Thu, 01 Jan 1970 00:00:00 GMT"),
            "a=<1 bytes>; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure, b=<2 bytes>; expires=Thu, 01 Jan 1970 00:00:00 GMT"
        );
        // Known attributes case-insensitively; anything else by its size.
        assert_eq!(
            redact_set_cookie("x=1; DOMAIN=.a.test; max-age=60; samesite=None; Partitioned; Priority=High; sid=SECRET; junk"),
            "x=<1 bytes>; DOMAIN=.a.test; max-age=60; samesite=None; Partitioned; Priority=High; sid=<6 bytes>; <4 bytes>"
        );
        let out = redact_set_cookie("a=1; Path=/, sid=SECRET123\nt=TOPSECRET, u=ALSOSECRET; Max-Age=1");
        assert!(!out.contains("SECRET"), "{out}");
    }

    #[test]
    fn urls_redact_sensitive_and_long_parameter_values() {
        assert_eq!(redact_url("https://api.test/v1/items?x=1&y=two"), "https://api.test/v1/items?x=1&y=two");
        assert_eq!(
            redact_url("https://login.test/cb?code=abc123&state=xyz&session_state=s1#access_token=eyJ0&token_type=Bearer&expires_in=3600"),
            "https://login.test/cb?code=%3C6%20bytes%3E&state=%3C3%20bytes%3E&session_state=%3C2%20bytes%3E#access_token=%3C4%20bytes%3E&token_type=%3C6%20bytes%3E&expires_in=3600"
        );
        // Signed URLs (AWS, Azure SAS), API keys, passwords, SAML; percent-encoded names too.
        let aws = redact_url("https://b.s3.test/o?X-Amz-Algorithm=AWS4&X-Amz-Credential=AKIA%2F1&X-Amz-Signature=deadbeef&versionId=3");
        assert_eq!(aws, "https://b.s3.test/o?X-Amz-Algorithm=%3C4%20bytes%3E&X-Amz-Credential=%3C8%20bytes%3E&X-Amz-Signature=%3C8%20bytes%3E&versionId=3");
        let sas = redact_url("https://a.blob.test/c/f?sv=2022-11-02&sp=r&se=2026-01-01&sr=b&sig=abc%3D&comp=list");
        assert_eq!(sas, "https://a.blob.test/c/f?sv=%3C10%20bytes%3E&sp=%3C1%20bytes%3E&se=%3C10%20bytes%3E&sr=%3C1%20bytes%3E&sig=%3C6%20bytes%3E&comp=list");
        assert_eq!(redact_url("/x?api%5Fkey=k1&Password=p&SAMLResponse=PHN&client_secret=c&id_token=j"), "/x?api%5Fkey=%3C2%20bytes%3E&Password=%3C1%20bytes%3E&SAMLResponse=%3C3%20bytes%3E&client_secret=%3C1%20bytes%3E&id_token=%3C1%20bytes%3E");
        // Long values of any name; OData system options keep theirs; empty values stay.
        let long = "a".repeat(65);
        assert_eq!(redact_url(&format!("/p?q={long}&ok={}&e=", "b".repeat(64))), format!("/p?q=%3C65%20bytes%3E&ok={}&e=", "b".repeat(64)));
        let filter = format!("$filter=Name%20eq%20%27{}%27&$select=Id", "x".repeat(80));
        assert_eq!(redact_url(&format!("https://h.test/odata/Cases?{filter}")), format!("https://h.test/odata/Cases?{filter}"));
        assert_eq!(redact_url(&format!("/p?{long}")), "/p?%3C65%20bytes%3E");
        // User info, relative references and fragments.
        assert_eq!(redact_url("https://bob:hunter2@h.test:8443/a?b=1"), "https://%3C11%20bytes%3E@h.test:8443/a?b=1");
        assert_eq!(redact_url("/login?next=https://app.test/home"), "/login?next=https://app.test/home");
        assert_eq!(redact_url("https://h.test/doc#section-2"), "https://h.test/doc#section-2");
        assert_eq!(redact_url(&format!("https://h.test/#{long}")), "https://h.test/#%3C65%20bytes%3E");
        assert_eq!(redact_url("api.test:443"), "api.test:443");
        // The result stays a URL: no raw spaces or angle brackets.
        assert!(!redact_url("https://h.test/?token=a b").contains(['<', '>']));
    }

    #[test]
    fn absolute_urls_need_a_scheme_prefix() {
        assert!(has_scheme("https://a.test/") && has_scheme("wss://a.test/s") && has_scheme("git+ssh://h/x"));
        assert!(!has_scheme("/login?next=https://app.test/home") && !has_scheme("a.test:443") && !has_scheme("://x") && !has_scheme("1http://x"));
    }

    #[test]
    fn long_values_are_cut_and_marked() {
        let v = "é".repeat(5000); // 10 000 bytes
        let c = cap_field(v.clone(), false);
        assert!(c.len() < FIELD_LIMIT + 40 && c.ends_with(&format!("…<truncated {} bytes>", 10_000 - FIELD_LIMIT)), "{}", &c[c.len() - 40..]);
        assert_eq!(cap_field("short".into(), false), "short");
        // URLs: the mark is percent-encoded and no `%XX` escape is split.
        let url = format!("https://h.test/{}", "%41".repeat(4000));
        let c = cap_field(url, true);
        let (head, tail) = c.split_once("%E2%80%A6%3Ctruncated%20").unwrap();
        assert!(head.len() <= FIELD_LIMIT && head.ends_with("%41") && tail.ends_with("%20bytes%3E"), "{tail}");
        let h = headers(&[("Referer", &format!("https://h.test/?q=1&{}", "a=1&".repeat(3000))), ("Content-Type", &"x".repeat(9000))]);
        let r = redact_headers(&h);
        assert!(r.iter().all(|(_, v)| v.len() <= FIELD_LIMIT + 40), "{r:?}");
        let many: Vec<(&str, &str)> = (0..300).map(|_| ("Set-Cookie", "a=1")).collect();
        assert_eq!(redact_headers(&headers(&many)).len(), HEADER_COUNT_LIMIT);
    }

    #[test]
    fn headers_are_allow_listed_case_insensitively_and_redacted() {
        let h = headers(&[
            ("Host", "api.test"),
            ("AUTHORIZATION", "Bearer abcdefgh"),
            ("Content-Type", "application/json"),
            ("X-Api-Key", "secret"),
            ("proxy-authorization", "Negotiate abcd"),
            ("Cookie", "sid=1; theme=dark"),
            ("x-request-id", "r-1"),
            ("Cache-Control", "no-cache"),
        ]);
        assert_eq!(
            redact_headers(&h),
            vec![
                ("AUTHORIZATION".to_string(), "Bearer <8 bytes>".to_string()),
                ("Content-Type".into(), "application/json".into()),
                ("proxy-authorization".into(), "Negotiate <4 bytes>".into()),
                ("Cookie".into(), "sid; theme".into()),
                ("x-request-id".into(), "r-1".into()),
                ("Cache-Control".into(), "no-cache".into()),
            ]
        );
        let h = headers(&[
            ("Set-Cookie", "a=1; Path=/"),
            ("Server", "nginx"),
            ("WWW-Authenticate", "Bearer realm=\"x\""),
            ("Proxy-Authenticate", "NTLM"),
            ("set-cookie", "b=22; Secure"),
            ("ETag", "\"v1\""),
            ("Location", "https://app.test/cb#id_token=eyJ0&state=s"),
            ("Referer", "https://app.test/?password=hunter2"),
        ]);
        assert_eq!(
            redact_headers(&h),
            vec![
                ("Set-Cookie".to_string(), "a=<1 bytes>; Path=/".to_string()),
                ("WWW-Authenticate".into(), "Bearer realm".into()),
                ("Proxy-Authenticate".into(), "NTLM".into()),
                ("set-cookie".into(), "b=<2 bytes>; Secure".into()),
                ("ETag".into(), "\"v1\"".into()),
                ("Location".into(), "https://app.test/cb#id_token=%3C4%20bytes%3E&state=%3C1%20bytes%3E".into()),
                ("Referer".into(), "https://app.test/?password=%3C7%20bytes%3E".into()),
            ]
        );
        assert!(HEADER_ALLOW_LIST.iter().all(|h| h.bytes().all(|b| !b.is_ascii_uppercase())));
    }

    #[test]
    fn fnv1a_reference_values() {
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a(b"foobar"), 0x8594_4171_f739_67e8);
    }

    fn capture() -> (tempfile::TempDir, Arc<Capture>) {
        let dir = tempfile::tempdir().unwrap();
        let cap = Capture::open(dir.path().join("cap"), quena_body::BodyConfig::default(), true).unwrap();
        (dir, cap)
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn fingerprints_use_the_decoded_body_within_limits() {
        let (_d, cap) = capture();
        let text = b"hello world ".repeat(1000);
        let plain = cap.bodies.store_bytes(&text);
        let zipped = cap.bodies.store_bytes(&gzip(&text));
        let never = &|| false;
        assert_eq!(body_fingerprint(&plain, None, 1 << 20, true, never), (text.len() as u64, Some(fnv1a(&text))));
        assert_eq!(body_fingerprint(&zipped, Some("gzip"), 1 << 20, true, never), (text.len() as u64, Some(fnv1a(&text))));
        // Too large: no fingerprint, but the decoded size is still known.
        assert_eq!(body_fingerprint(&zipped, Some("gzip"), 100, true, never), (text.len() as u64, None));
        assert_eq!(body_fingerprint(&plain, None, 100, true, never), (text.len() as u64, None));
        assert_eq!(body_fingerprint(&zipped, Some("gzip"), 100, false, never).1, None);
        // Empty, undecodable and unknown codings.
        assert_eq!(body_fingerprint(&Body::empty(), None, 100, true, never), (0, None));
        assert_eq!(body_fingerprint(&plain, Some("gzip"), 1 << 20, true, never).1, None);
        assert_eq!(body_fingerprint(&plain, Some("x-custom"), 1 << 20, true, never), (text.len() as u64, None));
        // At the limit is still hashed.
        let exact = cap.bodies.store_bytes(&text[..100]);
        assert_eq!(body_fingerprint(&exact, None, 100, true, never), (100, Some(fnv1a(&text[..100]))));
    }

    fn detail(kind: SessionKind, url: &str, started: Micros) -> SessionDetail {
        let mut d = SessionDetail {
            summary: SessionSummary { kind, started_at: started, ..Default::default() },
            request: RequestHead {
                method: if kind == SessionKind::Tunnel { "CONNECT".into() } else { "POST".into() },
                url: url.into(),
                version: HttpVersion::Http2,
                headers: headers(&[("Authorization", "Bearer secret-token"), ("Cookie", "sid=42"), ("User-Agent", "test"), ("Content-Encoding", "gzip")]),
            },
            response: Some(ResponseHead {
                status: 201,
                reason: "Created".into(),
                version: HttpVersion::Http2,
                headers: headers(&[("Content-Type", "application/json; charset=utf-8"), ("Content-Encoding", "gzip"), ("Set-Cookie", "sid=abc; HttpOnly")]),
            }),
            timers: Timers {
                client_begin_request: Some(started),
                server_got_first_byte: Some(started + 40_000),
                client_done_response: Some(started + 50_000),
                dns_ms: Some(3),
                ..Default::default()
            },
            connection: ConnectionInfo {
                client_conn_id: Some(7),
                server_conn_reused: true,
                server_tls: Some(TlsInfo { version: "TLSv1.3".into(), ..Default::default() }),
                ..Default::default()
            },
            error: None,
            ..Default::default()
        };
        d.summary.process = "app:1".into();
        d
    }

    #[test]
    fn records_carry_redacted_headers_sizes_timers_and_fingerprints() {
        let (_d, cap) = capture();
        let req_text = br#"{"q":1}"#;
        let resp_text = br#"{"items":[1,2,3]}"#.repeat(100);
        let req = cap.bodies.store_bytes(&gzip(req_text));
        let resp_gz = gzip(&resp_text);
        let resp = cap.bodies.store_bytes(&resp_gz);
        let id = cap.insert(detail(SessionKind::Http, "https://api.test/v1/items?x=1", 1_000_000), req, resp);
        let t = cap.insert(detail(SessionKind::Tunnel, "api.test:443", 500_000), Body::empty(), Body::empty());
        let mut ws = detail(SessionKind::WebSocket, "wss://api.test/socket", 2_000_000);
        ws.response = None;
        ws.error = Some("connection reset".into());
        let w = cap.insert(ws, Body::empty(), Body::empty());

        let r = record_of(&cap, id, &|| false).unwrap();
        assert_eq!((r.id, r.kind.as_str(), r.started, r.duration_ms), (id, "http", 1_000_000, Some(50)));
        assert_eq!((r.method.as_str(), r.url.as_str(), r.host.as_str(), r.version.as_str(), r.status), ("POST", "https://api.test/v1/items?x=1", "api.test", "HTTP/2", 201));
        assert_eq!((r.request_bytes, r.response_bytes, r.response_decoded_bytes), (gzip(req_text).len() as u64, resp_gz.len() as u64, resp_text.len() as u64));
        assert_eq!(r.content_type, "application/json");
        assert_eq!(
            r.request_headers,
            vec![("Authorization".to_string(), "Bearer <12 bytes>".to_string()), ("Cookie".into(), "sid".into()), ("Content-Encoding".into(), "gzip".into())]
        );
        assert!(r.response_headers.contains(&("Set-Cookie".into(), "sid=<3 bytes>; HttpOnly".into())));
        assert_eq!((r.timers.client_begin_request, r.timers.server_got_first_byte, r.timers.dns_ms), (Some(1_000_000), Some(1_040_000), Some(3)));
        assert_eq!((r.client_connection, r.server_connection_reused, r.tls_version.as_deref(), r.process.as_str()), (Some(7), true, Some("TLSv1.3"), "app:1"));
        assert_eq!((r.request_body_hash, r.response_body_hash), (Some(fnv1a(req_text)), Some(fnv1a(&resp_text))));

        let r = record_of(&cap, t, &|| false).unwrap();
        assert_eq!((r.kind.as_str(), r.url.as_str(), r.method.as_str()), ("tunnel", "api.test:443", "CONNECT"));
        assert_eq!((r.request_body_hash, r.response_body_hash, r.response_decoded_bytes), (None, None, 0));
        let r = record_of(&cap, w, &|| false).unwrap();
        assert_eq!((r.kind.as_str(), r.status, r.error.as_deref()), ("websocket", 0, Some("connection reset")));
        assert!(r.response_headers.is_empty());
        assert!(record_of(&cap, 999, &|| false).is_none());

        // Scope: sorted by start; the selection keeps only known ids, once.
        cap.index.tick();
        let all = DiagFilter::default();
        assert_eq!(scope_ids(&cap, None, &all), (vec![t, id, w], "visible"));
        assert_eq!(scope_ids(&cap, Some(vec![]), &all), (vec![t, id, w], "visible"));
        assert_eq!(scope_ids(&cap, Some(vec![w, 999, id, w]), &all), (vec![id, w], "selection"));
        // Narrowed to a process / a host.
        let proc_of = |x| cap.index.get(x).unwrap().process;
        let only = DiagFilter { processes: vec![proc_of(id)], hosts: vec![] };
        assert!(scope_ids(&cap, None, &only).0.contains(&id));
        let none = DiagFilter { processes: vec!["no-such-process".into()], hosts: vec![] };
        assert!(scope_ids(&cap, None, &none).0.is_empty());
        let opts = scope_options(&cap);
        assert!(opts.processes.iter().any(|(p, n)| *p == proc_of(id) && *n >= 1), "{opts:?}");
    }

    #[test]
    fn report_gets_scope_and_time() {
        let f = DiagFilter { processes: vec!["chrome".into()], hosts: vec!["*.example.com".into()] };
        let r = finish_report(r#"{"schema":1,"findings":[]}"#, "selection", 3, &f, 42).unwrap();
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        assert_eq!(v["scope"], serde_json::json!({"kind": "selection", "sessions": 3, "processes": ["chrome"], "hosts": ["*.example.com"]}));
        assert_eq!((v["generatedAt"].as_i64(), v["schema"].as_i64()), (Some(42), Some(1)));
        assert!(finish_report("[]", "visible", 0, &f, 0).is_err());
        assert!(finish_report("{", "visible", 0, &f, 0).is_err());
    }

    #[derive(Default)]
    struct Events(parking_lot::Mutex<Vec<String>>);
    impl crate::EventSink for Events {
        fn emit(&self, event: &str, _: serde_json::Value) {
            self.0.lock().push(event.to_string());
        }
    }

    fn core() -> (tempfile::TempDir, Arc<AppCore>) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("settings.json"), r#"{"proxy":{"actAsSystemProxy":false,"captureOnStartup":false}}"#).unwrap();
        let core = AppCore::new(crate::Paths::at(dir.path().to_path_buf()), crate::logbuf::LogBuffer::new(10)).unwrap();
        (dir, core)
    }

    #[test]
    fn only_the_latest_uncancelled_run_stores_its_report() {
        let (_d, core) = core();
        let events = Arc::new(Events::default());
        core.set_sink(events.clone());
        let old = core.diag_report.lock().begin();
        let new = core.diag_report.lock().begin();
        assert!(core.diag_store(new, "new".into(), &|| false));
        // The older run finishes last: it must not overwrite the newer report.
        assert!(!core.diag_store(old, "old".into(), &|| false));
        // Cancelled after `finish`: not stored either.
        assert!(!core.diag_store(new, "cancelled".into(), &|| true));
        assert_eq!(core.diag_report().as_deref().map(String::as_str), Some("new"));
        assert_eq!(events.0.lock().iter().filter(|e| *e == "diag-report").count(), 1);
    }

    #[test]
    fn remove_all_and_switch_capture_drop_the_report_and_cancel_runs() {
        let (_d, core) = core();
        let events = Arc::new(Events::default());
        core.set_sink(events.clone());
        for reset in [0, 1] {
            let run = core.diag_report.lock().begin();
            assert!(core.diag_store(run, "r".into(), &|| false));
            // A run started before the reset (still running).
            let stale = core.diag_report.lock().begin();
            let job = core.jobs.submit("diag:test", "Diagnostics", Priority::Background, true, |ctx: &JobCtx| {
                while !ctx.cancelled() {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Ok(())
            });
            events.0.lock().clear();
            if reset == 0 {
                core.remove_all();
            } else {
                let (_d2, cap) = capture();
                core.switch_capture(cap);
            }
            assert!(core.diag_report().is_none());
            assert!(events.0.lock().iter().any(|e| e == "diag-report"));
            assert!(core.jobs.get(job).unwrap().cancelled());
            // Session ids restart: the stale run can no longer store its report.
            assert!(!core.diag_store(stale, "stale".into(), &|| false));
            assert!(core.diag_report().is_none());
        }
    }

    #[test]
    fn batches_are_bounded_by_bytes_too() {
        let (_d, cap) = capture();
        let mut d = detail(SessionKind::Http, "https://api.test/x", 1);
        d.request.headers = headers(&[("Content-Type", &"x".repeat(FIELD_LIMIT))]);
        let id = cap.insert(d, Body::empty(), Body::empty());
        let r = record_of(&cap, id, &|| false).unwrap();
        assert!(record_bytes(&r) > FIELD_LIMIT && record_bytes(&r) < FIELD_LIMIT + 2048);
        // A batch of such records stays well below the batch byte limit.
        assert!(BATCH_BYTES / record_bytes(&r) < BATCH);
    }

    #[test]
    fn host_patterns() {
        let m = DiagFilter::host_matches;
        assert!(m("api.example.com", "api.example.com") && m("api.example.com", "API.example.com:443"));
        assert!(m("*.example.com", "example.com") && m("*.example.com", "a.b.example.com:8443"));
        assert!(!m("*.example.com", "badexample.com") && !m("api.example.com", "www.example.com"));
    }
}
