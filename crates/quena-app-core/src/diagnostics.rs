//! Diagnostics: runs an analyzer plugin (e.g. `webdiag`) over the visible sessions or a
//! selection and keeps the last report.
//!
//! The host builds one record per session (plugins/webdiag/REPORT.md): allow-listed headers
//! with secrets redacted, sizes, timers, connection data and fingerprints of the decoded
//! bodies. Header values that carry credentials never reach the plugin.

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
/// Decoding stops here when only the decoded size is still wanted (decompression bombs).
const DECODED_COUNT_LIMIT: u64 = 256 << 20;

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

/// `Cookie`: names only.
pub fn redact_cookie(v: &str) -> String {
    v.split(';').map(|c| c.split_once('=').map_or(c, |(n, _)| n).trim()).filter(|n| !n.is_empty()).collect::<Vec<_>>().join("; ")
}

/// `Set-Cookie`: `name=<n bytes>` plus the attributes verbatim.
pub fn redact_set_cookie(v: &str) -> String {
    let (pair, attrs) = match v.find(';') {
        Some(i) => (&v[..i], &v[i..]),
        None => (v, ""),
    };
    let (name, value) = pair.split_once('=').unwrap_or(("", pair));
    format!("{}={}{attrs}", name.trim(), bytes(value.trim().len()))
}

/// Allow-listed headers in wire order, secrets redacted (REPORT.md).
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
                _ => value.to_string(),
            };
            Some((name.to_string(), value))
        })
        .collect()
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
    let url = if d.request.url.contains("://") || s.kind == SessionKind::Tunnel { d.request.url.clone() } else { s.full_url() };
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
        error: d.error.clone(),
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

    /// Start a diagnostics run as a background job over the selection (`ids`) or the visible
    /// sessions. When done, the report is kept ([`diag_report`](Self::diag_report)) and
    /// `diag-report` is emitted; a failing plugin fails the job. A new run cancels a running one.
    /// Processes and hosts of the visible sessions, for the scope of an analysis.
    pub fn diag_scope_options(&self) -> DiagScopeOptions {
        scope_options(&self.capture())
    }

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
                while pos < total && batch.len() < BATCH && !ctx.cancelled() {
                    if let Some(r) = record_of(&cap, ids[pos], &cancelled) {
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
            let report = host.analyze(index, &options, &mut next, &cancelled).map_err(|e| format!("{e:#}"))?;
            let report = finish_report(&report, scope, total, &filter, quena_model::now_us()).map_err(|e| format!("{e:#}"))?;
            let Some(core) = core.upgrade() else { return Ok(()) };
            *core.diag_report.lock() = Some(Arc::new(report));
            core.emit("diag-report", serde_json::Value::Null);
            Ok(())
        }))
    }

    /// The last diagnostics report (JSON).
    pub fn diag_report(&self) -> Option<Arc<String>> {
        self.diag_report.lock().clone()
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
        assert_eq!(redact_cookie(" theme=dark ;; flag"), "theme; flag");
        assert_eq!(redact_set_cookie("sid=abcdef; Path=/; HttpOnly; Secure; SameSite=Lax"), "sid=<6 bytes>; Path=/; HttpOnly; Secure; SameSite=Lax");
        assert_eq!(redact_set_cookie("token=; Max-Age=0"), "token=<0 bytes>; Max-Age=0");
        assert_eq!(redact_set_cookie("a=b=c"), "a=<3 bytes>");
        assert_eq!(redact_set_cookie("lonely"), "=<6 bytes>");
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
        ]);
        assert_eq!(
            redact_headers(&h),
            vec![
                ("Set-Cookie".to_string(), "a=<1 bytes>; Path=/".to_string()),
                ("WWW-Authenticate".into(), "Bearer realm".into()),
                ("Proxy-Authenticate".into(), "NTLM".into()),
                ("set-cookie".into(), "b=<2 bytes>; Secure".into()),
                ("ETag".into(), "\"v1\"".into()),
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

    #[test]
    fn host_patterns() {
        let m = DiagFilter::host_matches;
        assert!(m("api.example.com", "api.example.com") && m("api.example.com", "API.example.com:443"));
        assert!(m("*.example.com", "example.com") && m("*.example.com", "a.b.example.com:8443"));
        assert!(!m("*.example.com", "badexample.com") && !m("api.example.com", "www.example.com"));
    }
}
