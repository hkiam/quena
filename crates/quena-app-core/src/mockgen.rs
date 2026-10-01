//! Mocks from a recording: the sessions become a list of [`MockEntry`] (request matcher plus
//! recorded response), which is written as
//!
//! - a **Quena mock package** (`.quena-mocks`, a ZIP with `rules.json`, `responses/*.dat` and
//!   `README.txt`) that Mock Rules import, or that is installed directly
//!   ([`AppCore::mock_apply`]); the response files outlive the capture, unlike `session:ID` rules;
//! - a **WireMock export** (`mappings/*.json`, `__files/*`, `README.md`) as folder or ZIP.
//!
//! Responses are served decoded: Content-Encoding, hop-by-hop headers and (by default)
//! Set-Cookie are removed, Content-Length is recomputed. Optionally the sessions are sanitized
//! first ([`crate::sanitize`]); values the sanitizer replaced in the request are matched as
//! "any value", so the mock still answers the real client.

use crate::AppCore;
use crate::rules::{AutoResponderState, JSON_IGNORE, Rule, Rules};
use crate::sanitize::{SanitizeOptions, Sanitizer, decoded_body};
use anyhow::{Context, Result, anyhow, bail};
use quena_body::Body;
use quena_formats::Progress;
use quena_jobs::{JobCtx, JobId, Priority};
use quena_model::*;
use quena_store::Capture;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

// ------------------------------------------------------------------ options

/// How the query string of a request is matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum QueryMatch {
    /// The whole URL as recorded.
    Exact,
    /// The parameters in [`MockOptions::ignore_params`] may have any value or be missing.
    #[default]
    Ignore,
}

/// What happens with several recordings of the same request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum Repeats {
    /// The last response wins.
    #[default]
    Last,
    /// The responses in recorded order; the last one repeats (Quena: `match_once` chain,
    /// WireMock: scenario).
    Sequence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct MockOptions {
    /// Only these hosts (`host[:port]`, also matches subdomains); empty: all.
    pub hosts: Vec<String>,
    /// Include scripts, styles, images, fonts and media (usually served by the dev server).
    pub include_static: bool,
    pub query: QueryMatch,
    /// Parameter names ignored with [`QueryMatch::Ignore`]; `*` is a wildcard (`utm_*`).
    pub ignore_params: Vec<String>,
    pub repeats: Repeats,
    /// Match requests with a body (POST, PUT, PATCH …) by their body: JSON semantically,
    /// GraphQL by operation name and variables, forms and text exactly.
    pub match_body: bool,
    /// Answer after the recorded time to first byte.
    pub latency: bool,
    /// Include CORS preflights (OPTIONS).
    pub include_preflight: bool,
    /// Include 4xx/5xx responses.
    pub include_errors: bool,
    /// Sanitize before writing (`None`: as recorded). Deserializes from full options or from
    /// a preset name (`"credentials"`, `"support"`, `"gdpr"`).
    #[serde(deserialize_with = "sanitize_or_preset")]
    pub sanitize: Option<SanitizeOptions>,
    /// Keep Set-Cookie response headers.
    pub keep_set_cookie: bool,
}

fn sanitize_or_preset<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Option<SanitizeOptions>, D::Error> {
    use serde::de::Error;
    match Value::deserialize(d)? {
        Value::Null => Ok(None),
        Value::String(name) => SanitizeOptions::preset(&name).map(Some).ok_or_else(|| D::Error::custom(format!("unknown sanitize preset {name:?}"))),
        v => serde_json::from_value(v).map(Some).map_err(D::Error::custom),
    }
}

pub const DEFAULT_IGNORED_PARAMS: [&str; 4] = ["_", "t", "cacheBust", "utm_*"];

impl Default for MockOptions {
    fn default() -> Self {
        MockOptions {
            hosts: vec![],
            include_static: false,
            query: QueryMatch::Ignore,
            ignore_params: DEFAULT_IGNORED_PARAMS.iter().map(|s| s.to_string()).collect(),
            repeats: Repeats::Last,
            match_body: true,
            latency: false,
            include_preflight: true,
            include_errors: true,
            sanitize: Some(SanitizeOptions::preset("credentials").unwrap_or_default()),
            keep_set_cookie: false,
        }
    }
}

// ------------------------------------------------------------------ model

/// Why a session did not become a mock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SkipReason {
    NoResponse,
    Incomplete,
    Truncated,
    Tunnel,
    WebSocket,
    Host,
    Static,
    Preflight,
    ErrorStatus,
    NotModified,
    /// [`Repeats::Last`]: a later recording of the same request wins.
    Superseded,
    /// [`Repeats::Sequence`]: the same response as the one before.
    Duplicate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Skipped {
    pub id: SessionId,
    pub method: String,
    pub url: String,
    pub reason: SkipReason,
}

/// A query parameter the mock matches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct QueryParam {
    /// As in the URL (percent-encoded).
    pub raw_name: String,
    /// As in the URL; `None` for a bare `name` without `=`.
    pub raw_value: Option<String>,
    /// Decoded.
    pub name: String,
    pub value: Option<String>,
    /// Any value matches (the sanitizer replaced it).
    pub any: bool,
}

/// How the request body is matched.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum BodyMatch {
    None,
    /// Semantically equal JSON; [`JSON_IGNORE`] marks values that may differ.
    Json { value: Value },
    GraphQl { operation_name: String, variables: Value },
    /// `application/x-www-form-urlencoded` pairs as sent (raw); `None` matches any value.
    Form { pairs: Vec<(String, Option<String>)> },
    Text { text: String },
}

impl BodyMatch {
    pub fn is_none(&self) -> bool {
        matches!(self, BodyMatch::None)
    }
}

/// Position of an entry in a sequence of responses to the same request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Sequence {
    /// Number of the sequence (unique in the set).
    pub group: usize,
    pub index: usize,
    pub len: usize,
}

/// One mock: request matcher and recorded response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MockEntry {
    pub session: SessionId,
    pub method: String,
    /// The URL as written (sanitized when sanitizing).
    pub url: String,
    /// `scheme://host[:port]`
    pub origin: String,
    /// `host[:port]`
    pub host: String,
    pub path: String,
    /// The parameters that must be present (in recorded order), without the ignored ones.
    pub query: Vec<QueryParam>,
    /// Parameter patterns that may additionally appear with any value.
    pub ignored_params: Vec<String>,
    /// The whole URL matches exactly (no ignored or replaced parameters).
    pub exact_url: bool,
    pub body_match: BodyMatch,
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    #[serde(skip)]
    pub body: Vec<u8>,
    pub content_type: String,
    pub delay_ms: u32,
    pub sequence: Option<Sequence>,
}

/// The generated mocks plus what was left out.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MockSet {
    /// In rule order: specific matchers first, sequences in recorded order.
    pub entries: Vec<MockEntry>,
    pub skipped: Vec<Skipped>,
    /// Sessions examined.
    pub sessions: usize,
    /// Hosts of the entries (sorted).
    pub hosts: Vec<String>,
}

impl MockSet {
    pub fn sequences(&self) -> usize {
        self.entries.iter().filter(|e| e.sequence.is_some_and(|s| s.index == 0)).count()
    }
}

/// Summary for the dialog (live preview).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MockPreview {
    pub sessions: usize,
    pub mappings: usize,
    pub sequences: usize,
    pub hosts: Vec<String>,
    pub skipped_by_reason: BTreeMap<SkipReason, usize>,
    /// At most [`PREVIEW_ROWS`].
    pub skipped: Vec<Skipped>,
    /// At most [`PREVIEW_ROWS`].
    pub entries: Vec<PreviewEntry>,
}

pub const PREVIEW_ROWS: usize = 300;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewEntry {
    pub session: SessionId,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub body_match: bool,
    pub sequence: Option<Sequence>,
}

impl MockPreview {
    pub fn of(set: &MockSet) -> MockPreview {
        let mut by = BTreeMap::new();
        for s in &set.skipped {
            *by.entry(s.reason).or_insert(0) += 1;
        }
        MockPreview {
            sessions: set.sessions,
            mappings: set.entries.len(),
            sequences: set.sequences(),
            hosts: set.hosts.clone(),
            skipped_by_reason: by,
            skipped: set.skipped.iter().take(PREVIEW_ROWS).cloned().collect(),
            entries: set
                .entries
                .iter()
                .take(PREVIEW_ROWS)
                .map(|e| PreviewEntry { session: e.session, method: e.method.clone(), url: e.url.clone(), status: e.status, body_match: !e.body_match.is_none(), sequence: e.sequence })
                .collect(),
        }
    }
}

// ------------------------------------------------------------------ generation

/// Request bodies above this size are not matched.
const MAX_MATCH_BODY: usize = 1 << 20;

/// Response headers never written into a mock (the body is served decoded and complete).
const DROP_RESPONSE_HEADERS: [&str; 10] =
    ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "trailer", "upgrade", "content-length", "alt-svc", "content-encoding"];

struct Cand {
    entry: MockEntry,
    key: String,
}

/// Build the mocks for `ids` (in this order; usually ascending = recorded order).
///
/// `with_bodies: false` is the cheap variant for a preview: response bodies are not read and
/// nothing is sanitized (the counts are the same).
pub fn generate(cap: &Arc<Capture>, ids: &[SessionId], opts: &MockOptions, with_bodies: bool, p: &dyn Progress) -> Result<MockSet> {
    let mut sanitizer = if with_bodies { opts.sanitize.clone().map(Sanitizer::new) } else { None };
    let mut set = MockSet { sessions: ids.len(), ..Default::default() };
    let mut groups: Vec<Vec<Cand>> = Vec::new();
    let mut by_key: HashMap<String, usize> = HashMap::new();
    for (i, id) in ids.iter().enumerate() {
        if p.cancelled() {
            bail!("cancelled");
        }
        if i % 64 == 0 {
            p.progress(i as u64, ids.len() as u64);
        }
        let Some(d) = cap.detail(*id) else { continue };
        match candidate(cap, &d, opts, sanitizer.as_mut(), with_bodies) {
            Ok(c) => {
                let g = *by_key.entry(c.key.clone()).or_insert_with(|| {
                    groups.push(Vec::new());
                    groups.len() - 1
                });
                groups[g].push(c);
            }
            Err(reason) => set.skipped.push(Skipped { id: *id, method: d.request.method.clone(), url: d.request.url.clone(), reason }),
        }
    }
    // Specific matchers first: a request with a body rule must not be caught by a body-less
    // rule for the same URL (first match wins).
    let mut order: Vec<usize> = (0..groups.len()).collect();
    order.sort_by_key(|g| groups[*g].first().map(|c| c.entry.body_match.is_none()).unwrap_or(true));
    let mut seq_no = 0;
    for g in order {
        let mut items = std::mem::take(&mut groups[g]);
        let skip = |c: &Cand, reason| Skipped { id: c.entry.session, method: c.entry.method.clone(), url: c.entry.url.clone(), reason };
        match opts.repeats {
            Repeats::Last => {
                let last = items.pop().expect("groups are never empty");
                set.skipped.extend(items.iter().map(|c| skip(c, SkipReason::Superseded)));
                set.entries.push(last.entry);
            }
            Repeats::Sequence => {
                let mut kept: Vec<Cand> = Vec::new();
                for c in items {
                    if with_bodies && kept.last().is_some_and(|k| k.entry.status == c.entry.status && k.entry.body == c.entry.body) {
                        set.skipped.push(skip(&c, SkipReason::Duplicate));
                    } else {
                        kept.push(c);
                    }
                }
                let len = kept.len();
                if len > 1 {
                    seq_no += 1;
                }
                for (index, mut c) in kept.into_iter().enumerate() {
                    if len > 1 {
                        c.entry.sequence = Some(Sequence { group: seq_no, index, len });
                    }
                    set.entries.push(c.entry);
                }
            }
        }
    }
    let mut hosts: Vec<String> = set.entries.iter().map(|e| e.host.clone()).collect();
    hosts.sort();
    hosts.dedup();
    set.hosts = hosts;
    set.skipped.sort_by_key(|s| s.id);
    p.progress(ids.len() as u64, ids.len() as u64);
    Ok(set)
}

fn candidate(cap: &Arc<Capture>, d: &SessionDetail, opts: &MockOptions, sanitizer: Option<&mut Sanitizer>, with_bodies: bool) -> std::result::Result<Cand, SkipReason> {
    let method = d.request.method.to_ascii_uppercase();
    if d.summary.kind == SessionKind::Tunnel || method == "CONNECT" {
        return Err(SkipReason::Tunnel);
    }
    if d.summary.kind == SessionKind::WebSocket {
        return Err(SkipReason::WebSocket);
    }
    let Some(resp) = &d.response else { return Err(SkipReason::NoResponse) };
    match resp.status {
        0 => return Err(SkipReason::NoResponse),
        101 => return Err(SkipReason::WebSocket),
        304 => return Err(SkipReason::NotModified),
        _ => {}
    }
    if d.summary.state == SessionState::Aborted || d.summary.has_flag(flags::SERVER_ABORTED) {
        return Err(SkipReason::Incomplete);
    }
    if d.summary.has_flag(flags::RESPONSE_TRUNCATED) {
        return Err(SkipReason::Truncated);
    }
    let Some((origin, path, query)) = split_full_url(&d.request.url) else { return Err(SkipReason::Tunnel) };
    let host = origin.split_once("://").map(|(_, h)| h.to_string()).unwrap_or_default();
    if !opts.hosts.is_empty() && !opts.hosts.iter().any(|h| host_matches(h, &host)) {
        return Err(SkipReason::Host);
    }
    let resp_ct = resp.headers.get("content-type").unwrap_or("");
    if !opts.include_static && is_static(&path, resp_ct) {
        return Err(SkipReason::Static);
    }
    if method == "OPTIONS" && !opts.include_preflight {
        return Err(SkipReason::Preflight);
    }
    if resp.status >= 400 && !opts.include_errors {
        return Err(SkipReason::ErrorStatus);
    }
    let (req_body, resp_body) = cap.bodies_of(d.summary.id).unwrap_or_else(|| (Body::empty(), Body::empty()));
    if with_bodies && resp_body.is_truncated() {
        return Err(SkipReason::Truncated);
    }
    let wants_req = opts.match_body && !req_body.is_empty() && (req_body.len() as usize) <= MAX_MATCH_BODY * 4;
    let req_orig = if wants_req { decoded_body(&d.request.headers, &req_body, MAX_MATCH_BODY + 1) } else { Vec::new() };

    // Sanitize (or just decode) what is written.
    let (detail, req_san, resp_bytes, keep_encoding) = match sanitizer {
        Some(s) => {
            let out = s.session(d, &req_body, &resp_body);
            (out.detail, out.request, out.response, false)
        }
        None => {
            let resp_bytes = if with_bodies { decoded_body(&resp.headers, &resp_body, usize::MAX) } else { Vec::new() };
            // Unknown or broken encoding: the bytes are still encoded, so the header stays.
            let ce = resp.headers.get("content-encoding").map(|v| v.trim().to_ascii_lowercase()).filter(|v| !v.is_empty() && v != "identity");
            let still_encoded = with_bodies && ce.is_some() && !resp_body.is_empty() && resp_body.read_range(0, resp_bytes.len() + 1).is_ok_and(|raw| raw == resp_bytes);
            (d.clone(), req_orig.clone(), resp_bytes, still_encoded)
        }
    };
    let resp = detail.response.as_ref().unwrap_or(resp);

    // URL: parameters replaced by the sanitizer match any value.
    let (_, san_path, san_query) = split_full_url(&detail.request.url).unwrap_or((origin.clone(), path.clone(), query.clone()));
    let orig_params = parse_query(query.as_deref());
    let mut params = parse_query(san_query.as_deref());
    mark_replaced(&orig_params, &mut params);
    let ignored: Vec<String> = match opts.query {
        QueryMatch::Ignore => opts.ignore_params.iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
        QueryMatch::Exact => vec![],
    };
    let before = params.len();
    params.retain(|q| !ignored.iter().any(|pat| glob_matches(pat, &q.name)));
    // A URL without ignored (or replaced) parameters stays an exact, readable match.
    let exact_url = params.len() == before && !params.iter().any(|q| q.any);

    let req_ct = detail.request.headers.get("content-type").unwrap_or("").to_ascii_lowercase();
    let body_match = if wants_req && req_orig.len() <= MAX_MATCH_BODY { body_match(&req_ct, &req_orig, &req_san) } else { BodyMatch::None };

    // Response as served.
    let mut headers: Vec<(String, String)> = resp
        .headers
        .iter()
        .filter(|(n, _)| {
            let l = n.to_ascii_lowercase();
            !n.starts_with(':')
                && !(DROP_RESPONSE_HEADERS.contains(&l.as_str()) && !(keep_encoding && l == "content-encoding"))
                && (opts.keep_set_cookie || l != "set-cookie")
        })
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect();
    let body = if method == "HEAD" || resp.status == 204 { Vec::new() } else { resp_bytes };
    if with_bodies {
        headers.push(("Content-Length".into(), body.len().to_string()));
    }
    let content_type = resp.headers.get("content-type").unwrap_or("").to_string();
    let delay_ms = if opts.latency { ttfb_ms(&d.timers) } else { 0 };
    let reason = if resp.reason.trim().is_empty() { crate::mock::reason(resp.status).to_string() } else { resp.reason.clone() };

    let key = format!(
        "{method} {} {} ?{} #{}",
        origin.to_ascii_lowercase(),
        san_path,
        {
            let mut q: Vec<String> = params.iter().map(|q| format!("{}={}", q.raw_name, if q.any { "*" } else { q.raw_value.as_deref().unwrap_or("") })).collect();
            q.sort();
            q.join("&")
        },
        body_key(&body_match)
    );
    Ok(Cand {
        key,
        entry: MockEntry {
            session: d.summary.id,
            method,
            url: detail.request.url.clone(),
            origin,
            host,
            path: san_path,
            query: params,
            ignored_params: ignored,
            exact_url,
            body_match,
            status: resp.status,
            reason,
            headers,
            body,
            content_type,
            delay_ms,
            sequence: None,
        },
    })
}

/// `scheme://authority`, path (without query), query. `None` for a URL without scheme.
fn split_full_url(url: &str) -> Option<(String, String, Option<String>)> {
    let (scheme, rest) = url.split_once("://")?;
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(auth_end);
    let tail = &tail[..tail.find('#').unwrap_or(tail.len())];
    let (path, query) = match tail.split_once('?') {
        Some((p, q)) => (p, Some(q.to_string())),
        None => (tail, None),
    };
    let path = if path.is_empty() { "/".to_string() } else { path.to_string() };
    Some((format!("{scheme}://{authority}"), path, query))
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                match std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(v) => {
                        out.push(v);
                        i += 3;
                        continue;
                    }
                    None => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_query(q: Option<&str>) -> Vec<QueryParam> {
    let Some(q) = q else { return vec![] };
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (n, v) = match p.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (p, None),
            };
            QueryParam { raw_name: n.to_string(), raw_value: v.map(str::to_string), name: pct_decode(n), value: v.map(pct_decode), any: false }
        })
        .collect()
}

/// Parameters whose value the sanitizer changed match any value.
fn mark_replaced(orig: &[QueryParam], san: &mut [QueryParam]) {
    if orig.len() == san.len() && orig.iter().zip(san.iter()).all(|(o, s)| o.raw_name == s.raw_name) {
        for (o, s) in orig.iter().zip(san.iter_mut()) {
            s.any = o.raw_value != s.raw_value;
        }
    } else {
        for s in san.iter_mut() {
            s.any = orig.iter().find(|o| o.raw_name == s.raw_name).is_none_or(|o| o.raw_value != s.raw_value);
        }
    }
}

/// Case-insensitive name match with `*` as wildcard.
fn glob_matches(pat: &str, name: &str) -> bool {
    let (p, n) = (pat.to_ascii_lowercase(), name.to_ascii_lowercase());
    match p.split_once('*') {
        None => p == n,
        Some(_) => {
            let parts: Vec<&str> = p.split('*').collect();
            let mut rest = n.as_str();
            for (i, part) in parts.iter().enumerate() {
                if i == 0 {
                    let Some(r) = rest.strip_prefix(part) else { return false };
                    rest = r;
                } else if i == parts.len() - 1 {
                    return rest.ends_with(part);
                } else {
                    match rest.find(part) {
                        Some(at) => rest = &rest[at + part.len()..],
                        None => return false,
                    }
                }
            }
            true
        }
    }
}

fn host_matches(filter: &str, host: &str) -> bool {
    let f = filter.trim().trim_start_matches("*.").to_ascii_lowercase();
    let h = host.to_ascii_lowercase();
    let bare = quena_query::host_without_port(&h).to_string();
    !f.is_empty() && (h == f || bare == f || bare.ends_with(&format!(".{f}")))
}

/// Scripts, styles, images, fonts and media: by response type or file extension.
fn is_static(path: &str, content_type: &str) -> bool {
    let ct = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    if ct.starts_with("image/") || ct.starts_with("font/") || ct.starts_with("video/") || ct.starts_with("audio/") {
        return true;
    }
    if matches!(ct.as_str(), "text/css" | "application/javascript" | "text/javascript" | "application/x-javascript" | "application/font-woff" | "application/wasm") {
        return true;
    }
    let ext = path.rsplit('/').next().and_then(|f| f.rsplit_once('.')).map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    matches!(
        ext.as_str(),
        "js" | "mjs" | "css" | "map" | "png" | "jpg" | "jpeg" | "gif" | "svg" | "webp" | "avif" | "ico" | "woff" | "woff2" | "ttf" | "otf" | "eot" | "mp4" | "webm" | "mp3" | "wasm"
    )
}

/// Time to first byte in ms (at most a minute).
fn ttfb_ms(t: &Timers) -> u32 {
    let start = t.server_done_request.or(t.server_begin_request).or(t.client_done_request).or(t.client_begin_request);
    let first = t.server_got_first_byte.or(t.got_response_headers);
    match (start, first) {
        (Some(s), Some(f)) if f > s => ((f - s) / 1000).min(60_000) as u32,
        _ => 0,
    }
}

fn looks_like_json(ct: &str, body: &[u8]) -> bool {
    ct.contains("json") || (ct.is_empty() && body.iter().find(|b| !b.is_ascii_whitespace()).is_some_and(|b| *b == b'{' || *b == b'['))
}

fn body_match(ct: &str, orig: &[u8], san: &[u8]) -> BodyMatch {
    if san.is_empty() || san.len() > MAX_MATCH_BODY {
        return BodyMatch::None;
    }
    if looks_like_json(ct, san) {
        let Ok(s) = serde_json::from_slice::<Value>(san) else { return BodyMatch::None };
        let spec = match serde_json::from_slice::<Value>(orig) {
            Ok(o) => with_placeholders(&o, &s),
            Err(_) => s,
        };
        if let Some(op) = spec.get("operationName").and_then(|v| v.as_str()).filter(|o| !o.is_empty() && *o != JSON_IGNORE)
            && spec.get("query").is_some_and(|q| q.is_string())
        {
            return BodyMatch::GraphQl { operation_name: op.to_string(), variables: spec.get("variables").cloned().unwrap_or(Value::Null) };
        }
        return BodyMatch::Json { value: spec };
    }
    if ct.contains("x-www-form-urlencoded") {
        let (Ok(o), Ok(s)) = (std::str::from_utf8(orig), std::str::from_utf8(san)) else { return BodyMatch::None };
        let split = |x: &str| -> Vec<(String, Option<String>)> {
            x.split('&').filter(|p| !p.is_empty()).map(|p| p.split_once('=').map(|(n, v)| (n.to_string(), Some(v.to_string()))).unwrap_or((p.to_string(), None))).collect()
        };
        let (o, s) = (split(o), split(s));
        let same_shape = o.len() == s.len() && o.iter().zip(&s).all(|(a, b)| a.0 == b.0);
        let pairs = s
            .iter()
            .enumerate()
            .map(|(i, (n, v))| {
                let changed = if same_shape { o[i].1 != *v } else { o.iter().find(|x| x.0 == *n).is_none_or(|x| x.1 != *v) };
                (n.clone(), if changed { None } else { Some(v.clone().unwrap_or_default()) })
            })
            .collect();
        return BodyMatch::Form { pairs };
    }
    match std::str::from_utf8(san) {
        // Text the sanitizer changed cannot be matched exactly any more.
        Ok(t) if orig == san && !t.contains('\0') => BodyMatch::Text { text: t.to_string() },
        _ => BodyMatch::None,
    }
}

/// `san` with every value that differs from `orig` replaced by [`JSON_IGNORE`].
fn with_placeholders(orig: &Value, san: &Value) -> Value {
    if orig == san {
        return san.clone();
    }
    match (orig, san) {
        (Value::Object(o), Value::Object(s)) => Value::Object(s.iter().map(|(k, v)| (k.clone(), o.get(k).map(|ov| with_placeholders(ov, v)).unwrap_or_else(|| v.clone()))).collect()),
        (Value::Array(o), Value::Array(s)) if o.len() == s.len() => Value::Array(o.iter().zip(s).map(|(a, b)| with_placeholders(a, b)).collect()),
        _ => Value::String(JSON_IGNORE.into()),
    }
}

/// JSON with sorted keys (a stable grouping key).
fn canonical(v: &Value) -> String {
    fn walk(v: &Value, out: &mut String) {
        match v {
            Value::Object(m) => {
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort();
                out.push('{');
                for (i, k) in keys.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&Value::String((*k).clone()).to_string());
                    out.push(':');
                    walk(&m[*k], out);
                }
                out.push('}');
            }
            Value::Array(a) => {
                out.push('[');
                for (i, x) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    walk(x, out);
                }
                out.push(']');
            }
            Value::Number(n) => out.push_str(&n.as_f64().map(|f| f.to_string()).unwrap_or_else(|| n.to_string())),
            other => out.push_str(&other.to_string()),
        }
    }
    let mut s = String::new();
    walk(v, &mut s);
    s
}

fn body_key(b: &BodyMatch) -> String {
    match b {
        BodyMatch::None => String::new(),
        BodyMatch::Json { value } => format!("J{}", canonical(value)),
        BodyMatch::GraphQl { operation_name, variables } => format!("G{operation_name} {}", canonical(variables)),
        BodyMatch::Form { pairs } => format!("F{}", pairs.iter().map(|(n, v)| format!("{n}={}", v.as_deref().unwrap_or("\u{0}*"))).collect::<Vec<_>>().join("&")),
        BodyMatch::Text { text } => format!("T{text}"),
    }
}

// ------------------------------------------------------------------ Quena rules

/// A regex literal for the rules engine: escaped, control characters spelled out (the match
/// field is one line).
fn re_lit(s: &str) -> String {
    regex::escape(s).replace('\n', "\\n").replace('\r', "\\r").replace('\t', "\\t")
}

/// Regex (without `regex:`) for the entry's URL: path exactly, the kept parameters in recorded
/// order, ignored parameters anywhere with any value.
pub fn url_regex(e: &MockEntry) -> String {
    let base = re_lit(&format!("{}{}", e.origin, e.path));
    let ign = if e.ignored_params.is_empty() {
        None
    } else {
        let alts: Vec<String> = e.ignored_params.iter().map(|p| p.split('*').map(re_lit).collect::<Vec<_>>().join("[^=&]*")).collect();
        Some(format!("(?:(?i:{})(?:=[^&]*)?)", alts.join("|")))
    };
    let kept: Vec<String> = e
        .query
        .iter()
        .map(|q| match (&q.raw_value, q.any) {
            (_, true) => format!("{}(?:=[^&]*)?", re_lit(&q.raw_name)),
            (Some(v), false) => format!("{}={}", re_lit(&q.raw_name), re_lit(v)),
            (None, false) => re_lit(&q.raw_name),
        })
        .collect();
    let mut r = format!("^{base}");
    match (&ign, kept.is_empty()) {
        (None, true) => {}
        (Some(i), true) => r.push_str(&format!("(?:\\?(?:{i}(?:&{i})*)?)?")),
        (ign, false) => {
            r.push_str("\\?");
            if let Some(i) = ign {
                r.push_str(&format!("(?:{i}&)*"));
            }
            for (n, k) in kept.iter().enumerate() {
                if n > 0 {
                    r.push('&');
                }
                r.push_str(k);
                if let Some(i) = ign {
                    r.push_str(&format!("(?:&{i})*"));
                }
            }
        }
    }
    r.push('$');
    r
}

/// The Mock Rules match expression for an entry.
pub fn match_expression(e: &MockEntry) -> String {
    let url = if e.exact_url { format!("EXACT:{}", e.url) } else { format!("regex:{}", url_regex(e)) };
    let m = &e.method;
    match &e.body_match {
        BodyMatch::None => format!("METHOD:{m} {url}"),
        BodyMatch::Json { value } => format!("METHOD:{m} BODYJSON:{url} {value}"),
        BodyMatch::GraphQl { operation_name, variables } => format!("METHOD:{m} GRAPHQL:{url} {}", json!({ "operationName": operation_name, "variables": variables })),
        BodyMatch::Form { pairs } => {
            let parts: Vec<String> = pairs
                .iter()
                .map(|(n, v)| match v {
                    Some(v) => format!("{}={}", re_lit(n), re_lit(v)),
                    None => format!("{}=[^&]*", re_lit(n)),
                })
                .collect();
            format!("METHOD:{m} URLWithBody:{url} regex:(?s)^{}$", parts.join("&"))
        }
        BodyMatch::Text { text } => format!("METHOD:{m} URLWithBody:{url} regex:(?s)^{}$", re_lit(text)),
    }
}

/// The entry's response as a raw HTTP/1.1 message (what a `.dat` file action serves).
pub fn raw_response(e: &MockEntry) -> Vec<u8> {
    let mut h = Headers::new();
    for (n, v) in &e.headers {
        if !n.eq_ignore_ascii_case("content-length") {
            h.push(n.clone(), v.clone());
        }
    }
    h.push("Content-Length", e.body.len().to_string());
    let head = ResponseHead { status: e.status, reason: e.reason.clone(), version: HttpVersion::Http11, headers: h };
    let mut out = Vec::with_capacity(e.body.len() + 512);
    let _ = quena_formats::raw::write_response_head(&mut out, &head);
    out.extend_from_slice(&e.body);
    out
}

/// A short file-name part from a URL path.
fn slug(path: &str) -> String {
    let mut s = String::new();
    for c in path.chars() {
        if c.is_ascii_alphanumeric() {
            s.push(c);
        } else if !s.ends_with('-') {
            s.push('-');
        }
    }
    let s = s.trim_matches('-');
    let s: String = s.chars().take(40).collect();
    let s = s.trim_end_matches('-').to_string();
    if s.is_empty() { "root".into() } else { s }
}

fn method_slug(m: &str) -> String {
    m.chars().filter(|c| c.is_ascii_alphanumeric()).take(10).collect()
}

/// The rules of a package: actions are paths relative to the package folder
/// (`responses/0001-GET-api-items.dat`). Writes the response files through `out`.
fn package_rules(set: &MockSet, out: &mut dyn Out, opts_latency: bool) -> Result<AutoResponderState> {
    let mut rules = Vec::with_capacity(set.entries.len());
    for (i, e) in set.entries.iter().enumerate() {
        let file = format!("responses/{:04}-{}-{}.dat", i + 1, method_slug(&e.method), slug(&e.path));
        out.put(&file, &raw_response(e))?;
        let last = e.sequence.is_none_or(|s| s.index + 1 == s.len);
        rules.push(Rule {
            id: 0,
            enabled: true,
            match_: match_expression(e),
            action: file,
            latency_ms: e.delay_ms,
            match_once: !last,
            comment: format!("#{} {} {}", e.session, e.method, e.path),
            hits: 0,
        });
    }
    Ok(AutoResponderState { enabled: true, unmatched_passthrough: true, enable_latency: opts_latency && set.entries.iter().any(|e| e.delay_ms > 0), rules })
}

fn package_readme(set: &MockSet) -> String {
    let mut s = String::from("Quena mock package\r\n==================\r\n\r\n");
    s.push_str("Recorded responses as Quena Mock Rules. Import: Mock Rules tab -> Import package...\r\n");
    s.push_str("(or drop the .quena-mocks file onto the Mock Rules tab).\r\n\r\n");
    s.push_str(&format!("Mappings: {}\r\nSequences: {}\r\nHosts: {}\r\n\r\n", set.entries.len(), set.sequences(), set.hosts.join(", ")));
    s.push_str("Contents\r\n  rules.json      the rules (match expression -> response file)\r\n  responses/*.dat raw HTTP responses (status line, headers, body)\r\n");
    s
}

// ------------------------------------------------------------------ output

/// Where files go: a folder or a ZIP.
pub trait Out {
    fn put(&mut self, path: &str, data: &[u8]) -> Result<()>;
}

pub struct DirOut(pub PathBuf);
impl Out for DirOut {
    fn put(&mut self, path: &str, data: &[u8]) -> Result<()> {
        let p = self.0.join(path);
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        std::fs::write(&p, data).with_context(|| format!("write {}", p.display()))
    }
}

pub struct ZipOut(zip::ZipWriter<std::fs::File>);
impl ZipOut {
    pub fn create(path: &Path) -> Result<ZipOut> {
        Ok(ZipOut(zip::ZipWriter::new(std::fs::File::create(path).with_context(|| format!("create {}", path.display()))?)))
    }
    pub fn finish(self) -> Result<()> {
        self.0.finish()?;
        Ok(())
    }
}
impl Out for ZipOut {
    fn put(&mut self, path: &str, data: &[u8]) -> Result<()> {
        let o = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated).large_file(data.len() as u64 >= u32::MAX as u64);
        self.0.start_file(path, o)?;
        self.0.write_all(data)?;
        Ok(())
    }
}

/// Write a Quena mock package (ZIP, usually `.quena-mocks`).
pub fn write_package(set: &MockSet, path: &Path, opts: &MockOptions) -> Result<()> {
    let r = (|| {
        let mut z = ZipOut::create(path)?;
        let state = package_rules(set, &mut z, opts.latency)?;
        z.put("rules.json", &serde_json::to_vec_pretty(&state)?)?;
        z.put("README.txt", package_readme(set).as_bytes())?;
        z.finish()
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(path);
    }
    r
}

/// Write a WireMock root (`mappings/`, `__files/`, `README.md`): a folder, or a ZIP when
/// `path` ends in `.zip`.
pub fn write_wiremock(set: &MockSet, path: &Path) -> Result<()> {
    let files = wiremock_files(set);
    if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("zip")) {
        let r = (|| {
            let mut z = ZipOut::create(path)?;
            for (n, d) in &files {
                z.put(n, d)?;
            }
            z.finish()
        })();
        if r.is_err() {
            let _ = std::fs::remove_file(path);
        }
        r
    } else {
        let mut d = DirOut(path.to_path_buf());
        for (n, data) in &files {
            d.put(n, data)?;
        }
        Ok(())
    }
}

fn file_ext(ct: &str) -> &'static str {
    let ct = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    match ct.as_str() {
        c if c.contains("json") => "json",
        "text/html" => "html",
        c if c.contains("xml") && c != "image/svg+xml" => "xml",
        "image/svg+xml" => "svg",
        c if c.contains("javascript") => "js",
        "text/css" => "css",
        "text/csv" => "csv",
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "font/woff2" => "woff2",
        "font/woff" => "woff",
        "application/pdf" => "pdf",
        c if c.starts_with("text/") => "txt",
        _ => "bin",
    }
}

/// The WireMock mapping of an entry (`n`: number in the export, from 1). `multi_host`: add a
/// Host header matcher.
pub fn wiremock_mapping(e: &MockEntry, n: usize, body_file: Option<&str>, multi_host: bool) -> Value {
    let mut req = serde_json::Map::new();
    req.insert("method".into(), json!(e.method));
    let has_query = !e.query.is_empty();
    if e.exact_url {
        let q = e.url.split_once('?').map(|(_, q)| format!("?{}", q.split('#').next().unwrap_or(""))).unwrap_or_default();
        req.insert("url".into(), json!(format!("{}{q}", e.path)));
    } else {
        req.insert("urlPath".into(), json!(e.path));
        let mut qp = serde_json::Map::new();
        let mut by_name: Vec<(String, Vec<&QueryParam>)> = Vec::new();
        for q in &e.query {
            match by_name.iter_mut().find(|(n, _)| *n == q.name) {
                Some((_, v)) => v.push(q),
                None => by_name.push((q.name.clone(), vec![q])),
            }
        }
        for (name, vals) in by_name {
            let pat = |q: &QueryParam| if q.any { json!({ "matches": ".*" }) } else { json!({ "equalTo": q.value.clone().unwrap_or_default() }) };
            let m = if vals.len() == 1 { pat(vals[0]) } else { json!({ "hasExactly": vals.iter().map(|q| pat(q)).collect::<Vec<_>>() }) };
            qp.insert(name, m);
        }
        if !qp.is_empty() {
            req.insert("queryParameters".into(), Value::Object(qp));
        }
    }
    if multi_host {
        req.insert("headers".into(), json!({ "Host": { "equalTo": e.host, "caseInsensitive": true } }));
    }
    let patterns: Vec<Value> = match &e.body_match {
        BodyMatch::None => vec![],
        BodyMatch::Json { value } => vec![json!({ "equalToJson": value, "ignoreArrayOrder": false, "ignoreExtraElements": false })],
        BodyMatch::GraphQl { operation_name, variables } => {
            let mut v = vec![json!({ "matchesJsonPath": { "expression": "$.operationName", "equalTo": operation_name } })];
            if !(variables.is_null() || variables.as_object().is_some_and(|o| o.is_empty())) {
                v.push(json!({ "matchesJsonPath": { "expression": "$.variables", "equalToJson": variables.to_string() } }));
            }
            v
        }
        BodyMatch::Form { pairs } => {
            if pairs.iter().all(|(_, v)| v.is_some()) {
                vec![json!({ "equalTo": pairs.iter().map(|(n, v)| format!("{n}={}", v.as_deref().unwrap_or(""))).collect::<Vec<_>>().join("&") })]
            } else {
                let re: Vec<String> = pairs.iter().map(|(n, v)| format!("{}={}", regex::escape(n), v.as_deref().map(regex::escape).unwrap_or_else(|| "[^&]*".into()))).collect();
                vec![json!({ "matches": format!("(?s)^{}$", re.join("&")) })]
            }
        }
        BodyMatch::Text { text } => vec![json!({ "equalTo": text })],
    };
    let body_match = !patterns.is_empty();
    if body_match {
        req.insert("bodyPatterns".into(), Value::Array(patterns));
    }
    let mut headers = serde_json::Map::new();
    for (name, v) in &e.headers {
        match headers.get_mut(name) {
            Some(Value::Array(a)) => a.push(json!(v)),
            Some(prev) => *prev = json!([prev.clone(), v]),
            None => {
                headers.insert(name.clone(), json!(v));
            }
        }
    }
    let mut resp = serde_json::Map::new();
    resp.insert("status".into(), json!(e.status));
    if !headers.is_empty() {
        resp.insert("headers".into(), Value::Object(headers));
    }
    if let Some(f) = body_file {
        resp.insert("bodyFileName".into(), json!(f));
    }
    if e.delay_ms > 0 {
        resp.insert("fixedDelayMilliseconds".into(), json!(e.delay_ms));
    }
    let priority = if body_match {
        1
    } else if has_query || e.url.contains('?') {
        2
    } else {
        3
    };
    let mut m = serde_json::Map::new();
    m.insert("name".into(), json!(format!("{n:04} {} {}", e.method, e.path)));
    m.insert("priority".into(), json!(priority));
    m.insert("request".into(), Value::Object(req));
    m.insert("response".into(), Value::Object(resp));
    if let Some(s) = e.sequence {
        m.insert("scenarioName".into(), json!(format!("sequence-{:03} {} {}", s.group, e.method, e.path)));
        m.insert("requiredScenarioState".into(), json!(if s.index == 0 { "Started".to_string() } else { format!("step-{}", s.index + 1) }));
        if s.index + 1 < s.len {
            m.insert("newScenarioState".into(), json!(format!("step-{}", s.index + 2)));
        }
    }
    Value::Object(m)
}

/// All files of a WireMock export (path, bytes).
pub fn wiremock_files(set: &MockSet) -> Vec<(String, Vec<u8>)> {
    let multi = set.hosts.len() > 1;
    let mut out = Vec::new();
    for (i, e) in set.entries.iter().enumerate() {
        let n = i + 1;
        let body_file = (!e.body.is_empty()).then(|| format!("{n:04}.{}", file_ext(&e.content_type)));
        if let Some(f) = &body_file {
            out.push((format!("__files/{f}"), e.body.clone()));
        }
        let m = wiremock_mapping(e, n, body_file.as_deref(), multi);
        out.push((format!("mappings/{n:04}-{}-{}.json", method_slug(&e.method), slug(&e.path)), serde_json::to_vec_pretty(&m).unwrap_or_default()));
    }
    out.push(("README.md".into(), wiremock_readme(set).into_bytes()));
    out
}

fn wiremock_readme(set: &MockSet) -> String {
    let mut s = String::from("# WireMock mocks from Quena\n\n");
    s.push_str(&format!("{} mappings, {} sequences (scenarios), hosts: {}.\n\n", set.entries.len(), set.sequences(), set.hosts.join(", ")));
    s.push_str("## Run\n\n```sh\ndocker run --rm -v \"$PWD:/home/wiremock\" -p 8080:8080 wiremock/wiremock\n```\n\n");
    s.push_str("Or with the standalone JAR: `java -jar wiremock-standalone.jar --root-dir .`\n\n");
    s.push_str("Then point the frontend at `http://localhost:8080` instead of the real backend, e.g. the API base URL, or a dev-server proxy (Vite `server.proxy`, webpack `devServer.proxy`).\n\n");
    if set.hosts.len() > 1 {
        s.push_str("## Several hosts\n\nThe recording spans several hosts, so every mapping also matches the `Host` header. Requests must arrive with the original host name, for example:\n\n");
        s.push_str("- a dev-server proxy that keeps the Host header (Vite: `changeOrigin: false`), or\n");
        s.push_str("- WireMock as forward proxy for plain HTTP (`--enable-browser-proxying`), or\n");
        s.push_str("- export one host at a time (host filter in Quena's Mocks dialog) and run one WireMock per host.\n\n");
    }
    s.push_str("Sequences use scenarios: the responses come in recorded order, the last one repeats. Reset them with `POST /__admin/scenarios/reset`.\n");
    s
}

// ------------------------------------------------------------------ packages

/// An installed mock package (folder `<data>/mocks/<name>/`).
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MockPackage {
    pub name: String,
    pub dir: String,
    /// Rules of this package in Mock Rules.
    pub rules: usize,
    /// Rules of the package file that were not taken over (unsafe or invalid).
    pub rejected: usize,
    /// Unix time in ms.
    pub created: Option<i64>,
}

/// The comment that marks the rules of a package.
pub fn package_tag(name: &str) -> String {
    format!("pkg:{name}")
}

/// A safe package (folder) name: letters, digits, `.`, `_`, `-`; at most 64 characters.
pub fn sanitize_name(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let t: String = out.trim_matches(['-', '.']).chars().take(64).collect();
    let t = t.trim_matches(['-', '.']).to_string();
    if t.is_empty() { "mocks".into() } else { t }
}

fn safe_file_name(f: &str) -> bool {
    !f.is_empty() && f.len() <= 128 && !f.starts_with('.') && f.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Largest package accepted (all files uncompressed) and the most entries.
const MAX_PACKAGE_BYTES: u64 = 4 << 30;
const MAX_PACKAGE_FILES: usize = 100_000;

/// Unpack a package into `dest` (created, must not exist). Only `rules.json`, `README.txt`
/// and `responses/<file>` are taken; no path can leave `dest` (zip-slip), sizes are bounded.
pub fn extract_package(zip_path: &Path, dest: &Path) -> Result<AutoResponderState> {
    let f = std::fs::File::open(zip_path).with_context(|| format!("open {}", zip_path.display()))?;
    let mut z = zip::ZipArchive::new(std::io::BufReader::new(f)).map_err(|e| anyhow!("{}: not a mock package ({e})", zip_path.display()))?;
    if z.len() > MAX_PACKAGE_FILES {
        bail!("mock package has too many files ({})", z.len());
    }
    std::fs::create_dir_all(dest.join("responses"))?;
    let mut total = 0u64;
    let mut rules_json: Option<Vec<u8>> = None;
    for i in 0..z.len() {
        let mut entry = z.by_index(i)?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().replace('\\', "/");
        let target = if name == "rules.json" || name == "README.txt" {
            dest.join(&name)
        } else if let Some(f) = name.strip_prefix("responses/").filter(|f| safe_file_name(f)) {
            dest.join("responses").join(f)
        } else {
            tracing::warn!(target: "quena", "mock package: skipped {name:?}");
            continue;
        };
        let left = MAX_PACKAGE_BYTES - total;
        let mut data = Vec::new();
        entry.by_ref().take(left + 1).read_to_end(&mut data)?;
        total += data.len() as u64;
        if total > MAX_PACKAGE_BYTES {
            bail!("mock package is larger than {} GiB", MAX_PACKAGE_BYTES >> 30);
        }
        if name == "rules.json" {
            rules_json = Some(data.clone());
        }
        std::fs::write(&target, &data)?;
    }
    let raw = rules_json.ok_or_else(|| anyhow!("{}: no rules.json, not a mock package", zip_path.display()))?;
    serde_json::from_slice(&raw).map_err(|e| anyhow!("rules.json: {e}"))
}

/// The package's rules with absolute file actions and the package tag. Rules with another
/// action than a response file of the package or a simple status/delay/drop are left out
/// (a package must not map remote hosts or local folders); also rules that do not compile.
pub fn resolve_package_rules(state: &AutoResponderState, dir: &Path, name: &str) -> (Vec<Rule>, usize) {
    let mut out = Vec::new();
    let mut rejected = 0;
    for r in &state.rules {
        let Some(action) = package_action(&r.action, dir) else {
            rejected += 1;
            continue;
        };
        if crate::rules::validate_match(&r.match_).is_err() {
            rejected += 1;
            continue;
        }
        out.push(Rule { id: 0, enabled: r.enabled, match_: r.match_.clone(), action, latency_ms: r.latency_ms, match_once: r.match_once, comment: package_tag(name), hits: 0 });
    }
    (out, rejected)
}

fn package_action(a: &str, dir: &Path) -> Option<String> {
    let t = a.trim();
    if let Some(f) = t.strip_prefix("responses/") {
        let p = dir.join("responses").join(f);
        return (safe_file_name(f) && p.is_file()).then(|| p.to_string_lossy().into_owned());
    }
    let l = t.to_ascii_lowercase();
    let r = l.strip_prefix('*')?;
    let ok = r.parse::<u16>().is_ok()
        || matches!(r, "drop" | "reset" | "corspreflightallow")
        || r.strip_prefix("delay:").is_some_and(|d| d.trim().parse::<u64>().is_ok());
    ok.then(|| t.to_string())
}

/// Put package rules into Mock Rules: an earlier import of the same package is replaced; with
/// `replace` all other rules go too. The package rules come first (they are specific).
pub fn install_rules(rules: &Rules, name: &str, new_rules: Vec<Rule>, replace: bool, enable_latency: bool) -> Result<usize> {
    let mut s = rules.autoresponder();
    let tag = package_tag(name);
    if replace {
        s.rules.clear();
    } else {
        s.rules.retain(|r| r.comment != tag);
    }
    let n = new_rules.len();
    s.rules.splice(0..0, new_rules);
    s.enabled = true;
    s.enable_latency |= enable_latency;
    rules.set_autoresponder(s, true)?;
    Ok(n)
}

fn unix_ms(t: std::time::SystemTime) -> Option<i64> {
    t.duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_millis() as i64)
}

// ------------------------------------------------------------------ AppCore

struct JobProgress<'a>(&'a JobCtx);
impl Progress for JobProgress<'_> {
    fn cancelled(&self) -> bool {
        self.0.cancelled()
    }
    fn progress(&self, done: u64, total: u64) {
        self.0.progress(done, total)
    }
}

/// Event `mocks` when a mock job finished.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MockJobResult {
    pub job: JobId,
    /// `wiremock`, `package` or `apply`.
    pub target: String,
    /// File or folder written, or the package folder.
    pub path: String,
    /// Package name (`apply`).
    pub name: Option<String>,
    pub mappings: usize,
    pub sequences: usize,
    pub skipped: usize,
}

impl AppCore {
    fn mocks_dir(&self) -> PathBuf {
        self.paths.data.join("mocks")
    }

    /// The sessions to use: `ids` sorted (recorded order), or all visible ones.
    fn mock_ids(&self, mut ids: Vec<SessionId>) -> Vec<SessionId> {
        if ids.is_empty() {
            ids = self.capture().index.find(|_| true);
        }
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// Counts for the Mocks dialog (cheap: no response bodies, no sanitizing).
    pub fn mock_preview(&self, ids: Vec<SessionId>, opts: MockOptions) -> Result<MockPreview> {
        let ids = self.mock_ids(ids);
        let set = generate(&self.capture(), &ids, &opts, false, &quena_formats::NoProgress)?;
        Ok(MockPreview::of(&set))
    }

    fn mock_job(self: &Arc<Self>, ids: Vec<SessionId>, opts: MockOptions, target: &'static str, path: PathBuf, title: String, name: Option<String>) -> JobId {
        let ids = self.mock_ids(ids);
        let cap = self.capture();
        let core = Arc::downgrade(self);
        self.jobs.submit(format!("mocks:{target}:{}", path.display()), title, Priority::Background, true, move |ctx| {
            let set = generate(&cap, &ids, &opts, true, &JobProgress(ctx)).map_err(|e| e.to_string())?;
            let core = core.upgrade().ok_or("shutting down")?;
            match target {
                "wiremock" => write_wiremock(&set, &path).map_err(|e| e.to_string())?,
                "package" => write_package(&set, &path, &opts).map_err(|e| e.to_string())?,
                _ => {
                    let name = name.clone().unwrap_or_default();
                    core.install_generated(&set, &opts, &name).map_err(|e| e.to_string())?;
                }
            }
            tracing::info!(target: "quena", "mocks ({target}): {} mapping(s) from {} session(s) to {}", set.entries.len(), set.sessions, path.display());
            core.emit(
                "mocks",
                MockJobResult {
                    job: ctx.id(),
                    target: target.into(),
                    path: path.display().to_string(),
                    name: name.clone(),
                    mappings: set.entries.len(),
                    sequences: set.sequences(),
                    skipped: set.skipped.len(),
                },
            );
            Ok(())
        })
    }

    /// Write a WireMock export (folder, or ZIP for `*.zip`) as a job.
    pub fn mock_export_wiremock(self: &Arc<Self>, ids: Vec<SessionId>, path: PathBuf, opts: MockOptions) -> Result<JobId> {
        let title = format!("Writing WireMock mocks to {}", path.display());
        Ok(self.mock_job(ids, opts, "wiremock", path, title, None))
    }

    /// Write a Quena mock package (`.quena-mocks`) as a job.
    pub fn mock_export_package(self: &Arc<Self>, ids: Vec<SessionId>, path: PathBuf, opts: MockOptions) -> Result<JobId> {
        let title = format!("Writing mock package {}", path.display());
        Ok(self.mock_job(ids, opts, "package", path, title, None))
    }

    /// Create mock rules from sessions right away: the package is written to
    /// `<data>/mocks/<name>/` and installed (an earlier package of that name is replaced).
    /// An empty name picks `sessions-<date>-<time>`.
    pub fn mock_apply(self: &Arc<Self>, ids: Vec<SessionId>, opts: MockOptions, name: String) -> Result<JobId> {
        if self.rules.is_none() {
            bail!("mock rules unavailable");
        }
        let name = if name.trim().is_empty() {
            let t = time::OffsetDateTime::now_utc();
            format!("sessions-{:04}{:02}{:02}-{:02}{:02}{:02}", t.year(), t.month() as u8, t.day(), t.hour(), t.minute(), t.second())
        } else {
            sanitize_name(&name)
        };
        let dir = self.mocks_dir().join(&name);
        let title = format!("Creating mock rules '{name}'");
        Ok(self.mock_job(ids, opts, "apply", dir, title, Some(name)))
    }

    fn install_generated(&self, set: &MockSet, opts: &MockOptions, name: &str) -> Result<()> {
        let rules = self.rules.as_ref().ok_or_else(|| anyhow!("mock rules unavailable"))?;
        let root = self.mocks_dir();
        std::fs::create_dir_all(&root)?;
        let tmp = root.join(format!(".new-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let state = (|| {
            let mut out = DirOut(tmp.clone());
            let state = package_rules(set, &mut out, opts.latency)?;
            out.put("rules.json", &serde_json::to_vec_pretty(&state)?)?;
            out.put("README.txt", package_readme(set).as_bytes())?;
            Ok::<_, anyhow::Error>(state)
        })();
        let state = match state {
            Ok(s) => s,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&tmp);
                return Err(e);
            }
        };
        let dir = root.join(name);
        self.swap_in(&tmp, &dir)?;
        let (new_rules, _) = resolve_package_rules(&state, &dir, name);
        install_rules(rules, name, new_rules, false, state.enable_latency)?;
        Ok(())
    }

    /// Replace `dir` by the freshly written `tmp`.
    fn swap_in(&self, tmp: &Path, dir: &Path) -> Result<()> {
        if dir.exists() {
            std::fs::remove_dir_all(dir).with_context(|| format!("remove {}", dir.display()))?;
        }
        std::fs::rename(tmp, dir).with_context(|| format!("move to {}", dir.display()))?;
        Ok(())
    }

    /// Import a `.quena-mocks` package: unpacked to `<data>/mocks/<name>/` (name from the file
    /// name), rules tagged `pkg:<name>` on top of Mock Rules. `replace`: remove all other rules.
    pub fn mock_import_package(&self, path: PathBuf, replace: bool) -> Result<MockPackage> {
        let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        self.import_package_as(&path, &sanitize_name(&stem), replace)
    }

    /// Import a package from bytes (dropped onto the Mock Rules tab).
    pub fn mock_import_package_bytes(&self, file_name: &str, data: &[u8], replace: bool) -> Result<MockPackage> {
        let root = self.mocks_dir();
        std::fs::create_dir_all(&root)?;
        let tmp = root.join(format!(".incoming-{}-{}.zip", std::process::id(), rand::random::<u32>()));
        std::fs::write(&tmp, data)?;
        let stem = Path::new(file_name).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let r = self.import_package_as(&tmp, &sanitize_name(&stem), replace);
        let _ = std::fs::remove_file(&tmp);
        r
    }

    fn import_package_as(&self, path: &Path, name: &str, replace: bool) -> Result<MockPackage> {
        let rules = self.rules.as_ref().ok_or_else(|| anyhow!("mock rules unavailable"))?;
        let root = self.mocks_dir();
        std::fs::create_dir_all(&root)?;
        let tmp = root.join(format!(".import-{name}-{}-{}", std::process::id(), rand::random::<u32>()));
        let state = match extract_package(path, &tmp) {
            Ok(s) => s,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&tmp);
                return Err(e);
            }
        };
        let dir = root.join(name);
        if let Err(e) = self.swap_in(&tmp, &dir) {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(e);
        }
        let (new_rules, rejected) = resolve_package_rules(&state, &dir, name);
        let n = install_rules(rules, name, new_rules, replace, state.enable_latency)?;
        tracing::info!(target: "quena", "mock package {name}: {n} rule(s) imported, {rejected} left out");
        Ok(MockPackage { name: name.into(), dir: dir.display().to_string(), rules: n, rejected, created: std::fs::metadata(&dir).and_then(|m| m.modified()).ok().and_then(unix_ms) })
    }

    /// Remove a package: its rules and its folder. Returns the number of rules removed.
    pub fn mock_remove_package(&self, name: &str) -> Result<usize> {
        if name.is_empty() || sanitize_name(name) != name {
            bail!("invalid package name {name:?}");
        }
        let rules = self.rules.as_ref().ok_or_else(|| anyhow!("mock rules unavailable"))?;
        let tag = package_tag(name);
        let mut s = rules.autoresponder();
        let before = s.rules.len();
        s.rules.retain(|r| r.comment != tag);
        let n = before - s.rules.len();
        rules.set_autoresponder(s, true)?;
        let dir = self.mocks_dir().join(name);
        if dir.exists() {
            std::fs::remove_dir_all(&dir).with_context(|| format!("remove {}", dir.display()))?;
        }
        Ok(n)
    }

    /// Installed packages (folders in `<data>/mocks/`) with their rule counts.
    pub fn mock_packages(&self) -> Vec<MockPackage> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        if let Some(r) = &self.rules {
            for rule in r.autoresponder().rules {
                if let Some(n) = rule.comment.strip_prefix("pkg:") {
                    *counts.entry(n.to_string()).or_insert(0) += 1;
                }
            }
        }
        let mut out: Vec<MockPackage> = std::fs::read_dir(self.mocks_dir())
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                (!name.starts_with('.')).then(|| MockPackage {
                    rules: counts.get(&name).copied().unwrap_or(0),
                    dir: e.path().display().to_string(),
                    created: e.metadata().and_then(|m| m.modified()).ok().and_then(unix_ms),
                    rejected: 0,
                    name,
                })
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(url: &str) -> MockEntry {
        let (origin, path, query) = split_full_url(url).unwrap();
        MockEntry {
            session: 1,
            method: "GET".into(),
            url: url.into(),
            host: origin.split_once("://").unwrap().1.into(),
            origin,
            path,
            query: parse_query(query.as_deref()),
            ignored_params: vec![],
            exact_url: true,
            body_match: BodyMatch::None,
            status: 200,
            reason: "OK".into(),
            headers: vec![],
            body: vec![],
            content_type: String::new(),
            delay_ms: 0,
            sequence: None,
        }
    }

    #[test]
    fn url_regex_ignores_params_anywhere() {
        let mut e = entry("https://api.x.de/items?page=2&_=1700000&utm_source=mail");
        e.ignored_params = DEFAULT_IGNORED_PARAMS.iter().map(|s| s.to_string()).collect();
        e.query.retain(|q| !e.ignored_params.iter().any(|p| glob_matches(p, &q.name)));
        e.exact_url = false;
        let re = regex::Regex::new(&url_regex(&e)).unwrap();
        for (u, want) in [
            ("https://api.x.de/items?page=2", true),
            ("https://api.x.de/items?_=99&page=2", true),
            ("https://api.x.de/items?page=2&_=5&UTM_campaign=x&t", true),
            ("https://api.x.de/items?page=3", false),
            ("https://api.x.de/items", false),
            ("https://api.x.de/items?page=2&other=1", false),
            ("https://api.x.de/itemsX?page=2", false),
        ] {
            assert_eq!(re.is_match(u), want, "{u}");
        }
        let mut e = entry("https://api.x.de/a.b");
        e.ignored_params = vec!["_".into()];
        e.exact_url = false;
        let re = regex::Regex::new(&url_regex(&e)).unwrap();
        assert!(re.is_match("https://api.x.de/a.b") && re.is_match("https://api.x.de/a.b?_=1") && !re.is_match("https://api.x.de/aXb"));
    }

    #[test]
    fn options_from_json() {
        let o: MockOptions = serde_json::from_str(r#"{"sanitize":"gdpr","repeats":"sequence"}"#).unwrap();
        assert_eq!(o.sanitize, SanitizeOptions::preset("gdpr"));
        assert_eq!((o.repeats, o.query, o.match_body), (Repeats::Sequence, QueryMatch::Ignore, true));
        let o: MockOptions = serde_json::from_str(r#"{"sanitize":null}"#).unwrap();
        assert!(o.sanitize.is_none());
        let o: MockOptions = serde_json::from_str("{}").unwrap();
        assert_eq!(o, MockOptions::default());
        assert!(serde_json::from_str::<MockOptions>(r#"{"sanitize":"nope"}"#).is_err());
        let full = serde_json::to_value(SanitizeOptions::default()).unwrap();
        let o: MockOptions = serde_json::from_value(json!({ "sanitize": full })).unwrap();
        assert_eq!(o.sanitize, Some(SanitizeOptions::default()));
    }

    #[test]
    fn helpers() {
        assert!(glob_matches("utm_*", "UTM_Source") && !glob_matches("utm_*", "xutm_") && glob_matches("a*b*c", "aXXbYc"));
        assert!(host_matches("example.com", "api.example.com:8443") && !host_matches("example.com", "badexample.com"));
        assert_eq!(sanitize_name("../../etc/passwd"), "etc-passwd");
        assert_eq!(sanitize_name("Mein Paket (2)"), "Mein-Paket-2");
        assert_eq!(sanitize_name("..."), "mocks");
        assert_eq!(slug("/api/v1/items/"), "api-v1-items");
        assert_eq!(pct_decode("a%20b+c%zz"), "a b c%zz");
        assert!(is_static("/app.js", "") && is_static("/x", "image/png") && !is_static("/api/items", "application/json"));
        let o: Value = serde_json::from_str(r#"{"user":"a","password":"secret","n":[1,2]}"#).unwrap();
        let s: Value = serde_json::from_str(r#"{"user":"a","password":"<redacted>","n":[1,2]}"#).unwrap();
        assert_eq!(with_placeholders(&o, &s), json!({"user":"a","password":JSON_IGNORE,"n":[1,2]}));
        assert_eq!(canonical(&json!({"b":1,"a":[1.0,{"d":2,"c":3}]})), r#"{"a":[1,{"c":3,"d":2}],"b":1}"#);
    }
}
