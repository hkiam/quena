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
//! first ([`crate::sanitize`], bodies always kept whole: [`SanitizeOptions::for_mocks`]);
//! values the sanitizer replaced in the request (query parameters, path segments, body
//! fields) are matched as "any value", so the mock still answers the real client.

use crate::AppCore;
use crate::rules::{AutoResponderState, JSON_IGNORE, Rule, Rules, graphql_query_hash, sha256_hex};
use crate::sanitize::{SanitizeOptions, Sanitizer, decoded_body};
use anyhow::{Context, Result, anyhow, bail};
use quena_body::Body;
use quena_formats::Progress;
use quena_jobs::{JobCtx, JobId, Priority};
use quena_model::*;
use quena_store::Capture;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

// ------------------------------------------------------------------ options

/// How the query string of a request is matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, Hash)]
#[serde(rename_all = "camelCase")]
pub enum QueryMatch {
    /// The whole URL as recorded.
    Exact,
    /// The parameters in [`MockOptions::ignore_params`] may have any value or be missing.
    #[default]
    Ignore,
}

/// What happens with several recordings of the same request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, Hash)]
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
    /// a preset name (`"credentials"`, `"support"`, `"gdpr"`). Bodies are always kept whole
    /// ([`SanitizeOptions::for_mocks`]): a mock response must stay a valid response.
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
    /// The decoded response body is larger than [`MAX_RESPONSE_BODY`].
    TooLarge,
    /// Sanitizing: the response body could not be decoded (a placeholder would be served).
    Undecodable,
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
    /// By operation name (empty: none sent) and variables; with `query` also by the query
    /// text (normalized: formatting does not matter). The query is matched when the request
    /// has no operation name, or when two recorded queries share name and variables.
    GraphQl {
        operation_name: String,
        variables: Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        query: Option<String>,
    },
    /// `application/x-www-form-urlencoded` pairs as sent (raw); `None` matches any value.
    Form { pairs: Vec<(String, Option<String>)> },
    /// Exactly this text (above [`MAX_REGEX_BODY`] matched by SHA-256, `BODYHASH:`).
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
    /// `scheme://host[:port]` (without user info)
    pub origin: String,
    /// `host[:port]`
    pub host: String,
    /// The path as written (sanitized when sanitizing).
    pub path: String,
    /// The path as regular expression when the sanitizer replaced segments of it (those
    /// match any value, `[^/]*`); `None`: the path matches exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_regex: Option<String>,
    /// The parameters that must be present (in recorded order), without the ignored ones.
    pub query: Vec<QueryParam>,
    /// Parameter patterns that may additionally appear with any value.
    pub ignored_params: Vec<String>,
    /// The whole URL matches exactly (no ignored or replaced parameters, path unchanged; the
    /// same for every entry of a sequence).
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
    /// In rule order: specific matchers first ([`specificity`]), sequences in recorded order.
    pub entries: Vec<MockEntry>,
    pub skipped: Vec<Skipped>,
    /// Sessions examined.
    pub sessions: usize,
    /// Hosts of the entries (sorted).
    pub hosts: Vec<String>,
    /// Recorded response headers left out because their name or value is not valid HTTP
    /// (CR, LF or NUL in the value, no token as name).
    pub dropped_headers: usize,
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

/// Request bodies above this size (decoded) are not matched.
const MAX_MATCH_BODY: usize = 1 << 20;
/// The preview decodes request bodies up to this size only.
const PREVIEW_MATCH_BODY: usize = 64 << 10;
/// Form and text bodies above this size are matched by hash, not by regular expression
/// (a regex that large would exceed the regex size limit).
pub const MAX_REGEX_BODY: usize = 64 << 10;
/// Larger (decoded) responses are left out ([`SkipReason::TooLarge`]).
pub const MAX_RESPONSE_BODY: usize = crate::sanitize::MAX_DECODED;
/// Latency of a rule from a package at most (ms).
pub const MAX_PACKAGE_LATENCY_MS: u32 = 60_000;
/// Responses up to this size are compared in the preview to find repeated responses.
const PREVIEW_COMPARE_BODY: u64 = 64 << 10;

/// Response headers never written into a mock (the body is served decoded and complete).
const DROP_RESPONSE_HEADERS: [&str; 10] =
    ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "trailer", "upgrade", "content-length", "alt-svc", "content-encoding"];

struct Cand {
    entry: MockEntry,
    /// Method, origin, path (or its pattern) and the matched parameters.
    url_key: String,
    /// GraphQL: the query as recorded (matched only when needed, see [`BodyMatch::GraphQl`]).
    gql_query: Option<String>,
    /// Preview: a fingerprint of the stored response (status, encoding, bytes).
    fingerprint: Option<u64>,
}

impl Cand {
    fn key(&self) -> String {
        format!("{} #{}", self.url_key, body_key(&self.entry.body_match))
    }
}

/// HTTP token characters (header names, methods).
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// A header that can be written as is: token name, no CR, LF or NUL in the value.
pub fn valid_header(name: &str, value: &str) -> bool {
    !name.is_empty() && name.bytes().all(is_tchar) && !value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

/// A status reason without control characters (the standard one when nothing is left).
fn clean_reason(reason: &str, status: u16) -> String {
    let r: String = reason.chars().filter(|c| !c.is_control()).collect();
    let r = r.trim();
    if r.is_empty() { crate::mock::reason(status).to_string() } else { r.to_string() }
}

/// No body and no Content-Length (1xx, 204, 304).
fn bodiless_status(status: u16) -> bool {
    status == 204 || status == 304 || (100..200).contains(&status)
}

/// How specific an entry's matcher is; lower is more specific. Quena rules are ordered by it
/// (first match wins) and it is the WireMock priority (1 = highest), so a broader matcher
/// never shadows a narrower one: with body matcher before without; within that the exact
/// URL, then path with parameters (more parameters first), the bare path, and last the path
/// patterns (sanitized segments).
pub fn specificity(e: &MockEntry) -> u32 {
    let n = e.query.len().min(19) as u32;
    let url = match (&e.path_regex, e.exact_url, e.query.is_empty()) {
        (None, true, _) => 0,
        (None, false, false) => 1 + (19 - n),
        (None, false, true) => 30,
        (Some(_), _, false) => 40 + (19 - n),
        (Some(_), _, true) => 70,
    };
    1 + if e.body_match.is_none() { 100 } else { 0 } + url
}

/// Build the mocks for `ids` (in this order; usually ascending = recorded order).
///
/// `with_bodies: false` is the cheap variant for a preview: response bodies are not read and
/// request bodies only up to 64 KiB; URLs and headers are sanitized as in the real run, so
/// the counts are the same in the common cases. What may differ: request bodies between
/// 64 KiB and 1 MiB are not body-matched in the preview (fewer mappings when such requests
/// differ only by body); repeated responses ([`SkipReason::Duplicate`]) are recognized only
/// up to 64 KiB of stored bytes and only when stored identically (not when they are equal
/// only after decoding or sanitizing); a decoded response above [`MAX_RESPONSE_BODY`] is
/// noticed only when the stored body is that large, and an undecodable one not at all.
pub fn generate(cap: &Arc<Capture>, ids: &[SessionId], opts: &MockOptions, with_bodies: bool, p: &dyn Progress) -> Result<MockSet> {
    let mut sanitizer = opts.sanitize.as_ref().map(|o| Sanitizer::new(SanitizeOptions::for_mocks(o)));
    let mut set = MockSet { sessions: ids.len(), ..Default::default() };
    let mut cands: Vec<Cand> = Vec::new();
    for (i, id) in ids.iter().enumerate() {
        if p.cancelled() {
            bail!("cancelled");
        }
        if i % 64 == 0 {
            p.progress(i as u64, ids.len() as u64);
        }
        let Some(d) = cap.detail(*id) else { continue };
        match candidate(cap, &d, opts, sanitizer.as_mut(), with_bodies, &mut set.dropped_headers) {
            Ok(c) => cands.push(c),
            Err(reason) => set.skipped.push(Skipped { id: *id, method: d.request.method.clone(), url: d.request.url.clone(), reason }),
        }
    }
    if set.dropped_headers > 0 {
        tracing::warn!(target: "quena", "mocks: {} recorded response header(s) with invalid name or value left out", set.dropped_headers);
    }
    disambiguate_graphql(&mut cands);
    let mut groups: Vec<Vec<Cand>> = Vec::new();
    let mut by_key: HashMap<String, usize> = HashMap::new();
    for c in cands {
        let g = *by_key.entry(c.key()).or_insert_with(|| {
            groups.push(Vec::new());
            groups.len() - 1
        });
        groups[g].push(c);
    }
    for g in &mut groups {
        unify_matcher(g);
    }
    // Specific matchers first (stable: otherwise recorded order).
    let mut order: Vec<usize> = (0..groups.len()).collect();
    order.sort_by_key(|g| groups[*g].first().map(|c| specificity(&c.entry)).unwrap_or(u32::MAX));
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
                    let same = kept.last().is_some_and(|k| {
                        k.entry.status == c.entry.status && if with_bodies { k.entry.body == c.entry.body } else { k.fingerprint.is_some() && k.fingerprint == c.fingerprint }
                    });
                    if same {
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

/// One matcher form per group: the URL is exact only when it is exact (and the same) for
/// every recording, otherwise all use the pattern; the parameters come from the first one.
/// A sequence whose rules matched differently would break its chain.
fn unify_matcher(items: &mut [Cand]) {
    let Some(first) = items.first() else { return };
    let exact = items.iter().all(|c| c.entry.exact_url && c.entry.url == first.entry.url);
    let query = first.entry.query.clone();
    for c in items.iter_mut() {
        c.entry.exact_url = exact;
        c.entry.query = query.clone();
    }
}

/// GraphQL requests with the same operation name and variables but another query are told
/// apart by their query.
fn disambiguate_graphql(cands: &mut [Cand]) {
    let mut hashes: HashMap<String, BTreeSet<String>> = HashMap::new();
    let gkey = |c: &Cand| match &c.entry.body_match {
        BodyMatch::GraphQl { operation_name, variables, query: None } => Some(format!("{} {operation_name} {}", c.url_key, canonical(variables))),
        _ => None,
    };
    for c in cands.iter() {
        if let (Some(k), Some(q)) = (gkey(c), &c.gql_query) {
            hashes.entry(k).or_default().insert(graphql_query_hash(q));
        }
    }
    for c in cands.iter_mut() {
        if let Some(k) = gkey(c)
            && hashes.get(&k).is_some_and(|h| h.len() > 1)
            && let BodyMatch::GraphQl { query, .. } = &mut c.entry.body_match
        {
            *query = c.gql_query.clone();
        }
    }
}

/// Where the sanitizer changed path segments, they match any value: the path as regex
/// (without anchors), `None` when the path is unchanged.
fn path_pattern(orig: &str, san: &str) -> Option<String> {
    if orig == san {
        return None;
    }
    let o: Vec<&str> = orig.split('/').collect();
    let s: Vec<&str> = san.split('/').collect();
    let parts: Vec<String> = if o.len() == s.len() {
        s.iter().zip(&o).map(|(s, o)| if s == o { re_lit(s) } else { "[^/]*".to_string() }).collect()
    } else {
        // Another number of segments: the changed middle matches anything up to the query.
        let pre = o.iter().zip(&s).take_while(|(a, b)| a == b).count();
        let suf = o.iter().rev().zip(s.iter().rev()).take_while(|(a, b)| a == b).count().min(o.len().min(s.len()) - pre);
        let mut v: Vec<String> = s[..pre].iter().map(|x| re_lit(x)).collect();
        v.push("[^?#]*".into());
        v.extend(s[s.len() - suf..].iter().map(|x| re_lit(x)));
        v
    };
    Some(parts.join("/"))
}

fn candidate(cap: &Arc<Capture>, d: &SessionDetail, opts: &MockOptions, sanitizer: Option<&mut Sanitizer>, with_bodies: bool, dropped: &mut usize) -> std::result::Result<Cand, SkipReason> {
    let method = d.request.method.to_ascii_uppercase();
    if d.summary.kind == SessionKind::Tunnel || method == "CONNECT" {
        return Err(SkipReason::Tunnel);
    }
    if d.summary.kind == SessionKind::WebSocket {
        return Err(SkipReason::WebSocket);
    }
    if method.is_empty() || !method.bytes().all(is_tchar) {
        return Err(SkipReason::Incomplete);
    }
    let Some(orig_resp) = &d.response else { return Err(SkipReason::NoResponse) };
    match orig_resp.status {
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
    let Some((full_origin, path, query)) = split_full_url(&d.request.url) else { return Err(SkipReason::Tunnel) };
    let (scheme, authority) = full_origin.split_once("://").unwrap_or(("http", ""));
    let has_userinfo = authority.contains('@');
    let host = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority).to_string();
    if host.is_empty() {
        return Err(SkipReason::Tunnel);
    }
    let origin = format!("{scheme}://{host}");
    if !opts.hosts.is_empty() && !opts.hosts.iter().any(|h| host_matches(h, &host)) {
        return Err(SkipReason::Host);
    }
    let resp_ct = orig_resp.headers.get("content-type").unwrap_or("");
    if !opts.include_static && is_static(&path, resp_ct) {
        return Err(SkipReason::Static);
    }
    if method == "OPTIONS" && !opts.include_preflight {
        return Err(SkipReason::Preflight);
    }
    if orig_resp.status >= 400 && !opts.include_errors {
        return Err(SkipReason::ErrorStatus);
    }
    let (req_body, resp_body) = cap.bodies_of(d.summary.id).unwrap_or_else(|| (Body::empty(), Body::empty()));
    if resp_body.is_truncated() {
        return Err(SkipReason::Truncated);
    }
    if resp_body.len() > MAX_RESPONSE_BODY as u64 {
        return Err(SkipReason::TooLarge);
    }
    let limit = if with_bodies { MAX_MATCH_BODY } else { PREVIEW_MATCH_BODY };
    let wants_req = opts.match_body && !req_body.is_empty() && req_body.len() <= (limit * 4) as u64;
    let req_orig = if wants_req { decoded_body(&d.request.headers, &req_body, limit + 1) } else { Vec::new() };
    let wants_req = wants_req && req_orig.len() <= limit;
    let empty = Body::empty();
    let req_in = if wants_req { &req_body } else { &empty };
    let resp_in = if with_bodies { &resp_body } else { &empty };

    // Sanitize (or just decode) what is written.
    let (detail, req_san, resp_bytes, keep_encoding): (Cow<SessionDetail>, Cow<[u8]>, Vec<u8>, bool) = match sanitizer {
        Some(s) => {
            let removed = |s: &Sanitizer| s.log().count("bodyRemoved") + s.log().count("undecodable");
            let before = removed(s);
            let out = s.session(d, req_in, resp_in);
            if with_bodies && !resp_body.is_empty() && removed(s) > before && out.response.starts_with(b"<body removed:") {
                return Err(if out.response.starts_with(b"<body removed: could not be decoded") { SkipReason::Undecodable } else { SkipReason::TooLarge });
            }
            (Cow::Owned(out.detail), Cow::Owned(out.request), out.response, false)
        }
        None => {
            let resp_bytes = if with_bodies { decoded_body(&orig_resp.headers, &resp_body, MAX_RESPONSE_BODY + 1) } else { Vec::new() };
            if resp_bytes.len() > MAX_RESPONSE_BODY {
                return Err(SkipReason::TooLarge);
            }
            // Unknown or broken encoding: the bytes are still encoded, so the header stays.
            let ce = orig_resp.headers.get("content-encoding").map(|v| v.trim().to_ascii_lowercase()).filter(|v| !v.is_empty() && v != "identity");
            let still_encoded = with_bodies && ce.is_some() && !resp_body.is_empty() && resp_body.read_range(0, resp_bytes.len() + 1).is_ok_and(|raw| raw == resp_bytes);
            (Cow::Borrowed(d), Cow::Borrowed(&req_orig[..]), resp_bytes, still_encoded)
        }
    };
    let resp = detail.response.as_ref().unwrap_or(orig_resp);

    // URL: parameters and path segments replaced by the sanitizer match any value.
    let (_, san_path, san_query) = split_full_url(&detail.request.url).unwrap_or((origin.clone(), path.clone(), query.clone()));
    let path_regex = path_pattern(&path, &san_path);
    let orig_params = parse_query(query.as_deref());
    let mut params = parse_query(san_query.as_deref());
    mark_replaced(&orig_params, &mut params);
    let ignored: Vec<String> = match opts.query {
        QueryMatch::Ignore => opts.ignore_params.iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
        QueryMatch::Exact => vec![],
    };
    let before = params.len();
    params.retain(|q| !ignored.iter().any(|pat| glob_matches(pat, &q.name)));
    // A URL the sanitizer left alone, without ignored parameters, stays an exact, readable
    // match (`EXACT:` has no room for whitespace, user info or a fragment).
    let plain = !has_userinfo && !detail.request.url.contains('#') && !detail.request.url.chars().any(|c| c.is_whitespace() || c.is_control());
    let exact_url = plain && detail.request.url == d.request.url && path_regex.is_none() && params.len() == before && !params.iter().any(|q| q.any);

    let req_ct = detail.request.headers.get("content-type").unwrap_or("").to_ascii_lowercase();
    let (body_match, gql_query) = if wants_req { body_match(&req_ct, &req_orig, &req_san) } else { (BodyMatch::None, None) };

    // Response as served.
    let mut headers: Vec<(String, String)> = Vec::new();
    for (n, v) in resp.headers.iter() {
        let l = n.to_ascii_lowercase();
        if n.starts_with(':') || (DROP_RESPONSE_HEADERS.contains(&l.as_str()) && !(keep_encoding && l == "content-encoding")) || (!opts.keep_set_cookie && l == "set-cookie") {
            continue;
        }
        if !valid_header(n, v) {
            *dropped += 1;
            continue;
        }
        headers.push((n.to_string(), v.to_string()));
    }
    let is_head = method == "HEAD";
    let body = if is_head || bodiless_status(resp.status) { Vec::new() } else { resp_bytes };
    if with_bodies && !bodiless_status(resp.status) {
        if is_head {
            // The length of the GET body, when the recording tells it (and it is not the
            // length of an encoded body that the mock would serve decoded).
            let encoded = orig_resp.headers.get("content-encoding").is_some_and(|v| !v.trim().is_empty() && !v.trim().eq_ignore_ascii_case("identity"));
            if let Some(cl) = resp.headers.get("content-length").map(str::trim).filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                && (!encoded || keep_encoding)
            {
                headers.push(("Content-Length".into(), cl.to_string()));
            }
        } else {
            headers.push(("Content-Length".into(), body.len().to_string()));
        }
    }
    let content_type = resp.headers.get("content-type").filter(|v| valid_header("content-type", v)).unwrap_or("").to_string();
    let delay_ms = if opts.latency { ttfb_ms(&d.timers) } else { 0 };
    let reason = clean_reason(&resp.reason, resp.status);
    let fingerprint = (!with_bodies && opts.repeats == Repeats::Sequence && resp_body.len() <= PREVIEW_COMPARE_BODY).then(|| {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        orig_resp.headers.get("content-encoding").unwrap_or("").hash(&mut h);
        resp_body.read_range(0, PREVIEW_COMPARE_BODY as usize).unwrap_or_default().hash(&mut h);
        h.finish()
    });

    let url_key = format!(
        "{method} {} {} ?{}",
        origin.to_ascii_lowercase(),
        match &path_regex {
            Some(r) => format!("R{r}"),
            None => format!("P{san_path}"),
        },
        {
            let mut q: Vec<String> = params.iter().map(|q| format!("{}={}", q.raw_name, if q.any { "*" } else { q.raw_value.as_deref().unwrap_or("") })).collect();
            q.sort();
            q.join("&")
        },
    );
    Ok(Cand {
        url_key,
        gql_query,
        fingerprint,
        entry: MockEntry {
            session: d.summary.id,
            method,
            url: detail.request.url.clone(),
            origin,
            host,
            path: san_path,
            path_regex,
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

pub(crate) fn pct_decode(s: &str) -> String {
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

/// The matcher for a request body, plus the GraphQL query as recorded (for
/// [`disambiguate_graphql`]).
fn body_match(ct: &str, orig: &[u8], san: &[u8]) -> (BodyMatch, Option<String>) {
    if san.is_empty() || san.len() > MAX_MATCH_BODY {
        return (BodyMatch::None, None);
    }
    if looks_like_json(ct, san) {
        let Ok(s) = serde_json::from_slice::<Value>(san) else { return (BodyMatch::None, None) };
        let spec = match serde_json::from_slice::<Value>(orig) {
            Ok(o) => with_placeholders(&o, &s),
            Err(_) => s,
        };
        let query = spec.get("query").and_then(|q| q.as_str()).filter(|q| *q != JSON_IGNORE).map(str::to_string);
        let variables = || spec.get("variables").cloned().unwrap_or(Value::Null);
        if let Some(op) = spec.get("operationName").and_then(|v| v.as_str()).filter(|o| !o.is_empty() && *o != JSON_IGNORE)
            && spec.get("query").is_some_and(|q| q.is_string())
        {
            return (BodyMatch::GraphQl { operation_name: op.to_string(), variables: variables(), query: None }, query);
        }
        // GraphQL without operation name: by query (normalized) and variables. Only for a
        // body that is nothing but a GraphQL request (`{"query": "…"}` from a search API is not).
        let graphql_only = spec.as_object().is_some_and(|o| o.keys().all(|k| matches!(k.as_str(), "query" | "variables" | "operationName" | "extensions")))
            && spec.get("operationName").is_none_or(|o| o.is_null() || o.as_str() == Some(""));
        if let Some(q) = &query
            && graphql_only
        {
            return (BodyMatch::GraphQl { operation_name: String::new(), variables: variables(), query: Some(q.clone()) }, query);
        }
        return (BodyMatch::Json { value: spec }, None);
    }
    if ct.contains("x-www-form-urlencoded") {
        let (Ok(o), Ok(s)) = (std::str::from_utf8(orig), std::str::from_utf8(san)) else { return (BodyMatch::None, None) };
        if s.len() > MAX_REGEX_BODY {
            // Too large for a regex: matched by hash, which needs it unchanged.
            return (if o == s && !s.contains('\0') { BodyMatch::Text { text: s.to_string() } } else { BodyMatch::None }, None);
        }
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
        return (BodyMatch::Form { pairs }, None);
    }
    match std::str::from_utf8(san) {
        // Text the sanitizer changed cannot be matched exactly any more.
        Ok(t) if orig == san && !t.contains('\0') => (BodyMatch::Text { text: t.to_string() }, None),
        _ => (BodyMatch::None, None),
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

/// JSON with sorted keys (a stable grouping key). Integers are written exactly, other
/// numbers as `f64` (so `1.0` and `1` are the same, as in [`crate::rules::json_matches`]).
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
            Value::Number(n) if n.is_i64() || n.is_u64() => out.push_str(&n.to_string()),
            Value::Number(n) => match n.as_f64() {
                // A float that holds an integer prints like that integer.
                Some(f) if f.fract() == 0.0 && f.abs() < 9.007_199_254_740_992e15 => out.push_str(&(f as i64).to_string()),
                Some(f) => out.push_str(&f.to_string()),
                None => out.push_str(&n.to_string()),
            },
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
        BodyMatch::GraphQl { operation_name, variables, query } => {
            format!("G{operation_name} {} {}", canonical(variables), query.as_deref().map(graphql_query_hash).unwrap_or_default())
        }
        BodyMatch::Form { pairs } => format!("F{}", pairs.iter().map(|(n, v)| format!("{n}={}", v.as_deref().unwrap_or("\u{0}*"))).collect::<Vec<_>>().join("&")),
        BodyMatch::Text { text } => format!("T{text}"),
    }
}

// ------------------------------------------------------------------ Quena rules

/// A regex literal for the rules engine: escaped; whitespace and control characters spelled
/// out (the match expression is one line and split at whitespace). Also valid in Java
/// (WireMock).
fn re_lit(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in regex::escape(s).chars() {
        if c.is_whitespace() || c.is_control() {
            out.push_str(&format!("\\x{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// Regex (without `regex:`) for the entry's URL: path exactly (or its pattern), the kept
/// parameters in recorded order, ignored parameters anywhere with any value.
pub fn url_regex(e: &MockEntry) -> String {
    let base = format!("{}{}", re_lit(&e.origin), e.path_regex.clone().unwrap_or_else(|| re_lit(&e.path)));
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
        BodyMatch::GraphQl { operation_name, variables, query } => {
            let mut spec = serde_json::Map::new();
            if !operation_name.is_empty() {
                spec.insert("operationName".into(), json!(operation_name));
            }
            spec.insert("variables".into(), variables.clone());
            if let Some(q) = query {
                spec.insert("queryHash".into(), json!(graphql_query_hash(q)));
            }
            format!("METHOD:{m} GRAPHQL:{url} {}", Value::Object(spec))
        }
        BodyMatch::Form { pairs } => {
            let parts: Vec<String> = pairs
                .iter()
                .map(|(n, v)| match v {
                    Some(v) => format!("{}={}", re_lit(n), re_lit(v)),
                    None => format!("{}=[^&]*", re_lit(n)),
                })
                .collect();
            let joined: usize = parts.iter().map(|p| p.len() + 1).sum();
            if joined > MAX_REGEX_BODY && pairs.iter().all(|(_, v)| v.is_some()) {
                let text = pairs.iter().map(|(n, v)| format!("{n}={}", v.as_deref().unwrap_or(""))).collect::<Vec<_>>().join("&");
                return format!("METHOD:{m} BODYHASH:{url} {}", sha256_hex(text.as_bytes()));
            }
            format!("METHOD:{m} URLWithBody:{url} regex:(?s)^{}$", parts.join("&"))
        }
        BodyMatch::Text { text } if text.len() > MAX_REGEX_BODY => format!("METHOD:{m} BODYHASH:{url} {}", sha256_hex(text.as_bytes())),
        BodyMatch::Text { text } => format!("METHOD:{m} URLWithBody:{url} regex:(?s)^{}$", re_lit(text)),
    }
}

/// The entry's response as a raw HTTP/1.1 message (what a `.dat` file action serves).
/// Headers with an invalid name or value are left out; 1xx/204/304 get no Content-Length,
/// a HEAD response keeps the recorded one (the length of the GET body), all others the
/// length of the body.
pub fn raw_response(e: &MockEntry) -> Vec<u8> {
    let mut h = Headers::new();
    let mut recorded_len = None;
    for (n, v) in &e.headers {
        if !valid_header(n, v) {
            continue;
        }
        if n.eq_ignore_ascii_case("content-length") {
            recorded_len.get_or_insert_with(|| v.clone());
        } else {
            h.push(n.clone(), v.clone());
        }
    }
    let body: &[u8] = if bodiless_status(e.status) || e.method.eq_ignore_ascii_case("HEAD") { &[] } else { &e.body };
    if !bodiless_status(e.status) {
        if e.method.eq_ignore_ascii_case("HEAD") {
            if let Some(l) = recorded_len {
                h.push("Content-Length", l);
            }
        } else {
            h.push("Content-Length", body.len().to_string());
        }
    }
    let head = ResponseHead { status: e.status, reason: clean_reason(&e.reason, e.status), version: HttpVersion::Http11, headers: h };
    let mut out = Vec::with_capacity(body.len() + 512);
    let _ = quena_formats::raw::write_response_head(&mut out, &head);
    out.extend_from_slice(body);
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
/// (`responses/0001-GET-api-items.dat`). Writes the response files through `out`. Returns
/// the state and how many entries were left out because their expression does not compile
/// (logged; should not happen).
fn package_rules(set: &MockSet, out: &mut dyn Out, opts_latency: bool) -> Result<(AutoResponderState, usize)> {
    let mut rules = Vec::with_capacity(set.entries.len());
    let mut rejected = 0;
    for (i, e) in set.entries.iter().enumerate() {
        let expr = match_expression(e);
        if let Err(err) = crate::rules::validate_match(&expr) {
            tracing::warn!(target: "quena", "mocks: #{} {} {} left out: {err}", e.session, e.method, e.path);
            rejected += 1;
            continue;
        }
        let file = format!("responses/{:04}-{}-{}.dat", i + 1, method_slug(&e.method), slug(&e.path));
        out.put(&file, &raw_response(e))?;
        let last = e.sequence.is_none_or(|s| s.index + 1 == s.len);
        rules.push(Rule {
            id: 0,
            enabled: true,
            match_: expr,
            action: file,
            latency_ms: e.delay_ms,
            match_once: !last,
            comment: format!("#{} {} {}", e.session, e.method, e.path),
            hits: 0,
        });
    }
    Ok((AutoResponderState { enabled: true, unmatched_passthrough: true, enable_latency: opts_latency && set.entries.iter().any(|e| e.delay_ms > 0), rules }, rejected))
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
        self.0.finish()?.sync_all()?;
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

/// Collects the files in memory (tests, small sets).
struct MemOut(Vec<(String, Vec<u8>)>);
impl Out for MemOut {
    fn put(&mut self, path: &str, data: &[u8]) -> Result<()> {
        self.0.push((path.to_string(), data.to_vec()));
        Ok(())
    }
}

/// A unique hidden name next to `path` (same folder, so a rename replaces atomically).
fn temp_sibling(path: &Path, what: &str) -> PathBuf {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    path.with_file_name(format!(".{name}.{what}-{}-{:08x}", std::process::id(), rand::random::<u32>()))
}

/// Write a ZIP through a temporary file and move it into place: an existing file is replaced
/// only by a complete new one.
fn write_zip_atomic(path: &Path, f: impl FnOnce(&mut ZipOut) -> Result<()>) -> Result<()> {
    let tmp = temp_sibling(path, "tmp");
    let r = (|| {
        let mut z = ZipOut::create(&tmp)?;
        f(&mut z)?;
        z.finish()?;
        std::fs::rename(&tmp, path).with_context(|| format!("move to {}", path.display()))
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

/// Write a Quena mock package (ZIP, usually `.quena-mocks`). An existing file is replaced
/// atomically.
pub fn write_package(set: &MockSet, path: &Path, opts: &MockOptions) -> Result<()> {
    write_zip_atomic(path, |z| {
        let (state, _) = package_rules(set, z, opts.latency)?;
        z.put("rules.json", &serde_json::to_vec_pretty(&state)?)?;
        z.put("README.txt", package_readme(set).as_bytes())
    })
}

/// The files of a WireMock export that this export owns in its folder.
const WIREMOCK_OWN: [&str; 3] = ["mappings", "__files", "README.md"];

/// Write a WireMock root (`mappings/`, `__files/`, `README.md`): a folder, or a ZIP when
/// `path` ends in `.zip`. In an existing folder, `mappings/`, `__files/` and `README.md` are
/// replaced as a whole (no stale mappings of an earlier export stay); other files there are
/// left alone. The new files are written first (into a hidden folder inside), then swapped
/// in, so a failed export leaves the old one intact. A ZIP is replaced atomically.
pub fn write_wiremock(set: &MockSet, path: &Path) -> Result<()> {
    if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("zip")) {
        return write_zip_atomic(path, |z| write_wiremock_to(set, z));
    }
    std::fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;
    let tmp = path.join(format!(".quena-new-{}-{:08x}", std::process::id(), rand::random::<u32>()));
    let r = (|| {
        write_wiremock_to(set, &mut DirOut(tmp.clone()))?;
        std::fs::create_dir_all(tmp.join("mappings"))?;
        for own in WIREMOCK_OWN {
            let old = path.join(own);
            match std::fs::symlink_metadata(&old) {
                Ok(m) if m.is_dir() => std::fs::remove_dir_all(&old).with_context(|| format!("remove {}", old.display()))?,
                Ok(_) => std::fs::remove_file(&old).with_context(|| format!("remove {}", old.display()))?,
                Err(_) => {}
            }
            let new = tmp.join(own);
            if new.exists() {
                std::fs::rename(&new, &old).with_context(|| format!("move to {}", old.display()))?;
            }
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    r
}

/// Writes the export file by file (bodies are not copied).
fn write_wiremock_to(set: &MockSet, out: &mut dyn Out) -> Result<()> {
    let multi = set.hosts.len() > 1;
    for (i, e) in set.entries.iter().enumerate() {
        let n = i + 1;
        let body_file = (!e.body.is_empty() && !bodiless_status(e.status) && !e.method.eq_ignore_ascii_case("HEAD")).then(|| format!("{n:04}.{}", file_ext(&e.content_type)));
        if let Some(f) = &body_file {
            out.put(&format!("__files/{f}"), &e.body)?;
        }
        let m = wiremock_mapping(e, n, body_file.as_deref(), multi);
        out.put(&format!("mappings/{n:04}-{}-{}.json", method_slug(&e.method), slug(&e.path)), &serde_json::to_vec_pretty(&m)?)?;
    }
    out.put("README.md", wiremock_readme(set).as_bytes())
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
/// Host header matcher. The priority is [`specificity`].
pub fn wiremock_mapping(e: &MockEntry, n: usize, body_file: Option<&str>, multi_host: bool) -> Value {
    let mut req = serde_json::Map::new();
    req.insert("method".into(), json!(e.method));
    if e.exact_url {
        let q = e.url.split_once('?').map(|(_, q)| format!("?{}", q.split('#').next().unwrap_or(""))).unwrap_or_default();
        req.insert("url".into(), json!(format!("{}{q}", e.path)));
    } else {
        match &e.path_regex {
            Some(r) => req.insert("urlPathPattern".into(), json!(r)),
            None => req.insert("urlPath".into(), json!(e.path)),
        };
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
        BodyMatch::GraphQl { operation_name, variables, query } => {
            let mut v = vec![];
            if !operation_name.is_empty() {
                v.push(json!({ "matchesJsonPath": { "expression": "$.operationName", "equalTo": operation_name } }));
            }
            if !(variables.is_null() || variables.as_object().is_some_and(|o| o.is_empty())) {
                v.push(json!({ "matchesJsonPath": { "expression": "$.variables", "equalToJson": variables.to_string() } }));
            }
            if let Some(q) = query {
                v.push(json!({ "matchesJsonPath": { "expression": "$.query", "equalTo": q } }));
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
    if !patterns.is_empty() {
        req.insert("bodyPatterns".into(), Value::Array(patterns));
    }
    let mut headers = serde_json::Map::new();
    for (name, v) in e.headers.iter().filter(|(n, v)| valid_header(n, v)) {
        if bodiless_status(e.status) && name.eq_ignore_ascii_case("content-length") {
            continue;
        }
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
    let mut m = serde_json::Map::new();
    m.insert("name".into(), json!(format!("{n:04} {} {}", e.method, e.path)));
    m.insert("priority".into(), json!(specificity(e)));
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

/// All files of a WireMock export (path, bytes), in memory (copies the bodies; the writers
/// stream instead).
pub fn wiremock_files(set: &MockSet) -> Vec<(String, Vec<u8>)> {
    let mut out = MemOut(Vec::new());
    let _ = write_wiremock_to(set, &mut out);
    out.0
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
    s.push_str("Sequences use scenarios: the responses come in recorded order, the last one repeats. Reset them with `POST /__admin/scenarios/reset`.\n\n");
    s.push_str("`mappings/`, `__files/` and this README are replaced by the next export into this folder.\n");
    s
}

// ------------------------------------------------------------------ packages

/// An installed mock package (folder `<data>/mocks/<name>/`).
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MockPackage {
    /// Lower case ([`sanitize_name`]).
    pub name: String,
    pub dir: String,
    /// Rules of this package in Mock Rules.
    pub rules: usize,
    /// Rules of the package file that were not taken over (unsafe, invalid, or not limited
    /// to a host); 0 in [`AppCore::mock_packages`].
    pub rejected: usize,
    /// Hosts the package's rules answer for (sorted).
    pub hosts: Vec<String>,
    /// Unix time in ms.
    pub created: Option<i64>,
}

/// The comment that marks the rules of a package (`pkg:<name>`, name lower case).
pub fn package_tag(name: &str) -> String {
    format!("pkg:{}", name.to_ascii_lowercase())
}

/// Is this rule one of package `name`'s? (Case-insensitive: packages installed before names
/// were lower case.)
pub fn is_package_rule(r: &Rule, name: &str) -> bool {
    r.comment.eq_ignore_ascii_case(&package_tag(name))
}

/// A safe package (folder) name: lower-case letters, digits, `.`, `_`, `-`; at most 64
/// characters (lower case: on case-insensitive file systems `Shop` and `shop` would share a
/// folder).
pub fn sanitize_name(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
            out.push(c.to_ascii_lowercase());
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

/// Largest package accepted (all files uncompressed), largest single file, largest
/// `rules.json`, and the most entries.
const MAX_PACKAGE_BYTES: u64 = 2 << 30;
const MAX_PACKAGE_ENTRY: u64 = 256 << 20;
const MAX_RULES_JSON: u64 = 64 << 20;
const MAX_PACKAGE_FILES: usize = 100_000;

/// Unpack a package into `dest` (created). Only `rules.json`, `README.txt` and
/// `responses/<file>` are taken; no path can leave `dest` (zip-slip); files are streamed to
/// disk and bounded (256 MiB each, 2 GiB in all).
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
        let cap = if name == "rules.json" { MAX_RULES_JSON } else { MAX_PACKAGE_ENTRY };
        if entry.size() > cap {
            bail!("mock package: {name} is larger than {} MiB", cap >> 20);
        }
        let mut file = std::fs::File::create(&target).with_context(|| format!("create {}", target.display()))?;
        // The declared size may lie: the copy itself is bounded.
        let n = std::io::copy(&mut entry.by_ref().take(cap + 1), &mut file)?;
        if n > cap {
            bail!("mock package: {name} is larger than {} MiB", cap >> 20);
        }
        total += n;
        if total > MAX_PACKAGE_BYTES {
            bail!("mock package is larger than {} GiB", MAX_PACKAGE_BYTES >> 30);
        }
        if name == "rules.json" {
            drop(file);
            rules_json = Some(std::fs::read(&target)?);
        }
    }
    let raw = rules_json.ok_or_else(|| anyhow!("{}: no rules.json, not a mock package", zip_path.display()))?;
    serde_json::from_slice(&raw).map_err(|e| anyhow!("rules.json: {e}"))
}

/// The host (`host[:port]`, lower case) a match expression is limited to, or `None` when it
/// can match other hosts too. Understood: `METHOD:`, `BODYJSON:`, `GRAPHQL:`, `BODYHASH:` and
/// `URLWithBody:` around `EXACT:<url>`, `prefix:<url>` or `regex:^<literal origin>/…`
/// (without top-level alternation).
pub fn match_host(expr: &str) -> Option<String> {
    let mut s = expr.trim();
    let lower = |x: &str| x.to_ascii_lowercase();
    if lower(s).starts_with("method:") {
        s = s[7..].trim_start().split_once(char::is_whitespace)?.1.trim();
    }
    for p in ["bodyjson:", "graphql:", "bodyhash:", "urlwithbody:"] {
        if lower(s).starts_with(p) {
            s = s[p.len()..].trim_start().split_once(char::is_whitespace)?.0;
            break;
        }
    }
    let l = lower(s);
    let url_host = |u: &str| -> Option<String> {
        let (scheme, rest) = u.split_once("://")?;
        if scheme.is_empty() || !scheme.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) {
            return None;
        }
        let auth = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
        let host = auth.rsplit_once('@').map(|(_, h)| h).unwrap_or(auth);
        (!host.is_empty() && !host.contains(['*', ' '])).then(|| host.to_ascii_lowercase())
    };
    if l.starts_with("exact:") {
        return url_host(&s[6..]);
    }
    if l.starts_with("prefix:") {
        return url_host(s[7..].trim());
    }
    if l.starts_with("regex:") {
        let r = &s[6..];
        let body = r.strip_prefix('^')?;
        if top_level_alternation(body) {
            return None;
        }
        // The literal start of the regex.
        let mut lit = String::new();
        let mut it = body.chars().peekable();
        while let Some(c) = it.next() {
            match c {
                '\\' => match it.peek() {
                    Some(n) if !n.is_ascii_alphanumeric() => {
                        lit.push(*n);
                        it.next();
                    }
                    _ => break,
                },
                '?' | '*' | '+' | '{' => {
                    // A quantifier makes the previous character optional/repeatable.
                    lit.pop();
                    break;
                }
                '.' | '(' | ')' | '|' | '[' | ']' | '}' | '^' | '$' => break,
                c => lit.push(c),
            }
        }
        let (_, rest) = lit.split_once("://")?;
        // The authority must end inside the literal (`https://a.test` could go on as
        // `https://a.test.evil.net`).
        rest.find(['/', '?', '#'])?;
        return url_host(&lit);
    }
    None
}

/// Does the regex have a `|` outside of any group (which would undo a leading `^literal`)?
fn top_level_alternation(r: &str) -> bool {
    let mut depth = 0i32;
    let mut class = false;
    let mut it = r.chars();
    while let Some(c) = it.next() {
        match c {
            '\\' => {
                it.next();
            }
            '[' if !class => class = true,
            ']' if class => class = false,
            '(' if !class => depth += 1,
            ')' if !class => depth -= 1,
            '|' if !class && depth <= 0 => return true,
            _ => {}
        }
    }
    false
}

/// The package's rules with absolute file actions and the package tag. Left out (counted as
/// rejected): rules with another action than a response file of the package or a simple
/// status/delay/drop (a package must not map remote hosts or local folders), rules that do
/// not compile, and rules not limited to one host ([`match_host`]: `*` or a substring would
/// answer for every site). Latency is capped at [`MAX_PACKAGE_LATENCY_MS`].
pub fn resolve_package_rules(state: &AutoResponderState, dir: &Path, name: &str) -> (Vec<Rule>, usize) {
    let mut out = Vec::new();
    let mut rejected = 0;
    for r in &state.rules {
        let Some(mut action) = package_action(&r.action, dir) else {
            rejected += 1;
            continue;
        };
        if crate::rules::validate_match(&r.match_).is_err() || match_host(&r.match_).is_none() {
            rejected += 1;
            continue;
        }
        // A top-level regex rule expands `$1` … in its action: a `$` in the data folder's
        // path must stay literal.
        if r.match_.trim_start().to_ascii_lowercase().starts_with("regex:") && !r.action.trim().starts_with('*') {
            action = action.replace('$', "$$");
        }
        out.push(Rule {
            id: 0,
            enabled: r.enabled,
            match_: r.match_.clone(),
            action,
            latency_ms: r.latency_ms.min(MAX_PACKAGE_LATENCY_MS),
            match_once: r.match_once,
            comment: package_tag(name),
            hits: 0,
        });
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
        || r.strip_prefix("delay:").is_some_and(|d| d.trim().parse::<u64>().is_ok_and(|ms| ms <= MAX_PACKAGE_LATENCY_MS as u64));
    ok.then(|| t.to_string())
}

/// Hosts of a list of rules (sorted, distinct).
fn rule_hosts<'a>(rules: impl Iterator<Item = &'a Rule>) -> Vec<String> {
    let set: BTreeSet<String> = rules.filter_map(|r| match_host(&r.match_)).collect();
    set.into_iter().collect()
}

/// Put package rules into Mock Rules: an earlier import of the same package is replaced; with
/// `replace` all other rules go too. The package rules come first (they are specific). The
/// change is atomic ([`Rules::update_autoresponder`]).
pub fn install_rules(rules: &Rules, name: &str, new_rules: Vec<Rule>, replace: bool, enable_latency: bool) -> Result<usize> {
    let n = new_rules.len();
    rules.update_autoresponder(true, |s| {
        if replace {
            s.rules.clear();
        } else {
            s.rules.retain(|r| !is_package_rule(r, name));
        }
        s.rules.splice(0..0, new_rules);
        s.enabled = true;
        s.enable_latency |= enable_latency;
    })?;
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
    /// Mappings that did not become rules (`apply`: rejected on install, otherwise whose
    /// expression did not compile). 0 normally.
    pub rejected: usize,
    /// Recorded response headers left out as invalid ([`MockSet::dropped_headers`]).
    pub dropped_headers: usize,
}

/// A fresh, unique folder name for one installation of a package.
fn generation_name() -> String {
    format!("g{}-{:08x}", unix_ms(std::time::SystemTime::now()).unwrap_or(0), rand::random::<u32>())
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

    /// Counts for the Mocks dialog (cheap: no response bodies; see [`generate`] for what may
    /// differ from the result).
    pub fn mock_preview(&self, ids: Vec<SessionId>, opts: MockOptions) -> Result<MockPreview> {
        let ids = self.mock_ids(ids);
        let set = generate(&self.capture(), &ids, &opts, false, &quena_formats::NoProgress)?;
        Ok(MockPreview::of(&set))
    }

    fn mock_job(self: &Arc<Self>, ids: Vec<SessionId>, opts: MockOptions, target: &'static str, path: PathBuf, title: String, name: Option<String>) -> JobId {
        let ids = self.mock_ids(ids);
        let cap = self.capture();
        let core = Arc::downgrade(self);
        // The same job (same target, sessions and options) running already is not started
        // twice; a different one is.
        let fingerprint = {
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            ids.hash(&mut h);
            serde_json::to_string(&opts).unwrap_or_default().hash(&mut h);
            h.finish()
        };
        self.jobs.submit(format!("mocks:{target}:{}:{fingerprint:016x}", path.display()), title, Priority::Background, true, move |ctx| {
            let set = generate(&cap, &ids, &opts, true, &JobProgress(ctx)).map_err(|e| e.to_string())?;
            let core = core.upgrade().ok_or("shutting down")?;
            let mut rejected = 0;
            let mut out_path = path.clone();
            match target {
                "wiremock" => write_wiremock(&set, &path).map_err(|e| e.to_string())?,
                "package" => write_package(&set, &path, &opts).map_err(|e| e.to_string())?,
                _ => {
                    let name = name.clone().unwrap_or_default();
                    let (_, r, dir) = core.install_generated(&set, &opts, &name).map_err(|e| e.to_string())?;
                    rejected = r;
                    out_path = dir;
                }
            }
            tracing::info!(target: "quena", "mocks ({target}): {} mapping(s) from {} session(s) to {}, {rejected} rejected", set.entries.len(), set.sessions, out_path.display());
            core.emit(
                "mocks",
                MockJobResult {
                    job: ctx.id(),
                    target: target.into(),
                    path: out_path.display().to_string(),
                    name: name.clone(),
                    mappings: set.entries.len(),
                    sequences: set.sequences(),
                    skipped: set.skipped.len(),
                    rejected,
                    dropped_headers: set.dropped_headers,
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
    /// An empty name picks `sessions-<date>-<time>`; names are lower case.
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

    /// Install a generated set as package `name`. Returns (rules installed, rejected, folder).
    fn install_generated(&self, set: &MockSet, opts: &MockOptions, name: &str) -> Result<(usize, usize, PathBuf)> {
        let rules = self.rules.as_ref().ok_or_else(|| anyhow!("mock rules unavailable"))?;
        let _lock = rules.package_lock();
        let pkg = self.mocks_dir().join(name);
        let gen_name = generation_name();
        let r#gen = pkg.join(&gen_name);
        let written = (|| {
            let mut out = DirOut(r#gen.clone());
            std::fs::create_dir_all(r#gen.join("responses"))?;
            let (state, rejected) = package_rules(set, &mut out, opts.latency)?;
            out.put("rules.json", &serde_json::to_vec_pretty(&state)?)?;
            out.put("README.txt", package_readme(set).as_bytes())?;
            Ok::<_, anyhow::Error>((state, rejected))
        })();
        let (state, gen_rejected) = match written {
            Ok(s) => s,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&r#gen);
                return Err(e);
            }
        };
        let (new_rules, rejected) = resolve_package_rules(&state, &r#gen, name);
        if let Err(e) = install_rules(rules, name, new_rules.clone(), false, state.enable_latency) {
            let _ = std::fs::remove_dir_all(&r#gen);
            return Err(e);
        }
        self.drop_old_generations(name, &gen_name);
        Ok((new_rules.len(), gen_rejected + rejected, pkg))
    }

    /// After the rules point to the new generation: remove everything else of the package
    /// (older generations, the flat layout of older versions, a folder that differs only in
    /// case).
    fn drop_old_generations(&self, name: &str, keep: &str) {
        let root = self.mocks_dir();
        let pkg = root.join(name);
        for e in std::fs::read_dir(&pkg).into_iter().flatten().flatten() {
            if e.file_name() != keep {
                let p = e.path();
                let r = if e.file_type().is_ok_and(|t| t.is_dir()) { std::fs::remove_dir_all(&p) } else { std::fs::remove_file(&p) };
                if let Err(err) = r {
                    tracing::warn!(target: "quena", "mock package {name}: cannot remove {}: {err}", p.display());
                }
            }
        }
        for e in std::fs::read_dir(&root).into_iter().flatten().flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            // The same folder on a case-insensitive file system shows the new generation.
            if n != name && n.eq_ignore_ascii_case(name) && !e.path().join(keep).exists() {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }

    /// Import a `.quena-mocks` package: unpacked to `<data>/mocks/<name>/` (name from the file
    /// name, lower case), rules tagged `pkg:<name>` on top of Mock Rules. `replace`: remove all
    /// other rules.
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
        let _lock = rules.package_lock();
        let pkg = self.mocks_dir().join(name);
        let gen_name = generation_name();
        let r#gen = pkg.join(&gen_name);
        let state = match extract_package(path, &r#gen) {
            Ok(s) => s,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&r#gen);
                return Err(e);
            }
        };
        let (new_rules, rejected) = resolve_package_rules(&state, &r#gen, name);
        let hosts = rule_hosts(new_rules.iter());
        let n = match install_rules(rules, name, new_rules, replace, state.enable_latency) {
            Ok(n) => n,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&r#gen);
                return Err(e);
            }
        };
        self.drop_old_generations(name, &gen_name);
        tracing::info!(target: "quena", "mock package {name}: {n} rule(s) imported, {rejected} left out");
        Ok(MockPackage { name: name.into(), dir: pkg.display().to_string(), rules: n, rejected, hosts, created: std::fs::metadata(&r#gen).and_then(|m| m.modified()).ok().and_then(unix_ms) })
    }

    fn check_package_name(name: &str) -> Result<String> {
        if name.is_empty() || sanitize_name(name) != name.to_ascii_lowercase() {
            bail!("invalid package name {name:?}");
        }
        Ok(name.to_ascii_lowercase())
    }

    /// Remove a package: its rules and its folder. Returns the number of rules removed.
    /// The name is compared case-insensitively.
    pub fn mock_remove_package(&self, name: &str) -> Result<usize> {
        let name = Self::check_package_name(name)?;
        let rules = self.rules.as_ref().ok_or_else(|| anyhow!("mock rules unavailable"))?;
        let _lock = rules.package_lock();
        let n = rules.update_autoresponder(true, |s| {
            let before = s.rules.len();
            s.rules.retain(|r| !is_package_rule(r, &name));
            before - s.rules.len()
        })?;
        for e in std::fs::read_dir(self.mocks_dir()).into_iter().flatten().flatten() {
            if e.file_name().to_string_lossy().eq_ignore_ascii_case(&name) && e.file_type().is_ok_and(|t| t.is_dir()) {
                std::fs::remove_dir_all(e.path()).with_context(|| format!("remove {}", e.path().display()))?;
            }
        }
        Ok(n)
    }

    /// Start the sequences of a package over: the hit counters of its rules go back to 0, so
    /// `match_once` chains answer from their first response again. Returns the number of
    /// rules reset.
    pub fn mock_reset_sequences(&self, name: &str) -> Result<usize> {
        let name = Self::check_package_name(name)?;
        let rules = self.rules.as_ref().ok_or_else(|| anyhow!("mock rules unavailable"))?;
        Ok(rules.reset_hits(|r| is_package_rule(r, &name)))
    }

    /// Installed packages (folders in `<data>/mocks/`) with their rule counts and hosts.
    pub fn mock_packages(&self) -> Vec<MockPackage> {
        let mut by_pkg: HashMap<String, Vec<Rule>> = HashMap::new();
        if let Some(r) = &self.rules {
            for rule in r.autoresponder().rules {
                if let Some(n) = rule.comment.strip_prefix("pkg:") {
                    by_pkg.entry(n.to_ascii_lowercase()).or_default().push(rule);
                }
            }
        }
        let mut out: Vec<MockPackage> = Vec::new();
        for e in std::fs::read_dir(self.mocks_dir()).into_iter().flatten().flatten() {
            let name = e.file_name().to_string_lossy().to_ascii_lowercase();
            if name.starts_with('.') || !e.file_type().is_ok_and(|t| t.is_dir()) || out.iter().any(|p| p.name == name) {
                continue;
            }
            let rules = by_pkg.get(&name).map(Vec::as_slice).unwrap_or(&[]);
            out.push(MockPackage {
                rules: rules.len(),
                hosts: rule_hosts(rules.iter()),
                dir: e.path().display().to_string(),
                created: e.metadata().and_then(|m| m.modified()).ok().and_then(unix_ms),
                rejected: 0,
                name,
            });
        }
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
            path_regex: None,
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
    fn path_patterns() {
        assert_eq!(path_pattern("/a/b", "/a/b"), None);
        assert_eq!(path_pattern("/reset/eyJabc", "/reset/%3Cjwt-1%3E").as_deref(), Some("/reset/[^/]*"));
        assert_eq!(path_pattern("/u/a.b/x/y/z", "/u/a.b/%3Cp%3E/z").as_deref(), Some(r"/u/a\.b/[^?#]*/z"));
        let mut e = entry("https://api.x.de/users/%3Cemail-1%3E/orders");
        e.path_regex = path_pattern("/users/max%40example.com/orders", &e.path);
        e.exact_url = false;
        let re = regex::Regex::new(&url_regex(&e)).unwrap();
        assert!(re.is_match("https://api.x.de/users/max%40example.com/orders") && !re.is_match("https://api.x.de/users/a/b/orders"));
        assert!(!match_expression(&e).contains(char::is_whitespace) || match_expression(&e).starts_with("METHOD:GET regex:"));
        // Whitespace is spelled out (the expression is split at whitespace).
        assert_eq!(re_lit("a b\n"), r"a\x{20}b\x{a}");
    }

    #[test]
    fn hosts_of_match_expressions() {
        for (m, want) in [
            ("METHOD:GET EXACT:https://API.x.de:8443/a?b=1", Some("api.x.de:8443")),
            (r"METHOD:POST BODYJSON:regex:^https://api\.x\.de/search(?:\?x)?$ {}", Some("api.x.de")),
            ("prefix:http://mock.invalid/api/", Some("mock.invalid")),
            ("METHOD:POST URLWithBody:EXACT:http://a.test/x regex:^a$", Some("a.test")),
            ("*", None),
            ("login", None),
            ("NOT:x", None),
            (r"regex:^https://a\.test/x|.*", None),
            (r"regex:^https://a\.test.*", None),
            (r"regex:(?i)^https://a\.test/", None),
            (r"regex:^https://a\.test/*", None),
            ("regex:.*", None),
            ("EXACT:/relative", None),
        ] {
            assert_eq!(match_host(m).as_deref(), want, "{m}");
        }
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
        assert_eq!(sanitize_name("Mein Paket (2)"), "mein-paket-2");
        assert_eq!(sanitize_name("..."), "mocks");
        assert_eq!(package_tag("Shop-API"), "pkg:shop-api");
        assert_eq!(slug("/api/v1/items/"), "api-v1-items");
        assert_eq!(pct_decode("a%20b+c%zz"), "a b c%zz");
        assert!(is_static("/app.js", "") && is_static("/x", "image/png") && !is_static("/api/items", "application/json"));
        let o: Value = serde_json::from_str(r#"{"user":"a","password":"secret","n":[1,2]}"#).unwrap();
        let s: Value = serde_json::from_str(r#"{"user":"a","password":"<redacted>","n":[1,2]}"#).unwrap();
        assert_eq!(with_placeholders(&o, &s), json!({"user":"a","password":JSON_IGNORE,"n":[1,2]}));
        assert_eq!(canonical(&json!({"b":1,"a":[1.0,{"d":2,"c":3}]})), r#"{"a":[1,{"c":3,"d":2}],"b":1}"#);
        // Large integers stay apart.
        let a: Value = serde_json::from_str(r#"{"id":9007199254740993}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"id":9007199254740992}"#).unwrap();
        assert_ne!(canonical(&a), canonical(&b));
        assert!(valid_header("X-A", "b\tc") && !valid_header("X-A", "b\r\nSet-Cookie: x") && !valid_header("X A", "b") && !valid_header("X-A", "a\0"));
        assert_eq!(clean_reason("OK\r\nX: y", 200), "OKX: y");
        assert_eq!(clean_reason("\r\n", 404), "Not Found");
    }

    #[test]
    fn raw_response_framing() {
        let mut e = entry("http://a.test/x");
        e.body = b"hello".to_vec();
        e.headers = vec![("Content-Length".into(), "999".into()), ("X-Bad".into(), "a\r\nInjected: 1".into()), ("X-Ok".into(), "1".into())];
        let raw = String::from_utf8(raw_response(&e)).unwrap();
        assert!(raw.contains("Content-Length: 5\r\n") && !raw.contains("Injected") && raw.ends_with("\r\n\r\nhello"), "{raw}");
        e.status = 204;
        let raw = String::from_utf8(raw_response(&e)).unwrap();
        assert!(!raw.to_ascii_lowercase().contains("content-length") && raw.ends_with("\r\n\r\n"), "{raw}");
        e.status = 200;
        e.method = "HEAD".into();
        let raw = String::from_utf8(raw_response(&e)).unwrap();
        assert!(raw.contains("Content-Length: 999\r\n") && raw.ends_with("\r\n\r\n"), "{raw}");
        e.reason = "OK\r\nX-Evil: 1".into();
        assert!(!String::from_utf8(raw_response(&e)).unwrap().contains("\r\nX-Evil"));
    }
}
