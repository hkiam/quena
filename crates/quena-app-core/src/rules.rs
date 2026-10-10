//! AutoResponder (M7) and Breakpoints/Tamper (M8) – the interceptor chain
//! installed into the proxy.

use crate::AppCore;
use anyhow::{Result, anyhow};
use parking_lot::{Mutex, RwLock};
use quena_body::Body;
use quena_model::*;
use quena_proxy::hooks::{BoxFuture, Mode};
use quena_proxy::{Interceptor, RequestAction, ResponseAction, SessionView};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use quena_script::{RequestDecision, RequestInfo, ResponseDecision, ResponseInfo, ScriptEngine, SessionMeta};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::sync::oneshot;

// ------------------------------------------------------------ AutoResponder

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Rule {
    pub id: u64,
    pub enabled: bool,
    /// Match expression (`*`, `exact:`, `prefix:`, `regex:`, `NOT:`, `METHOD:`, `HEADER:`, `URLWithBody:`,
    /// `BODYJSON:`, `GRAPHQL:` or substring).
    ///
    /// `BODYJSON:<url match> <json>` matches when the URL matches and the (decoded) request body
    /// is JSON equal to `<json>`: key order and whitespace do not matter, the string
    /// `"${json-unit.ignore}"` matches any value. `GRAPHQL:<url match> {"operationName":…,
    /// "variables":…}` matches a GraphQL request body by operation name and variables.
    #[serde(rename = "match")]
    pub match_: String,
    /// Action (`file path`, `dir:folder`, `*404`, `*delay:500`, `*drop`, `*redir:url`, `*header:N=V`, `*bpu`, `*bpafter`, `http://…`, `session:ID`).
    ///
    /// With a `prefix:` match, `http(s)://…` is *Map Remote*: the part of the URL after the prefix
    /// (rest of the path and the query) is appended to the target. `dir:folder` is *Map Local*: it
    /// serves the file at the rest of the path inside the folder (the rest after a `prefix:` match,
    /// regex group 1, or else the whole URL path), never outside of it.
    ///
    /// A Map Remote target may end in ` *nocreds`: then Cookie, Authorization and
    /// Proxy-Authorization are removed when the request goes to another host or port, or from
    /// https to http. Without it (older rules) they are forwarded unchanged.
    pub action: String,
    pub latency_ms: u32,
    pub match_once: bool,
    pub comment: String,
    #[serde(skip_deserializing)]
    pub hits: u64,
}

impl Default for Rule {
    fn default() -> Self {
        Rule { id: 0, enabled: true, match_: String::new(), action: String::new(), latency_ms: 0, match_once: false, comment: String::new(), hits: 0 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct AutoResponderState {
    pub enabled: bool,
    /// Forward requests that match no rule (otherwise answer 404).
    pub unmatched_passthrough: bool,
    pub enable_latency: bool,
    pub rules: Vec<Rule>,
}

impl Default for AutoResponderState {
    fn default() -> Self {
        AutoResponderState { enabled: false, unmatched_passthrough: true, enable_latency: false, rules: vec![] }
    }
}

pub(crate) enum Matcher {
    All,
    Exact(String),
    /// URL starts with this text (ASCII case-insensitive); the rest is handed to the action.
    Prefix(String),
    Regex(Regex),
    Not(String),
    Contains(String),
    Method(String, Box<Matcher>),
    Header(String, String),
    UrlWithBody(Box<Matcher>, Regex),
    /// URL matcher and a JSON value the request body must equal semantically.
    BodyJson(Box<Matcher>, serde_json::Value),
    /// URL matcher, GraphQL operation name, variables and (optional) the SHA-256 of the
    /// normalized query text ([`graphql_query_hash`]).
    GraphQl(Box<Matcher>, Option<String>, serde_json::Value, Option<String>),
    /// URL matcher and the SHA-256 (hex) of the decoded request body.
    BodyHash(Box<Matcher>, String),
}

/// In a `BODYJSON:` / `GRAPHQL:` value: matches any value (the WireMock / JsonUnit placeholder).
pub const JSON_IGNORE: &str = "${json-unit.ignore}";

/// Semantic JSON comparison for mock rules: objects regardless of key order, arrays in order,
/// numbers by value. Placeholders in `spec`: `${json-unit.ignore}` (anything),
/// `${json-unit.any-string}`, `${json-unit.any-number}`, `${json-unit.any-boolean}`.
pub fn json_matches(spec: &serde_json::Value, actual: &serde_json::Value) -> bool {
    use serde_json::Value as V;
    match (spec, actual) {
        (V::String(s), _) if s == JSON_IGNORE => true,
        (V::String(s), a) if s == "${json-unit.any-string}" => a.is_string(),
        (V::String(s), a) if s == "${json-unit.any-number}" => a.is_number(),
        (V::String(s), a) if s == "${json-unit.any-boolean}" => a.is_boolean(),
        (V::Object(s), V::Object(a)) => s.len() == a.len() && s.iter().all(|(k, v)| a.get(k).is_some_and(|x| json_matches(v, x))),
        (V::Array(s), V::Array(a)) => s.len() == a.len() && s.iter().zip(a).all(|(x, y)| json_matches(x, y)),
        (V::Number(x), V::Number(y)) => numbers_equal(x, y),
        _ => spec == actual,
    }
}

/// Integers compare exactly (large IDs must not collide through `f64`); only when one side
/// is not an integer are both compared as floating point (`1` equals `1.0`).
pub fn numbers_equal(x: &serde_json::Number, y: &serde_json::Number) -> bool {
    let int = |n: &serde_json::Number| n.as_i64().map(i128::from).or_else(|| n.as_u64().map(i128::from));
    match (int(x), int(y)) {
        (Some(a), Some(b)) => a == b,
        _ => x.as_f64().zip(y.as_f64()).is_some_and(|(a, b)| a == b),
    }
}

/// Lower-case hex SHA-256.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// The GraphQL query text without comments and insignificant whitespace (so formatting does
/// not matter), as SHA-256 hex.
pub fn graphql_query_hash(query: &str) -> String {
    sha256_hex(normalize_graphql(query).as_bytes())
}

fn normalize_graphql(q: &str) -> String {
    const PUNCT: &str = "{}()[]:,!=@$|&.";
    let mut out = String::with_capacity(q.len());
    let mut chars = q.chars().peekable();
    let mut pending_space = false;
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if pending_space && !out.is_empty() && !out.ends_with(|p| PUNCT.contains(p)) {
                    out.push(' ');
                }
                pending_space = false;
                // Strings stay as they are (escapes included).
                out.push('"');
                while let Some(x) = chars.next() {
                    out.push(x);
                    if x == '\\' {
                        if let Some(n) = chars.next() {
                            out.push(n);
                        }
                    } else if x == '"' {
                        break;
                    }
                }
            }
            '#' => {
                for x in chars.by_ref() {
                    if x == '\n' || x == '\r' {
                        break;
                    }
                }
                pending_space = true;
            }
            c if c.is_whitespace() || c == ',' => pending_space = true,
            c => {
                if pending_space && !out.is_empty() && !PUNCT.contains(c) && !out.ends_with(|p| PUNCT.contains(p)) {
                    out.push(' ');
                }
                pending_space = false;
                out.push(c);
            }
        }
    }
    out
}

/// Does a GraphQL request body carry this operation name and these variables (and, with
/// `query_hash`, this query)? Absent, `null` and `{}` variables are the same.
fn graphql_matches(op: &Option<String>, vars: &serde_json::Value, query_hash: &Option<String>, body: &serde_json::Value) -> bool {
    let empty = |v: Option<&serde_json::Value>| v.is_none_or(|v| v.is_null() || v.as_object().is_some_and(|o| o.is_empty()));
    let Some(obj) = body.as_object() else { return false };
    if obj.get("operationName").and_then(|v| v.as_str()).filter(|o| !o.is_empty()) != op.as_deref().filter(|o| !o.is_empty()) {
        return false;
    }
    if let Some(h) = query_hash
        && !obj.get("query").and_then(|q| q.as_str()).is_some_and(|q| graphql_query_hash(q).eq_ignore_ascii_case(h))
    {
        return false;
    }
    if empty(Some(vars)) {
        return empty(obj.get("variables"));
    }
    obj.get("variables").is_some_and(|a| json_matches(vars, a))
}

/// Check the syntax of a match expression (as rules are compiled).
pub fn validate_match(s: &str) -> Result<()> {
    Matcher::parse(s).map(|_| ())
}

/// Largest decoded request body the body matchers look at.
const MAX_MATCHED_BODY: usize = 8 << 20;

/// One request being matched: the body is decoded (Content-Encoding removed) and parsed at
/// most once, however many rules look at it.
struct MatchCtx<'a> {
    head: &'a RequestHead,
    body: Option<&'a Body>,
    decoded: std::cell::OnceCell<Option<Vec<u8>>>,
    text: std::cell::OnceCell<Option<String>>,
    json: std::cell::OnceCell<Option<serde_json::Value>>,
    sha: std::cell::OnceCell<Option<String>>,
}

impl<'a> MatchCtx<'a> {
    fn new(head: &'a RequestHead, body: Option<&'a Body>) -> Self {
        MatchCtx { head, body, decoded: Default::default(), text: Default::default(), json: Default::default(), sha: Default::default() }
    }
    /// The request body as the client meant it (Content-Encoding removed), at most 8 MiB.
    fn decoded(&self) -> Option<&[u8]> {
        self.decoded.get_or_init(|| self.body.map(|b| crate::sanitize::decoded_body(&self.head.headers, b, MAX_MATCHED_BODY))).as_deref()
    }
    fn text(&self) -> Option<&str> {
        self.text.get_or_init(|| self.decoded().map(|d| String::from_utf8_lossy(d).into_owned())).as_deref()
    }
    fn json(&self) -> Option<&serde_json::Value> {
        self.json.get_or_init(|| self.decoded().and_then(|d| serde_json::from_slice(d).ok())).as_ref()
    }
    fn sha(&self) -> Option<&str> {
        self.sha.get_or_init(|| self.decoded().map(sha256_hex)).as_deref()
    }
}

/// `<url match> <rest>`: split at the first whitespace (URL matchers contain none).
fn split_url_and_rest(rest: &str, usage: &str) -> Result<(Matcher, String)> {
    let (u, b) = rest.trim().split_once(char::is_whitespace).ok_or_else(|| anyhow!("{usage}"))?;
    Ok((Matcher::parse(u)?, b.trim().to_string()))
}

impl Matcher {
    pub(crate) fn parse(s: &str) -> Result<Matcher> {
        let s = s.trim();
        let lower = s.to_ascii_lowercase();
        Ok(if s == "*" || s.is_empty() {
            Matcher::All
        } else if lower.starts_with("exact:") {
            Matcher::Exact(s[6..].to_string())
        } else if lower.starts_with("prefix:") {
            let p = s[7..].trim();
            if p.is_empty() {
                return Err(anyhow!("prefix: needs a URL prefix, e.g. prefix:https://example.com/api/"));
            }
            Matcher::Prefix(p.to_string())
        } else if lower.starts_with("regex:") {
            Matcher::Regex(Regex::new(&s[6..]).map_err(|e| anyhow!("regex: {e}"))?)
        } else if lower.starts_with("not:") {
            Matcher::Not(s[4..].trim().to_lowercase())
        } else if lower.starts_with("method:") {
            let rest = s[7..].trim();
            let (m, r) = rest.split_once(char::is_whitespace).unwrap_or((rest, "*"));
            Matcher::Method(m.to_ascii_uppercase(), Box::new(Matcher::parse(r)?))
        } else if lower.starts_with("header:") {
            let rest = &s[7..];
            let (n, v) = rest.split_once('=').unwrap_or((rest, ""));
            Matcher::Header(n.trim().to_string(), v.trim().to_lowercase())
        } else if lower.starts_with("bodyjson:") {
            let (u, j) = split_url_and_rest(&s[9..], "BODYJSON:<url> <json>")?;
            let v = serde_json::from_str(&j).map_err(|e| anyhow!("BODYJSON: {e}"))?;
            Matcher::BodyJson(Box::new(u), v)
        } else if lower.starts_with("graphql:") {
            let (u, j) = split_url_and_rest(&s[8..], "GRAPHQL:<url> {\"operationName\":…,\"variables\":…}")?;
            let v: serde_json::Value = serde_json::from_str(&j).map_err(|e| anyhow!("GRAPHQL: {e}"))?;
            let op = v.get("operationName").and_then(|o| o.as_str()).map(str::to_string);
            let vars = v.get("variables").cloned().unwrap_or(serde_json::Value::Null);
            let qh = match v.get("queryHash") {
                None | Some(serde_json::Value::Null) => None,
                Some(serde_json::Value::String(h)) if h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()) => Some(h.to_ascii_lowercase()),
                Some(_) => return Err(anyhow!("GRAPHQL: queryHash must be a SHA-256 in hex")),
            };
            Matcher::GraphQl(Box::new(u), op, vars, qh)
        } else if lower.starts_with("bodyhash:") {
            let (u, h) = split_url_and_rest(&s[9..], "BODYHASH:<url> <sha256 hex>")?;
            let h = h.strip_prefix("sha256:").unwrap_or(&h).to_ascii_lowercase();
            if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(anyhow!("BODYHASH: expects the SHA-256 of the request body in hex"));
            }
            Matcher::BodyHash(Box::new(u), h)
        } else if lower.starts_with("urlwithbody:") {
            let rest = s[12..].trim();
            let (u, b) = rest.split_once(char::is_whitespace).ok_or_else(|| anyhow!("URLWithBody:<url> <body regex>"))?;
            let b = b.trim().strip_prefix("regex:").unwrap_or(b.trim());
            Matcher::UrlWithBody(Box::new(Matcher::parse(u)?), Regex::new(b).map_err(|e| anyhow!("regex: {e}"))?)
        } else {
            Matcher::Contains(lower)
        })
    }

    /// Match by URL, method and headers only (rules that never look at a body).
    pub(crate) fn matches_head(&self, head: &RequestHead) -> bool {
        self.matches_in(&MatchCtx::new(head, None))
    }

    pub(crate) fn needs_body(&self) -> bool {
        match self {
            Matcher::UrlWithBody(..) | Matcher::BodyJson(..) | Matcher::GraphQl(..) | Matcher::BodyHash(..) => true,
            // `METHOD:POST URLWithBody:…` must buffer the body as well.
            Matcher::Method(_, inner) => inner.needs_body(),
            _ => false,
        }
    }

    #[cfg(test)]
    fn matches(&self, head: &RequestHead, body: Option<&Body>) -> bool {
        self.matches_in(&MatchCtx::new(head, body))
    }

    fn matches_in(&self, ctx: &MatchCtx) -> bool {
        let head = ctx.head;
        match self {
            Matcher::All => true,
            Matcher::Exact(u) => head.url == *u,
            Matcher::Prefix(p) => prefix_matches(p, &head.url),
            Matcher::Regex(r) => r.is_match(&head.url),
            Matcher::Not(t) => !head.url.to_lowercase().contains(t.as_str()),
            Matcher::Contains(t) => head.url.to_lowercase().contains(t.as_str()),
            Matcher::Method(m, inner) => head.method.eq_ignore_ascii_case(m) && inner.matches_in(ctx),
            Matcher::Header(n, v) => head.headers.get_all(n).any(|x| x.to_lowercase().contains(v.as_str())),
            Matcher::UrlWithBody(u, re) => u.matches_in(ctx) && ctx.text().is_some_and(|t| re.is_match(t)),
            Matcher::BodyJson(u, spec) => u.matches_in(ctx) && ctx.json().is_some_and(|v| json_matches(spec, v)),
            Matcher::GraphQl(u, op, vars, qh) => u.matches_in(ctx) && ctx.json().is_some_and(|v| graphql_matches(op, vars, qh, v)),
            Matcher::BodyHash(u, h) => u.matches_in(ctx) && ctx.sha() == Some(h.as_str()),
        }
    }

    /// What the action gets as "the rest of the URL" (see [`Rest`]). Only called after a match.
    fn rest(&self, url: &str) -> Rest {
        match self {
            Matcher::Prefix(p) => Rest::Prefix(url.get(p.len()..).unwrap_or("").to_string()),
            Matcher::Method(_, inner) | Matcher::UrlWithBody(inner, _) | Matcher::BodyJson(inner, _) | Matcher::GraphQl(inner, ..) | Matcher::BodyHash(inner, _) => inner.rest(url),
            Matcher::Regex(re) => re.captures(url).and_then(|c| c.get(1)).map(|m| Rest::Group(m.as_str().to_string())).unwrap_or(Rest::None),
            _ => Rest::None,
        }
    }
}

/// `prefix:` match (ASCII case-insensitive). A prefix that is only an origin
/// (`https://host[:port]`) must end at the authority of the URL too: the next character has to
/// be `/`, `?`, `#` or the end, so `https://prod.example.com` does not also match
/// `https://prod.example.com.evil.net/` or `https://prod.example.com:8443/`.
fn prefix_matches(p: &str, url: &str) -> bool {
    if !url.get(..p.len()).is_some_and(|x| x.eq_ignore_ascii_case(p)) {
        return false;
    }
    let origin_only = p.split_once("://").is_some_and(|(_, r)| !r.is_empty() && !r.contains(['/', '?', '#']));
    !origin_only || url[p.len()..].chars().next().is_none_or(|c| matches!(c, '/' | '?' | '#'))
}

/// The part of a matched URL that mapping actions carry over.
#[derive(Debug, Clone, PartialEq)]
enum Rest {
    None,
    /// Everything after a `prefix:` match (path rest and query).
    Prefix(String),
    /// Regex capture group 1.
    Group(String),
}

/// Map Remote: append the rest of the original URL to the target prefix. Joins `/` sensibly
/// (no `//`, a `/` after a bare origin) and merges two queries with `&`.
fn join_target(target: &str, rest: &str) -> String {
    if rest.is_empty() {
        return target.to_string();
    }
    let has_path = target.split_once("://").is_some_and(|(_, r)| r.contains(['/', '?', '#']));
    if target.ends_with('/') && rest.starts_with('/') {
        format!("{target}{}", &rest[1..])
    } else if rest.starts_with('?') && target.contains('?') {
        format!("{target}&{}", &rest[1..])
    } else if !has_path && !rest.starts_with(['/', '?', '#']) {
        format!("{target}/{rest}")
    } else {
        format!("{target}{rest}")
    }
}

fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = b.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok()).and_then(|h| u8::from_str_radix(h, 16).ok())?;
            out.push(h);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Why Map Local did not find a file (status + message for the synthetic response).
#[derive(Debug, PartialEq)]
struct LocalMiss(u16, String);

/// Map Local: resolve the URL rest `rel` inside `base`, never escaping it.
///
/// The query/fragment is cut off, the path percent-decoded once, and then rejected if any
/// segment is `..`, contains a backslash, NUL or (on Windows) a drive colon. Both the folder
/// and the final file are canonicalised and the file must still lie inside the folder, so a
/// symlink pointing outside is refused as well. Directories serve their `index.html`.
fn resolve_in_dir(base: &str, rel: &str) -> std::result::Result<PathBuf, LocalMiss> {
    let forbid = || LocalMiss(403, "[Quena] Map Local: the path leaves the mapped folder and was refused".into());
    let base_p = std::path::Path::new(base);
    if !base_p.is_absolute() {
        return Err(LocalMiss(500, format!("[Quena] Map Local: the folder must be an absolute path: {base}")));
    }
    let base_c = std::fs::canonicalize(base_p).map_err(|_| LocalMiss(404, format!("[Quena] Map Local: folder not found: {base}")))?;
    let rel = &rel[..rel.find(['?', '#']).unwrap_or(rel.len())];
    let decoded = percent_decode(rel).ok_or_else(|| LocalMiss(400, "[Quena] Map Local: invalid percent-encoding in the path".into()))?;
    let mut p = base_c.clone();
    let mut shown = String::new();
    for seg in decoded.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." || seg.contains(['\\', '\0']) || (cfg!(windows) && seg.contains(':')) {
            return Err(forbid());
        }
        p.push(seg);
        shown.push('/');
        shown.push_str(seg);
    }
    if shown.is_empty() {
        shown.push('/');
    }
    let not_found = || LocalMiss(404, format!("[Quena] Map Local: no file {shown} in {}", base_c.display()));
    let mut c = std::fs::canonicalize(&p).map_err(|_| not_found())?;
    if !c.starts_with(&base_c) {
        return Err(forbid());
    }
    if c.is_dir() {
        c = std::fs::canonicalize(c.join("index.html")).map_err(|_| LocalMiss(404, format!("[Quena] Map Local: {shown} is a folder without index.html in {}", base_c.display())))?;
        if !c.starts_with(&base_c) {
            return Err(forbid());
        }
    }
    if !c.is_file() {
        return Err(not_found());
    }
    Ok(c)
}

/// Map Local: resolve like [`resolve_in_dir`], open the file and check that the *opened*
/// handle still lies inside the folder. The path may be swapped for a symlink (or a folder on
/// the way for a link) between resolving and opening; the real path of the open handle tells
/// where the file actually is. Where the platform cannot tell (not Linux, macOS or Windows),
/// the check falls back to canonicalising the path again right after opening.
fn open_in_dir(base: &str, rel: &str) -> std::result::Result<(PathBuf, std::fs::File), LocalMiss> {
    let c = resolve_in_dir(base, rel)?;
    let base_c = std::fs::canonicalize(base).map_err(|_| LocalMiss(404, format!("[Quena] Map Local: folder not found: {base}")))?;
    let f = std::fs::File::open(&c).map_err(|e| LocalMiss(500, format!("[Quena] Map Local: cannot read {}: {e}", c.display())))?;
    verify_opened(&base_c, &c, &f)?;
    Ok((c, f))
}

/// The opened file must be a regular file whose real location is inside `base_c`.
fn verify_opened(base_c: &std::path::Path, path: &std::path::Path, f: &std::fs::File) -> std::result::Result<(), LocalMiss> {
    let forbid = || LocalMiss(403, "[Quena] Map Local: the path leaves the mapped folder and was refused".into());
    let real = opened_path(f).or_else(|_| std::fs::canonicalize(path)).map_err(|_| forbid())?;
    if !real.starts_with(base_c) {
        return Err(forbid());
    }
    if !f.metadata().is_ok_and(|m| m.is_file()) {
        return Err(LocalMiss(404, format!("[Quena] Map Local: {} is not a file", path.display())));
    }
    Ok(())
}

/// Where an open file really is (symlinks resolved), from the handle itself.
#[cfg(target_os = "linux")]
fn opened_path(f: &std::fs::File) -> std::io::Result<PathBuf> {
    use std::os::fd::AsRawFd;
    std::fs::read_link(format!("/proc/self/fd/{}", f.as_raw_fd()))
}

#[cfg(target_os = "macos")]
fn opened_path(f: &std::fs::File) -> std::io::Result<PathBuf> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    const F_GETPATH: std::ffi::c_int = 50;
    const MAXPATHLEN: usize = 1024;
    unsafe extern "C" {
        fn fcntl(fd: std::ffi::c_int, cmd: std::ffi::c_int, ...) -> std::ffi::c_int;
    }
    let mut buf = [0u8; MAXPATHLEN];
    // SAFETY: F_GETPATH writes a NUL-terminated path of at most MAXPATHLEN bytes into buf.
    if unsafe { fcntl(f.as_raw_fd(), F_GETPATH, buf.as_mut_ptr()) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(&buf[..n])))
}

#[cfg(windows)]
fn opened_path(f: &std::fs::File) -> std::io::Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;
    unsafe extern "system" {
        fn GetFinalPathNameByHandleW(file: *mut std::ffi::c_void, path: *mut u16, len: u32, flags: u32) -> u32;
    }
    // The same form std::fs::canonicalize returns (\\?\C:\…), so starts_with compares like with like.
    let mut buf = vec![0u16; 1024];
    loop {
        // SAFETY: the buffer is valid for buf.len() u16s; the handle belongs to `f`.
        let n = unsafe { GetFinalPathNameByHandleW(f.as_raw_handle() as *mut std::ffi::c_void, buf.as_mut_ptr(), buf.len() as u32, 0) } as usize;
        if n == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n < buf.len() {
            buf.truncate(n);
            return Ok(PathBuf::from(std::ffi::OsString::from_wide(&buf)));
        }
        buf.resize(n + 1, 0);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn opened_path(_f: &std::fs::File) -> std::io::Result<PathBuf> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

/// Map Remote with `*nocreds`: these request headers are removed when the host changes.
const CREDENTIAL_HEADERS: [&str; 3] = ["cookie", "authorization", "proxy-authorization"];

/// Split a trailing ` *nocreds` modifier off a Map Remote target.
fn split_nocreds(action: &str) -> (&str, bool) {
    let a = action.trim();
    match a.rsplit_once(char::is_whitespace) {
        Some((url, m)) if m.eq_ignore_ascii_case("*nocreds") => (url.trim_end(), true),
        _ => (a, false),
    }
}

/// Does Map Remote go to another origin (host or port), or from https down to http?
fn leaves_origin(from: &str, to: &str) -> bool {
    let https = |u: &str| u.get(..8).is_some_and(|x| x.eq_ignore_ascii_case("https://"));
    let auth = |u: &str| authority_of(u).map(|a| a.to_ascii_lowercase());
    auth(from) != auth(to) || (https(from) && !https(to))
}

/// Does this action read a local file (Map Local or a response file)? Those run off the
/// proxy's async workers.
/// The file or folder a mock rule action serves (`dir:folder` or a path), if any.
pub fn action_path(action: &str) -> Option<String> {
    if !reads_file(action) {
        return None;
    }
    let a = action.trim();
    Some(if a.len() >= 4 && a[..4].eq_ignore_ascii_case("dir:") { a[4..].trim() } else { a }.to_string())
}

fn reads_file(action: &str) -> bool {
    let a = action.trim_start().to_ascii_lowercase();
    a.starts_with("dir:") || !(a.starts_with('*') || a.starts_with("session:") || a.starts_with("http://") || a.starts_with("https://"))
}

struct Compiled {
    rule: Rule,
    matcher: Matcher,
    /// Kept outside `rule` so matching only needs a read lock.
    hits: AtomicU64,
}

pub(crate) fn guess_type(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase()).as_deref() {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("json") => "application/json",
        Some("js" | "mjs") => "application/javascript",
        Some("css") => "text/css",
        Some("xml") => "application/xml",
        Some("txt" | "log") => "text/plain; charset=utf-8",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("pdf") => "application/pdf",
        Some("wasm") => "application/wasm",
        Some("map") => "application/json",
        Some("csv") => "text/csv; charset=utf-8",
        Some("md") => "text/markdown; charset=utf-8",
        Some("yaml" | "yml") => "application/yaml",
        Some("avif") => "image/avif",
        Some("ttf") => "font/ttf",
        Some("otf") => "font/otf",
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        Some("mp3") => "audio/mpeg",
        _ => "application/octet-stream",
    }
}

// --------------------------------------------------------------- breakpoints

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct BreakpointState {
    /// Capture → Breakpoints → Before Requests.
    pub all_requests: bool,
    /// Capture → Breakpoints → After Responses.
    pub all_responses: bool,
    /// `bpu text`
    pub request_url: Option<String>,
    /// `bpafter text`
    pub response_url: Option<String>,
    /// `bps 500`
    pub status: Option<u16>,
    /// `bpv POST`
    pub method: Option<String>,
    /// Release paused sessions automatically after this many seconds (0 = never).
    pub timeout_s: u64,
}

impl BreakpointState {
    pub fn labels(&self) -> Vec<String> {
        let mut v = Vec::new();
        if self.all_requests {
            v.push("before requests".into());
        }
        if self.all_responses {
            v.push("after responses".into());
        }
        if let Some(u) = &self.request_url {
            v.push(format!("bpu {u}"));
        }
        if let Some(u) = &self.response_url {
            v.push(format!("bpafter {u}"));
        }
        if let Some(s) = self.status {
            v.push(format!("bps {s}"));
        }
        if let Some(m) = &self.method {
            v.push(format!("bpv {m}"));
        }
        v
    }
}

/// Decision taken in the UI for a paused session.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resume {
    /// "continue" | "breakOnResponse" | "abort" | "respond"
    pub action: String,
    /// Edited head (start line + headers) of the paused message.
    pub head_text: Option<String>,
    /// Replacement body text.
    pub body_text: Option<String>,
    /// Charset the body text was shown in; the text is encoded in the charset the (edited)
    /// Content-Type declares, else in this one, else UTF-8 (`quena_body::text::encode_edited`).
    #[serde(default)]
    pub body_charset: Option<String>,
    /// Replacement body from a file.
    pub body_file: Option<String>,
    /// For "respond": status code of a synthetic response.
    pub status: Option<u16>,
}

enum Waiter {
    Request(oneshot::Sender<Resume>),
    Response(oneshot::Sender<Resume>),
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PausedInfo {
    pub id: SessionId,
    pub phase: String,
    pub url: String,
    pub since: i64,
}

// ------------------------------------------------------------------ chain

pub struct Rules {
    core: RwLock<Weak<AppCore>>,
    ar: RwLock<AutoResponderState>,
    compiled: RwLock<Vec<Compiled>>,
    /// Serializes rule set changes (read-modify-write in [`Rules::update_autoresponder`]).
    edit: Mutex<()>,
    /// Serializes mock package operations (install, import, remove, reset): folder changes
    /// and the matching rule changes happen as one step.
    packages: Mutex<()>,
    next_rule: AtomicU64,
    bp: RwLock<BreakpointState>,
    paused: Mutex<HashMap<SessionId, (Waiter, PausedInfo)>>,
    /// Sessions that asked to break on the response (Break on Response / *bpafter).
    break_response: Mutex<std::collections::HashSet<SessionId>>,
    path: PathBuf,
    // ---- Scripting (M14)
    script: ScriptEngine,
    script_path: PathBuf,
    script_enabled: AtomicBool,
    /// Rewrite rules (body, header and status changes of real traffic).
    pub rewrite: crate::rewrite::Rewriter,
    /// Answers to LLM API calls served again (agent cache).
    pub llm_cache: crate::llm_cache::LlmCache,
}

fn parse_head_text(text: &str) -> (String, Headers) {
    let mut lines = text.lines();
    let first = lines.next().unwrap_or("").trim_end().to_string();
    let mut h = Headers::new();
    for l in lines {
        let l = l.trim_end_matches('\r');
        if l.trim().is_empty() {
            continue;
        }
        if let Some((k, v)) = l.split_once(':') {
            h.push(k.trim(), v.trim_start());
        }
    }
    (first, h)
}

/// Split a request URL into (host, path+query). Handles absolute URLs and the
/// `host:port` form used for CONNECT tunnels.
fn split_url_host_path(url: &str) -> (String, String) {
    let after_scheme = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    // The authority ends at the first '/', '?' or '#'.
    let auth_end = after_scheme.find(['/', '?', '#']).unwrap_or(after_scheme.len());
    let (authority, rest) = after_scheme.split_at(auth_end);
    // Drop any userinfo so it never leaks into the host field handed to scripts.
    let host_port = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
    let host = quena_query::host_without_port(host_port).to_string();
    let path = if rest.is_empty() {
        "/".to_string()
    } else if rest.starts_with('/') {
        rest.to_string()
    } else {
        format!("/{rest}")
    };
    (host, path)
}

/// The host[:port] authority of a request URL (for syncing the `Host` header on redirect).
fn authority_of(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, r)| r)?;
    let auth_end = after_scheme.find(['/', '?', '#']).unwrap_or(after_scheme.len());
    let authority = &after_scheme[..auth_end];
    let host_port = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
    (!host_port.is_empty()).then(|| host_port.to_string())
}

fn headers_to_pairs(h: &Headers) -> Vec<(String, String)> {
    h.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect()
}

fn pairs_to_headers(pairs: Vec<(String, String)>) -> Headers {
    let mut h = Headers::new();
    for (n, v) in pairs {
        h.push(n, v);
    }
    h
}

impl Rules {
    pub fn new(data_dir: &std::path::Path) -> Arc<Rules> {
        let path = data_dir.join("autoresponder.json");
        let ar: AutoResponderState = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_else(|e| {
                let aside = crate::keep_corrupt(&path);
                tracing::warn!(target: "quena", "mock rules unreadable ({e}); starting without rules, the old file was kept as {aside}");
                AutoResponderState::default()
            }),
            Err(_) => AutoResponderState::default(),
        };
        let max = ar.rules.iter().map(|r| r.id).max().unwrap_or(0);
        let r = Arc::new(Rules {
            core: RwLock::new(Weak::new()),
            ar: RwLock::new(AutoResponderState::default()),
            compiled: RwLock::new(vec![]),
            edit: Mutex::new(()),
            packages: Mutex::new(()),
            next_rule: AtomicU64::new(max + 1),
            bp: RwLock::new(BreakpointState { timeout_s: 0, ..Default::default() }),
            paused: Mutex::new(HashMap::new()),
            break_response: Mutex::new(Default::default()),
            path,
            script: ScriptEngine::new(),
            script_path: data_dir.join("rules.js"),
            script_enabled: AtomicBool::new(false),
            rewrite: crate::rewrite::Rewriter::load(data_dir),
            llm_cache: crate::llm_cache::LlmCache::load(data_dir),
        });
        let _ = r.set_autoresponder(ar, false);
        r
    }

    // ---- Scripting (M14)

    /// A cheap handle to the script engine (for async load/log queries).
    pub fn script_engine(&self) -> ScriptEngine {
        self.script.clone()
    }

    /// The current rules script source (the saved file, or the starter template).
    pub fn script_source(&self) -> String {
        std::fs::read_to_string(&self.script_path).unwrap_or_else(|_| quena_script::DEFAULT_SCRIPT.to_string())
    }

    /// Whether the user toggled scripting on.
    pub fn script_enabled(&self) -> bool {
        self.script_enabled.load(Ordering::Relaxed)
    }

    /// Scripting is on *and* a script compiled successfully.
    pub fn script_active(&self) -> bool {
        self.script_enabled() && self.script.is_loaded()
    }

    /// Save and hot-reload the script source. Returns the compile/boot error, if any.
    pub async fn set_script(&self, source: String) -> std::result::Result<(), String> {
        if let Err(e) = std::fs::write(&self.script_path, &source) {
            return Err(format!("save {}: {e}", self.script_path.display()));
        }
        self.script.load(source).await
    }

    /// Turn scripting on/off. When turning on, compile the saved script if not loaded.
    pub async fn set_script_enabled(&self, on: bool) -> std::result::Result<(), String> {
        self.script_enabled.store(on, Ordering::Relaxed);
        if on && !self.script.is_loaded() {
            let src = self.script_source();
            return self.script.load(src).await;
        }
        Ok(())
    }

    /// Menu commands the script registered via `Quena.registerMenu` (empty when off).
    pub fn script_menus(&self) -> Vec<String> {
        if self.script_active() { self.script.menus() } else { Vec::new() }
    }

    /// Title of the script's Custom column, if any (only when scripting is active).
    pub fn script_column_title(&self) -> Option<String> {
        if self.script_active() { self.script.column_title() } else { None }
    }

    /// Run a registered menu command over the given sessions, applying any
    /// comment/color/custom updates the handler returns. Returns how many
    /// sessions were updated.
    pub async fn run_script_menu(&self, index: usize, ids: &[SessionId]) -> std::result::Result<usize, String> {
        let core = self.core().ok_or_else(|| "core unavailable".to_string())?;
        let cap = core.capture();
        let sessions: Vec<serde_json::Value> = ids
            .iter()
            .filter_map(|id| {
                cap.detail(*id).map(|d| {
                    serde_json::json!({
                        "id": id,
                        "method": d.summary.method,
                        "url": d.summary.full_url(),
                        "status": d.summary.status,
                        "host": d.summary.host,
                        "process": d.summary.process,
                        "comment": d.summary.comment,
                        "contentType": d.summary.content_type,
                    })
                })
            })
            .collect();
        let ctx = serde_json::to_string(&sessions).map_err(|e| e.to_string())?;
        let out = self.script.run_menu(index, ctx).await?;
        let actions: Vec<quena_script::MenuAction> = serde_json::from_str(&out).unwrap_or_default();
        let mut n = 0;
        for a in actions {
            cap.update_summary(a.id, |s| {
                if let Some(c) = &a.comment {
                    s.comment = c.clone();
                }
                if let Some(c) = &a.color
                    && let Some(mc) = MarkColor::parse(c)
                {
                    s.color = Some(mc);
                }
                if let Some(c) = &a.custom {
                    s.custom = c.clone();
                }
            });
            n += 1;
        }
        Ok(n)
    }

    /// Apply a script's session metadata (comment/color/flags) to the live row.
    fn apply_meta(&self, s: &SessionView, meta: &SessionMeta) {
        if meta.is_empty() {
            return;
        }
        s.live.update(|d| {
            if let Some(c) = &meta.comment {
                d.summary.comment = c.clone();
            }
            if let Some(c) = &meta.color {
                // Only recolour on a recognised name; an unknown value must not
                // wipe an existing colour.
                if let Some(mc) = MarkColor::parse(c) {
                    d.summary.color = Some(mc);
                }
            }
            if let Some(c) = &meta.custom {
                d.summary.custom = c.clone();
            }
            for (k, v) in &meta.flags {
                if let Some(e) = d.extra_flags.iter_mut().find(|(ek, _)| ek == k) {
                    e.1 = v.clone();
                } else {
                    d.extra_flags.push((k.clone(), v.clone()));
                }
            }
        });
    }

    pub fn attach(&self, core: &Arc<AppCore>) {
        *self.core.write() = Arc::downgrade(core);
    }

    fn core(&self) -> Option<Arc<AppCore>> {
        self.core.read().upgrade()
    }

    // ---- AutoResponder API
    pub fn autoresponder(&self) -> AutoResponderState {
        let mut s = self.ar.read().clone();
        let c = self.compiled.read();
        for r in &mut s.rules {
            if let Some(x) = c.iter().find(|x| x.rule.id == r.id) {
                r.hits = x.hits.load(Ordering::Relaxed);
            }
        }
        s
    }

    /// Replace the rule set. Rules with invalid syntax are rejected.
    pub fn set_autoresponder(&self, s: AutoResponderState, save: bool) -> Result<()> {
        let _g = self.edit.lock();
        self.set_locked(s, save)
    }

    /// Change the rule set atomically: `f` gets the current state (with hits), and what it
    /// leaves is installed; no other change can slip in between (no lost updates).
    pub fn update_autoresponder<R>(&self, save: bool, f: impl FnOnce(&mut AutoResponderState) -> R) -> Result<R> {
        let _g = self.edit.lock();
        let mut s = self.autoresponder();
        let r = f(&mut s);
        self.set_locked(s, save)?;
        Ok(r)
    }

    /// Hold this while changing mock packages (folders plus their rules).
    pub fn package_lock(&self) -> parking_lot::MutexGuard<'_, ()> {
        self.packages.lock()
    }

    /// Set the hit counters of the rules `pred` selects back to 0 (sequences, `match_once`
    /// rules answer again from the start). Returns how many rules were reset.
    pub fn reset_hits(&self, pred: impl Fn(&Rule) -> bool) -> usize {
        let c = self.compiled.read();
        let mut n = 0;
        for x in c.iter().filter(|x| pred(&x.rule)) {
            x.hits.store(0, Ordering::Relaxed);
            n += 1;
        }
        n
    }

    fn set_locked(&self, mut s: AutoResponderState, save: bool) -> Result<()> {
        let mut compiled = Vec::new();
        let old = self.compiled.read();
        for r in &mut s.rules {
            if r.id == 0 {
                r.id = self.next_rule.fetch_add(1, Ordering::Relaxed);
            }
            let matcher = Matcher::parse(&r.match_).map_err(|e| anyhow!("rule '{}': {e}", r.match_))?;
            let rule = r.clone();
            let hits = old.iter().find(|x| x.rule.id == r.id).map(|x| x.hits.load(Ordering::Relaxed)).unwrap_or(0);
            compiled.push(Compiled { rule, matcher, hits: AtomicU64::new(hits) });
        }
        drop(old);
        *self.compiled.write() = compiled;
        *self.ar.write() = s.clone();
        if save {
            std::fs::write(&self.path, serde_json::to_vec_pretty(&s)?)?;
        }
        Ok(())
    }

    pub fn autoresponder_active(&self) -> bool {
        let s = self.ar.read();
        s.enabled && (s.rules.iter().any(|r| r.enabled) || !s.unmatched_passthrough)
    }

    /// Rules from sessions: exact URL → recorded response.
    pub fn add_rules_from_sessions(&self, ids: &[SessionId], exact: bool) -> Result<usize> {
        let core = self.core().ok_or_else(|| anyhow!("no core"))?;
        let cap = core.capture();
        let mut new = Vec::new();
        for id in ids {
            let Some(d) = cap.detail(*id) else { continue };
            if d.response.is_none() || d.summary.kind == SessionKind::Tunnel {
                continue;
            }
            let m = if exact { format!("EXACT:{}", d.request.url) } else { d.request.url.clone() };
            new.push(Rule { id: 0, match_: m, action: format!("session:{id}"), comment: format!("from #{id}"), ..Default::default() });
        }
        let n = new.len();
        self.update_autoresponder(true, |s| {
            for r in new {
                s.rules.insert(0, r);
            }
            s.enabled = true;
        })?;
        Ok(n)
    }

    /// Add one rule (first or last) and switch the mock rules on. Returns the new rule's id.
    pub fn add_rule(&self, rule: Rule, first: bool) -> Result<u64> {
        let _g = self.edit.lock();
        let mut s = self.autoresponder();
        let at = if first { 0 } else { s.rules.len() };
        s.rules.insert(at, Rule { id: 0, ..rule });
        s.enabled = true;
        self.set_locked(s, true)?;
        Ok(self.ar.read().rules[at].id)
    }

    // ---- Breakpoint API
    pub fn breakpoints(&self) -> BreakpointState {
        self.bp.read().clone()
    }

    pub fn set_breakpoints(&self, b: BreakpointState) {
        *self.bp.write() = b;
    }

    pub fn update_breakpoints(&self, f: impl FnOnce(&mut BreakpointState)) {
        f(&mut self.bp.write());
    }

    pub fn paused(&self) -> Vec<PausedInfo> {
        let mut v: Vec<PausedInfo> = self.paused.lock().values().map(|(_, i)| i.clone()).collect();
        v.sort_by_key(|p| p.id);
        v
    }

    pub fn resume(&self, id: SessionId, r: Resume) -> Result<()> {
        let (w, _) = self.paused.lock().remove(&id).ok_or_else(|| anyhow!("session #{id} is not paused"))?;
        let _ = match w {
            Waiter::Request(tx) => tx.send(r),
            Waiter::Response(tx) => tx.send(r),
        };
        Ok(())
    }

    /// Resume all paused sessions unchanged (`g`, toolbar "Go").
    pub fn go_all(&self) -> usize {
        let all: Vec<SessionId> = self.paused.lock().keys().copied().collect();
        let n = all.len();
        for id in all {
            let _ = self.resume(id, Resume { action: "continue".into(), head_text: None, body_text: None, body_charset: None, body_file: None, status: None });
        }
        n
    }

    fn bp_request(&self, s: &SessionView, head: &RequestHead) -> bool {
        if s.live.summary().has_flag(flags::BREAKPOINTED) && s.live.summary().has_flag(flags::REPLAYED | flags::COMPOSED) {
            return true;
        }
        let b = self.bp.read();
        b.all_requests
            || b.request_url.as_ref().is_some_and(|u| head.url.to_lowercase().contains(u.as_str()))
            || b.method.as_ref().is_some_and(|m| head.method.eq_ignore_ascii_case(m))
    }

    fn bp_response(&self, s: &SessionView, req: &RequestHead, resp: &ResponseHead) -> bool {
        if self.break_response.lock().contains(&s.id) {
            return true;
        }
        let b = self.bp.read();
        b.all_responses || b.response_url.as_ref().is_some_and(|u| req.url.to_lowercase().contains(u.as_str())) || b.status == Some(resp.status)
    }

    fn find_rule(&self, head: &RequestHead, body: Option<&Body>) -> Option<(Rule, Rest)> {
        let s = self.ar.read();
        if !s.enabled {
            return None;
        }
        drop(s);
        // Read lock only: bodies are decoded and parsed (once, in the context) while other
        // requests match concurrently; hits are atomic.
        let ctx = MatchCtx::new(head, body);
        let c = self.compiled.read();
        for x in c.iter() {
            if !x.rule.enabled || (x.rule.match_once && x.hits.load(Ordering::Relaxed) > 0) {
                continue;
            }
            if x.matcher.matches_in(&ctx) {
                if x.rule.match_once {
                    // Two requests at once: only one gets a match-once rule.
                    if x.hits.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_err() {
                        continue;
                    }
                } else {
                    x.hits.fetch_add(1, Ordering::Relaxed);
                }
                let mut rule = x.rule.clone();
                rule.hits = x.hits.load(Ordering::Relaxed);
                // Regex capture substitution ($1 …) in the action. Not for a Map Local
                // folder: it is taken literally, the URL rest is resolved inside it.
                if let Matcher::Regex(re) = &x.matcher
                    && rule.action.contains('$')
                    && !rule.action.trim_start().to_ascii_lowercase().starts_with("dir:")
                    && let Some(caps) = re.captures(&head.url)
                {
                    let mut out = String::new();
                    caps.expand(&rule.action, &mut out);
                    rule.action = out;
                }
                let rest = x.matcher.rest(&head.url);
                return Some((rule, rest));
            }
        }
        None
    }

    fn needs_request_body(&self) -> bool {
        self.ar.read().enabled && self.compiled.read().iter().any(|c| c.rule.enabled && c.matcher.needs_body())
    }

    fn synthetic(&self, status: u16, content_type: &str, body: &[u8], extra: &[(&str, String)]) -> Option<(ResponseHead, Body)> {
        let core = self.core()?;
        let mut h = Headers::new();
        h.push("Date", httpdate_now());
        h.push("Server", "Quena Mock Rules");
        if !content_type.is_empty() {
            h.push("Content-Type", content_type);
        }
        h.push("Content-Length", body.len().to_string());
        for (k, v) in extra {
            h.push(*k, v.clone());
        }
        let reason = crate::mock::reason(status).to_string();
        Some((ResponseHead { status, reason, version: HttpVersion::Http11, headers: h }, core.capture().bodies.store_bytes(body)))
    }

    /// Build a response from a file (raw `.dat` HTTP response or plain body). `method`: of
    /// the request (a HEAD response keeps the Content-Length of its file).
    fn file_response(&self, path: &str, method: &str) -> Option<(ResponseHead, Body)> {
        let core = self.core()?;
        let p = std::path::Path::new(path);
        let file = std::fs::File::open(p).ok();
        let Some(file) = file else {
            return self.synthetic(404, "text/plain; charset=utf-8", format!("[Quena] Mock Rules: file not found: {path}").as_bytes(), &[]);
        };
        let mut br = std::io::BufReader::new(file);
        use std::io::{BufRead, Read};
        let starts_http = br.fill_buf().map(|b| b.starts_with(b"HTTP/")).unwrap_or(false);
        let cap = core.capture();
        if starts_http
            && let Ok(Some((first, headers))) = quena_formats::raw::read_head(&mut br)
        {
            let (v, status, reason) = quena_formats::raw::parse_status_line(&first);
            let src: Box<dyn Read> = if quena_formats::raw::is_chunked(&headers) { Box::new(quena_formats::raw::ChunkedReader::new(br)) } else { Box::new(br) };
            let body = match copy_to_body(&cap.bodies, src) {
                Ok(b) => b,
                Err(e) => return self.synthetic(500, "text/plain; charset=utf-8", format!("[Quena] Mock Rules: cannot read {path}: {e}").as_bytes(), &[]),
            };
            let mut headers = headers;
            headers.remove("transfer-encoding");
            if status == 204 || status == 304 || (100..200).contains(&status) {
                // No body, no length (RFC 9110 8.6).
                headers.remove("content-length");
            } else if !(method.eq_ignore_ascii_case("HEAD") && body.is_empty() && headers.contains("content-length")) {
                headers.set("Content-Length", body.len().to_string());
            }
            return Some((ResponseHead { status, reason, version: v, headers }, body));
        }
        self.plain_file_response(p, br)
    }

    /// A 200 response with the file's bytes and a Content-Type guessed from its extension;
    /// a 500 if the file cannot be read to the end (never a cut-off 200).
    fn plain_file_response(&self, p: &std::path::Path, src: impl std::io::Read) -> Option<(ResponseHead, Body)> {
        let core = self.core()?;
        let cap = core.capture();
        let body = match copy_to_body(&cap.bodies, src) {
            Ok(b) => b,
            Err(e) => return self.synthetic(500, "text/plain; charset=utf-8", format!("[Quena] Mock Rules: cannot read {}: {e}", p.display()).as_bytes(), &[]),
        };
        let mut h = Headers::new();
        h.push("Date", httpdate_now());
        h.push("Server", "Quena Mock Rules");
        h.push("Content-Type", guess_type(p));
        h.push("Content-Length", body.len().to_string());
        h.push("Cache-Control", "no-cache");
        Some((ResponseHead { status: 200, reason: "OK".into(), version: HttpVersion::Http11, headers: h }, body))
    }

    fn session_response(&self, id: SessionId) -> Option<(ResponseHead, Body)> {
        let core = self.core()?;
        let cap = core.capture();
        let d = cap.detail(id)?;
        let mut head = d.response?;
        let (_, body) = cap.bodies_of(id)?;
        if quena_formats::raw::is_chunked(&head.headers) {
            head.headers.remove("transfer-encoding");
            head.headers.set("Content-Length", body.len().to_string());
        }
        Some((head, body))
    }

    /// Turn an AutoResponder action into a proxy action. `mapped` receives where a
    /// Map Remote (`true`) / Map Local (`false`) action sent the request (shown on the session).
    fn apply_action(&self, rule: &Rule, head: RequestHead, rest: &Rest, mapped: &mut Option<(bool, String)>) -> Option<RequestAction> {
        let latency = if self.ar.read().enable_latency { rule.latency_ms as u64 } else { 0 };
        let a = rule.action.trim();
        let lower = a.to_ascii_lowercase();
        let respond = |x: Option<(ResponseHead, Body)>| x.map(|(h, b)| RequestAction::Respond { head: h, body: b, delay_ms: latency });
        if lower.starts_with("dir:") {
            let dir = a[4..].trim();
            let rel = match rest {
                Rest::Prefix(r) | Rest::Group(r) => r.clone(),
                Rest::None => split_url_host_path(&head.url).1,
            };
            return match open_in_dir(dir, &rel) {
                Ok((p, f)) => {
                    *mapped = Some((false, format!("local file {}", p.display())));
                    respond(self.plain_file_response(&p, f))
                }
                Err(LocalMiss(code, msg)) => {
                    *mapped = Some((false, format!("{dir} (HTTP {code})")));
                    respond(self.synthetic(code, "text/plain; charset=utf-8", msg.as_bytes(), &[]))
                }
            };
        }
        if let Some(rest) = lower.strip_prefix('*') {
            if let Ok(code) = rest.parse::<u16>() {
                return respond(self.synthetic(code, "text/plain; charset=utf-8", format!("[Quena] Mock Rules: {code}").as_bytes(), &[]));
            }
            if let Some(ms) = rest.strip_prefix("delay:") {
                // At most an hour: a typo like *delay:99999999999 must not park requests forever.
                let d: u64 = ms.trim().parse::<u64>().unwrap_or(0).min(3_600_000);
                return Some(RequestAction::Forward { head: None, body: None, delay_ms: d.saturating_add(latency) });
            }
            if rest == "drop" || rest == "reset" || rest == "exit" {
                return Some(RequestAction::Abort);
            }
            if rest.starts_with("redir:") {
                let target = a[7..].trim().to_string();
                return respond(self.synthetic(307, "", b"", &[("Location", target)]));
            }
            if rest.starts_with("header:") {
                let spec = &a[8..];
                let (n, v) = spec.split_once('=').unwrap_or((spec, ""));
                let mut h = head;
                h.headers.set(n.trim(), v.trim());
                return Some(RequestAction::Forward { head: Some(h), body: None, delay_ms: latency });
            }
            if rest == "corspreflightallow" {
                let origin = head.headers.get("origin").unwrap_or("*").to_string();
                let req_h = head.headers.get("access-control-request-headers").unwrap_or("*").to_string();
                return respond(self.synthetic(
                    200,
                    "",
                    b"",
                    &[
                        ("Access-Control-Allow-Origin", origin),
                        ("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS".into()),
                        ("Access-Control-Allow-Headers", req_h),
                        ("Access-Control-Allow-Credentials", "true".into()),
                    ],
                ));
            }
            if rest == "bpu" || rest == "bpafter" {
                return None; // handled as breakpoint by the caller
            }
            return respond(self.synthetic(500, "text/plain", format!("[Quena] unknown AutoResponder action {a}").as_bytes(), &[]));
        }
        if let Some(id) = lower.strip_prefix("session:")
            && let Ok(id) = id.trim().parse()
        {
            return respond(self.session_response(id).or_else(|| self.synthetic(404, "text/plain", b"[Quena] session not found", &[])));
        }
        if lower.starts_with("http://") || lower.starts_with("https://") {
            // Retarget the request (Map Remote with a prefix: match keeps the rest of the URL).
            // The upstream client connects (and sends TLS SNI) from the URL; Host follows it.
            let (a, nocreds) = split_nocreds(a);
            let target = match rest {
                Rest::Prefix(r) => join_target(a, r),
                _ => a.to_string(),
            };
            let mut h = head;
            // `*nocreds`: cookies and credentials meant for the original host stay behind.
            if nocreds && leaves_origin(&h.url, &target) {
                for n in CREDENTIAL_HEADERS {
                    h.headers.remove(n);
                }
            }
            let host = authority_of(&target).unwrap_or_else(|| split_url(&target, "GET").0);
            *mapped = Some((true, target.clone()));
            h.url = target;
            h.headers.set("Host", host);
            return Some(RequestAction::Forward { head: Some(h), body: None, delay_ms: latency });
        }
        respond(self.file_response(a, &head.method))
    }

    async fn pause(self: Arc<Self>, s: SessionView, phase: &str, url: String) -> Resume {
        let (tx, rx) = oneshot::channel();
        let info = PausedInfo { id: s.id, phase: phase.into(), url, since: now_us() };
        self.paused.lock().insert(s.id, (if phase == "request" { Waiter::Request(tx) } else { Waiter::Response(tx) }, info.clone()));
        // Removes the entry also when this future is dropped (the client went away while
        // paused), so no dead breakpoint stays listed.
        struct Unpause<'a>(&'a Mutex<HashMap<SessionId, (Waiter, PausedInfo)>>, SessionId);
        impl Drop for Unpause<'_> {
            fn drop(&mut self) {
                self.0.lock().remove(&self.1);
            }
        }
        let unpause = Unpause(&self.paused, s.id);
        s.live.update(|d| {
            d.summary.flags |= flags::BREAKPOINTED;
            d.summary.state = if phase == "request" { SessionState::BreakpointRequest } else { SessionState::BreakpointResponse };
        });
        if let Some(c) = self.core() {
            c.emit("breakpoint", &info);
        }
        let timeout = self.bp.read().timeout_s;
        let r = if timeout > 0 {
            match tokio::time::timeout(Duration::from_secs(timeout), rx).await {
                Ok(Ok(r)) => r,
                _ => Resume { action: "continue".into(), head_text: None, body_text: None, body_charset: None, body_file: None, status: None },
            }
        } else {
            rx.await.unwrap_or(Resume { action: "continue".into(), head_text: None, body_text: None, body_charset: None, body_file: None, status: None })
        };
        drop(unpause);
        s.live.update(|d| {
            d.summary.state = if phase == "request" { SessionState::SendingRequest } else { SessionState::ReceivingResponse };
        });
        r
    }

    /// Bytes as a new body of the current capture.
    /// Whether the agent cache looks at this request (an LLM API call while it holds answers
    /// or caches every call).
    fn cache_wants(&self, head: &RequestHead) -> bool {
        self.llm_cache.active() && crate::llm::api_of(&head.method, &head.url).is_some()
    }

    fn store_bytes(&self, bytes: &[u8]) -> Option<Body> {
        Some(self.core()?.capture().bodies.store_bytes(bytes))
    }

    /// The replacement body for a resumed message with `headers` (edited text is encoded in the
    /// message's charset; if it needs UTF-8 instead, the Content-Type in `headers` says so).
    fn replacement_body(&self, r: &Resume, headers: &mut Headers) -> Option<Body> {
        let core = self.core()?;
        let cap = core.capture();
        if let Some(f) = &r.body_file {
            let mut w = cap.bodies.writer_with_limit(u64::MAX);
            let mut file = std::fs::File::open(f).ok()?;
            let mut buf = vec![0u8; 1 << 20];
            use std::io::Read;
            while let Ok(n) = file.read(&mut buf) {
                if n == 0 || w.write(&buf[..n]).is_err() {
                    break;
                }
            }
            return Some(w.finish());
        }
        let text = r.body_text.as_ref()?;
        let (bytes, content_type) = quena_body::text::encode_edited(text, headers.get("content-type"), r.body_charset.as_deref());
        if let Some(ct) = content_type {
            headers.set("Content-Type", ct);
        }
        Some(cap.bodies.store_bytes(&bytes))
    }
}

/// Copy a file into a new body. Read errors (and a capture store without room, which would
/// cut the body short) are errors, so no truncated response is served as complete.
fn copy_to_body(store: &Arc<quena_body::BodyStore>, mut src: impl std::io::Read) -> std::result::Result<Body, String> {
    let mut w = store.writer_with_limit(u64::MAX);
    let mut buf = vec![0u8; 1 << 20];
    loop {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => w.write(&buf[..n]).map_err(|e| e.to_string())?,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                let b = w.finish();
                store.delete(&b);
                return Err(e.to_string());
            }
        }
    }
    let body = w.finish();
    if body.is_truncated() {
        store.delete(&body);
        return Err("the capture store has no room for the file".into());
    }
    Ok(body)
}

fn httpdate_now() -> String {
    let t = time::OffsetDateTime::now_utc();
    const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        DAYS[t.weekday().number_days_from_monday() as usize],
        t.day(),
        MONTHS[t.month() as usize - 1],
        t.year(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// Name the rewrite rules that applied (or why they changed nothing) in the session comment.
fn note_rewrite(s: &SessionView, applied: &[crate::rewrite::Applied], changed: bool) {
    // Named in the comment: the rules that changed the message (or left a note), not those
    // that only marked or commented it.
    let names: Vec<String> = applied.iter().filter(|a| a.changed || !a.notes.is_empty()).flat_map(|a| a.names.iter().cloned()).collect();
    let notes: Vec<String> = applied.iter().flat_map(|a| a.notes.iter().cloned()).collect();
    // Marks and comments the rules give the session (also when the message stays as it is).
    let mark = applied.iter().rev().find_map(|a| a.meta.mark);
    let comments: Vec<String> = applied.iter().flat_map(|a| a.meta.comments.iter().cloned()).collect();
    let add = |d: &mut quena_model::SessionDetail, text: &str| {
        if d.summary.comment.is_empty() {
            d.summary.comment = text.to_string();
        } else if !d.summary.comment.contains(text) {
            d.summary.comment = format!("{}; {text}", d.summary.comment);
        }
    };
    if mark.is_some() || !comments.is_empty() {
        s.live.update(|d| {
            if let Some(c) = mark {
                d.summary.color = Some(c);
            }
            for c in &comments {
                add(d, c);
            }
        });
    }
    if names.is_empty() || (!changed && notes.is_empty()) {
        return;
    }
    let text = crate::rewrite::Applied { names, notes, ..Default::default() }.comment();
    s.live.update(move |d| {
        if changed {
            d.summary.flags |= flags::TAMPERED;
        }
        add(d, &text);
    });
}

fn fix_length(h: &mut Headers, body: &Body) {
    h.remove("transfer-encoding");
    h.set("Content-Length", body.len().to_string());
}

impl Interceptor for Rules {
    fn request_mode(&self, s: &SessionView, head: &RequestHead) -> Mode {
        if self.bp_request(s, head) || self.needs_request_body() || self.rewrite.request_needs_body(head) || self.cache_wants(head) {
            Mode::Buffer
        } else {
            Mode::Stream
        }
    }

    fn request_hold_limit(&self, s: &SessionView, head: &RequestHead) -> Option<u64> {
        // Breakpoints and body matchers need the whole body; only rewriting can give up.
        if self.bp_request(s, head) || self.needs_request_body() {
            None
        } else {
            let cache = if self.cache_wants(head) { crate::llm_cache::MAX_REQUEST as u64 } else { 0 };
            Some((self.rewrite.max_body() as u64).max(cache))
        }
    }

    fn on_request(&self, s: SessionView, head: RequestHead, body: Option<Body>) -> BoxFuture<RequestAction> {
        let this = self.core().and_then(|c| c.rules.clone());
        let Some(this) = this else { return Box::pin(async { RequestAction::forward() }) };
        Box::pin(async move {
            let mut head = head;
            let mut script_edited = false;
            // 1. AutoResponder
            let mut want_bp = false;
            if let Some((rule, rest)) = this.find_rule(&head, body.as_ref()) {
                let a = rule.action.trim().to_ascii_lowercase();
                if a == "*bpu" {
                    want_bp = true;
                } else if a == "*bpafter" {
                    this.break_response.lock().insert(s.id);
                } else {
                    // File work (Map Local, response files) runs on a blocking thread so large
                    // or slow files do not stall the proxy's async workers.
                    let (action, mapped) = if reads_file(&rule.action) {
                        let (t, r, h, rs) = (this.clone(), rule.clone(), head.clone(), rest.clone());
                        tokio::task::spawn_blocking(move || {
                            let mut mapped = None;
                            let a = t.apply_action(&r, h, &rs, &mut mapped);
                            (a, mapped)
                        })
                        .await
                        .unwrap_or_else(|_| (this.synthetic(500, "text/plain; charset=utf-8", b"[Quena] Mock Rules: reading the file failed", &[]).map(|(h, b)| RequestAction::Respond { head: h, body: b, delay_ms: 0 }), None))
                    } else {
                        let mut mapped = None;
                        let a = this.apply_action(&rule, head.clone(), &rest, &mut mapped);
                        (a, mapped)
                    };
                    if let Some(action) = action {
                        // Map Remote: the list shows the new target, so the comment names the
                        // original URL. Map Local: the list keeps the URL, the comment names the
                        // file. Session flags record both ends either way.
                        let original = head.url.clone();
                        s.live.update(|d| {
                            if d.summary.comment.is_empty() {
                                d.summary.comment = match &mapped {
                                    Some((true, _)) => format!("Mapped from {original}"),
                                    Some((false, to)) => format!("Mapped to {to}"),
                                    None => format!("Mock rule: {}", rule.match_),
                                };
                            }
                            if let Some((_, to)) = &mapped {
                                d.extra_flags.retain(|(k, _)| k != "x-quena-mapped-from" && k != "x-quena-mapped-to");
                                d.extra_flags.push(("x-quena-mapped-from".into(), original.clone()));
                                d.extra_flags.push(("x-quena-mapped-to".into(), to.clone()));
                            }
                        });
                        return action;
                    }
                }
            } else if this.ar.read().enabled
                && !this.ar.read().unmatched_passthrough
                && let Some((h, b)) = this.synthetic(404, "text/plain; charset=utf-8", b"[Quena] Mock Rules: no rule matched and unmatched requests are not passed through", &[])
            {
                return RequestAction::Respond { head: h, body: b, delay_ms: 0 };
            }
            // 1a. Agent cache: the same LLM API call answered before (mock rules came first;
            // a breakpoint on the request wins over the cache).
            if let Some(b) = &body
                && this.cache_wants(&head)
                && !want_bp
                && !this.bp_request(&s, &head)
            {
                let bytes = quena_body::text::decoded_prefix(b, &crate::dto::spec_of(&head.headers), crate::llm_cache::MAX_REQUEST + 1);
                if bytes.len() <= crate::llm_cache::MAX_REQUEST
                    && let Some(key) = crate::llm_cache::key_of(&head.method, &head.url, &head.headers, &bytes)
                {
                    // Reads the kept answer from disk: off the async workers.
                    let t = this.clone();
                    let found = tokio::task::spawn_blocking(move || t.llm_cache.hit(&key)).await.ok().flatten();
                    if let Some((e, answer)) = found
                        && let Some(body) = this.store_bytes(&answer)
                    {
                        let flag = crate::llm_cache::hit_flag(&e);
                        s.live.update(|d| {
                            d.extra_flags.retain(|(k, _)| k != crate::llm_cache::CACHE_FLAG);
                            d.extra_flags.push((crate::llm_cache::CACHE_FLAG.into(), flag.clone()));
                            if d.summary.comment.is_empty() {
                                d.summary.comment = format!("Agent cache: answer of #{}", e.source);
                            }
                        });
                        return RequestAction::Respond { head: crate::llm_cache::response_of(&e), body, delay_ms: 0 };
                    }
                }
            }
            // 1b. Script onBeforeRequest (heads/metadata only; bodies keep streaming).
            if this.script_active() && this.script.has_request_hook() {
                let (host, path) = split_url_host_path(&head.url);
                let info = RequestInfo {
                    id: s.id,
                    method: head.method.clone(),
                    url: head.url.clone(),
                    host,
                    path,
                    process: s.process.clone(),
                    client_ip: s.client_ip.clone(),
                    headers: headers_to_pairs(&head.headers),
                };
                match this.script.on_request(&info).await {
                    RequestDecision::Continue { method, url, headers, meta } => {
                        this.apply_meta(&s, &meta);
                        if let Some(m) = method {
                            head.method = m;
                            script_edited = true;
                        }
                        if let Some(u) = url {
                            // Keep the Host header in step with a redirect so vhosts resolve.
                            let old_auth = authority_of(&head.url);
                            let new_auth = authority_of(&u);
                            head.url = u;
                            if headers.is_none()
                                && new_auth != old_auth
                                && let Some(a) = new_auth
                            {
                                head.headers.set("Host", a);
                            }
                            script_edited = true;
                        }
                        if let Some(hs) = headers {
                            // The request body streams unchanged, so the framing headers
                            // must still describe it — restore them if the script dropped
                            // or altered them (M5: no truncation/hang from a bad length).
                            let orig_cl = head.headers.get("content-length").map(|s| s.to_string());
                            let orig_te = head.headers.get("transfer-encoding").map(|s| s.to_string());
                            head.headers = pairs_to_headers(hs);
                            match (orig_cl, orig_te) {
                                (Some(cl), _) => head.headers.set("Content-Length", cl),
                                (None, Some(te)) => head.headers.set("Transfer-Encoding", te),
                                (None, None) => head.headers.remove("content-length"),
                            }
                            script_edited = true;
                        }
                    }
                    RequestDecision::Respond { status, headers, body, meta } => {
                        this.apply_meta(&s, &meta);
                        let ct = headers
                            .iter()
                            .find(|(n, _)| n.eq_ignore_ascii_case("content-type"))
                            .map(|(_, v)| v.clone())
                            .unwrap_or_else(|| "text/plain; charset=utf-8".into());
                        let extra: Vec<(&str, String)> = headers
                            .iter()
                            .filter(|(n, _)| !n.eq_ignore_ascii_case("content-type") && !n.eq_ignore_ascii_case("content-length"))
                            .map(|(n, v)| (n.as_str(), v.clone()))
                            .collect();
                        if let Some((h, b)) = this.synthetic(status, &ct, body.as_bytes(), &extra) {
                            return RequestAction::Respond { head: h, body: b, delay_ms: 0 };
                        }
                    }
                    RequestDecision::Abort { meta } => {
                        this.apply_meta(&s, &meta);
                        return RequestAction::Abort;
                    }
                }
            }
            // 1c. Rewrite rules: after mocks and the script, before the breakpoint.
            let mut rewritten: Option<Body> = None;
            if this.rewrite.wants_request() {
                let mut names = Vec::new();
                if let Some((h, a)) = this.rewrite.request_head(&head) {
                    if a.changed {
                        head = h;
                        script_edited = true;
                    }
                    names.push(a);
                }
                if let Some(b) = body.clone() {
                    let (t, h) = (this.clone(), head.clone());
                    let _permit = this.rewrite.transform_permit(b.len()).await;
                    // Reads and parses up to the size limit: off the async workers.
                    if let Ok((out, a)) = tokio::task::spawn_blocking(move || t.rewrite.body(crate::rewrite::Phase::Request, &h, None, &h.headers, &b)).await {
                        if let Some((headers, bytes)) = out
                            && let Some(nb) = this.store_bytes(&bytes)
                        {
                            head.headers = headers;
                            fix_length(&mut head.headers, &nb);
                            s.live.set_request_body(nb.clone());
                            rewritten = Some(nb);
                            script_edited = true;
                        }
                        names.push(a);
                    }
                }
                note_rewrite(&s, &names, script_edited);
            }
            // 2. Breakpoint before request
            if want_bp || this.bp_request(&s, &head) {
                let r = this.clone().pause(s.clone(), "request", head.url.clone()).await;
                let mut new_head = r.head_text.as_ref().map(|t| {
                    let (first, headers) = parse_head_text(t);
                    let mut parts = first.splitn(3, ' ');
                    let method = parts.next().unwrap_or(&head.method).to_string();
                    let url = parts.next().unwrap_or(&head.url).to_string();
                    RequestHead { method, url, version: head.version, headers }
                });
                let mut head_edit = new_head.as_ref().map(|h| h.headers.clone()).unwrap_or_else(|| head.headers.clone());
                let new_body = this.replacement_body(&r, &mut head_edit).or_else(|| rewritten.clone());
                if new_body.is_some() {
                    // The body's charset may have changed the Content-Type.
                    let h = new_head.get_or_insert_with(|| head.clone());
                    h.headers = head_edit;
                }
                match r.action.as_str() {
                    "abort" => return RequestAction::Abort,
                    "respond" => {
                        let status = r.status.unwrap_or(200);
                        if let Some((h, b)) = this.synthetic(status, "text/plain; charset=utf-8", r.body_text.clone().unwrap_or_default().as_bytes(), &[]) {
                            return RequestAction::Respond { head: h, body: b, delay_ms: 0 };
                        }
                    }
                    "breakOnResponse" => {
                        this.break_response.lock().insert(s.id);
                    }
                    _ => {}
                }
                let mut head_out = new_head;
                if let (Some(h), Some(b)) = (head_out.as_mut(), new_body.as_ref()) {
                    fix_length(&mut h.headers, b);
                } else if let (None, Some(b)) = (&head_out, new_body.as_ref()) {
                    let mut h = head.clone();
                    fix_length(&mut h.headers, b);
                    head_out = Some(h);
                } else if head_out.is_none() && script_edited {
                    // Carry the script's head edits through the breakpoint.
                    head_out = Some(head.clone());
                }
                return RequestAction::Forward { head: head_out, body: new_body, delay_ms: 0 };
            }
            if script_edited {
                RequestAction::Forward { head: Some(head), body: rewritten, delay_ms: 0 }
            } else {
                RequestAction::forward()
            }
        })
    }

    fn wants_response_head(&self, _s: &SessionView) -> bool {
        (self.script_active() && self.script.has_response_hook()) || self.rewrite.wants_response()
    }

    fn on_response_head(&self, s: SessionView, resp: ResponseHead) -> BoxFuture<quena_proxy::ResponseHeadAction> {
        use quena_proxy::ResponseHeadAction;
        let this = self.core().and_then(|c| c.rules.clone());
        let Some(this) = this else { return Box::pin(async { ResponseHeadAction::Continue }) };
        let script = this.script_active() && this.script.has_response_hook();
        let rewrite = this.rewrite.wants_response();
        if !script && !rewrite {
            return Box::pin(async { ResponseHeadAction::Continue });
        }
        Box::pin(async move {
            let mut changed: Option<ResponseHead> = None;
            if script {
                let info = ResponseInfo {
                    id: s.id,
                    url: s.live.detail().request.url,
                    status: resp.status,
                    reason: resp.reason.clone(),
                    headers: headers_to_pairs(&resp.headers),
                };
                match this.script.on_response(&info).await {
                    ResponseDecision::Continue { status, headers, meta } => {
                        this.apply_meta(&s, &meta);
                        if status.is_some() || headers.is_some() {
                            let mut h = resp.clone();
                            if let Some(st) = status {
                                h.status = st;
                                h.reason = crate::mock::reason(st).to_string();
                            }
                            if let Some(hs) = headers {
                                // The response body streams unchanged, so keep the framing
                                // headers consistent (M5).
                                let orig_cl = h.headers.get("content-length").map(|s| s.to_string());
                                let orig_te = h.headers.get("transfer-encoding").map(|s| s.to_string());
                                h.headers = pairs_to_headers(hs);
                                match (orig_cl, orig_te) {
                                    (Some(cl), _) => h.headers.set("Content-Length", cl),
                                    (None, Some(te)) => h.headers.set("Transfer-Encoding", te),
                                    (None, None) => h.headers.remove("content-length"),
                                }
                            }
                            changed = Some(h);
                        }
                    }
                    ResponseDecision::Abort { meta } => {
                        this.apply_meta(&s, &meta);
                        return ResponseHeadAction::Abort;
                    }
                }
            }
            if rewrite {
                // Rewrite rules never touch the framing headers, so the body streams as is.
                let req = s.live.detail().request;
                if let Some((h, a)) = this.rewrite.response_head(&req, changed.as_ref().unwrap_or(&resp)) {
                    let edited = a.changed;
                    if edited {
                        changed = Some(h);
                    }
                    note_rewrite(&s, &[a], edited);
                }
            }
            match changed {
                Some(h) => ResponseHeadAction::Replace(h),
                None => ResponseHeadAction::Continue,
            }
        })
    }

    fn response_mode(&self, s: &SessionView, req: &RequestHead, resp: &ResponseHead) -> Mode {
        if self.bp_response(s, req, resp) || self.rewrite.response_needs_body(req, resp) { Mode::Buffer } else { Mode::Stream }
    }

    fn response_hold_limit(&self, s: &SessionView, req: &RequestHead, resp: &ResponseHead) -> Option<u64> {
        if self.bp_response(s, req, resp) { None } else { Some(self.rewrite.max_body() as u64) }
    }

    fn on_response(&self, s: SessionView, resp: ResponseHead, body: Body) -> BoxFuture<ResponseAction> {
        let this = self.core().and_then(|c| c.rules.clone());
        let Some(this) = this else { return Box::pin(async { ResponseAction::Continue }) };
        Box::pin(async move {
            let req = s.live.detail().request;
            // Buffered for a breakpoint, a rewrite, or both.
            let bp = this.bp_response(&s, &req, &resp);
            this.break_response.lock().remove(&s.id);
            let mut resp = resp;
            let mut rewritten: Option<Body> = None;
            if this.rewrite.response_needs_body(&req, &resp) {
                let (t, h) = (this.clone(), resp.clone());
                let _permit = this.rewrite.transform_permit(body.len()).await;
                // Reads and parses up to the size limit: off the async workers.
                if let Ok((out, a)) = tokio::task::spawn_blocking(move || t.rewrite.body(crate::rewrite::Phase::Response, &req, Some(h.status), &h.headers, &body)).await {
                    if let Some((headers, bytes)) = out
                        && let Some(nb) = this.store_bytes(&bytes)
                    {
                        resp.headers = headers;
                        fix_length(&mut resp.headers, &nb);
                        // A breakpoint shows the rewritten message.
                        s.live.set_response_body(nb.clone());
                        let h = resp.clone();
                        s.live.update(move |d| {
                            d.response = Some(h);
                            d.summary.flags |= flags::TAMPERED;
                        });
                        rewritten = Some(nb);
                    }
                    note_rewrite(&s, &[a], rewritten.is_some());
                }
            }
            if !bp {
                return match rewritten {
                    Some(b) => ResponseAction::Replace { head: resp, body: Some(b) },
                    None => ResponseAction::Continue,
                };
            }
            let url = s.live.detail().request.url;
            let r = this.clone().pause(s.clone(), "response", url).await;
            if r.action == "abort" {
                return ResponseAction::Abort;
            }
            let mut head = match &r.head_text {
                Some(t) => {
                    let (first, headers) = parse_head_text(t);
                    let (v, status, reason) = quena_formats::raw::parse_status_line(&first);
                    ResponseHead { status: if status == 0 { resp.status } else { status }, reason, version: v, headers }
                }
                None => resp.clone(),
            };
            let body = this.replacement_body(&r, &mut head.headers).or(rewritten);
            match (&r.head_text, body) {
                (None, None) => ResponseAction::Continue,
                (_, body) => {
                    if let Some(b) = &body {
                        fix_length(&mut head.headers, b);
                    }
                    ResponseAction::Replace { head, body }
                }
            }
        })
    }

    fn wants_ws(&self, s: &SessionView) -> bool {
        (self.script_active() && self.script.has_ws_hook()) || self.rewrite.wants_ws(&s.live.detail().request)
    }

    fn on_ws_message(&self, s: SessionView, dir: u8, opcode: u8, payload: Vec<u8>) -> BoxFuture<quena_proxy::WsAction> {
        use quena_proxy::WsAction;
        let this = self.core().and_then(|c| c.rules.clone());
        Box::pin(async move {
            let Some(this) = this else { return WsAction::Forward };
            let req = s.live.detail().request;
            // 1. Rewrite rules (text messages), 2. the script's onWebSocketMessage.
            let mut cur: Option<Vec<u8>> = None;
            if opcode == 0x1
                && let Ok(text) = std::str::from_utf8(&payload)
            {
                // Large messages (regexes, JSON paths over up to 1 MB) off the async workers.
                let out = if payload.len() >= 64 << 10 {
                    let (t, r, p) = (this.clone(), req.clone(), text.to_string());
                    let _permit = this.rewrite.transform_permit(payload.len() as u64).await;
                    tokio::task::spawn_blocking(move || t.rewrite.ws_message(&r, dir, &p)).await.ok().flatten()
                } else {
                    this.rewrite.ws_message(&req, dir, text)
                };
                cur = out.map(String::into_bytes);
            }
            if this.script_active() && this.script.has_ws_hook() {
                let text = (opcode == 0x1).then(|| String::from_utf8_lossy(cur.as_deref().unwrap_or(&payload)).into_owned());
                let msg = quena_script::WsMessage {
                    id: s.id,
                    url: req.url.clone(),
                    direction: if dir == quena_model::wslog::DIR_CLIENT { "up" } else { "down" }.into(),
                    is_binary: opcode == 0x2,
                    text,
                    size: payload.len(),
                };
                match this.script.on_ws_message(&msg).await {
                    quena_script::WsDecision::Drop => return WsAction::Drop,
                    quena_script::WsDecision::Replace(t) => cur = Some(t.into_bytes()),
                    quena_script::WsDecision::Forward => {}
                }
            }
            match cur {
                Some(p) if p != payload => WsAction::Replace(p),
                _ => WsAction::Forward,
            }
        })
    }

    fn on_complete(&self, s: &SessionView) {
        self.break_response.lock().remove(&s.id);
        // Calls to LLM APIs get their model, tokens and cost (parsed off the proxy's threads).
        let summary = s.live.summary();
        if crate::llm::api_of(&summary.method, &summary.full_url()).is_some()
            && let Some(core) = self.core()
        {
            core.llm_mark_later(s.id);
        }
        // Exchanges with MCP servers get their method, tool and server.
        let mcp_header = |h: &quena_model::Headers| h.get("mcp-session-id").is_some() || h.get("mcp-protocol-version").is_some();
        let has_header = { let d = s.live.detail(); mcp_header(&d.request.headers) || d.response.as_ref().is_some_and(|r| mcp_header(&r.headers)) };
        if crate::mcp_traffic::candidate(&summary.method, &summary.full_url(), has_header)
            && let Some(core) = self.core()
        {
            core.mcp_mark_later(s.id);
        }
        if self.script_active() && self.script.has_complete_hook() {
            let d = s.live.detail();
            self.script.on_complete(serde_json::json!({
                "id": s.id,
                "method": d.summary.method,
                "url": d.summary.full_url(),
                "status": d.summary.status,
                "host": d.summary.host,
                "process": d.summary.process,
            }));
        }
    }
}

// ------------------------------------------------------------------- .farx

pub fn export_farx(s: &AutoResponderState) -> String {
    let esc = |x: &str| x.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<AutoResponder LastSave=\"");
    out.push_str(&httpdate_now());
    out.push_str("\" FiddlerVersion=\"Quena\">\r\n");
    out.push_str(&format!("  <State Enabled=\"{}\" Fallthrough=\"{}\" UseLatency=\"{}\">\r\n", s.enabled, s.unmatched_passthrough, s.enable_latency));
    let one_shot = s.rules.iter().filter(|r| r.match_once && !r.action.starts_with("session:")).count();
    if one_shot > 0 {
        // .farx has no "match once": of a sequence (a chain of match-once rules), only the
        // last (fallback) rule is exported.
        out.push_str(&format!("    <!-- {one_shot} match-once rule(s) left out (.farx cannot express them); sequences keep their last response -->\r\n"));
    }
    for r in &s.rules {
        if r.action.starts_with("session:") {
            continue; // session-backed rules are local to this capture
        }
        if r.match_once {
            continue;
        }
        out.push_str(&format!(
            "    <ResponseRule Match=\"{}\" Action=\"{}\" Enabled=\"{}\" Latency=\"{}\" />\r\n",
            esc(&r.match_),
            esc(&r.action),
            r.enabled,
            r.latency_ms
        ));
    }
    out.push_str("  </State>\r\n</AutoResponder>\r\n");
    out
}

pub fn import_farx(xml: &str) -> Result<AutoResponderState> {
    use quick_xml::events::Event;
    let mut r = quick_xml::Reader::from_str(xml);
    let mut s = AutoResponderState::default();
    loop {
        match r.read_event() {
            Ok(Event::Empty(e)) | Ok(Event::Start(e)) => {
                let attrs: HashMap<String, String> = e
                    .attributes()
                    .flatten()
                    .map(|a| (String::from_utf8_lossy(a.key.as_ref()).to_ascii_lowercase(), a.unescape_value().map(|v| v.into_owned()).unwrap_or_default()))
                    .collect();
                match e.name().as_ref() {
                    b"State" => {
                        s.enabled = attrs.get("enabled").is_some_and(|v| v.eq_ignore_ascii_case("true"));
                        s.unmatched_passthrough = attrs.get("fallthrough").is_none_or(|v| v.eq_ignore_ascii_case("true"));
                        s.enable_latency = attrs.get("uselatency").is_some_and(|v| v.eq_ignore_ascii_case("true"));
                    }
                    b"ResponseRule" => s.rules.push(Rule {
                        id: 0,
                        enabled: attrs.get("enabled").is_none_or(|v| v.eq_ignore_ascii_case("true")),
                        match_: attrs.get("match").cloned().unwrap_or_default(),
                        action: attrs.get("action").cloned().unwrap_or_default(),
                        latency_ms: attrs.get("latency").and_then(|v| v.parse().ok()).unwrap_or(0),
                        ..Default::default()
                    }),
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(anyhow!("invalid .farx: {e}")),
            _ => {}
        }
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn head(m: &str, url: &str) -> RequestHead {
        RequestHead { method: m.into(), url: url.into(), version: HttpVersion::Http11, headers: Headers::new() }
    }
    #[test]
    fn matchers() {
        let h = head("POST", "https://api.x.de/login?a=1");
        for (m, want) in [
            ("*", true),
            ("login", true),
            ("LOGIN", true),
            ("exact:https://api.x.de/login?a=1", true),
            ("exact:https://api.x.de/login", false),
            ("regex:^https://.*\\.x\\.de/log", true),
            ("NOT:login", false),
            ("METHOD:POST login", true),
            ("METHOD:GET login", false),
        ] {
            assert_eq!(Matcher::parse(m).unwrap().matches(&h, None), want, "{m}");
        }
    }
    #[test]
    fn body_json_and_graphql_matchers() {
        let d = tempfile::tempdir().unwrap();
        let store = quena_body::BodyStore::open(d.path(), Default::default()).unwrap();
        let h = head("POST", "https://api.x.de/graphql");
        let body = |s: &str| store.store_bytes(s.as_bytes());
        let m = Matcher::parse(r#"METHOD:POST BODYJSON:EXACT:https://api.x.de/graphql {"a":1,"b":[1,2],"p":"${json-unit.ignore}"}"#).unwrap();
        assert!(m.needs_body());
        assert!(m.matches(&h, Some(&body(r#"{ "p": "anything", "b": [1, 2], "a": 1.0 }"#))));
        assert!(!m.matches(&h, Some(&body(r#"{"a":1,"b":[2,1],"p":1}"#))), "arrays keep their order");
        assert!(!m.matches(&h, Some(&body(r#"{"a":1,"b":[1,2],"p":1,"extra":true}"#))));
        assert!(!m.matches(&h, Some(&body("not json"))));
        assert!(!m.matches(&h, None));
        assert!(!m.matches(&head("GET", "https://api.x.de/graphql"), Some(&body(r#"{"a":1,"b":[1,2],"p":0}"#))));
        let g = Matcher::parse(r#"GRAPHQL:EXACT:https://api.x.de/graphql {"operationName":"GetUser","variables":{"id":7}}"#).unwrap();
        assert!(g.matches(&h, Some(&body(r#"{"query":"query GetUser { … }","operationName":"GetUser","variables":{"id":7}}"#))));
        assert!(!g.matches(&h, Some(&body(r#"{"query":"…","operationName":"GetUser","variables":{"id":8}}"#))));
        assert!(!g.matches(&h, Some(&body(r#"{"query":"…","operationName":"Other","variables":{"id":7}}"#))));
        let g = Matcher::parse(r#"GRAPHQL:EXACT:https://api.x.de/graphql {"operationName":"Me","variables":null}"#).unwrap();
        assert!(g.matches(&h, Some(&body(r#"{"query":"…","operationName":"Me","variables":{}}"#))));
        assert!(g.matches(&h, Some(&body(r#"{"query":"…","operationName":"Me"}"#))));
        assert!(Matcher::parse("BODYJSON:EXACT:https://x/ {broken").is_err());
        // URLWithBody behind METHOD: buffers the body too.
        assert!(Matcher::parse("METHOD:POST URLWithBody:/soap regex:GetOrder").unwrap().needs_body());
        // Gzip-encoded request bodies are compared decoded.
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, br#"{"a":1,"b":[1,2],"p":"x"}"#).unwrap();
        let mut hz = h.clone();
        hz.headers.push("Content-Encoding", "gzip");
        assert!(m.matches(&hz, Some(&store.store_bytes(&gz.finish().unwrap()))));
    }

    #[test]
    fn exact_integers_hashes_and_graphql_queries() {
        let d = tempfile::tempdir().unwrap();
        let store = quena_body::BodyStore::open(d.path(), Default::default()).unwrap();
        let h = head("POST", "https://api.x.de/x");
        let body = |s: &str| store.store_bytes(s.as_bytes());
        // Integers beyond 2^53 compare exactly; 1 and 1.0 stay equal.
        let m = Matcher::parse(r#"BODYJSON:EXACT:https://api.x.de/x {"id":9007199254740993,"n":1}"#).unwrap();
        assert!(m.matches(&h, Some(&body(r#"{"id":9007199254740993,"n":1.0}"#))));
        assert!(!m.matches(&h, Some(&body(r#"{"id":9007199254740992,"n":1}"#))));
        assert!(!json_matches(&serde_json::json!(u64::MAX), &serde_json::json!(u64::MAX - 1)));
        // BODYHASH: SHA-256 of the decoded body.
        let text = "a=1&b=".to_string() + &"x".repeat(100_000);
        let m = Matcher::parse(&format!("METHOD:POST BODYHASH:EXACT:https://api.x.de/x {}", sha256_hex(text.as_bytes()))).unwrap();
        assert!(m.needs_body());
        assert!(m.matches(&h, Some(&body(&text))));
        assert!(!m.matches(&h, Some(&body(&(text.clone() + "y")))));
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, text.as_bytes()).unwrap();
        let mut hz = h.clone();
        hz.headers.push("Content-Encoding", "gzip");
        assert!(m.matches(&hz, Some(&store.store_bytes(&gz.finish().unwrap()))));
        assert!(Matcher::parse("BODYHASH:EXACT:https://x/ abc").is_err());
        // URLWithBody compares the decoded body.
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, b"user=al").unwrap();
        let m = Matcher::parse("URLWithBody:EXACT:https://api.x.de/x regex:^user=al$").unwrap();
        assert!(m.matches(&hz, Some(&store.store_bytes(&gz.finish().unwrap()))));
        // GraphQL query hash: formatting does not matter, the query does.
        assert_eq!(graphql_query_hash("query { a b }"), graphql_query_hash("query {\n  a,\n  b # c\n}"));
        assert_ne!(graphql_query_hash("{ a }"), graphql_query_hash("{ b }"));
        assert_ne!(graphql_query_hash(r#"{ a(s:"x  y") }"#), graphql_query_hash(r#"{ a(s:"x y") }"#));
        let g = Matcher::parse(&format!(r#"GRAPHQL:EXACT:https://api.x.de/x {{"variables":{{"id":1}},"queryHash":"{}"}}"#, graphql_query_hash("{ user(id:$id) { name } }"))).unwrap();
        assert!(g.matches(&h, Some(&body(r#"{"query":"{ user(id: $id) {\n name } }","variables":{"id":1}}"#))));
        assert!(!g.matches(&h, Some(&body(r#"{"query":"{ user(id: $id) { email } }","variables":{"id":1}}"#))));
        assert!(!g.matches(&h, Some(&body(r#"{"query":"{ user(id: $id) { name } }","operationName":"X","variables":{"id":1}}"#))));
    }

    #[test]
    fn farx_leaves_out_match_once() {
        let r = |m: &str, once: bool| Rule { match_: m.into(), action: "*200".into(), match_once: once, ..Default::default() };
        let s = AutoResponderState { rules: vec![r("EXACT:http://a/1", true), r("EXACT:http://a/1", false), r("EXACT:http://a/2", false)], ..Default::default() };
        let x = export_farx(&s);
        assert!(x.contains("1 match-once rule(s) left out"), "{x}");
        let back = import_farx(&x).unwrap();
        assert_eq!(back.rules.iter().map(|r| r.match_.as_str()).collect::<Vec<_>>(), ["EXACT:http://a/1", "EXACT:http://a/2"]);
    }

    #[test]
    fn farx_roundtrip() {
        let s = AutoResponderState {
            enabled: true,
            unmatched_passthrough: false,
            enable_latency: true,
            rules: vec![Rule { match_: "regex:(?i)^https://a/<x>".into(), action: "*404".into(), latency_ms: 20, ..Default::default() }],
        };
        let back = import_farx(&export_farx(&s)).unwrap();
        assert_eq!(back.rules[0].match_, s.rules[0].match_);
        assert!(!back.unmatched_passthrough);
        assert_eq!(back.rules[0].latency_ms, 20);
    }

    #[test]
    fn split_url_host_path_edges() {
        assert_eq!(split_url_host_path("http://example.com/a/b?q=1"), ("example.com".into(), "/a/b?q=1".into()));
        // userinfo must not leak into the host field
        assert_eq!(split_url_host_path("http://user:pass@example.com/x"), ("example.com".into(), "/x".into()));
        // query with no path
        assert_eq!(split_url_host_path("http://example.com?q=1"), ("example.com".into(), "/?q=1".into()));
        // port is stripped from host
        assert_eq!(split_url_host_path("https://example.com:8443/p"), ("example.com".into(), "/p".into()));
        // bracketed IPv6 with port (brackets kept, consistent with the rest of the app)
        assert_eq!(split_url_host_path("http://[::1]:8080/p"), ("[::1]".into(), "/p".into()));
        // CONNECT-style host:port
        assert_eq!(split_url_host_path("example.com:443").0, "example.com");
    }

    #[test]
    fn authority_of_edges() {
        assert_eq!(authority_of("http://example.com/x"), Some("example.com".into()));
        assert_eq!(authority_of("http://example.com:8080/x"), Some("example.com:8080".into()));
        assert_eq!(authority_of("http://user@example.com/x"), Some("example.com".into()));
        assert_eq!(authority_of("example.com:443"), None); // no scheme
    }

    #[test]
    fn prefix_and_join_target() {
        let m = Matcher::parse("prefix:https://Prod.example.com/api/").unwrap();
        let h = head("GET", "https://prod.example.com/api/users?id=1");
        assert!(m.matches(&h, None));
        assert_eq!(m.rest(&h.url), Rest::Prefix("users?id=1".into()));
        assert!(!m.matches(&head("GET", "https://prod.example.com/other"), None));
        assert!(Matcher::parse("prefix:").is_err());
        assert_eq!(join_target("https://s.example.com/api/", "users?id=1"), "https://s.example.com/api/users?id=1");
        assert_eq!(join_target("https://s.example.com/api/", "/users"), "https://s.example.com/api/users");
        assert_eq!(join_target("https://s.example.com", "users"), "https://s.example.com/users");
        assert_eq!(join_target("https://s.example.com", "/users?x"), "https://s.example.com/users?x");
        assert_eq!(join_target("https://s.example.com/x?k=1", "?q=2"), "https://s.example.com/x?k=1&q=2");
        assert_eq!(join_target("https://s.example.com/v2", ""), "https://s.example.com/v2");
    }

    #[test]
    fn map_local_resolution() {
        let d = tempfile::tempdir().unwrap();
        let base = d.path().join("site");
        std::fs::create_dir_all(base.join("sub")).unwrap();
        std::fs::write(base.join("sub/index.html"), "x").unwrap();
        std::fs::write(base.join("a b.txt"), "x").unwrap();
        let b = base.to_str().unwrap();
        assert!(resolve_in_dir(b, "sub/").unwrap().ends_with("sub/index.html"));
        assert!(resolve_in_dir(b, "a%20b.txt?v=1").unwrap().ends_with("a b.txt"));
        assert_eq!(resolve_in_dir(b, "../site/a%20b.txt").unwrap_err().0, 403);
        assert_eq!(resolve_in_dir(b, "%2e%2e/x").unwrap_err().0, 403);
        assert_eq!(resolve_in_dir(b, "x%5c..%5cy").unwrap_err().0, 403);
        assert_eq!(resolve_in_dir(b, "%00").unwrap_err().0, 403);
        assert_eq!(resolve_in_dir(b, "%zz").unwrap_err().0, 400);
        assert_eq!(resolve_in_dir(b, "nope").unwrap_err().0, 404);
        assert_eq!(resolve_in_dir(b, "").unwrap_err().0, 404); // folder without index.html
        assert_eq!(resolve_in_dir("relative/dir", "x").unwrap_err().0, 500);
    }

    #[test]
    fn origin_prefix_needs_a_boundary() {
        let m = Matcher::parse("prefix:https://prod.example.com").unwrap();
        for (url, want) in [
            ("https://prod.example.com", true),
            ("https://prod.example.com/", true),
            ("https://PROD.example.com/a?b", true),
            ("https://prod.example.com?q=1", true),
            ("https://prod.example.com#f", true),
            ("https://prod.example.com.evil.net/x", false),
            ("https://prod.example.com:8443/x", false),
            ("https://prod.example.comx/", false),
        ] {
            assert_eq!(m.matches(&head("GET", url), None), want, "{url}");
        }
        let m = Matcher::parse("prefix:http://localhost:3000").unwrap();
        assert!(m.matches(&head("GET", "http://localhost:3000/api"), None));
        assert!(!m.matches(&head("GET", "http://localhost:30001/api"), None));
        // A prefix with a path keeps plain prefix semantics.
        let m = Matcher::parse("prefix:https://prod.example.com/api").unwrap();
        assert!(m.matches(&head("GET", "https://prod.example.com/api-v2/x"), None));
        assert_eq!(m.rest("https://prod.example.com/api/x"), Rest::Prefix("/x".into()));
    }

    #[test]
    fn nocreds_modifier() {
        assert_eq!(split_nocreds("https://s.example.com/api/ *nocreds"), ("https://s.example.com/api/", true));
        assert_eq!(split_nocreds("  https://s.example.com  *NoCreds "), ("https://s.example.com", true));
        assert_eq!(split_nocreds("https://s.example.com/api/"), ("https://s.example.com/api/", false));
        assert!(leaves_origin("https://a.example.com/x", "https://b.example.com/x"));
        assert!(leaves_origin("https://a.example.com/x", "https://a.example.com:8443/x"));
        assert!(leaves_origin("https://a.example.com/x", "http://a.example.com/x"));
        assert!(!leaves_origin("https://A.example.com/x", "https://a.example.com/v2/x"));
        assert!(!leaves_origin("http://a.example.com/x", "https://a.example.com/x"));
    }

    /// The handle, not the path, decides: a file opened through a link that was swapped in
    /// after the path was checked is refused.
    #[test]
    fn opened_handle_must_stay_inside() {
        let d = tempfile::tempdir().unwrap();
        let base = d.path().join("site");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("ok.txt"), "ok").unwrap();
        std::fs::write(d.path().join("secret.txt"), "TOP-SECRET").unwrap();
        let base_c = std::fs::canonicalize(&base).unwrap();
        let (p, f) = open_in_dir(base.to_str().unwrap(), "ok.txt").unwrap();
        assert!(p.ends_with("ok.txt"));
        verify_opened(&base_c, &p, &f).unwrap();
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        assert!(opened_path(&f).unwrap().starts_with(&base_c), "{:?}", opened_path(&f));
        #[cfg(unix)]
        {
            // The race: "ok.txt" was checked, then replaced by a link to the secret.
            std::fs::remove_file(base.join("ok.txt")).unwrap();
            std::os::unix::fs::symlink(d.path().join("secret.txt"), base.join("ok.txt")).unwrap();
            let swapped = std::fs::File::open(&p).unwrap();
            assert_eq!(verify_opened(&base_c, &p, &swapped).unwrap_err().0, 403);
            assert_eq!(open_in_dir(base.to_str().unwrap(), "ok.txt").unwrap_err().0, 403);
        }
    }

    #[test]
    fn file_read_errors_are_not_served_as_complete() {
        struct Broken(usize);
        impl std::io::Read for Broken {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0 == 0 {
                    return Err(std::io::Error::other("disk gone"));
                }
                self.0 -= 1;
                buf[..4].copy_from_slice(b"data");
                Ok(4)
            }
        }
        let d = tempfile::tempdir().unwrap();
        let store = quena_body::BodyStore::open(d.path(), Default::default()).unwrap();
        assert_eq!(copy_to_body(&store, Broken(3)).unwrap_err(), "disk gone");
        assert_eq!(copy_to_body(&store, &b"hello"[..]).unwrap().read_range(0, 10).unwrap(), b"hello");
    }

    #[test]
    fn file_actions_are_recognised() {
        assert!(reads_file("dir:/srv/site"));
        assert!(reads_file("/tmp/mock.json"));
        assert!(!reads_file("*404"));
        assert!(!reads_file("session:3"));
        assert!(!reads_file("https://x.example.com/ *nocreds"));
    }
}
