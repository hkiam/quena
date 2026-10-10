//! Comparing two captures: which requests are new, which are gone, and which answer
//! differently (status, content type, size, time, headers, body) — "what changed since the
//! last release", "why does staging work and production not".
//!
//! A side is a set of sessions in the list: the live capture, or an archive loaded into it
//! (each import is remembered by its file name). Requests are paired by method, host and a
//! normalized path: numbers and ids become placeholders, query values are ignored, and the
//! n-th occurrence on one side meets the n-th on the other.

use crate::AppCore;
use anyhow::{Result, anyhow};
use quena_model::{SessionDetail, SessionId, SessionSummary, flags};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// Bytes of a response body compared.
const MAX_BODY: usize = 8 << 20;
/// A time is "changed" when it is this many times as long (or short) …
const TIME_FACTOR: f64 = 2.0;
/// … and differs by at least this much.
const TIME_MIN_MS: u32 = 200;

/// Response headers whose values are compared (others: only whether they are there).
const COMPARED_HEADERS: &[&str] = &[
    "content-type",
    "content-encoding",
    "cache-control",
    "location",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "www-authenticate",
    "vary",
];
/// Headers that change on every response and are ignored.
const VOLATILE_HEADERS: &[&str] = &[
    "date", "age", "expires", "last-modified", "etag", "content-length", "set-cookie", "x-request-id", "x-correlation-id", "request-id", "traceparent", "cf-ray", "server-timing", "x-amz-request-id",
    "x-amz-id-2", "x-cache", "via", "connection", "keep-alive", "transfer-encoding", "report-to", "nel",
];

/// One side of a comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "name")]
pub enum Source {
    /// Sessions recorded live (not imported).
    Live,
    /// The sessions of an archive loaded into the list (by its file name).
    Archive(String),
    /// Chosen sessions.
    Ids(Vec<SessionId>),
}

/// How two captures are compared.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CompareOptions {
    /// Pair requests to different hosts (staging and production): by method and path only.
    pub ignore_host: bool,
    /// How requests are paired.
    pub pair_by: PairBy,
    /// Response headers not compared (besides the volatile ones), any case.
    pub ignore_headers: Vec<String>,
}

/// How the requests of two sides are paired.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PairBy {
    /// Method, host and the path with numbers and ids as placeholders (the default).
    #[default]
    Path,
    /// Method and the exact URL.
    Url,
    /// The n-th request with the n-th (two runs of the same steps).
    Order,
}

/// A side as offered for choosing.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceInfo {
    pub source: Source,
    pub label: String,
    pub sessions: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum DiffKind {
    Changed,
    Added,
    Removed,
    Same,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffEntry {
    pub kind: DiffKind,
    pub method: String,
    /// `host/normalized/path`.
    pub key: String,
    pub id_a: Option<SessionId>,
    pub id_b: Option<SessionId>,
    pub url_a: Option<String>,
    pub url_b: Option<String>,
    pub status_a: Option<u16>,
    pub status_b: Option<u16>,
    pub size_a: Option<u64>,
    pub size_b: Option<u64>,
    pub ms_a: Option<u32>,
    pub ms_b: Option<u32>,
    /// What differs, in words (`status 200 → 500`, `body differs`, `header vary added` …).
    pub changes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DiffCounts {
    pub changed: usize,
    pub added: usize,
    pub removed: usize,
    pub same: usize,
    /// Pairs that worked before and fail now (an error status, or no answer).
    pub new_errors: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureDiff {
    pub sessions_a: usize,
    pub sessions_b: usize,
    pub counts: DiffCounts,
    /// Changed first, then added, removed, same; within a kind in the order of side B (A).
    pub entries: Vec<DiffEntry>,
}

/// The path of a URL with what varies replaced: `/users/123/orders/9f8c…` → `/users/{n}/orders/{id}`,
/// `/assets/index-B2x9kQ1a.js` → `/assets/index-{hash}.js`; query values dropped, keys sorted.
pub fn normalize(url: &str) -> (String, String) {
    let (host, rest) = match url.split_once("://") {
        Some((_, r)) => match r.find('/') {
            Some(i) => (r[..i].to_ascii_lowercase(), &r[i..]),
            None => (r.to_ascii_lowercase(), "/"),
        },
        None => (String::new(), url),
    };
    let rest = rest.split('#').next().unwrap_or("");
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let seg = |s: &str| -> String {
        let hexish = s.len() >= 16 && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
        if !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()) {
            "{n}".into()
        } else if hexish || (s.len() >= 20 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') && s.chars().any(|c| c.is_ascii_digit())) {
            "{id}".into()
        } else if s.contains('.') {
            hashes(s)
        } else {
            s.to_string()
        }
    };
    let mut p: String = path.split('/').map(seg).collect::<Vec<_>>().join("/");
    if p.is_empty() {
        p = "/".into();
    }
    let mut keys: Vec<&str> = query.split('&').filter(|q| !q.is_empty()).map(|q| q.split('=').next().unwrap_or(q)).collect();
    keys.sort_unstable();
    keys.dedup();
    if !keys.is_empty() {
        p.push('?');
        p.push_str(&keys.join("&"));
    }
    (host, p)
}

/// A file name with the content hashes of a build replaced: `main.3f9a2c1b.js` →
/// `main.{hash}.js`, `index-B2x9kQ1a.js` → `index-{hash}.js`.
fn hashes(name: &str) -> String {
    // At least 8 letters and digits: hex, or upper and lower case mixed (base64-like).
    let hashy = |t: &str| {
        t.len() >= 8
            && t.chars().all(|c| c.is_ascii_alphanumeric())
            && t.chars().any(|c| c.is_ascii_digit())
            && (t.chars().all(|c| c.is_ascii_hexdigit()) || (t.chars().any(|c| c.is_ascii_uppercase()) && t.chars().any(|c| c.is_ascii_lowercase())))
    };
    let mut out = String::with_capacity(name.len());
    let mut token = String::new();
    for c in name.chars().map(Some).chain([None]) {
        match c {
            Some(c) if !matches!(c, '.' | '-' | '_') => token.push(c),
            _ => {
                out.push_str(if hashy(&token) { "{hash}" } else { &token });
                token.clear();
                out.extend(c);
            }
        }
    }
    out
}

/// A status that is an answer, not an error (0: no answer).
fn ok(status: u16) -> bool {
    (1..400).contains(&status)
}

fn header_map(d: &SessionDetail) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    if let Some(r) = &d.response {
        for (k, v) in &r.headers.0 {
            let k = k.to_ascii_lowercase();
            if !VOLATILE_HEADERS.contains(&k.as_str()) && !k.starts_with(':') {
                m.entry(k).and_modify(|e: &mut String| e.push_str(&format!(", {v}"))).or_insert_with(|| v.clone());
            }
        }
    }
    m
}

fn fmt_size(n: u64) -> String {
    match n {
        n if n >= 1 << 20 => format!("{:.1} MB", n as f64 / (1 << 20) as f64),
        n if n >= 1 << 10 => format!("{:.1} KB", n as f64 / 1024.0),
        n => format!("{n} B"),
    }
}

impl AppCore {
    /// Remember which sessions an archive import brought (for comparing captures).
    pub(crate) fn note_import(&self, name: &str, ids: &[SessionId]) {
        if ids.is_empty() {
            return;
        }
        let numbering = self.capture().numbering();
        let file = std::path::Path::new(name).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| name.to_string());
        let mut imports = self.imports.lock();
        imports.retain(|(_, n, _)| *n == numbering);
        // A name loaded before (the same file again, or another with that name): numbered.
        let mut label = file.clone();
        let mut n = 2;
        while imports.iter().any(|(f, _, _)| *f == label) {
            label = format!("{file} ({n})");
            n += 1;
        }
        imports.push((label, numbering, ids.to_vec()));
    }

    /// The sides one can compare: live sessions and each archive in the list.
    pub fn compare_sources(&self) -> Vec<SourceInfo> {
        let cap = self.capture();
        let numbering = cap.numbering();
        let mut out = Vec::new();
        let live = cap.index.find_all(|s| !s.has_flag(flags::IMPORTED)).len();
        if live > 0 {
            out.push(SourceInfo { source: Source::Live, label: "live".into(), sessions: live });
        }
        for (file, n, ids) in self.imports.lock().iter() {
            if *n != numbering {
                continue;
            }
            let present = ids.iter().filter(|id| cap.index.get(**id).is_some()).count();
            if present > 0 {
                out.push(SourceInfo { source: Source::Archive(file.clone()), label: file.clone(), sessions: present });
            }
        }
        out
    }

    fn source_ids(&self, s: &Source) -> Result<Vec<SessionId>> {
        let cap = self.capture();
        let mut ids = match s {
            Source::Live => cap.index.find_all(|x| !x.has_flag(flags::IMPORTED)),
            Source::Ids(v) => v.iter().copied().filter(|id| cap.index.get(*id).is_some()).collect(),
            Source::Archive(name) => {
                let numbering = cap.numbering();
                let imports = self.imports.lock();
                let (_, _, v) = imports.iter().find(|(f, n, _)| f == name && *n == numbering).ok_or_else(|| anyhow!("{name} is not loaded"))?;
                v.iter().copied().filter(|id| cap.index.get(*id).is_some()).collect()
            }
        };
        ids.sort_unstable();
        Ok(ids)
    }

    fn body_hash(&self, id: SessionId, d: &SessionDetail) -> Option<u64> {
        use std::hash::{Hash, Hasher};
        let (_, body) = self.capture().bodies_of(id)?;
        let r = d.response.as_ref()?;
        let bytes = quena_body::text::decoded_prefix(&body, &crate::dto::spec_of(&r.headers), MAX_BODY);
        let mut h = std::collections::hash_map::DefaultHasher::new();
        // JSON compares by content (key order and spacing do not count).
        match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(v) if !bytes.is_empty() => canonical(&v).hash(&mut h),
            _ => bytes.hash(&mut h),
        }
        Some(h.finish())
    }

    /// Compare side `a` (before) with side `b` (after).
    pub fn compare_captures(&self, a: &Source, b: &Source) -> Result<CaptureDiff> {
        self.compare_captures_with(a, b, &CompareOptions::default())
    }

    /// [`AppCore::compare_captures`] with options.
    pub fn compare_captures_with(&self, a: &Source, b: &Source, o: &CompareOptions) -> Result<CaptureDiff> {
        let cap = self.capture();
        let ids_a = self.source_ids(a)?;
        let ids_b = self.source_ids(b)?;
        if ids_a.is_empty() || ids_b.is_empty() {
            return Err(anyhow!("both sides need sessions"));
        }
        let rows = |ids: &[SessionId]| -> Vec<SessionSummary> { ids.iter().filter_map(|id| cap.index.get(*id)).filter(|s| s.kind != quena_model::SessionKind::Tunnel).collect() };
        let (ra, rb) = (rows(&ids_a), rows(&ids_b));
        let label = |s: &SessionSummary| {
            let (host, path) = normalize(&s.full_url());
            (s.method.to_ascii_uppercase(), if o.ignore_host { path } else { format!("{host}{path}") })
        };
        // The pairing key: by order the position on its side (the label is still shown).
        let pos_a: HashMap<SessionId, usize> = ra.iter().enumerate().map(|(i, s)| (s.id, i)).collect();
        let pos_b: HashMap<SessionId, usize> = rb.iter().enumerate().map(|(i, s)| (s.id, i)).collect();
        let key = |s: &SessionSummary| -> (String, String) {
            match o.pair_by {
                PairBy::Path => label(s),
                PairBy::Url => {
                    let u = s.full_url();
                    let u = if o.ignore_host { u.split_once("://").and_then(|(_, r)| r.find('/').map(|i| r[i..].to_string())).unwrap_or(u) } else { u };
                    (s.method.to_ascii_uppercase(), u)
                }
                PairBy::Order => (String::new(), pos_a.get(&s.id).or(pos_b.get(&s.id)).copied().unwrap_or(0).to_string()),
            }
        };
        // Occurrences of each key on side A, in order.
        let mut by_key: HashMap<(String, String), std::collections::VecDeque<&SessionSummary>> = HashMap::new();
        for s in &ra {
            by_key.entry(key(s)).or_default().push_back(s);
        }
        let mut entries = Vec::new();
        let mut counts = DiffCounts::default();
        for sb in &rb {
            let sa = by_key.get_mut(&key(sb)).and_then(|q| q.pop_front());
            let k = label(sb);
            let mut e = DiffEntry {
                kind: DiffKind::Added,
                method: k.0.clone(),
                key: k.1.clone(),
                id_a: sa.map(|s| s.id),
                id_b: Some(sb.id),
                url_a: sa.map(|s| s.full_url()),
                url_b: Some(sb.full_url()),
                status_a: sa.map(|s| s.status),
                status_b: Some(sb.status),
                size_a: sa.map(|s| s.response_body_len),
                size_b: Some(sb.response_body_len),
                ms_a: sa.and_then(|s| s.duration_ms),
                ms_b: sb.duration_ms,
                changes: vec![],
            };
            if let Some(sa) = sa {
                e.changes = self.pair_changes(sa, sb, &o.ignore_headers);
                e.kind = if e.changes.is_empty() { DiffKind::Same } else { DiffKind::Changed };
                if ok(sa.status) && !ok(sb.status) {
                    counts.new_errors += 1;
                }
            }
            entries.push(e);
        }
        // What no session of B took, in the order of A.
        let left: std::collections::HashSet<SessionId> = by_key.values().flatten().map(|s| s.id).collect();
        for s in ra.iter().filter(|s| left.contains(&s.id)) {
            let k = label(s);
            entries.push(DiffEntry {
                kind: DiffKind::Removed,
                method: k.0,
                key: k.1,
                id_a: Some(s.id),
                id_b: None,
                url_a: Some(s.full_url()),
                url_b: None,
                status_a: Some(s.status),
                status_b: None,
                size_a: Some(s.response_body_len),
                size_b: None,
                ms_a: s.duration_ms,
                ms_b: None,
                changes: vec![],
            });
        }
        for e in &entries {
            match e.kind {
                DiffKind::Changed => counts.changed += 1,
                DiffKind::Added => counts.added += 1,
                DiffKind::Removed => counts.removed += 1,
                DiffKind::Same => counts.same += 1,
            }
        }
        // Stable: kind first, then the order they came in.
        entries.sort_by_key(|e| e.kind);
        Ok(CaptureDiff { sessions_a: ra.len(), sessions_b: rb.len(), counts, entries })
    }

    fn pair_changes(&self, a: &SessionSummary, b: &SessionSummary, ignore: &[String]) -> Vec<String> {
        let mut out = Vec::new();
        if a.status != b.status {
            out.push(format!("status {} → {}", a.status, b.status));
        }
        if a.content_type != b.content_type {
            out.push(format!("type {} → {}", if a.content_type.is_empty() { "-" } else { &a.content_type }, if b.content_type.is_empty() { "-" } else { &b.content_type }));
        }
        if let (Some(x), Some(y)) = (a.duration_ms, b.duration_ms) {
            let (lo, hi) = (x.min(y).max(1) as f64, x.max(y) as f64);
            if hi / lo >= TIME_FACTOR && x.abs_diff(y) >= TIME_MIN_MS {
                out.push(format!("time {x} ms → {y} ms"));
            }
        }
        let (Some(da), Some(db)) = (self.capture().detail(a.id), self.capture().detail(b.id)) else { return out };
        let (mut ha, mut hb) = (header_map(&da), header_map(&db));
        for h in ignore {
            let h = h.trim().to_ascii_lowercase();
            ha.remove(&h);
            hb.remove(&h);
        }
        for (k, v) in &hb {
            match ha.get(k) {
                None => out.push(format!("header {k} added")),
                Some(old) if COMPARED_HEADERS.contains(&k.as_str()) && old != v && k != "content-type" => out.push(format!("header {k}: {old} → {v}")),
                _ => {}
            }
        }
        for k in ha.keys().filter(|k| !hb.contains_key(*k)) {
            out.push(format!("header {k} removed"));
        }
        if a.status == b.status && self.body_hash(a.id, &da) != self.body_hash(b.id, &db) {
            let size = if a.response_body_len != b.response_body_len { format!(" ({} → {})", fmt_size(a.response_body_len), fmt_size(b.response_body_len)) } else { String::new() };
            out.push(format!("body differs{size}"));
        }
        out
    }
}

/// JSON with object keys sorted, for comparing content.
pub(crate) fn canonical_json(v: &serde_json::Value) -> String {
    canonical(v)
}

fn canonical(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            format!("{{{}}}", keys.iter().map(|k| format!("{}:{}", serde_json::to_string(k).unwrap_or_default(), canonical(&m[*k]))).collect::<Vec<_>>().join(","))
        }
        serde_json::Value::Array(a) => format!("[{}]", a.iter().map(canonical).collect::<Vec<_>>().join(",")),
        other => other.to_string(),
    }
}

/// The comparison as Markdown (for a ticket or a pull request).
pub fn to_markdown(d: &CaptureDiff, name_a: &str, name_b: &str, all: bool) -> String {
    let c = &d.counts;
    let mut out = format!(
        "## {name_a} → {name_b}\n\n{} changed · {} new · {} gone · {} same ({} / {} requests){}\n\n",
        c.changed,
        c.added,
        c.removed,
        c.same,
        d.sessions_a,
        d.sessions_b,
        if c.new_errors > 0 { format!(" · **{} now fail**", c.new_errors) } else { String::new() }
    );
    out.push_str("| | Request | Status | Changes |\n|---|---|---|---|\n");
    for e in d.entries.iter().filter(|e| all || e.kind != DiffKind::Same) {
        let mark = match e.kind {
            DiffKind::Changed => "~",
            DiffKind::Added => "+",
            DiffKind::Removed => "−",
            DiffKind::Same => "=",
        };
        let status = match (e.status_a, e.status_b) {
            (Some(x), Some(y)) if x != y => format!("{x} → {y}"),
            (_, Some(y)) => y.to_string(),
            (Some(x), None) => x.to_string(),
            _ => String::new(),
        };
        out.push_str(&format!("| {mark} | `{} {}` | {status} | {} |\n", e.method, e.key.replace('|', "\\|"), e.changes.join("; ").replace('|', "\\|")));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_normalized() {
        assert_eq!(normalize("https://API.example.com/users/123/orders/9f8c2a1b4d5e6f708192a3b4?b=2&a=1&b=3"), ("api.example.com".into(), "/users/{n}/orders/{id}?a&b".into()));
        assert_eq!(normalize("https://x/"), ("x".into(), "/".into()));
        assert_eq!(normalize("https://x"), ("x".into(), "/".into()));
        assert_eq!(normalize("https://x/a/550e8400-e29b-41d4-a716-446655440000#f").1, "/a/{id}");
        assert_eq!(normalize("https://x/v2/items").1, "/v2/items", "short words with digits stay");
        assert_eq!(normalize("https://x/assets/index-B2x9kQ1a.js").1, "/assets/index-{hash}.js");
        assert_eq!(normalize("https://x/static/main.3f9a2c1b.chunk.js").1, "/static/main.{hash}.chunk.js");
        assert_eq!(normalize("https://x/lib/jquery-3.7.1.min.js").1, "/lib/jquery-3.7.1.min.js", "versions stay");
        assert_eq!(normalize("https://x/docs/Background.html").1, "/docs/Background.html", "words stay");
        assert!(!ok(0) && ok(200) && ok(304) && !ok(404));
    }

    #[test]
    fn json_is_compared_by_content() {
        let a: serde_json::Value = serde_json::from_str(r#"{"b":1,"a":[1,{"y":2,"x":1}]}"#).unwrap();
        let b: serde_json::Value = serde_json::from_str(r#"{ "a": [1, {"x":1,"y":2}], "b": 1 }"#).unwrap();
        assert_eq!(canonical(&a), canonical(&b));
    }
}
