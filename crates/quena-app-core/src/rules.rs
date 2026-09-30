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
    /// Match expression (`*`, `exact:`, `prefix:`, `regex:`, `NOT:`, `METHOD:`, `HEADER:`, `URLWithBody:` or substring).
    #[serde(rename = "match")]
    pub match_: String,
    /// Action (`file path`, `dir:folder`, `*404`, `*delay:500`, `*drop`, `*redir:url`, `*header:N=V`, `*bpu`, `*bpafter`, `http://…`, `session:ID`).
    ///
    /// With a `prefix:` match, `http(s)://…` is *Map Remote*: the part of the URL after the prefix
    /// (rest of the path and the query) is appended to the target. `dir:folder` is *Map Local*: it
    /// serves the file at the rest of the path inside the folder (the rest after a `prefix:` match,
    /// regex group 1, or else the whole URL path), never outside of it.
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

enum Matcher {
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
}

impl Matcher {
    fn parse(s: &str) -> Result<Matcher> {
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
        } else if lower.starts_with("urlwithbody:") {
            let rest = s[12..].trim();
            let (u, b) = rest.split_once(char::is_whitespace).ok_or_else(|| anyhow!("URLWithBody:<url> <body regex>"))?;
            let b = b.trim().strip_prefix("regex:").unwrap_or(b.trim());
            Matcher::UrlWithBody(Box::new(Matcher::parse(u)?), Regex::new(b).map_err(|e| anyhow!("regex: {e}"))?)
        } else {
            Matcher::Contains(lower)
        })
    }

    fn needs_body(&self) -> bool {
        matches!(self, Matcher::UrlWithBody(..))
    }

    fn matches(&self, head: &RequestHead, body: Option<&Body>) -> bool {
        match self {
            Matcher::All => true,
            Matcher::Exact(u) => head.url == *u,
            Matcher::Prefix(p) => head.url.get(..p.len()).is_some_and(|x| x.eq_ignore_ascii_case(p)),
            Matcher::Regex(r) => r.is_match(&head.url),
            Matcher::Not(t) => !head.url.to_lowercase().contains(t.as_str()),
            Matcher::Contains(t) => head.url.to_lowercase().contains(t.as_str()),
            Matcher::Method(m, inner) => head.method.eq_ignore_ascii_case(m) && inner.matches(head, body),
            Matcher::Header(n, v) => head.headers.get_all(n).any(|x| x.to_lowercase().contains(v.as_str())),
            Matcher::UrlWithBody(u, re) => {
                u.matches(head, body)
                    && body.is_some_and(|b| {
                        let data = b.read_range(0, 8 << 20).unwrap_or_default();
                        re.is_match(&String::from_utf8_lossy(&data))
                    })
            }
        }
    }

    /// What the action gets as "the rest of the URL" (see [`Rest`]). Only called after a match.
    fn rest(&self, url: &str) -> Rest {
        match self {
            Matcher::Prefix(p) => Rest::Prefix(url.get(p.len()..).unwrap_or("").to_string()),
            Matcher::Method(_, inner) | Matcher::UrlWithBody(inner, _) => inner.rest(url),
            Matcher::Regex(re) => re.captures(url).and_then(|c| c.get(1)).map(|m| Rest::Group(m.as_str().to_string())).unwrap_or(Rest::None),
            _ => Rest::None,
        }
    }
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

struct Compiled {
    rule: Rule,
    matcher: Matcher,
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
            next_rule: AtomicU64::new(max + 1),
            bp: RwLock::new(BreakpointState { timeout_s: 0, ..Default::default() }),
            paused: Mutex::new(HashMap::new()),
            break_response: Mutex::new(Default::default()),
            path,
            script: ScriptEngine::new(),
            script_path: data_dir.join("rules.js"),
            script_enabled: AtomicBool::new(false),
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
                if let Some(c) = &a.color {
                    if let Some(mc) = MarkColor::parse(c) {
                        s.color = Some(mc);
                    }
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
                r.hits = x.rule.hits;
            }
        }
        s
    }

    /// Replace the rule set. Rules with invalid syntax are rejected.
    pub fn set_autoresponder(&self, mut s: AutoResponderState, save: bool) -> Result<()> {
        let mut compiled = Vec::new();
        let old = self.compiled.read();
        for r in &mut s.rules {
            if r.id == 0 {
                r.id = self.next_rule.fetch_add(1, Ordering::Relaxed);
            }
            let matcher = Matcher::parse(&r.match_).map_err(|e| anyhow!("rule '{}': {e}", r.match_))?;
            let mut rule = r.clone();
            rule.hits = old.iter().find(|x| x.rule.id == r.id).map(|x| x.rule.hits).unwrap_or(0);
            compiled.push(Compiled { rule, matcher });
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
        let mut s = self.ar.read().clone();
        let mut n = 0;
        for id in ids {
            let Some(d) = cap.detail(*id) else { continue };
            if d.response.is_none() || d.summary.kind == SessionKind::Tunnel {
                continue;
            }
            let m = if exact { format!("EXACT:{}", d.request.url) } else { d.request.url.clone() };
            s.rules.insert(0, Rule { id: 0, match_: m, action: format!("session:{id}"), comment: format!("from #{id}"), ..Default::default() });
            n += 1;
        }
        s.enabled = true;
        self.set_autoresponder(s, true)?;
        Ok(n)
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
            let _ = self.resume(id, Resume { action: "continue".into(), head_text: None, body_text: None, body_file: None, status: None });
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
        let mut c = self.compiled.write();
        for x in c.iter_mut() {
            if !x.rule.enabled || (x.rule.match_once && x.rule.hits > 0) {
                continue;
            }
            if x.matcher.matches(head, body) {
                x.rule.hits += 1;
                let mut rule = x.rule.clone();
                // Regex capture substitution ($1 …) in the action. Not for a Map Local
                // folder: it is taken literally, the URL rest is resolved inside it.
                if let Matcher::Regex(re) = &x.matcher {
                    if rule.action.contains('$') && !rule.action.trim_start().to_ascii_lowercase().starts_with("dir:") {
                        if let Some(caps) = re.captures(&head.url) {
                            let mut out = String::new();
                            caps.expand(&rule.action, &mut out);
                            rule.action = out;
                        }
                    }
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

    /// Build a response from a file (raw `.dat` HTTP response or plain body).
    fn file_response(&self, path: &str) -> Option<(ResponseHead, Body)> {
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
        if starts_http {
            if let Ok(Some((first, headers))) = quena_formats::raw::read_head(&mut br) {
                let (v, status, reason) = quena_formats::raw::parse_status_line(&first);
                let mut w = cap.bodies.writer_with_limit(u64::MAX);
                let mut buf = vec![0u8; 1 << 20];
                let mut src: Box<dyn Read> = if quena_formats::raw::is_chunked(&headers) { Box::new(quena_formats::raw::ChunkedReader::new(br)) } else { Box::new(br) };
                while let Ok(n) = src.read(&mut buf) {
                    if n == 0 || w.write(&buf[..n]).is_err() {
                        break;
                    }
                }
                let body = w.finish();
                let mut headers = headers;
                headers.remove("transfer-encoding");
                headers.set("Content-Length", body.len().to_string());
                return Some((ResponseHead { status, reason, version: v, headers }, body));
            }
        }
        self.plain_file_response(p, br)
    }

    /// A 200 response with the file's bytes and a Content-Type guessed from its extension.
    fn plain_file_response(&self, p: &std::path::Path, mut src: impl std::io::Read) -> Option<(ResponseHead, Body)> {
        let core = self.core()?;
        let cap = core.capture();
        let mut w = cap.bodies.writer_with_limit(u64::MAX);
        let mut buf = vec![0u8; 1 << 20];
        while let Ok(n) = src.read(&mut buf) {
            if n == 0 || w.write(&buf[..n]).is_err() {
                break;
            }
        }
        let body = w.finish();
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
            return match resolve_in_dir(dir, &rel) {
                Ok(p) => {
                    *mapped = Some((false, format!("local file {}", p.display())));
                    match std::fs::File::open(&p) {
                        Ok(f) => respond(self.plain_file_response(&p, f)),
                        Err(e) => respond(self.synthetic(500, "text/plain; charset=utf-8", format!("[Quena] Map Local: cannot read {}: {e}", p.display()).as_bytes(), &[])),
                    }
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
        if let Some(id) = lower.strip_prefix("session:") {
            if let Ok(id) = id.trim().parse() {
                return respond(self.session_response(id).or_else(|| self.synthetic(404, "text/plain", b"[Quena] session not found", &[])));
            }
        }
        if lower.starts_with("http://") || lower.starts_with("https://") {
            // Retarget the request (Map Remote with a prefix: match keeps the rest of the URL).
            // The upstream client connects (and sends TLS SNI) from the URL; Host follows it.
            let target = match rest {
                Rest::Prefix(r) => join_target(a, r),
                _ => a.to_string(),
            };
            let mut h = head;
            let host = authority_of(&target).unwrap_or_else(|| split_url(&target, "GET").0);
            *mapped = Some((true, target.clone()));
            h.url = target;
            h.headers.set("Host", host);
            return Some(RequestAction::Forward { head: Some(h), body: None, delay_ms: latency });
        }
        respond(self.file_response(a))
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
                _ => Resume { action: "continue".into(), head_text: None, body_text: None, body_file: None, status: None },
            }
        } else {
            rx.await.unwrap_or(Resume { action: "continue".into(), head_text: None, body_text: None, body_file: None, status: None })
        };
        drop(unpause);
        s.live.update(|d| {
            d.summary.state = if phase == "request" { SessionState::SendingRequest } else { SessionState::ReceivingResponse };
        });
        r
    }

    fn replacement_body(&self, r: &Resume) -> Option<Body> {
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
        r.body_text.as_ref().map(|t| cap.bodies.store_bytes(t.as_bytes()))
    }
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

fn fix_length(h: &mut Headers, body: &Body) {
    h.remove("transfer-encoding");
    h.set("Content-Length", body.len().to_string());
}

impl Interceptor for Rules {
    fn request_mode(&self, s: &SessionView, head: &RequestHead) -> Mode {
        if self.bp_request(s, head) || self.needs_request_body() {
            Mode::Buffer
        } else {
            Mode::Stream
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
                    let mut mapped = None;
                    if let Some(action) = this.apply_action(&rule, head.clone(), &rest, &mut mapped) {
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
            } else if this.ar.read().enabled && !this.ar.read().unmatched_passthrough {
                if let Some((h, b)) = this.synthetic(404, "text/plain; charset=utf-8", b"[Quena] Mock Rules: no rule matched and unmatched requests are not passed through", &[]) {
                    return RequestAction::Respond { head: h, body: b, delay_ms: 0 };
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
                            if headers.is_none() && new_auth.is_some() && new_auth != old_auth {
                                if let Some(a) = new_auth {
                                    head.headers.set("Host", a);
                                }
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
            // 2. Breakpoint before request
            if want_bp || this.bp_request(&s, &head) {
                let r = this.clone().pause(s.clone(), "request", head.url.clone()).await;
                let new_body = this.replacement_body(&r);
                let new_head = r.head_text.as_ref().map(|t| {
                    let (first, headers) = parse_head_text(t);
                    let mut parts = first.splitn(3, ' ');
                    let method = parts.next().unwrap_or(&head.method).to_string();
                    let url = parts.next().unwrap_or(&head.url).to_string();
                    RequestHead { method, url, version: head.version, headers }
                });
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
                RequestAction::Forward { head: Some(head), body: None, delay_ms: 0 }
            } else {
                RequestAction::forward()
            }
        })
    }

    fn wants_response_head(&self, _s: &SessionView) -> bool {
        self.script_active() && self.script.has_response_hook()
    }

    fn on_response_head(&self, s: SessionView, resp: ResponseHead) -> BoxFuture<quena_proxy::ResponseHeadAction> {
        use quena_proxy::ResponseHeadAction;
        let this = self.core().and_then(|c| c.rules.clone());
        let Some(this) = this else { return Box::pin(async { ResponseHeadAction::Continue }) };
        if !this.script_active() || !this.script.has_response_hook() {
            return Box::pin(async { ResponseHeadAction::Continue });
        }
        Box::pin(async move {
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
                    if status.is_none() && headers.is_none() {
                        return ResponseHeadAction::Continue;
                    }
                    let mut h = resp;
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
                    ResponseHeadAction::Replace(h)
                }
                ResponseDecision::Abort { meta } => {
                    this.apply_meta(&s, &meta);
                    ResponseHeadAction::Abort
                }
            }
        })
    }

    fn response_mode(&self, s: &SessionView, req: &RequestHead, resp: &ResponseHead) -> Mode {
        if self.bp_response(s, req, resp) { Mode::Buffer } else { Mode::Stream }
    }

    fn on_response(&self, s: SessionView, resp: ResponseHead, _body: Body) -> BoxFuture<ResponseAction> {
        let this = self.core().and_then(|c| c.rules.clone());
        let Some(this) = this else { return Box::pin(async { ResponseAction::Continue }) };
        Box::pin(async move {
            this.break_response.lock().remove(&s.id);
            let url = s.live.detail().request.url;
            let r = this.clone().pause(s.clone(), "response", url).await;
            if r.action == "abort" {
                return ResponseAction::Abort;
            }
            let body = this.replacement_body(&r);
            match (&r.head_text, body) {
                (None, None) => ResponseAction::Continue,
                (head_text, body) => {
                    let mut head = match head_text {
                        Some(t) => {
                            let (first, headers) = parse_head_text(t);
                            let (v, status, reason) = quena_formats::raw::parse_status_line(&first);
                            ResponseHead { status: if status == 0 { resp.status } else { status }, reason, version: v, headers }
                        }
                        None => resp.clone(),
                    };
                    if let Some(b) = &body {
                        fix_length(&mut head.headers, b);
                    }
                    ResponseAction::Replace { head, body }
                }
            }
        })
    }

    fn on_complete(&self, s: &SessionView) {
        self.break_response.lock().remove(&s.id);
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
    for r in &s.rules {
        if r.action.starts_with("session:") {
            continue; // session-backed rules are local to this capture
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
}
