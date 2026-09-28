//! AutoResponder (M7) and Breakpoints/Tamper (M8) – the interceptor chain
//! installed into the proxy (PLAN.md §1.7, §1.8, §2.1).

use crate::AppCore;
use anyhow::{Result, anyhow};
use parking_lot::{Mutex, RwLock};
use piper_body::Body;
use piper_model::*;
use piper_proxy::hooks::{BoxFuture, Mode};
use piper_proxy::{Interceptor, RequestAction, ResponseAction, SessionView};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::sync::oneshot;

// ------------------------------------------------------------ AutoResponder

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Rule {
    pub id: u64,
    pub enabled: bool,
    /// Match expression (`*`, `exact:`, `regex:`, `NOT:`, `METHOD:`, `HEADER:`, `URLWithBody:` or substring).
    #[serde(rename = "match")]
    pub match_: String,
    /// Action (`file path`, `*404`, `*delay:500`, `*drop`, `*redir:url`, `*header:N=V`, `*bpu`, `*bpafter`, `http://…`, `session:ID`).
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
        _ => "application/octet-stream",
    }
}

// --------------------------------------------------------------- breakpoints

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct BreakpointState {
    /// Rules → Automatic Breakpoints → Before Requests.
    pub all_requests: bool,
    /// Rules → Automatic Breakpoints → After Responses.
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

impl Rules {
    pub fn new(data_dir: &std::path::Path) -> Arc<Rules> {
        let path = data_dir.join("autoresponder.json");
        let ar: AutoResponderState = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
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
        });
        let _ = r.set_autoresponder(ar, false);
        r
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

    fn find_rule(&self, head: &RequestHead, body: Option<&Body>) -> Option<(Rule, Option<regex::Captures<'static>>)> {
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
                // Regex capture substitution ($1 …) in the action.
                if let Matcher::Regex(re) = &x.matcher {
                    if rule.action.contains('$') {
                        if let Some(caps) = re.captures(&head.url) {
                            let mut out = String::new();
                            caps.expand(&rule.action, &mut out);
                            rule.action = out;
                        }
                    }
                }
                return Some((rule, None));
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
        h.push("Server", "Piper AutoResponder");
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
            return self.synthetic(404, "text/plain; charset=utf-8", format!("[Piper] AutoResponder: file not found: {path}").as_bytes(), &[]);
        };
        let mut br = std::io::BufReader::new(file);
        use std::io::{BufRead, Read};
        let starts_http = br.fill_buf().map(|b| b.starts_with(b"HTTP/")).unwrap_or(false);
        let cap = core.capture();
        if starts_http {
            if let Ok(Some((first, headers))) = piper_formats::raw::read_head(&mut br) {
                let (v, status, reason) = piper_formats::raw::parse_status_line(&first);
                let mut w = cap.bodies.writer_with_limit(u64::MAX);
                let mut buf = vec![0u8; 1 << 20];
                let mut src: Box<dyn Read> = if piper_formats::raw::is_chunked(&headers) { Box::new(piper_formats::raw::ChunkedReader::new(br)) } else { Box::new(br) };
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
        let mut w = cap.bodies.writer_with_limit(u64::MAX);
        let mut buf = vec![0u8; 1 << 20];
        while let Ok(n) = br.read(&mut buf) {
            if n == 0 || w.write(&buf[..n]).is_err() {
                break;
            }
        }
        let body = w.finish();
        let mut h = Headers::new();
        h.push("Date", httpdate_now());
        h.push("Server", "Piper AutoResponder");
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
        if piper_formats::raw::is_chunked(&head.headers) {
            head.headers.remove("transfer-encoding");
            head.headers.set("Content-Length", body.len().to_string());
        }
        Some((head, body))
    }

    /// Turn an AutoResponder action into a proxy action.
    fn apply_action(&self, rule: &Rule, head: RequestHead) -> Option<RequestAction> {
        let latency = if self.ar.read().enable_latency { rule.latency_ms as u64 } else { 0 };
        let a = rule.action.trim();
        let lower = a.to_ascii_lowercase();
        let respond = |x: Option<(ResponseHead, Body)>| x.map(|(h, b)| RequestAction::Respond { head: h, body: b, delay_ms: latency });
        if let Some(rest) = lower.strip_prefix('*') {
            if let Ok(code) = rest.parse::<u16>() {
                return respond(self.synthetic(code, "text/plain; charset=utf-8", format!("[Piper] AutoResponder: {code}").as_bytes(), &[]));
            }
            if let Some(ms) = rest.strip_prefix("delay:") {
                let d: u64 = ms.trim().parse().unwrap_or(0);
                return Some(RequestAction::Forward { head: None, body: None, delay_ms: d + latency });
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
            return respond(self.synthetic(500, "text/plain", format!("[Piper] unknown AutoResponder action {a}").as_bytes(), &[]));
        }
        if let Some(id) = lower.strip_prefix("session:") {
            if let Ok(id) = id.trim().parse() {
                return respond(self.session_response(id).or_else(|| self.synthetic(404, "text/plain", b"[Piper] session not found", &[])));
            }
        }
        if lower.starts_with("http://") || lower.starts_with("https://") {
            // Retarget the request.
            let mut h = head;
            let (host, _) = split_url(a, "GET");
            h.url = a.to_string();
            h.headers.set("Host", host);
            return Some(RequestAction::Forward { head: Some(h), body: None, delay_ms: latency });
        }
        respond(self.file_response(a))
    }

    async fn pause(self: Arc<Self>, s: SessionView, phase: &str, url: String) -> Resume {
        let (tx, rx) = oneshot::channel();
        let info = PausedInfo { id: s.id, phase: phase.into(), url, since: now_us() };
        self.paused.lock().insert(s.id, (if phase == "request" { Waiter::Request(tx) } else { Waiter::Response(tx) }, info.clone()));
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
        self.paused.lock().remove(&s.id);
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
            // 1. AutoResponder
            let mut want_bp = false;
            if let Some((rule, _)) = this.find_rule(&head, body.as_ref()) {
                let a = rule.action.trim().to_ascii_lowercase();
                if a == "*bpu" {
                    want_bp = true;
                } else if a == "*bpafter" {
                    this.break_response.lock().insert(s.id);
                } else if let Some(action) = this.apply_action(&rule, head.clone()) {
                    s.live.update(|d| {
                        if d.summary.comment.is_empty() {
                            d.summary.comment = format!("AutoResponder: {}", rule.match_);
                        }
                    });
                    return action;
                }
            } else if this.ar.read().enabled && !this.ar.read().unmatched_passthrough {
                if let Some((h, b)) = this.synthetic(404, "text/plain; charset=utf-8", b"[Piper] AutoResponder: no rule matched and unmatched requests are not passed through", &[]) {
                    return RequestAction::Respond { head: h, body: b, delay_ms: 0 };
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
                }
                return RequestAction::Forward { head: head_out, body: new_body, delay_ms: 0 };
            }
            RequestAction::forward()
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
                            let (v, status, reason) = piper_formats::raw::parse_status_line(&first);
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
    }
}

// ------------------------------------------------------------------- .farx

pub fn export_farx(s: &AutoResponderState) -> String {
    let esc = |x: &str| x.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<AutoResponder LastSave=\"");
    out.push_str(&httpdate_now());
    out.push_str("\" FiddlerVersion=\"Piper\">\r\n");
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
}
