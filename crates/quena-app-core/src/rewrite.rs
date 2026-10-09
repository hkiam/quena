//! Rewrite rules: change real requests and responses on their way — JSON values by JSONPath
//! (RFC 9535), text by regex, headers and the status.
//!
//! Cost when unused: one atomic load per request and response. Header and status changes
//! never buffer a body. Body changes buffer (in the body store, not in RAM) only messages a
//! rule matches with a text content type and a size within the limit; a body that turns out
//! larger, is not complete, or is not JSON for a JSON operation passes through unchanged,
//! with a note in the session comment.

use crate::rules::Matcher;
use anyhow::{Result, anyhow, bail};
use parking_lot::{Mutex, RwLock};
use quena_body::Body;
use quena_model::{Headers, RequestHead, ResponseHead, SessionId};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json_path::JsonPath;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub enum Phase {
    Request,
    #[default]
    Response,
    /// Messages of a WebSocket (text messages; JSON also inside Socket.IO packets).
    WebSocket,
}

/// Which WebSocket messages a rule changes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub enum WsDirection {
    #[default]
    Both,
    /// Client → server.
    Up,
    /// Server → client.
    Down,
}

/// One change. JSON paths are RFC 9535 JSONPath (`$.items[*].price`, `$..id`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Op {
    /// Set every value the path selects; a missing member of a plain path (`$.a.b`) is created.
    JsonSet { path: String, value: Value },
    /// Remove every value the path selects.
    JsonRemove { path: String },
    /// Append to every array the path selects. Without `value`: a "broken" copy of the
    /// first element (same keys, all values null).
    JsonAppend {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<Value>,
    },
    /// Append to every array in the document, the root included (`value` as above).
    JsonAppendAll {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<Value>,
    },
    /// Replace regex matches in the body text (`$1`, `${name}` refer to groups).
    RegexReplace { pattern: String, replacement: String },
    SetHeader { name: String, value: String },
    RemoveHeader { name: String },
    /// Response status (responses only).
    SetStatus { code: u16 },
}

impl Op {
    fn on_body(&self) -> bool {
        !matches!(self, Op::SetHeader { .. } | Op::RemoveHeader { .. } | Op::SetStatus { .. })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct RewriteRule {
    pub id: u64,
    pub enabled: bool,
    /// Match pattern of Mock Rules by URL, method and headers (`*`, `exact:`, `prefix:`,
    /// `regex:`, `NOT:`, `METHOD:`, `HEADER:`, substring).
    #[serde(rename = "match")]
    pub match_: String,
    pub phase: Phase,
    /// With [`Phase::WebSocket`]: which direction.
    #[serde(default)]
    pub direction: WsDirection,
    /// Response status filter: `200`, `4xx`, `500-599`, several separated by `,` (empty: any).
    pub status: String,
    /// Content types (substrings, `;` separated); empty: any text type (JSON, XML, text …).
    pub content_type: String,
    pub ops: Vec<Op>,
    pub comment: String,
    /// Named group, switched on and off together (empty: none).
    pub group: String,
    #[serde(skip_deserializing)]
    pub hits: u64,
}

impl Default for RewriteRule {
    fn default() -> Self {
        RewriteRule {
            id: 0,
            enabled: true,
            match_: "*".into(),
            phase: Phase::Response,
            direction: WsDirection::Both,
            status: String::new(),
            content_type: String::new(),
            ops: vec![],
            comment: String::new(),
            group: String::new(),
            hits: 0,
        }
    }
}

/// Upper bound of [`RewriteState::max_body_kb`]. A JSON document takes several times its
/// size in memory while it is changed.
pub const MAX_BODY_KB: u64 = 16 << 10;

/// Body volume (MiB) changed at the same time; a larger change waits for others to finish.
const TRANSFORM_BUDGET_MIB: u32 = 32;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct RewriteState {
    pub enabled: bool,
    /// Largest body (raw and decoded) a rule changes, in KiB.
    pub max_body_kb: u64,
    pub rules: Vec<RewriteRule>,
    /// Groups whose rules are off.
    pub disabled_groups: Vec<String>,
}

impl Default for RewriteState {
    fn default() -> Self {
        RewriteState { enabled: true, max_body_kb: 4096, rules: vec![], disabled_groups: vec![] }
    }
}

impl RewriteState {
    /// Whether `rule` runs: enabled, and not in a group that is off.
    pub fn runs(&self, rule: &RewriteRule) -> bool {
        rule.enabled && (rule.group.trim().is_empty() || !self.disabled_groups.iter().any(|g| g == rule.group.trim()))
    }
}

// ------------------------------------------------------------------ compiled

enum COp {
    JsonSet(JsonPath, Option<Vec<String>>, Value),
    JsonRemove(JsonPath),
    JsonAppend(JsonPath, Option<Value>),
    JsonAppendAll(Option<Value>),
    Regex(Regex, String),
    SetHeader(String, String),
    RemoveHeader(String),
    SetStatus(u16),
}

struct Compiled {
    rule: RewriteRule,
    matcher: Matcher,
    status: Vec<(u16, u16)>,
    types: Vec<String>,
    ops: Vec<COp>,
    body_ops: bool,
    head_ops: bool,
    /// Only JSON operations on the body: without content types, only JSON bodies apply.
    json_only: bool,
    hits: AtomicU64,
}

/// `$.a.b['c d']` as member names, for creating missing members; `None` for other paths.
fn plain_members(path: &str) -> Option<Vec<String>> {
    let mut rest = path.trim().strip_prefix('$')?;
    let mut out = Vec::new();
    while !rest.is_empty() {
        if let Some(r) = rest.strip_prefix("['") {
            let end = r.find("']")?;
            out.push(r[..end].to_string());
            rest = &r[end + 2..];
        } else if let Some(r) = rest.strip_prefix('.') {
            let end = r.find(['.', '[']).unwrap_or(r.len());
            let name = &r[..end];
            if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
                return None;
            }
            out.push(name.to_string());
            rest = &r[end..];
        } else {
            return None;
        }
    }
    (!out.is_empty()).then_some(out)
}

fn parse_status(s: &str) -> Result<Vec<(u16, u16)>> {
    let mut out = Vec::new();
    for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let lower = part.to_ascii_lowercase();
        let range = if let Some(d) = lower.strip_suffix("xx") {
            let d: u16 = d.parse().map_err(|_| anyhow!("status {part}"))?;
            (d * 100, d * 100 + 99)
        } else if let Some((a, b)) = lower.split_once('-') {
            (a.trim().parse().map_err(|_| anyhow!("status {part}"))?, b.trim().parse().map_err(|_| anyhow!("status {part}"))?)
        } else {
            let n: u16 = lower.parse().map_err(|_| anyhow!("status {part}"))?;
            (n, n)
        };
        out.push(range);
    }
    Ok(out)
}

const FRAMING: &[&str] = &["content-length", "transfer-encoding", "content-encoding", "connection", "upgrade"];

fn compile(r: &RewriteRule) -> Result<Compiled> {
    let matcher = Matcher::parse(&r.match_)?;
    if matcher.needs_body() {
        bail!("rewrite rules match by URL, method and headers (no body patterns)");
    }
    let path = |p: &str| JsonPath::parse(p).map_err(|e| anyhow!("JSONPath {p}: {e}"));
    let mut ops = Vec::new();
    for op in &r.ops {
        ops.push(match op {
            Op::SetHeader { .. } | Op::RemoveHeader { .. } | Op::SetStatus { .. } if r.phase == Phase::WebSocket => bail!("WebSocket messages have no headers or status; use JSON or regex changes"),
            Op::JsonSet { path: p, value } => COp::JsonSet(path(p)?, plain_members(p), value.clone()),
            Op::JsonRemove { path: p } => COp::JsonRemove(path(p)?),
            Op::JsonAppend { path: p, value } => COp::JsonAppend(path(p)?, value.clone()),
            Op::JsonAppendAll { value } => COp::JsonAppendAll(value.clone()),
            Op::RegexReplace { pattern, replacement } => COp::Regex(Regex::new(pattern).map_err(|e| anyhow!("regex: {e}"))?, replacement.clone()),
            Op::SetHeader { name, .. } | Op::RemoveHeader { name } if FRAMING.contains(&name.trim().to_ascii_lowercase().as_str()) => {
                bail!("{name} is set by Quena (message framing)")
            }
            Op::SetHeader { name, value } => COp::SetHeader(name.trim().to_string(), value.clone()),
            Op::RemoveHeader { name } => COp::RemoveHeader(name.trim().to_string()),
            Op::SetStatus { code } if r.phase == Phase::Request => bail!("setStatus applies to responses (status {code})"),
            Op::SetStatus { code } if !(100..=999).contains(code) || *code == 101 => bail!("status {code} is not allowed"),
            Op::SetStatus { code } => COp::SetStatus(*code),
        });
    }
    if ops.is_empty() {
        bail!("a rewrite rule needs at least one operation");
    }
    let types = r.content_type.split(';').map(|t| t.trim().to_ascii_lowercase()).filter(|t| !t.is_empty()).collect();
    Ok(Compiled {
        matcher,
        status: parse_status(&r.status)?,
        types,
        body_ops: r.ops.iter().any(Op::on_body),
        head_ops: r.ops.iter().any(|o| !o.on_body()),
        json_only: r.ops.iter().filter(|o| o.on_body()).all(|o| !matches!(o, Op::RegexReplace { .. })),
        ops,
        rule: r.clone(),
        hits: AtomicU64::new(0),
    })
}

impl Compiled {
    fn status_ok(&self, status: u16) -> bool {
        self.status.is_empty() || self.status.iter().any(|(a, b)| (*a..=*b).contains(&status))
    }
    fn type_ok(&self, ct: Option<&str>) -> bool {
        let ct = ct.unwrap_or("").to_ascii_lowercase();
        if streaming_type(&ct) {
            return false;
        }
        if !self.types.is_empty() {
            self.types.iter().any(|t| ct.contains(t.as_str()))
        } else if self.json_only {
            quena_body::charset::is_json(ct.split(';').next().unwrap_or("").trim())
        } else {
            crate::dto::is_textual_type(&ct)
        }
    }
}

/// Bodies that arrive piece by piece and are read that way (holding them back would stall
/// the client): event streams, newline-delimited JSON, JSON text sequences, multipart
/// streams, gRPC.
fn streaming_type(ct: &str) -> bool {
    ["event-stream", "ndjson", "jsonl", "json-seq", "stream+json", "x-mixed-replace", "grpc"].iter().any(|t| ct.contains(t))
}

/// Partial content cannot be rewritten (the change would not match the other ranges).
fn partial(h: &Headers, status: u16) -> bool {
    status == 206 || h.get("content-range").is_some()
}

// ------------------------------------------------------------------ engine

/// The rule set, compiled once per change; the forwarding path only reads an `Arc`.
pub struct Rewriter {
    /// Weighted by body size in MiB (see [`TRANSFORM_BUDGET_MIB`]).
    transforms: Arc<tokio::sync::Semaphore>,
    state: RwLock<RewriteState>,
    compiled: RwLock<Arc<Vec<Compiled>>>,
    active: AtomicBool,
    has_request: AtomicBool,
    has_response: AtomicBool,
    edit: Mutex<()>,
    next_id: AtomicU64,
    path: PathBuf,
}

/// What a rewrite did to a message (for the session comment).
pub(crate) struct Applied {
    pub names: Vec<String>,
    pub notes: Vec<String>,
}

impl Applied {
    pub fn comment(&self) -> String {
        let mut s = format!("Rewrite: {}", self.names.join(", "));
        if !self.notes.is_empty() {
            s.push_str(&format!(" ({})", self.notes.join("; ")));
        }
        s
    }
}

impl Rewriter {
    pub fn load(data_dir: &std::path::Path) -> Rewriter {
        let path = data_dir.join("rewrite.json");
        let state: RewriteState = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_else(|e| {
                let aside = crate::keep_corrupt(&path);
                tracing::warn!(target: "quena", "rewrite rules unreadable ({e}); starting without them, the old file was kept as {aside}");
                RewriteState::default()
            }),
            Err(_) => RewriteState::default(),
        };
        let r = Rewriter {
            transforms: Arc::new(tokio::sync::Semaphore::new(TRANSFORM_BUDGET_MIB as usize)),
            next_id: AtomicU64::new(state.rules.iter().map(|r| r.id).max().unwrap_or(0) + 1),
            state: RwLock::new(RewriteState::default()),
            compiled: RwLock::new(Arc::new(vec![])),
            active: AtomicBool::new(false),
            has_request: AtomicBool::new(false),
            has_response: AtomicBool::new(false),
            edit: Mutex::new(()),
            path,
        };
        if let Err(e) = r.install(state.clone(), false) {
            // Keep the file's rules (shown, editable) but run none of them.
            tracing::warn!(target: "quena", "rewrite rules not active: {e:#}");
            *r.state.write() = state;
        }
        r
    }

    /// The rules with their hit counts.
    pub fn state(&self) -> RewriteState {
        let mut s = self.state.read().clone();
        let c = self.compiled.read().clone();
        for r in &mut s.rules {
            if let Some(x) = c.iter().find(|x| x.rule.id == r.id) {
                r.hits = x.hits.load(Ordering::Relaxed);
            }
        }
        s
    }

    /// Replace the rule set; an invalid rule rejects the whole change.
    pub fn set(&self, s: RewriteState) -> Result<RewriteState> {
        let _g = self.edit.lock();
        self.install(s, true)?;
        Ok(self.state())
    }

    /// Change the rule set atomically (see `Rules::update_autoresponder`).
    pub fn update<R>(&self, f: impl FnOnce(&mut RewriteState) -> R) -> Result<R> {
        let _g = self.edit.lock();
        let mut s = self.state();
        let r = f(&mut s);
        self.install(s, true)?;
        Ok(r)
    }

    /// Add a rule (first or last); returns its id.
    pub fn add(&self, rule: RewriteRule, first: bool) -> Result<u64> {
        let _g = self.edit.lock();
        let mut s = self.state();
        let at = if first { 0 } else { s.rules.len() };
        s.rules.insert(at, RewriteRule { id: 0, ..rule });
        self.install(s, true)?;
        Ok(self.state.read().rules[at].id)
    }

    fn install(&self, mut s: RewriteState, save: bool) -> Result<()> {
        let old = self.compiled.read().clone();
        let mut compiled = Vec::new();
        for r in &mut s.rules {
            if r.id == 0 {
                r.id = self.next_id.fetch_add(1, Ordering::Relaxed);
            }
        }
        for r in &s.rules {
            if !s.runs(r) {
                continue;
            }
            let c = compile(r).map_err(|e| anyhow!("rewrite rule {} ('{}'): {e}", r.id, r.match_))?;
            c.hits.store(old.iter().find(|x| x.rule.id == r.id).map(|x| x.hits.load(Ordering::Relaxed)).unwrap_or(r.hits), Ordering::Relaxed);
            compiled.push(c);
        }
        // Disabled rules keep their count in the state.
        for r in &mut s.rules {
            if let Some(x) = old.iter().find(|x| x.rule.id == r.id) {
                r.hits = x.hits.load(Ordering::Relaxed);
            }
        }
        let on = s.enabled && !compiled.is_empty();
        self.has_request.store(on && compiled.iter().any(|c| c.rule.phase == Phase::Request), Ordering::Relaxed);
        self.has_response.store(on && compiled.iter().any(|c| c.rule.phase == Phase::Response), Ordering::Relaxed);
        *self.compiled.write() = Arc::new(compiled);
        if save {
            std::fs::write(&self.path, serde_json::to_vec_pretty(&s)?)?;
        }
        *self.state.write() = s;
        self.active.store(on, Ordering::Relaxed);
        Ok(())
    }

    /// Wait until a body of `len` bytes may be changed (bounds the memory of parallel changes).
    pub async fn transform_permit(&self, len: u64) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let mib = u32::try_from(len >> 20).unwrap_or(u32::MAX).clamp(1, TRANSFORM_BUDGET_MIB);
        self.transforms.clone().acquire_many_owned(mib).await.ok()
    }

    /// Largest body changed (held back in memory while it arrives, so at most 16 MiB).
    pub fn max_body(&self) -> usize {
        (self.state.read().max_body_kb.clamp(1, MAX_BODY_KB) as usize) << 10
    }

    fn matching(&self, phase: Phase, req: &RequestHead, status: Option<u16>, ct: Option<&str>) -> Vec<usize> {
        let c = self.compiled.read().clone();
        c.iter()
            .enumerate()
            .filter(|(_, x)| x.rule.phase == phase && status.is_none_or(|s| x.status_ok(s)) && x.matcher.matches_head(req))
            .filter(|(_, x)| !x.body_ops || x.head_ops || x.type_ok(ct))
            .map(|(i, _)| i)
            .collect()
    }

    /// Does a WebSocket rule apply to the connection upgraded by `req`?
    pub fn wants_ws(&self, req: &RequestHead) -> bool {
        self.active.load(Ordering::Relaxed) && self.compiled.read().iter().any(|x| x.rule.phase == Phase::WebSocket && x.matcher.matches_head(req))
    }

    /// A text message of the WebSocket upgraded by `req`, changed by the WebSocket rules for
    /// direction `dir` (`None`: unchanged). JSON in a Socket.IO packet (`42["event",{…}]`) is
    /// changed in place, keeping the packet prefix.
    pub fn ws_message(&self, req: &RequestHead, dir: u8, text: &str) -> Option<String> {
        if !self.active.load(Ordering::Relaxed) {
            return None;
        }
        let c = self.compiled.read().clone();
        let want = if dir == quena_model::wslog::DIR_CLIENT { WsDirection::Up } else { WsDirection::Down };
        let rules: Vec<&Compiled> = c.iter().filter(|x| x.rule.phase == Phase::WebSocket && (x.rule.direction == WsDirection::Both || x.rule.direction == want) && x.matcher.matches_head(req)).collect();
        if rules.is_empty() {
            return None;
        }
        // Socket.IO / Engine.IO: digits, an optional namespace and ack id before the JSON.
        let split = ws_json_start(text);
        let (prefix, json) = text.split_at(split);
        let (out, _) = transform(json, &rules);
        let out = out?;
        for x in &rules {
            x.hits.fetch_add(1, Ordering::Relaxed);
        }
        Some(format!("{prefix}{out}"))
    }

    /// Any rule active (shown in the status bar: they change real traffic).
    pub fn active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    pub fn wants_request(&self) -> bool {
        self.active.load(Ordering::Relaxed) && self.has_request.load(Ordering::Relaxed)
    }

    pub fn wants_response(&self) -> bool {
        self.active.load(Ordering::Relaxed) && self.has_response.load(Ordering::Relaxed)
    }

    /// Must the request body be buffered for a body change?
    pub fn request_needs_body(&self, head: &RequestHead) -> bool {
        if !self.wants_request() || !has_body(&head.headers) || partial(&head.headers, 0) {
            return false;
        }
        let ct = head.headers.get("content-type");
        let c = self.compiled.read().clone();
        size_ok(&head.headers, self.max_body())
            && c.iter().any(|x| x.rule.phase == Phase::Request && x.body_ops && x.type_ok(ct) && x.matcher.matches_head(head))
    }

    /// Must the response body be buffered for a body change?
    pub fn response_needs_body(&self, req: &RequestHead, resp: &ResponseHead) -> bool {
        if !self.wants_response() || req.method.eq_ignore_ascii_case("HEAD") || matches!(resp.status, 100..=199 | 204 | 304) || partial(&resp.headers, resp.status) {
            return false;
        }
        let ct = resp.headers.get("content-type");
        let c = self.compiled.read().clone();
        size_ok(&resp.headers, self.max_body())
            && c.iter().any(|x| x.rule.phase == Phase::Response && x.body_ops && x.status_ok(resp.status) && x.type_ok(ct) && x.matcher.matches_head(req))
    }

    /// Header and status changes of a response (no body involved). `None`: unchanged.
    pub(crate) fn response_head(&self, req: &RequestHead, resp: &ResponseHead) -> Option<(ResponseHead, Applied)> {
        if !self.wants_response() {
            return None;
        }
        let c = self.compiled.read().clone();
        let mut head = resp.clone();
        let mut applied = Applied { names: vec![], notes: vec![] };
        for i in self.matching(Phase::Response, req, Some(resp.status), resp.headers.get("content-type")) {
            let x = &c[i];
            if !x.head_ops {
                continue;
            }
            for op in &x.ops {
                match op {
                    COp::SetHeader(n, v) => head.headers.set(n, v.clone()),
                    COp::RemoveHeader(n) => head.headers.remove(n),
                    COp::SetStatus(s) => {
                        head.status = *s;
                        head.reason = crate::mock::reason(*s).to_string();
                    }
                    _ => {}
                }
            }
            // A rule with header changes counts here, once (its body part may not apply).
            x.hits.fetch_add(1, Ordering::Relaxed);
            applied.names.push(name_of(&x.rule));
        }
        (!applied.names.is_empty()).then_some((head, applied))
    }

    /// Header changes of a request (applied whether or not the body is buffered).
    pub(crate) fn request_head(&self, head: &RequestHead) -> Option<(RequestHead, Applied)> {
        if !self.wants_request() {
            return None;
        }
        let c = self.compiled.read().clone();
        let mut out = head.clone();
        let mut applied = Applied { names: vec![], notes: vec![] };
        for i in self.matching(Phase::Request, head, None, head.headers.get("content-type")) {
            let x = &c[i];
            if !x.head_ops {
                continue;
            }
            for op in &x.ops {
                match op {
                    COp::SetHeader(n, v) => out.headers.set(n, v.clone()),
                    COp::RemoveHeader(n) => out.headers.remove(n),
                    _ => {}
                }
            }
            x.hits.fetch_add(1, Ordering::Relaxed);
            applied.names.push(name_of(&x.rule));
        }
        (!applied.names.is_empty()).then_some((out, applied))
    }

    /// Body changes of a buffered message. `matched_on` is the request (URL, method,
    /// headers the rules match); `headers` are the message's own. Returns the new body
    /// bytes and headers, or `None` when nothing changed (the reason, if any, in `notes`).
    pub(crate) fn body(&self, phase: Phase, matched_on: &RequestHead, status: Option<u16>, headers: &Headers, body: &Body) -> (Option<(Headers, Vec<u8>)>, Applied) {
        let mut applied = Applied { names: vec![], notes: vec![] };
        let ct = headers.get("content-type");
        let c = self.compiled.read().clone();
        let rules: Vec<&Compiled> = self.matching(phase, matched_on, status, ct).into_iter().map(|i| &c[i]).filter(|x| x.body_ops && x.type_ok(ct)).collect();
        if rules.is_empty() || partial(headers, status.unwrap_or(0)) {
            return (None, applied);
        }
        for x in &rules {
            applied.names.push(name_of(&x.rule));
        }
        let (out, notes) = transform_body(&rules, headers, body, self.max_body());
        applied.notes.extend(notes);
        for x in rules.iter().filter(|x| !x.head_ops) {
            x.hits.fetch_add(1, Ordering::Relaxed);
        }
        (out, applied)
    }

    /// Apply a rule (enabled or not, unsaved) to a captured message without traffic.
    pub fn preview(&self, rule: &RewriteRule, text: &str) -> Result<(String, Vec<String>)> {
        let c = compile(rule)?;
        let (out, notes) = transform(text, &[&c]);
        Ok((out.unwrap_or_else(|| text.to_string()), notes))
    }
}

/// The body after the body operations of `rules` (decoding Content-Encoding and charset,
/// encoding the result as text). `None`: unchanged; the reason, if any, in the notes.
fn transform_body(rules: &[&Compiled], headers: &Headers, body: &Body, max: usize) -> (Option<(Headers, Vec<u8>)>, Vec<String>) {
    let mut notes = Vec::new();
    let ct = headers.get("content-type");
    let raw = match read_complete(body, max) {
        Ok(r) => r,
        Err(e) => {
            notes.push(e);
            return (None, notes);
        }
    };
    let ce = headers.get("content-encoding").map(str::trim).filter(|c| !c.is_empty() && !c.eq_ignore_ascii_case("identity"));
    let decoded = match ce {
        Some(ce) => match quena_body::decode::decode_bytes(&raw, ce, max + 1) {
            Ok(d) if d.len() > max => {
                notes.push(format!("body larger than {} KiB decoded, unchanged", max >> 10));
                return (None, notes);
            }
            Ok(d) => d,
            Err(e) => {
                notes.push(format!("cannot decode {ce}: {e}"));
                return (None, notes);
            }
        },
        None => raw,
    };
    let det = quena_body::charset::detect(ct, &decoded[..decoded.len().min(quena_body::text::DETECT_PREFIX)]);
    let text = quena_body::charset::decode(&decoded[det.bom_len.min(decoded.len())..], det.encoding).0.into_owned();
    let (new_text, n) = transform(&text, rules);
    notes.extend(n);
    let Some(new_text) = new_text.filter(|t| *t != text) else { return (None, notes) };
    let mut h = headers.clone();
    h.remove("content-encoding");
    let (bytes, new_ct) = quena_body::text::encode_edited(&new_text, ct, Some(det.name()));
    if let Some(ct) = new_ct {
        h.set("Content-Type", ct);
    }
    // Validators describe the original bytes.
    h.remove("content-md5");
    (Some((h, bytes)), notes)
}

/// A captured exchange after rewrite rules were applied to it ([`apply_offline`]).
#[derive(Debug, Clone)]
pub struct Offline {
    pub request: RequestHead,
    pub response: Option<ResponseHead>,
    /// New bodies (identity encoding); `None`: unchanged.
    pub request_body: Option<Vec<u8>>,
    pub response_body: Option<Vec<u8>>,
    /// Names of the rules that changed something.
    pub names: Vec<String>,
    pub notes: Vec<String>,
}

impl Offline {
    pub fn changed(&self) -> bool {
        !self.names.is_empty()
    }
}

/// Apply `rules` (whether enabled or not) to a captured exchange, without traffic and
/// without counting hits: match, phase, status and content-type filters as on live traffic.
pub fn apply_offline(rules: &[RewriteRule], max_body_kb: u64, req: &RequestHead, resp: Option<&ResponseHead>, req_body: &Body, resp_body: &Body) -> Result<Offline> {
    let compiled: Vec<Compiled> = rules.iter().map(|r| compile(r).map_err(|e| anyhow!("rewrite rule {} ('{}'): {e}", r.id, r.match_))).collect::<Result<_>>()?;
    let max = (max_body_kb.clamp(1, MAX_BODY_KB) as usize) << 10;
    let mut out = Offline { request: req.clone(), response: resp.cloned(), request_body: None, response_body: None, names: vec![], notes: vec![] };
    let note = |names: &mut Vec<String>, x: &Compiled| {
        let n = name_of(&x.rule);
        if !names.contains(&n) {
            names.push(n);
        }
    };
    // Request: headers, then the body.
    let req_ct = req.headers.get("content-type").map(str::to_string);
    let req_rules: Vec<&Compiled> = compiled.iter().filter(|x| x.rule.phase == Phase::Request && x.matcher.matches_head(req)).collect();
    for x in &req_rules {
        let mut touched = false;
        for op in &x.ops {
            match op {
                COp::SetHeader(n, v) => {
                    out.request.headers.set(n, v.clone());
                    touched = true;
                }
                COp::RemoveHeader(n) => {
                    out.request.headers.remove(n);
                    touched = true;
                }
                _ => {}
            }
        }
        if touched {
            note(&mut out.names, x);
        }
    }
    let body_rules: Vec<&Compiled> = req_rules.iter().copied().filter(|x| x.body_ops && x.type_ok(req_ct.as_deref())).collect();
    if !body_rules.is_empty() && req_body.len() > 0 {
        let (b, notes) = transform_body(&body_rules, &out.request.headers, req_body, max);
        out.notes.extend(notes);
        if let Some((h, bytes)) = b {
            out.request.headers = h;
            out.request.headers.set("Content-Length", bytes.len().to_string());
            out.request_body = Some(bytes);
            body_rules.iter().for_each(|x| note(&mut out.names, x));
        }
    }
    // Response: status and headers, then the body; matched on the original request.
    if let Some(resp) = resp {
        let ct = resp.headers.get("content-type").map(str::to_string);
        let rules: Vec<&Compiled> = compiled.iter().filter(|x| x.rule.phase == Phase::Response && x.status_ok(resp.status) && x.matcher.matches_head(req)).collect();
        let mut head = resp.clone();
        for x in &rules {
            let mut touched = false;
            for op in &x.ops {
                match op {
                    COp::SetHeader(n, v) => {
                        head.headers.set(n, v.clone());
                        touched = true;
                    }
                    COp::RemoveHeader(n) => {
                        head.headers.remove(n);
                        touched = true;
                    }
                    COp::SetStatus(st) => {
                        head.status = *st;
                        head.reason = crate::mock::reason(*st).to_string();
                        touched = true;
                    }
                    _ => {}
                }
            }
            if touched {
                note(&mut out.names, x);
            }
        }
        let body_rules: Vec<&Compiled> = rules.iter().copied().filter(|x| x.body_ops && x.type_ok(ct.as_deref())).collect();
        if !body_rules.is_empty() && resp_body.len() > 0 && !partial(&resp.headers, resp.status) {
            let (b, notes) = transform_body(&body_rules, &head.headers, resp_body, max);
            out.notes.extend(notes);
            if let Some((h, bytes)) = b {
                head.headers = h;
                if head.headers.get("content-length").is_some() || head.headers.get("transfer-encoding").is_none() {
                    head.headers.set("Content-Length", bytes.len().to_string());
                }
                head.headers.remove("transfer-encoding");
                out.response_body = Some(bytes);
                body_rules.iter().for_each(|x| note(&mut out.names, x));
            }
        }
        out.response = Some(head);
    }
    Ok(out)
}

fn name_of(r: &RewriteRule) -> String {
    if r.comment.trim().is_empty() { format!("#{}", r.id) } else { r.comment.trim().to_string() }
}

/// The message announces a body (requests without one are never buffered).
fn has_body(h: &Headers) -> bool {
    h.get("transfer-encoding").is_some() || h.get("content-length").and_then(|l| l.trim().parse::<u64>().ok()).is_some_and(|l| l > 0)
}

/// Content-Length within the limit, or unknown (then checked after buffering).
fn size_ok(h: &Headers, max: usize) -> bool {
    h.get("content-length").and_then(|l| l.trim().parse::<u64>().ok()).is_none_or(|l| l <= max as u64)
}

fn read_complete(body: &Body, max: usize) -> std::result::Result<Vec<u8>, String> {
    if !body.is_complete() || body.is_truncated() {
        return Err("body incomplete, unchanged".into());
    }
    if body.len() > max as u64 {
        return Err(format!("body larger than {} KiB, unchanged", max >> 10));
    }
    body.read_range(0, body.len() as usize).map_err(|e| format!("reading the body failed: {e}"))
}

/// The text after all body operations of `rules`; `None` if nothing applied.
fn transform(text: &str, rules: &[&Compiled]) -> (Option<String>, Vec<String>) {
    let mut notes = Vec::new();
    let mut cur = text.to_string();
    let mut changed = false;
    let pretty = text.trim_start().starts_with(['{', '[']) && text.contains('\n');
    for x in rules {
        let mut json: Option<Value> = None;
        for op in &x.ops {
            match op {
                COp::Regex(re, rep) => {
                    if let Some(v) = json.take() {
                        cur = to_text(&v, pretty);
                    }
                    let out = re.replace_all(&cur, rep.as_str());
                    if out != cur {
                        cur = out.into_owned();
                        changed = true;
                    }
                }
                COp::SetHeader(..) | COp::RemoveHeader(..) | COp::SetStatus(_) => {}
                json_op => {
                    if json.is_none() {
                        match serde_json::from_str::<Value>(&cur) {
                            Ok(v) => json = Some(v),
                            Err(_) => {
                                notes.push(format!("{}: body is not JSON", name_of(&x.rule)));
                                break;
                            }
                        }
                    }
                    if let Some(v) = json.as_mut()
                        && apply_json(json_op, v)
                    {
                        changed = true;
                    }
                }
            }
        }
        if let Some(v) = json {
            cur = to_text(&v, pretty);
        }
    }
    (changed.then_some(cur), notes)
}

/// Where the JSON of a WebSocket text message starts: 0, or after a Socket.IO packet
/// prefix (`42`, `42/chat,`, `4317`, `451-`).
fn ws_json_start(text: &str) -> usize {
    let b = text.as_bytes();
    if b.first().is_none_or(|c| !c.is_ascii_digit()) {
        return 0;
    }
    match text.find(['[', '{']) {
        Some(i) if text[..i].bytes().all(|c| c.is_ascii_digit() || c == b'-' || c == b'/' || c == b',' || c.is_ascii_alphanumeric() || c == b'_') => i,
        _ => 0,
    }
}

fn to_text(v: &Value, pretty: bool) -> String {
    if pretty { serde_json::to_string_pretty(v) } else { serde_json::to_string(v) }.unwrap_or_default()
}

/// A "broken" element like `sample`: objects keep their keys with null values.
fn broken_like(sample: Option<&Value>) -> Value {
    match sample {
        Some(Value::Object(o)) => Value::Object(o.keys().map(|k| (k.clone(), Value::Null)).collect()),
        Some(Value::Array(_)) => Value::Array(vec![]),
        _ => Value::Null,
    }
}

fn append_to(a: &mut Vec<Value>, value: &Option<Value>) {
    let v = value.clone().unwrap_or_else(|| broken_like(a.first()));
    a.push(v);
}

fn append_all(v: &mut Value, value: &Option<Value>) -> bool {
    match v {
        Value::Array(a) => {
            for x in a.iter_mut() {
                append_all(x, value);
            }
            append_to(a, value);
            true
        }
        Value::Object(o) => {
            let mut any = false;
            for x in o.values_mut() {
                any |= append_all(x, value);
            }
            any
        }
        _ => false,
    }
}

fn pointers(path: &JsonPath, v: &Value) -> Vec<String> {
    path.query_located(v).locations().map(|l| l.to_json_pointer()).collect()
}

/// Apply one JSON operation; `true` if the document changed.
fn apply_json(op: &COp, v: &mut Value) -> bool {
    match op {
        COp::JsonSet(path, members, value) => {
            let ptrs = pointers(path, v);
            if ptrs.is_empty() {
                return members.as_ref().is_some_and(|m| create_member(v, m, value.clone()));
            }
            let mut changed = false;
            for p in ptrs {
                if let Some(t) = v.pointer_mut(&p)
                    && *t != *value
                {
                    *t = value.clone();
                    changed = true;
                }
            }
            changed
        }
        COp::JsonRemove(path) => {
            // Deepest and highest array index first, so the other pointers stay valid
            // (a selector list like `[1,0]` yields them in its own order).
            let mut ptrs = pointers(path, v);
            ptrs.sort_by_key(|p| std::cmp::Reverse(pointer_key(p)));
            let mut changed = false;
            for p in ptrs {
                changed |= remove_at(v, &p);
            }
            changed
        }
        COp::JsonAppend(path, value) => {
            let mut changed = false;
            for p in pointers(path, v) {
                if let Some(Value::Array(a)) = v.pointer_mut(&p) {
                    append_to(a, value);
                    changed = true;
                }
            }
            changed
        }
        COp::JsonAppendAll(value) => append_all(v, value),
        _ => false,
    }
}

/// Sort key of a JSON pointer: its tokens, array indices compared as numbers.
fn pointer_key(ptr: &str) -> Vec<(u8, usize, String)> {
    ptr.split('/').skip(1).map(|t| match t.parse::<usize>() {
        Ok(n) => (0, n, String::new()),
        Err(_) => (1, 0, t.to_string()),
    }).collect()
}

fn unescape(token: &str) -> String {
    token.replace("~1", "/").replace("~0", "~")
}

fn remove_at(v: &mut Value, ptr: &str) -> bool {
    if ptr.is_empty() {
        return false;
    }
    let Some((parent, last)) = ptr.rsplit_once('/') else { return false };
    let key = unescape(last);
    match v.pointer_mut(parent) {
        Some(Value::Object(o)) => o.remove(&key).is_some(),
        Some(Value::Array(a)) => match key.parse::<usize>() {
            Ok(i) if i < a.len() => {
                a.remove(i);
                true
            }
            _ => false,
        },
        _ => false,
    }
}

fn create_member(v: &mut Value, members: &[String], value: Value) -> bool {
    let mut cur = v;
    for (i, m) in members.iter().enumerate() {
        let Value::Object(o) = cur else { return false };
        if i + 1 == members.len() {
            o.insert(m.clone(), value);
            return true;
        }
        cur = o.entry(m.clone()).or_insert_with(|| Value::Object(Default::default()));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rule(ops: Vec<Op>) -> RewriteRule {
        RewriteRule { id: 1, ops, ..Default::default() }
    }

    fn run(text: &str, ops: Vec<Op>) -> (String, Vec<String>) {
        let c = compile(&rule(ops)).unwrap();
        let (t, n) = transform(text, &[&c]);
        (t.unwrap_or_else(|| text.to_string()), n)
    }

    #[test]
    fn json_set_remove_append() {
        let doc = r#"{"items":[{"id":1,"name":"a"},{"id":2,"name":"b"}],"total":2}"#;
        let (t, _) = run(doc, vec![Op::JsonSet { path: "$.items[*].name".into(), value: json!("x") }]);
        assert_eq!(t, r#"{"items":[{"id":1,"name":"x"},{"id":2,"name":"x"}],"total":2}"#);
        let (t, _) = run(doc, vec![Op::JsonRemove { path: "$.items[*].id".into() }, Op::JsonRemove { path: "$.total".into() }]);
        assert_eq!(t, r#"{"items":[{"name":"a"},{"name":"b"}]}"#);
        let (t, _) = run(doc, vec![Op::JsonRemove { path: "$.items[*]".into() }]);
        assert_eq!(t, r#"{"items":[],"total":2}"#);
        // A selector list in any order removes exactly those elements.
        let (t, _) = run(r#"{"a":[0,1,2,3]}"#, vec![Op::JsonRemove { path: "$.a[1,0]".into() }]);
        assert_eq!(t, r#"{"a":[2,3]}"#);
        let (t, _) = run(r#"{"a":[0,1,2,3,4,5,6,7,8,9,10,11]}"#, vec![Op::JsonRemove { path: "$.a[2,10]".into() }]);
        assert_eq!(t, r#"{"a":[0,1,3,4,5,6,7,8,9,11]}"#);
        let (t, _) = run(doc, vec![Op::JsonAppend { path: "$.items".into(), value: Some(json!({"id":"oops"})) }]);
        assert!(t.ends_with(r#"{"id":"oops"}],"total":2}"#), "{t}");
        // Missing members of a plain path are created.
        let (t, _) = run(doc, vec![Op::JsonSet { path: "$.meta.debug".into(), value: json!(true) }]);
        assert!(t.contains(r#""meta":{"debug":true}"#), "{t}");
    }

    #[test]
    fn broken_element_in_every_list() {
        let doc = r#"{"users":[{"id":1,"tags":["a"]}],"empty":[],"n":5}"#;
        let (t, _) = run(doc, vec![Op::JsonAppendAll { value: None }]);
        let v: Value = serde_json::from_str(&t).unwrap();
        assert_eq!(v["users"][1], json!({ "id": null, "tags": null }));
        assert_eq!(v["users"][0]["tags"], json!(["a", null]));
        assert_eq!(v["empty"], json!([null]));
        assert_eq!(v["n"], 5);
        // The root array too, and the appended element is not walked again.
        let (t, _) = run(r#"[[1],[2]]"#, vec![Op::JsonAppendAll { value: Some(json!("X")) }]);
        assert_eq!(t, r#"[[1,"X"],[2,"X"],"X"]"#);
    }

    #[test]
    fn regex_and_not_json() {
        let (t, n) = run("hello world", vec![Op::RegexReplace { pattern: "(w)orld".into(), replacement: "${1}ide".into() }]);
        assert_eq!((t.as_str(), n.len()), ("hello wide", 0));
        let (t, n) = run("<a/>", vec![Op::JsonSet { path: "$.a".into(), value: json!(1) }]);
        assert_eq!(t, "<a/>");
        assert!(n[0].contains("not JSON"));
        // Key order is kept.
        let (t, _) = run(r#"{"z":1,"a":2}"#, vec![Op::JsonSet { path: "$.a".into(), value: json!(3) }]);
        assert_eq!(t, r#"{"z":1,"a":3}"#);
        // Pretty documents stay pretty.
        let (t, _) = run("{\n  \"a\": 1\n}", vec![Op::JsonSet { path: "$.a".into(), value: json!(2) }]);
        assert_eq!(t, "{\n  \"a\": 2\n}");
    }

    #[test]
    fn compile_errors() {
        assert!(compile(&rule(vec![])).is_err());
        assert!(compile(&rule(vec![Op::JsonSet { path: "items".into(), value: json!(1) }])).is_err());
        assert!(compile(&rule(vec![Op::SetHeader { name: "Content-Length".into(), value: "1".into() }])).is_err());
        assert!(compile(&RewriteRule { match_: "BODYJSON:x {}".into(), ..rule(vec![Op::RemoveHeader { name: "X".into() }]) }).is_err());
        assert!(compile(&RewriteRule { phase: Phase::Request, ..rule(vec![Op::SetStatus { code: 500 }]) }).is_err());
        assert!(compile(&RewriteRule { status: "4xx, 200-204,500".into(), ..rule(vec![Op::SetStatus { code: 500 }]) }).is_ok());
        assert!(compile(&RewriteRule { status: "abc".into(), ..rule(vec![Op::SetStatus { code: 500 }]) }).is_err());
    }

    #[test]
    fn websocket_messages_and_socketio_packets() {
        assert_eq!(ws_json_start(r#"{"a":1}"#), 0);
        assert_eq!(ws_json_start(r#"42["chat",{"a":1}]"#), 2);
        assert_eq!(ws_json_start(r#"42/admin,7["x"]"#), 10);
        assert_eq!(ws_json_start("2probe"), 0);
        let rule = RewriteRule {
            phase: Phase::WebSocket,
            direction: WsDirection::Down,
            ops: vec![Op::JsonSet { path: "$[1].a".into(), value: serde_json::json!(2) }],
            ..Default::default()
        };
        let rw = Rewriter::load(&tempfile::tempdir().unwrap().keep());
        rw.set(RewriteState { enabled: true, rules: vec![rule], ..Default::default() }).unwrap();
        let req = RequestHead { method: "GET".into(), url: "wss://x.example/socket.io/?EIO=4".into(), ..Default::default() };
        assert!(rw.wants_ws(&req));
        assert_eq!(rw.ws_message(&req, quena_model::wslog::DIR_SERVER, r#"42["chat",{"a":1}]"#).as_deref(), Some(r#"42["chat",{"a":2}]"#));
        assert_eq!(rw.ws_message(&req, quena_model::wslog::DIR_CLIENT, r#"42["chat",{"a":1}]"#), None, "other direction");
        assert_eq!(rw.ws_message(&req, quena_model::wslog::DIR_SERVER, "plain text"), None);
        // Header and status changes make no sense for messages.
        let bad = RewriteRule { phase: Phase::WebSocket, ops: vec![Op::SetStatus { code: 500 }], ..Default::default() };
        assert!(compile(&bad).is_err());
    }

    #[test]
    fn content_types() {
        let json = compile(&rule(vec![Op::JsonAppendAll { value: None }])).unwrap();
        assert!(json.type_ok(Some("application/json; charset=utf-8")) && json.type_ok(Some("application/problem+json")));
        assert!(!json.type_ok(Some("text/html")) && !json.type_ok(Some("application/javascript")));
        assert!(!json.type_ok(Some("application/x-ndjson")) && !json.type_ok(Some("application/stream+json")) && !json.type_ok(Some("text/event-stream")));
        let text = compile(&rule(vec![Op::RegexReplace { pattern: "a".into(), replacement: "b".into() }])).unwrap();
        assert!(text.type_ok(Some("text/html")) && !text.type_ok(Some("image/png")) && !text.type_ok(Some("multipart/x-mixed-replace; boundary=x")));
        let own = compile(&RewriteRule { content_type: "xml".into(), ..rule(vec![Op::JsonAppendAll { value: None }]) }).unwrap();
        assert!(own.type_ok(Some("application/xml")) && !own.type_ok(Some("application/json")));
    }

    #[test]
    fn ops_serialize_with_a_tag() {
        let op: Op = serde_json::from_value(json!({ "op": "jsonAppendAll" })).unwrap();
        assert_eq!(op, Op::JsonAppendAll { value: None });
        let op: Op = serde_json::from_value(json!({ "op": "regexReplace", "pattern": "a", "replacement": "b" })).unwrap();
        assert!(matches!(op, Op::RegexReplace { .. }));
        assert_eq!(serde_json::to_value(Op::SetStatus { code: 503 }).unwrap(), json!({ "op": "setStatus", "code": 503 }));
    }
}

// ------------------------------------------------------------------ editor and offline use

/// A rule tried on a captured session ([`crate::AppCore::rewrite_preview`]).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RewritePreview {
    /// The rule's filters (match, phase, status, content type) take the session.
    pub matched: bool,
    /// Something changed.
    pub changed: bool,
    pub part: Phase,
    pub notes: Vec<String>,
    pub status_before: Option<u16>,
    pub status_after: Option<u16>,
    pub headers_before: Headers,
    pub headers_after: Headers,
    /// Body text (decoded), cut at [`PREVIEW_TEXT`].
    pub before: String,
    pub after: String,
}

/// Body text shown in a preview, at most.
const PREVIEW_TEXT: usize = 256 << 10;

/// What [`crate::AppCore::rewrite_apply`] did.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RewriteApplied {
    /// New sessions (copies with the changes).
    pub created: Vec<SessionId>,
    /// Sessions no rule changed.
    pub unchanged: usize,
}

fn body_text(bytes: &[u8], headers: &Headers) -> String {
    let det = quena_body::charset::detect(headers.get("content-type"), &bytes[..bytes.len().min(quena_body::text::DETECT_PREFIX)]);
    let mut t = quena_body::charset::decode(&bytes[det.bom_len.min(bytes.len())..], det.encoding).0.into_owned();
    if t.len() > PREVIEW_TEXT {
        let mut cut = PREVIEW_TEXT;
        while !t.is_char_boundary(cut) {
            cut -= 1;
        }
        t.truncate(cut);
        t.push_str("\n…");
    }
    t
}

impl crate::AppCore {
    fn rewriter(&self) -> Result<&Rewriter> {
        self.rules.as_ref().map(|r| &r.rewrite).ok_or_else(|| anyhow!("rules are not available"))
    }

    /// Save one rule: a new one (`id` 0) is added at the end, an existing one replaced.
    /// Locked like the agents' changes, so none is lost.
    pub fn rewrite_update(&self, rule: RewriteRule) -> Result<RewriteState> {
        let rw = self.rewriter()?;
        rw.update(|s| match s.rules.iter_mut().find(|r| r.id == rule.id && rule.id != 0) {
            Some(r) => *r = RewriteRule { hits: r.hits, ..rule },
            None => s.rules.push(RewriteRule { id: 0, ..rule }),
        })?;
        Ok(rw.state())
    }

    /// Try `rule` (saved or not, enabled or not) on session `id`, without traffic.
    pub fn rewrite_preview(&self, rule: RewriteRule, id: SessionId) -> Result<RewritePreview> {
        let cap = self.capture();
        let d = cap.detail(id).ok_or_else(|| anyhow!("session #{id} not found"))?;
        if rule.phase == Phase::WebSocket {
            return self.rewrite_preview_ws(rule, id, &d);
        }
        let (req_body, resp_body) = cap.bodies_of(id).ok_or_else(|| anyhow!("session #{id} not found"))?;
        let max_kb = self.rewriter()?.state().max_body_kb;
        let part = rule.phase;
        let off = apply_offline(std::slice::from_ref(&RewriteRule { enabled: true, ..rule.clone() }), max_kb, &d.request, d.response.as_ref(), &req_body, &resp_body)?;
        let matcher = compile(&rule)?;
        let matched = matcher.matcher.matches_head(&d.request) && (part == Phase::Request || d.response.as_ref().is_some_and(|r| matcher.status_ok(r.status)));
        let (headers_before, body, status_before) = match part {
            Phase::Request | Phase::WebSocket => (d.request.headers.clone(), req_body, None),
            Phase::Response => (d.response.as_ref().map(|r| r.headers.clone()).unwrap_or_default(), resp_body, d.response.as_ref().map(|r| r.status)),
        };
        let before_bytes = quena_body::text::decoded_prefix(&body, &crate::dto::spec_of(&headers_before), PREVIEW_TEXT + 1);
        let before = body_text(&before_bytes, &headers_before);
        let (headers_after, status_after, after) = match part {
            Phase::Request | Phase::WebSocket => (off.request.headers.clone(), None, off.request_body.as_deref().map(|b| body_text(b, &off.request.headers))),
            Phase::Response => {
                let h = off.response.as_ref().map(|r| r.headers.clone()).unwrap_or_default();
                let a = off.response_body.as_deref().map(|b| body_text(b, &h));
                (h, off.response.as_ref().map(|r| r.status), a)
            }
        };
        Ok(RewritePreview {
            matched,
            changed: off.changed(),
            part,
            notes: off.notes,
            status_before,
            status_after,
            headers_before,
            headers_after,
            after: after.unwrap_or_else(|| before.clone()),
            before,
        })
    }

    /// A WebSocket rule tried on the first text message of session `id` it applies to.
    fn rewrite_preview_ws(&self, rule: RewriteRule, id: SessionId, d: &quena_model::SessionDetail) -> Result<RewritePreview> {
        let c = compile(&rule)?;
        let matched = c.matcher.matches_head(&d.request);
        let frames = self.ws_frames(id, 0, 2000).frames;
        let dir_ok = |dir: u8| match rule.direction {
            WsDirection::Both => true,
            WsDirection::Up => dir == quena_model::wslog::DIR_CLIENT,
            WsDirection::Down => dir == quena_model::wslog::DIR_SERVER,
        };
        // The whole message (the list shows a shortened text), up to the size rules change.
        let first = frames.iter().find(|f| f.opcode == 1 && dir_ok(f.dir)).and_then(|f| {
            let whole = self.capture().bodies_of(id).and_then(|(_, b)| b.read_range(f.offset, (f.len as usize).min(1 << 20)).ok());
            whole.map(|b| String::from_utf8_lossy(&b).into_owned()).or_else(|| f.text.clone())
        });
        let mut notes = Vec::new();
        let (before, after) = match &first {
            Some(text) => {
                let i = ws_json_start(text);
                let (out, n) = transform(&text[i..], &[&c]);
                notes = n;
                (text.clone(), out.map(|o| format!("{}{o}", &text[..i])).unwrap_or_else(|| text.clone()))
            }
            None => {
                notes.push(if d.summary.kind == quena_model::SessionKind::WebSocket { "no text message in this direction".into() } else { "not a WebSocket session".into() });
                (String::new(), String::new())
            }
        };
        Ok(RewritePreview {
            matched,
            changed: before != after,
            part: Phase::WebSocket,
            notes,
            status_before: None,
            status_after: None,
            headers_before: Headers::default(),
            headers_after: Headers::default(),
            before,
            after,
        })
    }

    /// Apply rewrite rules to captured sessions: every session a rule changes gets a copy
    /// with the changes (marked as tampered); the originals stay as they were. Rules:
    /// `rule_ids`, else the rules of `group`, else the rules that run.
    pub fn rewrite_apply(&self, ids: &[SessionId], rule_ids: Option<&[u64]>, group: Option<&str>) -> Result<RewriteApplied> {
        let state = self.rewriter()?.state();
        let rules: Vec<RewriteRule> = match (rule_ids, group) {
            (Some(ids), _) => state.rules.iter().filter(|r| ids.contains(&r.id)).cloned().collect(),
            (None, Some(g)) => state.rules.iter().filter(|r| r.group.trim() == g.trim()).cloned().collect(),
            (None, None) => state.rules.iter().filter(|r| state.runs(r)).cloned().collect(),
        };
        if rules.is_empty() {
            bail!("no rewrite rules to apply");
        }
        let cap = self.capture();
        let mut out = RewriteApplied::default();
        for &id in ids {
            let (Some(d), Some((req_body, resp_body))) = (cap.detail(id), cap.bodies_of(id)) else { continue };
            if d.summary.kind != quena_model::SessionKind::Http {
                out.unchanged += 1;
                continue;
            }
            let off = apply_offline(&rules, state.max_body_kb, &d.request, d.response.as_ref(), &req_body, &resp_body)?;
            if !off.changed() {
                out.unchanged += 1;
                continue;
            }
            let mut nd = d.clone();
            nd.request = off.request;
            nd.response = off.response;
            nd.summary.flags |= quena_model::flags::TAMPERED;
            nd.summary.comment = format!("Rewrite of #{id}: {}", off.names.join(", "));
            nd.extra_flags.retain(|(k, _)| k != "x-quena-rewrite-of");
            nd.extra_flags.push(("x-quena-rewrite-of".into(), id.to_string()));
            let req = match off.request_body {
                Some(b) => cap.bodies.store_bytes(&b),
                None => req_body,
            };
            let resp = match off.response_body {
                Some(b) => cap.bodies.store_bytes(&b),
                None => resp_body,
            };
            out.created.push(cap.insert(nd, req, resp));
        }
        cap.index.tick();
        Ok(out)
    }
}
