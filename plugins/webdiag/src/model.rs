//! Data model of the diagnosis: sessions in, findings/metrics/operations out.
//! Mirrors `wit/plugin.wit` (interface `analyzer`) and `REPORT.md`.

/// Session timers: microseconds since the Unix epoch; handshake parts in milliseconds.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Timers {
    pub client_begin_request: Option<u64>,
    pub client_done_request: Option<u64>,
    pub server_connect_start: Option<u64>,
    pub server_connected: Option<u64>,
    pub server_begin_request: Option<u64>,
    pub server_done_request: Option<u64>,
    pub server_got_first_byte: Option<u64>,
    pub server_done_response: Option<u64>,
    pub client_done_response: Option<u64>,
    pub dns_ms: Option<u32>,
    pub tcp_connect_ms: Option<u32>,
    pub tls_handshake_ms: Option<u32>,
}

/// Character encoding facts of a textual body, from the first 256 KiB of the decoded body
/// (host side: `quena_body::charset::facts`; see `text-info` in the WIT and REPORT.md).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TextInfo {
    /// `charset` of the Content-Type as sent, and the WHATWG name it resolves to.
    pub header_charset: Option<String>,
    pub header_resolved: Option<String>,
    /// Declaration inside the document (XML declaration, HTML meta) and its WHATWG name.
    pub document_charset: Option<String>,
    pub document_resolved: Option<String>,
    /// Byte order mark (`UTF-8`, `UTF-16LE`, `UTF-16BE`).
    pub bom: Option<String>,
    /// Effective charset (WHATWG name) and where it came from (`bom`, `header`,
    /// `document`, `default`).
    pub effective: String,
    pub source: String,
    pub unknown_label: bool,
    /// Bytes examined.
    pub sampled: u64,
    pub non_ascii: bool,
    pub utf8_valid: bool,
    pub decode_errors: u32,
    pub replacement_chars: u32,
    pub double_encoded: u32,
    pub nul_bytes: u32,
    /// Magic bytes of a compressed stream at the start (`gzip`, `zstd`, `deflate`).
    pub looks_compressed: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Kind {
    #[default]
    Http,
    Tunnel,
    WebSocket,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Session {
    pub id: u64,
    pub kind: Kind,
    /// Start, µs since the epoch.
    pub started: u64,
    pub duration_ms: Option<u32>,
    pub method: String,
    /// Absolute URL.
    pub url: String,
    pub host: String,
    pub version: String,
    /// 0 = no response.
    pub status: u16,
    pub error: Option<String>,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub response_decoded_bytes: u64,
    pub content_type: String,
    pub request_headers: Vec<(String, String)>,
    pub response_headers: Vec<(String, String)>,
    pub timers: Timers,
    pub client_connection: Option<u64>,
    pub server_connection_reused: bool,
    pub tls_version: Option<String>,
    pub process: String,
    pub request_body_hash: Option<u64>,
    pub response_body_hash: Option<u64>,
    /// Encoding facts of textual bodies (boxed: most sessions of a large capture carry
    /// none or share the memory budget with their headers).
    pub request_text: Option<Box<TextInfo>>,
    pub response_text: Option<Box<TextInfo>>,
    /// The Content-Encoding could not be decoded: `unsupported: …` / `invalid: …`.
    pub request_decoding_error: Option<String>,
    pub response_decoding_error: Option<String>,
}

fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

impl Session {
    pub fn is_http(&self) -> bool {
        self.kind == Kind::Http
    }
    pub fn req_header(&self, name: &str) -> Option<&str> {
        header(&self.request_headers, name)
    }
    pub fn resp_header(&self, name: &str) -> Option<&str> {
        header(&self.response_headers, name)
    }
    /// All values of a response header (e.g. several `Set-Cookie`).
    pub fn resp_headers<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.response_headers.iter().filter(move |(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
    /// The capture knows when the session ended (a duration or a response-end timer).
    /// Sessions without one (still open at capture end, sparse imports) have no usable
    /// timing: `end()` falls back to the start, so they must not count as zero-length
    /// requests in timing statistics or dependency chains.
    pub fn has_end(&self) -> bool {
        self.duration_ms.is_some() || self.timers.client_done_response.is_some() || self.timers.server_done_response.is_some()
    }
    /// Still open at capture end: no response, no error and no end.
    pub fn incomplete(&self) -> bool {
        self.status == 0 && self.error.is_none() && !self.has_end()
    }
    /// End in µs since the epoch (start + duration when the timers are missing).
    pub fn end(&self) -> u64 {
        self.timers
            .client_done_response
            .or(self.timers.server_done_response)
            .unwrap_or(self.started + self.duration_ms.unwrap_or(0) as u64 * 1000)
            .max(self.started)
    }
    pub fn duration_us(&self) -> u64 {
        self.end() - self.started
    }
    /// Server time to first byte in ms (request sent → first response byte), if known.
    pub fn ttfb_ms(&self) -> Option<f64> {
        let t = &self.timers;
        let sent = t.server_done_request.or(t.server_begin_request)?;
        let first = t.server_got_first_byte?;
        (first >= sent).then(|| (first - sent) as f64 / 1000.0)
    }
    /// Download time in ms (first byte → last byte), if known.
    pub fn download_ms(&self) -> Option<f64> {
        let t = &self.timers;
        let first = t.server_got_first_byte?;
        let last = t.server_done_response?;
        (last >= first).then(|| (last - first) as f64 / 1000.0)
    }
    /// A new upstream connection was opened for this session (handshake timers present).
    pub fn new_connection(&self) -> bool {
        !self.server_connection_reused && self.timers.server_connect_start.is_some()
    }
    pub fn is_https(&self) -> bool {
        self.url.len() >= 8 && self.url[..8].eq_ignore_ascii_case("https://")
    }
    /// `type/subtype` of the response, lower-case, without parameters.
    pub fn mime(&self) -> String {
        self.content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase()
    }
    /// Failed without a usable response (connect error, timeout, reset …). A session that
    /// was still open at capture end ([`Session::incomplete`]) has not failed.
    pub fn failed(&self) -> bool {
        self.error.is_some() || (self.status == 0 && self.has_end())
    }
}

// ------------------------------------------------------------------ output

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::Warning => "warning",
            Severity::Info => "info",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    Count,
    Bytes,
    Ms,
    Ratio,
    Rate,
    Text,
}

impl Unit {
    pub fn as_str(self) -> &'static str {
        match self {
            Unit::Count => "count",
            Unit::Bytes => "bytes",
            Unit::Ms => "ms",
            Unit::Ratio => "ratio",
            Unit::Rate => "rate",
            Unit::Text => "text",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Metric {
    pub key: String,
    pub label: String,
    pub value: f64,
    pub unit: Unit,
    /// Only for `Unit::Text`.
    pub text: Option<String>,
}

impl Metric {
    pub fn new(key: &str, label: &str, value: f64, unit: Unit) -> Metric {
        Metric { key: key.into(), label: label.into(), value, unit, text: None }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Table {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    /// Rule id, e.g. `PERF-SEQ`.
    pub id: &'static str,
    /// Stable identity across captures: rule id + subject (see REPORT.md).
    pub key: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub categories: Vec<&'static str>,
    /// 0–100, orders findings within a severity.
    pub score: u8,
    pub observation: String,
    pub impact: String,
    pub hypotheses: Vec<String>,
    pub recommendations: Vec<String>,
    pub next_steps: Vec<String>,
    /// Modelled rather than measured.
    pub estimate: bool,
    pub threshold: Option<String>,
    pub facts: Vec<(String, String)>,
    pub table: Option<Table>,
    pub sessions: Vec<u64>,
    pub operation: Option<String>,
    pub tags: Vec<&'static str>,
}

impl Finding {
    /// A finding with the required parts; fill the rest with the builder methods.
    pub fn new(id: &'static str, subject: &str, severity: Severity, title: impl Into<String>, observation: impl Into<String>) -> Finding {
        Finding {
            id,
            key: if subject.is_empty() { id.to_string() } else { format!("{id}|{subject}") },
            title: title.into(),
            severity,
            confidence: Confidence::High,
            categories: vec![],
            score: 50,
            observation: observation.into(),
            impact: String::new(),
            hypotheses: vec![],
            recommendations: vec![],
            next_steps: vec![],
            estimate: false,
            threshold: None,
            facts: vec![],
            table: None,
            sessions: vec![],
            operation: None,
            tags: vec![],
        }
    }
    pub fn confidence(mut self, c: Confidence) -> Self {
        self.confidence = c;
        self
    }
    pub fn categories(mut self, c: &[&'static str]) -> Self {
        self.categories = c.to_vec();
        self
    }
    pub fn score(mut self, s: f64) -> Self {
        self.score = s.clamp(0.0, 100.0).round() as u8;
        self
    }
    pub fn impact(mut self, s: impl Into<String>) -> Self {
        self.impact = s.into();
        self
    }
    pub fn hypothesis(mut self, s: impl Into<String>) -> Self {
        self.hypotheses.push(s.into());
        self
    }
    pub fn recommend(mut self, s: impl Into<String>) -> Self {
        self.recommendations.push(s.into());
        self
    }
    pub fn next_step(mut self, s: impl Into<String>) -> Self {
        self.next_steps.push(s.into());
        self
    }
    pub fn estimate(mut self) -> Self {
        self.estimate = true;
        self
    }
    pub fn threshold(mut self, s: impl Into<String>) -> Self {
        self.threshold = Some(s.into());
        self
    }
    pub fn fact(mut self, label: impl Into<String>, value: impl Into<String>) -> Self {
        self.facts.push((label.into(), value.into()));
        self
    }
    pub fn table(mut self, columns: Vec<String>, rows: Vec<Vec<String>>) -> Self {
        self.table = Some(Table { columns, rows });
        self
    }
    pub fn sessions(mut self, ids: impl IntoIterator<Item = u64>) -> Self {
        self.sessions.extend(ids);
        self.sessions.sort_unstable();
        self.sessions.dedup();
        self
    }
    pub fn operation(mut self, op: &str) -> Self {
        self.operation = Some(op.to_string());
        self
    }
    pub fn tags(mut self, t: &[&'static str]) -> Self {
        self.tags.extend_from_slice(t);
        self
    }
}

/// A logical user/application operation: sessions that belong together (see ops.rs).
#[derive(Debug, Clone, PartialEq)]
pub struct Operation {
    pub id: String,
    pub label: String,
    pub start: u64,
    pub end: u64,
    /// Indexes into `Ctx::sessions` (not ids), in start order.
    pub members: Vec<usize>,
    pub metrics: Vec<Metric>,
    /// Recurring background requests (timers, polling), not a user action: per-operation
    /// checks (N+1, chattiness, latency chains …) skip it.
    pub background: bool,
    /// The main request (`ops::main_request`): session index, the source of the label.
    pub main: usize,
    /// Critical path (`net::critical_path`): session indexes in time order; its length is
    /// the `sequentialLevels` metric.
    pub critical_path: Vec<usize>,
}

// ------------------------------------------------------------------ options

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    #[default]
    En,
    De,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Network {
    pub id: String,
    pub name: String,
    pub rtt_ms: f64,
    pub mbps: f64,
    pub loss_pct: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Options {
    pub profile: String,
    pub lang: Lang,
    pub slow_ms: f64,
    pub ttfb_ms: f64,
    pub large_request_bytes: u64,
    pub large_response_bytes: u64,
    pub operation_gap_ms: f64,
    pub networks: Vec<Network>,
}

impl Default for Options {
    fn default() -> Self {
        let n = |id: &str, name: &str, rtt_ms: f64, mbps: f64, loss_pct: f64| Network { id: id.into(), name: name.into(), rtt_ms, mbps, loss_pct };
        Options {
            profile: "full".into(),
            lang: Lang::En,
            slow_ms: 1000.0,
            ttfb_ms: 500.0,
            large_request_bytes: 1 << 20,
            large_response_bytes: 5 << 20,
            operation_gap_ms: 1500.0,
            networks: vec![
                n("lan", "LAN", 1.0, 1000.0, 0.0),
                n("good-wan", "Good WAN", 20.0, 100.0, 0.0),
                n("vpn", "VPN/WAN", 60.0, 20.0, 0.1),
                n("weak-wan", "Weak WAN", 120.0, 5.0, 0.5),
                n("mobile", "Mobile", 80.0, 10.0, 1.0),
            ],
        }
    }
}

// ------------------------------------------------------------------ analysis context

/// Everything an analyzer sees. `sessions` are sorted by start time.
///
/// Per-session derived data (canonical form, template, endpoint, host, MIME type …) is
/// computed once per run, on first use, and shared by all analyzers: [`Ctx::prep`].
pub struct Ctx<'a> {
    pub sessions: &'a [Session],
    pub ops: &'a [Operation],
    pub opts: &'a Options,
    prep: std::cell::OnceCell<crate::prep::Prep>,
}

impl<'a> Ctx<'a> {
    pub fn new(sessions: &'a [Session], ops: &'a [Operation], opts: &'a Options) -> Ctx<'a> {
        Ctx { sessions, ops, opts, prep: std::cell::OnceCell::new() }
    }
    /// The shared per-run preparation (built on first use).
    pub fn prep(&self) -> &crate::prep::Prep {
        self.prep.get_or_init(|| crate::prep::Prep::build(self.sessions, self.ops))
    }
    /// Index of `s` in `sessions`; `s` must be an element of `sessions` (as every session
    /// reached through the context is), so that per-session data of [`Ctx::prep`] applies.
    pub fn index_of(&self, s: &Session) -> usize {
        let i = (s as *const Session as usize).wrapping_sub(self.sessions.as_ptr() as usize) / std::mem::size_of::<Session>().max(1);
        debug_assert!(i < self.sessions.len() && std::ptr::eq(&self.sessions[i], s), "session not from this context");
        i
    }
}

impl Ctx<'_> {
    /// Text in the report language: `ctx.l("Slow requests", "Langsame Requests")`.
    pub fn l<'s>(&self, en: &'s str, de: &'s str) -> &'s str {
        match self.opts.lang {
            Lang::En => en,
            Lang::De => de,
        }
    }
    pub fn de(&self) -> bool {
        self.opts.lang == Lang::De
    }
    /// HTTP sessions only (no tunnels / WebSocket frames), in start order.
    pub fn http(&self) -> impl Iterator<Item = &Session> {
        self.sessions.iter().filter(|s| s.is_http())
    }
    pub fn fmt_ms(&self, ms: f64) -> String {
        crate::fmt::ms(ms, self.opts.lang)
    }
    pub fn fmt_bytes(&self, b: f64) -> String {
        crate::fmt::bytes(b, self.opts.lang)
    }
    pub fn fmt_count(&self, n: usize) -> String {
        crate::fmt::count(n as f64, self.opts.lang)
    }
    pub fn fmt_pct(&self, ratio: f64) -> String {
        crate::fmt::pct(ratio, self.opts.lang)
    }
}

/// One diagnostic check. Analyzers are stateless; `run` sees the whole capture.
pub trait Analyzer {
    /// Rule id(s) this analyzer emits, e.g. `PERF-SLOW` (first one is its name).
    fn id(&self) -> &'static str;
    /// Profiles the analyzer runs in (`full` always runs everything): `performance`,
    /// `troubleshooting`, `auth`, `resilience`, `modernization`.
    fn profiles(&self) -> &'static [&'static str];
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>);
}
