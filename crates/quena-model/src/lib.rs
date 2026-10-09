//! Quena domain model.
//!
//! The model is transport-independent: the proxy, importers (SAZ/HAR) and the
//! composer all produce the same [`SessionDetail`] records. Bodies are never
//! part of the model itself – only references ([`BodyRef`]) are.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod correlation;
pub mod wslog;
mod headers;
pub use headers::{Headers, latin1_to_string, string_to_latin1};

/// Sequential session number, shown as `#` in the session list.
pub type SessionId = u64;

/// Microseconds since the Unix epoch.
pub type Micros = i64;

pub fn now_us() -> Micros {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or_default()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum SessionKind {
    #[default]
    Http,
    /// CONNECT tunnel (decrypted or not).
    Tunnel,
    /// HTTP upgrade to WebSocket; frames flow through the tunnel.
    WebSocket,
    /// Created locally (Composer, AutoResponder without upstream, import placeholder).
    Synthetic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum SessionState {
    #[default]
    RequestHeaders,
    SendingRequest,
    BreakpointRequest,
    AwaitingResponse,
    ReceivingResponse,
    BreakpointResponse,
    Done,
    Aborted,
}

impl SessionState {
    pub fn is_final(self) -> bool {
        matches!(self, SessionState::Done | SessionState::Aborted)
    }
    pub fn is_breakpoint(self) -> bool {
        matches!(self, SessionState::BreakpointRequest | SessionState::BreakpointResponse)
    }
}

/// Session flags (bit set).
pub mod flags {
    pub const REPLAYED: u32 = 1 << 0;
    pub const AUTO_RESPONDED: u32 = 1 << 1;
    pub const BREAKPOINTED: u32 = 1 << 2;
    pub const TAMPERED: u32 = 1 << 3;
    pub const REQUEST_TRUNCATED: u32 = 1 << 4;
    pub const RESPONSE_TRUNCATED: u32 = 1 << 5;
    pub const DECRYPTED: u32 = 1 << 6;
    pub const REMOTE_CLIENT: u32 = 1 << 7;
    pub const IMPORTED: u32 = 1 << 8;
    pub const STREAMED: u32 = 1 << 9;
    pub const CLIENT_ABORTED: u32 = 1 << 10;
    pub const SERVER_ABORTED: u32 = 1 << 11;
    pub const COMPOSED: u32 = 1 << 12;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MarkColor {
    Red,
    Blue,
    Gold,
    Green,
    Orange,
    Purple,
}

impl MarkColor {
    pub const ALL: [MarkColor; 6] = [
        MarkColor::Red,
        MarkColor::Blue,
        MarkColor::Gold,
        MarkColor::Green,
        MarkColor::Orange,
        MarkColor::Purple,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            MarkColor::Red => "red",
            MarkColor::Blue => "blue",
            MarkColor::Gold => "gold",
            MarkColor::Green => "green",
            MarkColor::Orange => "orange",
            MarkColor::Purple => "purple",
        }
    }
    pub fn parse(s: &str) -> Option<MarkColor> {
        MarkColor::ALL.into_iter().find(|c| c.as_str().eq_ignore_ascii_case(s))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum HttpVersion {
    #[serde(rename = "HTTP/0.9")]
    Http09,
    #[serde(rename = "HTTP/1.0")]
    Http10,
    #[default]
    #[serde(rename = "HTTP/1.1")]
    Http11,
    #[serde(rename = "HTTP/2")]
    Http2,
    #[serde(rename = "HTTP/3")]
    Http3,
}

impl HttpVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            HttpVersion::Http09 => "HTTP/0.9",
            HttpVersion::Http10 => "HTTP/1.0",
            HttpVersion::Http11 => "HTTP/1.1",
            HttpVersion::Http2 => "HTTP/2",
            HttpVersion::Http3 => "HTTP/3",
        }
    }
    pub fn parse(s: &str) -> Option<HttpVersion> {
        Some(match s.trim().to_ascii_uppercase().as_str() {
            "HTTP/0.9" => HttpVersion::Http09,
            "HTTP/1.0" => HttpVersion::Http10,
            "HTTP/1.1" => HttpVersion::Http11,
            "HTTP/2" | "HTTP/2.0" => HttpVersion::Http2,
            "HTTP/3" | "HTTP/3.0" => HttpVersion::Http3,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RequestHead {
    pub method: String,
    /// Absolute URL (`https://host/path?q`), or `host:port` for CONNECT.
    pub url: String,
    pub version: HttpVersion,
    pub headers: Headers,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResponseHead {
    pub status: u16,
    pub reason: String,
    pub version: HttpVersion,
    pub headers: Headers,
}

/// Reference to a stored body. Raw bytes are the source of truth; decoded
/// variants are derived caches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", tag = "t")]
pub enum BodyRef {
    #[default]
    Empty,
    Inline {
        id: u64,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        /// Bytes that passed the wire (may exceed stored bytes when truncated).
        wire_len: u64,
        truncated: bool,
    },
    Blob {
        id: u64,
        len: u64,
        wire_len: u64,
        truncated: bool,
        complete: bool,
    },
}

impl BodyRef {
    pub fn stored_len(&self) -> u64 {
        match self {
            BodyRef::Empty => 0,
            BodyRef::Inline { data, .. } => data.len() as u64,
            BodyRef::Blob { len, .. } => *len,
        }
    }
    pub fn wire_len(&self) -> u64 {
        match self {
            BodyRef::Empty => 0,
            BodyRef::Inline { wire_len, .. } | BodyRef::Blob { wire_len, .. } => *wire_len,
        }
    }
}

/// Timestamps of a session (Fiddler "SessionTimers"). All optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Timers {
    pub client_connected: Option<Micros>,
    pub client_begin_request: Option<Micros>,
    pub got_request_headers: Option<Micros>,
    pub client_done_request: Option<Micros>,
    pub server_connect_start: Option<Micros>,
    pub server_connected: Option<Micros>,
    pub server_begin_request: Option<Micros>,
    pub server_done_request: Option<Micros>,
    pub server_got_first_byte: Option<Micros>,
    pub got_response_headers: Option<Micros>,
    pub server_done_response: Option<Micros>,
    pub client_begin_response: Option<Micros>,
    pub client_done_response: Option<Micros>,
    pub dns_ms: Option<u32>,
    pub tcp_connect_ms: Option<u32>,
    pub tls_handshake_ms: Option<u32>,
    pub gateway_ms: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsInfo {
    pub version: String,
    pub cipher: String,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    /// Upstream certificate chain (PEM), leaf first.
    pub server_chain_pem: Vec<String>,
    /// The server certificate's end of validity (Unix seconds), subject and issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// The server certificate expired or expires soon ([`CERT_FLAG`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionInfo {
    pub client_addr: Option<String>,
    pub server_addr: Option<String>,
    pub client_conn_id: Option<u64>,
    pub server_conn_reused: bool,
    pub client_tls: Option<TlsInfo>,
    pub server_tls: Option<TlsInfo>,
    /// Upstream gateway (proxy chaining), if any.
    pub gateway: Option<String>,
    /// HTTP/2 stream id on the client connection.
    pub stream_id: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
}

impl ProcessInfo {
    pub fn display(&self) -> String {
        if self.pid == 0 {
            self.name.clone()
        } else {
            format!("{}:{}", self.name, self.pid)
        }
    }
}

/// Row shown in the session list. Kept small; the index holds one per session.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummary {
    pub id: SessionId,
    pub kind: SessionKind,
    pub state: SessionState,
    pub flags: u32,
    pub color: Option<MarkColor>,
    pub method: String,
    /// `HTTP`, `HTTPS`, `HTTP/2`… as shown in the Protocol column.
    pub protocol: String,
    pub host: String,
    /// Path + query (or `host:port` for tunnels).
    pub url: String,
    pub status: u16,
    pub request_body_len: u64,
    pub response_body_len: u64,
    pub content_type: String,
    pub caching: String,
    pub process: String,
    pub comment: String,
    pub custom: String,
    pub started_at: Micros,
    /// Total duration in milliseconds, once known.
    pub duration_ms: Option<u32>,
    pub client_ip: String,
    /// The client connection the request came on (keep-alive, HTTP/2); 0: unknown.
    #[serde(default)]
    pub conn: u64,
    /// Trace or correlation id the client sent ([`correlation::trace_id`]).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub trace: String,
    /// Session cookie as name and hash ([`correlation::session_key`]).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session: String,
    /// Listener the request came through: a reverse proxy entry, `SOCKS5` or `transparent`
    /// (empty: the proxy port, or Quena's own request).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub via: String,
    /// End of validity of the server's certificate (Unix seconds), for HTTPS sessions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_expires: Option<i64>,
    /// LLM API call: `provider/model` (empty: not one).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub llm: String,
    /// Its tokens (input + output) and estimated cost in millionths of a dollar.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm_cost_micros: Option<u64>,
    /// TLS version towards the server (else towards the client), e.g. `TLSv1.3`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tls: String,
    /// The server's IP address.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub remote_ip: String,
    /// HTTP version of the request (`HTTP/1.1`, `HTTP/2` …).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub http_version: String,
    /// Values of the header columns ([`set_header_columns`]), in their order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub header_values: Vec<String>,
}

/// A request or response header shown as a list column.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeaderColumn {
    pub response: bool,
    pub name: String,
}

/// At most this many header columns.
pub const MAX_HEADER_COLUMNS: usize = 3;

static HEADER_COLUMNS: std::sync::RwLock<Vec<HeaderColumn>> = std::sync::RwLock::new(Vec::new());

/// The headers shown as list columns (filled in by [`SessionDetail::refresh_summary`]).
pub fn set_header_columns(mut cols: Vec<HeaderColumn>) {
    cols.retain(|c| !c.name.trim().is_empty());
    cols.truncate(MAX_HEADER_COLUMNS);
    if let Ok(mut g) = HEADER_COLUMNS.write() {
        *g = cols;
    }
}

pub fn header_columns() -> Vec<HeaderColumn> {
    HEADER_COLUMNS.read().map(|g| g.clone()).unwrap_or_default()
}

impl SessionSummary {
    pub fn has_flag(&self, f: u32) -> bool {
        self.flags & f != 0
    }
    pub fn full_url(&self) -> String {
        match self.kind {
            SessionKind::Tunnel => self.url.clone(),
            _ => {
                let scheme = if self.protocol.starts_with("HTTPS") || self.protocol == "HTTP/2" {
                    "https"
                } else {
                    "http"
                };
                format!("{scheme}://{}{}", self.host, self.url)
            }
        }
    }
}

/// Everything known about a session except body bytes.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionDetail {
    pub summary: SessionSummary,
    pub request: RequestHead,
    pub response: Option<ResponseHead>,
    pub request_body: BodyRef,
    pub response_body: BodyRef,
    pub timers: Timers,
    pub connection: ConnectionInfo,
    pub process: Option<ProcessInfo>,
    /// Human readable error (connect failure, TLS error, abort reason…).
    pub error: Option<String>,
    /// Free-form flags (Fiddler "SessionFlags"), preserved on SAZ import/export.
    pub extra_flags: Vec<(String, String)>,
}

/// Session flag naming the listener a request came through besides the proxy port: a reverse
/// proxy entry, `SOCKS5` or `transparent`.
pub const VIA_FLAG: &str = "x-quena-via";

/// Session flag: the server's certificate expired or expires soon (the text says when).
pub const CERT_FLAG: &str = "x-quena-cert";

impl SessionDetail {
    /// The listener the request came through (reverse proxy entry, SOCKS5, transparent), if any.
    pub fn via(&self) -> String {
        self.extra_flags.iter().find(|(k, _)| k == VIA_FLAG).map(|(_, v)| v.clone()).unwrap_or_default()
    }

    /// Recompute the list row fields that are derived from heads.
    pub fn refresh_summary(&mut self) {
        let s = &mut self.summary;
        s.method = self.request.method.clone();
        let (host, path) = split_url(&self.request.url, &self.request.method);
        if s.kind != SessionKind::Tunnel {
            s.host = host;
            s.url = path;
        } else {
            // The list shows the tunnel's target as host; the path column marks it as a tunnel.
            s.host = self.request.url.clone();
            s.url = String::new();
        }
        s.protocol = protocol_label(&self.request.url, self.request.version, s.kind);
        s.conn = self.connection.client_conn_id.unwrap_or(0);
        s.trace = correlation::trace_id(&self.request.headers);
        s.session = correlation::session_key(&self.request.headers);
        s.via = self.extra_flags.iter().find(|(k, _)| k == VIA_FLAG).map(|(_, v)| v.clone()).unwrap_or_default();
        s.cert_expires = self.connection.server_tls.as_ref().and_then(|t| t.not_after);
        let flag = |k: &str| self.extra_flags.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        s.llm = flag("x-quena-llm").unwrap_or_default().to_string();
        s.llm_tokens = flag("x-quena-llm-tokens").and_then(|v| v.parse().ok());
        s.llm_cost_micros = flag("x-quena-llm-cost").and_then(|v| v.parse::<f64>().ok()).map(|c| (c * 1_000_000.0).round() as u64);
        s.request_body_len = self.request_body.wire_len();
        if let Some(resp) = &self.response {
            s.status = resp.status;
            s.content_type = resp
                .headers
                .get("content-type")
                .map(|v| v.split(';').next().unwrap_or("").trim().to_string())
                .unwrap_or_default();
            s.caching = caching_summary(&resp.headers);
            s.response_body_len = self.response_body.wire_len();
        }
        if let Some(p) = &self.process {
            s.process = p.display();
        }
        if let (Some(start), Some(end)) = (
            self.timers.client_begin_request.or(self.timers.client_connected),
            self.timers.client_done_response.or(self.timers.server_done_response),
        ) {
            s.duration_ms = Some(((end - start).max(0) / 1000) as u32);
        }
        s.tls = self.connection.server_tls.as_ref().or(self.connection.client_tls.as_ref()).map(|t| t.version.clone()).unwrap_or_default();
        s.remote_ip = self.connection.server_addr.as_deref().map(ip_of).unwrap_or_default();
        s.http_version = if s.kind == SessionKind::Tunnel { String::new() } else { self.request.version.as_str().to_string() };
        let cols = header_columns();
        s.header_values = if cols.is_empty() {
            Vec::new()
        } else {
            cols.iter()
                .map(|c| {
                    let h = if c.response { self.response.as_ref().map(|r| &r.headers) } else { Some(&self.request.headers) };
                    h.map(|h| h.0.iter().filter(|(n, _)| n.eq_ignore_ascii_case(c.name.trim())).map(|(_, v)| v.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default()
                })
                .collect()
        };
    }
}

/// The IP address of `host:port`, `[v6]:port` or a bare address.
fn ip_of(addr: &str) -> String {
    if let Ok(a) = addr.parse::<std::net::SocketAddr>() {
        return a.ip().to_canonical().to_string();
    }
    addr.trim_start_matches('[').split(']').next().unwrap_or(addr).rsplit_once(':').filter(|(h, _)| !h.contains(':')).map(|(h, _)| h).unwrap_or(addr).to_string()
}

fn protocol_label(url: &str, version: HttpVersion, kind: SessionKind) -> String {
    if kind == SessionKind::Tunnel {
        return "HTTP".into();
    }
    let https = url.starts_with("https://") || url.starts_with("wss://");
    match version {
        HttpVersion::Http2 => "HTTP/2".into(),
        HttpVersion::Http3 => "HTTP/3".into(),
        _ if https => "HTTPS".into(),
        _ => "HTTP".into(),
    }
}

/// Split an absolute URL into (`host[:port]`, `path?query`).
pub fn split_url(url: &str, method: &str) -> (String, String) {
    if method.eq_ignore_ascii_case("CONNECT") {
        return (url.to_string(), url.to_string());
    }
    let rest = match url.find("://") {
        Some(i) => &url[i + 3..],
        None => return (String::new(), url.to_string()),
    };
    match rest.find(['/', '?']) {
        Some(i) => {
            let path = &rest[i..];
            let path = if path.starts_with('?') { format!("/{path}") } else { path.to_string() };
            (rest[..i].to_string(), path)
        }
        None => (rest.to_string(), "/".to_string()),
    }
}

fn caching_summary(h: &Headers) -> String {
    let mut parts = Vec::new();
    if let Some(v) = h.get("cache-control") {
        parts.push(v.to_string());
    }
    if let Some(v) = h.get("expires") {
        parts.push(format!("Expires: {v}"));
    }
    parts.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split() {
        assert_eq!(
            split_url("https://a.b:8443/x/y?z=1", "GET"),
            ("a.b:8443".into(), "/x/y?z=1".into())
        );
        assert_eq!(split_url("http://a.b", "GET"), ("a.b".into(), "/".into()));
        assert_eq!(split_url("http://a.b?x", "GET"), ("a.b".into(), "/?x".into()));
        assert_eq!(split_url("a.b:443", "CONNECT"), ("a.b:443".into(), "a.b:443".into()));
    }

    #[test]
    fn summary_refresh() {
        let mut d = SessionDetail::default();
        d.request = RequestHead {
            method: "GET".into(),
            url: "https://example.com/index.html".into(),
            version: HttpVersion::Http11,
            headers: Headers::default(),
        };
        let mut h = Headers::default();
        h.push("Content-Type", "text/html; charset=utf-8");
        d.response = Some(ResponseHead { status: 200, reason: "OK".into(), version: HttpVersion::Http11, headers: h });
        d.refresh_summary();
        assert_eq!(d.summary.host, "example.com");
        assert_eq!(d.summary.protocol, "HTTPS");
        assert_eq!(d.summary.content_type, "text/html");
        assert_eq!(d.summary.status, 200);
    }
}
