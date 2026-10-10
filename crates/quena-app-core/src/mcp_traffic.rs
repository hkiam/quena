//! Traffic of MCP servers (Model Context Protocol), the tools AI agents call: JSON-RPC over
//! HTTP (Streamable HTTP: POST with JSON or a stream of server-sent events; the older SSE
//! transport: a GET stream and POSTs to `/messages`), and stdio servers recorded by
//! `quena mcp-tap`. Each exchange is taken apart: the method, the tool called with its
//! arguments and result, the tools a server offers with what their definitions cost in tokens,
//! the server's name and protocol version.

use crate::AppCore;
use quena_model::{SessionDetail, SessionId};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;

/// Flags of a recognised exchange (kept in archives).
pub const MCP_FLAG: &str = "x-quena-mcp";
pub const MCP_SERVER_FLAG: &str = "x-quena-mcp-server";

/// Bytes of a body read.
const MAX_BODY: usize = 16 << 20;
/// Longest text kept per part.
const MAX_TEXT: usize = 100_000;

/// Methods of the protocol (a JSON-RPC call with another method is no MCP).
const METHODS: &[&str] = &[
    "initialize",
    "ping",
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/templates/list",
    "resources/read",
    "resources/subscribe",
    "resources/unsubscribe",
    "prompts/list",
    "prompts/get",
    "completion/complete",
    "logging/setLevel",
    "sampling/createMessage",
    "elicitation/create",
    "roots/list",
];

fn is_mcp_method(m: &str) -> bool {
    METHODS.contains(&m) || m.starts_with("notifications/")
}

/// What the heads of a session say about MCP.
#[derive(Debug, Clone, Copy, Default)]
pub struct Hint {
    /// `Mcp-Session-Id` or `MCP-Protocol-Version` in the request or the response.
    pub mcp_header: bool,
    /// The request accepts JSON and an event stream, as MCP clients must.
    pub accepts_both: bool,
}

impl Hint {
    pub fn of(d: &SessionDetail) -> Hint {
        let mcp = |h: &quena_model::Headers| h.get("mcp-session-id").is_some() || h.get("mcp-protocol-version").is_some();
        let accept = d.request.headers.get("accept").unwrap_or("").to_ascii_lowercase();
        Hint { mcp_header: mcp(&d.request.headers) || d.response.as_ref().is_some_and(|r| mcp(&r.headers)), accepts_both: accept.contains("application/json") && accept.contains("text/event-stream") }
    }
}

/// Whether a session may be an MCP exchange, by what is cheap to see: MCP headers, the Accept
/// header MCP clients send, a path or host MCP servers use. Calls to LLM APIs are none.
pub fn candidate(method: &str, url: &str, hint: Hint) -> bool {
    if url.starts_with("stdio://") {
        return true;
    }
    // A call to an LLM API is never MCP, whatever headers it carries.
    if crate::llm::api_of(method, url).is_some() {
        return false;
    }
    if hint.mcp_header {
        return true;
    }
    let (post, get) = (method.eq_ignore_ascii_case("POST"), method.eq_ignore_ascii_case("GET"));
    if !(post || get) {
        return false;
    }
    if post && hint.accepts_both {
        return true;
    }
    let Ok(u) = url.parse::<http::Uri>() else { return false };
    let path = u.path().trim_end_matches('/').to_ascii_lowercase();
    u.host().is_some_and(|h| h.to_ascii_lowercase().starts_with("mcp.")) || path.ends_with("/mcp") || path.contains("/mcp/") || path.ends_with("/sse") || path.ends_with("/messages") || path.ends_with("/message")
}

/// The query parameter the older SSE transport names its session with.
fn session_param(url: &str) -> Option<String> {
    let q = url.split_once('?')?.1;
    q.split('&').find_map(|kv| kv.split_once('=').filter(|(k, _)| k.eq_ignore_ascii_case("sessionid") || k.eq_ignore_ascii_case("session_id")).map(|(_, v)| v.to_string()))
}

/// The older transport's stream announces where to post: an `event: endpoint` line.
fn announces_endpoint(resp_headers: Option<&quena_model::Headers>, text: &str) -> bool {
    resp_headers.and_then(|h| h.get("content-type")).is_some_and(|c| c.to_ascii_lowercase().contains("text/event-stream")) && text.lines().any(|l| matches!(l.trim_end_matches('\r'), "event: endpoint" | "event:endpoint"))
}

/// One JSON-RPC message.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RpcMessage {
    /// `request`, `notification`, `result`, `error`.
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Params, result or error, as indented JSON.
    pub body: String,
}

/// A tool a server offers.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpTool {
    pub name: String,
    pub description: String,
    /// Bytes and estimated tokens of its definition: what it adds to every LLM request that
    /// offers it.
    pub size: usize,
    pub tokens: u64,
}

/// Content of a tool's result.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Content {
    /// `text`, `image`, `audio`, `resource`, `resource_link`, `structured`, `other`.
    pub kind: String,
    pub text: String,
}

/// A tool call with its result.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ToolCall {
    pub name: String,
    pub arguments: String,
    pub content: Vec<Content>,
    pub is_error: bool,
    /// Estimated tokens of the result: what it adds to the agent's next LLM request.
    pub tokens: u64,
}

/// An MCP exchange taken apart.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpExchange {
    /// `http`, `sse` (the older transport), `stdio`.
    pub transport: &'static str,
    /// What it is: `tools/call get_issue`, `tools/list`, `initialize`, …
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// The server's name and version (from `initialize`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<(String, String)>,
    /// What the client sent and what the server answered (also over the stream).
    pub sent: Vec<RpcMessage>,
    pub received: Vec<RpcMessage>,
    /// `tools/list`: the tools offered.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<McpTool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call: Option<ToolCall>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn cut(s: String) -> String {
    if s.len() <= MAX_TEXT {
        return s;
    }
    let mut end = MAX_TEXT;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{} … ({} characters)", &s[..end], s.chars().count())
}

fn pretty(v: &Value) -> String {
    cut(serde_json::to_string_pretty(v).unwrap_or_default())
}

fn id_of(v: &Value) -> Option<String> {
    match v.get("id")? {
        Value::String(s) => Some(s.clone()),
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

/// The JSON-RPC messages of a body: one object, a batch, or server-sent events.
fn messages(text: &str) -> Vec<Value> {
    let t = text.trim_start();
    let one = |v: Value| match v {
        Value::Array(a) => a,
        v @ Value::Object(_) => vec![v],
        _ => vec![],
    };
    if t.starts_with('{') || t.starts_with('[') {
        return serde_json::from_str::<Value>(t).map(one).unwrap_or_default();
    }
    // Server-sent events (and stdio's JSON lines).
    let mut out = Vec::new();
    let mut data: Vec<&str> = Vec::new();
    for line in text.lines().chain(std::iter::once("")) {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            if !data.is_empty() {
                if let Ok(v) = serde_json::from_str::<Value>(&data.join("\n")) {
                    out.extend(one(v));
                }
                data.clear();
            }
        } else if let Some(d) = line.strip_prefix("data:") {
            data.push(d.strip_prefix(' ').unwrap_or(d));
        } else if line.starts_with('{') {
            if let Ok(v) = serde_json::from_str::<Value>(line) {
                out.extend(one(v));
            }
        }
    }
    out
}

fn rpc(v: &Value) -> Option<RpcMessage> {
    if v.get("jsonrpc").and_then(|x| x.as_str()) != Some("2.0") {
        return None;
    }
    let method = v.get("method").and_then(|m| m.as_str()).map(str::to_string);
    let id = id_of(v);
    Some(if let Some(m) = method {
        RpcMessage { kind: if id.is_some() { "request" } else { "notification" }, id, body: v.get("params").map(pretty).unwrap_or_default(), method: Some(m) }
    } else if let Some(e) = v.get("error") {
        RpcMessage { kind: "error", id, method: None, body: pretty(e) }
    } else {
        RpcMessage { kind: "result", id, method: None, body: v.get("result").map(pretty).unwrap_or_default() }
    })
}

fn content_of(c: &Value) -> Content {
    let kind = c.get("type").and_then(|t| t.as_str()).unwrap_or("other").to_string();
    let text = match kind.as_str() {
        "text" => c.get("text").and_then(|t| t.as_str()).unwrap_or("").to_string(),
        "image" | "audio" => format!("[{kind} {}]", c.get("mimeType").and_then(|m| m.as_str()).unwrap_or("")),
        "resource" => c.get("resource").map(|r| r.get("text").and_then(|t| t.as_str()).map(str::to_string).unwrap_or_else(|| pretty(r))).unwrap_or_default(),
        "resource_link" => c.get("uri").and_then(|u| u.as_str()).unwrap_or("").to_string(),
        _ => pretty(c),
    };
    Content { kind, text: cut(text) }
}

/// An exchange from its request and response bodies (`None`: no MCP).
pub fn decode(url: &str, req_headers: &quena_model::Headers, request: &[u8], resp_headers: Option<&quena_model::Headers>, response: &[u8]) -> Option<McpExchange> {
    let req_text = String::from_utf8_lossy(request);
    let resp_text = String::from_utf8_lossy(response);
    let sent_v = messages(&req_text);
    let recv_v = messages(&resp_text);
    let sent: Vec<RpcMessage> = sent_v.iter().filter_map(rpc).collect();
    let received: Vec<RpcMessage> = recv_v.iter().filter_map(rpc).collect();
    let header = |h: Option<&quena_model::Headers>, n: &str| h.and_then(|h| h.get(n)).map(str::trim).filter(|v| !v.is_empty()).map(str::to_string);
    let query_session = session_param(url);
    let session = header(Some(req_headers), "mcp-session-id").or_else(|| header(resp_headers, "mcp-session-id")).or_else(|| query_session.clone());
    let protocol_header = header(Some(req_headers), "mcp-protocol-version");
    let mcp_method = sent.iter().chain(&received).filter_map(|m| m.method.as_deref()).any(is_mcp_method);
    let endpoint = announces_endpoint(resp_headers, &resp_text);
    if !(mcp_method || endpoint || ((session.is_some() || protocol_header.is_some()) && (!sent.is_empty() || !received.is_empty()))) {
        return None;
    }
    let transport = if url.starts_with("stdio://") {
        "stdio"
    } else if endpoint || query_session.is_some() {
        "sse"
    } else {
        "http"
    };
    let requests: Vec<String> = sent.iter().filter_map(|m| m.method.clone()).collect();
    let req0 = sent_v.iter().find(|v| v.get("method").is_some());
    let result_of = |id: &Option<String>| recv_v.iter().find(|v| id.is_some() && id_of(v) == *id && v.get("method").is_none());
    let mut ex = McpExchange {
        transport,
        // A stream the server opened (no request of the client) is a stream, whatever it sends.
        label: requests.first().cloned().unwrap_or_else(|| if sent.is_empty() && !received.is_empty() || endpoint { "stream".into() } else { "response".into() }),
        session,
        protocol: protocol_header,
        server: None,
        sent,
        received,
        tools: vec![],
        call: None,
        error: None,
    };
    if let Some(r) = req0 {
        let params = r.get("params").unwrap_or(&Value::Null);
        let res = result_of(&id_of(r));
        if let Some(e) = res.and_then(|v| v.get("error")) {
            ex.error = Some(e.get("message").and_then(|m| m.as_str()).map(str::to_string).unwrap_or_else(|| e.to_string()));
        }
        let result = res.and_then(|v| v.get("result"));
        match ex.label.as_str() {
            "initialize" => {
                ex.protocol = ex.protocol.take().or_else(|| result.and_then(|r| r.get("protocolVersion")).or_else(|| params.get("protocolVersion")).and_then(|p| p.as_str()).map(str::to_string));
                if let Some(si) = result.and_then(|r| r.get("serverInfo")) {
                    let s = |k: &str| si.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
                    ex.server = Some((s("name"), s("version")));
                }
            }
            "tools/list" => {
                for t in result.and_then(|r| r.get("tools")).and_then(|t| t.as_array()).into_iter().flatten() {
                    let text = t.to_string();
                    ex.tools.push(McpTool {
                        name: t.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string(),
                        description: t.get("description").and_then(|n| n.as_str()).unwrap_or("").to_string(),
                        size: text.len(),
                        tokens: crate::agent::estimate_tokens(&text).max(1),
                    });
                }
            }
            "tools/call" => {
                let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                ex.label = format!("tools/call {name}");
                let content: Vec<Content> = result.and_then(|r| r.get("content")).and_then(|c| c.as_array()).into_iter().flatten().map(content_of).chain(result.and_then(|r| r.get("structuredContent")).map(|s| Content { kind: "structured".into(), text: pretty(s) })).collect();
                let tokens = result.map(|r| crate::agent::estimate_tokens(&r.to_string())).unwrap_or(0);
                ex.call = Some(ToolCall { name, arguments: params.get("arguments").map(pretty).unwrap_or_default(), content, is_error: result.and_then(|r| r.get("isError")).and_then(|e| e.as_bool()).unwrap_or(false) || ex.error.is_some(), tokens });
            }
            "resources/read" | "resources/subscribe" => {
                if let Some(u) = params.get("uri").and_then(|u| u.as_str()) {
                    ex.label = format!("{} {u}", ex.label);
                }
            }
            "prompts/get" => {
                if let Some(n) = params.get("name").and_then(|u| u.as_str()) {
                    ex.label = format!("prompts/get {n}");
                }
            }
            _ => {}
        }
    }
    // A batch (protocol 2025-03-26): the first request and how many more.
    if requests.len() > 1 {
        ex.label = format!("{} +{}", ex.label, requests.len() - 1);
    }
    Some(ex)
}

/// The flags of an exchange.
pub fn flags_of(ex: &McpExchange, server: &str) -> Vec<(String, String)> {
    let mut f = vec![(MCP_FLAG.to_string(), ex.label.clone())];
    if !server.is_empty() {
        f.push((MCP_SERVER_FLAG.to_string(), server.to_string()));
    }
    f
}

/// Names of MCP servers (from their `initialize`) by server and session, and by server for
/// those without sessions, for the exchanges after it.
#[derive(Default)]
pub struct McpNames {
    by_session: HashMap<(String, String), String>,
    by_server: HashMap<String, String>,
    /// The older transport's stream found for a host and session (capture numbering, session).
    streams: HashMap<(String, String), (u64, SessionId)>,
    /// Exchanges marked so far (for [`AppCore::agent_stamp`]).
    pub(crate) marks: u64,
}

/// Where an exchange goes: the URL's authority, or the stdio name.
fn authority(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("stdio://") {
        return rest.split('/').next().unwrap_or(rest).to_string();
    }
    url.parse::<http::Uri>().ok().and_then(|u| u.authority().map(|a| a.to_string())).unwrap_or_default()
}

impl AppCore {
    /// Session `id` as an MCP exchange (`None`: it is not one). A request over the older SSE
    /// transport gets its result from the stream it was answered on.
    pub fn mcp_exchange(&self, id: SessionId) -> Option<McpExchange> {
        let cap = self.capture();
        let (d, req, resp) = cap.bodies_stored(id)?;
        let mut ex = Self::mcp_from(&d, &req, &resp)?;
        self.answer_from_stream(&d, &req, &mut ex);
        Some(ex)
    }

    fn mcp_from(d: &SessionDetail, req: &quena_body::Body, resp: &quena_body::Body) -> Option<McpExchange> {
        let request = quena_body::text::decoded_prefix(req, &crate::dto::spec_of(&d.request.headers), MAX_BODY);
        let response = d.response.as_ref().map(|r| quena_body::text::decoded_prefix(resp, &crate::dto::spec_of(&r.headers), MAX_BODY)).unwrap_or_default();
        // Not JSON-RPC at all: no need to parse.
        let has = |b: &[u8]| b[..b.len().min(4096)].windows(7).any(|w| w == b"jsonrpc") || b.windows(14).take(4096).any(|w| w == b"event: endpoint");
        if !has(&request) && !has(&response) && !d.request.url.starts_with("stdio://") {
            return None;
        }
        decode(&d.request.url, &d.request.headers, &request, d.response.as_ref().map(|r| &r.headers), &response)
    }

    /// The older SSE transport answers a POST with 202 and sends the result on the GET stream
    /// that announced the endpoint: find it there (also while the stream is still open).
    fn answer_from_stream(&self, d: &SessionDetail, req: &quena_body::Body, ex: &mut McpExchange) {
        let Some(sid) = session_param(&d.request.url) else { return };
        if !ex.received.is_empty() || !ex.sent.iter().any(|m| m.kind == "request") {
            return;
        }
        let cap = self.capture();
        let host = authority(&d.request.url);
        let started = d.summary.started_at;
        let numbering = cap.numbering();
        let known = self.mcp_names.lock().streams.get(&(host.clone(), sid.clone())).filter(|(n, _)| *n == numbering).map(|(_, id)| *id);
        let mut streams: Vec<(i64, SessionId)> = Vec::new();
        match known {
            Some(id) => streams.push((0, id)),
            None => cap.index.for_each(|s| {
                if s.method.eq_ignore_ascii_case("GET") && s.started_at <= started && s.content_type.to_ascii_lowercase().contains("event-stream") && authority(&s.full_url()) == host {
                    streams.push((s.started_at, s.id));
                }
            }),
        }
        streams.sort_by(|a, b| b.0.cmp(&a.0));
        for (_, sid_stream) in streams.into_iter().take(20) {
            let Some((sd, _, sresp)) = cap.bodies_stored(sid_stream) else { continue };
            let text = sd.response.as_ref().map(|r| quena_body::text::decoded_prefix(&sresp, &crate::dto::spec_of(&r.headers), MAX_BODY)).unwrap_or_default();
            let text = String::from_utf8_lossy(&text);
            if !text.contains(&sid) {
                continue;
            }
            {
                let mut g = self.mcp_names.lock();
                if g.streams.len() > 10_000 {
                    g.streams.clear();
                }
                g.streams.insert((host.clone(), sid.clone()), (numbering, sid_stream));
            }
            let ids: Vec<Option<String>> = ex.sent.iter().filter(|m| m.kind == "request").map(|m| m.id.clone()).collect();
            let answers: Vec<Value> = messages(&text).into_iter().filter(|v| v.get("method").is_none() && ids.contains(&id_of(v))).collect();
            if answers.is_empty() {
                continue;
            }
            let request = quena_body::text::decoded_prefix(req, &crate::dto::spec_of(&d.request.headers), MAX_BODY);
            let joined = Value::Array(answers).to_string();
            if let Some(mut full) = decode(&d.request.url, &d.request.headers, &request, d.response.as_ref().map(|r| &r.headers), joined.as_bytes()) {
                full.transport = "sse";
                *ex = full;
            }
            return;
        }
    }

    /// The server an exchange goes to: its name from `initialize` (remembered by session), else
    /// the host (or the stdio name).
    pub(crate) fn mcp_server(&self, d: &SessionDetail, ex: &McpExchange) -> String {
        let host = authority(&d.request.url);
        let mut g = self.mcp_names.lock();
        if g.by_session.len() > 10_000 {
            g.by_session.clear();
        }
        if let Some((name, _)) = ex.server.as_ref().filter(|(n, _)| !n.is_empty()) {
            match &ex.session {
                Some(s) => g.by_session.insert((host.clone(), s.clone()), name.clone()),
                // A server without sessions: by where it is.
                None => g.by_server.insert(host.clone(), name.clone()),
            };
            return name.clone();
        }
        if let Some(n) = ex.session.as_ref().and_then(|s| g.by_session.get(&(host.clone(), s.clone()))) {
            return n.clone();
        }
        g.by_server.get(&host).cloned().unwrap_or(host)
    }

    /// Mark a finished session that may be an MCP exchange, later on a worker thread (a full
    /// queue drops it: marks are a help, not a record).
    pub(crate) fn mcp_mark_later(self: &std::sync::Arc<Self>, id: SessionId) {
        type Job = (std::sync::Weak<AppCore>, u64, SessionId);
        static QUEUE: std::sync::OnceLock<Option<std::sync::mpsc::SyncSender<Job>>> = std::sync::OnceLock::new();
        let queue = QUEUE.get_or_init(|| {
            let (tx, rx) = std::sync::mpsc::sync_channel::<Job>(1024);
            let worker = std::thread::Builder::new().name("quena-mcp-mark".into()).spawn(move || {
                for (core, numbering, id) in rx {
                    if let Some(core) = core.upgrade() {
                        core.mcp_mark(numbering, id);
                    }
                }
            });
            worker.ok().map(|_| tx)
        });
        if let Some(q) = queue {
            let _ = q.try_send((std::sync::Arc::downgrade(self), self.capture().numbering(), id));
        }
    }

    /// Mark session `id` (of numbering `numbering`) if it is an MCP exchange.
    pub fn mcp_mark(&self, numbering: u64, id: SessionId) {
        let cap = self.capture();
        if cap.numbering() != numbering {
            return;
        }
        let Some((d, req, resp)) = cap.bodies_stored(id) else { return };
        let Some(mut ex) = Self::mcp_from(&d, &req, &resp) else { return };
        self.answer_from_stream(&d, &req, &mut ex);
        let server = self.mcp_server(&d, &ex);
        let mut flags = flags_of(&ex, &server);
        if let Some(a) = d.request.headers.get("user-agent").and_then(crate::agent::agent_label) {
            flags.push((crate::agent::AGENT_FLAG.into(), a));
        }
        let set = |det: &mut SessionDetail| {
            det.extra_flags.retain(|(k, _)| !k.starts_with(MCP_FLAG) && k != crate::agent::AGENT_FLAG);
            det.extra_flags.extend(flags.iter().cloned());
        };
        if let Some(live) = cap.live(id) {
            live.update(set);
        } else {
            cap.update_detail(id, set);
        }
        self.mcp_names.lock().marks += 1;
    }

    /// Changes whenever LLM calls or MCP exchanges were added or marked: the Agents panel
    /// and the trails ask again only then (other traffic leaves it alone).
    pub fn agent_stamp(&self) -> u64 {
        let digests = self.llm_digests.lock().generation();
        digests.wrapping_mul(1_000_003).wrapping_add(self.mcp_names.lock().marks).wrapping_add(self.capture().numbering().wrapping_mul(7))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quena_model::Headers;

    fn h(pairs: &[(&str, &str)]) -> Headers {
        let mut h = Headers::default();
        for (k, v) in pairs {
            h.push(*k, *v);
        }
        h
    }

    #[test]
    fn streamable_http_exchanges_are_taken_apart() {
        let init = decode(
            "https://mcp.example.com/mcp",
            &h(&[("content-type", "application/json")]),
            br#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"claude-code","version":"2"}}}"#,
            Some(&h(&[("mcp-session-id", "s-1"), ("content-type", "text/event-stream")])),
            b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"jira\",\"version\":\"1.4\"}}}\n\n",
        )
        .unwrap();
        assert_eq!(init.label, "initialize");
        assert_eq!(init.session.as_deref(), Some("s-1"));
        assert_eq!(init.server, Some(("jira".into(), "1.4".into())));
        assert_eq!(init.protocol.as_deref(), Some("2025-06-18"));
        assert_eq!((init.sent[0].kind, init.received[0].kind), ("request", "result"));

        let list = decode(
            "https://mcp.example.com/mcp",
            &h(&[("mcp-session-id", "s-1"), ("mcp-protocol-version", "2025-06-18")]),
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
            None,
            br#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_issue","description":"Get a Jira issue","inputSchema":{"type":"object","properties":{"key":{"type":"string"}}}}]}}"#,
        )
        .unwrap();
        assert_eq!(list.tools.len(), 1);
        assert!(list.tools[0].tokens > 10);

        let call = decode(
            "https://mcp.example.com/mcp",
            &h(&[("mcp-session-id", "s-1")]),
            br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_issue","arguments":{"key":"PRJ-1"}}}"#,
            None,
            br#"{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"PRJ-1: Login fails"},{"type":"image","mimeType":"image/png","data":"AA"}],"isError":false}}"#,
        )
        .unwrap();
        assert_eq!(call.label, "tools/call get_issue");
        let c = call.call.unwrap();
        assert_eq!((c.name.as_str(), c.is_error), ("get_issue", false));
        assert_eq!(c.content[0].text, "PRJ-1: Login fails");
        assert_eq!(c.content[1].text, "[image image/png]");
        assert!(c.arguments.contains("PRJ-1"));
    }

    #[test]
    fn errors_notifications_and_the_older_transport() {
        let e = decode("http://localhost:3000/mcp", &h(&[]), br#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"x"}}"#, None, br#"{"jsonrpc":"2.0","id":5,"error":{"code":-32602,"message":"Unknown tool"}}"#).unwrap();
        assert_eq!(e.error.as_deref(), Some("Unknown tool"));
        assert!(e.call.unwrap().is_error);
        let n = decode("http://localhost:3000/mcp", &h(&[]), br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#, None, b"").unwrap();
        assert_eq!(n.sent[0].kind, "notification");
        let sse = decode("http://localhost:3000/sse", &h(&[]), b"", Some(&h(&[("content-type", "text/event-stream")])), b"event: endpoint\ndata: /messages?sessionId=abc\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n\n").unwrap();
        assert_eq!((sse.transport, sse.label.as_str()), ("sse", "stream"));
        let post = decode("http://localhost:3000/messages?sessionId=abc", &h(&[]), br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"x"}}"#, None, b"Accepted").unwrap();
        assert_eq!((post.transport, post.session.as_deref()), ("sse", Some("abc")));
        let batch = decode("http://localhost:3000/mcp", &h(&[]), br#"[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a"}},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"b"}}]"#, None, b"").unwrap();
        assert_eq!(batch.label, "tools/call a +1");
        // Other JSON-RPC (an Ethereum node) is no MCP.
        assert!(decode("https://rpc.example.com/", &h(&[]), br#"{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber"}"#, None, br#"{"jsonrpc":"2.0","id":1,"result":"0x1"}"#).is_none());
        let none = Hint::default();
        assert!(candidate("POST", "https://x.example.com/v1/mcp", none));
        assert!(!candidate("POST", "https://x.example.com/api", none));
        assert!(candidate("POST", "https://x.example.com/api", Hint { mcp_header: true, ..none }));
        assert!(candidate("POST", "https://x.example.com/", Hint { accepts_both: true, ..none }), "what MCP clients accept");
        assert!(candidate("POST", "https://mcp.stripe.com/", none));
        assert!(!candidate("POST", "https://api.anthropic.com/v1/messages", none), "LLM calls are no MCP");
        // A model explaining the SSE transport is no stream of it.
        assert!(decode("https://api.example.com/v1/chat", &h(&[]), b"{}", Some(&h(&[("content-type", "application/json")])), br#"{"text":"event: endpoint"}"#).is_none());
    }
}
