//! LLM calls over WebSocket: OpenAI's Responses API also runs over a WebSocket (`wss://…/responses`,
//! Codex with `responses_websockets`). Each `response.create` the client sends and the events the
//! server answers with, up to `response.completed`, become a session of their own (a POST with
//! the request as body and the events as a stream), so the LLM view, conversations, costs and the
//! agent cache's statistics work as for calls over HTTP. Read while the WebSocket is open.

use crate::AppCore;
use crate::ws::{Assembler, Deflate};
use quena_model::wslog::{self, RECORD_HEAD};
use quena_model::{Headers, HttpVersion, RequestHead, ResponseHead, SessionDetail, SessionId, SessionKind, SessionState};
use serde_json::Value;
use std::collections::HashMap;

/// Flag of a session made from a WebSocket: `#ws-session call n`.
pub const WS_CALL_FLAG: &str = "x-quena-ws-call";

/// Bytes of WebSocket logs read per tick.
const BUDGET: u64 = 8 << 20;

/// Events kept of a call: what the parser reads (`response.*`, errors).
fn kept(ty: &str) -> bool {
    ty.starts_with("response.") || ty == "error"
}

/// The WebSocket carries LLM calls (its path ends in `/responses`).
pub fn is_llm_socket(url: &str) -> bool {
    let path = url.split(['?', '#']).next().unwrap_or(url).trim_end_matches('/');
    path.ends_with("/responses")
}

#[derive(Default)]
pub struct WsLlmState {
    numbering: u64,
    readers: HashMap<SessionId, Reader>,
}

struct Reader {
    pos: u64,
    asm: Assembler,
    pending: Option<Pending>,
    calls: u32,
    finished: bool,
}

struct Pending {
    started: i64,
    request: Value,
    events: String,
}

/// A call read to its end.
struct Done {
    socket: SessionId,
    n: u32,
    started: i64,
    ended: i64,
    request: Value,
    events: String,
}

impl Reader {
    /// One message of the WebSocket; a call once its last event is in.
    fn message(&mut self, socket: SessionId, dir: u8, time: i64, text: &[u8]) -> Option<Done> {
        let v: Value = serde_json::from_slice(text).ok()?;
        let ty = v.get("type").and_then(|t| t.as_str()).unwrap_or("").to_string();
        if dir == 0 {
            if ty == "response.create" {
                let mut request = v;
                if let Some(o) = request.as_object_mut() {
                    o.remove("type");
                }
                self.pending = Some(Pending { started: time, request, events: String::new() });
            }
            return None;
        }
        let p = self.pending.as_mut()?;
        if kept(&ty) {
            p.events.push_str(&format!("event: {ty}\ndata: "));
            p.events.push_str(&String::from_utf8_lossy(text));
            p.events.push_str("\n\n");
        }
        if !matches!(ty.as_str(), "response.completed" | "response.failed" | "response.incomplete" | "error") {
            return None;
        }
        let p = self.pending.take()?;
        self.calls += 1;
        Some(Done { socket, n: self.calls, started: p.started, ended: time, request: p.request, events: p.events })
    }
}

impl AppCore {
    /// Read new messages of WebSockets that carry LLM calls; finished calls become sessions
    /// (called every second). Sessions of loaded archives are left alone: their calls were
    /// saved with them.
    pub fn ws_llm_tick(&self) {
        let cap = self.capture();
        let numbering = cap.numbering();
        let mut cands: Vec<(SessionId, bool)> = Vec::new();
        cap.index.for_each(|s| {
            if s.kind == SessionKind::WebSocket && s.archive.is_empty() && s.status == 101 && is_llm_socket(&s.url) {
                cands.push((s.id, s.state.is_final()));
            }
        });
        if cands.is_empty() {
            return;
        }
        let mut ready = Vec::new();
        {
            let mut st = self.ws_llm.lock();
            if st.numbering != numbering {
                st.numbering = numbering;
                st.readers.clear();
            }
            st.readers.retain(|id, _| cands.iter().any(|(c, _)| c == id));
            let mut budget = BUDGET;
            for (id, done) in cands {
                if budget == 0 {
                    break;
                }
                if st.readers.get(&id).is_some_and(|r| r.finished) {
                    continue;
                }
                let Some((_, body)) = cap.bodies_of(id) else { continue };
                let reader = st.readers.entry(id).or_insert_with(|| {
                    let deflate = Deflate::of(cap.detail(id).as_ref().and_then(|d| d.response.as_ref()));
                    Reader { pos: 0, asm: Assembler::new(deflate), pending: None, calls: 0, finished: false }
                });
                let total = body.len();
                let mut head = [0u8; RECORD_HEAD];
                while reader.pos + RECORD_HEAD as u64 <= total && budget > 0 {
                    if body.read_at(reader.pos, &mut head).unwrap_or(0) < RECORD_HEAD {
                        break;
                    }
                    let Some(h) = wslog::Head::parse(&head) else {
                        reader.finished = true;
                        break;
                    };
                    let end = reader.pos + RECORD_HEAD as u64 + h.len as u64;
                    // The rest of this frame is still being written.
                    if end > total {
                        break;
                    }
                    let payload = body.read_range(reader.pos + RECORD_HEAD as u64, h.len as usize).unwrap_or_default();
                    reader.pos = end;
                    budget = budget.saturating_sub(RECORD_HEAD as u64 + h.len as u64);
                    if let Some(m) = reader.asm.push(&h, &payload)
                        && m.opcode == 0x1
                        && let Some(call) = reader.message(id, m.dir, m.time, &m.data)
                    {
                        ready.push(call);
                    }
                }
                if done && reader.pos + RECORD_HEAD as u64 > total {
                    reader.finished = true;
                }
            }
        }
        for call in ready {
            if let Some(id) = self.ws_call_insert(&call) {
                self.llm_mark(numbering, id);
            }
        }
    }

    /// Call `c` as a session of its own, next to its WebSocket.
    fn ws_call_insert(&self, c: &Done) -> Option<SessionId> {
        let cap = self.capture();
        let ws = cap.detail(c.socket)?;
        let mut headers = Headers::default();
        for (k, v) in ws.request.headers.iter() {
            let lk = k.to_ascii_lowercase();
            if !(lk == "upgrade" || lk == "connection" || lk.starts_with("sec-websocket-") || lk == "content-length") {
                headers.push(k, v);
            }
        }
        headers.push("Content-Type", "application/json");
        let mut stream = Headers::default();
        stream.push("Content-Type", "text/event-stream");
        let mut d = SessionDetail::default();
        d.request = RequestHead { method: "POST".into(), url: ws.request.url.clone(), version: HttpVersion::Http11, headers };
        d.response = Some(ResponseHead { status: 200, reason: String::new(), version: HttpVersion::Http11, headers: stream });
        d.summary.state = SessionState::Done;
        d.summary.started_at = c.started;
        d.summary.comment = format!("Over WebSocket #{} (call {})", c.socket, c.n);
        d.timers.client_begin_request = Some(c.started);
        d.timers.client_done_response = Some(c.ended.max(c.started));
        d.process = ws.process.clone();
        d.extra_flags.push((WS_CALL_FLAG.into(), format!("#{} call {}", c.socket, c.n)));
        let req = cap.bodies.store_bytes(serde_json::to_string(&c.request).ok()?.as_bytes());
        let resp = cap.bodies.store_bytes(c.events.as_bytes());
        Some(cap.insert(d, req, resp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockets_for_llm_calls() {
        assert!(is_llm_socket("https://chatgpt.com/backend-api/codex/responses"));
        assert!(is_llm_socket("wss://api.openai.com/v1/responses?x=1"));
        assert!(!is_llm_socket("https://example.com/socket.io/?EIO=4"));
    }

    #[test]
    fn a_call_runs_from_create_to_completed() {
        let mut r = Reader { pos: 0, asm: Assembler::new(Deflate::default()), pending: None, calls: 0, finished: false };
        assert!(r.message(7, 1, 1, br#"{"type":"codex.rate_limits"}"#).is_none(), "nothing asked yet");
        assert!(r.message(7, 0, 10, br#"{"type":"response.create","model":"gpt-5","input":[]}"#).is_none());
        assert!(r.message(7, 1, 11, br#"{"type":"codex.rate_limits"}"#).is_none());
        assert!(r.message(7, 1, 12, br#"{"type":"response.created","response":{"id":"resp_1"}}"#).is_none());
        let d = r.message(7, 1, 20, br#"{"type":"response.completed","response":{"id":"resp_1","output":[]}}"#).unwrap();
        assert_eq!((d.n, d.started, d.ended), (1, 10, 20));
        assert_eq!(d.request, serde_json::json!({"model": "gpt-5", "input": []}));
        assert!(d.events.starts_with("event: response.created\ndata: ") && !d.events.contains("rate_limits"), "{}", d.events);
    }

    #[test]
    fn calls_of_a_compressed_websocket_become_sessions() {
        use crate::ws::tests::{deflate_all, rec_rsv};
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("settings.json"), "{}").unwrap();
        let core = AppCore::new(crate::Paths::at(dir.path().to_path_buf()), crate::logbuf::LogBuffer::new(10)).unwrap();
        let cap = core.capture();
        let up = deflate_all(&[br#"{"type":"response.create","model":"gpt-5","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"Fix the parser"}]}]}"#]);
        let down = deflate_all(&[
            br#"{"type":"codex.rate_limits","plan_type":"plus"}"#,
            br#"{"type":"response.created","response":{"id":"resp_1"}}"#,
            br#"{"type":"response.output_item.done","item":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Done."}]}}"#,
            br#"{"type":"response.completed","response":{"id":"resp_1","output":[],"usage":{"input_tokens":1200,"output_tokens":30}}}"#,
        ]);
        let mut log = rec_rsv(0, 1, 4, &up[0], 1_000_000);
        for (i, m) in down.iter().enumerate() {
            log.extend(rec_rsv(1, 1, 4, m, 1_100_000 + i as i64 * 100_000));
        }
        let mut d = SessionDetail::default();
        d.summary.kind = SessionKind::WebSocket;
        d.summary.state = SessionState::Done;
        let mut req = Headers::default();
        req.push("User-Agent", "codex_exec/0.154.0");
        req.push("Upgrade", "websocket");
        req.push("Sec-WebSocket-Key", "x");
        d.request = RequestHead { method: "GET".into(), url: "https://chatgpt.com/backend-api/codex/responses".into(), version: HttpVersion::Http11, headers: req };
        let mut h = Headers::default();
        h.push("Sec-WebSocket-Extensions", "permessage-deflate");
        d.response = Some(ResponseHead { status: 101, headers: h, ..Default::default() });
        let ws = cap.insert(d, cap.bodies.store_bytes(&[]), cap.bodies.store_bytes(&log));
        core.ws_llm_tick();
        core.ws_llm_tick();
        cap.index.tick();
        let calls = cap.index.find_all(|s| !s.llm.is_empty());
        assert_eq!(calls.len(), 1, "read once");
        let s = cap.index.get(calls[0]).unwrap();
        assert_eq!((s.method.as_str(), s.llm.as_str(), s.llm_tokens), ("POST", "OpenAI (ChatGPT)/gpt-5", Some(1230)));
        assert_eq!(s.comment, format!("Over WebSocket #{ws} (call 1)"));
        let call = core.llm(calls[0]).unwrap();
        assert_eq!(call.output[0].text, "Done.");
        let d = cap.detail(calls[0]).unwrap();
        assert!(d.request.headers.get("upgrade").is_none() && d.request.headers.get("user-agent") == Some("codex_exec/0.154.0"));
        assert_eq!(core.llm_conversations()[0].title, "Fix the parser");
    }
}
