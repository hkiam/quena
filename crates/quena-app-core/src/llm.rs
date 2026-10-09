//! Calls to large language model APIs: which provider and model, the conversation sent, the
//! answer (also assembled from a stream), tool calls, token usage and an estimated cost.
//!
//! Understood: OpenAI Chat Completions and Responses (and the many OpenAI-compatible APIs:
//! Azure OpenAI, Mistral, Groq, OpenRouter, DeepSeek, xAI, Together, local servers),
//! Anthropic Messages, Google Gemini (`generateContent`, `streamGenerateContent`) and Ollama
//! (`/api/chat`, `/api/generate`); embeddings requests with their usage. Streams come as
//! server-sent events, Ollama's as JSON lines, Gemini's also as one JSON array.

use crate::AppCore;
use quena_model::{SessionDetail, SessionId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Bytes of a request or response body read.
const MAX_BODY: usize = 16 << 20;
/// Longest text kept per part (the UI shows the start; the body views have the rest).
const MAX_TEXT: usize = 200_000;

/// The flags a recognised call gets (kept in archives).
pub const LLM_FLAG: &str = "x-quena-llm";
pub const LLM_TOKENS_FLAG: &str = "x-quena-llm-tokens";
pub const LLM_USAGE_FLAG: &str = "x-quena-llm-usage";
pub const LLM_COST_FLAG: &str = "x-quena-llm-cost";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Api {
    /// OpenAI Chat Completions and compatible.
    Chat,
    /// OpenAI Responses.
    Responses,
    /// Anthropic Messages.
    Messages,
    Gemini,
    OllamaChat,
    OllamaGenerate,
    Embeddings,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Part {
    /// `text`, `image`, `toolCall`, `toolResult`, `thinking`, `other`.
    pub kind: String,
    pub text: String,
    /// Tool name (calls), or the media type of an image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Tool call id (calls and results).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    /// `system`, `user`, `assistant`, `tool`.
    pub role: String,
    pub parts: Vec<Part>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ToolDef {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Usage {
    /// Input tokens, including cached ones.
    pub input: u64,
    pub output: u64,
    /// Input tokens read from the provider's cache.
    pub cache_read: u64,
    /// Input tokens written to the cache (Anthropic).
    pub cache_write: u64,
    /// Output tokens spent on reasoning (part of `output`).
    pub reasoning: u64,
}

impl Usage {
    pub fn total(&self) -> u64 {
        self.input.saturating_add(self.output)
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Cost {
    pub usd: f64,
    /// Which price was used (model prefix and where it comes from).
    pub price: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LlmCall {
    pub provider: String,
    pub api: Api,
    pub model: String,
    pub stream: bool,
    /// System prompt / instructions.
    pub system: Vec<String>,
    /// The conversation sent.
    pub messages: Vec<Message>,
    pub tools: Vec<ToolDef>,
    /// Sampling and limit parameters as sent.
    pub params: Vec<(String, String)>,
    /// The answer: text, thinking, tool calls.
    pub output: Vec<Part>,
    pub stop_reason: Option<String>,
    pub usage: Option<Usage>,
    pub cost: Option<Cost>,
    /// An error the API answered with.
    pub error: Option<String>,
    /// Texts were shortened, the response is not complete, …
    pub notes: Vec<String>,
}

// ------------------------------------------------------------------ detection

fn host_of(url: &str) -> String {
    url.parse::<http::Uri>().ok().and_then(|u| u.host().map(|h| h.to_ascii_lowercase())).unwrap_or_default()
}

fn path_of(url: &str) -> String {
    url.parse::<http::Uri>().ok().map(|u| u.path().to_string()).unwrap_or_default()
}

/// The provider's name for a host (generic hosts by their name).
fn provider_of(host: &str, api: Api) -> String {
    let known: &[(&str, &str)] = &[
        ("api.openai.com", "OpenAI"),
        ("openai.azure.com", "Azure OpenAI"),
        ("cognitiveservices.azure.com", "Azure OpenAI"),
        ("services.ai.azure.com", "Azure AI"),
        ("api.anthropic.com", "Anthropic"),
        ("generativelanguage.googleapis.com", "Google Gemini"),
        ("aiplatform.googleapis.com", "Google Vertex AI"),
        ("api.mistral.ai", "Mistral"),
        ("api.groq.com", "Groq"),
        ("openrouter.ai", "OpenRouter"),
        ("api.deepseek.com", "DeepSeek"),
        ("api.x.ai", "xAI"),
        ("api.together.xyz", "Together"),
        ("api.fireworks.ai", "Fireworks"),
        ("api.perplexity.ai", "Perplexity"),
        ("api.cohere.com", "Cohere"),
    ];
    if let Some((_, n)) = known.iter().find(|(h, _)| host == *h || host.ends_with(&format!(".{h}"))) {
        return n.to_string();
    }
    if matches!(api, Api::OllamaChat | Api::OllamaGenerate) {
        return "Ollama".into();
    }
    host.to_string()
}

/// The API a request goes to, judged by its URL (and method): `None` for anything else.
pub fn api_of(method: &str, url: &str) -> Option<Api> {
    if !method.eq_ignore_ascii_case("POST") {
        return None;
    }
    let path = path_of(url);
    let p = path.trim_end_matches('/');
    Some(if p.ends_with("/chat/completions") {
        Api::Chat
    } else if p.ends_with("/responses") {
        Api::Responses
    } else if p.ends_with("/v1/messages") || p == "/messages" && host_of(url).contains("anthropic") {
        Api::Messages
    } else if p.contains(":generateContent") || p.contains(":streamGenerateContent") {
        Api::Gemini
    } else if p.ends_with("/api/chat") {
        Api::OllamaChat
    } else if p.ends_with("/api/generate") {
        Api::OllamaGenerate
    } else if p.ends_with("/embeddings") || p.ends_with("/api/embed") || p.ends_with("/api/embeddings") || p.contains(":embedContent") || p.contains(":batchEmbedContents") {
        Api::Embeddings
    } else {
        return None;
    })
}

// ------------------------------------------------------------------ helpers

fn cut(s: &str, notes: &mut Vec<String>) -> String {
    if s.len() <= MAX_TEXT {
        return s.to_string();
    }
    let mut end = MAX_TEXT;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    let note = "long texts are shortened here; the body views show them whole".to_string();
    if !notes.contains(&note) {
        notes.push(note);
    }
    format!("{} … ({} characters)", &s[..end], s.chars().count())
}

fn text_part(t: &str, notes: &mut Vec<String>) -> Part {
    Part { kind: "text".into(), text: cut(t, notes), ..Default::default() }
}

fn pretty(v: &Value) -> String {
    match v {
        Value::String(s) => match serde_json::from_str::<Value>(s) {
            Ok(j) if j.is_object() || j.is_array() => serde_json::to_string_pretty(&j).unwrap_or_else(|_| s.clone()),
            _ => s.clone(),
        },
        Value::Null => String::new(),
        other => serde_json::to_string_pretty(other).unwrap_or_default(),
    }
}

fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(str::to_string)
}

fn n(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(|x| x.as_u64()).unwrap_or(0)
}

fn params(v: &Value, keys: &[&str]) -> Vec<(String, String)> {
    keys.iter().filter_map(|k| v.get(*k).filter(|x| !x.is_null()).map(|x| (k.to_string(), if let Value::String(s) = x { s.clone() } else { x.to_string() }))).collect()
}

/// Server-sent events: (event name, data) for each event.
fn sse_events(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let (mut event, mut data) = (String::new(), Vec::<&str>::new());
    for line in text.lines().chain(std::iter::once("")) {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            if !data.is_empty() {
                out.push((std::mem::take(&mut event), data.join("\n")));
                data.clear();
            }
            event.clear();
        } else if let Some(d) = line.strip_prefix("data:") {
            data.push(d.strip_prefix(' ').unwrap_or(d));
        } else if let Some(e) = line.strip_prefix("event:") {
            event = e.trim().to_string();
        }
    }
    out
}

/// The JSON objects of a streamed response: SSE `data:`, JSON lines, or one JSON array.
fn stream_objects(text: &str) -> Vec<Value> {
    let t = text.trim_start();
    if t.starts_with('[') {
        if let Ok(Value::Array(a)) = serde_json::from_str::<Value>(t) {
            return a;
        }
    }
    if t.starts_with("data:") || t.starts_with("event:") || t.starts_with(':') || text.contains("\ndata:") {
        return sse_events(text).into_iter().filter_map(|(_, d)| serde_json::from_str(&d).ok()).collect();
    }
    text.lines().filter_map(|l| serde_json::from_str(l.trim()).ok()).collect()
}

fn error_of(v: &Value) -> Option<String> {
    let e = v.get("error")?;
    if e.is_null() {
        return None;
    }
    Some(match e {
        Value::String(s) => s.clone(),
        _ => {
            let msg = s(e, "message").unwrap_or_default();
            let kind = s(e, "type").or_else(|| s(e, "code")).or_else(|| s(e, "status")).unwrap_or_default();
            if kind.is_empty() { msg } else { format!("{kind}: {msg}") }
        }
    })
}

// ------------------------------------------------------------------ requests

/// Content of an OpenAI-style message: a string or a list of typed parts.
fn openai_content(c: &Value, notes: &mut Vec<String>) -> Vec<Part> {
    match c {
        Value::String(t) => vec![text_part(t, notes)],
        Value::Array(items) => items
            .iter()
            .map(|p| match s(p, "type").as_deref() {
                Some("text" | "input_text" | "output_text") => text_part(&s(p, "text").unwrap_or_default(), notes),
                Some("image_url" | "input_image") => Part { kind: "image".into(), text: "[image]".into(), ..Default::default() },
                Some("input_audio") => Part { kind: "other".into(), text: "[audio]".into(), ..Default::default() },
                Some("file" | "input_file") => Part { kind: "other".into(), text: "[file]".into(), ..Default::default() },
                Some("refusal") => text_part(&s(p, "refusal").unwrap_or_default(), notes),
                _ => Part { kind: "other".into(), text: cut(&pretty(p), notes), ..Default::default() },
            })
            .collect(),
        Value::Null => vec![],
        other => vec![Part { kind: "other".into(), text: cut(&pretty(other), notes), ..Default::default() }],
    }
}

fn chat_request(v: &Value, call: &mut LlmCall) {
    let notes = &mut call.notes;
    for m in v.get("messages").and_then(|m| m.as_array()).into_iter().flatten() {
        let role = s(m, "role").unwrap_or_default();
        let mut parts = openai_content(m.get("content").unwrap_or(&Value::Null), notes);
        for tc in m.get("tool_calls").and_then(|t| t.as_array()).into_iter().flatten() {
            let f = tc.get("function").unwrap_or(&Value::Null);
            parts.push(Part { kind: "toolCall".into(), name: s(f, "name"), id: s(tc, "id"), text: cut(&pretty(f.get("arguments").unwrap_or(&Value::Null)), notes) });
        }
        if role == "tool" {
            for p in &mut parts {
                p.kind = "toolResult".into();
                p.id = s(m, "tool_call_id");
            }
        }
        if role == "system" || role == "developer" {
            call.system.extend(parts.iter().map(|p| p.text.clone()));
        } else {
            call.messages.push(Message { role, parts });
        }
    }
    for t in v.get("tools").and_then(|t| t.as_array()).into_iter().flatten() {
        let f = t.get("function").unwrap_or(t);
        call.tools.push(ToolDef { name: s(f, "name").unwrap_or_else(|| s(t, "type").unwrap_or_default()), description: s(f, "description").unwrap_or_default() });
    }
    call.params = params(v, &["temperature", "top_p", "max_tokens", "max_completion_tokens", "reasoning_effort", "tool_choice", "response_format", "seed", "n"]);
}

fn responses_request(v: &Value, call: &mut LlmCall) {
    if let Some(i) = s(v, "instructions") {
        call.system.push(cut(&i, &mut call.notes));
    }
    match v.get("input") {
        Some(Value::String(t)) => call.messages.push(Message { role: "user".into(), parts: vec![text_part(t, &mut call.notes)] }),
        Some(Value::Array(items)) => {
            for it in items {
                match s(it, "type").as_deref() {
                    Some("function_call") => call.messages.push(Message {
                        role: "assistant".into(),
                        parts: vec![Part { kind: "toolCall".into(), name: s(it, "name"), id: s(it, "call_id"), text: cut(&pretty(it.get("arguments").unwrap_or(&Value::Null)), &mut call.notes) }],
                    }),
                    Some("function_call_output") => call.messages.push(Message {
                        role: "tool".into(),
                        parts: vec![Part { kind: "toolResult".into(), id: s(it, "call_id"), text: cut(&pretty(it.get("output").unwrap_or(&Value::Null)), &mut call.notes), ..Default::default() }],
                    }),
                    Some("reasoning") => {}
                    _ => {
                        let role = s(it, "role").unwrap_or_else(|| "user".into());
                        let parts = openai_content(it.get("content").unwrap_or(&Value::Null), &mut call.notes);
                        if role == "system" || role == "developer" {
                            call.system.extend(parts.into_iter().map(|p| p.text));
                        } else {
                            call.messages.push(Message { role, parts });
                        }
                    }
                }
            }
        }
        _ => {}
    }
    for t in v.get("tools").and_then(|t| t.as_array()).into_iter().flatten() {
        call.tools.push(ToolDef { name: s(t, "name").unwrap_or_else(|| s(t, "type").unwrap_or_default()), description: s(t, "description").unwrap_or_default() });
    }
    call.params = params(v, &["temperature", "top_p", "max_output_tokens", "tool_choice", "previous_response_id", "store"]);
    if let Some(r) = v.get("reasoning").and_then(|r| r.get("effort")) {
        call.params.push(("reasoning.effort".into(), r.as_str().unwrap_or_default().into()));
    }
}

fn anthropic_blocks(c: &Value, notes: &mut Vec<String>) -> Vec<Part> {
    match c {
        Value::String(t) => vec![text_part(t, notes)],
        Value::Array(items) => items
            .iter()
            .map(|b| match s(b, "type").as_deref() {
                Some("text") => text_part(&s(b, "text").unwrap_or_default(), notes),
                Some("image") => Part { kind: "image".into(), text: "[image]".into(), name: b.get("source").and_then(|x| s(x, "media_type")), ..Default::default() },
                Some("document") => Part { kind: "other".into(), text: "[document]".into(), ..Default::default() },
                Some("tool_use" | "server_tool_use") => Part { kind: "toolCall".into(), name: s(b, "name"), id: s(b, "id"), text: cut(&pretty(b.get("input").unwrap_or(&Value::Null)), notes) },
                Some("tool_result") => {
                    let content = match b.get("content") {
                        Some(Value::Array(a)) => a.iter().filter_map(|x| s(x, "text")).collect::<Vec<_>>().join("\n"),
                        Some(x) => pretty(x),
                        None => String::new(),
                    };
                    Part { kind: "toolResult".into(), id: s(b, "tool_use_id"), text: cut(&content, notes), ..Default::default() }
                }
                Some("thinking") => Part { kind: "thinking".into(), text: cut(&s(b, "thinking").unwrap_or_default(), notes), ..Default::default() },
                Some("redacted_thinking") => Part { kind: "thinking".into(), text: "[redacted]".into(), ..Default::default() },
                _ => Part { kind: "other".into(), text: cut(&pretty(b), notes), ..Default::default() },
            })
            .collect(),
        _ => vec![],
    }
}

fn anthropic_request(v: &Value, call: &mut LlmCall) {
    match v.get("system") {
        Some(Value::String(t)) => call.system.push(cut(t, &mut call.notes)),
        Some(Value::Array(a)) => call.system.extend(a.iter().filter_map(|b| s(b, "text"))),
        _ => {}
    }
    for m in v.get("messages").and_then(|m| m.as_array()).into_iter().flatten() {
        let parts = anthropic_blocks(m.get("content").unwrap_or(&Value::Null), &mut call.notes);
        call.messages.push(Message { role: s(m, "role").unwrap_or_default(), parts });
    }
    for t in v.get("tools").and_then(|t| t.as_array()).into_iter().flatten() {
        call.tools.push(ToolDef { name: s(t, "name").unwrap_or_default(), description: s(t, "description").unwrap_or_default() });
    }
    call.params = params(v, &["max_tokens", "temperature", "top_p", "top_k", "tool_choice", "stop_sequences"]);
    if let Some(t) = v.get("thinking").filter(|t| !t.is_null()) {
        call.params.push(("thinking".into(), t.to_string()));
    }
}

fn gemini_parts(c: &Value, notes: &mut Vec<String>) -> Vec<Part> {
    c.get("parts")
        .and_then(|p| p.as_array())
        .into_iter()
        .flatten()
        .map(|p| {
            if let Some(t) = s(p, "text") {
                let thought = p.get("thought").and_then(|x| x.as_bool()).unwrap_or(false);
                Part { kind: if thought { "thinking" } else { "text" }.into(), text: cut(&t, notes), ..Default::default() }
            } else if let Some(f) = p.get("functionCall") {
                Part { kind: "toolCall".into(), name: s(f, "name"), id: s(f, "id"), text: cut(&pretty(f.get("args").unwrap_or(&Value::Null)), notes) }
            } else if let Some(f) = p.get("functionResponse") {
                Part { kind: "toolResult".into(), name: s(f, "name"), id: s(f, "id"), text: cut(&pretty(f.get("response").unwrap_or(&Value::Null)), notes) }
            } else if p.get("inlineData").is_some() || p.get("fileData").is_some() {
                Part { kind: "image".into(), text: "[media]".into(), ..Default::default() }
            } else {
                Part { kind: "other".into(), text: cut(&pretty(p), notes), ..Default::default() }
            }
        })
        .collect()
}

fn gemini_request(v: &Value, call: &mut LlmCall) {
    if let Some(si) = v.get("systemInstruction").or_else(|| v.get("system_instruction")) {
        call.system.extend(gemini_parts(si, &mut call.notes).into_iter().map(|p| p.text));
    }
    for c in v.get("contents").and_then(|m| m.as_array()).into_iter().flatten() {
        let role = match s(c, "role").as_deref() {
            Some("model") => "assistant".to_string(),
            Some(r) => r.to_string(),
            None => "user".into(),
        };
        let parts = gemini_parts(c, &mut call.notes);
        call.messages.push(Message { role, parts });
    }
    for t in v.get("tools").and_then(|t| t.as_array()).into_iter().flatten() {
        for f in t.get("functionDeclarations").or_else(|| t.get("function_declarations")).and_then(|f| f.as_array()).into_iter().flatten() {
            call.tools.push(ToolDef { name: s(f, "name").unwrap_or_default(), description: s(f, "description").unwrap_or_default() });
        }
    }
    if let Some(g) = v.get("generationConfig").or_else(|| v.get("generation_config")) {
        call.params = params(g, &["temperature", "topP", "topK", "maxOutputTokens", "candidateCount", "responseMimeType"]);
        if let Some(t) = g.get("thinkingConfig") {
            call.params.push(("thinkingConfig".into(), t.to_string()));
        }
    }
}

fn ollama_request(v: &Value, call: &mut LlmCall) {
    if call.api == Api::OllamaGenerate {
        if let Some(sys) = s(v, "system") {
            call.system.push(cut(&sys, &mut call.notes));
        }
        let mut parts = vec![text_part(&s(v, "prompt").unwrap_or_default(), &mut call.notes)];
        if v.get("images").and_then(|i| i.as_array()).is_some_and(|a| !a.is_empty()) {
            parts.push(Part { kind: "image".into(), text: "[image]".into(), ..Default::default() });
        }
        call.messages.push(Message { role: "user".into(), parts });
    } else {
        chat_request(v, call);
    }
    if let Some(o) = v.get("options") {
        call.params = params(o, &["temperature", "top_p", "top_k", "num_predict", "num_ctx", "seed"]);
    }
}

// ------------------------------------------------------------------ responses

fn chat_response(v: &Value, call: &mut LlmCall) {
    if let Some(c) = v.get("choices").and_then(|c| c.get(0)) {
        let m = c.get("message").unwrap_or(&Value::Null);
        call.output.extend(openai_content(m.get("content").unwrap_or(&Value::Null), &mut call.notes).into_iter().filter(|p| !p.text.is_empty()));
        if let Some(r) = s(m, "reasoning_content").or_else(|| s(m, "reasoning")) {
            call.output.insert(0, Part { kind: "thinking".into(), text: cut(&r, &mut call.notes), ..Default::default() });
        }
        for tc in m.get("tool_calls").and_then(|t| t.as_array()).into_iter().flatten() {
            let f = tc.get("function").unwrap_or(&Value::Null);
            call.output.push(Part { kind: "toolCall".into(), name: s(f, "name"), id: s(tc, "id"), text: cut(&pretty(f.get("arguments").unwrap_or(&Value::Null)), &mut call.notes) });
        }
        call.stop_reason = s(c, "finish_reason");
    }
    if let Some(u) = v.get("usage").filter(|u| u.is_object()) {
        call.usage = Some(openai_usage(u));
    }
}

fn openai_usage(u: &Value) -> Usage {
    let input = n(u, "prompt_tokens").max(n(u, "input_tokens"));
    let output = n(u, "completion_tokens").max(n(u, "output_tokens"));
    let cached = u.get("prompt_tokens_details").or_else(|| u.get("input_tokens_details")).map(|d| n(d, "cached_tokens")).unwrap_or(0);
    let reasoning = u.get("completion_tokens_details").or_else(|| u.get("output_tokens_details")).map(|d| n(d, "reasoning_tokens")).unwrap_or(0);
    Usage { input, output, cache_read: cached, cache_write: 0, reasoning }
}

/// OpenAI chat stream: deltas of text and tool calls (by index), finish reason, usage.
fn chat_stream(objs: &[Value], call: &mut LlmCall) {
    let mut text = String::new();
    let mut reasoning = String::new();
    let mut tools: BTreeMap<u64, (Option<String>, Option<String>, String)> = BTreeMap::new();
    for o in objs {
        if let Some(e) = error_of(o) {
            call.error = Some(e);
        }
        if call.model.is_empty() {
            call.model = s(o, "model").unwrap_or_default();
        }
        if let Some(c) = o.get("choices").and_then(|c| c.get(0)) {
            let d = c.get("delta").unwrap_or(&Value::Null);
            if let Some(t) = s(d, "content") {
                text.push_str(&t);
            }
            if let Some(t) = s(d, "reasoning_content").or_else(|| s(d, "reasoning")) {
                reasoning.push_str(&t);
            }
            for tc in d.get("tool_calls").and_then(|t| t.as_array()).into_iter().flatten() {
                let e = tools.entry(tc.get("index").and_then(|i| i.as_u64()).unwrap_or(0)).or_default();
                if let Some(id) = s(tc, "id") {
                    e.1 = Some(id);
                }
                if let Some(f) = tc.get("function") {
                    if let Some(n) = s(f, "name") {
                        e.0 = Some(n);
                    }
                    if let Some(a) = s(f, "arguments") {
                        e.2.push_str(&a);
                    }
                }
            }
            if let Some(r) = s(c, "finish_reason") {
                call.stop_reason = Some(r);
            }
        }
        if let Some(u) = o.get("usage").filter(|u| u.is_object()) {
            call.usage = Some(openai_usage(u));
        }
    }
    if !reasoning.is_empty() {
        call.output.push(Part { kind: "thinking".into(), text: cut(&reasoning, &mut call.notes), ..Default::default() });
    }
    if !text.is_empty() {
        call.output.push(text_part(&text, &mut call.notes));
    }
    for (_, (name, id, args)) in tools {
        call.output.push(Part { kind: "toolCall".into(), name, id, text: cut(&pretty(&Value::String(args)), &mut call.notes) });
    }
    if call.usage.is_none() {
        call.notes.push("the stream carries no token usage (OpenAI sends it with stream_options.include_usage)".into());
    }
}

fn responses_response(v: &Value, call: &mut LlmCall) {
    for it in v.get("output").and_then(|o| o.as_array()).into_iter().flatten() {
        match s(it, "type").as_deref() {
            Some("message") => call.output.extend(openai_content(it.get("content").unwrap_or(&Value::Null), &mut call.notes)),
            Some("function_call") => call.output.push(Part { kind: "toolCall".into(), name: s(it, "name"), id: s(it, "call_id"), text: cut(&pretty(it.get("arguments").unwrap_or(&Value::Null)), &mut call.notes) }),
            Some("reasoning") => {
                let summary: Vec<String> = it.get("summary").and_then(|x| x.as_array()).into_iter().flatten().filter_map(|x| s(x, "text")).collect();
                call.output.push(Part { kind: "thinking".into(), text: if summary.is_empty() { "[reasoning]".into() } else { cut(&summary.join("\n"), &mut call.notes) }, ..Default::default() });
            }
            Some(other) => call.output.push(Part { kind: "toolCall".into(), name: Some(other.to_string()), id: s(it, "id"), text: cut(&pretty(it), &mut call.notes) }),
            None => {}
        }
    }
    call.stop_reason = s(v, "status").or(call.stop_reason.take());
    if let Some(r) = v.get("incomplete_details").and_then(|d| s(d, "reason")) {
        call.stop_reason = Some(r);
    }
    if let Some(u) = v.get("usage").filter(|u| u.is_object()) {
        call.usage = Some(openai_usage(u));
    }
    if call.model.is_empty() {
        call.model = s(v, "model").unwrap_or_default();
    }
}

fn responses_stream(text: &str, call: &mut LlmCall) {
    let events = sse_events(text);
    // The final event carries the whole response.
    if let Some(done) = events.iter().rev().filter_map(|(_, d)| serde_json::from_str::<Value>(d).ok()).find(|v| matches!(s(v, "type").as_deref(), Some("response.completed" | "response.incomplete" | "response.failed"))) {
        if let Some(r) = done.get("response") {
            responses_response(r, call);
            if let Some(e) = r.get("error").filter(|e| !e.is_null()) {
                call.error = Some(pretty(e));
            }
            return;
        }
    }
    let mut out = String::new();
    for (_, d) in &events {
        if let Ok(v) = serde_json::from_str::<Value>(d)
            && s(&v, "type").as_deref() == Some("response.output_text.delta")
        {
            out.push_str(&s(&v, "delta").unwrap_or_default());
        }
    }
    if !out.is_empty() {
        call.output.push(text_part(&out, &mut call.notes));
    }
    call.notes.push("the stream did not complete".into());
}

fn anthropic_response(v: &Value, call: &mut LlmCall) {
    call.output.extend(anthropic_blocks(v.get("content").unwrap_or(&Value::Null), &mut call.notes));
    call.stop_reason = s(v, "stop_reason");
    if let Some(u) = v.get("usage") {
        call.usage = Some(anthropic_usage(u, None));
    }
}

/// Anthropic counts cached input apart; `input` here includes it.
fn anthropic_usage(u: &Value, before: Option<Usage>) -> Usage {
    let b = before.unwrap_or_default();
    let read = n(u, "cache_read_input_tokens").max(b.cache_read);
    let write = n(u, "cache_creation_input_tokens").max(b.cache_write);
    let fresh = n(u, "input_tokens");
    let input = if fresh > 0 || read > 0 || write > 0 { fresh.saturating_add(read).saturating_add(write) } else { b.input };
    Usage { input: input.max(b.input), output: n(u, "output_tokens").max(b.output), cache_read: read, cache_write: write, reasoning: 0 }
}

fn anthropic_stream(text: &str, call: &mut LlmCall) {
    let mut blocks: BTreeMap<u64, Part> = BTreeMap::new();
    let mut json: BTreeMap<u64, String> = BTreeMap::new();
    let mut complete = false;
    for (_, d) in sse_events(text) {
        let Ok(v) = serde_json::from_str::<Value>(&d) else { continue };
        match s(&v, "type").as_deref() {
            Some("message_start") => {
                if let Some(m) = v.get("message") {
                    call.model = s(m, "model").unwrap_or_default();
                    if let Some(u) = m.get("usage") {
                        call.usage = Some(anthropic_usage(u, None));
                    }
                }
            }
            Some("content_block_start") => {
                let i = n(&v, "index");
                let b = v.get("content_block").unwrap_or(&Value::Null);
                let part = match s(b, "type").as_deref() {
                    Some("tool_use" | "server_tool_use") => Part { kind: "toolCall".into(), name: s(b, "name"), id: s(b, "id"), text: String::new() },
                    Some("thinking") => Part { kind: "thinking".into(), text: s(b, "thinking").unwrap_or_default(), ..Default::default() },
                    Some("redacted_thinking") => Part { kind: "thinking".into(), text: "[redacted]".into(), ..Default::default() },
                    _ => Part { kind: "text".into(), text: s(b, "text").unwrap_or_default(), ..Default::default() },
                };
                blocks.insert(i, part);
            }
            Some("content_block_delta") => {
                let i = n(&v, "index");
                let d = v.get("delta").unwrap_or(&Value::Null);
                let p = blocks.entry(i).or_insert_with(|| Part { kind: "text".into(), ..Default::default() });
                match s(d, "type").as_deref() {
                    Some("text_delta") => p.text.push_str(&s(d, "text").unwrap_or_default()),
                    Some("thinking_delta") => p.text.push_str(&s(d, "thinking").unwrap_or_default()),
                    Some("input_json_delta") => json.entry(i).or_default().push_str(&s(d, "partial_json").unwrap_or_default()),
                    _ => {}
                }
            }
            Some("message_delta") => {
                if let Some(r) = v.get("delta").and_then(|d| s(d, "stop_reason")) {
                    call.stop_reason = Some(r);
                }
                if let Some(u) = v.get("usage") {
                    call.usage = Some(anthropic_usage(u, call.usage));
                }
            }
            Some("message_stop") => complete = true,
            Some("error") => call.error = error_of(&v),
            _ => {}
        }
    }
    for (i, mut p) in blocks {
        if let Some(j) = json.remove(&i) {
            p.text = pretty(&Value::String(j));
        }
        p.text = cut(&p.text, &mut call.notes);
        call.output.push(p);
    }
    if !complete && call.error.is_none() {
        call.notes.push("the stream did not complete".into());
    }
}

fn gemini_response(objs: &[Value], call: &mut LlmCall) {
    let mut text = String::new();
    let mut thinking = String::new();
    for o in objs {
        if let Some(e) = error_of(o) {
            call.error = Some(e);
        }
        if let Some(m) = s(o, "modelVersion") {
            call.model = m;
        }
        if let Some(c) = o.get("candidates").and_then(|c| c.get(0)) {
            for p in gemini_parts(c.get("content").unwrap_or(&Value::Null), &mut call.notes) {
                match p.kind.as_str() {
                    "text" => text.push_str(&p.text),
                    "thinking" => thinking.push_str(&p.text),
                    _ => call.output.push(p),
                }
            }
            if let Some(r) = s(c, "finishReason") {
                call.stop_reason = Some(r);
            }
        }
        if let Some(u) = o.get("usageMetadata") {
            let reasoning = n(u, "thoughtsTokenCount");
            call.usage = Some(Usage { input: n(u, "promptTokenCount"), output: n(u, "candidatesTokenCount") + reasoning, cache_read: n(u, "cachedContentTokenCount"), cache_write: 0, reasoning });
        }
    }
    if !thinking.is_empty() {
        call.output.insert(0, Part { kind: "thinking".into(), text: cut(&thinking, &mut call.notes), ..Default::default() });
    }
    if !text.is_empty() {
        call.output.push(text_part(&text, &mut call.notes));
    }
}

fn ollama_response(objs: &[Value], call: &mut LlmCall) {
    let mut text = String::new();
    let mut thinking = String::new();
    let mut done = false;
    for o in objs {
        if let Some(e) = error_of(o) {
            call.error = Some(e);
        }
        if call.model.is_empty() {
            call.model = s(o, "model").unwrap_or_default();
        }
        if let Some(m) = o.get("message") {
            text.push_str(&s(m, "content").unwrap_or_default());
            thinking.push_str(&s(m, "thinking").unwrap_or_default());
            for tc in m.get("tool_calls").and_then(|t| t.as_array()).into_iter().flatten() {
                let f = tc.get("function").unwrap_or(&Value::Null);
                call.output.push(Part { kind: "toolCall".into(), name: s(f, "name"), id: None, text: cut(&pretty(f.get("arguments").unwrap_or(&Value::Null)), &mut call.notes) });
            }
        }
        text.push_str(&s(o, "response").unwrap_or_default());
        if o.get("done").and_then(|d| d.as_bool()) == Some(true) {
            done = true;
            call.stop_reason = s(o, "done_reason");
            call.usage = Some(Usage { input: n(o, "prompt_eval_count"), output: n(o, "eval_count"), ..Default::default() });
        }
    }
    if !thinking.is_empty() {
        call.output.insert(0, Part { kind: "thinking".into(), text: cut(&thinking, &mut call.notes), ..Default::default() });
    }
    if !text.is_empty() {
        call.output.push(text_part(&text, &mut call.notes));
    }
    if !done && call.error.is_none() {
        call.notes.push("the stream did not complete".into());
    }
}

// ------------------------------------------------------------------ prices

/// USD per million tokens.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Price {
    pub input: f64,
    pub output: f64,
    /// Cached input read (default: like input).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_read: Option<f64>,
    /// Input written to the cache (default: like input).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_write: Option<f64>,
}

/// Own prices, in the data folder.
pub const PRICES_FILE: &str = "llm-prices.json";
/// The fetched list, in the data folder.
pub const FETCHED_PRICES_FILE: &str = "llm-prices-litellm.json";
/// LiteLLM's list of model prices (MIT licence), fetched on request only.
pub const LITELLM_PRICES_URL: &str = "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json";

/// The prices a cost is estimated with: own ones first, then a fetched list, then the
/// built-in one.
#[derive(Debug, Clone, Default)]
pub struct PriceList {
    /// `llm-prices.json`, by model name prefix.
    pub custom: BTreeMap<String, Price>,
    /// Why `llm-prices.json` could not be read (its prices are then not used).
    pub custom_error: Option<String>,
    /// The fetched list, by model name.
    pub fetched: BTreeMap<String, Price>,
    /// When the list was fetched (Unix seconds).
    pub fetched_at: Option<i64>,
}

/// The fetched list as kept in the data folder.
#[derive(Serialize, Deserialize)]
struct FetchedPrices {
    source: String,
    fetched: i64,
    prices: BTreeMap<String, Price>,
}

/// What the settings show about the prices.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LlmPricesInfo {
    /// `llm-prices.json` (whether or not it exists).
    pub path: String,
    pub exists: bool,
    pub custom: usize,
    pub custom_error: Option<String>,
    pub fetched: usize,
    pub fetched_at: Option<i64>,
    pub source: String,
    pub built_in: usize,
}

/// LiteLLM's `model_prices_and_context_window.json` (USD per token) as prices per million
/// tokens, by model name without the provider (`azure/gpt-4o` → `gpt-4o`; a provider's own
/// entry wins over a reseller's).
pub fn parse_litellm(json: &[u8]) -> Result<BTreeMap<String, Price>, String> {
    let v: Value = serde_json::from_slice(json).map_err(|e| format!("not a price list: {e}"))?;
    let m = v.as_object().ok_or("not a price list: no JSON object")?;
    let mut out = BTreeMap::new();
    let per_m = |e: &Value, k: &str| e.get(k).and_then(|x| x.as_f64()).filter(|x| x.is_finite() && *x >= 0.0).map(|x| x * 1_000_000.0);
    // Direct entries first, then those under a provider prefix.
    let mut keys: Vec<&String> = m.keys().filter(|k| *k != "sample_spec").collect();
    keys.sort_by_key(|k| k.contains('/'));
    for k in keys {
        let e = &m[k];
        let Some(input) = per_m(e, "input_cost_per_token") else { continue };
        let name = k.rsplit('/').next().unwrap_or(k).trim().to_ascii_lowercase();
        if name.is_empty() || out.contains_key(&name) {
            continue;
        }
        let p = Price {
            input,
            output: per_m(e, "output_cost_per_token").unwrap_or(0.0),
            cache_read: per_m(e, "cache_read_input_token_cost"),
            cache_write: per_m(e, "cache_creation_input_token_cost"),
        };
        out.insert(name, p);
    }
    if out.is_empty() {
        return Err("the list holds no prices".into());
    }
    Ok(out)
}

/// List prices (USD per 1M tokens) as published by the providers in 2025, by model name
/// prefix (the longest prefix wins). They change; `llm-prices.json` in the data folder
/// adds or overrides entries.
const PRICES: &[(&str, f64, f64, f64)] = &[
    // OpenAI (input, output, cached input)
    ("gpt-4o-mini", 0.15, 0.60, 0.075),
    ("gpt-4o", 2.50, 10.0, 1.25),
    ("gpt-4.1-nano", 0.10, 0.40, 0.025),
    ("gpt-4.1-mini", 0.40, 1.60, 0.10),
    ("gpt-4.1", 2.0, 8.0, 0.50),
    ("gpt-5-nano", 0.05, 0.40, 0.005),
    ("gpt-5-mini", 0.25, 2.0, 0.025),
    ("gpt-5", 1.25, 10.0, 0.125),
    ("gpt-5.1", 1.25, 10.0, 0.125),
    ("gpt-5-pro", 15.0, 120.0, 15.0),
    ("o3-pro", 20.0, 80.0, 20.0),
    ("o1-pro", 150.0, 600.0, 150.0),
    ("o4-mini", 1.10, 4.40, 0.275),
    ("o3-mini", 1.10, 4.40, 0.55),
    ("o3", 2.0, 8.0, 0.50),
    ("o1-mini", 1.10, 4.40, 0.55),
    ("o1", 15.0, 60.0, 7.50),
    ("text-embedding-3-small", 0.02, 0.0, 0.02),
    ("text-embedding-3-large", 0.13, 0.0, 0.13),
    // Anthropic (cache read 10 % of input; cache write 125 %)
    ("claude-opus-4", 15.0, 75.0, 1.50),
    ("claude-opus-4-1", 15.0, 75.0, 1.50),
    ("claude-opus-4-5", 5.0, 25.0, 0.50),
    ("claude-sonnet-4-5", 3.0, 15.0, 0.30),
    ("claude-sonnet-4", 3.0, 15.0, 0.30),
    ("claude-3-7-sonnet", 3.0, 15.0, 0.30),
    ("claude-3-5-sonnet", 3.0, 15.0, 0.30),
    ("claude-3-5-haiku", 0.80, 4.0, 0.08),
    ("claude-haiku-4-5", 1.0, 5.0, 0.10),
    ("claude-3-haiku", 0.25, 1.25, 0.03),
    // Google
    ("gemini-2.5-pro", 1.25, 10.0, 0.31),
    ("gemini-2.5-flash-lite", 0.10, 0.40, 0.025),
    ("gemini-2.5-flash", 0.30, 2.50, 0.075),
    ("gemini-2.0-flash-lite", 0.075, 0.30, 0.075),
    ("gemini-2.0-flash", 0.10, 0.40, 0.025),
    // Others
    ("mistral-large", 2.0, 6.0, 2.0),
    ("mistral-small", 0.10, 0.30, 0.10),
    ("deepseek-chat", 0.27, 1.10, 0.07),
    ("deepseek-reasoner", 0.55, 2.19, 0.14),
];

/// Whether what follows a name in the price list still names that model: nothing, a date or
/// a release tag (`-20250514`, `-2024-08-06`, `-latest`, `-preview-05-20`, `@20240620`), not
/// another model (`-5` of `claude-opus-4-5`, `-pro` of `o3-pro`, `.1` of `gpt-5.1`).
fn same_model(rest: &str) -> bool {
    let Some(tail) = rest.strip_prefix(['-', '@', ':']) else { return rest.is_empty() };
    let first = tail.split(['-', '@', ':']).next().unwrap_or("");
    (first.len() >= 4 && first.chars().all(|c| c.is_ascii_digit())) || matches!(first, "latest" | "preview" | "exp" | "experimental")
}

/// The price for `model`: from `llm-prices.json` (its own longest prefix), else from the
/// fetched list, else built in (both: that model, with a date or release tag at most).
pub fn price_of(model: &str, prices: &PriceList) -> Option<(String, Price)> {
    let m = model.rsplit('/').next().unwrap_or(model).to_ascii_lowercase();
    if let Some((k, p)) = prices.custom.iter().filter(|(k, _)| m.starts_with(&k.to_ascii_lowercase())).max_by_key(|(k, _)| k.len()) {
        return Some((format!("{k} ({PRICES_FILE})"), *p));
    }
    if let Some((k, p)) = prices.fetched.iter().filter(|(k, _)| m.strip_prefix(k.as_str()).is_some_and(same_model)).max_by_key(|(k, _)| k.len()) {
        let when = prices.fetched_at.map(|t| format!(", fetched {}", quena_tls::date(t))).unwrap_or_default();
        return Some((format!("{k} (LiteLLM price list{when})"), *p));
    }
    PRICES.iter().filter(|(k, ..)| m.strip_prefix(k).is_some_and(same_model)).max_by_key(|(k, ..)| k.len()).map(|(k, i, o, c)| {
        let write = if k.starts_with("claude") { Some(i * 1.25) } else { None };
        (format!("{k} (built-in list prices, 2025)"), Price { input: *i, output: *o, cache_read: Some(*c), cache_write: write })
    })
}

/// Estimated cost of `u` at `p`.
pub fn cost_of(u: &Usage, p: &Price) -> f64 {
    let fresh = u.input.saturating_sub(u.cache_read.saturating_add(u.cache_write)) as f64;
    (fresh * p.input + u.cache_read as f64 * p.cache_read.unwrap_or(p.input) + u.cache_write as f64 * p.cache_write.unwrap_or(p.input) + u.output as f64 * p.output) / 1_000_000.0
}

// ------------------------------------------------------------------ parsing

/// Read a call from its URL, request body and response (`None`: not an LLM API call).
pub fn parse(method: &str, url: &str, request: &[u8], response: Option<(&[u8], &str)>, prices: &PriceList) -> Option<LlmCall> {
    let api = api_of(method, url)?;
    let req: Value = serde_json::from_slice(request).ok()?;
    // What a call to that API carries (`/api/chat` or `/responses` of another app does not).
    let carries = |keys: &[&str]| keys.iter().any(|k| req.get(k).is_some());
    let fits = match api {
        Api::Chat | Api::Messages | Api::OllamaChat => carries(&["messages"]),
        Api::Responses => carries(&["input", "prompt", "previous_response_id"]),
        Api::Gemini => carries(&["contents"]),
        Api::OllamaGenerate => carries(&["prompt"]) && carries(&["model"]),
        Api::Embeddings => carries(&["input", "content", "requests"]),
    };
    if !req.is_object() || !fits {
        return None;
    }
    let host = host_of(url);
    let path = path_of(url);
    // Gemini and Azure name the model in the path.
    let path_model = if api == Api::Gemini || path.contains(":embedContent") {
        path.split("/models/").nth(1).map(|m| m.split(':').next().unwrap_or(m).to_string())
    } else {
        path.split("/deployments/").nth(1).map(|m| m.split('/').next().unwrap_or(m).to_string())
    };
    let mut call = LlmCall {
        provider: provider_of(&host, api),
        api,
        model: s(&req, "model").or(path_model).unwrap_or_default(),
        stream: req.get("stream").and_then(|x| x.as_bool()).unwrap_or(api == Api::OllamaChat || api == Api::OllamaGenerate) || path.contains(":streamGenerateContent"),
        system: vec![],
        messages: vec![],
        tools: vec![],
        params: vec![],
        output: vec![],
        stop_reason: None,
        usage: None,
        cost: None,
        error: None,
        notes: vec![],
    };
    match api {
        Api::Chat => chat_request(&req, &mut call),
        Api::Responses => responses_request(&req, &mut call),
        Api::Messages => anthropic_request(&req, &mut call),
        Api::Gemini => gemini_request(&req, &mut call),
        Api::OllamaChat | Api::OllamaGenerate => ollama_request(&req, &mut call),
        Api::Embeddings => {
            let inputs = match req.get("input").or_else(|| req.get("content")) {
                Some(Value::Array(a)) => a.len(),
                Some(_) => 1,
                None => req.get("requests").and_then(|r| r.as_array()).map(|a| a.len()).unwrap_or(0),
            };
            call.params.push(("inputs".into(), inputs.to_string()));
            call.params.extend(params(&req, &["dimensions", "encoding_format"]));
        }
    }
    if let Some((body, content_type)) = response {
        let text = String::from_utf8_lossy(body);
        let streamed = content_type.contains("event-stream") || content_type.contains("ndjson") || content_type.contains("x-ndjson");
        let json: Option<Value> = if streamed { None } else { serde_json::from_str(&text).ok() };
        if let Some(e) = json.as_ref().and_then(error_of) {
            call.error = Some(e);
        }
        match (api, &json) {
            (Api::Chat, Some(v)) => chat_response(v, &mut call),
            (Api::Chat, None) => chat_stream(&stream_objects(&text), &mut call),
            (Api::Responses, Some(v)) => responses_response(v, &mut call),
            (Api::Responses, None) => responses_stream(&text, &mut call),
            (Api::Messages, Some(v)) => anthropic_response(v, &mut call),
            (Api::Messages, None) => anthropic_stream(&text, &mut call),
            (Api::Gemini, Some(Value::Array(a))) => gemini_response(a, &mut call),
            (Api::Gemini, Some(v)) => gemini_response(std::slice::from_ref(v), &mut call),
            (Api::Gemini, None) => gemini_response(&stream_objects(&text), &mut call),
            (Api::OllamaChat | Api::OllamaGenerate, Some(v)) => ollama_response(std::slice::from_ref(v), &mut call),
            (Api::OllamaChat | Api::OllamaGenerate, None) => ollama_response(&stream_objects(&text), &mut call),
            (Api::Embeddings, Some(v)) => {
                if let Some(u) = v.get("usage") {
                    call.usage = Some(Usage { input: n(u, "prompt_tokens").max(n(u, "total_tokens")), ..Default::default() });
                } else if let Some(c) = v.get("prompt_eval_count").and_then(|c| c.as_u64()) {
                    call.usage = Some(Usage { input: c, ..Default::default() });
                }
            }
            (Api::Embeddings, None) => {}
        }
        if call.model.is_empty() {
            call.model = json.as_ref().and_then(|v| s(v, "model")).unwrap_or_default();
        }
    }
    if let Some(u) = &call.usage
        && let Some((name, p)) = price_of(&call.model, prices)
    {
        call.cost = Some(Cost { usd: cost_of(u, &p), price: name });
    }
    if let Some(e) = &prices.custom_error {
        call.notes.push(format!("{PRICES_FILE} cannot be read, its prices are not used: {e}"));
    }
    Some(call)
}

/// The flags of a recognised call: model, tokens, usage, cost.
pub fn flags_of(c: &LlmCall) -> Vec<(String, String)> {
    let mut f = vec![(LLM_FLAG.to_string(), format!("{}/{}", c.provider, if c.model.is_empty() { "?" } else { &c.model }))];
    if let Some(u) = &c.usage {
        f.push((LLM_TOKENS_FLAG.into(), u.total().to_string()));
        let mut usage = format!("in {} · out {}", u.input, u.output);
        if u.cache_read > 0 {
            usage.push_str(&format!(" · cache read {}", u.cache_read));
        }
        if u.cache_write > 0 {
            usage.push_str(&format!(" · cache write {}", u.cache_write));
        }
        if u.reasoning > 0 {
            usage.push_str(&format!(" · reasoning {}", u.reasoning));
        }
        f.push((LLM_USAGE_FLAG.into(), usage));
    }
    if let Some(c) = &c.cost {
        f.push((LLM_COST_FLAG.into(), format!("{:.6}", c.usd)));
    }
    f
}

impl AppCore {
    /// The prices: own ones from `llm-prices.json` in the data folder (`{"model-prefix":
    /// {"input": …, "output": …, "cacheRead": …, "cacheWrite": …}}`, USD per million tokens),
    /// the fetched list, the built-in one. Read again when a file changes.
    pub fn llm_prices(&self) -> Arc<PriceList> {
        let (own, fetched) = (self.paths.data.join(PRICES_FILE), self.paths.data.join(FETCHED_PRICES_FILE));
        let stamp = |p: &std::path::Path| std::fs::metadata(p).ok().map(|m| (m.modified().ok(), m.len()));
        let now = (stamp(&own), stamp(&fetched));
        let mut cache = self.llm_prices.lock();
        if let Some((s, list)) = cache.as_ref()
            && *s == now
        {
            return list.clone();
        }
        let mut list = PriceList::default();
        match std::fs::read(&own) {
            Ok(b) => match serde_json::from_slice::<BTreeMap<String, Price>>(&b) {
                Ok(m) => list.custom = m,
                Err(e) => {
                    tracing::warn!(target: "quena", "{} cannot be read, its prices are not used: {e}", own.display());
                    list.custom_error = Some(e.to_string());
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => list.custom_error = Some(e.to_string()),
        }
        if let Ok(f) = std::fs::read(&fetched).map_err(|_| ()).and_then(|b| serde_json::from_slice::<FetchedPrices>(&b).map_err(|_| ())) {
            list.fetched = f.prices;
            list.fetched_at = Some(f.fetched);
        }
        let list = Arc::new(list);
        *cache = Some((now, list.clone()));
        list
    }

    /// The state of the price lists (for the settings).
    pub fn llm_prices_info(&self) -> LlmPricesInfo {
        let p = self.llm_prices();
        let path = self.paths.data.join(PRICES_FILE);
        LlmPricesInfo {
            exists: path.exists(),
            path: path.display().to_string(),
            custom: p.custom.len(),
            custom_error: p.custom_error.clone(),
            fetched: p.fetched.len(),
            fetched_at: p.fetched_at,
            source: LITELLM_PRICES_URL.to_string(),
            built_in: PRICES.len(),
        }
    }

    /// Fetch LiteLLM's price list (only when asked: it leaves the machine) through the proxy
    /// engine's connector, and keep it in the data folder.
    pub fn llm_prices_update(&self) -> anyhow::Result<LlmPricesInfo> {
        self.llm_prices_update_from(LITELLM_PRICES_URL)
    }

    /// [`AppCore::llm_prices_update`] from another address (a mirror, or a test server).
    pub fn llm_prices_update_from(&self, url: &str) -> anyhow::Result<LlmPricesInfo> {
        let engine = self.proxy_engine()?;
        let shared = engine.proxy.shared.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let u = url.to_string();
        engine.proxy.runtime().handle().spawn(async move {
            let _ = tx.send(quena_proxy::fetch::get(&shared, &u, 32 << 20, std::time::Duration::from_secs(60)).await);
        });
        let body = rx.recv_timeout(std::time::Duration::from_secs(65)).map_err(|_| anyhow::anyhow!("no answer"))?.map_err(|e| anyhow::anyhow!("{url}: {e}"))?;
        let prices = parse_litellm(&body).map_err(|e| anyhow::anyhow!("{url}: {e}"))?;
        let f = FetchedPrices { source: url.into(), fetched: time::OffsetDateTime::now_utc().unix_timestamp(), prices };
        let path = self.paths.data.join(FETCHED_PRICES_FILE);
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(&f)?)?;
        std::fs::rename(&tmp, &path)?;
        tracing::info!(target: "quena", "fetched {} LLM prices from {url}", f.prices.len());
        Ok(self.llm_prices_info())
    }

    /// Remove the fetched list (back to own and built-in prices).
    pub fn llm_prices_forget(&self) -> anyhow::Result<LlmPricesInfo> {
        match std::fs::remove_file(self.paths.data.join(FETCHED_PRICES_FILE)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
        Ok(self.llm_prices_info())
    }

    /// A session as an LLM call (`None`: it is not one).
    pub fn llm(&self, id: SessionId) -> Option<LlmCall> {
        let cap = self.capture();
        let d = cap.detail(id)?;
        api_of(&d.request.method, &d.request.url)?;
        let (req, resp) = cap.bodies_of(id)?;
        let request = quena_body::text::decoded_prefix(&req, &crate::dto::spec_of(&d.request.headers), MAX_BODY);
        let response = d.response.as_ref().map(|r| (quena_body::text::decoded_prefix(&resp, &crate::dto::spec_of(&r.headers), MAX_BODY), r.headers.get("content-type").unwrap_or("").to_ascii_lowercase()));
        parse(&d.request.method, &d.request.url, &request, response.as_ref().map(|(b, ct)| (b.as_slice(), ct.as_str())), &self.llm_prices())
    }

    /// Mark a finished session that is an LLM call with its model, tokens and cost, later on
    /// a worker thread (a full queue drops it: marks are a help, not a record).
    pub(crate) fn llm_mark_later(self: &Arc<Self>, id: SessionId) {
        static QUEUE: std::sync::OnceLock<Option<std::sync::mpsc::SyncSender<(std::sync::Weak<AppCore>, u64, SessionId)>>> = std::sync::OnceLock::new();
        let queue = QUEUE.get_or_init(|| {
            let (tx, rx) = std::sync::mpsc::sync_channel::<(std::sync::Weak<AppCore>, u64, SessionId)>(1024);
            let worker = std::thread::Builder::new().name("quena-llm".into()).spawn(move || {
                for (core, numbering, id) in rx {
                    if let Some(core) = core.upgrade() {
                        core.llm_mark(numbering, id);
                    }
                }
            });
            worker.ok().map(|_| tx)
        });
        if let Some(q) = queue {
            let _ = q.try_send((Arc::downgrade(self), self.capture().numbering(), id));
        }
    }

    /// Mark session `id` (of numbering `numbering`) if it is an LLM call.
    pub fn llm_mark(&self, numbering: u64, id: SessionId) {
        let cap = self.capture();
        // Numbering restarted meanwhile: `id` is another session now.
        if cap.numbering() != numbering {
            return;
        }
        let Some(call) = self.llm(id) else { return };
        let mut flags = flags_of(&call);
        // Answered from the agent cache: nothing was spent, so no tokens or cost to add up.
        let hit = cap.detail(id).is_some_and(|d| d.extra_flags.iter().any(|(k, _)| k == crate::llm_cache::CACHE_FLAG));
        if hit {
            flags.retain(|(k, _)| k != LLM_TOKENS_FLAG && k != LLM_COST_FLAG);
        }
        let set = |d: &mut SessionDetail| {
            d.extra_flags.retain(|(k, _)| !k.starts_with(LLM_FLAG));
            d.extra_flags.extend(flags.iter().cloned());
        };
        // Still being written (bodies pending): change the live session, it persists itself.
        if let Some(live) = cap.live(id) {
            live.update(set);
        } else if !cap.update_detail(id, set) {
            // Removed meanwhile.
            return;
        }
        if !hit {
            self.llm_cache_auto(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(url: &str, req: &str, resp: &str, ct: &str) -> LlmCall {
        parse("POST", url, req.as_bytes(), Some((resp.as_bytes(), ct)), &PriceList::default()).expect("an LLM call")
    }
    fn texts(p: &[Part], kind: &str) -> Vec<String> {
        p.iter().filter(|x| x.kind == kind).map(|x| x.text.clone()).collect()
    }

    #[test]
    fn litellm_list_and_its_order() {
        let json = br#"{
            "sample_spec": {"input_cost_per_token": 1},
            "azure/gpt-9": {"input_cost_per_token": 9e-6, "output_cost_per_token": 9e-5},
            "gpt-9": {"input_cost_per_token": 2e-6, "output_cost_per_token": 8e-6, "cache_read_input_token_cost": 5e-7},
            "claude-opus-4-7": {"input_cost_per_token": 5e-6, "output_cost_per_token": 2.5e-5, "cache_creation_input_token_cost": 6.25e-6},
            "dall-e-3": {"output_cost_per_image": 0.04}
        }"#;
        let fetched = parse_litellm(json).unwrap();
        assert_eq!(fetched.keys().collect::<Vec<_>>(), ["claude-opus-4-7", "gpt-9"], "no sample, no image model");
        assert!((fetched["gpt-9"].input - 2.0).abs() < 1e-9, "the provider's own entry wins over azure/");
        assert!((fetched["gpt-9"].cache_read.unwrap() - 0.5).abs() < 1e-9);
        assert!(parse_litellm(b"[]").is_err() && parse_litellm(b"{}").is_err());
        let mut l = PriceList { fetched, fetched_at: Some(1_760_000_000), ..Default::default() };
        let name = |m: &str, l: &PriceList| price_of(m, l).map(|(k, _)| k);
        assert!(name("claude-opus-4-7-20261001", &l).unwrap().starts_with("claude-opus-4-7 (LiteLLM price list, fetched 2025-10-09"));
        assert!(name("gpt-4o", &l).unwrap().contains("built-in"), "built-in for what the list lacks");
        l.custom.insert("gpt-9".into(), Price { input: 1.0, output: 1.0, cache_read: None, cache_write: None });
        assert!(name("gpt-9", &l).unwrap().contains("llm-prices.json"), "own prices first");
    }

    #[test]
    fn prices_only_for_the_model_named() {
        let p = |m: &str| price_of(m, &PriceList::default()).map(|(k, _)| k.split(' ').next().unwrap_or("").to_string());
        assert_eq!(p("claude-opus-4-20250514").as_deref(), Some("claude-opus-4"));
        assert_eq!(p("claude-opus-4-5-20251101").as_deref(), Some("claude-opus-4-5"));
        assert_eq!(p("gpt-4o-2024-08-06").as_deref(), Some("gpt-4o"));
        assert_eq!(p("openai/gpt-4o-mini").as_deref(), Some("gpt-4o-mini"));
        assert_eq!(p("gemini-2.5-flash-preview-05-20").as_deref(), Some("gemini-2.5-flash"));
        assert_eq!(p("mistral-large-latest").as_deref(), Some("mistral-large"));
        assert_eq!(p("claude-opus-4-7"), None, "a newer model has no price yet");
        assert_eq!(p("gpt-5.2"), None);
        assert_eq!(p("o3-deep-research"), None);
    }

    #[test]
    fn recognises_apis_by_url() {
        assert_eq!(api_of("POST", "https://api.openai.com/v1/chat/completions"), Some(Api::Chat));
        assert_eq!(api_of("POST", "https://x.openai.azure.com/openai/deployments/gpt4o/chat/completions?api-version=2024-10-21"), Some(Api::Chat));
        assert_eq!(api_of("POST", "https://api.openai.com/v1/responses"), Some(Api::Responses));
        assert_eq!(api_of("POST", "https://api.anthropic.com/v1/messages"), Some(Api::Messages));
        assert_eq!(api_of("POST", "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse"), Some(Api::Gemini));
        assert_eq!(api_of("POST", "http://localhost:11434/api/chat"), Some(Api::OllamaChat));
        assert_eq!(api_of("POST", "https://api.openai.com/v1/embeddings"), Some(Api::Embeddings));
        assert_eq!(api_of("GET", "https://api.openai.com/v1/chat/completions"), None);
        // Another app's endpoint with such a path: not an LLM call.
        assert!(parse("POST", "https://shop.example.com/api/chat", br#"{"text":"hi","room":1}"#, None, &PriceList::default()).is_none());
        assert!(parse("POST", "https://app.example.com/v2/responses", br#"{"answers":[1]}"#, None, &PriceList::default()).is_none());
        assert_eq!(api_of("POST", "https://example.com/v1/users"), None);
        assert!(parse("POST", "https://api.openai.com/v1/chat/completions", b"not json", None, &PriceList::default()).is_none());
    }

    #[test]
    fn openai_chat_with_tools_and_cost() {
        let req = r#"{"model":"gpt-4o-mini","temperature":0.2,"messages":[{"role":"system","content":"Be brief."},{"role":"user","content":[{"type":"text","text":"Weather in Bonn?"},{"type":"image_url","image_url":{"url":"data:..."}}]},{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"weather","arguments":"{\"city\":\"Bonn\"}"}}]},{"role":"tool","tool_call_id":"call_1","content":"12 °C"}],"tools":[{"type":"function","function":{"name":"weather","description":"Current weather"}}]}"#;
        let resp = r#"{"id":"x","model":"gpt-4o-mini-2024-07-18","choices":[{"index":0,"message":{"role":"assistant","content":"12 °C and cloudy."},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":200,"total_tokens":1200,"prompt_tokens_details":{"cached_tokens":400}}}"#;
        let c = call("https://api.openai.com/v1/chat/completions", req, resp, "application/json");
        assert_eq!((c.provider.as_str(), c.model.as_str(), c.api), ("OpenAI", "gpt-4o-mini", Api::Chat));
        assert_eq!(c.system, vec!["Be brief."]);
        assert_eq!(c.messages.len(), 3);
        assert_eq!(c.messages[0].parts[1].kind, "image");
        assert_eq!(c.messages[1].parts[0].name.as_deref(), Some("weather"));
        assert!(c.messages[1].parts[0].text.contains("\"city\": \"Bonn\""));
        assert_eq!((c.messages[2].parts[0].kind.as_str(), c.messages[2].parts[0].id.as_deref()), ("toolResult", Some("call_1")));
        assert_eq!(c.tools[0].name, "weather");
        assert_eq!(texts(&c.output, "text"), vec!["12 °C and cloudy."]);
        assert_eq!(c.stop_reason.as_deref(), Some("stop"));
        assert_eq!(c.usage, Some(Usage { input: 1000, output: 200, cache_read: 400, cache_write: 0, reasoning: 0 }));
        // 600 × 0.15 + 400 × 0.075 + 200 × 0.60 per million.
        let cost = c.cost.clone().unwrap();
        assert!((cost.usd - 0.00024).abs() < 1e-9, "{}", cost.usd);
        assert!(cost.price.starts_with("gpt-4o-mini"));
        let f = flags_of(&c);
        assert_eq!(f[0], (LLM_FLAG.to_string(), "OpenAI/gpt-4o-mini".to_string()));
        assert_eq!(f[1].1, "1200");
    }

    #[test]
    fn openai_chat_stream_with_tool_call_deltas() {
        let req = r#"{"model":"gpt-4.1","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"hi"}]}"#;
        let resp = concat!(
            "data: {\"model\":\"gpt-4.1\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hel\"}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",\"function\":{\"name\":\"f\",\"arguments\":\"{\\\"a\\\":\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"1}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":7}}\n\n",
            "data: [DONE]\n\n"
        );
        let c = call("https://api.openai.com/v1/chat/completions", req, resp, "text/event-stream; charset=utf-8");
        assert!(c.stream);
        assert_eq!(texts(&c.output, "text"), vec!["Hello"]);
        let tc = c.output.iter().find(|p| p.kind == "toolCall").unwrap();
        assert_eq!((tc.name.as_deref(), tc.id.as_deref()), (Some("f"), Some("c1")));
        assert!(tc.text.contains("\"a\": 1"));
        assert_eq!(c.stop_reason.as_deref(), Some("tool_calls"));
        assert_eq!(c.usage.unwrap().total(), 12);
    }

    #[test]
    fn openai_responses_json_and_stream() {
        let req = r#"{"model":"gpt-5","instructions":"You are terse.","input":[{"role":"user","content":[{"type":"input_text","text":"2+2?"}]}],"reasoning":{"effort":"low"}}"#;
        let resp = r#"{"model":"gpt-5-2025-08-07","status":"completed","output":[{"type":"reasoning","summary":[]},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"4"}]}],"usage":{"input_tokens":20,"output_tokens":30,"output_tokens_details":{"reasoning_tokens":25}}}"#;
        let c = call("https://api.openai.com/v1/responses", req, resp, "application/json");
        assert_eq!(c.system, vec!["You are terse."]);
        assert_eq!(c.messages[0].parts[0].text, "2+2?");
        assert_eq!(texts(&c.output, "text"), vec!["4"]);
        assert_eq!(c.usage.unwrap().reasoning, 25);
        assert!(c.params.contains(&("reasoning.effort".into(), "low".into())));
        let stream = format!("event: response.output_text.delta\ndata: {{\"type\":\"response.output_text.delta\",\"delta\":\"4\"}}\n\nevent: response.completed\ndata: {{\"type\":\"response.completed\",\"response\":{resp}}}\n\n");
        let s = call("https://api.openai.com/v1/responses", req, &stream, "text/event-stream");
        assert_eq!(texts(&s.output, "text"), vec!["4"]);
        assert_eq!(s.usage, c.usage);
    }

    #[test]
    fn anthropic_json_and_stream_with_tool_use_and_cache() {
        let req = r#"{"model":"claude-sonnet-4-20250514","max_tokens":1024,"system":[{"type":"text","text":"You help.","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"Weather?"},{"role":"assistant","content":[{"type":"tool_use","id":"tu1","name":"weather","input":{"city":"Bonn"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"tu1","content":[{"type":"text","text":"12 °C"}]}]}],"tools":[{"name":"weather","description":"Weather now","input_schema":{}}]}"#;
        let resp = r#"{"id":"m","type":"message","model":"claude-sonnet-4-20250514","content":[{"type":"text","text":"It is 12 °C."}],"stop_reason":"end_turn","usage":{"input_tokens":100,"cache_read_input_tokens":2000,"cache_creation_input_tokens":0,"output_tokens":50}}"#;
        let c = call("https://api.anthropic.com/v1/messages", req, resp, "application/json");
        assert_eq!(c.provider, "Anthropic");
        assert_eq!(c.system, vec!["You help."]);
        assert_eq!(c.messages[1].parts[0].kind, "toolCall");
        assert_eq!(c.messages[2].parts[0].text, "12 °C");
        assert_eq!(c.usage, Some(Usage { input: 2100, output: 50, cache_read: 2000, cache_write: 0, reasoning: 0 }));
        // 100 × 3 + 2000 × 0.30 + 50 × 15 per million.
        assert!((c.cost.as_ref().unwrap().usd - 0.00165).abs() < 1e-9, "{:?}", c.cost);
        let stream = concat!(
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-4-20250514\",\"usage\":{\"input_tokens\":10,\"cache_read_input_tokens\":0,\"output_tokens\":1}}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"Hmm.\"}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"Let me \"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"check.\"}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"tool_use\",\"id\":\"tu2\",\"name\":\"weather\",\"input\":{}}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"city\\\": \\\"Bo\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"nn\\\"}\"}}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":42}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
        );
        let s = call("https://api.anthropic.com/v1/messages", &req.replace("\"max_tokens\"", "\"stream\":true,\"max_tokens\""), stream, "text/event-stream");
        assert_eq!(texts(&s.output, "thinking"), vec!["Hmm."]);
        assert_eq!(texts(&s.output, "text"), vec!["Let me check."]);
        assert!(s.output[2].text.contains("\"city\": \"Bonn\""), "{:?}", s.output);
        assert_eq!(s.stop_reason.as_deref(), Some("tool_use"));
        assert_eq!(s.usage.map(|u| (u.input, u.output)), Some((10, 42)));
        assert!(s.notes.is_empty(), "{:?}", s.notes);
        // A cut-off stream says so.
        let cut = call("https://api.anthropic.com/v1/messages", req, &stream[..stream.find("event: message_delta").unwrap()], "text/event-stream");
        assert!(cut.notes.iter().any(|n| n.contains("did not complete")));
    }

    #[test]
    fn gemini_stream_and_errors() {
        let req = r#"{"systemInstruction":{"parts":[{"text":"Answer in German."}]},"contents":[{"role":"user","parts":[{"text":"Hi"}]}],"generationConfig":{"temperature":0.5,"maxOutputTokens":100}}"#;
        let resp = concat!(
            "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Hal\"}]}}],\"modelVersion\":\"gemini-2.5-flash\"}\r\n\r\n",
            "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"lo!\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":8,\"candidatesTokenCount\":3,\"thoughtsTokenCount\":4,\"totalTokenCount\":15}}\r\n\r\n"
        );
        let c = call("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse", req, resp, "text/event-stream");
        assert_eq!((c.provider.as_str(), c.model.as_str()), ("Google Gemini", "gemini-2.5-flash"));
        assert!(c.stream);
        assert_eq!(c.system, vec!["Answer in German."]);
        assert_eq!(texts(&c.output, "text"), vec!["Hallo!"]);
        assert_eq!(c.usage.map(|u| (u.input, u.output, u.reasoning)), Some((8, 7, 4)));
        assert!(c.params.contains(&("maxOutputTokens".into(), "100".into())));
        // Without alt=sse the stream is one JSON array.
        let arr = r#"[{"candidates":[{"content":{"parts":[{"text":"A"}]}}]},{"candidates":[{"content":{"parts":[{"text":"B"}]},"finishReason":"STOP"}]}]"#;
        let a = call("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:streamGenerateContent", req, arr, "application/json");
        assert_eq!(texts(&a.output, "text"), vec!["AB"]);
        let e = call("https://generativelanguage.googleapis.com/v1beta/models/x:generateContent", req, r#"{"error":{"code":429,"message":"Quota exceeded","status":"RESOURCE_EXHAUSTED"}}"#, "application/json");
        assert_eq!(e.error.as_deref(), Some("RESOURCE_EXHAUSTED: Quota exceeded"));
    }

    #[test]
    fn ollama_lines_and_custom_prices() {
        let req = r#"{"model":"llama3.2","messages":[{"role":"user","content":"Hi"}]}"#;
        let resp = "{\"model\":\"llama3.2\",\"message\":{\"role\":\"assistant\",\"content\":\"Hel\"},\"done\":false}\n{\"model\":\"llama3.2\",\"message\":{\"role\":\"assistant\",\"content\":\"lo\"},\"done\":false}\n{\"model\":\"llama3.2\",\"message\":{\"role\":\"assistant\",\"content\":\"\"},\"done\":true,\"done_reason\":\"stop\",\"prompt_eval_count\":26,\"eval_count\":12}\n";
        let c = call("http://127.0.0.1:11434/api/chat", req, resp, "application/x-ndjson");
        assert_eq!(c.provider, "Ollama");
        assert!(c.stream, "Ollama streams unless told not to");
        assert_eq!(texts(&c.output, "text"), vec!["Hello"]);
        assert_eq!(c.usage.map(|u| u.total()), Some(38));
        assert!(c.cost.is_none(), "no price for local models");
        let mut prices = PriceList::default();
        prices.custom.insert("llama3".to_string(), Price { input: 1.0, output: 2.0, cache_read: None, cache_write: None });
        let p = parse("POST", "http://127.0.0.1:11434/api/chat", req.as_bytes(), Some((resp.as_bytes(), "application/x-ndjson")), &prices).unwrap();
        assert!((p.cost.unwrap().usd - (26.0 + 24.0) / 1e6).abs() < 1e-12);
        let g = call("http://127.0.0.1:11434/api/generate", r#"{"model":"llama3.2","prompt":"Why?","system":"Short.","stream":false}"#, r#"{"model":"llama3.2","response":"Because.","done":true,"prompt_eval_count":3,"eval_count":2}"#, "application/json");
        assert_eq!(g.system, vec!["Short."]);
        assert_eq!(texts(&g.output, "text"), vec!["Because."]);
    }

    #[test]
    fn embeddings_and_long_texts() {
        let e = call("https://api.openai.com/v1/embeddings", r#"{"model":"text-embedding-3-small","input":["a","b","c"]}"#, r#"{"data":[],"usage":{"prompt_tokens":9,"total_tokens":9}}"#, "application/json");
        assert_eq!(e.api, Api::Embeddings);
        assert!(e.params.contains(&("inputs".into(), "3".into())));
        assert_eq!(e.usage.unwrap().input, 9);
        let long = "x".repeat(MAX_TEXT + 10);
        let c = call("https://api.openai.com/v1/chat/completions", &format!(r#"{{"model":"m","messages":[{{"role":"user","content":"{long}"}}]}}"#), "{}", "application/json");
        assert!(c.messages[0].parts[0].text.len() < MAX_TEXT + 100);
        assert!(!c.notes.is_empty());
    }
}
