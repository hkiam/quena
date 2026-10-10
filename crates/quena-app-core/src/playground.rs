//! Prompt playground: send an LLM call again with changes — another system prompt, fewer
//! tools, another model, another output limit — and compare answer and tokens with the
//! original. The variant goes to the same API with the original request's headers (and so
//! its credentials); it is sent only when asked for and costs tokens like any call.

use crate::AppCore;
use anyhow::{Result, anyhow, bail};
use quena_model::{SessionDetail, SessionId};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

/// What to change.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Variant {
    /// The whole system prompt (`None`: as it was; empty: none).
    #[serde(default)]
    pub system: Option<String>,
    /// Tools to leave out (names; `*` at the end for a prefix).
    #[serde(default)]
    pub drop_tools: Vec<String>,
    #[serde(default)]
    pub model: Option<String>,
    /// The output limit (`max_tokens`, `max_output_tokens`, …).
    #[serde(default)]
    pub max_tokens: Option<u64>,
}

/// Replace the system prompt of an LLM request body (Anthropic, OpenAI Chat / Responses,
/// Gemini); empty text removes it.
fn set_system(v: &mut Value, text: &str) {
    let Some(obj) = v.as_object_mut() else { return };
    if obj.contains_key("instructions") || obj.contains_key("input") {
        if text.is_empty() {
            obj.remove("instructions");
        } else {
            obj.insert("instructions".into(), Value::String(text.into()));
        }
        return;
    }
    if obj.contains_key("contents") {
        if text.is_empty() {
            obj.remove("systemInstruction");
            obj.remove("system_instruction");
        } else {
            obj.insert("systemInstruction".into(), serde_json::json!({"parts": [{"text": text}]}));
        }
        return;
    }
    let chat_system = obj.get("messages").and_then(|m| m.as_array()).is_some_and(|m| m.iter().any(|x| matches!(x.get("role").and_then(|r| r.as_str()), Some("system" | "developer"))));
    if obj.contains_key("system") || (!chat_system && obj.contains_key("max_tokens") && !obj.contains_key("max_completion_tokens")) {
        if text.is_empty() {
            obj.remove("system");
        } else {
            obj.insert("system".into(), Value::String(text.into()));
        }
        return;
    }
    if let Some(Value::Array(msgs)) = obj.get_mut("messages") {
        // The leading system messages are the system prompt.
        let lead = msgs.iter().take_while(|m| matches!(m.get("role").and_then(|r| r.as_str()), Some("system" | "developer"))).count();
        msgs.drain(..lead);
        if !text.is_empty() {
            msgs.insert(0, serde_json::json!({"role": "system", "content": text}));
        }
    }
}

/// The request body with the variant's changes.
pub fn variant_body(body: &str, var: &Variant) -> Result<String> {
    let mut v: Value = serde_json::from_str(body).map_err(|e| anyhow!("the request body is not JSON: {e}"))?;
    if !v.is_object() {
        bail!("the request body is not a JSON object");
    }
    if let Some(s) = &var.system {
        set_system(&mut v, s);
    }
    for t in &var.drop_tools {
        crate::rewrite::llm_remove_tool(&mut v, t);
    }
    // No tools left: also no tool choice (the API would refuse it).
    if v.get("tools").and_then(|t| t.as_array()).is_some_and(|t| t.is_empty()) {
        let o = v.as_object_mut().expect("object");
        o.remove("tools");
        o.remove("tool_choice");
    }
    if let Some(m) = var.model.as_ref().filter(|m| !m.trim().is_empty()) {
        v["model"] = Value::String(m.trim().into());
    }
    if let Some(n) = var.max_tokens {
        let o = v.as_object_mut().expect("object");
        let key = ["max_tokens", "max_completion_tokens", "max_output_tokens"].into_iter().find(|k| o.contains_key(*k));
        match (key, o.get_mut("generationConfig")) {
            (Some(k), _) => {
                o.insert(k.into(), n.into());
            }
            (None, Some(g)) => g["maxOutputTokens"] = n.into(),
            (None, None) => {
                o.insert("max_tokens".into(), n.into());
            }
        }
    }
    Ok(serde_json::to_string(&v)?)
}

/// Header lines of the original request for sending it again (length and framing set anew).
fn header_lines(d: &SessionDetail) -> String {
    const SKIP: &[&str] = &["content-length", "transfer-encoding", "content-encoding", "connection", "proxy-connection", "proxy-authorization", "keep-alive", "upgrade", "host"];
    d.request.headers.iter().filter(|(n, _)| !SKIP.contains(&n.to_ascii_lowercase().as_str())).map(|(n, v)| format!("{n}: {v}\n")).collect()
}

impl AppCore {
    /// Send LLM call `id` again with the changes of `var`; returns the new session.
    pub fn llm_variant(self: &Arc<Self>, id: SessionId, var: Variant) -> Result<SessionId> {
        let cap = self.capture();
        let (d, req, _) = cap.bodies_stored(id).ok_or_else(|| anyhow!("session {id} is gone"))?;
        if crate::llm::api_of(&d.request.method, &d.request.url).is_none() {
            bail!("session {id} is not a call to an LLM API");
        }
        let text = quena_body::text::decoded_prefix(&req, &crate::dto::spec_of(&d.request.headers), 32 << 20);
        let body = variant_body(&String::from_utf8_lossy(&text), &var)?;
        let r: crate::compose::ComposeRequest = serde_json::from_value(serde_json::json!({
            "method": d.request.method,
            "url": d.request.url,
            "headers": header_lines(&d),
            "body": body,
        }))?;
        let new = self.compose(r)?;
        let note = format!("Variant of #{id}");
        cap.update_detail(new, |x| {
            if x.summary.comment.is_empty() {
                x.summary.comment = note.clone();
            }
        });
        if let Some(live) = cap.live(new) {
            live.update(|x| {
                if x.summary.comment.is_empty() {
                    x.summary.comment = note;
                }
            });
        }
        Ok(new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(s: &str, v: Variant) -> Value {
        serde_json::from_str(&variant_body(s, &v).unwrap()).unwrap()
    }

    #[test]
    fn variants_change_what_they_say() {
        let anthropic = r#"{"model":"claude-sonnet-4-5","max_tokens":1000,"system":[{"type":"text","text":"long prompt"}],"tools":[{"name":"Read"},{"name":"mcp__jira__x"}],"tool_choice":{"type":"auto"},"messages":[{"role":"user","content":"hi"}]}"#;
        let v = body(anthropic, Variant { system: Some("short".into()), drop_tools: vec!["mcp__jira__*".into()], model: Some("claude-haiku-4-5".into()), max_tokens: Some(200) });
        assert_eq!(v["system"], "short");
        assert_eq!(v["tools"].as_array().unwrap().len(), 1);
        assert_eq!((v["model"].as_str(), v["max_tokens"].as_u64()), (Some("claude-haiku-4-5"), Some(200)));
        let v = body(anthropic, Variant { drop_tools: vec!["*".into()], ..Default::default() });
        assert!(v.get("tools").is_none() && v.get("tool_choice").is_none(), "no tools, no tool choice");
        let chat = r#"{"model":"gpt-4o","messages":[{"role":"system","content":"a"},{"role":"developer","content":"b"},{"role":"user","content":"hi"}]}"#;
        let v = body(chat, Variant { system: Some("new".into()), ..Default::default() });
        assert_eq!(v["messages"].as_array().unwrap().len(), 2);
        assert_eq!(v["messages"][0]["content"], "new");
        let v = body(chat, Variant { system: Some(String::new()), max_tokens: Some(50), ..Default::default() });
        assert_eq!(v["messages"][0]["role"], "user");
        assert_eq!(v["max_tokens"], 50);
        let responses = r#"{"model":"gpt-5","instructions":"x","input":[],"max_output_tokens":10}"#;
        let v = body(responses, Variant { system: Some("y".into()), max_tokens: Some(99), ..Default::default() });
        assert_eq!((v["instructions"].as_str(), v["max_output_tokens"].as_u64()), (Some("y"), Some(99)));
        assert!(variant_body("not json", &Variant::default()).is_err());
    }
}
