//! Prompt playground: send an LLM call again with changes — another system prompt, fewer
//! tools, another model, another output limit — and compare answer and tokens with the
//! original. The variant goes to the same API with the original request's headers (and so
//! its credentials); it is sent only when asked for and costs tokens like any call.

use crate::AppCore;
use crate::llm::Api;
use crate::llm_edit;
use anyhow::{Result, anyhow, bail};
use quena_model::{SessionDetail, SessionId};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

/// The comment of a variant (`Variant of #12`): the proxy leaves such requests alone.
pub const VARIANT_PREFIX: &str = "Variant of #";

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

/// The request body (and, for Gemini, the URL) with the variant's changes, in the format of
/// `api`.
pub fn variant_body(url: &str, api: Api, body: &str, var: &Variant) -> Result<(String, String)> {
    let mut v: Value = serde_json::from_str(body).map_err(|e| anyhow!("the request body is not JSON: {e}"))?;
    if !v.is_object() {
        bail!("the request body is not a JSON object");
    }
    if let Some(s) = &var.system {
        llm_edit::set_system(&mut v, api, s);
    }
    for t in &var.drop_tools {
        llm_edit::remove_tool(&mut v, api, t);
    }
    let mut url = url.to_string();
    if let Some(m) = var.model.as_ref().map(|m| m.trim()).filter(|m| !m.is_empty()) {
        if api == Api::Gemini {
            if let Some(u) = llm_edit::gemini_model_url(&url, m) {
                url = u;
            }
        } else {
            llm_edit::set_model(&mut v, api, m);
        }
    }
    if let Some(n) = var.max_tokens {
        llm_edit::set_max_tokens(&mut v, api, n);
    }
    Ok((url, serde_json::to_string(&v)?))
}

/// Header lines of the original request for sending it again (length and framing set anew).
fn header_lines(d: &SessionDetail) -> String {
    const SKIP: &[&str] = &["content-length", "transfer-encoding", "content-encoding", "connection", "proxy-connection", "proxy-authorization", "keep-alive", "upgrade", "host"];
    d.request.headers.iter().filter(|(n, _)| !n.starts_with(':') && !SKIP.contains(&n.to_ascii_lowercase().as_str())).map(|(n, v)| format!("{n}: {v}\n")).collect()
}

impl AppCore {
    /// Send LLM call `id` again with the changes of `var`; returns the new session.
    pub fn llm_variant(self: &Arc<Self>, id: SessionId, var: Variant) -> Result<SessionId> {
        let cap = self.capture();
        let (d, req, _) = cap.bodies_stored(id).ok_or_else(|| anyhow!("session {id} is gone"))?;
        let api = crate::llm::api_of(&d.request.method, &d.request.url).ok_or_else(|| anyhow!("session {id} is not a call to an LLM API"))?;
        let text = quena_body::text::decoded_prefix(&req, &crate::dto::spec_of(&d.request.headers), 32 << 20);
        let (url, body) = variant_body(&d.request.url, api, &String::from_utf8_lossy(&text), &var)?;
        let r: crate::compose::ComposeRequest = serde_json::from_value(serde_json::json!({
            "method": d.request.method,
            "url": url,
            "headers": header_lines(&d),
            "body": body,
        }))?;
        // Marked from the start: neither the agent cache nor rewrite rules touch a variant.
        self.compose_with_comment(r, format!("{VARIANT_PREFIX}{id}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(api: Api, s: &str, v: Variant) -> Value {
        serde_json::from_str(&variant_body("https://x/v1/x", api, s, &v).unwrap().1).unwrap()
    }

    #[test]
    fn variants_change_what_they_say() {
        let anthropic = r#"{"model":"claude-sonnet-4-5","max_tokens":1000,"system":[{"type":"text","text":"long prompt"}],"tools":[{"name":"Read"},{"name":"mcp__jira__x"}],"tool_choice":{"type":"auto"},"messages":[{"role":"user","content":"hi"}]}"#;
        let v = body(Api::Messages, anthropic, Variant { system: Some("short".into()), drop_tools: vec!["mcp__jira__*".into()], model: Some("claude-haiku-4-5".into()), max_tokens: Some(200) });
        assert_eq!(v["system"], "short");
        assert_eq!(v["tools"].as_array().unwrap().len(), 1);
        assert_eq!((v["model"].as_str(), v["max_tokens"].as_u64()), (Some("claude-haiku-4-5"), Some(200)));
        let v = body(Api::Messages, anthropic, Variant { drop_tools: vec!["*".into()], ..Default::default() });
        assert!(v.get("tools").is_none() && v.get("tool_choice").is_none(), "no tools, no tool choice");
        let chat = r#"{"model":"gpt-4o","max_tokens":10,"messages":[{"role":"system","content":"a"},{"role":"developer","content":"b"},{"role":"user","content":"hi"}]}"#;
        let v = body(Api::Chat, chat, Variant { system: Some("new".into()), ..Default::default() });
        assert_eq!(v["messages"].as_array().unwrap().len(), 2);
        assert_eq!(v["messages"][0]["content"], "new");
        assert!(v.get("system").is_none(), "OpenAI has no top-level system");
        let v = body(Api::Chat, chat, Variant { system: Some(String::new()), max_tokens: Some(50), ..Default::default() });
        assert_eq!(v["messages"][0]["role"], "user");
        assert_eq!(v["max_tokens"], 50);
        let responses = r#"{"model":"gpt-5","instructions":"x","input":[]}"#;
        let v = body(Api::Responses, responses, Variant { system: Some("y".into()), max_tokens: Some(99), ..Default::default() });
        assert_eq!((v["instructions"].as_str(), v["max_output_tokens"].as_u64()), (Some("y"), Some(99)));
        let (url, _) = variant_body("https://g/v1beta/models/gemini-2.5-pro:generateContent", Api::Gemini, r#"{"contents":[]}"#, &Variant { model: Some("gemini-2.5-flash".into()), ..Default::default() }).unwrap();
        assert_eq!(url, "https://g/v1beta/models/gemini-2.5-flash:generateContent", "Gemini names the model in the URL");
        assert!(variant_body("https://x", Api::Chat, "not json", &Variant::default()).is_err());
    }
}
