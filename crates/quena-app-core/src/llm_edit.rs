//! Changes to LLM API requests in the format of their API (known from the URL): the system
//! prompt, the tools offered, the model, the output limit. Used by rewrite rules and the prompt
//! playground. A body of an unknown API is left alone.

use crate::llm::Api;
use serde_json::{Value, json};

/// Tool name matching: exact, or a prefix with `*` at the end.
pub fn tool_matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(p) => name.starts_with(p),
        None => name == pattern,
    }
}

fn name_of(t: &Value) -> Option<&str> {
    t.get("name").or_else(|| t.get("function").and_then(|f| f.get("name"))).and_then(|n| n.as_str())
}

fn is_system_role(m: &Value) -> bool {
    matches!(m.get("role").and_then(|r| r.as_str()), Some("system" | "developer"))
}

/// The key Gemini's system instruction is under (camelCase or snake_case).
fn gemini_si_key(o: &serde_json::Map<String, Value>) -> &'static str {
    if o.contains_key("system_instruction") { "system_instruction" } else { "systemInstruction" }
}

/// Take the tools matching `pattern` out of the offer. A tool choice naming a removed tool, and
/// tools and tool choice when none is left, go too (the APIs refuse them).
pub fn remove_tool(v: &mut Value, api: Api, pattern: &str) -> bool {
    let Some(obj) = v.as_object_mut() else { return false };
    let mut removed: Vec<String> = Vec::new();
    // Bedrock Converse: toolConfig.tools[].toolSpec.
    if api == Api::Converse {
        let Some(Value::Array(tools)) = obj.get_mut("toolConfig").and_then(|c| c.get_mut("tools")) else { return false };
        tools.retain(|t| match t.get("toolSpec").and_then(name_of) {
            Some(n) if tool_matches(pattern, n) => {
                removed.push(n.to_string());
                false
            }
            _ => true,
        });
        let empty = tools.is_empty();
        let choice_named = obj.get("toolConfig").and_then(|c| c.get("toolChoice")).and_then(|c| c.get("tool")).and_then(name_of).is_some_and(|n| removed.iter().any(|r| r == n));
        if empty {
            obj.remove("toolConfig");
        } else if choice_named && let Some(c) = obj.get_mut("toolConfig").and_then(|c| c.as_object_mut()) {
            c.remove("toolChoice");
        }
        return !removed.is_empty();
    }
    if let Some(Value::Array(tools)) = obj.get_mut("tools") {
        tools.retain(|t| match name_of(t) {
            Some(n) if tool_matches(pattern, n) => {
                removed.push(n.to_string());
                false
            }
            _ => true,
        });
        if api == Api::Gemini {
            for t in tools.iter_mut() {
                for key in ["functionDeclarations", "function_declarations"] {
                    if let Some(Value::Array(decls)) = t.get_mut(key) {
                        decls.retain(|d| match name_of(d) {
                            Some(n) if tool_matches(pattern, n) => {
                                removed.push(n.to_string());
                                false
                            }
                            _ => true,
                        });
                    }
                }
            }
            // Groups without declarations (and nothing else) go.
            tools.retain(|t| !(t.as_object().is_some_and(|o| o.len() == 1) && ["functionDeclarations", "function_declarations"].iter().any(|k| t.get(*k).and_then(|d| d.as_array()).is_some_and(|d| d.is_empty()))));
        }
    }
    if removed.is_empty() {
        return false;
    }
    let empty = obj.get("tools").and_then(|t| t.as_array()).is_some_and(|t| t.is_empty());
    let choice_named = obj.get("tool_choice").and_then(|c| c.get("name").or_else(|| c.get("function").and_then(|f| f.get("name")))).and_then(|n| n.as_str()).is_some_and(|n| removed.iter().any(|r| r == n));
    if empty {
        obj.remove("tools");
        obj.remove("tool_choice");
        obj.remove("toolConfig");
        obj.remove("tool_config");
    } else if choice_named {
        obj.remove("tool_choice");
    }
    true
}

/// Add `text` at the end of the system prompt (created when there is none).
pub fn append_system(v: &mut Value, api: Api, text: &str) -> bool {
    let Some(obj) = v.as_object_mut() else { return false };
    let join = |cur: &str| if cur.is_empty() { text.to_string() } else { format!("{cur}\n\n{text}") };
    match api {
        Api::Messages => match obj.get_mut("system") {
            Some(Value::String(s)) => *s = join(s),
            Some(Value::Array(blocks)) => blocks.push(json!({"type": "text", "text": text})),
            _ => {
                obj.insert("system".into(), Value::String(text.into()));
            }
        },
        Api::Responses => {
            let cur = obj.get("instructions").and_then(|i| i.as_str()).unwrap_or("").to_string();
            obj.insert("instructions".into(), Value::String(join(&cur)));
        }
        Api::OllamaGenerate => {
            let cur = obj.get("system").and_then(|i| i.as_str()).unwrap_or("").to_string();
            obj.insert("system".into(), Value::String(join(&cur)));
        }
        Api::Gemini => {
            let key = gemini_si_key(obj);
            let si = obj.entry(key).or_insert_with(|| json!({"parts": []}));
            match si.get_mut("parts") {
                Some(Value::Array(parts)) => parts.push(json!({"text": text})),
                _ => si["parts"] = json!([{"text": text}]),
            }
        }
        Api::Chat | Api::OllamaChat => {
            let Some(Value::Array(msgs)) = obj.get_mut("messages") else { return false };
            match msgs.iter_mut().find(|m| is_system_role(m)) {
                Some(m) => match m.get_mut("content") {
                    Some(Value::String(s)) => *s = join(s),
                    Some(Value::Array(parts)) => parts.push(json!({"type": "text", "text": text})),
                    _ => m["content"] = Value::String(text.into()),
                },
                None => msgs.insert(0, json!({"role": "system", "content": text})),
            }
        }
        Api::Converse => match obj.get_mut("system") {
            Some(Value::Array(blocks)) => blocks.push(json!({"text": text})),
            _ => {
                obj.insert("system".into(), json!([{"text": text}]));
            }
        },
        Api::Embeddings => return false,
    }
    true
}

/// Replace the whole system prompt (empty text: none).
pub fn set_system(v: &mut Value, api: Api, text: &str) {
    let Some(obj) = v.as_object_mut() else { return };
    let put = |obj: &mut serde_json::Map<String, Value>, key: &str| {
        if text.is_empty() {
            obj.remove(key);
        } else {
            obj.insert(key.into(), Value::String(text.into()));
        }
    };
    match api {
        Api::Messages | Api::OllamaGenerate => put(obj, "system"),
        Api::Responses => put(obj, "instructions"),
        Api::Gemini => {
            obj.remove("system_instruction");
            obj.remove("systemInstruction");
            if !text.is_empty() {
                obj.insert("systemInstruction".into(), json!({"parts": [{"text": text}]}));
            }
        }
        Api::Chat | Api::OllamaChat => {
            if let Some(Value::Array(msgs)) = obj.get_mut("messages") {
                // The leading system messages are the system prompt.
                let lead = msgs.iter().take_while(|m| is_system_role(m)).count();
                msgs.drain(..lead);
                if !text.is_empty() {
                    msgs.insert(0, json!({"role": "system", "content": text}));
                }
            }
        }
        Api::Converse => {
            obj.remove("system");
            if !text.is_empty() {
                obj.insert("system".into(), json!([{"text": text}]));
            }
        }
        Api::Embeddings => {}
    }
}

/// Set the model in the body (APIs that name it in the URL — Gemini, Vertex AI, Bedrock —
/// are changed with [`model_url`]).
pub fn set_model(v: &mut Value, api: Api, model: &str) -> bool {
    if matches!(api, Api::Gemini | Api::Converse) || !v.is_object() || v.get("model").and_then(|m| m.as_str()) == Some(model) {
        return false;
    }
    v["model"] = Value::String(model.into());
    true
}

/// A URL with another model where the API names it there: Gemini and Vertex AI
/// (`…/models/{model}:generateContent`), Bedrock (`…/model/{model}/invoke`).
pub fn model_url(url: &str, model: &str) -> Option<String> {
    if let Some(i) = url.find("/model/").map(|i| i + "/model/".len()).filter(|_| url.contains("bedrock-runtime")) {
        let end = url[i..].find('/').map(|e| i + e).unwrap_or(url.len());
        // A path segment: an inference profile ARN carries `/` and `:`.
        let enc = model.replace('%', "%25").replace(':', "%3A").replace('/', "%2F").replace('?', "%3F").replace('#', "%23");
        return (url[i..end] != enc && url[i..end] != *model).then(|| format!("{}{}{}", &url[..i], enc, &url[end..]));
    }
    let i = url.find("/models/")? + "/models/".len();
    let end = url[i..].find(':').map(|e| i + e)?;
    let enc = model.replace('%', "%25").replace('/', "%2F").replace('?', "%3F").replace('#', "%23");
    (url[i..end] != enc).then(|| format!("{}{}{}", &url[..i], enc, &url[end..]))
}

/// Set the output limit under the key the API uses.
pub fn set_max_tokens(v: &mut Value, api: Api, n: u64) {
    let Some(obj) = v.as_object_mut() else { return };
    match api {
        Api::Messages => {
            obj.insert("max_tokens".into(), n.into());
        }
        Api::Chat => {
            let key = if obj.contains_key("max_tokens") && !obj.contains_key("max_completion_tokens") { "max_tokens" } else { "max_completion_tokens" };
            obj.insert(key.into(), n.into());
        }
        Api::Responses => {
            obj.insert("max_output_tokens".into(), n.into());
        }
        Api::Gemini => {
            let key = if obj.contains_key("generation_config") { "generation_config" } else { "generationConfig" };
            let g = obj.entry(key).or_insert_with(|| json!({}));
            g["maxOutputTokens"] = n.into();
        }
        Api::OllamaChat | Api::OllamaGenerate => {
            let o = obj.entry("options").or_insert_with(|| json!({}));
            o["num_predict"] = n.into();
        }
        Api::Converse => {
            let o = obj.entry("inferenceConfig").or_insert_with(|| json!({}));
            o["maxTokens"] = n.into();
        }
        Api::Embeddings => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    #[test]
    fn the_api_decides_the_format() {
        // OpenAI Chat with max_tokens and no system message: a system message, not `system`.
        let mut chat = v(r#"{"model":"gpt-4o","max_tokens":256,"messages":[{"role":"user","content":"hi"}]}"#);
        assert!(append_system(&mut chat, Api::Chat, "Be brief."));
        assert!(chat.get("system").is_none());
        assert_eq!(chat["messages"][0], json!({"role": "system", "content": "Be brief."}));
        let mut anthropic = v(r#"{"model":"claude","max_tokens":5,"messages":[]}"#);
        append_system(&mut anthropic, Api::Messages, "x");
        assert_eq!(anthropic["system"], "x");
        let mut generate = v(r#"{"model":"llama3","prompt":"hi","system":"old"}"#);
        assert!(append_system(&mut generate, Api::OllamaGenerate, "new"));
        assert_eq!(generate["system"], "old\n\nnew");
        let mut gemini = v(r#"{"contents":[],"system_instruction":{"parts":[{"text":"old"}]}}"#);
        append_system(&mut gemini, Api::Gemini, "x");
        assert!(gemini.get("systemInstruction").is_none(), "the key it has");
        assert_eq!(gemini["system_instruction"]["parts"][1]["text"], "x");
        set_system(&mut gemini, Api::Gemini, "only");
        assert!(gemini.get("system_instruction").is_none());
        assert_eq!(gemini["systemInstruction"]["parts"][0]["text"], "only");
        assert!(!append_system(&mut v(r#"{"input":"x"}"#), Api::Embeddings, "x"));
    }

    #[test]
    fn removing_tools_cleans_up() {
        let mut a = v(r#"{"tools":[{"name":"a"},{"name":"b"}],"tool_choice":{"type":"tool","name":"a"}}"#);
        assert!(remove_tool(&mut a, Api::Messages, "a"));
        assert!(a.get("tool_choice").is_none(), "named a removed tool");
        let mut r = v(r#"{"tools":[{"type":"function","name":"f"}],"tool_choice":"required"}"#);
        remove_tool(&mut r, Api::Responses, "*");
        assert!(r.get("tools").is_none() && r.get("tool_choice").is_none());
        let mut g = v(r#"{"tools":[{"functionDeclarations":[{"name":"x"}]}],"toolConfig":{"functionCallingConfig":{"mode":"ANY"}}}"#);
        assert!(remove_tool(&mut g, Api::Gemini, "x"));
        assert!(g.get("tools").is_none() && g.get("toolConfig").is_none());
        assert!(!remove_tool(&mut v(r#"{"tools":[{"name":"a"}]}"#), Api::Chat, "z"));
    }

    #[test]
    fn model_and_limit() {
        assert_eq!(model_url("https://g/v1beta/models/gemini-2.5-pro:generateContent?alt=sse", "gemini-2.5-flash").as_deref(), Some("https://g/v1beta/models/gemini-2.5-flash:generateContent?alt=sse"));
        assert!(!set_model(&mut v(r#"{"contents":[]}"#), Api::Gemini, "x"));
        assert_eq!(model_url("https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-sonnet-4-5-20250929-v1%3A0/invoke", "anthropic.claude-haiku-4-5-20251001-v1:0").as_deref(), Some("https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-haiku-4-5-20251001-v1%3A0/invoke"));
        let mut c = v(r#"{"messages":[],"toolConfig":{"tools":[{"toolSpec":{"name":"a"}},{"toolSpec":{"name":"b"}}],"toolChoice":{"tool":{"name":"a"}}}}"#);
        assert!(remove_tool(&mut c, Api::Converse, "a"));
        assert!(c["toolConfig"].get("toolChoice").is_none());
        append_system(&mut c, Api::Converse, "x");
        set_max_tokens(&mut c, Api::Converse, 5);
        assert_eq!((c["system"][0]["text"].as_str(), c["inferenceConfig"]["maxTokens"].as_u64()), (Some("x"), Some(5)));
        let mut c = v(r#"{"model":"gpt-5","messages":[]}"#);
        set_max_tokens(&mut c, Api::Chat, 100);
        assert_eq!(c["max_completion_tokens"], 100);
        let mut r = v(r#"{"input":[]}"#);
        set_max_tokens(&mut r, Api::Responses, 7);
        assert_eq!(r["max_output_tokens"], 7);
        let mut o = v(r#"{"prompt":"x"}"#);
        set_max_tokens(&mut o, Api::OllamaGenerate, 9);
        assert_eq!(o["options"]["num_predict"], 9);
    }
}
