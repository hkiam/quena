//! A conversation of an AI agent as a file: Markdown to read (each turn with what it added and
//! the answer), JSON lines for evaluations (one call per line, as the LLM view takes it apart),
//! or OpenTelemetry spans after the GenAI semantic conventions (OTLP JSON) for tracing tools
//! like Langfuse or Phoenix (counts and models, no content).

use crate::AppCore;
use crate::agent::Turn;
use crate::llm::{LlmCall, Part};
use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};
use std::fmt::Write as _;

/// Longest text written per part in Markdown.
const MD_TEXT: usize = 4_000;

fn short(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    format!("{} … ({} characters)", s.chars().take(n).collect::<String>(), s.chars().count())
}

fn part_md(out: &mut String, p: &Part) {
    match p.kind.as_str() {
        "toolCall" => {
            let _ = writeln!(out, "**→ {}**\n\n```json\n{}\n```\n", p.name.as_deref().unwrap_or("?"), short(&p.text, MD_TEXT));
        }
        "toolResult" => {
            let _ = writeln!(out, "**← result**\n\n```\n{}\n```\n", short(&p.text, MD_TEXT));
        }
        "thinking" => {
            let _ = writeln!(out, "<details><summary>Thinking</summary>\n\n{}\n\n</details>\n", short(&p.text, MD_TEXT));
        }
        "text" => {
            let _ = writeln!(out, "{}\n", short(&p.text, MD_TEXT));
        }
        _ => {
            let _ = writeln!(out, "_{}_\n", short(&p.text, 200));
        }
    }
}

fn usage_line(t: &Turn) -> String {
    let mut s = t.model.clone();
    if let Some(u) = t.usage {
        let _ = write!(s, " · in {} · out {}", u.input, u.output);
        if u.cache_read > 0 {
            let _ = write!(s, " · cached {}", u.cache_read);
        }
    }
    if let Some(c) = t.cost {
        let _ = write!(s, " · ≈ ${c:.4}");
    }
    if t.side {
        s.push_str(" · side call");
    }
    s
}

/// Nanoseconds since the epoch, as OTLP JSON wants them (a string).
fn nanos(us: i64) -> String {
    (us.max(0) as u128 * 1_000).to_string()
}

fn attr(key: &str, v: Value) -> Value {
    let value = match v {
        Value::String(s) => json!({"stringValue": s}),
        Value::Number(n) if n.is_u64() || n.is_i64() => json!({"intValue": n.to_string()}),
        Value::Number(n) => json!({"doubleValue": n}),
        Value::Bool(b) => json!({"boolValue": b}),
        Value::Array(a) => json!({"arrayValue": {"values": a.into_iter().map(|x| json!({"stringValue": x.as_str().unwrap_or("")})).collect::<Vec<_>>()}}),
        other => json!({"stringValue": other.to_string()}),
    };
    json!({"key": key, "value": value})
}

impl AppCore {
    /// Write conversation `key` to `path` as `markdown`, `jsonl` or `otel`; returns the turns
    /// written.
    pub fn llm_export(&self, key: &str, format: &str, path: &std::path::Path) -> Result<usize> {
        let d = self.llm_conversation(key).ok_or_else(|| anyhow!("no conversation {key}"))?;
        let calls: Vec<Option<LlmCall>> = d.turns.iter().map(|t| self.llm(t.id)).collect();
        let text = match format {
            "markdown" => {
                let s = &d.summary;
                let mut out = format!("# {}\n\n", s.title);
                let _ = writeln!(out, "- Agent: {}\n- Models: {}\n- Turns: {}\n- Tokens: in {} · out {} · cached {}", if s.agent.is_empty() { &s.provider } else { &s.agent }, s.models.join(", "), s.turns, s.input, s.output, s.cache_read);
                if let Some(c) = s.cost {
                    let _ = writeln!(out, "- Estimated cost: ${c:.4}");
                }
                let _ = writeln!(out, "- Conversation: {} (Quena)\n", s.key);
                for h in &d.hints {
                    let _ = writeln!(out, "> Hint: {} ({} tokens)", h.code, h.tokens);
                }
                for (i, (t, c)) in d.turns.iter().zip(&calls).enumerate() {
                    let _ = writeln!(out, "\n## Turn {} — #{}\n\n{}\n", i + 1, t.id, usage_line(t));
                    for n in &t.cache {
                        let _ = writeln!(out, "> Cache: {} {}", n.code, n.args.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(" "));
                    }
                    let Some(c) = c else {
                        out.push_str("_(request not readable)_\n");
                        continue;
                    };
                    if i == 0 && !c.system.is_empty() {
                        let _ = writeln!(out, "### System\n\n{}\n", short(&c.system.join("\n\n"), MD_TEXT));
                    }
                    // What this turn added to the call it continues.
                    let from = t.messages.saturating_sub(t.diff.added);
                    for m in c.messages.iter().skip(from) {
                        let _ = writeln!(out, "### {}\n", m.role);
                        for p in &m.parts {
                            part_md(&mut out, p);
                        }
                    }
                    if !c.output.is_empty() {
                        out.push_str("### Answer\n\n");
                        for p in &c.output {
                            part_md(&mut out, p);
                        }
                    }
                }
                out
            }
            "jsonl" => {
                let mut out = String::new();
                for (i, (t, c)) in d.turns.iter().zip(&calls).enumerate() {
                    let line = json!({"conversation": d.summary.key, "turn": i + 1, "session": t.id, "started": t.started, "side": t.side, "diff": t.diff, "cache": t.cache, "call": c});
                    out.push_str(&serde_json::to_string(&line)?);
                    out.push('\n');
                }
                out
            }
            "otel" => {
                let s = &d.summary;
                // One trace per conversation: a root span for the run, a child per call.
                let trace = format!("{:0>32}", s.key);
                let root = format!("{:0>16}", &s.key[..s.key.len().min(16)]);
                let mut spans = vec![json!({
                    "traceId": trace, "spanId": root, "name": format!("invoke_agent {}", if s.agent.is_empty() { "agent" } else { &s.agent }),
                    "kind": 1, "startTimeUnixNano": nanos(s.started), "endTimeUnixNano": nanos(s.ended),
                    "attributes": [attr("gen_ai.operation.name", json!("invoke_agent")), attr("gen_ai.agent.name", json!(s.agent)), attr("gen_ai.conversation.id", json!(s.key)), attr("gen_ai.usage.input_tokens", json!(s.input)), attr("gen_ai.usage.output_tokens", json!(s.output))],
                })];
                for t in &d.turns {
                    let end = t.started + t.duration_ms.unwrap_or(0) as i64 * 1_000;
                    let mut attrs = vec![attr("gen_ai.operation.name", json!("chat")), attr("gen_ai.provider.name", json!(s.provider)), attr("gen_ai.request.model", json!(t.model)), attr("gen_ai.conversation.id", json!(s.key)), attr("quena.session.id", json!(t.id))];
                    if let Some(u) = t.usage {
                        attrs.push(attr("gen_ai.usage.input_tokens", json!(u.input)));
                        attrs.push(attr("gen_ai.usage.output_tokens", json!(u.output)));
                        attrs.push(attr("gen_ai.usage.cache_read.input_tokens", json!(u.cache_read)));
                    }
                    if let Some(r) = &t.stop {
                        attrs.push(attr("gen_ai.response.finish_reasons", json!([r])));
                    }
                    if !t.calls.is_empty() {
                        attrs.push(attr("quena.tool_calls", json!(t.calls)));
                    }
                    spans.push(json!({
                        "traceId": trace, "spanId": format!("{:016x}", t.id), "parentSpanId": root, "name": format!("chat {}", t.model),
                        "kind": 3, "startTimeUnixNano": nanos(t.started), "endTimeUnixNano": nanos(end), "attributes": attrs,
                        "status": if t.error { json!({"code": 2}) } else { json!({"code": 1}) },
                    }));
                }
                let doc = json!({"resourceSpans": [{"resource": {"attributes": [attr("service.name", json!("quena-capture"))]}, "scopeSpans": [{"scope": {"name": "quena", "version": env!("CARGO_PKG_VERSION")}, "spans": spans}]}]});
                serde_json::to_string_pretty(&doc)?
            }
            other => bail!("unknown format {other} (markdown, jsonl, otel)"),
        };
        let tmp = path.with_extension("quena-tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, path)?;
        Ok(d.turns.len())
    }
}
