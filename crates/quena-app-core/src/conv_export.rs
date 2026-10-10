//! A conversation of an AI agent as a file: Markdown to read (each turn with what it added and
//! the answer), JSON lines for evaluations (one call per line, as the LLM view takes it apart),
//! or OpenTelemetry spans after the GenAI semantic conventions (OTLP JSON) for tracing tools
//! like Langfuse or Phoenix (counts and models, no content).

use crate::AppCore;
use crate::agent::Turn;
use crate::llm::Part;
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

/// A cache note in words (as the Agents panel says it, in English).
fn cache_text(code: &str, args: &std::collections::BTreeMap<String, String>) -> String {
    let a = |k: &str| args.get(k).map(String::as_str).unwrap_or("");
    match code {
        "miss" => format!("Cache missed: {} tokens were processed again without it", a("tokens")),
        "expired" => format!("Cache expired: {} min since the previous turn (lifetime {} min)", a("minutes"), a("ttl")),
        "systemChanged" => "The system prompt changed".into(),
        "toolsChanged" => format!("The tool definitions changed (+{} −{}, {} changed; or their order)", a("added"), a("removed"), a("changed")),
        "messageChanged" => format!("Message {} of {} changed: everything from it on is new to the cache", a("n"), a("of")),
        "modelChanged" => format!("The model changed from {} to {}", a("from"), a("to")),
        "settingsChanged" => format!("Settings the cache depends on changed: {}", a("names")),
        "noMarks" => "The request sets no cache_control breakpoint: Anthropic caches marked prefixes only".into(),
        "short" => format!("Marked for caching, but shorter than the {} tokens the provider caches for this model", a("min")),
        "unknown" => "Reason not known".into(),
        other => other.to_string(),
    }
}

/// A hint in words, with what its tokens mean.
fn hint_text(code: &str, args: &std::collections::BTreeMap<String, String>, tokens: u64) -> String {
    let a = |k: &str| args.get(k).map(String::as_str).unwrap_or("");
    let tool = || if a("tool").is_empty() { "?" } else { a("tool") };
    let what = match code {
        "dupResult" => format!("The same {} result is in the context {} times", tool(), a("n")),
        "bigResult" => format!("A large {} result", tool()),
        "repeatCall" => format!("{} called {} times with the same arguments: {}", tool(), a("n"), a("args")),
        "dupReminder" => format!("The same reminder {} times: {}", a("n"), a("text")),
        "unusedTools" => format!("{} of {} tools never called in {} turns: {}", a("n"), a("of"), a("turns"), a("names")),
        "window" => format!("The context fills {} % of the window ({} tokens)", a("pct"), a("window")),
        "cacheMisses" => format!("The cache missed in {} of {} turns", a("n"), a("turns")),
        "rateLimited" => format!("{} calls refused for the rate limit or an overloaded provider; {} sent again", a("n"), a("retries")),
        "rateHeadroom" => format!("Close to the rate limit: {} of {} tokens left", a("left"), a("limit")),
        other => other.to_string(),
    };
    let cost = match code {
        "unusedTools" => format!("{tokens} tokens in every request"),
        "window" => format!("{tokens} tokens input"),
        "cacheMisses" => format!("{tokens} tokens without the cache"),
        "rateLimited" | "rateHeadroom" => "waiting time instead of tokens".into(),
        _ => format!("≈ {tokens} tokens per request"),
    };
    format!("{what} — {cost}")
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
    /// Write conversation `key` to `path` as `markdown`, `jsonl` (each call with the messages it
    /// added), `jsonl-full` (each call whole) or `otel`; returns the turns written. Written as it
    /// goes, one call read at a time, into a temporary file renamed at the end.
    pub fn llm_export(&self, key: &str, format: &str, path: &std::path::Path) -> Result<usize> {
        use std::io::Write as _;
        if !matches!(format, "markdown" | "jsonl" | "jsonl-full" | "otel") {
            bail!("unknown format {format} (markdown, jsonl, jsonl-full, otel)");
        }
        let d = self.llm_conversation(key).ok_or_else(|| anyhow!("no conversation {key}"))?;
        let tmp = path.with_extension("quena-tmp");
        let mut w = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
        let written = self.write_export(&d, format, &mut w).and_then(|()| Ok(w.flush()?));
        drop(w);
        if let Err(e) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        std::fs::rename(&tmp, path)?;
        Ok(d.turns.len())
    }

    fn write_export(&self, d: &crate::agent::ConvDetail, format: &str, w: &mut impl std::io::Write) -> Result<()> {
        match format {
            "markdown" => {
                let s = &d.summary;
                let mut out = format!("# {}\n\n", s.title);
                let _ = writeln!(out, "- Agent: {}\n- Models: {}\n- Turns: {}\n- Tokens: in {} · out {} · cached {}", if s.agent.is_empty() { &s.provider } else { &s.agent }, s.models.join(", "), s.turns, s.input, s.output, s.cache_read);
                if let Some(c) = s.cost {
                    let _ = writeln!(out, "- Estimated cost: ${c:.4}");
                }
                let _ = writeln!(out, "- Conversation: {} (Quena)\n", s.key);
                for h in &d.hints {
                    let _ = writeln!(out, "> Hint: {}", hint_text(h.code, &h.args, h.tokens));
                }
                w.write_all(out.as_bytes())?;
                for (i, t) in d.turns.iter().enumerate() {
                    let mut out = String::new();
                    let _ = writeln!(out, "\n## Turn {} — #{}\n\n{}\n", i + 1, t.id, usage_line(t));
                    for n in &t.cache {
                        let _ = writeln!(out, "> Cache: {}", cache_text(n.code, &n.args));
                    }
                    match self.llm(t.id) {
                        None => out.push_str("_(request not readable)_\n"),
                        Some(c) => {
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
                    }
                    w.write_all(out.as_bytes())?;
                }
            }
            "jsonl" | "jsonl-full" => {
                let full = format == "jsonl-full";
                let (mut system, mut tools) = (None::<Vec<String>>, None::<Vec<crate::llm::ToolDef>>);
                for (i, t) in d.turns.iter().enumerate() {
                    let mut call = self.llm(t.id);
                    let mut before = 0;
                    if !full && let Some(c) = call.as_mut() {
                        // Only what changed: the messages this turn added, system and tools when
                        // they differ from the call before.
                        before = t.messages.saturating_sub(t.diff.added).min(c.messages.len());
                        c.messages.drain(..before);
                        if system.as_ref() == Some(&c.system) {
                            c.system.clear();
                        } else {
                            system = Some(c.system.clone());
                        }
                        if tools.as_ref().is_some_and(|x| *x == c.tools) {
                            c.tools.clear();
                        } else {
                            tools = Some(c.tools.clone());
                        }
                    }
                    let line = json!({"conversation": d.summary.key, "turn": i + 1, "session": t.id, "started": t.started, "side": t.side, "diff": t.diff, "cache": t.cache, "messagesBefore": before, "call": call});
                    serde_json::to_writer(&mut *w, &line)?;
                    w.write_all(b"\n")?;
                }
            }
            _ => {
                let s = &d.summary;
                // One trace per conversation: a root span for the run, a child per call.
                // Ids from the key and the start, so the same run exported twice keeps them and a
                // later run with the same key (after a restart) does not collide.
                let digest = {
                    use sha2::Digest;
                    sha2::Sha256::digest(format!("{}\u{0}{}", s.key, s.started).as_bytes())
                };
                let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
                let trace = hex[..32].to_string();
                let root = hex[32..48].to_string();
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
                serde_json::to_writer_pretty(&mut *w, &doc)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn codes_are_written_in_words() {
        let args: BTreeMap<String, String> = [("tool", "Read"), ("n", "3"), ("args", "{}")].into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        assert_eq!(hint_text("repeatCall", &args, 21_544), "Read called 3 times with the same arguments: {} — ≈ 21544 tokens per request");
        let miss: BTreeMap<String, String> = [("tokens".to_string(), "38100".to_string())].into_iter().collect();
        assert_eq!(cache_text("miss", &miss), "Cache missed: 38100 tokens were processed again without it");
        for code in ["dupResult", "bigResult", "dupReminder", "unusedTools", "window", "cacheMisses", "rateLimited", "rateHeadroom"] {
            assert_ne!(hint_text(code, &BTreeMap::new(), 1).split(" — ").next(), Some(code), "{code}");
        }
        for code in ["expired", "systemChanged", "toolsChanged", "messageChanged", "modelChanged", "settingsChanged", "noMarks", "short", "unknown"] {
            assert_ne!(cache_text(code, &BTreeMap::new()), code);
        }
    }
}
