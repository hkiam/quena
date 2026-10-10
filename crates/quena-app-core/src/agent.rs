//! Conversations of AI agents (Claude Code, Codex, own apps): the LLM calls of one run put
//! together, what fills each request's context, what changed from one turn to the next, why
//! the provider's prompt cache missed, and where tokens go to waste.
//!
//! An agent sends its whole conversation with every turn. Calls belong to one conversation
//! when they start with the same system prompt and the same first prompt of the user (the
//! text the agent adds around it — `<system-reminder>`, AGENTS.md, the environment — does not
//! count). Each call is kept as a small digest (hashes of its parts, usage), so a run of
//! hundreds of turns is put together without reading the bodies again.

use crate::AppCore;
use crate::llm::{self, Api, LlmCall, Part, Usage};
use quena_model::{SessionDetail, SessionId};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

/// Flag naming the conversation of an LLM call (kept in archives).
pub const CONV_FLAG: &str = "x-quena-llm-conv";

/// Tokens an image is counted with when its size is not known.
const IMAGE_TOKENS: u64 = 1_600;
/// Anthropic's default cache lifetime; OpenAI keeps cached prefixes for 5–10 minutes.
const CACHE_TTL_MS: i64 = 5 * 60_000;
const CACHE_TTL_LONG_MS: i64 = 60 * 60_000;
/// OpenAI caches prompts from this length on.
const OPENAI_CACHE_MIN: u64 = 1_024;

// ------------------------------------------------------------------ hashing

fn fnv(mut h: u64, bytes: &[u8]) -> u64 {
    for b in bytes {
        h = (h ^ *b as u64).wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

const FNV0: u64 = 0xcbf2_9ce4_8422_2325;

fn hash_str(s: &str) -> u64 {
    fnv(FNV0, s.as_bytes())
}

fn hash_part(h: u64, p: &Part) -> u64 {
    let h = fnv(h, p.kind.as_bytes());
    let h = fnv(h, &[0]);
    let h = fnv(h, p.name.as_deref().unwrap_or("").as_bytes());
    let h = fnv(h, &[0]);
    let h = fnv(h, p.id.as_deref().unwrap_or("").as_bytes());
    fnv(fnv(h, &[0]), p.text.as_bytes())
}

fn hash_message(m: &llm::Message) -> u64 {
    m.parts.iter().fold(fnv(FNV0, m.role.as_bytes()), hash_part)
}

/// A conversation key as shown and kept in the flag.
pub fn key_text(k: u64) -> String {
    format!("{:08x}", (k >> 32) as u32 ^ k as u32)
}

// ------------------------------------------------------------------ token estimate

/// Tokens of `s`, estimated the way BPE tokenizers split text: a word piece per few letters,
/// a token per punctuation mark, one per line break. Rough on its own; the breakdown scales
/// the estimates to the usage the provider reported.
pub fn estimate_tokens(s: &str) -> u64 {
    // A text shortened by the parser ends in "… (N characters)": scale up to its full length.
    if let Some(cut) = s.rfind(" … (")
        && let Some(n) = s[cut + " … (".len()..].strip_suffix(" characters)").and_then(|n| n.parse::<u64>().ok())
    {
        let head = &s[..cut];
        let chars = head.chars().count().max(1) as u64;
        return estimate_plain(head).saturating_mul(n) / chars;
    }
    estimate_plain(s)
}

fn estimate_plain(s: &str) -> u64 {
    let (mut t, mut run, mut newline) = (0u64, 0u64, false);
    for c in s.chars() {
        if c.is_alphanumeric() {
            run += if c.is_ascii() { 1 } else { 2 };
            newline = false;
            continue;
        }
        if run > 0 {
            t += run.div_ceil(5);
            run = 0;
        }
        if c == '\n' {
            if !newline {
                t += 1;
            }
            newline = true;
        } else if !c.is_whitespace() {
            t += 1;
            newline = false;
        }
    }
    t + run.div_ceil(5)
}

// ------------------------------------------------------------------ text the agents add

/// What a stretch of a message's text is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seg {
    /// Written by the user or the model.
    Text,
    /// `<system-reminder>` and similar notes the agent adds.
    Reminder,
    /// CLAUDE.md, AGENTS.md and other instruction files.
    Instructions,
    /// The list of skills an agent offers the model.
    Skills,
    /// `<environment_context>` (Codex): folder, shell, sandbox.
    Context,
}

/// The stretches of `text` with what they are and a label (the instruction file's path).
fn segments(text: &str) -> Vec<(Seg, String, &str)> {
    let mut out = Vec::new();
    let t = text.trim_start();
    // Codex sends AGENTS.md as a message of its own.
    if t.starts_with("# AGENTS.md instructions") || t.starts_with("<user_instructions>") || t.starts_with("<INSTRUCTIONS>") {
        let label = t.lines().next().and_then(|l| l.strip_prefix("# ")).map(|l| l.trim_end_matches(':').to_string()).unwrap_or_else(|| "AGENTS.md".into());
        return vec![(Seg::Instructions, label, text)];
    }
    let tags: &[(&str, &str, Seg)] = &[("<system-reminder>", "</system-reminder>", Seg::Reminder), ("<environment_context>", "</environment_context>", Seg::Context)];
    let mut rest = text;
    loop {
        let next = tags.iter().filter_map(|(open, close, seg)| rest.find(open).map(|i| (i, *open, *close, *seg))).min_by_key(|x| x.0);
        let Some((i, open, close, seg)) = next else { break };
        if i > 0 {
            out.push((Seg::Text, String::new(), &rest[..i]));
        }
        let end = rest[i + open.len()..].find(close).map(|e| i + open.len() + e + close.len()).unwrap_or(rest.len());
        let block = &rest[i..end];
        if seg == Seg::Reminder {
            out.extend(reminder_parts(block));
        } else {
            out.push((seg, open.trim_matches(['<', '>']).to_string(), block));
        }
        rest = &rest[end..];
    }
    if !rest.is_empty() {
        out.push((Seg::Text, String::new(), rest));
    }
    out
}

/// A `<system-reminder>` block: instruction files it carries (Claude Code: "Contents of
/// /path/CLAUDE.md …"), a list of skills, or a note.
fn reminder_parts(block: &str) -> Vec<(Seg, String, &str)> {
    const MARK: &str = "Contents of ";
    let starts: Vec<usize> = block.match_indices(MARK).map(|(i, _)| i).filter(|i| block[i + MARK.len()..].lines().next().is_some_and(|l| l.contains(".md"))).collect();
    if starts.is_empty() {
        let lower = block.to_ascii_lowercase();
        let seg = if lower.contains("skill") && (lower.contains("skills are available") || lower.contains("skill tool") || lower.contains("available skills")) { Seg::Skills } else { Seg::Reminder };
        return vec![(seg, if seg == Seg::Skills { "skills".into() } else { "system-reminder".into() }, block)];
    }
    let mut out = Vec::new();
    if starts[0] > 0 {
        out.push((Seg::Reminder, "system-reminder".into(), &block[..starts[0]]));
    }
    for (n, &s) in starts.iter().enumerate() {
        let end = starts.get(n + 1).copied().unwrap_or(block.len());
        let line = block[s + MARK.len()..].lines().next().unwrap_or("");
        let path = line.split(" (").next().unwrap_or(line).trim_end_matches(':').trim();
        out.push((Seg::Instructions, path.to_string(), &block[s..end]));
    }
    out
}

/// The user's own words in a message: its text without what the agent added.
fn own_text(m: &llm::Message) -> String {
    let mut out = String::new();
    for p in m.parts.iter().filter(|p| p.kind == "text") {
        for (seg, _, t) in segments(&p.text) {
            if seg == Seg::Text {
                out.push_str(t);
            }
        }
    }
    out.trim().to_string()
}

/// The first prompt of the user: the first user message with words of its own.
fn first_prompt(call: &LlmCall) -> String {
    call.messages.iter().filter(|m| m.role == "user").map(own_text).find(|t| !t.is_empty()).unwrap_or_default()
}

fn snippet(s: &str, n: usize) -> String {
    let one: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if one.chars().count() <= n { one } else { format!("{}…", one.chars().take(n).collect::<String>()) }
}

/// The agent that sent a request, by its User-Agent (`claude-cli/2.0.14 (external, cli)` →
/// `claude-cli/2.0.14`).
pub fn agent_of(user_agent: &str) -> String {
    user_agent.split_whitespace().next().unwrap_or("").to_string()
}

// ------------------------------------------------------------------ digest

/// What is kept of one LLM call to put conversations together.
#[derive(Debug, Clone)]
pub struct Digest {
    pub id: SessionId,
    /// Microseconds since the epoch.
    pub started: i64,
    pub duration_ms: Option<u32>,
    pub provider: String,
    pub api: Api,
    pub model: String,
    pub agent: String,
    /// The conversation.
    pub key: u64,
    pub system: Vec<u64>,
    /// Tools by name: hash of the definition, its estimated tokens.
    pub tools: Vec<(String, u64, u64)>,
    pub messages: Vec<u64>,
    pub usage: Option<Usage>,
    pub cost: Option<f64>,
    /// The first prompt (shortened): the conversation's title.
    pub prompt: String,
    /// Tools the answer calls, and their arguments (shortened), in order.
    pub calls: Vec<(String, String)>,
    pub stop: Option<String>,
    pub error: bool,
    pub cache_marks: usize,
    pub cache_long: bool,
    /// Estimated input tokens.
    pub est: u64,
}

impl Digest {
    pub fn new(id: SessionId, d: &SessionDetail, call: &LlmCall) -> Digest {
        let prompt = first_prompt(call);
        let system_text = call.system.join("\n");
        let head: String = system_text.chars().take(200).collect();
        // Embeddings have no conversation.
        let key = if call.api == Api::Embeddings {
            0
        } else if prompt.is_empty() && head.is_empty() {
            call.messages.first().map(hash_message).unwrap_or(0)
        } else {
            fnv(fnv(hash_str(&head), &[1]), prompt.as_bytes())
        };
        let tools = call.tools.iter().map(|t| (t.name.clone(), fnv(hash_str(&t.name), &t.size.to_le_bytes()) ^ hash_str(&t.description), (t.size as u64).div_ceil(4))).collect();
        Digest {
            id,
            started: d.summary.started_at,
            duration_ms: d.summary.duration_ms,
            provider: call.provider.clone(),
            api: call.api,
            model: call.model.clone(),
            agent: agent_of(d.request.headers.get("user-agent").unwrap_or("")),
            key,
            system: call.system.iter().map(|s| hash_str(s)).collect(),
            tools,
            messages: call.messages.iter().map(hash_message).collect(),
            usage: call.usage,
            cost: call.cost.as_ref().map(|c| c.usd),
            prompt: snippet(&prompt, 300),
            calls: call.output.iter().filter(|p| p.kind == "toolCall").map(|p| (p.name.clone().unwrap_or_default(), p.text.chars().take(1_000).collect())).collect(),
            stop: call.stop_reason.clone(),
            error: call.error.is_some(),
            cache_marks: call.cache_marks.iter().filter(|m| !m.starts_with("ttl")).count(),
            cache_long: call.cache_marks.iter().any(|m| m == "ttl 1h"),
            est: breakdown(call).estimated,
        }
    }

    fn end_us(&self) -> i64 {
        self.started + self.duration_ms.unwrap_or(0) as i64 * 1_000
    }
}

// ------------------------------------------------------------------ breakdown

/// One slice of a request's context.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Slice {
    /// `system`, `tools`, `instructions`, `skills`, `reminders`, `context`, `user`,
    /// `assistant`, `thinking`, `toolCalls`, `toolResults`, `images`, `other`.
    pub category: &'static str,
    /// Tool name, instruction file, … (empty: the category as a whole).
    pub label: String,
    /// Tokens: the estimate scaled to the usage the provider reported.
    pub tokens: u64,
    /// The estimate itself.
    pub est: u64,
    /// How many pieces (messages, results, images).
    pub count: u32,
}

/// What fills a request's input.
#[derive(Debug, Clone, Serialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Breakdown {
    /// Largest first.
    pub slices: Vec<Slice>,
    /// Estimated input tokens.
    pub estimated: u64,
    /// Input tokens the provider reported.
    pub actual: Option<u64>,
}

/// The slices of `call`'s input.
pub fn breakdown(call: &LlmCall) -> Breakdown {
    let mut acc: BTreeMap<(&'static str, String), (u64, u32)> = BTreeMap::new();
    let mut add = |cat: &'static str, label: String, est: u64| {
        let e = acc.entry((cat, label)).or_default();
        e.0 += est;
        e.1 += 1;
    };
    for s in &call.system {
        add("system", String::new(), estimate_tokens(s));
    }
    for t in &call.tools {
        add("tools", t.name.clone(), (t.size as u64).div_ceil(4).max(1));
    }
    // Tool results by the name of the call they answer.
    let names: HashMap<&str, &str> = call.messages.iter().flat_map(|m| &m.parts).filter(|p| p.kind == "toolCall").filter_map(|p| Some((p.id.as_deref()?, p.name.as_deref()?))).collect();
    for m in &call.messages {
        for p in &m.parts {
            match p.kind.as_str() {
                "text" if m.role == "user" => {
                    for (seg, label, t) in segments(&p.text) {
                        let est = estimate_tokens(t);
                        match seg {
                            Seg::Text => add("user", String::new(), est),
                            Seg::Reminder => add("reminders", String::new(), est),
                            Seg::Instructions => add("instructions", label, est),
                            Seg::Skills => add("skills", String::new(), est),
                            Seg::Context => add("context", String::new(), est),
                        }
                    }
                }
                "text" => add(if m.role == "assistant" { "assistant" } else { "other" }, String::new(), estimate_tokens(&p.text)),
                "thinking" => add("thinking", String::new(), estimate_tokens(&p.text)),
                "toolCall" => add("toolCalls", p.name.clone().unwrap_or_default(), estimate_tokens(&p.text) + 8),
                "toolResult" => {
                    let name = p.name.as_deref().or_else(|| p.id.as_deref().and_then(|id| names.get(id).copied())).unwrap_or("");
                    add("toolResults", name.to_string(), estimate_tokens(&p.text) + 4)
                }
                "image" => add("images", String::new(), IMAGE_TOKENS),
                _ => add("other", String::new(), estimate_tokens(&p.text)),
            }
        }
    }
    let estimated: u64 = acc.values().map(|(e, _)| e).sum();
    let actual = call.usage.map(|u| u.input).filter(|i| *i > 0);
    let scale = |e: u64| match actual {
        Some(a) if estimated > 0 => ((e as f64) * (a as f64) / (estimated as f64)).round() as u64,
        _ => e,
    };
    let mut slices: Vec<Slice> = acc.into_iter().map(|((category, label), (est, count))| Slice { category, label, tokens: scale(est), est, count }).collect();
    slices.sort_by(|a, b| b.tokens.cmp(&a.tokens).then_with(|| a.category.cmp(b.category)).then_with(|| a.label.cmp(&b.label)));
    Breakdown { slices, estimated, actual }
}

// ------------------------------------------------------------------ turn diff and cache

/// How a turn's request differs from the one before it in its conversation.
#[derive(Debug, Clone, Serialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TurnDiff {
    /// `first`, `append` (the request before it, with messages added), `same` (sent again,
    /// e.g. a retry), `changed` (an earlier message differs).
    pub kind: &'static str,
    /// The first message that differs (0-based), for `changed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<usize>,
    /// Messages after the common start, and those of the previous request not kept.
    pub added: usize,
    pub dropped: usize,
    pub system_changed: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tools_added: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tools_removed: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tools_changed: Vec<String>,
    pub tools_reordered: bool,
    pub model_changed: bool,
    /// From the end of the previous call to the start of this one (ms).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gap_ms: Option<i64>,
}

fn diff(prev: Option<&Digest>, cur: &Digest) -> TurnDiff {
    let Some(p) = prev else { return TurnDiff { kind: "first", added: cur.messages.len(), ..Default::default() } };
    let common = p.messages.iter().zip(&cur.messages).take_while(|(a, b)| a == b).count();
    let kind = if common == p.messages.len() && common == cur.messages.len() {
        "same"
    } else if common == p.messages.len() {
        "append"
    } else {
        "changed"
    };
    let names = |d: &Digest| d.tools.iter().map(|t| t.0.clone()).collect::<Vec<_>>();
    let (pn, cn) = (names(p), names(cur));
    let pset: HashSet<&String> = pn.iter().collect();
    let cset: HashSet<&String> = cn.iter().collect();
    let phash: HashMap<&str, u64> = p.tools.iter().map(|t| (t.0.as_str(), t.1)).collect();
    let kept_order = |v: &[String], other: &HashSet<&String>| v.iter().filter(|n| other.contains(n)).cloned().collect::<Vec<_>>();
    TurnDiff {
        kind,
        at: (kind == "changed").then_some(common),
        added: cur.messages.len() - common,
        dropped: p.messages.len() - common,
        system_changed: p.system != cur.system,
        tools_added: cn.iter().filter(|n| !pset.contains(n)).cloned().collect(),
        tools_removed: pn.iter().filter(|n| !cset.contains(n)).cloned().collect(),
        tools_changed: cur.tools.iter().filter(|t| phash.get(t.0.as_str()).is_some_and(|h| *h != t.1)).map(|t| t.0.clone()).collect(),
        tools_reordered: kept_order(&pn, &cset) != kept_order(&cn, &pset),
        model_changed: p.model != cur.model,
        gap_ms: Some((cur.started - p.end_us()) / 1_000),
    }
}

/// Something about the provider's prompt cache for a turn.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CacheNote {
    /// `miss` (the cache did not serve the start it could have), then the reasons:
    /// `expired`, `systemChanged`, `toolsChanged`, `messageChanged`, `modelChanged`,
    /// `noMarks`, `short`, `unknown`.
    pub code: &'static str,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub args: BTreeMap<String, String>,
}

fn note(code: &'static str, args: &[(&str, String)]) -> CacheNote {
    CacheNote { code, args: args.iter().map(|(k, v)| (k.to_string(), v.clone())).collect() }
}

/// Whether the cache missed for `cur` and why, judged against the turn before it.
fn cache_notes(prev: Option<&Digest>, cur: &Digest, d: &TurnDiff) -> Vec<CacheNote> {
    let (Some(p), Some(u)) = (prev, cur.usage) else { return vec![] };
    let Some(pu) = p.usage else { return vec![] };
    // What could have come from the cache: the previous request's input, at most this one's.
    let could = pu.input.min(u.input);
    if could < OPENAI_CACHE_MIN.min(1_000) || u.cache_read * 2 >= could {
        return vec![];
    }
    let mut out = vec![note("miss", &[("tokens", could.saturating_sub(u.cache_read).to_string())])];
    if d.model_changed {
        out.push(note("modelChanged", &[("from", p.model.clone()), ("to", cur.model.clone())]));
    }
    if d.system_changed {
        out.push(note("systemChanged", &[]));
    }
    if !d.tools_added.is_empty() || !d.tools_removed.is_empty() || !d.tools_changed.is_empty() || d.tools_reordered {
        out.push(note("toolsChanged", &[("added", d.tools_added.len().to_string()), ("removed", d.tools_removed.len().to_string()), ("changed", d.tools_changed.len().to_string())]));
    }
    if let Some(at) = d.at {
        out.push(note("messageChanged", &[("n", (at + 1).to_string()), ("of", p.messages.len().to_string())]));
    }
    let ttl = if cur.cache_long { CACHE_TTL_LONG_MS } else { CACHE_TTL_MS };
    if let Some(gap) = d.gap_ms
        && gap > ttl
    {
        out.push(note("expired", &[("minutes", (gap / 60_000).to_string()), ("ttl", (ttl / 60_000).to_string())]));
    }
    if cur.api == Api::Messages && cur.cache_marks == 0 {
        out.push(note("noMarks", &[]));
    }
    if matches!(cur.api, Api::Chat | Api::Responses) && could < OPENAI_CACHE_MIN {
        out.push(note("short", &[("min", OPENAI_CACHE_MIN.to_string())]));
    }
    if out.len() == 1 {
        out.push(note("unknown", &[]));
    }
    out
}

// ------------------------------------------------------------------ conversations

/// A conversation in the list.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ConvSummary {
    pub key: String,
    pub title: String,
    pub agent: String,
    pub provider: String,
    pub models: Vec<String>,
    pub turns: u32,
    pub first: SessionId,
    pub last: SessionId,
    /// Microseconds since the epoch.
    pub started: i64,
    pub ended: i64,
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    /// Estimated cost (USD) of the turns with a known price.
    pub cost: Option<f64>,
    pub errors: u32,
    /// Turns where the cache missed.
    pub cache_misses: u32,
    /// The last request's input and the model's context window.
    pub last_input: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window: Option<u64>,
    /// The conversation that started this one (a subagent's parent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
}

/// One turn of a conversation.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Turn {
    pub id: SessionId,
    pub started: i64,
    pub duration_ms: Option<u32>,
    pub model: String,
    pub usage: Option<Usage>,
    pub cost: Option<f64>,
    pub stop: Option<String>,
    pub error: bool,
    /// Tools the answer calls.
    pub calls: Vec<String>,
    pub messages: usize,
    pub diff: TurnDiff,
    pub cache: Vec<CacheNote>,
}

/// A hint where tokens go to waste.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Hint {
    /// `dupResult`, `repeatCall`, `bigResult`, `dupReminder`, `window`, `unusedTools`,
    /// `cacheMisses`.
    pub code: &'static str,
    /// Tokens it costs (per request where it says so).
    pub tokens: u64,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub args: BTreeMap<String, String>,
}

fn hint(code: &'static str, tokens: u64, args: &[(&str, String)]) -> Hint {
    Hint { code, tokens, args: args.iter().map(|(k, v)| (k.to_string(), v.clone())).collect() }
}

/// A conversation with its turns.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ConvDetail {
    pub summary: ConvSummary,
    pub turns: Vec<Turn>,
    pub hints: Vec<Hint>,
    /// The last request's context.
    pub breakdown: Option<Breakdown>,
    /// Conversations it started (subagents).
    pub children: Vec<String>,
}

/// A call within its conversation (for the LLM view).
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CallContext {
    pub key: Option<String>,
    /// Its turn (1-based) and the conversation's turns.
    pub turn: usize,
    pub turns: usize,
    pub prev: Option<SessionId>,
    pub breakdown: Breakdown,
    pub diff: Option<TurnDiff>,
    /// The message that differs from the previous request (role and start), before and after.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed: Option<(String, String)>,
    pub cache: Vec<CacheNote>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window: Option<u64>,
}

fn group(digests: &[Arc<Digest>]) -> BTreeMap<u64, Vec<Arc<Digest>>> {
    let mut by: BTreeMap<u64, Vec<Arc<Digest>>> = BTreeMap::new();
    for d in digests.iter().filter(|d| d.key != 0) {
        by.entry(d.key).or_default().push(d.clone());
    }
    for v in by.values_mut() {
        v.sort_by_key(|d| d.id);
    }
    by
}

fn turns_of(ds: &[Arc<Digest>]) -> Vec<Turn> {
    let mut prev: Option<&Digest> = None;
    ds.iter()
        .map(|d| {
            let df = diff(prev, d);
            let cache = cache_notes(prev, d, &df);
            prev = Some(d);
            Turn { id: d.id, started: d.started, duration_ms: d.duration_ms, model: d.model.clone(), usage: d.usage, cost: d.cost, stop: d.stop.clone(), error: d.error, calls: d.calls.iter().map(|c| c.0.clone()).collect(), messages: d.messages.len(), diff: df, cache }
        })
        .collect()
}

fn summary_of(ds: &[Arc<Digest>], turns: &[Turn], prices: &llm::PriceList) -> ConvSummary {
    let first = &ds[0];
    let last = &ds[ds.len() - 1];
    let mut models: Vec<String> = Vec::new();
    for d in ds {
        if !d.model.is_empty() && !models.contains(&d.model) {
            models.push(d.model.clone());
        }
    }
    let sum = |f: fn(&Usage) -> u64| ds.iter().filter_map(|d| d.usage.as_ref()).map(f).sum::<u64>();
    let costs: Vec<f64> = ds.iter().filter_map(|d| d.cost).collect();
    ConvSummary {
        key: key_text(first.key),
        title: if first.prompt.is_empty() { first.model.clone() } else { snippet(&first.prompt, 100) },
        agent: first.agent.clone(),
        provider: first.provider.clone(),
        models,
        turns: ds.len() as u32,
        first: first.id,
        last: last.id,
        started: first.started,
        ended: ds.iter().map(|d| d.end_us()).max().unwrap_or(first.started),
        input: sum(|u| u.input),
        output: sum(|u| u.output),
        cache_read: sum(|u| u.cache_read),
        cache_write: sum(|u| u.cache_write),
        cost: (!costs.is_empty()).then(|| costs.iter().sum()),
        errors: ds.iter().filter(|d| d.error).count() as u32,
        cache_misses: turns.iter().filter(|t| t.cache.iter().any(|c| c.code == "miss")).count() as u32,
        last_input: last.usage.map(|u| u.input).unwrap_or(last.est),
        window: llm::context_of(&last.model, prices),
        parent: None,
    }
}

fn norm(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Subagents: a conversation whose first prompt a tool call of another one carries, while
/// that one ran.
fn parents(by: &BTreeMap<u64, Vec<Arc<Digest>>>) -> HashMap<u64, u64> {
    let mut out = HashMap::new();
    for (k, ds) in by {
        let head: String = norm(&ds[0].prompt).chars().take(120).collect();
        if head.chars().count() < 20 {
            continue;
        }
        let start = ds[0].started;
        let found = by
            .iter()
            .filter(|(pk, _)| *pk != k)
            .filter(|(_, pds)| pds[0].started <= start)
            .find(|(_, pds)| pds.iter().filter(|d| d.started <= start).any(|d| d.calls.iter().any(|(_, args)| norm(&args.replace("\\n", "\n")).contains(&head))));
        if let Some((pk, _)) = found {
            out.insert(*k, *pk);
        }
    }
    out
}

/// Waste in a conversation, judged by its last request (which carries the whole history) and
/// the tools all its turns called.
fn hints(last: &LlmCall, ds: &[Arc<Digest>], turns: &[Turn], window: Option<u64>) -> Vec<Hint> {
    let b = breakdown(last);
    let scale = match b.actual {
        Some(a) if b.estimated > 0 => a as f64 / b.estimated as f64,
        _ => 1.0,
    };
    let tok = |e: u64| (e as f64 * scale).round() as u64;
    let mut out = Vec::new();
    let names: HashMap<&str, &str> = last.messages.iter().flat_map(|m| &m.parts).filter(|p| p.kind == "toolCall").filter_map(|p| Some((p.id.as_deref()?, p.name.as_deref()?))).collect();
    let name_of = |p: &Part| p.name.as_deref().or_else(|| p.id.as_deref().and_then(|id| names.get(id).copied())).unwrap_or("").to_string();
    // The same call (tool and arguments) more than twice: it costs what its later results add.
    let results_by_id: HashMap<&str, &Part> = last.messages.iter().flat_map(|m| &m.parts).filter(|p| p.kind == "toolResult").filter_map(|p| Some((p.id.as_deref()?, p))).collect();
    let mut calls: HashMap<u64, (String, String, Vec<&str>)> = HashMap::new();
    for p in last.messages.iter().flat_map(|m| &m.parts).filter(|p| p.kind == "toolCall") {
        let name = p.name.clone().unwrap_or_default();
        let e = calls.entry(fnv(hash_str(&name), p.text.as_bytes())).or_insert((name, snippet(&p.text, 100), vec![]));
        e.2.extend(p.id.as_deref());
    }
    // Results a repeated call explains are not counted again below.
    let mut explained: HashSet<u64> = HashSet::new();
    for (name, args, ids) in calls.into_values().filter(|c| c.2.len() > 2) {
        let res: Vec<&&Part> = ids.iter().filter_map(|id| results_by_id.get(id)).collect();
        let later: u64 = res.iter().skip(1).map(|r| estimate_tokens(&r.text)).sum();
        explained.extend(res.iter().map(|r| hash_str(&r.text)));
        out.push(hint("repeatCall", tok(later), &[("tool", name), ("n", ids.len().to_string()), ("args", args)]));
    }
    // The same tool result more than once; large results (each text once).
    let mut results: HashMap<u64, (String, u64, u32)> = HashMap::new();
    for p in last.messages.iter().flat_map(|m| &m.parts).filter(|p| p.kind == "toolResult") {
        let e = results.entry(hash_str(&p.text)).or_insert((name_of(p), estimate_tokens(&p.text), 0));
        e.2 += 1;
    }
    let mut big: Vec<(String, u64, u32)> = Vec::new();
    for (h, (name, est, n)) in results {
        if n > 1 && !explained.contains(&h) && est >= 50 {
            out.push(hint("dupResult", tok(est) * (n as u64 - 1), &[("tool", name.clone()), ("n", n.to_string())]));
        }
        if tok(est) >= 8_000 {
            big.push((name, tok(est), n));
        }
    }
    big.sort_by(|a, b| b.1.cmp(&a.1));
    for (name, t, n) in big.into_iter().take(5) {
        out.push(hint("bigResult", t, &[("tool", name), ("n", n.to_string())]));
    }
    // Notes the agent adds again and again.
    let mut reminders: HashMap<u64, (u64, u32, String)> = HashMap::new();
    for p in last.messages.iter().filter(|m| m.role == "user").flat_map(|m| &m.parts).filter(|p| p.kind == "text") {
        for (seg, _, t) in segments(&p.text) {
            if seg == Seg::Reminder && t.len() >= 100 {
                let e = reminders.entry(hash_str(t)).or_insert((estimate_tokens(t), 0, snippet(t.trim_start_matches("<system-reminder>"), 80)));
                e.1 += 1;
            }
        }
    }
    for (est, n, text) in reminders.into_values().filter(|r| r.1 > 2) {
        out.push(hint("dupReminder", tok(est) * (n as u64 - 1), &[("n", n.to_string()), ("text", text)]));
    }
    // Tools offered in every request but never called.
    let called: HashSet<&str> = ds.iter().flat_map(|d| d.calls.iter().map(|c| c.0.as_str())).chain(last.messages.iter().flat_map(|m| &m.parts).filter(|p| p.kind == "toolCall").filter_map(|p| p.name.as_deref())).collect();
    let unused: Vec<&llm::ToolDef> = last.tools.iter().filter(|t| !called.contains(t.name.as_str())).collect();
    if !unused.is_empty() && ds.len() >= 3 {
        let per = tok(unused.iter().map(|t| (t.size as u64).div_ceil(4)).sum());
        let list = unused.iter().take(12).map(|t| t.name.as_str()).collect::<Vec<_>>().join(", ");
        out.push(hint("unusedTools", per, &[("n", unused.len().to_string()), ("of", last.tools.len().to_string()), ("turns", ds.len().to_string()), ("names", list)]));
    }
    // Near the end of the context window.
    if let (Some(w), Some(input)) = (window, b.actual)
        && w > 0
        && input * 10 >= w * 7
    {
        out.push(hint("window", input, &[("pct", (input * 100 / w).to_string()), ("window", w.to_string())]));
    }
    let misses: Vec<&Turn> = turns.iter().filter(|t| t.cache.iter().any(|c| c.code == "miss")).collect();
    if !misses.is_empty() {
        let lost: u64 = misses.iter().flat_map(|t| &t.cache).filter(|c| c.code == "miss").filter_map(|c| c.args.get("tokens")?.parse::<u64>().ok()).sum();
        out.push(hint("cacheMisses", lost, &[("n", misses.len().to_string()), ("turns", turns.len().to_string())]));
    }
    out.sort_by(|a, b| b.tokens.cmp(&a.tokens).then_with(|| a.code.cmp(b.code)));
    out
}

// ------------------------------------------------------------------ AppCore

/// Digests of the current capture's LLM calls.
#[derive(Default)]
pub struct Digests {
    numbering: u64,
    map: HashMap<SessionId, Arc<Digest>>,
}

impl AppCore {
    /// The digest of LLM call `id` (made from its bodies once).
    pub fn llm_digest(&self, id: SessionId) -> Option<Arc<Digest>> {
        let numbering = self.capture().numbering();
        {
            let g = self.llm_digests.lock();
            if g.numbering == numbering
                && let Some(d) = g.map.get(&id)
            {
                return Some(d.clone());
            }
        }
        let d = self.capture().detail(id)?;
        let call = self.llm(id)?;
        Some(self.keep_digest(numbering, Digest::new(id, &d, &call)))
    }

    pub(crate) fn keep_digest(&self, numbering: u64, d: Digest) -> Arc<Digest> {
        let d = Arc::new(d);
        let mut g = self.llm_digests.lock();
        if g.numbering != numbering {
            g.numbering = numbering;
            g.map.clear();
        }
        g.map.insert(d.id, d.clone());
        d
    }

    /// Digests of all LLM calls in the capture; calls without the conversation flag (loaded
    /// from older archives or other tools) get it.
    fn all_digests(&self) -> Vec<Arc<Digest>> {
        let cap = self.capture();
        let ids = cap.index.find_all(|s| !s.llm.is_empty());
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let Some(d) = self.llm_digest(id) else { continue };
            if d.key != 0 && cap.index.get(id).is_some_and(|s| s.llm_conv != key_text(d.key)) {
                let k = key_text(d.key);
                let set = |det: &mut SessionDetail| {
                    det.extra_flags.retain(|(n, _)| n != CONV_FLAG);
                    det.extra_flags.push((CONV_FLAG.into(), k.clone()));
                };
                if let Some(live) = cap.live(id) {
                    live.update(set);
                } else {
                    cap.update_detail(id, set);
                }
            }
            out.push(d);
        }
        out
    }

    /// The conversations in the capture, newest first; subagents name their parent.
    pub fn llm_conversations(&self) -> Vec<ConvSummary> {
        let by = group(&self.all_digests());
        let prices = self.llm_prices();
        let parents = parents(&by);
        let mut out: Vec<ConvSummary> = by
            .iter()
            .map(|(k, ds)| {
                let mut s = summary_of(ds, &turns_of(ds), &prices);
                s.parent = parents.get(k).map(|p| key_text(*p));
                s
            })
            .collect();
        out.sort_by(|a, b| b.started.cmp(&a.started).then(b.first.cmp(&a.first)));
        out
    }

    /// A conversation with its turns, hints and the context of its last request.
    pub fn llm_conversation(&self, key: &str) -> Option<ConvDetail> {
        let by = group(&self.all_digests());
        let (k, ds) = by.iter().find(|(k, _)| key_text(**k) == key)?;
        let prices = self.llm_prices();
        let turns = turns_of(ds);
        let parents = parents(&by);
        let mut summary = summary_of(ds, &turns, &prices);
        summary.parent = parents.get(k).map(|p| key_text(*p));
        // The newest turn with a request that can be read carries the whole history.
        let last = ds.iter().rev().find_map(|d| self.llm(d.id));
        let (hints, breakdown) = match &last {
            Some(c) => (hints(c, ds, &turns, summary.window), Some(breakdown(c))),
            None => (vec![], None),
        };
        let mut children: Vec<String> = parents.iter().filter(|(_, p)| *p == k).map(|(c, _)| key_text(*c)).collect();
        children.sort();
        Some(ConvDetail { summary, turns, hints, breakdown, children })
    }

    /// LLM call `id` in its conversation: its context, and what changed from the turn before.
    pub fn llm_context(&self, id: SessionId) -> Option<CallContext> {
        let call = self.llm(id)?;
        let cur = self.llm_digest(id)?;
        let b = breakdown(&call);
        let window = llm::context_of(&call.model, &self.llm_prices());
        if cur.key == 0 {
            return Some(CallContext { key: None, turn: 1, turns: 1, prev: None, breakdown: b, diff: None, changed: None, cache: vec![], window });
        }
        let cap = self.capture();
        let same: Vec<Arc<Digest>> = {
            let mut v: Vec<Arc<Digest>> = cap.index.find_all(|s| s.llm_conv == key_text(cur.key)).into_iter().filter_map(|i| self.llm_digest(i)).filter(|d| d.key == cur.key).collect();
            if !v.iter().any(|d| d.id == id) {
                v.push(cur.clone());
            }
            v.sort_by_key(|d| d.id);
            v
        };
        let pos = same.iter().position(|d| d.id == id).unwrap_or(0);
        let prev = pos.checked_sub(1).map(|i| same[i].clone());
        let df = diff(prev.as_deref(), &cur);
        let cache = cache_notes(prev.as_deref(), &cur, &df);
        let changed = match (df.at, prev.as_ref()) {
            (Some(at), Some(p)) => self.llm(p.id).and_then(|pc| {
                let show = |m: Option<&llm::Message>| m.map(|m| format!("{}: {}", m.role, snippet(&m.parts.iter().map(|p| p.text.as_str()).collect::<Vec<_>>().join(" "), 300))).unwrap_or_default();
                Some((show(pc.messages.get(at)), show(call.messages.get(at))))
            }),
            _ => None,
        };
        Some(CallContext { key: Some(key_text(cur.key)), turn: pos + 1, turns: same.len(), prev: prev.map(|p| p.id), breakdown: b, diff: Some(df), changed, cache, window })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::{Message, ToolDef};

    fn text(t: &str) -> Part {
        Part { kind: "text".into(), text: t.into(), ..Default::default() }
    }
    fn msg(role: &str, parts: Vec<Part>) -> Message {
        Message { role: role.into(), parts }
    }
    fn call(system: &str, messages: Vec<Message>, input: u64, cache_read: u64) -> LlmCall {
        LlmCall {
            provider: "Anthropic".into(),
            api: Api::Messages,
            model: "claude-sonnet-4-5".into(),
            stream: true,
            system: vec![system.into()],
            messages,
            tools: vec![ToolDef { name: "Read".into(), description: "read a file".into(), size: 400 }, ToolDef { name: "Bash".into(), description: "run".into(), size: 800 }],
            params: vec![],
            output: vec![],
            stop_reason: None,
            usage: Some(Usage { input, output: 10, cache_read, cache_write: 0, reasoning: 0 }),
            cost: None,
            error: None,
            notes: vec![],
            cache_marks: vec!["messages[0]".into()],
        }
    }
    fn digest(id: SessionId, started_s: i64, c: &LlmCall) -> Arc<Digest> {
        let mut d = SessionDetail::default();
        d.summary.started_at = started_s * 1_000_000;
        d.summary.duration_ms = Some(1_000);
        Arc::new(Digest::new(id, &d, c))
    }

    #[test]
    fn estimate_is_in_the_right_range() {
        let e = estimate_tokens("The quick brown fox jumps over the lazy dog.");
        assert!((9..=14).contains(&e), "{e}");
        let json = r#"{"path": "/src/main.rs", "line": 12}"#;
        assert!((12..=24).contains(&estimate_tokens(json)));
        let long = format!("{} … (40000 characters)", "word ".repeat(2000));
        assert!(estimate_tokens(&long) > 7_000, "a shortened text counts at its full length");
    }

    #[test]
    fn agent_text_is_told_apart() {
        let t = "<system-reminder>\nAs you answer, use this context:\nContents of /repo/CLAUDE.md (project instructions):\nUse tabs.\nContents of /home/u/.claude/CLAUDE.md (user's private global instructions):\nBe brief.\n</system-reminder>\nFix the bug in main.rs";
        let segs = segments(t);
        let labels: Vec<(Seg, String)> = segs.iter().map(|(s, l, _)| (*s, l.clone())).collect();
        assert_eq!(labels[1], (Seg::Instructions, "/repo/CLAUDE.md".into()));
        assert_eq!(labels[2], (Seg::Instructions, "/home/u/.claude/CLAUDE.md".into()));
        assert_eq!(labels.last().unwrap().0, Seg::Text);
        assert_eq!(own_text(&msg("user", vec![text(t)])), "Fix the bug in main.rs");
        let codex = segments("# AGENTS.md instructions for /repo\n\n<INSTRUCTIONS>\nRun tests.\n</INSTRUCTIONS>");
        assert_eq!(codex[0].0, Seg::Instructions);
        let env = segments("<environment_context>\n  <cwd>/repo</cwd>\n</environment_context>");
        assert_eq!(env[0].0, Seg::Context);
        let skills = segments("<system-reminder>The following skills are available for use with the Skill tool: pdf</system-reminder>");
        assert_eq!(skills[0].0, Seg::Skills);
    }

    #[test]
    fn turns_of_one_run_are_one_conversation() {
        let reminder = "<system-reminder>today is 2026-10-10</system-reminder>";
        let m1 = msg("user", vec![text(reminder), text("Refactor the parser")]);
        let a1 = msg("assistant", vec![Part { kind: "toolCall".into(), name: Some("Read".into()), id: Some("t1".into()), text: "{\"file\":\"p.rs\"}".into() }]);
        let r1 = msg("user", vec![Part { kind: "toolResult".into(), id: Some("t1".into()), text: "fn parse() {}".repeat(50), ..Default::default() }]);
        let c1 = call("You are Claude Code.", vec![m1.clone()], 5_000, 0);
        let c2 = call("You are Claude Code.", vec![m1.clone(), a1.clone(), r1.clone()], 6_000, 4_900);
        let other = call("You are Claude Code.", vec![msg("user", vec![text(reminder), text("Write docs")])], 5_000, 0);
        let d1 = digest(1, 0, &c1);
        let d2 = digest(2, 10, &c2);
        let d3 = digest(3, 20, &other);
        assert_eq!(d1.key, d2.key, "same system and first prompt");
        assert_ne!(d1.key, d3.key, "another first prompt");
        let by = group(&[d1.clone(), d2.clone(), d3]);
        assert_eq!(by.len(), 2);
        let turns = turns_of(&by[&d1.key]);
        assert_eq!(turns[0].diff.kind, "first");
        assert_eq!(turns[1].diff.kind, "append");
        assert_eq!(turns[1].diff.added, 2);
        assert!(turns[1].cache.is_empty(), "the cache served the start");
    }

    #[test]
    fn cache_misses_are_explained() {
        let m1 = msg("user", vec![text("Refactor the parser")]);
        let m2 = msg("assistant", vec![text("Done.")]);
        let c1 = call("You are Claude Code.", vec![m1.clone(), m2.clone()], 20_000, 0);
        // An earlier message changed, 7 minutes later, and the model too.
        let mut c2 = call("You are Claude Code.", vec![m1.clone(), msg("assistant", vec![text("Done!")]), msg("user", vec![text("thanks")])], 21_000, 0);
        c2.model = "claude-opus-4-5".into();
        let d1 = digest(1, 0, &c1);
        let d2 = digest(2, 7 * 60 + 1, &c2);
        let t = turns_of(&[d1, d2]);
        let codes: Vec<&str> = t[1].cache.iter().map(|c| c.code).collect();
        assert_eq!(t[1].diff.kind, "changed");
        assert_eq!(t[1].diff.at, Some(1));
        assert_eq!(codes, ["miss", "modelChanged", "messageChanged", "expired"]);
        assert_eq!(t[1].cache[0].args["tokens"], "20000");
        // Without cache marks the reason is that.
        let mut c3 = call("You are Claude Code.", vec![m1.clone(), m2.clone(), msg("user", vec![text("more")])], 21_000, 0);
        c3.cache_marks.clear();
        let t = turns_of(&[digest(1, 0, &c1), digest(2, 10, &c3)]);
        assert_eq!(t[1].cache.iter().map(|c| c.code).collect::<Vec<_>>(), ["miss", "noMarks"]);
    }

    #[test]
    fn breakdown_scales_to_the_usage() {
        let t = "<system-reminder>Contents of /r/CLAUDE.md (project):\nrules rules rules</system-reminder>do it";
        let mut c = call("You are an agent.", vec![msg("user", vec![text(t)])], 1_000, 0);
        c.messages.push(msg("assistant", vec![Part { kind: "toolCall".into(), name: Some("Read".into()), id: Some("x".into()), text: "{}".into() }]));
        c.messages.push(msg("user", vec![Part { kind: "toolResult".into(), id: Some("x".into()), text: "data ".repeat(400), ..Default::default() }]));
        let b = breakdown(&c);
        assert_eq!(b.actual, Some(1_000));
        let total: u64 = b.slices.iter().map(|s| s.tokens).sum();
        assert!((995..=1005).contains(&total), "{total}");
        assert_eq!(b.slices[0].category, "toolResults");
        assert_eq!(b.slices[0].label, "Read", "a result is named by its call");
        assert!(b.slices.iter().any(|s| s.category == "instructions" && s.label == "/r/CLAUDE.md"));
        assert!(b.slices.iter().any(|s| s.category == "tools" && s.label == "Bash"));
    }

    #[test]
    fn hints_find_waste() {
        let read = |id: &str| Part { kind: "toolCall".into(), name: Some("Read".into()), id: Some(id.into()), text: "{\"file\":\"big.rs\"}".into() };
        let res = |id: &str| Part { kind: "toolResult".into(), id: Some(id.into()), text: "x = 1;\n".repeat(400), ..Default::default() };
        let rem = text(&format!("<system-reminder>{}</system-reminder>", "Remember the todo list. ".repeat(10)));
        let mut msgs = vec![msg("user", vec![text("go")])];
        for i in 0..3 {
            let id = format!("r{i}");
            msgs.push(msg("assistant", vec![read(&id)]));
            msgs.push(msg("user", vec![res(&id), rem.clone()]));
        }
        // Two different searches with the same answer.
        for (id, pat) in [("g1", "foo"), ("g2", "fo+")] {
            msgs.push(msg("assistant", vec![Part { kind: "toolCall".into(), name: Some("Grep".into()), id: Some(id.into()), text: format!("{{\"pattern\":\"{pat}\"}}") }]));
            msgs.push(msg("user", vec![Part { kind: "toolResult".into(), id: Some(id.into()), text: "src/a.rs:1 foo\n".repeat(40), ..Default::default() }]));
        }
        let c = call("sys", msgs, 9_000, 0);
        let ds: Vec<Arc<Digest>> = (1..=3).map(|i| digest(i, i as i64, &c)).collect();
        let h = hints(&c, &ds, &turns_of(&ds), Some(10_000));
        let codes: Vec<&str> = h.iter().map(|h| h.code).collect();
        for want in ["repeatCall", "dupReminder", "unusedTools", "window"] {
            assert!(codes.contains(&want), "{want} in {codes:?}");
        }
        assert!(h.iter().find(|h| h.code == "repeatCall").unwrap().tokens > 0, "the later results count");
        let dups: Vec<&Hint> = h.iter().filter(|h| h.code == "dupResult").collect();
        assert_eq!(dups.len(), 1, "results of a repeated call are counted once: {codes:?}");
        assert_eq!(dups[0].args["tool"], "Grep");
        let unused = h.iter().find(|h| h.code == "unusedTools").unwrap();
        assert_eq!(unused.args["names"], "Bash");
        assert_eq!(h.iter().filter(|h| h.code == "bigResult").count(), 0, "no result is that large here");
    }

    #[test]
    fn subagents_find_their_parent() {
        let task = "Search the codebase for every caller of parse_config and list them";
        let mut parent = call("You are Claude Code.", vec![msg("user", vec![text("Find callers")])], 3_000, 0);
        let pd = {
            let mut d = SessionDetail::default();
            d.summary.started_at = 0;
            parent.output.push(Part { kind: "toolCall".into(), name: Some("Task".into()), id: Some("t".into()), text: format!("{{\n  \"prompt\": \"{task}\"\n}}") });
            Arc::new(Digest::new(1, &d, &parent))
        };
        let child = call("You are a subagent.", vec![msg("user", vec![text(task)])], 2_000, 0);
        let cd = digest(2, 5, &child);
        let by = group(&[pd.clone(), cd.clone()]);
        assert_eq!(parents(&by).get(&cd.key), Some(&pd.key));
    }
}
