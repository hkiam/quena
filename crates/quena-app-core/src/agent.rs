//! Conversations of AI agents (Claude Code, Codex, own apps): the LLM calls of one run put
//! together, what fills each request's context, what changed from one turn to the next, why
//! the provider's prompt cache missed, and where tokens go to waste.
//!
//! An agent sends its whole conversation with every turn. Each call is kept as a small digest
//! (hashes of its messages, tools and settings, its usage), and every call is linked to the
//! one it continues:
//!
//! - the request Claude Code names as the previous one (`cc_prev_req` of its attribution
//!   block), or the response a `previous_response_id` names;
//! - else, among earlier calls of the same session (Claude Code's session id, Codex's
//!   session/thread id or `prompt_cache_key`) with the same start of the system prompt and the
//!   same first prompt of the user, the one whose messages this call carries furthest.
//!
//! Calls linked that way form a conversation. A call that no later one continues while the
//! conversation goes on is a side call (Claude Code's prompt suggestions, summaries).
//! Subagents are conversations of their own, linked to the one that started them by the
//! parent session id, Claude Code's `cc_is_subagent`, or the task prompt a tool call carried.

use crate::AppCore;
use crate::llm::{self, Api, LlmCall, Part, Usage};
use quena_model::{SessionDetail, SessionId};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

/// Flag naming the conversation of an LLM call (kept in archives).
pub const CONV_FLAG: &str = "x-quena-llm-conv";

/// Tokens an image is counted with when its size is not known.
const IMAGE_TOKENS: u64 = 1_600;
/// The system prompt Anthropic adds when a request offers tools.
const ANTHROPIC_TOOL_OVERHEAD: u64 = 346;
/// Cache lifetimes: Anthropic's default and long one; OpenAI keeps prefixes 5–10 minutes, or
/// 24 hours when asked.
const CACHE_TTL_MS: i64 = 5 * 60_000;
const CACHE_TTL_LONG_MS: i64 = 60 * 60_000;
const CACHE_TTL_24H_MS: i64 = 24 * 60 * 60_000;
/// Calls without a session id further apart than this are not linked by their messages alone.
const LINK_GAP_US: i64 = 30 * 60 * 1_000_000;
/// Characters of a tool argument's start a subagent's first prompt is matched by.
const HEAD: usize = 60;
/// A subagent is looked for among calls this long before it started.
const PARENT_WINDOW_US: i64 = 2 * 60 * 60 * 1_000_000;

// ------------------------------------------------------------------ hashing

fn fnv(mut h: u64, bytes: &[u8]) -> u64 {
    for b in bytes {
        h = (h ^ *b as u64).wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

const FNV0: u64 = 0xcbf2_9ce4_8422_2325;

/// FNV-1a of a text.
pub fn hash_text(s: &str) -> u64 {
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
    format!("{k:016x}")[..10].to_string()
}

// ------------------------------------------------------------------ token estimate

/// Tokens of `s`, estimated the way BPE tokenizers split text: a word piece per few letters,
/// one token per two marks in a row (`{"`, `":`), one per line break. Rough on its own; the
/// breakdown scales the estimates to the usage the provider reported.
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
    let (mut t, mut word, mut marks, mut newline) = (0u64, 0u64, 0u64, false);
    let flush = |t: &mut u64, word: &mut u64, marks: &mut u64| {
        *t += word.div_ceil(5) + marks.div_ceil(2);
        *word = 0;
        *marks = 0;
    };
    for c in s.chars() {
        if c.is_alphanumeric() {
            if marks > 0 {
                t += marks.div_ceil(2);
                marks = 0;
            }
            word += if c.is_ascii() { 1 } else { 2 };
            newline = false;
        } else if c == '\n' {
            flush(&mut t, &mut word, &mut marks);
            if !newline {
                t += 1;
            }
            newline = true;
        } else if c.is_whitespace() {
            flush(&mut t, &mut word, &mut marks);
        } else {
            if word > 0 {
                t += word.div_ceil(5);
                word = 0;
            }
            marks += 1;
            newline = false;
        }
    }
    flush(&mut t, &mut word, &mut marks);
    t
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
    /// The environment, open files, output of commands the user ran.
    Context,
    /// The summary an agent continues with after compacting the conversation.
    Summary,
}

/// Tags agents put around text they add: its kind.
const TAGS: &[(&str, Seg)] = &[
    ("system-reminder", Seg::Reminder),
    ("local-command-caveat", Seg::Reminder),
    ("command-message", Seg::Reminder),
    ("current_time_reminder", Seg::Reminder),
    ("turn_aborted", Seg::Reminder),
    ("environment_context", Seg::Context),
    ("environment_details", Seg::Context),
    ("ide_opened_file", Seg::Context),
    ("ide_selection", Seg::Context),
    ("command-name", Seg::Context),
    ("command-args", Seg::Context),
    ("local-command-stdout", Seg::Context),
    ("local-command-stderr", Seg::Context),
    ("bash-input", Seg::Context),
    ("bash-stdout", Seg::Context),
    ("bash-stderr", Seg::Context),
    ("user_shell_command", Seg::Context),
    ("skills_instructions", Seg::Skills),
];

/// The stretches of `text` with what they are and a label (the instruction file's path, the
/// tag).
fn segments(text: &str) -> Vec<(Seg, String, &str)> {
    let t = text.trim_start();
    // Codex sends AGENTS.md as a message of its own.
    if t.starts_with("# AGENTS.md instructions") || t.starts_with("<user_instructions>") || t.starts_with("<INSTRUCTIONS>") {
        let label = t.lines().next().and_then(|l| l.strip_prefix("# ")).map(|l| l.trim_end_matches(':').to_string()).unwrap_or_else(|| "AGENTS.md".into());
        return vec![(Seg::Instructions, label, text)];
    }
    if t.starts_with("This session is being continued from a previous conversation") {
        return vec![(Seg::Summary, String::new(), text)];
    }
    // Gemini CLI starts every chat with this.
    if t.starts_with("This is the Gemini CLI. We are setting up the context") {
        return vec![(Seg::Context, "setup".into(), text)];
    }
    let mut out = Vec::new();
    let mut rest = text;
    loop {
        // The first tag in what is left.
        let mut next: Option<(usize, &str, Seg)> = None;
        for (tag, seg) in TAGS {
            let open = format!("<{tag}>");
            if let Some(i) = rest.find(&open)
                && next.is_none_or(|n| i < n.0)
            {
                next = Some((i, tag, *seg));
            }
        }
        let Some((i, tag, seg)) = next else { break };
        if i > 0 {
            out.push((Seg::Text, String::new(), &rest[..i]));
        }
        let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
        let end = rest[i + open.len()..].find(&close).map(|e| i + open.len() + e + close.len()).unwrap_or(rest.len());
        let block = &rest[i..end];
        if tag == "system-reminder" {
            out.extend(reminder_parts(block));
        } else {
            out.push((seg, tag.to_string(), block));
        }
        rest = &rest[end..];
    }
    if !rest.is_empty() {
        out.push((Seg::Text, String::new(), rest));
    }
    out
}

/// A `<system-reminder>` block: instruction files it carries (Claude Code: "Contents of
/// /path/CLAUDE.md (project instructions, …):"), a list of skills, or a note.
fn reminder_parts(block: &str) -> Vec<(Seg, String, &str)> {
    const MARK: &str = "Contents of ";
    let starts: Vec<usize> = block.match_indices(MARK).map(|(i, _)| i).filter(|i| block[i + MARK.len()..].lines().next().is_some_and(|l| l.contains(".md"))).collect();
    if starts.is_empty() {
        let lower = block.to_ascii_lowercase();
        let seg = if lower.contains("skill") && (lower.contains("skills are available") || lower.contains("skill tool") || lower.contains("available skills")) { Seg::Skills } else { Seg::Reminder };
        return vec![(seg, String::new(), block)];
    }
    let mut out = Vec::new();
    if starts[0] > 0 {
        out.push((Seg::Reminder, String::new(), &block[..starts[0]]));
    }
    for (n, &s) in starts.iter().enumerate() {
        let end = starts.get(n + 1).copied().unwrap_or(block.len());
        let line = block[s + MARK.len()..].lines().next().unwrap_or("");
        // `/path/CLAUDE.md (project instructions, …):` or `/path/CLAUDE.md:`.
        let path = match line.find(".md") {
            Some(i) => &line[..i + 3],
            None => line.trim_end_matches(':'),
        };
        out.push((Seg::Instructions, path.trim().to_string(), &block[s..end]));
    }
    out
}

/// The user's own words in a message: its text without what the agent added; a slash command
/// counts by its name and arguments.
fn own_text(m: &llm::Message) -> String {
    let mut out = String::new();
    let mut command = String::new();
    for p in m.parts.iter().filter(|p| p.kind == "text") {
        for (seg, label, t) in segments(&p.text) {
            match seg {
                Seg::Text => out.push_str(t),
                Seg::Context if label == "command-name" || label == "command-args" => {
                    let inner = t.trim_start_matches(&format!("<{label}>")).trim_end_matches(&format!("</{label}>"));
                    command.push_str(inner.trim());
                    command.push(' ');
                }
                _ => {}
            }
        }
    }
    let out = out.trim();
    if out.is_empty() { command.trim().to_string() } else { out.to_string() }
}

/// The first prompt of the user: the first user message with words of its own.
fn first_prompt(call: &LlmCall) -> String {
    call.messages.iter().filter(|m| m.role == "user").map(own_text).find(|t| !t.is_empty()).unwrap_or_default()
}

fn snippet(s: &str, n: usize) -> String {
    let one: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if one.chars().count() <= n { one } else { format!("{}…", one.chars().take(n).collect::<String>()) }
}

fn norm(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The start of a text as a subagent's first prompt is matched by (`None`: too short to tell).
fn head_of(s: &str) -> Option<String> {
    let n = norm(s);
    (n.chars().count() >= 20).then(|| n.chars().take(HEAD).collect())
}

/// The starts of the string values in a tool call's arguments (JSON): a subagent started with
/// one of them as its prompt.
fn call_heads(args: &str, out: &mut Vec<String>) {
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::String(s) => out.extend(head_of(s)),
            Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            Value::Object(o) => o.values().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    if let Ok(v) = serde_json::from_str::<Value>(args) {
        walk(&v, out);
    }
}

/// The agent that sent a request, by its User-Agent (`claude-cli/2.0.14 (external, cli)` →
/// `claude-cli/2.0.14`).
pub fn agent_of(user_agent: &str) -> String {
    user_agent.split_whitespace().next().unwrap_or("").to_string()
}

/// Settings that are part of what a provider caches (a change makes the cache miss).
const CACHED_SETTINGS: &[&str] = &["thinking", "tool_choice", "reasoning.effort", "reasoning_effort", "output_config"];

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
    /// Same session, same start of the system prompt, same first prompt.
    pub group: u64,
    /// The agent's session (Claude Code's session id, Codex's thread, `prompt_cache_key`).
    pub session: Option<String>,
    /// The session that started this one (a subagent's parent).
    pub parent_session: Option<String>,
    /// The agent says this is a subagent.
    pub subagent: bool,
    /// This response's request id, and the one the agent names as the previous request.
    pub request_id: Option<String>,
    pub prev_request: Option<String>,
    /// OpenAI Responses: this response's id and the one the request continues.
    pub response_id: Option<String>,
    pub prev_response: Option<String>,
    pub system: Vec<u64>,
    /// Tools by name: hash of the definition, its estimated tokens.
    pub tools: Vec<(String, u64, u64)>,
    /// Settings the cache depends on (name, value).
    pub settings: Vec<(String, String)>,
    pub messages: Vec<u64>,
    pub usage: Option<Usage>,
    pub cost: Option<f64>,
    /// Answered from Quena's agent cache: nothing was spent.
    pub hit: bool,
    /// The first prompt (shortened): the conversation's title.
    pub prompt: String,
    /// Its start as subagents are matched by.
    pub prompt_full: String,
    /// Tools the answer calls.
    pub calls: Vec<String>,
    /// Starts of the string values of those calls' arguments.
    pub call_heads: Vec<String>,
    pub stop: Option<String>,
    pub error: bool,
    pub cache_marks: usize,
    pub cache_long: bool,
    /// Estimated input tokens.
    pub est: u64,
}

fn header<'a>(d: &'a SessionDetail, name: &str) -> Option<&'a str> {
    d.request.headers.get(name).map(str::trim).filter(|v| !v.is_empty())
}

impl Digest {
    pub fn new(id: SessionId, d: &SessionDetail, call: &LlmCall) -> Digest {
        let prompt = first_prompt(call);
        let system_text = call.system.join("\n");
        let head: String = system_text.chars().take(200).collect();
        let attr = |k: &str| call.attribution.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        let param = |k: &str| call.params.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        // Claude Code sends its session in a header and in metadata.user_id (JSON).
        let user: Option<Value> = call.user.as_deref().and_then(|u| serde_json::from_str(u).ok());
        let from_user = |k: &str| user.as_ref().and_then(|u| u.get(k)).and_then(|v| v.as_str()).map(str::to_string);
        let session = header(d, "x-claude-code-session-id")
            .map(str::to_string)
            .or_else(|| from_user("session_id"))
            .or_else(|| header(d, "session_id").or_else(|| header(d, "session-id")).or_else(|| header(d, "thread_id")).map(str::to_string))
            .or_else(|| param("prompt_cache_key"));
        let parent_session = from_user("parent_session_id").or_else(|| header(d, "x-codex-parent-thread-id").map(str::to_string));
        let subagent = attr("cc_is_subagent").as_deref() == Some("true") || header(d, "x-openai-subagent").is_some() || parent_session.is_some();
        // Embeddings have no conversation.
        let group = if call.api == Api::Embeddings {
            0
        } else {
            let base = fnv(fnv(FNV0, session.as_deref().unwrap_or("").as_bytes()), &[1]);
            if prompt.is_empty() && head.is_empty() {
                fnv(base, &call.messages.first().map(hash_message).unwrap_or(0).to_le_bytes())
            } else {
                fnv(fnv(fnv(base, head.as_bytes()), &[1]), prompt.as_bytes())
            }
        };
        let mut settings: Vec<(String, String)> = CACHED_SETTINGS.iter().filter_map(|k| param(k).map(|v| (k.to_string(), v))).collect();
        if let Some(b) = header(d, "anthropic-beta") {
            settings.push(("anthropic-beta".into(), b.to_string()));
        }
        let mut heads = Vec::new();
        for p in call.output.iter().filter(|p| p.kind == "toolCall") {
            call_heads(&p.text, &mut heads);
        }
        let resp = d.response.as_ref();
        Digest {
            id,
            started: d.summary.started_at,
            duration_ms: d.summary.duration_ms,
            provider: call.provider.clone(),
            api: call.api,
            model: call.model.clone(),
            agent: agent_of(header(d, "user-agent").unwrap_or("")),
            group,
            session,
            parent_session,
            subagent,
            request_id: resp.and_then(|r| r.headers.get("request-id").or_else(|| r.headers.get("x-request-id"))).map(str::to_string),
            prev_request: attr("cc_prev_req"),
            response_id: call.response_id.clone(),
            prev_response: param("previous_response_id"),
            system: call.system.iter().map(|s| hash_text(s)).collect(),
            tools: call.tools.iter().map(|t| (t.name.clone(), t.hash, t.tokens)).collect(),
            settings,
            messages: call.messages.iter().map(hash_message).collect(),
            usage: call.usage,
            cost: call.cost.as_ref().map(|c| c.usd),
            hit: d.extra_flags.iter().any(|(k, _)| k == crate::llm_cache::CACHE_FLAG),
            prompt: snippet(&prompt, 300),
            prompt_full: prompt.chars().take(HEAD * 2).collect(),
            calls: call.output.iter().filter(|p| p.kind == "toolCall").map(|p| p.name.clone().unwrap_or_default()).collect(),
            call_heads: heads,
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

    /// Usage that counts: not for answers from Quena's agent cache.
    fn spent(&self) -> Option<Usage> {
        self.usage.filter(|_| !self.hit)
    }
}

// ------------------------------------------------------------------ breakdown

/// One slice of a request's context.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Slice {
    /// `system`, `tools`, `overhead`, `instructions`, `skills`, `reminders`, `context`,
    /// `summary`, `user`, `assistant`, `thinking`, `toolCalls`, `toolResults`, `images`,
    /// `server` (history the provider keeps, not sent again), `other`.
    pub category: &'static str,
    /// Tool name, instruction file, … (empty: the category as a whole).
    pub label: String,
    /// Tokens: the estimate scaled to the usage the provider reported (fixed amounts, like
    /// images and the provider's tool prompt, are not scaled).
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

/// Categories counted with a fixed number of tokens.
fn fixed(cat: &str) -> bool {
    matches!(cat, "images" | "overhead")
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
        add("tools", t.name.clone(), t.tokens.max(1));
    }
    if call.api == Api::Messages && !call.tools.is_empty() {
        add("overhead", String::new(), ANTHROPIC_TOOL_OVERHEAD);
    }
    // Tool results by the name of the call they answer.
    let names: HashMap<&str, &str> = call.messages.iter().flat_map(|m| &m.parts).filter(|p| p.kind == "toolCall").filter_map(|p| Some((p.id.as_deref()?, p.name.as_deref()?))).collect();
    for m in &call.messages {
        for p in &m.parts {
            match p.kind.as_str() {
                "text" if m.role == "user" || m.role == "developer" || m.role == "system" => {
                    for (seg, label, t) in segments(&p.text) {
                        let est = estimate_tokens(t);
                        match seg {
                            // Notes in the agent's own role (Codex developer items) are notes.
                            Seg::Text if m.role != "user" => add("reminders", String::new(), est),
                            Seg::Text => add("user", String::new(), est),
                            Seg::Reminder => add("reminders", String::new(), est),
                            Seg::Instructions => add("instructions", label, est),
                            Seg::Skills => add("skills", String::new(), est),
                            Seg::Context => add("context", String::new(), est),
                            Seg::Summary => add("summary", String::new(), est),
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
                _ => add("other", p.name.clone().unwrap_or_default(), estimate_tokens(&p.text)),
            }
        }
    }
    let estimated: u64 = acc.values().map(|(e, _)| e).sum();
    let actual = call.usage.map(|u| u.input).filter(|i| *i > 0);
    let fixed_est: u64 = acc.iter().filter(|((c, _), _)| fixed(c)).map(|(_, (e, _))| e).sum();
    // History the provider keeps (`previous_response_id`): the reported input is far more than
    // the request carries. It shows as a slice of its own instead of inflating the others.
    let server_side = call.params.iter().any(|(k, _)| k == "previous_response_id");
    let mut server = 0;
    let scale = match actual {
        Some(a) if server_side && a > estimated.saturating_mul(3) / 2 => {
            server = a - estimated;
            1.0
        }
        Some(a) if estimated > fixed_est && a > fixed_est => (a - fixed_est) as f64 / (estimated - fixed_est) as f64,
        _ => 1.0,
    };
    let mut slices: Vec<Slice> = acc
        .into_iter()
        .map(|((category, label), (est, count))| {
            let tokens = if fixed(category) { est } else { ((est as f64) * scale).round() as u64 };
            Slice { category, label, tokens, est, count }
        })
        .collect();
    if server > 0 {
        slices.push(Slice { category: "server", label: String::new(), tokens: server, est: 0, count: 1 });
    }
    slices.sort_by(|a, b| b.tokens.cmp(&a.tokens).then_with(|| a.category.cmp(b.category)).then_with(|| a.label.cmp(&b.label)));
    Breakdown { slices, estimated, actual }
}

// ------------------------------------------------------------------ turn diff and cache

/// How a turn's request differs from the one it continues.
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
    /// Settings the cache depends on that changed (`thinking`, `anthropic-beta` …).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub settings_changed: Vec<String>,
    pub model_changed: bool,
    /// From the end of the previous call to the start of this one (ms).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gap_ms: Option<i64>,
}

fn common_prefix(a: &[u64], b: &[u64]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

fn diff(prev: Option<&Digest>, cur: &Digest) -> TurnDiff {
    let Some(p) = prev else { return TurnDiff { kind: "first", added: cur.messages.len(), ..Default::default() } };
    let common = common_prefix(&p.messages, &cur.messages);
    let kind = if common == p.messages.len() && common == cur.messages.len() {
        "same"
    } else if common == p.messages.len() {
        "append"
    } else {
        "changed"
    };
    let pn: Vec<&String> = p.tools.iter().map(|t| &t.0).collect();
    let cn: Vec<&String> = cur.tools.iter().map(|t| &t.0).collect();
    let pset: HashSet<&String> = pn.iter().copied().collect();
    let cset: HashSet<&String> = cn.iter().copied().collect();
    let phash: HashMap<&str, u64> = p.tools.iter().map(|t| (t.0.as_str(), t.1)).collect();
    fn kept_order<'a>(v: &[&'a String], other: &HashSet<&String>) -> Vec<&'a String> {
        v.iter().filter(|n| other.contains(*n)).copied().collect()
    }
    let pset_settings: HashMap<&str, &str> = p.settings.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let cset_settings: HashMap<&str, &str> = cur.settings.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let mut settings_changed: Vec<String> = pset_settings.keys().chain(cset_settings.keys()).filter(|k| pset_settings.get(*k) != cset_settings.get(*k)).map(|k| k.to_string()).collect();
    settings_changed.sort();
    settings_changed.dedup();
    TurnDiff {
        kind,
        at: (kind == "changed").then_some(common),
        added: cur.messages.len() - common,
        dropped: p.messages.len() - common,
        system_changed: p.system != cur.system,
        tools_added: cn.iter().filter(|n| !pset.contains(*n)).map(|n| n.to_string()).collect(),
        tools_removed: pn.iter().filter(|n| !cset.contains(*n)).map(|n| n.to_string()).collect(),
        tools_changed: cur.tools.iter().filter(|t| phash.get(t.0.as_str()).is_some_and(|h| *h != t.1)).map(|t| t.0.clone()).collect(),
        tools_reordered: kept_order(&pn, &cset) != kept_order(&cn, &pset),
        settings_changed,
        model_changed: p.model != cur.model,
        gap_ms: Some((cur.started - p.end_us()) / 1_000),
    }
}

/// Something about the provider's prompt cache for a turn.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CacheNote {
    /// `miss` (the cache did not serve the start it could have), then the reasons:
    /// `expired`, `systemChanged`, `toolsChanged`, `settingsChanged`, `messageChanged`,
    /// `modelChanged`, `noMarks`, `unknown`. On its own: `short` (marked for caching, but
    /// shorter than the provider caches).
    pub code: &'static str,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub args: BTreeMap<String, String>,
}

fn note(code: &'static str, args: &[(&str, String)]) -> CacheNote {
    CacheNote { code, args: args.iter().map(|(k, v)| (k.to_string(), v.clone())).collect() }
}

/// The shortest prompt the provider caches.
fn cache_min(d: &Digest) -> u64 {
    let m = d.model.to_ascii_lowercase();
    if d.api != Api::Messages {
        return 1_024;
    }
    if m.contains("haiku-3") || m.contains("3-haiku") || m.contains("3-5-haiku") {
        2_048
    } else if ["opus-4-5", "opus-4-6", "opus-4-7", "opus-5", "haiku-4-5", "sonnet-5"].iter().any(|x| m.contains(x)) {
        4_096
    } else {
        1_024
    }
}

/// Whether the cache missed for `cur` and why, judged against `base` (the turn it continues,
/// or the nearest before that with usage). `judged`: the provider reports cached tokens in
/// this conversation (else a missing cache read says nothing).
fn cache_notes(base: Option<&Digest>, cur: &Digest, judged: bool) -> Vec<CacheNote> {
    let (Some(b), Some(u)) = (base, cur.spent()) else { return vec![] };
    let Some(bu) = b.spent() else { return vec![] };
    if !judged {
        return vec![];
    }
    // What could have come from the cache: the previous request's input, at most this one's.
    let could = bu.input.min(u.input);
    let min = cache_min(cur);
    if could < min {
        return if cur.api == Api::Messages && cur.cache_marks > 0 && u.cache_read == 0 && u.input < min { vec![note("short", &[("min", min.to_string())])] } else { vec![] };
    }
    if u.cache_read * 2 >= could {
        return vec![];
    }
    let d = diff(Some(b), cur);
    let mut out = vec![note("miss", &[("tokens", could.saturating_sub(u.cache_read).to_string())])];
    if d.model_changed {
        out.push(note("modelChanged", &[("from", b.model.clone()), ("to", cur.model.clone())]));
    }
    if d.system_changed {
        out.push(note("systemChanged", &[]));
    }
    if !d.tools_added.is_empty() || !d.tools_removed.is_empty() || !d.tools_changed.is_empty() || d.tools_reordered {
        out.push(note("toolsChanged", &[("added", d.tools_added.len().to_string()), ("removed", d.tools_removed.len().to_string()), ("changed", d.tools_changed.len().to_string())]));
    }
    if !d.settings_changed.is_empty() {
        out.push(note("settingsChanged", &[("names", d.settings_changed.join(", "))]));
    }
    if let Some(at) = d.at {
        out.push(note("messageChanged", &[("n", (at + 1).to_string()), ("of", b.messages.len().to_string())]));
    }
    let ttl = if cur.settings.iter().any(|(k, v)| k == "prompt_cache_retention" && v.contains("24h")) {
        CACHE_TTL_24H_MS
    } else if cur.cache_long {
        CACHE_TTL_LONG_MS
    } else {
        CACHE_TTL_MS
    };
    if let Some(gap) = d.gap_ms
        && gap > ttl
    {
        out.push(note("expired", &[("minutes", (gap / 60_000).to_string()), ("ttl", (ttl / 60_000).to_string())]));
    }
    if cur.api == Api::Messages && cur.cache_marks == 0 {
        out.push(note("noMarks", &[]));
    }
    if out.len() == 1 {
        out.push(note("unknown", &[]));
    }
    out
}

// ------------------------------------------------------------------ conversations

/// The calls of a capture put into conversations.
#[derive(Debug, Default)]
pub struct Built {
    pub convs: Vec<Conv>,
    /// Conversation of each call.
    pub conv_of: HashMap<SessionId, usize>,
    /// The conversation that started each (subagents).
    pub parent: HashMap<usize, usize>,
}

/// One conversation.
#[derive(Debug)]
pub struct Conv {
    pub key: u64,
    /// Its calls, in the order they started.
    pub digests: Vec<Arc<Digest>>,
    /// The call each continues.
    pub pred: HashMap<SessionId, SessionId>,
    /// Calls no later one continues while the conversation goes on.
    pub side: HashSet<SessionId>,
}

impl Conv {
    fn get(&self, id: SessionId) -> Option<&Arc<Digest>> {
        self.digests.binary_search_by_key(&id, |d| d.id).ok().map(|i| &self.digests[i])
    }

    /// The call `id` continues.
    fn pred_of(&self, id: SessionId) -> Option<&Arc<Digest>> {
        self.pred.get(&id).and_then(|p| self.get(*p))
    }

    /// What `id` is judged against for the cache: the call it continues, or the nearest
    /// before that which used tokens.
    fn cache_base(&self, id: SessionId) -> Option<&Arc<Digest>> {
        let mut cur = self.pred_of(id);
        while let Some(d) = cur {
            if d.spent().is_some() && !d.error {
                return Some(d);
            }
            cur = self.pred_of(d.id);
        }
        None
    }

    /// The provider reports cached tokens here (Anthropic always).
    fn judged(&self) -> bool {
        self.digests.iter().any(|d| d.api == Api::Messages || d.spent().is_some_and(|u| u.cache_read > 0 || u.cache_write > 0))
    }

    fn main(&self) -> bool {
        !self.digests.iter().any(|d| d.subagent)
    }
}

/// The call `d` continues among `earlier` (all started before it; `same_group`: indices of
/// those of its group).
fn link<'a>(d: &Digest, earlier: &'a [Arc<Digest>], same_group: &[usize], by_request: &HashMap<&str, usize>, by_response: &HashMap<&str, usize>) -> Option<&'a Arc<Digest>> {
    // The request the agent names as the previous one: the last it sent, which may be another
    // agent's (a subagent's first call names its parent's); it counts when this call carries on
    // from it.
    if let Some(e) = d.prev_request.as_deref().and_then(|r| by_request.get(r)).map(|i| &earlier[*i])
        && (e.group == d.group || common_prefix(&e.messages, &d.messages) > 0)
    {
        return Some(e);
    }
    if let Some(i) = d.prev_response.as_deref().and_then(|r| by_response.get(r)) {
        return Some(&earlier[*i]);
    }
    // The call of the same group whose messages this one carries furthest (the latest of
    // equals): a turn extends it, a retry repeats it, an edit changes its end.
    let mut best: Option<(&Arc<Digest>, usize)> = None;
    for e in same_group.iter().rev().map(|i| &earlier[*i]) {
        if d.session.is_none() && d.started - e.end_us() > LINK_GAP_US {
            continue;
        }
        let common = common_prefix(&e.messages, &d.messages);
        if common == 0 || (common < e.messages.len() && common * 2 < e.messages.len()) {
            continue;
        }
        // A call this one carries whole is what it continues: the latest such (searching from
        // the newest) wins over any it only shares a start with.
        if common == e.messages.len() {
            return Some(e);
        }
        if best.is_none_or(|(_, c)| common > c) {
            best = Some((e, common));
        }
    }
    best.map(|(e, _)| e)
}

/// Conversations of `digests` (any order).
pub fn build(digests: &[Arc<Digest>]) -> Built {
    let mut all: Vec<Arc<Digest>> = digests.iter().filter(|d| d.group != 0).cloned().collect();
    all.sort_by_key(|d| (d.started, d.id));
    let mut by_request: HashMap<&str, usize> = HashMap::new();
    let mut by_response: HashMap<&str, usize> = HashMap::new();
    let mut built = Built::default();
    // Earlier calls by group, for linking (indices into `all`).
    let mut groups: HashMap<u64, Vec<usize>> = HashMap::new();
    for (i, d) in all.iter().enumerate() {
        let same = groups.entry(d.group).or_default();
        let pred = link(d, &all[..i], same, &by_request, &by_response).map(|p| p.id);
        same.push(i);
        let ci = match pred.and_then(|p| built.conv_of.get(&p).copied()) {
            Some(ci) => ci,
            None => {
                built.convs.push(Conv { key: fnv(d.group, &d.id.to_le_bytes()), digests: vec![], pred: HashMap::new(), side: HashSet::new() });
                built.convs.len() - 1
            }
        };
        let c = &mut built.convs[ci];
        c.digests.push(d.clone());
        if let Some(p) = pred {
            c.pred.insert(d.id, p);
        }
        built.conv_of.insert(d.id, ci);
        if let Some(r) = d.request_id.as_deref() {
            by_request.insert(r, i);
        }
        if let Some(r) = d.response_id.as_deref() {
            by_response.insert(r, i);
        }
    }
    for c in &mut built.convs {
        c.digests.sort_by_key(|d| d.id);
        // The main line: from the newest call back to the first; calls off it are side calls.
        let mut main: HashSet<SessionId> = HashSet::new();
        let mut cur = c.digests.iter().max_by_key(|d| (d.started, d.id)).map(|d| d.id);
        while let Some(id) = cur {
            if !main.insert(id) {
                break;
            }
            cur = c.pred.get(&id).copied();
        }
        let continued: HashSet<SessionId> = c.pred.values().copied().collect();
        c.side = c.digests.iter().map(|d| d.id).filter(|id| !main.contains(id) && !continued.contains(id)).collect();
    }
    built.parent = parents(&built);
    built
}

/// The conversation that started each subagent: by the parent session the agent names, as
/// the agent's own subagent in the same session, or by its first prompt in a tool call of
/// another conversation shortly before it started.
fn parents(b: &Built) -> HashMap<usize, usize> {
    let mut out = HashMap::new();
    // Starts of tool arguments: which calls carried them, when.
    let mut heads: HashMap<&str, Vec<(i64, usize, Option<&str>)>> = HashMap::new();
    for (ci, c) in b.convs.iter().enumerate() {
        for d in &c.digests {
            for h in &d.call_heads {
                heads.entry(h.as_str()).or_default().push((d.started, ci, d.session.as_deref()));
            }
        }
    }
    for (ci, c) in b.convs.iter().enumerate() {
        let first = &c.digests[0];
        let start = first.started;
        // The latest conversation started before `start` that matches.
        let latest = |f: &dyn Fn(usize, &Conv) -> bool| b.convs.iter().enumerate().filter(|(pi, p)| *pi != ci && p.digests[0].started <= start && f(*pi, p)).max_by_key(|(_, p)| p.digests[0].started).map(|(pi, _)| pi);
        let by_session = first.parent_session.as_deref().and_then(|ps| latest(&|_, p| p.main() && p.digests[0].session.as_deref() == Some(ps)));
        let by_text = || {
            let head = head_of(&first.prompt_full)?;
            heads
                .get(head.as_str())?
                .iter()
                .filter(|x| x.0 <= start && x.0 >= start - PARENT_WINDOW_US && x.1 != ci)
                .filter(|x| first.session.is_none() || x.2.is_none() || x.2 == first.session.as_deref())
                .max_by_key(|x| x.0)
                .map(|x| x.1)
        };
        let same_session = || first.session.as_deref().filter(|_| first.subagent).and_then(|s| latest(&|_, p| p.main() && p.digests[0].session.as_deref() == Some(s)));
        if let Some(p) = by_session.or_else(by_text).or_else(same_session) {
            out.insert(ci, p);
        }
    }
    out
}

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
    /// Of those, side calls and answers from Quena's agent cache.
    pub side: u32,
    pub hits: u32,
    pub first: SessionId,
    pub last: SessionId,
    /// Microseconds since the epoch.
    pub started: i64,
    pub ended: i64,
    /// Tokens spent (answers from the agent cache do not count).
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
    pub subagent: bool,
}

/// One turn of a conversation.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Turn {
    pub id: SessionId,
    /// The call it continues.
    pub prev: Option<SessionId>,
    pub started: i64,
    pub duration_ms: Option<u32>,
    pub model: String,
    pub usage: Option<Usage>,
    pub cost: Option<f64>,
    pub stop: Option<String>,
    pub error: bool,
    /// A side call (no later call continues it).
    pub side: bool,
    /// Answered from Quena's agent cache.
    pub hit: bool,
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
    pub side: bool,
    pub breakdown: Breakdown,
    pub diff: Option<TurnDiff>,
    /// The message that differs from the previous request (role and start), before and after.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed: Option<(String, String)>,
    pub cache: Vec<CacheNote>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window: Option<u64>,
}

fn turns_of(c: &Conv) -> Vec<Turn> {
    let judged = c.judged();
    c.digests
        .iter()
        .map(|d| {
            let prev = c.pred_of(d.id);
            Turn {
                id: d.id,
                prev: prev.map(|p| p.id),
                started: d.started,
                duration_ms: d.duration_ms,
                model: d.model.clone(),
                usage: d.usage,
                cost: d.cost.filter(|_| !d.hit),
                stop: d.stop.clone(),
                error: d.error,
                side: c.side.contains(&d.id),
                hit: d.hit,
                calls: d.calls.clone(),
                messages: d.messages.len(),
                diff: diff(prev.map(|p| p.as_ref()), d),
                cache: cache_notes(c.cache_base(d.id).map(|b| b.as_ref()), d, judged),
            }
        })
        .collect()
}

/// The context window of `model`; Claude models with the 1M context get it when a request
/// was larger than the usual window.
fn window_of(model: &str, input: u64, prices: &llm::PriceList) -> Option<u64> {
    let w = llm::context_of(model, prices)?;
    Some(if input > w && model.contains("claude") { 1_000_000 } else { w })
}

fn summary_of(b: &Built, ci: usize, turns: &[Turn], prices: &llm::PriceList) -> ConvSummary {
    let c = &b.convs[ci];
    let ds = &c.digests;
    let first = &ds[0];
    let main_last = ds.iter().filter(|d| !c.side.contains(&d.id)).max_by_key(|d| (d.started, d.id)).unwrap_or(first);
    let mut models: Vec<String> = Vec::new();
    for d in ds {
        if !d.model.is_empty() && !models.contains(&d.model) {
            models.push(d.model.clone());
        }
    }
    let sum = |f: fn(&Usage) -> u64| ds.iter().filter_map(|d| d.spent()).map(|u| f(&u)).sum::<u64>();
    let costs: Vec<f64> = ds.iter().filter(|d| !d.hit).filter_map(|d| d.cost).collect();
    let last_input = main_last.usage.map(|u| u.input).unwrap_or(main_last.est);
    ConvSummary {
        key: key_text(c.key),
        title: if first.prompt.is_empty() { first.model.clone() } else { snippet(&first.prompt, 100) },
        agent: first.agent.clone(),
        provider: first.provider.clone(),
        models,
        turns: ds.len() as u32,
        side: c.side.len() as u32,
        hits: ds.iter().filter(|d| d.hit).count() as u32,
        first: first.id,
        last: ds[ds.len() - 1].id,
        started: first.started,
        ended: ds.iter().map(|d| d.end_us()).max().unwrap_or(first.started),
        input: sum(|u| u.input),
        output: sum(|u| u.output),
        cache_read: sum(|u| u.cache_read),
        cache_write: sum(|u| u.cache_write),
        cost: (!costs.is_empty()).then(|| costs.iter().sum()),
        errors: ds.iter().filter(|d| d.error).count() as u32,
        cache_misses: turns.iter().filter(|t| t.cache.iter().any(|n| n.code == "miss")).count() as u32,
        last_input,
        window: window_of(&main_last.model, last_input, prices),
        parent: b.parent.get(&ci).map(|p| key_text(b.convs[*p].key)),
        subagent: !c.main() || b.parent.contains_key(&ci),
    }
}

/// Waste in a conversation, judged by its last request (which carries the whole history) and
/// the tools all its turns called.
fn hints(last: &LlmCall, c: &Conv, turns: &[Turn], window: Option<u64>) -> Vec<Hint> {
    let b = breakdown(last);
    let fixed_est: u64 = b.slices.iter().filter(|s| fixed(s.category)).map(|s| s.est).sum();
    let scale = match b.actual {
        Some(a) if b.estimated > fixed_est && a > fixed_est => (a - fixed_est) as f64 / (b.estimated - fixed_est) as f64,
        _ => 1.0,
    };
    let tok = |e: u64| (e as f64 * scale).round() as u64;
    let mut out = Vec::new();
    let parts = || last.messages.iter().flat_map(|m| &m.parts);
    let names: HashMap<&str, &str> = parts().filter(|p| p.kind == "toolCall").filter_map(|p| Some((p.id.as_deref()?, p.name.as_deref()?))).collect();
    let name_of = |p: &Part| p.name.as_deref().or_else(|| p.id.as_deref().and_then(|id| names.get(id).copied())).unwrap_or("").to_string();
    // The same call (tool and arguments) more than twice: it costs what its later results add.
    let results_by_id: HashMap<&str, &Part> = parts().filter(|p| p.kind == "toolResult").filter_map(|p| Some((p.id.as_deref()?, p))).collect();
    let mut calls: HashMap<u64, (String, String, Vec<&str>)> = HashMap::new();
    for p in parts().filter(|p| p.kind == "toolCall") {
        let name = p.name.clone().unwrap_or_default();
        let e = calls.entry(fnv(hash_text(&name), p.text.as_bytes())).or_insert((name, snippet(&p.text, 100), vec![]));
        e.2.extend(p.id.as_deref());
    }
    // Results a repeated call explains are not counted again below.
    let mut explained: HashSet<u64> = HashSet::new();
    for (name, args, ids) in calls.into_values().filter(|c| c.2.len() > 2) {
        let res: Vec<&&Part> = ids.iter().filter_map(|id| results_by_id.get(id)).collect();
        let later: u64 = res.iter().skip(1).map(|r| estimate_tokens(&r.text)).sum();
        explained.extend(res.iter().map(|r| hash_text(&r.text)));
        out.push(hint("repeatCall", tok(later), &[("tool", name), ("n", ids.len().to_string()), ("args", args)]));
    }
    // The same tool result more than once; large results (each text once).
    let mut results: HashMap<u64, (String, u64, u32)> = HashMap::new();
    for p in parts().filter(|p| p.kind == "toolResult") {
        let e = results.entry(hash_text(&p.text)).or_insert((name_of(p), estimate_tokens(&p.text), 0));
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
                let e = reminders.entry(hash_text(t)).or_insert((estimate_tokens(t), 0, snippet(t.trim_start_matches("<system-reminder>"), 80)));
                e.1 += 1;
            }
        }
    }
    for (est, n, text) in reminders.into_values().filter(|r| r.1 > 2) {
        out.push(hint("dupReminder", tok(est) * (n as u64 - 1), &[("n", n.to_string()), ("text", text)]));
    }
    // Tools offered in every request but never called.
    let called: HashSet<&str> = c.digests.iter().flat_map(|d| d.calls.iter().map(String::as_str)).chain(parts().filter(|p| p.kind == "toolCall").filter_map(|p| p.name.as_deref())).collect();
    let unused: Vec<&llm::ToolDef> = last.tools.iter().filter(|t| !called.contains(t.name.as_str())).collect();
    let main_turns = c.digests.len() - c.side.len();
    if !unused.is_empty() && main_turns >= 3 {
        let per = tok(unused.iter().map(|t| t.tokens).sum());
        let list = unused.iter().take(12).map(|t| t.name.as_str()).collect::<Vec<_>>().join(", ");
        out.push(hint("unusedTools", per, &[("n", unused.len().to_string()), ("of", last.tools.len().to_string()), ("turns", main_turns.to_string()), ("names", list)]));
    }
    // Near the end of the context window.
    if let (Some(w), Some(input)) = (window, b.actual)
        && w > 0
        && input * 10 >= w * 7
    {
        out.push(hint("window", input, &[("pct", (input * 100 / w).to_string()), ("window", w.to_string())]));
    }
    let misses: Vec<&Turn> = turns.iter().filter(|t| t.cache.iter().any(|n| n.code == "miss")).collect();
    if !misses.is_empty() {
        let lost: u64 = misses.iter().flat_map(|t| &t.cache).filter(|n| n.code == "miss").filter_map(|n| n.args.get("tokens")?.parse::<u64>().ok()).sum();
        out.push(hint("cacheMisses", lost, &[("n", misses.len().to_string()), ("turns", turns.len().to_string())]));
    }
    out.sort_by(|a, b| b.tokens.cmp(&a.tokens).then_with(|| a.code.cmp(b.code)));
    out
}

// ------------------------------------------------------------------ AppCore

/// Digests of the current capture's LLM calls (`None`: the session is no LLM call that can
/// be read), and the conversations last built from them.
#[derive(Default)]
pub struct Digests {
    numbering: u64,
    /// Bumped with every digest kept.
    generation: u64,
    map: HashMap<SessionId, Option<Arc<Digest>>>,
    built: Option<(u64, Arc<Built>)>,
}

impl AppCore {
    /// A session as an LLM call, read without pushing other sessions out of the detail cache.
    fn llm_peek(&self, id: SessionId) -> Option<(SessionDetail, LlmCall)> {
        let cap = self.capture();
        let (d, req, resp) = cap.bodies_stored(id)?;
        llm::api_of(&d.request.method, &d.request.url)?;
        let call = self.llm_from(&d, &req, &resp)?;
        Some((d, call))
    }

    /// The digest of session `id` (made from its bodies once; `None`: not an LLM call). A call
    /// that had no LLM flags yet (an archive from elsewhere) gets them.
    pub fn llm_digest(&self, id: SessionId) -> Option<Arc<Digest>> {
        let cap = self.capture();
        let numbering = cap.numbering();
        {
            let g = self.llm_digests.lock();
            if g.numbering == numbering
                && let Some(d) = g.map.get(&id)
            {
                return d.clone();
            }
        }
        let made = self.llm_peek(id).map(|(d, call)| {
            if !d.extra_flags.iter().any(|(k, _)| k == llm::LLM_FLAG) {
                let flags = llm::flags_of(&call);
                let set = |det: &mut SessionDetail| {
                    det.extra_flags.retain(|(k, _)| !k.starts_with(llm::LLM_FLAG) || k == CONV_FLAG);
                    det.extra_flags.extend(flags.iter().cloned());
                };
                if let Some(live) = cap.live(id) {
                    live.update(set);
                } else {
                    cap.update_detail(id, set);
                }
            }
            Digest::new(id, &d, &call)
        });
        self.keep_digest(numbering, id, made)
    }

    /// Keep a digest made for capture numbering `numbering` (dropped when the capture started
    /// over meanwhile).
    pub(crate) fn keep_digest(&self, numbering: u64, id: SessionId, d: Option<Digest>) -> Option<Arc<Digest>> {
        let d = d.map(Arc::new);
        let current = self.capture().numbering();
        if current != numbering {
            return d;
        }
        let mut g = self.llm_digests.lock();
        if g.numbering != numbering {
            g.numbering = numbering;
            g.map.clear();
            g.built = None;
        }
        g.map.insert(id, d.clone());
        g.generation += 1;
        d
    }

    /// Conversations of the digests made so far (built again only after new ones).
    fn built(&self) -> Arc<Built> {
        let (generation, digests) = {
            let g = self.llm_digests.lock();
            if let Some((gen_, b)) = &g.built
                && *gen_ == g.generation
                && g.numbering == self.capture().numbering()
            {
                return b.clone();
            }
            (g.generation, g.map.values().flatten().cloned().collect::<Vec<_>>())
        };
        let b = Arc::new(build(&digests));
        let mut g = self.llm_digests.lock();
        if g.generation == generation {
            g.built = Some((generation, b.clone()));
        }
        b
    }

    /// The conversation key of LLM call `id` (after its digest was kept).
    pub(crate) fn conv_key(&self, id: SessionId) -> Option<String> {
        let b = self.built();
        b.conv_of.get(&id).map(|ci| key_text(b.convs[*ci].key))
    }

    /// Digests of all LLM calls in the capture (sessions whose URL is an LLM API), and the
    /// conversations; calls whose conversation flag is missing or out of date get it.
    fn all_built(&self) -> Arc<Built> {
        let cap = self.capture();
        let mut cand: Vec<(SessionId, String)> = Vec::new();
        cap.index.for_each(|s| {
            if !s.llm.is_empty() || (s.method.eq_ignore_ascii_case("POST") && llm::api_of("POST", &format!("http://{}{}", s.host, s.url)).is_some()) {
                cand.push((s.id, s.llm_conv.clone()));
            }
        });
        for (id, _) in &cand {
            self.llm_digest(*id);
        }
        let b = self.built();
        for (id, flag) in cand {
            let Some(want) = b.conv_of.get(&id).map(|ci| key_text(b.convs[*ci].key)) else { continue };
            if flag != want {
                let set = |det: &mut SessionDetail| {
                    det.extra_flags.retain(|(n, _)| n != CONV_FLAG);
                    det.extra_flags.push((CONV_FLAG.into(), want.clone()));
                };
                if let Some(live) = cap.live(id) {
                    live.update(set);
                } else {
                    cap.update_detail(id, set);
                }
            }
        }
        b
    }

    /// The conversations in the capture, newest first; subagents name their parent.
    pub fn llm_conversations(&self) -> Vec<ConvSummary> {
        let b = self.all_built();
        let prices = self.llm_prices();
        let mut out: Vec<ConvSummary> = (0..b.convs.len()).map(|ci| summary_of(&b, ci, &turns_of(&b.convs[ci]), &prices)).collect();
        out.sort_by(|a, b| b.started.cmp(&a.started).then(b.first.cmp(&a.first)));
        out
    }

    /// A conversation with its turns, hints and the context of its last request.
    pub fn llm_conversation(&self, key: &str) -> Option<ConvDetail> {
        let b = self.all_built();
        let ci = b.convs.iter().position(|c| key_text(c.key) == key)?;
        let c = &b.convs[ci];
        let prices = self.llm_prices();
        let turns = turns_of(c);
        let summary = summary_of(&b, ci, &turns, &prices);
        // The newest call of the main line that can be read carries the whole history.
        let mut main: Vec<&Arc<Digest>> = c.digests.iter().filter(|d| !c.side.contains(&d.id)).collect();
        main.sort_by_key(|d| (d.started, d.id));
        let last = main.iter().rev().find_map(|d| self.llm_peek(d.id).map(|x| x.1));
        let (hints, breakdown) = match &last {
            Some(call) => (hints(call, c, &turns, summary.window), Some(breakdown(call))),
            None => (vec![], None),
        };
        let mut children: Vec<String> = b.parent.iter().filter(|(_, p)| **p == ci).map(|(k, _)| key_text(b.convs[*k].key)).collect();
        children.sort();
        Some(ConvDetail { summary, turns, hints, breakdown, children })
    }

    /// LLM call `id` in its conversation: its context, and what changed from the call it
    /// continues.
    pub fn llm_context(&self, id: SessionId) -> Option<CallContext> {
        let (_, call) = self.llm_peek(id)?;
        let b = breakdown(&call);
        let window = window_of(&call.model, b.actual.unwrap_or(0), &self.llm_prices());
        let built = self.all_built();
        let Some(ci) = built.conv_of.get(&id).copied() else {
            return Some(CallContext { key: None, turn: 1, turns: 1, prev: None, side: false, breakdown: b, diff: None, changed: None, cache: vec![], window });
        };
        let c = &built.convs[ci];
        let cur = c.get(id)?.clone();
        let pos = c.digests.iter().position(|d| d.id == id).unwrap_or(0);
        let prev = c.pred_of(id).cloned();
        let df = diff(prev.as_deref(), &cur);
        let cache = cache_notes(c.cache_base(id).map(|x| x.as_ref()), &cur, c.judged());
        let changed = match (df.at, prev.as_ref()) {
            (Some(at), Some(p)) => self.llm_peek(p.id).map(|(_, pc)| {
                let show = |m: Option<&llm::Message>| m.map(|m| format!("{}: {}", m.role, snippet(&m.parts.iter().map(|p| p.text.as_str()).collect::<Vec<_>>().join(" "), 300))).unwrap_or_default();
                (show(pc.messages.get(at)), show(call.messages.get(at)))
            }),
            _ => None,
        };
        Some(CallContext { key: Some(key_text(c.key)), turn: pos + 1, turns: c.digests.len(), prev: prev.map(|p| p.id), side: c.side.contains(&id), breakdown: b, diff: Some(df), changed, cache, window })
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
    fn tool(name: &str, size: usize) -> ToolDef {
        ToolDef { name: name.into(), description: String::new(), size, tokens: size as u64 / 4, hash: hash_text(name) }
    }
    fn call(system: &str, messages: Vec<Message>, input: u64, cache_read: u64) -> LlmCall {
        LlmCall {
            provider: "Anthropic".into(),
            api: Api::Messages,
            model: "claude-sonnet-4-5".into(),
            stream: true,
            system: vec![system.into()],
            messages,
            tools: vec![tool("Read", 400), tool("Bash", 800)],
            params: vec![],
            output: vec![],
            stop_reason: None,
            usage: Some(Usage { input, output: 10, cache_read, cache_write: 0, reasoning: 0 }),
            cost: None,
            error: None,
            notes: vec![],
            cache_marks: vec!["messages[0]".into()],
            attribution: vec![],
            user: None,
            response_id: None,
        }
    }
    fn detail(started_s: i64, headers: &[(&str, &str)]) -> SessionDetail {
        let mut d = SessionDetail::default();
        d.summary.started_at = started_s * 1_000_000;
        d.summary.duration_ms = Some(1_000);
        for (k, v) in headers {
            d.request.headers.push(*k, *v);
        }
        d
    }
    fn digest(id: SessionId, started_s: i64, c: &LlmCall) -> Arc<Digest> {
        Arc::new(Digest::new(id, &detail(started_s, &[]), c))
    }
    fn session(id: SessionId, started_s: i64, sid: &str, c: &LlmCall) -> Arc<Digest> {
        Arc::new(Digest::new(id, &detail(started_s, &[("X-Claude-Code-Session-Id", sid)]), c))
    }
    fn result(id: &str, t: &str) -> Part {
        Part { kind: "toolResult".into(), id: Some(id.into()), text: t.into(), ..Default::default() }
    }
    fn use_tool(id: &str, name: &str, args: &str) -> Part {
        Part { kind: "toolCall".into(), name: Some(name.into()), id: Some(id.into()), text: args.into() }
    }

    #[test]
    fn estimate_is_in_the_right_range() {
        let e = estimate_tokens("The quick brown fox jumps over the lazy dog.");
        assert!((9..=14).contains(&e), "{e}");
        let json = r#"{"path": "/src/main.rs", "line": 12}"#;
        assert!((10..=18).contains(&estimate_tokens(json)), "{}", estimate_tokens(json));
        let long = format!("{} … (40000 characters)", "word ".repeat(2000));
        assert!(estimate_tokens(&long) > 7_000, "a shortened text counts at its full length");
    }

    #[test]
    fn agent_text_is_told_apart() {
        let t = "<system-reminder>\nAs you answer, use this context:\nContents of /repo/CLAUDE.md (project instructions, checked into the codebase):\nUse tabs.\nContents of /home/u/.claude/CLAUDE.md (user's private global instructions for all projects):\nBe brief.\n</system-reminder>\nFix the bug in main.rs";
        let labels: Vec<(Seg, String)> = segments(t).iter().map(|(s, l, _)| (*s, l.clone())).collect();
        assert_eq!(labels[1], (Seg::Instructions, "/repo/CLAUDE.md".into()));
        assert_eq!(labels[2], (Seg::Instructions, "/home/u/.claude/CLAUDE.md".into()));
        assert_eq!(labels.last().unwrap().0, Seg::Text);
        assert_eq!(own_text(&msg("user", vec![text(t)])), "Fix the bug in main.rs");
        assert_eq!(segments("# AGENTS.md instructions for /repo\n\n<INSTRUCTIONS>\nRun tests.\n</INSTRUCTIONS>")[0].0, Seg::Instructions);
        assert_eq!(segments("<environment_context>\n  <cwd>/repo</cwd>\n</environment_context>")[0].0, Seg::Context);
        assert_eq!(segments("<system-reminder>The following skills are available for use with the Skill tool: pdf</system-reminder>")[0].0, Seg::Skills);
        assert_eq!(segments("This session is being continued from a previous conversation that ran out of context.")[0].0, Seg::Summary);
        // A slash command counts by its name and arguments; the caveat does not count.
        let cmd = msg("user", vec![text("<local-command-caveat>Caveat: generated by local commands</local-command-caveat>"), text("<command-name>/review</command-name>\n<command-message>review</command-message>\n<command-args>PR 12</command-args>")]);
        assert_eq!(own_text(&cmd), "/review PR 12");
    }

    #[test]
    fn claude_codes_attribution_block_is_no_system_prompt() {
        let req = |turn: u32| {
            format!(
                r#"{{"model":"claude-sonnet-4-5","max_tokens":10,"system":[{{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.296.abc; cc_entrypoint=cli; cch=00000; cc_prev_req=req_{turn}; cc_turn_index={turn};"}},{{"type":"text","text":"You are Claude Code, Anthropic's official CLI for Claude."}},{{"type":"text","text":"You help with software.","cache_control":{{"type":"ephemeral"}}}}],"messages":[{{"role":"user","content":"Fix the parser"}}]}}"#
            )
        };
        let a = llm::parse("POST", "https://api.anthropic.com/v1/messages", req(1).as_bytes(), None, &llm::PriceList::default()).unwrap();
        let b = llm::parse("POST", "https://api.anthropic.com/v1/messages", req(2).as_bytes(), None, &llm::PriceList::default()).unwrap();
        assert_eq!(a.system.len(), 2);
        assert!(a.attribution.iter().any(|(k, v)| k == "cc_prev_req" && v == "req_1"));
        let (da, db) = (digest(1, 0, &a), digest(2, 5, &b));
        assert_eq!(da.group, db.group, "the attribution block changes every turn but does not count");
        assert_eq!(db.prev_request.as_deref(), Some("req_2"));
    }

    #[test]
    fn turns_link_to_what_they_continue() {
        let reminder = "<system-reminder>today is 2026-10-10</system-reminder>";
        let m1 = msg("user", vec![text(reminder), text("Refactor the parser")]);
        let a1 = msg("assistant", vec![use_tool("t1", "Read", "{\"file\":\"p.rs\"}")]);
        let r1 = msg("user", vec![result("t1", &"fn parse() {}".repeat(50))]);
        let c1 = call("You are Claude Code.", vec![m1.clone()], 5_000, 0);
        let c2 = call("You are Claude Code.", vec![m1.clone(), a1.clone(), r1.clone()], 6_000, 4_900);
        // A side call (prompt suggestion) forks off the same history.
        let side = call("You are Claude Code.", vec![m1.clone(), a1.clone(), r1.clone(), msg("user", vec![text("Suggest the next prompt")])], 6_100, 5_900);
        let c3 = call("You are Claude Code.", vec![m1.clone(), a1.clone(), r1.clone(), msg("assistant", vec![text("Done.")]), msg("user", vec![text("thanks")])], 6_300, 5_900);
        let other = call("You are Claude Code.", vec![msg("user", vec![text(reminder), text("Write docs")])], 5_000, 0);
        let ds = vec![session(1, 0, "s1", &c1), session(2, 10, "s1", &c2), session(3, 12, "s1", &side), session(4, 20, "s1", &c3), session(5, 30, "s1", &other)];
        let b = build(&ds);
        assert_eq!(b.convs.len(), 2);
        let c = &b.convs[b.conv_of[&1]];
        let turns = turns_of(c);
        let kinds: Vec<&str> = turns.iter().map(|t| t.diff.kind).collect();
        assert_eq!(kinds, ["first", "append", "append", "append"], "the turn after the side call continues turn 2, not the side call");
        assert_eq!(turns[3].prev, Some(2));
        assert_eq!(c.side.iter().copied().collect::<Vec<_>>(), vec![3]);
        assert!(turns.iter().all(|t| t.cache.is_empty()), "{:?}", turns.iter().map(|t| &t.cache).collect::<Vec<_>>());
    }

    #[test]
    fn separate_runs_with_the_same_prompt_stay_apart() {
        let m = msg("user", vec![text("run the tests")]);
        let c = call("You are Claude Code.", vec![m.clone()], 3_000, 0);
        let c2 = call("You are Claude Code.", vec![m.clone(), msg("assistant", vec![text("ok")]), msg("user", vec![text("again")])], 3_100, 2_900);
        // Two sessions at the same time.
        let b = build(&[session(1, 0, "a", &c), session(2, 1, "b", &c), session(3, 5, "a", &c2), session(4, 6, "b", &c2)]);
        assert_eq!(b.convs.len(), 2);
        assert_eq!(b.conv_of[&1], b.conv_of[&3]);
        assert_eq!(b.conv_of[&2], b.conv_of[&4]);
        // Without sessions, hours apart.
        let b = build(&[digest(1, 0, &c), digest(2, 5 * 3600, &c)]);
        assert_eq!(b.convs.len(), 2);
    }

    #[test]
    fn cache_misses_are_explained() {
        let m1 = msg("user", vec![text("Refactor the parser")]);
        let m2 = msg("assistant", vec![text("Done.")]);
        let c1 = call("You are Claude Code.", vec![m1.clone(), m2.clone()], 20_000, 0);
        // An earlier message changed, 7 minutes later, and the model too.
        let mut c2 = call("You are Claude Code.", vec![m1.clone(), msg("assistant", vec![text("Done!")]), msg("user", vec![text("thanks")])], 21_000, 0);
        c2.model = "claude-opus-4-1".into();
        c2.params.push(("thinking".into(), "{\"type\":\"enabled\"}".into()));
        let b = build(&[digest(1, 0, &c1), digest(2, 7 * 60 + 1, &c2)]);
        let t = turns_of(&b.convs[0]);
        let codes: Vec<&str> = t[1].cache.iter().map(|c| c.code).collect();
        assert_eq!(t[1].diff.kind, "changed");
        assert_eq!(codes, ["miss", "modelChanged", "settingsChanged", "messageChanged", "expired"]);
        assert_eq!(t[1].cache[0].args["tokens"], "20000");
        // Without cache marks the reason is that.
        let mut c3 = call("You are Claude Code.", vec![m1.clone(), m2.clone(), msg("user", vec![text("more")])], 21_000, 0);
        c3.cache_marks.clear();
        let b = build(&[digest(1, 0, &c1), digest(2, 10, &c3)]);
        assert_eq!(turns_of(&b.convs[0])[1].cache.iter().map(|c| c.code).collect::<Vec<_>>(), ["miss", "noMarks"]);
        // A tool schema changed with the same size.
        let mut c4 = call("You are Claude Code.", vec![m1.clone(), m2.clone(), msg("user", vec![text("more")])], 21_000, 0);
        c4.tools[1].hash = 7;
        let b = build(&[digest(1, 0, &c1), digest(2, 10, &c4)]);
        assert!(turns_of(&b.convs[0])[1].cache.iter().any(|c| c.code == "toolsChanged"));
        // Too short for the cache, but marked.
        let s1 = call("You are Claude Code.", vec![m1.clone()], 600, 0);
        let s2 = call("You are Claude Code.", vec![m1.clone(), m2.clone(), msg("user", vec![text("go")])], 700, 0);
        let b = build(&[digest(1, 0, &s1), digest(2, 10, &s2)]);
        assert_eq!(turns_of(&b.convs[0])[1].cache.iter().map(|c| c.code).collect::<Vec<_>>(), ["short"]);
        // A provider that never reports cached tokens: nothing to say.
        let mut o1 = call("sys", vec![m1.clone()], 20_000, 0);
        let mut o2 = call("sys", vec![m1.clone(), m2.clone(), msg("user", vec![text("go")])], 21_000, 0);
        o1.api = Api::Chat;
        o2.api = Api::Chat;
        let b = build(&[digest(1, 0, &o1), digest(2, 10, &o2)]);
        assert!(turns_of(&b.convs[0])[1].cache.is_empty());
    }

    #[test]
    fn answers_from_the_agent_cache_cost_nothing() {
        let m1 = msg("user", vec![text("Refactor the parser")]);
        let c1 = call("sys", vec![m1.clone()], 20_000, 0);
        let c2 = call("sys", vec![m1.clone(), msg("assistant", vec![text("ok")]), msg("user", vec![text("go")])], 21_000, 0);
        let mut hit = detail(10, &[]);
        hit.extra_flags.push((crate::llm_cache::CACHE_FLAG.into(), "hit".into()));
        let ds = vec![digest(1, 0, &c1), Arc::new(Digest::new(2, &hit, &c2))];
        let b = build(&ds);
        let t = turns_of(&b.convs[0]);
        assert!(t[1].hit && t[1].cache.is_empty());
        let s = summary_of(&b, 0, &t, &llm::PriceList::default());
        assert_eq!((s.input, s.hits), (20_000, 1));
    }

    #[test]
    fn breakdown_scales_to_the_usage() {
        let t = "<system-reminder>Contents of /r/CLAUDE.md (project):\nrules rules rules</system-reminder>do it";
        let mut c = call("You are an agent.", vec![msg("user", vec![text(t)])], 3_000, 0);
        c.messages.push(msg("assistant", vec![use_tool("x", "Read", "{}")]));
        c.messages.push(msg("user", vec![result("x", &"data ".repeat(400)), Part { kind: "image".into(), text: "[image]".into(), id: Some("x".into()), ..Default::default() }]));
        let b = breakdown(&c);
        assert_eq!(b.actual, Some(3_000));
        let total: u64 = b.slices.iter().map(|s| s.tokens).sum();
        assert!((2_995..=3_005).contains(&total), "{total}");
        let get = |cat: &str| b.slices.iter().find(|s| s.category == cat).unwrap();
        assert_eq!(get("images").tokens, IMAGE_TOKENS, "fixed amounts are not scaled");
        assert_eq!(get("overhead").tokens, ANTHROPIC_TOOL_OVERHEAD);
        assert_eq!(get("toolResults").label, "Read", "a result is named by its call");
        assert!(b.slices.iter().any(|s| s.category == "instructions" && s.label == "/r/CLAUDE.md"));
        // History kept by the provider shows as such.
        let mut r = call("sys", vec![msg("user", vec![text("next")])], 50_000, 0);
        r.api = Api::Responses;
        r.tools.clear();
        r.params.push(("previous_response_id".into(), "resp_1".into()));
        let b = breakdown(&r);
        assert!(b.slices[0].category == "server" && b.slices[0].tokens > 45_000);
    }

    #[test]
    fn hints_find_waste() {
        let rem = text(&format!("<system-reminder>{}</system-reminder>", "Remember the todo list. ".repeat(10)));
        let mut msgs = vec![msg("user", vec![text("go")])];
        for i in 0..3 {
            let id = format!("r{i}");
            msgs.push(msg("assistant", vec![use_tool(&id, "Read", "{\"file\":\"big.rs\"}")]));
            msgs.push(msg("user", vec![result(&id, &"x = 1;\n".repeat(400)), rem.clone()]));
        }
        // Two different searches with the same answer.
        for (id, pat) in [("g1", "foo"), ("g2", "fo+")] {
            msgs.push(msg("assistant", vec![use_tool(id, "Grep", &format!("{{\"pattern\":\"{pat}\"}}"))]));
            msgs.push(msg("user", vec![result(id, &"src/a.rs:1 foo\n".repeat(40))]));
        }
        let c = call("sys", msgs, 9_000, 0);
        let ds: Vec<Arc<Digest>> = (1..=3).map(|i| digest(i, i as i64, &c)).collect();
        let b = build(&ds);
        let conv = &b.convs[0];
        let h = hints(&c, conv, &turns_of(conv), Some(10_000));
        let codes: Vec<&str> = h.iter().map(|h| h.code).collect();
        for want in ["repeatCall", "dupReminder", "unusedTools", "window"] {
            assert!(codes.contains(&want), "{want} in {codes:?}");
        }
        assert!(h.iter().find(|h| h.code == "repeatCall").unwrap().tokens > 0, "the later results count");
        let dups: Vec<&Hint> = h.iter().filter(|h| h.code == "dupResult").collect();
        assert_eq!(dups.len(), 1, "results of a repeated call are counted once: {codes:?}");
        assert_eq!(dups[0].args["tool"], "Grep");
        assert_eq!(h.iter().find(|h| h.code == "unusedTools").unwrap().args["names"], "Bash");
        assert_eq!(h.iter().filter(|h| h.code == "bigResult").count(), 0, "no result is that large here");
    }

    #[test]
    fn subagents_find_their_parent() {
        let task = "Find the file called \"config.rs\" and every caller of parse_config\tthen list them";
        let mut parent = call("You are Claude Code.", vec![msg("user", vec![text("Find callers")])], 3_000, 0);
        parent.output.push(use_tool("t", "Task", &serde_json::to_string_pretty(&serde_json::json!({"description": "find", "prompt": task, "subagent_type": "general-purpose"})).unwrap()));
        let child = call("You are a subagent.", vec![msg("user", vec![text(task)])], 2_000, 0);
        let b = build(&[digest(1, 0, &parent), digest(2, 5, &child)]);
        assert_eq!(b.parent.get(&b.conv_of[&2]), Some(&b.conv_of[&1]), "quotes and tabs in the task prompt");
        // Claude Code: the subagent's first call names the parent's last request as previous.
        let mut pd = detail(0, &[("X-Claude-Code-Session-Id", "s")]);
        pd.response = Some(Default::default());
        pd.response.as_mut().unwrap().headers.push("request-id", "req_p");
        let mut child2 = child.clone();
        child2.attribution = vec![("cc_prev_req".into(), "req_p".into()), ("cc_is_subagent".into(), "true".into())];
        let b = build(&[Arc::new(Digest::new(1, &pd, &parent)), Arc::new(Digest::new(2, &detail(5, &[("X-Claude-Code-Session-Id", "s")]), &child2))]);
        assert_eq!(b.convs.len(), 2, "a subagent is a conversation of its own");
        assert_eq!(b.parent.get(&b.conv_of[&2]), Some(&b.conv_of[&1]));
        // By the session the agent names.
        let p = Arc::new(Digest::new(1, &detail(0, &[]), &{
            let mut c = call("Codex", vec![msg("user", vec![text("Plan the release")])], 1_000, 0);
            c.params.push(("prompt_cache_key".into(), "thread-1".into()));
            c
        }));
        let ch = Arc::new(Digest::new(2, &detail(3, &[("x-codex-parent-thread-id", "thread-1"), ("session_id", "thread-2")]), &call("Codex", vec![msg("user", vec![text("Check the changelog")])], 1_000, 0)));
        assert!(ch.subagent);
        let b = build(&[p, ch]);
        assert_eq!(b.parent.get(&b.conv_of[&2]), Some(&b.conv_of[&1]));
    }
}
