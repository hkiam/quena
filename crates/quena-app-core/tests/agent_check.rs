//! Captures of real agent runs (tools/agent-check/run.sh records Claude Code and Codex): every
//! LLM call is read with model and usage, a run is one conversation, the system prompt is taken
//! apart into the agent's base prompt and the parts it adds. Ignored without captures:
//!
//!   AGENT_CHECK=claude.saz,codex.saz cargo test -p quena-app-core --test agent_check -- --ignored --nocapture

use quena_app_core::{AppCore, Paths};
use std::time::Duration;

/// What a capture holds, printed, and what is wrong with it.
fn check(path: &str) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("settings.json"), r#"{"proxy":{"port":0,"actAsSystemProxy":false,"captureOnStartup":false}}"#).unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    let job = core.import_archive(path.into()).unwrap();
    core.jobs.wait(job, Duration::from_secs(60)).unwrap();
    let cap = core.capture();
    cap.index.tick();
    // Calls over a WebSocket (Codex) become sessions of their own.
    core.ws_llm_tick();
    cap.index.tick();
    let numbering = cap.numbering();
    let calls: Vec<_> = cap.index.find_all(|_| true).into_iter().filter(|id| core.llm(*id).is_some()).collect();
    for id in &calls {
        core.llm_mark(numbering, *id);
    }
    cap.index.tick();

    let mut wrong = Vec::new();
    println!("\n{path}: {} LLM call(s)", calls.len());
    if calls.is_empty() {
        wrong.push(format!("{path}: no LLM call found"));
    }
    for id in &calls {
        let c = quena_app_core::agent::labelled(core.llm(*id).unwrap());
        let usage = c.call.usage.map(|u| format!("in {} out {} cache {}", u.input, u.output, u.cache_read)).unwrap_or_else(|| "no usage".into());
        let cost = c.call.cost.as_ref().map(|x| format!("≈ ${:.4}", x.usd)).unwrap_or_else(|| "price unknown".into());
        let parts: Vec<String> = c.system_sections.iter().map(|s| if s.label.is_empty() { s.kind.to_string() } else { format!("{}:{}", s.kind, s.label) }).collect();
        println!("  #{id} {} {} · {usage} · {cost}{}", c.call.provider, c.call.model, c.call.error.as_ref().map(|e| format!(" · error {e}")).unwrap_or_default());
        println!("      system: {}", parts.join(", "));
        if c.call.model.is_empty() {
            wrong.push(format!("#{id}: no model"));
        }
        if c.call.usage.is_none() && c.call.error.is_none() {
            wrong.push(format!("#{id}: no token usage"));
        }
        if c.call.cost.is_none() {
            println!("      note: no price for {} (llm.rs PRICES)", c.call.model);
        }
        // The agent's own prompt comes first (a call that continues a thread the provider keeps
        // sends only what is new); what it adds is labelled, never most of it.
        let system: usize = c.system_sections.iter().map(|s| s.text.len()).sum();
        let continues = c.call.params.iter().any(|(k, _)| k == "previous_response_id" || k == "previous_message_id");
        if !continues && !c.call.system.is_empty() && c.system_sections.first().map(|s| s.kind) != Some("base") {
            wrong.push(format!("#{id}: the system prompt does not start with the agent's base prompt: {}", parts.join(", ")));
        }
        let reminders: usize = c.system_sections.iter().filter(|s| s.kind == "reminder").map(|s| s.text.len()).sum();
        if system > 0 && reminders * 2 > system {
            wrong.push(format!("#{id}: most of the system prompt taken for reminders ({reminders} of {system} characters)"));
        }
    }
    let convs = core.llm_conversations();
    for c in &convs {
        println!("  conversation {:?} · {} · {} turn(s), {} side call(s) · {} cache miss(es) · {}{}", c.title, c.agent, c.turns, c.side, c.cache_misses, c.cost.map(|x| format!("≈ ${x:.4}")).unwrap_or_else(|| "cost unknown".into()), if c.subagent { " · subagent" } else { "" });
    }
    let runs: Vec<_> = convs.iter().filter(|c| c.parent.is_none() && !c.subagent).collect();
    if !calls.is_empty() && runs.len() != 1 {
        wrong.push(format!("{path}: one run, {} conversations: {:?}", runs.len(), runs.iter().map(|c| &c.title).collect::<Vec<_>>()));
    }
    wrong
}

#[test]
#[ignore]
fn captures_of_real_agent_runs() {
    let paths = std::env::var("AGENT_CHECK").expect("AGENT_CHECK: captures to check, separated by commas");
    let wrong: Vec<String> = paths.split(',').filter(|p| !p.trim().is_empty()).flat_map(|p| check(p.trim())).collect();
    assert!(wrong.is_empty(), "\n{}", wrong.join("\n"));
}
