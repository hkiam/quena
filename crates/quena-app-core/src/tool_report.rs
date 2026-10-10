//! Tools and skills across the agent runs of a capture: what each tool definition costs in
//! every request that offers it, how often the model calls it and the MCP server answers, with
//! which errors and how large results; which skills are offered and which loaded. And the way
//! of one tool call: the LLM answer that asked for it, the MCP exchange that ran it, the next
//! request that carried its result.

use crate::AppCore;
use crate::agent::Digest;
use quena_model::SessionId;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

/// A tool call is linked to MCP exchanges within this long after the LLM call ended.
const LINK_US: i64 = 10 * 60 * 1_000_000;

/// The server and tool of an LLM tool name: Claude Code names MCP tools `mcp__server__tool`.
pub fn split_tool(name: &str) -> (Option<&str>, &str) {
    if let Some(rest) = name.strip_prefix("mcp__")
        && let Some((server, tool)) = rest.split_once("__")
    {
        return (Some(server), tool);
    }
    (None, name)
}

/// One tool.
#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ToolStat {
    /// As the model sees it (`mcp__jira__get_issue`), else as the MCP server names it.
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// LLM requests that offer it, and the tokens its definition costs in each.
    pub offered: u32,
    pub def_tokens: u64,
    /// Calls the model asked for, exchanges with the MCP server, those that failed.
    pub model_calls: u32,
    pub mcp_calls: u32,
    pub errors: u32,
    /// Tokens of the MCP results (all, and the largest).
    pub result_tokens: u64,
    pub max_result_tokens: u64,
    /// Conversations that offer it, and those that call it.
    pub convs_offered: u32,
    pub convs_called: u32,
}

/// One skill.
#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct SkillStat {
    pub name: String,
    /// Conversations that list it, and how often it was loaded (in how many conversations).
    pub offered: u32,
    pub used: u32,
    pub convs_used: u32,
}

/// Tools and skills of the capture.
#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ToolReport {
    /// Most expensive first (definition tokens × requests).
    pub tools: Vec<ToolStat>,
    pub skills: Vec<SkillStat>,
    /// LLM requests looked at.
    pub requests: u32,
}

/// The way of one tool call.
#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ToolTrail {
    pub tool: String,
    /// The LLM call whose answer asked for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<SessionId>,
    /// The MCP exchange that ran it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp: Option<SessionId>,
    /// The next LLM call of the conversation, which carries the result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_in: Option<SessionId>,
    /// Requests that offer the tool, and its definition's tokens.
    pub offered: u32,
    pub def_tokens: u64,
}

fn matches(llm_name: &str, mcp_tool: &str) -> bool {
    llm_name == mcp_tool || split_tool(llm_name).1 == mcp_tool
}

/// MCP tool calls of the capture: id, start, tool, server, result tokens, failed.
struct McpCall {
    id: SessionId,
    started: i64,
    tool: String,
    server: String,
}

impl AppCore {
    fn mcp_calls(&self) -> Vec<McpCall> {
        let mut out = Vec::new();
        self.capture().index.for_each(|s| {
            if let Some(tool) = s.mcp.strip_prefix("tools/call ") {
                out.push(McpCall { id: s.id, started: s.started_at, tool: tool.to_string(), server: s.mcp_server.clone() });
            }
        });
        out
    }

    /// Result tokens and failure of MCP exchange `id` (kept once read).
    fn mcp_result(&self, id: SessionId) -> (u64, bool) {
        if let Some(r) = self.mcp_results.lock().get(&(self.capture().numbering(), id)) {
            return *r;
        }
        let r = self.mcp_exchange(id).and_then(|x| x.call).map(|c| (c.tokens, c.is_error)).unwrap_or((0, false));
        let mut g = self.mcp_results.lock();
        if g.len() > 100_000 {
            g.clear();
        }
        g.insert((self.capture().numbering(), id), r);
        r
    }

    /// Tools and skills across all agent runs of the capture.
    pub fn tool_report(&self) -> ToolReport {
        let built = self.all_built();
        let mut tools: BTreeMap<String, ToolStat> = BTreeMap::new();
        let mut convs_offered: HashMap<String, HashSet<usize>> = HashMap::new();
        let mut convs_called: HashMap<String, HashSet<usize>> = HashMap::new();
        let mut skills: BTreeMap<String, SkillStat> = BTreeMap::new();
        let mut skill_offered: HashMap<String, HashSet<usize>> = HashMap::new();
        let mut skill_used: HashMap<String, HashSet<usize>> = HashMap::new();
        let mut requests = 0;
        for (ci, c) in built.convs.iter().enumerate() {
            for d in &c.digests {
                requests += 1;
                for (name, _, tokens) in &d.tools {
                    let t = tools.entry(name.clone()).or_insert_with(|| ToolStat { name: name.clone(), server: split_tool(name).0.map(str::to_string), ..Default::default() });
                    t.offered += 1;
                    t.def_tokens = *tokens;
                    convs_offered.entry(name.clone()).or_default().insert(ci);
                }
                for name in &d.calls {
                    let t = tools.entry(name.clone()).or_insert_with(|| ToolStat { name: name.clone(), server: split_tool(name).0.map(str::to_string), ..Default::default() });
                    t.model_calls += 1;
                    convs_called.entry(name.clone()).or_default().insert(ci);
                }
                for s in &d.skills_offered {
                    skills.entry(s.clone()).or_insert_with(|| SkillStat { name: s.clone(), ..Default::default() });
                    skill_offered.entry(s.clone()).or_default().insert(ci);
                }
                for s in &d.skills_used {
                    skills.entry(s.clone()).or_insert_with(|| SkillStat { name: s.clone(), ..Default::default() }).used += 1;
                    skill_used.entry(s.clone()).or_default().insert(ci);
                }
            }
        }
        // MCP exchanges: to the tool the model knows by that name, else a tool of their own.
        for m in self.mcp_calls() {
            let (tokens, failed) = self.mcp_result(m.id);
            let key = tools.keys().find(|k| matches(k, &m.tool) && split_tool(k).0.is_none_or(|s| m.server.is_empty() || s.eq_ignore_ascii_case(&m.server) || s.contains(&m.server.to_ascii_lowercase()))).cloned().or_else(|| tools.keys().find(|k| matches(k, &m.tool)).cloned()).unwrap_or_else(|| m.tool.clone());
            let t = tools.entry(key.clone()).or_insert_with(|| ToolStat { name: key, server: (!m.server.is_empty()).then(|| m.server.clone()), ..Default::default() });
            t.mcp_calls += 1;
            t.errors += failed as u32;
            t.result_tokens += tokens;
            t.max_result_tokens = t.max_result_tokens.max(tokens);
            if t.server.is_none() && !m.server.is_empty() {
                t.server = Some(m.server.clone());
            }
        }
        let mut tools: Vec<ToolStat> = tools
            .into_values()
            .map(|mut t| {
                t.convs_offered = convs_offered.get(&t.name).map_or(0, |s| s.len() as u32);
                t.convs_called = convs_called.get(&t.name).map_or(0, |s| s.len() as u32);
                t
            })
            .collect();
        tools.sort_by(|a, b| (b.def_tokens * b.offered as u64).cmp(&(a.def_tokens * a.offered as u64)).then(b.model_calls.cmp(&a.model_calls)).then(a.name.cmp(&b.name)));
        let mut skills: Vec<SkillStat> = skills
            .into_values()
            .map(|mut s| {
                s.offered = skill_offered.get(&s.name).map_or(0, |x| x.len() as u32);
                s.convs_used = skill_used.get(&s.name).map_or(0, |x| x.len() as u32);
                s
            })
            .collect();
        skills.sort_by(|a, b| b.used.cmp(&a.used).then(b.offered.cmp(&a.offered)).then(a.name.cmp(&b.name)));
        ToolReport { tools, skills, requests }
    }

    /// The way of the tool call of MCP exchange `id` (a `tools/call`).
    pub fn mcp_trail(&self, id: SessionId) -> Option<ToolTrail> {
        let s = self.capture().index.get(id)?;
        let tool = s.mcp.strip_prefix("tools/call ")?.to_string();
        let built = self.all_built();
        // The latest LLM call before it whose answer asked for the tool.
        let asked = built.convs.iter().enumerate().flat_map(|(ci, c)| c.digests.iter().map(move |d| (ci, d))).filter(|(_, d)| d.started <= s.started_at && s.started_at - d.started <= LINK_US && d.calls.iter().any(|n| matches(n, &tool))).max_by_key(|(_, d)| d.started);
        let result_in = asked.and_then(|(ci, d)| next_in(&built.convs[ci].pred, &built.convs[ci].digests, d.id));
        let offering: Vec<&Arc<Digest>> = built.convs.iter().flat_map(|c| &c.digests).filter(|d| d.tools.iter().any(|t| matches(&t.0, &tool))).collect();
        Some(ToolTrail {
            tool,
            requested_by: asked.map(|(_, d)| d.id),
            mcp: Some(id),
            result_in,
            offered: offering.len() as u32,
            def_tokens: offering.last().and_then(|d| d.tools.iter().find(|t| matches(&t.0, &s.mcp["tools/call ".len()..]))).map(|t| t.2).unwrap_or(0),
        })
    }

    /// For each tool call in the answer of LLM call `id`: the MCP exchange that ran it.
    pub fn llm_tool_trails(&self, id: SessionId) -> Vec<ToolTrail> {
        let built = self.all_built();
        let Some(ci) = built.conv_of.get(&id).copied() else { return vec![] };
        let c = &built.convs[ci];
        let Some(d) = c.digests.iter().find(|d| d.id == id) else { return vec![] };
        let end = d.started + d.duration_ms.unwrap_or(0) as i64 * 1_000;
        let calls = self.mcp_calls();
        let mut used: HashSet<SessionId> = HashSet::new();
        let result_in = next_in(&c.pred, &c.digests, id);
        d.calls
            .iter()
            .map(|name| {
                let mcp = calls.iter().filter(|m| m.started >= end && m.started - end <= LINK_US && matches(name, &m.tool) && !used.contains(&m.id)).min_by_key(|m| m.started).map(|m| m.id);
                if let Some(m) = mcp {
                    used.insert(m);
                }
                ToolTrail { tool: name.clone(), requested_by: Some(id), mcp, result_in, offered: 0, def_tokens: d.tools.iter().find(|t| &t.0 == name).map(|t| t.2).unwrap_or(0) }
            })
            .collect()
    }
}

/// The call that continues `id` in its conversation (the first of them).
fn next_in(pred: &HashMap<SessionId, SessionId>, digests: &[Arc<Digest>], id: SessionId) -> Option<SessionId> {
    digests.iter().filter(|d| pred.get(&d.id) == Some(&id)).map(|d| d.id).min()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_tool_names() {
        assert_eq!(split_tool("mcp__jira__get_issue"), (Some("jira"), "get_issue"));
        assert_eq!(split_tool("mcp__claude_ai_Notion__search"), (Some("claude_ai_Notion"), "search"));
        assert_eq!(split_tool("Read"), (None, "Read"));
        assert!(matches("mcp__jira__get_issue", "get_issue"));
        assert!(!matches("mcp__jira__get_issue", "get"));
    }
}
