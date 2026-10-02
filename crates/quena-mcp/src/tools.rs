//! The MCP tools: thin wrappers over the [`AppCore`] API, with bounded output (lists are
//! paged, bodies cut at a byte limit) so an agent never pulls a whole capture at once.

use anyhow::{Result, anyhow, bail};
use quena_app_core::AppCore;
use quena_app_core::compose::{ComposeRequest, ReplayOptions};
use quena_app_core::dto::{is_textual_type, sniff_text, spec_of};
use quena_app_core::rewrite::{Op, Phase, RewriteRule};
use quena_app_core::rules::{BreakpointState, Resume, Rule};
use quena_app_core::settings::McpAccess;
use quena_body::Body;
use quena_model::{Headers, SessionId, SessionSummary, flags};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::{Duration, Instant};

const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 200;
const DEFAULT_BODY: usize = 16 << 10;
const MAX_BODY: usize = 1 << 20;
/// `get_body` decodes from the start; offsets beyond this would decode too much per call.
const MAX_OFFSET: u64 = 64 << 20;

struct Tool {
    name: &'static str,
    description: &'static str,
    /// Changes state: hidden and refused unless the user granted full control.
    write: bool,
    destructive: bool,
    schema: fn() -> Value,
    run: fn(&Arc<AppCore>, Value) -> Result<Value>,
}

static TOOLS: &[Tool] = &[
    // ------------------------------------------------------------------ read
    Tool {
        name: "status",
        description: "Capture state (capturing, listen address, HTTPS decryption, upstream proxy), number of sessions, active breakpoints and mock rules, and what this MCP client may do.",
        write: false,
        destructive: false,
        schema: || obj(json!({})),
        run: status,
    },
    Tool {
        name: "list_sessions",
        description: "List captured sessions (oldest first) as compact rows: id, method, url, status, content type, sizes, duration, state, flags. Use `filter` with Quena's expression syntax (e.g. `host ~= \"*.example.com\" and status >= 400`, `method == POST`, `type ~ json`, `size > 100k`, `time > 1s`; a bare word matches the URL) and `since_id` to fetch only new sessions.",
        write: false,
        destructive: false,
        schema: || {
            obj(json!({
                "filter": { "type": "string", "description": "Filter expression (empty: all sessions)" },
                "since_id": { "type": "integer", "description": "Only sessions with a higher id" },
                "limit": { "type": "integer", "description": "Rows to return (default 50, at most 200)" },
                "offset": { "type": "integer", "description": "Rows to skip" },
                "newest_first": { "type": "boolean", "description": "Newest sessions first" }
            }))
        },
        run: list_sessions,
    },
    Tool {
        name: "get_session",
        description: "One session: request and response line and headers, timers, error, connection, and the bodies as text (Content-Encoding removed, charset decoded), each cut at `max_body_bytes`. Binary bodies are described, not included.",
        write: false,
        destructive: false,
        schema: || {
            req(
                json!({
                    "id": { "type": "integer" },
                    "bodies": { "type": "boolean", "description": "Include the bodies (default true)" },
                    "max_body_bytes": { "type": "integer", "description": "Per body (default 16384, at most 1048576)" }
                }),
                &["id"],
            )
        },
        run: get_session,
    },
    Tool {
        name: "get_body",
        description: "Read part of a request or response body: `length` bytes from `offset` of the decoded body (or the raw bytes with `decoded: false`). `more: true` means there is more after this piece.",
        write: false,
        destructive: false,
        schema: || {
            req(
                json!({
                    "id": { "type": "integer" },
                    "part": { "type": "string", "enum": ["request", "response"] },
                    "offset": { "type": "integer", "description": "Byte offset (default 0)" },
                    "length": { "type": "integer", "description": "Bytes (default 16384, at most 1048576)" },
                    "decoded": { "type": "boolean", "description": "Remove the Content-Encoding first (default true)" }
                }),
                &["id", "part"],
            )
        },
        run: get_body,
    },
    Tool {
        name: "search_sessions",
        description: "Find sessions whose URL, headers or bodies contain a text or match a regex. Returns matching session ids (and their rows).",
        write: false,
        destructive: false,
        schema: || {
            req(
                json!({
                    "text": { "type": "string" },
                    "regex": { "type": "boolean" },
                    "match_case": { "type": "boolean" },
                    "scope": { "type": "string", "enum": ["all", "requests", "responses", "urls"], "description": "default all" },
                    "examine": { "type": "string", "enum": ["all", "headers", "bodies"], "description": "default all" },
                    "filter": { "type": "string", "description": "Only search sessions matching this filter expression" },
                    "limit": { "type": "integer", "description": "Rows to return (default 50, at most 200)" }
                }),
                &["text"],
            )
        },
        run: search_sessions,
    },
    Tool {
        name: "statistics",
        description: "Totals for sessions (all, or those matching `filter`): bytes, status codes, content types, hosts, processes, aborted and in-flight counts.",
        write: false,
        destructive: false,
        schema: || obj(json!({ "filter": { "type": "string" } })),
        run: statistics,
    },
    Tool {
        name: "list_mock_rules",
        description: "The mock rules (AutoResponder): whether they are on, whether unmatched requests pass through, and each rule's id, match pattern, action, latency and hit count.",
        write: false,
        destructive: false,
        schema: || obj(json!({})),
        run: list_mock_rules,
    },
    Tool {
        name: "list_rewrite_rules",
        description: "Rewrite rules that change real traffic (JSON values, text, headers, status), with hit counts, whether they are on, and the body size limit.",
        write: false,
        destructive: false,
        schema: || obj(json!({})),
        run: list_rewrite_rules,
    },
    Tool {
        name: "preview_rewrite",
        description: "Dry run: apply a rewrite rule (same fields as add_rewrite_rule) to the body of a captured session and return the result, without sending anything. Use it to check a rule before adding it.",
        write: false,
        destructive: false,
        schema: || {
            req(
                json!({
                    "rule": rewrite_rule_schema(),
                    "id": { "type": "integer", "description": "Session whose body to use" },
                    "part": { "type": "string", "enum": ["request", "response"], "description": "default: the rule's phase" },
                    "max_body_bytes": { "type": "integer", "description": "Result limit (default 16384)" }
                }),
                &["rule", "id"],
            )
        },
        run: preview_rewrite,
    },
    Tool {
        name: "get_breakpoints",
        description: "Active breakpoints and the sessions currently paused at one.",
        write: false,
        destructive: false,
        schema: || obj(json!({})),
        run: get_breakpoints,
    },
    // ----------------------------------------------------------------- write
    Tool {
        name: "set_capture",
        description: "Start or stop capturing (Quena then acts as system proxy if configured so).",
        write: true,
        destructive: false,
        schema: || req(json!({ "on": { "type": "boolean" } }), &["on"]),
        run: set_capture,
    },
    Tool {
        name: "clear_sessions",
        description: "Remove sessions from the capture: those matching `filter`, or all when no filter is given.",
        write: true,
        destructive: true,
        schema: || obj(json!({ "filter": { "type": "string", "description": "Filter expression; omit to remove all" } })),
        run: clear_sessions,
    },
    Tool {
        name: "send_request",
        description: "Send an HTTP request through Quena (rules and breakpoints apply; it appears in the capture) and wait for the response. Returns the new session like `get_session`.",
        write: true,
        destructive: false,
        schema: || {
            req(
                json!({
                    "method": { "type": "string" },
                    "url": { "type": "string", "description": "Absolute http:// or https:// URL" },
                    "headers": { "type": "object", "additionalProperties": { "type": "string" } },
                    "body": { "type": "string" },
                    "wait_ms": { "type": "integer", "description": "Wait this long for the response (default 30000; 0: do not wait)" },
                    "max_body_bytes": { "type": "integer", "description": "Response body limit (default 16384)" }
                }),
                &["method", "url"],
            )
        },
        run: send_request,
    },
    Tool {
        name: "replay_sessions",
        description: "Send captured requests again (they appear as new sessions).",
        write: true,
        destructive: false,
        schema: || {
            req(
                json!({
                    "ids": { "type": "array", "items": { "type": "integer" } },
                    "count": { "type": "integer", "description": "Times each (default 1)" },
                    "unconditional": { "type": "boolean", "description": "Remove If-None-Match / If-Modified-Since …" },
                    "sequential": { "type": "boolean" }
                }),
                &["ids"],
            )
        },
        run: replay_sessions,
    },
    Tool {
        name: "add_mock_rule",
        description: "Add a mock rule and switch mock rules on. `match`: `exact:URL`, `prefix:URL`, `regex:…`, `NOT:…`, `METHOD:POST <match>`, `HEADER:Name=value`, `BODYJSON:<url match> <json>`, or a URL substring. `action`: a local file path, `dir:folder`, `*404` (any status), `*delay:500`, `*drop`, `*reset`, `*redir:URL`, `*header:Name=Value`, `*CORSPreflightAllow`, `http(s)://…` (map remote), `session:ID` (answer with a recorded response). New rules go first unless `position` is `last`.",
        write: true,
        destructive: false,
        schema: || {
            req(
                json!({
                    "match": { "type": "string" },
                    "action": { "type": "string" },
                    "comment": { "type": "string" },
                    "latency_ms": { "type": "integer" },
                    "match_once": { "type": "boolean" },
                    "position": { "type": "string", "enum": ["first", "last"] }
                }),
                &["match", "action"],
            )
        },
        run: add_mock_rule,
    },
    Tool {
        name: "update_mock_rule",
        description: "Change fields of a mock rule by id (only the fields given).",
        write: true,
        destructive: false,
        schema: || {
            req(
                json!({
                    "id": { "type": "integer" },
                    "enabled": { "type": "boolean" },
                    "match": { "type": "string" },
                    "action": { "type": "string" },
                    "comment": { "type": "string" },
                    "latency_ms": { "type": "integer" },
                    "match_once": { "type": "boolean" }
                }),
                &["id"],
            )
        },
        run: update_mock_rule,
    },
    Tool {
        name: "remove_mock_rule",
        description: "Delete a mock rule by id.",
        write: true,
        destructive: true,
        schema: || req(json!({ "id": { "type": "integer" } }), &["id"]),
        run: remove_mock_rule,
    },
    Tool {
        name: "set_mock_options",
        description: "Switch mock rules on or off as a whole, and choose whether requests matching no rule pass through (otherwise they get 404).",
        write: true,
        destructive: false,
        schema: || {
            obj(json!({
                "enabled": { "type": "boolean" },
                "unmatched_passthrough": { "type": "boolean" },
                "enable_latency": { "type": "boolean" }
            }))
        },
        run: set_mock_options,
    },
    Tool {
        name: "mock_from_sessions",
        description: "Create mock rules that answer the URLs of these sessions with their recorded responses.",
        write: true,
        destructive: false,
        schema: || req(json!({ "ids": { "type": "array", "items": { "type": "integer" } }, "exact": { "type": "boolean", "description": "Match the exact URL (default true)" } }), &["ids"]),
        run: mock_from_sessions,
    },
    Tool {
        name: "add_rewrite_rule",
        description: "Add a rule that changes matching real requests or responses on their way (switches rewriting on). Operations run in order: `jsonSet` {path, value} (creates missing members of a plain path), `jsonRemove` {path}, `jsonAppend` {path, value?}, `jsonAppendAll` {value?} (append to every array in the document; without value a broken copy of the first element: same keys, all null), `regexReplace` {pattern, replacement}, `setHeader` {name, value}, `removeHeader` {name}, `setStatus` {code}. Paths are RFC 9535 JSONPath (`$.items[*].price`, `$..id`). Bodies are decoded (gzip, br …) and sent back uncompressed; bodies over the size limit, event streams and non-text types pass unchanged. Example, a broken element in every list of /api/ responses: {\"match\": \"/api/\", \"ops\": [{\"op\": \"jsonAppendAll\"}]}.",
        write: true,
        destructive: false,
        schema: || {
            let mut s = rewrite_rule_schema();
            s["properties"]["position"] = json!({ "type": "string", "enum": ["first", "last"] });
            s["required"] = json!(["match", "ops"]);
            s
        },
        run: add_rewrite_rule,
    },
    Tool {
        name: "update_rewrite_rule",
        description: "Change a rewrite rule by id: `enabled`, or any field of add_rewrite_rule (the fields given replace the old ones).",
        write: true,
        destructive: false,
        schema: || {
            let mut s = rewrite_rule_schema();
            s["properties"]["id"] = json!({ "type": "integer" });
            s["properties"]["enabled"] = json!({ "type": "boolean" });
            s["required"] = json!(["id"]);
            s
        },
        run: update_rewrite_rule,
    },
    Tool {
        name: "remove_rewrite_rule",
        description: "Delete a rewrite rule by id.",
        write: true,
        destructive: true,
        schema: || req(json!({ "id": { "type": "integer" } }), &["id"]),
        run: remove_rewrite_rule,
    },
    Tool {
        name: "set_rewrite_options",
        description: "Switch all rewrite rules on or off, and set the largest body (KiB, default 4096) they change.",
        write: true,
        destructive: false,
        schema: || obj(json!({ "enabled": { "type": "boolean" }, "max_body_kb": { "type": "integer" } })),
        run: set_rewrite_options,
    },
    Tool {
        name: "set_breakpoints",
        description: "Change breakpoints (only the fields given; an empty string or 0 clears one). Paused sessions wait until `resume_session` or `resume_all` (or the timeout).",
        write: true,
        destructive: false,
        schema: || {
            obj(json!({
                "all_requests": { "type": "boolean" },
                "all_responses": { "type": "boolean" },
                "request_url": { "type": "string", "description": "Break before requests whose URL contains this" },
                "response_url": { "type": "string", "description": "Break after responses whose URL contains this" },
                "status": { "type": "integer", "description": "Break on this response status" },
                "method": { "type": "string" },
                "timeout_s": { "type": "integer", "description": "Release paused sessions after this many seconds (0: never)" }
            }))
        },
        run: set_breakpoints,
    },
    Tool {
        name: "resume_session",
        description: "Release a session paused at a breakpoint: `continue`, `breakOnResponse`, `abort`, or `respond` (synthetic response with `status`). `head_text` (start line and headers) and `body_text` replace the paused message.",
        write: true,
        destructive: false,
        schema: || {
            req(
                json!({
                    "id": { "type": "integer" },
                    "action": { "type": "string", "enum": ["continue", "breakOnResponse", "abort", "respond"] },
                    "head_text": { "type": "string" },
                    "body_text": { "type": "string" },
                    "status": { "type": "integer" }
                }),
                &["id", "action"],
            )
        },
        run: resume_session,
    },
    Tool {
        name: "resume_all",
        description: "Release all paused sessions unchanged.",
        write: true,
        destructive: false,
        schema: || obj(json!({})),
        run: resume_all,
    },
    Tool {
        name: "export_archive",
        description: "Save sessions (all, the given ids, or those matching `filter`) as .har or .saz. `path` must be absolute; an existing file is only replaced with `overwrite: true`.",
        write: true,
        destructive: false,
        schema: || {
            req(
                json!({
                    "path": { "type": "string" },
                    "ids": { "type": "array", "items": { "type": "integer" } },
                    "filter": { "type": "string" },
                    "overwrite": { "type": "boolean" }
                }),
                &["path"],
            )
        },
        run: export_archive,
    },
];

fn rewrite_rule_schema() -> Value {
    obj(json!({
        "match": { "type": "string", "description": "Mock Rules pattern on URL, method, headers: `*`, `exact:URL`, `prefix:URL`, `regex:…`, `METHOD:POST /x`, `HEADER:Name=value`, or a URL substring" },
        "phase": { "type": "string", "enum": ["request", "response"], "description": "default response" },
        "status": { "type": "string", "description": "Response status filter: `200`, `2xx`, `500-599`, comma separated (empty: any)" },
        "content_type": { "type": "string", "description": "Content type substrings, `;` separated (empty: any text type)" },
        "comment": { "type": "string" },
        "ops": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "op": { "type": "string", "enum": ["jsonSet", "jsonRemove", "jsonAppend", "jsonAppendAll", "regexReplace", "setHeader", "removeHeader", "setStatus"] },
                    "path": { "type": "string" },
                    "value": {},
                    "pattern": { "type": "string" },
                    "replacement": { "type": "string" },
                    "name": { "type": "string" },
                    "code": { "type": "integer" }
                },
                "required": ["op"]
            }
        }
    }))
}

fn obj(props: Value) -> Value {
    json!({ "type": "object", "properties": props })
}

fn req(props: Value, required: &[&str]) -> Value {
    json!({ "type": "object", "properties": props, "required": required })
}

/// `tools/list`: the tools this access level may call.
pub fn list(access: McpAccess) -> Vec<Value> {
    TOOLS
        .iter()
        .filter(|t| !t.write || access == McpAccess::Full)
        .map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": (t.schema)(),
                "annotations": { "readOnlyHint": !t.write, "destructiveHint": t.destructive, "openWorldHint": false },
            })
        })
        .collect()
}

/// `tools/call`; `None` for an unknown tool. Tool failures are results with `isError`.
pub fn call(core: &Arc<AppCore>, access: McpAccess, name: &str, args: Value) -> Option<Value> {
    let tool = TOOLS.iter().find(|t| t.name == name)?;
    let r = if tool.write && access != McpAccess::Full {
        Err(anyhow!("`{name}` changes Quena; the user has to grant full control in Quena → Options → MCP"))
    } else {
        (tool.run)(core, args)
    };
    Some(match r {
        Ok(v) => json!({ "content": [{ "type": "text", "text": v.to_string() }] }),
        Err(e) => json!({ "content": [{ "type": "text", "text": format!("{e:#}") }], "isError": true }),
    })
}

fn args<T: DeserializeOwned>(v: Value) -> Result<T> {
    let v = if v.is_null() { json!({}) } else { v };
    serde_json::from_value(v).map_err(|e| anyhow!("invalid arguments: {e}"))
}

// ------------------------------------------------------------------ helpers

fn flag_names(f: u32) -> Vec<&'static str> {
    const NAMES: &[(u32, &str)] = &[
        (flags::REPLAYED, "replayed"),
        (flags::AUTO_RESPONDED, "mocked"),
        (flags::BREAKPOINTED, "breakpointed"),
        (flags::TAMPERED, "tampered"),
        (flags::REQUEST_TRUNCATED, "requestTruncated"),
        (flags::RESPONSE_TRUNCATED, "responseTruncated"),
        (flags::DECRYPTED, "decrypted"),
        (flags::REMOTE_CLIENT, "remoteClient"),
        (flags::IMPORTED, "imported"),
        (flags::STREAMED, "streamed"),
        (flags::CLIENT_ABORTED, "clientAborted"),
        (flags::SERVER_ABORTED, "serverAborted"),
        (flags::COMPOSED, "composed"),
    ];
    NAMES.iter().filter(|(b, _)| f & b != 0).map(|(_, n)| *n).collect()
}

fn row(s: &SessionSummary) -> Value {
    let mut v = json!({
        "id": s.id,
        "method": s.method,
        "url": s.full_url(),
        "status": s.status,
        "type": s.content_type,
        "requestSize": s.request_body_len,
        "responseSize": s.response_body_len,
        "durationMs": s.duration_ms,
        "state": s.state,
        "flags": flag_names(s.flags),
    });
    if !s.comment.is_empty() {
        v["comment"] = json!(s.comment);
    }
    if !s.process.is_empty() {
        v["process"] = json!(s.process);
    }
    v
}

/// Ids of all sessions (hidden ones too) matching an optional expression, ascending.
fn matching_ids(core: &AppCore, filter: Option<&str>, since: SessionId) -> Result<Vec<SessionId>> {
    let cap = core.capture();
    let mut ids = match filter.map(str::trim).filter(|f| !f.is_empty()) {
        Some(f) => {
            let e = quena_query::expr::parse(f).map_err(|e| anyhow!("filter: {e}"))?;
            cap.index.find_all(|s| s.id > since && e.eval(s))
        }
        None => cap.index.find_all(|s| s.id > since),
    };
    ids.sort_unstable();
    Ok(ids)
}

fn headers_json(h: &Headers) -> Value {
    Value::Array(h.0.iter().map(|(n, v)| json!([n, v])).collect())
}

/// A piece of a body as text (or a description of a binary one).
fn body_piece(body: &Body, headers: &Headers, offset: u64, max: usize, decoded: bool) -> Value {
    let spec = spec_of(headers);
    let ct = headers.get("content-type");
    let encoded = spec.content_encoding.as_deref().is_some_and(|c| !c.trim().is_empty() && !c.eq_ignore_ascii_case("identity"));
    let end = (offset as usize).saturating_add(max).saturating_add(1);
    let bytes = if decoded { quena_body::text::decoded_prefix(body, &spec, end) } else { body.read_range(0, end).unwrap_or_default() };
    let start = (offset as usize).min(bytes.len());
    let stop = start.saturating_add(max).min(bytes.len());
    let mut v = json!({
        "storedLength": body.len(),
        "offset": start,
        "more": bytes.len() > stop,
    });
    if let Some(c) = ct {
        v["contentType"] = json!(c);
    }
    if let Some(e) = &spec.content_encoding {
        v["contentEncoding"] = json!(e);
        v["decoded"] = json!(decoded);
    }
    if !body.is_complete() {
        v["complete"] = json!(false);
    }
    if body.is_truncated() {
        v["truncatedInCapture"] = json!(true);
    }
    if body.is_empty() {
        v["text"] = json!("");
        return v;
    }
    let sample = &bytes[..bytes.len().min(1024)];
    let textual = (!encoded || decoded)
        && match ct {
            Some(c) if is_textual_type(c) => true,
            Some(c) if c.starts_with("image/") || c.starts_with("video/") || c.starts_with("audio/") || c.starts_with("font/") => false,
            _ => sniff_text(sample),
        };
    if !textual {
        v["binary"] = json!(true);
        return v;
    }
    let det = quena_body::charset::detect(ct, &bytes[..bytes.len().min(quena_body::text::DETECT_PREFIX)]);
    let from = if start == 0 { det.bom_len.min(stop) } else { start };
    v["charset"] = json!(det.name());
    v["text"] = json!(quena_body::text::decode_piece(&bytes[from..stop], det.encoding));
    v
}

fn session_json(core: &AppCore, id: SessionId, bodies: bool, max: usize) -> Result<Value> {
    let cap = core.capture();
    let d = cap.detail(id).ok_or_else(|| anyhow!("session #{id} not found"))?;
    let mut v = json!({
        "session": row(&d.summary),
        "request": { "method": d.request.method, "url": d.request.url, "version": d.request.version, "headers": headers_json(&d.request.headers) },
        "timers": d.timers,
        "connection": d.connection,
    });
    if let Some(r) = &d.response {
        v["response"] = json!({ "status": r.status, "reason": r.reason, "version": r.version, "headers": headers_json(&r.headers) });
    }
    if let Some(e) = &d.error {
        v["error"] = json!(e);
    }
    if bodies && let Some((req_body, resp_body)) = cap.bodies_of(id) {
        v["request"]["body"] = body_piece(&req_body, &d.request.headers, 0, max, true);
        if let Some(r) = &d.response {
            v["response"]["body"] = body_piece(&resp_body, &r.headers, 0, max, true);
        }
    }
    Ok(v)
}

fn body_limit(n: Option<usize>) -> usize {
    n.unwrap_or(DEFAULT_BODY).clamp(1, MAX_BODY)
}

fn page(n: Option<usize>) -> usize {
    n.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
}

fn rules(core: &AppCore) -> Result<&Arc<quena_app_core::rules::Rules>> {
    core.rules.as_ref().ok_or_else(|| anyhow!("rules unavailable"))
}

// ---------------------------------------------------------------- read tools

fn status(core: &Arc<AppCore>, _: Value) -> Result<Value> {
    let st = core.status();
    let s = core.settings();
    let r = core.rules.as_ref();
    Ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "capturing": st.engine.capturing,
        "listen": st.engine.listen,
        "systemProxy": st.engine.system_proxy,
        "decryptingHttps": st.engine.decrypting,
        "upstream": st.engine.upstream,
        "engineError": st.engine.error,
        "sessions": st.sessions,
        "breakpoints": st.engine.breakpoints,
        "paused": st.engine.paused,
        "mockRulesActive": r.is_some_and(|r| r.autoresponder_active()),
        "access": s.mcp.access,
    }))
}

#[derive(Deserialize)]
struct ListArgs {
    filter: Option<String>,
    since_id: Option<SessionId>,
    limit: Option<usize>,
    offset: Option<usize>,
    #[serde(default)]
    newest_first: bool,
}

fn list_sessions(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: ListArgs = args(a)?;
    let mut ids = matching_ids(core, a.filter.as_deref(), a.since_id.unwrap_or(0))?;
    if a.newest_first {
        ids.reverse();
    }
    let total = ids.len();
    let cap = core.capture();
    let rows: Vec<Value> = ids.iter().skip(a.offset.unwrap_or(0)).take(page(a.limit)).filter_map(|id| cap.index.get(*id)).map(|s| row(&s)).collect();
    Ok(json!({ "total": total, "returned": rows.len(), "sessions": rows }))
}

#[derive(Deserialize)]
struct SessionArgs {
    id: SessionId,
    bodies: Option<bool>,
    max_body_bytes: Option<usize>,
}

fn get_session(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: SessionArgs = args(a)?;
    session_json(core, a.id, a.bodies.unwrap_or(true), body_limit(a.max_body_bytes))
}

#[derive(Deserialize)]
struct BodyArgs {
    id: SessionId,
    part: String,
    offset: Option<u64>,
    length: Option<usize>,
    decoded: Option<bool>,
}

fn get_body(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: BodyArgs = args(a)?;
    let offset = a.offset.unwrap_or(0);
    if offset > MAX_OFFSET {
        bail!("offset beyond {} MiB: use export_archive for bodies this large", MAX_OFFSET >> 20);
    }
    let cap = core.capture();
    let d = cap.detail(a.id).ok_or_else(|| anyhow!("session #{} not found", a.id))?;
    let (req_body, resp_body) = cap.bodies_of(a.id).ok_or_else(|| anyhow!("session #{} not found", a.id))?;
    let empty = Headers::default();
    let (body, headers) = match a.part.as_str() {
        "request" => (req_body, &d.request.headers),
        "response" => (resp_body, d.response.as_ref().map(|r| &r.headers).unwrap_or(&empty)),
        p => bail!("part must be request or response, not {p}"),
    };
    Ok(body_piece(&body, headers, offset, body_limit(a.length), a.decoded.unwrap_or(true)))
}

#[derive(Deserialize)]
struct SearchArgs {
    text: String,
    #[serde(default)]
    regex: bool,
    #[serde(default)]
    match_case: bool,
    scope: Option<String>,
    examine: Option<String>,
    filter: Option<String>,
    limit: Option<usize>,
}

fn search_sessions(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: SearchArgs = args(a)?;
    let ids = matching_ids(core, a.filter.as_deref(), 0)?;
    if ids.is_empty() {
        return Ok(json!({ "total": 0, "sessions": [] }));
    }
    let opts: quena_app_core::find::FindOptions = serde_json::from_value(json!({
        "text": a.text,
        "regex": a.regex,
        "matchCase": a.match_case,
        "scope": a.scope.unwrap_or_else(|| "all".into()),
        "examine": a.examine.unwrap_or_else(|| "all".into()),
        "ids": ids,
        "decode": true,
    }))?;
    let job = core.find_sessions(opts)?;
    let done = core.jobs.wait(job, Duration::from_secs(60));
    let r = core.find_result(job).ok_or_else(|| anyhow!("search result gone"))?;
    let cap = core.capture();
    let rows: Vec<Value> = r.ids.iter().take(page(a.limit)).filter_map(|id| cap.index.get(*id)).map(|s| row(&s)).collect();
    Ok(json!({ "total": r.ids.len(), "complete": done.is_ok() && r.done, "sessions": rows }))
}

#[derive(Deserialize)]
struct FilterArgs {
    filter: Option<String>,
}

fn statistics(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: FilterArgs = args(a)?;
    let ids = matching_ids(core, a.filter.as_deref(), 0)?;
    Ok(serde_json::to_value(core.statistics(ids))?)
}

fn list_mock_rules(core: &Arc<AppCore>, _: Value) -> Result<Value> {
    Ok(serde_json::to_value(rules(core)?.autoresponder())?)
}

fn list_rewrite_rules(core: &Arc<AppCore>, _: Value) -> Result<Value> {
    Ok(serde_json::to_value(rules(core)?.rewrite.state())?)
}

/// Rule fields as the tools take them (snake_case) or the app stores them (camelCase).
#[derive(Deserialize, Default)]
struct RuleArgs {
    #[serde(rename = "match")]
    match_: Option<String>,
    phase: Option<Phase>,
    status: Option<String>,
    #[serde(alias = "contentType")]
    content_type: Option<String>,
    comment: Option<String>,
    ops: Option<Vec<Op>>,
}

impl RuleArgs {
    fn apply(self, r: &mut RewriteRule) {
        if let Some(v) = self.match_ {
            r.match_ = v;
        }
        if let Some(v) = self.phase {
            r.phase = v;
        }
        if let Some(v) = self.status {
            r.status = v;
        }
        if let Some(v) = self.content_type {
            r.content_type = v;
        }
        if let Some(v) = self.comment {
            r.comment = v;
        }
        if let Some(v) = self.ops {
            r.ops = v;
        }
    }
}

#[derive(Deserialize)]
struct PreviewArgs {
    rule: RuleArgs,
    id: SessionId,
    part: Option<String>,
    max_body_bytes: Option<usize>,
}

fn preview_rewrite(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: PreviewArgs = args(a)?;
    let mut rule = RewriteRule::default();
    a.rule.apply(&mut rule);
    let cap = core.capture();
    let d = cap.detail(a.id).ok_or_else(|| anyhow!("session #{} not found", a.id))?;
    let (req_body, resp_body) = cap.bodies_of(a.id).ok_or_else(|| anyhow!("session #{} not found", a.id))?;
    let part = a.part.unwrap_or_else(|| if rule.phase == Phase::Request { "request".into() } else { "response".into() });
    let (body, headers) = match part.as_str() {
        "request" => (req_body, d.request.headers.clone()),
        "response" => (resp_body, d.response.as_ref().map(|r| r.headers.clone()).unwrap_or_default()),
        p => bail!("part must be request or response, not {p}"),
    };
    const LIMIT: usize = 8 << 20;
    let bytes = quena_body::text::decoded_prefix(&body, &spec_of(&headers), LIMIT + 1);
    if bytes.len() > LIMIT {
        bail!("body larger than {} MiB", LIMIT >> 20);
    }
    let det = quena_body::charset::detect(headers.get("content-type"), &bytes[..bytes.len().min(quena_body::text::DETECT_PREFIX)]);
    let text = quena_body::charset::decode(&bytes[det.bom_len.min(bytes.len())..], det.encoding).0.into_owned();
    let (out, notes) = rules(core)?.rewrite.preview(&rule, &text)?;
    let max = body_limit(a.max_body_bytes);
    let mut cut = out.len().min(max);
    while !out.is_char_boundary(cut) {
        cut -= 1;
    }
    Ok(json!({ "changed": out != text, "notes": notes, "length": out.len(), "more": out.len() > cut, "text": &out[..cut] }))
}

fn get_breakpoints(core: &Arc<AppCore>, _: Value) -> Result<Value> {
    let r = rules(core)?;
    Ok(json!({ "breakpoints": r.breakpoints(), "paused": r.paused() }))
}

// --------------------------------------------------------------- write tools

#[derive(Deserialize)]
struct OnArgs {
    on: bool,
}

fn set_capture(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: OnArgs = args(a)?;
    if a.on { core.start_capture()? } else { core.stop_capture()? }
    Ok(json!({ "capturing": core.status().engine.capturing }))
}

fn clear_sessions(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: FilterArgs = args(a)?;
    let removed = match a.filter.as_deref().map(str::trim).filter(|f| !f.is_empty()) {
        Some(f) => core.remove_where(f)?,
        None => {
            let n = core.capture().index.len();
            core.remove_all();
            n
        }
    };
    Ok(json!({ "removed": removed }))
}

#[derive(Deserialize)]
struct SendArgs {
    method: String,
    url: String,
    #[serde(default)]
    headers: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    body: String,
    wait_ms: Option<u64>,
    max_body_bytes: Option<usize>,
}

fn send_request(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: SendArgs = args(a)?;
    let headers = a.headers.iter().map(|(n, v)| format!("{n}: {v}")).collect::<Vec<_>>().join("\n");
    let id = core.compose(ComposeRequest {
        method: a.method,
        url: a.url,
        version: None,
        headers,
        body: a.body,
        body_charset: None,
        body_from_session: None,
        body_file: None,
        fix_content_length: true,
        breakpoint: false,
    })?;
    let wait = Duration::from_millis(a.wait_ms.unwrap_or(30_000).min(300_000));
    let finished = wait_for(core, id, wait);
    let mut v = session_json(core, id, true, body_limit(a.max_body_bytes))?;
    if !finished {
        v["pending"] = json!(true);
    }
    Ok(v)
}

/// Wait until a session is done, aborted or paused at a breakpoint.
fn wait_for(core: &AppCore, id: SessionId, wait: Duration) -> bool {
    let until = Instant::now() + wait;
    loop {
        match core.capture().index.get(id) {
            Some(s) if s.state.is_final() || s.state.is_breakpoint() => return true,
            None => return true,
            _ => {}
        }
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[derive(Deserialize)]
struct ReplayArgs {
    ids: Vec<SessionId>,
    count: Option<u32>,
    #[serde(default)]
    unconditional: bool,
    #[serde(default)]
    sequential: bool,
}

fn replay_sessions(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: ReplayArgs = args(a)?;
    let since = core.capture().index.find_all(|_| true).into_iter().max().unwrap_or(0);
    let n = core.replay(a.ids, ReplayOptions { unconditional: a.unconditional, count: a.count.unwrap_or(1).clamp(1, 1000), breakpoint: false, sequential: a.sequential })?;
    Ok(json!({ "started": n, "hint": format!("new sessions appear with ids above {since} (list_sessions since_id={since})") }))
}

#[derive(Deserialize)]
struct AddRuleArgs {
    #[serde(rename = "match")]
    match_: String,
    action: String,
    #[serde(default)]
    comment: String,
    #[serde(default)]
    latency_ms: u32,
    #[serde(default)]
    match_once: bool,
    position: Option<String>,
}

fn add_mock_rule(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: AddRuleArgs = args(a)?;
    let comment = if a.comment.is_empty() { "added by an MCP client".to_string() } else { a.comment };
    let rule = Rule { id: 0, enabled: true, match_: a.match_, action: a.action, latency_ms: a.latency_ms, match_once: a.match_once, comment, hits: 0 };
    let id = rules(core)?.add_rule(rule, a.position.as_deref() != Some("last"))?;
    Ok(json!({ "id": id }))
}

#[derive(Deserialize)]
struct UpdateRuleArgs {
    id: u64,
    enabled: Option<bool>,
    #[serde(rename = "match")]
    match_: Option<String>,
    action: Option<String>,
    comment: Option<String>,
    latency_ms: Option<u32>,
    match_once: Option<bool>,
}

fn update_mock_rule(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: UpdateRuleArgs = args(a)?;
    let found = rules(core)?.update_autoresponder(true, |s| {
        let Some(r) = s.rules.iter_mut().find(|r| r.id == a.id) else { return false };
        if let Some(v) = a.enabled {
            r.enabled = v;
        }
        if let Some(v) = a.match_ {
            r.match_ = v;
        }
        if let Some(v) = a.action {
            r.action = v;
        }
        if let Some(v) = a.comment {
            r.comment = v;
        }
        if let Some(v) = a.latency_ms {
            r.latency_ms = v;
        }
        if let Some(v) = a.match_once {
            r.match_once = v;
        }
        true
    })?;
    if !found {
        bail!("no mock rule with id {}", a.id);
    }
    Ok(json!({ "updated": a.id }))
}

#[derive(Deserialize)]
struct IdArgs {
    id: u64,
}

fn remove_mock_rule(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: IdArgs = args(a)?;
    let found = rules(core)?.update_autoresponder(true, |s| {
        let n = s.rules.len();
        s.rules.retain(|r| r.id != a.id);
        s.rules.len() != n
    })?;
    if !found {
        bail!("no mock rule with id {}", a.id);
    }
    Ok(json!({ "removed": a.id }))
}

#[derive(Deserialize)]
struct MockOptionArgs {
    enabled: Option<bool>,
    unmatched_passthrough: Option<bool>,
    enable_latency: Option<bool>,
}

fn set_mock_options(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: MockOptionArgs = args(a)?;
    let r = rules(core)?;
    r.update_autoresponder(true, |s| {
        if let Some(v) = a.enabled {
            s.enabled = v;
        }
        if let Some(v) = a.unmatched_passthrough {
            s.unmatched_passthrough = v;
        }
        if let Some(v) = a.enable_latency {
            s.enable_latency = v;
        }
    })?;
    let s = r.autoresponder();
    Ok(json!({ "enabled": s.enabled, "unmatchedPassthrough": s.unmatched_passthrough, "enableLatency": s.enable_latency }))
}

#[derive(Deserialize)]
struct MockFromArgs {
    ids: Vec<SessionId>,
    exact: Option<bool>,
}

fn mock_from_sessions(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: MockFromArgs = args(a)?;
    let n = rules(core)?.add_rules_from_sessions(&a.ids, a.exact.unwrap_or(true))?;
    Ok(json!({ "added": n }))
}

#[derive(Deserialize)]
struct AddRewriteArgs {
    #[serde(flatten)]
    rule: RuleArgs,
    position: Option<String>,
}

fn add_rewrite_rule(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: AddRewriteArgs = args(a)?;
    let mut rule = RewriteRule { comment: "added by an MCP client".into(), ..Default::default() };
    a.rule.apply(&mut rule);
    let rw = &rules(core)?.rewrite;
    let id = rw.add(rule, a.position.as_deref() != Some("last"))?;
    let enabled = rw.state().enabled;
    if !enabled {
        rw.update(|s| s.enabled = true)?;
    }
    Ok(json!({ "id": id }))
}

#[derive(Deserialize)]
struct UpdateRewriteArgs {
    id: u64,
    enabled: Option<bool>,
    #[serde(flatten)]
    rule: RuleArgs,
}

fn update_rewrite_rule(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: UpdateRewriteArgs = args(a)?;
    let found = rules(core)?.rewrite.update(|s| {
        let Some(r) = s.rules.iter_mut().find(|r| r.id == a.id) else { return false };
        if let Some(v) = a.enabled {
            r.enabled = v;
        }
        a.rule.apply(r);
        true
    })?;
    if !found {
        bail!("no rewrite rule with id {}", a.id);
    }
    Ok(json!({ "updated": a.id }))
}

fn remove_rewrite_rule(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: IdArgs = args(a)?;
    let found = rules(core)?.rewrite.update(|s| {
        let n = s.rules.len();
        s.rules.retain(|r| r.id != a.id);
        s.rules.len() != n
    })?;
    if !found {
        bail!("no rewrite rule with id {}", a.id);
    }
    Ok(json!({ "removed": a.id }))
}

#[derive(Deserialize)]
struct RewriteOptionArgs {
    enabled: Option<bool>,
    max_body_kb: Option<u64>,
}

fn set_rewrite_options(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: RewriteOptionArgs = args(a)?;
    let rw = &rules(core)?.rewrite;
    rw.update(|s| {
        if let Some(v) = a.enabled {
            s.enabled = v;
        }
        if let Some(v) = a.max_body_kb {
            s.max_body_kb = v.clamp(1, 256 << 10);
        }
    })?;
    let s = rw.state();
    Ok(json!({ "enabled": s.enabled, "maxBodyKb": s.max_body_kb }))
}

#[derive(Deserialize)]
struct BreakpointArgs {
    all_requests: Option<bool>,
    all_responses: Option<bool>,
    request_url: Option<String>,
    response_url: Option<String>,
    status: Option<u16>,
    method: Option<String>,
    timeout_s: Option<u64>,
}

fn set_breakpoints(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: BreakpointArgs = args(a)?;
    let r = rules(core)?;
    let text = |s: String| {
        let s = s.trim().to_lowercase();
        (!s.is_empty()).then_some(s)
    };
    r.update_breakpoints(|b: &mut BreakpointState| {
        if let Some(v) = a.all_requests {
            b.all_requests = v;
        }
        if let Some(v) = a.all_responses {
            b.all_responses = v;
        }
        if let Some(v) = a.request_url {
            b.request_url = text(v);
        }
        if let Some(v) = a.response_url {
            b.response_url = text(v);
        }
        if let Some(v) = a.status {
            b.status = (v != 0).then_some(v);
        }
        if let Some(v) = a.method {
            b.method = (!v.trim().is_empty()).then(|| v.trim().to_ascii_uppercase());
        }
        if let Some(v) = a.timeout_s {
            b.timeout_s = v;
        }
    });
    Ok(json!({ "breakpoints": r.breakpoints() }))
}

#[derive(Deserialize)]
struct ResumeArgs {
    id: SessionId,
    action: String,
    head_text: Option<String>,
    body_text: Option<String>,
    status: Option<u16>,
}

fn resume_session(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: ResumeArgs = args(a)?;
    if !matches!(a.action.as_str(), "continue" | "breakOnResponse" | "abort" | "respond") {
        bail!("unknown action {}", a.action);
    }
    rules(core)?.resume(a.id, Resume { action: a.action, head_text: a.head_text, body_text: a.body_text, body_charset: None, body_file: None, status: a.status })?;
    Ok(json!({ "resumed": a.id }))
}

fn resume_all(core: &Arc<AppCore>, _: Value) -> Result<Value> {
    Ok(json!({ "resumed": rules(core)?.go_all() }))
}

#[derive(Deserialize)]
struct ExportArgs {
    path: String,
    ids: Option<Vec<SessionId>>,
    filter: Option<String>,
    #[serde(default)]
    overwrite: bool,
}

fn export_archive(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: ExportArgs = args(a)?;
    let path = std::path::PathBuf::from(&a.path);
    if !path.is_absolute() {
        bail!("path must be absolute");
    }
    if path.exists() && !a.overwrite {
        bail!("{} exists (pass overwrite: true to replace it)", path.display());
    }
    let ids = match a.ids {
        Some(ids) if !ids.is_empty() => ids,
        _ => matching_ids(core, a.filter.as_deref(), 0)?,
    };
    if ids.is_empty() {
        bail!("no sessions to export");
    }
    let n = ids.len();
    let job = core.export_archive(ids, path.clone(), None)?;
    let info = core.jobs.wait(job, Duration::from_secs(600)).map_err(|e| anyhow!("export {e}"))?;
    if let Some(e) = info.error {
        bail!("export failed: {e}");
    }
    Ok(json!({ "path": path.display().to_string(), "sessions": n }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_hides_write_tools() {
        let ro: Vec<String> = list(McpAccess::ReadOnly).iter().map(|t| t["name"].as_str().unwrap().to_string()).collect();
        let full = list(McpAccess::Full);
        assert!(ro.contains(&"list_sessions".to_string()));
        assert!(!ro.iter().any(|n| n == "add_mock_rule" || n == "send_request" || n == "clear_sessions"));
        assert!(full.len() > ro.len());
        for t in TOOLS {
            let s = (t.schema)();
            assert_eq!(s["type"], "object", "{}", t.name);
        }
    }

    #[test]
    fn flags_by_name() {
        assert_eq!(flag_names(flags::TAMPERED | flags::COMPOSED), vec!["tampered", "composed"]);
    }
}
