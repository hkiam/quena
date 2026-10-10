//! The MCP tools: thin wrappers over the [`AppCore`] API, with bounded output (lists are
//! paged, bodies cut at a byte limit) so an agent never pulls a whole capture at once.

use anyhow::{Context, Result, anyhow, bail};
use quena_app_core::AppCore;
use quena_app_core::compose::{ComposeRequest, ReplayOptions};
use quena_app_core::dto::{is_textual_type, sniff_text, spec_of};
use quena_app_core::rewrite::{Op, Phase, RewriteRule};
use quena_app_core::rules::{BreakpointState, Resume, Rule};
use quena_app_core::sanitize::{BodyMode, SanitizeOptions, Sanitizer};
use quena_app_core::settings::McpAccess;
use quena_formats::http_file::Access;
use quena_body::Body;
use quena_model::{Headers, SessionDetail, SessionId, SessionSummary, flags};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 200;
const DEFAULT_BODY: usize = 16 << 10;
const MAX_BODY: usize = 1 << 20;
/// `get_body` decodes from the start; offsets beyond this would decode too much per call.
const MAX_OFFSET: u64 = 8 << 20;

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
        description: "List captured sessions (oldest first) as compact rows: id, method, url, status, content type, sizes, duration, state, flags, client connection (`conn`) and trace id. Use `filter` with Quena's expression syntax (e.g. `host ~= \"*.example.com\" and status >= 400`, `method == POST`, `type ~ json`, `size > 100k`, `time > 1s`; a bare word matches the URL) and `since_id` to fetch only new sessions.",
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
        name: "compare_captures",
        description: "Compare two captures in the list: `a` (before) and `b` (after) are `live` (recorded sessions) or the file name of an archive loaded into the list (without `a`/`b`: the sides are listed). Returns requests that changed (status, type, time, headers, body), are new or gone, paired by method, host and normalized path.",
        write: false,
        destructive: false,
        schema: || obj(json!({ "a": { "type": "string" }, "b": { "type": "string" }, "all": { "type": "boolean", "description": "Also unchanged requests" }, "ignore_host": { "type": "boolean", "description": "Pair by method and path only (staging against production)" }, "pair_by": { "type": "string", "enum": ["path", "url", "order"] }, "ignore_headers": { "type": "array", "items": { "type": "string" }, "description": "Response headers not compared" } })),
        run: compare_captures,
    },
    Tool {
        name: "run_diagnostics",
        description: "Run Quena's diagnostics over sessions (all, those matching `filter`, or `ids`) and return the findings: slow or failing endpoints, retries, caching, compression, redirects, TLS and connection problems … each with severity, observation, impact, recommendations and the session ids. Takes up to `wait_s` seconds (default 120). The report replaces the one in Quena's Diagnostics tab (an analysis running there is stopped).",
        write: false,
        destructive: false,
        schema: || obj(json!({
            "filter": { "type": "string", "description": "Quena filter expression; default all sessions" },
            "ids": { "type": "array", "items": { "type": "integer" } },
            "hosts": { "type": "array", "items": { "type": "string" }, "description": "Only these hosts (`*.example.com` allowed)" },
            "processes": { "type": "array", "items": { "type": "string" } },
            "profile": { "type": "string", "description": "Analyzer profile (see get_diagnostics_report without a report for the list)" },
            "wait_s": { "type": "integer" }
        })),
        run: run_diagnostics,
    },
    Tool {
        name: "get_diagnostics_report",
        description: "The last diagnostics report (from run_diagnostics or the Diagnostics tab) as findings, and the analyzer's profiles.",
        write: false,
        destructive: false,
        schema: || obj(json!({ "all": { "type": "boolean", "description": "Also findings of severity info" } })),
        run: get_diagnostics_report,
    },
    Tool {
        name: "get_llm_call",
        description: "A call to an LLM API (OpenAI, Anthropic, Gemini, Ollama and OpenAI-compatible) taken apart: provider, model, system prompt, the messages sent, tools, parameters, the answer (assembled from a stream), tool calls, stop reason, token usage and an estimated cost. Find such sessions with the filter `llm ~ claude` or `tokens > 1000`.",
        write: false,
        destructive: false,
        schema: || req(json!({ "id": { "type": "integer" } }), &["id"]),
        run: get_llm_call,
    },
    Tool {
        name: "llm_cache_status",
        description: "The agent cache: LLM API answers Quena serves again for the same request (entries with model, hits, saved tokens/cost/time), whether every call is cached, and repeated calls in the capture worth caching.",
        write: false,
        destructive: false,
        schema: || obj(json!({})),
        run: llm_cache_status,
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
        name: "list_http_requests",
        description: "The requests of a .http file (JetBrains HTTP Client / VS Code REST Client format) with variables resolved for an environment of http-client.env.json (and http-client.private.env.json) next to it; also lists the environments and parse warnings. `path` is relative to the agents' folder (see `status`) or inside it, or `collection:NAME` for one of the Composer's collections (see list_collections).",
        write: false,
        destructive: false,
        schema: || req(json!({ "path": { "type": "string" }, "env": { "type": "string", "description": "Environment name" } }), &["path"]),
        run: list_http_requests,
    },
    Tool {
        name: "list_collections",
        description: "The Composer's request collections (name, number of requests). Use `collection:NAME` as `path` in list_http_requests and run_http_file.",
        write: false,
        destructive: false,
        schema: || obj(json!({})),
        run: list_collections,
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
        name: "cache_llm_calls",
        description: "Agent cache: cache (`on`: true) or forget the answers of LLM API call sessions `ids`; the next identical request (same URL and JSON body, key order and `user`/`metadata` not counting) is answered by Quena without asking the model. `auto` true/false turns caching of every LLM call on or off.",
        write: true,
        destructive: false,
        schema: || obj(json!({ "ids": { "type": "array", "items": { "type": "integer" } }, "on": { "type": "boolean" }, "auto": { "type": "boolean" } })),
        run: cache_llm_calls,
    },
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
                    "follow_redirects": { "type": "boolean", "description": "Follow redirects, each as its own session (returns the first)" },
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
                    "sequential": { "type": "boolean" },
                    "parallel": { "type": "integer", "description": "At most this many at a time (1-100)" }
                }),
                &["ids"],
            )
        },
        run: replay_sessions,
    },
    Tool {
        name: "add_mock_rule",
        description: "Add a mock rule and switch mock rules on. `match`: `exact:URL`, `prefix:URL`, `regex:…`, `NOT:…`, `METHOD:POST <match>`, `HEADER:Name=value`, `BODYJSON:<url match> <json>`, or a URL substring. `action`: a file or `dir:folder` inside the agents' folder (see `status`), `*404` (any status), `*delay:500`, `*drop`, `*reset`, `*redir:URL`, `*header:Name=Value`, `*CORSPreflightAllow`, `http(s)://…` (map remote), `session:ID` (answer with a recorded response). New rules go first unless `position` is `last`.",
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
        name: "list_host_remaps",
        description: "Host remapping entries: connections to a host (or `*.domain`) go to another host, IP or port instead, like a hosts-file entry for traffic through Quena. `keepHost`: Host and TLS name stay the original's, only the connection moves.",
        write: false,
        destructive: false,
        schema: || obj(json!({})),
        run: list_host_remaps,
    },
    Tool {
        name: "set_host_remap",
        description: "Add a host remapping entry, or change one by `id` (only the fields given). `host`: name or `*.domain`; `target`: host, IP or host:port. `enabled_all` switches host remapping on or off as a whole.",
        write: true,
        destructive: false,
        schema: || {
            obj(json!({
                "id": { "type": "string" },
                "host": { "type": "string" },
                "target": { "type": "string" },
                "keep_host": { "type": "boolean", "description": "Keep Host and TLS name of the original (default true)" },
                "protocol": { "type": "string", "enum": ["", "http", "https"], "description": "Talk http or https to the target whatever the client used (empty: the same)" },
                "enabled": { "type": "boolean" },
                "comment": { "type": "string" },
                "enabled_all": { "type": "boolean" }
            }))
        },
        run: set_host_remap,
    },
    Tool {
        name: "remove_host_remap",
        description: "Delete a host remapping entry by id.",
        write: true,
        destructive: true,
        schema: || req(json!({ "id": { "type": "string" } }), &["id"]),
        run: remove_host_remap,
    },
    Tool {
        name: "launch_browser",
        description: "Start an installed browser (Chrome, Edge, Brave, Vivaldi, Chromium, Firefox) with its own profile and Quena as proxy, without the system proxy; capturing starts if it is off. Without `kind`, lists the browsers found instead. Chromium browsers accept Quena's certificates in that profile; Firefox needs the root certificate trusted.",
        write: true,
        destructive: false,
        schema: || obj(json!({ "kind": { "type": "string", "description": "chrome, edge, brave, vivaldi, chromium or firefox; omit to list" }, "url": { "type": "string" } })),
        run: launch_browser,
    },
    Tool {
        name: "open_terminal",
        description: "Open a terminal window on the user's desktop whose tools use Quena: HTTP_PROXY/HTTPS_PROXY and the root certificate (NODE_EXTRA_CA_CERTS, SSL_CERT_FILE, REQUESTS_CA_BUNDLE …). Capturing starts if it is off.",
        write: true,
        destructive: false,
        schema: || obj(json!({})),
        run: open_terminal,
    },
    Tool {
        name: "list_reverse_proxies",
        description: "Reverse proxy entries (a local port that forwards every request to a target, optionally other targets per path prefix, for clients that cannot use a proxy), and the SOCKS and transparent ports. Shows the settings and, while capturing, whether each listens.",
        write: false,
        destructive: false,
        schema: || obj(json!({})),
        run: list_reverse_proxies,
    },
    Tool {
        name: "set_reverse_proxy",
        description: "Add a reverse proxy entry, or change one by `id` (only the fields given). `target`: `http(s)://host[:port][/base path]`; `listen_port`: the local port clients call. Entries listen on this machine only and while capturing; `enabled_all` switches reverse proxying on or off as a whole.",
        write: true,
        destructive: false,
        schema: || {
            obj(json!({
                "id": { "type": "string", "description": "Entry to change (omit to add one)" },
                "name": { "type": "string" },
                "enabled": { "type": "boolean" },
                "listen_port": { "type": "integer" },
                "target": { "type": "string" },
                "client_protocol": { "type": "string", "enum": ["auto", "http", "https"] },
                "preserve_host": { "type": "boolean" },
                "rewrite_location": { "type": "boolean" },
                "rewrite_cookie_domain": { "type": "boolean" },
                "forwarded_headers": { "type": "boolean" },
                "paths": {
                    "type": "array",
                    "description": "Path routes (replace the entry's list): requests whose path starts with `prefix` go to `target`; `strip_prefix` drops the prefix",
                    "items": { "type": "object", "properties": { "prefix": { "type": "string" }, "target": { "type": "string" }, "strip_prefix": { "type": "boolean" } }, "required": ["prefix", "target"] }
                },
                "enabled_all": { "type": "boolean", "description": "Master switch for all entries" }
            }))
        },
        run: set_reverse_proxy,
    },
    Tool {
        name: "set_listeners",
        description: "Switch the SOCKS port (SOCKS5/4 clients name their target) or the port for transparently redirected traffic on or off, or move them to another port. They listen on this machine only and while capturing.",
        write: true,
        destructive: false,
        schema: || {
            obj(json!({
                "socks": { "type": "boolean" },
                "socks_port": { "type": "integer" },
                "transparent": { "type": "boolean" },
                "transparent_port": { "type": "integer" }
            }))
        },
        run: set_listeners,
    },
    Tool {
        name: "remove_reverse_proxy",
        description: "Delete a reverse proxy entry by id.",
        write: true,
        destructive: true,
        schema: || req(json!({ "id": { "type": "string" } }), &["id"]),
        run: remove_reverse_proxy,
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
        description: "Add a rule that changes matching real requests or responses on their way (switches rewriting on). Operations run in order: `jsonSet` {path, value} (creates missing members of a plain path), `jsonRemove` {path}, `jsonAppend` {path, value?}, `jsonAppendAll` {value?} (append to every array in the document; without value a broken copy of the first element: same keys, all null), `regexReplace` {pattern, replacement}, `setHeader` {name, value}, `removeHeader` {name}, `setStatus` {code}, `setQuery` {name, value} / `removeQuery` {name} (requests), `setCookie` {name, value} / `removeCookie` {name, `*` for all} (request Cookie or response Set-Cookie), `mark` {color: red|blue|gold|green|orange|purple}, `comment` {text} (the session). Paths are RFC 9535 JSONPath (`$.items[*].price`, `$..id`). Bodies are decoded (gzip, br …) and sent back uncompressed; bodies over the size limit, event streams and non-text types pass unchanged. Example, a broken element in every list of /api/ responses: {\"match\": \"/api/\", \"ops\": [{\"op\": \"jsonAppendAll\"}]}.",
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
        description: "Switch all rewrite rules on or off, switch groups of rules off (`disabled_groups`, replaces the list), and set the largest body (KiB, default 4096) they change.",
        write: true,
        destructive: false,
        schema: || obj(json!({ "enabled": { "type": "boolean" }, "max_body_kb": { "type": "integer" }, "disabled_groups": { "type": "array", "items": { "type": "string" } } })),
        run: set_rewrite_options,
    },
    Tool {
        name: "apply_rewrite_rules",
        description: "Apply rewrite rules to captured sessions without sending anything: each session a rule changes gets a new copy with the changes (marked tampered, comment \"Rewrite of #id\"); the originals stay. Rules: `rule_ids`, else those of `group`, else all that run.",
        write: true,
        destructive: false,
        schema: || {
            req(
                json!({
                    "ids": { "type": "array", "items": { "type": "integer" } },
                    "rule_ids": { "type": "array", "items": { "type": "integer" } },
                    "group": { "type": "string" }
                }),
                &["ids"],
            )
        },
        run: apply_rewrite_rules,
    },
    Tool {
        name: "run_http_file",
        description: "Send the requests of a .http file (or `collection:NAME`, a Composer collection) through Quena, one after the other (all, or those in `names`: `# @name` / `### title`, or `line:N`), with an environment's variables. Returns per request the session id, status, duration or error; read details with get_session.",
        write: true,
        destructive: false,
        schema: || {
            req(
                json!({
                    "path": { "type": "string" },
                    "env": { "type": "string" },
                    "names": { "type": "array", "items": { "type": "string" } },
                    "wait_ms": { "type": "integer", "description": "Wait per request (default 30000)" }
                }),
                &["path"],
            )
        },
        run: run_http_file,
    },
    Tool {
        name: "sessions_to_http_file",
        description: "Write captured sessions (ids, or those matching `filter`) as a .http file. A shared scheme and host becomes {{host}} in environment `captured` of http-client.env.json; bearer tokens and cookies become {{token}} / {{cookie}} in http-client.private.env.json. `path` is relative to the agents' folder (see `status` filesFolder) or absolute inside it; an existing file is only replaced with `overwrite: true`.",
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
        run: sessions_to_http_file,
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
        description: "Save sessions (all, the given ids, or those matching `filter`) as .har or .saz. `path` is relative to the agents' folder (see `status` filesFolder) or absolute inside it; an existing file is only replaced with `overwrite: true`.",
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
        "phase": { "type": "string", "enum": ["request", "response", "webSocket"], "description": "default response; webSocket changes text messages of matching WebSockets (JSON also inside Socket.IO packets)" },
        "direction": { "type": "string", "enum": ["both", "up", "down"], "description": "webSocket phase: client→server (up), server→client (down) or both (default)" },
        "status": { "type": "string", "description": "Response status filter: `200`, `2xx`, `500-599`, comma separated (empty: any)" },
        "content_type": { "type": "string", "description": "Content type substrings, `;` separated (empty: any text type)" },
        "comment": { "type": "string" },
        "group": { "type": "string", "description": "Named group, switched on and off together (set_rewrite_options disabled_groups)" },
        "ops": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "op": { "type": "string", "enum": ["jsonSet", "jsonRemove", "jsonAppend", "jsonAppendAll", "regexReplace", "setHeader", "removeHeader", "setStatus", "setQuery", "removeQuery", "setCookie", "removeCookie", "mark", "comment"] },
                    "path": { "type": "string" },
                    "value": {},
                    "pattern": { "type": "string" },
                    "replacement": { "type": "string" },
                    "name": { "type": "string" },
                    "code": { "type": "integer" },
                    "color": { "type": "string", "enum": ["red", "blue", "gold", "green", "orange", "purple"] },
                    "text": { "type": "string" }
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
/// `tools/list`: all tools. Changing ones say so while the user has not granted full
/// control: the list cannot be pushed to clients again (no event stream), so a later grant
/// works without reconnecting, and the agent can tell the user what to switch on.
pub fn list(access: McpAccess) -> Vec<Value> {
    TOOLS
        .iter()
        .map(|t| {
            let description = if t.write && access != McpAccess::Full {
                format!("[Needs full control: Quena → Options → AI agents (MCP). Not granted now.] {}", t.description)
            } else {
                t.description.to_string()
            };
            json!({
                "name": t.name,
                "description": description,
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

/// What leaves Quena. Unless the user allowed secrets, credentials, tokens, cookies and
/// secret parameters and fields are replaced (the sanitizer's `credentials` preset) in
/// URLs, headers and bodies before an agent (and its model provider) sees them.
struct View {
    red: Option<Sanitizer>,
}

impl View {
    /// `window`: how many leading bytes of a body the caller looks at.
    fn new(core: &AppCore, window: usize) -> View {
        if core.settings().mcp.include_secrets {
            return View { red: None };
        }
        let mut o = SanitizeOptions::preset("credentials").unwrap_or_default();
        o.bodies = BodyMode::Truncate;
        o.truncate_kib = u32::try_from((window >> 10) + 2).unwrap_or(u32::MAX);
        View { red: Some(Sanitizer::new(o)) }
    }

    fn redacts(&self) -> bool {
        self.red.is_some()
    }

    fn url(&mut self, url: &str) -> String {
        match &mut self.red {
            Some(r) => r.scrub_url(url),
            None => url.to_string(),
        }
    }

    /// Free text (a finding, a fact): URLs in it (any case, also `ws(s)://`) and paths with a
    /// query (`/cb?code=…`) redacted like [`View::url`].
    fn text(&mut self, s: &str) -> String {
        if self.red.is_none() || !(s.contains("://") || s.contains('?')) {
            return s.to_string();
        }
        let ends = |c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | ')' | ']' | '`' | ',');
        let mut out = String::with_capacity(s.len());
        let mut rest = s;
        loop {
            let lower = rest.to_ascii_lowercase();
            let url = ["http://", "https://", "ws://", "wss://"].iter().filter_map(|p| lower.find(p)).min();
            // A path with a query: starts after a space or the start, with `/`.
            let path = rest.char_indices().find(|&(i, c)| c == '/' && (i == 0 || rest[..i].ends_with(char::is_whitespace)) && rest[i..].split(ends).next().is_some_and(|t| t.contains('?'))).map(|(i, _)| i);
            let Some(i) = url.into_iter().chain(path).min() else { break };
            out.push_str(&rest[..i]);
            let end = rest[i..].find(ends).map_or(rest.len(), |e| i + e);
            let token = &rest[i..end];
            if token.starts_with('/') {
                let scrubbed = self.url(&format!("http://h{token}"));
                out.push_str(scrubbed.strip_prefix("http://h").unwrap_or(&scrubbed));
            } else {
                out.push_str(&self.url(token));
            }
            rest = &rest[end..];
        }
        out.push_str(rest);
        out
    }

    /// A difference of a comparison: a redirect target (`header location: A → B`) can carry
    /// a code or token.
    fn change(&mut self, c: &str) -> String {
        match c.strip_prefix("header location: ").and_then(|r| r.split_once(" → ")) {
            Some((a, b)) if self.red.is_some() => format!("header location: {} → {}", self.url(a), self.url(b)),
            _ => c.to_string(),
        }
    }

    fn row(&mut self, s: &SessionSummary) -> Value {
        let mut v = json!({
            "id": s.id,
            "method": s.method,
            "url": self.url(&s.full_url()),
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
        // What ties sessions together (filter with `conn == …`, `trace == …`).
        if s.conn != 0 {
            v["conn"] = json!(s.conn);
        }
        if !s.trace.is_empty() {
            v["trace"] = json!(s.trace);
        }
        if !s.via.is_empty() {
            v["via"] = json!(s.via);
        }
        if !s.llm.is_empty() {
            v["llm"] = json!(s.llm);
            v["tokens"] = json!(s.llm_tokens);
        }
        v
    }

    /// The session as it may be shown, with the first `window` (+1) bytes of each body
    /// without Content-Encoding (`decoded`), or raw when secrets may be shown.
    fn session(&mut self, core: &AppCore, id: SessionId, window: usize, decoded: bool) -> Result<Shown> {
        let cap = core.capture();
        let d = cap.detail(id).ok_or_else(|| anyhow!("session #{id} not found"))?;
        let (req, resp) = cap.bodies_of(id).ok_or_else(|| anyhow!("session #{id} not found"))?;
        let stored = (req.len(), resp.len());
        let complete = (req.is_complete() && !req.is_truncated(), resp.is_complete() && !resp.is_truncated());
        let want = window.saturating_add(1);
        if let Some(r) = &mut self.red {
            let s = r.session(&d, &req, &resp);
            return Ok(Shown { detail: s.detail, req: s.request, resp: s.response, stored, complete, decoded: true });
        }
        let read = |b: &Body, h: &Headers| {
            if decoded {
                quena_body::text::decoded_prefix(b, &spec_of(h), want)
            } else {
                b.read_range(0, want).unwrap_or_default()
            }
        };
        let empty = Headers::default();
        let req_bytes = read(&req, &d.request.headers);
        let resp_bytes = read(&resp, d.response.as_ref().map(|r| &r.headers).unwrap_or(&empty));
        Ok(Shown { detail: d, req: req_bytes, resp: resp_bytes, stored, complete, decoded })
    }
}

/// A session prepared by [`View::session`].
struct Shown {
    detail: SessionDetail,
    req: Vec<u8>,
    resp: Vec<u8>,
    stored: (u64, u64),
    complete: (bool, bool),
    decoded: bool,
}

/// Ids of all sessions (hidden ones too) matching an optional expression, ascending.
fn matching_ids(core: &AppCore, filter: Option<&str>, since: SessionId) -> Result<Vec<SessionId>> {
    let cap = core.capture();
    let mut ids = match filter.map(str::trim).filter(|f| !f.is_empty()) {
        Some(f) => {
            let e = quena_query::expr::parse(f).map_err(|e| anyhow!("filter: {e}"))?;
            quena_app_core::details::matching(&cap, &e, false, |s| s.id > since)
        }
        None => cap.index.find_all(|s| s.id > since),
    };
    ids.sort_unstable();
    Ok(ids)
}

fn headers_json(h: &Headers) -> Value {
    Value::Array(h.0.iter().map(|(n, v)| json!([n, v])).collect())
}

/// `max` bytes from `offset` of a body's leading `bytes` as text (or a description of a
/// binary body).
fn piece(bytes: &[u8], headers: &Headers, offset: usize, max: usize, stored: u64, complete: bool, decoded: bool) -> Value {
    let ct = headers.get("content-type");
    let encoded = !decoded && headers.get("content-encoding").is_some_and(|c| !c.trim().is_empty() && !c.eq_ignore_ascii_case("identity"));
    let start = offset.min(bytes.len());
    let stop = start.saturating_add(max).min(bytes.len());
    let mut v = json!({ "storedLength": stored, "offset": start, "more": bytes.len() > stop });
    if let Some(c) = ct {
        v["contentType"] = json!(c);
    }
    if let Some(e) = headers.get("content-encoding") {
        v["contentEncoding"] = json!(e);
    }
    if !complete {
        v["complete"] = json!(false);
    }
    if stored == 0 {
        v["text"] = json!("");
        return v;
    }
    let sample = &bytes[..bytes.len().min(1024)];
    let textual = !encoded
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
    let mut view = View::new(core, max);
    let s = view.session(core, id, if bodies { max } else { 0 }, true)?;
    let d = &s.detail;
    let mut v = json!({
        "session": view.row(&d.summary),
        "request": { "method": d.request.method, "url": d.request.url, "version": d.request.version, "headers": headers_json(&d.request.headers) },
        "timers": d.timers,
        "connection": d.connection,
    });
    if view.redacts() {
        v["redacted"] = json!("credentials, tokens and secret values are replaced (Quena → Options → AI agents)");
    }
    if let Some(r) = &d.response {
        v["response"] = json!({ "status": r.status, "reason": r.reason, "version": r.version, "headers": headers_json(&r.headers) });
    }
    if let Some(e) = &d.error {
        v["error"] = json!(e);
    }
    if !d.extra_flags.is_empty() {
        v["notes"] = json!(d.extra_flags.iter().filter(|(k, _)| k.starts_with("x-quena")).map(|(k, v)| json!({ k: v })).collect::<Vec<_>>());
    }
    if bodies {
        v["request"]["body"] = piece(&s.req, &d.request.headers, 0, max, s.stored.0, s.complete.0, s.decoded);
        if let Some(r) = &d.response {
            v["response"]["body"] = piece(&s.resp, &r.headers, 0, max, s.stored.1, s.complete.1, s.decoded);
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

/// The folder agents may use, created when missing.
fn files_root(core: &AppCore) -> Result<PathBuf> {
    let dir = core.settings().mcp.files_folder(&core.paths.data);
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    Ok(dir.canonicalize()?)
}

/// A path inside the agents' folder: relative paths are taken from it, absolute ones must
/// lie in it (links resolved). The file itself need not exist yet; its folder must.
fn inside(core: &AppCore, path: &str) -> Result<PathBuf> {
    let root = files_root(core)?;
    let p = PathBuf::from(path.trim());
    let p = if p.is_absolute() { p } else { root.join(p) };
    let resolved = match p.canonicalize() {
        Ok(c) => c,
        Err(_) => {
            let name = p.file_name().ok_or_else(|| anyhow!("{} names no file", p.display()))?;
            let parent = p.parent().unwrap_or(&root);
            parent.canonicalize().with_context(|| format!("folder {} does not exist", parent.display()))?.join(name)
        }
    };
    if !resolved.starts_with(&root) {
        bail!("{} is outside the folder agents may use ({}); the user can change it in Quena → Options → AI agents", resolved.display(), root.display());
    }
    Ok(resolved)
}

/// Mock rule actions from agents may serve files only from their folder.
fn check_action(core: &AppCore, action: &str) -> Result<()> {
    if let Some(p) = quena_app_core::rules::action_path(action) {
        if p.contains('$') {
            bail!("file actions from agents cannot use $1 substitutions");
        }
        inside(core, &p)?;
    }
    Ok(())
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
        "rewriteRulesActive": st.engine.rewrite,
        "listeners": st.engine.listeners,
        "access": s.mcp.access,
        "secretsRedacted": !s.mcp.include_secrets,
        "filesFolder": files_root(core).map(|p| p.display().to_string()).unwrap_or_default(),
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
    let mut view = View::new(core, 0);
    let rows: Vec<Value> = ids.iter().skip(a.offset.unwrap_or(0)).take(page(a.limit)).filter_map(|id| cap.index.get(*id)).map(|s| view.row(&s)).collect();
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

#[derive(Deserialize)]
struct DiffArgs {
    a: Option<String>,
    b: Option<String>,
    #[serde(default)]
    all: bool,
    #[serde(default)]
    ignore_host: bool,
    #[serde(default)]
    pair_by: Option<quena_app_core::capdiff::PairBy>,
    #[serde(default)]
    ignore_headers: Vec<String>,
}

fn compare_captures(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    use quena_app_core::capdiff::{CompareOptions, DiffKind, Source};
    let a: DiffArgs = args(a)?;
    let sources = core.compare_sources();
    let (Some(x), Some(y)) = (&a.a, &a.b) else {
        return Ok(json!({ "sides": sources.iter().map(|s| json!({ "name": s.label, "sessions": s.sessions })).collect::<Vec<_>>() }));
    };
    let side = |n: &str| if n.eq_ignore_ascii_case("live") { Source::Live } else { Source::Archive(n.to_string()) };
    let d = core.compare_captures_with(&side(x), &side(y), &CompareOptions { ignore_host: a.ignore_host, pair_by: a.pair_by.unwrap_or_default(), ignore_headers: a.ignore_headers.clone() })?;
    let mut view = View::new(core, 0);
    let entries: Vec<Value> = d
        .entries
        .iter()
        .filter(|e| a.all || e.kind != DiffKind::Same)
        .take(500)
        .map(|e| {
            json!({
                "kind": e.kind, "method": e.method,
                "urlA": e.url_a.as_deref().map(|u| view.url(u)), "urlB": e.url_b.as_deref().map(|u| view.url(u)),
                "idA": e.id_a, "idB": e.id_b, "statusA": e.status_a, "statusB": e.status_b,
                "msA": e.ms_a, "msB": e.ms_b, "changes": e.changes.iter().map(|c| view.change(c)).collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(json!({ "counts": d.counts, "sessionsA": d.sessions_a, "sessionsB": d.sessions_b, "entries": entries }))
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct DiagArgs {
    filter: Option<String>,
    ids: Option<Vec<SessionId>>,
    hosts: Vec<String>,
    processes: Vec<String>,
    profile: Option<String>,
    wait_s: Option<u64>,
    all: bool,
}

/// The analyzer (the first one) and its description (`options`, `profiles`).
fn analyzer(core: &AppCore) -> Result<(u16, Value)> {
    let a = core.diag_analyzers().into_iter().next().ok_or_else(|| anyhow!("no diagnostics analyzer is installed"))?;
    let desc: Value = serde_json::from_str(&core.diag_describe(a.index, "en")?).unwrap_or(Value::Null);
    Ok((a.index, desc))
}

fn profiles(desc: &Value) -> Value {
    Value::Array(desc.get("profiles").and_then(|p| p.as_array()).map(|a| a.iter().map(|p| json!({ "id": p.get("id"), "name": p.get("name") })).collect()).unwrap_or_default())
}

fn run_diagnostics(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: DiagArgs = args(a)?;
    let (index, desc) = analyzer(core)?;
    let mut options = desc.get("options").cloned().filter(|o| o.is_object()).unwrap_or_else(|| json!({}));
    options["lang"] = json!("en");
    if let Some(p) = &a.profile {
        if !desc.get("profiles").and_then(|x| x.as_array()).is_some_and(|ps| ps.iter().any(|x| x.get("id").and_then(|i| i.as_str()) == Some(p))) {
            bail!("unknown profile {p:?}; profiles: {}", profiles(&desc));
        }
        options["profile"] = json!(p);
    }
    let ids = match a.ids {
        Some(ids) => ids,
        None => matching_ids(core, a.filter.as_deref(), 0)?,
    };
    if ids.is_empty() {
        bail!("no sessions to analyse");
    }
    let filter = quena_app_core::diagnostics::DiagFilter { hosts: a.hosts, processes: a.processes };
    let job = core.diag_run(index, options.to_string(), Some(ids), filter)?;
    let wait = Duration::from_secs(a.wait_s.unwrap_or(120).clamp(5, 600));
    let info = core.jobs.wait(job, wait).map_err(|_| anyhow!("diagnostics did not finish within {} s (it goes on in Quena; read it later with get_diagnostics_report)", wait.as_secs()))?;
    if let Some(e) = info.error.filter(|e| !e.is_empty()) {
        bail!("diagnostics failed: {e}");
    }
    // Cancelled: another analysis (the user's, or another agent's) replaced this one, and the
    // report there is not this run's.
    if info.status != quena_jobs::JobStatus::Done {
        bail!("diagnostics did not finish ({:?}): another analysis was started meanwhile; try again", info.status);
    }
    report_json(core, a.all)
}

fn get_diagnostics_report(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: DiagArgs = args(a)?;
    match core.diag_report() {
        Some(_) => report_json(core, a.all),
        None => {
            let profiles = analyzer(core).map(|(_, d)| profiles(&d)).unwrap_or(Value::Null);
            Ok(json!({ "report": null, "hint": "no report yet: call run_diagnostics", "profiles": profiles }))
        }
    }
}

/// The last report, findings first (info findings only with `all`), redacted like sessions.
fn report_json(core: &Arc<AppCore>, all: bool) -> Result<Value> {
    let text = core.diag_report().ok_or_else(|| anyhow!("no diagnostics report"))?;
    let (_, r) = quena_report::parse(&text).map_err(|e| anyhow!("report: {e}"))?;
    let mut view = View::new(core, 0);
    let mut t = |s: &str| view.text(s);
    let findings: Vec<Value> = r
        .findings
        .iter()
        .filter(|f| all || f.severity != quena_report::Severity::Info)
        .take(100)
        .map(|f| {
            json!({
                "title": t(&f.title), "severity": f.severity, "confidence": f.confidence, "categories": f.categories,
                "observation": t(&f.observation), "impact": t(&f.impact),
                "hypotheses": f.hypotheses.iter().map(|x| t(x)).collect::<Vec<_>>(),
                "recommendations": f.recommendations.iter().map(|x| t(x)).collect::<Vec<_>>(),
                "nextSteps": f.next_steps.iter().map(|x| t(x)).collect::<Vec<_>>(),
                "facts": f.facts.iter().map(|x| json!({ "label": t(&x.label), "value": t(&x.value) })).collect::<Vec<_>>(),
                "sessions": f.sessions.iter().take(50).map(|x| *x as u64).collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(json!({
        "profile": r.profile.name,
        "sessions": r.range.sessions as u64,
        "summary": { "critical": r.summary.critical, "warning": r.summary.warning, "info": r.summary.info, "headline": r.summary.headline.iter().map(|x| t(x)).collect::<Vec<_>>() },
        "findings": findings,
    }))
}

fn llm_cache_status(core: &Arc<AppCore>, _: Value) -> Result<Value> {
    let st = core.llm_cache_status()?;
    let mut view = View::new(core, 0);
    let entries: Vec<Value> = st
        .entries
        .iter()
        .take(200)
        .map(|e| json!({ "key": e.key, "url": view.url(&e.url), "model": e.model, "hits": e.hits, "tokens": e.tokens, "costUsd": e.cost_usd, "durationMs": e.duration_ms, "source": e.source }))
        .collect();
    let advice: Vec<Value> = core.llm_cache_advice().iter().map(|a| json!({ "model": a.model, "url": view.url(&a.url), "sessions": a.sessions, "repeatTokens": a.repeat_tokens, "repeatUsd": a.repeat_usd })).collect();
    Ok(json!({ "auto": st.auto, "hits": st.hits, "savedTokens": st.saved_tokens, "savedUsd": st.saved_usd, "savedMs": st.saved_ms, "entries": entries, "worthCaching": advice }))
}

#[derive(Deserialize)]
struct CacheArgs {
    #[serde(default)]
    ids: Vec<SessionId>,
    #[serde(default = "yes")]
    on: bool,
    auto: Option<bool>,
}

fn yes() -> bool {
    true
}

fn cache_llm_calls(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: CacheArgs = args(a)?;
    if let Some(auto) = a.auto {
        core.llm_cache_set_auto(auto)?;
    }
    let mut done = Vec::new();
    let mut failed = Vec::new();
    for id in a.ids.iter().take(500) {
        match core.llm_cache_set(*id, a.on) {
            Ok(()) => done.push(*id),
            Err(e) => failed.push(json!({ "id": id, "error": format!("{e:#}") })),
        }
    }
    llm_cache_status(core, Value::Null).map(|mut v| {
        v["changed"] = json!(done);
        v["failed"] = json!(failed);
        v
    })
}

fn get_llm_call(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: IdArgs = args(a)?;
    const WINDOW: usize = 16 << 20;
    // The bodies as an agent may see them (secrets replaced unless allowed).
    let s = View::new(core, WINDOW).session(core, a.id, WINDOW, true)?;
    let d = &s.detail;
    let ct = d.response.as_ref().and_then(|r| r.headers.get("content-type")).unwrap_or("").to_ascii_lowercase();
    let call = quena_app_core::llm::parse(&d.request.method, &d.request.url, &s.req, d.response.as_ref().map(|_| (s.resp.as_slice(), ct.as_str())), &core.llm_prices())
        .ok_or_else(|| anyhow!("session #{} is not a call to an LLM API", a.id))?;
    Ok(serde_json::to_value(call)?)
}

fn get_body(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: BodyArgs = args(a)?;
    let offset = a.offset.unwrap_or(0);
    if offset > MAX_OFFSET {
        bail!("offset beyond {} MiB: export the session (export_archive) to read further", MAX_OFFSET >> 20);
    }
    let len = body_limit(a.length);
    let mut view = View::new(core, offset as usize + len);
    let s = view.session(core, a.id, offset as usize + len, a.decoded.unwrap_or(true))?;
    let empty = Headers::default();
    let mut v = match a.part.as_str() {
        "request" => piece(&s.req, &s.detail.request.headers, offset as usize, len, s.stored.0, s.complete.0, s.decoded),
        "response" => piece(&s.resp, s.detail.response.as_ref().map(|r| &r.headers).unwrap_or(&empty), offset as usize, len, s.stored.1, s.complete.1, s.decoded),
        p => bail!("part must be request or response, not {p}"),
    };
    if view.redacts() && a.decoded == Some(false) {
        v["note"] = json!("raw bytes are not available while secrets are redacted; this is the decoded body");
    }
    Ok(v)
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
    // Its own search: the user's Find Sessions keeps running.
    let job = core.find_sessions_for(opts, "mcp")?;
    let done = core.jobs.wait(job, Duration::from_secs(60));
    if done.is_err() {
        core.cancel_job(job);
    }
    let r = core.take_find_result(job).ok_or_else(|| anyhow!("search result gone"))?;
    let cap = core.capture();
    let mut view = View::new(core, 0);
    let rows: Vec<Value> = r.ids.iter().take(page(a.limit)).filter_map(|id| cap.index.get(*id)).map(|s| view.row(&s)).collect();
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
    direction: Option<quena_app_core::rewrite::WsDirection>,
    status: Option<String>,
    #[serde(alias = "contentType")]
    content_type: Option<String>,
    comment: Option<String>,
    group: Option<String>,
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
        if let Some(v) = self.direction {
            r.direction = v;
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
        if let Some(v) = self.group {
            r.group = v;
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
    const LIMIT: usize = 8 << 20;
    let part = a.part.unwrap_or_else(|| if rule.phase == Phase::Request { "request".into() } else { "response".into() });
    let s = View::new(core, LIMIT).session(core, a.id, LIMIT, true)?;
    let (bytes, headers) = match part.as_str() {
        "request" => (s.req, s.detail.request.headers.clone()),
        "response" => (s.resp, s.detail.response.as_ref().map(|r| r.headers.clone()).unwrap_or_default()),
        p => bail!("part must be request or response, not {p}"),
    };
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

/// `.http` files from agents: body files only from their folder, no process environment.
fn http_access(root: &std::path::Path) -> Access<'_> {
    Access { process_env: false, root: Some(root) }
}

#[derive(Deserialize)]
struct HttpListArgs {
    path: String,
    env: Option<String>,
}

/// The `.http` file named by `path` and the folder its body files must be in: a Composer
/// collection (`collection:NAME`) or a file in the agents' folder.
fn http_source(core: &AppCore, path: &str) -> Result<(PathBuf, PathBuf)> {
    match path.trim().strip_prefix("collection:") {
        Some(name) => {
            let file = core.collection_path(name)?;
            if !file.is_file() {
                bail!("there is no collection {name:?}");
            }
            Ok((file, core.collections_dir()))
        }
        None => Ok((inside(core, path)?, files_root(core)?)),
    }
}

fn list_collections(core: &Arc<AppCore>, _: Value) -> Result<Value> {
    let l = core.collections_list()?;
    Ok(json!({ "collections": l.iter().map(|c| json!({ "name": c.name, "requests": c.requests })).collect::<Vec<_>>() }))
}

fn list_http_requests(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: HttpListArgs = args(a)?;
    let (file, root) = http_source(core, &a.path)?;
    let mut l = core.http_requests(&file, a.env.as_deref(), &http_access(&root))?;
    let mut view = View::new(core, 0);
    for r in &mut l.requests {
        r.url = view.url(&r.url);
    }
    Ok(serde_json::to_value(l)?)
}

#[derive(Deserialize)]
struct HttpRunArgs {
    path: String,
    env: Option<String>,
    #[serde(default)]
    names: Vec<String>,
    wait_ms: Option<u64>,
}

fn run_http_file(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: HttpRunArgs = args(a)?;
    let wait = Duration::from_millis(a.wait_ms.unwrap_or(30_000).min(300_000));
    let (file, root) = http_source(core, &a.path)?;
    let mut results = core.run_http_file(&file, a.env.as_deref(), &a.names, wait, &http_access(&root))?;
    let mut view = View::new(core, 0);
    for r in &mut results {
        r.url = view.url(&r.url);
    }
    Ok(json!({ "results": results }))
}

fn sessions_to_http_file(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: ExportArgs = args(a)?;
    let path = inside(core, &a.path)?;
    let ids = match a.ids {
        Some(ids) if !ids.is_empty() => ids,
        _ => matching_ids(core, a.filter.as_deref(), 0)?,
    };
    let redact = !core.settings().mcp.include_secrets;
    Ok(serde_json::to_value(core.sessions_to_http(&ids, &path, a.overwrite, redact)?)?)
}

fn get_breakpoints(core: &Arc<AppCore>, _: Value) -> Result<Value> {
    let r = rules(core)?;
    let mut view = View::new(core, 0);
    let paused: Vec<Value> = r.paused().into_iter().map(|p| json!({ "id": p.id, "phase": p.phase, "url": view.url(&p.url), "since": p.since })).collect();
    Ok(json!({ "breakpoints": r.breakpoints(), "paused": paused }))
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
    #[serde(default)]
    follow_redirects: bool,
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
        follow_redirects: a.follow_redirects,
    })?;
    let wait = Duration::from_millis(a.wait_ms.unwrap_or(30_000).min(300_000));
    let finished = core.wait_session(id, wait);
    let mut v = session_json(core, id, true, body_limit(a.max_body_bytes))?;
    if !finished {
        v["pending"] = json!(true);
    }
    Ok(v)
}

#[derive(Deserialize)]
struct ReplayArgs {
    ids: Vec<SessionId>,
    count: Option<u32>,
    #[serde(default)]
    unconditional: bool,
    #[serde(default)]
    sequential: bool,
    parallel: Option<u32>,
}

fn replay_sessions(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: ReplayArgs = args(a)?;
    let since = core.capture().index.find_all(|_| true).into_iter().max().unwrap_or(0);
    let n = core.replay(a.ids, ReplayOptions { unconditional: a.unconditional, count: a.count.unwrap_or(1).clamp(1, 1000), breakpoint: false, sequential: a.sequential, parallel: a.parallel.unwrap_or(0) })?;
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
    check_action(core, &a.action)?;
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
    if let Some(action) = &a.action {
        check_action(core, action)?;
    }
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

fn remap_json(core: &AppCore) -> Value {
    let s = core.settings().host_remap;
    json!({
        "enabled": s.enabled,
        "entries": s.entries.iter().map(|e| json!({ "id": e.id, "enabled": e.enabled, "host": e.host, "target": e.target, "keepHost": e.keep_host, "comment": e.comment })).collect::<Vec<_>>(),
    })
}

fn list_host_remaps(core: &Arc<AppCore>, _: Value) -> Result<Value> {
    Ok(remap_json(core))
}

#[derive(Deserialize)]
struct RemapArgs {
    id: Option<String>,
    host: Option<String>,
    target: Option<String>,
    keep_host: Option<bool>,
    protocol: Option<String>,
    enabled: Option<bool>,
    comment: Option<String>,
    enabled_all: Option<bool>,
}

fn set_host_remap(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: RemapArgs = args(a)?;
    let mut s = core.settings();
    let rm = &mut s.host_remap;
    if let Some(v) = a.enabled_all {
        rm.enabled = v;
    }
    if a.id.is_some() || a.host.is_some() || a.target.is_some() {
        let i = match &a.id {
            Some(id) => rm.entries.iter().position(|e| &e.id == id).ok_or_else(|| anyhow!("no host remapping entry {id}"))?,
            None => {
                let (Some(_), Some(_)) = (&a.host, &a.target) else { bail!("a new entry needs `host` and `target`") };
                rm.entries.push(quena_app_core::settings::HostRemapEntry { id: format!("mcp-{}", quena_model::now_us()), ..Default::default() });
                if a.enabled_all.is_none() {
                    rm.enabled = true;
                }
                rm.entries.len() - 1
            }
        };
        let e = &mut rm.entries[i];
        if let Some(v) = a.host {
            e.host = v;
        }
        if let Some(v) = a.target {
            e.target = v;
        }
        if let Some(v) = a.protocol {
            e.protocol = v;
        }
        if let Some(v) = a.keep_host {
            e.keep_host = v;
        }
        if let Some(v) = a.enabled {
            e.enabled = v;
        }
        if let Some(v) = a.comment {
            e.comment = v;
        }
    }
    core.update_settings(s)?;
    Ok(remap_json(core))
}

fn remove_host_remap(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: ReverseIdArgs = args(a)?;
    let mut s = core.settings();
    let before = s.host_remap.entries.len();
    s.host_remap.entries.retain(|e| e.id != a.id);
    if s.host_remap.entries.len() == before {
        bail!("no host remapping entry {}", a.id);
    }
    core.update_settings(s)?;
    Ok(remap_json(core))
}

#[derive(Deserialize)]
struct LaunchArgs {
    kind: Option<String>,
    url: Option<String>,
}

fn launch_browser(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: LaunchArgs = args(a)?;
    let Some(kind) = a.kind else {
        return Ok(json!({ "browsers": core.browsers().iter().map(|b| json!({ "kind": b.kind, "name": b.name })).collect::<Vec<_>>() }));
    };
    let b = core.launch_browser(&kind, a.url.as_deref())?;
    Ok(json!({ "started": b.name }))
}

fn open_terminal(core: &Arc<AppCore>, _: Value) -> Result<Value> {
    core.open_terminal()?;
    Ok(json!({ "opened": true }))
}

fn reverse_json(core: &AppCore) -> Value {
    let s = core.settings().reverse_proxy;
    let status = core.status().engine.listeners;
    let entries: Vec<Value> = s
        .entries
        .iter()
        .map(|e| {
            let st = status.iter().find(|r| r.id == e.id);
            json!({
                "id": e.id, "name": e.name, "enabled": e.enabled, "listenPort": e.listen_port, "target": e.target,
                "clientProtocol": e.client_protocol, "preserveHost": e.preserve_host, "allowRemote": e.allow_remote,
                "rewriteLocation": e.rewrite_location, "rewriteCookieDomain": e.rewrite_cookie_domain, "forwardedHeaders": e.forwarded_headers,
                "paths": e.paths.iter().map(|p| json!({ "prefix": p.prefix, "target": p.target, "stripPrefix": p.strip_prefix })).collect::<Vec<_>>(),
                "listen": st.map(|r| r.listen.clone()).unwrap_or_default(), "error": st.and_then(|r| r.error.clone()),
            })
        })
        .collect();
    let all = core.settings();
    let port = |l: &quena_app_core::settings::ListenerSettings| json!({ "enabled": l.enabled, "port": l.port, "allowRemote": l.allow_remote });
    json!({ "enabled": s.enabled, "entries": entries, "socks": port(&all.socks), "transparent": port(&all.transparent) })
}

fn list_reverse_proxies(core: &Arc<AppCore>, _: Value) -> Result<Value> {
    Ok(reverse_json(core))
}

#[derive(Deserialize)]
struct ReverseArgs {
    id: Option<String>,
    name: Option<String>,
    enabled: Option<bool>,
    listen_port: Option<u16>,
    target: Option<String>,
    client_protocol: Option<quena_app_core::settings::ClientProtocol>,
    preserve_host: Option<bool>,
    rewrite_location: Option<bool>,
    rewrite_cookie_domain: Option<bool>,
    forwarded_headers: Option<bool>,
    paths: Option<Vec<PathArg>>,
    enabled_all: Option<bool>,
}

#[derive(Deserialize)]
struct PathArg {
    prefix: String,
    target: String,
    #[serde(default)]
    strip_prefix: bool,
}

fn set_reverse_proxy(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: ReverseArgs = args(a)?;
    let mut s = core.settings();
    let rp = &mut s.reverse_proxy;
    if let Some(v) = a.enabled_all {
        rp.enabled = v;
    }
    let touches_entry = a.id.is_some() || a.target.is_some() || a.listen_port.is_some() || a.paths.is_some();
    if touches_entry {
        let i = match &a.id {
            Some(id) => rp.entries.iter().position(|e| &e.id == id).ok_or_else(|| anyhow!("no reverse proxy entry {id}"))?,
            None => {
                let (Some(_), Some(_)) = (&a.target, a.listen_port) else { bail!("a new entry needs `target` and `listen_port`") };
                let id = format!("mcp-{}", quena_model::now_us());
                rp.entries.push(quena_app_core::settings::ReverseProxyEntry { id, ..Default::default() });
                // Adding an entry means using it.
                if a.enabled_all.is_none() {
                    rp.enabled = true;
                }
                rp.entries.len() - 1
            }
        };
        let e = &mut rp.entries[i];
        if let Some(v) = a.name {
            e.name = v;
        }
        if let Some(v) = a.enabled {
            e.enabled = v;
        }
        if let Some(v) = a.listen_port {
            e.listen_port = v;
        }
        if let Some(v) = a.target {
            e.target = v;
        }
        if let Some(v) = a.client_protocol {
            e.client_protocol = v;
        }
        if let Some(v) = a.preserve_host {
            e.preserve_host = v;
        }
        if let Some(v) = a.rewrite_location {
            e.rewrite_location = v;
        }
        if let Some(v) = a.rewrite_cookie_domain {
            e.rewrite_cookie_domain = v;
        }
        if let Some(v) = a.forwarded_headers {
            e.forwarded_headers = v;
        }
        if let Some(v) = a.paths {
            e.paths = v.into_iter().map(|p| quena_app_core::settings::ReversePathEntry { prefix: p.prefix, target: p.target, strip_prefix: p.strip_prefix }).collect();
        }
    }
    core.update_settings(s)?;
    Ok(reverse_json(core))
}

#[derive(Deserialize)]
struct ListenerArgs {
    socks: Option<bool>,
    socks_port: Option<u16>,
    transparent: Option<bool>,
    transparent_port: Option<u16>,
}

fn set_listeners(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: ListenerArgs = args(a)?;
    let mut s = core.settings();
    if let Some(v) = a.socks {
        s.socks.enabled = v;
    }
    if let Some(v) = a.socks_port {
        s.socks.port = v;
    }
    if let Some(v) = a.transparent {
        s.transparent.enabled = v;
    }
    if let Some(v) = a.transparent_port {
        s.transparent.port = v;
    }
    core.update_settings(s)?;
    Ok(reverse_json(core))
}

#[derive(Deserialize)]
struct ReverseIdArgs {
    id: String,
}

fn remove_reverse_proxy(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: ReverseIdArgs = args(a)?;
    let mut s = core.settings();
    let before = s.reverse_proxy.entries.len();
    s.reverse_proxy.entries.retain(|e| e.id != a.id);
    if s.reverse_proxy.entries.len() == before {
        bail!("no reverse proxy entry {}", a.id);
    }
    core.update_settings(s)?;
    Ok(reverse_json(core))
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
    disabled_groups: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct ApplyRewriteArgs {
    ids: Vec<SessionId>,
    rule_ids: Option<Vec<u64>>,
    group: Option<String>,
}

fn apply_rewrite_rules(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: ApplyRewriteArgs = args(a)?;
    let out = core.rewrite_apply(&a.ids, a.rule_ids.as_deref(), a.group.as_deref())?;
    Ok(json!({ "created": out.created, "unchanged": out.unchanged }))
}

fn set_rewrite_options(core: &Arc<AppCore>, a: Value) -> Result<Value> {
    let a: RewriteOptionArgs = args(a)?;
    let rw = &rules(core)?.rewrite;
    rw.update(|s| {
        if let Some(v) = a.enabled {
            s.enabled = v;
        }
        if let Some(v) = a.max_body_kb {
            s.max_body_kb = v.clamp(1, quena_app_core::rewrite::MAX_BODY_KB);
        }
        if let Some(v) = a.disabled_groups {
            s.disabled_groups = v;
        }
    })?;
    let s = rw.state();
    Ok(json!({ "enabled": s.enabled, "maxBodyKb": s.max_body_kb, "disabledGroups": s.disabled_groups }))
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
    let path = inside(core, &a.path)?;
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
    // The agent can read the file with its own tools: it gets the same redaction.
    let redact = !core.settings().mcp.include_secrets;
    let job = if redact {
        core.export_sanitized_quietly(ids, path.clone(), SanitizeOptions::preset("credentials").unwrap_or_default())?
    } else {
        core.export_archive(ids, path.clone(), None)?
    };
    let info = core.jobs.wait(job, Duration::from_secs(600)).map_err(|e| anyhow!("export {e}"))?;
    if let Some(e) = info.error {
        bail!("export failed: {e}");
    }
    Ok(json!({ "path": path.display().to_string(), "sessions": n, "secretsRedacted": redact }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_text_is_redacted() {
        let mut v = View { red: Some(Sanitizer::new(SanitizeOptions::preset("credentials").unwrap_or_default())) };
        let t = v.text("see HTTPS://a.example/cb?code=SECRET1 and /reset?token=SECRET2, wss://w.example/s?access_token=SECRET3");
        assert!(!t.contains("SECRET1") && !t.contains("SECRET2") && !t.contains("SECRET3"), "{t}");
        assert!(t.contains("/reset?"), "{t}");
        assert_eq!(v.text("no urls here"), "no urls here");
    }

    #[test]
    fn read_only_marks_write_tools() {
        let ro = list(McpAccess::ReadOnly);
        let desc = |name: &str| ro.iter().find(|t| t["name"] == name).unwrap()["description"].as_str().unwrap().to_string();
        assert!(!desc("list_sessions").contains("Needs full control"));
        assert!(desc("send_request").starts_with("[Needs full control"));
        assert!(!list(McpAccess::Full).iter().any(|t| t["description"].as_str().unwrap().contains("Needs full control")));
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
