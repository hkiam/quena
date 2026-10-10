# Quena's MCP server

Quena can run a [Model Context Protocol](https://modelcontextprotocol.io) server, so an AI
agent such as Claude Code can read the capture and, if you allow it, control Quena. The agent
can look at failing requests, read LLM calls and agent conversations, set mock rules and
breakpoints, send requests and replay them.

This page is about the MCP server Quena offers. How Quena records and shows the MCP traffic of
your agents (their tool calls to other MCP servers) is on
[MCP servers and skills](mcp-traffic.md).

## Turn it on

1. Open *Options → AI agents (MCP)* and check *Enable MCP server*. Quena creates a random
   token the first time.
2. Choose what agents may do:
    - *…only read sessions, rules and statistics* (the default). Agents can list, search
      and read sessions and bodies, and see rules and breakpoints.
    - *…also change rules and breakpoints, capture and send requests*. Quena checks this
      on every call; without it the changing tools say *Needs full control* and refuse, so
      granting it later works without reconnecting the agent.
3. Click *OK*. The tab then shows *Running at http://127.0.0.1:8867/mcp*.
4. Copy the *Claude Code* line and run it in a terminal:

    ```sh
    claude mcp add --transport http quena http://127.0.0.1:8867/mcp \
      --header "Authorization: Bearer <token>"
    ```

    Or click **Set up for** *Claude Code*, *VS Code*, *Cursor* or *Codex*: Quena adds itself
    with the token to that program's user configuration and keeps a copy of the file
    (`.bak`):

    | Client | What Quena changes |
    |---|---|
    | Claude Code | runs `claude mcp add --scope user …` (the `claude` command must be installed) |
    | VS Code | `servers.quena` in the user `mcp.json` (`~/Library/Application Support/Code/User/` on macOS, `%APPDATA%\Code\User\` on Windows, `~/.config/Code/User/` on Linux) |
    | Cursor | `mcpServers.quena` in `~/.cursor/mcp.json` |
    | Codex | the table `[mcp_servers.quena]` in `~/.codex/config.toml` (`url`, `http_headers`) |

    Other entries stay as they are; a file that is not valid JSON is left alone. After *New
    token*, click the button again. Other MCP clients need the same three things: the URL,
    the transport *Streamable HTTP* and the `Authorization` header.

5. Optional: **Agent skill** → *Claude Code* or *Codex* installs the skill
   `quena-traffic-debugging` (`~/.claude/skills/…/SKILL.md`, `~/.codex/skills/…/SKILL.md`). It
   tells the agent when to use Quena and how: which filters find failing or slow requests,
   when to run the diagnostics, how to read LLM calls and mock endpoints.

The settings of the tab:

| Setting | Default | Meaning |
|---|---|---|
| *Enable MCP server* | off | listen on `127.0.0.1` while Quena runs |
| *Port* | 8867 | the server's port; another program on it makes the start fail (Quena says so after *OK*) |
| *Agents may* | only read | read only, or full control (see above) |
| *Show credentials and tokens to agents unredacted (unsafe)* | off | see [What agents see and touch](#what-agents-see-and-touch) |
| *Folder for agent files* | empty (`mcp-files` in the data folder) | the only folder agents read files from and write files to |
| *Token* | generated | *Copy*, or *New token* to lock out every client that has the old one |

To stop all agents at once, uncheck *Enable MCP server*.

### Check the connection

```sh
curl -s http://127.0.0.1:8867/mcp -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"status","arguments":{}}}'
```

`401` means a wrong or missing token, `403` a `Host` or `Origin` that is not
`127.0.0.1`/`localhost`, *connection refused* that the server is off or on another port.

## What agents see and touch

- **Secrets are replaced.** An agent sends what it reads to its model provider. Unless
  *Show credentials and tokens to agents unredacted* is checked, Quena replaces
  `Authorization` and `Cookie` values, token and API-key headers, secret URL parameters
  and secret body fields (`password`, `access_token`, JWTs …) in everything it hands out —
  rows, headers, bodies, previews, and also in the files it writes for agents (exports,
  `.http` collections; no private environment file). Quena itself still sends and records
  the real values.
  E-mail addresses and other personal data are not replaced; use
  [sanitized export](archives.md) when that matters.
- **One folder for files.** Exports, `.http` collections (and their body files) and files
  served by mock rules created by agents must lie in *Folder for agent files* (empty:
  `mcp-files` in the data folder; `status` names it). Relative paths are taken from there.
  `{{$processEnv}}` is not available to agents.
- **Captured traffic is foreign content.** A response can contain text written to mislead
  an agent. With full control an agent can send requests (also into a VPN), change rules and
  write files in its folder. Grant full control for a task you watch, and switch it off
  again.
- Searching (`search_sessions`) runs as its own job and never cancels your Find Sessions.

The server only listens on `127.0.0.1`. It rejects requests without the token, and requests
whose `Host` or `Origin` is not a loopback name (that blocks web pages using DNS
rebinding). *New token* makes the old token useless once you click *OK*. The server runs
apart from the proxy, so agent calls never slow down forwarding.

## Tools

✓ marks the tools that need full control.

### Sessions and capture

| Tool | Full control | What it does |
|---|---|---|
| `status` | | capture state, listen address, upstream, number of sessions, breakpoints, the agents' folder |
| `list_sessions` | | compact rows; `filter` (see [syntax](syntax.md#filter-expressions)), `since_id`, paging |
| `get_session` | | request and response heads, timers, bodies as text (decoded, cut at 16 KB by default) |
| `get_body` | | a piece of a body: `offset`, `length`, decoded or raw |
| `search_sessions` | | text or regex in URLs, headers, bodies |
| `statistics` | | bytes, status codes, content types, hosts |
| `compare_captures` | | two captures in the list compared: changed, new and gone requests ([Compare captures](analyze.md#compare-captures)) |
| `set_capture` | ✓ | start or stop capturing |
| `clear_sessions` | ✓ | remove sessions matching a filter, or all |
| `export_archive` | ✓ | save sessions as `.har` or `.saz` in the agents' folder (existing files only with `overwrite`) |

### LLM calls and agents

| Tool | Full control | What it does |
|---|---|---|
| `get_llm_call` | | an [LLM API call](llm.md) taken apart: model, messages, tools, answer, tokens, estimated cost |
| `list_conversations` | | the [agent conversations](agents.md) in the capture: title, agent, models, turns, side calls, tokens, cached share, cost, cache misses, refused calls, retries, latency, context size; subagents name their parent. `limit` (default 100) and `offset` |
| `get_conversation` | | one conversation by key: its turns with the change from the call it continues and why the cache missed, hints where tokens go to waste, what filled the last request, its subagents. `limit` (default 500 turns) and `offset`; the result has `turnsTotal` and `turnsOffset` |
| `get_context` | | what fills one LLM call's input by category (system prompt, each tool, instruction files, results by tool …), its turn and the cache's verdict |
| `get_tool_report` | | [tools and skills](mcp-traffic.md#tools-and-skills) across all conversations: offered, definition cost, model calls, MCP calls, failures, result sizes; skills listed and loaded |
| `llm_cache_status` | | the [agent cache](optimize-agents.md#agent-cache): kept answers with hits and savings, whether every call is cached, repeated calls worth caching |
| `cache_llm_calls` | ✓ | cache or forget the answers of LLM call sessions; turn *Cache every LLM call* on or off |

Titles of conversations, the text in hints and the changed message of `get_context` are free
text: unless agents may see secrets, they are redacted with the sanitizer's credentials preset,
like the bodies.

### Diagnostics

| Tool | Full control | What it does |
|---|---|---|
| `run_diagnostics` | | runs the [diagnostics](diagnostics.md) over all sessions, a filter or chosen ids (profile, hosts, processes) and returns the findings with severity, evidence, recommendations and session ids; the report also shows in the *Diagnostics* tab |
| `get_diagnostics_report` | | the last diagnostics report as findings, or the analyser's profiles when there is none |

### Mock rules

| Tool | Full control | What it does |
|---|---|---|
| `list_mock_rules` | | [Mock Rules](change-replay.md#mock-rules) with hit counts |
| `add_mock_rule`, `update_mock_rule`, `remove_mock_rule`, `set_mock_options` | ✓ | add, change or delete mock rules, and their options |
| `mock_from_sessions` | ✓ | rules that answer with recorded responses |

### Rewrite rules

| Tool | Full control | What it does |
|---|---|---|
| `list_rewrite_rules` | | [rewrite rules](change-replay.md#rewrite-rules) with hit counts |
| `preview_rewrite` | | apply a rewrite rule to a captured body without sending anything |
| `add_rewrite_rule`, `update_rewrite_rule`, `remove_rewrite_rule`, `set_rewrite_options` | ✓ | change real requests and responses (JSONPath, regex, headers, query, cookies, status, marks); rules can have a `group`, and `set_rewrite_options` switches groups off. The LLM operations `llmRemoveTool`, `llmSetModel` and `llmAppendSystem` change requests to LLM APIs ([Change requests while an agent runs](optimize-agents.md#change-requests-while-an-agent-runs)) |
| `apply_rewrite_rules` | ✓ | apply rewrite rules to captured sessions: changed copies, the originals stay |

### Breakpoints

| Tool | Full control | What it does |
|---|---|---|
| `get_breakpoints` | | breakpoints and paused sessions |
| `set_breakpoints` | ✓ | set or clear the [breakpoints](change-replay.md#setting-breakpoints) before requests, after responses, by URL, status or method (not the LLM breakpoint `bpllm`) |
| `resume_session`, `resume_all` | ✓ | release paused sessions, unchanged or with a new head and body, aborted, or answered |

### Send and replay

| Tool | Full control | What it does |
|---|---|---|
| `send_request` | ✓ | send a request through Quena and return the session |
| `replay_sessions` | ✓ | send captured requests again (`count`, one after the other or `parallel` 1–100 at a time) |
| `list_http_requests` | | the requests of a [`.http` file](change-replay.md#request-collections-http-files), resolved for an environment |
| `run_http_file` | ✓ | send a `.http` collection (or some of its requests) through Quena |
| `list_collections` | | the Composer's collections; `collection:NAME` as `path` above names one |
| `sessions_to_http_file` | ✓ | write captured sessions as a `.http` file with environment files |

### Connections

| Tool | Full control | What it does |
|---|---|---|
| `list_host_remaps` | | [host remapping](host-remapping.md) entries |
| `set_host_remap`, `remove_host_remap` | ✓ | add, change or delete host remapping entries |
| `list_reverse_proxies` | | [reverse proxy](reverse-proxy.md) entries and whether they listen |
| `set_reverse_proxy`, `remove_reverse_proxy` | ✓ | add, change or delete reverse proxy entries and their path routes (agents cannot open one to remote computers) |
| `set_listeners` | ✓ | switch the [SOCKS and transparent ports](socks-transparent.md) on or off, or move them (this machine only) |
| `launch_browser`, `open_terminal` | ✓ | start a browser with its own profile, or a terminal, that uses Quena ([Start a browser or terminal](capture.md#start-a-browser-or-terminal-with-quena)); `launch_browser` without `kind` lists the browsers. `open_terminal` takes no command, so it cannot start an agent |

Session lists return at most 200 rows and bodies at most 1 MB per call (reading from up to
8 MB into a body), so an agent never pulls a whole capture at once; `list_conversations`
returns up to 1,000 conversations and `get_conversation` up to 5,000 turns per call. A tool
error comes back as a result with `isError`, so the agent sees the message, for example a
filter syntax error.

## Prompts

MCP clients show Quena's prompts as commands (in Claude Code `/mcp__quena__debug_failures` …):

| Prompt | Arguments | Task |
|---|---|---|
| `debug_failures` | `filter` (optional) | find failing requests, group them by endpoint and explain the cause |
| `analyze_performance` | `filter` (optional) | run the diagnostics and statistics, name the most important problems with a change for each |
| `explain_session` | `id` | explain one request and its response in plain words |
| `llm_costs` | | LLM calls per model, tokens, estimated cost and where to save |
| `mock_endpoint` | `url` | mock an endpoint from its recorded response (needs full control) |

## Examples for an agent

- "Which requests to `api.example.com` failed in the last minutes? Show me the response
  of the first one."
- "Answer `GET https://api.example.com/v1/config` with a 503 and check how the app
  behaves."
- "Pause every POST to `/orders` and show me the body before it goes out."
- "Append a broken element to every list in the responses of `/api/` and tell me which
  requests the app sends afterwards."
