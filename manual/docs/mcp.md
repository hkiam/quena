# AI agents (MCP)

Quena can run a [Model Context Protocol](https://modelcontextprotocol.io) server, so an AI
agent such as Claude Code can read the capture and, if you allow it, control Quena. The agent
can look at failing requests, set mock rules and breakpoints, send requests and replay them.

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

    Other MCP clients need the same three things: the URL, the transport *Streamable HTTP*
    and the `Authorization` header.

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

| Tool | Needs full control | What it does |
|---|---|---|
| `status` | | capture state, listen address, upstream, number of sessions, breakpoints |
| `list_sessions` | | compact rows; `filter` (see [syntax](syntax.md#filter-expressions)), `since_id`, paging |
| `get_session` | | request and response heads, timers, bodies as text (decoded, cut at 16 KB by default) |
| `get_body` | | a piece of a body: `offset`, `length`, decoded or raw |
| `search_sessions` | | text or regex in URLs, headers, bodies |
| `statistics` | | bytes, status codes, content types, hosts |
| `list_mock_rules`, `get_breakpoints` | | rules with hit counts; breakpoints and paused sessions |
| `list_rewrite_rules` | | [rewrite rules](change-replay.md#rewrite-rules) with hit counts |
| `preview_rewrite` | | apply a rewrite rule to a captured body without sending anything |
| `set_capture` | ✓ | start or stop capturing |
| `clear_sessions` | ✓ | remove sessions matching a filter, or all |
| `send_request` | ✓ | send a request through Quena and return the session |
| `replay_sessions` | ✓ | send captured requests again |
| `add_mock_rule`, `update_mock_rule`, `remove_mock_rule`, `set_mock_options` | ✓ | [Mock Rules](change-replay.md#mock-rules) |
| `mock_from_sessions` | ✓ | rules that answer with recorded responses |
| `add_rewrite_rule`, `update_rewrite_rule`, `remove_rewrite_rule`, `set_rewrite_options` | ✓ | change real requests and responses (JSONPath, regex, headers, status) |
| `set_breakpoints`, `resume_session`, `resume_all` | ✓ | [breakpoints](change-replay.md) |
| `list_http_requests` | | the requests of a [`.http` file](change-replay.md#request-collections-http-files), resolved for an environment |
| `run_http_file` | ✓ | send a `.http` collection (or some of its requests) through Quena |
| `sessions_to_http_file` | ✓ | write captured sessions as a `.http` file with environment files |
| `export_archive` | ✓ | save sessions as `.har` or `.saz` in the agents' folder (existing files only with `overwrite`) |
| `list_host_remaps` | | [host remapping](host-remapping.md) entries |
| `set_host_remap`, `remove_host_remap` | ✓ | add, change or delete host remapping entries |
| `launch_browser`, `open_terminal` | ✓ | start a browser with its own profile, or a terminal, that uses Quena ([Start a browser or terminal](capture.md#start-a-browser-or-terminal-with-quena)); `launch_browser` without `kind` lists the browsers |
| `list_reverse_proxies` | | [reverse proxy](reverse-proxy.md) entries and whether they listen |
| `set_reverse_proxy`, `remove_reverse_proxy` | ✓ | add, change or delete reverse proxy entries and their path routes (agents cannot open one to remote computers) |
| `set_listeners` | ✓ | switch the [SOCKS and transparent ports](socks-transparent.md) on or off, or move them (this machine only) |

Lists return at most 200 rows and bodies at most 1 MB per call (reading from up to 8 MB into
a body), so an agent never pulls a whole capture at once. A tool error comes back as a result with `isError`, so the agent sees
the message, for example a filter syntax error.

## Examples for an agent

- "Which requests to `api.example.com` failed in the last minutes? Show me the response
  of the first one."
- "Answer `GET https://api.example.com/v1/config` with a 503 and check how the app
  behaves."
- "Pause every POST to `/orders` and show me the body before it goes out."
- "Append a broken element to every list in the responses of `/api/` and tell me which
  requests the app sends afterwards."
