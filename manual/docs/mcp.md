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
    - *…also change rules and breakpoints, capture and send requests*. The changing tools
      are only offered with this setting, and Quena checks it on every call.
3. Click *OK*. The tab then shows *Running at http://127.0.0.1:8867/mcp*.
4. Copy the *Claude Code* line and run it in a terminal:

    ```sh
    claude mcp add --transport http quena http://127.0.0.1:8867/mcp \
      --header "Authorization: Bearer <token>"
    ```

    Other MCP clients need the same three things: the URL, the transport *Streamable HTTP*
    and the `Authorization` header.

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
| `export_archive` | ✓ | save sessions as `.har` or `.saz` (absolute path; existing files only with `overwrite`) |

Lists return at most 200 rows and bodies at most 1 MB per call, so an agent never pulls a
whole capture at once. A tool error comes back as a result with `isError`, so the agent sees
the message, for example a filter syntax error.

## Examples for an agent

- "Which requests to `api.example.com` failed in the last minutes? Show me the response
  of the first one."
- "Answer `GET https://api.example.com/v1/config` with a 503 and check how the app
  behaves."
- "Pause every POST to `/orders` and show me the body before it goes out."
- "Append a broken element to every list in the responses of `/api/` and tell me which
  requests the app sends afterwards."
