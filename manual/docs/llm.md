# LLM traffic

Applications that use large language models talk to their APIs over HTTPS like any other
client. Quena recognises these calls and shows them as what they are: a conversation with
a model, its tools, the answer and what it cost — also when the answer came as a stream.

## What is recognised

| API | Recognised by |
|---|---|
| OpenAI Chat Completions and every OpenAI-compatible API (Azure OpenAI, Mistral, Groq, OpenRouter, DeepSeek, xAI, Together, Fireworks, LM Studio, vLLM, LiteLLM …) | `POST …/chat/completions` |
| OpenAI Responses | `POST …/responses` |
| Anthropic Messages | `POST …/v1/messages` |
| Google Gemini and Vertex AI | `POST …:generateContent`, `…:streamGenerateContent` |
| Ollama | `POST …/api/chat`, `…/api/generate` |
| Embeddings | `POST …/embeddings`, `…/api/embed`, `…:embedContent` |

The provider is named by the API's host (`OpenAI`, `Anthropic`, `Google Gemini`, …); other
hosts — a company gateway, a local server — keep their host name. HTTPS decryption must be
on, as for any HTTPS content.

## The LLM view

Selecting such a session opens the **LLM** view (on both the request and the response
side):

- a header with provider, model, whether the answer was streamed, the stop reason
  (`stop`, `end_turn`, `tool_calls`, `max_tokens` …), the **token usage** — input, output,
  read from and written to the provider's cache, reasoning — and the **estimated cost**;
- the **system prompt** (also `instructions`, `systemInstruction`);
- the **messages** sent, by role: text, images as placeholders, **tool calls** with their
  arguments and **tool results** with the call they answer;
- the **answer**: text, thinking or reasoning summaries (collapsed), tool calls. Streams
  (server-sent events, Ollama's JSON lines, Gemini's array) are put together;
- **tools and parameters**: the tool definitions offered and the parameters sent
  (`temperature`, `max_tokens`, `reasoning_effort`, `thinking` …).

An error the API answered with (rate limit, invalid request) is shown at the top. Texts
longer than 200,000 characters are shortened in this view; the body views show them
whole. A stream that ended early says so.

## Conversations of agents

An agent — Claude Code, Codex, an app of your own — sends its whole conversation with every
turn. The **Agents** panel (right pane, *Agents*) puts the calls of one run together:

- **Conversations**, newest first: title (the first prompt), agent (by its User-Agent,
  e.g. `claude-cli/2.0.14`), turns, tokens, the share of input the provider's prompt cache
  served, the estimated cost. A badge counts the turns where the cache missed. A
  **subagent** (Claude Code's *Task*, a Codex sub-thread) is listed under the conversation
  that started it.
- Choose one to see its **turns**: time, a bar on the run's time axis, input, cached share,
  output, cost, **the change from the call it continues** (`+2 messages`; `message 12
  changed`, `system prompt changed`, `tools changed`, `settings changed: thinking`, `model
  changed` — those break the cached prefix) and the tools the answer called. A **side call**
  — a call no later turn continues, such as Claude Code's prompt suggestions and summaries —
  is marked as such; answers from Quena's [agent cache](#agent-cache) are marked and cost
  nothing. Click a turn for its context; double-click selects its session.
- **Hints** where tokens go to waste, with the tokens they cost: the same tool result more
  than once in the context, large tool results, the same call repeated with the same
  arguments, a reminder the agent adds again and again, tools offered in every request but
  never called, a context close to the model's window, turns where the cache missed.
- **What fills the context**: a map of the last request (or the turn clicked) — system
  prompt, each tool definition, the provider's tool prompt, instruction files (CLAUDE.md,
  AGENTS.md), the list of skills, reminders, the environment, a compaction summary, user and
  assistant messages, thinking, tool calls and results by tool, images (also those in tool
  results). The slices are estimated from the text and scaled to the input tokens the
  provider reported, so they add up to the real figure; images and the tool prompt count with
  fixed amounts. History the provider keeps (`previous_response_id`) shows as a slice of its
  own.

Each call is linked to the call it continues: the request Claude Code names as the previous
one, the response a `previous_response_id` names, or else — among calls of the same agent
session (Claude Code's session id, Codex's session or thread, `prompt_cache_key`) with the
same system prompt and first prompt of the user — the one whose messages it carries
furthest. What agents add around the user's words (`<system-reminder>`, AGENTS.md,
`<environment_context>`, slash-command caveats, Claude Code's attribution block in the system
prompt) does not count. Without a session id, calls more than 30 minutes apart are not linked
by their messages alone. Subagents are found by the parent session the agent names, as the
agent's own subagent in the same session, or by their first prompt in a tool call shortly
before.

Each call gets the flag `x-quena-llm-conv` with the conversation's key: column
**Conversation**, *Group by → Conversation (agent run)* and the filter `conv == 22480fee4e`.
LLM calls in archives from other tools (no Quena flags) are found by their URL when the panel
opens and get all LLM flags.

### Why the cache missed

Providers keep the start of a request (Anthropic for 5 minutes, or 1 hour when asked; OpenAI
5–10 minutes, or 24 hours with `prompt_cache_retention`) and charge it at a fraction of the
price the next time. When a turn's cached input stays below half of what it could have been,
the turn says why — judged against the call it continues (or the nearest before it that used
tokens), and only where the provider reports cached tokens (Anthropic always; others once a
turn of the conversation was served from the cache):

| Reason | What happened |
|---|---|
| Message *n* changed | An earlier message differs: everything from it on is new to the cache. |
| System prompt changed / tool definitions changed | Also when only the order of the tools or a tool's schema changed. |
| Settings changed | `thinking`, `tool_choice`, the effort, or the `anthropic-beta` header. |
| Model changed | Each model has its own cache. |
| Cache expired | More than the cache's lifetime passed since the turn before. |
| No cache_control breakpoint | Anthropic caches only prefixes the request marks. |
| Marked, but too short | The request asks for caching, but is shorter than the provider caches for the model (Anthropic: 1,024 tokens, 2,048 for Haiku 3, 4,096 for the newest models). |
| Reason not known | Another server, the cache was evicted, or the provider reports no cached tokens. |

The **LLM** view shows the same for one call under *Context*: its turn in the conversation
(*Show conversation* opens the panel), the map, the change from the turn before (the message
that changed, before and after) and the cache. The context window comes from the fetched
LiteLLM list, else from the model's family.

## In the session list

When a call is done, it gets the flags `x-quena-llm` (`provider/model`),
`x-quena-llm-tokens`, `x-quena-llm-usage` and `x-quena-llm-cost`. They are kept in `.saz`
archives.

- Columns **LLM**, **Tokens** and **Cost** (right-click the column headers); they sort.
- *Group by → LLM model* puts the calls of each model together.
- Filters: `llm ~ claude`, `llm == "OpenAI/gpt-4o"`, `tokens > 10000` (see
  [syntax](syntax.md#filter-expressions)).
- *Statistics* lists calls, tokens and estimated cost per model for the selection.

## Costs

The cost is an estimate: tokens times the model's list price, with cached input at the
cached price. Discounts and batch prices are not known, and models without a price show
*cost unknown*. Prices come from three places, the first that knows the model wins
(*Settings → Bodies & Storage → LLM prices* shows all three):

1. **Your own prices** in `llm-prices.json` in the [data directory](settings.md#data-directory)
   — *Create llm-prices.json* / *Edit llm-prices.json* opens it. US dollars per million
   tokens, by model name prefix (the longest prefix wins):

    ```json
    {
      "gpt-5.1": { "input": 1.25, "output": 10, "cacheRead": 0.125 },
      "claude-opus-4-5": { "input": 5, "output": 25, "cacheRead": 0.5, "cacheWrite": 6.25 },
      "llama": { "input": 0, "output": 0 }
    }
    ```

    Changes count from the next call on, without a restart. A file that is no valid JSON is
    reported in the settings, the log and the *LLM* view; its prices are not used until it
    is fixed.

2. **The fetched price list**: *Fetch prices* / *Update prices* downloads
   [LiteLLM's price list](https://github.com/BerriAI/litellm/blob/main/model_prices_and_context_window.json)
   (MIT licence, several hundred models of OpenAI, Anthropic, Google, Mistral, DeepSeek,
   Groq, Bedrock, Azure …) through Quena's [upstream settings](settings.md) and keeps it in
   `llm-prices-litellm.json` in the data directory. This is the only time Quena asks for
   prices, and only when clicked; *Remove list* goes back to the other two. A model matches
   by its name with a date or release tag at most (`gpt-4o-2024-08-06` → `gpt-4o`).

3. **Built-in list prices** of common OpenAI, Anthropic, Google, Mistral and DeepSeek models
   as published in 2025, matched like the fetched list (a newer `claude-opus-4-7` does not
   get the price of `claude-opus-4`).

## Agent cache

The agent cache answers a call that was answered before, without asking the model again: an
agent or an app under development that sends the same prompt twice pays and waits only
once.

- In the **LLM** view of a successful call, check **Cache this answer**. From then on, the
  same request is answered by Quena from the kept answer, streamed answers as recorded.
- *Settings → Bodies & Storage → Agent cache → Cache every LLM call* caches each successful
  call by itself.
- "The same request" means the same method and URL, the same credentials (`Authorization`,
  `x-api-key`, `?key=` … — kept only as a hash: another key never gets these answers) and API
  version headers (`anthropic-version`, `anthropic-beta`, `openai-beta` …), and the same JSON
  body; key order, spacing and the fields `user` and `metadata` do not count.
- The answer is kept decoded (any client can read it) and without headers that name the
  account (`set-cookie`, `openai-organization`, request ids). At most 2000 answers or 1 GB are
  kept; the least recently used go first. A breakpoint on the request wins over the cache.
- A session answered from the cache shows *Answered by Quena from the agent cache* with the
  tokens, estimated cost and time saved (flag `x-quena-cache`); its tokens and cost are not
  added up in the columns and *Statistics*, as nothing was spent.
- The settings list the kept answers with their hits and the total saved, remove single ones
  or all, and name calls of the capture **asked more than once** that are not cached yet,
  with what the repeats cost — *Cache* caches them.
- Mock rules come first: a request a mock rule answers never reaches the cache.

The answers are kept in `llm-cache/` in the data directory and stay over restarts. Agents use
`llm_cache_status` and, with full control, `cache_llm_calls` ([MCP](mcp.md)).

## Replay answers without calling the model

To test an application without paying for (or waiting on) the model, answer its calls from
recorded sessions: select them and use *Mock Rules → Mocks from Sessions…* (see
[mocks from a capture](mocks.md)). With *Match request bodies* each prompt gets its own
recorded answer (JSON compared regardless of key order); without it, *In recorded order*
answers the calls one after the other. Streamed answers are replayed as recorded.

### Latency and rate limits

The turns show the time to the response's first byte and the output tokens per second; the
conversation their medians. A turn refused with 429 (rate limit) or 529/503 (provider
overloaded) is marked with its status, and the rate limits a response reports
(`anthropic-ratelimit-*`, `x-ratelimit-*`, `retry-after`) show when pointing at its tokens per
second. Hints say how many calls were refused and sent again, and when little of the token
limit is left.

### Try a variant

*Try a variant…* in the LLM view sends the call again with changes: another **system
prompt**, **tools** left out, another **model**, another **output limit**. The variant goes
to the same API with the original request's headers — its credentials included — after you
confirm, and costs tokens like any call. Its answer and tokens show next to the original's;
the new session is commented *Variant of #N*.

### Freeze a run for replays

*Freeze for replays…* puts a conversation's answered turns into the [agent
cache](#agent-cache). Run the agent again — after changing a skill, an MCP server, a prompt
file — and Quena answers the same requests from the recording without asking the model.
Where the new run asks something the recording does not have, the call goes to the model,
and the conversation says at which turn the run *left the frozen run*.

### Compare two runs

*Compare with* sets two conversations side by side — an A/B test of a prompt, a skill, a model
or an MCP server: turns, input and output tokens, cached share, cost, duration, the size of
the last request, cache misses, errors and hints, what filled the last request by category,
and the tool calls by tool, each with the difference.

To change what an agent sends while it runs, use the rewrite rules' LLM changes (remove a
tool, set the model, add to the system prompt; see [rewrite
rules](change-replay.md#the-editor)); to stop a request and edit it, the breakpoint
`bpllm` (see [breakpoints](change-replay.md#setting-breakpoints)).

## MCP servers

Agents call their tools on MCP servers (Model Context Protocol). Quena recognises these
exchanges — JSON-RPC over Streamable HTTP (a POST answered with JSON or a stream of
server-sent events), the older SSE transport (a GET stream and POSTs to `/messages`) — and
shows them in the **MCP** view:

- the method (`initialize`, `tools/list`, `tools/call`, `resources/read` …), the server's
  name and version, the protocol version and the MCP session;
- for `tools/call`: the tool, its **arguments**, the **result** (text, images, resources,
  structured content), whether it failed, and how many tokens the result adds to the
  agent's next request;
- the **way of the call**: the LLM call whose answer asked for the tool, the MCP exchange that
  ran it, the next LLM call that carries the result back to the model — and how many
  requests offer the tool, with what its definition costs in each;
- for `tools/list`: the tools offered with the tokens each definition costs;
- all JSON-RPC messages sent and received.

The LLM view lists, under the answer, the MCP exchanges that ran its tool calls (of the same
server, the same client process first). Over the older SSE transport a tool call's result
arrives on the server's event stream, not in the answer to the POST; Quena takes it from
there. A stream stays open for the whole run and is marked when it closes.

Exchanges get the flags `x-quena-mcp` (`tools/call get_issue`) and `x-quena-mcp-server` (the
name from `initialize`, else the host): columns **MCP** and **MCP server**, *Group by → MCP
server*, filters `mcp ~ "tools/call"` and `mcpserver == jira`. Exchanges in archives from
elsewhere get them when the tools report or the way of a call is asked for.

### Servers that talk over stdio

Most MCP servers run as a local process and talk over stdin and stdout; no proxy sees that.
Put `quena-cli mcp-tap` in front of the server's command in the MCP client's configuration.
`quena-cli` is a download of its own (see [CI](ci.md#quick-start)); give its full path, as
apps started from the dock or the start menu do not see the shell's `PATH`:

```json
{
  "mcpServers": {
    "jira": {
      "command": "/usr/local/bin/quena-cli",
      "args": ["mcp-tap", "--name", "jira", "--", "npx", "-y", "jira-mcp-server"]
    }
  }
}
```

`mcp-tap` runs the server and passes everything through unchanged; it pairs the requests with
their responses and writes each exchange to `mcp-tap/` in Quena's data folder (only for the
user: the recordings hold tool arguments and results). It finds that folder as the app does
— unless the app is portable or started with `QUENA_DATA_DIR`: then add `"--data-dir",
"<the app's data folder>"` before `--` (*About Quena* shows it). On
Windows, commands like `npx` or `uvx` that are `.cmd` files are run through `cmd.exe`. When
the folder cannot be written, the server still runs, without recording. A signal (Ctrl-C,
the client ending the server) is passed on to the server, which gets five seconds to end;
`mcp-tap` exits with the server's exit code.

While Quena captures, the exchanges appear as sessions `stdio://jira/tools/call`, with the
server's process and the name given with `--name` as MCP server; requests of the server to
the client (sampling, roots) as `stdio://jira/server/…`, requests never answered (the server
ended, the client cancelled) without a response. Exchanges recorded while Quena does not
capture wait in the folder and appear when it captures. Recordings read completely are
removed after a week without new exchanges.

## Tools and skills

*Agents → Tools & skills* sums up the tools and skills of all conversations:

- every **tool**: the LLM requests that offer it and what its definition costs in each and
  in all, how often the model called it, the exchanges with its MCP server, failures, and the
  average and largest result in tokens. Tools that are offered but never called are shown
  muted — *Only tools never called* lists them alone, with the tokens they cost in all. MCP
  tools named the way Claude Code names them (`mcp__jira__get_issue`) are matched with the
  server's `get_issue`;
- every **skill**: in how many conversations it is listed, how often the model loaded it
  (Claude Code's Skill tool, or reading its `SKILL.md`), and in how many conversations.

## AI agents

Over [MCP](mcp.md), `get_llm_call` returns a call taken apart the same way; the session
rows carry `llm` and `tokens`. Unless agents may see secrets, the bodies are redacted first
(credentials and secret fields), as for `get_session`.
