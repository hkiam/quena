# Agent conversations

An agent (Claude Code, Codex, an app of your own) sends its whole conversation to the model
with every turn. Quena links each call to the call it continues and puts the calls of one run
together as a **conversation**. For each conversation it shows what changed from one call to
the next, why the provider's prompt cache missed, where tokens go to waste and what fills the
context. How to get an agent's traffic into Quena is on the
[overview](agents-overview.md#get-agent-traffic-into-quena).

## The Agents panel

![The Agents panel: a Codex run, a Claude Code run with a subagent; for the Claude Code run its hints (a cache miss, a file read three times, tools never called, a recurring reminder) and its turns with a side call, the turn whose cache missed and an MCP tool call](img/agents.png)

*View → Agents*, the tab *Agents* in the right pane or *Show conversation* in the
[LLM view](llm.md#the-llm-view) opens the panel. Its tab *Conversations* lists the runs, newest first; the tab
[*Tools & skills*](mcp-traffic.md#tools-and-skills) sums up tools and skills. The panel is
computed from the capture when it opens and updates as calls arrive; the refresh button
computes it again. Calls still running are read once they are done, and conversations of
removed sessions go with them.

| Column | What it shows |
|---|---|
| Conversation | The title: the first prompt of the user, without what the agent adds around it (reminders, instruction files, environment). A badge counts the turns where the cache missed, a red one the calls that failed. A **subagent** is listed under the conversation that started it. |
| Started | When the first call started. |
| Agent | The agent that sent the first call, by its User-Agent (`Claude Code 2.0.14`, `Codex 0.46.0` …; the first word of the User-Agent for clients Quena does not know, the provider when there is none). |
| Turns | All LLM calls of the conversation, side calls, variants and answers from the agent cache included. |
| Tokens | Input (cached tokens included) plus output, of the calls that spent tokens. |
| Cached | The **cached share**: input tokens read from the provider's prompt cache divided by all input tokens. Answers from Quena's agent cache count in neither. `–` when the provider reported no cache reads and no turn missed. |
| Cost | The estimated cost of the turns whose model has a known price ([Costs](llm.md#costs)). |

Double-click a row (or Shift+Enter) to select the conversation's first session in the list.
Choose a conversation to see, at the top, its key, agent and models, the number of turns
(with side calls and answers from the agent cache), the time from the first call's start to
the last call's end, input and output tokens, the cached share, the cost, how much of the
model's context window the last request filled, the median latency, refused calls and
retries. Below that are *Freeze for replays…*, *Export:* and *Compare with* (see
[Optimising agents](optimize-agents.md)), the conversation that started it and its
subagents, the hints, the turns and the context of the last request.

## Turns

One row per LLM call, in the order they started (long runs show the first 1,000; *Show all
… turns* shows the rest):

- **#** and **Time**; pointing at the number names the turn it continues.
- A **bar** on the run's time axis: when the call ran and how long it took.
- **In** (input tokens, cached ones included), **Cached** (the share read from the prompt
  cache), **Out**, **Cost**.
- **Headers**: the time from sending the request to the response headers (with connecting,
  on a new connection). **tok/s**: output tokens per second of a streamed answer, from its
  first byte. See [Latency and rate limits](#latency-and-rate-limits).
- **Change**: how the request differs from **the call it continues**, which need not be the
  row above (a side call or a subagent may have run in between): `first turn`,
  `+2 messages`, `sent again` (the same messages, e.g. a retry), `message 12 changed`,
  `system prompt changed`, `tools changed` (also when only their order or a schema changed),
  `settings changed: thinking`, `model changed`. Changes that break the provider's cached
  prefix are orange. A status of 400 or more shows as a red badge.
- **Tool calls**: the tools the answer called. A **side call**, a call no later turn
  continues (Claude Code's prompt suggestions and summaries, a [variant](optimize-agents.md#try-a-variant)),
  is marked *side call*. An answer from Quena's [agent cache](optimize-agents.md#agent-cache)
  is marked *agent cache* and costs nothing.

Click a row for that turn's context (the same as in the LLM view); double-click it or press
Shift+Enter to select its session. Pointing at a row shows the cache verdict.

## Why the cache missed

Providers keep the start of a request for a while and charge it at a fraction of the price
the next time: Anthropic for 5 minutes, or 1 hour when the request asks for it (`"ttl": "1h"`);
OpenAI for 5 to 10 minutes, or 24 hours with `prompt_cache_retention: "24h"`.

A turn counts as a **cache miss** when the tokens it read from the cache are less than half
of what could have come from there: the input of the call it was judged against, at most
this call's input. That call is the one it continues, or, if that one used no tokens or
failed, the nearest before it that did. Turns where that amount is below the shortest prompt
the provider caches (see below; 1,024 tokens for the other APIs) are not judged. Quena judges only where the provider
reports cached tokens: for Anthropic's Messages API always (also on Vertex AI and Bedrock),
for the other APIs once a turn of the conversation read from or wrote to the cache.

A missed turn names the reasons it can see:

| Reason | What happened |
|---|---|
| Message *n* of *m* changed | An earlier message differs: everything from it on is new to the cache. |
| The system prompt changed | Claude Code's attribution block does not count. |
| The tool definitions changed | Tools added, removed or changed, or only their order. |
| Settings the cache depends on changed | `thinking`, `tool_choice`, the reasoning effort (`reasoning.effort`, `reasoning_effort`), `output_config`, `prompt_cache_retention`, or the `anthropic-beta` header. |
| The model changed | Each model has its own cache. |
| Cache expired | More time passed since the end of the call it was judged against than the cache's lifetime: 24 hours with `prompt_cache_retention` `24h`, 1 hour with Anthropic's `ttl` `1h`, else 5 minutes. |
| No cache_control breakpoint | Anthropic caches only prefixes the request marks with `cache_control`. |
| Reason not known | None of the above: another server answered, the provider evicted the entry, or it does not report cached tokens. |

A request to Anthropic's Messages API that sets `cache_control` but is shorter than the
provider caches gets its own note, *Marked for caching, but shorter than … tokens*: 1,024
tokens, 2,048 for Claude 3 Haiku and 3.5 Haiku, 4,096 for Opus 4.5 and later, Haiku 4.5 and
Sonnet 5. Other APIs get no such note.

## Hints where tokens go to waste

The hints look at the conversation's last request on its main line (it carries the whole
history) and at the tools all turns called. Each names the tokens it costs, largest first:

| Hint | When it shows | Tokens |
|---|---|---|
| The same call repeated | A tool called more than twice with the same arguments. | What the later results add. |
| The same tool result more than once | An identical result of 50 tokens or more is in the context twice or more (and no repeated call explains it). | The extra copies. |
| A large result | Results of 8,000 tokens or more; the five largest. | The result. |
| The same reminder again and again | A note the agent adds (`<system-reminder>` …) of 100 characters or more, three times or more. | The extra copies. |
| Tools never called | Tools offered in the last request that no turn called, once the conversation has three or more turns besides side calls. | Their definitions, in every request. |
| The context fills the window | The last request's input is 70 % or more of the model's context window. | The input. |
| Calls refused | Calls answered with 429, 529 or 503, and how many were sent again unchanged after a failure. | Waiting time instead of tokens. |
| Close to the rate limit | The latest rate limit the provider reported has less than 10 % of its tokens left. | – |
| The cache missed | Turns that were cache misses (see above). | The tokens processed again without the cache. |

Token counts in the hints are estimated from the text and scaled to the input the provider
reported, as in the context map.

## What fills the context

*Context of the last request* (and the context of a turn you click) shows a map of the
request's input: the system prompt, each tool definition, the provider's tool prompt,
instruction files (CLAUDE.md, AGENTS.md, by path), the list of skills, reminders, the
environment (working folder, open files, output of commands the user ran), a compaction
summary, user and assistant messages, thinking, tool calls and tool results by tool, and
images (also those in tool results).

- The slices are **estimated** from the text the way tokenisers split it, then **scaled** so
  that they add up to the input tokens the provider reported.
- Two slices have **fixed amounts** and are not scaled: each image counts 1,600 tokens (the
  size of an image is not known), and Anthropic's tool prompt, the system prompt Anthropic
  adds when a request offers tools, counts 346 tokens.
- History the provider keeps (OpenAI Responses with `previous_response_id`) shows as a slice
  of its own, *History kept by the provider*, when the reported input is well above what the
  request carries.
- The **context window** comes from `context` in your `llm-prices.json`, else from the fetched
  LiteLLM list, else from the model's family. Claude models count with a window of 1,000,000
  tokens once a request was larger than their usual window (they run with the 1M context
  then).

## Latency and rate limits

Each turn shows the time from sending the request to the response headers (on a new
connection with connecting) and, for streamed answers, the output tokens per second from the
answer's first byte; the conversation shows the medians of both. A turn refused with 429
(rate limit) or 529 / 503 (provider overloaded) shows its status. The rate limits a response
reports (`anthropic-ratelimit-*`, `x-ratelimit-*`, `retry-after`) show when pointing at the
status or the tokens per second. *Retries* counts calls sent again unchanged after the call
before them failed.

## The Context section of the LLM view

The **LLM** view shows the same for one call under *Context*: its turn in the conversation
(*Show conversation* opens the panel), the context map with the share of the context window,
the change from the call it continues (the message that changed, before and after) and the
cache verdict.

## How calls are put together

Each call is linked to the call it continues:

1. the request Claude Code names as its previous one (in its attribution block), when the
   two share messages or the same group (below);
2. the response that a `previous_response_id` names (OpenAI Responses), or the message that
   Claude Code's `thread.previous_message_id` names (its message threads); such a call carries
   only its new messages, so it counts as `+n messages`, a system prompt or tools it leaves
   out count as unchanged, and the history for the hints and the context map is put together
   from the calls before it;
3. else, among earlier calls of the same **group**, the one whose messages this call carries
   furthest. The latest call it carries whole wins; a call that shares only a start must
   share at least half of that call's messages.

A **group** is the agent's session, the first 200 characters of the system prompt and the
first prompt of the user. The agent's session is Claude Code's session id
(`X-Claude-Code-Session-Id`, or `session_id` in `metadata.user_id`), Codex's session or
thread (`session_id`, `thread_id` headers) or a `prompt_cache_key`. What agents add around the
user's words (`<system-reminder>`, AGENTS.md, `<environment_context>`, slash-command caveats)
and Claude Code's attribution block do not count. Without a session id, calls more than
**30 minutes** apart are not linked by their messages alone.

Calls linked that way form a conversation. Its **main line** runs from its newest call back
through the calls each continues; a call off the main line that no other call continues is a
side call.

A conversation is a **subagent** of another when:

- the agent names the parent session (Claude Code's `parent_session_id` in
  `metadata.user_id`, Codex's `x-codex-parent-thread-id`): the latest conversation of that
  session started before it;
- else its first prompt (the first 60 characters, at least 20) appears in the arguments of a
  tool call of another conversation in the **2 hours** before it started (Claude Code's
  *Task* tool, for example);
- else the agent marks it as a subagent (Claude Code's `cc_is_subagent`, Codex's
  `x-openai-subagent`) and another conversation of the same session started before it.

Each conversation has a **key** of 10 hexadecimal characters, made from its group and the
session number of its first call. Keys are stable within one capture. The same calls loaded
again from an archive can get other keys; the flags are brought up to date when the Agents
panel opens.

## Columns, grouping and filters

Each call gets the flag `x-quena-llm-conv` with its conversation's key:

- column **Conversation** (right-click the column headers);
- *Group by → Conversation (agent run)*;
- filters `conv == 22480fee4e` (also `conversation`) and `agent ~ "claude code"`
  (see [syntax](syntax.md#filter-expressions)).

The columns **LLM**, **Tokens**, **Cost** and **Agent** are described on
[LLM traffic](llm.md#in-the-session-list).

## Export a conversation

*Export:* in a conversation writes it to a file you choose. Only that conversation is
written; its subagents are exported on their own.

| Format | What it holds |
|---|---|
| **Markdown** | A header (agent, models, turns, tokens, cost, key) and the hints in words, then each turn: model, tokens and cost, the cache notes in words (*Cache missed: … tokens were processed again without it*), the system prompt (first turn only), the messages the turn added (tool calls and results included) and the answer. Each part is cut at 4,000 characters. To read or share. |
| **JSON lines** | One line per turn, for evaluations: `conversation`, `turn`, `session`, `started`, `side`, the change (`diff`), the cache notes, and `call`, the LLM call as the LLM view takes it apart. `call` carries only the messages this turn added (`messagesBefore` says how many came before), and the system prompt and tools only when they differ from the line before. |
| **OpenTelemetry** | Spans after the OpenTelemetry GenAI semantic conventions as OTLP JSON: a span for the run (`invoke_agent`) and one per call (`chat <model>`) with provider, model, tokens, cached tokens, finish reason and the names of the tools called. No prompts or results. Trace and span ids are derived from the conversation's key and start, so exporting the same run again keeps them. To load into Langfuse, Phoenix or another tracing tool. |

The file is written as it goes, a call at a time, and put in place at the end. Texts are
taken as the LLM view has them, so a part longer than 200,000 characters is shortened.

### Privacy of exports

Markdown and JSON lines hold the **full content**: the system prompt, the user's prompts,
tool arguments and results (file contents, command output) and the answers, including any
secrets in them. Nothing is redacted. Read the file before you share it. The OpenTelemetry
export holds no content, but it does name the agent, the models and the tools.

## For AI agents

Over [Quena's MCP server](mcp.md):

- `list_conversations`: the conversations with title, agent, models, turns, side calls,
  tokens, cached share, cost, cache misses, refused calls, retries, latency and context size;
  subagents name their parent. `limit` (default 100) and `offset` page through them.
- `get_conversation`: one conversation by key, with its turns (the change, the cache
  verdict, rate limits), the hints, what filled the last request and its subagents. `limit`
  (default 500 turns) and `offset` page through long runs; `turnsTotal` and `turnsOffset`
  say where the page is.
- `get_context`: what fills one call's input, its turn and the cache verdict.

Unless agents may see secrets, titles, the text in hints and the changed message are redacted
with the credentials preset of the sanitizer first.
