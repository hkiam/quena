# Optimising agents

Once an agent's runs are in Quena, you can change what it sends and see what that does to its
tokens, cost and answers, without editing the agent itself.

A workflow that works well:

1. **Measure.** Run the agent through Quena and look at its
   [conversation](agents.md#the-agents-panel): the hints, the cache misses, the context map,
   the tools never called ([Tools & skills](mcp-traffic.md#tools-and-skills)).
2. **Change one thing.** Try a single call with another system prompt, fewer tools or another
   model ([Try a variant](#try-a-variant)), or change every request of the next run with a
   rewrite rule ([Change requests while an agent runs](#change-requests-while-an-agent-runs)).
3. **Run again cheaply.** [Freeze](#freeze-a-run-for-replays) the first run, so the second
   gets the same answers from Quena as long as it asks the same things.
4. **Compare** the two runs side by side ([Compare two runs](#compare-two-runs)).

## Try a variant

*Try a variant…* in the [LLM view](llm.md#the-llm-view) sends the call again with changes:

- another **system prompt**, or none. A changed system prompt is sent as one text, so cache
  marks and Claude Code's attribution block are left out, and the provider's cache starts
  over. A system prompt too long to edit in the view is sent as it was;
- **tools** left out (a name, or a prefix with `*` at the end such as `mcp__jira__*`). A tool
  choice that names a removed tool is removed as well, and so are tools and tool choice when
  no tool is left;
- another **model**. APIs that name the model in the URL get it there: Gemini and Vertex AI
  (`…/models/{model}:generateContent`, `…/publishers/…`) and Bedrock (`…/model/{model}/…`);
  the others in the body;
- another **output limit**, under the key the API uses: `max_tokens` (Anthropic, and OpenAI
  Chat when the request used it), `max_completion_tokens` (OpenAI Chat),
  `max_output_tokens` (OpenAI Responses), `generationConfig.maxOutputTokens` (Gemini),
  `options.num_predict` (Ollama), `inferenceConfig.maxTokens` (Bedrock Converse).

The changes are made in the format of the API, known from the URL (for OpenAI the system
prompt is a `system` message, for Gemini `systemInstruction` …).

**What is sent.** The variant goes to the same API with the original request's headers, its
credentials included, after you confirm, and costs tokens like any call. For a session loaded
from an archive these are the credentials of whoever recorded it, and Quena says so before
sending. Its answer, error and tokens show next to the original's; the new session is
commented *Variant of #N* and counts in its conversation as a side call.

**What still applies.** Neither the agent cache nor rewrite rules touch a variant: it goes out
as written. Mock rules, the rules script and breakpoints, including
[the LLM breakpoint](#break-before-llm-requests), still apply to it.

**Limits.** Requests signed with AWS Signature V4 (Amazon Bedrock) cannot be sent as a
variant: AWS would refuse the changed copy, so Quena refuses it with a message. Calls whose
credentials have expired since (OAuth tokens, such as those of Vertex AI, last about an hour)
fail with the provider's error.

## Change requests while an agent runs

Rewrite rules can change every LLM request an agent sends, while it runs, with three
operations for requests to LLM APIs (see [the rewrite editor](change-replay.md#the-editor)):

| Operation | In the editor | What it does |
|---|---|---|
| `llmRemoveTool` | *LLM: remove tool* | Takes tools out of what the agent offers: a name, or a prefix with `*` (`mcp__jira__*` for all tools of a server). A tool choice naming a removed tool is removed as well. |
| `llmSetModel` | *LLM: set model* | Sends another model, in the URL where the API names it there (Gemini, Vertex AI, Bedrock). |
| `llmAppendSystem` | *LLM: add to system prompt* | Adds an instruction at the end of the system prompt. |

They work in the format of the API known from the URL: Anthropic (also Claude on Vertex AI
and Bedrock), OpenAI Chat and Responses, Gemini, Bedrock Converse and Ollama. Requests to
other APIs stay as they are, and so do requests signed with AWS Signature V4. Choosing an LLM
operation sets the rule to change requests.

The agent gets the changed requests and works on with them. A changed system prompt or tool
list breaks the provider's cached prefix from that point. Agents can add such rules over
[Quena's MCP server](mcp.md) with `add_rewrite_rule`.

## Break before LLM requests

*Capture → Breakpoints → Before LLM Requests* (or `bpllm *` in the command field) pauses every
request to an LLM API before it goes out, so you can read and edit it. With conditions, only
matching requests pause:

```text
bpllm model=claude tool=mcp__jira__* tokens=50k
```

`model=` the model contains the text, `tool=` the request offers that tool (`*` at the end for
a prefix), `tokens=` at least that many input tokens (estimated); all given must hold. `bpllm`
alone switches it off. The menu item switches between every LLM request and off; with
conditions set, it switches to every LLM request. See
[Setting breakpoints](change-replay.md#setting-breakpoints).

The breakpoint is decided on the request as the agent sent it, before the rules script and
rewrite rules change it, and it wins over the agent cache.

## Agent cache

The agent cache answers a call that was answered before, without asking the model again: an
agent or an app under development that sends the same request twice pays and waits only
once.

- In the **LLM** view of a successful call, check **Cache this answer**. From then on, the
  same request is answered by Quena from the kept answer, streamed answers as recorded.
- *Settings → Bodies & Storage → Agent cache → Cache every LLM call* caches each successful
  call by itself.
- The answer is kept decoded (any client can read it) and without headers that name the
  account or the original request (`set-cookie`, `openai-organization`, `openai-project`,
  `anthropic-organization-id`, request ids). Answers cut off or larger than 16 MB, error
  answers and requests over 4 MB are not cached. At most 2,000 answers or 1 GB are kept; the
  least recently used go first.
- A session answered from the cache shows *Answered by Quena from the agent cache* with the
  tokens, estimated cost and time saved (flag `x-quena-cache`, comment *Agent cache: answer of
  #N*); its tokens and cost are not added up in the columns, the conversation and
  *Statistics*, as nothing was spent.
- The settings list the kept answers with their hits and the total saved, remove single ones
  or all, and name calls of the capture **asked more than once** that are not cached yet,
  with what the repeats cost; *Cache* caches them.

### When two requests are the same

The cache key is made from:

- the method, the URL and its query parameters in sorted order (Gemini's `key=` apart);
- the credentials (`Authorization`, `x-api-key`, `api-key`, `x-goog-api-key`, Gemini's
  `?key=`), kept only as a hash, so another key never gets these answers. For AWS Signature
  V4 only the access key id counts, not the signature, which changes with every request;
- the API version headers `anthropic-version`, `anthropic-beta`, `openai-beta`,
  `openai-organization` and `openai-project`;
- the JSON body, with key order and spacing not counting.

Left out of the body, because they change with every request or run without changing the
question: `user`, `metadata`, Codex's `prompt_cache_key`, every `cache_control` mark, and
Claude Code's attribution block in the system prompt (`x-anthropic-billing-header: …`).
Everything else counts. In particular, Codex's `previous_response_id` still differs from run to
run, and a refreshed OAuth token changes the credential hash.

### Where it sits

Requests pass Quena's rules in this order: mock rules, the rules script, rewrite rules, then
the agent cache. A request a mock rule answers never reaches the cache. The cache looks up the
request **as it goes out**, after the script and rewrite rules, so a rewritten request finds
the answer kept from a rewritten one. A breakpoint on the request (also `bpllm`) wins over the
cache.

The answers are kept in `llm-cache/` in the data directory and stay over restarts. Agents use
`llm_cache_status` and, with full control, `cache_llm_calls` ([Quena's MCP server](mcp.md)).

## Freeze a run for replays

*Freeze for replays…* in a conversation puts its answered turns, and those of the subagents it
started, into the [agent cache](#agent-cache). Turns that cannot be kept (an answer cut off or
too large) are skipped and counted; error answers, variants and answers already from the cache
are left out.

Then run the agent again, after changing a skill, an MCP server or a prompt file. Quena
answers every request that is [the same](#when-two-requests-are-the-same) as one in the
recording without asking the model. Where the new run asks something the recording does not
have, the call goes to the model, and the new conversation shows at which turn it *left the
frozen run*.

Claude Code's attribution block, Codex's `prompt_cache_key`, cache marks and Bedrock's
changing signatures do not count, so runs of Claude Code, Codex and Bedrock can be replayed.
A new run still leaves the recording at the first request that differs in anything else: a
date or the working folder in a reminder, another git status, a refreshed OAuth token, or
Codex's `previous_response_id` once it refers to a response of the new run. When the very
first request differs, the new run gets no answer from the recording at all.

## Compare two runs

*Compare with* in a conversation sets it side by side with another one: an A/B test of a
prompt, a skill, a model or an MCP server. For each side, with the difference coloured by
which way is better:

- turns, input and output tokens, cached share, cost, duration, the size of the last request,
  cache misses, errors and hints;
- what filled the last request, by category;
- the tool calls, by tool.
