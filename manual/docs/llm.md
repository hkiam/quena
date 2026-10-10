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

## AI agents

Over [MCP](mcp.md), `get_llm_call` returns a call taken apart the same way; the session
rows carry `llm` and `tokens`. Unless agents may see secrets, the bodies are redacted first
(credentials and secret fields), as for `get_session`.
