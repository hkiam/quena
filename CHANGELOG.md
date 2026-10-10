# Changelog

All notable changes to Quena are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Quena uses
[Semantic Versioning](https://semver.org/). While the major version is `0`, any release may
contain breaking changes (settings, file formats, plugin API).

## [Unreleased]

## [0.2.0] — 2026-10-10

### Highlights
- **See what your AI agents do.** LLM traffic of OpenAI, Anthropic, Gemini, Vertex AI,
  Amazon Bedrock, Ollama and compatible APIs taken apart with tokens and costs; agent runs of
  Claude Code, Codex or your own app put together as conversations, with why the prompt cache
  missed, hints where tokens go to waste and a map of what fills the context; MCP servers
  (also stdio ones through `quena-cli mcp-tap`) with the trail of every tool call; tools and
  skills across runs; prompt playground, LLM rewrite operations, an LLM breakpoint, the agent
  cache with frozen runs, A/B comparison and export. *Start Agent…* runs an agent through Quena.
- **Reverse proxy, SOCKS and transparent ports** for clients that cannot use a proxy, also
  headless as `quena-cli reverse`; **host remapping**; *Do not capture* for hosts that must
  bypass Quena.
- **Compare captures** and groups of sessions (app, `quena-cli diff`, MCP).
- **Rewrite rules with an editor**, groups, templates, applied to captured sessions and to
  WebSocket messages.
- **Snapshot library**, **AutoSave** and **password-protected archives**.
- **Your company's CA**, the CA exported with its key, and warnings for expiring server
  certificates.
- **gRPC with a schema** (`.proto` files or server reflection), MessagePack and Socket.IO views.
- A **software bill of materials** (CycloneDX) for every release.

### Added

#### AI agents and LLM traffic
- **LLM traffic**: calls to OpenAI (Chat Completions, Responses), Anthropic Messages, Google
  Gemini, **Claude on Vertex AI** (`rawPredict`), **Amazon Bedrock** (Claude through `invoke`,
  streamed in AWS's binary event stream, and the **Converse API**), Ollama and
  OpenAI-compatible APIs are recognised; only bodies shaped like such a call count, so other
  apps' `/api/chat` or `/responses` endpoints are left alone.
  - The **LLM** view shows provider and model, system prompt, the messages with tool calls and
    results (also Codex `developer`, `custom_tool_call` and `local_shell_call` items, images in
    tool results), the answer assembled from server-sent events, JSON lines, arrays or AWS
    event streams, stop reason, errors (also AWS stream exceptions), token usage (cache,
    reasoning) and an estimated cost. Claude Code's attribution block is shown apart from the
    system prompt.
  - **Prices**: built-in list prices (e.g. Claude Opus 4.5, Sonnet 4.5, GPT-5.1, GPT-5 Codex, o3-pro), own
    ones and context windows in `llm-prices.json` (reported when it is not valid JSON), and
    *Fetch prices* (*Settings → Bodies & Storage → LLM prices*) downloads LiteLLM's list of
    several hundred models on request. Bedrock model ids like
    `us.anthropic.claude-sonnet-4-5-20250929-v1:0` are priced.
  - Finished calls get flags; columns *LLM*, *Tokens*, *Cost*, *Group by → LLM model*,
    filter fields `llm` and `tokens`, per-model totals in *Statistics*. MCP: `get_llm_call`.
- **Agent conversations** (right pane → *Agents*, also *View → Agents*): the LLM calls of one
  agent run — Claude Code, Codex, an app — put together as a conversation, subagents under the
  conversation whose tool call started them. Each call is linked to the call it continues
  (Claude Code's previous request, `previous_response_id`, else the furthest common history
  within the agent's session), so separate runs with the same prompt stay apart and side
  calls (prompt suggestions, summaries) are marked instead of breaking the turn order.
  - Turns on a time axis with input, cached share, output, cost, the change from the call it
    continues (`+2 messages`, `message 12 changed`, system prompt, tools, settings, model), the
    tools called, the time to the response headers, tokens per second of streamed answers,
    refused calls (429/529/503), retries and the rate limits the provider reports.
  - **Why the prompt cache missed**: an earlier message, the system prompt, tools or settings
    changed, another model, the cache expired (5 minutes, 1 hour, OpenAI's 24 hours), no
    `cache_control` mark, too short to be cached.
  - **Hints** where tokens go to waste: the same tool result several times, large results,
    repeated calls, recurring reminders, tools never called, a context near the window, cache
    misses, refused calls and little rate limit left — with the tokens they cost.
  - **What fills the context** as a map: system prompt, each tool definition,
    CLAUDE.md/AGENTS.md, skills list, reminders, environment, messages, thinking, tool calls
    and results by tool, images — estimated and scaled to the reported input tokens. The LLM
    view shows the same for one call under *Context*.
  - Flag `x-quena-llm-conv`: column *Conversation*, *Group by → Conversation (agent run)*,
    filter `conv`. LLM calls in archives from other tools are found by their URL and flagged.
  - **Agent** column, *Group by → Agent* and filter `agent`: the agent or SDK that sent an LLM
    or MCP request, from its User-Agent (Claude Code, Codex, Gemini CLI, Cursor, GitHub
    Copilot, Cline, aider, the OpenAI/Anthropic SDKs …; flag `x-quena-agent`).
  - **Export** a conversation as Markdown (each turn with what it added and the answer), JSON
    lines (one call per line with the messages it added, for evaluations) or OpenTelemetry
    GenAI spans (OTLP JSON, counts and models, no content).
- **MCP servers** (Model Context Protocol): exchanges over Streamable HTTP and the older SSE
  transport are recognised and shown in a new **MCP** view — method, server name and version,
  protocol and session; for `tools/call` the arguments, the result (text, images, resources,
  structured content), failures and the tokens the result adds to the agent's next request;
  `tools/list` with the tokens of each tool definition; all JSON-RPC messages, also batches
  and results sent on the older transport's stream.
  - The **tool call trail** links the LLM call that asked for a tool, the MCP exchange that
    ran it and the LLM call that carries the result back (also from the LLM view's answer).
  - Flags `x-quena-mcp` and `x-quena-mcp-server`; columns *MCP* and *MCP server*, *Group by →
    MCP server*, filters `mcp` and `mcpserver`.
- **`quena-cli mcp-tap --name NAME -- COMMAND …`** records MCP servers that talk over stdio:
  it passes everything through and writes the exchanges to Quena's data folder (`--data-dir`
  for a portable app; files only for the user, at most 1 GB each, removed after a week
  without exchanges), where the app picks them up while capturing (`stdio://NAME/tools/call`).
  The server runs even when recording fails; signals are passed on to it; on Windows `.cmd`
  launchers such as `npx` work; requests never answered are recorded too.
- **Tools & skills** (*Agents → Tools & skills*): every tool across the conversations with
  the requests that offer it, what its definition costs, model calls, MCP exchanges, failures
  and result sizes, tools never called; every skill with where it is listed and how often it
  was loaded (Skill tool or `SKILL.md`).
- **Optimising agents**:
  - *Try a variant…* (LLM view) sends a call again with another system prompt, fewer tools,
    another model or output limit, after a confirmation and with the original's headers, and
    shows answer and tokens next to the original's. Variants bypass the agent cache and
    rewrite rules and count as side calls; requests signed with AWS Signature V4 are refused
    with the reason.
  - Rewrite rules **LLM: remove tool** (`mcp__jira__*` for all of a server), **LLM: set
    model** and **LLM: add to system prompt**, in the format of the API known from the URL
    (Anthropic, OpenAI Chat and Responses, Gemini, Bedrock Converse, Ollama; the model in the
    URL for Gemini, Vertex AI and Bedrock); a tool choice naming a removed tool is removed as
    well; signed Bedrock requests are left unchanged. Also over MCP (`llmRemoveTool`,
    `llmSetModel`, `llmAppendSystem`).
  - **Break before LLM requests**: *Capture → Breakpoints → Before LLM Requests*, or `bpllm`
    with conditions (`model=claude tool=mcp__jira__* tokens=50k`).
  - **Agent cache**: an LLM API call answered before is answered by Quena again without asking
    the model. The key leaves out what changes with every request (key order, `user`,
    `metadata`, Claude Code's attribution block, `prompt_cache_key`, cache marks, AWS
    signatures) and is taken from the request as it goes out after rewrite rules. Cache a call
    in the *LLM* view or every call (*Settings → Bodies & Storage → Agent cache*); hits show
    the tokens, cost and time saved and spend nothing in the totals. Mock rules come first.
    MCP: `llm_cache_status`, `cache_llm_calls`.
  - *Freeze for replays…* puts a conversation's answered turns and those of its subagents into
    the agent cache and shows where a new run left the recording.
  - *Compare with* sets two conversations side by side (turns, tokens, cached share, cost,
    duration, last request, cache misses, errors, hints, context by category, tool calls by
    tool) with the differences coloured by which way is better.
- **Start Agent…** (*Capture* menu and the globe button: *Start Claude Code*, *Start Codex*,
  or any command): runs an AI agent in a terminal that uses Quena (proxy,
  `NODE_EXTRA_CA_CERTS`, `CODEX_CA_CERTIFICATE`), in an interactive login shell so what the
  shell profile adds to PATH is found.
- **Quena's MCP server for agents**: the diagnostics as tools (`run_diagnostics`,
  `get_diagnostics_report`; findings with evidence and session ids), the agent runs
  (`list_conversations`, `get_conversation` with `limit`/`offset`, `get_context`,
  `get_tool_report`; prompts redacted like bodies), MCP prompts (`debug_failures`,
  `analyze_performance`, `explain_session`, `llm_costs`, `mock_endpoint`), *Set up for*
  Claude Code, VS Code, Cursor or Codex in one click (the server with its token added to the
  user configuration, a copy of the file kept), and an agent skill
  `quena-traffic-debugging` for Claude Code and Codex.

#### Capture and connections
- **Reverse proxy ports for clients that cannot use a proxy** (*Capture → Reverse Proxy…*).
  Each entry listens on a local port while capturing and forwards every request to one target
  (`http(s)://host[:port][/base path]`): backends with a fixed API URL, containers, test
  suites, webhook senders, gRPC. Breakpoints, Mock Rules, rewrite rules and scripts apply.
  - The port accepts HTTPS (certificates from the Quena root certificate), plain HTTP and
    cleartext HTTP/2 (h2c) on one port; it refuses `CONNECT`, so it never becomes an open
    proxy, and a target that is Quena itself is refused.
  - Options per entry: keep the client's `Host`, point `Location` redirects back to the port,
    drop cookie domains, add `X-Forwarded-*` headers; remote computers only when allowed.
  - **Path routes** send some paths of a port to other targets (`/auth` to the login server,
    `/api` to the backend); the longest prefix wins and can be removed from the path.
  - The *Via* column, *Group by → Via* and the filter `via == name` show which entry a
    request came through; *Reverse Proxy for this Host…* in the session menu; MCP tools.
- **SOCKS5/4 port and transparent port** (*Settings → Connections*, off by default): SOCKS5
  (with or without a password) and SOCKS4/4a clients name their target; connections a
  firewall redirects (iptables, pf) need no client setting. Both are handled like `CONNECT`
  tunnels; the manual shows the firewall rules for Linux and macOS.
- **Host remapping** (*Capture → Host Remapping…*): connections to a host or `*.domain` go to
  another host, IP address or port, like a hosts-file entry but only for traffic through
  Quena — by default keeping `Host` and TLS name, optionally with a port in the pattern and a
  forced protocol. Entries can be imported from the hosts file; sessions are marked
  (`x-quena-remap`); also `quena-cli reverse --remap` and MCP.
- **Do not capture (bypass Quena)** (*Settings → Connections*, or *Filter Now → Do not capture
  this Host…*): hosts become exceptions of the system proxy and of started browsers and
  terminals, and pass Quena undecrypted if a client sends them anyway; optionally the DNS
  domains of an active VPN.
- **Start a browser or a terminal that uses Quena**, without changing the system proxy (the
  globe button, *Capture → Start Browser…*, *Capture → Open Terminal*): Chromium browsers
  with their own profile that accepts Quena's certificates, Firefox with its own profile; the
  terminal sets `HTTP(S)_PROXY`, `NO_PROXY` and the root certificate for Node.js, Python,
  curl, Git, pip, Cargo and the AWS CLI. MCP: `launch_browser`, `open_terminal`.
- **`quena-cli reverse`** (also `quena-cli serve`) runs the reverse proxy without a window,
  e.g. in CI or as a Docker sidecar, with `--path`, `--socks`, `--transparent`, `--decrypt`,
  `--duration`, `--max-sessions`, `--save run.saz|.har` and `--ca-dir`/`--ca-p12`.

#### Inspect
- **gRPC and Protobuf with a schema**: with `.proto` files (*Settings → Bodies & Storage →
  Protobuf schemas*) the *gRPC* view shows field names, types, enum values and nested
  messages; **server reflection** (off by default) fetches the schema from the server.
  Messages are uncompressed per `grpc-encoding`; gRPC-Web trailers and `grpc-web-text` are read.
- **MessagePack view** for `application/msgpack` and its variants.
- **Socket.IO**: the WebSocket view shows event names and arguments, hides ping/pong and
  searches events; a *Socket.IO* view decodes long-polling bodies (v4 and v3).
- *Statistics* show median, mean, p90/p95/p99, standard deviation, throughput, header bytes
  and summed DNS, connect, TLS and waiting times; a **Params** view lists the query
  parameters; **Decode Value…** opens the *Text Tools* with the likely decoding; the *Auth*
  view decodes **SAML** requests and responses.

#### Change and replay
- **Rewrite rules have an editor** in the Mock Rules tab with fields per operation, checks
  before saving and a preview on the selected session; rules can be sorted, cloned and put
  into **groups**, exported and imported as JSON. New operations set or remove query
  parameters and cookies and mark or comment the session; **From template ▾** adds *Bypass
  CORS*, *Block cookies*, *Disable caching*, *Change User-Agent*, *Mark errors red*, *Block a
  host* and *Allow only one host*.
- **Apply Rewrite Rules…** to captured sessions: each changed session gets a changed copy,
  nothing is sent. MCP: `apply_rewrite_rules`.
- **Change WebSocket messages on the way**: rewrite rules for WebSocket messages (direction,
  JSON also inside Socket.IO packets) and `onWebSocketMessage(msg)` in rules scripts; changed
  and dropped messages are marked in the frame log.
- **Composer**: request **tabs**, query parameters and headers as **tables**, **Follow
  redirects**, method `QUERY`, the **HTTP version** per request (automatic, HTTP/1.1, HTTP/2,
  also h2c), and **collections** saved as `.http` files (JetBrains/VS Code format) with
  variables, environments, *Run all* and import. MCP: `list_collections`,
  `collection:NAME` in `run_http_file`.
- **Advanced Replay** sends up to 100,000 repeats one after the other or 1–100 at a time and
  can be stopped (MCP `replay_sessions` takes `parallel`).

#### Filters, columns and comparing
- Filter on request and response headers (`reqheader.NAME`, `resheader.NAME`,
  `header.NAME`), cookies (`cookie.NAME`), bodies (`reqbody`, `resbody`), TLS version
  (`tls`), server IP (`ip`) and HTTP version (`http`). **Saved filters** with match counts,
  **column filters** from the heading's menu, new columns *TLS*, *Server IP*, *HTTP version*
  and up to three **header columns**.
- **Compare captures** (*Tools → Compare Captures…*): the live capture and loaded archives
  side by side, requests paired by method, host and normalised path (content hashes in file
  names ignored, optionally without the host) and marked new, gone or changed; requests that
  now fail or get no answer are counted apart. **Compare Groups** pairs chosen sessions by
  path, exact URL or order with own headers to ignore. Headless: `quena-cli diff before after
  --fail-on errors|changes --pair-by --ignore-header --ignore-host`. MCP: `compare_captures`.

#### Archives
- **Snapshot library** (*File → Snapshot Library…*): archives in folders of the data folder,
  opened as a **source** of their own (*Group by → Source*), so a snapshot can be looked at
  while capturing goes on.
- **AutoSave** (*Settings → General*): all sessions (or only those the filters show) saved
  as `.saz` every few minutes when something changed; the newest are kept.
- **Password-protected archives** (AES-256, readable by Fiddler, 7-Zip, WinZip): exported
  with *SAZ Archive with Password…*, asked for when loading.
- Export as a **WCAT** load test script; import of Internet Explorer **NetXML** captures.

#### Certificates
- **Use an existing CA** (*Capture → HTTPS Settings… → Import CA…*), e.g. the company's
  interception CA: a PKCS#12 file or a PEM certificate with its key; Quena checks it and keeps
  the previous CA's files. An intermediate CA sends its chain along.
- **Export the CA with its key** as a password-protected `.p12`.
- **Expiring server certificates** are flagged `x-quena-cert` (within 30 days by default);
  column *Cert. until*, filter `certdays`, subject, issuer and validity in *Properties*.
- On Windows, *Trust for all users…* puts the root certificate into the local machine's store.

#### Supply chain
- **Software bill of materials (SBOM) for every release**: a CycloneDX SBOM per platform for
  the app and `quena-cli` (Rust crates, npm packages, bundled plugins) as release assets and
  inside the packages; the Docker image carries an SBOM and provenance attestation.

### Changed
- Apple services that pin their certificates bypass Quena by default (*Do not capture*), so
  they keep working while the system proxy points to Quena.

### Fixed
- Loading a password-protected archive loaded no sessions and gave no reason; it now asks
  for the password.
- The command field's answers (`filter`, `=404`, errors such as an unknown command) are shown
  in the UI language; an unknown command points to `filter EXPRESSION`.
- The loop guard took a server for Quena itself when it listened on the same port number at
  another address (`127.0.0.1:P` while Quena listened on `[::1]:P`), and kept the ports of a
  stopped proxy engine.
- Hiding the navigator right after choosing a group could leave the list narrowed to it.
- A session that just finished could briefly not be found (its details vanished for a moment
  between recording and storage).

## [0.1.7] — 2026-10-07

### Changed
- **Loading an archive or packet capture no longer mixes it with live traffic.** Capturing
  stops, and when the list already holds sessions, Quena asks whether to remove them (only
  the import is in the list afterwards) or keep them and add the import. *Don't ask again*
  remembers the answer; *Settings → General → Importing into a non-empty list* changes it.
  This applies to the File menu, *Load Archive…*, drag and drop and *Open With*; a sanitized
  copy opened after the export is still added next to the original.

### Added
- **Packet captures from Wireshark and tcpdump can be loaded** (`.pcap`, `.pcapng`):
  *File → Import Sessions → Packet Capture (pcap, pcapng)…*, *File → Load Archive…*, drag and
  drop, or `quena-cli`. Quena puts the TCP connections back together, including packets that
  arrive out of order or twice. Plain HTTP/1.x (keep-alive, pipelining, chunked bodies),
  WebSocket messages and cleartext HTTP/2 (h2c, gRPC) become sessions, with the client and
  server address and timings from the packet times. Where packets are missing from the capture
  (lost, or cut short by the snapshot length), the affected session says so in its error,
  and the requests and responses after it still pair up correctly.
- **HTTPS in packet captures is decrypted with a TLS key log** (`SSLKEYLOGFILE`, as written by
  browsers, curl and many apps): TLS 1.3 and TLS 1.2 with AES-GCM, ChaCha20-Poly1305 and
  AES-CBC, with HTTP/1.x, WebSocket and HTTP/2 inside. The secrets come from pcapng files
  that carry them (`editcap --inject-secrets`), a key log next to the capture (`name.keys`,
  `sslkeylog.log`), *Settings → HTTPS → Packet captures*, or, after an import that left
  connections encrypted, *Choose key log file…* in the status bar, which loads the capture
  again in place of the first import. `quena-cli` takes `--tls-keylog`. Connections without
  secrets show up as tunnels with their server name (SNI), ALPN, TLS version and cipher, also
  behind a `CONNECT` to a proxy. The new manual page *Packet captures* describes recording,
  loading, decryption and how missing packets are handled.

## [0.1.6] — 2026-10-07

### Fixed
- **Windows: intranet and VPN hosts are recorded.** While capturing, Quena no longer turns on
  *Don't use the proxy server for local (intranet) addresses*, which let requests to hosts
  without a dot (`http://appserver/`) pass Quena unseen, and no longer adds the macOS
  exceptions `*.local` and `169.254.*` to the Windows proxy settings. Hosts that the
  previous system proxy's exceptions sent direct still go direct from Quena, not through
  the upstream proxy; *Bypass upstream for* now also understands `<local>` and networks
  such as `10.0.0.0/8` or `169.254/16`.
- **Quena no longer quits without a word when it cannot start.** A portable copy on a
  read-only drive (write-protected stick, CD, read-only share) now says that its
  `quena-data` folder beside the program cannot be written and what to do; other start
  errors are shown in a system dialog too. Starting a second Quena with the same data
  folder now says that Quena is already running.

## [0.1.5] — 2026-10-03

### Changed
- **Inspector views in two levels**: each request and response card first offers the
  sections *Headers*, *Body*, *Cookies*, *Auth* and *Raw* (with the number of headers and
  cookies, and a dot for authentication), then, below them, only the body views that fit
  the content, the best one first. For example, *Formatted · Tree · Plain Text* for JSON and
  *SOAP · Formatted · Tree · Plain Text* for SOAP. Views that do not fit stay reachable under
  *Other*. `Alt 1`…`Alt 5` pick the section, `Alt ←/→` the view. The single row of all views
  is still available: *Settings → General → Inspector views → Flat*.
- **New installations start in the Quena layout with the request above the response**; the
  layout choice on first start is gone. *Settings → General → Layout* and
  *View → Request Beside Response* still switch. Existing layouts are kept.

- **No browser menu on right-click any more** (Reload, Inspect Element …). Text fields and
  editors get an Edit menu (Undo, Redo, Cut, Copy, Paste, Select All), selected text a Copy
  menu, and places without a sensible menu none. In release builds the developer tools are
  off, and on Windows WebView2's own menus too (this also covers the HTML preview). The
  *Developer* menu (mock data, Reload UI) is only in debug builds; *Performance Overlay*
  moved to *View*.

- **Context menus in the inspector**: copy header values, table rows, JSON values with their
  JSONPath, XML elements with their XPath, WebSocket messages and SSE events; copy or save
  bodies and multipart parts; expand or collapse trees. From the JSON tree a value can be
  changed or removed, or a broken element appended to a list, in later messages of the
  same URL (a rewrite rule).
- **More context menus**: below the sessions (open archive, save all, select all, remove
  all), on timeline rows (inspect, copy URL, remove from the timeline, the selection's menu),
  on navigator entries (show only, select their sessions), on diagnostic findings
  (select affected sessions, copy), log lines and statistics.

- **Navigator** left of the session list (off by default; toolbar button, *View → Navigator*,
  `Ctrl/⌘ Alt N`): the groups of the sessions (connection, host, process, trace id,
  session cookie, Custom) or the host/path structure, with counts and errors. A click
  narrows the list to that group or path, on top of the filters; a bar above the list
  shows it and brings everything back. *Structure* moved from the right pane into the
  navigator; there a click now narrows the list instead of selecting (right-click →
  *Select These Sessions*). It opens with the structure until the list is grouped; while
  it is open, the list's Group column starts narrower.
- README and manual screenshots retaken with the new defaults, plus one of the navigator.

### Fixed
- A plain XML document sent as `text/xml` or `application/xml` no longer opens in the SOAP
  view, and is no longer offered the SOAP and Atom/OData views. Quena now checks the root
  element of the decoded body (SOAP envelope, Atom feed or entry, OData metadata) instead
  of trusting the content type. JSON and XML with a wrong or missing content type get the
  matching views.
- The session count of a list group no longer overlaps the group's name.
- A saved layout without a preset (e.g. only a theme set by hand) opened with the Classic
  columns; it now gets the Quena layout.

## [0.1.4] — 2026-10-02

### Added
- **MCP server for AI agents** (*Options → AI agents (MCP)*): Claude Code and other MCP
  clients connect over Streamable HTTP on `127.0.0.1` with a bearer token. They list,
  search and read sessions and bodies (decoded, paged, size-limited), and see statistics,
  mock rules and breakpoints. With *full control* they also start and stop capturing,
  remove sessions, send and replay requests, edit mock rules, set breakpoints, release
  paused sessions and export archives. The server is off by default, runs apart from the
  proxy and rejects other `Host`/`Origin` names (DNS rebinding). Captured credentials,
  tokens and secret values are replaced before an agent sees them (unless allowed), and
  agents read and write files only in one folder (*Folder for agent files*).
- **Rewrite rules**: change real requests and responses on their way — JSON values by
  JSONPath (set, remove, append; *append to every list*, with a broken copy of the first
  element by default), regex replacements, headers and status, filtered by match pattern,
  status and content type. Set up by agents over MCP (with a dry run on a captured session)
  and listed in the Mock Rules tab; the status bar shows when they are active. Without
  rules the forwarding path is unchanged; header and status changes never hold a body
  back; body changes hold back only matching bodies (JSON by default) up to 4 MB
  (at most 16 MB; 256 MB for all held-back bodies together) and 30 s and otherwise
  forward them unchanged as they stream, decode gzip/br/zstd, keep
  charset and JSON key order, and leave event streams, JSON lines, partial content and
  binary bodies alone.
- **Grouping in the session list** (*Group by* in the heading's context menu and the command
  palette): by client connection (keep-alive, HTTP/2), host, process, trace or correlation
  id (`traceparent`, B3, Jaeger, X-Ray, `X-Correlation-ID` …), session cookie (shown as name
  and hash, never the value) or the Custom column. Groups keep the order of their first
  session and are sorted inside by the chosen column; they can be collapsed and expanded
  (click ▾/▸, `←`/`→`, all at once) and selected as a whole; live traffic joins its group.
  New filter fields `conn`, `trace` and `session`. Connection ids no longer start at 1 on
  every run, so a recovered capture and new traffic never share one.
- **Request collections (`.http`)** in the format of the JetBrains HTTP Client and the VS
  Code REST Client: file variables, environments from `http-client.env.json` and
  `http-client.private.env.json` (with `$shared`), dynamic values (`$uuid`, `$timestamp`,
  `$randomInt`, `$processEnv` …) and file bodies. Agents list and run them over MCP and
  write captured sessions as a collection; `quena-cli http run` runs them headless (exit
  code 1 on failures, `--save` for a HAR/SAZ of the run), `quena-cli http from-har` writes
  one from captures. The requests appear in the capture, and rules apply.

### Fixed
- **Automatic authentication no longer hangs for a minute over a VPN**: with a Kerberos
  ticket but no reachable KDC, Negotiate blocked each request until the library gave up.
  Now each step of the Kerberos/SSPI library is cut off after 5 s (Quena falls back to the
  next scheme and skips Negotiate for that host for 10 minutes), and IP addresses and
  `localhost` never try Kerberos.

### Changed
- Buffering a message for a body rule no longer shows it as paused at a breakpoint.
- JSON written by `quena-cli` (sanitized archives, mocks) keeps the key order of
  the source instead of sorting keys, as the app already did.

## [0.1.3] — 2026-10-01

### Added
- **Sanitized export for sharing** (*File → Export Sessions → Sanitized for Sharing*): a
  SAZ/HAR copy for vendors or support. The *Support* preset replaces credentials, tokens,
  secret URL parameters, secret body fields, e-mail addresses, IBANs and card numbers (check
  digits); *GDPR strict* also replaces phone numbers, IP addresses, personal fields, tax and
  social security numbers and process names, and cuts bodies. Deterministic and local (no
  AI), structure-preserving for JSON, forms, multipart, XML, HTML, SSE and WebSocket
  messages, stable pseudonyms (`<email-3>`), bodies keep/cut/placeholder, own names and
  patterns; a redaction log is shown and stored in the archive (`QUENA-REDACTION.txt`, HAR
  `log.comment`). Names are read as words (`apiKey`, `X-Api-Key`, `otpCode` are secrets,
  `passenger` or `token_type` are not; weak names like `key`/`code` only with a
  credential-like value); YAML, JavaScript, CSS, GraphQL and other text is scanned for
  `name: value` pairs, credentials and URLs; compressed and fragmented WebSocket messages,
  path tokens, signed-URL parameters and user headers are covered; hosts stay, IP literals
  go with the IP option. From the session list's context menu it exports the right-clicked
  sessions, even a single one; the dialog shows the scope and switches between the
  selection and all sessions, checks own patterns before the file is chosen (an error
  keeps the entries), and never replaces another open dialog with the redaction log (the
  status bar offers *Show redaction log* instead).
- **Mocks from a capture** (*Mocks from Sessions…*, *Create from sessions…* in Mock Rules,
  the command palette; *File → Export Sessions → Mocks…* starts with the package): recorded
  sessions become Mock Rules at once, a shareable `.quena-mocks` package (import in Mock
  Rules, also by drag and drop), or a WireMock export (mappings, `__files`, scenarios for
  sequences). Options for hosts, static resources, ignored query parameters, responses in
  recorded order, body matching, latency, preflights, error responses and sanitizing.
  Package chips show the hosts and offer *Reset sequences*; package names are lower case.
  An imported package may only answer from its own files or with `*<status>`, `*delay:` (at
  most 60 s), `*drop`, `*reset` and `*CORSPreflightAllow`, and each rule must be limited to
  a host; other rules are left out and counted. A WireMock folder export replaces its
  `mappings/`, `__files/` and `README.md` (no stale mappings); ZIPs and packages are written
  atomically. `204`/`304` mocks carry no body.
- Mock Rules match request bodies as JSON (`BODYJSON:`), GraphQL operations (`GRAPHQL:`,
  optionally by `queryHash`) and by SHA-256 (`BODYHASH:`); `URLWithBody:` compares the
  decoded body. `.farx` export leaves out *match once* chains (with a note in the file).
- `quena-cli sanitize` and `quena-cli mock`: config files are read strictly (unknown keys
  are named, exit 2; `sanitize --config` also takes the app's saved options), no output may
  overwrite a capture or another output, `--package` must end in `.quena-mocks`, a
  `--wiremock` folder may not be an existing file, and `--timeout` also covers sanitizing
  and building the mocks (exit 3).
- **Diagnostics in CI**: `quena-cli`, a command line program without a window, runs the
  diagnostics on HAR/SAZ files (e.g. recorded by Playwright or Cypress tests) and turns the
  report into a quality gate: `--fail-on`, comparison with a `--baseline` report (only new or
  more severe findings count), metric budgets (`--budget requests=+10%`), `--ignore`, a
  settings file, output as Markdown, JSON, JUnit XML and GitHub annotations, exit codes for
  CI. Ships as archives for Windows, macOS and Linux (x64/arm64), as a GitHub Action
  (`hkiam/quena/diagnose`) and as a Docker image (`ghcr.io/hkiam/quena-cli`); examples for
  Playwright and Cypress, manual page *Diagnostics in CI*.
- *Diagnostics*: OAuth 2.0 / OpenID Connect rules (`OAUTH-ERROR`, `OAUTH-FLOW`,
  `TOKEN-EXPIRED`, `TOKEN-NOTYET`, `TOKEN-AUDIENCE`, `TOKEN-SCOPE`, `TOKEN-SIZE`,
  `TOKEN-IN-URL`, `TOKEN-REFRESH`, `OIDC-LOOP`, `OIDC-SILENT`, `OIDC-DISCOVERY`). A built-in
  knowledge base recognises Microsoft Entra ID (incl. B2C and External ID), Keycloak, Okta,
  Auth0, Amazon Cognito, Google, AD FS, Duende IdentityServer and PingFederate, explains
  their error codes (e.g. AADSTS50011, Keycloak's “Session not active”) and names the place
  in the admin UI where the cause is fixed — in English and German.
- Analyzer plugins receive authentication facts: the non-secret claims of JWTs sent as
  bearer tokens, the parameters of OAuth authorization and token requests, OAuth error
  responses and OpenID discovery documents (`auth` in the analyzer contract). Secrets,
  signatures and personal claims never leave the host.

### Changed
- *Diagnostics*: repeated token requests are reported as `TOKEN-REFRESH` (previously part of
  `AUTH-REPEAT`); sign-in loops, OAuth errors and the requests of a sign-in loop are no longer
  repeated as `REDIRECT`, `AUTH-FAIL`, `ERR-HTTP` or `DUP-EXACT`; `AUTH-FAIL` shows the
  `WWW-Authenticate` error of an API.
- Redaction for analyzer plugins keeps the non-secret OAuth parameters of URLs
  (`client_id`, `response_type`, `scope`, `prompt` …; `redirect_uri` without query and user
  info) and the `error`, `error_description`, `realm` and `scope` values of
  `WWW-Authenticate`; `code_challenge`, `code_verifier` and `login_hint` are now redacted.
- *Timeline*: long pauses without traffic (e.g. sessions of two captures a day apart) are
  collapsed to a narrow break labelled with their length, and every block of traffic starts
  with its clock time; *Collapse pauses* switches back to the real scale. Axis labels never
  overlap.
- *Timeline*: a time axis with grid lines; zoom with Ctrl/⌘ + wheel (or pinch) around the
  pointer, or with the zoom buttons and *Fit*; columns (#, method, status, URL, duration,
  size, graph) can be moved, resized and shown or hidden (right-click the header), and the
  columns left of the graph stay in place while it scrolls; scrollbars appear when needed.
  A click focuses a session without changing the selection, a double-click opens it in
  *Inspect*.
- Removing sessions (Del / Backspace, Shift+Del, Ctrl+X, toolbar, menus) asks for
  confirmation first; Enter confirms, Esc cancels.

### Fixed
- Mock Rules: `METHOD:` combined with `URLWithBody:` never matched, because the request body
  was not buffered for the inner pattern.
- *Timeline*: the session that ends last was cut off at the right edge, and long time spans
  were labelled in thousands of seconds; the axis now uses clock units (ms, s, min, h, d) and
  shows the date when the sessions span more than a day.
- Removed sessions stayed in the list (the status bar showed “4 of 3 sessions”) until
  something else changed it, so Del seemed to do nothing.

## [0.1.2] — 2026-09-30

Diagnostics, a German user interface and correct character encodings everywhere — plus the
fixes of a thorough review (including a security fix for *Copy as PowerShell/cURL*).
Packages are still not signed with a paid certificate (see the notes for 0.1.0).
- **Diagnostics** turns a capture into a short list of prioritised findings with evidence:
  performance, duplicates and N+1, errors and authentication, character encodings, clocks,
  and how sensitive each operation is to slow networks.
- **German** user interface, including the menus (*Settings → General → Language*).
- **Character encodings**: every view shows bodies in their real charset, with an override.
- **Map Remote / Map Local**, drag & drop of archives, a timing waterfall, a host/path tree,
  a theme choice, and a user manual.
- macOS: one universal `.dmg`; Windows: installer (`.exe` / `.msi`) or the portable
  `Quena_0.1.2_x64-portable.zip`; Linux: `.deb`, `.rpm` and AppImage for x86_64 and arm64.

### Added
- Character encodings: every text view decodes bodies in their real charset (BOM, then the
  `Content-Type` charset, then `<?xml encoding>` / HTML `<meta>`, then the type's default) and
  shows it ("windows-1252 · header") with a menu to view the body in another charset. UTF-16
  bodies are formatted too; multipart parts and form data use their own charset; RFC 8187
  `filename*=` parameters are shown decoded.
- Diagnostics finds encoding problems: a declared charset that does not match the bytes
  (“Grüße” → “Gr��e” or “GrÃ¼ÃŸe”), header, BOM and document declaration that disagree, text
  without any charset, double-encoded UTF-8, characters already lost (`�`), JSON not in UTF-8,
  unknown charset names, NUL bytes in text, and compressed data without (or with a broken)
  `Content-Encoding`.
- Diagnostics finds clock problems from the `Date` header: a server whose clock differs from
  this computer (critical from 5 minutes, Kerberos' tolerance), this computer's own clock
  being off (several unrelated sites agree), and servers behind one name with different
  clocks.
- **Diagnostics** (View → Diagnostics, bundled plugin *webdiag*): turns a capture into a short
  list of prioritised findings with evidence instead of thousands of sessions — slow requests
  and server time, large and uncompressed transfers, exact and semantic duplicates (OData
  aware), N+1 and polling patterns, retries and double submits, HTTP errors and connection
  failures, authentication loops and repeated NTLM/Kerberos handshakes, redirect chains, cookie
  and caching problems, connection reuse, old TLS, CORS preflights, unbounded OData queries,
  and how sensitive each operation is to latency and bandwidth (estimates per network
  profile, clearly marked). Profiles: full, performance, troubleshooting, authentication,
  network resilience, modernization. Scope: visible or selected sessions, narrowed to
  processes or target hosts; mixed traffic of several applications is pointed out. Findings
  select their sessions with one click. Reports save as JSON or Markdown, copy as a prompt for
  an AI assistant (redacted), and compare with a saved report. Everything runs locally; tokens
  and cookie values never reach the plugin.
- Plugin API: *analyzer* plugins analyse a whole capture (contract in
  `plugins/webdiag/REPORT.md`).
- Inspectors remember the chosen view per kind of content, separately for request and
  response (e.g. SOAP → XML, JSON → Body, Fast Infoset → its plugin view). Until a view was
  chosen, the one that fits the content opens (SOAP, gRPC, WebSocket, images, form data …).
  On by default; *Settings → General → Inspector views* turns it off or forgets the choices.
- JWT plugin: decodes JSON Web Tokens in `Authorization`/`Proxy-Authorization` (Bearer, DPoP),
  cookies, `Set-Cookie` and common token headers: header (alg, typ, kid …), claims with the
  registered ones explained, `exp`/`nbf`/`iat` as dates with "expired 3 h ago" / "valid for
  12 min", and the signature algorithm (not verified). Encrypted tokens (JWE) show their header.
  Shown in the *Auth* view next to Kerberos/NTLM (no extra tab); the Auth view now also lists
  tokens a plugin recognises in cookies and token headers.
- GraphQL plugin: requests (`application/graphql` or JSON with `query`/`variables`/
  `operationName`, batches, persisted queries) with the operation and the query pretty-printed,
  and GraphQL JSON responses with the errors first.
- Drop `.saz` or `.har` archives onto the window to load them.
- *Timeline* shows a waterfall: request, DNS, connect, TLS, send, wait (time to first byte)
  and receive per session, with the time of each phase in the tooltip.
- *Structure* tab: the visible sessions as a tree of hosts and paths with counts and errors;
  clicking a host or folder selects its sessions.
- German user interface, including the native menus: *Settings → General → Language* (like
  the system, English, Deutsch). Numbers and sizes follow the language (1.234, 1,5 KB).
- Theme choice in *Settings → General*: like the system, light or dark.
- Slow and large responses stand out in the session list: duration over 1 s / 5 s and body
  size over 1 MB / 10 MB are shown in amber / red.
- *Copy as* fetch (JavaScript), PowerShell (`Invoke-WebRequest`) and Python `requests`, next
  to cURL.
- Map Remote: *Mock Rules → Add mapping… → Map Remote* forwards everything under a URL
  prefix to another server (`prefix:https://prod…/api/` → `https://staging…/api/`), keeping
  the rest of the path and the query; the session comment names the original URL.
- Map Local: *Add mapping… → Map Local* serves a folder under a URL prefix (`dir:/folder`
  action): `index.html` for folders, Content-Type by extension, a clear 404 for missing files;
  paths that would leave the folder (`..`, encoded `%2e%2e`, symlinks outside) are refused.
- Mock Rules match `prefix:` for URLs that start with a given text.
- User manual at <https://hkiam.github.io/quena/> (MkDocs Material, sources in `manual/`):
  installation, capturing, HTTPS and devices, the session list, inspectors, Mock Rules,
  analysis, archives, scripting, authentication, plugins, settings, shortcuts and
  troubleshooting; built by the *Manual* workflow and published to GitHub Pages.

### Changed
- The right pane's tabs show icons only when their names do not fit the pane.
- The command palette also finds commands by their English names.
- Inspector view tabs show as many views as fit the width; *More* only holds the ones that do
  not fit, and the views are ordered by how well they fit the content.

### Fixed
- Diagnostics and header inspectors (JWT, Kerberos/NTLM) opened right after start said no
  plugin was installed while the plugins were still being compiled; they now show that
  plugins are loading and update when they are ready.
- Umlauts and other non-ASCII characters were shown as `�` in inspector bodies (and in JSON,
  XML, SOAP, multipart, form data, the large-text view) when a body was not UTF-8; search
  did not find them either.
- Composer and breakpoint edits keep the body's charset (unedited bodies are sent byte for
  byte); *Copy as* sends exactly the recorded bytes for bodies that are not UTF-8.
- HAR import: a leftover `Content-Encoding` on a request whose text is already decoded is
  dropped, so it is no longer reported as undecodable.
- *Plugins* dialog: long "Applies to" lists squeezed the other columns to single characters;
  the columns keep their width, the Diagnostics plugin shows what it applies to, and status
  and column titles are translated.
- Inspector view tabs overflowed (and hid the pane titles) after coming back to *Inspect*
  from another right-pane tab; they are measured again when the view shows.
- Diagnostics:
  - A single sign-on round trip is no longer reported as a redirect loop.
  - Polling during an outage is no longer a "retry storm".
  - Data timestamps are no longer dropped as cache busters.
  - Requests still open at capture end are neither failures nor sequential chains.
  - A session-wide correlation id no longer merges separate actions.
  - Transfer-time estimates agree between rules and include packet loss.
  - Slow critical endpoints are never cut from the list.
  - Large captures stay fast (500 000 sessions in about 2 s); the authentication check is
    linear.
  - A cancelled or older run can no longer replace a newer report, and "Remove all" clears
    the report.
- Diagnostics tab:
  - It keeps the chosen finding and a running analysis across tab switches.
  - It notices enabled or disabled plugins.
  - Filters are reset for a new report.
  - Markdown exports escape text from the traffic.
- *Structure*: the "(this path)" row selects exactly that path; all open levels refresh in
  one pass and less often.
- Map Local serves large files without blocking the proxy and answers `500` instead of a
  truncated file when reading fails.
- Dropped archives: temporary copies are removed even when an import fails or is
  cancelled, left-overs at startup; drops are limited to 8 GiB and need free disk space.
- GraphQL formatting stops at a size limit instead of growing without bound; JWT dates given
  in milliseconds are recognised.
- Language switch: nothing changes when the choice cannot be saved; *Exit* is translated.

### Security
- *Copy as PowerShell* / *cURL*: a crafted HTTP method or typographic quotes in a header or
  body could make the pasted command run other programs. Methods are quoted
  (`-CustomMethod` for non-standard ones), all PowerShell quote characters escaped, control
  characters written explicitly; duplicate header names are merged.
- Map Local verifies the opened file itself (no symlink swap between check and open), and
  `prefix:` rules that name only an origin no longer match look-alike hosts or other ports
  (`https://prod.example.com` ≠ `https://prod.example.com.other.net`).
- Map Remote can remove `Cookie` and `Authorization` when the request goes to another host
  (`*nocreds`; on by default in *Add mapping… → Map Remote*).
- Diagnostics: credentials in URLs (tokens, codes, signatures, passwords, long query values),
  in `Location`/`Referer`, nameless cookies and several cookies in one `Set-Cookie` value are
  redacted before the analyzer sees them; saved reports are read only from regular `.json`
  files.

## [0.1.1] — 2026-09-30

Faster start and capture switching, more platforms, and more robustness. Packages are still
not signed with a paid certificate (see the notes for 0.1.0).
- macOS: one universal `.dmg` for Apple Silicon and Intel.
- Windows: installer (`.exe` / `.msi`) or the portable `Quena_0.1.1_x64-portable.zip`.
- Linux: `.deb`, `.rpm` and AppImage for x86_64 and arm64.

### Added
- macOS builds are universal (Apple Silicon and Intel); Linux packages for arm64 (aarch64)
  in addition to x86_64.
- UI end-to-end tests that start the real app and drive it through WebDriver (Linux, in CI).
- Requests the HTTP parser rejects (malformed request line or headers, too large heads) appear
  as aborted sessions with the raw bytes received, instead of only a 400 to the client.

### Changed
- Layout uses the whole window at every size: the Path column of the session list takes the
  width left over by the other columns; in a narrow right pane request and response go above
  each other automatically and the pane's tabs show icons only; toolbars in the inspectors wrap
  instead of cutting off buttons; splitters keep a usable minimum size for every area.
- The capture switch reacts immediately and shows "Starting…"/"Stopping…" while the system
  proxy is being changed.
- Stopping the capture also closes open client connections, tunnels and WebSockets (after the
  request in flight), so nothing more is recorded.
- WebSocket over HTTP/2 (RFC 8441) is no longer offered to browsers; they open WebSockets on a
  separate HTTP/1.1 connection, which Quena records frame by frame.
- Faster start: the window no longer waits for the capture to start (setting the system proxy,
  loading a PAC file), for plugins to compile or for the OS root certificates to load. Plugins
  are compiled once and cached (`plugin-cache` in the data folder); the UI's startup bundle is
  60 % smaller (editors, diff view and the QR code load on first use).
- Starting and stopping the capture on macOS changes all network services at once instead of
  one after another (several times faster on Macs with many network services).
- Portable mode (a `portable` file or `quena-data` folder beside the executable, on every
  platform) now keeps the web view's cache and storage in `quena-data` as well, and bundled
  plugins are found in a `plugins` folder next to the executable.

### Fixed
- Body views of small responses left a white area below the text (the editor did not fill
  the pane when no notice was shown above it).
- Mock Rules: the Latency and Hits column headings broke in the middle of the word.
- Windows: logging off or shutting down while Quena runs restores the system proxy (it could
  stay pointed at Quena until the next start, leaving the user without internet).
- Starting the capture at launch and toggling it at the same moment could start it twice.

## [0.1.0] — 2026-09-29

First public release of Quena, a local HTTP(S) debugging proxy for macOS, Windows and Linux:
capture, inspect, change and replay HTTP/1.1, HTTP/2, HTTPS, WebSocket and SSE traffic, with
mock rules, breakpoints, a composer, JavaScript rules, WebAssembly plugins, automatic
authentication (NTLM, Kerberos, Basic) and SAZ/HAR import and export.

**Installing:** packages are **not signed with a paid certificate or notarized** yet.
- macOS (`.dmg`, Apple Silicon): on first start macOS warns about an unidentified developer —
  open *System Settings → Privacy & Security* and choose *Open Anyway*.
- Windows (`.exe` / `.msi`): SmartScreen may warn — *More info → Run anyway*.
- Windows portable (`Quena_0.1.0_x64-portable.zip`, xcopy deployment): unzip anywhere and
  start `Quena.exe` — no installation; settings, sessions and the root certificate stay in
  `quena-data` beside it (see `README-portable.txt`).
- Linux: `.deb` (Debian, Ubuntu), `.rpm` (Fedora, openSUSE) or the AppImage (x86_64).

This is an early `0.x` release: settings, file formats and the plugin API may still change.

### Added
- Linux support on par with macOS and Windows: system proxy for GNOME and KDE Plasma (restored
  on quit and after a crash), root certificate trust for Chrome/Firefox (NSS) and the system
  store (via `pkexec`), process attribution via `/proc`, credentials in the Secret Service
  keyring, Kerberos single sign-on via GSSAPI (loaded at runtime), `xdg-open`/file manager
  integration. Packages: `.deb`, `.rpm`, AppImage; built and tested in CI on Ubuntu 22.04.
- Double-clicked or "Open With" `.har`/`.saz` files are loaded (all platforms).
- `tools/linux/Dockerfile`: the Linux build and test environment.
- Hardening against broken and hostile traffic: timeouts for stalled clients and servers
  (request head, TLS handshake, DNS, upstream CONNECT, response head, idle tunnels and
  WebSockets), limits for concurrent connections, buffered bodies, decompression, imports and
  inspectors, refusal of request loops into Quena itself, bounded PAC evaluation and download.
  Damaged settings, rules, root certificate, database rows and system-proxy backups no longer
  block the start or lose data; a failing view shows an error instead of a blank window.
- New app icon.
- Portable edition for Windows (xcopy deployment, added to the release afterwards): settings,
  sessions, rules and the root certificate stay in `quena-data` next to `Quena.exe`; the web
  view's cache is still in the user profile in this version.
- Header inspector plugins: the plugin API gains an additive `header-plugin` world (existing
  decoder plugins keep working). The bundled **auth-tokens** plugin decodes SPNEGO, Kerberos
  (AP-REQ/AP-REP/KRB-ERROR) and NTLM Type 1/2/3 tokens in the Auth inspector and flags
  Negotiate that fell back to NTLM. (Marian Gavalier)
- `Ctrl`/`⌘` `+`/`-`/`0` zoom the whole UI; `cargo build --profile local` for fast optimized
  local builds. (Marian Gavalier)

### Changed
- Own default layout: session list left, request and response side by side, rows coloured by
  outcome (5xx red, 4xx amber, redirects muted). The dense stacked arrangement is available as
  the **Classic** layout (first start, *Settings → General*).
- Own look: SVG icons (Lucide), a capture switch, method and status badges in the session list,
  a state bar for in-flight/paused/mocked sessions, tunnels shown by target host with a badge.
- Command field in the toolbar (`Alt+Q`) replaces the bar below the list; new command palette
  (`Ctrl/⌘ K`) with every menu command.
- Inspectors: request and response cards with segmented tabs (Headers, Body, Cookies, Raw and
  content-specific views), the rest under *More*; headers as a filterable table in wire order
  with topic tags and optional A–Z sorting.
- Menus: *File, Edit, Capture, View, Tools, Help*; breakpoints, mock rules, rules script and
  authentication are under *Capture*, the *Hide …* items under *View → Hide in List*.
- Own names: Mock Rules, Text Tools, Inspect; inspector tabs Plain Text, Body,
  Form Data, Hex, Image, Preview, Encoding; *Rules Script…*; *Replay …*. Filter/command syntax
  and shortcuts are unchanged. *Help → Coming from Fiddler Classic…* maps the names.
- `.saz` is registered as a viewer (macOS rank "Alternate") and not at all on Windows, so Quena
  never takes over another application's file association.

### Fixed
- Automatic authentication falls back to the next offered scheme when the server rejects one
  (e.g. Negotiate advertised but only NTLM working).
- NTLM no longer uploads the request body twice (the Type 1 leg now goes without it).
- Plugin call timeout follows wall-clock time on loaded machines.
- Sorting 500k sessions by host no longer allocates per comparison (several times faster on
  Windows).
- Request bodies could go missing when a response finished before its request body was
  recorded (both are now recorded in order, and a session is saved only when all its bodies are).
- Sessions whose client disconnected stayed "in flight" forever; they now end as aborted.
- Windows: `Ctrl+F` opened the web view's page search instead of *Find Sessions*; browser
  shortcuts (`Ctrl+R`, `F5`, `Ctrl+P`) no longer reach the web view.
- macOS: downloaded builds were reported as "damaged" (incomplete signature); the bundle is now
  signed ad hoc, with the JIT permission the plugin engine needs.
- Tab strips in Settings, Composer and Connect Device had no spacing between titles.
- Raw inspector uses the whole pane; larger base text size (13 px). Documented toolchain
  minimums corrected (Rust 1.95, Node.js 20.19+/22.12+). (Marian Gavalier)

## 0.0.1 — 2026-09-29

Internal test build (not tagged) — an early preview for trying Quena on macOS and Windows. Installers are
**not code-signed** yet.

### Added
- HTTP(S) debugging proxy on port 8866: HTTP/1.1, HTTP/2, HTTPS interception with a locally
  generated root certificate, CONNECT tunnels, WebSocket and Server-Sent Events.
- Session list for hundreds of thousands of sessions, request/response inspectors
  (Headers, Text, Pretty, Form Data, Hex, Auth, Cookies, Raw, JSON, XML, Caching,
  Image, Preview, Encoding) and auto-detected WebSocket, SSE, gRPC/Protobuf,
  Multipart/MTOM, SOAP and Atom/OData inspectors; streaming viewer for multi-GB bodies.
- Command Bar, filters, find, statistics, timeline, compare, Text Tools, comments and marks.
- Mock Rules (with `.farx` import/export), breakpoints and tampering, Composer with cURL
  import, replay variants.
- JavaScript rules with `registerMenu`, `registerColumn` and a
  rules editor with hot reload.
- WebAssembly plugin host (sandboxed) with the bundled Fast Infoset decoder.
- System proxy integration on macOS and Windows with crash recovery; upstream proxy, PAC,
  bypass list; remote devices with QR-code assistant and `http://quena.cert` landing page.
- Automatic authentication (NTLM, Negotiate/Kerberos, Basic) with SSO on Windows (SSPI) and
  macOS (Kerberos); credentials in the OS secure store.
- Client certificates (mTLS) per host; bandwidth and latency simulation.
- SAZ (compatible with Fiddler Classic) and HAR 1.2 import/export; copy as cURL.

[Unreleased]: https://github.com/hkiam/quena/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/hkiam/quena/compare/v0.1.7...v0.2.0
[0.1.7]: https://github.com/hkiam/quena/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/hkiam/quena/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/hkiam/quena/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/hkiam/quena/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/hkiam/quena/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/hkiam/quena/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/hkiam/quena/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/hkiam/quena/releases/tag/v0.1.0
