# Quena

**Quena** is a local HTTP(S) debugging proxy for macOS, Windows and Linux. It records the
traffic between your applications and the servers they talk to, and lets you inspect,
change, replay and mock it. **It diagnoses web traffic, and it shows what your AI agents do.**

![Quena main window: session list on the left, the request headers above the pretty-printed JSON response on the right](img/overview.png)

## See what your AI agents do

Run Claude Code, Codex or your own agent through Quena (*Capture → Start Agent…*) and
every model call becomes readable: the system prompt, the messages, the tool calls and the
answer, the tokens and what they cost.

- **Agent conversations**: each run with its turns, subagents and side calls, what changed
  from one call to the next, why the provider's prompt cache missed, and where tokens go to
  waste. A map shows what fills the context.
- **MCP servers and skills**: every tool call with its arguments and result, traced from
  the model's request to the server and back — stdio servers too, through
  `quena-cli mcp-tap`. Tools that are offered but never called, and what they cost.
- **Optimise and test**: try a variant of a call (another system prompt, fewer tools, another
  model), change requests while the agent runs, freeze a run and replay against it,
  compare two runs side by side, and export a run as Markdown, JSON lines or OpenTelemetry spans.
- Works with OpenAI, Anthropic, Gemini, Vertex AI, Amazon Bedrock, Ollama and any
  OpenAI-compatible API.

[AI agents and LLM traffic →](agents-overview.md){ .md-button .md-button--primary }

## Diagnostics: from thousands of sessions to what matters

A capture of a few minutes easily holds thousands of sessions. **Diagnostics** does the first
pass for you: it turns them into a short, prioritised list of findings — N+1 queries,
redundant calls, retry storms, authentication loops, missing compression and caching,
request chains that get slow on VPN or mobile networks — and answers for each one *what is
conspicuous, why it matters and where to look next*, with the evidence one click away.

![Diagnostics: 68 sessions condensed to 5 critical findings and 8 warnings; the N+1 finding is open, its 30 sessions are selected in the list](img/diagnostics.png)

[Read more about Diagnostics →](diagnostics.md){ .md-button }

## What you can do with it

- **Capture** HTTP/1.1, HTTP/2 and HTTPS (with a locally generated root certificate),
  CONNECT tunnels, WebSocket frames and Server-Sent Events — from this computer, from
  phones and tablets, or from VMs.
- **Reach clients without proxy settings**: a [reverse proxy](reverse-proxy.md) port
  forwards to a fixed target (or one per path) — for backends, containers, test suites,
  webhooks and gRPC — and [SOCKS and transparent ports](socks-transparent.md) take SOCKS
  clients and firewall-redirected traffic. Headless too, with `quena-cli reverse`.
- **Inspect** headers, bodies, cookies, caching and authentication, with views that pick
  themselves for the content: JSON, XML, SOAP, Atom/OData, gRPC, multipart/MTOM,
  WebSocket, SSE, images and more. Multi-gigabyte bodies open instantly.
- **Change and replay**: breakpoints and tampering, Mock Rules (including Map Remote and
  Map Local), a Composer with cURL import, and replay in several variants.
- **Debug AI agents**: LLM calls, agent conversations, MCP tool calls and their costs — see
  [AI agents](agents-overview.md).
- **Diagnose**: prioritised findings with evidence, profiles for performance, troubleshooting,
  authentication, network resilience and modernization, estimates for slow networks, and
  comparison of two captures — see [Diagnostics](diagnostics.md).
- **Analyze**: statistics, a timing waterfall, a host/path tree, comparing two sessions,
  and Text Tools for quick encoding and decoding.
- **Automate**: JavaScript rules scripts, WebAssembly plugins, automatic authentication
  (NTLM, Negotiate/Kerberos, Basic), client certificates, bandwidth simulation.
- **Share**: save and load `.saz` and `.har` archives, copy requests as cURL, fetch,
  PowerShell or Python.
- **Read packet captures**: `.pcap`/`.pcapng` from tcpdump or Wireshark become sessions,
  HTTPS included when its TLS key log is at hand — see [Packet captures](packet-captures.md).

## Local and private

Quena runs entirely on your machine. There is no account, no cloud service and no
telemetry. The root certificate is generated locally and trusted only when you ask for it,
HTTPS decryption is opt-in, and saved passwords live in the operating system's secure store
(Keychain, Windows Credential Manager or Secret Service). Prompts and tool results never
leave your machine unless you send a variant of a call to the provider or share an export.

## How this manual is organised

| If you want to … | Read |
|---|---|
| install Quena and record your first request | [Install and first start](install.md) |
| capture from browsers, CLI tools, phones or through a corporate proxy | [Capturing traffic](capture.md), [HTTPS and devices](https.md) |
| capture clients that cannot use a proxy (backends, containers, gRPC, redirected traffic) | [Reverse proxy](reverse-proxy.md), [SOCKS and transparent](socks-transparent.md) |
| find, sort, mark and filter sessions | [Session list](sessions.md) |
| read requests and responses | [Inspect](inspect.md) |
| change, mock or resend traffic | [Change and replay](change-replay.md) |
| find out what is wrong with the traffic | [Diagnostics](diagnostics.md) |
| see what an AI agent sends, why it is expensive, which tools it uses | [AI agents overview](agents-overview.md), [Agent conversations](agents.md), [MCP servers and skills](mcp-traffic.md) |
| let an AI agent read and control Quena | [Quena's MCP server](mcp.md) |
| look at timing, volumes and structure | [Analyze](analyze.md) |
| exchange captures with colleagues | [Archives and copying](archives.md) |
| read a tcpdump or Wireshark recording, decrypt its HTTPS | [Packet captures](packet-captures.md) |
| automate with scripts or plugins | [Rules scripts](scripting.md), [Plugins](plugins.md) |
| look up a setting, shortcut or command | [Reference](settings.md) |

!!! note "Early preview"
    Quena is at version `0.x`. Settings, file formats and the plugin API may still change
    between releases. See the
    [changelog](https://github.com/hkiam/quena/blob/main/CHANGELOG.md) for what is new.

Quena is open source under the Apache License 2.0. Source code, releases and issue tracker:
[github.com/hkiam/quena](https://github.com/hkiam/quena).
