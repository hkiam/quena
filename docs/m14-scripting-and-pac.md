# M14 — Scripting (FiddlerScript replacement) + PAC

Quena embeds **QuickJS** (via `rquickjs`, MIT) for two features that share one engine
design: a JavaScript rules script (the FiddlerScript replacement) and PAC
(proxy auto-config) evaluation for upstream selection.

## Design

- The engine runs on a **dedicated OS thread** that owns the QuickJS runtime
  (single-threaded, never shared). Hooks are dispatched over a channel and the
  async proxy pipeline awaits the reply (`tokio::sync::oneshot`), so scripts run
  *off* the forwarding threads.
- Scripts run under a **wall-clock budget** (interrupt handler, 250 ms per hook,
  2 s for load/boot) and a **memory limit** (64 MB), and have **no access** to the
  filesystem, network or environment — only `console.*` and the session object.
- Per Quena's large-body invariant (PLAN.md §2.12), scripts see **heads and
  metadata only**; bodies never enter the JS engine. Response headers are rewritten
  through a head-only hook (`on_response_head`) that runs in the streaming path, so
  huge responses are never buffered just because a script is enabled.

## Rules API (crates/quena-script/src/quena.d.ts)

Define any of these top-level functions; each is optional:

```js
function onBoot() {}                    // once, when the script loads
function onBeforeRequest(session) {}    // before a request is forwarded
function onBeforeResponse(session) {}   // before a response returns to the client
function onSessionComplete(summary) {}  // after a session finishes (summary only)
```

The `session` object exposes `method`, `url`, `host`, `path`, `status`,
`requestHeaders`/`responseHeaders` (ordered, case-insensitive `get/set/add/remove`),
and actions: `redirect(url)`, `abort()`, `respond(status, body, headers)`,
`comment(text)`, `color(name)`, `flag(k, v)`.

Edit under **Rules → Customize Rules… (Ctrl/Cmd+R)**: a CodeMirror editor with an
enable toggle, hot reload on save (Ctrl/Cmd+S), a compile-error banner and the
script's `console` output. Enabled state is persisted (`scripting_enabled`); the
script itself lives in `rules.js` in the data dir.

## PAC

`FindProxyForURL(url, host)` is evaluated once per host and **cached**, so the
forwarding path never blocks on JS after the first lookup. DNS-dependent helpers
(`dnsResolve`, `myIpAddress`, `isInNet`, `isResolvable`) are implemented in Rust;
the rest (`isPlainHostName`, `dnsDomainIs`, `shExpMatch`, `weekdayRange`,
`timeRange`, `dateRange`, …) are pure JS.

Configured under **Connection** options: *Use the system PAC* (the URL Quena
detected from the OS proxy settings) or a manual *PAC URL / file*. A manual
upstream proxy overrides PAC. `file://`, `http://` and local paths are fetched;
`https://` PAC URLs must be provided as a downloaded file. The result feeds
`ProxyConfig::upstream_for` via the `UpstreamResolver` trait, exactly like a
static upstream.

## Tests

- `quena-script`: engine (header rewrite, redirect, abort, respond, response
  edits, error isolation, infinite-loop interrupt, console) and PAC (evaluation,
  cache, invalid script, directive parsing, per-host resolver).
- `quena-app-core`: PAC resolver + file loading; `rules_e2e::scripting_through_proxy`
  drives a real proxy and verifies request-header rewrite, local `respond()`,
  `redirect()`, and streaming response-header rewrite end to end.
