<div align="center">

<img src="docs/logo.png" alt="Piper logo" width="128" height="128">

# Piper

**The easy, intuitive — yet seriously powerful — HTTP(S) debugging proxy. On every desktop.**

If you know Fiddler Classic on Windows, you already know Piper.

[![CI](https://github.com/hkiam/piper/actions/workflows/ci.yml/badge.svg)](https://github.com/hkiam/piper/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Windows%20%7C%20Linux%20(experimental)-lightgrey)
![Rust](https://img.shields.io/badge/core-Rust-orange?logo=rust)
![Tauri 2](https://img.shields.io/badge/UI-Tauri%202%20%2B%20React-24C8DB?logo=tauri)
![Status](https://img.shields.io/badge/status-early%20preview-yellow)

[Why Piper?](#why-piper) ·
[Features](#features) ·
[Screenshots](#screenshots) ·
[Getting started](#getting-started) ·
[Scripting](#scripting) ·
[Architecture](#architecture) ·
[Contributing](#contributing)

<br>

<img src="docs/screenshots/overview.png" alt="Piper main window: session list, request headers and a pretty-printed JSON response" width="920">

</div>

---

## Why Piper?

For many developers, **Fiddler Classic** is *the* HTTP debugger: a dense session list, inspectors
right next to it, keyboard-driven, and powerful enough to break, tamper, replay or script any
request — without ever getting in the way. It is also **Windows-only** and built on a platform
that is no longer evolving.

Piper exists to bring exactly that experience to **every desktop platform**:

- **Easy to use.** Start Piper, and traffic appears. HTTPS decryption is one checkbox and one
  "Trust" click. No accounts, no cloud, no setup wizard marathon.
- **Intuitive — especially if you know Fiddler.** Same layout, same mental model, same
  shortcuts (`F12`, `F11`, `Ctrl/⌘ R`, `Alt Q` …), QuickExec, AutoResponder, Composer,
  and SAZ files you can exchange with colleagues who still use Fiddler.
- **Powerful.** Breakpoints and tampering, auto-responders, replay, JavaScript rules,
  WASM plugins, enterprise authentication (NTLM/Kerberos), PAC, mTLS, bandwidth simulation,
  and inspectors for WebSocket, SSE, gRPC, SOAP, OData and MTOM.
- **Fast, even when traffic is not friendly.** Hundreds of thousands of sessions and
  multi-gigabyte response bodies with constant memory; the UI never waits on the core.
- **Local and private by design.** Everything stays on your machine. The root certificate is
  generated locally, decryption is opt-in, credentials live in the OS secure store,
  and there is no telemetry.
- **Open source.** Apache-2.0 licensed, built in the open, contributions welcome.

> Piper is an independent project. It is not affiliated with, endorsed by, or connected to
> Progress Software Corporation or the Fiddler product family. *Fiddler* is a trademark of its
> respective owner and is mentioned here only to describe familiarity and compatibility.

---

## Features

<table>
<tr>
<td valign="top" width="50%">

### Capture
- HTTP/1.1, **HTTP/2**, HTTPS (on-the-fly certificates), CONNECT tunnels
- **WebSocket** frames and **Server-Sent Events**, live
- System proxy on macOS and Windows — restored on quit *and* after a crash
- Upstream proxy chaining, bypass list, **PAC** (proxy auto-config)
- Remote devices: allow-list, landing page `http://piper.cert`,
  **QR-code device assistant** for iOS and Android
- Process attribution (which app sent the request)

### Inspect
- Headers, TextView, SyntaxView, WebForms, HexView, Auth, Cookies,
  Raw, JSON, XML, Caching, ImageView, WebView, Transformer
- Auto-detected inspectors: **WebSocket**, **SSE**, **gRPC / Protobuf**
  (schemaless), **Multipart / MTOM**, **SOAP**, **Atom / OData**
- **Fast Infoset** (SOAP, OData, EDMX) via bundled plugin
- Transparent gzip / deflate / brotli / zstd decoding, with bomb protection
- Large-body viewer: open a multi-GB body instantly, search it, save ranges

</td>
<td valign="top" width="50%">

### Change & replay
- **AutoResponder** with Fiddler `.farx` import/export
- **Breakpoints & tamper** before request / after response
- **Composer** (parsed, raw, history) with **cURL import**
- Replay: reissue, unconditionally, *n* times, sequentially, with edit
- **JavaScript rules** (FiddlerScript replacement) with hot reload,
  custom menu commands and a custom column

### Analyze
- **QuickExec** command line (`?text`, `@host`, `=404`, `>10k`, `bpu`, `g` …)
- Filters, Find, Statistics, Timeline, Compare, TextWizard
- Comments, color marks, custom column

### Enterprise-ready
- **Automatic authentication**: NTLM, Negotiate/Kerberos, Basic —
  single sign-on via Windows SSPI and macOS Kerberos tickets
- **Client certificates (mTLS)** per host
- **Bandwidth & latency simulation**
- Import/export **SAZ** (Fiddler-compatible), **HAR 1.2**, copy as cURL

</td>
</tr>
</table>

---

## Screenshots

<table>
<tr>
<td width="50%">
<img src="docs/screenshots/soap-inspector.png" alt="SOAP request with syntax-highlighted XML response and auto-detected SOAP inspector">
<p align="center"><sub><b>SOAP & XML</b> — pretty-printed, with auto-detected SOAP and Atom/OData inspectors</sub></p>
</td>
<td width="50%">
<img src="docs/screenshots/statistics.png" alt="Statistics for 13 selected sessions: timing, response codes, bytes by content type">
<p align="center"><sub><b>Statistics</b> — timing, status codes and bytes by content type for any selection</sub></p>
</td>
</tr>
<tr>
<td width="50%">
<img src="docs/screenshots/scripting.png" alt="Customize Rules editor with a JavaScript rules script and its console output">
<p align="center"><sub><b>JavaScript rules</b> — hooks, custom menu and column, live console</sub></p>
</td>
<td width="50%">
<img src="docs/screenshots/overview.png" alt="Main window with script-populated Comments and Custom columns">
<p align="center"><sub><b>Session list</b> — comments, colors and the Custom column set by a script</sub></p>
</td>
</tr>
</table>

---

## Feels like Fiddler

| Action | Piper | |
|---|---|---|
| Start / stop capturing | `F12` | |
| Break before requests / after responses / off | `F11` / `Alt F11` / `Shift F11` | |
| Resume all paused sessions | QuickExec `g` | |
| Customize rules (scripting) | `Ctrl/⌘ R` | |
| Focus QuickExec | `Alt Q` | |
| Statistics / Inspectors | `F7` / `F8` | |
| Composer | `F9` | |
| TextWizard | `Ctrl/⌘ E` | |
| Find sessions | `Ctrl/⌘ F` | |
| Mark session red … purple / unmark | `Ctrl/⌘ 1` … `6` / `Ctrl/⌘ 0` | |

QuickExec examples:

```text
?login        select sessions whose URL contains "login"
@github.com   select sessions for a host
=500          select by status code (or =POST for a method)
>100k         select responses larger than 100 KB
bpu /api      break before requests matching /api
bps 500       break on responses with status 500
keeponly json keep only JSON responses
tail 1000     keep the 1000 most recent sessions
dump          save everything as a .saz archive
```

Piper listens on **port 8866** by default, so it can run next to Fiddler (8888).

---

## Getting started

### Install

Pre-built, signed installers for macOS (`.dmg`) and Windows (`.exe`, NSIS) will be published on the
[Releases](https://github.com/hkiam/piper/releases) page. Until the first release, build from source.

### Build from source

Requirements: [Rust](https://rustup.rs) **1.90+**, [Node.js](https://nodejs.org) **20+**, and the
[Tauri 2 prerequisites](https://tauri.app/start/prerequisites/) for your platform.

```bash
git clone https://github.com/hkiam/piper.git
cd piper

# UI dependencies
npm ci --prefix app/ui

# Bundled plugins (optional, e.g. Fast Infoset) — built as WebAssembly components
rustup target add wasm32-wasip2
./plugins/build.sh

# Run in development mode
npm run tauri --prefix app/ui -- dev

# …or build an installable bundle
npm run tauri --prefix app/ui -- build
```

Run the test suite:

```bash
cargo test --workspace --exclude piper-app
npm run build --prefix app/ui      # typecheck + production build of the UI
```

### First capture

1. Start Piper. It begins capturing and — with *Act as system proxy* in *Settings → Connections* (on by default) — registers
   itself as the system proxy (the previous proxy is kept as upstream and restored on exit).
2. Browse. Sessions appear live in the list; select one to inspect it.
3. Want HTTPS content? Open **Tools → HTTPS Settings…**, enable *Decrypt HTTPS traffic* and click
   **Trust root certificate**. The certificate is generated on your machine and never leaves it.
4. Command-line tools work too: `curl -x http://127.0.0.1:8866 https://example.com`.

### Phones, tablets and VMs

Open **Tools → Connect Device…**, allow remote connections, and scan the QR code with the device.
It leads to `http://piper.cert`, which serves the certificate (`.crt` for Android,
`.mobileconfig` for iOS) together with step-by-step instructions.

---

## Scripting

Piper embeds a sandboxed JavaScript engine (QuickJS) as a modern replacement for FiddlerScript.
Open **Rules → Customize Rules…** (`Ctrl/⌘ R`), edit, and press `Ctrl/⌘ S` — the script reloads
instantly and errors appear inline.

```js
function onBoot() {
    // A "Custom" column filled from each response
    Piper.registerColumn('Server', s => s.responseHeaders.get('Server') || '');

    // A command in the session context menu (right click → Scripts)
    Piper.registerMenu('Tag as reviewed', sessions =>
        sessions.map(s => ({ id: s.id, comment: 'reviewed', color: 'green' })));
}

function onBeforeRequest(s) {
    s.requestHeaders.set('X-Debug-Trace', 'piper-' + s.id);
    if (s.host === 'ads.example.com') s.abort();
    if (s.path === '/api/feature-flags') s.respond(200, '{"newCheckout":true}',
                                                   { 'Content-Type': 'application/json' });
}

function onBeforeResponse(s) {
    if (s.status >= 500) s.color('red').comment('server error');
    s.responseHeaders.remove('Strict-Transport-Security');
}
```

Scripts run off the proxy threads with a time and memory budget and have no file-system,
network or environment access. They see headers and metadata only — bodies keep streaming,
so enabling a script never turns a 5 GB download into a 5 GB buffer.
Full API: [`crates/piper-script/src/piper.d.ts`](crates/piper-script/src/piper.d.ts) ·
Design notes: [`docs/m14-scripting-and-pac.md`](docs/m14-scripting-and-pac.md)

## Plugins

Inspectors and decoders can be added as **WebAssembly components** (WASI Preview 2, see
[`wit/plugin.wit`](wit/plugin.wit)). Plugins are sandboxed — no file-system, network or
environment access, with memory and time limits — and stream their input and output, so they
are safe to run on untrusted, huge payloads. The bundled
[Fast Infoset plugin](plugins/fast-infoset) is a complete example.

---

## Platform support

|                           | macOS            | Windows                      | Linux                  |
|---------------------------|------------------|------------------------------|------------------------|
| Capture, inspect, tamper  | ✅               | ✅                           | 🧪 manual proxy only   |
| System proxy integration  | ✅               | ✅                           | —                      |
| Trust root certificate    | ✅ Keychain      | ✅ user certificate store     | manual                 |
| Process attribution       | ✅               | ✅                           | —                      |
| Single sign-on auth       | ✅ Kerberos      | ✅ NTLM + Kerberos (SSPI)     | —                      |
| Credentials storage       | ✅ Keychain      | ✅ Credential Manager         | —                      |
| Continuous integration    | ✅               | ✅                           | planned                |

macOS is the primary development platform. Windows is built and tested in CI.
Linux builds are experimental — help is very welcome.

---

## Architecture

Piper is a Rust core with a thin, fast UI:

```text
┌──────────────────────── Tauri 2 app ────────────────────────┐
│  React + TypeScript UI · canvas session grid · CodeMirror 6  │
│        ▲ viewport rows & deltas (≤ 60 Hz)   ▲ bodies via     │
│        │ async IPC commands                 │ piper:// + Range│
├────────┴────────────────────────────────────┴────────────────┤
│ piper-app-core   commands, jobs, rules, settings, archives    │
│ piper-proxy      hyper/rustls MITM proxy, HTTP/2, WS, auth    │
│ piper-index      incremental sort/filter over 500k sessions   │
│ piper-body       disk-backed bodies, range reads, decoding    │
│ piper-store      capture database (SQLite) + recovery         │
│ piper-tls        root CA, per-host certificates, mTLS         │
│ piper-auth       NTLMv2, Negotiate/Kerberos (GSS, SSPI)       │
│ piper-script     QuickJS rules + PAC evaluation               │
│ piper-plugin-host  Wasmtime component host (sandboxed)        │
│ piper-formats    SAZ, HAR, cURL, raw HTTP                     │
│ piper-query · piper-model · piper-jobs · piper-platform       │
└───────────────────────────────────────────────────────────────┘
```

Two principles shape every component:

1. **Bodies can be huge.** Memory per session is O(1) in body size. Bodies never travel over IPC,
   into React state or into the DOM as a whole; every operation — viewing, searching, decoding,
   exporting — is streaming or windowed. See the large-body tests in
   [`crates/piper-body/tests`](crates/piper-body/tests).
2. **The UI never waits.** The core owns all state; the UI renders a viewport. Anything that can
   take time is a cancellable job, and list updates are coalesced with back-pressure.
   See the performance guards in [`crates/piper-index/tests/perf.rs`](crates/piper-index/tests/perf.rs).

The full design and roadmap live in [`PLAN.md`](PLAN.md) (German).

---

## Security & privacy

- Piper runs **entirely locally**. There is no account, no cloud service and no telemetry.
- The root certificate and its private key are **generated on your machine** and stored in
  Piper's data directory. You decide whether to trust it, and you can remove it at any time.
- HTTPS decryption is **opt-in**, can be scoped (browsers only, non-browsers, remote clients)
  and can exclude hosts entirely.
- Stored credentials for automatic authentication live in the **OS secure store**
  (Keychain / Credential Manager) — never in plain-text settings. Auth headers are redacted in logs.
- Remote connections are **off by default** and restricted by an allow-list when enabled.

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

---

## Roadmap

- Signed and notarized releases for macOS and Windows
- Linux system integration (proxy, certificate trust, process attribution)
- Capture without a system proxy (macOS Network Extension), HAR live import, remote capture
- "Any Process" window picker for process filters
- HTTP/3 (QUIC)

Ideas and feedback are welcome in [Discussions](https://github.com/hkiam/piper/discussions) and
[Issues](https://github.com/hkiam/piper/issues).

---

## Contributing

Contributions of all sizes are welcome — bug reports, documentation, inspectors, plugins, platform
support. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

All dependencies must use permissive licenses (MIT, Apache-2.0, BSD, ISC, Zlib …); this is checked
in CI with [`cargo-deny`](deny.toml).

## License

Piper is licensed under the [Apache License, Version 2.0](LICENSE).

Copyright © 2026 Maik Hofmann and Piper contributors.

## Acknowledgements

Piper stands on the shoulders of great open-source projects, among them
[Tauri](https://tauri.app), [hyper](https://hyper.rs), [rustls](https://github.com/rustls/rustls),
[rcgen](https://github.com/rustls/rcgen), [Tokio](https://tokio.rs),
[Wasmtime](https://wasmtime.dev), [QuickJS](https://bellard.org/quickjs/) via
[rquickjs](https://github.com/DelSkayn/rquickjs), [SQLite](https://sqlite.org) and
[CodeMirror](https://codemirror.net) — and it is inspired by the workflow that Fiddler Classic
made so many developers love.
