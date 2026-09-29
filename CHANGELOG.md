# Changelog

All notable changes to Quena are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Quena uses
[Semantic Versioning](https://semver.org/). While the major version is `0`, any release may
contain breaking changes (settings, file formats, plugin API).

## [Unreleased]

## [0.1.0] — 2026-09-29

First public release of Quena, a local HTTP(S) debugging proxy for macOS, Windows and Linux:
capture, inspect, change and replay HTTP/1.1, HTTP/2, HTTPS, WebSocket and SSE traffic, with
mock rules, breakpoints, a composer, JavaScript rules, WebAssembly plugins, automatic
authentication (NTLM, Kerberos, Basic) and SAZ/HAR import and export.

**Installing:** packages are **not signed with a paid certificate or notarized** yet.
- macOS (`.dmg`, Apple Silicon): on first start macOS warns about an unidentified developer —
  open *System Settings → Privacy & Security* and choose *Open Anyway*.
- Windows (`.exe` / `.msi`): SmartScreen may warn — *More info → Run anyway*.
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

[Unreleased]: https://github.com/hkiam/quena/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hkiam/quena/releases/tag/v0.1.0
