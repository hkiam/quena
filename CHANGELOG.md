# Changelog

All notable changes to Quena are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Quena uses
[Semantic Versioning](https://semver.org/). While the major version is `0`, any release may
contain breaking changes (settings, file formats, plugin API).

## [Unreleased]

### Added
- Linux support on par with macOS and Windows: system proxy for GNOME and KDE Plasma (restored
  on quit and after a crash), root certificate trust for Chrome/Firefox (NSS) and the system
  store (via `pkexec`), process attribution via `/proc`, credentials in the Secret Service
  keyring, Kerberos single sign-on via GSSAPI (loaded at runtime), `xdg-open`/file manager
  integration. Packages: `.deb`, `.rpm`, AppImage; built and tested in CI on Ubuntu 22.04.
- Double-clicked or "Open With" `.har`/`.saz` files are loaded (all platforms).
- `tools/linux/Dockerfile`: the Linux build and test environment.

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

## [0.0.1] — 2026-09-29

First test build — an early preview for trying Quena on macOS and Windows. Installers are
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

[Unreleased]: https://github.com/hkiam/quena/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/hkiam/quena/releases/tag/v0.0.1
