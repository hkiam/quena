# Changelog

All notable changes to Quena are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Quena uses
[Semantic Versioning](https://semver.org/). While the major version is `0`, any release may
contain breaking changes (settings, file formats, plugin API).

## [Unreleased]

### Added
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

[Unreleased]: https://github.com/hkiam/quena/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/hkiam/quena/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/hkiam/quena/releases/tag/v0.1.0
