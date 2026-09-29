# Changelog

All notable changes to Piper are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Piper uses
[Semantic Versioning](https://semver.org/). While the major version is `0`, any release may
contain breaking changes (settings, file formats, plugin API).

## [Unreleased]

## [0.0.1] — 2026-09-29

First test build — an early preview for trying Piper on macOS and Windows. Installers are
**not code-signed** yet.

### Added
- HTTP(S) debugging proxy on port 8866: HTTP/1.1, HTTP/2, HTTPS interception with a locally
  generated root certificate, CONNECT tunnels, WebSocket and Server-Sent Events.
- Fiddler-style session list for hundreds of thousands of sessions, request/response inspectors
  (Headers, TextView, SyntaxView, WebForms, HexView, Auth, Cookies, Raw, JSON, XML, Caching,
  ImageView, WebView, Transformer) and auto-detected WebSocket, SSE, gRPC/Protobuf,
  Multipart/MTOM, SOAP and Atom/OData inspectors; streaming viewer for multi-GB bodies.
- QuickExec, filters, find, statistics, timeline, compare, TextWizard, comments and marks.
- AutoResponder (with `.farx` import/export), breakpoints and tampering, Composer with cURL
  import, replay variants.
- JavaScript rules (FiddlerScript replacement) with `registerMenu`, `registerColumn` and a
  rules editor with hot reload.
- WebAssembly plugin host (sandboxed) with the bundled Fast Infoset decoder.
- System proxy integration on macOS and Windows with crash recovery; upstream proxy, PAC,
  bypass list; remote devices with QR-code assistant and `http://piper.cert` landing page.
- Automatic authentication (NTLM, Negotiate/Kerberos, Basic) with SSO on Windows (SSPI) and
  macOS (Kerberos); credentials in the OS secure store.
- Client certificates (mTLS) per host; bandwidth and latency simulation.
- SAZ (Fiddler-compatible) and HAR 1.2 import/export; copy as cURL.

[Unreleased]: https://github.com/hkiam/piper/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/hkiam/piper/releases/tag/v0.0.1
