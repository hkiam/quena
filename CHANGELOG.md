# Changelog

All notable changes to Quena are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Quena uses
[Semantic Versioning](https://semver.org/). While the major version is `0`, any release may
contain breaking changes (settings, file formats, plugin API).

## [Unreleased]

### Added
- **Compare captures** (*Tools → Compare Captures…*): the live capture and archives loaded
  into the list, side by side.
  - Requests are paired by method, host and normalized path and marked new, gone or
    changed (status, type, time, headers, body; JSON by content).
  - Requests that now fail are counted apart. Double-click compares two sessions; *Copy as
    Markdown*.
  - Headless: `quena-cli diff before after --fail-on errors|changes`. MCP:
    `compare_captures`.
- **AutoSave** (*Settings → General*): all sessions are saved as `.saz` every few minutes
  when something changed, into the data folder or a chosen one; the newest archives are
  kept (10 by default). *Save now*, *Open folder*.
- **Password-protected archives**: *File → Export Sessions → SAZ Archive with Password…*
  encrypts the archive with AES-256 (readable by Fiddler, 7-Zip, WinZip). Loading or
  dropping a protected archive asks for its password; before, it loaded no sessions without
  saying why.
- **Socket.IO**: the WebSocket view shows the event name or packet type and the arguments
  of Socket.IO messages, can hide ping/pong and search for events; a *Socket.IO* view
  decodes long-polling bodies (v4 and v3).
- **Change WebSocket messages on the way**: rewrite rules with *Change: WebSocket messages*
  (direction, JSON also inside Socket.IO packets) and `onWebSocketMessage(msg)` in rules
  scripts (change text, drop). Changed and dropped messages are marked in the frame log.
  MCP: rewrite rules take `phase: webSocket` and `direction`.
- **LLM traffic**: calls to OpenAI (Chat Completions, Responses), Anthropic Messages,
  Google Gemini, Ollama and OpenAI-compatible APIs are recognised.
  - The **LLM** view shows provider and model, system prompt, the messages with tool calls
    and results, the answer (assembled from server-sent events, JSON lines or arrays),
    stop reason, token usage (cache, reasoning) and an estimated cost (built-in list
    prices, own ones in `llm-prices.json`).
  - Finished calls get flags; new columns *LLM*, *Tokens*, *Cost*, grouping by model,
    filter fields `llm` and `tokens`, per-model totals in *Statistics*. MCP:
    `get_llm_call`.
- **LLM prices kept up to date without a new release** (*Settings → Bodies & Storage → LLM
  prices*): *Fetch prices* downloads LiteLLM's price list (several hundred models), on
  request only and through the upstream settings; own prices in `llm-prices.json` still come
  first and can be created and opened from there. A `llm-prices.json` that is no valid JSON
  is reported (settings, log, *LLM* view) instead of being ignored without a word.
- **Collections in the Composer**: requests are saved as `.http` files in the data folder
  (one per collection; JetBrains/VS Code format).
  - Load, send, run all with a result list, sort, duplicate and remove requests; edit the
    collection's variables and choose an environment; import existing `.http` files.
  - Requests with `{{variables}}` are sent with the collection's variables. MCP:
    `list_collections`, `collection:NAME` in `run_http_file` / `list_http_requests`.
- **HTTP version per Composer request**: automatic, HTTP/1.1 or HTTP/2 (also cleartext
  h2c). `.http` files keep a version written after the URL.
- **Use an existing CA** (*Capture → HTTPS Settings… → Import CA…*), e.g. the company's
  interception CA that machines already trust: a PKCS#12 file (`.p12`/`.pfx`, also legacy
  3DES/RC2) or a PEM certificate with its key (PKCS#8, PKCS#1 RSA, SEC1 EC).
  - Quena checks that it is a CA allowed to sign certificates, that the key belongs to it
    and that it is valid. An intermediate CA sends its chain along with every leaf.
  - The previous CA's files are kept. Headless: `quena-cli reverse --ca-p12` with
    `QUENA_CA_PASSWORD`.
- **Export the CA with its key** as a password-protected `.p12` (for a second machine).
  The dialog shows the CA's name and validity; the device assistant and the iOS profile use
  the CA's real name.
- **Expiring server certificates**: sessions to servers whose certificate expires within 30
  days (setting) are flagged `x-quena-cert`, expired ones too when certificate errors are
  ignored. New column *Cert. until*, filter field `certdays`, and the server certificate's
  subject, issuer and validity in *Properties*.
- **gRPC and Protobuf with a schema**: with `.proto` files (*Settings → Bodies & Storage →
  Protobuf schemas*, files or folders, import paths) the *gRPC* view shows field names,
  schema types, enum values by name and nested message types; unknown fields stay by
  number. The message type comes from the gRPC method in the URL, or is chosen for plain
  Protobuf bodies.
  - **Server reflection** (off by default): *Fetch schema from server* asks the session's
    gRPC server for its schema (v1, else v1alpha, imports by file name) and keeps it in the
    data directory.
  - The view also uncompresses messages per `grpc-encoding`, reads gRPC-Web trailers
    (`grpc-status` in the last frame) and decodes `grpc-web-text` (base64).
- **MessagePack view** for `application/msgpack`, `x-msgpack` and `vnd.msgpack`: the
  values as a tree, with binary data, extension types, timestamps and streams of several
  values.
- **Rewrite rules have an editor** in the Mock Rules tab: *New rewrite rule…*, a double-click
  or the context menu.
  - Every operation has its own fields: JSONPath, a JSON value, regex and replacement,
    header, status. The form checks what it can before saving.
  - A preview tries the rule on the selected session and shows the status, header and body
    before and after.
  - Rules can be sorted, cloned and put into **groups** that are switched on and off
    together. The largest body a rule changes can be set.
- **Rewrite rules can be applied to captured sessions**: *Apply Rewrite Rules…* in the
  session context menu or on a rule. Each session a rule changes gets a changed copy; the
  original stays and nothing is sent. MCP has `apply_rewrite_rules`, and rules can have a
  `group`.
- **Host remapping** (*Capture → Host Remapping…*): connections to a host or `*.domain` go
  to another host, IP address or port, like a hosts-file entry but only for traffic through
  Quena.
  - By default the request keeps its `Host` and TLS name, and only the connection moves,
    e.g. to test the production URL against a staging server. Without *keep host* it is
    sent to the target as if addressed there.
  - Applies to proxied, SOCKS, transparent and reverse proxy traffic and to HTTPS tunnels
    that are not decrypted. Remapped hosts bypass the upstream proxy.
  - Entries can be imported from the hosts file. Sessions are marked (`x-quena-remap`).
  - Also available as `quena-cli reverse --remap` and through MCP tools.
- **Start a browser or a terminal that uses Quena**, without changing the system proxy: the
  globe button next to the capture switch, *Capture → Start Browser…* and *Capture → Open
  Terminal*.
  - Chrome, Edge, Brave, Vivaldi and Chromium start with their own profile and accept
    Quena's certificates in it without trusting the root certificate system-wide. Requests
    to `localhost` are captured as well.
  - Firefox starts with its own profile and the system's trusted roots.
  - The terminal sets `HTTP(S)_PROXY` and the root certificate for Node.js, Python, curl,
    Git, pip, Cargo and the AWS CLI.
  - Capturing starts if it is off. Agents (MCP) have `launch_browser` and `open_terminal`.
- **Reverse proxy ports for clients that cannot use a proxy** (*Capture → Reverse Proxy…*).
  Each entry listens on a local port while capturing and forwards every request to one target
  (`http(s)://host[:port][/base path]`). This suits backends with a fixed API URL, containers,
  test suites, webhook senders and gRPC. The traffic is recorded like proxied traffic, and
  breakpoints, Mock Rules, rewrite rules and scripts apply to it.
  - On the client side, the port accepts HTTPS (certificates from the Quena root
    certificate), plain HTTP and cleartext HTTP/2 (h2c, gRPC without TLS) on one port.
  - Options per entry: keep the client's `Host`, point `Location` redirects back to the port,
    drop cookie domains, add `X-Forwarded-*` headers.
  - Entries listen on this machine only unless one allows remote computers.
  - A port refuses `CONNECT`, so it never becomes an open proxy, and a target that is Quena
    itself is refused.
  - The new *Via* column, *Group by → Via* and the filter `via == name` show which
    entry a request came through; the status bar shows the running entries.
  - Right-clicking a session offers *Reverse Proxy for this Host…*, and agents (MCP) can
    manage entries.
  - **Path routes** send some paths of a port to other targets, e.g. `/auth` to the login
    server and `/api` to the backend. The longest prefix wins, and the prefix can be removed
    from the forwarded path. Redirects and `Host` follow the chosen target.
- **SOCKS5/4 port and transparent port** (*Settings → Connections*, off by default).
  - SOCKS5 (with or without a password) and SOCKS4/4a clients name their target.
  - Connections a firewall redirects (iptables, pf) need no client setting at all. Quena
    takes the target from the original destination (Linux), the TLS server name or the
    `Host` header.
  - Both are handled like `CONNECT` tunnels: HTTPS is decrypted when decryption is on,
    plain HTTP is recorded, anything else is passed through.
  - The *Via* column shows `SOCKS5` or `transparent`, the status bar shows the open ports,
    and the manual shows the firewall rules for Linux and macOS.
- **`quena-cli reverse` (also `quena-cli serve`) runs the reverse proxy without a window**,
  e.g. in CI or as a Docker sidecar:
  `quena-cli reverse --route api=8080=https://api.example.com --save run.saz`. `--path`
  adds path routes, and `--socks` and `--transparent` open those ports (`--decrypt` for
  HTTPS inside them). It
  prints an access log, stops on Ctrl-C/SIGTERM, after `--duration` or `--max-sessions`, and
  saves the sessions as `.saz` or `.har` for `quena-cli diagnose` or `mock`. With
  `--ca-dir` the root certificate stays the same between runs.
- **Software bill of materials (SBOM) for every release.** Each build lists what the app and
  `quena-cli` are made of as a CycloneDX SBOM (JSON) per platform: Rust crates, the npm
  packages of the user interface and the bundled plugins, with versions, licenses and package
  URLs. The SBOMs are release assets (`quena-<version>-<platform>.cdx.json`,
  `quena-cli-<version>-<platform>.cdx.json`), and `sbom.cdx.json` comes with the app
  (macOS app bundle, Windows installer and portable ZIP, Linux packages), the `quena-cli`
  archive and the Docker image, which also carries an SBOM and provenance attestation.

### Fixed
- The loop guard (since the previous fix) refused every server on the port number of a
  wildcard listener: a reverse proxy entry on `0.0.0.0:8080` forwarding to `backend:8080`
  answered every request with "is Quena itself". Requests to `0.0.0.0:P` reach a listener
  on `127.0.0.1:P` again.
- AutoSave removed the oldest archives before writing the new one; when writing failed (a
  full disk) every interval cost one more archive. Now older archives go only after the new
  one is written, and a failed save is tried again at the next interval.
- *Save to collection* replaced a collection it could not read (e.g. a file in another
  encoding) by one with just this request, and put the request back at its old position
  even when the collection had been sorted or shortened meanwhile, overwriting another one.
  It now stops with the error, and appends when the position no longer holds the request.
- Collections: the first rewrite of a `.http` file written elsewhere keeps the original as
  `.http.bak` (comments, response handlers and requests the Composer cannot read are not
  kept). `.rest` files are no longer listed (they could not be opened), names Windows keeps
  for devices (`NUL`, `COM1` …) are refused, and a collection can be renamed in case only.
- `quena-cli diff` compared the first capture with itself when the second had no sessions,
  and passed `--fail-on`; such a file is now an error (exit code 2).
- Compare captures: a request that now gets no answer (status 0) counts as one that now
  fails; content hashes in file names (`index-B2x9kQ1a.js`) no longer make every built asset
  new and gone; captures with many requests to one path compare quickly. New: *Ignore host*
  (`--ignore-host`, MCP `ignore_host`) pairs staging with production. MCP no longer shows
  redirect targets with their codes or tokens unless secrets are allowed.
- Importing a CA moved the current CA's files aside before the new ones were written; a
  failed write left no usable CA, and the next start made a new one. The new files are now
  written first, the current ones kept as copies (also two imports in one second).
- LLM traffic: sessions were parsed on one new thread each, and other apps' endpoints named
  `/api/chat`, `/responses` or `/embeddings` were marked as LLM calls. One worker now parses
  them, and only bodies shaped like such a call count. A mark could bring back a session
  removed meanwhile. Newer models no longer get the list price of an older one with the same
  prefix (`claude-opus-4-5` was priced as `claude-opus-4`); prices added for Claude Opus 4.1
  and 4.5, Sonnet 4.5, GPT-5.1, GPT-5 pro, o3-pro and o1-pro.
- Rewrite rules on large WebSocket messages ran on the proxy's async workers and could
  stall other connections; their preview used only the first 4 KB of a message.
- The sanitized export lost the marks of changed and dropped WebSocket messages; v3
  Socket.IO polling bodies with emoji were split in the wrong places; a damaged protected
  archive asked for the password again and again; a Composer request with `HTTP/1.0` was
  recorded as 1.0 but sent as 1.1 (now recorded as sent); a script setting a WebSocket
  message to text that is no valid Unicode was ignored without a word (now logged).
- The loop guard took a server for Quena itself when it listened on the same port number at
  another address (`127.0.0.1:P` while Quena listened on `[::1]:P`), and kept the ports of
  a stopped proxy engine.
- Hiding the navigator right after choosing a group could leave the list narrowed to it.
- A session that just finished could briefly not be found (its details vanished for a
  moment between recording and storage).

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

[Unreleased]: https://github.com/hkiam/quena/compare/v0.1.7...HEAD
[0.1.7]: https://github.com/hkiam/quena/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/hkiam/quena/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/hkiam/quena/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/hkiam/quena/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/hkiam/quena/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/hkiam/quena/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/hkiam/quena/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/hkiam/quena/releases/tag/v0.1.0
