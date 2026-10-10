# Troubleshooting and FAQ

## No traffic appears

- Is the capture switch on (*Capturing*)? Press `F12`. The status bar shows the address
  Quena listens on and a *system proxy* tag when it registered itself.
- Is *Settings → Connections → Act as system proxy while capturing* on? Without it,
  applications must be pointed at `127.0.0.1:8866` by hand.
- Command-line tools and many runtimes (Node.js, Java, Python …) ignore the desktop proxy
  setting. Use their proxy option or `HTTP_PROXY`/`HTTPS_PROXY` — see
  [Tools that ignore the system proxy](capture.md#tools-that-ignore-the-system-proxy).
- A client with no proxy setting at all (a backend with a fixed URL, a container, gRPC):
  point it at a [reverse proxy](reverse-proxy.md) port instead, or redirect its connections
  to the [transparent port](socks-transparent.md#transparent).
- Is a filter hiding sessions? The status bar says *filtered* and the *Filters* tab shows a
  dot. Also check *View → Hide in List* and the process scope in the status bar.
- Is another program using port 8866? Change *Settings → Connections → Listen port*.
- Linux: only GNOME and KDE Plasma proxy settings are supported; on other desktops,
  configure the proxy in the browser.
- Windows, intranet or VPN hosts without a dot (`http://appserver/`) missing: Quena 0.1.5
  and older switched on *Don't use the proxy server for local (intranet) addresses* while
  capturing. Untick it in the Windows proxy settings, or update Quena.

## I have no internet after Quena crashed

Quena saves the previous system proxy before it changes it and restores it when it quits.
After a crash, it restores it **at the next start** — so start Quena once and quit it
again. On Windows, logging off or shutting down while Quena runs restores the proxy as well.

If you uninstalled Quena in the meantime, reset the proxy by hand: *System Settings →
Network → Details → Proxies* (macOS), *Settings → Network & Internet → Proxy* (Windows), or
the network proxy settings of GNOME or KDE.

## Browsers show certificate errors

- Is decryption on, and is the root certificate **trusted**? *Capture → HTTPS Settings…*
  shows the status; click **Trust root certificate…** (or *Re-trust*).
- **Firefox on Linux** uses its own certificate database; Quena adds the certificate there
  when `certutil` is installed (package libnss3-tools / nss-tools). Restart the browser
  afterwards.
- **curl and other CLI tools on Linux** use the system store; trusting asks for your
  password via `pkexec`. Without `pkexec`, export the certificate (*Export…*) and add it
  by hand.
- Java, Node.js, Python and similar runtimes often bring their own trust store. Export the
  certificate and add it there, or use the runtime's option for extra CA certificates.
- Applications that **pin** certificates reject any certificate but their own. Add their
  hosts to *Skip decryption for*.
- After *Regenerate*, the old certificate is no longer valid — trust the new one on every
  device again.

## Android apps fail with HTTPS, the browser works

Since Android 7, apps trust user-installed CA certificates only if their network security
configuration allows it. Browsers do, many apps do not. Debug builds of your own app can
opt in; for other apps, put their hosts into *Skip decryption for*.

## A phone or VM cannot connect

- Enable *Settings → Connections → Allow remote computers to connect*.
- Check *Allowed remote networks*: empty means local subnets; add the device's network if
  it is elsewhere (e.g. a VM network).
- Use the address shown in *Capture → Connect Device…* for the interface the device can
  reach, and allow Quena in your firewall.

## Windows: the window stays blank or Quena does not start

Quena's window uses the **Microsoft Edge WebView2 Runtime**. Windows 11 and current
Windows 10 include it; on older or stripped-down systems, install it from
[developer.microsoft.com/microsoft-edge/webview2](https://developer.microsoft.com/microsoft-edge/webview2/).

## Quena says it cannot write its data folder

Quena needs a writable data folder for its settings, captures and certificate. A portable
copy keeps it next to the program (`quena-data`), so it cannot run from a read-only place:
a write-protected USB stick, a CD, a network share without write access. Quena says so on
start and quits. Copy the Quena folder to a writable place (e.g. the hard disk) and start
it there, or point `QUENA_DATA_DIR` to a writable folder (see
[Data directory](settings.md#data-directory)).

## Quena says it is already running

Only one Quena runs per data folder: a second one would undo the system proxy the first
one set. Switch to the open window; to open an archive there, use *File → Load Archive…* or drag
it onto the window.

## macOS says the app is damaged or from an unidentified developer

The packages are not notarised yet. Open *System Settings → Privacy & Security* after the
first launch attempt and choose *Open Anyway*.

## The corporate proxy asks for a password

Turn on [automatic authentication](authentication.md) with
*Also authenticate to the upstream proxy (407)*. With a PAC file, check
*Settings → Connections → Use the system proxy auto-config (PAC) script* or enter the PAC
URL. An `https://` PAC URL must be downloaded and entered as a file.

## Requests with automatic authentication take seconds (VPN, Kerberos)

With a Kerberos ticket (`klist` shows one) but no reachable KDC, asking for a service ticket
can block for a minute. Quena waits at most 5 seconds per step, then uses NTLM or Basic and
skips Kerberos for that host for 10 minutes (see
[Automatic authentication](authentication.md#schemes-and-single-sign-on)). If every first
request to a host is 5 seconds slow, put `ntlm` first in *Scheme order*, or connect the VPN
so the KDC is reachable.

## Responses look different from what the server sent

Check the status bar: *Mock Rules* answer requests locally, *Rewrite rules* change real
responses (both are listed in the Mock Rules tab). Changed sessions are marked *tampered*
and name the rule in their comment. A rule an AI agent added stays until it is removed.

## An AI agent cannot connect to Quena's MCP server

See [Quena's MCP server → Check the connection](mcp.md#check-the-connection). After *OK* in
the options, Quena reports when the server could not start (for example, the port is in use).

## Agent traffic does not show up

Claude Code, Codex or another agent runs, but its LLM calls do not appear (or only as
tunnels):

- **HTTPS decryption is off**, or the provider's host is in *Skip decryption for*. Turn
  decryption on in *Capture → HTTPS Settings…*; the sessions then show as LLM calls.
- **The agent was started outside Quena.** Node.js agents (Claude Code, Gemini CLI) ignore
  the macOS and Windows system proxy. Start them with *Capture → Start Agent…*, or set
  `HTTPS_PROXY` and the certificate variables yourself — see
  [Get agent traffic into Quena](agents-overview.md#get-agent-traffic-into-quena).
- **The agent does not trust Quena's certificate.** It needs `NODE_EXTRA_CA_CERTS`
  (Node.js agents) or `CODEX_CA_CERTIFICATE` (Codex) pointing to Quena's root certificate;
  *Start Agent…* and *Open Terminal* set both.
- **The host is in *Do not capture*** (*Settings → Connections*): it then goes past Quena,
  also from terminals Quena starts (`NO_PROXY`).
- **The agent has its own proxy setting**, e.g. a corporate proxy in its configuration, which
  sends its traffic past Quena. Point that setting at Quena and let Quena chain to the
  corporate proxy ([Upstream proxy and PAC](capture.md#upstream-proxy-and-pac)).
- **IDE agents** (Cursor, GitHub Copilot and others in an editor) follow the editor's proxy
  settings: set the proxy there and trust Quena's root certificate in the system.
- **MCP servers that talk over stdio** send nothing over the network. Record them with
  [`quena-cli mcp-tap`](mcp-traffic.md#servers-that-talk-over-stdio).

## Exchanges recorded by mcp-tap do not appear

- **Capturing is off.** The app reads mcp-tap's recordings only while it captures.
- **The MCP client cannot find `quena-cli`.** Desktop apps and IDEs often do not have your
  shell's `PATH`: give the full path to the program in the client's configuration
  ([Install → quena-cli](install.md#quena-cli)). The client's MCP log shows whether the
  server started.
- **App and quena-cli use different data folders.** In [portable mode](settings.md#portable-mode),
  or when the app runs with `QUENA_DATA_DIR`, pass the same folder with
  `--data-dir` (see [Data folder](install.md#data-folder)).

## One agent run splits into several conversations, or two runs merge

Quena puts calls together by the agent's session id (Claude Code, Codex) and by their
messages ([How calls are put together](agents.md#how-calls-are-put-together)):

- Calls without a session id that are more than 30 minutes apart are not linked by their
  messages alone, so a long pause starts a new conversation.
- A call whose system prompt starts differently, or whose first user prompt differs, starts
  a conversation of its own.
- Two runs of an app that sends no session id, the same system prompt and the same first
  prompt within 30 minutes can end up in one conversation.

## The Agents panel says "Reason not known" for a cache miss

The prompt cache missed, but nothing in the request explains it: the model, the system
prompt, the tools, the cache settings and the earlier messages are the same, and the time
since the previous turn is within the cache's lifetime. Typical causes are on the provider's
side: the request went to another server, the cache entry was evicted early, or the provider
does not report cached tokens for this call. See
[Why the cache missed](agents.md#why-the-cache-missed).

## Replays or variants of Bedrock calls fail with 403

Requests to Amazon Bedrock are signed with AWS Signature Version 4: the signature covers the
URL, headers and body. Quena leaves signed requests alone where it can: the
[LLM rewrite operations](optimize-agents.md#change-requests-while-an-agent-runs) skip them,
and the [prompt playground](optimize-agents.md#try-a-variant) refuses them with a reason.
Everything else that changes such a request still breaks the signature, and Bedrock answers
`403`: edits at a breakpoint, generic JSON rewrite operations, a rules script that
changes the request, and replays with a changed body. Replay the request unchanged, or make
the change in the agent itself.

## Recording stopped: "Recording suspended (disk)"

The disk has less free space than *Settings → Bodies & Storage → Stop recording below free
space*. Free some space, remove sessions, or lower the limit. Traffic keeps flowing while
recording is suspended.

## A packet capture shows HTTPS only as tunnels

The key log has no secrets for those connections — it was recorded at another time, by
another program, or not at all. Choose the right key log with *Choose key log file…* in the
status bar after the import, put it next to the capture as `<name>.keys`, or set it in
*Settings → HTTPS → Packet captures*. Programs only write a key log when `SSLKEYLOGFILE` is
set in the environment they were started from (start the browser from that shell). When
*Properties* of a tunnel says its version or cipher suite cannot be decrypted (TLS 1.0/1.1,
for example), no key log helps. See [Packet captures](packet-captures.md#decrypting-https).

## A packet capture says "no HTTP traffic found"

The summary in the message tells what the file holds instead: connections that are not
HTTP, packets of an unsupported link type (Wi-Fi monitor mode, USB …), or missing packets
everywhere. Record on the interface the traffic passes (`tcpdump -i any` on Linux,
`-i all` on macOS), with whole packets. See [Packet captures](packet-captures.md).

## Where are my settings and captures?

In the [data directory](settings.md#data-directory), or in `quena-data` next to the
executable in [portable mode](settings.md#portable-mode).

## How do I remove everything Quena changed?

1. *Capture → HTTPS Settings… → Remove from trust store*.
2. Quit Quena (this restores the system proxy).
3. Remove saved passwords under *Settings → Authentication → Credentials*.
4. Delete the data directory (or the portable folder).
