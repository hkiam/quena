# Capturing traffic

Quena is a proxy: applications send their requests to Quena, and Quena forwards them to the
server (or to the next proxy) and records both directions.

## Start and stop

- The **capture switch** at the left of the toolbar shows *Capturing* or *Paused*. Click it,
  press `F12`, use *Capture → Capture Traffic*, or type `start` / `stop` in the command field.
- While the system proxy is being changed, the switch shows *Starting…* or *Stopping…*.
- Stopping the capture also closes open client connections, tunnels and WebSockets (after
  the request in flight), so nothing more is recorded.
- *Settings → General → Capture traffic on startup* (on by default) decides whether Quena
  captures right after it starts.

## Start a browser or terminal with Quena

Without changing the system proxy, Quena can start programs whose traffic goes through it:
the **globe button** next to the capture switch, *Capture → Start Browser…*,
*Capture → Open Terminal* and *Capture → Start Agent…*. Capturing starts if it is off.

- **Browsers.** Quena finds Chrome, Edge, Brave, Vivaldi, Chromium and Firefox and starts the
  chosen one with **its own profile** (kept in Quena's data folder, so logins stay) and Quena as
  proxy. Your normal browser windows are not affected.
    - Chrome, Edge, Brave, Vivaldi and Chromium accept Quena's certificates in that profile
      without the root certificate being trusted by the system
      (`--ignore-certificate-errors-spki-list`). Chromium shows a notice about this
      "unsupported command-line flag"; it applies to this profile only. Requests to
      `localhost` go through Quena too.
    - Firefox uses the system's trusted roots: trust the Quena root certificate first
      ([HTTPS and devices](https.md)).
    - *Start with URL…* opens the dialog to enter a start page.
- **Terminal.** A new terminal window (Terminal.app, Windows Terminal or `cmd`, or the Linux
  terminal found) whose shell has:
    - `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` (also in lower case) pointing to Quena;
    - `NODE_EXTRA_CA_CERTS` and `CODEX_CA_CERTIFICATE` with Quena's root certificate (Node.js
      programs such as Claude Code and Gemini CLI, and Codex, add it to their own roots);
    - on macOS and Linux also `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`,
      `GIT_SSL_CAINFO`, `AWS_CA_BUNDLE`, `PIP_CERT` and `CARGO_HTTP_CAINFO` with a bundle of
      the system's roots plus Quena's (`quena-ca-bundle.pem` in the data folder).

    On Windows, curl, Git and Python use the system store: trust the Quena root certificate
    there. Java has its own trust store; import the certificate with
    `keytool -importcert -cacerts -alias quena -file quena-root-ca.pem`.

- **AI agent.** *Start Agent…* (or *Start Claude Code* / *Start Codex* in the globe button's
  menu) opens such a terminal and runs the agent's command in it (`claude`, `codex`, `gemini`
  …, in your login shell, so its `PATH` finds it); the shell stays open after it. Its calls to
  the model and to MCP servers over HTTP go through Quena and show in the [Agents
  panel](llm.md#conversations-of-agents). HTTPS decryption must be on.

Agents can do the same with the MCP tools `launch_browser` and `open_terminal`.

## Listen port

Quena listens on **port 8866** by default (`127.0.0.1:8866`). Change it in
*Settings → Connections → Listen port*. The status bar shows the address Quena listens on.

## System proxy

With *Settings → Connections → Act as system proxy while capturing* (on by default), Quena
registers itself as the system proxy while it captures, so browsers and most desktop
applications send their traffic through it automatically.

| Platform | What Quena changes |
|---|---|
| macOS | the proxy of all network services (changed at once) |
| Windows | the proxy of the current user |
| Linux | the GNOME or KDE Plasma proxy setting that browsers follow |

Quena's own exceptions while it captures: on macOS and Linux `*.local` and `169.254/16`
(Bonjour names and link-local addresses, as in the macOS defaults); on Windows none. In
particular, Windows' *Don't use the proxy server for local (intranet) addresses* stays
off, so intranet and VPN hosts without a dot (`http://appserver/`) are recorded too. The
exceptions of the previous proxy are not lost: those hosts still go direct from Quena
instead of through the upstream proxy (see [Upstream proxy and PAC](#upstream-proxy-and-pac)).

The previous proxy setting is saved and **restored when you quit** — and, if Quena ever
crashes, at the next start. On Windows, logging off or shutting down while Quena runs
restores it as well.

### Tools that ignore the system proxy

Command-line tools usually do not follow desktop proxy settings. Point them at Quena
explicitly:

```bash
curl -x http://127.0.0.1:8866 https://example.com

export HTTP_PROXY=http://127.0.0.1:8866
export HTTPS_PROXY=http://127.0.0.1:8866
```

For HTTPS, such tools must also trust Quena's root certificate — see
[HTTPS and devices](https.md).

Clients that take no proxy at all (a backend with a fixed API URL, a container, a webhook
sender, gRPC) can call a [reverse proxy](reverse-proxy.md) port of Quena instead: it
forwards everything to one target (or one per path) and records it. Clients that speak
SOCKS, and connections a firewall redirects, have [ports of their own](socks-transparent.md).

## Upstream proxy and PAC

In a corporate network, Quena forwards to the proxy you used before. The options are in
*Settings → Connections*:

| Option | Meaning |
|---|---|
| *Chain to the previous system proxy (upstream gateway)* | On by default: the proxy that was active before Quena took over becomes Quena's upstream. |
| *Manual upstream proxy* | `host:port` of a proxy to use instead. A manual upstream overrides PAC. |
| *Bypass upstream for* | Hosts that go direct instead of through the upstream. Default: `localhost;127.0.0.1;::1;*.local`. Patterns: `*.corp.example`, `10.1.*`, networks (`10.0.0.0/8`, `169.254/16`) and `<local>` for names without a dot. With the chained system proxy, its exceptions apply as well. |
| *Use the system proxy auto-config (PAC) script* | On by default: evaluate the PAC script the OS proxy settings point to. |
| *PAC URL or file* | A PAC script of your own (`http://…/proxy.pac`, `file://…` or a local path). Empty means the system PAC. |

PAC notes:

- `FindProxyForURL(url, host)` is evaluated once per host and cached.
- `https://` PAC URLs are not fetched — download the file and enter its path instead.
- The download must finish within 15 s and be at most 1 MB. A script that hangs or fails
  falls back to `DIRECT` for that lookup, so a broken PAC file never stalls the app.

If the upstream proxy asks for authentication (`407`), Quena can answer it — see
[Automatic authentication](authentication.md).

## Remote computers and devices

Remote connections are **off by default**. To capture a phone, a tablet, a VM or another
computer:

1. Enable *Settings → Connections → Allow remote computers to connect* (or click the button
   in *Capture → Connect Device…*).
2. Optionally restrict who may connect with *Allowed remote networks*: CIDR ranges or
   addresses separated by `;` (e.g. `192.168.1.0/24; 10.0.0.5`). Empty means local subnets.
3. Configure the device to use your computer's address and port 8866 as its HTTP proxy.

*Capture → Connect Device…* walks you through this with a QR code — see
[Phones, tablets and VMs](https.md#phones-tablets-and-vms).

## Which application sent a request

Quena attributes each request to the process that sent it. The name appears in the
*Process* column (hidden by default in the Quena layout, visible in Classic) and in the
inspector header.

| Platform | Process attribution |
|---|---|
| macOS | ✅ |
| Windows | ✅ |
| Linux | ✅ for processes of your own user (via `/proc`) |

Use it to narrow the list:

- **Status bar → process scope**: *All processes*, *Browsers only*, *Non-browsers* or
  *Remote clients*.
- **Filters → Client Process**: the same choices, plus *Show only traffic from* and
  *Hide traffic from* (e.g. `chrome; java`).
- **Right-click a session → Filter Now → Hide this Process / Show only this Process**.
- **Right-click → Select → Same Process**.

## Streaming and storage

- **Stream** (toolbar toggle, on by default) passes response bodies to the client as they
  arrive. Turned off, Quena buffers the response first.
- **Keep** (toolbar button with the history icon) keeps only the newest 100, 200, 500,
  1,000 or 10,000 sessions; the default is *Keep all sessions*.
- Bodies are stored on disk, not in memory, so large downloads do not fill the RAM. The
  status bar shows how much the capture uses and how much disk space is free. The limits
  are in *Settings → Bodies & Storage*; see [Settings](settings.md#bodies-storage).
