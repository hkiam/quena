# Troubleshooting and FAQ

## No traffic appears

- Is the capture switch on (*Capturing*)? Press `F12`. The status bar shows the address
  Quena listens on and a *system proxy* tag when it registered itself.
- Is *Settings → Connections → Act as system proxy while capturing* on? Without it,
  applications must be pointed at `127.0.0.1:8866` by hand.
- Command-line tools and many runtimes (Node.js, Java, Python …) ignore the desktop proxy
  setting. Use their proxy option or `HTTP_PROXY`/`HTTPS_PROXY` — see
  [Tools that ignore the system proxy](capture.md#tools-that-ignore-the-system-proxy).
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

The packages are not notarized yet. Open *System Settings → Privacy & Security* after the
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

## An AI agent cannot connect

See [AI agents → Check the connection](mcp.md#check-the-connection). After *OK* in the
options, Quena reports when the server could not start (for example, the port is in use).

## Recording stopped: "Recording suspended (disk)"

The disk has less free space than *Settings → Bodies & Storage → Stop recording below free
space*. Free some space, remove sessions, or lower the limit. Traffic keeps flowing while
recording is suspended.

## Where are my settings and captures?

In the [data directory](settings.md#data-directory), or in `quena-data` next to the
executable in [portable mode](settings.md#portable-mode).

## How do I remove everything Quena changed?

1. *Capture → HTTPS Settings… → Remove from trust store*.
2. Quit Quena (this restores the system proxy).
3. Remove saved passwords under *Settings → Authentication → Credentials*.
4. Delete the data directory (or the portable folder).
