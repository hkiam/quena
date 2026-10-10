# Host remapping

**Capture → Host Remapping…** sends connections to a host to another host, IP address or
port, like an entry in the hosts file. It applies only to traffic through Quena, and no
administrator rights or DNS changes are needed.

Typical uses:

- test the production URL against a staging or canary server (`api.example.com` →
  `10.0.0.5`);
- point an app's backend at a local build (`api.example.com` → `127.0.0.1:8080`);
- try a new server before the DNS change, or one server out of a pool.

| Column | Meaning |
|---|---|
| *Host, \*.domain or host:port* | The name the client uses: `api.example.com`, or `*.example.com` for all subdomains (and `example.com` itself); with `:port` only connections to that port (`api.example.com:8443`). The most specific entry wins (one with a port first). |
| *Target* | `host`, `IP` or `host:port` (IPv6 as `[::1]:8443`). Without a port, the original port is kept. |
| *Protocol* | *as sent* (default), or **HTTP** / **HTTPS** to the target whatever the client used — e.g. the HTTPS URL of production to a local HTTP dev server (`localhost:3000`). Without a target port, the other protocol's default port is taken (443 → 80). The client must send HTTPS through Quena with decryption on; undecrypted tunnels keep their protocol. Cannot be combined with a port in the pattern. |
| *keep host* | On (default): the request keeps its `Host` header and TLS server name (SNI), and the server's certificate is checked for the original name — only the connection moves. Off: the request is sent to the target as if it had been addressed there (URL, `Host` and SNI of the target). |

- *Import hosts file…* adds the entries of the system's hosts file (`/etc/hosts`, or
  `C:\Windows\System32\drivers\etc\hosts`), without `localhost`.
- Changes take effect with **Save**. Entries are checked when saving.
- The status bar shows *↪ N remaps* while remapping is on; click it to open the dialog.

Remapping applies to everything Quena forwards:

- requests through the proxy port, SOCKS, transparent and [reverse proxy](reverse-proxy.md)
  ports;
- HTTPS that is not decrypted (the tunnel goes to the target).

Remapped hosts **bypass the upstream proxy**, like a hosts-file entry. A target that is one of
Quena's own ports is refused, to prevent a request loop.

## In the session list

A remapped session has the flag `x-quena-remap`, e.g.
`api.example.com:443 → 10.0.0.5:443` (*Inspect → Raw*, MCP `get_session`). The connection
details show the address actually used.

## Remapping or Map Remote?

| | Host remapping | [Map Remote](change-replay.md#map-remote) |
|---|---|---|
| Changes | where the connection goes | the URL of the request |
| Unit | a host name (or `*.domain`) | a URL prefix or regex |
| Host header, SNI | kept (by default) | the target's |
| Also for undecrypted HTTPS tunnels | yes | no |

## Without a window and for agents

- `quena-cli reverse --remap api.example.com=10.0.0.5` (repeatable) — see
  [Reverse proxy](reverse-proxy.md#without-a-window-quena-cli-reverse).
- MCP tools `list_host_remaps`, `set_host_remap` and `remove_host_remap`.
