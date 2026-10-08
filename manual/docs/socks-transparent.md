# SOCKS and transparent ports

Besides the proxy port and [reverse proxy](reverse-proxy.md) ports, Quena can open two more
ports in *Settings → Connections*. Both are off by default, listen only on this machine
unless *from other computers too* is ticked, and run while capturing, like the proxy port.

| Port | Default | For |
|---|---|---|
| *SOCKS5/4 port* | 8868 | Clients that support SOCKS but not HTTP proxies, or where a SOCKS setting is easier to set. |
| *Transparent port* | 8869 | Connections the firewall redirects to Quena, from clients that know nothing about a proxy. |

What arrives on them is handled like a `CONNECT` tunnel on the proxy port:

- **HTTPS** is decrypted when *Decrypt HTTPS traffic* is on (*Capture → HTTPS Settings…*),
  with the same scopes and exceptions. The clients must trust the Quena root certificate.
- **Plain HTTP** is recorded request by request.
- **Anything else** (databases, SSH, mail) is passed through and shown as a tunnel with its
  byte counts.

The *Via* column, *Group by → Via* and the filter `via == SOCKS5` or `via == transparent`
show which sessions came in this way. The status bar shows the open ports; click one to
open the settings.

## SOCKS

Quena speaks SOCKS5 (with or without a user name and password; any credentials are
accepted) and SOCKS4/4a. It supports `CONNECT` only, so UDP and `BIND` are refused.

```bash
curl --socks5-hostname 127.0.0.1:8868 https://example.com      # host name resolved by Quena
export ALL_PROXY=socks5h://127.0.0.1:8868                       # many CLI tools
git config --global http.proxy socks5h://127.0.0.1:8868
java -DsocksProxyHost=127.0.0.1 -DsocksProxyPort=8868 -jar app.jar
```

Browsers have a SOCKS setting in their network options (Firefox: *Manual proxy
configuration → SOCKS Host*, with *Proxy DNS when using SOCKS v5*).

## Transparent

With transparent capture, clients connect to their real server, and a firewall rule
redirects these connections to Quena's transparent port. Quena finds the original target
in this order:

1. **The original destination of the connection.** Linux (iptables/nftables `REDIRECT`)
   tells it to Quena. Every TCP port works this way.
2. **The TLS server name (SNI)**, then port 443.
3. **The `Host` header** of plain HTTP, then port 80.

On macOS and Windows Quena does not learn the original destination, so 2. and 3. decide:
redirect only ports 80 and 443 there.

Quena's own connections to the targets must not be redirected again. Otherwise they come
back to Quena, and it refuses them as a loop.

### Linux: apps on this machine

Run Quena as its own user, so the rules can leave its traffic alone. The example uses the
headless `quena-cli` (see [Reverse proxy → Without a window](reverse-proxy.md#without-a-window-quena-cli-reverse)):

```bash
sudo useradd --system --create-home quena
sudo -u quena quena-cli serve --transparent 8869 --decrypt --ca-dir /home/quena/ca --save /tmp/run.saz &
for ip in iptables ip6tables; do
  sudo $ip -t nat -A OUTPUT -p tcp -m owner ! --uid-owner quena -m multiport --dports 80,443 -j REDIRECT --to-ports 8869
done
```

Remove the rules again with `-D` instead of `-A`. Clients must trust
`/home/quena/ca/quena-root-ca.pem`, e.g. through `update-ca-certificates`,
`NODE_EXTRA_CA_CERTS` or `REQUESTS_CA_BUNDLE`.

### Linux: devices routed through this machine

On a router, a VM host or a Docker host, redirect forwarded traffic. Tick *from other
computers too* (or pass `--bind-all` to `quena-cli`):

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports 8869
```

### macOS: devices using this Mac as gateway

For devices on *Internet Sharing*, or devices with this Mac as their router, redirect
their web traffic with pf and tick *from other computers too*:

```bash
sudo sysctl -w net.inet.ip.forwarding=1
echo "rdr pass on en0 inet proto tcp to any port {80, 443} -> 127.0.0.1 port 8869" | sudo pfctl -ef -
sudo pfctl -F nat     # remove the rule again
```

For apps on the Mac itself, use the system proxy (Quena's default), SOCKS or a
[reverse proxy](reverse-proxy.md) instead.

!!! note
    Quena changes no firewall rules itself. They need administrator rights and affect the
    whole machine; set them up and remove them as shown above.
