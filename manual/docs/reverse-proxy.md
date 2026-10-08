# Reverse proxy

Some clients cannot be pointed at a proxy: a backend calling an API, a service in a
container, a test suite, a webhook sender, an app with a fixed base URL, a gRPC client.
For them Quena can listen on an extra local port and forward **every** request on it to
one fixed target. The client talks to `http://localhost:8080` as if it were the server.
Quena forwards each request to, for example, `https://api.example.com` and records the
exchange like any other session.

```text
client ──▶ localhost:8080 (Quena) ──▶ https://api.example.com
```

Everything that works for proxied traffic works here too: breakpoints,
[Mock Rules](change-replay.md#mock-rules) (also Map Remote and Map Local),
[rewrite rules](change-replay.md#rewrite-rules), [rules scripts](scripting.md), automatic
authentication, the upstream proxy, client certificates and throttling. Quena then sits as
a gateway in front of a backend, and you can change that gateway's traffic.

## Set it up

1. Open **Capture → Reverse Proxy…**. The dialog is also in the command palette, and there
   is a button in *Settings → Connections*.
2. Click **Add entry…**.
3. Enter the **Local port** (the port your client will call) and the **Target**: an
   `http://` or `https://` URL, optionally with a port and a base path, e.g.
   `https://api.example.com/v1`.
4. Click **Add**. Adding the first entry also switches on **Enable reverse proxy ports**.

The ports listen **while capturing**. They start and stop with *Capture Traffic* (`F12`),
together with the proxy port. The status bar shows how many reverse proxies are running
(*⇄ 1 reverse proxy*); click it to open the dialog. **Copy address** copies the address
clients call.

A port that cannot be opened (it is taken, or it is below 1024 without administrator
rights) is shown as *error* in the dialog and in the status bar. The proxy port and the
other entries keep running. Unlike the proxy port, a reverse proxy port never moves to
another port: clients expect it where you configured it.

To start an entry from captured traffic, right-click a session and choose
**Reverse Proxy for this Host…**. The target is then filled in from the session.

## Options of an entry

| Option | Default | Meaning |
|---|---|---|
| *Name* | the target's host | Shown in the *Via* column and in the status bar. |
| *Local port* | the first free port from 8080 | The port clients call. |
| *Target* | | `http(s)://host[:port][/base path]`. The base path goes in front of every request path: `/users` on the port becomes `/v1/users` at the target. |
| *Path routes* | none | Other targets for some paths, see [below](#path-routes). |
| *Clients speak* | *HTTP or HTTPS (detected)* | *Detected* accepts TLS and plain HTTP on the same port, and cleartext HTTP/2 (h2c, gRPC without TLS). *HTTP only* or *HTTPS only* refuse the other kind. |
| *Certificate name* | `localhost` | Name in the certificate for TLS clients that send no server name (SNI). Clients that send one get a certificate for that name. |
| *Keep the client's Host header* | off | Off: the target gets its own name as `Host`. On: it gets the name the client used, e.g. for virtual hosts that expect the public name. |
| *Point redirects to the target back to this port* | on | A `Location` or `Content-Location` header that names the target (inside the base path) is changed to the address the client called. The browser therefore stays on Quena. |
| *Remove the Domain of cookies the target sets* | off | Removes `Domain=` from `Set-Cookie`, so cookies stick to the host the client called. |
| *Add X-Forwarded-For, -Proto and -Host* | off | Tells the target the client's address, its scheme and the host it called. Off by default, so the request reaches the target as the client sent it. |
| *Allow remote computers to connect* | off | Listen on all interfaces instead of only on this machine. Clients must be in *Allowed remote networks* (*Settings → Connections*). |

The session list shows **what the target sent**. When Quena changed a header on the way
back to the client (*Location*, *Set-Cookie*), the session says so in its flags
(`x-quena-reverse-rewrite`), for example in *Inspect → Raw* and in the MCP tool
`get_session`.

## Path routes

One port can serve several backends, for example a web app with its API and its login on
different servers. Each path route has a **prefix** and a **target**. A request whose path
starts with the prefix goes to the route's target. The longest matching prefix wins, and
all other requests go to the entry's target.

| Prefix | Target | *remove prefix* | `/auth/login` goes to |
|---|---|---|---|
| `/auth` | `https://sso.example.com` | on | `https://sso.example.com/login` |
| `/auth` | `https://sso.example.com` | off | `https://sso.example.com/auth/login` |
| `/auth` | `https://sso.example.com/v2` | on | `https://sso.example.com/v2/login` |

A prefix matches whole path segments: `/api` takes `/api` and `/api/users`, not `/apiary`.
`Host`, redirects and cookies follow the target the request went to. A redirect from
`https://sso.example.com/done` therefore comes back to the client as `/auth/done`.

## HTTPS

- **HTTPS to the target** works like for proxied traffic: the target's certificate is
  checked unless *Ignore server certificate errors* allows it (*Capture → HTTPS Settings…*),
  and client certificates (mTLS) are presented when they match the target's host.
- **HTTPS from the client:** Quena answers with a certificate from its root certificate
  (created when needed). The client has to trust that root certificate. Install it with
  *Capture → HTTPS Settings… → Trust root certificate…*, or give the exported file to the
  client, e.g. `curl --cacert`, `NODE_EXTRA_CA_CERTS`, the Java `cacerts` store or
  `REQUESTS_CA_BUNDLE`.

## gRPC and HTTP/2

- gRPC with TLS uses HTTP/2 through ALPN, as with proxied traffic.
- gRPC without TLS (an *insecure channel*) speaks cleartext HTTP/2 from the first byte. With
  *HTTP or HTTPS (detected)* or *HTTP only*, Quena recognises it and records the calls.
- WebSockets (HTTP/1.1 upgrade) are forwarded and recorded frame by frame.

## Session list

Every request that came through a reverse proxy port names its entry. Requests from the
[SOCKS and transparent ports](socks-transparent.md) show `SOCKS5` or `transparent` the same
way:

- the **Via** column (hidden by default; right-click the heading row to show it),
- *Group by → Via*,
- the filter `via == api` (see [filter expressions](syntax.md#filter-expressions)).

The entry's name is stored with the session (`x-quena-via`), also in `.saz`
archives.

## Security

- Reverse proxy ports listen on this machine only, unless an entry allows remote computers.
- A reverse proxy port forwards to its target and nowhere else. It does not accept
  `CONNECT` (405), so it never becomes an open proxy for other hosts.
- A target that points back to one of Quena's own ports is refused, to prevent a request
  loop.
- Agents (MCP) can add and change entries when you granted them full control, but they
  cannot open an entry to remote computers.

## Without a window: `quena-cli reverse`

`quena-cli` runs the same reverse proxy headless, for example in CI in front of the
service your integration tests call, or as a sidecar container. It prints an access log
and saves the sessions at the end:

```sh
quena-cli reverse --route api=8080=https://api.example.com --save run.saz
```

```text
quena-cli: api 127.0.0.1:8080 → https://api.example.com
 200    42 ms  GET     https://api.example.com/users  [api]
 404    18 ms  GET     https://api.example.com/nope  [api]
```

It stops on Ctrl-C or SIGTERM (a second signal ends it at once), after `--duration`
seconds or after `--max-sessions`, and then writes `--save` (`.saz` or `.har`). The archive
can go straight into [`quena-cli diagnose`](ci.md) or into
[`quena-cli mock`](mocks.md).

| Option | Effect |
|---|---|
| `--route [NAME=]PORT=URL` | listen on `PORT` and forward to `URL` (repeatable) |
| `--path PORT/PREFIX=URL` | a [path route](#path-routes) on the `--route` of `PORT` (repeatable) |
| `--strip-prefix` | remove the prefix of the `--path` routes from the forwarded path |
| `--socks PORT`, `--transparent PORT` | also open the [SOCKS and transparent ports](socks-transparent.md) (then `--route` is optional; `quena-cli serve` is the same command) |
| `--decrypt` | decrypt HTTPS inside SOCKS and transparent connections (clients must trust the root certificate) |
| `--protocol auto\|http\|https` | what clients speak (default `auto`) |
| `--preserve-host`, `--forwarded-headers`, `--rewrite-cookie-domain`, `--no-rewrite-location` | as the options above |
| `--bind-all`, `--allow CIDR` | listen on all interfaces; clients from these networks (default: private ranges) |
| `--ca-dir DIR` | keep the root certificate in `DIR`, so clients trust it once (otherwise every run makes a new one and prints its path) |
| `--insecure` | do not check the target's certificate |
| `--upstream HOST:PORT` | upstream proxy for the targets |
| `--rules PATH` | Mock Rules from a Fiddler `.farx` file or a Quena mock package |
| `--save PATH` | save the sessions at the end (`.saz`, `.har`) |
| `--duration SECONDS`, `--max-sessions N` | stop after this time or this many sessions |
| `-q`, `--quiet` | no access log |

Exit code 0 on a normal stop. Exit code 2 for a wrong `--route`, an invalid target, a port
that is taken or an unsupported `--save` type.

### Docker

The `quena-cli` image runs it as well. Publish the port and listen on all interfaces inside
the container:

```sh
docker run --rm -p 8080:8080 -v "$PWD:/work" ghcr.io/hkiam/quena-cli \
  reverse --bind-all --route api=8080=http://host.docker.internal:3000 --save /work/run.saz
```

As a sidecar in Docker Compose, in front of the service your tests call:

```yaml
services:
  app:
    image: my-backend
  quena:
    image: ghcr.io/hkiam/quena-cli
    command: ["reverse", "--bind-all", "--route", "app=8080=http://app:3000", "--save", "/work/run.saz"]
    volumes: ["./captures:/work"]
  tests:
    image: my-tests
    environment:
      API_BASE_URL: http://quena:8080
```

`docker compose stop quena` sends SIGTERM: quena-cli stops and writes `run.saz`.
