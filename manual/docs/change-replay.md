# Change and replay

## Replay

Select one or more sessions and replay their requests:

| Command | Key | Effect |
|---|---|---|
| *Replay Requests* | `R` | Send the requests again. |
| *Replay Unconditionally* | `U` | Send them again without conditional headers (`If-Modified-Since`, `If-None-Match`, `If-Match`, `If-Unmodified-Since`, `If-Range`), so the server sends a full response. |
| *Replay Sequentially…* | `Shift R` | Ask for a repeat count (up to 10,000) and send the requests that many times, one after another. |
| *Replay and Edit* | | Send the request with a breakpoint, so you can change it before it goes out. |
| *Replay from Composer* | | Load the request into the Composer. |

The commands are in the context menu (*Replay*) and behind the **Replay** button in the
toolbar. Replayed sessions appear as new sessions. Tunnels cannot be replayed.

## Composer

The **Composer** (`F9`, *Tools → Composer*) builds a request from scratch or from a
recorded one.

- **Parsed** — method, URL, request headers (one `Name: value` per line) and body. The body
  can be text, a file (*Upload file…*) or the body of a recorded session.
- **Raw** — the whole request as text. Paste a raw HTTP request, or paste a **cURL command**
  and click **Import as cURL** to turn it into a parsed request.
- **History** — the last requests you issued. Click to load, double-click to send again.

Click **▶ Execute** (or press `Enter` in the URL field). Options:

- *Fix Content-Length* — set `Content-Length` to the actual body length.
- *Inspect session* — select the new session and open *Inspect* after sending.

To load a recorded request, drag a session from the list onto the Composer, or right-click
→ *Replay → Replay from Composer*.

A loaded body is shown in its charset (see [Character encodings](inspect.md#character-encodings)).
As long as you do not change the text, the original bytes are sent. Edited text is sent in
the charset the `Content-Type` declares, else in the charset it was shown in, else UTF-8.
If it contains characters that charset cannot represent (an emoji in a Latin-1 form), it is
sent as UTF-8 and the `Content-Type` gets `charset=utf-8`, so the declaration stays true.

## Breakpoints and tampering

A breakpoint pauses a session so you can look at it and change it — before the request
goes to the server, or after the response arrives and before it reaches the client.

### Setting breakpoints

| Breakpoint | How |
|---|---|
| Before every request | `F11`, *Capture → Breakpoints → Before Requests* |
| After every response | `Alt F11`, *Capture → Breakpoints → After Responses* |
| All off | `Shift F11`, *Capture → Breakpoints → Off* |
| Before requests whose URL contains a text | `bpu /api` |
| After responses whose URL contains a text | `bpafter /api` |
| On a response status | `bps 500` |
| On a request method | `bpv POST` (or `bpm POST`) |
| From a Mock Rule | action `*bpu` or `*bpafter` |

A command without an argument (e.g. `bpu`) switches that breakpoint off. The status bar
lists the active breakpoints and the number of paused sessions.

### Working with a paused session

Paused sessions are marked red in the list. Select one: the inspector shows a breakpoint
bar and the paused part becomes editable — **headers** as text, and the **body** as text or
replaced by a file. `Content-Length` is fixed automatically. An unchanged body is
forwarded byte for byte; an edited one is encoded like in the Composer (declared charset,
else the one it was shown in; UTF-8 with an adjusted `Content-Type` if it does not fit).

| Button | Effect |
|---|---|
| *Run to Completion* | Continue with your changes. |
| *Break on Response* | (request) Continue, and pause again when the response arrives. |
| *Choose Response ▾* | (request) Answer locally with 200, 204, 302, 401, 403, 404, 500, 502 or 503 instead of contacting the server. |
| *Abort* | Drop the session. |

To release everything at once, press the **Resume** button in the toolbar (it shows the
number of paused sessions) or type `g` in the command field.

## Mock Rules

**Mock Rules** answer or redirect requests that match a pattern — to test error handling,
work against a server that is not there yet, or replace a file with a local version. Open
the **Mock Rules** tab (*Capture → Mock Rules*).

- **Enable rules** switches the whole set on or off. While rules are active, the tab shows a
  dot and the status bar shows *Mock Rules*.
- **Unmatched requests passthrough** (on by default): requests that match no rule go to the
  server as usual. Off, they are answered with `404`.
- **Enable Latency**: apply each rule's *Latency (ms)* before answering.
- Rules are evaluated **top to bottom; the first match wins.** The *Hits* column counts
  matches.
- Right-click a rule: *Enable/Disable*, *Match only once*, *Clone*, *Move up/down*, *Remove*.

### Adding rules

- **Add Rule**, then fill in *If request matches* and *then respond with* in the editor
  below and click *Add*. Both fields offer templates.
- **From recorded sessions**: right-click sessions → *Mock Rules → Add Rule* (URL contains)
  or *Add Rule (Exact URL)*, or drag sessions from the list onto the Mock Rules tab. The
  rule answers with the recorded response (`session:<id>`). Rules are switched on.
- **Add mapping…** creates [Map Remote](#map-remote) and [Map Local](#map-local) rules.

### Match patterns

| Pattern | Matches when |
|---|---|
| `*` | always |
| `text` | the URL contains `text` (case-insensitive) |
| `EXACT:https://example.com/path` | the URL is exactly this |
| `prefix:https://example.com/api/` | the URL starts with this (case-insensitive); the rest is handed to the action |
| `regex:(?i)^https://.*\.example\.com/api/(.*)$` | the regular expression matches the URL |
| `NOT:tracking` | the URL does **not** contain the text |
| `METHOD:POST /login` | the method matches and the rest of the pattern matches |
| `HEADER:Accept=json` | a request header contains the value |
| `URLWithBody:/soap regex:GetOrder` | the URL pattern matches and the request body matches the regex |

### Actions

| Action | Response |
|---|---|
| a file path | the file: either a raw HTTP response (starting with `HTTP/`, e.g. a `.dat` file) or a plain body served as `200` with a Content-Type from the extension (*Find a file…* picks one) |
| `session:12` | the recorded response of session 12 |
| `*404`, `*500`, … | a generated response with that status |
| `*drop` | close the connection without a response |
| `*delay:2000` | forward to the server after waiting 2,000 ms |
| `*redir:https://example.com/` | a `307` redirect to that URL |
| `*header:X-Quena=1` | forward, with the request header set |
| `*CORSPreflightAllow` | a `200` that allows the CORS preflight (origin, methods, headers, credentials) |
| `*bpu`, `*bpafter` | pause at a breakpoint before the request / after the response |
| `https://other.example/…` | forward the request to this URL instead (see Map Remote) |
| `dir:/path/to/folder` | serve a file from this folder (see Map Local) |

With a `regex:` match, `$1` … in an `https://…` action is replaced by the capture groups.

### Map Remote

Forward everything under a URL prefix to another server — for example to test a
production front end against a staging API.

*Add mapping… → Map Remote…*: enter the **From URL prefix** and the target. This creates:

```text
prefix:https://prod.example.com/api/   →   https://staging.example.com/api/
```

The rest of the path and the query are kept: `…/api/users?id=1` goes to
`https://staging.example.com/api/users?id=1`. The `Host` header follows the target.

A prefix that is only an origin (`https://prod.example.com`) matches that origin exactly —
not `https://prod.example.com.other.net` or another port.

**Credentials.** By default the request is forwarded as it is, cookies and
`Authorization` included. When the target is another host (or http instead of https), the
form's option *Remove credentials (Cookie, Authorization) when the host changes* — on by
default — appends ` *nocreds` to the action:

```text
prefix:https://prod.example.com/api/   →   https://staging.example.com/api/ *nocreds
```

Then `Cookie`, `Authorization` and `Proxy-Authorization` are not sent to the other host, so
production credentials don't end up on a test server.

### Map Local

Serve a folder on your disk under a URL prefix — for example to try local builds of static
files against a live site.

*Add mapping… → Map Local…*: enter the prefix and the folder. This creates:

```text
prefix:https://example.com/static/   →   dir:/path/to/folder
```

- The file at the rest of the path is served; a folder serves its `index.html`.
- Content-Type follows the file extension.
- A missing file gets a clear `404`.
- Nothing outside the folder is ever served: `..`, encoded `%2e%2e`, backslashes and
  symlinks that point outside are refused with `403`.

A `dir:` action uses the rest after a `prefix:` match; with a `regex:` match it uses group
1, and otherwise the whole URL path.

A remapped session is listed with its **new** URL; its comment names the original one, and
the session flags `x-quena-mapped-from` and `x-quena-mapped-to` keep both ends.

### Import and export (`.farx`)

**Import…** reads a `.farx` rule file (as written by Fiddler Classic's AutoResponder),
**Export…** writes the current rules as `.farx`. Enabled state, passthrough and latency
settings travel with the file.

## Latency

Three ways to slow things down:

- a Mock Rule's *Latency (ms)*, with *Enable Latency* checked;
- the action `*delay:<ms>`, which forwards to the server after the delay;
- global [bandwidth and latency simulation](network.md#bandwidth-and-latency-simulation).
