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
- **Collections** — saved requests, see [Collections in the Composer](#collections-in-the-composer).

Next to the URL, the **HTTP version** is *Automatic* (what the server offers, as for
proxied traffic), *HTTP/1.1* or *HTTP/2*. HTTP/2 over `https://` insists on HTTP/2 (an
error if the server does not offer it); over `http://` it is cleartext HTTP/2 with prior
knowledge (h2c), e.g. for gRPC servers without TLS.

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

## Request collections (`.http` files)

Quena runs `.http` files as written for the JetBrains HTTP Client and the VS Code REST
Client. The requests go through Quena like Composer requests: they appear in the session
list, and Mock Rules, rewrite rules and breakpoints apply.

```text
@base = {{host}}/v1

### List users
GET {{base}}/users?page=1
Authorization: Bearer {{token}}

### Create a user
# @name create
POST {{base}}/users
Content-Type: application/json

{"id": "{{$uuid}}", "name": "Test"}

### Upload
PUT {{base}}/files
Content-Type: application/json

< ./body.json
```

- Requests are separated by `###`; the text after it, or `# @name …`, names the request.
- `{{name}}` takes values from `@name = value` lines, then from the chosen environment in
  `http-client.env.json` next to the file, overridden by `http-client.private.env.json`
  (keep that one out of version control). An environment `$shared` applies to all.
- Dynamic values: `{{$uuid}}`, `{{$timestamp}}`, `{{$isoTimestamp}}`,
  `{{$randomInt 1 100}}`, `{{$processEnv NAME}}`.
- `< path` sends a file as the body; `<@ path` sends the file's text with its variables
  substituted.
- Response handler scripts (`> {% … %}`) and values from earlier responses are not
  supported; scripts are skipped with a warning, an unknown variable stops that request with
  its name and line.

A version after the URL (`GET {{base}}/users HTTP/2`) is used as in the Composer.

### Collections in the Composer

The Composer's **Collections** tab keeps requests as `.http` files in the `collections`
folder of the data directory — one file per collection, so they can be opened in an editor
or put under version control (*Open folder*).

- **Save to collection…** in the Composer's toolbar asks for a collection (an existing one
  or a new name) and a name for the request. A request loaded from a collection is saved
  back with **Save**; *Save as…* puts a copy elsewhere.
- Click a request to load it into the Composer. **▶** sends it, **▶ Run all** sends the
  collection's requests one after the other and lists status and time; click a result to
  select its session.
- Requests can be moved, duplicated and removed; **Variables** of the collection
  (`name = value`, used as `{{name}}`) are edited below its requests.
- **Environment** picks the environment of `http-client.env.json` /
  `http-client.private.env.json` in the collections folder.
- **Import .http…** copies an existing file (and its environment files, if the folder has
  none yet) into the collections.

A request with `{{variables}}` — from a collection or typed into the Composer — is sent with
the collection's variables and the chosen environment. Quena writes the files itself:
comments and response handler scripts of an imported file are not kept when it is saved.

AI agents use them over [MCP](mcp.md) (`list_http_requests`, `run_http_file`,
`sessions_to_http_file`; `collection:NAME` names a Composer collection, `list_collections`
lists them). On the command line:

```sh
quena-cli http run api.http --env dev            # all requests, one after the other
quena-cli http run api.http --env dev --name create --save run.har
quena-cli http from-har capture.har -o api.http  # captured requests as a collection
```

`http run` prints status and time per request and exits with 1 when a request fails or
answers with 400 or above. It sends directly (or through the system's upstream proxy),
without a listener and without touching the system proxy. `from-har` (and
`sessions_to_http_file`) puts a scheme and host shared by all requests into `{{host}}` of the
environment `captured`, and bearer tokens and cookies into `{{token}}` / `{{cookie}}` of the
private environment file. For agents, `.http` files and their body files must lie in the
[agents' folder](mcp.md#what-agents-see-and-touch), and `{{$processEnv}}` is refused.

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
| `URLWithBody:/soap regex:GetOrder` | the URL pattern matches and the request body (decoded, without `Content-Encoding`) matches the regex |
| `BODYJSON:EXACT:https://example.com/api/search {"q":"shoes"}` | the URL pattern matches and the request body is this JSON (key order and spacing do not matter; `"${json-unit.ignore}"` matches any value) |
| `GRAPHQL:/graphql {"operationName":"Cart","variables":{"id":1}}` | the URL pattern matches and the GraphQL request has this operation name and variables; an optional `"queryHash"` (SHA-256 in hex of the query text without comments and extra whitespace) also tells apart requests without an operation name or with the same name and variables |
| `BODYHASH:EXACT:https://example.com/api/upload 9f86d0…` | the URL pattern matches and the SHA-256 (hex) of the request body — decoded, without `Content-Encoding` — is this one (used by mocks for text and form bodies over 64 KiB) |

### Actions

| Action | Response |
|---|---|
| a file path | the file: either a raw HTTP response (starting with `HTTP/`, e.g. a `.dat` file) or a plain body served as `200` with a Content-Type from the extension (*Find a file…* picks one) |
| `session:12` | the recorded response of session 12 |
| `*404`, `*500`, … | a generated response with that status |
| `*drop`, `*reset` | close the connection without a response |
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

To send a whole host elsewhere while keeping its name (`Host`, TLS name and certificate),
use [host remapping](host-remapping.md) instead.

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

### Mocks from sessions

**Create from sessions…** in the Mock Rules tab (also *Mock Rules → Mocks from Sessions…* in
the session list's context menu and *File → Export Sessions → Mocks…*) turns recorded
sessions into a complete set of rules with their responses, into a shareable `.quena-mocks`
package, or into a WireMock export — see [Mocks from a capture](mocks.md).

### Import and export (`.farx`)

**Import…** reads a `.farx` rule file (as written by Fiddler Classic's AutoResponder),
**Export…** writes the current rules as `.farx`. Enabled state, passthrough and latency
settings travel with the file. *Match once* chains (the sequences of
[mocks from sessions](mocks.md)) cannot be expressed in `.farx` and are left out; an XML
comment in the file says so.

## Rewrite rules

Rewrite rules change **real** traffic on its way: the request still goes to the server, and
the rule edits the request before it leaves or the response before the client gets it.
That tests how an application copes with data it does not expect — an extra, broken element
in every list, a missing field, a 500 instead of a 200. Mock Rules, in contrast, answer
without the server.

Rules are made in the **Mock Rules** tab: *New rewrite rule…* opens the editor, a double-click
on a rule edits it, and a right-click offers *Enable/Disable*, *Clone*, *Move Up/Down*,
*Apply to selected sessions* and *Remove*. The list shows each rule's hit count, the switch
for all rules and the largest body a rule changes (*max. body*, default 4096 KiB). Rules are
kept in `rewrite.json` in the data folder. An AI agent can do the same over [MCP](mcp.md)
(`add_rewrite_rule`, `preview_rewrite`, `apply_rewrite_rules` …).

### The editor

- **Name**, and an optional **group**.
- **If request matches…**, **Change** (the request or the response), **Only status** and
  **Only content types**: the filters below.
- **Changes**, in their order. Each has its own fields: a JSONPath, a value as JSON (`"text"`,
  `42`, `null`, `{"a":1}`), a regular expression and replacement, a header, a status code. The
  form says what is wrong before saving.
- **Preview on #N** tries the rule on the session selected in the list, without sending
  anything: whether its filters take the session, the status and header changes, and the
  body before and after.

### Groups

Rules with the same **group** are switched on and off together with the group's chip above
the list, for example a set of "chaos tests" that you switch on when you need them. A rule
runs when it is on and its group (if any) is on.

### Apply to captured sessions

*Apply Rewrite Rules…* in a session's context menu, or *Apply to selected sessions* on a rule,
runs rules on sessions that were already recorded. Nothing is sent. Every session a rule
changes gets a **new copy** with the changes, marked as tampered with the comment
*Rewrite of #N*; the original stays as it was. You can choose all rules that are on, a group,
or one rule.

A rule has:

- **match**: the [match pattern](#match-patterns) of Mock Rules on URL, method and headers
  (`*`, `exact:`, `prefix:`, `regex:`, `METHOD:POST /orders`, `HEADER:Accept=json`,
  a URL substring);
- **phase**: `request` or `response` (default);
- **status** (responses): `200`, `4xx`, `500-599`, several with `,`; empty: any;
- **content type**: substrings separated by `;`; empty: JSON when the rule only has JSON
  operations, else any text type (JSON, XML, text, JavaScript, forms);
- **ops**, applied in order:

| Operation | Effect |
|---|---|
| `jsonSet {path, value}` | set every value the [JSONPath](https://www.rfc-editor.org/rfc/rfc9535) selects; a missing member of a plain path (`$.meta.debug`) is created |
| `jsonRemove {path}` | remove the selected values |
| `jsonAppend {path, value?}` | append to the selected arrays |
| `jsonAppendAll {value?}` | append to **every** array in the document, the root included |
| `regexReplace {pattern, replacement}` | replace in the body text; `$1`, `${name}` refer to groups |
| `setHeader {name, value}`, `removeHeader {name}` | change a header (not the framing headers) |
| `setStatus {code}` | change the response status |

Without `value`, `jsonAppend` and `jsonAppendAll` append a *broken copy* of the list's first
element: the same keys, all `null` (`[{"id":1,"name":"a"}]` becomes
`[{"id":1,"name":"a"},{"id":null,"name":null}]`). Example, a broken element in every list of
the API's responses:

```json
{ "match": "prefix:https://api.example.com/", "ops": [{ "op": "jsonAppendAll" }] }
```

What it costs and what it leaves alone:

- Without rules nothing changes in the forwarding path.
- Header and status changes never hold a body back; it streams as usual.
- Body changes hold the matching message back while it arrives, up to the size limit
  (4 MB by default, at most 16 MB, raw and decoded) and for at most 30 seconds. All held
  back bodies together use at most 256 MB of memory, and bodies of 32 MB in total are
  changed at the same time (a JSON document takes several times its size while it is
  changed); beyond that, bodies stream unchanged or wait their turn. A body that
  turns out larger or slower is forwarded unchanged as it streams — nothing fails and
  nothing waits for the end; the session's properties say why (`x-quena-held-back`).
- Never held back: event streams, JSON lines (`ndjson`, `json-seq`, `stream+json`),
  `multipart/x-mixed-replace`, gRPC, binary types, partial content (`206`, `Content-Range`)
  and `HEAD`/`204`/`304` responses.
- Compressed bodies (gzip, deflate, brotli, zstd) are decoded and sent on uncompressed with
  a new `Content-Length`; the charset is kept, key order and indentation of JSON as well.
- If a JSON operation meets a body that is not JSON, the body passes unchanged; the session
  comment says why. Changed sessions are marked *tampered* and name the rule in their
  comment.
- Mock responses are not rewritten. A breakpoint after the response shows the rewritten
  body.

## Latency

Three ways to slow things down:

- a Mock Rule's *Latency (ms)*, with *Enable Latency* checked;
- the action `*delay:<ms>`, which forwards to the server after the delay;
- global [bandwidth and latency simulation](network.md#bandwidth-and-latency-simulation).
