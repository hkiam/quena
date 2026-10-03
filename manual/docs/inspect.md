# Inspect

Select a session and the **Inspect** tab (`F8`) shows it: a header line with method, URL,
session number, duration and process, then a **Request** and a **Response** card, each
with its own row of views.

- By default the request is above the response. Switch any time with
  *View → Request Above Response / Request Beside Response*. In a narrow pane they go
  above each other automatically.
- Drag the splitter between them to change the proportions.
- The response card shows the status as a badge.

![SOAP request: header table with topic tags and the SOAP inspector showing the parsed response](img/soap-inspector.png)

## Sections and views

Each card has two rows of tabs:

1. **Sections**: *Headers*, *Body*, *Cookies*, *Auth*, *Raw*, always in this order.
   *Headers* and *Cookies* show how many there are, and *Auth* has a dot when the message
   carries authentication. Sections with nothing in them are faint but can still be opened.
   For WebSockets and SSE streams, *Body* is called *Messages*.
2. **Views of the section**: for *Body*, only the views that fit the content, the best one
   first. For example, *Formatted · Tree · Plain Text* for JSON,
   *SOAP · Formatted · Tree · Plain Text* for a SOAP envelope, and *Image · Hex* for a PNG.
   The other views are under **Other**: first those that may help (such as *Hex* for text),
   then those that do not fit the content, marked so. They stay selectable in case the
   content is mislabelled. On responses, *Headers* has a second view, *Caching*.

Quena does not trust the `Content-Type` alone. It also looks at the start of the body,
decoded: a SOAP `Envelope`, an Atom `feed`/`entry`, OData metadata (`edmx:Edmx`), OData JSON,
plain JSON, XML or HTML. A plain XML document sent as `text/xml` therefore opens in
*Formatted* with the XML tree, not in the SOAP view, and JSON sent as `text/plain` gets the
JSON tree.

`Alt 1`…`Alt 5` choose the section and `Alt ←`/`Alt →` the view; see
[Keyboard shortcuts](shortcuts.md#inspect).

**Prefer the single row of views?** *Settings → General → Inspector views → Flat* brings
back the strip of all views from earlier versions. The views, and which view is
remembered, are the same in both.

## Right-click

| Where | Menu |
|---|---|
| Header row | Copy value, name, the header or all headers; *Show only* this header in the table |
| Body, Raw, Hex, Image | Copy (selection), Select All, *Copy Body*, *Save Body…*; in the body also *Wrap* and *Format* |
| JSON tree | Copy value, key or **JSONPath**; Expand / Collapse All; **change or remove this value, or append a broken element to this list, in later messages of the same URL** (adds a [rewrite rule](change-replay.md)) |
| XML tree (also SOAP) | Copy text, **XPath** or the element as XML; Expand / Collapse All |
| Tables (form data, cookies, encoding) | Copy value, row or all rows (tab-separated) |
| WebSocket frame, SSE event, multipart part | Copy the message / data / event; save the part |
| Text fields and editors | Undo, Redo, Cut, Copy, Paste, Select All |

Elsewhere a right-click shows nothing, or *Copy* for selected text.

## Views

| View | Request | Response | Shows |
|---|:-:|:-:|---|
| *Headers* | ✅ | ✅ | Start line and a header table in wire order, with a filter box, topic tags (auth, cookie, cache, cors, body, conn, fetch, policy), optional A–Z sorting, a raw mode and *Copy*. Double-click a value to copy it. |
| *Plain Text* | ✅ | ✅ | The body as plain text. |
| *Body* | ✅ | ✅ | The body with syntax highlighting and a *Format* switch for pretty-printing (JSON, XML …). |
| *Form Data* | ✅ | | URL-encoded form fields as a table. |
| *Hex* | ✅ | ✅ | Hex dump of any size; jump to an offset (hex or decimal). |
| *Auth* | ✅ | ✅ | Authentication headers, decoded (see below). |
| *Cookies* | ✅ | ✅ | Cookies sent, or cookies set with their attributes. |
| *Raw* | ✅ | ✅ | The message as it went over the wire. |
| *JSON* | ✅ | ✅ | JSON as a collapsible tree. |
| *XML* | ✅ | ✅ | XML as a collapsible tree. |
| *Encoding* | | ✅ | How the response body is encoded (compression, chunking). |
| *Image* | | ✅ | The image. |
| *Preview* | | ✅ | The response rendered in a sandboxed frame without scripts, forms or network access. |
| *Caching* | | ✅ | The response's caching headers (`Cache-Control`, `Expires`, validators). |

The body views have *Wrap*, *Format* (where available) and **Save…** (save the body to a
file). Compressed bodies (gzip, deflate, brotli, zstd) are shown decoded; the **Decode**
toggle in the toolbar switches this off, and a banner then offers to decode again. The
recorded bytes are never changed — decoded and formatted views are derived from them.

## Views for special content

These views appear only when the content fits:

| View | Appears for | Shows |
|---|---|---|
| *WebSocket* | WebSocket sessions | the frame log with direction, type, size and payload; *All frames* or *Text messages* only |
| *SSE* | `text/event-stream` responses | the stream split into events, live |
| *gRPC* | gRPC / Protobuf messages | message frames and a schemaless field tree (no `.proto` needed) |
| *Parts* | `multipart/*` bodies, including MTOM | the parts of `multipart/related`, `form-data` and `mixed` |
| *SOAP* | SOAP envelopes | SOAP version, action, operation, body and SOAP faults |
| *Atom/OData* | Atom feeds and OData (v2/v3 Atom) | entity sets and types, entries, properties and links |

SOAP and Atom/OData also work on the output of decoder plugins, e.g. Fast Infoset.
[Plugins](plugins.md) can add further views, such as *Fast Infoset* and *GraphQL*.

## Which view opens

- With flat views, the views are ordered by how well they fit the content: *Headers* first,
  then the special and plugin views, then *Body*, and so on. As many views as fit the
  width are shown as tabs; the rest are under **More**. The active view is always visible.
- Until you choose a view for a kind of content, the one that fits opens: *SOAP* for SOAP,
  *gRPC* for gRPC, *WebSocket* for WebSockets, *Image* for images, *Form Data* for form
  requests, *Body* for JSON, XML, HTML, JavaScript, CSS and text, *Hex* for binary content,
  *Headers* when there is no body.
- **Quena remembers the view you choose per kind of content, separately for request and
  response.** Choose *XML* once for a SOAP response, and every SOAP response opens in *XML*;
  JSON can stay on *Body* at the same time.

The memory can be switched off, or cleared, in
*Settings → General → Inspector views*. With it off, the last view chosen is used for every
session.

## Character encodings

Text is shown in the character encoding (charset) the message is in, determined the way
browsers do it:

1. a byte order mark (UTF-8, UTF-16) at the start of the body;
2. the `charset` of the `Content-Type` header;
3. the document's own declaration — `<?xml … encoding="…"?>` in XML,
   `<meta charset>` in HTML;
4. the default of the type: UTF-8 for JSON and XML; other text is UTF-8 when it is valid
   UTF-8, else windows-1252. `ISO-8859-1` and `latin1` mean windows-1252, as in browsers.

The toolbar of *Plain Text* and *Body* shows the result, e.g. `windows-1252 · header`
(where it came from: *BOM*, *header*, *document* or *default*). If characters look wrong —
typically `�` for a body declared UTF-8 that is really Latin-1 — choose another charset in
the menu next to it. The choice applies to that message's views (text, Raw, JSON, XML,
SOAP, Atom, SSE, the large-body viewer and its search) until you select another session.
*Parts* shows each multipart part in its own charset, with its own menu; *Form Data*
decodes the fields in the form's charset (the `Content-Type` charset, else a `_charset_`
field, else UTF-8).

UTF-16 bodies are converted to UTF-8 for display and formatting; the recorded bytes are
never changed (*Hex* and *Save…* show them as they are). *Find Sessions* and *Find in
body* search the text in each body's charset. In *Headers*, parameters encoded after RFC
8187 (`filename*=UTF-8''%E2%82%AC.pdf`) are shown decoded below the value.

## Large bodies

Bodies are read from disk in windows, so even multi-gigabyte bodies open instantly:

- Up to 8 MB (after decoding), a body opens in the regular editor.
- Larger bodies, and responses that are still arriving, open in the **large-body viewer**:
  it shows size and line count (indexing runs in the background), jumps to a line, and
  searches the whole body with *Find in body* and `↑`/`↓` through the hits.
- *Hex* works on bodies of any size.
- *Save…* writes the whole body to a file.

## Auth view

The **Auth** view shows `Authorization`/`Proxy-Authorization` (request) and
`WWW-Authenticate`/`Proxy-Authenticate` (response) headers in readable form:

- **Basic**: the decoded `user:password`.
- **Negotiate, Kerberos and NTLM**: with the bundled *Kerberos / NTLM* plugin, the tokens
  are decoded (SPNEGO; Kerberos AP-REQ, AP-REP, KRB-ERROR; NTLM Type 1, 2 and 3). A
  Negotiate exchange that fell back to NTLM is flagged.
- **JWT**: with the bundled *JWT* plugin, JSON Web Tokens in Bearer or DPoP authorization,
  cookies, `Set-Cookie` and common token headers (`X-Access-Token`, `X-Id-Token` …) are
  decoded: header (alg, typ, kid …), claims with the registered ones explained, `exp`,
  `nbf` and `iat` as dates with "expired 3 h ago" / "valid for 12 min", and the signature
  algorithm. Signatures are **not** verified. Encrypted tokens (JWE) show their header.

Tokens a plugin recognises in cookies or other headers are listed below the authentication
headers.

## GraphQL

With the bundled *GraphQL* plugin, a **GraphQL** view appears for GraphQL requests
(`application/graphql`, or JSON with `query`/`variables`/`operationName`, batches and
persisted queries), showing the operation with the query pretty-printed, and for GraphQL
JSON responses, with the errors first.

## Inspecting from elsewhere

- *Enter* or a double-click in the session list opens *Inspect*.
- Right-click → **Properties…** shows a session's metadata: state, process and PID, client
  and server addresses, TLS versions, ciphers, SNI and ALPN, HTTP/2 stream and all timers.
- Right-click → **Compare** with two sessions selected — see [Analyze](analyze.md#compare).
