# Archives and copying

## Session archives

Quena reads and writes two archive formats and reads packet captures:

| Format | Use |
|---|---|
| **SAZ** (`.saz`) | Session archive compatible with Fiddler Classic. Keeps marks, comments, the Custom column and process information. |
| **HAR 1.2** (`.har`) | The HTTP Archive format that browsers' developer tools import and export. Comments are kept. |
| **Packet capture** (`.pcap`, `.pcapng`) | Recordings of tcpdump, Wireshark or dumpcap; import only, HTTPS decrypted with a TLS key log (see [Packet captures](packet-captures.md)). |
| **Internet Explorer NetXML** (`.xml`) | The network capture of Internet Explorer's F12 tools (HAR written as XML); import only: *File → Import Sessions → Internet Explorer NetXML…* or drop the file. |
| **WCAT script** (`.wcat`) | A Web Capacity Analysis Tool scenario with one transaction of the sessions' requests (server, port, TLS, path, method, headers, text bodies up to 256 KB, expected status) for a load test; export only: *File → Export Sessions → WCAT Script…*. |

### Saving

| Command | Saves |
|---|---|
| *File → Save → All Sessions…* (`Ctrl/⌘ S`, or the disk icon in the toolbar) | all sessions as `.saz` |
| *File → Save → Selected Sessions…* | the selected sessions as `.saz` |
| *File → Export Sessions → SAZ Archive…* / *HTTP Archive (HAR)…* | the selection if more than one session is selected, else all sessions |
| *File → Export Sessions → SAZ Archive with Password…* | the same as a [password-protected](#password-protected-archives) `.saz` |
| `dump` in the command field | all sessions as `.saz` |

The file name defaults to `quena_<date>_<time>.saz`. Saving runs as a background job; the
status bar shows its progress.

### Password-protected archives

*SAZ Archive with Password…* asks for a password (twice) and encrypts every entry of the
archive with **AES-256** — the way Fiddler protects archives; 7-Zip, WinZip and Fiddler open
such files with the password, too. Loading one (menu, drag and drop) asks for its password
and asks again when it is wrong. Without the password nothing of the content is readable;
the entry names (`raw/01_c.txt` …) are not hidden. HAR files are plain JSON and cannot be
protected; to share a capture without secrets in it at all, use the
[sanitized export](#sanitized-export-for-sharing).

### AutoSave

*Settings → General → AutoSave the sessions every … minutes* saves all sessions — also
those a filter hides — as `autosave-<date>-<time>Z.saz` (UTC) into the folder `autosave` in
the data folder or one you choose, but only when something changed since the last save. The
newest archives are kept (10 by default), older ones removed. *Save now* saves at once,
*Open folder* shows them; load one with *File → Load Archive…*. AutoSave archives are not
encrypted. With *Only the sessions the filters show* an archive holds just those (nothing is
saved while the filters show none). A newer archive is written only after it is complete;
older ones are removed after that, so a failed save (a full disk) costs none of them.

### Snapshot library

*File → Snapshot Library…* keeps archives in the folder `library` of the data folder, in
folders of your own (up to four levels):

- **Save as snapshot…** saves the selected sessions (or all in the list) under a name in the
  chosen folder; **Save with password…** protects it (AES-256). An existing name is not
  overwritten.
- **Add selected sessions** appends sessions to a chosen `.saz` snapshot (not to protected
  ones).
- **Open** (or a double-click) loads a snapshot into the list. Each loaded archive is a
  **source** of its own: the list is grouped by *Source* and the navigator shows *live* and
  each snapshot — click one to see only its sessions, while the live capture goes on. *Group
  by → Source* does the same for any archive you load.
- **New folder…**, **Rename…**, **Delete** (an archive, or an empty folder), **Open folder**.

### Loading

- *File → Load Archive…* (`Ctrl/⌘ O`), or *File → Import Sessions → SAZ Archive… / HTTP
  Archive (HAR)… / Packet Capture (pcap, pcapng)…*.
- **Drag and drop** `.saz`, `.har`, `.pcap` or `.pcapng` files onto the Quena window. Other
  files are skipped with a message.
- **Double-click** a `.har` or `.saz` file, or use *Open With → Quena*, on any platform.
  (Quena registers `.saz`, `.pcap` and `.pcapng` only as an alternative viewer on macOS, and
  not at all on Windows and Linux, so it never takes over another application's file
  association such as Wireshark's.)

So that an archive is not mixed with live traffic by accident, loading **stops capturing**,
and when the list already holds sessions, Quena asks: **Remove and load** (only the archive
is in the list afterwards), **Keep and load** (the archive is added), or *Cancel*. *Don't ask
again* remembers the answer; *Settings → General → Importing into a non-empty list* changes
it back. Opening a sanitised copy after the [sanitized export](#sanitized-export-for-sharing)
adds it without asking, to compare it with the original.

### Packet captures

`.pcap` and `.pcapng` files from tcpdump, Wireshark or dumpcap load the same ways as archives
(menu, *Load Archive…*, drag and drop). Quena reassembles the TCP connections and turns the
HTTP/1.x, WebSocket and HTTP/2 in them into sessions; HTTPS is decrypted with a TLS key log
(`SSLKEYLOGFILE`). How to record, what you get and how decryption works:
[Packet captures](packet-captures.md).

### Recovering a capture

Quena records into a capture database on disk. If Quena did not exit cleanly, it offers to
recover the previous capture at the next start (*Settings → General → Offer to recover
sessions after a crash*). You can also open unfinished captures any time with
*File → Recover Previous Capture…*. With *Keep capture data after exit*, captures are kept
after a clean exit as well.

## Sanitized export for sharing

Captures sent to a vendor or a support team usually carry session cookies, tokens and
personal data. *File → Export Sessions → Sanitized for Sharing (SAZ/HAR)…* writes a copy
without them — the selection if more than one session is selected, else all sessions in the
list. From the session list's context menu (*Save → Sanitized for Sharing…*) it starts with
the sessions you right-clicked, even a single one. The dialog shows which sessions go into
the file and lets you switch between the selection and all sessions. The analysis is
deterministic and runs locally; no AI model and no network are involved.

| Preset | Replaces |
|---|---|
| **Support** | credentials and tokens (Authorization, cookies, secret headers, secret URL parameters, secret fields in JSON/form/XML bodies, JWTs anywhere), e-mail addresses, IBANs and card numbers |
| **GDPR strict** | in addition phone numbers, IP addresses (headers, bodies, client and server address), fields named like personal data (`name`, `street`, `birthDate`, `telefon` …), tax ids and social security numbers, process names; bodies are cut to 64 KiB |
| **Custom** | any combination, plus your own header, parameter and field names and regular expressions |

* **Structure stays intact.** Headers are kept, only sensitive values change
  (`Authorization: Bearer <token-3>`, `Cookie: sid=<cookie-1>`); the same credential gets the
  same pseudonym in headers, URLs and bodies. Headers that describe the exact bytes of a
  changed body (`Digest`, `Content-MD5`, `ETag` …) are dropped. JSON, forms, multipart,
  XML/SOAP, HTML (form fields, `<meta>`, URLs in `href`/`src`/`action`), server-sent events,
  WebSocket messages (also `permessage-deflate` compressed and fragmented ones, written as
  one uncompressed frame) are scrubbed field by field and stay valid. Other text — YAML,
  JavaScript, CSS, GraphQL, TOML, logs — is scanned for `name: value` / `name = "value"`
  pairs, `Bearer …`/`Basic …` credentials, `Cookie:` lines and URLs. Text in other charsets
  is written as UTF-8. Bodies are written decoded (no `Content-Encoding`).
* **Names are read as words.** A field, parameter or header name is split into words
  (`apiKey`, `X-Api-Key`, `client_secret`, `otpCode`), so `pass`, `pwd` or `X-Api-Key` count
  as secrets while `passenger`, `compass` or `keyboard` do not, and metadata such as
  `token_type`, `password_length` or `expires_in` stays. Weak names (`key`, `code`,
  `state`, `hash`) are only replaced when the value looks like a credential. A field that
  names another (`{"name": "password", "value": "…"}`, `<Parameter name="password">`)
  makes that value secret. Tokens in URL paths (`/reset/…`, `/invite/…`), signed-URL
  parameters (Azure SAS, AWS, GCS), tokens sent as WebSocket subprotocols and headers that
  name a user (`X-Forwarded-User`, client certificates) are replaced as well.
* **Hosts stay.** Host names in `Host`, `:authority` and CONNECT targets are kept; IP
  literals there are replaced with the IP option, and your own patterns apply.
* **Pseudonyms keep relations visible.** The same value becomes the same placeholder within
  one export (`<email-3>` in the request and in the response), but cannot be traced back.
* **Few false alarms.** IBANs and card numbers are checked with their check digits (and
  cards with their written layout); phone numbers need a country or area prefix, 8–15
  digits and consistent separators, and are no dates; e-mail addresses stop before file
  extensions and escapes; timestamps, ids, versions and UUIDs are left alone.
* **Bodies** can be kept (sanitised), cut to a size, replaced by a placeholder
  (`<body removed: 12 KB application/json>`) or dropped; binary bodies (images, fonts, PDF,
  archives) and uploaded files become placeholders.
* **Redaction log.** After the export Quena lists what was replaced, by category and place
  (header, URL, body, WebSocket) — never the values. If you opened another dialog meanwhile,
  the status bar offers **Show redaction log** instead. The SAZ contains it as
  `QUENA-REDACTION.txt`, the HAR in `log.comment` and `log._quenaRedaction`.
  **Open Sanitized File** adds the copy to the session list for a final check.
* **Own patterns are checked first.** An invalid regular expression is reported in the
  dialog before the file is chosen; your entries stay as they are.

!!! warning "Check before you share"
    Automatic detection cannot know every field of every application — a customer number
    in a custom format is just a number. Add your own names and patterns under *Custom*,
    and look through the sanitised file before you send it.

The same export runs on the command line: `quena-cli sanitize capture.har -o shared.har
--preset gdpr` ([Diagnostics in CI](ci.md#sanitize-and-mocks)).

## Saving bodies

- *File → Save → Response Body…* / *Request Body…*, the context menu (*Save*), or the
  **Save…** button in a body view write the body of the focused session to a file —
  decoded when *Decode* is on.

## Copying sessions

Right-click the selection → **Copy**, or *Edit → Copy Session*:

| Copy | Result |
|---|---|
| *Just Url* | the URLs, one per line |
| *Summary* (`Ctrl/⌘ C`) | method, URL, status and content type |
| *Headers only* | request and response heads |
| *Full Session* | request and response with bodies (text up to 1 MB, up to 20 sessions) |
| *As cURL* | a `curl` command line |
| *As fetch (JavaScript)* | a `fetch(…)` call |
| *As PowerShell* | an `Invoke-WebRequest` command |
| *As Python requests* | a `requests` call |

For the code variants, text request bodies up to 1 MB are included inline; binary or larger
bodies are referenced as a file. Up to 50 sessions are copied at once.

*File → Export Sessions → cURL Script…* writes the selected sessions (or the first 500) as a
shell script with one `curl` command per session.

## Moving sessions elsewhere in Quena

Drag selected sessions from the list:

- onto the **Composer**, to load the first one for editing;
- onto **Mock Rules**, to create rules that answer with their recorded responses.
