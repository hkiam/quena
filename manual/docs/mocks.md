# Mocks from a capture

Record the traffic of your application once, then test the frontend without its backend:
Quena turns the recorded sessions into **Mock Rules** that answer with the recorded
responses, into a portable **Quena mock package**, or into a **WireMock** export.

Open the *Mocks from Sessions* dialog with **Create from sessions…** in the Mock Rules tab,
from the session list's context menu (*Mock Rules → Mocks from Sessions…*), from the command
palette, or with *File → Export Sessions → Mocks…* — the last one starts with the package as
the target, the others with *Create Mock Rules now*.

## Targets

| Target | Result |
|---|---|
| **Create Mock Rules now** | the mocks are installed as a package and answer at once (the Mock Rules tab shows the package with its rule count) |
| **Save Quena mock package (.quena-mocks)** | a file to share: *Mock Rules → Import package…* (or drag it onto the window or the Mock Rules tab) installs it on another machine |
| **WireMock export (mappings and __files)** | `mappings/*.json`, `__files/*` and a `README.md` — as a *ZIP file* or a *Folder* (see [WireMock](#wiremock)) |

The preview shows how many mocks and sequences come out and which sessions are skipped, and
why (no response, static resource, other host, superseded by a later recording, a response
over 64 MB decoded, a body that could not be decoded …). After the job the status bar
reports the counts of the job itself, including rules that were left out.

## Options

| Option | Effect |
|---|---|
| **Sessions** | the selected or all visible sessions (the preview follows new sessions and filter changes); **Only hosts** narrows them (`api.example.com`, subdomains included) |
| **Static resources** | scripts, styles, images and fonts are left out by default — the dev server delivers them |
| **Error responses**, **CORS preflights** | included by default: they are test cases too |
| **Query string** | *Ignore parameters below* (default `_`, `t`, `cacheBust`, `utm_*`): these may have any value or be missing; or *Exact URL* |
| **Same request, several responses** | *Last response wins*, or *In recorded order (sequence)*: the responses come one after the other, the last one repeats (polling, paging, a list before and after a change) |
| **Match request bodies** | POST, PUT and PATCH are told apart by their body: JSON regardless of key order and spacing, GraphQL by operation name and variables, forms and text exactly |
| **Recorded latency** | answer after the recorded time to first byte |
| **Sanitize responses** | *Credentials and tokens* (default), *Support (credentials and personal data)*, *GDPR strict* or *As recorded* — the same rules as the [sanitized export](archives.md#sanitized-export-for-sharing). Values that were replaced in a request match any value |
| **Keep Set-Cookie headers** | off by default |

Responses are served decoded: `Content-Encoding` and hop-by-hop headers are removed and
`Content-Length` is recomputed; `204` and `304` responses get neither a body nor a
`Content-Length`. Recorded headers that are not valid HTTP are left out (and counted).

## Packages in Mock Rules

Package names are lower case, with spaces and other characters replaced (`Shop API` →
`shop-api`); an empty name becomes the date and time. Installed packages live in Quena's
data folder (`mocks/<name>/`); their rules are marked `pkg:<name>` and are listed as chips
in the Mock Rules tab with their rule count and the hosts they answer for. On a chip, **↺**
(*Reset sequences*) starts the package's sequences over with the first recorded response,
and **✕** removes the package with its rules and files. Importing a package of the same name
again replaces it; *Replace all rules* removes all other rules first. Dropping a
`.quena-mocks` file onto the window or the Mock Rules tab imports it, too.

The generated patterns are ordinary [Mock Rules](change-replay.md#match-patterns):
`METHOD:GET EXACT:…`, `regex:` when parameters are ignored, `BODYJSON:` and `GRAPHQL:` for
bodies, `BODYHASH:` for text and form bodies over 64 KiB. Sequences are chains of *match
once* rules; they start over with **↺** or when the package is imported again.

For safety an imported package may only answer from its own response files or with status
codes (`*404` …), `*delay:` up to 60 s, `*drop`, `*reset` and `*CORSPreflightAllow`. Rules
that would map remote hosts or local folders, that do not compile, or that are not limited
to one host (`*`, a plain substring — the pattern must be `EXACT:` or `prefix:` with a
host, or a `regex:` starting with a literal origin such as `^https://api\.example\.com/`)
are rejected and counted; the import message names how many. Rule latency is capped at
60 s.

## WireMock

As a *Folder*, the export owns `mappings/`, `__files/` and `README.md` in the chosen folder
and replaces them on every export, so no stale mappings of an earlier export stay behind;
other files in the folder are left alone. ZIP files and `.quena-mocks` packages are written
to a temporary file first and only replace an existing file when complete.

```sh
cd wiremock-export
docker run --rm -v "$PWD:/home/wiremock" -p 8080:8080 wiremock/wiremock
```

Then point the frontend at `http://localhost:8080`, e.g. with the API base URL or a dev-server
proxy:

```js
// vite.config.js
export default { server: { proxy: { "/api": "http://localhost:8080" } } };
```

Sequences become WireMock scenarios (reset with `POST /__admin/scenarios/reset`), more
specific mappings get a higher priority, JSON bodies are matched with `equalToJson`. When the
capture spans several hosts, every mapping also matches the `Host` header; the generated
README explains how to run it then (a proxy that keeps the host name, or one export per
host).

!!! note "CORS"
    Recorded `Access-Control-Allow-Origin` headers name the origin of the recording. If the
    frontend now runs on another origin, serve it through the dev-server proxy (same origin)
    or adjust the header.

## On the command line

```sh
quena-cli mock captures/*.har --wiremock wiremock/ --sequence
quena-cli mock captures/*.har --package shop.quena-mocks --host api.example.com
```

See [Diagnostics in CI](ci.md#sanitize-and-mocks) for all options.
