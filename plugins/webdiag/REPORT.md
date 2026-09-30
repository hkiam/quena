# Diagnostics plugin contract (analyzer API 1)

The `analyzer` interface in `wit/plugin.wit` connects Quena (host) and an analyzer plugin
such as `webdiag`. This file fixes the JSON formats that pass through it. Everything is
UTF-8 JSON, camelCase keys; unknown keys must be ignored by readers (forward compatible).

## Flow

1. UI → host: `describe(lang)` of the plugin → profiles and default options (below).
2. UI → host: run with options (profile, overrides, scope = visible sessions or selection).
3. Host → plugin: `run(options)`, then `push(batch)` of ≤ 2 000 sessions (and about
   ≤ 16 MiB) in start order, then `finish()` → report JSON. The host runs this as a
   cancellable background job; cancelling interrupts the plugin even inside a call (the
   cancel flag is polled every 50 ms), and a cancelled or superseded run never stores its
   report. Only the latest run's report is kept; "Remove all" and opening another capture
   drop it (session ids restart) and cancel running analyses.
4. Host → UI: the report JSON unchanged (plus `scope` info added by the host, see below).

Deadlines (wall clock): 10 s for the constructor (`run(options)`) and for each `push`,
60 s for `finish`, 10 s for `describe`. The report (and `describe`) may be at most 64 MiB.
A call that exceeds its deadline or the memory limit (512 MiB) fails the run. Analyzers
keep per-session work in `push` small and do at most O(n log n) work in `finish`.

## Session records (host side)

* Sessions of kind `tunnel` are included (so connection counts are right); analyzers that
  look at HTTP content skip them. Their `url` is the authority form `host:port` (as in
  `CONNECT host:port`), not an absolute URL.
* `url` of other sessions is absolute (`scheme://host[:port]/path?query`), redacted as
  described below.
* Headers: only this allow-list is passed (case-insensitive), in wire order:
  `accept-encoding, access-control-allow-origin, access-control-max-age,
  access-control-request-method, age, authorization, cache-control, connection,
  content-encoding, content-length, content-type, cookie, etag, expires, if-match,
  if-modified-since, if-none-match, keep-alive, last-modified, location, odata-version,
  origin, pragma, prefer, proxy-authenticate, proxy-authorization, range, content-range,
  referer, request-id, retry-after, set-cookie, soapaction, strict-transport-security,
  traceparent, transfer-encoding, vary, www-authenticate, x-correlation-id,
  x-http-method-override, x-ms-request-id, x-request-id`.
* Redaction (values never leave the host unredacted):
  * `authorization`, `proxy-authorization`: scheme only, e.g. `Bearer`, `Negotiate`,
    `NTLM`, `Basic` (plus ` <n bytes>`), e.g. `Bearer <812 bytes>`.
  * `www-authenticate`, `proxy-authenticate`: scheme and parameter names; token
    values replaced by `<n bytes>` (e.g. `Negotiate <1320 bytes>`, `Bearer realm, error`).
  * `cookie`: names only, `a; b; sid` (values dropped); a pair without `=` is a value
    (RFC 6265bis) and becomes `<n bytes>`.
  * `set-cookie`: `name=<n bytes>` plus the attributes `Path`, `Domain`, `Expires`,
    `Max-Age`, `Secure`, `HttpOnly`, `SameSite`, `Partitioned`, `Priority` verbatim (names
    case-insensitive); any other attribute becomes `name=<n bytes>` (or `<n bytes>`). A
    value that carries several cookies (joined with a line break, or folded with `, ` —
    a comma inside an `Expires` date does not split) has every cookie redacted.
  * `location`, `referer` and the session `url`: URL redaction (below).
* URL redaction (session `url`, `Location`, `Referer`; absolute or relative):
  * user info (`user:password@`) → `%3Cn%20bytes%3E@`;
  * query and fragment parameters (`name=value`, `&`-separated) whose name (percent-decoded,
    case-insensitive) is sensitive → `name=%3Cn%20bytes%3E`. Sensitive: exactly `auth`,
    `code`, `state`, `nonce`, `sig`, `key`, `sid`, `otp`, the Azure SAS fields `se`, `sp`,
    `sv`, `sr`, `st`, `spr`, `srt`, `ss`, `si`, `sdd`, `skoid`, `sktid`, `skt`, `ske`,
    `sks`, `skv`; any name containing `token`, `password`, `passwd`, `secret`, `signature`,
    `apikey`, `api_key`, `api-key`, `session`, `credential`, `jwt`, `assertion`,
    `samlresponse`, `samlrequest`, `ticket` (e.g. `access_token`, `id_token`,
    `refresh_token`, `client_secret`, `$skiptoken`); any name starting with `x-amz-` or
    `x-goog-` (signed URLs);
  * any other parameter value longer than 64 bytes → `name=%3Cn%20bytes%3E`, except for
    OData system options (names starting with `$`, e.g. `$filter`, `$select`, `$expand`),
    which keep their values; a parameter without `=` longer than 64 bytes, or a name
    longer than 64 bytes, is replaced as a whole; a fragment without `=` longer than 64
    bytes is replaced as a whole;
  * `n` is the length of the value as it appears in the URL (percent-encoded). The
    placeholder is percent-encoded so the URL stays valid; it decodes to `<n bytes>`.
    Requests that differ only in redacted values look identical to the analyzer.
  * Scheme, host, port and path are passed unchanged (a secret in the path is not
    recognised).
* Size caps: `url` and every header value at most 8 KiB — longer ones are cut and end
  with `…<truncated n bytes>` (in `url` percent-encoded,
  `%E2%80%A6%3Ctruncated%20n%20bytes%3E`); at most 256 headers per direction (further
  ones dropped); `error` at most 8 KiB.
* `requestBodyHash` / `responseBodyHash`: 64-bit fingerprint of the decoded body, computed
  for bodies up to 1 MiB (request) / 8 MiB (response); `none` otherwise or for empty bodies.
* `responseDecodedBytes`: decoded size of the response body; decoding stops at 256 MiB
  (decompression bombs), so a value ≥ 256 MiB is a lower bound. Undecodable bodies report
  the stored size.
* Missing data is normal (HAR/SAZ imports have fewer timers, no connection ids): analyzers
  must lower `confidence` or skip, never fail.

## `describe(lang)` → JSON

```json
{
  "schema": 1,
  "profiles": [
    { "id": "full", "name": "Full diagnostic", "description": "…", "default": true },
    { "id": "performance", "name": "Performance", "description": "…" }
  ],
  "options": {
    "profile": "full",
    "lang": "en",
    "slowMs": 1000, "ttfbMs": 500,
    "largeRequestBytes": 1048576, "largeResponseBytes": 5242880,
    "operationGapMs": 1500,
    "networks": [
      { "id": "lan", "name": "LAN", "rttMs": 1, "mbps": 1000, "lossPct": 0 },
      { "id": "good-wan", "name": "Good WAN", "rttMs": 20, "mbps": 100, "lossPct": 0 },
      { "id": "vpn", "name": "VPN/WAN", "rttMs": 60, "mbps": 20, "lossPct": 0.1 },
      { "id": "weak-wan", "name": "Weak WAN", "rttMs": 120, "mbps": 5, "lossPct": 0.5 },
      { "id": "mobile", "name": "Mobile", "rttMs": 80, "mbps": 10, "lossPct": 1 }
    ]
  },
  "optionLabels": { "slowMs": "Slow request (ms)", "…": "…" }
}
```

`options` in `run(options)` has the same shape; omitted keys take the defaults. `lang` is
`en` or `de` and selects the language of all report texts.

## Report JSON (`finish`)

```json
{
  "schema": 1,
  "tool": { "id": "io.github.hkiam.webdiag", "version": "0.1.0" },
  "profile": { "id": "performance", "name": "Performance" },
  "lang": "en",
  "range": { "from": 1727690000000000, "to": 1727690060000000, "sessions": 10000 },
  "summary": {
    "critical": 3, "warning": 12, "info": 28,
    "headline": ["Sequential API communication adds significant latency.", "…"]
  },
  "metrics": [
    { "key": "requests", "label": "HTTP requests", "value": 10000, "unit": "count" },
    { "key": "bytes", "label": "Transferred", "value": 50331648, "unit": "bytes" },
    { "key": "duplicateShare", "label": "Duplicate requests", "value": 0.31, "unit": "ratio" }
  ],
  "operations": [
    {
      "id": "op-3", "label": "GET /odata/Cases(42) …",
      "start": 1727690001000000, "end": 1727690007800000,
      "sessions": [4711, 4712],
      "metrics": [ { "key": "requests", "label": "Requests", "value": 187, "unit": "count" } ]
    }
  ],
  "findings": [
    {
      "id": "PERF-SEQ",
      "key": "PERF-SEQ|op-3",
      "title": "Latency-sensitive request chain",
      "severity": "warning",
      "confidence": "high",
      "categories": ["performance", "latency"],
      "score": 72,
      "observation": "42 requests of “Open …” ran one after another (7.8 s).",
      "impact": "Every additional 50 ms of round-trip time adds about 2.1 s.",
      "hypotheses": ["The requests appear independent and could run concurrently."],
      "recommendations": ["Check request dependencies.", "Parallelise independent requests."],
      "nextSteps": ["Test under 100–200 ms RTT (Settings → Connections → bandwidth simulation)."],
      "estimate": true,
      "threshold": "≥ 10 sequential requests",
      "facts": [ { "label": "Sequential levels", "value": "42" } ],
      "table": {
        "columns": ["Network", "RTT", "Estimated extra time"],
        "rows": [["Good WAN", "20 ms", "+0.8 s"], ["Weak WAN", "120 ms", "+5.0 s"]]
      },
      "sessions": [4711, 4712, 4713],
      "operation": "op-3",
      "tags": ["n+1"]
    }
  ]
}
```

* `severity`: `critical` | `warning` | `info`. `confidence`: `high` | `medium` | `low`.
* `key` identifies "the same finding" across captures (rule id + stable subject such as an
  endpoint template); the UI compares reports by `key` (new / resolved / changed).
* `score` 0–100 orders findings within a severity (impact).
* `estimate: true` marks modelled (not measured) statements; the UI labels them.
* `sessions`: all affected session ids (may be long); the UI selects them in the list.
* Units: `count`, `bytes`, `ms`, `ratio` (0–1), `rate` (per second), `text`.
* Findings are sorted by severity, then score descending.

The host adds `"scope": { "kind": "visible" | "selection", "sessions": n, "processes":
[…], "hosts": […] }` and
`"generatedAt"` (µs since the epoch) before handing the report to the UI.

## webdiag specifics

These describe the bundled analyzer, not the API; other analyzers may differ.

* **Capture metrics** (keys): `requests`, `bytes`, `span`, `hosts`, `errors`, `operations`,
  `rate`, `open` (requests still open at capture end — neither failures nor slow requests),
  `notAnalysed` (sessions beyond the analyser's limit of 500 000; then the info finding
  `SCOPE-LIMIT` says so). `SCOPE-MIXED` points out traffic of several applications.
* **Failures** are sessions with an error or without a response *that ended*; sessions
  still in flight at capture end are *incomplete* and left out of error, timing and chain
  statistics.
* **Operations** split at idle gaps per process; segments sharing a `traceparent` trace id or
  an `x-correlation-id` merge only when they are close in time (within 5 × the operation
  gap). Recurring single requests of one endpoint form a *background* operation
  (`"background": true`) when they repeat the same URL or come at a regular interval;
  per-operation checks skip background operations.
* **Cache busters**: `_`, `_t`, `cb`, `nocache`, `rnd` … are dropped from the canonical form;
  `t`, `ts`, `timestamp` only when the value is within ±5 minutes of the session start (as s,
  ms or µs) — otherwise they are data.
* **Estimates**: transfer time on a network profile = one RTT + bytes over the effective
  throughput min(bandwidth, Mathis limit for the packet loss); the latency of a sequential
  chain adds the round trips of each step (plus TCP/TLS/DNS for new connections) times the
  RTT difference. Both are marked `estimate: true`.
