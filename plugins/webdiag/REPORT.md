# Diagnostics plugin contract (analyzer API 1)

The `analyzer` interface in `wit/plugin.wit` connects Quena (host) and an analyzer plugin
such as `webdiag`. This file fixes the JSON formats that pass through it. Everything is
UTF-8 JSON, camelCase keys; unknown keys must be ignored by readers (forward compatible).

## Flow

1. UI → host: `describe(lang)` of the plugin → profiles and default options (below).
2. UI → host: run with options (profile, overrides, scope = visible sessions or selection).
3. Host → plugin: `run(options)`, then `push(batch)` of ≤ 2 000 sessions in start order,
   then `finish()` → report JSON. The host runs this as a cancellable background job.
4. Host → UI: the report JSON unchanged (plus `scope` info added by the host, see below).

Each call must return within the host's call deadline (10 s): analyzers keep per-session
work in `push` small and do at most O(n log n) work in `finish`.

## Session records (host side)

* Sessions of kind `tunnel` are included (so connection counts are right); analyzers that
  look at HTTP content skip them.
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
  * `cookie`: names only, `a; b; sid` (values dropped).
  * `set-cookie`: `name=<n bytes>; attributes…` (attributes kept verbatim).
* `requestBodyHash` / `responseBodyHash`: 64-bit fingerprint of the decoded body, computed
  for bodies up to 1 MiB (request) / 8 MiB (response); `none` otherwise or for empty bodies.
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

The host adds `"scope": { "kind": "visible" | "selection", "sessions": n }` and
`"generatedAt"` (µs since the epoch) before handing the report to the UI.
