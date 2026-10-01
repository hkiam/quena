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
  content-encoding, content-length, content-type, cookie, date, etag, expires, if-match,
  if-modified-since, if-none-match, keep-alive, last-modified, location, odata-version,
  origin, pragma, prefer, proxy-authenticate, proxy-authorization, range, content-range,
  referer, request-id, retry-after, set-cookie, soapaction, strict-transport-security,
  traceparent, transfer-encoding, vary, www-authenticate, x-correlation-id,
  x-http-method-override, x-ms-request-id, x-request-id`.
* Redaction (values never leave the host unredacted):
  * `authorization`, `proxy-authorization`: scheme only, e.g. `Bearer`, `Negotiate`,
    `NTLM`, `Basic` (plus ` <n bytes>`), e.g. `Bearer <812 bytes>`.
  * `www-authenticate`, `proxy-authenticate`: scheme and parameter names; token
    values replaced by `<n bytes>` (e.g. `Negotiate <1320 bytes>`). The values of the
    descriptive parameters `realm`, `error`, `error_description`, `error_uri`, `scope`,
    `authorization_uri`, `resource_metadata`, `resource` and `trusted_issuers` are kept
    (e.g. `Bearer realm="api", error="invalid_token"`), capped like OAuth parameters.
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
    `code`, `state`, `nonce`, `code_challenge`, `code_verifier`, `login_hint`, `sig`, `key`, `sid`, `otp`, the Azure SAS fields `se`, `sp`,
    `sv`, `sr`, `st`, `spr`, `srt`, `ss`, `si`, `sdd`, `skoid`, `sktid`, `skt`, `ske`,
    `sks`, `skv`; any name containing `token`, `password`, `passwd`, `secret`, `signature`,
    `apikey`, `api_key`, `api-key`, `session`, `credential`, `jwt`, `assertion`,
    `samlresponse`, `samlrequest`, `ticket` (e.g. `access_token`, `id_token`,
    `refresh_token`, `client_secret`, `$skiptoken`); any name starting with `x-amz-` or
    `x-goog-` (signed URLs);
  * any other parameter value longer than 64 bytes → `name=%3Cn%20bytes%3E`, except for
    OData system options (names starting with `$`, e.g. `$filter`, `$select`, `$expand`),
    which keep their values, and for the OAuth parameters listed under Authentication
    facts (`redirect_uri` keeps scheme, host, port and path only — its query, fragment and
    user info are dropped); a parameter without `=` longer than 64 bytes, or a name
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
* `requestText` / `responseText` (`text-info`): character encoding facts of textual bodies
  (`text/*`, JSON, XML, HTML, JavaScript, form posts, SVG — by the Content-Type of that
  direction), computed by the host on the first 256 KiB of the decoded body with the same
  rules as the display (`quena_body::charset`): BOM > `Content-Type` charset > in-document
  declaration (`<?xml encoding>`, HTML `<meta charset>` in the first 1024 bytes) > default of
  the type (JSON/XML UTF-8; other text UTF-8 if valid, else windows-1252). Fields:
  `headerCharset` / `documentCharset` as written (at most 64 bytes of `A–Z a–z 0–9 -_.:()`,
  otherwise `<n bytes>`) with `headerResolved` / `documentResolved` (WHATWG name, none if
  unknown), `bom`, `effective` + `source` (`bom` | `header` | `document` | `default`),
  `unknownLabel`, `sampled` (bytes examined; `262144` means the body was probably longer),
  `nonAscii`, `utf8Valid`, `decodeErrors`, `replacementChars` (U+FFFD in valid text),
  `doubleEncoded` (`Ã¤`-style traces), `nulBytes`, `looksCompressed` (`gzip` | `zstd` |
  `deflate` magic bytes at the start of the decoded body). Only these facts leave the host,
  never body content. None for other types, empty bodies and undecodable bodies.
* `requestDecodingError` / `responseDecodingError`: the Content-Encoding could not be
  decoded — `unsupported: <coding>` (not gzip, x-gzip, deflate, br, zstd, identity, or more
  than 4 stacked codings) or `invalid: <Content-Encoding>: <error>` (corrupt data; at most
  200 bytes). None for bodies stored truncated or still incomplete. HAR/SAZ imports store
  response bodies decoded and drop the response `Content-Encoding`.
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
* **Encoding** (`ENC-*`, profiles troubleshooting and full; `ENC-JSON` and `ENC-MISSING`
  also modernization): from `requestText` / `responseText` and the decoding errors. Each
  body gets at most one verdict, the most specific: `ENC-DECODE` (undecodable
  Content-Encoding; compressed data as text) > `ENC-BINARY` (NUL bytes) > `ENC-UNKNOWN`
  (unknown label) > `ENC-DOUBLE` (double-encoded UTF-8, valid bytes) > `ENC-CONFLICT`
  (BOM, header and document disagree; `latin1`/`ISO-8859-1` or UTF-16 byte orders are
  equal) > `ENC-JSON` (JSON not in UTF-8) > `ENC-MISMATCH` (invalid sequences in the
  declared/default charset, or a legacy charset declared for valid non-ASCII UTF-8) >
  `ENC-MISSING` (non-ASCII `text/*` or form data without any declaration; not XML, JSON,
  `text/event-stream`, `text/vtt`, `text/calendar`). `ENC-LOST` (U+FFFD in valid text) is
  reported besides. Pure ASCII is never a mismatch. Keys: `RULE|direction|[variant|]subject`
  — direction `request` or `response`; subject the endpoint (the host for `ENC-CONFLICT`,
  `ENC-UNKNOWN`, `ENC-MISSING`); variants `not-utf8`, `invalid`, `utf8` (ENC-MISMATCH) and
  `invalid`, `unsupported`, `compressed` (ENC-DECODE). Statements that depend on the whole
  body (valid UTF-8) have medium confidence when a body filled the 256 KiB sample.
* **Clocks**: the offset of a response is `Date + Age − local time of the first response
  byte` (+0.5 s for the whole-second resolution of `Date`). `CLOCK-SKEW` per host from 30 s
  (warning 60 s, critical 5 min), `CLOCK-LOCAL` when ≥ 3 unrelated sites agree on the same
  offset (this computer's clock; then no per-host findings), `CLOCK-DRIFT` when uncached
  responses of one host disagree by ≥ 30 s (10th–90th percentile, ≥ 5 responses).

## Authentication facts (`auth`)

The host fills `session.auth` (WIT `auth-info`) only with facts that are not secrets. Tokens,
codes, secrets, signatures, `state`, `nonce`, `jti` and personal claims (`sub`, `oid`,
`email`, `upn`, `unique_name`, `name`, `preferred_username`, `given_name`, `family_name`,
`login_hint` …) never leave the host.

* `bearer`: when the request carries `Authorization: Bearer <JWT>` or `DPoP <JWT>`, the
  claims of the JWT payload (base64url-decoded, ≤ 16 KiB): `alg`/`typ` from the header;
  `iss`, `aud` (string or list), `exp`, `nbf`, `iat`, client (`azp`, `appid`, `client_id`),
  `tid`, `ver`, `scp`/`scope` (split at spaces), `roles`, the number of `groups` and the
  Entra ID groups overage (`_claim_names.groups` or `hasgroups`); `size` = token length.
  Opaque tokens give `opaque-bearer` = their size. String values are capped at 256 bytes,
  lists at 64 entries.
* `oauth-request`: for `POST` requests with an `application/x-www-form-urlencoded` body
  (≤ 64 KiB) that contains `grant_type`, or that go to a token endpoint (path ends in
  `/token`, `/oauth2/token`, `/oauth2/v2.0/token`, `/protocol/openid-connect/token`,
  `/connect/token`, `/as/token.oauth2`, `/oauth/token`, `/devicecode`, `/device/code`):
  `grant_type`, `client_id`, `scope`, `redirect_uri` (without its query), and whether
  `code`, `code_verifier`, `refresh_token`, `client_secret`, `client_assertion` are present;
  `basic-client-auth` if the request has `Authorization: Basic`.
* `oauth-response`: for JSON responses (≤ 64 KiB decoded) that contain `error`,
  `access_token` or `device_code`: `error`, `error_description` (≤ 300 bytes, e-mail
  addresses replaced by `<email>`), `error_codes` (Entra ID) plus every `AADSTS<n>` in the
  description, `error_uri`, `trace_id`, `correlation_id`, `token_type`, `expires_in`, `scope`,
  whether `access_token` / `refresh_token` / `id_token` are present, and the claims (as for
  `bearer`) of a JWT access token and of the ID token.
* `discovery`: for `/.well-known/openid-configuration` responses: `issuer`,
  `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `end_session_endpoint`.
* URLs and `Location`: the values of the OAuth parameters `response_type`, `response_mode`,
  `scope`, `prompt`, `client_id`, `redirect_uri` (its own query removed),
  `code_challenge_method`, `grant_type`, `max_age`, `acr_values`, `ui_locales`,
  `domain_hint`, `error`, `error_description` (≤ 300 bytes, e-mails masked), `error_uri`,
  `error_subcode` are kept even when longer than 64 bytes (cap 512); `code`, `state`,
  `nonce`, `code_challenge`, `login_hint`, `id_token_hint`, tokens stay redacted.
* `WWW-Authenticate` / `Proxy-Authenticate`: the values of `realm`, `error`,
  `error_description` (≤ 300 bytes, e-mails masked), `error_uri`, `scope`,
  `authorization_uri`, `resource_metadata`, `resource` and `trusted_issuers` are kept
  (`Bearer realm="api", error="invalid_token"`); token68 values stay redacted.

## OAuth / OIDC rules

These describe the bundled analyzer (`analyzers/oauth.rs`, knowledge base `idp.rs`). They use
the authentication facts above, the OAuth parameters of URLs and `Location` headers, and the
`WWW-Authenticate` parameters; without facts (HAR imports without bodies) flows, URL errors,
tokens in URLs and token sizes still come from URLs and headers alone. Profiles `auth`,
`troubleshooting` and `full`; `OAUTH-FLOW` and `TOKEN-IN-URL` also `modernization`,
`TOKEN-REFRESH` also `performance`. All findings carry the tag `oauth`.

* **Identity providers** are recognised by host, path and issuer: Microsoft Entra ID
  (`login.microsoftonline.com`, `login.windows.net`, `login.microsoft.com`, `sts.windows.net`
  = v1 issuer, `.us` / `.cn` clouds), Azure AD B2C (`*.b2clogin.com`), Entra External ID
  (`*.ciamlogin.com`), AD FS (`/adfs/`), Keycloak (`/realms/<realm>/protocol/openid-connect/…`,
  issuer `…/realms/<realm>`), Okta (`*.okta.com`, `*.oktapreview.com`, `*.okta-emea.com`),
  Auth0 (`*.auth0.com`), Amazon Cognito (`*.amazoncognito.com`, `cognito-idp.*.amazonaws.com`),
  Google (`accounts.google.com`, `oauth2.googleapis.com`), Duende IdentityServer
  (`/connect/token|authorize|…`), PingFederate (`/as/token.oauth2`), otherwise generic OpenID
  Connect. Findings name the IdP, the tenant or realm, and say where the remedy is configured
  in that IdP (e.g. Entra "App registrations → <app> → Authentication → Redirect URIs",
  Keycloak "Clients → <client> → Settings → Valid redirect URIs").
* **Error knowledge**: 83 Entra ID `AADSTS` codes, 25 standard OAuth 2 / OIDC / device
  flow / DPoP / resource server error codes, and 19 Keycloak `error_description` texts —
  each with cause, remedy and the admin topic; ASP.NET Core `IDX…` and similar API messages
  are classified as expired / not yet valid / audience / issuer / signature.
* `OAUTH-ERROR` — errors of token, device, authorization and introspection endpoints (JSON
  `error`, `error=` in the redirect `Location` or the callback URL — counted once — and API
  `WWW-Authenticate: Bearer error=…`), per IdP host, error and first AADSTS code. Key
  `OAUTH-ERROR|<host>|<error>|<aadsts>`. Facts: endpoints, AADSTS codes with names,
  `error_description`, `error_subcode`, `error_uri`, clients, grant types, tenant/realm, trace
  and correlation ids (for the IdP's support). Severity: info for normal steps (device flow
  `authorization_pending` / `slow_down`, `use_dpop_nonce`, KMSI); critical for ≥ 3 client
  credential or grant errors (`invalid_client`, `invalid_grant`, `unauthorized_client`, AADSTS
  credential/grant classes) on the token endpoint; otherwise warning. A JSON `error` counts
  only on an OAuth endpoint, with token request facts, on a recognised IdP host, with a known
  OAuth code, AADSTS codes or a trace id; a URL `error=` only with a known code, a
  description, `state` or a `snake_case` code. Silent sign-in errors are `OIDC-SILENT`'s; API
  errors explained by a `TOKEN-*` rule are not repeated.
* `OAUTH-FLOW` — per IdP host and client: an info summary of the flows (authorization code
  ± PKCE, hybrid, implicit, ROPC, client credentials, refresh, device code, JWT bearer /
  on-behalf-of, token exchange, SAML bearer, CIBA). Keys `OAUTH-FLOW|<kind>|<host>|<client>`
  with kind `summary`, `implicit` (response_type with `token`; warning), `ropc`
  (`grant_type=password`; warning), `pkce` (code flow without `code_challenge` /
  `code_verifier`: warning for public clients — token request without client
  authentication —, info for confidential or unknown ones), `browser-secret` (client secret
  on a token request with `Origin`; warning), `secret-post` (client_secret in the body; info),
  `http-redirect` (redirect URI `http://` except localhost; warning), `query-tokens`
  (`response_mode=query` with token response types; warning).
* `TOKEN-IN-URL` — `access_token`, `id_token`, `refresh_token` as query or fragment
  parameter of a request URL, a `Location` or a `Referer` (values are redacted, the names
  suffice). Key `TOKEN-IN-URL|<host>|<name>|<place>`. Warning; critical when a `Referer`
  carries it to another site; info for `id_token` in a fragment (OIDC implicit sign-in) and
  for SignalR/WebSocket `access_token` queries. `id_token_hint` is not reported.
* `TOKEN-EXPIRED` — requests whose bearer JWT `exp` lies more than 60 s before the request
  start, or that the API rejects as expired (`error_description`), per API host and client;
  warning with the 401 count. When the server's `Date` says the token was still valid, the
  cause is this computer's clock (medium confidence, see `CLOCK-LOCAL`). Expired tokens that
  get 2xx more than 5 minutes after `exp`: `TOKEN-EXPIRED|accepted|<host>` (warning, the
  API does not validate the lifetime).
* `TOKEN-NOTYET` — `nbf`/`iat` more than 60 s after the request start (bearer tokens) or
  after the token response was received (ID and access tokens of token responses), per
  issuer; warning, critical from 5 minutes; names the clock offsets of IdP and API hosts
  measured from `Date` (`CLOCK-*`).
* `TOKEN-AUDIENCE` — 401 with a bearer JWT whose audience does not fit the API: the API says
  so (`IDX10214`, "audience", "issuer" — high confidence), the audience is another API (a
  Microsoft first-party resource such as Graph `00000003-…`, or a URL of another site), the
  accepted tokens of that host have other audiences, or Entra ID v1 tokens fail where v2
  tokens work (or vice versa). Per API host, warning, with a claims table (iss, aud, ver, scp,
  roles, exp at the request, client) of rejected and accepted tokens. Wording as hypothesis:
  the API's expected audience is not visible in the capture.
* `TOKEN-SCOPE` — 403 with a bearer JWT or `WWW-Authenticate error="insufficient_scope"`,
  per endpoint: the required scope (`scope=`) against the token's `scp` and `roles`, missing
  ones, app-only vs. delegated tokens. Confidence high with required scope and claims, medium
  with `insufficient_scope` alone, low for a bare 403 (may be the app's own authorisation).
  `AUTH-FAIL` leaves these 403s to `TOKEN-SCOPE`.
* `TOKEN-SIZE` — `TOKEN-SIZE|bearer|<host>`: Authorization tokens ≥ 8 KiB (warning; critical
  from 16 KiB or when answered 400/431), with groups/roles counts and the groups overage;
  `TOKEN-SIZE|cookie|<host>`: ≥ 3 chunks of one authentication cookie in a request
  (`.AspNetCore.CookiesC1…`, `FedAuth1…`, `MSISAuth1…`, `appSession.0…`,
  `*.session-token.0…`), ≥ 5 OIDC nonce/correlation cookies in a request, or ≥ 8 KiB of
  authentication cookies set by the host (warning; critical when such a request got 400/431).
  `COOKIE` does not report the size of these hosts again.
* `TOKEN-REFRESH` — successful token requests (not device flow polling, not errors) per IdP
  host and client: ≥ 3 new tokens for the same grant and scope before 50 % of the previous
  `expires_in` passed, or token requests ≥ 50 % of the client's API calls (≥ 5), warning;
  without `expires_in`, ≥ 3 within 5 minutes (warning when the bodies are identical or
  unknown, else info; medium confidence). Replaces the former token part of `AUTH-REPEAT`,
  which now covers NTLM/Negotiate only.
* `OIDC-LOOP` — ≥ 3 non-silent authorization requests of one client within 60 s
  (critical; Entra ID's `sso_reload=true` repeat within one sign-in does not count), with
  the cycle as a table (authorize, callback). Evidence-based hypotheses:
  cookies the callback sets that the next request does not send back, correlation/nonce
  cookies `SameSite=None` without `Secure` or not `SameSite=None` with `form_post`, `http`
  redirect URIs, large authentication cookies (`TOKEN-SIZE`), clock offsets; plus the usual
  middleware causes.
* `OIDC-SILENT` — silent authorization requests (`prompt=none`, `response_mode=web_message`)
  answered with `login_required` / `interaction_required` / `consent_required` /
  `account_selection_required`, or followed by an interactive one of the same client within
  60 s (medium confidence): warning; third-party cookie blocking when IdP and app are on
  different sites; remedies refresh tokens with rotation or a BFF. ≥ 3 silent requests across
  sites without visible failures: info (low confidence).
* `OIDC-DISCOVERY` — `repeat|discovery|…` / `repeat|jwks|…`: one document fetched ≥ 5 times
  within 5 minutes by one process (info; warning from 20); `fail|<host>`: discovery or JWKS
  requests with status ≥ 400 or no response (warning); `issuer|<host>`: ID tokens (and access
  tokens that are not for Microsoft first-party APIs) of a host's token responses whose `iss`
  does not match the discovery `issuer` (Entra's `{tenantid}` placeholder matches any
  tenant), or — except Entra ID — a discovery `issuer` that differs from the URL it was
  fetched from (warning).
