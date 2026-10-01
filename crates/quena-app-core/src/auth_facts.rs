//! Authentication facts for analyzers (plugins/webdiag/REPORT.md "Authentication facts"):
//! the non-secret claims of JWTs, OAuth token requests and responses, OpenID Connect
//! discovery documents. Tokens, codes, secrets, signatures, `state`, `nonce`, `jti` and
//! personal claims (`sub`, `oid`, `email`, `upn`, `name` …) never leave the host: only the
//! fields listed here are copied, nothing else of a token or body.

use super::{decode_param, redact_url};
use quena_plugin_host::{AnalyzerAuthInfo, AnalyzerJwtClaims, AnalyzerOauthRequest, AnalyzerOauthResponse, AnalyzerOidcDiscovery};
use serde_json::{Map, Value};

/// Largest decoded JWT header / payload that is parsed.
pub const JWT_PART_LIMIT: usize = 16 << 10;
/// Largest decoded OAuth form body / JSON response that is parsed.
pub const AUTH_BODY_LIMIT: usize = 64 << 10;
/// Longest claim string; longer ones are cut (marked with `…`).
pub const CLAIM_LIMIT: usize = 256;
/// Entries of a claim list (aud, scopes, roles) or of `error_codes`.
pub const LIST_LIMIT: usize = 64;
/// Longest OAuth parameter / endpoint value.
pub const PARAM_LIMIT: usize = 512;
/// Longest `error_description`.
pub const DESCRIPTION_LIMIT: usize = 300;

/// Paths of token / device endpoints (lower case suffixes, REPORT.md).
const TOKEN_PATHS: &[&str] = &[
    "/token",
    "/oauth2/token",
    "/oauth2/v2.0/token",
    "/protocol/openid-connect/token",
    "/connect/token",
    "/as/token.oauth2",
    "/oauth/token",
    "/devicecode",
    "/device/code",
];

// ------------------------------------------------------------------ text helpers

/// `s` cut to at most `max` bytes in total (at a char boundary), marked with `…`.
pub fn cap_bytes(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max.saturating_sub('…'.len_utf8());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// Characters that end a word for e-mail masking.
fn word_break(c: char) -> bool {
    c.is_whitespace() || "\"'<>()[]{},;`".contains(c)
}

/// Every word with an `@` followed (later) by a `.` becomes `<email>` (a trailing `.` of a
/// sentence stays).
pub fn mask_emails(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut String| {
        let core = word.trim_end_matches('.');
        let is_mail = core.find('@').is_some_and(|i| i > 0 && core[i + 1..].contains('.'));
        if is_mail {
            out.push_str("<email>");
            out.push_str(&word[core.len()..]);
        } else {
            out.push_str(word);
        }
        word.clear();
    };
    for c in s.chars() {
        if word_break(c) {
            flush(&mut word, &mut out);
            out.push(c);
        } else {
            word.push(c);
        }
    }
    flush(&mut word, &mut out);
    out
}

/// An `error_description`: e-mails masked, then cut to [`DESCRIPTION_LIMIT`] bytes.
pub fn safe_description(s: &str) -> String {
    cap_bytes(&mask_emails(s), DESCRIPTION_LIMIT)
}

/// Every `AADSTS<digits>` in `s`.
pub fn aadsts_codes(s: &str) -> Vec<u32> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(i) = rest.find("AADSTS") {
        rest = &rest[i + 6..];
        let n = rest.bytes().take_while(u8::is_ascii_digit).count();
        if let Some(code) = (n > 0 && n <= 9).then(|| rest[..n].parse().ok()).flatten() {
            out.push(code);
        }
        rest = &rest[n..];
    }
    out
}

/// Percent-encoding of everything but the unreserved characters (RFC 3986).
pub fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A URL without its query and fragment (as written, also percent-encoded `%3F` / `%23`).
pub fn strip_query(v: &str) -> &str {
    let lower = v.to_ascii_lowercase();
    let end = ["?", "#", "%3f", "%23"].iter().filter_map(|m| lower.find(m)).min().unwrap_or(v.len());
    &v[..end]
}

/// A redirect URI as it may be shown: without query and fragment, and without user info
/// (`https://user:pass@host/cb` → `https://host/cb`), also when percent-encoded.
pub fn bare_redirect(v: &str) -> String {
    let v = strip_query(v);
    let lower = v.to_ascii_lowercase();
    let Some((sep, sep_len)) = [("://", 3), ("%3a%2f%2f", 9)].iter().find_map(|(m, n)| lower.find(m).map(|i| (i, *n))) else {
        return v.to_string();
    };
    let auth_start = sep + sep_len;
    let rest = &lower[auth_start..];
    let auth_end = auth_start + ["/", "%2f"].iter().filter_map(|m| rest.find(m)).min().unwrap_or(rest.len());
    let authority = &lower[auth_start..auth_end];
    match ["@", "%40"].iter().filter_map(|m| authority.rfind(m).map(|i| (i, m.len()))).max_by_key(|x| x.0) {
        Some((at, n)) => format!("{}{}", &v[..auth_start], &v[auth_start + at + n..]),
        None => v.to_string(),
    }
}

/// The path of an absolute or origin-form URL (without query and fragment).
pub fn url_path(url: &str) -> &str {
    let rest = match url.find("://") {
        Some(i) => {
            let after = &url[i + 3..];
            &after[after.find(['/', '?', '#']).unwrap_or(after.len())..]
        }
        None => url,
    };
    &rest[..rest.find(['?', '#']).unwrap_or(rest.len())]
}

// ------------------------------------------------------------------ JWT

/// base64url (padding and the standard alphabet tolerated) → bytes; `None` if invalid or
/// the result would exceed `limit`.
pub fn base64url(s: &str, limit: usize) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    if s.len() / 4 * 3 > limit + 3 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in s.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    (out.len() <= limit).then_some(out)
}

fn json_object(bytes: &[u8]) -> Option<Map<String, Value>> {
    match serde_json::from_slice::<Value>(bytes).ok()? {
        Value::Object(o) => Some(o),
        _ => None,
    }
}

fn claim_str(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) => Some(cap_bytes(s, CLAIM_LIMIT)),
        Value::Number(n) => Some(cap_bytes(&n.to_string(), CLAIM_LIMIT)),
        _ => None,
    }
}

/// A string or a list of strings (at most [`LIST_LIMIT`]); `split` also splits strings at
/// whitespace (`scp` / `scope`).
fn claim_list(v: Option<&Value>, split: bool) -> Vec<String> {
    let mut out: Vec<String> = match v {
        Some(Value::String(s)) if split => s.split_whitespace().map(|x| cap_bytes(x, CLAIM_LIMIT)).collect(),
        Some(Value::String(s)) => vec![cap_bytes(s, CLAIM_LIMIT)],
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str()).map(|x| cap_bytes(x, CLAIM_LIMIT)).collect(),
        _ => vec![],
    };
    out.truncate(LIST_LIMIT);
    out
}

/// Seconds since the epoch as given (integers or floats ≥ 0).
fn claim_time(v: Option<&Value>) -> Option<u64> {
    let n = v?.as_number()?;
    n.as_u64().or_else(|| n.as_f64().filter(|f| f.is_finite() && *f >= 0.0).map(|f| f as u64))
}

fn truthy(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Bool(true))) || v.and_then(Value::as_str).is_some_and(|s| s.eq_ignore_ascii_case("true"))
}

/// The allowed claims of a compact JWS (`header.payload.signature`); `None` for anything
/// else (opaque tokens, JWE, oversized or undecodable parts). The signature is never read.
pub fn jwt_claims(token: &str) -> Option<AnalyzerJwtClaims> {
    let token = token.trim();
    let mut parts = token.split('.');
    let (h, p, _sig) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || h.is_empty() || p.is_empty() {
        return None;
    }
    let header = json_object(&base64url(h, JWT_PART_LIMIT)?)?;
    let payload = json_object(&base64url(p, JWT_PART_LIMIT)?)?;
    let alg = claim_str(header.get("alg"))?;
    let c = |k: &str| payload.get(k);
    let scopes = match c("scp") {
        Some(v) => claim_list(Some(v), true),
        None => claim_list(c("scope"), true),
    };
    let groups_overage = payload.get("_claim_names").and_then(Value::as_object).is_some_and(|o| o.contains_key("groups")) || truthy(c("hasgroups"));
    Some(AnalyzerJwtClaims {
        alg,
        typ: claim_str(header.get("typ")),
        iss: claim_str(c("iss")),
        aud: claim_list(c("aud"), false),
        exp: claim_time(c("exp")),
        nbf: claim_time(c("nbf")),
        iat: claim_time(c("iat")),
        client: claim_str(c("azp")).or_else(|| claim_str(c("appid"))).or_else(|| claim_str(c("client_id"))),
        tenant: claim_str(c("tid")),
        ver: claim_str(c("ver")),
        scopes,
        roles: claim_list(c("roles"), false),
        groups: c("groups").and_then(Value::as_array).map(|a| a.len().min(u32::MAX as usize) as u32),
        groups_overage,
        size: token.len().min(u32::MAX as usize) as u32,
    })
}

/// `Authorization: Bearer|DPoP <token>` → (claims of a JWT, size of an opaque token).
pub fn bearer(authorization: Option<&str>) -> (Option<AnalyzerJwtClaims>, Option<u32>) {
    let Some((scheme, token)) = authorization.map(str::trim).and_then(|v| v.split_once(|c: char| c.is_ascii_whitespace())) else {
        return (None, None);
    };
    let token = token.trim();
    if token.is_empty() || !(scheme.eq_ignore_ascii_case("bearer") || scheme.eq_ignore_ascii_case("dpop")) {
        return (None, None);
    }
    match jwt_claims(token) {
        Some(c) => (Some(c), None),
        None => (None, Some(token.len().min(u32::MAX as usize) as u32)),
    }
}

// ------------------------------------------------------------------ OAuth request

/// `application/x-www-form-urlencoded` (parameters ignored).
fn is_form(content_type: Option<&str>) -> bool {
    content_type.and_then(|c| c.split(';').next()).is_some_and(|m| m.trim().eq_ignore_ascii_case("application/x-www-form-urlencoded"))
}

/// Whether the path is a token / device endpoint (REPORT.md).
pub fn is_token_path(path: &str) -> bool {
    let p = path.trim_end_matches('/').to_ascii_lowercase();
    TOKEN_PATHS.iter().any(|t| p.ends_with(t))
}

/// Whether a request is worth reading as an OAuth form (cheap: method and content type).
pub fn oauth_request_candidate(method: &str, content_type: Option<&str>) -> bool {
    method.eq_ignore_ascii_case("POST") && is_form(content_type)
}

/// Facts of an OAuth form request (`body`: the decoded body, at most [`AUTH_BODY_LIMIT`]).
/// Only `grant_type`, `client_id`, `scope` and `redirect_uri` (without its query) are
/// copied; codes, verifiers, refresh tokens, secrets and assertions only as "present".
pub fn oauth_request(method: &str, path: &str, content_type: Option<&str>, authorization: Option<&str>, body: &[u8]) -> Option<AnalyzerOauthRequest> {
    if !oauth_request_candidate(method, content_type) || body.len() > AUTH_BODY_LIMIT {
        return None;
    }
    let text = String::from_utf8_lossy(body);
    let pairs: Vec<(String, String)> = text
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (n, v) = p.split_once('=').unwrap_or((p, ""));
            (decode_param(n).trim().to_ascii_lowercase(), decode_param(v))
        })
        .collect();
    let get = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    let has = |k: &str| get(k).is_some_and(|v| !v.is_empty());
    if get("grant_type").is_none() && !is_token_path(path) {
        return None;
    }
    let value = |k: &str| get(k).map(|v| cap_bytes(v, PARAM_LIMIT));
    let basic = authorization.and_then(|a| a.split_whitespace().next()).is_some_and(|s| s.eq_ignore_ascii_case("basic"));
    Some(AnalyzerOauthRequest {
        grant_type: value("grant_type"),
        client_id: value("client_id"),
        scope: value("scope"),
        redirect_uri: get("redirect_uri").map(|v| cap_bytes(&redact_url(&bare_redirect(v)), PARAM_LIMIT)),
        has_code: has("code"),
        has_code_verifier: has("code_verifier"),
        has_refresh_token: has("refresh_token"),
        has_client_secret: has("client_secret"),
        has_client_assertion: has("client_assertion"),
        basic_client_auth: basic,
    })
}

// ------------------------------------------------------------------ OAuth response

/// The body starts (after whitespace / a UTF-8 BOM) with `{`.
pub fn json_object_prefix(body: &[u8]) -> bool {
    let b = body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body);
    b.iter().find(|c| !c.is_ascii_whitespace()) == Some(&b'{')
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn param_str(o: &Map<String, Value>, k: &str, limit: usize) -> Option<String> {
    claim_str(o.get(k)).map(|s| cap_bytes(&mask_emails(&s), limit))
}

fn present(o: &Map<String, Value>, k: &str) -> bool {
    o.get(k).and_then(Value::as_str).is_some_and(|s| !s.is_empty())
}

/// Facts of an OAuth / OIDC JSON response (token, error, device code): `None` unless the
/// body is a JSON object (at most [`AUTH_BODY_LIMIT`]) with a string `error`,
/// `access_token` or `device_code`.
pub fn oauth_response(body: &[u8]) -> Option<AnalyzerOauthResponse> {
    if body.len() > AUTH_BODY_LIMIT || !json_object_prefix(body) {
        return None;
    }
    // Cheap pre-check before parsing.
    if ![&b"\"error\""[..], b"\"access_token\"", b"\"device_code\""].iter().any(|k| contains(body, k)) {
        return None;
    }
    let o = json_object(body)?;
    if !["error", "access_token", "device_code"].iter().any(|k| o.get(*k).is_some_and(Value::is_string)) {
        return None;
    }
    let description = o.get("error_description").and_then(Value::as_str);
    let mut codes: Vec<u32> = o.get("error_codes").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_u64).filter_map(|n| u32::try_from(n).ok()).collect()).unwrap_or_default();
    for c in description.map(aadsts_codes).unwrap_or_default() {
        if !codes.contains(&c) {
            codes.push(c);
        }
    }
    codes.truncate(LIST_LIMIT);
    let expires_in = match o.get("expires_in") {
        Some(Value::Number(n)) => n.as_u64().or_else(|| n.as_f64().filter(|f| *f >= 0.0).map(|f| f as u64)),
        Some(Value::String(s)) => s.trim().parse().ok(),
        _ => None,
    }
    .map(|n| n.min(u32::MAX as u64) as u32);
    let token_claims = |k: &str| o.get(k).and_then(Value::as_str).and_then(jwt_claims);
    Some(AnalyzerOauthResponse {
        error: param_str(&o, "error", CLAIM_LIMIT),
        error_description: description.map(safe_description),
        error_codes: codes,
        error_uri: o.get("error_uri").and_then(Value::as_str).map(|u| cap_bytes(&redact_url(u), PARAM_LIMIT)),
        trace_id: param_str(&o, "trace_id", CLAIM_LIMIT),
        correlation_id: param_str(&o, "correlation_id", CLAIM_LIMIT),
        token_type: param_str(&o, "token_type", CLAIM_LIMIT),
        expires_in,
        has_access_token: present(&o, "access_token"),
        has_refresh_token: present(&o, "refresh_token"),
        has_id_token: present(&o, "id_token"),
        scope: param_str(&o, "scope", PARAM_LIMIT),
        access_token: token_claims("access_token"),
        id_token: token_claims("id_token"),
    })
}

// ------------------------------------------------------------------ discovery

/// Whether the path is an OpenID Connect discovery document.
pub fn is_discovery_path(path: &str) -> bool {
    path.to_ascii_lowercase().ends_with("/.well-known/openid-configuration")
}

/// The endpoints of a discovery document (each at most [`PARAM_LIMIT`], URL-redacted).
pub fn discovery(path: &str, body: &[u8]) -> Option<AnalyzerOidcDiscovery> {
    if !is_discovery_path(path) || body.len() > AUTH_BODY_LIMIT || !json_object_prefix(body) {
        return None;
    }
    let o = json_object(body)?;
    let url = |k: &str| o.get(k).and_then(Value::as_str).map(|u| cap_bytes(&redact_url(u), PARAM_LIMIT));
    let d = AnalyzerOidcDiscovery {
        issuer: url("issuer"),
        authorization_endpoint: url("authorization_endpoint"),
        token_endpoint: url("token_endpoint"),
        jwks_uri: url("jwks_uri"),
        end_session_endpoint: url("end_session_endpoint"),
    };
    (d != AnalyzerOidcDiscovery::default()).then_some(d)
}

// ------------------------------------------------------------------ session

/// Inputs of [`auth_info`]: the request line and headers that matter, and the decoded
/// bodies when they are complete and at most [`AUTH_BODY_LIMIT`] (else `None`).
pub struct AuthInput<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub authorization: Option<&'a str>,
    pub request_content_type: Option<&'a str>,
    pub request_body: Option<&'a [u8]>,
    pub response_body: Option<&'a [u8]>,
}

/// All authentication facts of a session; `None` when there are none.
pub fn auth_info(i: &AuthInput) -> Option<AnalyzerAuthInfo> {
    let path = url_path(i.url);
    let (bearer, opaque_bearer) = bearer(i.authorization);
    let a = AnalyzerAuthInfo {
        bearer,
        opaque_bearer,
        oauth_request: i.request_body.and_then(|b| oauth_request(i.method, path, i.request_content_type, i.authorization, b)),
        oauth_response: i.response_body.and_then(oauth_response),
        discovery: i.response_body.and_then(|b| discovery(path, b)),
    };
    (a != AnalyzerAuthInfo::default()).then_some(a)
}

/// Approximate size of the facts in a batch.
pub fn auth_bytes(a: &AnalyzerAuthInfo) -> usize {
    let s = |o: &Option<String>| o.as_ref().map_or(0, String::len);
    let l = |v: &Vec<String>| v.iter().map(|x| x.len() + 16).sum::<usize>();
    let jwt = |c: &Option<AnalyzerJwtClaims>| c.as_ref().map_or(0, |c| 160 + c.alg.len() + s(&c.typ) + s(&c.iss) + s(&c.client) + s(&c.tenant) + s(&c.ver) + l(&c.aud) + l(&c.scopes) + l(&c.roles));
    let req = a.oauth_request.as_ref().map_or(0, |r| 64 + s(&r.grant_type) + s(&r.client_id) + s(&r.scope) + s(&r.redirect_uri));
    let resp = a.oauth_response.as_ref().map_or(0, |r| {
        128 + s(&r.error) + s(&r.error_description) + s(&r.error_uri) + s(&r.trace_id) + s(&r.correlation_id) + s(&r.token_type) + s(&r.scope) + r.error_codes.len() * 4 + jwt(&r.access_token) + jwt(&r.id_token)
    });
    let disc = a.discovery.as_ref().map_or(0, |d| 64 + s(&d.issuer) + s(&d.authorization_endpoint) + s(&d.token_endpoint) + s(&d.jwks_uri) + s(&d.end_session_endpoint));
    64 + jwt(&a.bearer) + req + resp + disc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uris_lose_query_and_user_info() {
        assert_eq!(bare_redirect("https://user:SECRET-PASS@app.test/cb?x=1"), "https://app.test/cb");
        assert_eq!(bare_redirect("https%3A%2F%2Fuser%3ASECRET-PASS%40app.test%2Fcb%3Fx%3D1"), "https%3A%2F%2Fapp.test%2Fcb");
        assert_eq!(bare_redirect("https://app.test/cb#frag"), "https://app.test/cb");
        assert_eq!(bare_redirect("http://localhost:3000/a@b"), "http://localhost:3000/a@b", "an @ in the path is no user info");
        assert_eq!(bare_redirect("com.example.app:/oauth2redirect"), "com.example.app:/oauth2redirect");
    }

    fn b64url(data: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for c in data.chunks(3) {
            let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
            for k in 0..=c.len() {
                out.push(A[(n >> (18 - 6 * k) & 63) as usize] as char);
            }
        }
        out
    }

    fn jwt(header: &Value, payload: &Value) -> String {
        format!("{}.{}.{}", b64url(header.to_string().as_bytes()), b64url(payload.to_string().as_bytes()), "SECRET-SIGNATURE-xyz")
    }

    /// Secret / personal values used in the tests; none may appear in any fact.
    const SECRETS: &[&str] = &[
        "SECRET-SUB-1",
        "secret.person@example.com",
        "SECRET-UPN",
        "Secret Person",
        "SECRET-OID",
        "SECRET-NONCE",
        "SECRET-JTI",
        "SECRET-SIGNATURE",
        "SECRET-CODE-123",
        "SECRET-VERIFIER",
        "SECRET-REFRESH",
        "SECRET-CLIENT-SECRET",
        "SECRET-ASSERTION",
        "SECRET-ACCESS",
        "SECRET-STATE",
        "SECRET-HINT",
        "SECRET-CHALLENGE",
        "secret.person",
        "SECRET-UTI",
        "SECRET-CB-QUERY",
    ];

    fn assert_clean(what: &str) {
        for s in SECRETS {
            assert!(!what.contains(s), "{s} leaked: {what}");
        }
    }

    fn personal_payload() -> Value {
        serde_json::json!({
            "iss": "https://login.microsoftonline.com/tenant-1/v2.0",
            "aud": ["api://orders", "https://graph.test"],
            "exp": 1_790_000_000u64, "nbf": 1_789_996_400.5, "iat": 1_789_996_400u64,
            "azp": "client-app-1", "tid": "tenant-1", "ver": "2.0",
            "scp": "Orders.Read Orders.Write  openid",
            "roles": ["Admin", "Reader"],
            "groups": ["g1", "g2", "g3"],
            "sub": "SECRET-SUB-1", "oid": "SECRET-OID", "email": "secret.person@example.com",
            "upn": "SECRET-UPN", "name": "Secret Person", "preferred_username": "secret.person@example.com",
            "given_name": "Secret", "family_name": "Person", "unique_name": "SECRET-UPN",
            "nonce": "SECRET-NONCE", "jti": "SECRET-JTI", "uti": "SECRET-UTI",
        })
    }

    #[test]
    fn jwt_yields_only_allowed_claims() {
        let t = jwt(&serde_json::json!({"alg": "RS256", "typ": "JWT", "kid": "SECRET-SUB-1"}), &personal_payload());
        let c = jwt_claims(&t).expect("claims");
        assert_eq!(c.alg, "RS256");
        assert_eq!(c.typ.as_deref(), Some("JWT"));
        assert_eq!(c.iss.as_deref(), Some("https://login.microsoftonline.com/tenant-1/v2.0"));
        assert_eq!(c.aud, vec!["api://orders", "https://graph.test"]);
        assert_eq!((c.exp, c.nbf, c.iat), (Some(1_790_000_000), Some(1_789_996_400), Some(1_789_996_400)));
        assert_eq!((c.client.as_deref(), c.tenant.as_deref(), c.ver.as_deref()), (Some("client-app-1"), Some("tenant-1"), Some("2.0")));
        assert_eq!(c.scopes, vec!["Orders.Read", "Orders.Write", "openid"]);
        assert_eq!(c.roles, vec!["Admin", "Reader"]);
        assert_eq!((c.groups, c.groups_overage, c.size as usize), (Some(3), false, t.len()));
        assert_clean(&format!("{c:?}"));

        // aud as a string, scope instead of scp, appid / client_id, groups overage.
        let p = serde_json::json!({"aud": "api://x", "scope": "a b", "appid": "app-2", "_claim_names": {"groups": "src1"}, "exp": "soon"});
        let c = jwt_claims(&jwt(&serde_json::json!({"alg": "none"}), &p)).unwrap();
        assert_eq!((c.aud, c.scopes, c.client.as_deref(), c.groups_overage, c.exp, c.groups), (vec!["api://x".to_string()], vec!["a".to_string(), "b".into()], Some("app-2"), true, None, None));
        let c = jwt_claims(&jwt(&serde_json::json!({"alg": "HS256"}), &serde_json::json!({"client_id": "c3", "hasgroups": true}))).unwrap();
        assert_eq!((c.client.as_deref(), c.groups_overage), (Some("c3"), true));

        // Caps: strings 256 bytes, lists 64 entries.
        let roles: Vec<String> = (0..100).map(|i| format!("{i}{}", "r".repeat(if i == 0 { 300 } else { 10 }))).collect();
        let c = jwt_claims(&jwt(&serde_json::json!({"alg": "RS256"}), &serde_json::json!({"roles": roles, "iss": "i".repeat(1000)}))).unwrap();
        assert_eq!(c.roles.len(), LIST_LIMIT);
        assert!(c.roles.iter().all(|r| r.len() <= CLAIM_LIMIT) && c.iss.unwrap().len() <= CLAIM_LIMIT);

        // Not JWTs.
        assert!(jwt_claims("opaque-token").is_none());
        assert!(jwt_claims("a.b.c.d.e").is_none(), "JWE");
        assert!(jwt_claims(&format!("{}.{}.s", b64url(b"{\"typ\":\"JWT\"}"), b64url(b"{}"))).is_none(), "no alg");
        assert!(jwt_claims(&format!("{}.{}.s", b64url(b"{\"alg\":\"RS256\"}"), b64url(&vec![b' '; JWT_PART_LIMIT + 10]))).is_none(), "payload too large");
    }

    #[test]
    fn bearer_and_dpop_headers() {
        let t = jwt(&serde_json::json!({"alg": "ES256"}), &personal_payload());
        let (c, o) = bearer(Some(&format!("Bearer {t}")));
        assert!(c.is_some() && o.is_none());
        assert_clean(&format!("{c:?}"));
        assert!(bearer(Some(&format!("dpop  {t} "))).0.is_some());
        assert_eq!(bearer(Some("Bearer SECRET-ACCESS-opaque")), (None, Some(20)));
        assert_eq!(bearer(Some("Basic dXNlcjpwYXNz")), (None, None));
        assert_eq!(bearer(Some("Bearer")), (None, None));
        assert_eq!(bearer(None), (None, None));
    }

    #[test]
    fn token_requests_give_only_names_and_booleans() {
        let body = b"grant_type=authorization_code&code=SECRET-CODE-123&code_verifier=SECRET-VERIFIER&client_id=app-1&client_secret=SECRET-CLIENT-SECRET&redirect_uri=https%3A%2F%2Fapp.test%2Fcb%3Fx%3DSECRET-CB-QUERY&scope=openid+profile+api%3A%2F%2Forders%2F.default";
        let r = oauth_request("POST", "/tenant/oauth2/v2.0/token", Some("application/x-www-form-urlencoded; charset=utf-8"), None, body).unwrap();
        assert_eq!(r.grant_type.as_deref(), Some("authorization_code"));
        assert_eq!(r.client_id.as_deref(), Some("app-1"));
        assert_eq!(r.scope.as_deref(), Some("openid profile api://orders/.default"));
        assert_eq!(r.redirect_uri.as_deref(), Some("https://app.test/cb"));
        assert!(r.has_code && r.has_code_verifier && r.has_client_secret && !r.has_refresh_token && !r.has_client_assertion && !r.basic_client_auth);
        assert_clean(&format!("{r:?}"));

        let body = b"grant_type=refresh_token&refresh_token=SECRET-REFRESH&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=SECRET-ASSERTION";
        let r = oauth_request("post", "/x", Some("application/x-www-form-urlencoded"), Some("Basic Y2xpZW50OnNlY3JldA=="), body).unwrap();
        assert!(r.has_refresh_token && r.has_client_assertion && r.basic_client_auth && !r.has_code);
        assert_clean(&format!("{r:?}"));

        // A token endpoint without grant_type (device code request); other forms are no OAuth.
        assert!(oauth_request("POST", "/realms/r/protocol/openid-connect/token/", Some("application/x-www-form-urlencoded"), None, b"client_id=a").is_some());
        assert!(oauth_request("POST", "/oauth2/devicecode", Some("application/x-www-form-urlencoded"), None, b"client_id=a&scope=x").is_some());
        assert!(oauth_request("POST", "/search", Some("application/x-www-form-urlencoded"), None, b"q=token").is_none());
        assert!(oauth_request("GET", "/token", Some("application/x-www-form-urlencoded"), None, b"grant_type=x").is_none());
        assert!(oauth_request("POST", "/token", Some("application/json"), None, b"{\"grant_type\":\"x\"}").is_none());
        assert!(oauth_request("POST", "/token", Some("application/x-www-form-urlencoded"), None, &vec![b'a'; AUTH_BODY_LIMIT + 1]).is_none());
    }

    #[test]
    fn error_responses_keep_codes_and_mask_emails() {
        let body = serde_json::json!({
            "error": "invalid_request",
            "error_description": "AADSTS50011: The redirect URI 'https://app/cb' specified in the request does not match the redirect URIs configured for the application. User 'secret.person@example.com' (also <secret.person@example.com>). Trace ID: t-1 Correlation ID: c-1 Timestamp: 2026-10-01 10:00:00Z. See also AADSTS90072 for the next step. Please contact the administrator of the tenant.",
            "error_codes": [50011],
            "timestamp": "2026-10-01 10:00:00Z",
            "trace_id": "trace-1", "correlation_id": "corr-1",
            "error_uri": "https://login.microsoftonline.com/error?code=50011",
        });
        let r = oauth_response(body.to_string().as_bytes()).unwrap();
        assert_eq!(r.error.as_deref(), Some("invalid_request"));
        assert_eq!(r.error_codes, vec![50011, 90072]);
        let d = r.error_description.clone().unwrap();
        assert!(d.starts_with("AADSTS50011: The redirect URI 'https://app/cb' specified"), "{d}");
        assert!(d.len() <= DESCRIPTION_LIMIT && d.ends_with('…'), "{d}");
        assert_eq!((r.trace_id.as_deref(), r.correlation_id.as_deref()), (Some("trace-1"), Some("corr-1")));
        assert!(r.error_uri.as_deref().unwrap().starts_with("https://login.microsoftonline.com/error?code=%3C"), "{:?}", r.error_uri);
        assert!(!r.has_access_token && r.access_token.is_none());
        assert_clean(&format!("{r:?}"));

        // Masking also in a short description.
        assert_eq!(safe_description("User secret.person@example.com. Not found"), "User <email>. Not found");
        assert_eq!(mask_emails("a@b x@y.z, @. foo@bar"), "a@b <email>, @. foo@bar");

        let kc = oauth_response(br#"{"error":"invalid_grant","error_description":"Code not valid"}"#).unwrap();
        assert_eq!((kc.error.as_deref(), kc.error_description.as_deref(), kc.error_codes.len()), (Some("invalid_grant"), Some("Code not valid"), 0));

        // Not OAuth: error as an object (OData), no keys, arrays, too large.
        assert!(oauth_response(br#"{"error":{"code":"x","message":"y"}}"#).is_none());
        assert!(oauth_response(br#"{"items":[]}"#).is_none());
        assert!(oauth_response(br#"[{"error":"x"}]"#).is_none());
        let mut big = br#"{"error":"x","pad":""#.to_vec();
        big.extend(vec![b'a'; AUTH_BODY_LIMIT]);
        big.extend(b"\"}");
        assert!(oauth_response(&big).is_none());
    }

    #[test]
    fn token_responses_give_claims_but_no_tokens() {
        let access = jwt(&serde_json::json!({"alg": "RS256", "typ": "at+jwt"}), &personal_payload());
        let id = jwt(&serde_json::json!({"alg": "RS256"}), &personal_payload());
        let body = serde_json::json!({
            "token_type": "Bearer", "expires_in": "3599", "scope": "openid Orders.Read",
            "access_token": access, "refresh_token": "SECRET-REFRESH", "id_token": id,
        });
        let r = oauth_response(body.to_string().as_bytes()).unwrap();
        assert_eq!((r.token_type.as_deref(), r.expires_in, r.scope.as_deref()), (Some("Bearer"), Some(3599), Some("openid Orders.Read")));
        assert!(r.has_access_token && r.has_refresh_token && r.has_id_token);
        assert_eq!(r.access_token.as_ref().unwrap().typ.as_deref(), Some("at+jwt"));
        assert_eq!(r.id_token.as_ref().unwrap().client.as_deref(), Some("client-app-1"));
        let dbg = format!("{r:?}");
        assert!(!dbg.contains(&access) && !dbg.contains(&id));
        assert_clean(&dbg);
        // Opaque access token: present, no claims.
        let r = oauth_response(br#"{"access_token":"SECRET-ACCESS","expires_in":3600}"#).unwrap();
        assert!(r.has_access_token && r.access_token.is_none() && r.expires_in == Some(3600));
        assert_clean(&format!("{r:?}"));
        // Device code response.
        let r = oauth_response(br#"{"device_code":"SECRET-CODE-123","user_code":"SECRET-CODE-123","verification_uri":"https://x/device","expires_in":900}"#).unwrap();
        assert_eq!(r.expires_in, Some(900));
        assert_clean(&format!("{r:?}"));
    }

    #[test]
    fn discovery_documents() {
        let body = br#"{"issuer":"https://kc.test/realms/r","authorization_endpoint":"https://kc.test/realms/r/protocol/openid-connect/auth","token_endpoint":"https://kc.test/realms/r/protocol/openid-connect/token","jwks_uri":"https://kc.test/realms/r/protocol/openid-connect/certs","end_session_endpoint":"https://kc.test/realms/r/protocol/openid-connect/logout","grant_types_supported":["x"]}"#;
        let d = discovery("/realms/r/.well-known/openid-configuration", body).unwrap();
        assert_eq!(d.issuer.as_deref(), Some("https://kc.test/realms/r"));
        assert_eq!(d.token_endpoint.as_deref(), Some("https://kc.test/realms/r/protocol/openid-connect/token"));
        assert!(d.authorization_endpoint.is_some() && d.jwks_uri.is_some() && d.end_session_endpoint.is_some());
        assert!(discovery("/realms/r/account", body).is_none());
        assert!(discovery("/.well-known/openid-configuration", b"<html>").is_none());
        let long = format!(r#"{{"issuer":"https://x.test/{}"}}"#, "a".repeat(1000));
        assert!(discovery("/.well-known/openid-configuration", long.as_bytes()).unwrap().issuer.unwrap().len() <= PARAM_LIMIT);
    }

    #[test]
    fn helpers() {
        assert_eq!(url_path("https://h.test:8443/a/token?x=1#f"), "/a/token");
        assert_eq!(url_path("https://h.test?x=1"), "");
        assert_eq!(url_path("/p/q?x"), "/p/q");
        assert_eq!(strip_query("https%3A%2F%2Fa%2Fcb%3Fx%3D1"), "https%3A%2F%2Fa%2Fcb");
        assert_eq!(strip_query("https://a/cb#f"), "https://a/cb");
        assert_eq!(aadsts_codes("AADSTS70008: expired. See AADSTS 1 and AADSTS700016x"), vec![70008, 700016]);
        assert_eq!(cap_bytes(&"é".repeat(200), 300).len(), 299);
        assert_eq!(encode_component("a b<é>"), "a%20b%3C%C3%A9%3E");
        assert!(is_token_path("/as/token.oauth2") && is_token_path("/OAuth/Token") && !is_token_path("/tokens"));
    }
}
