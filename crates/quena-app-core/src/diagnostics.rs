//! Diagnostics: runs an analyzer plugin (e.g. `webdiag`) over the visible sessions or a
//! selection and keeps the last report.
//!
//! The host builds one record per session (plugins/webdiag/REPORT.md): allow-listed headers
//! with secrets redacted, sizes, timers, connection data and fingerprints of the decoded
//! bodies. Credentials in the redacted headers (`Authorization`, `Cookie`, `Set-Cookie`,
//! the `*-Authenticate` challenges) never reach the plugin; in the session URL, `Location`
//! and `Referer` the user info, the values of sensitive query/fragment parameters and every
//! other parameter value longer than 64 bytes are replaced by their size (OData `$` system
//! options are only subject to the name rule). URL paths are passed unchanged. The values of
//! well-known OAuth parameters (`response_type`, `scope`, `client_id`, `redirect_uri` without
//! its query, `error` …) and of the non-secret `*-Authenticate` parameters (`realm`, `error`,
//! `error_description` …) are kept; `error_description` is cut and has e-mails masked.
//! Authentication facts (JWT claims, OAuth requests / responses, discovery) come from
//! [`auth_facts`].

#[path = "auth_facts.rs"]
pub mod auth_facts;

use crate::AppCore;
use anyhow::{Result, anyhow};
use quena_body::Body;
use quena_jobs::{JobCtx, JobId, Priority};
use quena_model::{Headers, Micros, SessionDetail, SessionId, SessionKind};
use auth_facts::{AUTH_BODY_LIMIT, AuthInput, PARAM_LIMIT, encode_component, safe_description};
use quena_plugin_host::{AnalyzerSession, AnalyzerTextInfo, AnalyzerTimers, PluginKind};
use quena_store::Capture;
use serde::Serialize;
use std::io::Read;
use std::sync::Arc;

/// Sessions per `push`.
pub const BATCH: usize = 2000;
/// Largest decoded request body that gets a fingerprint.
pub const REQUEST_HASH_LIMIT: u64 = 1 << 20;
/// Largest decoded response body that gets a fingerprint.
pub const RESPONSE_HASH_LIMIT: u64 = 8 << 20;
/// Decoding stops here when only the decoded size is still wanted (decompression bombs);
/// a larger decoded size is reported as this lower bound (REPORT.md).
pub const DECODED_COUNT_LIMIT: u64 = 256 << 20;
/// Longest URL / header value passed to an analyzer; longer values are cut and marked.
pub const FIELD_LIMIT: usize = 8 << 10;
/// Headers per direction passed to an analyzer (further ones are dropped).
pub const HEADER_COUNT_LIMIT: usize = 256;
/// Approximate size limit of one `push` batch (besides [`BATCH`] sessions).
pub const BATCH_BYTES: usize = 16 << 20;
/// Query/fragment parameter values longer than this are replaced by their size.
pub const URL_VALUE_LIMIT: usize = 64;
/// Decoded bytes of a textual body examined for its encoding facts (REPORT.md).
pub const TEXT_SAMPLE: usize = 256 << 10;
/// Longest charset label passed as written; longer ones become `<n bytes>` (a label comes
/// from the body and must not carry content out of the host).
pub const LABEL_LIMIT: usize = 64;
/// Longest decoding error message passed to an analyzer.
pub const DECODING_ERROR_LIMIT: usize = 200;

/// Headers passed to analyzers (lower case); everything else is dropped.
pub const HEADER_ALLOW_LIST: &[&str] = &[
    "accept-encoding",
    "access-control-allow-origin",
    "access-control-max-age",
    "access-control-request-method",
    "age",
    "authorization",
    "cache-control",
    "connection",
    "content-encoding",
    "content-length",
    "content-type",
    "cookie",
    // Server time: clock-skew diagnostics compare it with the local receive time.
    "date",
    "etag",
    "expires",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "keep-alive",
    "last-modified",
    "location",
    "odata-version",
    "origin",
    "pragma",
    "prefer",
    "proxy-authenticate",
    "proxy-authorization",
    "range",
    "content-range",
    "referer",
    "request-id",
    "retry-after",
    "set-cookie",
    "soapaction",
    "strict-transport-security",
    "traceparent",
    "transfer-encoding",
    "vary",
    "www-authenticate",
    "x-correlation-id",
    "x-http-method-override",
    "x-ms-request-id",
    "x-request-id",
];

// ------------------------------------------------------------------ redaction

/// `token` characters of RFC 9110 (header names, auth schemes, parameter names).
fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Plausible authentication scheme name (`Bearer`, `AWS4-HMAC-SHA256` …).
fn is_scheme(s: &str) -> bool {
    s.len() <= 32 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') && s.bytes().any(|b| b.is_ascii_alphabetic())
}

/// Schemes that are recognised even without credentials after them.
const KNOWN_SCHEMES: &[&str] = &["basic", "bearer", "digest", "negotiate", "ntlm", "kerberos", "hoba", "mutual", "hawk", "oauth", "token", "dpop"];

fn bytes(n: usize) -> String {
    format!("<{n} bytes>")
}

/// `Authorization` / `Proxy-Authorization`: scheme plus the credential size.
pub fn redact_authorization(v: &str) -> String {
    let v = v.trim();
    if v.is_empty() {
        return String::new();
    }
    match v.split_once(|c: char| c.is_ascii_whitespace()) {
        Some((scheme, rest)) if is_scheme(scheme) => {
            let rest = rest.trim();
            if rest.is_empty() { scheme.to_string() } else { format!("{scheme} {}", bytes(rest.len())) }
        }
        None if is_scheme(v) && KNOWN_SCHEMES.contains(&v.to_ascii_lowercase().as_str()) => v.to_string(),
        // No recognisable scheme: the whole value may be the secret.
        _ => bytes(v.len()),
    }
}

/// Split at commas outside quoted strings.
fn split_commas(v: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut start, mut quoted, mut escaped) = (0, false, false);
    for (i, c) in v.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ',' if !quoted => {
                out.push(&v[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&v[start..]);
    out
}

/// `name=value` auth parameter → (`name`, `value` as written; a token68 like `abc==` is no
/// parameter).
fn param_name(s: &str) -> Option<(&str, &str)> {
    let (name, value) = s.split_once('=')?;
    let (name, value) = (name.trim_end(), value.trim());
    (is_token(name) && !value.is_empty() && !value.bytes().all(|b| b == b'=')).then_some((name, value))
}

/// Challenge parameters whose values are no secrets and are kept (lower case).
const AUTHENTICATE_KEEP: &[&str] = &["realm", "error", "error_description", "error_uri", "scope", "authorization_uri", "resource_metadata", "resource", "trusted_issuers"];

/// A `*-Authenticate` parameter: `name="value"` for the kept names (`error_description` cut
/// and e-mails masked, others at most [`PARAM_LIMIT`] bytes or `<n bytes>`), else the name.
fn authenticate_param(name: &str, value: &str) -> String {
    let lower = name.to_ascii_lowercase();
    if !AUTHENTICATE_KEEP.contains(&lower.as_str()) {
        return name.to_string();
    }
    let quoted = value.len() >= 2 && value.starts_with('"') && value.ends_with('"');
    if lower == "error_description" {
        let raw = if quoted { &value[1..value.len() - 1] } else { value };
        let mut text = String::with_capacity(raw.len());
        let mut esc = false;
        for c in raw.chars() {
            match c {
                '\\' if !esc => esc = true,
                _ => {
                    esc = false;
                    text.push(c);
                }
            }
        }
        let safe = safe_description(&text).replace('\\', "\\\\").replace('"', "\\\"");
        return format!("{name}=\"{safe}\"");
    }
    if value.len() > PARAM_LIMIT { format!("{name}={}", bytes(value.len())) } else { format!("{name}={value}") }
}

/// `WWW-Authenticate` / `Proxy-Authenticate`: scheme and parameter names of every
/// challenge, plus the values of the non-secret parameters ([`AUTHENTICATE_KEEP`]); token68
/// values (e.g. a Negotiate token) become `<n bytes>`.
pub fn redact_authenticate(v: &str) -> String {
    // (scheme, token size, parameters)
    let mut challenges: Vec<(String, Option<usize>, Vec<String>)> = Vec::new();
    for item in split_commas(v).into_iter().map(str::trim).filter(|s| !s.is_empty()) {
        if let Some((name, value)) = param_name(item) {
            let p = authenticate_param(name, value);
            match challenges.last_mut() {
                Some(c) => c.2.push(p),
                None => challenges.push((String::new(), None, vec![p])),
            }
            continue;
        }
        let (scheme, rest) = match item.split_once(|c: char| c.is_ascii_whitespace()) {
            Some((s, r)) => (s, r.trim()),
            None => (item, ""),
        };
        if !is_scheme(scheme) {
            challenges.push((bytes(item.len()), None, vec![]));
            continue;
        }
        let mut c = (scheme.to_string(), None, vec![]);
        if !rest.is_empty() {
            match param_name(rest) {
                Some((name, value)) => c.2.push(authenticate_param(name, value)),
                None => c.1 = Some(rest.len()),
            }
        }
        challenges.push(c);
    }
    challenges
        .into_iter()
        .map(|(scheme, token, params)| {
            let mut s = scheme;
            if let Some(n) = token {
                s.push(' ');
                s.push_str(&bytes(n));
            }
            if !params.is_empty() {
                if !s.is_empty() {
                    s.push(' ');
                }
                s.push_str(&params.join(", "));
            }
            s
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// `Cookie`: names only; a pair without `=` is a value (RFC 6265bis) and becomes `<n bytes>`.
pub fn redact_cookie(v: &str) -> String {
    v.split(';')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(|c| match c.split_once('=') {
            Some((n, _)) => n.trim().to_string(),
            None => bytes(c.len()),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// `Set-Cookie` attributes that are passed verbatim (lower case).
const COOKIE_ATTRS: &[&str] = &["path", "domain", "expires", "max-age", "secure", "httponly", "samesite", "partitioned", "priority"];

/// Whether `s` (after a comma) starts a new `name=value` cookie. A comma inside an
/// `Expires` date is followed by a day number and a space (`Wed, 21 Oct …`), no token `=`.
fn starts_cookie(s: &str) -> bool {
    s.split_once('=').is_some_and(|(n, _)| is_token(n.trim()))
}

/// One cookie: `name=<n bytes>`, known attributes verbatim, anything else by its size.
fn redact_one_set_cookie(v: &str) -> String {
    let mut parts = v.split(';');
    let pair = parts.next().unwrap_or("").trim();
    let (name, value) = pair.split_once('=').unwrap_or(("", pair));
    let mut out = format!("{}={}", name.trim(), bytes(value.trim().len()));
    for a in parts.map(str::trim).filter(|a| !a.is_empty()) {
        let (n, val) = match a.split_once('=') {
            Some((n, v)) => (n.trim(), Some(v.trim())),
            None => (a, None),
        };
        out.push_str("; ");
        if COOKIE_ATTRS.contains(&n.to_ascii_lowercase().as_str()) {
            out.push_str(a);
        } else {
            match val {
                Some(v) if is_token(n) => out.push_str(&format!("{n}={}", bytes(v.len()))),
                _ => out.push_str(&bytes(a.len())),
            }
        }
    }
    out
}

/// `Set-Cookie`: `name=<n bytes>` plus the known attributes (Path, Domain, Expires,
/// Max-Age, Secure, HttpOnly, SameSite, Partitioned, Priority) verbatim; unknown attributes
/// become `name=<n bytes>`. A value carrying several cookies (joined with a line break or
/// folded with `, ` by HAR exporters and intermediaries) has each of them redacted.
pub fn redact_set_cookie(v: &str) -> String {
    v.split('\n')
        .map(|line| {
            let mut cookies: Vec<&str> = Vec::new();
            let mut start = 0;
            for (i, _) in line.match_indices(',') {
                if starts_cookie(&line[i + 1..]) {
                    cookies.push(&line[start..i]);
                    start = i + 1;
                }
            }
            cookies.push(&line[start..]);
            cookies.into_iter().map(redact_one_set_cookie).collect::<Vec<_>>().join(", ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Query/fragment parameter names whose values are secrets (lower case, exact).
const SECRET_PARAMS: &[&str] = &[
    "auth", "code", "state", "nonce", "sig", "key", "sid", "otp", // OAuth, signed URLs, sessions
    "code_challenge", "code_verifier", "login_hint", // OAuth PKCE, personal hints
    "se", "sp", "sv", "sr", "st", "spr", "srt", "ss", "si", "sdd", "skoid", "sktid", "skt", "ske", "sks", "skv", // Azure SAS
];
/// Parameter names that contain one of these (lower case) carry secrets, e.g. `access_token`,
/// `id_token`, `refresh_token`, `client_secret`, `SAMLResponse`, `X-Goog-Credential`.
const SECRET_PARAM_PARTS: &[&str] =
    &["token", "password", "passwd", "secret", "signature", "apikey", "api_key", "api-key", "session", "credential", "jwt", "assertion", "samlresponse", "samlrequest", "ticket"];
/// Parameter name prefixes that carry secrets (AWS / GCS signed URLs).
const SECRET_PARAM_PREFIXES: &[&str] = &["x-amz-", "x-goog-"];

/// OAuth / OIDC parameters whose values are kept up to [`PARAM_LIMIT`] bytes (lower case;
/// REPORT.md "Authentication facts"). `error_description` is cut and has e-mails masked,
/// `redirect_uri` loses its own query.
const OAUTH_PARAMS: &[&str] = &[
    "response_type",
    "response_mode",
    "scope",
    "prompt",
    "client_id",
    "redirect_uri",
    "code_challenge_method",
    "grant_type",
    "max_age",
    "acr_values",
    "ui_locales",
    "domain_hint",
    "error",
    "error_description",
    "error_uri",
    "error_subcode",
];

/// The value of a kept OAuth parameter (`name` lower case, see [`OAUTH_PARAMS`]).
fn oauth_param_value(name: &str, value: &str) -> String {
    let v = match name {
        "error_description" => encode_component(&safe_description(&decode_param(value))),
        "redirect_uri" => auth_facts::bare_redirect(value),
        _ => value.to_string(),
    };
    if v.len() > PARAM_LIMIT { url_bytes(v.len()) } else { v }
}

/// Percent-decoding (and `+` → space) of a parameter name, for matching only.
fn decode_param(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => match std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                Some(x) => {
                    out.push(x);
                    i += 2;
                }
                None => out.push(b'%'),
            },
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn secret_param(name: &str) -> bool {
    let n = decode_param(name).trim().to_ascii_lowercase();
    SECRET_PARAMS.contains(&n.as_str()) || SECRET_PARAM_PARTS.iter().any(|p| n.contains(p)) || SECRET_PARAM_PREFIXES.iter().any(|p| n.starts_with(p))
}

/// `<n bytes>`, percent-encoded so the URL stays valid (it decodes to `<n bytes>`).
fn url_bytes(n: usize) -> String {
    format!("%3C{n}%20bytes%3E")
}

/// `a=1&b=2` with sensitive or long values replaced by their size.
fn redact_params(q: &str) -> String {
    q.split('&')
        .map(|p| match p.split_once('=') {
            Some((name, value)) => {
                if name.len() > URL_VALUE_LIMIT {
                    url_bytes(p.len())
                } else if !value.is_empty() && secret_param(name) {
                    format!("{name}={}", url_bytes(value.len()))
                } else if let Some(n) = Some(decode_param(name).trim().to_ascii_lowercase()).filter(|n| OAUTH_PARAMS.contains(&n.as_str())) {
                    format!("{name}={}", oauth_param_value(&n, value))
                } else if value.len() > URL_VALUE_LIMIT && !decode_param(name).starts_with('$') {
                    format!("{name}={}", url_bytes(value.len()))
                } else {
                    p.to_string()
                }
            }
            None if p.len() > URL_VALUE_LIMIT => url_bytes(p.len()),
            None => p.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Whether `url` starts with a scheme and `://` (`^[A-Za-z][A-Za-z0-9+.-]*://`).
pub fn has_scheme(url: &str) -> bool {
    let Some(i) = url.find("://") else { return false };
    let s = &url[..i];
    s.bytes().next().is_some_and(|b| b.is_ascii_alphabetic()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"+.-".contains(&b))
}

/// A URL (absolute or relative) with the user info, sensitive query/fragment values
/// (tokens, codes, signatures, keys, passwords, sessions …) and every other parameter value
/// longer than [`URL_VALUE_LIMIT`] bytes replaced by `%3Cn%20bytes%3E` (`<n bytes>`, `n` =
/// encoded length). OData system options (`$filter`, `$select` …) are only subject to the
/// name rule. Scheme, host, port and path are kept.
pub fn redact_url(url: &str) -> String {
    let (rest, fragment) = match url.split_once('#') {
        Some((r, f)) => (r, Some(f)),
        None => (url, None),
    };
    let (base, query) = match rest.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (rest, None),
    };
    let mut out = String::with_capacity(url.len());
    match base.find("://").filter(|_| has_scheme(base)) {
        Some(i) => {
            let after = &base[i + 3..];
            let auth_end = after.find('/').unwrap_or(after.len());
            let authority = &after[..auth_end];
            out.push_str(&base[..i + 3]);
            match authority.rsplit_once('@') {
                Some((userinfo, host)) => {
                    out.push_str(&url_bytes(userinfo.len()));
                    out.push('@');
                    out.push_str(host);
                }
                None => out.push_str(authority),
            }
            out.push_str(&after[auth_end..]);
        }
        None => out.push_str(base),
    }
    if let Some(q) = query {
        out.push('?');
        out.push_str(&redact_params(q));
    }
    if let Some(f) = fragment {
        out.push('#');
        if f.contains('=') {
            out.push_str(&redact_params(f));
        } else if f.len() > URL_VALUE_LIMIT {
            out.push_str(&url_bytes(f.len()));
        } else {
            out.push_str(f);
        }
    }
    out
}

/// Cut `s` to [`FIELD_LIMIT`] bytes (at a char boundary, before a split `%XX` escape in a
/// URL) and mark the cut with `…<truncated n bytes>` (percent-encoded for URLs).
fn cap_field(mut s: String, url: bool) -> String {
    if s.len() <= FIELD_LIMIT {
        return s;
    }
    let mut end = FIELD_LIMIT;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    if url && let Some(p) = s[end.saturating_sub(2)..end].find('%') {
        end = end.saturating_sub(2) + p;
    }
    let cut = s.len() - end;
    s.truncate(end);
    if url {
        s.push_str(&format!("%E2%80%A6%3Ctruncated%20{cut}%20bytes%3E"));
    } else {
        s.push_str(&format!("…<truncated {cut} bytes>"));
    }
    s
}

/// Allow-listed headers in wire order (at most [`HEADER_COUNT_LIMIT`]), secrets redacted,
/// values cut to [`FIELD_LIMIT`] (REPORT.md).
pub fn redact_headers(h: &Headers) -> Vec<(String, String)> {
    h.iter()
        .filter_map(|(name, value)| {
            let lower = name.to_ascii_lowercase();
            if !HEADER_ALLOW_LIST.contains(&lower.as_str()) {
                return None;
            }
            let value = match lower.as_str() {
                "authorization" | "proxy-authorization" => redact_authorization(value),
                "www-authenticate" | "proxy-authenticate" => redact_authenticate(value),
                "cookie" => redact_cookie(value),
                "set-cookie" => redact_set_cookie(value),
                "location" | "referer" => redact_url(value),
                _ => value.to_string(),
            };
            Some((name.to_string(), cap_field(value, false)))
        })
        .take(HEADER_COUNT_LIMIT)
        .collect()
}

/// Approximate size of a record in a batch (strings dominate).
pub fn record_bytes(r: &AnalyzerSession) -> usize {
    let h: usize = r.request_headers.iter().chain(&r.response_headers).map(|(n, v)| n.len() + v.len() + 16).sum();
    let opt = |o: &Option<String>| o.as_ref().map_or(0, |e| e.len());
    let text: usize = [&r.request_text, &r.response_text].into_iter().flatten().map(|t| 160 + opt(&t.header_charset) + opt(&t.document_charset) + t.effective.len()).sum();
    let auth = r.auth.as_ref().map_or(0, auth_facts::auth_bytes);
    256 + r.url.len() + r.method.len() + r.host.len() + r.content_type.len() + r.process.len() + opt(&r.error) + h + text + opt(&r.request_decoding_error) + opt(&r.response_decoding_error) + auth
}

// ------------------------------------------------------------------ bodies

/// FNV-1a, 64 bit.
#[derive(Clone, Copy)]
pub struct Fnv1a(u64);

impl Default for Fnv1a {
    fn default() -> Self {
        Fnv1a(0xcbf2_9ce4_8422_2325)
    }
}

impl Fnv1a {
    pub fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.0 ^= b as u64;
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    pub fn finish(self) -> u64 {
        self.0
    }
}

pub fn fnv1a(data: &[u8]) -> u64 {
    let mut h = Fnv1a::default();
    h.update(data);
    h.finish()
}

/// Decoded size and fingerprint of a body: (decoded bytes, FNV-1a of the decoded bytes if
/// they are not empty and at most `hash_limit`). With `need_len` false, decoding stops as
/// soon as the fingerprint is out of reach. Undecodable bodies get no fingerprint.
pub fn body_fingerprint(body: &Body, content_encoding: Option<&str>, hash_limit: u64, need_len: bool, cancelled: &dyn Fn() -> bool) -> (u64, Option<u64>) {
    let s = body_scan(body, content_encoding, hash_limit, need_len, 0, cancelled);
    (s.decoded, s.hash)
}

/// What one pass over a body yields ([`body_scan`]).
#[derive(Debug, Default, PartialEq)]
pub struct BodyScan {
    /// Decoded bytes (see [`body_fingerprint`]).
    pub decoded: u64,
    pub hash: Option<u64>,
    /// The first `prefix_limit` decoded bytes (for the encoding facts; never leaves the host).
    pub prefix: Vec<u8>,
    /// The Content-Encoding could not be decoded (REPORT.md: `unsupported: …` / `invalid: …`).
    pub error: Option<String>,
}

/// [`body_fingerprint`] plus the first `prefix_limit` decoded bytes and the decoding error,
/// in one pass. A body stored truncated or still incomplete reports no decoding error (its
/// end is missing, not corrupt).
pub fn body_scan(body: &Body, content_encoding: Option<&str>, hash_limit: u64, need_len: bool, prefix_limit: usize, cancelled: &dyn Fn() -> bool) -> BodyScan {
    let mut out = BodyScan::default();
    if body.is_empty() {
        return out;
    }
    let encodings = match content_encoding.map(quena_body::decode::parse_encodings) {
        None => vec![],
        Some(Ok(e)) => e,
        Some(Err(name)) => {
            out.decoded = body.len();
            out.error = Some(cap_text(format!("unsupported: {name}"), DECODING_ERROR_LIMIT));
            return out;
        }
    };
    // Plain bodies above the limit: the size is known, only the prefix is still read.
    let hashing = !(encodings.is_empty() && body.len() > hash_limit);
    if !hashing && prefix_limit == 0 {
        out.decoded = body.len();
        return out;
    }
    let mut reader = quena_body::decode::decoding_reader(Box::new(body.stream(0, false)), &encodings);
    let mut h = Fnv1a::default();
    let mut n = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        if cancelled() {
            out.decoded = n;
            return out;
        }
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(k) => {
                if out.prefix.len() < prefix_limit {
                    let take = k.min(prefix_limit - out.prefix.len());
                    out.prefix.extend_from_slice(&buf[..take]);
                }
                if n + k as u64 <= hash_limit {
                    h.update(&buf[..k]);
                }
                n += k as u64;
                let prefix_done = out.prefix.len() >= prefix_limit;
                if !hashing && prefix_done {
                    out.decoded = body.len();
                    return out;
                }
                if n > hash_limit && prefix_done && (!need_len || n >= DECODED_COUNT_LIMIT) {
                    out.decoded = if need_len { n } else { 0 };
                    return out;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            // Truncated or corrupt stream: report what was decoded, no fingerprint.
            Err(e) => {
                out.decoded = if n == 0 { body.len() } else { n };
                if !encodings.is_empty() && !body.is_truncated() && body.is_complete() && !quena_body::is_cancelled(&e) {
                    out.error = Some(cap_text(format!("invalid: {}: {e}", content_encoding.unwrap_or("").trim()), DECODING_ERROR_LIMIT));
                }
                return out;
            }
        }
    }
    out.decoded = n;
    out.hash = (n > 0 && n <= hash_limit).then(|| h.finish());
    out
}

/// `s` cut to at most `max` bytes (at a character boundary), marked with `…`.
fn cap_text(s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// A charset label as written, or `<n bytes>` when it is longer than [`LABEL_LIMIT`] or not
/// a plain token (a label is ASCII letters, digits and `-_.:()`).
fn safe_label(l: Option<String>) -> Option<String> {
    l.map(|l| {
        let token = l.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.:()".contains(&b));
        if l.len() <= LABEL_LIMIT && token { l } else { format!("<{} bytes>", l.len()) }
    })
}

/// Encoding facts of a decoded body prefix with this Content-Type, if the type is textual.
pub fn text_info(content_type: Option<&str>, prefix: &[u8]) -> Option<AnalyzerTextInfo> {
    use quena_body::charset;
    if prefix.is_empty() || !charset::is_textual(content_type) {
        return None;
    }
    let f = charset::facts(content_type, prefix);
    Some(AnalyzerTextInfo {
        header_resolved: f.header.as_deref().and_then(charset::resolved_name).map(String::from),
        document_resolved: f.document.as_deref().and_then(charset::resolved_name).map(String::from),
        header_charset: safe_label(f.header),
        document_charset: safe_label(f.document),
        bom: f.bom,
        effective: f.effective,
        source: f.source.into(),
        unknown_label: f.unknown_label,
        sampled: f.sampled,
        non_ascii: f.non_ascii,
        utf8_valid: f.utf8_valid,
        decode_errors: f.decode_errors,
        replacement_chars: f.replacement_chars,
        double_encoded: f.double_encoded,
        nul_bytes: f.nul_bytes,
        looks_compressed: charset::compressed_magic(prefix).map(String::from),
    })
}

// ------------------------------------------------------------------ records

fn us(t: Option<Micros>) -> Option<u64> {
    t.filter(|t| *t >= 0).map(|t| t as u64)
}

fn kind_name(k: SessionKind) -> &'static str {
    match k {
        SessionKind::Tunnel => "tunnel",
        SessionKind::WebSocket => "websocket",
        SessionKind::Http | SessionKind::Synthetic => "http",
    }
}

/// The analyzer record of one session (`req`/`resp`: its stored bodies).
pub fn build_record(d: &SessionDetail, req: &Body, resp: &Body, cancelled: &dyn Fn() -> bool) -> AnalyzerSession {
    let s = &d.summary;
    let t = &d.timers;
    let empty = Headers::new();
    let resp_headers = d.response.as_ref().map(|r| &r.headers).unwrap_or(&empty);
    // Tunnels keep their authority form (`host:port`).
    let full_url = if s.kind == SessionKind::Tunnel || has_scheme(&d.request.url) { d.request.url.clone() } else { s.full_url() };
    let url = if s.kind == SessionKind::Tunnel { full_url.clone() } else { redact_url(&full_url) };
    let url = cap_field(url, true);
    // One pass per body: size, fingerprint and (textual types) the prefix for the encoding
    // facts. Only facts leave the host.
    let req_ct = d.request.headers.get("content-type");
    let resp_ct = resp_headers.get("content-type").or(Some(s.content_type.as_str()).filter(|c| !c.is_empty()));
    // An untyped response may still be an OAuth / discovery JSON: its prefix is kept too
    // (the body is read for its size anyway).
    let sample = |ct: Option<&str>| if quena_body::charset::is_textual(ct) { TEXT_SAMPLE } else if ct.is_none_or(|c| c.trim().is_empty()) { AUTH_BODY_LIMIT + 1 } else { 0 };
    let rq = body_scan(req, d.request.headers.get("content-encoding"), REQUEST_HASH_LIMIT, false, sample(req_ct), cancelled);
    let rs = body_scan(resp, resp_headers.get("content-encoding"), RESPONSE_HASH_LIMIT, true, sample(resp_ct), cancelled);
    // Authentication facts from the same prefixes (only complete bodies ≤ 64 KiB are parsed).
    fn whole<'a>(scan: &'a BodyScan, body: &Body) -> Option<&'a [u8]> {
        (scan.error.is_none() && !body.is_truncated() && !scan.prefix.is_empty() && scan.prefix.len() <= AUTH_BODY_LIMIT && scan.decoded == scan.prefix.len() as u64).then_some(scan.prefix.as_slice())
    }
    let auth = if s.kind == SessionKind::Tunnel {
        None
    } else {
        auth_facts::auth_info(&AuthInput {
            method: &d.request.method,
            url: &full_url,
            authorization: d.request.headers.get("authorization"),
            request_content_type: req_ct,
            request_body: whole(&rq, req),
            response_body: whole(&rs, resp),
        })
    };
    let text = |ct: Option<&str>, b: &BodyScan| if b.error.is_none() { text_info(ct, &b.prefix) } else { None };
    let (request_text, response_text) = (text(req_ct, &rq), text(resp_ct, &rs));
    let (req_hash, resp_decoded, resp_hash) = (rq.hash, rs.decoded, rs.hash);
    AnalyzerSession {
        id: s.id,
        kind: kind_name(s.kind).into(),
        started: us(Some(s.started_at)).unwrap_or(0),
        duration_ms: s.duration_ms,
        method: d.request.method.clone(),
        url,
        host: s.host.clone(),
        version: d.request.version.as_str().into(),
        status: d.response.as_ref().map(|r| r.status).unwrap_or(0),
        error: d.error.clone().map(|e| cap_field(e, false)),
        request_bytes: d.request_body.wire_len().max(s.request_body_len),
        response_bytes: d.response_body.wire_len().max(s.response_body_len),
        response_decoded_bytes: resp_decoded,
        content_type: s.content_type.clone(),
        request_headers: redact_headers(&d.request.headers),
        response_headers: redact_headers(resp_headers),
        timers: AnalyzerTimers {
            client_begin_request: us(t.client_begin_request),
            client_done_request: us(t.client_done_request),
            server_connect_start: us(t.server_connect_start),
            server_connected: us(t.server_connected),
            server_begin_request: us(t.server_begin_request),
            server_done_request: us(t.server_done_request),
            server_got_first_byte: us(t.server_got_first_byte),
            server_done_response: us(t.server_done_response),
            client_done_response: us(t.client_done_response),
            dns_ms: t.dns_ms,
            tcp_connect_ms: t.tcp_connect_ms,
            tls_handshake_ms: t.tls_handshake_ms,
        },
        client_connection: d.connection.client_conn_id,
        server_connection_reused: d.connection.server_conn_reused,
        tls_version: d.connection.server_tls.as_ref().map(|t| t.version.clone()).filter(|v| !v.is_empty()),
        process: s.process.clone(),
        request_body_hash: req_hash,
        response_body_hash: resp_hash,
        request_text,
        response_text,
        request_decoding_error: rq.error,
        response_decoding_error: rs.error,
        auth,
    }
}

/// Record of a session in a capture (`None` if it was removed meanwhile).
pub fn record_of(cap: &Capture, id: SessionId, cancelled: &dyn Fn() -> bool) -> Option<AnalyzerSession> {
    let d = cap.detail(id)?;
    let (req, resp) = cap.bodies_of(id)?;
    Some(build_record(&d, &req, &resp, cancelled))
}

/// Scope of a run: the selection (`ids`, if not empty) or the visible sessions, sorted by
/// start (ties keep the view / selection order). Returns (ids, `"selection"` | `"visible"`).
/// Narrows the analysed sessions to processes and/or target hosts (empty = no restriction).
/// A host entry `*.example.com` also matches its subdomains.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DiagFilter {
    pub processes: Vec<String>,
    pub hosts: Vec<String>,
}

impl DiagFilter {
    pub fn is_empty(&self) -> bool {
        self.processes.is_empty() && self.hosts.is_empty()
    }
    fn host_matches(pattern: &str, host: &str) -> bool {
        // Hosts in the list may carry a port; patterns match with or without it.
        let bare = |h: &str| h.rsplit_once(':').filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit())).map(|(h, _)| h.to_string()).unwrap_or_else(|| h.to_string());
        let (p, h) = (pattern.to_ascii_lowercase(), host.to_ascii_lowercase());
        match p.strip_prefix("*.") {
            Some(domain) => {
                let hb = bare(&h);
                hb == domain || hb.ends_with(&format!(".{domain}"))
            }
            None => h == p || bare(&h) == p,
        }
    }
    pub fn matches(&self, s: &quena_model::SessionSummary) -> bool {
        (self.processes.is_empty() || self.processes.iter().any(|p| p == &s.process))
            && (self.hosts.is_empty() || self.hosts.iter().any(|p| Self::host_matches(p, &s.host)))
    }
}

/// Sessions to analyse, in start order: the given ids (selection) or the visible list,
/// narrowed by `filter`.
pub fn scope_ids(cap: &Capture, ids: Option<Vec<SessionId>>, filter: &DiagFilter) -> (Vec<SessionId>, &'static str) {
    let mut rows: Vec<(Micros, SessionId)> = Vec::new();
    let kind = match ids.filter(|i| !i.is_empty()) {
        Some(ids) => {
            let mut seen = std::collections::HashSet::new();
            rows.extend(
                ids.into_iter().filter(|id| seen.insert(*id)).filter_map(|id| cap.index.get(id)).filter(|s| filter.matches(s)).map(|s| (s.started_at, s.id)),
            );
            "selection"
        }
        None => {
            cap.index.for_each_view(|s| {
                if filter.matches(s) {
                    rows.push((s.started_at, s.id))
                }
            });
            "visible"
        }
    };
    rows.sort_by_key(|r| r.0);
    (rows.into_iter().map(|r| r.1).collect(), kind)
}

/// Processes and hosts of the visible sessions with their counts (most first), for choosing
/// the scope of an analysis.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagScopeOptions {
    pub processes: Vec<(String, u64)>,
    pub hosts: Vec<(String, u64)>,
}

pub fn scope_options(cap: &Capture) -> DiagScopeOptions {
    let mut procs: std::collections::HashMap<String, u64> = Default::default();
    let mut hosts: std::collections::HashMap<String, u64> = Default::default();
    cap.index.for_each_view(|s| {
        *procs.entry(s.process.clone()).or_default() += 1;
        if !s.host.is_empty() {
            *hosts.entry(s.host.clone()).or_default() += 1;
        }
    });
    let top = |m: std::collections::HashMap<String, u64>| {
        let mut v: Vec<(String, u64)> = m.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.truncate(500);
        v
    };
    DiagScopeOptions { processes: top(procs), hosts: top(hosts) }
}

/// Add the host's `scope` and `generatedAt` to a report.
pub fn finish_report(report: &str, scope: &str, sessions: usize, filter: &DiagFilter, generated_at: Micros) -> Result<String> {
    let mut v: serde_json::Value = serde_json::from_str(report).map_err(|e| anyhow!("analyzer report is not valid JSON: {e}"))?;
    let o = v.as_object_mut().ok_or_else(|| anyhow!("analyzer report is not a JSON object"))?;
    o.insert("scope".into(), serde_json::json!({ "kind": scope, "sessions": sessions, "processes": filter.processes, "hosts": filter.hosts }));
    o.insert("generatedAt".into(), serde_json::json!(generated_at));
    Ok(serde_json::to_string(&v)?)
}

// ------------------------------------------------------------------ AppCore

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiagAnalyzer {
    pub index: u16,
    pub id: String,
    pub name: String,
    pub title: String,
    pub version: String,
}

impl AppCore {
    fn plugin_host_or_err(&self) -> Result<Arc<quena_plugin_host::PluginHost>> {
        self.plugin_host.read().clone().ok_or_else(|| anyhow!("plugin host not available"))
    }

    /// Enabled, loaded analyzer plugins.
    pub fn diag_analyzers(&self) -> Vec<DiagAnalyzer> {
        self.plugins()
            .into_iter()
            .filter(|p| p.kind == PluginKind::Analyzer && p.enabled && p.error.is_none())
            .map(|p| DiagAnalyzer { index: p.index, id: p.id, name: p.name, title: p.tab, version: p.version })
            .collect()
    }

    /// Profiles and default options of an analyzer (JSON, see REPORT.md).
    pub fn diag_describe(&self, index: u16, lang: &str) -> Result<String> {
        self.plugin_host_or_err()?.describe(index, lang)
    }

    /// Processes and hosts of the visible sessions, for the scope of an analysis.
    pub fn diag_scope_options(&self) -> DiagScopeOptions {
        scope_options(&self.capture())
    }

    /// Start a diagnostics run as a background job over the selection (`ids`) or the visible
    /// sessions. When done, the report is kept ([`diag_report`](Self::diag_report)) and
    /// `diag-report` is emitted; a failing plugin fails the job. A new run cancels a running
    /// one; only the latest run (and none started before a reset, see
    /// [`diag_reset`](Self::diag_reset)) can store its report.
    pub fn diag_run(self: &Arc<Self>, index: u16, options: String, ids: Option<Vec<SessionId>>, filter: DiagFilter) -> Result<JobId> {
        let host = self.plugin_host_or_err()?;
        if !self.diag_analyzers().iter().any(|a| a.index == index) {
            return Err(anyhow!("analyzer {index} is not available"));
        }
        let cap = self.capture();
        let (ids, scope) = scope_ids(&cap, ids, &filter);
        if ids.is_empty() {
            return Err(anyhow!("no sessions in the chosen scope"));
        }
        let generation = self.diag_report.lock().begin();
        let core = Arc::downgrade(self);
        self.jobs.cancel_prefix("diag:");
        let key = format!("diag:{}", quena_model::now_us());
        Ok(self.jobs.submit(key, "Diagnostics", Priority::Background, true, move |ctx: &JobCtx| {
            let total = ids.len();
            let mut pos = 0usize;
            let cancelled = || ctx.cancelled();
            // Sessions removed meanwhile are skipped; an empty batch means the end.
            let mut next = || -> Option<Vec<AnalyzerSession>> {
                let mut batch = Vec::with_capacity(BATCH.min(total - pos));
                let mut size = 0usize;
                while pos < total && batch.len() < BATCH && size < BATCH_BYTES && !ctx.cancelled() {
                    if let Some(r) = record_of(&cap, ids[pos], &cancelled) {
                        size += record_bytes(&r);
                        batch.push(r);
                    }
                    pos += 1;
                    if pos.is_multiple_of(256) {
                        ctx.progress(pos as u64, total as u64);
                    }
                }
                ctx.progress(pos as u64, total as u64);
                (!batch.is_empty()).then_some(batch)
            };
            // Interrupts the plugin in flight when the job is cancelled.
            let state = ctx.state().clone();
            let report = host.analyze_interruptible(index, &options, &mut next, Arc::new(move || state.cancelled())).map_err(|e| format!("{e:#}"))?;
            let report = finish_report(&report, scope, total, &filter, quena_model::now_us()).map_err(|e| format!("{e:#}"))?;
            let Some(core) = core.upgrade() else { return Ok(()) };
            core.diag_store(generation, report, &cancelled);
            Ok(())
        }))
    }

    /// Keep the report of run `generation` and emit `diag-report` — unless the run was
    /// cancelled or superseded (a newer run or a reset). Checked under the report lock, so a
    /// stale run can never overwrite a newer report. Returns whether it was stored.
    pub(crate) fn diag_store(&self, generation: u64, report: String, cancelled: &dyn Fn() -> bool) -> bool {
        {
            let mut slot = self.diag_report.lock();
            if slot.generation != generation || cancelled() {
                return false;
            }
            slot.report = Some(Arc::new(report));
        }
        self.emit("diag-report", serde_json::Value::Null);
        true
    }

    /// Forget the report and cancel running analyses (the sessions it refers to are gone:
    /// "Remove all", another capture). Runs started before cannot store afterwards.
    pub fn diag_reset(&self) {
        {
            let mut slot = self.diag_report.lock();
            slot.generation += 1;
            slot.report = None;
        }
        self.jobs.cancel_prefix("diag:");
        self.emit("diag-report", serde_json::Value::Null);
    }

    /// The last diagnostics report (JSON).
    pub fn diag_report(&self) -> Option<Arc<String>> {
        self.diag_report.lock().report.clone()
    }
}

/// The last report and the generation of the latest run / reset (only that run may store).
#[derive(Default)]
pub(crate) struct DiagSlot {
    report: Option<Arc<String>>,
    generation: u64,
}

impl DiagSlot {
    /// A new run: supersedes all earlier ones.
    fn begin(&mut self) -> u64 {
        self.generation += 1;
        self.generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quena_model::{ConnectionInfo, HttpVersion, RequestHead, ResponseHead, SessionSummary, Timers, TlsInfo};

    fn headers(list: &[(&str, &str)]) -> Headers {
        let mut h = Headers::new();
        for (n, v) in list {
            h.push(*n, *v);
        }
        h
    }

    #[test]
    fn authorization_keeps_scheme_and_size() {
        let token = "x".repeat(812);
        assert_eq!(redact_authorization(&format!("Bearer {token}")), "Bearer <812 bytes>");
        assert_eq!(redact_authorization("Basic dXNlcjpwYXNz"), "Basic <12 bytes>");
        assert_eq!(redact_authorization("Negotiate  YIIGhgYGKwYBBQUCoIIGejCCBnag== "), "Negotiate <30 bytes>");
        assert_eq!(redact_authorization("NTLM TlRMTVNTUAABAAAAl4II4g=="), "NTLM <24 bytes>");
        assert_eq!(redact_authorization(r#"Digest username="bob", realm="x", response="abc""#), "Digest <41 bytes>");
        assert_eq!(redact_authorization("Bearer"), "Bearer");
        assert_eq!(redact_authorization(""), "");
        // No scheme: the value itself may be the secret.
        assert_eq!(redact_authorization("sk-live-1234567890"), "<18 bytes>");
        assert_eq!(redact_authorization("eyJhbGciOi.eyJzdWIi.sig"), "<23 bytes>");
        assert_eq!(redact_authorization("abc.def ghi"), "<11 bytes>");
    }

    #[test]
    fn authenticate_keeps_schemes_and_parameter_names() {
        assert_eq!(redact_authenticate(&format!("Negotiate {}", "A".repeat(1320))), "Negotiate <1320 bytes>");
        // Non-secret parameters keep their values (REPORT.md "Authentication facts").
        assert_eq!(
            redact_authenticate(r#"Bearer realm="api", error="invalid_token", error_description="The token expired at '10/01/2026 10:00:00'""#),
            r#"Bearer realm="api", error="invalid_token", error_description="The token expired at '10/01/2026 10:00:00'""#
        );
        assert_eq!(
            redact_authenticate(r#"Bearer resource_metadata="https://api.test/.well-known/oauth-protected-resource", scope="a b", authorization_uri="https://login.test/authorize", trusted_issuers="https://iss", resource=api, error_uri="https://e""#),
            r#"Bearer resource_metadata="https://api.test/.well-known/oauth-protected-resource", scope="a b", authorization_uri="https://login.test/authorize", trusted_issuers="https://iss", resource=api, error_uri="https://e""#
        );
        // error_description: e-mails masked, escapes kept valid, at most 300 bytes.
        let long = redact_authenticate(&format!(r#"Bearer error="invalid_token", error_description="user secret.person@example.com said \"no\" {}""#, "x".repeat(400)));
        assert!(long.starts_with(r#"Bearer error="invalid_token", error_description="user <email> said \"no\" xxx"#) && long.ends_with("…\""), "{long}");
        assert!(!long.contains("secret.person") && long.len() < 360, "{long}");
        // Other parameters (Digest nonce, unknown ones) keep only their names; long values become sizes.
        assert_eq!(redact_authenticate(&format!(r#"Bearer realm="{}""#, "r".repeat(600))), "Bearer realm=<602 bytes>");
        assert_eq!(redact_authenticate("Negotiate, NTLM"), "Negotiate, NTLM");
        assert_eq!(redact_authenticate(r#"Basic realm="a, b", charset="UTF-8", Negotiate"#), r#"Basic realm="a, b", charset, Negotiate"#);
        assert_eq!(redact_authenticate("NTLM TlRMTVNTUAACAAAADAAMADgAAAA="), "NTLM <28 bytes>");
        assert_eq!(redact_authenticate(r#"Digest realm="x", nonce="secret-nonce", opaque="o", qop="auth""#), r#"Digest realm="x", nonce, opaque, qop"#);
        assert_eq!(redact_authenticate(""), "");
    }

    #[test]
    fn cookies_keep_names_only() {
        assert_eq!(redact_cookie("a=1; b=secret; sid=xyz"), "a; b; sid");
        // A pair without `=` is a value (RFC 6265bis), not a name.
        assert_eq!(redact_cookie(" theme=dark ;; flag"), "theme; <4 bytes>");
        assert_eq!(redact_cookie("sessiontoken-abc123; theme=dark"), "<19 bytes>; theme");
        assert_eq!(redact_set_cookie("sid=abcdef; Path=/; HttpOnly; Secure; SameSite=Lax"), "sid=<6 bytes>; Path=/; HttpOnly; Secure; SameSite=Lax");
        assert_eq!(redact_set_cookie("token=; Max-Age=0"), "token=<0 bytes>; Max-Age=0");
        assert_eq!(redact_set_cookie("a=b=c"), "a=<3 bytes>");
        assert_eq!(redact_set_cookie("lonely"), "=<6 bytes>");
    }

    #[test]
    fn set_cookie_with_several_cookies_redacts_each() {
        // Folded with ", " (HAR exporters, intermediaries) and joined with line breaks.
        assert_eq!(redact_set_cookie("a=1; Path=/, sid=SECRET123; Path=/; HttpOnly"), "a=<1 bytes>; Path=/, sid=<9 bytes>; Path=/; HttpOnly");
        assert_eq!(redact_set_cookie("a=1; Path=/\nsid=SECRET123; Path=/"), "a=<1 bytes>; Path=/\nsid=<9 bytes>; Path=/");
        // The comma of an Expires date does not start a cookie.
        assert_eq!(
            redact_set_cookie("a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure, b=22; expires=Thu, 01 Jan 1970 00:00:00 GMT"),
            "a=<1 bytes>; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure, b=<2 bytes>; expires=Thu, 01 Jan 1970 00:00:00 GMT"
        );
        // Known attributes case-insensitively; anything else by its size.
        assert_eq!(
            redact_set_cookie("x=1; DOMAIN=.a.test; max-age=60; samesite=None; Partitioned; Priority=High; sid=SECRET; junk"),
            "x=<1 bytes>; DOMAIN=.a.test; max-age=60; samesite=None; Partitioned; Priority=High; sid=<6 bytes>; <4 bytes>"
        );
        let out = redact_set_cookie("a=1; Path=/, sid=SECRET123\nt=TOPSECRET, u=ALSOSECRET; Max-Age=1");
        assert!(!out.contains("SECRET"), "{out}");
    }

    #[test]
    fn urls_redact_sensitive_and_long_parameter_values() {
        assert_eq!(redact_url("https://api.test/v1/items?x=1&y=two"), "https://api.test/v1/items?x=1&y=two");
        assert_eq!(
            redact_url("https://login.test/cb?code=abc123&state=xyz&session_state=s1#access_token=eyJ0&token_type=Bearer&expires_in=3600"),
            "https://login.test/cb?code=%3C6%20bytes%3E&state=%3C3%20bytes%3E&session_state=%3C2%20bytes%3E#access_token=%3C4%20bytes%3E&token_type=%3C6%20bytes%3E&expires_in=3600"
        );
        // Signed URLs (AWS, Azure SAS), API keys, passwords, SAML; percent-encoded names too.
        let aws = redact_url("https://b.s3.test/o?X-Amz-Algorithm=AWS4&X-Amz-Credential=AKIA%2F1&X-Amz-Signature=deadbeef&versionId=3");
        assert_eq!(aws, "https://b.s3.test/o?X-Amz-Algorithm=%3C4%20bytes%3E&X-Amz-Credential=%3C8%20bytes%3E&X-Amz-Signature=%3C8%20bytes%3E&versionId=3");
        let sas = redact_url("https://a.blob.test/c/f?sv=2022-11-02&sp=r&se=2026-01-01&sr=b&sig=abc%3D&comp=list");
        assert_eq!(sas, "https://a.blob.test/c/f?sv=%3C10%20bytes%3E&sp=%3C1%20bytes%3E&se=%3C10%20bytes%3E&sr=%3C1%20bytes%3E&sig=%3C6%20bytes%3E&comp=list");
        assert_eq!(redact_url("/x?api%5Fkey=k1&Password=p&SAMLResponse=PHN&client_secret=c&id_token=j"), "/x?api%5Fkey=%3C2%20bytes%3E&Password=%3C1%20bytes%3E&SAMLResponse=%3C3%20bytes%3E&client_secret=%3C1%20bytes%3E&id_token=%3C1%20bytes%3E");
        // Long values of any name; OData system options keep theirs; empty values stay.
        let long = "a".repeat(65);
        assert_eq!(redact_url(&format!("/p?q={long}&ok={}&e=", "b".repeat(64))), format!("/p?q=%3C65%20bytes%3E&ok={}&e=", "b".repeat(64)));
        let filter = format!("$filter=Name%20eq%20%27{}%27&$select=Id", "x".repeat(80));
        assert_eq!(redact_url(&format!("https://h.test/odata/Cases?{filter}")), format!("https://h.test/odata/Cases?{filter}"));
        assert_eq!(redact_url(&format!("/p?{long}")), "/p?%3C65%20bytes%3E");
        // User info, relative references and fragments.
        assert_eq!(redact_url("https://bob:hunter2@h.test:8443/a?b=1"), "https://%3C11%20bytes%3E@h.test:8443/a?b=1");
        assert_eq!(redact_url("/login?next=https://app.test/home"), "/login?next=https://app.test/home");
        assert_eq!(redact_url("https://h.test/doc#section-2"), "https://h.test/doc#section-2");
        assert_eq!(redact_url(&format!("https://h.test/#{long}")), "https://h.test/#%3C65%20bytes%3E");
        assert_eq!(redact_url("api.test:443"), "api.test:443");
        // The result stays a URL: no raw spaces or angle brackets.
        assert!(!redact_url("https://h.test/?token=a b").contains(['<', '>']));
    }

    #[test]
    fn urls_keep_oauth_parameters_but_not_codes_state_or_hints() {
        let scope = "openid+profile+offline_access+api%3A%2F%2Forders%2FOrders.Read+api%3A%2F%2Forders%2FOrders.Write";
        assert!(scope.len() > URL_VALUE_LIMIT);
        let url = format!(
            "https://login.test/tenant/oauth2/v2.0/authorize?response_type=code&response_mode=form_post&client_id=11111111-2222-3333-4444-555555555555&scope={scope}\
             &redirect_uri=https%3A%2F%2Fapp.test%2Fcb%3Ftenant%3DSECRET-CB-QUERY&state=SECRET-STATE&nonce=SECRET-NONCE&code_challenge=SECRET-CHALLENGE-abcdefghijklmnopqrstuvwxyz\
             &code_challenge_method=S256&login_hint=secret.person%40example.com&id_token_hint=eyJSECRET&prompt=select_account&max_age=0&ui_locales=de&domain_hint=example.com"
        );
        let r = redact_url(&url);
        assert_eq!(
            r,
            format!(
                "https://login.test/tenant/oauth2/v2.0/authorize?response_type=code&response_mode=form_post&client_id=11111111-2222-3333-4444-555555555555&scope={scope}\
                 &redirect_uri=https%3A%2F%2Fapp.test%2Fcb&state=%3C12%20bytes%3E&nonce=%3C12%20bytes%3E&code_challenge=%3C43%20bytes%3E\
                 &code_challenge_method=S256&login_hint=%3C27%20bytes%3E&id_token_hint=%3C9%20bytes%3E&prompt=select_account&max_age=0&ui_locales=de&domain_hint=example.com"
            )
        );
        for secret in ["SECRET", "secret.person"] {
            assert!(!r.contains(secret), "{r}");
        }
        // Callback with an error: description kept (e-mails masked, ≤ 300 bytes), code/state not.
        let r = redact_url("https://app.test/cb?error=access_denied&error_description=AADSTS50105%3A+The+user+secret.person%40example.com+is+not+assigned&error_uri=https%3A%2F%2Fe.test&error_subcode=cancel&state=SECRET-STATE&code=SECRET-CODE-123");
        assert_eq!(
            r,
            "https://app.test/cb?error=access_denied&error_description=AADSTS50105%3A%20The%20user%20%3Cemail%3E%20is%20not%20assigned&error_uri=https%3A%2F%2Fe.test&error_subcode=cancel&state=%3C12%20bytes%3E&code=%3C15%20bytes%3E"
        );
        let long = redact_url(&format!("/cb?error_description={}", "x".repeat(1000)));
        assert!(long.len() < 340 && long.ends_with("%E2%80%A6"), "{long}");
        // Kept values have a cap too; the fragment of an implicit flow stays redacted.
        let r = redact_url(&format!("/a?scope={}#access_token=SECRET-ACCESS&state=SECRET-STATE&token_type=Bearer", "s".repeat(600)));
        assert_eq!(r, "/a?scope=%3C600%20bytes%3E#access_token=%3C13%20bytes%3E&state=%3C12%20bytes%3E&token_type=%3C6%20bytes%3E");
        // Location headers use the same rules.
        let h = redact_headers(&headers(&[("Location", "https://app.test/cb?code=SECRET-CODE-123&state=SECRET-STATE&session_state=s&iss=https%3A%2F%2Flogin.test")]));
        assert_eq!(h[0].1, "https://app.test/cb?code=%3C15%20bytes%3E&state=%3C12%20bytes%3E&session_state=%3C1%20bytes%3E&iss=https%3A%2F%2Flogin.test");
    }

    #[test]
    fn records_carry_authentication_facts() {
        use base64_url as b64;
        let (_d, cap) = capture();
        let token = format!(
            "{}.{}.SECRET-SIGNATURE",
            b64(br#"{"alg":"RS256","typ":"JWT"}"#),
            b64(br#"{"iss":"https://kc.test/realms/r","aud":"account","exp":1790000000,"azp":"web","scope":"openid email","sub":"SECRET-SUB-1","email":"secret.person@example.com","nonce":"SECRET-NONCE","jti":"SECRET-JTI"}"#)
        );
        // Token request with a form body and a JSON response.
        let mut d = detail(SessionKind::Http, "https://kc.test/realms/r/protocol/openid-connect/token", 1_000_000);
        d.request.headers = headers(&[("Content-Type", "application/x-www-form-urlencoded"), ("Authorization", "Basic d2ViOlNFQ1JFVA==")]);
        d.response.as_mut().unwrap().headers = headers(&[("Content-Type", "application/json")]);
        let req = cap.bodies.store_bytes(b"grant_type=authorization_code&code=SECRET-CODE-123&redirect_uri=https%3A%2F%2Fapp.test%2Fcb&code_verifier=SECRET-VERIFIER");
        let resp = cap.bodies.store_bytes(format!(r#"{{"access_token":"{token}","expires_in":300,"refresh_token":"SECRET-REFRESH","token_type":"Bearer","id_token":"{token}"}}"#).as_bytes());
        let id = cap.insert(d, req, resp);
        let r = record_of(&cap, id, &|| false).unwrap();
        let a = r.auth.clone().expect("auth facts");
        let q = a.oauth_request.as_ref().unwrap();
        assert_eq!((q.grant_type.as_deref(), q.redirect_uri.as_deref(), q.has_code, q.has_code_verifier, q.basic_client_auth), (Some("authorization_code"), Some("https://app.test/cb"), true, true, true));
        let p = a.oauth_response.as_ref().unwrap();
        assert_eq!((p.expires_in, p.has_refresh_token, p.access_token.as_ref().unwrap().client.as_deref()), (Some(300), true, Some("web")));
        assert!(a.bearer.is_none(), "Basic is no bearer");
        let dbg = format!("{r:?}");
        for s in ["SECRET", "secret.person", &token] {
            assert!(!dbg.contains(s), "{s} in {dbg}");
        }
        assert!(record_bytes(&r) > 300);

        // API call with the JWT; an untyped discovery response; tunnels get nothing.
        let mut d = detail(SessionKind::Http, "https://kc.test/realms/r/.well-known/openid-configuration", 2_000_000);
        d.request.headers = headers(&[("Authorization", &format!("Bearer {token}"))]);
        d.response.as_mut().unwrap().headers = Headers::new();
        let id = cap.insert(d, Body::empty(), cap.bodies.store_bytes(br#"{"issuer":"https://kc.test/realms/r","token_endpoint":"https://kc.test/t"}"#));
        let a = record_of(&cap, id, &|| false).unwrap().auth.unwrap();
        assert_eq!((a.bearer.as_ref().unwrap().exp, a.discovery.as_ref().unwrap().issuer.as_deref()), (Some(1_790_000_000), Some("https://kc.test/realms/r")));
        let t = cap.insert(detail(SessionKind::Tunnel, "kc.test:443", 3_000_000), Body::empty(), Body::empty());
        assert!(record_of(&cap, t, &|| false).unwrap().auth.is_none());
        // A plain API call: no facts (the default detail carries an opaque bearer).
        let mut d = detail(SessionKind::Http, "https://api.test/x", 4_000_000);
        d.request.headers = headers(&[("Accept", "*/*")]);
        let id = cap.insert(d, Body::empty(), cap.bodies.store_bytes(br#"{"error":{"code":"NotFound"}}"#));
        assert!(record_of(&cap, id, &|| false).unwrap().auth.is_none());
    }

    fn base64_url(data: &[u8]) -> String {
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

    #[test]
    fn absolute_urls_need_a_scheme_prefix() {
        assert!(has_scheme("https://a.test/") && has_scheme("wss://a.test/s") && has_scheme("git+ssh://h/x"));
        assert!(!has_scheme("/login?next=https://app.test/home") && !has_scheme("a.test:443") && !has_scheme("://x") && !has_scheme("1http://x"));
    }

    #[test]
    fn long_values_are_cut_and_marked() {
        let v = "é".repeat(5000); // 10 000 bytes
        let c = cap_field(v.clone(), false);
        assert!(c.len() < FIELD_LIMIT + 40 && c.ends_with(&format!("…<truncated {} bytes>", 10_000 - FIELD_LIMIT)), "{}", &c[c.len() - 40..]);
        assert_eq!(cap_field("short".into(), false), "short");
        // URLs: the mark is percent-encoded and no `%XX` escape is split.
        let url = format!("https://h.test/{}", "%41".repeat(4000));
        let c = cap_field(url, true);
        let (head, tail) = c.split_once("%E2%80%A6%3Ctruncated%20").unwrap();
        assert!(head.len() <= FIELD_LIMIT && head.ends_with("%41") && tail.ends_with("%20bytes%3E"), "{tail}");
        let h = headers(&[("Referer", &format!("https://h.test/?q=1&{}", "a=1&".repeat(3000))), ("Content-Type", &"x".repeat(9000))]);
        let r = redact_headers(&h);
        assert!(r.iter().all(|(_, v)| v.len() <= FIELD_LIMIT + 40), "{r:?}");
        let many: Vec<(&str, &str)> = (0..300).map(|_| ("Set-Cookie", "a=1")).collect();
        assert_eq!(redact_headers(&headers(&many)).len(), HEADER_COUNT_LIMIT);
    }

    #[test]
    fn headers_are_allow_listed_case_insensitively_and_redacted() {
        let h = headers(&[
            ("Host", "api.test"),
            ("AUTHORIZATION", "Bearer abcdefgh"),
            ("Content-Type", "application/json"),
            ("X-Api-Key", "secret"),
            ("proxy-authorization", "Negotiate abcd"),
            ("Cookie", "sid=1; theme=dark"),
            ("x-request-id", "r-1"),
            ("Cache-Control", "no-cache"),
        ]);
        assert_eq!(
            redact_headers(&h),
            vec![
                ("AUTHORIZATION".to_string(), "Bearer <8 bytes>".to_string()),
                ("Content-Type".into(), "application/json".into()),
                ("proxy-authorization".into(), "Negotiate <4 bytes>".into()),
                ("Cookie".into(), "sid; theme".into()),
                ("x-request-id".into(), "r-1".into()),
                ("Cache-Control".into(), "no-cache".into()),
            ]
        );
        let h = headers(&[
            ("Set-Cookie", "a=1; Path=/"),
            ("Server", "nginx"),
            ("WWW-Authenticate", "Bearer realm=\"x\""),
            ("Proxy-Authenticate", "NTLM"),
            ("set-cookie", "b=22; Secure"),
            ("ETag", "\"v1\""),
            ("Location", "https://app.test/cb#id_token=eyJ0&state=s"),
            ("Referer", "https://app.test/?password=hunter2"),
        ]);
        assert_eq!(
            redact_headers(&h),
            vec![
                ("Set-Cookie".to_string(), "a=<1 bytes>; Path=/".to_string()),
                ("WWW-Authenticate".into(), "Bearer realm=\"x\"".into()),
                ("Proxy-Authenticate".into(), "NTLM".into()),
                ("set-cookie".into(), "b=<2 bytes>; Secure".into()),
                ("ETag".into(), "\"v1\"".into()),
                ("Location".into(), "https://app.test/cb#id_token=%3C4%20bytes%3E&state=%3C1%20bytes%3E".into()),
                ("Referer".into(), "https://app.test/?password=%3C7%20bytes%3E".into()),
            ]
        );
        assert!(HEADER_ALLOW_LIST.iter().all(|h| h.bytes().all(|b| !b.is_ascii_uppercase())));
    }

    #[test]
    fn fnv1a_reference_values() {
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a(b"foobar"), 0x8594_4171_f739_67e8);
    }

    fn capture() -> (tempfile::TempDir, Arc<Capture>) {
        let dir = tempfile::tempdir().unwrap();
        let cap = Capture::open(dir.path().join("cap"), quena_body::BodyConfig::default(), true).unwrap();
        (dir, cap)
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn fingerprints_use_the_decoded_body_within_limits() {
        let (_d, cap) = capture();
        let text = b"hello world ".repeat(1000);
        let plain = cap.bodies.store_bytes(&text);
        let zipped = cap.bodies.store_bytes(&gzip(&text));
        let never = &|| false;
        assert_eq!(body_fingerprint(&plain, None, 1 << 20, true, never), (text.len() as u64, Some(fnv1a(&text))));
        assert_eq!(body_fingerprint(&zipped, Some("gzip"), 1 << 20, true, never), (text.len() as u64, Some(fnv1a(&text))));
        // Too large: no fingerprint, but the decoded size is still known.
        assert_eq!(body_fingerprint(&zipped, Some("gzip"), 100, true, never), (text.len() as u64, None));
        assert_eq!(body_fingerprint(&plain, None, 100, true, never), (text.len() as u64, None));
        assert_eq!(body_fingerprint(&zipped, Some("gzip"), 100, false, never).1, None);
        // Empty, undecodable and unknown codings.
        assert_eq!(body_fingerprint(&Body::empty(), None, 100, true, never), (0, None));
        assert_eq!(body_fingerprint(&plain, Some("gzip"), 1 << 20, true, never).1, None);
        assert_eq!(body_fingerprint(&plain, Some("x-custom"), 1 << 20, true, never), (text.len() as u64, None));
        // At the limit is still hashed.
        let exact = cap.bodies.store_bytes(&text[..100]);
        assert_eq!(body_fingerprint(&exact, None, 100, true, never), (100, Some(fnv1a(&text[..100]))));
    }

    fn detail(kind: SessionKind, url: &str, started: Micros) -> SessionDetail {
        let mut d = SessionDetail {
            summary: SessionSummary { kind, started_at: started, ..Default::default() },
            request: RequestHead {
                method: if kind == SessionKind::Tunnel { "CONNECT".into() } else { "POST".into() },
                url: url.into(),
                version: HttpVersion::Http2,
                headers: headers(&[("Authorization", "Bearer secret-token"), ("Cookie", "sid=42"), ("User-Agent", "test"), ("Content-Encoding", "gzip")]),
            },
            response: Some(ResponseHead {
                status: 201,
                reason: "Created".into(),
                version: HttpVersion::Http2,
                headers: headers(&[("Content-Type", "application/json; charset=utf-8"), ("Content-Encoding", "gzip"), ("Set-Cookie", "sid=abc; HttpOnly")]),
            }),
            timers: Timers {
                client_begin_request: Some(started),
                server_got_first_byte: Some(started + 40_000),
                client_done_response: Some(started + 50_000),
                dns_ms: Some(3),
                ..Default::default()
            },
            connection: ConnectionInfo {
                client_conn_id: Some(7),
                server_conn_reused: true,
                server_tls: Some(TlsInfo { version: "TLSv1.3".into(), ..Default::default() }),
                ..Default::default()
            },
            error: None,
            ..Default::default()
        };
        d.summary.process = "app:1".into();
        d
    }

    #[test]
    fn records_carry_redacted_headers_sizes_timers_and_fingerprints() {
        let (_d, cap) = capture();
        let req_text = br#"{"q":1}"#;
        let resp_text = br#"{"items":[1,2,3]}"#.repeat(100);
        let req = cap.bodies.store_bytes(&gzip(req_text));
        let resp_gz = gzip(&resp_text);
        let resp = cap.bodies.store_bytes(&resp_gz);
        let id = cap.insert(detail(SessionKind::Http, "https://api.test/v1/items?x=1", 1_000_000), req, resp);
        let t = cap.insert(detail(SessionKind::Tunnel, "api.test:443", 500_000), Body::empty(), Body::empty());
        let mut ws = detail(SessionKind::WebSocket, "wss://api.test/socket", 2_000_000);
        ws.response = None;
        ws.error = Some("connection reset".into());
        let w = cap.insert(ws, Body::empty(), Body::empty());

        let r = record_of(&cap, id, &|| false).unwrap();
        assert_eq!((r.id, r.kind.as_str(), r.started, r.duration_ms), (id, "http", 1_000_000, Some(50)));
        assert_eq!((r.method.as_str(), r.url.as_str(), r.host.as_str(), r.version.as_str(), r.status), ("POST", "https://api.test/v1/items?x=1", "api.test", "HTTP/2", 201));
        assert_eq!((r.request_bytes, r.response_bytes, r.response_decoded_bytes), (gzip(req_text).len() as u64, resp_gz.len() as u64, resp_text.len() as u64));
        assert_eq!(r.content_type, "application/json");
        assert_eq!(
            r.request_headers,
            vec![("Authorization".to_string(), "Bearer <12 bytes>".to_string()), ("Cookie".into(), "sid".into()), ("Content-Encoding".into(), "gzip".into())]
        );
        assert!(r.response_headers.contains(&("Set-Cookie".into(), "sid=<3 bytes>; HttpOnly".into())));
        assert_eq!((r.timers.client_begin_request, r.timers.server_got_first_byte, r.timers.dns_ms), (Some(1_000_000), Some(1_040_000), Some(3)));
        assert_eq!((r.client_connection, r.server_connection_reused, r.tls_version.as_deref(), r.process.as_str()), (Some(7), true, Some("TLSv1.3"), "app:1"));
        assert_eq!((r.request_body_hash, r.response_body_hash), (Some(fnv1a(req_text)), Some(fnv1a(&resp_text))));

        let r = record_of(&cap, t, &|| false).unwrap();
        assert_eq!((r.kind.as_str(), r.url.as_str(), r.method.as_str()), ("tunnel", "api.test:443", "CONNECT"));
        assert_eq!((r.request_body_hash, r.response_body_hash, r.response_decoded_bytes), (None, None, 0));
        let r = record_of(&cap, w, &|| false).unwrap();
        assert_eq!((r.kind.as_str(), r.status, r.error.as_deref()), ("websocket", 0, Some("connection reset")));
        assert!(r.response_headers.is_empty());
        assert!(record_of(&cap, 999, &|| false).is_none());

        // Scope: sorted by start; the selection keeps only known ids, once.
        cap.index.tick();
        let all = DiagFilter::default();
        assert_eq!(scope_ids(&cap, None, &all), (vec![t, id, w], "visible"));
        assert_eq!(scope_ids(&cap, Some(vec![]), &all), (vec![t, id, w], "visible"));
        assert_eq!(scope_ids(&cap, Some(vec![w, 999, id, w]), &all), (vec![id, w], "selection"));
        // Narrowed to a process / a host.
        let proc_of = |x| cap.index.get(x).unwrap().process;
        let only = DiagFilter { processes: vec![proc_of(id)], hosts: vec![] };
        assert!(scope_ids(&cap, None, &only).0.contains(&id));
        let none = DiagFilter { processes: vec!["no-such-process".into()], hosts: vec![] };
        assert!(scope_ids(&cap, None, &none).0.is_empty());
        let opts = scope_options(&cap);
        assert!(opts.processes.iter().any(|(p, n)| *p == proc_of(id) && *n >= 1), "{opts:?}");
    }

    /// A session with these bodies and content types (no Content-Encoding unless given).
    fn text_session(cap: &Arc<Capture>, req: (&str, Option<&str>, &[u8]), resp: (&str, Option<&str>, &[u8])) -> AnalyzerSession {
        let mut d = detail(SessionKind::Http, "https://api.test/v1/text", 1_000_000);
        let hs = |ct: &str, ce: Option<&str>| {
            let mut v = vec![("Content-Type", ct)];
            if let Some(ce) = ce {
                v.push(("Content-Encoding", ce));
            }
            headers(&v)
        };
        d.request.headers = hs(req.0, req.1);
        d.response.as_mut().unwrap().headers = hs(resp.0, resp.1);
        let id = cap.insert(d, cap.bodies.store_bytes(req.2), cap.bodies.store_bytes(resp.2));
        record_of(cap, id, &|| false).unwrap()
    }

    #[test]
    fn records_carry_text_facts_but_no_content() {
        let (_d, cap) = capture();
        // Request: form post in Latin-1 declared as UTF-8; response: gzipped JSON with a
        // double-encoded umlaut and a replacement character.
        let resp_json = "{\"name\":\"GrÃ¼ÃŸe SECRETWORD\",\"x\":\"a\u{fffd}b\"}";
        let r = text_session(&cap, ("application/x-www-form-urlencoded; charset=utf-8", None, b"q=Gr\xfc\xdfe+SECRETWORD"), ("application/json", Some("gzip"), &gzip(resp_json.as_bytes())));
        let q = r.request_text.clone().expect("request facts");
        assert_eq!((q.header_charset.as_deref(), q.header_resolved.as_deref(), q.effective.as_str(), q.source.as_str()), (Some("utf-8"), Some("UTF-8"), "UTF-8", "header"));
        assert_eq!((q.utf8_valid, q.non_ascii, q.decode_errors, q.sampled), (false, true, 2, 18));
        let p = r.response_text.clone().expect("response facts");
        assert_eq!((p.effective.as_str(), p.source.as_str(), p.double_encoded, p.replacement_chars, p.decode_errors), ("UTF-8", "default", 2, 1, 0));
        assert_eq!((r.request_decoding_error.as_deref(), r.response_decoding_error.as_deref(), p.looks_compressed.as_deref()), (None, None, None));
        // Only facts: no body text in the record.
        assert!(!format!("{r:?}").contains("SECRETWORD"), "{r:?}");

        // Non-textual types get no facts; XML declaration and header disagree.
        let r = text_session(&cap, ("application/octet-stream", None, b"\xff\xfe"), ("text/xml; charset=ISO-8859-1", None, b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><a>\xc3\xa4</a>"));
        assert!(r.request_text.is_none());
        let p = r.response_text.unwrap();
        assert_eq!((p.header_resolved.as_deref(), p.document_charset.as_deref(), p.document_resolved.as_deref(), p.effective.as_str()), (Some("windows-1252"), Some("UTF-8"), Some("UTF-8"), "windows-1252"));

        // Labels from the body are capped: a long or odd "label" does not leave the host.
        let long = format!("<?xml version=\"1.0\" encoding=\"{}\"?><a/>", "SECRETWORD".repeat(10));
        let r = text_session(&cap, ("text/plain", None, b""), ("application/xml", None, long.as_bytes()));
        let p = r.response_text.unwrap();
        assert_eq!((p.document_charset.as_deref(), p.unknown_label), (Some("<100 bytes>"), true));
        let r = text_session(&cap, ("text/plain", None, b""), ("application/xml", None, b"<?xml version='1.0' encoding='a b=c'?><a/>"));
        assert_eq!(r.response_text.unwrap().document_charset.as_deref(), Some("<5 bytes>"));
        assert!(r.request_text.is_none(), "empty body: no facts");

        // Compressed data without Content-Encoding.
        let r = text_session(&cap, ("text/plain", None, b""), ("application/json", None, &gzip(b"{}")));
        assert_eq!(r.response_text.unwrap().looks_compressed.as_deref(), Some("gzip"));

        // Undecodable bodies: an error, no facts, no fingerprint.
        let r = text_session(&cap, ("application/json", Some("gzip"), b"{\"not\":\"gzip\"}"), ("text/html", Some("x-custom"), b"<p>hi</p>"));
        assert!(r.request_decoding_error.as_deref().is_some_and(|e| e.starts_with("invalid: gzip: ")), "{:?}", r.request_decoding_error);
        assert_eq!(r.response_decoding_error.as_deref(), Some("unsupported: x-custom"));
        assert!(r.request_text.is_none() && r.response_text.is_none() && r.request_body_hash.is_none());
    }

    #[test]
    fn scans_sample_large_bodies_and_skip_truncated_ones() {
        let (_d, cap) = capture();
        let never = &|| false;
        // A plain body above the hash limit: size known, no hash, but the prefix is read.
        let big = "ä".repeat(300 << 10);
        let body = cap.bodies.store_bytes(big.as_bytes());
        let s = body_scan(&body, None, 1 << 10, true, TEXT_SAMPLE, never);
        assert_eq!((s.decoded, s.hash, s.prefix.len(), s.error), (big.len() as u64, None, TEXT_SAMPLE, None));
        let s = body_scan(&cap.bodies.store_bytes(&gzip(big.as_bytes())), Some("gzip"), 1 << 10, false, TEXT_SAMPLE, never);
        assert_eq!((s.prefix.len(), s.hash), (TEXT_SAMPLE, None));
        let f = text_info(Some("text/plain; charset=utf-8"), &s.prefix).unwrap();
        assert_eq!((f.sampled, f.decode_errors, f.utf8_valid), (TEXT_SAMPLE as u64, 0, true));
        // A truncated gzip body is not "invalid": its end is missing.
        let gz = gzip(big.as_bytes());
        let mut w = cap.bodies.writer_with_limit(gz.len() as u64 / 2);
        let _ = std::io::Write::write(&mut w, &gz);
        let cut = w.finish();
        assert!(cut.is_truncated());
        assert_eq!(body_scan(&cut, Some("gzip"), 1 << 20, true, TEXT_SAMPLE, never).error, None);
    }

    #[test]
    fn report_gets_scope_and_time() {
        let f = DiagFilter { processes: vec!["chrome".into()], hosts: vec!["*.example.com".into()] };
        let r = finish_report(r#"{"schema":1,"findings":[]}"#, "selection", 3, &f, 42).unwrap();
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        assert_eq!(v["scope"], serde_json::json!({"kind": "selection", "sessions": 3, "processes": ["chrome"], "hosts": ["*.example.com"]}));
        assert_eq!((v["generatedAt"].as_i64(), v["schema"].as_i64()), (Some(42), Some(1)));
        assert!(finish_report("[]", "visible", 0, &f, 0).is_err());
        assert!(finish_report("{", "visible", 0, &f, 0).is_err());
    }

    #[derive(Default)]
    struct Events(parking_lot::Mutex<Vec<String>>);
    impl crate::EventSink for Events {
        fn emit(&self, event: &str, _: serde_json::Value) {
            self.0.lock().push(event.to_string());
        }
    }

    fn core() -> (tempfile::TempDir, Arc<AppCore>) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("settings.json"), r#"{"proxy":{"actAsSystemProxy":false,"captureOnStartup":false}}"#).unwrap();
        let core = AppCore::new(crate::Paths::at(dir.path().to_path_buf()), crate::logbuf::LogBuffer::new(10)).unwrap();
        (dir, core)
    }

    #[test]
    fn only_the_latest_uncancelled_run_stores_its_report() {
        let (_d, core) = core();
        let events = Arc::new(Events::default());
        core.set_sink(events.clone());
        let old = core.diag_report.lock().begin();
        let new = core.diag_report.lock().begin();
        assert!(core.diag_store(new, "new".into(), &|| false));
        // The older run finishes last: it must not overwrite the newer report.
        assert!(!core.diag_store(old, "old".into(), &|| false));
        // Cancelled after `finish`: not stored either.
        assert!(!core.diag_store(new, "cancelled".into(), &|| true));
        assert_eq!(core.diag_report().as_deref().map(String::as_str), Some("new"));
        assert_eq!(events.0.lock().iter().filter(|e| *e == "diag-report").count(), 1);
    }

    #[test]
    fn remove_all_and_switch_capture_drop_the_report_and_cancel_runs() {
        let (_d, core) = core();
        let events = Arc::new(Events::default());
        core.set_sink(events.clone());
        for reset in [0, 1] {
            let run = core.diag_report.lock().begin();
            assert!(core.diag_store(run, "r".into(), &|| false));
            // A run started before the reset (still running).
            let stale = core.diag_report.lock().begin();
            let job = core.jobs.submit("diag:test", "Diagnostics", Priority::Background, true, |ctx: &JobCtx| {
                while !ctx.cancelled() {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Ok(())
            });
            events.0.lock().clear();
            if reset == 0 {
                core.remove_all();
            } else {
                let (_d2, cap) = capture();
                core.switch_capture(cap);
            }
            assert!(core.diag_report().is_none());
            assert!(events.0.lock().iter().any(|e| e == "diag-report"));
            assert!(core.jobs.get(job).unwrap().cancelled());
            // Session ids restart: the stale run can no longer store its report.
            assert!(!core.diag_store(stale, "stale".into(), &|| false));
            assert!(core.diag_report().is_none());
        }
    }

    #[test]
    fn batches_are_bounded_by_bytes_too() {
        let (_d, cap) = capture();
        let mut d = detail(SessionKind::Http, "https://api.test/x", 1);
        d.request.headers = headers(&[("Content-Type", &"x".repeat(FIELD_LIMIT))]);
        let id = cap.insert(d, Body::empty(), Body::empty());
        let r = record_of(&cap, id, &|| false).unwrap();
        assert!(record_bytes(&r) > FIELD_LIMIT && record_bytes(&r) < FIELD_LIMIT + 2048);
        // A batch of such records stays well below the batch byte limit.
        assert!(BATCH_BYTES / record_bytes(&r) < BATCH);
    }

    #[test]
    fn host_patterns() {
        let m = DiagFilter::host_matches;
        assert!(m("api.example.com", "api.example.com") && m("api.example.com", "API.example.com:443"));
        assert!(m("*.example.com", "example.com") && m("*.example.com", "a.b.example.com:8443"));
        assert!(!m("*.example.com", "badexample.com") && !m("api.example.com", "www.example.com"));
    }
}
