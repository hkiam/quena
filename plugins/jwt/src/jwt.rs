//! JSON Web Tokens in header values: JWS (RFC 7515, compact form, three segments)
//! and JWE (RFC 7516, five segments), claims as registered in RFC 7519 and OpenID
//! Connect Core. Signatures are not verified (no keys); JWE payloads stay encrypted.
//!
//! Malformed input never panics: a value without a JWT yields `None`, a token whose
//! payload cannot be read is shown with a note.

use crate::json::{self, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Section,
    Field,
    Note,
    Code,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub depth: u8,
    pub kind: NodeKind,
    pub name: String,
    pub value: String,
}

/// A JWT found in a header value; `source` says where (e.g. `Bearer`, `cookie access_token`).
#[derive(Debug, Clone, PartialEq)]
pub struct Found {
    pub source: String,
    pub token: Token,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Jws { header: Value, payload: Payload, signature: Vec<u8> },
    Jwe { header: Value, parts: [usize; 4] },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Payload {
    Json(Value),
    Text(String),
    Binary(Vec<u8>),
}

// ------------------------------------------------------------------ helpers

/// base64url (RFC 7515 §2), padding tolerated; standard alphabet accepted too.
pub fn base64url(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // A single leftover character (6 bits) cannot come from any byte sequence.
    if bits == 6 {
        return None;
    }
    Some(out)
}

fn is_segment(s: &str) -> bool {
    s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'=' | b'+' | b'/'))
}

/// Parse one compact JWS/JWE. The header must be a JSON object with a string `alg`.
pub fn parse(tok: &str) -> Option<Token> {
    let tok = tok.trim();
    if tok.len() < 10 {
        return None;
    }
    let seg: Vec<&str> = tok.split('.').collect();
    if !(seg.len() == 3 || seg.len() == 5) || !seg.iter().all(|s| is_segment(s)) || seg[0].is_empty() {
        return None;
    }
    let header = json::parse(&base64url(seg[0])?).ok()?;
    header.get("alg")?.as_str()?;
    if seg.len() == 5 {
        let mut parts = [0usize; 4];
        for (i, s) in seg[1..].iter().enumerate() {
            parts[i] = base64url(s)?.len();
        }
        return Some(Token::Jwe { header, parts });
    }
    let raw = base64url(seg[1])?;
    let payload = match json::parse(&raw) {
        Ok(v) => Payload::Json(v),
        Err(_) => match String::from_utf8(raw) {
            Ok(s) => Payload::Text(s),
            Err(e) => Payload::Binary(e.into_bytes()),
        },
    };
    Some(Token::Jws { header, payload, signature: base64url(seg[2])? })
}

fn unquote(v: &str) -> &str {
    let v = v.trim();
    v.strip_prefix('"').and_then(|x| x.strip_suffix('"')).unwrap_or(v)
}

/// Cookie values sometimes carry `Bearer <jwt>` (URL-encoded or not).
fn strip_bearer(v: &str) -> &str {
    for p in ["Bearer ", "bearer ", "Bearer%20", "bearer%20", "Bearer+"] {
        if let Some(r) = v.strip_prefix(p) {
            return r;
        }
    }
    v
}

/// Find the JWTs in one header value. `name` is lower-case.
pub fn find(name: &str, value: &str) -> Vec<Found> {
    let value = value.trim();
    let mut out = Vec::new();
    match name {
        "cookie" => {
            for pair in value.split(';') {
                if let Some((k, v)) = pair.split_once('=')
                    && let Some(t) = parse(strip_bearer(unquote(v)))
                {
                    out.push(Found { source: format!("Cookie {}", k.trim()), token: t });
                }
            }
        }
        "set-cookie" => {
            let first = value.split(';').next().unwrap_or("");
            if let Some((k, v)) = first.split_once('=')
                && let Some(t) = parse(strip_bearer(unquote(v)))
            {
                out.push(Found { source: format!("Set-Cookie {}", k.trim()), token: t });
            }
        }
        _ => {
            // `Scheme token` (Bearer, DPoP, JWT …) or a bare token.
            let (scheme, cred) = match value.split_once(char::is_whitespace) {
                Some((s, c)) => (s, c.trim()),
                None => ("", value),
            };
            if let Some(t) = parse(unquote(cred)) {
                let source = if scheme.is_empty() { "Token".to_string() } else { scheme.to_string() };
                out.push(Found { source, token: t });
            } else if !scheme.is_empty() && value.contains(',') {
                // Parameter lists, e.g. `Bearer realm="x", error="invalid_token"` carry no token;
                // some gateways put `id_token=<jwt>` there.
                for p in value[scheme.len()..].split(',') {
                    if let Some((k, v)) = p.split_once('=')
                        && let Some(t) = parse(unquote(v))
                    {
                        out.push(Found { source: format!("{scheme} {}", k.trim()), token: t });
                    }
                }
            }
        }
    }
    out
}

/// Unix seconds → `YYYY-MM-DD HH:MM:SS UTC` (proleptic Gregorian, civil-from-days).
pub fn iso_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", rem / 3600, rem / 60 % 60, rem % 60)
}

/// Duration in the two largest units, e.g. `3 h 12 min`, `45 s`, `2 d 4 h`.
pub fn span(secs: i64) -> String {
    let s = secs.unsigned_abs();
    let (d, h, m, s) = (s / 86_400, s / 3600 % 24, s / 60 % 60, s % 60);
    let parts: Vec<String> = [(d, "d"), (h, "h"), (m, "min"), (s, "s")]
        .iter()
        .skip_while(|(v, _)| *v == 0)
        .take(2)
        .filter(|(v, _)| *v != 0)
        .map(|(v, u)| format!("{v} {u}"))
        .collect();
    if parts.is_empty() { "0 s".into() } else { parts.join(" ") }
}

/// Above this a NumericDate (seconds) would lie after the year 5000: such values are almost
/// always milliseconds (JavaScript `Date.now()`), and are shown as `value / 1000`.
const MILLIS_ABOVE: f64 = 1e11;

/// Seconds of a NumericDate claim and whether the value looked like milliseconds; `None` for
/// non-numbers and absurd values.
fn numeric_date_ms(v: &Value) -> Option<(i64, bool)> {
    let f = v.as_f64()?;
    if !f.is_finite() || f.abs() >= 1e13 {
        return None;
    }
    Some(if f.abs() > MILLIS_ABOVE { ((f / 1000.0).floor() as i64, true) } else { (f.floor() as i64, false) })
}

/// Seconds of a NumericDate claim (milliseconds converted); `None` for non-numbers and absurd values.
fn numeric_date(v: &Value) -> Option<i64> {
    numeric_date_ms(v).map(|(t, _)| t)
}

fn time_value(claim: &str, v: &Value, now: Option<i64>) -> Option<String> {
    let (t, millis) = numeric_date_ms(v)?;
    let raw = match v {
        Value::Num(n) => n.clone(),
        _ => t.to_string(),
    };
    let note = if millis { "; looks like milliseconds, shown as value / 1000" } else { "" };
    let mut s = format!("{} ({raw}{note})", iso_utc(t));
    if let Some(now) = now {
        let d = t - now;
        let rel = match claim {
            "exp" if d <= 0 => format!("expired {} ago", span(d)),
            "exp" => format!("valid for {}", span(d)),
            "nbf" if d > 0 => format!("not valid yet, starts in {}", span(d)),
            _ if d > 0 => format!("{} in the future", span(d)),
            _ => format!("{} ago", span(d)),
        };
        s.push_str(&format!(" – {rel}"));
    }
    Some(s)
}

fn claim_label(k: &str) -> Option<&'static str> {
    Some(match k {
        // RFC 7519 §4.1
        "iss" => "Issuer",
        "sub" => "Subject",
        "aud" => "Audience",
        "exp" => "Expiration time",
        "nbf" => "Not before",
        "iat" => "Issued at",
        "jti" => "JWT ID",
        // OpenID Connect Core, RFC 8693, RFC 9068, RFC 7800
        "auth_time" => "Authentication time",
        "updated_at" => "Profile updated at",
        "nonce" => "Nonce",
        "azp" => "Authorized party",
        "acr" => "Authentication context class",
        "amr" => "Authentication methods",
        "at_hash" => "Access token hash",
        "c_hash" => "Code hash",
        "sid" => "Session ID",
        "scope" | "scp" => "Scopes",
        "client_id" => "Client ID",
        "cnf" => "Confirmation (proof-of-possession key)",
        "act" => "Actor (delegation)",
        "may_act" => "May act as",
        "roles" => "Roles",
        "groups" => "Groups",
        "entitlements" => "Entitlements",
        "name" => "Full name",
        "given_name" => "Given name",
        "family_name" => "Family name",
        "preferred_username" => "Preferred username",
        "email" => "E-mail",
        "email_verified" => "E-mail verified",
        "locale" => "Locale",
        "zoneinfo" => "Time zone",
        // Microsoft Entra ID
        "tid" => "Tenant ID (Entra ID)",
        "oid" => "Object ID (Entra ID)",
        "upn" => "User principal name",
        "appid" => "Application ID (Entra ID)",
        "ver" => "Token version",
        _ => return None,
    })
}

const TIME_CLAIMS: [&str; 5] = ["exp", "nbf", "iat", "auth_time", "updated_at"];

fn header_label(k: &str) -> Option<&'static str> {
    Some(match k {
        "alg" => "Algorithm",
        "typ" => "Type",
        "cty" => "Content type",
        "kid" => "Key ID",
        "jku" => "JWK Set URL",
        "jwk" => "JSON Web Key",
        "x5u" => "X.509 URL",
        "x5c" => "X.509 certificate chain",
        "x5t" => "X.509 SHA-1 thumbprint",
        "x5t#S256" => "X.509 SHA-256 thumbprint",
        "crit" => "Critical extensions",
        "enc" => "Content encryption",
        "zip" => "Compression",
        "epk" => "Ephemeral public key",
        "apu" => "Agreement PartyUInfo",
        "apv" => "Agreement PartyVInfo",
        "iv" => "Key wrap IV",
        "tag" => "Key wrap tag",
        "p2s" => "PBES2 salt",
        "p2c" => "PBES2 iteration count",
        "b64" => "Payload base64-encoded",
        _ => return None,
    })
}

fn alg_label(a: &str) -> Option<&'static str> {
    Some(match a {
        "HS256" => "HMAC with SHA-256",
        "HS384" => "HMAC with SHA-384",
        "HS512" => "HMAC with SHA-512",
        "RS256" => "RSASSA-PKCS1-v1_5 with SHA-256",
        "RS384" => "RSASSA-PKCS1-v1_5 with SHA-384",
        "RS512" => "RSASSA-PKCS1-v1_5 with SHA-512",
        "PS256" => "RSASSA-PSS with SHA-256",
        "PS384" => "RSASSA-PSS with SHA-384",
        "PS512" => "RSASSA-PSS with SHA-512",
        "ES256" => "ECDSA P-256 with SHA-256",
        "ES384" => "ECDSA P-384 with SHA-384",
        "ES512" => "ECDSA P-521 with SHA-512",
        "ES256K" => "ECDSA secp256k1 with SHA-256",
        "EdDSA" | "Ed25519" => "Edwards-curve signature",
        "none" => "no signature (unsecured JWT)",
        // JWE key management (RFC 7518 §4)
        "RSA1_5" => "RSAES-PKCS1-v1_5 key encryption",
        "RSA-OAEP" => "RSAES-OAEP (SHA-1) key encryption",
        "RSA-OAEP-256" => "RSAES-OAEP (SHA-256) key encryption",
        "A128KW" | "A192KW" | "A256KW" => "AES key wrap",
        "dir" => "direct use of a shared key",
        "ECDH-ES" => "ECDH-ES key agreement",
        "ECDH-ES+A128KW" | "ECDH-ES+A192KW" | "ECDH-ES+A256KW" => "ECDH-ES key agreement with AES key wrap",
        "A128GCMKW" | "A192GCMKW" | "A256GCMKW" => "AES-GCM key wrap",
        "PBES2-HS256+A128KW" | "PBES2-HS384+A192KW" | "PBES2-HS512+A256KW" => "password-based key wrap",
        // JWE content encryption (RFC 7518 §5)
        "A128CBC-HS256" | "A192CBC-HS384" | "A256CBC-HS512" => "AES-CBC with HMAC",
        "A128GCM" | "A192GCM" | "A256GCM" => "AES-GCM",
        _ => return None,
    })
}

/// Expected signature length and what a different one means.
fn signature_check(alg: &str, len: usize) -> Option<String> {
    let expect = match alg {
        "HS256" => 32,
        "HS384" => 48,
        "HS512" => 64,
        "ES256" | "ES256K" => 64,
        "ES384" => 96,
        "ES512" => 132,
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => {
            return Some(format!("{}-bit RSA key", len * 8));
        }
        "EdDSA" | "Ed25519" => {
            return Some(match len {
                64 => "Ed25519".into(),
                114 => "Ed448".into(),
                _ => "unexpected length for EdDSA (64 or 114 bytes)".into(),
            });
        }
        _ => return None,
    };
    (len != expect).then(|| format!("unexpected length for {alg} ({expect} bytes)"))
}

/// Header or claim value for display: strings without quotes, the rest as JSON.
fn display(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        Value::Arr(a) if a.iter().all(|x| matches!(x, Value::Str(_))) && !a.is_empty() => {
            a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")
        }
        v => json::compact(v),
    }
}

fn clip(s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… ({} bytes)", &s[..end], s.len())
}

// ------------------------------------------------------------------ result tree

struct Out(Vec<Node>);

impl Out {
    fn push(&mut self, depth: u8, kind: NodeKind, name: impl Into<String>, value: impl Into<String>) {
        self.0.push(Node { depth, kind, name: name.into(), value: value.into() });
    }
    fn section(&mut self, d: u8, t: impl Into<String>) {
        self.push(d, NodeKind::Section, t, "");
    }
    fn field(&mut self, d: u8, n: impl Into<String>, v: impl Into<String>) {
        self.push(d, NodeKind::Field, n, v);
    }
    fn note(&mut self, d: u8, v: impl Into<String>) {
        self.push(d, NodeKind::Note, "", v);
    }
}

fn header_fields(o: &mut Out, header: &Value, d: u8) {
    let Value::Obj(m) = header else { return };
    for (k, v) in m {
        let name = match header_label(k) {
            Some(l) => format!("{k} ({l})"),
            None => k.clone(),
        };
        let value = match (k.as_str(), v) {
            ("alg" | "enc", Value::Str(a)) => match alg_label(a) {
                Some(l) => format!("{a} – {l}"),
                None => a.clone(),
            },
            ("x5c", Value::Arr(a)) => format!("{} certificate(s)", a.len()),
            _ => clip(display(v), 512),
        };
        o.field(d, name, value);
    }
}

fn status(payload: &Value, now: Option<i64>) -> Option<String> {
    let now = now?;
    let exp = payload.get("exp").and_then(numeric_date);
    let nbf = payload.get("nbf").and_then(numeric_date);
    if let Some(n) = nbf.filter(|&n| n > now) {
        return Some(format!("not valid yet (starts in {})", span(n - now)));
    }
    match exp {
        Some(e) if e <= now => Some(format!("expired {} ago", span(now - e))),
        Some(e) => Some(format!("valid for {}", span(e - now))),
        None => Some("no expiration time (exp)".into()),
    }
}

fn token_nodes(f: &Found, now: Option<i64>, o: &mut Out) {
    match &f.token {
        Token::Jws { header, payload, signature } => {
            let alg = header.get("alg").and_then(Value::as_str).unwrap_or("");
            o.section(0, format!("JWT ({}, {alg})", f.source));
            if let Payload::Json(p) = payload {
                if let Some(s) = status(p, now) {
                    o.field(0, "Status", s);
                }
                if let Some(s) = p.get("sub").or_else(|| p.get("preferred_username")).or_else(|| p.get("email")) {
                    o.field(0, "Subject", clip(display(s), 256));
                }
                if let Some(s) = p.get("iss") {
                    o.field(0, "Issuer", clip(display(s), 256));
                }
            }
            if now.is_none() {
                o.note(0, "No clock available: dates are shown without relative time.");
            }
            o.section(1, "Header");
            header_fields(o, header, 1);
            o.section(1, "Payload");
            match payload {
                Payload::Json(Value::Obj(m)) => {
                    for (k, v) in m {
                        let name = match claim_label(k) {
                            Some(l) => format!("{k} ({l})"),
                            None => k.clone(),
                        };
                        let value = if TIME_CLAIMS.contains(&k.as_str()) {
                            time_value(k, v, now).unwrap_or_else(|| clip(display(v), 1024))
                        } else if k == "scope" {
                            clip(v.as_str().map(|s| s.split_whitespace().collect::<Vec<_>>().join(", ")).unwrap_or_else(|| display(v)), 1024)
                        } else {
                            clip(display(v), 1024)
                        };
                        o.field(1, name, value);
                    }
                    if m.is_empty() {
                        o.note(1, "Empty claims set.");
                    }
                }
                Payload::Json(v) => {
                    o.note(1, "The payload is JSON but no claims object.");
                    o.push(1, NodeKind::Code, "Payload", clip(json::pretty(v), 64 << 10));
                }
                Payload::Text(t) => {
                    o.note(1, "The payload is not JSON (not a JWT claims set).");
                    o.push(1, NodeKind::Code, "Payload", clip(t.clone(), 64 << 10));
                }
                Payload::Binary(b) => {
                    o.note(1, format!("The payload is binary ({} bytes), not a JWT claims set.", b.len()));
                }
            }
            o.section(1, "Signature");
            if alg == "none" {
                o.field(1, "Algorithm", "none");
                o.note(1, "Unsecured JWT: there is no signature. Servers must not accept it as proof of anything.");
                if !signature.is_empty() {
                    o.note(1, format!("alg none but a {}-byte signature is present.", signature.len()));
                }
            } else {
                o.field(1, "Algorithm", alg_label(alg).map(|l| format!("{alg} – {l}")).unwrap_or_else(|| alg.to_string()));
                let mut len = format!("{} bytes", signature.len());
                if let Some(c) = signature_check(alg, signature.len()) {
                    len.push_str(&format!(" ({c})"));
                }
                o.field(1, "Length", len);
                o.note(1, "Signature not verified (no key).");
            }
            if let Payload::Json(p) = payload {
                o.push(0, NodeKind::Code, "Payload JSON", clip(json::pretty(p), 64 << 10));
            }
        }
        Token::Jwe { header, parts } => {
            let enc = header.get("enc").and_then(Value::as_str).unwrap_or("?");
            let alg = header.get("alg").and_then(Value::as_str).unwrap_or("");
            o.section(0, format!("JWE ({}, {alg} / {enc})", f.source));
            o.note(0, "Encrypted token (JWE): the payload cannot be shown without the recipient's key.");
            o.section(1, "Header");
            header_fields(o, header, 1);
            o.section(1, "Parts");
            o.field(1, "Encrypted key", format!("{} bytes", parts[0]));
            o.field(1, "Initialization vector", format!("{} bytes", parts[1]));
            o.field(1, "Ciphertext", format!("{} bytes", parts[2]));
            o.field(1, "Authentication tag", format!("{} bytes", parts[3]));
            if header.get("cty").and_then(Value::as_str).is_some_and(|c| c.eq_ignore_ascii_case("JWT")) {
                o.note(1, "cty JWT: the ciphertext holds a nested (signed) JWT.");
            }
        }
    }
}

/// The flattened result tree of all tokens in one header value.
pub fn nodes(found: &[Found], now: Option<i64>) -> Vec<Node> {
    let mut o = Out(Vec::new());
    for f in found {
        token_nodes(f, now, &mut o);
    }
    o.0
}

/// Current time in Unix seconds, if the sandbox provides a wall clock.
pub fn now() -> Option<i64> {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?;
    // A zeroed clock (1970) would make every token look ancient.
    (d.as_secs() > 1_000_000_000).then_some(d.as_secs() as i64)
}
