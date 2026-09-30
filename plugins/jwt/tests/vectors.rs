//! JWT inspector tests: RFC vectors, realistic header shapes and garbage.
use ::jwt::jwt::{self, Found, NodeKind, Payload, Token};

// RFC 7519 §3.1 (HS256, CRLF inside the JSON, as in the RFC).
const RFC7519: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
// RFC 7515 Appendix A.3 (ES256).
const RFC7515_ES256: &str = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
// RFC 7519 §6.1 unsecured JWT (alg none, empty signature).
const RFC7519_NONE: &str = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";
// jwt.io default example (HS256).
const JWT_IO: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
// JWE after RFC 7516 Appendix A.1 (RSA-OAEP / A256GCM): protected header, IV and tag as in
// the RFC, 256-byte encrypted key (RSA-2048).
const RFC7516_JWE: &str = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ";

fn b64url(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..=c.len() {
            s.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    s
}

fn make(header: &str, payload: &str, sig: &[u8]) -> String {
    format!("{}.{}.{}", b64url(header.as_bytes()), b64url(payload.as_bytes()), b64url(sig))
}

/// OAuth 2 access token as issued by an OpenID provider (RS256, 2048-bit key).
fn access_token() -> String {
    make(
        r#"{"typ":"at+jwt","alg":"RS256","kid":"kWbkaa6qs8wsTnBwiiNYOhHbnAw"}"#,
        r#"{"aud":"api://quena-test","iss":"https://login.example.com/11111111-2222-3333-4444-555555555555/v2.0","iat":1727690400,"nbf":1727690400,"exp":1727694300,"scope":"openid profile orders.read","sub":"AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ","client_id":"quena-cli","roles":["Reader","Writer"],"jti":"e1c0b4a2-9d3f-4f8e-a1b2-c3d4e5f60718"}"#,
        &[7u8; 256],
    )
}

const NOW: i64 = 1727691120; // 2024-09-30 10:12:00 UTC, 12 min after iat

fn nodes(name: &str, value: &str, now: Option<i64>) -> Vec<jwt::Node> {
    jwt::nodes(&jwt::find(name, value), now)
}

fn field<'a>(n: &'a [jwt::Node], name: &str) -> Option<&'a str> {
    n.iter().find(|x| x.kind == NodeKind::Field && x.name == name).map(|x| x.value.as_str())
}

#[test]
fn rfc7519_example() {
    let f = jwt::find("authorization", &format!("Bearer {RFC7519}"));
    assert_eq!(f.len(), 1);
    let Token::Jws { header, payload: Payload::Json(p), signature } = &f[0].token else { panic!("{f:?}") };
    assert_eq!(header.get("typ").and_then(|v| v.as_str()), Some("JWT"));
    assert_eq!(p.get("iss").and_then(|v| v.as_str()), Some("joe"));
    assert_eq!(signature.len(), 32);
    let n = jwt::nodes(&f, Some(NOW));
    assert_eq!((n[0].kind, n[0].name.as_str()), (NodeKind::Section, "JWT (Bearer, HS256)"));
    assert_eq!(field(&n, "Status"), Some("expired 4940 d 15 h ago"));
    assert_eq!(field(&n, "exp (Expiration time)"), Some("2011-03-22 18:43:00 UTC (1300819380) – expired 4940 d 15 h ago"));
    assert_eq!(field(&n, "http://example.com/is_root"), Some("true"));
    assert_eq!(field(&n, "alg (Algorithm)"), Some("HS256 – HMAC with SHA-256"));
    assert_eq!(field(&n, "Length"), Some("32 bytes"));
    assert!(n.iter().any(|x| x.kind == NodeKind::Note && x.value == "Signature not verified (no key)."));
    assert_eq!(n.last().map(|x| (x.kind, x.name.as_str())), Some((NodeKind::Code, "Payload JSON")));
}

#[test]
fn rfc7515_es256_signature_length() {
    let n = nodes("authorization", &format!("Bearer {RFC7515_ES256}"), None);
    assert_eq!(n[0].name, "JWT (Bearer, ES256)");
    assert_eq!(field(&n, "Length"), Some("64 bytes"));
    assert_eq!(field(&n, "exp (Expiration time)"), Some("2011-03-22 18:43:00 UTC (1300819380)"));
    assert!(n.iter().any(|x| x.kind == NodeKind::Note && x.value.contains("No clock")));
    assert_eq!(field(&n, "Status"), None);
}

#[test]
fn unsecured_jwt() {
    let n = nodes("authorization", &format!("Bearer {RFC7519_NONE}"), Some(NOW));
    assert_eq!(n[0].name, "JWT (Bearer, none)");
    assert!(n.iter().any(|x| x.kind == NodeKind::Note && x.value.starts_with("Unsecured JWT")));
}

#[test]
fn jwt_io_example_iat() {
    let n = nodes("authorization", &format!("Bearer {JWT_IO}"), Some(1516239022 + 3 * 3600 + 5));
    assert_eq!(field(&n, "iat (Issued at)"), Some("2018-01-18 01:30:22 UTC (1516239022) – 3 h ago"));
    assert_eq!(field(&n, "name (Full name)"), Some("John Doe"));
    assert_eq!(field(&n, "Subject"), Some("1234567890"));
    assert_eq!(field(&n, "Status"), Some("no expiration time (exp)"));
}

#[test]
fn access_token_claims() {
    let n = nodes("authorization", &format!("Bearer {}", access_token()), Some(NOW));
    assert_eq!(field(&n, "Status"), Some("valid for 53 min"));
    assert_eq!(field(&n, "typ (Type)"), Some("at+jwt"));
    assert_eq!(field(&n, "kid (Key ID)"), Some("kWbkaa6qs8wsTnBwiiNYOhHbnAw"));
    assert_eq!(field(&n, "aud (Audience)"), Some("api://quena-test"));
    assert_eq!(field(&n, "iat (Issued at)"), Some("2024-09-30 10:00:00 UTC (1727690400) – 12 min ago"));
    assert_eq!(field(&n, "nbf (Not before)"), Some("2024-09-30 10:00:00 UTC (1727690400) – 12 min ago"));
    assert_eq!(field(&n, "exp (Expiration time)"), Some("2024-09-30 11:05:00 UTC (1727694300) – valid for 53 min"));
    assert_eq!(field(&n, "scope (Scopes)"), Some("openid, profile, orders.read"));
    assert_eq!(field(&n, "roles (Roles)"), Some("Reader, Writer"));
    assert_eq!(field(&n, "Length"), Some("256 bytes (2048-bit RSA key)"));
    // Header, Payload and Signature are nested one level below the token.
    let secs: Vec<(u8, &str)> = n.iter().filter(|x| x.kind == NodeKind::Section).map(|x| (x.depth, x.name.as_str())).collect();
    assert_eq!(secs, [(0, "JWT (Bearer, RS256)"), (1, "Header"), (1, "Payload"), (1, "Signature")]);
    // Before nbf.
    let n = nodes("authorization", &format!("Bearer {}", access_token()), Some(1727690400 - 90));
    assert_eq!(field(&n, "Status"), Some("not valid yet (starts in 1 min 30 s)"));
    assert_eq!(field(&n, "nbf (Not before)"), Some("2024-09-30 10:00:00 UTC (1727690400) – not valid yet, starts in 1 min 30 s"));
}

#[test]
fn jwe_shows_header_only() {
    let n = nodes("authorization", &format!("Bearer {RFC7516_JWE}"), Some(NOW));
    assert_eq!(n[0].name, "JWE (Bearer, RSA-OAEP / A256GCM)");
    assert_eq!(field(&n, "enc (Content encryption)"), Some("A256GCM – AES-GCM"));
    assert_eq!(field(&n, "Encrypted key"), Some("256 bytes"));
    assert_eq!(field(&n, "Initialization vector"), Some("12 bytes"));
    assert_eq!(field(&n, "Authentication tag"), Some("16 bytes"));
    assert!(n.iter().any(|x| x.kind == NodeKind::Note && x.value.contains("cannot be shown")));
}

#[test]
fn cookies() {
    let at = access_token();
    let v = format!("_ga=GA1.2.1234567.1727690000; access_token={at}; theme=dark; id_token=\"{JWT_IO}\"");
    let f = jwt::find("cookie", &v);
    let src: Vec<&str> = f.iter().map(|x| x.source.as_str()).collect();
    assert_eq!(src, ["Cookie access_token", "Cookie id_token"]);
    let n = jwt::nodes(&f, Some(NOW));
    assert_eq!(n.iter().filter(|x| x.depth == 0 && x.kind == NodeKind::Section).count(), 2);

    let f = jwt::find("set-cookie", &format!("session={at}; Path=/; Expires=Mon, 30 Sep 2024 11:05:00 GMT; HttpOnly; Secure; SameSite=Lax"));
    assert_eq!(f.iter().map(|x| x.source.as_str()).collect::<Vec<_>>(), ["Set-Cookie session"]);
    // `Bearer%20` prefix inside a cookie value.
    assert_eq!(jwt::find("cookie", &format!("auth=Bearer%20{JWT_IO}")).len(), 1);
    // Cookies without tokens.
    assert!(jwt::find("cookie", "a=b; c=d.e.f; sid=abc.def.ghi").is_empty());
    assert!(jwt::find("set-cookie", "theme=dark; Path=/").is_empty());
}

#[test]
fn other_schemes_and_bare_tokens() {
    assert_eq!(jwt::find("authorization", &format!("DPoP {JWT_IO}"))[0].source, "DPoP");
    assert_eq!(jwt::find("x-amzn-oidc-data", JWT_IO)[0].source, "Token");
    assert!(jwt::find("authorization", "Basic dXNlcjpwYXNz").is_empty());
    assert!(jwt::find("authorization", "Bearer 2YotnFZFEjr1zCsicMWpAA").is_empty());
    assert!(jwt::find("authorization", "Negotiate TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAKAPRlAAAADw==").is_empty());
}

#[test]
fn not_jwts() {
    let bad = [
        "",
        "Bearer",
        "Bearer a.b.c",
        "Bearer ....",
        "Bearer e30.e30.e30",                            // {} without alg
        "Bearer eyJhbGciOjF9.e30.",                      // alg is a number
        "Bearer eyJhbGciOiJIUzI1NiJ9",                   // one segment
        "Bearer eyJhbGciOiJIUzI1NiJ9.e30",               // two segments
        "Bearer eyJhbGciOiJIUzI1NiJ9.e30.e30.e30",       // four segments
        "Bearer eyJhbGciOiJIUzI1NiJ9.e3!0.abc",          // bad character
        "Bearer eyJhbGciOiJIUzI1NiJ9.e30.a",             // impossible base64 length
        "Bearer bm90IGpzb24.e30.abc",                    // header not JSON
        "Bearer eyJhbGciOiJIUzI1NiI.e30.abc",            // truncated header JSON
    ];
    for v in bad {
        assert!(jwt::find("authorization", v).is_empty(), "{v}");
    }
}

#[test]
fn odd_payloads_are_shown_not_rejected() {
    let text = make(r#"{"alg":"HS256"}"#, "hello world", &[1; 32]);
    let n = nodes("authorization", &format!("Bearer {text}"), Some(NOW));
    assert!(n.iter().any(|x| x.kind == NodeKind::Code && x.value == "hello world"));
    let arr = make(r#"{"alg":"HS256"}"#, "[1,2]", &[1; 31]);
    let n = nodes("authorization", &format!("Bearer {arr}"), Some(NOW));
    assert_eq!(field(&n, "Length"), Some("31 bytes (unexpected length for HS256 (32 bytes))"));
    let bin = make(r#"{"alg":"HS256"}"#, "\u{0}\u{1}", &[1; 32]);
    assert!(nodes("authorization", &format!("Bearer {bin}"), Some(NOW)).iter().any(|x| x.kind == NodeKind::Note));
    // Non-numeric and absurd dates fall back to the raw value.
    let odd = make(r#"{"alg":"HS256"}"#, r#"{"exp":"tomorrow","iat":1e300,"nbf":-5}"#, &[1; 32]);
    let n = nodes("authorization", &format!("Bearer {odd}"), Some(NOW));
    assert_eq!(field(&n, "exp (Expiration time)"), Some("tomorrow"));
    assert_eq!(field(&n, "iat (Issued at)"), Some("1e300"));
    assert_eq!(field(&n, "nbf (Not before)").map(|s| &s[..24]), Some("1969-12-31 23:59:55 UTC "));
}

#[test]
fn helpers() {
    assert_eq!(jwt::span(0), "0 s");
    assert_eq!(jwt::span(59), "59 s");
    assert_eq!(jwt::span(3 * 3600), "3 h");
    assert_eq!(jwt::span(-(2 * 86400 + 5)), "2 d");
    assert_eq!(jwt::iso_utc(0), "1970-01-01 00:00:00 UTC");
    assert_eq!(jwt::iso_utc(951_782_400), "2000-02-29 00:00:00 UTC");
    assert!(jwt::now().is_some());
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn mutations_never_panic() {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let at = access_token();
    for orig in [RFC7519, RFC7515_ES256, JWT_IO, RFC7516_JWE, at.as_str()] {
        for _ in 0..3000 {
            let mut d = orig.as_bytes().to_vec();
            for _ in 0..1 + rng.next() % 4 {
                let i = (rng.next() as usize) % d.len();
                match rng.next() % 3 {
                    0 => d[i] = b"AZaz09-_.=%\" ;"[(rng.next() % 14) as usize],
                    1 => d[i] ^= 1 << (rng.next() % 7),
                    _ => d.truncate(i.max(1)),
                }
            }
            let v = String::from_utf8_lossy(&d).into_owned();
            let r = std::panic::catch_unwind(|| {
                for name in ["authorization", "cookie", "set-cookie"] {
                    let f: Vec<Found> = jwt::find(name, &format!("Bearer {v}"));
                    jwt::nodes(&f, Some(NOW));
                    jwt::nodes(&jwt::find(name, &format!("t={v}")), None);
                }
            });
            assert!(r.is_ok(), "panic on {v}");
        }
    }
}

#[test]
fn millisecond_dates_and_long_scopes() {
    // exp/iat in milliseconds (Date.now()) used to show as the year ~56 000.
    let scope = (0..2000).map(|i| format!("s{i}")).collect::<Vec<_>>().join(" ");
    let payload = format!(r#"{{"iat":1727690400000,"exp":1727694300000,"nbf":1727690400,"scope":"{scope}"}}"#);
    let tok = make(r#"{"alg":"HS256"}"#, &payload, &[1u8; 32]);
    let n = nodes("authorization", &format!("Bearer {tok}"), Some(NOW));
    assert_eq!(field(&n, "iat (Issued at)"), Some("2024-09-30 10:00:00 UTC (1727690400000; looks like milliseconds, shown as value / 1000) – 12 min ago"));
    assert_eq!(field(&n, "exp (Expiration time)"), Some("2024-09-30 11:05:00 UTC (1727694300000; looks like milliseconds, shown as value / 1000) – valid for 53 min"));
    // Seconds stay seconds.
    assert_eq!(field(&n, "nbf (Not before)"), Some("2024-09-30 10:00:00 UTC (1727690400) – 12 min ago"));
    assert_eq!(field(&n, "Status"), Some("valid for 53 min"));
    let s = field(&n, "scope (Scopes)").unwrap();
    assert!(s.len() < 1100 && s.starts_with("s0, s1, ") && s.ends_with(" bytes)"), "{} bytes", s.len());
}
