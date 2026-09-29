//! Automatic authentication (docs/m8a-automatic-authentication.md).
//!
//! Scheme-agnostic: parse `WWW-Authenticate`/`Proxy-Authenticate`, run the chosen
//! scheme's handshake, produce the `Authorization`/`Proxy-Authorization` token.
//! No network or proxy dependency – the proxy drives the loop (see quena-proxy).

pub mod crypto;
mod ntlm;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod negotiate_gss;
#[cfg(windows)]
mod sspi_windows;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

/// Server tokens arrive with or without `=` padding (and occasionally wrapped).
const B64_LENIENT: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    base64::engine::GeneralPurposeConfig::new().with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
);

/// Split on `sep` outside double quotes (`realm="a, b"` stays one parameter).
fn split_unquoted(s: &str, sep: char) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            c if c == sep && !quoted => {
                out.push(&s[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("no credentials available")]
    NoCredentials,
    #[error("unsupported scheme")]
    Unsupported,
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Basic,
    Ntlm,
    Negotiate,
}

impl Scheme {
    pub fn header_name(self) -> &'static str {
        match self {
            Scheme::Basic => "Basic",
            Scheme::Ntlm => "NTLM",
            Scheme::Negotiate => "Negotiate",
        }
    }
    fn parse(s: &str) -> Option<Scheme> {
        match s.to_ascii_lowercase().as_str() {
            "basic" => Some(Scheme::Basic),
            "ntlm" => Some(Scheme::Ntlm),
            "negotiate" => Some(Scheme::Negotiate),
            _ => None,
        }
    }
    /// Higher = stronger / preferred.
    fn rank(self) -> u8 {
        match self {
            Scheme::Negotiate => 3,
            Scheme::Ntlm => 2,
            Scheme::Basic => 1,
        }
    }
}

/// One offered scheme parsed from a challenge header.
#[derive(Debug, Clone)]
pub struct Offer {
    pub scheme: Scheme,
    /// Base64-decoded token that followed the scheme (NTLM/Negotiate continuation), if any.
    pub token: Option<Vec<u8>>,
    /// `key=value` parameters (Basic realm etc.).
    pub params: Vec<(String, String)>,
}

/// Parse all `WWW-Authenticate` / `Proxy-Authenticate` header values.
pub fn parse_challenges(values: &[String]) -> Vec<Offer> {
    let mut out = Vec::new();
    for v in values {
        for part in split_challenges(v) {
            let part = part.trim();
            let (scheme_str, rest) = match part.split_once(char::is_whitespace) {
                Some((s, r)) => (s, r.trim()),
                None => (part, ""),
            };
            let Some(scheme) = Scheme::parse(scheme_str) else { continue };
            let mut token = None;
            let mut params = Vec::new();
            if !rest.is_empty() {
                if rest.contains('=') && rest.contains(char::is_whitespace) || rest.contains(',') || looks_like_params(rest) {
                    for kv in split_unquoted(rest, ',') {
                        if let Some((k, val)) = kv.split_once('=') {
                            params.push((k.trim().to_string(), val.trim().trim_matches('"').to_string()));
                        }
                    }
                } else {
                    // Bare token (NTLM/Negotiate continuation) is base64.
                    let compact: String = rest.chars().filter(|c| !c.is_whitespace()).collect();
                    token = B64_LENIENT.decode(compact.as_bytes()).ok();
                }
            }
            out.push(Offer { scheme, token, params });
        }
    }
    out
}

fn looks_like_params(rest: &str) -> bool {
    // "realm=..." style vs. a base64 token
    rest.split_once('=').map(|(k, _)| k.chars().all(|c| c.is_ascii_alphabetic() || c == '-') && k.len() <= 16).unwrap_or(false)
}

/// Split a header value into separate `scheme ...` challenges. Basic/simple split on
/// the boundary before a known scheme keyword.
fn split_challenges(v: &str) -> Vec<String> {
    // Common case: a single scheme per header line. Handle "Negotiate, NTLM" too.
    let mut result = Vec::new();
    let mut current = String::new();
    for tok in split_unquoted(v, ',') {
        let t = tok.trim();
        let first = t.split_whitespace().next().unwrap_or("");
        if Scheme::parse(first).is_some() && !current.is_empty() {
            result.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(',');
        }
        current.push_str(t);
    }
    if !current.is_empty() {
        result.push(current);
    }
    result
}

/// Credentials for a host/realm. `password` empty means "use current OS identity" (SSO).
#[derive(Debug, Clone, Default)]
pub struct Credentials {
    pub user: String,
    pub domain: String,
    pub password: String,
}

/// A running handshake for one scheme.
pub enum Handshake {
    Basic { header: String, done: bool },
    Ntlm { creds: Credentials, stage: NtlmStage },
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    Negotiate(negotiate_gss::NegotiateCtx),
    #[cfg(windows)]
    Sspi { ctx: sspi_windows::SspiCtx, scheme: Scheme, started: bool },
}

pub enum NtlmStage {
    Type1,
    Type3,
    Done,
}

/// Random-ish 8 bytes without pulling in a crate (good enough for the NTLM client
/// challenge; the security of NTLMv2 does not rest on this nonce's cryptographic
/// quality, only on uniqueness within the handshake).
fn client_challenge() -> [u8; 8] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let a = (n as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(31);
    let b = (n >> 64) as u64 ^ std::process::id() as u64;
    (a ^ b.rotate_left(17)).to_le_bytes()
}

fn windows_filetime_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // 100-ns ticks since 1601-01-01.
    let unix = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    (unix / 100) as u64 + 116_444_736_000_000_000
}

impl Handshake {
    /// Start a handshake for `scheme`. Basic and NTLM need `creds`; Negotiate uses SSO.
    pub fn start(scheme: Scheme, creds: Option<&Credentials>, host: &str) -> Result<Handshake, AuthError> {
        match scheme {
            Scheme::Basic => {
                let c = creds.ok_or(AuthError::NoCredentials)?;
                let up = if c.domain.is_empty() { format!("{}:{}", c.user, c.password) } else { format!("{}\\{}:{}", c.domain, c.user, c.password) };
                Ok(Handshake::Basic { header: format!("Basic {}", B64.encode(up)), done: false })
            }
            Scheme::Ntlm => {
                #[cfg(windows)]
                {
                    // SSPI: SSO with the current user (no creds) or explicit creds.
                    let c = creds.cloned().unwrap_or_default();
                    let ctx = sspi_windows::SspiCtx::new("NTLM", host, &c.user, &c.domain, &c.password)?;
                    return Ok(Handshake::Sspi { ctx, scheme: Scheme::Ntlm, started: false });
                }
                #[cfg(not(windows))]
                {
                    let c = creds.ok_or(AuthError::NoCredentials)?;
                    Ok(Handshake::Ntlm { creds: c.clone(), stage: NtlmStage::Type1 })
                }
            }
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            Scheme::Negotiate => Ok(Handshake::Negotiate(negotiate_gss::NegotiateCtx::new(host)?)),
            #[cfg(windows)]
            Scheme::Negotiate => {
                let c = creds.cloned().unwrap_or_default();
                let ctx = sspi_windows::SspiCtx::new("Negotiate", host, &c.user, &c.domain, &c.password)?;
                Ok(Handshake::Sspi { ctx, scheme: Scheme::Negotiate, started: false })
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
            Scheme::Negotiate => {
                let _ = host;
                Err(AuthError::Unsupported)
            }
        }
    }

    pub fn scheme(&self) -> Scheme {
        match self {
            Handshake::Basic { .. } => Scheme::Basic,
            Handshake::Ntlm { .. } => Scheme::Ntlm,
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            Handshake::Negotiate(_) => Scheme::Negotiate,
            #[cfg(windows)]
            Handshake::Sspi { scheme, .. } => *scheme,
        }
    }

    /// Produce the next header value given the server's continuation token (if any).
    /// Returns the full header value, e.g. `NTLM TlRMTVNT...`.
    pub fn next_header(&mut self, challenge_token: Option<&[u8]>) -> Result<String, AuthError> {
        match self {
            Handshake::Basic { header, done } => {
                if *done {
                    return Err(AuthError::Protocol("basic auth rejected".into()));
                }
                *done = true;
                Ok(header.clone())
            }
            Handshake::Ntlm { creds, stage } => match stage {
                NtlmStage::Type1 => {
                    *stage = NtlmStage::Type3;
                    Ok(format!("NTLM {}", B64.encode(ntlm::type1())))
                }
                NtlmStage::Type3 => {
                    let token = challenge_token.ok_or_else(|| AuthError::Protocol("missing NTLM Type 2".into()))?;
                    let ch = ntlm::parse_type2(token)?;
                    let msg = ntlm::type3(&creds.user, &creds.domain, &creds.password, &ch, windows_filetime_now(), client_challenge());
                    *stage = NtlmStage::Done;
                    Ok(format!("NTLM {}", B64.encode(msg)))
                }
                NtlmStage::Done => Err(AuthError::Protocol("NTLM handshake already complete".into())),
            },
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            Handshake::Negotiate(ctx) => {
                let out = ctx.step(challenge_token)?;
                Ok(format!("Negotiate {}", B64.encode(out)))
            }
            #[cfg(windows)]
            Handshake::Sspi { ctx, scheme, started } => {
                let token = ctx.step(if *started { challenge_token } else { None })?;
                *started = true;
                Ok(format!("{} {}", scheme.header_name(), B64.encode(token)))
            }
        }
    }

    /// Whether the scheme expects at least one more leg after the last header.
    pub fn is_multi_leg(&self) -> bool {
        match self {
            Handshake::Ntlm { .. } => true,
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            Handshake::Negotiate(_) => true,
            #[cfg(windows)]
            Handshake::Sspi { .. } => true,
            _ => false,
        }
    }
}

/// Choose the strongest offered scheme we can satisfy.
pub fn choose<'a>(offers: &'a [Offer], prefer: &[Scheme], have_creds: bool) -> Option<&'a Offer> {
    let supported = |s: Scheme| match s {
        Scheme::Basic | Scheme::Ntlm => have_creds,
        Scheme::Negotiate => cfg!(target_os = "macos") || cfg!(target_os = "linux") || cfg!(windows),
    };
    offers
        .iter()
        .filter(|o| supported(o.scheme))
        .max_by_key(|o| (prefer.iter().rev().position(|p| *p == o.scheme).map(|i| i as i32).unwrap_or(-1), o.scheme.rank() as i32))
}

/// Redact Authorization/Proxy-Authorization values for logs.
pub fn redact(name: &str, value: &str) -> String {
    if name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("proxy-authorization") {
        let scheme = value.split_whitespace().next().unwrap_or("");
        format!("{scheme} <redacted>")
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lenient_challenges() {
        // Unpadded token (len % 4 == 2) and a quoted realm with a comma.
        let offers = parse_challenges(&["NTLM TlRMTVNTUAACAA".into(), "Basic realm=\"Sales, EMEA\", charset=\"UTF-8\"".into()]);
        assert_eq!(offers.len(), 2);
        assert!(offers[0].token.is_some(), "unpadded base64 must decode");
        assert_eq!(offers[1].params[0], ("realm".into(), "Sales, EMEA".into()));
        assert_eq!(offers[1].params[1].1, "UTF-8");
        // Garbage never panics.
        for v in ["", ",,,", "NTLM ===", "Negotiate \u{0}", "Basic realm=\"unterminated", "\"\"\""] {
            let _ = parse_challenges(&[v.to_string()]);
        }
    }

    #[test]
    fn parse_basic_and_ntlm() {
        let offers = parse_challenges(&["Basic realm=\"corp\", charset=\"UTF-8\"".into()]);
        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0].scheme, Scheme::Basic);
        assert_eq!(offers[0].params.iter().find(|(k, _)| k == "realm").unwrap().1, "corp");

        let offers = parse_challenges(&["Negotiate".into(), "NTLM".into()]);
        assert_eq!(offers.len(), 2);

        let offers = parse_challenges(&["NTLM TlRMTVNTUAACAAAA".into()]);
        assert!(offers[0].token.is_some());
    }

    #[test]
    fn choose_prefers_negotiate_then_ntlm() {
        let offers = parse_challenges(&["Negotiate".into(), "NTLM".into(), "Basic realm=x".into()]);
        let prefer = [Scheme::Negotiate, Scheme::Ntlm, Scheme::Basic];
        // With creds and on macOS, Negotiate wins; without the framework, NTLM.
        let c = choose(&offers, &prefer, true).unwrap();
        assert!(matches!(c.scheme, Scheme::Negotiate | Scheme::Ntlm));
        // NTLM before Basic
        let offers2 = parse_challenges(&["NTLM".into(), "Basic realm=x".into()]);
        assert_eq!(choose(&offers2, &prefer, true).unwrap().scheme, Scheme::Ntlm);
    }

    /// Linux without a Kerberos ticket (or without libgssapi): Negotiate must fail at
    /// start or on the first leg so the proxy falls back to NTLM.
    #[cfg(target_os = "linux")]
    #[test]
    fn negotiate_without_ticket_fails() {
        // SAFETY: tests touching KRB5CCNAME all set this same value.
        unsafe { std::env::set_var("KRB5CCNAME", "FILE:/nonexistent/quena-test-no-ccache") };
        let r = Handshake::start(Scheme::Negotiate, None, "example.com").and_then(|mut h| h.next_header(None));
        assert!(matches!(r, Err(AuthError::NoCredentials | AuthError::Unsupported)), "{:?}", r.err());
    }

    #[test]
    fn basic_header() {
        let mut h = Handshake::start(Scheme::Basic, Some(&Credentials { user: "aladdin".into(), password: "opensesame".into(), domain: String::new() }), "x").unwrap();
        assert_eq!(h.next_header(None).unwrap(), "Basic YWxhZGRpbjpvcGVuc2VzYW1l");
    }

    /// First leg on every platform: the pure-Rust Type 1 on macOS/Linux, SSPI on Windows.
    #[test]
    fn ntlm_first_leg() {
        let creds = Credentials { user: "User".into(), domain: "Domain".into(), password: "Password".into() };
        let mut h = Handshake::start(Scheme::Ntlm, Some(&creds), "server").unwrap();
        let t1 = h.next_header(None).unwrap();
        let raw = B64.decode(t1.trim_start_matches("NTLM ")).unwrap();
        assert!(t1.starts_with("NTLM "));
        assert_eq!(&raw[..8], b"NTLMSSP\0");
        assert_eq!(u32::from_le_bytes(raw[8..12].try_into().unwrap()), 1, "Type 1 message");
    }


    /// A well-formed NTLM CHALLENGE_MESSAGE (MS-NLMP 2.2.1.2): flags, target name,
    /// version and AV pairs — accepted by SSPI on Windows as well as by the
    /// pure-Rust implementation.
    fn realistic_type2() -> Vec<u8> {
        fn utf16(s: &str) -> Vec<u8> {
            s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
        }
        fn av(id: u16, v: &[u8], out: &mut Vec<u8>) {
            out.extend_from_slice(&id.to_le_bytes());
            out.extend_from_slice(&(v.len() as u16).to_le_bytes());
            out.extend_from_slice(v);
        }
        let target = utf16("DOMAIN");
        let mut info = Vec::new();
        av(2, &utf16("DOMAIN"), &mut info); // MsvAvNbDomainName
        av(1, &utf16("SERVER"), &mut info); // MsvAvNbComputerName
        av(4, &utf16("domain.example"), &mut info); // MsvAvDnsDomainName
        av(3, &utf16("server.domain.example"), &mut info); // MsvAvDnsComputerName
        av(7, &133_000_000_000_000_000u64.to_le_bytes(), &mut info); // MsvAvTimestamp
        av(0, &[], &mut info); // MsvAvEOL
        // UNICODE | REQUEST_TARGET | NTLM | ALWAYS_SIGN | TARGET_TYPE_DOMAIN |
        // EXTENDED_SESSIONSECURITY | TARGET_INFO | VERSION | 128 | KEY_EXCH | 56
        let flags: u32 = 0xE289_8205;
        let payload = 56u32;
        let mut m = Vec::new();
        m.extend_from_slice(b"NTLMSSP\0");
        m.extend_from_slice(&2u32.to_le_bytes());
        m.extend_from_slice(&(target.len() as u16).to_le_bytes());
        m.extend_from_slice(&(target.len() as u16).to_le_bytes());
        m.extend_from_slice(&payload.to_le_bytes());
        m.extend_from_slice(&flags.to_le_bytes());
        m.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]); // server challenge
        m.extend_from_slice(&[0; 8]); // reserved
        m.extend_from_slice(&(info.len() as u16).to_le_bytes());
        m.extend_from_slice(&(info.len() as u16).to_le_bytes());
        m.extend_from_slice(&(payload + target.len() as u32).to_le_bytes());
        m.extend_from_slice(&[10, 0, 0x61, 0x4a, 0, 0, 0, 15]); // version 10.0.19041, NTLM rev 15
        m.extend_from_slice(&target);
        m.extend_from_slice(&info);
        m
    }

    /// Both legs on every platform (SSPI on Windows, pure Rust elsewhere).
    #[test]
    fn ntlm_two_legs() {
        let creds = Credentials { user: "User".into(), domain: "Domain".into(), password: "Password".into() };
        let mut h = Handshake::start(Scheme::Ntlm, Some(&creds), "server").unwrap();
        let t1 = h.next_header(None).unwrap();
        assert!(t1.starts_with("NTLM "));
        let t3 = h.next_header(Some(&realistic_type2())).unwrap();
        assert!(t3.starts_with("NTLM "));
        assert!(B64.decode(t3.trim_start_matches("NTLM ")).unwrap().len() > 88);
    }
}
