//! Decoder tests against public vectors (see fixtures.rs for sources).
use auth_tokens::token::{self, Decoded, NodeKind, Section};

mod fixtures;
use fixtures::*;

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn b64(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            s.push(if i <= c.len() { A[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    s
}

fn decode(scheme: &str, tok: &str) -> Section {
    token::decode(scheme, tok).expect("token").section
}

fn field<'a>(s: Option<&'a Section>, name: &str) -> Option<&'a str> {
    s.and_then(|s| s.get(name))
}

// ------------------------------------------------ Kerberos (MIT krb5 reference encodings)

#[test]
fn mit_ap_req() {
    let s = decode("Negotiate", &b64(&unhex(MIT_AP_REQ_HEX)));
    assert_eq!(s.title, "Kerberos AP-REQ");
    assert_eq!(s.get("Protocol version"), Some("5"));
    assert_eq!(s.get("AP options"), Some("0xfedcba98 (use-session-key, mutual-required)"));
    let t = s.find("Ticket");
    assert_eq!(field(t, "Service principal (SPN)"), Some("hftsai/extra@ATHENA.MIT.EDU"));
    assert_eq!(field(t, "Name type"), Some("NT-PRINCIPAL (1)"));
    assert_eq!(field(t, "Key version (kvno)"), Some("5"));
    assert_eq!(field(t, "Cipher"), Some("21 bytes (encrypted)"));
    assert!(s.find("Authenticator").is_some());
}

#[test]
fn mit_ap_rep() {
    let s = decode("Negotiate", &b64(&unhex(MIT_AP_REP_HEX)));
    assert_eq!(s.title, "Kerberos AP-REP (mutual authentication)");
    assert_eq!(s.get("Cipher"), Some("21 bytes (encrypted)"));
}

#[test]
fn mit_krb_error() {
    let s = decode("Negotiate", &b64(&unhex(MIT_KRB_ERROR_HEX)));
    assert_eq!(s.title, "Kerberos KRB-ERROR");
    assert_eq!(s.get("Error code"), Some("60 KRB_ERR_GENERIC"));
    assert_eq!(s.get("Server time"), Some("1994-06-10 06:03:17 UTC"));
    assert_eq!(s.get("Realm"), Some("ATHENA.MIT.EDU"));
    assert_eq!(s.get("Client name"), Some("hftsai/extra@ATHENA.MIT.EDU"));
    assert_eq!(s.get("Error text"), Some("krb5data"));
}

// ------------------------------------------------ SPNEGO / GSS-API (pyspnego test data)

#[test]
fn neg_token_init_with_ap_req() {
    let s = decode("Negotiate", PYSPNEGO_NEG_TOKEN_INIT);
    assert_eq!(s.title, "SPNEGO NegTokenInit");
    let mechs: Vec<&str> = s.fields.iter().map(|(_, v)| v.as_str()).collect();
    assert_eq!(mechs, ["Kerberos 5 (1.2.840.113554.1.2.2)", "NTLM (1.3.6.1.4.1.311.2.2.10)"]);
    let ap = s.find("Kerberos AP-REQ");
    assert_eq!(field(ap, "GSS token id"), Some("0x0100"));
    assert_eq!(field(ap, "AP options"), Some("0x20000000 (mutual-required)"));
    let t = s.find("Ticket");
    assert_eq!(field(t, "Service principal (SPN)"), Some("host/dc01@DOMAIN.LOCAL"));
    assert_eq!(field(t, "Name type"), Some("NT-SRV-HST (3)"));
    assert_eq!(field(t, "Encryption type"), Some("aes256-cts-hmac-sha1-96 (18)"));
    assert_eq!(field(t, "Key version (kvno)"), Some("6"));
    assert_eq!(field(s.find("Authenticator"), "Encryption type"), Some("aes256-cts-hmac-sha1-96 (18)"));
}

#[test]
fn neg_token_init2_server_hints() {
    let s = decode("Negotiate", PYSPNEGO_NEG_TOKEN_INIT2);
    assert_eq!(s.title, "SPNEGO NegTokenInit");
    let mechs: Vec<&str> = s.fields.iter().filter(|(n, _)| n != "mechListMIC").map(|(_, v)| v.as_str()).collect();
    assert_eq!(
        mechs,
        [
            "NEGOEX (1.3.6.1.4.1.311.2.2.30)",
            "Kerberos 5 (Microsoft legacy OID) (1.2.840.48018.1.2.2)",
            "Kerberos 5 (1.2.840.113554.1.2.2)",
            "Kerberos 5 User-to-User (1.2.840.113554.1.2.2.3)",
            "NTLM (1.3.6.1.4.1.311.2.2.10)",
        ]
    );
    assert!(s.children.is_empty());
}

#[test]
fn neg_token_resp_with_ap_rep() {
    let s = decode("Negotiate", PYSPNEGO_NEG_TOKEN_RESP);
    assert_eq!(s.title, "SPNEGO NegTokenResp");
    assert_eq!(s.get("Negotiation state"), Some("accept-completed (0)"));
    assert_eq!(s.get("Supported mechanism"), Some("Kerberos 5 (1.2.840.113554.1.2.2)"));
    let rep = s.find("Kerberos AP-REP");
    assert_eq!(field(rep, "GSS token id"), Some("0x0200"));
    assert_eq!(field(rep, "Encryption type"), Some("aes256-cts-hmac-sha1-96 (18)"));
}

#[test]
fn gss_framed_kerberos_without_spnego() {
    let req = decode("Kerberos", PYSPNEGO_KRB_AP_REQ);
    assert_eq!(req.title, "Kerberos AP-REQ");
    assert_eq!(field(req.find("Ticket"), "Service principal (SPN)"), Some("host/dc01@DOMAIN.LOCAL"));
    assert_eq!(decode("Kerberos", PYSPNEGO_KRB_AP_REP).title, "Kerberos AP-REP (mutual authentication)");
}

#[test]
fn krb_error_as_bare_sequence() {
    let s = decode("Negotiate", PYSPNEGO_KRB_ERROR);
    assert_eq!(s.title, "Kerberos KRB-ERROR");
    assert_eq!(s.get("Error code"), Some("25 KDC_ERR_PREAUTH_REQUIRED"));
    assert_eq!(s.get("Server name"), Some("krbtgt/DOMAIN.LOCAL"));
}

// ------------------------------------------------ NTLM

#[test]
fn ntlm_type1() {
    let s = decode("NTLM", PYSPNEGO_NTLM_NEGOTIATE);
    assert_eq!(s.title, "NTLM Type 1 (Negotiate)");
    let flags = s.get("Flags").unwrap();
    assert!(flags.starts_with("0xe20882b7 ") && flags.contains("UNICODE") && flags.contains("EXTENDED_SESSIONSECURITY") && flags.contains("VERSION"), "{flags}");
    assert_eq!(s.get("OS version"), Some("10.0 (build 17763), NTLM revision 15"));
}

#[test]
fn ntlm_type2_ms_nlmp_example() {
    let s = decode("NTLM", &b64(&unhex(MS_NLMP_CHALLENGE_V2_HEX)));
    assert_eq!(s.title, "NTLM Type 2 (Challenge)");
    assert_eq!(s.get("Target name"), Some("Server"));
    assert_eq!(s.get("Server challenge"), Some("0123456789abcdef"));
    assert_eq!(s.get("OS version"), Some("6.0 (build 6000), NTLM revision 15"));
    let ti = s.find("Target info");
    assert_eq!(field(ti, "NetBIOS domain"), Some("Domain"));
    assert_eq!(field(ti, "NetBIOS computer"), Some("Server"));
}

#[test]
fn ntlm_type2_full_target_info() {
    let s = decode("NTLM", PYSPNEGO_NTLM_CHALLENGE);
    let ti = s.find("Target info");
    assert_eq!(field(ti, "DNS computer"), Some("DC01.domain.local"));
    assert_eq!(field(ti, "Timestamp"), Some("2020-04-30T02:46:22.414Z"));
}

#[test]
fn ntlm_type3_v2_with_target_spn() {
    let s = decode("NTLM", PYSPNEGO_NTLM_AUTHENTICATE);
    assert_eq!(s.title, "NTLM Type 3 (Authenticate)");
    assert_eq!(s.get("User"), Some("vagrant-domain@DOMAIN.LOCAL"));
    assert_eq!(s.get("Workstation"), Some("JBOREAN-LINUX"));
    assert_eq!(s.get("NT response"), Some("252 bytes (NTLMv2)"));
    let v2 = s.find("NTLMv2 response");
    assert_eq!(field(v2, "Client challenge"), Some("dc5a7473ac5672fc"));
    assert_eq!(field(v2, "Target name (SPN)"), Some("dc01.domain.local"));
}

#[test]
fn negotiate_with_client_ntlm_is_flagged_as_kerberos_fallback() {
    // The Type 1 Quena captured against a CNAME host whose SPN did not exist.
    let s = decode("Negotiate", "TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAKAPRlAAAADw==");
    assert_eq!(s.title, "NTLM Type 1 (Negotiate)");
    assert!(s.notes.iter().any(|n| n.contains("fell back to NTLM")));
    // A Type 2 is the server's answer and not flagged; plain NTLM is never flagged.
    assert!(decode("Negotiate", PYSPNEGO_NTLM_CHALLENGE).notes.is_empty());
    assert!(decode("NTLM", PYSPNEGO_NTLM_NEGOTIATE).notes.is_empty());
}

// ------------------------------------------------ header values and plugin output

#[test]
fn header_values() {
    let d = token::decode_header_value(&format!("Negotiate {PYSPNEGO_NEG_TOKEN_RESP}")).unwrap();
    assert_eq!(d.section.title, "SPNEGO NegTokenResp");
    assert_eq!(token::decode_header_value(&format!("  NTLM {PYSPNEGO_NTLM_CHALLENGE}  ")).unwrap().section.title, "NTLM Type 2 (Challenge)");
    // Challenges without token and other schemes are not decoded.
    for v in ["Negotiate", "NTLM", "Basic dXNlcjpwYXNz", "Bearer abc.def.ghi", "Basic realm=\"VIS-Core\"", "Bearer realm=\"vis-realm\"", "Negotiate a=b"] {
        assert!(token::decode_header_value(v).is_none(), "{v}");
    }
}

#[test]
fn flattened_nodes() {
    let d: Decoded = token::decode("Negotiate", PYSPNEGO_NEG_TOKEN_RESP).unwrap();
    let n = token::nodes(&d);
    assert_eq!((n[0].depth, n[0].kind, n[0].name.as_str()), (0, NodeKind::Section, "SPNEGO NegTokenResp"));
    assert_eq!((n[1].depth, n[1].kind, n[1].name.as_str(), n[1].value.as_str()), (0, NodeKind::Field, "Negotiation state", "accept-completed (0)"));
    let child = n.iter().find(|x| x.kind == NodeKind::Section && x.depth == 1).unwrap();
    assert_eq!(child.name, "Kerberos AP-REP (mutual authentication)");
    let raw = n.last().unwrap();
    assert_eq!((raw.depth, raw.kind), (0, NodeKind::Code));
    assert_eq!(raw.name, format!("Raw token ({} bytes)", d.bytes.len()));
    assert!(raw.value.starts_with("0000  a1 81 b7 30"), "{}", raw.value);
}

// ------------------------------------------------ robustness

#[test]
fn invalid_input() {
    assert!(token::decode("Basic", "dXNlcjpwYXNz").is_none());
    assert!(token::decode("Negotiate", "  ").is_none());
    assert_eq!(decode("Negotiate", "@@@").title, "Invalid token");
    let cut = &token::base64(PYSPNEGO_NEG_TOKEN_INIT).unwrap()[..40];
    assert_eq!(decode("Negotiate", &b64(cut)).title, "Token could not be parsed");
}

#[test]
fn every_prefix_and_mutation_decodes_without_panic() {
    let vectors = [
        PYSPNEGO_NEG_TOKEN_INIT,
        PYSPNEGO_NEG_TOKEN_INIT2,
        PYSPNEGO_NEG_TOKEN_RESP,
        PYSPNEGO_KRB_AP_REQ,
        PYSPNEGO_KRB_AP_REP,
        PYSPNEGO_KRB_ERROR,
        PYSPNEGO_NTLM_NEGOTIATE,
        PYSPNEGO_NTLM_CHALLENGE,
        PYSPNEGO_NTLM_AUTHENTICATE,
    ];
    let mut rng = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    for v in vectors {
        let bin = token::base64(v).unwrap();
        for n in 1..bin.len() {
            let _ = token::decode("Negotiate", &b64(&bin[..n]));
        }
        for _ in 0..500 {
            let mut m = bin.clone();
            for _ in 0..1 + next() % 4 {
                let i = (next() as usize) % m.len();
                m[i] = next() as u8;
            }
            let _ = token::decode("Negotiate", &b64(&m));
        }
    }
}

#[test]
fn base64_variants() {
    let std = token::base64(PYSPNEGO_NTLM_NEGOTIATE).unwrap();
    let url = PYSPNEGO_NTLM_NEGOTIATE.replace('+', "-").replace('/', "_");
    assert_eq!(token::base64(url.trim_end_matches('=')).unwrap(), std);
    assert!(token::base64("ab$c").is_none());
}

#[test]
fn hex_dump() {
    assert_eq!(token::hex_dump(b"NTLM\0", 4096), "0000  4e 54 4c 4d 00                                   NTLM.");
    assert_eq!(token::hex_dump(&[0u8; 40], 16).lines().count(), 2);
}
