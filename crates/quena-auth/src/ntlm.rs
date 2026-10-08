//! NTLMv2 (MS-NLMP). Type 1 → send, parse Type 2 challenge, build Type 3.

use crate::AuthError;
use crate::crypto::{hmac_md5, md4, utf16le};

const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

// Negotiate flags we set (MS-NLMP §2.2.2.5).
const NEG_UNICODE: u32 = 0x0000_0001;
const NEG_REQUEST_TARGET: u32 = 0x0000_0004;
const NEG_NTLM: u32 = 0x0000_0200;
const NEG_ALWAYS_SIGN: u32 = 0x0000_8000;
const NEG_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
const NEG_TARGET_INFO: u32 = 0x0080_0000;
const NEG_128: u32 = 0x2000_0000;
const NEG_56: u32 = 0x8000_0000;

pub fn type1() -> Vec<u8> {
    let flags = NEG_UNICODE
        | NEG_REQUEST_TARGET
        | NEG_NTLM
        | NEG_ALWAYS_SIGN
        | NEG_EXTENDED_SESSIONSECURITY
        | NEG_TARGET_INFO
        | NEG_128
        | NEG_56;
    let mut m = Vec::with_capacity(40);
    m.extend_from_slice(SIGNATURE);
    m.extend_from_slice(&1u32.to_le_bytes()); // MessageType = 1
    m.extend_from_slice(&flags.to_le_bytes());
    m.extend_from_slice(&[0u8; 8]); // DomainNameFields (empty)
    m.extend_from_slice(&[0u8; 8]); // WorkstationFields (empty)
    m
}

pub struct Challenge {
    pub server_challenge: [u8; 8],
    pub target_info: Vec<u8>,
    pub flags: u32,
}

pub fn parse_type2(data: &[u8]) -> Result<Challenge, AuthError> {
    if data.len() < 48
        || &data[..8] != SIGNATURE
        || u32::from_le_bytes(data[8..12].try_into().unwrap()) != 2
    {
        return Err(AuthError::Protocol("invalid NTLM Type 2 message".into()));
    }
    let flags = u32::from_le_bytes(data[20..24].try_into().unwrap());
    let mut server_challenge = [0u8; 8];
    server_challenge.copy_from_slice(&data[24..32]);
    // TargetInfoFields at offset 40: len(2), maxlen(2), offset(4)
    let ti_len = u16::from_le_bytes(data[40..42].try_into().unwrap()) as usize;
    // The Type 3 message carries target info in u16-length fields together with ~50 more
    // bytes; a larger block cannot be answered correctly.
    if ti_len > 60_000 {
        return Err(AuthError::Protocol(
            "NTLM Type 2 target info too large".into(),
        ));
    }
    let ti_off = u32::from_le_bytes(data[44..48].try_into().unwrap()) as usize;
    let target_info = if ti_len > 0 && ti_off + ti_len <= data.len() {
        data[ti_off..ti_off + ti_len].to_vec()
    } else {
        Vec::new()
    };
    Ok(Challenge {
        server_challenge,
        target_info,
        flags,
    })
}

/// NTOWFv2 = HMAC_MD5(MD4(UTF16LE(pass)), UTF16LE(UPPER(user) + domain)).
fn ntowf_v2(user: &str, domain: &str, password: &str) -> [u8; 16] {
    let nt = md4(&utf16le(password));
    let mut id = utf16le(&user.to_uppercase());
    id.extend_from_slice(&utf16le(domain));
    hmac_md5(&nt, &id)
}

/// Build the Type 3 message. `time`/`client_challenge` are parameters for testing;
/// in production pass the real time and 8 random bytes.
pub fn type3(
    user: &str,
    domain: &str,
    password: &str,
    ch: &Challenge,
    time: u64,
    client_challenge: [u8; 8],
) -> Vec<u8> {
    let ntowf = ntowf_v2(user, domain, password);
    // temp = Responserversion(1) HiResp(1) Z(6) Time(8) ClientChallenge(8) Z(4) TargetInfo Z(4)
    let mut temp = Vec::with_capacity(28 + ch.target_info.len() + 4);
    temp.push(0x01);
    temp.push(0x01);
    temp.extend_from_slice(&[0u8; 6]);
    temp.extend_from_slice(&time.to_le_bytes());
    temp.extend_from_slice(&client_challenge);
    temp.extend_from_slice(&[0u8; 4]);
    temp.extend_from_slice(&ch.target_info);
    temp.extend_from_slice(&[0u8; 4]);
    let mut proof_input = Vec::with_capacity(8 + temp.len());
    proof_input.extend_from_slice(&ch.server_challenge);
    proof_input.extend_from_slice(&temp);
    let nt_proof = hmac_md5(&ntowf, &proof_input);
    let mut nt_response = Vec::with_capacity(16 + temp.len());
    nt_response.extend_from_slice(&nt_proof);
    nt_response.extend_from_slice(&temp);
    // LMv2: HMAC_MD5(NTOWFv2, server_challenge ++ client_challenge) ++ client_challenge
    let mut lm_input = Vec::with_capacity(16);
    lm_input.extend_from_slice(&ch.server_challenge);
    lm_input.extend_from_slice(&client_challenge);
    let mut lm_response = hmac_md5(&ntowf, &lm_input).to_vec();
    lm_response.extend_from_slice(&client_challenge);

    let domain_b = utf16le(domain);
    let user_b = utf16le(user);
    let ws_b = utf16le("QUENA");
    let session_key: Vec<u8> = Vec::new(); // no key exchange

    // Layout after the 64-byte header + 8 security-buffer fields (each 8 bytes) = 88 bytes.
    let mut payload = Vec::new();
    let base = 88u32;
    let field = |off: &mut u32, data: &[u8], out: &mut Vec<u8>| -> [u8; 8] {
        let len = data.len() as u16;
        let start = base + *off;
        out.extend_from_slice(data);
        *off += data.len() as u32;
        let mut f = [0u8; 8];
        f[0..2].copy_from_slice(&len.to_le_bytes());
        f[2..4].copy_from_slice(&len.to_le_bytes());
        f[4..8].copy_from_slice(&start.to_le_bytes());
        f
    };
    let mut off = 0u32;
    let f_lm = field(&mut off, &lm_response, &mut payload);
    let f_nt = field(&mut off, &nt_response, &mut payload);
    let f_domain = field(&mut off, &domain_b, &mut payload);
    let f_user = field(&mut off, &user_b, &mut payload);
    let f_ws = field(&mut off, &ws_b, &mut payload);
    let f_key = field(&mut off, &session_key, &mut payload);

    let flags = NEG_UNICODE
        | NEG_NTLM
        | NEG_ALWAYS_SIGN
        | NEG_EXTENDED_SESSIONSECURITY
        | NEG_TARGET_INFO
        | NEG_128
        | NEG_56
        | (ch.flags & NEG_REQUEST_TARGET);
    let mut m = Vec::with_capacity(88 + payload.len());
    m.extend_from_slice(SIGNATURE);
    m.extend_from_slice(&3u32.to_le_bytes());
    m.extend_from_slice(&f_lm);
    m.extend_from_slice(&f_nt);
    m.extend_from_slice(&f_domain);
    m.extend_from_slice(&f_user);
    m.extend_from_slice(&f_ws);
    m.extend_from_slice(&f_key);
    m.extend_from_slice(&flags.to_le_bytes());
    m.extend_from_slice(&[0u8; 8]); // Version (8 bytes, all zero)
    m.extend_from_slice(&[0u8; 16]); // MIC (zero – no key exchange)
    debug_assert_eq!(m.len(), 88);
    m.extend_from_slice(&payload);
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // MS-NLMP §4.2.4 known values.
    fn target_info() -> Vec<u8> {
        // MsvAvNbDomainName "Domain", MsvAvNbComputerName "Server", EOL
        let mut t = vec![0x02, 0x00, 0x0c, 0x00];
        t.extend_from_slice(&utf16le("Domain"));
        t.extend_from_slice(&[0x01, 0x00, 0x0c, 0x00]);
        t.extend_from_slice(&utf16le("Server"));
        t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        t
    }

    #[test]
    fn ntowfv2_vector() {
        assert_eq!(
            hex(&ntowf_v2("User", "Domain", "Password")),
            "0c868a403bfd7a93a3001ef22ef02e3f"
        );
    }

    #[test]
    fn nt_proof_vector() {
        let ch = Challenge {
            server_challenge: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            target_info: target_info(),
            flags: 0,
        };
        let m = type3("User", "Domain", "Password", &ch, 0, [0xaa; 8]);
        // NtChallengeResponse begins with NTProofStr; locate via the field pointer.
        let nt_off = u32::from_le_bytes(m[24..28].try_into().unwrap()) as usize;
        let nt_len = u16::from_le_bytes(m[20..22].try_into().unwrap()) as usize;
        let nt = &m[nt_off..nt_off + nt_len];
        assert_eq!(
            hex(&nt[..16]),
            "68cd0ab851e51c96aabc927bebef6a1c",
            "NTProofStr"
        );
        // temp starts right after the proof; must match the documented Responserversion header
        assert_eq!(&nt[16..18], &[0x01, 0x01]);
    }

    #[test]
    fn type1_shape() {
        let t = type1();
        assert_eq!(&t[..8], SIGNATURE);
        assert_eq!(u32::from_le_bytes(t[8..12].try_into().unwrap()), 1);
    }

    #[test]
    fn type2_roundtrip() {
        // Build a minimal Type 2 and parse it back.
        let ti = target_info();
        let mut m = vec![0u8; 48];
        m[..8].copy_from_slice(SIGNATURE);
        m[8..12].copy_from_slice(&2u32.to_le_bytes());
        m[24..32].copy_from_slice(&[9, 8, 7, 6, 5, 4, 3, 2]);
        m[40..42].copy_from_slice(&(ti.len() as u16).to_le_bytes());
        m[44..48].copy_from_slice(&48u32.to_le_bytes());
        m.extend_from_slice(&ti);
        let ch = parse_type2(&m).unwrap();
        assert_eq!(ch.server_challenge, [9, 8, 7, 6, 5, 4, 3, 2]);
        assert_eq!(ch.target_info, ti);
    }
}
