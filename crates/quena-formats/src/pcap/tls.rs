//! The hellos of a TLS connection: what it shows without its keys (SNI and ALPN offered in
//! the ClientHello; version, cipher suite and ALPN chosen in the ServerHello), and what
//! decrypting it takes (both randoms, the suite, encrypt-then-MAC).

use quena_model::TlsInfo;

/// Does `b` start like a TLS handshake record (as a ClientHello does)?
pub fn looks_like_tls(b: &[u8]) -> bool {
    b.len() >= 3 && b[0] == 0x16 && b[1] == 0x03 && b[2] <= 0x04
}

struct Cur<'a>(&'a [u8]);

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

/// Extensions of a hello: (type, data).
fn extensions(mut c: Cur<'_>) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let Some(ext) = c.vec16() else { return out };
    let mut c = Cur(ext);
    while let (Some(t), Some(d)) = (c.u16(), c.vec16()) {
        out.push((t, d));
    }
    out
}

fn alpn_list(d: &[u8]) -> Vec<String> {
    let mut c = Cur(d);
    let Some(list) = c.vec16() else { return Vec::new() };
    let mut c = Cur(list);
    let mut out = Vec::new();
    while let Some(p) = c.vec8() {
        out.push(String::from_utf8_lossy(p).into_owned());
    }
    out
}

/// SNI and ALPN offers from a ClientHello body; returns the client random.
pub fn client_hello(body: &[u8], info: &mut TlsInfo) -> Option<[u8; 32]> {
    let mut c = Cur(body);
    c.take(2)?;
    let random: [u8; 32] = c.take(32)?.try_into().ok()?;
    c.vec8()?; // session id
    c.vec16()?; // cipher suites
    c.vec8()?; // compression
    for (t, d) in extensions(c) {
        match t {
            0 => {
                let mut c = Cur(d);
                if let Some(list) = c.vec16() {
                    let mut c = Cur(list);
                    while let (Some(kind), Some(name)) = (c.u8(), c.vec16()) {
                        if kind == 0 {
                            info.sni = Some(String::from_utf8_lossy(name).into_owned());
                            break;
                        }
                    }
                }
            }
            16 => {
                let offered = alpn_list(d);
                if !offered.is_empty() && info.alpn.is_none() {
                    info.alpn = Some(offered.join(", "));
                }
            }
            _ => {}
        }
    }
    Some(random)
}

/// The random of a HelloRetryRequest (RFC 8446, 4.1.3): SHA-256 of "HelloRetryRequest".
const HELLO_RETRY: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2,
    0xc8, 0xa8, 0x33, 0x9c,
];

/// What the ServerHello chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerHello {
    pub random: [u8; 32],
    pub suite: u16,
    /// The negotiated version (supported_versions for TLS 1.3).
    pub version: u16,
    /// Encrypt-then-MAC (RFC 7366) for CBC suites.
    pub etm: bool,
    /// A HelloRetryRequest: another ClientHello and ServerHello follow.
    pub retry: bool,
}

/// Version, cipher suite and chosen ALPN from a ServerHello body.
pub fn server_hello(body: &[u8], info: &mut TlsInfo) -> Option<ServerHello> {
    let mut c = Cur(body);
    let mut version = c.u16()?;
    let random: [u8; 32] = c.take(32)?.try_into().ok()?;
    c.vec8()?;
    let suite = c.u16()?;
    c.u8()?;
    let mut etm = false;
    for (t, d) in extensions(c) {
        match t {
            43 if d.len() == 2 => version = u16::from_be_bytes([d[0], d[1]]),
            16 => {
                if let Some(p) = alpn_list(d).into_iter().next() {
                    info.alpn = Some(p);
                }
            }
            22 => etm = true,
            _ => {}
        }
    }
    info.version = match version {
        0x0300 => "SSL 3.0".into(),
        0x0301 => "TLS 1.0".into(),
        0x0302 => "TLS 1.1".into(),
        0x0303 => "TLS 1.2".into(),
        0x0304 => "TLS 1.3".into(),
        v if v >> 8 == 0x7f => format!("TLS 1.3 (draft {})", v & 0xff),
        v => format!("0x{v:04X}"),
    };
    info.cipher = cipher_name(suite);
    Some(ServerHello { random, suite, version, etm, retry: random == HELLO_RETRY })
}

fn cipher_name(s: u16) -> String {
    match s {
        0x1301 => "TLS13_AES_128_GCM_SHA256",
        0x1302 => "TLS13_AES_256_GCM_SHA384",
        0x1303 => "TLS13_CHACHA20_POLY1305_SHA256",
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        0xc013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xc014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x003c => "TLS_RSA_WITH_AES_128_CBC_SHA256",
        0x003d => "TLS_RSA_WITH_AES_256_CBC_SHA256",
        0x0033 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        0x0039 => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        0x0067 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        0x006b => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        0x009e => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        0x009f => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        0xc009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        0xc00a => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        0xc023 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        0xc024 => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        0xc027 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        0xc028 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        0xccaa => "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xccab => "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
        0xccac => "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
        0xccad => "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
        0xccae => "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256",
        _ => return format!("0x{s:04X}"),
    }
    .into()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn ext(t: u16, d: &[u8]) -> Vec<u8> {
        let mut v = t.to_be_bytes().to_vec();
        v.extend_from_slice(&(d.len() as u16).to_be_bytes());
        v.extend_from_slice(d);
        v
    }

    fn alpn(protos: &[&str]) -> Vec<u8> {
        let list: Vec<u8> = protos.iter().flat_map(|p| [&[p.len() as u8][..], p.as_bytes()].concat()).collect();
        [(list.len() as u16).to_be_bytes().to_vec(), list].concat()
    }

    fn record(hs_type: u8, body: &[u8]) -> Vec<u8> {
        let mut hs = vec![hs_type, 0, (body.len() >> 8) as u8, body.len() as u8];
        hs.extend_from_slice(body);
        let mut r = vec![0x16, 0x03, 0x01];
        r.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        r.extend(hs);
        r
    }

    /// A ClientHello record offering `sni` and h2/http1.1.
    pub fn client_hello_record(sni: &str) -> Vec<u8> {
        let mut b = vec![3, 3];
        b.extend_from_slice(&[0; 32]);
        b.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
        let mut name = vec![0];
        name.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        name.extend_from_slice(sni.as_bytes());
        let sni_ext = [(name.len() as u16).to_be_bytes().to_vec(), name].concat();
        let exts = [ext(0, &sni_ext), ext(16, &alpn(&["h2", "http/1.1"]))].concat();
        b.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        b.extend(exts);
        record(1, &b)
    }

    pub fn server_hello_record() -> Vec<u8> {
        let mut b = vec![3, 3];
        b.extend_from_slice(&[0; 32]);
        b.extend_from_slice(&[0, 0x13, 0x02, 0]);
        let exts = [ext(43, &[3, 4]), ext(16, &alpn(&["h2"]))].concat();
        b.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        b.extend(exts);
        record(2, &b)
    }

    #[test]
    fn hellos() {
        let ch = client_hello_record("example.org");
        assert!(looks_like_tls(&ch));
        let mut info = TlsInfo::default();
        // Record header (5) and handshake header (4) before the body.
        assert_eq!(client_hello(&ch[9..], &mut info), Some([0; 32]));
        assert_eq!(info.sni.as_deref(), Some("example.org"));
        assert_eq!(info.alpn.as_deref(), Some("h2, http/1.1"));
        let sh = server_hello(&server_hello_record()[9..], &mut info).unwrap();
        assert_eq!((sh.suite, sh.version, sh.etm, sh.retry), (0x1302, 0x0304, false, false));
        assert_eq!(info.version, "TLS 1.3");
        assert_eq!(info.cipher, "TLS13_AES_256_GCM_SHA384");
        assert_eq!(info.alpn.as_deref(), Some("h2"));
    }
}
