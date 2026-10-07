//! What a TLS connection shows without its keys: SNI and ALPN offered in the ClientHello,
//! version, cipher suite and ALPN chosen in the ServerHello.

use quena_model::TlsInfo;

/// Handshake bytes kept while looking for the hello; hellos are a few KB.
const MAX_HELLO: usize = 64 << 10;

/// Does `b` start like a TLS handshake record (as a ClientHello does)?
pub fn looks_like_tls(b: &[u8]) -> bool {
    b.len() >= 3 && b[0] == 0x16 && b[1] == 0x03 && b[2] <= 0x04
}

/// Collects one side's handshake messages from its records until the hello is found.
#[derive(Default)]
pub struct HelloReader {
    raw: Vec<u8>,
    /// Handshake payload of the records so far.
    hs: Vec<u8>,
    pub done: bool,
}

impl HelloReader {
    /// Feed stream bytes; returns the hello body (type, body) once complete.
    pub fn feed(&mut self, data: &[u8]) -> Option<(u8, Vec<u8>)> {
        if self.done {
            return None;
        }
        self.raw.extend_from_slice(data);
        // Unwrap complete handshake records; another record type (ChangeCipherSpec after the
        // hello, an alert) ends the handshake bytes in the clear.
        let mut other = false;
        while self.raw.len() >= 5 {
            let len = u16::from_be_bytes([self.raw[3], self.raw[4]]) as usize;
            if self.raw[0] != 0x16 {
                other = true;
                break;
            }
            if self.raw.len() < 5 + len {
                break;
            }
            self.hs.extend_from_slice(&self.raw[5..5 + len]);
            self.raw.drain(..5 + len);
        }
        if self.hs.len() >= 4 {
            let len = u32::from_be_bytes([0, self.hs[1], self.hs[2], self.hs[3]]) as usize;
            if self.hs.len() >= 4 + len {
                self.done = true;
                return Some((self.hs[0], self.hs[4..4 + len].to_vec()));
            }
        }
        if other || self.raw.len() + self.hs.len() > MAX_HELLO {
            self.done = true;
        }
        None
    }
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

/// SNI and ALPN offers from a ClientHello body.
pub fn client_hello(body: &[u8], info: &mut TlsInfo) {
    let mut c = Cur(body);
    let parsed = (|| {
        c.take(2 + 32)?;
        c.vec8()?; // session id
        c.vec16()?; // cipher suites
        c.vec8()?; // compression
        Some(())
    })();
    if parsed.is_none() {
        return;
    }
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
}

/// Version, cipher suite and chosen ALPN from a ServerHello body.
pub fn server_hello(body: &[u8], info: &mut TlsInfo) {
    let mut c = Cur(body);
    let Some(mut version) = c.u16() else { return };
    let suite = (|| {
        c.take(32)?;
        c.vec8()?;
        let s = c.u16()?;
        c.u8()?;
        Some(s)
    })();
    let Some(suite) = suite else { return };
    for (t, d) in extensions(c) {
        match t {
            43 if d.len() == 2 => version = u16::from_be_bytes([d[0], d[1]]),
            16 => {
                if let Some(p) = alpn_list(d).into_iter().next() {
                    info.alpn = Some(p);
                }
            }
            _ => {}
        }
    }
    info.version = match version {
        0x0300 => "SSL 3.0".into(),
        0x0301 => "TLS 1.0".into(),
        0x0302 => "TLS 1.1".into(),
        0x0303 => "TLS 1.2".into(),
        0x0304 => "TLS 1.3".into(),
        v => format!("0x{v:04X}"),
    };
    info.cipher = cipher_name(suite);
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
        let mut r = HelloReader::default();
        assert!(r.feed(&ch[..7]).is_none()); // split across segments
        let (t, body) = r.feed(&ch[7..]).unwrap();
        assert_eq!(t, 1);
        let mut info = TlsInfo::default();
        client_hello(&body, &mut info);
        assert_eq!(info.sni.as_deref(), Some("example.org"));
        assert_eq!(info.alpn.as_deref(), Some("h2, http/1.1"));
        let mut r = HelloReader::default();
        let (t, body) = r.feed(&server_hello_record()).unwrap();
        assert_eq!(t, 2);
        server_hello(&body, &mut info);
        assert_eq!(info.version, "TLS 1.3");
        assert_eq!(info.cipher, "TLS13_AES_256_GCM_SHA384");
        assert_eq!(info.alpn.as_deref(), Some("h2"));
    }
}
