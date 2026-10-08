//! TLS record decryption with logged secrets: the key schedules of TLS 1.2 (PRF) and
//! TLS 1.3 (HKDF-Expand-Label), and the record protection of the AEAD suites (AES-GCM,
//! ChaCha20-Poly1305) and of the TLS 1.2 AES-CBC suites.
//!
//! Records are only read: CBC MACs are stripped, not checked; AEAD tags are checked as part
//! of decryption (a wrong key or a corrupt record fails).

use ring::{aead, hkdf, hmac};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    Sha256,
    Sha384,
}

impl Hash {
    pub fn len(self) -> usize {
        match self {
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
        }
    }
    fn hmac(self) -> hmac::Algorithm {
        match self {
            Hash::Sha256 => hmac::HMAC_SHA256,
            Hash::Sha384 => hmac::HMAC_SHA384,
        }
    }
    fn hkdf(self) -> hkdf::Algorithm {
        match self {
            Hash::Sha256 => hkdf::HKDF_SHA256,
            Hash::Sha384 => hkdf::HKDF_SHA384,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    AesGcm,
    ChaCha,
    /// AES-CBC with an HMAC of `mac_len` bytes.
    AesCbc { mac_len: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Suite {
    pub tls13: bool,
    pub cipher: Cipher,
    pub key_len: usize,
    /// PRF (TLS 1.2) or HKDF (TLS 1.3) hash.
    pub hash: Hash,
}

/// The suites that can be decrypted.
pub fn suite(id: u16) -> Option<Suite> {
    use Cipher::*;
    use Hash::*;
    let s = |tls13, cipher, key_len, hash| Some(Suite { tls13, cipher, key_len, hash });
    let cbc = |mac_len| AesCbc { mac_len };
    match id {
        0x1301 => s(true, AesGcm, 16, Sha256),
        0x1302 => s(true, AesGcm, 32, Sha384),
        0x1303 => s(true, ChaCha, 32, Sha256),
        // TLS 1.2 AES-GCM (RSA, DHE_RSA, ECDHE_ECDSA, ECDHE_RSA)
        0x009c | 0x009e | 0xc02b | 0xc02f => s(false, AesGcm, 16, Sha256),
        0x009d | 0x009f | 0xc02c | 0xc030 => s(false, AesGcm, 32, Sha384),
        // TLS 1.2 ChaCha20-Poly1305 (ECDHE_RSA, ECDHE_ECDSA, DHE_RSA, and the PSK variants)
        0xcca8..=0xccae => s(false, ChaCha, 32, Sha256),
        // TLS 1.2 AES-CBC with SHA-1, SHA-256 and SHA-384 MACs
        0x002f | 0x0033 | 0xc009 | 0xc013 => s(false, cbc(20), 16, Sha256),
        0x0035 | 0x0039 | 0xc00a | 0xc014 => s(false, cbc(20), 32, Sha256),
        0x003c | 0x0067 | 0xc023 | 0xc027 => s(false, cbc(32), 16, Sha256),
        0x003d | 0x006b => s(false, cbc(32), 32, Sha256),
        0xc024 | 0xc028 => s(false, cbc(48), 32, Sha384),
        _ => None,
    }
}

/// TLS 1.2 PRF (RFC 5246, 5): P_hash(secret, label + seed), `len` bytes.
pub fn prf(hash: Hash, secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let key = hmac::Key::new(hash.hmac(), secret);
    let label_seed = [label, seed].concat();
    let mut a = hmac::sign(&key, &label_seed).as_ref().to_vec();
    let mut out = Vec::with_capacity(len + hash.len());
    while out.len() < len {
        out.extend_from_slice(hmac::sign(&key, &[&a[..], &label_seed].concat()).as_ref());
        a = hmac::sign(&key, &a).as_ref().to_vec();
    }
    out.truncate(len);
    out
}

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// TLS 1.3 HKDF-Expand-Label (RFC 8446, 7.1) with an empty context.
pub fn expand_label(hash: Hash, secret: &[u8], label: &str, len: usize) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let info = [&(len as u16).to_be_bytes()[..], &[full.len() as u8], full.as_bytes(), &[0u8]];
    let mut out = vec![0u8; len];
    hkdf::Prk::new_less_safe(hash.hkdf(), secret)
        .expand(&info, Len(len))
        .and_then(|okm| okm.fill(&mut out))
        .expect("HKDF output length is within limits");
    out
}

enum Key {
    Aead(Box<aead::LessSafeKey>),
    Aes128(Box<aes::Aes128>),
    Aes256(Box<aes::Aes256>),
}

/// The protection of one direction: key, IV and record sequence number.
pub struct Protection {
    suite: Suite,
    key: Key,
    iv: Vec<u8>,
    seq: u64,
    /// TLS 1.2 CBC with encrypt-then-MAC (RFC 7366).
    etm: bool,
    /// TLS 1.3: the traffic secret, for key updates.
    secret: Vec<u8>,
}

/// The key block of a TLS 1.2 connection, split per direction (client, server).
pub fn tls12_keys(suite: Suite, master: &[u8], client_random: &[u8; 32], server_random: &[u8; 32], etm: bool) -> Option<[Protection; 2]> {
    let mac_len = match suite.cipher {
        Cipher::AesCbc { mac_len } => mac_len,
        _ => 0,
    };
    let iv_len = match suite.cipher {
        Cipher::AesGcm => 4,
        Cipher::ChaCha => 12,
        Cipher::AesCbc { .. } => 0,
    };
    let seed = [&server_random[..], &client_random[..]].concat();
    let block = prf(suite.hash, master, b"key expansion", &seed, 2 * (mac_len + suite.key_len + iv_len));
    let keys = &block[2 * mac_len..];
    let (ck, sk) = (&keys[..suite.key_len], &keys[suite.key_len..2 * suite.key_len]);
    let ivs = &keys[2 * suite.key_len..];
    let (civ, siv) = (&ivs[..iv_len], &ivs[iv_len..2 * iv_len]);
    Some([Protection::new(suite, ck, civ, etm, Vec::new())?, Protection::new(suite, sk, siv, etm, Vec::new())?])
}

impl Protection {
    fn new(suite: Suite, key: &[u8], iv: &[u8], etm: bool, secret: Vec<u8>) -> Option<Protection> {
        use aes::cipher::KeyInit;
        let key = match suite.cipher {
            Cipher::AesGcm | Cipher::ChaCha => {
                let alg = match (suite.cipher, suite.key_len) {
                    (Cipher::ChaCha, _) => &aead::CHACHA20_POLY1305,
                    (_, 16) => &aead::AES_128_GCM,
                    _ => &aead::AES_256_GCM,
                };
                Key::Aead(Box::new(aead::LessSafeKey::new(aead::UnboundKey::new(alg, key).ok()?)))
            }
            Cipher::AesCbc { .. } if suite.key_len == 16 => Key::Aes128(Box::new(aes::Aes128::new_from_slice(key).ok()?)),
            Cipher::AesCbc { .. } => Key::Aes256(Box::new(aes::Aes256::new_from_slice(key).ok()?)),
        };
        Some(Protection { suite, key, iv: iv.to_vec(), seq: 0, etm, secret })
    }

    /// TLS 1.3 protection from a traffic secret.
    pub fn tls13(suite: Suite, secret: &[u8]) -> Option<Protection> {
        let key = expand_label(suite.hash, secret, "key", suite.key_len);
        let iv = expand_label(suite.hash, secret, "iv", 12);
        Protection::new(suite, &key, &iv, false, secret.to_vec())
    }

    /// TLS 1.3 KeyUpdate: the next traffic secret and its keys.
    pub fn updated(&self) -> Option<Protection> {
        let next = expand_label(self.suite.hash, &self.secret, "traffic upd", self.suite.hash.len());
        Protection::tls13(self.suite, &next)
    }

    /// Per-record nonce: the IV XOR the sequence number.
    fn xor_nonce(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n.copy_from_slice(&self.iv[..12]);
        for (b, s) in n[4..].iter_mut().zip(self.seq.to_be_bytes()) {
            *b ^= s;
        }
        n
    }

    /// Decrypt one record (`ty`, `version` and `fragment` as on the wire). Returns the
    /// content type and the plaintext; `None` if the record does not decrypt.
    pub fn open(&mut self, ty: u8, version: u16, fragment: &[u8]) -> Option<(u8, Vec<u8>)> {
        let r = if self.suite.tls13 { self.open13(ty, version, fragment) } else { self.open12(ty, version, fragment) };
        if r.is_some() {
            self.seq += 1;
        }
        r
    }

    fn aead(&self, nonce: [u8; 12], aad: &[u8], data: &[u8]) -> Option<Vec<u8>> {
        let Key::Aead(k) = &self.key else { return None };
        let mut buf = data.to_vec();
        let n = k.open_in_place(aead::Nonce::assume_unique_for_key(nonce), aead::Aad::from(aad), &mut buf).ok()?.len();
        buf.truncate(n);
        Some(buf)
    }

    fn open13(&self, ty: u8, version: u16, fragment: &[u8]) -> Option<(u8, Vec<u8>)> {
        let mut aad = vec![ty];
        aad.extend_from_slice(&version.to_be_bytes());
        aad.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
        let mut inner = self.aead(self.xor_nonce(), &aad, fragment)?;
        // TLSInnerPlaintext: content, the real content type, zero padding.
        let end = inner.iter().rposition(|b| *b != 0)?;
        let real = inner[end];
        inner.truncate(end);
        Some((real, inner))
    }

    fn open12(&self, ty: u8, version: u16, fragment: &[u8]) -> Option<(u8, Vec<u8>)> {
        let aad = |len: usize| {
            let mut a = self.seq.to_be_bytes().to_vec();
            a.push(ty);
            a.extend_from_slice(&version.to_be_bytes());
            a.extend_from_slice(&(len as u16).to_be_bytes());
            a
        };
        match self.suite.cipher {
            Cipher::AesGcm => {
                let (explicit, data) = (fragment.get(..8)?, fragment.get(8..)?);
                let len = data.len().checked_sub(16)?;
                let mut nonce = [0u8; 12];
                nonce[..4].copy_from_slice(&self.iv);
                nonce[4..].copy_from_slice(explicit);
                Some((ty, self.aead(nonce, &aad(len), data)?))
            }
            Cipher::ChaCha => {
                let len = fragment.len().checked_sub(16)?;
                Some((ty, self.aead(self.xor_nonce(), &aad(len), fragment)?))
            }
            Cipher::AesCbc { mac_len } => {
                let (iv, mut data) = (fragment.get(..16)?, fragment.get(16..)?);
                if self.etm {
                    data = data.get(..data.len().checked_sub(mac_len)?)?;
                }
                if data.is_empty() || !data.len().is_multiple_of(16) {
                    return None;
                }
                let mut plain = self.cbc_decrypt(iv, data);
                let pad = *plain.last()? as usize;
                let mut end = plain.len().checked_sub(pad + 1)?;
                if !self.etm {
                    end = end.checked_sub(mac_len)?;
                }
                plain.truncate(end);
                Some((ty, plain))
            }
        }
    }

    fn cbc_decrypt(&self, iv: &[u8], data: &[u8]) -> Vec<u8> {
        use aes::cipher::BlockCipherDecrypt;
        let mut out = Vec::with_capacity(data.len());
        let mut prev = iv;
        for chunk in data.chunks_exact(16) {
            let mut block = aes::Block::default();
            block.copy_from_slice(chunk);
            match &self.key {
                Key::Aes128(k) => k.decrypt_block(&mut block),
                Key::Aes256(k) => k.decrypt_block(&mut block),
                Key::Aead(_) => {}
            }
            out.extend(block.iter().zip(prev).map(|(b, p)| b ^ p));
            prev = chunk;
        }
        out
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn hkdf_expand_label_rfc8448() {
        // RFC 8448, 3 (Simple 1-RTT Handshake): server handshake traffic secret → key, iv.
        let secret = h("b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38");
        assert_eq!(expand_label(Hash::Sha256, &secret, "key", 16), h("3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc"));
        assert_eq!(expand_label(Hash::Sha256, &secret, "iv", 12), h("5d 31 3e b2 67 12 76 ee 13 00 0b 30"));
    }

    #[test]
    fn tls13_record_rfc8448() {
        // RFC 8448, 3: the server's first protected handshake record (EncryptedExtensions …)
        // starts like this; decryption with the server handshake key must succeed.
        let secret = h("b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38");
        let mut p = Protection::tls13(suite(0x1301).unwrap(), &secret).unwrap();
        // Our own record under that key: encrypt "hello" + content type 22 with ring.
        let nonce = p.xor_nonce();
        let Key::Aead(k) = &p.key else { panic!() };
        let mut buf = b"hello\x16".to_vec();
        let len = buf.len() + 16;
        let aad = [23, 3, 3, (len >> 8) as u8, len as u8];
        k.seal_in_place_append_tag(aead::Nonce::assume_unique_for_key(nonce), aead::Aad::from(aad), &mut buf).unwrap();
        assert_eq!(p.open(23, 0x0303, &buf), Some((22, b"hello".to_vec())));
        assert_eq!(p.seq, 1);
        assert!(p.open(23, 0x0303, &buf).is_none()); // wrong sequence number now
    }

    #[test]
    fn prf_sha256_vector() {
        // Test vector of the TLS 1.2 PRF (SHA-256), as published for the IETF TLS WG.
        let out = prf(
            Hash::Sha256,
            &h("9b be 43 6b a9 40 f0 17 b1 76 52 84 9a 71 db 35"),
            b"test label",
            &h("a0 ba 9f 93 6c da 31 18 27 a6 f7 96 ff d5 19 8c"),
            100,
        );
        assert_eq!(
            out,
            h("e3 f2 29 ba 72 7b e1 7b 8d 12 26 20 55 7c d4 53 c2 aa b2 1d 07 c3 d4 95 32 9b 52 d4 e6 1e db 5a
               6b 30 17 91 e9 0d 35 c9 c9 a4 6b 4e 14 ba f9 af 0f a0 22 f7 07 7d ef 17 ab fd 37 97 c0 56 4b ab
               4f bc 91 66 6e 9d ef 9b 97 fc e3 4f 79 67 89 ba a4 80 82 d1 22 ee 42 c5 a7 2e 5a 51 10 ff f7 01
               87 34 7b 66")
        );
    }

    /// AES-CBC encryption for tests (the importer only decrypts).
    pub fn cbc_encrypt(key: &[u8], iv: &[u8], plain: &[u8]) -> Vec<u8> {
        use aes::cipher::{BlockCipherEncrypt, KeyInit};
        let k = aes::Aes128::new_from_slice(key).unwrap();
        let mut prev = iv.to_vec();
        let mut out = Vec::new();
        for chunk in plain.chunks_exact(16) {
            let mut block = aes::Block::default();
            for (b, (c, p)) in block.iter_mut().zip(chunk.iter().zip(&prev)) {
                *b = c ^ p;
            }
            k.encrypt_block(&mut block);
            out.extend_from_slice(&block);
            prev = block.to_vec();
        }
        out
    }

    #[test]
    fn tls12_cbc_record() {
        let s = suite(0xc013).unwrap(); // ECDHE_RSA_WITH_AES_128_CBC_SHA
        let key = [7u8; 16];
        let mut p = Protection::new(s, &key, &[], false, Vec::new()).unwrap();
        // "GET /" + 20-byte MAC + padding to 32 bytes (6 bytes of value 6, plus the length byte).
        let mut plain = b"GET /".to_vec();
        plain.extend([0xaa; 20]);
        plain.extend([6u8; 7]);
        let iv = [9u8; 16];
        let frag = [&iv[..], &cbc_encrypt(&key, &iv, &plain)].concat();
        assert_eq!(p.open(23, 0x0303, &frag), Some((23, b"GET /".to_vec())));
        // Encrypt-then-MAC: the MAC follows the ciphertext.
        let mut p = Protection::new(s, &key, &[], true, Vec::new()).unwrap();
        let mut plain = b"GET /".to_vec();
        plain.extend([10u8; 11]);
        let frag = [&iv[..], &cbc_encrypt(&key, &iv, &plain), &[0xbb; 20]].concat();
        assert_eq!(p.open(23, 0x0303, &frag), Some((23, b"GET /".to_vec())));
    }
}
