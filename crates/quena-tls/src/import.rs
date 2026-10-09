//! Using an existing CA instead of the generated one (a company's interception CA, a CA
//! shared in a team), exporting the CA with its key, and reading certificate facts.
//!
//! Accepted: a PEM certificate (optionally followed by the chain up to the root) with an
//! unencrypted PEM key (PKCS#8, PKCS#1 RSA or SEC1 EC), or a PKCS#12 file (`.p12`, `.pfx`)
//! with its password. The certificate must be a CA that may sign certificates, the key must
//! belong to it and it must be valid now.

use crate::{CA_CERT_FILE, CA_CHAIN_FILE, CA_KEY_FILE, CertAuthority, Result, TlsError, write_atomic, write_private};
use rcgen::KeyPair;
use std::path::PathBuf;

/// What a certificate says about itself (display and checks).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertFacts {
    pub subject: String,
    pub issuer: String,
    /// Common name of the subject, if any.
    pub common_name: Option<String>,
    /// Validity, Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
    /// BasicConstraints CA=true.
    pub is_ca: bool,
    /// KeyUsage allows signing certificates (true when the extension is absent).
    pub can_sign_certs: bool,
    /// The subject's public key (the BIT STRING contents).
    pub public_key: Vec<u8>,
}

/// Facts of a DER certificate, `None` if it cannot be parsed.
pub fn cert_facts(der: &[u8]) -> Option<CertFacts> {
    let (_, c) = x509_parser::parse_x509_certificate(der).ok()?;
    let common_name = c.subject().iter_common_name().next().and_then(|cn| cn.as_str().ok()).map(str::to_string);
    let is_ca = c.basic_constraints().ok().flatten().map(|b| b.value.ca).unwrap_or(false);
    let can_sign_certs = c.key_usage().ok().flatten().map(|k| k.value.key_cert_sign()).unwrap_or(true);
    Some(CertFacts {
        subject: c.subject().to_string(),
        issuer: c.issuer().to_string(),
        common_name,
        not_before: c.validity().not_before.timestamp(),
        not_after: c.validity().not_after.timestamp(),
        is_ca,
        can_sign_certs,
        public_key: c.public_key().subject_public_key.data.to_vec(),
    })
}

/// A CA to import: its certificate, the chain above it (may be empty) and its key.
pub struct CaMaterial {
    pub cert_der: Vec<u8>,
    pub chain_der: Vec<Vec<u8>>,
    pub key_pkcs8: Vec<u8>,
}

impl std::fmt::Debug for CaMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaMaterial").field("cert_der", &self.cert_der.len()).field("chain_der", &self.chain_der.len()).field("key_pkcs8", &"<secret>").finish()
    }
}

fn other(s: impl Into<String>) -> TlsError {
    TlsError::Other(s.into())
}

// ------------------------------------------------------------------ DER helpers

fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let bytes: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend(bytes);
    out
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// One TLV: (tag, whole TLV, content, rest).
fn read_tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8], &[u8])> {
    let tag = *b.first()?;
    let first = *b.get(1)?;
    let (len, hdr) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *b.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    (end <= b.len()).then(|| (tag, &b[..end], &b[hdr..end], &b[end..]))
}

/// rsaEncryption 1.2.840.113549.1.1.1
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// id-ecPublicKey 1.2.840.10045.2.1
const OID_EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

/// PKCS#1 RSAPrivateKey → PKCS#8 PrivateKeyInfo.
fn pkcs1_to_pkcs8(pkcs1: &[u8]) -> Vec<u8> {
    let alg = tlv(0x30, &[tlv(0x06, OID_RSA), vec![0x05, 0x00]].concat());
    tlv(0x30, &[vec![0x02, 0x01, 0x00], alg, tlv(0x04, pkcs1)].concat())
}

/// SEC1 ECPrivateKey (with its curve in `[0]`) → PKCS#8. The curve moves into the
/// algorithm identifier; ring wants the inner key without it.
fn sec1_to_pkcs8(sec1: &[u8]) -> Result<Vec<u8>> {
    let bad = || other("the EC key is not a valid SEC1 ECPrivateKey");
    let (tag, _, body, _) = read_tlv(sec1).ok_or_else(bad)?;
    if tag != 0x30 {
        return Err(bad());
    }
    let mut rest = body;
    let mut inner = Vec::new();
    let mut curve = None;
    while !rest.is_empty() {
        let (tag, whole, content, r) = read_tlv(rest).ok_or_else(bad)?;
        match tag {
            0xa0 => curve = Some(read_tlv(content).filter(|t| t.0 == 0x06).ok_or_else(bad)?.1.to_vec()),
            _ => inner.extend_from_slice(whole),
        }
        rest = r;
    }
    let curve = curve.ok_or_else(|| other("the EC key does not name its curve; convert it to PKCS#8 (openssl pkcs8 -topk8 -nocrypt)"))?;
    let alg = tlv(0x30, &[tlv(0x06, OID_EC), curve].concat());
    Ok(tlv(0x30, &[vec![0x02, 0x01, 0x00], alg, tlv(0x04, &tlv(0x30, &inner))].concat()))
}

fn key_pair(pkcs8: &[u8]) -> Result<KeyPair> {
    KeyPair::try_from(pkcs8).map_err(|_| other("the key type is not supported (RSA, ECDSA P-256/P-384 and Ed25519 are)"))
}

// ------------------------------------------------------------------ reading CAs

/// A CA from PEM: `cert_pem` holds the CA certificate and optionally its chain (in any
/// order); `key_pem` the CA's private key.
pub fn ca_from_pem(cert_pem: &str, key_pem: &str) -> Result<CaMaterial> {
    if key_pem.contains("ENCRYPTED") {
        return Err(other("the key is encrypted; export it without a password, or import a .p12 file with its password instead"));
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())?.ok_or_else(|| other("no private key found in the key file"))?;
    let key_pkcs8 = match &key {
        rustls::pki_types::PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der().to_vec(),
        rustls::pki_types::PrivateKeyDer::Pkcs1(k) => pkcs1_to_pkcs8(k.secret_pkcs1_der()),
        rustls::pki_types::PrivateKeyDer::Sec1(k) => sec1_to_pkcs8(k.secret_sec1_der())?,
        _ => return Err(other("unsupported key format")),
    };
    let certs: Vec<Vec<u8>> = rustls_pemfile::certs(&mut cert_pem.as_bytes()).map(|c| c.map(|c| c.to_vec())).collect::<std::result::Result<_, _>>()?;
    pick(certs, key_pkcs8)
}

/// A CA from a PKCS#12 file.
pub fn ca_from_p12(data: &[u8], password: &str) -> Result<CaMaterial> {
    use p12_keystore::{KeyStore, Pkcs12ImportPolicy};
    let ks = KeyStore::from_pkcs12(data, password, Pkcs12ImportPolicy::Strict)
        .or_else(|_| KeyStore::from_pkcs12(data, password, Pkcs12ImportPolicy::Relaxed))
        .map_err(|e| other(format!("cannot read the .p12 file (wrong password?): {e}")))?;
    let (_, chain) = ks.private_key_chain().ok_or_else(|| other("the .p12 file contains no private key"))?;
    let mut certs: Vec<Vec<u8>> = chain.certs().iter().map(|c| c.as_der().to_vec()).collect();
    // Certificates stored without the key may complete the chain.
    for (_, e) in ks.entries() {
        if let p12_keystore::KeyStoreEntry::Certificate(c) = e {
            certs.push(c.as_der().to_vec());
        }
    }
    pick(certs, chain.key().as_der().to_vec())
}

/// The certificate the key belongs to is the CA; the others form its chain.
fn pick(certs: Vec<Vec<u8>>, key_pkcs8: Vec<u8>) -> Result<CaMaterial> {
    if certs.is_empty() {
        return Err(other("no certificate found"));
    }
    let key = key_pair(&key_pkcs8)?;
    let i = certs
        .iter()
        .position(|c| cert_facts(c).is_some_and(|f| f.public_key == key.public_key_raw()))
        .ok_or_else(|| other("the private key does not belong to the certificate"))?;
    let mut chain = certs;
    let cert_der = chain.remove(i);
    chain.dedup();
    chain.retain(|c| c != &cert_der);
    Ok(CaMaterial { cert_der, chain_der: chain, key_pkcs8 })
}

/// Check that `m` can work as Quena's CA.
pub fn check_ca(m: &CaMaterial) -> Result<CertFacts> {
    let f = cert_facts(&m.cert_der).ok_or_else(|| other("the certificate cannot be read"))?;
    let name = f.common_name.clone().unwrap_or_else(|| f.subject.clone());
    if !f.is_ca {
        return Err(other(format!("{name} is not a CA certificate (BasicConstraints CA:TRUE is missing)")));
    }
    if !f.can_sign_certs {
        return Err(other(format!("{name} may not sign certificates (KeyUsage keyCertSign is missing)")));
    }
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    if f.not_after < now {
        return Err(other(format!("{name} expired on {}", date(f.not_after))));
    }
    if f.not_before > now {
        return Err(other(format!("{name} is valid only from {}", date(f.not_before))));
    }
    if key_pair(&m.key_pkcs8)?.public_key_raw() != f.public_key.as_slice() {
        return Err(other("the private key does not belong to the certificate"));
    }
    Ok(f)
}

/// `YYYY-MM-DD` of Unix seconds.
pub fn date(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix).map(|t| format!("{:04}-{:02}-{:02}", t.year(), t.month() as u8, t.day())).unwrap_or_default()
}

fn backup(path: &std::path::Path, ts: u64) {
    if path.exists() {
        let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
        name.push(format!(".bak-{ts}"));
        if let Err(e) = std::fs::rename(path, path.with_file_name(name)) {
            tracing::warn!(target: "quena::tls", "could not back up {}: {e}", path.display());
        }
    }
}

impl CertAuthority {
    /// Use `m` as the CA from now on: the files of the current CA are kept as `*.bak-<time>`.
    pub fn import(dir: impl Into<PathBuf>, m: &CaMaterial) -> Result<CertAuthority> {
        crate::init();
        check_ca(m)?;
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        let key = key_pair(&m.key_pkcs8)?;
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        for f in [CA_CERT_FILE, CA_KEY_FILE, CA_CHAIN_FILE] {
            backup(&dir.join(f), ts);
        }
        let cert_pem = crate::der_to_pem(&m.cert_der);
        write_private(&dir.join(CA_KEY_FILE), key.serialize_pem().as_bytes())?;
        write_atomic(&dir.join(CA_CERT_FILE), cert_pem.as_bytes())?;
        if !m.chain_der.is_empty() {
            let chain: String = m.chain_der.iter().map(|c| crate::der_to_pem(c)).collect();
            write_atomic(&dir.join(CA_CHAIN_FILE), chain.as_bytes())?;
        }
        tracing::info!(target: "quena::tls", "imported root CA into {}", dir.display());
        Self::from_parts(dir, cert_pem, key)
    }

    /// The CA's private key (PKCS#8 PEM). Whoever has it can impersonate every site to
    /// devices that trust this CA.
    pub fn key_pem(&self) -> String {
        self.issuer.key().serialize_pem()
    }

    /// The CA with its key and chain as PKCS#12 (AES-256, HMAC-SHA256).
    pub fn to_p12(&self, password: &str) -> Result<Vec<u8>> {
        use p12_keystore::{Certificate, KeyStore, KeyStoreEntry, PrivateKey, PrivateKeyChain};
        if password.is_empty() {
            return Err(other("a password is required for a .p12 file"));
        }
        let e = |e: p12_keystore::error::Error| other(format!("PKCS#12: {e}"));
        let key = PrivateKey::from_der(&self.issuer.key().serialize_der()).map_err(e)?;
        let mut certs = vec![Certificate::from_der(self.cert_der()).map_err(e)?];
        for c in &self.chain {
            certs.push(Certificate::from_der(c.as_ref()).map_err(e)?);
        }
        let mut ks = KeyStore::new();
        let id = crate::ring_sha1(self.cert_der());
        ks.add_entry(&self.facts().common_name.unwrap_or_else(|| "quena".into()), KeyStoreEntry::PrivateKeyChain(PrivateKeyChain::new(id, key, certs)));
        ks.writer(password).write().map_err(e)
    }

    /// Facts of the CA certificate.
    pub fn facts(&self) -> CertFacts {
        cert_facts(self.cert_der()).unwrap_or_default()
    }

    /// Number of certificates sent after the CA (an imported intermediate's chain).
    pub fn chain_len(&self) -> usize {
        self.chain.len()
    }

    /// Display name: the certificate's common name.
    pub fn common_name(&self) -> String {
        self.facts().common_name.unwrap_or_else(|| crate::CA_COMMON_NAME.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)).unwrap()
    }

    /// The leaf Quena issues for `host` verifies against `root` (as a browser trusting it would).
    fn verifies(ca: &CertAuthority, host: &str, root: &[u8]) {
        let ck = ca.leaf(host).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(root.to_vec())).unwrap();
        let v = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::new(rustls::crypto::ring::default_provider())).build().unwrap();
        v.verify_server_cert(&ck.cert[0], &ck.cert[1..], &ServerName::try_from(host.to_string()).unwrap(), &[], UnixTime::now()).unwrap();
    }
    use std::sync::Arc;

    #[test]
    fn rsa_pkcs1_and_ec_sec1_cas_from_openssl() {
        for (cert, key, cn) in [("rsa-ca.pem", "rsa-ca.key", "Acme Corp Interception CA"), ("ec-ca.pem", "ec-ca.key", "Acme EC CA")] {
            let dir = tempfile::tempdir().unwrap();
            let before = CertAuthority::load_or_create(dir.path()).unwrap().sha256_fingerprint();
            let m = ca_from_pem(&fixture(cert), &fixture(key)).unwrap();
            let ca = CertAuthority::import(dir.path(), &m).unwrap();
            assert_ne!(ca.sha256_fingerprint(), before);
            assert_eq!(ca.common_name(), cn);
            assert!(ca.mobileconfig().contains(cn));
            verifies(&ca, "example.com", &m.cert_der);
            // The old CA is kept, and the new one loads again.
            assert!(std::fs::read_dir(dir.path()).unwrap().filter_map(|e| e.ok()).any(|e| e.file_name().to_string_lossy().contains(".bak-")));
            let again = CertAuthority::load_or_create(dir.path()).unwrap();
            assert_eq!(again.sha256_fingerprint(), ca.sha256_fingerprint());
            verifies(&again, "127.0.0.1", &m.cert_der);
        }
    }

    #[test]
    fn wrong_material_is_refused() {
        let e = ca_from_pem(&fixture("ec-ca.pem"), &fixture("ec-ca-encrypted.key")).unwrap_err().to_string();
        assert!(e.contains("encrypted"), "{e}");
        let e = ca_from_pem(&fixture("rsa-ca.pem"), &fixture("ec-ca.key")).unwrap_err().to_string();
        assert!(e.contains("does not belong"), "{e}");
        let m = ca_from_pem(&fixture("not-ca.pem"), &fixture("ec-ca.key")).unwrap();
        let e = check_ca(&m).unwrap_err().to_string();
        assert!(e.contains("not a CA"), "{e}");
        let dir = tempfile::tempdir().unwrap();
        assert!(CertAuthority::import(dir.path(), &m).is_err());
        assert!(!dir.path().join(CA_CERT_FILE).exists(), "nothing written for a refused CA");
        let e = ca_from_p12(fixture("rsa-ca.pem").as_bytes(), "x").unwrap_err().to_string();
        assert!(e.contains(".p12"), "{e}");
    }

    #[test]
    fn p12_from_openssl_and_roundtrip() {
        let data = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rsa-ca-legacy.p12")).unwrap();
        assert!(ca_from_p12(&data, "wrong").is_err());
        let m = ca_from_p12(&data, "secret").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let ca = CertAuthority::import(dir.path(), &m).unwrap();
        assert_eq!(ca.common_name(), "Acme Corp Interception CA");
        // Export and import elsewhere: the same CA.
        assert!(ca.to_p12("").is_err());
        let p12 = ca.to_p12("pw").unwrap();
        let dir2 = tempfile::tempdir().unwrap();
        let ca2 = CertAuthority::import(dir2.path(), &ca_from_p12(&p12, "pw").unwrap()).unwrap();
        assert_eq!(ca2.sha256_fingerprint(), ca.sha256_fingerprint());
        assert_eq!(ca2.key_pem(), ca.key_pem());
        // Quena's own generated CA exports as well.
        let own = CertAuthority::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let back = ca_from_p12(&own.to_p12("pw").unwrap(), "pw").unwrap();
        assert_eq!(back.cert_der, own.cert_der());
    }

    #[test]
    fn intermediate_ca_sends_its_chain() {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyIdMethod, KeyPair};
        let root_key = KeyPair::generate().unwrap();
        let mut rp = CertificateParams::default();
        rp.distinguished_name.push(DnType::CommonName, "Corp Root");
        rp.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root = rp.self_signed(&root_key).unwrap();
        let root_issuer = rcgen::Issuer::new(rp, root_key);
        let int_key = KeyPair::generate().unwrap();
        let mut ip = CertificateParams::default();
        ip.distinguished_name.push(DnType::CommonName, "Corp Proxy Intermediate");
        ip.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        // A subject key id not derived the way rcgen would: the leaf must use it as AKI.
        ip.key_identifier_method = KeyIdMethod::PreSpecified(vec![7; 20]);
        let int = ip.signed_by(&int_key, &root_issuer).unwrap();
        let pem = format!("{}{}", root.pem(), int.pem());
        let m = ca_from_pem(&pem, &int_key.serialize_pem()).unwrap();
        assert_eq!(m.chain_der.len(), 1);
        let dir = tempfile::tempdir().unwrap();
        let ca = CertAuthority::import(dir.path(), &m).unwrap();
        assert_eq!(ca.leaf("a.example").unwrap().cert.len(), 3);
        verifies(&ca, "a.example", root.der());
        // After a restart the chain is still sent.
        verifies(&CertAuthority::load_or_create(dir.path()).unwrap(), "b.example", root.der());
        // Regenerating drops the imported chain.
        let fresh = CertAuthority::regenerate(dir.path()).unwrap();
        assert_eq!(fresh.leaf("a.example").unwrap().cert.len(), 2);
    }

    #[test]
    fn facts_of_a_certificate() {
        let f = cert_facts(&rustls_pemfile::certs(&mut fixture("rsa-ca.pem").as_bytes()).next().unwrap().unwrap()).unwrap();
        assert!(f.is_ca && f.can_sign_certs);
        assert_eq!(f.common_name.as_deref(), Some("Acme Corp Interception CA"));
        assert!(f.subject.contains("O=Acme"));
        assert_eq!(date(f.not_after).len(), 10);
        assert!(f.not_after > f.not_before);
        assert!(cert_facts(b"junk").is_none());
    }
}
