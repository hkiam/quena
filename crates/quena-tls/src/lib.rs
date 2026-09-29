//! TLS for Quena: a local root CA, on-the-fly leaf certificates for HTTPS
//! interception and client configurations for upstream connections.
//!
//! Security (PLAN.md §9): the CA private key is stored with 0600
//! permissions in the data directory and never exported; the CA can be
//! removed and regenerated at any time.

use parking_lot::Mutex;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType, SerialNumber,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ServerConfig};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Once};

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("certificate: {0}")]
    Cert(#[from] rcgen::Error),
    #[error("tls: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, TlsError>;

pub const CA_CERT_FILE: &str = "quena-root-ca.pem";
pub const CA_KEY_FILE: &str = "quena-root-ca.key";
pub const CA_COMMON_NAME: &str = "Quena Root CA";

static INIT: Once = Once::new();

/// Install the ring crypto provider as process default (idempotent).
pub fn init() {
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The local root certificate authority.
pub struct CertAuthority {
    dir: PathBuf,
    cert_pem: String,
    cert_der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
    /// One key pair shared by all leaf certificates (fast issuance).
    leaf_key: KeyPair,
    leaf_signing: Arc<dyn rustls::sign::SigningKey>,
    leaves: Mutex<lru::LruCache<String, Arc<CertifiedKey>>>,
    configs: Mutex<lru::LruCache<(String, bool), Arc<ServerConfig>>>,
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(data)?;
    }
    #[cfg(not(unix))]
    std::fs::write(&tmp, data)?;
    std::fs::rename(tmp, path)
}

fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp-cert");
    std::fs::write(&tmp, data)?;
    std::fs::rename(tmp, path)
}

fn move_aside(path: &Path) {
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(format!(".corrupt-{ts}"));
    if let Err(e) = std::fs::rename(path, path.with_file_name(name)) {
        tracing::warn!(target: "quena::tls", "could not move {} aside: {e}", path.display());
    }
}

fn random_serial() -> SerialNumber {
    let mut b = [0u8; 16];
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
    let r = rustls::crypto::ring::default_provider().secure_random;
    if r.fill(&mut b).is_err() {
        b[..16].copy_from_slice(&t.to_be_bytes());
    }
    b[0] &= 0x7f; // positive
    SerialNumber::from_slice(&b)
}

fn ca_params() -> CertificateParams {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_COMMON_NAME);
    dn.push(DnType::OrganizationName, "Quena HTTP(S) Workbench");
    let user = std::env::var("USER").unwrap_or_default();
    let host = std::env::var("HOSTNAME").ok().or_else(|| std::env::var("HOST").ok()).unwrap_or_default();
    dn.push(DnType::OrganizationalUnitName, format!("Generated locally for {user}@{host}").trim_end_matches('@').to_string());
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    let now = time::OffsetDateTime::now_utc();
    p.not_before = now - time::Duration::days(1);
    p.not_after = now + time::Duration::days(3650);
    p.serial_number = Some(random_serial());
    p
}

impl CertAuthority {
    /// Load the CA from `dir`, creating it if it does not exist.
    pub fn load_or_create(dir: impl Into<PathBuf>) -> Result<CertAuthority> {
        init();
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        let cert_path = dir.join(CA_CERT_FILE);
        let key_path = dir.join(CA_KEY_FILE);
        match (cert_path.exists(), key_path.exists()) {
            (true, true) => {
                let loaded = (|| -> Result<CertAuthority> {
                    let cert_pem = std::fs::read_to_string(&cert_path)?;
                    let key = KeyPair::from_pem(&std::fs::read_to_string(&key_path)?)?;
                    Self::from_parts(dir.clone(), cert_pem, key)
                })();
                match loaded {
                    Ok(ca) => return Ok(ca),
                    // A damaged CA (truncated write, disk error) must not keep Quena from
                    // starting: keep the files for inspection and create a new CA. The UI
                    // then shows it as not trusted.
                    Err(e) => {
                        tracing::error!(target: "quena::tls", "root CA in {} is unreadable ({e}); moving it aside and creating a new one", dir.display());
                        move_aside(&cert_path);
                        move_aside(&key_path);
                    }
                }
            }
            // Only one half present (interrupted creation): start over.
            (true, false) => move_aside(&cert_path),
            (false, true) => move_aside(&key_path),
            (false, false) => {}
        }
        let key = KeyPair::generate()?;
        let cert = ca_params().self_signed(&key)?;
        write_private(&key_path, key.serialize_pem().as_bytes())?;
        write_atomic(&cert_path, cert.pem().as_bytes())?;
        tracing::info!(target: "quena::tls", "generated new root CA in {}", dir.display());
        Self::from_parts(dir, cert.pem(), key)
    }

    fn from_parts(dir: PathBuf, cert_pem: String, key: KeyPair) -> Result<CertAuthority> {
        let der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next()
            .ok_or_else(|| TlsError::Other("CA certificate missing".into()))??;
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, key)?;
        let leaf_key = KeyPair::generate()?;
        let pk = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let leaf_signing = rustls::crypto::ring::sign::any_supported_type(&pk)?;
        Ok(CertAuthority {
            dir,
            cert_pem,
            cert_der: der,
            issuer,
            leaf_key,
            leaf_signing,
            leaves: Mutex::new(lru::LruCache::new(NonZeroUsize::new(2048).unwrap())),
            configs: Mutex::new(lru::LruCache::new(NonZeroUsize::new(2048).unwrap())),
        })
    }

    /// Delete the CA files and create a new CA.
    pub fn regenerate(dir: impl Into<PathBuf>) -> Result<CertAuthority> {
        let dir = dir.into();
        let _ = std::fs::remove_file(dir.join(CA_CERT_FILE));
        let _ = std::fs::remove_file(dir.join(CA_KEY_FILE));
        Self::load_or_create(dir)
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn cert_der(&self) -> &[u8] {
        self.cert_der.as_ref()
    }

    pub fn cert_path(&self) -> PathBuf {
        self.dir.join(CA_CERT_FILE)
    }

    /// SHA-1 fingerprint (hex, upper case) – used by `security delete-certificate -Z`.
    pub fn sha1_fingerprint(&self) -> String {
        let d = ring_sha1(self.cert_der());
        hex::encode_upper(d)
    }

    /// SHA-256 fingerprint for display.
    pub fn sha256_fingerprint(&self) -> String {
        use sha2::Digest;
        let d = sha2::Sha256::digest(self.cert_der());
        d.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
    }

    /// Leaf certificate (chain + key) for `host`, cached.
    pub fn leaf(&self, host: &str) -> Result<Arc<CertifiedKey>> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if let Some(k) = self.leaves.lock().get(&host) {
            return Ok(k.clone());
        }
        let mut p = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host.clone());
        dn.push(DnType::OrganizationName, "Quena HTTP(S) Workbench");
        p.distinguished_name = dn;
        p.subject_alt_names = vec![match host.trim_matches(['[', ']']).parse::<IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(host.clone().try_into()?),
        }];
        // A wildcard SAN for the parent domain improves cache hits for sibling hosts.
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.use_authority_key_identifier_extension = true;
        let now = time::OffsetDateTime::now_utc();
        p.not_before = now - time::Duration::days(2);
        // Apple limits TLS server certificates to 398 days.
        p.not_after = now + time::Duration::days(390);
        p.serial_number = Some(random_serial());
        let cert = p.signed_by(&self.leaf_key, &self.issuer)?;
        let ck = Arc::new(CertifiedKey::new(vec![cert.der().clone(), self.cert_der.clone()], self.leaf_signing.clone()));
        self.leaves.lock().put(host, ck.clone());
        Ok(ck)
    }

    /// Server configuration presenting a certificate for `host`.
    pub fn server_config(&self, host: &str, allow_h2: bool) -> Result<Arc<ServerConfig>> {
        let key = (host.to_ascii_lowercase(), allow_h2);
        if let Some(c) = self.configs.lock().get(&key) {
            return Ok(c.clone());
        }
        let ck = self.leaf(host)?;
        let mut cfg = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Fixed(ck)));
        cfg.alpn_protocols = if allow_h2 { vec![b"h2".to_vec(), b"http/1.1".to_vec()] } else { vec![b"http/1.1".to_vec()] };
        let cfg = Arc::new(cfg);
        self.configs.lock().put(key, cfg.clone());
        Ok(cfg)
    }

    /// `.mobileconfig` profile for iOS/macOS installing this root certificate.
    pub fn mobileconfig(&self) -> String {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(self.cert_der());
        let uuid1 = uuid_like(&self.sha1_fingerprint(), 1);
        let uuid2 = uuid_like(&self.sha1_fingerprint(), 2);
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadCertificateFileName</key><string>quena-root-ca.cer</string>
      <key>PayloadContent</key><data>{b64}</data>
      <key>PayloadDescription</key><string>Adds the Quena root certificate for HTTPS inspection</string>
      <key>PayloadDisplayName</key><string>{CA_COMMON_NAME}</string>
      <key>PayloadIdentifier</key><string>io.github.hkiam.quena.ca.{uuid1}</string>
      <key>PayloadType</key><string>com.apple.security.root</string>
      <key>PayloadUUID</key><string>{uuid1}</string>
      <key>PayloadVersion</key><integer>1</integer>
    </dict>
  </array>
  <key>PayloadDisplayName</key><string>Quena HTTPS Inspection</string>
  <key>PayloadDescription</key><string>Only install this profile on devices you want to debug with Quena. Remove it afterwards.</string>
  <key>PayloadIdentifier</key><string>io.github.hkiam.quena.profile.{uuid2}</string>
  <key>PayloadRemovalDisallowed</key><false/>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>{uuid2}</string>
  <key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>
"#
        )
    }
}

fn uuid_like(hexs: &str, salt: u8) -> String {
    use sha2::Digest;
    let d = sha2::Sha256::digest([hexs.as_bytes(), &[salt]].concat());
    let h = hex::encode_upper(&d[..16]);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

fn ring_sha1(data: &[u8]) -> Vec<u8> {
    // Minimal SHA-1 (only used for the keychain fingerprint, not for security).
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    h.iter().flat_map(|x| x.to_be_bytes()).collect()
}

#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);
impl ResolvesServerCert for Fixed {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// Upstream TLS client configurations.
pub struct ClientConfigs {
    verified_h2: Arc<ClientConfig>,
    verified_h1: Arc<ClientConfig>,
    insecure_h2: Arc<ClientConfig>,
    insecure_h1: Arc<ClientConfig>,
    /// Client certificates (mTLS) per host: host pattern -> (chain, key PEM path).
    client_certs: Mutex<Vec<(String, Arc<ClientConfig>, Arc<ClientConfig>)>>,
    roots: Arc<rustls::RootCertStore>,
}

fn root_store() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // Native roots include enterprise CAs from the OS trust store.
    let native = rustls_native_certs::load_native_certs();
    let mut n = 0;
    for c in native.certs {
        if roots.add(c).is_ok() {
            n += 1;
        }
    }
    tracing::debug!(target: "quena::tls", "loaded {n} native root certificates");
    roots
}

fn with_alpn(mut c: ClientConfig, h2: bool) -> Arc<ClientConfig> {
    c.alpn_protocols = if h2 { vec![b"h2".to_vec(), b"http/1.1".to_vec()] } else { vec![b"http/1.1".to_vec()] };
    Arc::new(c)
}

impl ClientConfigs {
    pub fn new() -> Result<ClientConfigs> {
        init();
        let roots = Arc::new(root_store());
        let verified = || {
            ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .map(|b| b.with_root_certificates(roots.clone()).with_no_client_auth())
        };
        let insecure = || {
            ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .map(|b| b.dangerous().with_custom_certificate_verifier(Arc::new(NoVerify(provider()))).with_no_client_auth())
        };
        Ok(ClientConfigs {
            verified_h2: with_alpn(verified()?, true),
            verified_h1: with_alpn(verified()?, false),
            insecure_h2: with_alpn(insecure()?, true),
            insecure_h1: with_alpn(insecure()?, false),
            client_certs: Mutex::new(Vec::new()),
            roots,
        })
    }

    /// Configure a client certificate (PEM chain + PEM key) for hosts matching `pattern`.
    pub fn add_client_cert(&self, pattern: &str, chain_pem: &str, key_pem: &str) -> Result<()> {
        let chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut chain_pem.as_bytes()).collect::<std::result::Result<_, _>>()?;
        let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())?.ok_or_else(|| TlsError::Other("no private key in PEM".into()))?;
        let mk = |h2| -> Result<Arc<ClientConfig>> {
            let c = ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()?
                .with_root_certificates(self.roots.clone())
                .with_client_auth_cert(chain.clone(), key.clone_key())?;
            Ok(with_alpn(c, h2))
        };
        let (a, b) = (mk(true)?, mk(false)?);
        self.client_certs.lock().push((pattern.to_ascii_lowercase(), a, b));
        Ok(())
    }

    pub fn clear_client_certs(&self) {
        self.client_certs.lock().clear();
    }

    /// Pick a configuration for `host`.
    pub fn for_host(&self, host: &str, insecure: bool, h2: bool, glob: impl Fn(&str, &str) -> bool) -> Arc<ClientConfig> {
        let host = host.to_ascii_lowercase();
        if let Some((_, a, b)) = self.client_certs.lock().iter().find(|(p, _, _)| glob(p, &host)) {
            return if h2 { a.clone() } else { b.clone() };
        }
        match (insecure, h2) {
            (false, true) => self.verified_h2.clone(),
            (false, false) => self.verified_h1.clone(),
            (true, true) => self.insecure_h2.clone(),
            (true, false) => self.insecure_h1.clone(),
        }
    }
}

pub fn server_name(host: &str) -> Result<ServerName<'static>> {
    let h = host.trim_matches(['[', ']']);
    if let Ok(ip) = h.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(h.to_string()).map_err(|e| TlsError::Other(format!("invalid server name {host}: {e}")))
}

/// Encode a DER certificate as PEM.
pub fn der_to_pem(der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut s = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(line).unwrap_or(""));
        s.push('\n');
    }
    s.push_str("-----END CERTIFICATE-----\n");
    s
}

#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corrupt_ca_is_replaced_instead_of_failing() {
        let dir = tempfile::tempdir().unwrap();
        let first = CertAuthority::load_or_create(dir.path()).unwrap();
        std::fs::write(dir.path().join(CA_KEY_FILE), b"-----BEGIN PRIVATE KEY-----\ntruncated").unwrap();
        let second = CertAuthority::load_or_create(dir.path()).unwrap();
        assert_ne!(first.sha256_fingerprint(), second.sha256_fingerprint());
        let aside = std::fs::read_dir(dir.path()).unwrap().filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().contains(".corrupt-")).count();
        assert_eq!(aside, 2, "both halves of the damaged CA are kept");
        // A half-written CA (key only) is recreated as well.
        std::fs::remove_file(dir.path().join(CA_CERT_FILE)).unwrap();
        CertAuthority::load_or_create(dir.path()).unwrap();
    }

    #[test]
    fn ca_roundtrip_and_leaf() {
        let dir = tempfile_dir();
        let ca = CertAuthority::load_or_create(&dir).unwrap();
        let fp = ca.sha256_fingerprint();
        let ca2 = CertAuthority::load_or_create(&dir).unwrap();
        assert_eq!(fp, ca2.sha256_fingerprint());
        let leaf = ca.leaf("example.com").unwrap();
        assert_eq!(leaf.cert.len(), 2);
        let ip = ca.leaf("127.0.0.1").unwrap();
        assert_eq!(ip.cert.len(), 2);
        assert!(ca.server_config("example.com", true).is_ok());
        assert_eq!(ca.sha1_fingerprint().len(), 40);
        assert!(ca.mobileconfig().contains("com.apple.security.root"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join(CA_KEY_FILE)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn sha1_known() {
        assert_eq!(hex::encode(ring_sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    fn tempfile_dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("quena-tls-test-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}
