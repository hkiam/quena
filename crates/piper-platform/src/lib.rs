//! Platform services (PLAN.md §29, rule 4). No OS calls outside this crate.
//!
//! * system proxy: read the current configuration, point it to Piper,
//!   restore it (also after a crash via a backup file);
//! * root certificate trust: install/remove/check;
//! * process lookup: map a client TCP port to the owning process.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as imp;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as imp;

#[cfg(not(any(target_os = "macos", windows)))]
mod other;
#[cfg(not(any(target_os = "macos", windows)))]
use other as imp;

pub use imp::ProcessLookup;

#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error("{0}")]
    Command(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("not supported on this platform")]
    Unsupported,
}

pub type Result<T> = std::result::Result<T, PlatformError>;

/// Effective system proxy configuration (what the OS currently uses).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SystemProxy {
    pub http: Option<(String, u16)>,
    pub https: Option<(String, u16)>,
    pub pac_url: Option<String>,
    pub auto_discovery: bool,
    pub exceptions: Vec<String>,
}

impl SystemProxy {
    pub fn points_to(&self, port: u16) -> bool {
        let local = |h: &str| h == "127.0.0.1" || h == "localhost" || h == "::1";
        self.http.as_ref().is_some_and(|(h, p)| local(h) && *p == port) || self.https.as_ref().is_some_and(|(h, p)| local(h) && *p == port)
    }
}

/// Current system proxy settings.
pub fn system_proxy() -> Result<SystemProxy> {
    imp::system_proxy()
}

/// Point the system proxy to `127.0.0.1:port`. Saves the previous state to
/// `backup` first so it can be restored after a crash.
pub fn set_system_proxy(port: u16, bypass: &[String], backup: &Path) -> Result<()> {
    imp::set_system_proxy(port, bypass, backup)
}

/// Restore the system proxy from `backup` (no-op if there is no backup).
pub fn restore_system_proxy(backup: &Path) -> Result<bool> {
    imp::restore_system_proxy(backup)
}

/// Install `cert_pem_path` as trusted root for the current user (asks for confirmation/password).
pub fn install_root_ca(cert_pem_path: &Path) -> Result<()> {
    imp::install_root_ca(cert_pem_path)
}

/// Remove the root certificate (identified by its SHA-1 fingerprint) and its trust settings.
pub fn remove_root_ca(cert_pem_path: &Path, sha1: &str) -> Result<()> {
    imp::remove_root_ca(cert_pem_path, sha1)
}

/// Whether the OS trusts the certificate for TLS server authentication.
pub fn is_root_ca_trusted(cert_pem_path: &Path) -> bool {
    imp::is_root_ca_trusted(cert_pem_path)
}

/// Open a file or URL with the default handler.
pub fn open(target: &str) -> Result<()> {
    imp::open(target)
}

/// Reveal a file in the file manager.
pub fn reveal(path: &Path) -> Result<()> {
    imp::reveal(path)
}

/// Local IPv4 addresses of active interfaces (for the device assistant).
pub fn local_addresses() -> Vec<(String, String)> {
    imp::local_addresses()
}

/// OS secure storage for credentials (Keychain / Credential Manager).
/// Never stores secrets in plaintext files.
pub mod secure {
    use super::Result;

    pub const SERVICE: &str = "io.github.hkiam.piper.auth";

    /// Store a secret for `account` (e.g. "realm|host|user").
    pub fn set(account: &str, secret: &[u8]) -> Result<()> {
        super::imp::secure_set(account, secret)
    }
    /// Read a secret; `None` if not present.
    pub fn get(account: &str) -> Result<Option<Vec<u8>>> {
        super::imp::secure_get(account)
    }
    pub fn delete(account: &str) -> Result<()> {
        super::imp::secure_delete(account)
    }
}

#[cfg(test)]
mod secure_tests {
    #[test]
    fn roundtrip() {
        let acct = format!("piper-test|{}", std::process::id());
        super::secure::set(&acct, b"s3cr3t-\x00\xff").unwrap();
        assert_eq!(super::secure::get(&acct).unwrap().as_deref(), Some(&b"s3cr3t-\x00\xff"[..]));
        super::secure::delete(&acct).unwrap();
        assert_eq!(super::secure::get(&acct).unwrap(), None);
    }
}
