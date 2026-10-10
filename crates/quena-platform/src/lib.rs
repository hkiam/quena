//! Platform services. No OS calls outside this crate.
//!
//! * system proxy: read the current configuration, point it to Quena,
//!   restore it (also after a crash via a backup file);
//! * root certificate trust: install/remove/check;
//! * process lookup: map a client TCP port to the owning process;
//! * starting browsers and terminals that use Quena ([`launch`]).

use serde::{Deserialize, Serialize};
use std::path::Path;

pub mod launch;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as imp;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as imp;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as imp;

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
mod other;
#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
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

/// Windows: trust (`true`) or no longer trust the root certificate for all users of the
/// machine (the local machine's store; Windows asks for administrator rights). Elsewhere an
/// error: the user store already serves every program.
pub fn machine_root_ca(cert: &Path, sha1: &str, trust: bool) -> Result<()> {
    imp::machine_root_ca(cert, sha1, trust)
}

/// DNS domains of the VPN connections that are up (e.g. `corp.example`): requests to them
/// can be kept away from Quena. Empty when none is up or this cannot be told.
pub fn vpn_domains() -> Vec<String> {
    // The tools asked (scutil, resolvectl, PowerShell) can hang: at most 5 s.
    let (tx, rx) = std::sync::mpsc::channel();
    let _ = std::thread::Builder::new().name("quena-vpn".into()).spawn(move || {
        let _ = tx.send(imp::vpn_domains());
    });
    rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap_or_default()
}

fn is_vpn_interface(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["utun", "ipsec", "ppp", "tun", "tap", "wg", "vpn", "gpd", "cscotun"].iter().any(|p| n.starts_with(p))
}

fn keep_domain(d: &str, out: &mut Vec<String>) {
    let d = d.trim().trim_start_matches('~').trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() || d == "local" || d.ends_with(".arpa") || !d.contains(|c: char| c.is_ascii_alphanumeric()) || out.contains(&d) {
        return;
    }
    out.push(d);
}

/// Domains of `scutil --dns` resolvers bound to a VPN interface (utun, ipsec, ppp).
pub fn parse_scutil_dns(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for block in text.split("\nresolver #").skip(1) {
        let vpn = block.lines().any(|l| l.trim_start().starts_with("if_index") && l.split('(').nth(1).is_some_and(|n| is_vpn_interface(n.trim_end_matches(')'))));
        if !vpn {
            continue;
        }
        for l in block.lines() {
            let l = l.trim();
            if (l.starts_with("domain") || l.starts_with("search domain"))
                && let Some((_, v)) = l.split_once(':')
            {
                keep_domain(v, &mut out);
            }
        }
    }
    out
}

/// Domains of `resolvectl status` links that are VPN interfaces (tun, wg, ppp …).
pub fn parse_resolvectl(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut vpn = false;
    let mut domains = false;
    for l in text.lines() {
        let t = l.trim();
        if t.starts_with("Link ") {
            vpn = t.split('(').nth(1).is_some_and(|n| is_vpn_interface(n.trim_end_matches(')')));
        } else if t.starts_with("Global") {
            vpn = false;
        } else if vpn && let Some(v) = t.strip_prefix("DNS Domain:") {
            domains = true;
            for d in v.split_whitespace() {
                keep_domain(d, &mut out);
            }
        } else if vpn && domains && !t.is_empty() && !t.contains(':') {
            // A long list wraps onto lines of its own.
            for d in t.split_whitespace() {
                keep_domain(d, &mut out);
            }
        } else {
            domains = false;
        }
    }
    out
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

/// The system's hosts file.
pub fn hosts_file_path() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        std::path::PathBuf::from(root).join(r"System32\drivers\etc\hosts")
    }
    #[cfg(not(windows))]
    {
        std::path::PathBuf::from("/etc/hosts")
    }
}

/// Open a file or URL with the default handler.
pub fn open(target: &str) -> Result<()> {
    imp::open(target)
}

/// Reveal a file in the file manager.
pub fn reveal(path: &Path) -> Result<()> {
    imp::reveal(path)
}

/// Write a small state file so a crash mid-write never leaves a truncated file behind.
pub(crate) fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(tmp, path)
}

/// Raise the open-file limit (GUI apps on macOS start with a soft limit of 256, which a
/// busy browser plus tunnels exhausts quickly). Returns the new soft limit.
#[cfg(unix)]
pub fn raise_fd_limit(want: u64) -> Option<u64> {
    let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit/setrlimit only read/write the struct we pass.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) != 0 {
            return None;
        }
        let target = (want as libc::rlim_t).min(rl.rlim_max);
        // macOS rejects values above OPEN_MAX for the soft limit.
        #[cfg(target_os = "macos")]
        let target = target.min(10240);
        if target > rl.rlim_cur {
            let new = libc::rlimit { rlim_cur: target, rlim_max: rl.rlim_max };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &new) == 0 {
                return Some(target as u64);
            }
        }
        Some(rl.rlim_cur as u64)
    }
}

/// Windows has no small per-process descriptor limit for sockets.
#[cfg(not(unix))]
pub fn raise_fd_limit(_want: u64) -> Option<u64> {
    None
}

/// Local IPv4 addresses of active interfaces (for the device assistant).
pub fn local_addresses() -> Vec<(String, String)> {
    imp::local_addresses()
}

/// OS secure storage for credentials (Keychain / Credential Manager / Secret Service).
/// Never stores secrets in plaintext files.
pub mod secure {
    use super::Result;

    pub const SERVICE: &str = "io.github.hkiam.quena.auth";

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
        let acct = format!("quena-test|{}", std::process::id());
        super::secure::set(&acct, b"s3cr3t-\x00\xff").unwrap();
        assert_eq!(super::secure::get(&acct).unwrap().as_deref(), Some(&b"s3cr3t-\x00\xff"[..]));
        super::secure::delete(&acct).unwrap();
        assert_eq!(super::secure::get(&acct).unwrap(), None);
    }
}

#[cfg(test)]
mod vpn_tests {
    use super::*;

    #[test]
    fn vpn_domains_from_scutil_and_resolvectl() {
        let scutil = "DNS configuration\n\nresolver #1\n  search domain[0] : home.lan\n  nameserver[0] : 192.168.1.1\n  if_index : 15 (en0)\n\nresolver #2\n  domain   : corp.example\n  search domain[0] : corp.example\n  search domain[1] : eu.corp.example\n  nameserver[0] : 10.1.1.1\n  if_index : 22 (utun4)\n\nresolver #3\n  domain   : 10.in-addr.arpa\n  if_index : 22 (utun4)\n";
        assert_eq!(parse_scutil_dns(scutil), ["corp.example", "eu.corp.example"]);
        let resolvectl = "Global\n       Protocols: +LLMNR\n\nLink 2 (eth0)\n    DNS Domain: home.lan\n\nLink 7 (tun0)\n Current DNS Server: 10.8.0.1\n    DNS Domain: ~corp.example ~.\n                ~eu.corp.example\n";
        assert_eq!(parse_resolvectl(resolvectl), ["corp.example", "eu.corp.example"]);
        assert!(parse_scutil_dns("resolver #1\n  domain : x.example\n  if_index : 4 (en1)\n").is_empty());
    }
}
