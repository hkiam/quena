//! Hosts that do not go through Quena: entered by the user, Apple services that pin their
//! certificates (they fail behind any intercepting proxy), and the domains of a VPN. They
//! become exceptions of the system proxy and of browsers and terminals Quena starts; a client
//! that sends them to Quena anyway gets them passed through without decryption.

use crate::settings::Settings;

/// Apple services known to pin their certificates.
pub const APPLE_PINNED: &[&str] = &["*.push.apple.com", "*.ess.apple.com", "gs.apple.com", "albert.apple.com", "identity.apple.com", "*.apple-cloudkit.com", "*.icloud.com", "*.mzstatic.com", "itunes.apple.com"];

/// The hosts to keep away from Quena (`host`, `*.domain`), for these settings.
pub fn hosts(s: &Settings) -> Vec<String> {
    hosts_with(s, quena_platform::vpn_domains)
}

pub fn hosts_with(s: &Settings, vpn: impl FnOnce() -> Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |h: &str| {
        let h = h.trim().to_ascii_lowercase();
        if !h.is_empty() && !out.contains(&h) {
            out.push(h);
        }
    };
    for h in s.proxy.bypass_hosts.split([';', ',', '\n', ' ']) {
        add(h);
    }
    if s.proxy.bypass_apple {
        APPLE_PINNED.iter().for_each(|h| add(h));
    }
    if s.proxy.bypass_vpn {
        for d in vpn() {
            add(&format!("*.{d}"));
            add(&d);
        }
    }
    out
}

/// `NO_PROXY` form: `*.example.com` → `.example.com`.
pub fn no_proxy(hosts: &[String]) -> String {
    hosts.iter().map(|h| h.strip_prefix('*').unwrap_or(h).to_string()).collect::<Vec<_>>().join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_from_settings() {
        let mut s = Settings::default();
        s.proxy.bypass_hosts = "login.example.com; *.Bank.example ,login.example.com".into();
        s.proxy.bypass_apple = false;
        assert_eq!(hosts_with(&s, Vec::new), ["login.example.com", "*.bank.example"]);
        s.proxy.bypass_apple = true;
        s.proxy.bypass_vpn = true;
        let h = hosts_with(&s, || vec!["corp.example".into()]);
        assert!(h.contains(&"*.push.apple.com".to_string()) && h.contains(&"*.corp.example".to_string()) && h.contains(&"corp.example".to_string()));
        assert_eq!(no_proxy(&["*.a.example".into(), "b.example".into()]), ".a.example,b.example");
    }
}
