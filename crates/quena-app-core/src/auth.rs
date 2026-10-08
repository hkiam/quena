//! Credential resolver: bridges AuthSettings + the OS secure store to the proxy.

use crate::AppCore;
use quena_auth::Credentials;
use quena_proxy::CredentialResolver;
use std::sync::Arc;

pub struct AppCredentials {
    core: Arc<AppCore>,
}

impl AppCredentials {
    pub fn new(core: Arc<AppCore>) -> AppCredentials {
        AppCredentials { core }
    }
}

fn account(host: &str, user: &str, domain: &str) -> String {
    format!("{host}|{domain}|{user}")
}

impl CredentialResolver for AppCredentials {
    fn credentials(&self, host: &str, _realm: &str) -> Option<Credentials> {
        let s = self.core.settings();
        let auth = &s.auth;
        // If SSO is preferred, returning None lets the proxy try Negotiate first
        // (the resolver is still consulted for the NTLM/Basic fallback).
        let host_l = host.to_ascii_lowercase();
        let cred = auth
            .credentials
            .iter()
            .find(|c| {
                c.host.eq_ignore_ascii_case(host) || quena_query::glob_match(&c.host, &host_l)
            })
            .or_else(|| auth.credentials.iter().find(|c| c.host == "*"))?;
        let password = if cred.has_password {
            quena_platform::secure::get(&account(&cred.host, &cred.user, &cred.domain))
                .ok()
                .flatten()
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default()
        } else {
            String::new()
        };
        Some(Credentials {
            user: cred.user.clone(),
            domain: cred.domain.clone(),
            password,
        })
    }
}

impl AppCore {
    /// Store a credential (password → secure store) and update settings.
    pub fn auth_set_credential(
        self: &Arc<Self>,
        host: String,
        user: String,
        domain: String,
        password: Option<String>,
    ) -> anyhow::Result<()> {
        let mut s = self.settings();
        let has_password = password.as_ref().is_some_and(|p| !p.is_empty());
        if let Some(p) = &password {
            if !p.is_empty() {
                quena_platform::secure::set(&account(&host, &user, &domain), p.as_bytes())
                    .map_err(|e| anyhow::anyhow!("secure store: {e}"))?;
            }
        }
        let cref = crate::settings::CredentialRef {
            host: host.clone(),
            user,
            domain,
            has_password,
        };
        if let Some(existing) = s
            .auth
            .credentials
            .iter_mut()
            .find(|c| c.host.eq_ignore_ascii_case(&host))
        {
            *existing = cref;
        } else {
            s.auth.credentials.push(cref);
        }
        self.update_settings(s)
    }

    pub fn auth_remove_credential(self: &Arc<Self>, host: String) -> anyhow::Result<()> {
        let mut s = self.settings();
        if let Some(pos) = s
            .auth
            .credentials
            .iter()
            .position(|c| c.host.eq_ignore_ascii_case(&host))
        {
            let c = s.auth.credentials.remove(pos);
            let _ = quena_platform::secure::delete(&account(&c.host, &c.user, &c.domain));
        }
        self.update_settings(s)
    }
}
