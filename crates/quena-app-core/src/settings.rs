use quena_body::BodyConfig;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct ProxySettings {
    pub port: u16,
    /// Listen on all interfaces ("Allow remote computers to connect").
    pub allow_remote: bool,
    /// Allowed remote client networks (CIDR or IPs, `;` separated). Empty = local subnets.
    pub remote_allowlist: String,
    /// Set the macOS system proxy while capturing.
    pub act_as_system_proxy: bool,
    pub capture_on_startup: bool,
    /// Chain to the system proxy that was active before Quena took over.
    pub use_system_upstream: bool,
    /// Manual upstream proxy `host:port` (overrides system upstream).
    pub manual_upstream: String,
    /// Hosts that bypass the upstream proxy.
    pub upstream_bypass: String,
    /// Use the system-detected proxy auto-config (PAC) script for upstream selection.
    pub use_system_pac: bool,
    /// Manual PAC URL or file path (overrides the system PAC when non-empty).
    pub pac_url: String,
}

impl Default for ProxySettings {
    fn default() -> Self {
        ProxySettings {
            port: 8866,
            allow_remote: false,
            remote_allowlist: String::new(),
            act_as_system_proxy: true,
            capture_on_startup: true,
            use_system_upstream: true,
            manual_upstream: String::new(),
            upstream_bypass: "localhost;127.0.0.1;::1;*.local".into(),
            use_system_pac: true,
            pac_url: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub enum DecryptScope {
    #[default]
    All,
    Browsers,
    NonBrowsers,
    Remote,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct HttpsSettings {
    pub decrypt: bool,
    pub scope: DecryptScope,
    /// Hosts never decrypted (`;` separated, wildcards).
    pub skip_decryption: String,
    pub ignore_cert_errors: bool,
    /// Hosts for which upstream certificate errors are ignored.
    pub ignore_cert_errors_hosts: String,
    pub enable_http2: bool,
    /// Hosts for which HTTP/2 is downgraded to HTTP/1.1.
    pub http2_downgrade_hosts: String,
    /// Client certificates (mTLS) presented to matching upstream hosts.
    #[serde(default)]
    pub client_certs: Vec<ClientCert>,
}

/// A client certificate (mTLS) for hosts matching `host` (glob).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ClientCert {
    /// Host pattern this certificate is presented to (e.g. `*.corp.example`).
    pub host: String,
    /// Path to the certificate chain (PEM).
    pub cert_path: String,
    /// Path to the private key (PEM). May be the same file as the chain.
    pub key_path: String,
}

impl Default for HttpsSettings {
    fn default() -> Self {
        HttpsSettings {
            decrypt: false,
            scope: DecryptScope::All,
            skip_decryption: String::new(),
            ignore_cert_errors: false,
            ignore_cert_errors_hosts: String::new(),
            enable_http2: true,
            http2_downgrade_hosts: String::new(),
            client_certs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub proxy: ProxySettings,
    pub https: HttpsSettings,
    pub bodies: BodyConfigDto,
    /// "Keep: N sessions" (0 = all).
    pub keep_sessions: usize,
    /// "Stream" toggle: stream responses to the client (default) or buffer them.
    pub stream: bool,
    /// "Decode" toggle: show decoded bodies by default.
    pub decode: bool,
    /// Record only headers for these hosts/content types (`;` separated).
    pub headers_only_hosts: String,
    pub headers_only_types: String,
    /// Forwarding waits for the recorder instead of truncating when it falls behind.
    pub lossless_recording: bool,
    /// Keep temporary captures after a clean exit.
    pub keep_captures: bool,
    /// Offer to restore captures after a crash.
    pub offer_recovery: bool,
    pub auth: AuthSettings,
    /// Enable the JavaScript rules script (M14).
    pub scripting_enabled: bool,
    /// Simulated bandwidth cap in kilobits/s (0 = unlimited).
    #[serde(default)]
    pub throttle_kbps: u64,
    /// Extra latency added before each response, in milliseconds (0 = none).
    #[serde(default)]
    pub throttle_latency_ms: u64,
    /// Last options of the sanitized export.
    #[serde(default)]
    pub sanitize: crate::sanitize::SanitizeExportSettings,
    /// Opaque UI preferences (column layout, splitters …).
    pub ui: serde_json::Value,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            proxy: ProxySettings::default(),
            https: HttpsSettings::default(),
            bodies: BodyConfigDto::default(),
            keep_sessions: 0,
            stream: true,
            decode: true,
            headers_only_hosts: String::new(),
            headers_only_types: String::new(),
            lossless_recording: false,
            keep_captures: false,
            offer_recovery: true,
            auth: AuthSettings::default(),
            scripting_enabled: false,
            throttle_kbps: 0,
            throttle_latency_ms: 0,
            sanitize: Default::default(),
            ui: serde_json::Value::Null,
        }
    }
}

/// Body limits as exposed in the UI (MB / GB granularity).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct BodyConfigDto {
    pub inline_limit_kb: u64,
    pub max_recorded_body_mb: u64,
    pub quota_gb: u64,
    pub min_free_space_gb: u64,
    pub max_derived_gb: u64,
    pub max_ratio: u64,
}

impl Default for BodyConfigDto {
    fn default() -> Self {
        let d = BodyConfig::default();
        BodyConfigDto {
            inline_limit_kb: (d.inline_limit / 1024) as u64,
            max_recorded_body_mb: d.max_recorded_body >> 20,
            quota_gb: d.quota >> 30,
            min_free_space_gb: d.min_free_space >> 30,
            max_derived_gb: d.max_derived >> 30,
            max_ratio: d.max_ratio,
        }
    }
}

impl BodyConfigDto {
    pub fn to_config(&self) -> BodyConfig {
        BodyConfig {
            // Clamped: hand-edited or damaged settings must not overflow into tiny limits.
            inline_limit: (self.inline_limit_kb.clamp(1, 1 << 20) * 1024) as usize,
            max_recorded_body: self.max_recorded_body_mb.min(1 << 30) << 20,
            quota: self.quota_gb.clamp(1, 1 << 20) << 30,
            min_free_space: self.min_free_space_gb.min(1 << 20) << 30,
            max_derived: self.max_derived_gb.clamp(1, 1 << 20) << 30,
            max_ratio: self.max_ratio.max(10),
        }
    }
}

impl Settings {
    pub fn load(path: &Path) -> Settings {
        match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_else(|e| {
                // Keep the damaged file: the next save would otherwise overwrite it for good.
                let aside = crate::keep_corrupt(path);
                tracing::warn!("settings unreadable ({e}); using defaults, the old file was kept as {aside}");
                Settings::default()
            }),
            Err(_) => Settings::default(),
        }
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self).expect("settings json"))?;
        std::fs::rename(tmp, path)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct AuthSettings {
    /// Enable Automatic Authentication (Rules menu).
    pub enabled: bool,
    /// Hosts for which it runs (";"-separated, wildcards; empty = all).
    pub hosts: String,
    /// Also answer 407 from the upstream proxy.
    pub upstream: bool,
    /// Prefer the current OS identity (Kerberos/SSPI SSO) before stored credentials.
    pub use_current_identity: bool,
    /// Scheme order, "negotiate;ntlm;basic".
    pub prefer: String,
    /// Configured accounts (passwords live in the OS secure store).
    pub credentials: Vec<CredentialRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct CredentialRef {
    /// Host or realm this applies to ("*" = default).
    pub host: String,
    pub user: String,
    pub domain: String,
    /// Whether a password is stored for it (never the password itself).
    pub has_password: bool,
}

impl Default for AuthSettings {
    fn default() -> Self {
        AuthSettings {
            enabled: false,
            hosts: String::new(),
            upstream: false,
            use_current_identity: true,
            prefer: "negotiate;ntlm;basic".into(),
            credentials: vec![],
        }
    }
}
