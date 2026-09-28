use piper_body::BodyConfig;
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
    /// Chain to the system proxy that was active before Piper took over.
    pub use_system_upstream: bool,
    /// Manual upstream proxy `host:port` (overrides system upstream).
    pub manual_upstream: String,
    /// Hosts that bypass the upstream proxy.
    pub upstream_bypass: String,
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
    /// Fiddler "Stream" toggle: stream responses to the client (default) or buffer them.
    pub stream: bool,
    /// Fiddler "Decode" toggle: show decoded bodies by default.
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
            inline_limit: (self.inline_limit_kb.max(1) * 1024) as usize,
            max_recorded_body: self.max_recorded_body_mb << 20,
            quota: self.quota_gb.max(1) << 30,
            min_free_space: self.min_free_space_gb << 30,
            max_derived: self.max_derived_gb.max(1) << 30,
            max_ratio: self.max_ratio.max(10),
        }
    }
}

impl Settings {
    pub fn load(path: &Path) -> Settings {
        match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_else(|e| {
                tracing::warn!("settings unreadable, using defaults: {e}");
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
