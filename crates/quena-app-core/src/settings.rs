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

/// Reverse proxy ports: each forwards everything to one target (they listen while capturing).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ReverseProxySettings {
    /// Master switch; off leaves every entry unused.
    pub enabled: bool,
    pub entries: Vec<ReverseProxyEntry>,
}

pub use quena_proxy::reverse::ClientProtocol;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct ReverseProxyEntry {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub listen_port: u16,
    /// Accept clients from other machines (still limited by `proxy.remoteAllowlist`).
    pub allow_remote: bool,
    pub client_protocol: ClientProtocol,
    /// `http(s)://host[:port][/base path]`
    pub target: String,
    pub preserve_host: bool,
    /// Certificate name for TLS clients without SNI (empty: `localhost`).
    pub tls_host: String,
    pub rewrite_location: bool,
    pub rewrite_cookie_domain: bool,
    pub forwarded_headers: bool,
    /// Other targets for some paths; the longest matching prefix wins.
    pub paths: Vec<ReversePathEntry>,
}

/// Requests whose path starts with `prefix` go to `target`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ReversePathEntry {
    /// `/auth`, `/api/v2` …
    pub prefix: String,
    /// `http(s)://host[:port][/base path]`
    pub target: String,
    /// Drop the prefix from the forwarded path.
    pub strip_prefix: bool,
}

/// A port of its own: SOCKS or transparent (listening while capturing).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct ListenerSettings {
    pub enabled: bool,
    pub port: u16,
    /// Accept clients from other machines (still limited by `proxy.remoteAllowlist`).
    pub allow_remote: bool,
}

impl ListenerSettings {
    fn with_port(port: u16) -> Self {
        ListenerSettings { enabled: false, port, allow_remote: false }
    }
    pub fn to_port(&self) -> Option<quena_proxy::listener::ExtraPort> {
        self.enabled.then_some(quena_proxy::listener::ExtraPort { port: self.port, allow_remote: self.allow_remote })
    }
}

/// Host remapping (Capture → Host Remapping…): connections to a host go elsewhere.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct HostRemapSettings {
    pub enabled: bool,
    pub entries: Vec<HostRemapEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct HostRemapEntry {
    pub id: String,
    pub enabled: bool,
    /// `api.example.com`, `*.example.com`
    pub host: String,
    /// `host`, `ip`, `host:port`
    pub target: String,
    /// Keep Host and TLS server name of the original host (only the connection moves).
    pub keep_host: bool,
    pub comment: String,
}

impl Default for HostRemapEntry {
    fn default() -> Self {
        HostRemapEntry { id: String::new(), enabled: true, host: String::new(), target: String::new(), keep_host: true, comment: String::new() }
    }
}

impl HostRemapSettings {
    /// The rules that apply (switched on, valid).
    pub fn rules(&self) -> Vec<quena_proxy::remap::HostRemap> {
        if !self.enabled {
            return vec![];
        }
        self.entries
            .iter()
            .filter(|e| e.enabled)
            .filter_map(|e| quena_proxy::remap::HostRemap::parse(&e.host, &e.target, e.keep_host).map_err(|err| tracing::warn!(target: "quena", "host remap {err}")).ok())
            .collect()
    }

    pub fn validate(&self) -> Result<(), String> {
        for e in &self.entries {
            quena_proxy::remap::HostRemap::parse(&e.host, &e.target, e.keep_host).map_err(|err| format!("host remapping: {err}"))?;
        }
        Ok(())
    }
}

/// Entries of a hosts file (`ip name …`), without localhost and comments.
pub fn parse_hosts_file(text: &str) -> Vec<HostRemapEntry> {
    let mut out: Vec<HostRemapEntry> = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut parts = line.split_whitespace();
        let Some(ip) = parts.next() else { continue };
        if ip.parse::<std::net::IpAddr>().is_err() {
            continue;
        }
        for name in parts {
            let name = name.to_ascii_lowercase();
            let local = name == "localhost" || name.ends_with(".localhost") || name == "broadcasthost" || name.starts_with("ip6-");
            if local || out.iter().any(|e| e.host == name) {
                continue;
            }
            out.push(HostRemapEntry { host: name, target: ip.to_string(), comment: "hosts file".into(), ..Default::default() });
        }
    }
    out
}

/// Protobuf schemas for gRPC and protobuf bodies (Settings → Bodies & Storage).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ProtobufSettings {
    /// `.proto` files, or folders searched for them.
    pub proto_paths: Vec<String>,
    /// Folders `import` statements are resolved against (besides the folders above).
    pub include_paths: Vec<String>,
    /// Offer to fetch schemas from gRPC servers (server reflection), on request.
    pub reflection: bool,
}

/// Default SOCKS port.
pub const SOCKS_PORT: u16 = 8868;
/// Default port for transparently redirected traffic.
pub const TRANSPARENT_PORT: u16 = 8869;

impl Default for ReverseProxyEntry {
    fn default() -> Self {
        ReverseProxyEntry {
            id: String::new(),
            name: String::new(),
            enabled: true,
            listen_port: 8080,
            allow_remote: false,
            client_protocol: ClientProtocol::Auto,
            target: String::new(),
            preserve_host: false,
            tls_host: String::new(),
            rewrite_location: true,
            rewrite_cookie_domain: false,
            forwarded_headers: false,
            paths: vec![],
        }
    }
}

impl ReverseProxyEntry {
    /// Display name: the name, else `:port`.
    pub fn label(&self) -> String {
        if self.name.trim().is_empty() { format!(":{}", self.listen_port) } else { self.name.trim().to_string() }
    }

    /// The proxy's view of the entry, or why it cannot be used.
    pub fn to_route(&self) -> Result<quena_proxy::reverse::ReverseRoute, String> {
        use quena_proxy::reverse::{PathRoute, Target, parse_prefix};
        let label = self.label();
        let target = Target::parse(&self.target).map_err(|e| format!("{label}: {e}"))?;
        let mut paths = Vec::new();
        for p in &self.paths {
            let prefix = parse_prefix(&p.prefix).map_err(|e| format!("{label}: {e}"))?;
            let t = Target::parse(&p.target).map_err(|e| format!("{label} {prefix}: {e}"))?;
            paths.push(PathRoute { prefix, target: t, strip_prefix: p.strip_prefix });
        }
        let tls_host = self.tls_host.trim();
        Ok(quena_proxy::reverse::ReverseRoute {
            id: self.id.clone(),
            name: label,
            port: self.listen_port,
            allow_remote: self.allow_remote,
            client_protocol: self.client_protocol,
            target,
            paths,
            preserve_host: self.preserve_host,
            tls_host: if tls_host.is_empty() { "localhost".into() } else { tls_host.to_string() },
            rewrite_location: self.rewrite_location,
            rewrite_cookie_domain: self.rewrite_cookie_domain,
            forwarded_headers: self.forwarded_headers,
        })
    }
}

impl ReverseProxySettings {
    /// Entries that listen while capturing.
    pub fn active(&self) -> impl Iterator<Item = &ReverseProxyEntry> {
        self.entries.iter().filter(move |e| self.enabled && e.enabled)
    }

    /// Check the entries against each other and the other ports Quena uses (`taken`: port
    /// and what uses it).
    pub fn validate(&self, taken: &[(u16, &str)]) -> Result<(), String> {
        let mut seen: std::collections::HashMap<u16, String> = taken.iter().map(|(p, n)| (*p, n.to_string())).collect();
        for e in &self.entries {
            e.to_route()?;
            if e.listen_port == 0 {
                return Err(format!("{}: the port must not be 0", e.label()));
            }
            // Ports only matter for entries that listen.
            if !self.enabled || !e.enabled {
                continue;
            }
            if let Some(other) = seen.insert(e.listen_port, e.label()) {
                return Err(format!("{} and {other} both use port {}", e.label(), e.listen_port));
            }
        }
        Ok(())
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
    /// TLS key log (`SSLKEYLOGFILE`, NSS format) used to decrypt packet captures; empty: none.
    #[serde(default)]
    pub tls_key_log_file: String,
    /// Flag sessions whose server certificate expires within this many days (0: off).
    #[serde(default = "default_cert_warn_days")]
    pub cert_warn_days: u32,
}

fn default_cert_warn_days() -> u32 {
    30
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
            tls_key_log_file: String::new(),
            cert_warn_days: default_cert_warn_days(),
        }
    }
}

/// What happens to the sessions in the list when an archive or capture is imported.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub enum ImportExisting {
    #[default]
    Ask,
    Remove,
    Keep,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub proxy: ProxySettings,
    /// Reverse proxy ports (Capture → Reverse Proxy…).
    #[serde(default)]
    pub reverse_proxy: ReverseProxySettings,
    /// SOCKS5/4 port (Settings → Connections).
    #[serde(default = "default_socks")]
    pub socks: ListenerSettings,
    /// Port for transparently redirected traffic (Settings → Connections).
    #[serde(default = "default_transparent")]
    pub transparent: ListenerSettings,
    /// Host remapping (Capture → Host Remapping…).
    #[serde(default)]
    pub host_remap: HostRemapSettings,
    /// Protobuf schemas (`.proto` files) for gRPC and protobuf bodies.
    #[serde(default)]
    pub protobuf: ProtobufSettings,
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
    /// Importing into a non-empty list: ask, or remove or keep its sessions.
    #[serde(default)]
    pub import_existing: ImportExisting,
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
    /// Remote control by AI agents (MCP server on 127.0.0.1).
    #[serde(default)]
    pub mcp: McpSettings,
    /// Opaque UI preferences (column layout, splitters …).
    pub ui: serde_json::Value,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            proxy: ProxySettings::default(),
            reverse_proxy: ReverseProxySettings::default(),
            socks: default_socks(),
            transparent: default_transparent(),
            host_remap: HostRemapSettings::default(),
            protobuf: ProtobufSettings::default(),
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
            import_existing: ImportExisting::Ask,
            auth: AuthSettings::default(),
            scripting_enabled: false,
            throttle_kbps: 0,
            throttle_latency_ms: 0,
            sanitize: Default::default(),
            mcp: McpSettings::default(),
            ui: serde_json::Value::Null,
        }
    }
}

/// What an MCP client may do.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub enum McpAccess {
    /// Read sessions, bodies, rules and statistics only.
    #[default]
    ReadOnly,
    /// Also change rules and breakpoints, capture, send and replay requests, export.
    Full,
}

/// The MCP server (Streamable HTTP on `127.0.0.1:port/mcp`, bearer token).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct McpSettings {
    pub enabled: bool,
    pub port: u16,
    pub access: McpAccess,
    /// Bearer token clients must send; generated when the server is first enabled.
    pub token: String,
    /// Hand captured credentials (Authorization, cookies, tokens, secret parameters and
    /// fields) to agents as they are. Off: they are replaced before anything leaves Quena.
    pub include_secrets: bool,
    /// The only folder agents may read files from and write files to (exports, `.http`
    /// collections, mock rule files). Empty: `mcp-files` in the data folder.
    pub files_dir: String,
}

impl Default for McpSettings {
    fn default() -> Self {
        McpSettings { enabled: false, port: 8867, access: McpAccess::ReadOnly, token: String::new(), include_secrets: false, files_dir: String::new() }
    }
}

impl McpSettings {
    /// The folder agents may use (see [`McpSettings::files_dir`]).
    pub fn files_folder(&self, data: &Path) -> std::path::PathBuf {
        match self.files_dir.trim() {
            "" => data.join("mcp-files"),
            d => std::path::PathBuf::from(d),
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

fn default_socks() -> ListenerSettings {
    ListenerSettings::with_port(SOCKS_PORT)
}

fn default_transparent() -> ListenerSettings {
    ListenerSettings::with_port(TRANSPARENT_PORT)
}

impl Default for ListenerSettings {
    fn default() -> Self {
        ListenerSettings::with_port(0)
    }
}

impl Settings {
    /// Ports of Quena's listeners must differ: the proxy, MCP, SOCKS, transparent and the
    /// reverse proxy entries.
    pub fn validate_ports(&self) -> Result<(), String> {
        let mut taken: Vec<(u16, &str)> = vec![(self.proxy.port, "the proxy port")];
        if self.mcp.enabled {
            taken.push((self.mcp.port, "the MCP server's port"));
        }
        for (l, name) in [(&self.socks, "the SOCKS port"), (&self.transparent, "the transparent port")] {
            if !l.enabled {
                continue;
            }
            if l.port == 0 {
                return Err(format!("{name} must not be 0"));
            }
            if let Some((_, other)) = taken.iter().find(|(p, _)| *p == l.port) {
                return Err(format!("port {} is {other} and cannot be {name}", l.port));
            }
            taken.push((l.port, name));
        }
        self.reverse_proxy.validate(&taken).map_err(|e| format!("reverse proxy: {e}"))
    }

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
