//! WASM component plugin host.
//!
//! * discovery: `<dir>/<plugin>/plugin.toml` + component `.wasm`
//! * API: `wit/plugin.wit`, versioned: body decoders (world `plugin`, streaming
//!   sessions) and header inspectors (world `header-plugin`, one value per call);
//!   and analyzers (world `analyzer-plugin`, a whole capture streamed in batches);
//!   the manifest section `[decoder]` / `[header_inspector]` / `[analyzer]` selects the world
//! * isolation: fresh store per decoding run, no preopened directories,
//!   no network, no environment, memory limit, execution deadline
//! * a trapping or misbehaving plugin only fails its own run

use anyhow::{Context, Result, anyhow};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

mod decoder_world {
    wasmtime::component::bindgen!({
        path: "../../wit/plugin.wit",
        world: "plugin",
    });
}

mod header_world {
    wasmtime::component::bindgen!({
        path: "../../wit/plugin.wit",
        world: "header-plugin",
    });
}

mod analyzer_world {
    wasmtime::component::bindgen!({
        path: "../../wit/plugin.wit",
        world: "analyzer-plugin",
    });
}

use analyzer_world::exports::quena::plugin::analyzer::{
    AuthInfo as WitAuthInfo, Info as AnalyzerInfo, JwtClaims as WitJwtClaims, OauthRequest as WitOauthRequest, OauthResponse as WitOauthResponse, OidcDiscovery as WitOidcDiscovery,
    Session as WitSession, TextInfo as WitTextInfo, Timers as WitTimers,
};
use analyzer_world::{AnalyzerPlugin, AnalyzerPluginPre};
use decoder_world::exports::quena::plugin::decoder::{Info as DecoderInfo, Representation};
use decoder_world::{Plugin, PluginPre};
use header_world::exports::quena::plugin::header_inspector::{Info as HeaderInfo, NodeKind};
use header_world::{HeaderPlugin, HeaderPluginPre};

pub const API_VERSION: &str = "1";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DecoderManifest {
    #[serde(default)]
    pub mime_types: Vec<String>,
    #[serde(default)]
    pub extensions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HeaderInspectorManifest {
    /// Header names (case-insensitive) the plugin is asked about; empty = all.
    #[serde(default)]
    pub headers: Vec<String>,
}

/// `[analyzer]` section (no keys yet; an empty table marks the plugin as an analyzer).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AnalyzerManifest {}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Manifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub api_version: String,
    /// Component file relative to the manifest (default: first `.wasm`).
    pub wasm: Option<String>,
    pub decoder: Option<DecoderManifest>,
    pub header_inspector: Option<HeaderInspectorManifest>,
    pub analyzer: Option<AnalyzerManifest>,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PluginKind {
    Decoder,
    HeaderInspector,
    Analyzer,
}

/// Session timers passed to an analyzer (mirrors `timers` of the `analyzer` interface):
/// microseconds since the Unix epoch, durations in milliseconds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnalyzerTimers {
    pub client_begin_request: Option<u64>,
    pub client_done_request: Option<u64>,
    pub server_connect_start: Option<u64>,
    pub server_connected: Option<u64>,
    pub server_begin_request: Option<u64>,
    pub server_done_request: Option<u64>,
    pub server_got_first_byte: Option<u64>,
    pub server_done_response: Option<u64>,
    pub client_done_response: Option<u64>,
    pub dns_ms: Option<u32>,
    pub tcp_connect_ms: Option<u32>,
    pub tls_handshake_ms: Option<u32>,
}

/// Encoding facts of a textual body (mirrors `text-info` of the `analyzer` interface).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnalyzerTextInfo {
    pub header_charset: Option<String>,
    pub header_resolved: Option<String>,
    pub document_charset: Option<String>,
    pub document_resolved: Option<String>,
    pub bom: Option<String>,
    pub effective: String,
    pub source: String,
    pub unknown_label: bool,
    pub sampled: u64,
    pub non_ascii: bool,
    pub utf8_valid: bool,
    pub decode_errors: u32,
    pub replacement_chars: u32,
    pub double_encoded: u32,
    pub nul_bytes: u32,
    pub looks_compressed: Option<String>,
}

impl From<AnalyzerTextInfo> for WitTextInfo {
    fn from(t: AnalyzerTextInfo) -> WitTextInfo {
        WitTextInfo {
            header_charset: t.header_charset,
            header_resolved: t.header_resolved,
            document_charset: t.document_charset,
            document_resolved: t.document_resolved,
            bom: t.bom,
            effective: t.effective,
            source: t.source,
            unknown_label: t.unknown_label,
            sampled: t.sampled,
            non_ascii: t.non_ascii,
            utf8_valid: t.utf8_valid,
            decode_errors: t.decode_errors,
            replacement_chars: t.replacement_chars,
            double_encoded: t.double_encoded,
            nul_bytes: t.nul_bytes,
            looks_compressed: t.looks_compressed,
        }
    }
}

/// Non-secret claims of a JSON Web Token (mirrors `jwt-claims` of the `analyzer` interface).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnalyzerJwtClaims {
    pub alg: String,
    pub typ: Option<String>,
    pub iss: Option<String>,
    pub aud: Vec<String>,
    pub exp: Option<u64>,
    pub nbf: Option<u64>,
    pub iat: Option<u64>,
    pub client: Option<String>,
    pub tenant: Option<String>,
    pub ver: Option<String>,
    pub scopes: Vec<String>,
    pub roles: Vec<String>,
    pub groups: Option<u32>,
    pub groups_overage: bool,
    pub size: u32,
}

impl From<AnalyzerJwtClaims> for WitJwtClaims {
    fn from(c: AnalyzerJwtClaims) -> WitJwtClaims {
        WitJwtClaims {
            alg: c.alg,
            typ: c.typ,
            iss: c.iss,
            aud: c.aud,
            exp: c.exp,
            nbf: c.nbf,
            iat: c.iat,
            client: c.client,
            tenant: c.tenant,
            ver: c.ver,
            scopes: c.scopes,
            roles: c.roles,
            groups: c.groups,
            groups_overage: c.groups_overage,
            size: c.size,
        }
    }
}

/// An OAuth token-endpoint request, facts only (mirrors `oauth-request`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnalyzerOauthRequest {
    pub grant_type: Option<String>,
    pub client_id: Option<String>,
    pub scope: Option<String>,
    pub redirect_uri: Option<String>,
    pub has_code: bool,
    pub has_code_verifier: bool,
    pub has_refresh_token: bool,
    pub has_client_secret: bool,
    pub has_client_assertion: bool,
    pub basic_client_auth: bool,
}

impl From<AnalyzerOauthRequest> for WitOauthRequest {
    fn from(r: AnalyzerOauthRequest) -> WitOauthRequest {
        WitOauthRequest {
            grant_type: r.grant_type,
            client_id: r.client_id,
            scope: r.scope,
            redirect_uri: r.redirect_uri,
            has_code: r.has_code,
            has_code_verifier: r.has_code_verifier,
            has_refresh_token: r.has_refresh_token,
            has_client_secret: r.has_client_secret,
            has_client_assertion: r.has_client_assertion,
            basic_client_auth: r.basic_client_auth,
        }
    }
}

/// An OAuth/OIDC JSON response, facts only (mirrors `oauth-response`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnalyzerOauthResponse {
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub error_codes: Vec<u32>,
    pub error_uri: Option<String>,
    pub trace_id: Option<String>,
    pub correlation_id: Option<String>,
    pub token_type: Option<String>,
    pub expires_in: Option<u32>,
    pub has_access_token: bool,
    pub has_refresh_token: bool,
    pub has_id_token: bool,
    pub scope: Option<String>,
    pub access_token: Option<AnalyzerJwtClaims>,
    pub id_token: Option<AnalyzerJwtClaims>,
}

impl From<AnalyzerOauthResponse> for WitOauthResponse {
    fn from(r: AnalyzerOauthResponse) -> WitOauthResponse {
        WitOauthResponse {
            error: r.error,
            error_description: r.error_description,
            error_codes: r.error_codes,
            error_uri: r.error_uri,
            trace_id: r.trace_id,
            correlation_id: r.correlation_id,
            token_type: r.token_type,
            expires_in: r.expires_in,
            has_access_token: r.has_access_token,
            has_refresh_token: r.has_refresh_token,
            has_id_token: r.has_id_token,
            scope: r.scope,
            access_token: r.access_token.map(Into::into),
            id_token: r.id_token.map(Into::into),
        }
    }
}

/// An OpenID Connect discovery document (mirrors `oidc-discovery`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnalyzerOidcDiscovery {
    pub issuer: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub end_session_endpoint: Option<String>,
}

impl From<AnalyzerOidcDiscovery> for WitOidcDiscovery {
    fn from(d: AnalyzerOidcDiscovery) -> WitOidcDiscovery {
        WitOidcDiscovery {
            issuer: d.issuer,
            authorization_endpoint: d.authorization_endpoint,
            token_endpoint: d.token_endpoint,
            jwks_uri: d.jwks_uri,
            end_session_endpoint: d.end_session_endpoint,
        }
    }
}

/// Authentication facts of a session (mirrors `auth-info` of the `analyzer` interface).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnalyzerAuthInfo {
    pub bearer: Option<AnalyzerJwtClaims>,
    pub opaque_bearer: Option<u32>,
    pub oauth_request: Option<AnalyzerOauthRequest>,
    pub oauth_response: Option<AnalyzerOauthResponse>,
    pub discovery: Option<AnalyzerOidcDiscovery>,
}

impl From<AnalyzerAuthInfo> for WitAuthInfo {
    fn from(a: AnalyzerAuthInfo) -> WitAuthInfo {
        WitAuthInfo {
            bearer: a.bearer.map(Into::into),
            opaque_bearer: a.opaque_bearer,
            oauth_request: a.oauth_request.map(Into::into),
            oauth_response: a.oauth_response.map(Into::into),
            discovery: a.discovery.map(Into::into),
        }
    }
}

/// One session record for an analyzer (mirrors `session` of the `analyzer` interface), so
/// callers do not depend on wasmtime types. Headers must already be allow-listed and
/// redacted (plugins/webdiag/REPORT.md).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnalyzerSession {
    pub id: u64,
    /// `http`, `tunnel` or `websocket`.
    pub kind: String,
    pub started: u64,
    pub duration_ms: Option<u32>,
    pub method: String,
    pub url: String,
    pub host: String,
    pub version: String,
    pub status: u16,
    pub error: Option<String>,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub response_decoded_bytes: u64,
    pub content_type: String,
    pub request_headers: Vec<(String, String)>,
    pub response_headers: Vec<(String, String)>,
    pub timers: AnalyzerTimers,
    pub client_connection: Option<u64>,
    pub server_connection_reused: bool,
    pub tls_version: Option<String>,
    pub process: String,
    pub request_body_hash: Option<u64>,
    pub response_body_hash: Option<u64>,
    pub request_text: Option<AnalyzerTextInfo>,
    pub response_text: Option<AnalyzerTextInfo>,
    pub request_decoding_error: Option<String>,
    pub response_decoding_error: Option<String>,
    /// OAuth / OpenID Connect facts (none when the session has nothing of that kind).
    pub auth: Option<AnalyzerAuthInfo>,
}

impl From<AnalyzerSession> for WitSession {
    fn from(s: AnalyzerSession) -> WitSession {
        let t = s.timers;
        WitSession {
            id: s.id,
            kind: s.kind,
            started: s.started,
            duration_ms: s.duration_ms,
            method: s.method,
            url: s.url,
            host: s.host,
            version: s.version,
            status: s.status,
            error: s.error,
            request_bytes: s.request_bytes,
            response_bytes: s.response_bytes,
            response_decoded_bytes: s.response_decoded_bytes,
            content_type: s.content_type,
            request_headers: s.request_headers,
            response_headers: s.response_headers,
            timers: WitTimers {
                client_begin_request: t.client_begin_request,
                client_done_request: t.client_done_request,
                server_connect_start: t.server_connect_start,
                server_connected: t.server_connected,
                server_begin_request: t.server_begin_request,
                server_done_request: t.server_done_request,
                server_got_first_byte: t.server_got_first_byte,
                server_done_response: t.server_done_response,
                client_done_response: t.client_done_response,
                dns_ms: t.dns_ms,
                tcp_connect_ms: t.tcp_connect_ms,
                tls_handshake_ms: t.tls_handshake_ms,
            },
            client_connection: s.client_connection,
            server_connection_reused: s.server_connection_reused,
            tls_version: s.tls_version,
            process: s.process,
            request_body_hash: s.request_body_hash,
            response_body_hash: s.response_body_hash,
            request_text: s.request_text.map(Into::into),
            response_text: s.response_text.map(Into::into),
            request_decoding_error: s.request_decoding_error,
            response_decoding_error: s.response_decoding_error,
            auth: s.auth.map(Into::into),
        }
    }
}

/// One line of a header inspection (see `node` in `wit/plugin.wit`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InspectNode {
    pub depth: u8,
    /// `section`, `field`, `note` or `code`.
    pub kind: &'static str,
    pub name: String,
    pub value: String,
}

/// Result of one header inspector for one header value.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HeaderInspection {
    pub plugin_id: String,
    pub tab: String,
    pub confidence: u8,
    pub nodes: Vec<InspectNode>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Output {
    Text,
    Xml,
    Json,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginInfo {
    pub index: u16,
    pub id: String,
    pub name: String,
    pub version: String,
    pub tab: String,
    pub output: Output,
    pub enabled: bool,
    pub status: String,
    pub error: Option<String>,
    pub path: String,
    pub kind: PluginKind,
    pub mime_types: Vec<String>,
    /// Header names of a header inspector.
    pub headers: Vec<String>,
}

/// Resource limits per decoding run.
#[derive(Debug, Clone)]
pub struct Limits {
    pub memory: usize,
    /// Wall-clock budget per call into the plugin.
    pub call_timeout: Duration,
    /// Maximum output size of one run.
    pub max_output: u64,
    /// Maximum text (names + values) of one header inspection.
    pub max_inspect_output: usize,
    /// Wall-clock budget of an analyzer's `finish` (the report is built there).
    pub finish_timeout: Duration,
    /// Maximum size of an analyzer report (and of `describe`).
    pub max_report: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { memory: 512 << 20, call_timeout: Duration::from_secs(10), max_output: 16 << 30, max_inspect_output: 4 << 20, finish_timeout: Duration::from_secs(60), max_report: 64 << 20 }
    }
}

struct State {
    wasi: WasiCtx,
    table: ResourceTable,
    limits: StoreLimits,
    /// Wall-clock end of the current call when the deadline is checked in slices
    /// (interruptible analyzer runs, see [`PluginHost::analyze_interruptible`]).
    call_end: Option<Instant>,
}

impl WasiView for State {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView { ctx: &mut self.wasi, table: &mut self.table }
    }
}

struct Loaded {
    manifest: Manifest,
    dir: PathBuf,
    kind: PluginKind,
    /// Decoder plugins.
    pre: Option<PluginPre<State>>,
    info: Option<DecoderInfo>,
    /// Header inspector plugins.
    header: Option<(HeaderPluginPre<State>, HeaderInfo)>,
    /// Analyzer plugins.
    analyzer: Option<(AnalyzerPluginPre<State>, AnalyzerInfo)>,
    enabled: AtomicBool,
    error: Option<String>,
}

impl Loaded {
    /// (name, version, tab) as reported by the plugin, or from the manifest if it failed to load.
    fn labels(&self) -> (&str, &str, &str) {
        match (&self.info, &self.header, &self.analyzer) {
            (Some(i), _, _) => (&i.name, &i.version, &i.tab),
            (_, Some((_, i)), _) => (&i.name, &i.version, &i.tab),
            (_, _, Some((_, i))) => (&i.name, &i.version, &i.title),
            _ => (&self.manifest.name, &self.manifest.version, &self.manifest.name),
        }
    }
}

pub struct PluginHost {
    engine: Engine,
    linker: Linker<State>,
    plugins: RwLock<Vec<Arc<Loaded>>>,
    dirs: Vec<PathBuf>,
    limits: Limits,
    disabled_file: PathBuf,
    /// Compiled components (`<sha256 of wasm + engine>.cwasm`), so a plugin is compiled
    /// once instead of at every start.
    cache_dir: PathBuf,
}

/// Ticks per call deadline (the ticker increments the epoch every 10 ms).
const TICK: Duration = Duration::from_millis(10);

fn ticks(d: Duration) -> u64 {
    (d.as_millis() / TICK.as_millis()).max(1) as u64
}

/// How often an interruptible analyzer call checks its cancel flag (in ticks).
const INTERRUPT_SLICE: u64 = 5;

/// Arm the deadline of the next call: `budget` wall-clock time; with a slice callback
/// installed ([`PluginHost::analyze_interruptible`]) the epoch fires every
/// [`INTERRUPT_SLICE`] ticks and the callback enforces `budget`.
fn arm(store: &mut Store<State>, budget: Duration, sliced: bool) {
    if sliced {
        store.data_mut().call_end = Some(Instant::now() + budget);
        store.set_epoch_deadline(INTERRUPT_SLICE.min(ticks(budget)));
    } else {
        store.set_epoch_deadline(ticks(budget));
    }
}

impl PluginHost {
    /// `dirs`: plugin search paths; `state_dir`: where enable/disable state and the compiled
    /// plugins are kept.
    pub fn new(dirs: Vec<PathBuf>, state_dir: &Path) -> Result<Arc<PluginHost>> {
        Self::with_cache(dirs, state_dir, state_dir.join("plugin-cache"))
    }

    /// Like [`PluginHost::new`], with the compiled plugins in `cache_dir` (which several
    /// processes may share).
    pub fn with_cache(dirs: Vec<PathBuf>, state_dir: &Path, cache_dir: PathBuf) -> Result<Arc<PluginHost>> {
        let mut cfg = Config::new();
        cfg.wasm_component_model(true);
        cfg.epoch_interruption(true);
        let engine = Engine::new(&cfg).map_err(|e| anyhow!("{e}"))?;
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker).map_err(|e| anyhow!("{e}"))?;
        let e2 = engine.clone();
        // The deadline is counted in epoch ticks, so the ticker must follow wall-clock
        // time: `sleep(TICK)` can take several times longer on a loaded machine, which
        // would silently stretch the call timeout. Catch up on missed ticks instead.
        std::thread::Builder::new()
            .name("quena-wasm-epoch".into())
            .spawn(move || {
                let start = std::time::Instant::now();
                let mut ticks = 0u64;
                loop {
                    std::thread::sleep(TICK);
                    let due = (start.elapsed().as_millis() / TICK.as_millis()) as u64;
                    while ticks < due {
                        e2.increment_epoch();
                        ticks += 1;
                    }
                }
            })
            .context("epoch ticker")?;
        let host = Arc::new(PluginHost {
            engine,
            linker,
            plugins: RwLock::new(vec![]),
            dirs,
            limits: Limits::default(),
            disabled_file: state_dir.join("plugins-disabled.json"),
            cache_dir,
        });
        host.discover();
        Ok(host)
    }

    fn disabled_ids(&self) -> Vec<String> {
        std::fs::read(&self.disabled_file).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    /// (Re)scan the plugin directories.
    pub fn discover(&self) {
        let disabled = self.disabled_ids();
        let mut found = Vec::new();
        for d in &self.dirs {
            let Ok(rd) = std::fs::read_dir(d) else { continue };
            let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).filter(|p| p.join("plugin.toml").exists()).collect();
            entries.sort();
            for dir in entries {
                match self.load(&dir) {
                    Ok(l) => {
                        if found.iter().any(|x: &Arc<Loaded>| x.manifest.id == l.manifest.id) {
                            continue; // first search path wins
                        }
                        l.enabled.store(!disabled.contains(&l.manifest.id), Ordering::Relaxed);
                        tracing::info!(target: "quena::plugins", "loaded plugin {} {} from {}", l.manifest.name, l.manifest.version, dir.display());
                        found.push(Arc::new(l));
                    }
                    Err(e) => tracing::warn!(target: "quena::plugins", "plugin in {}: {e:#}", dir.display()),
                }
            }
        }
        let wasm: Vec<PathBuf> = found
            .iter()
            .flat_map(|l| std::fs::read_dir(&l.dir).into_iter().flatten().flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "wasm")))
            .collect();
        self.prune_cache(&wasm);
        *self.plugins.write() = found;
    }

    /// Compile `wasm`, or load the machine code compiled at an earlier start.
    fn compile_cached(&self, wasm: &Path) -> Result<Component> {
        use sha2::Digest;
        use std::hash::{Hash, Hasher};
        let bytes = std::fs::read(wasm).with_context(|| format!("{}", wasm.display()))?;
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.engine.precompile_compatibility_hash().hash(&mut h);
        let key = format!("{}-{:016x}", hex::encode(&sha2::Sha256::digest(&bytes)[..16]), h.finish());
        let cached = self.cache_dir.join(format!("{key}.cwasm"));
        // Read into memory rather than `deserialize_file`: a memory-mapped cache file is
        // locked on Windows (updates and pruning fail) and overwriting it on Unix while
        // mapped crashes the process (SIGBUS).
        if let Ok(ser) = std::fs::read(&cached) {
            // SAFETY: the bytes were produced by `serialize` of this engine configuration (the
            // key covers the wasm and the engine's compatibility hash) and live in Quena's own
            // data directory, which is as trusted as the plugin directories themselves;
            // wasmtime still rejects data that is not a compatible serialized component.
            match unsafe { Component::deserialize(&self.engine, &ser) } {
                Ok(c) => return Ok(c),
                Err(e) => tracing::debug!(target: "quena::plugins", "stale compile cache {}: {e}", cached.display()),
            }
        }
        let component = Component::new(&self.engine, &bytes).map_err(|e| anyhow!("{e:#}"))?;
        if let Ok(ser) = component.serialize() {
            let _ = std::fs::create_dir_all(&self.cache_dir);
            // A name of its own: processes sharing the cache may compile the same plugin at once.
            let tmp = cached.with_extension(format!("{}-{:x}.tmp", std::process::id(), rand_suffix()));
            if std::fs::write(&tmp, &ser).is_ok() {
                let _ = std::fs::rename(&tmp, &cached);
            }
        }
        Ok(component)
    }

    /// Drop compiled components no loaded plugin uses any more (updated or removed plugins).
    fn prune_cache(&self, keep: &[PathBuf]) {
        let Ok(rd) = std::fs::read_dir(&self.cache_dir) else { return };
        let used: Vec<String> = keep
            .iter()
            .filter_map(|w| std::fs::read(w).ok())
            .map(|b| {
                use sha2::Digest;
                hex::encode(&sha2::Sha256::digest(&b)[..16])
            })
            .collect();
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !used.iter().any(|u| name.starts_with(u.as_str())) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }

    fn load(&self, dir: &Path) -> Result<Loaded> {
        let manifest: Manifest = toml::from_str(&std::fs::read_to_string(dir.join("plugin.toml"))?).context("plugin.toml")?;
        let kind = if manifest.analyzer.is_some() {
            PluginKind::Analyzer
        } else if manifest.header_inspector.is_some() {
            PluginKind::HeaderInspector
        } else {
            PluginKind::Decoder
        };
        let mut l =
            Loaded { manifest: manifest.clone(), dir: dir.to_path_buf(), kind, pre: None, info: None, header: None, analyzer: None, enabled: AtomicBool::new(true), error: None };
        if manifest.api_version != API_VERSION {
            l.error = Some(format!("unsupported API version {} (host supports {API_VERSION})", manifest.api_version));
            return Ok(l);
        }
        let wasm = match &manifest.wasm {
            Some(w) => dir.join(w),
            None => std::fs::read_dir(dir)?
                .flatten()
                .map(|e| e.path())
                .find(|p| p.extension().is_some_and(|x| x == "wasm"))
                .ok_or_else(|| anyhow!("no .wasm file"))?,
        };
        let r = (|| -> Result<()> {
            let component = self.compile_cached(&wasm)?;
            let pre = self.linker.instantiate_pre(&component).map_err(|e| anyhow!("{e:#}"))?;
            match kind {
                PluginKind::Decoder => {
                    let pre = PluginPre::new(pre).map_err(|e| anyhow!("{e:#}"))?;
                    let (mut store, plugin) = self.instantiate(&pre)?;
                    let info = plugin.quena_plugin_decoder().call_get_info(&mut store).map_err(|e| anyhow!("{e:#}"))?;
                    l.pre = Some(pre);
                    l.info = Some(info);
                }
                PluginKind::HeaderInspector => {
                    let pre = HeaderPluginPre::new(pre).map_err(|e| anyhow!("{e:#}"))?;
                    let (mut store, plugin) = self.instantiate_header(&pre)?;
                    let info = plugin.quena_plugin_header_inspector().call_get_info(&mut store).map_err(|e| anyhow!("{e:#}"))?;
                    l.header = Some((pre, info));
                }
                PluginKind::Analyzer => {
                    let pre = AnalyzerPluginPre::new(pre).map_err(|e| anyhow!("{e:#}"))?;
                    let (mut store, plugin) = self.instantiate_analyzer(&pre)?;
                    let info = plugin.quena_plugin_analyzer().call_get_info(&mut store).map_err(|e| anyhow!("{e:#}"))?;
                    l.analyzer = Some((pre, info));
                }
            }
            Ok(())
        })();
        if let Err(e) = r {
            l.error = Some(format!("{e:#}"));
        }
        Ok(l)
    }

    /// Fresh sandboxed store: no preopens, no env, no args, no network — the plugin only computes.
    fn store(&self) -> Store<State> {
        let wasi = WasiCtxBuilder::new().build();
        let limits = StoreLimitsBuilder::new().memory_size(self.limits.memory).instances(4).tables(32).memories(4).build();
        let mut store = Store::new(&self.engine, State { wasi, table: ResourceTable::new(), limits, call_end: None });
        store.limiter(|s| &mut s.limits);
        store.set_epoch_deadline(self.deadline_ticks());
        store
    }

    fn instantiate(&self, pre: &PluginPre<State>) -> Result<(Store<State>, Plugin)> {
        let mut store = self.store();
        let plugin = pre.instantiate(&mut store).map_err(|e| anyhow!("{e:#}"))?;
        Ok((store, plugin))
    }

    fn instantiate_header(&self, pre: &HeaderPluginPre<State>) -> Result<(Store<State>, HeaderPlugin)> {
        let mut store = self.store();
        let plugin = pre.instantiate(&mut store).map_err(|e| anyhow!("{e:#}"))?;
        Ok((store, plugin))
    }

    fn instantiate_analyzer(&self, pre: &AnalyzerPluginPre<State>) -> Result<(Store<State>, AnalyzerPlugin)> {
        let mut store = self.store();
        let plugin = pre.instantiate(&mut store).map_err(|e| anyhow!("{e:#}"))?;
        Ok((store, plugin))
    }

    fn deadline_ticks(&self) -> u64 {
        ticks(self.limits.call_timeout)
    }

    pub fn list(&self) -> Vec<PluginInfo> {
        self.plugins
            .read()
            .iter()
            .enumerate()
            .map(|(i, l)| {
                let enabled = l.enabled.load(Ordering::Relaxed);
                let (name, version, tab) = l.labels();
                PluginInfo {
                    index: i as u16,
                    id: l.manifest.id.clone(),
                    name: name.to_string(),
                    version: version.to_string(),
                    tab: tab.to_string(),
                    output: match l.info.as_ref().map(|x| x.output) {
                        Some(Representation::Xml) => Output::Xml,
                        Some(Representation::Json) => Output::Json,
                        _ if l.kind == PluginKind::Analyzer => Output::Json,
                        _ => Output::Text,
                    },
                    enabled,
                    status: if l.error.is_some() { "Error".into() } else if enabled { "Enabled".into() } else { "Disabled".into() },
                    error: l.error.clone(),
                    path: l.dir.display().to_string(),
                    kind: l.kind,
                    mime_types: l.manifest.decoder.as_ref().map(|d| d.mime_types.clone()).unwrap_or_default(),
                    headers: l.manifest.header_inspector.as_ref().map(|h| h.headers.clone()).unwrap_or_default(),
                }
            })
            .collect()
    }

    pub fn set_enabled(&self, id: &str, on: bool) -> Result<()> {
        let list = self.plugins.read();
        let p = list.iter().find(|l| l.manifest.id == id).ok_or_else(|| anyhow!("unknown plugin {id}"))?;
        p.enabled.store(on, Ordering::Relaxed);
        let disabled: Vec<String> = list.iter().filter(|l| !l.enabled.load(Ordering::Relaxed)).map(|l| l.manifest.id.clone()).collect();
        std::fs::write(&self.disabled_file, serde_json::to_vec(&disabled)?)?;
        Ok(())
    }

    fn get(&self, index: u16) -> Option<Arc<Loaded>> {
        self.plugins.read().get(index as usize).cloned()
    }

    pub fn output(&self, index: u16) -> Option<Output> {
        self.list().into_iter().find(|p| p.index == index).map(|p| p.output)
    }

    /// Plugins that apply to a body: (index, tab title, confidence).
    pub fn candidates(&self, content_type: Option<&str>, prefix: &[u8]) -> Vec<(u16, String, u8)> {
        let ct = content_type.map(|c| c.split(';').next().unwrap_or("").trim().to_ascii_lowercase());
        let mut out = Vec::new();
        for (i, l) in self.plugins.read().iter().enumerate() {
            if !l.enabled.load(Ordering::Relaxed) {
                continue;
            }
            let (Some(pre), Some(info)) = (&l.pre, &l.info) else { continue };
            let manifest_hit = ct.as_ref().is_some_and(|ct| l.manifest.decoder.as_ref().is_some_and(|d| d.mime_types.iter().any(|m| m.eq_ignore_ascii_case(ct))));
            let conf = match self.instantiate(pre).and_then(|(mut store, p)| {
                p.quena_plugin_decoder().call_detect(&mut store, content_type, &prefix[..prefix.len().min(4096)]).map_err(|e| anyhow!("{e:#}"))
            }) {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(target: "quena::plugins", "{}: detect failed: {e}", l.manifest.id);
                    0
                }
            };
            let conf = if manifest_hit { conf.max(90) } else { conf };
            if conf >= 50 {
                out.push((i as u16, info.tab.clone(), conf));
            }
        }
        out.sort_by_key(|b| std::cmp::Reverse(b.2));
        out
    }

    /// Run plugin `index` over `input`, streaming output to `out`.
    pub fn decode(&self, index: u16, content_type: Option<&str>, input: &mut dyn Read, out: &mut dyn Write, cancelled: &dyn Fn() -> bool) -> Result<u64> {
        let l = self.get(index).ok_or_else(|| anyhow!("plugin {index} not found"))?;
        if !l.enabled.load(Ordering::Relaxed) {
            return Err(anyhow!("plugin {} is disabled", l.manifest.name));
        }
        let pre = l.pre.as_ref().ok_or_else(|| anyhow!("plugin {} failed to load: {}", l.manifest.name, l.error.clone().unwrap_or_default()))?;
        let (mut store, plugin) = self.instantiate(pre)?;
        let d = plugin.quena_plugin_decoder();
        let session = d.session().call_constructor(&mut store, content_type).map_err(|e| anyhow!("plugin: {e:#}"))?;
        let mut buf = vec![0u8; 256 * 1024];
        let mut written = 0u64;
        let result = (|| -> Result<()> {
            loop {
                if cancelled() {
                    return Err(anyhow!("cancelled"));
                }
                let n = input.read(&mut buf)?;
                store.set_epoch_deadline(self.deadline_ticks());
                let chunk = if n == 0 {
                    d.session().call_finish(&mut store, session).map_err(|e| anyhow!("plugin trapped: {e:#}"))?
                } else {
                    d.session().call_push(&mut store, session, &buf[..n]).map_err(|e| anyhow!("plugin trapped: {e:#}"))?
                };
                let chunk = chunk.map_err(|e| anyhow!("{e}"))?;
                written += chunk.len() as u64;
                if written > self.limits.max_output {
                    return Err(anyhow!("plugin output exceeds {} bytes", self.limits.max_output));
                }
                out.write_all(&chunk)?;
                if n == 0 {
                    return Ok(());
                }
            }
        })();
        let _ = session.resource_drop(&mut store);
        result.map(|_| written)
    }

    /// Ask all enabled header inspectors about one header value; best match first.
    /// A plugin that traps, times out or fails is reported with `error` and does
    /// not affect the others.
    pub fn inspect_header(&self, name: &str, value: &str) -> Vec<HeaderInspection> {
        let name = name.to_ascii_lowercase();
        let mut out = Vec::new();
        for l in self.plugins.read().iter() {
            if !l.enabled.load(Ordering::Relaxed) {
                continue;
            }
            let (Some((pre, info)), Some(m)) = (&l.header, &l.manifest.header_inspector) else { continue };
            if !m.headers.is_empty() && !m.headers.iter().any(|h| h.eq_ignore_ascii_case(&name)) {
                continue;
            }
            let r = (|| -> Result<Option<(u8, Vec<InspectNode>)>> {
                let (mut store, plugin) = self.instantiate_header(pre)?;
                let h = plugin.quena_plugin_header_inspector();
                let conf = h.call_detect(&mut store, &name, value).map_err(|e| anyhow!("plugin trapped: {e:#}"))?;
                if conf < 50 {
                    return Ok(None);
                }
                store.set_epoch_deadline(self.deadline_ticks());
                let nodes = h.call_inspect(&mut store, &name, value).map_err(|e| anyhow!("plugin trapped: {e:#}"))?.map_err(|e| anyhow!("{e}"))?;
                let size: usize = nodes.iter().map(|n| n.name.len() + n.value.len()).sum();
                if size > self.limits.max_inspect_output {
                    return Err(anyhow!("plugin output exceeds {} bytes", self.limits.max_inspect_output));
                }
                let nodes = nodes
                    .into_iter()
                    .map(|n| InspectNode {
                        depth: n.depth,
                        kind: match n.kind {
                            NodeKind::Section => "section",
                            NodeKind::Field => "field",
                            NodeKind::Note => "note",
                            NodeKind::Code => "code",
                        },
                        name: n.name,
                        value: n.value,
                    })
                    .collect();
                Ok(Some((conf, nodes)))
            })();
            let entry = |confidence, nodes, error| HeaderInspection { plugin_id: l.manifest.id.clone(), tab: info.tab.clone(), confidence, nodes, error };
            match r {
                Ok(Some((conf, nodes))) => out.push(entry(conf, nodes, None)),
                Ok(None) => {}
                Err(e) => {
                    tracing::debug!(target: "quena::plugins", "{}: inspect failed: {e:#}", l.manifest.id);
                    out.push(entry(0, vec![], Some(format!("{e:#}"))));
                }
            }
        }
        out.sort_by_key(|b| std::cmp::Reverse(b.confidence));
        out
    }

    /// Enabled, loaded analyzer plugin `index`.
    fn analyzer(&self, index: u16) -> Result<(Arc<Loaded>, AnalyzerPluginPre<State>)> {
        let l = self.get(index).ok_or_else(|| anyhow!("plugin {index} not found"))?;
        if l.kind != PluginKind::Analyzer {
            return Err(anyhow!("plugin {} is no analyzer", l.manifest.name));
        }
        if !l.enabled.load(Ordering::Relaxed) {
            return Err(anyhow!("plugin {} is disabled", l.manifest.name));
        }
        let pre = match &l.analyzer {
            Some((pre, _)) => pre.clone(),
            None => return Err(anyhow!("plugin {} failed to load: {}", l.manifest.name, l.error.clone().unwrap_or_default())),
        };
        Ok((l, pre))
    }

    /// Profiles and default options of analyzer `index` as JSON (`describe` in REPORT.md).
    pub fn describe(&self, index: u16, lang: &str) -> Result<String> {
        let (_, pre) = self.analyzer(index)?;
        let (mut store, plugin) = self.instantiate_analyzer(&pre)?;
        let out = plugin.quena_plugin_analyzer().call_describe(&mut store, lang).map_err(|e| anyhow!("plugin trapped: {e:#}"))?;
        if out.len() > self.limits.max_report {
            return Err(anyhow!("plugin output exceeds {} bytes", self.limits.max_report));
        }
        Ok(out)
    }

    /// One analyzer run: `run(options)`, a `push` per batch from `next_batch` (until it returns
    /// `None`), then `finish` → the report JSON. Fresh store per run; the call deadline applies
    /// to every call (`finish` gets [`Limits::finish_timeout`]). A plugin that traps, times out
    /// or exceeds its memory only fails this run. `cancelled` is checked between calls and
    /// after `finish` (a run cancelled meanwhile returns an error, never a report).
    pub fn analyze(
        &self,
        index: u16,
        options_json: &str,
        next_batch: &mut dyn FnMut() -> Option<Vec<AnalyzerSession>>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<String> {
        self.analyze_inner(index, options_json, next_batch, cancelled, None)
    }

    /// [`analyze`](Self::analyze) that also interrupts a call in flight: while the plugin
    /// runs, `cancelled` is polled every 50 ms (epoch callback) and the call traps with
    /// `cancelled` as soon as it returns true.
    pub fn analyze_interruptible(
        &self,
        index: u16,
        options_json: &str,
        next_batch: &mut dyn FnMut() -> Option<Vec<AnalyzerSession>>,
        cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<String> {
        let c = cancelled.clone();
        self.analyze_inner(index, options_json, next_batch, &move || c(), Some(cancelled))
    }

    fn analyze_inner(
        &self,
        index: u16,
        options_json: &str,
        next_batch: &mut dyn FnMut() -> Option<Vec<AnalyzerSession>>,
        cancelled: &dyn Fn() -> bool,
        interrupt: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    ) -> Result<String> {
        let (_, pre) = self.analyzer(index)?;
        let mut store = self.store();
        let sliced = interrupt.is_some();
        if let Some(stop) = interrupt {
            store.epoch_deadline_callback(move |ctx| {
                if stop() {
                    return Err(wasmtime::format_err!("cancelled"));
                }
                match ctx.data().call_end {
                    Some(end) if Instant::now() < end => Ok(wasmtime::UpdateDeadline::Continue(INTERRUPT_SLICE)),
                    _ => Ok(wasmtime::UpdateDeadline::Interrupt),
                }
            });
        }
        arm(&mut store, self.limits.call_timeout, sliced);
        let plugin = pre.instantiate(&mut store).map_err(|e| anyhow!("{e:#}"))?;
        let a = plugin.quena_plugin_analyzer();
        arm(&mut store, self.limits.call_timeout, sliced);
        let run = a.run().call_constructor(&mut store, options_json).map_err(|e| anyhow!("plugin trapped: {e:#}"))?;
        let result = (|| -> Result<String> {
            loop {
                if cancelled() {
                    return Err(anyhow!("cancelled"));
                }
                let batch = next_batch();
                // The batch source may stop early because of the cancellation.
                if cancelled() {
                    return Err(anyhow!("cancelled"));
                }
                let Some(batch) = batch else { break };
                let batch: Vec<WitSession> = batch.into_iter().map(WitSession::from).collect();
                arm(&mut store, self.limits.call_timeout, sliced);
                a.run().call_push(&mut store, run, &batch).map_err(|e| anyhow!("plugin trapped: {e:#}"))?.map_err(|e| anyhow!("{e}"))?;
            }
            arm(&mut store, self.limits.finish_timeout, sliced);
            let report = a.run().call_finish(&mut store, run).map_err(|e| anyhow!("plugin trapped: {e:#}"))?.map_err(|e| anyhow!("{e}"))?;
            // Cancelled while `finish` ran: the caller must not get (and store) a stale report.
            if cancelled() {
                return Err(anyhow!("cancelled"));
            }
            if report.len() > self.limits.max_report {
                return Err(anyhow!("plugin output exceeds {} bytes", self.limits.max_report));
            }
            Ok(report)
        })();
        let _ = run.resource_drop(&mut store);
        result
    }
}

/// A value that differs between threads and calls (temporary file names).
fn rand_suffix() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
    h.finish()
}
