//! WASM component plugin host (PLAN.md §12–§15).
//!
//! * discovery: `<dir>/<plugin>/plugin.toml` + component `.wasm`
//! * API: `wit/plugin.wit` (streaming decoder sessions), versioned
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
use std::time::Duration;
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

wasmtime::component::bindgen!({
    path: "../../wit/plugin.wit",
    world: "plugin",
});

use exports::quena::plugin::decoder::Representation;

pub const API_VERSION: &str = "1";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DecoderManifest {
    #[serde(default)]
    pub mime_types: Vec<String>,
    #[serde(default)]
    pub extensions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Manifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub api_version: String,
    /// Component file relative to the manifest (default: first `.wasm`).
    pub wasm: Option<String>,
    pub decoder: Option<DecoderManifest>,
    #[serde(default)]
    pub description: String,
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
    pub mime_types: Vec<String>,
}

/// Resource limits per decoding run.
#[derive(Debug, Clone)]
pub struct Limits {
    pub memory: usize,
    /// Wall-clock budget per call into the plugin.
    pub call_timeout: Duration,
    /// Maximum output size of one run.
    pub max_output: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { memory: 512 << 20, call_timeout: Duration::from_secs(10), max_output: 16 << 30 }
    }
}

struct State {
    wasi: WasiCtx,
    table: ResourceTable,
    limits: StoreLimits,
}

impl WasiView for State {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView { ctx: &mut self.wasi, table: &mut self.table }
    }
}

struct Loaded {
    manifest: Manifest,
    dir: PathBuf,
    pre: Option<PluginPre<State>>,
    info: Option<exports::quena::plugin::decoder::Info>,
    enabled: AtomicBool,
    error: Option<String>,
}

pub struct PluginHost {
    engine: Engine,
    linker: Linker<State>,
    plugins: RwLock<Vec<Arc<Loaded>>>,
    dirs: Vec<PathBuf>,
    limits: Limits,
    disabled_file: PathBuf,
}

/// Ticks per call deadline (the ticker increments the epoch every 10 ms).
const TICK: Duration = Duration::from_millis(10);

impl PluginHost {
    /// `dirs`: plugin search paths; `state_dir`: where enable/disable state is kept.
    pub fn new(dirs: Vec<PathBuf>, state_dir: &Path) -> Result<Arc<PluginHost>> {
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
        *self.plugins.write() = found;
    }

    fn load(&self, dir: &Path) -> Result<Loaded> {
        let manifest: Manifest = toml::from_str(&std::fs::read_to_string(dir.join("plugin.toml"))?).context("plugin.toml")?;
        let mut l = Loaded { manifest: manifest.clone(), dir: dir.to_path_buf(), pre: None, info: None, enabled: AtomicBool::new(true), error: None };
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
        let r = (|| -> Result<(PluginPre<State>, exports::quena::plugin::decoder::Info)> {
            let component = Component::from_file(&self.engine, &wasm).map_err(|e| anyhow!("{e:#}"))?;
            let pre = self.linker.instantiate_pre(&component).map_err(|e| anyhow!("{e:#}"))?;
            let pre = PluginPre::new(pre).map_err(|e| anyhow!("{e:#}"))?;
            let (mut store, plugin) = self.instantiate(&pre)?;
            let info = plugin.quena_plugin_decoder().call_get_info(&mut store).map_err(|e| anyhow!("{e:#}"))?;
            Ok((pre, info))
        })();
        match r {
            Ok((pre, info)) => {
                l.pre = Some(pre);
                l.info = Some(info);
            }
            Err(e) => l.error = Some(format!("{e:#}")),
        }
        Ok(l)
    }

    fn instantiate(&self, pre: &PluginPre<State>) -> Result<(Store<State>, Plugin)> {
        // No preopens, no env, no args, no network: the plugin only computes.
        let wasi = WasiCtxBuilder::new().build();
        let limits = StoreLimitsBuilder::new().memory_size(self.limits.memory).instances(4).tables(32).memories(4).build();
        let mut store = Store::new(&self.engine, State { wasi, table: ResourceTable::new(), limits });
        store.limiter(|s| &mut s.limits);
        store.set_epoch_deadline(self.deadline_ticks());
        let plugin = pre.instantiate(&mut store).map_err(|e| anyhow!("{e:#}"))?;
        Ok((store, plugin))
    }

    fn deadline_ticks(&self) -> u64 {
        (self.limits.call_timeout.as_millis() / TICK.as_millis()).max(1) as u64
    }

    pub fn list(&self) -> Vec<PluginInfo> {
        self.plugins
            .read()
            .iter()
            .enumerate()
            .map(|(i, l)| {
                let enabled = l.enabled.load(Ordering::Relaxed);
                PluginInfo {
                    index: i as u16,
                    id: l.manifest.id.clone(),
                    name: l.info.as_ref().map(|x| x.name.clone()).unwrap_or_else(|| l.manifest.name.clone()),
                    version: l.info.as_ref().map(|x| x.version.clone()).unwrap_or_else(|| l.manifest.version.clone()),
                    tab: l.info.as_ref().map(|x| x.tab.clone()).unwrap_or_else(|| l.manifest.name.clone()),
                    output: match l.info.as_ref().map(|x| x.output) {
                        Some(Representation::Xml) => Output::Xml,
                        Some(Representation::Json) => Output::Json,
                        _ => Output::Text,
                    },
                    enabled,
                    status: if l.error.is_some() { "Error".into() } else if enabled { "Enabled".into() } else { "Disabled".into() },
                    error: l.error.clone(),
                    path: l.dir.display().to_string(),
                    mime_types: l.manifest.decoder.as_ref().map(|d| d.mime_types.clone()).unwrap_or_default(),
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
        out.sort_by(|a, b| b.2.cmp(&a.2));
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
}
