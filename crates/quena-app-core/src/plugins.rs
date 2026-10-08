//! Decoder plugins: host setup, body-store adapter, inspector candidates.

use crate::AppCore;
use crate::dto::{DetailDto, PluginCandidate};
use anyhow::{Result, anyhow};
use quena_body::pretty::PrettyKind;
use quena_body::{Body, PluginDecoders, Variant};
use quena_plugin_host::{HeaderInspection, Output, PluginHost, PluginInfo};
use quena_store::Capture;
use std::path::PathBuf;
use std::sync::Arc;

struct Adapter(Arc<PluginHost>);

impl PluginDecoders for Adapter {
    fn decode(
        &self,
        index: u16,
        ct: Option<&str>,
        input: &mut dyn std::io::Read,
        output: &mut dyn std::io::Write,
        cancelled: &dyn Fn() -> bool,
    ) -> std::io::Result<u64> {
        self.0
            .decode(index, ct, input, output, cancelled)
            .map_err(|e| std::io::Error::other(format!("{e:#}")))
    }
    fn pretty_kind(&self, index: u16) -> Option<PrettyKind> {
        match self.0.output(index)? {
            Output::Xml => Some(PrettyKind::Xml),
            Output::Json => Some(PrettyKind::Json),
            Output::Text => None,
        }
    }
}

impl AppCore {
    /// Start the plugin host. `bundled` is the app's resource plugin dir. Compiling the
    /// plugins takes a while on a cold cache, so this runs in the background; the `plugins`
    /// event tells the UI when it is done (views that asked early reload their plugin lists).
    pub fn init_plugins(self: &Arc<Self>, bundled: Option<PathBuf>) -> Result<()> {
        let r = self.start_plugin_host(Self::plugin_search_path(&self.paths.data, bundled));
        self.plugins_done
            .store(true, std::sync::atomic::Ordering::Release);
        self.emit("plugins", serde_json::Value::Null);
        r
    }

    /// Start the plugin host on exactly these directories: no user plugin dir and no
    /// `QUENA_PLUGIN_DIR` (an explicit choice, e.g. the CLI's `--plugins`).
    pub fn init_plugins_from(self: &Arc<Self>, dirs: Vec<PathBuf>) -> Result<()> {
        let r = self.start_plugin_host(dirs);
        self.plugins_done
            .store(true, std::sync::atomic::Ordering::Release);
        self.emit("plugins", serde_json::Value::Null);
        r
    }

    /// The directories the plugin host searches, in order (empty before `init_plugins`).
    pub fn plugin_search_dirs(&self) -> Vec<PathBuf> {
        self.plugin_host
            .read()
            .as_ref()
            .map(|h| h.dirs().to_vec())
            .unwrap_or_default()
    }

    /// `QUENA_PLUGIN_DIR` (development: freshly built plugins win), the user's plugin dir, then
    /// the bundled one.
    fn plugin_search_path(data: &std::path::Path, bundled: Option<PathBuf>) -> Vec<PathBuf> {
        let user = data.join("plugins");
        let _ = std::fs::create_dir_all(&user);
        let mut dirs = vec![user];
        if let Some(b) = bundled {
            dirs.push(b);
        }
        if let Ok(extra) = std::env::var("QUENA_PLUGIN_DIR") {
            dirs.insert(0, PathBuf::from(extra));
        }
        dirs
    }

    /// Plugin loading has finished (the list of plugins is final until a rescan).
    pub fn plugins_ready(&self) -> bool {
        self.plugins_done.load(std::sync::atomic::Ordering::Acquire)
    }

    fn start_plugin_host(self: &Arc<Self>, dirs: Vec<PathBuf>) -> Result<()> {
        let host = PluginHost::with_cache(dirs, &self.paths.data, self.paths.plugin_cache.clone())?;
        *self.plugin_host.write() = Some(host);
        self.install_plugin_decoders(&self.capture());
        Ok(())
    }

    pub(crate) fn install_plugin_decoders(&self, cap: &Arc<Capture>) {
        let h = self.plugin_host.read().clone();
        cap.bodies
            .set_plugins(h.map(|h| Arc::new(Adapter(h)) as Arc<dyn PluginDecoders>));
    }

    pub fn plugins(&self) -> Vec<PluginInfo> {
        self.plugin_host
            .read()
            .as_ref()
            .map(|h| h.list())
            .unwrap_or_default()
    }

    pub fn plugin_set_enabled(&self, id: &str, on: bool) -> Result<()> {
        self.plugin_host
            .read()
            .as_ref()
            .ok_or_else(|| anyhow!("plugin host not available"))?
            .set_enabled(id, on)
    }

    pub fn plugins_rescan(&self) -> Vec<PluginInfo> {
        if let Some(h) = self.plugin_host.read().as_ref() {
            h.discover();
        }
        self.plugins()
    }

    /// Header inspector plugins' view of one header value (best match first).
    pub fn plugin_inspect_header(&self, name: &str, value: &str) -> Vec<HeaderInspection> {
        let host = self.plugin_host.read().clone();
        host.map(|h| h.inspect_header(name, value))
            .unwrap_or_default()
    }

    pub fn plugin_dir(&self) -> PathBuf {
        self.paths.data.join("plugins")
    }

    pub(crate) fn add_plugin_candidates(&self, dto: &mut DetailDto, req: &Body, resp: &Body) {
        let Some(host) = self.plugin_host.read().clone() else {
            return;
        };
        let probe = |b: &Body, ct: Option<&str>, ce: Option<&str>| -> Vec<PluginCandidate> {
            if b.is_empty() {
                return vec![];
            }
            let raw = b.read_range(0, 64 * 1024).unwrap_or_default();
            let prefix = match ce {
                Some(ce) => quena_body::decode::decode_bytes(&raw, ce, 4096).unwrap_or(raw),
                None => raw,
            };
            host.candidates(ct, &prefix)
                .into_iter()
                .map(|(i, tab, c)| PluginCandidate {
                    variant: Variant::Plugin(i),
                    tab,
                    confidence: c,
                    output: match host.output(i) {
                        Some(Output::Xml) => "xml".into(),
                        Some(Output::Json) => "json".into(),
                        _ => "text".into(),
                    },
                })
                .collect()
        };
        dto.request_body.plugins = probe(
            req,
            dto.request_body.content_type.as_deref(),
            dto.request_body.content_encoding.as_deref(),
        );
        dto.response_body.plugins = probe(
            resp,
            dto.response_body.content_type.as_deref(),
            dto.response_body.content_encoding.as_deref(),
        );
    }
}
