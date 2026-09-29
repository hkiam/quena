use crate::body::{Body, BodyWriter};
use crate::lines::LineIndex;
use parking_lot::Mutex;
use quena_model::BodyRef;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BodyConfig {
    /// Bodies up to this size stay in memory.
    pub inline_limit: usize,
    /// Maximum recorded bytes per body; the rest is forwarded but not stored.
    pub max_recorded_body: u64,
    /// Total quota for this store.
    pub quota: u64,
    /// Stop recording when free disk space drops below this.
    pub min_free_space: u64,
    /// Maximum size of a derived (decoded/pretty) cache file.
    pub max_derived: u64,
    /// Maximum expansion ratio when decompressing (bomb protection), applied after 16 MB.
    pub max_ratio: u64,
}

impl Default for BodyConfig {
    fn default() -> Self {
        BodyConfig {
            inline_limit: 64 * 1024,
            max_recorded_body: 2 * 1024 * 1024 * 1024,
            quota: 200 * 1024 * 1024 * 1024,
            min_free_space: 5 * 1024 * 1024 * 1024,
            max_derived: 64 * 1024 * 1024 * 1024,
            max_ratio: 2000,
        }
    }
}

/// Which representation of a body is requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Variant {
    /// Exactly as stored (content-encoding still applied).
    Raw,
    /// Content-encoding removed.
    Decoded,
    /// Decoded and pretty printed (JSON/XML).
    Pretty,
    /// Decoded by plugin `n` (output pretty printed if the plugin emits XML/JSON).
    Plugin(u16),
}

impl Variant {
    pub fn parse(s: &str) -> Option<Variant> {
        Some(match s {
            "raw" => Variant::Raw,
            "decoded" => Variant::Decoded,
            "pretty" => Variant::Pretty,
            p => Variant::Plugin(p.strip_prefix("plugin:")?.parse().ok()?),
        })
    }
    pub fn name(self) -> String {
        match self {
            Variant::Raw => "raw".into(),
            Variant::Decoded => "decoded".into(),
            Variant::Pretty => "pretty".into(),
            Variant::Plugin(n) => format!("plugin:{n}"),
        }
    }
    fn ext(self) -> String {
        match self {
            Variant::Raw => "bin".into(),
            Variant::Decoded => "dec".into(),
            Variant::Pretty => "pretty".into(),
            Variant::Plugin(n) => format!("plugin{n}"),
        }
    }
}

impl Serialize for Variant {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.name())
    }
}

impl<'de> Deserialize<'de> for Variant {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Variant::parse(&s).ok_or_else(|| serde::de::Error::custom(format!("unknown variant {s}")))
    }
}

/// Decoder plugins (implemented by the plugin host, installed by the app).
pub trait PluginDecoders: Send + Sync {
    fn decode(&self, index: u16, content_type: Option<&str>, input: &mut dyn std::io::Read, output: &mut dyn std::io::Write, cancelled: &dyn Fn() -> bool) -> std::io::Result<u64>;
    fn pretty_kind(&self, index: u16) -> Option<crate::pretty::PrettyKind>;
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreStats {
    pub used_bytes: u64,
    pub free_bytes: Option<u64>,
    pub recording_suspended: bool,
}

pub struct BodyStore {
    root: PathBuf,
    next_id: AtomicU64,
    used: AtomicU64,
    since_check: AtomicU64,
    suspended: AtomicBool,
    cfg: parking_lot::RwLock<BodyConfig>,
    derived: Mutex<HashMap<(u64, Variant), Body>>,
    line_indexes: Mutex<HashMap<(u64, Variant), Arc<LineIndex>>>,
    plugins: parking_lot::RwLock<Option<Arc<dyn PluginDecoders>>>,
}

impl BodyStore {
    pub fn open(root: impl Into<PathBuf>, cfg: BodyConfig) -> std::io::Result<Arc<BodyStore>> {
        let root = root.into();
        std::fs::create_dir_all(root.join("blobs"))?;
        std::fs::create_dir_all(root.join("cache"))?;
        Ok(Arc::new(BodyStore {
            root,
            next_id: AtomicU64::new(1),
            used: AtomicU64::new(0),
            since_check: AtomicU64::new(0),
            suspended: AtomicBool::new(false),
            cfg: parking_lot::RwLock::new(cfg),
            derived: Mutex::new(HashMap::new()),
            line_indexes: Mutex::new(HashMap::new()),
            plugins: parking_lot::RwLock::new(None),
        }))
    }

    pub fn set_plugins(&self, p: Option<Arc<dyn PluginDecoders>>) {
        *self.plugins.write() = p;
    }

    pub fn plugins(&self) -> Option<Arc<dyn PluginDecoders>> {
        self.plugins.read().clone()
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn config(&self) -> BodyConfig {
        self.cfg.read().clone()
    }

    pub fn set_config(&self, cfg: BodyConfig) {
        *self.cfg.write() = cfg;
    }

    /// Ensure future ids are above `id` (after loading persisted sessions).
    pub fn bump_id(&self, id: u64) {
        self.next_id.fetch_max(id.saturating_add(1), Ordering::Relaxed);
    }

    fn blob_path(&self, id: u64) -> PathBuf {
        self.root.join("blobs").join(format!("{:02x}", id & 0xff)).join(format!("{id}.bin"))
    }

    fn cache_path(&self, id: u64, v: Variant) -> PathBuf {
        self.root.join("cache").join(format!("{id}.{}", v.ext()))
    }

    /// Start recording a new body.
    pub fn writer(self: &Arc<Self>) -> BodyWriter {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let cfg = self.cfg.read();
        let max = if self.suspended.load(Ordering::Relaxed) { 0 } else { cfg.max_recorded_body };
        BodyWriter::new(Body::new(id, self.blob_path(id)), self.clone(), cfg.inline_limit, max)
    }

    /// Writer for a body with an explicit recording limit (e.g. "headers only" = 0).
    pub fn writer_with_limit(self: &Arc<Self>, max: u64) -> BodyWriter {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let cfg = self.cfg.read();
        BodyWriter::new(Body::new(id, self.blob_path(id)), self.clone(), cfg.inline_limit, max)
    }

    /// Writer for a derived cache file (no inline, no recording limit, derived limit applies).
    pub(crate) fn derived_writer(self: &Arc<Self>, source: &Body, v: Variant) -> BodyWriter {
        let max = self.cfg.read().max_derived;
        BodyWriter::new(Body::new(source.id(), self.cache_path(source.id(), v)), self.clone(), 0, max)
    }

    /// Store a complete body from memory.
    pub fn store_bytes(self: &Arc<Self>, data: &[u8]) -> Body {
        let mut w = self.writer_with_limit(u64::MAX);
        let _ = w.write(data);
        w.finish()
    }

    /// Development helper: a sparse blob of `len` bytes starting with `header`
    /// (used by the mock generator to test 10 GB+ bodies without writing them).
    pub fn sparse(self: &Arc<Self>, len: u64, header: &[u8]) -> std::io::Result<Body> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let path = self.blob_path(id);
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&path)?;
            f.write_all(header)?;
            f.set_len(len.max(header.len() as u64))?;
        }
        Ok(Body::from_ref(
            &BodyRef::Blob { id, len: len.max(header.len() as u64), wire_len: len.max(header.len() as u64), truncated: false, complete: true },
            path,
        ))
    }

    /// Re-open a persisted body.
    pub fn open_ref(&self, r: &BodyRef) -> Body {
        let id = match r {
            BodyRef::Empty => 0,
            BodyRef::Inline { id, .. } | BodyRef::Blob { id, .. } => *id,
        };
        self.bump_id(id);
        Body::from_ref(r, self.blob_path(id))
    }

    /// Account for `n` newly stored bytes. Returns false if recording must stop.
    pub(crate) fn reserve(&self, n: u64) -> bool {
        if self.suspended.load(Ordering::Relaxed) {
            return false;
        }
        let cfg = self.cfg.read();
        let used = self.used.fetch_add(n, Ordering::Relaxed) + n;
        if used > cfg.quota {
            tracing::warn!("body store quota exceeded, recording suspended");
            self.suspended.store(true, Ordering::Relaxed);
            return false;
        }
        // Check free disk space every 64 MB.
        if self.since_check.fetch_add(n, Ordering::Relaxed) + n > 64 * 1024 * 1024 {
            self.since_check.store(0, Ordering::Relaxed);
            if let Some(free) = crate::free_space(&self.root) {
                if free < cfg.min_free_space {
                    tracing::warn!(free, "low disk space, recording suspended");
                    self.suspended.store(true, Ordering::Relaxed);
                    return false;
                }
            }
        }
        true
    }

    pub fn resume_recording(&self) {
        self.suspended.store(false, Ordering::Relaxed);
    }

    pub fn stats(&self) -> StoreStats {
        StoreStats {
            used_bytes: self.used.load(Ordering::Relaxed),
            free_bytes: crate::free_space(&self.root),
            recording_suspended: self.suspended.load(Ordering::Relaxed),
        }
    }

    /// Cached derived body, if any.
    pub fn derived(&self, id: u64, v: Variant) -> Option<Body> {
        self.derived.lock().get(&(id, v)).cloned()
    }

    /// Get or create a derived body. Returns (body, created). If `created`, the
    /// caller must fill it using the returned writer.
    pub(crate) fn derived_or_create(self: &Arc<Self>, source: &Body, v: Variant) -> (Body, Option<BodyWriter>) {
        let mut map = self.derived.lock();
        if let Some(b) = map.get(&(source.id(), v)) {
            return (b.clone(), None);
        }
        let w = self.derived_writer(source, v);
        let b = w.body().clone();
        map.insert((source.id(), v), b.clone());
        (b, Some(w))
    }

    pub(crate) fn forget_derived(&self, id: u64, v: Variant) {
        if let Some(b) = self.derived.lock().remove(&(id, v)) {
            b.delete_file();
        }
        self.line_indexes.lock().remove(&(id, v));
    }

    pub fn line_index(&self, id: u64, v: Variant) -> Option<Arc<LineIndex>> {
        self.line_indexes.lock().get(&(id, v)).cloned()
    }

    pub fn line_index_or_create(&self, id: u64, v: Variant) -> (Arc<LineIndex>, bool) {
        let mut map = self.line_indexes.lock();
        if let Some(i) = map.get(&(id, v)) {
            return (i.clone(), false);
        }
        let i = Arc::new(LineIndex::new());
        map.insert((id, v), i.clone());
        (i, true)
    }

    /// Delete a body and all its derived data.
    pub fn delete(&self, body: &Body) {
        let len = body.path().map(|_| body.len()).unwrap_or(0);
        body.delete_file();
        self.used.fetch_sub(len.min(self.used.load(Ordering::Relaxed)), Ordering::Relaxed);
        let keys: Vec<Variant> = self.derived.lock().keys().filter(|(id, _)| *id == body.id()).map(|(_, v)| *v).collect();
        for v in keys {
            self.forget_derived(body.id(), v);
        }
    }

    /// Delete everything (Ctrl+X on the whole capture).
    pub fn clear(&self) {
        self.derived.lock().clear();
        self.line_indexes.lock().clear();
        let _ = std::fs::remove_dir_all(self.root.join("blobs"));
        let _ = std::fs::remove_dir_all(self.root.join("cache"));
        let _ = std::fs::create_dir_all(self.root.join("blobs"));
        let _ = std::fs::create_dir_all(self.root.join("cache"));
        self.used.store(0, Ordering::Relaxed);
        self.suspended.store(false, Ordering::Relaxed);
    }
}
