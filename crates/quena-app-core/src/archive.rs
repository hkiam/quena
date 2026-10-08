//! Load/Save archives (SAZ, HAR) and load packet captures as background jobs.

use crate::AppCore;
use anyhow::{Result, anyhow};
use quena_formats::har::HarOptions;
use quena_jobs::{JobCtx, JobId, Priority};
use quena_model::SessionId;
use crate::sanitize::{RedactionLog, SanitizeExportSettings, SanitizeOptions, Sanitizer};
use quena_store::Capture;
use std::path::{Path, PathBuf};
use std::sync::Arc;

struct P<'a>(&'a JobCtx);
impl quena_formats::Progress for P<'_> {
    fn cancelled(&self) -> bool {
        self.0.cancelled()
    }
    fn progress(&self, done: u64, total: u64) {
        self.0.progress(done, total)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ArchiveFormat {
    Saz,
    Har,
    Curl,
    /// Packet capture (pcap, pcapng): import only.
    Pcap,
}

/// Can [`AppCore::import_archive`] load this file (by its extension)?
pub fn importable(path: &std::path::Path) -> bool {
    matches!(format_of(path), Some(ArchiveFormat::Saz | ArchiveFormat::Har | ArchiveFormat::Pcap))
}

/// Is this a packet capture (by its extension)?
pub fn is_capture(path: &std::path::Path) -> bool {
    format_of(path) == Some(ArchiveFormat::Pcap)
}

fn format_of(path: &std::path::Path) -> Option<ArchiveFormat> {
    match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
        "saz" | "zip" => Some(ArchiveFormat::Saz),
        "har" | "json" => Some(ArchiveFormat::Har),
        "sh" | "txt" => Some(ArchiveFormat::Curl),
        "pcap" | "pcapng" | "cap" => Some(ArchiveFormat::Pcap),
        _ => None,
    }
}

impl AppCore {
    /// Export sessions (empty = all in view order).
    pub fn export_archive(self: &Arc<Self>, ids: Vec<SessionId>, path: PathBuf, format: Option<ArchiveFormat>) -> Result<JobId> {
        let format = format.or_else(|| format_of(&path)).ok_or_else(|| anyhow!("unknown archive type (use .saz or .har)"))?;
        let cap = self.capture();
        let ids = if ids.is_empty() { cap.index.find(|_| true) } else { ids };
        let title = format!("Saving {} session(s) to {}", ids.len(), path.display());
        Ok(self.jobs.submit(format!("export:{}", path.display()), title, Priority::Background, true, move |ctx| {
            let n = match format {
                ArchiveFormat::Saz => quena_formats::saz::export(&cap, &ids, &path, &P(ctx)),
                ArchiveFormat::Har => quena_formats::har::export(&cap, &ids, &path, &HarOptions::default(), &P(ctx)),
                ArchiveFormat::Curl => Err(quena_formats::FormatError::Invalid("use Copy → As cURL".into())),
                ArchiveFormat::Pcap => Err(quena_formats::FormatError::Invalid("sessions cannot be saved as a packet capture".into())),
            }
            .map_err(|e| e.to_string())?;
            tracing::info!(target: "quena", "saved {n} session(s) to {}", path.display());
            Ok(())
        }))
    }

    /// Export a sanitized copy of sessions (empty = all in view order): each session is
    /// scrubbed into a temporary capture (see [`crate::sanitize`]), which the normal SAZ / HAR
    /// exporters then write, together with the redaction log (`QUENA-REDACTION.txt` in the
    /// SAZ, `log.comment` and `log._quenaRedaction` in the HAR). The options are remembered
    /// in the settings; when the job is done, the event `export-sanitized` carries
    /// [`SanitizedExport`].
    pub fn export_sanitized(self: &Arc<Self>, ids: Vec<SessionId>, path: PathBuf, format: Option<ArchiveFormat>, opts: SanitizeOptions) -> Result<JobId> {
        self.export_sanitized_as(ids, path, format, opts, true)
    }

    /// A sanitized export for another client (MCP): the user's remembered options stay, and
    /// the UI shows no redaction log.
    pub fn export_sanitized_quietly(self: &Arc<Self>, ids: Vec<SessionId>, path: PathBuf, opts: SanitizeOptions) -> Result<JobId> {
        self.export_sanitized_as(ids, path, None, opts, false)
    }

    fn export_sanitized_as(self: &Arc<Self>, ids: Vec<SessionId>, path: PathBuf, format: Option<ArchiveFormat>, opts: SanitizeOptions, ui: bool) -> Result<JobId> {
        let format = format.or_else(|| format_of(&path)).ok_or_else(|| anyhow!("unknown archive type (use .saz or .har)"))?;
        if matches!(format, ArchiveFormat::Curl | ArchiveFormat::Pcap) {
            return Err(anyhow!("a sanitized export is a .saz or .har file"));
        }
        opts.validate().map_err(|e| anyhow!(e))?;
        if ui {
            let mut s = self.settings.write();
            s.sanitize = SanitizeExportSettings { options: opts.clone(), format: if format == ArchiveFormat::Har { "har".into() } else { "saz".into() } };
            if let Err(e) = s.save(&self.paths.settings) {
                tracing::warn!("settings not saved: {e}");
            }
        }
        let cap = self.capture();
        let ids = if ids.is_empty() { cap.index.find(|_| true) } else { ids };
        let title = format!("Saving {} sanitized session(s) to {}", ids.len(), path.display());
        let tmp_root = self.paths.data.join("sanitize-tmp");
        let body_cfg = self.settings().bodies.to_config();
        let core = self.clone();
        Ok(self.jobs.submit(format!("export-sanitized:{}", path.display()), title, Priority::Background, true, move |ctx| {
            let log = sanitized_export(&cap, &ids, &path, format, opts, &tmp_root, body_cfg, &P(ctx)).map_err(|e| e.to_string())?;
            tracing::info!(target: "quena", "saved {} sanitized session(s) to {} ({} replacement(s))", log.sessions, path.display(), log.total);
            if !ui {
                return Ok(());
            }
            core.emit("export-sanitized", SanitizedExport { path: path.display().to_string(), format: if format == ArchiveFormat::Har { "har".into() } else { "saz".into() }, log });
            Ok(())
        }))
    }

    /// Import an archive into the current session list.
    pub fn import_archive(self: &Arc<Self>, path: PathBuf) -> Result<JobId> {
        let name = path.display().to_string();
        self.import_file(path, name, false, Vec::new(), Vec::new())
    }

    /// Import a packet capture (again), with TLS key logs besides the usual ones (the
    /// setting, files next to the capture). `replace`: sessions of an earlier import of it
    /// (event `pcap-import`), removed once this one succeeded — only if session numbering is
    /// still `numbering`, so the ids still name those sessions. A dropped file's temporary
    /// copy goes once nothing is left to decrypt.
    pub fn import_capture(self: &Arc<Self>, path: PathBuf, name: Option<String>, keylogs: Vec<PathBuf>, replace: Vec<SessionId>, numbering: Option<u64>) -> Result<JobId> {
        if format_of(&path) != Some(ArchiveFormat::Pcap) {
            return Err(anyhow!("{}: not a packet capture", path.display()));
        }
        // A temporary copy only if it really lies in the drop folder (no `..` detours).
        let drop_dir = std::fs::canonicalize(self.paths.data.join("dropped")).ok();
        let dropped = drop_dir.is_some() && std::fs::canonicalize(&path).ok().and_then(|p| p.parent().map(Path::to_path_buf)) == drop_dir;
        let name = name.unwrap_or_else(|| path.display().to_string());
        let replace = match numbering {
            Some(n) if n == self.capture().numbering() => replace,
            _ => Vec::new(),
        };
        self.import_file(path, name, dropped, keylogs, replace)
    }

    /// TLS key logs for a capture: the setting, then files next to the capture.
    fn key_logs_for(&self, capture: &Path) -> Vec<PathBuf> {
        let mut v = Vec::new();
        let setting = self.settings().https.tls_key_log_file;
        if !setting.trim().is_empty() {
            v.push(PathBuf::from(setting.trim()));
        }
        if let (Some(dir), Some(stem), Some(name)) = (capture.parent(), capture.file_stem(), capture.file_name()) {
            let (stem, name) = (stem.to_string_lossy(), name.to_string_lossy());
            for n in [format!("{name}.keys"), format!("{stem}.keys"), format!("{stem}.keylog"), "sslkeylog.log".into(), "sslkeys.log".into()] {
                let p = dir.join(n);
                if p.is_file() && !v.contains(&p) {
                    v.push(p);
                }
            }
        }
        v
    }

    fn import_file(self: &Arc<Self>, path: PathBuf, name: String, remove_after: bool, extra_keylogs: Vec<PathBuf>, replace: Vec<SessionId>) -> Result<JobId> {
        let format = format_of(&path).ok_or_else(|| anyhow!("unknown archive type (use .saz, .har, .pcap or .pcapng)"))?;
        let cap = self.capture();
        let title = format!("Loading {name}");
        let mut keylogs = if format == ArchiveFormat::Pcap { self.key_logs_for(&path) } else { Vec::new() };
        keylogs.extend(extra_keylogs);
        let core = self.clone();
        let numbering = cap.numbering();
        // A temporary copy goes away with the job: after the import, when it fails or panics,
        // and also when the job is cancelled before it starts (the closure is then dropped).
        let remove = remove_after.then(|| RemoveOnDrop(Some(path.clone())));
        Ok(self.jobs.submit(format!("import:{}", path.display()), title, Priority::Background, true, move |ctx| {
            let mut remove = remove;
            let ids = match format {
                ArchiveFormat::Saz => quena_formats::saz::import(&cap, &path, &P(ctx)),
                ArchiveFormat::Har => quena_formats::har::import(&cap, &path, &P(ctx)),
                ArchiveFormat::Curl => Err(quena_formats::FormatError::Invalid("cannot import cURL scripts".into())),
                ArchiveFormat::Pcap => quena_formats::pcap::import_with(&cap, &path, &quena_formats::pcap::PcapOptions { keylogs }, &P(ctx)).map(|r| {
                    // Still the capture and numbering the ids were taken from (checked when
                    // the import was asked for; Remove All or another capture may have come since).
                    if !replace.is_empty() && Arc::ptr_eq(&core.capture(), &cap) && cap.numbering() == numbering {
                        core.remove(replace);
                    }
                    if r.no_keys > 0
                        && let Some(kept) = remove.as_mut().and_then(|rm| rm.0.take())
                    {
                        // Kept for an import with a key log, for an hour.
                        keep_for(kept, KEEP_DROPPED);
                    }
                    core.emit(
                        "pcap-import",
                        CaptureImport {
                            path: path.display().to_string(),
                            name: name.clone(),
                            sessions: r.ids.len(),
                            tls: r.tls,
                            decrypted: r.decrypted,
                            no_keys: r.no_keys,
                            ids: r.ids.clone(),
                            numbering: cap.numbering(),
                        },
                    );
                    r.ids
                }),
            };
            let ids = ids.map_err(|e| e.to_string())?;
            tracing::info!(target: "quena", "loaded {} session(s) from {name}", ids.len());
            Ok(())
        }))
    }

    /// Receive a file dropped onto the window, in chunks: the webview has the file's bytes but
    /// not its path. `offset` must continue the chunks received so far; the last chunk starts
    /// the import, and the temporary copy is removed once it is loaded.
    pub fn drop_chunk(self: &Arc<Self>, id: &str, name: &str, offset: u64, data: &[u8], last: bool) -> Result<Option<JobId>> {
        use std::io::Write;
        if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(anyhow!("invalid drop id"));
        }
        let ext = match format_of(std::path::Path::new(name)) {
            Some(ArchiveFormat::Saz) => "saz",
            Some(ArchiveFormat::Har) => "har",
            Some(ArchiveFormat::Pcap) => "pcapng",
            _ => return Err(anyhow!("{name}: not an archive (use .saz, .har, .pcap or .pcapng)")),
        };
        let dir = self.paths.data.join("dropped");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{id}.{ext}"));
        let end = offset.saturating_add(data.len() as u64);
        if end > MAX_DROP_BYTES {
            let _ = std::fs::remove_file(&path);
            return Err(anyhow!("{name}: larger than {} GiB, open it with File → Load Archive instead", MAX_DROP_BYTES >> 30));
        }
        if quena_body::free_space(&dir).is_some_and(|free| free < data.len() as u64 + MIN_FREE_BYTES) {
            let _ = std::fs::remove_file(&path);
            return Err(anyhow!("{name}: not enough free disk space for a copy of the dropped file"));
        }
        let mut f = if offset == 0 {
            clean_stale(&dir);
            std::fs::File::create(&path)?
        } else {
            let f = std::fs::OpenOptions::new().append(true).open(&path)?;
            let have = f.metadata()?.len();
            if have != offset {
                drop(f);
                let _ = std::fs::remove_file(&path);
                return Err(anyhow!("{name}: chunk at {offset} does not follow {have} bytes"));
            }
            f
        };
        if let Err(e) = f.write_all(data) {
            drop(f);
            let _ = std::fs::remove_file(&path);
            return Err(e.into());
        }
        drop(f);
        if !last {
            return Ok(None);
        }
        self.import_file(path, name.to_string(), true, Vec::new(), Vec::new()).map(Some)
    }
}

/// What a packet capture import found (event `pcap-import`).
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureImport {
    /// The file read (a temporary copy for dropped files) and its name for messages.
    pub path: String,
    pub name: String,
    pub sessions: usize,
    /// TLS connections, those decrypted, and those without secrets in the key logs.
    pub tls: u64,
    pub decrypted: u64,
    pub no_keys: u64,
    /// The new sessions (replaced when the capture is imported again with a key log), and the
    /// session numbering they belong to.
    pub ids: Vec<SessionId>,
    pub numbering: u64,
}

/// How long a dropped capture with encrypted connections is kept for a key log.
const KEEP_DROPPED: std::time::Duration = std::time::Duration::from_secs(3600);

/// Delete a temporary file after `after` (if it is still there).
fn keep_for(path: PathBuf, after: std::time::Duration) {
    let spawned = std::thread::Builder::new().name("quena-drop-expiry".into()).spawn(move || {
        std::thread::sleep(after);
        let _ = std::fs::remove_file(&path);
    });
    if let Err(e) = spawned {
        tracing::warn!("dropped capture kept until the next start: {e}");
    }
}

/// Result of a sanitized export (event `export-sanitized`).
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SanitizedExport {
    pub path: String,
    /// `saz` or `har`.
    pub format: String,
    pub log: RedactionLog,
}

/// Closes and deletes a temporary capture when dropped (also on errors and cancellation).
/// The capture is released before its folder is removed: Windows refuses to delete files
/// that are still open (the body store's files live as long as the capture).
struct TempCapture(Option<Arc<Capture>>, PathBuf);
impl TempCapture {
    fn cap(&self) -> &Arc<Capture> {
        self.0.as_ref().expect("open until dropped")
    }
}
impl Drop for TempCapture {
    fn drop(&mut self) {
        if let Some(cap) = self.0.take() {
            cap.close(true);
        }
        // Handles of the last references may close a moment later (scanner, antivirus).
        for _ in 0..50 {
            if !self.1.exists() || std::fs::remove_dir_all(&self.1).is_ok() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        tracing::warn!(target: "quena", "temporary copy not removed: {}", self.1.display());
    }
}

/// Write a sanitized copy of `ids` from `cap` to `path`; the temporary capture lives under
/// `tmp_root` and is removed afterwards. Returns the redaction log.
#[allow(clippy::too_many_arguments)]
pub fn sanitized_export(
    cap: &Arc<Capture>,
    ids: &[SessionId],
    path: &Path,
    format: ArchiveFormat,
    opts: SanitizeOptions,
    tmp_root: &Path,
    body_cfg: quena_body::BodyConfig,
    p: &dyn quena_formats::Progress,
) -> Result<RedactionLog> {
    // Copies left behind by a crash: nothing to recover there.
    remove_older_dirs(tmp_root, std::time::Duration::from_secs(3600));
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let tmp_dir = tmp_root.join(format!("{}-{nanos}", std::process::id()));
    let tmp = TempCapture(Some(Capture::open(&tmp_dir, body_cfg, true)?), tmp_dir);
    let mut z = Sanitizer::new(opts);
    // Scrubbing is the first half of the work, writing the archive the second.
    let total = ids.len() as u64 * 2;
    // Scrubbing runs on a worker thread; this thread watches `p` (which need not be `Sync`)
    // and passes a cancellation on through a flag the sanitizer checks inside large bodies.
    let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
    z.set_cancel(cancel.clone());
    let done = std::sync::atomic::AtomicU64::new(0);
    let tmp_cap = tmp.cap();
    let result = std::thread::scope(|sc| {
        let worker = sc.spawn(|| {
            let mut copied = Vec::with_capacity(ids.len());
            for id in ids {
                if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                    return None;
                }
                done.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(d) = cap.detail(*id) else { continue };
                let Some((req, resp)) = cap.bodies_of(*id) else { continue };
                let s = z.session(&d, &req, &resp);
                if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                    return None;
                }
                let (rb, sb) = (tmp_cap.bodies.store_bytes(&s.request), tmp_cap.bodies.store_bytes(&s.response));
                copied.push(tmp_cap.insert(s.detail, rb, sb));
            }
            Some((copied, z))
        });
        while !worker.is_finished() {
            if p.cancelled() {
                cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            p.progress(done.load(std::sync::atomic::Ordering::Relaxed).saturating_sub(1), total);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        worker.join()
    });
    let Some((copied, z)) = result.map_err(|_| anyhow!("sanitizing failed (internal error)"))? else {
        return Err(anyhow!("cancelled"));
    };
    if p.cancelled() {
        return Err(anyhow!("cancelled"));
    }
    let log = z.into_log();
    struct Half<'a>(&'a dyn quena_formats::Progress, u64);
    impl quena_formats::Progress for Half<'_> {
        fn cancelled(&self) -> bool {
            self.0.cancelled()
        }
        fn progress(&self, done: u64, total: u64) {
            let t = total.max(1);
            self.0.progress(self.1 + done * self.1 / t, self.1 * 2);
        }
    }
    let half = Half(p, ids.len() as u64);
    match format {
        ArchiveFormat::Saz => {
            let text = log.to_text();
            quena_formats::saz::export_with(tmp.cap(), &copied, path, &[("QUENA-REDACTION.txt", text.as_bytes())], &half)?;
        }
        ArchiveFormat::Har => {
            let o = HarOptions { comment: Some(log.summary_line()), extra: vec![("_quenaRedaction".into(), serde_json::to_value(&log)?)], ..HarOptions::default() };
            quena_formats::har::export(tmp.cap(), &copied, path, &o, &half)?;
        }
        ArchiveFormat::Curl | ArchiveFormat::Pcap => return Err(anyhow!("a sanitized export is a .saz or .har file")),
    }
    p.progress(total, total);
    Ok(log)
}

fn remove_older_dirs(dir: &std::path::Path, age: std::time::Duration) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let old = e.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|a| a > age);
        if old && e.file_type().is_ok_and(|t| t.is_dir()) {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

/// Largest file accepted by drag and drop (the webview sends a copy of its bytes).
pub const MAX_DROP_BYTES: u64 = 8 << 30;
/// Disk space that must stay free while a dropped file is copied.
const MIN_FREE_BYTES: u64 = 256 << 20;

/// Removes a file when dropped.
/// Deletes a temporary file when dropped, unless it was taken out (`None`).
struct RemoveOnDrop(Option<PathBuf>);
impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if let Some(p) = &self.0 {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Remove copies of dropped files left behind by an earlier run (crash, cancelled drop).
fn clean_stale(dir: &std::path::Path) {
    remove_older(dir, std::time::Duration::from_secs(3600));
}

/// At startup: remove what an earlier run left in the drop folder (partial transfers when the
/// app quit, crashes). Only files not written for a minute, so a transfer that another running
/// instance is receiving right now is left alone.
pub(crate) fn clean_dropped_at_startup(data_dir: &std::path::Path) {
    remove_older(&data_dir.join("dropped"), std::time::Duration::from_secs(60));
}

fn remove_older(dir: &std::path::Path, age: std::time::Duration) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let old = e.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|a| a > age);
        if old && e.file_type().is_ok_and(|t| t.is_file()) {
            let _ = std::fs::remove_file(e.path());
        }
    }
}
