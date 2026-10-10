//! AutoSave: the capture is written to an archive every few minutes while it changes, so a
//! crash, a full disk or a careless *Remove All* loses at most the last minutes. The newest
//! `keep` files are kept; older ones are removed.

use crate::AppCore;
use crate::archive::ArchiveFormat;
use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// File names: `autosave-YYYYMMDD-HHMMSSZ.saz` (UTC).
const PREFIX: &str = "autosave-";

#[derive(Default)]
pub(crate) struct State {
    last: Option<Instant>,
    /// What the capture looked like at the last save (capture, numbering, sessions, version).
    token: Option<(usize, u64, usize, u64)>,
}

impl AppCore {
    /// Folder of the AutoSave archives (the setting, else `autosave` in the data folder).
    pub fn autosave_dir(&self) -> PathBuf {
        let f = self.settings().autosave.folder.trim().to_string();
        if f.is_empty() { self.paths.data.join("autosave") } else { PathBuf::from(f) }
    }

    /// Called every second: saves when AutoSave is on, the interval has passed and the
    /// capture changed since the last save.
    pub fn autosave_tick(self: &Arc<Self>) {
        let s = self.settings().autosave;
        if !s.enabled {
            return;
        }
        let due = self.autosave.lock().last.is_none_or(|l| l.elapsed() >= Duration::from_secs(u64::from(s.interval_min.max(1)) * 60));
        if due && let Err(e) = self.autosave_now(false) {
            tracing::warn!(target: "quena", "AutoSave failed: {e:#}");
        }
    }

    /// Save now (`force`: also when nothing changed). Returns the archive's path, or `None`
    /// when there was nothing (new) to save.
    pub fn autosave_now(self: &Arc<Self>, force: bool) -> Result<Option<PathBuf>> {
        let cap = self.capture();
        let token = (Arc::as_ptr(&cap) as usize, cap.numbering(), cap.index.len(), cap.index.version());
        {
            let mut st = self.autosave.lock();
            st.last = Some(Instant::now());
            if cap.index.len() == 0 || (!force && st.token == Some(token)) {
                return Ok(None);
            }
            st.token = Some(token);
        }
        let dir = self.autosave_dir();
        if let Err(e) = std::fs::create_dir_all(&dir) {
            self.autosave.lock().token = None;
            return Err(e.into());
        }
        // UTC (the name sorts in time order across daylight saving changes).
        let t = time::OffsetDateTime::now_utc();
        let name = format!("{PREFIX}{:04}{:02}{:02}-{:02}{:02}{:02}Z.saz", t.year(), t.month() as u8, t.day(), t.hour(), t.minute(), t.second());
        let path = dir.join(name);
        // All sessions, also those a filter hides, unless only the visible ones are wanted.
        let ids = if self.settings().autosave.only_visible { cap.index.matching() } else { cap.index.find_all(|_| true) };
        if ids.is_empty() {
            self.autosave.lock().token = None;
            return Ok(None);
        }
        let keep = self.settings().autosave.keep.max(1) as usize;
        let core = Arc::downgrade(self);
        // Older archives go only once the new one is written: a full disk must not eat them.
        let done = move |ok: bool| {
            if ok {
                rotate(&dir, keep);
            } else if let Some(core) = core.upgrade() {
                // Try again at the next interval, also without a further change.
                core.autosave.lock().token = None;
            }
        };
        if let Err(e) = self.export_archive_then(ids, path.clone(), Some(ArchiveFormat::Saz), None, done) {
            self.autosave.lock().token = None;
            return Err(e);
        }
        Ok(Some(path))
    }
}

/// Keep the newest `keep` AutoSave archives in `dir`.
fn rotate(dir: &std::path::Path, keep: usize) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut old: Vec<PathBuf> =
        rd.flatten().map(|e| e.path()).filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with(PREFIX) && n.ends_with(".saz"))).collect();
    old.sort();
    let n = old.len().saturating_sub(keep);
    for p in &old[..n] {
        if let Err(e) = std::fs::remove_file(p) {
            tracing::warn!(target: "quena", "AutoSave: could not remove {}: {e}", p.display());
        }
    }
}
