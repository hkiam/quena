//! Load/Save archives (SAZ, HAR) as background jobs.

use crate::AppCore;
use anyhow::{Result, anyhow};
use piper_formats::har::HarOptions;
use piper_jobs::{JobCtx, JobId, Priority};
use piper_model::SessionId;
use std::path::PathBuf;
use std::sync::Arc;

struct P<'a>(&'a JobCtx);
impl piper_formats::Progress for P<'_> {
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
}

fn format_of(path: &std::path::Path) -> Option<ArchiveFormat> {
    match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
        "saz" | "zip" => Some(ArchiveFormat::Saz),
        "har" | "json" => Some(ArchiveFormat::Har),
        "sh" | "txt" => Some(ArchiveFormat::Curl),
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
                ArchiveFormat::Saz => piper_formats::saz::export(&cap, &ids, &path, &P(ctx)),
                ArchiveFormat::Har => piper_formats::har::export(&cap, &ids, &path, &HarOptions::default(), &P(ctx)),
                ArchiveFormat::Curl => Err(piper_formats::FormatError::Invalid("use Copy → As cURL".into())),
            }
            .map_err(|e| e.to_string())?;
            tracing::info!(target: "piper", "saved {n} session(s) to {}", path.display());
            Ok(())
        }))
    }

    /// Import an archive into the current session list.
    pub fn import_archive(self: &Arc<Self>, path: PathBuf) -> Result<JobId> {
        let format = format_of(&path).ok_or_else(|| anyhow!("unknown archive type (use .saz or .har)"))?;
        let cap = self.capture();
        let title = format!("Loading {}", path.display());
        Ok(self.jobs.submit(format!("import:{}", path.display()), title, Priority::Background, true, move |ctx| {
            let ids = match format {
                ArchiveFormat::Saz => piper_formats::saz::import(&cap, &path, &P(ctx)),
                ArchiveFormat::Har => piper_formats::har::import(&cap, &path, &P(ctx)),
                ArchiveFormat::Curl => Err(piper_formats::FormatError::Invalid("cannot import cURL scripts".into())),
            }
            .map_err(|e| e.to_string())?;
            tracing::info!(target: "piper", "loaded {} session(s) from {}", ids.len(), path.display());
            Ok(())
        }))
    }
}
