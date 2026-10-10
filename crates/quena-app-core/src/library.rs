//! Snapshot library: archives kept in `library/` in the data folder, in folders, to save the
//! sessions of an investigation, open them again (each a source of its own in the navigator)
//! and add sessions to them later.

use crate::AppCore;
use crate::archive::ArchiveFormat;
use anyhow::{Result, anyhow, bail};
use quena_jobs::JobId;
use quena_model::SessionId;
use serde::Serialize;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

/// Folders below the library root at most.
const MAX_DEPTH: usize = 4;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LibraryEntry {
    /// Path below the library root with `/` (`Release 1.4/login.saz`).
    pub path: String,
    pub name: String,
    pub folder: bool,
    pub size: u64,
    /// Unix seconds.
    pub modified: i64,
    /// Folder depth (0: in the root).
    pub depth: usize,
}

/// A path below the root: plain names only (no `..`, no absolute path, no drive).
fn safe_rel(rel: &str) -> Result<PathBuf> {
    let rel = rel.trim().trim_matches('/');
    let p = Path::new(rel);
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(n) => {
                let n = n.to_string_lossy();
                // Also what Windows cannot store: device names, a trailing dot or space.
                let stem = n.split('.').next().unwrap_or("").trim_end().to_ascii_uppercase();
                let device = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL") || ((stem.starts_with("COM") || stem.starts_with("LPT")) && stem.len() == 4 && stem.as_bytes()[3].is_ascii_digit());
                if n.starts_with('.') || n.ends_with(['.', ' ']) || device || n.contains(['\\', ':', '*', '?', '"', '<', '>', '|']) || n.chars().any(char::is_control) {
                    bail!("invalid name in the library: {n}");
                }
                out.push(&*n);
            }
            _ => bail!("invalid path in the library: {rel}"),
        }
    }
    if out.components().count() > MAX_DEPTH + 1 {
        bail!("folders go {MAX_DEPTH} levels deep at most");
    }
    Ok(out)
}

fn is_archive(p: &Path) -> bool {
    p.extension().and_then(|e| e.to_str()).is_some_and(|e| matches!(e.to_ascii_lowercase().as_str(), "saz" | "har"))
}

impl AppCore {
    pub fn library_dir(&self) -> PathBuf {
        self.paths.data.join("library")
    }

    /// The absolute path of `rel` in the library.
    pub fn library_path(&self, rel: &str) -> Result<PathBuf> {
        Ok(self.library_dir().join(safe_rel(rel)?))
    }

    /// Folders and archives of the library, folders first, by name.
    pub fn library_list(&self) -> Vec<LibraryEntry> {
        fn walk(root: &Path, dir: &Path, depth: usize, out: &mut Vec<LibraryEntry>) {
            let Ok(rd) = std::fs::read_dir(dir) else { return };
            let mut items: Vec<_> = rd.flatten().filter(|e| !e.file_name().to_string_lossy().starts_with('.')).collect();
            items.sort_by_key(|e| (!e.path().is_dir(), e.file_name().to_string_lossy().to_lowercase()));
            for e in items {
                let p = e.path();
                let meta = e.metadata().ok();
                let rel = p.strip_prefix(root).map(|r| r.to_string_lossy().replace('\\', "/")).unwrap_or_default();
                let modified = meta.as_ref().and_then(|m| m.modified().ok()).and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64).unwrap_or(0);
                if p.is_dir() {
                    out.push(LibraryEntry { path: rel, name: e.file_name().to_string_lossy().into_owned(), folder: true, size: 0, modified, depth });
                    if depth < MAX_DEPTH {
                        walk(root, &p, depth + 1, out);
                    }
                } else if is_archive(&p) {
                    out.push(LibraryEntry { path: rel, name: e.file_name().to_string_lossy().into_owned(), folder: false, size: meta.map(|m| m.len()).unwrap_or(0), modified, depth });
                }
            }
        }
        let root = self.library_dir();
        let mut out = Vec::new();
        walk(&root, &root, 0, &mut out);
        out
    }

    /// Save `ids` (empty: all in view order) as `name` (`.saz` added) in `folder`; a protected
    /// archive with `password`. Refuses to overwrite.
    pub fn library_save(self: &Arc<Self>, ids: Vec<SessionId>, folder: &str, name: &str, password: Option<String>) -> Result<(JobId, String)> {
        let name = name.trim();
        if name.is_empty() {
            bail!("a name is needed");
        }
        let file = if is_archive(Path::new(name)) { name.to_string() } else { format!("{name}.saz") };
        let rel = if folder.trim().is_empty() { file } else { format!("{}/{file}", folder.trim().trim_matches('/')) };
        let path = self.library_path(&rel)?;
        // Also one being written right now (its `.part`).
        if path.exists() || path.with_extension("saz.part").exists() || path.with_extension("har.part").exists() {
            bail!("{rel} exists already in the library; choose another name or add the sessions to it");
        }
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        Ok((self.export_archive_protected(ids, path, None, password)?, rel))
    }

    /// Add `ids` to the library's SAZ archive `rel`.
    pub fn library_add(self: &Arc<Self>, ids: Vec<SessionId>, rel: &str) -> Result<JobId> {
        let path = self.library_path(rel)?;
        if !path.is_file() || crate::archive::format_of_path(&path) != Some(ArchiveFormat::Saz) {
            bail!("{rel}: sessions can be added to a .saz archive of the library");
        }
        if ids.is_empty() {
            bail!("select the sessions to add");
        }
        // One addition per snapshot at a time (two would write the same copy); another one is
        // refused instead of merged into the running job.
        let canon = safe_rel(rel)?.to_string_lossy().replace('\\', "/");
        let key = format!("library-add:{canon}");
        if self.jobs.by_key(&key).is_some_and(|j| matches!(j.status(), quena_jobs::JobStatus::Queued | quena_jobs::JobStatus::Running)) {
            bail!("sessions are being added to {rel} already; try again when that is done");
        }
        let cap = self.capture();
        let title = format!("Adding {} session(s) to {rel}", ids.len());
        Ok(self.jobs.submit(key, title, quena_jobs::Priority::Background, true, move |ctx| {
            struct P<'a>(&'a quena_jobs::JobCtx);
            impl quena_formats::Progress for P<'_> {
                fn cancelled(&self) -> bool {
                    self.0.cancelled()
                }
                fn progress(&self, done: u64, total: u64) {
                    self.0.progress(done, total)
                }
            }
            quena_formats::saz::append(&cap, &ids, &path, &P(ctx)).map(|_| ()).map_err(|e| e.to_string())
        }))
    }

    pub fn library_mkdir(&self, rel: &str) -> Result<()> {
        let p = self.library_path(rel)?;
        if p == self.library_dir() {
            bail!("a folder name is needed");
        }
        std::fs::create_dir_all(p)?;
        Ok(())
    }

    /// Rename `rel` to `name` in its folder.
    pub fn library_rename(&self, rel: &str, name: &str) -> Result<String> {
        let from = self.library_path(rel)?;
        if !from.exists() || from == self.library_dir() {
            bail!("{rel} is not in the library");
        }
        let mut name = name.trim().to_string();
        if name.contains(['/', '\\']) {
            bail!("a name without folders (move archives in the file manager: Open folder)");
        }
        // An archive keeps its kind: `.saz` stays `.saz`.
        if from.is_file() {
            let ext = from.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
            let lower = name.to_ascii_lowercase();
            if let Some(stripped) = [".saz", ".har"].iter().find_map(|e| lower.ends_with(e).then(|| name[..name.len() - e.len()].to_string())) {
                name = stripped;
            }
            name = format!("{name}.{ext}");
        }
        let parent = Path::new(rel.trim_matches('/')).parent().map(|p| p.to_string_lossy().replace('\\', "/")).unwrap_or_default();
        let to_rel = if parent.is_empty() { name.clone() } else { format!("{parent}/{name}") };
        let to = self.library_path(&to_rel)?;
        // Only the case changes (one file on macOS and Windows): no clash.
        if to.exists() && to != from && to_rel.to_lowercase() != rel.trim_matches('/').to_lowercase() {
            bail!("{to_rel} exists already");
        }
        std::fs::rename(from, to)?;
        Ok(to_rel)
    }

    /// Delete an archive, or an empty folder.
    pub fn library_delete(&self, rel: &str) -> Result<()> {
        let p = self.library_path(rel)?;
        if p == self.library_dir() || !p.exists() {
            bail!("{rel} is not in the library");
        }
        if p.is_dir() {
            std::fs::remove_dir(&p).map_err(|_| anyhow!("{rel}: only an empty folder can be deleted"))?;
        } else {
            std::fs::remove_file(&p)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn library_paths_stay_inside() {
        assert_eq!(safe_rel("a/b.saz").unwrap(), PathBuf::from("a/b.saz"));
        assert!(safe_rel("../x.saz").is_err());
        assert!(safe_rel("/etc/passwd").is_ok_and(|p| p == PathBuf::from("etc/passwd")), "leading slashes are trimmed");
        assert!(safe_rel("a/../../x").is_err());
        assert!(safe_rel("a/.hidden").is_err());
        assert!(safe_rel("C:/x").is_err());
        assert!(safe_rel("1/2/3/4/5/6.saz").is_err());
        assert!(safe_rel("NUL.saz").is_err() && safe_rel("a/com1").is_err() && safe_rel("x. ").is_err() && safe_rel("x.").is_err());
        assert!(safe_rel("Console.saz").is_ok());
    }
}
