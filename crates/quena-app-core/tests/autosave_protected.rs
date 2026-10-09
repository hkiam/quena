//! AutoSave (only when something changed, rotation) and password-protected archives.

use quena_app_core::{AppCore, Paths};
use quena_model::{RequestHead, SessionDetail};
use std::sync::Arc;
use std::time::Duration;

fn core() -> (tempfile::TempDir, Arc<AppCore>) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("settings.json"), r#"{"proxy":{"port":0,"actAsSystemProxy":false,"captureOnStartup":false}}"#).unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    (dir, core)
}

fn add(core: &AppCore, url: &str) {
    let cap = core.capture();
    let mut d = SessionDetail::default();
    d.request = RequestHead { method: "GET".into(), url: url.into(), ..Default::default() };
    d.refresh_summary();
    let (a, b) = (cap.bodies.store_bytes(b""), cap.bodies.store_bytes(b"ok"));
    cap.insert(d, a, b);
    cap.index.tick();
}

fn wait_file(p: &std::path::Path) {
    let t = std::time::Instant::now();
    while !p.exists() {
        assert!(t.elapsed() < Duration::from_secs(20), "{} not written", p.display());
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn autosave_saves_changes_and_keeps_the_newest() {
    let (_dir, core) = core();
    let mut s = core.settings();
    s.autosave.enabled = true;
    s.autosave.keep = 2;
    core.update_settings(s).unwrap();
    // Nothing captured: nothing saved.
    assert_eq!(core.autosave_now(false).unwrap(), None);
    let mut written = Vec::new();
    for i in 0..3 {
        add(&core, &format!("http://example.com/{i}"));
        let p = core.autosave_now(false).unwrap().expect("a change is saved");
        wait_file(&p);
        written.push(p);
        // Unchanged: no new file.
        assert_eq!(core.autosave_now(false).unwrap(), None);
        std::thread::sleep(Duration::from_millis(1100)); // distinct file names
    }
    let left: Vec<_> = std::fs::read_dir(core.autosave_dir()).unwrap().flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "saz")).collect();
    assert_eq!(left.len(), 2, "{left:?}");
    assert!(!written[0].exists() && written[2].exists());
    // The last archive holds all three sessions.
    core.capture().clear();
    let job = core.import_archive(written[2].clone()).unwrap();
    core.jobs.wait(job, Duration::from_secs(20)).unwrap();
    core.capture().index.tick();
    assert_eq!(core.capture().index.len(), 3);
}

#[test]
fn protected_archives() {
    let (dir, core) = core();
    add(&core, "http://example.com/secret");
    let path = dir.path().join("p.saz");
    assert!(core.export_archive_protected(vec![], dir.path().join("p.har"), None, Some("pw".into())).is_err(), "HAR cannot be protected");
    let job = core.export_archive_protected(vec![], path.clone(), None, Some("pw".into())).unwrap();
    core.jobs.wait(job, Duration::from_secs(20)).unwrap();
    core.capture().clear();
    let e = core.import_archive(path.clone()).unwrap_err().to_string();
    assert!(e.contains("protected with a password"), "{e}");
    let e = core.import_archive_protected(path.clone(), Some("nope".into())).unwrap_err().to_string();
    assert!(e.contains("wrong password"), "{e}");
    let job = core.import_archive_protected(path, Some("pw".into())).unwrap();
    core.jobs.wait(job, Duration::from_secs(20)).unwrap();
    core.capture().index.tick();
    assert_eq!(core.capture().index.len(), 1);
}

/// A save that fails (here: a folder that cannot be written) keeps the older archives and
/// is tried again without a further change.
#[cfg(unix)]
#[test]
fn autosave_failure_keeps_older_archives() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, core) = core();
    let folder = dir.path().join("ro");
    std::fs::create_dir(&folder).unwrap();
    let old = folder.join("autosave-20000101-000000Z.saz");
    std::fs::write(&old, b"old").unwrap();
    let mut s = core.settings();
    s.autosave.enabled = true;
    s.autosave.keep = 1;
    s.autosave.folder = folder.display().to_string();
    core.update_settings(s).unwrap();
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o555)).unwrap();
    add(&core, "http://example.com/a");
    let p = core.autosave_now(false).unwrap().expect("a change is saved");
    let job = core.jobs.by_key(&format!("export:{}", p.display())).expect("the save job").id;
    let _ = core.jobs.wait(job, Duration::from_secs(20));
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(old.exists(), "the older archive stays when the new one could not be written");
    assert!(core.autosave_now(false).unwrap().is_some(), "tried again although nothing changed");
}
