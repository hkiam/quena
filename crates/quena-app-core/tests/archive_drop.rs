//! Files dropped onto the window arrive in chunks and are imported from a temporary copy.
use quena_app_core::{AppCore, Paths};
use std::time::{Duration, Instant};

fn core() -> (tempfile::TempDir, std::sync::Arc<AppCore>) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("settings.json"), r#"{"proxy":{"actAsSystemProxy":false,"captureOnStartup":false}}"#).unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    (dir, core)
}

#[test]
fn dropped_har_is_loaded_in_chunks_and_the_copy_removed() {
    let (dir, core) = core();
    let har = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../app/e2e/fixtures/two-sessions.har")).unwrap();
    let parts: Vec<&[u8]> = har.chunks(har.len() / 3 + 1).collect();
    let mut offset = 0u64;
    let mut job = None;
    for (i, p) in parts.iter().enumerate() {
        job = core.drop_chunk("t-1", "trace ä.har", offset, p, i + 1 == parts.len()).unwrap();
        assert_eq!(job.is_some(), i + 1 == parts.len());
        offset += p.len() as u64;
    }
    let job = core.jobs.get(job.unwrap()).unwrap();
    let t0 = Instant::now();
    while !matches!(format!("{:?}", job.status()).as_str(), "Done" | "Failed" | "Cancelled") {
        assert!(t0.elapsed() < Duration::from_secs(10), "import did not finish");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(format!("{:?}", job.status()), "Done", "{:?}", job.snapshot().error);
    assert_eq!(core.capture().index.len(), 4);
    assert!(!dir.path().join("dropped/t-1.har").exists(), "temporary copy removed");
}

#[test]
fn dropped_chunks_are_checked() {
    let (dir, core) = core();
    assert!(core.drop_chunk("../x", "a.har", 0, b"{}", false).is_err(), "id must not be a path");
    assert!(core.drop_chunk("t-2", "notes.txt", 0, b"hi", true).is_err(), "only archives");
    core.drop_chunk("t-2", "a.har", 0, b"{\"log\":", false).unwrap();
    assert!(core.drop_chunk("t-2", "a.har", 3, b"{}", true).is_err(), "gap or overlap is rejected");
    assert!(!dir.path().join("dropped/t-2.har").exists(), "a broken transfer leaves nothing behind");
    assert!(core.drop_chunk("t-2", "a.har", 7, b"{}", true).is_err(), "no continuation after an error");
}
