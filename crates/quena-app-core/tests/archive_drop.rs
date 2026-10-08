//! Files dropped onto the window arrive in chunks and are imported from a temporary copy.
use quena_app_core::{AppCore, Paths};
use std::time::{Duration, Instant};

fn core() -> (tempfile::TempDir, std::sync::Arc<AppCore>) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("settings.json"),
        r#"{"proxy":{"actAsSystemProxy":false,"captureOnStartup":false}}"#,
    )
    .unwrap();
    let core = AppCore::new(
        Paths::at(dir.path().to_path_buf()),
        quena_app_core::logbuf::LogBuffer::new(100),
    )
    .unwrap();
    (dir, core)
}

#[test]
fn dropped_har_is_loaded_in_chunks_and_the_copy_removed() {
    let (dir, core) = core();
    let har = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../app/e2e/fixtures/two-sessions.har"
    ))
    .unwrap();
    let parts: Vec<&[u8]> = har.chunks(har.len() / 3 + 1).collect();
    let mut offset = 0u64;
    let mut job = None;
    for (i, p) in parts.iter().enumerate() {
        job = core
            .drop_chunk("t-1", "trace ä.har", offset, p, i + 1 == parts.len())
            .unwrap();
        assert_eq!(job.is_some(), i + 1 == parts.len());
        offset += p.len() as u64;
    }
    let job = core.jobs.get(job.unwrap()).unwrap();
    let t0 = Instant::now();
    while !matches!(
        format!("{:?}", job.status()).as_str(),
        "Done" | "Failed" | "Cancelled"
    ) {
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "import did not finish"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        format!("{:?}", job.status()),
        "Done",
        "{:?}",
        job.snapshot().error
    );
    assert_eq!(core.capture().index.len(), 4);
    assert!(
        !dir.path().join("dropped/t-1.har").exists(),
        "temporary copy removed"
    );
}

#[test]
fn dropped_chunks_are_checked() {
    let (dir, core) = core();
    assert!(
        core.drop_chunk("../x", "a.har", 0, b"{}", false).is_err(),
        "id must not be a path"
    );
    assert!(
        core.drop_chunk("t-2", "notes.txt", 0, b"hi", true).is_err(),
        "only archives"
    );
    core.drop_chunk("t-2", "a.har", 0, b"{\"log\":", false)
        .unwrap();
    assert!(
        core.drop_chunk("t-2", "a.har", 3, b"{}", true).is_err(),
        "gap or overlap is rejected"
    );
    assert!(
        !dir.path().join("dropped/t-2.har").exists(),
        "a broken transfer leaves nothing behind"
    );
    assert!(
        core.drop_chunk("t-2", "a.har", 7, b"{}", true).is_err(),
        "no continuation after an error"
    );
}

fn wait_done(core: &AppCore, id: quena_jobs::JobId) -> String {
    let job = core.jobs.get(id).unwrap();
    let t0 = Instant::now();
    loop {
        let s = format!("{:?}", job.status());
        if matches!(s.as_str(), "Done" | "Failed" | "Cancelled") {
            return s;
        }
        assert!(t0.elapsed() < Duration::from_secs(10), "job did not finish");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn leftovers_are_removed_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let dropped = dir.path().join("dropped");
    std::fs::create_dir_all(&dropped).unwrap();
    let old = dropped.join("quit-mid-transfer.har");
    std::fs::write(&old, b"{\"log\":").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&old)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - Duration::from_secs(600))
        .unwrap();
    let fresh = dropped.join("other-instance.har");
    std::fs::write(&fresh, b"{").unwrap();
    std::fs::write(
        dir.path().join("settings.json"),
        r#"{"proxy":{"actAsSystemProxy":false,"captureOnStartup":false}}"#,
    )
    .unwrap();
    let _core = AppCore::new(
        Paths::at(dir.path().to_path_buf()),
        quena_app_core::logbuf::LogBuffer::new(100),
    )
    .unwrap();
    assert!(!old.exists(), "partial copy of an earlier run removed");
    assert!(fresh.exists(), "a file written just now is left alone");
}

#[test]
fn oversized_drops_are_refused_and_removed() {
    let (dir, core) = core();
    core.drop_chunk("t-3", "big.har", 0, b"{", false).unwrap();
    let err = core
        .drop_chunk(
            "t-3",
            "big.har",
            quena_app_core::archive::MAX_DROP_BYTES,
            b"}",
            true,
        )
        .unwrap_err();
    assert!(err.to_string().contains("larger than 8 GiB"), "{err}");
    assert!(!dir.path().join("dropped/t-3.har").exists());
}

#[test]
fn the_copy_goes_away_when_the_import_fails_or_is_cancelled() {
    let (dir, core) = core();
    let job = core
        .drop_chunk("t-4", "broken.har", 0, b"not json at all", true)
        .unwrap()
        .unwrap();
    assert_eq!(wait_done(&core, job), "Failed");
    assert!(
        !dir.path().join("dropped/t-4.har").exists(),
        "removed after a failed import"
    );
    let har = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../app/e2e/fixtures/two-sessions.har"
    ))
    .unwrap();
    let job = core
        .drop_chunk("t-5", "x.har", 0, &har, true)
        .unwrap()
        .unwrap();
    core.jobs.cancel(job);
    wait_done(&core, job);
    // Whether it was cancelled before or while running, no copy stays behind.
    let t0 = Instant::now();
    while dir.path().join("dropped/t-5.har").exists() {
        assert!(t0.elapsed() < Duration::from_secs(5), "copy left behind");
        std::thread::sleep(Duration::from_millis(20));
    }
}
