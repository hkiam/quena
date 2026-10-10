//! Snapshot library: save sessions in folders, add to a snapshot, open it as a source of its
//! own (navigator: group by source), rename and delete.

use quena_app_core::{AppCore, Paths};
use quena_index::GroupBy;
use quena_model::{RequestHead, ResponseHead, SessionDetail};
use std::sync::Arc;
use std::time::Duration;

fn add(core: &AppCore, url: &str) {
    let cap = core.capture();
    let mut d = SessionDetail::default();
    d.request = RequestHead { method: "GET".into(), url: url.into(), ..Default::default() };
    d.response = Some(ResponseHead { status: 200, ..Default::default() });
    d.refresh_summary();
    let (a, b) = (cap.bodies.store_bytes(b""), cap.bodies.store_bytes(b"ok"));
    cap.insert(d, a, b);
    cap.index.tick();
}

#[test]
fn snapshots_in_the_library() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("settings.json"), r#"{"proxy":{"port":0,"actAsSystemProxy":false,"captureOnStartup":false}}"#).unwrap();
    let core: Arc<AppCore> = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    add(&core, "http://a.example/1");
    add(&core, "http://a.example/2");
    let wait = |j| core.jobs.wait(j, Duration::from_secs(20)).unwrap();

    let (job, rel) = core.library_save(vec![1], "Release 1.4", "login", None).unwrap();
    wait(job);
    assert_eq!(rel, "Release 1.4/login.saz");
    assert!(core.library_save(vec![1], "Release 1.4", "login", None).is_err(), "no overwriting");
    assert!(core.library_save(vec![1], "../out", "x", None).is_err());
    let list = core.library_list();
    assert_eq!(list.iter().map(|e| (e.path.as_str(), e.folder)).collect::<Vec<_>>(), [("Release 1.4", true), ("Release 1.4/login.saz", false)]);

    // Add the second session, then open the snapshot: two sessions from it.
    wait(core.library_add(vec![2], &rel).unwrap());
    let job = core.import_archive(core.library_path(&rel).unwrap()).unwrap();
    wait(job);
    let cap = core.capture();
    cap.index.tick();
    let from: Vec<_> = cap.index.find_all(|s| s.archive == "login.saz");
    assert_eq!(from.len(), 2, "{:?}", cap.index.find_all(|_| true));
    let groups = core.nav_groups(GroupBy::Source);
    let names: Vec<&str> = groups.groups.iter().map(|g| g.label.as_str()).collect();
    assert!(names.contains(&"live") && names.contains(&"login.saz"), "{names:?}");

    let to = core.library_rename(&rel, "login flow").unwrap();
    assert_eq!(to, "Release 1.4/login flow.saz");
    assert!(core.library_delete("Release 1.4").is_err(), "a folder with archives stays");
    core.library_delete(&to).unwrap();
    core.library_delete("Release 1.4").unwrap();
    assert!(core.library_list().is_empty());
}
