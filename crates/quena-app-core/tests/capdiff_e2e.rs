//! Comparing two archives loaded into the list.

use quena_app_core::capdiff::{CompareOptions, DiffKind, Source, to_markdown};
use quena_app_core::{AppCore, Paths};
use std::time::Duration;

fn entry(url: &str, status: u16, body: &str, ms: u32, extra_header: Option<(&str, &str)>) -> serde_json::Value {
    let mut headers = vec![serde_json::json!({"name": "Content-Type", "value": "application/json"}), serde_json::json!({"name": "Date", "value": format!("{ms}")})];
    if let Some((n, v)) = extra_header {
        headers.push(serde_json::json!({"name": n, "value": v}));
    }
    serde_json::json!({
        "startedDateTime": "2026-10-01T10:00:00.000Z",
        "time": ms,
        "request": {"method": "GET", "url": url, "httpVersion": "HTTP/1.1", "headers": [], "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0},
        "response": {"status": status, "statusText": "", "httpVersion": "HTTP/1.1", "headers": headers, "cookies": [], "content": {"size": body.len(), "mimeType": "application/json", "text": body}, "redirectURL": "", "headersSize": -1, "bodySize": body.len()},
        "cache": {}, "timings": {"send": 0, "wait": ms, "receive": 0}
    })
}

fn har(path: &std::path::Path, entries: Vec<serde_json::Value>) {
    let h = serde_json::json!({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": entries}});
    std::fs::write(path, serde_json::to_vec(&h).unwrap()).unwrap();
}

#[test]
fn two_archives_compared() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("settings.json"), r#"{"proxy":{"port":0,"actAsSystemProxy":false,"captureOnStartup":false}}"#).unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    let (a, b) = (dir.path().join("release-1.har"), dir.path().join("release-2.har"));
    har(&a, vec![
        entry("https://api.example.com/users/1", 200, r#"{"id":1,"name":"a"}"#, 50, None),
        entry("https://api.example.com/users/1/orders?page=1", 200, "[]", 40, None),
        entry("https://api.example.com/health", 200, "{}", 10, None),
        entry("https://api.example.com/legacy", 200, "{}", 10, None),
    ]);
    har(&b, vec![
        // Other id, same content: the same request.
        entry("https://api.example.com/users/2", 200, r#"{ "name":"a", "id":1 }"#, 55, None),
        entry("https://api.example.com/users/2/orders?page=7", 500, "{\"error\":1}", 40, None),
        entry("https://api.example.com/health", 200, "{}", 900, Some(("Vary", "Origin"))),
        entry("https://api.example.com/new", 200, "{}", 10, None),
    ]);
    for p in [&a, &b] {
        let job = core.import_archive(p.clone()).unwrap();
        core.jobs.wait(job, Duration::from_secs(20)).unwrap();
    }
    core.capture().index.tick();
    let sources = core.compare_sources();
    let names: Vec<_> = sources.iter().map(|s| s.label.as_str()).collect();
    assert_eq!(names, ["release-1.har", "release-2.har"], "no live sessions, one side per archive");
    let d = core.compare_captures(&Source::Archive("release-1.har".into()), &Source::Archive("release-2.har".into())).unwrap();
    assert_eq!((d.counts.changed, d.counts.added, d.counts.removed, d.counts.same, d.counts.new_errors), (2, 1, 1, 1, 1), "{:#?}", d.entries);
    let find = |k: &str| d.entries.iter().find(|e| e.key.ends_with(k)).unwrap();
    assert_eq!(find("/users/{n}").kind, DiffKind::Same);
    let orders = find("/orders?page");
    assert_eq!(orders.kind, DiffKind::Changed);
    assert!(orders.changes.iter().any(|c| c == "status 200 → 500"), "{:?}", orders.changes);
    let health = find("/health");
    assert!(health.changes.iter().any(|c| c.starts_with("time 10 ms → 900 ms")), "{:?}", health.changes);
    assert!(health.changes.iter().any(|c| c == "header vary added"), "{:?}", health.changes);
    assert!(!health.changes.iter().any(|c| c.contains("date")), "volatile headers ignored");
    assert_eq!(find("/new").kind, DiffKind::Added);
    assert_eq!(find("/legacy").kind, DiffKind::Removed);
    assert_eq!(d.entries[0].kind, DiffKind::Changed, "changed first");
    let md = to_markdown(&d, "release-1", "release-2", false);
    assert!(md.contains("**1 now fail**") && md.contains("| + | `GET api.example.com/new`") && !md.contains("users/{n}`"), "{md}");
    assert!(core.compare_captures(&Source::Live, &Source::Archive("release-2.har".into())).is_err(), "no live sessions");
}

/// Staging against production (hosts ignored), and a request without an answer counted as
/// one that now fails.
#[test]
fn hosts_ignored_and_no_answer_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("settings.json"), r#"{"proxy":{"port":0,"actAsSystemProxy":false,"captureOnStartup":false}}"#).unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    let (a, b) = (dir.path().join("staging.har"), dir.path().join("prod.har"));
    har(&a, vec![entry("https://staging.example.com/api/a", 200, "{}", 10, None), entry("https://staging.example.com/api/b", 200, "{}", 10, None)]);
    har(&b, vec![entry("https://www.example.com/api/a", 200, "{}", 10, None), entry("https://www.example.com/api/b", 0, "", 10, None)]);
    for p in [&a, &b] {
        let job = core.import_archive(p.clone()).unwrap();
        core.jobs.wait(job, Duration::from_secs(20)).unwrap();
    }
    core.capture().index.tick();
    let (sa, sb) = (Source::Archive("staging.har".into()), Source::Archive("prod.har".into()));
    let d = core.compare_captures(&sa, &sb).unwrap();
    assert_eq!((d.counts.added, d.counts.removed), (2, 2), "other hosts do not pair");
    let d = core.compare_captures_with(&sa, &sb, &CompareOptions { ignore_host: true }).unwrap();
    assert_eq!((d.counts.same, d.counts.changed, d.counts.new_errors), (1, 1, 1), "{:#?}", d.entries);
    assert!(d.entries.iter().all(|e| e.key.starts_with("/api/")), "{:#?}", d.entries);
}
