//! Diagnostics end to end: HAR import → analyzer plugin (webdiag) → report with scope.
//! Requires `plugins/build.sh` to have been run (skips otherwise).
use quena_app_core::{AppCore, EventSink, Paths};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
struct Events(Mutex<Vec<(String, serde_json::Value)>>);
impl EventSink for Events {
    fn emit(&self, event: &str, payload: serde_json::Value) {
        self.0.lock().unwrap().push((event.to_string(), payload));
    }
}

fn wait(core: &AppCore, job: u64) {
    let job = core.jobs.get(job).unwrap();
    let t0 = Instant::now();
    while !matches!(format!("{:?}", job.status()).as_str(), "Done" | "Failed" | "Cancelled") {
        assert!(t0.elapsed() < Duration::from_secs(60), "job did not finish");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(format!("{:?}", job.status()), "Done", "{:?}", job.snapshot().error);
}

#[test]
fn diagnostics_run_over_visible_sessions_and_selection() {
    let dist = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../plugins/dist");
    if !dist.join("webdiag").exists() {
        eprintln!("webdiag plugin not built – run plugins/build.sh");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("settings.json"), r#"{"proxy":{"actAsSystemProxy":false,"captureOnStartup":false}}"#).unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    let events = Arc::new(Events::default());
    core.set_sink(events.clone());
    // No plugin host yet: a clean error, not a panic.
    assert!(core.diag_run(0, "{}".into(), None, Default::default()).is_err());
    assert!(core.diag_analyzers().is_empty());
    core.init_plugins(Some(dist)).unwrap();

    let a = core.diag_analyzers();
    let wd = a.iter().find(|a| a.id == "io.github.hkiam.webdiag").expect("webdiag analyzer").clone();
    assert!(!wd.title.is_empty());
    // Only analyzers are listed.
    assert!(!a.iter().any(|a| a.id == "io.github.hkiam.rot13-test"));
    let d: serde_json::Value = serde_json::from_str(&core.diag_describe(wd.index, "de").unwrap()).unwrap();
    assert!(d["profiles"].is_array(), "{d:#}");

    let har = concat!(env!("CARGO_MANIFEST_DIR"), "/../../app/e2e/fixtures/two-sessions.har");
    wait(&core, core.import_archive(har.into()).unwrap());
    let cap = core.capture();
    cap.index.tick();
    let n = cap.index.view_len();
    assert!(n > 0);
    assert!(core.diag_report().is_none());

    wait(&core, core.diag_run(wd.index, r#"{"lang":"en"}"#.into(), None, Default::default()).unwrap());
    let r: serde_json::Value = serde_json::from_str(&core.diag_report().expect("report")).unwrap();
    assert_eq!(r["scope"], serde_json::json!({"kind": "visible", "sessions": n, "processes": [], "hosts": []}), "{r:#}");
    let at = r["generatedAt"].as_i64().unwrap();
    assert!((at - quena_model::now_us()).abs() < 120_000_000, "{at}");
    assert!(r["findings"].is_array(), "{r:#}");
    assert!(events.0.lock().unwrap().iter().any(|(e, p)| e == "diag-report" && p.is_null()));

    let first = core.view_ids(0, 1);
    wait(&core, core.diag_run(wd.index, "{}".into(), Some(first.clone()), Default::default()).unwrap());
    let r: serde_json::Value = serde_json::from_str(&core.diag_report().unwrap()).unwrap();
    assert_eq!(r["scope"], serde_json::json!({"kind": "selection", "sessions": 1, "processes": [], "hosts": []}), "{r:#}");
    // A host filter narrows the scope; an empty scope is refused.
    let host = cap.index.get(first[0]).unwrap().host;
    let f = quena_app_core::diagnostics::DiagFilter { processes: vec![], hosts: vec![host.clone()] };
    wait(&core, core.diag_run(wd.index, "{}".into(), None, f).unwrap());
    let r: serde_json::Value = serde_json::from_str(&core.diag_report().unwrap()).unwrap();
    assert_eq!(r["scope"]["hosts"], serde_json::json!([host]));
    assert!(r["scope"]["sessions"].as_u64().unwrap() < n as u64 || n == 1);
    let none = quena_app_core::diagnostics::DiagFilter { processes: vec!["no-such".into()], hosts: vec![] };
    assert!(core.diag_run(wd.index, "{}".into(), None, none).is_err());

    // Unknown or disabled analyzers are refused.
    assert!(core.diag_run(999, "{}".into(), None, Default::default()).is_err());
    core.plugin_set_enabled("io.github.hkiam.webdiag", false).unwrap();
    assert!(core.diag_run(wd.index, "{}".into(), None, Default::default()).is_err());
}

/// Developer aid: `QUENA_DIAG_HAR=capture.har [QUENA_DIAG_OPTIONS='{"lang":"de"}'] cargo test -p
/// quena-app-core --test diagnostics report_for_har -- --nocapture` prints the report of any HAR.
#[test]
fn report_for_har() {
    let (Ok(har), dist) = (std::env::var("QUENA_DIAG_HAR"), PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../plugins/dist")) else { return };
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("settings.json"), r#"{"proxy":{"actAsSystemProxy":false,"captureOnStartup":false}}"#).unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    core.init_plugins(Some(dist)).unwrap();
    wait(&core, core.import_archive(har.into()).unwrap());
    core.capture().index.tick();
    let wd = core.diag_analyzers().into_iter().find(|a| a.id == "io.github.hkiam.webdiag").expect("webdiag");
    let opts = std::env::var("QUENA_DIAG_OPTIONS").unwrap_or_else(|_| "{}".into());
    wait(&core, core.diag_run(wd.index, opts, None, Default::default()).unwrap());
    println!("{}", core.diag_report().unwrap());
}
