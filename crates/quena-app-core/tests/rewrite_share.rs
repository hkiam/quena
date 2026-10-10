//! Rewrite rules exported to a file and imported elsewhere (all or none).

use quena_app_core::rewrite::{Op, Phase, RewriteRule};
use quena_app_core::{AppCore, Paths};
use std::sync::Arc;

fn core() -> (tempfile::TempDir, Arc<AppCore>) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("settings.json"), r#"{"proxy":{"port":0,"actAsSystemProxy":false,"captureOnStartup":false}}"#).unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    let engine = quena_app_core::engine::ProxyEngine::new(&core).unwrap();
    core.set_proxy_engine(engine);
    (dir, core)
}

#[test]
fn rules_travel_in_a_file() {
    let (dir, a) = core();
    let rule = |m: &str, g: &str| RewriteRule { match_: m.into(), phase: Phase::Response, ops: vec![Op::SetHeader { name: "X-A".into(), value: "1".into() }], comment: m.into(), group: g.into(), ..Default::default() };
    a.rewrite_update(rule("/one", "chaos")).unwrap();
    a.rewrite_update(rule("/two", "")).unwrap();
    let file = dir.path().join("rules.json");
    assert!(a.rewrite_export(&file, Some("nothing")).is_err(), "an empty group");
    assert_eq!(a.rewrite_export(&file, Some("chaos")).unwrap(), 1);
    assert_eq!(a.rewrite_export(&file, None).unwrap(), 2);

    let (_d2, b) = core();
    b.rewrite_update(rule("/mine", "")).unwrap();
    let (state, n) = b.rewrite_import(&file).unwrap();
    assert_eq!(n, 2);
    let names: Vec<&str> = state.rules.iter().map(|r| r.match_.as_str()).collect();
    assert_eq!(names, ["/mine", "/one", "/two"]);
    assert!(state.rules.iter().all(|r| r.id > 0) && state.rules[1].group == "chaos");

    // A broken rule: nothing is added.
    std::fs::write(&file, r#"{"rules":[{"match":"/ok","ops":[{"op":"removeHeader","name":"A"}]},{"match":"/bad","ops":[]}]}"#).unwrap();
    let e = b.rewrite_import(&file).unwrap_err().to_string();
    assert!(e.contains("rule 2"), "{e}");
    assert_eq!(b.rewrite_import(&dir.path().join("missing.json")).is_err(), true);
    std::fs::write(&file, "[]").unwrap();
    assert!(b.rewrite_import(&file).is_err());
}
