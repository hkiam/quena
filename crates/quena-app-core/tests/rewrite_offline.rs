//! Rewrite rules without traffic: groups, the editor's preview, and applying rules to
//! captured sessions (copies; the originals stay).

use quena_app_core::rewrite::{Op, Phase, RewriteRule, RewriteState};
use quena_app_core::{AppCore, Paths};
use quena_model::{Headers, HttpVersion, RequestHead, ResponseHead, SessionDetail, SessionKind};
use serde_json::json;
use std::io::Write;

fn core() -> (std::sync::Arc<AppCore>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("settings.json"), r#"{"proxy":{"actAsSystemProxy":false,"captureOnStartup":false}}"#).unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    (core, dir)
}

/// A finished GET with a gzip JSON response.
fn add_session(core: &AppCore, url: &str, json_body: &str) -> u64 {
    let cap = core.capture();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(json_body.as_bytes()).unwrap();
    let gz = gz.finish().unwrap();
    let mut d = SessionDetail::default();
    d.summary.kind = SessionKind::Http;
    d.summary.state = quena_model::SessionState::Done;
    d.request = RequestHead { method: "GET".into(), url: url.into(), version: HttpVersion::Http11, headers: Headers::new() };
    let mut h = Headers::new();
    h.push("Content-Type", "application/json");
    h.push("Content-Encoding", "gzip");
    h.push("Content-Length", gz.len().to_string());
    h.push("X-Old", "1");
    d.response = Some(ResponseHead { status: 200, reason: "OK".into(), version: HttpVersion::Http11, headers: h });
    let id = cap.insert(d, quena_body::Body::empty(), cap.bodies.store_bytes(&gz));
    cap.index.tick();
    id
}

fn rule(id: u64, group: &str, ops: Vec<Op>) -> RewriteRule {
    RewriteRule { id, match_: "prefix:https://api.example.com/".into(), phase: Phase::Response, ops, group: group.into(), comment: format!("r{id}"), ..Default::default() }
}

#[test]
fn groups_switch_their_rules_off() {
    let (core, _d) = core();
    let rw = &core.rules.as_ref().unwrap().rewrite;
    let st = RewriteState { rules: vec![rule(0, "chaos", vec![Op::SetStatus { code: 503 }])], ..Default::default() };
    rw.set(st).unwrap();
    assert!(rw.active());
    let mut st = rw.state();
    st.disabled_groups = vec!["chaos".into()];
    rw.set(st).unwrap();
    assert!(!rw.active(), "the only rule's group is off");
    // Saved and loaded with the group.
    let s = rw.state();
    assert_eq!(s.rules[0].group, "chaos");
    assert_eq!(s.disabled_groups, vec!["chaos".to_string()]);
}

#[test]
fn preview_shows_before_and_after() {
    let (core, _d) = core();
    let id = add_session(&core, "https://api.example.com/items", r#"{"items":[1,2],"name":"a"}"#);
    let r = rule(0, "", vec![Op::JsonSet { path: "$.name".into(), value: json!("b") }, Op::SetHeader { name: "X-New".into(), value: "yes".into() }]);
    let p = core.rewrite_preview(r.clone(), id).unwrap();
    assert!(p.matched && p.changed, "{p:?}");
    assert!(p.before.contains(r#""name":"a""#), "{}", p.before);
    assert!(p.after.contains(r#""name":"b""#), "{}", p.after);
    assert_eq!(p.headers_after.get("x-new"), Some("yes"));
    assert_eq!(p.headers_after.get("content-encoding"), None, "the new body is not compressed");
    // A rule for another URL does not take the session.
    let other = RewriteRule { match_: "prefix:https://other.example/".into(), ..r };
    let p = core.rewrite_preview(other, id).unwrap();
    assert!(!p.matched && !p.changed);
}

#[test]
fn applying_rules_creates_changed_copies() {
    let (core, _d) = core();
    let a = add_session(&core, "https://api.example.com/a", r#"{"v":1}"#);
    let b = add_session(&core, "https://elsewhere.example/b", r#"{"v":1}"#);
    let rw = &core.rules.as_ref().unwrap().rewrite;
    rw.set(RewriteState {
        rules: vec![rule(0, "g1", vec![Op::JsonSet { path: "$.v".into(), value: json!(2) }]), rule(0, "g2", vec![Op::SetStatus { code: 500 }])],
        ..Default::default()
    })
    .unwrap();
    // Only group g1: the matching session gets a copy, the other stays alone.
    let out = core.rewrite_apply(&[a, b], None, Some("g1")).unwrap();
    assert_eq!(out.created.len(), 1);
    assert_eq!(out.unchanged, 1);
    let cap = core.capture();
    let copy = cap.detail(out.created[0]).unwrap();
    assert!(copy.summary.has_flag(quena_model::flags::TAMPERED));
    assert!(copy.summary.comment.starts_with(&format!("Rewrite of #{a}")), "{}", copy.summary.comment);
    assert_eq!(copy.response.as_ref().unwrap().status, 200);
    let (_, body) = cap.bodies_of(out.created[0]).unwrap();
    assert_eq!(String::from_utf8(body.read_range(0, body.len() as usize).unwrap()).unwrap(), r#"{"v":2}"#);
    // The original is unchanged (still gzip).
    let orig = cap.detail(a).unwrap();
    assert_eq!(orig.response.as_ref().unwrap().headers.get("content-encoding"), Some("gzip"));
    // All running rules: status and body.
    let out = core.rewrite_apply(&[a], None, None).unwrap();
    assert_eq!(cap.detail(out.created[0]).unwrap().response.unwrap().status, 500);
    // The editor's update keeps ids and order.
    let mut first = rw.state().rules[0].clone();
    first.comment = "renamed".into();
    let st = core.rewrite_update(first).unwrap();
    assert_eq!(st.rules[0].comment, "renamed");
    assert_eq!(st.rules.len(), 2);
    let st = core.rewrite_update(rule(0, "", vec![Op::RemoveHeader { name: "X-Old".into() }])).unwrap();
    assert_eq!(st.rules.len(), 3);
}
