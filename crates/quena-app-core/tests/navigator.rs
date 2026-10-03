//! The navigator: groups of the filtered sessions, and narrowing the list to a group or a
//! structure node without losing the other groups from the navigator.
use quena_app_core::navigator::NavScope;
use quena_app_core::{AppCore, Paths};
use quena_index::GroupBy;
use quena_model::SessionSummary;

fn row(id: u64, host: &str, url: &str, conn: u64, status: u16) -> SessionSummary {
    SessionSummary { id, host: host.into(), url: url.into(), conn, status, response_body_len: 10, method: "GET".into(), ..Default::default() }
}

#[test]
fn groups_and_scope() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("settings.json"), r#"{"proxy":{"actAsSystemProxy":false,"captureOnStartup":false}}"#).unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    let cap = core.capture();
    for r in [row(1, "a.test", "/api/x", 7, 200), row(2, "B.test", "/img/1.png", 8, 404), row(3, "a.test", "/api/y", 7, 500), row(4, "b.test", "/", 0, 200)] {
        cap.index.upsert(r);
    }
    cap.index.tick();

    let g = core.nav_groups(GroupBy::Host);
    assert_eq!(g.total, 4);
    let hosts: Vec<_> = g.groups.iter().map(|g| (g.key.as_str(), g.count, g.errors)).collect();
    // Hosts without regard to case, in the order of their first session.
    assert_eq!(hosts, [("a.test", 2, 1), ("b.test", 2, 1)]);
    let c = core.nav_groups(GroupBy::Connection);
    assert_eq!((c.groups.len(), c.ungrouped), (2, 1));
    assert_eq!(c.groups[0].label, "a.test · #1");

    // Narrowed to a host: the list shows it, the navigator still all groups.
    core.set_scope(Some(NavScope::Group { by: GroupBy::Host, key: "b.test".into() })).unwrap();
    cap.index.tick();
    assert_eq!(core.view_ids(0, 10), vec![2, 4]);
    assert_eq!(core.nav_groups(GroupBy::Host).groups.len(), 2);
    assert_eq!(core.structure(None, "").nodes.len(), 3, "the structure tree stays whole (its hosts keep their case)");

    // A connection, and a structure node.
    core.set_scope(Some(NavScope::Group { by: GroupBy::Connection, key: "7".into() })).unwrap();
    cap.index.tick();
    assert_eq!(core.view_ids(0, 10), vec![1, 3]);
    core.set_scope(Some(NavScope::Path { host: "a.test".into(), path: "/api/".into(), exact: false })).unwrap();
    cap.index.tick();
    assert_eq!(core.view_ids(0, 10), vec![1, 3]);
    assert_eq!(core.structure_ids("b.test", "/", false), vec![4]);

    // The filters apply to both the list and the navigator; the scope comes on top.
    core.set_scope(None).unwrap();
    let f = quena_query::FilterSettings { enabled: true, expression: "status < 400".into(), ..Default::default() };
    core.set_filters(f).unwrap();
    cap.index.tick();
    assert_eq!(core.view_ids(0, 10), vec![1, 4]);
    assert_eq!(core.nav_groups(GroupBy::Host).total, 2);
    core.set_scope(Some(NavScope::Group { by: GroupBy::Host, key: "a.test".into() })).unwrap();
    cap.index.tick();
    assert_eq!(core.view_ids(0, 10), vec![1]);
}

#[test]
fn scope_serde_matches_the_ui() {
    let s: NavScope = serde_json::from_str(r#"{"kind":"group","by":"connection","key":"7"}"#).unwrap();
    assert_eq!(s, NavScope::Group { by: GroupBy::Connection, key: "7".into() });
    let p: NavScope = serde_json::from_str(r#"{"kind":"path","host":"a","path":"/x/","exact":false}"#).unwrap();
    assert!(matches!(p, NavScope::Path { .. }));
}
