//! Filters on headers, cookies, bodies, TLS version, server IP and HTTP version; header
//! columns filled in for the sessions in the list.

use quena_app_core::{AppCore, Paths};
use quena_model::{ConnectionInfo, Headers, HeaderColumn, HttpVersion, RequestHead, ResponseHead, SessionDetail, TlsInfo};
use quena_query::FilterSettings;
use std::sync::Arc;

fn core() -> (tempfile::TempDir, Arc<AppCore>) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("settings.json"), r#"{"proxy":{"port":0,"actAsSystemProxy":false,"captureOnStartup":false}}"#).unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    (dir, core)
}

fn add(core: &AppCore, url: &str, req: &[(&str, &str)], resp: &[(&str, &str)], body: &str, tls: &str, server: &str, h2: bool) {
    let cap = core.capture();
    let mut d = SessionDetail::default();
    let h = |v: &[(&str, &str)]| Headers(v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect());
    d.request = RequestHead { method: "GET".into(), url: url.into(), version: if h2 { HttpVersion::Http2 } else { HttpVersion::Http11 }, headers: h(req) };
    d.response = Some(ResponseHead { status: 200, headers: h(resp), ..Default::default() });
    d.connection = ConnectionInfo { server_addr: Some(server.into()), server_tls: Some(TlsInfo { version: tls.into(), ..Default::default() }), ..Default::default() };
    d.refresh_summary();
    let (a, b) = (cap.bodies.store_bytes(b""), cap.bodies.store_bytes(body.as_bytes()));
    cap.insert(d, a, b);
    cap.index.tick();
}

fn visible(core: &AppCore) -> usize {
    let cap = core.capture();
    cap.index.tick();
    cap.index.view_ids(0, 1000).len()
}

#[test]
fn filters_on_details_and_header_columns() {
    let (_dir, core) = core();
    add(&core, "https://a.example.com/1", &[("X-Api-Version", "2"), ("Cookie", "sid=1; theme=dark")], &[("Server", "nginx")], r#"{"error":"quota"}"#, "TLSv1.3", "10.0.0.9:443", true);
    add(&core, "https://b.example.com/2", &[("X-Api-Version", "1")], &[("Server", "envoy"), ("Set-Cookie", "sid=2; Path=/")], r#"{"ok":true}"#, "TLSv1.2", "[2001:db8::1]:443", false);
    add(&core, "http://c.example.com/3", &[], &[], "plain", "", "10.0.0.10:80", false);
    let r = core.capture().index.get(1).unwrap();
    assert_eq!((r.tls.as_str(), r.remote_ip.as_str(), r.http_version.as_str()), ("TLSv1.3", "10.0.0.9", "HTTP/2"));
    assert_eq!(core.capture().index.get(2).unwrap().remote_ip, "2001:db8::1");

    // Details of stored sessions are looked at in the background: the list settles shortly.
    let count = |expr: &str| {
        core.set_filters(FilterSettings { enabled: true, expression: expr.into(), ..Default::default() }).unwrap();
        // Unchanged over five looks (100 ms) after the worker had its time.
        let (mut last, mut same) = (usize::MAX, 0);
        for _ in 0..200 {
            std::thread::sleep(std::time::Duration::from_millis(20));
            let n = visible(&core);
            same = if n == last { same + 1 } else { 0 };
            last = n;
            if same >= 5 {
                break;
            }
        }
        last
    };
    assert_eq!(count("reqheader.x-api-version == 2"), 1);
    assert_eq!(count("resheader.server ~= \"n*\" or resheader.server == envoy"), 2);
    assert_eq!(count("cookie.sid != \"\""), 2, "sent or set");
    assert_eq!(count("resbody ~ quota"), 1);
    assert_eq!(count("tls == TLSv1.2"), 1);
    assert_eq!(count("ip ~= \"10.*\""), 2);
    assert_eq!(count("http == HTTP/2"), 1);
    assert_eq!(count("reqheader.x-api-version == \"\""), 1, "the session without it");
    assert_eq!(count(""), 3);
    let q = core.quickexec("find resbody ~ ok");
    assert_eq!(q.select.as_deref(), Some(&[2u64][..]), "{:?}", q.message);

    // Header columns: added in the settings, filled for the sessions already there.
    let mut s = core.settings();
    s.header_columns = vec![HeaderColumn { response: true, name: "Server".into() }, HeaderColumn { response: false, name: "x-api-version".into() }];
    core.update_settings(s).unwrap();
    let t = std::time::Instant::now();
    loop {
        let r = core.capture().index.get(1).unwrap();
        if r.header_values == ["nginx", "2"] {
            break;
        }
        assert!(t.elapsed() < std::time::Duration::from_secs(10), "{:?}", r.header_values);
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    add(&core, "https://d.example.com/4", &[("X-Api-Version", "3")], &[("Server", "caddy")], "", "TLSv1.3", "10.0.0.11:443", false);
    assert_eq!(core.capture().index.get(4).unwrap().header_values, ["caddy", "3"], "new sessions too");
    let mut s = core.settings();
    s.header_columns.clear();
    core.update_settings(s).unwrap();
}
