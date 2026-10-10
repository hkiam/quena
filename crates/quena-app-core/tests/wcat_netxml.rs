//! WCAT scripts written from sessions; Internet Explorer NetXML captures loaded.

use quena_app_core::{AppCore, Paths};
use quena_model::{Headers, RequestHead, ResponseHead, SessionDetail};
use std::sync::Arc;
use std::time::Duration;

fn core() -> (tempfile::TempDir, Arc<AppCore>) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("settings.json"), r#"{"proxy":{"port":0,"actAsSystemProxy":false,"captureOnStartup":false}}"#).unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    (dir, core)
}

#[test]
fn wcat_out_netxml_in() {
    let (dir, core) = core();
    let cap = core.capture();
    let mut d = SessionDetail::default();
    d.request = RequestHead { method: "POST".into(), url: "https://api.example.com:8443/v1/orders?x=1".into(), headers: Headers(vec![("Host".into(), "api.example.com:8443".into()), ("Content-Type".into(), "application/json".into())]), ..Default::default() };
    d.response = Some(ResponseHead { status: 201, ..Default::default() });
    d.refresh_summary();
    let (a, b) = (cap.bodies.store_bytes(br#"{"q":"a\"b"}"#), cap.bodies.store_bytes(b""));
    cap.insert(d, a, b);
    cap.index.tick();
    let path = dir.path().join("load.wcat");
    let job = core.export_archive(vec![], path.clone(), None).unwrap();
    core.jobs.wait(job, Duration::from_secs(20)).unwrap();
    let w = std::fs::read_to_string(&path).unwrap();
    for want in ["server     = \"api.example.com\";", "port       = 8443;", "secure     = true;", "url        = \"/v1/orders?x=1\";", "verb       = POST;", "statuscode = 201;", "name  = \"Content-Type\";", r#"postdata   = "{\"q\":\"a\\\"b\"}";"#] {
        assert!(w.contains(want), "{want} missing in\n{w}");
    }
    assert!(!w.contains("\"Host\""), "Host is WCAT's own");

    let xml = dir.path().join("ie.xml");
    std::fs::write(&xml, r#"<?xml version="1.0"?><log><version>1.1</version><entries><entry><startedDateTime>2011-07-12T09:28:34.316+02:00</startedDateTime><time>12</time><request><method>GET</method><url>http://legacy.example.com/page</url><httpVersion>HTTP/1.1</httpVersion><cookies/><headers><header><name>Accept</name><value>*/*</value></header></headers><queryString/><headersSize>-1</headersSize><bodySize>0</bodySize></request><response><status>200</status><statusText>OK</statusText><httpVersion>HTTP/1.1</httpVersion><cookies/><headers/><content><size>2</size><mimeType>text/plain</mimeType><text>ok</text></content><redirectURL/><headersSize>-1</headersSize><bodySize>2</bodySize></response><cache/><timings><send>0</send><wait>10</wait><receive>2</receive></timings></entry></entries></log>"#).unwrap();
    assert!(quena_app_core::archive::importable(&xml));
    let job = core.import_archive(xml).unwrap();
    core.jobs.wait(job, Duration::from_secs(20)).unwrap();
    cap.index.tick();
    let ids = cap.index.find_all(|s| s.host == "legacy.example.com");
    assert_eq!(ids.len(), 1);
    assert_eq!(cap.index.get(ids[0]).unwrap().status, 200);
}
