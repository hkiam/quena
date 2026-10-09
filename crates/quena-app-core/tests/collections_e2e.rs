//! Composer collections: saved as `.http` files, run through the proxy, with the HTTP
//! version as chosen (HTTP/1.1, HTTP/2 over TLS, h2c) or as negotiated.

use bytes::Bytes;
use http_body_util::Full;
use quena_app_core::collections::{Collection, CollectionRequest};
use quena_app_core::{AppCore, Paths};
use std::convert::Infallible;
use std::time::Duration;

/// Answers with the HTTP version of the request.
async fn app(req: http::Request<hyper::body::Incoming>) -> Result<http::Response<Full<Bytes>>, Infallible> {
    Ok(http::Response::new(Full::new(Bytes::from(format!("{:?}", req.version())))))
}

/// (plain HTTP port speaking HTTP/1.1 and h2c, HTTPS port offering h2 and http/1.1)
fn servers(dir: &std::path::Path) -> (u16, u16) {
    let ca = quena_tls::CertAuthority::load_or_create(dir.join("server-ca")).unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(ca.server_config("localhost", true).unwrap());
    let plain = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let tls = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let ports = (plain.local_addr().unwrap().port(), tls.local_addr().unwrap().port());
    for l in [&plain, &tls] {
        l.set_nonblocking(true).unwrap();
    }
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            let serve = |io| async move {
                let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new()).serve_connection(hyper_util::rt::TokioIo::new(io), hyper::service::service_fn(app)).await;
            };
            let plain = tokio::net::TcpListener::from_std(plain).unwrap();
            let tls = tokio::net::TcpListener::from_std(tls).unwrap();
            tokio::spawn(async move {
                loop {
                    let (s, _) = plain.accept().await.unwrap();
                    tokio::spawn(serve(s));
                }
            });
            loop {
                let (s, _) = tls.accept().await.unwrap();
                let acc = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(t) = acc.accept(s).await {
                        let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new()).serve_connection(hyper_util::rt::TokioIo::new(t), hyper::service::service_fn(app)).await;
                    }
                });
            }
        });
    });
    ports
}

fn req(name: &str, url: &str, version: &str) -> CollectionRequest {
    CollectionRequest { name: name.into(), method: "GET".into(), url: url.into(), version: version.into(), ..Default::default() }
}

#[test]
fn collections_are_saved_run_and_keep_the_http_version() {
    let dir = tempfile::tempdir().unwrap();
    let (plain, tls) = servers(dir.path());
    std::fs::write(
        dir.path().join("settings.json"),
        r#"{"proxy":{"port":0,"actAsSystemProxy":false,"captureOnStartup":false,"useSystemUpstream":false},"https":{"decrypt":true,"ignoreCertErrors":true}}"#,
    )
    .unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    let engine = quena_app_core::engine::ProxyEngine::new(&core).unwrap();
    core.set_proxy_engine(engine);
    core.start_capture().unwrap();

    let c = Collection {
        name: "Versions".into(),
        variables: vec![("tls".into(), format!("https://localhost:{tls}")), ("plain".into(), format!("http://127.0.0.1:{plain}"))],
        requests: vec![
            req("auto", "{{tls}}/a", ""),
            req("h1", "{{tls}}/b", "HTTP/1.1"),
            req("h2", "{{tls}}/c", "HTTP/2"),
            req("h2c", "{{plain}}/d", "HTTP/2"),
            req("plain", "{{plain}}/e", ""),
            CollectionRequest { name: "post".into(), method: "POST".into(), url: "{{plain}}/f".into(), headers: "Content-Type: application/json".into(), body: "{\"a\": 1}".into(), ..Default::default() },
        ],
        ..Default::default()
    };
    let info = core.collection_save(&c).unwrap();
    assert_eq!(info.requests, 6);
    let back = core.collection_read("Versions").unwrap();
    assert_eq!(back.requests, c.requests);
    assert_eq!(back.variables, c.variables);
    assert_eq!(core.collections_list().unwrap().iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["Versions"]);

    let results = core.collection_run("Versions", &[], None, Duration::from_secs(20)).unwrap();
    let body = |name: &str| {
        let r = results.iter().find(|r| r.name.as_deref() == Some(name)).unwrap();
        assert_eq!(r.error, None, "{name}");
        let id = r.session.unwrap();
        let (_, resp) = core.capture().bodies_of(id).unwrap();
        (String::from_utf8_lossy(&resp.read_range(0, 100).unwrap()).into_owned(), core.capture().detail(id).unwrap())
    };
    // Automatic: the server's choice (h2 by ALPN).
    assert_eq!(body("auto").0, "HTTP/2.0");
    let (b, d) = body("h1");
    assert_eq!(b, "HTTP/1.1");
    assert_eq!(d.request.version, quena_model::HttpVersion::Http11);
    let (b, d) = body("h2");
    assert_eq!(b, "HTTP/2.0");
    assert_eq!(d.summary.protocol, "HTTP/2");
    assert_eq!(body("h2c").0, "HTTP/2.0");
    assert_eq!(body("plain").0, "HTTP/1.1");
    assert_eq!(body("post").0, "HTTP/1.1");
    // Only some requests, by name.
    assert_eq!(core.collection_run("Versions", &["h2c".into()], None, Duration::from_secs(20)).unwrap().len(), 1);

    // An edited, unsaved request with the collection's variables (the Composer's Execute).
    let sent = core.collection_send(Some("Versions"), &req("draft", "{{plain}}/g", "HTTP/2"), None).unwrap();
    let id = sent.session.unwrap();
    assert!(core.wait_session(id, Duration::from_secs(20)));
    let (_, resp) = core.capture().bodies_of(id).unwrap();
    assert_eq!(resp.read_range(0, 100).unwrap(), b"HTTP/2.0");
    assert!(core.collection_send(None, &req("x", "{{nope}}/", ""), None).is_err());

    // Rename, import, delete; unsafe names are refused.
    core.collection_rename("Versions", "Renamed").unwrap();
    assert!(core.collection_read("Versions").is_err());
    let ext = dir.path().join("ext");
    std::fs::create_dir_all(&ext).unwrap();
    std::fs::write(ext.join("api.http"), "### one\nGET https://example.com/\n").unwrap();
    std::fs::write(ext.join("http-client.env.json"), r#"{"dev":{"x":"1"}}"#).unwrap();
    assert_eq!(core.collection_import(&ext.join("api.http")).unwrap(), "api");
    assert_eq!(core.collection_import(&ext.join("api.http")).unwrap(), "api 2");
    assert_eq!(core.collection_read("api").unwrap().environments, vec!["dev".to_string()]);
    core.collection_delete("api 2").unwrap();
    assert_eq!(core.collections_list().unwrap().len(), 2);
    for bad in ["../x", "a/b", "", ".hidden"] {
        assert!(core.collection_read(bad).is_err(), "{bad}");
    }
    // A request that cannot be written back the same is refused, nothing is written.
    let broken = Collection { name: "Broken".into(), requests: vec![CollectionRequest { body: "x\n### y".into(), ..req("b", "https://x/", "") }], ..Default::default() };
    assert!(core.collection_save(&broken).is_err());
    assert!(core.collection_read("Broken").is_err());
    core.shutdown();
}

/// Names, the listing, renaming only the case, and the copy kept when a file written
/// elsewhere is rewritten.
#[test]
fn collection_files_are_handled_with_care() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("settings.json"), r#"{"proxy":{"port":0,"actAsSystemProxy":false,"captureOnStartup":false}}"#).unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    for bad in ["NUL", "com1", "Aux.x", "a.", "../x", ".hidden"] {
        assert!(core.collection_path(bad).is_err(), "{bad}");
    }
    assert!(core.collection_path("COM10").is_ok() && core.collection_path("Console").is_ok());

    let folder = core.collections_dir();
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("other.rest"), "GET http://example.com/\n").unwrap();
    let hand = "# kept only in the copy\nGET http://example.com/a\n\n> {% client.log(1) %}\n";
    std::fs::write(folder.join("hand.http"), hand).unwrap();
    let names: Vec<String> = core.collections_list().unwrap().into_iter().map(|c| c.name).collect();
    assert_eq!(names, ["hand"], ".rest files are not collections");

    let mut c = core.collection_read("hand").unwrap();
    c.requests.push(req("b", "http://example.com/b", ""));
    core.collection_save(&c).unwrap();
    assert_eq!(std::fs::read_to_string(folder.join("hand.http.bak")).unwrap(), hand, "the original is kept");
    // A file Quena wrote itself: no new copy, the first stays.
    core.collection_save(&c).unwrap();
    assert_eq!(std::fs::read_to_string(folder.join("hand.http.bak")).unwrap(), hand);
    assert_eq!(core.collection_read("hand").unwrap().requests.len(), 2);

    core.collection_rename("hand", "Hand").unwrap();
    assert_eq!(core.collections_list().unwrap()[0].name, "Hand");
    core.collection_save(&Collection { name: "x".into(), variables: vec![], requests: vec![req("a", "http://example.com/", "")], ..Default::default() }).unwrap();
    assert!(core.collection_rename("x", "hand").is_err(), "another collection's name");
}
