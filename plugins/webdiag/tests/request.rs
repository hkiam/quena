//! Single-session / per-endpoint analyzers (analyzers/request.rs): positive and negative cases.
use webdiag::model::{Finding, Kind, Session, Severity};
use webdiag::testkit::*;

fn with(mut s: Session, f: impl FnOnce(&mut Session)) -> Session {
    f(&mut s);
    s
}

fn run(s: Vec<Session>) -> Vec<Finding> {
    analyse(s, "{}")
}

fn keys(f: &[&Finding]) -> Vec<String> {
    f.iter().map(|x| x.key.clone()).collect()
}

// ------------------------------------------------------------------ PERF-TTFB

#[test]
fn ttfb_per_endpoint_and_severity() {
    // took(2000) with 20 % download → TTFB 1.6 s > 500 ms
    let mut s: Vec<Session> = (0..4).map(|i| get(i, &format!("https://api.test/v1/cases/{i}")).at(i * 3000).took(2000)).collect();
    s.push(get(10, "https://api.test/v1/fast").at(20_000).took(300));
    let f = run(s);
    let t = of(&f, "PERF-TTFB");
    assert_eq!(keys(&t), vec!["PERF-TTFB|GET api.test/v1/cases/{}"]);
    assert_eq!(t[0].severity, Severity::Warning);
    assert_eq!(t[0].sessions, vec![0, 1, 2, 3]);
    // Median TTFB ≥ 5 × threshold → critical
    let f = run(vec![get(1, "https://api.test/slow").took(4000)]);
    assert_eq!(of(&f, "PERF-TTFB")[0].severity, Severity::Critical);
}

#[test]
fn ttfb_ignores_transfer_time_and_missing_timers() {
    // Slow, but the time is download (TTFB 150 ms).
    let f = run(vec![get(1, "https://api.test/big").took(3000).download_share(0.95)]);
    assert!(of(&f, "PERF-TTFB").is_empty());
    // HAR import without timers: no TTFB, no finding, no panic.
    let f = run(vec![with(get(1, "https://api.test/x").took(3000), |s| s.timers = Default::default())]);
    assert!(of(&f, "PERF-TTFB").is_empty());
}

// ------------------------------------------------------------------ PERF-LARGE-REQ / RESP

#[test]
fn large_requests() {
    let f = run(vec![post(1, "https://up.test/files").req_body(2 << 20, 7).req_h("Content-Type", "application/octet-stream")]);
    let r = of(&f, "PERF-LARGE-REQ");
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, Severity::Info);
    assert!(r[0].estimate && r[0].table.is_some());
    assert!(r[0].hypotheses.iter().any(|h| h.contains("Content-Range")));
    // Chunked with Content-Range: no resumability hypothesis; failed upload → warning.
    let f = run(vec![post(1, "https://up.test/files").req_body(2 << 20, 7).req_h("Content-Range", "bytes 0-2097151/9000000").failed_with("timed out")]);
    let r = of(&f, "PERF-LARGE-REQ");
    assert_eq!(r[0].severity, Severity::Warning);
    assert!(!r[0].hypotheses.iter().any(|h| h.contains("Content-Range")));
    // Small bodies: nothing.
    assert!(of(&run(vec![post(1, "https://up.test/files").req_body(1000, 7)]), "PERF-LARGE-REQ").is_empty());
}

#[test]
fn large_responses() {
    let f = run(vec![
        get(1, "https://h.test/odata/Documents?$top=5000").body(6 << 20, "application/json"),
        get(2, "https://h.test/export/1").at(100).body(30 << 20, "text/csv"),
        get(3, "https://h.test/small").at(200).body(1 << 20, "application/json"),
    ]);
    let r = of(&f, "PERF-LARGE-RESP");
    assert_eq!(r.len(), 2);
    let odata = r.iter().find(|x| x.key.contains("Documents")).unwrap();
    assert_eq!(odata.severity, Severity::Warning);
    assert!(odata.recommendations.iter().any(|x| x.contains("$select")));
    let export = r.iter().find(|x| x.key.contains("export")).unwrap();
    assert_eq!(export.severity, Severity::Critical, "≥ 5 × threshold");
}

// ------------------------------------------------------------------ PERF-COMPRESS

#[test]
fn compression_missing() {
    let s: Vec<Session> = (0..5).map(|i| get(i, &format!("https://api.test/items?page={i}")).at(i * 100).body(100 * 1024, "application/json; charset=utf-8").req_h("Accept-Encoding", "gzip, br")).collect();
    let f = run(s);
    let c = of(&f, "PERF-COMPRESS");
    assert_eq!(keys(&c), vec!["PERF-COMPRESS|api.test"]);
    assert_eq!(c[0].severity, Severity::Warning, "~350 KB saving");
    assert!(c[0].estimate);
    assert!(!c[0].hypotheses.iter().any(|h| h.contains("Accept-Encoding")));
    // No Accept-Encoding sent → hypothesis about the client; small saving → info.
    let f = run(vec![get(1, "https://api.test/a").body(4096, "text/html")]);
    let c = of(&f, "PERF-COMPRESS");
    assert_eq!(c[0].severity, Severity::Info);
    assert!(c[0].hypotheses.iter().any(|h| h.contains("Accept-Encoding")));
}

#[test]
fn compression_present_or_not_compressible() {
    let gz = with(get(1, "https://api.test/a").body(100 * 1024, "application/json").resp_h("Content-Encoding", "gzip"), |s| s.response_bytes = 20 * 1024);
    let png = get(2, "https://api.test/logo.png").at(10).body(100 * 1024, "image/png");
    let tiny = get(3, "https://api.test/t").at(20).body(500, "application/json");
    assert!(of(&run(vec![gz, png, tiny]), "PERF-COMPRESS").is_empty());
}

#[test]
fn compression_request_side() {
    let f = run(vec![post(1, "https://api.test/save").req_body(200 * 1024, 1).req_h("Content-Type", "application/json")]);
    let c = of(&f, "PERF-COMPRESS");
    assert_eq!(keys(&c), vec!["PERF-COMPRESS|request|api.test"]);
    assert_eq!(c[0].severity, Severity::Info);
}

// ------------------------------------------------------------------ ERR-HTTP

#[test]
fn http_errors_by_endpoint_and_status() {
    let mut s = vec![];
    for i in 0..10 {
        s.push(get(i, "https://api.test/orders").at(i * 100).status(if i < 5 { 500 } else { 200 }));
    }
    s.push(get(20, "https://api.test/favicon.ico").at(2000).status(404));
    s.push(get(21, "https://api.test/app.js").at(2100).status(404));
    s.push(post(22, "https://api.test/orders").at(2200).status(400));
    s.push(get(23, "https://api.test/secure").at(2300).status(401));
    s.push(get(24, "https://api.test/secure").at(2400).status(403));
    let f = run(s);
    let e = of(&f, "ERR-HTTP");
    let k = keys(&e);
    assert!(k.contains(&"ERR-HTTP|GET api.test/orders|500".to_string()));
    assert!(k.contains(&"ERR-HTTP|POST api.test/orders|400".to_string()));
    assert!(k.contains(&"ERR-HTTP|GET api.test/app.js|404".to_string()));
    assert!(!k.iter().any(|x| x.contains("favicon") || x.contains("secure")), "{k:?}");
    let e500 = e.iter().find(|x| x.key.ends_with("|500")).unwrap();
    assert_eq!(e500.severity, Severity::Critical, "50 % share");
    assert_eq!(e500.table.as_ref().unwrap().rows.len(), 2, "status distribution");
    assert_eq!(e.iter().find(|x| x.key.ends_with("|404")).unwrap().severity, Severity::Info);
    assert_eq!(e.iter().find(|x| x.key.ends_with("|400")).unwrap().severity, Severity::Warning);
}

#[test]
fn single_server_error_is_a_warning() {
    let mut s: Vec<Session> = (0..20).map(|i| get(i, "https://api.test/x").at(i * 10)).collect();
    s.push(get(99, "https://api.test/x").at(500).status(503));
    let e = of(&run(s), "ERR-HTTP").into_iter().cloned().collect::<Vec<_>>();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].severity, Severity::Warning);
}

#[test]
fn findings_are_capped_per_rule() {
    let s: Vec<Session> = (0..15).map(|i| get(i, &format!("https://api.test/r{i}/list")).at(i * 10).status(500)).collect();
    let f = run(s);
    let e = of(&f, "ERR-HTTP");
    assert_eq!(e.len(), 10);
    assert!(e.last().unwrap().facts.iter().any(|(l, v)| l.contains("Further") && v.starts_with('5')));
}

// ------------------------------------------------------------------ NET-FAIL

#[test]
fn network_failures_by_host_and_class() {
    let mut s: Vec<Session> = (0..40).map(|i| get(i, "https://api.test/x").at(i * 10)).collect();
    for i in 0..3 {
        s.push(get(100 + i, "https://api.test/x").at(1000 + i * 10).failed_with("The operation has timed out"));
    }
    s.push(get(200, "https://api.test/y").at(2000).failed_with("Connection reset by peer"));
    let tunnel = with(get(300, "https://other.test:443").at(3000).failed_with("No such host is known"), |s| s.kind = Kind::Tunnel);
    let ws = with(get(301, "https://ws.test/").at(3100).failed_with("timeout"), |s| s.kind = Kind::WebSocket);
    s.extend([tunnel, ws]);
    let f = run(s);
    let n = of(&f, "NET-FAIL");
    let k = keys(&n);
    assert!(k.contains(&"NET-FAIL|api.test|timeout".to_string()) && k.contains(&"NET-FAIL|api.test|reset".to_string()));
    assert!(k.contains(&"NET-FAIL|other.test|dns".to_string()), "failed tunnels count");
    assert!(!k.iter().any(|x| x.contains("ws.test")), "websocket frames are skipped");
    // 4 of 44 failed (9 %) → critical
    assert_eq!(n.iter().find(|x| x.key.ends_with("|timeout")).unwrap().severity, Severity::Critical);
}

#[test]
fn rare_failures_are_warnings_and_aborts_info() {
    let mut s: Vec<Session> = (0..100).map(|i| get(i, "https://api.test/x").at(i * 10)).collect();
    s.push(get(200, "https://api.test/x").at(5000).failed_with("timeout"));
    s.push(get(201, "https://api.test/x").at(5100).failed_with("Request aborted"));
    let f = run(s);
    let n = of(&f, "NET-FAIL");
    assert_eq!(n.iter().find(|x| x.key.ends_with("|timeout")).unwrap().severity, Severity::Warning);
    assert_eq!(n.iter().find(|x| x.key.ends_with("|aborted")).unwrap().severity, Severity::Info);
    assert!(of(&run(vec![get(1, "https://api.test/x")]), "NET-FAIL").is_empty());
}

// ------------------------------------------------------------------ AUTH-FAIL

#[test]
fn answered_challenges_are_normal() {
    let s = vec![
        get(1, "https://api.test/me").status(401).resp_h("WWW-Authenticate", "Negotiate"),
        get(2, "https://api.test/me").at(100).req_h("Authorization", "Negotiate <1800 bytes>"),
    ];
    assert!(of(&run(s), "AUTH-FAIL").is_empty());
    // Frequent challenges → info.
    let mut s = vec![];
    for i in 0..12 {
        s.push(get(i * 2, &format!("https://api.test/d/{i}")).at(i * 1000).status(401).resp_h("WWW-Authenticate", "Negotiate"));
        s.push(get(i * 2 + 1, &format!("https://api.test/d/{i}")).at(i * 1000 + 100).req_h("Authorization", "Negotiate <1800 bytes>"));
    }
    let f = run(s);
    let a = of(&f, "AUTH-FAIL");
    assert_eq!(keys(&a), vec!["AUTH-FAIL|challenge|api.test"]);
    assert_eq!(a[0].severity, Severity::Info);
}

#[test]
fn ntlm_three_leg_handshake_is_answered() {
    let s = vec![
        get(1, "https://intra.test/a").status(401).resp_h("WWW-Authenticate", "NTLM"),
        get(2, "https://intra.test/a").at(60).req_h("Authorization", "NTLM <56 bytes>").status(401).resp_h("WWW-Authenticate", "NTLM <300 bytes>"),
        get(3, "https://intra.test/a").at(120).req_h("Authorization", "NTLM <500 bytes>"),
    ];
    assert!(of(&run(s), "AUTH-FAIL").is_empty());
}

#[test]
fn authentication_loop_and_forbidden() {
    let mut s: Vec<Session> = (0..4).map(|i| get(i, "https://api.test/me").at(i * 10_000).status(401).req_h("Authorization", "Bearer <812 bytes>").resp_h("WWW-Authenticate", "Bearer realm, error")).collect();
    s.push(get(10, "https://api.test/admin").at(60_000).status(403).req_h("Authorization", "Bearer <812 bytes>"));
    s.push(get(11, "https://api.test/once").at(70_000).status(401));
    let f = run(s);
    let a = of(&f, "AUTH-FAIL");
    let lp = a.iter().find(|x| x.key == "AUTH-FAIL|unauthorized|GET api.test/me").unwrap();
    assert_eq!(lp.severity, Severity::Critical);
    assert!(lp.facts.iter().any(|(_, v)| v.contains("Bearer")));
    assert!(lp.hypotheses.iter().any(|h| h.contains("token")));
    assert_eq!(a.iter().find(|x| x.key == "AUTH-FAIL|unauthorized|GET api.test/once").unwrap().severity, Severity::Warning);
    assert_eq!(a.iter().find(|x| x.key == "AUTH-FAIL|forbidden|GET api.test/admin").unwrap().severity, Severity::Warning);
}

// ------------------------------------------------------------------ AUTH-REPEAT

#[test]
fn repeated_windows_handshakes() {
    let s: Vec<Session> = (0..12).map(|i| get(i, &format!("https://intra.test/x/{i}")).at(i * 500).new_conn(1, 5, 10).req_h("Authorization", "NTLM <500 bytes>")).collect();
    let f = run(s);
    let a = of(&f, "AUTH-REPEAT");
    assert_eq!(keys(&a), vec!["AUTH-REPEAT|handshake|intra.test"]);
    assert_eq!(a[0].severity, Severity::Warning);
    assert!(a[0].hypotheses.iter().any(|h| h.contains("new connection")));
    assert!(a[0].recommendations.iter().any(|h| h.contains("Kerberos")));
    // Authenticated once, then the connection carries it: nothing.
    let mut s = vec![get(0, "https://intra.test/x").req_h("Authorization", "Negotiate <1800 bytes>")];
    s.extend((1..12).map(|i| get(i, &format!("https://intra.test/x/{i}")).at(i * 500)));
    assert!(of(&run(s), "AUTH-REPEAT").is_empty());
}

#[test]
fn token_not_cached() {
    let s: Vec<Session> = (0..3).map(|i| post(i, "https://login.test/tenant/oauth2/v2.0/token").at(i * 40_000).req_body(300, 42)).collect();
    let f = run(s);
    let a = of(&f, "AUTH-REPEAT");
    assert_eq!(keys(&a), vec!["AUTH-REPEAT|token|POST login.test/tenant/oauth2/v2.0/token"]);
    assert_eq!(a[0].severity, Severity::Warning);
    // Every 10 minutes: cached as expected.
    let s: Vec<Session> = (0..3).map(|i| post(i, "https://login.test/connect/token").at(i * 600_000).req_body(300, 42)).collect();
    assert!(of(&run(s), "AUTH-REPEAT").is_empty());
}

// ------------------------------------------------------------------ REDIRECT

fn redirect(id: u64, url: &str, at: u64, loc: &str) -> Session {
    get(id, url).at(at).status(302).resp_h("Location", loc)
}

#[test]
fn redirect_chain_and_loop() {
    let f = run(vec![
        redirect(1, "https://a.test/start", 0, "/step1"),
        redirect(2, "https://a.test/step1", 100, "step2"),
        redirect(3, "https://a.test/step2", 200, "https://b.test/login"),
        get(4, "https://b.test/login").at(300),
    ]);
    let r = of(&f, "REDIRECT");
    assert_eq!(keys(&r), vec!["REDIRECT|chain|GET a.test/start"]);
    assert_eq!(r[0].severity, Severity::Warning);
    assert_eq!(r[0].sessions, vec![1, 2, 3, 4]);
    let f = run(vec![redirect(1, "https://a.test/x", 0, "/login"), redirect(2, "https://a.test/login", 100, "/x"), redirect(3, "https://a.test/x", 200, "/login")]);
    let r = of(&f, "REDIRECT");
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, Severity::Critical);
    assert!(r[0].key.starts_with("REDIRECT|loop|"));
}

#[test]
fn short_or_unfollowed_redirects_are_fine() {
    let f = run(vec![
        redirect(1, "https://a.test/old", 0, "/new"),
        get(2, "https://a.test/new").at(100),
        // Followed too late (> 10 s): not a chain.
        redirect(3, "https://a.test/p", 1000, "/q"),
        redirect(4, "https://a.test/q", 30_000, "/r"),
        redirect(5, "https://a.test/r", 60_000, "/s"),
        get(6, "https://a.test/s").at(90_000),
    ]);
    assert!(of(&f, "REDIRECT").is_empty());
}

#[test]
fn http_to_https_redirects() {
    let mut s = vec![];
    for i in 0..3 {
        s.push(redirect(i * 2, &format!("http://a.test/p{i}"), i * 1000, &format!("https://a.test/p{i}")));
        s.push(get(i * 2 + 1, &format!("https://a.test/p{i}")).at(i * 1000 + 50));
    }
    let f = run(s);
    let r = of(&f, "REDIRECT");
    assert_eq!(keys(&r), vec!["REDIRECT|https|a.test"]);
    assert_eq!(r[0].severity, Severity::Info);
    assert!(r[0].recommendations.iter().any(|x| x.contains("Strict-Transport-Security")));
}

// ------------------------------------------------------------------ COOKIE

#[test]
fn cookie_attributes() {
    let f = run(vec![
        get(1, "https://app.test/").resp_h("Set-Cookie", "sid=<32 bytes>; Path=/").resp_h("Set-Cookie", "x=<5 bytes>; SameSite=None"),
        get(2, "https://app.test/b").at(10).resp_h("Set-Cookie", "gone=<0 bytes>; Max-Age=0"),
    ]);
    let c = of(&f, "COOKIE");
    let k = keys(&c);
    assert!(k.contains(&"COOKIE|samesite|app.test".to_string()));
    assert!(k.contains(&"COOKIE|insecure|app.test".to_string()));
    assert!(k.contains(&"COOKIE|httponly|app.test".to_string()));
    assert_eq!(c.iter().find(|x| x.key.starts_with("COOKIE|samesite")).unwrap().severity, Severity::Critical);
    let insecure = c.iter().find(|x| x.key.starts_with("COOKIE|insecure")).unwrap();
    assert!(insecure.facts.iter().any(|(_, v)| v == "sid"), "deleted cookies and SameSite=None ones are not repeated here");
    // Well-configured cookies, or plain HTTP: nothing.
    let f = run(vec![get(1, "https://app.test/").resp_h("Set-Cookie", "sid=<32 bytes>; Path=/; Secure; HttpOnly; SameSite=Lax"), get(2, "http://plain.test/").resp_h("Set-Cookie", "theme=<4 bytes>")]);
    assert!(of(&f, "COOKIE").is_empty());
}

#[test]
fn cookie_size_and_churn() {
    let ok = "; Secure; HttpOnly";
    let mut s = vec![get(0, "https://app.test/").resp_h("Set-Cookie", &format!("big1=<2000 bytes>{ok}")).resp_h("Set-Cookie", &format!("big2=<2500 bytes>{ok}"))];
    // Set 10 times, never sent back.
    for i in 1..=10 {
        s.push(get(i, "https://app.test/api").at(i * 100).resp_h("Set-Cookie", &format!("track=<10 bytes>{ok}")));
    }
    let f = run(s);
    let c = of(&f, "COOKIE");
    assert_eq!(c.iter().find(|x| x.key == "COOKIE|size|app.test").unwrap().severity, Severity::Warning);
    assert_eq!(c.iter().find(|x| x.key == "COOKIE|repeat|app.test|track").unwrap().severity, Severity::Warning);
    // Sent back (sliding renewal) → info.
    let s: Vec<Session> = (0..10).map(|i| get(i, "https://app.test/api").at(i * 100).req_h("Cookie", "a; track").resp_h("Set-Cookie", &format!("track=<10 bytes>{ok}"))).collect();
    let f = run(s);
    assert_eq!(of(&f, "COOKIE").iter().find(|x| x.key == "COOKIE|repeat|app.test|track").unwrap().severity, Severity::Info);
    // Many cookie names in one request.
    let names: Vec<String> = (0..35).map(|i| format!("c{i}")).collect();
    let f = run(vec![get(1, "https://app.test/").req_h("Cookie", &names.join("; "))]);
    assert_eq!(keys(&of(&f, "COOKIE")), vec!["COOKIE|size|app.test"]);
}

// ------------------------------------------------------------------ CACHE

#[test]
fn static_resources_without_caching() {
    let s: Vec<Session> = (0..3).map(|i| get(i, "https://cdn.test/app.js").at(i * 1000).body(50_000, "application/javascript")).collect();
    let f = run(s);
    let c = of(&f, "CACHE");
    let k = keys(&c);
    assert!(k.contains(&"CACHE|uncacheable|cdn.test".to_string()) && k.contains(&"CACHE|reload|cdn.test".to_string()), "{k:?}");
    assert!(c.iter().all(|x| x.severity == Severity::Warning));
    // Cacheable and loaded once: nothing.
    let f = run(vec![get(1, "https://cdn.test/app.js").body(50_000, "application/javascript").resp_h("Cache-Control", "public, max-age=31536000, immutable")]);
    assert!(of(&f, "CACHE").is_empty());
}

#[test]
fn revalidation_no_store_and_etags() {
    let mut s: Vec<Session> = (0..10).map(|i| get(i, "https://cdn.test/logo.png").at(i * 1000).status(304).req_h("If-None-Match", "\"a\"").resp_h("ETag", "\"a\"")).collect();
    s.push(get(20, "https://cdn.test/site.css").at(20_000).body(1000, "text/css").resp_h("Cache-Control", "no-store"));
    for i in 0..3 {
        s.push(get(30 + i, "https://api.test/v1/profile").at(30_000 + i * 1000).body(2000, "application/json").resp_h("ETag", "\"v1\""));
    }
    let f = run(s);
    let k = keys(&of(&f, "CACHE"));
    assert!(k.contains(&"CACHE|revalidate|cdn.test".to_string()), "{k:?}");
    assert!(k.contains(&"CACHE|nostore|cdn.test".to_string()));
    assert!(k.contains(&"CACHE|etag|api.test".to_string()));
    assert!(of(&f, "CACHE").iter().all(|x| x.severity == Severity::Info));
    // The client revalidates the API resource: no ETag finding.
    let s: Vec<Session> = (0..3).map(|i| get(i, "https://api.test/v1/profile").at(i * 1000).status(304).req_h("If-None-Match", "\"v1\"").resp_h("ETag", "\"v1\"")).collect();
    assert!(of(&run(s), "CACHE").is_empty());
}

// ------------------------------------------------------------------ CONN-REUSE

#[test]
fn new_connection_per_request() {
    let s: Vec<Session> = (0..12).map(|i| get(i, "https://api.test/x").at(i * 1000).new_conn(5, 20, 40)).collect();
    let f = run(s);
    let c = of(&f, "CONN-REUSE");
    assert_eq!(keys(&c), vec!["CONN-REUSE|api.test"]);
    assert_eq!(c[0].severity, Severity::Warning);
    assert!(c[0].estimate);
    // Reused connections: nothing.
    let s: Vec<Session> = (0..12).map(|i| get(i, "https://api.test/x").at(i * 1000)).collect();
    assert!(of(&run(s), "CONN-REUSE").is_empty());
}

#[test]
fn connection_data_missing_or_close() {
    // Import without connection data: no warning.
    let s: Vec<Session> = (0..12).map(|i| with(get(i, "https://api.test/x").at(i * 1000), |s| s.server_connection_reused = false)).collect();
    assert!(of(&run(s), "CONN-REUSE").is_empty());
    // Connection: close → info.
    let s: Vec<Session> = (0..5).map(|i| get(i, "https://api.test/x").at(i * 1000).resp_h("Connection", "close")).collect();
    let f = run(s);
    let c = of(&f, "CONN-REUSE");
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].severity, Severity::Info);
}

#[test]
fn parallel_http1_suggests_http2() {
    let s: Vec<Session> = (0..8).map(|i| get(i, &format!("https://api.test/p/{i}")).at(i).took(500)).collect();
    let f = run(s.clone());
    assert_eq!(keys(&of(&f, "CONN-REUSE")), vec!["CONN-REUSE|h2|api.test"]);
    let h2: Vec<Session> = s.into_iter().map(|x| with(x, |s| s.version = "HTTP/2".into())).collect();
    assert!(of(&run(h2), "CONN-REUSE").is_empty());
}

// ------------------------------------------------------------------ TLS-OLD

#[test]
fn old_tls() {
    let f = run(vec![with(get(1, "https://legacy.test/"), |s| s.tls_version = Some("TLSv1".into())), with(get(2, "https://ok.test/"), |s| s.tls_version = Some("TLSv1.2".into()))]);
    let t = of(&f, "TLS-OLD");
    assert_eq!(keys(&t), vec!["TLS-OLD|legacy.test"]);
    assert_eq!(t[0].severity, Severity::Warning);
}

// ------------------------------------------------------------------ CORS-PREFLIGHT

#[test]
fn preflight_per_request() {
    let mut s = vec![];
    for i in 0..10 {
        s.push(req(i * 2, "OPTIONS", &format!("https://api.test/items/{i}")).at(i * 1000).status(204).req_h("Origin", "https://app.test").req_h("Access-Control-Request-Method", "PUT").resp_h("Access-Control-Allow-Origin", "https://app.test"));
        s.push(req(i * 2 + 1, "PUT", &format!("https://api.test/items/{i}")).at(i * 1000 + 60).req_h("Origin", "https://app.test"));
    }
    let f = run(s);
    let c = of(&f, "CORS-PREFLIGHT");
    assert_eq!(keys(&c), vec!["CORS-PREFLIGHT|api.test"]);
    assert_eq!(c[0].severity, Severity::Warning);
    assert!(c[0].recommendations.iter().any(|x| x.contains("Access-Control-Max-Age")));
    assert_eq!(c[0].sessions.len(), 10);
}

#[test]
fn preflight_failures_and_non_preflights() {
    let f = run(vec![req(1, "OPTIONS", "https://api.test/x").status(403).req_h("Access-Control-Request-Method", "POST")]);
    assert_eq!(keys(&of(&f, "CORS-PREFLIGHT")), vec!["CORS-PREFLIGHT|fail|api.test"]);
    // Plain OPTIONS (no Access-Control-Request-Method) is not a preflight.
    let s: Vec<Session> = (0..10).map(|i| req(i, "OPTIONS", "https://api.test/x").at(i * 100)).collect();
    assert!(of(&run(s), "CORS-PREFLIGHT").is_empty());
}

// ------------------------------------------------------------------ robustness, profiles, language

#[test]
fn odd_sessions_never_panic() {
    let odd = vec![
        Session { id: 1, ..Default::default() },
        with(get(2, ""), |s| s.status = 0),
        with(get(3, "not a url"), |s| s.timers = Default::default()),
        get(4, "https://h.test/").status(302).resp_h("Location", ""),
        get(5, "https://h.test/").status(301).resp_h("Location", "::::"),
        get(6, "https://h.test/").resp_h("Set-Cookie", "").resp_h("Set-Cookie", ";;=").req_h("Cookie", ""),
        req(7, "OPTIONS", "https://h.test/").req_h("Access-Control-Request-Method", ""),
        with(get(8, "https://h.test/"), |s| s.tls_version = Some("".into())),
        with(get(9, "https://h.test/").status(401), |s| s.kind = Kind::Tunnel),
        get(10, "https://h.test/token").status(401).req_h("Authorization", ""),
    ];
    for lang in ["en", "de"] {
        let mut r = webdiag::Run::new(&format!(r#"{{"lang":"{lang}"}}"#));
        r.push(odd.clone());
        assert!(webdiag::json::parse(r.finish().as_bytes()).is_ok());
    }
}

#[test]
fn profiles_select_analyzers_and_german_texts() {
    let s = vec![get(1, "https://api.test/a").body(100 * 1024, "application/json"), get(2, "https://api.test/b").at(10).status(403)];
    let f = analyse(s.clone(), r#"{"profile":"auth","lang":"de"}"#);
    assert!(of(&f, "PERF-COMPRESS").is_empty());
    let a = of(&f, "AUTH-FAIL");
    assert_eq!(a.len(), 1);
    assert!(a[0].title.starts_with("Zugriff verweigert"));
    let f = analyse(s, r#"{"profile":"performance","lang":"de"}"#);
    let c = of(&f, "PERF-COMPRESS");
    assert!(c[0].impact.contains("einsparen") && c[0].impact.contains(','), "German number format: {}", c[0].impact);
    assert!(of(&f, "AUTH-FAIL").is_empty());
}
