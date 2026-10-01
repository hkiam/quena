//! Mocks from sessions: generation (mockgen), WireMock structure, Quena packages (import,
//! zip-slip) and the package answering through the real proxy.

use quena_app_core::mockgen::{self, BodyMatch, MockOptions, QueryMatch, Repeats, SkipReason};
use quena_app_core::rules::{AutoResponderState, Rule};
use quena_app_core::sanitize::{SanitizeOptions, Sanitizer};
use quena_app_core::{AppCore, JobStatus, Paths};
use quena_model::*;
use quena_store::Capture;
use serde_json::json;
use std::io::Write;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

fn capture(dir: &std::path::Path) -> Arc<Capture> {
    Capture::open(dir.join("cap"), Default::default(), true).unwrap()
}

struct S<'a> {
    method: &'a str,
    url: &'a str,
    req_headers: &'a [(&'a str, &'a str)],
    req: &'a [u8],
    status: u16,
    headers: &'a [(&'a str, &'a str)],
    body: &'a [u8],
}

fn get(url: &str, status: u16, ct: &'static str, body: &'static str) -> S<'static> {
    let url: &'static str = Box::leak(url.to_string().into_boxed_str());
    let headers: &'static [(&str, &str)] = Box::leak(vec![("Content-Type", ct)].into_boxed_slice());
    S { method: "GET", url, req_headers: &[], req: b"", status, headers, body: body.as_bytes() }
}

fn post_json(url: &'static str, req: &'static str, body: &'static str) -> S<'static> {
    S { method: "POST", url, req_headers: &[("Content-Type", "application/json")], req: req.as_bytes(), status: 200, headers: &[("Content-Type", "text/plain")], body: body.as_bytes() }
}

fn add(cap: &Arc<Capture>, s: &S) -> SessionId {
    let mut d = SessionDetail::default();
    d.summary.kind = SessionKind::Http;
    d.summary.state = SessionState::Done;
    let mut h = Headers::new();
    for (n, v) in s.req_headers {
        h.push(*n, *v);
    }
    d.request = RequestHead { method: s.method.into(), url: s.url.into(), version: HttpVersion::Http11, headers: h };
    let mut rh = Headers::new();
    for (n, v) in s.headers {
        rh.push(*n, *v);
    }
    d.response = Some(ResponseHead { status: s.status, reason: String::new(), version: HttpVersion::Http11, headers: rh });
    d.timers.server_begin_request = Some(10_000_000);
    d.timers.server_got_first_byte = Some(10_250_000);
    let (req, resp) = (cap.bodies.store_bytes(s.req), cap.bodies.store_bytes(s.body));
    cap.insert(d, req, resp)
}

fn mocks(cap: &Arc<Capture>, ids: &[SessionId], opts: &MockOptions) -> mockgen::MockSet {
    mockgen::generate(cap, ids, opts, true, &quena_formats::NoProgress).unwrap()
}

fn no_sanitize() -> MockOptions {
    MockOptions { sanitize: None, ..Default::default() }
}

#[test]
fn last_or_sequence() {
    let d = tempfile::tempdir().unwrap();
    let cap = capture(d.path());
    let ids: Vec<_> = ["A", "B", "B", "C"].iter().map(|b| add(&cap, &get("https://api.x.de/status", 200, "text/plain", b))).collect();
    let last = mocks(&cap, &ids, &no_sanitize());
    assert_eq!(last.entries.len(), 1);
    assert_eq!(last.entries[0].body, b"C");
    assert_eq!(last.skipped.iter().filter(|s| s.reason == SkipReason::Superseded).count(), 3);

    let seq = mocks(&cap, &ids, &MockOptions { repeats: Repeats::Sequence, ..no_sanitize() });
    let bodies: Vec<&[u8]> = seq.entries.iter().map(|e| e.body.as_slice()).collect();
    assert_eq!(bodies, [b"A", b"B", b"C"], "the repeated B collapses");
    assert_eq!(seq.skipped.iter().map(|s| s.reason).collect::<Vec<_>>(), [SkipReason::Duplicate]);
    assert_eq!(seq.sequences(), 1);
    assert!(seq.entries.iter().enumerate().all(|(i, e)| e.sequence.is_some_and(|s| s.index == i && s.len == 3)));

    // As rules: a match_once chain, the last one stays as fallback.
    let pkg = d.path().join("seq.quena-mocks");
    mockgen::write_package(&seq, &pkg, &MockOptions::default()).unwrap();
    let state = mockgen::extract_package(&pkg, &d.path().join("x")).unwrap();
    assert_eq!(state.rules.iter().map(|r| r.match_once).collect::<Vec<_>>(), [true, true, false]);
    assert!(state.rules.iter().all(|r| r.match_ == "METHOD:GET EXACT:https://api.x.de/status"), "{:?}", state.rules);
}

#[test]
fn ignored_query_params() {
    let d = tempfile::tempdir().unwrap();
    let cap = capture(d.path());
    let a = add(&cap, &get("https://api.x.de/items?page=2&_=111", 200, "application/json", "[1]"));
    let b = add(&cap, &get("https://api.x.de/items?_=222&page=2&utm_source=x", 200, "application/json", "[2]"));
    let c = add(&cap, &get("https://api.x.de/items?page=3&_=333", 200, "application/json", "[3]"));
    let set = mocks(&cap, &[a, b, c], &no_sanitize());
    assert_eq!(set.entries.len(), 2, "page=2 twice, page=3 once");
    let e = set.entries.iter().find(|e| e.body == b"[2]").unwrap();
    assert!(!e.exact_url);
    let m = mockgen::match_expression(e);
    let re = regex::Regex::new(m.strip_prefix("METHOD:GET regex:").unwrap()).unwrap();
    assert!(re.is_match("https://api.x.de/items?page=2&_=999"));
    assert!(re.is_match("https://api.x.de/items?page=2"));
    assert!(!re.is_match("https://api.x.de/items?page=3&_=1"));

    let exact = mocks(&cap, &[a, b, c], &MockOptions { query: QueryMatch::Exact, ..no_sanitize() });
    assert_eq!(exact.entries.len(), 3);
    assert!(exact.entries.iter().all(|e| e.exact_url));
    assert_eq!(mockgen::match_expression(&exact.entries[0]), "METHOD:GET EXACT:https://api.x.de/items?page=2&_=111");
}

#[test]
fn json_bodies_and_graphql_tell_requests_apart() {
    let d = tempfile::tempdir().unwrap();
    let cap = capture(d.path());
    let ids = vec![
        add(&cap, &post_json("https://api.x.de/search", r#"{"q":"a","limit":10}"#, "A")),
        add(&cap, &post_json("https://api.x.de/search", r#"{"limit":10,"q":"b"}"#, "B")),
        add(&cap, &post_json("https://api.x.de/search", r#"{ "q" : "a", "limit" : 10 }"#, "A2")),
        add(&cap, &post_json("https://api.x.de/graphql", r#"{"query":"query GetUser($id:ID){user(id:$id){name}}","operationName":"GetUser","variables":{"id":1}}"#, "user1")),
        add(&cap, &post_json("https://api.x.de/graphql", r#"{"query":"query GetUser($id:ID){user(id:$id){name}}","operationName":"GetUser","variables":{"id":2}}"#, "user2")),
        add(&cap, &post_json("https://api.x.de/graphql", r#"{"query":"query Me{me{name}}","operationName":"Me"}"#, "me")),
        add(&cap, &S { method: "POST", url: "https://api.x.de/login", req_headers: &[("Content-Type", "application/x-www-form-urlencoded")], req: b"user=al&remember=1", status: 200, headers: &[], body: b"ok" }),
    ];
    let set = mocks(&cap, &ids, &no_sanitize());
    assert_eq!(set.entries.len(), 6, "{:#?}", set.entries.iter().map(|e| (&e.url, &e.body_match)).collect::<Vec<_>>());
    // Same JSON (other formatting): the later response wins.
    let search: Vec<_> = set.entries.iter().filter(|e| e.path == "/search").collect();
    assert_eq!(search.len(), 2);
    assert!(search.iter().any(|e| e.body == b"A2") && search.iter().any(|e| e.body == b"B"));
    assert!(matches!(&search[0].body_match, BodyMatch::Json { .. }));
    let gql: Vec<_> = set.entries.iter().filter(|e| e.path == "/graphql").collect();
    assert_eq!(gql.len(), 3);
    assert!(gql.iter().any(|e| e.body_match == BodyMatch::GraphQl { operation_name: "GetUser".into(), variables: json!({"id": 2}) }));
    assert!(gql.iter().any(|e| e.body_match == BodyMatch::GraphQl { operation_name: "Me".into(), variables: serde_json::Value::Null }));
    // Every expression compiles.
    for e in &set.entries {
        quena_app_core::rules::validate_match(&mockgen::match_expression(e)).unwrap();
    }
    let login = set.entries.iter().find(|e| e.path == "/login").unwrap();
    assert_eq!(mockgen::match_expression(login), r"METHOD:POST URLWithBody:EXACT:https://api.x.de/login regex:(?s)^user=al&remember=1$");
}

#[test]
fn what_is_left_out() {
    let d = tempfile::tempdir().unwrap();
    let cap = capture(d.path());
    let js = add(&cap, &get("https://app.x.de/assets/app.js", 200, "application/javascript", "x()"));
    let png = add(&cap, &get("https://app.x.de/logo", 200, "image/png", "PNG"));
    let api = add(&cap, &get("https://api.x.de/v1/me", 200, "application/json", "{}"));
    let err = add(&cap, &get("https://api.x.de/v1/broken", 503, "application/json", r#"{"error":"down"}"#));
    let not_mod = add(&cap, &get("https://api.x.de/v1/cached", 304, "application/json", ""));
    let pre = add(&cap, &S { method: "OPTIONS", url: "https://api.x.de/v1/me", req_headers: &[("Origin", "https://app.x.de")], req: b"", status: 204, headers: &[("Access-Control-Allow-Origin", "https://app.x.de")], body: b"" });
    let other = add(&cap, &get("https://cdn.other.net/v1/x", 200, "application/json", "{}"));
    let all = [js, png, api, err, not_mod, pre, other];
    let set = mocks(&cap, &all, &no_sanitize());
    let reasons: std::collections::HashMap<_, _> = set.skipped.iter().map(|s| (s.id, s.reason)).collect();
    assert_eq!(reasons.get(&js), Some(&SkipReason::Static));
    assert_eq!(reasons.get(&png), Some(&SkipReason::Static));
    assert_eq!(reasons.get(&not_mod), Some(&SkipReason::NotModified));
    let ids: Vec<_> = set.entries.iter().map(|e| e.session).collect();
    assert!(ids.contains(&api) && ids.contains(&err) && ids.contains(&pre) && ids.contains(&other), "errors and preflights are kept by default");
    assert_eq!(set.hosts, ["api.x.de", "cdn.other.net"]);

    let strict = mocks(&cap, &all, &MockOptions { include_errors: false, include_preflight: false, include_static: true, hosts: vec!["x.de".into()], ..no_sanitize() });
    let reasons: std::collections::HashMap<_, _> = strict.skipped.iter().map(|s| (s.id, s.reason)).collect();
    assert_eq!(reasons.get(&err), Some(&SkipReason::ErrorStatus));
    assert_eq!(reasons.get(&pre), Some(&SkipReason::Preflight));
    assert_eq!(reasons.get(&other), Some(&SkipReason::Host));
    assert!(strict.entries.iter().any(|e| e.session == js), "static included on request");

    // The preview counts the same without reading response bodies.
    let p = mockgen::MockPreview::of(&mockgen::generate(&cap, &all, &no_sanitize(), false, &quena_formats::NoProgress).unwrap());
    assert_eq!((p.mappings, p.sessions), (set.entries.len(), 7));
    assert_eq!(p.skipped_by_reason.get(&SkipReason::Static), Some(&2));
}

#[test]
fn responses_are_served_decoded_and_sanitized() {
    let d = tempfile::tempdir().unwrap();
    let cap = capture(d.path());
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(br#"{"access_token":"SECRET-TOKEN-123","name":"x"}"#).unwrap();
    let gz = gz.finish().unwrap();
    let id = add(
        &cap,
        &S {
            method: "GET",
            url: "https://api.x.de/token?access_token=SECRET-TOKEN-123",
            req_headers: &[("Authorization", "Bearer SECRET-TOKEN-123")],
            req: b"",
            status: 200,
            headers: &[
                ("Content-Type", "application/json"),
                ("Content-Encoding", "gzip"),
                ("Content-Length", "999"),
                ("Transfer-Encoding", "chunked"),
                ("Connection", "keep-alive"),
                ("Set-Cookie", "sid=SECRET-TOKEN-123; HttpOnly"),
                ("X-Kept", "yes"),
            ],
            body: &gz,
        },
    );
    let plain = mocks(&cap, &[id], &no_sanitize());
    let e = &plain.entries[0];
    assert_eq!(e.body, br#"{"access_token":"SECRET-TOKEN-123","name":"x"}"#);
    let names: Vec<String> = e.headers.iter().map(|(n, _)| n.to_ascii_lowercase()).collect();
    assert_eq!(names, ["content-type", "x-kept", "content-length"]);
    assert!(e.headers.contains(&("Content-Length".into(), e.body.len().to_string())));
    let keep = mocks(&cap, &[id], &MockOptions { keep_set_cookie: true, ..no_sanitize() });
    assert!(keep.entries[0].headers.iter().any(|(n, _)| n == "Set-Cookie"));

    // With sanitizing, what is written is the sanitizer's output: whatever it removes from the
    // session never reaches the mock.
    let opts = MockOptions { sanitize: Some(SanitizeOptions::preset("credentials").unwrap()), ..Default::default() };
    let set = mocks(&cap, &[id], &opts);
    let e = &set.entries[0];
    let detail = cap.detail(id).unwrap();
    let (rq, rs) = cap.bodies_of(id).unwrap();
    let probe = Sanitizer::new(opts.sanitize.clone().unwrap()).session(&detail, &rq, &rs);
    let has = |b: &[u8]| String::from_utf8_lossy(b).contains("SECRET-TOKEN-123");
    assert_eq!(has(&e.body), has(&probe.response));
    assert_eq!(e.url.contains("SECRET-TOKEN-123"), probe.detail.request.url.contains("SECRET-TOKEN-123"));
    assert!(!e.headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("content-encoding")));
    // A replaced URL parameter matches any value (the real client still sends its token).
    if !probe.detail.request.url.contains("SECRET-TOKEN-123") {
        let m = mockgen::match_expression(e);
        assert!(!m.contains("SECRET-TOKEN-123"), "{m}");
        let re = regex::Regex::new(m.strip_prefix("METHOD:GET regex:").expect(&m)).unwrap();
        assert!(re.is_match("https://api.x.de/token?access_token=SECRET-TOKEN-123"));
    }
    // The latency comes from the recorded time to first byte.
    assert_eq!(mocks(&cap, &[id], &MockOptions { latency: true, ..no_sanitize() }).entries[0].delay_ms, 250);
}

#[test]
fn wiremock_structure() {
    let d = tempfile::tempdir().unwrap();
    let cap = capture(d.path());
    let ids = vec![
        add(&cap, &get("https://api.x.de/items?page=2&_=1", 200, "application/json", r#"{"items":[1]}"#)),
        add(&cap, &post_json("https://api.x.de/search", r#"{"q":"a"}"#, "A")),
        add(&cap, &get("https://api.x.de/poll", 200, "text/plain", "first")),
        add(&cap, &get("https://api.x.de/poll", 200, "text/plain", "second")),
        add(&cap, &post_json("https://api.x.de/graphql", r#"{"query":"q","operationName":"GetUser","variables":{"id":1}}"#, "u")),
    ];
    let set = mocks(&cap, &ids, &MockOptions { repeats: Repeats::Sequence, ..no_sanitize() });
    let files = mockgen::wiremock_files(&set);
    let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
    let json_of = |prefix: &str| -> serde_json::Value {
        let (_, data) = files.iter().find(|(n, _)| n.starts_with("mappings/") && n.contains(prefix)).unwrap_or_else(|| panic!("{prefix} in {names:?}"));
        serde_json::from_slice(data).unwrap()
    };
    assert!(names.contains(&"README.md"));
    assert!(std::str::from_utf8(&files.iter().find(|(n, _)| n == "README.md").unwrap().1).unwrap().contains("docker run --rm -v \"$PWD:/home/wiremock\" -p 8080:8080 wiremock/wiremock"));

    // Body matchers come first.
    assert_eq!(
        json_of("0001-POST-search"),
        json!({
            "name": "0001 POST /search",
            "priority": 1,
            "request": { "method": "POST", "url": "/search", "bodyPatterns": [{ "equalToJson": { "q": "a" }, "ignoreArrayOrder": false, "ignoreExtraElements": false }] },
            "response": { "status": 200, "headers": { "Content-Type": "text/plain", "Content-Length": "1" }, "bodyFileName": "0001.txt" }
        })
    );
    assert_eq!(
        json_of("POST-graphql")["request"]["bodyPatterns"],
        json!([
            { "matchesJsonPath": { "expression": "$.operationName", "equalTo": "GetUser" } },
            { "matchesJsonPath": { "expression": "$.variables", "equalToJson": "{\"id\":1}" } }
        ])
    );
    let items = json_of("GET-items");
    assert_eq!(items["request"], json!({ "method": "GET", "urlPath": "/items", "queryParameters": { "page": { "equalTo": "2" } } }));
    assert_eq!(items["priority"], 2);
    let f = items["response"]["bodyFileName"].as_str().unwrap();
    assert_eq!(files.iter().find(|(n, _)| *n == format!("__files/{f}")).unwrap().1, br#"{"items":[1]}"#);

    // The sequence as scenario: Started → step-2, the last one stays.
    let polls: Vec<serde_json::Value> = files.iter().filter(|(n, _)| n.contains("GET-poll")).map(|(_, d)| serde_json::from_slice(d).unwrap()).collect();
    assert_eq!(polls.len(), 2);
    assert_eq!(polls[0]["scenarioName"], polls[1]["scenarioName"]);
    assert_eq!((polls[0]["requiredScenarioState"].as_str(), polls[0]["newScenarioState"].as_str()), (Some("Started"), Some("step-2")));
    assert_eq!((polls[1]["requiredScenarioState"].as_str(), polls[1].get("newScenarioState")), (Some("step-2"), None));
    assert!(polls.iter().all(|p| p["request"].get("headers").is_none()), "one host: no Host matcher");

    // Several hosts: a Host matcher; exact URLs as `url`.
    let other = add(&cap, &get("https://cdn.y.de/a?b=1", 200, "text/plain", "y"));
    let set = mocks(&cap, &[ids[0], other], &MockOptions { query: QueryMatch::Exact, ..no_sanitize() });
    let files = mockgen::wiremock_files(&set);
    let m: serde_json::Value = serde_json::from_slice(&files.iter().find(|(n, _)| n.contains("GET-a")).unwrap().1).unwrap();
    assert_eq!(m["request"], json!({ "method": "GET", "url": "/a?b=1", "headers": { "Host": { "equalTo": "cdn.y.de", "caseInsensitive": true } } }));

    // Folder and ZIP output.
    mockgen::write_wiremock(&set, &d.path().join("wm")).unwrap();
    assert!(d.path().join("wm/mappings").read_dir().unwrap().count() == 2 && d.path().join("wm/__files").is_dir());
    mockgen::write_wiremock(&set, &d.path().join("wm.zip")).unwrap();
    let z = zip::ZipArchive::new(std::fs::File::open(d.path().join("wm.zip")).unwrap()).unwrap();
    assert!(z.file_names().any(|n| n == "README.md") && z.file_names().any(|n| n.starts_with("mappings/")));
}

#[test]
fn package_import_is_zip_slip_safe() {
    let d = tempfile::tempdir().unwrap();
    let pkg = d.path().join("evil.quena-mocks");
    let mut z = zip::ZipWriter::new(std::fs::File::create(&pkg).unwrap());
    let o = zip::write::SimpleFileOptions::default();
    let rules = AutoResponderState {
        rules: vec![
            Rule { match_: "METHOD:GET EXACT:http://a.invalid/ok".into(), action: "responses/ok.dat".into(), ..Default::default() },
            Rule { match_: "*".into(), action: "responses/../../outside.dat".into(), ..Default::default() },
            Rule { match_: "*".into(), action: "dir:/".into(), ..Default::default() },
            Rule { match_: "*".into(), action: "http://evil.invalid/".into(), ..Default::default() },
            Rule { match_: "*".into(), action: "/etc/passwd".into(), ..Default::default() },
            Rule { match_: "regex:(".into(), action: "*404".into(), ..Default::default() },
            Rule { match_: "*".into(), action: "*503".into(), ..Default::default() },
        ],
        ..Default::default()
    };
    for (name, data) in [
        ("rules.json", serde_json::to_vec(&rules).unwrap()),
        ("responses/ok.dat", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()),
        ("../outside.dat", b"x".to_vec()),
        ("responses/../../outside2.dat", b"x".to_vec()),
        ("/abs-outside.dat", b"x".to_vec()),
        ("other/file.txt", b"x".to_vec()),
    ] {
        z.start_file(name, o).unwrap();
        z.write_all(&data).unwrap();
    }
    z.finish().unwrap();
    let dest = d.path().join("data/mocks/evil");
    let state = mockgen::extract_package(&pkg, &dest).unwrap();
    let mut found = Vec::new();
    for e in walk(d.path()) {
        found.push(e.strip_prefix(d.path()).unwrap().to_string_lossy().replace('\\', "/"));
    }
    found.sort();
    assert_eq!(found, ["data/mocks/evil/responses/ok.dat", "data/mocks/evil/rules.json", "evil.quena-mocks"]);
    let (ok, rejected) = mockgen::resolve_package_rules(&state, &dest, "evil");
    assert_eq!(rejected, 5);
    assert_eq!(ok.len(), 2);
    assert_eq!(ok[0].action, dest.join("responses/ok.dat").to_string_lossy());
    assert_eq!(ok[1].action, "*503");
    assert!(ok.iter().all(|r| r.comment == "pkg:evil"));
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        if e.file_type().unwrap().is_dir() {
            out.extend(walk(&e.path()));
        } else {
            out.push(e.path());
        }
    }
    out
}

/// `curl` through the proxy → (status, headers lower-cased, body).
fn curl(proxy: &str, args: &[&str]) -> (u16, String, String) {
    let mut a = vec!["-sS", "--max-time", "20", "-x", proxy, "-D", "-"];
    a.extend_from_slice(args);
    let o = Command::new("curl").args(&a).output().unwrap();
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    let (head, body) = out.split_once("\r\n\r\n").unwrap_or((&out, ""));
    let code = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    (code, head.to_ascii_lowercase(), body.to_string())
}

/// Generate a package from sessions, import it, and let the proxy answer from it.
#[test]
fn package_roundtrip_through_the_proxy() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("settings.json"), r#"{"proxy":{"port":0,"actAsSystemProxy":false,"captureOnStartup":false,"useSystemUpstream":false}}"#).unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    let engine = quena_app_core::engine::ProxyEngine::new(&core).unwrap();
    core.set_proxy_engine(engine.clone());
    core.start_capture().unwrap();
    let addr = engine.proxy.listen_addrs().into_iter().find(|a| a.is_ipv4()).unwrap();
    let proxy = format!("http://{addr}");

    let cap = core.capture();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(br#"{"items":[1,2]}"#).unwrap();
    let gz = gz.finish().unwrap();
    let ids = vec![
        add(
            &cap,
            &S {
                method: "GET",
                url: "http://mock.invalid/api/items?page=2&_=111",
                req_headers: &[],
                req: b"",
                status: 201,
                headers: &[("Content-Type", "application/json"), ("Content-Encoding", "gzip"), ("X-Recorded", "yes"), ("Set-Cookie", "sid=1")],
                body: &gz,
            },
        ),
        add(&cap, &post_json("http://mock.invalid/api/search", r#"{"q":"a","n":1}"#, "result A")),
        add(&cap, &post_json("http://mock.invalid/api/search", r#"{"q":"b","n":1}"#, "result B")),
        add(&cap, &get("http://mock.invalid/api/poll", 200, "text/plain", "poll 1")),
        add(&cap, &get("http://mock.invalid/api/poll", 200, "text/plain", "poll 2")),
    ];
    let pkg = dir.path().join("Shop API.quena-mocks");
    let opts = MockOptions { repeats: Repeats::Sequence, ..MockOptions::default() };
    let job = core.mock_export_package(ids.clone(), pkg.clone(), opts.clone()).unwrap();
    let info = core.jobs.wait(job, Duration::from_secs(30)).unwrap();
    assert_eq!(info.status, JobStatus::Done, "{:?}", info.error);

    let p = core.mock_import_package(pkg.clone(), false).unwrap();
    assert_eq!((p.name.as_str(), p.rules, p.rejected), ("Shop-API", 5, 0));
    let rules = core.rules.clone().unwrap();
    let mut st = rules.autoresponder();
    st.unmatched_passthrough = false;
    rules.set_autoresponder(st, true).unwrap();

    let (code, head, body) = curl(&proxy, &["http://mock.invalid/api/items?_=999&page=2"]);
    assert_eq!((code, body.as_str()), (201, r#"{"items":[1,2]}"#), "{head}");
    assert!(head.contains("x-recorded: yes") && head.contains("content-length: 15"), "{head}");
    assert!(!head.contains("content-encoding") && !head.contains("set-cookie"), "{head}");
    // JSON compared semantically: other order and spacing.
    let (code, _, body) = curl(&proxy, &["-H", "Content-Type: application/json", "--data-binary", r#"{ "n": 1, "q": "b" }"#, "http://mock.invalid/api/search"]);
    assert_eq!((code, body.as_str()), (200, "result B"));
    let (_, _, body) = curl(&proxy, &["-H", "Content-Type: application/json", "--data-binary", r#"{"q":"a","n":1}"#, "http://mock.invalid/api/search"]);
    assert_eq!(body, "result A");
    // Another body, another method: no rule.
    let (code, _, body) = curl(&proxy, &["-H", "Content-Type: application/json", "--data-binary", r#"{"q":"c","n":1}"#, "http://mock.invalid/api/search"]);
    assert!(code == 404 && !body.starts_with("result"), "{code} {body}");
    let (code, _, body) = curl(&proxy, &["-X", "DELETE", "http://mock.invalid/api/items?page=2"]);
    assert!(code == 404 && !body.contains("items"), "{code} {body}");
    // The sequence: recorded order, then the last one repeats.
    let polls: Vec<String> = (0..3).map(|_| curl(&proxy, &["http://mock.invalid/api/poll"]).2).collect();
    assert_eq!(polls, ["poll 1", "poll 2", "poll 2"]);

    // Packages: listed, imported again replaces, removed with rules and folder.
    assert_eq!(core.mock_packages().iter().map(|p| (p.name.as_str(), p.rules)).collect::<Vec<_>>(), [("Shop-API", 5)]);
    core.mock_import_package(pkg.clone(), false).unwrap();
    assert_eq!(rules.autoresponder().rules.len(), 5, "re-import replaces the package's rules");
    assert_eq!(core.mock_remove_package("Shop-API").unwrap(), 5);
    assert!(rules.autoresponder().rules.is_empty() && !dir.path().join("mocks/Shop-API").exists());
    assert!(core.mock_remove_package("../x").is_err());

    // "Create from sessions" installs directly; other rules stay below the package.
    let mut st = rules.autoresponder();
    st.rules.push(Rule { match_: "*".into(), action: "*418".into(), ..Default::default() });
    rules.set_autoresponder(st, true).unwrap();
    let job = core.mock_apply(ids[..1].to_vec(), MockOptions::default(), "direct".into()).unwrap();
    assert_eq!(core.jobs.wait(job, Duration::from_secs(30)).unwrap().status, JobStatus::Done);
    let st = rules.autoresponder();
    assert_eq!(st.rules.len(), 2);
    assert_eq!((st.rules[0].comment.as_str(), st.rules[1].action.as_str()), ("pkg:direct", "*418"));
    assert!(st.rules[0].action.starts_with(&dir.path().join("mocks/direct/responses").to_string_lossy().into_owned()));
    let (code, _, body) = curl(&proxy, &["http://mock.invalid/api/items?page=2"]);
    assert_eq!((code, body.as_str()), (201, r#"{"items":[1,2]}"#));
    let (code, _, _) = curl(&proxy, &["http://mock.invalid/other"]);
    assert_eq!(code, 418);
    // Replace: the package rules only.
    core.mock_import_package(pkg, true).unwrap();
    assert!(rules.autoresponder().rules.iter().all(|r| r.comment == "pkg:Shop-API"));
    core.stop_capture().unwrap();
}
