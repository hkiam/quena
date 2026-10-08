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
    add_with_reason(cap, s, "")
}

fn add_with_reason(cap: &Arc<Capture>, s: &S, reason: &str) -> SessionId {
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
    d.response = Some(ResponseHead { status: s.status, reason: reason.into(), version: HttpVersion::Http11, headers: rh });
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
    assert!(gql.iter().any(|e| e.body_match == BodyMatch::GraphQl { operation_name: "GetUser".into(), variables: json!({"id": 2}), query: None }));
    assert!(gql.iter().any(|e| e.body_match == BodyMatch::GraphQl { operation_name: "Me".into(), variables: serde_json::Value::Null, query: None }));
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
    assert_eq!(items["priority"], 120, "urlPath with one parameter, no body");
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
    // `*` matches every host: even the harmless `*503` is not taken over.
    assert_eq!(rejected, 6);
    assert_eq!(ok.len(), 1);
    assert_eq!(std::path::Path::new(&ok[0].action), dest.join("responses").join("ok.dat"));
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
    assert_eq!((p.name.as_str(), p.rules, p.rejected), ("shop-api", 5, 0));
    assert_eq!(p.hosts, ["mock.invalid"]);
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
    assert_eq!(core.mock_packages().iter().map(|p| (p.name.as_str(), p.rules, p.hosts.clone())).collect::<Vec<_>>(), [("shop-api", 5, vec!["mock.invalid".to_string()])]);
    core.mock_import_package(pkg.clone(), false).unwrap();
    assert_eq!(rules.autoresponder().rules.len(), 5, "re-import replaces the package's rules");
    assert_eq!(core.mock_remove_package("Shop-API").unwrap(), 5);
    assert!(rules.autoresponder().rules.is_empty() && !dir.path().join("mocks/shop-api").exists());
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
    assert!(std::path::Path::new(&st.rules[0].action).starts_with(dir.path().join("mocks").join("direct")) && st.rules[0].action.contains("responses"), "{}", st.rules[0].action);
    let (code, _, body) = curl(&proxy, &["http://mock.invalid/api/items?page=2"]);
    assert_eq!((code, body.as_str()), (201, r#"{"items":[1,2]}"#));
    let (code, _, _) = curl(&proxy, &["http://mock.invalid/other"]);
    assert_eq!(code, 418);
    // Replace: the package rules only.
    core.mock_import_package(pkg, true).unwrap();
    assert!(rules.autoresponder().rules.iter().all(|r| r.comment == "pkg:shop-api"));
    core.stop_capture().unwrap();
}

// ------------------------------------------------------------------ review fixes

struct Live {
    dir: tempfile::TempDir,
    core: Arc<AppCore>,
    proxy: String,
    _engine: Arc<quena_app_core::engine::ProxyEngine>,
}

fn live() -> Live {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("settings.json"), r#"{"proxy":{"port":0,"actAsSystemProxy":false,"captureOnStartup":false,"useSystemUpstream":false}}"#).unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    let engine = quena_app_core::engine::ProxyEngine::new(&core).unwrap();
    core.set_proxy_engine(engine.clone());
    core.start_capture().unwrap();
    let addr = engine.proxy.listen_addrs().into_iter().find(|a| a.is_ipv4()).unwrap();
    Live { dir, proxy: format!("http://{addr}"), core, _engine: engine }
}

impl Live {
    /// Create mock rules from `ids` (as package `name`) and let unmatched requests fail.
    fn apply(&self, ids: &[SessionId], opts: MockOptions, name: &str) {
        let job = self.core.mock_apply(ids.to_vec(), opts, name.into()).unwrap();
        let info = self.core.jobs.wait(job, Duration::from_secs(30)).unwrap();
        assert_eq!(info.status, JobStatus::Done, "{:?}", info.error);
        let rules = self.core.rules.clone().unwrap();
        let mut st = rules.autoresponder();
        st.unmatched_passthrough = false;
        rules.set_autoresponder(st, true).unwrap();
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        let _ = self.core.stop_capture();
    }
}

const JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

#[test]
fn sanitized_path_segments_match_any_value() {
    let d = tempfile::tempdir().unwrap();
    let cap = capture(d.path());
    let reset = add(&cap, &get(&format!("http://api.test/reset/{JWT}"), 200, "text/plain", "reset ok"));
    let orders = add(&cap, &get("http://api.test/users/max%40example.com/orders", 200, "application/json", "[]"));
    let set = mocks(&cap, &[reset, orders], &MockOptions { sanitize: SanitizeOptions::preset("support"), ..Default::default() });
    for e in &set.entries {
        let m = mockgen::match_expression(e);
        assert!(!m.contains("%3C") && !m.contains("EXACT:"), "placeholder in the matcher: {m}");
        assert!(e.path_regex.is_some() && !e.exact_url, "{e:?}");
        let re = regex::Regex::new(m.strip_prefix("METHOD:GET regex:").unwrap()).unwrap();
        let orig = cap.detail(e.session).unwrap().request.url;
        assert!(re.is_match(&orig), "{m} vs {orig}");
    }
    let files = mockgen::wiremock_files(&set);
    let maps: Vec<serde_json::Value> = files.iter().filter(|(n, _)| n.starts_with("mappings/")).map(|(_, d)| serde_json::from_slice(d).unwrap()).collect();
    let patterns: Vec<&str> = maps.iter().filter_map(|m| m["request"]["urlPathPattern"].as_str()).collect();
    assert!(patterns.contains(&"/reset/[^/]*") && patterns.contains(&"/users/[^/]*/orders"), "{maps:#?}");
    assert!(maps.iter().all(|m| m["request"].get("urlPath").is_none() && m["request"].get("url").is_none()));
}

#[test]
fn wiremock_priorities_follow_specificity() {
    let d = tempfile::tempdir().unwrap();
    let cap = capture(d.path());
    let bare = add(&cap, &get("http://api.test/p?_=1", 200, "text/plain", "bare"));
    let one = add(&cap, &get("http://api.test/p?x=1&_=2", 200, "text/plain", "one"));
    let exact = add(&cap, &get("http://api.test/p?x=1&y=2", 200, "text/plain", "exact"));
    let two = add(&cap, &get("http://api.test/p?x=1&y=3&_=9", 200, "text/plain", "two"));
    let body = add(&cap, &post_json("http://api.test/p", r#"{"a":1}"#, "body"));
    let set = mocks(&cap, &[bare, one, exact, two, body], &no_sanitize());
    let files = mockgen::wiremock_files(&set);
    let prio = |id: SessionId| -> u64 {
        let i = set.entries.iter().position(|e| e.session == id).unwrap();
        let (_, data) = files.iter().filter(|(n, _)| n.starts_with("mappings/")).nth(i).unwrap();
        serde_json::from_slice::<serde_json::Value>(data).unwrap()["priority"].as_u64().unwrap()
    };
    let (b, o, e, t, j) = (prio(bare), prio(one), prio(exact), prio(two), prio(body));
    assert!(j < e && e < t && t < o && o < b, "body {j} < exact {e} < two params {t} < one param {o} < bare {b}");
    // The Quena rules are in the same order.
    let order: Vec<SessionId> = set.entries.iter().map(|e| e.session).collect();
    assert_eq!(order, [body, exact, two, one, bare]);
}

#[test]
fn mixed_sequences_use_one_matcher() {
    let d = tempfile::tempdir().unwrap();
    let cap = capture(d.path());
    let ids: Vec<_> = [("http://api.test/seq?_=1", "1"), ("http://api.test/seq", "2"), ("http://api.test/seq?_=3", "3")].iter().map(|(u, b)| add(&cap, &get(u, 200, "text/plain", b))).collect();
    let set = mocks(&cap, &ids, &MockOptions { repeats: Repeats::Sequence, ..no_sanitize() });
    assert_eq!(set.entries.len(), 3);
    let exprs: Vec<String> = set.entries.iter().map(mockgen::match_expression).collect();
    assert!(exprs.iter().all(|m| *m == exprs[0] && m.contains("regex:")), "{exprs:?}");
    let files = mockgen::wiremock_files(&set);
    let reqs: Vec<serde_json::Value> = files.iter().filter(|(n, _)| n.starts_with("mappings/")).map(|(_, d)| serde_json::from_slice::<serde_json::Value>(d).unwrap()["request"].clone()).collect();
    assert!(reqs.iter().all(|r| *r == json!({ "method": "GET", "urlPath": "/seq" })), "{reqs:?}");
}

#[test]
fn crlf_in_recorded_headers_is_dropped() {
    let d = tempfile::tempdir().unwrap();
    let cap = capture(d.path());
    let id = add_with_reason(
        &cap,
        &S {
            method: "GET",
            url: "http://api.test/x",
            req_headers: &[],
            req: b"",
            status: 200,
            headers: &[("Content-Type", "text/plain"), ("X-Evil", "a\r\nSet-Cookie: sid=1"), ("Bad Name", "v"), ("X-Nul", "a\0b"), ("X-Ok", "fine")],
            body: b"ok",
        },
        "OK\r\nX-Injected: 1",
    );
    let set = mocks(&cap, &[id], &no_sanitize());
    let e = &set.entries[0];
    assert_eq!(set.dropped_headers, 3);
    assert_eq!(e.headers.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), ["Content-Type", "X-Ok", "Content-Length"]);
    let raw = String::from_utf8(mockgen::raw_response(e)).unwrap();
    assert!(!raw.contains("Set-Cookie") && !raw.contains("\r\nX-Injected") && raw.starts_with("HTTP/1.1 200 OKX-Injected: 1\r\n"), "{raw}");
    let wm = String::from_utf8(mockgen::wiremock_files(&set).into_iter().find(|(n, _)| n.starts_with("mappings/")).unwrap().1).unwrap();
    assert!(!wm.contains("Set-Cookie") && !wm.contains("Bad Name"), "{wm}");
}

#[test]
fn large_integers_do_not_collide() {
    let d = tempfile::tempdir().unwrap();
    let cap = capture(d.path());
    let a = add(&cap, &post_json("http://api.test/o", r#"{"id":9007199254740993}"#, "A"));
    let b = add(&cap, &post_json("http://api.test/o", r#"{"id":9007199254740992}"#, "B"));
    let set = mocks(&cap, &[a, b], &no_sanitize());
    assert_eq!(set.entries.len(), 2, "different IDs, different mocks");
}

#[test]
fn graphql_queries_are_told_apart() {
    let d = tempfile::tempdir().unwrap();
    let cap = capture(d.path());
    let ids = vec![
        add(&cap, &post_json("http://api.test/graphql", r#"{"query":"query Q { a }","operationName":"Q","variables":{}}"#, "a")),
        add(&cap, &post_json("http://api.test/graphql", r#"{"query":"query Q { b }","operationName":"Q","variables":{}}"#, "b")),
        add(&cap, &post_json("http://api.test/graphql", r#"{"query":"{ me { name } }"}"#, "me")),
        add(&cap, &post_json("http://api.test/search", r#"{"query":"shoes","page":2}"#, "shoes")),
    ];
    let set = mocks(&cap, &ids, &no_sanitize());
    assert_eq!(set.entries.len(), 4);
    let gql: Vec<_> = set.entries.iter().filter(|e| e.path == "/graphql").collect();
    assert!(gql.iter().all(|e| matches!(&e.body_match, BodyMatch::GraphQl { query: Some(_), .. })), "{gql:#?}");
    assert!(matches!(&set.entries.iter().find(|e| e.path == "/search").unwrap().body_match, BodyMatch::Json { .. }), "a search body is not GraphQL");
    for e in &set.entries {
        quena_app_core::rules::validate_match(&mockgen::match_expression(e)).unwrap();
    }
}

#[test]
fn mocks_keep_bodies_whole_when_sanitizing() {
    let d = tempfile::tempdir().unwrap();
    let cap = capture(d.path());
    let big = format!(r#"{{"items":[{}]}}"#, (0..20_000).map(|i| format!(r#"{{"n":{i},"label":"item number {i}"}}"#)).collect::<Vec<_>>().join(","));
    let id = add(&cap, &get("http://api.test/items", 200, "application/json", Box::leak(big.clone().into_boxed_str())));
    for preset in ["gdpr", "support"] {
        let set = mocks(&cap, &[id], &MockOptions { sanitize: SanitizeOptions::preset(preset), ..Default::default() });
        let e = &set.entries[0];
        assert!(e.body.len() > 64 << 10, "{preset}: truncated to {}", e.body.len());
        serde_json::from_slice::<serde_json::Value>(&e.body).unwrap_or_else(|err| panic!("{preset}: not valid JSON any more: {err}"));
    }
}

#[test]
fn wiremock_export_replaces_its_own_files_only() {
    let d = tempfile::tempdir().unwrap();
    let cap = capture(d.path());
    let ids: Vec<_> = ["a", "b", "c"].iter().map(|p| add(&cap, &get(&format!("http://api.test/{p}"), 200, "text/plain", "x"))).collect();
    let out = d.path().join("wm");
    mockgen::write_wiremock(&mocks(&cap, &ids, &no_sanitize()), &out).unwrap();
    std::fs::write(out.join("keep.txt"), "mine").unwrap();
    assert_eq!(out.join("mappings").read_dir().unwrap().count(), 3);
    mockgen::write_wiremock(&mocks(&cap, &ids[..1], &no_sanitize()), &out).unwrap();
    assert_eq!(out.join("mappings").read_dir().unwrap().count(), 1, "stale mappings removed");
    assert_eq!(out.join("__files").read_dir().unwrap().count(), 1);
    assert_eq!(std::fs::read_to_string(out.join("keep.txt")).unwrap(), "mine");
    assert_eq!(out.read_dir().unwrap().count(), 4, "no temporary folder left: {:?}", out.read_dir().unwrap().map(|e| e.unwrap().file_name()).collect::<Vec<_>>());
    // ZIP: replaced as a whole, no temporary file left.
    let z = d.path().join("wm.zip");
    std::fs::write(&z, "old").unwrap();
    mockgen::write_wiremock(&mocks(&cap, &ids, &no_sanitize()), &z).unwrap();
    assert_eq!(zip::ZipArchive::new(std::fs::File::open(&z).unwrap()).unwrap().file_names().filter(|n| n.starts_with("mappings/")).count(), 3);
    assert_eq!(d.path().read_dir().unwrap().count(), 3, "cap, wm, wm.zip");
}

#[test]
fn preview_counts_match_the_result() {
    let d = tempfile::tempdir().unwrap();
    let cap = capture(d.path());
    let ids = vec![
        add(&cap, &get(&format!("http://api.test/reset/{JWT}"), 200, "text/plain", "r")),
        add(&cap, &get("http://api.test/items?page=1&_=1", 200, "application/json", "[1]")),
        add(&cap, &get("http://api.test/items?page=1&_=2", 200, "application/json", "[1]")),
        add(&cap, &get("http://api.test/items?page=1&_=3", 200, "application/json", "[2]")),
        add(&cap, &get(&format!("http://api.test/token?access_token={JWT}"), 200, "text/plain", "t1")),
        add(&cap, &get("http://api.test/token?access_token=other-token-value", 200, "text/plain", "t2")),
        add(&cap, &post_json("http://api.test/login", r#"{"user":"a","password":"one"}"#, "ok")),
        add(&cap, &post_json("http://api.test/login", r#"{"user":"a","password":"two"}"#, "ok2")),
        add(&cap, &get("http://api.test/app.js", 200, "application/javascript", "x")),
        add(&cap, &get("http://api.test/cached", 304, "text/plain", "")),
    ];
    for repeats in [Repeats::Last, Repeats::Sequence] {
        for sanitize in [None, SanitizeOptions::preset("credentials"), SanitizeOptions::preset("gdpr")] {
            let opts = MockOptions { repeats, sanitize: sanitize.clone(), ..Default::default() };
            let real = mockgen::MockPreview::of(&mocks(&cap, &ids, &opts));
            let preview = mockgen::MockPreview::of(&mockgen::generate(&cap, &ids, &opts, false, &quena_formats::NoProgress).unwrap());
            let what = format!("{repeats:?} {:?}", sanitize.map(|s| s.preset));
            assert_eq!((preview.mappings, preview.sequences, &preview.skipped_by_reason), (real.mappings, real.sequences, &real.skipped_by_reason), "{what}");
            assert_eq!(preview.entries.iter().map(|e| (e.session, e.body_match)).collect::<Vec<_>>(), real.entries.iter().map(|e| (e.session, e.body_match)).collect::<Vec<_>>(), "{what}");
        }
    }
}

/// A package file with these rules and one response file `ok.dat`.
fn package_file(path: &std::path::Path, rules: Vec<Rule>) {
    let mut z = zip::ZipWriter::new(std::fs::File::create(path).unwrap());
    let o = zip::write::SimpleFileOptions::default();
    z.start_file("rules.json", o).unwrap();
    z.write_all(&serde_json::to_vec(&AutoResponderState { rules, ..Default::default() }).unwrap()).unwrap();
    z.start_file("responses/ok.dat", o).unwrap();
    z.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap();
    z.finish().unwrap();
}

#[test]
fn package_import_rules_are_limited() {
    let l = live();
    let pkg = l.dir.path().join("Limits.quena-mocks");
    package_file(
        &pkg,
        vec![
            Rule { match_: "METHOD:GET EXACT:http://a.invalid/ok".into(), action: "responses/ok.dat".into(), latency_ms: 999_999, ..Default::default() },
            Rule { match_: r"regex:^http://b\.invalid/x/(.*)$".into(), action: "responses/ok.dat".into(), ..Default::default() },
            Rule { match_: "ok".into(), action: "responses/ok.dat".into(), ..Default::default() },
            Rule { match_: r"regex:^http://a\.invalid/|.*".into(), action: "*404".into(), ..Default::default() },
            Rule { match_: "EXACT:http://a.invalid/slow".into(), action: "*delay:99999999".into(), ..Default::default() },
        ],
    );
    let p = l.core.mock_import_package(pkg, false).unwrap();
    assert_eq!((p.name.as_str(), p.rules, p.rejected), ("limits", 2, 3));
    assert_eq!(p.hosts, ["a.invalid", "b.invalid"]);
    let st = l.core.rules.clone().unwrap().autoresponder();
    assert_eq!(st.rules[0].latency_ms, 60_000, "latency capped");
    assert!(std::path::Path::new(&st.rules[1].action.replace("$$", "$")).is_file());
}

#[test]
fn package_names_are_case_insensitive() {
    let l = live();
    let rules = l.core.rules.clone().unwrap();
    // A package installed before names were lower case.
    let mut st = rules.autoresponder();
    st.rules.push(Rule { match_: "EXACT:http://a.invalid/old".into(), action: "*200".into(), comment: "pkg:Shop".into(), ..Default::default() });
    rules.set_autoresponder(st, true).unwrap();
    std::fs::create_dir_all(l.dir.path().join("mocks/Shop/responses")).unwrap();
    let rule = || vec![Rule { match_: "METHOD:GET EXACT:http://a.invalid/ok".into(), action: "responses/ok.dat".into(), ..Default::default() }];
    for file in ["Shop.quena-mocks", "shop.quena-mocks", "SHOP.quena-mocks"] {
        let pkg = l.dir.path().join(file);
        package_file(&pkg, rule());
        assert_eq!(l.core.mock_import_package(pkg, false).unwrap().name, "shop");
    }
    let st = rules.autoresponder();
    assert_eq!(st.rules.len(), 1, "{:#?}", st.rules);
    assert_eq!(st.rules[0].comment, "pkg:shop");
    let pkgs = l.core.mock_packages();
    assert_eq!(pkgs.iter().map(|p| (p.name.as_str(), p.rules)).collect::<Vec<_>>(), [("shop", 1)]);
    // One generation folder, the old flat layout gone.
    let pkg_dir = std::path::PathBuf::from(&pkgs[0].dir);
    assert_eq!(pkg_dir.read_dir().unwrap().count(), 1);
    assert!(!pkg_dir.join("responses").exists());
    assert_eq!(l.core.mock_remove_package("SHOP").unwrap(), 1);
    assert!(l.core.mock_packages().is_empty());
}

#[test]
fn concurrent_installs_do_not_lose_rules() {
    let l = live();
    let n = 8;
    let files: Vec<_> = (0..n)
        .map(|i| {
            let p = l.dir.path().join(format!("p{i}.quena-mocks"));
            package_file(&p, (0..5).map(|k| Rule { match_: format!("METHOD:GET EXACT:http://p{i}.invalid/{k}"), action: "responses/ok.dat".into(), ..Default::default() }).collect());
            p
        })
        .collect();
    std::thread::scope(|s| {
        for f in &files {
            let core = l.core.clone();
            s.spawn(move || {
                for _ in 0..3 {
                    core.mock_import_package(f.clone(), false).unwrap();
                }
            });
        }
        // Rule changes from elsewhere at the same time.
        let rules = l.core.rules.clone().unwrap();
        s.spawn(move || {
            for k in 0..20 {
                rules.update_autoresponder(false, |st| st.rules.push(Rule { match_: format!("EXACT:http://other.invalid/{k}"), action: "*200".into(), ..Default::default() })).unwrap();
            }
        });
    });
    let st = l.core.rules.clone().unwrap().autoresponder();
    assert_eq!(st.rules.len(), n * 5 + 20);
    let pkgs = l.core.mock_packages();
    assert_eq!(pkgs.len(), n);
    assert!(pkgs.iter().all(|p| p.rules == 5 && std::path::Path::new(&p.dir).read_dir().unwrap().count() == 1), "{pkgs:#?}");
    // Every rule's response file exists.
    assert!(st.rules.iter().filter(|r| r.comment.starts_with("pkg:")).all(|r| std::path::Path::new(&r.action).is_file()));
}

#[test]
fn live_wildcards_hashes_head_204_and_sequence_reset() {
    let l = live();
    let cap = l.core.capture();
    let form = "data=".to_string() + &"x".repeat(200_000) + "&end=1";
    let text = "line\n".repeat(50_000);
    let ids = vec![
        add(&cap, &get(&format!("http://mock.invalid/reset/{JWT}"), 200, "text/plain", "reset ok")),
        add(&cap, &S { method: "POST", url: "http://mock.invalid/form", req_headers: &[("Content-Type", "application/x-www-form-urlencoded")], req: form.as_bytes(), status: 200, headers: &[("Content-Type", "text/plain")], body: b"big form" }),
        add(&cap, &S { method: "POST", url: "http://mock.invalid/text", req_headers: &[("Content-Type", "text/plain")], req: text.as_bytes(), status: 200, headers: &[("Content-Type", "text/plain")], body: b"big text" }),
        add(&cap, &S { method: "HEAD", url: "http://mock.invalid/file", req_headers: &[], req: b"", status: 200, headers: &[("Content-Type", "application/pdf"), ("Content-Length", "1234")], body: b"" }),
        add(&cap, &S { method: "DELETE", url: "http://mock.invalid/item/1", req_headers: &[], req: b"", status: 204, headers: &[("Content-Length", "0")], body: b"" }),
        add(&cap, &get("http://mock.invalid/poll", 200, "text/plain", "poll 1")),
        add(&cap, &get("http://mock.invalid/poll", 200, "text/plain", "poll 2")),
    ];
    let opts = MockOptions { repeats: Repeats::Sequence, ..MockOptions::default() };
    let set = mocks(&cap, &ids, &opts);
    let expr = |path: &str| mockgen::match_expression(set.entries.iter().find(|e| e.path == path).unwrap());
    assert!(expr("/form").starts_with("METHOD:POST BODYHASH:") && expr("/text").starts_with("METHOD:POST BODYHASH:"), "{}", expr("/form"));
    l.apply(&ids, opts, "live");

    let (code, _, body) = curl(&l.proxy, &[&format!("http://mock.invalid/reset/{JWT}")]);
    assert_eq!((code, body.as_str()), (200, "reset ok"), "the real token matches the sanitized path");
    let (code, _, body) = curl(&l.proxy, &["http://mock.invalid/reset/another"]);
    assert_eq!((code, body.as_str()), (200, "reset ok"));
    let f = l.dir.path().join("form.txt");
    std::fs::write(&f, &form).unwrap();
    let (code, _, body) = curl(&l.proxy, &["-H", "Content-Type: application/x-www-form-urlencoded", "--data-binary", &format!("@{}", f.display()), "http://mock.invalid/form"]);
    assert_eq!((code, body.as_str()), (200, "big form"));
    let (code, _, _) = curl(&l.proxy, &["-H", "Content-Type: application/x-www-form-urlencoded", "--data-binary", "data=y&end=1", "http://mock.invalid/form"]);
    assert_eq!(code, 404);
    std::fs::write(&f, &text).unwrap();
    let (code, _, body) = curl(&l.proxy, &["-H", "Content-Type: text/plain", "--data-binary", &format!("@{}", f.display()), "http://mock.invalid/text"]);
    assert_eq!((code, body.as_str()), (200, "big text"));
    // HEAD announces the length of the recorded GET body.
    let (code, head, _) = curl(&l.proxy, &["-I", "http://mock.invalid/file"]);
    assert!(code == 200 && head.contains("content-length: 1234"), "{head}");
    let head_rule = l.core.rules.clone().unwrap().autoresponder().rules.into_iter().find(|r| r.match_.starts_with("METHOD:HEAD")).unwrap();
    let dat = String::from_utf8(std::fs::read(&head_rule.action).unwrap()).unwrap();
    assert!(dat.contains("Content-Length: 1234\r\n") && dat.ends_with("\r\n\r\n"), "{dat}");
    let (code, head, body) = curl(&l.proxy, &["-X", "DELETE", "http://mock.invalid/item/1"]);
    assert!(code == 204 && body.is_empty() && !head.contains("content-length"), "{head}");

    let polls = |n: usize| (0..n).map(|_| curl(&l.proxy, &["http://mock.invalid/poll"]).2).collect::<Vec<_>>();
    assert_eq!(polls(3), ["poll 1", "poll 2", "poll 2"]);
    assert!(l.core.mock_reset_sequences("LIVE").unwrap() >= 2);
    assert_eq!(polls(2), ["poll 1", "poll 2"], "the sequence starts over");
    assert!(l.core.mock_reset_sequences("../x").is_err());
}

/// Writes a WireMock export with priorities, a mixed sequence and sanitized path segments to
/// `$QUENA_WIREMOCK_OUT` (for checking against a real WireMock; see the review notes).
#[test]
#[ignore]
fn wiremock_export_for_a_real_wiremock() {
    let out = std::path::PathBuf::from(std::env::var("QUENA_WIREMOCK_OUT").expect("QUENA_WIREMOCK_OUT"));
    let d = tempfile::tempdir().unwrap();
    let cap = capture(d.path());
    let ids = vec![
        add(&cap, &get("http://api.test/p?_=1", 200, "text/plain", "bare")),
        add(&cap, &get("http://api.test/p?x=1&_=2", 200, "text/plain", "one")),
        add(&cap, &get("http://api.test/p?x=1&y=2", 200, "text/plain", "exact")),
        add(&cap, &post_json("http://api.test/p", r#"{"a":1}"#, "body")),
        add(&cap, &get("http://api.test/seq?_=1", 200, "text/plain", "s1")),
        add(&cap, &get("http://api.test/seq", 200, "text/plain", "s2")),
        add(&cap, &get("http://api.test/seq?_=3", 200, "text/plain", "s3")),
        add(&cap, &get(&format!("http://api.test/reset/{JWT}"), 200, "text/plain", "reset")),
        add(&cap, &get("http://api.test/users/max%40example.com/orders", 200, "text/plain", "orders")),
    ];
    let set = mocks(&cap, &ids, &MockOptions { repeats: Repeats::Sequence, sanitize: SanitizeOptions::preset("support"), ..Default::default() });
    mockgen::write_wiremock(&set, &out).unwrap();
}
