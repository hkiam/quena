//! WP-I: load, detect, decode, errors, timeout, memory limit.
//! Requires `plugins/build.sh` to have been run (skips otherwise).

use quena_plugin_host::PluginHost;
use std::path::PathBuf;
use std::time::Instant;

fn host() -> Option<std::sync::Arc<PluginHost>> {
    let dist = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../plugins/dist");
    if !dist.join("rot13-test").exists() {
        eprintln!("plugins not built – run plugins/build.sh");
        return None;
    }
    let state = tempfile::tempdir().unwrap().keep();
    Some(PluginHost::new(vec![dist], &state).unwrap())
}

fn index(h: &PluginHost, id: &str) -> u16 {
    h.list().into_iter().find(|p| p.id == id).unwrap().index
}

#[test]
fn rot13_decodes_streaming() {
    let Some(h) = host() else { return };
    let list = h.list();
    assert!(list.iter().any(|p| p.id == "io.github.hkiam.rot13-test" && p.error.is_none()), "{list:#?}");
    let c = h.candidates(Some("text/x-rot13"), b"Uryyb");
    assert_eq!(c.first().map(|x| x.1.as_str()), Some("ROT13"));
    let idx = index(&h, "io.github.hkiam.rot13-test");
    let input = "Uryyb Jbeyq! ".repeat(100_000); // 1.3 MB, several chunks
    let mut out = Vec::new();
    let t = Instant::now();
    h.decode(idx, Some("text/x-rot13"), &mut input.as_bytes(), &mut out, &|| false).unwrap();
    eprintln!("rot13 1.3 MB in {:?}", t.elapsed());
    assert_eq!(String::from_utf8(out).unwrap(), "Hello World! ".repeat(100_000));
}

#[test]
fn misbehaving_plugin_is_contained() {
    let Some(h) = host() else { return };
    let idx = index(&h, "io.github.hkiam.evil-test");
    let mut out = Vec::new();
    // Trap (panic inside the plugin)
    let e = h.decode(idx, Some("trap"), &mut &b"x"[..], &mut out, &|| false).unwrap_err();
    assert!(e.to_string().contains("trap"), "{e}");
    // Error result
    let e = h.decode(idx, Some("error"), &mut &b"x"[..], &mut out, &|| false).unwrap_err();
    assert!(e.to_string().contains("evil decoding error"));
    // Infinite loop → deadline
    let t = Instant::now();
    let e = h.decode(idx, Some("loop"), &mut &b"x"[..], &mut out, &|| false).unwrap_err();
    assert!(t.elapsed().as_secs() < 30, "deadline not enforced");
    eprintln!("loop stopped after {:?}: {e}", t.elapsed());
    // Memory hog → limit
    let e = h.decode(idx, Some("oom"), &mut &b"x"[..], &mut out, &|| false).unwrap_err();
    eprintln!("oom: {e}");
    // The host still works afterwards.
    let r = index(&h, "io.github.hkiam.rot13-test");
    let mut out = Vec::new();
    h.decode(r, None, &mut &b"nop"[..], &mut out, &|| false).unwrap();
    assert_eq!(out, b"abc");
}

#[test]
fn header_inspector_decodes_auth_tokens() {
    let Some(h) = host() else { return };
    if !h.list().iter().any(|p| p.id == "io.github.hkiam.auth-tokens") {
        eprintln!("auth-tokens plugin not built – run plugins/build.sh");
        return;
    }
    let p = h.list().into_iter().find(|p| p.id == "io.github.hkiam.auth-tokens").unwrap();
    assert!(p.error.is_none(), "{p:#?}");
    assert_eq!(p.kind, quena_plugin_host::PluginKind::HeaderInspector);
    assert!(p.headers.iter().any(|x| x == "www-authenticate"));
    // Header inspectors are no body decoders.
    assert!(h.candidates(Some("text/plain"), b"Negotiate").iter().all(|c| c.1 != p.tab));

    // NTLM Type 1 inside Negotiate (a client that found no Kerberos ticket).
    let r = h.inspect_header("Authorization", "Negotiate TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAKAPRlAAAADw==");
    assert_eq!(r.len(), 1, "{r:#?}");
    let r = &r[0];
    assert!(r.error.is_none(), "{r:#?}");
    assert_eq!((r.nodes[0].depth, r.nodes[0].kind, r.nodes[0].name.as_str()), (0, "section", "NTLM Type 1 (Negotiate)"));
    assert!(r.nodes.iter().any(|n| n.kind == "field" && n.name == "OS version" && n.value == "10.0 (build 26100), NTLM revision 15"));
    assert!(r.nodes.iter().any(|n| n.kind == "note" && n.value.contains("fell back to NTLM")));
    assert_eq!(r.nodes.last().map(|n| n.kind), Some("code"));

    // Not for the plugin: other headers, other schemes, challenges without token.
    assert!(h.inspect_header("Cookie", "Negotiate TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAKAPRlAAAADw==").is_empty());
    assert!(h.inspect_header("Authorization", "Basic dXNlcjpwYXNz").is_empty());
    assert!(h.inspect_header("WWW-Authenticate", "Negotiate").is_empty());

    // Disabled plugins are not asked.
    h.set_enabled("io.github.hkiam.auth-tokens", false).unwrap();
    assert!(h.inspect_header("Authorization", "NTLM TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAKAPRlAAAADw==").is_empty());
}

/// The second start loads compiled machine code instead of compiling again, and a
/// damaged cache file is ignored (recompiled).
#[test]
fn compiled_plugins_are_cached() {
    let dist = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../plugins/dist");
    if !dist.join("rot13-test").exists() {
        return;
    }
    let state = tempfile::tempdir().unwrap();
    let t = Instant::now();
    drop(PluginHost::new(vec![dist.clone()], state.path()).unwrap());
    let cold = t.elapsed();
    let cache: Vec<_> = std::fs::read_dir(state.path().join("plugin-cache")).unwrap().flatten().map(|e| e.path()).collect();
    assert!(!cache.is_empty(), "no compile cache written");
    let t = Instant::now();
    let h = PluginHost::new(vec![dist.clone()], state.path()).unwrap();
    let warm = t.elapsed();
    eprintln!("plugin load cold {cold:?}, warm {warm:?}");
    assert!(h.list().iter().all(|p| p.error.is_none()));
    // Damaged cache: still works.
    for f in &cache {
        std::fs::write(f, b"garbage").unwrap();
    }
    let h = PluginHost::new(vec![dist], state.path()).unwrap();
    let idx = h.list().into_iter().find(|p| p.id == "io.github.hkiam.rot13-test").unwrap().index;
    let mut out = Vec::new();
    h.decode(idx, Some("text/x-rot13"), &mut &b"Uryyb"[..], &mut out, &|| false).unwrap();
    assert_eq!(out, b"Hello");
}

/// JWT header inspector (with the sandbox's wall clock for relative dates) and GraphQL decoder.
#[test]
fn jwt_and_graphql_plugins() {
    let Some(h) = host() else { return };
    if !h.list().iter().any(|p| p.id == "io.github.hkiam.jwt") || !h.list().iter().any(|p| p.id == "io.github.hkiam.graphql") {
        eprintln!("jwt/graphql plugins not built – run plugins/build.sh");
        return;
    }
    // {"alg":"HS256","typ":"JWT"} . {"sub":"42","exp":4102444800} (2100-01-01) . 32-byte signature
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MiIsImV4cCI6NDEwMjQ0NDgwMH0.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let r = h.inspect_header("Authorization", &format!("Bearer {jwt}"));
    let r = r.iter().find(|r| r.plugin_id == "io.github.hkiam.jwt").expect("jwt inspection");
    assert!(r.error.is_none(), "{r:#?}");
    assert!(r.nodes.iter().any(|n| n.name == "exp (Expiration time)" && n.value.starts_with("2100-01-01 00:00:00 UTC") && n.value.contains("valid for")), "{r:#?}");
    assert!(h.inspect_header("Cookie", &format!("theme=dark; access_token={jwt}")).iter().any(|r| r.plugin_id == "io.github.hkiam.jwt"));

    let body = br#"{"operationName":"Me","query":"query Me { me { name } }","variables":{}}"#;
    let c = h.candidates(Some("application/json"), body);
    assert_eq!(c.first().map(|x| x.1.as_str()), Some("GraphQL"), "{c:?}");
    let mut out = Vec::new();
    h.decode(c[0].0, Some("application/json"), &mut &body[..], &mut out, &|| false).unwrap();
    let out = String::from_utf8(out).unwrap();
    assert!(out.starts_with("Operation: query Me\n\n--- Query ---\nquery Me {\n  me {\n    name\n  }\n}\n"), "{out}");
}

/// Synthetic session for the analyzer: `n`-th request of a slow, repeated API call.
fn analyzer_session(id: u64, started: u64, status: u16, duration_ms: u32) -> quena_plugin_host::AnalyzerSession {
    use quena_plugin_host::{AnalyzerSession, AnalyzerTextInfo, AnalyzerTimers};
    AnalyzerSession {
        id,
        kind: "http".into(),
        started,
        duration_ms: Some(duration_ms),
        method: "GET".into(),
        url: "https://api.example.test/odata/Cases(42)?$expand=Items".into(),
        host: "api.example.test".into(),
        version: "HTTP/1.1".into(),
        status,
        error: None,
        request_bytes: 0,
        response_bytes: 2_000_000,
        response_decoded_bytes: 8_000_000,
        content_type: "application/json".into(),
        request_headers: vec![("Authorization".into(), "Bearer <812 bytes>".into()), ("Cookie".into(), "sid; theme".into())],
        response_headers: vec![("Content-Type".into(), "application/json".into()), ("Cache-Control".into(), "no-store".into())],
        timers: AnalyzerTimers {
            client_begin_request: Some(started),
            server_got_first_byte: Some(started + duration_ms as u64 * 900),
            client_done_response: Some(started + duration_ms as u64 * 1000),
            ..Default::default()
        },
        client_connection: Some(1),
        server_connection_reused: false,
        tls_version: Some("TLSv1.2".into()),
        process: "browser:42".into(),
        request_body_hash: None,
        response_body_hash: Some(0x1234_5678_9abc_def0),
        // Declared UTF-8, but the bytes are not (ENC-MISMATCH): the facts cross the WIT boundary.
        response_text: Some(AnalyzerTextInfo {
            header_charset: Some("utf-8".into()),
            header_resolved: Some("UTF-8".into()),
            effective: "UTF-8".into(),
            source: "header".into(),
            sampled: 4096,
            non_ascii: true,
            decode_errors: 12,
            ..Default::default()
        }),
        request_decoding_error: (id % 100 == 0).then(|| "invalid: gzip: corrupt deflate stream".into()),
        // Authentication facts cross the WIT boundary (every record kind, nested claims).
        auth: id.is_multiple_of(50).then(|| auth_info(id)),
        ..Default::default()
    }
}

/// Every authentication record, filled.
fn auth_info(id: u64) -> quena_plugin_host::AnalyzerAuthInfo {
    use quena_plugin_host::{AnalyzerAuthInfo, AnalyzerJwtClaims, AnalyzerOauthRequest, AnalyzerOauthResponse, AnalyzerOidcDiscovery};
    let claims = AnalyzerJwtClaims {
        alg: "RS256".into(),
        typ: Some("JWT".into()),
        iss: Some("https://login.example.test/tenant/v2.0".into()),
        aud: vec!["api://orders".into()],
        exp: Some(1_727_690_000),
        nbf: Some(1_727_686_400),
        iat: Some(1_727_686_400),
        client: Some("client-1".into()),
        tenant: Some("tenant".into()),
        ver: Some("2.0".into()),
        scopes: vec!["Orders.Read".into()],
        roles: vec!["Admin".into()],
        groups: Some(3),
        groups_overage: id.is_multiple_of(100),
        size: 1200,
    };
    AnalyzerAuthInfo {
        bearer: Some(claims.clone()),
        opaque_bearer: None,
        oauth_request: Some(AnalyzerOauthRequest { grant_type: Some("authorization_code".into()), client_id: Some("client-1".into()), has_code: true, basic_client_auth: true, ..Default::default() }),
        oauth_response: Some(AnalyzerOauthResponse {
            error: Some("invalid_grant".into()),
            error_description: Some("AADSTS70008: The provided authorization code or refresh token has expired.".into()),
            error_codes: vec![70008],
            expires_in: Some(3600),
            access_token: Some(claims.clone()),
            id_token: Some(claims),
            ..Default::default()
        }),
        discovery: Some(AnalyzerOidcDiscovery { issuer: Some("https://login.example.test/tenant/v2.0".into()), token_endpoint: Some("https://login.example.test/token".into()), ..Default::default() }),
    }
}

/// The diagnostics analyzer: describe, a run over synthetic sessions in batches, cancellation.
#[test]
fn webdiag_analyzer() {
    let Some(h) = host() else { return };
    let Some(p) = h.list().into_iter().find(|p| p.id == "io.github.hkiam.webdiag") else {
        eprintln!("webdiag plugin not built – run plugins/build.sh");
        return;
    };
    assert!(p.error.is_none(), "{p:#?}");
    assert_eq!(p.kind, quena_plugin_host::PluginKind::Analyzer);
    assert!(!p.tab.is_empty());
    // Analyzers are neither body decoders nor header inspectors.
    assert!(h.candidates(Some("application/json"), b"{}").iter().all(|c| c.0 != p.index));
    assert!(h.inspect_header("Authorization", "Bearer x").iter().all(|r| r.plugin_id != p.id));
    // …and decoders are no analyzers.
    assert!(h.describe(index(&h, "io.github.hkiam.rot13-test"), "en").is_err());

    let d: serde_json::Value = serde_json::from_str(&h.describe(p.index, "de").unwrap()).expect("describe is JSON");
    assert!(d["profiles"].as_array().is_some_and(|a| !a.is_empty()), "{d:#}");
    assert!(d["options"].is_object(), "{d:#}");

    // 2 500 slow, duplicate, partly failing requests one after another, in two batches.
    let t0 = 1_727_690_000_000_000u64;
    let all: Vec<_> = (0..2500u64).map(|i| analyzer_session(i + 1, t0 + i * 3_000_000, if i % 10 == 0 { 500 } else { 200 }, 2500)).collect();
    let mut batches = all.chunks(2000).map(|c| c.to_vec()).collect::<Vec<_>>().into_iter();
    let t = Instant::now();
    let report = h.analyze(p.index, r#"{"profile":"full","lang":"en"}"#, &mut || batches.next(), &|| false).unwrap();
    eprintln!("webdiag: 2500 sessions in {:?}, report {} bytes", t.elapsed(), report.len());
    let r: serde_json::Value = serde_json::from_str(&report).expect("report is JSON");
    assert_eq!(r["schema"], 1, "{r:#}");
    let findings = r["findings"].as_array().expect("findings");
    assert!(!findings.is_empty(), "no findings: {r:#}");
    assert!(findings.iter().all(|f| f["id"].is_string() && f["severity"].is_string()), "{findings:#?}");
    // Text facts and decoding errors reach the plugin.
    assert!(findings.iter().any(|f| f["id"] == "ENC-MISMATCH"), "{findings:#?}");
    assert!(findings.iter().any(|f| f["id"] == "ENC-DECODE"), "{findings:#?}");

    // Cancelled before the first batch.
    let mut once = vec![all[..10].to_vec()].into_iter();
    let e = h.analyze(p.index, "{}", &mut || once.next(), &|| true).unwrap_err();
    assert!(e.to_string().contains("cancelled"), "{e}");
    // An empty run still reports.
    let empty = h.analyze(p.index, "{}", &mut || None, &|| false).unwrap();
    assert!(serde_json::from_str::<serde_json::Value>(&empty).is_ok(), "{empty}");
    // Disabled analyzers do not run.
    h.set_enabled("io.github.hkiam.webdiag", false).unwrap();
    assert!(h.analyze(p.index, "{}", &mut || None, &|| false).is_err());
}

/// A run cancelled while `finish` runs returns no report; a cancel flag interrupts a call
/// in flight.
#[test]
fn webdiag_analyzer_cancellation() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let Some(h) = host() else { return };
    let Some(p) = h.list().into_iter().find(|p| p.id == "io.github.hkiam.webdiag") else { return };
    let t0 = 1_727_690_000_000_000u64;
    let all: Vec<_> = (0..500u64).map(|i| analyzer_session(i + 1, t0 + i * 3_000_000, 200, 2500)).collect();
    // `cancelled` is checked before and after fetching the (only) batch, twice around the
    // end-of-input `None`, then after `finish`: cancel exactly while `finish` runs.
    let calls = AtomicUsize::new(0);
    let mut once = vec![all.clone()].into_iter();
    let e = h.analyze(p.index, "{}", &mut || once.next(), &|| calls.fetch_add(1, Ordering::SeqCst) >= 4).unwrap_err();
    assert!(e.to_string().contains("cancelled"), "{e}");
    assert_eq!(calls.load(Ordering::SeqCst), 5, "cancel was not checked after finish");
    // Same counts without the cancellation: a report.
    let calls = AtomicUsize::new(0);
    let mut once = vec![all.clone()].into_iter();
    assert!(h.analyze(p.index, "{}", &mut || once.next(), &|| calls.fetch_add(1, Ordering::SeqCst) >= 5).is_ok());

    // Interruptible: a flag raised while the plugin computes stops the call in flight.
    let big: Vec<_> = (0..40_000u64).map(|i| analyzer_session(i + 1, t0 + i * 1_000, if i % 7 == 0 { 500 } else { 200 }, 2500)).collect();
    let mut one = vec![big.clone()].into_iter();
    let t = Instant::now();
    h.analyze(p.index, "{}", &mut || one.next(), &|| false).unwrap();
    let full = t.elapsed();
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let mut one = vec![big].into_iter();
    let started = Arc::new(AtomicBool::new(false));
    let st2 = started.clone();
    let flag = std::thread::spawn(move || {
        while !st2.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        s2.store(true, Ordering::SeqCst);
    });
    let t = Instant::now();
    let e = h
        .analyze_interruptible(
            p.index,
            "{}",
            &mut || {
                started.store(true, Ordering::SeqCst);
                one.next()
            },
            Arc::new(move || stop.load(Ordering::SeqCst)),
        )
        .unwrap_err();
    flag.join().unwrap();
    eprintln!("webdiag: 40 000 sessions in {full:?}; interrupted after {:?}: {e:#}", t.elapsed());
    assert!(e.to_string().contains("cancelled"), "{e}");
    // Only meaningful when the uninterrupted run takes clearly longer than the poll interval.
    if full > std::time::Duration::from_millis(500) {
        assert!(t.elapsed() < full / 2, "not interrupted in flight: {:?} of {full:?}", t.elapsed());
    }
}
