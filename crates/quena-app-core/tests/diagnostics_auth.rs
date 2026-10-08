//! Authentication facts end to end: a generated HAR of an OpenID Connect flow (discovery,
//! authorize redirect, callback, token request with a form body, token response with an
//! unsigned test JWT, an API call with the expired JWT answered by 401 + WWW-Authenticate, an
//! Entra ID style error response) → host records (`auth`, redacted URLs and headers) → webdiag.
//! The privacy guarantee: no secret or personal test value reaches a record or the report.
//! The plugin part requires `plugins/build.sh` to have been run (skipped otherwise).
use quena_app_core::diagnostics::{DiagFilter, record_of, scope_ids};
use quena_app_core::{AppCore, Paths};
use quena_plugin_host::AnalyzerSession;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn wait(core: &AppCore, job: u64) {
    let job = core.jobs.get(job).unwrap();
    let t0 = Instant::now();
    while !matches!(format!("{:?}", job.status()).as_str(), "Done" | "Failed" | "Cancelled") {
        assert!(t0.elapsed() < Duration::from_secs(60), "job did not finish");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(format!("{:?}", job.status()), "Done", "{:?}", job.snapshot().error);
}

/// Secret and personal values of the fixture; none may leave the host.
const SECRETS: &[&str] = &[
    "SECRET-CODE-123",
    "SECRET-STATE",
    "SECRET-NONCE",
    "SECRET-CHALLENGE",
    "SECRET-VERIFIER",
    "SECRET-CLIENT-SECRET",
    "SECRET-REFRESH",
    "SECRET-SUB",
    "SECRET-OID",
    "SECRET-JTI",
    "SECRET-SIG",
    "SECRET-CB-QUERY",
    "SECRET-BASIC",
    "secret.person",
    "Secret Person",
];

fn b64url(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for k in 0..=c.len() {
            out.push(A[(n >> (18 - 6 * k) & 63) as usize] as char);
        }
    }
    out
}

/// An unsigned test JWT (the "signature" is a marker) with personal claims.
fn test_jwt(exp: u64) -> String {
    let header = json!({"alg": "RS256", "typ": "JWT", "kid": "k1"});
    let payload = json!({
        "iss": "https://login.example.test/tenant-1/v2.0", "aud": "api://orders", "exp": exp, "nbf": exp - 3600, "iat": exp - 3600,
        "azp": "web-client", "tid": "tenant-1", "ver": "2.0", "scp": "Orders.Read openid", "roles": ["Reader"],
        "sub": "SECRET-SUB", "oid": "SECRET-OID", "email": "secret.person@example.com", "upn": "secret.person@example.com",
        "name": "Secret Person", "preferred_username": "secret.person@example.com", "nonce": "SECRET-NONCE", "jti": "SECRET-JTI",
    });
    format!("{}.{}.SECRET-SIG", b64url(header.to_string().as_bytes()), b64url(payload.to_string().as_bytes()))
}

fn time_iso(ms: i64) -> String {
    let t = time::OffsetDateTime::from_unix_timestamp_nanos(ms as i128 * 1_000_000).unwrap();
    t.format(&time::format_description::well_known::Rfc3339).unwrap()
}

struct Req<'a> {
    method: &'a str,
    url: &'a str,
    headers: Vec<(&'a str, String)>,
    body: Option<(&'a str, String)>,
}

fn entry(ms: i64, r: Req, status: u16, resp_headers: Vec<(&str, String)>, resp_body: (&str, String)) -> Value {
    let t0 = 1_790_000_000_000i64;
    let h = |l: &[(&str, String)]| l.iter().map(|(n, v)| json!({"name": n, "value": v})).collect::<Vec<_>>();
    let mut req = json!({"method": r.method, "url": r.url, "httpVersion": "HTTP/1.1", "cookies": [], "headers": h(&r.headers), "queryString": [], "headersSize": -1, "bodySize": -1});
    if let Some((mime, text)) = r.body {
        req["postData"] = json!({"mimeType": mime, "text": text});
    }
    let location = resp_headers.iter().find(|(n, _)| *n == "Location").map(|(_, v)| v.clone()).unwrap_or_default();
    let mut rh = resp_headers.clone();
    rh.push(("Content-Type", resp_body.0.to_string()));
    json!({
        "startedDateTime": time_iso(t0 + ms),
        "time": 30,
        "request": req,
        "response": {
            "status": status, "statusText": "", "httpVersion": "HTTP/1.1", "cookies": [], "headers": h(&rh),
            "content": {"size": resp_body.1.len(), "mimeType": resp_body.0, "text": resp_body.1},
            "redirectURL": location, "headersSize": -1, "bodySize": resp_body.1.len()
        },
        "cache": {},
        "timings": {"blocked": -1, "dns": -1, "connect": -1, "ssl": -1, "send": 1, "wait": 25, "receive": 4}
    })
}

const EXPIRED: u64 = 1_789_990_000; // before the capture (2026-09-21)

fn oidc_har() -> Value {
    let jwt = test_jwt(EXPIRED);
    let id_token = test_jwt(EXPIRED + 7200);
    let login = "https://login.example.test/tenant-1";
    let get = |url: &'static str| Req { method: "GET", url, headers: vec![], body: None };
    let e = vec![
        entry(
            0,
            Req { method: "GET", url: "https://login.example.test/tenant-1/v2.0/.well-known/openid-configuration", headers: vec![], body: None },
            200,
            vec![],
            (
                "application/json",
                json!({
                    "issuer": format!("{login}/v2.0"), "authorization_endpoint": format!("{login}/oauth2/v2.0/authorize"),
                    "token_endpoint": format!("{login}/oauth2/v2.0/token"), "jwks_uri": format!("{login}/discovery/v2.0/keys"),
                    "end_session_endpoint": format!("{login}/oauth2/v2.0/logout"), "response_types_supported": ["code"],
                })
                .to_string(),
            ),
        ),
        entry(
            100,
            get("https://login.example.test/tenant-1/oauth2/v2.0/authorize?client_id=web-client&response_type=code&response_mode=query&scope=openid+profile+offline_access+api%3A%2F%2Forders%2FOrders.Read&redirect_uri=https%3A%2F%2Fapp.example.test%2Fcb%3Ftenant%3DSECRET-CB-QUERY&state=SECRET-STATE&nonce=SECRET-NONCE&code_challenge=SECRET-CHALLENGE-0123456789abcdefghijklmnop&code_challenge_method=S256&login_hint=secret.person%40example.com&prompt=select_account"),
            302,
            vec![("Location", "https://app.example.test/cb?code=SECRET-CODE-123&state=SECRET-STATE&session_state=s-1".to_string())],
            ("text/html", String::new()),
        ),
        entry(200, get("https://app.example.test/cb?code=SECRET-CODE-123&state=SECRET-STATE&session_state=s-1"), 200, vec![], ("text/html", "<p>ok</p>".into())),
        entry(
            300,
            Req {
                method: "POST",
                url: "https://login.example.test/tenant-1/oauth2/v2.0/token",
                headers: vec![("Content-Type", "application/x-www-form-urlencoded".into()), ("Authorization", "Basic SECRET-BASIC==".into())],
                body: Some((
                    "application/x-www-form-urlencoded",
                    "grant_type=authorization_code&client_id=web-client&code=SECRET-CODE-123&code_verifier=SECRET-VERIFIER&client_secret=SECRET-CLIENT-SECRET&redirect_uri=https%3A%2F%2Fapp.example.test%2Fcb%3Ftenant%3DSECRET-CB-QUERY&scope=openid+offline_access".into(),
                )),
            },
            200,
            vec![("Cache-Control", "no-store".into())],
            (
                "application/json; charset=utf-8",
                json!({"token_type": "Bearer", "scope": "Orders.Read openid", "expires_in": 3599, "ext_expires_in": 3599, "access_token": jwt, "refresh_token": "SECRET-REFRESH", "id_token": id_token}).to_string(),
            ),
        ),
        entry(
            400,
            Req { method: "GET", url: "https://api.example.test/orders/42", headers: vec![("Authorization", format!("Bearer {jwt}"))], body: None },
            401,
            vec![("WWW-Authenticate", r#"Bearer realm="api", error="invalid_token", error_description="The token expired at '09/21/2026 10:00:00'""#.into())],
            ("application/json", r#"{"message":"unauthorized"}"#.into()),
        ),
        entry(
            500,
            Req {
                method: "POST",
                url: "https://login.example.test/tenant-1/oauth2/v2.0/token",
                headers: vec![("Content-Type", "application/x-www-form-urlencoded".into())],
                body: Some(("application/x-www-form-urlencoded", "grant_type=refresh_token&client_id=web-client&refresh_token=SECRET-REFRESH".into())),
            },
            400,
            vec![],
            (
                "application/json",
                json!({
                    "error": "invalid_grant",
                    "error_description": "AADSTS70008: The provided authorization code or refresh token has expired due to inactivity. User secret.person@example.com must sign in again. Trace ID: 0a1b Correlation ID: 2c3d",
                    "error_codes": [70008], "timestamp": "2026-09-21 10:00:00Z", "trace_id": "0a1b-trace", "correlation_id": "2c3d-corr",
                    "error_uri": "https://login.example.test/error?code=70008",
                })
                .to_string(),
            ),
        ),
    ];
    json!({"log": {"version": "1.2", "creator": {"name": "quena-e2e", "version": "1"}, "entries": e}})
}

fn assert_clean(what: &str, text: &str) {
    for s in SECRETS {
        assert!(!text.contains(s), "{what}: {s} leaked in {text}");
    }
}

#[test]
fn authentication_facts_from_a_har_import() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("settings.json"), r#"{"proxy":{"actAsSystemProxy":false,"captureOnStartup":false}}"#).unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    let har = dir.path().join("oidc.har");
    std::fs::write(&har, serde_json::to_vec(&oidc_har()).unwrap()).unwrap();
    wait(&core, core.import_archive(har).unwrap());
    let cap = core.capture();
    cap.index.tick();
    let (ids, _) = scope_ids(&cap, None, &DiagFilter::default());
    let records: Vec<AnalyzerSession> = ids.iter().filter_map(|id| record_of(&cap, *id, &|| false)).collect();
    assert_eq!(records.len(), 6, "{records:#?}");
    let all = format!("{records:?}");
    assert_clean("records", &all);
    let jwt = test_jwt(EXPIRED);
    assert!(!all.contains(&jwt[..40]), "token in records");

    // Discovery.
    let d = records[0].auth.as_ref().and_then(|a| a.discovery.as_ref()).expect("discovery");
    assert_eq!(d.issuer.as_deref(), Some("https://login.example.test/tenant-1/v2.0"));
    assert_eq!(d.token_endpoint.as_deref(), Some("https://login.example.test/tenant-1/oauth2/v2.0/token"));
    assert!(d.authorization_endpoint.is_some() && d.jwks_uri.is_some() && d.end_session_endpoint.is_some());

    // Authorize: OAuth parameters kept (long scope too), state/nonce/challenge/hint not.
    let a = &records[1];
    for kept in [
        "client_id=web-client",
        "response_type=code",
        "response_mode=query",
        "scope=openid+profile+offline_access+api%3A%2F%2Forders%2FOrders.Read",
        "redirect_uri=https%3A%2F%2Fapp.example.test%2Fcb&",
        "code_challenge_method=S256",
        "prompt=select_account",
        "state=%3C12%20bytes%3E",
        "nonce=%3C12%20bytes%3E",
    ] {
        assert!(a.url.contains(kept), "{kept} not in {}", a.url);
    }
    assert!(a.auth.is_none(), "{:?}", a.auth);
    let loc = a.response_headers.iter().find(|(n, _)| n.eq_ignore_ascii_case("location")).map(|(_, v)| v.as_str()).unwrap_or_default();
    assert!(loc.contains("code=%3C15%20bytes%3E") && loc.contains("state=%3C12%20bytes%3E"), "{loc}");
    // Callback.
    assert!(records[2].url.ends_with("?code=%3C15%20bytes%3E&state=%3C12%20bytes%3E&session_state=%3C3%20bytes%3E"), "{}", records[2].url);

    // Token request and response.
    let t = records[3].auth.as_ref().expect("token facts");
    let q = t.oauth_request.as_ref().expect("oauth request");
    assert_eq!((q.grant_type.as_deref(), q.client_id.as_deref(), q.scope.as_deref()), (Some("authorization_code"), Some("web-client"), Some("openid offline_access")));
    assert_eq!(q.redirect_uri.as_deref(), Some("https://app.example.test/cb"));
    assert!(q.has_code && q.has_code_verifier && q.has_client_secret && q.basic_client_auth && !q.has_refresh_token && !q.has_client_assertion);
    let p = t.oauth_response.as_ref().expect("oauth response");
    assert_eq!((p.token_type.as_deref(), p.expires_in, p.scope.as_deref()), (Some("Bearer"), Some(3599), Some("Orders.Read openid")));
    assert!(p.has_access_token && p.has_refresh_token && p.has_id_token && p.error.is_none());
    let at = p.access_token.as_ref().expect("access token claims");
    assert_eq!((at.alg.as_str(), at.iss.as_deref(), at.exp, at.client.as_deref(), at.tenant.as_deref()), ("RS256", Some("https://login.example.test/tenant-1/v2.0"), Some(EXPIRED), Some("web-client"), Some("tenant-1")));
    assert_eq!((at.aud.clone(), at.scopes.clone(), at.roles.clone()), (vec!["api://orders".to_string()], vec!["Orders.Read".to_string(), "openid".into()], vec!["Reader".to_string()]));
    assert_eq!(p.id_token.as_ref().unwrap().exp, Some(EXPIRED + 7200));
    assert!(t.bearer.is_none() && t.opaque_bearer.is_none(), "Basic client auth is no bearer");

    // API call with the expired JWT, answered by 401 + WWW-Authenticate.
    let api = &records[4];
    let b = api.auth.as_ref().and_then(|a| a.bearer.as_ref()).expect("bearer claims");
    assert_eq!((b.exp, b.size as usize), (Some(EXPIRED), jwt.len()));
    let wa = api.response_headers.iter().find(|(n, _)| n == "WWW-Authenticate").map(|(_, v)| v.as_str()).unwrap();
    assert_eq!(wa, r#"Bearer realm="api", error="invalid_token", error_description="The token expired at '09/21/2026 10:00:00'""#);
    assert!(api.request_headers.iter().any(|(n, v)| n == "Authorization" && v == &format!("Bearer <{} bytes>", jwt.len())));

    // Entra ID error response: codes, support ids, e-mail masked.
    let e = records[5].auth.as_ref().and_then(|a| a.oauth_response.as_ref()).expect("error response");
    assert_eq!((e.error.as_deref(), e.error_codes.clone()), (Some("invalid_grant"), vec![70008]));
    assert_eq!((e.trace_id.as_deref(), e.correlation_id.as_deref()), (Some("0a1b-trace"), Some("2c3d-corr")));
    let desc = e.error_description.as_deref().unwrap();
    assert!(desc.starts_with("AADSTS70008: The provided authorization code") && desc.contains("User <email> must sign in again"), "{desc}");
    assert!(records[5].auth.as_ref().unwrap().oauth_request.as_ref().is_some_and(|q| q.has_refresh_token && q.grant_type.as_deref() == Some("refresh_token")));

    // Through the plugin: the records cross the WIT boundary; the report carries no secret.
    let dist = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../plugins/dist");
    if !dist.join("webdiag").exists() {
        eprintln!("webdiag plugin not built – run plugins/build.sh");
        return;
    }
    core.init_plugins(Some(dist)).unwrap();
    let wd = core.diag_analyzers().into_iter().find(|a| a.id == "io.github.hkiam.webdiag").expect("webdiag");
    wait(&core, core.diag_run(wd.index, r#"{"profile":"full","lang":"en"}"#.into(), None, Default::default()).unwrap());
    let report = core.diag_report().expect("report");
    assert_clean("report", &report);
    assert!(!report.contains(&jwt[..40]), "token in report");
    let r: Value = serde_json::from_str(&report).unwrap();
    assert!(r["findings"].is_array(), "{r:#}");
}
