//! OAuth 2 / OpenID Connect analyzers (analyzers/oauth.rs, idp.rs): positive and negative
//! cases per rule, on synthetic captures with the host's authentication facts.
use webdiag::model::{Confidence, Finding, Session, Severity};
use webdiag::testkit::*;

fn run(s: Vec<Session>) -> Vec<Finding> {
    analyse(s, r#"{"profile":"auth"}"#)
}

fn keys(f: &[&Finding]) -> Vec<String> {
    f.iter().map(|x| x.key.clone()).collect()
}

fn fact<'a>(f: &'a Finding, label: &str) -> Option<&'a str> {
    f.facts.iter().find(|(l, _)| l == label).map(|(_, v)| v.as_str())
}

fn any_text(v: &[String], needle: &str) -> bool {
    v.iter().any(|x| x.contains(needle))
}

const ENTRA: &str = "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0";
const ENTRA_ISS: &str = "https://login.microsoftonline.com/72f988bf-0000-0000-0000-000000000000/v2.0";
const KC: &str = "https://sso.example.com/realms/main/protocol/openid-connect";

fn authorize(id: u64, base: &str, query: &str) -> Session {
    get(id, &format!("{base}/authorize?{query}"))
}

// ------------------------------------------------------------------ OAUTH-ERROR

#[test]
fn entra_invalid_client_secret_repeated_is_critical_with_trace_ids() {
    let s: Vec<Session> = (0..3)
        .map(|i| {
            let mut e = oauth_err("invalid_client", "AADSTS7000215: Invalid client secret provided. Ensure the secret being sent in the request is the client secret value, not the client secret ID.");
            e.trace_id = Some(format!("trace-{i}"));
            e.correlation_id = Some("corr-1".into());
            post(i, &format!("{ENTRA}/token")).at(i * 2000).status(401).oauth_req(webdiag::model::OAuthRequest { has_client_secret: true, ..token_req("client_credentials", "app-1") }).oauth_resp(e)
        })
        .collect();
    let f = run(s);
    let e = of(&f, "OAUTH-ERROR");
    assert_eq!(keys(&e), vec!["OAUTH-ERROR|login.microsoftonline.com|invalid_client|7000215"]);
    assert_eq!(e[0].severity, Severity::Critical);
    assert_eq!(e[0].sessions, vec![0, 1, 2]);
    assert!(e[0].title.contains("Microsoft Entra ID"), "{}", e[0].title);
    assert!(fact(e[0], "Trace ids (examples)").is_some_and(|v| v.contains("trace-0")));
    assert!(fact(e[0], "Correlation ids (examples)").is_some_and(|v| v.contains("corr-1")));
    assert!(fact(e[0], "AADSTS codes").is_some_and(|v| v.contains("InvalidClientSecretProvided")));
    assert!(fact(e[0], "Tenant").is_some_and(|v| v.contains("contoso.onmicrosoft.com")));
    assert!(any_text(&e[0].recommendations, "Certificates & secrets"), "{:?}", e[0].recommendations);
    assert!(any_text(&e[0].next_steps, "Sign-in logs"));
    // Once: warning. German texts.
    let one = vec![post(1, &format!("{ENTRA}/token")).status(401).oauth_req(token_req("client_credentials", "app-1")).oauth_resp(oauth_err("invalid_client", "AADSTS7000222: The provided client secret keys are expired."))];
    let f = analyse(one, r#"{"profile":"auth","lang":"de"}"#);
    let e = of(&f, "OAUTH-ERROR");
    assert_eq!(e[0].severity, Severity::Warning);
    assert!(any_text(&e[0].hypotheses, "abgelaufen"), "{:?}", e[0].hypotheses);
}

#[test]
fn device_flow_polling_is_info_and_keycloak_texts_are_explained() {
    let mut s: Vec<Session> =
        (0..5).map(|i| post(i, &format!("{ENTRA}/token")).at(i * 5000).status(400).oauth_req(token_req("urn:ietf:params:oauth:grant-type:device_code", "cli")).oauth_resp(oauth_err("authorization_pending", "AADSTS70016: OAuth 2.0 device flow error. Authorization is pending."))).collect();
    s.push(post(10, &format!("{KC}/token")).at(60_000).status(400).oauth_req(token_req("refresh_token", "web")).oauth_resp(oauth_err("invalid_grant", "Session not active")));
    let f = run(s);
    let e = of(&f, "OAUTH-ERROR");
    let pending = e.iter().find(|x| x.key.contains("authorization_pending")).unwrap();
    assert_eq!(pending.severity, Severity::Info);
    let kc = e.iter().find(|x| x.key.starts_with("OAUTH-ERROR|sso.example.com|invalid_grant")).unwrap();
    assert!(kc.title.contains("Keycloak"));
    assert!(any_text(&kc.hypotheses, "SSO Session Idle"), "{:?}", kc.hypotheses);
    assert!(any_text(&kc.recommendations, "Realm settings"), "{:?}", kc.recommendations);
    assert_eq!(fact(kc, "Realm"), Some("main"));
    // Device polling is not a token refresh problem.
    assert!(of(&f, "TOKEN-REFRESH").is_empty());
}

#[test]
fn redirect_errors_are_counted_once() {
    let s = vec![
        authorize(1, ENTRA, "client_id=app-1&response_type=code&redirect_uri=https%3A%2F%2Fapp.test%2Fsignin-oidc&state=%3C32%20bytes%3E&code_challenge=%3C43%20bytes%3E&code_challenge_method=S256")
            .status(302)
            .resp_h("Location", "https://app.test/signin-oidc?error=invalid_request&error_description=AADSTS50011%3A+The+redirect+URI+does+not+match&state=%3C32%20bytes%3E"),
        get(2, "https://app.test/signin-oidc?error=invalid_request&error_description=AADSTS50011%3A+The+redirect+URI+does+not+match&state=%3C32%20bytes%3E").at(100),
    ];
    let f = run(s);
    let e = of(&f, "OAUTH-ERROR");
    assert_eq!(e.len(), 1, "{e:#?}");
    assert_eq!(e[0].key, "OAUTH-ERROR|login.microsoftonline.com|invalid_request|50011");
    assert_eq!(e[0].sessions, vec![1]);
    assert_eq!(fact(e[0], "Clients (client_id)"), Some("app-1"));
    assert!(any_text(&e[0].recommendations, "Redirect URIs"));
    // Only the callback captured (IdP not in the capture): still found, with the client
    // from the authorization request seen as the app's redirect.
    let s = vec![
        get(1, "https://app.test/login").status(302).resp_h("Location", &format!("{ENTRA}/authorize?client_id=app-1&response_type=code&redirect_uri=https%3A%2F%2Fapp.test%2Fsignin-oidc&state=%3C32%20bytes%3E")),
        get(2, "https://app.test/signin-oidc?error=access_denied&error_description=AADSTS65004%3A+User+declined+to+consent&state=%3C32%20bytes%3E").at(5000),
    ];
    let f = run(s);
    let e = of(&f, "OAUTH-ERROR");
    assert_eq!(keys(&e), vec!["OAUTH-ERROR|login.microsoftonline.com|access_denied|65004"]);
    assert_eq!(e[0].confidence, Confidence::Medium);
}

#[test]
fn non_oauth_errors_are_not_reported() {
    let mut api = get(1, "https://api.test/v1/items/7").status(404).oauth_resp(oauth_err("not_found", ""));
    api.content_type = "application/json".into();
    let s = vec![api, get(2, "https://shop.test/login?error=1").at(100), get(3, "https://shop.test/page?error=Something%20went%20wrong").at(200)];
    assert!(of(&run(s), "OAUTH-ERROR").is_empty());
}

#[test]
fn api_challenge_errors_left_to_token_rules_or_reported() {
    // Expired token: TOKEN-EXPIRED explains it, OAUTH-ERROR stays silent.
    let expired = get(1, "https://api.example.com/orders").status(401).bearer(jwt(ENTRA_ISS, "api://orders").valid(-4000, -600)).www_auth(r#"Bearer error="invalid_token", error_description="The token expired at '10/01/2026 10:00:00'""#);
    let f = run(vec![expired]);
    assert!(of(&f, "OAUTH-ERROR").is_empty(), "{:#?}", of(&f, "OAUTH-ERROR"));
    assert_eq!(of(&f, "TOKEN-EXPIRED").len(), 1);
    // An opaque token rejected for its signature: nothing else explains it.
    let s = vec![get(1, "https://api.example.com/orders").status(401).opaque_bearer(40).www_auth(r#"Bearer error="invalid_token", error_description="The signature key was not found""#)];
    let f = run(s);
    let e = of(&f, "OAUTH-ERROR");
    assert_eq!(keys(&e), vec!["OAUTH-ERROR|api.example.com|invalid_token|"]);
    assert!(e[0].title.starts_with("API rejects the token"));
    // AUTH-FAIL shows the WWW-Authenticate error instead of "redacted".
    let a = of(&f, "AUTH-FAIL");
    assert!(a.iter().any(|x| fact(x, "WWW-Authenticate error") == Some("invalid_token")), "{a:#?}");
    assert!(a.iter().all(|x| !any_text(&x.hypotheses, "redacted")));
}

// ------------------------------------------------------------------ OAUTH-FLOW

#[test]
fn implicit_ropc_and_summary() {
    let s = vec![
        authorize(1, ENTRA, "client_id=spa-1&response_type=id_token+token&redirect_uri=https%3A%2F%2Fspa.test%2F&nonce=%3C36%20bytes%3E"),
        post(2, &format!("{ENTRA}/token")).at(1000).oauth_req(token_req("password", "legacy-1")).oauth_resp(token_ok(3600)),
    ];
    let f = analyse(s, r#"{"profile":"modernization"}"#);
    let fl = of(&f, "OAUTH-FLOW");
    let k = keys(&fl);
    assert!(k.contains(&"OAUTH-FLOW|implicit|login.microsoftonline.com|spa-1".to_string()), "{k:?}");
    assert!(k.contains(&"OAUTH-FLOW|ropc|login.microsoftonline.com|legacy-1".to_string()), "{k:?}");
    assert!(k.contains(&"OAUTH-FLOW|summary|login.microsoftonline.com|spa-1".to_string()));
    let imp = fl.iter().find(|x| x.key.contains("|implicit|")).unwrap();
    assert_eq!(imp.severity, Severity::Warning);
    assert!(any_text(&imp.recommendations, "Implicit grant"), "Entra-specific place: {:?}", imp.recommendations);
    // TOKEN-IN-URL is modernization, too; token rules (TOKEN-EXPIRED) are not.
    assert!(f.iter().all(|x| x.id != "TOKEN-EXPIRED"));
}

#[test]
fn pkce_public_vs_confidential() {
    // Public client without PKCE: warning.
    let s = vec![
        authorize(1, KC, "client_id=mobile&response_type=code&redirect_uri=com.example.app%3A%2Fcb&state=%3C16%20bytes%3E"),
        post(2, &format!("{KC}/token")).at(2000).oauth_req(token_req("authorization_code", "mobile")).oauth_resp(token_ok(300)),
    ];
    let f = run(s);
    let p = of(&f, "OAUTH-FLOW").into_iter().find(|x| x.key.contains("|pkce|")).expect("pkce finding");
    assert_eq!(p.severity, Severity::Warning);
    assert!(any_text(&p.recommendations, "Proof Key for Code Exchange"), "Keycloak place: {:?}", p.recommendations);
    // Confidential client without PKCE: info.
    let s = vec![
        authorize(1, KC, "client_id=web&response_type=code&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb"),
        post(2, &format!("{KC}/token")).at(2000).oauth_req(webdiag::model::OAuthRequest { basic_client_auth: true, ..token_req("authorization_code", "web") }),
    ];
    let p = of(&run(s), "OAUTH-FLOW").into_iter().find(|x| x.key.contains("|pkce|")).map(|x| x.severity);
    assert_eq!(p, Some(Severity::Info));
    // With PKCE: no finding, the summary names it.
    let s = vec![
        authorize(1, KC, "client_id=spa&response_type=code&code_challenge=%3C43%20bytes%3E&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fapp.example.com%2F"),
        post(2, &format!("{KC}/token")).at(2000).oauth_req(webdiag::model::OAuthRequest { has_code_verifier: true, ..token_req("authorization_code", "spa") }),
    ];
    let f = run(s);
    let fl = of(&f, "OAUTH-FLOW");
    assert!(fl.iter().all(|x| !x.key.contains("|pkce|")));
    let sum = fl.iter().find(|x| x.key.contains("|summary|")).unwrap();
    assert!(sum.observation.contains("PKCE"), "{}", sum.observation);
    assert_eq!(sum.severity, Severity::Info);
}

#[test]
fn http_redirect_uri_and_secret_in_the_browser() {
    let s = vec![
        authorize(1, ENTRA, "client_id=web&response_type=code&code_challenge_method=S256&code_challenge=%3C43%20bytes%3E&redirect_uri=http%3A%2F%2Fapp.example.com%2Fsignin-oidc"),
        authorize(2, ENTRA, "client_id=dev&response_type=code&code_challenge_method=S256&code_challenge=%3C43%20bytes%3E&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Fsignin-oidc").at(100),
        post(3, &format!("{ENTRA}/token")).at(200).req_h("Origin", "https://spa.example.com").oauth_req(webdiag::model::OAuthRequest { has_client_secret: true, has_code_verifier: true, ..token_req("authorization_code", "spa") }),
    ];
    let f = run(s);
    let k = keys(&of(&f, "OAUTH-FLOW"));
    assert!(k.contains(&"OAUTH-FLOW|http-redirect|login.microsoftonline.com|web".to_string()), "{k:?}");
    assert!(!k.iter().any(|x| x.contains("http-redirect") && x.ends_with("|dev")), "localhost is fine: {k:?}");
    assert!(k.contains(&"OAUTH-FLOW|browser-secret|login.microsoftonline.com|spa".to_string()), "{k:?}");
    assert!(!k.iter().any(|x| x.contains("secret-post")), "the browser case replaces the info");
}

// ------------------------------------------------------------------ TOKEN-IN-URL

#[test]
fn tokens_in_urls() {
    let s = vec![
        get(1, "https://api.example.com/report?access_token=%3C900%20bytes%3E&id=4"),
        get(2, "https://login.example.com/cb").status(302).resp_h("Location", "https://spa.example.com/#id_token=%3C900%20bytes%3E&state=%3C9%20bytes%3E"),
        get(3, "https://cdn.other.net/lib.js").req_h("Referer", "https://spa.example.com/home?access_token=%3C900%20bytes%3E"),
        get(4, "https://app.example.com/chathub/negotiate?negotiateVersion=1&access_token=%3C900%20bytes%3E"),
        get(5, "https://login.example.com/logout?id_token_hint=%3C900%20bytes%3E&post_logout_redirect_uri=x"),
    ];
    let f = run(s);
    let t = of(&f, "TOKEN-IN-URL");
    let by = |k: &str| t.iter().find(|x| x.key == k).unwrap_or_else(|| panic!("{k} missing: {:?}", keys(&t)));
    assert_eq!(by("TOKEN-IN-URL|api.example.com|access_token|query").severity, Severity::Warning);
    assert_eq!(by("TOKEN-IN-URL|spa.example.com|id_token|locationfragment").severity, Severity::Info);
    let leak = by("TOKEN-IN-URL|cdn.other.net|access_token|referer");
    assert_eq!(leak.severity, Severity::Critical);
    assert!(any_text(&leak.recommendations, "Referrer-Policy"));
    assert_eq!(by("TOKEN-IN-URL|app.example.com|access_token|query").severity, Severity::Info, "SignalR negotiate");
    assert_eq!(t.len(), 4, "id_token_hint is not a token parameter: {:?}", keys(&t));
}

// ------------------------------------------------------------------ TOKEN-EXPIRED

#[test]
fn expired_tokens() {
    let s: Vec<Session> = (0..3).map(|i| get(i, "https://api.example.com/orders").at(i * 1000).status(401).bearer(jwt(ENTRA_ISS, "api://orders").client("spa-1").valid(-4200, -600))).collect();
    let f = run(s);
    let e = of(&f, "TOKEN-EXPIRED");
    assert_eq!(keys(&e), vec!["TOKEN-EXPIRED|api.example.com|spa-1"]);
    assert_eq!(e[0].severity, Severity::Warning);
    assert_eq!(fact(e[0], "Rejected with 401"), Some("3"));
    assert!(any_text(&e[0].hypotheses, "does not refresh"));
    // Within the leeway, or valid: nothing.
    let s = vec![get(1, "https://api.example.com/orders").bearer(jwt(ENTRA_ISS, "api://orders").valid(-3600, -30)), get(2, "https://api.example.com/orders").at(10).bearer(jwt(ENTRA_ISS, "api://orders"))];
    assert!(of(&run(s), "TOKEN-EXPIRED").is_empty());
}

#[test]
fn expired_tokens_accepted_and_local_clock() {
    // Accepted an hour after expiry: the API does not check exp.
    let s = vec![get(1, "https://api.example.com/orders").status(200).bearer(jwt(ENTRA_ISS, "api://orders").valid(-7200, -3600)).server_clock(0)];
    let f = run(s);
    let k = keys(&of(&f, "TOKEN-EXPIRED"));
    assert!(k.contains(&"TOKEN-EXPIRED|accepted|api.example.com".to_string()), "{k:?}");
    // This computer's clock is 15 minutes ahead: by the server's Date the token is valid.
    let s = vec![get(1, "https://api.example.com/orders").status(401).bearer(jwt(ENTRA_ISS, "api://orders").valid(-3000, -600)).server_clock(-900)];
    let f = run(s);
    let e = of(&f, "TOKEN-EXPIRED");
    let main = e.iter().find(|x| x.key == "TOKEN-EXPIRED|api.example.com|?").unwrap();
    assert_eq!(main.confidence, Confidence::Medium);
    assert!(any_text(&main.hypotheses, "CLOCK-LOCAL"), "{:?}", main.hypotheses);
}

// ------------------------------------------------------------------ TOKEN-NOTYET

#[test]
fn tokens_from_the_future() {
    let s = vec![get(1, "https://api.example.com/orders").status(401).bearer(jwt(KC.trim_end_matches("/protocol/openid-connect"), "orders").valid(600, 4200))];
    let f = run(s);
    let n = of(&f, "TOKEN-NOTYET");
    assert_eq!(n.len(), 1);
    assert_eq!(n[0].severity, Severity::Critical);
    // Two minutes: warning; from a token response (ID token).
    let mut r = token_ok(300);
    r.id_token = Some(jwt(ENTRA_ISS, "app-1").valid(120, 3720));
    let f = run(vec![post(1, &format!("{ENTRA}/token")).oauth_req(token_req("authorization_code", "app-1")).oauth_resp(r)]);
    let n = of(&f, "TOKEN-NOTYET");
    assert_eq!(n.len(), 1, "{f:#?}");
    assert_eq!(n[0].severity, Severity::Warning);
    assert_eq!(fact(n[0], "Seen in token responses"), Some("1"));
    // 30 s ahead is within the leeway.
    let s = vec![get(1, "https://api.example.com/orders").bearer(jwt(ENTRA_ISS, "api://orders").valid(30, 3600))];
    assert!(of(&run(s), "TOKEN-NOTYET").is_empty());
}

// ------------------------------------------------------------------ TOKEN-AUDIENCE

#[test]
fn graph_token_sent_to_own_api() {
    let s: Vec<Session> = (0..2).map(|i| get(i, "https://api.example.com/orders").at(i * 1000).status(401).bearer(jwt(ENTRA_ISS, "00000003-0000-0000-c000-000000000000").scopes(&["User.Read", "openid"]))).collect();
    let f = run(s);
    let a = of(&f, "TOKEN-AUDIENCE");
    assert_eq!(keys(&a), vec!["TOKEN-AUDIENCE|api.example.com"]);
    assert_eq!(a[0].confidence, Confidence::High);
    assert!(any_text(&a[0].hypotheses, "Microsoft Graph"));
    assert!(any_text(&a[0].recommendations, "Expose an API"), "{:?}", a[0].recommendations);
    let t = a[0].table.as_ref().unwrap();
    assert_eq!(t.columns[1], "iss");
    assert!(t.rows[0][2].contains("00000003"));
}

#[test]
fn audience_from_api_message_comparison_and_token_version() {
    // The API says so.
    let s = vec![get(1, "https://api.example.com/orders").status(401).bearer(jwt(ENTRA_ISS, "api://3f2c0e1a-1111-2222-3333-444455556666")).www_auth(r#"Bearer error="invalid_token", error_description="IDX10214: Audience validation failed""#)];
    let a = of(&run(s), "TOKEN-AUDIENCE").first().map(|x| x.confidence);
    assert_eq!(a, Some(Confidence::High));
    // Accepted tokens have another audience.
    let s = vec![
        get(1, "https://api.example.com/orders").bearer(jwt("https://id.example.com", "orders-api")),
        get(2, "https://api.example.com/orders").at(100).status(401).bearer(jwt("https://id.example.com", "billing-api")),
    ];
    let f = run(s);
    let a = of(&f, "TOKEN-AUDIENCE");
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].confidence, Confidence::Medium);
    assert_eq!(fact(a[0], "Audience of accepted tokens"), Some("orders-api"));
    // Entra v1 token where v2 tokens work.
    let s = vec![
        get(1, "https://api.example.com/orders").bearer(jwt(ENTRA_ISS, "api://orders").ver("2.0")),
        get(2, "https://api.example.com/orders").at(100).status(401).bearer(jwt("https://sts.windows.net/72f988bf-0000-0000-0000-000000000000/", "api://orders").ver("1.0")),
    ];
    let a = run(s);
    let a = of(&a, "TOKEN-AUDIENCE");
    assert_eq!(a.len(), 1);
    assert!(any_text(&a[0].hypotheses, "v1"), "{:?}", a[0].hypotheses);
    // A plausible audience and no message: no finding (expired/other causes are not guessed).
    let s = vec![get(1, "https://api.example.com/orders").status(401).bearer(jwt("https://id.example.com", "https://api.example.com"))];
    assert!(of(&run(s), "TOKEN-AUDIENCE").is_empty());
    // A Graph token that works against Graph.
    let s = vec![get(1, "https://graph.microsoft.com/v1.0/me").bearer(jwt(ENTRA_ISS, "00000003-0000-0000-c000-000000000000"))];
    assert!(of(&run(s), "TOKEN-AUDIENCE").is_empty());
}

// ------------------------------------------------------------------ TOKEN-SCOPE

#[test]
fn insufficient_scope_and_app_only_tokens() {
    let s = vec![
        req(1, "PUT", "https://api.example.com/orders/1").status(403).bearer(jwt(ENTRA_ISS, "api://orders").scopes(&["Orders.Read"])).www_auth(r#"Bearer error="insufficient_scope", scope="Orders.Write""#),
        get(2, "https://api.example.com/admin").at(100).status(403).bearer(jwt(ENTRA_ISS, "api://orders").roles(&["Reader"])),
    ];
    let f = run(s);
    let sc = of(&f, "TOKEN-SCOPE");
    let w = sc.iter().find(|x| x.key == "TOKEN-SCOPE|PUT api.example.com/orders/{}").unwrap();
    assert_eq!(w.confidence, Confidence::High);
    assert_eq!(fact(w, "Missing in the token"), Some("Orders.Write"));
    assert!(any_text(&w.recommendations, "API permissions"));
    let admin = sc.iter().find(|x| x.key == "TOKEN-SCOPE|GET api.example.com/admin").unwrap();
    assert_eq!(admin.confidence, Confidence::Low);
    assert!(any_text(&admin.hypotheses, "app-only"));
    // AUTH-FAIL leaves these to TOKEN-SCOPE …
    assert!(of(&f, "AUTH-FAIL").iter().all(|x| !x.key.starts_with("AUTH-FAIL|forbidden")), "{:?}", keys(&of(&f, "AUTH-FAIL")));
    // … but keeps 403s without token facts.
    let f = run(vec![get(1, "https://api.example.com/admin").status(403)]);
    assert!(of(&f, "TOKEN-SCOPE").is_empty());
    assert_eq!(keys(&of(&f, "AUTH-FAIL")), vec!["AUTH-FAIL|forbidden|GET api.example.com/admin"]);
}

// ------------------------------------------------------------------ TOKEN-SIZE

#[test]
fn large_bearer_tokens() {
    let mk = |id: u64, size: u32, status: u16| get(id, "https://api.example.com/x").at(id * 10).status(status).bearer(webdiag::model::JwtClaims { groups: Some(180), ..jwt(ENTRA_ISS, "api://x").size(size) });
    let sev = |v: Vec<Session>| run(v).into_iter().find(|x| x.id == "TOKEN-SIZE").map(|x| x.severity);
    assert_eq!(sev(vec![mk(1, 9000, 200)]), Some(Severity::Warning));
    assert_eq!(sev(vec![mk(1, 17_000, 200)]), Some(Severity::Critical));
    assert_eq!(sev(vec![mk(1, 9000, 431)]), Some(Severity::Critical));
    assert_eq!(sev(vec![mk(1, 4000, 200)]), None);
    let f = run(vec![mk(1, 9000, 200)]);
    let t = of(&f, "TOKEN-SIZE");
    assert!(any_text(&t[0].hypotheses, "Group"));
    assert!(any_text(&t[0].recommendations, "Groups assigned to the application"));
}

#[test]
fn chunked_and_nonce_cookies_take_over_from_cookie_size() {
    let chunks = ".AspNetCore.Cookies; .AspNetCore.CookiesC1; .AspNetCore.CookiesC2; .AspNetCore.CookiesC3; other";
    let mut s = vec![
        get(1, "https://app.example.com/")
            .resp_h("Set-Cookie", ".AspNetCore.Cookies=<9 bytes>; path=/; secure; httponly")
            .resp_h("Set-Cookie", ".AspNetCore.CookiesC1=<4050 bytes>; path=/; secure; httponly")
            .resp_h("Set-Cookie", ".AspNetCore.CookiesC2=<4050 bytes>; path=/; secure; httponly")
            .resp_h("Set-Cookie", ".AspNetCore.CookiesC3=<1200 bytes>; path=/; secure; httponly"),
    ];
    s.extend((2..5).map(|i| get(i, "https://app.example.com/page").at(i * 100).req_h("Cookie", chunks)));
    let f = run(s);
    let t = of(&f, "TOKEN-SIZE");
    assert_eq!(keys(&t), vec!["TOKEN-SIZE|cookie|app.example.com"]);
    assert_eq!(fact(t[0], "Chunks of one cookie (max.)"), Some("3"));
    assert!(of(&f, "COOKIE").iter().all(|x| !x.key.starts_with("COOKIE|size")), "reported once, by TOKEN-SIZE");
    // Nonce cookies piling up, one request rejected.
    let nonces = (0..7).map(|k| format!(".AspNetCore.OpenIdConnect.Nonce.CfDJ8{k}")).collect::<Vec<_>>().join("; ");
    let f = run(vec![get(1, "https://app.example.com/").status(400).req_h("Cookie", &nonces)]);
    let t = of(&f, "TOKEN-SIZE");
    assert_eq!(t[0].severity, Severity::Critical);
    assert!(any_text(&t[0].hypotheses, "pile up"));
    // Two chunks, small values: nothing.
    let f = run(vec![get(1, "https://app.example.com/").req_h("Cookie", ".AspNetCore.Cookies; .AspNetCore.CookiesC1; .AspNetCore.CookiesC2")]);
    assert!(of(&f, "TOKEN-SIZE").is_empty());
}

// ------------------------------------------------------------------ TOKEN-REFRESH

#[test]
fn tokens_requested_while_still_valid() {
    let cc = |i: u64, at_s: u64| post(i, &format!("{ENTRA}/token")).at(at_s * 1000).oauth_req(webdiag::model::OAuthRequest { scope: Some("https://graph.microsoft.com/.default".into()), has_client_secret: true, ..token_req("client_credentials", "daemon") }).oauth_resp(token_ok(3599));
    let f = run((0..4).map(|i| cc(i, i * 60)).collect());
    let r = of(&f, "TOKEN-REFRESH");
    assert_eq!(keys(&r), vec!["TOKEN-REFRESH|login.microsoftonline.com|daemon"]);
    assert_eq!(r[0].severity, Severity::Warning);
    assert_eq!(fact(r[0], "New tokens before 50 % of the lifetime"), Some("3"), "{:?}", r[0].facts);
    assert!(of(&f, "AUTH-REPEAT").is_empty());
    // Every 50 minutes with a 1 h lifetime: fine.
    assert!(of(&run((0..4).map(|i| cc(i, i * 3000)).collect()), "TOKEN-REFRESH").is_empty());
    // Failing retries are OAUTH-ERROR's, not a caching problem.
    let failing: Vec<Session> = (0..5).map(|i| post(i, &format!("{ENTRA}/token")).at(i * 1000).status(400).oauth_req(token_req("refresh_token", "spa")).oauth_resp(oauth_err("invalid_grant", "AADSTS700084: The refresh token was issued to a single page app (SPA), and therefore has a fixed, limited lifetime of 1.00:00:00"))).collect();
    let f = run(failing);
    assert!(of(&f, "TOKEN-REFRESH").is_empty());
    assert_eq!(of(&f, "OAUTH-ERROR")[0].severity, Severity::Critical);
}

#[test]
fn a_token_per_api_call() {
    let mut s = vec![];
    for i in 0..6u64 {
        s.push(post(i * 2, &format!("{KC}/token")).at(i * 400_000).oauth_req(token_req("client_credentials", "worker")).oauth_resp(token_ok(300)));
        s.push(get(i * 2 + 1, "https://api.example.com/jobs").at(i * 400_000 + 100).bearer(jwt("https://sso.example.com/realms/main", "jobs").client("worker")));
    }
    let f = run(s);
    let r = of(&f, "TOKEN-REFRESH");
    assert_eq!(r.len(), 1, "{f:#?}");
    assert!(any_text(&r[0].hypotheses, "every API call"));
}

// ------------------------------------------------------------------ OIDC-LOOP

#[test]
fn sign_in_loop_with_lost_cookie() {
    let mut s = vec![];
    for k in 0..4u64 {
        let t = k * 8000;
        s.push(
            authorize(k * 10, ENTRA, "client_id=web&response_type=code&response_mode=form_post&redirect_uri=https%3A%2F%2Fapp.example.com%2Fsignin-oidc&state=%3C32%20bytes%3E&nonce=%3C40%20bytes%3E&code_challenge=%3C43%20bytes%3E&code_challenge_method=S256")
                .at(t)
                .status(200)
                .body(4000, "text/html"),
        );
        s.push(post(k * 10 + 1, "https://app.example.com/signin-oidc").at(t + 2000).status(302).resp_h("Location", "/").resp_h("Set-Cookie", ".AspNetCore.Cookies=<3000 bytes>; path=/; secure; samesite=lax; httponly"));
        s.push(get(k * 10 + 2, "https://app.example.com/").at(t + 2500).status(302).resp_h("Set-Cookie", ".AspNetCore.Correlation.abc=<20 bytes>; path=/signin-oidc; samesite=none; httponly"));
    }
    let f = run(s);
    let l = of(&f, "OIDC-LOOP");
    assert_eq!(keys(&l), vec!["OIDC-LOOP|login.microsoftonline.com|web"]);
    assert_eq!(l[0].severity, Severity::Critical);
    assert_eq!(fact(l[0], "Callbacks"), Some("4"));
    assert!(fact(l[0], "Set by the callback, not sent back").is_some_and(|v| v.contains(".AspNetCore.Cookies")));
    assert!(fact(l[0], "SameSite=None without Secure").is_some());
    assert!(l[0].table.as_ref().is_some_and(|t| t.rows.len() >= 8));
    // Two attempts, or silent renewals: no loop.
    let s = (0..2).map(|k| authorize(k, ENTRA, "client_id=web&response_type=code").at(k * 1000)).collect();
    assert!(of(&run(s), "OIDC-LOOP").is_empty());
    let s = (0..5).map(|k| authorize(k, ENTRA, "client_id=web&response_type=code&prompt=none").at(k * 1000)).collect();
    assert!(of(&run(s), "OIDC-LOOP").is_empty());
    // Two sign-ins, each with Entra's sso_reload continuation: no loop.
    let s = (0..4).map(|k| authorize(k, ENTRA, if k % 2 == 0 { "client_id=web&response_type=code" } else { "client_id=web&response_type=code&sso_reload=true" }).at(k * 3000)).collect();
    assert!(of(&run(s), "OIDC-LOOP").is_empty());
}

// ------------------------------------------------------------------ OIDC-SILENT

#[test]
fn silent_renewal_fails() {
    let s = vec![
        authorize(1, ENTRA, "client_id=spa&response_type=code&prompt=none&redirect_uri=https%3A%2F%2Fspa.example.com%2Fblank.html&code_challenge_method=S256&code_challenge=%3C43%20bytes%3E")
            .status(302)
            .resp_h("Location", "https://spa.example.com/blank.html#error=login_required&error_description=AADSTS50058%3A+A+silent+sign-in+request+was+sent+but+no+user+is+signed+in.&state=%3C9%20bytes%3E"),
    ];
    let f = run(s);
    let si = of(&f, "OIDC-SILENT");
    assert_eq!(keys(&si), vec!["OIDC-SILENT|login.microsoftonline.com|spa"]);
    assert_eq!(si[0].severity, Severity::Warning);
    assert!(any_text(&si[0].hypotheses, "third-party cookie"));
    assert!(any_text(&si[0].recommendations, "MSAL.js"), "{:?}", si[0].recommendations);
    assert!(of(&f, "OAUTH-ERROR").is_empty(), "silent errors belong to OIDC-SILENT");
    // A silent attempt followed by an interactive one: failed (medium confidence).
    let s = vec![
        authorize(1, KC, "client_id=spa&response_type=code&prompt=none&response_mode=web_message&redirect_uri=https%3A%2F%2Fspa.example.org%2F").status(200),
        authorize(2, KC, "client_id=spa&response_type=code&redirect_uri=https%3A%2F%2Fspa.example.org%2F").at(3000),
    ];
    let si = run(s);
    let si = of(&si, "OIDC-SILENT");
    assert_eq!(si.len(), 1);
    assert_eq!(si[0].confidence, Confidence::Medium);
    // Succeeds: nothing.
    let s = vec![authorize(1, ENTRA, "client_id=spa&response_type=code&prompt=none&redirect_uri=https%3A%2F%2Fspa.example.com%2F").status(302).resp_h("Location", "https://spa.example.com/?code=%3C900%20bytes%3E&state=%3C9%20bytes%3E")];
    assert!(of(&run(s), "OIDC-SILENT").is_empty());
}

// ------------------------------------------------------------------ OIDC-DISCOVERY

#[test]
fn discovery_not_cached_failing_and_issuer_mismatch() {
    let url = "https://sso.example.com/realms/main/.well-known/openid-configuration";
    let mk = |n: u64| (0..n).map(|i| get(i, url).at(i * 5000).discovery(discovery_doc("https://sso.example.com/realms/main"))).collect::<Vec<_>>();
    let sev = |v: Vec<Session>| run(v).into_iter().find(|x| x.id == "OIDC-DISCOVERY").map(|x| x.severity);
    assert_eq!(sev(mk(6)), Some(Severity::Info));
    assert_eq!(sev(mk(25)), Some(Severity::Warning));
    assert_eq!(sev(mk(3)), None);
    // Failing.
    let f = run(vec![get(1, "https://login.example.com/tenant/v2.0/.well-known/openid-configuration").status(404)]);
    assert_eq!(keys(&of(&f, "OIDC-DISCOVERY")), vec!["OIDC-DISCOVERY|fail|login.example.com"]);
    // Keycloak behind a proxy advertises its internal URL.
    let f = run(vec![get(1, url).discovery(discovery_doc("http://keycloak:8080/realms/main"))]);
    let d = of(&f, "OIDC-DISCOVERY");
    assert_eq!(keys(&d), vec!["OIDC-DISCOVERY|issuer|sso.example.com"]);
    assert!(any_text(&d[0].hypotheses, "KC_HOSTNAME"));
    // Entra: v1 tokens while the discovery document is v2.
    let mut r = token_ok(3600);
    r.id_token = Some(jwt("https://sts.windows.net/72f988bf-0000-0000-0000-000000000000/", "app-1"));
    let s = vec![
        get(1, &format!("{ENTRA}/.well-known/openid-configuration")).discovery(discovery_doc("https://login.microsoftonline.com/{tenantid}/v2.0")),
        post(2, &format!("{ENTRA}/token")).at(100).oauth_req(token_req("authorization_code", "app-1")).oauth_resp(r),
    ];
    let d = run(s);
    let d = of(&d, "OIDC-DISCOVERY");
    assert_eq!(keys(&d), vec!["OIDC-DISCOVERY|issuer|login.microsoftonline.com"]);
    assert!(any_text(&d[0].hypotheses, "accessTokenAcceptedVersion"));
    // Matching issuer: nothing.
    let mut r = token_ok(3600);
    r.id_token = Some(jwt(ENTRA_ISS, "app-1"));
    let s = vec![
        get(1, &format!("{ENTRA}/.well-known/openid-configuration")).discovery(discovery_doc("https://login.microsoftonline.com/{tenantid}/v2.0")),
        post(2, &format!("{ENTRA}/token")).at(100).oauth_req(token_req("authorization_code", "app-1")).oauth_resp(r),
    ];
    assert!(of(&run(s), "OIDC-DISCOVERY").is_empty());
}

// ------------------------------------------------------------------ robustness

#[test]
fn missing_and_odd_data_never_panics() {
    let mut odd = get(9, "https://h.test/authorize?response_type=&client_id=");
    odd.auth = Some(Box::new(webdiag::model::AuthInfo {
        bearer: Some(webdiag::model::JwtClaims { exp: Some(0), nbf: Some(u64::MAX / 4), iat: None, ..Default::default() }),
        oauth_request: Some(Default::default()),
        oauth_response: Some(webdiag::model::OAuthResponse { error: Some(" ".into()), expires_in: Some(0), ..Default::default() }),
        discovery: Some(Default::default()),
        opaque_bearer: Some(0),
    }));
    let s = vec![
        odd,
        get(1, "https://h.test/cb#error=login_required"),
        get(2, "relative/path?error=x_y&state=%3C1%20byte%3E"),
        get(3, "https://h.test/x").status(302).resp_h("Location", "?access_token=%3C9%20bytes%3E#"),
        get(4, "https://h.test/y").status(401).www_auth("Bearer error=\"").req_h("Authorization", "Bearer"),
        post(5, "https://h.test/oauth2/token"),
        get(6, "https://h.test/.well-known/openid-configuration").failed_with("timeout"),
        get(7, "https://h.test/z").req_h("Cookie", ";;=;.AspNetCore.CookiesC;FedAuth9999999999999999999"),
        get(8, "").req_h("Referer", "token"),
    ];
    for profile in ["full", "auth", "modernization", "performance"] {
        let mut r = webdiag::Run::new(&format!(r#"{{"profile":"{profile}","lang":"de"}}"#));
        r.push(s.clone());
        assert!(r.finish().starts_with('{'));
    }
}

// ------------------------------------------------------------------ timing

/// 500k sessions with OAuth traffic in every tenth session (token requests, authorize
/// redirects, callbacks, bearer calls, chunked cookies, discovery):
/// `cargo test --release --test oauth -- --ignored --nocapture`.
#[test]
#[ignore]
fn stress_oauth_500k() {
    let entra = "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0";
    let n: u64 = 500_000;
    let mut s = Vec::with_capacity(n as usize);
    for i in 0..n {
        let x = match i % 20 {
            0 => post(i, &format!("{entra}/token")).oauth_req(token_req("refresh_token", &format!("c{}", i % 7))).oauth_resp(token_ok(3600)),
            1 => get(i, &format!("{entra}/authorize?client_id=c{}&response_type=code&redirect_uri=https%3A%2F%2Fapp{}.test%2Fcb&state=%3C9%20bytes%3E", i % 7, i % 5)).status(302).resp_h("Location", &format!("https://app{}.test/cb?code=%3C9%20bytes%3E", i % 5)),
            2 => get(i, &format!("https://app{}.test/cb?code=%3C9%20bytes%3E", i % 5)).resp_h("Set-Cookie", ".AspNetCore.Cookies=<3000 bytes>; path=/; secure"),
            3 => get(i, "https://api.test/x").status(if i % 3 == 0 { 401 } else { 200 }).bearer(jwt("https://login.microsoftonline.com/t/v2.0", if i % 2 == 0 { "api://a" } else { "api://b" }).valid(-4000, if i % 4 == 0 { -100 } else { 100 })).www_auth("Bearer error=\"invalid_token\""),
            4 => get(i, "https://app1.test/p").req_h("Cookie", ".AspNetCore.Cookies; .AspNetCore.CookiesC1; .AspNetCore.CookiesC2; .AspNetCore.CookiesC3"),
            5 => get(i, &format!("{entra}/.well-known/openid-configuration")).discovery(discovery_doc("https://login.microsoftonline.com/{tenantid}/v2.0")),
            _ => get(i, &format!("https://h{}.test/api/items/{}", i % 40, i % 5000)),
        };
        s.push(x.at(i * 7));
    }
    let mut r = webdiag::Run::new("{}");
    r.push(s);
    let t = std::time::Instant::now();
    let (f, _, _) = r.analyse();
    let e = t.elapsed().as_secs_f64();
    eprintln!("analyse {e:.2}s, {} findings, {} OAuth findings", f.len(), f.iter().filter(|x| x.tags.contains(&"oauth")).count());
    assert!(f.iter().any(|x| x.id == "OIDC-LOOP") && f.iter().any(|x| x.id == "TOKEN-REFRESH"));
    if !cfg!(debug_assertions) {
        assert!(e < 3.0, "500k OAuth-heavy sessions took {e:.2}s natively");
    }
}

#[test]
fn a_sign_in_loop_is_reported_once_as_oidc_loop_not_also_as_redirect_loop() {
    // app → IdP authorize → callback → app → authorize … (state values are redacted, so the
    // URLs repeat exactly and the redirect rule would see a loop as well).
    let az = "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/authorize?client_id=web&response_type=code&redirect_uri=https%3A%2F%2Fapp.example.com%2Fsignin-oidc&state=%3C32%20bytes%3E";
    let mut s = vec![];
    for k in 0..4u64 {
        let t = k * 900;
        s.push(get(k * 10, "https://app.example.com/").at(t).status(302).resp_h("Location", az));
        s.push(get(k * 10 + 1, az).at(t + 100).status(302).resp_h("Location", "https://app.example.com/signin-oidc?code=%3C800%20bytes%3E&state=%3C32%20bytes%3E"));
        s.push(get(k * 10 + 2, "https://app.example.com/signin-oidc?code=%3C800%20bytes%3E&state=%3C32%20bytes%3E").at(t + 300).status(302).resp_h("Location", "https://app.example.com/"));
    }
    let full = analyse(s.clone(), r#"{"profile":"full"}"#);
    assert!(!of(&full, "OIDC-LOOP").is_empty(), "{:#?}", full.iter().map(|f| &f.key).collect::<Vec<_>>());
    assert!(of(&full, "REDIRECT").iter().all(|f| !f.key.starts_with("REDIRECT|loop")), "reported twice: {:#?}", of(&full, "REDIRECT"));
    // The performance profile has no OIDC-LOOP: there the redirect rule still reports the loop.
    let perf = analyse(s, r#"{"profile":"performance"}"#);
    assert!(of(&perf, "REDIRECT").iter().any(|f| f.key.starts_with("REDIRECT|loop")));
}

#[test]
fn oauth_errors_are_not_repeated_as_generic_http_or_auth_failures() {
    // Token endpoint 401 invalid_client and 400 invalid_grant, a callback with error=: the
    // OAuth rule explains them, AUTH-FAIL and ERR-HTTP stay silent.
    let s = vec![
        post(1, &format!("{ENTRA}/token")).status(401).oauth_req(token_req("client_credentials", "app-1")).oauth_resp(oauth_err("invalid_client", "AADSTS7000215: Invalid client secret provided.")),
        post(2, &format!("{ENTRA}/token")).at(1000).status(400).oauth_req(token_req("refresh_token", "app-1")).oauth_resp(oauth_err("invalid_grant", "AADSTS700082: The refresh token has expired due to inactivity.")),
        get(3, "https://app.example.com/signin-oidc?error=access_denied&error_description=AADSTS50105&state=%3C32%20bytes%3E").at(2000).status(400),
    ];
    let f = analyse(s, r#"{"profile":"full"}"#);
    assert!(!of(&f, "OAUTH-ERROR").is_empty(), "{:#?}", f.iter().map(|f| &f.key).collect::<Vec<_>>());
    assert!(of(&f, "AUTH-FAIL").is_empty(), "{:#?}", of(&f, "AUTH-FAIL"));
    assert!(of(&f, "ERR-HTTP").is_empty(), "{:#?}", of(&f, "ERR-HTTP"));
}

#[test]
fn a_sign_in_loop_is_not_also_reported_as_duplicate_requests() {
    let az = "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/authorize?client_id=web&response_type=code&redirect_uri=https%3A%2F%2Fapp.example.com%2Fsignin-oidc&state=%3C32%20bytes%3E";
    let cb = "https://app.example.com/signin-oidc?code=%3C800%20bytes%3E&state=%3C32%20bytes%3E";
    let mut s = vec![];
    for k in 0..4u64 {
        let t = k * 900;
        s.push(get(k * 10, "https://app.example.com/").at(t).status(302).resp_h("Location", az));
        s.push(get(k * 10 + 1, az).at(t + 100).status(302).resp_h("Location", cb));
        s.push(get(k * 10 + 2, cb).at(t + 300).status(302).resp_h("Location", "https://app.example.com/"));
    }
    let full = analyse(s.clone(), r#"{"profile":"full"}"#);
    assert!(!of(&full, "OIDC-LOOP").is_empty());
    assert!(of(&full, "DUP-EXACT").is_empty(), "{:#?}", of(&full, "DUP-EXACT"));
    // Without OIDC-LOOP (performance profile) the duplicates are still reported.
    assert!(!of(&analyse(s, r#"{"profile":"performance"}"#), "DUP-EXACT").is_empty());
}
