//! Cross-session analyzers (analyzers/patterns.rs), operations (ops.rs) and the network
//! model (net.rs) on synthetic captures: positive and negative cases for every rule.
use webdiag::json;
use webdiag::model::{Finding, Session, Severity};
use webdiag::testkit::*;

fn run(s: Vec<Session>) -> Vec<Finding> {
    analyse(s, "{}")
}
fn run_with(s: Vec<Session>, opts: &str) -> Vec<Finding> {
    analyse(s, opts)
}
fn fact<'a>(f: &'a Finding, label: &str) -> Option<&'a str> {
    f.facts.iter().find(|(l, _)| l == label).map(|(_, v)| v.as_str())
}
fn keys(f: &[&Finding]) -> Vec<String> {
    f.iter().map(|x| x.key.clone()).collect()
}

// ------------------------------------------------------------------ DUP-EXACT

#[test]
fn dup_exact_positive() {
    let mut s: Vec<Session> = (0..6).map(|i| get(i, "https://api.test/config?v=1").at(i * 100).body(2000, "application/json")).collect();
    s[4].status = 304;
    s[5].status = 304;
    s.push(get(10, "https://api.test/other").at(700));
    let f = run(s);
    let d = of(&f, "DUP-EXACT");
    assert_eq!(d.len(), 1, "{:?}", keys(&d));
    assert_eq!(d[0].severity, Severity::Warning);
    assert_eq!(d[0].sessions, vec![0, 1, 2, 3, 4, 5]);
    assert_eq!(fact(d[0], "Repeats"), Some("5"));
    assert_eq!(fact(d[0], "Of which 304 revalidations"), Some("2"));
    assert_eq!(d[0].operation.as_deref(), Some("op-1"));
    assert!(d[0].tags.contains(&"duplicate"));
}

#[test]
fn dup_exact_critical_and_share() {
    let s: Vec<Session> = (0..21).map(|i| get(i, "https://api.test/me").at(i * 50)).collect();
    let f = run(s);
    let d = of(&f, "DUP-EXACT");
    let single = d.iter().find(|x| x.key != "DUP-EXACT|share").unwrap();
    assert_eq!(single.severity, Severity::Critical, "one URL ≥ 20 times");
    let share = d.iter().find(|x| x.key == "DUP-EXACT|share").expect("share finding");
    assert_eq!(share.severity, Severity::Critical);
    assert_eq!(share.sessions.len(), 20);
}

#[test]
fn dup_exact_negative() {
    // Different ids, and identical POSTs (not GET/HEAD) are no exact GET duplicates.
    let mut s: Vec<Session> = (0..6).map(|i| get(i, &format!("https://api.test/items/{i}")).at(i * 100)).collect();
    s.extend((0..3).map(|i| post(10 + i, "https://api.test/save").at(1000 + i * 3000).req_body(10, 7)));
    assert!(of(&run(s), "DUP-EXACT").is_empty());
}

#[test]
fn findings_are_capped_per_rule() {
    let mut s = vec![];
    for g in 0..15u64 {
        for k in 0..3 {
            s.push(get(g * 10 + k, &format!("https://api.test/res{g}")).at(g * 400 + k * 100));
        }
    }
    let d = run(s);
    let d: Vec<&Finding> = of(&d, "DUP-EXACT").into_iter().filter(|x| x.key != "DUP-EXACT|share").collect();
    assert_eq!(d.len(), 10);
    let more = d.iter().find(|x| x.key == "DUP-EXACT|more").expect("summary");
    assert_eq!(more.sessions.len(), 6 * 3);
}

// ------------------------------------------------------------------ DUP-SUBMIT

#[test]
fn dup_submit_positive() {
    let s = vec![post(1, "https://api.test/orders").at(0).req_body(120, 42), post(2, "https://api.test/orders").at(400).req_body(120, 42)];
    let f = run(s);
    let d = of(&f, "DUP-SUBMIT");
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].severity, Severity::Warning);
    assert_eq!(d[0].sessions, vec![1, 2]);

    let s: Vec<Session> = (0..3).map(|i| post(i, "https://api.test/orders").at(i * 300).req_body(120, 42)).collect();
    assert_eq!(of(&run(s), "DUP-SUBMIT")[0].severity, Severity::Critical);
}

#[test]
fn dup_submit_negative() {
    // 10 s apart; different bodies; a retry after a failure; PUT is idempotent.
    let s = vec![
        post(1, "https://api.test/a").at(0).req_body(10, 1),
        post(2, "https://api.test/a").at(10_000).req_body(10, 1),
        post(3, "https://api.test/b").at(20_000).req_body(10, 1),
        post(4, "https://api.test/b").at(20_500).req_body(10, 2),
        post(5, "https://api.test/c").at(30_000).req_body(10, 1).status(503),
        post(6, "https://api.test/c").at(31_000).req_body(10, 1),
        req(7, "PUT", "https://api.test/d").at(40_000).req_body(10, 1),
        req(8, "PUT", "https://api.test/d").at(40_100).req_body(10, 1),
    ];
    assert!(of(&run(s), "DUP-SUBMIT").is_empty());
}

// ------------------------------------------------------------------ DUP-SEMANTIC

#[test]
fn dup_semantic_order_and_format() {
    let s = vec![
        get(1, "https://h.test/odata/Docs?$top=10&$filter=Type eq 'A'").at(0),
        get(2, "https://h.test/odata/Docs?$filter=Type%20EQ%20'A'&$top=10").at(100),
        get(3, "https://h.test/odata/Docs?$filter=Type eq 'A'&$top=10").at(200),
    ];
    let f = run(s);
    let d = of(&f, "DUP-SEMANTIC");
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].sessions, vec![1, 2, 3]);
    assert!(d[0].observation.contains("parameter order (1)"), "{}", d[0].observation);
    assert!(d[0].observation.contains("formatting/encoding (1)"), "{}", d[0].observation);
    assert!(d[0].tags.contains(&"odata"));
}

#[test]
fn dup_semantic_cache_buster() {
    let s: Vec<Session> = (0..5).map(|i| get(i, &format!("https://h.test/api/list?x=1&_={}", 1_727_690_000_000u64 + i * 777)).at(i * 200)).collect();
    let f = run(s);
    let d = of(&f, "DUP-SEMANTIC");
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].severity, Severity::Warning);
    assert!(d[0].observation.contains("cache busters (4)"), "{}", d[0].observation);
}

#[test]
fn dup_semantic_negative() {
    let s = vec![get(1, "https://h.test/odata/Docs?$filter=Type eq 'A'").at(0), get(2, "https://h.test/odata/Docs?$filter=Type eq 'B'").at(100), get(3, "https://h.test/odata/Docs?$filter=Type eq 'A'").at(200)];
    assert!(of(&run(s), "DUP-SEMANTIC").is_empty(), "exact repeats and different values are not semantic duplicates");
}

// ------------------------------------------------------------------ DUP-REFRESH

#[test]
fn dup_refresh_positive_and_negative() {
    let times = [0u64, 2_000, 9_000, 12_000, 25_000];
    // Reloads that defeat caches (cache buster) with an unchanged response.
    let s: Vec<Session> = times.iter().enumerate().map(|(i, &t)| get(i as u64, &format!("https://h.test/api/user?_={}", 1727690000000u64 + t)).at(t).resp_hash(99)).collect();
    let f = run(s);
    let d = of(&f, "DUP-REFRESH");
    assert_eq!(d.len(), 1);
    assert_eq!(fact(d[0], "Unchanged reloads"), Some("4"));
    assert_eq!(d[0].sessions.len(), 5);
    // The same URL again and again is reported once, as exact duplicate.
    let s: Vec<Session> = times.iter().enumerate().map(|(i, &t)| get(i as u64, "https://h.test/api/user").at(t).resp_hash(99)).collect();
    let f = run(s);
    assert!(of(&f, "DUP-REFRESH").is_empty());
    assert_eq!(of(&f, "DUP-EXACT").len(), 1);

    // Changing responses are no redundant refresh.
    let s: Vec<Session> = times.iter().enumerate().map(|(i, &t)| get(i as u64, "https://h.test/api/user").at(t).resp_hash(i as u64)).collect();
    assert!(of(&run(s), "DUP-REFRESH").is_empty());
    // Regular polling is reported as PAT-POLLING, not as refresh.
    let s: Vec<Session> = (0..8).map(|i| get(i, "https://h.test/api/user").at(i * 3000).resp_hash(99)).collect();
    let f = run(s);
    assert!(of(&f, "DUP-REFRESH").is_empty());
    assert_eq!(of(&f, "PAT-POLLING").len(), 1);
}

// ------------------------------------------------------------------ PAT-NPLUS1

fn n_plus_one(n: u64, sequential: bool) -> Vec<Session> {
    let mut s = vec![get(0, "https://h.test/odata/Cases?$top=100").at(0).took(50)];
    for i in 1..=n {
        let at = if sequential { 50 + (i - 1) * 40 } else { 60 };
        s.push(get(i, &format!("https://h.test/odata/Documents?$filter=CaseId eq {}", 1000 + i)).at(at).took(40));
    }
    s
}

#[test]
fn nplus1_sequential_odata() {
    let f = run(n_plus_one(12, true));
    let d = of(&f, "PAT-NPLUS1");
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].severity, Severity::Warning);
    assert_eq!(d[0].sessions.len(), 12);
    assert_eq!(fact(d[0], "Varying part"), Some("literal in $filter"));
    assert_eq!(fact(d[0], "Sequential levels"), Some("12"));
    assert!(d[0].tags.contains(&"n+1") && d[0].tags.contains(&"odata"));
    assert!(d[0].recommendations.iter().any(|r| r.contains("in (1,2,3)")));
    assert_eq!(d[0].operation.as_deref(), Some("op-1"));
    assert!(d[0].estimate, "the latency impact of the chain is modelled");
    // ≥ 20 sequential → critical; ≥ 50 in parallel → critical
    assert_eq!(of(&run(n_plus_one(22, true)), "PAT-NPLUS1")[0].severity, Severity::Critical);
    let p = run(n_plus_one(55, false));
    let p = of(&p, "PAT-NPLUS1");
    assert_eq!(p[0].severity, Severity::Critical);
    assert_eq!(fact(p[0], "Sequential levels"), Some("1"));
}

#[test]
fn nplus1_rest_path_ids() {
    let s: Vec<Session> = (0..15).map(|i| get(i, &format!("https://h.test/api/users/{}/avatar-info", 500 + i)).at(i * 10)).collect();
    let f = run(s);
    let d = of(&f, "PAT-NPLUS1");
    assert_eq!(d.len(), 1);
    assert_eq!(fact(d[0], "Varying part"), Some("path segment 3"));
    assert!(d[0].recommendations.iter().any(|r| r.contains("bulk endpoint")));
}

#[test]
fn nplus1_negative() {
    // too few; paging; same id repeated; different templates
    assert!(of(&run(n_plus_one(9, true)), "PAT-NPLUS1").is_empty());
    let paging: Vec<Session> = (0..12).map(|i| get(i, &format!("https://h.test/odata/Docs?$top=50&$skip={}", i * 50)).at(i * 60)).collect();
    assert!(of(&run(paging), "PAT-NPLUS1").is_empty());
    let same: Vec<Session> = (0..12).map(|i| get(i, "https://h.test/api/users/42").at(i * 60)).collect();
    assert!(of(&run(same), "PAT-NPLUS1").is_empty());
    // Two positions vary: not a single-id loop.
    let two: Vec<Session> = (0..12).map(|i| get(i, &format!("https://h.test/api/users/{}/orders/{}", 100 + i, 900 + i)).at(i * 60)).collect();
    assert!(of(&run(two), "PAT-NPLUS1").is_empty());
    // Separate operations (idle gap) are separate clusters.
    let split: Vec<Session> = (0..12).map(|i| get(i, &format!("https://h.test/api/users/{}", 100 + i)).at(i * 3000)).collect();
    assert!(of(&run(split), "PAT-NPLUS1").is_empty());
}

// ------------------------------------------------------------------ PAT-POLLING

#[test]
fn polling_positive() {
    let s: Vec<Session> = (0..10).map(|i| get(i, "https://h.test/api/status").at(i * 2000 + (i % 3) * 40).resp_hash(5)).collect();
    let f = run(s);
    let d = of(&f, "PAT-POLLING");
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].severity, Severity::Warning, "interval < 5 s");
    assert_eq!(fact(d[0], "Unchanged responses"), Some("100 %"));
    assert!(d[0].title.contains("2.0 s"), "{}", d[0].title);
    assert!(d[0].tags.contains(&"polling"));
    // every 10 s with changing data → info
    let s: Vec<Session> = (0..6).map(|i| get(i, "https://h.test/api/news").at(i * 10_000).resp_hash(i)).collect();
    let f = run(s);
    let d = of(&f, "PAT-POLLING");
    assert_eq!(d[0].severity, Severity::Info);
    assert_eq!(fact(d[0], "Unchanged responses"), Some("0 %"));
    // ≥ 60 polls → warning even at 10 s
    let s: Vec<Session> = (0..60).map(|i| get(i, "https://h.test/api/news").at(i * 10_000)).collect();
    assert_eq!(of(&run(s), "PAT-POLLING")[0].severity, Severity::Warning);
}

#[test]
fn polling_long_poll_is_info() {
    let s: Vec<Session> = (0..6).map(|i| get(i, "https://h.test/api/events").at(i * 30_010).took(30_000)).collect();
    let f = run(s);
    let d = of(&f, "PAT-POLLING");
    assert_eq!(d[0].severity, Severity::Info);
    assert!(d[0].hypotheses.iter().any(|h| h.contains("long polling")));
}

#[test]
fn polling_negative() {
    let irregular = [0u64, 1_000, 7_000, 8_000, 20_000, 21_500, 40_000];
    let s: Vec<Session> = irregular.iter().enumerate().map(|(i, &t)| get(i as u64, "https://h.test/api/status").at(t)).collect();
    assert!(of(&run(s), "PAT-POLLING").is_empty(), "irregular");
    let s: Vec<Session> = (0..10).map(|i| get(i, "https://h.test/api/status").at(i * 500)).collect();
    assert!(of(&run(s), "PAT-POLLING").is_empty(), "interval < 1 s");
    let s: Vec<Session> = (0..4).map(|i| get(i, "https://h.test/api/status").at(i * 2000)).collect();
    assert!(of(&run(s), "PAT-POLLING").is_empty(), "fewer than 5");
}

// ------------------------------------------------------------------ PAT-RETRY

#[test]
fn retry_recovered_is_info() {
    let s = vec![get(1, "https://h.test/api/a").at(0).status(503), get(2, "https://h.test/api/a").at(1000)];
    let f = run(s);
    let d = of(&f, "PAT-RETRY");
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].severity, Severity::Info);
    assert_eq!(d[0].sessions, vec![1, 2]);
    assert_eq!(fact(d[0], "Recovered"), Some("1"));
}

#[test]
fn retry_after_ignored_is_warning() {
    let s = vec![get(1, "https://h.test/api/a").at(0).status(429).resp_h("Retry-After", "5"), get(2, "https://h.test/api/a").at(1000)];
    let f = run(s);
    let d = of(&f, "PAT-RETRY");
    assert_eq!(d[0].severity, Severity::Warning);
    assert_eq!(fact(d[0], "Retry-After ignored"), Some("1 / 1"));
    // respected
    let s = vec![get(1, "https://h.test/api/a").at(0).status(429).resp_h("Retry-After", "1"), get(2, "https://h.test/api/a").at(2000)];
    let f = run(s);
    assert_eq!(fact(of(&f, "PAT-RETRY")[0], "Retry-After ignored"), Some("0 / 1"));
}

#[test]
fn retry_non_idempotent_and_storms() {
    let s = vec![post(1, "https://h.test/api/pay").at(0).req_body(10, 3).failed_with("connection reset"), post(2, "https://h.test/api/pay").at(500).req_body(10, 3)];
    let f = run(s);
    let d = of(&f, "PAT-RETRY");
    assert_eq!(d[0].severity, Severity::Critical);
    assert!(d[0].tags.contains(&"idempotency"));
    // 6 retries of one request, all failing
    let s: Vec<Session> = (0..7).map(|i| get(i, "https://h.test/api/b").at(i * 300).status(502)).collect();
    let f = run(s);
    let d = of(&f, "PAT-RETRY");
    assert_eq!(d[0].severity, Severity::Critical);
    assert!(d[0].title.starts_with("Retry storm"));
    // 25 different requests failing and retried within 10 s → burst storm
    let mut s = vec![];
    for i in 0..25u64 {
        s.push(get(i * 2, &format!("https://h.test/api/r{i}")).at(i * 100).status(503));
        s.push(get(i * 2 + 1, &format!("https://h.test/api/r{i}")).at(i * 100 + 3000));
    }
    let f = run(s);
    let storm = of(&f, "PAT-RETRY").into_iter().find(|x| x.key == "PAT-RETRY|storm").expect("storm");
    assert_eq!(storm.sessions.len(), 25);
}

#[test]
fn retry_negative() {
    let s = vec![
        get(1, "https://h.test/api/a").at(0),
        get(2, "https://h.test/api/a").at(1000), // after success: not a retry
        get(3, "https://h.test/api/b").at(5000).status(500),
        get(4, "https://h.test/api/b").at(60_000), // too late
        get(5, "https://h.test/api/c").at(70_000).status(404),
        get(6, "https://h.test/api/c").at(70_500), // 404 is not retryable
    ];
    assert!(of(&run(s), "PAT-RETRY").is_empty());
}

// ------------------------------------------------------------------ PAT-CHATTY

#[test]
fn chatty_positive_and_negative() {
    let s: Vec<Session> = (0..60).map(|i| get(i, &format!("https://h.test/api/part{}", i % 30)).at(i * 20)).collect();
    let f = run(s);
    let d = of(&f, "PAT-CHATTY");
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].severity, Severity::Warning);
    assert_eq!(d[0].sessions.len(), 60);
    let t = d[0].table.as_ref().unwrap();
    assert_eq!(t.rows[1], vec!["Unique resources".to_string(), "30".to_string()]);
    assert_eq!(t.rows[2], vec!["Duplicates".to_string(), "30".to_string()]);
    assert_eq!(d[0].operation.as_deref(), Some("op-1"));

    let s: Vec<Session> = (0..160).map(|i| get(i, &format!("https://h.test/api/p{i}")).at(i * 10)).collect();
    assert_eq!(of(&run(s), "PAT-CHATTY")[0].severity, Severity::Critical);
    // 25 requests within 0.5 s: ≥ 20/s
    let s: Vec<Session> = (0..25).map(|i| get(i, &format!("https://h.test/api/q{i}")).at(i * 20).took(20)).collect();
    assert_eq!(of(&run(s), "PAT-CHATTY").len(), 1);
    // 40 requests over 8 s (5/s)
    let s: Vec<Session> = (0..40).map(|i| get(i, &format!("https://h.test/api/q{i}")).at(i * 200).took(190)).collect();
    assert!(of(&run(s), "PAT-CHATTY").is_empty());
}

#[test]
fn repeated_operations_are_one_finding() {
    let mut s = vec![];
    for op in 0..3u64 {
        for i in 0..60u64 {
            s.push(get(op * 100 + i, &format!("https://h.test/api/part{i}")).at(op * 10_000 + i * 20));
        }
    }
    let f = run(s);
    let d = of(&f, "PAT-CHATTY");
    assert_eq!(d.len(), 1);
    assert_eq!(fact(d[0], "Similar operations"), Some("3"));
    assert_eq!(d[0].sessions.len(), 180);
}

// ------------------------------------------------------------------ ODATA-QUERY / ODATA-PAGING

const MIB: u64 = 1 << 20;

#[test]
fn odata_query_unbounded_and_overfetching() {
    let s = vec![get(1, "https://h.test/odata/Documents?$filter=Type eq 'A'").body(2 * MIB, "application/json")];
    let f = run(s);
    let d = of(&f, "ODATA-QUERY");
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].severity, Severity::Warning);
    assert_eq!(fact(d[0], "Without $top/paging"), Some("1"));
    assert_eq!(fact(d[0], "Without $select"), Some("1"));
    let s = vec![get(1, "https://h.test/odata/Documents").body(12 * MIB, "application/json")];
    assert_eq!(of(&run(s), "ODATA-QUERY")[0].severity, Severity::Critical);
}

#[test]
fn odata_query_deep_expand_note() {
    let s = vec![get(1, "https://h.test/odata/Cases?$top=20&$select=Id&$expand=Docs($expand=Versions($expand=Author))").body(2 * MIB, "application/json")];
    let f = run(s);
    let d = of(&f, "ODATA-QUERY");
    assert_eq!(d[0].severity, Severity::Info);
    assert_eq!(fact(d[0], "$expand depth / items"), Some("3 / 3"));
}

#[test]
fn odata_query_negative() {
    let s = vec![
        get(1, "https://h.test/odata/Documents?$top=50&$select=Id,Name").body(2 * MIB, "application/json"),
        get(2, "https://h.test/odata/Documents").at(10).body(500_000, "application/json"),
        get(3, "https://h.test/odata/Documents(42)").at(20).body(2 * MIB, "application/json"),
        get(4, "https://h.test/api/documents").at(30).body(2 * MIB, "application/json"),
    ];
    assert!(of(&run(s), "ODATA-QUERY").is_empty());
}

#[test]
fn odata_paging_positive_and_negative() {
    let u = |skip: u64| format!("https://h.test/odata/Docs?$filter=Open eq true&$top=50&$skip={skip}");
    let s = vec![get(1, &u(0)).at(0), get(2, &u(50)).at(100), get(3, &u(50)).at(200), get(4, &u(25)).at(300)];
    let f = run(s);
    let d = of(&f, "ODATA-PAGING");
    assert_eq!(d.len(), 1);
    assert_eq!(fact(d[0], "Repeated pages"), Some("1"));
    assert_eq!(fact(d[0], "Overlapping pages"), Some("2"));
    let s = vec![get(1, &u(0)).at(0), get(2, &u(50)).at(100), get(3, &u(100)).at(200)];
    assert!(of(&run(s), "ODATA-PAGING").is_empty());
}

// ------------------------------------------------------------------ NET-LATENCY

fn chain(n: u64) -> Vec<Session> {
    (0..n).map(|i| get(i, &format!("https://api.example.com/step{i}")).at(i * 100).took(100)).collect()
}

#[test]
fn net_latency_positive() {
    let f = run(chain(12));
    let d = of(&f, "NET-LATENCY");
    assert_eq!(d.len(), 1);
    assert!(d[0].estimate);
    assert_eq!(d[0].severity, Severity::Info, "12 × (120 − 20) ms = 1.2 s");
    let t = d[0].table.as_ref().unwrap();
    assert_eq!(t.rows.len(), 5, "one row per network profile");
    let weak = t.rows.iter().find(|r| r[0] == "Weak WAN").unwrap();
    assert_eq!(weak[3], "+1.2 s");
    let lan = t.rows.iter().find(|r| r[0] == "LAN").unwrap();
    assert_eq!(lan[3], "+0 ms");
    assert_eq!(fact(d[0], "Sequential levels"), Some("12"));
    assert!(d[0].next_steps.iter().any(|x| x.contains("Settings → Connections")));
    // All steps on one client connection → high confidence.
    assert_eq!(d[0].confidence, webdiag::model::Confidence::High);
    // 60 levels → 6 s extra on Weak WAN → warning
    assert_eq!(of(&run(chain(60)), "NET-LATENCY")[0].severity, Severity::Warning);
}

#[test]
fn net_latency_counts_handshakes() {
    let mut s = chain(10);
    for x in s.iter_mut() {
        *x = x.clone().new_conn(5, 30, 30);
        x.tls_version = Some("TLSv1.2".into());
    }
    let f = run(s);
    let d = of(&f, "NET-LATENCY");
    // 10 × (1 + 1 TCP + 2 TLS + 1 DNS) = 50 round trips; observed RTT = median TCP = 30 ms.
    assert_eq!(fact(d[0], "Round trips on the chain"), Some("50"));
    let weak = d[0].table.as_ref().unwrap().rows.iter().find(|r| r[0] == "Weak WAN").unwrap().clone();
    assert_eq!(weak[3], "+4.5 s");
}

#[test]
fn net_latency_negative() {
    let s: Vec<Session> = (0..30).map(|i| get(i, &format!("https://api.example.com/p{i}")).at(0).took(100)).collect();
    assert!(of(&run(s), "NET-LATENCY").is_empty(), "parallel");
    assert!(of(&run(chain(9)), "NET-LATENCY").is_empty(), "< 10 levels");
}

// ------------------------------------------------------------------ NET-BANDWIDTH

#[test]
fn net_bandwidth_large_response() {
    let s = vec![get(1, "https://h.test/export").took(3000).body(6 * MIB, "application/json")];
    let f = run(s);
    let d = of(&f, "NET-BANDWIDTH");
    assert_eq!(d.len(), 1);
    assert!(d[0].estimate);
    // Weak WAN: min(5 Mbit/s, Mathis 1.68 Mbit/s) → ~30 s
    assert_eq!(d[0].severity, Severity::Warning);
    let weak = d[0].table.as_ref().unwrap().rows.iter().find(|r| r[0] == "Weak WAN").unwrap().clone();
    assert_eq!(weak[3], "1.7 Mbit/s");
    assert!(d[0].recommendations.iter().any(|r| r.contains("Compress")), "uncompressed JSON");
}

#[test]
fn net_bandwidth_heavy_operation() {
    let s: Vec<Session> = (0..12).map(|i| get(i, &format!("https://h.test/tile/{i}.bin")).at(i * 50).body(MIB, "application/octet-stream")).collect();
    let f = run(s);
    let d = of(&f, "NET-BANDWIDTH");
    assert_eq!(d.len(), 1);
    assert!(d[0].key.starts_with("NET-BANDWIDTH|op:"));
    assert_eq!(d[0].operation.as_deref(), Some("op-1"));
    assert_eq!(d[0].sessions.len(), 12);
}

#[test]
fn net_bandwidth_negative() {
    let s = vec![get(1, "https://h.test/export").body(MIB, "application/json")];
    assert!(of(&run(s), "NET-BANDWIDTH").is_empty());
}

// ------------------------------------------------------------------ NET-RESILIENCE

#[test]
fn net_resilience_combines_factors() {
    let mut s = chain(12);
    s.push(get(100, "https://api.example.com/flaky").at(1300).took(100).status(503));
    s.push(get(101, "https://api.example.com/flaky").at(1500).took(100));
    let f = run_with(s.clone(), r#"{"profile":"resilience"}"#);
    let d = of(&f, "NET-RESILIENCE");
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].severity, Severity::Warning);
    assert_eq!(d[0].table.as_ref().unwrap().rows.len(), 2);
    assert!(d[0].estimate);
    // + a timeout → three factors → critical
    s.push(get(102, "https://api.example.com/slow").at(1700).took(100).failed_with("upstream timed out"));
    let f = run(s);
    assert_eq!(of(&f, "NET-RESILIENCE")[0].severity, Severity::Critical);
}

#[test]
fn net_resilience_negative_and_profile() {
    // One factor only.
    assert!(of(&run(chain(12)), "NET-RESILIENCE").is_empty());
    // Not part of the performance profile.
    let mut s = chain(12);
    s.push(get(100, "https://api.example.com/flaky").at(1300).took(100).status(503));
    s.push(get(101, "https://api.example.com/flaky").at(1500).took(100));
    let f = run_with(s, r#"{"profile":"performance"}"#);
    assert!(of(&f, "NET-RESILIENCE").is_empty());
    assert!(of(&f, "PAT-RETRY").is_empty(), "PAT-RETRY is troubleshooting/resilience");
    assert!(!of(&f, "NET-LATENCY").is_empty());
}

// ------------------------------------------------------------------ report, languages

#[test]
fn german_texts() {
    let f = run_with(n_plus_one(12, true), r#"{"lang":"de"}"#);
    let d = of(&f, "PAT-NPLUS1");
    assert!(d[0].title.starts_with("N+1-Request-Muster"), "{}", d[0].title);
    assert!(d[0].observation.contains("Literal in $filter"));
    let f = run_with(chain(12), r#"{"lang":"de"}"#);
    let d = of(&f, "NET-LATENCY");
    assert!(d[0].next_steps[0].contains("Einstellungen → Verbindungen"));
    assert_eq!(d[0].table.as_ref().unwrap().columns[3], "Geschätzte Mehrzeit");
    assert!(d[0].table.as_ref().unwrap().rows.iter().any(|r| r[3] == "+1,2 s"));
}

#[test]
fn operations_in_report() {
    let mut r = webdiag::Run::new(r#"{"lang":"de"}"#);
    let mut s = chain(12);
    s.push(get(50, "https://api.example.com/later").at(10_000));
    r.push(s);
    let out = r.finish();
    let v = json::parse(out.as_bytes()).unwrap();
    let Some(json::Value::Arr(ops)) = v.get("operations") else { panic!("operations") };
    assert_eq!(ops.len(), 2);
    assert_eq!(ops[0].get("id").and_then(|x| x.as_str()), Some("op-1"));
    assert_eq!(ops[0].get("label").and_then(|x| x.as_str()), Some("GET /step0 (+11)"));
    assert!(out.contains("Sequenzielle Stufen"));
    let Some(json::Value::Arr(sessions)) = ops[1].get("sessions") else { panic!() };
    assert_eq!(sessions.len(), 1);
}

#[test]
fn deterministic() {
    let mk = || {
        let mut s = n_plus_one(30, true);
        s.extend((0..10).map(|i| get(200 + i, "https://h.test/api/status").at(i * 2000)));
        s
    };
    let a = webdiag::testkit::analyse(mk(), "{}");
    let b = webdiag::testkit::analyse(mk(), "{}");
    assert_eq!(a, b);
}

// ------------------------------------------------------------------ scale

/// 100 000 sessions: operations with N+1 loops, duplicates, retries, polling and large
/// transfers. Bound: 2 s in release, relaxed in debug builds.
#[test]
fn hundred_thousand_sessions() {
    let mut s = Vec::with_capacity(100_000);
    let mut id = 0u64;
    let mut push = |x: Session| s.push(x);
    for op in 0..1_950u64 {
        let base = op * 3_000;
        id += 1;
        push(get(id, &format!("https://app.test/view/{}", op % 40)).at(base).took(30).body(20_000, "text/html"));
        for k in 0..20u64 {
            id += 1;
            push(get(id, &format!("https://app.test/odata/Documents?$filter=CaseId eq {}", op * 100 + k)).at(base + 40 + k * 25).took(20).body(3_000, "application/json"));
        }
        for k in 0..25u64 {
            id += 1;
            let mut x = get(id, &format!("https://app.test/api/part{}?lang=de&x={}", k, op % 7)).at(base + 600 + k * 3).took(60).body(8_000, "application/json").resp_hash(k);
            if k == 3 && op % 10 == 0 {
                x = x.status(503);
            }
            if k % 8 == 0 {
                x = x.new_conn(2, 12, 15);
            }
            push(x);
        }
        id += 1;
        push(get(id, "https://app.test/api/part3?lang=de&x=0").at(base + 900).took(40));
        id += 1;
        push(post(id, "https://app.test/api/save").at(base + 950).took(40).req_body(300, op % 5));
        id += 1;
        push(get(id, "https://app.test/api/me").at(base + 1000).took(10).resp_hash(1));
        id += 1;
        let size = if op % 100 == 0 { 6 << 20 } else { 10_000 };
        push(get(id, "https://app.test/odata/Items?$filter=Open eq true").at(base + 1100).took(200).body(size, "application/json"));
    }
    let mut pid = 10_000_000u64;
    for t in 0..(1_950u64 * 3) {
        pid += 1;
        let mut x = get(pid, "https://app.test/api/notifications").at(t * 1_000 + 500).took(15).resp_hash(7);
        x.process = "tray".into();
        push(x);
    }
    let n = s.len();
    assert!(n >= 100_000, "{n}");
    let mut r = webdiag::Run::new("{}");
    r.push(s);
    let t0 = std::time::Instant::now();
    let (findings, ops, _) = r.analyse();
    let took = t0.elapsed();
    eprintln!("{n} sessions: {} findings, {} operations in {:?}", findings.len(), ops.len(), took);
    let limit = if cfg!(debug_assertions) { 30.0 } else { 2.0 };
    assert!(took.as_secs_f64() < limit, "{took:?} for {n} sessions");
    assert!(!of(&findings, "PAT-NPLUS1").is_empty());
    assert!(!of(&findings, "PAT-POLLING").is_empty());
}

#[test]
fn dup_exact_leaves_auth_loops_and_failures_to_their_rules() {
    let s: Vec<Session> = (0..6).map(|i| get(i, "https://h.test/api/data").at(i * 300).status(401).resp_h("WWW-Authenticate", "Negotiate")).collect();
    assert!(of(&run(s), "DUP-EXACT").is_empty());
    let s: Vec<Session> = (0..6).map(|i| get(i, "https://h.test/api/data").at(i * 300).status(503)).collect();
    assert!(of(&run(s), "DUP-EXACT").is_empty());
}
