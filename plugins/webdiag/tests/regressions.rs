//! Regression tests for review findings (R1–R12, Q1–Q4 and the smaller ones). Each test
//! asserts the correct behaviour; the name says which finding it guards.
use webdiag::model::{Ctx, Options, Session, Severity};
use webdiag::testkit::*;
use webdiag::{canon, net, ops};

fn sorted(mut v: Vec<Session>) -> Vec<Session> {
    v.sort_by_key(|s| (s.started, s.id));
    v
}

/// Run one analyzer on its own (sessions sorted, operations segmented) and return the
/// elapsed time and its findings.
fn run_one(id: &str, sessions: Vec<Session>) -> (f64, Vec<webdiag::model::Finding>) {
    let ss = sorted(sessions);
    let o = Options::default();
    let opsv = ops::segment(&ss, &o);
    let ctx = Ctx::new(&ss, &opsv, &o);
    let a = webdiag::analyzers::all().into_iter().find(|a| a.id() == id).unwrap();
    let t = std::time::Instant::now();
    let mut out = vec![];
    a.run(&ctx, &mut out);
    (t.elapsed().as_secs_f64(), out)
}

// R1: an SSO round trip that returns to the start URL (which then answers 200) is not a loop.
#[test]
fn r1_sso_round_trip_is_not_a_redirect_loop() {
    let s = vec![
        get(1, "https://app.test/app").at(0).took(20).status(302).resp_h("location", "https://idp.test/authorize?client=app"),
        get(2, "https://idp.test/authorize?client=app").at(30).took(20).status(302).resp_h("location", "https://app.test/app/callback?code=abc"),
        get(3, "https://app.test/app/callback?code=abc").at(60).took(20).status(302).resp_h("location", "/app"),
        get(4, "https://app.test/app").at(90).took(20).status(200).body(1000, "text/html"),
    ];
    let f = analyse(s, "{}");
    let r = of(&f, "REDIRECT");
    assert!(r.iter().all(|x| !x.key.starts_with("REDIRECT|loop")), "SSO round trip reported as a redirect loop");
    // It is still a chain of three redirects.
    assert!(r.iter().any(|x| x.key.starts_with("REDIRECT|chain")), "{r:?}");
}

// R1 (counterpart): a URL that redirects again the same way is a loop.
#[test]
fn r1_real_redirect_loop_is_still_found() {
    let s = vec![
        get(1, "https://app.test/a").at(0).took(20).status(302).resp_h("location", "/b"),
        get(2, "https://app.test/b").at(30).took(20).status(302).resp_h("location", "/a"),
        get(3, "https://app.test/a").at(60).took(20).status(302).resp_h("location", "/b"),
        get(4, "https://app.test/b").at(90).took(20).status(302).resp_h("location", "/a"),
    ];
    let f = analyse(s, "{}");
    let r = of(&f, "REDIRECT");
    assert!(r.iter().any(|x| x.key.starts_with("REDIRECT|loop") && x.severity == Severity::Critical), "{r:?}");
}

// R2: AUTH-FAIL is linear on an endpoint that keeps answering 401 (poll every second).
#[test]
fn r2_auth_fail_scales_linearly() {
    let mk = |n: u64| -> Vec<Session> { (0..n).map(|i| get(i, "https://api.test/status").at(i * 1000).took(20).status(401)).collect() };
    // 8× the sessions: linear ≈ 8× the time, the old quadratic pass ≈ 64×. Best of three runs
    // and a wide margin keep this stable on busy CI machines.
    let best = |n: u64| (0..3).map(|_| run_one("AUTH-FAIL", mk(n)).0).fold(f64::MAX, f64::min).max(1e-4);
    let (t1, t2) = (best(5_000), best(40_000));
    let (_, f) = run_one("AUTH-FAIL", mk(40_000));
    eprintln!("AUTH-FAIL 5k: {t1:.3}s, 40k: {t2:.3}s, ratio {:.1}", t2 / t1);
    assert!(t2 / t1 < 24.0, "super-linear: {t1:.3}s -> {t2:.3}s");
    assert!(f.iter().any(|x| x.key.starts_with("AUTH-FAIL|unauthorized|")));
}

// R2: the linear pass keeps the semantics: a 401 answered by a success within 5 s of the
// running end is a challenge; one without is a failure.
#[test]
fn r2_auth_fail_semantics() {
    let mut s = vec![];
    for k in 0..12u64 {
        s.push(get(k * 2, "https://api.test/x").at(k * 20_000).took(10).status(401).resp_h("www-authenticate", "Negotiate"));
        s.push(get(k * 2 + 1, "https://api.test/x").at(k * 20_000 + 20).took(10));
    }
    for k in 0..3u64 {
        s.push(get(100 + k, "https://api.test/y").at(k * 20_000).took(10).status(401));
    }
    let (_, f) = run_one("AUTH-FAIL", s);
    assert!(f.iter().any(|x| x.key == "AUTH-FAIL|challenge|api.test" && x.sessions.len() == 12), "{f:?}");
    let un: Vec<_> = f.iter().filter(|x| x.key.starts_with("AUTH-FAIL|unauthorized|")).collect();
    assert_eq!(un.len(), 1);
    assert!(un[0].key.ends_with("/y") && un[0].sessions == vec![100, 101, 102]);
}

// R3: PERF-LARGE-RESP and NET-BANDWIDTH estimate the transfer time of the same response on
// the same network profile identically (both include packet loss).
#[test]
fn r3_transfer_tables_agree() {
    let s = vec![get(1, "https://api.test/export").took(3000).body(5 << 20, "application/octet-stream")];
    let f = analyse(s, "{}");
    let lr = of(&f, "PERF-LARGE-RESP")[0].table.clone().unwrap();
    let nb = of(&f, "NET-BANDWIDTH")[0].table.clone().unwrap();
    let row = |t: &webdiag::model::Table, name: &str| t.rows.iter().find(|r| r[0] == name).unwrap().clone();
    let a = row(&lr, "Mobile");
    let b = row(&nb, "Mobile");
    assert_eq!(a.last(), b.get(4), "same 5 MiB response, same profile, different estimate");
    // The effective (loss-limited) throughput is shown.
    assert!(lr.columns.iter().any(|c| c == "Effective throughput"), "{:?}", lr.columns);
}

// R4: a status poll every 5 s during a 40 s outage is not a (critical) retry storm.
#[test]
fn r4_polling_during_outage_is_not_a_retry_storm() {
    let s: Vec<Session> = (0..20)
        .map(|i| {
            let x = get(i, "https://api.test/health").at(i * 5000).took(30);
            if (4..12).contains(&i) { x.status(503) } else { x }
        })
        .collect();
    let f = analyse(s, "{}");
    assert!(of(&f, "PAT-RETRY").iter().all(|x| x.severity != Severity::Critical), "fixed-interval poll reported as a critical retry storm");
    assert!(!of(&f, "PAT-POLLING").is_empty());
}

// R4 (counterpart): a client that retries at a fixed interval right after a failure is still
// a retry sequence.
#[test]
fn r4_fixed_interval_retry_loop_is_still_a_retry() {
    let s: Vec<Session> = (0..8).map(|i| get(i, "https://api.test/save").at(i * 2000).took(30).status(503)).collect();
    let f = analyse(s, "{}");
    assert!(of(&f, "PAT-RETRY").iter().any(|x| x.severity == Severity::Critical), "{:?}", of(&f, "PAT-RETRY"));
}

// R5: `time`/`timestamp` with a 10-digit value is data unless it is close to the session start.
#[test]
fn r5_time_parameter_is_data() {
    let a = canon::canonical("GET", "https://api.test/history?sensor=7&time=1727690000", None);
    let b = canon::canonical("GET", "https://api.test/history?sensor=7&time=1727693600", None);
    assert_ne!(a, b, "different points in time are different resources");
    let s: Vec<Session> = (0..5u64).map(|k| get(k, &format!("https://api.test/history?sensor=7&ts={}", 1_727_000_000 + k * 3600)).at(k * 100)).collect();
    let f = analyse(s, "{}");
    assert!(of(&f, "DUP-SEMANTIC").is_empty(), "{:?}", of(&f, "DUP-SEMANTIC"));
    // A timestamp at the session start is still a cache buster.
    let s: Vec<Session> = (0..5u64).map(|k| get(k, &format!("https://api.test/list?ts={}", T0 / 1000 + k * 100)).at(k * 100)).collect();
    let f = analyse(s, "{}");
    assert!(!of(&f, "DUP-SEMANTIC").is_empty());
}

// R6: OData v2 typed numeric literals (100L, 12.5M, 1.5d) are templated → N+1 found.
#[test]
fn r6_odata_v2_typed_literals() {
    let a = canon::template("GET", "https://h/odata/Items?$filter=OrderId eq 100L");
    let b = canon::template("GET", "https://h/odata/Items?$filter=OrderId eq 101L");
    assert_eq!(a.key, b.key);
    let s: Vec<Session> = (0..12u64).map(|k| get(k, &format!("https://h/odata/Items?$filter=OrderId eq {}L", 100 + k)).at(k * 60).took(50)).collect();
    let f = analyse(s, "{}");
    assert!(!of(&f, "PAT-NPLUS1").is_empty());
}

// R7: PERF-SLOW orders by severity, so a critical endpoint is not dropped behind ten
// endpoints with more total time; the rest is summarised.
#[test]
fn r7_perf_slow_keeps_critical_endpoint() {
    let mut s = vec![];
    let mut id = 0;
    for e in 0..10 {
        for k in 0..10 {
            s.push(get(id, &format!("https://api.test/e{e}")).at(id * 2000 + k).took(1500));
            id += 1;
        }
    }
    s.push(get(id, "https://api.test/export").at(id * 2000).took(8000));
    let f = analyse(s, "{}");
    let slow = of(&f, "PERF-SLOW");
    assert!(slow.iter().any(|x| x.key.ends_with("/export") && x.severity == Severity::Critical), "the 8 s request (critical) is not reported");
    assert_eq!(slow.len(), 10);
    assert!(slow.last().unwrap().facts.iter().any(|(k, _)| k.starts_with("Further findings")), "no summary of the dropped endpoint");
}

// R8: "Tls13" (.NET naming, recognised by util::tls_version) is counted with 1 TLS round trip.
#[test]
fn r8_tls13_naming() {
    let mut s = get(1, "https://h/a").new_conn(0, 10, 10);
    s.tls_version = Some("Tls13".into());
    assert_eq!(webdiag::util::tls_version("Tls13"), Some((1, 3)));
    assert_eq!(net::tls_round_trips(&s), 1, "TLS 1.3 = 1 round trip");
}

// R9: a correlation id reused for a whole user session (≤ 8 segments) does not glue separate
// user actions into one operation.
#[test]
fn r9_session_wide_correlation_id_does_not_merge_actions() {
    let mut s = vec![];
    let mut id = 0;
    for action in 0..6u64 {
        for k in 0..20u64 {
            s.push(get(id, &format!("https://api.test/a{action}/r{k}")).at(action * 20_000 + k * 60).took(50).req_h("x-correlation-id", "user-session-1"));
            id += 1;
        }
    }
    let ss = sorted(s.clone());
    let o = ops::segment(&ss, &Options::default());
    assert_eq!(o.len(), 6, "six user actions 20 s apart");
    let f = analyse(s, "{}");
    assert!(of(&f, "PAT-CHATTY").is_empty(), "{:?}", of(&f, "PAT-CHATTY"));
}

// R10: sessions without any duration or timers are not zero-length links of a chain.
#[test]
fn r10_missing_durations_do_not_make_everything_sequential() {
    let s: Vec<Session> = (0..30)
        .map(|i| {
            let mut x = get(i, &format!("https://api.test/r{i}")).at(i * 20);
            x.duration_ms = None;
            x.timers = Default::default();
            x.client_connection = None;
            x
        })
        .collect();
    assert!(!s[0].has_end());
    let f = analyse(s, "{}");
    assert!(of(&f, "NET-LATENCY").is_empty(), "no timing data, yet a 30-level chain is claimed");
}

// R11: formatting at unit boundaries rounds first.
#[test]
fn r11_fmt_boundaries() {
    use webdiag::model::Lang;
    assert_eq!(webdiag::fmt::ms(999.6, Lang::En), "1.0 s");
    assert_eq!(webdiag::fmt::ms(59_999.0, Lang::En), "1 min 0 s");
    assert_eq!(webdiag::fmt::ms(9_999.0, Lang::De), "10 s");
}

// R12 / P1: whole-run timing on a large synthetic capture (per analyzer). Release only:
// `cargo test --release --test regressions -- --ignored --nocapture`.
#[test]
#[ignore]
fn r12_timing_500k() {
    let n: u64 = 500_000;
    let mut s = Vec::with_capacity(n as usize);
    for i in 0..n {
        let host = format!("h{}.test", i % 40);
        let url = match i % 10 {
            0 => format!("https://{host}/api/items/{}", i % 5000),
            1 => format!("https://{host}/odata/Docs?$filter=Owner eq {}&$top=50&$skip={}", i % 300, (i % 7) * 50),
            2 => format!("https://{host}/static/app{}.js", i % 50),
            3 => format!("https://{host}/api/poll"),
            4 => format!("https://{host}/api/search?q=w{}&_={}", i % 900, 1_727_690_000_000u64 + i),
            _ => format!("https://{host}/api/x/{}/y?z={}", i % 97, i % 13),
        };
        let mut x = get(i, &url).at(i * 7).took(20 + (i % 50) as u32).body(1000 + (i % 3000), if i % 10 == 2 { "application/javascript" } else { "application/json" });
        x.process = format!("p{}", i % 3);
        if i % 101 == 0 {
            x = x.status(401).resp_h("www-authenticate", "Negotiate");
        }
        if i % 53 == 0 {
            x = x.status(503);
        }
        x = x.resp_h("set-cookie", &format!("c{}=<20 bytes>; Path=/", i % 30));
        // Encoding facts on every body (most clean, some broken), as the host sends them.
        let t = match i % 211 {
            0 => webdiag::testkit::utf8_declared_latin1_sent(),
            1 => webdiag::model::TextInfo { double_encoded: 3, non_ascii: true, ..webdiag::testkit::declared("utf-8", "UTF-8") },
            2 => webdiag::testkit::latin1_declared_utf8_sent(),
            _ => webdiag::model::TextInfo { non_ascii: i % 3 == 0, ..webdiag::testkit::text_facts("UTF-8", "default") },
        };
        x.response_text = Some(Box::new(t));
        s.push(x);
    }
    let whole = std::time::Instant::now();
    let t = std::time::Instant::now();
    let mut ss = s;
    ss.sort_by_key(|s| (s.started, s.id));
    let o = Options::default();
    let opsv = ops::segment(&ss, &o);
    let seg = t.elapsed().as_secs_f64();
    eprintln!("segment          {seg:6.2}s  ({} ops)", opsv.len());
    let ctx = Ctx::new(&ss, &opsv, &o);
    let t = std::time::Instant::now();
    let _ = ctx.prep();
    let prep = t.elapsed().as_secs_f64();
    eprintln!("prep             {prep:6.2}s");
    let t = std::time::Instant::now();
    let _ = webdiag::analyzers::oauth::model(&ctx);
    let oauth = t.elapsed().as_secs_f64();
    eprintln!("oauth model      {oauth:6.2}s");
    let mut total = seg + prep + oauth;
    for a in webdiag::analyzers::all() {
        let t = std::time::Instant::now();
        let mut out = vec![];
        a.run(&ctx, &mut out);
        let e = t.elapsed().as_secs_f64();
        total += e;
        eprintln!("{:16} {:6.2}s  findings {}", a.id(), e, out.len());
    }
    eprintln!("analysis total   {total:6.2}s (wall {:.2}s)", whole.elapsed().as_secs_f64());
    drop(ctx);
    drop(opsv);
    // The complete plugin call: sort, segment, analyse, JSON.
    let mut r = webdiag::Run::new("{}");
    r.push(ss);
    let t = std::time::Instant::now();
    let json = r.finish();
    let finish = t.elapsed().as_secs_f64();
    eprintln!("Run::finish      {finish:6.2}s  ({} KB JSON)", json.len() / 1024);
    if !cfg!(debug_assertions) {
        assert!(total < 2.0, "500k sessions took {total:.2}s natively (budget 2 s)");
        assert!(finish < 3.0, "Run::finish took {finish:.2}s natively");
    }
}

// Q1: full reloads of a static resource are reported once (CACHE), not also as DUP-EXACT.
#[test]
fn q1_static_reload_reported_once() {
    let s: Vec<Session> = (0..4).map(|i| get(i, "https://cdn.test/app.js").at(i * 3000).body(200_000, "application/javascript")).collect();
    let f = analyse(s, "{}");
    let n = f.iter().filter(|x| x.id == "DUP-EXACT" || (x.id == "CACHE" && x.key.contains("reload"))).count();
    assert_eq!(n, 1, "same 4 downloads reported by DUP-EXACT and CACHE");
    assert!(f.iter().any(|x| x.key == "CACHE|reload|cdn.test"));
}

// Q2: DUP-SUBMIT's window is measured from the group's first request.
#[test]
fn q2_dup_submit_window_does_not_chain() {
    let s: Vec<Session> = (0..3).map(|i| post(i, "https://api.test/orders").at(i * 4500).req_body(100, 42)).collect();
    let f = analyse(s, "{}");
    let d = of(&f, "DUP-SUBMIT");
    assert!(d.iter().all(|x| x.severity != Severity::Critical), "3 POSTs spread over 9 s: 'critical, within 5 s'");
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].sessions, vec![0, 1]);
}

// Q3: single-request user actions on different resources of one endpoint are not background.
#[test]
fn q3_single_request_user_actions_are_not_background() {
    let s: Vec<Session> = (0..3).map(|i| get(i, &format!("https://api.test/cases/{}", 100 + i)).at(i * 10_000).took(80)).collect();
    let o = ops::segment(&sorted(s), &Options::default());
    assert_eq!(o.len(), 3);
    assert!(o.iter().all(|x| !x.background));
}

// Q4: requests still open at capture end are not connection failures.
#[test]
fn q4_in_flight_is_not_a_failure() {
    let mut s: Vec<Session> = (0..20).map(|i| get(i, "https://api.test/x").at(i * 100)).collect();
    for i in 0..3 {
        let mut x = get(100 + i, "https://api.test/events").at(3000 + i);
        x.status = 0;
        x.duration_ms = None;
        x.timers = Default::default();
        s.push(x);
    }
    assert!(s[20].incomplete() && !s[20].failed());
    let mut r = webdiag::Run::new("{}");
    r.push(s);
    let (f, _, m) = r.analyse();
    assert!(of(&f, "NET-FAIL").is_empty(), "requests still open at capture end reported as connection failures");
    assert_eq!(m.iter().find(|x| x.key == "open").map(|x| x.value), Some(3.0));
    assert_eq!(m.iter().find(|x| x.key == "errors").map(|x| x.value), Some(0.0));
}

// NET-FAIL: the severity of an error class follows its own count and share, not the host's.
#[test]
fn net_fail_severity_per_class() {
    let mut s: Vec<Session> = (0..40).map(|i| get(i, "https://api.test/x").at(i * 100)).collect();
    for i in 0..5 {
        s.push(get(100 + i, "https://api.test/x").at(5000 + i * 100).failed_with("connection reset by peer"));
    }
    s.push(get(200, "https://api.test/x").at(9000).failed_with("operation timed out"));
    let f = analyse(s, "{}");
    let nf = of(&f, "NET-FAIL");
    let reset = nf.iter().find(|x| x.key == "NET-FAIL|api.test|reset").unwrap();
    let timeout = nf.iter().find(|x| x.key == "NET-FAIL|api.test|timeout").unwrap();
    assert_eq!(reset.severity, Severity::Critical);
    assert_eq!(timeout.severity, Severity::Warning, "a single timeout is not critical");
}

// TLS-OLD counts connections, not requests.
#[test]
fn tls_old_counts_connections() {
    let s: Vec<Session> = (0..6)
        .map(|i| {
            let mut x = get(i, "https://old.test/a").at(i * 100).conn(1 + i % 2);
            x.tls_version = Some("TLSv1.0".into());
            x
        })
        .collect();
    let f = analyse(s, "{}");
    let t = of(&f, "TLS-OLD");
    assert_eq!(t.len(), 1);
    assert!(t[0].observation.starts_with("2 connection(s) to old.test (6 requests)"), "{}", t[0].observation);
}

// MAX_SESSIONS: a truncated capture says so (finding and metric).
#[test]
fn truncation_is_reported() {
    let mut r = webdiag::Run::new(r#"{"lang":"de"}"#).with_limit(10);
    r.push((0..15).map(|i| get(i, "https://h.test/a").at(i * 1000)));
    assert_eq!(r.dropped(), 5);
    let (f, _, m) = r.analyse();
    let t = of(&f, "SCOPE-LIMIT");
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].title, "Nur die ersten 10 Sessions wurden analysiert");
    assert_eq!(m.iter().find(|x| x.key == "notAnalysed").map(|x| x.value), Some(5.0));
    let mut r = webdiag::Run::new("{}").with_limit(10);
    r.push((0..10).map(|i| get(i, "https://h.test/a").at(i * 1000)));
    assert!(of(&r.analyse().0, "SCOPE-LIMIT").is_empty());
}
