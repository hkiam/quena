//! Clock differences between servers and this computer (CLOCK-SKEW / -LOCAL / -DRIFT).
use webdiag::model::Severity;
use webdiag::testkit::*;

fn run(s: Vec<webdiag::model::Session>) -> Vec<webdiag::model::Finding> {
    analyse(s, r#"{"profile":"troubleshooting"}"#)
}

#[test]
fn http_dates_round_trip() {
    let t = 1_727_690_000u64;
    assert_eq!(webdiag::util::parse_http_date(&http_date(t)), Some(t));
    assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
}

#[test]
fn a_server_ahead_by_minutes_is_critical() {
    let mut s: Vec<_> = (0..4).map(|i| get(i, "https://login.example.com/token").at(i * 1000).server_clock(420)).collect();
    s.extend((10..14).map(|i| get(i, "https://api.example.org/x").at(i * 1000).server_clock(0)));
    let f = run(s);
    let skew = of(&f, "CLOCK-SKEW");
    assert_eq!(skew.len(), 1, "{f:#?}");
    assert_eq!(skew[0].key, "CLOCK-SKEW|login.example.com");
    assert_eq!(skew[0].severity, Severity::Critical);
    assert!(skew[0].facts.iter().any(|(_, v)| v.contains("server ahead")), "{:?}", skew[0].facts);
    assert_eq!(skew[0].sessions, vec![0, 1, 2, 3]);
    assert!(of(&f, "CLOCK-LOCAL").is_empty());
}

#[test]
fn severity_follows_the_offset() {
    let sev = |off: i64| run((0..3).map(|i| get(i, "https://a.example.com/").at(i * 500).server_clock(off)).collect()).into_iter().find(|f| f.id == "CLOCK-SKEW").map(|f| f.severity);
    assert_eq!(sev(-40), Some(Severity::Info));
    assert_eq!(sev(-90), Some(Severity::Warning));
    assert_eq!(sev(-301), Some(Severity::Critical));
    assert_eq!(sev(-5), None, "a few seconds is network delay and rounding, not a clock problem");
}

#[test]
fn many_sites_with_the_same_offset_point_to_this_computer() {
    let hosts = ["a.example.com", "b.example.net", "c.example.org", "d.example.de"];
    let mut s = vec![];
    for (k, h) in hosts.iter().enumerate() {
        for i in 0..3u64 {
            s.push(get(k as u64 * 10 + i, &format!("https://{h}/")).at(k as u64 * 5000 + i * 700).server_clock(-3600 + k as i64));
        }
    }
    let f = run(s);
    let local = of(&f, "CLOCK-LOCAL");
    assert_eq!(local.len(), 1, "{f:#?}");
    assert_eq!(local[0].severity, Severity::Critical);
    assert!(of(&f, "CLOCK-SKEW").is_empty(), "explained by the local clock, not reported per host");
    // German text.
    let de = analyse(
        hosts.iter().enumerate().flat_map(|(k, h)| (0..3u64).map(move |i| get(k as u64 * 10 + i, &format!("https://{h}/")).at(i * 700).server_clock(-3600))).collect(),
        r#"{"lang":"de"}"#,
    );
    assert!(of(&de, "CLOCK-LOCAL")[0].title.contains("Uhr dieses Computers"));
}

#[test]
fn servers_behind_one_name_that_disagree() {
    let s: Vec<_> = (0..10u64).map(|i| get(i, "https://shop.example.com/api").at(i * 800).server_clock(if i % 2 == 0 { 0 } else { 95 })).collect();
    let f = run(s);
    let d = of(&f, "CLOCK-DRIFT");
    assert_eq!(d.len(), 1, "{f:#?}");
    assert_eq!(d[0].severity, Severity::Warning);
    // A steady offset is skew, not drift.
    let s: Vec<_> = (0..10u64).map(|i| get(i, "https://shop.example.com/api").at(i * 800).server_clock(95)).collect();
    assert!(of(&run(s), "CLOCK-DRIFT").is_empty());
}

#[test]
fn cached_responses_count_their_age() {
    // A CDN serves a response generated 10 minutes ago: Date is old, Age says so.
    let s: Vec<_> = (0..3u64).map(|i| get(i, "https://cdn.example.com/app.js").at(i * 500).server_clock(-600).resp_h("Age", "600")).collect();
    assert!(of(&run(s), "CLOCK-SKEW").is_empty());
}

#[test]
fn no_date_header_no_finding() {
    let s: Vec<_> = (0..5u64).map(|i| get(i, "https://a.example.com/").at(i * 500)).collect();
    let f = run(s);
    assert!(f.iter().all(|x| !x.id.starts_with("CLOCK")));
    let s = vec![get(1, "https://a.example.com/").resp_h("Date", "not a date"), get(2, "https://a.example.com/").failed_with("timeout").resp_h("Date", &http_date(1))];
    assert!(run(s).iter().all(|x| !x.id.starts_with("CLOCK")));
}
