//! Engine basics: options, report JSON, the example analyzer.
use webdiag::json;
use webdiag::testkit::*;

#[test]
fn slow_requests_are_aggregated_per_endpoint() {
    let mut s = vec![];
    for i in 0..5 {
        s.push(get(i, &format!("https://api.test/v1/items/{i}")).at(i * 3000).took(2500));
    }
    s.push(get(9, "https://api.test/fast").at(20000).took(20));
    let f = analyse(s, r#"{"slowMs":1000}"#);
    let slow = of(&f, "PERF-SLOW");
    assert_eq!(slow.len(), 1, "one finding per endpoint");
    assert_eq!(slow[0].sessions, vec![0, 1, 2, 3, 4]);
    assert_eq!(slow[0].key, "PERF-SLOW|GET api.test/v1/items/{}");
}

#[test]
fn report_is_valid_json_in_both_languages() {
    for lang in ["en", "de"] {
        let mut r = webdiag::Run::new(&format!(r#"{{"lang":"{lang}"}}"#));
        r.push(vec![get(1, "https://a.test/x").took(3000), get(2, "https://a.test/y").at(10).status(500)]);
        let out = r.finish();
        let v = json::parse(out.as_bytes()).expect("valid JSON");
        assert_eq!(v.get("schema").and_then(|x| x.as_f64()), Some(1.0));
        assert!(matches!(v.get("findings"), Some(json::Value::Arr(a)) if !a.is_empty()));
    }
    let d = webdiag::describe("de");
    assert!(json::parse(d.as_bytes()).is_ok() && d.contains("Netzprofile"));
}

#[test]
fn options_are_robust() {
    let o = webdiag::parse_options(r#"{"slowMs":-5,"profile":"nope","networks":[{"name":"X","rttMs":"a"}],"lang":"de"}"#);
    assert_eq!(o.slow_ms, 1000.0);
    assert_eq!(o.profile, "full");
    assert_eq!(o.networks.len(), 1);
    assert_eq!(webdiag::parse_options("not json").profile, "full");
}

#[test]
fn empty_capture() {
    let r = webdiag::Run::new("{}");
    assert!(json::parse(r.finish().as_bytes()).is_ok());
}
