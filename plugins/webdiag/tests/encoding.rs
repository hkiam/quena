//! Character encoding analyzers (analyzers/encoding.rs): positive and negative cases per rule,
//! with synthetic text facts (testkit `text_facts`, `declared`, …).
use webdiag::model::{Confidence, Finding, Session, Severity, TextInfo};
use webdiag::testkit::*;

fn run(s: Vec<Session>) -> Vec<Finding> {
    analyse(s, "{}")
}

fn enc(f: &[Finding]) -> Vec<String> {
    f.iter().filter(|x| x.id.starts_with("ENC-")).map(|x| x.key.clone()).collect()
}

/// `n` responses of one endpoint with these facts.
fn responses(n: u64, ct: &str, t: TextInfo) -> Vec<Session> {
    (0..n).map(|i| get(i + 1, &format!("https://api.test/v1/items/{i}")).at(i * 1000).text(ct, t.clone())).collect()
}

const EP: &str = "GET api.test/v1/items/{}";

// ------------------------------------------------------------------ ENC-MISMATCH

#[test]
fn mismatch_declared_utf8_but_latin1_bytes() {
    let f = run(responses(4, "text/plain; charset=utf-8", utf8_declared_latin1_sent()));
    assert_eq!(enc(&f), vec![format!("ENC-MISMATCH|response|not-utf8|{EP}")]);
    let m = of(&f, "ENC-MISMATCH")[0];
    // Frequent: 4 of 4 bodies → critical; all sessions listed; the example is in the text.
    assert_eq!((m.severity, m.sessions.clone()), (Severity::Critical, vec![1, 2, 3, 4]));
    assert!(m.impact.contains("Gr��e"), "{}", m.impact);
    // A single one is a warning.
    let f = run(responses(1, "text/plain; charset=utf-8", utf8_declared_latin1_sent()));
    assert_eq!(of(&f, "ENC-MISMATCH")[0].severity, Severity::Warning);
    // Rare among many clean bodies: a warning.
    let mut s = responses(3, "text/plain; charset=utf-8", utf8_declared_latin1_sent());
    s.extend((10..30).map(|i| get(i, &format!("https://api.test/v1/items/{i}")).at(i * 1000).text("text/plain; charset=utf-8", TextInfo { non_ascii: true, ..declared("utf-8", "UTF-8") })));
    assert_eq!(of(&run(s), "ENC-MISMATCH")[0].severity, Severity::Warning);
}

#[test]
fn mismatch_json_default_utf8() {
    // JSON without charset is UTF-8 by definition; Latin-1 bytes contradict it.
    let t = TextInfo { non_ascii: true, utf8_valid: false, decode_errors: 2, ..text_facts("UTF-8", "default") };
    let f = run(responses(1, "application/json", t));
    assert_eq!(enc(&f), vec![format!("ENC-MISMATCH|response|not-utf8|{EP}")]);
    assert!(of(&f, "ENC-MISMATCH")[0].observation.contains("JSON"));
}

#[test]
fn mismatch_legacy_declared_but_utf8_bytes() {
    let f = run(responses(2, "text/html; charset=ISO-8859-1", latin1_declared_utf8_sent()));
    assert_eq!(enc(&f), vec![format!("ENC-MISMATCH|response|utf8|{EP}")]);
    let m = of(&f, "ENC-MISMATCH")[0];
    assert_eq!((m.severity, m.confidence), (Severity::Warning, Confidence::High));
    assert!(m.impact.contains("GrÃ¼ÃŸe"), "{}", m.impact);
    // Only the sample was examined: medium confidence.
    let big = TextInfo { sampled: 256 << 10, ..latin1_declared_utf8_sent() };
    assert_eq!(of(&run(responses(1, "text/html; charset=ISO-8859-1", big)), "ENC-MISMATCH")[0].confidence, Confidence::Medium);
}

#[test]
fn no_mismatch_when_bytes_match_or_are_ascii() {
    // Latin-1 declared and sent (not valid UTF-8, no errors in windows-1252).
    let latin = TextInfo { non_ascii: true, utf8_valid: false, ..declared("ISO-8859-1", "windows-1252") };
    // Pure ASCII under a legacy label: harmless.
    let ascii = declared("ISO-8859-1", "windows-1252");
    let utf = TextInfo { non_ascii: true, ..declared("utf-8", "UTF-8") };
    let json = TextInfo { non_ascii: true, ..text_facts("UTF-8", "default") };
    let mut s = responses(1, "text/plain; charset=ISO-8859-1", latin);
    s.push(get(20, "https://b.test/a").text("text/plain; charset=ISO-8859-1", ascii));
    s.push(get(21, "https://c.test/a").text("text/plain; charset=utf-8", utf));
    s.push(get(22, "https://d.test/a").text("application/json", json));
    assert_eq!(enc(&run(s)), Vec::<String>::new());
}

#[test]
fn request_bodies_are_checked_too() {
    let s = vec![post(1, "https://api.test/v1/save").req_text("application/x-www-form-urlencoded; charset=utf-8", utf8_declared_latin1_sent())];
    let f = run(s);
    assert_eq!(enc(&f), vec!["ENC-MISMATCH|request|not-utf8|POST api.test/v1/save".to_string()]);
    assert!(of(&f, "ENC-MISMATCH")[0].hypotheses[0].contains("client"));
}

// ------------------------------------------------------------------ ENC-CONFLICT

fn conflicting(non_ascii: bool, utf8_valid: bool) -> TextInfo {
    TextInfo { document_charset: Some("UTF-8".into()), document_resolved: Some("UTF-8".into()), non_ascii, utf8_valid, ..declared("ISO-8859-1", "windows-1252") }
}

#[test]
fn conflict_between_header_and_document() {
    let f = run(responses(3, "application/xml; charset=ISO-8859-1", conflicting(true, true)));
    // Reported once, per host, and not also as a mismatch.
    assert_eq!(enc(&f), vec!["ENC-CONFLICT|response|api.test".to_string()]);
    let c = of(&f, "ENC-CONFLICT")[0];
    assert_eq!(c.severity, Severity::Warning);
    assert!(c.impact.contains("BOM first"), "{}", c.impact);
    assert!(c.hypotheses.iter().any(|h| h.contains("UTF-8 declaration is probably right")), "{:?}", c.hypotheses);
    // ASCII only: harmless for now.
    let f = run(responses(1, "application/xml; charset=ISO-8859-1", conflicting(false, true)));
    assert_eq!(of(&f, "ENC-CONFLICT")[0].severity, Severity::Info);
    // The winning header is wrong and characters get lost in most bodies: critical.
    let broken = TextInfo {
        document_charset: Some("ISO-8859-1".into()),
        document_resolved: Some("windows-1252".into()),
        ..utf8_declared_latin1_sent()
    };
    let f = run(responses(4, "text/xml; charset=utf-8", broken));
    assert_eq!(of(&f, "ENC-CONFLICT")[0].severity, Severity::Critical);
    assert!(of(&f, "ENC-MISMATCH").is_empty());
}

#[test]
fn no_conflict_for_equivalent_labels_or_utf16_byte_orders() {
    // latin1 and ISO-8859-1 both resolve to windows-1252.
    let same = TextInfo { document_charset: Some("latin1".into()), document_resolved: Some("windows-1252".into()), ..declared("ISO-8859-1", "windows-1252") };
    // A UTF-16BE BOM and an XML declaration "UTF-16" (which resolves to UTF-16LE).
    let u16 = TextInfo {
        bom: Some("UTF-16BE".into()),
        document_charset: Some("UTF-16".into()),
        document_resolved: Some("UTF-16LE".into()),
        non_ascii: true,
        utf8_valid: false,
        ..text_facts("UTF-16BE", "bom")
    };
    let mut s = responses(1, "application/xml; charset=ISO-8859-1", same);
    s.push(get(9, "https://x.test/a").text("application/xml", u16));
    assert_eq!(enc(&run(s)), Vec::<String>::new());
}

// ------------------------------------------------------------------ ENC-MISSING

fn undeclared(utf8_valid: bool) -> TextInfo {
    TextInfo { non_ascii: true, utf8_valid, ..text_facts(if utf8_valid { "UTF-8" } else { "windows-1252" }, "default") }
}

#[test]
fn missing_charset_for_text_types() {
    let f = run(responses(2, "text/plain", undeclared(false)));
    assert_eq!(enc(&f), vec!["ENC-MISSING|response|api.test".to_string()]);
    assert_eq!(of(&f, "ENC-MISSING")[0].severity, Severity::Warning);
    // Valid UTF-8 CSV: clients may still guess ISO-8859-1 → info.
    let f = run(responses(1, "text/csv", undeclared(true)));
    assert_eq!(of(&f, "ENC-MISSING")[0].severity, Severity::Info);
    // HTML: browsers fall back to a locale default → warning even when it is UTF-8.
    let f = run(responses(1, "text/html", undeclared(true)));
    assert_eq!(of(&f, "ENC-MISSING")[0].severity, Severity::Warning);
    // Form posts.
    let f = run(vec![post(1, "https://api.test/form").req_text("application/x-www-form-urlencoded", undeclared(false))]);
    assert_eq!(enc(&f), vec!["ENC-MISSING|request|api.test".to_string()]);
}

#[test]
fn no_missing_charset_for_utf8_default_types_or_ascii() {
    let mut s = responses(1, "application/json", undeclared(true));
    s.push(get(10, "https://x.test/feed").text("application/xml", undeclared(true)));
    s.push(get(11, "https://y.test/events").text("text/event-stream", undeclared(true)));
    s.push(get(12, "https://z.test/a").text("text/plain", text_facts("UTF-8", "default")));
    // A document declaration is a declaration.
    s.push(get(13, "https://w.test/a").text("text/html", TextInfo { document_charset: Some("utf-8".into()), document_resolved: Some("UTF-8".into()), ..undeclared(true) }));
    assert_eq!(enc(&run(s)), Vec::<String>::new());
}

// ------------------------------------------------------------------ ENC-DOUBLE

fn doubled(hits: u32) -> TextInfo {
    TextInfo { non_ascii: true, double_encoded: hits, ..declared("utf-8", "UTF-8") }
}

#[test]
fn double_encoding() {
    let f = run(responses(2, "application/json; charset=utf-8", doubled(4)));
    assert_eq!(enc(&f), vec![format!("ENC-DOUBLE|response|{EP}")]);
    let d = of(&f, "ENC-DOUBLE")[0];
    assert_eq!((d.severity, d.confidence), (Severity::Warning, Confidence::High));
    assert!(d.recommendations[0].contains("source"), "{:?}", d.recommendations);
    // Few traces: medium confidence; a single trace is not reported (could be real text).
    assert_eq!(of(&run(responses(1, "application/json", doubled(3))), "ENC-DOUBLE")[0].confidence, Confidence::Medium);
    assert!(of(&run(responses(1, "application/json", doubled(1))), "ENC-DOUBLE").is_empty());
    // Widespread: critical.
    assert_eq!(of(&run(responses(12, "application/json", doubled(3))), "ENC-DOUBLE")[0].severity, Severity::Critical);
}

#[test]
fn double_encoding_with_invalid_bytes_is_a_mismatch_only() {
    let t = TextInfo { double_encoded: 5, ..utf8_declared_latin1_sent() };
    let f = run(responses(1, "text/plain; charset=utf-8", t));
    assert_eq!(enc(&f), vec![format!("ENC-MISMATCH|response|not-utf8|{EP}")]);
    assert!(of(&f, "ENC-MISMATCH")[0].facts.iter().any(|(l, _)| l.contains("double")));
}

#[test]
fn double_encoded_requests_after_legacy_labelled_responses() {
    let s = vec![
        get(1, "https://app.test/form").text("text/html; charset=ISO-8859-1", latin1_declared_utf8_sent()),
        post(2, "https://app.test/save").at(1000).req_text("application/json", doubled(4)),
    ];
    let f = run(s);
    let d = of(&f, "ENC-DOUBLE");
    assert_eq!(d.len(), 1);
    assert!(d[0].hypotheses.iter().any(|h| h.contains("ENC-MISMATCH")), "{:?}", d[0].hypotheses);
    assert_eq!(of(&f, "ENC-MISMATCH").len(), 1);
}

// ------------------------------------------------------------------ ENC-LOST

#[test]
fn lost_characters() {
    let t = TextInfo { non_ascii: true, replacement_chars: 2, ..declared("utf-8", "UTF-8") };
    let f = run(responses(1, "application/json", t.clone()));
    assert_eq!(enc(&f), vec![format!("ENC-LOST|response|{EP}")]);
    assert_eq!(of(&f, "ENC-LOST")[0].severity, Severity::Info);
    assert_eq!(of(&run(responses(3, "application/json", t)), "ENC-LOST")[0].severity, Severity::Warning);
    // Reported besides other verdicts, but not for binary data.
    let both = TextInfo { replacement_chars: 1, ..latin1_declared_utf8_sent() };
    let f = run(responses(1, "text/plain; charset=ISO-8859-1", both));
    assert_eq!(enc(&f).len(), 2, "{:?}", enc(&f));
    let bin = TextInfo { nul_bytes: 9, replacement_chars: 1, ..declared("utf-8", "UTF-8") };
    assert!(of(&run(responses(1, "text/plain", bin)), "ENC-LOST").is_empty());
    // Clean text: nothing.
    assert!(enc(&run(responses(3, "application/json", TextInfo { non_ascii: true, ..declared("utf-8", "UTF-8") }))).is_empty());
}

// ------------------------------------------------------------------ ENC-JSON

#[test]
fn json_not_in_utf8() {
    // Declared ISO-8859-1 with Latin-1 bytes: UTF-8 readers lose characters.
    let latin = TextInfo { non_ascii: true, utf8_valid: false, ..declared("ISO-8859-1", "windows-1252") };
    let f = run(responses(1, "application/json; charset=ISO-8859-1", latin));
    assert_eq!(enc(&f), vec![format!("ENC-JSON|response|{EP}")]);
    let j = of(&f, "ENC-JSON")[0];
    assert_eq!(j.severity, Severity::Warning);
    assert!(j.impact.contains("RFC 8259"));
    // UTF-8 bytes under a Latin-1 label: ENC-JSON, not also ENC-MISMATCH.
    let f = run(responses(1, "application/json; charset=ISO-8859-1", latin1_declared_utf8_sent()));
    assert_eq!(enc(&f), vec![format!("ENC-JSON|response|{EP}")]);
    assert!(of(&f, "ENC-JSON")[0].hypotheses[0].contains("only the label"));
    // UTF-16 with a BOM.
    let u16 = TextInfo { bom: Some("UTF-16LE".into()), non_ascii: true, utf8_valid: false, ..text_facts("UTF-16LE", "bom") };
    assert_eq!(of(&run(responses(1, "application/json", u16)), "ENC-JSON")[0].severity, Severity::Warning);
    // ASCII only: info.
    assert_eq!(of(&run(responses(1, "application/json; charset=ISO-8859-1", declared("ISO-8859-1", "windows-1252"))), "ENC-JSON")[0].severity, Severity::Info);
    // charset=utf-8 is fine.
    assert!(enc(&run(responses(1, "application/json; charset=utf-8", TextInfo { non_ascii: true, ..declared("utf-8", "UTF-8") }))).is_empty());
}

// ------------------------------------------------------------------ ENC-UNKNOWN, ENC-BINARY

#[test]
fn unknown_label() {
    let t = TextInfo { header_charset: Some("utf8mb4".into()), header_resolved: None, unknown_label: true, non_ascii: true, ..text_facts("UTF-8", "default") };
    let f = run(responses(2, "text/plain; charset=utf8mb4", t));
    assert_eq!(enc(&f), vec!["ENC-UNKNOWN|response|api.test".to_string()]);
    let u = of(&f, "ENC-UNKNOWN")[0];
    assert_eq!(u.severity, Severity::Warning);
    assert!(u.observation.contains("utf8mb4"), "{}", u.observation);
}

#[test]
fn binary_as_text() {
    let t = TextInfo { nul_bytes: 12, non_ascii: true, utf8_valid: false, ..text_facts("windows-1252", "default") };
    let f = run(responses(1, "text/plain", t));
    assert_eq!(enc(&f), vec![format!("ENC-BINARY|response|{EP}")]);
    assert_eq!(of(&f, "ENC-BINARY")[0].severity, Severity::Info);
    // UTF-16 has NUL bytes by nature (the host does not count them there anyway).
    let u16 = TextInfo { nul_bytes: 3, bom: Some("UTF-16LE".into()), ..text_facts("UTF-16LE", "bom") };
    assert!(of(&run(responses(1, "text/plain", u16)), "ENC-BINARY").is_empty());
}

// ------------------------------------------------------------------ ENC-DECODE

#[test]
fn undecodable_content_encoding() {
    let bad = |n: u64| (0..n).map(|i| get(i + 1, &format!("https://api.test/v1/items/{i}")).at(i * 1000).resp_h("Content-Encoding", "gzip").resp_decoding_error("invalid: gzip: invalid gzip header")).collect::<Vec<_>>();
    let f = run(bad(1));
    assert_eq!(enc(&f), vec![format!("ENC-DECODE|response|invalid|{EP}")]);
    let d = of(&f, "ENC-DECODE")[0];
    assert_eq!(d.severity, Severity::Warning);
    assert!(d.facts.iter().any(|(_, v)| v.contains("gzip")), "{:?}", d.facts);
    assert_eq!(of(&run(bad(3)), "ENC-DECODE")[0].severity, Severity::Critical);
    // Unknown coding.
    let f = run(vec![get(1, "https://api.test/a").resp_h("Content-Encoding", "x-custom").resp_decoding_error("unsupported: x-custom")]);
    assert_eq!(enc(&f), vec!["ENC-DECODE|response|unsupported|GET api.test/a".to_string()]);
    // Requests.
    let f = run(vec![post(1, "https://api.test/up").req_h("Content-Encoding", "br").req_decoding_error("invalid: br: corrupt")]);
    assert_eq!(enc(&f), vec!["ENC-DECODE|request|invalid|POST api.test/up".to_string()]);
}

#[test]
fn compressed_without_or_with_one_content_encoding_too_few() {
    let gz = TextInfo { looks_compressed: Some("gzip".into()), non_ascii: true, utf8_valid: false, decode_errors: 30, ..declared("utf-8", "UTF-8") };
    let f = run(responses(1, "application/json; charset=utf-8", gz.clone()));
    // One report (not also a mismatch of the compressed bytes).
    assert_eq!(enc(&f), vec![format!("ENC-DECODE|response|compressed|{EP}")]);
    assert!(of(&f, "ENC-DECODE")[0].title.contains("without Content-Encoding"));
    let twice = vec![get(1, "https://api.test/a").resp_h("Content-Encoding", "gzip").text("text/html", gz)];
    assert!(of(&run(twice), "ENC-DECODE")[0].title.contains("twice"));
}

// ------------------------------------------------------------------ profiles, language

#[test]
fn profiles_and_language() {
    let s = || {
        let mut v = responses(1, "text/plain; charset=utf-8", utf8_declared_latin1_sent());
        v.push(get(20, "https://x.test/a").text("text/plain", undeclared(false)));
        v
    };
    assert!(enc(&analyse(s(), r#"{"profile":"performance"}"#)).is_empty());
    assert_eq!(enc(&analyse(s(), r#"{"profile":"troubleshooting"}"#)).len(), 2);
    // Modernization: only the declaration checks.
    assert_eq!(enc(&analyse(s(), r#"{"profile":"modernization"}"#)), vec!["ENC-MISSING|response|x.test".to_string()]);
    let de = analyse(s(), r#"{"lang":"de"}"#);
    let m = of(&de, "ENC-MISMATCH")[0];
    assert!(m.title.starts_with("UTF-8 deklariert"), "{}", m.title);
    assert!(m.impact.contains("Zeichen gehen verloren"), "{}", m.impact);
}

#[test]
fn sessions_without_facts_are_ignored() {
    let s: Vec<Session> = (0..5).map(|i| get(i, &format!("https://api.test/v1/items/{i}")).body(100, "text/plain")).collect();
    assert!(enc(&run(s)).is_empty());
}
