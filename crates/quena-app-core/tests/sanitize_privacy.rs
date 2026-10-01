//! Sanitized export end to end: a capture full of marker values (secrets, e-mail, IBAN, card,
//! phone, IP, JWT, cookies, Basic auth, a form `client_secret`, a JSON password, a gzip
//! response) is exported as SAZ and HAR with the `gdpr` preset. No marker may appear in the
//! archives (the SAZ unzipped), both must load again, and the redaction log must count what
//! was replaced. With the `support` preset, phone numbers and IPs stay.
use quena_app_core::archive::ArchiveFormat;
use quena_app_core::sanitize::SanitizeOptions;
use quena_app_core::{AppCore, Paths};
use quena_model::{Headers, ProcessInfo, RequestHead, ResponseHead, SessionDetail};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

const JWT: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtYXJrZXItc3ViIiwiZW1haWwiOiJtYXJrZXJAZXhhbXBsZS5jb20ifQ.SECRET-JWTSIG";

/// Values that must not survive the `gdpr` preset (in any form).
const MARKERS: &[&str] = &[
    "SECRET-",
    "marker.person",
    "DE89370400440532013000",
    "DE89 3704",
    "4111111111111111",
    "4111 1111",
    "+49 30 1234567",
    "+49%2030%201234567",
    "203.0.113.7",
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
    "Ym9iOlNFQ1JFVC1CQVNJQw",
    "marker-process",
    "Maxi Markermann",
];

fn wait(core: &AppCore, job: u64) {
    let job = core.jobs.get(job).unwrap();
    let t0 = Instant::now();
    while !matches!(format!("{:?}", job.status()).as_str(), "Done" | "Failed" | "Cancelled") {
        assert!(t0.elapsed() < Duration::from_secs(60), "job did not finish");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(format!("{:?}", job.status()), "Done", "{:?}", job.snapshot().error);
}

fn core(dir: &Path) -> Arc<AppCore> {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("settings.json"), r#"{"proxy":{"actAsSystemProxy":false,"captureOnStartup":false}}"#).unwrap();
    AppCore::new(Paths::at(dir.to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap()
}

fn headers(h: &[(&str, &str)]) -> Headers {
    let mut out = Headers::new();
    for (k, v) in h {
        out.push(*k, *v);
    }
    out
}

fn detail(method: &str, url: &str, req: &[(&str, &str)], status: u16, resp: &[(&str, &str)]) -> SessionDetail {
    let mut d = SessionDetail {
        request: RequestHead { method: method.into(), url: url.into(), headers: headers(req), ..Default::default() },
        response: Some(ResponseHead { status, reason: "OK".into(), headers: headers(resp), ..Default::default() }),
        process: Some(ProcessInfo { pid: 4711, name: "marker-process".into() }),
        ..Default::default()
    };
    d.connection.client_addr = Some("203.0.113.7:50123".into());
    d.connection.server_addr = Some("198.51.100.20:443".into());
    d.summary.started_at = 1_790_000_000_000_000;
    d
}

fn fill(core: &AppCore) {
    let cap = core.capture();
    // 1: token request with Basic auth, cookie, form body; gzip JSON response.
    let form = "grant_type=client_credentials&client_secret=SECRET-CLIENT&username=marker.person%40example.com&phone=%2B49+30+1234567";
    let json = format!(
        r#"{{"access_token":"{JWT}","token_type":"Bearer","email":"marker.person@example.com","iban":"DE89370400440532013000","card":"4111111111111111","phone":"+49 30 1234567","ip":"203.0.113.7","name":"Maxi Markermann"}}"#
    );
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(json.as_bytes()).unwrap();
    let gz = gz.finish().unwrap();
    let gz_len = gz.len().to_string();
    let form_len = form.len().to_string();
    let mut d = detail(
        "POST",
        "https://api.example.test/oauth/token?api_key=SECRET-URLKEY&email=marker.person%40example.com&lang=de",
        &[
            ("Host", "api.example.test"),
            ("Authorization", "Basic Ym9iOlNFQ1JFVC1CQVNJQw=="),
            ("Cookie", "sid=SECRET-COOKIE; theme=dark"),
            ("X-Forwarded-For", "203.0.113.7"),
            ("X-Api-Key", "SECRET-APIKEY"),
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Content-Length", &form_len),
        ],
        200,
        &[("Content-Type", "application/json; charset=utf-8"), ("Content-Encoding", "gzip"), ("Content-Length", &gz_len), ("Set-Cookie", "session=SECRET-SETCOOKIE; Path=/; Secure; HttpOnly")],
    );
    d.summary.comment = "reported by marker.person@example.com".into();
    let (rq, rs) = (cap.bodies.store_bytes(form.as_bytes()), cap.bodies.store_bytes(&gz));
    cap.insert(d, rq, rs);
    // 2: JSON request with a password and free text; HTML response.
    let req = format!(
        r#"{{"password":"SECRET-PASSWORD","note":"IBAN DE89 3704 0044 0532 0130 00, Karte 4111 1111 1111 1111, Tel +49 30 1234567, IP 203.0.113.7, mail marker.person@example.com, token {JWT}"}}"#
    );
    let html = "<html><body><p>Hallo Maxi, deine Adresse marker.person@example.com</p><input type=\"hidden\" name=\"csrf_token\" value=\"SECRET-CSRF\"></body></html>";
    let d = detail(
        "POST",
        "https://app.example.test/profile",
        &[("Content-Type", "application/json"), ("Bearer-Token", "SECRET-HDR"), ("Referer", "https://app.example.test/cb?code=SECRET-CODE&state=SECRET-STATE")],
        200,
        &[("Content-Type", "text/html; charset=utf-8")],
    );
    let (rq, rs) = (cap.bodies.store_bytes(req.as_bytes()), cap.bodies.store_bytes(html.as_bytes()));
    cap.insert(d, rq, rs);
    // What the UI ticker does: make the new rows part of the view.
    cap.index.tick();
}

fn saz_text(path: &Path) -> (String, String) {
    let mut zip = zip::ZipArchive::new(std::fs::File::open(path).unwrap()).unwrap();
    let mut all = String::new();
    let mut log = String::new();
    for i in 0..zip.len() {
        let mut f = zip.by_index(i).unwrap();
        let name = f.name().to_string();
        let mut b = Vec::new();
        f.read_to_end(&mut b).unwrap();
        let t = String::from_utf8_lossy(&b).into_owned();
        if name == "QUENA-REDACTION.txt" {
            log = t.clone();
        }
        all.push_str(&format!("\n=== {name}\n{t}"));
    }
    (all, log)
}

fn assert_clean(what: &str, text: &str) {
    for m in MARKERS {
        assert!(!text.contains(m), "{what} contains {m:?}:\n{text}");
    }
}

fn reimport(path: &Path, dir: &Path) -> Arc<AppCore> {
    let c = core(dir);
    let job = c.import_archive(path.to_path_buf()).unwrap();
    wait(&c, job);
    c.capture().index.tick();
    c
}

#[test]
fn gdpr_export_contains_no_marker_and_loads_again() {
    let tmp = tempfile::tempdir().unwrap();
    let c = core(&tmp.path().join("data"));
    fill(&c);
    let saz = tmp.path().join("out.saz");
    let har = tmp.path().join("out.har");
    let gdpr = SanitizeOptions::preset("gdpr").unwrap();
    wait(&c, c.export_sanitized(vec![], saz.clone(), None, gdpr.clone()).unwrap());
    wait(&c, c.export_sanitized(vec![], har.clone(), Some(ArchiveFormat::Har), gdpr.clone()).unwrap());
    // The options are remembered; the temporary copies are gone.
    assert_eq!(c.settings().sanitize.options, gdpr);
    assert_eq!(c.settings().sanitize.format, "har");
    let left: Vec<_> = std::fs::read_dir(tmp.path().join("data/sanitize-tmp")).unwrap().flatten().collect();
    assert!(left.is_empty(), "{left:?}");

    let (saz_all, saz_log) = saz_text(&saz);
    assert_clean("SAZ", &saz_all);
    let har_text = std::fs::read_to_string(&har).unwrap();
    assert_clean("HAR", &har_text);
    // Placeholders, kept structure, decoded bodies.
    assert!(saz_all.contains("Authorization: Basic <24 bytes>") && saz_all.contains("Cookie: sid=<cookie-1>; theme=<cookie-2>"), "{saz_all}");
    assert!(saz_all.contains("Set-Cookie: session=<cookie-3>; Path=/; Secure; HttpOnly"), "{saz_all}");
    assert!(!saz_all.to_ascii_lowercase().contains("content-encoding:"), "{saz_all}");
    assert!(saz_all.contains(r#""token_type":"Bearer""#) && saz_all.contains(r#""email":"<personal-"#), "{saz_all}");

    // Redaction log: as text in the SAZ, as JSON in the HAR.
    assert!(saz_log.contains("Preset: gdpr") && saz_log.contains("Sessions with replacements (numbers in the original capture): 1, 2"), "{saz_log}");
    let v: serde_json::Value = serde_json::from_str(&har_text).unwrap();
    assert!(v["log"]["comment"].as_str().unwrap().starts_with("Sanitized by Quena (gdpr preset)"));
    let log = &v["log"]["_quenaRedaction"];
    let n = |c: &str| log["byCategory"][c].as_u64().unwrap_or(0);
    assert_eq!(log["sessions"], 2);
    assert_eq!(log["touched"], serde_json::json!([1, 2]));
    assert_eq!(n("authorization"), 1);
    assert_eq!(n("cookie"), 3);
    assert_eq!(n("secretHeader"), 2, "X-Api-Key, Bearer-Token");
    assert!(n("urlSecret") >= 3, "api_key, code, state: {log}");
    assert!(n("secretField") >= 3, "client_secret, access_token, password: {log}");
    // The `iban` / `phone` fields of session 1 count as personal fields, `card` is no such name.
    assert!(n("email") >= 3 && n("iban") == 1 && n("card") == 2 && n("phone") == 1 && n("jwt") == 1, "{log}");
    assert!(n("ip") >= 4 && n("process") == 2 && n("personalField") >= 5, "{log}");
    assert!(log["byLocation"]["body"].as_u64().unwrap() > 5 && log["byLocation"]["meta"].as_u64().unwrap() >= 3);

    // Both archives load again, without markers.
    for (p, name) in [(&saz, "saz"), (&har, "har")] {
        let r = reimport(p, &tmp.path().join(format!("re-{name}")));
        let cap = r.capture();
        let ids = cap.index.find(|_| true);
        assert_eq!(ids.len(), 2, "{name}");
        for id in ids {
            let d = cap.detail(id).unwrap();
            let (rq, rs) = cap.bodies_of(id).unwrap();
            let mut b = Vec::new();
            rq.stream(0, false).read_to_end(&mut b).unwrap();
            rs.stream(0, false).read_to_end(&mut b).unwrap();
            assert_clean(name, &format!("{d:?}{}", String::from_utf8_lossy(&b)));
        }
    }
}

#[test]
fn support_keeps_phones_and_ips() {
    let tmp = tempfile::tempdir().unwrap();
    let c = core(&tmp.path().join("data"));
    fill(&c);
    let har = tmp.path().join("support.har");
    wait(&c, c.export_sanitized(vec![2], har.clone(), None, SanitizeOptions::default()).unwrap());
    let t = std::fs::read_to_string(&har).unwrap();
    for gone in ["SECRET-", "marker.person", "DE89 3704", "4111 1111", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"] {
        assert!(!t.contains(gone), "{gone}: {t}");
    }
    for kept in ["+49 30 1234567", "203.0.113.7", "marker-process"] {
        assert!(t.contains(kept), "{kept}: {t}");
    }
    let v: serde_json::Value = serde_json::from_str(&t).unwrap();
    assert_eq!(v["log"]["_quenaRedaction"]["sessions"], 1);
    assert_eq!(v["log"]["entries"].as_array().unwrap().len(), 1);
}
