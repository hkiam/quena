//! Encoding diagnostics end to end: a generated HAR with base64 bodies in different charsets →
//! host (text facts, decoding errors) → webdiag → ENC-* findings. Requires `plugins/build.sh`
//! to have been run (skips otherwise).
use quena_app_core::{AppCore, Paths};
use serde_json::{Value, json};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn wait(core: &AppCore, job: u64) {
    let job = core.jobs.get(job).unwrap();
    let t0 = Instant::now();
    while !matches!(
        format!("{:?}", job.status()).as_str(),
        "Done" | "Failed" | "Cancelled"
    ) {
        assert!(t0.elapsed() < Duration::from_secs(60), "job did not finish");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        format!("{:?}", job.status()),
        "Done",
        "{:?}",
        job.snapshot().error
    );
}

fn base64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for k in 0..4 {
            out.push(if k <= c.len() {
                A[(n >> (18 - 6 * k) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// One HAR entry; bodies are base64 so any bytes survive.
fn entry(
    ms: i64,
    method: &str,
    url: &str,
    content_type: &str,
    body: &[u8],
    request: Option<(&str, Option<&str>, &[u8])>,
) -> Value {
    let t0 = 1_790_000_000_000i64; // 2026-09-21
    let started = time_iso(t0 + ms);
    let mut req_headers = vec![json!({"name": "User-Agent", "value": "quena-e2e"})];
    let mut post = Value::Null;
    if let Some((ct, ce, b)) = request {
        req_headers.push(json!({"name": "Content-Type", "value": ct}));
        if let Some(ce) = ce {
            req_headers.push(json!({"name": "Content-Encoding", "value": ce}));
        }
        post = json!({"mimeType": ct, "text": base64(b), "encoding": "base64"});
    }
    let mut req = json!({"method": method, "url": url, "httpVersion": "HTTP/1.1", "cookies": [], "headers": req_headers, "queryString": [], "headersSize": -1, "bodySize": -1});
    if !post.is_null() {
        req["postData"] = post;
    }
    json!({
        "startedDateTime": started,
        "time": 30,
        "request": req,
        "response": {
            "status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1", "cookies": [],
            "headers": [{"name": "Content-Type", "value": content_type}],
            "content": {"size": body.len(), "mimeType": content_type, "text": base64(body), "encoding": "base64"},
            "redirectURL": "", "headersSize": -1, "bodySize": body.len()
        },
        "cache": {},
        "timings": {"blocked": -1, "dns": -1, "connect": -1, "ssl": -1, "send": 1, "wait": 25, "receive": 4}
    })
}

/// ISO 8601 of ms since the epoch (UTC).
fn time_iso(ms: i64) -> String {
    let t = time::OffsetDateTime::from_unix_timestamp_nanos(ms as i128 * 1_000_000).unwrap();
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

/// The fixture: one host per problem (so per-host keys stay apart), plus a clean host.
fn encoding_har() -> Value {
    let latin1 = b"Gr\xfc\xdfe SECRETBODY"; // "Grüße" in ISO-8859-1
    let utf8 = "Grüße SECRETBODY".as_bytes();
    let utf16: Vec<u8> = [0xFF, 0xFE]
        .into_iter()
        .chain(r#"{"a":"Grüße"}"#.encode_utf16().flat_map(|c| c.to_le_bytes()))
        .collect();
    let mut e = vec![];
    for i in 0..4 {
        e.push(entry(
            i * 100,
            "GET",
            &format!("https://mismatch.test/items/{i}"),
            "text/plain; charset=utf-8",
            latin1,
            None,
        ));
    }
    e.push(entry(
        500,
        "GET",
        "https://legacy.test/page",
        "text/html; charset=ISO-8859-1",
        format!("<html><body>{}</body></html>", "Grüße").as_bytes(),
        None,
    ));
    e.push(entry(
        600,
        "GET",
        "https://conflict.test/feed",
        "application/xml; charset=ISO-8859-1",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><a>Grüße</a>".as_bytes(),
        None,
    ));
    e.push(entry(
        700,
        "GET",
        "https://double.test/names",
        "application/json; charset=utf-8",
        r#"{"n":"GrÃ¼ÃŸe"}"#.as_bytes(),
        None,
    ));
    e.push(entry(
        800,
        "GET",
        "https://missing.test/export.csv",
        "text/csv",
        b"name\nGr\xfc\xdfe\n",
        None,
    ));
    e.push(entry(
        900,
        "GET",
        "https://lost.test/names",
        "application/json",
        "{\"n\":\"Gr\u{fffd}\u{fffd}e\"}".as_bytes(),
        None,
    ));
    e.push(entry(
        1000,
        "GET",
        "https://utf16.test/data",
        "application/json",
        &utf16,
        None,
    ));
    e.push(entry(
        1100,
        "GET",
        "https://unknown.test/t",
        "text/plain; charset=x-klingon",
        utf8,
        None,
    ));
    e.push(entry(
        1200,
        "GET",
        "https://binary.test/file",
        "text/plain",
        b"PK\x03\x04\x00\x00\x00\x00binary",
        None,
    ));
    // HAR content is stored decoded, so gzip bytes here are compressed data without
    // Content-Encoding.
    e.push(entry(
        1300,
        "GET",
        "https://gz.test/data",
        "application/json",
        &gzip(br#"{"a":1}"#),
        None,
    ));
    // A really corrupt gzip request (gzip signature, truncated stream). Plain text with a
    // gzip header is how most HAR writers store decoded requests: that is no finding.
    let corrupt = gzip(br#"{"upload":"a long enough body to be cut"}"#);
    e.push(entry(
        1400,
        "POST",
        "https://upload.test/save",
        "application/json",
        b"{}",
        Some(("application/json", Some("gzip"), &corrupt[..12])),
    ));
    e.push(entry(
        1450,
        "POST",
        "https://upload.test/text",
        "application/json",
        b"{}",
        Some(("application/json", Some("gzip"), b"{\"decoded\":true}")),
    ));
    // Clean: UTF-8 declared and sent, JSON without charset in UTF-8, a Latin-1 page declared so.
    e.push(entry(
        1500,
        "GET",
        "https://clean.test/a",
        "text/plain; charset=utf-8",
        utf8,
        None,
    ));
    e.push(entry(
        1600,
        "POST",
        "https://clean.test/b",
        "application/json",
        "{\"n\":\"Grüße\"}".as_bytes(),
        Some(("application/json", None, "{\"n\":\"Grüße\"}".as_bytes())),
    ));
    e.push(entry(
        1700,
        "GET",
        "https://clean.test/c",
        "text/html; charset=ISO-8859-1",
        latin1,
        None,
    ));
    json!({"log": {"version": "1.2", "creator": {"name": "quena-e2e", "version": "1"}, "entries": e}})
}

#[test]
fn encoding_findings_from_a_har_import() {
    let dist = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../plugins/dist");
    if !dist.join("webdiag").exists() {
        eprintln!("webdiag plugin not built – run plugins/build.sh");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("settings.json"),
        r#"{"proxy":{"actAsSystemProxy":false,"captureOnStartup":false}}"#,
    )
    .unwrap();
    let core = AppCore::new(
        Paths::at(dir.path().to_path_buf()),
        quena_app_core::logbuf::LogBuffer::new(100),
    )
    .unwrap();
    core.init_plugins(Some(dist)).unwrap();
    let wd = core
        .diag_analyzers()
        .into_iter()
        .find(|a| a.id == "io.github.hkiam.webdiag")
        .expect("webdiag");
    let har = dir.path().join("encoding.har");
    std::fs::write(&har, serde_json::to_vec(&encoding_har()).unwrap()).unwrap();
    wait(&core, core.import_archive(har.clone()).unwrap());
    core.capture().index.tick();
    wait(
        &core,
        core.diag_run(
            wd.index,
            r#"{"profile":"troubleshooting","lang":"en"}"#.into(),
            None,
            Default::default(),
        )
        .unwrap(),
    );
    let report = core.diag_report().expect("report");
    // Only facts reach the plugin: no body text in the report.
    assert!(!report.contains("SECRETBODY"), "{report}");
    let r: Value = serde_json::from_str(&report).unwrap();
    let keys: Vec<String> = r["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["key"].as_str())
        .filter(|k| k.starts_with("ENC-"))
        .map(String::from)
        .collect();
    let has = |prefix: &str, host: &str| {
        keys.iter()
            .any(|k| k.starts_with(prefix) && k.contains(host))
    };
    for (prefix, host) in [
        ("ENC-MISMATCH|response|not-utf8|", "mismatch.test"),
        ("ENC-MISMATCH|response|utf8|", "legacy.test"),
        ("ENC-CONFLICT|response|", "conflict.test"),
        ("ENC-DOUBLE|response|", "double.test"),
        ("ENC-MISSING|response|", "missing.test"),
        ("ENC-LOST|response|", "lost.test"),
        ("ENC-JSON|response|", "utf16.test"),
        ("ENC-UNKNOWN|response|", "unknown.test"),
        ("ENC-BINARY|response|", "binary.test"),
        ("ENC-DECODE|response|compressed|", "gz.test"),
        ("ENC-DECODE|request|invalid|", "upload.test"),
    ] {
        assert!(has(prefix, host), "{prefix}{host} missing in {keys:#?}");
    }
    // One report per problem, nothing for the clean host.
    assert_eq!(keys.len(), 11, "{keys:#?}");
    assert!(!keys.iter().any(|k| k.contains("clean.test")), "{keys:#?}");
    // The decoded request text with a leftover gzip header is not reported.
    let decode: Vec<_> = r["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| {
            f["key"]
                .as_str()
                .is_some_and(|k| k.starts_with("ENC-DECODE|request"))
        })
        .collect();
    assert_eq!(decode.len(), 1, "{decode:#?}");
    assert!(!decode[0]["sessions"].as_array().unwrap().is_empty());
    let critical = r["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| {
            f["key"]
                .as_str()
                .is_some_and(|k| k.contains("mismatch.test"))
        })
        .unwrap();
    assert_eq!(critical["severity"], "critical", "{critical:#}");
}
