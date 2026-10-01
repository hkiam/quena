//! The `quena-cli` binary end to end: analysis, gate, baseline, outputs and exit codes.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_quena-cli"));
    c.env(
        "QUENA_CACHE_DIR",
        std::env::temp_dir().join("quena-cli-test-cache"),
    );
    c.env_remove("QUENA_PLUGIN_DIR");
    c
}

fn plugins() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../plugins/dist")
}

/// Skip (with a note) when the plugins were not built (`plugins/build.sh`); on CI (`CI` set)
/// fail instead, so that a pipeline cannot go green without running these tests.
fn have_plugins() -> bool {
    let ok = plugins().join("webdiag/webdiag.wasm").is_file();
    if !ok {
        assert!(
            std::env::var_os("CI").is_none(),
            "plugins/dist/webdiag missing on CI: run plugins/build.sh before the tests"
        );
        eprintln!("plugins/dist/webdiag missing: run plugins/build.sh");
    }
    ok
}

fn entry(i: usize, url: &str, status: u16, ms: f64) -> Value {
    let t = 1_790_000_000_000i64 + i as i64 * 50;
    let secs = t / 1000;
    let (h, m, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    let started = format!("2026-09-21T{h:02}:{m:02}:{s:02}.{:03}Z", t % 1000);
    json!({
        "startedDateTime": started, "time": ms,
        "request": {"method": "GET", "url": url, "httpVersion": "HTTP/1.1", "headers": [{"name": "Host", "value": "shop.example.com"}], "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0},
        "response": {"status": status, "statusText": "", "httpVersion": "HTTP/1.1", "headers": [{"name": "Content-Type", "value": "application/json"}], "cookies": [],
                     "content": {"size": 2, "mimeType": "application/json", "text": "{}"}, "redirectURL": "", "headersSize": -1, "bodySize": 2},
        "cache": {}, "timings": {"send": 1, "wait": ms - 2.0, "receive": 1}
    })
}

/// A capture with `n` item requests (N+1), and `errors` server errors of one endpoint.
fn har(dir: &Path, name: &str, n: usize, errors: usize) -> PathBuf {
    let mut e = vec![entry(0, "https://shop.example.com/api/items", 200, 40.0)];
    for i in 0..n {
        e.push(entry(
            e.len(),
            &format!("https://shop.example.com/api/items/{}", 1000 + i),
            200,
            30.0,
        ));
    }
    for _ in 0..errors {
        e.push(entry(
            e.len(),
            "https://shop.example.com/api/save",
            500,
            20.0,
        ));
    }
    let p = dir.join(name);
    std::fs::write(&p, json!({"log": {"version": "1.2", "creator": {"name": "test", "version": "1"}, "entries": e}}).to_string()).unwrap();
    p
}

fn run(args: &[&str]) -> Output {
    let mut c = bin();
    c.args(args);
    if args[0] == "diagnose" {
        c.args(["--plugins", plugins().to_str().unwrap()]);
    }
    c.output().unwrap()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn text(o: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn findings_decide_the_exit_code() {
    if !have_plugins() {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let h = har(d.path(), "a.har", 30, 25);
    let h = h.to_str().unwrap();
    let json = d.path().join("r.json");
    let o = run(&[
        "diagnose",
        h,
        "--fail-on",
        "warning",
        "-o",
        &format!("json={}", json.display()),
        "--format",
        "md",
    ]);
    assert_eq!(code(&o), 1, "{}", text(&o));
    let md = String::from_utf8_lossy(&o.stdout);
    assert!(md.starts_with("# ") || md.contains("Quality gate"), "{md}");
    let r: Value = serde_json::from_str(&std::fs::read_to_string(&json).unwrap()).unwrap();
    assert_eq!(r["schema"], 1);
    assert_eq!(r["gate"]["passed"], false);
    assert!(
        r["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == "ERR-HTTP"),
        "{r:#}"
    );
    let o = run(&[
        "diagnose",
        h,
        "--fail-on",
        "none",
        "--quiet",
        "--format",
        "json",
    ]);
    assert_eq!(code(&o), 0, "{}", text(&o));
    assert!(o.stderr.is_empty(), "{}", text(&o));
}

#[test]
fn a_baseline_fails_only_on_what_is_new_and_on_budgets() {
    if !have_plugins() {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let base = har(d.path(), "base.har", 30, 25);
    let base_json = d.path().join("base.json");
    let o = run(&[
        "diagnose",
        base.to_str().unwrap(),
        "--fail-on",
        "none",
        "-o",
        &format!("json={}", base_json.display()),
        "--quiet",
    ]);
    assert_eq!(code(&o), 0, "{}", text(&o));
    let b = base_json.to_str().unwrap();
    // The same capture again: the known findings do not break the gate …
    let o = run(&[
        "diagnose",
        base.to_str().unwrap(),
        "--baseline",
        b,
        "--fail-on",
        "warning",
    ]);
    assert_eq!(code(&o), 0, "{}", text(&o));
    // … unless asked to.
    let o = run(&[
        "diagnose",
        base.to_str().unwrap(),
        "--baseline",
        b,
        "--fail-on",
        "warning",
        "--fail-on-existing",
    ]);
    assert_eq!(code(&o), 1, "{}", text(&o));
    // The command line wins over the settings file, in both directions.
    let strict = d.path().join("strict.json");
    std::fs::write(&strict, r#"{"failOn":"warning","failOnExisting":true}"#).unwrap();
    let strict = strict.to_str().unwrap();
    let o = run(&[
        "diagnose",
        base.to_str().unwrap(),
        "--baseline",
        b,
        "--config",
        strict,
    ]);
    assert_eq!(code(&o), 1, "{}", text(&o));
    let o = run(&[
        "diagnose",
        base.to_str().unwrap(),
        "--baseline",
        b,
        "--config",
        strict,
        "--no-fail-on-existing",
    ]);
    assert_eq!(code(&o), 0, "{}", text(&o));
    // Many more requests than the baseline: the budget breaks it.
    let more = har(d.path(), "more.har", 60, 25);
    let o = run(&[
        "diagnose",
        more.to_str().unwrap(),
        "--baseline",
        b,
        "--fail-on",
        "none",
        "--budget",
        "requests=+10%",
        "--format",
        "junit",
    ]);
    assert_eq!(code(&o), 1, "{}", text(&o));
    let junit = String::from_utf8_lossy(&o.stdout);
    assert!(
        junit.starts_with("<?xml") && junit.contains("<testsuites") && junit.contains("<failure"),
        "{junit}"
    );
    // compare: two saved reports, no analysis.
    let more_json = d.path().join("more.json");
    run(&[
        "diagnose",
        more.to_str().unwrap(),
        "--fail-on",
        "none",
        "-o",
        &format!("json={}", more_json.display()),
        "--quiet",
    ]);
    let o = run(&[
        "compare",
        b,
        more_json.to_str().unwrap(),
        "--budget",
        "requests=+10%",
        "--fail-on",
        "none",
    ]);
    assert_eq!(code(&o), 1, "{}", text(&o));
}

#[test]
fn input_errors_exit_with_2() {
    let d = tempfile::tempdir().unwrap();
    let broken = d.path().join("broken.har");
    std::fs::write(&broken, "not json").unwrap();
    for args in [
        vec!["diagnose", "/no/such/file.har"],
        vec!["diagnose", broken.to_str().unwrap()],
        vec!["diagnose", broken.to_str().unwrap(), "--budget", "requests"],
        vec![
            "compare",
            broken.to_str().unwrap(),
            broken.to_str().unwrap(),
        ],
    ] {
        if args.len() == 2 && args[1] == broken.to_str().unwrap() && !have_plugins() {
            continue;
        }
        let o = run(&args);
        assert_eq!(code(&o), 2, "{args:?}: {}", text(&o));
    }
}

/// A saved report as `diagnose -o json=…` writes it (only what the tests need).
fn saved(dir: &Path, name: &str, lang: &str, requests: f64) -> String {
    let p = dir.join(name);
    std::fs::write(
        &p,
        json!({
            "schema": 1, "lang": lang,
            "summary": { "critical": 0, "warning": 0, "info": 0 },
            "metrics": [
                { "key": "requests", "label": "HTTP requests", "value": requests, "unit": "count" },
                { "key": "errors", "label": "Errors", "value": 0, "unit": "count" }
            ],
            "findings": []
        })
        .to_string(),
    )
    .unwrap();
    p.to_str().unwrap().to_string()
}

#[test]
fn help_and_version() {
    for arg in ["--help", "--version"] {
        let o = bin().arg(arg).output().unwrap();
        assert_eq!(code(&o), 0, "{arg}: {}", text(&o));
        assert!(!o.stdout.is_empty());
    }
    let help = bin().args(["diagnose", "--help"]).output().unwrap();
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(
        help.contains("--no-fail-on-existing") && help.contains("whole run"),
        "{help}"
    );
}

#[test]
fn compare_budgets_boundary_and_typos() {
    let d = tempfile::tempdir().unwrap();
    let (a, b) = (
        saved(d.path(), "a.json", "en", 100.0),
        saved(d.path(), "b.json", "en", 115.0),
    );
    let o = run(&[
        "compare",
        &a,
        &b,
        "--budget",
        "requests=+15%",
        "--format",
        "none",
    ]);
    assert_eq!(code(&o), 0, "{}", text(&o));
    let o = run(&[
        "compare",
        &a,
        &b,
        "--budget",
        "requests=+14.9%",
        "--format",
        "none",
    ]);
    assert_eq!(code(&o), 1, "{}", text(&o));
    // A budget on a metric the report does not have: a configuration error.
    let o = run(&["compare", &a, &b, "--budget", "reqests=+10%"]);
    assert_eq!(code(&o), 2, "{}", text(&o));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("\"reqests\"") && err.contains("requests, errors"),
        "{err}"
    );
    assert!(o.stdout.is_empty(), "{}", text(&o));
    // Metrics reported only when they apply are no typo.
    let o = run(&[
        "compare",
        &a,
        &b,
        "--budget",
        "open=0",
        "--budget",
        "rate=+10%",
    ]);
    assert_eq!(code(&o), 0, "{}", text(&o));
}

/// One settings file for `diagnose` and `compare`: compare ignores the analysis keys.
#[test]
fn compare_takes_the_diagnose_settings_file() {
    let d = tempfile::tempdir().unwrap();
    let (a, b) = (
        saved(d.path(), "a.json", "en", 100.0),
        saved(d.path(), "b.json", "en", 200.0),
    );
    let cfg = d.path().join("quena.json");
    std::fs::write(&cfg, r#"{"profile":"performance","lang":"de","options":{"slowMs":1500},"hosts":["*.example.com"],"processes":["x"],"failOn":"warning","budgets":["requests=+10%"]}"#).unwrap();
    let o = run(&[
        "compare",
        &a,
        &b,
        "--config",
        cfg.to_str().unwrap(),
        "--format",
        "md",
    ]);
    assert_eq!(code(&o), 1, "{}", text(&o));
    // The frame language comes from the report, not from the settings file.
    assert!(
        String::from_utf8_lossy(&o.stdout).contains("Quality gate: FAILED"),
        "{}",
        text(&o)
    );
}

/// `compare` takes the language of the new report, also as a locale, and never fails on it.
#[test]
fn compare_language_from_the_report() {
    let d = tempfile::tempdir().unwrap();
    for (lang, expect) in [
        ("de-DE", "Quality Gate: bestanden"),
        ("fr", "Quality gate: passed"),
        ("", "Quality gate: passed"),
    ] {
        let a = saved(d.path(), "a.json", lang, 1.0);
        let o = run(&["compare", &a, &a]);
        assert_eq!(code(&o), 0, "{lang}: {}", text(&o));
        assert!(
            String::from_utf8_lossy(&o.stdout).contains(expect),
            "{lang}: {}",
            text(&o)
        );
    }
    let a = saved(d.path(), "a.json", "de", 1.0);
    let o = run(&["compare", &a, &a, "--lang", "en"]);
    assert!(String::from_utf8_lossy(&o.stdout).contains("Quality gate: passed"));
}

/// Mistakes found before the analysis: exit 2, nothing on stdout.
#[test]
fn usage_errors_before_the_analysis() {
    let d = tempfile::tempdir().unwrap();
    let h = har(d.path(), "a.har", 3, 0);
    let h = h.to_str().unwrap();
    let report = saved(d.path(), "r.json", "en", 1.0);
    let missing = d.path().join("no/such/dir/out.json");
    let bad_o = format!("json={}", missing.display());
    let into_dir = format!("md={}", d.path().display());
    let twice = d.path().join(".").join("a.har");
    for args in [
        vec!["diagnose", h, twice.to_str().unwrap()],
        vec!["diagnose", h, h],
        vec!["diagnose", h, "--set", "lang=de"],
        vec!["diagnose", h, "--set", "profile=auth"],
        vec!["diagnose", h, "-o", &bad_o],
        vec!["diagnose", h, "-o", &into_dir],
        vec!["compare", &report, &report, "-o", &bad_o],
    ] {
        let o = run(&args);
        assert_eq!(code(&o), 2, "{args:?}: {}", text(&o));
        assert!(o.stdout.is_empty(), "{args:?}: {}", text(&o));
    }
    assert!(!missing.exists());
    let o = run(&["diagnose", h, h]);
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("given twice"),
        "{}",
        text(&o)
    );
    let o = run(&["diagnose", h, "--set", "lang=de"]);
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("--lang"),
        "{}",
        text(&o)
    );
}

/// A relative budget without a baseline (the run that makes the first one) is skipped; a
/// typo in a budget is a configuration error naming the metrics; a huge --timeout is fine.
#[test]
fn diagnose_budgets_without_baseline() {
    if !have_plugins() {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let h = har(d.path(), "a.har", 30, 2);
    let h = h.to_str().unwrap();
    let o = run(&[
        "diagnose",
        h,
        "--fail-on",
        "none",
        "--budget",
        "requests=+10%",
        "--timeout",
        "18446744073709551615",
    ]);
    assert_eq!(code(&o), 0, "{}", text(&o));
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("skipped: no baseline"),
        "{}",
        text(&o)
    );
    let o = run(&["diagnose", h, "--fail-on", "none", "--budget", "reqests=0"]);
    assert_eq!(code(&o), 2, "{}", text(&o));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("\"reqests\"") && err.contains("requests"),
        "{err}"
    );
    assert!(o.stdout.is_empty(), "{}", text(&o));
}

/// `--plugins` is the only folder searched, also when QUENA_PLUGIN_DIR is set.
#[test]
fn plugins_option_beats_the_environment() {
    if !have_plugins() {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let empty = tempfile::tempdir().unwrap();
    let h = har(d.path(), "a.har", 3, 0);
    let o = bin()
        .env("QUENA_PLUGIN_DIR", empty.path())
        .args([
            "diagnose",
            h.to_str().unwrap(),
            "--fail-on",
            "none",
            "--format",
            "none",
        ])
        .args(["--plugins", plugins().to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(code(&o), 0, "{}", text(&o));
    // Only the empty folder: missing, named in the message.
    let o = bin()
        .args([
            "diagnose",
            h.to_str().unwrap(),
            "--plugins",
            empty.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(code(&o), 2, "{}", text(&o));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("missing in") && err.contains(&*empty.path().to_string_lossy()),
        "{err}"
    );
}

/// A diagnostics plugin that is there but does not load: an analysis error (3) with the
/// reason; an empty scope is an input error (2).
#[test]
fn broken_plugin_and_empty_scope() {
    if !have_plugins() {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let h = har(d.path(), "a.har", 3, 0);
    let broken = d.path().join("plugins/webdiag");
    std::fs::create_dir_all(&broken).unwrap();
    std::fs::copy(
        plugins().join("webdiag/plugin.toml"),
        broken.join("plugin.toml"),
    )
    .unwrap();
    std::fs::write(broken.join("webdiag.wasm"), b"not wasm").unwrap();
    let o = bin()
        .args(["diagnose", h.to_str().unwrap(), "--plugins"])
        .arg(d.path().join("plugins"))
        .output()
        .unwrap();
    assert_eq!(code(&o), 3, "{}", text(&o));
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("failed to load"),
        "{}",
        text(&o)
    );

    let o = run(&["diagnose", h.to_str().unwrap(), "--host", "nowhere.invalid"]);
    assert_eq!(code(&o), 2, "{}", text(&o));
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("no sessions"),
        "{}",
        text(&o)
    );
}

#[test]
fn sanitize_removes_secrets_and_writes_a_log() {
    let d = tempfile::tempdir().unwrap();
    let mut e = entry(0, "https://shop.example.com/api/login?access_token=SECRET-TOKEN-1&page=2", 200, 30.0);
    e["request"]["headers"] = json!([{"name": "Cookie", "value": "sid=SECRET-COOKIE-1"}, {"name": "Authorization", "value": "Bearer SECRET-BEARER-1"}]);
    e["response"]["content"]["text"] = json!(r#"{"email":"secret.person@example.com","name":"Erika Mustermann"}"#);
    let input = d.path().join("in.har");
    std::fs::write(&input, json!({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": [e]}}).to_string()).unwrap();
    let out = d.path().join("out.har");
    let log = d.path().join("log.json");
    let o = run(&["sanitize", input.to_str().unwrap(), "-o", out.to_str().unwrap(), "--preset", "gdpr", "--log", log.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "{}", text(&o));
    let har = std::fs::read_to_string(&out).unwrap();
    for marker in ["SECRET-TOKEN-1", "SECRET-COOKIE-1", "SECRET-BEARER-1", "secret.person@example.com", "Erika Mustermann"] {
        assert!(!har.contains(marker), "{marker} left in {har}");
    }
    assert!(har.contains("page=2"), "{har}");
    let log: Value = serde_json::from_str(&std::fs::read_to_string(&log).unwrap()).unwrap();
    assert!(log["total"].as_u64().unwrap() >= 5, "{log:#}");
    // Wrong output type and unknown preset are input errors.
    assert_eq!(code(&run(&["sanitize", input.to_str().unwrap(), "-o", d.path().join("x.txt").to_str().unwrap()])), 2);
    assert_eq!(code(&run(&["sanitize", input.to_str().unwrap(), "-o", out.to_str().unwrap(), "--preset", "lax"])), 2);
}

#[test]
fn mock_writes_wiremock_and_a_package() {
    let d = tempfile::tempdir().unwrap();
    let input = har(d.path(), "a.har", 3, 1);
    let wm = d.path().join("wiremock");
    let pkg = d.path().join("shop.quena-mocks");
    let o = run(&["mock", input.to_str().unwrap(), "--wiremock", wm.to_str().unwrap(), "--package", pkg.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "{}", text(&o));
    let mappings: Vec<_> = std::fs::read_dir(wm.join("mappings")).unwrap().flatten().collect();
    assert!(mappings.len() >= 4, "{mappings:?}");
    let m: Value = serde_json::from_str(&std::fs::read_to_string(mappings[0].path()).unwrap()).unwrap();
    assert!(m["request"]["method"].is_string() && m["response"]["status"].is_number(), "{m:#}");
    assert!(pkg.is_file());
    // Neither target given: clap rejects it (exit 2).
    assert_eq!(code(&run(&["mock", input.to_str().unwrap()])), 2);
}
