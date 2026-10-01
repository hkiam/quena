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

/// Skip (with a note) when the plugins were not built (`plugins/build.sh`).
fn have_plugins() -> bool {
    let ok = plugins().join("webdiag/webdiag.wasm").is_file();
    if !ok {
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
