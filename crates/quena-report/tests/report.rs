use quena_report::gate::{GateConfig, Limit, evaluate, parse_budget};
use quena_report::{
    Lang, MdOptions, MetricValue, Report, Severity, compare, normalize, parse, to_github, to_json,
    to_junit, to_markdown,
};
use serde_json::{Value, json};

fn sample() -> Value {
    json!({
        "schema": 1,
        "tool": { "id": "io.github.hkiam.webdiag", "version": "0.1.0" },
        "profile": { "id": "performance", "name": "Performance" },
        "range": { "from": 1727690000000000u64, "to": 1727690060000000u64, "sessions": 10 },
        "summary": { "critical": 1, "warning": 1, "info": 0, "headline": ["Sequential API communication adds latency."] },
        "metrics": [
            { "key": "requests", "label": "HTTP requests", "value": 100, "unit": "count" },
            { "key": "bytes", "label": "Transferred", "value": 2048, "unit": "bytes" },
            { "key": "errors", "label": "Errors", "value": 0, "unit": "count" },
            { "key": "server", "label": "Server", "value": "nginx", "unit": "text" }
        ],
        "findings": [
            { "id": "INFO-X", "key": "INFO-X|a", "title": "Info thing", "severity": "warning", "score": 10 },
            {
                "id": "PERF-SEQ", "key": "PERF-SEQ|op-3", "title": "Latency | chain", "severity": "critical", "confidence": "high",
                "categories": ["performance"], "score": 72, "observation": "42 requests ran one after another.",
                "recommendations": ["Parallelise."], "facts": [{ "label": "Levels", "value": "42" }]
            },
            { "id": "OAUTH-FLOW", "key": "OAUTH-FLOW|idp", "title": "OAuth", "severity": "critical", "score": 5, "categories": ["auth"] }
        ],
        "generatedAt": 1727690070000000u64
    })
}

fn report(v: &Value) -> Report {
    normalize(v).unwrap()
}

fn with(mut v: Value, f: impl FnOnce(&mut Value)) -> Report {
    f(&mut v);
    report(&v)
}

fn keys(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

#[test]
fn normalizes_with_defaults_and_sorts_findings() {
    let r = report(&sample());
    assert_eq!(
        r.findings.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
        ["PERF-SEQ", "OAUTH-FLOW", "INFO-X"]
    );
    assert_eq!(r.findings[2].confidence, "medium");
    assert!(r.findings[2].sessions.is_empty());
    assert_eq!(r.scope, None);

    let r = report(
        &json!({ "schema": 1, "findings": [{ "severity": "bogus" }, null, { "title": 5 }] }),
    );
    assert_eq!(r.findings.len(), 3);
    assert!(r.findings.iter().all(|f| f.severity == Severity::Info));
    assert_eq!(r.findings[1].id, "F2");
    assert_eq!(r.findings[2].title, "5");
    assert_eq!(r.summary.info, 3);
    assert!(r.metrics.is_empty());
    assert!(normalize(&json!({ "schema": 2 })).is_none());
    assert!(normalize(&json!([])).is_none());
    assert!(parse("not json").unwrap_err().starts_with("not JSON"));
    assert_eq!(
        parse(r#"{"schema": 3}"#).unwrap_err(),
        "not a schema 1 diagnostics report"
    );

    let r = report(
        &json!({ "schema": 1, "summary": { "warning": -5, "critical": 1.7, "info": "x" }, "findings": [{ "id": "A", "severity": "warning" }],
        "scope": { "kind": "visible", "sessions": 3, "processes": ["chrome", 1] }, "metrics": [{ "key": "t", "value": "x" }, { "value": 1 }] }),
    );
    assert_eq!(
        (r.summary.critical, r.summary.warning, r.summary.info),
        (1, 1, 0)
    );
    assert_eq!(r.scope.unwrap().processes, ["chrome", "1"]);
    assert_eq!(r.metrics.len(), 1);
    assert_eq!(
        (r.metrics[0].label.as_str(), r.metrics[0].unit.as_str()),
        ("t", "text")
    );
}

#[test]
fn serializes_like_the_ui() {
    let r = report(&sample());
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(v["generatedAt"], json!(1727690070000000u64));
    assert_eq!(v["findings"][0]["nextSteps"], json!([]));
    assert_eq!(v["findings"][0]["score"], json!(72));
    assert_eq!(v["metrics"][0]["value"], json!(100));
    assert_eq!(v["scope"], Value::Null);
}

#[test]
fn severity_order_and_parsing() {
    assert!(Severity::Critical > Severity::Warning && Severity::Warning > Severity::Info);
    assert_eq!("warning".parse::<Severity>(), Ok(Severity::Warning));
    assert!("fatal".parse::<Severity>().is_err());
    assert_eq!(
        serde_json::to_value(Severity::Critical).unwrap(),
        json!("critical")
    );
    assert_eq!("de".parse::<Lang>(), Ok(Lang::De));
    assert!("fr".parse::<Lang>().is_err());
}

#[test]
fn budgets_parse() {
    let b = parse_budget("requests=+10%").unwrap();
    assert_eq!(
        (b.key.as_str(), b.limit),
        ("requests", Limit::RelativePct(10.0))
    );
    assert_eq!(
        parse_budget(" errors = 0 ").unwrap().limit,
        Limit::Absolute(0.0)
    );
    assert_eq!(
        parse_budget("bytes=5242880").unwrap().to_string(),
        "bytes=5242880"
    );
    assert_eq!(
        parse_budget("requests=+10%").unwrap().to_string(),
        "requests=+10%"
    );
    for bad in [
        "requests",
        "=5",
        "requests=",
        "requests=abc",
        "requests=x%",
        "requests=inf",
    ] {
        assert!(parse_budget(bad).is_err(), "{bad}");
    }
}

#[test]
fn gate_config_from_json() {
    let cfg = GateConfig::from_json(r#"{"failOn":"warning","failOnExisting":true,"budgets":["requests=+10%"],"ignore":["OAUTH-FLOW"]}"#).unwrap();
    assert_eq!(cfg.fail_on, Some(Severity::Warning));
    assert!(cfg.fail_on_existing);
    assert_eq!(cfg.budgets.len(), 1);
    assert_eq!(cfg.ignore, ["OAUTH-FLOW"]);
    assert_eq!(
        GateConfig::from_json(r#"{"failOn":"none"}"#)
            .unwrap()
            .fail_on,
        None
    );
    let e = GateConfig::from_json(r#"{"failOn":"critical","fail_on":"x"}"#).unwrap_err();
    assert!(e.contains("\"fail_on\""), "{e}");
    assert!(GateConfig::from_json(r#"{"budgets":["x"]}"#).is_err());
    assert!(GateConfig::from_json(r#"{"failOn":"fatal"}"#).is_err());
    assert!(GateConfig::from_json(r#"{"ignore":"A"}"#).is_err());
    assert!(GateConfig::from_json("[]").is_err());
}

fn cfg(fail_on: Option<Severity>) -> GateConfig {
    GateConfig {
        fail_on,
        ..GateConfig::default()
    }
}

#[test]
fn gate_without_baseline() {
    let r = report(&sample());
    let g = evaluate(&r, None, &cfg(Some(Severity::Critical)), Lang::En);
    assert!(!g.passed);
    assert_eq!(keys(&g.failing), ["PERF-SEQ|op-3", "OAUTH-FLOW|idp"]);
    assert_eq!(g.reasons, ["2 findings at Critical or above."]);
    let g = evaluate(&r, None, &cfg(Some(Severity::Warning)), Lang::En);
    assert_eq!(g.failing.len(), 3);
    let g = evaluate(&r, None, &cfg(None), Lang::En);
    assert!(g.passed && g.failing.is_empty());

    // Ignored by rule id and by exact key.
    let ignore = GateConfig {
        ignore: vec!["OAUTH-FLOW".into(), "PERF-SEQ|op-3".into()],
        ..cfg(Some(Severity::Critical))
    };
    let g = evaluate(&r, None, &ignore, Lang::De);
    assert!(g.passed);
    assert_eq!(
        g.reasons,
        [
            "Keine Befunde ab Schweregrad Kritisch.",
            "2 Befunde per Konfiguration ignoriert."
        ]
    );
}

#[test]
fn gate_with_baseline_fails_on_new_and_worsened_only() {
    let base = report(&sample());
    let cur = with(sample(), |v| {
        let f = v["findings"].as_array_mut().unwrap();
        f[0]["severity"] = json!("critical"); // INFO-X: warning → critical (worse)
        f[1]["severity"] = json!("warning"); // PERF-SEQ: critical → warning (better)
        f.push(json!({ "id": "NEW", "key": "NEW|1", "title": "New", "severity": "critical" }));
        f.push(json!({ "id": "NEW-INFO", "title": "New info", "severity": "info" }));
    });
    let c = compare(&base, &cur);
    let crit = cfg(Some(Severity::Critical));
    let g = evaluate(&cur, Some((&base, &c)), &crit, Lang::En);
    assert_eq!(keys(&g.failing), ["INFO-X|a", "NEW|1"]);
    assert_eq!(
        g.reasons,
        ["2 new or worsened findings at Critical or above."]
    );

    // The existing critical OAUTH-FLOW fails as soon as existing findings count.
    let all = GateConfig {
        fail_on_existing: true,
        ..crit.clone()
    };
    let g = evaluate(&cur, Some((&base, &c)), &all, Lang::En);
    assert_eq!(keys(&g.failing), ["INFO-X|a", "OAUTH-FLOW|idp", "NEW|1"]);

    // Changed to better never fails, and info is below the threshold.
    let g = evaluate(
        &cur,
        Some((&base, &c)),
        &cfg(Some(Severity::Info)),
        Lang::En,
    );
    assert_eq!(keys(&g.failing), ["INFO-X|a", "NEW|1", "NEW-INFO"]);

    let ignore = GateConfig {
        ignore: vec!["NEW".into(), "INFO-X|a".into()],
        ..crit
    };
    assert!(evaluate(&cur, Some((&base, &c)), &ignore, Lang::En).passed);

    let same = compare(&base, &base);
    assert!(
        evaluate(
            &base,
            Some((&base, &same)),
            &cfg(Some(Severity::Info)),
            Lang::En
        )
        .passed
    );
}

#[test]
fn gate_budgets() {
    let base = report(&sample());
    let cur = with(sample(), |v| {
        v["metrics"][0]["value"] = json!(111);
        v["metrics"][1]["value"] = json!(2252);
        v["metrics"][2]["value"] = json!(1);
    });
    let c = compare(&base, &cur);
    let budgets = |list: &[&str]| GateConfig {
        budgets: list.iter().map(|b| parse_budget(b).unwrap()).collect(),
        ..GateConfig::default()
    };

    let g = evaluate(
        &cur,
        Some((&base, &c)),
        &budgets(&["requests=+10%", "bytes=+10%", "errors=0", "errors=1"]),
        Lang::En,
    );
    let passed: Vec<bool> = g.budgets.iter().map(|b| b.passed).collect();
    assert_eq!(passed, [false, true, false, true]);
    assert!(!g.passed);
    let r = &g.budgets[0];
    assert_eq!(
        (r.label.as_str(), r.baseline, r.value),
        ("HTTP requests", Some(100.0), Some(111.0))
    );
    assert_eq!(r.limit_text, "≤ baseline +10 %");
    assert_eq!(r.reason, "111 > 110 (baseline 100 +10 %)");
    assert_eq!(
        g.budgets[1].reason,
        "2.20 KB ≤ 2.20 KB (baseline 2.00 KB +10 %)"
    );
    assert_eq!(g.budgets[2].limit_text, "≤ 0");
    assert_eq!(
        g.reasons[1],
        "Budget requests: 111 > 110 (baseline 100 +10 %)"
    );

    // Base 0: any increase fails.
    let zero = with(sample(), |v| v["metrics"][2]["value"] = json!(0));
    let g = evaluate(
        &cur,
        Some((&zero, &compare(&zero, &cur))),
        &budgets(&["errors=+50%"]),
        Lang::En,
    );
    assert!(!g.passed);
    let g = evaluate(
        &zero,
        Some((&zero, &compare(&zero, &zero))),
        &budgets(&["errors=+50%"]),
        Lang::En,
    );
    assert!(g.passed);

    // Usage problems fail too, so that CI notices.
    let g = evaluate(
        &cur,
        None,
        &budgets(&["requests=+10%", "nope=1", "server=1"]),
        Lang::En,
    );
    assert_eq!(
        g.budgets
            .iter()
            .map(|b| b.reason.as_str())
            .collect::<Vec<_>>(),
        [
            "needs --baseline",
            "metric not in report",
            "metric is not numeric"
        ]
    );
    assert!(g.budgets.iter().all(|b| !b.passed));
    let bare = with(sample(), |v| v["metrics"] = json!([]));
    let g = evaluate(
        &cur,
        Some((&bare, &compare(&bare, &cur))),
        &budgets(&["requests=+10%"]),
        Lang::De,
    );
    assert_eq!(g.budgets[0].reason, "Kennzahl nicht in der Baseline");
    assert!(!g.passed);

    let v = serde_json::to_value(&g).unwrap();
    assert_eq!(v["budgets"][0]["limitText"], json!("≤ Baseline +10 %"));
    assert_eq!(v["budgets"][0]["value"], json!(111));
}

#[test]
fn markdown_keeps_traffic_texts_inert() {
    let r = report(&json!({
        "schema": 1,
        "findings": [{
            "id": "A", "title": "Slow\n# injected heading", "severity": "warning",
            "observation": "line1\n\n## Fake section", "hypotheses": ["one\n### two"],
            "table": { "columns": ["Path", "x"], "rows": [["/a\\|b", "c\\"], ["`/x", "<img src=x>"]] }
        }, {
            "id": "B", "title": "- item", "severity": "info", "observation": "1. first", "recommendations": ["`/x` *b* _i_ [l](u) a|b ~s~ c\\", "+ plus", "> quote", "= eq", "12) twelve"]
        }]
    }));
    let md = to_markdown(&r, None, None, Lang::En, &MdOptions::default());
    assert!(md.contains("### [Warning] Slow # injected heading (A)"));
    assert!(md.contains("**Observation:** line1 ## Fake section"));
    let headings: Vec<&str> = md.lines().filter(|l| l.starts_with('#')).collect();
    assert_eq!(
        headings,
        [
            "# Diagnostics report",
            "## Summary",
            "## Findings",
            "### [Warning] Slow # injected heading (A)",
            "### [Info] \\- item (B)"
        ]
    );
    assert!(md.contains("- one ### two"));
    assert!(md.contains("| /a\\\\\\|b | c\\\\ |"));
    assert!(md.contains("| \\`/x | \\<img src=x\\> |"));
    assert!(md.contains("**Observation:** 1\\. first"));
    assert!(md.contains("- \\`/x\\` \\*b\\* \\_i\\_ \\[l\\](u) a\\|b \\~s\\~ c\\\\\n- \\+ plus\n- \\> quote\n- \\= eq\n- 12\\) twelve"));
    assert!(!md.contains("<img") || md.matches("<img").count() == md.matches("\\<img").count());
}

#[test]
fn markdown_with_gate_and_comparison() {
    let base = report(&sample());
    let cur = with(sample(), |v| {
        v["metrics"][0]["value"] = json!(80);
        v["metrics"][1]["value"] = json!(4096);
        v["summary"]["critical"] = json!(2);
        v["findings"].as_array_mut().unwrap().push(
            json!({ "id": "NEW", "key": "NEW|1", "title": "New *one*", "severity": "critical" }),
        );
        v["findings"][0]["severity"] = json!("info");
    });
    let c = compare(&base, &cur);
    let gate = GateConfig {
        fail_on: Some(Severity::Critical),
        budgets: vec![parse_budget("requests=+10%").unwrap()],
        ..GateConfig::default()
    };
    let g = evaluate(&cur, Some((&base, &c)), &gate, Lang::En);
    let md = to_markdown(&cur, Some(&c), Some(&g), Lang::En, &MdOptions::default());
    assert!(md.starts_with("**Quality gate: FAILED ❌**\n\n- 1 new or worsened finding at Critical or above.\n\n| Budget | Value | Limit | Baseline | Result |\n| --- | --- | --- | --- | --- |\n| HTTP requests | 80 | ≤ baseline +10 % | 100 | ✅ |\n\n# Diagnostics report: Performance"), "{md}");
    assert!(
        md.contains(
            "## Comparison with baseline\n\n| Severity | Before | After | Change | Trend |"
        )
    );
    assert!(md.contains("| Critical | 1 | 2 | ▲ +1 | worse |"));
    assert!(md.contains("| Warning | 1 | 1 | ±0 | unchanged |"));
    assert!(md.contains("| HTTP requests | 100 | 80 | ▼ −20 | better |"));
    assert!(md.contains("| Transferred | 2\\.00 KB | 4\\.00 KB | ▲ +2.00 KB | worse |"));
    assert!(md.contains("| Server | nginx | nginx |  | unchanged |"));
    assert!(md.contains("**New findings (1):**\n\n- ❌ \\[Critical\\] New \\*one\\* (NEW)"));
    assert!(md.contains("**Changed severity (1):**\n\n- \\[Warning → Info\\] Info thing (INFO-X)"));
    assert!(md.contains("**Resolved findings (0):**\n\n- None"));
    assert!(md.contains("2 findings unchanged."));
    assert!(md.contains("### ❌ [Critical] New \\*one\\* (NEW)"));
    assert!(md.contains("### [Critical] Latency \\| chain (PERF-SEQ)"));
    assert!(md.contains("- Time range: 2024-09-30 09:53:20 UTC – 2024-09-30 09:54:20 UTC"));

    let g = evaluate(&cur, Some((&base, &c)), &gate, Lang::De);
    let de = to_markdown(&cur, Some(&c), Some(&g), Lang::De, &MdOptions::default());
    assert!(de.starts_with("**Qualitätsschranke: NICHT bestanden ❌**\n\n- 1 neuer oder verschlechterter Befund ab Schweregrad Kritisch."));
    assert!(de.contains(
        "## Vergleich mit der Baseline\n\n| Schweregrad | Vorher | Nachher | Änderung | Tendenz |"
    ));
    assert!(de.contains("| Kritisch | 1 | 2 | ▲ +1 | schlechter |"));
    assert!(de.contains("| Transferred | 2,00 KB | 4,00 KB | ▲ +2,00 KB | schlechter |"));
    assert!(de.contains("**Neue Befunde (1):**"));
    assert!(de.contains("2 Befunde unverändert."));
    assert!(de.contains("## Zusammenfassung\n\nKritisch: 2 · Warnung: 1 · Hinweis: 0"));

    let passed = evaluate(&base, None, &GateConfig::default(), Lang::En);
    assert!(
        to_markdown(&base, None, Some(&passed), Lang::En, &MdOptions::default())
            .starts_with("**Quality gate: passed ✅**\n\n- Findings do not fail the gate.\n\n# ")
    );
}

#[test]
fn junit_is_well_formed() {
    let r = with(sample(), |v| {
        v["findings"][1]["title"] = json!("<Latency> & \"chain\" 'x'");
        v["findings"][1]["observation"] = json!("a < b && c\u{1}\u{7}d\nnext");
    });
    let g = evaluate(
        &r,
        None,
        &GateConfig {
            fail_on: Some(Severity::Critical),
            budgets: vec![
                parse_budget("errors=0").unwrap(),
                parse_budget("requests=50").unwrap(),
            ],
            ..GateConfig::default()
        },
        Lang::En,
    );
    let x = to_junit(&r, &g, Lang::En);
    assert!(x.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites name=\"Quena diagnostics\" tests=\"5\" failures=\"3\" errors=\"0\">"), "{x}");
    assert!(x.contains("<testsuite name=\"performance\" tests=\"1\" failures=\"1\" errors=\"0\">"));
    assert!(x.contains("<testsuite name=\"auth\" tests=\"1\" failures=\"1\" errors=\"0\">"));
    assert!(x.contains("<testsuite name=\"general\" tests=\"1\" failures=\"0\" errors=\"0\">"));
    assert!(x.contains("<testsuite name=\"budgets\" tests=\"2\" failures=\"1\" errors=\"0\">"));
    assert!(x.contains("<testcase classname=\"quena.PERF-SEQ\" name=\"&lt;Latency&gt; &amp; &quot;chain&quot; &apos;x&apos;\">"));
    assert!(x.contains("<failure message=\"a &lt; b &amp;&amp; cd&#10;next\" type=\"critical\">Observation: a &lt; b &amp;&amp; cd\nnext\nLevels: 42\nRecommendations:\n- Parallelise.</failure>"));
    assert!(x.contains("<testcase classname=\"quena.INFO-X\" name=\"Info thing\"/>"));
    assert!(x.contains("<testcase classname=\"quena.budget.requests\" name=\"HTTP requests ≤ 50\">\n      <failure message=\"100 &gt; 50\" type=\"budget\">"));
    assert!(!x.chars().any(|c| (c as u32) < 0x20 && c != '\n'));
    assert_eq!(x.matches("<testcase ").count(), 5);
    assert_eq!(x.matches("<failure ").count(), 3);
    assert_eq!(
        x.matches("<testsuite ").count(),
        x.matches("</testsuite>").count()
    );
}

#[test]
fn github_annotations() {
    let r = with(sample(), |v| {
        v["findings"][1]["title"] = json!("Chain: a, b");
        v["findings"][1]["observation"] = json!("100% sequential\r\nnext");
    });
    let g = evaluate(
        &r,
        None,
        &GateConfig {
            fail_on: Some(Severity::Critical),
            ignore: vec!["OAUTH-FLOW".into()],
            budgets: vec![parse_budget("requests=50").unwrap()],
            ..GateConfig::default()
        },
        Lang::En,
    );
    let out = to_github(&r, &g);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines,
        [
            "::error title=PERF-SEQ%3A Chain%3A a%2C b::100%25 sequential%0D%0Anext",
            "::warning title=OAUTH-FLOW%3A OAuth::OAuth",
            "::warning title=INFO-X%3A Info thing::Info thing",
            "::error title=Budget requests::HTTP requests ≤ 50: 100 > 50",
        ]
    );
}

#[test]
fn json_adds_comparison_and_gate() {
    let raw = sample();
    let r = report(&raw);
    let c = compare(&r, &r);
    let g = evaluate(&r, Some((&r, &c)), &GateConfig::default(), Lang::En);
    let v: Value = serde_json::from_str(&to_json(&raw, Some(&c), Some(&g))).unwrap();
    assert_eq!(v["unchanged"], Value::Null);
    assert_eq!(v["comparison"]["unchanged"], json!(3));
    assert_eq!(v["gate"]["passed"], json!(true));
    assert_eq!(v["findings"], raw["findings"]);
    let plain: Value = serde_json::from_str(&to_json(&raw, None, None)).unwrap();
    assert_eq!(plain, raw);
    assert_eq!(MetricValue::Number(1.0).as_f64(), Some(1.0));
}
