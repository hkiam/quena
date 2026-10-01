//! JUnit XML for CI test reports: one test case per finding and per budget.

use crate::gate::{BudgetResult, GateResult};
use crate::i18n::t;
use crate::{Finding, Lang, Report};
use std::fmt::Write;

/// Text or attribute value as XML; characters XML 1.0 does not allow are dropped.
fn xml(s: &str, attr: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\n' if attr => out.push_str("&#10;"),
            '\r' if attr => out.push_str("&#13;"),
            '\t' if attr => out.push_str("&#9;"),
            '\t' | '\n' | '\r' => out.push(c),
            c if (c as u32) < 0x20 || c == '\u{fffe}' || c == '\u{ffff}' => {}
            c => out.push(c),
        }
    }
    out
}

fn attr(s: &str) -> String {
    xml(s, true)
}

fn text(s: &str) -> String {
    xml(s, false)
}

/// Observation, facts and recommendations of a finding as plain text.
fn details(f: &Finding, lang: Lang) -> String {
    let mut out = Vec::new();
    if !f.observation.is_empty() {
        out.push(format!("{}: {}", t(lang, "Observation"), f.observation));
    }
    for x in &f.facts {
        out.push(format!("{}: {}", x.label, x.value));
    }
    if !f.impact.is_empty() {
        out.push(format!("{}: {}", t(lang, "Impact"), f.impact));
    }
    if !f.recommendations.is_empty() {
        out.push(format!("{}:", t(lang, "Recommendations")));
        out.extend(f.recommendations.iter().map(|r| format!("- {r}")));
    }
    out.join("\n")
}

struct Suite<'a> {
    name: &'a str,
    findings: Vec<&'a Finding>,
}

/// The report as JUnit XML: a test suite per (first) finding category, failures for the
/// findings that fail the gate, and a suite `budgets` with a test case per budget.
pub fn to_junit(r: &Report, gate: &GateResult, lang: Lang) -> String {
    let mut suites: Vec<Suite> = Vec::new();
    for f in &r.findings {
        let name = f.categories.first().map_or("general", String::as_str);
        match suites.iter_mut().find(|s| s.name == name) {
            Some(s) => s.findings.push(f),
            None => suites.push(Suite {
                name,
                findings: vec![f],
            }),
        }
    }
    let failures = r.findings.iter().filter(|f| gate.is_failing(f)).count()
        + gate.budgets.iter().filter(|b| !b.passed).count();
    let tests = r.findings.len() + gate.budgets.len();
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let _ = writeln!(
        out,
        "<testsuites name=\"Quena diagnostics\" tests=\"{tests}\" failures=\"{failures}\" errors=\"0\">"
    );
    for s in &suites {
        let failed = s.findings.iter().filter(|f| gate.is_failing(f)).count();
        let _ = writeln!(
            out,
            "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{failed}\" errors=\"0\">",
            attr(s.name),
            s.findings.len()
        );
        for f in &s.findings {
            finding_case(&mut out, f, gate.is_failing(f), lang);
        }
        out.push_str("  </testsuite>\n");
    }
    if !gate.budgets.is_empty() {
        let failed = gate.budgets.iter().filter(|b| !b.passed).count();
        let _ = writeln!(
            out,
            "  <testsuite name=\"budgets\" tests=\"{}\" failures=\"{failed}\" errors=\"0\">",
            gate.budgets.len()
        );
        for b in &gate.budgets {
            budget_case(&mut out, b);
        }
        out.push_str("  </testsuite>\n");
    }
    out.push_str("</testsuites>\n");
    out
}

fn finding_case(out: &mut String, f: &Finding, failing: bool, lang: Lang) {
    let _ = write!(
        out,
        "    <testcase classname=\"quena.{}\" name=\"{}\"",
        attr(&f.id),
        attr(&f.title)
    );
    let body = details(f, lang);
    if failing {
        let message = if f.observation.is_empty() {
            &f.title
        } else {
            &f.observation
        };
        let _ = writeln!(
            out,
            ">\n      <failure message=\"{}\" type=\"{}\">{}</failure>",
            attr(message),
            f.severity.as_str(),
            text(&body)
        );
        out.push_str("    </testcase>\n");
    } else if !f.observation.is_empty() {
        let _ = writeln!(
            out,
            ">\n      <system-out>{}</system-out>",
            text(&f.observation)
        );
        out.push_str("    </testcase>\n");
    } else {
        out.push_str("/>\n");
    }
}

fn budget_case(out: &mut String, b: &BudgetResult) {
    let _ = write!(
        out,
        "    <testcase classname=\"quena.budget.{}\" name=\"{} {}\"",
        attr(&b.key),
        attr(&b.label),
        attr(&b.limit_text)
    );
    if b.passed {
        let _ = writeln!(out, ">\n      <system-out>{}</system-out>", text(&b.reason));
        out.push_str("    </testcase>\n");
    } else {
        let _ = writeln!(
            out,
            ">\n      <failure message=\"{}\" type=\"budget\">{}</failure>",
            attr(&b.reason),
            text(&b.reason)
        );
        out.push_str("    </testcase>\n");
    }
}
