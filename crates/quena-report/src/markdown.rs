//! The report as Markdown (`toMarkdown` of the UI), optionally with the quality gate and
//! the comparison with a baseline.

use crate::fmt::{fmt_datetime, fmt_delta, fmt_int, fmt_ms, fmt_value, js_num, js_round};
use crate::gate::GateResult;
use crate::i18n::{plural, t, tv};
use crate::{Comparison, Finding, Lang, MetricDelta, Operation, Report, Severity, Trend};

/// Limits of the Markdown export.
#[derive(Clone, Debug)]
pub struct MdOptions {
    /// At most this many findings per severity (the rest is counted).
    pub limit: Option<usize>,
    /// At most this many session ids per finding.
    pub session_ids: usize,
}

impl Default for MdOptions {
    fn default() -> Self {
        MdOptions {
            limit: None,
            session_ids: 50,
        }
    }
}

/// `\s` of JavaScript regular expressions.
fn js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

/// Report texts (partly derived from the traffic) as inline Markdown: one line, and nothing
/// that Markdown or HTML would interpret — no headings, lists, emphasis, links, code or tags.
pub(crate) fn md_text(s: &str) -> String {
    // Whitespace runs that contain a line break become one space.
    let mut one = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if js_space(chars[i]) {
            let start = i;
            while i < chars.len() && js_space(chars[i]) {
                i += 1;
            }
            let run = &chars[start..i];
            if run.iter().any(|&c| c == '\r' || c == '\n') {
                one.push(' ');
            } else {
                one.extend(run);
            }
        } else {
            one.push(chars[i]);
            i += 1;
        }
    }
    let one = one.trim_matches(js_space);
    let mut esc = String::with_capacity(one.len() + 8);
    for c in one.chars() {
        if matches!(
            c,
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '|' | '~'
        ) {
            esc.push('\\');
        }
        esc.push(c);
    }
    // Block markers at the start of a line (list, heading, quote, ordered list).
    if esc.starts_with(['-', '+', '#', '>', '=']) {
        return format!("\\{esc}");
    }
    let digits = esc.bytes().take_while(u8::is_ascii_digit).count();
    if digits > 0 && matches!(esc.as_bytes().get(digits), Some(b'.' | b')')) {
        return format!("{}\\{}", &esc[..digits], &esc[digits..]);
    }
    esc
}

fn md_table(head: &[&str], rows: &[Vec<String>]) -> String {
    let mut out = vec![
        format!(
            "| {} |",
            head.iter()
                .map(|h| md_text(h))
                .collect::<Vec<_>>()
                .join(" | ")
        ),
        format!("|{}|", vec![" --- "; head.len()].join("|")),
    ];
    for r in rows {
        let cells: Vec<String> = (0..head.len())
            .map(|i| md_text(r.get(i).map_or("", String::as_str)))
            .collect();
        out.push(format!("| {} |", cells.join(" | ")));
    }
    out.join("\n")
}

/// A bullet list; `raw` items are frame texts that are already Markdown-safe.
fn list<S: AsRef<str>>(items: &[S], raw: bool) -> String {
    items
        .iter()
        .map(|s| {
            if raw {
                format!("- {}", s.as_ref())
            } else {
                format!("- {}", md_text(s.as_ref()))
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn confidence_label(c: &str, lang: Lang) -> &'static str {
    t(
        lang,
        match c {
            "high" => "High confidence",
            "low" => "Low confidence",
            _ => "Medium confidence",
        },
    )
}

fn scope_label(r: &Report, lang: Lang) -> String {
    let Some(s) = &r.scope else {
        return String::new();
    };
    let mut parts = vec![
        t(
            lang,
            if s.kind == "selection" {
                "Selected sessions"
            } else {
                "Visible sessions"
            },
        )
        .to_string(),
    ];
    if !s.processes.is_empty() {
        parts.push(tv(
            lang,
            "Process: {list}",
            &[("list", &s.processes.join(", "))],
        ));
    }
    if !s.hosts.is_empty() {
        parts.push(tv(lang, "Host: {list}", &[("list", &s.hosts.join(", "))]));
    }
    parts.join(" · ")
}

fn op_duration(o: &Operation, lang: Lang) -> String {
    match (o.start, o.end) {
        (Some(s), Some(e)) if e >= s => fmt_ms(js_round((e - s) / 1000.0), lang),
        _ => String::new(),
    }
}

/// The report as Markdown, frame texts in `lang` (report texts are already localized).
/// With `gate`, a status line and its reasons come first; with `cmp`, a comparison section
/// follows the summary. Findings that fail the gate are marked ❌.
pub fn to_markdown(
    r: &Report,
    cmp: Option<&Comparison>,
    gate: Option<&GateResult>,
    lang: Lang,
    opts: &MdOptions,
) -> String {
    let limit = opts.limit.unwrap_or(usize::MAX);
    let mut out: Vec<String> = Vec::new();
    if let Some(g) = gate {
        out.push(gate_markdown(g, lang));
    }
    let profile = if r.profile.name.is_empty() {
        String::new()
    } else {
        format!(": {}", md_text(&r.profile.name))
    };
    out.push(format!("# {}{profile}", t(lang, "Diagnostics report")));
    let mut meta = Vec::new();
    if !r.tool.id.is_empty() {
        // One text: escaped on its own, a version would look like an ordered list ("0\.1.0").
        let tool = if r.tool.version.is_empty() {
            r.tool.id.clone()
        } else {
            format!("{} {}", r.tool.id, r.tool.version)
        };
        meta.push(format!("{}: {}", t(lang, "Analyzer"), md_text(&tool)));
    }
    if r.scope.is_some() {
        meta.push(format!(
            "{}: {}",
            t(lang, "Scope"),
            md_text(&scope_label(r, lang))
        ));
    }
    let sessions = [
        r.range.sessions,
        r.scope.as_ref().map_or(0.0, |s| s.sessions),
    ]
    .into_iter()
    .find(|&n| n != 0.0)
    .unwrap_or(0.0);
    meta.push(format!(
        "{}: {}",
        t(lang, "Sessions"),
        fmt_int(sessions, lang)
    ));
    if r.range.from.is_some() {
        meta.push(format!(
            "{}: {} – {}",
            t(lang, "Time range"),
            fmt_datetime(r.range.from),
            fmt_datetime(r.range.to)
        ));
    }
    if r.generated_at.is_some() {
        meta.push(format!(
            "{}: {}",
            t(lang, "Generated"),
            fmt_datetime(r.generated_at)
        ));
    }
    out.push(list(&meta, true));

    out.push(format!("## {}", t(lang, "Summary")));
    out.push(format!(
        "{}: {} · {}: {} · {}: {}",
        t(lang, "Critical"),
        r.summary.critical,
        t(lang, "Warning"),
        r.summary.warning,
        t(lang, "Info"),
        r.summary.info
    ));
    if !r.summary.headline.is_empty() {
        out.push(list(&r.summary.headline, false));
    }

    if let Some(c) = cmp {
        out.push(comparison_markdown(c, gate, lang));
    }

    if !r.metrics.is_empty() {
        out.push(format!("## {}", t(lang, "Key metrics")));
        let rows: Vec<Vec<String>> = r
            .metrics
            .iter()
            .map(|m| vec![m.label.clone(), fmt_value(&m.value, &m.unit, lang)])
            .collect();
        out.push(md_table(&[t(lang, "Metric"), t(lang, "Value")], &rows));
    }

    if !r.findings.is_empty() {
        out.push(format!("## {}", t(lang, "Findings")));
        for s in Severity::ALL {
            let all: Vec<(usize, &Finding)> = r
                .findings
                .iter()
                .enumerate()
                .filter(|(_, f)| f.severity == s)
                .collect();
            for &(i, f) in all.iter().take(limit) {
                out.push(finding_markdown(
                    f,
                    r,
                    gate.is_some_and(|g| g.is_failing_at(i)),
                    lang,
                    opts.session_ids,
                ));
            }
            if all.len() > limit {
                let n = (all.len() - limit).to_string();
                out.push(format!(
                    "_{}_",
                    tv(
                        lang,
                        "{n} more findings of this severity not shown.",
                        &[("n", &n)]
                    )
                ));
            }
        }
    }

    if !r.operations.is_empty() {
        out.push(format!("## {}", t(lang, "Operations")));
        let ops = &r.operations[..r.operations.len().min(limit)];
        let rows: Vec<Vec<String>> = ops
            .iter()
            .map(|o| {
                let metrics = o
                    .metrics
                    .iter()
                    .map(|m| format!("{}: {}", m.label, fmt_value(&m.value, &m.unit, lang)))
                    .collect::<Vec<_>>();
                vec![o.label.clone(), op_duration(o, lang), metrics.join(", ")]
            })
            .collect();
        out.push(md_table(
            &[
                t(lang, "Operation"),
                t(lang, "Duration"),
                t(lang, "Metrics"),
            ],
            &rows,
        ));
        if r.operations.len() > ops.len() {
            let n = (r.operations.len() - ops.len()).to_string();
            out.push(format!(
                "_{}_",
                tv(lang, "{n} more operations not shown.", &[("n", &n)])
            ));
        }
    }
    out.join("\n\n") + "\n"
}

fn finding_markdown(f: &Finding, r: &Report, failing: bool, lang: Lang, max_ids: usize) -> String {
    let mut out = Vec::new();
    let mark = if failing { "❌ " } else { "" };
    out.push(format!(
        "### {mark}[{}] {} ({})",
        f.severity.label(lang),
        md_text(&f.title),
        md_text(&f.id)
    ));
    let mut tags = vec![confidence_label(&f.confidence, lang).to_string()];
    if f.estimate {
        tags.push(t(lang, "Estimate").into());
    }
    if !f.categories.is_empty() {
        tags.push(format!(
            "{}: {}",
            t(lang, "Categories"),
            md_text(&f.categories.join(", "))
        ));
    }
    out.push(tags.join(" · "));
    if !f.observation.is_empty() {
        out.push(format!(
            "**{}:** {}",
            t(lang, "Observation"),
            md_text(&f.observation)
        ));
    }
    if !f.facts.is_empty() {
        let rows: Vec<Vec<String>> = f
            .facts
            .iter()
            .map(|x| vec![x.label.clone(), x.value.clone()])
            .collect();
        out.push(md_table(&[t(lang, "Fact"), t(lang, "Value")], &rows));
    }
    if let Some(table) = f.table.as_ref().filter(|t| !t.columns.is_empty()) {
        let head: Vec<&str> = table.columns.iter().map(String::as_str).collect();
        out.push(md_table(&head, &table.rows));
    }
    if !f.impact.is_empty() {
        out.push(format!("**{}:** {}", t(lang, "Impact"), md_text(&f.impact)));
    }
    for (title, items) in [
        ("Hypotheses (not verified)", &f.hypotheses),
        ("Recommendations", &f.recommendations),
        ("Next steps", &f.next_steps),
    ] {
        if !items.is_empty() {
            out.push(format!("**{}:**\n\n{}", t(lang, title), list(items, false)));
        }
    }
    if !f.threshold.is_empty() {
        out.push(format!(
            "**{}:** {}",
            t(lang, "Threshold"),
            md_text(&f.threshold)
        ));
    }
    if let Some(op) = &f.operation {
        let label = r
            .operations
            .iter()
            .find(|o| &o.id == op)
            .map(|o| o.label.as_str())
            .filter(|l| !l.is_empty())
            .unwrap_or(op);
        out.push(format!("**{}:** {}", t(lang, "Operation"), md_text(label)));
    }
    if !f.sessions.is_empty() {
        let shown = f
            .sessions
            .iter()
            .take(max_ids)
            .map(|id| format!("#{}", js_num(*id)))
            .collect::<Vec<_>>()
            .join(", ");
        let more = if f.sessions.len() > max_ids {
            ", …"
        } else {
            ""
        };
        out.push(format!(
            "**{}:** {} ({shown}{more})",
            t(lang, "Affected sessions"),
            fmt_int(f.sessions.len() as f64, lang)
        ));
    }
    out.join("\n\n")
}

fn gate_markdown(g: &GateResult, lang: Lang) -> String {
    let status = t(
        lang,
        if g.passed {
            "Quality gate: passed ✅"
        } else {
            "Quality gate: FAILED ❌"
        },
    );
    let mut out = vec![format!("**{status}**")];
    if !g.reasons.is_empty() {
        out.push(list(&g.reasons, false));
    }
    if !g.budgets.is_empty() {
        let rows: Vec<Vec<String>> = g
            .budgets
            .iter()
            .map(|b| {
                let num = |v: Option<f64>| {
                    v.map_or(String::new(), |v| crate::fmt::fmt_number(v, &b.unit, lang))
                };
                let result = if b.passed {
                    "✅".to_string()
                } else {
                    format!("❌ {}", b.reason)
                };
                vec![
                    b.label.clone(),
                    num(b.value),
                    b.limit_text.clone(),
                    num(b.baseline),
                    result,
                ]
            })
            .collect();
        out.push(md_table(
            &[
                t(lang, "Budget"),
                t(lang, "Value"),
                t(lang, "Limit"),
                t(lang, "Baseline"),
                t(lang, "Result"),
            ],
            &rows,
        ));
    }
    out.join("\n\n")
}

fn trend_label(d: &MetricDelta, lang: Lang) -> &'static str {
    match d.trend {
        Trend::Better => t(lang, "better"),
        Trend::Worse => t(lang, "worse"),
        Trend::Same => t(lang, "unchanged"),
        Trend::Neutral => "",
    }
}

fn delta_row(label: String, d: &MetricDelta, lang: Lang) -> Vec<String> {
    let change = d.delta.map_or(String::new(), |x| {
        let arrow = if x > 0.0 && d.trend != Trend::Same {
            "▲ "
        } else if x < 0.0 && d.trend != Trend::Same {
            "▼ "
        } else {
            ""
        };
        format!("{arrow}{}", fmt_delta(x, &d.unit, lang))
    });
    vec![
        label,
        fmt_value(&d.before, &d.unit, lang),
        fmt_value(&d.after, &d.unit, lang),
        change,
        trend_label(d, lang).to_string(),
    ]
}

fn comparison_markdown(c: &Comparison, gate: Option<&GateResult>, lang: Lang) -> String {
    let mut out = vec![format!("## {}", t(lang, "Comparison with baseline"))];
    let head = |first: &'static str| {
        [
            t(lang, first),
            t(lang, "Before"),
            t(lang, "After"),
            t(lang, "Change"),
            t(lang, "Trend"),
        ]
    };
    let sev_label = |key: &str| {
        key.parse::<Severity>()
            .map_or(key.to_string(), |s| s.label(lang).to_string())
    };
    let rows: Vec<Vec<String>> = c
        .severity
        .iter()
        .map(|d| delta_row(sev_label(&d.key), d, lang))
        .collect();
    out.push(md_table(&head("Severity"), &rows));
    if !c.metrics.is_empty() {
        let rows: Vec<Vec<String>> = c
            .metrics
            .iter()
            .map(|d| delta_row(d.label.clone(), d, lang))
            .collect();
        out.push(md_table(&head("Metric"), &rows));
    }
    let line = |f: &Finding, sev: String| {
        let mark = if gate.is_some_and(|g| g.is_failing(f)) {
            "❌ "
        } else {
            ""
        };
        format!(
            "{mark}\\[{sev}\\] {} ({})",
            md_text(&f.title),
            md_text(&f.id)
        )
    };
    let section = |title: &'static str, items: Vec<String>| {
        let body = if items.is_empty() {
            format!("- {}", t(lang, "None"))
        } else {
            list(&items, true)
        };
        format!("**{} ({}):**\n\n{body}", t(lang, title), items.len())
    };
    out.push(section(
        "New findings",
        c.added
            .iter()
            .map(|f| line(f, f.severity.label(lang).into()))
            .collect(),
    ));
    out.push(section(
        "Changed severity",
        c.changed
            .iter()
            .map(|x| {
                line(
                    &x.after,
                    format!(
                        "{} → {}",
                        x.before.severity.label(lang),
                        x.after.severity.label(lang)
                    ),
                )
            })
            .collect(),
    ));
    out.push(section(
        "Resolved findings",
        c.resolved
            .iter()
            .map(|f| line(f, f.severity.label(lang).into()))
            .collect(),
    ));
    out.push(plural(
        lang,
        c.unchanged,
        "{n} finding unchanged.",
        "{n} findings unchanged.",
    ));
    out.join("\n\n")
}
