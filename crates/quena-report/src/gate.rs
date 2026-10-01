//! Quality gates for CI: which findings and metric budgets fail a build.

use crate::fmt::{decimal, fmt_number, js_num};
use crate::i18n::{plural, t, tv};
use crate::{Comparison, Finding, Lang, Report, Severity, ser_opt_num};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;
use std::fmt;

/// The limit of a metric budget.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Limit {
    /// The value must not exceed this number (`errors=0`).
    Absolute(f64),
    /// The value must not exceed the baseline by more than this many percent (`requests=+10%`).
    RelativePct(f64),
}

/// A metric budget, `key=limit`.
#[derive(Clone, PartialEq, Debug)]
pub struct Budget {
    pub key: String,
    pub limit: Limit,
}

impl fmt::Display for Budget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.limit {
            Limit::Absolute(v) => write!(f, "{}={}", self.key, js_num(v)),
            Limit::RelativePct(p) => write!(
                f,
                "{}={}{}%",
                self.key,
                if p >= 0.0 { "+" } else { "" },
                js_num(p)
            ),
        }
    }
}

/// `errors=0`, `bytes=5242880`, `requests=+10%` (relative to the baseline).
pub fn parse_budget(s: &str) -> Result<Budget, String> {
    let (key, limit) = s.split_once('=').ok_or_else(|| {
        format!("budget {s:?}: expected key=limit, e.g. errors=0 or requests=+10%")
    })?;
    let key = key.trim();
    if key.is_empty() {
        return Err(format!("budget {s:?}: the metric key is missing"));
    }
    let limit = limit.trim();
    let number = |v: &str| v.trim().parse::<f64>().ok().filter(|v| v.is_finite());
    let limit = match limit.strip_suffix('%') {
        Some(p) => Limit::RelativePct(
            number(p).ok_or_else(|| format!("budget {s:?}: {p:?} is not a percentage"))?,
        ),
        None => Limit::Absolute(
            number(limit).ok_or_else(|| format!("budget {s:?}: {limit:?} is not a number"))?,
        ),
    };
    Ok(Budget {
        key: key.to_string(),
        limit,
    })
}

/// What fails the gate.
#[derive(Clone, Debug, Default)]
pub struct GateConfig {
    /// Findings of this severity or above fail; `None` never fails on findings.
    pub fail_on: Option<Severity>,
    /// With a baseline, existing findings fail too (otherwise only new and worsened ones).
    pub fail_on_existing: bool,
    pub budgets: Vec<Budget>,
    /// Finding ids (rule ids) or exact keys that never fail.
    pub ignore: Vec<String>,
}

impl GateConfig {
    /// A gate file: `{"failOn": "critical"|"warning"|"info"|"none", "failOnExisting": false,
    /// "budgets": ["requests=+10%"], "ignore": ["OAUTH-FLOW"]}`. Missing keys keep the
    /// defaults; unknown keys are an error.
    pub fn from_json(text: &str) -> Result<GateConfig, String> {
        let v: Value =
            serde_json::from_str(text).map_err(|e| format!("gate config: not JSON: {e}"))?;
        let o = v.as_object().ok_or("gate config: expected a JSON object")?;
        let strings = |k: &str, v: &Value| -> Result<Vec<String>, String> {
            v.as_array()
                .and_then(|a| {
                    a.iter()
                        .map(|x| x.as_str().map(str::to_string))
                        .collect::<Option<Vec<_>>>()
                })
                .ok_or_else(|| format!("gate config: {k:?} must be an array of strings"))
        };
        let mut cfg = GateConfig::default();
        for (k, v) in o {
            match k.as_str() {
                "failOn" => {
                    cfg.fail_on = match v.as_str() {
                        Some("none") => None,
                        Some(s) => Some(s.parse().map_err(|e| format!("gate config: \"failOn\": {e}"))?),
                        None => return Err("gate config: \"failOn\" must be \"critical\", \"warning\", \"info\" or \"none\"".into()),
                    }
                }
                "failOnExisting" => cfg.fail_on_existing = v.as_bool().ok_or("gate config: \"failOnExisting\" must be true or false")?,
                "budgets" => {
                    cfg.budgets = strings(k, v)?.iter().map(|s| parse_budget(s).map_err(|e| format!("gate config: {e}"))).collect::<Result<_, _>>()?
                }
                "ignore" => cfg.ignore = strings(k, v)?,
                other => return Err(format!("gate config: unknown key {other:?} (failOn, failOnExisting, budgets, ignore)")),
            }
        }
        Ok(cfg)
    }
}

#[derive(Clone, PartialEq, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BudgetResult {
    pub key: String,
    /// The metric label, else the key.
    pub label: String,
    pub unit: String,
    pub limit_text: String,
    #[serde(serialize_with = "ser_opt_num")]
    pub baseline: Option<f64>,
    #[serde(serialize_with = "ser_opt_num")]
    pub value: Option<f64>,
    pub passed: bool,
    pub reason: String,
}

#[derive(Clone, PartialEq, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GateResult {
    pub passed: bool,
    /// Keys (`Finding::key_of`) of the findings that fail the gate, in report order.
    pub failing: Vec<String>,
    pub budgets: Vec<BudgetResult>,
    /// Why the gate passed or failed, one line each, in the report language.
    pub reasons: Vec<String>,
}

impl GateResult {
    pub fn is_failing(&self, f: &Finding) -> bool {
        self.failing.iter().any(|k| k == f.key_of())
    }
}

/// Evaluate the gate for `report`, optionally against a baseline and `compare(baseline, report)`.
pub fn evaluate(
    report: &Report,
    baseline: Option<(&Report, &Comparison)>,
    cfg: &GateConfig,
    lang: Lang,
) -> GateResult {
    let new_only = baseline.is_some() && !cfg.fail_on_existing;
    let mut failing: Vec<String> = Vec::new();
    let mut ignored = 0;
    let mut reasons = Vec::new();
    match cfg.fail_on {
        None => reasons.push(t(lang, "Findings do not fail the gate.").to_string()),
        Some(min) => {
            let worse: HashSet<&str> = baseline
                .map(|(_, c)| {
                    c.added
                        .iter()
                        .map(Finding::key_of)
                        .chain(
                            c.changed
                                .iter()
                                .filter(|x| x.after.severity > x.before.severity)
                                .map(|x| x.after.key_of()),
                        )
                        .collect()
                })
                .unwrap_or_default();
            for f in &report.findings {
                if f.severity < min || (new_only && !worse.contains(f.key_of())) {
                    continue;
                }
                if cfg.ignore.iter().any(|i| *i == f.id || *i == f.key) {
                    ignored += 1;
                } else if !failing.iter().any(|k| k == f.key_of()) {
                    failing.push(f.key_of().to_string());
                }
            }
            let sev = min.label(lang);
            let n = failing.len();
            let line = match (new_only, n) {
                (false, 0) => tv(
                    lang,
                    "No findings at {severity} or above.",
                    &[("severity", sev)],
                ),
                (true, 0) => tv(
                    lang,
                    "No new or worsened findings at {severity} or above.",
                    &[("severity", sev)],
                ),
                (false, _) => plural(
                    lang,
                    n,
                    "{n} finding at {severity} or above.",
                    "{n} findings at {severity} or above.",
                ),
                (true, _) => plural(
                    lang,
                    n,
                    "{n} new or worsened finding at {severity} or above.",
                    "{n} new or worsened findings at {severity} or above.",
                ),
            };
            reasons.push(line.replace("{severity}", sev));
            if ignored > 0 {
                reasons.push(plural(
                    lang,
                    ignored,
                    "{n} finding ignored by the configuration.",
                    "{n} findings ignored by the configuration.",
                ));
            }
        }
    }
    let budgets: Vec<BudgetResult> = cfg
        .budgets
        .iter()
        .map(|b| budget(report, baseline.map(|(r, _)| r), b, lang))
        .collect();
    for b in budgets.iter().filter(|b| !b.passed) {
        reasons.push(tv(
            lang,
            "Budget {key}: {reason}",
            &[("key", &b.key), ("reason", &b.reason)],
        ));
    }
    GateResult {
        passed: failing.is_empty() && budgets.iter().all(|b| b.passed),
        failing,
        budgets,
        reasons,
    }
}

fn budget(report: &Report, baseline: Option<&Report>, b: &Budget, lang: Lang) -> BudgetResult {
    let find = |r: &Report| r.metrics.iter().find(|m| m.key == b.key).cloned();
    let metric = find(report);
    let unit = metric.as_ref().map_or(String::new(), |m| m.unit.clone());
    let label = metric.as_ref().map_or(b.key.clone(), |m| {
        if m.label.is_empty() {
            b.key.clone()
        } else {
            m.label.clone()
        }
    });
    let value = metric.as_ref().and_then(|m| m.value.as_f64());
    let pct_text = |p: f64| {
        format!(
            "{}{} %",
            if p >= 0.0 { "+" } else { "−" },
            decimal(p.abs(), 2, lang)
        )
    };
    let limit_text = match b.limit {
        Limit::Absolute(v) => format!("≤ {}", fmt_number(v, &unit, lang)),
        Limit::RelativePct(p) => format!("≤ {} {}", t(lang, "baseline"), pct_text(p)),
    };
    let mut base = None;
    let outcome: Result<(f64, String), &'static str> = match (&metric, value) {
        (None, _) => Err("metric not in report"),
        (Some(_), None) => Err("metric is not numeric"),
        (Some(_), Some(v)) => match b.limit {
            Limit::Absolute(limit) => Ok((limit, String::new())),
            Limit::RelativePct(p) => match baseline {
                None => Err("needs --baseline"),
                Some(r) => match find(r).and_then(|m| m.value.as_f64()) {
                    None => Err("metric not in baseline"),
                    Some(bv) => {
                        base = Some(bv);
                        let allowed = if bv == 0.0 {
                            0.0
                        } else {
                            bv * (1.0 + p / 100.0)
                        };
                        Ok((
                            allowed,
                            format!(
                                " ({} {} {})",
                                t(lang, "baseline"),
                                fmt_number(bv, &unit, lang),
                                pct_text(p)
                            ),
                        ))
                    }
                },
            },
        }
        .map(|(allowed, note)| {
            let op = if v > allowed { ">" } else { "≤" };
            (
                allowed,
                format!(
                    "{} {op} {}{note}",
                    fmt_number(v, &unit, lang),
                    fmt_number(allowed, &unit, lang)
                ),
            )
        }),
    };
    let (passed, reason) = match outcome {
        Ok((allowed, reason)) => (value.is_some_and(|v| v <= allowed), reason),
        Err(e) => (false, t(lang, e).to_string()),
    };
    BudgetResult {
        key: b.key.clone(),
        label,
        unit,
        limit_text,
        baseline: base,
        value,
        passed,
        reason,
    }
}
