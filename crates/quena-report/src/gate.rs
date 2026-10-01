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
    /// Not checked (a relative budget without a baseline, e.g. the run that creates the
    /// first baseline); `passed` is true and `reason` says why.
    pub skipped: bool,
    pub reason: String,
}

#[derive(Clone, PartialEq, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GateResult {
    pub passed: bool,
    /// Keys (`Finding::key_of`) of the findings that fail the gate, in report order, each once.
    pub failing: Vec<String>,
    pub budgets: Vec<BudgetResult>,
    /// Why the gate passed or failed, one line each, in the report language.
    pub reasons: Vec<String>,
    /// Indexes into `report.findings` of the failing findings (findings may share a key).
    #[serde(skip)]
    failing_idx: HashSet<usize>,
    #[serde(skip)]
    failing_keys: HashSet<String>,
}

impl GateResult {
    /// Whether `report.findings[i]` (of the evaluated report) fails the gate.
    pub fn is_failing_at(&self, i: usize) -> bool {
        self.failing_idx.contains(&i)
    }

    /// Whether a finding with this key fails the gate; for findings outside the evaluated
    /// report's list, such as the entries of a [`Comparison`] (which matches by key). For the
    /// report's own findings [`GateResult::is_failing_at`] is exact when keys repeat.
    pub fn is_failing(&self, f: &Finding) -> bool {
        self.failing_keys.contains(f.key_of())
    }

    /// Number of findings that fail the gate.
    pub fn failing_count(&self) -> usize {
        self.failing_idx.len()
    }
}

/// Budgets must name metrics of the report: a typo would otherwise pass or fail silently
/// forever. `Err` lists the unknown keys and the numeric metric keys the report has.
pub fn check_budgets(report: &Report, cfg: &GateConfig) -> Result<(), String> {
    let mut unknown: Vec<&str> = Vec::new();
    for b in &cfg.budgets {
        if !report.metrics.iter().any(|m| m.key == b.key)
            && optional_metric(&b.key).is_none()
            && !unknown.contains(&b.key.as_str())
        {
            unknown.push(&b.key);
        }
    }
    if unknown.is_empty() {
        return Ok(());
    }
    let numeric: Vec<&str> = report
        .metrics
        .iter()
        .filter(|m| !m.key.is_empty() && m.value.as_f64().is_some())
        .map(|m| m.key.as_str())
        .collect();
    let optional: Vec<&str> = OPTIONAL_METRICS
        .iter()
        .map(|(k, _)| *k)
        .filter(|k| !numeric.contains(k))
        .collect();
    Err(format!(
        "budget metric{} {} not in the report; numeric metrics: {} (also allowed, reported only when they apply: {})",
        if unknown.len() == 1 { "" } else { "s" },
        unknown
            .iter()
            .map(|k| format!("{k:?}"))
            .collect::<Vec<_>>()
            .join(", "),
        if numeric.is_empty() {
            "(none)".to_string()
        } else {
            numeric.join(", ")
        },
        optional.join(", ")
    ))
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
    let mut failing_idx: HashSet<usize> = HashSet::new();
    let mut failing_keys: HashSet<String> = HashSet::new();
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
            let ignore: HashSet<&str> = cfg.ignore.iter().map(String::as_str).collect();
            for (i, f) in report.findings.iter().enumerate() {
                if f.severity < min || (new_only && !worse.contains(f.key_of())) {
                    continue;
                }
                if ignore.contains(f.id.as_str()) || ignore.contains(f.key.as_str()) {
                    ignored += 1;
                    continue;
                }
                failing_idx.insert(i);
                if failing_keys.insert(f.key_of().to_string()) {
                    failing.push(f.key_of().to_string());
                }
            }
            let sev = min.label(lang);
            let n = failing_idx.len();
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
    // Failed budgets, and the skipped ones as information (the gate still passes).
    for b in budgets.iter().filter(|b| !b.passed || b.skipped) {
        reasons.push(tv(
            lang,
            "Budget {key}: {reason}",
            &[("key", &b.key), ("reason", &b.reason)],
        ));
    }
    GateResult {
        passed: failing_idx.is_empty() && budgets.iter().all(|b| b.passed),
        failing,
        budgets,
        reasons,
        failing_idx,
        failing_keys,
    }
}

/// Metrics an analyzer reports only when they apply (webdiag: `open` and `notAnalysed` only
/// when above 0, `rate` only when the capture spans time), with the value their absence
/// means; `None`: absent means "not measured", a budget on it is skipped. A budget on one of
/// these is no configuration error when this report lacks it.
pub const OPTIONAL_METRICS: &[(&str, Option<f64>)] = &[
    ("open", Some(0.0)),
    ("notAnalysed", Some(0.0)),
    ("rate", None),
];

fn optional_metric(key: &str) -> Option<Option<f64>> {
    OPTIONAL_METRICS
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, d)| *d)
}

enum Lookup {
    Missing,
    NotNumeric,
    Value(f64),
}

/// A metric's number, an absent optional metric with a default counting as that.
fn lookup(r: &Report, key: &str) -> Lookup {
    match r.metrics.iter().find(|m| m.key == key) {
        Some(m) => m.value.as_f64().map_or(Lookup::NotNumeric, Lookup::Value),
        None => match optional_metric(key) {
            Some(Some(d)) => Lookup::Value(d),
            _ => Lookup::Missing,
        },
    }
}

fn budget(report: &Report, baseline: Option<&Report>, b: &Budget, lang: Lang) -> BudgetResult {
    let metric = report.metrics.iter().find(|m| m.key == b.key);
    let optional = optional_metric(&b.key).is_some();
    let unit = metric.map_or(if optional { "count" } else { "" }.to_string(), |m| {
        m.unit.clone()
    });
    let label = metric.map_or(b.key.clone(), |m| {
        if m.label.is_empty() {
            b.key.clone()
        } else {
            m.label.clone()
        }
    });
    let current = lookup(report, &b.key);
    let value = match current {
        Lookup::Value(v) => Some(v),
        _ => None,
    };
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
    let mut skipped = false;
    let mut skip = |why: &'static str| {
        skipped = true;
        Err(why)
    };
    let outcome: Result<(f64, String), &'static str> = match current {
        Lookup::Missing if optional => skip("skipped: metric not in report"),
        Lookup::Missing => Err("metric not in report"),
        Lookup::NotNumeric => Err("metric is not numeric"),
        Lookup::Value(_) => match b.limit {
            Limit::Absolute(limit) => Ok((limit, String::new())),
            Limit::RelativePct(p) => match baseline {
                None => skip("skipped: no baseline"),
                Some(r) => match lookup(r, &b.key) {
                    Lookup::Missing if optional => skip("skipped: metric not in baseline"),
                    Lookup::Missing => Err("metric not in baseline"),
                    Lookup::NotNumeric => Err("metric not numeric in baseline"),
                    Lookup::Value(bv) => {
                        base = Some(bv);
                        // `bv * (1 + p/100)` rounds 100 +15 % to 115.00000000000001.
                        let allowed = bv * (100.0 + p) / 100.0;
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
        },
    };
    let (passed, reason) = match (outcome, value) {
        (Ok((allowed, note)), Some(v)) => {
            let ok = within(v, allowed);
            let op = if ok { "≤" } else { ">" };
            (
                ok,
                format!(
                    "{} {op} {}{note}",
                    fmt_number(v, &unit, lang),
                    fmt_number(allowed, &unit, lang)
                ),
            )
        }
        (Ok(_), None) => (false, t(lang, "metric is not numeric").to_string()),
        (Err(e), _) => (skipped, t(lang, e).to_string()),
    };
    BudgetResult {
        key: b.key.clone(),
        label,
        unit,
        limit_text,
        baseline: base,
        value,
        passed,
        skipped,
        reason,
    }
}

/// `value ≤ limit`, tolerating the rounding error of the limit's computation.
fn within(value: f64, limit: f64) -> bool {
    value <= limit + 1e-9 * limit.abs().max(1.0)
}
