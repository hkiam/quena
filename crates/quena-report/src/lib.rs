//! Diagnostics reports of analyzer plugins (analyzer API 1, `plugins/webdiag/REPORT.md`):
//! tolerant parsing, the comparison of two reports, quality gates for CI and the exports
//! (Markdown, JUnit XML, GitHub workflow commands, JSON).
//!
//! A port of `app/ui/src/lib/diagReport.ts`; both sides are checked against the shared
//! fixtures in `tests/fixtures` so that the UI and the CLI never disagree.

mod fmt;
pub mod gate;
mod github;
mod i18n;
mod junit;
mod markdown;

use serde::{Serialize, Serializer};
use serde_json::{Map, Value};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::str::FromStr;

pub use fmt::{fmt_datetime, fmt_delta, fmt_value};
pub use github::to_github;
pub use junit::to_junit;
pub use markdown::{MdOptions, to_markdown};

/// Severity of a finding. Ordered by severity: `Critical > Warning > Info`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

impl Severity {
    /// Most severe first.
    pub const ALL: [Severity; 3] = [Severity::Critical, Severity::Warning, Severity::Info];

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::Warning => "warning",
            Severity::Info => "info",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Severity::Critical => 2,
            Severity::Warning => 1,
            Severity::Info => 0,
        }
    }

    /// The frame label ("Critical" / "Kritisch").
    pub fn label(self, lang: Lang) -> &'static str {
        i18n::t(
            lang,
            match self {
                Severity::Critical => "Critical",
                Severity::Warning => "Warning",
                Severity::Info => "Info",
            },
        )
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "critical" => Ok(Severity::Critical),
            "warning" => Ok(Severity::Warning),
            "info" => Ok(Severity::Info),
            _ => Err(format!(
                "unknown severity {s:?} (critical, warning or info)"
            )),
        }
    }
}

/// Language of the frame texts of the exports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lang {
    En,
    De,
}

impl FromStr for Lang {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "en" => Ok(Lang::En),
            "de" => Ok(Lang::De),
            _ => Err(format!("unknown language {s:?} (en or de)")),
        }
    }
}

/// A metric value: a number, a text or missing (`null`).
#[derive(Clone, PartialEq, Debug)]
pub enum MetricValue {
    Number(f64),
    Text(String),
    None,
}

impl MetricValue {
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            MetricValue::Number(v) => Some(*v),
            _ => None,
        }
    }
}

impl Serialize for MetricValue {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            MetricValue::Number(v) => Num(*v).serialize(s),
            MetricValue::Text(t) => s.serialize_str(t),
            MetricValue::None => s.serialize_none(),
        }
    }
}

/// A number serialized like `JSON.stringify` does: integral values without a fraction.
struct Num(f64);

impl Serialize for Num {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if self.0.fract() == 0.0 && self.0.abs() < 9_007_199_254_740_992.0 {
            s.serialize_i64(self.0 as i64)
        } else {
            s.serialize_f64(self.0)
        }
    }
}

pub(crate) fn ser_num<S: Serializer>(v: &f64, s: S) -> Result<S::Ok, S::Error> {
    Num(*v).serialize(s)
}

pub(crate) fn ser_opt_num<S: Serializer>(v: &Option<f64>, s: S) -> Result<S::Ok, S::Error> {
    match v {
        Some(v) => s.serialize_some(&Num(*v)),
        None => s.serialize_none(),
    }
}

fn ser_nums<S: Serializer>(v: &[f64], s: S) -> Result<S::Ok, S::Error> {
    s.collect_seq(v.iter().map(|&x| Num(x)))
}

#[derive(Clone, PartialEq, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Metric {
    pub key: String,
    pub label: String,
    pub value: MetricValue,
    pub unit: String,
}

#[derive(Clone, PartialEq, Debug, Serialize)]
pub struct Fact {
    pub label: String,
    pub value: String,
}

#[derive(Clone, PartialEq, Debug, Serialize)]
pub struct Table {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

#[derive(Clone, PartialEq, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    /// Identifies "the same finding" across captures; reports are compared by it.
    pub key: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: String,
    pub categories: Vec<String>,
    #[serde(serialize_with = "ser_num")]
    pub score: f64,
    pub observation: String,
    pub impact: String,
    pub hypotheses: Vec<String>,
    pub recommendations: Vec<String>,
    pub next_steps: Vec<String>,
    pub estimate: bool,
    pub threshold: String,
    pub facts: Vec<Fact>,
    pub table: Option<Table>,
    #[serde(serialize_with = "ser_nums")]
    pub sessions: Vec<f64>,
    pub operation: Option<String>,
    pub tags: Vec<String>,
}

impl Finding {
    /// The comparison key: `key`, else `id`.
    pub fn key_of(&self) -> &str {
        if self.key.is_empty() {
            &self.id
        } else {
            &self.key
        }
    }
}

#[derive(Clone, PartialEq, Debug, Serialize)]
pub struct Operation {
    pub id: String,
    pub label: String,
    #[serde(serialize_with = "ser_opt_num")]
    pub start: Option<f64>,
    #[serde(serialize_with = "ser_opt_num")]
    pub end: Option<f64>,
    #[serde(serialize_with = "ser_nums")]
    pub sessions: Vec<f64>,
    pub metrics: Vec<Metric>,
}

#[derive(Clone, PartialEq, Debug, Serialize)]
pub struct Tool {
    pub id: String,
    pub version: String,
}

#[derive(Clone, PartialEq, Debug, Serialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
}

#[derive(Clone, PartialEq, Debug, Serialize)]
pub struct Range {
    /// µs since the epoch.
    #[serde(serialize_with = "ser_opt_num")]
    pub from: Option<f64>,
    #[serde(serialize_with = "ser_opt_num")]
    pub to: Option<f64>,
    #[serde(serialize_with = "ser_num")]
    pub sessions: f64,
}

#[derive(Clone, PartialEq, Debug, Serialize)]
pub struct Summary {
    pub critical: u64,
    pub warning: u64,
    pub info: u64,
    pub headline: Vec<String>,
}

impl Summary {
    pub fn count(&self, s: Severity) -> u64 {
        match s {
            Severity::Critical => self.critical,
            Severity::Warning => self.warning,
            Severity::Info => self.info,
        }
    }
}

#[derive(Clone, PartialEq, Debug, Serialize)]
pub struct Scope {
    pub kind: String,
    #[serde(serialize_with = "ser_num")]
    pub sessions: f64,
    pub processes: Vec<String>,
    pub hosts: Vec<String>,
}

/// A normalized report: every field present, findings sorted by severity, then score.
#[derive(Clone, PartialEq, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    /// Always 1.
    pub schema: u32,
    pub tool: Tool,
    pub profile: Profile,
    pub lang: String,
    pub range: Range,
    pub summary: Summary,
    pub metrics: Vec<Metric>,
    pub operations: Vec<Operation>,
    pub findings: Vec<Finding>,
    pub scope: Option<Scope>,
    #[serde(serialize_with = "ser_opt_num")]
    pub generated_at: Option<f64>,
}

// ------------------------------------------------------------------ tolerant readers

type Obj = Map<String, Value>;

fn obj(v: Option<&Value>) -> Option<&Obj> {
    v.and_then(Value::as_object)
}

fn get<'a>(o: Option<&'a Obj>, k: &str) -> Option<&'a Value> {
    o.and_then(|o| o.get(k))
}

fn arr(v: Option<&Value>) -> &[Value] {
    v.and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

/// Strings, numbers and booleans as text (like `String(v)`), anything else `d`.
fn str_or(v: Option<&Value>, d: &str) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => fmt::js_num(n.as_f64().unwrap_or(0.0)),
        Some(Value::Bool(b)) => b.to_string(),
        _ => d.to_string(),
    }
}

fn str(v: Option<&Value>) -> String {
    str_or(v, "")
}

fn num_or_null(v: Option<&Value>) -> Option<f64> {
    v.and_then(Value::as_f64).filter(|v| v.is_finite())
}

fn num(v: Option<&Value>) -> f64 {
    num_or_null(v).unwrap_or(0.0)
}

fn strs(v: Option<&Value>) -> Vec<String> {
    arr(v)
        .iter()
        .map(|x| str(Some(x)))
        .filter(|s| !s.is_empty())
        .collect()
}

fn ids(v: Option<&Value>) -> Vec<f64> {
    arr(v).iter().filter_map(|x| num_or_null(Some(x))).collect()
}

/// `String(v)` of any JSON value.
fn js_string(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Array(a) => a
            .iter()
            .map(|x| {
                if x.is_null() {
                    String::new()
                } else {
                    js_string(x)
                }
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".into(),
        other => str(Some(other)),
    }
}

fn severity(v: Option<&Value>) -> Severity {
    v.and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .unwrap_or(Severity::Info)
}

fn metric(v: &Value) -> Option<Metric> {
    let m = obj(Some(v));
    let key = str(get(m, "key"));
    if key.is_empty() && str(get(m, "label")).is_empty() {
        return None;
    }
    let value = match get(m, "value") {
        Some(Value::Number(n)) => n.as_f64().map_or(MetricValue::None, MetricValue::Number),
        Some(Value::String(s)) => MetricValue::Text(s.clone()),
        _ => MetricValue::None,
    };
    let unit = str_or(
        get(m, "unit"),
        if matches!(value, MetricValue::Text(_)) {
            "text"
        } else {
            "count"
        },
    );
    Some(Metric {
        label: str_or(get(m, "label"), &key),
        key,
        value,
        unit,
    })
}

fn metrics(v: Option<&Value>) -> Vec<Metric> {
    arr(v).iter().filter_map(metric).collect()
}

fn finding(v: &Value, i: usize) -> Finding {
    let f = obj(Some(v));
    let id = str_or(get(f, "id"), &format!("F{}", i + 1));
    let table = obj(get(f, "table"));
    let columns = strs(get(table, "columns"));
    let rows: Vec<Vec<String>> = arr(get(table, "rows"))
        .iter()
        .map(|r| arr(Some(r)).iter().map(|c| str(Some(c))).collect())
        .collect();
    let facts = arr(get(f, "facts"))
        .iter()
        .map(|x| {
            let o = obj(Some(x));
            Fact {
                label: str(get(o, "label")),
                value: str(get(o, "value")),
            }
        })
        .filter(|x| !x.label.is_empty() || !x.value.is_empty())
        .collect();
    let operation = str(get(f, "operation"));
    Finding {
        key: str_or(get(f, "key"), &id),
        title: str_or(get(f, "title"), &id),
        severity: severity(get(f, "severity")),
        confidence: str_or(get(f, "confidence"), "medium"),
        categories: strs(get(f, "categories")),
        score: num(get(f, "score")),
        observation: str(get(f, "observation")),
        impact: str(get(f, "impact")),
        hypotheses: strs(get(f, "hypotheses")),
        recommendations: strs(get(f, "recommendations")),
        next_steps: strs(get(f, "nextSteps")),
        estimate: get(f, "estimate") == Some(&Value::Bool(true)),
        threshold: str(get(f, "threshold")),
        facts,
        table: (!columns.is_empty() || !rows.is_empty()).then_some(Table { columns, rows }),
        sessions: ids(get(f, "sessions")),
        operation: (!operation.is_empty()).then_some(operation),
        tags: strs(get(f, "tags")),
        id,
    }
}

/// A report from its JSON value; `None` unless it is an object with `schema: 1`. Missing
/// fields get defaults, unknown keys are ignored.
pub fn normalize(v: &Value) -> Option<Report> {
    let r = v.as_object()?;
    if r.get("schema").and_then(Value::as_f64) != Some(1.0) {
        return None;
    }
    let r = Some(r);
    let tool = obj(get(r, "tool"));
    let profile = obj(get(r, "profile"));
    let range = obj(get(r, "range"));
    let summary = obj(get(r, "summary"));
    let mut findings: Vec<(Finding, usize)> = arr(get(r, "findings"))
        .iter()
        .enumerate()
        .map(|(i, v)| (finding(v, i), i))
        .collect();
    findings.sort_by(|(a, i), (b, j)| {
        b.severity
            .cmp(&a.severity)
            .then(b.score.partial_cmp(&a.score).unwrap_or(Ordering::Equal))
            .then(i.cmp(j))
    });
    let findings: Vec<Finding> = findings.into_iter().map(|(f, _)| f).collect();
    // Counts from a (possibly foreign) report: whole, non-negative numbers, else counted.
    let count = |s: Severity| match num_or_null(get(summary, s.as_str())) {
        Some(v) if v >= 0.0 => v.floor() as u64,
        _ => findings.iter().filter(|f| f.severity == s).count() as u64,
    };
    let scope = match get(r, "scope") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let s = obj(Some(v));
            let list = |k| {
                get(s, k)
                    .and_then(Value::as_array)
                    .map(|a| a.iter().map(js_string).collect())
                    .unwrap_or_default()
            };
            Some(Scope {
                kind: str_or(get(s, "kind"), "visible"),
                sessions: num(get(s, "sessions")),
                processes: list("processes"),
                hosts: list("hosts"),
            })
        }
    };
    Some(Report {
        schema: 1,
        tool: Tool {
            id: str(get(tool, "id")),
            version: str(get(tool, "version")),
        },
        profile: Profile {
            id: str(get(profile, "id")),
            name: str_or(get(profile, "name"), &str(get(profile, "id"))),
        },
        lang: str(get(r, "lang")),
        range: Range {
            from: num_or_null(get(range, "from")),
            to: num_or_null(get(range, "to")),
            sessions: num(get(range, "sessions")),
        },
        summary: Summary {
            critical: count(Severity::Critical),
            warning: count(Severity::Warning),
            info: count(Severity::Info),
            headline: strs(get(summary, "headline")),
        },
        metrics: metrics(get(r, "metrics")),
        operations: arr(get(r, "operations"))
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let o = obj(Some(v));
                Operation {
                    id: str_or(get(o, "id"), &format!("op-{}", i + 1)),
                    label: str_or(get(o, "label"), &str(get(o, "id"))),
                    start: num_or_null(get(o, "start")),
                    end: num_or_null(get(o, "end")),
                    sessions: ids(get(o, "sessions")),
                    metrics: metrics(get(o, "metrics")),
                }
            })
            .collect(),
        findings,
        scope,
        generated_at: num_or_null(get(r, "generatedAt")),
    })
}

/// Parse report JSON text into the raw value and the normalized report; fails when it is
/// not JSON or not a schema 1 report.
pub fn parse(text: &str) -> Result<(Value, Report), String> {
    let raw: Value = serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
    let report = normalize(&raw).ok_or_else(|| "not a schema 1 diagnostics report".to_string())?;
    Ok((raw, report))
}

// ------------------------------------------------------------------ comparison

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Trend {
    Better,
    Worse,
    Same,
    Neutral,
}

#[derive(Clone, PartialEq, Debug, Serialize)]
pub struct MetricDelta {
    pub key: String,
    pub label: String,
    pub unit: String,
    pub before: MetricValue,
    pub after: MetricValue,
    #[serde(serialize_with = "ser_opt_num")]
    pub delta: Option<f64>,
    pub trend: Trend,
}

#[derive(Clone, PartialEq, Debug, Serialize)]
pub struct Changed {
    pub before: Finding,
    pub after: Finding,
}

#[derive(Clone, PartialEq, Debug, Serialize)]
pub struct Comparison {
    pub severity: Vec<MetricDelta>,
    pub metrics: Vec<MetricDelta>,
    /// Findings of `b` whose key is not in `a`.
    pub added: Vec<Finding>,
    /// Findings of `a` whose key is not in `b`.
    pub resolved: Vec<Finding>,
    /// Same key, different severity.
    pub changed: Vec<Changed>,
    pub unchanged: usize,
}

/// Which direction of a metric is an improvement: -1 lower is better, 1 higher, 0 unknown.
pub fn direction(key: &str, unit: &str) -> i8 {
    if unit == "text" {
        return 0;
    }
    let k = key.to_ascii_lowercase();
    let any = |words: &[&str]| words.iter().any(|w| k.contains(w));
    if any(&["uncached", "uncompressed", "miss"]) {
        return -1;
    }
    if any(&[
        "hit",
        "cached",
        "compress",
        "reuse",
        "parallel",
        "throughput",
        "success",
    ]) {
        return 1;
    }
    if any(&[
        "request",
        "bytes",
        "transfer",
        "size",
        "error",
        "fail",
        "duplicate",
        "redundant",
        "redirect",
        "retr",
        "slow",
        "large",
        "timeout",
        "abort",
        "4xx",
        "5xx",
        "critical",
        "warning",
        "latency",
        "wait",
        "duration",
        "ttfb",
        "preflight",
        "roundtrip",
        "chain",
        "sequential",
    ]) {
        return -1;
    }
    if unit == "ms" { -1 } else { 0 }
}

fn delta(
    key: &str,
    label: &str,
    unit: &str,
    before: MetricValue,
    after: MetricValue,
) -> MetricDelta {
    let (d, trend) = match (&before, &after) {
        (MetricValue::Number(b), MetricValue::Number(a)) => {
            let d = a - b;
            let dir = direction(key, unit);
            let trend = if d.abs() <= 1e-9 * b.abs().max(1.0) {
                Trend::Same
            } else if dir == 0 {
                Trend::Neutral
            } else if (d.signum() as i8) == dir {
                Trend::Better
            } else {
                Trend::Worse
            };
            (Some(d), trend)
        }
        _ => (
            None,
            if before == after {
                Trend::Same
            } else {
                Trend::Neutral
            },
        ),
    };
    MetricDelta {
        key: key.into(),
        label: label.into(),
        unit: unit.into(),
        before,
        after,
        delta: d,
        trend,
    }
}

/// Insertion-ordered map like a JavaScript `Map` built from pairs: a later duplicate key
/// replaces the value (`last`) or is dropped (`!last`) but keeps the first position.
fn ordered<'a, T>(
    items: impl Iterator<Item = (&'a str, &'a T)>,
    last: bool,
) -> (Vec<(&'a str, &'a T)>, HashMap<&'a str, usize>) {
    let mut list: Vec<(&str, &T)> = Vec::new();
    let mut index: HashMap<&str, usize> = HashMap::new();
    for (k, v) in items {
        match index.get(k) {
            Some(&i) if last => list[i].1 = v,
            Some(_) => {}
            None => {
                index.insert(k, list.len());
                list.push((k, v));
            }
        }
    }
    (list, index)
}

/// Compare a baseline report `a` (before) with `b` (after). Findings match by key.
pub fn compare(a: &Report, b: &Report) -> Comparison {
    let severity = Severity::ALL
        .iter()
        .map(|&s| {
            let n = |r: &Report| MetricValue::Number(r.summary.count(s) as f64);
            delta(s.as_str(), s.as_str(), "count", n(a), n(b))
        })
        .collect();
    fn mkey(m: &Metric) -> &str {
        if m.key.is_empty() { &m.label } else { &m.key }
    }
    let (am, am_index) = ordered(a.metrics.iter().map(|m| (mkey(m), m)), true);
    let (bm, bm_index) = ordered(b.metrics.iter().map(|m| (mkey(m), m)), true);
    let mut metrics = Vec::new();
    for (k, m) in &bm {
        let before = am_index
            .get(k)
            .map_or(MetricValue::None, |&i| am[i].1.value.clone());
        metrics.push(delta(k, &m.label, &m.unit, before, m.value.clone()));
    }
    for (k, o) in &am {
        if !bm_index.contains_key(k) {
            metrics.push(delta(
                k,
                &o.label,
                &o.unit,
                o.value.clone(),
                MetricValue::None,
            ));
        }
    }

    let (af, af_index) = ordered(a.findings.iter().map(|f| (f.key_of(), f)), false);
    let (bf, bf_index) = ordered(b.findings.iter().map(|f| (f.key_of(), f)), false);
    let mut added = Vec::new();
    let mut changed = Vec::new();
    let mut unchanged = 0;
    for (k, f) in &bf {
        match af_index.get(k) {
            None => added.push((*f).clone()),
            Some(&i) if af[i].1.severity != f.severity => changed.push(Changed {
                before: af[i].1.clone(),
                after: (*f).clone(),
            }),
            Some(_) => unchanged += 1,
        }
    }
    let resolved = af
        .iter()
        .filter(|(k, _)| !bf_index.contains_key(k))
        .map(|(_, f)| (*f).clone())
        .collect();
    Comparison {
        severity,
        metrics,
        added,
        resolved,
        changed,
        unchanged,
    }
}

// ------------------------------------------------------------------ JSON

/// The raw report object, unchanged, plus `comparison` and `gate` when given; pretty-printed.
pub fn to_json(raw: &Value, cmp: Option<&Comparison>, gate: Option<&gate::GateResult>) -> String {
    let mut v = raw.clone();
    if let Some(o) = v.as_object_mut() {
        if let Some(c) = cmp {
            o.insert(
                "comparison".into(),
                serde_json::to_value(c).unwrap_or(Value::Null),
            );
        }
        if let Some(g) = gate {
            o.insert(
                "gate".into(),
                serde_json::to_value(g).unwrap_or(Value::Null),
            );
        }
    }
    serde_json::to_string_pretty(&v).unwrap_or_default() + "\n"
}
