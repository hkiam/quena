//! One filter engine, three front ends:
//! * [`FilterSettings`] – the Filters tab,
//! * [`expr`] – the expression language (`host ~= "*.x.de" and status >= 400`),
//! * [`quickexec`] – command field commands (`?text`, `=404`, `@host`, `bpu` …).

pub mod expr;
pub mod quickexec;
mod settings;

pub use expr::{Expr, ParseError};
pub use settings::{FilterSettings, HostMode, ProcessMode};

use quena_model::SessionSummary;
use std::sync::Arc;

/// A predicate narrowing the list on top of the filters (the navigator's group or path).
#[derive(Clone)]
pub struct Scope(Arc<dyn Fn(&SessionSummary) -> bool + Send + Sync>);

impl Scope {
    pub fn new(f: impl Fn(&SessionSummary) -> bool + Send + Sync + 'static) -> Scope {
        Scope(Arc::new(f))
    }

    pub fn matches(&self, s: &SessionSummary) -> bool {
        (self.0)(s)
    }
}

impl std::fmt::Debug for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Scope(..)")
    }
}

/// Compiled filter used by the session index.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    settings: Option<settings::Compiled>,
    expr: Option<Expr>,
    scope: Option<Scope>,
}

impl Filter {
    pub fn all() -> Filter {
        Filter::default()
    }

    pub fn compile(settings: &FilterSettings) -> Result<Filter, ParseError> {
        if !settings.enabled {
            return Ok(Filter::default());
        }
        let expr = match settings.expression.trim() {
            "" => None,
            e => Some(expr::parse(e)?),
        };
        Ok(Filter { settings: Some(settings::Compiled::new(settings)), expr, scope: None })
    }

    pub fn from_expr(e: Expr) -> Filter {
        Filter { settings: None, expr: Some(e), scope: None }
    }

    /// This filter, narrowed to `scope` as well.
    pub fn with_scope(mut self, scope: Option<Scope>) -> Filter {
        self.scope = scope;
        self
    }

    pub fn is_all(&self) -> bool {
        self.settings.is_none() && self.expr.is_none() && self.scope.is_none()
    }

    pub fn matches(&self, s: &SessionSummary) -> bool {
        if let Some(sc) = &self.scope
            && !(sc.0)(s)
        {
            return false;
        }
        if let Some(c) = &self.settings {
            if !c.matches(s) {
                return false;
            }
        }
        if let Some(e) = &self.expr {
            if !e.eval(s) {
                return false;
            }
        }
        true
    }
}

/// Case-insensitive glob match with `*` and `?`.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Strip the port from `host:port` (keeps IPv6 brackets intact).
pub fn host_without_port(host: &str) -> &str {
    if host.starts_with('[') {
        return host.find(']').map(|i| &host[..=i]).unwrap_or(host);
    }
    match host.rfind(':') {
        Some(i) if host[i + 1..].chars().all(|c| c.is_ascii_digit()) => &host[..i],
        _ => host,
    }
}

/// Parse sizes like `10k`, `1.5mb`, `200`.
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim().to_ascii_lowercase();
    let s = s.trim_end_matches('b');
    let (num, mul) = match s.chars().last()? {
        'k' => (&s[..s.len() - 1], 1024f64),
        'm' => (&s[..s.len() - 1], 1024f64 * 1024.0),
        'g' => (&s[..s.len() - 1], 1024f64 * 1024.0 * 1024.0),
        _ => (s, 1.0),
    };
    num.trim().parse::<f64>().ok().map(|n| (n * mul) as u64)
}

/// Parse durations like `200`, `200ms`, `1.5s`, `2m` into milliseconds.
pub fn parse_duration_ms(s: &str) -> Option<u64> {
    let s = s.trim().to_ascii_lowercase();
    let (num, mul) = if let Some(n) = s.strip_suffix("ms") {
        (n, 1.0)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1000.0)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60_000.0)
    } else {
        (s.as_str(), 1.0)
    };
    num.trim().parse::<f64>().ok().map(|n| (n * mul) as u64)
}

pub const BROWSERS: &[&str] = &[
    "chrome", "google chrome", "google chrome helper", "safari", "com.apple.webkit.networking", "firefox",
    "msedge", "microsoft edge", "microsoft edge helper", "opera", "brave", "brave browser", "brave browser helper",
    "arc", "vivaldi", "chromium", "iexplore", "orion",
];

pub fn is_browser(process: &str) -> bool {
    let name = process.rsplit_once(':').map(|(n, _)| n).unwrap_or(process).to_ascii_lowercase();
    BROWSERS.iter().any(|b| name == *b || name.starts_with(&format!("{b} helper")))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn glob() {
        assert!(glob_match("*.company.de", "api.company.de"));
        assert!(!glob_match("*.company.de", "company.de"));
        assert!(glob_match("a?c", "ABC"));
        assert!(glob_match("*", ""));
    }
    #[test]
    fn sizes() {
        assert_eq!(parse_size("10k"), Some(10240));
        assert_eq!(parse_size("1.5MB"), Some(1572864));
        assert_eq!(parse_duration_ms("1.5s"), Some(1500));
    }
    #[test]
    fn host_port() {
        assert_eq!(host_without_port("a.b:443"), "a.b");
        assert_eq!(host_without_port("[::1]:80"), "[::1]");
        assert_eq!(host_without_port("a.b"), "a.b");
    }
}
