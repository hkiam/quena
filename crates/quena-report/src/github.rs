//! GitHub Actions workflow commands: annotations for findings and budgets.

use crate::gate::GateResult;
use crate::{Report, Severity};

/// Escape the message of a workflow command.
fn data(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

/// Escape a property value of a workflow command.
fn property(s: &str) -> String {
    data(s).replace(':', "%3A").replace(',', "%2C")
}

/// `::error` for each finding and budget that fails the gate, `::warning` for the other
/// critical and warning findings.
pub fn to_github(r: &Report, gate: &GateResult) -> String {
    let mut out = String::new();
    for (i, f) in r.findings.iter().enumerate() {
        let level = if gate.is_failing_at(i) {
            "error"
        } else if f.severity >= Severity::Warning {
            "warning"
        } else {
            continue;
        };
        let message = if f.observation.is_empty() {
            &f.title
        } else {
            &f.observation
        };
        out.push_str(&format!(
            "::{level} title={}::{}\n",
            property(&format!("{}: {}", f.id, f.title)),
            data(message)
        ));
    }
    for b in gate.budgets.iter().filter(|b| !b.passed) {
        out.push_str(&format!(
            "::error title={}::{}\n",
            property(&format!("Budget {}", b.key)),
            data(&format!("{} {}: {}", b.label, b.limit_text, b.reason))
        ));
    }
    out
}
