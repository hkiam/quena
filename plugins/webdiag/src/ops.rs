//! Operations: sessions that belong to one user/application action (see REPORT.md).
use crate::model::{Operation, Options, Session};

/// Split the capture into operations. (Implemented by the patterns work package.)
pub fn segment(sessions: &[Session], _opts: &Options) -> Vec<Operation> {
    if sessions.is_empty() {
        return vec![];
    }
    vec![Operation {
        id: "op-1".into(),
        label: String::new(),
        start: sessions[0].started,
        end: sessions.iter().map(|s| s.end()).max().unwrap_or(0),
        members: (0..sessions.len()).collect(),
        metrics: vec![],
    }]
}
