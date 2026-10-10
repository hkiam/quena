//! The navigator next to the session list: its groups (by connection, host, process, trace id,
//! session cookie or Custom) and the scope it narrows the list to — a group or a node of the
//! host/path structure, on top of the filters.

use crate::AppCore;
use quena_index::GroupBy;
use quena_model::SessionSummary;
use quena_query::{Filter, Scope};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Groups listed at most (the rest are counted as truncated).
const MAX_GROUPS: usize = 5000;

/// What the list is narrowed to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum NavScope {
    /// Sessions whose group key (see [`group_value`]) is `key`.
    Group { by: GroupBy, key: String },
    /// A node of the structure tree (see [`crate::structure::matches`]).
    Path { host: String, path: String, exact: bool },
}

/// The value a session is grouped by, as text (`None`: in no group). Connections are numbers.
pub fn group_value(s: &SessionSummary, by: GroupBy) -> Option<std::borrow::Cow<'_, str>> {
    let text = |v: &'_ str| (!v.is_empty()).then_some(());
    match by {
        GroupBy::None => None,
        GroupBy::Connection => (s.conn != 0).then(|| s.conn.to_string().into()),
        GroupBy::Host => text(&s.host).map(|_| s.host.to_ascii_lowercase().into()),
        GroupBy::Process => text(&s.process).map(|_| s.process.as_str().into()),
        GroupBy::Trace => text(&s.trace).map(|_| s.trace.as_str().into()),
        GroupBy::Session => text(&s.session).map(|_| s.session.as_str().into()),
        GroupBy::Custom => text(&s.custom).map(|_| s.custom.as_str().into()),
        GroupBy::Via => text(&s.via).map(|_| s.via.as_str().into()),
        GroupBy::Llm => text(&s.llm).map(|_| s.llm.as_str().into()),
        GroupBy::Source => Some(quena_index::source_of(s).into()),
    }
}

impl NavScope {
    pub(crate) fn predicate(&self) -> Scope {
        match self.clone() {
            NavScope::Group { by: GroupBy::Connection, key } => {
                let conn: u64 = key.parse().unwrap_or(u64::MAX);
                Scope::new(move |s| s.conn == conn)
            }
            NavScope::Group { by: GroupBy::Host, key } => Scope::new(move |s| s.host.eq_ignore_ascii_case(&key)),
            NavScope::Group { by, key } => Scope::new(move |s| group_value(s, by).is_some_and(|v| v == key.as_str())),
            NavScope::Path { host, path, exact } => Scope::new(move |s| crate::structure::matches(s, &host, &path, exact)),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NavGroup {
    /// Narrows the list to this group ([`NavScope::Group`]).
    pub key: String,
    /// What to show: the key, or for a connection its host and first session.
    pub label: String,
    pub count: u64,
    pub errors: u64,
    pub bytes: u64,
    /// The group's first session.
    pub first: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NavGroups {
    pub groups: Vec<NavGroup>,
    /// Sessions the filters let through (all groups, and those in none).
    pub total: u64,
    /// Sessions without a value to group by (no connection id, no trace id …).
    pub ungrouped: u64,
    pub truncated: bool,
}

impl AppCore {
    /// Narrow the list to a group or path (`None`: everything the filters let through).
    pub fn set_scope(&self, scope: Option<NavScope>) -> anyhow::Result<()> {
        *self.scope.write() = scope;
        self.apply_filter()
    }

    pub fn scope(&self) -> Option<NavScope> {
        self.scope.read().clone()
    }

    /// Every session the filters let through, ignoring the navigator's scope (the navigator
    /// lists all groups, not only the chosen one).
    pub(crate) fn for_each_unscoped(&self, mut f: impl FnMut(&SessionSummary)) {
        // All rows, not the view: collapsed groups and the scope take rows out of the view.
        let base = self.base_filter.read().clone();
        self.capture().index.for_each(|s| {
            if base.matches(s) {
                f(s)
            }
        });
    }

    /// The sessions of a group or path that the filters let through (for "Select").
    pub fn nav_ids(&self, scope: &NavScope) -> Vec<quena_model::SessionId> {
        let p = scope.predicate();
        let mut ids = Vec::new();
        self.for_each_unscoped(|s| {
            if p.matches(s) {
                ids.push(s.id)
            }
        });
        ids.sort_unstable();
        ids
    }

    /// The groups of the sessions the filters let through, in the order of their first session.
    pub fn nav_groups(&self, by: GroupBy) -> NavGroups {
        let mut order: Vec<NavGroup> = Vec::new();
        let mut at: HashMap<String, usize> = HashMap::new();
        let (mut total, mut ungrouped, mut truncated) = (0u64, 0u64, false);
        self.for_each_unscoped(|s| {
            total += 1;
            let Some(key) = group_value(s, by) else {
                ungrouped += 1;
                return;
            };
            let i = match at.get(key.as_ref()) {
                Some(&i) => i,
                None if order.len() >= MAX_GROUPS => {
                    truncated = true;
                    return;
                }
                None => {
                    let label = match by {
                        GroupBy::Connection => format!("{} · #{}", s.host, s.id),
                        GroupBy::Host => s.host.clone(),
                        _ => key.to_string(),
                    };
                    order.push(NavGroup { key: key.to_string(), label, count: 0, errors: 0, bytes: 0, first: s.id });
                    at.insert(key.into_owned(), order.len() - 1);
                    order.len() - 1
                }
            };
            let g = &mut order[i];
            g.count += 1;
            g.errors += u64::from(s.status >= 400);
            g.bytes += s.response_body_len;
            g.first = g.first.min(s.id);
        });
        order.sort_by_key(|g| g.first);
        NavGroups { groups: order, total, ungrouped, truncated }
    }

    /// The compiled filters without the scope, and with it (for the index).
    pub(crate) fn scoped(&self, base: Filter) -> Filter {
        *self.base_filter.write() = std::sync::Arc::new(base.clone());
        base.with_scope(self.scope.read().as_ref().map(NavScope::predicate))
    }
}
