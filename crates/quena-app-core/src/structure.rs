//! Structure view: the visible sessions as a tree of hosts and URL paths.
//!
//! The tree is built one level at a time (the UI expands nodes lazily), so even very large
//! captures only cost one pass over the view per expanded node.

use crate::AppCore;
use quena_model::{SessionId, SessionSummary};
use serde::Serialize;
use std::collections::BTreeMap;

/// Most children returned for one node.
const MAX_CHILDREN: usize = 5000;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeNode {
    /// Host, a folder (`name/`) or a last path segment (`name`); empty for the path itself.
    pub name: String,
    pub count: u64,
    pub errors: u64,
    pub bytes: u64,
    pub has_children: bool,
}

/// Path without query or fragment; tunnels and odd request targets have none.
fn path_of(s: &SessionSummary) -> &str {
    let u = s.url.as_str();
    if !u.starts_with('/') {
        return "";
    }
    let end = u.find(['?', '#']).unwrap_or(u.len());
    &u[..end]
}

fn add(n: &mut TreeNode, s: &SessionSummary) {
    n.count += 1;
    if s.status >= 400 {
        n.errors += 1;
    }
    n.bytes += s.response_body_len;
}

/// Children of a node. `host: None` lists the hosts; otherwise the entries directly below
/// `prefix` (a path ending in `/`, starting with `/`).
pub fn children<'a>(rows: impl IntoIterator<Item = &'a SessionSummary>, host: Option<&str>, prefix: &str) -> (Vec<TreeNode>, bool) {
    let mut level = Level::new(host, prefix);
    rows.into_iter().for_each(|s| level.visit(s));
    level.finish()
}

struct Level<'q> {
    host: Option<&'q str>,
    prefix: &'q str,
    map: BTreeMap<String, TreeNode>,
}

impl<'q> Level<'q> {
    fn new(host: Option<&'q str>, prefix: &'q str) -> Self {
        Level { host, prefix, map: BTreeMap::new() }
    }

    fn visit(&mut self, s: &SessionSummary) {
        let (name, below) = match self.host {
            None => (s.host.as_str(), !path_of(s).is_empty()),
            Some(h) if s.host != h => return,
            Some(_) => {
                let Some(rest) = path_of(s).strip_prefix(self.prefix) else { return };
                match rest.find('/') {
                    Some(i) => (&rest[..=i], true),
                    None => (rest, false),
                }
            }
        };
        let n = match self.map.get_mut(name) {
            Some(n) => n,
            None => self.map.entry(name.to_string()).or_default(),
        };
        n.has_children |= below;
        add(n, s);
    }

    fn finish(self) -> (Vec<TreeNode>, bool) {
        let truncated = self.map.len() > MAX_CHILDREN;
        let nodes = self
            .map
            .into_iter()
            .take(MAX_CHILDREN)
            .map(|(name, mut n)| {
                n.name = name;
                n
            })
            .collect();
        (nodes, truncated)
    }
}

/// Does a session belong to the node `host` + `path`? A `path` ending in `/` (or empty)
/// covers everything below it; otherwise only that exact path.
pub fn matches(s: &SessionSummary, host: &str, path: &str) -> bool {
    if s.host != host {
        return false;
    }
    let p = path_of(s);
    if path.is_empty() {
        true
    } else if path.ends_with('/') {
        p.starts_with(path)
    } else {
        p == path
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeLevel {
    pub nodes: Vec<TreeNode>,
    pub truncated: bool,
}

impl AppCore {
    pub fn structure(&self, host: Option<&str>, prefix: &str) -> TreeLevel {
        let mut level = Level::new(host, prefix);
        self.capture().index.for_each_view(|s| level.visit(s));
        let (nodes, truncated) = level.finish();
        TreeLevel { nodes, truncated }
    }

    /// Visible sessions below a node, in view order.
    pub fn structure_ids(&self, host: &str, path: &str) -> Vec<SessionId> {
        self.capture().index.find(|s| matches(s, host, path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(host: &str, url: &str, status: u16) -> SessionSummary {
        SessionSummary { host: host.into(), url: url.into(), status, response_body_len: 10, ..Default::default() }
    }

    #[test]
    fn levels() {
        let rows = vec![
            s("a.test", "/api/v1/users?x=1", 200),
            s("a.test", "/api/v1/users", 404),
            s("a.test", "/api/health", 200),
            s("a.test", "/", 200),
            s("b.test:443", "b.test:443", 200),
        ];
        let (hosts, _) = children(&rows, None, "");
        assert_eq!(hosts.iter().map(|n| (n.name.as_str(), n.count, n.has_children)).collect::<Vec<_>>(), [("a.test", 4, true), ("b.test:443", 1, false)]);
        let (root, _) = children(&rows, Some("a.test"), "/");
        assert_eq!(root.iter().map(|n| (n.name.as_str(), n.count, n.has_children)).collect::<Vec<_>>(), [("", 1, false), ("api/", 3, true)]);
        let (api, _) = children(&rows, Some("a.test"), "/api/");
        assert_eq!(api.iter().map(|n| (n.name.as_str(), n.count)).collect::<Vec<_>>(), [("health", 1), ("v1/", 2)]);
        let (v1, _) = children(&rows, Some("a.test"), "/api/v1/");
        assert_eq!((v1[0].name.as_str(), v1[0].count, v1[0].errors, v1[0].bytes), ("users", 2, 1, 20));
    }

    #[test]
    fn node_membership() {
        let x = s("a.test", "/api/v1/users?x=1", 200);
        assert!(matches(&x, "a.test", ""));
        assert!(matches(&x, "a.test", "/api/"));
        assert!(matches(&x, "a.test", "/api/v1/users"));
        assert!(!matches(&x, "a.test", "/api/v1/use"));
        assert!(!matches(&x, "b.test", "/api/"));
    }
}
