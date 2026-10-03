//! Structure view: the visible sessions as a tree of hosts and URL paths.
//!
//! The tree is built level by level (the UI expands nodes lazily); all levels the UI shows
//! are computed together in one pass over the view ([`AppCore::structure_levels`]).

use crate::AppCore;
use quena_model::{SessionId, SessionSummary};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

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
    /// A name beyond [`MAX_CHILDREN`] was seen (and not collected).
    more: bool,
}

impl<'q> Level<'q> {
    fn new(host: Option<&'q str>, prefix: &'q str) -> Self {
        Level { host, prefix, map: BTreeMap::new(), more: false }
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
        let full = self.map.len() >= MAX_CHILDREN;
        let n = match self.map.get_mut(name) {
            Some(n) => n,
            // Once the level is full, new names are only counted as "more": a level with
            // millions of distinct names must not collect them all first.
            None if full => {
                self.more = true;
                return;
            }
            None => self.map.entry(name.to_string()).or_default(),
        };
        n.has_children |= below;
        add(n, s);
    }

    fn finish(self) -> (Vec<TreeNode>, bool) {
        let truncated = self.more;
        let nodes = self
            .map
            .into_iter()
            .map(|(name, mut n)| {
                n.name = name;
                n
            })
            .collect();
        (nodes, truncated)
    }
}

/// Does a session belong to the node `host` + `path`? A `path` ending in `/` (or empty)
/// covers everything below it; otherwise only that exact path. `exact` (the "(this path)"
/// node of a folder) takes only sessions whose path is exactly `path`.
pub fn matches(s: &SessionSummary, host: &str, path: &str, exact: bool) -> bool {
    if s.host != host {
        return false;
    }
    let p = path_of(s);
    if exact {
        p == path
    } else if path.is_empty() {
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

/// One level asked for: `host: None` is the list of hosts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LevelQuery {
    pub host: Option<String>,
    pub prefix: String,
}

/// Several levels in one pass over `rows`; each row is only offered to the levels of its host.
pub fn levels<'a>(rows: impl FnOnce(&mut dyn FnMut(&SessionSummary)), queries: &'a [LevelQuery]) -> Vec<TreeLevel> {
    let mut levels: Vec<Level<'a>> = queries.iter().map(|q| Level::new(q.host.as_deref(), &q.prefix)).collect();
    let mut roots = Vec::new();
    let mut by_host: HashMap<&'a str, Vec<usize>> = HashMap::new();
    for (i, q) in queries.iter().enumerate() {
        match &q.host {
            None => roots.push(i),
            Some(h) => by_host.entry(h.as_str()).or_default().push(i),
        }
    }
    rows(&mut |s: &SessionSummary| {
        for &i in &roots {
            levels[i].visit(s);
        }
        if let Some(ix) = by_host.get(s.host.as_str()) {
            for &i in ix {
                levels[i].visit(s);
            }
        }
    });
    levels
        .into_iter()
        .map(|l| {
            let (nodes, truncated) = l.finish();
            TreeLevel { nodes, truncated }
        })
        .collect()
}

impl AppCore {
    pub fn structure(&self, host: Option<&str>, prefix: &str) -> TreeLevel {
        let q = [LevelQuery { host: host.map(str::to_string), prefix: prefix.to_string() }];
        self.structure_levels(&q).pop().unwrap_or(TreeLevel { nodes: vec![], truncated: false })
    }

    /// Several levels (the hosts and every open node) in one pass over the view.
    pub fn structure_levels(&self, queries: &[LevelQuery]) -> Vec<TreeLevel> {
        // The whole tree, also while the navigator narrows the list to one of its nodes.
        levels(|f| self.for_each_unscoped(f), queries)
    }

    /// Visible sessions of a node, in view order (`exact`: see [`matches`]).
    pub fn structure_ids(&self, host: &str, path: &str, exact: bool) -> Vec<SessionId> {
        let mut ids = Vec::new();
        self.for_each_unscoped(|s| {
            if matches(s, host, path, exact) {
                ids.push(s.id)
            }
        });
        ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(host: &str, url: &str, status: u16) -> SessionSummary {
        SessionSummary { host: host.into(), url: url.into(), status, response_body_len: 10, ..Default::default() }
    }

    #[test]
    fn levels_one_at_a_time() {
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
        assert!(matches(&x, "a.test", "", false));
        assert!(matches(&x, "a.test", "/api/", false));
        assert!(matches(&x, "a.test", "/api/v1/users", false));
        assert!(!matches(&x, "a.test", "/api/v1/use", false));
        assert!(!matches(&x, "b.test", "/api/", false));
        assert!(matches(&x, "a.test", "/api/v1/users", true));
    }

    /// The "(this path)" node (empty name below a folder) selects exactly the sessions it
    /// counts, not everything below the folder.
    #[test]
    fn this_path_node_is_exact() {
        let rows = vec![s("a.test", "/api/", 200), s("a.test", "/api/?x", 200), s("a.test", "/api/users", 200), s("a.test", "/", 200), s("a.test", "/x", 200)];
        let (api, _) = children(&rows, Some("a.test"), "/api/");
        let this = api.iter().find(|n| n.name.is_empty()).unwrap();
        assert_eq!(this.count, 2);
        assert_eq!(rows.iter().filter(|r| matches(r, "a.test", "/api/", true)).count(), 2);
        assert_eq!(rows.iter().filter(|r| matches(r, "a.test", "/api/", false)).count(), 3);
        let (root, _) = children(&rows, Some("a.test"), "/");
        assert_eq!(root.iter().find(|n| n.name.is_empty()).unwrap().count, 1);
        assert_eq!(rows.iter().filter(|r| matches(r, "a.test", "/", true)).count(), 1);
    }

    #[test]
    fn several_levels_in_one_pass_and_capped() {
        let mut rows: Vec<SessionSummary> = (0..MAX_CHILDREN + 50).map(|i| s("big.test", &format!("/f/{i:06}"), 200)).collect();
        rows.push(s("a.test", "/api/x", 200));
        let q = [
            LevelQuery { host: None, prefix: String::new() },
            LevelQuery { host: Some("a.test".into()), prefix: "/".into() },
            LevelQuery { host: Some("big.test".into()), prefix: "/f/".into() },
        ];
        let mut passes = 0;
        let out = levels(
            |f| {
                passes += 1;
                rows.iter().for_each(f)
            },
            &q,
        );
        assert_eq!(passes, 1);
        assert_eq!(out[0].nodes.len(), 2);
        assert_eq!(out[1].nodes.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(), ["api/"]);
        assert_eq!(out[2].nodes.len(), MAX_CHILDREN);
        assert!(out[2].truncated && !out[0].truncated && !out[1].truncated);
        // The same as one level at a time.
        assert_eq!(out[1].nodes, children(&rows, Some("a.test"), "/").0);
    }
}
