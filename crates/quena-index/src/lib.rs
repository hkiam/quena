//! Session index.
//!
//! The core owns the session list. Producers call [`SessionIndex::upsert`]
//! at any rate; the UI ticker calls [`SessionIndex::tick`] (≤ 60 Hz) which
//! folds all pending changes into the current view in one go. The UI only
//! ever asks for a window of rows.

use parking_lot::RwLock;
use quena_model::{SessionId, SessionSummary};
use quena_query::Filter;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum Column {
    #[default]
    Id,
    Result,
    Protocol,
    Host,
    Url,
    Body,
    Caching,
    ContentType,
    Process,
    Comments,
    Custom,
    Method,
    Duration,
    Started,
    /// Reverse proxy entry the request came through.
    Via,
    /// End of validity of the server certificate.
    Cert,
    /// LLM provider/model, tokens and estimated cost of LLM API calls.
    Llm,
    Tokens,
    Cost,
    /// The conversation (agent run) of an LLM call.
    Conversation,
    /// MCP exchange (method and tool) and its server.
    Mcp,
    McpServer,
    /// TLS version, the server's IP address, the request's HTTP version.
    Tls,
    RemoteIp,
    Http,
    /// Header columns (see `quena_model::set_header_columns`).
    Header1,
    Header2,
    Header3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Sort {
    pub column: Column,
    pub descending: bool,
}

fn hv(s: &SessionSummary, i: usize) -> &str {
    s.header_values.get(i).map(String::as_str).unwrap_or("")
}

/// IP addresses sort by number (`10.0.0.9` before `10.0.0.10`), others after them.
fn ip_key(s: &str) -> (u8, u128, &str) {
    match s.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => (0, u32::from(a) as u128, s),
        Ok(std::net::IpAddr::V6(a)) => (1, u128::from(a), s),
        Err(_) => (2, 0, s),
    }
}

/// "Group by" of the list: rows with the same key stay together (groups in the order of
/// their first session), sorted inside their group by the chosen column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum GroupBy {
    #[default]
    None,
    /// The client connection (keep-alive, HTTP/2).
    Connection,
    Host,
    Process,
    /// Trace or correlation id.
    Trace,
    /// Session cookie.
    Session,
    /// The Custom column (set by rules scripts).
    Custom,
    /// The reverse proxy entry.
    Via,
    /// The LLM provider/model.
    Llm,
    /// The conversation (agent run) of LLM calls.
    Conversation,
    /// The MCP server.
    McpServer,
    /// Where the session comes from: recorded live, or the archive it was loaded from.
    Source,
}

/// Group of a row in a [`RowWindow`].
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RowGroup {
    /// The first row of its group in the view.
    pub start: bool,
    /// Stable per group (0–7), for its colour.
    pub hue: u8,
    /// Sessions in the group (the filter applied, collapsed ones included).
    pub size: u32,
    pub collapsed: bool,
    /// The group's first session (its place in the list; names a connection).
    pub first: SessionId,
}

fn hash_str(s: &str, fold_case: bool) -> u64 {
    // FNV-1a; equal keys only need equal hashes (a collision merges two groups).
    s.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ if fold_case { b.to_ascii_lowercase() } else { b } as u64).wrapping_mul(0x0000_0100_0000_01b3))
}

/// The source of a session for grouping: the archive's name, else `live`.
pub fn source_of(r: &SessionSummary) -> &str {
    if !r.archive.is_empty() {
        &r.archive
    } else if r.has_flag(quena_model::flags::IMPORTED) {
        "imported"
    } else {
        "live"
    }
}

fn group_key(r: &SessionSummary, by: GroupBy) -> Option<u64> {
    let text = |s: &str, fold: bool| (!s.is_empty()).then(|| hash_str(s, fold));
    match by {
        GroupBy::None => None,
        GroupBy::Connection => (r.conn != 0).then_some(r.conn),
        GroupBy::Host => text(&r.host, true),
        GroupBy::Process => text(&r.process, false),
        GroupBy::Trace => text(&r.trace, false),
        GroupBy::Session => text(&r.session, false),
        GroupBy::Custom => text(&r.custom, false),
        GroupBy::Via => text(&r.via, false),
        GroupBy::Llm => text(&r.llm, false),
        GroupBy::Conversation => text(&r.llm_conv, false),
        GroupBy::McpServer => text(&r.mcp_server, false),
        GroupBy::Source => Some(hash_str(source_of(r), false)),
    }
}

/// Case-insensitive order without allocating (hosts are ASCII / punycode). The sort
/// comparator runs O(n log n) times — two `to_lowercase()` Strings per call made a
/// 500k-row Host sort several seconds slow on Windows.
fn cmp_ignore_ascii_case(a: &str, b: &str) -> Ordering {
    a.bytes().map(|c| c.to_ascii_lowercase()).cmp(b.bytes().map(|c| c.to_ascii_lowercase()))
}

fn compare(a: &SessionSummary, b: &SessionSummary, c: Column) -> Ordering {
    let o = match c {
        Column::Id => Ordering::Equal,
        Column::Result => a.status.cmp(&b.status),
        Column::Protocol => a.protocol.cmp(&b.protocol),
        Column::Host => cmp_ignore_ascii_case(&a.host, &b.host),
        Column::Url => a.url.cmp(&b.url),
        Column::Body => a.response_body_len.cmp(&b.response_body_len),
        Column::Caching => a.caching.cmp(&b.caching),
        Column::ContentType => a.content_type.cmp(&b.content_type),
        Column::Process => a.process.cmp(&b.process),
        Column::Comments => a.comment.cmp(&b.comment),
        Column::Custom => a.custom.cmp(&b.custom),
        Column::Method => a.method.cmp(&b.method),
        Column::Duration => a.duration_ms.cmp(&b.duration_ms),
        Column::Started => a.started_at.cmp(&b.started_at),
        Column::Via => a.via.cmp(&b.via),
        Column::Cert => a.cert_expires.cmp(&b.cert_expires),
        Column::Llm => a.llm.cmp(&b.llm),
        Column::Tokens => a.llm_tokens.cmp(&b.llm_tokens),
        Column::Cost => a.llm_cost_micros.cmp(&b.llm_cost_micros),
        Column::Conversation => a.llm_conv.cmp(&b.llm_conv),
        Column::Mcp => a.mcp.cmp(&b.mcp),
        Column::McpServer => a.mcp_server.cmp(&b.mcp_server),
        Column::Tls => a.tls.cmp(&b.tls),
        Column::RemoteIp => ip_key(&a.remote_ip).cmp(&ip_key(&b.remote_ip)),
        Column::Http => a.http_version.cmp(&b.http_version),
        Column::Header1 => hv(a, 0).cmp(hv(b, 0)),
        Column::Header2 => hv(a, 1).cmp(hv(b, 1)),
        Column::Header3 => hv(a, 2).cmp(hv(b, 2)),
    };
    o.then(a.id.cmp(&b.id))
}

#[derive(Default)]
struct Inner {
    rows: Vec<SessionSummary>,
    pos: HashMap<SessionId, u32>,
    /// Positions into `rows`, in display order.
    view: Vec<u32>,
    in_view: HashSet<u32>,
    filter: Arc<Filter>,
    sort: Sort,
    pending_new: Vec<u32>,
    /// The view changed outside `tick` (removal): the next tick reports it, so the UI hears.
    changed: bool,
    pending_upd: HashSet<u32>,
    rebuild: bool,
    version: u64,
    last_full_sort: Option<Instant>,
    // ---- grouping (empty unless `group` is set)
    group: GroupBy,
    /// Group key per row position (`rows` order); positions beyond are computed on demand.
    keys: Vec<Option<u64>>,
    /// Smallest id of the filter-matching rows of each group: the group's place in the list.
    first: HashMap<u64, SessionId>,
    /// Filter-matching rows per group.
    counts: HashMap<u64, u32>,
    /// Filter-matching positions (in the view, or hidden in a collapsed group).
    members: HashSet<u32>,
    collapsed: HashSet<u64>,
}

impl Inner {
    fn is_default_sort(&self) -> bool {
        self.sort.column == Column::Id && self.group == GroupBy::None
    }

    fn grouped(&self) -> bool {
        self.group != GroupBy::None
    }

    fn key(&self, p: u32) -> Option<u64> {
        match self.keys.get(p as usize) {
            Some(k) => *k,
            None => group_key(&self.rows[p as usize], self.group),
        }
    }

    /// Place of a row's group: the first id of its group, or its own id when it has none.
    fn rank(&self, p: u32) -> SessionId {
        self.key(p).and_then(|k| self.first.get(&k).copied()).unwrap_or(self.rows[p as usize].id)
    }

    fn cmp_pos(&self, a: u32, b: u32) -> Ordering {
        let (ra, rb) = (&self.rows[a as usize], &self.rows[b as usize]);
        if self.grouped() {
            let (ga, gb) = (self.rank(a), self.rank(b));
            if ga != gb {
                // Groups in the order of their first session (newest first for "# descending").
                let o = ga.cmp(&gb);
                return if self.sort.column == Column::Id && self.sort.descending { o.reverse() } else { o };
            }
        }
        let o = if self.sort.column == Column::Id { ra.id.cmp(&rb.id) } else { compare(ra, rb, self.sort.column) };
        if self.sort.descending { o.reverse() } else { o }
    }

    /// A filter-matching row is shown unless its group is collapsed (the group's first
    /// session stands for it).
    fn shown(&self, p: u32) -> bool {
        match self.key(p) {
            Some(k) if self.collapsed.contains(&k) => self.first.get(&k) == Some(&self.rows[p as usize].id),
            _ => true,
        }
    }

    /// A row joins the filter-matching set. `false`: the order of its group changes (it is
    /// older than the group's first session), a rebuild is needed.
    fn join(&mut self, p: u32) -> bool {
        self.members.insert(p);
        let id = self.rows[p as usize].id;
        if let Some(k) = self.key(p) {
            *self.counts.entry(k).or_default() += 1;
            match self.first.get(&k) {
                Some(&f) if f <= id => {}
                Some(_) => return false,
                None => {
                    self.first.insert(k, id);
                }
            }
        }
        true
    }

    /// A row leaves the filter-matching set. `false`: it was its group's first session.
    fn leave(&mut self, p: u32, key: Option<u64>) -> bool {
        self.members.remove(&p);
        let id = self.rows[p as usize].id;
        if let Some(k) = key {
            let n = self.counts.entry(k).or_default();
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.counts.remove(&k);
                self.first.remove(&k);
                return true;
            }
            if self.first.get(&k) == Some(&id) {
                return false;
            }
        }
        true
    }

    fn full_rebuild(&mut self) {
        let filter = self.filter.clone();
        let mut view: Vec<u32> = (0..self.rows.len() as u32).filter(|&p| filter.matches(&self.rows[p as usize])).collect();
        if self.grouped() {
            let by = self.group;
            self.keys = self.rows.iter().map(|r| group_key(r, by)).collect();
            self.first.clear();
            self.counts.clear();
            for &p in &view {
                if let Some(k) = self.keys[p as usize] {
                    *self.counts.entry(k).or_default() += 1;
                    let id = self.rows[p as usize].id;
                    self.first.entry(k).and_modify(|f| *f = (*f).min(id)).or_insert(id);
                }
            }
            self.collapsed.retain(|k| self.counts.contains_key(k));
            self.members = view.iter().copied().collect();
            view.retain(|&p| self.shown(p));
            view.sort_unstable_by(|&a, &b| self.cmp_pos(a, b));
        } else if self.sort.column == Column::Host {
            // Lower-case each host once (O(n)) instead of inside the comparator
            // (O(n log n) allocations); same order as `cmp_ignore_ascii_case`.
            let mut keyed: Vec<(String, SessionId, u32)> = view
                .iter()
                .map(|&p| {
                    let r = &self.rows[p as usize];
                    (r.host.to_ascii_lowercase(), r.id, p)
                })
                .collect();
            keyed.sort_unstable();
            if self.sort.descending {
                keyed.reverse();
            }
            view = keyed.into_iter().map(|(_, _, p)| p).collect();
        } else if !(self.is_default_sort() && !self.sort.descending) {
            view.sort_unstable_by(|&a, &b| self.cmp_pos(a, b));
        } else {
            view.sort_unstable_by_key(|&p| self.rows[p as usize].id);
        }
        self.in_view = view.iter().copied().collect();
        self.view = view;
        self.pending_new.clear();
        self.pending_upd.clear();
        self.rebuild = false;
        self.last_full_sort = Some(Instant::now());
    }

    /// [`SessionIndex::tick`] while grouped: few changes in place, else (or when a group's
    /// order changes) a rebuild.
    fn tick_grouped(&mut self, filter: &Arc<Filter>, new: Vec<u32>, upd: HashSet<u32>) -> bool {
        let throttle = self.rows.len() > 100_000 && self.last_full_sort.is_some_and(|t| t.elapsed() < Duration::from_millis(500));
        if new.len() + upd.len() > 256 {
            if throttle {
                self.pending_new = new;
                self.pending_upd = upd;
                return false;
            }
            self.full_rebuild();
            self.version += 1;
            return true;
        }
        let by = self.group;
        let mut rebuild = false;
        for &p in &upd {
            let old = self.keys.get(p as usize).copied().flatten();
            let now = group_key(&self.rows[p as usize], by);
            let was = self.members.contains(&p);
            let is = filter.matches(&self.rows[p as usize]);
            self.remove_from_view(p);
            if old != now && (was || is) {
                rebuild = true;
                break;
            }
            match (was, is) {
                (true, false) => rebuild |= !self.leave(p, old),
                (false, true) => rebuild |= !self.join(p),
                _ => {}
            }
            if rebuild {
                break;
            }
            if is && self.shown(p) {
                self.insert_sorted(p);
            }
        }
        if !rebuild {
            if self.keys.len() < self.rows.len() {
                let from = self.keys.len();
                let rows = &self.rows[from..];
                self.keys.extend(rows.iter().map(|r| group_key(r, by)));
            }
            for p in new {
                if !filter.matches(&self.rows[p as usize]) {
                    continue;
                }
                if !self.join(p) {
                    rebuild = true;
                    break;
                }
                if self.shown(p) {
                    self.insert_sorted(p);
                }
            }
        }
        if rebuild {
            self.full_rebuild();
        } else {
            // Keys of updated rows are current now.
            for p in upd {
                if let Some(k) = self.keys.get_mut(p as usize) {
                    *k = group_key(&self.rows[p as usize], by);
                }
            }
        }
        self.version += 1;
        true
    }

    fn insert_sorted(&mut self, p: u32) {
        let idx = self.view.partition_point(|&q| self.cmp_pos(q, p) == Ordering::Less);
        self.view.insert(idx, p);
        self.in_view.insert(p);
    }

    fn remove_from_view(&mut self, p: u32) {
        if !self.in_view.remove(&p) {
            return;
        }
        if let Some(i) = self.view.iter().rposition(|&q| q == p) {
            self.view.remove(i);
        }
    }
}

/// Thread-safe session index.
#[derive(Default)]
pub struct SessionIndex {
    inner: RwLock<Inner>,
}

/// Rows returned for a viewport request.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RowWindow {
    pub version: u64,
    pub total: usize,
    pub start: usize,
    pub rows: Vec<SessionSummary>,
    /// Per row, its group (only while grouped; `None`: the row has no group key).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<Option<RowGroup>>,
}

impl SessionIndex {
    pub fn new() -> Arc<SessionIndex> {
        Arc::new(SessionIndex::default())
    }

    /// Insert or replace a summary (cheap; folded in on the next tick).
    pub fn upsert(&self, s: SessionSummary) {
        let mut g = self.inner.write();
        if let Some(&p) = g.pos.get(&s.id) {
            g.rows[p as usize] = s;
            g.pending_upd.insert(p);
        } else {
            let p = g.rows.len() as u32;
            g.pos.insert(s.id, p);
            g.rows.push(s);
            g.pending_new.push(p);
        }
    }

    /// Modify a row in place.
    pub fn update(&self, id: SessionId, f: impl FnOnce(&mut SessionSummary)) -> bool {
        let mut g = self.inner.write();
        let Some(&p) = g.pos.get(&id) else { return false };
        f(&mut g.rows[p as usize]);
        g.pending_upd.insert(p);
        true
    }

    /// Have the filter look at these sessions again at the next tick (their filter result
    /// became known).
    pub fn touch(&self, ids: &[SessionId]) {
        let mut g = self.inner.write();
        for id in ids {
            if let Some(&p) = g.pos.get(id) {
                g.pending_upd.insert(p);
            }
        }
    }

    pub fn get(&self, id: SessionId) -> Option<SessionSummary> {
        let g = self.inner.read();
        g.pos.get(&id).map(|&p| g.rows[p as usize].clone())
    }

    pub fn len(&self) -> usize {
        self.inner.read().rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn view_len(&self) -> usize {
        self.inner.read().view.len()
    }

    pub fn version(&self) -> u64 {
        self.inner.read().version
    }

    /// Remove sessions. Returns the removed ids.
    pub fn remove(&self, ids: &HashSet<SessionId>) -> Vec<SessionId> {
        let mut g = self.inner.write();
        let mut removed = Vec::new();
        let rows = std::mem::take(&mut g.rows);
        let mut kept = Vec::with_capacity(rows.len());
        for r in rows {
            if ids.contains(&r.id) {
                removed.push(r.id);
            } else {
                kept.push(r);
            }
        }
        g.rows = kept;
        let pos: HashMap<SessionId, u32> = g.rows.iter().enumerate().map(|(i, r)| (r.id, i as u32)).collect();
        g.pos = pos;
        g.full_rebuild();
        g.version += 1;
        g.changed |= !removed.is_empty();
        removed
    }

    /// Remove everything.
    pub fn clear(&self) -> Vec<SessionId> {
        let mut g = self.inner.write();
        let ids = g.rows.iter().map(|r| r.id).collect();
        let (filter, sort, group) = (g.filter.clone(), g.sort, g.group);
        *g = Inner { filter, sort, group, version: g.version + 1, ..Default::default() };
        ids
    }

    pub fn set_filter(&self, f: Filter) {
        let mut g = self.inner.write();
        g.filter = Arc::new(f);
        g.rebuild = true;
    }

    pub fn set_sort(&self, s: Sort) {
        let mut g = self.inner.write();
        g.sort = s;
        g.rebuild = true;
    }

    pub fn sort(&self) -> Sort {
        self.inner.read().sort
    }

    /// Fold pending changes into the view. Returns true if the view changed.
    pub fn tick(&self) -> bool {
        let mut g = self.inner.write();
        // Removals rebuild the view at once (positions shift); report them here.
        let removed = std::mem::take(&mut g.changed);
        if g.rebuild {
            g.full_rebuild();
            g.version += 1;
            return true;
        }
        if g.pending_new.is_empty() && g.pending_upd.is_empty() {
            return removed;
        }
        let filter = g.filter.clone();
        let natural = g.is_default_sort();
        let new = std::mem::take(&mut g.pending_new);
        let mut upd = std::mem::take(&mut g.pending_upd);
        if !upd.is_empty() && !new.is_empty() {
            // Rows that are new *and* updated are handled as new only.
            for p in &new {
                upd.remove(p);
            }
        }
        if g.grouped() {
            return g.tick_grouped(&filter, new, upd) || removed;
        }
        if !natural {
            // Sort keys may have changed. Many changes: rebuild (throttled for huge lists);
            // few changes: remove/insert individually.
            let changes = new.len() + upd.len();
            if changes > 256 {
                let throttle = g.rows.len() > 100_000
                    && g.last_full_sort.is_some_and(|t| t.elapsed() < Duration::from_millis(500));
                if throttle {
                    g.pending_new = new;
                    g.pending_upd = upd;
                    return removed;
                }
                g.full_rebuild();
                g.version += 1;
                return true;
            }
            // Remove all changed rows first so the view stays sorted for the binary searches.
            for &p in &upd {
                g.remove_from_view(p);
            }
            for p in upd {
                if filter.matches(&g.rows[p as usize]) {
                    g.insert_sorted(p);
                }
            }
            for p in new {
                if filter.matches(&g.rows[p as usize]) {
                    g.insert_sorted(p);
                }
            }
            g.version += 1;
            return true;
        }
        // Natural (id) order: updates only change membership.
        for p in upd {
            let m = filter.matches(&g.rows[p as usize]);
            let inside = g.in_view.contains(&p);
            if m && !inside {
                g.insert_sorted(p);
            } else if !m && inside {
                g.remove_from_view(p);
            }
        }
        let desc = g.sort.descending;
        let mut new: Vec<u32> = new.into_iter().filter(|&p| filter.matches(&g.rows[p as usize])).collect();
        new.sort_unstable_by_key(|&p| g.rows[p as usize].id);
        for p in new {
            let id = g.rows[p as usize].id;
            let append = if desc {
                g.view.first().is_none_or(|&q| g.rows[q as usize].id < id)
            } else {
                g.view.last().is_none_or(|&q| g.rows[q as usize].id < id)
            };
            if append {
                if desc {
                    g.view.insert(0, p);
                } else {
                    g.view.push(p);
                }
                g.in_view.insert(p);
            } else {
                g.insert_sorted(p);
            }
        }
        g.version += 1;
        true
    }

    /// Rows for `[start, start+count)` of the current view.
    pub fn window(&self, start: usize, count: usize) -> RowWindow {
        let g = self.inner.read();
        let end = (start + count).min(g.view.len());
        let start = start.min(end);
        let groups = if g.grouped() {
            (start..end)
                .map(|i| {
                    let p = g.view[i];
                    let k = g.key(p)?;
                    let begins = i == 0 || g.key(g.view[i - 1]) != Some(k);
                    let first = g.first.get(&k).copied().unwrap_or(g.rows[p as usize].id);
                    Some(RowGroup {
                        start: begins,
                        hue: (k % 8) as u8,
                        size: g.counts.get(&k).copied().unwrap_or(1),
                        collapsed: g.collapsed.contains(&k),
                        first,
                    })
                })
                .collect()
        } else {
            Vec::new()
        };
        RowWindow {
            version: g.version,
            total: g.view.len(),
            start,
            rows: g.view[start..end].iter().map(|&p| g.rows[p as usize].clone()).collect(),
            groups,
        }
    }

    pub fn set_group(&self, by: GroupBy) {
        let mut g = self.inner.write();
        if g.group != by {
            g.group = by;
            g.collapsed.clear();
            g.keys.clear();
            g.first.clear();
            g.counts.clear();
            g.members.clear();
            g.rebuild = true;
        }
    }

    pub fn group(&self) -> GroupBy {
        self.inner.read().group
    }

    /// Collapse or expand the group of a session. Returns the new state (`None`: the
    /// session has no group).
    pub fn toggle_group(&self, id: SessionId) -> Option<bool> {
        let mut g = self.inner.write();
        let p = *g.pos.get(&id)?;
        let k = g.key(p)?;
        let collapsed = if g.collapsed.remove(&k) {
            false
        } else {
            g.collapsed.insert(k);
            true
        };
        g.rebuild = true;
        Some(collapsed)
    }

    /// Collapse (or expand) all groups.
    pub fn collapse_all(&self, collapse: bool) {
        let mut g = self.inner.write();
        g.collapsed = if collapse { g.counts.keys().copied().collect() } else { HashSet::new() };
        g.rebuild = true;
    }

    /// The filter-matching sessions of a session's group (ascending), collapsed ones
    /// included; just the session when it has no group.
    pub fn group_ids(&self, id: SessionId) -> Vec<SessionId> {
        let g = self.inner.read();
        let Some(&p) = g.pos.get(&id) else { return vec![] };
        let Some(k) = g.key(p).filter(|_| g.grouped()) else { return vec![id] };
        let mut ids: Vec<SessionId> = g.members.iter().filter(|&&q| g.key(q) == Some(k)).map(|&q| g.rows[q as usize].id).collect();
        ids.sort_unstable();
        ids
    }

    /// Ids of the current view in display order for a range.
    pub fn view_ids(&self, start: usize, count: usize) -> Vec<SessionId> {
        let g = self.inner.read();
        let end = (start + count).min(g.view.len());
        g.view[start.min(end)..end].iter().map(|&p| g.rows[p as usize].id).collect()
    }

    /// View position of a session.
    pub fn position(&self, id: SessionId) -> Option<usize> {
        let g = self.inner.read();
        let p = *g.pos.get(&id)?;
        if !g.in_view.contains(&p) {
            return None;
        }
        if g.is_default_sort() {
            let idx = g.view.partition_point(|&q| g.cmp_pos(q, p) == Ordering::Less);
            return (g.view.get(idx) == Some(&p)).then_some(idx);
        }
        g.view.iter().position(|&q| q == p)
    }

    /// Ids in view order matching a predicate.
    pub fn find(&self, pred: impl Fn(&SessionSummary) -> bool) -> Vec<SessionId> {
        let g = self.inner.read();
        g.view.iter().map(|&p| &g.rows[p as usize]).filter(|r| pred(r)).map(|r| r.id).collect()
    }

    /// The sessions the filters let through, in list order, also those inside collapsed groups.
    pub fn matching(&self) -> Vec<SessionId> {
        let g = self.inner.read();
        if g.group == GroupBy::None {
            return g.view.iter().map(|&p| g.rows[p as usize].id).collect();
        }
        let mut pos: Vec<u32> = g.members.iter().copied().collect();
        pos.sort_unstable_by(|&a, &b| g.cmp_pos(a, b));
        pos.into_iter().map(|p| g.rows[p as usize].id).collect()
    }

    /// All ids (any order) matching a predicate, including hidden rows.
    pub fn find_all(&self, pred: impl Fn(&SessionSummary) -> bool) -> Vec<SessionId> {
        let g = self.inner.read();
        g.rows.iter().filter(|r| pred(r)).map(|r| r.id).collect()
    }

    /// Visit all rows (read lock held – keep the callback cheap).
    pub fn for_each(&self, mut f: impl FnMut(&SessionSummary)) {
        let g = self.inner.read();
        for r in &g.rows {
            f(r);
        }
    }

    /// Visit the visible rows in view order (read lock held – keep the callback cheap).
    pub fn for_each_view(&self, mut f: impl FnMut(&SessionSummary)) {
        let g = self.inner.read();
        for &p in &g.view {
            f(&g.rows[p as usize]);
        }
    }

    /// Oldest ids beyond the most recent `keep` (for "Keep: N sessions").
    pub fn ids_beyond(&self, keep: usize) -> Vec<SessionId> {
        let g = self.inner.read();
        if g.rows.len() <= keep {
            return vec![];
        }
        let mut ids: Vec<SessionId> = g.rows.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        ids.truncate(ids.len() - keep);
        ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removal_is_reported_by_the_next_tick() {
        // The ticker only tells the UI about index changes when tick() says so; a removal
        // rebuilt the view directly and the list in the UI kept showing removed rows.
        let idx = SessionIndex::new();
        for id in 1..=4 {
            idx.upsert(SessionSummary { id, host: "h".into(), url: "/".into(), ..Default::default() });
        }
        idx.tick();
        assert!(!idx.tick(), "nothing pending");
        idx.remove(&[2u64, 3].into_iter().collect());
        assert_eq!((idx.len(), idx.view_len()), (2, 2));
        assert!(idx.tick(), "the removal must be reported");
        assert!(!idx.tick(), "only once");
        // Removing nothing is no change.
        idx.remove(&[99u64].into_iter().collect());
        assert!(!idx.tick());
    }
    use quena_query::FilterSettings;

    fn row(id: u64, status: u16, host: &str) -> SessionSummary {
        SessionSummary { id, status, host: host.into(), url: "/".into(), protocol: "HTTP".into(), ..Default::default() }
    }

    #[test]
    fn natural_order_and_filter() {
        let idx = SessionIndex::new();
        idx.upsert(row(2, 200, "b"));
        idx.upsert(row(1, 404, "a"));
        idx.upsert(row(3, 200, "c"));
        assert!(idx.tick());
        assert_eq!(idx.view_ids(0, 10), vec![1, 2, 3]);
        idx.set_filter(
            quena_query::Filter::compile(&FilterSettings { enabled: true, hide_success: true, ..Default::default() }).unwrap(),
        );
        idx.tick();
        assert_eq!(idx.view_ids(0, 10), vec![1]);
        idx.update(2, |r| r.status = 500);
        idx.tick();
        assert_eq!(idx.view_ids(0, 10), vec![1, 2]);
        assert_eq!(idx.position(2), Some(1));
    }

    #[test]
    fn sorted_incremental_matches_rebuild() {
        use rand::Rng;
        let idx = SessionIndex::new();
        idx.set_sort(Sort { column: Column::Result, descending: true });
        let mut rng = rand::rng();
        for id in 1..=2000u64 {
            idx.upsert(row(id, rng.random_range(100..600), "h"));
            if id % 7 == 0 {
                idx.tick();
            }
            if id % 13 == 0 {
                let t = rng.random_range(1..=id);
                idx.update(t, |r| r.status = 999);
            }
        }
        idx.tick();
        let inc = idx.view_ids(0, 5000);
        idx.set_sort(Sort { column: Column::Result, descending: true });
        idx.tick();
        let full = idx.view_ids(0, 5000);
        assert_eq!(inc, full);
    }

    /// Host sort: the keyed full rebuild and the incremental comparator must agree,
    /// including mixed case and ties (broken by id), ascending and descending.
    #[test]
    fn host_sort_incremental_matches_rebuild() {
        use rand::Rng;
        let hosts = ["b.example", "A.example", "a.example", "B.Example", "c.test", "api.GitHub.com", "api.github.com"];
        for descending in [false, true] {
            let idx = SessionIndex::new();
            idx.set_sort(Sort { column: Column::Host, descending });
            idx.tick();
            let mut rng = rand::rng();
            for id in 1..=1500u64 {
                idx.upsert(row(id, 200, hosts[rng.random_range(0..hosts.len())]));
                if id % 11 == 0 {
                    idx.tick(); // small batches → incremental insert path
                }
            }
            idx.tick();
            let inc = idx.view_ids(0, 5000);
            idx.set_sort(Sort { column: Column::Host, descending });
            idx.tick(); // full keyed rebuild
            let full = idx.view_ids(0, 5000);
            assert_eq!(inc, full, "descending = {descending}");
        }
    }

    #[test]
    fn remove_and_keep() {
        let idx = SessionIndex::new();
        for id in 1..=10 {
            idx.upsert(row(id, 200, "h"));
        }
        idx.tick();
        let beyond = idx.ids_beyond(3);
        assert_eq!(beyond, (1..=7).collect::<Vec<_>>());
        idx.remove(&beyond.into_iter().collect());
        assert_eq!(idx.view_ids(0, 10), vec![8, 9, 10]);
    }

    #[test]
    fn perf_500k() {
        let idx = SessionIndex::new();
        let t = Instant::now();
        for id in 1..=500_000u64 {
            idx.upsert(row(id, 200, "host.example"));
            if id % 5000 == 0 {
                idx.tick();
            }
        }
        idx.tick();
        let ingest = t.elapsed();
        let t = Instant::now();
        let w = idx.window(250_000, 60);
        let window = t.elapsed();
        assert_eq!(w.rows.len(), 60);
        idx.set_sort(Sort { column: Column::Host, descending: false });
        let t = Instant::now();
        idx.tick();
        let sort = t.elapsed();
        // Grouped: by connection (6 sessions per keep-alive connection), then live traffic.
        idx.set_sort(Sort::default());
        for id in 1..=500_000u64 {
            idx.update(id, |r| r.conn = 1 + id / 6);
        }
        idx.tick();
        idx.set_group(GroupBy::Connection);
        let t = Instant::now();
        idx.tick();
        let group = t.elapsed();
        let t = Instant::now();
        let w = idx.window(250_000, 60);
        let gwindow = t.elapsed();
        assert_eq!(w.groups.len(), 60);
        let t = Instant::now();
        for id in 500_001..=500_100u64 {
            idx.upsert(SessionSummary { conn: 1 + id / 6, ..row(id, 200, "host.example") });
        }
        idx.tick();
        let live = t.elapsed();
        eprintln!("ingest {ingest:?} window {window:?} sort {sort:?} group {group:?} grouped window {gwindow:?} 100 live {live:?}");
        assert!(window < Duration::from_millis(5));
        assert!(gwindow < Duration::from_millis(5));
    }

    fn conn_row(id: u64, conn: u64, status: u16) -> SessionSummary {
        SessionSummary { id, conn, status, host: "h".into(), url: format!("/{id}"), ..Default::default() }
    }

    fn starts(idx: &SessionIndex) -> Vec<(u64, bool, u32)> {
        let w = idx.window(0, 100);
        w.rows.iter().zip(&w.groups).map(|(r, g)| (r.id, g.as_ref().is_some_and(|g| g.start), g.as_ref().map_or(0, |g| g.size))).collect()
    }

    #[test]
    fn groups_keep_together_in_order_of_their_first_session() {
        let idx = SessionIndex::new();
        // Two keep-alive connections interleaved, one session without a connection.
        for (id, conn) in [(1, 10), (2, 20), (3, 10), (4, 0), (5, 20), (6, 10)] {
            idx.upsert(conn_row(id, conn, 200));
        }
        idx.tick();
        idx.set_group(GroupBy::Connection);
        idx.tick();
        assert_eq!(idx.view_ids(0, 10), vec![1, 3, 6, 2, 5, 4]);
        assert_eq!(starts(&idx), vec![(1, true, 3), (3, false, 3), (6, false, 3), (2, true, 2), (5, false, 2), (4, false, 0)]);
        assert_eq!(idx.window(4, 1).groups[0].as_ref().unwrap().first, 2);
        // Sorted inside each group; the groups keep their place.
        idx.set_sort(Sort { column: Column::Url, descending: true });
        idx.tick();
        assert_eq!(idx.view_ids(0, 10), vec![6, 3, 1, 5, 2, 4]);
        // Newest groups first with "# descending".
        idx.set_sort(Sort { column: Column::Id, descending: true });
        idx.tick();
        assert_eq!(idx.view_ids(0, 10), vec![4, 5, 2, 6, 3, 1]);
        idx.set_sort(Sort::default());
        idx.tick();
        // Live traffic: new sessions join their group, a new connection goes last.
        idx.upsert(conn_row(7, 20, 200));
        idx.upsert(conn_row(8, 30, 200));
        assert!(idx.tick());
        assert_eq!(idx.view_ids(0, 10), vec![1, 3, 6, 2, 5, 7, 4, 8]);
        assert_eq!(idx.group_ids(5), vec![2, 5, 7]);
        // Back to the plain list.
        idx.set_group(GroupBy::None);
        idx.tick();
        assert_eq!(idx.view_ids(0, 10), vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(idx.window(0, 10).groups.is_empty());
    }

    #[test]
    fn collapse_and_filter_changes() {
        let idx = SessionIndex::new();
        for (id, conn) in [(1, 10), (2, 20), (3, 10), (4, 20)] {
            idx.upsert(conn_row(id, conn, 200));
        }
        idx.set_group(GroupBy::Connection);
        idx.tick();
        assert_eq!(idx.toggle_group(3), Some(true));
        idx.tick();
        // The collapsed group shows its first session only, and still counts all.
        assert_eq!(idx.view_ids(0, 10), vec![1, 2, 4]);
        assert_eq!(starts(&idx)[0], (1, true, 2));
        assert!(idx.window(0, 1).groups[0].as_ref().unwrap().collapsed);
        // New members of a collapsed group stay hidden.
        idx.upsert(conn_row(5, 10, 200));
        idx.tick();
        assert_eq!(idx.view_ids(0, 10), vec![1, 2, 4]);
        assert_eq!(starts(&idx)[0], (1, true, 3));
        idx.collapse_all(false);
        idx.tick();
        assert_eq!(idx.view_ids(0, 10), vec![1, 3, 5, 2, 4]);
        // A session that leaves the filter leaves its group; the first one moves the group.
        idx.set_filter(quena_query::Filter::compile(&FilterSettings { enabled: true, hide_success: true, ..Default::default() }).unwrap());
        idx.tick();
        assert!(idx.view_ids(0, 10).is_empty());
        idx.update(4, |r| r.status = 500);
        idx.update(3, |r| r.status = 404);
        idx.tick();
        assert_eq!(idx.view_ids(0, 10), vec![3, 4]);
        idx.update(3, |r| r.status = 200);
        idx.update(1, |r| r.status = 500);
        idx.tick();
        assert_eq!(idx.view_ids(0, 10), vec![1, 4]);
        assert_eq!(starts(&idx), vec![(1, true, 1), (4, true, 1)]);
        // Removing sessions keeps the grouping.
        idx.set_filter(quena_query::Filter::default());
        idx.remove(&[1u64].into_iter().collect());
        idx.tick();
        // Connection 10 now starts with #3, after connection 20 (#2).
        assert_eq!(idx.view_ids(0, 10), vec![2, 4, 3, 5]);
        assert_eq!(idx.toggle_group(99), None);
    }

    #[test]
    fn groups_by_text_keys() {
        let idx = SessionIndex::new();
        let r = |id: u64, host: &str, trace: &str| SessionSummary { id, host: host.into(), trace: trace.into(), url: "/".into(), ..Default::default() };
        for x in [r(1, "A.example", "t1"), r(2, "b.example", "t2"), r(3, "a.example", "t1"), r(4, "b.example", "")] {
            idx.upsert(x);
        }
        idx.set_group(GroupBy::Host);
        idx.tick();
        assert_eq!(idx.view_ids(0, 10), vec![1, 3, 2, 4], "host ignores case");
        assert_eq!(idx.window(1, 1).groups[0].as_ref().unwrap().first, 1);
        idx.set_group(GroupBy::Trace);
        idx.tick();
        assert_eq!(idx.view_ids(0, 10), vec![1, 3, 2, 4]);
        assert!(idx.window(3, 1).groups[0].is_none(), "no trace id, no group");
    }

    #[test]
    fn grouped_view_matches_a_rebuild_under_random_traffic() {
        use rand::Rng;
        let mut rng = rand::rng();
        let idx = SessionIndex::new();
        idx.set_group(GroupBy::Connection);
        idx.set_filter(quena_query::Filter::compile(&FilterSettings { enabled: true, hide_success: true, ..Default::default() }).unwrap());
        let mut next = 1u64;
        for round in 0..200 {
            for _ in 0..rng.random_range(0..5) {
                idx.upsert(conn_row(next, rng.random_range(0..6), if rng.random_bool(0.5) { 200 } else { 500 }));
                next += 1;
            }
            for _ in 0..rng.random_range(0..4) {
                if next > 1 {
                    let id = rng.random_range(1..next);
                    let st = if rng.random_bool(0.5) { 200 } else { 404 };
                    idx.update(id, |r| r.status = st);
                }
            }
            if round % 37 == 0 && next > 1 {
                idx.toggle_group(rng.random_range(1..next));
            }
            idx.tick();
            let live = idx.view_ids(0, 10_000);
            idx.inner.write().rebuild = true;
            idx.tick();
            assert_eq!(live, idx.view_ids(0, 10_000), "round {round}");
        }
    }
}
