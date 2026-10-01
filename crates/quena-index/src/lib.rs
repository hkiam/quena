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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Sort {
    pub column: Column,
    pub descending: bool,
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
}

impl Inner {
    fn is_default_sort(&self) -> bool {
        self.sort.column == Column::Id
    }

    fn cmp_pos(&self, a: u32, b: u32) -> Ordering {
        let (ra, rb) = (&self.rows[a as usize], &self.rows[b as usize]);
        let o = if self.sort.column == Column::Id { ra.id.cmp(&rb.id) } else { compare(ra, rb, self.sort.column) };
        if self.sort.descending { o.reverse() } else { o }
    }

    fn full_rebuild(&mut self) {
        let filter = self.filter.clone();
        let mut view: Vec<u32> = (0..self.rows.len() as u32).filter(|&p| filter.matches(&self.rows[p as usize])).collect();
        if self.sort.column == Column::Host {
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
        let (filter, sort) = (g.filter.clone(), g.sort);
        *g = Inner { filter, sort, version: g.version + 1, ..Default::default() };
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
        RowWindow {
            version: g.version,
            total: g.view.len(),
            start,
            rows: g.view[start..end].iter().map(|&p| g.rows[p as usize].clone()).collect(),
        }
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
        eprintln!("ingest {ingest:?} window {window:?} sort {sort:?}");
        assert!(window < Duration::from_millis(5));
    }
}
