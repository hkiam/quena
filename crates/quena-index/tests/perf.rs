//! Reactive session-index performance (PLAN.md §2.13.1). These are regression
//! guards, not micro-benchmarks: they build a 500k-row index and assert the hot
//! operations (viewport query, coalesced delta tick, filter/sort switch) stay far
//! inside the interaction budgets. Thresholds are deliberately generous so slow CI
//! machines don't flake; they exist to catch accidental O(n²) regressions. They
//! print timings with `--nocapture`.

use quena_index::{Column, SessionIndex, Sort};
use quena_model::SessionSummary;
use quena_query::{Filter, FilterSettings};
use std::time::Instant;

const N: u64 = 500_000;

/// Multiplier for the time thresholds (`QUENA_PERF_SLACK`, default 1). CI runs these
/// debug-build guards on slow shared VMs and sets a larger value; an accidental
/// O(n²) at 500k rows would still take minutes and fail.
fn slack() -> f64 {
    std::env::var("QUENA_PERF_SLACK").ok().and_then(|v| v.parse().ok()).unwrap_or(1.0)
}

fn row(id: u64) -> SessionSummary {
    let status = match id % 7 {
        0 => 500,
        1 => 404,
        2 => 301,
        _ => 200,
    };
    SessionSummary {
        id,
        status,
        host: format!("host{}.example.com", id % 1000),
        url: format!("/path/{id}"),
        protocol: "HTTPS".into(),
        method: if id % 3 == 0 { "POST" } else { "GET" }.into(),
        response_body_len: (id * 31) % 1_000_000,
        ..Default::default()
    }
}

fn build() -> std::sync::Arc<SessionIndex> {
    let idx = SessionIndex::new();
    for id in 1..=N {
        idx.upsert(row(id));
    }
    idx.tick();
    idx
}

#[test]
fn viewport_query_is_fast_on_500k() {
    let idx = build();
    assert_eq!(idx.len(), N as usize);

    // A viewport is ~100 rows; the UI asks for one per scroll frame.
    let t = Instant::now();
    let iters = 2000;
    let mut sink = 0usize;
    for i in 0..iters {
        let start = (i * 137) % (N as usize - 100);
        let w = idx.window(start, 100);
        sink += w.rows.len();
    }
    let per = t.elapsed().as_micros() as f64 / iters as f64;
    eprintln!("[perf] window(100) over 500k: {per:.1} µs/query ({sink} rows total)");
    assert!(per < 2000.0 * slack(), "viewport query too slow: {per} µs (budget frame is 16 ms)");
}

#[test]
fn per_frame_inserts_stay_incremental_and_fast() {
    // Sorted view (non-natural order) is the expensive case: inserts keep it sorted.
    let idx = build();
    idx.set_sort(Sort { column: Column::Host, descending: false });
    idx.tick();

    // 5000 sessions/s arrive over ~60 frames/s, i.e. ~83 per frame — the index takes
    // the incremental insert path (≤256 changes) rather than a rebuild. Simulate a
    // generous 200-per-frame cadence for 30 frames and time each coalesced tick.
    let mut next = N + 1;
    let mut worst_ms = 0.0f64;
    for _ in 0..30 {
        for _ in 0..200 {
            idx.upsert(row(next));
            next += 1;
        }
        let t = Instant::now();
        let changed = idx.tick();
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        assert!(changed);
        worst_ms = worst_ms.max(ms);
    }
    eprintln!("[perf] worst per-frame tick (200 sorted inserts): {worst_ms:.2} ms");
    assert_eq!(idx.len(), (next - 1) as usize);
    // Must stay well inside a 16 ms frame so scrolling never stutters under load.
    assert!(worst_ms < 16.0 * slack(), "per-frame insert tick too slow: {worst_ms} ms");
}

#[test]
fn large_burst_is_throttled_then_rebuilds() {
    // A big burst under a sorted view is coalesced: the index throttles the rebuild
    // (backpressure, R5) rather than rebuilding on every tick, then rebuilds once the
    // throttle window passes. This proves the coalescing, not just raw speed.
    let idx = build();
    idx.set_sort(Sort { column: Column::Host, descending: false });
    idx.tick();

    for id in (N + 1)..=(N + 5000) {
        idx.upsert(row(id));
    }
    // Immediately after a full sort, the >256-change burst is throttled (coalesced):
    // the tick reports no change and defers the rebuild rather than rebuilding now.
    let immediate = idx.tick();
    eprintln!("[perf] burst tick immediately after sort: changed={immediate} (expected false = throttled)");
    assert!(!immediate, "large burst should be throttled right after a full sort, not rebuilt every tick");
    assert_eq!(idx.view_len(), N as usize, "throttled tick must not yet apply the burst to the view");

    // After the throttle window, a tick applies the burst in one rebuild.
    std::thread::sleep(std::time::Duration::from_millis(550));
    let t = Instant::now();
    let changed = idx.tick();
    let ms = t.elapsed().as_secs_f64() * 1000.0;
    eprintln!("[perf] rebuild tick after throttle window (5000 inserts): {ms:.1} ms");
    assert!(changed);
    assert_eq!(idx.len(), (N + 5000) as usize);
    assert!(ms < 1500.0 * slack(), "throttled rebuild too slow: {ms} ms");
}

#[test]
fn filter_and_sort_switch_on_500k() {
    let idx = build();

    let t = Instant::now();
    idx.set_filter(Filter::compile(&FilterSettings { enabled: true, hide_success: true, ..Default::default() }).unwrap());
    idx.tick();
    let filter_ms = t.elapsed().as_secs_f64() * 1000.0;
    let visible = idx.view_len();
    eprintln!("[perf] filter switch (hide 200s) over 500k: {filter_ms:.1} ms, {visible} visible");
    // ~4/7 of rows are 200 and hidden.
    assert!(visible > 0 && visible < N as usize);

    let t = Instant::now();
    idx.set_sort(Sort { column: Column::Body, descending: true });
    idx.tick();
    let sort_ms = t.elapsed().as_secs_f64() * 1000.0;
    eprintln!("[perf] sort switch (body desc) over 500k: {sort_ms:.1} ms");

    // Verify the sort actually holds at the top of the view.
    let w = idx.window(0, 3);
    if w.rows.len() == 3 {
        assert!(w.rows[0].response_body_len >= w.rows[1].response_body_len);
        assert!(w.rows[1].response_body_len >= w.rows[2].response_body_len);
    }
    // A full re-sort/rebuild of 500k is a background-ish operation but must stay well
    // under a second so the "latest wins" switch feels immediate.
    assert!(filter_ms < 1500.0 * slack(), "filter switch too slow: {filter_ms} ms");
    assert!(sort_ms < 1500.0 * slack(), "sort switch too slow: {sort_ms} ms");
}
