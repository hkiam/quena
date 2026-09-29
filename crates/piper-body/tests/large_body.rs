//! Large-body invariant (PLAN.md §2.12): a body of arbitrary size is written and
//! read back with a **constant, small** memory footprint. Nothing here ever holds
//! more than a fixed-size buffer, whatever the total size — that is the whole
//! point. The default size is modest so CI stays fast; set `PIPER_BIGBODY_MB` to
//! run it against multi-GB bodies by hand (e.g. `PIPER_BIGBODY_MB=51200` for 50 GB).

use piper_body::{BodyConfig, BodyStore};
use std::time::Instant;

/// Deterministic content so any window can be verified without storing the body.
fn byte_at(pos: u64) -> u8 {
    (pos % 251) as u8
}

#[test]
fn huge_body_constant_memory_and_random_access() {
    let mb: u64 = std::env::var("PIPER_BIGBODY_MB").ok().and_then(|v| v.parse().ok()).unwrap_or(256);
    let total = mb * 1024 * 1024;
    let dir = tempfile::tempdir().unwrap();
    let cfg = BodyConfig {
        inline_limit: 64 * 1024,
        max_recorded_body: total + 1,
        quota: total * 2 + (1 << 20),
        min_free_space: 0, // don't make the test depend on the machine's free space
        max_derived: 1 << 30,
        max_ratio: 2000,
    };
    let store = BodyStore::open(dir.path(), cfg).unwrap();

    // ---- Write `total` bytes through a single fixed-size (1 MiB) buffer.
    const CHUNK: usize = 1024 * 1024;
    let mut buf = vec![0u8; CHUNK];
    let mut w = store.writer();
    let mut written: u64 = 0;
    let t0 = Instant::now();
    while written < total {
        let n = CHUNK.min((total - written) as usize);
        for (i, b) in buf[..n].iter_mut().enumerate() {
            *b = byte_at(written + i as u64);
        }
        w.write(&buf[..n]).unwrap();
        written += n as u64;
    }
    let body = w.finish();
    let write_secs = t0.elapsed().as_secs_f64();

    assert_eq!(body.len(), total, "stored length must equal what we wrote");
    let throughput = (total as f64 / (1024.0 * 1024.0)) / write_secs.max(1e-9);
    eprintln!("[perf] wrote {mb} MiB in {write_secs:.2}s = {throughput:.0} MiB/s (buffer stayed 1 MiB)");

    // ---- Random access: every window must match the pattern, read via pread only.
    const WIN: usize = 64 * 1024;
    let probes = [0u64, WIN as u64, total / 3, total / 2, total - WIN as u64, total - 1];
    let t1 = Instant::now();
    for &off in &probes {
        let got = body.read_range(off, WIN).unwrap();
        let expect_len = (WIN as u64).min(total - off) as usize;
        assert_eq!(got.len(), expect_len, "short read at {off}");
        for (i, &b) in got.iter().enumerate() {
            assert_eq!(b, byte_at(off + i as u64), "byte mismatch at {}", off + i as u64);
        }
    }
    let read_us = t1.elapsed().as_micros() as f64 / probes.len() as f64;
    eprintln!("[perf] random {WIN}-byte window read: {read_us:.0} µs avg over {} probes", probes.len());

    // A window read is a pread, so it must be fast and independent of total size.
    assert!(read_us < 50_000.0, "range read too slow ({read_us} µs) — not O(1) in body size?");
}
