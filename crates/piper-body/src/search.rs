//! Streaming byte search inside a body.

use crate::body::Body;
use crate::decode::Progress;
use crate::{BodyError, Result};

/// Find occurrences of `needle`, reporting absolute offsets via `on_hit`.
/// `on_hit` returns false to stop. ASCII case-insensitive if `ignore_case`.
pub fn search(
    body: &Body,
    needle: &[u8],
    ignore_case: bool,
    from: u64,
    p: &dyn Progress,
    mut on_hit: impl FnMut(u64) -> bool,
) -> Result<u64> {
    if needle.is_empty() {
        return Ok(0);
    }
    let needle: Vec<u8> = if ignore_case { needle.to_ascii_lowercase() } else { needle.to_vec() };
    let finder = memchr::memmem::Finder::new(&needle);
    let overlap = needle.len() - 1;
    let mut buf = vec![0u8; (1 << 20) + overlap];
    let mut pos = from;
    let mut hits = 0u64;
    let total = body.len();
    while pos < total {
        if p.cancelled() {
            return Err(BodyError::Cancelled);
        }
        let n = body.read_at(pos, &mut buf)?;
        if n == 0 {
            break;
        }
        let hay = &mut buf[..n];
        if ignore_case {
            hay.make_ascii_lowercase();
        }
        for i in finder.find_iter(hay) {
            hits += 1;
            if !on_hit(pos + i as u64) {
                return Ok(hits);
            }
        }
        if pos + n as u64 >= total {
            break;
        }
        // Step back by `overlap` so matches across chunk borders are found once.
        pos += (n - overlap.min(n - 1)) as u64;
        p.progress(pos, total);
    }
    Ok(hits)
}
