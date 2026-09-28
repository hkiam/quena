//! Malformed input must yield errors (or best-effort output), never panics or hangs.
use fast_infoset::fi::{Decoder, decode_all};

fn corpus(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/interop/corpus/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn mutations_never_panic() {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    for name in ["soap.fi", "namespaces.fi", "attributes.fi", "primitives.fi", "misc.fi", "indexes.fi"] {
        let orig = corpus(name);
        for _ in 0..3000 {
            let mut d = orig.clone();
            let n = 1 + (rng.next() % 4) as usize;
            for _ in 0..n {
                let i = (rng.next() as usize) % d.len();
                match rng.next() % 3 {
                    0 => d[i] = rng.next() as u8,
                    1 => d[i] ^= 1 << (rng.next() % 8),
                    _ => d.truncate(i.max(4)),
                }
            }
            let r = std::panic::catch_unwind(|| decode_all(&d));
            assert!(r.is_ok(), "panic on mutated {name}");
        }
    }
}

#[test]
fn truncation_is_reported_or_closed() {
    let d = corpus("soap.fi");
    for cut in [0usize, 3, 4, 5, 20, d.len() / 2, d.len() - 1] {
        let mut dec = Decoder::new();
        let _ = dec.push(&d[..cut]);
        let r = dec.finish();
        if let Ok(s) = r {
            assert!(s.contains("truncated") || cut == d.len(), "cut {cut}: {s}");
        }
    }
}

#[test]
fn not_fast_infoset() {
    assert!(decode_all(b"<?xml version=\"1.0\"?><a/>").is_err());
    assert!(decode_all(b"hello world").is_err());
}

#[test]
fn deep_nesting_is_limited() {
    // header + no properties + 100k literal elements "a" (index reuse after first)
    let mut d = vec![0xE0, 0, 0, 1, 0x00];
    d.extend_from_slice(&[0x3C, 0x00, b'a']); // literal qname, local name "a"
    for _ in 0..100_000 {
        d.push(0x00); // element index 0 without attributes
    }
    let mut dec = Decoder::new();
    let r = dec.push(&d);
    assert!(r.is_err_and(|e| e.contains("depth")));
}
