//! Body storage for Piper.
//!
//! Invariants (see PLAN.md §2.12):
//! * memory per body is O(1) in body size – bodies above the inline limit
//!   are written to append-only blob files from the first spilled byte on;
//! * all reads are range reads (`read_at`);
//! * derived data (decompressed, pretty printed, line index) lives in cache
//!   files and can be regenerated at any time.

mod body;
pub mod decode;
pub mod lines;
pub mod pretty;
pub mod search;
mod store;

pub use body::{Body, BodyReader, BodyWriter};
pub use store::{BodyConfig, BodyStore, StoreStats, Variant};

#[derive(Debug, thiserror::Error)]
pub enum BodyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("cancelled")]
    Cancelled,
    #[error("limit exceeded: {0}")]
    Limit(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
}

pub type Result<T> = std::result::Result<T, BodyError>;

/// Free disk space of the file system containing `path`.
pub fn free_space(path: &std::path::Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c = CString::new(path.as_os_str().as_bytes()).ok()?;
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(c.as_ptr(), &mut st) } == 0 {
            #[allow(clippy::unnecessary_cast)]
            return Some(st.f_bavail as u64 * st.f_frsize as u64);
        }
        None
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

#[derive(Debug)]
struct CancelMarker;
impl std::fmt::Display for CancelMarker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cancelled")
    }
}
impl std::error::Error for CancelMarker {}

/// I/O error signalling cancellation (not retried like `Interrupted`).
pub fn cancelled_io() -> std::io::Error {
    std::io::Error::other(CancelMarker)
}

pub fn is_cancelled(e: &std::io::Error) -> bool {
    e.get_ref().is_some_and(|r| r.is::<CancelMarker>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use decode::{DeriveSpec, NoProgress, derive};
    use std::io::Write;

    #[test]
    fn spill_and_range_read() {
        let dir = tempfile::tempdir().unwrap();
        let store = BodyStore::open(dir.path(), BodyConfig { inline_limit: 10, ..Default::default() }).unwrap();
        let mut w = store.writer();
        w.write(b"hello").unwrap();
        assert!(w.body().path().is_none());
        w.write(b" wonderful world").unwrap();
        assert!(w.body().path().is_some());
        let b = w.finish();
        assert_eq!(b.len(), 21);
        assert_eq!(b.read_range(6, 9).unwrap(), b"wonderful");
        let r = b.to_ref();
        let b2 = store.open_ref(&r);
        assert_eq!(b2.read_range(0, 100).unwrap(), b"hello wonderful world");
    }

    #[test]
    fn truncation() {
        let dir = tempfile::tempdir().unwrap();
        let store = BodyStore::open(dir.path(), BodyConfig { inline_limit: 4, max_recorded_body: 8, ..Default::default() }).unwrap();
        let mut w = store.writer();
        w.write(b"0123456789abcdef").unwrap();
        let b = w.finish();
        assert_eq!(b.len(), 8);
        assert_eq!(b.wire_len(), 16);
        assert!(b.is_truncated());
    }

    #[test]
    fn derive_gzip_pretty() {
        let dir = tempfile::tempdir().unwrap();
        let store = BodyStore::open(dir.path(), BodyConfig::default()).unwrap();
        let json = br#"{"a":[1,2,3],"b":"x"}"#;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(json).unwrap();
        let gz = enc.finish().unwrap();
        let body = store.store_bytes(&gz);
        let spec = DeriveSpec { content_encoding: Some("gzip".into()), content_type: Some("application/json".into()) };
        let d = derive(&store, &body, Variant::Decoded, &spec).unwrap();
        (d.work.unwrap())(&NoProgress).unwrap();
        assert_eq!(d.body.read_range(0, 1000).unwrap(), json);
        let p = derive(&store, &body, Variant::Pretty, &spec).unwrap();
        (p.work.unwrap())(&NoProgress).unwrap();
        let text = String::from_utf8(p.body.read_range(0, 1000).unwrap()).unwrap();
        assert!(text.starts_with("{\n  \"a\": [\n    1,"), "{text}");
        // Second request hits the cache.
        assert!(derive(&store, &body, Variant::Pretty, &spec).unwrap().work.is_none());
    }

    #[test]
    fn bomb_protection() {
        let dir = tempfile::tempdir().unwrap();
        let store = BodyStore::open(dir.path(), BodyConfig { max_ratio: 100, ..Default::default() }).unwrap();
        let zeros = vec![0u8; 64 << 20];
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(&zeros).unwrap();
        let gz = enc.finish().unwrap();
        let body = store.store_bytes(&gz);
        let spec = DeriveSpec { content_encoding: Some("gzip".into()), content_type: None };
        let d = derive(&store, &body, Variant::Decoded, &spec).unwrap();
        let r = (d.work.unwrap())(&NoProgress);
        assert!(r.is_err());
    }

    #[test]
    fn search_across_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let store = BodyStore::open(dir.path(), BodyConfig::default()).unwrap();
        let mut data = vec![b'.'; (1 << 20) - 2];
        data.extend_from_slice(b"NEEDLE");
        data.extend(vec![b'.'; 100]);
        data.extend_from_slice(b"needle");
        let body = store.store_bytes(&data);
        let mut hits = vec![];
        search::search(&body, b"needle", true, 0, &NoProgress, |o| {
            hits.push(o);
            true
        })
        .unwrap();
        assert_eq!(hits, vec![(1 << 20) - 2, (1 << 20) + 104]);
    }
}
