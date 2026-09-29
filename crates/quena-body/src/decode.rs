//! Streaming content decoding and derivation of body variants.

use crate::body::{Body, BodyWriter};
use crate::pretty::{self, PrettyKind};
use crate::store::{BodyStore, Variant};
use crate::{BodyError, Result};
use std::io::{self, BufWriter, Read, Write};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Gzip,
    Deflate,
    Brotli,
    Zstd,
    Identity,
}

/// Parse a `Content-Encoding` header value (applied in order; decode in reverse).
pub fn parse_encodings(value: &str) -> std::result::Result<Vec<Encoding>, String> {
    let mut out = Vec::new();
    for t in value.split(',').map(|t| t.trim().to_ascii_lowercase()) {
        out.push(match t.as_str() {
            "" | "identity" => Encoding::Identity,
            "gzip" | "x-gzip" => Encoding::Gzip,
            "deflate" => Encoding::Deflate,
            "br" => Encoding::Brotli,
            "zstd" => Encoding::Zstd,
            other => return Err(other.to_string()),
        });
    }
    out.retain(|e| *e != Encoding::Identity);
    Ok(out)
}

/// Progress/cancel callbacks for long running derivations.
pub trait Progress: Send + Sync {
    fn cancelled(&self) -> bool;
    fn progress(&self, done: u64, total: u64);
}

pub struct NoProgress;
impl Progress for NoProgress {
    fn cancelled(&self) -> bool {
        false
    }
    fn progress(&self, _: u64, _: u64) {}
}

/// Reader that counts consumed bytes and reports progress.
struct Counting<'a, R> {
    inner: R,
    count: u64,
    total: u64,
    last_report: u64,
    progress: &'a dyn Progress,
}

impl<R: Read> Read for Counting<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.progress.cancelled() {
            return Err(crate::cancelled_io());
        }
        let n = self.inner.read(buf)?;
        self.count += n as u64;
        if self.count - self.last_report > 1 << 20 {
            self.last_report = self.count;
            self.progress.progress(self.count, self.total);
        }
        Ok(n)
    }
}

/// Wrap `r` with decoders for `encodings` (applied in header order).
pub fn decoding_reader<'a>(mut r: Box<dyn Read + 'a>, encodings: &[Encoding]) -> Box<dyn Read + 'a> {
    for e in encodings.iter().rev() {
        r = wrap_decoder(r, *e);
    }
    r
}

fn wrap_decoder<'a>(r: Box<dyn Read + 'a>, e: Encoding) -> Box<dyn Read + 'a> {
    match e {
        Encoding::Gzip => Box::new(flate2::read::MultiGzDecoder::new(r)),
        Encoding::Deflate => Box::new(DeflateAuto::new(r)),
        Encoding::Brotli => Box::new(brotli::Decompressor::new(r, 64 * 1024)),
        Encoding::Zstd => match zstd::stream::read::Decoder::new(r) {
            Ok(d) => Box::new(d),
            Err(e) => Box::new(ErrReader(Some(e))),
        },
        Encoding::Identity => r,
    }
}

struct ErrReader(Option<io::Error>);
impl Read for ErrReader {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(self.0.take().unwrap_or_else(|| io::Error::other("decoder error")))
    }
}

/// `deflate` is specified as zlib, but many servers send raw deflate. Sniff the header.
struct DeflateAuto<'a> {
    inner: Option<Box<dyn Read + 'a>>,
    dec: Option<Box<dyn Read + 'a>>,
}

impl<'a> DeflateAuto<'a> {
    fn new(r: Box<dyn Read + 'a>) -> Self {
        DeflateAuto { inner: Some(r), dec: None }
    }
}

impl Read for DeflateAuto<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.dec.is_none() {
            let mut inner = self.inner.take().expect("inner");
            let mut head = [0u8; 2];
            let mut got = 0;
            while got < 2 {
                let n = inner.read(&mut head[got..])?;
                if n == 0 {
                    break;
                }
                got += n;
            }
            let chained: Box<dyn Read> = Box::new(io::Cursor::new(head[..got].to_vec()).chain(inner));
            let zlib = got == 2 && (head[0] & 0x0f) == 8 && ((head[0] as u16) << 8 | head[1] as u16) % 31 == 0;
            self.dec = Some(if zlib {
                Box::new(flate2::read::ZlibDecoder::new(chained))
            } else {
                Box::new(flate2::read::DeflateDecoder::new(chained))
            });
        }
        self.dec.as_mut().expect("dec").read(buf)
    }
}

/// Wraps a writer and enforces the decompression-ratio limit.
struct RatioGuard<'a, W: Write> {
    inner: W,
    written: u64,
    input: &'a dyn Fn() -> u64,
    max_ratio: u64,
}

impl<W: Write> Write for RatioGuard<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written += buf.len() as u64;
        if self.written > 16 << 20 {
            let input = (self.input)().max(1);
            if self.written / input > self.max_ratio {
                return Err(io::Error::other(format!(
                    "decompression ratio above {}:1 – possible decompression bomb",
                    self.max_ratio
                )));
            }
        }
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Parameters for deriving a variant.
#[derive(Debug, Clone, Default)]
pub struct DeriveSpec {
    pub content_encoding: Option<String>,
    pub content_type: Option<String>,
}

/// Result of [`derive`]: the (possibly still growing) body plus the work to
/// run if it has not been produced yet.
pub struct Derivation {
    pub body: Body,
    pub work: Option<Box<dyn FnOnce(&dyn Progress) -> Result<()> + Send>>,
}

/// Whether a variant differs from raw for this spec.
pub fn variant_applies(spec: &DeriveSpec, v: Variant) -> bool {
    match v {
        Variant::Raw => true,
        Variant::Decoded => spec
            .content_encoding
            .as_deref()
            .map(|ce| parse_encodings(ce).map(|e| !e.is_empty()).unwrap_or(false))
            .unwrap_or(false),
        Variant::Pretty => pretty::kind_for(spec.content_type.as_deref()).is_some(),
        Variant::Plugin(_) => true,
    }
}

/// Get (or start producing) a variant of `source`.
pub fn derive(store: &Arc<BodyStore>, source: &Body, v: Variant, spec: &DeriveSpec) -> Result<Derivation> {
    if v == Variant::Raw {
        return Ok(Derivation { body: source.clone(), work: None });
    }
    let encodings = match spec.content_encoding.as_deref() {
        Some(ce) => parse_encodings(ce).map_err(|e| BodyError::Unsupported(format!("content-encoding {e}")))?,
        None => vec![],
    };
    if let Variant::Plugin(n) = v {
        let Some(plugins) = store.plugins() else { return Err(BodyError::Unsupported("plugins are not available".into())) };
        let (body, writer) = store.derived_or_create(source, v);
        let Some(writer) = writer else { return Ok(Derivation { body, work: None }) };
        let source = source.clone();
        let store2 = store.clone();
        let ct = spec.content_type.clone();
        let work = move |p: &dyn Progress| -> Result<()> {
            let total = source.len();
            let src = source.stream(0, true);
            let counted = Counting { inner: src, count: 0, total, last_report: 0, progress: p };
            let mut reader = decoding_reader(Box::new(counted), &encodings);
            let buffered = BufWriter::with_capacity(256 * 1024, writer);
            let kind = plugins.pretty_kind(n);
            let cancelled = || p.cancelled();
            let r = match kind {
                Some(k) => {
                    let mut f = pretty::Formatter::new(k, buffered);
                    plugins.decode(n, ct.as_deref(), &mut reader, &mut f, &cancelled).and_then(|_| f.finish())
                }
                None => {
                    let mut w = buffered;
                    plugins.decode(n, ct.as_deref(), &mut reader, &mut w, &cancelled).and_then(|_| w.flush())
                }
            };
            p.progress(total, total);
            match r {
                Ok(()) => Ok(()),
                Err(e) if p.cancelled() => {
                    store2.forget_derived(source.id(), v);
                    let _ = e;
                    Err(BodyError::Cancelled)
                }
                Err(e) => Err(BodyError::Io(e)),
            }
        };
        return Ok(Derivation { body, work: Some(Box::new(work)) });
    }
    let pretty_kind = pretty::kind_for(spec.content_type.as_deref());
    if v == Variant::Decoded && encodings.is_empty() {
        return Ok(Derivation { body: source.clone(), work: None });
    }
    if v == Variant::Pretty && pretty_kind.is_none() {
        return derive(store, source, Variant::Decoded, spec);
    }
    let (body, writer) = store.derived_or_create(source, v);
    let Some(writer) = writer else {
        return Ok(Derivation { body, work: None });
    };
    let source = source.clone();
    let store2 = store.clone();
    let max_ratio = store.config().max_ratio;
    let work = move |p: &dyn Progress| -> Result<()> {
        let id = source.id();
        let r = run_derivation(&source, writer, &encodings, if v == Variant::Pretty { pretty_kind } else { None }, max_ratio, p);
        if let Err(e) = &r {
            // Keep the partial output for errors (useful for inspection) but drop it when cancelled.
            if matches!(e, BodyError::Cancelled) {
                store2.forget_derived(id, v);
            }
        }
        r
    };
    Ok(Derivation { body, work: Some(Box::new(work)) })
}

fn run_derivation(
    source: &Body,
    writer: BodyWriter,
    encodings: &[Encoding],
    pretty_kind: Option<PrettyKind>,
    max_ratio: u64,
    p: &dyn Progress,
) -> Result<()> {
    let consumed = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let total = source.len();
    let src = source.stream(0, true);
    let counted = Counting { inner: src, count: 0, total, last_report: 0, progress: p };
    let tracker = TrackRead { inner: counted, consumed: consumed.clone() };
    let mut reader: Box<dyn Read> = Box::new(tracker);
    for e in encodings.iter().rev() {
        reader = wrap_decoder(reader, *e);
    }
    let consumed2 = consumed.clone();
    let input = move || consumed2.load(std::sync::atomic::Ordering::Relaxed);
    let guard = RatioGuard { inner: writer, written: 0, input: &input, max_ratio };
    let buffered = BufWriter::with_capacity(256 * 1024, guard);
    let res = match pretty_kind {
        Some(k) => {
            let mut f = pretty::Formatter::new(k, buffered);
            copy(&mut reader, &mut f).and_then(|_| f.finish())
        }
        None => {
            let mut w = buffered;
            copy(&mut reader, &mut w).and_then(|_| w.flush())
        }
    };
    p.progress(total, total);
    match res {
        Ok(()) => Ok(()),
        Err(e) if crate::is_cancelled(&e) => Err(BodyError::Cancelled),
        Err(e) => Err(BodyError::Io(e)),
    }
}

struct TrackRead<R> {
    inner: R,
    consumed: Arc<std::sync::atomic::AtomicU64>,
}
impl<R: Read> Read for TrackRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.consumed.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(n)
    }
}

fn copy(r: &mut dyn Read, w: &mut dyn Write) -> io::Result<()> {
    let mut buf = vec![0u8; 128 * 1024];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        w.write_all(&buf[..n])?;
    }
}

/// Decode a complete in-memory buffer (small bodies, tests).
pub fn decode_bytes(data: &[u8], content_encoding: &str, limit: usize) -> io::Result<Vec<u8>> {
    let encodings = parse_encodings(content_encoding).map_err(io::Error::other)?;
    let mut reader: Box<dyn Read> = Box::new(io::Cursor::new(data.to_vec()));
    for e in encodings.iter().rev() {
        reader = wrap_decoder(reader, *e);
    }
    let mut out = Vec::new();
    reader.take(limit as u64).read_to_end(&mut out)?;
    Ok(out)
}
