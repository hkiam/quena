//! Streaming content decoding and derivation of body variants.

use crate::body::{Body, BodyWriter};
use crate::pretty::{self, PrettyKind};
use crate::store::{BodyStore, Variant};
use crate::{BodyError, Result};
use std::io::{self, BufWriter, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Gzip,
    Deflate,
    Brotli,
    Zstd,
    Identity,
}

/// More stacked codings than this are refused: nobody sends them legitimately, and
/// each layer is another nested decoder (stack depth, buffers, bomb multiplier).
pub const MAX_STACKED_ENCODINGS: usize = 4;

/// Absolute floor of the cap on derived output; the cap is the larger of this and
/// 4× the source size (pretty printing grows text), never above `max_derived`.
pub const MAX_DECODED_OUTPUT: u64 = 2 << 30;

/// Parse a `Content-Encoding` header value (applied in order; decode in reverse).
pub fn parse_encodings(value: &str) -> std::result::Result<Vec<Encoding>, String> {
    let mut out = Vec::new();
    for t in value.split(',').map(|t| t.trim().to_ascii_lowercase()) {
        let e = match t.as_str() {
            "" | "identity" => continue,
            "gzip" | "x-gzip" => Encoding::Gzip,
            "deflate" => Encoding::Deflate,
            "br" => Encoding::Brotli,
            "zstd" => Encoding::Zstd,
            other => return Err(other.chars().take(64).collect()),
        };
        if out.len() >= MAX_STACKED_ENCODINGS {
            return Err(format!("with more than {MAX_STACKED_ENCODINGS} stacked codings"));
        }
        out.push(e);
    }
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
            // `inner` is gone if sniffing the header failed before; don't panic on a retry.
            let Some(mut inner) = self.inner.take() else { return Err(io::Error::other("deflate stream failed")) };
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
        match self.dec.as_mut() {
            Some(d) => d.read(buf),
            None => Err(io::Error::other("deflate stream failed")),
        }
    }
}

/// Wraps the derived writer and enforces the decompression-ratio limit and the
/// absolute output cap. Once the output is truncated (cap reached, derived limit
/// or quota hit) it fails the next write so decoding stops instead of churning
/// through the rest; `stopped` tells the caller that this was a clean truncation.
struct RatioGuard<'a> {
    inner: BodyWriter,
    written: u64,
    input: &'a dyn Fn() -> u64,
    max_ratio: u64,
    max_output: u64,
    stopped: Arc<AtomicBool>,
}

impl Write for RatioGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let room = self.max_output.saturating_sub(self.written);
        if room == 0 || self.inner.body().is_truncated() {
            self.inner.add_dropped(buf.len() as u64);
            self.stopped.store(true, Ordering::Relaxed);
            return Err(io::Error::other(format!("output truncated at {} bytes", self.written)));
        }
        let n = (buf.len() as u64).min(room) as usize;
        self.written += n as u64;
        if self.written > 16 << 20 {
            let input = (self.input)().max(1);
            if self.written / input > self.max_ratio {
                return Err(io::Error::other(format!(
                    "decompression ratio above {}:1 – possible decompression bomb",
                    self.max_ratio
                )));
            }
        }
        Write::write(&mut self.inner, &buf[..n])
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
        let cfg = store.config();
        let work = move |p: &dyn Progress| -> Result<()> {
            let total = source.len();
            let src = source.stream(0, true);
            let counted = Counting { inner: src, count: 0, total, last_report: 0, progress: p };
            let consumed = Arc::new(AtomicU64::new(0));
            let tracker = TrackRead { inner: counted, consumed: consumed.clone() };
            let mut reader = decoding_reader(Box::new(tracker), &encodings);
            let input = move || consumed.load(Ordering::Relaxed);
            let stopped = Arc::new(AtomicBool::new(false));
            let guard = RatioGuard { inner: writer, written: 0, input: &input, max_ratio: cfg.max_ratio, max_output: output_cap(&cfg, total), stopped: stopped.clone() };
            let buffered = BufWriter::with_capacity(256 * 1024, guard);
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
                // Output cap reached: the partial result is kept, marked truncated.
                Err(_) if stopped.load(Ordering::Relaxed) && !p.cancelled() => Ok(()),
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
    let cfg = store.config();
    let work = move |p: &dyn Progress| -> Result<()> {
        let id = source.id();
        let limits = (cfg.max_ratio, output_cap(&cfg, source.len()));
        let r = run_derivation(&source, writer, &encodings, if v == Variant::Pretty { pretty_kind } else { None }, limits, p);
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

/// Absolute cap on derived output for a source of `source_len` bytes.
fn output_cap(cfg: &crate::BodyConfig, source_len: u64) -> u64 {
    MAX_DECODED_OUTPUT.max(source_len.saturating_mul(4)).min(cfg.max_derived)
}

fn run_derivation(
    source: &Body,
    writer: BodyWriter,
    encodings: &[Encoding],
    pretty_kind: Option<PrettyKind>,
    (max_ratio, max_output): (u64, u64),
    p: &dyn Progress,
) -> Result<()> {
    let consumed = Arc::new(AtomicU64::new(0));
    let total = source.len();
    let src = source.stream(0, true);
    let counted = Counting { inner: src, count: 0, total, last_report: 0, progress: p };
    let tracker = TrackRead { inner: counted, consumed: consumed.clone() };
    let mut reader: Box<dyn Read> = Box::new(tracker);
    for e in encodings.iter().rev() {
        reader = wrap_decoder(reader, *e);
    }
    let consumed2 = consumed.clone();
    let input = move || consumed2.load(Ordering::Relaxed);
    let stopped = Arc::new(AtomicBool::new(false));
    let guard = RatioGuard { inner: writer, written: 0, input: &input, max_ratio, max_output, stopped: stopped.clone() };
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
        // Output cap reached: the partial result is kept, marked truncated.
        Err(_) if stopped.load(Ordering::Relaxed) => Ok(()),
        Err(e) => Err(BodyError::Io(e)),
    }
}

struct TrackRead<R> {
    inner: R,
    consumed: Arc<AtomicU64>,
}
impl<R: Read> Read for TrackRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.consumed.fetch_add(n as u64, Ordering::Relaxed);
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

/// Decode (at most `limit` bytes of) a stored body in memory without creating a
/// cached variant – for searching. A decoder error after some output returns the
/// part decoded so far (truncated/corrupt streams are common); cancellation errors.
pub fn decode_prefix(source: &Body, content_encoding: &str, limit: usize, p: &dyn Progress) -> io::Result<Vec<u8>> {
    let encodings = parse_encodings(content_encoding).map_err(io::Error::other)?;
    let total = source.len();
    let counted = Counting { inner: source.stream(0, false), count: 0, total, last_report: 0, progress: p };
    let mut reader = decoding_reader(Box::new(counted), &encodings);
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    while out.len() < limit {
        let want = buf.len().min(limit - out.len());
        match reader.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if crate::is_cancelled(&e) || out.is_empty() => return Err(e),
            Err(_) => break,
        }
    }
    Ok(out)
}
