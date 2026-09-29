//! Streaming Fast Infoset decoder (ITU-T X.891 | ISO/IEC 24824-1) → XML text.
//!
//! The decoder is incremental at the level of information items: input is
//! appended with [`Decoder::push`]; complete items are decoded and turned
//! into XML immediately, an incomplete item is rolled back (including any
//! vocabulary table additions) and retried when more bytes arrive. Memory
//! use is bounded by the vocabulary plus the largest single item.

use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    /// More input is needed to finish the current item.
    NeedMore,
    Invalid(String),
}

type Res<T> = Result<T, Error>;

fn bad<T>(msg: impl Into<String>) -> Res<T> {
    Err(Error::Invalid(msg.into()))
}

const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

#[derive(Debug, Clone, Default, PartialEq)]
struct QName {
    prefix: String,
    ns: String,
    local: String,
}

impl QName {
    fn display(&self) -> String {
        if self.prefix.is_empty() { self.local.clone() } else { format!("{}:{}", self.prefix, self.local) }
    }
}

#[derive(Default)]
struct Vocab {
    prefixes: Vec<String>,
    ns_names: Vec<String>,
    local_names: Vec<String>,
    other_ncnames: Vec<String>,
    other_uris: Vec<String>,
    attr_values: Vec<String>,
    chunks: Vec<String>,
    other_strings: Vec<String>,
    element_names: Vec<QName>,
    attr_names: Vec<QName>,
    alphabets: Vec<Vec<char>>,
    algorithms: Vec<String>,
}

/// Table lengths, for rolling back partially decoded items.
#[derive(Clone, Copy)]
struct Mark([usize; 12]);

impl Vocab {
    fn mark(&self) -> Mark {
        Mark([
            self.prefixes.len(),
            self.ns_names.len(),
            self.local_names.len(),
            self.other_ncnames.len(),
            self.other_uris.len(),
            self.attr_values.len(),
            self.chunks.len(),
            self.other_strings.len(),
            self.element_names.len(),
            self.attr_names.len(),
            self.alphabets.len(),
            self.algorithms.len(),
        ])
    }
    fn reset(&mut self, m: Mark) {
        let m = m.0;
        self.prefixes.truncate(m[0]);
        self.ns_names.truncate(m[1]);
        self.local_names.truncate(m[2]);
        self.other_ncnames.truncate(m[3]);
        self.other_uris.truncate(m[4]);
        self.attr_values.truncate(m[5]);
        self.chunks.truncate(m[6]);
        self.other_strings.truncate(m[7]);
        self.element_names.truncate(m[8]);
        self.attr_names.truncate(m[9]);
        self.alphabets.truncate(m[10]);
        self.algorithms.truncate(m[11]);
    }
}

/// Byte reader over the buffered input.
struct R<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> R<'a> {
    fn u8(&mut self) -> Res<u8> {
        let v = *self.b.get(self.p).ok_or(Error::NeedMore)?;
        self.p += 1;
        Ok(v)
    }
    fn peek(&self) -> Res<u8> {
        self.b.get(self.p).copied().ok_or(Error::NeedMore)
    }
    fn take(&mut self, n: usize) -> Res<&'a [u8]> {
        if self.b.len() - self.p < n {
            return Err(Error::NeedMore);
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    fn be32(&mut self) -> Res<usize> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as usize)
    }
    fn be16(&mut self) -> Res<usize> {
        let s = self.take(2)?;
        Ok(((s[0] as usize) << 8) | s[1] as usize)
    }
}

fn utf8(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn utf16(b: &[u8]) -> Res<String> {
    if b.len() % 2 != 0 {
        return bad("odd UTF-16 length");
    }
    let units: Vec<u16> = b.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
    Ok(String::from_utf16_lossy(&units))
}

/// Result of a non-identifying string (C.14 / C.15 / C.19).
enum NiStr {
    Str(String, bool),
    Index(usize),
    Algorithm(u8, Vec<u8>, bool),
    Alphabet(u8, Vec<u8>, bool),
    Empty,
}

const MAX_ITEM: usize = 1 << 30;

fn check_len(n: usize) -> Res<usize> {
    if n > MAX_ITEM { bad(format!("item length {n} exceeds limit")) } else { Ok(n) }
}

/// C.22: non-empty octet string starting on the 2nd bit (literal form of C.13).
fn octets_2nd(r: &mut R, b: u8) -> Res<Vec<u8>> {
    let n = match b {
        0x00..=0x3F => b as usize + 1,
        0x40 => r.u8()? as usize + 65,
        0x60 => check_len(r.be32()? + 321)?,
        _ => return bad(format!("invalid octet string length prefix {b:#04x}")),
    };
    Ok(r.take(n)?.to_vec())
}

/// C.25 integer (index) starting on the 2nd bit; `b` already read.
fn index_2nd(r: &mut R, b: u8) -> Res<usize> {
    let b = b | 0x80;
    Ok(match b {
        0x80..=0xBF => (b & 0x3F) as usize,
        0xC0..=0xDF => ((((b & 0x1F) as usize) << 8) | r.u8()? as usize) + 64,
        0xE0..=0xEF => ((((b & 0x0F) as usize) << 16) | r.be16()?) + 8256,
        _ => return bad("invalid index on 2nd bit"),
    })
}

/// C.13 identifying string (literal → added to `table`, or index into it). 0-based table.
fn istring(r: &mut R, table: &mut Vec<String>) -> Res<String> {
    let b = r.u8()?;
    if b < 0x80 {
        let s = utf8(&octets_2nd(r, b)?);
        table.push(s.clone());
        Ok(s)
    } else {
        let i = index_2nd(r, b)?;
        table.get(i).cloned().ok_or_else(|| Error::Invalid(format!("identifying string index {i} out of range")))
    }
}

/// Prefix / namespace name identifying string: index 0 is the built-in `xml` entry,
/// user entries start at index 1. `literal_ok` false for literal qualified names.
fn istring_builtin(r: &mut R, table: &mut Vec<String>, builtin: &str, literal_ok: bool) -> Res<String> {
    let b = r.u8()?;
    if b < 0x80 {
        if !literal_ok {
            return bad("literal prefix/namespace not allowed here");
        }
        let s = utf8(&octets_2nd(r, b)?);
        table.push(s.clone());
        return Ok(s);
    }
    let i = index_2nd(r, b)?;
    if i == 0 {
        return Ok(builtin.to_string());
    }
    table.get(i - 1).cloned().ok_or_else(|| Error::Invalid(format!("prefix/namespace index {i} out of range")))
}

/// C.14 non-identifying string starting on the 1st bit.
fn nistring(r: &mut R) -> Res<NiStr> {
    let b = r.u8()?;
    if b == 0xFF {
        return Ok(NiStr::Empty);
    }
    if b >= 0x80 {
        return Ok(NiStr::Index(match b {
            0x80..=0xBF => (b & 0x3F) as usize,
            0xC0..=0xDF => ((((b & 0x1F) as usize) << 8) | r.u8()? as usize) + 64,
            0xE0..=0xEF => ((((b & 0x0F) as usize) << 16) | r.be16()?) + 8256,
            _ => return bad("invalid non-identifying string index"),
        }));
    }
    let add = b & 0x40 != 0;
    let kind = b & 0x30;
    let len5 = |r: &mut R, b: u8| -> Res<usize> {
        Ok(match b & 0x0F {
            0x00..=0x07 => (b & 0x07) as usize + 1,
            0x08 => r.u8()? as usize + 9,
            0x0C => check_len(r.be32()? + 265)?,
            _ => return bad("invalid length on 5th bit"),
        })
    };
    match kind {
        0x00 => {
            let n = len5(r, b)?;
            Ok(NiStr::Str(utf8(r.take(n)?), add))
        }
        0x10 => {
            let n = len5(r, b)?;
            Ok(NiStr::Str(utf16(r.take(n)?)?, add))
        }
        _ => {
            // restricted alphabet (0x20) or encoding algorithm (0x30): 8-bit id spans two octets
            let b2 = r.u8()?;
            let id = ((b & 0x0F) << 4) | (b2 >> 4);
            let n = len5(r, b2 & 0x0F)?;
            let data = r.take(n)?.to_vec();
            if kind == 0x20 { Ok(NiStr::Alphabet(id, data, add)) } else { Ok(NiStr::Algorithm(id, data, add)) }
        }
    }
}

const NUMERIC: &str = "0123456789-+.E ";
const DATETIME: &str = "0123456789-:TZ ";

fn decode_alphabet(chars: &[char], data: &[u8]) -> Res<String> {
    if chars.len() < 2 {
        return bad("restricted alphabet needs 2+ characters");
    }
    let mut bits = 1;
    while (1usize << bits) <= chars.len() {
        bits += 1;
    }
    let term = (1usize << bits) - 1;
    let total = data.len() * 8 / bits;
    let mut out = String::new();
    let mut acc: u32 = 0;
    let mut nacc = 0;
    let mut it = data.iter();
    for _ in 0..total {
        while nacc < bits {
            acc = (acc << 8) | *it.next().unwrap_or(&0xFF) as u32;
            nacc += 8;
        }
        let v = ((acc >> (nacc - bits)) & ((1 << bits) - 1)) as usize;
        nacc -= bits;
        if bits < 8 && v == term {
            break;
        }
        out.push(*chars.get(v).ok_or_else(|| Error::Invalid("restricted alphabet value out of range".into()))?);
    }
    Ok(out)
}

fn java_float(f: f64, single: bool) -> String {
    if f.is_nan() {
        return "NaN".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    let a = f.abs();
    let s = if single { format!("{}", f as f32) } else { format!("{f}") };
    if a != 0.0 && !(1e-3..1e7).contains(&a) {
        // Java uses scientific notation outside [10^-3, 10^7)
        let e = if single { format!("{:E}", f as f32) } else { format!("{f:E}") };
        let (m, x) = e.split_once('E').unwrap_or((&e, "0"));
        let m = if m.contains('.') { m.to_string() } else { format!("{m}.0") };
        return format!("{m}E{x}");
    }
    if s.contains('.') || s.contains('e') { s } else { format!("{s}.0") }
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        s.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    s
}

/// Text form of a value encoded with a built-in algorithm (Table 10 of X.891).
fn algorithm_text(v: &Vocab, id: u8, data: &[u8]) -> Res<(String, bool)> {
    // (text, is_cdata)
    let join = |parts: Vec<String>| parts.join(" ");
    Ok(match id {
        0 => (data.iter().map(|b| format!("{b:02X}")).collect(), false),
        1 => (b64(data), false),
        2 => {
            if data.len() % 2 != 0 {
                return bad("short array length");
            }
            (join(data.chunks(2).map(|c| i16::from_be_bytes([c[0], c[1]]).to_string()).collect()), false)
        }
        3 => {
            if data.len() % 4 != 0 {
                return bad("int array length");
            }
            (join(data.chunks(4).map(|c| i32::from_be_bytes([c[0], c[1], c[2], c[3]]).to_string()).collect()), false)
        }
        4 => {
            if data.len() % 8 != 0 {
                return bad("long array length");
            }
            (join(data.chunks(8).map(|c| i64::from_be_bytes(c.try_into().unwrap()).to_string()).collect()), false)
        }
        5 => {
            let Some(first) = data.first() else { return bad("empty boolean") };
            let unused = (first >> 4) as usize;
            let total = data.len() * 8 - 4 - unused.min(data.len() * 8 - 4);
            let mut out = Vec::with_capacity(total);
            for i in 0..total {
                let bit = i + 4;
                let byte = data[bit / 8];
                out.push(if byte & (0x80 >> (bit % 8)) != 0 { "true" } else { "false" }.to_string());
            }
            (join(out), false)
        }
        6 => {
            if data.len() % 4 != 0 {
                return bad("float array length");
            }
            (join(data.chunks(4).map(|c| java_float(f32::from_be_bytes([c[0], c[1], c[2], c[3]]) as f64, true)).collect()), false)
        }
        7 => {
            if data.len() % 8 != 0 {
                return bad("double array length");
            }
            (join(data.chunks(8).map(|c| java_float(f64::from_be_bytes(c.try_into().unwrap()), false)).collect()), false)
        }
        8 => {
            if data.len() % 16 != 0 {
                return bad("uuid array length");
            }
            let mut parts = Vec::new();
            for c in data.chunks(16) {
                let h: String = c.iter().map(|b| format!("{b:02x}")).collect();
                parts.push(format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32]));
            }
            (join(parts), false)
        }
        9 => (utf8(data), true),
        10..=31 => return bad(format!("reserved encoding algorithm {id}")),
        _ => {
            // Application-defined algorithm: show the octets as base64 (the URI is in the vocabulary).
            let uri = v.algorithms.get(id as usize - 32).cloned().unwrap_or_default();
            (format!("[application encoding {uri}: base64 {}]", b64(data)), false)
        }
    })
}

fn escape_text(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#13;"),
            _ => out.push(c),
        }
    }
}

fn escape_attr(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\n' => out.push_str("&#10;"),
            '\t' => out.push_str("&#9;"),
            '\r' => out.push_str("&#13;"),
            _ => out.push(c),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Phase {
    Header,
    Properties,
    Children,
    Done,
}

pub struct Decoder {
    buf: Vec<u8>,
    pos: usize,
    phase: Phase,
    v: Vocab,
    stack: Vec<String>,
    /// A start tag was written without '>' yet (to allow `<x/>`).
    open_tag: bool,
    out: String,
    xml_decl: bool,
    root_seen: bool,
    /// Maximum nesting depth (protects against deeply nested bombs).
    pub max_depth: usize,
    /// Maximum vocabulary size (protects against table bombs).
    pub max_table: usize,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub fn new() -> Decoder {
        Decoder {
            buf: Vec::new(),
            pos: 0,
            phase: Phase::Header,
            v: Vocab::default(),
            stack: Vec::new(),
            open_tag: false,
            out: String::new(),
            xml_decl: false,
            root_seen: false,
            max_depth: 4096,
            max_table: 1 << 22,
        }
    }

    pub fn is_done(&self) -> bool {
        self.phase == Phase::Done
    }

    /// Feed input; returns the XML text produced so far.
    pub fn push(&mut self, data: &[u8]) -> Result<String, String> {
        self.buf.extend_from_slice(data);
        self.run().map_err(|e| match e {
            Error::Invalid(m) => format!("Fast Infoset: {m} (at byte {})", self.pos),
            Error::NeedMore => unreachable!(),
        })?;
        Ok(std::mem::take(&mut self.out))
    }

    /// End of input.
    pub fn finish(&mut self) -> Result<String, String> {
        if self.phase != Phase::Done {
            if self.phase == Phase::Children && !self.stack.is_empty() {
                // Truncated document: close what is open so the output stays well-formed.
                let open = self.stack.len();
                self.close_open();
                while let Some(n) = self.stack.pop() {
                    let _ = write!(self.out, "</{n}>");
                }
                let _ = write!(self.out, "\n<!-- Quena: Fast Infoset document truncated; {open} element(s) were closed automatically -->");
            } else if self.buf.len() > self.pos || self.phase != Phase::Children || !self.root_seen {
                return Err(format!("Fast Infoset: unexpected end of document (at byte {})", self.pos));
            }
        }
        Ok(std::mem::take(&mut self.out))
    }

    fn compact(&mut self) {
        if self.pos > 1 << 20 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }

    fn run(&mut self) -> Res<()> {
        loop {
            if self.phase == Phase::Done {
                self.buf.clear();
                self.pos = 0;
                return Ok(());
            }
            let mark = self.v.mark();
            let out_len = self.out.len();
            let stack_len = self.stack.len();
            let open = self.open_tag;
            let phase = self.phase;
            match self.step() {
                Ok(()) => {
                    if self.v.element_names.len() + self.v.attr_values.len() + self.v.chunks.len() + self.v.local_names.len() > self.max_table {
                        return bad("vocabulary table limit exceeded");
                    }
                    self.compact();
                }
                Err(Error::NeedMore) => {
                    // Roll back the partial item and wait for more input.
                    self.v.reset(mark);
                    self.out.truncate(out_len);
                    self.stack.truncate(stack_len);
                    self.open_tag = open;
                    self.phase = phase;
                    self.compact();
                    return Ok(());
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Decode one item at `pos`; advances `pos` only on success.
    fn step(&mut self) -> Res<()> {
        let buf = std::mem::take(&mut self.buf);
        let mut r = R { b: &buf, p: self.pos };
        let res = self.step_inner(&mut r);
        if res.is_ok() {
            self.pos = r.p;
        }
        self.buf = buf;
        res
    }

    fn step_inner(&mut self, r: &mut R) -> Res<()> {
        match self.phase {
            Phase::Header => self.header(r),
            Phase::Properties => self.properties(r),
            Phase::Children => self.child(r),
            Phase::Done => Ok(()),
        }
    }

    fn header(&mut self, r: &mut R) -> Res<()> {
        // Optional XML declaration, e.g. <?xml version='1.0' encoding='finf'?>
        if r.peek()? == b'<' {
            let rest = &r.b[r.p..];
            let Some(end) = rest.windows(2).position(|w| w == b"?>") else {
                if rest.len() > 256 {
                    return bad("invalid XML declaration");
                }
                return Err(Error::NeedMore);
            };
            r.p += end + 2;
        }
        let id = r.take(4)?;
        if id[0] != 0xE0 || id[1] != 0x00 {
            return bad("not a Fast Infoset document (missing identification E0 00)");
        }
        if id[2] != 0x00 || id[3] != 0x01 {
            return bad(format!("unsupported Fast Infoset version {:02X}{:02X}", id[2], id[3]));
        }
        self.phase = Phase::Properties;
        Ok(())
    }

    fn properties(&mut self, r: &mut R) -> Res<()> {
        let b = r.u8()?;
        if b & 0x80 != 0 {
            return bad("invalid document properties octet");
        }
        let mut version = None;
        let mut standalone = None;
        if b & 0x40 != 0 {
            // additional data
            let n = seq_len(r)?;
            for _ in 0..n {
                let b = r.u8()?;
                octets_2nd(r, b)?;
                let b = r.u8()?;
                octets_2nd(r, b)?;
            }
        }
        if b & 0x20 != 0 {
            self.initial_vocabulary(r)?;
        }
        if b & 0x10 != 0 {
            // notations
            loop {
                let x = r.u8()?;
                if x == 0xF0 {
                    break;
                }
                if x & 0xFC != 0xC0 {
                    return bad("invalid notation item");
                }
                istring(r, &mut self.v.other_ncnames)?;
                if x & 0x02 != 0 {
                    istring(r, &mut self.v.other_uris)?;
                }
                if x & 0x01 != 0 {
                    istring(r, &mut self.v.other_uris)?;
                }
            }
        }
        if b & 0x08 != 0 {
            // unparsed entities
            loop {
                let x = r.u8()?;
                if x == 0xF0 {
                    break;
                }
                if x & 0xFE != 0xD0 {
                    return bad("invalid unparsed entity item");
                }
                istring(r, &mut self.v.other_ncnames)?;
                istring(r, &mut self.v.other_uris)?;
                if x & 0x01 != 0 {
                    istring(r, &mut self.v.other_uris)?;
                }
                istring(r, &mut self.v.other_ncnames)?;
            }
        }
        if b & 0x04 != 0 {
            let x = r.u8()?;
            octets_2nd(r, x)?; // character encoding scheme
        }
        if b & 0x02 != 0 {
            standalone = Some(r.u8()? != 0);
        }
        if b & 0x01 != 0 {
            version = match nistring(r)? {
                NiStr::Str(s, add) => {
                    if add {
                        self.v.other_strings.push(s.clone());
                    }
                    Some(s)
                }
                NiStr::Index(i) => self.v.other_strings.get(i).cloned(),
                _ => None,
            };
        }
        if !self.xml_decl {
            self.xml_decl = true;
            let _ = write!(self.out, "<?xml version=\"{}\" encoding=\"UTF-8\"", version.as_deref().unwrap_or("1.0"));
            if let Some(s) = standalone {
                let _ = write!(self.out, " standalone=\"{}\"", if s { "yes" } else { "no" });
            }
            self.out.push_str("?>\n");
        }
        self.phase = Phase::Children;
        Ok(())
    }

    fn initial_vocabulary(&mut self, r: &mut R) -> Res<()> {
        let b1 = r.u8()?;
        let b2 = r.u8()?;
        if b1 & 0x10 != 0 {
            let x = r.u8()?;
            let uri = utf8(&octets_2nd(r, x)?);
            return bad(format!("external vocabulary {uri} is not available"));
        }
        if b1 & 0x08 != 0 {
            for _ in 0..seq_len(r)? {
                match nistring(r)? {
                    NiStr::Str(s, _) => self.v.alphabets.push(s.chars().collect()),
                    _ => return bad("invalid restricted alphabet"),
                }
            }
        }
        if b1 & 0x04 != 0 {
            for _ in 0..seq_len(r)? {
                let x = r.u8()?;
                self.v.algorithms.push(utf8(&octets_2nd(r, x)?));
            }
        }
        let str_table = |r: &mut R, t: &mut Vec<String>| -> Res<()> {
            for _ in 0..seq_len(r)? {
                let x = r.u8()?;
                t.push(utf8(&octets_2nd(r, x)?));
            }
            Ok(())
        };
        if b1 & 0x02 != 0 {
            str_table(r, &mut self.v.prefixes)?;
        }
        if b1 & 0x01 != 0 {
            str_table(r, &mut self.v.ns_names)?;
        }
        if b2 & 0x80 != 0 {
            str_table(r, &mut self.v.local_names)?;
        }
        if b2 & 0x40 != 0 {
            str_table(r, &mut self.v.other_ncnames)?;
        }
        if b2 & 0x20 != 0 {
            str_table(r, &mut self.v.other_uris)?;
        }
        let ni_table = |r: &mut R, t: &mut Vec<String>| -> Res<()> {
            for _ in 0..seq_len(r)? {
                match nistring(r)? {
                    NiStr::Str(s, _) => t.push(s),
                    _ => return bad("invalid table entry"),
                }
            }
            Ok(())
        };
        if b2 & 0x10 != 0 {
            ni_table(r, &mut self.v.attr_values)?;
        }
        if b2 & 0x08 != 0 {
            ni_table(r, &mut self.v.chunks)?;
        }
        if b2 & 0x04 != 0 {
            ni_table(r, &mut self.v.other_strings)?;
        }
        for (flag, attr) in [(0x02u8, false), (0x01, true)] {
            if b2 & flag == 0 {
                continue;
            }
            for _ in 0..seq_len(r)? {
                let x = r.u8()?;
                let prefix = if x & 0x02 != 0 {
                    let i = { let b = r.u8()?; index_2nd(r, b)? };
                    if i == 0 { "xml".to_string() } else { self.v.prefixes.get(i - 1).cloned().unwrap_or_default() }
                } else {
                    String::new()
                };
                let ns = if x & 0x01 != 0 {
                    let i = { let b = r.u8()?; index_2nd(r, b)? };
                    if i == 0 { XML_NS.to_string() } else { self.v.ns_names.get(i - 1).cloned().unwrap_or_default() }
                } else {
                    String::new()
                };
                let li = { let b = r.u8()?; index_2nd(r, b)? };
                let local = self.v.local_names.get(li).cloned().ok_or_else(|| Error::Invalid("surrogate local name out of range".into()))?;
                let q = QName { prefix, ns, local };
                if attr { self.v.attr_names.push(q) } else { self.v.element_names.push(q) }
            }
        }
        Ok(())
    }

    fn literal_qname(&mut self, r: &mut R, state: u8) -> Res<QName> {
        let (prefix, ns) = match state & 0x03 {
            0 => (String::new(), String::new()),
            1 => (String::new(), istring_builtin(r, &mut self.v.ns_names, XML_NS, false)?),
            2 => return bad("qualified name with prefix but without namespace"),
            _ => {
                let p = istring_builtin(r, &mut self.v.prefixes, "xml", false)?;
                let n = istring_builtin(r, &mut self.v.ns_names, XML_NS, false)?;
                (p, n)
            }
        };
        let local = istring(r, &mut self.v.local_names)?;
        Ok(QName { prefix, ns, local })
    }

    fn element_name(&mut self, r: &mut R, b: u8) -> Res<QName> {
        let low = b & 0x3F;
        let idx = match low {
            0x00..=0x1F => (low & 0x1F) as usize,
            0x20..=0x27 => ((((low & 0x07) as usize) << 8) | r.u8()? as usize) + 32,
            0x28..=0x2F => ((((low & 0x07) as usize) << 16) | r.be16()?) + 2080,
            0x30 => ((((r.u8()? & 0x0F) as usize) << 16) | r.be16()?) + 526368,
            0x3C | 0x3D | 0x3F => {
                let q = self.literal_qname(r, low)?;
                self.v.element_names.push(q.clone());
                return Ok(q);
            }
            _ => return bad(format!("invalid element name octet {b:#04x}")),
        };
        self.v.element_names.get(idx).cloned().ok_or_else(|| Error::Invalid(format!("element name index {idx} out of range")))
    }

    fn close_open(&mut self) {
        if self.open_tag {
            self.out.push('>');
            self.open_tag = false;
        }
    }

    /// End the innermost element.
    fn end_element(&mut self) {
        if let Some(name) = self.stack.pop() {
            if self.open_tag {
                self.out.push_str("/>");
                self.open_tag = false;
            } else {
                let _ = write!(self.out, "</{name}>");
            }
        }
        if self.stack.is_empty() {
            // Root closed: only comments/PIs may follow, until the document terminator.
        }
    }

    fn element(&mut self, r: &mut R, first: u8) -> Res<()> {
        if self.stack.len() >= self.max_depth {
            return bad("maximum nesting depth exceeded");
        }
        let mut has_attrs = first & 0x40 != 0;
        let mut b = first;
        let mut ns_decls: Vec<(String, String)> = Vec::new();
        if first & 0x3F == 0x38 {
            // namespace attributes
            loop {
                let x = r.u8()?;
                if x == 0xF0 {
                    break;
                }
                if x & 0xFC != 0xCC {
                    return bad("invalid namespace attribute");
                }
                let prefix = if x & 0x02 != 0 { istring_builtin(r, &mut self.v.prefixes, "xml", true)? } else { String::new() };
                let ns = if x & 0x01 != 0 { istring_builtin(r, &mut self.v.ns_names, XML_NS, true)? } else { String::new() };
                ns_decls.push((prefix, ns));
            }
            b = r.u8()?;
            if b & 0xC0 != 0 {
                return bad("invalid element after namespace attributes");
            }
        } else {
            has_attrs = first & 0x40 != 0;
        }
        let name = self.element_name(r, b & 0x3F)?;
        let mut tag = String::new();
        let _ = write!(tag, "<{}", name.display());
        for (p, n) in &ns_decls {
            if p.is_empty() {
                tag.push_str(" xmlns=\"");
            } else {
                let _ = write!(tag, " xmlns:{p}=\"");
            }
            escape_attr(n, &mut tag);
            tag.push('"');
        }
        let mut empty = false;
        if has_attrs {
            loop {
                let x = r.u8()?;
                if x == 0xF0 {
                    break;
                }
                if x == 0xFF {
                    empty = true;
                    break;
                }
                let aname = match x {
                    0x00..=0x3F => self.v.attr_names.get(x as usize).cloned(),
                    0x40..=0x5F => {
                        let i = ((((x & 0x1F) as usize) << 8) | r.u8()? as usize) + 64;
                        self.v.attr_names.get(i).cloned()
                    }
                    0x60..=0x6F => {
                        let i = ((((x & 0x0F) as usize) << 16) | r.be16()?) + 8256;
                        self.v.attr_names.get(i).cloned()
                    }
                    0x78 | 0x79 | 0x7B => {
                        let q = self.literal_qname(r, x & 0x03)?;
                        self.v.attr_names.push(q.clone());
                        Some(q)
                    }
                    _ => return bad(format!("invalid attribute octet {x:#04x}")),
                }
                .ok_or_else(|| Error::Invalid("attribute name index out of range".into()))?;
                let value = match nistring(r)? {
                    NiStr::Str(s, add) => {
                        if add {
                            self.v.attr_values.push(s.clone());
                        }
                        s
                    }
                    NiStr::Index(i) => self.v.attr_values.get(i).cloned().ok_or_else(|| Error::Invalid(format!("attribute value index {i} out of range")))?,
                    NiStr::Empty => String::new(),
                    NiStr::Algorithm(id, data, add) => {
                        let s = algorithm_text(&self.v, id, &data)?.0;
                        if add {
                            self.v.attr_values.push(s.clone());
                        }
                        s
                    }
                    NiStr::Alphabet(id, data, add) => {
                        let s = self.alphabet_text(id, &data)?;
                        if add {
                            self.v.attr_values.push(s.clone());
                        }
                        s
                    }
                };
                let _ = write!(tag, " {}=\"", aname.display());
                escape_attr(&value, &mut tag);
                tag.push('"');
            }
        }
        self.close_open();
        self.out.push_str(&tag);
        self.open_tag = true;
        self.root_seen = true;
        self.stack.push(name.display());
        if empty {
            self.end_element();
        }
        Ok(())
    }

    fn alphabet_text(&self, id: u8, data: &[u8]) -> Res<String> {
        match id {
            0 => decode_alphabet(&NUMERIC.chars().collect::<Vec<_>>(), data),
            1 => decode_alphabet(&DATETIME.chars().collect::<Vec<_>>(), data),
            2..=31 => bad(format!("reserved restricted alphabet {id}")),
            _ => {
                let a = self.v.alphabets.get(id as usize - 32).ok_or_else(|| Error::Invalid(format!("restricted alphabet {id} not defined")))?;
                decode_alphabet(a, data)
            }
        }
    }

    fn characters(&mut self, r: &mut R, b: u8) -> Res<()> {
        let add = b & 0x10 != 0;
        let (text, cdata) = match b & 0x2C {
            // index forms (0xA0-0xB8)
            x if b >= 0xA0 => {
                let _ = x;
                let i = match b {
                    0xA0..=0xAF => (b & 0x0F) as usize,
                    0xB0..=0xB3 => ((((b & 0x03) as usize) << 8) | r.u8()? as usize) + 16,
                    0xB4..=0xB7 => ((((b & 0x03) as usize) << 16) | r.be16()?) + 1040,
                    0xB8 => ((r.u8()? as usize) << 16 | r.be16()?) + 263184,
                    _ => return bad(format!("invalid character chunk octet {b:#04x}")),
                };
                (self.v.chunks.get(i).cloned().ok_or_else(|| Error::Invalid(format!("character chunk index {i} out of range")))?, false)
            }
            _ => {
                let len7 = |r: &mut R, b: u8| -> Res<usize> {
                    Ok(match b & 0x03 {
                        0 => 1,
                        1 => 2,
                        2 => r.u8()? as usize + 3,
                        _ => check_len(r.be32()? + 259)?,
                    })
                };
                match b & 0x0C {
                    0x00 => {
                        let n = len7(r, b)?;
                        (utf8(r.take(n)?), false)
                    }
                    0x04 => {
                        let n = len7(r, b)?;
                        (utf16(r.take(n)?)?, false)
                    }
                    kind => {
                        let b2 = r.u8()?;
                        let id = ((b & 0x02) << 6) | (b2 >> 2);
                        let n = len7(r, b2)?;
                        let data = r.take(n)?;
                        if kind == 0x08 { (self.alphabet_text(id, data)?, false) } else { algorithm_text(&self.v, id, data)? }
                    }
                }
            }
        };
        if add && b < 0xA0 {
            self.v.chunks.push(text.clone());
        }
        self.close_open();
        if cdata {
            self.out.push_str("<![CDATA[");
            self.out.push_str(&text.replace("]]>", "]]]]><![CDATA[>"));
            self.out.push_str("]]>");
        } else {
            escape_text(&text, &mut self.out);
        }
        Ok(())
    }

    fn other_string(&mut self, r: &mut R) -> Res<String> {
        Ok(match nistring(r)? {
            NiStr::Str(s, add) => {
                if add {
                    self.v.other_strings.push(s.clone());
                }
                s
            }
            NiStr::Index(i) => self.v.other_strings.get(i).cloned().unwrap_or_default(),
            NiStr::Empty => String::new(),
            NiStr::Algorithm(..) | NiStr::Alphabet(..) => return bad("encoding algorithm not allowed here"),
        })
    }

    fn child(&mut self, r: &mut R) -> Res<()> {
        let b = r.u8()?;
        let in_element = !self.stack.is_empty();
        match b {
            0x00..=0x7F => self.element(r, b),
            0x80..=0xBF if in_element => self.characters(r, b),
            0xC4..=0xC7 if !in_element => {
                let sys = if b & 0x02 != 0 { Some(istring(r, &mut self.v.other_uris)?) } else { None };
                let public = if b & 0x01 != 0 { Some(istring(r, &mut self.v.other_uris)?) } else { None };
                loop {
                    let x = r.peek()?;
                    if x != 0xE1 {
                        break;
                    }
                    r.u8()?;
                    self.other_string(r)?;
                }
                let t = r.u8()?;
                if t & 0xF0 != 0xF0 {
                    return bad("DTD not terminated");
                }
                self.close_open();
                // The root element name is not known here; output a comment instead of a DOCTYPE.
                let _ = writeln!(
                    self.out,
                    "<!-- DOCTYPE{}{} -->",
                    public.map(|p| format!(" PUBLIC \"{p}\"")).unwrap_or_default(),
                    sys.map(|s| format!(" SYSTEM \"{s}\"")).unwrap_or_default()
                );
                if t == 0xFF {
                    self.phase = Phase::Done;
                }
                Ok(())
            }
            0xC8..=0xCB if in_element => {
                let name = istring(r, &mut self.v.other_ncnames)?;
                if b & 0x02 != 0 {
                    istring(r, &mut self.v.other_uris)?;
                }
                if b & 0x01 != 0 {
                    istring(r, &mut self.v.other_uris)?;
                }
                self.close_open();
                let _ = write!(self.out, "&{name};");
                Ok(())
            }
            0xE1 => {
                let target = istring(r, &mut self.v.other_ncnames)?;
                let data = self.other_string(r)?;
                self.close_open();
                let _ = write!(self.out, "<?{target} {data}?>");
                if !in_element {
                    self.out.push('\n');
                }
                Ok(())
            }
            0xE2 => {
                let text = self.other_string(r)?;
                self.close_open();
                let _ = write!(self.out, "<!--{}-->", text.replace("--", "- -"));
                if !in_element {
                    self.out.push('\n');
                }
                Ok(())
            }
            0xF0 => {
                if in_element {
                    self.end_element();
                } else {
                    self.phase = Phase::Done;
                }
                Ok(())
            }
            0xFF => {
                if in_element {
                    self.end_element();
                    if self.stack.is_empty() {
                        self.phase = Phase::Done;
                    } else {
                        self.end_element();
                    }
                } else {
                    self.phase = Phase::Done;
                }
                Ok(())
            }
            _ => bad(format!("unexpected octet {b:#04x} {}", if in_element { "in element content" } else { "at document level" })),
        }
    }
}

fn seq_len(r: &mut R) -> Res<usize> {
    let b = r.u8()?;
    if b < 128 {
        Ok(b as usize + 1)
    } else {
        let hi = ((b & 0x0F) as usize) << 16;
        Ok((hi | r.be16()?) + 129)
    }
}

/// Convenience: decode a complete buffer.
pub fn decode_all(data: &[u8]) -> Result<String, String> {
    let mut d = Decoder::new();
    let mut s = d.push(data)?;
    s.push_str(&d.finish()?);
    Ok(s)
}

/// Confidence that `prefix` is a Fast Infoset document.
pub fn looks_like_fi(prefix: &[u8]) -> bool {
    if prefix.len() >= 4 && prefix[0] == 0xE0 && prefix[1] == 0x00 && prefix[2] == 0x00 && prefix[3] == 0x01 {
        return true;
    }
    if prefix.starts_with(b"<?xml") {
        let head = String::from_utf8_lossy(&prefix[..prefix.len().min(128)]).to_ascii_lowercase();
        return head.contains("finf");
    }
    false
}
