//! Character encoding of text bodies: which charset a body is in, and facts about it.
//!
//! The display (inspectors, large-text view, search) and the diagnostics use the same rules,
//! following what browsers do (WHATWG Encoding/HTML, RFC 8259 for JSON, XML 1.0 §4.3.3):
//!
//! 1. a byte order mark (UTF-8, UTF-16 LE/BE) wins;
//! 2. then the `charset` parameter of `Content-Type`;
//! 3. then the document's own declaration: `<?xml … encoding="…"?>` for XML, `<meta charset>`
//!    / `<meta http-equiv="Content-Type" content="…charset=…">` for HTML (first 1024 bytes);
//! 4. then the default of the type: JSON and XML are UTF-8 (JSON in UTF-16/32 is recognised
//!    by its NUL pattern); other text is UTF-8 when the bytes are valid UTF-8, else
//!    windows-1252 (the browsers' fallback for Western text).
//!
//! Labels are resolved with the WHATWG label table (`encoding_rs`), so `latin1` and
//! `iso-8859-1` mean windows-1252 like in browsers.

use encoding_rs::{Encoding, UTF_8, UTF_16BE, UTF_16LE, WINDOWS_1252};
use std::borrow::Cow;

/// Bytes examined for declarations (BOM, XML declaration, HTML meta) and for sniffing.
pub const PRESCAN: usize = 1024;

/// Where the effective charset came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Bom,
    Header,
    Document,
    /// No declaration: the default of the content type (or sniffed UTF-8 / UTF-16 JSON).
    Default,
    /// Chosen by the user (display override).
    User,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Bom => "bom",
            Source::Header => "header",
            Source::Document => "document",
            Source::Default => "default",
            Source::User => "user",
        }
    }
}

/// The charset of a body and how it was determined.
#[derive(Debug, Clone, PartialEq)]
pub struct Detected {
    pub encoding: &'static Encoding,
    pub source: Source,
    /// `charset` of the Content-Type as sent (may be unknown to the label table).
    pub header: Option<String>,
    /// Declaration inside the document (XML declaration or HTML meta), as written.
    pub document: Option<String>,
    /// Byte order mark found at the start.
    pub bom: Option<&'static Encoding>,
    /// Length of the BOM in bytes (to skip when decoding).
    pub bom_len: usize,
}

impl Detected {
    /// WHATWG name, e.g. `UTF-8`, `windows-1252`, `UTF-16LE`.
    pub fn name(&self) -> &'static str {
        self.encoding.name()
    }
}

/// Lower-case `type/subtype` of a Content-Type.
fn mime(content_type: Option<&str>) -> String {
    content_type.unwrap_or("").split(';').next().unwrap_or("").trim().to_ascii_lowercase()
}

pub fn is_json(mime: &str) -> bool {
    mime == "application/json" || mime.ends_with("+json") || mime == "text/json" || mime.ends_with("/json")
}

pub fn is_xml(mime: &str) -> bool {
    mime == "application/xml" || mime == "text/xml" || mime.ends_with("+xml")
}

pub fn is_html(mime: &str) -> bool {
    mime == "text/html" || mime == "application/xhtml+xml"
}

/// Is this content type text (so a charset applies)?
pub fn is_textual(content_type: Option<&str>) -> bool {
    let m = mime(content_type);
    m.starts_with("text/")
        || is_json(&m)
        || is_xml(&m)
        || matches!(
            m.as_str(),
            "application/javascript" | "application/x-javascript" | "application/ecmascript" | "application/x-www-form-urlencoded" | "application/graphql" | "image/svg+xml"
        )
}

/// The `charset` parameter of a Content-Type (unquoted, as written).
pub fn header_charset(content_type: &str) -> Option<String> {
    for p in content_type.split(';').skip(1) {
        let (k, v) = p.split_once('=')?;
        if k.trim().eq_ignore_ascii_case("charset") {
            let v = v.trim().trim_matches(|c| c == '"' || c == '\'').trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// A byte order mark at the start: the encoding and its length.
pub fn bom(bytes: &[u8]) -> Option<(&'static Encoding, usize)> {
    Encoding::for_bom(bytes)
}

/// Value of `name="…"` / `name='…'` / `name=…` after `from` in ASCII-lowered `hay`.
fn attr_value<'a>(orig: &'a str, lower: &str, name: &str) -> Option<&'a str> {
    let i = lower.find(name)?;
    let rest_l = &lower[i + name.len()..];
    let skip = rest_l.len() - rest_l.trim_start().len();
    let rest_l = rest_l.trim_start();
    if !rest_l.starts_with('=') {
        return None;
    }
    let start = i + name.len() + skip + 1;
    let tail = &orig[start..];
    let t = tail.trim_start();
    let off = start + (tail.len() - t.len());
    let s = &orig[off..];
    let (q, body) = match s.chars().next()? {
        c @ ('"' | '\'') => (Some(c), &s[1..]),
        _ => (None, s),
    };
    let end = match q {
        Some(c) => body.find(c)?,
        None => body.find(|c: char| c.is_whitespace() || c == '>' || c == ';' || c == '"' || c == '\'' || c == '/').unwrap_or(body.len()),
    };
    let v = body[..end].trim();
    (!v.is_empty()).then_some(v)
}

/// The prescan window as ASCII text: UTF-16 without BOM is folded to its low bytes, other
/// non-ASCII bytes become `?` (declarations are ASCII).
fn ascii_window(bytes: &[u8]) -> String {
    let b = &bytes[..bytes.len().min(PRESCAN)];
    // `<\0?\0` or `\0<\0?`: an XML declaration in UTF-16 without BOM.
    let utf16 = b.len() >= 4 && ((b[1] == 0 && b[3] == 0 && b[0] != 0) || (b[0] == 0 && b[2] == 0 && b[1] != 0));
    let it: Box<dyn Iterator<Item = u8>> = if utf16 { Box::new(b.iter().copied().filter(|&c| c != 0)) } else { Box::new(b.iter().copied()) };
    it.map(|c| if c.is_ascii() { c as char } else { '?' }).collect()
}

/// `encoding` of an XML declaration at the start (`<?xml version="1.0" encoding="…"?>`).
pub fn xml_declared(bytes: &[u8]) -> Option<String> {
    let text = ascii_window(bytes);
    let t = text.trim_start_matches('\u{feff}').trim_start();
    if !t.starts_with("<?xml") {
        return None;
    }
    let decl = &t[..t.find("?>")?];
    let lower = decl.to_ascii_lowercase();
    attr_value(decl, &lower, "encoding").map(str::to_string)
}

/// Charset of an HTML `<meta charset>` or `<meta http-equiv="Content-Type" content="…">`
/// within the first 1024 bytes.
pub fn html_declared(bytes: &[u8]) -> Option<String> {
    let text = ascii_window(bytes);
    let lower = text.to_ascii_lowercase();
    let mut from = 0;
    while let Some(i) = lower[from..].find("<meta") {
        let start = from + i;
        let end = lower[start..].find('>').map(|e| start + e).unwrap_or(lower.len());
        let (tag, tag_l) = (&text[start..end], &lower[start..end]);
        if let Some(v) = attr_value(tag, tag_l, "charset") {
            return Some(v.to_string());
        }
        if tag_l.contains("http-equiv")
            && let Some(c) = attr_value(tag, tag_l, "content")
            && let Some(cs) = header_charset(c)
        {
            return Some(cs);
        }
        from = end.max(start + 5);
    }
    None
}

/// JSON without BOM in UTF-16/32 (RFC 8259 §8.1 / RFC 4627 §3 detection by NUL pattern).
fn json_utf16(bytes: &[u8]) -> Option<&'static Encoding> {
    if bytes.len() < 4 {
        return None;
    }
    match (bytes[0] == 0, bytes[1] == 0, bytes[2] == 0, bytes[3] == 0) {
        (true, false, true, false) => Some(UTF_16BE),
        (false, true, false, true) => Some(UTF_16LE),
        _ => None, // UTF-32 is not supported by the WHATWG table; shown as bytes
    }
}

/// Encoding for a label (WHATWG table); `None` for unknown labels.
pub fn for_label(label: &str) -> Option<&'static Encoding> {
    Encoding::for_label(label.trim().as_bytes())
}

/// Determine the charset of a body from its Content-Type and its first bytes (at least
/// [`PRESCAN`] bytes when available; more makes the UTF-8 validity check more reliable).
pub fn detect(content_type: Option<&str>, prefix: &[u8]) -> Detected {
    let m = mime(content_type);
    let header = content_type.and_then(header_charset);
    let document = if is_xml(&m) || (m.is_empty() && prefix.starts_with(b"<?xml")) {
        xml_declared(prefix)
    } else if is_html(&m) {
        html_declared(prefix).or_else(|| xml_declared(prefix))
    } else {
        None
    };
    let bom = bom(prefix);
    let mut d = Detected { encoding: UTF_8, source: Source::Default, header: header.clone(), document: document.clone(), bom: bom.map(|b| b.0), bom_len: bom.map(|b| b.1).unwrap_or(0) };
    if let Some((e, _)) = bom {
        d.encoding = e;
        d.source = Source::Bom;
        return d;
    }
    if let Some(e) = header.as_deref().and_then(for_label) {
        // A document that declares UTF-16 while the header says otherwise is still read by
        // the header (browsers do the same); the diagnostics report the conflict.
        d.encoding = e;
        d.source = Source::Header;
        return d;
    }
    if let Some(e) = document.as_deref().and_then(for_label) {
        // An ASCII-compatible declaration inside a document cannot really be UTF-16.
        d.encoding = if e == UTF_16LE || e == UTF_16BE { json_utf16(prefix).unwrap_or(UTF_8) } else { e };
        d.source = Source::Document;
        return d;
    }
    if is_json(&m) || is_xml(&m) {
        d.encoding = json_utf16(prefix).unwrap_or(UTF_8);
        return d;
    }
    // Other text: UTF-8 if the bytes are valid UTF-8 (a multi-byte sequence cut at the end of
    // the prefix is fine), else the Western default.
    d.encoding = if utf8_valid_prefix(prefix) { UTF_8 } else { WINDOWS_1252 };
    d
}

/// Are these bytes valid UTF-8, allowing a sequence cut off at the very end?
pub fn utf8_valid_prefix(bytes: &[u8]) -> bool {
    match std::str::from_utf8(bytes) {
        Ok(_) => true,
        Err(e) => e.error_len().is_none() && bytes.len() - e.valid_up_to() < 4,
    }
}

/// Decode to text (BOM removed); `true` if malformed sequences were replaced by U+FFFD.
pub fn decode<'a>(bytes: &'a [u8], encoding: &'static Encoding) -> (Cow<'a, str>, bool) {
    let (text, _, errors) = encoding.decode(bytes);
    (text, errors)
}

/// Facts about the text of a body, for diagnostics (no content leaves this function).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TextFacts {
    /// `charset` parameter of the Content-Type, as sent.
    pub header: Option<String>,
    /// Declaration inside the document (XML/HTML), as written.
    pub document: Option<String>,
    /// Byte order mark (`UTF-8`, `UTF-16LE`, `UTF-16BE`).
    pub bom: Option<String>,
    /// Effective charset (WHATWG name) and where it came from (`bom`, `header`, …).
    pub effective: String,
    pub source: &'static str,
    /// The header or document names a charset the label table does not know.
    pub unknown_label: bool,
    /// Bytes examined (a prefix of the decoded body).
    pub sampled: u64,
    /// Any byte ≥ 0x80 (otherwise the charset hardly matters).
    pub non_ascii: bool,
    /// The bytes are valid UTF-8 (cut sequence at the sample end allowed).
    pub utf8_valid: bool,
    /// Malformed sequences when decoding with the effective charset.
    pub decode_errors: u32,
    /// U+FFFD already in the text (characters lost before the data was sent).
    pub replacement_chars: u32,
    /// Typical traces of UTF-8 decoded as Latin-1/windows-1252 and encoded again ("Ã¤", "â€").
    pub double_encoded: u32,
    /// NUL bytes outside UTF-16 (binary data declared as text).
    pub nul_bytes: u32,
}

/// Count "Ã¤"-style double encodings in decoded text: a lead character of a UTF-8 sequence
/// read as windows-1252 (U+00C2–U+00DF, U+00E2–U+00EF with the next char in the typical
/// continuation range).
fn count_double_encoded(text: &str) -> u32 {
    let mut n = 0u32;
    let mut it = text.chars().peekable();
    while let Some(c) = it.next() {
        let Some(&next) = it.peek() else { break };
        // Latin-1 continuation bytes 0x80–0xBF appear as U+0080–U+00BF, or in windows-1252 as
        // the punctuation it maps 0x80–0x9F to (€ ‚ ƒ „ … † ‡ ˆ ‰ Š ‹ Œ Ž ‘ ’ “ ” • – — ˜ ™ š › œ ž Ÿ).
        let cont = ('\u{80}'..='\u{bf}').contains(&next) || "€‚ƒ„…†‡ˆ‰Š‹ŒŽ‘’“”•–—˜™š›œžŸ".contains(next);
        if cont && (('\u{c2}'..='\u{df}').contains(&c) || ('\u{e2}'..='\u{ef}').contains(&c)) {
            n += 1;
            it.next();
        }
    }
    n
}

/// Examine a body prefix (decoded from Content-Encoding) for [`TextFacts`].
pub fn facts(content_type: Option<&str>, prefix: &[u8]) -> TextFacts {
    let d = detect(content_type, prefix);
    let body = trim_cut_sequence(&prefix[d.bom_len..], d.encoding);
    let (text, had_errors) = d.encoding.decode_without_bom_handling(body);
    let utf16 = d.encoding == UTF_16LE || d.encoding == UTF_16BE;
    let literal = literal_replacements(body, d.encoding);
    let produced = text.matches('\u{fffd}').count();
    let errors = if had_errors { produced.saturating_sub(literal) } else { 0 };
    let unknown = d.header.as_deref().is_some_and(|l| for_label(l).is_none()) || d.document.as_deref().is_some_and(|l| for_label(l).is_none());
    TextFacts {
        header: d.header.clone(),
        document: d.document.clone(),
        bom: d.bom.map(|e| e.name().to_string()),
        effective: d.encoding.name().to_string(),
        source: d.source.as_str(),
        unknown_label: unknown,
        sampled: prefix.len() as u64,
        non_ascii: utf16 || prefix.iter().any(|&b| b >= 0x80),
        utf8_valid: utf8_valid_prefix(prefix),
        decode_errors: errors as u32,
        replacement_chars: literal as u32,
        double_encoded: if d.encoding == UTF_8 || utf16 { count_double_encoded(&text) } else { 0 },
        nul_bytes: if utf16 { 0 } else { prefix.iter().filter(|&&b| b == 0).count() as u32 },
    }
}

/// `body` without a multi-byte sequence cut at its end (a sample boundary, not an error).
fn trim_cut_sequence<'a>(body: &'a [u8], enc: &'static Encoding) -> &'a [u8] {
    if enc == UTF_8 {
        if let Err(e) = std::str::from_utf8(body)
            && e.error_len().is_none()
        {
            return &body[..e.valid_up_to()];
        }
        body
    } else if (enc == UTF_16LE || enc == UTF_16BE) && body.len() % 2 == 1 {
        &body[..body.len() - 1]
    } else {
        body
    }
}

/// U+FFFD that is validly encoded in the bytes (part of the text itself).
fn literal_replacements(body: &[u8], enc: &'static Encoding) -> usize {
    if enc == UTF_8 {
        body.windows(3).filter(|w| *w == [0xEF, 0xBF, 0xBD]).count()
    } else if enc == UTF_16LE {
        body.chunks_exact(2).filter(|c| *c == [0xFD, 0xFF]).count()
    } else if enc == UTF_16BE {
        body.chunks_exact(2).filter(|c| *c == [0xFF, 0xFD]).count()
    } else {
        0 // single-byte and legacy multi-byte charsets cannot encode U+FFFD
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precedence() {
        let latin1 = b"Gr\xfc\xdfe"; // "Grüße" in ISO-8859-1
        let d = detect(Some("text/plain; charset=ISO-8859-1"), latin1);
        assert_eq!((d.name(), d.source), ("windows-1252", Source::Header));
        assert_eq!(decode(latin1, d.encoding).0, "Grüße");
        // BOM beats the header.
        let d = detect(Some("text/plain; charset=iso-8859-1"), b"\xEF\xBB\xBFGr\xc3\xbc\xc3\x9fe");
        assert_eq!((d.name(), d.source, d.bom_len), ("UTF-8", Source::Bom, 3));
        // XML declaration without header charset.
        let x = b"<?xml version='1.0' encoding=\"ISO-8859-15\"?><a>\xa4</a>";
        let d = detect(Some("application/xml"), x);
        assert_eq!((d.name(), d.source, d.document.as_deref()), ("ISO-8859-15", Source::Document, Some("ISO-8859-15")));
        assert_eq!(decode(x, d.encoding).0, "<?xml version='1.0' encoding=\"ISO-8859-15\"?><a>€</a>");
        // HTML meta.
        let h = b"<!doctype html><html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=windows-1252\"></head>\x80";
        assert_eq!(detect(Some("text/html"), h).source, Source::Document);
        assert_eq!(detect(Some("text/html"), b"<meta charset=utf-8>").name(), "UTF-8");
        // Defaults.
        assert_eq!(detect(Some("application/json"), "{\"a\":\"ä\"}".as_bytes()).name(), "UTF-8");
        assert_eq!(detect(Some("application/json"), b"{\0\"\0a\0\"\0").name(), "UTF-16LE");
        assert_eq!(detect(Some("text/plain"), b"Gr\xfc\xdfe").name(), "windows-1252");
        assert_eq!(detect(Some("text/plain"), "Grüße".as_bytes()).name(), "UTF-8");
        assert_eq!(detect(None, "Grüße".as_bytes()).name(), "UTF-8");
        // latin1 labels are windows-1252 like in browsers; unknown labels fall through.
        assert_eq!(detect(Some("text/plain; charset=\"latin1\""), b"x").name(), "windows-1252");
        assert_eq!(detect(Some("text/plain; charset=bogus"), "ü".as_bytes()).source, Source::Default);
        // UTF-16 XML without BOM.
        let u16: Vec<u8> = "<?xml version=\"1.0\" encoding=\"UTF-16\"?><a/>".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let d = detect(Some("application/xml"), &u16);
        assert_eq!((d.name(), d.document.as_deref()), ("UTF-16LE", Some("UTF-16")));
    }

    #[test]
    fn cut_sequences_are_not_errors() {
        let s = "Grüße".as_bytes();
        assert!(utf8_valid_prefix(&s[..3])); // "Gr" + first byte of ü
        let f = facts(Some("text/plain; charset=utf-8"), &s[..3]);
        assert_eq!((f.decode_errors, f.replacement_chars, f.utf8_valid), (0, 0, true));
    }

    #[test]
    fn facts_find_problems() {
        // Declared UTF-8, bytes are Latin-1.
        let f = facts(Some("text/plain; charset=utf-8"), b"Gr\xfc\xdfe");
        assert_eq!((f.effective.as_str(), f.utf8_valid, f.decode_errors), ("UTF-8", false, 2));
        // Declared Latin-1, bytes are UTF-8.
        let f = facts(Some("text/plain; charset=iso-8859-1"), "Grüße".as_bytes());
        assert!(f.utf8_valid && f.non_ascii && f.source == "header" && f.effective == "windows-1252");
        // Double encoded UTF-8 ("Ã¼" for ü, "â€“" for –).
        let f = facts(Some("application/json"), "{\"a\":\"GrÃ¼ÃŸe â€“ ok\"}".as_bytes());
        assert_eq!(f.double_encoded, 3);
        assert_eq!(facts(Some("application/json"), "{\"a\":\"Grüße – ok, Ärger Äpfel\"}".as_bytes()).double_encoded, 0);
        // Replacement characters in valid UTF-8.
        let f = facts(Some("text/plain; charset=utf-8"), "Gr\u{fffd}\u{fffd}e".as_bytes());
        assert_eq!((f.replacement_chars, f.decode_errors), (2, 0));
        // Unknown label, NUL bytes.
        let f = facts(Some("text/plain; charset=x-klingon"), b"a\0b");
        assert!(f.unknown_label && f.nul_bytes == 1);
        // UTF-16 with BOM is fine.
        let u: Vec<u8> = [0xFF, 0xFE].into_iter().chain("Grüße".encode_utf16().flat_map(|c| c.to_le_bytes())).collect();
        let f = facts(Some("text/plain"), &u);
        assert_eq!((f.effective.as_str(), f.bom.as_deref(), f.decode_errors, f.nul_bytes), ("UTF-16LE", Some("UTF-16LE"), 0, 0));
    }

    #[test]
    fn never_panics() {
        for ct in [None, Some(""), Some("text/html; charset="), Some("application/xml;charset='"), Some(";;;charset")] {
            for b in [&b""[..], b"<", b"<?xml", b"<?xml encoding=", b"<meta charset", b"\xff\xfe\x00", b"\x00\x00\x00", &[0xc3][..]] {
                let _ = detect(ct, b);
                let _ = facts(ct, b);
            }
        }
    }
}
