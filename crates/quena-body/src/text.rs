//! Body text in its charset: detection on the decoded body, transcoding to UTF-8 for the
//! byte-wise consumers (pretty printers, line index, search), and encoding edited text back.
//!
//! The rules which charset a body is in live in [`crate::charset`]; this module applies them.
//!
//! Charsets that are ASCII compatible (UTF-8, windows-1252, ISO-8859-x, Shift_JIS, GB18030 …)
//! are processed byte-wise: `{`, `<`, `"`, `\n` are the ASCII bytes, so the pretty printers and
//! the line index keep the original bytes and the viewer decodes them with the charset. The
//! others (UTF-16LE/BE, ISO-2022-JP) are transcoded to UTF-8 first; such output reports
//! UTF-8 as its charset (see [`crate::decode::output_charset`]).

use crate::body::Body;
use crate::charset::{self, Detected};
use crate::decode::{DeriveSpec, NoProgress, decode_prefix, parse_encodings};
pub use encoding_rs::{Encoding, UTF_8, UTF_16BE, UTF_16LE};
use std::io::{self, Read};

/// Bytes of the decoded body examined to determine its charset (the UTF-8 validity check for
/// undeclared text needs more than the 1 KiB prescan).
pub const DETECT_PREFIX: usize = 64 * 1024;

/// Must text in this charset be transcoded before byte-wise processing?
pub fn needs_transcoding(enc: &'static Encoding) -> bool {
    !enc.is_ascii_compatible()
}

/// The first `limit` bytes of a body with its Content-Encoding removed (the raw bytes when the
/// coding is unknown or decoding fails).
pub fn decoded_prefix(body: &Body, spec: &DeriveSpec, limit: usize) -> Vec<u8> {
    if let Some(ce) = spec.content_encoding.as_deref()
        && parse_encodings(ce).is_ok_and(|e| !e.is_empty())
        && let Ok(v) = decode_prefix(body, ce, limit, &NoProgress)
    {
        return v;
    }
    body.read_range(0, limit).unwrap_or_default()
}

/// Charset of a stored body (examines the decoded prefix).
pub fn detect_body(body: &Body, spec: &DeriveSpec) -> Detected {
    charset::detect(spec.content_type.as_deref(), &decoded_prefix(body, spec, DETECT_PREFIX))
}

/// Decode bytes of one piece of text (a line) without BOM handling; malformed sequences
/// become U+FFFD.
pub fn decode_piece(bytes: &[u8], enc: &'static Encoding) -> String {
    if enc == UTF_8 {
        return match std::str::from_utf8(bytes) {
            Ok(s) => s.to_string(),
            Err(_) => String::from_utf8_lossy(bytes).into_owned(),
        };
    }
    enc.decode_without_bom_handling(bytes).0.into_owned()
}

/// Encode text in `enc`; `None` if a character cannot be represented. UTF-16 is encoded
/// directly (the WHATWG encoders, like browsers, only produce UTF-8 for it).
pub fn encode(text: &str, enc: &'static Encoding) -> Option<Vec<u8>> {
    if enc == UTF_8 {
        return Some(text.as_bytes().to_vec());
    }
    if enc == UTF_16LE {
        return Some(text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect());
    }
    if enc == UTF_16BE {
        return Some(text.encode_utf16().flat_map(|u| u.to_be_bytes()).collect());
    }
    let (bytes, used, unmappable) = enc.encode(text);
    (!unmappable && used == enc).then(|| bytes.into_owned())
}

/// `content_type` with its `charset` parameter set to `name` (replaced or appended).
pub fn with_charset(content_type: &str, name: &str) -> String {
    let mut parts: Vec<String> = content_type.split(';').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        return content_type.to_string();
    }
    parts.retain(|p| !p.split_once('=').is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("charset")));
    parts.push(format!("charset={name}"));
    parts.join("; ")
}

/// Bytes for edited body text (Composer, breakpoints).
///
/// The text is encoded in the charset the message declares in its Content-Type; without a
/// declaration in the charset it was shown in (`shown`: detected from BOM or document, or
/// chosen by the user), else UTF-8. UTF-16 without a declaration gets a byte order mark, so
/// the receiver can tell. If the text has characters that charset cannot represent, it is
/// sent as UTF-8 and the second value is the Content-Type with `charset=utf-8`, which the
/// caller puts into the message (nothing is replaced by `?` or character references).
pub fn encode_edited(text: &str, content_type: Option<&str>, shown: Option<&str>) -> (Vec<u8>, Option<String>) {
    let declared = content_type.and_then(charset::header_charset).and_then(|l| charset::for_label(&l));
    let target = declared.or_else(|| shown.and_then(charset::for_label)).unwrap_or(UTF_8);
    match encode(text, target) {
        Some(mut b) => {
            if declared.is_none() && (target == UTF_16LE || target == UTF_16BE) && !text.is_empty() {
                let bom: &[u8] = if target == UTF_16LE { &[0xFF, 0xFE] } else { &[0xFE, 0xFF] };
                b.splice(0..0, bom.iter().copied());
            }
            (b, None)
        }
        None => (text.as_bytes().to_vec(), content_type.map(|c| with_charset(c, "utf-8"))),
    }
}

/// A search needle as bytes of the text's charset; `None` when it cannot occur (characters the
/// charset cannot represent) or the charset is not byte-searchable (transcode first).
pub fn encode_needle(needle: &str, enc: &'static Encoding) -> Option<Vec<u8>> {
    if needs_transcoding(enc) {
        return None;
    }
    encode(needle, enc)
}

/// Reader adapter: text in `enc` in, UTF-8 out (BOM of that charset removed, malformed
/// sequences replaced by U+FFFD). Streaming, constant memory.
pub struct Transcoder<R> {
    inner: R,
    dec: encoding_rs::Decoder,
    input: Vec<u8>,
    in_start: usize,
    in_end: usize,
    out: Vec<u8>,
    out_start: usize,
    out_end: usize,
    eof: bool,
    done: bool,
}

impl<R: Read> Transcoder<R> {
    pub fn new(inner: R, enc: &'static Encoding) -> Self {
        Transcoder {
            inner,
            dec: enc.new_decoder_with_bom_removal(),
            input: vec![0; 64 * 1024],
            in_start: 0,
            in_end: 0,
            out: vec![0; 3 * 64 * 1024 + 16],
            out_start: 0,
            out_end: 0,
            eof: false,
            done: false,
        }
    }
}

impl<R: Read> Read for Transcoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.out_start < self.out_end {
                let n = buf.len().min(self.out_end - self.out_start);
                buf[..n].copy_from_slice(&self.out[self.out_start..self.out_start + n]);
                self.out_start += n;
                return Ok(n);
            }
            if self.done || buf.is_empty() {
                return Ok(0);
            }
            if self.in_start == self.in_end && !self.eof {
                let n = loop {
                    match self.inner.read(&mut self.input) {
                        Ok(n) => break n,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e),
                    }
                };
                self.in_start = 0;
                self.in_end = n;
                self.eof = n == 0;
            }
            let (res, read, written, _) = self.dec.decode_to_utf8(&self.input[self.in_start..self.in_end], &mut self.out, self.eof);
            self.in_start += read;
            self.out_start = 0;
            self.out_end = written;
            if self.eof && res == encoding_rs::CoderResult::InputEmpty {
                self.done = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(s: &str, bom: bool) -> Vec<u8> {
        let mut v: Vec<u8> = if bom { vec![0xFF, 0xFE] } else { vec![] };
        v.extend(s.encode_utf16().flat_map(|u| u.to_le_bytes()));
        v
    }

    #[test]
    fn transcoder_streams_utf16_to_utf8() {
        let text = "{\"name\":\"Grüße 😀\",\"n\":[1,2]}\n".repeat(5000);
        let src = utf16le(&text, true);
        // Tiny reads cut surrogate pairs and code units apart.
        struct Slow<'a>(&'a [u8]);
        impl Read for Slow<'_> {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                let n = b.len().min(self.0.len()).min(3);
                b[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }
        let mut out = String::new();
        Transcoder::new(Slow(&src), UTF_16LE).read_to_string(&mut out).unwrap();
        assert_eq!(out, text);
        let mut out = Vec::new();
        Transcoder::new(&b"Gr\xfc\xdfe"[..], encoding_rs::WINDOWS_1252).read_to_end(&mut out).unwrap();
        assert_eq!(out, "Grüße".as_bytes());
        // Malformed input: replacement characters, no error.
        let mut out = String::new();
        Transcoder::new(&b"a\xffb"[..], UTF_8).read_to_string(&mut out).unwrap();
        assert_eq!(out, "a\u{fffd}b");
    }

    #[test]
    fn encoding_back() {
        let w1252 = encoding_rs::WINDOWS_1252;
        assert_eq!(encode("Grüße €", w1252).unwrap(), b"Gr\xfc\xdfe \x80");
        assert!(encode("😀", w1252).is_none());
        assert_eq!(encode("ä", UTF_16BE).unwrap(), [0x00, 0xE4]);
        // Declared charset wins; the text is encoded in it.
        assert_eq!(encode_edited("Grüße", Some("text/plain; charset=ISO-8859-1"), Some("UTF-8")), (b"Gr\xfc\xdfe".to_vec(), None));
        // Not representable: UTF-8, and the Content-Type says so.
        let (b, ct) = encode_edited("Grüße 😀", Some("text/plain; charset=ISO-8859-1"), None);
        assert_eq!(b, "Grüße 😀".as_bytes());
        assert_eq!(ct.as_deref(), Some("text/plain; charset=utf-8"));
        // Without a declaration: the charset it was shown in (XML declaration, BOM …).
        assert_eq!(encode_edited("<a>€</a>", Some("application/xml"), Some("ISO-8859-15")).0, b"<a>\xa4</a>");
        assert_eq!(encode_edited("ä", Some("text/plain"), Some("UTF-16LE")).0, [0xFF, 0xFE, 0xE4, 0x00]);
        assert_eq!(encode_edited("ä", None, None).0, "ä".as_bytes());
        assert_eq!(with_charset("text/html;charset=\"latin1\"; x=1", "utf-8"), "text/html; x=1; charset=utf-8");
    }

    #[test]
    fn needles() {
        assert_eq!(encode_needle("Grüße", encoding_rs::WINDOWS_1252).unwrap(), b"Gr\xfc\xdfe");
        assert_eq!(encode_needle("Grüße", UTF_8).unwrap(), "Grüße".as_bytes());
        assert!(encode_needle("x", UTF_16LE).is_none());
        assert!(encode_needle("€", encoding_rs::ISO_8859_2).is_none());
        assert_eq!(decode_piece(b"\xa4", encoding_rs::ISO_8859_15), "€");
    }
}
