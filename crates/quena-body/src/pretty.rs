//! Streaming pretty printers for JSON and XML. Constant memory, any input size.
//! Malformed input is passed through best-effort (never fails on syntax).

use std::io::{self, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrettyKind {
    Json,
    Xml,
}

/// Map a content type to a pretty printer.
pub fn kind_for(content_type: Option<&str>) -> Option<PrettyKind> {
    let ct = content_type?.split(';').next()?.trim().to_ascii_lowercase();
    if ct.ends_with("json")
        || ct.ends_with("+json")
        || ct == "text/json"
        || ct.contains("javascript-json")
    {
        Some(PrettyKind::Json)
    } else if ct.ends_with("xml") || ct.ends_with("+xml") || ct == "application/soap+xml" {
        Some(PrettyKind::Xml)
    } else {
        None
    }
}

const MAX_INDENT: usize = 64;
const INDENT: &[u8] = b"                                                                                                                                ";

fn indent(w: &mut dyn Write, depth: usize) -> io::Result<()> {
    w.write_all(b"\n")?;
    w.write_all(&INDENT[..depth.min(MAX_INDENT) * 2])
}

pub struct Formatter<W: Write> {
    kind: PrettyKind,
    out: W,
    json: JsonState,
    xml: XmlState,
}

impl<W: Write> Formatter<W> {
    pub fn new(kind: PrettyKind, out: W) -> Self {
        Formatter {
            kind,
            out,
            json: JsonState::default(),
            xml: XmlState::default(),
        }
    }
    pub fn finish(mut self) -> io::Result<()> {
        if self.kind == PrettyKind::Xml {
            self.xml.flush_ws(&mut self.out)?;
        }
        self.out.write_all(b"\n")?;
        self.out.flush()
    }
}

impl<W: Write> Write for Formatter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.kind {
            PrettyKind::Json => self.json.feed(buf, &mut self.out)?,
            PrettyKind::Xml => self.xml.feed(buf, &mut self.out)?,
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

#[derive(Default)]
struct JsonState {
    in_string: bool,
    escape: bool,
    depth: usize,
    pending_open: bool,
}

impl JsonState {
    fn feed(&mut self, buf: &[u8], out: &mut dyn Write) -> io::Result<()> {
        let mut i = 0;
        while i < buf.len() {
            if self.in_string {
                // Copy the string run in one go.
                let start = i;
                while i < buf.len() {
                    let b = buf[i];
                    i += 1;
                    if self.escape {
                        self.escape = false;
                    } else if b == b'\\' {
                        self.escape = true;
                    } else if b == b'"' {
                        self.in_string = false;
                        break;
                    }
                }
                out.write_all(&buf[start..i])?;
                continue;
            }
            let b = buf[i];
            i += 1;
            if b.is_ascii_whitespace() {
                continue;
            }
            if self.pending_open {
                self.pending_open = false;
                if b == b'}' || b == b']' {
                    self.depth = self.depth.saturating_sub(1);
                    out.write_all(&[b])?;
                    continue;
                }
                indent(out, self.depth)?;
            }
            match b {
                b'{' | b'[' => {
                    out.write_all(&[b])?;
                    self.depth += 1;
                    self.pending_open = true;
                }
                b'}' | b']' => {
                    self.depth = self.depth.saturating_sub(1);
                    indent(out, self.depth)?;
                    out.write_all(&[b])?;
                }
                b',' => {
                    out.write_all(b",")?;
                    indent(out, self.depth)?;
                }
                b':' => out.write_all(b": ")?,
                b'"' => {
                    self.in_string = true;
                    out.write_all(b"\"")?;
                }
                _ => {
                    // Literal run (numbers, true/false/null, garbage).
                    let start = i - 1;
                    while i < buf.len()
                        && !matches!(buf[i], b'{' | b'}' | b'[' | b']' | b',' | b':' | b'"')
                        && !buf[i].is_ascii_whitespace()
                    {
                        i += 1;
                    }
                    out.write_all(&buf[start..i])?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Default, PartialEq, Eq, Clone, Copy, Debug)]
enum XmlMode {
    #[default]
    Text,
    /// Just saw '<', deciding the tag type.
    TagStart,
    /// Inside `<name ...>` (open or close tag).
    Tag,
    /// `<?...?>` or `<!DOCTYPE ...>`
    Decl,
    Comment,
    Cdata,
}

#[derive(Default, PartialEq, Eq, Clone, Copy, Debug)]
enum Last {
    #[default]
    Start,
    Open,
    Text,
    Other,
}

#[derive(Default)]
struct XmlState {
    mode: XmlMode,
    depth: usize,
    closing: bool,
    quote: u8,
    prev: u8,
    prev2: u8,
    bracket: usize,
    last: Last,
    /// Buffered whitespace between tags (bounded).
    ws: Vec<u8>,
    /// Buffered bytes of the tag start (`<!-`, `<![CDATA` …) until the type is known.
    head: Vec<u8>,
}

impl XmlState {
    fn flush_ws(&mut self, out: &mut dyn Write) -> io::Result<()> {
        if !self.ws.is_empty() && self.last == Last::Text {
            out.write_all(&self.ws)?;
        }
        self.ws.clear();
        Ok(())
    }

    fn feed(&mut self, buf: &[u8], out: &mut dyn Write) -> io::Result<()> {
        let mut i = 0;
        while i < buf.len() {
            let b = buf[i];
            i += 1;
            match self.mode {
                XmlMode::Text => {
                    if b == b'<' {
                        self.mode = XmlMode::TagStart;
                        self.head.clear();
                        self.head.push(b);
                        continue;
                    }
                    if b.is_ascii_whitespace() {
                        if self.ws.len() < 4096 {
                            self.ws.push(b);
                        } else {
                            // Huge whitespace run inside text: flush it.
                            self.flush_ws(out)?;
                        }
                        continue;
                    }
                    if self.last != Last::Text {
                        if self.last != Last::Open {
                            indent(out, self.depth)?;
                        }
                        self.ws.clear();
                    } else {
                        out.write_all(&self.ws)?;
                        self.ws.clear();
                    }
                    self.last = Last::Text;
                    // Copy the text run.
                    let start = i - 1;
                    while i < buf.len() && buf[i] != b'<' && !buf[i].is_ascii_whitespace() {
                        i += 1;
                    }
                    out.write_all(&buf[start..i])?;
                }
                XmlMode::TagStart => {
                    self.head.push(b);
                    let h = self.head.as_slice();
                    let decided = if h.len() == 2 {
                        match b {
                            b'/' => Some(XmlMode::Tag),
                            b'?' => Some(XmlMode::Decl),
                            b'!' => None,
                            _ => Some(XmlMode::Tag),
                        }
                    } else if h.starts_with(b"<!--") {
                        Some(XmlMode::Comment)
                    } else if h.starts_with(b"<![CDATA[") {
                        Some(XmlMode::Cdata)
                    } else if b"<![CDATA[".starts_with(h) || b"<!--".starts_with(h) {
                        None
                    } else {
                        Some(XmlMode::Decl)
                    };
                    if let Some(m) = decided {
                        self.closing = self.head.get(1) == Some(&b'/');
                        let inline_close = self.closing && self.last == Last::Text;
                        let empty_elem_close = self.closing && self.last == Last::Open;
                        if self.closing {
                            self.depth = self.depth.saturating_sub(1);
                        }
                        self.ws.clear();
                        if m == XmlMode::Cdata {
                            // CDATA behaves like text.
                            if self.last != Last::Text && self.last != Last::Open {
                                indent(out, self.depth)?;
                            }
                            self.last = Last::Text;
                        } else if !(inline_close || empty_elem_close) && self.last != Last::Start {
                            indent(out, self.depth)?;
                        }
                        out.write_all(&self.head)?;
                        self.head.clear();
                        self.mode = m;
                        self.quote = 0;
                        self.bracket = 0;
                        self.prev = 0;
                        self.prev2 = 0;
                        // A tag that consists of "<x" and whose '>' arrives later.
                        if m == XmlMode::Tag && b == b'>' {
                            self.end_tag();
                        }
                    }
                }
                XmlMode::Tag => {
                    out.write_all(&[b])?;
                    if self.quote != 0 {
                        if b == self.quote {
                            self.quote = 0;
                        }
                    } else if b == b'"' || b == b'\'' {
                        self.quote = b;
                    } else if b == b'>' {
                        self.end_tag();
                    }
                    self.prev = b;
                }
                XmlMode::Decl => {
                    out.write_all(&[b])?;
                    if self.quote != 0 {
                        if b == self.quote {
                            self.quote = 0;
                        }
                    } else if b == b'"' || b == b'\'' {
                        self.quote = b;
                    } else if b == b'[' {
                        self.bracket += 1;
                    } else if b == b']' {
                        self.bracket = self.bracket.saturating_sub(1);
                    } else if b == b'>' && self.bracket == 0 {
                        self.mode = XmlMode::Text;
                        self.last = Last::Other;
                    }
                }
                XmlMode::Comment | XmlMode::Cdata => {
                    out.write_all(&[b])?;
                    let end = if self.mode == XmlMode::Comment {
                        b'-'
                    } else {
                        b']'
                    };
                    if b == b'>' && self.prev == end && self.prev2 == end {
                        if self.mode == XmlMode::Comment {
                            self.last = Last::Other;
                        }
                        self.mode = XmlMode::Text;
                    }
                    self.prev2 = self.prev;
                    self.prev = b;
                }
            }
        }
        Ok(())
    }

    fn end_tag(&mut self) {
        self.mode = XmlMode::Text;
        if self.closing {
            self.last = Last::Other;
        } else if self.prev == b'/' {
            self.last = Last::Other; // self-closing
        } else {
            self.depth += 1;
            self.last = Last::Open;
        }
    }
}

/// Pretty print a complete buffer (tests, small bodies).
pub fn pretty_bytes(kind: PrettyKind, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut f = Formatter::new(kind, &mut out);
        let _ = f.write_all(data);
        let _ = f.finish();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pj(s: &str) -> String {
        String::from_utf8(pretty_bytes(PrettyKind::Json, s.as_bytes())).unwrap()
    }
    fn px(s: &str) -> String {
        String::from_utf8(pretty_bytes(PrettyKind::Xml, s.as_bytes())).unwrap()
    }

    #[test]
    fn json_basic() {
        assert_eq!(
            pj(r#"{"a":1,"b":[true,null],"c":{}}"#),
            "{\n  \"a\": 1,\n  \"b\": [\n    true,\n    null\n  ],\n  \"c\": {}\n}\n"
        );
    }

    #[test]
    fn json_strings_with_specials() {
        assert_eq!(pj(r#"{"a":"x,{\"}"}"#), "{\n  \"a\": \"x,{\\\"}\"\n}\n");
    }

    #[test]
    fn json_chunked_equals_whole() {
        let src = r#"{"a":[1,2,{"x":"y\"z"}],"b":"long string, with: stuff"}"#;
        let whole = pretty_bytes(PrettyKind::Json, src.as_bytes());
        let mut out = Vec::new();
        {
            let mut f = Formatter::new(PrettyKind::Json, &mut out);
            for b in src.as_bytes() {
                f.write_all(&[*b]).unwrap();
            }
            f.finish().unwrap();
        }
        assert_eq!(whole, out);
    }

    #[test]
    fn xml_basic() {
        assert_eq!(
            px(
                r#"<?xml version="1.0"?><a x="1>2"><b>text</b><c/><d></d><!-- c --><e><![CDATA[<x>]]></e></a>"#
            ),
            "<?xml version=\"1.0\"?>\n<a x=\"1>2\">\n  <b>text</b>\n  <c/>\n  <d></d>\n  <!-- c -->\n  <e><![CDATA[<x>]]></e>\n</a>\n"
        );
    }

    #[test]
    fn xml_chunked_equals_whole() {
        let src =
            r#"<s:Envelope xmlns:s="u"><s:Body><m:x a='q'>hello world</m:x></s:Body></s:Envelope>"#;
        let whole = pretty_bytes(PrettyKind::Xml, src.as_bytes());
        let mut out = Vec::new();
        {
            let mut f = Formatter::new(PrettyKind::Xml, &mut out);
            for b in src.as_bytes() {
                f.write_all(&[*b]).unwrap();
            }
            f.finish().unwrap();
        }
        assert_eq!(
            String::from_utf8(whole).unwrap(),
            String::from_utf8(out).unwrap()
        );
    }
}
