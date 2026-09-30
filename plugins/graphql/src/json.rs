//! Minimal JSON reader and pretty printer (no dependencies, keeps key order).
//! The same file is used by the `jwt` and `graphql` plugins.
//!
//! Malformed input never panics; nesting is limited. In lenient mode a document
//! cut off at the end (a truncated body) is closed and reported as `truncated`.

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// Number as written (keeps precision and form).
    Num(String),
    Str(String),
    Arr(Vec<Value>),
    Obj(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Num(n) => n.parse().ok(),
            _ => None,
        }
    }
}

const MAX_DEPTH: usize = 128;

struct Parser<'a> {
    b: &'a [u8],
    o: usize,
    lenient: bool,
    truncated: bool,
}

type R<T> = Result<T, String>;

impl Parser<'_> {
    fn ws(&mut self) {
        while let Some(c) = self.b.get(self.o) {
            if !matches!(c, b' ' | b'\t' | b'\n' | b'\r') {
                break;
            }
            self.o += 1;
        }
    }
    fn eof(&mut self) -> R<()> {
        if self.lenient {
            self.truncated = true;
            Ok(())
        } else {
            Err("unexpected end of JSON".into())
        }
    }
    fn err<T>(&self, what: &str) -> R<T> {
        Err(format!("invalid JSON at byte {}: {what}", self.o))
    }
    fn value(&mut self, depth: usize) -> R<Value> {
        if depth > MAX_DEPTH {
            return self.err("nested too deeply");
        }
        self.ws();
        let Some(&c) = self.b.get(self.o) else {
            self.eof()?;
            return Ok(Value::Null);
        };
        match c {
            b'{' => {
                self.o += 1;
                let mut m = Vec::new();
                loop {
                    self.ws();
                    match self.b.get(self.o) {
                        None => {
                            self.eof()?;
                            return Ok(Value::Obj(m));
                        }
                        Some(b'}') => {
                            self.o += 1;
                            return Ok(Value::Obj(m));
                        }
                        Some(b',') if !m.is_empty() => self.o += 1,
                        Some(b'"') if m.is_empty() => {}
                        _ => return self.err("expected ',' or '}'"),
                    }
                    self.ws();
                    match self.b.get(self.o) {
                        None => {
                            self.eof()?;
                            return Ok(Value::Obj(m));
                        }
                        Some(b'"') => {}
                        _ => return self.err("expected a key"),
                    }
                    let k = self.string()?;
                    self.ws();
                    match self.b.get(self.o) {
                        None => {
                            self.eof()?;
                            m.push((k, Value::Null));
                            return Ok(Value::Obj(m));
                        }
                        Some(b':') => self.o += 1,
                        _ => return self.err("expected ':'"),
                    }
                    let v = self.value(depth + 1)?;
                    m.push((k, v));
                    if self.truncated {
                        return Ok(Value::Obj(m));
                    }
                }
            }
            b'[' => {
                self.o += 1;
                let mut a = Vec::new();
                loop {
                    self.ws();
                    match self.b.get(self.o) {
                        None => {
                            self.eof()?;
                            return Ok(Value::Arr(a));
                        }
                        Some(b']') => {
                            self.o += 1;
                            return Ok(Value::Arr(a));
                        }
                        Some(b',') if !a.is_empty() => self.o += 1,
                        _ if a.is_empty() => {}
                        _ => return self.err("expected ',' or ']'"),
                    }
                    a.push(self.value(depth + 1)?);
                    if self.truncated {
                        return Ok(Value::Arr(a));
                    }
                }
            }
            b'"' => self.string().map(Value::Str),
            b't' => self.word("true", Value::Bool(true)),
            b'f' => self.word("false", Value::Bool(false)),
            b'n' => self.word("null", Value::Null),
            b'-' | b'0'..=b'9' => {
                let s = self.o;
                while let Some(c) = self.b.get(self.o) {
                    if !matches!(c, b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9') {
                        break;
                    }
                    self.o += 1;
                }
                let n = String::from_utf8_lossy(&self.b[s..self.o]).into_owned();
                if n.parse::<f64>().is_err() {
                    if self.o == self.b.len() && self.lenient {
                        self.truncated = true;
                        return Ok(Value::Num(n));
                    }
                    return self.err("invalid number");
                }
                Ok(Value::Num(n))
            }
            _ => self.err("unexpected character"),
        }
    }
    fn word(&mut self, w: &str, v: Value) -> R<Value> {
        let rest = &self.b[self.o..];
        if rest.starts_with(w.as_bytes()) {
            self.o += w.len();
            return Ok(v);
        }
        if w.as_bytes().starts_with(rest) {
            self.o = self.b.len();
            self.eof()?;
            return Ok(v);
        }
        self.err("unexpected word")
    }
    fn hex4(&mut self) -> Option<u32> {
        let h = self.b.get(self.o..self.o + 4)?;
        let v = u32::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok()?;
        self.o += 4;
        Some(v)
    }
    fn string(&mut self) -> R<String> {
        self.o += 1; // opening quote
        let mut out: Vec<u8> = Vec::new();
        loop {
            let Some(&c) = self.b.get(self.o) else {
                self.eof()?;
                return Ok(String::from_utf8_lossy(&out).into_owned());
            };
            self.o += 1;
            match c {
                b'"' => return Ok(String::from_utf8_lossy(&out).into_owned()),
                b'\\' => {
                    let Some(&e) = self.b.get(self.o) else {
                        self.eof()?;
                        return Ok(String::from_utf8_lossy(&out).into_owned());
                    };
                    self.o += 1;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let Some(hi) = self.hex4() else {
                                if self.b.len() - self.o < 4 && self.lenient {
                                    self.o = self.b.len();
                                    self.truncated = true;
                                    return Ok(String::from_utf8_lossy(&out).into_owned());
                                }
                                return self.err("invalid \\u escape");
                            };
                            let cp = if (0xd800..0xdc00).contains(&hi) && self.b.get(self.o..self.o + 2) == Some(b"\\u") {
                                self.o += 2;
                                match self.hex4() {
                                    Some(lo) if (0xdc00..0xe000).contains(&lo) => 0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00),
                                    _ => 0xfffd,
                                }
                            } else {
                                hi
                            };
                            char::from_u32(cp).unwrap_or('\u{fffd}')
                        }
                        _ => return self.err("invalid escape"),
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                _ => out.push(c),
            }
        }
    }
}

/// Parse a complete JSON document.
pub fn parse(b: &[u8]) -> R<Value> {
    let mut p = Parser { b, o: 0, lenient: false, truncated: false };
    let v = p.value(0)?;
    p.ws();
    if p.o != b.len() {
        return p.err("trailing data");
    }
    Ok(v)
}

/// Parse a document that may be cut off at the end; `true` when it was.
pub fn parse_lenient(b: &[u8]) -> R<(Value, bool)> {
    let mut p = Parser { b, o: 0, lenient: true, truncated: false };
    let v = p.value(0)?;
    p.ws();
    if !p.truncated && p.o != b.len() {
        return p.err("trailing data");
    }
    Ok((v, p.truncated))
}

pub fn quote(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Single-line JSON.
pub fn compact(v: &Value) -> String {
    let mut s = String::new();
    write(v, None, 0, &mut s);
    s
}

/// Indented JSON (two spaces).
pub fn pretty(v: &Value) -> String {
    let mut s = String::new();
    write(v, Some(2), 0, &mut s);
    s
}

fn write(v: &Value, indent: Option<usize>, level: usize, out: &mut String) {
    let nl = |out: &mut String, level: usize| {
        if let Some(i) = indent {
            out.push('\n');
            out.extend(std::iter::repeat_n(' ', i * level));
        }
    };
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Num(n) => out.push_str(n),
        Value::Str(s) => quote(s, out),
        Value::Arr(a) if a.is_empty() => out.push_str("[]"),
        Value::Obj(m) if m.is_empty() => out.push_str("{}"),
        Value::Arr(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                    if indent.is_none() {
                        out.push(' ');
                    }
                }
                nl(out, level + 1);
                write(x, indent, level + 1, out);
            }
            nl(out, level);
            out.push(']');
        }
        Value::Obj(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                    if indent.is_none() {
                        out.push(' ');
                    }
                }
                nl(out, level + 1);
                quote(k, out);
                out.push_str(": ");
                write(x, indent, level + 1, out);
            }
            nl(out, level);
            out.push('}');
        }
    }
}
