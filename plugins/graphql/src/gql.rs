//! GraphQL over HTTP: requests (`application/graphql` or JSON `{"query": …}`, also
//! batched arrays and persisted queries) and JSON responses (`{"data": …, "errors": […]}`)
//! as readable text. The query formatter is a small tolerant tokenizer/pretty printer:
//! it never rejects a document, unknown characters are passed through.
//!
//! Bodies are buffered up to `MAX_BUFFER`; beyond that the rest is dropped and the
//! output says so (a JSON document cut off there is closed and shown as far as it goes).

use crate::json::{self, Value};

pub const MAX_BUFFER: usize = 8 << 20;

// ------------------------------------------------------------------ tokenizer

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    /// `{ } ( ) [ ] : = @ $ ! | & , ...`
    P(&'static str),
    Name(String),
    /// Number, string or block string, verbatim.
    Lit(String),
    Comment(String),
    Other(char),
}

fn tokens(src: &str) -> Vec<Tok> {
    let c: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let word = |i: usize, w: &str| w.chars().enumerate().all(|(k, x)| c.get(i + k) == Some(&x));
    while i < c.len() {
        let ch = c[i];
        match ch {
            ' ' | '\t' | '\n' | '\r' | '\u{feff}' => i += 1,
            '#' => {
                let s = i;
                while i < c.len() && c[i] != '\n' && c[i] != '\r' {
                    i += 1;
                }
                out.push(Tok::Comment(c[s..i].iter().collect::<String>().trim_end().to_string()));
            }
            '{' | '}' | '(' | ')' | '[' | ']' | ':' | '=' | '@' | '$' | '!' | '|' | '&' | ',' => {
                out.push(Tok::P(match ch {
                    '{' => "{",
                    '}' => "}",
                    '(' => "(",
                    ')' => ")",
                    '[' => "[",
                    ']' => "]",
                    ':' => ":",
                    '=' => "=",
                    '@' => "@",
                    '$' => "$",
                    '!' => "!",
                    '|' => "|",
                    '&' => "&",
                    _ => ",",
                }));
                i += 1;
            }
            '.' if word(i, "...") => {
                out.push(Tok::P("..."));
                i += 3;
            }
            '"' if word(i, "\"\"\"") => {
                let s = i;
                i += 3;
                while i < c.len() && !word(i, "\"\"\"") {
                    i += if word(i, "\\\"\"\"") { 4 } else { 1 };
                }
                i = (i + 3).min(c.len());
                out.push(Tok::Lit(c[s..i].iter().collect()));
            }
            '"' => {
                let s = i;
                i += 1;
                while i < c.len() && c[i] != '"' && c[i] != '\n' {
                    i += if c[i] == '\\' { 2 } else { 1 };
                }
                i = (i + 1).min(c.len());
                out.push(Tok::Lit(c[s..i].iter().collect::<String>().trim_end().to_string()));
            }
            '-' | '0'..='9' => {
                let s = i;
                i += 1;
                while i < c.len() && (c[i].is_ascii_alphanumeric() || c[i] == '.' || ((c[i] == '+' || c[i] == '-') && matches!(c[i - 1], 'e' | 'E'))) {
                    i += 1;
                }
                out.push(Tok::Lit(c[s..i].iter().collect()));
            }
            c0 if c0 == '_' || c0.is_ascii_alphabetic() => {
                let s = i;
                while i < c.len() && (c[i] == '_' || c[i].is_ascii_alphanumeric()) {
                    i += 1;
                }
                out.push(Tok::Name(c[s..i].iter().collect()));
            }
            _ => {
                out.push(Tok::Other(ch));
                i += 1;
            }
        }
    }
    out
}

// ------------------------------------------------------------------ formatter

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ctx {
    /// Selection set or type body: one item per line.
    Block,
    Paren,
    List,
    Object,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Sep {
    None,
    Space,
    Newline,
    Blank,
}

const DEFINITIONS: [&str; 13] =
    ["query", "mutation", "subscription", "fragment", "type", "interface", "union", "enum", "input", "scalar", "schema", "directive", "extend"];

struct Fmt {
    out: String,
    sep: Sep,
    stack: Vec<Ctx>,
    /// Number of `Block` entries in `stack`.
    blocks: usize,
}

impl Fmt {
    fn level(&self) -> usize {
        self.blocks.min(40)
    }
    fn emit(&mut self, s: &str) {
        if !self.out.is_empty() {
            match self.sep {
                Sep::None => {}
                Sep::Space => {
                    if !self.out.ends_with(['\n', ' ']) {
                        self.out.push(' ');
                    }
                }
                Sep::Newline | Sep::Blank => {
                    while self.out.ends_with(' ') {
                        self.out.pop();
                    }
                    self.out.push('\n');
                    if self.sep == Sep::Blank {
                        self.out.push('\n');
                    }
                    self.out.extend(std::iter::repeat_n(' ', 2 * self.level()));
                }
            }
        }
        self.out.push_str(s);
        self.sep = Sep::Space;
    }
    fn at_least(&mut self, s: Sep) {
        self.sep = self.sep.max(s);
    }
}

fn is_p(t: Option<&Tok>, p: &str) -> bool {
    matches!(t, Some(Tok::P(x)) if *x == p)
}

fn is_name(t: Option<&Tok>, n: &str) -> bool {
    matches!(t, Some(Tok::Name(x)) if x == n)
}

/// Does token `i` start an `argument: value` / `$var: Type` / `field: value` pair?
fn starts_key(t: &[Tok], i: usize) -> bool {
    match &t[i] {
        Tok::Name(_) => is_p(t.get(i + 1), ":"),
        Tok::P("$") => matches!(t.get(i + 1), Some(Tok::Name(_))) && is_p(t.get(i + 2), ":"),
        _ => false,
    }
}

fn ends_value(t: Option<&Tok>) -> bool {
    matches!(t, Some(Tok::Name(_) | Tok::Lit(_) | Tok::P("]") | Tok::P("}")))
}

fn starts_value(t: &Tok) -> bool {
    matches!(t, Tok::Name(_) | Tok::Lit(_) | Tok::P("[") | Tok::P("{") | Tok::P("$"))
}

/// Upper bound for formatted output: indentation can blow a document of nested braces up
/// ~80×, so the output is capped at 4× the input plus 1 MiB, and never more than 16 MiB.
pub fn output_cap(input_len: usize) -> usize {
    input_len.saturating_mul(4).saturating_add(1 << 20).min(16 << 20)
}

/// Pretty-print a GraphQL document (two-space indentation, one selection per line).
/// Stops at [`output_cap`] and says so at the end.
pub fn format_query(src: &str) -> String {
    format_query_capped(src, output_cap(src.len()))
}

/// [`format_query`] with an explicit output limit in bytes.
pub fn format_query_capped(src: &str, cap: usize) -> String {
    let t = tokens(src);
    let mut f = Fmt { out: String::with_capacity(src.len() + src.len() / 2), sep: Sep::None, stack: Vec::new(), blocks: 0 };
    let mut prev: Option<&Tok> = None;
    let mut prev2: Option<&Tok> = None;
    let mut stopped = false;
    for (i, tok) in t.iter().enumerate() {
        if f.out.len() > cap {
            stopped = true;
            break;
        }
        let top = f.stack.last().copied();
        let inline = matches!(top, Some(Ctx::Paren | Ctx::List | Ctx::Object));
        // Separators between list items and arguments are optional in GraphQL; add them.
        if inline && !matches!(prev, Some(Tok::P("(" | "{" | "[" | "," | ":" | "=" | "$" | "@" | "!")) | None) {
            let key = matches!(top, Some(Ctx::Paren | Ctx::Object)) && starts_key(&t, i);
            let item = top == Some(Ctx::List) && starts_value(tok) && ends_value(prev);
            if key || item {
                f.sep = Sep::None;
                f.emit(",");
            }
        }
        match tok {
            Tok::Comment(c) => {
                f.at_least(Sep::Newline);
                f.emit(c);
                f.sep = Sep::Newline;
                continue; // comments do not count as previous token
            }
            Tok::P("{") => {
                let object = inline || is_p(prev, ":") || is_p(prev, "=");
                f.emit("{");
                if object {
                    f.stack.push(Ctx::Object);
                    f.sep = Sep::None;
                } else {
                    f.stack.push(Ctx::Block);
                    f.blocks += 1;
                    f.sep = Sep::Newline;
                }
            }
            Tok::P("}") => match f.stack.last() {
                Some(Ctx::Block) => {
                    f.stack.pop();
                    f.blocks -= 1;
                    f.sep = Sep::Newline;
                    f.emit("}");
                    f.sep = if f.stack.is_empty() { Sep::Blank } else { Sep::Newline };
                }
                Some(Ctx::Object) => {
                    f.stack.pop();
                    f.sep = Sep::None;
                    f.emit("}");
                }
                _ => {
                    // Unbalanced: print as-is.
                    f.at_least(Sep::Newline);
                    f.emit("}");
                }
            },
            Tok::P("(") => {
                f.sep = Sep::None;
                f.emit("(");
                f.stack.push(Ctx::Paren);
                f.sep = Sep::None;
            }
            Tok::P("[") => {
                f.emit("[");
                f.stack.push(Ctx::List);
                f.sep = Sep::None;
            }
            Tok::P(close @ (")" | "]")) => {
                f.sep = Sep::None;
                f.emit(close);
                let want = if *close == ")" { Ctx::Paren } else { Ctx::List };
                if f.stack.last() == Some(&want) {
                    f.stack.pop();
                }
            }
            Tok::P(p @ (":" | "!")) => {
                f.sep = Sep::None;
                f.emit(p);
            }
            Tok::P(",") => {
                if matches!(top, Some(Ctx::Block) | None) {
                    continue; // one item per line instead
                }
                f.sep = Sep::None;
                f.emit(",");
            }
            Tok::P(p @ ("@" | "$")) => {
                if top == Some(Ctx::Block) && *p == "@" && is_p(prev, "...") {
                    f.sep = Sep::Space;
                }
                f.emit(p);
                f.sep = Sep::None;
            }
            Tok::P("...") => {
                if top == Some(Ctx::Block) {
                    f.at_least(Sep::Newline);
                }
                f.emit("...");
                f.sep = if is_name(t.get(i + 1), "on") || is_p(t.get(i + 1), "@") || is_p(t.get(i + 1), "{") { Sep::Space } else { Sep::None };
            }
            Tok::P(p) => f.emit(p),
            Tok::Name(n) => {
                let continues = matches!(prev, Some(Tok::P(":" | "@" | "..." | "$" | "=" | "|" | "&" | "(" | "[")))
                    || (is_name(prev, "on") && is_p(prev2, "..."))
                    || prev.is_none();
                match top {
                    Some(Ctx::Block) if !continues => f.at_least(Sep::Newline),
                    None if !continues && DEFINITIONS.contains(&n.as_str()) && !is_name(prev, "extend") => f.at_least(Sep::Blank),
                    _ => {}
                }
                f.emit(n);
            }
            Tok::Lit(l) => {
                if top == Some(Ctx::Block) && !matches!(prev, Some(Tok::P(":" | "=" | "(" | "["))) {
                    f.at_least(Sep::Newline);
                }
                f.emit(l);
            }
            Tok::Other(c) => f.emit(&c.to_string()),
        }
        prev2 = prev;
        prev = Some(tok);
    }
    if stopped {
        let mut end = cap.min(f.out.len());
        while !f.out.is_char_boundary(end) {
            end -= 1;
        }
        f.out.truncate(end);
        let mut out = f.out.trim_end().to_string();
        out.push_str(&format!(
            "\n\n# [Quena] Formatting stopped after {cap} bytes of output.\n# The document has {} bytes; the rest is not shown.",
            src.len()
        ));
        return out;
    }
    f.out.trim_end().to_string()
}

// ------------------------------------------------------------------ document outline

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Definition {
    /// `query`, `mutation`, `subscription`, `fragment`, `type` …
    pub kind: String,
    pub name: Option<String>,
}

impl Definition {
    fn label(&self) -> String {
        match &self.name {
            Some(n) => format!("{} {n}", self.kind),
            None => format!("{} (anonymous)", self.kind),
        }
    }
}

/// Top-level definitions of a document; a bare `{ … }` is an anonymous query.
pub fn definitions(src: &str) -> Vec<Definition> {
    let t = tokens(src);
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut i = 0;
    while i < t.len() {
        match &t[i] {
            Tok::P("{" | "(" | "[") => {
                if depth == 0 && matches!(t[i], Tok::P("{")) && (i == 0 || matches!(t[..i].iter().rev().find(|x| !matches!(x, Tok::Comment(_))), Some(Tok::P("}")) | None)) {
                    out.push(Definition { kind: "query".into(), name: None });
                }
                depth += 1;
            }
            Tok::P("}" | ")" | "]") => depth = depth.saturating_sub(1),
            Tok::Name(k) if depth == 0 && DEFINITIONS.contains(&k.as_str()) && k != "extend" => {
                let name = match t.get(i + 1) {
                    Some(Tok::Name(n)) if k != "schema" => Some(n.clone()),
                    Some(Tok::P("@")) if k == "directive" => match t.get(i + 2) {
                        Some(Tok::Name(n)) => Some(format!("@{n}")),
                        _ => None,
                    },
                    _ => None,
                };
                let kind = if is_name(i.checked_sub(1).and_then(|p| t.get(p)), "extend") { format!("extend {k}") } else { k.clone() };
                out.push(Definition { kind, name });
            }
            _ => {}
        }
        i += 1;
    }
    out
}

fn is_operation(d: &Definition) -> bool {
    matches!(d.kind.as_str(), "query" | "mutation" | "subscription")
}

// ------------------------------------------------------------------ detection

fn base_type(ct: Option<&str>) -> String {
    ct.map(|c| c.split(';').next().unwrap_or("").trim().to_ascii_lowercase()).unwrap_or_default()
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// Does the JSON string starting at `p` (after the quote) begin like a GraphQL document?
fn graphql_string_at(p: &[u8]) -> bool {
    let mut i = 0;
    // skip whitespace and escaped whitespace (\n, \t, \r)
    loop {
        match p.get(i) {
            Some(b' ' | b'\t') => i += 1,
            Some(b'\\') if matches!(p.get(i + 1), Some(b'n' | b't' | b'r')) => i += 2,
            _ => break,
        }
    }
    let rest = &p[i.min(p.len())..];
    if rest.is_empty() {
        return true; // cut off by the prefix limit
    }
    if rest[0] == b'{' || rest[0] == b'#' {
        return true;
    }
    ["query", "mutation", "subscription", "fragment"].iter().any(|k| {
        rest.starts_with(k.as_bytes()) && rest.get(k.len()).is_none_or(|c| !(c.is_ascii_alphanumeric() || *c == b'_'))
    })
}

/// Confidence 0..=100. `prefix` holds the first bytes of the body.
pub fn detect(content_type: Option<&str>, prefix: &[u8]) -> u8 {
    let ct = base_type(content_type);
    if ct.contains("graphql") {
        return 100;
    }
    if !(ct.is_empty() || ct.contains("json") || ct.starts_with("text/plain")) {
        return 0;
    }
    let s = prefix.iter().position(|c| !matches!(c, b' ' | b'\t' | b'\r' | b'\n')).map_or(&[][..], |i| &prefix[i..]);
    let s = s.strip_prefix(b"\xef\xbb\xbf").unwrap_or(s);
    if !matches!(s.first(), Some(b'{' | b'[')) {
        return 0;
    }
    // Request: "query": "<graphql>"
    let mut from = 0;
    while let Some(k) = find(&s[from..], b"\"query\"") {
        let mut j = from + k + 7;
        while matches!(s.get(j), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            j += 1;
        }
        if s.get(j) == Some(&b':') {
            j += 1;
            while matches!(s.get(j), Some(b' ' | b'\t' | b'\r' | b'\n')) {
                j += 1;
            }
            if s.get(j) == Some(&b'"') && graphql_string_at(&s[j + 1..]) {
                return 95;
            }
        }
        from += k + 7;
    }
    // Automatic persisted query (hash instead of the document).
    if find(s, b"\"persistedQuery\"").is_some() && find(s, b"\"sha256Hash\"").is_some() {
        return 85;
    }
    // Response: GraphQL errors carry locations/path; data rarely comes without __typename.
    if find(s, b"\"errors\"").is_some() && find(s, b"\"message\"").is_some() && (find(s, b"\"locations\"").is_some() || find(s, b"\"path\"").is_some()) {
        return 60;
    }
    if s.starts_with(b"{\"data\"") && find(s, b"\"__typename\"").is_some() {
        return 55;
    }
    0
}

// ------------------------------------------------------------------ rendering

fn heading(out: &mut String, title: &str) {
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(&format!("--- {title} ---\n"));
}

fn is_request(v: &Value) -> bool {
    v.get("query").and_then(Value::as_str).is_some() || v.get("extensions").and_then(|e| e.get("persistedQuery")).is_some()
}

fn is_response(v: &Value) -> bool {
    matches!(v, Value::Obj(_)) && (v.get("data").is_some() || matches!(v.get("errors"), Some(Value::Arr(_))))
}

/// JSON that may have been sent as a string (some clients stringify `variables`).
fn json_block(v: &Value) -> String {
    if let Value::Str(s) = v
        && let Ok(inner) = json::parse(s.as_bytes())
    {
        return json::pretty(&inner);
    }
    json::pretty(v)
}

fn render_document(q: &str, operation_name: Option<&str>, out: &mut String) {
    let defs = definitions(q);
    let ops: Vec<&Definition> = defs.iter().filter(|d| is_operation(d)).collect();
    let selected = match operation_name {
        Some(n) => ops.iter().find(|d| d.name.as_deref() == Some(n)).copied(),
        None if ops.len() == 1 => Some(ops[0]),
        None => None,
    };
    match (selected, operation_name) {
        (Some(d), _) => out.push_str(&format!("Operation: {}\n", d.label())),
        (None, Some(n)) => out.push_str(&format!("Operation: {n} (operationName; not defined in the document)\n")),
        (None, None) if ops.len() > 1 => out.push_str("Operation: none selected (several operations, no operationName)\n"),
        (None, None) if defs.is_empty() => out.push_str("Operation: none found in the document\n"),
        (None, None) => {}
    }
    if defs.len() > 1 || (defs.len() == 1 && !is_operation(&defs[0])) {
        let list: Vec<String> = defs.iter().map(Definition::label).collect();
        out.push_str(&format!("Document: {}\n", list.join(", ")));
    }
    heading(out, "Query");
    out.push_str(&format_query(q));
    out.push('\n');
}

fn render_request(v: &Value, out: &mut String) {
    let name = v.get("operationName").and_then(Value::as_str).filter(|s| !s.is_empty());
    match v.get("query").and_then(Value::as_str) {
        Some(q) => render_document(q, name, out),
        None => {
            if let Some(n) = name {
                out.push_str(&format!("Operation: {n}\n"));
            }
            let hash = v.get("extensions").and_then(|e| e.get("persistedQuery")).and_then(|p| p.get("sha256Hash")).and_then(Value::as_str);
            out.push_str(&format!("Persisted query{}: the document is not sent, only its hash.\n", hash.map(|h| format!(" {h}")).unwrap_or_default()));
        }
    }
    if let Some(vars) = v.get("variables").filter(|x| **x != Value::Null) {
        heading(out, "Variables");
        out.push_str(&json_block(vars));
        out.push('\n');
    }
    if let Some(ext) = v.get("extensions").filter(|x| **x != Value::Null) {
        heading(out, "Extensions");
        out.push_str(&json_block(ext));
        out.push('\n');
    }
    if let Value::Obj(m) = v {
        let rest: Vec<(String, Value)> =
            m.iter().filter(|(k, _)| !matches!(k.as_str(), "query" | "operationName" | "variables" | "extensions")).cloned().collect();
        if !rest.is_empty() {
            heading(out, "Other fields");
            out.push_str(&json::pretty(&Value::Obj(rest)));
            out.push('\n');
        }
    }
}

fn path_text(p: &Value) -> String {
    match p {
        Value::Arr(a) => a
            .iter()
            .map(|x| match x {
                Value::Str(s) => s.clone(),
                other => json::compact(other),
            })
            .collect::<Vec<_>>()
            .join("."),
        other => json::compact(other),
    }
}

fn render_response(v: &Value, out: &mut String) {
    let errors = match v.get("errors") {
        Some(Value::Arr(a)) => a.as_slice(),
        _ => &[],
    };
    let data = v.get("data");
    let data_state = match data {
        None => "no data",
        Some(Value::Null) => "data null",
        Some(_) if errors.is_empty() => "data",
        Some(_) => "partial data",
    };
    out.push_str(&format!("Response: {}, {data_state}\n", match errors.len() {
        0 => "no errors".to_string(),
        1 => "1 error".to_string(),
        n => format!("{n} errors"),
    }));
    if !errors.is_empty() {
        heading(out, "Errors");
        for (i, e) in errors.iter().enumerate() {
            let msg = e.get("message").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| json::compact(e));
            out.push_str(&format!("{}. {msg}\n", i + 1));
            if let Some(Value::Arr(locs)) = e.get("locations") {
                for l in locs {
                    match (l.get("line").and_then(Value::as_f64), l.get("column").and_then(Value::as_f64)) {
                        (Some(line), Some(col)) => out.push_str(&format!("   at line {line}, column {col}\n")),
                        _ => out.push_str(&format!("   at {}\n", json::compact(l))),
                    }
                }
            }
            if let Some(p) = e.get("path") {
                out.push_str(&format!("   path: {}\n", path_text(p)));
            }
            if let Some(x) = e.get("extensions") {
                out.push_str(&format!("   extensions: {}\n", json::compact(x)));
            }
        }
    }
    if let Some(d) = data {
        heading(out, "Data");
        out.push_str(&json::pretty(d));
        out.push('\n');
    }
    if let Some(x) = v.get("extensions") {
        heading(out, "Extensions");
        out.push_str(&json::pretty(x));
        out.push('\n');
    }
}

fn batch(items: &[Value], what: &str, one: fn(&Value, &mut String), out: &mut String) {
    out.push_str(&format!("Batch of {} {what}s\n", items.len()));
    for (i, v) in items.iter().enumerate() {
        out.push_str(&format!("\n=== {} {} of {} ===\n", capitalize(what), i + 1, items.len()));
        one(v, out);
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next().map(|f| f.to_ascii_uppercase().to_string() + c.as_str()).unwrap_or_default()
}

fn looks_like_document(s: &str) -> bool {
    let t = s.trim_start_matches(['\u{feff}', ' ', '\t', '\r', '\n']);
    t.starts_with('{') || t.starts_with('#') || definitions(t).iter().any(|d| t.starts_with(d.kind.split(' ').next().unwrap_or("")))
}

/// Render a (possibly truncated) body. `total` is the full body size in bytes.
pub fn render(content_type: Option<&str>, body: &[u8], total: u64) -> Result<String, String> {
    let ct = base_type(content_type);
    let mut out = String::new();
    if total > body.len() as u64 {
        out.push_str(&format!("Note: the body has {total} bytes; only the first {} are shown.\n", body.len()));
    }
    let text = String::from_utf8_lossy(body);
    let text = text.trim_start_matches('\u{feff}');
    let first = text.trim_start().chars().next();
    let graphql_ct = ct == "application/graphql" || ct == "application/x-graphql";
    let raw_document = graphql_ct && first != Some('[') || !matches!(first, Some('{' | '['));
    if raw_document {
        if !looks_like_document(text) {
            return Err("not a GraphQL document".into());
        }
        render_document(text, None, &mut out);
        return Ok(out);
    }
    let (v, cut) = match json::parse_lenient(text.as_bytes()) {
        Ok(x) => x,
        // `application/graphql` with a document that starts with `{` (shorthand query).
        Err(_) if graphql_ct => {
            render_document(text, None, &mut out);
            return Ok(out);
        }
        Err(e) => return Err(e),
    };
    if cut {
        out.push_str("Note: the JSON is cut off; it is shown as far as it goes.\n");
    }
    match &v {
        Value::Obj(_) if is_request(&v) => render_request(&v, &mut out),
        Value::Obj(_) if is_response(&v) => render_response(&v, &mut out),
        Value::Arr(a) if !a.is_empty() && a.iter().all(is_request) => batch(a, "request", render_request, &mut out),
        Value::Arr(a) if !a.is_empty() && a.iter().all(is_response) => batch(a, "response", render_response, &mut out),
        _ => return Err("no GraphQL request or response in this JSON".into()),
    }
    Ok(out)
}

/// Streaming session: buffers up to `MAX_BUFFER`, renders on `finish`.
pub struct Decoder {
    content_type: Option<String>,
    buf: Vec<u8>,
    total: u64,
    cap: usize,
}

impl Decoder {
    pub fn new(content_type: Option<String>) -> Decoder {
        Decoder::with_limit(content_type, MAX_BUFFER)
    }
    pub fn with_limit(content_type: Option<String>, cap: usize) -> Decoder {
        Decoder { content_type, buf: Vec::new(), total: 0, cap }
    }
    pub fn push(&mut self, chunk: &[u8]) -> Result<String, String> {
        self.total += chunk.len() as u64;
        let room = self.cap.saturating_sub(self.buf.len());
        self.buf.extend_from_slice(&chunk[..chunk.len().min(room)]);
        Ok(String::new())
    }
    pub fn finish(&mut self) -> Result<String, String> {
        let body = std::mem::take(&mut self.buf);
        render(self.content_type.as_deref(), &body, self.total)
    }
}
