//! Expression language.
//!
//! ```text
//! expr    := or
//! or      := and ( ("or" | "||") and )*
//! and     := unary ( ("and" | "&&") unary )*
//! unary   := ("not" | "!") unary | "(" expr ")" | cmp | word
//! cmp     := field op value
//! op      := == | != | ~= (glob) | ~ (contains) | !~ | =~ (regex) | < | <= | > | >=
//! word    := bare text -> URL contains (case-insensitive)
//! ```
//! Fields: host, url, path, method, status, type (content-type), process,
//! size (response), reqsize, time/duration (ms), comment, protocol, color,
//! kind, id, client, custom, decoder (reserved for decoder plugins).

use crate::{glob_match, host_without_port, parse_duration_ms, parse_size};
use quena_model::{SessionKind, SessionSummary};
use regex::Regex;

#[derive(Debug, thiserror::Error, Clone, PartialEq)]
#[error("{msg} (at {pos})")]
pub struct ParseError {
    pub msg: String,
    pub pos: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Id,
    Host,
    Url,
    Path,
    Method,
    Status,
    ContentType,
    Process,
    Size,
    ReqSize,
    Duration,
    Comment,
    Protocol,
    Color,
    Kind,
    Client,
    Custom,
    Decoder,
    /// Client connection id.
    Conn,
    Trace,
    Session,
    /// Reverse proxy entry (`via == api`).
    Via,
}

impl Field {
    fn parse(s: &str) -> Option<Field> {
        Some(match s.to_ascii_lowercase().as_str() {
            "id" | "#" => Field::Id,
            "host" => Field::Host,
            "url" => Field::Url,
            "path" => Field::Path,
            "method" | "verb" => Field::Method,
            "status" | "result" | "code" => Field::Status,
            "type" | "ctype" | "content-type" | "contenttype" | "mime" => Field::ContentType,
            "process" | "proc" => Field::Process,
            "size" | "body" | "respsize" => Field::Size,
            "reqsize" => Field::ReqSize,
            "time" | "duration" | "ms" => Field::Duration,
            "comment" | "comments" => Field::Comment,
            "protocol" | "proto" => Field::Protocol,
            "color" | "mark" | "marked" => Field::Color,
            "kind" => Field::Kind,
            "client" | "clientip" => Field::Client,
            "custom" => Field::Custom,
            "decoder" => Field::Decoder,
            "conn" | "connection" => Field::Conn,
            "trace" | "correlation" => Field::Trace,
            "session" | "sessioncookie" => Field::Session,
            "via" | "reverse" => Field::Via,
            _ => return None,
        })
    }
    fn numeric(self) -> bool {
        matches!(
            self,
            Field::Id
                | Field::Status
                | Field::Size
                | Field::ReqSize
                | Field::Duration
                | Field::Conn
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Glob,
    Contains,
    NotContains,
    Regex,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone)]
pub enum Value {
    Num(u64),
    Text(String),
    Re(Regex),
}

#[derive(Debug, Clone)]
pub enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Cmp(Field, Op, Value),
    UrlContains(String),
    True,
}

impl Expr {
    pub fn eval(&self, s: &SessionSummary) -> bool {
        match self {
            Expr::True => true,
            Expr::And(a, b) => a.eval(s) && b.eval(s),
            Expr::Or(a, b) => a.eval(s) || b.eval(s),
            Expr::Not(a) => !a.eval(s),
            Expr::UrlContains(t) => s.full_url().to_lowercase().contains(t.as_str()),
            Expr::Cmp(f, op, v) => eval_cmp(*f, *op, v, s),
        }
    }
}

fn text_of(f: Field, s: &SessionSummary) -> String {
    match f {
        Field::Host => host_without_port(if s.kind == SessionKind::Tunnel {
            &s.url
        } else {
            &s.host
        })
        .to_string(),
        Field::Url => s.full_url(),
        Field::Path => s.url.clone(),
        Field::Method => s.method.clone(),
        Field::ContentType => s.content_type.clone(),
        Field::Process => s.process.clone(),
        Field::Comment => s.comment.clone(),
        Field::Protocol => s.protocol.clone(),
        Field::Color => s.color.map(|c| c.as_str().to_string()).unwrap_or_default(),
        Field::Kind => format!("{:?}", s.kind).to_lowercase(),
        Field::Client => s.client_ip.clone(),
        Field::Custom => s.custom.clone(),
        Field::Decoder => String::new(),
        Field::Conn => s.conn.to_string(),
        Field::Trace => s.trace.clone(),
        Field::Session => s.session.clone(),
        Field::Via => s.via.clone(),
        Field::Id => s.id.to_string(),
        Field::Status => s.status.to_string(),
        Field::Size => s.response_body_len.to_string(),
        Field::ReqSize => s.request_body_len.to_string(),
        Field::Duration => s.duration_ms.map(|d| d.to_string()).unwrap_or_default(),
    }
}

fn num_of(f: Field, s: &SessionSummary) -> Option<u64> {
    Some(match f {
        Field::Id => s.id,
        Field::Status => s.status as u64,
        Field::Size => s.response_body_len,
        Field::ReqSize => s.request_body_len,
        Field::Duration => s.duration_ms? as u64,
        Field::Conn => s.conn,
        _ => return None,
    })
}

fn eval_cmp(f: Field, op: Op, v: &Value, s: &SessionSummary) -> bool {
    if let (true, Value::Num(n)) = (f.numeric(), v) {
        let Some(x) = num_of(f, s) else { return false };
        return match op {
            Op::Eq | Op::Glob | Op::Contains => x == *n,
            Op::Ne | Op::NotContains => x != *n,
            Op::Lt => x < *n,
            Op::Le => x <= *n,
            Op::Gt => x > *n,
            Op::Ge => x >= *n,
            Op::Regex => false,
        };
    }
    let t = text_of(f, s);
    match (op, v) {
        (_, Value::Re(re)) => re.is_match(&t),
        (Op::Eq, Value::Text(x)) => t.eq_ignore_ascii_case(x),
        (Op::Ne, Value::Text(x)) => !t.eq_ignore_ascii_case(x),
        (Op::Glob, Value::Text(x)) => glob_match(x, &t),
        (Op::Contains, Value::Text(x)) => t.to_lowercase().contains(x.as_str()),
        (Op::NotContains, Value::Text(x)) => !t.to_lowercase().contains(x.as_str()),
        (Op::Lt, Value::Text(x)) => t.as_str() < x.as_str(),
        (Op::Le, Value::Text(x)) => t.as_str() <= x.as_str(),
        (Op::Gt, Value::Text(x)) => t.as_str() > x.as_str(),
        (Op::Ge, Value::Text(x)) => t.as_str() >= x.as_str(),
        (_, Value::Num(n)) => t == n.to_string(),
        (Op::Regex, Value::Text(_)) => false,
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    Str(String),
    Op(&'static str),
    LParen,
    RParen,
}

fn lex(src: &str) -> Result<Vec<(Tok, usize)>, ParseError> {
    let b: Vec<char> = src.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < b.len() {
        let c = b[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        if c == '(' {
            out.push((Tok::LParen, i));
            i += 1;
        } else if c == ')' {
            out.push((Tok::RParen, i));
            i += 1;
        } else if c == '"' || c == '\'' {
            let q = c;
            i += 1;
            let mut s = String::new();
            while i < b.len() && b[i] != q {
                if b[i] == '\\' && i + 1 < b.len() {
                    i += 1;
                }
                s.push(b[i]);
                i += 1;
            }
            if i >= b.len() {
                return Err(ParseError {
                    msg: "unterminated string".into(),
                    pos: start,
                });
            }
            i += 1;
            out.push((Tok::Str(s), start));
        } else {
            let two: String = b[i..(i + 2).min(b.len())].iter().collect();
            let op = match two.as_str() {
                "==" => Some("=="),
                "!=" => Some("!="),
                "~=" => Some("~="),
                "=~" => Some("=~"),
                "!~" => Some("!~"),
                "<=" => Some("<="),
                ">=" => Some(">="),
                "&&" => Some("and"),
                "||" => Some("or"),
                _ => None,
            };
            if let Some(op) = op {
                out.push((Tok::Op(op), i));
                i += 2;
                continue;
            }
            let one = match c {
                '<' => Some("<"),
                '>' => Some(">"),
                '~' => Some("~"),
                '=' => Some("=="),
                '!' => Some("not"),
                _ => None,
            };
            if let Some(op) = one {
                out.push((Tok::Op(op), i));
                i += 1;
                continue;
            }
            let mut s = String::new();
            while i < b.len() && !b[i].is_whitespace() && !"()<>=!~\"'".contains(b[i]) {
                s.push(b[i]);
                i += 1;
            }
            out.push((Tok::Word(s), start));
        }
    }
    Ok(out)
}

/// Parentheses/`not` nesting accepted (recursive descent: each level is stack).
const MAX_DEPTH: usize = 64;
/// Terms per expression.
const MAX_TERMS: usize = 10_000;

struct Parser {
    toks: Vec<(Tok, usize)>,
    i: usize,
    len: usize,
    depth: usize,
    terms: usize,
}

/// Combine `v` (non-empty) into a balanced tree, so long `a and b and …` chains
/// don't make `eval`/drop recurse once per term. Evaluation order is unchanged.
fn balanced(mut v: Vec<Expr>, f: fn(Box<Expr>, Box<Expr>) -> Expr) -> Expr {
    if v.len() == 1 {
        return v.pop().expect("non-empty");
    }
    let right = v.split_off(v.len() / 2);
    f(Box::new(balanced(v, f)), Box::new(balanced(right, f)))
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.i).map(|t| &t.0)
    }
    fn pos(&self) -> usize {
        self.toks.get(self.i).map(|t| t.1).unwrap_or(self.len)
    }
    fn err<T>(&self, msg: &str) -> Result<T, ParseError> {
        Err(ParseError {
            msg: msg.into(),
            pos: self.pos(),
        })
    }
    fn is_kw(&self, kw: &str) -> bool {
        match self.peek() {
            Some(Tok::Word(w)) => w.eq_ignore_ascii_case(kw),
            Some(Tok::Op(o)) => *o == kw,
            _ => false,
        }
    }
    fn or(&mut self) -> Result<Expr, ParseError> {
        let mut v = vec![self.and()?];
        while self.is_kw("or") {
            self.i += 1;
            v.push(self.and()?);
        }
        Ok(balanced(v, Expr::Or))
    }
    fn and(&mut self) -> Result<Expr, ParseError> {
        let mut v = vec![self.unary()?];
        loop {
            if self.is_kw("and") {
                self.i += 1;
            } else if self.peek().is_none()
                || matches!(self.peek(), Some(Tok::RParen))
                || self.is_kw("or")
            {
                break;
            }
            // Implicit AND between adjacent terms.
            v.push(self.unary()?);
        }
        Ok(balanced(v, Expr::And))
    }
    fn unary(&mut self) -> Result<Expr, ParseError> {
        let nests = self.is_kw("not") || self.peek() == Some(&Tok::LParen);
        if nests {
            if self.depth >= MAX_DEPTH {
                return self.err(&format!("expression nested deeper than {MAX_DEPTH} levels"));
            }
            self.depth += 1;
        }
        let r = self.unary_inner();
        if nests {
            self.depth -= 1;
        }
        r
    }
    fn unary_inner(&mut self) -> Result<Expr, ParseError> {
        if self.is_kw("not") {
            self.i += 1;
            return Ok(Expr::Not(Box::new(self.unary()?)));
        }
        if !matches!(self.peek(), Some(Tok::LParen) | None) {
            self.terms += 1;
            if self.terms > MAX_TERMS {
                return self.err(&format!("more than {MAX_TERMS} terms"));
            }
        }
        match self.peek().cloned() {
            Some(Tok::LParen) => {
                self.i += 1;
                let e = self.or()?;
                if self.peek() != Some(&Tok::RParen) {
                    return self.err("expected ')'");
                }
                self.i += 1;
                Ok(e)
            }
            Some(Tok::Word(w)) => {
                self.i += 1;
                if let (Some(field), Some(Tok::Op(op))) = (Field::parse(&w), self.peek().cloned()) {
                    if op != "and" && op != "or" && op != "not" {
                        self.i += 1;
                        return self.cmp(field, op);
                    }
                }
                Ok(Expr::UrlContains(w.to_lowercase()))
            }
            Some(Tok::Str(s)) => {
                self.i += 1;
                Ok(Expr::UrlContains(s.to_lowercase()))
            }
            Some(Tok::Op(_)) => self.err("unexpected operator"),
            Some(Tok::RParen) => self.err("unexpected ')'"),
            None => self.err("unexpected end of expression"),
        }
    }
    fn cmp(&mut self, field: Field, op: &str) -> Result<Expr, ParseError> {
        let raw = match self.peek().cloned() {
            Some(Tok::Word(w)) | Some(Tok::Str(w)) => {
                self.i += 1;
                w
            }
            _ => return self.err("expected value"),
        };
        let op = match op {
            "==" => Op::Eq,
            "!=" => Op::Ne,
            "~=" => Op::Glob,
            "~" => Op::Contains,
            "!~" => Op::NotContains,
            "=~" => Op::Regex,
            "<" => Op::Lt,
            "<=" => Op::Le,
            ">" => Op::Gt,
            ">=" => Op::Ge,
            _ => return self.err("unknown operator"),
        };
        let value = if op == Op::Regex {
            Value::Re(Regex::new(&format!("(?i){raw}")).map_err(|e| ParseError {
                msg: format!("regex: {e}"),
                pos: self.pos(),
            })?)
        } else if field.numeric() {
            let n = match field {
                Field::Size | Field::ReqSize => parse_size(&raw),
                Field::Duration => parse_duration_ms(&raw),
                _ => raw.parse().ok(),
            };
            match n {
                Some(n) => Value::Num(n),
                None if field == Field::Status && raw.to_ascii_lowercase().ends_with("xx") => {
                    // status == 4xx
                    let d: u64 = raw.get(..1).unwrap_or("").parse().map_err(|_| ParseError {
                        msg: "bad status class".into(),
                        pos: self.pos(),
                    })?;
                    let lo = Expr::Cmp(Field::Status, Op::Ge, Value::Num(d * 100));
                    let hi = Expr::Cmp(Field::Status, Op::Lt, Value::Num(d * 100 + 100));
                    let both = Expr::And(Box::new(lo), Box::new(hi));
                    return Ok(match op {
                        Op::Ne => Expr::Not(Box::new(both)),
                        _ => both,
                    });
                }
                None => return self.err("expected number"),
            }
        } else {
            Value::Text(if matches!(op, Op::Contains | Op::NotContains) {
                raw.to_lowercase()
            } else {
                raw
            })
        };
        Ok(Expr::Cmp(field, op, value))
    }
}

pub fn parse(src: &str) -> Result<Expr, ParseError> {
    let toks = lex(src)?;
    if toks.is_empty() {
        return Ok(Expr::True);
    }
    let mut p = Parser {
        toks,
        i: 0,
        len: src.len(),
        depth: 0,
        terms: 0,
    };
    let e = p.or()?;
    if p.i != p.toks.len() {
        return p.err("unexpected token");
    }
    Ok(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s() -> SessionSummary {
        SessionSummary {
            id: 7,
            host: "api.company.de:443".into(),
            url: "/v1/login?x=1".into(),
            method: "POST".into(),
            status: 502,
            protocol: "HTTPS".into(),
            content_type: "application/json".into(),
            response_body_len: 20_000,
            duration_ms: Some(1200),
            conn: 1_234_567,
            trace: "4bf92f3577b34da6a3ce929d0e0e4736".into(),
            session: "JSESSIONID #1a2b3c4d".into(),
            via: "api".into(),
            ..Default::default()
        }
    }

    #[test]
    fn plan_example() {
        let e = parse(r#"host ~= "*.company.de" and method == POST and status >= 400"#).unwrap();
        assert!(e.eval(&s()));
    }

    #[test]
    fn variants() {
        let cases = [
            ("status == 5xx", true),
            ("status != 5xx", false),
            ("size > 10k and time > 1s", true),
            ("login", true),
            ("not login", false),
            ("type ~ json or host == x", true),
            ("(method == GET or method == POST) && !(status < 500)", true),
            ("url =~ 'v[0-9]/log'", true),
            ("process ~ chrome", false),
            ("conn == 1234567", true),
            ("connection > 1234567", false),
            ("trace == 4bf92f3577b34da6a3ce929d0e0e4736", true),
            ("session ~ jsessionid", true),
            ("via == api", true),
            ("reverse == other", false),
        ];
        for (src, want) in cases {
            assert_eq!(parse(src).unwrap().eval(&s()), want, "{src}");
        }
    }

    #[test]
    fn errors() {
        assert!(parse("status >= ").is_err());
        assert!(parse("(a").is_err());
        assert!(parse("size > abc").is_err());
        assert!(parse("status == äxx").is_err());
    }

    #[test]
    fn nesting_and_term_limits() {
        let deep = format!("{}a{}", "(".repeat(100_000), ")".repeat(100_000));
        assert!(parse(&deep).unwrap_err().msg.contains("nested"));
        assert!(parse(&"not ".repeat(100_000)).is_err());
        let ok = format!("{}login{}", "(".repeat(MAX_DEPTH), ")".repeat(MAX_DEPTH));
        assert!(parse(&ok).unwrap().eval(&s()));
        assert!(
            parse(&"a ".repeat(MAX_TERMS + 1))
                .unwrap_err()
                .msg
                .contains("terms")
        );
        // A long chain parses into a shallow tree: evaluating and dropping it is cheap on the stack.
        let long = vec!["status == 502"; MAX_TERMS].join(" and ");
        let e = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || parse(&long).unwrap().eval(&s()))
            .unwrap()
            .join()
            .unwrap();
        assert!(e);
        let long = format!("{} or login", vec!["process ~ x"; 5000].join(" or "));
        assert!(parse(&long).unwrap().eval(&s()));
    }
}
