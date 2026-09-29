//! Command Bar parser (QuickExec-compatible syntax).

use crate::expr::{Expr, Field, Op, Value};
use crate::{ParseError, parse_size};

#[derive(Debug, Clone)]
pub enum BreakTarget {
    /// Clear this breakpoint type.
    Off,
    UrlContains(String),
    Status(u16),
    Method(String),
}

#[derive(Debug, Clone)]
pub enum Command {
    /// Select all sessions matching the expression (`?`, `=`, `@`, `>`, `<`, `select`).
    Select(Expr),
    /// Set the ad-hoc filter expression (`filter …`), empty = remove.
    Filter(String),
    /// Remove all sessions (`cls`, `clear`).
    Clear,
    /// Remove sessions not matching (`keeponly`).
    KeepOnly(Expr),
    /// Keep only the most recent N sessions (`tail`).
    Tail(usize),
    /// `bpu` – break before request.
    BreakRequest(BreakTarget),
    /// `bpafter` – break after response.
    BreakResponse(BreakTarget),
    /// `bps` – break on response status.
    BreakStatus(BreakTarget),
    /// `bpv`/`bpm` – break on method.
    BreakMethod(BreakTarget),
    /// `g`/`go` – resume all breakpointed sessions.
    Go,
    /// `dump` – save all sessions to a SAZ file.
    Dump,
    /// `start` / `stop` capturing.
    Capture(bool),
    Help,
}

pub const HELP: &str = "\
?text         select sessions whose URL contains text
>10k  <5k     select by response size
=404  =POST   select by status or method
@host         select by host
select type   select by content type (e.g. select image)
filter expr   hide sessions not matching expr (empty: remove)
keeponly type remove sessions whose content type does not match
cls | clear   remove all sessions
tail 100      keep the most recent 100 sessions
bpu [text]    break before request (URL contains text); without text: off
bpafter [t]   break after response (URL contains t)
bps 500       break on response status
bpv POST      break on request method
g | go        resume all paused sessions
dump          save all sessions as .saz
start | stop  start/stop capturing
help          this help";

fn url_contains(t: &str) -> Expr {
    Expr::UrlContains(t.to_lowercase())
}

pub fn parse(input: &str) -> Result<Command, ParseError> {
    let input = input.trim();
    let err = |m: &str| Err(ParseError { msg: m.into(), pos: 0 });
    if input.is_empty() {
        return err("empty command");
    }
    let first = input.chars().next().unwrap();
    let rest = input[first.len_utf8()..].trim();
    match first {
        '?' => return Ok(Command::Select(url_contains(rest))),
        '@' => return Ok(Command::Select(Expr::Cmp(Field::Host, Op::Contains, Value::Text(rest.to_lowercase())))),
        '=' => {
            if let Ok(code) = rest.parse::<u64>() {
                return Ok(Command::Select(Expr::Cmp(Field::Status, Op::Eq, Value::Num(code))));
            }
            return Ok(Command::Select(Expr::Cmp(Field::Method, Op::Eq, Value::Text(rest.to_string()))));
        }
        '>' | '<' => {
            let Some(n) = parse_size(rest) else { return err("expected size, e.g. >10k") };
            let op = if first == '>' { Op::Gt } else { Op::Lt };
            return Ok(Command::Select(Expr::Cmp(Field::Size, op, Value::Num(n))));
        }
        _ => {}
    }
    let (cmd, arg) = match input.split_once(char::is_whitespace) {
        Some((c, a)) => (c.to_ascii_lowercase(), a.trim().to_string()),
        None => (input.to_ascii_lowercase(), String::new()),
    };
    let target = |arg: &str| if arg.is_empty() { BreakTarget::Off } else { BreakTarget::UrlContains(arg.to_lowercase()) };
    Ok(match cmd.as_str() {
        "cls" | "clear" => Command::Clear,
        "select" => {
            if arg.is_empty() {
                return err("select needs a content type");
            }
            Command::Select(Expr::Cmp(Field::ContentType, Op::Contains, Value::Text(arg.to_lowercase())))
        }
        "keeponly" => {
            if arg.is_empty() {
                return err("keeponly needs a content type");
            }
            Command::KeepOnly(Expr::Cmp(Field::ContentType, Op::Contains, Value::Text(arg.to_lowercase())))
        }
        "filter" => {
            if !arg.is_empty() {
                crate::expr::parse(&arg)?;
            }
            Command::Filter(arg)
        }
        "find" => Command::Select(crate::expr::parse(&arg)?),
        "tail" => Command::Tail(arg.parse().map_err(|_| ParseError { msg: "tail needs a number".into(), pos: 0 })?),
        "bpu" => Command::BreakRequest(target(&arg)),
        "bpafter" => Command::BreakResponse(target(&arg)),
        "bps" => Command::BreakStatus(if arg.is_empty() {
            BreakTarget::Off
        } else {
            BreakTarget::Status(arg.parse().map_err(|_| ParseError { msg: "bps needs a status code".into(), pos: 0 })?)
        }),
        "bpv" | "bpm" => Command::BreakMethod(if arg.is_empty() { BreakTarget::Off } else { BreakTarget::Method(arg.to_ascii_uppercase()) }),
        "g" | "go" => Command::Go,
        "dump" => Command::Dump,
        "start" => Command::Capture(true),
        "stop" => Command::Capture(false),
        "help" | "?" => Command::Help,
        _ => return err("unknown command – type help"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use piper_model::SessionSummary;

    #[test]
    fn select_forms() {
        let s = SessionSummary { host: "api.x.de".into(), url: "/login".into(), status: 404, method: "GET".into(), response_body_len: 20000, content_type: "image/png".into(), ..Default::default() };
        for (cmd, want) in [("?login", true), ("@x.de", true), ("=404", true), ("=GET", true), (">10k", true), ("<10k", false), ("select image", true), ("?nope", false)] {
            match parse(cmd).unwrap() {
                Command::Select(e) => assert_eq!(e.eval(&s), want, "{cmd}"),
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn commands() {
        assert!(matches!(parse("bpu").unwrap(), Command::BreakRequest(BreakTarget::Off)));
        assert!(matches!(parse("bpu /login").unwrap(), Command::BreakRequest(BreakTarget::UrlContains(_))));
        assert!(matches!(parse("bps 500").unwrap(), Command::BreakStatus(BreakTarget::Status(500))));
        assert!(matches!(parse("tail 10").unwrap(), Command::Tail(10)));
        assert!(matches!(parse("CLS").unwrap(), Command::Clear));
        assert!(parse("wat").is_err());
    }
}
