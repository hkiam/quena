//! WCAT (Web Capacity Analysis Tool) scenario script: the sessions as transactions of a load
//! test, as Fiddler exports them. Each request names its server, port and TLS; bodies up to
//! [`MAX_POSTDATA`] go in as text.

use crate::{FormatError, Progress, Result};
use quena_model::{SessionId, SessionKind};
use quena_store::Capture;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

/// Request bodies larger than this are left out (WCAT keeps them in the script).
pub const MAX_POSTDATA: usize = 256 << 10;
/// Headers WCAT sets itself.
const SKIP: &[&str] = &["host", "content-length", "connection", "transfer-encoding", "keep-alive", "proxy-connection"];

/// A WCAT string literal.
fn lit(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// (secure, host, port, path) of an absolute URL.
fn parts(url: &str) -> Option<(bool, String, u16, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let secure = scheme.eq_ignore_ascii_case("https");
    let end = rest.find('/').unwrap_or(rest.len());
    let (authority, path) = (&rest[..end], &rest[end..]);
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') || h.ends_with(']') => (h.to_string(), p.parse().ok()?),
        _ => (authority.to_string(), if secure { 443 } else { 80 }),
    };
    Some((secure, host, port, if path.is_empty() { "/".into() } else { path.to_string() }))
}

/// Write `ids` as a WCAT scenario to `path`. Returns how many requests it holds.
pub fn export(cap: &Arc<Capture>, ids: &[SessionId], path: &Path, p: &dyn Progress) -> Result<usize> {
    let mut out = String::from("scenario\n{\n    name     = \"Quena-generated WCAT script\";\n    warmup   = 30;\n    duration = 120;\n    cooldown = 10;\n\n    default\n    {\n        version = HTTP11;\n        setheader\n        {\n            name  = \"Connection\";\n            value = \"keep-alive\";\n        }\n    }\n\n    transaction\n    {\n        id     = \"quena\";\n        weight = 1;\n");
    let mut n = 0;
    for (i, id) in ids.iter().enumerate() {
        if p.cancelled() {
            return Err(FormatError::Cancelled);
        }
        p.progress(i as u64, ids.len() as u64);
        let Some(d) = cap.detail(*id) else { continue };
        if d.summary.kind == SessionKind::Tunnel {
            continue;
        }
        let Some((secure, host, port, url)) = parts(&d.request.url) else { continue };
        n += 1;
        out.push_str(&format!("\n        request\n        {{\n            server     = {};\n            port       = {port};\n", lit(&host)));
        if secure {
            out.push_str("            secure     = true;\n");
        }
        out.push_str(&format!("            url        = {};\n            verb       = {};\n", lit(&url), d.request.method.to_ascii_uppercase()));
        if d.summary.status != 0 {
            out.push_str(&format!("            statuscode = {};\n", d.summary.status));
        }
        for (k, v) in &d.request.headers.0 {
            if k.starts_with(':') || SKIP.contains(&k.to_ascii_lowercase().as_str()) {
                continue;
            }
            out.push_str(&format!("            setheader\n            {{\n                name  = {};\n                value = {};\n            }}\n", lit(k), lit(v)));
        }
        if let Some((body, _)) = cap.bodies_of(*id)
            && !body.is_empty()
        {
            if body.len() <= MAX_POSTDATA as u64
                && let Ok(bytes) = body.read_range(0, body.len() as usize)
                && let Ok(text) = String::from_utf8(bytes)
            {
                out.push_str(&format!("            postdata   = {};\n", lit(&text)));
            } else {
                out.push_str("            // request body left out (binary or larger than 256 KB)\n");
            }
        }
        out.push_str("        }\n");
    }
    out.push_str("    }\n}\n");
    if n == 0 {
        return Err(FormatError::Invalid("no HTTP requests to write".into()));
    }
    let tmp = path.with_extension("wcat.part");
    std::fs::File::create(&tmp)?.write_all(out.as_bytes())?;
    std::fs::rename(&tmp, path)?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_and_urls() {
        assert_eq!(lit("a\"b\\c\n"), "\"a\\\"b\\\\c\\n\"");
        assert_eq!(parts("https://api.example.com/v1?a=1"), Some((true, "api.example.com".into(), 443, "/v1?a=1".into())));
        assert_eq!(parts("http://h:8080"), Some((false, "h".into(), 8080, "/".into())));
        assert_eq!(parts("http://[::1]:9/x"), Some((false, "[::1]".into(), 9, "/x".into())));
    }
}
