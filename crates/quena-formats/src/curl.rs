//! Parse a `curl` command line into an HTTP request, for importing into the
//! Composer. Handles the flags people actually paste from browser devtools
//! ("Copy as cURL"): -X/--request, -H/--header, -d/--data*, -u/--user,
//! -b/--cookie, -A/--user-agent, -e/--referer, -G, --url, --compressed.

use crate::FormatError;
use base64::Engine;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CurlRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// Parse a curl command (with or without a leading `curl`) into a request.
pub fn parse(input: &str) -> Result<CurlRequest, FormatError> {
    let tokens = tokenize(input)?;
    let mut it = tokens.iter().peekable();
    // Skip a leading `curl` (and a shell prompt like `$`).
    while let Some(t) = it.peek() {
        if *t == "curl" || *t == "$" || t.is_empty() {
            it.next();
        } else {
            break;
        }
    }

    let mut method: Option<String> = None;
    let mut url: Option<String> = None;
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut data: Vec<String> = Vec::new();
    let mut get_with_data = false;

    let mut next = || it.next().cloned();
    while let Some(tok) = next() {
        let (flag, inline) = split_flag(&tok);
        let mut value = || inline.clone().or_else(&mut next);
        match flag.as_str() {
            "-X" | "--request" => {
                if let Some(v) = value() {
                    method = Some(v.to_ascii_uppercase());
                }
            }
            "-H" | "--header" => {
                if let Some(v) = value() {
                    if let Some((n, val)) = v.split_once(':') {
                        headers.push((n.trim().to_string(), val.trim().to_string()));
                    }
                }
            }
            "-d" | "--data" | "--data-raw" | "--data-binary" | "--data-ascii" | "--data-urlencode" => {
                if let Some(v) = value() {
                    data.push(v);
                }
            }
            "-u" | "--user" => {
                if let Some(v) = value() {
                    let enc = base64::engine::general_purpose::STANDARD.encode(v.as_bytes());
                    headers.push(("Authorization".into(), format!("Basic {enc}")));
                }
            }
            "-b" | "--cookie" => {
                if let Some(v) = value() {
                    headers.push(("Cookie".into(), v));
                }
            }
            "-A" | "--user-agent" => {
                if let Some(v) = value() {
                    headers.push(("User-Agent".into(), v));
                }
            }
            "-e" | "--referer" => {
                if let Some(v) = value() {
                    headers.push(("Referer".into(), v));
                }
            }
            "-G" | "--get" => get_with_data = true,
            "--url" => url = value(),
            "--compressed" => headers.push(("Accept-Encoding".into(), "gzip, deflate, br".into())),
            // Flags we accept and ignore (they don't shape the request line).
            "-s" | "--silent" | "-k" | "--insecure" | "-L" | "--location" | "-i" | "--include" | "-v"
            | "--verbose" | "-#" | "--progress-bar" | "--http1.1" | "--http2" => {}
            // Flags that take an argument we don't use.
            "-o" | "--output" | "-w" | "--write-out" | "--connect-timeout" | "-m" | "--max-time"
            | "--retry" | "-x" | "--proxy" | "--cacert" | "--cert" | "--key" | "-E" => {
                let _ = value();
            }
            other if other.starts_with('-') => {
                // Unknown flag: skip it (and its value if it clearly takes one is unknown,
                // so leave the next token as positional to be safe).
            }
            _ => {
                // Positional argument: the URL (first one wins).
                if url.is_none() {
                    url = Some(tok.clone());
                }
            }
        }
    }

    let url = url.ok_or_else(|| FormatError::Invalid("no URL found in the curl command".into()))?;
    let body = data.join("&");

    // -G moves data into the query string.
    if get_with_data && !body.is_empty() {
        let sep = if url.contains('?') { '&' } else { '?' };
        return Ok(CurlRequest {
            method: method.unwrap_or_else(|| "GET".into()),
            url: format!("{url}{sep}{body}"),
            headers,
            body: String::new(),
        });
    }

    let method = method.unwrap_or_else(|| if body.is_empty() { "GET".into() } else { "POST".into() });
    // A body with a default content type gets form-urlencoded, matching curl.
    if !body.is_empty() && !headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("content-type")) {
        headers.push(("Content-Type".into(), "application/x-www-form-urlencoded".into()));
    }

    Ok(CurlRequest { method, url, headers, body })
}

/// `--flag=value` → ("--flag", Some("value")); otherwise (tok, None).
fn split_flag(tok: &str) -> (String, Option<String>) {
    if tok.starts_with("--") {
        if let Some((f, v)) = tok.split_once('=') {
            return (f.to_string(), Some(v.to_string()));
        }
    }
    (tok.to_string(), None)
}

/// Split a shell-ish command line into tokens, honouring single/double quotes,
/// backslash escapes and `\<newline>` / trailing `^` line continuations.
fn tokenize(input: &str) -> Result<Vec<String>, FormatError> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut has = false;
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                has = true;
                for d in chars.by_ref() {
                    if d == '\'' {
                        break;
                    }
                    cur.push(d);
                }
            }
            '"' => {
                has = true;
                while let Some(d) = chars.next() {
                    if d == '"' {
                        break;
                    }
                    if d == '\\' {
                        if let Some(&e) = chars.peek() {
                            // In double quotes, backslash only escapes these.
                            if matches!(e, '"' | '\\' | '$' | '`') {
                                cur.push(e);
                                chars.next();
                                continue;
                            }
                        }
                    }
                    cur.push(d);
                }
            }
            '\\' => {
                // Line continuation or escaped char.
                match chars.next() {
                    Some('\n') | None => {}
                    Some('\r') => {
                        if chars.peek() == Some(&'\n') {
                            chars.next();
                        }
                    }
                    Some(other) => {
                        has = true;
                        cur.push(other);
                    }
                }
            }
            '^' if chars.peek() == Some(&'\n') => {
                // Windows caret line continuation.
                chars.next();
            }
            c if c.is_whitespace() => {
                if has {
                    out.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            c => {
                has = true;
                cur.push(c);
            }
        }
    }
    if has {
        out.push(cur);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_get() {
        let r = parse("curl https://example.com/a?b=1").unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.url, "https://example.com/a?b=1");
        assert!(r.body.is_empty());
    }

    #[test]
    fn devtools_style_post() {
        let cmd = r#"curl 'https://api.example.com/login' \
          -H 'Content-Type: application/json' \
          -H 'Accept: */*' \
          --data-raw '{"user":"a","pass":"b"}' \
          --compressed"#;
        let r = parse(cmd).unwrap();
        assert_eq!(r.method, "POST");
        assert_eq!(r.url, "https://api.example.com/login");
        assert_eq!(r.body, r#"{"user":"a","pass":"b"}"#);
        assert!(r.headers.iter().any(|(n, v)| n == "Content-Type" && v == "application/json"));
        assert!(r.headers.iter().any(|(n, _)| n == "Accept-Encoding"));
    }

    #[test]
    fn explicit_method_and_basic_auth() {
        let r = parse("curl -X PUT -u alice:secret https://example.com/x -H 'X-Foo: bar'").unwrap();
        assert_eq!(r.method, "PUT");
        let auth = r.headers.iter().find(|(n, _)| n == "Authorization").unwrap();
        // base64("alice:secret")
        assert_eq!(auth.1, "Basic YWxpY2U6c2VjcmV0");
        assert!(r.headers.iter().any(|(n, v)| n == "X-Foo" && v == "bar"));
    }

    #[test]
    fn data_defaults_to_post_and_form_ct() {
        let r = parse("curl https://x/y -d 'a=1' -d 'b=2'").unwrap();
        assert_eq!(r.method, "POST");
        assert_eq!(r.body, "a=1&b=2");
        assert!(r.headers.iter().any(|(n, v)| n == "Content-Type" && v.contains("x-www-form-urlencoded")));
    }

    #[test]
    fn get_with_data_moves_to_query() {
        let r = parse("curl -G https://x/y -d 'a=1' -d 'b=2'").unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.url, "https://x/y?a=1&b=2");
        assert!(r.body.is_empty());
    }

    #[test]
    fn equals_form_flags() {
        let r = parse("curl --request=DELETE --url=https://x/z").unwrap();
        assert_eq!(r.method, "DELETE");
        assert_eq!(r.url, "https://x/z");
    }

    #[test]
    fn no_url_is_error() {
        assert!(parse("curl -X POST -d 'a=1'").is_err());
    }
}
