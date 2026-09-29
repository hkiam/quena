//! Raw HTTP/1 message heads and chunked transfer coding.

use quena_model::{Headers, RequestHead, ResponseHead, HttpVersion, latin1_to_string, string_to_latin1};
use std::io::{self, BufRead, Read, Write};

const MAX_HEAD: usize = 1 << 20;

/// Read a message head (start line + headers) up to the empty line.
pub fn read_head<R: BufRead>(r: &mut R) -> io::Result<Option<(String, Headers)>> {
    let mut first = String::new();
    let mut total = 0usize;
    let mut headers = Headers::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = r.read_until(b'\n', &mut line)?;
        if n == 0 {
            return Ok(if first.is_empty() { None } else { Some((first, headers)) });
        }
        total += n;
        if total > MAX_HEAD {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "message head too large"));
        }
        while line.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
            line.pop();
        }
        if first.is_empty() {
            if line.is_empty() {
                continue; // leading blank lines
            }
            first = latin1_to_string(&line);
            continue;
        }
        if line.is_empty() {
            return Ok(Some((first, headers)));
        }
        if (line[0] == b' ' || line[0] == b'\t') && !headers.is_empty() {
            // obsolete line folding
            let last = headers.0.last_mut().unwrap();
            last.1.push(' ');
            last.1.push_str(latin1_to_string(&line).trim());
            continue;
        }
        if let Some(i) = line.iter().position(|b| *b == b':') {
            let name = latin1_to_string(&line[..i]).trim().to_string();
            let mut v = &line[i + 1..];
            while v.first() == Some(&b' ') || v.first() == Some(&b'\t') {
                v = &v[1..];
            }
            headers.push(name, latin1_to_string(v));
        }
    }
}

pub fn parse_request_line(line: &str) -> (String, String, HttpVersion) {
    let mut p = line.splitn(3, ' ');
    let m = p.next().unwrap_or("GET").to_string();
    let u = p.next().unwrap_or("/").to_string();
    let v = p.next().and_then(HttpVersion::parse).unwrap_or(HttpVersion::Http11);
    (m, u, v)
}

pub fn parse_status_line(line: &str) -> (HttpVersion, u16, String) {
    let mut p = line.splitn(3, ' ');
    let v = p.next().and_then(HttpVersion::parse).unwrap_or(HttpVersion::Http11);
    let s = p.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    let r = p.next().unwrap_or("").to_string();
    (v, s, r)
}

fn wire_version(v: HttpVersion) -> &'static str {
    // Fiddler cannot parse "HTTP/2"; the real version is kept in the session flags.
    match v {
        HttpVersion::Http10 => "HTTP/1.0",
        HttpVersion::Http09 => "HTTP/0.9",
        _ => "HTTP/1.1",
    }
}

fn write_headers(w: &mut dyn Write, h: &Headers) -> io::Result<()> {
    for (k, v) in h.iter() {
        if k.starts_with(':') {
            continue;
        }
        w.write_all(k.as_bytes())?;
        w.write_all(b": ")?;
        w.write_all(&string_to_latin1(v))?;
        w.write_all(b"\r\n")?;
    }
    w.write_all(b"\r\n")
}

/// `GET http://host/path HTTP/1.1` + headers. Adds a Host header for HTTP/2 requests.
pub fn write_request_head(w: &mut dyn Write, r: &RequestHead) -> io::Result<()> {
    write!(w, "{} {} {}\r\n", r.method, r.url, wire_version(r.version))?;
    if r.version == HttpVersion::Http2 && r.headers.get("host").is_none() {
        let (host, _) = quena_model::split_url(&r.url, &r.method);
        let mut h = Headers::new();
        h.push("Host", host);
        h.0.extend(r.headers.0.iter().cloned());
        return write_headers(w, &h);
    }
    write_headers(w, &r.headers)
}

pub fn write_response_head(w: &mut dyn Write, r: &ResponseHead) -> io::Result<()> {
    write!(w, "{} {} {}\r\n", wire_version(r.version), r.status, r.reason)?;
    write_headers(w, &r.headers)
}

pub fn is_chunked(h: &Headers) -> bool {
    h.has_token("transfer-encoding", "chunked")
}

/// Streaming decoder for `Transfer-Encoding: chunked`.
pub struct ChunkedReader<R> {
    inner: R,
    remaining: u64,
    done: bool,
}

impl<R: BufRead> ChunkedReader<R> {
    pub fn new(inner: R) -> Self {
        ChunkedReader { inner, remaining: 0, done: false }
    }
}

impl<R: BufRead> Read for ChunkedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut line = String::new();
            // Skip the CRLF that terminates the previous chunk.
            loop {
                line.clear();
                if self.inner.read_line(&mut line)? == 0 {
                    self.done = true;
                    return Ok(0);
                }
                if !line.trim().is_empty() {
                    break;
                }
            }
            let size = line.trim().split(';').next().unwrap_or("0");
            self.remaining = u64::from_str_radix(size.trim(), 16).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("bad chunk size {size:?}")))?;
            if self.remaining == 0 {
                self.done = true;
                return Ok(0);
            }
        }
        let n = (buf.len() as u64).min(self.remaining) as usize;
        let got = self.inner.read(&mut buf[..n])?;
        if got == 0 {
            self.done = true;
            return Ok(0);
        }
        self.remaining -= got as u64;
        Ok(got)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn head_and_chunked() {
        let data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Long: a\r\n b\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\n\r\n";
        let mut r = io::BufReader::new(&data[..]);
        let (first, h) = read_head(&mut r).unwrap().unwrap();
        assert_eq!(first, "HTTP/1.1 200 OK");
        assert_eq!(h.get("x-long"), Some("a b"));
        assert!(is_chunked(&h));
        let mut out = String::new();
        ChunkedReader::new(r).read_to_string(&mut out).unwrap();
        assert_eq!(out, "hello world");
    }
}
