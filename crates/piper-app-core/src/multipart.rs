//! Multipart parser (M17): multipart/related (MTOM/XOP), multipart/form-data,
//! multipart/mixed. Splits a body into parts with their headers, streaming from
//! the store (large attachments are not loaded into memory).

use crate::AppCore;
use piper_body::Body;
use piper_model::{Headers, Micros, SessionId};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Part {
    pub index: usize,
    pub headers: Vec<(String, String)>,
    pub content_type: String,
    pub content_id: String,
    pub name: String,
    pub filename: String,
    pub encoding: String,
    /// Byte range of the part body within the source body.
    pub offset: u64,
    pub len: u64,
    pub is_text: bool,
    /// Small text preview (decoded), if textual.
    pub preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Multipart {
    pub boundary: String,
    pub subtype: String,
    /// For multipart/related: the type of the root part (e.g. application/soap+xml).
    pub root_type: String,
    /// content-id of the root/start part.
    pub start: String,
    pub parts: Vec<Part>,
    pub error: Option<String>,
}

fn param<'a>(ct: &'a str, name: &str) -> Option<&'a str> {
    for seg in ct.split(';').skip(1) {
        let seg = seg.trim();
        if let Some(rest) = seg.strip_prefix(name) {
            let rest = rest.trim_start();
            if let Some(v) = rest.strip_prefix('=') {
                return Some(v.trim().trim_matches('"'));
            }
        }
    }
    None
}

const PREVIEW: usize = 2048;
const MAX_HEADER: usize = 64 * 1024;

/// Parse the multipart structure of a body given its Content-Type.
pub fn parse(body: &Body, content_type: &str) -> Multipart {
    let mut out = Multipart::default();
    let ct = content_type.to_ascii_lowercase();
    out.subtype = ct.split(';').next().unwrap_or("").trim().strip_prefix("multipart/").unwrap_or("").to_string();
    let Some(boundary) = param(content_type, "boundary") else {
        out.error = Some("no boundary parameter in Content-Type".into());
        return out;
    };
    out.boundary = boundary.to_string();
    out.root_type = param(content_type, "type").unwrap_or("").to_string();
    out.start = param(content_type, "start").unwrap_or("").trim_matches(['<', '>']).to_string();
    let delim = format!("--{boundary}");
    let total = body.len();

    // Find boundaries by scanning; boundaries are line-delimited.
    let mut pos = 0u64;
    let mut buf = vec![0u8; 256 * 1024];
    // Simple state machine over the whole body via a moving window search of "\r\n--boundary".
    let needle = format!("\r\n--{boundary}");
    let needle_start = format!("--{boundary}");
    let finder = memchr_find(needle.as_bytes());
    let mut boundaries: Vec<u64> = Vec::new();
    // Check if body starts with the boundary (no preceding CRLF).
    let head = body.read_range(0, needle_start.len() + 2).unwrap_or_default();
    if head.starts_with(needle_start.as_bytes()) {
        boundaries.push(0);
    }
    let overlap = needle.len();
    while pos < total {
        let n = body.read_at(pos, &mut buf).unwrap_or(0);
        if n == 0 {
            break;
        }
        for i in finder.iter(&buf[..n]) {
            boundaries.push(pos + i as u64 + 2); // skip the leading CRLF
        }
        if pos + n as u64 >= total {
            break;
        }
        pos += (n - overlap.min(n)) as u64;
    }
    boundaries.sort_unstable();
    boundaries.dedup();

    for (idx, w) in boundaries.windows(2).enumerate() {
        let bstart = w[0];
        let bend = w[1];
        // part starts after "--boundary\r\n"
        let after = bstart + delim.len() as u64;
        // closing boundary "--boundary--"
        let two = body.read_range(after, 2).unwrap_or_default();
        if two == b"--" {
            break;
        }
        let hdr_start = skip_crlf(body, after);
        let (headers, body_start) = read_part_headers(body, hdr_start);
        // body ends at bend (start of the "\r\n--boundary"), so the part body is [body_start, bend)
        let body_end = bend.saturating_sub(2).max(body_start); // remove trailing CRLF before boundary... bend already points after CRLF
        let plen = bend.saturating_sub(body_start);
        let plen = plen.min(total.saturating_sub(body_start));
        let _ = body_end;
        let h = Headers(headers.clone());
        let ct = h.get("content-type").unwrap_or("text/plain").to_string();
        let cid = h.get("content-id").unwrap_or("").trim_matches(['<', '>']).to_string();
        let cd = h.get("content-disposition").unwrap_or("");
        let name = disp_param(cd, "name");
        let filename = disp_param(cd, "filename");
        let encoding = h.get("content-transfer-encoding").unwrap_or("").to_string();
        let part_len = plen.saturating_sub(2); // strip trailing CRLF that precedes the next boundary
        let is_text = is_textual(&ct);
        let preview = if is_text {
            let data = body.read_range(body_start, PREVIEW.min(part_len as usize)).unwrap_or_default();
            Some(String::from_utf8_lossy(&data).into_owned())
        } else {
            None
        };
        out.parts.push(Part {
            index: idx,
            headers,
            content_type: ct,
            content_id: cid,
            name,
            filename,
            encoding,
            offset: body_start,
            len: part_len,
            is_text,
            preview,
        });
    }
    if out.parts.is_empty() && out.error.is_none() {
        out.error = Some("no parts found (boundary mismatch?)".into());
    }
    out
}

fn is_textual(ct: &str) -> bool {
    let ct = ct.to_ascii_lowercase();
    ct.starts_with("text/") || ct.contains("xml") || ct.contains("json") || ct.contains("soap") || ct.contains("x-www-form-urlencoded")
}

fn disp_param(cd: &str, name: &str) -> String {
    for seg in cd.split(';') {
        let seg = seg.trim();
        if let Some(rest) = seg.strip_prefix(name) {
            if let Some(v) = rest.trim_start().strip_prefix('=') {
                return v.trim().trim_matches('"').to_string();
            }
        }
    }
    String::new()
}

fn skip_crlf(body: &Body, mut pos: u64) -> u64 {
    let b = body.read_range(pos, 2).unwrap_or_default();
    if b.starts_with(b"\r\n") {
        pos += 2;
    } else if b.first() == Some(&b'\n') {
        pos += 1;
    }
    pos
}

fn read_part_headers(body: &Body, start: u64) -> (Vec<(String, String)>, u64) {
    let chunk = body.read_range(start, MAX_HEADER).unwrap_or_default();
    // headers end at the first blank line
    let end = chunk.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4).or_else(|| chunk.windows(2).position(|w| w == b"\n\n").map(|i| i + 2)).unwrap_or(chunk.len());
    let text = String::from_utf8_lossy(&chunk[..end.saturating_sub(if end >= 2 { 2 } else { 0 })]);
    let mut headers = Vec::new();
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    (headers, start + end as u64)
}

/// Minimal multi-substring finder (avoid a memchr dep here).
struct Find {
    needle: Vec<u8>,
}
fn memchr_find(needle: &[u8]) -> Find {
    Find { needle: needle.to_vec() }
}
impl Find {
    fn iter<'a>(&'a self, hay: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
        let n = &self.needle;
        (0..hay.len().saturating_sub(n.len() - 1)).filter(move |&i| &hay[i..i + n.len()] == n.as_slice())
    }
}

impl AppCore {
    pub fn multipart(&self, id: SessionId, part: crate::dto::Part) -> Option<Multipart> {
        let cap = self.capture();
        let (req, resp) = cap.bodies_of(id)?;
        let d = cap.detail(id)?;
        let (body, headers) = match part {
            crate::dto::Part::Request => (req, d.request.headers),
            crate::dto::Part::Response => (resp, d.response.map(|r| r.headers).unwrap_or_default()),
        };
        let ct = headers.get("content-type")?.to_string();
        if !ct.to_ascii_lowercase().starts_with("multipart/") {
            return None;
        }
        // Decode content-encoding first if present (rare for multipart).
        Some(parse(&body, &ct))
    }
}

#[allow(dead_code)]
fn _micros(_: Micros) {}

#[cfg(test)]
mod tests {
    use super::*;
    use piper_body::{BodyConfig, BodyStore};

    #[test]
    fn parse_mtom() {
        let dir = tempfile::tempdir().unwrap();
        let store = BodyStore::open(dir.path(), BodyConfig::default()).unwrap();
        let body = b"--MIME_boundary\r\nContent-Type: application/soap+xml; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\nContent-ID: <root@piper>\r\n\r\n<soap:Envelope><soap:Body><Doc><data><xop:Include href=\"cid:img@piper\"/></data></Doc></soap:Body></soap:Envelope>\r\n--MIME_boundary\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: binary\r\nContent-ID: <img@piper>\r\n\r\n\x89PNG\r\n\x00\x01\x02BINARYDATA\r\n--MIME_boundary--\r\n".to_vec();
        let b = store.store_bytes(&body);
        let ct = "multipart/related; boundary=\"MIME_boundary\"; type=\"application/soap+xml\"; start=\"<root@piper>\"";
        let m = parse(&b, ct);
        assert_eq!(m.error, None);
        assert_eq!(m.subtype, "related");
        assert_eq!(m.start, "root@piper");
        assert_eq!(m.parts.len(), 2);
        assert_eq!(m.parts[0].content_id, "root@piper");
        assert!(m.parts[0].preview.as_ref().unwrap().contains("soap:Envelope"));
        assert_eq!(m.parts[1].content_type, "image/png");
        assert_eq!(m.parts[1].content_id, "img@piper");
        assert!(!m.parts[1].is_text);
        // The image part body is exactly the bytes between headers and boundary.
        let img = b.read_range(m.parts[1].offset, m.parts[1].len as usize).unwrap();
        assert_eq!(img, b"\x89PNG\r\n\x00\x01\x02BINARYDATA");
    }

    #[test]
    fn parse_form_data() {
        let dir = tempfile::tempdir().unwrap();
        let store = BodyStore::open(dir.path(), BodyConfig::default()).unwrap();
        let body = b"--X\r\nContent-Disposition: form-data; name=\"field1\"\r\n\r\nvalue1\r\n--X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nhello file\r\n--X--\r\n".to_vec();
        let b = store.store_bytes(&body);
        let m = parse(&b, "multipart/form-data; boundary=X");
        assert_eq!(m.parts.len(), 2);
        assert_eq!(m.parts[0].name, "field1");
        assert_eq!(m.parts[0].preview.as_deref(), Some("value1"));
        assert_eq!(m.parts[1].name, "file");
        assert_eq!(m.parts[1].filename, "a.txt");
    }
}
