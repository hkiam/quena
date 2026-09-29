//! HTTP Archive (HAR 1.2). Export streams JSON (bodies decoded, text or
//! base64, written in chunks); import parses entries one by one.

use crate::time_fmt::{from_iso, to_iso};
use crate::{FormatError, Progress, Result};
use base64::Engine;
use quena_body::Body;
use quena_model::*;
use quena_store::Capture;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct HarOptions {
    /// Bodies larger than this (decoded) are omitted.
    pub max_body: u64,
    /// Decode Content-Encoding (HAR expects decoded content).
    pub decode: bool,
}

impl Default for HarOptions {
    fn default() -> Self {
        HarOptions { max_body: 64 << 20, decode: true }
    }
}

fn jstr(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

fn headers_json(h: &Headers) -> String {
    let items: Vec<String> = h
        .iter()
        .filter(|(k, _)| !k.starts_with(':'))
        .map(|(k, v)| format!("{{\"name\":{},\"value\":{}}}", jstr(k), jstr(&latin1_to_utf8(v))))
        .collect();
    format!("[{}]", items.join(","))
}

fn latin1_to_utf8(s: &str) -> String {
    let b = string_to_latin1(s);
    String::from_utf8(b).unwrap_or_else(|_| s.to_string())
}

fn query_json(url: &str) -> String {
    let q = url.split_once('?').map(|(_, q)| q.split('#').next().unwrap_or("")).unwrap_or("");
    let items: Vec<String> = q
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            format!("{{\"name\":{},\"value\":{}}}", jstr(k), jstr(v))
        })
        .collect();
    format!("[{}]", items.join(","))
}

fn cookies_json(h: &Headers, response: bool) -> String {
    let mut items = Vec::new();
    if response {
        for v in h.get_all("set-cookie") {
            let nv = v.split(';').next().unwrap_or("");
            let (k, val) = nv.split_once('=').unwrap_or((nv, ""));
            items.push(format!("{{\"name\":{},\"value\":{}}}", jstr(k.trim()), jstr(val.trim())));
        }
    } else {
        for v in h.get_all("cookie") {
            for c in v.split(';') {
                let (k, val) = c.split_once('=').unwrap_or((c, ""));
                if !k.trim().is_empty() {
                    items.push(format!("{{\"name\":{},\"value\":{}}}", jstr(k.trim()), jstr(val.trim())));
                }
            }
        }
    }
    format!("[{}]", items.join(","))
}

fn is_text_type(ct: &str) -> bool {
    let ct = ct.to_ascii_lowercase();
    ct.starts_with("text/") || ct.contains("json") || ct.contains("xml") || ct.contains("javascript") || ct.contains("x-www-form-urlencoded")
}

/// Decoded view of a body (streams through the decompressor).
fn decoded_reader(body: &Body, headers: &Headers, decode: bool) -> Box<dyn Read> {
    let base: Box<dyn Read> = Box::new(body.stream(0, false));
    if !decode {
        return base;
    }
    let Some(ce) = headers.get("content-encoding") else { return base };
    let Ok(encs) = quena_body::decode::parse_encodings(ce) else { return base };
    quena_body::decode::decoding_reader(base, &encs)
}

/// Write a JSON string value by streaming `r`, either as UTF-8 text (with
/// escaping) or base64. Returns the number of decoded bytes.
fn write_stream_value(w: &mut dyn Write, mut r: Box<dyn Read>, text: bool, max: u64) -> Result<(u64, bool)> {
    w.write_all(b"\"")?;
    let mut total = 0u64;
    let mut buf = vec![0u8; 1 << 20];
    let mut carry: Vec<u8> = Vec::new();
    let mut truncated = false;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > max {
            truncated = true;
            break;
        }
        carry.extend_from_slice(&buf[..n]);
        if text {
            // Emit up to the last complete UTF-8 sequence.
            let valid = match std::str::from_utf8(&carry) {
                Ok(_) => carry.len(),
                Err(e) if e.error_len().is_none() => e.valid_up_to(),
                Err(_) => carry.len(),
            };
            let s = String::from_utf8_lossy(&carry[..valid]).into_owned();
            let esc = serde_json::to_string(&s)?;
            w.write_all(&esc.as_bytes()[1..esc.len() - 1])?;
            carry.drain(..valid);
        } else {
            let whole = carry.len() / 3 * 3;
            let enc = base64::engine::general_purpose::STANDARD.encode(&carry[..whole]);
            w.write_all(enc.as_bytes())?;
            carry.drain(..whole);
        }
    }
    if !truncated && !carry.is_empty() {
        if text {
            let esc = serde_json::to_string(&String::from_utf8_lossy(&carry))?;
            w.write_all(&esc.as_bytes()[1..esc.len() - 1])?;
        } else {
            w.write_all(base64::engine::general_purpose::STANDARD.encode(&carry).as_bytes())?;
        }
    }
    w.write_all(b"\"")?;
    Ok((total, truncated))
}

fn ms_between(a: Option<Micros>, b: Option<Micros>) -> f64 {
    match (a, b) {
        (Some(a), Some(b)) if b >= a => (b - a) as f64 / 1000.0,
        _ => -1.0,
    }
}

pub fn export(cap: &Arc<Capture>, ids: &[SessionId], path: &Path, o: &HarOptions, p: &dyn Progress) -> Result<usize> {
    let tmp = path.with_extension("har.part");
    let mut w = BufWriter::with_capacity(1 << 20, File::create(&tmp)?);
    write!(w, "{{\"log\":{{\"version\":\"1.2\",\"creator\":{{\"name\":\"Quena\",\"version\":\"{}\"}},\"pages\":[],\"entries\":[", env!("CARGO_PKG_VERSION"))?;
    let mut n = 0;
    for (i, id) in ids.iter().enumerate() {
        if p.cancelled() {
            drop(w);
            let _ = std::fs::remove_file(&tmp);
            return Err(FormatError::Cancelled);
        }
        p.progress(i as u64, ids.len() as u64);
        let Some(d) = cap.detail(*id) else { continue };
        if d.summary.kind == SessionKind::Tunnel {
            continue;
        }
        let Some((req_body, resp_body)) = cap.bodies_of(*id) else { continue };
        if n > 0 {
            w.write_all(b",")?;
        }
        n += 1;
        let t = &d.timers;
        let start = t.client_begin_request.or(t.client_connected).unwrap_or(d.summary.started_at);
        let wait = ms_between(t.server_begin_request.or(t.client_done_request), t.got_response_headers);
        let receive = ms_between(t.got_response_headers, t.server_done_response);
        let send = ms_between(t.client_begin_request, t.client_done_request).max(0.0);
        let total = d.summary.duration_ms.map(|v| v as f64).unwrap_or(0.0);
        write!(
            w,
            "{{\"startedDateTime\":{},\"time\":{total},\"request\":{{\"method\":{},\"url\":{},\"httpVersion\":{},\"cookies\":{},\"headers\":{},\"queryString\":{},\"headersSize\":-1,\"bodySize\":{}",
            jstr(&to_iso(start)),
            jstr(&d.request.method),
            jstr(&d.request.url),
            jstr(d.request.version.as_str()),
            cookies_json(&d.request.headers, false),
            headers_json(&d.request.headers),
            query_json(&d.request.url),
            req_body.wire_len()
        )?;
        if !req_body.is_empty() {
            let ct = d.request.headers.get("content-type").unwrap_or("application/octet-stream").to_string();
            write!(w, ",\"postData\":{{\"mimeType\":{},\"text\":", jstr(&ct))?;
            let text = is_text_type(&ct);
            let (_, truncated) = write_stream_value(&mut w, decoded_reader(&req_body, &d.request.headers, false), text, o.max_body)?;
            if !text {
                w.write_all(b",\"encoding\":\"base64\"")?;
            }
            if truncated {
                w.write_all(b",\"comment\":\"body omitted (too large)\"")?;
            }
            w.write_all(b"}")?;
        }
        w.write_all(b"},")?;
        match &d.response {
            Some(r) => {
                let ct = r.headers.get("content-type").unwrap_or("").to_string();
                write!(
                    w,
                    "\"response\":{{\"status\":{},\"statusText\":{},\"httpVersion\":{},\"cookies\":{},\"headers\":{},\"redirectURL\":{},\"headersSize\":-1,\"bodySize\":{},\"content\":{{\"mimeType\":{}",
                    r.status,
                    jstr(&r.reason),
                    jstr(r.version.as_str()),
                    cookies_json(&r.headers, true),
                    headers_json(&r.headers),
                    jstr(r.headers.get("location").unwrap_or("")),
                    resp_body.wire_len(),
                    jstr(&ct)
                )?;
                if resp_body.is_empty() {
                    w.write_all(b",\"size\":0")?;
                } else {
                    let text = is_text_type(&ct);
                    w.write_all(b",\"text\":")?;
                    let (size, truncated) = write_stream_value(&mut w, decoded_reader(&resp_body, &r.headers, o.decode), text, o.max_body)?;
                    if !text {
                        w.write_all(b",\"encoding\":\"base64\"")?;
                    }
                    if truncated {
                        w.write_all(b",\"comment\":\"body omitted (too large)\"")?;
                    }
                    write!(w, ",\"size\":{size},\"compression\":{}", size as i64 - resp_body.len() as i64)?;
                }
                w.write_all(b"}},")?;
            }
            None => {
                w.write_all(b"\"response\":{\"status\":0,\"statusText\":\"\",\"httpVersion\":\"\",\"cookies\":[],\"headers\":[],\"redirectURL\":\"\",\"headersSize\":-1,\"bodySize\":-1,\"content\":{\"size\":0,\"mimeType\":\"\"},\"_error\":\"no response\"},")?;
            }
        }
        write!(
            w,
            "\"cache\":{{}},\"timings\":{{\"blocked\":-1,\"dns\":{},\"connect\":{},\"ssl\":{},\"send\":{send},\"wait\":{},\"receive\":{}}}",
            t.dns_ms.map(|v| v as i64).unwrap_or(-1),
            t.tcp_connect_ms.map(|v| v as i64).unwrap_or(-1),
            t.tls_handshake_ms.map(|v| v as i64).unwrap_or(-1),
            wait.max(0.0),
            receive.max(0.0)
        )?;
        if let Some(a) = &d.connection.server_addr {
            write!(w, ",\"serverIPAddress\":{}", jstr(a.rsplit_once(':').map(|(ip, _)| ip.trim_matches(['[', ']'])).unwrap_or(a)))?;
        }
        if !d.summary.comment.is_empty() {
            write!(w, ",\"comment\":{}", jstr(&d.summary.comment))?;
        }
        if let Some(pinfo) = &d.process {
            write!(w, ",\"_process\":{}", jstr(&pinfo.display()))?;
        }
        w.write_all(b"}")?;
    }
    w.write_all(b"]}}")?;
    w.flush()?;
    drop(w);
    std::fs::rename(tmp, path)?;
    Ok(n)
}

// ------------------------------------------------------------------ import

#[derive(Deserialize, Default)]
#[serde(default)]
struct NameValue {
    name: String,
    value: String,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct PostData {
    mime_type: String,
    text: String,
    encoding: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct HarRequest {
    method: String,
    url: String,
    http_version: String,
    headers: Vec<NameValue>,
    post_data: Option<PostData>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Content {
    mime_type: String,
    text: Option<String>,
    encoding: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct HarResponse {
    status: u16,
    status_text: String,
    http_version: String,
    headers: Vec<NameValue>,
    content: Content,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Timings {
    dns: f64,
    connect: f64,
    ssl: f64,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct HarEntry {
    started_date_time: String,
    time: f64,
    request: HarRequest,
    response: HarResponse,
    timings: Timings,
    #[serde(rename = "serverIPAddress")]
    server_ip_address: Option<String>,
    comment: Option<String>,
    #[serde(rename = "_process")]
    process: Option<String>,
}

fn to_headers(v: &[NameValue]) -> Headers {
    let mut h = Headers::new();
    for nv in v {
        h.push(nv.name.clone(), nv.value.clone());
    }
    h
}

fn body_bytes(text: &str, encoding: Option<&str>) -> Vec<u8> {
    if encoding == Some("base64") {
        base64::engine::general_purpose::STANDARD.decode(text.trim()).unwrap_or_else(|_| text.as_bytes().to_vec())
    } else {
        text.as_bytes().to_vec()
    }
}

fn to_session(cap: &Arc<Capture>, e: HarEntry) -> (SessionDetail, Body, Body) {
    let mut d = SessionDetail::default();
    let start = from_iso(&e.started_date_time).unwrap_or_else(now_us);
    let mut req_headers = to_headers(&e.request.headers);
    req_headers.0.retain(|(k, _)| !k.starts_with(':'));
    d.request = RequestHead {
        method: e.request.method,
        url: e.request.url,
        version: HttpVersion::parse(&e.request.http_version).unwrap_or(HttpVersion::Http11),
        headers: req_headers,
    };
    let req = match &e.request.post_data {
        Some(p) => cap.bodies.store_bytes(&body_bytes(&p.text, p.encoding.as_deref())),
        None => cap.bodies.store_bytes(&[]),
    };
    let mut resp_headers = to_headers(&e.response.headers);
    resp_headers.0.retain(|(k, _)| !k.starts_with(':'));
    // HAR content is decoded: drop encoding headers so the stored body matches.
    resp_headers.remove("content-encoding");
    resp_headers.remove("transfer-encoding");
    let resp_bytes = e.response.content.text.as_deref().map(|t| body_bytes(t, e.response.content.encoding.as_deref())).unwrap_or_default();
    if resp_headers.get("content-length").is_some() {
        resp_headers.set("Content-Length", resp_bytes.len().to_string());
    }
    if resp_headers.get("content-type").is_none() && !e.response.content.mime_type.is_empty() {
        resp_headers.push("Content-Type", e.response.content.mime_type.clone());
    }
    let resp = cap.bodies.store_bytes(&resp_bytes);
    if e.response.status > 0 {
        d.response = Some(ResponseHead {
            status: e.response.status,
            reason: e.response.status_text,
            version: HttpVersion::parse(&e.response.http_version).unwrap_or(HttpVersion::Http11),
            headers: resp_headers,
        });
    }
    let dur = (e.time.max(0.0) * 1000.0) as i64;
    d.timers.client_begin_request = Some(start);
    d.timers.client_done_response = Some(start + dur);
    let ms = |v: f64| if v >= 0.0 { Some(v as u32) } else { None };
    d.timers.dns_ms = ms(e.timings.dns);
    d.timers.tcp_connect_ms = ms(e.timings.connect);
    d.timers.tls_handshake_ms = ms(e.timings.ssl);
    d.connection.server_addr = e.server_ip_address;
    d.summary.comment = e.comment.unwrap_or_default();
    d.process = e.process.map(|p| {
        let (n, pid) = p.rsplit_once(':').map(|(a, b)| (a.to_string(), b.parse().unwrap_or(0))).unwrap_or((p.clone(), 0));
        ProcessInfo { pid, name: n }
    });
    d.summary.state = SessionState::Done;
    d.summary.flags |= flags::IMPORTED;
    d.summary.started_at = start;
    (d, req, resp)
}

struct Import<'a> {
    cap: &'a Arc<Capture>,
    ids: &'a mut Vec<SessionId>,
    p: &'a dyn Progress,
}

impl<'de> DeserializeSeed<'de> for Import<'_> {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> std::result::Result<(), D::Error> {
        d.deserialize_map(RootV(self))
    }
}

struct RootV<'a>(Import<'a>);
impl<'de> Visitor<'de> for RootV<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("HAR object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> std::result::Result<(), A::Error> {
        let mut imp = Some(self.0);
        while let Some(k) = m.next_key::<String>()? {
            if k == "log" {
                if let Some(i) = imp.take() {
                    m.next_value_seed(LogSeed(i))?;
                    continue;
                }
            }
            m.next_value::<IgnoredAny>()?;
        }
        Ok(())
    }
}

struct LogSeed<'a>(Import<'a>);
impl<'de> DeserializeSeed<'de> for LogSeed<'_> {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> std::result::Result<(), D::Error> {
        d.deserialize_map(LogV(self.0))
    }
}
struct LogV<'a>(Import<'a>);
impl<'de> Visitor<'de> for LogV<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("HAR log")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> std::result::Result<(), A::Error> {
        let mut imp = Some(self.0);
        while let Some(k) = m.next_key::<String>()? {
            if k == "entries" {
                if let Some(i) = imp.take() {
                    m.next_value_seed(EntriesSeed(i))?;
                    continue;
                }
            }
            m.next_value::<IgnoredAny>()?;
        }
        Ok(())
    }
}

struct EntriesSeed<'a>(Import<'a>);
impl<'de> DeserializeSeed<'de> for EntriesSeed<'_> {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> std::result::Result<(), D::Error> {
        d.deserialize_seq(EntriesV(self.0))
    }
}
struct EntriesV<'a>(Import<'a>);
impl<'de> Visitor<'de> for EntriesV<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("HAR entries")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> std::result::Result<(), A::Error> {
        let imp = self.0;
        while let Some(e) = s.next_element::<HarEntry>()? {
            if imp.p.cancelled() {
                return Err(serde::de::Error::custom("cancelled"));
            }
            let (d, req, resp) = to_session(imp.cap, e);
            imp.ids.push(imp.cap.insert(d, req, resp));
            imp.p.progress(imp.ids.len() as u64, 0);
        }
        Ok(())
    }
}

pub fn import(cap: &Arc<Capture>, path: &Path, p: &dyn Progress) -> Result<Vec<SessionId>> {
    let f = BufReader::with_capacity(1 << 20, File::open(path)?);
    let mut ids = Vec::new();
    let mut de = serde_json::Deserializer::from_reader(f);
    Import { cap, ids: &mut ids, p }.deserialize(&mut de).map_err(|e| {
        if e.to_string().contains("cancelled") { FormatError::Cancelled } else { FormatError::Json(e) }
    })?;
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NoProgress;
    use quena_body::BodyConfig;

    fn sample(cap: &Arc<Capture>) -> SessionId {
        let mut d = SessionDetail::default();
        let mut rh = Headers::new();
        rh.push("Host", "example.com");
        rh.push("Cookie", "a=1; b=2");
        rh.push("Content-Type", "application/json");
        d.request = RequestHead { method: "POST".into(), url: "https://example.com/api?x=1&y=2".into(), version: HttpVersion::Http11, headers: rh };
        let mut sh = Headers::new();
        sh.push("Content-Type", "text/html; charset=utf-8");
        sh.push("Content-Encoding", "gzip");
        sh.push("Transfer-Encoding", "chunked");
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all("<p>Grüße \"quoted\"</p>".as_bytes()).unwrap();
        let gz = gz.finish().unwrap();
        d.response = Some(ResponseHead { status: 200, reason: "OK".into(), version: HttpVersion::Http11, headers: sh });
        d.summary.state = SessionState::Done;
        d.summary.comment = "hello".into();
        d.summary.color = Some(MarkColor::Red);
        d.process = Some(ProcessInfo { pid: 42, name: "chrome".into() });
        d.timers.client_begin_request = Some(1_790_000_000_000_000);
        d.timers.client_done_response = Some(1_790_000_000_250_000);
        let req = cap.bodies.store_bytes(br#"{"q":1}"#);
        let resp = cap.bodies.store_bytes(&gz);
        cap.insert(d, req, resp)
    }

    #[test]
    fn har_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let cap = Capture::open(dir.path().join("a"), BodyConfig::default(), true).unwrap();
        let id = sample(&cap);
        let path = dir.path().join("x.har");
        assert_eq!(export(&cap, &[id], &path, &HarOptions::default(), &NoProgress).unwrap(), 1);
        let v: serde_json::Value = serde_json::from_reader(File::open(&path).unwrap()).unwrap();
        let e = &v["log"]["entries"][0];
        assert_eq!(e["response"]["content"]["text"], "<p>Grüße \"quoted\"</p>");
        assert_eq!(e["request"]["postData"]["text"], r#"{"q":1}"#);
        assert_eq!(e["request"]["queryString"][1]["value"], "2");
        let cap2 = Capture::open(dir.path().join("b"), BodyConfig::default(), true).unwrap();
        let ids = import(&cap2, &path, &NoProgress).unwrap();
        assert_eq!(ids.len(), 1);
        let d = cap2.detail(ids[0]).unwrap();
        assert_eq!(d.request.method, "POST");
        assert_eq!(d.summary.comment, "hello");
        let (_, resp) = cap2.bodies_of(ids[0]).unwrap();
        assert_eq!(String::from_utf8(resp.read_range(0, 1000).unwrap()).unwrap(), "<p>Grüße \"quoted\"</p>");
    }

    #[test]
    fn saz_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let cap = Capture::open(dir.path().join("a"), BodyConfig::default(), true).unwrap();
        let id = sample(&cap);
        let path = dir.path().join("x.saz");
        assert_eq!(crate::saz::export(&cap, &[id], &path, &NoProgress).unwrap(), 1);
        let cap2 = Capture::open(dir.path().join("b"), BodyConfig::default(), true).unwrap();
        let ids = crate::saz::import(&cap2, &path, &NoProgress).unwrap();
        assert_eq!(ids.len(), 1);
        let d = cap2.detail(ids[0]).unwrap();
        let orig = cap.detail(id).unwrap();
        assert_eq!(d.request.url, orig.request.url);
        assert_eq!(d.response.as_ref().unwrap().status, 200);
        assert_eq!(d.summary.color, Some(MarkColor::Red));
        assert_eq!(d.summary.comment, "hello");
        assert_eq!(d.process.as_ref().unwrap().display(), "chrome:42");
        assert_eq!(d.timers.client_begin_request, orig.timers.client_begin_request);
        // chunked re-encoding round-trips to the same raw bytes
        let (_, a) = cap.bodies_of(id).unwrap();
        let (_, b) = cap2.bodies_of(ids[0]).unwrap();
        assert_eq!(a.read_range(0, 10_000).unwrap(), b.read_range(0, 10_000).unwrap());
    }
}
