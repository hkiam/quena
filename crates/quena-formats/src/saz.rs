//! Fiddler SAZ archives (`raw/NN_c.txt`, `raw/NN_s.txt`, `raw/NN_m.xml`).
//!
//! Export is Fiddler Classic compatible; bodies are streamed into the ZIP
//! (zip64 for entries > 4 GB). Import streams bodies out of the ZIP and
//! de-chunks them on the fly.

use crate::raw::{self, ChunkedReader};
use crate::time_fmt::{from_dotnet, to_dotnet};
use crate::{FormatError, Progress, Result};
use quena_body::Body;
use quena_model::*;
use quena_store::Capture;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::Arc;
use zip::write::SimpleFileOptions;

const CONTENT_TYPES: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="htm" ContentType="text/html" />
<Default Extension="xml" ContentType="application/xml" />
<Default Extension="txt" ContentType="text/plain" />
</Types>"#;

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn color_name(c: MarkColor) -> &'static str {
    match c {
        MarkColor::Red => "Red",
        MarkColor::Blue => "Blue",
        MarkColor::Gold => "Gold",
        MarkColor::Green => "Green",
        MarkColor::Orange => "Orange",
        MarkColor::Purple => "Purple",
    }
}

fn copy_body(body: &Body, w: &mut dyn Write, p: &dyn Progress) -> Result<u64> {
    let mut r = body.stream(0, false);
    let mut buf = vec![0u8; 1 << 20];
    let mut n = 0u64;
    loop {
        if p.cancelled() {
            return Err(FormatError::Cancelled);
        }
        let k = r.read(&mut buf)?;
        if k == 0 {
            return Ok(n);
        }
        w.write_all(&buf[..k])?;
        n += k as u64;
    }
}

/// Write the body; if the head says `chunked`, re-chunk it as a single chunk
/// (the store keeps de-chunked bytes).
fn write_body(w: &mut dyn Write, headers: &Headers, body: &Body, p: &dyn Progress) -> Result<()> {
    if raw::is_chunked(headers) {
        if !body.is_empty() {
            write!(w, "{:x}\r\n", body.len())?;
            copy_body(body, w, p)?;
            w.write_all(b"\r\n")?;
        }
        w.write_all(b"0\r\n\r\n")?;
    } else {
        copy_body(body, w, p)?;
    }
    Ok(())
}

fn metadata(sid: usize, d: &SessionDetail) -> String {
    let t = &d.timers;
    let mut flags: Vec<(String, String)> = Vec::new();
    if let Some(a) = &d.connection.client_addr {
        if let Some((ip, port)) = a.rsplit_once(':') {
            flags.push(("x-clientip".into(), ip.trim_matches(['[', ']']).into()));
            flags.push(("x-clientport".into(), port.into()));
        }
    }
    if let Some(p) = &d.process {
        flags.push(("x-processinfo".into(), p.display()));
    }
    if let Some(a) = &d.connection.server_addr {
        flags.push(("x-hostip".into(), a.rsplit_once(':').map(|(ip, _)| ip.trim_matches(['[', ']']).to_string()).unwrap_or_else(|| a.clone())));
    }
    if let Some(c) = d.summary.color {
        flags.push(("ui-color".into(), color_name(c).into()));
        flags.push(("ui-bold".into(), "true".into()));
    }
    if !d.summary.comment.is_empty() {
        flags.push(("ui-comments".into(), d.summary.comment.clone()));
    }
    if !d.summary.custom.is_empty() {
        flags.push(("ui-customcolumn".into(), d.summary.custom.clone()));
    }
    if d.request.version == HttpVersion::Http2 {
        flags.push(("x-quena-http-version".into(), "HTTP/2".into()));
    }
    if d.summary.has_flag(flags::DECRYPTED) {
        flags.push(("https-client-sessionid".into(), "decrypted".into()));
    }
    if d.summary.state == SessionState::Aborted {
        flags.push(("x-quena-aborted".into(), d.error.clone().unwrap_or_default()));
    }
    if d.summary.has_flag(flags::AUTO_RESPONDED) {
        flags.push(("x-autoresponder".into(), "true".into()));
    }
    for (k, v) in &d.extra_flags {
        if !flags.iter().any(|(n, _)| n == k) {
            flags.push((k.clone(), v.clone()));
        }
    }
    let bitflags = if d.summary.kind == SessionKind::Tunnel { 0x2000 } else { 0 };
    let mut s = String::new();
    s.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n");
    s.push_str(&format!("<Session SID=\"{sid}\" BitFlags=\"{bitflags}\">\r\n"));
    s.push_str(&format!(
        "  <SessionTimers ClientConnected=\"{}\" ClientBeginRequest=\"{}\" GotRequestHeaders=\"{}\" ClientDoneRequest=\"{}\" GatewayTime=\"{}\" DNSTime=\"{}\" TCPConnectTime=\"{}\" HTTPSHandshakeTime=\"{}\" ServerConnected=\"{}\" FiddlerBeginRequest=\"{}\" ServerGotRequest=\"{}\" ServerBeginResponse=\"{}\" GotResponseHeaders=\"{}\" ServerDoneResponse=\"{}\" ClientBeginResponse=\"{}\" ClientDoneResponse=\"{}\" />\r\n",
        to_dotnet(t.client_connected),
        to_dotnet(t.client_begin_request),
        to_dotnet(t.got_request_headers),
        to_dotnet(t.client_done_request),
        t.gateway_ms.unwrap_or(0),
        t.dns_ms.unwrap_or(0),
        t.tcp_connect_ms.unwrap_or(0),
        t.tls_handshake_ms.unwrap_or(0),
        to_dotnet(t.server_connected),
        to_dotnet(t.server_begin_request),
        to_dotnet(t.server_done_request),
        to_dotnet(t.server_got_first_byte),
        to_dotnet(t.got_response_headers),
        to_dotnet(t.server_done_response),
        to_dotnet(t.client_begin_response),
        to_dotnet(t.client_done_response),
    ));
    s.push_str(&format!("  <PipeInfo{} />\r\n", if d.connection.server_conn_reused { " Reused=\"true\"" } else { "" }));
    s.push_str("  <SessionFlags>\r\n");
    for (k, v) in flags {
        s.push_str(&format!("    <SessionFlag N=\"{}\" V=\"{}\" />\r\n", xml_escape(&k), xml_escape(&v)));
    }
    s.push_str("  </SessionFlags>\r\n</Session>");
    s
}

/// Export sessions to a SAZ file. Returns the number of sessions written.
pub fn export(cap: &Arc<Capture>, ids: &[SessionId], path: &Path, p: &dyn Progress) -> Result<usize> {
    let tmp = path.with_extension("saz.part");
    let file = BufWriter::with_capacity(1 << 20, File::create(&tmp)?);
    let mut zip = zip::ZipWriter::new(file);
    let deflate = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated).large_file(true);
    zip.start_file("[Content_Types].xml", deflate)?;
    zip.write_all(CONTENT_TYPES.as_bytes())?;
    let width = ids.len().to_string().len().max(2);
    let mut index = String::from("<html><head><style>body,thead,td,a,p{font-family:verdana,sans-serif;font-size:10px;}</style></head><body><table cols=12><thead><tr><th>&nbsp;</th><th>#</th><th>Result</th><th>Protocol</th><th>Host</th><th>URL</th><th>Body</th><th>Caching</th><th>Content-Type</th><th>Process</th><th>Comments</th><th>Custom</th></tr></thead><tbody>");
    let mut n = 0;
    for (i, id) in ids.iter().enumerate() {
        if p.cancelled() {
            drop(zip);
            let _ = std::fs::remove_file(&tmp);
            return Err(FormatError::Cancelled);
        }
        p.progress(i as u64, ids.len() as u64);
        let Some(d) = cap.detail(*id) else { continue };
        let Some((req_body, resp_body)) = cap.bodies_of(*id) else { continue };
        let num = format!("{:0width$}", i + 1);
        // Bodies can be huge and are often already compressed – store large ones.
        let opts = |len: u64| if len > 8 << 20 { SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored).large_file(true) } else { deflate };
        zip.start_file(format!("raw/{num}_c.txt"), opts(req_body.len()))?;
        raw::write_request_head(&mut zip, &d.request)?;
        write_body(&mut zip, &d.request.headers, &req_body, p)?;
        zip.start_file(format!("raw/{num}_s.txt"), opts(resp_body.len()))?;
        if let Some(r) = &d.response {
            raw::write_response_head(&mut zip, r)?;
            write_body(&mut zip, &r.headers, &resp_body, p)?;
        } else {
            zip.write_all(b"HTTP/1.1 504 Receive Failure\r\nContent-Length: 0\r\n\r\n")?;
        }
        zip.start_file(format!("raw/{num}_m.xml"), deflate)?;
        zip.write_all(metadata(i + 1, &d).as_bytes())?;
        let s = &d.summary;
        index.push_str(&format!(
            "<tr><td><a href='raw\\{num}_c.txt'>C</a>&nbsp;<a href='raw\\{num}_s.txt'>S</a>&nbsp;<a href='raw\\{num}_m.xml'>M</a></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            s.id,
            s.status,
            xml_escape(&s.protocol),
            xml_escape(&s.host),
            xml_escape(&s.url),
            s.response_body_len,
            xml_escape(&s.caching),
            xml_escape(&s.content_type),
            xml_escape(&s.process),
            xml_escape(&s.comment),
            xml_escape(&s.custom)
        ));
        n += 1;
    }
    index.push_str("</tbody></table></body></html>");
    zip.start_file("_index.htm", deflate)?;
    zip.write_all(index.as_bytes())?;
    zip.finish()?.flush()?;
    std::fs::rename(tmp, path)?;
    p.progress(ids.len() as u64, ids.len() as u64);
    Ok(n)
}

#[derive(Default)]
struct Entry {
    c: Option<usize>,
    s: Option<usize>,
    m: Option<usize>,
}

fn read_meta(xml: &str, d: &mut SessionDetail) {
    use quick_xml::events::Event;
    let mut r = quick_xml::Reader::from_str(xml);
    loop {
        match r.read_event() {
            Ok(Event::Empty(e)) | Ok(Event::Start(e)) => {
                let name = e.name();
                let attrs: BTreeMap<String, String> = e
                    .attributes()
                    .flatten()
                    .map(|a| (String::from_utf8_lossy(a.key.as_ref()).into_owned(), a.unescape_value().map(|v| v.into_owned()).unwrap_or_default()))
                    .collect();
                match name.as_ref() {
                    b"Session" => {
                        if attrs.get("BitFlags").and_then(|b| b.parse::<u32>().ok()).is_some_and(|b| b & 0x2000 != 0) {
                            d.summary.kind = SessionKind::Tunnel;
                        }
                    }
                    b"SessionTimers" => {
                        let t = &mut d.timers;
                        let g = |k: &str| attrs.get(k).and_then(|v| from_dotnet(v));
                        let ms = |k: &str| attrs.get(k).and_then(|v| v.parse::<i64>().ok()).filter(|v| *v > 0).map(|v| v as u32);
                        t.client_connected = g("ClientConnected");
                        t.client_begin_request = g("ClientBeginRequest");
                        t.got_request_headers = g("GotRequestHeaders");
                        t.client_done_request = g("ClientDoneRequest");
                        t.server_connected = g("ServerConnected");
                        t.server_begin_request = g("FiddlerBeginRequest");
                        t.server_done_request = g("ServerGotRequest");
                        t.server_got_first_byte = g("ServerBeginResponse");
                        t.got_response_headers = g("GotResponseHeaders");
                        t.server_done_response = g("ServerDoneResponse");
                        t.client_begin_response = g("ClientBeginResponse");
                        t.client_done_response = g("ClientDoneResponse");
                        t.gateway_ms = ms("GatewayTime");
                        t.dns_ms = ms("DNSTime");
                        t.tcp_connect_ms = ms("TCPConnectTime");
                        t.tls_handshake_ms = ms("HTTPSHandshakeTime");
                    }
                    b"PipeInfo" => {
                        d.connection.server_conn_reused = attrs.get("Reused").is_some_and(|v| v == "true");
                    }
                    b"SessionFlag" => {
                        let (Some(n), Some(v)) = (attrs.get("N"), attrs.get("V")) else { continue };
                        match n.to_ascii_lowercase().as_str() {
                            "x-processinfo" => {
                                let (name, pid) = v.rsplit_once(':').map(|(a, b)| (a.to_string(), b.parse().unwrap_or(0))).unwrap_or((v.clone(), 0));
                                d.process = Some(ProcessInfo { pid, name });
                            }
                            "x-clientip" => d.summary.client_ip = v.clone(),
                            "x-clientport" => {
                                d.connection.client_addr = Some(format!("{}:{v}", if d.summary.client_ip.is_empty() { "?" } else { &d.summary.client_ip }))
                            }
                            "x-hostip" => d.connection.server_addr = Some(v.clone()),
                            "ui-color" => d.summary.color = MarkColor::parse(v),
                            "ui-comments" => d.summary.comment = v.clone(),
                            "ui-customcolumn" => d.summary.custom = v.clone(),
                            "x-quena-http-version" => {
                                if let Some(ver) = HttpVersion::parse(v) {
                                    d.request.version = ver;
                                    if let Some(r) = d.response.as_mut() {
                                        r.version = ver;
                                    }
                                }
                            }
                            "https-client-sessionid" => d.summary.flags |= flags::DECRYPTED,
                            "x-autoresponder" => d.summary.flags |= flags::AUTO_RESPONDED,
                            "x-quena-aborted" => {
                                d.summary.state = SessionState::Aborted;
                                if !v.is_empty() {
                                    d.error = Some(v.clone());
                                }
                            }
                            _ => {}
                        }
                        d.extra_flags.push((n.clone(), v.clone()));
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
}

/// `_m.xml` is small; anything beyond this is not metadata.
const MAX_META: u64 = 1 << 20;

/// Read a message (head + body) from a ZIP entry into the store. The body is
/// recorded with the normal recording limit; reading stops once it truncates.
fn read_message<R: Read>(cap: &Arc<Capture>, r: R, p: &dyn Progress) -> Result<Option<(String, Headers, Body)>> {
    let mut br = BufReader::with_capacity(256 * 1024, r);
    let Some((first, headers)) = raw::read_head(&mut br)? else { return Ok(None) };
    let mut w = cap.bodies.writer();
    let mut buf = vec![0u8; 1 << 20];
    let mut src: Box<dyn Read> = if raw::is_chunked(&headers) { Box::new(ChunkedReader::new(br)) } else { Box::new(br) };
    loop {
        if p.cancelled() {
            return Err(FormatError::Cancelled);
        }
        let n = match src.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                // Corrupt/truncated entry: keep what was read so far.
                tracing::warn!("SAZ body: {e}");
                w.add_dropped(1);
                break;
            }
        };
        if n == 0 {
            break;
        }
        if let Err(e) = w.write(&buf[..n]) {
            tracing::warn!("SAZ body not stored completely: {e}");
            w.add_dropped(n as u64);
            break;
        }
        if w.body().is_truncated() {
            break;
        }
    }
    Ok(Some((first, headers, w.finish())))
}

/// Read one session from its ZIP entries. `Ok(None)`: no usable request.
fn read_session<R: Read + io::Seek>(cap: &Arc<Capture>, zip: &mut zip::ZipArchive<R>, e: &Entry, p: &dyn Progress) -> Result<Option<(SessionDetail, Body, Body)>> {
    let Some(ci) = e.c else { return Ok(None) };
    let mut d = SessionDetail::default();
    let (req_first, req_headers, req_body) = match read_message(cap, zip.by_index(ci)?, p)? {
        Some(v) => v,
        None => return Ok(None),
    };
    let (method, url, version) = raw::parse_request_line(&req_first);
    let url = if url.starts_with('/') {
        let host = req_headers.get("host").unwrap_or("unknown");
        let scheme = if host.ends_with(":443") { "https" } else { "http" };
        format!("{scheme}://{host}{url}")
    } else {
        url
    };
    if method.eq_ignore_ascii_case("CONNECT") {
        d.summary.kind = SessionKind::Tunnel;
    }
    d.request = RequestHead { method, url, version, headers: req_headers };
    let mut resp_body = cap.bodies.store_bytes(&[]);
    // A broken response or metadata entry doesn't lose the request.
    if let Some(si) = e.s {
        match zip.by_index(si).map_err(FormatError::from).and_then(|f| read_message(cap, f, p)) {
            Ok(Some((first, headers, body))) => {
                let (v, status, reason) = raw::parse_status_line(&first);
                d.response = Some(ResponseHead { status, reason, version: v, headers });
                resp_body = body;
            }
            Ok(None) => {}
            Err(FormatError::Cancelled) => return Err(FormatError::Cancelled),
            Err(err) => d.error = Some(format!("SAZ response entry unreadable: {err}")),
        }
    }
    if let Some(mi) = e.m {
        let mut b = Vec::new();
        match zip.by_index(mi).map_err(FormatError::from).and_then(|f| Ok(f.take(MAX_META).read_to_end(&mut b)?)) {
            Ok(_) => read_meta(&String::from_utf8_lossy(&b), &mut d),
            Err(err) => tracing::warn!("SAZ metadata entry unreadable: {err}"),
        }
    }
    Ok(Some((d, req_body, resp_body)))
}

/// Import a SAZ file into `cap`. Returns the new session ids. Unreadable entries
/// (corrupt, encrypted, unsupported compression) are skipped and logged.
pub fn import(cap: &Arc<Capture>, path: &Path, p: &dyn Progress) -> Result<Vec<SessionId>> {
    let file = File::open(path)?;
    let mut zip = zip::ZipArchive::new(BufReader::new(file))?;
    let mut entries: BTreeMap<String, Entry> = BTreeMap::new();
    let mut skipped = 0usize;
    for i in 0..zip.len() {
        let name = match zip.by_index_raw(i) {
            Ok(f) => f.name().replace('\\', "/"),
            Err(e) => {
                tracing::warn!("SAZ entry {i}: {e}");
                skipped += 1;
                continue;
            }
        };
        let Some(rest) = name.strip_prefix("raw/") else { continue };
        let Some((num, kind)) = rest.rsplit_once('_') else { continue };
        let e = entries.entry(num.to_string()).or_default();
        match kind {
            "c.txt" => e.c = Some(i),
            "s.txt" => e.s = Some(i),
            "m.xml" => e.m = Some(i),
            _ => {}
        }
    }
    // Numeric order (01, 02 … 100).
    let mut keys: Vec<String> = entries.keys().cloned().collect();
    keys.sort_by_key(|k| k.parse::<u64>().unwrap_or(u64::MAX));
    let total = keys.len() as u64;
    let mut ids = Vec::new();
    for (n, k) in keys.iter().enumerate() {
        if p.cancelled() {
            return Err(FormatError::Cancelled);
        }
        p.progress(n as u64, total);
        let (mut d, req_body, resp_body) = match read_session(cap, &mut zip, &entries[k], p) {
            Ok(Some(v)) => v,
            Ok(None) => continue,
            Err(FormatError::Cancelled) => return Err(FormatError::Cancelled),
            Err(e) => {
                tracing::warn!("SAZ session {k} skipped: {e}");
                skipped += 1;
                continue;
            }
        };
        if d.summary.state != SessionState::Aborted {
            d.summary.state = SessionState::Done;
        }
        d.summary.flags |= flags::IMPORTED;
        d.summary.started_at = d.timers.client_begin_request.or(d.timers.client_connected).unwrap_or_else(now_us);
        let id = cap.insert(d, req_body, resp_body);
        ids.push(id);
    }
    if skipped > 0 {
        tracing::warn!(skipped, imported = ids.len(), "SAZ import: skipped unreadable entries");
    }
    p.progress(total, total);
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NoProgress;
    use quena_body::BodyConfig;

    #[test]
    fn bad_entries_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.saz");
        {
            let mut z = zip::ZipWriter::new(File::create(&path).unwrap());
            let o = SimpleFileOptions::default();
            z.start_file("raw/01_c.txt", o).unwrap();
            z.write_all(b"GET http://a/ok HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
            z.start_file("raw/01_s.txt", o).unwrap();
            z.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\nzz\r\n").unwrap();
            z.start_file("raw/01_m.xml", o).unwrap();
            z.write_all(b"<Session><SessionFlags><SessionFlag N=\"ui-comments\" V=\"caf\xe9\" /></SessionFlags></Session>").unwrap();
            // Head without end: a 2 MB line.
            z.start_file("raw/02_c.txt", o).unwrap();
            z.write_all(&vec![b'a'; 2 << 20]).unwrap();
            z.start_file("raw/03_c.txt", o).unwrap();
            z.write_all(b"GET http://a/three HTTP/1.1\r\n\r\n").unwrap();
            z.finish().unwrap();
        }
        let cap = Capture::open(dir.path().join("cap"), BodyConfig { max_recorded_body: 3, ..Default::default() }, true).unwrap();
        let ids = import(&cap, &path, &NoProgress).unwrap();
        assert_eq!(ids.len(), 2);
        let d = cap.detail(ids[0]).unwrap();
        assert_eq!(d.summary.comment, "caf\u{fffd}");
        let (_, resp) = cap.bodies_of(ids[0]).unwrap();
        assert_eq!(resp.read_range(0, 100).unwrap(), b"hel");
        assert!(resp.is_truncated());
        assert_eq!(cap.detail(ids[1]).unwrap().request.url, "http://a/three");
    }
}
