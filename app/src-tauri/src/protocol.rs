//! `quena://localhost/body/{session}/{part}/{variant}` – body bytes with
//! HTTP Range support (inspectors, hex view, image/media preview). Bodies
//! never travel through the JSON IPC.

use quena_app_core::AppCore;
use quena_app_core::dto::Part;
use quena_body::Variant;
use tauri::http::{Request, Response, StatusCode, header};

fn error(status: StatusCode, msg: &str) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(msg.as_bytes().to_vec())
        .expect("response")
}

fn parse_range(v: &str, total: u64) -> Option<(u64, u64)> {
    let v = v.strip_prefix("bytes=")?;
    let (a, b) = v.split_once('-')?;
    if a.is_empty() {
        let n: u64 = b.parse().ok()?;
        return Some((total.saturating_sub(n), total.saturating_sub(1)));
    }
    let start: u64 = a.parse().ok()?;
    let end = if b.is_empty() { total.saturating_sub(1) } else { b.parse::<u64>().ok()?.min(total.saturating_sub(1)) };
    Some((start, end))
}

pub fn handle(core: &AppCore, req: Request<Vec<u8>>) -> Response<Vec<u8>> {
    // convertFileSrc() percent-encodes the whole path (including '/').
    let raw = req.uri().path().trim_start_matches('/');
    let path = percent_encoding::percent_decode_str(raw).decode_utf8_lossy().to_string();
    let parts: Vec<&str> = path.split('/').collect();
    if req.method() == "OPTIONS" {
        return Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header(header::ACCESS_CONTROL_ALLOW_HEADERS, "Range")
            .body(Vec::new())
            .expect("response");
    }
    if parts.len() != 4 || parts[0] != "body" {
        return error(StatusCode::NOT_FOUND, "not found");
    }
    let (Ok(id), Some(part), Some(variant)) = (parts[1].parse::<u64>(), Part::parse(parts[2]), Variant::parse(parts[3])) else {
        return error(StatusCode::BAD_REQUEST, "bad body path");
    };
    let (total, complete, _) = match core.body_len(id, part, variant) {
        Ok(v) => v,
        Err(e) => return error(StatusCode::NOT_FOUND, &e.to_string()),
    };
    let range = req.headers().get(header::RANGE).and_then(|v| v.to_str().ok()).and_then(|v| parse_range(v, total));
    let (start, end) = range.unwrap_or((0, total.saturating_sub(1)));
    // Without a Range header only the first 16 MB are served.
    let len = if total == 0 || start > end { 0 } else { (end - start + 1).min(16 << 20) as usize };
    let body = match core.body_range(id, part, variant, start, len) {
        Ok(b) => b,
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    let ct = if variant == Variant::Raw && !body.content_type.as_deref().is_some_and(|c| c.starts_with("image/") || c.starts_with("video/") || c.starts_with("audio/")) {
        "application/octet-stream".to_string()
    } else {
        body.content_type.clone().unwrap_or_else(|| "application/octet-stream".into())
    };
    let n = body.data.len() as u64;
    let mut b = Response::builder()
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .header(header::ACCESS_CONTROL_EXPOSE_HEADERS, "Content-Range, X-Quena-Total, X-Quena-Complete, X-Quena-Variant, X-Quena-Charset")
        .header(header::CONTENT_TYPE, ct)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CACHE_CONTROL, "no-store")
        .header("X-Quena-Total", total.to_string())
        .header("X-Quena-Complete", if complete { "1" } else { "0" })
        .header("X-Quena-Variant", body.variant.name());
    // The bytes are in this charset regardless of the body's own (transcoded text).
    if let Some(cs) = body.charset {
        b = b.header("X-Quena-Charset", cs);
    }
    if range.is_some() {
        b = b.status(StatusCode::PARTIAL_CONTENT).header(
            header::CONTENT_RANGE,
            if n == 0 { format!("bytes */{total}") } else { format!("bytes {start}-{}/{total}", start + n - 1) },
        );
    } else {
        b = b.status(StatusCode::OK);
    }
    b.body(body.data).expect("response")
}
