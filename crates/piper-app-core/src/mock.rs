//! Mock traffic generator (M0, UI and performance testing without a proxy).

use crate::AppCore;
use piper_jobs::Priority;
use piper_model::*;
use rand::Rng;
use rand::seq::IndexedRandom;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub struct MockHandle {
    stop: Arc<AtomicBool>,
}

const HOSTS: &[&str] = &[
    "api.company.de", "service.company.de", "www.example.com", "cdn.example.net", "login.microsoftonline.com",
    "graph.microsoft.com", "fonts.gstatic.com", "soap.example.com", "telemetry.vendor.io", "github.com",
    "api.github.com", "registry.npmjs.org", "localhost:8080", "10.0.0.12:8443", "ws.chat.example",
];
const PROCS: &[(&str, u32)] = &[
    ("chrome", 4211), ("safari", 811), ("firefox", 2210), ("curl", 9921), ("Teams", 3120), ("java", 7781), ("node", 5512),
    ("dotnet", 6620),
];

enum Kind {
    Json,
    Html,
    Xml,
    Soap,
    Js,
    Css,
    Png,
    GzJson,
    Empty,
    Font,
}

fn body_for(kind: &Kind, rng: &mut impl Rng) -> (Vec<u8>, &'static str, Option<&'static str>) {
    match kind {
        Kind::Json => {
            let n = rng.random_range(1..30);
            let items: Vec<String> = (0..n)
                .map(|i| format!(r#"{{"id":{i},"name":"item-{i}","active":{},"score":{:.3},"tags":["a","b"]}}"#, rng.random_bool(0.5), rng.random::<f64>()))
                .collect();
            (format!(r#"{{"ok":true,"count":{n},"items":[{}]}}"#, items.join(",")).into_bytes(), "application/json; charset=utf-8", None)
        }
        Kind::GzJson => {
            let (raw, ct, _) = body_for(&Kind::Json, rng);
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            e.write_all(&raw).unwrap();
            (e.finish().unwrap(), ct, Some("gzip"))
        }
        Kind::Html => (
            b"<!doctype html><html><head><title>Piper Mock</title></head><body><h1>Hello</h1><p>Mock page</p></body></html>".to_vec(),
            "text/html; charset=utf-8",
            None,
        ),
        Kind::Xml => (b"<?xml version=\"1.0\"?><items><item id=\"1\">one</item><item id=\"2\">two</item></items>".to_vec(), "application/xml", None),
        Kind::Soap => (
            br#"<?xml version="1.0" encoding="utf-8"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Header><h:Trace xmlns:h="urn:t">42</h:Trace></s:Header><s:Body><GetOrderResponse xmlns="urn:orders"><Order id="4711"><Status>shipped</Status></Order></GetOrderResponse></s:Body></s:Envelope>"#.to_vec(),
            "text/xml; charset=utf-8",
            None,
        ),
        Kind::Js => (b"(function(){console.log('piper');var a=1,b=2;return a+b;})();".to_vec(), "application/javascript", None),
        Kind::Css => (b"body{margin:0;font-family:system-ui}h1{color:#c00}".to_vec(), "text/css", None),
        Kind::Png => (PNG.to_vec(), "image/png", None),
        Kind::Font => (vec![0u8; 2048], "font/woff2", None),
        Kind::Empty => (Vec::new(), "", None),
    }
}

/// 1x1 red PNG.
const PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, 0x08,
    0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00, 0x00, 0x03, 0x01, 0x01, 0x00, 0x18, 0xDD, 0x8D, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45,
    0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
];

fn random_session(rng: &mut impl Rng) -> (SessionDetail, Vec<u8>, Vec<u8>) {
    let host = *HOSTS.choose(rng).unwrap();
    let (proc_name, pid) = *PROCS.choose(rng).unwrap();
    let https = !host.starts_with("localhost") && rng.random_bool(0.9);
    let kind = match rng.random_range(0..100) {
        0..30 => Kind::Json,
        30..40 => Kind::GzJson,
        40..48 => Kind::Html,
        48..54 => Kind::Xml,
        54..62 => Kind::Soap,
        62..70 => Kind::Js,
        70..75 => Kind::Css,
        75..85 => Kind::Png,
        85..88 => Kind::Font,
        _ => Kind::Empty,
    };
    let method = match kind {
        Kind::Soap => "POST",
        _ => *["GET", "GET", "GET", "GET", "POST", "PUT", "DELETE", "OPTIONS"].choose(rng).unwrap(),
    };
    let status = *[200u16, 200, 200, 200, 200, 200, 204, 301, 302, 304, 400, 401, 403, 404, 500, 502, 503].choose(rng).unwrap();
    let path = match kind {
        Kind::Soap => "/services/OrderService.svc".to_string(),
        Kind::Png => format!("/img/{}.png", rng.random_range(1..999)),
        Kind::Js => "/static/app.js".into(),
        Kind::Css => "/static/site.css".into(),
        Kind::Font => "/fonts/inter.woff2".into(),
        _ => format!("/api/v{}/{}?page={}", rng.random_range(1..3), ["orders", "users", "login", "search", "items"].choose(rng).unwrap(), rng.random_range(1..50)),
    };
    let url = format!("{}://{host}{path}", if https { "https" } else { "http" });
    let (req_body, req_ct) = if method == "POST" || method == "PUT" {
        if matches!(kind, Kind::Soap) {
            (br#"<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><GetOrder xmlns="urn:orders"><id>4711</id></GetOrder></s:Body></s:Envelope>"#.to_vec(), "text/xml; charset=utf-8")
        } else if rng.random_bool(0.5) {
            (b"user=alice&password=secret&remember=true".to_vec(), "application/x-www-form-urlencoded")
        } else {
            (br#"{"query":"piper","limit":20}"#.to_vec(), "application/json")
        }
    } else {
        (Vec::new(), "")
    };
    let mut rh = Headers::new();
    rh.push("Host", host);
    rh.push("User-Agent", format!("Mozilla/5.0 (Macintosh) {proc_name}"));
    rh.push("Accept", "*/*");
    rh.push("Accept-Encoding", "gzip, deflate, br");
    if !req_ct.is_empty() {
        rh.push("Content-Type", req_ct);
        rh.push("Content-Length", req_body.len().to_string());
    }
    if matches!(kind, Kind::Soap) {
        rh.push("SOAPAction", "\"urn:orders/GetOrder\"");
    }
    rh.push("Cookie", "session=abc123; theme=dark");
    let (mut body, ct, ce) = body_for(&kind, rng);
    if status == 304 || status == 204 || method == "OPTIONS" {
        body.clear();
    }
    let mut sh = Headers::new();
    sh.push("Date", "Mon, 28 Sep 2026 10:00:00 GMT");
    sh.push("Server", "mock/1.0");
    if !ct.is_empty() && !body.is_empty() {
        sh.push("Content-Type", ct);
    }
    if let Some(ce) = ce {
        sh.push("Content-Encoding", ce);
    }
    sh.push("Content-Length", body.len().to_string());
    sh.push("Cache-Control", *["no-cache", "max-age=3600", "private, max-age=0", "public, max-age=31536000"].choose(rng).unwrap());
    if status == 301 || status == 302 {
        sh.push("Location", format!("https://{host}/new"));
    }
    let now = now_us();
    let dur = rng.random_range(2_000..900_000i64);
    let d = SessionDetail {
        request: RequestHead { method: method.into(), url, version: HttpVersion::Http11, headers: rh },
        response: Some(ResponseHead { status, reason: reason(status).into(), version: HttpVersion::Http11, headers: sh }),
        timers: Timers {
            client_connected: Some(now - dur - 1000),
            client_begin_request: Some(now - dur),
            got_request_headers: Some(now - dur + 100),
            client_done_request: Some(now - dur + 200),
            server_connected: Some(now - dur + 5000),
            server_got_first_byte: Some(now - dur / 3),
            got_response_headers: Some(now - dur / 3),
            server_done_response: Some(now - 100),
            client_done_response: Some(now),
            tcp_connect_ms: Some(rng.random_range(1..40)),
            tls_handshake_ms: if https { Some(rng.random_range(5..80)) } else { None },
            ..Default::default()
        },
        process: Some(ProcessInfo { pid, name: proc_name.into() }),
        connection: ConnectionInfo { client_addr: Some(format!("127.0.0.1:{}", rng.random_range(50000..65000))), ..Default::default() },
        summary: SessionSummary {
            state: SessionState::Done,
            flags: if https { flags::DECRYPTED } else { 0 },
            client_ip: "127.0.0.1".into(),
            ..Default::default()
        },
        ..Default::default()
    };
    (d, req_body, body)
}

pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "",
    }
}

/// Start generating `total` sessions at `rate` per second (0 total = unlimited).
pub fn start(core: &Arc<AppCore>, rate: u32, total: u64) {
    stop(core);
    let stop_flag = Arc::new(AtomicBool::new(false));
    *core.mock.lock() = Some(MockHandle { stop: stop_flag.clone() });
    let weak = Arc::downgrade(core);
    std::thread::Builder::new()
        .name("piper-mock".into())
        .spawn(move || {
            let mut rng = rand::rng();
            let start = Instant::now();
            let mut made = 0u64;
            let rate = rate.max(1) as f64;
            while !stop_flag.load(Ordering::Relaxed) && (total == 0 || made < total) {
                let Some(core) = weak.upgrade() else { return };
                let cap = core.capture();
                let due = (start.elapsed().as_secs_f64() * rate) as u64;
                let batch = due.saturating_sub(made).min(10_000);
                for _ in 0..batch {
                    let (d, req, resp) = random_session(&mut rng);
                    let rb = cap.bodies.store_bytes(&req);
                    let sb = cap.bodies.store_bytes(&resp);
                    cap.insert(d, rb, sb);
                    made += 1;
                    if total != 0 && made >= total {
                        break;
                    }
                }
                // Occasionally a slow streaming download to exercise live updates.
                if rng.random_ratio(1, 200) {
                    spawn_streaming(&cap, &mut rng);
                }
                drop(core);
                std::thread::sleep(Duration::from_millis(10));
            }
            if let Some(core) = weak.upgrade() {
                let mut m = core.mock.lock();
                if m.as_ref().is_some_and(|h| Arc::ptr_eq(&h.stop, &stop_flag)) {
                    *m = None;
                }
            }
        })
        .expect("spawn mock");
}

fn spawn_streaming(cap: &Arc<piper_store::Capture>, rng: &mut impl Rng) {
    let (mut d, _, _) = random_session(rng);
    d.request.url = format!("https://downloads.example.com/stream/{}.ndjson", rng.random_range(1..100));
    d.request.method = "GET".into();
    if let Some(r) = d.response.as_mut() {
        r.status = 200;
        r.headers = Headers::new();
        r.headers.push("Content-Type", "application/x-ndjson");
        r.headers.push("Transfer-Encoding", "chunked");
    }
    d.summary.state = SessionState::ReceivingResponse;
    let resp_head = d.response.clone();
    let live = cap.begin(SessionKind::Http, |x| {
        x.request = d.request.clone();
        x.process = d.process.clone();
        x.timers.client_begin_request = Some(now_us());
    });
    live.update(|x| {
        x.response = resp_head;
        x.summary.state = SessionState::ReceivingResponse;
        x.summary.flags |= flags::STREAMED;
    });
    let mut w = cap.bodies.writer();
    live.set_response_body(w.body().clone());
    let secs = rng.random_range(3..15);
    std::thread::spawn(move || {
        let end = Instant::now() + Duration::from_secs(secs);
        let mut i = 0u64;
        while Instant::now() < end {
            let line = format!("{{\"seq\":{i},\"ts\":{},\"payload\":\"{}\"}}\n", now_us(), "x".repeat(200));
            let _ = w.write(line.repeat(50).as_bytes());
            i += 1;
            std::thread::sleep(Duration::from_millis(50));
        }
        let b = w.finish();
        live.set_response_body(b);
        live.update(|x| {
            x.summary.state = SessionState::Done;
            x.timers.client_done_response = Some(now_us());
        });
        live.finish();
    });
}

pub fn stop(core: &AppCore) {
    if let Some(h) = core.mock.lock().take() {
        h.stop.store(true, Ordering::Relaxed);
    }
}

/// Generate sessions with very large bodies (runs as background jobs).
/// `scale` 1 = development sizes, 10 = PLAN.md test sizes (10 GB+).
pub fn big_bodies(core: &Arc<AppCore>, scale: u64) {
    let scale = scale.max(1);
    let specs: Vec<(&str, &str, Option<&str>, u64)> = vec![
        ("/export/orders.ndjson", "application/x-ndjson", None, 200 << 20),
        ("/export/big-single-line.json", "application/json", None, 50 << 20),
        ("/export/archive.ndjson.gz", "application/x-ndjson", Some("gzip"), 100 << 20),
        ("/download/disk-image.bin", "application/octet-stream", None, 1 << 30),
    ];
    for (path, ct, ce, size) in specs {
        let size = size * scale;
        let core2 = Arc::downgrade(core);
        let title = format!("Generating mock body {path} ({})", crate::bodies::human(size));
        core.jobs.submit(format!("mockbig:{path}:{}", now_us()), title, Priority::Background, true, move |ctx| {
            let Some(core) = core2.upgrade() else { return Ok(()) };
            let cap = core.capture();
            let mut rh = Headers::new();
            rh.push("Host", "bulk.example.com");
            let mut sh = Headers::new();
            sh.push("Content-Type", ct);
            if let Some(ce) = ce {
                sh.push("Content-Encoding", ce);
            }
            sh.push("Content-Length", size.to_string());
            let d = SessionDetail {
                request: RequestHead { method: "GET".into(), url: format!("https://bulk.example.com{path}"), version: HttpVersion::Http11, headers: rh },
                response: Some(ResponseHead { status: 200, reason: "OK".into(), version: HttpVersion::Http11, headers: sh }),
                summary: SessionSummary { state: SessionState::Done, process: "mock:1".into(), ..Default::default() },
                timers: Timers { client_begin_request: Some(now_us() - 5_000_000), client_done_response: Some(now_us()), ..Default::default() },
                ..Default::default()
            };
            let body = if ct == "application/octet-stream" {
                cap.bodies.sparse(size, b"PIPERBIN\x00\x01\x02\x03 sparse mock body").map_err(|e| e.to_string())?
            } else {
                let mut w = cap.bodies.writer_with_limit(u64::MAX);
                let single = path.contains("single-line");
                let mut sink: Box<dyn Write> = match ce {
                    Some(_) => Box::new(flate2::write::GzEncoder::new(Vec::with_capacity(1 << 20), flate2::Compression::fast())),
                    None => Box::new(Vec::with_capacity(1 << 20)),
                };
                let _ = &mut sink;
                let mut written = 0u64;
                let mut i = 0u64;
                let mut chunk = String::with_capacity(1 << 20);
                if single {
                    chunk.push('[');
                }
                let mut gz = ce.map(|_| flate2::write::GzEncoder::new(Vec::with_capacity(1 << 20), flate2::Compression::fast()));
                while written < size {
                    if ctx.cancelled() {
                        return Err("cancelled".into());
                    }
                    chunk.clear();
                    while chunk.len() < (1 << 20) {
                        if single {
                            chunk.push_str(&format!(r#"{{"id":{i},"name":"Order {i}","amount":{},"items":[1,2,3]}},"#, i * 7 % 1000));
                        } else {
                            chunk.push_str(&format!("{{\"id\":{i},\"customer\":\"Kunde {i}\",\"amount\":{}.{:02},\"status\":\"shipped\"}}\n", i * 13 % 10_000, i % 100));
                        }
                        i += 1;
                    }
                    match gz.as_mut() {
                        Some(g) => {
                            g.write_all(chunk.as_bytes()).map_err(|e| e.to_string())?;
                            let out = std::mem::take(g.get_mut());
                            w.write(&out).map_err(|e| e.to_string())?;
                        }
                        None => w.write(chunk.as_bytes()).map_err(|e| e.to_string())?,
                    }
                    written += chunk.len() as u64;
                    ctx.progress(written, size);
                }
                if single {
                    w.write(b"{}]").map_err(|e| e.to_string())?;
                }
                if let Some(g) = gz {
                    let out = g.finish().map_err(|e| e.to_string())?;
                    w.write(&out).map_err(|e| e.to_string())?;
                }
                w.finish()
            };
            let empty = cap.bodies.store_bytes(&[]);
            cap.insert(d, empty, body);
            Ok(())
        });
    }
}
