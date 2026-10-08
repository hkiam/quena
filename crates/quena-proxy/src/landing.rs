//! Built-in pages served by the proxy itself: `http://quena.cert/` and
//! `http://<ip>:<port>/` (certificate download for devices).

use crate::Shared;
use crate::body::{ProxyBody, full};
use http::{HeaderValue, Request, Response, StatusCode};

fn resp(
    status: StatusCode,
    ct: &'static str,
    body: impl Into<bytes::Bytes>,
) -> Response<ProxyBody> {
    let mut r = Response::new(full(body.into()));
    *r.status_mut() = status;
    r.headers_mut()
        .insert(http::header::CONTENT_TYPE, HeaderValue::from_static(ct));
    r.headers_mut().insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    r
}

pub fn serve<B>(shared: &Shared, req: &Request<B>) -> Response<ProxyBody> {
    let ca = shared.ca.read().clone();
    let path = req.uri().path();
    match (path, &ca) {
        ("/quena-root-ca.crt" | "/quena-root-ca.pem", Some(ca)) => {
            let mut r = resp(
                StatusCode::OK,
                "application/x-x509-ca-cert",
                ca.cert_pem().to_string(),
            );
            r.headers_mut().insert(
                http::header::CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment; filename=\"quena-root-ca.crt\""),
            );
            r
        }
        ("/quena-root-ca.cer" | "/quena-root-ca.der", Some(ca)) => {
            let mut r = resp(
                StatusCode::OK,
                "application/pkix-cert",
                ca.cert_der().to_vec(),
            );
            r.headers_mut().insert(
                http::header::CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment; filename=\"quena-root-ca.cer\""),
            );
            r
        }
        ("/quena.mobileconfig", Some(ca)) => resp(
            StatusCode::OK,
            "application/x-apple-aspen-config",
            ca.mobileconfig(),
        ),
        ("/" | "/index.html", _) => {
            let fp = ca
                .as_ref()
                .map(|c| c.sha256_fingerprint())
                .unwrap_or_default();
            let cert = if ca.is_some() {
                format!(
                    r#"<h2>Root certificate</h2>
<p>Install the Quena root certificate on this device to inspect HTTPS traffic. Remove it when you are done.</p>
<ul>
<li><a href="/quena.mobileconfig">iOS / iPadOS / macOS profile (.mobileconfig)</a> – then <i>Settings → General → VPN &amp; Device Management</i> and <i>General → About → Certificate Trust Settings</i></li>
<li><a href="/quena-root-ca.cer">Android / Windows (DER, .cer)</a> – Android: <i>Settings → Security → Encryption &amp; credentials → Install a certificate → CA certificate</i></li>
<li><a href="/quena-root-ca.crt">PEM (.crt)</a> – Linux, Firefox, Java …</li>
</ul>
<p class="fp">SHA-256: {fp}</p>"#
                )
            } else {
                "<p>HTTPS interception is not configured yet (no root certificate).</p>".to_string()
            };
            let body = format!(
                r#"<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Quena</title>
<style>body{{font-family:-apple-system,system-ui,sans-serif;margin:2em;max-width:720px;line-height:1.5}}.fp{{font-family:monospace;font-size:12px;color:#666;word-break:break-all}}</style></head>
<body><h1>Quena Echo Service</h1><p>You are connected to Quena, an HTTP(S) debugging proxy.</p>{cert}</body></html>"#
            );
            resp(StatusCode::OK, "text/html; charset=utf-8", body)
        }
        _ => resp(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            "Not found",
        ),
    }
}
