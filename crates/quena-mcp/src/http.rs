//! HTTP side of the Streamable HTTP transport: `POST /mcp` only, localhost only, bearer token.

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode, header};
use quena_app_core::AppCore;
use std::convert::Infallible;
use std::sync::{Arc, Weak};

/// Largest JSON-RPC message accepted (rule sets, request bodies to send).
const MAX_MESSAGE: usize = 8 << 20;

pub(crate) async fn serve(listener: std::net::TcpListener, core: Weak<AppCore>, mut stop: tokio::sync::oneshot::Receiver<()>) {
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    let listener = match tokio::net::TcpListener::from_std(listener) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(target: "quena", "MCP listener: {e}");
            return;
        }
    };
    loop {
        let (stream, _) = tokio::select! {
            _ = &mut stop => return,
            r = listener.accept() => match r {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(target: "quena", "MCP accept: {e}");
                    continue;
                }
            },
        };
        let core = core.clone();
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req| handle(req, core.clone(), port));
            let io = hyper_util::rt::TokioIo::new(stream);
            if let Err(e) = hyper::server::conn::http1::Builder::new().serve_connection(io, svc).await {
                tracing::debug!(target: "quena", "MCP connection: {e}");
            }
        });
    }
}

fn reply(status: StatusCode, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(body.into()));
    *r.status_mut() = status;
    r
}

fn json_reply(v: &serde_json::Value) -> Response<Full<Bytes>> {
    let mut r = reply(StatusCode::OK, serde_json::to_vec(v).unwrap_or_default());
    r.headers_mut().insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json"));
    r
}

/// `localhost`, `127.0.0.1` or `[::1]`, with this port or none: anything else is a request a
/// web page made through DNS rebinding.
pub(crate) fn host_allowed(host: &str, port: u16) -> bool {
    let (name, p) = match host.rsplit_once(':') {
        Some((n, p)) if !n.ends_with(':') && !host.ends_with(']') => (n, Some(p)),
        _ => (host, None),
    };
    let local = matches!(name.to_ascii_lowercase().as_str(), "localhost" | "127.0.0.1" | "[::1]");
    local && p.is_none_or(|p| p == port.to_string())
}

/// Browsers send `Origin`; only pages on this machine's loopback names may call.
pub(crate) fn origin_allowed(origin: &str) -> bool {
    let Some(rest) = origin.strip_prefix("http://").or_else(|| origin.strip_prefix("https://")) else { return false };
    let host = rest.split('/').next().unwrap_or("");
    let name = match host.rsplit_once(':') {
        Some((n, _)) if !host.ends_with(']') => n,
        _ => host,
    };
    matches!(name.to_ascii_lowercase().as_str(), "localhost" | "127.0.0.1" | "[::1]")
}

/// Compare without an early exit, so the time taken says nothing about the token.
pub(crate) fn token_matches(given: &str, want: &str) -> bool {
    let (a, b) = (given.as_bytes(), want.as_bytes());
    if a.len() != b.len() || b.is_empty() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn handle(req: Request<Incoming>, core: Weak<AppCore>, port: u16) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.uri().path() != "/mcp" {
        return Ok(reply(StatusCode::NOT_FOUND, "not found"));
    }
    let h = req.headers();
    let host = h.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !host_allowed(host, port) {
        return Ok(reply(StatusCode::FORBIDDEN, "host not allowed"));
    }
    if let Some(o) = h.get(header::ORIGIN)
        && !o.to_str().is_ok_and(origin_allowed)
    {
        return Ok(reply(StatusCode::FORBIDDEN, "origin not allowed"));
    }
    let Some(core) = core.upgrade() else { return Ok(reply(StatusCode::SERVICE_UNAVAILABLE, "shutting down")) };
    let token = core.settings().mcp.token;
    let given = h.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or("");
    if !token_matches(given.trim(), token.trim()) {
        let mut r = reply(StatusCode::UNAUTHORIZED, "missing or wrong bearer token");
        r.headers_mut().insert(header::WWW_AUTHENTICATE, header::HeaderValue::from_static("Bearer"));
        return Ok(r);
    }
    if req.method() != Method::POST {
        // No server-sent event stream and no session to delete.
        let mut r = reply(StatusCode::METHOD_NOT_ALLOWED, "");
        r.headers_mut().insert(header::ALLOW, header::HeaderValue::from_static("POST"));
        return Ok(r);
    }
    let body = match Limited::new(req.into_body(), MAX_MESSAGE).collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return Ok(reply(StatusCode::PAYLOAD_TOO_LARGE, "message too large")),
    };
    let msg: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return Ok(json_reply(&crate::rpc::error_response(serde_json::Value::Null, -32700, &format!("parse error: {e}")))),
    };
    // Tools call the blocking core API (and may wait for jobs or requests).
    let out = tokio::task::spawn_blocking(move || handle_batch(&core, msg)).await.unwrap_or(None);
    Ok(match out {
        Some(v) => json_reply(&v),
        None => reply(StatusCode::ACCEPTED, ""),
    })
}

fn handle_batch(core: &Arc<AppCore>, msg: serde_json::Value) -> Option<serde_json::Value> {
    match msg {
        serde_json::Value::Array(items) => {
            let out: Vec<serde_json::Value> = items.into_iter().filter_map(|m| crate::rpc::handle_message(core, m)).collect();
            (!out.is_empty()).then_some(serde_json::Value::Array(out))
        }
        m => crate::rpc::handle_message(core, m),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_and_origins() {
        assert!(host_allowed("127.0.0.1:8867", 8867));
        assert!(host_allowed("localhost:8867", 8867));
        assert!(host_allowed("localhost", 8867));
        assert!(host_allowed("[::1]:8867", 8867));
        assert!(host_allowed("[::1]", 8867));
        assert!(!host_allowed("localhost:9999", 8867));
        assert!(!host_allowed("evil.example:8867", 8867));
        assert!(!host_allowed("127.0.0.1.evil.example", 8867));
        assert!(!host_allowed("", 8867));
        assert!(origin_allowed("http://localhost:5173"));
        assert!(origin_allowed("http://127.0.0.1"));
        assert!(!origin_allowed("https://evil.example"));
        assert!(!origin_allowed("http://localhost.evil.example"));
        assert!(!origin_allowed("null"));
    }

    #[test]
    fn tokens() {
        assert!(token_matches("abc", "abc"));
        assert!(!token_matches("abd", "abc"));
        assert!(!token_matches("ab", "abc"));
        assert!(!token_matches("", ""));
    }
}
