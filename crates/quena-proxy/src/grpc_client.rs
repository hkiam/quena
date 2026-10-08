//! A single gRPC call from Quena itself (server reflection): HTTP/2 to the target, with
//! TLS and ALPN for `https://` and prior knowledge (h2c) for `http://`. It goes through the
//! same connector as proxied traffic, so upstream proxy, host remapping, client
//! certificates and the loop guard apply.

use crate::Shared;
use crate::connector::Connector;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::sync::Arc;
use std::time::Duration;

/// A gRPC call that did not succeed.
#[derive(Debug)]
pub enum GrpcError {
    /// The server answered with a gRPC status other than OK (code, message).
    Status(u32, String),
    /// Connection, HTTP or framing problem.
    Other(String),
}

impl std::fmt::Display for GrpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrpcError::Status(c, m) => write!(f, "gRPC status {c}: {m}"),
            GrpcError::Other(m) => f.write_str(m),
        }
    }
}

/// Send one request message to `url` (`scheme://host[:port]/pkg.Service/Method`) and return
/// the response messages (unframed).
pub async fn call(
    shared: &Arc<Shared>,
    url: &str,
    message: &[u8],
) -> Result<Vec<Vec<u8>>, GrpcError> {
    let other = |e: &dyn std::fmt::Display| GrpcError::Other(e.to_string());
    let client: Client<Connector, crate::ProxyBody> = Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build(Connector {
            cfg: shared.cfg(),
            tls: shared.tls_clients.clone(),
        });
    let mut framed = Vec::with_capacity(message.len() + 5);
    framed.push(0);
    framed.extend_from_slice(&(message.len() as u32).to_be_bytes());
    framed.extend_from_slice(message);
    let req = http::Request::post(url)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("user-agent", concat!("quena/", env!("CARGO_PKG_VERSION")))
        .body(crate::body::full(Bytes::from(framed)))
        .map_err(|e| other(&e))?;
    let resp = tokio::time::timeout(Duration::from_secs(20), client.request(req))
        .await
        .map_err(|_| GrpcError::Other("no answer within 20 s".into()))?
        .map_err(|e| {
            let mut msg = e.to_string();
            let mut src = std::error::Error::source(&e);
            while let Some(s) = src {
                msg.push_str(&format!(": {s}"));
                src = s.source();
            }
            GrpcError::Other(msg)
        })?;
    let status = resp.status();
    let head_status = grpc_status(resp.headers());
    let collected = tokio::time::timeout(Duration::from_secs(20), resp.into_body().collect())
        .await
        .map_err(|_| GrpcError::Other("the answer did not end within 20 s".into()))?
        .map_err(|e| other(&e))?;
    let trailers = collected.trailers().cloned();
    let body = collected.to_bytes();
    if let Some((code, msg)) = trailers.as_ref().and_then(grpc_status).or(head_status)
        && code != 0
    {
        return Err(GrpcError::Status(code, msg));
    }
    if !status.is_success() {
        return Err(GrpcError::Other(format!("HTTP {status}")));
    }
    let mut out = Vec::new();
    let mut p = 0usize;
    while p + 5 <= body.len() {
        let len = u32::from_be_bytes([body[p + 1], body[p + 2], body[p + 3], body[p + 4]]) as usize;
        if body[p] & 1 != 0 {
            return Err(GrpcError::Other("compressed answer".into()));
        }
        let end = p + 5 + len;
        if end > body.len() {
            return Err(GrpcError::Other("truncated gRPC frame".into()));
        }
        out.push(body[p + 5..end].to_vec());
        p = end;
    }
    Ok(out)
}

fn grpc_status(h: &http::HeaderMap) -> Option<(u32, String)> {
    let code = h.get("grpc-status")?.to_str().ok()?.trim().parse().ok()?;
    let msg = h
        .get("grpc-message")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    Some((code, msg))
}
