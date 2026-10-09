//! A plain GET from Quena itself (e.g. a price list the user asked to update). It goes through
//! the same connector as proxied traffic, so upstream proxy, host remapping, the trusted
//! roots (also an imported company CA) and the loop guard apply.

use crate::Shared;
use crate::connector::Connector;
use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::sync::Arc;
use std::time::Duration;

/// GET `url` (HTTP/1.1) and return the body, at most `max` bytes, within `timeout`.
pub async fn get(shared: &Arc<Shared>, url: &str, max: usize, timeout: Duration) -> Result<Vec<u8>, String> {
    let client: Client<Connector, crate::ProxyBody> =
        Client::builder(TokioExecutor::new()).build(Connector { cfg: shared.cfg(), tls: shared.tls_clients.clone(), force_h2: Some(false) });
    let req = http::Request::get(url)
        .header("user-agent", concat!("quena/", env!("CARGO_PKG_VERSION")))
        .header("accept", "application/json")
        .body(crate::body::empty())
        .map_err(|e| e.to_string())?;
    let fetch = async {
        let resp = client.request(req).await.map_err(|e| {
            let mut msg = e.to_string();
            let mut src = std::error::Error::source(&e);
            while let Some(s) = src {
                msg.push_str(&format!(": {s}"));
                src = s.source();
            }
            msg
        })?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }
        let mut body = resp.into_body();
        let mut out = Vec::new();
        while let Some(frame) = body.frame().await {
            if let Ok(data) = frame.map_err(|e| e.to_string())?.into_data() {
                out.extend_from_slice(&data);
                if out.len() > max {
                    return Err(format!("the answer is larger than {} MB", max >> 20));
                }
            }
        }
        Ok(out)
    };
    tokio::time::timeout(timeout, fetch).await.map_err(|_| format!("no complete answer within {} s", timeout.as_secs()))?
}
