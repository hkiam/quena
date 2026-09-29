//! Automatic authentication: connection-pinned handshake loop (401/407).
//! See docs/m8a-automatic-authentication.md.

use crate::body::{ProxyBody, StoredStream, empty};
use crate::connector::Connector;
use crate::forward::ConnCtx;
use crate::Shared;
use http::{Request, Response, Version};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use piper_auth::{Credentials, Handshake, Scheme};
use piper_body::Body as StoredBody;
use piper_model::RequestHead;
use std::sync::Arc;
use std::time::Duration;

/// Resolves credentials for a host/realm (implemented by the app).
pub trait CredentialResolver: Send + Sync {
    fn credentials(&self, host: &str, realm: &str) -> Option<Credentials>;
}

pub struct NoCredentials;
impl CredentialResolver for NoCredentials {
    fn credentials(&self, _host: &str, _realm: &str) -> Option<Credentials> {
        None
    }
}

/// A dedicated upstream client pinned to one client connection + host, so an
/// authenticated TCP connection is never shared with another client (security)
/// and the handshake legs reuse the same connection (correctness).
pub fn pinned_client(ctx: &ConnCtx, host: &str, port: u16) -> Arc<Client<Connector, ProxyBody>> {
    let key = (host.to_ascii_lowercase(), port);
    let mut map = ctx.auth_clients.lock();
    if let Some(c) = map.get(&key) {
        return c.clone();
    }
    let cfg = ctx.shared.cfg();
    let client = Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(120))
        .pool_max_idle_per_host(1)
        .http1_preserve_header_case(true)
        .http2_only(false)
        .set_host(true)
        .build(Connector { cfg, tls: ctx.shared.tls_clients.clone() });
    let client = Arc::new(client);
    map.insert(key, client.clone());
    client
}

fn build_req(head: &RequestHead, extra_auth: Option<(&str, String)>, body: ProxyBody, force_empty_len: bool) -> Result<Request<ProxyBody>, String> {
    let uri: http::Uri = head.url.parse().map_err(|e| format!("invalid URL {}: {e}", head.url))?;
    let mut req = Request::builder()
        .method(http::Method::from_bytes(head.method.as_bytes()).map_err(|e| e.to_string())?)
        .uri(uri)
        .version(Version::HTTP_11)
        .body(body)
        .map_err(|e| e.to_string())?;
    *req.headers_mut() = crate::forward::to_header_map_pub(&head.headers, true, false);
    if force_empty_len {
        req.headers_mut().remove(http::header::CONTENT_LENGTH);
        req.headers_mut().remove(http::header::TRANSFER_ENCODING);
        req.headers_mut().insert(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("0"));
    }
    if let Some((name, value)) = extra_auth {
        if let Ok(v) = http::HeaderValue::from_str(&value) {
            req.headers_mut().insert(http::HeaderName::from_bytes(name.as_bytes()).unwrap(), v);
        }
    }
    Ok(req)
}

async fn drain(resp: Response<Incoming>) {
    let mut b = resp.into_body();
    while let Some(f) = b.frame().await {
        if f.is_err() {
            break;
        }
    }
}

fn challenge_values(resp: &Response<Incoming>, proxy: bool) -> Vec<String> {
    let name = if proxy { "proxy-authenticate" } else { "www-authenticate" };
    resp.headers().get_all(name).iter().filter_map(|v| v.to_str().ok().map(|s| s.to_string())).collect()
}

/// Run the request with automatic authentication. Legs are pinned to one
/// upstream connection. Returns the final response (headers + streaming body).
///
/// `body` is buffered so it can be replayed on the final authenticated leg.
pub async fn send_with_auth(
    shared: &Arc<Shared>,
    ctx: &ConnCtx,
    head: &RequestHead,
    body: StoredBody,
    on_leg: &mut (dyn FnMut(u16) + Send),
) -> Result<Response<Incoming>, String> {
    let cfg = shared.cfg();
    let (host, port) = crate::util::split_host_port(&crate::forward::url_host_pub(&head.url), if head.url.starts_with("https") { 443 } else { 80 });
    let client = pinned_client(ctx, &host, port);
    let stream = |b: &StoredBody| StoredStream::new(b.clone()).boxed();

    // Leg 1: normal request with body.
    let req = build_req(head, None, stream(&body), false)?;
    let resp = client.request(req).await.map_err(err_chain)?;
    let is_proxy_challenge = resp.status() == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
    let is_server_challenge = resp.status() == http::StatusCode::UNAUTHORIZED;
    let applies = (is_server_challenge && cfg.auth_applies(&host)) || (is_proxy_challenge && cfg.auto_auth && cfg.auto_auth_upstream);
    if !applies {
        return Ok(resp);
    }

    let offers = piper_auth::parse_challenges(&challenge_values(&resp, is_proxy_challenge));
    let resolver = shared.creds();
    let realm = offers.iter().find_map(|o| o.params.iter().find(|(k, _)| k.eq_ignore_ascii_case("realm")).map(|(_, v)| v.clone())).unwrap_or_default();
    let creds = resolver.credentials(&host, &realm);
    let auth_header = if is_proxy_challenge { "Proxy-Authorization" } else { "Authorization" };

    // Candidate schemes in preference order; try each until one produces a first
    // header (e.g. skip Negotiate when there is no Kerberos ticket → fall back to NTLM).
    let mut candidates: Vec<&piper_auth::Offer> = offers
        .iter()
        .filter(|o| match o.scheme {
            Scheme::Basic | Scheme::Ntlm => creds.is_some(),
            Scheme::Negotiate => cfg!(target_os = "macos") || cfg!(windows),
        })
        .collect();
    candidates.sort_by_key(|o| std::cmp::Reverse(cfg.auth_prefer.iter().rev().position(|p| *p == o.scheme).map(|i| i as i32).unwrap_or(-1)));
    if candidates.is_empty() {
        return Ok(resp);
    }
    drain(resp).await; // free the connection for the next leg (connection-oriented auth)

    // Try each candidate scheme in preference order. A scheme that cannot produce a
    // first header (e.g. Negotiate without a Kerberos ticket) or that the server
    // rejects (a fresh challenge without a continuation token) falls through to the
    // next one — e.g. a server that advertises Negotiate but only really does NTLM.
    for cand in &candidates {
        let mut hs = match Handshake::start(cand.scheme, creds.as_ref(), &host) {
            Ok(h) => h,
            Err(e) => {
                tracing::debug!(target: "piper::auth", "{} start failed for {host}: {e}", cand.scheme.header_name());
                continue;
            }
        };
        let first_header = match hs.next_header(cand.token.as_deref()) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(target: "piper::auth", "{} unavailable for {host}: {e}", cand.scheme.header_name());
                continue;
            }
        };
        let mut challenge_token = cand.token.clone();
        let mut pending_header = Some(first_header);
        let mut rejected = false;
        for leg in 0..6u8 {
            let header_value = match pending_header.take() {
                Some(v) => v,
                None => match hs.next_header(challenge_token.as_deref()) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!(target: "piper::auth", "{} continuation failed for {host}: {e}", hs.scheme().header_name());
                        rejected = true;
                        break;
                    }
                },
            };
            on_leg((leg as u16) + 2);
            let final_leg = !hs.is_multi_leg() || !expects_more_legs(&hs, leg);
            // Send body only on the final leg; negotiate legs carry an empty body.
            let leg_body = if final_leg { stream(&body) } else { empty() };
            let req = build_req(head, Some((auth_header, header_value)), leg_body, !final_leg)?;
            let resp = client.request(req).await.map_err(err_chain)?;
            let again_proxy = resp.status() == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
            let again_server = resp.status() == http::StatusCode::UNAUTHORIZED;
            if (again_proxy && is_proxy_challenge) || (again_server && is_server_challenge) {
                // Need another leg: pick the continuation token for this scheme.
                let vals = challenge_values(&resp, is_proxy_challenge);
                challenge_token = piper_auth::parse_challenges(&vals).into_iter().find(|o| o.scheme == hs.scheme()).and_then(|o| o.token);
                drain(resp).await;
                if challenge_token.is_none() && final_leg {
                    tracing::debug!(target: "piper::auth", "{} rejected by {host}", hs.scheme().header_name());
                    rejected = true;
                    break;
                }
                continue;
            }
            return Ok(resp);
        }
        if !rejected {
            break; // ran out of legs; don't loop forever over schemes
        }
    }
    // Nothing worked → re-send the original request so the caller sees the 401/407.
    let req = build_req(head, None, stream(&body), false)?;
    client.request(req).await.map_err(err_chain)
}

/// Whether another leg is certain to follow the one being sent. Only then is the
/// (possibly huge) body withheld from this leg. NTLM always starts with a Type 1
/// negotiate leg — pure Rust or SSPI alike. Negotiate/Kerberos may complete in a
/// single leg, so its legs always carry the body (withholding it would lose data).
fn expects_more_legs(hs: &Handshake, leg: u8) -> bool {
    hs.scheme() == Scheme::Ntlm && leg == 0
}

fn err_chain(e: hyper_util::client::legacy::Error) -> String {
    let mut msg = e.to_string();
    let mut src = std::error::Error::source(&e);
    while let Some(s) = src {
        msg.push_str(&format!(": {s}"));
        src = s.source();
    }
    msg
}

pub fn scheme_label(s: Scheme) -> &'static str {
    s.header_name()
}
