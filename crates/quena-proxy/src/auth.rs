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
use quena_auth::{Credentials, Handshake, Scheme};
use quena_body::Body as StoredBody;
use quena_model::RequestHead;
use std::sync::Arc;
use std::time::Duration;

/// Longest wait for one step of the security library (Kerberos via GSSAPI, SSPI). Without a
/// reachable KDC — a VPN with a ticket but no route, or DNS that never answers the KDC
/// lookup — a step can block for a minute or more; the request must not.
const HANDSHAKE_STEP_TIMEOUT: Duration = Duration::from_secs(5);
/// A scheme that timed out for a host is not tried there again for this long.
const UNAVAILABLE_FOR: Duration = Duration::from_secs(600);

/// (scheme, host) → until when the scheme is skipped for the host.
static UNAVAILABLE: std::sync::OnceLock<parking_lot::Mutex<std::collections::HashMap<(Scheme, String), std::time::Instant>>> = std::sync::OnceLock::new();

fn unavailable() -> &'static parking_lot::Mutex<std::collections::HashMap<(Scheme, String), std::time::Instant>> {
    UNAVAILABLE.get_or_init(Default::default)
}

/// Kerberos needs a host name: for IP literals and `localhost` there is no service principal,
/// and asking the KDC only costs time (Windows and browsers use NTLM there as well).
fn negotiate_possible(host: &str) -> bool {
    let h = host.trim_matches(['[', ']']);
    !(h.eq_ignore_ascii_case("localhost") || h.parse::<std::net::IpAddr>().is_ok())
}

fn skipped(scheme: Scheme, host: &str) -> bool {
    let mut m = unavailable().lock();
    let key = (scheme, host.to_ascii_lowercase());
    match m.get(&key) {
        Some(until) if *until > std::time::Instant::now() => true,
        Some(_) => {
            m.remove(&key);
            false
        }
        None => false,
    }
}

/// One step of a handshake on a blocking thread, bounded by [`HANDSHAKE_STEP_TIMEOUT`]. A step
/// that times out keeps running on its thread (the libraries cannot be interrupted) and the
/// scheme is skipped for the host for [`UNAVAILABLE_FOR`].
async fn bounded_step<T: Send + 'static>(scheme: Scheme, host: &str, f: impl FnOnce() -> Result<T, quena_auth::AuthError> + Send + 'static) -> Result<T, String> {
    match tokio::time::timeout(HANDSHAKE_STEP_TIMEOUT, tokio::task::spawn_blocking(f)).await {
        Ok(Ok(r)) => r.map_err(|e| e.to_string()),
        Ok(Err(e)) => Err(format!("handshake step failed: {e}")),
        Err(_) => {
            unavailable().lock().insert((scheme, host.to_ascii_lowercase()), std::time::Instant::now() + UNAVAILABLE_FOR);
            tracing::warn!(target: "quena::auth", "{} for {host} did not answer within {} s (no reachable KDC or domain controller?); skipped for this host for {} min", scheme.header_name(), HANDSHAKE_STEP_TIMEOUT.as_secs(), UNAVAILABLE_FOR.as_secs() / 60);
            Err(format!("no answer within {} s", HANDSHAKE_STEP_TIMEOUT.as_secs()))
        }
    }
}

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
        // Real servers send sloppy heads; accept what browsers accept instead of a 502.
        .http1_allow_spaces_after_header_name_in_responses(true)
        .http1_allow_obsolete_multiline_headers_in_responses(true)
        .http1_ignore_invalid_headers_in_responses(true)
        .http1_max_headers(1000)
        // Reap idle pooled connections in the background, not only on checkout.
        .pool_timer(hyper_util::rt::TokioTimer::new())
        .http1_preserve_header_case(true)
        .http2_only(false)
        .set_host(true)
        .build(Connector { cfg, tls: ctx.shared.tls_clients.clone(), force_h2: None });
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

/// Read and discard a 401/407 body so the connection can be reused for the next leg.
/// Bounded: a huge or endless challenge body is abandoned (the connection is then dropped).
async fn drain(resp: Response<Incoming>) {
    let mut b = resp.into_body();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut total = 0usize;
        while let Some(f) = b.frame().await {
            match f {
                Ok(f) => {
                    total += f.data_ref().map_or(0, |d| d.len());
                    if total > 1 << 20 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    })
    .await;
}

/// `client.request` with the same response-head bound as ordinary requests.
async fn request_bounded<C>(client: &hyper_util::client::legacy::Client<C, crate::body::ProxyBody>, req: http::Request<crate::body::ProxyBody>) -> Result<Response<Incoming>, String>
where
    C: hyper_util::client::legacy::connect::Connect + Clone + Send + Sync + 'static,
{
    match tokio::time::timeout(crate::forward::RESPONSE_HEAD_TIMEOUT, client.request(req)).await {
        Ok(r) => r.map_err(err_chain),
        Err(_) => Err(format!("no response from the server within {} s", crate::forward::RESPONSE_HEAD_TIMEOUT.as_secs())),
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
    let resp = request_bounded(&client, req).await?;
    let is_proxy_challenge = resp.status() == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
    let is_server_challenge = resp.status() == http::StatusCode::UNAUTHORIZED;
    let applies = (is_server_challenge && cfg.auth_applies(&host)) || (is_proxy_challenge && cfg.auto_auth && cfg.auto_auth_upstream);
    if !applies {
        return Ok(resp);
    }

    let offers = quena_auth::parse_challenges(&challenge_values(&resp, is_proxy_challenge));
    let resolver = shared.creds();
    let realm = offers.iter().find_map(|o| o.params.iter().find(|(k, _)| k.eq_ignore_ascii_case("realm")).map(|(_, v)| v.clone())).unwrap_or_default();
    let creds = resolver.credentials(&host, &realm);
    let auth_header = if is_proxy_challenge { "Proxy-Authorization" } else { "Authorization" };

    // Candidate schemes in preference order; try each until one produces a first
    // header (e.g. skip Negotiate when there is no Kerberos ticket → fall back to NTLM).
    let mut candidates: Vec<&quena_auth::Offer> = offers
        .iter()
        .filter(|o| match o.scheme {
            Scheme::Basic | Scheme::Ntlm => creds.is_some(),
            Scheme::Negotiate => (cfg!(target_os = "macos") || cfg!(target_os = "linux") || cfg!(windows)) && negotiate_possible(&host),
        })
        .filter(|o| !skipped(o.scheme, &host))
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
        // Kerberos/SSPI may contact a domain controller: on a blocking thread, bounded.
        let (scheme, c, h, token) = (cand.scheme, creds.clone(), host.clone(), cand.token.clone());
        let started = bounded_step(scheme, &host, move || {
            let mut hs = Handshake::start(scheme, c.as_ref(), &h)?;
            let first = hs.next_header(token.as_deref())?;
            Ok((hs, first))
        })
        .await;
        let (mut hs, first_header) = match started {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(target: "quena::auth", "{} unavailable for {host}: {e}", cand.scheme.header_name());
                continue;
            }
        };
        let mut challenge_token = cand.token.clone();
        let mut pending_header = Some(first_header);
        let mut rejected = false;
        for leg in 0..6u8 {
            let header_value = match pending_header.take() {
                Some(v) => v,
                None => {
                    let (mut moved, token) = (hs, challenge_token.clone());
                    let scheme = moved.scheme();
                    match bounded_step(scheme, &host, move || moved.next_header(token.as_deref()).map(|v| (moved, v))).await {
                        Ok((back, v)) => {
                            hs = back;
                            v
                        }
                        Err(e) => {
                            tracing::debug!(target: "quena::auth", "{} continuation failed for {host}: {e}", scheme.header_name());
                            rejected = true;
                            break;
                        }
                    }
                }
            };
            on_leg((leg as u16) + 2);
            let final_leg = !hs.is_multi_leg() || !expects_more_legs(&hs, leg);
            // Send body only on the final leg; negotiate legs carry an empty body.
            let leg_body = if final_leg { stream(&body) } else { empty() };
            let req = build_req(head, Some((auth_header, header_value)), leg_body, !final_leg)?;
            let resp = request_bounded(&client, req).await?;
            tracing::debug!(target: "quena::auth", "{} leg {} to {host}: {} (body sent: {})", hs.scheme().header_name(), leg + 1, resp.status(), final_leg);
            let again_proxy = resp.status() == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
            let again_server = resp.status() == http::StatusCode::UNAUTHORIZED;
            if (again_proxy && is_proxy_challenge) || (again_server && is_server_challenge) {
                // Need another leg: pick the continuation token for this scheme.
                let vals = challenge_values(&resp, is_proxy_challenge);
                challenge_token = quena_auth::parse_challenges(&vals).into_iter().find(|o| o.scheme == hs.scheme()).and_then(|o| o.token);
                drain(resp).await;
                if challenge_token.is_none() && final_leg {
                    tracing::debug!(target: "quena::auth", "{} rejected by {host}", hs.scheme().header_name());
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
    request_bounded(&client, req).await
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

#[cfg(test)]
mod step_tests {
    use super::*;

    #[test]
    fn negotiate_needs_a_host_name() {
        assert!(negotiate_possible("intranet.corp.example"));
        assert!(!negotiate_possible("127.0.0.1"));
        assert!(!negotiate_possible("[::1]"));
        assert!(!negotiate_possible("LocalHost"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_hanging_step_is_cut_off_and_remembered() {
        let host = "hangs.test.invalid";
        let r: Result<(), String> = bounded_step(Scheme::Negotiate, host, || {
            std::thread::sleep(HANDSHAKE_STEP_TIMEOUT + Duration::from_secs(1));
            Ok(())
        })
        .await;
        assert!(r.unwrap_err().contains("no answer"));
        assert!(skipped(Scheme::Negotiate, "HANGS.test.invalid"));
        assert!(!skipped(Scheme::Ntlm, host));
        // Quick steps pass through, errors keep their text.
        assert_eq!(bounded_step(Scheme::Ntlm, "x", || Ok(7)).await, Ok(7));
        let e: Result<(), String> = bounded_step(Scheme::Ntlm, "x", || Err(quena_auth::AuthError::NoCredentials)).await;
        assert!(e.is_err() && !skipped(Scheme::Ntlm, "x"));
    }
}
