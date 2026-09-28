//! Raw tunnels (undecrypted CONNECT) and WebSocket pass-through.

use crate::Shared;
use crate::body::{ProxyBody, empty};
use crate::connector::{connect_via_proxy, tcp_connect};
use http::Response;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use piper_model::*;
use piper_store::LiveSession;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

fn byte_body(shared: &Shared, n: u64) -> piper_body::Body {
    let mut w = shared.capture().bodies.writer_with_limit(0);
    w.add_dropped(n);
    w.finish()
}

pub async fn raw<S>(shared: &Arc<Shared>, live: &Arc<LiveSession>, mut client: S, host: &str, port: u16)
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let cfg = shared.cfg();
    let upstream = cfg.upstream_for(&format!("{host}:{port}"));
    let connected = match &upstream {
        Some((ph, pp)) => match tcp_connect(ph, *pp).await {
            Ok((mut s, ..)) => connect_via_proxy(&mut s, host, port).await.map(|_| s),
            Err(e) => Err(e),
        },
        None => tcp_connect(host, port).await.map(|(s, ..)| s),
    };
    let mut server = match connected {
        Ok(s) => s,
        Err(e) => {
            live.update(|d| {
                d.summary.state = SessionState::Aborted;
                d.error = Some(format!("tunnel to {host}:{port} failed: {e}"));
            });
            live.finish();
            return;
        }
    };
    if let Ok(a) = server.peer_addr() {
        live.update(|d| d.connection.server_addr = Some(a.to_string()));
    }
    let r = tokio::io::copy_bidirectional(&mut client, &mut server).await;
    let (up, down) = r.unwrap_or((0, 0));
    live.set_request_body(byte_body(shared, up));
    live.update(|d| {
        d.summary.state = SessionState::Done;
        d.timers.client_done_response = Some(now_us());
        d.extra_flags.push(("x-tunnel-bytes".into(), format!("{up} up / {down} down")));
        d.summary.custom = format!("↑{up} ↓{down}");
    });
    live.finish();
}

pub fn websocket(shared: &Arc<Shared>, live: &Arc<LiveSession>, mut resp: Response<Incoming>, client: hyper::upgrade::OnUpgrade) -> Response<ProxyBody> {
    let server = hyper::upgrade::on(&mut resp);
    live.update(|d| {
        d.summary.kind = SessionKind::WebSocket;
        d.summary.state = SessionState::ReceivingResponse;
    });
    let (parts, _) = resp.into_parts();
    let shared = shared.clone();
    let live = live.clone();
    tokio::spawn(async move {
        let (c, s) = tokio::join!(client, server);
        match (c, s) {
            (Ok(c), Ok(s)) => {
                let mut c = TokioIo::new(c);
                let mut s = TokioIo::new(s);
                let (up, down) = tokio::io::copy_bidirectional(&mut c, &mut s).await.unwrap_or((0, 0));
                live.set_request_body(byte_body(&shared, up));
                live.set_response_body(byte_body(&shared, down));
                live.update(|d| {
                    d.summary.state = SessionState::Done;
                    d.timers.client_done_response = Some(now_us());
                    d.summary.custom = format!("WS ↑{up} ↓{down}");
                });
            }
            (c, s) => {
                live.update(|d| {
                    d.summary.state = SessionState::Aborted;
                    d.error = Some(format!("websocket upgrade failed: client {:?} server {:?}", c.err(), s.err()));
                });
            }
        }
        live.finish();
    });
    let mut out = Response::from_parts(parts, empty());
    out.headers_mut().remove(http::header::CONTENT_LENGTH);
    out
}
