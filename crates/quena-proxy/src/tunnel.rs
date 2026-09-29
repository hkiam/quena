//! Raw tunnels (undecrypted CONNECT) and WebSocket pass-through.

use crate::Shared;
use crate::body::{ProxyBody, empty};
use crate::connector::{connect_via_proxy, tcp_connect};
use http::Response;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use quena_model::*;
use quena_store::LiveSession;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

fn byte_body(shared: &Shared, n: u64) -> quena_body::Body {
    let mut w = shared.capture().bodies.writer_with_limit(0);
    w.add_dropped(n);
    w.finish()
}

pub async fn raw<S>(shared: &Arc<Shared>, live: &Arc<LiveSession>, mut client: S, host: &str, port: u16)
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let cfg = shared.cfg();
    let upstream = crate::resolve_upstream(&cfg, format!("{host}:{port}")).await;
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
                use tokio::io::split;
                let (cr, cw) = split(TokioIo::new(c));
                let (sr, sw) = split(TokioIo::new(s));
                // Frame log: both pumps send records to one writer task (sequential store writes).
                let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
                let store = shared.capture();
                let live_log = live.clone();
                let log_task = tokio::spawn(async move {
                    let mut w = store.bodies.writer_with_limit(u64::MAX);
                    live_log.set_response_body(w.body().clone());
                    let mut frames = 0u64;
                    while let Some(rec) = rx.recv().await {
                        let _ = tokio::task::block_in_place(|| w.write(&rec));
                        frames += 1;
                        if frames % 32 == 0 {
                            live_log.set_response_body(w.body().clone());
                        }
                    }
                    let b = w.finish();
                    live_log.set_response_body(b);
                    frames
                });
                let up = crate::wsframe::pump(cr, sw, crate::wsframe::DIR_CLIENT, &tx);
                let down = crate::wsframe::pump(sr, cw, crate::wsframe::DIR_SERVER, &tx);
                let (up, down) = tokio::join!(up, down);
                drop(tx);
                let frames = log_task.await.unwrap_or(0);
                live.update(move |d| {
                    d.summary.state = SessionState::Done;
                    d.timers.client_done_response = Some(now_us());
                    d.summary.flags |= flags::STREAMED;
                    d.summary.custom = format!("WS {frames} frames ↑{up} ↓{down}");
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
