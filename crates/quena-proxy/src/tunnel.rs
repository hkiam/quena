//! Raw tunnels (undecrypted CONNECT) and WebSocket pass-through.

use crate::Shared;
use crate::body::{ProxyBody, empty};
use crate::connector::{connect_via_proxy, tcp_connect};
use http::Response;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use quena_model::*;
use quena_store::LiveSession;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A tunnel or WebSocket with no traffic in either direction for this long is closed
/// (half-open peers: sleeping laptops, dropped networks).
const IDLE_TIMEOUT: Duration = Duration::from_secs(3600);
/// After one WebSocket direction ended, how long the other may continue.
const HALF_CLOSE_GRACE: Duration = Duration::from_secs(30);
/// Frame records waiting for the store; beyond this, frames are forwarded but not logged.
const WS_LOG_BUDGET: usize = 64 << 20;

/// Records the time of the last read/write on the wrapped stream.
struct Activity<S> {
    inner: S,
    last: Arc<AtomicI64>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Activity<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            self.last.store(now_us(), Ordering::Relaxed);
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Activity<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(_)) = &r {
            self.last.store(now_us(), Ordering::Relaxed);
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Resolves once `last` is older than `idle`.
async fn idle_watch(last: Arc<AtomicI64>, idle: Duration) {
    loop {
        let since = Duration::from_micros((now_us() - last.load(Ordering::Relaxed)).max(0) as u64);
        if since >= idle {
            return;
        }
        tokio::time::sleep(idle - since + Duration::from_millis(10)).await;
    }
}

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
    let last = Arc::new(AtomicI64::new(now_us()));
    let mut client = Activity { inner: &mut client, last: last.clone() };
    let mut server = Activity { inner: &mut server, last: last.clone() };
    let mut idle = false;
    let mut closing = shared.closing.subscribe();
    let r = tokio::select! {
        _ = closing.changed() => Ok((0, 0)),
        r = tokio::io::copy_bidirectional(&mut client, &mut server) => r,
        _ = idle_watch(last.clone(), IDLE_TIMEOUT) => {
            idle = true;
            Ok((0, 0))
        }
    };
    let (up, down) = r.unwrap_or((0, 0));
    live.set_request_body(byte_body(shared, up));
    live.update(|d| {
        if idle {
            d.error = Some(format!("closed after {} minutes without traffic", IDLE_TIMEOUT.as_secs() / 60));
        }
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
    let mut closing = shared.closing.subscribe();
    tokio::spawn(async move {
        let (c, s) = tokio::join!(client, server);
        match (c, s) {
            (Ok(c), Ok(s)) => {
                use tokio::io::split;
                let (cr, cw) = split(TokioIo::new(c));
                let (sr, sw) = split(TokioIo::new(s));
                // Frame log: both pumps send records to one writer task (sequential store writes).
                let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
                let queued = Arc::new(AtomicUsize::new(0));
                let store = shared.capture();
                let live_log = live.clone();
                let q2 = queued.clone();
                let log_task = tokio::spawn(async move {
                    let mut w = store.bodies.writer();
                    live_log.set_response_body(w.body().clone());
                    let mut frames = 0u64;
                    while let Some(rec) = rx.recv().await {
                        q2.fetch_sub(rec.len(), Ordering::Relaxed);
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
                let last = Arc::new(AtomicI64::new(now_us()));
                // The pump futures borrow the log; scope them so they are gone before `tx` drops.
                let (up, down, note) = {
                    let log = crate::wsframe::FrameLog { tx: &tx, queued: &queued, budget: WS_LOG_BUDGET, last: &last };
                    let up = crate::wsframe::pump(cr, sw, crate::wsframe::DIR_CLIENT, &log);
                    let down = crate::wsframe::pump(sr, cw, crate::wsframe::DIR_SERVER, &log);
                    tokio::pin!(up, down);
                    // When one direction ends, the other gets a short grace period; no traffic at
                    // all for IDLE_TIMEOUT ends both.
                    tokio::select! {
                        u = &mut up => {
                            let d = tokio::time::timeout(HALF_CLOSE_GRACE, &mut down).await;
                            (u, d.unwrap_or((0, Some("the server did not close its side".into()))), None)
                        }
                        d = &mut down => {
                            let u = tokio::time::timeout(HALF_CLOSE_GRACE, &mut up).await;
                            (u.unwrap_or((0, Some("the client did not close its side".into()))), d, None)
                        }
                        _ = idle_watch(last.clone(), IDLE_TIMEOUT) => ((0, None), (0, None), Some(format!("closed after {} minutes without frames", IDLE_TIMEOUT.as_secs() / 60))),
                    _ = closing.changed() => ((0, None), (0, None), Some("closed because the capture was stopped".into())),
                    }
                };
                drop(tx);
                let frames = log_task.await.unwrap_or(0);
                let (up, up_err) = up;
                let (down, down_err) = down;
                let error = note.or(up_err.map(|e| format!("client → server: {e}"))).or(down_err.map(|e| format!("server → client: {e}")));
                live.update(move |d| {
                    if error.is_some() {
                        d.error = error;
                    }
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
