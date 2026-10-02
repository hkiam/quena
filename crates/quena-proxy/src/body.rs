//! Body plumbing: boxed bodies, the recording tee and bodies streamed from the store.

use crate::recorder::{RecKey, Recorder};
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use http_body_util::combinators::BoxBody;
use quena_body::Body as StoredBody;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::task::{Context, Poll};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type ProxyBody = BoxBody<Bytes, BoxError>;

pub fn full(b: impl Into<Bytes>) -> ProxyBody {
    http_body_util::Full::new(b.into()).map_err(|e| match e {}).boxed()
}

pub fn empty() -> ProxyBody {
    http_body_util::Empty::<Bytes>::new().map_err(|e| match e {}).boxed()
}

/// A body some of whose frames were read already (a hold-back that gave up): replays them,
/// then continues with the rest. With no frames it is the plain inner body.
pub struct Prefixed<B> {
    head: std::collections::VecDeque<Frame<Bytes>>,
    head_len: u64,
    inner: B,
}

impl<B> Prefixed<B> {
    pub fn new(inner: B) -> Self {
        Prefixed { head: Default::default(), head_len: 0, inner }
    }
    /// Put frames read from this body back in front of it.
    pub(crate) fn unread(mut self, mut frames: std::collections::VecDeque<Frame<Bytes>>) -> Self {
        frames.extend(self.head.drain(..));
        self.head_len = frames.iter().filter_map(|f| f.data_ref()).map(|d| d.len() as u64).sum();
        self.head = frames;
        self
    }
}

impl<B> Body for Prefixed<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        if let Some(f) = this.head.pop_front() {
            if let Some(d) = f.data_ref() {
                this.head_len -= d.len() as u64;
            }
            return Poll::Ready(Some(Ok(f)));
        }
        Pin::new(&mut this.inner).poll_frame(cx).map(|o| o.map(|r| r.map_err(Into::into)))
    }

    fn is_end_stream(&self) -> bool {
        self.head.is_empty() && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        let inner = self.inner.size_hint();
        let mut h = SizeHint::new();
        h.set_lower(inner.lower() + self.head_len);
        if let Some(u) = inner.upper() {
            h.set_upper(u + self.head_len);
        }
        h
    }
}

/// Timing information collected by a tee.
#[derive(Debug, Default)]
pub struct TeeTimes {
    pub first: AtomicI64,
    pub last: AtomicI64,
}

/// Forwards frames unchanged and hands a copy of every data frame to the recorder.
pub struct Tee<B> {
    inner: B,
    rec: Recorder,
    key: RecKey,
    times: Arc<TeeTimes>,
    done: bool,
}

impl<B> Tee<B> {
    pub fn new(inner: B, rec: Recorder, key: RecKey, times: Arc<TeeTimes>) -> Self {
        Tee { inner, rec, key, times, done: false }
    }
}

impl<B> Body for Tee<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(d) = frame.data_ref() {
                    if !d.is_empty() {
                        let now = quena_model::now_us();
                        let _ = this.times.first.compare_exchange(0, now, Ordering::Relaxed, Ordering::Relaxed);
                        this.times.last.store(now, Ordering::Relaxed);
                        this.rec.chunk(this.key, d.clone());
                    }
                }
                // Consumers that know the length (Content-Length) stop polling after
                // the last byte, so detect the end here instead of waiting for `None`.
                if !this.done && this.inner.is_end_stream() {
                    this.done = true;
                    this.rec.end(this.key, false);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                if !this.done {
                    this.done = true;
                    this.rec.end(this.key, true);
                }
                Poll::Ready(Some(Err(e.into())))
            }
            Poll::Ready(None) => {
                if !this.done {
                    this.done = true;
                    let now = quena_model::now_us();
                    let _ = this.times.first.compare_exchange(0, now, Ordering::Relaxed, Ordering::Relaxed);
                    this.times.last.store(now, Ordering::Relaxed);
                    this.rec.end(this.key, false);
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl<B> Drop for Tee<B> {
    fn drop(&mut self) {
        if !self.done {
            self.done = true;
            // Dropped before the end: the peer went away.
            self.rec.end(self.key, true);
        }
    }
}

/// Paces a body to a target byte rate (bandwidth simulation). Each data frame is
/// forwarded immediately; a delay is then inserted before the next poll so the
/// cumulative throughput stays under `bytes_per_sec`.
pub struct Throttle<B> {
    inner: B,
    bytes_per_sec: u64,
    start: std::time::Instant,
    sent: u64,
    delay: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<B> Throttle<B> {
    pub fn new(inner: B, bytes_per_sec: u64) -> Self {
        Throttle { inner, bytes_per_sec: bytes_per_sec.max(1), start: std::time::Instant::now(), sent: 0, delay: None }
    }
}

impl<B> Body for Throttle<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        // Honour a pending pacing delay before pulling the next frame.
        if let Some(d) = this.delay.as_mut() {
            match d.as_mut().poll(cx) {
                Poll::Ready(()) => this.delay = None,
                Poll::Pending => return Poll::Pending,
            }
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(d) = frame.data_ref() {
                    this.sent += d.len() as u64;
                    let target = this.sent as f64 / this.bytes_per_sec as f64;
                    let elapsed = this.start.elapsed().as_secs_f64();
                    if target > elapsed {
                        // Cap a single sleep so a tiny rate can't wedge the connection.
                        let wait = std::time::Duration::from_secs_f64((target - elapsed).min(30.0));
                        this.delay = Some(Box::pin(tokio::time::sleep(wait)));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.delay.is_none() && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}



/// Streams a stored body (used for buffered responses, replay and AutoResponder files).
pub struct StoredStream {
    body: StoredBody,
    pos: u64,
    end: u64,
    task: Option<tokio::task::JoinHandle<std::io::Result<Vec<u8>>>>,
}

impl StoredStream {
    pub fn new(body: StoredBody) -> Self {
        let end = body.len();
        StoredStream { body, pos: 0, end, task: None }
    }
}

impl Body for StoredStream {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        loop {
            if let Some(t) = this.task.as_mut() {
                return match Pin::new(t).poll(cx) {
                    Poll::Ready(Ok(Ok(data))) => {
                        this.task = None;
                        if data.is_empty() {
                            this.pos = this.end;
                            return Poll::Ready(None);
                        }
                        this.pos += data.len() as u64;
                        Poll::Ready(Some(Ok(Frame::data(Bytes::from(data)))))
                    }
                    Poll::Ready(Ok(Err(e))) => Poll::Ready(Some(Err(e.into()))),
                    Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e.into()))),
                    Poll::Pending => Poll::Pending,
                };
            }
            if this.pos >= this.end {
                return Poll::Ready(None);
            }
            let b = this.body.clone();
            let pos = this.pos;
            let n = ((this.end - pos) as usize).min(256 * 1024);
            this.task = Some(tokio::task::spawn_blocking(move || b.read_range(pos, n)));
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.end - self.pos)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// A multi-frame source body for exercising the throttle.
    struct Chunks(std::collections::VecDeque<Bytes>);
    impl Body for Chunks {
        type Data = Bytes;
        type Error = BoxError;
        fn poll_frame(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
            match self.0.pop_front() {
                Some(b) => Poll::Ready(Some(Ok(Frame::data(b)))),
                None => Poll::Ready(None),
            }
        }
    }

    #[tokio::test]
    async fn throttle_paces_to_target_rate() {
        // 10 KiB at 100_000 B/s should take ~0.1s of (paused, virtual) time.
        let chunks: std::collections::VecDeque<Bytes> = (0..10).map(|_| Bytes::from(vec![0u8; 1024])).collect();
        let mut body = Throttle::new(Chunks(chunks), 100_000);
        let start = std::time::Instant::now();
        let mut total = 0usize;
        loop {
            match std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
                Some(Ok(f)) => {
                    if let Some(d) = f.data_ref() {
                        total += d.len();
                    }
                }
                Some(Err(e)) => panic!("{e}"),
                None => break,
            }
        }
        let elapsed = start.elapsed();
        assert_eq!(total, 10 * 1024);
        // At 100 KB/s, 10 KiB needs ~102ms; allow generous slack around the paced value.
        assert!(elapsed >= std::time::Duration::from_millis(80), "throttle did not pace: {elapsed:?}");
    }

    #[tokio::test]
    async fn zero_rate_disabled_via_new_guard() {
        // Throttle::new clamps to >=1 B/s; a huge rate imposes no meaningful delay.
        let chunks: std::collections::VecDeque<Bytes> = (0..4).map(|_| Bytes::from(vec![0u8; 1024])).collect();
        let mut body = Throttle::new(Chunks(chunks), u64::MAX);
        let start = std::time::Instant::now();
        while let Some(r) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
            r.unwrap();
        }
        assert!(start.elapsed() < std::time::Duration::from_millis(10));
    }
}
