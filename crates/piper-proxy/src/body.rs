//! Body plumbing: boxed bodies, the recording tee and bodies streamed from the store.

use crate::recorder::{RecKey, Recorder};
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use http_body_util::combinators::BoxBody;
use piper_body::Body as StoredBody;
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
                        let now = piper_model::now_us();
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
                    let now = piper_model::now_us();
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

use std::future::Future;
