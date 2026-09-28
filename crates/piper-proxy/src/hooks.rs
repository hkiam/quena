//! Interception hook points (PLAN.md §2.1).
//!
//! The forwarding pipeline calls the installed [`Interceptor`] at two points.
//! For each point the interceptor first says whether it needs the complete
//! body (`Buffer`) – only then is the body buffered (through the body store,
//! never in RAM). The default implementation streams everything untouched.

use piper_body::Body;
use piper_model::{RequestHead, ResponseHead, SessionId};
use piper_store::LiveSession;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// What the pipeline knows about the session at a hook point.
#[derive(Clone)]
pub struct SessionView {
    pub id: SessionId,
    pub live: Arc<LiveSession>,
    pub process: String,
    pub client_ip: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Stream,
    Buffer,
}

pub enum RequestAction {
    /// Forward (optionally modified head/body, optionally to another URL, after a delay).
    Forward { head: Option<RequestHead>, body: Option<Body>, delay_ms: u64 },
    /// Answer locally without contacting the server.
    Respond { head: ResponseHead, body: Body, delay_ms: u64 },
    /// Close the client connection without a response.
    Abort,
}

impl RequestAction {
    pub fn forward() -> Self {
        RequestAction::Forward { head: None, body: None, delay_ms: 0 }
    }
}

pub enum ResponseAction {
    Continue,
    Replace { head: ResponseHead, body: Option<Body> },
    Abort,
}

pub trait Interceptor: Send + Sync {
    /// Does the request hook need the complete request body?
    fn request_mode(&self, _s: &SessionView, _head: &RequestHead) -> Mode {
        Mode::Stream
    }
    /// Called before forwarding. `body` is `Some` only in buffer mode.
    fn on_request(&self, _s: SessionView, _head: RequestHead, _body: Option<Body>) -> BoxFuture<RequestAction> {
        Box::pin(async { RequestAction::forward() })
    }
    /// Does the response hook need the complete response body?
    fn response_mode(&self, _s: &SessionView, _req: &RequestHead, _resp: &ResponseHead) -> Mode {
        Mode::Stream
    }
    /// Called with the buffered response (buffer mode only).
    fn on_response(&self, _s: SessionView, _resp: ResponseHead, _body: Body) -> BoxFuture<ResponseAction> {
        Box::pin(async { ResponseAction::Continue })
    }
    /// Informational: session finished.
    fn on_complete(&self, _s: &SessionView) {}
}

pub struct NoInterceptor;
impl Interceptor for NoInterceptor {}
