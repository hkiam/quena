//! Interception hook points.
//!
//! The forwarding pipeline calls the installed [`Interceptor`] at two points.
//! For each point the interceptor first says whether it needs the complete
//! body (`Buffer`) – only then is the body buffered (through the body store,
//! never in RAM). The default implementation streams everything untouched.

use quena_body::Body;
use quena_model::{RequestHead, ResponseHead, SessionId};
use quena_store::LiveSession;
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
    Forward {
        head: Option<RequestHead>,
        body: Option<Body>,
        delay_ms: u64,
    },
    /// Answer locally without contacting the server.
    Respond {
        head: ResponseHead,
        body: Body,
        delay_ms: u64,
    },
    /// Close the client connection without a response.
    Abort,
}

impl RequestAction {
    pub fn forward() -> Self {
        RequestAction::Forward {
            head: None,
            body: None,
            delay_ms: 0,
        }
    }
}

pub enum ResponseAction {
    Continue,
    Replace {
        head: ResponseHead,
        body: Option<Body>,
    },
    Abort,
}

/// Head-only response decision. Runs in both streaming and buffering modes, so
/// a script can rewrite response headers without the body being materialised
/// (Quena's large-body invariant).
pub enum ResponseHeadAction {
    Continue,
    Replace(ResponseHead),
    Abort,
}

pub trait Interceptor: Send + Sync {
    /// Does the request hook need the complete request body?
    fn request_mode(&self, _s: &SessionView, _head: &RequestHead) -> Mode {
        Mode::Stream
    }
    /// With [`Mode::Buffer`]: hold back at most this many bytes of the request body. A larger
    /// body (or one that takes too long) is forwarded unchanged as it streams, and
    /// [`Interceptor::on_request`] gets no body. `None`: hold back completely (breakpoints).
    fn request_hold_limit(&self, _s: &SessionView, _head: &RequestHead) -> Option<u64> {
        None
    }
    /// Called before forwarding. `body` is `Some` only in buffer mode.
    fn on_request(
        &self,
        _s: SessionView,
        _head: RequestHead,
        _body: Option<Body>,
    ) -> BoxFuture<RequestAction> {
        Box::pin(async { RequestAction::forward() })
    }
    /// Cheap sync check: does [`Interceptor::on_response_head`] need to run for
    /// this session? Lets the hot path skip the clones + boxed future when no
    /// script is active (the common case).
    fn wants_response_head(&self, _s: &SessionView) -> bool {
        false
    }
    /// Head-only response hook, called when [`Interceptor::wants_response_head`]
    /// is true (streaming and buffering). Lets a script rewrite response headers
    /// or abort without buffering the body.
    fn on_response_head(
        &self,
        _s: SessionView,
        _resp: ResponseHead,
    ) -> BoxFuture<ResponseHeadAction> {
        Box::pin(async { ResponseHeadAction::Continue })
    }
    /// Does the response hook need the complete response body?
    fn response_mode(&self, _s: &SessionView, _req: &RequestHead, _resp: &ResponseHead) -> Mode {
        Mode::Stream
    }
    /// With [`Mode::Buffer`]: hold back at most this many bytes of the response body; a
    /// larger (or slower) body streams unchanged and [`Interceptor::on_response`] is not
    /// called. `None`: hold back completely (breakpoints).
    fn response_hold_limit(
        &self,
        _s: &SessionView,
        _req: &RequestHead,
        _resp: &ResponseHead,
    ) -> Option<u64> {
        None
    }
    /// Called with the buffered response (buffer mode only).
    fn on_response(
        &self,
        _s: SessionView,
        _resp: ResponseHead,
        _body: Body,
    ) -> BoxFuture<ResponseAction> {
        Box::pin(async { ResponseAction::Continue })
    }
    /// Informational: session finished.
    fn on_complete(&self, _s: &SessionView) {}
}

pub struct NoInterceptor;
impl Interceptor for NoInterceptor {}
