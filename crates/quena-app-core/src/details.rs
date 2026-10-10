//! Session details for filter expressions that test headers, cookies or bodies
//! (`reqheader.x-api-version == 2`, `resbody ~ error`). Read without the index, since the
//! index evaluates its filter while it is locked; stored sessions are looked at by the filter's
//! background thread ([`quena_query::Filter::with_details`]), not under that lock.

use quena_model::SessionId;
use quena_query::expr::Details;
use quena_store::Capture;
use std::sync::{Arc, Weak};

/// Bytes of a body a filter looks at (decoded).
const BODY_WINDOW: usize = 256 << 10;

pub struct CaptureDetails(Weak<Capture>);

impl CaptureDetails {
    pub fn of(cap: &Arc<Capture>) -> Arc<dyn Details> {
        Arc::new(CaptureDetails(Arc::downgrade(cap)))
    }
}

impl Details for CaptureDetails {
    fn headers(&self, id: SessionId, response: bool) -> Option<Vec<(String, String)>> {
        let d = self.0.upgrade()?.detail_stored(id)?;
        Some(if response { d.response?.headers.0 } else { d.request.headers.0 })
    }

    fn at_hand(&self, id: SessionId) -> bool {
        self.0.upgrade().is_some_and(|c| c.live(id).is_some())
    }

    fn summary(&self, id: SessionId) -> Option<quena_model::SessionSummary> {
        self.0.upgrade()?.index.get(id)
    }

    fn ready(&self, ids: &[SessionId]) {
        if let Some(c) = self.0.upgrade() {
            c.index.touch(ids);
        }
    }

    fn body(&self, id: SessionId, response: bool) -> Option<String> {
        let (d, req, resp) = self.0.upgrade()?.bodies_stored(id)?;
        let (body, headers) = if response { (resp, d.response?.headers) } else { (req, d.request.headers) };
        let bytes = quena_body::text::decoded_prefix(&body, &crate::dto::spec_of(&headers), BODY_WINDOW);
        // In the body's charset (Latin-1, UTF-16 …), so `resbody ~ Grüße` finds it.
        let enc = quena_body::charset::detect(headers.get("content-type"), &bytes).encoding;
        Some(quena_body::text::decode_piece(&bytes, enc))
    }
}

/// Ids of the sessions `e` matches (`view`: those the list shows, in its order; else all), and
/// `also`. An expression testing details is evaluated outside the index lock.
pub fn matching(cap: &Arc<Capture>, e: &quena_query::Expr, view: bool, also: impl Fn(&quena_model::SessionSummary) -> bool) -> Vec<SessionId> {
    if !e.needs_details() {
        return if view { cap.index.find(|s| also(s) && e.eval(s)) } else { cap.index.find_all(|s| also(s) && e.eval(s)) };
    }
    let ids = if view { cap.index.find(&also) } else { cap.index.find_all(&also) };
    let d = CaptureDetails::of(cap);
    ids.into_iter().filter(|id| cap.index.get(*id).is_some_and(|s| e.eval_with(&s, Some(&*d)))).collect()
}
