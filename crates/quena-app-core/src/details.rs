//! Session details for filter expressions that test headers, cookies or bodies
//! (`reqheader.x-api-version == 2`, `resbody ~ error`). Read without the index, since the
//! index evaluates its filter while it is locked.

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

    fn body(&self, id: SessionId, response: bool) -> Option<String> {
        let (d, req, resp) = self.0.upgrade()?.bodies_stored(id)?;
        let (body, headers) = if response { (resp, d.response?.headers) } else { (req, d.request.headers) };
        let bytes = quena_body::text::decoded_prefix(&body, &crate::dto::spec_of(&headers), BODY_WINDOW);
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }
}
