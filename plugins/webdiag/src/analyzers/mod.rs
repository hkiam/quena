//! All analyzers. Two families:
//! * `request` — checks of single sessions and simple aggregates (errors, sizes, headers …)
//! * `patterns` — checks across sessions (duplicates, N+1, polling, chains, networks …)
//! * `encoding` — character encoding of text bodies (charset declarations vs. the bytes)
use crate::model::Analyzer;

pub mod encoding;
pub mod clock;
pub mod patterns;
pub mod request;
pub mod scope;

pub fn all() -> Vec<Box<dyn Analyzer>> {
    let mut v = request::all();
    v.extend(patterns::all());
    v.extend(encoding::all());
    v.extend(scope::all());
    v.extend(clock::all());
    v
}
