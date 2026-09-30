//! All analyzers. Two families:
//! * `request` — checks of single sessions and simple aggregates (errors, sizes, headers …)
//! * `patterns` — checks across sessions (duplicates, N+1, polling, chains, networks …)
use crate::model::Analyzer;

pub mod patterns;
pub mod request;

pub fn all() -> Vec<Box<dyn Analyzer>> {
    let mut v = request::all();
    v.extend(patterns::all());
    v
}
