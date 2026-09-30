//! Analyzers across sessions. (Implemented by the patterns work package.)
use crate::model::Analyzer;

pub fn all() -> Vec<Box<dyn Analyzer>> {
    vec![]
}
