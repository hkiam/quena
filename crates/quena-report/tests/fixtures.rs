//! The comparison fixtures shared with the UI (`app/ui/src/lib/diagReport.fixtures.test.ts`);
//! `expected` was produced by the TypeScript `compare()`.

use quena_report::{Lang, MdOptions, compare, normalize, to_markdown};
use serde_json::Value;
use std::path::Path;

#[test]
fn compare_matches_the_ui() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut n = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.starts_with("compare-") || !name.ends_with(".json") {
            continue;
        }
        let f: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let a = normalize(&f["a"]).unwrap();
        let b = normalize(&f["b"]).unwrap();
        let got = serde_json::to_value(compare(&a, &b)).unwrap();
        assert_eq!(got, f["expected"], "{name}");
        n += 1;
    }
    assert!(n >= 2, "fixtures missing in {}", dir.display());
}

#[test]
fn markdown_matches_the_ui() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/markdown-basic.json");
    let f: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let r = normalize(&f["report"]).unwrap();
    let md = |lang, opts: &MdOptions| to_markdown(&r, None, None, lang, opts);
    assert_eq!(
        md(Lang::En, &MdOptions::default()),
        f["en"].as_str().unwrap()
    );
    assert_eq!(
        md(Lang::De, &MdOptions::default()),
        f["de"].as_str().unwrap()
    );
    assert_eq!(
        md(
            Lang::En,
            &MdOptions {
                limit: Some(1),
                session_ids: 10
            }
        ),
        f["enLimited"].as_str().unwrap()
    );
}
