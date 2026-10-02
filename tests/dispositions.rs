//! `docs/DISPOSITIONS.md` claims to account for the legacy monolith. This test recomputes
//! that accounting from `legacy/`, so a row for a file that does not exist, or a stale
//! "Not yet dispositioned" count, fails the build.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const UNLISTED_HEADING: &str = "## Not yet dispositioned";

fn monolith() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("legacy/hse-monolith-v1.41.0")
}

fn doc() -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/DISPOSITIONS.md")).unwrap()
}

/// First cell of every table row, without backticks or annotations.
fn first_cells(markdown: &str) -> impl Iterator<Item = (&str, &str)> {
    markdown.lines().filter_map(|line| {
        let row = line.strip_prefix("| ")?;
        if row.starts_with("---") {
            return None;
        }
        let cell = row.split(" |").next()?.trim();
        let path = cell.split(' ').next()?.trim_matches('`');
        Some((path, cell))
    })
}

fn files_under(dir: &Path, base: &Path, out: &mut BTreeSet<String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files_under(&path, base, out);
        } else {
            let rel = path.strip_prefix(base).unwrap().to_string_lossy();
            out.insert(rel.replace('\\', "/"));
        }
    }
}

fn legacy_src() -> BTreeSet<String> {
    let src = monolith().join("src");
    let mut files = BTreeSet::new();
    files_under(&src, &src, &mut files);
    files
}

/// Legacy paths (relative to the monolith's `src/`) listed in the per-area sections.
fn listed(doc: &str) -> BTreeSet<String> {
    let body = &doc[..doc.find(UNLISTED_HEADING).expect("unlisted section")];
    first_cells(body)
        .filter(|(_, cell)| !cell.contains("(current owner)"))
        .map(|(path, _)| path.strip_prefix("src/").unwrap_or(path).to_owned())
        .filter(|path| path.contains('/') || Path::new(path).extension().is_some())
        .collect()
}

fn area(path: &str) -> &str {
    path.split_once('/').map_or("(root)", |(top, _)| top)
}

/// The `Not yet dispositioned` table as area → (unlisted, total).
fn unlisted_table(doc: &str) -> BTreeMap<String, (usize, usize)> {
    let section = &doc[doc.find(UNLISTED_HEADING).expect("unlisted section")..];
    section
        .lines()
        .filter_map(|line| {
            let cells: Vec<&str> = line
                .strip_prefix("| ")?
                .split(" |")
                .map(|c| c.trim().trim_start_matches("| ").trim())
                .collect();
            let unlisted = cells.get(1)?.parse().ok()?;
            let total = cells.get(2)?.parse().ok()?;
            let label = cells[0];
            let key = if label.starts_with("crate root") {
                "(root)".to_owned()
            } else {
                let path = label.split('`').nth(1)?;
                path.trim_start_matches("src/")
                    .trim_end_matches('/')
                    .to_owned()
            };
            Some((key, (unlisted, total)))
        })
        .collect()
}

#[test]
fn every_listed_legacy_row_exists() {
    let doc = doc();
    let src = legacy_src();
    let missing: Vec<String> = listed(&doc)
        .into_iter()
        .filter(|path| !src.contains(path) && !monolith().join(path).is_file())
        .collect();
    assert!(
        missing.is_empty(),
        "rows name absent legacy files: {missing:?}"
    );
}

#[test]
fn unlisted_counts_match_legacy() {
    let doc = doc();
    let listed = listed(&doc);
    let mut want: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for path in legacy_src() {
        let slot = want.entry(area(&path).to_owned()).or_default();
        slot.1 += 1;
        if !listed.contains(&path) {
            slot.0 += 1;
        }
    }
    want.retain(|_, (unlisted, _)| *unlisted > 0);
    assert_eq!(unlisted_table(&doc), want);

    let unlisted: usize = want.values().map(|v| v.0).sum();
    let total = legacy_src().len();
    let sentence = format!("({unlisted} of {total})");
    assert!(
        doc.contains(&sentence),
        "DISPOSITIONS should state {sentence}"
    );
}
