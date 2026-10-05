//! Canonical extracted legacy trees used as reconstruction oracles.
//!
//! The original ZIP containers are intentionally absent from HEAD: their exact
//! hashes and recoverable Git commit are recorded in `docs/ARCHIVE_PROVENANCE.md`.
//! Keeping the extracted trees makes the reference material reviewable and
//! searchable while Git history preserves the original archive bytes.

use std::fs;
use std::path::{Path, PathBuf};

const EXTRACTED_TREES: &[(&str, usize)] = &[
    ("hse-monolith-v1.41.0", 1314),
    ("refactor-overlay-feef60a", 40),
];

fn count_files(dir: &Path) -> usize {
    fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|entry| {
            let path = entry.expect("entry").path();
            if path.is_dir() { count_files(&path) } else { 1 }
        })
        .sum()
}

#[test]
fn extracted_legacy_trees_are_complete() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("legacy");
    for (dir, files) in EXTRACTED_TREES {
        assert_eq!(count_files(&root.join(dir)), *files, "{dir}");
    }
}
