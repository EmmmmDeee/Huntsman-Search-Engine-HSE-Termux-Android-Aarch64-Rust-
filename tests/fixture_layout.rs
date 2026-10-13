//! Invariants of `tests/fixtures/`: every fixture has a reader, run-time reads go through
//! `support/fixtures.rs` so they work from any working directory, and checkouts keep fixture bytes
//! exactly as committed.

use std::fs;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
#[path = "support/fixtures.rs"]
mod fixtures;

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

fn rust_sources(dirs: &[&str]) -> Vec<(PathBuf, String)> {
    dirs.iter()
        .flat_map(|dir| files_under(&root().join(dir)))
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .map(|path| {
            let text = fs::read_to_string(&path).unwrap();
            (path, text)
        })
        .collect()
}

#[test]
fn every_fixture_is_read_by_some_test_or_source() {
    let fixture_root = fixtures::path("");
    let sources = rust_sources(&["src", "tests", "crates"]);
    let orphans: Vec<String> = files_under(&fixture_root)
        .iter()
        .filter(|path| path.extension().is_none_or(|ext| ext != "md"))
        .map(|path| {
            path.strip_prefix(&fixture_root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        })
        .filter(|relative| {
            !sources
                .iter()
                .any(|(_, text)| text.contains(relative.as_str()))
        })
        .collect();
    assert!(
        orphans.is_empty(),
        "fixtures nothing reads (delete them with their last reader): {orphans:?}"
    );
}

#[test]
fn fixtures_are_read_at_run_time_only_through_the_shared_loader() {
    let needle = ["\"tests", "/fixtures"].concat();
    let exempt = [
        root().join("tests/support/fixtures.rs"),
        root().join(file!()),
    ];
    let bypasses: Vec<String> = rust_sources(&["tests"])
        .into_iter()
        .filter(|(path, text)| !exempt.contains(path) && text.contains(&needle))
        .map(|(path, _)| path.display().to_string())
        .collect();
    assert!(
        bypasses.is_empty(),
        "read fixtures with support/fixtures.rs (manifest-anchored) instead: {bypasses:?}"
    );
}

#[test]
fn checkouts_never_rewrite_fixture_bytes() {
    let attributes = fs::read_to_string(root().join(".gitattributes")).unwrap();
    assert!(
        attributes
            .lines()
            .any(|line| line.trim() == "tests/fixtures/** -text"),
        ".gitattributes must keep `tests/fixtures/** -text` so line endings survive checkout"
    );
}
