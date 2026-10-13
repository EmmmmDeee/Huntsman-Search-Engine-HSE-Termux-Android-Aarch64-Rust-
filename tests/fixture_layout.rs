//! Invariants of `tests/fixtures/`:
//! - every fixture is named, by its full path under `tests/fixtures`, in a string literal in
//!   `src/`, `tests/` or `crates/`; comments do not count. A `.md` note counts as read while its
//!   directory still holds a fixture for it to describe.
//! - run-time reads go through `support/fixtures.rs`, which works from any working directory.
//! - `.gitattributes` keeps checkouts from rewriting fixture bytes, and no later rule overrides it.
//!
//! Hidden entries and `~` backups (editor swap files, `.DS_Store`) are never fixtures.

use std::fs;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
#[path = "support/fixtures.rs"]
mod fixtures;

#[allow(dead_code)]
#[path = "support/rust_code.rs"]
mod rust_code;

const FIXTURE_RULE: &str = "tests/fixtures/** -text";

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy();
            if name.starts_with('.') || name.ends_with('~') {
                continue;
            }
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

fn relative(path: &Path, base: &Path) -> String {
    path.strip_prefix(base)
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/")
}

/// The ordinary string literals of every `.rs` file under `dirs`, with the file they are in.
fn string_literals(dirs: &[&str]) -> Vec<(PathBuf, Vec<String>)> {
    dirs.iter()
        .flat_map(|dir| files_under(&root().join(dir)))
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .map(|path| {
            let text = fs::read_to_string(&path).unwrap();
            let literals = rust_code::code_with_string_literals(&text).1;
            (path, literals)
        })
        .collect()
}

/// True when `rule` (one `.gitattributes` line) sets an attribute that decides line endings.
fn sets_line_endings(rule: &str) -> bool {
    rule.split_whitespace().skip(1).any(|attribute| {
        let name = attribute.trim_start_matches(['-', '!']);
        let name = name.split('=').next().unwrap_or(name);
        matches!(name, "text" | "eol" | "crlf")
    })
}

#[test]
fn every_fixture_is_named_by_a_reader() {
    let fixture_root = fixtures::path("");
    let all = files_under(&fixture_root);
    let literals: Vec<String> = string_literals(&["src", "tests", "crates"])
        .into_iter()
        .flat_map(|(_, literals)| literals)
        .collect();
    let named = |relative: &str| {
        let anchored = format!("fixtures/{relative}");
        let nested = format!("/{anchored}");
        literals
            .iter()
            .any(|lit| lit == relative || *lit == anchored || lit.ends_with(&nested))
    };
    let is_note = |path: &Path| path.extension().is_some_and(|ext| ext == "md");
    let orphans: Vec<String> = all
        .iter()
        .filter(|path| {
            if is_note(path) {
                !all.iter()
                    .any(|other| !is_note(other) && other.parent() == path.parent())
            } else {
                !named(&relative(path, &fixture_root))
            }
        })
        .map(|path| relative(path, &fixture_root))
        .collect();
    assert!(
        orphans.is_empty(),
        "no string literal names these by their full path under tests/fixtures, or a note has no \
         fixture left beside it; delete them with their last reader (a helper that adds a \
         directory prefix hides its readers): {orphans:?}"
    );
}

#[test]
fn fixtures_are_read_at_run_time_only_through_the_shared_loader() {
    let exempt = [
        root().join("tests/support/fixtures.rs"),
        root().join(file!()),
    ];
    let bypasses: Vec<String> = string_literals(&["tests"])
        .into_iter()
        .filter(|(path, literals)| {
            !exempt.contains(path) && literals.iter().any(|lit| lit.contains("tests/fixtures"))
        })
        .map(|(path, _)| relative(&path, root()))
        .collect();
    assert!(
        bypasses.is_empty(),
        "read fixtures with support/fixtures.rs (manifest-anchored) instead: {bypasses:?}"
    );
}

#[test]
fn checkouts_never_rewrite_fixture_bytes() {
    let attributes = fs::read_to_string(root().join(".gitattributes")).unwrap();
    let rules: Vec<&str> = attributes
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    let last_line_ending_rule = rules.iter().rposition(|rule| sets_line_endings(rule));
    assert!(
        last_line_ending_rule.is_some_and(|at| rules[at] == FIXTURE_RULE),
        ".gitattributes must keep `{FIXTURE_RULE}` as its last rule that sets text, eol or crlf; \
         a later rule overrides it and lets checkouts rewrite fixture line endings"
    );
}
