//! `docs/DISPOSITIONS.md` claims to account for the legacy monolith. This test recomputes
//! that accounting from `legacy/`, so a row for a file that does not exist, or a stale
//! "Not yet dispositioned" count, fails the build. It also recomputes the crate's module
//! tree from `src/lib.rs` and `src/main.rs`, so a row that says code was rebuilt into a
//! `src/` file the compiler never reads, or a `src/` file with no `mod` line, fails too.

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

/// Decisions that claim the code now lives in a current `src/` file.
const CLAIMS: [&str; 4] = ["REBUILT", "REIMPLEMENT", "MERGED", "PARTIAL"];

fn crate_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Out-of-line `mod name;` declarations (any visibility) in one source file.
fn declared_mods(text: &str) -> Vec<&str> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            assert!(
                !line.starts_with("#[path"),
                "#[path] is not supported by this check: {line}"
            );
            let rest = match line.strip_prefix("pub") {
                Some(rest) if rest.starts_with('(') => rest.split_once(") ")?.1,
                Some(rest) => rest.strip_prefix(' ')?,
                None => line,
            };
            let name = rest.strip_prefix("mod ")?.strip_suffix(';')?;
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
                .then_some(name)
        })
        .collect()
}

/// Directory that holds the children of `file` (a path relative to the crate root).
fn child_dir(file: &str) -> String {
    let (dir, name) = file.rsplit_once('/').unwrap();
    match name {
        "lib.rs" | "main.rs" | "mod.rs" => dir.to_owned(),
        _ => format!("{dir}/{}", name.trim_end_matches(".rs")),
    }
}

/// Every `src/` file the compiler reads: the module tree reached from both crate roots.
fn compiled_sources() -> BTreeSet<String> {
    let root = crate_root();
    let mut seen = BTreeSet::new();
    let mut queue = vec!["src/lib.rs".to_owned(), "src/main.rs".to_owned()];
    while let Some(file) = queue.pop() {
        if !seen.insert(file.clone()) {
            continue;
        }
        let text = fs::read_to_string(root.join(&file)).unwrap();
        let dir = child_dir(&file);
        for name in declared_mods(&text) {
            let found = [format!("{dir}/{name}.rs"), format!("{dir}/{name}/mod.rs")]
                .into_iter()
                .find(|path| root.join(path).is_file());
            match found {
                Some(path) => queue.push(path),
                None => panic!("{file} declares `mod {name};` but no file backs it"),
            }
        }
    }
    seen
}

fn is_rust(path: &str) -> bool {
    Path::new(path).extension().is_some_and(|ext| ext == "rs")
}

/// `src/…/*.rs` paths named in `cell`.
fn src_paths(cell: &str) -> Vec<String> {
    cell.match_indices("src/")
        .filter(|(at, _)| {
            at.checked_sub(1)
                .is_none_or(|i| !cell.as_bytes()[i].is_ascii_alphanumeric())
        })
        .map(|(at, _)| {
            cell[at..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '/' | '.'))
                .collect::<String>()
        })
        .filter(|path| is_rust(path))
        .collect()
}

/// Current `src/` files that the per-area sections say hold rebuilt code: every path
/// outside the legacy (first) column of a claiming row, and every bullet that starts
/// with a backticked `src/` path.
fn claimed_targets(doc: &str) -> BTreeSet<String> {
    let body = &doc[..doc.find(UNLISTED_HEADING).expect("unlisted section")];
    let mut out = BTreeSet::new();
    for line in body.lines() {
        if let Some(row) = line.strip_prefix("| ") {
            let cells: Vec<&str> = row.split(" |").map(str::trim).collect();
            let claims = cells
                .iter()
                .skip(1)
                .any(|cell| CLAIMS.iter().any(|claim| cell.starts_with(claim)));
            if claims {
                out.extend(cells.iter().skip(1).flat_map(|cell| src_paths(cell)));
            }
        } else if let Some(item) = line.strip_prefix("- `src/") {
            out.extend(src_paths(&format!("src/{item}")).into_iter().take(1));
        }
    }
    out
}

fn uncompiled(claimed: &BTreeSet<String>, compiled: &BTreeSet<String>) -> Vec<String> {
    claimed.difference(compiled).cloned().collect()
}

#[test]
fn every_rebuilt_target_is_compiled() {
    let claimed = claimed_targets(&doc());
    assert!(
        claimed.contains("src/diamond.rs") && claimed.contains("src/dmarc.rs"),
        "claim parser found too little: {claimed:?}"
    );
    let missing = uncompiled(&claimed, &compiled_sources());
    assert!(
        missing.is_empty(),
        "DISPOSITIONS claims code lives in files the crate never compiles (no `mod` line): {missing:?}"
    );
}

#[test]
fn every_src_file_is_compiled() {
    let root = crate_root();
    let mut files = BTreeSet::new();
    files_under(&root.join("src"), root, &mut files);
    files.retain(|path| is_rust(path));
    let missing = uncompiled(&files, &compiled_sources());
    assert!(
        missing.is_empty(),
        "src files with no `mod` line are never compiled or tested: {missing:?}"
    );
}

#[test]
fn claim_check_flags_an_uncompiled_target() {
    let doc = format!(
        "| `src/core/x.rs` | 1 | REBUILT | `src/x.rs`, `src/y/mod.rs` tests | why |\n\
         | `src/core/z.rs` | 1 | PENDING | `src/z.rs` | not yet |\n\
         - `src/w.rs`\n{UNLISTED_HEADING}\n- `src/after.rs`\n"
    );
    let claimed = claimed_targets(&doc);
    let want: BTreeSet<String> = ["src/w.rs", "src/x.rs", "src/y/mod.rs"]
        .map(str::to_owned)
        .into();
    assert_eq!(claimed, want);
    let compiled: BTreeSet<String> = ["src/x.rs".to_owned()].into();
    assert_eq!(
        uncompiled(&claimed, &compiled),
        ["src/w.rs", "src/y/mod.rs"]
    );
}

#[test]
fn module_tree_follows_mod_rs_and_nested_files() {
    let compiled = compiled_sources();
    for path in [
        "src/lib.rs",
        "src/main.rs",
        "src/hibp/mod.rs",
        "src/hibp/tests.rs",
        "src/eval/stats.rs",
    ] {
        assert!(compiled.contains(path), "{path} missing from {compiled:?}");
    }
    assert_eq!(child_dir("src/lib.rs"), "src");
    assert_eq!(child_dir("src/hibp/mod.rs"), "src/hibp");
    assert_eq!(child_dir("src/geo.rs"), "src/geo");
    assert_eq!(
        declared_mods("pub mod a;\npub(crate) mod b;\n    mod c;\nmod d {\n// mod e;\n"),
        ["a", "b", "c"]
    );
}
