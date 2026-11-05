//! The source classification table (`src/source_profile.rs`) against the code that writes
//! sources:
//!
//! - every collector constant (`…SRC`, `…SOURCE`, `…SOURCE_ID`, `…COLLECTOR_ID`) and every
//!   registry row has a `PROFILES` row, so a new source is classified on purpose, never by the
//!   words in its name;
//! - every `PROFILES` ID is written somewhere in production code, and no `LEGACY` ID is, so the
//!   live table holds only live sources and the legacy table only IDs a saved scan may still carry.
//!
//! Production code is every file under `src/` but the out-of-line test modules, read without its
//! comments and `#[cfg(test)]` items.

#[allow(dead_code)]
#[path = "support/rust_code.rs"]
mod rust_code;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use huntsman_recon::module::reachable_modules;
use huntsman_recon::source_profile::{LEGACY, PROFILES};
use rust_code::{code_with_string_literals, strip_non_code, tokens, without_test_items};

/// The table itself names every ID; it is no evidence that one is written.
const TABLE: &str = "src/source_profile.rs";

struct Source {
    path: String,
    text: String,
}

fn normal(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("readable directory") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Every file under `src/` but the out-of-line test modules: for `#[cfg(test)] mod x;` in a file,
/// `x.rs` and `x/mod.rs` in that file's module directory.
fn production_sources() -> Vec<Source> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    collect(&root.join("src"), &mut files);
    files.sort();
    let all: Vec<Source> = files
        .into_iter()
        .map(|file| Source {
            path: normal(file.strip_prefix(root).expect("under the crate root")),
            text: fs::read_to_string(&file).expect("readable source"),
        })
        .collect();
    let mut test_only = BTreeSet::new();
    for source in &all {
        let (_, declared) = without_test_items(&tokens(&strip_non_code(&source.text)));
        let path = Path::new(&source.path);
        let dir: PathBuf = match path.file_name().and_then(|name| name.to_str()) {
            Some("lib.rs" | "main.rs" | "mod.rs") => path.parent().unwrap_or(Path::new("")).into(),
            _ => path.with_extension(""),
        };
        for name in declared {
            test_only.insert(normal(&dir.join(format!("{name}.rs"))));
            test_only.insert(normal(&dir.join(&name).join("mod.rs")));
        }
    }
    all.into_iter()
        .filter(|source| !test_only.contains(&source.path))
        .collect()
}

/// A production file's tokens, with each string literal a `__strN` token, and the literals.
fn production_tokens(source: &Source) -> (Vec<String>, Vec<String>) {
    let (code, literals) = code_with_string_literals(&source.text);
    let (toks, _) = without_test_items(&tokens(&code));
    (toks, literals)
}

/// The literal a `__strN` token stands for.
fn literal<'a>(token: &str, literals: &'a [String]) -> Option<&'a str> {
    let index: usize = token.strip_prefix("__str")?.parse().ok()?;
    literals.get(index).map(String::as_str)
}

/// Every string literal in production code outside the table.
fn written_literals() -> BTreeSet<String> {
    let mut written = BTreeSet::new();
    for source in production_sources().iter().filter(|s| s.path != TABLE) {
        let (toks, literals) = production_tokens(source);
        written.extend(
            toks.iter()
                .filter_map(|token| literal(token, &literals))
                .map(str::to_owned),
        );
    }
    written
}

/// Whether a constant's name marks it as a collector's source ID: `SRC`, `SOURCE`, `SOURCE_ID` or
/// `COLLECTOR_ID`, alone or as the name's last part (`RESOURCE` is not one).
fn names_a_source(name: &str) -> bool {
    ["SRC", "SOURCE", "SOURCE_ID", "COLLECTOR_ID"]
        .iter()
        .any(|part| name == *part || name.ends_with(&format!("_{part}")))
}

/// Each `const NAME: &str = "value";` in production code whose name marks a source ID, as
/// `(file, NAME, value)`.
fn collector_constants() -> Vec<(String, String, String)> {
    let mut found = Vec::new();
    for source in production_sources() {
        let (toks, literals) = production_tokens(&source);
        for (at, token) in toks.iter().enumerate() {
            if token != "const" {
                continue;
            }
            let Some(name) = toks.get(at + 1) else {
                continue;
            };
            if !names_a_source(name) || toks.get(at + 2).map(String::as_str) != Some(":") {
                continue;
            }
            // `: &str =` or `: &'static str =`, then the value and `;`.
            let Some(eq) = toks[at..].iter().take(8).position(|t| t == "=") else {
                continue;
            };
            let value = toks.get(at + eq + 1).and_then(|t| literal(t, &literals));
            if let (Some(value), Some(";")) = (value, toks.get(at + eq + 2).map(String::as_str)) {
                found.push((source.path.clone(), name.clone(), value.to_owned()));
            }
        }
    }
    found
}

fn profiled(id: &str) -> bool {
    PROFILES.iter().any(|row| row.id == id)
}

#[test]
fn every_collector_constant_has_a_profile() {
    let constants = collector_constants();
    assert!(
        constants.len() >= 80,
        "the scan found only {} collector constants",
        constants.len()
    );
    let missing: Vec<String> = constants
        .iter()
        .filter(|(_, _, value)| !profiled(value))
        .map(|(file, name, value)| format!("{file}: {name} = {value:?}"))
        .collect();
    assert!(
        missing.is_empty(),
        "add a PROFILES row in src/source_profile.rs for each source these constants name, so \
         the correlator and the coverage report classify it on purpose: {missing:#?}"
    );
}

#[test]
fn every_registry_row_has_a_profile() {
    let missing: Vec<&str> = reachable_modules()
        .iter()
        .map(|module| module.name)
        .filter(|name| !profiled(name))
        .collect();
    assert!(
        missing.is_empty(),
        "add a PROFILES row in src/source_profile.rs for each of these registry rows: {missing:?}"
    );
}

#[test]
fn every_live_id_is_written_and_no_legacy_id_is() {
    let written = written_literals();
    let unwritten: Vec<&str> = PROFILES
        .iter()
        .map(|row| row.id)
        .filter(|id| !written.contains(*id))
        .collect();
    assert!(
        unwritten.is_empty(),
        "no production code writes these PROFILES IDs; move each to LEGACY if a saved scan may \
         still carry it, else delete it: {unwritten:?}"
    );
    let revived: Vec<&str> = LEGACY
        .iter()
        .map(|row| row.id)
        .filter(|id| written.contains(*id))
        .collect();
    assert!(
        revived.is_empty(),
        "production code writes these LEGACY IDs again; move each to PROFILES: {revived:?}"
    );
}

/// The scans above find what they are meant to: a known constant, a known literal, and nothing
/// from test code.
#[test]
fn the_scans_read_production_code_only() {
    let constants = collector_constants();
    assert!(
        constants
            .iter()
            .any(|(file, name, value)| file == "src/acnc.rs" && name == "SRC" && value == "acnc"),
        "the constant scan misses acnc::SRC"
    );
    assert!(
        constants
            .iter()
            .all(|(file, _, _)| !file.ends_with("/tests.rs") && !file.contains("test_support")),
        "the constant scan read test code"
    );
    let written = written_literals();
    assert!(
        written.contains("gleif_lei"),
        "the literal scan misses gleif's SOURCE"
    );
    assert!(
        !written.contains("zz_unregistered_probe"),
        "the literal scan read a test fixture's probe"
    );
}
