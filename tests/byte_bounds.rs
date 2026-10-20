//! One name, one bound. A byte ceiling declared under the same name in two modules with two values
//! let the wrong one look authoritative: `MAX_ARTIFACT_BYTES` was 1 MiB in the CLI and 32 MiB in the
//! artifact store, and `MAX_HISTORY_BYTES` was 16 MiB and 128 MiB. Every module-level byte bound in
//! `src/` has one name, and each declaration of that name has the same value.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("source directory") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Every module-level `const NAME: u64|usize = VALUE;` whose name says BYTES, as
/// `NAME -> [(file, VALUE)]`. Indented declarations inside a module are not module-level.
fn byte_bounds() -> BTreeMap<String, Vec<(String, String)>> {
    let mut files = Vec::new();
    rust_files(Path::new("src"), &mut files);
    let mut bounds: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for file in files {
        let text = fs::read_to_string(&file).expect("source file");
        for line in text.lines() {
            let decl = line
                .strip_prefix("pub(crate) const ")
                .or_else(|| line.strip_prefix("pub const "))
                .or_else(|| line.strip_prefix("const "));
            let Some(decl) = decl else { continue };
            let Some((name, rest)) = decl.split_once(':') else {
                continue;
            };
            let name = name.trim();
            if !name.contains("BYTES") {
                continue;
            }
            let Some((ty, value)) = rest.split_once('=') else {
                continue;
            };
            if !matches!(ty.trim(), "u64" | "usize") {
                continue;
            }
            bounds.entry(name.to_owned()).or_default().push((
                file.display().to_string(),
                value.trim().trim_end_matches(';').trim().to_owned(),
            ));
        }
    }
    bounds
}

#[test]
fn every_byte_bound_name_has_one_value() {
    let bounds = byte_bounds();
    assert!(
        bounds.contains_key("MAX_ARTIFACT_BYTES"),
        "the scan found no byte bounds: {bounds:?}"
    );
    for (name, uses) in &bounds {
        let values: BTreeSet<&str> = uses.iter().map(|(_, value)| value.as_str()).collect();
        assert_eq!(
            values.len(),
            1,
            "{name} is declared with different values: {uses:?}"
        );
    }
}
