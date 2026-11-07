//! Static integration guard for the library's public Rust module graph.
//! This checks file ownership, not runtime behaviour or live-provider availability.

use std::collections::BTreeSet;
use std::path::Path;

#[test]
fn every_public_library_module_resolves_to_one_canonical_source_path() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let lib = std::fs::read_to_string(root.join("src/lib.rs")).expect("read src/lib.rs");
    let mut names = BTreeSet::new();
    let mut checked = 0_usize;

    for statement in lib.split(';') {
        // Declarations may share a line, and the first declaration follows
        // crate attributes and comments. Inspect the final line of each
        // semicolon-delimited segment rather than its entire prefix.
        let statement = statement.rsplit('\n').next().unwrap_or("").trim();
        // The library root declares public modules with 'pub mod name;'.
        let Some(name) = statement.strip_prefix("pub mod ") else {
            continue;
        };
        let name = name.trim();
        assert!(
            !name.is_empty()
                && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "noncanonical public module name: {name}"
        );
        assert!(names.insert(name.to_owned()), "duplicate public module: {name}");
        let file = root.join(format!("src/{name}.rs"));
        let directory = root.join(format!("src/{name}/mod.rs"));
        let count = usize::from(file.is_file()) + usize::from(directory.is_file());
        assert_eq!(
            count, 1,
            "module {name} must resolve to exactly one canonical source file ({} or {})",
            file.display(),
            directory.display()
        );
        checked += 1;
    }
    assert!(
        checked >= 200,
        "only {checked} public modules checked; parser or library layout may have changed"
    );
}
