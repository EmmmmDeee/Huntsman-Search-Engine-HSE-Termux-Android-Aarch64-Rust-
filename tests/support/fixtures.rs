//! The one way integration tests read `tests/fixtures/` at run time. Paths are anchored on
//! `CARGO_MANIFEST_DIR`, so a test binary finds its fixtures from any working directory, and the
//! bytes are returned exactly as stored (`.gitattributes` stops checkouts rewriting line endings).
//! `tests/fixture_layout.rs` enforces that no other test reads the directory by a relative path.

use std::path::{Path, PathBuf};

pub fn path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(relative)
}

pub fn bytes(relative: &str) -> Vec<u8> {
    let path = path(relative);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

pub fn text(relative: &str) -> String {
    let path = path(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}
