//! The manifests carry the invariants that every later file inherits: unsafe code is forbidden
//! in every crate, and every runtime dependency of the package states its purpose. A `forbid`
//! cannot be reopened by a local `allow`, where a `deny` can. A dependency without a stated
//! purpose is one nobody can judge for removal.

use std::fs;

/// The lines of the section headed `[NAME]` in MANIFEST, up to the next section header.
fn section<'a>(manifest: &'a str, name: &str) -> Vec<&'a str> {
    let header = format!("[{name}]");
    manifest
        .lines()
        .skip_while(|line| line.trim() != header)
        .skip(1)
        .take_while(|line| !line.trim_start().starts_with('['))
        .collect()
}

#[test]
fn every_crate_forbids_unsafe_code() {
    for path in ["Cargo.toml", "xtask/Cargo.toml"] {
        let manifest = fs::read_to_string(path).expect(path);
        let lints = section(&manifest, "lints.rust");
        assert!(
            lints
                .iter()
                .any(|line| line.trim() == "unsafe_code = \"forbid\""),
            "{path} must set unsafe_code = \"forbid\" under [lints.rust]: {lints:?}"
        );
    }
}

#[test]
fn every_runtime_dependency_states_its_purpose() {
    let manifest = fs::read_to_string("Cargo.toml").expect("root manifest");
    let dependencies = section(&manifest, "dependencies");
    let mut previous: Option<&str> = None;
    let mut seen = 0;
    for line in dependencies {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !trimmed.starts_with('#') {
            let name = trimmed.split('=').next().unwrap_or(trimmed).trim();
            assert!(
                previous.is_some_and(|comment| comment.starts_with('#')),
                "dependency {name} must be preceded by a comment stating its purpose"
            );
            seen += 1;
        }
        previous = Some(trimmed);
    }
    assert!(
        seen > 0,
        "the root manifest declares no runtime dependencies"
    );
}
