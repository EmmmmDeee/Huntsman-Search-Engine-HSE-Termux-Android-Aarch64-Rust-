//! The manifests carry the invariants that every later file inherits: unsafe code is forbidden
//! in every crate, lint levels are set in the manifests and nowhere else, and every runtime
//! dependency of the package states its purpose. A `forbid` cannot be reopened by a local
//! `allow`, where a `deny` can. A dependency without a stated purpose is one nobody can judge
//! for removal.

use std::collections::BTreeMap;
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

/// A crate root sets no lint level of its own, so the manifests show the whole policy. The one
/// exception is test-only: `assert_is_empty` fires on the 1.99 clippy the gate runs, and
/// `unknown_lints` covers toolchains that lack it.
#[test]
fn crate_roots_set_no_lint_level_outside_the_manifests() {
    const LEVELS: [&str; 5] = ["allow(", "deny(", "warn(", "forbid(", "expect("];
    const TEST_ONLY: &str = "#![cfg_attr(test, allow(unknown_lints, clippy::assert_is_empty))]";
    let mut roots = vec![
        "src/lib.rs".to_string(),
        "src/main.rs".to_string(),
        "xtask/src/main.rs".to_string(),
    ];
    // Any further executable under src/bin is a crate root too; today there is none.
    for entry in fs::read_dir("src/bin").into_iter().flatten() {
        roots.push(entry.expect("src/bin entry").path().display().to_string());
    }
    for path in &roots {
        let source = fs::read_to_string(path).expect(path);
        for line in source.lines().map(str::trim) {
            let exempt = path == "src/lib.rs" && line == TEST_ONLY;
            if !line.starts_with("#![") || exempt {
                continue;
            }
            assert!(
                !LEVELS.iter().any(|level| line.contains(level)),
                "{path} sets a lint level outside [lints] in Cargo.toml: {line}"
            );
        }
    }
}

/// The release profile is what both the phone (`cargo install`) and CI's Android build use, so
/// the binary's speed and size come from it. Unwinding must stay: `serve` turns a panicking
/// handler into a 500 for that request only (`web_server.rs`), and `panic = "abort"` would end
/// the server instead.
#[test]
fn the_release_profile_optimises_across_crates_strips_and_unwinds() {
    let manifest = fs::read_to_string("Cargo.toml").expect("root manifest");
    // Settings by key, so a spelling that means the same thing passes and nothing else does.
    let profile: BTreeMap<&str, &str> = section(&manifest, "profile.release")
        .into_iter()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim(), value.trim().trim_matches('"')))
        .collect();
    assert_eq!(
        profile.get("lto"),
        Some(&"thin"),
        "release profile must use thin LTO: {profile:?}"
    );
    assert!(
        matches!(profile.get("strip"), Some(&"symbols" | &"true")),
        "release profile must strip symbols: {profile:?}"
    );
    assert!(
        matches!(profile.get("panic"), None | Some(&"unwind")),
        "release profile must keep the unwinding panic strategy: {profile:?}"
    );
}
