//! Contract for the source-only Termux rebuild path. This test can execute in
//! host CI; physical Android execution remains a separate, explicitly named gate.

use std::process::Command;

const SCRIPT: &str = include_str!("../scripts/termux-full-rebuild.sh");

#[test]
fn full_rebuild_is_valid_bash() {
    let status = Command::new("bash")
        .args(["-n", "scripts/termux-full-rebuild.sh"])
        .status()
        .expect("CI provides bash");
    assert!(status.success(), "native rebuild orchestrator must parse");
}

#[test]
fn rebuild_preserves_native_canonical_acceptance_and_rollback_gates() {
    // No fallback to a prebuilt or silent host-mode substitution.
    for required in [
        "requires Android AArch64",
        "refusing to run as root",
        "requires the standard rootless Termux PREFIX",
        "git clone --quiet --depth 1 --single-branch --branch main",
        "HUNTSMAN_EXPECT_SHA",
        "cargo fmt --all --check",
        "cargo clippy --locked --workspace --all-targets -- -D warnings",
        "cargo test --locked --workspace",
        "cargo build --locked --release --bin huntsman-recon",
        "native-std-ok",
        "CARGO_PROFILE_DEV_DEBUG=0",
        "CARGO_PROFILE_TEST_DEBUG=0",
        "HUNTSMAN_BUILD_SHA",
        "build-sha",
        "scripts/termux-runtime-acceptance.sh",
        "TERMUX_RUNTIME_ACCEPTANCE",
        "candidate_sha",
        "staged_sha",
        "mv -f -- \"$stage\" \"$destination\"",
        "previous executable restored",
    ] {
        assert!(
            SCRIPT.contains(required),
            "missing native rebuild contract: {required}"
        );
    }
    assert!(!SCRIPT.contains("HSE_ACCEPTANCE_HOST=1"));
    assert!(!SCRIPT.contains("install_prebuilt"));
    assert!(!SCRIPT.contains("cargo install --git"));
}
