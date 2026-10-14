//! The toolchains CI runs. The repair gate runs on one pinned stable release, never on the
//! floating `stable` channel: a new release's lints turned `main` red with no change to the code
//! (clippy 1.99 against a tree the gate had passed on 1.97). The MSRV leg stays on the crate's
//! `rust-version`. To move to a new stable, run `cargo gate full` on it, then bump
//! [`PINNED_STABLE`] and the workflows together.

use std::fs;

/// The stable release the gate is verified with.
const PINNED_STABLE: &str = "1.99";
/// `rust-version` in `Cargo.toml`.
const MSRV: &str = "1.87";

/// The workflows that build or test the crate. `audit.yml` is not among them: it only installs
/// `cargo-audit` and reads the lockfile, so it may use the newest stable.
const GATED_WORKFLOWS: [&str; 4] = [
    ".github/workflows/ci.yml",
    ".github/workflows/release.yml",
    ".github/workflows/issue-fix.yml",
    ".github/workflows/dual-pass.yml",
];

fn workflow(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("{path}: {error}"))
}

/// Every `toolchain:` value in a workflow, with quotes and a trailing comment removed. A matrix
/// expression counts as one value.
fn toolchain_values(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.trim_start().strip_prefix("toolchain:"))
        .map(|value| {
            let value = value.split(" #").next().unwrap_or(value);
            value.trim().trim_matches('"').to_string()
        })
        .collect()
}

#[test]
fn the_gated_workflows_name_only_the_msrv_and_the_pinned_stable_release() {
    let msrv_patch = format!("{MSRV}.0");
    for path in GATED_WORKFLOWS {
        let values = toolchain_values(&workflow(path));
        assert!(!values.is_empty(), "{path} must set up a toolchain");
        for value in values {
            assert!(
                value == MSRV
                    || value == msrv_patch
                    || value == PINNED_STABLE
                    || value == "${{ matrix.toolchain }}",
                "{path} sets up toolchain {value:?}: only {MSRV} (the MSRV), {PINNED_STABLE} (the \
                 pinned stable release) or the test matrix may be named; a channel such as \
                 `stable` would let a new release's lints turn main red"
            );
        }
    }
}

#[test]
fn ci_gates_the_msrv_leg_with_msrv_and_the_pinned_stable_leg_with_full() {
    let ci = workflow(".github/workflows/ci.yml");
    let matrix = format!("        toolchain: [\"{MSRV}\", \"{PINNED_STABLE}\"]\n");
    assert!(
        ci.contains(&matrix),
        "ci.yml must test the MSRV and the pinned stable release, and nothing else:\n{matrix}"
    );
    let full = format!(
        "        if: matrix.toolchain == '{PINNED_STABLE}'\n        run: cargo run --locked -p \
         xtask -- gate full\n"
    );
    assert!(
        ci.contains(&full),
        "ci.yml must run `gate full` on the pinned stable release:\n{full}"
    );
    let msrv = format!(
        "        if: matrix.toolchain == '{MSRV}'\n        run: cargo run --locked -p xtask -- \
         gate msrv\n"
    );
    assert!(
        ci.contains(&msrv),
        "ci.yml must run `gate msrv` on the MSRV:\n{msrv}"
    );
}

#[test]
fn the_msrv_pin_is_the_manifest_rust_version() {
    let manifest = fs::read_to_string("Cargo.toml").expect("Cargo.toml");
    assert!(
        manifest.contains(&format!("rust-version = \"{MSRV}\"")),
        "Cargo.toml must declare rust-version = \"{MSRV}\", the MSRV CI tests"
    );
}

#[test]
fn the_pinned_stable_release_is_newer_than_the_msrv() {
    let minor = |version: &str| -> u32 {
        version
            .split('.')
            .nth(1)
            .and_then(|minor| minor.parse().ok())
            .unwrap_or_else(|| panic!("{version:?} is not MAJOR.MINOR"))
    };
    assert!(
        minor(PINNED_STABLE) > minor(MSRV),
        "the pinned stable release must be newer than the MSRV, or the stable leg tests nothing \
         the MSRV leg does not"
    );
}
