//! Behaviour of the xtask binary: its usage, its refusals, and the gate's arguments. The gate's
//! own checks run from `gate.rs`, and its fingerprint is tested there.

use std::process::{Command, Output};

fn xtask(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .output()
        .expect("xtask must run")
}

#[test]
fn gate_help_names_the_modes_and_the_platform_limit() {
    let out = xtask(&["gate", "--help"]);
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("fast|msrv|full"), "{text}");
    assert!(text.contains("platform-specific"), "{text}");
}

#[test]
fn gate_refuses_an_unknown_mode_with_the_usage_status() {
    assert_eq!(xtask(&["gate", "invalid-mode"]).status.code(), Some(64));
    assert_eq!(xtask(&["gate", "fast", "extra"]).status.code(), Some(64));
}

#[test]
fn gate_refuses_a_timeout_that_is_not_a_whole_number_of_seconds() {
    for value in ["0", "abc", "-5", "1.5"] {
        let out = Command::new(env!("CARGO_BIN_EXE_xtask"))
            .args(["gate", "fast"])
            .env("REPAIR_GATE_TIMEOUT_SECONDS", value)
            .output()
            .expect("xtask must run");
        assert_eq!(out.status.code(), Some(64), "timeout {value:?}");
    }
}

#[test]
fn xtask_refuses_an_unknown_command() {
    assert_eq!(xtask(&["nope"]).status.code(), Some(64));
}

/// The gate checks the checkout that `cargo run` names in `CARGO_MANIFEST_DIR`, not the one whose
/// path was compiled into the binary. Two checkouts that share a target directory (worktrees, or
/// one `CARGO_TARGET_DIR`) share one `xtask` binary, and cargo does not rebuild it for the second
/// checkout, so the gate run from one checkout checked, and passed, the other. Here cargo names a
/// directory that is not a git checkout: the gate must take that directory's lock and stop on it.
#[test]
fn the_gate_checks_the_checkout_cargo_names_not_the_one_that_built_it() {
    let elsewhere = std::env::temp_dir().join(format!("xtask-elsewhere-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&elsewhere);
    std::fs::create_dir_all(elsewhere.join("xtask")).expect("create a checkout-shaped directory");
    let out = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["gate", "fast"])
        .env("CARGO_MANIFEST_DIR", elsewhere.join("xtask"))
        // Keep git from finding a checkout above the directory, and bound a run that, with the
        // compiled path, would gate this checkout instead.
        .env("GIT_CEILING_DIRECTORIES", std::env::temp_dir())
        .env("REPAIR_GATE_TIMEOUT_SECONDS", "5")
        .output()
        .expect("xtask must run");
    let gated_elsewhere = elsewhere.join("target").join("repair-gate").is_dir();
    let _ = std::fs::remove_dir_all(&elsewhere);
    assert!(
        gated_elsewhere,
        "the gate did not run on the checkout cargo named: {out:?}"
    );
    assert!(
        !out.status.success(),
        "a directory that is not a git checkout cannot pass: {out:?}"
    );
}
