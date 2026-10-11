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
