//! CLI seed-validation guards: `hse scan` / `hse live` must reject reserved /
//! placeholder targets at the boundary, so an "example anything" can never be
//! dispatched against every module. Spawns the real binary (the faithful test
//! of the wiring — a unit test on `Target::validate` can't catch a missing call
//! site, which is exactly the gap this guards).

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_hse");

/// Run `hse <args>` with logging off; return (success, stderr).
fn run(args: &[&str]) -> (bool, String) {
    let out = Command::new(BIN)
        .args(args)
        .env("RUST_LOG", "off")
        .output()
        .expect("spawn hse");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn scan_rejects_placeholder_domain() {
    let (ok, err) = run(&["scan", "--kind", "domain", "--value", "example.com"]);
    assert!(!ok, "example.com must be rejected, not scanned");
    assert!(
        err.contains("reserved/placeholder") || err.contains("invalid target"),
        "expected a placeholder-rejection message, got: {err}"
    );
}

#[test]
fn scan_rejects_placeholder_email_host() {
    let (ok, err) = run(&["scan", "--kind", "email", "--value", "jordan@example.com"]);
    assert!(!ok, "jordan@example.com must be rejected");
    assert!(
        err.contains("reserved/placeholder") || err.contains("invalid target"),
        "{err}"
    );
}

#[test]
fn live_rejects_placeholder_domain() {
    let (ok, err) = run(&["live", "--kind", "domain", "--value", "test.example"]);
    assert!(!ok, "test.example must be rejected");
    assert!(
        err.contains("reserved/placeholder") || err.contains("invalid target"),
        "{err}"
    );
}
