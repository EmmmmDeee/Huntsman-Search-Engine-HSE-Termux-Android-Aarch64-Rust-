use std::fs;
use std::process::Command;

#[test]
fn repair_protocol_is_executable_and_pins_required_gates() {
    let script = fs::read_to_string("scripts/repair-gate.sh").expect("repair gate");
    for required in [
        "cargo fmt --check",
        "cargo clippy --all-targets --locked -- -D warnings",
        "cargo test --locked",
        "cargo run --locked -- check",
        "repo_fingerprint()",
        "git diff --binary --no-ext-diff HEAD --",
        "git ls-files --others --exclude-standard -z",
        "sha256sum",
        "REPAIR_GATE_TIMEOUT_SECONDS",
        "timeout --signal=TERM --kill-after=10s",
        "scripts/railway-live-acceptance.sh",
        "scripts/railway-entrypoint.sh",
        "--test repair_contract",
        "necessary but not sufficient for platform-specific changes",
    ] {
        assert!(
            script.contains(required),
            "repair gate must contain {required:?}"
        );
    }

    let syntax = Command::new("bash")
        .args(["-n", "scripts/repair-gate.sh"])
        .status()
        .expect("bash must execute");
    assert!(syntax.success(), "repair gate must parse as bash");

    let help = Command::new("bash")
        .args(["scripts/repair-gate.sh", "--help"])
        .output()
        .expect("repair gate help must execute");
    assert!(help.status.success());
    let help_text = String::from_utf8_lossy(&help.stdout);
    assert!(help_text.contains("fast|msrv|full"));
    assert!(help_text.contains("platform-specific"));

    let invalid = Command::new("bash")
        .args(["scripts/repair-gate.sh", "invalid-mode"])
        .status()
        .expect("repair gate invalid mode must execute");
    assert_eq!(invalid.code(), Some(64));
}

#[test]
fn repair_protocol_covers_failure_regression_and_platform_semantics() {
    let doc = fs::read_to_string("docs/REPAIR_PROTOCOL.md").expect("repair protocol");
    for required in [
        "error, bug, broken file, malfunctioning code path",
        "Reproduce",
        "Localize",
        "Diagnose",
        "Repair",
        "Verify",
        "Regression-check",
        "Falsify",
        "Retain or roll back",
        "bash scripts/repair-gate.sh full",
        "Railway/container",
        "Android cross-build",
        "Termux runtime behavior",
        "host gate is necessary, not universally sufficient",
        "bash scripts/railway-live-acceptance.sh",
    ] {
        assert!(
            doc.contains(required),
            "repair protocol must contain {required:?}"
        );
    }
}
