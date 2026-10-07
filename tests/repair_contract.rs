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
        "git diff --exit-code -- var/",
        "scripts/railway-live-acceptance.sh",
        "scripts/railway-entrypoint.sh",
    ] {
        assert!(
            script.contains(required),
            "repair gate must contain {required:?}"
        );
    }

    let status = Command::new("bash")
        .args(["-n", "scripts/repair-gate.sh"])
        .status()
        .expect("bash must execute");
    assert!(status.success(), "repair gate must parse as bash");
}

#[test]
fn repair_protocol_covers_failure_and_regression_semantics() {
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
        "bash scripts/railway-live-acceptance.sh",
    ] {
        assert!(
            doc.contains(required),
            "repair protocol must contain {required:?}"
        );
    }
}
