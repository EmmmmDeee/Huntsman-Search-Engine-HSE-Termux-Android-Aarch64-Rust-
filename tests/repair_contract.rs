use std::fs;

const GATE: &str = "xtask/src/gate.rs";

#[test]
fn repair_protocol_is_executable_and_pins_required_gates() {
    // The gate is Rust, in the xtask crate. Its behaviour (usage, refusals) is tested in
    // xtask/tests/gate.rs; this pins the commands and checks it must run.
    let gate = fs::read_to_string(GATE).expect("repair gate");
    for required in [
        "\"fmt\", \"--check\"",
        "\"clippy\"",
        "\"clippy::unwrap_used\"",
        "\"-p\", \"huntsman-recon\", \"--lib\", \"--bins\"",
        "\"-p\", \"xtask\", \"--bins\"",
        "\"--workspace\",",
        "\"--all-targets\",",
        "\"warnings\"",
        "\"test\", \"--locked\", \"--workspace\"",
        "\"run\", \"--locked\", \"--\", \"check\"",
        "fn snapshot(",
        "REPAIR_GATE_TIMEOUT_SECONDS",
        "\"diff\", \"--binary\", \"--no-ext-diff\", \"HEAD\", \"--\"",
        "\"ls-files\", \"--others\", \"--exclude-standard\", \"-z\"",
        "\"*.sh\"",
        "\"sh\", &[\"-n\"",
        "\"--test\", test",
        "\"functional_code_contract\"",
        "\"directive_lock\"",
        "\"deployment_targets\"",
        "\"repair_contract\"",
        "verification mutated tracked or untracked repository content",
        "necessary but not sufficient for platform-specific changes",
    ] {
        assert!(
            gate.contains(required),
            "repair gate must contain {required:?}"
        );
    }
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
        "cargo gate full",
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
