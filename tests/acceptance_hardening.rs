use std::fs;
use std::process::Command;

const RELEASE: &str = ".github/workflows/release.yml";
const REPAIR_GATE: &str = "xtask/src/gate.rs";

#[test]
fn failed_ci_prereleases_are_machine_quarantined() {
    let raw = fs::read_to_string(".github/unverified-prereleases.json")
        .expect("failed-CI prerelease quarantine manifest");
    let json: serde_json::Value = serde_json::from_str(&raw).expect("valid quarantine JSON");
    let entries = json["entries"].as_array().expect("entries array");
    assert_eq!(
        entries.len(),
        9,
        "the independently revalidated failed-CI prerelease set must remain pinned"
    );
    for entry in entries {
        assert_eq!(entry["ci_conclusion"], "failure");
        assert!(
            entry["tag"]
                .as_str()
                .unwrap_or_default()
                .starts_with("main-"),
            "quarantine entries must be immutable main-channel tags"
        );
        assert!(
            entry["commit"]
                .as_str()
                .is_some_and(|sha| sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit())),
            "quarantine commits must be full hexadecimal SHAs"
        );
    }

    let cleanup = fs::read_to_string("scripts/cleanup-unverified-prereleases.sh")
        .expect("guarded prerelease cleanup script");
    for required in [
        "audit|delete",
        ".github/unverified-prereleases.json",
        "prerelease",
        "ci_run_id",
        "conclusion",
        "gh release delete",
        "--cleanup-tag",
    ] {
        assert!(
            cleanup.contains(required),
            "cleanup script must contain {required:?}"
        );
    }
    let status = Command::new("bash")
        .args(["-n", "scripts/cleanup-unverified-prereleases.sh"])
        .status()
        .expect("bash must execute");
    assert!(status.success(), "cleanup script must parse as bash");
}

#[test]
fn release_is_path_scoped_pr_origin_gated_and_validates_railway_iac() {
    let wf = fs::read_to_string(RELEASE).expect("release workflow");
    for required in [
        "pull-requests: read",
        "Require merged PR origin for main pushes",
        "commits/${GITHUB_SHA}/pulls",
        ".base.ref == \"main\" and .merged_at != null",
        "for attempt in 1 2 3 4 5 6 7 8 9 10",
        "[ \"$attempt\" -eq 10 ] || sleep 3",
        "after bounded retry",
        "\"src/**\"",
        "\"Dockerfile\"",
        "\".railway/**\"",
        "\"xtask/**\"",
        "\"scripts/validate-railway-iac.sh\"",
        "actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38 # v6.5.0",
        "node-version: \"22\"",
        "bash scripts/validate-railway-iac.sh",
    ] {
        assert!(wf.contains(required), "{RELEASE} must contain {required:?}");
    }
}

#[test]
fn railway_iac_validation_and_live_plan_contracts_are_shell_valid() {
    let validate =
        fs::read_to_string("scripts/validate-railway-iac.sh").expect("Railway IaC validator");
    for required in [
        "Node.js 22+ required",
        "railway\": \"3.12.0",
        "typescript\": \"5.9.3",
        "./node_modules/.bin/tsc -p tsconfig.json",
        ".railway/railway.ts",
    ] {
        assert!(
            validate.contains(required),
            "Railway IaC validator must contain {required:?}"
        );
    }
    assert!(
        Command::new("bash")
            .args(["-n", "scripts/validate-railway-iac.sh"])
            .status()
            .expect("bash must execute")
            .success(),
        "Railway IaC validator must parse as bash"
    );

    let plan = fs::read_to_string("scripts/railway-iac-plan.sh").expect("Railway IaC plan wrapper");
    for required in ["railway config plan", "Railway CLI is required"] {
        assert!(
            plan.contains(required),
            "Railway plan wrapper must contain {required:?}"
        );
    }
    assert!(
        Command::new("bash")
            .args(["-n", "scripts/railway-iac-plan.sh"])
            .status()
            .expect("bash must execute")
            .success(),
        "Railway IaC plan wrapper must parse as bash"
    );
}

#[test]
fn repair_gate_covers_every_added_acceptance_script_and_current_termux_harness() {
    let gate = fs::read_to_string(REPAIR_GATE).expect("repair gate");
    for required in ["\"*.sh\"", "\"sh\", &[\"-n\""] {
        assert!(
            gate.contains(required),
            "{REPAIR_GATE} must contain {required:?}"
        );
    }
}
