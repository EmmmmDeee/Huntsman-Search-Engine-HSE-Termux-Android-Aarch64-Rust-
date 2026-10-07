use std::fs;

const CI: &str = ".github/workflows/ci.yml";

#[test]
fn main_pushes_must_have_a_merged_pr_association() {
    let ci = fs::read_to_string(CI).expect("CI workflow");
    for required in [
        "main-pr-origin:",
        "if: github.event_name == 'push'",
        "pull-requests: read",
        "commits/${GITHUB_SHA}/pulls",
        ".base.ref == \"main\" and .merged_at != null",
        "reached main without an associated merged pull request",
    ] {
        assert!(ci.contains(required), "{CI} must contain {required:?}");
    }
}

#[test]
fn railway_iac_has_an_executable_ci_gate() {
    let ci = fs::read_to_string(CI).expect("CI workflow");
    for required in [
        "railway-iac:",
        "Railway IaC type validation",
        "actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38 # v6.5.0",
        "node-version: \"22\"",
        "bash scripts/validate-railway-iac.sh",
    ] {
        assert!(ci.contains(required), "{CI} must contain {required:?}");
    }
}
