//! The advisory audit workflow reports vulnerabilities in the locked dependency graph. It must stay
//! read-only, pin each action by full commit SHA, run on a schedule and on dependency changes, and
//! fail only on vulnerabilities. These checks keep an edit from weakening any of those properties.

use std::fs;

const AUDIT: &str = ".github/workflows/audit.yml";

fn audit_workflow() -> String {
    fs::read_to_string(AUDIT).expect("audit workflow")
}

#[test]
fn audit_workflow_is_read_only_and_keeps_no_checkout_credentials() {
    let audit = audit_workflow();
    assert!(
        audit.contains("permissions:\n  contents: read\n"),
        "{AUDIT} must grant only `contents: read` at the top level"
    );
    assert!(
        !audit.contains(": write"),
        "{AUDIT} must not request any write scope"
    );
    assert!(
        audit.contains("persist-credentials: false"),
        "{AUDIT} must check out without persisted credentials"
    );
}

#[test]
fn audit_workflow_pins_its_two_actions_by_full_commit_sha() {
    let audit = audit_workflow();
    for pinned in [
        "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
        "uses: dtolnay/rust-toolchain@e97e2d8cc328f1b50210efc529dca0028893a2d9 # stable",
    ] {
        assert!(audit.contains(pinned), "{AUDIT} must contain {pinned:?}");
    }
    assert_eq!(
        audit.matches("uses:").count(),
        2,
        "{AUDIT} must use no action beyond the two pinned above"
    );
}

#[test]
fn audit_step_is_advisory_and_installs_a_pinned_cargo_audit() {
    let audit = audit_workflow();
    assert!(
        audit.contains("cargo install cargo-audit --locked --version =0.22.2"),
        "{AUDIT} must install the verified cargo-audit release"
    );
    assert!(
        audit.contains("run: cargo audit"),
        "{AUDIT} must run cargo audit"
    );
    assert!(
        !audit.contains("--deny"),
        "{AUDIT} must not pass --deny: it would fail on unmaintained, unsound or yanked crates"
    );
}

#[test]
fn audit_runs_on_schedule_dispatch_and_dependency_changes_only() {
    let audit = audit_workflow();
    for trigger in [
        "schedule:",
        "cron: \"0 6 * * 1\"",
        "workflow_dispatch:",
        "push:",
        "\"**/Cargo.toml\"",
        "\"**/Cargo.lock\"",
        "\".github/workflows/audit.yml\"",
    ] {
        assert!(audit.contains(trigger), "{AUDIT} must contain {trigger}");
    }
    assert!(
        !audit.contains("pull_request"),
        "{AUDIT} must not run on pull requests, so it cannot gate one"
    );
}
