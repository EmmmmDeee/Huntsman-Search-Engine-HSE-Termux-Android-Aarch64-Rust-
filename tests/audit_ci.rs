//! The RustSec audit must run on every PR as a required check, and on dependency-changing
//! pushes, schedules and manual dispatch. It remains read-only, pins actions by SHA,
//! and fails on vulnerabilities in the locked dependency graph.

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
fn audit_step_installs_a_pinned_cargo_audit() {
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
fn audit_runs_on_every_pr_and_scoped_pushes() {
    let audit = audit_workflow();
    for trigger in [
        "schedule:",
        "cron: \"0 6 * * 1\"",
        "workflow_dispatch:",
        "push:",
        "pull_request:",
        "\"**/Cargo.toml\"",
        "\"**/Cargo.lock\"",
        "\".github/workflows/audit.yml\"",
    ] {
        assert!(audit.contains(trigger), "{AUDIT} must contain {trigger}");
    }
    // Every PR must emit the required audit check, even for source-only changes.
    assert!(
        audit.contains("  pull_request:\n  "),
        "pull_request must have no paths filter"
    );
    // Main pushes need only audit dependency and workflow changes.
    for event in ["push:"] {
        let marker = format!("  {event}\n");
        let section = audit
            .split_once(&marker)
            .map(|(_, tail)| {
                tail.lines()
                    .take_while(|line| line.starts_with("    ") || line.trim().is_empty())
                    .collect::<Vec<_>>()
            })
            .expect("event trigger must have a scoped paths section");
        assert!(
            section.iter().any(|line| line.trim() == "paths:"),
            "{event} must declare paths"
        );
        let actual = section
            .iter()
            .filter_map(|line| line.trim().strip_prefix("- "))
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            [
                "\"**/Cargo.toml\"",
                "\"**/Cargo.lock\"",
                "\".github/workflows/audit.yml\"",
            ],
            "{event} must include exactly the audited paths"
        );
    }
}
