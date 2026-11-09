//! Regression contract for the read-only completion workflow.
//!
//! The completion job generates a source-addressed handoff, not a release. These checks reject
//! accidental credential persistence, unpinned actions, skipped validation or source mutation.

use std::fs;

const WORKFLOW: &str = ".github/workflows/completion.yml";

fn verify_completion_contract(workflow: &str) -> Result<(), String> {
    for required in [
        "  push:\n    branches: [main]\n  pull_request:",
        "  workflow_dispatch:",
        "  schedule:",
        "permissions:\n  contents: read\n",
        "persist-credentials: false",
        "if-no-files-found: error",
    ] {
        if !workflow.contains(required) {
            return Err(format!("completion workflow missing required control: {required}"));
        }
    }

    if workflow
        .lines()
        .filter(|line| line.trim_start().starts_with("permissions:"))
        .count()
        != 1
    {
        return Err("completion workflow must have only one top-level permissions block".into());
    }
    for forbidden in [
        ": write",
        "    paths:",
        "    paths-ignore:",
        "persist-credentials: true",
        "continue-on-error: true",
        "|| true",
        "git push",
        "git commit",
        "git tag",
        "gh pr ",
        "gh api ",
    ] {
        if workflow.contains(forbidden) {
            return Err(format!("completion workflow contains forbidden operation: {forbidden}"));
        }
    }

    let actions: Vec<&str> = workflow
        .lines()
        .filter_map(|line| {
            line.trim_start()
                .strip_prefix("- uses: ")
                .or_else(|| line.trim_start().strip_prefix("uses: "))
        })
        .collect();
    if actions.len() != 3 {
        return Err("completion workflow must use only its three reviewed actions".into());
    }
    for action in actions {
        let (_, revision) = action
            .split_once('@')
            .ok_or_else(|| format!("action lacks revision: {action}"))?;
        let sha = revision.split_whitespace().next().unwrap_or_default();
        if sha.len() != 40 || !sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!("action is not pinned by a full commit SHA: {action}"));
        }
    }

    let steps = [
        "cargo fmt --all -- --check",
        "cargo test --locked -p xtask",
        "cargo test --locked --test completion_ci --test ci_toolchains",
        "cargo run --locked -p xtask -- completion write",
        "cargo run --locked -p xtask -- completion check",
        "cargo run --locked -p xtask -- roadmap check",
        "sha256sum -c HUNTSMAN_IMPLEMENTATION_MAP.sha256",
        "sha256sum -c IMPLEMENTATION_REGISTER.md.sha256",
        "uses: actions/upload-artifact@",
    ];
    let mut previous_end = 0;
    for step in steps {
        let start = workflow
            .find(step)
            .ok_or_else(|| format!("completion workflow missing step: {step}"))?;
        if start < previous_end {
            return Err(format!("completion workflow reorders validation: {step}"));
        }
        previous_end = start + step.len();
    }
    Ok(())
}

#[test]
fn completion_workflow_preserves_read_only_verification_before_publication() {
    let text = fs::read_to_string(WORKFLOW).expect("completion workflow");
    verify_completion_contract(&text).expect("completion CI contract");
}

#[test]
fn completion_workflow_guard_rejects_unsafe_mutations() {
    let original = fs::read_to_string(WORKFLOW).expect("completion workflow");
    verify_completion_contract(&original).expect("baseline workflow");
    for (old, new) in [
        ("permissions:\n  contents: read", "permissions:\n  contents: write"),
        ("persist-credentials: false", "persist-credentials: true"),
        ("cargo fmt --all -- --check", "echo formatting skipped"),
        ("cargo test --locked -p xtask", "echo tests skipped"),
        (
            "cargo test --locked --test completion_ci --test ci_toolchains",
            "echo completion CI safety checks skipped",
        ),
        (
            "cargo run --locked -p xtask -- completion check",
            "echo completion validation skipped",
        ),
        (
            "sha256sum -c HUNTSMAN_IMPLEMENTATION_MAP.sha256",
            "sha256sum HUNTSMAN_IMPLEMENTATION_MAP.sha256",
        ),
        ("  pull_request:", "  pull_request:\n    paths:\n      - 'docs/**'"),
        (
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/checkout@v7",
        ),
    ] {
        assert!(original.contains(old), "missing mutation fixture: {old}");
        let mutated = original.replacen(old, new, 1);
        assert!(
            verify_completion_contract(&mutated).is_err(),
            "unsafe mutation escaped completion CI guard: {old}"
        );
    }
    let unsafe_workflow = format!("{original}\n      - run: gh pr create --fill\n");
    assert!(verify_completion_contract(&unsafe_workflow).is_err());
}
