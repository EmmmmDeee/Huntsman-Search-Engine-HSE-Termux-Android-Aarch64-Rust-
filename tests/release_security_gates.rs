//! Release publication must be gated on the independent exact-main RustSec and
//! CodeQL workflows, not only on Rust CI. These are source-level contracts;
//! live GitHub Actions verification remains a separate acceptance requirement.

use std::fs;

const RELEASE: &str = ".github/workflows/release.yml";
const AUDIT: &str = ".github/workflows/audit.yml";
const CODEQL: &str = ".github/workflows/codeql.yml";

fn check_release_gate(workflow: &str) -> Result<(), &'static str> {
    let ci = workflow
        .find("      - name: Require successful exact-main CI before publishing")
        .ok_or("missing CI gate")?;
    let security = workflow
        .find("      - name: Require successful exact-main RustSec and CodeQL before publishing")
        .ok_or("missing security gate")?;
    let download = workflow
        .find("      - name: Download staged release files")
        .ok_or("missing artifact download")?;
    let publication = workflow
        .find("      - name: Publish pre-release")
        .ok_or("missing publication")?;
    if !(ci < security && security < download && download < publication) {
        return Err("security gate must precede download and publication");
    }

    let step = &workflow[security..download];
    for required in [
        "GH_TOKEN: ${{ github.token }}",
        "timeout-minutes: 65",
        "set -euo pipefail",
        "workflows=(audit.yml codeql.yml)",
        "for attempt in $(seq 1 120)",
        "for workflow in \"${workflows[@]}\"",
        "actions/workflows/${workflow}/runs",
        "-f head_sha=\"$GITHUB_SHA\" -f event=push",
        "select(.head_sha == $sha and .event == \"push\")",
        "sort_by(.created_at, .run_attempt) | last",
        "if . == null then \"missing\"",
        "completed:success)",
        "completed:*)",
        "exit 1",
        "if [ \"$pending\" -eq 0 ]; then",
        "if [ \"$attempt\" -eq 120 ]; then",
        "sleep 30",
    ] {
        if !step.contains(required) {
            return Err("security gate missing required fail-closed control");
        }
    }
    if step.contains("|| true") || step.contains("continue-on-error: true") {
        return Err("security gate must not swallow failures");
    }
    Ok(())
}

#[test]
fn release_requires_exact_main_rustsec_and_codeql_before_publication() {
    let workflow = fs::read_to_string(RELEASE).expect("release workflow");
    check_release_gate(&workflow).expect("release publication gate contract");
    for path in [AUDIT, CODEQL] {
        let source = fs::read_to_string(path).expect("independent workflow");
        assert!(
            source.contains("  push:\n    branches: [main]"),
            "{path} must run for every main push"
        );
        assert!(
            !source.contains("    paths:"),
            "{path} must not skip source-only main pushes"
        );
    }
}

#[test]
fn release_gate_rejects_missing_bypassed_and_reordered_checks() {
    let workflow = fs::read_to_string(RELEASE).expect("release workflow");
    assert!(check_release_gate(&workflow).is_ok());

    for (needle, replacement) in [
        ("workflows=(audit.yml codeql.yml)", "workflows=(audit.yml)"),
        ("workflows=(audit.yml codeql.yml)", "workflows=(codeql.yml)"),
        ("-f head_sha=\"$GITHUB_SHA\" -f event=push", "-f event=push"),
        ("completed:*)", "completed:failure)"),
        ("if . == null then \"missing\"", "if . == null then \"completed:success\""),
        ("if [ \"$attempt\" -eq 120 ]; then", "if false; then"),
    ] {
        let start = workflow
            .find("      - name: Require successful exact-main RustSec and CodeQL before publishing")
            .expect("security gate");
        let mutated = format!(
            "{}{}",
            &workflow[..start],
            workflow[start..].replacen(needle, replacement, 1)
        );
        assert_ne!(mutated, workflow, "mutation fixture must change source");
        assert!(
            check_release_gate(&mutated).is_err(),
            "unsafe release gate mutation escaped detection: {needle}"
        );
    }

    let bypassed = workflow.replacen(
        "workflows=(audit.yml codeql.yml)",
        "workflows=(audit.yml codeql.yml) # || true",
        1,
    );
    assert!(check_release_gate(&bypassed).is_err());
}
