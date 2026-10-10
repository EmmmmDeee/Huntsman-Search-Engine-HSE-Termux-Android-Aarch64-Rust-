//! Contract for the issue-fix workflow. The model step must run bare, with a pinned
//! CLI, a spend cap, and a tool allowlist, and it must never see the workflow token.
//! The workflow must never merge. The offline self-check of its scripts must pass.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

const WORKFLOW: &str = ".github/workflows/issue-fix.yml";
const SCRIPTS: [&str; 6] = [
    "scripts/issue-fix/instructions.md",
    "scripts/issue-fix/build-prompt.sh",
    "scripts/issue-fix/check-protected.sh",
    "scripts/issue-fix/publish.sh",
    "scripts/issue-fix/report.sh",
    "scripts/issue-fix/self-check.sh",
];

fn workflow() -> String {
    fs::read_to_string(WORKFLOW).expect("the issue-fix workflow must exist at the repository root")
}

/// The text of the named step: from its `- name:` line to the next step.
fn step(wf: &str, name: &str) -> String {
    let header = format!("      - name: {name}");
    let mut lines = wf.lines().skip_while(|l| *l != header);
    let first = lines
        .next()
        .unwrap_or_else(|| panic!("step {name:?} must exist in {WORKFLOW}"));
    let body: Vec<&str> = lines.take_while(|l| !l.starts_with("      - ")).collect();
    format!("{first}\n{}", body.join("\n"))
}

fn is_full_sha(text: &str) -> bool {
    text.len() == 40 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

#[test]
fn model_step_runs_bare_pinned_capped_and_without_the_workflow_token() {
    let wf = workflow();
    let model = step(&wf, "Run the model under the tool allowlist");
    for flag in [
        "--bare",
        "--permission-prompts none",
        "--permission-mode acceptEdits",
        "--max-budget-usd",
        "--output-format json",
    ] {
        assert!(model.contains(flag), "model step must pass {flag}");
    }
    for denied in ["\"Bash(gh *)\"", "\"Bash(git push *)\"", "\"Bash(env)\""] {
        assert!(model.contains(denied), "model step must deny {denied}");
    }
    assert!(
        !model.contains("GH_TOKEN") && !model.contains("github.token"),
        "the model step must not see the workflow token"
    );
    assert!(
        !model.contains("--max-turns"),
        "this CLI version has no --max-turns; the spend cap is --max-budget-usd"
    );
    assert!(
        wf.contains("CLAUDE_CODE_VERSION: \"2.1.283\""),
        "the Claude Code CLI must be pinned to an exact version"
    );
    assert!(
        wf.contains("npm install -g \"@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}\""),
        "the CLI install must use the pinned version"
    );
}

#[test]
fn workflow_never_merges_and_keeps_the_model_key_out_of_publish() {
    let wf = workflow();
    assert!(
        !wf.contains("pr merge"),
        "the workflow must not merge pull requests"
    );
    assert!(
        !wf.contains("--auto"),
        "the workflow must not enable auto-merge"
    );
    let publish = step(&wf, "Commit, push, and open the pull request");
    assert!(
        !publish.contains("ANTHROPIC_API_KEY"),
        "the publish step must not see the model key"
    );
}

#[test]
fn every_remote_action_is_pinned_to_a_full_commit_sha() {
    let wf = workflow();
    let mut remote = 0;
    for line in wf
        .lines()
        .filter(|l| l.trim_start().starts_with("- uses: ") || l.trim_start().starts_with("uses: "))
    {
        let spec = line.split("uses: ").nth(1).expect("uses line");
        if spec.starts_with("./") {
            continue;
        }
        remote += 1;
        let (_, rest) = spec.split_once('@').expect("action must have a ref");
        let sha = rest.split_whitespace().next().unwrap_or("");
        assert!(
            is_full_sha(sha),
            "action ref must be a full commit SHA: {spec}"
        );
    }
    assert!(
        remote >= 3,
        "expected the checkout, toolchain, and upload actions"
    );
}

#[test]
fn issue_fix_scripts_exist_and_are_executable() {
    for script in SCRIPTS {
        let path = Path::new(script);
        let meta = fs::metadata(path).unwrap_or_else(|e| panic!("{script}: {e}"));
        if path.extension().and_then(|ext| ext.to_str()) == Some("sh") {
            assert!(
                meta.permissions().mode() & 0o111 != 0,
                "{script} must be executable"
            );
        }
    }
}

#[test]
fn offline_self_check_of_the_issue_fix_scripts_passes() {
    let out = Command::new("bash")
        .arg("scripts/issue-fix/self-check.sh")
        .output()
        .expect("bash must run the issue-fix self-check");
    assert!(
        out.status.success(),
        "issue-fix self-check failed:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
