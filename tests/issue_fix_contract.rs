//! Contract for the issue-fix workflow. The model key reaches one step, in one job.
//! Only the publish job holds a write token, and it runs only scripts copied before
//! the patch arrived. The jobs that run model-written code hold no write permission.
//! Checkouts keep their credentials out of the repository, and every remote action is
//! pinned to a full commit SHA. The offline self-check of the scripts must pass.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

const WORKFLOW: &str = ".github/workflows/issue-fix.yml";
const SCRIPTS: [&str; 8] = [
    "scripts/issue-fix/instructions.md",
    "scripts/issue-fix/build-prompt.sh",
    "scripts/issue-fix/check-protected.sh",
    "scripts/issue-fix/capture.sh",
    "scripts/issue-fix/redact.sh",
    "scripts/issue-fix/publish.sh",
    "scripts/issue-fix/report.sh",
    "scripts/issue-fix/self-check.sh",
];

fn workflow() -> String {
    fs::read_to_string(WORKFLOW).expect("the issue-fix workflow must exist at the repository root")
}

/// A job header is a line indented by exactly two spaces that ends with a colon.
fn is_job_header(line: &str) -> bool {
    line.starts_with("  ") && !line.starts_with("   ") && line.ends_with(':')
}

/// The text of one job, from its header to the next job header.
fn job(wf: &str, name: &str) -> String {
    let header = format!("  {name}:");
    let mut lines = wf.lines().skip_while(|l| *l != header);
    let first = lines
        .next()
        .unwrap_or_else(|| panic!("job {name:?} must exist in {WORKFLOW}"));
    let body: Vec<&str> = lines.take_while(|l| !is_job_header(l)).collect();
    format!("{first}\n{}", body.join("\n"))
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

/// The names of the steps in a job's text that contain NEEDLE, in order.
fn steps_containing(job_text: &str, needle: &str) -> Vec<String> {
    job_text
        .split("\n      - ")
        .filter(|block| block.contains(needle))
        .map(|block| {
            let first = block.lines().next().unwrap_or("").trim();
            first.strip_prefix("name: ").unwrap_or(first).to_owned()
        })
        .collect()
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
        !model.contains("GH_TOKEN")
            && !model.contains("github.token")
            && !model.contains("GITHUB_TOKEN"),
        "the model step must not see the workflow token"
    );
    assert_eq!(
        model.matches("secrets.").count(),
        1,
        "the model step reads one secret, the model key"
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
fn the_fix_job_carries_no_token_at_job_level() {
    let wf = workflow();
    let fix = job(&wf, "fix");
    let header = fix
        .split("\n    steps:")
        .next()
        .expect("the fix job has a steps list");
    assert!(
        !header.contains("github.token") && !header.contains("secrets."),
        "job-level env is inherited by the model step, so it must hold no token or secret"
    );
}

#[test]
fn the_model_key_reaches_only_the_model_step_and_its_check_in_the_fix_job() {
    let wf = workflow();
    assert_eq!(
        steps_containing(&job(&wf, "fix"), "ANTHROPIC_API_KEY"),
        [
            "Require the model key",
            "Run the model under the tool allowlist"
        ],
    );
    for other in ["gate", "publish", "report"] {
        assert!(
            !job(&wf, other).contains("ANTHROPIC_API_KEY"),
            "the {other} job must not see the model key"
        );
    }
}

#[test]
fn only_publish_and_report_can_write_and_only_publish_holds_the_token() {
    let wf = workflow();
    for untrusted in ["fix", "gate"] {
        let text = job(&wf, untrusted);
        assert!(
            !text.contains(": write"),
            "the {untrusted} job runs model-written code and must hold no write permission"
        );
        assert!(
            !text.contains("ISSUE_FIX_TOKEN"),
            "the {untrusted} job must not read the publish token"
        );
    }
    let publish = job(&wf, "publish");
    assert!(
        publish.contains("contents: write") && publish.contains("pull-requests: write"),
        "publish must hold the write permissions it needs"
    );
    assert!(
        !job(&wf, "report").contains("contents: write"),
        "report comments on an issue and does not need to write contents"
    );
    assert!(
        wf.contains("permissions: {}"),
        "the workflow default must grant no permission"
    );
}

#[test]
fn publish_runs_only_scripts_copied_before_the_patch_arrived() {
    let wf = workflow();
    let publish = job(&wf, "publish");
    let copy = publish
        .find("Keep a copy of the publish scripts")
        .expect("publish must copy its scripts");
    let download = publish
        .find("actions/download-artifact")
        .expect("publish must download the change");
    let run = publish
        .find("Publish the pull request")
        .expect("publish must have its publish step");
    assert!(
        copy < download && download < run,
        "the scripts are copied, then the patch is downloaded, then publish runs"
    );
    assert!(publish.contains("bash \"$RUNNER_TEMP/trusted-scripts/publish.sh\""));
    assert!(
        !publish.contains("scripts/issue-fix/publish.sh"),
        "publish must not run the script from the checkout, which the patch can change"
    );
}

#[test]
fn fix_runs_the_policy_and_the_capture_from_a_copy_made_before_the_model() {
    let wf = workflow();
    let fix = job(&wf, "fix");
    let copy = fix
        .find("Keep a copy of the policy scripts")
        .expect("fix must copy the policy scripts");
    let model = fix
        .find("Run the model under the tool allowlist")
        .expect("fix must run the model");
    assert!(copy < model, "the copy must be made before the model runs");
    for script in ["check-protected.sh", "capture.sh", "redact.sh"] {
        assert!(
            fix.contains(&format!("issue-fix-scripts/{script}")),
            "{script} must run from the copy"
        );
        assert!(
            !fix.contains(&format!("bash scripts/issue-fix/{script}")),
            "{script} must not run from the workspace, which the model can change"
        );
    }
}

#[test]
fn the_gate_applies_the_patch_and_holds_no_secret() {
    let wf = workflow();
    let gate = job(&wf, "gate");
    assert!(gate.contains("git apply --index \"$RUNNER_TEMP/change/change.patch\""));
    assert!(gate.contains("bash scripts/repair-gate.sh full"));
    assert!(
        !gate.contains("secrets."),
        "the gate job must hold no secret"
    );
}

#[test]
fn publish_takes_the_issue_from_the_trigger_not_from_the_artifact() {
    let wf = workflow();
    let publish = job(&wf, "publish");
    assert!(publish.contains("ISSUE: ${{ github.event.issue.number || inputs.issue }}"));
    assert!(publish.contains("gh issue view \"$ISSUE\""));
    assert!(
        !publish.contains("change/issue.json"),
        "the issue data must not come from the untrusted artifact"
    );
}

#[test]
fn every_job_checks_the_issue_number_before_using_it() {
    let wf = workflow();
    for name in ["fix", "publish", "report"] {
        assert!(
            job(&wf, name).contains("^[0-9]+$"),
            "the {name} job must check that the issue number is numeric"
        );
    }
}

#[test]
fn every_checkout_keeps_its_credentials_out_of_the_repository() {
    let wf = workflow();
    let checkouts = wf.matches("actions/checkout@").count();
    assert!(checkouts >= 4, "expected a checkout in each job");
    assert_eq!(
        wf.matches("persist-credentials: false").count(),
        checkouts,
        "every checkout must set persist-credentials: false"
    );
}

#[test]
fn nothing_in_the_issue_fix_automation_merges_a_pull_request() {
    let mut texts = vec![workflow()];
    for script in SCRIPTS {
        texts.push(fs::read_to_string(script).expect("issue-fix script"));
    }
    for text in texts {
        for banned in [
            "pr merge",
            "--auto",
            "enable-auto-merge",
            "merge_pull_request",
        ] {
            assert!(
                !text.contains(banned),
                "the issue-fix automation must not merge: found {banned}"
            );
        }
    }
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
        remote >= 8,
        "expected the checkout, toolchain, artifact, and download actions in their jobs"
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
fn the_repair_gate_checks_the_syntax_of_every_issue_fix_script() {
    let gate = fs::read_to_string("scripts/repair-gate.sh").expect("the repair gate");
    assert!(
        gate.contains("for script in scripts/issue-fix/*.sh"),
        "the repair gate must run bash -n on the issue-fix scripts"
    );
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
