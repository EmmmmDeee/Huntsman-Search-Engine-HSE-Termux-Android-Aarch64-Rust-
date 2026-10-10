//! Contract for the dual-pass runner. It does not call a model. The plan job is given no
//! credential, because the Rust it runs can read its process's environment. The gate job
//! holds the read token and finishes before the plan starts. The publish job holds the
//! write token and applies only what the plan job wrote, after the path policy has
//! checked it. The red classification runs on fixture logs, so its verdicts are tested.

use std::fs;
use std::process::Command;

const WORKFLOW: &str = ".github/workflows/dual-pass.yml";
const RED_CLASS: &str = "scripts/dual-pass/red_class.py";
const RED_FIXTURES: &str = "scripts/dual-pass/fixtures/red";

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"))
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

/// True when a line of a script is code, not a comment.
fn code_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().filter(|l| !l.trim_start().starts_with('#'))
}

/// Token, secret, and write-permission references in the text of one job, at job level or
/// step level. Generated Rust reads the environment, so the plan job must contain none.
fn credential_refs(job: &str) -> Vec<&'static str> {
    const NAMED: [&str; 5] = [
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "github.token",
        "secrets.",
        "ISSUE_FIX_TOKEN",
    ];
    const WRITES: [&str; 2] = [": write", "write-all"];
    let mut found: Vec<&'static str> = NAMED
        .into_iter()
        .chain(WRITES)
        .filter(|needle| job.contains(*needle))
        .collect();
    if job.to_ascii_lowercase().contains("token") {
        found.push("token");
    }
    found
}

#[test]
fn dual_pass_workflow_has_no_llm_api() {
    let workflow = read(WORKFLOW);
    assert!(
        !workflow.contains("XAI_API_KEY"),
        "workflow must not require an LLM secret"
    );
    // The egress guard names openai.com in its own grep, so that one line is excluded.
    // Any other line that mentions openai, in any case, is an SDK, a secret, or an endpoint.
    assert!(
        !workflow
            .lines()
            .filter(|line| !line.contains("openai\\.com"))
            .any(|line| line.to_ascii_lowercase().contains("openai")),
        "workflow must not install, read, or call an OpenAI SDK, key, or endpoint"
    );
    for required in [
        "types: [labeled]",
        "github.event.label.name == 'dual-pass'",
        "bash scripts/dual-pass/run.sh",
        "bash \"$RUNNER_TEMP/trusted-dual-pass/publish.sh\"",
        "toolchain: 1.87.0",
        "tree-sitter",
    ] {
        assert!(workflow.contains(required), "missing {required}");
    }
    let runner = read("scripts/dual-pass/run.sh");
    assert!(
        !runner.contains("api.x.ai"),
        "runner must not call an LLM API"
    );
    assert!(
        !runner.contains("XAI_API_KEY"),
        "runner must not read an LLM secret"
    );
    for required in [
        "execution-plan.json",
        "red gate rejected",
        "declared patch budget exhausted",
        "needs-human-review",
        "tests/generated_",
        "restore_protected",
        "MAX_TURNS=3",
        "No LLM API",
    ] {
        assert!(runner.contains(required), "runner missing {required}");
    }
    let publish = read("scripts/dual-pass/publish.sh");
    for required in ["gh pr create", "needs-human-review", "push_branch()"] {
        assert!(publish.contains(required), "publish missing {required}");
    }
    let apply = read("scripts/dual-pass/apply_change.py");
    assert!(apply.contains("git apply"));
    assert!(apply.contains("tree_sitter"));
}

#[test]
fn plan_job_holds_no_credential_and_runs_generated_code_without_one() {
    let wf = read(WORKFLOW);
    let plan = job(&wf, "plan");
    let refs = credential_refs(&plan);
    assert!(
        refs.is_empty(),
        "the plan job runs generated Rust and must hold no token, secret, or write permission, at job or step level; found {refs:?}"
    );
    assert!(
        plan.contains("needs: gate"),
        "plan must wait for the gate job, which holds the read token"
    );
    assert!(
        plan.contains("persist-credentials: false"),
        "the plan checkout must not persist credentials"
    );
    let fetch = plan
        .find("actions/download-artifact")
        .expect("plan receives the issue body from the gate job");
    let toolchain = plan
        .find("dtolnay/rust-toolchain")
        .expect("plan toolchain step");
    let run = plan.find("Plan, then red and green").expect("run step");
    assert!(
        fetch < toolchain && toolchain < run,
        "the issue body is received, then the toolchain is set up, then the runner runs"
    );
}

#[test]
fn a_job_level_token_added_to_the_plan_job_is_refused() {
    let wf = read(WORKFLOW);
    let plan = job(&wf, "plan");
    let job_env = "\n    env:\n";
    assert!(
        plan.contains(job_env),
        "the plan job has a job-level env block to tamper with"
    );
    let tampered = plan.replacen(
        job_env,
        "\n    env:\n      GH_TOKEN: ${{ github.token }}\n",
        1,
    );
    let refs = credential_refs(&tampered);
    assert!(
        refs.contains(&"GH_TOKEN") && refs.contains(&"github.token"),
        "a job-level GH_TOKEN added to the plan job must be caught, found {refs:?}"
    );
}

#[test]
fn the_gate_job_holds_the_read_token_and_no_write_permission() {
    let wf = read(WORKFLOW);
    let gate = job(&wf, "gate");
    assert!(
        gate.contains("GH_TOKEN: ${{ github.token }}"),
        "the gate job reads the issue with the workflow token"
    );
    assert!(
        !gate.contains(": write") && !gate.contains("write-all"),
        "the gate job must not hold a write permission"
    );
    assert!(
        step(&wf, "Require a plan written by the owner or a member").contains("gh api"),
        "the author check runs in the gate job"
    );
}

#[test]
fn plan_job_accepts_only_plans_written_by_the_owner_or_a_member() {
    let wf = read(WORKFLOW);
    let gate = step(&wf, "Require a plan written by the owner or a member");
    assert!(
        gate.contains("OWNER|MEMBER)"),
        "the gate must allow OWNER and MEMBER"
    );
    assert!(
        !gate.contains("COLLABORATOR"),
        "COLLABORATOR includes outside collaborators with read access, so the gate must not allow it"
    );
}

#[test]
fn publish_job_runs_only_scripts_copied_before_the_plan_output_arrived() {
    let wf = read(WORKFLOW);
    let publish = job(&wf, "publish");
    assert!(
        publish.contains("needs: plan"),
        "publish waits for the plan"
    );
    assert!(
        publish.contains("contents: write") && publish.contains("pull-requests: write"),
        "publish must hold the write permissions it needs"
    );
    let copy = publish
        .find("Keep copies of the scripts publish runs")
        .expect("publish copies its scripts");
    let download = publish
        .find("actions/download-artifact")
        .expect("publish downloads the plan output");
    let run = publish
        .find("Publish the change")
        .expect("publish has its publish step");
    assert!(
        copy < download && download < run,
        "the scripts are copied, then the plan output is downloaded, then publish runs"
    );
    assert!(
        !publish.contains("bash scripts/dual-pass/publish.sh"),
        "publish must not run the script from the checkout, which the plan output can change"
    );
}

#[test]
fn only_publish_takes_the_write_token_and_the_plan_stage_never_pushes() {
    let runner = read("scripts/dual-pass/run.sh");
    assert!(
        !runner.contains("GH_TOKEN"),
        "the plan stage must not read the token"
    );
    for forbidden in ["git push", "gh issue", "gh pr", "gh label"] {
        assert!(
            !runner.contains(forbidden),
            "the plan stage must not run `{forbidden}`"
        );
    }
    let publish = read("scripts/dual-pass/publish.sh");
    assert!(
        publish.contains("remote_git() {")
            && publish.contains("http.https://github.com/.extraheader=AUTHORIZATION: basic"),
        "publish must push through a helper that passes the token in a header"
    );
    assert!(
        !code_lines(&publish).any(|l| {
            let words: Vec<&str> = l.split_whitespace().collect();
            words.windows(2).any(|pair| pair == ["git", "push"])
        }),
        "publish must not push with the checkout's credentials"
    );
    assert!(
        publish.contains("--force-with-lease=refs/heads/$branch:$tip"),
        "publish must replace its own branch only under a lease on the tip it saw"
    );
}

#[test]
fn every_python_call_in_the_plan_stage_runs_in_isolated_mode() {
    let runner = read("scripts/dual-pass/run.sh");
    assert_eq!(
        runner.matches("python3 ").count(),
        runner.matches("python3 -I").count(),
        "a generated test can write a module into the working directory, and python3 without -I imports it"
    );
    let plan = read("scripts/dual-pass/plan.py");
    assert!(
        plan.contains("from patchpaths import"),
        "plan imports the path helper by path, so it can run in isolated mode"
    );
}

/// Runs the red classifier on fixture logs, as run.sh does. Returns whether it accepted
/// the run, and the verdict lines it printed.
fn judge_red(logs: &[&str]) -> (bool, String) {
    let mut command = Command::new("python3");
    command.args(["-I", RED_CLASS]);
    for log in logs {
        command.arg(format!("{RED_FIXTURES}/{log}.log"));
    }
    let output = command
        .output()
        .expect("python3 must run the red classifier");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout)
            .trim_end()
            .to_owned(),
    )
}

#[test]
fn a_red_gate_accepts_only_a_missing_symbol_or_a_failed_assertion() {
    // Each log is one failing generated test binary, judged on its own. The verdicts are
    // the classifier's output, line for line.
    let single = [
        ("missing-symbol", "missing-symbol: missing-symbol"),
        ("assertion", "assertion: assertion-failed"),
        (
            "assertion-with-message",
            "assertion-with-message: assertion-failed",
        ),
        (
            "custom-assert",
            "custom-assert: rejected (a panic that is not an assertion: answer must be one)",
        ),
        (
            "unwrap-on-err",
            "unwrap-on-err: rejected (a panic that is not an assertion: called `Result::unwrap()` on an `Err` value: ParseIntError { kind: InvalidDigit })",
        ),
        (
            "err-return",
            "err-return: rejected (the test failed without an assertion panic)",
        ),
        (
            "lone-mismatch",
            "lone-mismatch: rejected (the build failed on an error other than a missing symbol)",
        ),
        (
            "mismatch-and-missing",
            "mismatch-and-missing: rejected (the build failed on an error other than a missing symbol)",
        ),
        (
            "does-not-parse",
            "does-not-parse: rejected (the generated test does not parse)",
        ),
        (
            "missing-symbol-colored",
            "missing-symbol-colored: missing-symbol",
        ),
        ("missing-value", "missing-value: missing-symbol"),
        ("missing-type", "missing-type: missing-symbol"),
    ];
    for (log, verdict) in single {
        let (accepted, printed) = judge_red(&[log]);
        assert_eq!(printed, verdict, "verdict for {log}");
        assert_eq!(
            accepted,
            !verdict.contains("rejected"),
            "exit status for {log}"
        );
    }
    // A run is a valid red only when every binary is one. A lone E0308 next to a valid
    // missing symbol, or next to a valid assertion, refuses the whole run.
    let runs: [(&[&str], bool, &str); 4] = [
        (
            &["missing-symbol", "assertion"],
            true,
            "missing-symbol: missing-symbol\nassertion: assertion-failed",
        ),
        (
            &["missing-symbol-colored", "assertion"],
            true,
            "missing-symbol-colored: missing-symbol\nassertion: assertion-failed",
        ),
        (
            &["lone-mismatch", "missing-symbol"],
            false,
            "lone-mismatch: rejected (the build failed on an error other than a missing symbol)\nmissing-symbol: missing-symbol",
        ),
        (
            &["lone-mismatch", "assertion"],
            false,
            "lone-mismatch: rejected (the build failed on an error other than a missing symbol)\nassertion: assertion-failed",
        ),
    ];
    for (logs, accepted, verdict) in runs {
        let (got, printed) = judge_red(logs);
        assert_eq!(printed, verdict, "verdicts for {logs:?}");
        assert_eq!(got, accepted, "exit status for {logs:?}");
    }
    let runner = read("scripts/dual-pass/run.sh");
    assert!(
        runner.contains("python3 -I scripts/dual-pass/red_class.py"),
        "the runner must judge red with the classifier, not a copy of it"
    );
}
