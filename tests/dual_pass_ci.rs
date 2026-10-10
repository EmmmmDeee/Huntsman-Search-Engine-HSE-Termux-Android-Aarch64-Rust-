//! Contract for the dual-pass runner. It does not call a model. The plan job holds no
//! credential, because the Rust it runs can read its process's environment. The publish
//! job holds the write token and applies only what the plan job wrote, after the path
//! policy has checked it.

use std::fs;

const WORKFLOW: &str = ".github/workflows/dual-pass.yml";

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
    for write in ["contents: write", "issues: write", "pull-requests: write"] {
        assert!(
            !plan.contains(write),
            "the plan job runs generated Rust and must not hold {write}"
        );
    }
    assert!(
        plan.contains("persist-credentials: false"),
        "the plan checkout must not persist credentials"
    );
    let run = step(&wf, "Plan, then red and green, with no credential");
    assert!(
        !run.contains("GH_TOKEN") && !run.contains("github.token") && !run.contains("secrets."),
        "the step that runs generated Rust must hold no credential"
    );
    let toolchain = plan
        .find("dtolnay/rust-toolchain")
        .expect("plan toolchain step");
    let gate = plan
        .find("Require a plan written by the owner or a member")
        .expect("author gate step");
    let fetch = plan.find("Fetch the issue body").expect("issue fetch step");
    assert!(
        gate < toolchain && fetch < toolchain,
        "the token-holding steps run, and exit, before any toolchain or code"
    );
    assert!(
        plan.find("Plan, then red and green").expect("run step") > toolchain,
        "the runner runs after the toolchain is set up"
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

#[test]
fn a_red_gate_accepts_only_a_missing_symbol_or_a_failed_assertion() {
    let runner = read("scripts/dual-pass/run.sh");
    assert!(
        runner.contains("red_class=\"rejected\""),
        "the red classification must default to rejected"
    );
    assert!(
        runner.contains("neither failed an assertion nor referenced a missing symbol"),
        "a red result that is neither must be refused"
    );
}
