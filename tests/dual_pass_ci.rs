//! Contract for the dual-pass runner. It does not call a model.

use std::fs;

#[test]
fn dual_pass_workflow_has_no_llm_api() {
    let workflow = fs::read_to_string(".github/workflows/dual-pass.yml").expect("workflow");
    assert!(
        !workflow.contains("XAI_API_KEY"),
        "workflow must not require an LLM secret"
    );
    // The workflow's own egress guard names openai.com, so match the endpoint a call would use.
    assert!(
        !workflow.contains("OPENAI_API_KEY"),
        "workflow must not read an OpenAI secret"
    );
    assert!(
        !workflow.contains("api.openai.com"),
        "workflow must not call OpenAI"
    );
    for required in [
        "types: [labeled]",
        "github.event.label.name == 'dual-pass'",
        "bash scripts/dual-pass/run.sh",
        "toolchain: 1.87.0",
        "tree-sitter",
    ] {
        assert!(workflow.contains(required), "missing {required}");
    }
    let runner = fs::read_to_string("scripts/dual-pass/run.sh").expect("runner");
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
        "gh pr create",
        "No LLM API",
    ] {
        assert!(runner.contains(required), "runner missing {required}");
    }
    let apply = fs::read_to_string("scripts/dual-pass/apply_change.py").expect("apply");
    assert!(apply.contains("git apply"));
    assert!(apply.contains("tree_sitter"));
}

/// The plan job runs Rust from an issue body with a write-capable token. Only a
/// collaborator-authored issue may reach it, and the checkout must not persist a
/// credential that generated tests could read from .git/config.
#[test]
fn plan_job_runs_only_collaborator_plans_and_keeps_no_checkout_credential() {
    let workflow = fs::read_to_string(".github/workflows/dual-pass.yml").expect("workflow");
    let plan = workflow
        .split("  plan-and-execute:")
        .nth(1)
        .expect("plan-and-execute job");
    assert!(
        plan.contains("persist-credentials: false"),
        "plan checkout must not persist credentials"
    );
    let gate = plan
        .find("Require a collaborator-authored issue")
        .expect("author gate step");
    let toolchain = plan.find("dtolnay/rust-toolchain").expect("toolchain step");
    assert!(
        gate < toolchain,
        "the author gate must run before any toolchain or code"
    );
    for allowed in ["OWNER", "MEMBER", "COLLABORATOR"] {
        assert!(
            plan[gate..toolchain].contains(allowed),
            "author gate must allow {allowed}"
        );
    }
}

#[test]
fn runner_pushes_with_an_explicit_token_and_never_bare_git_push() {
    let runner = fs::read_to_string("scripts/dual-pass/run.sh").expect("runner");
    assert!(
        runner.contains("git_push() {"),
        "runner must define the explicit-token push helper"
    );
    assert!(
        !runner.contains("\n  git push ") && !runner.contains("\ngit push "),
        "runner must not push with the checkout's credentials"
    );
    assert!(
        runner.contains("git_push -u origin"),
        "runner must push through the helper"
    );
}
