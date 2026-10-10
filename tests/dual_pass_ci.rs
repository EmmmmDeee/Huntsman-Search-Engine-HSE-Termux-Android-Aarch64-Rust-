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
