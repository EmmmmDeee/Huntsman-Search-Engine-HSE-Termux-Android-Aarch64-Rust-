//! Contract for the dual-pass runner. It does not call a model.

use std::fs;

#[test]
fn dual_pass_workflow_is_issue_scoped_and_red_green() {
    let workflow = fs::read_to_string(".github/workflows/dual-pass.yml").expect("workflow");
    for required in [
        "types: [labeled]",
        "github.event.label.name == 'dual-pass'",
        "XAI_API_KEY:",
        "bash scripts/dual-pass/run.sh",
        "toolchain: 1.87.0",
    ] {
        assert!(workflow.contains(required), "missing {required}");
    }
    let runner = fs::read_to_string("scripts/dual-pass/run.sh").expect("runner");
    for required in [
        "execution-plan.json",
        "red gate rejected",
        "self-correction budget exhausted",
        "needs-human-review",
        "tests/generated/",
        "restore_protected",
        "MAX_TURNS=3",
        "gh pr create",
    ] {
        assert!(runner.contains(required), "runner missing {required}");
    }
    let apply = fs::read_to_string("scripts/dual-pass/apply_change.py").expect("apply");
    assert!(apply.contains("git apply"));
    assert!(apply.contains("tree_sitter"));
}
