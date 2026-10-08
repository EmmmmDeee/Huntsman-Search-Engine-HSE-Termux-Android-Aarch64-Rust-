# Dual-pass runner

No LLM API. No model secret.

Label an issue `dual-pass`, or dispatch the workflow with an issue number. The issue body must contain one fenced json plan:

```json
{
  "targets": [{"path": "src/repository_identity.rs", "signatures": ["pub const CANONICAL_REPOSITORY"]}],
  "new_tests": [{"path": "tests/generated_1.rs", "signatures": ["generated_identity_is_nonempty"], "source": "..."}],
  "patches": [{"diff": "", "ops": [{"path": "src/repository_identity.rs", "kind": "replace_fn", "name": "canonical", "body": "fn canonical() {}"}]}]
}
```

Pass 1 extracts that object to `execution-plan.json` and rejects protected paths. Pass 2 writes `tests/generated_*.rs` and runs it against untouched `main`. A passing test is rejected. A failure is the red gate. The runner then applies `patches` in order, at most 3, using `git apply` and then the tree-sitter or brace-matched function replace.

Gates: `cargo check --locked`, then the generated integration test, then `rustfmt`. Snapshotted tests, `Cargo.toml`, `Cargo.lock`, `ci.yml`, and `release.yml` are restored if a patch touches them.

Success opens a pull request to `main` with `dual-pass-report.md`. Failure pushes `dual-pass/issue-N-wip`, labels `needs-human-review`, and comments the trace.
