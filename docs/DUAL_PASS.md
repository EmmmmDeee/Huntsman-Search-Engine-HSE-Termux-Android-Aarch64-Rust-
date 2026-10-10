# Dual-pass runner

No LLM API. No model secret. No token in the job that runs generated code.

Label an issue `dual-pass`, or dispatch the workflow with an issue number. The issue must be written by the repository owner or a member, and its body must contain one fenced json plan:

```json
{
  "targets": [{"path": "src/repository_identity.rs", "signatures": ["pub const CANONICAL_REPOSITORY"]}],
  "new_tests": [{"path": "tests/generated_1.rs", "signatures": ["generated_identity_is_nonempty"], "source": "..."}],
  "patches": [{"diff": "", "ops": [{"path": "src/repository_identity.rs", "kind": "replace_fn", "name": "canonical", "body": "fn canonical() {}"}]}]
}
```

## Three jobs

- **plan** compiles and runs the Rust the plan describes, so it holds no credential at all. Generated Rust can read its process's environment, and a parent's environment is readable by the same user, so a token in any step of this job would be readable by a generated test. The job writes four files to its output directory: `outcome`, `change.patch`, `execution-plan.json`, and `dual-pass-report.md`. It also writes `reason.md` when a human is needed.
- **publish** holds the write token. It runs only scripts copied before the plan's output arrived. It applies `change.patch` to a fresh checkout of `main`, runs the path policy on the result, and only then commits. It never reads the plan's working tree.
- **self-check** runs the runner's offline tests on a pull request that touches the runner.

## Plan stage

Pass 1 extracts the plan to `execution-plan.json`, binds it to live signatures and `Cargo.lock`, and rejects protected paths and model fields. Pass 2 writes `tests/generated_*.rs` and runs it against untouched `main`. Red is valid only when the test runs and fails an assertion, or when the build fails on a missing symbol. Any other compile error is refused. The runner then applies `patches` in order, at most 3, using `git apply` and then the tree-sitter or brace-matched function replace.

Gates: `cargo check --locked`, then the generated integration test, then the existing locked suite. Snapshotted tests, `Cargo.toml`, `Cargo.lock`, `ci.yml`, and `release.yml` are restored if a patch touches them. Every Python call runs with `-I`, so a generated test cannot shadow a module by writing one into the working directory.

## Publish stage

A green plan pushes `dual-pass/issue-N` and opens a pull request to `main`, with the report as its body. A plan that needs a human pushes `dual-pass/issue-N-wip` when it has a change, labels the issue `needs-human-review`, and comments the reason and the end of the report. A plan with no change pushes nothing.

The push replaces the bot's own branch only under a lease on the tip it saw. The policy refuses a patch that touches protected paths, test code in `src/`, or anything that is not a source file or a new test, and then nothing is pushed.

## Limits

- The plan job runs code the plan describes. The control is the author gate: only the owner or a member can write a plan that reaches that job.
- The plan job's network access is not restricted by the runner.
- The gates prove the tests fail on untouched `main` and pass after the patch. They do not prove the patch is the right fix.
