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

## Four jobs

- **self-check** runs the runner's offline tests on a pull request that touches the runner.
- **gate** checks that the issue was written by the owner or a member, and passes its body to plan as an artifact. It holds the read token, runs no repository code, and finishes before plan starts.
- **plan** compiles and runs the Rust the plan describes, so it holds no credential at all: no token, no secret, and no write permission, at job level or step level. Generated Rust can read its process's environment, and a parent's environment is readable by the same user. The job writes four files to its output directory: `outcome`, `change.patch`, `execution-plan.json`, and `dual-pass-report.md`. It also writes `reason.md` when a human is needed.
- **publish** holds the write token. It runs only scripts copied before the plan's output arrived. It applies `change.patch` to a fresh checkout of `main`, runs the path policy on the result, and only then commits. It never reads the plan's working tree.

## Plan stage

Pass 1 extracts the plan to `execution-plan.json`, binds it to live signatures and `Cargo.lock`, and rejects protected paths and model fields. A target must be a path under `src/`, or a new file under `tests/`. Any other target, such as a file under `docs/`, is refused here, before any build. A new test path must not already exist on main.

Pass 2 writes `tests/generated_*.rs` and runs each generated test binary on untouched `main`. A binary that passes refuses the plan. Each failing binary is judged on its own by `scripts/dual-pass/red_class.py`, and any one that is not a valid red refuses the whole run:

- **missing-symbol**: the build failed, and every compile error is a `cannot find` error. That covers E0425 for a function or a value, E0412 for a type, and an error with no code. Colour codes in the log are removed before it is read.
- **assertion-failed**: the test ran, and every panic is an assertion macro's default message. The default messages begin with ``assertion `left`` (from `assert_eq!` and `assert_ne!`) or with `assertion failed` (from `assert!`).

A custom message is refused unless it keeps one of those default texts. A custom message on `assert!` replaces the default text, so it is refused. A custom message on `assert_eq!` or `assert_ne!` is added after the default text, so it is accepted. The judgement reads the log text, so a hand-written panic with the same text cannot be told apart from an assertion.

Anything else is refused: a build failure on another error (a mismatched type, for example), a parse error, a panic that is not an assertion (`unwrap()` on an `Err`, `expect()`), and a failure with no panic (a test that returns `Err`).

The runner then applies `patches` in order, at most 3, using `git apply` and then the tree-sitter or brace-matched function replace.

Gates: `cargo check --locked`, then the generated integration tests, then the existing locked suite. Tracked files under `tests/` are restored from main after every patch and are never deleted, so a generated test merged earlier runs in the existing suite and fails it when a patch breaks it. `Cargo.toml`, `Cargo.lock`, `ci.yml`, `release.yml`, and `dual-pass.yml` are restored too. Every Python call runs with `-I`, so a generated test cannot shadow a module by writing one into the working directory.

## Publish stage

A green plan pushes `dual-pass/issue-N` and opens a pull request to `main`, with the report as its body. A plan that needs a human pushes `dual-pass/issue-N-wip` when it has a change, labels the issue `needs-human-review`, and comments the reason and the end of the report. A plan with no change pushes nothing.

A change that cannot be published is never left silent. When the patch does not apply, the path policy refuses it, or the push fails, the issue is labelled and commented with the reason first, and publish then exits non-zero.

The push replaces the bot's own branch only under a lease on the tip it saw. The policy refuses a patch that touches protected paths, test code in `src/`, or anything that is not a source file or a new test, and then nothing is pushed.

## Limits

- The plan job runs code the plan describes. The control is the author gate: only the owner or a member can write a plan that reaches that job.
- The plan job's network access is not restricted by the runner.
- The gates prove the tests fail on untouched `main` and pass after the patch. They do not prove the patch is the right fix.
- The path policy's test-code rules (`#[cfg(test)]` modules and test-only files in `src/`) are applied by `check-protected.sh` at publish. Plan refuses a target by its path only.
