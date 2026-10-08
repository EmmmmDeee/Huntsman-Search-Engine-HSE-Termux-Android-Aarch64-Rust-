# Dual-pass runner

Label a GitHub issue `dual-pass`, or run the `dual-pass` workflow with an issue number.

Pass 1 asks the model for `execution-plan.json`: target files, signatures, and new tests under `tests/generated/` only.

Pass 2 writes those tests and runs them against untouched code. A pass is rejected. A failure is the red gate. The model may then patch only declared files, at most 3 turns.

Apply order: `git apply`, then a tree-sitter Rust function replace if that import is present, then a brace-matched `fn` replace.

Gates: `cargo check --locked`, then the generated tests. `tsc` and `mypy` are not used; this crate is Rust. `rustfmt` runs before the pull request.

Protected and restored if mutated: `tests/` except the generated write that the runner itself adds, `Cargo.toml`, `Cargo.lock`, `ci.yml`, `release.yml`.

Success opens a pull request to `main` with `dual-pass-report.md`. Failure pushes `dual-pass/issue-N-wip`, labels `needs-human-review`, and comments the trace.

Required secret: `XAI_API_KEY`. Optional: `XAI_MODEL` (default `grok-4`). The static prefix is `scripts/dual-pass/static-context.md` so the provider can cache it. Missing key stops in the human-review path.
