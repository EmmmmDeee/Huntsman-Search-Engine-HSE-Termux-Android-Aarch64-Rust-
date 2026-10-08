# Dual-pass runner

Label a GitHub issue `dual-pass`, or run the `dual-pass` workflow with an issue number. The workflow file is on `main`, which is what GitHub uses for issue events.

Pass 1 asks the model for `execution-plan.json`: target files, required signatures, and new tests. New tests must be `tests/generated_<issue>.rs` so Cargo runs them as integration tests. Existing files under `tests/` are snapshotted and restored.

Pass 2 writes those tests and runs them against untouched code. A pass is rejected. A failure is the red gate. The model may then patch only declared files, at most 3 turns.

Apply order: `git apply`, then a tree-sitter Rust function replace, then a brace-matched `fn` replace. The workflow installs `tree-sitter` and `tree-sitter-rust`.

Gates: `cargo check --locked`, then the generated integration test. `tsc` and `mypy` are not used; this crate is Rust. `rustfmt` runs before the pull request.

Protected and restored if mutated: snapshotted `tests/` files, `Cargo.toml`, `Cargo.lock`, `ci.yml`, `release.yml`. Generated `tests/generated_*.rs` files are new, so restore does not delete them.

Success opens a pull request to `main` with `dual-pass-report.md`. Failure pushes `dual-pass/issue-N-wip`, labels `needs-human-review`, and comments the trace.

Required secret: `XAI_API_KEY`. Optional: `XAI_MODEL` (default `grok-4`). The static prefix is `scripts/dual-pass/static-context.md` so the provider can cache it. Missing key stops in the human-review path.
