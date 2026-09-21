# /ci — Run the CI Gate

Runs `scripts/gate.sh` — the comprehensive verification gate.

That script, not this file, is the authority on what runs: it reports every
check as PASS, FAIL or SKIP-with-reason, and `scripts/check_workflows.py`
enforces that it covers every `pull_request` job CI runs (REQ-GATE-002). The
list below is a summary and can lag; the gate's own summary cannot.

## Usage
```
/ci              # Full gate (fmt, clippy, tests, rustdoc, MSRV, cross-build)
/ci --quick      # Fast gate (skip MSRV and cross-build for dev loop)
```

## What It Does
- `cargo fmt --all -- --check` — formatting
- `cargo check --all-targets --locked` — compilation
- `cargo clippy --all-targets --locked -- -D warnings` — lints
- `cargo doc --no-deps` — rustdoc lint pass (broken intra-doc links)
- `cargo test --all --locked` — unit + integration tests
- `cargo +<MSRV> check` — minimum supported Rust version
- `cargo build --target aarch64-linux-android` — Termux target
- `gitleaks dir .` — secret scan (SKIPPED with a reason when not installed)
- sibling crates (`hse-core`, `wasm-ui`) + `wasm-ui/pkg` drift
- `install.sh` / `reconcile.sh` syntax, workflow-file lint, doc coverage

## Exit Status
- `0` — all checks passed
- Non-zero — one or more checks failed (see output for details)

## When to Run
- Before every push (or use pre-push hook)
- After major refactors
- When you suspect a regression
- As part of PR review

## Related Commands
- `/test` — run just the test suite
- `/quick` — fast inner-loop validation (fmt + clippy + test)
