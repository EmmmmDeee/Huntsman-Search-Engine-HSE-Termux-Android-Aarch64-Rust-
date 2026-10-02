# /ci — Run the CI Gate

Runs the comprehensive verification gate — same checks as GitHub CI.

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
