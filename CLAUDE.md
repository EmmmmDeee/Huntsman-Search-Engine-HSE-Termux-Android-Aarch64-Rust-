# Project notes for Claude Code

## Working with the user

- The user identifies as **Haigen Bamford**. Address them accordingly, with respect.

## Verification gate (run before committing)

```
cargo fmt
cargo clippy --all-targets
RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links" cargo doc --no-deps
cargo test
```

## Conventions

- Edition 2024, MSRV 1.88, `#![forbid(unsafe_code)]`; pinned reqwest 0.12 / rusqlite 0.39 (Termux aarch64, no root).
- Layering: `core` must not import `modules`; module layer may use `util`. Architecture guards in `tests/architecture.rs` enforce this.
- MITRE ATT&CK Reconnaissance (TA0043) alignment lives in `core::attack`; every collection module declares `attack_techniques()` (guarded — no module may be left unmapped).
