# Project notes for Claude Code

## Working with the user

- The user identifies as **Haigen Bamford**. Address them accordingly, with respect.
- Do **not** use the user's former name or any email/handle derived from it — none of it is applicable any more. For an authorised self-test, seed on the name **Haigen Bamford** (the current email is unknown/forgotten). `jordanavery@gmail.com` / `Jordan Avery` are synthetic placeholders used only in test fixtures, not the user's identity.

## Verification gate (must match CI before committing)

CI's `Check & test` job runs clippy with `-D warnings` on a newer toolchain and
docs with `--document-private-items` plus extra rustdoc lints. Match it locally:

```
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links -D rustdoc::bare_urls -D rustdoc::invalid_html_tags" \
  cargo doc --no-deps --document-private-items --locked
cargo test
```

Notes:
- `--document-private-items` matters: a broken intra-doc link in a *private* item
  (e.g. a `fn`'s doc) only fails under it. Fully-qualify cross-module links.
- The CI clippy toolchain is newer than the local one, so some lints
  (e.g. `collapsible_match`) only surface in CI; treat clippy failures there as real.

## Conventions

- Edition 2024, MSRV 1.88, `#![forbid(unsafe_code)]`; pinned reqwest 0.12 / rusqlite 0.39 (Termux aarch64, no root).
- Layering: `core` must not import `modules`; module layer may use `util`. Architecture guards in `tests/architecture.rs` enforce this.
- MITRE ATT&CK Reconnaissance (TA0043) alignment lives in `core::attack`; every module is mapped to `attack_techniques()` — via a per-category default (`techniques_for_category`) or an explicit override — and a guard rejects any unmapped module or out-of-register technique ID.
