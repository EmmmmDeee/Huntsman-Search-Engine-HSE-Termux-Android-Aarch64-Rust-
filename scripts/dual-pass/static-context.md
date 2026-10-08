# Static repository context (cacheable prefix)

Canonical crate: huntsman-recon. One binary. Rust edition 2024. rust-version 1.87.
Dependencies: serde, serde_json, thiserror, ureq. No tokio. No root. No ports below 1024.
Termux target is aarch64-linux-android.

Do not modify tests outside tests/generated/, Cargo.toml, Cargo.lock, or .github/workflows/ci.yml and release.yml.
New tests must fail on the current main before implementation. Return machine-readable JSON only.
Gates after a patch: cargo check --locked, then the generated tests. Maximum 3 correction turns.
