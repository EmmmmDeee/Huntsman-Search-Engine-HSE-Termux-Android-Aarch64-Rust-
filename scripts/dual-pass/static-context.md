# Dual-pass contract

No LLM API. No XAI_API_KEY. The issue body is the plan.

Canonical crate: huntsman-recon. Rust edition 2024. rust-version 1.87.
Dependencies: serde, serde_json, thiserror, ureq. No root. No ports below 1024.

A fenced ```json block in the issue must contain targets, new_tests, and patches.
new_tests paths must be tests/generated_<issue>.rs and must fail on untouched main.
patches has at most 3 items. Each item is {diff, ops}. diff is a unified patch.
ops is the tree-sitter fallback: path, kind replace_fn, name, body.
Do not target existing tests, Cargo.toml, Cargo.lock, or .github/workflows/ci.yml and release.yml.
