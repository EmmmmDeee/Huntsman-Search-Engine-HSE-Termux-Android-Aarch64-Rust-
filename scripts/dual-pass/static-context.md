# Dual-pass contract

No LLM API. No model secret. No prompt cache. The issue body is the plan.
Pass 1 binds that plan to live Rust signatures and the Cargo.lock dependency tree, then writes execution-plan.json with schema huntsman-dual-pass/1 and llm=false.
Static context is a sha256 digest of this file plus Cargo.toml and Cargo.lock.

Canonical crate: huntsman-recon. Rust edition 2024. rust-version 1.87.
Dependencies: serde, serde_json, thiserror, ureq. No root. No ports below 1024.

A fenced ```json block in the issue must contain targets, new_tests, and patches.
new_tests paths must be tests/generated_<issue>.rs, must contain an assertion, and must fail on untouched main.
patches has 1 to 3 items. Each item is {diff, ops}. diff is a unified patch.
ops is the tree-sitter fallback: path, kind replace_fn, name, body.
Do not target existing tests, Cargo.toml, Cargo.lock, or workflow files.
Do not include model, prompt, endpoint, or api key fields.
