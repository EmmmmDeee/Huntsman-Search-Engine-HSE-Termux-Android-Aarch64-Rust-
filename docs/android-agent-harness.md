# Android-controlled coding-agent harness: first executable component

This is an independent Rust source file with no third-party dependencies. It is not yet a complete AI agent. It implements deterministic, bounded, query-ranked source-symbol retrieval — the first local component of an agent harness.

## Build and run in rootless Termux

```sh
pkg install rust git
rustc --edition=2024 tools/agent_repo_map.rs -o "$PREFIX/bin/agent-repo-map"
agent-repo-map . entity provenance correlation > agent-context.md
rustc --edition=2024 --test tools/agent_repo_map.rs -o /tmp/agent-repo-map-tests
/tmp/agent-repo-map-tests
```

Inspect the resulting `agent-context.md` and provide it alongside the specific source files to a browser-accessible coding model. It includes bounded signatures with file and line references, ranked by query terms. It is a lexical index: it does **not** prove symbol resolution, imports, type relationships or call edges.

## Full workflow design

1. **Discover**: query the repo map and read only relevant source files.
2. **Plan**: use a read-only model pass to state the behavioural invariant, change scope and acceptance tests.
3. **Edit**: request a unified patch on an isolated branch, never on main.
4. **Review**: use a separate model pass to challenge attribution, provenance, backward compatibility and test coverage.
5. **Validate**: run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` in a capable environment. Distinguish actual executed results from recommendations.
6. **Integrate**: inspect GitHub CI, open a draft PR and keep main installable.
7. **Resume**: record exact SHAs, changed paths, test evidence and next action in the PR.

## Why this architecture

- Codex documents an agent loop, tools, persistent threads, and a separate client-facing app server.
- OpenCode documents separate plan/build agents and tool permissions.
- Aider documents compact, ranked repository symbol maps and architect/editor separation.

These are publicly documented concepts, not a claim to reproduce proprietary implementations. The model connector, patch applicator, isolated execution environment and durable task scheduler are future components, not features implemented by this PR.

## Constraints

No paid service, root access, LLM in Huntsman runtime, or additional Rust crate is required for this component. The user still needs a model-access channel for actual LLM reasoning. Cloud-free usage is quota-dependent. Android physical acceptance is not equivalent to cloud CI.

## Acceptance

- Compile on Android AArch64 Termux with installed `rustc`.
- Run the three included unit tests.
- Produce a bounded source map for a query.
- Verify no tracked application logic or dependency manifests changed.
