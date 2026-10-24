# Claude Code — Complete HSE Refactor Execution Contract

## Objective

Upgrade the whole Huntsman repository to the strongest **verified** maintainable state. Work through the complete reachable dependency graph, but replace complete files only where the change has a demonstrated benefit. Never represent a plan, code write, or passing unit test as a complete-system validation.

This file supplements the canonical repository directives; it does not supersede platform rules, existing contracts, or established user functionality.

## Recovery and baseline — execute before edits

1. Read `CLAUDE.md`, `Cargo.toml`, workspace manifests, `ARCHITECTURE.md`, relevant tests, `.github/workflows/ci.yml`, installer, Dockerfile, Railway configuration and API/interface documentation.
2. Inspect `git status --porcelain=v1`, `git log`, open branches/PRs, recent CI failures and all locally available logs and artifacts. Never erase or incorporate unrelated uncommitted changes without explicit scope.
3. Execute `bash scripts/refactor-baseline.sh`. Preserve the generated evidence directory, command output, failure exit codes and exact commit SHA. If the script cannot run, report why and run all feasible individual checks.
4. Trace executable entry points, registered modules, CLI commands, HTTP routes, persisted schemas, credentials, network access, user-visible HTML/JS, Android native integrations and Railway deployment. Distinguish reachable production paths from dead code before deletion.
5. Record behavior, build size and performance only where actually measured. Unknown baseline values remain unknown.

## Refactor algorithm — repeat to exhaustion of positive-value verified work

1. Select one meaningful architectural defect or duplication supported by repository evidence. Prioritize correctness and broken public behavior before speculative performance improvements.
2. Map all affected interfaces, call sites, fixtures, tests, docs, generated artifacts, and downstream deployment surfaces.
3. Design an internally consistent full-file replacement set. Preserve public API/CLI/HTTP/JSON formats unless a migration and compatibility plan is implemented and tested.
4. Replace complete affected files when that reduces partial-edit drift. Avoid cosmetic rewrites of unrelated modules and never revert others' concurrent changes.
5. Integrate through compile-time type checks, unit tests, functional integration tests, CLI contract tests, corpus fixtures, snapshot/baseline comparisons and end-to-end acceptance.
6. Prove before/after equivalence for unchanged behavior; attach regression tests for fixed failures; retain meaningful provenance on recorded evidence and derived graph edges.
7. Run `cargo fmt --all -- --check`, `cargo test --workspace --locked`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, release build, `cargo run --locked -p xtask -- gate full`, and relevant specific tests.
8. Run the repository CI gates for Rust MSRV and pinned stable, Android aarch64, Web UI and Railway container. Report actual CI status. Never equate desktop compilation with handset verification.
9. If any gate fails, investigate and fix the root cause before accepting the change. On infeasible or expensive changes, revert only the task's own edits with evidence and preserve prior verified capability.
10. Repeat with the next highest-value task. Stop only when acceptance is demonstrably complete, a hard blocker prevents further execution, or no remaining action has positive verified expected value.

## Module design constraints

- Rust-first, safe Rust preferred, no LLM dependency in the HSE runtime.
- Work on Android Termux aarch64 userland without root; retain offline paths when providers fail.
- Module boundaries should separate external transport, canonical entity representation, provenance, decision policy, persistence, and presentation.
- Entity graphs represent documented relationships; direct evidence must remain inspectable. Do not promote weak or syndicated observations into independent verification.
- Respect API keys/consent, service restrictions, bounded requests and rate limits; never print credentials into evidence or CI logs.
- Favor incremental JSON/SQLite migration over breaking persisted schemas. Backups and rollback paths are mandatory for migrations.
- Preserve CLI compatibility, SpiderFoot-style entry points, existing Web UI routes, scan-history access and deterministic offline testing.

## Completion evidence

Report:
- Baseline commit, final commit and comparison branch.
- Every complete-file replacement and the defect it resolves.
- Dependency, schema and public-contract changes.
- Tests, builds, compiler/linter versions, Android/Termux and Railway evidence, including failures.
- Known open issues, regressions, omitted checks, rejected alternatives and concrete rollback method.

Do not claim an entire-repository refactor is complete until the actual full repository and all relevant release targets have passed their required gates. A focused PR must be identified as focused, not comprehensive.
