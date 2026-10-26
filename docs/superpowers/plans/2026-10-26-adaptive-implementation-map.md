# Adaptive implementation map implementation plan

> For agentic workers: implement inline with the executing-plans workflow; review
> the entire change independently before merging. Read the spec and handoff first.

**Goal:** Generate a current, complete, evidence-labelled Huntsman implementation
handoff from an immutable checkout using existing Rust automation.

**Architecture:** One read-only `xtask roadmap` command owns Git inventory and
rendering. A separate inclusion scanner and queue validator own their respective
contracts. The curated queue is the editable source; CI artifacts are projections.

**Tech stack:** Existing Rust edition 2024, MSRV 1.87, `syn`, `serde_json`, Git.

**Spec:** `docs/superpowers/specs/2026-10-26-adaptive-implementation-map-design.md`.

## Global constraints

Pure Rust; rootless Android AArch64 Termux; no runtime LLM. No new crates or product
dependencies. Keep current CLI, Web UI, schemas and storage compatible. Never
execute queue instructions or delete allegedly unused/duplicate code. No package
version changes. Continuous refresh requires actual CI; completion requires receipts.

## Review focus

- Dirty/staged checkouts must not be represented as the inventoried commit.
- Symlinks, control characters and nonstandard Rust inclusion must not leak data or
  yield false definitive unused-code claims.
- Dependencies outrank priority; duplicate IDs, dangling edges and cycles fail.
- Moved/deleted paths and overlapping edits must remain visible to the next agent.
- Report generation must not mutate sources, execute queue strings, or imply tests passed.

## Task 1: Inventory and ordered handoff

**Files:** create `xtask/src/roadmap/{mod,queue,wiring}.rs` and
`xtask/tests/roadmap.rs`; modify `xtask/src/main.rs`.

**Interfaces:** `roadmap::run(&[String]) -> ExitCode` consumes the captured commit
and its queue blob, produces JSON or Markdown on stdout, and prints diagnostics on
stderr. `check` validates the same snapshot and does not claim verification.

- [ ] Write real-Git regression fixtures for each review focus and inclusion syntax.
- [ ] Run `cargo test --locked -p xtask --test roadmap`; expect missing command failures.
- [ ] Implement bounded immutable Git inventory, safe inclusion hints, DAG validation,
  path drift, task overlap reporting, and complete tree rendering.
- [ ] Run the same test; expect all fixture behaviours to pass.
- [ ] Run `cargo test --locked -p xtask` and strict workspace Clippy.

## Task 2: Ground the queue and refresh it

**Files:** create `docs/implementation/{README.md,queue.json}` and a changelog
fragment; modify `.github/workflows/{ci,fortified-controller}.yml` and the README.

**Interfaces:** author queue fields specified by Task 1; CI captures both output
formats under `target/implementation-map/`, with read-only GitHub permissions.

- [ ] Cross-check each task's evidence and existing file paths against current code.
- [ ] Describe exact adapter contracts, resource policies, test commands, rollback,
  external blockers and finite completion rules for the next coding agent.
- [ ] Add snapshot generation/upload steps to existing CI and daily controller.
- [ ] Commit the coherent source so generation includes the new tracked paths.
- [ ] Generate both outputs and compare inventory counts with Git independently.
- [ ] Run host gate; obtain independent correctness/security review; fix material findings.
- [ ] Push a branch, open a PR, observe CI and merge only an authorized verified head.
- [ ] Verify merged-source identity, post-merge checks and generated artifacts. Report
  the actual merge/test state and remaining device access limitations.
