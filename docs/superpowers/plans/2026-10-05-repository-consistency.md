# Repository Consistency Repair Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore consistency between the repository's current extracted-reference architecture, its hygiene tests, and its provenance documentation without reintroducing obsolete opaque ZIP snapshots.

**Architecture:** Treat `legacy/` extracted trees as the canonical reviewable historical source and `docs/ARCHIVE_PROVENANCE.md` as the preserved identity record for the removed ZIP containers. Root-level opaque archives are forbidden. Preserve all unrelated runtime behavior.

**Tech Stack:** Rust 1.87+, Cargo test suite, GitHub Actions, Markdown.

**Spec:** Current `main` commit `793919b12590be835661f2f6aab0966d0885845b`, whose commit intentionally removed the two root ZIP containers while retaining extracted trees.

## Global Constraints

- Do not re-add the historical ZIP containers.
- Preserve the recorded SHA-256 and Git blob identities for historical provenance.
- Keep `legacy/refactor-overlay-feef60a/` and `legacy/hse-monolith-v1.41.0/` as canonical reviewable references.
- Reject all opaque archive files at the repository root.
- Do not change Huntsman runtime behavior in this repair.

## Review Focus

- A root `.zip` must fail the hygiene test.
- Other supported opaque archive suffixes must also fail.
- An archive-free root must pass.
- Historical archive hashes and blob identities must remain documented.
- Extracted legacy tree counts remain guarded by `tests/legacy_reference.rs`.

---

### Task 1: Repair the root archive invariant

**Files:**
- Modify: `tests/repository_hygiene.rs`
- Test: `tests/repository_hygiene.rs`

**Interfaces:**
- Consumes: repository root directory and `OPAQUE_ARCHIVE_SUFFIXES`.
- Produces: a hygiene invariant that accepts zero opaque root archives and rejects any opaque root archive.

- [ ] **Step 1: Preserve the existing failing CI result as the regression reproduction**

Run: `cargo test --locked --test repository_hygiene`
Expected before repair: FAIL because the test requires two ZIP files intentionally removed from current `main`.

- [ ] **Step 2: Replace the obsolete pinned-root-archive policy**

Remove `PINNED_REFERENCE_ARCHIVES` and hash verification from this test. Rename the test to describe the actual invariant and assert that the collected root archive list is empty.

- [ ] **Step 3: Run the focused test**

Run: `cargo test --locked --test repository_hygiene`
Expected: PASS.

### Task 2: Repair provenance documentation

**Files:**
- Modify: `docs/ARCHIVE_PROVENANCE.md`

**Interfaces:**
- Consumes: historical ZIP SHA-256 values, Git blob SHA-1 values, extracted-tree paths, historical tree identities, baseline commit.
- Produces: accurate current-state documentation: ZIP bytes are recoverable from history but absent from current root; extracted trees are canonical.

- [ ] **Step 1: Update current-state wording without changing provenance identities**

State that the ZIP containers were removed after extraction, remain recoverable from the historical commit/blob identities, and are intentionally not present in the current root.

- [ ] **Step 2: Verify documentation contract through the repository test suite**

Run: `cargo test --locked --test repository_hygiene --test legacy_reference`
Expected: PASS.

### Task 3: Full regression verification

**Files:** none.

- [ ] **Step 1: Run formatting**

Run: `cargo fmt --check`
Expected: exit 0.

- [ ] **Step 2: Run strict linting**

Run: `cargo clippy --all-targets --locked -- -D warnings`
Expected: exit 0.

- [ ] **Step 3: Run complete tests**

Run: `cargo test --locked`
Expected: all tests pass.

- [ ] **Step 4: Verify Android build in CI**

Expected: `Android aarch64 cross-build` succeeds.
