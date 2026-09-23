# Maintainer run log

Run state: `.agent/state.json`. Repair queue: `.agent/files.md`. The 42-cycle
ledger that used to live in `state.json` is `.agent/history.json`, content
unchanged. Check its `rejected_candidates` and `verified_negatives_recent`
before selecting a candidate, so a disproven one is not re-proposed.

## Run 2026-09-23

- **Work branch.** `claude/charming-meitner-85h3aj`. The session requires
  this name, so it replaces `agent/<date>`. The branch carries two commits
  published before this run (PR #648: REQ-CI-011, REQ-SSE-001). They cannot
  be rebased without a force-push, so this run builds on them. Its first two
  changes close that PR's review findings.
- **Verification.** `CARGO_INCREMENTAL=0 scripts/gate.sh --quick` (build,
  lint, suite), then the suite twice more with per-test output: `cargo test
  --all --lib --bins --tests --locked --features dep-cooldown` and `cargo test
  --doc --locked`. Runs are compared test by test on the `test <name> ...
  ok|FAILED|ignored` lines, keyed on (test target, test name). The doc-test
  `(line N)` suffix is stripped first, because toolchain 1.98 reports it
  unreliably (CLAUDE.md). The fresh worktree is a `git worktree add --detach`
  of the commit, with `target/`, `hse-core/target/` and `wasm-ui/target/`
  symlinked to the main tree's, so dependencies are not rebuilt. One worktree
  path is reused per run, so the crate's artifacts keep one hash set on disk.
- **Baseline `cf86bded`.**
  - The gate passed (`GATE_EXIT=0`). Six checks were skipped, each with its
    reason printed:
    - wasm-ui/pkg drift, MSRV and the cross-build, because of `--quick`;
    - shellcheck and gitleaks, because they are not installed;
    - cargo-audit, deny, machete and dep-cooldown, because no manifest
      changed.
  - Suite, run twice: 8530 tests (8503 passed, 27 ignored, 0 failed), and
    both runs were identical.
  - Doctests, run twice: 86 (83 passed, 3 ignored), both runs identical.
  - No baseline failures and no flaky tests.
  - An earlier attempt died of disk exhaustion (`No space left on device`,
    `ld … signal 7`), and its results are void.
- **Repair queue.** `.agent/files.md` ranks all 1337 tracked files; its
  header gives the formula. Cursor: #1 `src/core/scan/mod.rs`, not started.

### Change 1: [DEFECT] A live iteration's scan id is in flight before any client learns it (core::live)

- **What.** The live loop mints each iteration's scan id inside
  `CancelRegistryGuard::install` and reads it back through `scan_id()`.
- **Why.** The loop sent the `LiveTick` and recorded the id on the session
  before registering it, so `/scans/{id}/events` (REQ-SSE-001) could 404 a
  running scan.
- **Evidence.** The baseline order restored in full, and `record_scan` alone
  moved above the install, both fail
  `a_live_iteration_never_hands_out_a_scan_id_before_it_is_registered`.
  Moving the announcement above the install does not compile. The fix
  restored passes.
