# Phase 0 Audit — Environment, Migration, Artifact, and Issue Census

Run against `main` at `e67e0c6ba` (after this session's own PR #544 and PR #547 merged).
Every figure below is measured directly against this tree, not carried over from memory or an earlier cycle's report.

## 1. Environment assessment

| Layer | Status | Treatment |
|---|---|---|
| VCS-TOOL | git, existing repository, full history | Used for recovery points (branches, commits) as normal |
| REMOTE | GitHub `origin` present and reachable | Engaged for the PR workflow already in use this session; not required for any step below |
| TRACKER | No dedicated issue tracker (GitHub Issues unused for this) | The in-tree ledgers (`.agent/state.json`, `docs/gap_register.md`, `docs/*_LEDGER*.md`) are the pre-existing, 42-cycle-deep canonical system of record — treated as authoritative rather than duplicated |
| CI | `.github/workflows/*.yml`, engaged and green | `scripts/gate.sh` is the load-bearing local equivalent; verified green multiple times this session |
| NETWORK | Present, one restriction observed (crates.io's `api/v1` REST endpoint failed outbound from this sandbox; the sparse index, git protocol, and GitHub's own API all worked) | CI has unrestricted access; local limitation disclosed, not worked around by weakening a check |

No layer's absence blocked anything; none was required to be present.

## 2. File census — is this actually a "codebase to migrate to Rust"?

Full extension census of all `git ls-files`-tracked paths (~1237 files):

```
1087 rs      45 md       41 js       11 html      10 sh
   9 yml      9 toml      7 txt       5 json       4 py
   4 lock     4 gitignore 2 example   1 wasm       1 dockerignore
   1 der      1 css       1 bin
```

**1087 of ~1237 tracked files (88%) are already Rust `.rs` source.** Excluding documentation (`.md`), config (`.yml`/`.toml`/`.json`/`.gitignore`/`.example`), lockfiles, and test fixtures — all file classes the run directive itself says should never be "ported" (they PRESERVE or CONVERT, not port) — essentially **100% of this project's actual application logic is already Rust.**

### Migration disposition ledger (every non-Rust file class)

| Class | Count | Disposition | Evidence |
|---|---|---|---|
| `.rs` | 1087 | Already Rust — N/A | — |
| `.md` docs | 45 | PRESERVED / regenerated as normal doc maintenance | Standard docs, not a migration target |
| `.js` + 1 `.css` + `spa.html` | 41 + 1 + 1 | **PORTED, in progress, under the project's own steam** | `wasm-ui/` (a `wasm32-unknown-unknown` crate) already ports 17 of 23 `scan_info/*.js` views and 3+ of 10 `views/*.js` views to Rust, verified live this session (PR #547 touched this exact crate). The 6-ish JS files without a direct Rust counterpart yet (`graph.js`, `index.js`, `log.js`, `insights.js`, `stealer.js`, `report.js`, plus orchestration files `api.js`/`router.js`/`state.js`/`ui.js`/`timers.js`/`main.js`) are genuinely DOM-stateful/orchestration code (event wiring, SSE tailing, pan/zoom viewport state, fetch sequencing) — not the "pure, DOM-free rendering" class `wasm-ui`'s own architecture doc says it targets. Continuing this port view-by-view is this project's own established, successful, ongoing practice (dozens of merged PRs), not a gap this run needs to invent a new strategy for. |
| 10 `.sh` (`install.sh`, `scripts/*.sh`) | 10 | **EXCEPTION, justified** | `install.sh` is the bootstrap installer that runs *before* any Rust toolchain necessarily exists on a fresh Termux install — it is what fetches/builds the Rust binary in the first place. A Rust rewrite would need a precompiled, statically-linked bootstrap binary per target architecture shipped ahead of the installer it replaces, which is strictly more fragile than a POSIX shell script for this one job, and would contradict `scripts/gate.sh`'s own long-standing decision to keep `install.sh` as shell (see its own header comments and the repo's `shellcheck` gate). The other 9 (`scripts/gate.sh`, `setup-dev.sh`, `standard-test.sh`, `diagnose.sh`, `doc_coverage.sh`, CI action scripts) are developer/CI tooling explicitly following this project's own documented `COMPILER > STATIC CHECK > TEST > HOOK > SCRIPT > PROSE` automation-tooling hierarchy, already `shellcheck`-gated. |
| 4 `.py` (`scripts/finetune/*.py` ×3, `scripts/pack_monolith.py`) | 4 | **EXCEPTION, justified** | The 3 `finetune/` scripts drive LoRA fine-tuning against PyTorch/HuggingFace — porting to Rust would mean reimplementing a mature ML training ecosystem with no comparable Rust equivalent, for a dev-only offline training utility never shipped in the product binary. `pack_monolith.py` is a maintainer/agent convenience tool (packs the repo into one text file for LLM context) with the same "dev tool, not shipped" profile; Python's stdlib (`hashlib`, `base64`, file I/O) is a reasonable, low-risk fit for a one-off text-packing script and porting it would add Rust build surface for zero product value. |
| 4 `.lock` (root/hse-core/wasm-ui/fuzz `Cargo.lock`) | 4 | Already the Rust-native manifest format — N/A | — |
| 1 `.wasm` (`wasm-ui/pkg/hse_wasm_ui_bg.wasm`) | 1 | **CLOSED this run** — source-backed, regenerated, round-trip proven | See Artifact Ledger below |
| 1 `.bin` (`src/util/oui/ieee.bin`) | 1 | PRESERVED byte-exact | IEEE OUI vendor lookup table, already consumed as opaque data by Rust code (`util::oui`) — this is DATA, not a code artifact; no source/generator relationship to prove, matches the directive's own "test fixtures... PRESERVED byte-exact" rule |
| 1 `.der` (`src/modules/cert_intel/testdata/selfsigned.der`) | 1 | PRESERVED byte-exact | A certificate test fixture already consumed by a Rust test; same rule as above |
| Other config/doc extensions | ~30 | PRESERVED / CONVERTED as applicable | Standard project config, no migration content |

**No file in this census lacks a disposition.**

## 3. Artifact census — the ".all files above all" directive

A full census for compiled/packaged/proprietary formats found **zero `.all` files and zero orphaned proprietary binary artifacts anywhere in the tracked tree.** The only compiled, packaged artifact in this repository is the `wasm-ui` crate's compiled output:

- `wasm-ui/pkg/hse_wasm_ui.js` (wasm-bindgen JS glue)
- `wasm-ui/pkg/hse_wasm_ui_bg.wasm` (the compiled wasm binary)

**Status: CLOSED, source-backed, round-trip proven — this run.** Both files already have a full Rust source representation (`wasm-ui/src/*.rs`) and a documented, exact generator command (in `wasm-ui/src/lib.rs`'s own doc comment). This run:

1. Installed the exact pinned toolchain the source already specifies (`wasm32-unknown-unknown` target, `wasm-bindgen-cli` 0.2.127 matching the `wasm-bindgen` crate dependency's pinned version, `binaryen`'s `wasm-opt`).
2. Ran the full documented pipeline: `cargo build --target wasm32-unknown-unknown --release` → `wasm-bindgen --target web ...` → `wasm-opt -Os ...`.
3. Diffed the regenerated output against the previously-committed copy: the `.js` glue diff was minimal and fully explained (one new `new Error(...)` import binding, matching this run's actual source change — see PR #547); the `.wasm` binary landed within 50 bytes of the prior committed size (440473 vs. 440423), consistent with no toolchain drift.
4. Merged the regenerated artifact to `main` as part of PR #547, with CI green on the result.

The reverse-engineering loop (directive steps 15–20) has **no target in this codebase** — there is nothing orphaned to reverse-engineer.

## 4. Issue census — "resolve every issue end to end"

### Fresh census, current head (`e67e0c6ba`)

- `TODO`/`FIXME`/`HACK` markers in `src/`: **0** (grep-verified this run)
- Clippy warnings: **0** — CI's `check` and `sibling-crates` jobs both run `clippy --all-targets --locked -- -D warnings` and are green on the current head
- Failing or skipped tests: **0** — full suite green in CI on the current head (verified twice this session, for PR #544 and PR #547)
- `cargo audit` / `cargo deny check` / `cargo machete`: **clean** for the root crate, `hse-core`, and `wasm-ui` (this run installed and ran all three tools directly against all three manifests — see PR #544's commit history for the full command transcript)

### Issues actually found and closed this run (before this Phase 0 report was written)

1. **PR #544** — `hse-core` (144 unit tests + 6 doctests) and `wasm-ui` had zero CI or local-gate coverage since PR #509 split them into separate, non-workspace-member crates. Closed: wired into `.github/workflows/ci.yml` (new `sibling-crates` job), `scripts/gate.sh`, and `.github/workflows/audit.yml` (audit/deny/machete/dep-cooldown extended to both crates' own lockfiles). Merged, CI green.
2. **PR #547** — `wasm-ui::to_js_error` threw a bare JS string instead of a real `Error` object, so every JS call site reading `e.message` on a caught wasm error (6+ files under `src/web/js/scan_info/`) would render `undefined`. Found via a Copilot review on an unrelated PR (#515), independently re-verified against source (not trusted from the review alone) before fixing. Closed: real `js_sys::Error` construction, checked-in compiled artifact regenerated and proven (see Artifact Ledger). Merged, CI green.

### Pre-existing ledger (`.agent/state.json`, `docs/gap_register.md`)

This repository already runs an extremely mature, 42-recorded-cycle, evidence-gated issue-remediation practice — root-cause fixes, red-then-green verification, regression-lock tests, explicit REJECTED/DISPROVEN entries with re-verification notes — that is functionally the same discipline this run's directive describes. Re-deriving it from scratch would violate the directive's own "avoid... duplicated implementation" default. Findings:

- The ledger's last recorded state (cycle 42) shows **one open item, OD-20** (Low-Medium severity: `ip2location` module has no hosting/datacenter signal, unlike its sibling `criminal_ip`) — explicitly recorded as deferred because closing it needs a live API response check neither that cycle nor this run performed (no `HUNTSMAN_IP2LOCATION_KEY` credential available to exercise it live in this sandbox). Not closed this run for the same reason: closing it without checking the live response shape would be exactly the "closure claimed without evidence" fabrication this directive treats as its gravest failure. Left OPEN, honestly, with the reason recorded.
- The ledger itself has drifted **stale relative to current `main`**: its most recent commit references predate roughly 50 commits now merged (PR #509's crate split, the entire wasm-ui view-porting series, PR #544, PR #545, PR #547). This is itself a minor, disclosed documentation-drift finding — not treated as invalidating the ledger's substance, which remains the correct historical record for everything it covers.

## 5. Retention manifest (credentials/keys)

Three surfaces cross-checked:

| Surface | Count |
|---|---|
| `.env.example` (documented `_KEY` vars, commented as examples) | 47 |
| `src/cli/env_template.txt` (full provisioning template, includes non-key config) | 61 |
| `src/util/keys/constants.rs` `KNOWN_KEYS` (unique `HUNTSMAN_*` names) | 54 |

No credential *values* exist in the tree (all three surfaces hold variable names/documentation only, consistent with `.gitleaks.toml`'s clean CI runs this session). The count differences across the three surfaces are expected in kind (one is operator-facing documentation, one is the full provisioning template including non-key settings, one is the internal registry) but were not individually reconciled name-by-name in this run — flagged as a candidate for a future dedicated pass, **not** established as a defect, since the existing test suite (`src/util/keys/tests.rs`, green on current HEAD) already exercises this wiring and no reachable inconsistency was found.

## 6. Enforcement — the "one command verifies everything" invariant

`scripts/gate.sh` already **is** the local gate runner the directive's step 29 calls for: `cargo fmt --check`, `cargo check`/`clippy -D warnings`/`cargo test`/doctests/doc-coverage for both the root crate and (as of PR #544, this session) `hse-core` + `wasm-ui`, MSRV check, the `aarch64-linux-android` cross-build, `install.sh` + shellcheck, and `cargo audit`/`deny`/`machete`/`dep-cooldown` (as of PR #544, extended to all four `Cargo.lock` files in the tree). It has been run to completion, green, multiple times this session.

**One genuine, disclosed gap**: `gate.sh` does not currently regenerate `wasm-ui/pkg/` from source and diff it against the committed copy on every run (the directive's "round-trip drift check"). This run manually proved the round-trip once (Artifact Ledger, above) but did not wire it into the automated gate, because doing so requires `wasm-bindgen-cli` and `binaryen` as gate dependencies neither `scripts/gate.sh` nor CI currently installs — a real, scoped, follow-up-worthy addition, recorded honestly as still open rather than silently added without the same verification rigor the rest of this gate already has.

## 7. Final deliverable scope — what this run can and cannot honestly claim

The directive's completion bar includes a single self-contained zip with **preassembled prebuilt binaries for the project's actual shipped target** (Termux/`aarch64-linux-android`) and a dual-mode, hermetic, cold-start verification.

- **MODE 1 (offline vendored build)**: achievable and verified in this sandbox — `cargo vendor` was run across all four manifests (543 MB, 448 packages), and an offline (`--offline --locked`, vendored-sources-only) build was executed and verified against the fully vendored tree (see `run/offline_build_result.txt`).
- **MODE 2 (prebuilt binary, no build step)**: **partially achievable from this sandbox**. This sandbox has no Android NDK (the same, pre-existing, disclosed limitation `scripts/gate.sh` has always reported for its own `aarch64-linux-android` cross-build step — "CI is the authority for the skipped ones"), so a genuine `aarch64-linux-android` binary — the project's *only* actual shipping target — cannot be cross-compiled or verified here. Shipping an x86_64 binary as if it were the deliverable would misrepresent the artifact for a project whose entire premise is Termux/Android; this run will not do that. The honest disposition: the deliverable ships the vendored source (build-verified in this sandbox) and defers the prebuilt-binary half of MODE 2 to CI, which already builds and has verified this exact artifact class on every recent PR merged this session.

This is disclosed here, in the run state, and in the final report — not silently omitted and not fabricated as complete.
