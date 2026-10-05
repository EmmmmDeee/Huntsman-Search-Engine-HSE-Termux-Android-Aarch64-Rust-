# Rust Migration & Remediation Audit — 2026-08-27 (branch `claude/huntsman-consolidation-czrqs1`)

## Executive summary

This run was scoped as a full legacy-codebase-to-Rust migration with
end-to-end remediation. **Phase 0 found the codebase already 100% Rust**
(v1.40.0, single-package workspace, `#![forbid(unsafe_code)]` crate-wide, no
non-Rust implementation anywhere in git history). This finding was reached
**independently and simultaneously by a concurrent session** on a separate
branch (`claude/migrate-codebase-rust-qen2pn`, PR #483) — both sessions were
given the same task against this repository at the same time. Cross-checking
two independent audits reaching the identical conclusion is stronger evidence
than either alone.

Per the run's own "adapt strategy to the code as actually found" instruction,
the MIGRATION LOOP (Phase 0 §2 batching, characterization tests, FFI/interop
bridging) is a no-op — there is no legacy implementation to port, and no
"half-Rust, half-legacy" state to bridge. This document and the
REMEDIATION LOOP work landed on this branch instead deliver what the
mandate's Phase 0 and completion criteria actually call for: an audit,
a retention manifest, an issue census, and end-to-end remediation of every
issue found, against the codebase as it actually exists.

## Architecture map (as found)

- **Language**: 100% Rust, edition 2024, single package (`huntsman-search-engine`
  v1.40.0) plus one auxiliary crate (`fuzz/`, a `cargo-fuzz` harness with its
  own `Cargo.toml`/`Cargo.lock`).
- **Safety posture**: `#![forbid(unsafe_code)]` at the crate root — no
  `unsafe` block exists anywhere in `src/`. This eliminates the entire
  "reflection / unsafe FFI / raw pointer" risk class Phase 0 step 2 asks to
  flag for special handling.
- **Toolchain**: pinned via `rust-toolchain.toml` (1.97.1, `rustfmt` +
  `clippy` components, `aarch64-linux-android` target), mirrored in
  `.github/workflows/ci.yml` so local and CI toolchains cannot silently
  diverge.
- **Module system**: 182 self-contained OSINT/GEOINT provider modules under
  `src/modules/`, each implementing a shared `Module` trait
  (`src/core/module/mod.rs`), dispatched through one registry
  (`src/modules::registry()`). No dynamic dispatch beyond this one
  intentional trait-object seam; no reflection, no runtime codegen, no
  eval/metaprogramming beyond ordinary declarative macros.
- **Concurrency**: `tokio` async runtime, bounded worker/blocking thread
  pools (`WORKER_THREADS`, `MAX_BLOCKING_THREADS` — pinned constants,
  test-asserted). Shared mutable state is confined to a small number of
  explicit, documented seams: the key pool (`util::key_pool`, behind a
  `Mutex`), the module-health/quarantine tracker
  (`util::scraper_health`), and the SQLite storage layer
  (`storage::Store`, a `dyn`-safe trait per
  `storage_port_is_object_safe`'s own architecture test). No unguarded
  global mutable state.
- **Storage**: SQLite via `rusqlite`, one `Store` trait
  (`src/core/storage_port` equivalent) so the concrete backend is swappable
  and app/composition code (`src/app`) is the only layer that constructs it
  — enforced by architecture tests (`modules_do_not_import_engine_or_storage`,
  `util_does_not_import_upper_layers`).
- **Interop / platform-specific calls**: Termux-specific sensor/telephony
  probes (`src/modules/termux_sensor.rs` and consumers) shell out to
  `termux-*` CLI tools via `tokio::process::Command`, failing closed (empty
  result) when the binary is absent — this is the one deliberate
  "platform-specific call" surface Phase 0 step 2 asks to flag, and it is
  already isolated behind a single narrow module rather than scattered.
- **Build/CI surface**: `.github/workflows/{ci,rust-clippy,fuzz,audit,
  secret-scan,bench-smoke,live-drift,release}.yml` plus a single local
  entry point, `scripts/gate.sh`, that runs every check CI runs (fmt,
  clippy `-D warnings`, rustdoc lints, full test suite, doctests, a
  doc-coverage ratchet, install.sh syntax, MSRV, the `aarch64-linux-android`
  cross-build) so a contributor never has to reconstruct CI's actual scope
  from the workflow YAML by hand.

## High-risk constructs flagged (Phase 0 step 2)

| Construct | Finding |
|---|---|
| Reflection / eval / metaprogramming | None found beyond ordinary `macro_rules!`/derive macros. |
| Dynamic dispatch | One intentional, tested seam: `dyn Module`, `dyn Storage`-equivalent. No untested/undocumented trait objects. |
| Threading / shared mutable state | Tokio-managed, bounded pools; mutable state confined to `key_pool`, `scraper_health`, `storage::Store`, each behind its own sync primitive. |
| Platform-specific calls | Isolated to `termux_sensor` and its consumers; fails closed off-Termux. |
| `unsafe` | Zero — `#![forbid(unsafe_code)]` crate-wide. |

None of these required special migration handling, since there is no
migration — they are noted here as the Phase-0-mandated risk inventory of
the codebase as it stands.

## Retention manifest

Full per-key audit (method, findings, and every `HUNTSMAN_*` variable's
consumer/documentation status) is in this session's workflow output and
summarized in the commit messages of:

- `fix(keys): route opencellid/cell_intel/abn_lookup through resolve_key's placeholder filter`
- `fix(see_know): document SeekNow email/password fallback; filter its placeholder`
- `docs: document 14 orphaned-but-functional HUNTSMAN_* operational vars`

**Headline findings, all remediated on this branch:**

1. Three modules (`opencellid`, `cell_intel`, `abn_lookup`) read their API
   key via a raw accessor that bypassed the shared placeholder filter, so an
   unedited `hse provision` template's literal `insert_..._here` string
   would have been forwarded to the live provider API as a credential
   instead of triggering a clean skip. **Fixed**, with regression tests
   where the module's own execution path is testable without live
   Termux hardware.
2. `HUNTSMAN_SEEKNOW_EMAIL`/`HUNTSMAN_SEEKNOW_PASSWORD` — a real plaintext
   credential pair for a browser-automation login fallback — existed with
   zero documentation anywhere an operator would look, and had no
   placeholder filter at all. **Fixed**: documented as an optional
   (never-auto-provisioned) entry, filter added, regression test added.
3. 14 further `HUNTSMAN_*` operational/tuning vars were real, wired, and
   functioning but absent from both provisioning-surface files. **Fixed**:
   documented in `.env.example` with source-verified (not guessed) default
   values.
4. One credential — a live-shaped SeekNow API key committed to
   `.agent/state.json` roughly 17 days prior — was found leaked into
   git-tracked history. **Fixed**: redacted in place after tagging a local
   recovery point, `.gitleaks.toml` detection gap closed, full writeup in
   `docs/CREDENTIAL_AUDIT_2026-08-27_czrqs1.md`. This was found and fixed
   independently on the concurrent session's branch too (see that PR's own
   `docs/CREDENTIAL_AUDIT_2026-08-27.md`); both branches now carry
   equivalent fixes, since this branch forked before the other's redaction
   commit and so still carried the live value.

No hardcoded/literal API key values were found anywhere in non-test source
for any of the ~65 keyed providers this codebase integrates.

## Issue census results

- **Compiler/linter warnings**: zero (`cargo check --all-targets`, `cargo
  clippy --all-targets -- -D warnings`). One `cargo doc` warning
  (redundant explicit link target) found and fixed.
- **TODO/FIXME/HACK/XXX markers**: zero real occurrences. All 10 raw text
  matches are literal placeholder text inside phone-number/tracking-ID
  format documentation (e.g. `UA-XXXXXXX-X`), not debt markers.
- **Ignored/skipped tests**: 24 real `#[ignore]` attributes, every one
  documented with a reason (live-network dependency or perf-baseline —
  matching this repo's own established `--ignored`/live-drift-workflow
  convention). Zero unexplained skips.
- **`cargo audit`**: zero live vulnerabilities. One `unmaintained` advisory
  (`RUSTSEC-2024-0436`, the `paste` crate) — pre-existing, already carries a
  written justification in `deny.toml` (transitive-only, `--all-features`
  only, no viable replacement upstream, removal trigger documented).
- **`cargo deny check`**: clean (advisories/bans/licenses/sources all ok).
- **`cargo machete`**: zero unused dependencies.
- **`fuzz/Cargo.lock`**: found genuinely stale (verified: restoring it and
  running `cargo check --locked` in `fuzz/` failed outright). Regenerated
  minimally (additive-only diff, not a full re-resolve) and reverified.
- **Doc coverage ratchet** (`scripts/doc_coverage.sh`): held at baseline
  throughout this run's changes; the pre-existing baseline itself was
  already lowered to 1051 (from 1064) by earlier work on this branch, with
  its arithmetic corrected against a fresh measurement rather than trusted
  from an earlier PR's stale claim.
- **Open PRs (tracker items)**: 17 open pull requests at time of writing;
  this repo tracks all in-flight work through PRs and carries zero open
  GitHub Issues. This branch's own prior commits (see git log) already
  cherry-picked and independently re-verified the genuinely valuable,
  still-applicable content from most of them. Closing/commenting on the
  now-superseded ones requires GitHub write access this session did not
  have (see "Known risks / blockers" below) — recorded as a follow-up.

## Gate results

`scripts/gate.sh --quick` (fmt, check, clippy `-D warnings`, rustdoc lints,
full test suite, doctests, doc-coverage ratchet, install.sh syntax): **8/8
executed checks PASS**, run repeatedly across this branch's commits, most
recently after every remediation fix. MSRV and the `aarch64-linux-android`
cross-build are correctly SKIPPED in this sandbox (no MSRV 1.88 toolchain,
no Android NDK installed) — CI is authoritative for those, per the script's
own documented design.

`cargo audit`, `cargo deny check`, and `cargo machete` were run directly
(not just via gate.sh's CI-optimized skip path) to get real, current data
rather than trusting the "no manifest change" skip reasoning alone —
results summarized above.

## Known risks / external blockers

- **GitHub write access unavailable this session.** Both `git push` (over
  HTTPS) and the GitHub API's write endpoints (`git/trees`,
  `contents/{path}`) returned 403/"Resource not accessible by integration"
  throughout this run, despite read access and (earlier in this session,
  before the access regression) PR creation/merge having worked. All work
  is committed locally on this branch; nothing is lost, but it cannot be
  pushed, and the 17 open PRs this branch's history addresses cannot be
  closed/commented from here. The final zip deliverable's git bundle
  preserves full history so this is recoverable the moment access is
  restored.
- **Shared working tree**: this container's checkout was observed being
  switched to `main` and back to this branch by processes outside this
  session's own actions at least twice during this run (confirmed via
  `git reflog` and independently corroborated by two of the workflow
  audit's own sub-agents). Every commit in this branch's history was
  verified against `git branch --show-current` immediately before
  committing to guard against this; no commit landed on the wrong branch
  as a result, but it is worth flagging to whoever manages this
  environment's session pool.
- **`cell_intel`'s placeholder-filter fix is not independently
  end-to-end-testable** in this sandbox: its `process()` reads a live
  Termux hardware sensor before reaching the fixed code path, and returns
  early with no sensor binary present. The fix is a one-line delegation to
  an already-exhaustively-unit-tested pure function
  (`resolve_key`/`resolve_key_policy`), so it is review-verified rather
  than independently test-verified — the same documented tradeoff this
  codebase already accepts elsewhere for HTTP-mock-free modules.
- **`HUNTSMAN_SEEKNOW_EMAIL`/`_PASSWORD` are not registered in
  `KNOWN_KEYS`** (the Settings-UI paste grid), left as a follow-up: that
  grid's UX assumptions are built around API-key strings, and a plaintext
  password may warrant different handling (masking, etc.) that is a design
  decision outside a documentation fix's scope.
