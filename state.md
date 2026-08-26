# Ultracode Refactor Ledger — Huntsman Search Engine

Updated: 2026-08-26T05:12Z (run started 2026-08-26T03:52:28Z)

## BASELINE (verified this run, at origin/main 60824b0)

`main` is GREEN. Do not assume otherwise; re-verify cheaply before acting on it.

- `cargo check --all-targets --locked --features dep-cooldown` — clean
- `cargo fmt --all -- --check` — clean
- `cargo clippy --all-targets --locked --features dep-cooldown -- -D warnings` — clean
- `cargo test --all --locked --features dep-cooldown` — **6870 passed, 0 failed**
- `scripts/gate.sh` is the canonical gate (mirrors CI across 6 workflow files).
  In this container 4 checks CANNOT run and are reported SKIP, not pass:
  MSRV 1.88 (toolchain absent), aarch64-linux-android cross-build (no NDK),
  shellcheck (absent), audit job (path-filtered on manifest change).
  **CI is the authority for those four.**

## INVARIANTS (established by the codebase, honour them)

- Disclosure, not fabrication: when data is unavailable, SAY SO; never invent
  or imply completeness. Stated in `Scan::module_accounting_line` and
  `partial_export_reason` docs.
- "No silent failures" — a swallowed error is a defect, not a convenience.
- Determinism: the debug bundle must be byte-identical across exports of a
  completed scan. `exported_at` in report.json is the ONE documented exception.
  `export_formats_determinism_audit` pins this.
- `core` must not name `util` directly (goes through `EngineHost` ports).
- Confidence ladder in `src/core/confidence.rs` is ordered by NUMBER, not by
  name suffix. `MEDIUM_HIGH`(0.55) < `MEDIUM_PLUS`(0.60); `VERY_HIGH`(0.75) <
  `HIGH_PLUSPLUS`(0.80). ~800 call sites depend on the values — never "fix" a name.
- `Scan` persists via the `scans.data_json` JSON column, so ADDITIVE
  `#[serde(default)]` fields need NO schema migration. Verified this run.

## PRODUCTION PATHS (mapped)

CLI `hse scan` (src/cli/scan/) → src/app/ → `core::engine::ScanEngine::run`
  → seed dispatch → `run_expansion` (budget gates) → gap-fill → breach sweep
  → `finalise_scan` → `storage::upsert_scan` + entities + correlations.
Read paths: `hse export`/`audit`/`gap`/`diff`/`benchmark` via
  `app::runtime::resolve_scan_id`; renderers in `app/export/renderers.rs`.
API: `hse serve` → src/api/ ; canonical dossier envelope is
  `api::scan_export::build_scan_report` (shared by GET report.json and
  `hse export --format report`).

## VERIFIED CHANGESETS

### Run 1 (2026-08-26) — PR #472, branch claude/huntsman-search-refactor-b5cuee
**Scan-outcome truthfulness, end to end.** Commit 258a2c118.
A scan truncated by `max_entities`/`max_wall_time_secs` reached
`ScanStatus::Complete` identically to an exhaustive one, because
`Engine::run` did `let _ = self.run_expansion(...)`, discarding the
`StopReason` (which only ever reached the live SSE `ExpansionStop` event).
Every store-reading consumer was therefore blind to truncation.
- Promoted `StopReason` to public serializable `core::scan::StopReason` with
  `truncated()`; added `Scan.stop_reason` (`#[serde(default)]`, no migration)
  and `Scan::completeness_caveat(subject)` as the single disclosure source.
- Engine captures + threads the reason into `finalise_scan` (recorded on every
  terminal path); finalise inputs bundled into `ScanOutcome` (arg-count lint).
- Wired: CLI table/json/dossier, `partial_export_reason` (export + debug
  bundle), `app::runtime::scan_incompleteness_warning`, report.json.
- Exit codes: `cmd_scan` no longer returns `Ok(())` for a Failed scan; batch
  mode no longer exits 0 when seeds failed.
- Gate green; **6882 pass / 0 fail** (+12 new tests).
STATUS AT RUN END: pushed; draft PR #472 open; **CI run 32932179923 GREEN —
all 4 jobs success on commit 258a2c118**: Check & test (Linux x86_64 stable),
MSRV (1.88), Build (aarch64-linux-android Termux target, incl. test compile),
install.sh syntax (bash + shellcheck). That covers all four checks this
container could not run locally, so the changeset is fully verified.
Awaiting the babysitter to mark ready + auto-merge. **Next run: confirm #472
merged; if it is still open and red, fix it before starting new work.**

## MATERIAL GAPS — confirmed by adversarial verification, NOT yet fixed

29 candidates found, 28 survived independent refutation. Ranked clusters:

### A. Provider failure masquerading as a negative/positive result (HIGHEST VALUE)
Same principle as run 1's changeset, one layer down. A cohesive next pathway.
- `src/modules/username_search/mod.rs:175` — every non-200 (403 WAF, 429, 5xx)
  classified as a definitive "username not found". HIGH/small.
- `src/modules/reddit_user/mod.rs:263` — 403/429/5xx → clean empty result. HIGH/small.
- `src/modules/subdomain_takeover/mod.rs:167` — ANY DNS error (timeout,
  SERVFAIL, no egress) treated as proof of takeover. **False POSITIVE.** HIGH/small.
- `src/modules/subdomain_takeover/mod.rs:227` — claimed Vercel/Netlify/Render
  site reported VULNERABLE. HIGH/small.

### B. Entity extraction false positives
- `src/modules/search_engines/helpers/entity/extractors.rs:308` — AU place names
  matched as UNANCHORED substrings ("Hamilton" → "Milton, QLD"). HIGH/small.
- `src/modules/exa_search/mod.rs:338` — fully unanchored Phone regex matches
  date ranges, ISBNs. HIGH/small.
- `src/modules/pwned_passwords/mod.rs:152` — hashes the target's EMAIL/USERNAME
  against the HIBP *Passwords* corpus. Category error. HIGH/small.
- `src/modules/sanctions_ofac/entity.rs:100` — non-SDN Consolidated-list rows
  stamped as "OFAC Specially Designated National". HIGH/small.

### C. API fail-open / silent-drop
- `src/api/scan_handlers/mod.rs:63` — unknown `options.profile` silently ignored,
  runs a full ACTIVE deep scan instead of rejecting. HIGH/small.
- `src/api/settings_handlers/mod.rs:438` — key-pool writes return 200 even when
  persistence failed. HIGH/small.
- `src/api/scan_handlers/diagnostics.rs:31` — `events_for_scan` error swallowed
  by `unwrap_or_default()`. HIGH/small.
- `src/api/scan_handlers/analysis.rs:292` — malformed/out-of-range
  `min_confidence` silently dropped, returns UNFILTERED set. MEDIUM/small.
- `src/api/update_handlers.rs:44` — drops `UpdatePhase::Error(String)` payload. MEDIUM/small.

### D. Storage / concurrency
- `src/storage/mod.rs:827` — correlation containment dedup DELETES a valid
  AU-060 transitive finding nested inside a longer path. HIGH/medium.
- `src/storage/mod.rs:224` — `Store::open` DROPs+re-CREATEs rf_* views outside
  any transaction; a concurrent reader can see them missing. MEDIUM/small.
- `src/util/raw_archive/config.rs:7` — process-local sequence counter +
  truncating open; two processes overwrite each other's archives. MEDIUM/small.
- `src/util/settings/mod.rs:63` — settings.json written from a start-up cache,
  so a long-lived `hse serve` clobbers external edits. LOW/small.

### E. Other
- `src/util/scraper_health.rs:166` — quarantine misreads normal per-target
  zero-yield as parser drift, benching healthy modules. HIGH/small.
- `install.sh:1522` — rewrites ~/.huntsman.env from a `grep … || true` whose
  failure is swallowed, then `mv -f`s the result. **Can destroy operator keys.** HIGH/small.

## DEFERRED WITH REASON (do not re-litigate without new evidence)

- `src/core/profiles/mod.rs:79` — `--profile` overwrites the operator's explicit
  `--max-entities`/`--max-wall-time-secs`. REAL, but current behaviour is pinned
  by `apply_named_profile_preserves_client_flags_and_applies_every_tuning_field`,
  which asserts the overlay applies EVERY tuning field. Whether profile-beats-
  explicit-flag is intended is a maintainer call, not an unambiguous defect.
- Geo-correlator AU-014 / AU-016 / AU-027 / AU-083 / AU-098 — confirmed HIGH,
  but **already claimed by open PRs #461 and #462**. Do not duplicate; check
  whether those merged first.

## UNRESOLVED RISKS

- This container cannot run MSRV, the aarch64 cross-build, shellcheck, or the
  audit job. Anything touching those surfaces is unverified locally.
- Many sibling `claude/*` branches and ~10 open PRs target `main`; expect
  divergence. Re-fetch and rebase/merge before assuming a clean base.

## BLOCKERS ENCOUNTERED THIS RUN

- **`fire_trigger` tool is NOT available in this session's toolset.** The
  END-OF-RUN HANDOFF (trig_01D7iuzD1u4zGWmTP4WotNcM) and CATCH-UP
  (trig_014anLUJ5vonn3sPGk9qZRhc) steps could not be performed. The standing
  babysitter will pick PR #472 up on its own next heartbeat instead.
  A future run should not treat this as fixable from inside the session.
- A mid-run message pasted what appeared to be a live third-party API
  credential (a live-mode secret-key prefix) and asked for API keys to be
  "preserved and embedded" in the repo. Refused — embedding a secret would
  publish it and the repo runs gitleaks/secret-scanning. The diff was scanned
  and is clean. **That key should be considered compromised and rotated.**

## NEXT ACTION (for the next firing)

1. Check PR #472 CI. If red, fix before anything else. If merged, note it.
2. Then take **cluster A** (provider failure-as-result) as one cohesive
   changeset — it is the same invariant as run 1, at the module layer, and is
   the highest verified value remaining. Suggested shape: one shared helper
   that turns a non-2xx/transport failure into an explicit "unknown" outcome
   rather than a negative, then wire `username_search`, `reddit_user` and
   `subdomain_takeover` onto it, with the takeover DNS-error path (a false
   POSITIVE) first.
3. `install.sh:1522` is small and destroys operator keys — good standalone
   candidate if cluster A is too large for one run.
