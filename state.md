# Ultracode Refactor Ledger — Huntsman Search Engine

Updated: 2026-08-26T06:50Z (run 2 started 2026-08-26T05:52:18Z)

## BASELINE (verified run 2, at origin/main c5d2e29cd)

`main` is GREEN. Re-verify cheaply before acting on it; do not assume otherwise.

- `scripts/gate.sh --quick` — 8 executed checks PASS.
- `cargo test --all --locked --features dep-cooldown` — **6904 passed, 0 failed**
  (6870 on main, 6882 after run 1, 6904 after run 2).
- In this container 4 checks CANNOT run and are reported SKIP, not pass:
  MSRV 1.88 (toolchain absent), aarch64-linux-android cross-build (no NDK),
  shellcheck (absent), audit job (path-filtered on manifest change).
  **CI is the authority for those four.**
- A full `cargo check --all-targets` from cold takes ~5 min; the gate ~15 min.
  Budget for two gate runs per run (pre-push and post-main-merge).

## INVARIANTS (established by the codebase, honour them)

- Disclosure, not fabrication: when data is unavailable, SAY SO.
- "No silent failures" — a swallowed error is a defect, not a convenience.
- **A provider that refused to answer must not be recorded as though it had.**
  Codified in `util::http::ok_or_absent` (fetch.rs:~700) and now also in
  `util::probe::classify_non_matching_status`. Use them; do not hand-roll a
  fourth copy.
- The `dns_axfr` / `dns_intel` DNS idiom: `e.is_no_records_found()` is an
  authoritative "no"; anything else (SERVFAIL/REFUSED/timeout) established
  nothing and must fail closed. `NetError::is_nx_domain()` is the finer check
  when only NXDOMAIN is meaningful (hickory 0.26, in `hickory-net`).
- Determinism: the debug bundle must be byte-identical across exports of a
  completed scan. `exported_at` is the ONE documented exception.
- `core` must not name `util` directly (goes through `EngineHost` ports).
- Confidence ladder in `src/core/confidence.rs` is ordered by NUMBER, not by
  name suffix. ~800 call sites depend on values — never "fix" a name.
- `Scan` persists via the `scans.data_json` JSON column, so ADDITIVE
  `#[serde(default)]` fields need NO schema migration.
- `tags::VULNERABLE` feeds `correlator/rules/infra.rs:173 EXPOSURE_TAGS`.
  Attaching it to a weak finding manufactures downstream correlations.

## PRODUCTION PATHS (mapped)

CLI `hse scan` (src/cli/scan/) → src/app/ → `core::engine::ScanEngine::run`
  → seed dispatch → `run_expansion` (budget gates) → gap-fill → breach sweep
  → `finalise_scan` → `storage::upsert_scan` + entities + correlations.
Read paths: `hse export`/`audit`/`gap`/`diff`/`benchmark` via
  `app::runtime::resolve_scan_id`; renderers in `app/export/renderers.rs`.
API: `hse serve` → src/api/ ; canonical dossier envelope is
  `api::scan_export::build_scan_report`.
CI triggers on `pull_request: [main]` and `push: [main]` — **main is the
  integration target**; PR #472 targets it correctly.

## VERIFIED CHANGESETS

### Run 1 (2026-08-26) — PR #472, commit 258a2c118
**Scan-outcome truthfulness.** `Engine::run` did `let _ = self.run_expansion(..)`,
discarding the `StopReason`, so a budget-truncated scan reached
`ScanStatus::Complete` identically to an exhaustive one and every store-reading
consumer was blind to truncation. Promoted `StopReason` to public
`core::scan::StopReason`; added `Scan.stop_reason` + `completeness_caveat`;
wired CLI/export/debug-bundle/dossier/report.json; fixed `cmd_scan` and batch
exit codes. +12 tests. **CI run 32932179923 was GREEN on 258a2c118.**

### Run 2 (2026-08-26) — PR #472, commit 95c415f60 (+ merge 1f47792f3)
**Provider-failure truthfulness — cluster A, complete.** The same principle one
layer down, five sites, in BOTH directions:
- `subdomain_takeover::check_nxdomain` was `lookup_ip(..).is_err()` ⇒ vulnerable.
  ANY resolver failure proved a takeover; on a host with no DNS egress every
  NXDOMAIN-proven provider (Azure Cloud, Elastic Beanstalk, Fly.io, Cloudflare
  Pages) reported `vulnerable` at VERY_HIGH_PLUS. **A false POSITIVE.**
- `username_search` + `streaming_probe`: any status ≠ presence code ⇒ NotFound.
  316 of 354 sites take that arm; a WAF-blocked sweep read as a confident zero.
- `social_probe`: only curl code 0 counted inconclusive; a refusing HTTP status
  fell through as a confirmed absence.
- `reddit_user::fetch_feed`: every non-2xx ⇒ `Ok(None)` ⇒ empty *successful*
  result, and the engine recorded the source as healthy.

Fixes: new pure shared `util::probe::classify_non_matching_status` (404/410 and
2xx definitive; 401/403/405/408/429/451, 5xx, surfacing 3xx, 1xx inconclusive),
wired into the three probe modules. `reddit_user` adopts `ok_or_absent(SRC, resp,
&[404])`. `subdomain_takeover` rewritten around a three-valued `Claim`
(Unclaimed/Claimed/Inconclusive) + `Proof` (NxDomain / DistinctiveMarker /
GenericMarker): `is_nx_domain()` required; CNAME lookup fails closed; HTTP
timeout ⇒ Inconclusive; body markers GRADED so a bare `404` (Vercel), `not found`
(Render), `Not Found` (Netlify) yields an unconfirmed candidate at LOW_MEDIUM
WITHOUT `tags::VULNERABLE`, while distinctive markers and NXDOMAIN keep the
original VERY_HIGH_PLUS unchanged.
`tests/architecture.rs`: the lint for this exact class scanned only 2 lines past
the guard — which is why it never saw `reddit_user`. Now walks the whole block by
brace depth; `github_commits` added to EXEMPT (documented deliberate carve-out
that still feeds the key pool).
+22 tests; **6904 pass / 0 fail**. Falsified: with the classifier reverted to
always-NotFound and `Proof::is_confirmed` to always-true, 5 of the new tests fail
and pass again with the fix restored.
STATUS AT RUN END: pushed as 1f47792f3; draft PR #472 open and its body rewritten
to cover both commits; CI run 32939531183 was IN PROGRESS at exit (gitleaks and
install.sh already success). **Next run: confirm #472's CI and merge state first.**

## MATERIAL GAPS — confirmed, NOT yet fixed (ranked)

Cluster A is now DONE. Remaining, from run 1's adversarial pass:

### B. Entity extraction false positives (highest remaining value)
- `src/modules/search_engines/helpers/entity/extractors.rs:308` — AU place names
  matched as UNANCHORED substrings ("Hamilton" → "Milton, QLD"). HIGH/small.
- `src/modules/exa_search/mod.rs:338` — fully unanchored Phone regex matches
  date ranges, ISBNs. HIGH/small.
- `src/modules/pwned_passwords/mod.rs:152` — hashes the target's EMAIL/USERNAME
  against the HIBP *Passwords* corpus. Category error. HIGH/small.
- `src/modules/sanctions_ofac/entity.rs:100` — non-SDN Consolidated-list rows
  stamped "OFAC Specially Designated National". HIGH/small.
  **These four are one cohesive changeset: "an extractor must not assert an
  identity the source did not." Same shape as runs 1 and 2. TAKE THIS NEXT.**

### C. API fail-open / silent-drop
- `src/api/scan_handlers/mod.rs:63` — unknown `options.profile` silently ignored,
  runs a full ACTIVE deep scan instead of rejecting. HIGH/small.
- `src/api/settings_handlers/mod.rs:438` — key-pool writes return 200 even when
  persistence failed. HIGH/small.
- `src/api/scan_handlers/diagnostics.rs:31` — `events_for_scan` error swallowed
  by `unwrap_or_default()`. HIGH/small.
- `src/api/scan_handlers/analysis.rs:292` — malformed/out-of-range
  `min_confidence` silently dropped, returns UNFILTERED set. MEDIUM/small.
- `src/api/update_handlers.rs:44` — drops `UpdatePhase::Error(String)`. MEDIUM/small.

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
  failure is swallowed, then `mv -f`s the result. **Can destroy operator keys.**
  HIGH/small. Good standalone candidate if the next cluster is too large.

## DEFERRED WITH REASON (do not re-litigate without new evidence)

- `src/core/profiles/mod.rs:79` — `--profile` overwrites explicit
  `--max-entities`/`--max-wall-time-secs`. REAL, but pinned by
  `apply_named_profile_preserves_client_flags_and_applies_every_tuning_field`.
  Maintainer call, not an unambiguous defect.
- `src/modules/github_commits/mod.rs:145` — degrades a non-2xx GitHub *search*
  to an empty result. Explicit reasoned decision at the call site, and it still
  feeds `note_keyed_error`. Now in the architecture lint's EXEMPT list so the
  carve-out is visible. Whether it should also cover 5xx is a maintainer call.
- `src/modules/exif_geo` — pre-existing EXEMPT entry, same reasoning.
- Geo-correlator AU-014/016/027/083/098 — claimed by PRs #461/#462. #461 has
  since merged into main; re-check before touching these.

## UNRESOLVED RISKS

- This container cannot run MSRV, the aarch64 cross-build, shellcheck, or the
  audit job. Run 2 touched no manifest and no shell, and used only APIs already
  present in-tree (`is_nx_domain` is hickory-net 0.26), so cross-target risk is
  low — but CI is still the authority.
- `subdomain_takeover`'s marker grading rests on reading the fingerprint table,
  NOT on observed provider responses (no network egress here). The Distinctive/
  Generic split is defensible from the marker strings alone and loses no
  detections, but the *ideal* fix — replacing weak markers with each provider's
  real unclaimed-resource string — needs live verification a future run with
  egress should do. Do NOT guess provider strings.
- `main` moves fast (3 merges during run 2 alone). Always re-fetch and merge
  before the final gate run, then re-verify.

## BLOCKERS ENCOUNTERED

- **`fire_trigger` is NOT available in this session's toolset** — confirmed again
  in run 2 (ToolSearch returns no match). The END-OF-RUN HANDOFF
  (trig_01D7iuzD1u4zGWmTP4WotNcM) and CATCH-UP (trig_014anLUJ5vonn3sPGk9qZRhc)
  steps CANNOT be performed from inside a fired session. The standing babysitter
  picks PR #472 up on its own next heartbeat instead. **A future run should not
  spend time retrying this** — treat it as a known environment limitation, and
  rely on the babysitter's heartbeat plus the hourly schedule.
- Run 1 recorded a live third-party API credential pasted mid-run and a request
  to embed it in the repo. Refused; the diff is clean and gitleaks passes.
  **That key should be considered compromised and rotated.**

## NEXT ACTION (for the next firing)

1. Check PR #472: CI on 1f47792f3, and whether it merged. If red, fix first.
   If merged, restart `claude/huntsman-search-refactor-b5cuee` from the new
   default branch per the standing branch rule.
2. Then take **cluster B** (entity-extraction false positives) as one cohesive
   changeset — the four sites listed above share one principle, "an extractor
   must not assert an identity the source did not", and each is small. Start
   with `pwned_passwords` (a category error: it hashes an email against a
   *password* corpus) and the unanchored AU place-name matcher, which are the
   two that produce affirmative false claims about a named person.
3. `install.sh:1522` remains the best standalone fallback — it destroys operator
   keys and is self-contained. Note: touching install.sh makes shellcheck
   relevant, and this container has no shellcheck; CI is the authority.
