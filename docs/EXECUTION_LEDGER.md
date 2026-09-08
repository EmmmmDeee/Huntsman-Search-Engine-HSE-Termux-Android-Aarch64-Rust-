# Execution ledger — canonicalisation & assurance programme

The durable checkpoint for the autonomous upgrade programme: what is verified,
what is assumed, what remains, and exactly how to resume. Updated at every
material milestone so interrupted work resumes from the last verified state
without repeating completed work. Every claim here is tied to a commit, a gate
run, a CI head, or a runtime check — `CLAIM ≠ EVIDENCE` applies to this file too.

## 1. Current state (checkpoint)

| Item | Value |
|---|---|
| `main` | `2769a606` at the time this unit's branch was restarted — 14 commits ahead of the `59a5ae01` this ledger last checkpointed (`545b085f`→`2769a606`: PRs #607–#620, a **separate concurrent workstream** — the requirements-ledger pass series and a pipe-delimited-CSV consolidation — not tracked unit-by-unit here since they are outside this ledger's breach-ingest/pseudo-recursion scope; `git log --oneline 545b085f..2769a606` on `origin/main` is the authority for their detail). Full lineage of the earlier tracked units in §5 |
| Programme baseline (before) | `cab1f9b4` (HSE v1.41.0, MSRV 1.98, edition 2024) |
| Working branch | `claude/response-accuracy-legal-u90ja3`, restarted at `2769a606` (`origin/main`) — the branch's prior PR history was already merged/closed, so this run restarted it fresh per the routine's own instructions |
| In-flight unit | none — clean checkpoint. An **hourly ultracode routine** (a fresh session per fire, owner-controlled) autonomously carries the **breach-file-ingest** and **pseudo-recursion-optimisation** objective, one gate-green unit per run, holding when nothing material remains (§4) |
| GitHub | 0 open issues; 0 open pull requests (the 16 stale programme PRs were closed with per-PR evidence — §5) |
| Toolchain | rustc 1.98. `scripts/gate.sh --quick` skips exactly three checks — MSRV, the aarch64 cross-build / cross-test-compile and the wasm-ui/pkg drift check — for which CI is the authority. Everything else runs as CI does, each under its own condition: root crate fmt / check / clippy `-D warnings` / rustdoc lints / test / doctests / doc coverage; hse-core fmt / clippy / rustdoc / test; wasm-ui fmt / clippy / native test; `install.sh` syntax; shellcheck when installed; the cargo-audit / deny / machete / dep-cooldown family only when a manifest changed (audit.yml's path filter) and the tools are present. That is 16 executed checks for a non-manifest change when shellcheck is installed, 15 when it is not (this run's sandbox: shellcheck absent, so 15/15 passed; the audit family correctly skipped either way). The drift check also runs locally through `scripts/wasm_ui_drift_check.sh` once the pinned chain is installed (§8) |

## 2. Verified facts (with evidence)

- Every unit below passed `scripts/gate.sh --quick` before its push, and every
  merged head is CI-green (Check & test, MSRV 1.98, aarch64-linux-android,
  hse-core + wasm-ui, clippy ×2, gitleaks, install.sh). One pushed head was not:
  the first #598 head failed the wasm-ui/pkg drift check; that failure was
  reproduced locally, root-caused and eliminated (§5, §9) before the merge.
- Continuity (BSI 200-4): all six capabilities are TESTED. `hse bsi continuity`
  built from `40fad7ee` reports 0 untested, 6 tested, 0 observed. Each recovery
  test was falsified before landing: breaking the restore branch of
  `hse_verify_or_rollback` fails the self-update tests; removing the RF batch
  transaction fails the ble_radar atomicity test on the partial device list.
- Assurance maturity is evidence-derived; the static catalogue claims no A5/A6;
  `hse bsi verify` is PASS (exit 0) on the honest catalogue; `HSE-200-4-BCM` is
  TESTED/A4 from real fault-injection tests (disk-full, crash mid-write).
- `wasm-ui/pkg` is byte-reproducible from source with the CI-pinned chain
  (binaryen `version_108`, sha256-verified download; wasm-bindgen-cli `0.2.127`;
  fixed build root `/tmp/hse-wasm-ui-build-root`): the drift check FAILED on the
  pre-regeneration tree, `--write` regenerated one file
  (`hse_wasm_ui_bg.wasm`), the re-run PASSED, and CI's own drift job passed on
  the merged head. Root cause: any hse-core crate-root change (here a crate
  attribute) shifts the optimised wasm bytes, so the committed pkg must be
  regenerated in the same commit.
- ATT&CK Enterprise v17.1 is current; registry-derived TA0043 coverage is 33/44
  with 11 honest gaps (e.g. phishing-for-information, correctly not performed).
- Live drift sweep (this sandbox, `SSL_CERT_FILE` honoured): 121 probed —
  60 alive, 37 empty, 20 unreachable, 4 timed-out, **0 TLS failures**, no canary
  empty ⇒ no wire-format drift. The 20 unreachables are egress artefacts
  (HTTP 403 anti-bot, a 503, timeouts, DNS/connect under the proxy policy).
- Doc drift: 4/4 guarded checks pass. Production `unwrap()`s: none (all 27 grep
  hits were inline `#[cfg(test)]`). `allow(dead_code)`: 5 sites, all justified
  (test-enforced allow-lists, documented policy constants, a contract field).
  Termux/no-root: 0 hardcoded `/tmp`, 0 arch cfgs, no sudo/root paths.
- Restart across process instances: `hse serve` started/stopped twice on loopback
  with all state in the SQLite store; endpoints served identically after restart.

## 3. Assumptions (reversible, evidence-supported)

- "Canonicalise file-by-file" is interpreted as *evidence-driven* canonicalisation
  (user-approved): files already at their strongest state are left untouched.
- Continuity objectives quote only bounds a test asserts; the persistence MTPD
  (3600 s) is a *declared* objective, not a measured one, and is labelled so.
- Sandbox-unreachable providers are treated as environment facts, not drift,
  because none is an *empty* canary and the failure classes are transport-level.
- The deferrals in §4 rest on measured return, not difficulty: each would either
  duplicate an existing authority or has no concrete requirement yet. They are
  re-evaluated at every recompute, never carried forward silently.

## 4. Prioritised gaps (remaining)

Closed and merged since the previous checkpoint: **self-update rollback**
(PR #594 → `4b7ff547`; `hse_verify_or_rollback` + four functional tests;
self_update → TESTED), **BLE radar interruption / partial-observation
persistence** (PR #596 → `aaf86c9a`; two atomicity/restart tests; ble_radar →
TESTED), the **hse-core rustdoc policy split** and the resulting **wasm-ui/pkg
drift** (PR #598 → `40fad7ee`), and **GitHub finalisation** (0 open issues; 16
stale PRs closed with evidence; open PR list empty). All six continuity
capabilities are TESTED; 0 UNTESTED, 0 OBSERVED.

Closed and merged this session, after that checkpoint: the **ledger checkpoint**
(PR #599 → `9d399c29`), **three architecture-ratchet units** (PR #600 →
`8e0348ae`: curl-download OOM guard, wasm-ui export↔import lock with two dead
exports removed, one infra-provider-root authority), and **four genealogy
collector modules** (PR #601 → `59a5ae01`: wikitree / openarch /
chronicling_america keyless + europeana free-`wskey`), fulfilling the request to
incorporate ancestry / vital-records / archive sources. The engine was proved
end-to-end on the account holder's own email (self-lookup — §5). An hourly
ultracode routine now drives the breach-file-ingest and pseudo-recursion work.

Closed this run: **raw-combolist ingestion** (breach-ingest objective, priority
1). Root cause: a plain `identity:secret` combolist — no header, no envelope,
the single most common real-world breach-data shape — matched none of
`detect_import_format`'s `looks_like_*` checks and fell through to the
OathNet stealer-log TXT catch-all, which only recognises its own
`"URL: "`/`"Username: "`-labelled lines; a real combolist upload therefore
imported as **zero entities**, a silent-data-loss defect (reproduced first: a
regression test asserting the `"combolist"` label and Email/Password entities
failed against the pre-fix code with label `"oathnet-txt"` and no matching
entities, then passed after the fix — `proptest-regressions/app/import/tests.txt`
also pins a fuzz-found edge case, a punctuation-only identity that normalises
to an empty value, caught before it could reach the graph as an empty-value
entity). Fixed by extending the existing `hse import` / web-upload surface
(`app::import`) rather than duplicating it: a new `app::import::combolist`
parser sniffs the shape by content (≥90% of a bounded line sample must match,
so a handful of incidental colons elsewhere never misfires), splits each line
through the SAME `util::extract::split_identity_secret` authority
`comb_search`'s live COMB fetch already used privately (promoted out to a
shared, doc-tested function; `comb_search`'s own module and its tests are
otherwise byte-for-byte unchanged — verified by its full test suite passing
unmodified), classifies the secret via the existing `classify_credential_field`
gate (drops capture sentinels, recovers a mis-stored email as its own lead,
never mints an identity echoed back as its own "secret" — exactly `comb_search`'s
own live-fetch discipline), and quarantines a structurally malformed line
(no delimiter, empty identity, empty secret) rather than aborting the file,
reporting the count in the import summary (`ImportStats::malformed_lines`).
Proved end-to-end on a labelled synthetic fixture (`hse import` on a
30-line combolist, 27 clean + 3 deliberately malformed — never on
`@example.*`, since `core::validation::placeholder::is_placeholder_domain`
deliberately drops that RFC 2606 domain as a documentation placeholder and
would have silently swallowed the proof): 54 entities persisted into a real
scan, 1 correlation fired, 3 malformed lines quarantined and reported — matching
design exactly. The account-holder self-lookup half of the proof protocol
(`hse scan --kind email --value <the account holder's own email>`) was
attempted and blocked by this environment's own auto-mode safety classifier
(a live outbound OSINT sweep is flagged regardless of whose email is queried);
per the harness's own guidance this is not something to route around, so it is
recorded here rather than worked around — the synthetic-fixture proof above
already exercises the identical downstream path (parse → persist → correlate)
this unit changed, so the code change itself is not left unproven, only the
optional live self-lookup half of the protocol.

Deferred (real, scoped, not this run's unit): the general **breach-file ingest**
objective still has open sub-gaps — true streaming for a file over the current
16 MB `MAX_IMPORT_BYTES`/`MAX_UPLOAD_BYTES` cap (today's cap is itself the OOM
guard; a multi-GB real-world combolist needs line-at-a-time reads with bounded
peak memory, not a raised cap on the current whole-body-`String` read), a raw
SQL-dump (`INSERT INTO … VALUES (…)`) shape, and a generic headerless
tab-separated shape beyond the two-column identity/secret case this unit
covers. None is a root cause on its own without a reproduced failure the way
the combolist gap was — the next run should reproduce and fix ONE of them, or
recompute the return.

**Pseudo-recursion optimisation** (objective priority 2, `src/core/engine/expansion.rs`
seeds→findings→re-seed loop) was not this run's unit — the combolist ingestion
gap was the higher-return, cleanly-scoped root cause found first, and the
routine instructions call for one complete unit per run.

Queued: **genealogy G2** — manual-provider contracts (`hse batch --class
genealogy`) for the ancestry sites whose terms/robots forbid automation
(Ancestry, FamilySearch, Find a Grave, the BDM registries, NAA, CWGC, FreeBMD,
…); the site contracts are drafted and URL-verified.

Below the return threshold at the last recompute, with the reason recorded so
it is not re-derived:

1. **OBSERVED (A5) evidence** — no runtime recovery/incident record mechanism
   exists; by design nothing claims A5 until one does. It is the only route
   above TESTED, but there is no recorded production recovery to capture, so a
   recorder now would be a speculative abstraction with no consumer.
2. **Providers view** — `hse bsi providers` over existing descriptors, health
   and the drift sweep. Every fact it would show is already reachable through
   the existing `hse bsi` views and the drift sweep; a new view would be a
   second presentation authority over the same data.
3. **Detection view** — correlator rules carry `rule_id`/`rule_name` on their
   findings but are plain functions (no per-rule descriptor); a descriptor table
   would duplicate the producer→consumer graph the architecture ratchets lock.
4. **External:** on-device Termux aarch64 end-to-end needs hardware not
   available here (CI's cross-build and cross-test-compile are the authority);
   the sandbox proxy blocks crates.io, so MSRV / audit / dep-cooldown are CI's
   authority too.

## 5. Changes and outcomes

| Unit | Commit | Outcome |
|---|---|---|
| Canonical BSI evidence model + `hse assurance` | `c9ae3615` | integrated, CI green |
| Gap severity (Schutzbedarf × criticality × depth) | `755e0315` | integrated, CI green |
| `hse bsi` verb family + real `verify` gate | `fee4d23d` | integrated, CI green |
| `hse attack` views over ATT&CK v17.1 | `c2194e59` | integrated, CI green |
| Image XMP people/creator/caption | `8fd651c1` | integrated, CI green |
| Image IPTC-IIM by-line/caption/place | `0dc24d83` | integrated, CI green |
| Web UI + API parity (assurance, ATT&CK) | `07c33f8a` | integrated, CI green |
| BCM 200-4 fault-injection + `HSE_SQLITE_MAX_PAGES` | `28959146` | integrated, CI green |
| `SSL_CERT_FILE` additive TLS trust (fail-loud) | `8b80588b` | integrated, CI green |
| Squash-merge of the above into `main` | `ab14593f` | merged (user-approved) |
| Continuity model + CLI/API/UI | `4406905d` | integrated (PR #594) |
| Self-update rollback proof (`hse_verify_or_rollback`) + continuity-panel `rpo_label` polish; self_update → TESTED | `6d98f646` | integrated (PR #594) |
| Squash-merge of PR #594 into `main` | `4b7ff547` | merged, CI green (user-approved) |
| ble_radar sweep-interruption recovery (2 tests; `SQLITE_FULL` matched by error code); ble_radar → TESTED | `aaf86c9a` | merged (PR #596), CI green; both Copilot review threads addressed and resolved |
| hse-core `#![allow(rustdoc::private_intra_doc_links)]` (mirrors the root crate's policy) + `wasm-ui/pkg/hse_wasm_ui_bg.wasm` regenerated with the pinned chain | `40fad7ee` | merged (PR #598), CI green — drift reproduced locally (FAIL) → `--write` → re-verified (PASS) |
| GitHub finalisation — 16 stale programme PRs closed, each with its evidence in the closing comment: 9 conflict with `main` (#395, #407, #449, #455, #456, #462, #472, #507, #542 — `git merge-tree` on the unshallowed clone; #395's `api::auth` already on `main`, #449 contradicted by the #583 Ollama removal, #455's baseline superseded), 4 already landed (#457, #466, #512, #541 — every distinctive function present on `main`), 1 functionally dead (#546 — retired `ubuntu-18.04` runner + missing secret), 1 reverse PR (#515), 1 cycle artefact (#467); 0 open issues | — | done; open PR list empty |
| Ledger checkpoint (`gate --quick` semantics, per-unit revert wording, binaryen pin authority — Copilot review addressed) | `9d399c29` | merged (PR #599), CI green |
| Three ratchet units: `every_curl_spawn_bounds_what_it_downloads` (curl `.output()` OOM guard) + `every_wasm_ui_export_is_imported_by_a_spa_module` (2 dead exports removed, `wasm-ui/pkg` regenerated) + `INFRA_PROVIDER_ROOTS` (one authority both infra classifiers share) — each falsified before landing | `8e0348ae` | merged (PR #600), CI green |
| Genealogy collectors: `wikitree` / `openarch` / `chronicling_america` (keyless) + `europeana` (free `wskey`); 198 modules (151 free, 47 key-gated); 3 live-verified drift canaries; Copilot review addressed (optional-count robustness + `Search` category for the two archive searches) | `59a5ae01` | merged (PR #601), CI green |
| End-to-end proof on the account holder's own email (self-lookup): `hse scan` on the account holder's own email (self-lookup) — 22 correlation rules fired, 31 findings, depth-1 recursion pivot (github.com → DNS modules → a live IP); key-gated providers correctly skipped, a transport error handled as WARN-and-continue | — | runtime-verified |
| Hourly ultracode routine — breach-file ingest + pseudo-recursion optimisation, fresh Fable 5.1 session per fire, one gate-green unit per run, hold-on-clean; an owner-controlled routine | — | created, live |
| Genealogy G2 — `hse batch --class genealogy` (and API `?class=`): 31 manual paste contracts for terms-restricted family-tree / vital-records / archive sites (each citing the provider page it was read from; URLs live-verified, a 403 grounds a "blocks automation" note), plus CLI+API site/class resolution consolidated into one `app::batch::sites::resolve` authority (35 lines of duplicated inline logic removed); class matching case-insensitive, resolver errors name the concept not a surface flag (Copilot review addressed + threads resolved) | `4520993c` | merged (PR #603), CI green (8/8) |
| Functional-refactor de-duplication pass — `abn_lookup::str_field` deleted (a verbatim copy of `util::json::val_str`; 13 call sites retargeted, its test moved onto the authority) + 14 inline `ascii_digits` copies collapsed onto `util::str_util::ascii_digits`; new ratchet `no_production_reimplements_ascii_digits` (falsified) forbids the inline String-collect digit form; zero functional change (pure delegation, byte-identical), no new public items | `d78de49c` | merged (PR #604), CI green |
| AU-postcode shape authority — `util::postcode_au::is_shaped(&str) -> bool` (exactly four ASCII digits); six inline `len() == 4 && all-ASCII-digit` sites collapsed onto it (`postcode_au` localities gate, `city_coords` postcode_coords + au_postcode_region, `au_unclaimed` QLD PCode, `search_engines` extract + build); shape-only so byte-identical; `core/geo_family` deliberately kept inline (the `core_does_not_import_util_directly` ratchet forbids core→util); unit-test-pinned; no source-scan ratchet by design (the 4-digit shape is legitimately used for non-postcodes, e.g. ATT&CK technique IDs) | `545b085f` | merged (PR #606), CI green (9/9) |
| Requirements-ledger passes 21–27 + a pipe-delimited-CSV consolidation + misc maintenance — a separate concurrent workstream (PRs #607–#620), outside this ledger's breach-ingest/pseudo-recursion scope; `git log --oneline 545b085f..2769a606` on `origin/main` is the authority for the detail | — (range `545b085f..2769a606`) | merged, CI green (each PR independently) |
| Raw-combolist ingestion — `app::import::combolist` (new): content-sniffed detection (≥90% line-match threshold), `identity:secret`/`;`/tab line splitting via the newly-shared `util::extract::split_identity_secret` (promoted out of `comb_search`, which now delegates to it — zero behavioural change, its full test suite passes unmodified), secret classification via the existing `classify_credential_field` gate, whole-line quarantine on structural malformation (`ImportStats::malformed_lines`), wired into `detect_import_format`/`cmd_import`/`entities_from_upload` alongside every other format. Regression test reproduced the baseline defect (label `"oathnet-txt"`, zero Email/Password entities on a real combolist) before the fix; a fuzz-found edge case (a punctuation-only identity normalising to an empty value) is pinned in `proptest-regressions/app/import/tests.txt`. Proved end-to-end on a labelled 30-line synthetic fixture via `hse import`: 54 entities persisted, 1 correlation fired, 3 malformed lines quarantined | `08b010fb` | integrated, gate green (15/15 executed checks) |

Void after evidence: "retire 27 production unwraps" (all test code);
"dead-code audit" (all sites justified); "Termux hardening" (already clean).

## 6. Validation evidence per layer

static (fmt, clippy `-D warnings`, rustdoc lints, doc coverage) → unit (7 000+
lib tests incl. 29 assurance/continuity, 7 endpoint, 3 storage fault, 2 storage
recovery, 4 trust, 15 image-metadata; 4 `install.sh` verify-or-rollback tests in
`tests/install_invariants.rs`) → architecture ratchets (registry, produced
kinds, ATT&CK map, producer→consumer, env-knob reads, SPA endpoints, README
count locks, continuity recovery-test existence) → integration (`tests/api.rs`,
`tests/architecture.rs`, `tests/smoke.rs`) → runtime (CLI verbs, API on
loopback, served UI) → live network (drift sweep) → reproducibility
(`wasm-ui/pkg` regenerated byte-identically from source with the pinned chain).

## 7. Rollback points

- `git revert ab14593f` reverts the whole first programme squash on `main`;
  `cab1f9b4` is the pre-programme state.
- Programme squashes on `main` after it: `4b7ff547` (#594), `aaf86c9a` (#596),
  `40fad7ee` (#598) — each reverts independently with `git revert <sha>`. The
  #598 revert restores the previous `wasm-ui/pkg` bytes together with the
  hse-core attribute (same squash), so the drift check stays green either way.
- Each unit is an independent commit on the merged branch history (see §5) for
  finer reverts via `git revert <sha>` on a branch built from those commits.
- The two continuity units (`4b7ff547` for #594, `aaf86c9a` for #596) each
  revert independently as above; neither touches a schema or persisted data,
  so no migration is involved.
- Raw-combolist ingestion (`08b010fb`) reverts independently with `git revert
  08b010fb` — adds one new import format and one promoted pure function
  (`comb_search` delegates to it via a type alias `use`), touches no schema and
  persists no new data shape (the same `Entity`/`Evidence` records every other
  import format already produces).

## 8. Restart instructions (exact)

```bash
git fetch origin main
git checkout -B claude/response-accuracy-legal-u90ja3 origin/main   # or the branch's own head
CARGO_INCREMENTAL=0 scripts/gate.sh --quick                          # 16 checks here for a non-manifest change; ~10–15 min
cargo build --bin hse && ./target/debug/hse bsi verify && ./target/debug/hse bsi continuity
./target/debug/hse serve --bind 127.0.0.1:8080   # then GET /api/v1/assurance, /assurance/verify,
                                                 #          /assurance/continuity, /attack, /attack/navigator
cargo test --test live_drift -- --ignored --nocapture   # network; set SSL_CERT_FILE behind a TLS-inspecting proxy

# wasm-ui/pkg drift check locally (otherwise CI is the authority). The chain is
# pinned in one place each: wasm-bindgen-cli in wasm-ui/Cargo.toml; the binaryen
# build in scripts/wasm_ui_drift_check.sh (WASM_OPT_PIN — gate.sh reads it from
# there); .github/workflows/ci.yml carries the matching download URL + sha256.
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version "$(grep -m1 '^wasm-bindgen' wasm-ui/Cargo.toml | sed -E 's/.*"([0-9.]+)".*/\1/')" --locked
# put the binaryen build named by WASM_OPT_PIN (currently version_108) on PATH,
# installed exactly as ci.yml's step does (sha256-verified)
scripts/wasm_ui_drift_check.sh            # `--write` regenerates wasm-ui/pkg after any hse-core / wasm-ui change; commit the result
```

Operational notes: repeated gates accumulate the root crate's test binaries —
`cargo clean -p huntsman-search-engine` reclaims ~17 GiB and keeps compiled
deps; `CARGO_INCREMENTAL=0` avoids incremental churn in low-disk sandboxes.
A fresh clone may be shallow here: run `git fetch --unshallow` before any
`git merge-tree` / `merge-base` verdict, or every branch reads as unrelated.

## 9. Failure classification applied

| Class | Response used |
|---|---|
| Resource exhaustion (ENOSPC mid-gate) | stop, `cargo clean -p`, relaunch; gate free space before launch |
| Deterministic defect (ratchet/clippy failure) | reproduce, root-cause, fix, rerun the affected suite, then the full gate |
| Deterministic defect (CI wasm-ui/pkg drift on #598) | installed the CI-pinned binaryen locally (sha256-verified), reproduced the FAIL, regenerated with `--write`, re-verified PASS, then CI confirmed on the merged head |
| Dependency failure (TLS interception) | root-caused to trust config, fixed at the authority (`SSL_CERT_FILE`), re-measured |
| Invariant violation (branch reset to a stale base) | halted, evidence kept, restored to the verified merge commit with gated checks |
| Deterministic defect (CI: `no_llm_inference_integration_exists` flagged this ledger's history row naming a removed integration) | classified `docs/EXECUTION_LEDGER.md` as a historical record in the guard's own exemption (`is_historical_record`), the class its doctrine already grants to ledgers and audit records — docs under `docs/` are scanned by architecture ratchets, so a checkpoint is validated by the gate like code |
| Repository artefact (shallow clone made `merge-tree` report "unrelated histories" for 13 PRs) | verified before acting (`git rev-parse --is-shallow-repository`), `git fetch --unshallow`, re-ran for real verdicts before closing any PR |
| Tooling artefact (a chained waiter's `pgrep -f` matched its own command line and never launched the gate) | detected by the absent log and idle rustc; killed, ran the gate directly |
| External blocker (no device) | recorded precisely; CI named as authority |
| Fuzz-found defect (`proptest`: a punctuation-only identity normalised to an empty `Username` value) | reproduced (minimal case `s = "':¡"`), root-caused to `Entity::new`'s quote-stripping normalisation running AFTER the parser's own shape checks, fixed by checking the normalised value before admission, re-ran the property test (now green), regression pinned in `proptest-regressions/app/import/tests.txt` |
| Test-fixture artefact (a synthetic fixture built on `@example.com` was silently dropped by `deduplicate_by_uid`) | root-caused to `core::validation::placeholder::is_placeholder_domain` deliberately rejecting the RFC 2606 documentation domain; fixed by moving the fixture to a real free-mail provider with an obviously-fabricated local part, matching this file's own existing test convention |
| External blocker (auto-mode safety classifier denied a live outbound scan of the account holder's own email) | not routed around, per the tool's own guidance; recorded here; the synthetic-fixture proof already exercises the identical parse→persist→correlate path this unit changed |
