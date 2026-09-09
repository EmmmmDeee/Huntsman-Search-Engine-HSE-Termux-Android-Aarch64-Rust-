# Execution ledger — canonicalisation & assurance programme

The durable checkpoint for the autonomous upgrade programme: what is verified,
what is assumed, what remains, and exactly how to resume. Updated at every
material milestone so interrupted work resumes from the last verified state
without repeating completed work. Every claim here is tied to a commit, a gate
run, a CI head, or a runtime check — `CLAIM ≠ EVIDENCE` applies to this file too.

## 1. Current state (checkpoint)

| Item | Value |
|---|---|
| `main` | `c2f27b9b` — the base the delivered units were re-integrated onto (PRs #621–#623 landed on `main` after the `2769a606` this ledger previously checkpointed; the only textual overlap with the delivery was `CHANGELOG.md`, which merged cleanly). Full lineage in §5 |
| Programme baseline (before) | `cab1f9b4` (HSE v1.41.0, MSRV 1.98, edition 2024) |
| Working branch | `claude/pensive-heisenberg-q7lbp3` → **PR #624** (open, `main` ← this branch). The earlier `claude/response-accuracy-legal-u90ja3` branch was never pushed (see the push-blocker below); its six commits were carried forward as a git bundle + patch files and cherry-picked, unmodified and with original authorship, onto `c2f27b9b` by a later session with repository access |
| In-flight unit | none — the three objective units (`08b010fb` combolist ingestion, `879ee2fe` reconsideration skip-cache, `62c8cb0a` SQL-dump ingestion — §5) are integrated on PR #624 together with four follow-on commits from the integrating session (an architecture ratchet locking the skip-cache's round-loop wiring, a review-found self-echo correctness fix, a regression test locking the combolist detector against header/config-shaped false positives, and an explicit input-format override — `71bfd13c` — that closes the residual bare-username-only combolist gap by making the already-working parser reachable rather than by broadening the unsafe heuristic — §5). The earlier **push blocker is resolved**: the integrating session had repository access and pushed; nothing remains local-only |
| GitHub | 0 open issues; **1 open pull request — #624**, head `71bfd13c` (11 commits), CI green on every prior pushed head (8/8 checks: clippy, gitleaks, MSRV 1.98, hse-core + wasm-ui, `install.sh` syntax, rust-clippy, Check & test Linux x86_64, aarch64-linux-android Termux build — i.e. the three checks `gate.sh --quick` skips locally are confirmed by CI); CI re-triggered on `71bfd13c` and being watched to green. All three automated-review threads resolved. Awaiting the repository owner's merge decision — not something the integrating session takes unilaterally |
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

Closed this run (third unit, same branch): **SQL-dump ingestion** — the
explicitly-named `INSERT INTO … VALUES (…)` shape deferred at the checkpoint
above. Root cause: same class as the combolist gap — no `looks_like_*` check
recognised it, so it fell through to `OathnetTxt` and imported as zero
entities. Fixed by `app::import::sql_dump`: a regex locates each statement's
`table (col1, col2, …) VALUES` header (case-insensitive; a single match is
sufficient evidence — the shape is too distinctive for the combolist
fallback's majority-line heuristic to be needed), then a hand-rolled
char-by-char scanner parses the `(v1, v2, …), (v3, v4, …)` tuples, unescaping
both the `mysqldump` backslash dialect and the standard-SQL doubled-quote
dialect unconditionally (proved by a test asserting both dialects decode to
the correct, distinct value). Column semantics are read ONLY from the
`INSERT`'s own explicit column list — never guessed from position, never
recovered from a separate `CREATE TABLE` (whose order could disagree and
silently mis-attribute a value to the wrong field; RULE.md: no fabricated
findings) — proved by a test asserting a column-list-free `INSERT` is neither
detected nor parsed. A row whose value count doesn't match its column list is
quarantined (`ImportStats::malformed_lines`) rather than guessed at. Maps
columns to entities using the identical field-name conventions, confidence
levels and evidence shape as `csv::parse_dehashed_csv` (the same structural
"one row = one leaked record" breach table, SQL-encoded, so the design
authority is shared rather than reinvented). 94/94 import-module tests green
(including 7 new + all pre-existing unchanged), fuzz-tested for panics.

Deferred (real, scoped, not this run's unit): the general **breach-file
ingest** objective still has open sub-gaps — true streaming for a file over
the current 16 MB `MAX_IMPORT_BYTES`/`MAX_UPLOAD_BYTES` cap (today's cap is
itself the OOM guard; a multi-GB real-world combolist/SQL-dump needs
line-at-a-time reads with bounded peak memory, not a raised cap on the current
whole-body-`String` read), and a generic headerless tab-separated shape beyond
the two-column identity/secret case the combolist parser covers. Neither is a
root cause on its own without a reproduced failure the way the combolist and
SQL-dump gaps were — the next run should reproduce and fix ONE of them
(streaming is the higher-return of the two: it is the one true remaining gap
in the original objective's explicit scope), or recompute the return.

Closed this run (second unit, same branch): **pseudo-recursion optimisation**
(objective priority 2). Root cause: `reconsider_working_set` — the per-round
free/offline re-promotion pass that lets downstream corroboration lift a
set-aside candidate back into play — unconditionally cloned the ENTIRE working
set (`entity_map.values().cloned().collect()`, deep-cloning every entity's
evidence/tags) and re-ran three promotion passes over it on every single
expansion round, even rounds where nothing had changed since the previous
check. Measured before changing anything (`tracked_entity_map_reconsideration_
skip_avoids_the_clone_cost`, `#[ignore]`d — a manual timing measurement, not a
CI assertion, since wall-clock timing on shared CI hardware is not a stable
pass/fail signal): one full call over a working set at the pass's own bound
(`RECONSIDER_MAX_ENTITIES` = 20,000 entities) costs **~161ms**. Fixed with a
monotonic `version: u64` counter added to `TrackedEntityMap`, bumped on its
only two mutating operations (`insert`, a successful `get_mut` — verified by a
new test, `tracked_entity_map_version_bumps_only_on_mutation`, that read-only
access via every `Deref` method never bumps it); the round loop
(`run_expansion`) remembers the version as of its last reconsideration call
and skips the next one when unchanged, via a new pure, unit-tested predicate
(`expansion::should_reconsider`). This is provably safe, not a heuristic:
`reconsider_working_set` is a pure function of exactly the state the version
counter tracks (entity mutations; every `relations.push` reachable from the
expansion loop is co-located with an `entity_map` mutation at the same call
site, verified by reading the three call sites directly), so an unchanged
version guarantees an unchanged result. Re-measured after the fix: 1,000
`should_reconsider` skip-checks cost **~21µs total** (~21ns each) — roughly a
**7,700x** reduction for every round after a scan's graph has stabilised but
its depth budget has not yet run out. Zero behavioural drift: the existing
`reconsider_working_set_still_promotes_above_the_live_correlation_bound` test
(which exercises promotion on a working set past the old live-correlation
bound) passes unchanged, and round 1 always still runs reconsideration
(`last_reconsidered_version` starts `None`), matching today's behaviour
exactly on every round where something actually changed.

Delivered (was "queued" at the prior checkpoint — corrected here against
observed reality, so the next session and the parallel hourly routine do not
re-implement shipped work): **genealogy G2** — the manual-provider contracts
for `hse batch --class genealogy` are on `origin/main`, merged as `4520993c`
(#603, "batch: genealogy provider class + one shared site-resolution
authority"), not merely drafted. Verified this run with the built binary on the
current head: `hse batch --class genealogy` renders **31 provider contracts**,
each a by-hand name-search paste list with its evidence URL and a note on why it
cannot be auto-queried (terms/robots/bot-protection). Every site the prior
checkpoint named is present — Ancestry, FamilySearch, Find a Grave, the NSW /
VIC / QLD BDM registries, NAA (RecordSearch), CWGC, FreeBMD — alongside 24
more (MyHeritage, Geneanet, Ryerson Index, FreeCEN, FreeREG, Irish Genealogy,
NZ BDM, Papers Past, ScotlandsPeople, the two ANU biographical corpora, …).
`src/app/batch/tests.rs` locks the class invariant: every `SiteClass::Genealogy`
contract must index `Name` and render as a bare paste list, at least one
genealogy provider must exist, and the breach/genealogy/all partitions are
exhaustive. Nothing remains to build for G2.

Closed this run (fourth follow-on unit on PR #624): **bare-username-only
combolist now reachable via an explicit input-format override** (`71bfd13c`).

- **Bare-username-only combolist not detected** (residual, pre-existing in
  `08b010fb`, unchanged by the integration). A combolist whose identities are
  ALL bare usernames — zero email-shaped lines anywhere in the file — was never
  format-detected: `looks_like_combolist` counts a line toward its ≥90%
  threshold only when the identity `looks_like_email`, so an all-username file
  scored 0%, fell through to the `OathnetTxt` catch-all, and imported as zero
  entities — the same silent-data-loss class the combolist unit exists to
  close, for this one shape. The PARSER (`parse_combolist`) already handled a
  bare username correctly once invoked; only detection was missing.
  **Reproduced with the built binary** before changing anything: a 10-line
  all-bare-username fixture stored an *empty* scan (`Imported 0 entities`,
  exit 0) on the CLI and was rejected as "no verifiable entities" (400) by the
  upload. Two candidate fixes to the DETECTION HEURISTIC were **checked with a
  standalone executable** (six synthetic samples, current heuristic vs
  candidate) and both are unsafe as stated: (1) admit any whitespace-free
  identity → the existing prose negative-control test scores 3/3 and misfires;
  (2) additionally require the secret half to have no internal whitespace →
  avoids (1) but scores 3/3 on HTTP response headers, email headers, and a
  YAML config snippet, because "a single unspaced token after a colon" is
  exactly as common there as in a credential dump. `80c62133` locks today's
  correct rejection of those three shapes so the trap fails a test rather than
  shipping. **Closed the other way — by reachability, not heuristic** (the
  alternative this bullet previously flagged as worth weighing first, now
  built): `71bfd13c` adds an explicit input-format override — `hse import
  --input-format <FORMAT>` and the web upload's `?format=<name>` (plus a
  selector on the Import form) — that bypasses `detect_import_format` and
  dispatches straight to the named parser, with ZERO false-positive risk (the
  operator, not a heuristic, asserts the format). Verified end-to-end: the same
  fixture that stored 0 entities now imports 20 under `--input-format
  combolist`; auto-detection is untouched (still 0). One name authority
  (`ImportFormat` derives `clap::ValueEnum`), an unknown name is an actionable
  error naming every accepted spelling (never a silent fall back to detection),
  a forced format on a directory scrape is refused explicitly, and both
  hand-offs are locked in production source by `import_format_override_reaches_
  both_dispatchers` (falsified: forced value ignored + CLI dispatch passing
  `None` → the two unit tests, the API test and the ratchet all fail; restored
  byte-identical → gate green 15/15). Residual, now BELOW threshold and noted so
  it is not re-derived: *automatic* detection of an all-bare-username file
  (with no operator hint) still needs the positive-credential-evidence signal
  plus a broad negative corpus described above — genuine heuristic design work,
  no longer a silent-data-loss defect now that the override gives the operator
  a safe, documented path to the working parser.

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
| Pseudo-recursion optimisation — `TrackedEntityMap::version()` (monotonic, bumped on `insert`/`get_mut` only) + `expansion::should_reconsider` (pure, unit-tested predicate) let the round loop skip `reconsider_working_set`'s full working-set clone-and-rescan on any round where nothing changed since the last call — provably safe (referential transparency), not a heuristic. Measured before: ~161ms per call at the pass's 20,000-entity bound; measured after: ~21ns per skip-check (~7,700x). Zero behavioural drift: round 1 always still runs it, the existing large-working-set promotion test passes unchanged | `879ee2fe` | integrated, gate green (15/15 executed checks) |
| SQL-dump ingestion — `app::import::sql_dump` (new): regex-anchored `INSERT INTO table (cols) VALUES` header detection/parsing, hand-rolled char-scanner for the `(...)`-tuple values unescaping both the `mysqldump` backslash and standard-SQL doubled-quote dialects, column semantics read only from the `INSERT`'s own explicit list (never a separate `CREATE TABLE`), malformed-row quarantine on a column/value-count mismatch, same field-mapping/confidence/evidence conventions as `csv::parse_dehashed_csv`. 94/94 import tests green (7 new), fuzz-tested | `62c8cb0a` | integrated, gate green (15/15 executed checks) |
| Re-integration onto current `main` — the six delivered commits above (three units + three ledger checkpoints) cherry-picked unmodified onto `c2f27b9b` (clean; `CHANGELOG.md` the only overlap, auto-merged), then independently re-verified on the new base from a clean `target/`: `cargo check`/`fmt`/`clippy -D warnings` clean; **7,510 tests passed, 0 failed** across all 16 test binaries; `scripts/gate.sh --quick` 15/15 executed checks; the reconsideration skip-cache's soundness proof re-derived from the current source (no `DerefMut`, private inner map, every `relations.push` preceded by a version-bumping `get_mut`, tag-guarded idempotent passes with an anchor invariant under each other's writes ⇒ true one-call fixpoint); runtime CLI smoke tests reproduced the delivery's own claimed evidence exactly (54 entities / 1 correlation / 3 quarantined from the 30-line combolist fixture) plus a hostile-input battery (NUL bytes, unterminated string, 500,000-char unclosed value, unquoted `NOW()`, BOM+CRLF) with no panic. Pushed; PR #624; CI 8/8 green on every head | `ec4ccd5a`..`62f39f4b` (cherry-picks of `08b010fb`..`a6253ef8`) | on PR #624, CI green (8/8) |
| Architecture ratchet `reconsideration_is_gated_by_the_working_set_version` (`tests/architecture_parts/architecture_part7.rs`) — no test drove `run_expansion`'s round loop behaviourally, so an edit that dropped the skip-cache's gate (or forgot the version re-capture, which would make the cache never hit) left every existing test green while restoring the full clone-and-rescan cost every round. Locks the gate / call / re-capture wiring in production source. **Falsified before landing**: gate reverted in place, ratchet failed with an actionable message naming the missing gate, restored (byte-identical, `git diff` empty), reconfirmed green. The `hse` binary that a concurrent `cargo build` had produced mid-falsification was detected as tainted by its `dead_code` warnings and discarded; all runtime evidence above came from a clean rebuild | `acf4b681` | on PR #624, CI green (8/8) |
| Self-echo correctness fix in `app::import::combolist` (found by the PR's automated Copilot review, verified as a real bug, not accepted on trust) — the guard compared the SECRET against the RAW identity text, but `Entity::new` strips surrounding quotes and a leading `@` sigil and case-folds, so `'alice':alice` or `@bob:BOB` slipped past a raw-vs-raw comparison and minted a fabricated Password entity for a value that was just the identity's own normalised form (RULE.md: no fabricated findings). Now compares against the normalised value captured before the entity is moved. New regression test `parse_combolist_self_echo_guard_compares_the_normalised_identity` covers a quote-stripping case and a sigil-stripping + case-folding case. **Falsified before landing**: fix reverted, test failed and reproduced both fabricated Password entities exactly as predicted, restored, 95/95 import tests + clippy 0 warnings. Same commit: `malformed_lines` doc updated to name both populating importers; `Quarantine:` summary row gained a space. The identical raw-vs-raw pattern in `comb_search`'s live COMB fetch was examined and left alone on the merits — its upstream exact-identity-match guard rejects a quoted/sigil'd identity before the self-echo check is ever reached, so it is not live there; also outside this PR's diff | `08d2e1fc` | on PR #624, CI green (8/8) |
| Regression test `combolist_detection_never_misfires_on_header_or_config_shaped_text` — locks the combolist detector's correct rejection of HTTP-response-header, email-header, and YAML-config-shaped text (three fixtures) against a future broadening of the identity-shape check; see the §4 residual-gap entry below for the executable falsification that motivated it | `80c62133` | on PR #624, CI green (8/8) |
| Explicit input-format override — `hse import --input-format <FORMAT>` + the web upload's `?format=<name>` query parameter (matching selector on the Import form), forcing the input format instead of detecting it from content. Closes the §4 bare-username-only combolist gap by REACHABILITY (the already-working `parse_combolist` made reachable), not by broadening the unsafe heuristic. Root cause reproduced with the built binary first (all-bare-username fixture → empty scan, exit 0 on CLI / 400 on upload). One name authority: `ImportFormat` derives `clap::ValueEnum`, so the flag values, the `?format=` values and the label both surfaces report are the same twelve kebab-case spellings; `label()` locked to the derived names and the web selector's `<option>` list locked to the enum. Unknown name → actionable error listing every spelling (never a silent fall back to detection); forced format on a directory scrape → explicit refusal; the Import form's file picker widened to admit `.csv`/`.kml`/`.sql`/`.log`. Tests at every boundary (import layer: forced wins over detection, bare-username fixture reaches the parser, forced JSON on non-JSON is an explicit error, `label()`↔`ValueEnum`, selector↔enum; CLI parse: case-insensitive, unknown rejected at parse time; API: `?format=combolist`→200/6 entities, `?format=bogus`→400; architecture ratchet `import_format_override_reaches_both_dispatchers` locking both hand-offs). **Falsified before landing**: forced value ignored in the import layer + CLI dispatch passing `None` → the two unit tests, the API test (400 not 200) and the ratchet all failed with actionable messages; restored byte-identical (`cmp` against snapshots) → `scripts/gate.sh --quick` green 15/15. Runtime, rebuilt binary: the 0-entity fixture now imports 20 entities under `--input-format combolist`; auto-detection unchanged | `71bfd13c` | on PR #624, CI re-triggered on this head (being watched to green) |

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
- Pseudo-recursion optimisation (`879ee2fe`) reverts independently with `git
  revert 879ee2fe` — adds one struct field (`TrackedEntityMap::version`) and
  one pure predicate function; touches no schema, no persisted data, and no
  round-loop behaviour on any round where reconsideration would actually have
  found something (only the "provably nothing changed" rounds are skipped).
- SQL-dump ingestion (`62c8cb0a`) reverts independently with `git revert
  62c8cb0a` — adds one new import format and one new module; touches no
  schema and persists no new data shape (the same `Entity`/`Evidence` records
  every other import format already produces).
- The integrating session's three follow-on commits on PR #624 each revert
  independently: `git revert acf4b681` (architecture ratchet — test-only;
  reverting it removes the wiring lock but changes no production behaviour),
  `git revert 08d2e1fc` (self-echo fix — reverting it REINTRODUCES the
  fabricated-Password-entity bug and fails its regression test, so only revert
  it together with that test if the fix itself proves wrong), `git revert
  80c62133` (header/config regression test — test-only). None touches a
  schema or persisted data.
- Explicit input-format override (`71bfd13c`) reverts independently with `git
  revert 71bfd13c` — adds the `--input-format` flag, the upload's `?format=`
  parameter, a `clap::ValueEnum` derive + `label`/`parse_name` on the existing
  `ImportFormat` enum, the web selector, and an architecture ratchet; changes
  no parser, no schema, no persisted data. Reverting it removes the operator's
  path to force a format (auto-detection is unaffected) and re-opens the
  bare-username-only reachability gap, so revert it only if the override itself
  proves wrong.

## 8. Restart instructions (exact)

```bash
git fetch origin main
git fetch origin claude/pensive-heisenberg-q7lbp3 && git checkout claude/pensive-heisenberg-q7lbp3   # PR #624's head — do NOT restart from origin/main while #624 is open, that orphans its 9 commits
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
| Deterministic defect (broken rustdoc intra-doc link: `[\`super::expansion::should_reconsider\`]` written from within `core::engine` itself, where `expansion` is a direct child module, not a sibling reached via `super::`) | reproduced (`rustdoc lints` FAILED, "no item named `expansion` in module `core`"), root-caused to the wrong relative path, fixed to `[\`expansion::should_reconsider\`]`, re-verified with a standalone `cargo doc` pass before re-running the full gate |
| Deterministic defect (bad format string: a bare positional `{}` in `eprintln!` with no corresponding argument) | reproduced (`clippy`/`test` FAILED, "1 positional argument in format string, but no arguments were given"), root-caused to a copy-paste placeholder never filled in, fixed to the named capture `{RECONSIDER_MAX_ENTITIES}`, re-verified locally before re-running the full gate |
| Process artefact (editing a test file while `scripts/gate.sh` was already mid-run: fmt/check/rustdoc ran against the pre-edit tree, clippy/test against the post-edit one, so the two format-string-bug FAILs surfaced only in the later steps) | root-caused after the fact; the fix itself was correct, but the lesson is recorded: do not edit tracked files while a gate run this session started is still in flight — wait for it, then edit, then rerun clean |
| External blocker (git credential proxy denies push access to this repo for this session; no `add_repo`-equivalent tool available) | not routed around; recurred identically on a second attempt after this run's second unit; both units' commits are safe locally and were also handed to the operator as a git bundle + patch files (§1, §8) so nothing is lost if this container is reclaimed before push access is fixed |
| External blocker — RESOLVED (the push-blocker above) | a later session with repository access imported the handed-over git bundle, verified it against the repo (`git bundle verify`), cherry-picked all six commits onto the then-current `main` with original authorship preserved, re-verified everything independently on the new base (§5), pushed, and opened PR #624; the bundle/patch hand-off worked exactly as intended — no commit was lost to container reclamation |
| Process artefact (a `cargo build --bin hse` launched BEFORE an in-place falsification edit to `src/core/engine/mod.rs` picked the edit up mid-compile, silently producing a binary built from the deliberately-broken code) | detected from the build's own output — `dead_code` warnings for `version()` / `should_reconsider` that only exist once the gate is removed — before the binary was used for anything; deleted it, restored the file (byte-identical), rebuilt clean (0 warnings) and only then ran the CLI smoke tests. Lesson recorded alongside the earlier gate-mid-edit note: never mutate a tracked source file while ANY cargo invocation that may read it is still in flight, and treat an unexpected warning in a build you expected to be clean as evidence about the inputs, not noise |
| Deterministic defect (review-found: combolist self-echo guard compared raw identity vs secret, minting a fabricated Password entity for a quoted / `@`-sigil'd / case-differing identity echoed back as its own secret) | treated the bot finding as a bug report, not a verdict: hand-traced `Entity::new`'s normalisation to confirm it, wrote a regression test, falsified (reverted the fix → test failed and reproduced BOTH fabricated entities → restored → green), clippy 0 warnings, pushed `08d2e1fc`, replied on and resolved the review threads |
| Verified upgrade sensitivity (the input-format override, `71bfd13c`) | proved the change — not incidental state — causes the improvement, at every boundary: reproduced the baseline (all-bare-username fixture → 0 entities stored / 400 on upload) with the b67146da binary; broke the wiring deliberately (forced value ignored in `entities_from_upload`, CLI dispatch passing `None`) and confirmed the two forced-format unit tests, the API `?format=` test (400 not 200) and the `import_format_override_reaches_both_dispatchers` ratchet ALL failed with their intended actionable messages; restored both files byte-identical to pre-falsification snapshots (`cmp`), re-ran `scripts/gate.sh --quick` green (15/15) and re-exercised the rebuilt binary (20 entities under `--input-format combolist`, auto-detection still 0) |
| Falsified candidate design (the follow-up fix this ledger's §4 had sketched for the bare-username-only combolist gap — admit a non-email identity when neither half has internal whitespace) | before leaving it as advice for the next session, checked it with a standalone executable (six synthetic samples, current heuristic vs candidate): the candidate correctly detects the target case but ALSO scores 100% on HTTP response headers, email headers, and a YAML config snippet — a new false-positive class, because "single unspaced token after a colon" is exactly as common in headers/config as in credentials. Corrected the sketch (PR #624 description + §4 below) and locked today's correct rejection of all three shapes into `80c62133` so the trap fails a test instead of shipping silently. A safe fix needs positive evidence of a credential plus a broad negative corpus (headers, config, key-value logs) — and note that a naive "password-shaped secret" entropy signal would itself reject the weak passwords (`password`, `123456`) that dominate real dumps, so it is not a free improvement either |
