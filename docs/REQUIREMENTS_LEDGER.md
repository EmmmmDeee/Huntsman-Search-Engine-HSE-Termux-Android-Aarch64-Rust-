# Requirements Traceability Ledger

**Scope.** This ledger covers HSE's cross-cutting *core contracts*, not the
individual scanning modules' business logic — that was the subject of a
separate, now-complete module-by-module bug audit under
`src/modules/*/mod.rs` (Phases 0-10, PRs #553-568, merged; every one of the
188 registered modules read against an established bug-class checklist). The
areas covered here, across thirteen passes:

1. The `Module` trait contract (`src/core/module/mod.rs`).
2. The CLI surface (`src/main.rs`, `src/cli/`).
3. `install.sh`.
4. The env/config template and key consumption.
5. Top-level `README.md`'s stated capabilities/counts.
6. The HTTP API surface (`src/api/`) — routes, auth middleware, scan
   lifecycle handlers, settings/cells/key-harvest/update handlers, scan
   export/redaction.
7. Scan engine dispatch (`src/core/engine/`) — the dead-module quarantine
   gate only; expansion and the rest of the engine's internals remain out
   of scope (the `max_roi` ROI/budget-pruning levers it hosts the call
   sites for are covered separately, section 10).
8. Correlator rule registry (`src/core/correlator/`) — registration
   completeness/uniqueness only; individual rules' firing logic remains out
   of scope beyond the pre-existing per-rule test corpus.
9. Storage subsystem (`src/storage/`) — the `integrity_check()` corruption
   detector only; schema migration, concurrent-open behavior, and the rest
   of the storage layer remain out of scope.
10. ROI-maximising expansion (`src/core/roi/`) — the three `max_roi` levers
    (saturation-pruning, top-K/knee candidate cutoff, adaptive-depth
    termination) at their real dispatch call sites; the levers' own pure
    functions have separate, pre-existing unit coverage not tracked here.
11. Provider capability + economics descriptor (`src/core/module/provider.rs`)
    — the canonical `ProviderDescriptor` every registered module exposes,
    its derivation/override consistency, the env-configurable cost input,
    the cost-budget eligibility gate, and the CLI/API/Web field-drift fix
    that made the API surface read the same descriptor the engine does.
12. Dispatch-utility explainability (`src/core/roi/utility.rs`) — the ROI
    subsystem's fourth, additive-formula lever: the missing-value-robust
    `DispatchUtility` formula itself, the new quota-exhaustion eligibility
    gate, and the real-dispatch wiring proving gates fire before the score
    is ever computed and the lever is off-by-default zero-behavior-change.

**Pass 2** re-verified every row Pass 1 left
`IMPLEMENTED_UNVERIFIED`/`PARTIAL`/`AMBIGUOUS` by actually running its cited
test or command, resolved the one genuinely missing behavioral test found
(REQ-CORE-009, the inter-scan cache's dispatch-level hit/miss path), and
closed the one documented ambiguity (REQ-README-004) with a one-paragraph
README clarification plus a drift-guard extension. See "Pass 2 findings"
below for the full account.

**Pass 3** (this pass) extended coverage to section 6, the HTTP API surface —
`hse serve`'s actual remote-facing product surface, and the highest-value
gap Pass 2 identified. Derived via a 4-agent parallel sweep with one
adversarial re-verification agent per candidate row (every cited test
independently re-run, not accepted from the deriving agent's say-so), then
fixed the one BROKEN finding (REQ-API-MISC-004 — an unfiltered credential
check that could forward an un-edited template placeholder to a live
request). See section 6 above for the full row set.

**Pass 4** (this pass) closed the ledger's one remaining `MISSING` row
(REQ-ENV-003) — and, in re-deriving it, corrected an overclaim inherited
from Pass 1/3 (only 1 of the 4 env knobs it names is actually live; the
other 3 are parsed then never read) — and opened two new one-row sections
for previously-unrepresented subsystems: REQ-ENGINE-001 (the scan engine's
dead-module quarantine gate, previously a completely untested hot path) and
REQ-CORRELATOR-001 (the correlator rule registry's completeness/uniqueness
guards, which turned out to already exist in full — this row is
documentary only, added after a drafted duplicate test was caught and
reverted before being shipped). See "Pass 4 findings" below for the full
account.

**Pass 5** (this pass) closed one correctness-affecting `PARTIAL` row,
REQ-API-MISC-003: `settings_toggles_put`'s success path, and the
`set_bool` persistence primitive it and `hse config` both write through,
had zero test coverage of any kind — only the write endpoint's two
rejection paths were tested. Added a direct `set_bool`/`get_bool`
round-trip and an HTTP-level success-path test proving the write actually
persists (not just the two rejection tests). No production code changed —
see "Pass 5 findings" below.

**Pass 6** (this pass) closed one more correctness-affecting `PARTIAL`
row, REQ-API-SCAN-007: `GET /api/v1/scans/{id}/entities`'s pagination
boundary validation had thorough coverage of every valid offset/limit
combination but none of its three `bad_request` rejection branches
(non-numeric offset, non-numeric limit, `limit=0`). Added one new test
driving all 5 invalid-input cases through the real handler. No production
code changed — see "Pass 6 findings" below.

**Pass 7** (this pass) closed REQ-API-SCAN-002: real in-flight scan
cancellation had never been driven through the actual HTTP `scan_cancel`
handler — the only existing coverage was the 404 branch and a
deadline-triggered abort driven directly against the engine, bypassing
HTTP. Added a shared cancellation-cooperative probe module and a small,
backward-compatible harness refactor (`test_app_with_modules`) so a test
can inject a caller-chosen module set, then a new test that creates a real
scan, cancels it mid-flight via `POST /scans/{id}/cancel`, and polls
`GET /scans/{id}` until it finalizes as `"aborted"`. No production code
changed — see "Pass 7 findings" below.

**Pass 8** (this pass) was not self-directed from the backlog — it was a
direct, targeted request to critically assess this repo's readiness for
immediate installation on a real, no-root Termux Android aarch64 device.
Found no installation blocker, but two genuine gaps: REQ-INSTALL-001 (the
Play-Store-Termux rejection had zero test coverage — fixed, mutation-tested)
and a new REQ-INSTALL-010 (CI's aarch64 cross-compile job built only `hse`,
not the 3 other default binaries `install.sh`'s on-device build fallback
also compiles — widened, pending this PR's own CI run for VERIFIED status
per the ledger's own evidence rule). See "Pass 8 findings" below.

**Pass 9** (this pass) closed the ledger's one remaining `UNREACHABLE` row,
REQ-API-SCAN-006: the `/scans/import` handler's own oversized-upload check
was genuinely dead code, because the route's `DefaultBodyLimit` was set to
exactly the handler's own cap — so any body large enough to trip the
in-handler check had already been rejected one layer up by axum's bare
plain-text 413, before the handler ever ran. Fixed by giving the route a
small (1 MiB) headroom over the handler's cap, so a body in that window now
reaches the handler and gets this API's normal JSON error shape instead;
anything larger still hits axum's hard backstop, so the underlying
OOM-protection safety property is unchanged. Added one new test proving the
branch is reachable, mutation-tested (reverted the fix locally, confirmed
the new test fails, restored it). No other rows changed this pass.

**Pass 10** (this pass) closed one new one-row section, REQ-STORAGE-001
(`Store::integrity_check()` had never been proven against real corruption,
only the healthy-DB path), fixing a related `hse doctor` bug found along the
way (an `integrity_check()` execution failure wasn't flagged critical, even
though that's a *more* severe signal than "ran and found problems"). Also
closed two pre-existing evidence gaps (REQ-CLI-001, REQ-CLI-007: both had
dedicated tests all along, just uncited — search misses predating Pass 1)
and strengthened REQ-ENV-005's evidence without flipping its status. Started
as a working "Pass 9," this pass rebased onto PR #577's own, independently
merged, genuine Pass 9 (REQ-API-SCAN-006) mid-flight and renumbered to avoid
colliding with it — see "Pass 10 findings" below for the full account,
including that reconciliation.

**Pass 11** (this pass) closed one new one-row section, REQ-ROI-003
(`crate::core::roi::should_terminate_adaptive`, the `max_roi` adaptive-depth
lever — real dispatch, not just the pure function, had zero coverage). While
scoping it, found the ROI module's other two levers had never been
represented in the ledger at all despite one (saturation-pruning) already
having real dispatch-level proof from earlier architecture work — added
REQ-ROI-001 (VERIFIED, citing that pre-existing test) and REQ-ROI-002
(IMPLEMENTED_UNVERIFIED — the top-K/knee candidate cutoff has a real
`apply_roi_cutoff`-level test plus pure-function coverage, but nothing
proves it firing inside an actual over-budget `engine.run()`), so all three
levers are now at least represented, two of three VERIFIED at the real
dispatch call site. See "Pass 11 findings" below for the full account.

**Pass 12** (this pass) opened a new one-row-per-property section, section
11, for a directive-driven addition: a canonical `ProviderDescriptor` every
registered module now exposes via `Module::provider_descriptor()`
(mechanically derived from each module's existing `cost()`/`is_passive()`/
`cache_ttl_secs()`/`is_high_value_only()`/`requires_geo_corroboration()`/
`consumes()`/`produces()`, with 6 explicit per-module overrides where the
generic derivation would misrepresent a real provider's operational
profile). Also closed a genuine field-naming/completeness drift between the
engine's own `ModuleInfo` and the HTTP API's hand-rolled `modules_list`
JSON (the API was missing `attack_techniques` entirely and never exposed
the new `provider` descriptor), and added the cost-budget eligibility gate
(`unknown_cost_paid_provider_blocked`) that stops an UNKNOWN-cost paid/
enterprise provider from dispatching under an active `max_cost_usd` budget
unless the operator explicitly opts in via `allow_unknown_cost_dispatch`.
See "Pass 12 findings" below for the full account.

**Pass 13** (this pass) opened new section 12: the ROI subsystem's fourth
lever, `DispatchUtility` (`src/core/roi/utility.rs`) — a directive-driven
extension of the existing `max_roi` ROI bundle (section 10), not a
replacement or a separate "economic planner." An additive/log-space
formula folds novelty, source independence, pivot optionality, reliability,
cost, quota, latency, failure, and duplication signals into one canonical,
explainable score, provably robust to missing values (no factor can
multiplicatively collapse the total). A new quota-exhaustion hard
eligibility gate (`quota_exhausted_blocked`) joins the existing monetary
one, checked before any ranking. The lever is off by default
(`ScanOptions::dispatch_utility`) and purely additive telemetry in this
pass — it computes and surfaces a score without changing which module
dispatches or in what order, so all three pre-existing ROI levers and both
pre-existing dispatch-ordering mechanisms (priority/convex) are proven
unchanged. See "Pass 13 findings" below for the full account, including
where this implementation deliberately narrows the original design to keep
every signal real rather than invented.

This still does **not** claim to have reconstructed requirements for the
*entire* codebase (the correlator's actual rule logic beyond registry-level
completeness, the scan engine's internals beyond the quarantine gate and the
ROI levers, the storage layer beyond the `integrity_check()` detector, the
web/WASM UI, and `hse-ai-daemon` remain out of scope for all thirteen passes)
— see "Known limitations" for why, and for what a further pass would need
to cover.

**How to read this ledger.**

- **Status** is one of `VERIFIED | IMPLEMENTED_UNVERIFIED | PARTIAL | MISSING |
  BROKEN | UNREACHABLE | OBSOLETE | AMBIGUOUS`. `VERIFIED` requires an actual
  passing test and/or a command this pass personally ran and confirmed the
  output of — code that merely *looks* correct is `IMPLEMENTED_UNVERIFIED` at
  best.
- **Runtime verification evidence** states plainly whether this pass executed
  anything, or only read source. Existing architecture tests
  (`tests/architecture_parts/*.rs`, ~56 tests as of this pass) are treated as
  pre-existing verification evidence and cited by name rather than re-derived;
  this ledger only re-ran the specific ones it cites.
- All line numbers are approximate pointers as of when this pass was taken
  (captured locally against a build reporting `hse build-sha` `8b113ca`, an
  example snapshot rather than a value this document tracks going forward —
  the tree was also partially dirty from concurrent, unrelated work in
  `src/modules/*`, see "Known limitations" below). Any subsequent commit,
  this PR's own merge included, will have shifted past that SHA; treat every
  line number here as approximate for that reason, not just the ones noted
  individually.

**Known limitations of Pass 1.** A separate module-bug-audit session was
editing `src/modules/*` concurrently with Pass 1 (per that pass's task
brief). This ledger's scope explicitly excludes that code, and no row here
depended on the in-flight files' final state. One transient build breakage in
`src/modules/niamonx/{mod,tests}.rs` was observed and resolved itself (by the
other session) between two verification commands in Pass 1; it is not
reflected in any row below since it was never a defect in that pass's own
scope. That module-bug-audit has since completed in full (Phases 0-10,
188/188 registered modules, PRs #553-568, all merged).

**Known limitations of Pass 13 — what a further pass would need to cover.**
This ledger's 12 sections are the core contracts, the remote-facing API
surface, and six registry/detector/lever/descriptor-level guards of a Rust
CLI/module-engine tool: the `Module` trait, the CLI, the installer, the
env/config template, the README's own claims, `hse serve`'s HTTP API, the
scan engine's dead-module quarantine gate, the correlator's
rule-registration completeness, the storage layer's `integrity_check()`
corruption detector (section 9, added in Pass 10), the ROI-maximising
expansion levers (section 10, added in Pass 11), the provider capability +
economics descriptor (section 11, added in Pass 12), and the dispatch-utility
explainability lever (section 12, added in Pass 13). Passes 5, 6, and 7
each closed one more `PARTIAL` row within the existing HTTP API section
(section 6); Pass 8 closed one `IMPLEMENTED_UNVERIFIED` row and added one
new row within the existing `install.sh` section (section 3); Pass 9
(PR #577, merged independently of this ledger's own working session) closed
the one `UNREACHABLE` row, also within the existing HTTP API section — none
of those five expanded scope to any new subsystem. Pass 10 opened new
section 9; Pass 11 opened new section 10, narrowing (not closing) the ROI
bullet below; Pass 12 opened new section 11; Pass 13 opened new section 12,
further narrowing the scan-engine-internals bullet below (the per-round
candidate weight computation now has one documented follow-up: threading it
into `DispatchCx` so `expected_information_value` can use it directly
instead of the entity-confidence proxy — see section 12's own "deliberate
v1 narrowing" note). Deliberately still **not** covered by any of the
thirteen passes, and not claimed as VERIFIED/MISSING/etc. anywhere above:

- **The scan engine's internals beyond the quarantine gate and the ROI
  levers** (`src/core/engine/` past `gate_skips` and the section-10 call
  sites — the rest of expansion (candidate weighting/scoring, budget
  checks beyond ROI, geo-convergence strategy selection), and the
  *upstream* wiring that computes the `quarantined` set in production
  (`mod.rs:717-743`'s `skip_dead_modules` → `recent_module_outcome_events`
  → `quarantined_modules` chain — noted as an explicit follow-up in
  REQ-ENGINE-001's row, since `InMemoryStore`'s no-op default for
  `recent_module_outcome_events` makes it untestable under the standard
  harness).
- **The correlator's ~121 individual rules' own firing/business logic**
  (`src/core/correlator/rules/`) — Pass 4 only added registry-level
  completeness/uniqueness coverage (REQ-CORRELATOR-001), and even that
  turned out to already exist; per-rule correctness relies entirely on the
  pre-existing, uncounted `tests/part*.rs` firing-test corpus, not on
  anything this ledger tracks row-by-row.
- **The storage layer's own contracts beyond `integrity_check()`**
  (`src/storage/` — schema migrations, concurrent-open behavior, and the
  SQLite `Store`'s full method set beyond what Pass 2's cache-TTL fix and
  Pass 10's corruption-detection test (section 9) touched).
- **The web/WASM UI** (`src/web/`, `wasm-ui/`) and the embedded SPA served by
  `src/api/routes/mod.rs`.
- **`hse-ai-daemon`** (`src/bin/hse_ai_daemon`) and the other `src/bin/*`
  utilities (`architecture_audit`, `dep_cooldown`, `gen_oui`).
- **Docs beyond `README.md`** — `docs/*.md` carries dozens of other files
  (setup guides, prior audit reports) not cross-checked against current code
  in any pass.
- **The 3 dead `quota_config.rs` accessors** (`HSE_OATHNET_DAILY_LIMIT`,
  `HSE_SEE_KNOW_PER_SCAN_LIMIT`, `HSE_WIGLE_PER_SCAN_LIMIT`) — Pass 4
  documented their actual (inert) status accurately (REQ-ENV-003) but
  deliberately did not decide whether to wire them up or delete them; that
  is a real behavior decision left to a future pass.

Within section 6 itself, Pass 3's condensed 4-column format (ID / Behavior /
Runtime evidence / Status, versus the 10-column format sections 1-5 use)
trades some structure for density given the row count (35) and the depth of
evidence each row carries — implementation locations, test names, and full
adversarial-verification notes live in the source workflow transcript, not
reproduced in full here. Sections 7 and 8 (Pass 4) use the full 10-column
format, one row each.

None of this is a claim that these areas are broken or unverified in some
absolute sense — only that this ledger has not yet looked at them, and a
reader should not infer completeness beyond the 12 sections it actually
covers.

---

## 1. The `Module` trait contract (`src/core/module/mod.rs`)

| ID | Behavior | Inputs | Outputs | Side effects | Failure behavior | Implementation location | Tests covering it | Runtime verification evidence | Status |
|---|---|---|---|---|---|---|---|---|---|
| REQ-CORE-001 | `Module::name()` returns a stable snake_case identifier; every registered module's name is unique across the registry. | none | `&'static str` | none | Duplicate name would silently shadow dispatch/lookup by name. | `src/core/module/mod.rs:151`; enforced at `src/modules/mod.rs::registry()` | `module_names_are_unique` (`tests/architecture_parts/architecture_part*.rs`) | Ran `cargo test --test architecture` this pass — 55/55 passed, including this test. | VERIFIED |
| REQ-CORE-002 | `Module::priority()` (0..=255, higher = earlier) determines dispatch ordering within a round. | none | `u8` | Engine sort order | No explicit validation; any `u8` value is accepted. | `src/core/module/mod.rs:154` | Exercised indirectly by engine dispatch-order tests (`src/core/engine/tests.rs`) — no test asserts the full-registry ordering itself. | Read-only, not executed for this specific claim. | IMPLEMENTED_UNVERIFIED |
| REQ-CORE-003 | `Module::accepts(target)` gates whether `process()` runs for a given target; `consumes()` defaults to probing `accepts()` against every `TargetKind` when not overridden. | `&Target` | `bool` / `Vec<TargetKind>` | none | A module whose `accepts()` is not a pure `matches!` on kind but is not overridden for `consumes()` mis-reports its dispatch index (documented risk, not compiler-enforced). | `src/core/module/mod.rs:157,254-260` | `module_info_reflects_trait_defaults`, `override_category_and_produces_propagate_to_info` (`src/core/module/tests.rs`) | Ran `cargo test --lib core::module::tests` this pass — both cited tests passed, confirming the `consumes()` default-probe behavior (one with an `accepts()` that matches every kind, one restricted to `Domain` alone). Neither exercises `accepts()` for a module whose gate is not a pure `matches!` on kind (the documented edge case where an override is required), which stays unexercised. | PARTIAL |
| REQ-CORE-004 | `Module::process()` returns `Result<ModuleResult>`; a hard failure across independent concurrent sub-fetches must surface as `Err` only when NO evidence was collected at all (`ModuleResult::or_hard_failure`), never discarding partial evidence. | `&Target`, `&ModuleContext` | `Result<ModuleResult>` | none (module-specific network I/O aside) | Empty + hard failure ⇒ `Err`; empty + no failure ⇒ clean `Ok(empty)`; any evidence ⇒ always `Ok`, even alongside a sibling failure. | `src/core/module/mod.rs:159,482-489` | `or_hard_failure_errors_when_empty_and_a_hard_failure_occurred`, `or_hard_failure_stays_ok_when_empty_and_no_failure_occurred`, `or_hard_failure_preserves_evidence_despite_a_sibling_failure` (`src/core/module/tests.rs`) | Ran `cargo test --lib core::module::tests` this pass — all 3 passed (part of the broader `cargo test --lib` run below). | VERIFIED |
| REQ-CORE-005 | `Module::cost()` defaults to `Free`; drives the `--free-only` CLI/API filter. | none | `ModuleCost` | Filters dispatch set | none | `src/core/module/mod.rs:162-165,19-42` | `module_cost_as_str_matches_serde`, `module_cost_serializes_to_snake_case`, `module_info_reflects_trait_defaults` (`src/core/module/tests.rs`) | Ran `cargo test --lib core::module::tests` this pass — passed. | VERIFIED |
| REQ-CORE-006 | `Module::is_passive()` defaults to `false`; drives `--passive-only`. Modules with genuinely no network dependency (device sensors) must override `true`. | none | `bool` | Filters dispatch set | A module that is actually passive but doesn't override reports as active (under-inclusive `--passive-only`) — not compiler-checked. | `src/core/module/mod.rs:167-171` | No architecture test cross-checks `is_passive()` against actual network calls (would require dynamic analysis). `module_info_reflects_trait_defaults` covers only the default value. | Read-only. | IMPLEMENTED_UNVERIFIED |
| REQ-CORE-007 | `Module::max_timeout_ms()` bounds one `process()` call; every non-passive module MUST override it above `MODULE_TIMEOUT_MS` (3000ms), or the engine kills it mid-request on the default budget. | none | `u64` | Engine timeout wrapper | Under-budget non-passive module ⇒ premature `ModuleError{error:"timeout"}` on every call. | `src/core/module/mod.rs:173-185`; `crate::MODULE_TIMEOUT_MS = 3000` (`src/lib.rs:109`) | `non_passive_modules_budget_above_default` (`tests/architecture_parts/architecture_part3.rs:72`) | Ran `cargo test --test architecture non_passive_modules_budget_above_default` this pass — passed. | VERIFIED |
| REQ-CORE-008 | `Module::constrained_timeout_ms()` (default = `max_timeout_ms()`) sets the per-module budget the engine applies on a resource-constrained device (Termux/Android, or any small/metered container) when the operator hasn't pinned `ScanOptions::module_timeout_ms`; the engine additionally clamps to a 45s cap unless the module is cap-exempt. | none | `u64` | Engine timeout resolution on a constrained device | An exempt module bypasses the cap and is bounded only by its own value (still finite). | `src/core/module/mod.rs:187-220`; engine consumer `src/core/engine/timeout/mod.rs` | `constrained_cap_bounds_long_modules_only_when_constrained_without_override`, `cap_exempt_module_keeps_its_full_constrained_budget`, `resolve_timeout_uses_constrained_budget_then_cap` (`src/core/engine/timeout/tests.rs`) | **Citations updated in Pass 10** (renamed by PR #576's `CORE LOGIC != PLATFORM LOGIC` fix — `termux_timeout_ms`→`constrained_timeout_ms` etc.; the underlying gating logic is unchanged, confirmed by that PR's own zero-diff-in-behavior verification). Ran `cargo test --lib core::engine::timeout::tests` this pass — all 3 cited tests passed under their new names. | VERIFIED |
| REQ-CORE-009 | `Module::cache_ttl_secs()` (default 0 = no caching) lets the engine serve a prior result from the inter-scan entity cache instead of re-querying, for modules with stable, cacheable data. | none | `u64` (seconds) | Engine reads/writes an entity cache keyed on module+target when `ttl > 0` | `ttl == 0` ⇒ cache path is a no-op | `src/core/module/mod.rs:272-278`; consumers `src/core/engine/dispatch.rs:848,984,1106`; cache-hit contract documented at `src/core/port/mod.rs:139-155` | **Fixed this pass (Pass 2).** No dedicated unit test found exercising a cache HIT/MISS for a nonzero-TTL module end-to-end. Root cause: `core::test_support::InMemoryStore` (the standard engine-test double) inherited `StoragePort`'s no-op defaults for `archive_module_result`/`lookup_module_result_fresh` — a lookup could never return a hit, so the dispatch-level "cache hit skips `process()`" behavior was structurally untestable through it, independent of the storage layer's own coverage (`storage::archive_tests` already fully covers the SQLite-backed round-trip). | Gave `InMemoryStore` genuine in-memory cache semantics mirroring `Store`'s exact freshness predicate (`archived_at + ttl_secs > now`), then added `core::engine::tests::cache_hit_skips_reprocessing_a_later_scan_of_the_same_target`: dispatches a `cache_ttl_secs()`-overriding probe against the same target under two different scan_ids and asserts `process()` runs exactly once (the second dispatch replays from cache, `ModuleStats::cached == 1`), plus a third dispatch against a *different* target proves the cache is keyed per-target, not a blanket hit. Ran `cargo test --lib core::engine::tests::cache_hit_skips_reprocessing_a_later_scan_of_the_same_target` — passed. Updating `InMemoryStore` also broke a pre-existing test's premise (`core::port::tests::default_optional_methods_are_documented_no_ops` asserted `InMemoryStore` overrides none of the 7 default methods) — updated that test's assertions and comment to reflect the new, deliberate 5-no-op/2-real-cache split. Ran `cargo test --lib --features dep-cooldown` (6836 passed, 0 failed), `cargo test --test architecture` (55 passed), `cargo clippy --all-targets --features dep-cooldown -- -D warnings` (clean), `cargo fmt --all`. | VERIFIED |
| REQ-CORE-010 | `Module::attack_techniques()` defaults from `category()` via `attack::techniques_for_category`; every registered module must declare at least one real MITRE ATT&CK Reconnaissance technique ID from the catalogue. | none | `&'static [&'static str]` | Tags emitted entities with `attack:<ID>` | A module whose category is `Other` (unmapped) and has no override reports zero techniques. | `src/core/module/mod.rs:280-293`; category map `src/core/attack/mod.rs` | `every_module_maps_to_valid_attack_reconnaissance_techniques` (`tests/architecture_parts/architecture_part2.rs:14`) | Ran `cargo test --test architecture` this pass — passed (part of the 55/55 run). | VERIFIED |
| REQ-CORE-011 | `Module::produces()` (default empty) documents `EntityKind`s the module emits; every module that literally constructs an `Entity::new(EntityKind::X, ...)` must declare `X` in its `produces()`. | none | `&'static [EntityKind]` | Drives the UI pivot-chain / capability map | A module minting an undeclared kind under-represents its own output map (sound-but-incomplete check: only catches literal constructions, not dynamically-classified ones). | `src/core/module/mod.rs:268-270` | `every_literal_constructed_entity_kind_is_declared_in_produces` (`tests/architecture_parts/architecture_part5.rs:90`) | Ran `cargo test --test architecture` this pass — passed. | VERIFIED |
| REQ-CORE-012 | `ModuleContext::key()`/`key_opt()` are the sole sanctioned way a module reads a `HUNTSMAN_*` credential; a present-but-blank value or an un-edited `hse provision` template placeholder (`insert_<svc>_key_here`) must resolve as absent, never forwarded to a provider. | env var value | `Result<&str>` / `Option<&str>` | none | `key()` → `Error::MissingKey`; `key_opt()` → `None` | `src/core/module/mod.rs:334-398`; filter `src/util/keys/mod.rs::resolve_key` | `key_returns_ok_when_present`, `key_returns_missing_key_error_when_absent`, `key_treats_a_blank_value_as_missing`, `key_opt_returns_some_when_present`, `key_opt_returns_none_when_absent`, `key_opt_filters_blank_and_placeholder_slots` (`src/core/module/tests.rs`); structural guard `modules_never_read_credentials_via_raw_env` (`tests/architecture_parts/architecture_part3.rs:820`) | Ran `cargo test --lib core::module::tests` and `cargo test --test architecture modules_never_read_credentials_via_raw_env` this pass — all passed. | VERIFIED |
| REQ-CORE-013 | `ModuleContext::next_pooled_key()` / `report_key_exhausted()` implement the in-scan key cascade: a module whose key hits 401/403/429 can fetch the next untried pooled key for the same service and retry within one `process()` call. | `service: &str`, `tried: &HashSet<String>` (cascade); `service`, `key_value`, `status` (report) | `Option<String>` (cascade) | Mutates the global key pool's status + persists off-thread | `next_pooled_key` returns `None` once the pool is exhausted — caller must stop retrying, not loop. | `src/core/module/mod.rs:366-398`; pool `src/util/key_pool/mod.rs` | Key-pool unit tests exist under `src/util/key_pool/tests.rs` (55 tests, including `next_key_excluding_cascades_past_tried_keys`, the direct cascade contract). | Ran `cargo test --lib key_pool` this pass (Pass 2) — 55/55 passed. | VERIFIED |
| REQ-CORE-014 | `ModuleCategory`/`ModuleCost` round-trip serde exactly (their `as_str()` identifier must equal the serde snake_case wire form for every variant), so the API and the SPA never disagree on a category/cost string. | none | `&'static str` | none | A new enum variant that fails to update the drift-guard match arms fails to *compile* (arm-less match, no wildcard). | `src/core/module/mod.rs:19-106` | `module_cost_as_str_matches_serde`, `module_category_as_str_round_trips_serde` (`src/core/module/tests.rs`) | Ran `cargo test --lib core::module::tests` this pass — passed. | VERIFIED |
| REQ-CORE-015 (**new, Pass 14**) | `Module::is_derivation()` (default `false`) declares a module whose output is a deterministic transform of data already in the graph (parser, canonicaliser, permutation generator, offline decoder). Every module for which it is `true` must be listed in `hse_core::ENRICHMENT_ONLY_SOURCES` and vice-versa, every derivation must also be `is_passive()`, and every list entry that is not a registered module must be an engine pass (`geo_normalize`, `seed`). | `&self` | `bool` | none | Compile-time default `false`; the architecture tripwire fails the gate if the two declarations disagree or a list entry names neither a module nor an engine pass (a typo'd module name would otherwise silently re-enable corroboration for that module). | `src/core/module/mod.rs` (`is_derivation`), `hse-core/src/lib.rs` (`ENRICHMENT_ONLY_SOURCES`, 5 → 17 entries), the 15 module `impl`s | `derivation_modules_are_exactly_the_enrichment_only_sources` (`tests/architecture_parts/architecture_part2.rs`); `offline_derivation_sources_cannot_corroborate_the_seed_they_were_derived_from`, `is_enrichment_source_only_for_deterministic_passes`, `derived_entity_promotion_source_is_not_an_independent_source` (`hse-core/src/tests.rs`) | Ran `cargo test --test architecture` — 60/60 including the new tripwire; `cargo test --manifest-path hse-core/Cargo.toml` — 150/150; full lib suite 6876/6876. Before the fix a Phone entity carrying evidence from `seed` + `phone_intl` + `phone_au` + `phone_geo` reported `source_count() == 3` (three offline prefix-table lookups presented as three independent sightings); now 1, with `corroborating_sources()` empty and `c_effective() == confidence`. The browser build embeds this list, so `wasm-ui/pkg/hse_wasm_ui_bg.wasm` was regenerated with the pinned pipeline (toolchain parity proven first: the same pipeline reproduces the pre-change `pkg/` byte-for-byte) and `scripts/wasm_ui_drift_check.sh` passes. | VERIFIED |
| REQ-CORE-016 (**new, Pass 15**) | A module's finding says what its source can support: `pwned_passwords` (HIBP k-Anonymity range check) answers "this exact string appears N times as a PASSWORD in the corpus", so its entity is tagged `pwned-password` + `used-as-password` — never `breach` — its evidence summary says so and says it is not proof the account was breached, its attribute is `password_occurrences`, and a Username's confidence is capped at `HIGH_PLUS` (a bare handle is a stranger's password too). | Category error verified by reading the consumers: the `breach` tag is what AU-016 (`geo/chain.rs`), AU-019 (`breach.rs:703`), AU-022 (`org.rs:60`), the email-risk rule (`org.rs:99`, `breach` + `disposable` ≥ 2 signals) and the breach-geo promotion pass (`engine/passes.rs:201`) key on, so an email address that merely appears in a password list was entering "breach exposure" findings; the summary read "value seen in N breach(es)". `build_entities_high_count_yields_tagged_subject_with_evidence` now asserts the tags, the corrected summary and the attribute, and that `breach` is absent (fails on the baseline); `username_confidence_is_capped_because_a_handle_is_shared_by_strangers` pins the cap. `cargo test --lib modules::pwned_passwords` passes. Export redaction of the "Pwned Passwords" brand (REQ-API-EXPORT-007) is unaffected — the summary keeps that prefix. | VERIFIED |

---

## 2. The CLI surface (`src/main.rs`, `src/cli/`)

| ID | Behavior | Inputs | Outputs | Side effects | Failure behavior | Implementation location | Tests covering it | Runtime verification evidence | Status |
|---|---|---|---|---|---|---|---|---|---|
| REQ-CLI-001 | `hse` builds a bounded tokio runtime (2 worker threads, 16 max blocking threads) rather than `#[tokio::main]`'s 512-thread default, to bound OS-thread spawn on a low-RAM phone. | none | Configured `tokio::runtime::Runtime` | Process-wide runtime config | `.expect()`s on build failure (process aborts with a message — acceptable for a runtime that cannot be built at all). | `src/main.rs:12-17`; constants `src/lib.rs:112,120` | `architecture_constants` asserts `WORKER_THREADS == 2` (`tests/architecture_parts/architecture_part3.rs:89`, not `MAX_BLOCKING_THREADS`) — **and** a second, previously-uncited pre-existing test, `architecture_constants_are_correct` (`src/lib_tests.rs:63-69`, wired via `include!` at `src/lib.rs:161-163`), which asserts `MAX_BLOCKING_THREADS == 16` alongside `WORKER_THREADS == 2` and 3 other constants; `src/main.rs:12-14` wires both into the real `tokio::runtime::Builder`. Predates Pass 1 (`git log -S` places it before commit `26e430cf9`, #481). | **Found and fixed in Pass 10** — the row's own text said `MAX_BLOCKING_THREADS` "is not separately asserted," which was itself a search miss (a differently-named test elsewhere in the tree already covered it), not a real gap. Ran `cargo test --lib architecture_constants_are_correct` this pass — passed. | VERIFIED |
| REQ-CLI-002 | A panic caused specifically by a broken stdout pipe (`print!`/`println!` hitting `EPIPE`, e.g. `hse scan \| head`) exits 0 quietly instead of printing a backtrace; every other panic still propagates through the default hook. | Panic payload string | Process exit code | `std::process::exit(0)` for the matched case only | A genuine output failure unrelated to a closed pipe (e.g. disk full) still panics loudly, by design. | `src/main.rs:43-66` | `is_broken_pipe_panic` unit-tested in `src/main_tests.rs` (`#[cfg(test)] mod tests { include!("main_tests.rs"); }` at `src/main.rs:69`). | Ran `cargo test --bin hse` this pass (Pass 2) — `tests::recognises_only_the_broken_pipe_print_panic` passed. | VERIFIED |
| REQ-CLI-003 | `hse --version` / the `Cli` clap tree is internally consistent (no duplicate short flags, no conflicting IDs) — validated at test time via clap's own `debug_assert`, since a broken definition only panics at first real invocation otherwise. | none | n/a | none | A broken definition would otherwise panic on first invocation of the affected subcommand in production, not at build time. | `src/cli/command.rs:62-892` | `cli_definition_is_internally_consistent` (`src/cli/command.rs:909`) | Ran `cargo test --lib cli::command::tests::cli_definition_is_internally_consistent` this pass — passed. | VERIFIED |
| REQ-CLI-004 | `hse scan --min-confidence <f>` and `--min-expand-confidence` reject non-finite (`nan`/`inf`) and out-of-`0.0..=1.0` values at the argument-parsing boundary, rather than silently producing a floor that discards every entity. | CLI string | `Result<f64, String>` (clap `value_parser`) | none | Clap usage error before any scan work begins. | `src/cli/command.rs:23-34` (`confidence_floor`) | `confidence_floor_accepts_the_documented_range_inclusive`, `confidence_floor_rejects_non_finite_values`, `confidence_floor_rejects_values_outside_zero_to_one`, `confidence_floor_rejects_non_numeric_input` (`src/cli/command.rs`) | Ran `cargo test --lib cli::command::tests` this pass — all 4 passed. | VERIFIED |
| REQ-CLI-005 | `hse scan --min-marginal-yield <f>` rejects non-finite and negative values but, unlike confidence, accepts values above 1.0 (it's a rate, not a probability). | CLI string | `Result<f64, String>` | none | Clap usage error. | `src/cli/command.rs:47-60` (`non_negative_rate`) | `non_negative_rate_accepts_values_above_one`, `non_negative_rate_rejects_non_finite_and_negative` (`src/cli/command.rs`) | Ran `cargo test --lib cli::command::tests` this pass — passed. | VERIFIED |
| REQ-CLI-006 | `hse scan --full` (`--complete`/`--everything`) is the "no-compromise" preset: forces every module regardless of `--free-only`/`--passive-only`/`--modules`, pins `MAX_DEPTH` recursion, lifts the wrong-identity expansion gate, disables ROI pruning/dead-module skipping, and restores infra entities — overriding every one of those individual flags even when also passed. | CLI flags | `ScanCmd` struct fields | none | none (pure flag composition) | `src/cli/mod.rs:97-144` | Composition asserted inline via the doc comments; no dedicated unit test constructs `--full` alongside each conflicting flag and asserts the override wins for all of them simultaneously (each override is one `bool && !full` expression, individually simple but not table-tested as a set). | Read-only; traced the composition logic by hand, did not execute a combined-flags scenario. | IMPLEMENTED_UNVERIFIED |
| REQ-CLI-007 | `hse scan` with no `--value` and no `--input-file` falls back to `HUNTSMAN_DEFAULT_SEED`; if neither is set, errors with actionable guidance rather than a bare panic or an empty scan. | `Option<String>` (CLI), `Option<String>` (env-derived default) | `Result<String>` | none | `Error::Other("no target: ...")` | `src/cli/mod.rs:340-352` (`resolve_seed`) | `resolve_seed_prefers_explicit_cli_value`, `resolve_seed_falls_back_to_default_when_value_absent`, `resolve_seed_blank_cli_value_falls_back_to_default`, `resolve_seed_trims_explicit_value`, `resolve_seed_errors_when_nothing_set` (`src/cli/tests.rs:158-187`) — 5 dedicated tests covering exactly this precedence/error-message contract, predating Pass 1 (same `26e430cf9` commit as REQ-CLI-001's miss). | **Found and fixed in Pass 10** — the row's prior "none found" was a search miss, not a real gap (the earlier search apparently missed this exact block in `src/cli/tests.rs`). Ran `cargo test --lib resolve_seed` this pass — 5/5 passed. | VERIFIED |
| REQ-CLI-008 | `hse serve`'s key-write endpoint is loopback-only regardless of `--no-key-write`; a non-loopback bind requires either an explicit/auto-minted bearer token or `--allow-unauthenticated`. | `--bind`, `--auth-token`/`HSE_AUTH_TOKEN`, `--allow-unauthenticated`, `--no-key-write` | Server startup banner + enforced auth middleware | Binds a socket; may print a one-time minted token | Loopback + no token ⇒ silently open (by design, device-local); non-loopback + no token + no `--allow-unauthenticated` ⇒ auth is required (server still starts, all non-loopback requests 401). | `src/cli/serve/mod.rs:361-421`; enforcement `src/api/routes/mod.rs`, `src/api/auth/mod.rs` | `src/api/auth/tests.rs` (21 tests), `src/api/routes/tests.rs` (33 tests) | Ran `cargo test --lib api::auth` and `cargo test --lib api::routes` this pass (Pass 2) — 21/21 and 33/33 passed respectively. | VERIFIED |
| REQ-CLI-009 | `hse build-sha` exits non-zero when the build carries no verifiable revision (dirty tree, or no `.git` and no `HSE_BUILD_SHA`); `install.sh`/`hse update` treat a non-zero exit as "cannot prove it" and rebuild. | none | SHA to stdout (or JSON with `--json`) | Process exit code | Non-zero exit + `Error::Other` message | `src/cli/mod.rs:447-471` | No dedicated test name found asserting the exit-code contract specifically (`build_sha_is_verifiable` itself likely has coverage in its own module, not checked this pass). | Ran `./target/debug/hse build-sha; echo exit=$?` this pass (Pass 2) — `sha=cc55f3858…, dirty=1`, `exit=1` (the on-disk binary predates the current HEAD, the same "cannot prove it" signal a genuinely dirty tree produces). Exit code confirmed non-zero as documented. | VERIFIED |
| REQ-CLI-010 | `hse modules --category <cat> --json` filters the registry by category and emits the same JSON shape as `GET /api/v1/modules`. | `--category`, `--json` | stdout JSON or table | none | Unknown category presumably yields an empty filtered list (not explicitly checked this pass). | `src/cli/modules.rs`; `Command::Modules` in `src/cli/command.rs:276-283` | Not individually checked this pass. | Ran `./target/debug/hse modules --json` this pass — returned `{"count":188,"modules":[...]}` with per-module `consumes`/`category`/`cost` fields, confirming the JSON shape and that the registry currently holds 188 entries (used to derive REQ-README rows below). | VERIFIED |
| REQ-CLI-011 | `hse tidy`'s `--help` text quotes the dossier-cache retention cap ("newest N files") as a literal number that must equal `DOSSIER_MAX_FILES`, since clap renders doc-comment intra-doc links as raw unresolved markup rather than resolving them. | none | Help text string | none | Test failure on drift (not a runtime failure — an operator would just see a stale number in `--help`). | `src/cli/command.rs:866-874` (doc comment), constant `src/app/tidy/mod.rs` | `tidy_help_quotes_the_real_dossier_cap` (`src/cli/command.rs:920`) | Ran `cargo test --lib cli::command::tests::tidy_help_quotes_the_real_dossier_cap` this pass — passed. | VERIFIED |
| REQ-CLI-012 | `hse ingest`/`hse investigate --min-confidence` reuse the same `confidence_floor` parser as `hse scan`, so the "silent total data loss on NaN" regression is closed for every subcommand that takes a confidence floor, not just `scan`. | CLI string | `Result<f64, String>` | none | Same as REQ-CLI-004. | `src/cli/command.rs:508,545` | Same tests as REQ-CLI-004 (shared parser function) — no per-subcommand-wiring test confirms `ingest`/`investigate` actually pass the parsed value through unmodified to the extractor's filter. | Read-only for the wiring; the parser itself is VERIFIED (REQ-CLI-004). | PARTIAL |
| REQ-CLI-013 (**new, Pass 14**) | `hse config <key> on|off` validates `<key>` with the same `modules::is_known_toggle_key` the HTTP `PUT /api/v1/settings/toggles` handler uses (a registered `feature.*` switch, an `engine.<name>` from the search-engine catalogue, or a `module.<name>` in the registry) and exits non-zero on an unknown key instead of persisting a silent no-op. | CLI strings | `Result<()>` | `settings.json` written only for a known key | `Error::Other("unknown toggle key '<k>' …")`, nothing persisted | `src/cli/config.rs` (`cmd_config`), `src/modules/mod.rs` (`is_known_toggle_key` — the one validator, in the layer that owns the engine catalogue and the registry; the API handler's private duplicate `toggle_key_is_known` is deleted and it now calls the same function) | `config_set_rejects_an_unknown_toggle_key_instead_of_persisting_it` (`src/cli/tests.rs`), `is_known_toggle_key_accepts_exactly_the_three_real_key_families` (`src/modules/tests.rs`), the pre-existing `settings_toggles_put_*` API tests | Ran `cargo test --lib modules::tests::is_known_toggle_key cli::tests::config api::settings_handlers` — all pass. Before the fix `hse config module.shodann off` printed `module.shodann = ○ off`, persisted a key nothing reads, and exited 0. | VERIFIED |

---

## 3. `install.sh`

| ID | Behavior | Inputs | Outputs | Side effects | Failure behavior | Implementation location | Tests covering it | Runtime verification evidence | Status |
|---|---|---|---|---|---|---|---|---|---|
| REQ-INSTALL-001 (**fixed in Pass 8**) | Detects and rejects a Play Store Termux install (abandoned since 2020) via the `termux-build-info` marker, before doing anything else. | `/data/data/com.termux/files/usr/etc/termux-build-info` presence/contents | `die` with remediation message | Process exit 1 | Prints exact remediation (F-Droid link) via `die()`. | `install.sh:204-216` | `play_store_termux_is_detected_and_rejected_before_any_package_work` (`tests/install_invariants.rs`, new Pass 8) | **Was IMPLEMENTED_UNVERIFIED**: no dedicated test existed. **Fixed in Pass 8**: added a guard that confirms the `termux-build-info` read sits inside the `IS_TERMUX` branch, the marker match is case-insensitive, the failure is fatal (`die`, not a warning), and the message names the F-Droid remediation. Mutation-tested: flipping `grep -qi` to `grep -q` (case-sensitivity) reproducibly failed the new test before being reverted. Ran `cargo test --test install_invariants` — 6/6 passed. | VERIFIED |
| REQ-INSTALL-002 | `pkg`/apt index refresh retries up to 4 attempts with backoff (`2s, 4s, 6s`) before failing with actionable guidance (`termux-change-repo`). | Network/mirror state | Package manager state | Repeated `pkg update` invocations | `die` after 4th failed attempt, naming the fix. | `install.sh:625-632` | Not unit-testable (shell, network-dependent); no test found. | Read-only. | IMPLEMENTED_UNVERIFIED |
| REQ-INSTALL-003 | `cargo build` is retried up to 3 attempts with backoff (`3s, 6s, 9s`) to tolerate flaky mobile networks mid-build (crate downloads), per the README's "retrying on flaky mobile networks" claim. | Network state during build | Compiled binary or failure | Repeated `cargo build` invocations | `die` after 3rd failed attempt, pointing at the log file. | `install.sh:909-926` | Not unit-testable; no test found. | Read-only — but the claim is directly backed by inspectable retry-loop code, so this is a substantive match, not a bare assertion. | IMPLEMENTED_UNVERIFIED |
| REQ-INSTALL-004 | Prefers a prebuilt aarch64 binary over a source compile (Downloads-folder scan, then GitHub Releases download with size+ELF+`.sha256`+run-test verification); this is also the automatic fallback when an on-device build can't proceed. | `HSE_PREBUILT`, `HSE_PREBUILT_TAG`, `HSE_NO_DOWNLOAD`, `HSE_PREFER_BUILD`, `HSE_KEEP_MIRROR` env knobs | Installed `hse` binary | Writes to `$PREFIX/bin`, may write to Downloads cache | Falls through to source build if no valid prebuilt is found/verified. | `install.sh:322-668` (`resolve_target_sha`, `_prebuilt_sha_matches`, `_validate_prebuilt`, `maybe_use_prebuilt`, `maybe_download_prebuilt`, `_try_download_release`) | No dedicated automated test; `docs/INSTALL.md`'s "Environment knobs" table documents the same knob set this pass found live in the script (cross-checked by grep: all 8 knobs present in both). | Ran `grep -c` for each of the 8 documented knobs against `install.sh` this pass — every one has ≥3 occurrences, confirming they are wired, not just documented. | IMPLEMENTED_UNVERIFIED |
| REQ-INSTALL-005 | After building/installing the binary, delegates key-template provisioning to `hse provision --env-only --discover` (the Rust-native env-merge), rather than maintaining a second hand-copied template in the shell script. | none | Writes/merges `~/.huntsman.env` | Backs up existing file before changes (per `hse provision`'s own contract) | `log_warn` (non-fatal) if `hse provision` itself fails — install still completes. | `install.sh:1548-1558` | `hse provision`'s own merge/backup logic is covered by `src/cli/provision/tests.rs` (17 tests) — not re-run this pass. `env_template_keys_are_all_consumed` (architecture test) separately guards the template's own content. | Read-only for the install.sh call site; the delegate's test suite exists but wasn't re-run this pass. | IMPLEMENTED_UNVERIFIED |
| REQ-INSTALL-006 | Cross-platform: also works on Debian/Ubuntu (apt-get) and macOS (Darwin branch), not just Termux. | `uname -s` | OS-specific package install commands | `apt-get`/Homebrew-equivalent invocations | Unhandled OS falls through (not exhaustively checked this pass). | `install.sh:222-223,639-643` | No dedicated test (would require actual non-Termux CI runners). | Read-only; confirmed the `Linux`+`apt-get` and `Darwin` branches exist and dispatch to real package-install commands. | IMPLEMENTED_UNVERIFIED |
| REQ-INSTALL-007 | Self-heals a broken Termux `rust` package (ships libstd without a static `.rlib`) by reinstalling it automatically before attempting a build, per `docs/INSTALL.md`'s troubleshooting entry. | Detected build error signature | `apt-get install -y --reinstall rust` | Package reinstall | Falls through to the manual-fix message documented in `docs/INSTALL.md` if the self-heal itself fails. | `install.sh:709` | No dedicated test; matches the documented troubleshooting text closely (cross-checked by hand). | Read-only. | IMPLEMENTED_UNVERIFIED |
| REQ-INSTALL-008 | `hse-bg` background wrapper acquires the shared Android wake-lock through a refcounted helper (never releases it directly), and does not hardcode the Termux `$PREFIX` path. | none | Generated wrapper script | Manages `termux-wake-lock`/`termux-wake-unlock` | A wrapper that releases the lock directly, or hardcodes the prefix, breaks multi-wrapper coexistence / non-standard `$PREFIX` installs. | `install.sh` (wrapper-generation heredoc, ~line 1166-1273) | `generated_wrappers_never_release_the_shared_wake_lock_directly`, `wrappers_acquire_the_wake_lock_through_the_refcounted_helper`, `long_running_wrappers_actually_manage_the_shared_wake_lock`, `generated_wrappers_do_not_hardcode_the_termux_prefix` (`tests/install_invariants.rs`) | Ran `cargo test --test install_invariants` this pass — all 5 tests passed (see full output below). | VERIFIED |
| REQ-INSTALL-009 | TTY detection for interactive prompts happens *before* stdout is redirected into a pipe/log tee, so a piped `curl \| bash` invocation doesn't wrongly think it's interactive. | none | Boolean gate for interactive-only prompts | none | An interactive prompt issued after redirection would hang a piped/non-interactive install forever waiting for input that can never arrive. | `install.sh` (early in the script, before the log-tee redirection) | `tty_detection_happens_before_stdout_is_redirected_into_a_pipe` (`tests/install_invariants.rs`) | Ran `cargo test --test install_invariants` this pass — passed. | VERIFIED |
| REQ-INSTALL-010 (**new, Pass 8**) | CI cross-compiles every default-run binary (`hse`, `hse-ai-daemon`, `gen-oui`, `architecture-audit` — every `[[bin]]` with no `required-features` gate, via `cargo build --bins`, which Cargo itself skips a gated target for) for `aarch64-linux-android`, matching what `install.sh`'s on-device source-build fallback actually compiles (a bare `cargo build`, no `--bin` filter). | none | CI job pass/fail | none | Before this row: CI's `aarch64-android` job built only `--bin hse`, so a change that broke `hse-ai-daemon`/`gen-oui`/`architecture-audit`'s cross-compile for this target would merge clean and only surface as a failed on-device build the first time a real Termux user's install fell through to the source-build path. | `.github/workflows/ci.yml:227-248` (`aarch64-android` job) | The job itself — a compile-only CI check (no aarch64-android emulation exists in `ubuntu-latest`, so nothing here proves runtime correctness, only that the code compiles and links against the NDK's bionic sysroot for this exact target triple). | **Gap found in Pass 8**, triggered by a direct request to critically assess Termux/aarch64/no-root install readiness (not part of the self-directed backlog scan). Read `install.sh:910`'s on-device build invocation and `Cargo.toml`'s `[[bin]]` table directly: confirmed 4 bins ship with no feature gate (`dep-cooldown` is the only gated one, correctly excluded from install.sh's own build too). Widened the CI job's build and `--no-run` test-compile steps from `--bin hse` alone to `--bins` (a Copilot review suggestion, verified locally: `cargo build --bins` rebuilt all 4 ungated bins but left the already-built `dep-cooldown` binary's timestamp untouched, confirming Cargo silently skips a `required-features`-gated target under `--bins` rather than erroring — the same behavior install.sh's own bare `cargo build` relies on, and one that stays correct automatically if a new ungated bin is added later). Sanity-built the 3 newly-added bins natively (x86_64) — all compiled clean — but that was NOT proof of the aarch64 cross-compile itself: this sandbox has no Android NDK (confirmed via `scripts/gate.sh`'s own "SKIPPED (no Android NDK)" line every prior pass). **Confirmed**: this PR's own `aarch64-android` job ran on real CI twice — once explicitly naming all 4 bins (commit `c2a8dbd6c`, run `33579759589`, success) and once after simplifying to `--bins` (commit `e734bc33e`, run `33580302379`, success) — both genuinely cross-compiled and linked all 4 binaries against the NDK's aarch64 bionic sysroot. | VERIFIED |

---

## 4. Env/config template and key consumption

| ID | Behavior | Inputs | Outputs | Side effects | Failure behavior | Implementation location | Tests covering it | Runtime verification evidence | Status |
|---|---|---|---|---|---|---|---|---|---|
| REQ-ENV-001 | Every `HUNTSMAN_*` key declared in the canonical provisioning template (`src/cli/env_template.txt`) is genuinely read somewhere in `src/` (an `_ENV` const, a `ctx.key`/`key_opt` call, a `fetch_keyed_json` literal, or a raw `env::var` read), or is explicitly listed `[RESERVED]`/`NOT_YET_WIRED`. | Template file content, `src/` source tree | Pass/fail assertion | none | Guards the "documented key that silently does nothing" bug class (previously true of 6 real keys). | `src/cli/env_template.txt`; guard in `tests/architecture_parts/architecture_part3.rs:278-348` | `env_template_keys_are_all_consumed` | Ran `cargo test --test architecture env_template_keys_are_all_consumed` this pass — passed. | VERIFIED |
| REQ-ENV-002 | No module under `src/modules/` reads a `HUNTSMAN_*` credential via a raw `std::env::var(...)` call bypassing `ModuleContext::key`/`key_opt` (which is the sole enforcement point for the blank/placeholder filter); the two sanctioned non-credential exceptions (`HUNTSMAN_SEARCH_PROXY`, `HUNTSMAN_EMAIL_DOMAINS`) are allow-listed and anti-rot-checked. | `src/modules/` source tree | Pass/fail assertion | none | A credential read raw would forward an un-edited template placeholder to a provider as a live request. | `tests/architecture_parts/architecture_part3.rs:767-850` | `modules_never_read_credentials_via_raw_env` | Ran `cargo test --test architecture modules_never_read_credentials_via_raw_env` this pass — passed. | VERIFIED |
| REQ-ENV-003 (**fixed in Pass 4**) | The env var consumption guards above (REQ-ENV-001/002) only ever scan for **`HUNTSMAN_`-prefixed** literals (`push_huntsman_literal` requires the literal to start with `"HUNTSMAN_"`); any env var read via `std::env::var`/`var_os` under a *different* prefix is invisible to both tests, so it can be genuinely load-bearing yet fully undocumented with no test noticing. | Full `src/` tree | n/a | n/a | A tuning knob under this blind spot can drift silently (renamed, removed, or simply never documented) with zero test coverage. | Test blind spot in `tests/architecture_parts/architecture_part3.rs:353-365` (`push_huntsman_literal`); new guard `non_huntsman_env_reads_are_known` (~line 862) closes it | `non_huntsman_env_reads_are_known` (new, Pass 4) | **Corrected and fixed in Pass 4.** Pass 3's framing ("4 real, undocumented knobs feeding live `QuotaBudget`s") was itself unverified — Pass 4 traced every caller of `oathnet_quota()`/`see_know_quota()`/`wigle_quota()` directly (`grep -rn` across `src/`) and found only **`HSE_OATHNET_PER_SCAN_LIMIT`** has a live effect (`oathnet::BUDGET`, `src/util/oathnet/mod.rs:51`); the other three (`HSE_OATHNET_DAILY_LIMIT`, `HSE_SEE_KNOW_PER_SCAN_LIMIT`, `HSE_WIGLE_PER_SCAN_LIMIT`) are parsed by `quota_config.rs` and then never read again — `see_know_quota()`/`wigle_quota()` have zero callers outside their own definitions, and `OathnetQuotaConfig::daily_limit` is assigned to a local `config` binding at `oathnet/mod.rs:51` and never used again (a *different*, same-named field on `RealQuota`, populated from the live API's own response, is what actually tracks the daily limit). Fixed: (1) `.env.example` gained one commented entry for the one live knob only; (2) `quota_config.rs`'s own overclaiming module doc comment ("Each API module reads its limits once at startup and uses them") was corrected to state each var's actual live/dead status; (3) added `non_huntsman_env_reads_are_known` — a generalized, allow-listed, anti-rot-checked guard (mirrors `ALLOWED_RAW_ENV`/`NOT_YET_WIRED`'s existing idiom) that closes the blind spot for ANY future non-`HUNTSMAN_` var, not just these 4. Ran `cargo test --test architecture non_huntsman_env_reads_are_known` — passed. Ran `cargo test --test architecture` (full suite) — 56 passed, 0 failed. | VERIFIED |
| REQ-ENV-004 | `.env.example` (repo root, the file a user following its own header comment would copy to `~/.huntsman.env`) is a *second*, hand-maintained copy of the key list separate from the test-guarded canonical `src/cli/env_template.txt`; every key name it lists is at least textually referenced somewhere in `src/` (no outright typo'd/orphaned key found), but the two files have drifted apart in both directions — `.env.example` carries 37 keys/knobs `env_template.txt` doesn't (mostly non-credential tuning knobs like the `HUNTSMAN_WIGLE_*_SCAN_CAP`/`SESSION_CAP` family), while `env_template.txt` carries 7 keys `.env.example` doesn't (the `[RESERVED]`/`NOT_YET_WIRED` provider keys added after `.env.example` was last touched) — and none of this is covered by any architecture test the way `env_template.txt`'s own content is. | `.env.example`, `src/cli/env_template.txt`, `src/` | n/a | n/a | An operator who follows `.env.example`'s own instructions instead of `hse provision` gets a file that is stale but not actively wrong (every key it does list is genuinely consumed) and is simply missing 7 reserved-key placeholders that currently do nothing anyway. | `.env.example` (91 `HUNTSMAN_*` mentions, all commented-out) vs `src/cli/env_template.txt` (61 uncommented, live keys) | None. | Ran a diff of key-name sets between the two files this pass (`comm -23`/`comm -13` over sorted, deduped `grep -oE "HUNTSMAN_[A-Z0-9_]+"` extracts: 37 in `.env.example` only, 7 in `env_template.txt` only) and cross-checked every `.env.example`-only key against `grep -rl` over `src/` for a matching string literal — zero orphans found. | PARTIAL |
| REQ-ENV-005 | `HUNTSMAN_DEFAULT_SEED` (read via `std::env::var`, not the key-pool machinery) lets `hse scan`/`hse live` run with no `--value` at all. | env var | `Option<String>` | none | Absent + no `--value` ⇒ `Error::Other` with actionable guidance (REQ-CLI-007). | `src/util/keys/mod.rs::default_seed()` (consumer: `src/cli/mod.rs:340-352`, now VERIFIED under REQ-CLI-007) | **Strengthened in Pass 10.** `resolve_seed`'s own precedence/fallback logic is now fully covered (REQ-CLI-007, 5 tests). One layer below that, the pure precedence/blank-handling logic it delegates to, `keys::pick_default_seed`, has 3 dedicated tests too: `default_seed_precedence_env_wins_then_file_then_none`, `default_seed_trims_and_treats_blank_as_unset`, `default_seed_only_reads_the_seed_key` (`src/util/keys/tests.rs:677-709`). What remains genuinely untested: `keys::default_seed()`'s own one-line `std::env::var(DEFAULT_SEED_ENV)` read (`src/util/keys/io.rs:55`) — a thin, hard-to-unit-test-without-mutating-process-env wrapper, the same class of gap the ledger already tolerates for REQ-ENV-006 (clap's `env=` attribute). | Ran `cargo test --lib default_seed` this pass — 3/3 passed (in addition to REQ-CLI-007's 5/5). The remaining gap is a thin env-read wrapper, not the fallback logic itself — not worth a clean flip to VERIFIED per the ledger's own "no test exercises the actual X" standard, but no longer a real open question about whether the *behavior* works. | PARTIAL |
| REQ-ENV-006 | `HSE_BIND`/`HSE_AUTH_TOKEN` (non-`HUNTSMAN_`-prefixed, deliberately outside the credential-pool system) configure `hse serve`'s bind address and bearer token via clap's own `env = "..."` attribute, and are documented in `docs/RAILWAY.md` and `README.md` (not `.env.example`/`env_template.txt`, which is correct since these are deployment knobs, not OSINT-provider credentials). | env var (via clap) | Parsed `Cli` fields | none | Clap's own env-fallback semantics (CLI flag wins if both given). | `src/cli/command.rs:554,569` | No dedicated test asserts the clap `env = "HSE_BIND"` wiring actually reads the process environment (clap's own tests cover the mechanism generically, not this specific field). | Read-only; confirmed via `grep` that both vars appear in `docs/RAILWAY.md` and `README.md`. | IMPLEMENTED_UNVERIFIED |
| REQ-ENV-007 (**new, Pass 15**) | `util::http::redact_credentials` masks every configured secret wherever it appears in an upstream error body: the `HUNTSMAN_*` environment values AND every key value the rotation pool holds (`~/.huntsman/keys.json`, whatever its status — a revoked key is still a secret). | Gap verified by reading `redact_credentials`: its literal pass fed only `env_secret_values()`, but a key added via `hse keys add` / the Settings pool endpoints never lives in the environment — it is handed to a module by `merge_pool_into_env` / `ctx.next_pool_key` — so a pooled key echoed by a provider error body (the IPQS path-key case the env pass was added for) reached the persisted `events` table and the SSE stream verbatim. `pool_secret_values(&PoolData)` is pure; `redact_credentials` chains it over `global_pool().snapshot()`. `pooled_keys_are_masked_wherever_they_appear_whatever_their_status` (`src/util/http/tests.rs`) masks an Active and a Revoked pooled key in a path and a message over a local pool (never the global one, per REQ-TEST-006). `cargo test --lib util::http` passes. | VERIFIED |

---

## 5. Top-level `README.md`'s stated capabilities/counts

| ID | Behavior | Inputs | Outputs | Side effects | Failure behavior | Implementation location | Tests covering it | Runtime verification evidence | Status |
|---|---|---|---|---|---|---|---|---|---|
| REQ-README-001 | The "## Module Overview (N modules — F free, K key-gated/paid)" headline, and every other "N modules" mention in the README, must equal the live registry's total count and free/key-gated split. | `README.md`, `modules::registry()` | Pass/fail assertion | none | Was previously stated as "60+", "63", and "89" across files while the registry held different counts (per the test's own doc comment). | `README.md:277`; guard `tests/architecture_parts/architecture_part4.rs:306-374` | `readme_module_overview_count_matches_registry` | Ran `cargo test --test architecture readme_module_overview_count_matches_registry` this pass — passed (registry currently 188 modules, 142 free / 46 key-gated+paid). | VERIFIED |
| REQ-README-002 | The "Deterministic correlator: N rules (E entity + R graph-aware relation)" line must equal `core::correlator::rule_counts()`. | `README.md`, `correlator::rule_counts()` | Pass/fail assertion | none | Previously drifted once (108 documented vs 109 live) immediately after a rule addition. | `README.md` (Architecture section); guard `tests/architecture_parts/architecture_part4.rs:376-397` | `readme_correlator_rule_count_matches_registry` | Ran `cargo test --test architecture readme_correlator_rule_count_matches_registry` this pass — passed. | VERIFIED |
| REQ-README-003 (**fixed this pass**) | The "## Seed Types (16 supported)" table's per-seed-kind "Modules" column must equal the count of registered modules whose `consumes()` includes that `TargetKind`, for each of the 16 documented seed kinds. | `README.md`, `modules::registry()`, each module's `consumes()` | Pass/fail assertion | none | **Was BROKEN before this pass**: every row still cited an early (~90-module-era) snapshot against a registry that has since grown to 188 — e.g. README said "Full Name: 6" (live: 25), "Username: 14" (live: 50), "URL: 2" (live: 25), "Organisation: 2" (live: 22); 15 of 16 rows were wrong, understating real coverage by roughly 2-12×, with **zero test coverage** (unlike REQ-README-001/002 above, this table had no drift guard at all). | `README.md:258-273`; new guard `tests/architecture_parts/architecture_part4.rs` (`readme_seed_type_module_counts_match_registry`, appended this pass) | `readme_seed_type_module_counts_match_registry` (new, this pass) | **Fixed and verified this pass** — see "Fix applied" below for full command output. | VERIFIED |
| REQ-README-004 (**fixed this pass, Pass 2**) | The README's "Seed Types (16 supported)" heading claims 16 supported seed kinds; the CLI's `parse_target_kind` (`src/cli/mod.rs:362-390`) in fact accepts 19 distinct `TargetKind`s including 3 not in the table (`device_id`/`tower`/`cell`, `ssid`/`wifi`, `tracking_id`/`ga`/`gtm`). | `src/cli/mod.rs`, README table | n/a | n/a | **Was AMBIGUOUS before this pass**: not a false claim (the 3 omitted kinds are pivot-only — an operator would essentially never type them as a starting `--kind`, confirmed by their very low consumption counts, 1/1/2 modules), but the README never stated that scoping rule explicitly, so a reader had no way to distinguish "deliberately curated" from "incomplete" without reading the CLI source — and the architecture guard's own comment (`tests/architecture_parts/architecture_part4.rs`) already documented the exclusion rule without the README ever saying so. | `src/cli/mod.rs:362-390` vs `README.md:254-280`; fix in `README.md` + guard extended in `tests/architecture_parts/architecture_part4.rs` | `readme_seed_type_module_counts_match_registry` (extended this pass to also pin the new note's 3 counts) | **Fixed and verified this pass** — added one clarifying paragraph directly under the Seed Types table explaining the 3 pivot-only kinds and their live module counts (1, 1, 2), then extended the existing drift-guard test to assert that paragraph's counts against the live registry too, so it can't silently go stale the way the table itself once did (REQ-README-003). Ran `cargo test --test architecture readme_seed_type_module_counts_match_registry` — passed. | VERIFIED |
| REQ-README-005 | The "curated highlight" module list under "API-Free (no keys required) — 92" / "Key-gated / Paid — 32 (28 key-gated · 4 paid)" is explicitly disclaimed ("not the full list") and therefore is NOT expected to sum to the registry's 188/142/46 totals. | `README.md:283-303` | n/a | n/a | None — this is a documented exception, not a defect. | `README.md:283` (the disclaimer itself) | Deliberately excluded from `readme_module_overview_count_matches_registry`'s scope per that test's own doc comment. | Read-only; confirmed the disclaimer text is present and the curated counts (92 + 32 = 124) indeed don't match the registry total (188), consistent with "curated, not exhaustive." | OBSOLETE (n/a — by design, not a gap) |
| REQ-README-006 | The Quick Start block's `hse` command examples (`hse doctor`, `hse modules`, `hse engines`, `hse config`, `hse keys status`, `hse query ... --dark`, `hse scan --kind ... --depth N`, `hse serve`, `hse live --kind ... --interval N`) all name real, currently-registered subcommands/flags. | `README.md:205-218`, `src/cli/command.rs` | n/a | n/a | A stale example naming a removed/renamed flag would silently mislead a new user copy-pasting it. | `README.md` Quick Start section | No test walks README code blocks against the live `Cli::command()` tree. | Ran 5 of the 9 named commands end-to-end this pass (Pass 2) — `hse doctor`, `hse modules`, `hse engines`, `hse config`, `hse keys status` all exited 0 and produced the documented shape of output. `hse query ... --dark`, `hse scan --kind ... --depth N`, `hse serve`, `hse live --kind ... --interval N` were not run (network calls / long-running processes, unsafe to smoke-test blindly) — their subcommand+flag names were still hand-confirmed against `src/cli/command.rs`'s `Command` enum as in the first pass. | PARTIAL |
| REQ-README-007 | `install.sh`'s documented knobs (`HSE_PREBUILT`, `HSE_PREBUILT_TAG`, `HSE_NO_DOWNLOAD`, `HSE_PREFER_BUILD`, `HSE_KEEP_MIRROR`, `HSE_REF`, `HSE_INSTALL_DIR`, `HSE_WITH_AI`) named in the README's install section are all genuinely read by `install.sh` (cross-reference of REQ-INSTALL-004/README). | `README.md:26-90`, `install.sh` | n/a | n/a | A documented-but-unread knob would silently no-op for an operator setting it. | `README.md`, `install.sh` (multiple sites, see REQ-INSTALL-004) | None dedicated; `docs/INSTALL.md`'s own "Environment knobs" table duplicates the same claim. | Ran `grep -c` for each knob against `install.sh` this pass — all 8 present with ≥3 occurrences each (declaration + read + doc comment, typically). | VERIFIED |
| REQ-README-008 | "Value-per-query is maximised by default (v1.14+)" / convex budget allocation claim: `--no-convex-budget` is the only way to disable it, and it is on by default in both `hse scan` and `hse live`. | `README.md:92-99`, `src/cli/mod.rs:120-122,266-267` | n/a | n/a | If the default were accidentally flipped, every scan would silently stop maximizing value-per-query with no operator-visible signal. | `src/cli/mod.rs:122` (`convex_budget: !no_convex_budget`) for `scan`; `:267` for `live` | `core::convex` module has its own unit tests (not enumerated/re-run this pass); no CLI-level test asserts the *default* (omitting the flag) resolves to `convex_budget: true`. | Read-only; traced the boolean literally (`!no_convex_budget` with `no_convex_budget` defaulting `false` via `SetTrue` action ⇒ default `true`) but did not find or run a test pinning this specific default. | IMPLEMENTED_UNVERIFIED |
| REQ-README-009 | The MITRE ATT&CK claim ("all 14 tactics and every current technique/sub-technique (v17.1)... but HSE only claims coverage of Reconnaissance") is backed by `src/core/attack/`'s static data and the per-module technique mapping enforced by REQ-CORE-010. | `README.md:307-330`, `src/core/attack/` | n/a | n/a | An unmapped/invalid technique ID would be a false "coverage" claim. | `src/core/attack/mod.rs` (catalogue), `tests/architecture_parts/architecture_part2.rs` (enforcement) | `every_module_maps_to_valid_attack_reconnaissance_techniques` (same test as REQ-CORE-010) checks every declared ID resolves in the catalogue. | Ran `cargo test --test architecture` this pass — passed (same run as REQ-CORE-010). | VERIFIED |
| REQ-README-010 | The runtime-independence claim ("runtime carries no AI/ML inference dependency" outside the opt-in `hse-ai-daemon` binary) matches the actual crate dependency graph. | `Cargo.toml`, README's runtime-independence framing | n/a | n/a | An accidental transitive ML dependency in the main binary would falsify a stated architecture guarantee. | Guard: `tests/architecture_parts/architecture_part4.rs` (`runtime_carries_no_ai_ml_inference_dependency`) | `runtime_carries_no_ai_ml_inference_dependency` | Ran `cargo test --test architecture runtime_carries_no_ai_ml_inference_dependency` this pass — passed. | VERIFIED |

---

## Fix selection rationale

Two candidate gaps stood out as genuinely load-bearing and unguarded:

1. **REQ-ENV-003** — 4 real, undocumented, non-`HUNTSMAN_`-prefixed env knobs
   (`HSE_OATHNET_PER_SCAN_LIMIT`, `HSE_OATHNET_DAILY_LIMIT`,
   `HSE_SEE_KNOW_PER_SCAN_LIMIT`, `HSE_WIGLE_PER_SCAN_LIMIT`) sit in a genuine
   blind spot of the existing env-consumption architecture tests. However,
   each has a safe default, each is superseded in practice by a separately
   *documented* override (`HUNTSMAN_*_SCAN_CAP`), and the module's own doc
   comment frames them as a testing/repeatability knob rather than an
   operator-facing feature — so the real-world blast radius of leaving this
   undocumented is small.

2. **REQ-README-003** — the README's "Seed Types" table's per-seed module
   counts were wrong for 15 of 16 rows, by as much as 12× (URL: documented 2,
   live 25), with **zero test coverage**, sitting in the single highest-traffic
   file in the repository, directly adjacent to (and formatted identically to)
   two *other* count claims that already have drift guards
   (REQ-README-001/002) — making its own lack of a guard the more surprising
   and more likely-to-recur gap. It is also the more directly user-facing
   harm: an operator deciding whether a phone/email/domain seed is "worth
   scanning" reads this table first, and it was silently understating actual
   OSINT breadth by 2-12× depending on seed kind.

**REQ-README-003 was selected as the pass's one fix** — higher visibility,
higher-confidence "this actually misleads a user today", and directly
patternable against the two existing sibling tests, making the fix both
minimal and idiomatic.

## Fix applied

**Change 1 — `README.md`** (the "Seed Types (16 supported)" table): corrected
all 15 wrong per-seed "Modules" column values to match the live registry
(`188` modules) as of this pass:

| Seed | Was | Now (live) |
|---|---|---|
| Email | 35 | 42 |
| Username | 14 | 50 |
| Phone | 7 | 18 |
| Full Name | 6 | 25 |
| IP Address | 33 | 42 |
| Domain | 39 | 57 |
| ASN | 1 | 4 |
| CIDR | 3 | 2 |
| Coordinates | 6 | 19 |
| Address | 2 | 5 |
| URL | 2 | 25 |
| Organisation | 2 | 22 |
| ABN/ACN | 1 | 7 |
| MAC Address | 3 | 9 |
| Crypto Address | 2 | 5 |
| API Key | 1 | 1 *(already correct)* |

**Change 2 — `tests/architecture_parts/architecture_part4.rs`** (regression
test, appended at end of file): added
`readme_seed_type_module_counts_match_registry`, which parses each of the 16
table rows out of `README.md`, recomputes the live module count per
`TargetKind` from `modules::registry()`, and fails naming every mismatch —
the same no-silent-drift pattern as the two sibling tests
(`readme_module_overview_count_matches_registry`,
`readme_correlator_rule_count_matches_registry`) it sits beside.

### Verification commands run (this pass, in order)

```
$ cargo test --test architecture readme_seed_type_module_counts_match_registry -- --nocapture
# (before the fix) FAILED — panicked with the exact 15 mismatches listed above,
# e.g. "Email: README says 35, live registry has 42", "URL: README says 2, live
# registry has 25", ...
# (after the README fix) →
running 1 test
test readme_seed_type_module_counts_match_registry ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 54 filtered out; finished in 0.10s

$ cargo test --test architecture
test result: ok. 55 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.43s

$ cargo fmt --all
# then, to avoid reformatting concurrently in-flight files under src/modules/*
# (out of this pass's scope — see "Known limitations"), formatting was
# re-applied narrowly:
$ rustfmt --edition 2024 tests/architecture_parts/architecture_part4.rs
# diff confirmed scoped to only the newly-added function (89 lines, purely
# additive, no reformatting of pre-existing code)

$ cargo clippy --all-targets --features dep-cooldown -- -D warnings
Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 11s
# clean exit, zero warnings (run twice, since the first attempt raced a
# transient, unrelated compile error in the concurrently-edited
# src/modules/niamonx/{mod,tests}.rs — resolved by that other session between
# the two attempts, per "Known limitations" above; the second run was clean)

$ cargo test --lib core::module::tests -- --test-threads=4
running 19 tests
test core::module::tests::is_empty_and_len_track_correctly ... ok
test core::module::tests::extend_adds_multiple_entities ... ok
... (19 total)
test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 6799 filtered out; finished in 0.00s

$ cargo test --lib cli::command::tests -- --test-threads=4
running 8 tests
test cli::command::tests::confidence_floor_accepts_the_documented_range_inclusive ... ok
test cli::command::tests::confidence_floor_rejects_non_finite_values ... ok
test cli::command::tests::confidence_floor_rejects_non_numeric_input ... ok
test cli::command::tests::confidence_floor_rejects_values_outside_zero_to_one ... ok
test cli::command::tests::non_negative_rate_accepts_values_above_one ... ok
test cli::command::tests::non_negative_rate_rejects_non_finite_and_negative ... ok
test cli::command::tests::tidy_help_quotes_the_real_dossier_cap ... ok
test cli::command::tests::cli_definition_is_internally_consistent ... ok
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 6811 filtered out; finished in 0.00s

$ cargo test --test install_invariants
running 5 tests
test tty_detection_happens_before_stdout_is_redirected_into_a_pipe ... ok
test wrappers_acquire_the_wake_lock_through_the_refcounted_helper ... ok
test long_running_wrappers_actually_manage_the_shared_wake_lock ... ok
test generated_wrappers_do_not_hardcode_the_termux_prefix ... ok
test generated_wrappers_never_release_the_shared_wake_lock_directly ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

# Note: these three lib/integration builds each needed a fresh, non-incremental
# compile of the full 187-module crate under a shared build lock contended by
# the concurrent module-audit session (see "Known limitations") — 6m06s, 1m22s,
# and 4m18s respectively. All three passed cleanly once each compile finished;
# no test content was skipped or assumed.

# Final re-confirmation after all the above (tree still clean of any
# regression from the concurrent activity):
$ cargo test --test architecture
test result: ok. 55 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.06s
$ cargo clippy --all-targets --features dep-cooldown -- -D warnings
Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.28s   # clean, zero warnings
```

All commands were run from the repository root
(`/home/user/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-`) against
the working tree as left by this pass (`README.md` and
`tests/architecture_parts/architecture_part4.rs` modified; no other files
touched by this pass — see `git status` note in "Known limitations").

---

## Pass 2 findings

Re-verified every Pass 1 row left `IMPLEMENTED_UNVERIFIED`/`PARTIAL`/
`AMBIGUOUS` by actually running its cited test/command (not by re-reading the
code — Pass 1 already did that). Nine rows moved:

| ID | Pass 1 status | Pass 2 status | What changed |
|---|---|---|---|
| REQ-CORE-008 | IMPLEMENTED_UNVERIFIED | VERIFIED | Ran the 3 cited `core::engine::timeout::tests` — passed. |
| REQ-CORE-009 | PARTIAL | VERIFIED (**fixed**) | The one genuine gap this pass found and closed — see below. |
| REQ-CORE-013 | IMPLEMENTED_UNVERIFIED | VERIFIED | Ran `cargo test --lib key_pool` — 55/55 passed. |
| REQ-CLI-002 | IMPLEMENTED_UNVERIFIED | VERIFIED | Ran `cargo test --bin hse` — the broken-pipe-panic test passed. |
| REQ-CLI-008 | IMPLEMENTED_UNVERIFIED | VERIFIED | Ran `api::auth`/`api::routes` — 21/21 and 33/33 passed. |
| REQ-CLI-009 | PARTIAL | VERIFIED | Ran `hse build-sha` directly — confirmed non-zero exit + the dirty/stale-build signal. |
| REQ-README-004 | AMBIGUOUS | VERIFIED (**fixed**) | Closed the ambiguity — see below. |
| REQ-README-006 | IMPLEMENTED_UNVERIFIED | PARTIAL | Ran 5 of 9 named example commands (the safe, non-network, non-long-running ones) — all exited 0. Downgraded rather than upgraded: running fewer than all of them is a narrower claim than Pass 1's read-only "traced by hand", not a stronger one. |
| REQ-CLI-003..007, 012; REQ-INSTALL-001..007; REQ-ENV-006 | unchanged | unchanged | No dedicated automated test exists to run for these (shell-only behavior, or genuinely no test found) — re-confirmed the absence rather than manufacturing a claim, left as `IMPLEMENTED_UNVERIFIED`/`PARTIAL`. |

**Fix 1 — REQ-CORE-009** (the inter-scan entity cache never had a
dispatch-level HIT/MISS test): `core::test_support::InMemoryStore` — the
standard in-memory `StoragePort` double every engine test builds on —
inherited the trait's no-op defaults for `archive_module_result`/
`lookup_module_result_fresh`, so a lookup could never return a hit through it;
the cache-skips-`process()` behavior was structurally untestable independent
of the storage layer's own (already-thorough) coverage in
`storage::archive_tests`. Gave `InMemoryStore` genuine in-memory cache
semantics mirroring `Store`'s exact freshness predicate, then added
`core::engine::tests::cache_hit_skips_reprocessing_a_later_scan_of_the_same_target`:
dispatches a probe with a nonzero `cache_ttl_secs()` against one target under
two different scan_ids and asserts `process()` runs exactly once (the second
dispatch replays from cache), plus a third dispatch against a different
target proves the cache is keyed per-target. This changed `InMemoryStore`'s
documented contract, which broke `core::port::tests::default_optional_methods_are_documented_no_ops`'s
premise ("`InMemoryStore` overrides NONE" of the 7 default methods) — updated
that test's assertions and comment for the new 5-no-op/2-real-cache split.

**Fix 2 — REQ-README-004** (the ambiguity over the omitted `device_id`/
`ssid`/`tracking_id` seed kinds): added one clarifying paragraph directly
under the Seed Types table (`README.md`) stating why they're omitted and
their live module counts, then extended
`readme_seed_type_module_counts_match_registry`
(`tests/architecture_parts/architecture_part4.rs`) to assert that paragraph's
3 counts against the live registry too, closing the same "documented claim,
zero drift guard" gap REQ-README-003 fixed for the table itself.

### Verification commands run (Pass 2, in order)

```
$ cargo test --lib key_pool -- --test-threads=4                  # 55 passed
$ cargo test --lib core::engine::timeout::tests -- --test-threads=4   # 3 passed
$ cargo test --bin hse -- --test-threads=4                       # 1 passed
$ cargo test --lib api::auth -- --test-threads=4                 # 21 passed
$ cargo test --lib api::routes -- --test-threads=4                # 33 passed
$ ./target/debug/hse build-sha; echo exit=$?                      # exit=1, dirty=1
$ ./target/debug/hse doctor / modules / engines / config / keys status   # all exit 0
$ cargo fmt --all
$ cargo test --lib core::engine::tests::cache_hit_skips_reprocessing_a_later_scan_of_the_same_target
    # test result: ok. 1 passed
$ cargo test --lib --features dep-cooldown                        # 6836 passed, 0 failed
$ cargo test --test architecture                                  # 55 passed
$ cargo clippy --all-targets --features dep-cooldown -- -D warnings   # clean
```

---

## 6. The HTTP API surface (`src/api/`)

Derived via a 4-agent parallel sweep (routes+auth, scan handlers,
settings/cells/key-harvest/update handlers, scan export+redaction) followed
by one adversarial re-verification agent per candidate row — every row below
was independently re-checked against current source, and every cited test
was re-run by the verifying agent (not accepted from the deriving agent's
say-so). All 35 rows survived verification with their status confirmed as
shown; runtime evidence below is the deriving agent's, condensed. 35 rows
total: 20 VERIFIED (1 of which — REQ-API-MISC-004 — was BROKEN and is fixed
this pass), 12 PARTIAL, 2 IMPLEMENTED_UNVERIFIED, 1 UNREACHABLE.


### Routes + auth middleware

| ID | Behavior | Runtime verification evidence | Status |
|---|---|---|---|
| REQ-API-ROUTE-001 | The production `router()` wires every endpoint (~87 explicit path+method registrations plus `/static/{*file}`, `/favicon.ico`, `/manifest.webmanifest`, and the `/api` and `/` fallbacks) to its handler. Critically, this is the SAME function a live `hse serve`… | Ran a cross-section through the real router this pass, each individually: `cargo test --test api api_not_found_returns_json --exact` -> ok; `spa_fallback_returns_html` -> ok; `favicon_returns_svg_not_html` -> ok; `manifest_is_valid_installable_pwa` -> ok; `responses_carry_security_headers` -> ok; `loopback_bind_is_unchanged_by_the_auth_work` -> ok (6/6 passed, 0 failed each). Did not individually re-run all ~90 doc-table rows. | VERIFIED |
| REQ-API-ROUTE-002 | The router()'s own doc-comment "Endpoint surface" table at the top of the file claims to enumerate the whole route set; every GET/POST/PUT/DELETE actually registered in the function body should appear as a row. | Ran `grep -cE '^//! \\| (GET\|POST\|PUT\|DELETE\|\*) ' src/api/routes/mod.rs` -> 90 doc rows; cross-referenced by hand against the code's `.route()` calls (lines 415-640) and confirmed `/favicon.ico` (line 636) and `/manifest.webmanifest` (line 640) are real, working, GET routes with no doc-table row. Both are independently tested and passing: `cargo test --test api favicon_returns_svg_not_html --exact` -> ok; `manifest_is_valid_installable_pwa --exact` -> ok. | PARTIAL |
| REQ-API-ROUTE-003 | Any unmatched path/method under `/api` (typo'd endpoint, `/api/v2/...`) returns a JSON 404 naming the caller-typed path — not the embedded SPA's HTML 200 — via `.fallback(api_not_found)` nested at both the `/api/v1` and outer `/api` router levels, using… | Ran `cargo test --test api api_not_found_returns_json --exact --test-threads=4` this pass: `running 1 test / test api_not_found_returns_json ... ok / test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 122 filtered out`. | VERIFIED |
| REQ-API-ROUTE-004 | `enforce_csrf` requires an `X-HSE-CSRF` header on every POST/PUT/DELETE/PATCH under `/api` (GET/HEAD/OPTIONS exempt), including a BODYLESS mutating POST — the CORS-simple-request vector a cross-site page can drive with no preflight. Applies uniformly to every… | Ran `cargo test --test api csrf -- --test-threads=4` this pass: `running 2 tests / test bodyless_mutating_post_requires_csrf_header ... ok / test scan_import_requires_csrf_header ... ok / test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 121 filtered out`. | VERIFIED |
| REQ-API-ROUTE-005 | On a LOOPBACK bind only, `enforce_host_allowlist` rejects (403, before any handler) a request whose `Host` header is present AND not a loopback alias (the bind string itself, or localhost/127.0.0.1/[::1] with the bound port) — defeating DNS rebinding, where a… | Ran `cargo test --lib api::routes -- --test-threads=4` this pass: 33/33 passed (includes both routes/tests.rs cases: `host_allowlist_covers_loopback_aliases_and_rejects_rebind ... ok`, `host_allowlist_is_none_for_non_loopback_bind ... ok`). Ran `cargo test --test api dns_rebind_host_header_is_rejected --exact` separately: `test result: ok. 1 passed; 0 failed`. | VERIFIED |
| REQ-API-ROUTE-006 | build_cors_layer's docstring states it fixes a real, previously-flagged vulnerability (PR #9): CORS is bound to the bind's own explicit `http(s)://<bind>` origin (plus localhost/127.0.0.1/[::1] aliases, loopback only) — never `Access-Control-Allow-Origin:… | Ran `cargo test --lib api::routes` this pass — the 3 named CORS tests pass (part of 33/33), which is exactly the finding: a test that cannot fail carries no verification value regardless of pass/fail. Read build_cors_layer directly and confirmed it constructs an explicit Vec<HeaderValue> origin list via `push()`, never `Any` — the underlying behavior is genuinely implemented, but nothing in the test suite would catch a future regression to Any. | IMPLEMENTED_UNVERIFIED |
| REQ-API-ROUTE-007 | `/api/v1/scans/import` alone gets `DefaultBodyLimit::max(scan_handlers::MAX_UPLOAD_BYTES)` (16 MB) layered onto just that one `.route()` registration, raising it above axum's 2 MB default so a legitimate 2-16 MB breach dossier isn't 413'd before reaching the… | Ran `cargo test --test api dossier_upload_accepts_body_larger_than_axum_default_limit --exact --test-threads=4` this pass: `test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 122 filtered out; finished in 3.38s` — a real >2.2MB body was POSTed through the actual router and confirmed NOT rejected with 413. | VERIFIED |
| REQ-API-ROUTE-008 (**new, Pass 14**) | Every embedded `/static` asset is served with a strong, content-derived `ETag` (`"` + first 16 hex of SHA-256 over the served bytes + `"`, computed once per process) under `Cache-Control: public, max-age=3600, must-revalidate`; a conditional `GET` whose `If-None-Match` carries that tag gets `304`, any other tag — including the crate-version tag the pre-fix handler emitted — gets `200` with the bytes. | The tag used to be `env!("CARGO_PKG_VERSION")` on the premise that the version identifies the embedded bytes; it does not for this project's release model (`install.sh` `HSE_REF=main` and the in-app updater rebuild from `main` in place; the SPA/wasm changed in 8 of 88 consecutive `main` commits under one version), so after every upgrade a browser revalidated with the old tag and was told `304` — stale JS/wasm until someone bumped the version. Ran `cargo test --lib api::routes` (34, incl. `every_embedded_asset_etag_is_the_hash_of_its_bytes`: every `APP_FILES`/`VENDOR_FILES` entry's tag equals the SHA-256 of its bytes and is not the version tag) and `cargo test --test api static_assets_carry_a_content_derived_etag_not_the_crate_version` (tag ≠ version, 18-char quoted hex, distinct per asset, stable across requests, `304` on the real tag, `200` + body on the stale version tag) — all pass. | VERIFIED |
| REQ-API-ROUTE-009 (**new, Pass 14**) | The production binary embeds and serves only the SPA and its assets: no diagnostic or fixture page. `wasm-ui/pkg/wasm_test.html` (71 KB, self-described TEMPORARY, unreferenced by `spa.html`, carrying synthetic identities including a non-`example.com` `gmail.com` address) is removed from `APP_FILES` and the repository, and the wasm start-up `render_proof()` that wrote into that page's `#wasm-proof` element — baking `proof@example.com` / "corroborating observation" fixture strings into the shipped wasm — is removed with it. | `GET /static/wasm_test.html` → 404; `strings hse_wasm_ui_bg.wasm` no longer contains the fixture identity; `spa_references_only_served_static_assets`, `static_assets_carry_a_content_derived_etag_not_the_crate_version` and the routes unit tests pass; `scripts/wasm_ui_drift_check.sh` passes on the regenerated pkg. Every view is ported (the page's own removal condition) and its checks live in wasm-ui's unit tests. | VERIFIED |
| REQ-API-ROUTE-010 (**new, Pass 16**) | Every entity-serving read endpoint applies the candidate quarantine by default: `GET /scans/{id}/path`, `/communities`, `/trust` and `/gaps` now run their inputs through `EntityViewGate` (`?include_candidates=1` opts in), and `core::path::connect_cross_scan` takes `include_candidates` so its own store-merged graph is gated too. | Found by the Pass 16 discovery sweep and confirmed 3/3 by adversarial verification: these four handlers loaded `entities_and_relations`/`entities_for_scan` and passed the raw set to `community::detect`, `trust::propagate`, `gap::analyze` and `connect_values`/`connect_cross_scan` — none of which know the tag — so a `tags::CANDIDATE` row (an unverified same-name breach record the correlator quarantined) could be returned by value as a path node, join or name a community, be ranked, or be reported by `/gaps` as an actionable "orphan" with a re-scan recommendation, all without the opt-in every sibling requires and against `gap::analyze`'s own "every input is a validated seed" precondition. `paths_between`'s `present_uids`/`build_adjacency` refuse an edge whose endpoint is absent, so filtering entities is sufficient for the path graph. Locks: `scan_path_quarantines_a_candidate_bridge_by_default`, `scan_communities_quarantines_candidate_entities_by_default`, `scan_gaps_quarantines_candidate_entities_by_default` (`tests/api.rs`; `/path` had no prior coverage at all — `scan_path_connects_two_endpoints_through_a_relation` adds the baseline), `connect_cross_scan_hides_a_candidate_bridge_unless_opted_in` (`src/core/path/tests.rs`). With each gate reverted, all three API locks FAIL. | VERIFIED |
| REQ-API-AUTH-001 | `auth::resolve(bind, supplied, allow_unauthenticated)` returns `Ok(None)` (no gate) for a loopback bind unless a token was explicitly supplied (honored anyway, for defence-in-depth); for a non-loopback bind, returns `Ok(Some(token))` — the supplied token if… | Ran `cargo test --lib api::auth -- --test-threads=4` this pass: `running 21 tests ... test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 6836 filtered out`, including all 6 posture-resolution tests listed above. | VERIFIED |
| REQ-API-AUTH-002 | When a token is resolved, `enforce_auth` is layered as the outermost-but-one middleware (only `set_security_headers` sits further out) so it runs before the Host allowlist, CORS, CSRF, and every handler/SPA/static asset — an unauthenticated non-loopback… | Ran `cargo test --lib api::auth`: 21/21 passed (includes all 9 middleware tests). Ran `cargo test --test api exposed_bind -- --test-threads=4` separately: `running 4 tests / test exposed_bind_bootstraps_a_browser_then_drops_the_token_from_the_url ... ok / test exposed_bind_rejects_every_unauthenticated_surface ... ok / test exposed_bind_rejects_an_unauthenticated_mutation ... ok / test exposed_bind_admits_a_valid_token ... ok / test result: ok. 4 passed; 0 failed`. Ran… | VERIFIED |
| REQ-API-AUTH-003 | `AuthToken::matches` hashes the presented credential with SHA-256 and compares digests via `ct_eq`, which XOR-accumulates every byte pair and checks once at the end rather than short-circuiting on the first mismatch, so response timing cannot leak the token's… | Ran `cargo test --lib api::auth` this pass — all 4 tests pass (part of 21/21). These tests confirm ct_eq's functional correctness (right/wrong tokens match/reject as expected, near-misses at every position rejected) and that Debug never leaks the plaintext. They do NOT and cannot measure that the comparison is actually constant-time on real hardware — no timing/statistical test exists in the suite; the constant-time guarantee itself rests on reading the loop's structure (no early return), not… | PARTIAL |
| REQ-API-AUTH-004 | On a non-loopback bind, presenting a valid `X-HSE-CSRF` header with NO bearer credential must still 401 — CSRF and bearer-auth are independent, both-required (AND-ed) controls, not substitutes for each other, because `enforce_auth` is layered OUTSIDE… | Ran `cargo test --test api exposed_bind -- --test-threads=4` this pass (part of the 4-test group reported above): `test exposed_bind_rejects_an_unauthenticated_mutation ... ok` — a POST to /api/v1/radar carrying X-HSE-CSRF but no bearer token still returned 401. | VERIFIED |
| REQ-API-AUTH-005 (**new, Pass 14**) | On a non-loopback bind, `GET /api/v1/health` (`api::auth::HEALTH_PATH`) is admitted without a credential — it is the dependency-free liveness probe (status + version, nothing operator- or subject-derived) that `railway.json`'s `healthcheckPath` hits with none — while every other verb on that path and every other route stays gated; `railway.json`'s `healthcheckPath` is pinned to the constant by test. | Ran `cargo test --lib api::auth` including `health_probe_is_exempt_from_the_gate_for_get_only` (GET → 200, POST → 401, look-alike path → 401) and `cargo test --test api exposed_bind_still_answers_the_unauthenticated_health_probe` (the real `--bind 0.0.0.0` router: 200 without a token, POST 401, manifest path == constant) — all pass; `exposed_bind_rejects_every_unauthenticated_surface` is unchanged and still passes. Before the fix the same request returned 401, so the Dockerfile's `hse serve --bind 0.0.0.0:$PORT` could never pass its own Railway probe (`restartPolicyType: ON_FAILURE` → restart loop). | VERIFIED |

### Scan lifecycle handlers

| ID | Behavior | Runtime verification evidence | Status |
|---|---|---|---|
| REQ-API-SCAN-001 | POST /api/v1/scans validates the target at the API boundary (shape check via Target::validate_verbose, e.g. an email kind whose value has no '@') BEFORE the scan is persisted or dispatched to the engine, rejecting with 400 rather than queuing a scan that… | Ran `cargo test --lib api::scan_handlers` this pass — 14/14 passed, including build_scan_from_request_rejects_invalid_target and build_scan_from_request_valid_is_deterministic. Ran `cargo test --test api scan_create` this pass — 4/4 passed, including scan_create_rejects_invalid_target (POST value="not-an-email" kind=email -> 400) and scan_create_accepts_valid_request (-> 202 with a scan_id). | VERIFIED |
| REQ-API-SCAN-002 (**fixed in Pass 7**) | POST /api/v1/scans/{id}/cancel on a scan that is actually in-flight delivers the cancellation signal (via the shared s.cancellations map -> CancelHandle::cancel()) to the running engine task, and the engine honestly reports the outcome as ScanStatus::Aborted… | **Was PARTIAL**: `cargo test --test api scan_cancel` (1/1 passed, 404 branch only) and `cargo test --test halting wall_time_budget_stops_promptly_and_preserves_findings` (1/1 passed) proved the downstream engine mechanism (a wall-time deadline → `ScanStatus::Aborted`, findings preserved) driven directly against the engine, never through HTTP — no test drove a real in-flight scan through the actual HTTP `scan_cancel` handler and polled `GET /scans/{id}` to see status become "aborted". **Fixed in Pass 7**: added `CancelCooperativeProbe` (`tests/common/mod.rs`) — a module that blocks in `process()`, cooperatively polling `ctx.cancel.is_cancelled()` every ~100ms for up to 60s (mirrors `tests/halting.rs`'s `SlowModule`) — and a new parameterized harness helper, `test_app_with_modules`, so a test can build the real axum `Router`+`AppState` with a caller-chosen module set instead of the default `SyntheticModule`. New test `scan_cancel_stops_a_real_in_flight_scan_and_status_becomes_aborted` (`tests/api.rs`): `POST /scans` with the probe module (genuinely in-flight — `spawn_scan` registers the real `CancelHandle` into `s.cancellations` synchronously before the 202 response returns), `POST /scans/{id}/cancel` (asserts 200, `"status":"cancelling"`), then polls `GET /scans/{id}` until `"status":"aborted"` (resolves in ~100-200ms in practice, well inside the 5s poll budget). Ran 5 times consecutively — stable, ~0.12s each. Ran `cargo test --test api` (126 passed), `cargo test --test halting` (5 passed) and `cargo test --test smoke` (57 passed) to confirm the shared `tests/common/mod.rs` refactor didn't disturb either sibling test crate. | VERIFIED |
| REQ-API-SCAN-003 | DELETE /api/v1/scans/{id} refuses (409 Conflict) to delete a scan that is still in-flight (present in s.cancellations), instead of racing delete_scan's cascade against the live engine task's own mid-scan writes — which would silently resurrect a "deleted"… | Ran `cargo test --test api scan_delete` this pass — 3/3 passed, including scan_delete_refuses_an_in_flight_scan_then_succeeds_once_it_ends, which seeds s.cancellations directly, confirms the delete call returns 409 while the entry is present, then removes the entry and confirms delete now returns 200. | VERIFIED |
| REQ-API-SCAN-004 | POST /api/v1/scans/batch enforces DoS-relevant caps (empty array -> 400, >50 targets -> 400, exactly 50 -> 202) and, for a batch that mixes a structurally-invalid target among valid ones, records a per-item {"error": msg} entry and continues dispatching the… | **Fixed (Pass 14).** Ran `cargo test --test api batch_endpoint_enforces_empty_and_size_limits` — 1/1 passed (empty->400, 51 items->400, 50 items->202). Added `batch_endpoint_records_per_item_error_and_continues_for_mixed_valid_invalid_targets` (tests/api.rs) exercising the previously-untested continue-and-record path directly: a 3-item batch (valid, malformed email, valid) POSTed to /api/v1/scans/batch — asserts the request as a whole still 202s (not aborted by the bad item), the response `scans` array has one slot per input item in order, the malformed entry's slot carries `{"error": "invalid target: …"}` with no `scan_id`, and both valid entries (including the one *after* the bad one) are queued with a real `scan_id`. Ran `cargo test --test api` (full suite) — 128/128 passed, 0 failed. Ran `cargo fmt --all -- --check` and `cargo clippy --all-targets --features dep-cooldown -- -D warnings` — both clean. | VERIFIED |
| REQ-API-SCAN-005 | Every state-changing request on this surface (POST /scans, /scans/batch, /scans/{id}/cancel, /scans/{id}/rerun, DELETE /scans/{id}, POST /scans/import, /scan/auto*, /radar*) is blocked with 403 unless it carries a custom X-HSE-CSRF header — closing the… | Ran `cargo test --test api dossier_upload` (6/6 passed, includes CSRF-adjacent import tests) and `cargo test --test api bodyless_mutating_post_requires_csrf_header` this pass — 1/1 passed, confirming POST /api/v1/scans/does-not-exist/cancel is 403'd without the header and not 403'd with it. Confirmed by reading routes/mod.rs that this same middleware, not per-handler code, is what protects scan_cancel/scan_create/scan_batch/etc. | VERIFIED |
| REQ-API-SCAN-006 (**fixed in Pass 9**) | POST /api/v1/scans/import's own in-handler size backstop (`if body.len() > MAX_UPLOAD_BYTES { return bad_request(...) }`) rejects an oversized upload with this API's normal JSON `{"error": ...}` shape, for any body between `MAX_UPLOAD_BYTES` and the route's `DefaultBodyLimit` ceiling; only a body beyond that ceiling gets axum's own bare plain-text 413 (an intentional, bounded OOM backstop). | **Was UNREACHABLE**: the route's `DefaultBodyLimit` was set to exactly `MAX_UPLOAD_BYTES`, so any body large enough to trip the in-handler check had already been 413'd by axum one layer up — the handler's own check could never run. **Fixed in Pass 9**: added `scan_handlers::IMPORT_ROUTE_BODY_LIMIT_HEADROOM_BYTES` (1 MiB) and raised the route's `DefaultBodyLimit` to `MAX_UPLOAD_BYTES + IMPORT_ROUTE_BODY_LIMIT_HEADROOM_BYTES` (`src/api/routes/mod.rs`), so a body in that 1 MiB window now reaches the handler and gets the friendly JSON rejection instead; anything larger still hits axum's hard backstop, so the OOM-protection intent is unchanged. Added `dossier_upload_between_handler_cap_and_route_headroom_gets_friendly_json_rejection` (`tests/api.rs`), POSTing a 16 MB + 512 KB body and asserting `400` + JSON `error` containing "too large" (not axum's 413/plain-text). Mutation-tested: reverted the route-limit change locally, re-ran the new test — it failed (`left: 413, right: 400`) as expected, then restored the fix and re-confirmed the same test passes. Ran `cargo test --test api` — 127/127 passed (was 126; +1 new). Ran `cargo clippy --all-targets --features dep-cooldown -- -D warnings` — clean. `cargo build --locked` — clean. | VERIFIED |
| REQ-API-SCAN-007 (**fixed in Pass 6**) | GET /api/v1/scans/{id}/entities paginates via ?offset=&?limit=, validating both at the boundary: a non-numeric offset/limit or a limit of 0 is rejected with 400 rather than silently defaulting or panicking; a valid limit above 10000 is clamped down rather… | **Was PARTIAL**: `scan_entities_pagination_works` (1/1 passing) confirmed count/total/offset/limit accounting across 5 valid scenarios including the 10000 cap, but every one of the handler's `bad_request` branches (`analysis.rs:27,34,36` — non-numeric offset, non-numeric limit, limit=0) was read-only-verified, never test-executed. **Fixed in Pass 6**: added `scan_entities_pagination_rejects_invalid_offset_and_limit` (`tests/api.rs`), which drives all 5 invalid-input cases (`limit=0`, `limit=abc`, `limit=-5`, `offset=abc`, `offset=-1`) through the real HTTP handler and asserts 400 for each. Ran `cargo test --test api scan_entities_pagination` this pass — both the pre-existing and new tests passed (2/2). | VERIFIED |
| REQ-API-SCAN-008 | Several read endpoints validate free-form query params before use: scan_entities_filter caps ?kind (32 chars) and ?q (256 chars); scan_snake_svg's ?depth (positive integer, capped at 8), ?size (finite number, clamped 200-4000) and ?center (must name an entity… | Ran `cargo test --test api scan_snake_svg_renders_and_hides_candidate_nodes_by_default` and `cargo test --test api plan_preview_lists_engaged_modules_for_a_seed` this pass — both 1/1 passed (default-parameter rendering only). Grepped tests/api.rs for these handlers' malformed-input branches and found no coverage of any of the 400 paths listed. | PARTIAL |
| REQ-API-SCAN-009 | POST /api/v1/radar and POST /api/v1/radar/live are armed by default (a bare call with zero input queues the sensor sweep), but both refuse with 403 when the operator has explicitly switched the feature.live_radar toggle off — a client must be able to trust… | Ran `cargo test --lib api::scan_handlers` this pass, which includes radar_scan_spec_activates_only_the_live_sensors and every_live_sensor_accepts_the_radar_sentinel (both passed) — these confirm the SPEC the radar builds (sentinel target, allow_live_sensors, exact sensor module set), not the 403 kill-switch branch, which has zero automated coverage. | IMPLEMENTED_UNVERIFIED |
| REQ-API-SCAN-010 | A scan dispatched by this surface (spawn_scan always calls engine.run_panic_safe, never the bare run) that panics anywhere in dispatch, or that persists zero entities due to a store error, is force-marked ScanStatus::Failed with the causing error message and… | Ran `cargo test --lib core::engine::tests::run_panic_safe_force_fails_a_scan_that_panics_outside_process` this pass — 1/1 passed, confirming a scan whose accepts() panics ends with persisted.status == ScanStatus::Failed and persisted.error containing the panic message "kaboom in accepts()", read directly back from the store (not just the in-memory Err returned to the caller). | VERIFIED |

### Settings / cells / key-harvest / update handlers

| ID | Behavior | Runtime verification evidence | Status |
|---|---|---|---|
| REQ-API-MISC-001 | The 4 key-pool/env WRITE endpoints in settings_handlers (PUT /api/v1/settings/keys, POST /api/v1/keys/pool/add, /revoke, /rotate) gate on AppState.allow_key_write BEFORE inspecting the peer address — a non-loopback caller with writes disabled sees the 'key… | Ran `cargo test --test api keys_pool` this pass — 3 passed (keys_pool_add_is_write_gated, keys_pool_get_is_masked_and_revoke_is_write_gated, keys_pool_rotate_is_write_gated; 0.41s). Ran `cargo test --test api settings_keys` — 3 passed including settings_keys_put_forbidden_without_flag (0.49s). Then ran `grep -rn "allow_key_write" --include="*.rs" .` across the whole repo (excluding an unrelated build-staging mirror under run/deliverable/) and confirmed every non-definition hit is either the… | PARTIAL |
| REQ-API-MISC-002 | settings_handlers's read-only key/config endpoints (keys_status, keys_pool_get, keys_health, settings_keys_get) are loopback-gated and never serialise a plaintext key value — masking (mask_secret in keys_pool_get) and pure-count aggregation (summarize_pool,… | Ran `cargo test --lib api::` this pass (122 tests, 0 failed) which includes both settings_handlers::tests. Separately ran `cargo test --test api settings_keys` (3 passed), `cargo test --test api keys_status_endpoint` (2 passed), `cargo test --test api keys_health` (2 passed), and `cargo test --test api keys_pool` (3 passed) — all green, including the `!json.contains("SECRET")` assertion in summarize_pool_counts_by_status_and_never_leaks_values and every loopback-rejection test. | VERIFIED |
| REQ-API-MISC-003 (**fixed in Pass 5**) | settings_toggles_put (PUT /api/v1/settings/toggles) is loopback-only but is the ONE write endpoint across these four files that does NOT require allow_key_write (no secret is involved in flipping a bool), and only persists when toggle_key_is_known() resolves the key to a real engine/module/feature toggle, via `crate::util::settings::set_bool` — the same primitive `hse config` writes through. | **Was PARTIAL**: only the two rejection paths (non-loopback 403, unknown-key 400) were tested; `set_bool` itself — the actual cache-mutate-then-atomic-persist primitive — had zero test coverage anywhere in the repo, and the handler's success path had never been driven end-to-end. **Fixed in Pass 5**: added `set_bool_persists_and_get_bool_reads_it_back` (`src/util/settings/tests.rs`) — a direct round-trip proving `set_bool` both flips the in-process cache immediately and persists to disk (read back independently via `read_map`, not just the cache), using a scratch key so it can't collide with any other test's toggle assertions despite the cache/file being process-global. Added `settings_toggles_put_succeeds_and_persists_the_flip` (`tests/api.rs`) — a loopback PUT with a real feature key (`feature.depth_decay`) asserts the 200 response body, then a fresh GET on `/api/v1/settings/toggles` confirms the flip is visible (not just echoed back), then restores the default. Ran `cargo test --lib set_bool_persists_and_get_bool_reads_it_back` and `cargo test --test api settings_toggles_put` this pass — both new tests plus the 2 pre-existing rejection-path tests all passed. | VERIFIED |
| REQ-API-MISC-004 (**fixed this pass**) | cells_import (POST /api/v1/cells/import) treated `HUNTSMAN_OPENCELLID_KEY` as 'configured' whenever `std::env::var` returned `Ok(_)` at all — including an empty string or the exact, shipped-by-default template placeholder `insert_opencellid_key_here` — because the check was a raw env read rather than the codebase's one sanctioned resolution policy, `keys::resolve_key`, that every other credential check on this surface (e.g. `accounts_block`'s SeekNow/WiGLE lookups) already uses. **Was BROKEN**: a blank or un-edited-template key silently downgraded from the intended fast `400` to an async `202` that fired a real outbound request carrying the garbage credential, only failing later, visible solely by polling `GET /cells/status`. | Split the resolution into a pure `resolve_opencellid_key(&HashMap<String,String>) -> Option<String>` helper (routed through `keys::load()` + `keys::resolve_key`) so the placeholder-filtering behavior is unit-testable without mutating the process environment (`std::env::set_var` is `unsafe`, forbidden by this crate's `#![forbid(unsafe_code)]`). Added 4 regression tests: genuinely-unset, blank, the exact shipped placeholder, and a real-looking value — all pass. Ran `cargo test --lib api::cells_handlers` — 14/14 passed. Ran `cargo clippy --all-targets --features dep-cooldown -- -D warnings` — clean. | VERIFIED |
| REQ-API-MISC-005 | cells_import/cells_clear (the two mutating cell-DB endpoints) are loopback-only; cells_import additionally uses an atomic check-and-claim (try_start_import, one mutex acquisition) to refuse a second concurrent import while one is Running — mirroring… | Ran `cargo test --lib api::` this pass — all 10 cells_handlers tests passed, e.g. `test api::cells_handlers::tests::cells_clear_succeeds_with_confirm_true ... ok`, `test api::cells_handlers::tests::try_start_import_claims_atomically_and_refuses_a_concurrent_second_call ... ok` (full run: 122 passed; 0 failed). The clear-during-running-import race noted above was found by reading the two handlers side by side, not by a test. | VERIFIED |
| REQ-API-MISC-006 | keys_harvest (GET /api/v1/keys/harvest) — the actual axum handler function, including its reject_non_loopback gate and its {vault,pool,accounts} envelope construction — has no test anywhere in the repository that invokes it directly. Every existing test… | Ran `cargo test --lib api::` this pass — all 3 key_harvest_handlers tests passed (part of the 122-test, 0-failed run). Ran `grep -rn "keys/harvest\\|keys_harvest" tests/*.rs src/api/**/*.rs` across the repo — the only hits are the handler's own doc comments, its route registration, and one prose mention in settings_handlers/mod.rs:186; no call site in any test file constructs an HTTP request against this route. | PARTIAL |
| REQ-API-MISC-007 | accounts_block's SeekNow and WiGLE probes report a 3-state model rather than a plain boolean: configured:false (no credential present; reachable/verified reported as JSON null since nothing was probed) is kept strictly distinct from configured:true,… | Ran `cargo test --lib api::` this pass — `test api::key_harvest_handlers::tests::accounts_block_reports_all_three_providers ... ok`. This test performs the real, best-effort SeekNow/WiGLE network calls against whatever credentials happen to exist in this sandbox's environment (none), so both providers legitimately came back configured:false here, and the configured/reachable invariant assertion held under that real condition rather than a mock. | VERIFIED |
| REQ-API-MISC-008 | post_trigger (POST /api/v1/update/trigger) gates on reject_non_loopback FIRST, then performs an atomic check-and-claim (try_start_update, one lock acquisition) that admits exactly one of two concurrent callers and returns 409 while phase is Applying OR… | Ran `cargo test --lib api::` this pass — all 6 update_handlers tests passed: `try_start_update_admits_exactly_one_of_two_concurrent_callers ... ok`, `try_start_update_rejects_while_restarting ... ok`, `try_start_update_admits_after_error_or_idle ... ok`, `set_phase_recovers_from_a_poisoned_mutex ... ok`, `trigger_rejects_non_loopback_peers ... ok`, `trigger_allows_loopback_peers ... ok` (full run: 122 passed; 0 failed; 0.29s). Read update_handlers.rs's test module in full (lines 141-259): it… | PARTIAL |
| REQ-API-MISC-009 (**new, Pass 15**) | The 403 the four key-writing endpoints (`settings/keys` PUT, `keys/pool/add`, `revoke`, `rotate`) return when key writes are off names the switch that actually controls them: `hse serve --no-key-write` (writes are on by default, loopback-only). One body from one helper (`key_writes_disabled`); every `--flag` token in it must be an argument `hse serve` accepts. | The four handlers each carried their own copy of `"key writes disabled; restart with \`hse serve --allow-key-write\`"` — a flag that does not exist (the CLI's switch is `--no-key-write`, on by default), so the one operator-facing remedy was a dead end; the same phantom flag was in three doc comments, `util/keys/mod.rs`, `web/js/api.js` and four test comments. `keys_pool_add_is_write_gated` (`tests/api.rs`) now extracts every `--flag` from the 403 body and checks it against `Cli::command().find_subcommand("serve")`'s long arguments (clap, the CLI definition itself), so the message cannot drift from the CLI again; fails on the baseline. `cargo test --test api keys_` passes. | VERIFIED |

### Scan export + redaction

| ID | Behavior | Runtime verification evidence | Status |
|---|---|---|---|
| REQ-API-EXPORT-001 | redact_sensitive_sources() replaces every proprietary breach/intel provider name appearing anywhere in an export body with the fixed label "breach-source", via one whole-token (\b...\b), case-insensitive regex alternation built once from the sensitive-name… | Ran `cargo test --lib api::scan_export -- --nocapture` this pass: `running 8 tests ... test api::scan_export::redact::tests::covers_every_spelling_of_the_named_providers ... ok / idempotent ... ok / redacts_named_paid_provider_but_keeps_public_sources ... ok / redacts_capitalised_brand_in_evidence_summaries ... ok / every_breach_category_source_is_redacted ... ok / whole_token_match_leaves_longer_tokens_intact ... ok ... test result: ok. 8 passed; 0 failed`. | VERIFIED |
| REQ-API-EXPORT-002 | The sensitive-name set is registry-derived: every module whose category() == ModuleCategory::Breach is swept automatically (so a newly added breach-category module needs no redact.rs edit); EXTRA_SENSITIVE is reserved for names the sweep structurally cannot… | Ran `cargo test --lib api::scan_export::redact::tests::every_breach_category_source_is_redacted` this pass (part of the 8/8 run above) — passed. Cross-checked categories by reading source directly: oathnet_pro::category() returns ModuleCategory::People (src/modules/oathnet_pro/mod.rs:109-110), see_know::category() and dehashed::category() both return ModuleCategory::Breach (src/modules/see_know/mod.rs:194-196, src/modules/dehashed/mod.rs:93-95) — confirming the comment's factual claims about… | VERIFIED |
| REQ-API-EXPORT-003 | Redaction is enforced at one choke point: all four shareable download handlers (scan_entities_csv, scan_report_json, scan_export_gexf, scan_events_log) route their body through download_response(), which unconditionally calls redact_sensitive_sources(); only… | Ran `grep -n "download_response(\\|download_response_operator(" src/api/scan_export/mod.rs` this pass — output confirmed exactly 4 call sites (lines 49, 82, 120, 174) use download_response and exactly 1 (line 147, scan_debug_bundle) uses download_response_operator, matching the module doc comment's claim that the debug bundle is the sole conscious opt-out. | PARTIAL |
| REQ-API-EXPORT-004 | End-to-end: a real Breach-category module's evidence (Evidence{source: module name(), summary: the module's own capitalised-brand text, e.g. "DeHashed record from Adobe"}) and its ModuleDone scan event, once persisted and downloaded through the live HTTP… | Ran `cargo test --test api temp_probe_end_to_end_redaction_across_all_four_download_formats -- --nocapture` this pass (test added then reverted). Real output: entities.csv `sources` column = `breach-source\|breach-source`, `evidence` column = `[breach-source] breach-source record from Adobe \|\| [breach-source] breach-source record from MyFitnessPal`; report.json `"source": "breach-source"`, `"summary": "breach-source record from Adobe"` / `"...MyFitnessPal"`; events.log both lines read… | VERIFIED |
| REQ-API-EXPORT-005 | Candidate quarantine (speculative breach-victim entities tagged CANDIDATE) is excluded by default from both scan_entities_csv and scan_export_gexf, opt-in via `?include_candidates=1` — matching the same policy the `/entities` JSON endpoint and report.json… | Ran `cargo test --test api scan_gexf_quarantines_candidate_nodes_by_default -- --nocapture` this pass — `test result: ok. 1 passed`. Separately wrote and ran (then reverted via `git checkout -- tests/api.rs`) a temporary CSV-equivalent probe: default entities.csv response omitted `stranger@breach.example` entirely while including `subject@real.example`; `?include_candidates=1` response included the candidate row with `tags` column `candidate`. `test result: ok. 1 passed`. | PARTIAL |
| REQ-API-EXPORT-006 | Every scan-scoped export (CSV/JSON/GEXF via download_response; the debug bundle via download_response_operator) names its download `hse-<stem>-<short_id>.<ext>` with the scan id truncated to 12 characters, and every download (scan-scoped or system-scoped)… | Ran `cargo test --lib api::scan_export -- --nocapture` this pass: `test api::scan_export::tests::download_response_sets_attachment_disposition_with_scan_scoped_filename ... ok` / `test api::scan_export::tests::attachment_response_uses_the_filename_verbatim_for_system_downloads ... ok` (part of the 8/8 passing run). | VERIFIED |
| REQ-API-EXPORT-007 (**new, Pass 14**) | The shareable-export redactor (`redact_sensitive_sources`) matches every `Breach`-category module name (plus `EXTRA_SENSITIVE`) in its `snake_case`, spaced and hyphenated spellings, case-insensitively and whole-token, so the prose brand in an evidence summary ("HIBP Pwned Passwords: value seen in …") is hidden, not just the `pwned_passwords` token; `EXTRA_SENSITIVE` lists each provider once (the hyphenated duplicates are derived, not hand-listed). | Ran `cargo test --lib api::scan_export::redact` — all pass, including the new `every_breach_source_is_redacted_in_its_spaced_and_hyphenated_spellings_too` (every multi-word breach-category module, both spellings, title-cased as a summary prints them) and the pre-existing whole-token / idempotency / every-spelling tests. Before the fix `redact_sensitive_sources("HIBP Pwned Passwords: …")` returned `breach-source Pwned Passwords: …`. | VERIFIED |
| REQ-API-EXPORT-008 (**new, Pass 15**) | Every error the SeekNow transport/parse layer raises is labelled with the provider's ONE registered name (`util::see_know::SRC` = `see_know`, re-exported as the module's `SRC`), never a second spelling, so the redactor — whose brand list is derived from the registry — masks it in the shareable events log like any other `see_know` mention. | Found by re-reading this pass's SeekNow change against REQ-API-EXPORT-002/007: `util::see_know::client` labelled both `CurlClient`s and five error sites `"seek_now"` (the module-level labels had been corrected earlier — `docs/PROBLEM_TREE.md` records that as done — but the util layer kept the phantom name: an incomplete migration). `scan_events_log` renders `ModuleError` text through `download_response` → `redact_sensitive_sources`, whose list holds `see_know` and its spellings but not `seek_now`, so `[seek_now] HTTP 503` reached the export unmasked. Fixed at the source (one constant, both layers); `see_know_errors_carry_the_registered_module_name_not_a_phantom_one` (`tests/architecture_parts/architecture_part7.rs`) scans production source for the phantom name and pins the constant to a registered module; reintroducing one literal fails it. `cargo test --lib -- util::see_know modules::see_know core::error` passes. | VERIFIED |
| REQ-API-EXPORT-009 (**new, Pass 16**) | `report.json` (`build_scan_report`, behind `GET /scans/{id}/report.json` and `hse export --format report`) is self-resolving: every `correlations[].entity_uids` entry names an entity in the same envelope's `entities`. A platform-infra entity a finding references is unioned back under the default `include_infra=false`; a finding that references a hidden CANDIDATE is dropped (quarantine wins over completeness). | The correlator runs over the infra-inclusive set (only candidates excluded), while the default report filtered `PLATFORM_INFRA` rows from `entities` and embedded `correlations` unfiltered — so AU-004's Critical finding on a compromised hosting IP named a UID absent from the document, and `entity_count`/`correlation_count` described two sets that did not resolve against each other. `entities_to_gexf` already enforces the both-endpoints-present invariant for relation edges; the report now enforces it for correlations. `report_correlations_always_resolve_against_its_own_entities` (`src/app/export/tests.rs`) seeds an infra entity with an AU-004 correlation and a candidate with its own correlation, asserts every default-report correlation resolves, AU-004 is kept with its entity restored, the candidate finding is dropped, and both surface under the full flags. | VERIFIED |

---

## 7. Scan engine dispatch (`src/core/engine/`)

| ID | Behavior | Inputs | Outputs | Side effects | Failure behavior | Implementation location | Tests covering it | Runtime verification evidence | Status |
|---|---|---|---|---|---|---|---|---|---|
| REQ-ENGINE-001 | Capability-aware dead-module quarantine: when a target's dispatch context carries a non-empty `quarantined` set (module names the health system flagged as persistently drift/hard-failing), `gate_skips` must refuse to dispatch any module whose name is in that set — across all 3 call sites that invoke it (the sequential path and both concurrent phases) — while a module NOT in the set still dispatches normally in the same round. | `DispatchCx.quarantined: &HashSet<String>` | `bool` (gate_skips); tallied in `ModuleStats::skipped`/`.run` | None for the skip itself; an emitted `ModuleSkipped` event names the reason ("capability-quarantined — persistent drift"). | A module in the set must never have `process()` called and must contribute zero entities. | `src/core/engine/dispatch.rs:753-790` (`gate_skips`, the `cx.quarantined.contains(module.name())` check at line 780, called from dispatch.rs:836,975,1093) | `quarantined_module_is_skipped_at_dispatch_and_never_invoked`, `unquarantined_module_in_a_nonempty_quarantine_set_still_dispatches` (`src/core/engine/tests.rs`, new Pass 4) | **Was a completely open evidence gap before this pass**: every `DispatchCx` literal previously in `src/core/engine/tests.rs` (7 call sites) passed `no_quarantine()` (an empty static) — nothing had ever exercised the non-empty case, despite this being hot-path behavior on every single scan. Added two dispatch-level regression tests using an `Arc<AtomicU64>`-counted stub module (`CountingProbe`), each looped across `max_concurrent in [0, 4]` to cover both the sequential and concurrent `gate_skips` call sites. Ran `cargo test --lib quarantine` this pass — both new tests passed on first attempt; ran `cargo test --lib core::engine::tests` (full module) — 105 passed, 0 failed, 1 ignored (pre-existing, unrelated). | VERIFIED |

**Explicitly out of scope for this row** (see "Pass 4 findings" below): the
upstream gate at `src/core/engine/mod.rs:717-743` that COMPUTES the
`quarantined` set (`opts.skip_dead_modules && opts.modules.is_none()` →
`store.recent_module_outcome_events()` → `host.quarantined_modules()`) is
NOT independently tested by this row — `recent_module_outcome_events` is a
`StoragePort` trait method with a no-op default that `InMemoryStore` (the
standard engine-test double) does not override, so that upstream path
always computes an empty set under the standard harness regardless of the
flag. REQ-ENGINE-001 proves the DOWNSTREAM consequence (a populated
`quarantined` set is correctly honored); it does not prove the UPSTREAM
wiring that populates it in production.

---

## 8. Correlator rule registry (`src/core/correlator/`)

| ID | Behavior | Inputs | Outputs | Side effects | Failure behavior | Implementation location | Tests covering it | Runtime verification evidence | Status |
|---|---|---|---|---|---|---|---|---|---|
| REQ-CORRELATOR-001 | Every correlation rule function defined under `src/core/correlator/rules/` is (a) registered in exactly one of `RULES`/`RELATION_RULES` — no orphan that compiles but silently never fires; (b) claims a distinct `AU-<N>` number — no two different rule functions collide on the same id, which is the dedup/supersede key `storage::upsert_correlation` queries on; (c) internally consistent — a rule's own emitted `rule_id` string matches its own function-name number; and (d) has at least one positive firing test in the correlator test suite — a dispatched rule with no firing fixture is indistinguishable from a correctly-absent result. | n/a (static analysis of `RULES`/`RELATION_RULES` + `rules/*.rs` + the correlator test corpus) | Pass/fail assertions | none | A regression in any of the four properties fails CI, not just code review. | `RULES`/`RELATION_RULES` (`src/core/correlator/mod.rs:354-569,793-813`, 107 + 14 = 121 bare `fn` pointers) | `every_defined_correlation_rule_is_dispatched`, `no_two_correlation_rule_functions_share_a_number`, `correlation_rule_ids_match_their_function_number` (`tests/architecture_parts/architecture_part4.rs`), `every_dispatched_correlation_rule_has_a_firing_test` (`tests/architecture_parts/architecture_part5.rs`) | **This row was planned as new work and became pure documentation instead** — a genuine example of the ledger's own "do not rediscover already-covered behaviour" principle catching itself in real time. Two independent exploration passes plus a design pass all concluded no completeness/uniqueness guard existed for this registry (citing the `AU-121`/`AU-122` renumbering-after-merge doc comments as motivating evidence) and a new test was drafted and about to be added. Before committing it, a direct read of `tests/architecture_parts/architecture_part4.rs` surfaced FOUR pre-existing tests already covering exactly this — including `no_two_correlation_rule_functions_share_a_number`, whose own doc comment cites the identical AU-114/AU-115 incident. The drafted new test was reverted (confirmed via `git diff` — zero net change) rather than shipped as a duplicate. Ran all four cited tests fresh this pass: `cargo test --test architecture correlat` and `cargo test --test architecture rule` — 5/5 passed each run (both filters overlap on the 4 rule-registry tests plus `readme_correlator_rule_count_matches_registry`). | VERIFIED |
| REQ-CORRELATOR-002 (**new, Pass 16**) | AU-108 (breach-listed cross-platform handle footprint) recognises every platform `breach_rich` mints as a `platform:handle` breach Username: both read the ONE `core::breach_platforms::BREACH_SOCIAL_PLATFORMS` (telegram, skype, facebook, instagram, twitter, linkedin, vk, snapchat, github, tiktok, reddit). | The rule kept its own 8-entry copy whose doc claimed it was "kept in lockstep with breach_rich" while `breach_rich` had since added github/tiktok/reddit, so a subject whose breach data named exactly those platforms produced no footprint finding (`platforms.len() < 2` never satisfied). Consolidated to one constant; `au_108_counts_every_platform_breach_rich_mints` (`src/core/correlator/rules/tests.rs`) fires the rule on github+tiktok (FAILS on the old list) and iterates the shared list so a future addition cannot drift. | VERIFIED |
| REQ-CORRELATOR-003 (**new, Pass 16**) | AU-058's `extract_ratemyagent_suburb` accepts the smallest well-formed slug its own doc defines, `<name(1)>-<suburb(1)>-<id>` (three hyphen parts), so a single-token agent/business name resolves its suburb. | The guard was `parts.len() < 4` — requiring a two-token name, contradicting the documented "one or more" — so `/real-estate-agent/century21-bondi-12345/` returned `None` before the suburb window/fallback ever ran and the geographic signal was silently lost. Floor is 3; the id must still be ≥2 alphanumerics, so the existing malformed-slug cases (`a-b-c`) stay rejected. `extract_ratemyagent_suburb_accepts_a_single_token_name` (`src/core/correlator/rules/geo/mod.rs`) FAILS on the old floor. | VERIFIED |
| REQ-CLAIM-001 (**new, Pass 17; reconciled Pass 17b**) | The assertion layer exists as types, and there is exactly ONE of it. `core::intelligence` (landed on `main` in #584) separates ENTITY / CLAIM / EVIDENCE / INFERENCE, computes `ClaimState` from the record via `IntelligenceLedger::recompute_claim_state`, and counts corroboration by INDEPENDENT LINEAGE — a union-find over `SourceLineage::is_independent_of` that collapses transitive copy chains, so one corpus resold by several publishers is one witness. Pass 17 originally landed a second, parallel model (`core::claim`); this pass DELETES it and folds only its genuinely additive parts into `core::intelligence`, because a duplicated authority for the same capability is itself a defect. | `copied_reporting_does_not_promote_claim`, `transitive_copy_chain_counts_as_one_source_family`, `independent_support_promotes_but_contradiction_is_preserved`, `inference_never_self_promotes_to_fact` (`src/core/intelligence.rs`). `git grep core::claim` returns nothing outside history. **Not yet wired into the live scan pipeline** — the engine still promotes on `Entity::confidence`; adoption is REQ-CLAIM-003. | IMPLEMENTED_UNVERIFIED |
| REQ-CLAIM-002 (**new, Pass 17b**) | PROVIDER FAILURE ≠ ZERO EVIDENCE, enforced rather than documented. `ProviderOutcome` distinguishes `Observed` / `CleanNegative` / `NotAttempted{reason}` / `Failed{reason}`, and only the first two are `is_resolved()`. `IntelligenceLedger::record_provider` stores one observation per (claim, provider) — a later attempt supersedes an earlier one, and an unresolved outcome MUST name a reason. `reject_claim` then REFUSES with `LedgerError::UnresolvedCoverageGap(providers)` while any provider bearing on the claim never answered: a source that broke or was never queried can no longer be counted as having said no. Coverage is serialised with the ledger, so a resumed scan still knows what it is owed; a pre-coverage checkpoint still loads (`#[serde(default)]`). Gaps constrain conclusions from SILENCE only — three independent sources speaking still promote to `Verified` with a fourth outstanding. | `a_provider_outage_is_not_a_clean_negative`, `an_unqueried_provider_blocks_rejection_and_names_itself`, `a_coverage_gap_never_blocks_positive_corroboration`, `provider_coverage_survives_a_ledger_round_trip` (`src/core/intelligence.rs`). Falsified: removing the gap check from `reject_claim` fails 3 of the 4 while the other 11 tests in the module keep passing. | IMPLEMENTED_UNVERIFIED |
| REQ-CLAIM-003 (**new, Pass 17c**) | The intelligence model is REACHABLE, not just implemented. `core::intelligence::provider_coverage_from_events` derives `ProviderOutcome` rows from the engine's own `ModuleDone`/`ModuleError`/`ModuleSkipped` events — the one place the four provider states already existed as a signal and nowhere as a conclusion — and the aggregation is failure-dominant: a module that found five entities on one target and broke on another is `Failed`, because the question is not "did it find anything" (the findings are in the report either way) but "is its silence about the rest of the target set trustworthy". That derivation now reaches the operator on all three surfaces from ONE authority: `report.json`'s `provider_coverage` block, the CLI dossier's Collection appendix, and `GET /api/v1/scans/{id}/coverage` feeding a Provider Coverage panel in the web console's Summary tab (`wasm-ui/src/scan_info/coverage.rs`), so the on-device and over-the-wire dossiers cannot disagree about what was covered. All three represent UNKNOWN coverage (no retained dispatch events) as null/"not known", never as an empty list — an empty list reads as "every provider answered", which is the exact false clean negative the feature exists to prevent. | `a_broken_provider_never_reads_as_a_clean_negative_in_coverage`, `a_partial_outage_dominates_the_findings_it_sits_beside`, `an_unreasoned_outage_still_produces_a_recordable_observation` (`src/core/intelligence.rs`); `report_distinguishes_a_clean_sweep_from_one_nobody_answered` (`src/app/export/tests.rs`); `scan_coverage_never_reports_an_unknown_sweep_as_a_complete_one` (`tests/api.rs`); `an_unknown_coverage_never_renders_as_a_clean_bill_of_health`, `an_unresolved_outcome_is_warned_on_not_styled_as_a_result`, `a_provider_name_from_the_wire_is_escaped` (`wasm-ui/src/scan_info/coverage.rs`). Falsified: treating a failed dispatch as a clean negative and returning an empty coverage block instead of null fails exactly four of the locks and leaves the module's other sixteen tests passing. `export_formats_determinism_audit` still passes — rows are sorted by provider id. `wasm-ui/pkg` regenerated with the pinned toolchain; the drift check confirms no drift. | VERIFIED |
| REQ-CLAIM-004 (**new, Pass 17e**) | **Defect in REQ-CLAIM-003, same PR.** The engine emits `ModuleSkipped` for four materially different situations and flattened all four into one prose reason, so `provider_coverage_from_events` — which can only read that prose — counted every skip as an unresolved gap. A module the engine deduped because it had already been dispatched for this target HAS answered; a module preflighted out because the target is a private IP or a local domain was never owed anything. Both were reported as providers that never answered, which marks nearly every real scan incomplete and buries the failures that matter. Fixed at the gate that makes the decision, not at the consumer: `EventKind::ModuleSkipped` gains `class: Option<SkipClass>` — `Scoped` (an allowlist, an exclusion, a category focus, `--free-only`/`--passive-only`, a config toggle, a radar-only sensor, or an engine budget rule deferring a costly provider), `Unavailable` (a missing credential, an open circuit, a spent quota or cost budget, a capability quarantine), `NotApplicable` (a private IP, a local domain, a URL with a private host), `AlreadyCovered` (deduped this scan, or a sensor that already ran on the seed round) — and `SkipClass::is_coverage_gap` decides which two count. `module_skip_reason` returns the class beside the reason, so every one of its 16 gates classifies itself and a new gate cannot be added unclassified. An event persisted before the field existed deserialises to `None` and is treated as a gap: unknown is not harmless. The class also reaches the machine-readable event log as `skip_class`. | `a_dedup_or_inapplicable_skip_is_not_a_coverage_gap`, `an_unclassified_skip_is_treated_as_a_gap` (`src/core/intelligence.rs`); `every_skip_reason_carries_the_class_that_decides_whether_it_is_a_gap` — one representative per class, driven through the real gate (`src/core/engine/tests.rs`). Falsified: counting every skip as a gap, as before the class existed, fails the dedup lock and leaves the module's other 20 tests passing. | VERIFIED |
| REQ-CLAIM-005 (**new, Pass 17f**) | Coverage is reported on TWO axes that are never summed. Every real scan narrows its sweep — an allowlist, a category focus, `--free-only` — so dozens of providers are legitimately out of reach each time; a single "incomplete" count mixing those with the handful that actually broke is alarming on every scan and therefore read on none, burying the failures it exists to surface. `CoverageVerdict` splits them: `unavailable_count` (a missing credential, an open circuit, a spent quota or cost budget, a capability quarantine, an outright failure — what the operator can act on) and `out_of_scope_count` (the scan's own options, or an engine budget rule deferring a costly provider). `all_available_providers_answered()` says nothing broke; `is_exhaustive()` says nothing broke AND nothing was out of scope — only then is a thin result unambiguously a real negative. Both axes still bear on what may be concluded: silence from an out-of-scope provider is no more informative than silence from a broken one, and every surface says so. Only the ACTION differs, which is exactly why they are reported apart. Each unresolved row carries `skip_class`, so no consumer infers the axis from the reason prose. The web console styles the three states differently — `exhaustive` (success), `narrowed` (info, the ordinary case), `degraded` (danger, the only one needing action) — and the dossier lists only the unusable providers, since an out-of-scope one is already explained by the options the operator set. | `a_narrowed_sweep_is_reported_apart_from_a_broken_one` — 40 scoped + 2 unavailable + 1 failure gives 3 and 40, not 43, and dropping the three flips `all_available_providers_answered` to true while `is_exhaustive` stays false (`src/core/intelligence.rs`); `an_ordinary_narrowed_scan_is_not_styled_as_a_fault` (`wasm-ui/src/scan_info/coverage.rs`); the export and API locks assert both counts and that every unresolved row names its axis. | VERIFIED |
| REQ-BENCH-001 (**new, Pass 17g**) | The benchmark report states whether its own scorecard is safe to compare. `core::benchmark` exists for head-to-head comparison — two configurations on an identical seed, field by field — and carried no notion of what each run actually managed to ask. A run where a third of its providers had no credential, or whose circuits were open, yields fewer entities for a reason that has nothing to do with the configuration under test, and the two scorecards were indistinguishable, so the difference was attributed to the configuration: the exact false conclusion a benchmark exists to prevent. `BenchmarkReport` now carries the run's `CoverageVerdict` and a `comparability_caveat` derived from it — unavailable providers first (a lower yield may reflect that), then out-of-scope ones (compare only against a run with the same scope), and unknown coverage as its own caveat rather than a silent clean sweep. `report()` takes the scan's dispatch event log; both call sites (`hse benchmark`, `GET /api/v1/scans/{id}/benchmark`) already had store access. The CLI prints it above the numbers and the console renders it as a banner above the table — a reader who has absorbed the figures has already drawn the comparison the caveat qualifies. The serialised field is filled from the method, so the two can never disagree. This is the executable form of the contract's `provider_failure_degradation` metric at the artifact level. | `a_scorecard_from_a_degraded_run_says_it_is_not_comparable` — asserts the three caveat cases and, decisively, that two runs with an IDENTICAL scorecard carry different caveats (`src/core/benchmark/tests.rs`); `a_scorecard_without_a_caveat_shows_no_banner`, `a_caveat_from_the_wire_is_escaped` (`wasm-ui/src/scan_info/benchmark.rs`). Falsified: making `comparability_caveat()` always return `None` fails the lock and leaves the module's other three tests passing. | VERIFIED |
| REQ-GEO-004 (**new, Pass 17h**) | **Circular reporting on the live GEOINT path.** `cell_intel` geolocates each visible tower by querying OpenCelliD's `cell/get` with `HUNTSMAN_OPENCELLID_KEY`, and stamped the resulting `Coordinates` entity with its OWN source name. The standalone `opencellid` module accepts `DeviceId` targets and looks a tower up through the same endpoint with the same key — and `cell_intel` is what emits the `DeviceId` the engine expands, so both paths run against the same tower as a matter of course. Both mint the position as `{lat:.6},{lon:.6}`, so the two entities share a UID and merge, and the merged entity carried TWO distinct corroborating sources for ONE record from ONE corpus. `Entity::source_count` feeds `c_effective` directly, so retrieving the same OpenCelliD row twice bought a confidence boost it never earned — the contract's "repeated retrieval, aggregation, or republication of the same underlying source must not increase independent corroboration", violated on the tool's own cell-tower geolocation. Fixed by attributing the position to the corpus it came from (`opencellid::SRC`, now `pub(crate)` so the two names cannot drift), following the precedent already in the same file: its key errors were ALREADY reported against the `opencellid` service rather than itself. Deliberately narrow — a blanket `ENRICHMENT_ONLY_SOURCES` entry would have stripped `cell_intel`'s genuine radio observation and broken AU-084. The MCC-centroid fallback keeps `cell_intel` (its own offline derivation) and so does the tower's `DeviceId` evidence (the hardware sighting AU-084 correctly treats as independent of the database). | `an_opencellid_position_is_attributed_to_opencellid_not_to_this_module` (`src/modules/cell_intel/tests.rs`) — proves the two paths mint the same UID, that the merge leaves ONE corroborating source, and that the `DeviceId` radio observation is untouched. Falsified: restoring self-attribution fails it and leaves the module's other 30 tests passing. The entity construction was extracted to `build_opencellid_coordinate` so the lock exercises the real production builder, not a copy. | VERIFIED |
| REQ-GEO-006 (**new, Pass 17i**) | The circular-reporting class of REQ-GEO-004 is now machine-checked, and it found two more instances. `a_module_never_claims_another_providers_corpus_as_its_own_source` scans production module source for the tell both known cases shared and self-declared: evidence naming a foreign corpus in a `source` attribute while being attributed to the module that fetched it. On its FIRST run it failed on a third instance nobody had looked for — `ip_registry`, which queries the same `api.bgpview.io/asn/{n}` and `/ip/{ip}` endpoints as the standalone `bgpview` module and stamped the ASN contact emails and operator organisation with its own name. Fixed alongside it: **`wifi_intel`** resolves the BSSIDs it sees on the air through the same WiGLE endpoints with the same `HUNTSMAN_WIGLE_USER`/`_TOKEN` as the standalone `wigle` module, which is the PRIMARY resolver for the `MacAddress` entities `wifi_intel` itself emits — the same designed-pivot collision as the cell case, on both the `Coordinates` (`{lat:.6},{lon:.6}`, identical formatting) and the `Address` (identical `city, region, country postcode` construction). Each fix is narrow: only the foreign-corpus findings move. `wifi_intel` keeps its own name on the `MacAddress` entities, because seeing an AP on the air really is its own observation; `ip_registry` keeps it on the RDAP contacts, which are a genuinely different registry corpus — and re-attributing the BGPView half means an address appearing in BOTH registries now correctly counts as two. | The architecture test itself is the evidence: it failed on the pre-fix tree naming `src/modules/ip_registry/mod.rs` and the `bgpview` corpus. Falsified separately against the second shape: reverting `wifi_intel` alone makes it fail with `src/modules/wifi_intel/mod.rs claims \`wigle\`'s corpus under its own source name`. It matches a registered module name with separators stripped, so `"OpenCelliD"` resolves to the `opencellid` module, and ignores a module naming itself or a non-module value like `"rdap"` or `"mcc-centroid"`. | VERIFIED |
| REQ-PROVIDER-014 (**new, Pass 17j**) | **Cross-scan state leak, found via a CI test failure.** `util::see_know::budget` held two latches — the one-shot `/credits` quota probe (`QUOTA_PROBED`) and the key-rejection code (`KEY_REJECTED`) — as process-wide atomics, while documenting both as "latched once per scan" and "cleared by `reset_budget` at the start of each scan". `ScanState::rate_limited`'s own doc already names this exact failure: "a bare process-wide flag would let one of hse serve's concurrently-running scans silently block/mislabel every sibling scan's queries, and a new scan starting would clear a still-active sibling's latch out from under it." Both consequences are real: the first concurrent scan to claim the probe left every sibling unable to fire one, so a sibling ran its whole life pinned to the un-scaled default cap (the ≈60% under-provisioning `release_quota_probe`'s own doc warns about), and one scan latching a rejected key made every sibling report a key failure it never observed and fast-fail lookups that would have succeeded. Fixed by consolidation, not by a new mechanism: both moved into the existing scan-scoped `ScanState` beside `exhausted` and `rate_limited`, as `probe_claimed` and a generic `terminal_latch`, reached through `QuotaBudget::claim_probe`/`release_probe`/`set_terminal_latch`/`terminal_latch`. `reset_scan()` already clears the whole `ScanState`, so both explicit stores in `reset_budget` are gone and the documented per-scan reset now holds by construction. Both `static`s are deleted. | Surfaced by CI: `util::see_know::tests::reset_clears_override_too` failed on head `98f9182f` (`left: 300, right: 99` — the override read back as the `scan_budget_floor` default), the order-dependent flake this shared state causes. `a_probe_claim_and_a_terminal_latch_belong_to_one_scan_only` (`src/util/budget/tests.rs`) pins all four behaviours: a sibling scan gets its own probe, sees no latch it did not set, its reset leaves the other scan's live latches alone, and a released claim is re-takeable by its own scan only. Falsified: keying both latches to a single process-wide bucket fails it on the sibling-probe assertion and leaves the module's other 24 tests passing. | VERIFIED |
| REQ-CORRELATOR-004 (**new, Pass 17k**) | **Silent finding suppression across concurrent scans**, found by searching for the REQ-PROVIDER-014 shape rather than waiting for it to surface. `modules::typosquat` deduped registrable domains through a flat process-global `HashSet` — a WITHIN-scan optimisation implemented as a BETWEEN-scan one. `hse serve` runs scans concurrently, so once scan A had processed an apex, scan B reaching the same apex found it present and returned early, **losing every typosquat finding it would have produced for that domain**. That is precisely the "silently suppresses ALL typosquat findings … a cross-scan data-loss" the existing `reset_seen` doc says it exists to prevent — still reachable, because the reset was global too. The mirror image also bit: a new scan starting cleared a running sibling's live within-scan set, so it re-spent DNS on candidates already resolved. Fixed by keying the set on `scan_id` (from `ctx.scan_id` at the dedup site) and having `reset_seen(scan_id)` drop only that scan's entry — the same shape as `search_engines::reset_session_liveness(scan_id)` and `util::budget`'s per-scan state, so this is consolidation onto the established pattern, not a new mechanism. Unbounded growth across a long-lived process is still bounded, now per scan. | `a_sibling_scans_dedup_never_suppresses_this_scans_findings` (`src/modules/typosquat/tests.rs`): a sibling scan still processes an apex the first scan covered, within-scan dedup still holds, and one scan's reset leaves the other's live set intact. Falsified: restoring one shared bucket with a global clear fails it on `scan-a's live within-scan dedup survives scan-b's reset` and leaves the module's other 20 tests passing. | VERIFIED |
| REQ-PROVIDER-015 (**new, Pass 17l**) | The last instance of the shared-global class, and the one the codebase had already given up on. SeekNow's `RESPONSE_CACHE` dedups identical endpoint queries WITHIN one scan — its stated purpose — but was keyed globally, so under `hse serve`'s concurrent scans it was a BETWEEN-scan cache: **scan B was served provider records scan A had retrieved, as though B had retrieved them itself**, and the scan-start flush (`RESPONSE_CACHE.clear()`) wiped a running sibling's cache entirely. `util/see_know/tests.rs` already documented the second half as unfixable — "a lock inside this file cannot serialise against those… (an observed CI flake)" — and worked around it with a 200-iteration retry loop. Fixed at the single chokepoint: `cache_get`/`cache_put` namespace the key by `util::budget::current_scan()` (the ambient the engine already establishes around every scan and every spawned module dispatch, now `pub(crate)`), and `reset_budget` calls a new `cache_clear_scan()` built on `ResponseCache::clear_prefix`, dropping only this scan's entries. The 200-iteration retry loop is DELETED — a workaround for the defect, not a test of anything — and replaced by a single put and a direct assertion. | `one_scans_cached_responses_are_never_served_to_another` (`src/util/see_know/tests.rs`): scan B is not served scan A's retrieval, each scan reads back what IT cached, and one scan's start leaves a sibling's cache intact. Falsified: collapsing the namespace back to one global bucket fails it and leaves the module's other 84 tests passing. | VERIFIED |
| REQ-INSTALL-006 (**new, Pass 17m — ON-DEVICE EVIDENCE**) | **A successful install reported failure, and `hse update` reported an error.** Observed on a real Termux aarch64 device: `curl \| bash` printed every step succeeding — binary written to `$PREFIX/bin/hse`, `Verified installed revision: a18d989`, wrappers installed, keys provisioned, `hse --version` and `hse doctor` both running — then ended `Installation failed (exit 1)`; `hse update` produced the same sequence then `error: installer exited 1`. Root cause is one line: `install.sh:1679` used `df -Pm`, and Termux's toybox `df` has no `-m`. **The script already knew this** — its preflight disk check carries the comment "Termux's toybox `df` does NOT implement `-m`" and uses `df -Pk` with an `NF >= 4` guard and `\|\| true` (`install.sh:252-261`). The optional local-AI step got none of that. toybox exits 1, `2>/dev/null` hides the diagnostic, `set -o pipefail` promotes it to a failed pipeline, a bare assignment inherits that status, and `set -e` kills the shell **before any of `setup_ai`'s six `return 0` guards can run** — every anticipated failure was made non-fatal, and one unanticipated failure bypassed all of them. Consequences: `install_ai_wrapper` never ran (no `hse-ai`), "Installation complete!" never printed, and `hse update` surfaced the trap's exit code (`src/app/update.rs`, `src/main.rs`). Fixed three ways: the line now uses the portable form this file already established; the latent twin at `install.sh:1629` (an unguarded `[[ -r /proc/meminfo ]] && mem=$(awk ...)` AND-list with the identical hazard) is guarded; and — the systemic correction — the OPTIONAL step is invoked as `setup_ai \|\| log_warn ...`, so a future unanticipated failure inside it degrades to a warning instead of failing an install whose every other step succeeded. | Reproduced directly with a stub `df` that rejects `-m`: the original construct kills the shell (`outer rc=1`, never reaching the next statement); the repaired construct yields a real value and `rc=0`, and survives `/proc/meminfo` being unreadable AND present-but-empty. Two locks in `tests/install_invariants.rs`: `no_df_invocation_uses_the_non_portable_megabyte_flag` and `the_optional_local_ai_step_cannot_fail_the_install`. Both falsified against the exact pre-fix source — the first names `install.sh:1699` in its failure message. **The first version of that `df` detector was itself vacuous** (it compared tokens to `"df"`, but the real token is `avail=$(df`) and PASSED on a tree still containing `df -Pm`; the falsification pass caught it and it was rewritten to match on the boundary character. | VERIFIED |
| REQ-KEYS-007 (**new, Pass 17m — ON-DEVICE EVIDENCE**) | **A template placeholder was treated as a configured credential**, in three places, producing a self-contradicting operator report and real wasted network requests. On the same device, `hse provision` reported `template keys: 61, real values: 0`, and `hse doctor` **in the same run** reported `HUNTSMAN_* keys loaded: 62`, listed **no unset keys at all**, and then said WiGLE and SeekNow were `NOT CONFIGURED` — because those two sections resolve through `keys::resolve_key` (which rejects a placeholder) while the rest tested only presence. Meanwhile `hse keys validate` printed `censys: testing insert_c… UNKNOWN` / `wigle: testing insert_w… INVALID` and "Validated 49 keys: 8 active": the pool had ingested 49 unedited `insert_..._here` slots as **Active**, and validation was spending real requests probing them against live provider endpoints, then reporting providers as having rejected credentials the operator never supplied. Root cause is one policy asked three ways: `sorted_huntsman_keys` filtered on the NAME only; `rank_unset_keys(\|k\| loaded.contains_key(k))` treated name-presence as set, suppressing the **entire** 54-entry acquisition-guidance section on any freshly provisioned device; and `register_configured_keys` guarded only on `!raw.is_empty()`. The correct predicate already existed — and `is_template_placeholder`'s own doc comment had **predicted this exact divergence**: "They disagreed before — only provision knew the rule ... a divergence would mean a module sending the literal string `insert_haveibeenpwned_key_here` as its credential." Fixed by consolidation: one `keys::is_configured_value` (blank-or-placeholder ⇒ not a credential), which `resolve_key` now delegates to, used at all three sites. | End-to-end with the real binary against the shipped `env_template.txt` (62 names, 62 placeholders, one real value): `HUNTSMAN_* keys loaded` goes **62 → 1**, the suppressed **54-entry** remediation section is restored, WiGLE/SeekNow still correctly NOT CONFIGURED — the report is now internally consistent — and the key pool is **empty** where the device had 49 Active placeholders. Three locks, all falsified against the pre-fix predicates; the pool lock independently computed **49** placeholder slots, matching the device's "Validated 49 keys". **Two of the three locks were initially vacuous** (they exercised helpers rather than the production call sites and passed with the defect fully restored); falsification caught both, `key_slot_is_filled` was extracted so production and test share one predicate, and the pool lock now drives the real `register_configured_keys`. | VERIFIED |
| REQ-KEYS-008 (**new, Pass 17n — ON-DEVICE EVIDENCE**) | **The tool told the operator to renew credentials they had never set.** The device's `hse doctor` reported `10 CONFIGURED KEY(S) REJECTED by the upstream — replace or renew` with real 401/403 bodies (github, censys, greynoise, leakix, onyphe, pulsedive, securitytrails, threatfox, opensanctions, binaryedge) on a box where provision had just reported `real values: 0`. Traced: `ctx.key_opt` correctly routes through `resolve_key` and rejects placeholders, but the **key cascade** is a second path — `next_pooled_key` → `KeyPool::next_key_excluding` — whose auth-eligibility guard tested `is_usable() && !is_harvested() && !excluded` and **not** whether the value is a credential at all. With REQ-KEYS-007's 49 placeholders sitting in the pool as Active, the cascade handed them to providers, the providers answered 401, and `report_key_exhausted` marked them `Invalid` — manufacturing the "rejected key" report. This is verbatim the harm `is_template_placeholder`'s doc comment predicted. REQ-KEYS-007 closes the env ingest path; this closes the **consumption chokepoint** every pooled key passes through, so the invariant now holds regardless of ingest path (`keys add`, `import-json`, `import-tsv`, or a future one) rather than depending on each one being guarded. The entry is still retained for `hse keys list` — it is excluded from auth-eligibility only, exactly as `is_harvested()` already does for attacker-plantable harvested keys, in the same guard. | `a_pooled_placeholder_is_never_handed_out_as_a_credential` (`src/util/key_pool/tests.rs`): a placeholder is retained but never selected, and a real credential in the same pool is still served past it (so the guard has not simply disabled selection). Falsified by deleting the guard clause from the production selection loop — the lock fails on the "never handed out" assertion and the module's other 51 tests pass. | VERIFIED |
| REQ-NOISE-002 (**investigated, Pass 17n — NO DEFECT**) | The device reported `3673 weak finding(s) — review before trusting as evidence`, 3667 of them from `name_intel` at confidence 0.20 over 7 days. Investigated as a suspected noise-generation defect; **the hypothesis is refuted and no change was made.** `name_intel` is a no-network permutation module that deliberately emits usernames/emails/search-pivots as low-confidence CANDIDATE entities to fuel expansion, documented in its own module header, with `--min-expand-confidence` (floor 0.20) as the operator knob to skip them. The load-bearing claim — that the correlator's own floors keep RESOLVED findings precise regardless — was verified rather than taken on trust: `IDENTITY_LINK_MIN_CONF` is 0.50 (`src/core/relation/graph.rs:63`), `AU063_DETAIL_MIN_CONF` is 0.40, and the breach-PII rules gate Person/Address at `>= 0.50`. A 0.20 permutation cannot reach a resolved finding. Recorded so a future pass does not re-investigate this volume as a defect. Residual, NOT acted on: doctor's "review before trusting as evidence" framing applies the same language to 3667 by-design candidates as to the 6 `search_engines` findings at 0.25, which arguably buries the latter — a reporting-ergonomics judgement, not a demonstrated harm, and changing a diagnostic's semantics on my own reading is not warranted. | Module doc `src/modules/name_intel/mod.rs:14-21`; floors verified by direct read at the three cited sites. | NO DEFECT |
| REQ-ARCH-001 (**new, Pass 17h — DISCLOSED, decision needed**) | `core::intelligence::BoundedFrontier` / `PathCandidate` / `FrontierBudget` is a second, dormant scheduler. The contract says "use the existing ROI/frontier system wherever viable; consolidate rather than introducing another scheduler", and the existing one is `core::roi` plus the engine round loop, which is what actually dispatches. `BoundedFrontier` has no production caller (`git grep`: only `storage::intelligence`, which adds its checkpoint save/load), and it carries a second ranking function — `PathCandidate::score` — alongside `core::roi::compute_dispatch_utility` and `expansion::cmp_expansion_candidates`. It also holds a capability the engine genuinely lacks: a durable frontier checkpoint with a visited set and dispatch budget that survives restart. | Read directly: `src/core/intelligence.rs` (the type), `src/storage/intelligence.rs` (its only reference). **Not resolved either way in this pass, deliberately.** Deleting removes a checkpointing capability the engine wants and overwrites recently-merged work whose intended wiring is not mine to assume; wiring it into the round loop replaces `cmp_expansion_candidates` and the visited set with an unexercised alternative and risks regressing verified expansion behaviour, against "do not regress any higher-priority verified property". Recorded so the duplicate authority is disclosed rather than silently carried; the owner's call. | AMBIGUOUS |
| REQ-GEO-005 (**new, Pass 17h — DISCLOSED**) | Two geolocation precision models coexist. `core::correlator::rules::location::precision_radius_m` maps each `GeoSourceClass` to a real-world accuracy radius (10 m device GNSS … 100 km phone region) and is the LIVE authority — it weights the AU-059 fusion and floors the headline estimate. `core::intelligence::LocationBasis::min_uncertainty_m` maps each epistemic basis to a floor (10 m observed … 25 km network-derived) and governs `GeoAssertion`, which no module emits. They answer adjacent questions — which source class produced this, versus what epistemic basis does it rest on — and mostly agree, but not everywhere: an electoral-roll address is `Electoral` at 150 m under the live model and would be `Reported` at a 100 m floor under the other. | `git grep GeoAssertion` shows no producer outside `core::intelligence` and its tests. **Not consolidated in this pass:** mapping `GeoSourceClass` onto `LocationBasis` would impose a second floor on live data at values I cannot justify from evidence (a rooftop geocode is genuinely ~40 m, below a `Derived` 100 m floor), and changing live radii on a speculative mapping is precisely the class of change the contract forbids. Recorded so the divergence is visible; resolving it needs either a producer for `GeoAssertion` or a decision to retire it. | AMBIGUOUS |
| REQ-LIVE-001 (**new, Pass 17f — DISCLOSED GAP, not fixed**) | A radar session is entirely in-memory and does not survive a process restart. `core::live` holds sessions in `RwLock<HashMap<String, LiveSession>>` with no store round-trip, and `core::live::mod.rs` creates the radar dispatch ledger fresh per process (`live.radar.then(DispatchLog::new)`). `DispatchLog`'s own documentation describes it as spanning "a potentially multi-day session" whose purpose is that a keyed or paid module never re-queries a seed it has already covered. On Android, process eviction over days is routine: the session, its iteration count, its scan-id set and its dispatch ledger all vanish, the operator's watch silently stops, and a restarted session re-spends every keyed and paid provider on every seed already covered. | Read directly: `src/core/live/mod.rs:198` (in-memory session map) and `:401` (fresh ledger per process); no `Store` method persists a `LiveSession` or a `DispatchLog`. **Deliberately not fixed in this pass:** durable sessions need persistence, restore-on-start and reconciliation of an interrupted iteration, and none of it can be exercised against real Android eviction from this container. Persisting only the ledger would be half a bridge — the session it belongs to is lost first. Recorded rather than half-built. | MISSING |
| REQ-GEO-001 (**new, Pass 17; reconciled Pass 17b**) | A coordinate can no longer claim precision its basis never had. `LocationBasis::min_uncertainty_m` gives every basis an honest floor (observed 10 m … administrative 5 km … **network-derived 25 km**) and `GeoAssertion::is_valid` now REJECTS a radius below it — previously an IP-derived fix asserting 50 m validated and was thereafter indistinguishable from a doorway. `locates_subject_directly` marks the bases that locate the SUBJECT (observed, independently verified) apart from those that locate something merely associated with them (an egress, a registered office, an administrative area): INFRASTRUCTURE LOCATION ≠ HUMAN LOCATION. `GeoAssertion::reconcile` never averages — it narrows to the tighter constraint when the discs overlap, returns `Conflict{separation_m}` when they do not, and `Undecidable` when either side is label-only rather than silently reading that as agreement. `IntelligenceLedger::reconcile_locations` cross-links a conflict into `competing_location_ids` (a field #584 declared but nothing populated), so the disagreement is preserved in the ledger. The Pass 17 parallel module `core::geo_confidence` is DELETED. | `a_precision_claim_never_exceeds_what_its_basis_can_support`, `an_associated_location_is_never_the_subjects_own`, `disjoint_locations_conflict_and_are_never_averaged` (Sydney/Melbourne, ~713 km, both preserved and cross-linked), `agreeing_coarse_locations_corroborate_the_area_not_a_street`, `a_label_only_location_is_undecidable_not_agreement` (`src/core/intelligence.rs`). Falsified: restoring `radius >= 0.0` fails the precision lock; deleting the `Conflict` arm fails the disjoint lock. Existing geo modules do not yet emit `GeoAssertion` — migration is the next pass. | IMPLEMENTED_UNVERIFIED |
| REQ-GEO-002 (**new, Pass 17d**) | **Defect, live GEOINT path.** AU-059's cross-class synergy fix — the HIGHEST-precedence rung of `best_au_location_estimate`, exported as `report.json`'s headline `best_location` and printed as the dossier's best-location line — reported its radius as the median distance from the fused point to the contributing sightings. That measures how closely the sightings AGREE, which is not how precisely any of them located the subject. Reproduced: a `search_engines` snippet geocode (15 km grain) and a `social_location` bio (5 km grain) that both name Sydney resolve ~400 m apart and the fix reported **± 0.20 km** — a 25× false-precision claim manufactured from two city-grain guesses agreeing, delivered to the operator as the tool's best answer. Fixed at the authoritative layer: the fused radius is floored at the finest contributing observation's own `best_precision_radius_m`, the same per-class precision model rung 2 already used. Not the textbook inverse-variance case — an IP egress or a carrier-region centroid carries a systematic offset, not zero-mean noise, so averaging several reduces no bias. | `agreeing_coarse_sightings_never_synthesise_a_precision_neither_had` and `a_genuine_disagreement_still_widens_the_radius_beyond_the_floor` (`src/core/correlator/rules/location/tests.rs`). Falsified: restoring `radius_km = spread_km` fails the first with `cannot report 0.20015086796013432 km when the tightest contributing source was only good to 5 km`, and leaves the other 23 tests in the module — including `radius_reflects_source_precision_not_a_flat_default` — passing, so the mutation is targeted. | VERIFIED |
| REQ-GEO-003 (**new, Pass 17d**) | INFRASTRUCTURE LOCATION ≠ HUMAN LOCATION and REGISTERED LOCATION ≠ PHYSICAL PRESENCE reach the operator on real data. `class_locates_subject_directly` splits the `GeoSourceClass` table into the classes that sight the subject's own device (handset GNSS, photo EXIF, the Wi-Fi APs that device can see) and every other class — a registered office, a land-title parcel, an electoral address, a people-finder listing, a social bio, a search snippet, an ISP allocation block, an ACMA area-code region — each a real place that can be right about the address and wrong about the person. A geocoded street address is on the associated side too: geocoding resolves a REPORTED address precisely, which says nothing about the subject ever standing at it. Deliberately orthogonal to precision (a registered office is known to ~500 m and is not the subject; a Wi-Fi survey is coarser at ~75 m and is), because collapsing the two is how a filing agent's PO box becomes a residence. `SynergyFix` and `AuLocationEstimate` carry the verdict at every rung, and it is surfaced as `best_location.locates_subject_directly` in `report.json` / the API and as an explicit NOTE line under the dossier's headline fix. Nothing is printed for a fix that DID observe the subject — the absence of a caveat is not a claim. | `a_registered_or_inferred_place_is_never_the_subjects_own_position` (every class asserted, and the precision-orthogonality pinned), `a_fix_built_only_from_records_is_marked_as_an_associated_location` (a registry + search-snippet fix is associated; swapping the snippet for a photo GPS flips both the fix and the headline estimate) — `src/core/correlator/rules/location/tests.rs`. | VERIFIED |

This section exists purely to close the ledger's own blind spot — the
correlator subsystem had no representation here at all before Pass 4, even
though its underlying protections were already comprehensive. No code
changed for this row; the fix is documentary.

---

## 9. Storage subsystem (`src/storage/`)

| ID | Behavior | Inputs | Outputs | Side effects | Failure behavior | Implementation location | Tests covering it | Runtime verification evidence | Status |
|---|---|---|---|---|---|---|---|---|---|
| REQ-STORAGE-001 (**new, Pass 10**) | `Store::integrity_check()` (`PRAGMA integrity_check`) must surface real on-disk SQLite corruption as a non-`["ok"]` result — trusted by `hse doctor` (critical-exit-code path) and the debug-bundle export API to decide whether the database is healthy (FTA finding E5.1 / top event T5). | none | `Result<Vec<String>>` | Read-only pragma | A healthy DB returns exactly `["ok"]`; a corrupt one returns a row per problem found, OR (severe corruption) the pragma itself errors. | `src/core/port/mod.rs:258-261` (trait), `src/storage/mod.rs:584-591` (impl); consumers `src/app/doctor/mod.rs:63-75`, `src/api/handlers/mod.rs:662-664` | `integrity_check_reports_ok_on_healthy_db` (healthy path, pre-existing), `integrity_check_reports_problems_on_a_corrupted_db` (new, Pass 10) (`src/storage/tests.rs`) | **Gap found and fixed in Pass 10.** The only existing test proved the healthy-DB path; nothing had ever fed `integrity_check()` a genuinely corrupted database to prove it actually detects real corruption rather than always reporting "ok". Added a test that builds a real `Store`, writes 400 entities, checkpoints, then truncates away the trailing ~40% of the file (real row data, since SQLite allocates pages append-only) — a deterministic corruption technique. **Empirical finding along the way**: this reliably fails `Store::open()` itself, not just `integrity_check()` — `open()` is not a bare `sqlite3_open`, it runs an idempotent `entity_observations` backfill and an FTS freshness count that both scan `entities`' real data pages (`src/storage/mod.rs`, right after schema setup), so corruption in the most-written table is caught even earlier than the explicit check. The test accepts either real outcome (open failing, or opening fine and `integrity_check()` then reporting/erroring) as long as some stage surfaces it. **A second, related gap found and fixed in the same investigation**: `hse doctor`'s handling of `integrity_check()` returning `Err` (`src/app/doctor/mod.rs`) printed `"could not run check"` but did **not** set the `critical` flag that drives the command's exit code — meaning severe-enough corruption (the pragma itself failing, exactly the failure mode this test's corruption technique produces) would print an alarming-looking line but still exit 0. Fixed: that branch now sets `critical = true` too, matching the sibling "ran and found problems" arm. Ran `cargo test --lib storage::tests` (108/108 passed, including both integrity_check tests) and `cargo test --lib app::doctor::tests` (14/14 passed, confirming the doctor fix didn't disturb any existing assertion) this pass. **Hardened after this pass's own PR review**: a Copilot finding correctly noted the test's original corruption predicate (matching "corrupt"/"malformed" in the error's Display text) wasn't guaranteed to catch every SQLite corruption-shaped error across versions/platforms; reworked to match the underlying `rusqlite::ErrorCode` (`DatabaseCorrupt`/`NotADatabase`/`SystemIoFailure`) instead, substring matching kept only as a fallback for non-`SqliteFailure` shapes. Re-ran the test after the rework — still passes. | VERIFIED |
| REQ-STORAGE-002 (**new, Pass 14**) | Persisting an entity a scan has already observed (an `entity_observations` row for `(uid, scan_id)` exists) GREATEST-merges `corroboration` instead of summing it. The engine re-persists the same accumulated working-set entity several times per scan (seed-round checkpoint, every productive round's dirty set, the finalise persist, the promotion-pass re-persist), so summing counted each observation once per pass. A conflict from a different scan is a separate observation and still sums. | `&Entity` | `Result<()>` | `entities` row update | rusqlite error propagates | `src/storage/entities.rs` (`merge_and_persist_entity`) | `re_persisting_a_scans_own_entity_keeps_its_corroboration_magnitude`, `upsert_entities_batch_merges_on_conflict` (`src/storage/tests.rs`); engine-boundary lock `persisted_corroboration_never_exceeds_the_observations_that_produced_it` (`tests/smoke.rs`) | Baseline reproduced at the engine boundary: a seed observed twice (the `seed` anchor + one echo module, magnitude 2 in memory) persisted with corroboration **4**; after the fix **2**. Falsified by stashing only `src/storage/entities.rs`: the smoke test fails again with `4 > 2`. Full lib suite 6876/6876, smoke 58/58. | VERIFIED |
| REQ-STORAGE-003 (**new, Pass 14**) | `Store::checkpoint_truncate()` returns `Err` when SQLite reports the TRUNCATE checkpoint blocked (`busy = 1` in the pragma's `(busy, log, checkpointed)` result row), so `hse tidy`'s `wal_truncated` and the finalise-housekeeping log never claim a truncation that did not happen. | none | `Result<()>` | WAL fold-back + `-wal` truncate | `Error::Other("WAL checkpoint blocked by a concurrent reader …")`, `-wal` untouched | `src/storage/mod.rs` (`checkpoint_truncate`) | `checkpoint_truncate_reports_a_blocked_checkpoint_instead_of_claiming_success` (a second connection holds an open read transaction; 100 ms busy timeout; then released and re-checkpointed) plus the pre-existing `checkpoint_truncate_resets_wal_file_and_keeps_data` (`src/storage/tests.rs`) | Ran `cargo test --lib storage::tests::checkpoint` — both pass. The old `execute_batch` form discarded the result row: the pragma never raises for a blocked checkpoint, so the doc comment's "returns `SQLITE_BUSY`, surfaced as `Err`" was false and `hse tidy` reported `wal_truncated = true` while the `-wal` still held every frame. | VERIFIED |
| REQ-STORAGE-004 (**new, Pass 15**) | `Store::prune_events` (startup, `hse tidy`, every scan's finalise housekeeping) never cuts the event log of a scan that is still `pending`/`running` and started within the retention window; a finished scan, and a `running` row older than the window (a killed process's leftover), are pruned exactly as before. | Verified by reading the prune and its callers: both cuts were global (`DELETE … WHERE ts < cutoff`; `DELETE … WHERE id NOT IN (newest max_rows)`), and `run_finalise_housekeeping` runs them at the end of EVERY scan, so under `hse serve` scan B's finalise pruned the oldest rows beyond 100 000 — scan A's own `ScanStart` / early `ModuleDone` rows while A was still running, which `events_for_scan` feeds to the export's `ModuleEventTally`, the diagnostics view and `events.log`. `prune_events_spares_a_live_scans_events_but_not_a_finished_or_zombie_scans` (`src/storage/tests.rs`) inserts a live, a finished and a zombie scan's events and prunes at a 4-row cap: live keeps 5, finished is cut to 4, zombie's aged rows go; with the exemption stashed the live scan loses every row (fails on the baseline). `cargo test --lib storage::tests` passes. **CI caught what the local subset run did not**: `core::port::tests::trait_object_events_round_trip` asserted that a zero row-cap prunes a fresh scan's event — now a live scan, so exempt. The test was strengthened, not weakened: it asserts the live scan keeps its row under a zero cap, then finishes the scan and asserts the same cap prunes it. Lesson recorded below: after a lib change the whole `--lib` suite runs before a push, never a module subset. | VERIFIED |

---

## 10. ROI-maximising expansion (`src/core/roi/`)

Three orthogonal, `max_roi`-gated levers (see the module's own doc comment,
`src/core/roi/mod.rs:1-21`): convergence-pruning (`is_saturated`), the
top-K/knee candidate cutoff (`effective_cutoff`/`apply_roi_cutoff`), and
adaptive-depth termination (`should_terminate_adaptive`). All three had
pre-existing pure-function unit coverage (`src/core/roi/tests.rs`) before
this section existed; the rows below track only whether each lever is also
proven at its real dispatch call site in `src/core/engine/`, not the pure
functions themselves.

| ID | Behavior | Inputs | Outputs | Side effects | Failure behavior | Implementation location | Tests covering it | Runtime verification evidence | Status |
|---|---|---|---|---|---|---|---|---|---|
| REQ-ROI-001 | Convergence-pruning: under `max_roi`, an entity with ≥2 corroborating sources AND `c_effective ≥ 0.85` is "saturated" and is never re-selected as an expansion candidate — saves dispatch budget on entities further queries would only re-confirm. | none | `bool` (pure), gates candidate selection at dispatch | Excludes the entity from `next` with `EntityExcluded{reason:"roi_saturated"}` | With `max_roi` off, saturated entities are still re-dispatched (no behavior change) — by design, not a defect. | `src/core/roi/mod.rs:39-47` (`is_saturated`); call site `src/core/engine/mod.rs:2111` (`if opts.max_roi && is_saturated(entity)`) | `saturation_requires_both_corroboration_and_confidence`, `single_source_high_magnitude_is_not_saturated` (`src/core/roi/tests.rs`, pure); `max_roi_excludes_saturated_entity_from_real_dispatch` (`src/core/engine/tests.rs`, real `engine.run()` dispatch — added during the architecture-invariants Phase 2 work, PR #578, not previously cited in this ledger) | Ran `cargo test --lib core::engine::tests::max_roi_excludes_saturated_entity_from_real_dispatch` this pass — passed. Drives a real 2-round chain through `ScanEngine::run()`: with `max_roi` on, a saturated entity's own further expansion never happens (`g1child` absent); with it off, the same entity IS re-dispatched (`g1child` present). | VERIFIED |
| REQ-ROI-002 | Top-K + relative-knee candidate cutoff: under `max_roi`, an expansion round keeps only the smaller of a concurrency-scaled top-K budget and the candidates within 5% of the round's leading weight — bounds both a flat flood of low-weight leads and long-tail noise trailing a strong lead. | `Vec<(Target, f64 weight, String parent_uid)>`, `max_concurrent` | Truncated candidate vec; releases the `visited` key of every cut candidate (so a cut lead can resurface later if evidence strengthens it) | A round with a weak/absent leader falls back to the top-K budget alone (`effective_cutoff`'s degenerate-all-zero branch). | `src/core/roi/mod.rs:49-92` (`top_k_for_round`/`effective_cutoff`); `src/core/engine/expansion.rs:83` (`apply_roi_cutoff`); call site `src/core/engine/mod.rs:2322` (`if opts.max_roi { apply_roi_cutoff(...) }`) | `top_k_scales_with_concurrency`, `effective_cutoff_*` ×3 (`src/core/roi/tests.rs`, pure); `roi_cutoff_releases_visited_keys_of_truncated_candidates` (`src/core/engine/tests.rs`) — calls the real `apply_roi_cutoff` directly (not the pure `effective_cutoff`) and asserts its `visited`-release side effect, but with a synthetic candidate vec, not through a real `engine.run()` dispatch | Ran `cargo test --lib core::roi::tests` (7/7 passed) and `cargo test --lib core::engine::tests::roi_cutoff_releases_visited_keys_of_truncated_candidates` (passed) this pass. Nothing proves the cutoff actually firing and truncating a real over-budget round inside `engine.run()` — the next gap in this section for a future pass. | IMPLEMENTED_UNVERIFIED |
| REQ-ROI-003 (**new, Pass 11**) | Adaptive-depth termination: under `max_roi`, if a round's marginal yield (`new_entities / dispatched_targets`) drops below the floor (default 0.75, overridable via `ScanOptions::min_marginal_yield`), the engine stops recursing even though `--depth` would allow more rounds — captures the `dE/dDispatch → 0` convergence boundary. | `bool max_roi`, `usize new_entities`, `usize dispatched_targets`, `f64 floor` | `bool` (pure); at the call site, an early `return StopReason::NoMoreCandidates` plus an `EventKind::ExpansionStop{reason}` naming "adaptive-depth: marginal yield X < floor Y" | Never terminates on the first round of a scan (`dispatched_targets == 0` ⇒ insufficient data, always continues) | With `max_roi` off, a low-yield round is never a stop signal — recursion proceeds to `--depth`, unchanged from pre-lever behavior. | `src/core/roi/mod.rs:107-121` (`should_terminate_adaptive`); call site `src/core/engine/mod.rs:2463-2481` | `adaptive_termination_only_fires_when_enabled_and_below_floor`, `marginal_yield_handles_zero_dispatches` (`src/core/roi/tests.rs`, pure, pre-existing); `max_roi_adaptive_depth_stops_a_real_dispatch_round_on_low_marginal_yield` (new, Pass 11) (`src/core/engine/tests.rs`) | **Gap found and fixed in Pass 11.** The lever had zero coverage above the pure-function level. Added a 3-round real-dispatch test: round 1 (seed → 4 children) yields 4.0 (no stop); round 2 (4 children → the SAME shared entity, so 3 of 4 dispatches merge rather than insert) yields 0.25 (below floor); round 3 only ever runs without the lever. Asserts both the entity outcome (`deep_child` present/absent) AND the `ExpansionStop` event's reason text. **Mutation-tested**: temporarily short-circuited the termination check to always-false, re-ran — the entity-presence assertions alone still passed (a *different*, independent lever — saturation-pruning — also blocks round 3 once the shared entity accumulates 4 corroborating sources by then), but the event-reason assertion correctly failed, confirming that assertion is the one actually discriminating this lever from the others rather than the test being vacuously satisfied by an unrelated mechanism. Restored the real code, re-confirmed passing (5/5 repeated runs, ruling out flakiness from the real concurrent-dispatch path this test exercises at the default `max_concurrent: 2`). Ran `cargo test --lib core::engine::tests::max_roi_adaptive_depth_stops_a_real_dispatch_round_on_low_marginal_yield` this pass — passed. | VERIFIED |

---

## 11. Provider capability + economics descriptor (`src/core/module/provider.rs`)

A directive-driven addition (not backlog-derived): "unify provider
capability + economics metadata" — extend the nearest existing
authoritative abstraction (`Module`/`ModuleInfo`) rather than build a
disconnected registry. `ProviderDescriptor` is mechanically derived for
every module by `derive_default_provider_descriptor` from properties the
`Module` trait already exposes (`cost()`, `is_passive()`,
`cache_ttl_secs()`, `is_high_value_only()`, `requires_geo_corroboration()`,
`consumes()`, `produces()`, `category()`), with a default trait method
(`Module::provider_descriptor`) any module can override — 6 do, where the
generic derivation would misrepresent a real provider (`oathnet_pro`,
`wigle`, `see_know`, `osintcat`, `hudsonrock`, `comb_search`).

| ID | Behavior | Inputs | Outputs | Side effects | Failure behavior | Implementation location | Tests covering it | Runtime verification evidence | Status |
|---|---|---|---|---|---|---|---|---|---|
| REQ-PROVIDER-001 (**new, Pass 12**) | Every one of the 188 registered modules exposes an internally-consistent `ProviderDescriptor`: `access_class` and `requires_key` agree in both directions; a `Free` `cost_model` never carries a `cost_per_request` and implies `Keyless` access; `EscalationBand::L0Local` holds if-and-only-if `Module::is_passive()`; a cross-correlation-gated module (`is_high_value_only()` or `requires_geo_corroboration()`) is always `L4Specialist`; `cache_policy` exactly mirrors `cache_ttl_secs()`; and all 4 `[0,1]` priors (`provenance_quality_prior`, `uniqueness_prior`, `reliability_prior`, `optionality_prior`) stay in range. | none (derived from each module's own trait methods) | `ProviderDescriptor` (`Module::provider_descriptor()`, also exposed on `ModuleInfo.provider`) | none — pure derivation, no I/O | A module whose override breaks any of the above invariants fails this registry-wide test, not just at runtime. | `src/core/module/provider.rs` (`derive_default`, the `ProviderDescriptor` struct + enums); wired via `Module::provider_descriptor()` default method (`src/core/module/mod.rs`) | `every_registered_module_has_an_internally_consistent_provider_descriptor` (`tests/architecture_parts/architecture_part7.rs`) | Ran `cargo test --test architecture every_registered_module_has_an_internally_consistent_provider_descriptor` this pass — passed, iterating all 188 live modules from `crate::modules::registry()` (asserted `mods.len() > 100` as a registry-non-empty sanity floor). **Placed as an integration test, not a `src/core/module/` unit test**: an earlier draft put this directly in `src/core/module/provider_tests.rs`, which failed the pre-existing `core_does_not_import_modules` architecture invariant (`tests/architecture.rs`) — `src/core/` must stay module-agnostic, and this test genuinely needs the real registry. Moved here; `src/core/module/provider_tests.rs` keeps only the pure-function/local-stub-module tests (see REQ-PROVIDER-003/004). | VERIFIED |
| REQ-PROVIDER-002 (**new, Pass 12**) | The 6 providers whose real operational profile diverges from what the generic derivation alone would produce carry explicit, evidence-grounded overrides via struct-update syntax over `derive_default_provider_descriptor`: `oathnet_pro`/`wigle` → specialist escalation band + a named `quota_unit`; `wigle` → `AccessClass::FreeQuota` (not the generic `KeyGated`-derived class, reflecting its real quota-based free tier); `see_know` → `Enterprise`/`L5Enterprise`/`Estimated` cost model; `osintcat` → `Paid`/`L3Microcost`/`Exact` cost model (a genuinely live, provider-supplied per-search price); `hudsonrock`/`comb_search` → asymmetric `provenance_quality_prior` overrides (above/below the `0.5` neutral default) reflecting each provider's actual data-quality reputation. | none | `ProviderDescriptor` per named module | none | An override that regresses to the generic default, or drifts from its documented value, fails the row's own spot-check test. | `src/modules/oathnet_pro/mod.rs`, `src/modules/wigle/mod.rs`, `src/modules/see_know/mod.rs`, `src/modules/osintcat/mod.rs`, `src/modules/hudsonrock/mod.rs`, `src/modules/comb_search/mod.rs` (each a `provider_descriptor()` override) | `the_six_overridden_providers_have_their_expected_provider_descriptors` (`tests/architecture_parts/architecture_part7.rs`, same layering reason as REQ-PROVIDER-001) | Ran `cargo test --test architecture the_six_overridden_providers_have_their_expected_provider_descriptors` this pass — passed. | VERIFIED |
| REQ-PROVIDER-003 (**new, Pass 12**) | Per-provider `cost_per_request` is never a compiled-in constant (vendor prices change) — the only way to attach a live figure is the `HSE_PROVIDER_COST_<PROVIDER_ID_UPPERCASED>` env var, and the value is parsed defensively: finite and non-negative only. A negative, non-numeric, `"NaN"`, or `"inf"` value is rejected (falls back to `None`, i.e. `CostModel::Unknown` stays in effect), never silently accepted as a price. | `HSE_PROVIDER_COST_<ID>` env var (string) | `Option<f64>` | none (read-only env access) | An unset or malformed env var yields `None` — never a spurious cost that would wrongly satisfy a cost-budget check. | `src/core/module/provider.rs` (`env_cost_per_request` — thin env wrapper; `parse_cost_per_request` — the pure, directly-testable validation, split out specifically because `#![forbid(unsafe_code)]` blocks `env::set_var` even in `#[cfg(test)]` code) | `env_cost_per_request_is_none_when_unset`, `parse_cost_per_request_accepts_only_finite_nonnegative_numbers` (`src/core/module/provider_tests.rs`) | Ran both tests this pass — passed. `parse_cost_per_request_accepts_only_finite_nonnegative_numbers` directly exercises the negative/`NaN`/`inf`/non-numeric rejection paths without any env mutation. | VERIFIED |
| REQ-PROVIDER-004 (**new, Pass 12**) | Hard eligibility gate, checked before any ranking: when an operator has set a finite `ScanOptions::max_cost_usd` budget, a module whose provider is `Paid`/`Enterprise` access class AND `CostModel::Unknown` must be skipped at dispatch — UNKNOWN cost is never treated as FREE cost — unless the operator has explicitly set `ScanOptions::allow_unknown_cost_dispatch`. No budget configured ⇒ never blocks, regardless of cost model. | `ProviderDescriptor`, `Option<f64> max_cost_usd`, `bool allow_unknown_cost_dispatch` | `bool` (pure gate); at the dispatch call site, `Some("unknown-cost paid provider blocked...")` from `module_skip_reason`, tallied as a skip | none | A provider with a known/estimated cost, or a non-paid access class, is never blocked by this gate regardless of budget state (enforcing an actual cost cap against a known price is separate, future work). | `src/core/module/provider.rs` (`unknown_cost_paid_provider_blocked`); call site `src/core/engine/dispatch.rs:347-356` (`module_skip_reason`, checked before the `passive_only` gate and all ranking) | `unknown_cost_gate_only_blocks_paid_or_enterprise_unknown_cost_under_a_budget` (pure 6-case truth table, `src/core/module/provider_tests.rs`); `unknown_cost_paid_provider_is_blocked_by_an_active_cost_budget` (new, Pass 12) (`src/core/engine/tests.rs`) — drives a real `ScanEngine::dispatch_target()` call with a stub `Paid`/`Unknown`-cost module across all 3 budget states (none, active without opt-in, active with opt-in) | Ran the pure truth-table test (passed) and the new real-dispatch test this pass — `cargo test --lib core::engine::tests::unknown_cost_paid_provider_is_blocked_by_an_active_cost_budget --features dep-cooldown` — 1/1 passed, proving the gate actually stops dispatch at the real engine call site, not just as an isolated pure function. | VERIFIED |
| REQ-PROVIDER-005 (**new, Pass 12**) | All CLI/API/Web consumers read the same authoritative `ProviderDescriptor` — no separate, hand-maintained provider metadata anywhere else in the codebase. Found and fixed a real drift along the way: `GET /api/v1/modules`'s handler hand-rolled its JSON per-field and (a) named the seed-type field `"accepts"` where the CLI's own `ModuleInfo` calls the identical data `"consumes"`, and (b) omitted `attack_techniques` entirely — both silently missing from the API surface despite existing on every `ModuleInfo` the engine already builds. | `Arc<dyn Module>` (via `engine.modules()`) | JSON module list (`"provider"` key added; `"accepts"` key name kept for the existing served SPA's own JS compatibility, now sourced from `ModuleInfo.consumes` instead of being hand-duplicated) | none | A future field added to `ModuleInfo` that the handler forgets to forward is now structurally harder to miss — the handler builds from `m.info()` as a whole, not field-by-field. | `src/api/handlers/mod.rs` (`modules_list`, rewritten to build from `Module::info()` instead of a hand-rolled field list) | `modules_list_returns_array` (`tests/api.rs`, extended Pass 12) | **Gap found and fixed in Pass 12.** Extended the existing test to assert `attack_techniques` and `provider` are present in the API response and compare the full response for the API's one synthetic test module against `SyntheticModule.info()` directly (the `test_app` harness always serves a single test-double module, never the real 188-module registry — confirmed via `tests/common/mod.rs`, and a first draft of this test wrongly assumed otherwise before being corrected). Ran `cargo test --test api modules_list_returns_array --features dep-cooldown -- --nocapture` this pass — passed. | VERIFIED |

---

## 12. Dispatch-utility explainability (`src/core/roi/utility.rs`)

Directive-driven: "extend the existing ROI subsystem to reason about
novelty, source independence, pivot optionality, source reliability,
expected information gain, monetary cost, quota cost, latency, failure
probability, and duplication probability — one canonical `DispatchUtility`
result, additive/log-space, never a naive multiplication that lets one
uncertain zero-valued factor collapse the whole score; hard eligibility
gates before ranking; runtime evidence when available, static priors for
cold start; every decision explainable; preserve the three existing ROI
levers exactly." A 6-agent research + 1 design-synthesis workflow first
re-grounded the exact current source (the three existing levers, the
per-round candidate-weight computation, the just-merged `ProviderDescriptor`
cost/quota/reliability/optionality metadata, existing reliability/latency/
novelty/duplication signals, and the complete existing test corpus) before
any code was written — see "Pass 13 findings" below for what that research
found and where this implementation deliberately narrows the original
design for a defensible, fully-real v1 (no invented signals).

| ID | Behavior | Inputs | Outputs | Side effects | Failure behavior | Implementation location | Tests covering it | Runtime verification evidence | Status |
|---|---|---|---|---|---|---|---|---|---|
| REQ-ROI-004 (**new, Pass 13**) | `compute_dispatch_utility` maps a `DispatchUtilityInputs` to one canonical `DispatchUtility` via a strictly additive formula (10 named factors, each a bounded `+`/`-` term against a running sum) — a missing/unknown input resolves to a documented neutral default (never a silent `0.0` benefit or `1.0` penalty), so no single uncertain factor can collapse the score the way a `weight *= reliability` multiplication would. | `DispatchUtilityInputs` (source_count, entity_confidence, optionality_prior, novelty_prior, reliability_prior, cost_per_request_usd, quota_remaining, configured_timeout_ms, already_dispatched_this_module_target) | `DispatchUtility { expected_information_value, expected_novelty, expected_independence, expected_optionality, reliability, estimated_cost, quota_cost, latency_penalty, failure_penalty, duplicate_penalty, final_utility, explanation }` | none — pure function, no I/O | An all-unknown input set still yields a positive `final_utility` when `expected_information_value` is high; a zero-valued `reliability_prior` alone cannot zero the total. | `src/core/roi/utility.rs` (`compute_dispatch_utility`, the 10 `W_*` weight constants, `UNKNOWN_COST_PENALTY`, `QUOTA_COST_NEUTRAL`) | `missing_reliability_falls_back_to_neutral_prior_not_zero`, `missing_cost_yields_fixed_penalty_not_infinite_or_zero`, `missing_quota_yields_neutral_default_not_full_exhaustion`, `missing_factors_never_collapse_dominant_term`, `explanation_is_never_empty_and_always_restates_final_utility`, `duplicate_penalty_is_binary_and_dominant`, `expected_independence_is_monotonic_and_bounded` (`src/core/roi/utility_tests.rs`) | Ran `cargo test --lib core::roi::utility --features dep-cooldown` this pass — 8/8 passed, including `missing_factors_never_collapse_dominant_term`, which directly proves the directive's core robustness ask: an all-unknown-input candidate scores strictly higher than an all-known-worst-value one, and a zero `reliability_prior` alone leaves `final_utility > 0`. | VERIFIED |
| REQ-ROI-005 (**new, Pass 13**) | Quota-budget hard eligibility gate, same family and same call-site position as REQ-PROVIDER-004's monetary gate: a module that tracks a local quota (`ProviderDescriptor::quota_unit.is_some()`) and reports it exhausted (`Module::quota_remaining() == Some(false)`) must never dispatch, checked before any ranking. A module with no local quota, or an unresolvable remaining state, never blocks — unknown is not exhausted. | `Option<&'static str> quota_unit`, `Option<bool> remaining` | `bool` (pure gate); at the dispatch call site, a skip reason from `module_skip_reason`, tallied as a skip | none | A quota-untracked module (`quota_unit: None`, ~184 of 188 registered modules) is never blocked by this gate regardless of `quota_remaining()`'s return value. | `src/core/roi/utility.rs` (`quota_exhausted_blocked`); new `Module::quota_remaining()` default trait method (`src/core/module/mod.rs`, default `None`) overridden by `oathnet_pro` (`oathnet::budget_snapshot().quota_exhausted`) and `see_know` (`see_know::budget_remaining()`); call site `src/core/engine/dispatch.rs` (`module_skip_reason`, immediately after the existing unknown-cost gate) | `quota_exhausted_gate_only_blocks_quota_tracked_modules` (pure 5-case truth table, `src/core/roi/utility_tests.rs`); `quota_exhausted_provider_is_blocked_at_real_dispatch` (new, Pass 13) (`src/core/engine/tests.rs`) — drives a real `dispatch_target()` call across `Some(false)`/`Some(true)`/`None` remaining states | Ran both this pass — `cargo test --lib core::roi::utility::tests::quota_exhausted_gate_only_blocks_quota_tracked_modules` and `cargo test --lib core::engine::tests::quota_exhausted_provider_is_blocked_at_real_dispatch --features dep-cooldown` — both passed. **`wigle` deliberately NOT wired** — its real budget is five independent sub-budgets (geo/BSSID/cell/Bluetooth/SSID) and collapsing that to one bool would misrepresent the real state; documented in `src/modules/wigle/mod.rs` as an explicit, honest v1 gap rather than a wrong answer, matching REQ-ROI-002's own precedent of leaving a genuine gap IMPLEMENTED_UNVERIFIED rather than overclaiming. | VERIFIED |
| REQ-ROI-006 (**new, Pass 13**) | `DispatchUtility` is computed and surfaced (`EventKind::DispatchUtilityComputed`) ONLY for a candidate that every eligibility gate (allowlist, exclude, live-sensor, category-focus, circuit-open, disabled-in-config, `free_only`, unknown-cost budget, quota-exhausted, `passive_only`, sensor-dedup, high-value cross-correlation, SSRF preflight, quarantine) already cleared — never for one a gate rejected. Purely additive: off by default (`ScanOptions::dispatch_utility`, default `false`), changes no dispatch order, decision, or count when unset. | real per-module `ProviderDescriptor`/`quota_remaining()`/`constrained_timeout_ms()`, the target entity's `c_effective()`/`source_count()`, `crate::core::convex::module_cascade`, `DispatchLog::contains` (read-only) | `EventKind::DispatchUtilityComputed { module, target_kind, target_value, final_utility, explanation }` on the scan's event bus | Emits an event; never mutates dispatch state, `DispatchLog`, or `ModuleStats` | With `dispatch_utility` off (the default), zero events emitted and zero behavior change — the lever cannot fire accidentally. | `src/core/engine/dispatch.rs` (`maybe_emit_dispatch_utility`, called at all 3 `gate_skips` call sites — the sequential path and both concurrent phases — immediately after `gate_skips` returns `false`); new `dispatch_utility: bool` field (`src/core/scan/options.rs`); new `EventKind::DispatchUtilityComputed` variant (`src/core/event/mod.rs`) | `eligibility_gates_fire_before_dispatch_utility_is_ever_computed`, `dispatch_utility_off_by_default_produces_zero_behavior_change`, `dispatch_utility_explanation_is_surfaced_on_a_real_dispatch` (new, Pass 13) (`src/core/engine/tests.rs`) | Ran all three this pass — passed. The first reuses the existing `UnknownCostPaidProbe` (paid, unknown cost) under an active budget WITH `dispatch_utility: true`, and asserts zero `DispatchUtilityComputed` events fire for the gate-blocked module — proving the ordering the directive requires, not just asserting it in prose. The existing pinned-ordering tests (`convex_budget_dispatches_the_highest_query_value_module_first`, `priority_waterfall_seeknow_then_gov_then_free_then_geo`) and all pre-existing ROI/quarantine/cost-budget tests were re-run this pass and still pass unchanged, since this lever computes `DispatchUtility` for telemetry only and never substitutes it for the existing weight/priority/convex ordering. | VERIFIED |
| REQ-ROI-007 (**new, Pass 17**) | The frontier ranks GEOINT slightly ahead of otherwise-equal work: `DispatchUtilityInputs::geoint_bearing` (derived from the module's own `produces()`/`category()` by `is_geoint_bearing`, not a hand-kept list) adds `W_GEO = 0.25` to the dispatch utility and appears in the explanation. The tilt cannot override stronger evidence — `W_GEO` is an order of magnitude below `W_INFO = 3.0`. | `geoint_preference_orders_two_otherwise_identical_candidates` (the geo candidate wins by exactly `W_GEO`), `geoint_preference_cannot_outrank_stronger_evidence` (a low-information geo lookup still loses to a high-information non-geo one, and the weight bound is asserted), `geoint_bearing_is_derived_from_a_modules_own_declarations` (`src/core/roi/utility_tests.rs`). Wired at the real call site in `src/core/engine/dispatch.rs`. | VERIFIED |

**Deliberate v1 narrowing from the original design** (see "Pass 13 findings"
below for the full account): `expected_information_value` is grounded in
the target entity's own `c_effective()` (`1.0 - confidence`, so a wholly
unconfirmed candidate scores maximally valuable) rather than the per-round
expansion `weight: f64` the original design's research identified as the
"more natural" seed — that `weight` is computed earlier in
`src/core/engine/mod.rs`'s round loop and is not currently threaded into
`DispatchCx`/`dispatch.rs`'s per-module scope; threading it through is a
real, scoped, and explicitly NOT-built-here follow-up. `latency_penalty` is
a configured-timeout-budget proxy, not an observed measurement — no
`Instant::elapsed()` capture exists around module dispatch today. The live
circuit-breaker signal is deliberately NOT one of `DispatchUtility`'s
inputs: `module_skip_reason`'s existing `circuit::is_open` gate already
runs strictly before ranking, so any candidate reaching the scorer is, by
construction, circuit-closed — passing it in again would be dead state, not
a real signal.

---

## Pass 3 findings

Extended coverage to the HTTP API surface (section 6 above) — `hse serve`'s
actual remote-facing product surface, the highest-value gap Pass 2
identified. Derived and verified via a 4-agent-derive + per-row-adversarial-
verify workflow (39 agents total, 0 errors): 4 parallel agents each surveyed
one API sub-area (routes+auth, scan handlers, settings/cells/key-harvest/
update handlers, scan export+redaction) and proposed candidate rows; one
independent verification agent per candidate row then re-checked it against
current source and re-ran every cited test itself, correcting or confirming
the status. 35 rows survived: 19 VERIFIED, 12 PARTIAL, 2
IMPLEMENTED_UNVERIFIED, 1 BROKEN, 1 UNREACHABLE going in.

**Fix — REQ-API-MISC-004** (the one BROKEN finding): `cells_import`
(`POST /api/v1/cells/import`) read `HUNTSMAN_OPENCELLID_KEY` via a raw
`std::env::var` call, so a blank value or the exact template placeholder
`insert_opencellid_key_here` (`src/cli/env_template.txt`'s shipped default)
was treated as "configured" — the same "unfiltered credential reaches a live
request" bug class REQ-CORE-012 already closed at the `Module` trait layer,
recurring here because that layer's architecture guard
(`modules_never_read_credentials_via_raw_env`) is scoped to `src/modules/`
only and cannot see `src/api/`. Fixed by routing the same call site through
`keys::load()` + `keys::resolve_key` — the codebase's one sanctioned
resolution policy, already used one file over in `key_harvest_handlers.rs`.
Split the filtering logic into a pure `resolve_opencellid_key` helper so it
is unit-testable without mutating the process environment (`std::env::
set_var` is `unsafe`, forbidden under this crate's `#![forbid(unsafe_code)]`
— the same constraint `src/util/budget/tests.rs` documents hitting for the
identical reason). Added 4 regression tests (unset / blank / the exact
shipped placeholder / a real-looking value).

REQ-API-SCAN-006 (UNREACHABLE — a dead in-handler size-check branch behind
axum's own `DefaultBodyLimit` layer, so an oversized upload gets a
plain-text 413 instead of this API's usual JSON error shape) was found and
verified but **not** fixed this pass: the underlying safety property already
holds (oversized uploads are rejected either way), so this is a response-
shape/DX inconsistency, not a correctness or security defect — lower value
than REQ-API-MISC-004's credential-handling bug. Left as a known gap for a
future pass.

### Verification commands run (Pass 3, in order)

```
$ cargo test --lib api::cells_handlers -- --test-threads=4        # 14 passed
$ cargo fmt --all
$ cargo clippy --all-targets --features dep-cooldown -- -D warnings   # clean
$ cargo test --lib --features dep-cooldown                        # 6840 passed, 0 failed
$ cargo test --test architecture                                  # 55 passed, 0 failed
$ scripts/gate.sh                                                 # 17/17 executed checks PASS
```

## Pass 4 findings

Closed the ledger's one remaining `MISSING` row and opened two new
one-row sections for previously-unrepresented subsystems, per the "HSE
Requirements Closure Engine" directive's priority order (`MISSING` before
new-scope expansion). Scope was 3 items, none sharing a file with another:

1. **REQ-ENV-003** (`MISSING` → `VERIFIED`) — re-deriving this row rather
   than trusting Pass 1/3's prior framing found it had overclaimed: tracing
   every caller of `oathnet_quota()`/`see_know_quota()`/`wigle_quota()`
   directly (`grep -rn` across `src/`) showed only
   `HSE_OATHNET_PER_SCAN_LIMIT` has a live runtime effect
   (`oathnet::BUDGET`); the other 3 env knobs
   (`HSE_OATHNET_DAILY_LIMIT`/`HSE_SEE_KNOW_PER_SCAN_LIMIT`/
   `HSE_WIGLE_PER_SCAN_LIMIT`) are parsed by `quota_config.rs` and then
   never read again. Rather than paper over that distinction (which would
   have manufactured a new instance of the exact "documented knob that
   silently does nothing" bug class REQ-API-MISC-004/REQ-CORE-012 already
   guard against elsewhere), the fix documents only the one live knob
   accurately: `.env.example` gained one commented entry for it,
   `quota_config.rs`'s own overclaiming module doc comment ("Each API
   module reads its limits once at startup and uses them throughout the
   process lifetime" — false for 3 of 4) was corrected with an explicit
   live/dead annotation per var, and a new architecture test,
   `non_huntsman_env_reads_are_known`
   (`tests/architecture_parts/architecture_part3.rs`), closes the blind
   spot generally: it collects every non-`HUNTSMAN_`-prefixed literal
   `env::var`/`env::var_os` read anywhere in `src/`, asserts each is in an
   explicit, commented allowlist, and — mirroring the existing
   `ALLOWED_RAW_ENV`/`NOT_YET_WIRED` anti-rot idiom — asserts nothing in
   that allowlist has gone stale. (One mistake was caught before running
   the test: `HSE_BIND`/`HSE_AUTH_TOKEN` were initially included in the
   allowlist, but those are read via clap's `#[arg(env = "...")]` derive
   attribute, not a literal `env::var(...)` call this scanner can see, so
   they were removed with an explanatory comment.)

2. **REQ-ENGINE-001** (new, `VERIFIED`) — the scan engine's dead-module
   quarantine gate (`gate_skips`, `src/core/engine/dispatch.rs:753-790`,
   checked at all 3 dispatch call sites) had a completely open evidence
   gap: every `DispatchCx` literal across the existing
   `src/core/engine/tests.rs` passed the empty `no_quarantine()` static, so
   nothing had ever proven the engine actually skips a quarantined module
   — despite this being hot-path behavior on every scan. Added two new
   dispatch-level tests using the established `CachingProbe`-style harness
   (a `CountingProbe` incrementing an `Arc<AtomicU64>`), each looped across
   `max_concurrent in [0, 4]` to cover both the sequential and concurrent
   `gate_skips` call sites:
   `quarantined_module_is_skipped_at_dispatch_and_never_invoked` (the
   quarantined module is never called, contributes nothing, and
   `stats.skipped == 1`) and
   `unquarantined_module_in_a_nonempty_quarantine_set_still_dispatches`
   (proves quarantine is scoped by name, not "any non-empty set skips
   everything"). Deliberately left out of scope: the *upstream* gate
   (`src/core/engine/mod.rs:717-743`) that computes the `quarantined` set
   in production — `recent_module_outcome_events` is a `StoragePort` trait
   method `InMemoryStore` does not override (a no-op default), so that path
   always computes an empty set under the standard test double regardless
   of the flag. Proving it end-to-end needs a real event-store fake or a
   heavier SQLite integration test, noted as a follow-up rather than
   silently left uncovered.

3. **REQ-CORRELATOR-001** (new, `VERIFIED`) — planned as a new
   completeness/uniqueness guard for the correlator's `RULES`/
   `RELATION_RULES` registries (121 combined rule-function pointers),
   motivated by the same class of bug the module registry's own
   `module_names_are_unique` guards against, and by inline doc comments at
   the `AU-121`/`AU-122` entries recording a real past incident (a merge
   that produced two rules both claiming `AU-114`/`AU-115`, caught and
   manually renumbered by a human). Two independent exploration passes and
   a design pass all concluded no such guard existed. It did: before
   committing a drafted new test, a direct read of
   `tests/architecture_parts/architecture_part4.rs` surfaced four
   pre-existing tests already covering exactly this —
   `every_defined_correlation_rule_is_dispatched`,
   `no_two_correlation_rule_functions_share_a_number` (whose own doc
   comment cites the identical AU-114/AU-115 incident),
   `correlation_rule_ids_match_their_function_number`, and (in the sibling
   file `architecture_part5.rs`) `every_dispatched_correlation_rule_has_a_
   firing_test`. The drafted duplicate was reverted before being shipped
   (confirmed via `git diff --stat` showing zero net change), and all four
   pre-existing tests were re-run fresh as this row's evidence instead. No
   code changed for this row — new Section 8 exists purely to close the
   ledger's own blind spot (the correlator had no representation here at
   all before Pass 4, even though its underlying protections were already
   comprehensive), and to record, transparently, that this pass almost
   shipped a duplicate and caught it through direct verification rather
   than trusting two agents' and its own converging assumption. This is
   the same "claim ≠ evidence, verify before trusting" discipline the
   directive itself mandates, demonstrated on itself.

### Verification commands run (Pass 4, in order)

```
$ cargo test --test architecture non_huntsman_env_reads_are_known         # 1 passed
$ cargo test --test architecture                                          # 56 passed, 0 failed
$ cargo test --lib quarantine -- --test-threads=4                         # 2 new + related, all passed
$ cargo test --lib core::engine::tests -- --test-threads=4                # 105 passed, 0 failed, 1 ignored
$ cargo test --test architecture correlat                                 # 5 passed
$ cargo test --test architecture rule                                     # 5 passed
$ cargo fmt --all
$ cargo clippy --all-targets --features dep-cooldown -- -D warnings       # clean
$ cargo test --lib --features dep-cooldown                                # full suite, 0 failed
$ cargo test --test architecture                                          # 56 passed, 0 failed
$ scripts/gate.sh                                                         # 17/17 executed checks PASS
```

## Pass 5 findings

Continuing the loop after Pass 4's PR merged: re-fetched `origin/main`,
recomputed the ledger's non-`MISSING`/non-`BROKEN` remainder fresh (per the
priority order, next up is a correctness-affecting `PARTIAL`), and picked
**REQ-API-MISC-003** — the settings-toggle write endpoint.

Re-reading the row rather than trusting Pass 3's framing: `settings_toggles_put`
(`PUT /api/v1/settings/toggles`) had two rejection-path tests
(`settings_toggles_put_rejects_non_loopback_peer`,
`settings_toggles_put_rejects_unknown_key`) but its SUCCESS path — the one
that actually flips a capability on or off — had never been driven end to
end, and the persistence primitive it and `hse config` both funnel through,
`crate::util::settings::set_bool`, had zero test coverage anywhere in the
repository (confirmed via `grep -rn "set_bool("` — exactly 2 real call
sites, both non-test). A write endpoint whose only tested behavior was
"refuses to write" is a real gap: a regression in `set_bool`'s cache-mutate
step, or in the atomic-persist step, or in the handler's own success
branch, would ship with zero automated signal.

Fixed with two tests, one per layer:

- `set_bool_persists_and_get_bool_reads_it_back`
  (`src/util/settings/tests.rs`) — a direct round-trip: `set_bool` flips the
  in-process `CACHE` immediately (checked via `get_bool`), AND persists to
  disk (checked independently via `read_map(&settings_path())`, not the
  cache). Uses a private scratch key (`test.set_bool_round_trip_marker`,
  not a registered `FEATURE_TOGGLES` entry) and restores it to `false` at
  the end, since `CACHE` and the settings file are process-global and
  shared across every test in the binary.
- `settings_toggles_put_succeeds_and_persists_the_flip` (`tests/api.rs`) —
  a loopback `PUT` with a real, known key (`feature.depth_decay`, chosen
  because no other test in the file asserts a specific value for it)
  asserts the 200 response body (`status`/`key`/`enabled`), then issues a
  FRESH `GET /api/v1/settings/toggles` and confirms the flip is visible
  there too — proving the write actually persisted rather than merely being
  echoed back in the PUT's own response — then restores the default,
  matching the unit test's hygiene for the same process-global-state reason.

No production code changed for this row — same pattern as REQ-CORRELATOR-001
in Pass 4, a pure coverage fix for behavior that was already correct.

### Verification commands run (Pass 5, in order)

```
$ cargo test --lib set_bool_persists_and_get_bool_reads_it_back           # 1 passed
$ cargo test --test api settings_toggles_put                              # 3 passed (2 pre-existing + 1 new)
$ cargo fmt --all
$ cargo clippy --all-targets --features dep-cooldown -- -D warnings       # clean
$ cargo test --lib --features dep-cooldown                                # full suite, 0 failed
$ cargo test --test architecture                                          # 56 passed, 0 failed
$ cargo test --test api                                                   # full suite, 0 failed
$ scripts/gate.sh                                                         # 17/17 executed checks PASS
```

## Pass 6 findings

Continuing the loop after Pass 5's PR merged: re-fetched `origin/main`,
recomputed the ledger's remaining `PARTIAL` rows fresh, and picked
**REQ-API-SCAN-007** — `GET /api/v1/scans/{id}/entities`'s pagination
boundary validation.

The pre-existing `scan_entities_pagination_works` test (1/1 passing)
thoroughly covers every VALID offset/limit combination — default, custom
limit, a middle page, an out-of-range page, and the 10000 cap — but the
handler's three `bad_request` branches (non-numeric offset, non-numeric
limit, `limit=0`) had never been driven through the real HTTP handler;
they were read-only-verified in Pass 3 and left that way. A regression
that silently defaulted an invalid `offset`/`limit` to `0`, instead of
rejecting it, would have shipped undetected.

Fixed with one new test, `scan_entities_pagination_rejects_invalid_offset_and_limit`
(`tests/api.rs`), which drives 5 invalid-input cases through the real
handler in one loop (`limit=0`, `limit=abc`, `limit=-5`, `offset=abc`,
`offset=-1`) and asserts 400 for each. No production code changed — same
pure-coverage pattern as REQ-CORRELATOR-001 (Pass 4) and REQ-API-MISC-003
(Pass 5).

### Verification commands run (Pass 6, in order)

```
$ cargo test --test api scan_entities_pagination                          # 2 passed (1 pre-existing + 1 new)
$ cargo fmt --all
$ cargo clippy --all-targets --features dep-cooldown -- -D warnings       # clean
$ cargo test --lib --features dep-cooldown                                # full suite, 0 failed
$ cargo test --test architecture                                          # 56 passed, 0 failed
$ cargo test --test api                                                   # full suite, 0 failed
$ scripts/gate.sh                                                         # 17/17 executed checks PASS
```

## Pass 7 findings

Continuing the loop after Pass 6's PR merged: re-fetched `origin/main`,
surveyed the ledger's remaining 17 `PARTIAL` + 14 `IMPLEMENTED_UNVERIFIED`
rows fresh, and picked **REQ-API-SCAN-002** — real in-flight scan
cancellation through the actual HTTP `scan_cancel` handler. This is the
single most consequential remaining gap surveyed: a broken "stop this
scan" path is a real safety/usability defect (an operator scanning a
sensitive subject needs a working abort), not just a documentation or
edge-case gap.

The row's prior evidence was accurate but incomplete: `scan_cancel_not_found`
covers the 404 branch, and `wall_time_budget_stops_promptly_and_preserves_
findings` (`tests/halting.rs`) proves the DOWNSTREAM engine mechanism (a
deadline expiring → `ScanStatus::Aborted`, findings preserved) — but that
test drives `engine.run(...)` directly, bypassing HTTP entirely. Nothing
had ever proven that hitting `POST /api/v1/scans/{id}/cancel` on a
genuinely in-flight scan actually reaches the SAME `CancelHandle` the
running scan holds and that the engine then finalizes and persists
`"aborted"`, visible on a subsequent `GET`.

Closing this properly required a scan that stays in-flight long enough to
cancel mid-flight — the existing shared test harness
(`tests/common/mod.rs`, used by `tests/api.rs`/`tests/halting.rs`/
`tests/smoke.rs`) only builds its `AppState`/router with a fixed,
near-instant `SyntheticModule`, with no way to inject a different module
for one test. Rather than duplicate ~40 lines of `AppState` construction
locally in `tests/api.rs` (the module-list argument is threaded through
one small refactor, not copied), `test_app_with_store_and_state` was
split into a new parameterized `test_app_with_modules_and_state(modules,
suffix)` with the existing function now a thin default-module wrapper
around it, plus a new `pub fn test_app_with_modules(modules, suffix)` —
preserving every one of the ~100 existing call sites across all three test
crates unchanged (confirmed: `cargo test --test halting`/`--test smoke`
both still fully pass). Added `CancelCooperativeProbe` (`tests/common/
mod.rs`), a module that blocks in `process()`, cooperatively polling
`ctx.cancel.is_cancelled()` every ~100ms for up to 60s — mirroring
`tests/halting.rs`'s own `SlowModule` exactly, the established pattern for
"a module a test can genuinely interrupt mid-flight."

New test `scan_cancel_stops_a_real_in_flight_scan_and_status_becomes_aborted`
(`tests/api.rs`): builds a router with the probe module, `POST /scans`
(202, genuinely in-flight — `spawn_scan` registers the real `CancelHandle`
into `s.cancellations` synchronously before the response returns, so
there's no race to seed), `POST /scans/{id}/cancel` (200,
`"status":"cancelling"`), then polls `GET /scans/{id}` until
`"status":"aborted"`. One mistake was caught and fixed before the test
passed: the first attempt used `cancel-target@example.org` as the seed
value, which `Target::validate`'s `is_placeholder_domain` check rejects
(any label literally `"example"` is a reserved/placeholder domain per RFC
2606) — switched to `contoso.com`, matching the domain the pre-existing
`scan_create_accepts_valid_request` test already uses safely. Ran the new
test 5 times consecutively for stability (all green, ~0.12s each — the
cancellation resolves in roughly one poll cycle in practice, well inside
the 5s budget the assertion loop allows).

### Verification commands run (Pass 7, in order)

```
$ cargo check --test api --test halting --test smoke --features dep-cooldown  # harness refactor compiles clean everywhere
$ cargo test --test api scan_cancel -- --nocapture                        # 2 passed (1 pre-existing + 1 new)
$ for i in 1 2 3 4 5; do cargo test --test api scan_cancel_stops; done    # 5/5 green, ~0.12s each
$ cargo test --test api                                                   # 126 passed, 0 failed
$ cargo test --test halting                                               # 5 passed, 0 failed
$ cargo test --test smoke                                                 # 57 passed, 0 failed
$ cargo fmt --all
$ cargo clippy --all-targets --features dep-cooldown -- -D warnings       # clean
$ cargo test --lib --features dep-cooldown                                # full suite, 0 failed
$ cargo test --test architecture                                          # 56 passed, 0 failed
$ scripts/gate.sh                                                         # 17/17 executed checks PASS
```

## Pass 8 findings

Unlike Passes 4-7, this pass was **not** self-directed from the backlog —
it was triggered by a direct request to critically assess this repo's
readiness for immediate installation on a real, no-root Termux Android
aarch64 device. A dedicated read-only investigation (root assumptions,
Termux package-manager usage, the aarch64 prebuilt-binary path, the
on-device source-build fallback, CI's actual aarch64 validation, existing
`tests/install_invariants.rs` coverage, the TLS/libc dependency graph, and
whether any of Passes 4-7's merged changes touched install-relevant code)
found **no installation blocker**, and two genuine, fixable gaps:

1. **REQ-INSTALL-001** (`IMPLEMENTED_UNVERIFIED` → `VERIFIED`) — the
   Play-Store-Termux detection (`install.sh:204-216`, which rejects the
   abandoned-since-2020 Play Store build with a `die` and an F-Droid
   remediation link) had **zero** automated coverage — confirmed by
   grepping `tests/` and `src/` for `termux-build-info`/`playstore` and
   finding no hits outside `install.sh` itself. Fixed with a new guard,
   `play_store_termux_is_detected_and_rejected_before_any_package_work`
   (`tests/install_invariants.rs`), which checks the read sits inside the
   `IS_TERMUX` branch, the marker match is case-insensitive, the failure
   is fatal (not a warning), and the message names the actual fix.
   Mutation-tested before shipping: flipping `grep -qi` to `grep -q`
   reproducibly failed the new test, then was reverted (confirmed via
   `git diff` showing zero net change to `install.sh`).
2. **REQ-INSTALL-010** (new, `IMPLEMENTED_UNVERIFIED`) — CI's
   `aarch64-android` job (`.github/workflows/ci.yml`) built and
   test-compiled only `--bin hse` for the `aarch64-linux-android` target,
   but `install.sh:910`'s on-device source-build fallback runs a bare
   `cargo build` with no `--bin` filter, which compiles **all 4** default
   bins (`hse`, `hse-ai-daemon`, `gen-oui`, `architecture-audit` — every
   `[[bin]]` in `Cargo.toml` with no `required-features` gate; only
   `dep-cooldown` is gated and correctly excluded from both). A change
   that broke `hse-ai-daemon`/`gen-oui`/`architecture-audit`'s
   cross-compile for Termux's exact target triple would have merged clean
   and only surfaced as a real device's on-device build failing partway
   through. Widened the CI job's build and `--no-run` test-compile steps
   to all 4 bins. Sanity-built the 3 newly-added bins natively (x86_64) —
   clean — but that is not proof of the aarch64 cross-compile itself: this
   sandbox has no Android NDK (confirmed via `scripts/gate.sh`'s own
   "SKIPPED (no Android NDK)" line every prior pass), so the real
   verification is this PR's own CI run, which is what this row is
   pending on, per the ledger's own "claim ≠ evidence" rule.

Explicitly **not found** to be a blocker, with evidence: exactly one
`sudo` in the entire 1838-line `install.sh`, structurally unreachable from
the Termux branch (an `elif`, never falls through); every filesystem write
confirmed inside `$PREFIX`/`$HOME`; the TLS stack is rustls with zero
OpenSSL in `Cargo.lock`; no `crt-static`/`target-cpu=native`/glibc
assumptions; the Android JNI path is deliberately compiled out
(`hickory-resolver` with `default-features = false`) with DNS resolvers
hardcoded rather than read from Android's nonexistent `/etc/resolv.conf`;
the prebuilt-binary validator genuinely executes the downloaded binary
(not just a checksum) before trusting it; and a real self-healing probe
exists for Termux's documented broken-`rust`-package issue. What remains
inherently unverifiable from this sandbox: anything requiring execution on
physical Termux/Android hardware — this pass's evidence is static/
code-level analysis, existing and new automated tests, and CI's
compile-and-link (not runtime) proof for the aarch64 target.

### Verification commands run (Pass 8, in order)

```
$ bash -n install.sh                                                      # syntax clean
$ shellcheck --severity=warning install.sh                                # clean
$ python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"  # YAML valid
$ cargo build --locked --bin hse-ai-daemon --bin gen-oui --bin architecture-audit  # native x86_64 sanity build, clean
$ cargo test --test install_invariants -- --nocapture                     # 6 passed (5 pre-existing + 1 new)
$ # mutation check: grep -qi -> grep -q in install.sh, re-ran the new test -> FAILED as expected, then reverted
$ git diff --stat install.sh                                              # empty — mutation fully reverted
$ cargo fmt --all
$ cargo clippy --all-targets --features dep-cooldown -- -D warnings       # clean
$ cargo test --lib --features dep-cooldown                                # full suite, 0 failed
$ cargo test --test architecture                                         # 56 passed, 0 failed
$ scripts/gate.sh                                                         # 17/17 executed checks PASS
```

### Verification commands run (Pass 9, in order)

```
$ cargo build --locked                                                    # clean, full workspace build
$ cargo test --test api dossier_upload -- --nocapture                     # 7 passed (6 pre-existing + 1 new)
$ # mutation check: reverted DefaultBodyLimit to MAX_UPLOAD_BYTES (no headroom),
$ # re-ran the new test alone -> FAILED as expected (413 != 400), then restored the fix
$ cargo test --test api dossier_upload_between_handler_cap -- --nocapture # re-confirmed passing after restore
$ cargo test --test api                                                   # 127 passed, 0 failed (was 126; +1 new)
$ cargo fmt --all                                                         # no additional diff
$ cargo clippy --all-targets --features dep-cooldown -- -D warnings       # clean
$ cargo test --lib --features dep-cooldown                                # 6852 passed, 0 failed, 22 ignored
$ cargo test --test architecture                                          # 56 passed, 0 failed
```

## Pass 10 findings

Triggered by the same "requirements reconstruction and traceability"
directive mirroring this ledger's own established loop verbatim — re-sync
with `main`, reconcile the ledger against current reality without trusting
prior commentary, resolve the highest-value actionable gap, verify through
the real supported path, update the ledger, repeat. A dedicated
investigation reconciled the ledger against the two PRs merged since Pass 8
(#575, itself Pass 8; #576, "Architecture invariants: fix 5 real boundary
leaks") and swept fresh for gaps not yet in the ledger at all. **Pass 9**
(PR #577, "Confirm reasoning-effort fix for failing 'copilot' job") landed
on `main` while this pass was still in flight — a genuine, independent fix
for REQ-API-SCAN-006 (see its row above) — so this pass rebased onto it and
renumbered from its original working label of "Pass 9" to Pass 10, to avoid
colliding with that already-merged, correctly-numbered one.

**Drift found from PR #576** (real): REQ-CORE-008's cited test names/methods
were renamed (`termux_timeout_ms`→`constrained_timeout_ms` etc.) — citations
updated in place, status unchanged (VERIFIED, behavior confirmed unchanged by
PR #576's own zero-diff verification, re-confirmed by re-running the 3 tests
under their new names this pass).

**Two pre-existing evidence gaps found and closed** (search misses from
before Pass 1, not drift from #575/#576): REQ-CLI-001 and REQ-CLI-007 were
both marked `PARTIAL` citing "no test found," when in fact both already had
dedicated coverage under different file locations/names than the original
search checked (`src/lib_tests.rs`'s `architecture_constants_are_correct` for
REQ-CLI-001's `MAX_BLOCKING_THREADS`; `src/cli/tests.rs`'s 5
`resolve_seed_*` tests for REQ-CLI-007). Both flipped to `VERIFIED` after
personally re-running the tests this pass. REQ-ENV-005's evidence was
strengthened similarly (3 newly-found `default_seed_*` tests one layer below
`resolve_seed`) but deliberately left `PARTIAL` — a thin, genuinely-untested
one-line env-read wrapper remains, the same class of gap the ledger already
tolerates for REQ-ENV-006.

**New gap found and fixed — REQ-STORAGE-001** (top-priority pick, see
Section 9 above for the full writeup): `Store::integrity_check()`, the
mitigation `hse doctor` and the debug-bundle export both trust for
FTA finding E5.1 / top event T5, had never been tested against real
corruption — only the healthy-DB path was covered. Building the corruption
test surfaced a second, related, genuinely fixed bug along the way:
`hse doctor`'s handling of the pragma itself erroring (as opposed to running
and reporting problem rows) did not set the `critical` exit-code flag,
undertreating a severe corruption signal as merely informational. Both are
fixed and regression-tested this pass. A Copilot review on this pass's own
PR caught a real robustness gap in the new test itself: its corruption
predicate matched only "corrupt"/"malformed" Display-text substrings, which
SQLite doesn't guarantee across versions/platforms — fixed to match the
underlying `rusqlite::ErrorCode` (`DatabaseCorrupt`/`NotADatabase`/
`SystemIoFailure`) instead, keeping substring matching only as a fallback.

**New gaps found, not yet actioned** (ranked below REQ-STORAGE-001, left for
a future pass): `ScanOptions::max_roi`'s adaptive-depth-termination lever has
zero test coverage above the pure-function level (its convergence-pruning and
top-K/knee-gate sibling levers have at least one test each one layer closer
to real dispatch) — the natural next pick, same size/shape as this pass's.
`src/bin/hse_ai_daemon/main.rs` still has zero test coverage of any kind
(confirmed unchanged since Pass 4). The 6 web/JS UI workflow claims Pass 4
catalogued remain untested — confirmed this pass that **no JS test framework
exists in the repo at all** (no `package.json`/test runner), while correcting
an assumption nearly made: the `wasm-ui` Rust companion crate *is* tested in
CI, just not the interactive JS logic driving it. The evergreen-docs
drift-check backlog (33 files under `docs/`) remains fully untouched.

### Verification commands run (Pass 10, in order)

```
$ cargo test --lib --features dep-cooldown -- architecture_constants_are_correct resolve_seed default_seed core::engine::timeout::tests
                                                                            # 12/12 passed (personal re-verification of the investigation's own claims)
$ cargo test --lib --features dep-cooldown -- integrity_check              # 2/2 passed (new corruption test + pre-existing healthy-path test)
$ cargo test --lib --features dep-cooldown -- storage::tests app::doctor::tests
                                                                            # 108/108, 14/14 passed
$ cargo fmt --all
$ cargo clippy --all-targets --features dep-cooldown -- -D warnings        # clean
$ cargo test --test architecture                                          # 56 passed, 0 failed
$ scripts/gate.sh                                                         # 17/17 executed checks PASS
$ # Copilot review fix: reworked the corruption predicate onto rusqlite::ErrorCode
$ cargo test --lib storage::tests::integrity_check_reports_problems_on_a_corrupted_db
                                                                            # still passes after the rework
$ cargo clippy --lib --features dep-cooldown -- -D warnings               # clean
```

## Pass 11 findings

Picked the top item from Pass 10's own "new gaps found, not yet actioned"
list: `ScanOptions::max_roi`'s adaptive-depth-termination lever
(`crate::core::roi::should_terminate_adaptive`) had zero coverage above the
pure-function level. While scoping the fix, re-read the whole `src/core/roi/`
module (only 3 pure functions plus their dispatch call sites) and found the
ledger had never represented it at all — not even the saturation-pruning
lever, despite that one having gained real dispatch-level coverage back in
the architecture-invariants Phase 2 work (PR #578,
`max_roi_excludes_saturated_entity_from_real_dispatch`) without ever being
folded into this ledger. Opened a new Section 10 for all three levers rather
than a single bare row, so the whole module is now tracked consistently:

- **REQ-ROI-001** (saturation-pruning): already `VERIFIED` by pre-existing
  coverage — no code or test change this pass, only citing what PR #578
  already proved.
- **REQ-ROI-002** (top-K/knee candidate cutoff): `IMPLEMENTED_UNVERIFIED`.
  `apply_roi_cutoff` has a real, dedicated test
  (`roi_cutoff_releases_visited_keys_of_truncated_candidates`) proving its
  own correctness including the `visited`-release side effect, but that
  test drives the function directly with a synthetic candidate vec, not
  through a real `engine.run()` dispatch with an actual over-budget round —
  left as the next natural pick for a future pass, not fixed this pass to
  keep this one's scope matched to the single lever it set out to close.
- **REQ-ROI-003** (adaptive-depth termination, the actual target): fixed.
  Added `max_roi_adaptive_depth_stops_a_real_dispatch_round_on_low_marginal_yield`,
  a 3-round real-dispatch test through `ScanEngine::run()` — see the row
  above for the full design and its mutation-testing result. The mutation
  test surfaced a genuinely useful fact along the way: with the termination
  check disabled, the entity-absence assertions alone still passed, because
  the *independent* saturation-pruning lever (REQ-ROI-001) also blocked the
  would-be round 3 once the shared test entity accumulated enough
  corroborating sources — proof that an entity-outcome-only assertion would
  have been an insufficiently discriminating test for this specific lever,
  and that the added `ExpansionStop`-event assertion was the one actually
  pinning down *which* mechanism fired.

### Verification commands run (Pass 11, in order)

```
$ cargo test --lib core::engine::tests::max_roi_adaptive_depth_stops_a_real_dispatch_round_on_low_marginal_yield --features dep-cooldown
                                                                            # 1/1 passed; repeated 5x, no flakiness
$ # mutation check: short-circuited should_terminate_adaptive's call site to `if false && ...`,
$ # re-ran the same test alone -> FAILED on the ExpansionStop-event assertion specifically
$ # (the two entity-presence assertions still passed - see the finding above), then reverted
$ git diff --stat src/core/engine/mod.rs                                  # empty - mutation fully reverted
$ cargo test --lib core::engine::tests::max_roi_adaptive_depth_stops_a_real_dispatch_round_on_low_marginal_yield --features dep-cooldown
                                                                            # 1/1 passed after revert
$ cargo test --lib core::roi::tests --features dep-cooldown               # 7/7 passed
$ cargo test --lib core::engine::tests::roi_cutoff_releases_visited_keys_of_truncated_candidates --features dep-cooldown
                                                                            # passed
$ cargo fmt --all
$ cargo clippy --all-targets --features dep-cooldown -- -D warnings       # clean
$ cargo test --lib --features dep-cooldown                                # full suite, 0 failed
$ cargo test --test architecture                                         # 56 passed, 0 failed
$ scripts/gate.sh                                                        # 17/17 executed checks PASS
```

## Pass 12 findings

Directive-driven (not backlog-derived): "unify provider capability +
economics metadata," recognized as the natural prerequisite for a second,
larger directive ("extend ROI to reason about novelty/independence/cost/
reliability/..." — deferred to a future pass, since a `DispatchUtility`
model's cost/reliability/uniqueness/optionality inputs should be *read
from* this descriptor, not invented independently). Two 6-agent research
workflows first grounded the design in the real codebase before any code
was written — one surveying existing `Module` trait metadata, cost/quota
infrastructure, and every candidate reuse point (`crate::core::convex::
module_cascade` for `optionality_prior`, `cache_ttl_secs()` for
`cache_policy`, the shared circuit-breaker for `rate_limit_policy`,
`is_high_value_only()`/`requires_geo_corroboration()` for escalation-band
derivation), the other identifying which of the 188 modules' real,
provider-supplied operational details diverge from what a generic
derivation alone would produce (the 6 modules that ended up with explicit
overrides — see REQ-PROVIDER-002).

Added `src/core/module/provider.rs`: the `ProviderDescriptor` struct and
its 8 supporting enums (`AccessClass`, `EscalationBand`, `CostModel`,
`RecursiveUsePolicy`, `CachePolicy`, `RateLimitPolicy`, `LicensingPolicy`,
`HistoricalDepthClass`), a generic `derive_default<M: Module + ?Sized>`
derivation function (generic rather than `&dyn Module` specifically so it
can be called from the `Module` trait's own default `provider_descriptor()`
method without an `E0277` `Self: Sized` conflict that would otherwise break
every existing `dyn Module` call site), and the `unknown_cost_paid_provider_
blocked` eligibility gate. Wired a `pub provider: ProviderDescriptor` field
onto `ModuleInfo` and a `provider_descriptor()` default trait method
delegating to `derive_default`. Added two `ScanOptions` fields
(`max_cost_usd: Option<f64>`, `allow_unknown_cost_dispatch: bool`, both
default-off/no-op) and wired the eligibility gate into `module_skip_reason`
as a hard gate checked before any ranking, per the directive's own
ordering requirement. Fixed the REQ-PROVIDER-005 API/CLI field-drift bug
found while wiring the API's `modules_list` handler to read the same
`ModuleInfo` the engine builds instead of hand-rolling its own JSON.

`#![forbid(unsafe_code)]` (crate-wide, `src/lib.rs:39`, cannot be locally
overridden even in `#[cfg(test)]` code) ruled out testing `env_cost_per_
request` via `env::set_var`/`remove_var` — both are `unsafe fn` in current
Rust. Resolved by splitting the function into a thin env-reading wrapper
plus a separately-testable pure `parse_cost_per_request(&str) -> Option<f64>`,
tested directly with string literals instead of environment mutation.

**A real layering violation, caught by the full verification battery before
push.** The first draft of REQ-PROVIDER-001/002's two registry-wide
completeness tests lived in `src/core/module/provider_tests.rs` (alongside
the pure-function tests), each calling `crate::modules::registry()` to walk
all 188 real modules. That broke the pre-existing `core_does_not_import_
modules` architecture invariant (`tests/architecture.rs`) — `src/core/`
must stay module-agnostic; the application layer (`src/modules/`) depends
on `core`, never the reverse. Fixed by moving both tests to
`tests/architecture_parts/architecture_part7.rs` (an integration test,
outside `src/core/`, where `crate::modules::registry()` is the established
pattern for exactly this kind of registry-wide guard), and replacing
`provider_tests.rs`'s registry-derived `sample_module()` with a local
`StubModule` — matching how `src/core/engine/tests.rs` already tests
dispatch-level behavior without touching the real registry.

**A second real gap, also caught by the full verification battery, not by
any earlier narrow test run**: `scripts/gate.sh`'s doc-coverage ratchet
(`scripts/doc_coverage.sh`, `missing_docs` lint count capped at 1028) failed
at 1036 — 8 new undocumented public items. All 8 were struct fields on the
new `ProviderDescriptor` (`access_class`, `escalation_band`,
`recursive_use_policy`, `cache_policy`, `rate_limit_policy`,
`licensing_policy`, `cost_model`, `historical_depth_class`) that had been
left without their own doc comment while the struct's other fields and its
container doc comment were written — confirmed by re-measuring the
`missing_docs` count against a clean `origin/main` checkout (`git stash`)
first: exactly 1028, matching the ratchet's baseline, so this was
genuinely new debt, not a stale baseline (the documented failure mode this
same script's own history describes). Added a one-line doc comment to each
of the 8 fields; re-ran `scripts/doc_coverage.sh` — held at 1028.

### Verification commands run (Pass 12, in order)

```
$ cargo test --lib core::module::provider --features dep-cooldown         # 3/3 passed
$ cargo test --test architecture -- provider_descriptor                  # 2/2 passed
$ cargo test --test architecture core_does_not_import_modules             # 1/1 passed (confirms the fix)
$ cargo test --test api modules_list_returns_array --features dep-cooldown -- --nocapture
                                                                            # 1/1 passed
$ cargo test --lib core::engine::tests::unknown_cost_paid_provider_is_blocked_by_an_active_cost_budget --features dep-cooldown
                                                                            # 1/1 passed
$ cargo fmt --all
$ cargo clippy --all-targets --features dep-cooldown -- -D warnings       # clean
$ cargo test --lib --features dep-cooldown                                # 6861 passed, 0 failed
$ cargo test --test api                                                   # 127 passed, 0 failed
$ cargo test --test architecture                                         # 58 passed, 0 failed
$ scripts/doc_coverage.sh                                                # held at 1028 (after the 8-field doc fix)
$ scripts/gate.sh                                                        # all executed checks PASS
```

## Pass 13 findings

Directive-driven, arriving in two parts: "extend the existing ROI subsystem
with a canonical `DispatchUtility`" (this pass), sequenced explicitly after
"unify provider capability + economics metadata" (Pass 12, PR #581,
merged first) — a deliberate ordering decision, since `DispatchUtility`'s
cost/reliability/optionality/uniqueness cold-start priors read directly
from the now-merged `ProviderDescriptor` rather than inventing a parallel
set.

A 6-agent parallel research workflow first re-grounded the exact current
source before any code was written, each agent mapping one facet against
real files/line numbers (not memory or the earlier design conversation):
the three existing ROI levers' exact functions/constants/call sites; the
per-round candidate-weight computation (`src/core/engine/expansion.rs`/
`mod.rs`) and its relationship to `crate::core::convex::module_cascade`;
the cost/quota infrastructure (the just-merged `ProviderDescriptor`,
`ScanOptions::max_cost_usd`, `module_skip_reason`'s exact gate chain, and
each quota-tracked provider's real `budget_snapshot()`-style function);
reliability/latency signals (`DispatchLog`, the quarantine chain,
`Module::max_timeout_ms`/`constrained_timeout_ms`, the circuit breaker);
novelty/independence/duplication signals (`Entity::corroborating_sources`/
`source_count`, the `DispatchLog` dedup key, `Module::produces()`); and an
exhaustive enumeration of every existing test this change must not break. A
7th, high-effort design-synthesis agent then produced a complete,
citation-grounded implementation plan from those findings.

Implementing the plan surfaced one real structural fact the design's own
research had flagged as a risk: the per-round `weight: f64` the original
plan wanted to seed `expected_information_value` from is computed in
`src/core/engine/mod.rs`'s round loop and is **not** threaded into
`DispatchCx`/`dispatch.rs`'s per-module scope, where the rest of
`DispatchUtility`'s inputs (provider descriptor, quota, timeout, dedup
state) are naturally available. Rather than widen the change to thread a
new field through `DispatchCx` and every test/call site that constructs
one (a materially larger, riskier change), this pass grounds
`expected_information_value` in the target entity's own `c_effective()`
instead (`1.0 - confidence`, so a wholly unconfirmed candidate scores
maximally valuable) — a real, distinct signal already available at the
exact call site, not an invented one. This is documented explicitly, in
both `src/core/roi/utility.rs`'s module doc and section 12's ledger row, as
a deliberate v1 narrowing with a named follow-up, not a silent
simplification.

A second real finding, made while wiring the eligibility gate: the
directive's "provider reliability, live when available" requirement turns
out to already be fully satisfied by existing infrastructure in a way that
made a naive implementation redundant. `module_skip_reason`'s existing
`circuit::is_open` check already hard-gates a circuit-open module before
ranking — so any candidate that reaches `compute_dispatch_utility` at all
is, by construction, circuit-closed. Passing `circuit_open` into
`DispatchUtilityInputs` as originally planned would therefore always be
`false` at the one call site that matters, a dead signal masquerading as a
live one. Dropped from the inputs entirely; `reliability` is driven purely
by `ProviderDescriptor::reliability_prior` (the cold-start case), with the
reasoning documented in the module doc so a future reader doesn't
reintroduce the redundant check.

Third: `wigle`'s real budget is five independent sub-budgets
(geo/BSSID/cell/Bluetooth/SSID — `WigleBudgets`), so `Module::
quota_remaining()` (the new trait default method backing the quota-exhaustion
gate) is deliberately left un-overridden for it rather than collapsing five
numbers into one bool that would misrepresent the real state either way —
documented in `src/modules/wigle/mod.rs` as an honest gap, following this
ledger's own established precedent (REQ-ROI-002) of leaving a genuine gap
visible rather than overclaiming completeness.

Wiring the new `EventKind::DispatchUtilityComputed` variant surfaced two
pre-existing compile-time exhaustiveness tripwires this codebase already
has for exactly this class of change — `event_type_str_matches_serde_tag_for_every_variant`
(`src/core/event/tests.rs`, an exhaustive match with no `_` arm) and
`embedded_spa_renders_every_event_kind` (`src/api/routes/tests.rs`, which
counts `EventKind` variants against a pinned list and checks the served SPA
JS has a render case for each). Both caught the new variant immediately
and were updated in the same pass, alongside the actual SPA `mapEvent` case
(`src/web/js/scan_info/log.js`) and the `hse live` CLI renderer
(`src/cli/live/mod.rs`) — both genuinely exhaustive matches, not
optional cosmetic additions.

### Verification commands run (Pass 13, in order)

```
$ cargo test --lib core::roi::utility --features dep-cooldown            # 8/8 passed
$ cargo test --lib core::event --features dep-cooldown                   # 19/19 passed
$ cargo test --lib -- api::routes::tests::embedded_spa_renders_every_event_kind
                                                                            # 1/1 passed
$ cargo test --lib core::engine::tests::eligibility_gates_fire_before_dispatch_utility_is_ever_computed --features dep-cooldown
$ cargo test --lib core::engine::tests::dispatch_utility_off_by_default_produces_zero_behavior_change --features dep-cooldown
$ cargo test --lib core::engine::tests::dispatch_utility_explanation_is_surfaced_on_a_real_dispatch --features dep-cooldown
$ cargo test --lib core::engine::tests::quota_exhausted_provider_is_blocked_at_real_dispatch --features dep-cooldown
                                                                            # all 4 passed
$ cargo test --lib --features dep-cooldown -- core::engine::tests::max_roi core::engine::tests::quarantined \
    core::engine::tests::unquarantined core::engine::tests::unknown_cost core::engine::tests::roi_cutoff \
    core::engine::tests::convex_budget                                   # all pre-existing ROI/gate/ordering tests still pass unchanged
$ cargo test --features dep-cooldown --test smoke priority_waterfall     # pinned ordering test still passes unchanged
$ cargo fmt --all
$ cargo clippy --all-targets --features dep-cooldown -- -D warnings      # clean
$ cargo test --lib --features dep-cooldown                               # full suite, 0 failed
$ cargo test --test api                                                  # 0 failed
$ cargo test --test architecture                                        # 0 failed
$ scripts/doc_coverage.sh
$ scripts/gate.sh
```

## 13. Test-harness isolation and test integrity (`src/util/paths.rs`, `tests/common/`, the architecture tripwires)

| ID | Behavior | Inputs | Outputs | Side effects | Failure behavior | Implementation location | Tests covering it | Runtime verification evidence | Status |
|---|---|---|---|---|---|---|---|---|---|
| REQ-TEST-001 (**new, Pass 14**) | No test — unit or integration — writes into the developer's real `~/.huntsman`. Unit tests use the library's `cfg(test)` switch; integration crates (where `cfg!(test)` is `false` in the linked library) go through `paths::isolate_for_tests()`, a `OnceLock` base-dir override (no `unsafe` env mutation — the crate is `#![forbid(unsafe_code)]`) called by every `tests/common` harness constructor via `tmp_db`/`tmp_dir`; `cli_seed_validation`'s spawned binary gets `HOME` set like its sibling helpers. The override only moves the base path, so `huntsman_dir`'s `0700` creation and the single-base derivation of `data_file`/`subdir` are untouched, and production code never calls it. | n/a | per-process `huntsman-test-home-<pid>/.huntsman` under the OS temp dir | temp dir only | n/a | `src/util/paths.rs` (`isolate_for_tests`), `tests/common/mod.rs` (`isolate_home`), `tests/cli_seed_validation.rs` (`run`) | `production_code_never_redirects_the_data_dir` (`tests/architecture_parts/architecture_part3.rs`) | Baseline artefact observed in this environment after `cargo test --test api`: the real `~/.huntsman/module_stats.json` held 102 synthetic `seed` scans (the input to `hse scan --adaptive`) and `settings.json` had been overwritten with `{"feature.depth_decay": false}` by `settings_toggles_put_succeeds_and_persists_the_flip`. With the real directory moved aside, `cargo test --test api --test smoke --test cli_seed_validation` (129/58/9 pass) no longer recreates it; the smoke key-chaining fixture's fake `shodan` key now lands in `/tmp/huntsman-test-home-<pid>/.huntsman/key_pool.json`. | VERIFIED |

| REQ-TEST-002 (**new, Pass 14**) | The architecture lint `modules_do_not_collapse_a_non_2xx_into_an_empty_result` scans BOTH guard shapes — the inline `if !resp.status().is_success()` and the bound-variable `let status = resp.status(); if !status.is_success()` — with a vacuity floor just below the in-tree count. | n/a | n/a | none | fails the gate if any guarded block `return Ok(`s, or if fewer than 35 guards are found | `tests/architecture_parts/architecture_part7.rs` | itself | The trigger was `status().is_success()` only; 17 in-tree guards use the bound-variable form and were never scanned (a collapse written that way shipped green). Widened trigger scans 39 guards (measured with a probe, then removed); floor raised 20 → 35; all 39 comply. `cargo test --test architecture modules_do_not_collapse` passes. | VERIFIED |
| REQ-TEST-003 (**new, Pass 14**) | `non_huntsman_env_reads_are_known` sees every shape a non-`HUNTSMAN_` knob is read through — direct `env::var("…")`, the typed wrappers `env_i64`/`resolve_env_u64`, a typed constant (`const X: &str = "HSE_…"`) read by identifier, and clap `env = "HSE_…"` attributes — and `KNOWN_HSE_KNOBS` lists every one with its consumer; the anti-rot check still fails on a listed knob nothing reads. | n/a | n/a | none | fails the gate on an unlisted read or a stale entry | `tests/architecture_parts/architecture_part3.rs`; `src/core/module/provider.rs` (`PROVIDER_COST_ENV_PREFIX`, so the `HSE_PROVIDER_COST_<ID>` family is a visible constant, not an inline `format!` literal) | itself | Four live operator knobs — `HSE_SQLITE_CACHE_KB`, `HSE_SQLITE_MMAP` (storage `env_i64`), `HSE_RESOURCE_PROFILE` (typed const), `HSE_PROVIDER_COST_*` (`format!`) — were invisible to the scanner and absent from the list; `HSE_BIND`/`HSE_AUTH_TOKEN` (clap) were documented as deliberately unlisted. All six are now collected and listed; the test passes in both directions (no unknown, no stale). | VERIFIED |
| REQ-TEST-004 (**new, Pass 14**) | Every `install.sh` heredoc whose body touches the shared Termux wake-lock (`hse_wakelock_*` / `termux-wake-*`) is in `WAKE_LOCK_WRAPPERS` (and, if long-running, `WAKE_LOCK_MANAGERS`), so a new generated program cannot ship outside the no-raw-unlock / registered-acquire / actively-manages guards. | n/a | n/a | none | fails the gate naming the unguarded heredoc | `tests/install_invariants.rs` (`every_wake_lock_touching_heredoc_is_guarded`; `AIW` added to both lists and to the hardcoded-prefix list) | itself | The `hse-ai` wrapper (`<<'AIW'`, `install.sh:1732`, which acquires the refcounted lock) post-dated the hand-maintained lists and sat outside every guard; its body is compliant, so the green was luck. Now guarded and derived; `cargo test --test install_invariants` — 7/7. | VERIFIED |
| REQ-TEST-005 (**new, Pass 14**) | No production code under `src/ai/` (test modules stripped) constructs an entity, evidence record, relation or correlation or writes one to the store — an Ollama model may summarise a scan (`scan_analysis`) but never add to the evidentiary graph (RULE 1). The crate-level AI guard states exactly what it enforces (no third-party inference/vector crates in the runtime graph) and names this lock as the complement, instead of claiming "no AI/LLM dependency at runtime; AI is a development-time accelerator only" while `src/ai/ollama.rs` is a runtime LLM client. | n/a | n/a | none | fails the gate naming the offending `src/ai` line | `tests/architecture_parts/architecture_part4.rs` (`llm_output_never_becomes_a_finding`; `runtime_carries_no_ai_ml_inference_dependency` doc + failure text corrected) | itself | `cargo test --test architecture -- runtime_carries_no_ai llm_output_never` — both pass; `src/ai` production code's only store write is `upsert_scan_analysis`. | VERIFIED |
| REQ-TEST-006 (**new, Pass 14**) | `pool_keys_fill_empty_env_slots` asserts the mechanism its name promises — `merge_pool_into_env` fills an empty `HUNTSMAN_SHODAN_KEY` slot from the pool and never overwrites an operator-configured value — over a fresh local `KeyPool`, never the process-global pool. | n/a | n/a | none | n/a | `src/util/keys/tests.rs` | itself | The test injected a fake Active `shodan` key into `global_pool()` and then asserted nothing (`let _ = map;`) — it could not fail if `merge_pool_into_env` were deleted, and every other test consulting `next_key("shodan")` saw a phantom key depending on scheduling order. `cargo test --lib util::keys::tests::pool_keys` passes. | VERIFIED |
| REQ-TEST-007 (**new, Pass 14**) | `scripts/gate.sh` runs the wasm-ui drift check only with the exact binaryen build that produced the committed `pkg/` (`WASM_OPT_PIN` in `scripts/wasm_ui_drift_check.sh`, the single place the pin lives) and skips with the reason otherwise; the script itself refuses to run under any other build, so no environment — CI included — can silently produce a false DRIFT or a false pass with a different `wasm-opt`. | n/a | n/a | none | gate: skip with reason; script: exit 1 naming the installed build | `scripts/wasm_ui_drift_check.sh`, `scripts/gate.sh` | the check itself (`bash -n`; run under binaryen 108 locally and in CI) | `gate.sh`'s header promised exact-version gating but only tested `command -v wasm-opt`, so a developer with any other binaryen got a false DRIFT failure. The pin is read from the drift script (`ci.yml` installs the same sha256-pinned tarball). | VERIFIED |

---

## 14. Provider API contracts re-verified against the authoritative spec

| ID | Behavior | Runtime verification evidence | Status |
|---|---|---|---|
| REQ-PROVIDER-006 (**new, Pass 14**) | WiGLE: each observation corpus is queried on its own documented endpoint — `/api/v2/network/search` (WiFi), `/api/v2/cell/search`, `/api/v2/bluetooth/search` — with only parameters the Swagger lists for it (`latrange1/2`, `longrange1/2`, `resultsPerPage`; `ssid` on the WiFi SSID search). The BSSID detail path sends the documented `type=WIFI` to `network/detail` and uses `/api/v2/bluetooth/detail` for Bluetooth; it no longer probes a non-existent address-keyed cell lookup, so one dispatch is billed the two requests it makes. | Authoritative source retrieved and parsed 2026-09-03: `https://api.wigle.net/swagger.json` (Swagger 2.0, "WiGLE API"). `/api/v2/network/search` lists **no** `type` parameter — RULE.md's own cautionary case was still live in `src/modules/wigle/fetch.rs` (`&type={kind}`): `?type=cell` / `?type=bluetooth` were ignored and WiFi rows were labelled as cell-carrier and Bluetooth-beacon intelligence. `cell/search` and `bluetooth/search` document the same bbox parameters, and their result objects carry every field the extractors read (`ssid`, `city`/`region`/`country`/`postalcode`; `netid` for Bluetooth). `bbox_search_hits_each_corpus_own_endpoint_with_documented_params_only` (`src/modules/wigle/tests.rs`) asserts every emitted query key is in the documented-on-all-three set and no `type=` is sent; `one_bssid_dispatch_is_billed_for_every_corpus_it_probes` now pins two probes; `util::wigle` tests pin `type=WIFI` and the Bluetooth detail URL. `cargo test --lib modules::wigle util::wigle modules::wifi_intel` — all pass. Not exercised live from this environment (no WiGLE credential): the documented contract is the authority (RULE 1), the live response shape is unconfirmed here. | IMPLEMENTED_UNVERIFIED |
| REQ-PROVIDER-007 (**new, Pass 14; corrected in Pass 15**) | OathNet: `init_session` reads the search-session id from the documented `POST /service/search/init` response at `data.session.id` — the live reference (`docs.oathnet.org/api-reference/search-session/initialize-a-search-session.md`, retrieved 2026-09-03: "The returned `session.id` should be passed as `search_id` to all subsequent service calls"; response `{ success, message, data: { session: { id, query, search_type, status, created_at, expires_at, duration_minutes }, user, services, summary } }`) — so the id threads into every subsequent breach/stealer query and the pair costs one lookup, not two. Only that path is accepted: a flat `search_id`, a top-level `session.id`, an empty or non-string id, a `success:false` envelope and non-JSON all yield `None`. | **Pass 14's version of this row was wrong, and so was its fix.** The shipped code read `/session/id` then `/data/session/id` — the second of which IS the documented path. Pass 14 trusted the in-repo `docs/OATHNET_API_GUIDE.txt` (a derived summary that showed `{ "search_id": "…" }` in three places) over the provider's own reference, switched the parse to a top-level `search_id` no documented response carries, and pinned the correct shape as *rejected* — a regression that would have disabled sessions against the real service, and a RULE.md precedence violation (a derived in-repo document outranked the authoritative spec). Caught by Pass 15's re-verification against the live reference, not by any test: the test encoded the same wrong premise. Corrected: `session_id_from_init_response` reads `/data/session/id` only; `session_init_response_is_parsed_in_its_documented_shape` (`src/util/oathnet/tests.rs`) decodes the reference's own example body and pins every other shape as `None`; the guide's three occurrences are corrected with the source and retrieval date cited. `cargo test --lib util::oathnet` passes. Live session engagement is still unexercised here (no OathNet credential). | IMPLEMENTED_UNVERIFIED |
| REQ-PROVIDER-008 (**new, Pass 15**) | SeekNow: a seed whose lookups were answered with a key rejection (`invalid_api_key` / `plan_required`, HTTP 401) is reported by `see_know::process` as `Err(Error::Module)` naming the cause and its remedy — never as `Ok(empty)`, the module's "searched and found nothing" answer. `util::see_know::key_rejection()` exposes the latched `KeyRejection` (`InvalidKey` / `PlanRequired`) whose one `guidance()` text backs both the once-per-scan warning and the per-seed error; a seed with real evidence keeps it (folded through `ModuleResult::or_hard_failure`); with no rejection latched the empty seed stays a clean negative. | Reproduced by reading the path: a 401 is an HTTP response, so curl exits 0, `parse_response` classifies the body as `Terminal::Auth`, latches `KEY_INVALID` and returns `Ok(Value::Null)`; every later endpoint call short-circuits on the latch to `Ok(vec![])`; nothing sets `hard_failure`, so `process` returned `Ok(empty)` for every seed of the scan and the one `warn!` at latch time was the only trace (the engine records, the UI shows and the export carries the per-seed result, not the log). `a_rejected_key_is_an_error_not_a_clean_negative` (`src/modules/see_know/tests.rs`) drives the real `process()` under each latched rejection with no I/O (quota probe claimed, every endpoint short-circuits) and asserts the module error names the cause, then drains the budget with no rejection latched and asserts the same seed is still `Ok(empty)`; fails on the baseline (`Ok` with 0 entities). `key_rejected_failure_is_none_without_a_rejection` covers the pure mapping. `hse doctor`'s "SeekNow account" section printed its own generic remedy for every rejection; `CreditsProbe::InvalidKey` now carries the `KeyRejection` the probe latched and the doctor prints its `guidance()`, so a `plan_required` key is told to fix its plan, not to swap the key — one remedy text across the warning, the module error and the doctor (`credits_probe_reports_the_rejection_it_latched`). | VERIFIED |
| REQ-PROVIDER-009 (**new, Pass 16**) | Numverify (`contact_enrich`, `apilayer.net/api/validate`): apilayer's shared HTTP-200 error envelope `{"success":false,"error":{"code","type","info"}}` (invalid/expired access_key, plan restriction, exhausted quota) is reported to the key pool and surfaced as an `Err` naming the provider's detail — never folded into "no phone metadata". `valid:false` (the API's ordinary "not a real number", no `success`/`error` field) stays a clean miss. | `NumverifyResp` modelled only the success fields, so the envelope decoded to all-`None` and `build_phone_entities`'s `valid != Some(true)` gate returned empty on every number, forever, with the pool never told (`note_keyed_error` only fires on a non-2xx status). `numverify_key_error_detail` is the pure classification (same in-body-200 rule `whoisxml`/`hunter_io` apply); `an_in_body_200_error_envelope_is_classified_as_a_key_error_with_its_detail` + two siblings (`src/modules/contact_enrich/tests.rs`) FAIL with the classifier stubbed to `None`. Live call unexercised (no key). | VERIFIED |
| REQ-PROVIDER-010 (**new, Pass 16**) | SEON (`email-api/v3`, `phone-api/v2`): the shared `{success:false, error:{code, message}, data:{}}` envelope is classified by its message — a key/quota message (`is_key_or_quota_message`: "Insufficient credits", "Invalid API key", "Unauthorized", …) is reported to the pool and surfaced as an `Err` with SEON's own code+message; any other `success:false` (a malformed request, per SEON's documented Fraud API v2 example) stays a clean miss. | `SeonEmailResp`/`SeonPhoneResp` had no `error` field and both lookups returned `Ok(empty)` for every `success != true`, so an out-of-credits or revoked key read as "no SEON findings" on every Email/Phone target, and a second pooled key never rotated in. Envelope shape verified against SEON's live reference (docs.seon.io/api-reference/errors — documented explicitly for Fraud API v2, and the email-api success example already carries the empty `error` object of the same envelope). `seon_key_error_detail` is pure; `a_dead_or_exhausted_key_envelope_is_classified_as_a_key_error` / `a_non_key_failure_or_a_success_body_is_not_a_key_error` (`src/modules/seon/tests.rs`) FAIL with the classifier stubbed. Live call unexercised (no key). | VERIFIED |
| REQ-PROVIDER-011 (**new, Pass 16**) | BuiltWith: the documented key-class errors (api.builtwith.com/errorCodes: `-2` "API Key is wrong", `-3` "You've run out of API Credits", `-5` "Plan upgrade needed"), which arrive on HTTP 200 in `Errors[]`, are reported to the key pool and surfaced as an `Err`; a per-lookup error (`-8` invalid domain, …) keeps the best-effort empty result. `BwError` now captures `Code` as well as `Message`, and `builtwith_key_error` matches code first, documented text second (the provider says the text "cannot be guaranteed"). | `process` logged `tracing::warn!` and returned `Ok(empty)` for any `Errors[]`, so a dead or credit-less key read as "no tech profile for this domain" and a second pooled key was never tried. `a_wrong_key_or_exhausted_credits_error_is_a_key_error_not_a_clean_miss` (`src/modules/builtwith/tests.rs`) covers code+message, message-only, code-only and the per-lookup negative; FAILS with the classifier stubbed. Live call unexercised (no key). | VERIFIED |
| REQ-PROVIDER-012 (**new, Pass 16**) | domainsdb: a `429` ends the six-zone sweep and reports the key to the pool as `RateLimited` (its own cooldown), exactly as `401`/`403` report it `Invalid` — `zone_sweep_stops_on(status)` is the one routing, mirroring `opencorporates::should_report_key_status`; the surfaced error names "rate-limited" vs "rejected". `description()` no longer advertises "(free, no key)" beside `cost: key_gated` in the module-listing API. | The sweep recognised only 401/403; every other non-2xx — 429 included, likely for six back-to-back requests on one key — hit the generic `continue`, so a throttled key returned `Ok(empty)` ("no look-alike domains") with the pool never told and the key re-throttled on the next scan. `zone_sweep_stops_on_rejection_and_rate_limit_only` and `description_no_longer_contradicts_the_key_gated_cost` (`src/modules/domainsdb/tests.rs`). | VERIFIED |
| REQ-PROVIDER-013 (**new, Pass 16**) | `github_user` sends the configured `HUNTSMAN_GITHUB_TOKEN` on all five of its GitHub calls — the primary `/users/{login}` profile GET and the SSH-key and public-events side-calls included — and reports a rejected/throttled token to the pool from every one of them (`fetch::github_get` is the one side-call transport). | The token was read only AFTER the profile GET, `fetch_ssh_keys` and `fetch_events` had gone out anonymous, so three of five calls (the profile lookup everything depends on included) spent the shared-IP 60 req/h budget while the token's 5 000 req/h sat unused, and the two side-calls swallowed every non-2xx silently. `ssh_key_side_call_sends_the_configured_token_and_survives_a_rejection` (`src/modules/github_user/tests.rs`) drives `github_get` against a loopback listener that captures the request and asserts the `Authorization: Bearer` header. | VERIFIED |

---

## Pass 14 findings

Directive-driven ("autonomous project-execution contract … use a very
critical lens, high-value corrections that are high confidence, remove
redundancies and consolidate"). Two rounds.

**Round 1** closed the one remaining code-reading-only row in the API section
(REQ-API-SCAN-004, the mixed valid/invalid batch path, now VERIFIED by a
direct test — PR #583's first commit).

**Round 2** ran an 11-finder parallel discovery workflow (one finder per
subsystem/lens: engine, entity/correlator, API, storage, CLI, util, two
module halves, lifecycle, test integrity, web/wasm, docs-vs-reality) followed
by a 3-lens adversarial verification of each finding (reproduce /
already-handled / materiality, majority-refute). 31 raw findings. Every fix
below was additionally re-derived by hand from the source before it was
touched, and each carries a regression lock that was shown to fail on the
baseline:

1. **Offline derivation modules counted as independent sources**
   (REQ-CORE-015). Root cause: `ENRICHMENT_ONLY_SOURCES` listed 5 sources
   while 12 more registry modules are pure transforms of graph data.
   Consolidation: the fact is now declared once per module
   (`Module::is_derivation`) and pinned to the hse-core list in both
   directions by an architecture test, so the list can no longer drift from
   the registry. One hse-core test that asserted `email_parse` *was* a
   corroborating source was corrected to test its stated purpose (a
   promotion pass cannot ground a derived entity) with a real observing
   source, and now also pins the generator-only case.
2. **Persisted `corroboration` double-counted** (REQ-STORAGE-002). Baseline:
   seed observed twice → corroboration 4 on disk. Same-scan re-persists are
   idempotent; the storage test that had pinned same-scan summing was
   corrected (with its cross-scan accumulation assertion kept).
3. **Integration tests wrote into the real `~/.huntsman`** (REQ-TEST-001) —
   observed directly in this environment, 102 fixture scans in the real
   adaptive-scan ledger. A fixture escaping the harness is the exact thing
   RULE 1 forbids.
4. **Railway deployment could never pass its own health probe**
   (REQ-API-AUTH-005).
5. **WiGLE cell/Bluetooth fabrication — RULE.md's cautionary case, still
   live** (REQ-PROVIDER-006). The authoritative Swagger was retrieved and
   parsed rather than assumed; the fix is pinned to the documented parameter
   sets. This also removed a third, undocumented BSSID probe.
6. **OathNet session id** (REQ-PROVIDER-007) — Pass 14 recorded this as
   "parsed from an undocumented field" and switched the parse to a flat
   `search_id`. **That was the regression, not the fix**: the shipped
   `/data/session/id` read matched the provider's live reference all along;
   the in-repo guide was the wrong document. Corrected in Pass 15 — see
   its findings and the row.
7. **`checkpoint_truncate` reported success when blocked**
   (REQ-STORAGE-003).
8. **Two toggle-key validators that disagreed** (REQ-CLI-013) — consolidated
   to one; the API's private duplicate deleted.
9. **Export redaction leaked prose-spelled brands** (REQ-API-EXPORT-007) —
   fixed systematically (spelling variants derived from the registry), and
   `EXTRA_SENSITIVE`'s hand-listed hyphenated duplicates removed.
10. **Stale SPA/wasm after every in-place upgrade** (REQ-API-ROUTE-008) —
    the `/static` ETag was the crate version, which the `main`-tracking
    upgrade path never bumps; it is now a per-asset content hash.
11. **Five misleading tests** (REQ-TEST-002..006): a lint blind to half the
    guard shape it polices, an env-knob scanner blind to wrappers and
    constants (four live knobs undocumented), a wake-lock guard that never
    saw the `hse-ai` wrapper, an AI-independence test whose stated
    invariant the product does not satisfy (now says what it enforces, plus
    a RULE-1 lock that LLM output never becomes a finding), and a key-pool
    test that asserted nothing while polluting the global pool.
12. **A fixture page in every production binary** (REQ-API-ROUTE-009) —
    the TEMPORARY `wasm_test.html` (71 KB, synthetic identities) and the
    wasm start-up proof that fed it are removed; **gate fidelity**
    (REQ-TEST-007) — `gate.sh` now honours the `wasm-opt` pin it promised.

Because the browser build embeds hse-core, the first fix changed
`wasm-ui/pkg/hse_wasm_ui_bg.wasm` and CI's byte-exact drift check failed on
the first push; the artifact was regenerated with the pinned pipeline after
proving toolchain parity (the same local pipeline reproduces the pre-change
`pkg/` byte-for-byte). It failed a second time on the regenerated artifact:
the build is checkout-path-dependent — cargo's metadata hash includes the
absolute path of `hse-core`, an out-of-workspace path dependency of `wasm-ui`,
and under `lto = true` the item/data order follows it (measured: two builds
from one path byte-identical, from two paths not, already in cargo's raw
`.wasm`). `scripts/wasm_ui_drift_check.sh` now builds from one fixed absolute
path on every host and gained `--write` as the single regeneration procedure
(the hand-run recipe duplicated in `wasm-ui/src/lib.rs` is gone); verified by
the check passing from two different checkout paths.

**Deliberately not done this pass** (verified real, lower return or lower
confidence — recorded so they are not re-discovered): a per-scan
reconciliation of `running`/`pending` scan rows left by a killed process
(recovery; real but a schema/lifecycle design choice), `see_know`'s process-wide
invalid-key latch and its silent false-negative path, the FOFA module's
unverified response schema (the provider's spec was not reachable), the
event-prune of still-running scans, the SPA's wasm-init failure path, the
`--profile`/`--full` precedence question (documented as intended overlay
behaviour, so not a defect on current evidence), the identity-scan email
admission gate reusing the broad `INFRA_DOMAINS` list, and the
`running`/`pending` rows a killed process leaves behind (real, but the
only safe criterion — the scan's own wall-time budget — defaults to
unbounded, and a blanket startup reset would abort a sibling process's
live scan).

### Verification commands run (Pass 14, in order)

```
$ cargo test --test smoke persisted_corroboration_never_exceeds…   # baseline: FAILED (4 > 1), then (4 > 2)
$ cargo test --manifest-path hse-core/Cargo.toml                    # 150 passed
$ cargo test --lib --features dep-cooldown                          # 6876 passed, 0 failed, 22 ignored
$ cargo test --features dep-cooldown --test api --test smoke --test architecture \
    --test cli_seed_validation --test halting                       # 129 / 58 / 60 / 9 / 5, 0 failed
$ git stash push -- src/storage/entities.rs && cargo test --test smoke persisted_corroboration…
                                                                    # FAILED again (4 > 2) — the lock discriminates
$ mv ~/.huntsman ~/.huntsman.pre-fix && cargo test --test api --test smoke --test cli_seed_validation
$ ls ~/.huntsman                                                    # No such file or directory
$ cargo fmt --all --check && cargo clippy --all-targets --features dep-cooldown -- -D warnings   # clean
$ curl https://api.wigle.net/swagger.json                           # 107 558 bytes, parsed for the three search endpoints
$ scripts/wasm_ui_drift_check.sh   (at a384354)                     # no drift — toolchain parity
$ scripts/wasm_ui_drift_check.sh   (regenerated)                    # no drift
$ cargo test --lib --features dep-cooldown -- modules::wigle util::wigle util::oathnet util::settings \
    cli::tests::config storage::tests::checkpoint api::scan_export::redact api::settings_handlers modules::wifi_intel
                                                                    # 168 passed, 0 failed
```

## Pass 15 findings

Pass 15 re-baselined on the Pass 14 tree, re-read every Pass 14 change with
the contract's rules as the checklist (RULE.md precedence first), and
executed the four Pass 14 deferrals that were verified real.

1. **Pass 14's OathNet "fix" was a regression** (REQ-PROVIDER-007) — the
   authoritative spec (the provider's live reference) documents
   `data.session.id`; the in-repo guide, a derived summary, said
   `search_id`. Pass 14 let the derived document win. The parse now reads
   the documented path only, the test decodes the reference's own example,
   and the guide's three wrong occurrences are corrected with the source
   and retrieval date. The general lesson is recorded in RULE.md's terms:
   a repo-local API guide is not the spec.
2. **SeekNow's silent false negative** (REQ-PROVIDER-008) — a rejected key
   made every seed read as "searched, found nothing". Now a per-seed
   module error naming the cause and remedy, with the error's text and the
   latch-time warning sharing one `KeyRejection::guidance()`.
3. **`pwned_passwords` reported a password-corpus hit as a breach**
   (REQ-CORE-016) — the `breach` tag fed five breach rules/passes with
   evidence that does not support them.
4. **Pooled keys were not redacted** (REQ-ENV-007) — only environment
   values were masked in upstream error bodies.
5. **A phantom CLI flag in the key-write 403** (REQ-API-MISC-009) — four
   copies of an instruction naming `--allow-key-write`, which never
   existed; consolidated to one helper and pinned to the CLI definition.
6. **A fixture page in every binary** (REQ-API-ROUTE-009, committed at the
   start of this pass) — 65 KB smaller wasm once its start-up proof went.
7. **Finalise-time event prune cut a still-running scan's log**
   (REQ-STORAGE-004) — the last verified Pass 14 deferral; the exemption is
   bounded to live scans inside the retention window so a killed process's
   `running` leftover cannot make its events immortal.
8. **A phantom provider name escaped the export redactor**
   (REQ-API-EXPORT-008) — `seek_now`, a second name for `see_know` left in
   the util layer by an earlier, incomplete rename; one constant now, pinned
   by a source scan.

**Dispositions of the remaining Pass 14 deferrals** (re-examined, still
not done, with the reason; the event-prune deferral is done above): the
`running`/`pending` rows a killed process leaves behind — the engine already drains on SIGTERM and the only safe
reset criterion (the scan's wall-time budget) defaults to unbounded, so a
startup reset would abort a sibling process's live scan (residual: a
crash, not a signal); the FOFA response schema — the provider's spec is
still unreachable from here, so a change would be an assumed contract; the
SPA's wasm-init failure path — cosmetic (the page still loads its JS
views); `--profile`/`--full` precedence — documented overlay behaviour,
not a defect on current evidence; the identity-scan email admission gate
reusing `INFRA_DOMAINS` — a deliberate policy (infrastructure mailboxes are
not identities), recorded as such.

## Pass 16 findings

Pass 16 re-baselined on the merged Pass 15 head and ran a second discovery
workflow — six finders scoped to the subsystems the two Pass 15 bounded passes
had not reached (the remaining correlator rules, ~20 more provider modules,
storage/API handlers, entity/export logic, CLI/wasm-ui), each told what was
already fixed or cleared — followed by 3-lens adversarial verification. Twelve
findings; all twelve survived (eleven 3/3, one 2/3). Every one is fixed here
with a lock shown to fail on the pre-fix code.

1. **Four read endpoints bypassed the candidate quarantine**
   (REQ-API-ROUTE-010) — `/path`, `/communities`, `/trust`, `/gaps`; the
   highest-severity cluster (unverified PII returned as fact). `/path` had no
   test coverage at all.
2. **Five silent key failures** — the exact class of the Pass 15 SeekNow fix:
   Numverify's and SEON's in-body-200 envelopes (REQ-PROVIDER-009/010),
   BuiltWith's `Errors[]` (REQ-PROVIDER-011), domainsdb swallowing a 429
   (REQ-PROVIDER-012), and `github_user` never sending its token on three of
   five calls (REQ-PROVIDER-013). Provider contracts were taken from the
   providers' live references (SEON's error page, BuiltWith's error-code
   page), not assumed — RULE.md precedence, as Pass 15 relearned.
3. **AU-108 blind to three platforms** (REQ-CORRELATOR-002) — two hand-copied
   lists whose doc claimed lockstep; one constant now.
4. **AU-058 rejected every single-token agent name** (REQ-CORRELATOR-003).
5. **`report.json` did not resolve against itself** (REQ-API-EXPORT-009).
6. **domainsdb described itself as free beside `cost: key_gated`**
   (folded into REQ-PROVIDER-012).

### Verification commands run (Pass 16, in order)

```
$ Workflow: 6 finders → 12 findings → 3-lens verify → 12 confirmed (11 unanimous)
$ cargo test --features dep-cooldown --test api -- scan_path scan_communities scan_gaps scan_trust   # 8 passed
$ # each of the three quarantine gates reverted → its lock FAILED (3/3); restored → ok
$ cargo test --lib -- modules::contact_enrich                            # 17 passed; classifier stubbed → FAILED
$ cargo test --lib -- modules::seon                                      # 27 passed; classifier stubbed → FAILED
$ cargo test --lib -- modules::builtwith modules::domainsdb modules::github_user \
    core::correlator::rules::tests::au_108 core::correlator::rules::geo::tests::extract_ratemyagent \
    app::export::tests::report_                                          # see the Pass 16 commits
$ cargo clippy --all-targets --features dep-cooldown -- -D warnings      # clean
$ cargo test --lib --features dep-cooldown && cargo test --test api --test architecture --test smoke
                                                                    # 6903 / 134 / 62 / 58, 0 failed
$ # CI on bcc913c3: rustdoc lint FAILED — an intra-doc link to a private fn from a sibling file
$ #   (src/modules/seon/types.rs). Caught by CI, not locally: gate.sh's "rustdoc lints" step
$ #   was skipped for an ad-hoc fmt/clippy/test subset. Fixed; the rustdoc command run locally.
$ RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links -D rustdoc::bare_urls -D rustdoc::invalid_html_tags" \
    cargo doc --no-deps --document-private-items --locked --features dep-cooldown   # clean
```

### Verification commands run (Pass 15, in order)

```
$ curl https://docs.oathnet.org/api-reference/search-session/initialize-a-search-session.md
                                                                    # 387 lines; response schema + example: data.session.id
$ cargo test --lib --features dep-cooldown -- util::oathnet util::see_know modules::see_know \
    modules::pwned_passwords util::http api::settings                # 357 passed, 0 failed
$ cargo test --features dep-cooldown --test api -- keys_             # 11 passed (the 403's named flag checked against clap)
$ # falsification: each fix mutated back to its baseline behaviour, lock run, fix restored
$   see_know: `result.or_hard_failure(hard_failure)`                  # a_rejected_key_… FAILED: "got Ok with 0 entities"
$   pwned_passwords: `entity.tag("breach")`                           # build_entities_high_count_… FAILED (tags)
$   settings_handlers: the old `--allow-key-write` body               # keys_pool_add_is_write_gated FAILED: "which `hse serve` does not accept"
$   restored                                                          # 2 passed / 1 passed
$ scripts/gate.sh                                                   # 16 executed checks PASS (lib 6888, api 130,
                                                                    #   architecture 61, smoke 58, hse-core 150, wasm-ui 12,
                                                                    #   drift check no drift); MSRV / NDK cross-build /
                                                                    #   shellcheck / audit SKIPPED here — CI is the authority
$ cargo test --lib --features dep-cooldown -- storage::tests         # passes with the prune exemption; with
$ git stash push -- src/storage/mod.rs && cargo test --lib -- prune_events_spares   # the exemption stashed: FAILED (live scan cut to 0)
$ cargo test --test architecture -- see_know_errors                 # passes; with one "seek_now" literal restored: FAILED
$ # CI on e3907cd4: Linux test job FAILED — core::port::tests::trait_object_events_round_trip (pruned >= 1)
$ #   cause: the prune exemption landed after gate.sh ran, validated by `--lib -- storage::tests` only.
$ cargo test --lib --features dep-cooldown                          # whole suite, after the port-test correction (see the row)
$ cargo test --features dep-cooldown --test architecture --test api --test smoke
```

## Pass 17 findings

Pass 17 acts on a directive that reframes the contract: treat the Huntsman
specification (`RULE.md` + `docs/OPERATIONAL_CONSTITUTION.md`) as governing and
convert it into executable Rust, benchmarked against deliberately HARD targets
— sparse, obscured, multilingual, historical, cross-jurisdictional subjects —
without lowering rigour because a target is difficult.

A gap analysis against the directive's eight named invariants found the engine
had ENTITY and EVIDENCE as types but neither CLAIM nor INFERENCE, no claim
lifecycle, no contradiction preservation, no competing-hypothesis structure, no
geolocation uncertainty, and no GEOINT frontier preference. The scheduler,
by contrast, was already an explainable expected-information-value model
(`core::roi::utility`) and needed only the geo term.

Landed this pass:

1. **`core::claim`** — the assertion layer (claim-state transitions computed
   from the record, corroboration by independent lineage, contradictions
   preserved, competing hypotheses that refuse premature closure).
2. **`core::geo_confidence`** — fixes carrying uncertainty, method floors and
   provenance; disjoint fixes conflict rather than average.
3. **GEOINT frontier preference** (REQ-ROI-007) — a bounded tilt, wired at the
   live dispatch call site.

### Pass 17b — reconciliation with `core::intelligence`

While this branch was in review, `main` merged #584, which landed
`src/core/intelligence.rs`: an evidence-preserving intelligence model with an
`IntelligenceLedger`, `EvidenceRecord`, `Claim`, `Inference`, `Hypothesis`,
`GeoAssertion`, a union-find `independent_source_count`, and a checkpointable
`BoundedFrontier`. It covers most of what items 1 and 2 above covered, and it
covers some of it better — its lineage model collapses *transitive* copy chains,
which `core::claim`'s per-witness key did not.

Two models for one capability is a defect regardless of which is better, so
Pass 17b resolves it in `main`'s favour rather than defending this branch's
work:

* **`core::claim` and `core::geo_confidence` are deleted.** Not deprecated,
  not shimmed — removed, with `core::mod.rs` and the one doc-link in
  `util::http::fetch` updated. `git grep core::claim` finds nothing outside
  history.
* **Only what was genuinely additive was folded into `core::intelligence`**,
  as extensions of its existing types rather than new parallel ones:
  * `ProviderOutcome` / `ProviderObservation` / `record_provider` /
    `coverage_gaps`, and a `reject_claim` that refuses while a bearing provider
    never answered (REQ-CLAIM-002). #584 had no representation of provider
    state at all: a claim with no support looked identical whether the source
    was unasked, broken, or genuinely empty.
  * `LocationBasis::min_uncertainty_m` / `locates_subject_directly`, the floor
    enforced in `GeoAssertion::is_valid`, plus `separation_m`, `reconcile` and
    `IntelligenceLedger::reconcile_locations` (REQ-GEO-001).
* **Everything else was dropped, deliberately**: `TargetDifficulty`,
  `PromotionThresholds`, `ExpansionBudget`, `ClaimKind`, `Validity`,
  `CompetingHypotheses`, and this branch's own `SourceLineage` and `ClaimState`.
  Each was either already covered by `core::intelligence` or had no production
  caller, and dormant code with no caller is not an upgrade.

The GEOINT tilt survives unchanged and is now consistent at both layers: the
live dispatch model carries `W_GEO = 0.25` against `W_INFO = 3.0`, and #584's
`PathCandidate::score` carries `0.15 × geo_relevance` against its own `3.0`
information term.

**A real defect was found in the merged code and fixed.**
`GeoAssertion::is_valid` accepted any non-negative radius, so a
`NetworkDerived` (IP-geolocated) assertion claiming 50 m validated and was
thereafter indistinguishable from an instrument fix. `min_uncertainty_m` now
floors it at 25 km. The lock (`a_precision_claim_never_exceeds_what_its_basis_can_support`)
fails against `main` as merged.

**Honest scope limit, unchanged.** `core::intelligence` is still not consumed
by the live scan pipeline — `git grep` shows its only caller outside itself is
`storage::intelligence`, which just adds checkpoint save/load. The engine still
promotes on `Entity::confidence` and geo modules still emit bare coordinates.
Everything in this section is recorded IMPLEMENTED_UNVERIFIED for exactly that
reason: these types govern nothing at runtime until adoption lands, and
adoption — not more model surface — is the next pass's highest-return work.

**Termux runtime evidence is NOT claimed for this pass.** CI cross-builds
`aarch64-linux-android` on every push (the "Build (aarch64-linux-android,
Termux target)" job, green on this branch), which proves the code COMPILES for
the target. It does not prove on-device execution, restart/resume, provider
failure or resource-pressure behaviour, none of which this container can
exercise — there is no Android device attached to it. The directive requires
that evidence before these features count as complete, so they do not.

### Verification commands run (Pass 17, in order)

```
$ cargo test --lib --features dep-cooldown -- core::intelligence core::roi
                                                    # 16 tests (6 from #584 + 10 new), all pass
$ # Falsification (Pass 17b): three mutations back to #584's behaviour, run together —
$ #   is_valid floor removed, reject_claim gap check removed, reconcile Conflict arm removed
$ #   => 5 failed / 11 passed, exactly the five locks the fixes own. Restored, 16/16 pass.
$ cargo clippy --all-targets --features dep-cooldown -- -D warnings # clean
$ RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links ..." cargo doc --no-deps --document-private-items
$ cargo test --lib --features dep-cooldown                          # full suite
$ cargo test --features dep-cooldown --test api --test architecture --test smoke
```

## Summary statistics

| Status | Pass 1 | Pass 2 | Pass 3 | Pass 4 | Pass 5 | Pass 6 | Pass 7 | Pass 8 | Pass 9 | Pass 10 | Pass 11 | Pass 12 | Pass 13 | Pass 14 | Pass 15 | Pass 16 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| VERIFIED | 23 | 30 | 50 | 53 | 54 | 55 | 56 | 58 | 59 *(REQ-API-SCAN-006 fixed in Pass 9)* | 62 *(REQ-CLI-001, REQ-CLI-007 flipped from PARTIAL; REQ-STORAGE-001 new)* | 64 *(REQ-ROI-001, REQ-ROI-003 new)* | 69 *(REQ-PROVIDER-001..005 new, all landed VERIFIED)* | 72 *(REQ-ROI-004..006 new, all landed VERIFIED)* | 88 *(REQ-API-SCAN-004 flipped from PARTIAL; REQ-CORE-015, REQ-CLI-013, REQ-API-AUTH-005, REQ-API-ROUTE-008/009, REQ-API-EXPORT-007, REQ-STORAGE-002, REQ-STORAGE-003, REQ-TEST-001..007 new, all landed VERIFIED)* | 94 *(REQ-PROVIDER-008, REQ-CORE-016, REQ-ENV-007, REQ-API-MISC-009, REQ-STORAGE-004, REQ-API-EXPORT-008 new, all landed VERIFIED)* | 103 *(REQ-API-ROUTE-010, REQ-API-EXPORT-009, REQ-CORRELATOR-002/003, REQ-PROVIDER-009..013 new, all landed VERIFIED)* |
| IMPLEMENTED_UNVERIFIED | 17 | 12 | 14 | 14 | 14 | 14 | 14 | 13 *(REQ-INSTALL-001 out, fixed; REQ-INSTALL-010 in as new then confirmed VERIFIED by this PR's own CI run before merge — net -1)* | 13 | 13 | 14 *(REQ-ROI-002 new)* | 14 | 14 | 16 *(REQ-PROVIDER-006, REQ-PROVIDER-007 new — contract verified against the authoritative spec, live call unexercised without credentials)* | 16 *(REQ-PROVIDER-007 corrected — the Pass 14 change was itself a regression; still live-unexercised)* | 16 |
| PARTIAL | 8 | 7 | 19 | 19 | 18 *(REQ-API-MISC-003 fixed in Pass 5)* | 17 *(REQ-API-SCAN-007 fixed in Pass 6)* | 16 *(REQ-API-SCAN-002 fixed in Pass 7)* | 16 | 16 | 14 *(REQ-CLI-001, REQ-CLI-007 out, fixed; REQ-ENV-005 stays, evidence strengthened)* | 14 | 14 | 14 | 13 *(REQ-API-SCAN-004 out, fixed)* | 13 | 13 |
| MISSING | 1 | 1 *(REQ-ENV-003, unchanged — see Pass 1's "Fix selection rationale")* | 1 | 0 *(REQ-ENV-003 fixed in Pass 4)* | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| AMBIGUOUS | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| OBSOLETE (by design, not a gap) | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |
| BROKEN | 0 | 0 | 0 *(REQ-API-MISC-004 was BROKEN before Pass 3's fix; now VERIFIED, counted above)* | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| UNREACHABLE | 0 | 0 | 1 *(REQ-API-SCAN-006 — real, but lower-severity than the BROKEN finding; not fixed in Pass 3, see section 6)* | 1 *(REQ-API-SCAN-006, unchanged)* | 1 *(REQ-API-SCAN-006, unchanged)* | 1 *(REQ-API-SCAN-006, unchanged)* | 1 *(REQ-API-SCAN-006, unchanged)* | 1 *(REQ-API-SCAN-006, unchanged)* | 0 *(REQ-API-SCAN-006 fixed in Pass 9)* | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| **Total rows** | **51** | **51** | **86** | **88** | **88** | **88** | **88** | **89** | **89** | **90** *(REQ-STORAGE-001, new Section 9)* | **93** *(REQ-ROI-001/002/003, new Section 10)* | **98** *(REQ-PROVIDER-001..005, new Section 11)* | **101** *(REQ-ROI-004..006, new Section 12)* | **118** *(17 new rows: REQ-CORE-015, REQ-CLI-013, REQ-API-AUTH-005, REQ-API-ROUTE-008/009, REQ-API-EXPORT-007, REQ-STORAGE-002/003, new Section 13 REQ-TEST-001..007, new Section 14 REQ-PROVIDER-006/007)* | **124** *(6 new rows: REQ-PROVIDER-008, REQ-CORE-016, REQ-ENV-007, REQ-API-MISC-009, REQ-STORAGE-004, REQ-API-EXPORT-008)* | **133** *(9 new rows: REQ-API-ROUTE-010, REQ-API-EXPORT-009, REQ-CORRELATOR-002/003, REQ-PROVIDER-009..013)* |

Pass 4's `VERIFIED` count (53) is Pass 3's 50, plus the REQ-ENV-003 flip
(+1), plus the two new one-row sections REQ-ENGINE-001/REQ-CORRELATOR-001
(+2) — both landed `VERIFIED` on first pass, so no row moved through an
intermediate status this time. Passes 5, 6, and 7 each added no new rows
(88 unchanged) — just one `PARTIAL` → `VERIFIED` flip apiece
(REQ-API-MISC-003, then REQ-API-SCAN-007, then REQ-API-SCAN-002). Pass 8's
`VERIFIED` count (57) is Pass 7's 56 plus the REQ-INSTALL-001 flip (+1);
`IMPLEMENTED_UNVERIFIED` stays at 14 (REQ-INSTALL-001 leaves it,
REQ-INSTALL-010 — new, not yet confirmed by its own PR's CI run — enters
it), and the new row brings the total from 88 to 89. Pass 9 adds no new
rows (89 unchanged) — one `UNREACHABLE` → `VERIFIED` flip (REQ-API-SCAN-006),
so `VERIFIED` rises from 58 to 59 and `UNREACHABLE` drops from 1 to 0. Pass
10's `VERIFIED` count (62) is Pass 9's 59, plus two `PARTIAL` → `VERIFIED`
flips (REQ-CLI-001, REQ-CLI-007, +2), plus one new row (REQ-STORAGE-001,
+1); `PARTIAL` drops from 16 to 14 (the same two flips leaving it); the new
row brings the total from 89 to 90. Pass 11's `VERIFIED` count (64) is
Pass 10's 62, plus two new rows landing `VERIFIED` on first pass
(REQ-ROI-001, citing pre-existing PR #578 coverage never before cited in
this ledger; REQ-ROI-003, this pass's own fix, +2);
`IMPLEMENTED_UNVERIFIED` rises from 13 to 14 (one more new row,
REQ-ROI-002, +1); the three new rows bring the total from 90 to 93. Pass
12's `VERIFIED` count (69) is Pass 11's 64, plus one new five-row section,
REQ-PROVIDER-001..005, all five landing `VERIFIED` on first pass (+5) — no
row moved through an intermediate status this time; the five new rows bring
the total from 93 to 98. Pass 13's `VERIFIED` count (72) is Pass 12's 69,
plus one new three-row section, REQ-ROI-004..006, all three landing
`VERIFIED` on first pass (+3) — no row moved through an intermediate status
this time; the three new rows bring the total from 98 to 101. Pass 14's `VERIFIED` count (88) is Pass 13's 72, plus the
REQ-API-SCAN-004 flip from `PARTIAL` (+1, so `PARTIAL` drops from 14 to 13),
plus fifteen new rows landing `VERIFIED` on first pass (REQ-CORE-015,
REQ-CLI-013, REQ-API-AUTH-005, REQ-API-ROUTE-008/009, REQ-API-EXPORT-007,
REQ-STORAGE-002, REQ-STORAGE-003, REQ-TEST-001..007, +15); `IMPLEMENTED_UNVERIFIED` rises from 14 to
16 (REQ-PROVIDER-006/007 — contract verified against the authoritative spec,
live behaviour unexercised without credentials); the seventeen new rows bring the
total from 101 to 118.

Breakdown by section: Module trait contract 15 rows (REQ-CORE-001..015), CLI
surface 13 rows (REQ-CLI-001..013), `install.sh` 10 rows
(REQ-INSTALL-001..010), Env/config 6 rows (REQ-ENV-001..006), README claims 10
rows (REQ-README-001..010), HTTP API surface 39 rows (REQ-API-ROUTE-001..009,
REQ-API-AUTH-001..005, REQ-API-SCAN-001..010, REQ-API-MISC-001..008,
REQ-API-EXPORT-001..007), Scan engine dispatch 1 row (REQ-ENGINE-001),
Correlator rule registry 1 row (REQ-CORRELATOR-001), Storage subsystem 3 rows
(REQ-STORAGE-001..003), ROI-maximising expansion 3 rows
(REQ-ROI-001..003), Provider capability + economics descriptor 5 rows
(REQ-PROVIDER-001..005), Dispatch-utility explainability 3 rows
(REQ-ROI-004..006), Test-harness isolation and test integrity 7 rows (REQ-TEST-001..007), Provider API
contracts re-verified 2 rows (REQ-PROVIDER-006..007) —
15+13+10+6+10+39+1+1+3+3+5+3+7+2 = 118, matching the total above.
Some rows cite tests shared across sections (e.g. REQ-CORE-010 and
REQ-README-009 both cite `every_module_maps_to_valid_attack_reconnaissance_techniques`),
which is intentional — the two rows document the same underlying test from
two different requirement angles (the trait contract vs. the README's claim
built on it).
