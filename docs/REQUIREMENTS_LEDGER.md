# Requirements Traceability Ledger

**Scope.** This ledger covers HSE's cross-cutting *core contracts*, not the
individual scanning modules' business logic — that was the subject of a
separate, now-complete module-by-module bug audit under
`src/modules/*/mod.rs` (Phases 0-10, PRs #553-568, merged; every one of the
188 registered modules read against an established bug-class checklist). The
areas covered here, across nine passes:

1. The `Module` trait contract (`src/core/module/mod.rs`).
2. The CLI surface (`src/main.rs`, `src/cli/`).
3. `install.sh`.
4. The env/config template and key consumption.
5. Top-level `README.md`'s stated capabilities/counts.
6. The HTTP API surface (`src/api/`) — routes, auth middleware, scan
   lifecycle handlers, settings/cells/key-harvest/update handlers, scan
   export/redaction.
7. Scan engine dispatch (`src/core/engine/`) — the dead-module quarantine
   gate only; expansion, ROI/budget pruning, and the rest of the engine's
   internals remain out of scope.
8. Correlator rule registry (`src/core/correlator/`) — registration
   completeness/uniqueness only; individual rules' firing logic remains out
   of scope beyond the pre-existing per-rule test corpus.

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
the new test fails, restored it). No other rows changed this pass — see
"Pass 9 findings" below.

This still does **not** claim to have reconstructed requirements for the
*entire* codebase (the correlator's actual rule logic beyond registry-level
completeness, the scan engine's internals beyond the quarantine gate, the
storage layer beyond one fix, the web/WASM UI, and `hse-ai-daemon` remain
out of scope for all nine passes) — see "Known limitations" for why, and
for what a further pass would need to cover.

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

**Known limitations of Pass 8 — what a further pass would need to cover.**
This ledger's 8 sections are the core contracts, the remote-facing API
surface, and two registry-level guards of a Rust CLI/module-engine tool: the
`Module` trait, the CLI, the installer, the env/config template, the
README's own claims, `hse serve`'s HTTP API, the scan engine's dead-module
quarantine gate, and the correlator's rule-registration completeness. Passes
5, 6, and 7 each closed one more `PARTIAL` row within the existing HTTP API
section (section 6); Pass 8 closed one `IMPLEMENTED_UNVERIFIED` row and
added one new row within the existing `install.sh` section (section 3),
triggered by a direct install-readiness request rather than the backlog
scan — none of the four expanded scope to any new subsystem, so the list
below is unchanged from Pass 4's. Deliberately still **not** covered by any
of the nine passes, and not claimed as VERIFIED/MISSING/etc. anywhere
above:

- **The scan engine's internals beyond the quarantine gate**
  (`src/core/engine/` past `gate_skips` — expansion, ROI/budget pruning, and
  the *upstream* wiring that computes the `quarantined` set in production
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
- **The storage layer's own contracts** (`src/storage/` — schema migrations,
  the SQLite `Store`'s full method set beyond what Pass 2's one fix touched).
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
reader should not infer completeness beyond the 8 sections it actually
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
| REQ-CORE-008 | `Module::termux_timeout_ms()` (default = `max_timeout_ms()`) sets the per-module budget the engine applies on a Termux device when the operator hasn't pinned `ScanOptions::module_timeout_ms`; the engine additionally clamps to a 45s cap unless the module is cap-exempt. | none | `u64` | Engine timeout resolution on Termux | An exempt module bypasses the cap and is bounded only by its own value (still finite). | `src/core/module/mod.rs:187-220`; engine consumer `src/core/engine/timeout/mod.rs` | `termux_cap_bounds_long_modules_only_on_termux_without_override`, `cap_exempt_module_keeps_its_full_termux_budget`, `resolve_timeout_uses_termux_budget_then_cap` (`src/core/engine/timeout/tests.rs`) | Ran `cargo test --lib core::engine::timeout::tests` this pass (Pass 2) — all 3 cited tests passed. | VERIFIED |
| REQ-CORE-009 | `Module::cache_ttl_secs()` (default 0 = no caching) lets the engine serve a prior result from the inter-scan entity cache instead of re-querying, for modules with stable, cacheable data. | none | `u64` (seconds) | Engine reads/writes an entity cache keyed on module+target when `ttl > 0` | `ttl == 0` ⇒ cache path is a no-op | `src/core/module/mod.rs:272-278`; consumers `src/core/engine/dispatch.rs:848,984,1106`; cache-hit contract documented at `src/core/port/mod.rs:139-155` | **Fixed this pass (Pass 2).** No dedicated unit test found exercising a cache HIT/MISS for a nonzero-TTL module end-to-end. Root cause: `core::test_support::InMemoryStore` (the standard engine-test double) inherited `StoragePort`'s no-op defaults for `archive_module_result`/`lookup_module_result_fresh` — a lookup could never return a hit, so the dispatch-level "cache hit skips `process()`" behavior was structurally untestable through it, independent of the storage layer's own coverage (`storage::archive_tests` already fully covers the SQLite-backed round-trip). | Gave `InMemoryStore` genuine in-memory cache semantics mirroring `Store`'s exact freshness predicate (`archived_at + ttl_secs > now`), then added `core::engine::tests::cache_hit_skips_reprocessing_a_later_scan_of_the_same_target`: dispatches a `cache_ttl_secs()`-overriding probe against the same target under two different scan_ids and asserts `process()` runs exactly once (the second dispatch replays from cache, `ModuleStats::cached == 1`), plus a third dispatch against a *different* target proves the cache is keyed per-target, not a blanket hit. Ran `cargo test --lib core::engine::tests::cache_hit_skips_reprocessing_a_later_scan_of_the_same_target` — passed. Updating `InMemoryStore` also broke a pre-existing test's premise (`core::port::tests::default_optional_methods_are_documented_no_ops` asserted `InMemoryStore` overrides none of the 7 default methods) — updated that test's assertions and comment to reflect the new, deliberate 5-no-op/2-real-cache split. Ran `cargo test --lib --features dep-cooldown` (6836 passed, 0 failed), `cargo test --test architecture` (55 passed), `cargo clippy --all-targets --features dep-cooldown -- -D warnings` (clean), `cargo fmt --all`. | VERIFIED |
| REQ-CORE-010 | `Module::attack_techniques()` defaults from `category()` via `attack::techniques_for_category`; every registered module must declare at least one real MITRE ATT&CK Reconnaissance technique ID from the catalogue. | none | `&'static [&'static str]` | Tags emitted entities with `attack:<ID>` | A module whose category is `Other` (unmapped) and has no override reports zero techniques. | `src/core/module/mod.rs:280-293`; category map `src/core/attack/mod.rs` | `every_module_maps_to_valid_attack_reconnaissance_techniques` (`tests/architecture_parts/architecture_part2.rs:14`) | Ran `cargo test --test architecture` this pass — passed (part of the 55/55 run). | VERIFIED |
| REQ-CORE-011 | `Module::produces()` (default empty) documents `EntityKind`s the module emits; every module that literally constructs an `Entity::new(EntityKind::X, ...)` must declare `X` in its `produces()`. | none | `&'static [EntityKind]` | Drives the UI pivot-chain / capability map | A module minting an undeclared kind under-represents its own output map (sound-but-incomplete check: only catches literal constructions, not dynamically-classified ones). | `src/core/module/mod.rs:268-270` | `every_literal_constructed_entity_kind_is_declared_in_produces` (`tests/architecture_parts/architecture_part5.rs:90`) | Ran `cargo test --test architecture` this pass — passed. | VERIFIED |
| REQ-CORE-012 | `ModuleContext::key()`/`key_opt()` are the sole sanctioned way a module reads a `HUNTSMAN_*` credential; a present-but-blank value or an un-edited `hse provision` template placeholder (`insert_<svc>_key_here`) must resolve as absent, never forwarded to a provider. | env var value | `Result<&str>` / `Option<&str>` | none | `key()` → `Error::MissingKey`; `key_opt()` → `None` | `src/core/module/mod.rs:334-398`; filter `src/util/keys/mod.rs::resolve_key` | `key_returns_ok_when_present`, `key_returns_missing_key_error_when_absent`, `key_treats_a_blank_value_as_missing`, `key_opt_returns_some_when_present`, `key_opt_returns_none_when_absent`, `key_opt_filters_blank_and_placeholder_slots` (`src/core/module/tests.rs`); structural guard `modules_never_read_credentials_via_raw_env` (`tests/architecture_parts/architecture_part3.rs:820`) | Ran `cargo test --lib core::module::tests` and `cargo test --test architecture modules_never_read_credentials_via_raw_env` this pass — all passed. | VERIFIED |
| REQ-CORE-013 | `ModuleContext::next_pooled_key()` / `report_key_exhausted()` implement the in-scan key cascade: a module whose key hits 401/403/429 can fetch the next untried pooled key for the same service and retry within one `process()` call. | `service: &str`, `tried: &HashSet<String>` (cascade); `service`, `key_value`, `status` (report) | `Option<String>` (cascade) | Mutates the global key pool's status + persists off-thread | `next_pooled_key` returns `None` once the pool is exhausted — caller must stop retrying, not loop. | `src/core/module/mod.rs:366-398`; pool `src/util/key_pool/mod.rs` | Key-pool unit tests exist under `src/util/key_pool/tests.rs` (55 tests, including `next_key_excluding_cascades_past_tried_keys`, the direct cascade contract). | Ran `cargo test --lib key_pool` this pass (Pass 2) — 55/55 passed. | VERIFIED |
| REQ-CORE-014 | `ModuleCategory`/`ModuleCost` round-trip serde exactly (their `as_str()` identifier must equal the serde snake_case wire form for every variant), so the API and the SPA never disagree on a category/cost string. | none | `&'static str` | none | A new enum variant that fails to update the drift-guard match arms fails to *compile* (arm-less match, no wildcard). | `src/core/module/mod.rs:19-106` | `module_cost_as_str_matches_serde`, `module_category_as_str_round_trips_serde` (`src/core/module/tests.rs`) | Ran `cargo test --lib core::module::tests` this pass — passed. | VERIFIED |

---

## 2. The CLI surface (`src/main.rs`, `src/cli/`)

| ID | Behavior | Inputs | Outputs | Side effects | Failure behavior | Implementation location | Tests covering it | Runtime verification evidence | Status |
|---|---|---|---|---|---|---|---|---|---|
| REQ-CLI-001 | `hse` builds a bounded tokio runtime (2 worker threads, 16 max blocking threads) rather than `#[tokio::main]`'s 512-thread default, to bound OS-thread spawn on a low-RAM phone. | none | Configured `tokio::runtime::Runtime` | Process-wide runtime config | `.expect()`s on build failure (process aborts with a message — acceptable for a runtime that cannot be built at all). | `src/main.rs:12-17`; constants `src/lib.rs:112,120` | `architecture_constants` asserts `WORKER_THREADS == 2` (`tests/architecture_parts/architecture_part3.rs:89`); `MAX_BLOCKING_THREADS` itself is not separately asserted. | Ran `cargo test --test architecture architecture_constants` this pass — passed (covers `WORKER_THREADS`, not `MAX_BLOCKING_THREADS`). | PARTIAL |
| REQ-CLI-002 | A panic caused specifically by a broken stdout pipe (`print!`/`println!` hitting `EPIPE`, e.g. `hse scan \| head`) exits 0 quietly instead of printing a backtrace; every other panic still propagates through the default hook. | Panic payload string | Process exit code | `std::process::exit(0)` for the matched case only | A genuine output failure unrelated to a closed pipe (e.g. disk full) still panics loudly, by design. | `src/main.rs:43-66` | `is_broken_pipe_panic` unit-tested in `src/main_tests.rs` (`#[cfg(test)] mod tests { include!("main_tests.rs"); }` at `src/main.rs:69`). | Ran `cargo test --bin hse` this pass (Pass 2) — `tests::recognises_only_the_broken_pipe_print_panic` passed. | VERIFIED |
| REQ-CLI-003 | `hse --version` / the `Cli` clap tree is internally consistent (no duplicate short flags, no conflicting IDs) — validated at test time via clap's own `debug_assert`, since a broken definition only panics at first real invocation otherwise. | none | n/a | none | A broken definition would otherwise panic on first invocation of the affected subcommand in production, not at build time. | `src/cli/command.rs:62-892` | `cli_definition_is_internally_consistent` (`src/cli/command.rs:909`) | Ran `cargo test --lib cli::command::tests::cli_definition_is_internally_consistent` this pass — passed. | VERIFIED |
| REQ-CLI-004 | `hse scan --min-confidence <f>` and `--min-expand-confidence` reject non-finite (`nan`/`inf`) and out-of-`0.0..=1.0` values at the argument-parsing boundary, rather than silently producing a floor that discards every entity. | CLI string | `Result<f64, String>` (clap `value_parser`) | none | Clap usage error before any scan work begins. | `src/cli/command.rs:23-34` (`confidence_floor`) | `confidence_floor_accepts_the_documented_range_inclusive`, `confidence_floor_rejects_non_finite_values`, `confidence_floor_rejects_values_outside_zero_to_one`, `confidence_floor_rejects_non_numeric_input` (`src/cli/command.rs`) | Ran `cargo test --lib cli::command::tests` this pass — all 4 passed. | VERIFIED |
| REQ-CLI-005 | `hse scan --min-marginal-yield <f>` rejects non-finite and negative values but, unlike confidence, accepts values above 1.0 (it's a rate, not a probability). | CLI string | `Result<f64, String>` | none | Clap usage error. | `src/cli/command.rs:47-60` (`non_negative_rate`) | `non_negative_rate_accepts_values_above_one`, `non_negative_rate_rejects_non_finite_and_negative` (`src/cli/command.rs`) | Ran `cargo test --lib cli::command::tests` this pass — passed. | VERIFIED |
| REQ-CLI-006 | `hse scan --full` (`--complete`/`--everything`) is the "no-compromise" preset: forces every module regardless of `--free-only`/`--passive-only`/`--modules`, pins `MAX_DEPTH` recursion, lifts the wrong-identity expansion gate, disables ROI pruning/dead-module skipping, and restores infra entities — overriding every one of those individual flags even when also passed. | CLI flags | `ScanCmd` struct fields | none | none (pure flag composition) | `src/cli/mod.rs:97-144` | Composition asserted inline via the doc comments; no dedicated unit test constructs `--full` alongside each conflicting flag and asserts the override wins for all of them simultaneously (each override is one `bool && !full` expression, individually simple but not table-tested as a set). | Read-only; traced the composition logic by hand, did not execute a combined-flags scenario. | IMPLEMENTED_UNVERIFIED |
| REQ-CLI-007 | `hse scan` with no `--value` and no `--input-file` falls back to `HUNTSMAN_DEFAULT_SEED`; if neither is set, errors with actionable guidance rather than a bare panic or an empty scan. | `Option<String>` (CLI), `Option<String>` (env-derived default) | `Result<String>` | none | `Error::Other("no target: ...")` | `src/cli/mod.rs:340-352` (`resolve_seed`) | Not found under a dedicated test name in `src/cli/tests.rs` search for `resolve_seed`; the function is `pub(super)`-free and pure, ideal for a unit test, but none was located. | Read-only; searched `src/cli/tests.rs` and `src/cli/mod.rs` inline tests for `resolve_seed` — none found. | PARTIAL |
| REQ-CLI-008 | `hse serve`'s key-write endpoint is loopback-only regardless of `--no-key-write`; a non-loopback bind requires either an explicit/auto-minted bearer token or `--allow-unauthenticated`. | `--bind`, `--auth-token`/`HSE_AUTH_TOKEN`, `--allow-unauthenticated`, `--no-key-write` | Server startup banner + enforced auth middleware | Binds a socket; may print a one-time minted token | Loopback + no token ⇒ silently open (by design, device-local); non-loopback + no token + no `--allow-unauthenticated` ⇒ auth is required (server still starts, all non-loopback requests 401). | `src/cli/serve/mod.rs:361-421`; enforcement `src/api/routes/mod.rs`, `src/api/auth/mod.rs` | `src/api/auth/tests.rs` (21 tests), `src/api/routes/tests.rs` (33 tests) | Ran `cargo test --lib api::auth` and `cargo test --lib api::routes` this pass (Pass 2) — 21/21 and 33/33 passed respectively. | VERIFIED |
| REQ-CLI-009 | `hse build-sha` exits non-zero when the build carries no verifiable revision (dirty tree, or no `.git` and no `HSE_BUILD_SHA`); `install.sh`/`hse update` treat a non-zero exit as "cannot prove it" and rebuild. | none | SHA to stdout (or JSON with `--json`) | Process exit code | Non-zero exit + `Error::Other` message | `src/cli/mod.rs:447-471` | No dedicated test name found asserting the exit-code contract specifically (`build_sha_is_verifiable` itself likely has coverage in its own module, not checked this pass). | Ran `./target/debug/hse build-sha; echo exit=$?` this pass (Pass 2) — `sha=cc55f3858…, dirty=1`, `exit=1` (the on-disk binary predates the current HEAD, the same "cannot prove it" signal a genuinely dirty tree produces). Exit code confirmed non-zero as documented. | VERIFIED |
| REQ-CLI-010 | `hse modules --category <cat> --json` filters the registry by category and emits the same JSON shape as `GET /api/v1/modules`. | `--category`, `--json` | stdout JSON or table | none | Unknown category presumably yields an empty filtered list (not explicitly checked this pass). | `src/cli/modules.rs`; `Command::Modules` in `src/cli/command.rs:276-283` | Not individually checked this pass. | Ran `./target/debug/hse modules --json` this pass — returned `{"count":188,"modules":[...]}` with per-module `consumes`/`category`/`cost` fields, confirming the JSON shape and that the registry currently holds 188 entries (used to derive REQ-README rows below). | VERIFIED |
| REQ-CLI-011 | `hse tidy`'s `--help` text quotes the dossier-cache retention cap ("newest N files") as a literal number that must equal `DOSSIER_MAX_FILES`, since clap renders doc-comment intra-doc links as raw unresolved markup rather than resolving them. | none | Help text string | none | Test failure on drift (not a runtime failure — an operator would just see a stale number in `--help`). | `src/cli/command.rs:866-874` (doc comment), constant `src/app/tidy/mod.rs` | `tidy_help_quotes_the_real_dossier_cap` (`src/cli/command.rs:920`) | Ran `cargo test --lib cli::command::tests::tidy_help_quotes_the_real_dossier_cap` this pass — passed. | VERIFIED |
| REQ-CLI-012 | `hse ingest`/`hse investigate --min-confidence` reuse the same `confidence_floor` parser as `hse scan`, so the "silent total data loss on NaN" regression is closed for every subcommand that takes a confidence floor, not just `scan`. | CLI string | `Result<f64, String>` | none | Same as REQ-CLI-004. | `src/cli/command.rs:508,545` | Same tests as REQ-CLI-004 (shared parser function) — no per-subcommand-wiring test confirms `ingest`/`investigate` actually pass the parsed value through unmodified to the extractor's filter. | Read-only for the wiring; the parser itself is VERIFIED (REQ-CLI-004). | PARTIAL |

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
| REQ-ENV-005 | `HUNTSMAN_DEFAULT_SEED` (read via `std::env::var`, not the key-pool machinery) lets `hse scan`/`hse live` run with no `--value` at all. | env var | `Option<String>` | none | Absent + no `--value` ⇒ `Error::Other` with actionable guidance (REQ-CLI-007). | `src/util/keys/mod.rs::default_seed()` (consumer: `src/cli/mod.rs:340-352`) | Covered by `collect_raw_huntsman_env_reads`'s general sweep (part of REQ-ENV-001's passing assertion) for "is it consumed", but no test exercises the actual scan-launch fallback behavior end-to-end. | Read-only for the fallback path itself; REQ-ENV-001's pass confirms the var is at least consumed somewhere. | PARTIAL |
| REQ-ENV-006 | `HSE_BIND`/`HSE_AUTH_TOKEN` (non-`HUNTSMAN_`-prefixed, deliberately outside the credential-pool system) configure `hse serve`'s bind address and bearer token via clap's own `env = "..."` attribute, and are documented in `docs/RAILWAY.md` and `README.md` (not `.env.example`/`env_template.txt`, which is correct since these are deployment knobs, not OSINT-provider credentials). | env var (via clap) | Parsed `Cli` fields | none | Clap's own env-fallback semantics (CLI flag wins if both given). | `src/cli/command.rs:554,569` | No dedicated test asserts the clap `env = "HSE_BIND"` wiring actually reads the process environment (clap's own tests cover the mechanism generically, not this specific field). | Read-only; confirmed via `grep` that both vars appear in `docs/RAILWAY.md` and `README.md`. | IMPLEMENTED_UNVERIFIED |

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
| REQ-API-AUTH-001 | `auth::resolve(bind, supplied, allow_unauthenticated)` returns `Ok(None)` (no gate) for a loopback bind unless a token was explicitly supplied (honored anyway, for defence-in-depth); for a non-loopback bind, returns `Ok(Some(token))` — the supplied token if… | Ran `cargo test --lib api::auth -- --test-threads=4` this pass: `running 21 tests ... test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 6836 filtered out`, including all 6 posture-resolution tests listed above. | VERIFIED |
| REQ-API-AUTH-002 | When a token is resolved, `enforce_auth` is layered as the outermost-but-one middleware (only `set_security_headers` sits further out) so it runs before the Host allowlist, CORS, CSRF, and every handler/SPA/static asset — an unauthenticated non-loopback… | Ran `cargo test --lib api::auth`: 21/21 passed (includes all 9 middleware tests). Ran `cargo test --test api exposed_bind -- --test-threads=4` separately: `running 4 tests / test exposed_bind_bootstraps_a_browser_then_drops_the_token_from_the_url ... ok / test exposed_bind_rejects_every_unauthenticated_surface ... ok / test exposed_bind_rejects_an_unauthenticated_mutation ... ok / test exposed_bind_admits_a_valid_token ... ok / test result: ok. 4 passed; 0 failed`. Ran… | VERIFIED |
| REQ-API-AUTH-003 | `AuthToken::matches` hashes the presented credential with SHA-256 and compares digests via `ct_eq`, which XOR-accumulates every byte pair and checks once at the end rather than short-circuiting on the first mismatch, so response timing cannot leak the token's… | Ran `cargo test --lib api::auth` this pass — all 4 tests pass (part of 21/21). These tests confirm ct_eq's functional correctness (right/wrong tokens match/reject as expected, near-misses at every position rejected) and that Debug never leaks the plaintext. They do NOT and cannot measure that the comparison is actually constant-time on real hardware — no timing/statistical test exists in the suite; the constant-time guarantee itself rests on reading the loop's structure (no early return), not… | PARTIAL |
| REQ-API-AUTH-004 | On a non-loopback bind, presenting a valid `X-HSE-CSRF` header with NO bearer credential must still 401 — CSRF and bearer-auth are independent, both-required (AND-ed) controls, not substitutes for each other, because `enforce_auth` is layered OUTSIDE… | Ran `cargo test --test api exposed_bind -- --test-threads=4` this pass (part of the 4-test group reported above): `test exposed_bind_rejects_an_unauthenticated_mutation ... ok` — a POST to /api/v1/radar carrying X-HSE-CSRF but no bearer token still returned 401. | VERIFIED |

### Scan lifecycle handlers

| ID | Behavior | Runtime verification evidence | Status |
|---|---|---|---|
| REQ-API-SCAN-001 | POST /api/v1/scans validates the target at the API boundary (shape check via Target::validate_verbose, e.g. an email kind whose value has no '@') BEFORE the scan is persisted or dispatched to the engine, rejecting with 400 rather than queuing a scan that… | Ran `cargo test --lib api::scan_handlers` this pass — 14/14 passed, including build_scan_from_request_rejects_invalid_target and build_scan_from_request_valid_is_deterministic. Ran `cargo test --test api scan_create` this pass — 4/4 passed, including scan_create_rejects_invalid_target (POST value="not-an-email" kind=email -> 400) and scan_create_accepts_valid_request (-> 202 with a scan_id). | VERIFIED |
| REQ-API-SCAN-002 (**fixed in Pass 7**) | POST /api/v1/scans/{id}/cancel on a scan that is actually in-flight delivers the cancellation signal (via the shared s.cancellations map -> CancelHandle::cancel()) to the running engine task, and the engine honestly reports the outcome as ScanStatus::Aborted… | **Was PARTIAL**: `cargo test --test api scan_cancel` (1/1 passed, 404 branch only) and `cargo test --test halting wall_time_budget_stops_promptly_and_preserves_findings` (1/1 passed) proved the downstream engine mechanism (a wall-time deadline → `ScanStatus::Aborted`, findings preserved) driven directly against the engine, never through HTTP — no test drove a real in-flight scan through the actual HTTP `scan_cancel` handler and polled `GET /scans/{id}` to see status become "aborted". **Fixed in Pass 7**: added `CancelCooperativeProbe` (`tests/common/mod.rs`) — a module that blocks in `process()`, cooperatively polling `ctx.cancel.is_cancelled()` every ~100ms for up to 60s (mirrors `tests/halting.rs`'s `SlowModule`) — and a new parameterized harness helper, `test_app_with_modules`, so a test can build the real axum `Router`+`AppState` with a caller-chosen module set instead of the default `SyntheticModule`. New test `scan_cancel_stops_a_real_in_flight_scan_and_status_becomes_aborted` (`tests/api.rs`): `POST /scans` with the probe module (genuinely in-flight — `spawn_scan` registers the real `CancelHandle` into `s.cancellations` synchronously before the 202 response returns), `POST /scans/{id}/cancel` (asserts 200, `"status":"cancelling"`), then polls `GET /scans/{id}` until `"status":"aborted"` (resolves in ~100-200ms in practice, well inside the 5s poll budget). Ran 5 times consecutively — stable, ~0.12s each. Ran `cargo test --test api` (126 passed), `cargo test --test halting` (5 passed) and `cargo test --test smoke` (57 passed) to confirm the shared `tests/common/mod.rs` refactor didn't disturb either sibling test crate. | VERIFIED |
| REQ-API-SCAN-003 | DELETE /api/v1/scans/{id} refuses (409 Conflict) to delete a scan that is still in-flight (present in s.cancellations), instead of racing delete_scan's cascade against the live engine task's own mid-scan writes — which would silently resurrect a "deleted"… | Ran `cargo test --test api scan_delete` this pass — 3/3 passed, including scan_delete_refuses_an_in_flight_scan_then_succeeds_once_it_ends, which seeds s.cancellations directly, confirms the delete call returns 409 while the entry is present, then removes the entry and confirms delete now returns 200. | VERIFIED |
| REQ-API-SCAN-004 | POST /api/v1/scans/batch enforces DoS-relevant caps (empty array -> 400, >50 targets -> 400, exactly 50 -> 202) and, for a batch that mixes a structurally-invalid target among valid ones, records a per-item {"error": msg} entry and continues dispatching the… | Ran `cargo test --test api batch_endpoint_enforces_empty_and_size_limits` this pass — 1/1 passed (empty->400, 51 items->400, 50 items->202). The mixed valid/invalid-item continue-and-record-per-item-error path (core.rs:733-739) was confirmed by reading the code only; grepped tests/api.rs and found no batch request containing a malformed target. | PARTIAL |
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

### Scan export + redaction

| ID | Behavior | Runtime verification evidence | Status |
|---|---|---|---|
| REQ-API-EXPORT-001 | redact_sensitive_sources() replaces every proprietary breach/intel provider name appearing anywhere in an export body with the fixed label "breach-source", via one whole-token (\b...\b), case-insensitive regex alternation built once from the sensitive-name… | Ran `cargo test --lib api::scan_export -- --nocapture` this pass: `running 8 tests ... test api::scan_export::redact::tests::covers_every_spelling_of_the_named_providers ... ok / idempotent ... ok / redacts_named_paid_provider_but_keeps_public_sources ... ok / redacts_capitalised_brand_in_evidence_summaries ... ok / every_breach_category_source_is_redacted ... ok / whole_token_match_leaves_longer_tokens_intact ... ok ... test result: ok. 8 passed; 0 failed`. | VERIFIED |
| REQ-API-EXPORT-002 | The sensitive-name set is registry-derived: every module whose category() == ModuleCategory::Breach is swept automatically (so a newly added breach-category module needs no redact.rs edit); EXTRA_SENSITIVE is reserved for names the sweep structurally cannot… | Ran `cargo test --lib api::scan_export::redact::tests::every_breach_category_source_is_redacted` this pass (part of the 8/8 run above) — passed. Cross-checked categories by reading source directly: oathnet_pro::category() returns ModuleCategory::People (src/modules/oathnet_pro/mod.rs:109-110), see_know::category() and dehashed::category() both return ModuleCategory::Breach (src/modules/see_know/mod.rs:194-196, src/modules/dehashed/mod.rs:93-95) — confirming the comment's factual claims about… | VERIFIED |
| REQ-API-EXPORT-003 | Redaction is enforced at one choke point: all four shareable download handlers (scan_entities_csv, scan_report_json, scan_export_gexf, scan_events_log) route their body through download_response(), which unconditionally calls redact_sensitive_sources(); only… | Ran `grep -n "download_response(\\|download_response_operator(" src/api/scan_export/mod.rs` this pass — output confirmed exactly 4 call sites (lines 49, 82, 120, 174) use download_response and exactly 1 (line 147, scan_debug_bundle) uses download_response_operator, matching the module doc comment's claim that the debug bundle is the sole conscious opt-out. | PARTIAL |
| REQ-API-EXPORT-004 | End-to-end: a real Breach-category module's evidence (Evidence{source: module name(), summary: the module's own capitalised-brand text, e.g. "DeHashed record from Adobe"}) and its ModuleDone scan event, once persisted and downloaded through the live HTTP… | Ran `cargo test --test api temp_probe_end_to_end_redaction_across_all_four_download_formats -- --nocapture` this pass (test added then reverted). Real output: entities.csv `sources` column = `breach-source\|breach-source`, `evidence` column = `[breach-source] breach-source record from Adobe \|\| [breach-source] breach-source record from MyFitnessPal`; report.json `"source": "breach-source"`, `"summary": "breach-source record from Adobe"` / `"...MyFitnessPal"`; events.log both lines read… | VERIFIED |
| REQ-API-EXPORT-005 | Candidate quarantine (speculative breach-victim entities tagged CANDIDATE) is excluded by default from both scan_entities_csv and scan_export_gexf, opt-in via `?include_candidates=1` — matching the same policy the `/entities` JSON endpoint and report.json… | Ran `cargo test --test api scan_gexf_quarantines_candidate_nodes_by_default -- --nocapture` this pass — `test result: ok. 1 passed`. Separately wrote and ran (then reverted via `git checkout -- tests/api.rs`) a temporary CSV-equivalent probe: default entities.csv response omitted `stranger@breach.example` entirely while including `subject@real.example`; `?include_candidates=1` response included the candidate row with `tags` column `candidate`. `test result: ok. 1 passed`. | PARTIAL |
| REQ-API-EXPORT-006 | Every scan-scoped export (CSV/JSON/GEXF via download_response; the debug bundle via download_response_operator) names its download `hse-<stem>-<short_id>.<ext>` with the scan id truncated to 12 characters, and every download (scan-scoped or system-scoped)… | Ran `cargo test --lib api::scan_export -- --nocapture` this pass: `test api::scan_export::tests::download_response_sets_attachment_disposition_with_scan_scoped_filename ... ok` / `test api::scan_export::tests::attachment_response_uses_the_filename_verbatim_for_system_downloads ... ok` (part of the 8/8 passing run). | VERIFIED |

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

This section exists purely to close the ledger's own blind spot — the
correlator subsystem had no representation here at all before Pass 4, even
though its underlying protections were already comprehensive. No code
changed for this row; the fix is documentary.

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

## Summary statistics

| Status | Pass 1 | Pass 2 | Pass 3 | Pass 4 | Pass 5 | Pass 6 | Pass 7 | Pass 8 | Pass 9 |
|---|---|---|---|---|---|---|---|---|---|
| VERIFIED | 23 | 30 | 50 | 53 | 54 | 55 | 56 | 58 | 59 *(REQ-API-SCAN-006 fixed in Pass 9)* |
| IMPLEMENTED_UNVERIFIED | 17 | 12 | 14 | 14 | 14 | 14 | 14 | 13 *(REQ-INSTALL-001 out, fixed; REQ-INSTALL-010 in as new then confirmed VERIFIED by this PR's own CI run before merge — net -1)* | 13 |
| PARTIAL | 8 | 7 | 19 | 19 | 18 *(REQ-API-MISC-003 fixed in Pass 5)* | 17 *(REQ-API-SCAN-007 fixed in Pass 6)* | 16 *(REQ-API-SCAN-002 fixed in Pass 7)* | 16 | 16 |
| MISSING | 1 | 1 *(REQ-ENV-003, unchanged — see Pass 1's "Fix selection rationale")* | 1 | 0 *(REQ-ENV-003 fixed in Pass 4)* | 0 | 0 | 0 | 0 | 0 |
| AMBIGUOUS | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| OBSOLETE (by design, not a gap) | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |
| BROKEN | 0 | 0 | 0 *(REQ-API-MISC-004 was BROKEN before Pass 3's fix; now VERIFIED, counted above)* | 0 | 0 | 0 | 0 | 0 | 0 |
| UNREACHABLE | 0 | 0 | 1 *(REQ-API-SCAN-006 — real, but lower-severity than the BROKEN finding; not fixed in Pass 3, see section 6)* | 1 *(REQ-API-SCAN-006, unchanged)* | 1 *(REQ-API-SCAN-006, unchanged)* | 1 *(REQ-API-SCAN-006, unchanged)* | 1 *(REQ-API-SCAN-006, unchanged)* | 1 *(REQ-API-SCAN-006, unchanged)* | 0 *(REQ-API-SCAN-006 fixed in Pass 9)* |
| **Total rows** | **51** | **51** | **86** | **88** | **88** | **88** | **88** | **89** | **89** |

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
so `VERIFIED` rises from 58 to 59 and `UNREACHABLE` drops from 1 to 0.

Breakdown by section: Module trait contract 14 rows (REQ-CORE-001..014), CLI
surface 12 rows (REQ-CLI-001..012), `install.sh` 10 rows
(REQ-INSTALL-001..010), Env/config 6 rows (REQ-ENV-001..006), README claims 10
rows (REQ-README-001..010), HTTP API surface 35 rows (REQ-API-ROUTE-001..007,
REQ-API-AUTH-001..004, REQ-API-SCAN-001..010, REQ-API-MISC-001..008,
REQ-API-EXPORT-001..006), Scan engine dispatch 1 row (REQ-ENGINE-001),
Correlator rule registry 1 row (REQ-CORRELATOR-001) —
14+12+10+6+10+35+1+1 = 89, matching the total above.
Some rows cite tests shared across sections (e.g. REQ-CORE-010 and
REQ-README-009 both cite `every_module_maps_to_valid_attack_reconnaissance_techniques`),
which is intentional — the two rows document the same underlying test from
two different requirement angles (the trait contract vs. the README's claim
built on it).
