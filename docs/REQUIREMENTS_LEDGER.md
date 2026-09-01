# Requirements Traceability Ledger

**Scope.** This ledger covers HSE's cross-cutting *core contracts*, not the
individual scanning modules' business logic — that was the subject of a
separate, now-complete module-by-module bug audit under
`src/modules/*/mod.rs` (Phases 0-10, PRs #553-568, merged; every one of the
188 registered modules read against an established bug-class checklist). The
areas covered here, across two passes:

1. The `Module` trait contract (`src/core/module/mod.rs`).
2. The CLI surface (`src/main.rs`, `src/cli/`).
3. `install.sh`.
4. The env/config template and key consumption.
5. Top-level `README.md`'s stated capabilities/counts.

**Pass 2** (this pass) re-verified every row Pass 1 left
`IMPLEMENTED_UNVERIFIED`/`PARTIAL`/`AMBIGUOUS` by actually running its cited
test or command, resolved the one genuinely missing behavioral test found
(REQ-CORE-009, the inter-scan cache's dispatch-level hit/miss path), and
closed the one documented ambiguity (REQ-README-004) with a one-paragraph
README clarification plus a drift-guard extension. See "Pass 2 findings"
below for the full account. It does **not** claim to have reconstructed
requirements for the *entire* codebase (the API surface, the correlator, the
storage layer, the web/WASM UI, and `hse-ai-daemon` remain out of scope for
both passes) — see "Known limitations" for why, and for what a further pass
would need to cover.

**How to read this ledger.**

- **Status** is one of `VERIFIED | IMPLEMENTED_UNVERIFIED | PARTIAL | MISSING |
  BROKEN | UNREACHABLE | OBSOLETE | AMBIGUOUS`. `VERIFIED` requires an actual
  passing test and/or a command this pass personally ran and confirmed the
  output of — code that merely *looks* correct is `IMPLEMENTED_UNVERIFIED` at
  best.
- **Runtime verification evidence** states plainly whether this pass executed
  anything, or only read source. Existing architecture tests
  (`tests/architecture_parts/*.rs`, ~55 tests as of this pass) are treated as
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

**Known limitations of Pass 2 — what a further pass would need to cover.**
This ledger's 5 sections are the core contracts a Rust CLI/module-engine tool
built around: the `Module` trait, the CLI, the installer, the env/config
template, and the README's own claims about them. Deliberately still **not**
covered by either pass, and not claimed as VERIFIED/MISSING/etc. anywhere
above:

- **The HTTP API surface** (`src/api/` — routes, auth middleware, scan
  lifecycle handlers, settings/cells/key-harvest/update handlers, scan
  export/redaction). This is `hse serve`'s actual remote-facing product
  surface and the highest-value candidate for the next pass.
- **The scan engine's internals beyond dispatch** (`src/core/engine/` past
  the `Module` trait boundary — expansion, ROI/budget pruning, the
  correlator's ~109 rules in `src/core/correlator/`).
- **The storage layer's own contracts** (`src/storage/` — schema migrations,
  the SQLite `Store`'s full method set beyond what Pass 2's one fix touched).
- **The web/WASM UI** (`src/web/`, `wasm-ui/`) and the embedded SPA served by
  `src/api/routes/mod.rs`.
- **`hse-ai-daemon`** (`src/bin/hse_ai_daemon`) and the other `src/bin/*`
  utilities (`architecture_audit`, `dep_cooldown`, `gen_oui`).
- **Docs beyond `README.md`** — `docs/*.md` carries dozens of other files
  (setup guides, prior audit reports) not cross-checked against current code
  in either pass.

None of this is a claim that these areas are broken or unverified in some
absolute sense — only that this ledger has not yet looked at them, and a
reader should not infer completeness beyond the 5 sections it actually
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
| REQ-INSTALL-001 | Detects and rejects a Play Store Termux install (abandoned since 2020) via the `termux-build-info` marker, before doing anything else. | `/data/data/com.termux/files/usr/etc/termux-build-info` presence/contents | `die` with remediation message | Process exit 1 | Prints exact remediation (F-Droid link) via `die()`. | `install.sh:204-216` | No dedicated shell test found; `tests/install_invariants.rs` covers other invariants (wake-lock, TTY) but not this one. | Read-only. | IMPLEMENTED_UNVERIFIED |
| REQ-INSTALL-002 | `pkg`/apt index refresh retries up to 4 attempts with backoff (`2s, 4s, 6s`) before failing with actionable guidance (`termux-change-repo`). | Network/mirror state | Package manager state | Repeated `pkg update` invocations | `die` after 4th failed attempt, naming the fix. | `install.sh:625-632` | Not unit-testable (shell, network-dependent); no test found. | Read-only. | IMPLEMENTED_UNVERIFIED |
| REQ-INSTALL-003 | `cargo build` is retried up to 3 attempts with backoff (`3s, 6s, 9s`) to tolerate flaky mobile networks mid-build (crate downloads), per the README's "retrying on flaky mobile networks" claim. | Network state during build | Compiled binary or failure | Repeated `cargo build` invocations | `die` after 3rd failed attempt, pointing at the log file. | `install.sh:909-926` | Not unit-testable; no test found. | Read-only — but the claim is directly backed by inspectable retry-loop code, so this is a substantive match, not a bare assertion. | IMPLEMENTED_UNVERIFIED |
| REQ-INSTALL-004 | Prefers a prebuilt aarch64 binary over a source compile (Downloads-folder scan, then GitHub Releases download with size+ELF+`.sha256`+run-test verification); this is also the automatic fallback when an on-device build can't proceed. | `HSE_PREBUILT`, `HSE_PREBUILT_TAG`, `HSE_NO_DOWNLOAD`, `HSE_PREFER_BUILD`, `HSE_KEEP_MIRROR` env knobs | Installed `hse` binary | Writes to `$PREFIX/bin`, may write to Downloads cache | Falls through to source build if no valid prebuilt is found/verified. | `install.sh:322-668` (`resolve_target_sha`, `_prebuilt_sha_matches`, `_validate_prebuilt`, `maybe_use_prebuilt`, `maybe_download_prebuilt`, `_try_download_release`) | No dedicated automated test; `docs/INSTALL.md`'s "Environment knobs" table documents the same knob set this pass found live in the script (cross-checked by grep: all 8 knobs present in both). | Ran `grep -c` for each of the 8 documented knobs against `install.sh` this pass — every one has ≥3 occurrences, confirming they are wired, not just documented. | IMPLEMENTED_UNVERIFIED |
| REQ-INSTALL-005 | After building/installing the binary, delegates key-template provisioning to `hse provision --env-only --discover` (the Rust-native env-merge), rather than maintaining a second hand-copied template in the shell script. | none | Writes/merges `~/.huntsman.env` | Backs up existing file before changes (per `hse provision`'s own contract) | `log_warn` (non-fatal) if `hse provision` itself fails — install still completes. | `install.sh:1548-1558` | `hse provision`'s own merge/backup logic is covered by `src/cli/provision/tests.rs` (17 tests) — not re-run this pass. `env_template_keys_are_all_consumed` (architecture test) separately guards the template's own content. | Read-only for the install.sh call site; the delegate's test suite exists but wasn't re-run this pass. | IMPLEMENTED_UNVERIFIED |
| REQ-INSTALL-006 | Cross-platform: also works on Debian/Ubuntu (apt-get) and macOS (Darwin branch), not just Termux. | `uname -s` | OS-specific package install commands | `apt-get`/Homebrew-equivalent invocations | Unhandled OS falls through (not exhaustively checked this pass). | `install.sh:222-223,639-643` | No dedicated test (would require actual non-Termux CI runners). | Read-only; confirmed the `Linux`+`apt-get` and `Darwin` branches exist and dispatch to real package-install commands. | IMPLEMENTED_UNVERIFIED |
| REQ-INSTALL-007 | Self-heals a broken Termux `rust` package (ships libstd without a static `.rlib`) by reinstalling it automatically before attempting a build, per `docs/INSTALL.md`'s troubleshooting entry. | Detected build error signature | `apt-get install -y --reinstall rust` | Package reinstall | Falls through to the manual-fix message documented in `docs/INSTALL.md` if the self-heal itself fails. | `install.sh:709` | No dedicated test; matches the documented troubleshooting text closely (cross-checked by hand). | Read-only. | IMPLEMENTED_UNVERIFIED |
| REQ-INSTALL-008 | `hse-bg` background wrapper acquires the shared Android wake-lock through a refcounted helper (never releases it directly), and does not hardcode the Termux `$PREFIX` path. | none | Generated wrapper script | Manages `termux-wake-lock`/`termux-wake-unlock` | A wrapper that releases the lock directly, or hardcodes the prefix, breaks multi-wrapper coexistence / non-standard `$PREFIX` installs. | `install.sh` (wrapper-generation heredoc, ~line 1166-1273) | `generated_wrappers_never_release_the_shared_wake_lock_directly`, `wrappers_acquire_the_wake_lock_through_the_refcounted_helper`, `long_running_wrappers_actually_manage_the_shared_wake_lock`, `generated_wrappers_do_not_hardcode_the_termux_prefix` (`tests/install_invariants.rs`) | Ran `cargo test --test install_invariants` this pass — all 5 tests passed (see full output below). | VERIFIED |
| REQ-INSTALL-009 | TTY detection for interactive prompts happens *before* stdout is redirected into a pipe/log tee, so a piped `curl \| bash` invocation doesn't wrongly think it's interactive. | none | Boolean gate for interactive-only prompts | none | An interactive prompt issued after redirection would hang a piped/non-interactive install forever waiting for input that can never arrive. | `install.sh` (early in the script, before the log-tee redirection) | `tty_detection_happens_before_stdout_is_redirected_into_a_pipe` (`tests/install_invariants.rs`) | Ran `cargo test --test install_invariants` this pass — passed. | VERIFIED |

---

## 4. Env/config template and key consumption

| ID | Behavior | Inputs | Outputs | Side effects | Failure behavior | Implementation location | Tests covering it | Runtime verification evidence | Status |
|---|---|---|---|---|---|---|---|---|---|
| REQ-ENV-001 | Every `HUNTSMAN_*` key declared in the canonical provisioning template (`src/cli/env_template.txt`) is genuinely read somewhere in `src/` (an `_ENV` const, a `ctx.key`/`key_opt` call, a `fetch_keyed_json` literal, or a raw `env::var` read), or is explicitly listed `[RESERVED]`/`NOT_YET_WIRED`. | Template file content, `src/` source tree | Pass/fail assertion | none | Guards the "documented key that silently does nothing" bug class (previously true of 6 real keys). | `src/cli/env_template.txt`; guard in `tests/architecture_parts/architecture_part3.rs:278-348` | `env_template_keys_are_all_consumed` | Ran `cargo test --test architecture env_template_keys_are_all_consumed` this pass — passed. | VERIFIED |
| REQ-ENV-002 | No module under `src/modules/` reads a `HUNTSMAN_*` credential via a raw `std::env::var(...)` call bypassing `ModuleContext::key`/`key_opt` (which is the sole enforcement point for the blank/placeholder filter); the two sanctioned non-credential exceptions (`HUNTSMAN_SEARCH_PROXY`, `HUNTSMAN_EMAIL_DOMAINS`) are allow-listed and anti-rot-checked. | `src/modules/` source tree | Pass/fail assertion | none | A credential read raw would forward an un-edited template placeholder to a provider as a live request. | `tests/architecture_parts/architecture_part3.rs:767-850` | `modules_never_read_credentials_via_raw_env` | Ran `cargo test --test architecture modules_never_read_credentials_via_raw_env` this pass — passed. | VERIFIED |
| REQ-ENV-003 (**inverse gap — see fix below**) | The env var consumption guards above (REQ-ENV-001/002) only ever scan for **`HUNTSMAN_`-prefixed** literals (`push_huntsman_literal` requires the literal to start with `"HUNTSMAN_"`); any env var read via `std::env::var`/`var_os` under a *different* prefix is invisible to both tests, so it can be genuinely load-bearing yet fully undocumented with no test noticing. | Full `src/` tree | n/a | n/a | A tuning knob under this blind spot can drift silently (renamed, removed, or simply never documented) with zero test coverage. | Test blind spot in `tests/architecture_parts/architecture_part3.rs:350-365` (`push_huntsman_literal`) | None — this is the absence being reported. | Ran `grep -rEo 'env::var(_os)?\("[A-Za-z0-9_]+"\)' src/` this pass and cross-referenced every result against `.env.example`, `src/cli/env_template.txt`, `README.md`, and `docs/*.md`. Found 4 real, undocumented, non-`HUNTSMAN_`-prefixed knobs that are genuinely read and consumed: `HSE_OATHNET_PER_SCAN_LIMIT`, `HSE_OATHNET_DAILY_LIMIT`, `HSE_SEE_KNOW_PER_SCAN_LIMIT`, `HSE_WIGLE_PER_SCAN_LIMIT` (all in `src/util/quota_config.rs`, feeding `oathnet_quota()`/`see_know_quota()`/`wigle_quota()`, which `src/util/oathnet/mod.rs` genuinely calls to seed its `QuotaBudget`). They appear nowhere outside `quota_config.rs`'s own doc comment and its own unit tests. Each has a sane, harmless default and is superseded at runtime by the separately-documented `HUNTSMAN_OATHNET_SCAN_CAP`/`HUNTSMAN_SEEKNOW_SCAN_CAP`/`HUNTSMAN_WIGLE_*_SCAN_CAP` overrides, so the practical operator impact is low (an advanced/testing knob, not a feature an operator would reach for) — this was considered as the pass's one fix but deprioritized below in favor of the higher-visibility README fix (see "Fix selection rationale"). | MISSING |
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

## Summary statistics

| Status | Pass 1 | Pass 2 |
|---|---|---|
| VERIFIED | 23 | 30 |
| IMPLEMENTED_UNVERIFIED | 17 | 12 |
| PARTIAL | 8 | 7 |
| MISSING | 1 | 1 *(REQ-ENV-003, unchanged — see Pass 1's "Fix selection rationale")* |
| AMBIGUOUS | 1 | 0 |
| OBSOLETE (by design, not a gap) | 1 | 1 |
| BROKEN | 0 | 0 |
| UNREACHABLE | 0 | 0 |
| **Total rows** | **51** | **51** |

Breakdown by section: Module trait contract 14 rows (REQ-CORE-001..014), CLI
surface 12 rows (REQ-CLI-001..012), `install.sh` 9 rows
(REQ-INSTALL-001..009), Env/config 6 rows (REQ-ENV-001..006), README claims 10
rows (REQ-README-001..010) — 14+12+9+6+10 = 51, matching the total above.
Some rows cite tests shared across sections (e.g. REQ-CORE-010 and
REQ-README-009 both cite `every_module_maps_to_valid_attack_reconnaissance_techniques`),
which is intentional — the two rows document the same underlying test from
two different requirement angles (the trait contract vs. the README's claim
built on it).
