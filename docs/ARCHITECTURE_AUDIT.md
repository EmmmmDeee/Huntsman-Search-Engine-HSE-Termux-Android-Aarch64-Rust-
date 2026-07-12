# Architecture Reference — Huntsman Search Engine (HSE)

> Current-state architecture overview. HSE is a pure-Rust OSINT / GEOINT / NETINT
> platform whose baseline runtime is **Termux Android aarch64 (no root)**.
> This document describes the system **as built**; open defects and the forward
> plan live in [`PROBLEM_TREE.md`](PROBLEM_TREE.md) (the living problem +
> capability tree), which is the single source of truth for what to change.

## Facts (verified against the tree, 2026-07-11)

| Metric | Value |
|---|---|
| Version / edition / MSRV | 1.13.0 · edition 2024 · 1.88 |
| Source | ~231k lines · 807 `.rs` files |
| Modules | **162** registered — 129 Free · 28 KeyGated · 5 Paid · 14 categories |
| Correlation rules | **109** deterministic — 97 entity-only (`correlator::RULES`) + 12 graph-aware (`RELATION_RULES`), one function per distinct `AU-###` finding |
| Tests | **4,561** lib tests (`cargo test --lib -- --list`) + API/integration + architecture guards |
| Unsafe | **0** — `#![forbid(unsafe_code)]` (`src/lib.rs:22`; `[lints.rust] unsafe_code = "forbid"` in `Cargo.toml`) |
| Panic strategy | `panic = "unwind"` (`Cargo.toml [profile.release]`) + per-module `catch_unwind` at the dispatch boundary — a hostile/drifted provider tripping a panic degrades to one module error, not a downed `hse serve` process |
| Dependencies | 298 locked packages (`Cargo.lock`) · **0** AI/ML/LLM/vector (guard-enforced, `runtime_carries_no_ai_ml_inference_dependency`) |
| HTTP / DB | reqwest 0.12 (rustls, no native-TLS) · rusqlite 0.39 bundled (WAL + FTS5) · axum 0.8 |
| Release profile | `opt-level="s"`, `lto=true`, `codegen-units=1`, `strip=true` — plus a `[profile.fast]` (`opt-level=2`, no LTO, `codegen-units=16`) for faster on-device iteration builds |
| Runtime | tokio, `WORKER_THREADS=2` / `MAX_BLOCKING_THREADS=16` (Termux-tuned; bounds peak memory) |

**Module categories (sum = 162):** Social 36 · Geo 22 · Infrastructure 20 ·
People 16 · Corporate 14 · DnsRecon 13 · Breach 12 · Web 7 · Email 6 · Sensor 4 ·
Phone 4 · Threat 3 · Other 3 · Search 2.

**Two version-pinned dependencies, with the exact reason recorded in `Cargo.toml`:**
- `reqwest = "0.12"` — 0.13's rustls integration reads the OS cert store via
  Android JNI / an app `Context`, unavailable to a Termux CLI process. A move to
  0.13 needs `rustls-no-provider` + a hand-built `ClientConfig`, validated
  on-device first.
- `rusqlite = "0.39"` — 0.40 pulls `libsqlite3-sys` 0.38, whose build script
  needs the unstable `cfg_select!` (stabilises above MSRV 1.88). Do not bump
  without a toolchain audit.

## Dependency direction

```
 bin (main.rs) ─▶ cli ─┐
                       ├─▶ core ─▶ util (http, keys, geo, datasets, …)
 http (api/axum) ──────┘    │
 web (embedded SPA) ◀─ api  ├─▶ correlator (109 rules)
                            └─▶ storage (rusqlite WAL + FTS5, via StoragePort)
 modules (162) ─▶ core types + core::hooks (fn-ptr registry, installed at startup)
```

**Invariant (enforced):** `core` is module-agnostic — the engine drives modules
through `modules::registry()`, never the reverse. The one deliberate
`modules → core` wiring edge is hook installation: the module layer installs a
5-field function-pointer registry into `core::hooks`
(`reset_per_scan`, `set_regional`, `refresh_round_budget`, `identify_api_key`,
`drain_found_keys`), which `core` calls through instead of ever naming
`crate::modules`.

**Enforcement (`tests/architecture.rs`):** guards `core → util`
(`core_does_not_import_util_directly`, allowlisted exceptions only), `core →
storage` (`core_does_not_import_storage_directly`), `core → modules`
(`core_does_not_import_modules`), and `modules → engine/storage`
(`modules_do_not_import_engine_or_storage`); also pins the module registry
(`modules_md_lists_every_registered_module`), the README module count
(`readme_module_overview_count_matches_registry`), non-passive modules'
timeout budgets (`non_passive_modules_budget_above_default`), the
`StoragePort` object-safety proof (`storage_port_is_object_safe`), and
runtime AI-independence (`runtime_carries_no_ai_ml_inference_dependency`).
The `core → modules` edge was inverted via `core::hooks` in **T1.4**
(`PROBLEM_TREE.md` §3.1, done) — no laundering allowlist remains.

## Core subsystems

- **`core::engine`** (`src/core/engine/`) — the scan driver: `mod.rs`
  orchestrates a seed round (every accepting module fired once) followed by
  up to `depth` expansion rounds; mechanism lives in satellites — `dispatch`
  (priority waterfall: Phase 1 Paid → discovered-key hot-inject → Phase 2
  Free/KeyGated concurrent, Semaphore/JoinSet-bounded), `expansion`
  (recursive rounds gated by `c_effective ≥ min_expand_confidence`, six
  independent halting mechanisms — depth cap, entity/wall-time budget, a
  watchdog thread, a visited-set cycle guard, ROI-cutoff, adaptive-yield
  termination), `circuit` (a process-global breaker: rate-limit/quota errors
  trip 600s, other hard errors trip after 3 consecutive soft failures for
  120s), `timeout` (per-module resolution, clamped to a 45s
  `TERMUX_MODULE_TIMEOUT_CAP_MS` on Termux unless the module opts out via
  `termux_timeout_cap_exempt()`), `enrich` (geo + key harvest), `ledger`
  (dedup/lineage). A panicking module is caught at the dispatch boundary
  (`run_module_guarded`), so it degrades to a module error rather than
  aborting the process.
- **`core::correlator`** (`src/core/correlator/rules/`) — 109 deterministic
  rules across `assoc`/`breach`/`broker`/`crypto`/`gap`/`geo`/`infra`/
  `identity`/`integrity`/`location`/`multipath`/`org`/`resolved`/`sim`/
  `template`/`transitive`, synthesising entities into findings;
  candidate-quarantine before correlation. The recursive-linking family —
  `transitive` (AU-060), `multipath` (AU-062), `gap` (AU-063), `template`
  (AU-064), `resolved` (AU-067), `integrity` (AU-069), `broker` (AU-070),
  `robust` (AU-071) — all delegate to the shared `core::relation::graph`
  link-analysis primitives (`identity_paths`, `disjoint_pathways`,
  `resolve_identity_clusters`, `strongest_path`, `connection_brokers`) that
  also back the dossier CONNECTIONS section, so rule verdicts and the
  rendered chains can't drift: `multipath` rewards a link confirmed by
  independent routes, `gap` names the orthogonal source family that would
  corroborate a single-route link, `template` generalises a repeated route
  into a reusable attribution pattern, `resolved` collapses every
  transitively-linked identity into one resolved identity (the
  equivalence-class capstone, weakest-link confidence), `integrity` rewards
  the max-bottleneck route — a connection reliable at every hop, not merely
  present — `broker` names the identity articulation point: the single node
  whose removal would fragment ≥3 otherwise-linked identities (node
  criticality, the analyst's prime pivot) — and `robust` reports the
  complement: a resolved cluster that NO broker can split, so its identities
  stay bound after removing any one connector (cluster-level redundancy, the
  highest-confidence single-identity conclusion). `rank_and_sort` (shared by
  the finalise pass and the live incremental pass) additionally unions each
  correlation's child entities' MITRE ATT&CK techniques into a
  `techniques` field and applies a technique-diversity tie-break — a
  conclusion corroborated across more *distinct* techniques (orthogonal
  collection methods) ranks above one re-derived under a single technique,
  at equal severity/confidence.
- **`core::{scan,entity,relation,timeline}`** — the typed domain model.
  `uid = SHA-256(kind:normalised_value)`. Confidence fusion:
  `C_eff = clamp(max(multiplicative, agreement), 0, 1)`, where
  `multiplicative = confidence × (1 + 0.15·ln n)` and the noisy-OR
  `agreement = 1 − (1−confidence)·0.65^(n−1)`, `n` = distinct corroborating
  sources (floored at 1). A three-tier classification ladder derives purely
  from `C_eff`: **Candidate** (< 0.40) / **Probable** (0.40–0.75) /
  **Verified** (≥ 0.75) — single-sourced in `Classification::{VERIFIED_MIN,
  PROBABLE_MIN, from_c_eff}`, so a tier threshold literal outside `entity.rs`
  is a bug. `merge()`/`absorb()` use GREATEST semantics (confidence = max,
  corroboration sums, evidence/tags deduped and unioned) — confidence only
  ever rises, never falls, on a genuine merge.
- **`core::attack`** — a curated 33-technique MITRE ATT&CK TA0043
  (Reconnaissance) catalogue. Every module maps by category default
  (`techniques_for_category`), overridable where the category is too coarse;
  a drift-guard test rejects any unmapped module or out-of-catalogue
  technique ID. The mapping is woven into the data, not a side report: at
  the single admission point (`engine::finalise_module_result`) every
  admitted entity is stamped inline with the producing module's
  technique(s) as `attack:<TECHNIQUE_ID>` tags, so the technique that
  collected each datum travels with it through JSON output, the dossier,
  and the DB; cross-module merges union the tags. A parent/sub-technique
  rollup (`core::attack::coverage`) turns the per-datum tags into a
  scan-level Navigator-style coverage/gap report — which catalogued
  techniques a scan exercised versus left dark — with no STIX bundle
  vendored.
- **`modules`** (162) — OSINT sources, each implementing `Module` (3
  mandatory methods — `name`, `priority`, `accepts` — plus `async fn
  process`; the rest defaulted), registered in `modules::registry()` by a
  one-file change (create `src/modules/foo.rs`, `pub mod foo;`, push
  `Arc::new(foo::Foo)`). `ModuleCost` (Free / KeyGated / Paid) gates the
  scan's free-only filter; the engine sources ATT&CK technique IDs from the
  dispatched `Module` trait object (`Module::attack_techniques`), never
  `crate::modules` directly — the `core ↛ modules` guard stays green.
- **`storage`** (`src/storage/`) — the single `StoragePort` implementation
  over rusqlite (WAL + FTS5): events, entities, correlations, relations, the
  inter-scan entity cache (`raw_archive`), and the cross-scan
  `pathway_templates` store (a route confirmed in one scan is credited in
  every later scan via the engine-emitted AU-065 cross-scan finding, and a
  fragile single-pathway link whose route shape is proven in ≥2 prior scans
  is resolved by the engine-emitted AU-066 cross-scan gap-fill). Both are
  storage-dependent, so they are emitted by the engine at finalise, not by
  pure correlator rules, and are distinct from the 109 correlator rules.
  `StoragePort` is compile-time proven `Send + Sync + 'static` and dyn-safe
  (`assert_dyn_send_sync_static::<dyn StoragePort>()`) — ~11 call sites
  share one `Arc<dyn StoragePort>` across tokio tasks.
- **`api`** (axum 0.8) — versioned `/api/v1`, SSE live stream, embedded SPA;
  CSP + `127.0.0.1`-only bind (architecture invariant — no LAN exposure by
  default).
- **`util`** — HTTP client (rustls, SSRF-guarded DNS resolution rejecting
  private/reserved resolved addresses, redirect chains capped at 10 hops and
  blocked to any private next-hop; no blanket client-level timeout — a prior
  3s client timeout was removed because it silently overrode larger
  per-module budgets; bounded instead per-call via `tokio::time::timeout`),
  key pool (multi-key rotation by tier/health/LRU, `~/.huntsman/key_pool.json`
  at mode `0600`), atomic `0600` file writes, geo, log-capture ring buffer,
  settings/toggles.

## Determinism doctrine

Identical inputs produce identical outputs, independent of `HashMap`
iteration or task-completion order: sort by UID before any order-sensitive
fold, deterministic tie-breaks in every ranking comparator (NaN handled
explicitly), canonicalised evidence/tag order before persistence, ids
derived by hashing canonical inputs. New order-sensitive code requires a
permutation test (see `docs/CONVENTIONS.md` §5). This is a hard invariant,
not a style preference — a scan's persisted content must be a pure function
of the entity set it discovered, never of the order modules happened to
complete in.

## End-to-end flow

`hse scan` / `POST /api/v1/scans` → target validation → `engine.run` →
priority-ordered guarded dispatch → entities persisted (FTS-indexed) + events
broadcast (SSE) → expansion rounds → `correlator.run` → diagnostics → CLI
table / dossier / JSON, or the SPA.

All three entry points apply the **same comprehensive scan defaults**: a
`POST /api/v1/scans` with `options` omitted (or any field omitted), and the
Chrome-SPA "New Scan" wizard, both default to depth 3 / expansion floor 0.20 /
entity cap 2500 — exactly what `hse scan` uses. The API defaults flow from
`ScanRequest`'s serde field defaults (`core::scan::options`); the SPA submits
the same values from `buildWizardOptions()`. The library `ScanOptions::default()`
is deliberately decoupled and stays conservative (depth 0, floor 0.50,
uncapped) so programmatic callers and the test suite remain deterministic.

## CI / supply chain

- **`ci.yml`** — `fmt --check`, `clippy --all-targets -D warnings`,
  `test --all`, all `--locked`, plus an **aarch64-linux-android** cross-build
  proving the Termux baseline.
- **`audit.yml`** — `cargo audit` (RustSec) + `cargo deny check`
  (licence/ban/source policy) + `cargo machete` (unused dependencies).
- **`live-drift.yml`** (ignored live-network drift tests) and **`release.yml`**.

## The gate

A change is complete only when all of `cargo fmt --check`, `cargo clippy
--all-targets` (zero warnings), `RUSTDOCFLAGS="-D
rustdoc::broken_intra_doc_links" cargo doc`, and `cargo test` pass — plus,
for behaviour-touching changes, running the affected surface for real
(`hse selftest`, or the command itself). See `docs/CONVENTIONS.md` §9.

## Posture

The foundations are sound: a typed domain model, deterministic offline-capable
logic, 0 unsafe, rustls + bundled SQLite (no C / native-TLS), enforced runtime
AI-independence, `0600` atomic secrets, and a loopback-only server. The layering
invariants (incl. `core → modules`, T1.4) are guarded by the architecture test
suite. The remaining open engineering work — correctness, performance,
coverage, and capability expansion — is enumerated and prioritised in
[`PROBLEM_TREE.md`](PROBLEM_TREE.md). No ground-up rewrite is warranted; the
work is targeted hardening and capability expansion.
