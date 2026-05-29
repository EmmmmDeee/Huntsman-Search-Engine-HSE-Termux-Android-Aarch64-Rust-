# Architectural Blueprint

> **Status:** authoritative, code-grounded. Every claim below cites a real
> symbol or `path:line` you can open. Where the older [`ARCHITECTURE.md`](ARCHITECTURE.md)
> drifted from the tree, this document is the source of truth and the drift is
> logged in [§8 Integrity Audit](#8-integrity-audit).

This is the actionable blueprint requested of the platform: it parses the
engineering constraints into the three structural views that matter —
**the entry point**, **the modular boundaries**, and **the graph data-fabric
lifecycle** — and then maps each high-level constraint to the concrete
mechanism that satisfies it.

HSE is a single-binary, pure-Rust, recursive OSINT/GEOINT platform built to run
natively inside **Termux on Android (aarch64), no root**. It is a plugin-style
registry of **85 modules** feeding a module-agnostic `ScanEngine` that merges
their findings into a deterministic entity graph, pivots recursively on
high-confidence nodes, correlates the result against 30 declarative rules, and
surfaces everything over a CLI, a localhost HTTP API, and an embedded SPA.

---

## Table of contents

1. [Constraint → implementation matrix](#1-constraint--implementation-matrix)
2. [Entry point & runtime topology](#2-entry-point--runtime-topology)
3. [Modular boundaries (the dependency DAG)](#3-modular-boundaries-the-dependency-dag)
4. [The graph data-fabric lifecycle](#4-the-graph-data-fabric-lifecycle)
5. [Recursive discovery loop & adaptive pivoting](#5-recursive-discovery-loop--adaptive-pivoting)
6. [Enforcement gates & hardening](#6-enforcement-gates--hardening)
7. [Forward optimization levers](#7-forward-optimization-levers)
8. [Integrity audit](#8-integrity-audit)

---

## 1. Constraint → implementation matrix

The directive's constraints are not aspirational here — each is already pinned
to a mechanism and, where possible, to an automated test that fails CI if the
property regresses.

| # | Constraint | Mechanism | Enforced by |
|---|------------|-----------|-------------|
| 1 | **100% Rust, strict typing** | `#![forbid(unsafe_code)]` at crate root; edition 2024; typed `core::error::Error` (`thiserror`) | `lib.rs:15`; compiler |
| 1 | **Acyclic dependencies** | `core ⊥ modules`, `core/api ⊥ storage::Store` (only `StoragePort`), `modules ⊥ engine/storage` | `tests/architecture.rs` (static source scan) |
| 1 | **Zero-cost abstractions** | O(1) dispatch index replaces O(M) `accepts()` scan; index-iteration avoids per-target `Arc` clones | `core/dependency.rs` `ModuleGraph`; `engine.rs:703,833,920` |
| 1 | **aarch64 / Termux / no root** | rustls-only (no OpenSSL/C), bundled SQLite, localhost bind, Termux sensors shell out to packaged binaries | `Cargo.toml:27-28`; `util::termux` |
| 1 | **Low overhead / memory** | 2 tokio workers; sequential dispatch default; response cache; budget caps; `entity_map` capacity clamp; mmap-tunable SQLite | `main.rs:3`, `lib.rs:26`, `engine.rs:198-199` |
| 1 | **Single-binary recursive SpiderFoot** | `default-run = "hse"`; embedded SPA; `run_expansion` recursive walk | `Cargo.toml:9`; `engine.rs:341` |
| 2 | **Shared data fabric** (instant framework-wide propagation) | per-scan `entity_map` (GREATEST-merge) + SQLite store + `entity_observations` junction + `EventBus` + **key-pool hot-inject** | `engine.rs:623,300-304,358-367` |
| 2 | **Graph engine / entity-linking** | `ModuleGraph` (dispatch + richness), the correlator's 30 entity-linking rules, **and first-class typed `Relation` edges** (`SubdomainOf` / `BelongsToDomain` / `HostedOn`); GEXF export + D3 force graph | `core/dependency.rs`, `core/correlator/`, `core/relation.rs`, `core/gexf.rs` |
| 2 | **Discovery loops / adaptive pivoting** | `run_expansion`: depth-bounded DFS with ROI saturation-pruning, top-K gating, adaptive-depth termination, 4 expansion strategies | `engine.rs:341-510`, `core/roi.rs`, `core/scan.rs` |
| 3 | **Code quality / static+dynamic verification** | CI: `fmt --check`, `check --locked`, `clippy -D warnings`, `test --all`, MSRV 1.88, shellcheck | `.github/workflows/ci.yml` |
| 3 | **Resilience / regression testing** | 1,254 tests green (1173 lib + 36 API + 8 architecture + 37 smoke); per-module timeout; `panic = "abort"` | `tests/`, `engine.rs:752`, `Cargo.toml:64` |
| 3 | **Hardening / deterministic execution** | SSRF preflight gate; private-IP/local-domain rejection; credential & key redaction; **no LLM/fuzzy** in correlator (open math only) | `engine.rs:1044-1141`, `SECURITY.md`, `core/correlator/` |

---

## 2. Entry point & runtime topology

### 2.1 Boot sequence

```
src/main.rs
  └─ #[tokio::main(flavor = "multi_thread", worker_threads = 2)]   ← lib.rs:WORKER_THREADS
       └─ cli::run().await                                         ← single fallible entry; non-zero exit on Err
            └─ clap parse → Commands::{ … }                        ← 11 subcommands
                 └─ composition root: Store::open() → Arc<dyn StoragePort>
                      └─ registry() → Vec<Arc<dyn Module>>
                           └─ ScanEngine::new(modules, store, bus)  ← builds ModuleGraph once
```

The binary is intentionally thin (`main.rs` is 9 lines): it owns only the tokio
runtime shape and the process exit contract. All policy lives behind
`cli::run()`.

**Runtime invariants** (`lib.rs`, asserted in `lib.rs` tests and
`tests/architecture.rs`):

| Constant | Value | Rationale |
|----------|-------|-----------|
| `WORKER_THREADS` | `2` | Tuned for low-power aarch64; the engine's own concurrency is bounded separately by `max_concurrent`. |
| `MODULE_TIMEOUT_MS` | `3000` | Default wall-clock ceiling per `process()` call; a module may raise it via `max_timeout_ms()`. |
| `DEFAULT_BIND` | `127.0.0.1:8080` | Localhost only — never LAN-exposed. |

### 2.2 Subcommand surface (the composition roots)

`registry()` and `Store::open()` are constructed only at these CLI leaves —
they are the *only* legitimate places the concrete SQLite type is named (see
§3.2). Handlers live one-file-per-command under `src/cli/`.

| Subcommand | Handler | Role |
|------------|---------|------|
| `scan` | `cli/scan.rs` | One target → entities; `--depth/--recursive/--auto`, `--max-roi`, `--output table\|json\|dossier`. |
| `modules` | `cli/mod.rs` | List the registry; `--category`, `--json`. |
| `doctor` | `cli/doctor.rs` | Environment preflight (DB, keys, Termux, module count). |
| `provision` / `set-key` / `keys` | `cli/provision.rs`, `cli/keys_cmd.rs` | Manage `~/.huntsman.env` and the multi-key pool. |
| `serve` | `cli/serve.rs` | axum server + embedded SPA on `127.0.0.1:8080`. |
| `live` | `cli/live.rs` | Re-scan one target on an interval (continuous monitoring). |
| `radar` | `cli/radar.rs` | Continuous local-sensor sweep → auto-pivot on new findings. |
| `import` / `export` | `cli/import.rs`, `cli/export.rs` | OathNet JSON in; JSON/CSV/GEXF/dossier out. |

### 2.3 The `serve` topology

`hse serve` constructs an `AppState` (`api/mod.rs`) holding the same
`Arc<dyn StoragePort>` + `Arc<ScanEngine>` + `EventBus` the CLI uses, plus a
`CancelRegistry`, a `ProxyPool`, and a `scan_semaphore` that caps concurrent
in-flight scans. The router (`api/routes.rs`) serves the JSON API under
`/api/v1/*`, two **SSE** streams (`/scans/{id}/events`, `/live/{id}/events`)
that replay `EventBus` traffic to the browser, vendored assets under `/static`,
and the single-file SPA (`src/web/spa.html`) as the catch-all fallback.

---

## 3. Modular boundaries (the dependency DAG)

The architecture is a **strict layered DAG**. The acyclicity constraint is not
a convention — it is verified by `tests/architecture.rs`, which scans the source
tree and fails CI on a forbidden `use`.

```
            ┌──────────────────────────────────────────────┐
   cli  ───▶│  composition roots: registry() + Store::open  │
   api  ───▶│  (the ONLY sites that name the concrete Store)│
            └───────────────────┬──────────────────────────┘
                                │ Arc<dyn StoragePort>, Arc<ScanEngine>
                                ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  core/   (engine, entity, scan, module trait, correlator,      │
   │          dependency graph, roi, live, webhook, gexf, …)        │
   │  • never imports modules/                                      │
   │  • never imports storage::Store  → depends on StoragePort      │
   │  • imports util/ only via a small whitelist                    │
   └───────────────▲───────────────────────────┬──────────────────┘
                   │ Module trait               │ StoragePort trait
                   │ (the only contract)        ▼
   ┌───────────────┴───────────┐   ┌────────────────────────────────┐
   │  modules/  (85 plugins)    │   │  storage.rs  (SQLite WAL Store) │
   │  • depend on core only     │   │  • implements StoragePort       │
   │  • never import engine/    │   └────────────────────────────────┘
   │    storage                 │
   └────────────────────────────┘
```

### 3.1 The `Module` trait — the only plugin contract

`core/module.rs` defines `trait Module: Send + Sync`. The engine knows nothing
else about any plugin. Required methods are `name`, `priority`, `accepts`,
`process`; everything else is defaulted so a new module is low-ceremony:

- `cost() -> ModuleCost` — `Free | KeyGated | Paid`; drives `--free-only` and
  the key-discovery-first ordering.
- `is_passive()`, `max_timeout_ms()`, `description()`, `category()` — metadata.
- `consumes() -> Vec<TargetKind>` — declared input set; defaults to *probing*
  `accepts()` against every kind via `dependency::PROBE_VALUE`. **Value-shaped
  `accepts()` gates must override this** so the dispatch index is correct.
- `produces() -> &[EntityKind]` — declared output set; powers the pivot-chain UI.

`ModuleContext` is the per-scan capability bundle handed to every `process()`
call: `scan_id`, `bus`, a shared rustls `reqwest::Client`, the `keys` map, a
`CancelHandle`, and a `ProxyPool`. Modules pull keys via `ctx.key()` /
`ctx.key_opt()` and report quota exhaustion via `ctx.report_key_exhausted()`,
which feeds the pool's rotation logic.

**Adding a module is a two-file change:** create `src/modules/foo.rs`, then add
`pub mod foo;` + `Arc::new(foo::Foo)` to `registry()` in `src/modules/mod.rs`.
Nothing else in the tree references it by name.

### 3.2 The `StoragePort` Strangler-Fig boundary

`core::port::StoragePort` (`core/mod.rs:460`) is the minimal persistence
contract the engine and correlator need — scans, entities (incl. batch,
filtered, faceted, search), correlations, events, and the multi-scan
observation junction. The engine holds `Arc<dyn StoragePort>`, never the
concrete `storage::Store`. This makes the engine testable without SQLite,
keeps the backend replaceable, and enumerates the engine's storage needs in one
place. The boundary is enforced: `core_does_not_import_storage_directly` and
`api_does_not_import_storage_directly` fail CI on violation; the only sanctioned
`Store::open()` sites are the CLI composition roots.

### 3.3 The `util/` whitelist

`core/` is allowed to reach into `util/` only for a small, audited set
(`proxy::ProxyPool`, `key_pool`, `key_roi`, `geohash`, `preflight`, the
`oathnet`/`see_know` budget resets). `core_does_not_import_util_directly`
guards the rest, preventing the engine from quietly growing dependencies on
scraping/HTTP helpers that belong to the module layer.

---

## 4. The graph data-fabric lifecycle

There are **two distinct graphs**, and conflating them is the most common way
to misread the system:

| | **Module graph** (`core/dependency.rs`) | **Entity fabric** (the data) |
|--|------------------------------------------|------------------------------|
| Built | once, at `ScanEngine::new` | continuously, per scan + persisted across scans |
| Nodes | `TargetKind` ⇄ module indices | `Entity` (deterministic UID) |
| Purpose | O(1) dispatch + expansion "richness" weighting | the OSINT knowledge graph itself |
| Shape | `dispatch_index: HashMap<TargetKind, Vec<usize>>`, `consumer_count`, `richness_for()` | `entity_map` → SQLite + `entity_observations` + evidence-source edges |

This section traces the **entity fabric** through its full lifecycle — the
"shared data fabric" the directive calls for, where data ingested by one module
propagates framework-wide.

### 4.0 The node: `Entity` (`core/entity.rs`)

```
uid          = hex(SHA-256("<kind>:<normalised_value>"))   ← deterministic identity
kind         : EntityKind                                  ← 17 variants
value        : String  (normalised, canonical)             ← merge/UID key
raw_value    : String  (display original)
confidence   : f64 ∈ [0,1]
corroboration: u32 ≥ 1                                      ← independent-source count
observed_at  : u64 (unix s)                                ← decay clock
evidence     : Vec<Evidence>                               ← append-only provenance
tags         : Vec<String>
scan_id      : String
```

Three pieces of open math govern every node — all architecture invariants:

- **Deterministic UID.** `derive_uid(kind, normalise(kind, value))`. The same
  value in any context yields the same UID; this is *what makes merge
  associative and the graph self-deduplicating*.
- **Effective confidence.**
  `C_eff = clamp(confidence × (1 + 0.15 × ln(min(corroboration, 10))), 0, 1)`
  — corroboration is capped at 10 so redundant sources can't inflate certainty
  without bound (`entity.rs:229`).
- **Time decay.** `decayed = confidence × 0.85^hours_elapsed` (`entity.rs:251`).

`classify()` (`Candidate < 0.40 ≤ Probable < 0.75 ≤ Verified`) is **derived on
every read, never stored**, so tier labels can never go stale.

### 4.1 The lifecycle (nine stages)

```
 module.process() ─┐
                   ▼
 (1) INGEST      ModuleResult.entities drained in finalise_module_result      engine.rs:606
 (2) IDENTIFY    Entity::new → normalise(kind,·) → SHA-256 UID                entity.rs:197
 (3) ENRICH      enrich_geospatial(): geohash/tz/country, address parse;      engine.rs:1146
                 scan_entity_for_keys(): harvest API keys → key_pool          engine.rs:1222
 (4) MERGE       GREATEST into entity_map[uid]:                               engine.rs:623
                   confidence=max · corroboration=Σ · observed_at=max
                   · evidence dedup-union · tags union                        entity.rs:303
 (5) PROPAGATE   EntityFound event → EventBus → SSE/CLI tail;                 engine.rs:614
                 discovered keys hot-injected into ctx.keys for later modules engine.rs:767
 (6) PIVOT       run_expansion: C_eff-gated entities → new Targets (loop §5)  engine.rs:341
 (7) PERSIST     finalise_scan: upsert_entities_batch (1 txn; per-entity      engine.rs:236
                 fallback) + entity_observations(uid, scan_id) + save key_pool storage.rs
 (8) CORRELATE   30 declarative rules link entities → Correlation records     correlator/rules.rs
                 + correlation_found events
 (9) SURFACE     CLI (table/json/dossier) · HTTP API · SSE · GEXF · D3 graph  api/, gexf.rs
```

### 4.2 Why the fabric is "shared" (framework-wide propagation)

The directive's "data ingested by one module must instantly propagate
framework-wide" is realised by **four** propagation channels, not one:

1. **`entity_map` (intra-scan).** Every module's output GREATEST-merges into one
   keyed map, so a domain found by `crtsh` and the same domain found by
   `dns_intel` become a single node with accumulated corroboration.
2. **`EventBus` (real-time).** `tokio::broadcast` fan-out; the CLI verbose tail
   and both SSE endpoints subscribe, so the SPA's event log and force-graph
   update live.
3. **Key-pool hot-inject (cross-module capability).** When any module emits a
   value that matches an API-key pattern (`scan_entity_for_keys`), it lands in
   the global key pool with full provenance. Between modules and at the top of
   each expansion round, the engine injects newly-available keys into
   `ctx.keys` (`engine.rs:767, 358`). A free module that scrapes a leaked
   Shodan key thereby *unlocks* the key-gated Shodan module later in the same
   scan — the platform's "autonomous insight amplification" in concrete form.
4. **`entity_observations` (cross-scan).** Every `(uid, scan_id)` pair is
   recorded, so an entity seen by multiple scans accrues corroboration across
   them and shows up in every observer's listing.

### 4.3 Persistence model (`storage.rs`)

SQLite in **WAL** mode (`journal_mode=WAL`, `synchronous=NORMAL`,
`temp_store=MEMORY`, `foreign_keys=ON`, env-tunable `cache_size`/`mmap_size`).
WAL is load-bearing: concurrent reads during a long scan don't block, and the
DB survives a Termux process kill mid-scan. Tables: `scans`, `entities`,
`correlations`, `entity_observations`, `events`. For every row, the typed
columns exist for query/index while `data_json` is the authoritative
serialization of the full struct.

### 4.4 The correlation layer (`core/correlator/`)

After the last module, `Correlator::run(scan_id)` loads the scan's entities and
evaluates **30 deterministic rules** (`AU-001` … `AU-030`) — multi-source breach
corroboration, identity clusters (email+username+phone co-location), malicious
infrastructure, credential/key exposure, address chains, and more. Each firing
becomes a `Correlation { rule_id, severity (Low|Medium|High|Critical),
entity_uids, … }`, persisted and emitted as a `correlation_found` event. **No
LLM, no fuzzy matching** — every finding is reproducible open math, satisfying
the "deterministic execution" hardening constraint.

### 4.5 The relation layer (`core/relation.rs`)

Where the correlator emits *findings*, the relation layer emits *typed edges* —
the explicit attribution graph. After entities are persisted, `finalise_scan`
calls `derive_structural`, a pure builder that links entities by their canonical
values: `SubdomainOf` (Domain → closest present parent), `BelongsToDomain`
(Email → its Domain), `HostedOn` (Url → its Domain). Each `Relation` has a
deterministic SHA-256 id (so re-scans upsert idempotently), carries the weaker
endpoint's confidence, and is persisted to the `relations` table via
`StoragePort` (cascade-deleted with the scan). Edges are retrievable through
`relations_for_scan` and surfaced in `scan --output json` and the dossier's
RELATIONS section. Like the correlator it is **deterministic open math** — no
inference. (Lineage `DerivedFrom` edges and evidence-derived semantic edges
such as `resolves_to`/`registered_by` are reserved follow-on increments; see
[§7 P2](#7-forward-optimization-levers).)

---

## 5. Recursive discovery loop & adaptive pivoting

`run_expansion` (`engine.rs:341`) is the "recursive enumeration chain with
adaptive investigative pivoting." It is a **bounded depth-first graph walk** and
its termination is provable:

```
for depth in 1..=opts.depth:
    refresh ctx.keys from key_pool         # round-start hot-inject (§4.2.3)
    snapshot entity_map
    candidates = entities where C_eff ≥ min_expand_confidence (default 0.50)
                 minus ROI-saturated nodes (max_roi)                         roi::is_saturated
    map EntityKind → TargetKind (unmappable kinds dropped)                   scan.rs:from_entity_kind
    skip visited (TargetKind, normalised_value)                             # cycle-free
    weight each by expansion_strategy × C_eff × graph richness               scan::expansion_weight_*
    sort desc; if max_roi keep top-K (≈2·max_concurrent + 8)                 roi::top_k_for_round
    for each target: budget_check(max_entities, max_wall_time) then dispatch
    if max_roi and marginal_yield < floor: stop early (adaptive depth)       roi::should_terminate_adaptive
```

**Termination guarantees** (no expansion can run away):

- `depth: u32` hard-bounds the number of rounds.
- `visited: HashSet<(TargetKind, normalised value)>` — a target is dispatched at
  most once per scan, so cycles terminate naturally.
- `DispatchLog: HashSet<(module, TargetKind, value)>` — a *keyed/paid* module is
  invoked at most once per normalised target across all rounds (free modules are
  exempt, since re-running them yields independent corroboration). This is the
  primary guard on API-quota economy.
- Hard budgets `max_entities` / `max_wall_time_secs`, plus the operator
  `CancelHandle`, short-circuit at every iteration.
- The ROI bundle (`--max-roi`) adds *economic* termination: convergence-pruning
  of saturated nodes, top-K candidate gating, and adaptive-depth stop when
  new-entities-per-dispatched-target falls below `min_marginal_yield`.

**Expansion strategies** (`ScanOptions::expansion_strategy`):
`geo_converge` (default — biases toward the geolocation chain),
`breadth_first`, `depth_first`, `richest_first` (orders by module-graph
richness). All respect the same `min_expand_confidence` floor.

**Operator knobs** (`scan` subcommand): `--depth N` (0 = seed only),
`--recursive` (depth 5), `--auto` (`optimal_depth()` by seed type + key tier),
`--min-expand-confidence` (default **0.50**; set 0.75 for Verified-only),
`--max-entities`, `--max-wall-time`, `--max-concurrent` (0 = sequential), and
`--max-roi` / `--min-marginal-yield`.

### 5.1 Dispatch concurrency & key-discovery-first

`max_concurrent == 0` ⇒ sequential dispatch (best for low-power devices).
`> 0` ⇒ two-phase concurrent dispatch (`engine.rs:811`): **Phase 1** runs `Paid`
modules synchronously so any keys they discover hot-inject into `ctx` *before*
**Phase 2** fans out the remaining `Free`/`KeyGated` modules under a
`Semaphore`-bounded `JoinSet`. Both paths share `module_skip_reason` and
`finalise_module_result`, so event payloads are identical regardless of mode.

---

## 6. Enforcement gates & hardening

### 6.1 CI pipeline (`.github/workflows/ci.yml`)

Three jobs gate every PR to `main`:

1. **check** — `fmt --all --check` → `check --all-targets --locked` →
   `clippy --all-targets -- -D warnings` (warnings are errors) →
   `test --all --locked`.
2. **msrv** — `check` on the pinned 1.88 toolchain (the `rust-version` floor).
3. **install-script** — `bash -n install.sh` + `shellcheck --severity=warning`.

### 6.2 Architecture invariants as tests (`tests/architecture.rs`)

The boundaries in §3 are not documentation — they are executable assertions:
`core`/`api` may not import `storage::Store`; modules may not import the
engine/storage; `core` may not import `util` outside the whitelist;
`StoragePort` must stay object-safe; every registered module must have a
non-empty `description()`; the registry must hold **≥ 75** modules; the runtime
constants (`MODULE_TIMEOUT_MS=3000`, `WORKER_THREADS=2`, bind address) must
hold.

### 6.3 Security hardening (see [`SECURITY.md`](../SECURITY.md))

- **SSRF gate.** A discovered `Url` whose host resolves to a private IP or
  local domain is rejected before any URL-accepting module fires
  (`engine.rs:1111`, `url_host_is_private`). Without it, an autonomously-found
  `http://192.168.1.1/admin` could coerce HSE into hitting the operator's LAN.
- **Universal preflight.** Private/reserved IPs and local domains are skipped
  for every external-API module; only the `LOCAL_PASSIVE_MODULES` sensor set
  (`device_sensors`, `wifi_intel`, `cell_intel`, `local_net`) opts out. The
  gate is IPv6-aware: public v6 passes, loopback/ULA/link-local v6 is rejected.
- **No secrets in evidence.** Breach modules count credential fields and discard
  them; passwords never enter `Evidence`. API keys live in `~/.huntsman.env`
  (chmod 0600), are loaded into memory at scan time, and are never logged.
- **Deterministic + bounded.** Per-module `tokio::time::timeout`; `panic =
  "abort"` in release; correlator is pure open math.

### 6.4 Release profile (`Cargo.toml`)

`opt-level = "s"`, `lto = true`, `codegen-units = 1`, `strip = true`,
`panic = "abort"` → a single self-contained ~5 MB binary with no shared-library
dependencies beyond libc.

---

## 7. Forward optimization levers

The "continuously optimize" mandate, expressed as prioritized, low-risk work —
each item is scoped so it can land behind the existing CI gates without
disturbing the invariants above.

**P1 — correctness/consistency**
- ✅ **Done.** The `consumes()`/`accepts()` divergence is now a CI-enforced
  regression test (`modules::registry_invariants::module_consumes_covers_probed_accepts`):
  for every registered module and every `TargetKind` its `accepts()` matches
  against the canonical probe value, that kind must appear in `consumes()` —
  otherwise the O(1) dispatch index silently never serves it there. Encoded as
  a registry-wide test rather than a runtime `debug_assert` so it costs nothing
  at runtime and fails the build instead. (The engine still re-checks
  `accepts()` on the hit path at `engine.rs:718` as belt-and-braces.)

**P2 — fabric richness (first slice ✅)**
- ✅ **Done (slice 1).** First-class typed entity relations now exist
  (`core::relation`): a `Relation { from_uid, to_uid, kind, confidence }` model,
  a `relations` table + `StoragePort::{upsert_relation, relations_for_scan}`
  (idempotent on a deterministic edge id, cascade-deleted with the scan), and a
  **deterministic post-scan structural builder** (`derive_structural`) that
  emits `SubdomainOf` (Domain→closest parent), `BelongsToDomain` (Email→Domain),
  and `HostedOn` (Url→Domain). Wired into `finalise_scan` and surfaced in the
  `scan --output json` payload and the dossier's RELATIONS section. Pure open
  math — no inference — preserving the deterministic-only guarantee.
- _Remaining:_ (a) **lineage edges** (`DerivedFrom`: child → the entity whose
  expansion surfaced it) — variant reserved; needs parent context threaded
  through the dispatch path. (b) Evidence-derived semantic edges
  (`resolves_to` from DNS, `registered_by` from WHOIS, `co_located_with` from
  geo proximity). (c) Path-based correlator rules over the edge set and
  labelled edges in the SPA force-graph / GEXF export.

**P3 — performance on aarch64**
- ✅ **Done.** `finalise_scan` now persists the scan's entities through
  `upsert_entities_batch` in a single WAL transaction, collapsing N per-entity
  commits into one fsync (`engine.rs`, `storage.rs`). On a batch error it falls
  back to per-entity `upsert_entity`, so the prior continue-on-error resilience
  semantics (partial persist → Complete-with-error; nothing persisted → Failed)
  are preserved. `StoragePort::upsert_entities_batch` now takes `&[Entity]` so
  the caller keeps ownership for the fallback.
- _Remaining:_ `entity_map` is `HashMap<String, Entity>` keyed by 64-char hex
  UID. Interning UIDs (or keying by the raw 32-byte digest) would cut
  hashing/allocation on large scans. Measure first with a representative
  `--depth 3` scan.

**P4 — observability**
- ✅ **Done.** The `dossier` "modules ranked by yield" table now prints each
  module's cost tier (`free`/`key`/`paid`) and flags keyed/paid modules that
  yielded nothing this scan (`ROI: … consider --exclude …`), making the ROI
  tuning loop (`--max-roi`, `--exclude`) self-explanatory. Cost is looked up
  from `registry()` at render time, off the scan hot path.
- _Remaining:_ aggregate `ModuleStats` (run/errored/timed_out/deduped) is on the
  `Scan`; a machine-readable per-module ledger in the `json` output would let
  external tooling drive the `--adaptive` skip-list.

---

## 8. Integrity audit

Per the "continuous integrity auditing" constraint, the following drift between
the prose docs and the tree was found while authoring this blueprint. Items
marked ✔ are corrected in the same change that adds this file; the rest are
logged for follow-up.

| Source | Claim | Reality | Status |
|--------|-------|---------|--------|
| `ARCHITECTURE.md` crate layout | lists `core/error.rs`, `core/event.rs`, `util/uid.rs`, `storage/store.rs`, `modules/dns_resolver.rs`, … and ~5 modules | `error`/`event`/`port` are inline modules in `core/mod.rs`; storage is `storage.rs`; **85** modules | ✔ corrected + pointer added |
| `ARCHITECTURE.md` release profile | `opt-level = "z"` | `Cargo.toml` is `opt-level = "s"` | ✔ corrected |
| `ARCHITECTURE.md` / `README.md` | `min_expand_confidence` default `0.75` | code default is **0.50** (`scan.rs:511`, `cli/mod.rs:102`); 0.75 is the optional strict setting | ✔ corrected |
| `README.md` | "27 correlator rules (AU-001 … AU-027)" | **30** rules (AU-001 … AU-030) | ✔ corrected |
| `README.md` module overview | sensor names `gps_fix`, `wifi_scan`, `arp_scan`, `cell_survey`, `net_interfaces` | consolidated into `device_sensors`, `wifi_intel`, `cell_intel`, `local_net` | logged |
| `README.md` | "60+ modules" | 85 registered (understated, not wrong) | logged |

> **Maintenance rule going forward:** the headline numbers in this blueprint
> (module count, rule count, expansion defaults) are derived from
> `registry()`, `core/correlator/rules.rs`, and `core/scan.rs`. When those
> change, update [§1](#1-constraint--implementation-matrix) and
> [§4](#4-the-graph-data-fabric-lifecycle) here first — this file is the
> canonical architecture reference; `ARCHITECTURE.md` defers to it.
