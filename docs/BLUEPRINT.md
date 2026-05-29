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
registry of **88 modules** feeding a module-agnostic `ScanEngine` that merges
their findings into a deterministic entity graph, pivots recursively on
high-confidence nodes, correlates the result against 36 declarative rules, and
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
| 1 | **Single-binary recursive SpiderFoot** | `default-run = "hse"`; embedded SPA; `run_expansion` recursive walk; **a bare `scan` auto-recurses by default** (depth resolved from seed type + keys) | `Cargo.toml:9`; `engine.rs:341`; `cli/scan.rs` |
| 2 | **Shared data fabric** (instant framework-wide propagation) | per-scan `entity_map` (GREATEST-merge) + SQLite store + `entity_observations` junction + `EventBus` + **key-pool hot-inject** | `engine.rs:623,300-304,358-367` |
| 2 | **Graph engine / entity-linking** | `ModuleGraph` (dispatch + richness), the correlator's 37 rules (incl. **graph-aware AU-031/AU-032/AU-034** that walk the edges, and **AU-037 shared-web-tracker operator clustering**), **and first-class typed `Relation` edges** (structural + lineage + geo co-location + DNS resolution + WHOIS registration + image similarity + stealer co-occurrence); GEXF export + D3 force graph | `core/dependency.rs`, `core/correlator/`, `core/relation.rs`, `core/gexf.rs` |
| 2 | **Discovery loops / adaptive pivoting** | `run_expansion`: depth-bounded DFS with ROI saturation-pruning, top-K gating, adaptive-depth termination, 4 expansion strategies | `engine.rs:341-510`, `core/roi.rs`, `core/scan.rs` |
| 3 | **Code quality / static+dynamic verification** | CI: `fmt --check`, `check --locked`, `clippy -D warnings`, `test --all`, MSRV 1.88, shellcheck | `.github/workflows/ci.yml` |
| 3 | **Resilience / regression testing** | 1,350 tests green; per-module timeout; `panic = "abort"`; offline `hse selftest` (5-stage health check); `tests/perf.rs` complexity gate + `benches/pipeline.rs` offline timing harness | `tests/`, `engine.rs:752`, `Cargo.toml:64`, `cli/selftest.rs`, `benches/` |
| 3 | **Hardening / deterministic execution** | SSRF preflight gate; private-IP/local-domain rejection; **government/military range guardrail** (`preflight::sensitive_range_reason` — DoD /8s etc.; enforced on scan targets, target-URLs, and the proxy retriever, so no gov network is ever probed/routed — ABN/ACN + search engines excepted as hostname APIs); credential & key redaction; **no LLM/fuzzy** in correlator (open math only) | `engine.rs` `module_skip_reason`, `util/preflight.rs`, `util/proxy.rs`, `SECURITY.md` |

---

## 2. Entry point & runtime topology

### 2.1 Boot sequence

```
src/main.rs
  └─ #[tokio::main(flavor = "multi_thread", worker_threads = 2)]   ← lib.rs:WORKER_THREADS
       └─ cli::run().await                                         ← single fallible entry; non-zero exit on Err
            ├─ Cli::parse()  →  logging::init(verbose)             ← clap (–v/–vv); always-on debug file+bus sinks
            ├─ first-run pre-configuration (idempotent)            ← ensure_first_run_scaffold() + ensure_hardcoded_keys()
            └─ Commands::{ … }                                     ← 13 subcommands
                 └─ composition root: Store::open() → Arc<dyn StoragePort>
                      └─ registry() → Vec<Arc<dyn Module>>
                           └─ ScanEngine::new(modules, store, bus)  ← builds ModuleGraph once
```

The binary is intentionally thin (`main.rs` is 9 lines): it owns only the tokio
runtime shape and the process exit contract. All policy lives behind
`cli::run()`.

**Two startup side-effects run once, before dispatch, and are idempotent:**
(1) the layered `tracing` subscriber is initialised — stderr at `info`
(`-v`→`debug`, `-vv`→`trace`), plus an always-on secret-redacted `debug` sink to
`$HOME/.huntsman/logs/hse.log` and a broadcast bus the Web-UI **Logs** stream
fans out; (2) **first-run pre-configuration** creates `$HOME/.huntsman/` + a
`0600` key manifest if absent and fills the bundled always-on credentials
(OathNet/HIBP/WiGLE/SeekNow) into empty/placeholder slots, so the tool works
with zero setup. Neither clobbers real user state.

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
| `scan` | `cli/scan.rs` | One target → entities. **Auto-recurses by default** (optimal depth from seed type + keys); `--depth N` (incl. `0` = single round) / `--recursive` override; `--max-roi`, `--output table\|json\|dossier`. |
| `modules` | `cli/mod.rs` | List the registry; `--category`, `--json`. |
| `doctor` | `cli/doctor.rs` | Environment preflight (DB, keys, Termux, module count); `--bundle` = offline redacted diagnostic report + image-pipeline self-test. |
| `selftest` | `cli/selftest.rs` | Offline, deterministic 5-stage health check (storage / image codec / parsers / a real offline engine scan / cross-correlation builders); exits non-zero on failure. |
| `provision` / `set-key` / `keys` | `cli/provision.rs`, `cli/keys_cmd.rs` | Manage `~/.huntsman.env` and the multi-key pool. |
| `proxies` | `cli/proxies.rs` | Proxy retriever (HTTP + **SOCKS4/5**): `refresh` harvests from diverse public sources, validates highest-liveness-prior first (efficient), **anonymity-grades** (elite/anonymous/transparent) + **types** (datacenter/residential/mobile by ASN via a batched ip-api lookup) + captures country, persisting **best-first** (grade → type → latency); `--grade`/`--type`/`--country` filters; `list` shows the pool. **Government/military/reserved ranges are never probed, validated, or routed through** (`preflight::sensitive_range_reason`, enforced at harvest/validate/route); the ABN/ACN registry API + search engines are unaffected (hostname-based authorized resources). Scans route via `HUNTSMAN_PROXY=auto` (best, or same-country when `HUNTSMAN_REGION` is set). |
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
   │  modules/  (86 plugins)    │   │  storage.rs  (SQLite WAL Store) │
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
 (7) PERSIST     finalise_scan: upsert_entities_batch + upsert_relations_batch engine.rs:236
                 (1 txn each; per-row fallback) + entity_observations + keys   storage.rs
 (8) CORRELATE   32 declarative rules link entities → Correlation records     correlator/rules.rs
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
evaluates **36 deterministic rules** (`AU-001` … `AU-036`) — multi-source breach
corroboration, identity clusters (email+username+phone co-location), malicious
infrastructure, credential/key exposure, address chains, shared media origin
(`AU-033` — one capture/authoring device or author linking multiple images or
documents), stealer-log victim clusters (`AU-035`), credential reuse across
accounts (`AU-036` — same password/hash on ≥2 accounts; correlated on a
one-way hash, the cleartext never emitted), and more. Each firing
becomes a `Correlation { rule_id, severity (Low|Medium|High|Critical),
entity_uids, … }`, persisted and emitted as a `correlation_found` event. **No
LLM, no fuzzy matching** — every finding is reproducible open math, satisfying
the "deterministic execution" hardening constraint.

Most rules read only the flat entity list. A separate **graph-aware pass**
(`evaluate_relation_rules`) additionally loads `relations_for_scan` and walks the
typed edge set: `AU-031 — Adjacency to known-bad infrastructure` flags a benign
entity one edge away from a node tagged malicious / threat-intel / vulnerable
(e.g. a subdomain of a malicious apex, or an entity derived from a flagged node
during expansion), and `AU-032 — Geographic co-location cluster` reports each
connected component of 3+ `CoLocatedWith` coordinates (transitive convergence
within `CO_LOCATION_KM`) — attribution pathways the flat list can't express. New
graph rules slot into `RELATION_RULES` without touching the 31 entity rules'
signatures.

### 4.5 The relation layer (`core/relation.rs`)

Where the correlator emits *findings*, the relation layer emits *typed edges* —
the explicit attribution graph. After entities are persisted, `finalise_scan`
calls four pure builders: `derive_structural`, which links entities by their
canonical values — `SubdomainOf` (Domain → closest present parent),
`BelongsToDomain` (Email → its Domain), `HostedOn` (Url → its Domain);
`derive_colocation`, which links Coordinates within `CO_LOCATION_KM` (1 km) via
`util::geohash` Haversine distance as `CoLocatedWith`; `derive_resolution`,
which links a Domain to an IpAddress (`ResolvesTo`) by matching the IP entity's
DNS evidence (attribute values + summary tokens) against present Domain nodes;
and `derive_registration`, which links a Domain to its registrant Organisation
or Email (`RegisteredBy`) by matching the Domain's WHOIS evidence values against
present Organisation/Email nodes. The evidence-derived builders
(`derive_resolution`/`derive_registration`) match on the *value* being a known
entity, not on attribute-key names — robust across the modules that produce
them. Each `Relation` has a
deterministic SHA-256 id (so re-scans upsert idempotently), carries the weaker
endpoint's confidence, and is persisted to the `relations` table via
`StoragePort::upsert_relations_batch` — all five families in a single WAL
transaction (one fsync), with a per-relation fallback on error (cascade-deleted
with the scan). Edges are retrievable through
`relations_for_scan` and surfaced in `scan --output json`, the dossier's
RELATIONS section, the GEXF export (typed edges labelled by kind for Gephi /
Cytoscape), and the SPA's D3 force-graph (via `GET /api/v1/scans/{id}/relations`,
drawn as distinct dashed edges with the kind on hover). Like the correlator it
is **deterministic open math** — no inference.

Alongside the structural edges, the expansion loop records **lineage**
(`DerivedFrom`) edges: as `run_expansion` dispatches each candidate (built from
a parent entity), it diffs the entity map before/after and attributes every
newly-surfaced entity back to that parent — the literal "recursive enumeration
chain" made explicit as graph edges. Capture is a read-only side-effect
localised to `run_expansion`; it changes no dispatch behaviour.

A sixth family, **`SameImageAs`** (`derive_image_similarity`), links images
whose DCT perceptual hashes (`util::phash`) are within `EQUIV_MAX_HAMMING` —
the local, deterministic reverse-image-search that joins the *same picture*
across different sources independent of metadata. The image pipeline scores
**content** and **metadata** confidence independently (`util::media_score`): a
stripped image is still kept as a similarity anchor, while junk/low-relevance
metadata is gated out of the graph so it can't drive runaway recursion;
provenance is scrutinised at ingest and the graph-aware **AU-034** rule
attributes a metadata-bearing copy's location/author across its near-duplicate
cluster.

A seventh family, **`CompromisedWith`** (`derive_stealer_cooccurrence`),
exploits the single highest-fidelity signal in infostealer data: every email,
credential, domain, and victim IP in one stealer log belongs to the *same
infected machine*. Entities sharing a stealer-log origin key (`log_id` /
`computer_name` / victim IP, via `stealer_origin_keys`) are star-linked into a
victim cluster, and rule **AU-035** surfaces it (Critical when an Email pairs
with a Credential/Domain). `oathnet_pro` and `hudsonrock` thread those origin
keys onto every entity they emit so the cluster forms across modules.

This gives seven edge families in total — structural, lineage, co-location,
resolution, registration, image similarity, and stealer co-occurrence — all
deterministic and all surfaced through the same channels.

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

**Default depth resolution** (`cli/scan.rs`): `--depth` is `Option<u32>`, so the
CLI can tell "omitted" from an explicit `0`. Precedence: an explicit `--depth N`
wins (incl. `0` = seed only); else `--recursive` → depth 7 with a ≤0.40
confidence bar; else (**the default, and what `--auto` requests**)
`optimal_depth(seed_kind, has_paid_keys)` picks the rounds where marginal yield
still justifies cost (3–5 for identity/domain seeds). So a bare `hse scan`
recurses intelligently with no flags.

**Operator knobs** (`scan` subcommand): `--depth N` (omit for auto-depth; `0` =
seed only), `--recursive` (depth 7, low confidence bar), `--auto` (explicit
`optimal_depth()`), `--min-expand-confidence` (default **0.50**; set 0.75 for
Verified-only), `--max-entities`, `--max-wall-time`, `--max-concurrent`
(0 = sequential), and `--max-roi` / `--min-marginal-yield`.

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
`panic = "abort"` → a single self-contained ~10 MB binary with no shared-library
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

**P2 — fabric richness (slices 1–2 ✅)**
- ✅ **Done (slice 1 — structural).** First-class typed entity relations exist
  (`core::relation`): a `Relation { from_uid, to_uid, kind, confidence }` model,
  a `relations` table + `StoragePort::{upsert_relation, relations_for_scan}`
  (idempotent on a deterministic edge id, cascade-deleted with the scan), and a
  **deterministic post-scan structural builder** (`derive_structural`) that
  emits `SubdomainOf` (Domain→closest parent), `BelongsToDomain` (Email→Domain),
  and `HostedOn` (Url→Domain). Surfaced in the `scan --output json` payload and
  the dossier's RELATIONS section. Pure open math — no inference.
- ✅ **Done (slice 2 — lineage).** `run_expansion` now records `DerivedFrom`
  edges (child → the parent entity whose expansion surfaced it) via a read-only
  before/after entity-map diff, localised to the expansion loop — no change to
  dispatch behaviour. Persisted alongside the structural edges in
  `finalise_scan`.
- ✅ **Done (slice 3 — GEXF).** The GEXF export (`entities_to_gexf`) now emits
  the typed `Relation` edges, labelled by kind and weighted by confidence,
  alongside the existing shared-evidence co-occurrence edges — so the full
  attribution graph opens directly in Gephi / Cytoscape (`hse export … --format
  gexf` and `GET /api/v1/scans/{id}/graph.gexf`).
- ✅ **Done (slice 4 — co-location).** `derive_colocation` links Coordinates
  entities within `CO_LOCATION_KM` (1 km) with `CoLocatedWith` edges, using
  `util::geohash` Haversine distance — self-contained deterministic geo math,
  no module coupling. One canonically-directed edge per close pair; persisted
  with the other edges and exported to GEXF.
- ✅ **Done (slice 5 — consume the graph).** The correlator has a graph-aware
  pass (`evaluate_relation_rules`); `AU-031 — Adjacency to known-bad
  infrastructure` flags a benign entity one hop from a malicious / threat-intel
  / vulnerable node. New graph rules slot into `RELATION_RULES` without changing
  the 31 entity rules' signatures.
- ✅ **Done (slice 6 — graph cluster rule).** `AU-032 — Geographic co-location
  cluster` walks the `CoLocatedWith` edges (connected components, DFS) and
  reports each cluster of 3+ transitively-converging coordinates.
- ✅ **Done (slice 7 — SPA visualization).** The relation edges now render in
  the SPA's D3 force-graph as distinct dashed edges (kind shown on hover), fed
  by a new `GET /api/v1/scans/{id}/relations` endpoint. The graph is now
  surfaced in every read path (CLI dossier, JSON, GEXF, web UI).
- ✅ **Done (slice 8 — DNS resolution edges).** `derive_resolution` links
  Domain → IpAddress (`ResolvesTo`) by matching an IP entity's DNS evidence
  (attribute values *and* summary tokens) against present Domain nodes —
  robust across `dns_intel`/`doh_resolver` because it keys on the value being a
  known domain, not on a specific attribute name. Covered by realistic-fixture
  regression tests for both module shapes.
- ✅ **Done (slice 9 — WHOIS registration edges).** `derive_registration` links
  Domain → registrant Organisation/Email (`RegisteredBy`) by matching the
  Domain's WHOIS evidence values against present Organisation/Email entities
  (same value-match robustness as resolution; the registrar self-excludes since
  it isn't emitted as an entity). **The relation taxonomy is now closed** —
  structural, lineage, geo, resolution, and registration edges.
- _Remaining (optional):_ Further graph rules (e.g. multi-hop reachability) on
  the `RELATION_RULES` seam — composable, but increasingly marginal.

**P3 — performance on aarch64**
- ✅ **Done.** `finalise_scan` now persists the scan's entities through
  `upsert_entities_batch` in a single WAL transaction, collapsing N per-entity
  commits into one fsync (`engine.rs`, `storage.rs`). On a batch error it falls
  back to per-entity `upsert_entity`, so the prior continue-on-error resilience
  semantics (partial persist → Complete-with-error; nothing persisted → Failed)
  are preserved. `StoragePort::upsert_entities_batch` now takes `&[Entity]` so
  the caller keeps ownership for the fallback.
- ✅ **Done (measurement).** `benches/pipeline.rs` is an offline, deterministic
  timing harness over the real stages (relation builders, batched persistence,
  correlator) reporting per-stage medians, throughput, and peak RSS; baseline +
  methodology in `benches/BASELINE.md`. `tests/perf.rs` hard-gates the
  deterministic complexity invariants (star-not-mesh, closest-parent-only) plus
  a generous catastrophe ceiling, so regressions fail CI without flaking on
  wall-time. Reference: full 6-builder graph build ≈1.5 ms / ~300k entities·s⁻¹,
  peak RSS ≈8 MiB on the dev host (record on-device aarch64 numbers next).
- _Remaining:_ `entity_map` is `HashMap<String, Entity>` keyed by 64-char hex
  UID. Interning UIDs (or keying by the raw 32-byte digest) would cut
  hashing/allocation on large scans — the harness above is now the tool to
  prove it before/after.

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
