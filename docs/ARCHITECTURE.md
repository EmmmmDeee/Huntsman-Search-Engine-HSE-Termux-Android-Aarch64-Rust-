# Architecture

> **See also [`BLUEPRINT.md`](BLUEPRINT.md)** — the canonical, code-grounded
> architectural blueprint (entry point, modular boundaries, graph data-fabric
> lifecycle, constraint→implementation matrix). When the two disagree,
> `BLUEPRINT.md` is authoritative.

This document describes the engine's data flow, the invariants the codebase
upholds, and the design decisions behind them. For module-author specifics,
see [`MODULES.md`](MODULES.md). For the long-term north-star design (large
features not yet built), see [`DESIGN.md`](DESIGN.md).

## High-level data flow

```
┌─────────┐  ┌──────────────────────────────────────────────────────┐  ┌─────────┐
│  CLI /  │→ │  ScanEngine::run(scan, target, ctx)                  │ →│ SQLite  │
│  API    │  │                                                      │  │ store   │
│ (v0.3+) │  │  ┌──────────────┐    ┌────────────────────────────┐  │  └─────────┘
└─────────┘  │  │ Seed round   │ →  │ Autonomous expansion       │  │       ↑
   │          │ │ (dispatch_   │    │   for d in 1..=depth:      │  │       │
   ↓          │ │  target)     │    │     snapshot entities ≥ F  │  │       │
ScanRequest   │ └──────┬───────┘    │     convert via            │  │       │
 ScanOptions  │        ↓            │       TargetKind::from_    │  │       │
              │   Modules           │       entity_kind          │  │       │
              │   in priority       │     skip visited           │  │       │
              │   order:            │     respect budgets        │  │       │
              │   ┌─────────┐       │     dispatch_target        │  │       │
              │   │ Module  │  →    │       (re-uses round 0     │  │       │
              │   │ trait   │       │        dispatcher)         │  │       │
              │   └─────────┘       └────────────┬───────────────┘  │       │
              │        │                         │                  │       │
              │        └───── entity_map (GREATEST-merge) ─────────→│───────┘
              │                                                     │
              │   ────────── EventBus (tokio::broadcast) ──────────→│ SSE / CLI tail
              └──────────────────────────────────────────────────────┘
```

## Crate layout

```
src/
├── main.rs            – binary entry; tokio 2-worker runtime + cli::run()
├── lib.rs             – constants (WORKER_THREADS, MODULE_TIMEOUT_MS, …), default_db_path, is_termux
├── core/
│   ├── mod.rs         – re-exports + INLINE modules: error, event, port (StoragePort), cancel, tags
│   ├── entity.rs      – Entity, Evidence, Classification, EntityKind, derive_uid, normalise
│   ├── scan.rs        – Target, TargetKind, Scan, ScanStatus, ScanOptions, ScanRequest, ExpansionStrategy
│   ├── module.rs      – Module trait, ModuleContext, ModuleResult, ModuleCost, ModuleCategory, ModuleInfo
│   ├── engine.rs      – ScanEngine, dispatch_target (sequential/concurrent), run_expansion, finalise_scan
│   ├── dependency.rs  – ModuleGraph (O(1) dispatch index + expansion "richness")
│   ├── correlator/    – Correlator + 32 rules (AU-001..AU-032; 2 graph-aware)
│   ├── roi.rs         – saturation pruning, top-K gating, adaptive-depth termination
│   ├── live.rs        – LiveScanner / LiveSession (interval re-scan)
│   ├── webhook.rs     – POST-on-completion notifier
│   ├── gexf.rs        – GEXF graph export (Gephi/Cytoscape)
│   ├── profiles.rs    – named scan presets (passive/footprint/investigate/fast)
│   └── validation.rs  – entity invariant validators
├── util/              – http, keys, key_pool, key_roi, budget, preflight, proxy, geohash,
│                        response_cache, oui, html, domains, address_au, see_know, …
├── storage.rs         – SQLite WAL Store (implements core::port::StoragePort)
├── modules/
│   ├── mod.rs         – registry() — the SINGLE source of the module list (85 modules)
│   └── *.rs           – one file per module (+ subdirs: search_engines/, username_search/,
│                        web_crawler/, oathnet_pro/, api_key_probe/, see_know/, exa_search/)
├── api/               – axum routes, handlers, scan_handlers, AppState
└── cli/               – clap dispatch (mod.rs) + one handler file per subcommand
tests/
├── smoke.rs           – end-to-end synthetic-module engine tests
├── architecture.rs    – boundary/invariant enforcement (fails CI on a forbidden import)
└── api.rs             – axum HTTP integration tests
```

`core` never imports from `modules/`. Modules depend on `core` only.
`registry()` is the only place that knows the module list — adding or
removing one is a two-file change (the new `modules/<name>.rs` plus its
line in `registry()`). See [`BLUEPRINT.md`](BLUEPRINT.md) §3 for the full
dependency DAG and the `StoragePort` boundary.

## Architecture invariants

These are enforced and reviewed on every PR. Breaking one requires explicit
justification in the PR summary.

### Code & build

- `#![forbid(unsafe_code)]` at the crate root.
- No native-TLS, no openssl, no C-linked dependencies. Only rustls + bundled
  SQLite (statically linked via `cc-rs`). The release binary is therefore a
  single self-contained file with no shared-library dependencies beyond libc.
- `WORKER_THREADS = 2` (architecture invariant — tuned for low-power aarch64).
- `MODULE_TIMEOUT_MS = 3000` (architecture invariant — bounded module wall-time).
- Release profile is `opt-level = "s"`, `lto = true`, `codegen-units = 1`,
  `strip = true`, `panic = "abort"` → ~5 MB single-file binary.

### Data model

- **Deterministic UIDs.** `entity.uid = hex(SHA-256(kind_str + ":" + normalised_value))`.
  The same value scanned in any context produces the same UID — this is what
  enables merge to be associative.
- **GREATEST-semantics merge.** `confidence` is `max(self, other)`,
  `corroboration` accumulates with `saturating_add`, `observed_at` is
  `max(self, other)`. Confidence never decreases on merge. Always.
- **Effective confidence formula** (architecture invariant):
  `C_eff = clamp(confidence × (1 + 0.15 × ln(corroboration)), 0, 1)`.
  Don't modify the formula.
- **Classification is derived.** `Candidate < 0.40 ≤ Probable < 0.75 ≤ Verified`.
  Never stored — recomputed on every access. Avoids stale tier labels.
- **Time decay.** `decayed_confidence = confidence × 0.85^hours_elapsed`,
  clamped to `[0, 1]`. `apply_decay()` mutates in place; `decayed_confidence()`
  is pure.

### Security

- **No passwords / credentials in evidence.** Modules that hit breach APIs
  read credential fields only to count them and immediately discard. See
  [`SECURITY.md`](../SECURITY.md) for the full security model.
- **API keys** live in `$HOME/.huntsman.env` (chmod `0600`), loaded into
  memory at scan time, never logged.
- **Local-only binding** for the (future) HTTP server: `127.0.0.1:8080`.

### Modularity

- The `Module` trait is the only contract. The engine never references a
  specific module by name.
- `registry()` is the sole module list. Adding / removing modules touches
  exactly two files (the new file + `modules/mod.rs`).
- Every `ScanOptions` filter applies uniformly to both seed dispatch and
  expansion rounds.

## Engine details

### `dispatch_target`

Single-target dispatch — called once for the seed and once per expansion-round
target. Iterates `self.modules` (already sorted by priority descending):

1. Filter by `accepts(&target)`.
2. Filter by `opts.modules` allowlist (if set).
3. Filter by `opts.exclude_modules` denylist.
4. Filter by `opts.free_only`.
5. Filter by `opts.passive_only`.
6. Emit `ModuleStart`.
7. `tokio::time::timeout(module.process(...), module_timeout_ms)`.
8. On result: filter entities by `opts.min_confidence`, emit `EntityFound`
   per kept entity, merge into `entity_map` (GREATEST), emit `ModuleDone`.
9. On error: emit `ModuleError`. Scan continues.
10. Sleep `opts.throttle_ms`.

### `run_expansion`

Bounded depth-first graph walk. For each round `1..=opts.depth`:

1. Take a snapshot of the current `entity_map`.
2. Filter by `c_effective() >= opts.min_expand_confidence`.
3. Map each kept entity to a `Target` via `TargetKind::from_entity_kind`
   (unmappable kinds — `Organisation`, `MacAddress`, `Credential`, … —
   are dropped).
4. Skip targets already in `visited` (key is `(TargetKind, normalised_value)`,
   normalised the same way the entity normaliser would).
5. If `next` is empty → emit `ExpansionStop("no more candidates")`, return.
6. Emit `ExpansionTick { depth, queued, visited }`.
7. For each `next` target:
   - Check budgets (`max_entities`, `max_wall_time_secs`). If exceeded,
     emit `ExpansionStop` with the reason, return.
   - Call `dispatch_target` (re-uses the seed dispatcher).

### Termination guarantees

- `depth` is a `u32` upper bound on rounds.
- `visited` is a `HashSet<(TargetKind, String)>` per scan — same target is
  never dispatched twice.
- `max_entities` and `max_wall_time_secs` are hard budget caps.
- `min_expand_confidence` (default 0.50 — Probable tier and above; set 0.75
  for strict Verified-only expansion) prevents expansion of low-quality finds.

Together these mean expansion always terminates, and the user can tune
aggressiveness without changing the engine.

## Storage schema (v0.2)

```sql
CREATE TABLE scans (
    id           TEXT PRIMARY KEY,
    target_kind  TEXT NOT NULL,
    target_value TEXT NOT NULL,
    status       TEXT NOT NULL,
    started_at   INTEGER NOT NULL,
    finished_at  INTEGER,
    entity_count INTEGER NOT NULL DEFAULT 0,
    error        TEXT,
    data_json    TEXT NOT NULL    -- full Scan struct, source of truth
);

CREATE TABLE entities (
    uid           TEXT PRIMARY KEY,
    scan_id       TEXT NOT NULL,   -- last-scan-wins on upsert; kept for back-compat
    kind          TEXT NOT NULL,
    value         TEXT NOT NULL,
    confidence    REAL NOT NULL,
    corroboration INTEGER NOT NULL DEFAULT 1,
    observed_at   INTEGER NOT NULL,
    data_json     TEXT NOT NULL    -- full Entity struct, source of truth
);

-- v0.7+: every (entity, scan) observation pair the engine has seen.
-- `entities_for_scan` joins against this rather than the entities.scan_id
-- column, so older scans keep their entities visible after a re-scan.
CREATE TABLE entity_observations (
    entity_uid  TEXT NOT NULL,
    scan_id     TEXT NOT NULL,
    observed_at INTEGER NOT NULL,
    PRIMARY KEY (entity_uid, scan_id)
);

CREATE INDEX idx_entities_scan ON entities(scan_id);
CREATE INDEX idx_entities_kind ON entities(kind);
CREATE INDEX idx_scans_started ON scans(started_at DESC);
CREATE INDEX idx_obs_scan      ON entity_observations(scan_id);
CREATE INDEX idx_obs_entity    ON entity_observations(entity_uid);
```

`data_json` is authoritative; the typed columns exist for query and index.

PRAGMAs: `journal_mode=WAL`, `synchronous=NORMAL`, `temp_store=MEMORY`,
`foreign_keys=ON`. WAL is critical — concurrent reads during a long scan
don't block; database survives Termux process kills mid-scan.

### Multi-scan entity tracking (v0.7+)

Resolved by the `entity_observations` junction table. Every time
`upsert_entity` runs, it records the (uid, scan_id) pair so an entity
observed by multiple scans appears in every observer's
`entities_for_scan` listing, with corroboration accumulated across them.

The legacy `entities.scan_id` column is preserved for back-compat but
no longer consulted by `entities_for_scan`. New helper methods
`scan_ids_for_entity(uid)` and `observation_count(uid)` expose the
junction directly for callers that want a "seen in N scans" indicator
without pulling the full entity record.

Migration: on `Store::open`, a one-time `INSERT OR IGNORE INTO
entity_observations SELECT uid, scan_id, observed_at FROM entities`
backfills the junction from any pre-v0.7 entities table.
