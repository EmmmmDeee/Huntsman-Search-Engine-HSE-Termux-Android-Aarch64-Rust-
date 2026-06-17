# Architecture Reference — Huntsman Search Engine (HSE)

> Current-state architecture overview. HSE is a pure-Rust OSINT / GEOINT / NETINT
> platform whose baseline runtime is **Termux Android aarch64 (no root)**.
> This document describes the system **as built**; open defects and the forward
> plan live in [`PROBLEM_TREE.md`](PROBLEM_TREE.md) (the living problem +
> capability tree), which is the single source of truth for what to change.

## Facts (verified against the tree, 2026-06-17)

| Metric | Value |
|---|---|
| Version / edition / MSRV | 1.4.0 · edition 2024 · 1.88 |
| Source | ~136k LOC · 603 `.rs` files |
| Modules | **118** registered — 89 Free · 24 KeyGated · 5 Paid · 14 categories |
| Correlation rules | **59** deterministic (AU-001 … AU-059) |
| Tests | ~2,944 lib + API/integration + architecture guards |
| Unsafe | **0** — `#![forbid(unsafe_code)]` (`src/lib.rs:22`) |
| Panic strategy | `panic = "unwind"` (`Cargo.toml:115`) + per-module `catch_unwind` at the dispatch boundary |
| Dependencies | 285 crates · **0** AI/ML/LLM/vector (guard-enforced) · 100% permissive licences (`cargo deny`) · 0 unused (`cargo machete`) |
| HTTP / DB | reqwest 0.12 (rustls, no native-TLS) · rusqlite 0.39 bundled (WAL + FTS5) · axum 0.8 · hickory-resolver 0.26 |
| Release profile | `opt-level="s"`, `lto=true`, `codegen-units=1` |
| Runtime | tokio, 2 worker threads (Termux-tuned) |

**Module categories (sum = 118):** Infrastructure 20 · Geo 19 · People 15 ·
DnsRecon 13 · Breach 11 · Social 10 · Email 6 · Corporate 6 · Web 5 · Sensor 4 ·
Threat 3 · Search 2 · Phone 2 · Other 2.

## Dependency direction

```
 bin (main.rs) ─▶ cli ─┐
                       ├─▶ core ─▶ util (http, keys, geo, datasets, …)
 http (api/axum) ──────┘    │
 web (embedded SPA) ◀─ api  ├─▶ correlator (59 rules)
                            └─▶ storage (rusqlite WAL + FTS5, via StoragePort)
 modules (118) ─▶ core types
```

**Intended invariant:** `core` is module-agnostic — the engine drives modules
through `modules::registry()`, never the reverse.

**Enforcement (`tests/architecture.rs`):** guards `core → util`
(`core_does_not_import_util_directly`), `core → storage`
(`core_does_not_import_storage_directly`), and `modules → engine/storage`
(`modules_do_not_import_engine_or_storage`); also pins the module registry, the
README / `docs/MODULES.md` counts, and runtime AI-independence
(`runtime_carries_no_ai_ml_inference_dependency`).

**Known gap:** there is no guard forbidding `core → modules`, and it is
currently **violated** — `core/engine/mod.rs` and `core/engine/enrich.rs` import
`crate::modules`. Tracked as [`PROBLEM_TREE.md`](PROBLEM_TREE.md) §3.1 **T1.4**
(fix: invert the edge via a registry of hooks installed by the module layer).

## Core subsystems

- **`core::engine`** (`src/core/engine/`) — the scan driver: `mod.rs`
  orchestrates; mechanism lives in satellites — `dispatch` (priority waterfall;
  Phase 1 Paid → discovered-key hot-inject → Phase 2 Free/KeyGated concurrent),
  `expansion` (recursive rounds gated by `c_effective ≥ min_expand_confidence`),
  `circuit`/`timeout`, `enrich` (geo + key harvest), `ledger` (dedup/lineage). A
  panicking module is caught at the dispatch boundary (`run_module_guarded`), so
  it degrades to zero results rather than aborting the process.
- **`core::correlator`** (`src/core/correlator/rules/`) — 59 deterministic rules
  across `assoc`/`breach`/`crypto`/`geo`/`infra`/`org`/`identity`/`location`,
  synthesising entities into findings; candidate-quarantine before correlation.
- **`core::{scan,entity,relation,timeline}`** — the typed domain model:
  `Entity::c_effective` noisy-OR/multiplicative confidence fusion (clamped,
  monotone, contract-tested), SHA-256 deterministic UIDs, GREATEST-semantics
  merge.
- **`modules`** (118) — OSINT sources, each `Module: accepts/produces/process`,
  registered in `modules::registry()`; every collection module declares
  `attack_techniques()` (MITRE ATT&CK Reconnaissance, TA0043).
- **`storage`** (`src/storage/`) — the single `StoragePort` implementation over
  rusqlite (WAL + FTS5): events, entities, correlations, relations.
- **`api`** (axum 0.8) — versioned `/api/v1`, SSE live stream, embedded SPA +
  vendor bundle; CSP + `127.0.0.1`-only bind (architecture invariant).
- **`util`** — HTTP client (rustls + SSRF-guarded resolver), key pool, atomic
  `0600` file writes, geo, log-capture ring buffer, settings/toggles.

## End-to-end flow

`hse scan` / `POST /api/v1/scans` → target validation → `engine.run` →
priority-ordered guarded dispatch → entities persisted (FTS-indexed) + events
broadcast (SSE) → expansion rounds → `correlator.run` → diagnostics → CLI
table / dossier / JSON, or the SPA.

## CI / supply chain

- **`ci.yml`** — `fmt --check`, `clippy --all-targets -D warnings`,
  `test --all`, all `--locked`, plus an **aarch64-linux-android** cross-build
  proving the Termux baseline.
- **`audit.yml`** — `cargo audit` (RustSec) + `cargo deny check`
  (licence/ban/source policy) + `cargo machete` (unused dependencies).
- **`live-drift.yml`** (ignored live-network drift tests) and **`release.yml`**.

## Posture

The foundations are sound: a typed domain model, deterministic offline-capable
logic, 0 unsafe, rustls + bundled SQLite (no C / native-TLS), enforced runtime
AI-independence, `0600` atomic secrets, and a loopback-only server. The open
engineering work — correctness, performance, coverage, and the `core → modules`
layering fix — is enumerated and prioritised in
[`PROBLEM_TREE.md`](PROBLEM_TREE.md). No ground-up rewrite is warranted; the work
is targeted hardening and capability expansion.
