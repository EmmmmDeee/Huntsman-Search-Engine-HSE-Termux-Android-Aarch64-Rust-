# Architecture Audit & Rebuild Strategy — Huntsman Search Engine (HSE)

> Principal-architect review. Evidence-based: every claim is anchored to a file,
> metric, or CI artefact gathered from the tree at the time of writing. HSE is a
> pure-Rust OSINT/GEOINT platform targeting **Termux Android aarch64 (non-root)**
> as its baseline runtime.

## 0. Evidence base (metrics)

| Metric | Value | Source |
|---|---|---|
| Rust LOC (src+tests) | 87,398 | `wc -l` |
| Layers | core 14,879 · modules 47,465 · util 10,237 · cli 4,857 · api 2,235 · storage 2,039 · tests 5,047 | `find/wc` |
| Modules | 92 registered | `hse modules --json` |
| Dependencies | 277 crates; **0** AI/ML/LLM/vector | `Cargo.lock` + guard |
| Edition / MSRV | 2024 / 1.88 | `Cargo.toml` |
| Tests | ~1,683 passing | `cargo test --all` |
| Unsafe | `#![forbid(unsafe_code)]` | `src/lib.rs:22` |
| Panic strategy | release `panic = "unwind"` + per-module `catch_unwind` | `Cargo.toml:70`, `engine.rs` |
| Release profile | `opt-level="s"`, `lto=true`, `codegen-units=1` | `Cargo.toml` |
| CI workflows | ci, audit (cargo-audit), live-drift, release | `.github/workflows/` |
| Debt markers | 2 TODO/FIXME; 42 `#[allow(dead_code)]` | `grep` |
| Observability | 92 `tracing` sites + `util::log_capture` ring buffer | `grep` |
| Global mutable statics | 22 (the concurrent-scan state) | `grep` |

---

## 1. Architecture map

**Layering (enforced, not aspirational):** `tests/architecture.rs` mechanically
forbids `core → util` imports (curated allowlist) and pins the module registry,
docs/README counts, and runtime AI-independence. Dependency direction:

```
 bin (main.rs) ─▶ cli ─┐
                       ├─▶ core ──▶ storage (rusqlite/WAL)
 http (api/axum) ──────┘     │
                             ├──▶ modules (92)  ──▶ util (http, keys, geo, …)
 web (embedded SPA) ◀── api  └──▶ correlator (38 rules)
```

**Core subsystems & responsibilities**
- `core::engine` — scan driver: dispatch (priority waterfall, concurrent/sequential), per-module `catch_unwind` guard, recursive expansion, dedup ledger, lineage/relations.
- `core::correlator` — 38 deterministic rules (AU-001…038) synthesising entities into findings; candidate-quarantine before correlation.
- `core::scan`/`entity`/`relation`/`timeline` — domain model; `c_effective` noisy-OR confidence fusion (clamped, monotone, contract-tested).
- `modules` (92) — OSINT sources (free + key-gated/paid), each `Module: accepts/produces/process`; registered in `modules::registry()`.
- `storage` (`storage.rs`, 2,039 LOC, WAL + FTS5) — the single `StoragePort` impl; events, entities, correlations, relations.
- `api` (axum 0.8) — versioned `/api/v1`, SSE, embedded SPA + vendor; CSP/loopback security layer.
- `util` — HTTP client (rustls), key pool, atomic file writes, geo, log capture, settings/toggles.

**External dependencies:** network OSINT sources (search engines, DNS, platform APIs, paid enumerators); no datastore/queue/cache service — SQLite is embedded. **Offline-capable** for all deterministic logic.

**End-to-end flow:** `hse scan`/`POST /scans` → `validated_target` → `engine.run` → priority-ordered module dispatch (guarded) → entities persisted (store, FTS-indexed) + events broadcast (SSE) → expansion rounds (gated by `c_effective ≥ min_expand_confidence`, mega-domain/IP filters) → `correlator.run` → diagnostics → CLI table/dossier/JSON or SPA.

---

## 2. Critical findings (ranked, root-cause)

| # | Sev | Finding | Root cause | Impact |
|---|-----|---------|-----------|--------|
| F1 | **High** | Concurrent scans in `hse serve` share 22 process-global statics (`set_regional`, `reset_budget`, see_know/oathnet budgets) | Per-scan state implemented as globals to avoid threading through 25 `ModuleContext` sites | Overlapping scans on a shared server interfere (last-writer-wins on regional flag/budgets) → cross-scan result contamination |
| F2 | **High** | External search-engine reliability | OSINT scraping of CAPTCHA/anti-bot-protected engines; no key | From datacenter IPs 0–8/17 engines reachable → flaky live yield (graceful, but degraded) |
| F3 | Med | `storage.rs` is a 2,039-LOC single file; `search_engines/mod.rs` 2,898; `engine.rs` 2,459 | Organic growth without sub-module extraction | Compile-time, review friction, merge-conflict surface |
| F4 | Med | ~770 `unwrap()` in non-test code (locks already use poison-tolerant pattern) | No `clippy::unwrap_used` lint; reliance on local reasoning | Latent panic risk on new/changed paths (this session found & fixed 3 reachable ones) |
| F5 | Med | No metrics/tracing export from `serve`; observability is logs-only | Tool grew CLI-first | Hard to quantify per-module latency/error-rate in long-lived `serve` beyond the debug-log ring buffer |
| F6 | Low | 42 `#[allow(dead_code)]`; no automated unused-dep check | No `cargo-machete`/`udeps` in CI | Minor binary/maintenance bloat |
| F7 | Low | SSRF-shaped surface (modules fetch arbitrary discovered URLs/IPs) | Inherent to OSINT enrichment | Mitigated: non-routable-IP expansion guard, reserved-domain rejection; residual by design |
| F8 | Low | No `deny.toml` (license/duplicate policy); `cargo-audit` only | Advisory-only supply-chain gate | Dup/yanked/licence drift uncaught |

**No Critical findings.** Auth writes are loopback-gated + bounded; secrets are `0600` atomic-written; the runtime carries no AI/ML/cloud-inference dependency (CI-enforced).

---

## 3. Code quality

- **Maintainability/readability: strong.** Dense, intent-rich comments; consistent idiom; `rustfmt` + `clippy -D warnings` enforced in CI. Only **2** TODO/FIXME in 87k LOC.
- **Modularity/cohesion: strong at the boundary** (core ⊥ util enforced; trait-based `Module`/`StoragePort` ports), **weaker inside hotspots** (the 6 files >1,800 LOC concentrate complexity — F3).
- **Coupling/direction: clean** — dependencies point inward (cli/api → core → storage/modules → util); no core→util leakage.
- **Complexity hotspots:** `search_engines/mod.rs`, `engine.rs`, `scan.rs`, `oathnet_pro/key_harvest`, `storage.rs`, `correlator/mod.rs`.
- **Test coverage: strong** (~1,683 tests incl. architecture guards, reproducibility, panic-regression, per-rule correlator tests). Gaps: `serve` concurrency (F1) is unit-tested per-module but not for cross-scan isolation; live network paths are `#[ignore]` drift tests.
- **Anti-patterns:** the global-setter pattern (F1) is the one structural smell; otherwise free of leaky abstractions/framework misuse.

---

## 4. Dependencies & infrastructure

- **Dependencies:** 277 crates, modern (axum 0.8, reqwest 0.12/rustls, rusqlite 0.31 bundled, tokio, clap 4). `cargo audit` runs in CI. **0** AI/ML/vector crates (guard-enforced). Action: add `cargo-machete` (unused) + `deny.toml` (licence/dup/yank).
- **CI/CD: strong.** `ci.yml` = fmt-check + `cargo check`/`clippy -D warnings`/`test --all` all `--locked` + **aarch64-linux-android cross-build** (proves the Termux baseline) ; `audit.yml` (RustSec); `release.yml`; `live-drift.yml`. Deployment = single static binary via `install.sh` (idempotent, prebuilt fast-path).
- **Observability:** structured `tracing` (92 sites) captured into a downloadable ring buffer (`/api/v1/logs`) + `huntsman::*` targets; self-test endpoint. **Gap:** no metrics/OTel export (F5) — acceptable for a single-user local tool, a gap for shared `serve`.
- **Config/secrets:** `~/.huntsman.env` (mode 0600, atomic temp+fsync+rename), key-pool persisted likewise; web key writes loopback-only + `--allow-key-write`. Toggles in `~/.huntsman/settings.json` (atomic, unique-temp — race fixed this session).

---

## 5. Rebuild plan (phased)

**Immediate (1–7 days)** — *Problem → Root cause → Impact → Effort → Recommendation*
- F4 unwrap density → no lint → latent panics → **S** → add `#![warn(clippy::unwrap_used, clippy::expect_used)]` (allow in tests); burn down on hot paths.
- F8 supply chain → advisory-only → drift → **S** → add `deny.toml` + `cargo-machete` to `audit.yml`.
- F6 dead code → no check → bloat → **S** → triage the 42 `allow(dead_code)`; delete or wire.

**Short-term (1–4 weeks)**
- F1 concurrent-scan isolation → process-global per-scan state → cross-scan contamination in `serve` → **M** → move the 22 globals into a per-scan `ScanContext` (or task-local), threaded via `ModuleContext`; add a cross-scan isolation integration test. *Highest-value reliability fix.*
- F5 observability → logs-only → blind `serve` → **M** → per-module yield/latency/error counters exposed at `/api/v1/stats` (data already computed in `diagnostics`); optional OTel feature flag.

**Medium-term (1–3 months)**
- F3 hotspots → organic growth → review/compile friction → **M–L** → extract `search_engines/mod.rs` (queries/extract/dispatch), `engine.rs` (dispatch vs expansion), `storage.rs` (per-aggregate repos) into sub-modules behind the existing traits. Behaviour-preserving; guarded by the test suite.
- F2 search reliability → external scraping → flaky yield → **M** → strengthen the direct, engine-independent path (`username_search` profile enumeration) as the primary username discovery channel; treat dorking as augmentation; surface engine-health-gated expectations to the operator.

**Long-term (3–12 months)**
- Pluggable module ABI (stable `Module` trait + manifest) for third-party modules without recompiling core — **L**.
- Optional encrypted-at-rest store + retention policy for sensitive findings — **L**.

---

## 6. Engineering roadmap (Security → Reliability → Scalability → Business value → Developer velocity)

| Priority | Area | Issue | Root cause | Impact | Effort | Recommendation |
|---|---|---|---|---|---|---|
| 1 | Security | Supply-chain policy gap (F8) | advisory-only | dup/yank/licence drift | S | `deny.toml` + `cargo-machete` in CI |
| 2 | Security | SSRF-shaped fetch surface (F7) | OSINT by nature | residual | S | centralise an egress allow/deny + size/timeout guard in `util::http` (partly present) |
| 3 | Reliability | Concurrent-scan global state (F1) | globals vs ctx | cross-scan contamination | M | per-scan `ScanContext`; isolation test |
| 4 | Reliability | unwrap density (F4) | no lint | latent panics | S | `clippy::unwrap_used` gate + burn-down |
| 5 | Reliability | search-engine flakiness (F2) | external scraping | degraded yield | M | promote direct profile enumeration; engine-health-aware UX |
| 6 | Scalability | SQLite single-writer | embedded store | write contention at high concurrency | M | batch writes (present) + per-scan write coalescing; document single-user envelope |
| 7 | Business value | observability for `serve` (F5) | CLI-first | blind ops | M | `/stats` module metrics; OTel feature |
| 8 | Dev velocity | hotspot files >1.8k LOC (F3) | organic growth | review/compile friction | M–L | sub-module extraction behind traits |
| 9 | Dev velocity | dead code (F6) | no check | bloat | S | triage 42 `allow(dead_code)` |

---

## 7. Executive summary

**Overall grade: B+ (strong, production-capable for its single-user Termux/local envelope; not yet hardened for multi-tenant shared `serve`).**

| Dimension | Score (0–100) | Rationale |
|---|---|---|
| Security | 88 | forbid-unsafe, loopback-gated writes, 0600 atomic secrets, CSP, cargo-audit, 0 AI deps; −for SSRF surface (inherent) + no deny.toml |
| Reliability | 85 | per-module `catch_unwind`, atomic writes (races fixed), 1,683 tests; −for concurrent-scan global state + external-source flakiness |
| Scalability | 78 | tokio pool capped for Termux, WAL+FTS, batch writes; −SQLite single-writer + global per-scan state cap shared concurrency |
| Maintainability | 82 | enforced layering, 2 TODOs, strong tests/CI; −six >1.8k-LOC hotspots + 770 unwraps + 42 dead-code allows |

**Top 10 findings (root-cause):** F1 concurrent-scan globals; F2 external-engine reliability; F3 hotspot files; F4 unwrap density; F5 serve observability; F6 dead code; F7 SSRF surface; F8 supply-chain policy; single-writer SQLite envelope; live-path coverage via ignored drift tests only.

**Top 10 highest-ROI improvements:** (1) `clippy::unwrap_used` gate, (2) `deny.toml`+machete, (3) per-scan `ScanContext`, (4) `/stats` module metrics, (5) promote direct profile enumeration, (6) dead-code triage, (7) `storage.rs` repo split, (8) `search_engines` sub-module split, (9) cross-scan isolation test, (10) document/encode the single-user concurrency envelope.

**Recommended rebuild sequence:** harden supply-chain + lints (days) → isolate per-scan state + add observability (weeks) → modularise hotspots + strengthen engine-independent discovery (months) → pluggable module ABI + at-rest encryption (long-term). **No ground-up rewrite is warranted** — the foundations (typed domain model, enforced layering, deterministic offline-capable logic, strong CI, zero unsafe) are sound; the work is targeted extraction, concurrency isolation, and operational hardening.
