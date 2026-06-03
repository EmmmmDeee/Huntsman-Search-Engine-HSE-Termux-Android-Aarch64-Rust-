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
| CI workflows | ci, audit (cargo-audit **+ cargo-deny + cargo-machete**), live-drift, release | `.github/workflows/` |
| Debt markers | **0** real `// TODO`/`// FIXME` markers; 42 `#[allow(dead_code)]` | `grep` (strict) |
| Observability | 92 `tracing` sites + `util::log_capture` ring buffer | `grep` |
| Per-scan mutable globals | **~7** (`QuotaBudget` ×6 + `REGIONAL_SEARCH`), reset per scan | `grep` |
| Unused dependencies | **0** (`cargo machete --with-metadata`) | tool |
| License posture | 100% permissive (MIT/Apache/BSD/ISC/Unicode/Zlib/…) | `cargo deny` |

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
| F1 | **High** | Concurrent scans in `hse serve` share **~7** process-global statics — `search_engines::REGIONAL_SEARCH` (`AtomicBool`) + six `QuotaBudget` statics (`wigle` ×4, `oathnet`, `see_know`), written per-scan via `set_regional`/`reset_budget` | Per-scan state implemented as globals to avoid threading a context through the module call sites | Overlapping scans on a shared server interfere (last-writer-wins on the regional flag; shared rate budgets) → cross-scan contamination. *Narrower and more tractable than first estimated: it is the `QuotaBudget` + regional-flag pattern specifically, not 22 scattered globals.* |
| F2 | **High** | External search-engine reliability | OSINT scraping of CAPTCHA/anti-bot-protected engines; no key | From datacenter IPs 0–8/17 engines reachable → flaky live yield (graceful, but degraded) |
| F3 | Med | `storage.rs` is a 2,039-LOC single file; `search_engines/mod.rs` 2,898; `engine.rs` 2,459 | Organic growth without sub-module extraction | Compile-time, review friction, merge-conflict surface |
| F4 | Med | ~770 `unwrap()` in non-test code (locks already use poison-tolerant pattern) | No `clippy::unwrap_used` lint; reliance on local reasoning | Latent panic risk on new/changed paths (this session found & fixed 3 reachable ones) |
| F5 | Med | No metrics/tracing export from `serve`; observability is logs-only | Tool grew CLI-first | Hard to quantify per-module latency/error-rate in long-lived `serve` beyond the debug-log ring buffer |
| F6 | Low | 42 `#[allow(dead_code)]`; no automated unused-dep check | No `cargo-machete`/`udeps` in CI | Minor maintenance bloat. *Unused-dep half **RESOLVED**: `cargo machete --with-metadata` proves **0** unused crates and now gates CI; the 42 dead-code allows remain to triage.* |
| F7 | ~~Low~~ **HARDENED** | SSRF-shaped surface (modules fetch discovered URLs/IPs) | IP-literal egress guard lived at the engine/caller layer; the crawl loop fetches discovered links *outside* target-validation, so its IP-literal safety was implicit in the same-host filter | **This pass:** added a canonical `preflight::url_host_is_private` (loopback/RFC1918/`169.254` metadata/ULA/local-domain, IPv6-aware) and enforced it explicitly at the web-crawler fetch choke point (loop + `extract_links`), DRY-ing the engine's private copy. The hostname path was already resolver-guarded; the IP-literal path is now guarded at the fetch site, not by a fragile filter invariant. |
| F8 | ~~Low~~ **RESOLVED** | No `deny.toml` (license/duplicate policy); `cargo-audit` only | Advisory-only supply-chain gate | **Closed this pass:** `deny.toml` (100%-permissive allow-list, validated `cargo deny check` = ok) + `cargo-deny` + `cargo-machete` wired into `audit.yml`; licence/yank/source drift now caught. |

**No Critical findings.** Auth writes are loopback-gated + bounded; secrets are `0600` atomic-written; the runtime carries no AI/ML/cloud-inference dependency (CI-enforced).

> **Re-audit execution log.** Evidence is re-gathered against the live tree each
> pass (do-not-assume applied to the prior doc itself).
> - **Pass A** corrected two figures on evidence — **TODO/FIXME 2 → 0** (loose
>   count caught only substrings: `ma`**`stodo`**`n`, `belongs`**`todo`**`main`)
>   and **F1 globals 22 → ~7** (rest were benign `OnceLock<Regex>`/counters) —
>   then **executed F8** (supply-chain triple-gate) and proved **F6**'s
>   unused-dep half clean.
> - **Pass B (this pass)** executed **F7** in strict Security-first order: deep
>   tracing showed the raw `reqwest::Client::new()` sites are all `#[cfg(test)]`
>   (no prod gap) and the crawl path's IP-literal safety was only *implicit* in
>   the same-host filter. Added `preflight::url_host_is_private` and enforced it
>   explicitly at the web-crawler fetch choke point; DRY-ed the engine's private
>   copy; +4 SSRF tests. Full suite 1561 green, clippy `-D warnings` clean.

---

## 3. Code quality

- **Maintainability/readability: strong.** Dense, intent-rich comments; consistent idiom; `rustfmt` + `clippy -D warnings` enforced in CI. **Zero** genuine `// TODO`/`// FIXME` markers in 87k LOC.
- **Modularity/cohesion: strong at the boundary** (core ⊥ util enforced; trait-based `Module`/`StoragePort` ports), **weaker inside hotspots** (the 6 files >1,800 LOC concentrate complexity — F3).
- **Coupling/direction: clean** — dependencies point inward (cli/api → core → storage/modules → util); no core→util leakage.
- **Complexity hotspots:** `search_engines/mod.rs`, `engine.rs`, `scan.rs`, `oathnet_pro/key_harvest`, `storage.rs`, `correlator/mod.rs`.
- **Test coverage: strong** (~1,683 tests incl. architecture guards, reproducibility, panic-regression, per-rule correlator tests). Gaps: `serve` concurrency (F1) is unit-tested per-module but not for cross-scan isolation; live network paths are `#[ignore]` drift tests.
- **Anti-patterns:** the global-setter pattern (F1) is the one structural smell; otherwise free of leaky abstractions/framework misuse.

---

## 4. Dependencies & infrastructure

- **Dependencies:** 277 crates, modern (axum 0.8, reqwest 0.12/rustls, rusqlite 0.31 bundled, tokio, clap 4). **0** AI/ML/vector crates (guard-enforced), **0** unused crates (`cargo machete --with-metadata`), 100%-permissive licences. Supply-chain CI now runs `cargo audit` **+ `cargo deny check`** (licence/ban/source policy, validated ok) **+ `cargo machete`** — closing F8 and the unused-dep half of F6.
- **CI/CD: strong.** `ci.yml` = fmt-check + `cargo check`/`clippy -D warnings`/`test --all` all `--locked` + **aarch64-linux-android cross-build** (proves the Termux baseline) ; `audit.yml` (RustSec); `release.yml`; `live-drift.yml`. Deployment = single static binary via `install.sh` (idempotent, prebuilt fast-path).
- **Observability:** structured `tracing` (92 sites) captured into a downloadable ring buffer (`/api/v1/logs`) + `huntsman::*` targets; self-test endpoint. **Gap:** no metrics/OTel export (F5) — acceptable for a single-user local tool, a gap for shared `serve`.
- **Config/secrets:** `~/.huntsman.env` (mode 0600, atomic temp+fsync+rename), key-pool persisted likewise; web key writes loopback-only + `--allow-key-write`. Toggles in `~/.huntsman/settings.json` (atomic, unique-temp — race fixed this session).

---

## 5. Rebuild plan (phased)

**Immediate (1–7 days)** — *Problem → Root cause → Impact → Effort → Recommendation*
- ✅ **DONE** — F8 supply chain → advisory-only → drift → **S** → added `deny.toml` (validated `cargo deny check` ok) + `cargo-deny` + `cargo-machete --with-metadata` to `audit.yml`. Proved 0 unused deps, 100%-permissive licences.
- F4 unwrap density → no lint → latent panics → **S** → add `clippy::unwrap_used`/`expect_used` (allow in tests). *Note: cannot land as a blanket gate under `clippy -D warnings` without first burning down the 769 call sites — stage per-module or via `#[expect]`, not a one-shot.*
- F6 dead code → no check → bloat → **S** → triage the 42 `allow(dead_code)`; delete or wire. *(Unused-dep half already closed above.)*

**Short-term (1–4 weeks)**
- F1 concurrent-scan isolation → process-global per-scan state → cross-scan contamination in `serve` → **M** → move the ~7 globals (`REGIONAL_SEARCH` + six `QuotaBudget`) into a per-scan `ScanContext` (or task-local), threaded via `ModuleContext`; add a cross-scan isolation integration test. *Highest-value reliability fix.*
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
| 1 | Security | ✅ **DONE** Supply-chain policy gap (F8) | advisory-only | dup/yank/licence drift | S | **Shipped:** `deny.toml` + `cargo-deny` + `cargo-machete` in `audit.yml` (validated ok) |
| 2 | Security | ✅ **DONE** SSRF-shaped fetch surface (F7) | IP-literal guard at caller/engine layer, crawl loop unguarded | residual | S | **Shipped:** explicit `preflight::url_host_is_private` enforced at the web-crawler fetch choke point (loop + `extract_links`), DRY with the engine gate; tests added |
| **3 → next** | Reliability | Concurrent-scan global state (F1) | globals vs ctx | cross-scan contamination | M | per-scan `ScanContext`; isolation test — *highest remaining value* |
| 4 | Reliability | unwrap density (F4) | no lint | latent panics | S | `clippy::unwrap_used` gate + burn-down |
| 5 | Reliability | search-engine flakiness (F2) | external scraping | degraded yield | M | promote direct profile enumeration; engine-health-aware UX |
| 6 | Scalability | SQLite single-writer | embedded store | write contention at high concurrency | M | batch writes (present) + per-scan write coalescing; document single-user envelope |
| 7 | Business value | observability for `serve` (F5) | CLI-first | blind ops | M | `/stats` module metrics; OTel feature |
| 8 | Dev velocity | hotspot files >1.8k LOC (F3) | organic growth | review/compile friction | M–L | sub-module extraction behind traits |
| 9 | Dev velocity | dead code (F6) | no check | bloat | S | triage 42 `allow(dead_code)` |

---

## 7. Executive summary

**Overall grade: B+ (strong, production-capable for its single-user Termux/local envelope; not yet hardened for multi-tenant shared `serve`). Security ticks up to 90 with F8 closed this pass.**

| Dimension | Score (0–100) | Rationale |
|---|---|---|
| Security | **91** ▲ | forbid-unsafe, loopback-gated writes, 0600 atomic secrets, CSP, 0 AI deps; **supply-chain triple-gated** (cargo-audit + cargo-deny + cargo-machete) **and IP-literal SSRF now guarded at the fetch choke point** (F7); −only the inherent discovered-URL fetch surface (resolver-mitigated) remains |
| Reliability | 85 | per-module `catch_unwind`, atomic writes (races fixed), 1,683 tests; −for concurrent-scan global state (~7) + external-source flakiness |
| Scalability | 78 | tokio pool capped for Termux, WAL+FTS, batch writes; −SQLite single-writer + global per-scan state cap shared concurrency |
| Maintainability | **84** ▲ | enforced layering, **0** real TODOs, **0** unused deps, strong tests/CI; −six >1.8k-LOC hotspots + 769 unwraps + 42 dead-code allows |

**Top 10 findings (root-cause):** F1 concurrent-scan globals (~7); F2 external-engine reliability; F3 hotspot files; F4 unwrap density (769); F5 serve observability; F6 dead-code allows (42); ~~F7 SSRF surface~~ **(hardened)**; ~~F8 supply-chain policy~~ **(closed)**; single-writer SQLite envelope; live-path coverage via ignored drift tests only.

**Top 10 highest-ROI improvements:** (1) ~~`deny.toml`+machete~~ ✅ **shipped** + ~~IP-literal SSRF guard~~ ✅ **shipped**, (2) per-scan `ScanContext` (F1) — *next*, (3) staged `clippy::unwrap_used` burn-down, (4) `/stats` module metrics, (5) promote direct profile enumeration *(validated by the live kylo4kylo run — `social_probe` carried the result at 0.90)*, (6) dead-code triage, (7) `storage.rs` repo split, (8) `search_engines` sub-module split, (9) cross-scan isolation test, (10) document/encode the single-user concurrency envelope.

**Recommended rebuild sequence:** harden supply-chain + lints (days) → isolate per-scan state + add observability (weeks) → modularise hotspots + strengthen engine-independent discovery (months) → pluggable module ABI + at-rest encryption (long-term). **No ground-up rewrite is warranted** — the foundations (typed domain model, enforced layering, deterministic offline-capable logic, strong CI, zero unsafe) are sound; the work is targeted extraction, concurrency isolation, and operational hardening.
