# Fault Tree Analysis — Huntsman Search Engine (HSE)

**Scope:** the whole `hse` binary + `huntsman_search_engine` library (CLI, HTTP
API, embedded SPA, scan engine, 125 modules, SQLite store, Termux/aarch64
deployment).
**Method:** top-down Fault Tree Analysis. Gates: `[OR]`, `[AND]`, `[PAND]`
(priority-AND, left-to-right ordered), `[INHIBIT]` (fires only while a
conditioning event holds). Leaf nodes carry **Likelihood** (Very Low → Very
High), **Impact** (Low → Critical), **Detectability** (how readily the fault is
caught *before* it reaches a user), and **Mitigation** (with status: ✅ in
place · ⚒ shipped this cycle · ⚠ open/recommended).

> **Currency note (2026-06-17).** This FTA was generated against an earlier
> snapshot and has drifted. Corrected facts: the project now ships **118
> modules** (not 89); the release profile uses **`panic = "unwind"`** (not
> `"abort"`) with a `catch_unwind` guard at the dispatch boundary, so a module
> panic is **contained, not process-fatal** — which re-frames **E3.1 / SPOF #2**
> below; `audit.yml` is triple-gated (`cargo audit` + `cargo deny` + `cargo
> machete`); the suite is ~2,995 lib tests. The `to_lowercase()` byte-offset slice
> panic class flagged below at **E3.1 / SPOF #2 / Open-item #1** is now **fully
> closed** (T0.1/T0.2 done — boundary-safe `find_ascii_ci` + `proptest`); those
> rows are corrected inline. The live, prioritised view of open engineering issues
> is [`PROBLEM_TREE.md`](PROBLEM_TREE.md). The methodology and trees T1–T11 remain
> valid; treat count/profile claims as historical unless corrected inline.

> **Re-audit (2026-07-06).** A fresh top-down re-run of these trees against the
> current tree (11-branch multi-agent fault-tree workflow, every finding
> adversarially verified for reachability and checked against existing guards)
> found **8 residual defects**, all fixed the same day — see the
> [`PROBLEM_TREE.md`](PROBLEM_TREE.md) §8 log entry (nodes FT.1–FT.8). Note the
> stale "only residual gaps are T2.8/T2.9" line in the 2026-06-17 note above is
> **superseded**: T2.8 and T2.9 were both closed on 2026-06-17. The 2026-07-06
> findings, by tree: **T2/E2.4** (path-embedded own-key leaked into the raw
> archive → `own_api_keys()` exclusion in `describe_url`); **T5/E5.2** (cache-
> replay observation mis-attribution → re-stamp replayed entities to the current
> `scan_id`); **T6/B6.1.3** (typosquat session-dedup set never reset per scan →
> `reset_per_scan` hook); **T5/E5.1** (`au_postcode` read a stray value digit-run
> as a postcode on non-Address kinds → gate value-scan to Address); **T5** (CSV
> formula-guard not reversed on re-import → strip on import); **T1** (cell-tower
> ID mis-detected as Phone → detector reorder); **T3/E3.2** (`report.json`
> handler blocked the reactor → `spawn_blocking`); **T6** (O(k·n) inline-block
> stripping on untrusted SERP bytes → O(n)). The methodology stands: the trees
> are a point-in-time analysis and must be **re-run, not assumed** — which is
> exactly how each of these was caught.

The system remains healthy: `clippy -D warnings` clean, `fmt --check` clean,
`#![forbid(unsafe_code)]` crate-wide, MSRV 1.88, and an aarch64-Android
cross-build in CI. The trees emphasise **residual** and **latent** risk and the
controls that hold it down — not fabricated defects.

---

## System model

**Entry points**
- `src/main.rs` → `cli::run()` (Tokio multi-thread, 2 workers).
- Binary `hse` (`default-run`); library `huntsman_search_engine`.
- CLI subcommands: `scan`, `live`, `serve`, `modules`, `doctor`, `selftest`,
  `diff`, `import`, `export`, `provision`, `keys`, `radar`.
- HTTP surface: `axum` on `127.0.0.1:8080` (loopback invariant), `/api/v1/*`
  + embedded SPA fallback + `/static/*` vendor bundle.

**Boundaries (enforced by `tests/architecture.rs`)**
- `core/` ⟂ `storage/` (engine talks to `StoragePort` trait only).
- `api/` ⟂ `storage/` (handlers use `StoragePort`).
- `modules/` ⟂ `engine/`, `storage/` (modules depend on `core` types only).
- `core/` ⟂ `util/` except a curated allowlist (pure helpers:
  `proxy::ProxyPool`, `key_pool`, `geohash`, `abn::is_valid_*`, …).

**Dependency graph (trust surface)**
- Async: `tokio`, `futures`, `tokio-stream`. HTTP server: `axum`, `tower-http`.
- HTTP client + TLS: `reqwest` (**rustls only**, no native-TLS).
- DNS: `hickory-resolver`. Storage: `rusqlite` (**bundled** SQLite, WAL).
- Parsing: `serde`/`serde_json`, `regex`, `url`, `kamadak-exif`, `base64`.
- CLI: `clap`. Errors: `thiserror`. Logs: `tracing`.
- Native-code surface is intentionally minimal: bundled SQLite C, and `ring`'s
  C build-script (the reason the aarch64-Android CI job wires the NDK clang).

**Build profiles**
- `release`: `opt-level="s"`, `lto=true`, `codegen-units=1`, `strip=true`,
  **`panic="unwind"`** (a panicking module is trapped at the dispatch boundary
  via `catch_unwind`, never aborting the process).
- `fast`: installer default on Termux (drops single-threaded LTO link).
- `dev`/test: `panic="unwind"` (so tests trap panics).

---

## T1 — Functional failure (scan returns no / wrong results)

```
T1
├─[OR] E1.1  Search-engine scraping degrades
│        ├─[OR] B1.1.1  Engine deploys new anti-bot wall not in the detector
│        │       B1.1.2  Engine changes result markup (selectors miss)
│        │       B1.1.3  Block page mis-classified as a real SERP (false negative)
│        └─[INHIBIT: residential IP required] B1.1.4  Datacenter IP CAPTCHA-blocked
├─[OR] E1.2  Auto-detection mis-classifies the unified-scan target
│        ├─[OR] B1.2.1  Ambiguous value (e.g. dotted handle → domain)
│        └─      B1.2.2  Detector regression on a new TargetKind
├─[OR] E1.3  Module silently dead at runtime (declared, never registered)
└─[OR] E1.4  Key-gated module skipped (no API key) and no free fallback
```

| ID | Description | Likelihood | Impact | Detectability | Mitigation |
|----|-------------|-----------|--------|---------------|------------|
| B1.1.1 | New CAPTCHA vendor unrecognised | Medium | Medium | Medium | ⚒ Data-driven two-tier block detector (vendor fingerprints + AND-set phrases), broadened to CF challenge-platform / reCAPTCHA / hCaptcha / DataDome / PerimeterX / Imperva; one-line + test to extend |
| B1.1.2 | Result markup drift | Medium | Medium | Low | ✅ 3-tier extraction (href / `<cite>` / `/url?q=`) + alt-UA retry; 17-engine breadth so one engine's drift ≠ total loss |
| B1.1.3 | Block read as SERP | Low | Medium | Medium | ⚒ Detector is a strict superset of prior coverage; FP-avoidance tests |
| B1.1.4 | DC IP blocked | High (CI) / Low (Termux) | Low | High | ✅ Termux runs from residential IPs; `HUNTSMAN_SEARCH_PROXY` + proxy-pool fallback |
| B1.2.1 | Ambiguous detect | Low | Low | High | ⚒ Ordered most-specific→least; explicit `--kind` always overrides; detected kind echoed to stderr |
| B1.2.2 | Detector regression | Low | Medium | High | ⚒ Exhaustive detect tests (structured, free-text, overlap, junk-never-panics, detect→validate round-trip) |
| E1.3 | Module dead at runtime | Very Low | Medium | High | ✅ `tests/architecture.rs::every_declared_module_is_registered` fails CI |
| E1.4 | Key-gated skip, no fallback | Medium | Low | High | ✅ Graceful key-missing skip with signup hints; `modules_skipped` surfaced; free modules cover core kinds |

---

## T2 — Security compromise

```
T2
├─[OR] E2.1  In-repo OSINT output readable per repository visibility (accepted)
│        └─[INHIBIT: repo is public] in-repo PII readable by anyone
├─[OR] E2.2  Web UI exploited
│        ├─[OR] B2.2.1  DOM XSS from scanned content rendered unescaped
│        │       B2.2.2  Cross-origin site reads scan data (CSRF/CORS)
│        └─      B2.2.3  Key-mutation endpoint reachable off-host
├─[OR] E2.3  Injection
│        ├─[OR] B2.3.1  SQL injection in storage
│        │       B2.3.2  SSRF via user-controlled scan target
│        └─      B2.3.3  Path traversal in static file handler
├─[OR] E2.4  Secret leakage (API keys)
└─[OR] E2.5  Dependency / supply-chain compromise
```

| ID | Description | Likelihood | Impact | Detectability | Mitigation |
|----|-------------|-----------|--------|---------------|------------|
| E2.1 | In-repo OSINT output (dossiers + scan JSON) contains third-party PII | — | Accepted | High | ✅ **Accepted by design.** Faithful retention of findings is the purpose of an OSINT tool; the maintainer keeps generated dossiers/scan output in-repo intentionally, and HSE never removes or redacts PII. The single control over *who can read* it is **repository visibility** (public vs private) — a maintainer setting, not a code change. |
| B2.2.1 | DOM XSS | Low | High | Medium | ✅ Consistent `esc()` on every dynamic field; event renderer assembles trusted fragments from escaped parts; only integer counters are raw. ⚒ All responses now carry a CSP (`default-src`/`connect-src 'self'` blocks external exfiltration + script loads) + `nosniff` + `X-Frame-Options: DENY` + `Referrer-Policy: no-referrer` |
| B2.2.2 | Cross-origin read | Very Low | High | Medium | ✅ CORS bound to the exact `http(s)://<bind>` origin **even on loopback** (a website cannot XHR `127.0.0.1:8080`) |
| B2.2.3 | Off-host key write | Very Low | High | High | ✅ Unconditional loopback peer check on key-mutation regardless of `--no-key-write` |
| B2.3.1 | SQLi | Very Low | Critical | High | ✅ `rusqlite` parameterised statements throughout; no string-built SQL |
| B2.3.2 | SSRF (crawler follows attacker-controlled discovered links) | Low | Medium | Medium | ✅ **Comprehensive TOCTOU-safe defense already in place** (`util::http::build_client`): the `SsrfResolver` custom DNS resolver drops every private/reserved *resolved* address (loopback, RFC1918, 169.254 metadata, CGNAT, ULA, link-local) so reqwest can only connect to a public IP — this defeats internal hostnames **and** DNS-rebinding, not just IP literals; a redirect policy refuses 3xx hops onto private IPs; the `util::curl` fallback resolve-pins identically. Applied to every module's `ctx.http`, including the crawler's discovered-link fetches. Unit-tested (`ssrf_dns_filter_drops_private_and_metadata`) |
| B2.3.3 | Path traversal | Very Low | Medium | High | ✅ Vendor handler matches an exact filename allowlist; `Path<String>` does not decode slashes |
| E2.4 | Key leakage | Low | High | Medium | ✅ `.huntsman.env` git-ignored; keys live in `$HOME`; `/settings/keys` + `/keys/status` never return values; logs never print keys |
| E2.5 | Supply-chain | Low | High | Medium | ✅ `--locked` builds; rustls-only; minimal native surface. ⚒ `.github/workflows/audit.yml` runs `cargo audit` (RustSec advisories) weekly + on every dependency change + on dispatch; advisory-only (separate workflow, not a required check) so a new transitive advisory surfaces without blocking feature PRs |

---

## T3 — Availability failure (`hse serve` stops serving)

```
T3
├─[OR] E3.1  Process aborts
│        └─[PAND] module panic → caught at dispatch (panic="unwind") → module degraded, process survives
├─[OR] E3.2  Event loop starved / blocked
│        ├─[OR] B3.2.1  Blocking call on an async worker (only 2 threads)
│        └─      B3.2.2  Unbounded SSE/broadcast backpressure
└─[OR] E3.3  Listener bind fails (port in use)
```

| ID | Description | Likelihood | Impact | Detectability | Mitigation |
|----|-------------|-----------|--------|---------------|------------|
| **E3.1** | A module panics during a scan | Very Low | Low | Medium | ✅ **Contained by design:** the release profile is `panic="unwind"` and the dispatch boundary wraps each module in `catch_unwind` (`run_module_guarded`), so a panicking module yields no results and is logged — it does **not** abort `serve`. Preventive panic-freedom also holds: `forbid(unsafe)`, ~0 production `unwrap`, exhaustive `match`es (arch test), clippy `-D warnings`. ✅ The `str::to_lowercase()` byte-offset slice *class* (not length-preserving — `İ`→`i̇`, `ẞ`→`ß` — used to slice the **original** string) is now **fully closed**: `search_engines`, `au_electoral`, and `au_property` all route through the boundary-safe `util::str_util::find_ascii_ci`, machine-checked by `proptest` no-panic properties (see [`PROBLEM_TREE.md`](PROBLEM_TREE.md) §3.0 **T0.1/T0.2**, done). A 2026-06-17 multi-agent re-audit found **no remaining instance** of this class anywhere. Confirms the preventive approach must be *re-run*, not assumed — which is exactly how these were caught and fixed |
| B3.2.1 | Blocking on a 2-thread runtime | Low | Medium | Medium | ✅ Fully async I/O (reqwest/hickory); SQLite calls are short; per-module `tokio::timeout` |
| B3.2.2 | SSE backpressure | Low | Medium | Medium | ✅ `broadcast` channel (bounded, lagging receivers drop frames, never block producers); history endpoint backfills |
| E3.3 | Bind fails | Low | Low | High | ✅ Bind error surfaced as a clean `Error::Other("bind …")` and non-zero exit |

---

## T4 — Reliability failure (intermittent wrong behaviour)

```
T4
├─[OR] E4.1  Module hang consumes the scan budget
├─[OR] E4.2  Non-deterministic results across identical inputs
├─[OR] E4.3  Cancellation leak (stale handle / runaway task)
└─[OR] E4.4  Partial-result loss on early termination
```

| ID | Description | Likelihood | Impact | Detectability | Mitigation |
|----|-------------|-----------|--------|---------------|------------|
| E4.1 | Slow module starves the run | Low | Medium | High | ✅ Per-module `tokio::timeout`; `tests/architecture.rs::non_passive_modules_budget_above_default` forbids the silent-timeout class |
| E4.2 | Non-determinism | Low | Medium | Medium | ✅ Deterministic SHA-256 UIDs; GREATEST-semantics merge; `tests/halting.rs` bounds expansion |
| E4.3 | Cancel-handle leak | Very Low | Medium | High | ✅ `CancelRegistryGuard` (RAII) removes the entry even on task panic |
| E4.4 | Partial-result loss | Low | Medium | Medium | ✅ Engine finalises gathered entities under the deadline (esp. trimmed Termux budget) instead of hard-killing |

---

## T5 — Data corruption

```
T5
├─[OR] E5.1  Store corruption (interrupted write / WAL growth)
├─[OR] E5.2  Entity merge loses or fabricates data
└─[OR] E5.3  OSINT output (PII) persisted in-repo (intentional)
```

| ID | Description | Likelihood | Impact | Detectability | Mitigation |
|----|-------------|-----------|--------|---------------|------------|
| E5.1 | SQLite corruption / WAL bloat | Low | High | High | ✅ WAL mode + `checkpoint_truncate()` at safe boundaries; bundled SQLite (version-pinned). ⚒ `hse doctor` now runs `PRAGMA integrity_check` + reports the WAL high-water size, so corruption is detected explicitly instead of surfacing as silently-wrong results. ⚒ Two interrupted-write holes closed this cycle: `upsert_correlation` now deletes-superseded-rows **and** inserts the replacement in ONE `unchecked_transaction` (a crash / `SQLITE_FULL`/`BUSY` between them no longer drops the finding); `util::key_pool::save_pool` now writes temp-file + `fsync` + atomic `rename` (a crash mid-write no longer truncates the pool → `load_pool` discarding every harvested key) |
| E5.2 | Merge anomaly | Low | Medium | High | ✅ GREATEST-semantics merge; batch upsert in one transaction with per-entity fallback; round-trip tests |
| E5.3 | OSINT output (PII) persisted in-repo | — | Accepted | High | ✅ Intentional (see E2.1). Data fidelity is mandatory: the engine must never silently drop or redact a finding — that would be a functional defect, not a fix |

---

## T6 — Resource exhaustion

```
T6
├─[OR] E6.1  Memory blow-up on a low-RAM Termux device
│        ├─[OR] B6.1.1  Unbounded expansion frontier
│        ├─      B6.1.2  Unbounded result/entity accumulation
│        └─      B6.1.3  Unbounded long-session bookkeeping (events / ledgers)
├─[OR] E6.2  API quota exhaustion (paid keys)
└─[OR] E6.3  Concurrent-scan overload via the HTTP API
```

| ID | Description | Likelihood | Impact | Detectability | Mitigation |
|----|-------------|-----------|--------|---------------|------------|
| B6.1.1 | Frontier fan-out | Low | High | High | ✅ `MAX_DEPTH=3` clamp at every input boundary; visited-set; entity + wall-time caps; `tests/halting.rs` |
| B6.1.2 | Result blow-up | Low | Medium | High | ✅ `MAX_RESULTS_PER_ENGINE`, `MAX_ACCUMULATED_RESULTS`, per-extractor caps |
| B6.1.3 | Long-session bookkeeping growth | Low | Medium | Medium | ⚒ Closed this cycle for multi-day `serve`/`radar`: the `events` table is pruned at **every scan boundary** (not just at startup); the radar `DispatchLog` and `LiveSession.scan_ids` are now FIFO-bounded (100k / 10k keys) with eviction of only the oldest, so they can't grow without limit. A fixed-target `live` session never grew (deterministic scan_id) |
| E6.2 | Paid-quota burn | Medium | Medium | Medium | ✅ Per-scan/session budgets (SeekNow cap, OathNet budget); radar ledger never re-queries covered seeds; `free_only`. ⚒ The budget gate is now an atomic `QuotaBudget::try_increment` (CAS reserve, per-scan rollback on session-cap), closing a check-then-act TOCTOU where the `see_know` `join_all` fan-out / wigle `tokio::join!` could each pass `remaining()` then all increment past the operator's cap |
| E6.3 | Scan overload | Low | Medium | High | ✅ `MAX_CONCURRENT_SCANS=8` Tokio `Semaphore` on `POST /scans` |

---

## T7 — Performance collapse

```
T7
├─[OR] E7.1  Slow on-device build blocks adoption
├─[OR] E7.2  Hot-path allocation / CPU spikes
└─[OR] E7.3  Serial dispatch underuses the device
```

| ID | Description | Likelihood | Impact | Detectability | Mitigation |
|----|-------------|-----------|--------|---------------|------------|
| E7.1 | 15–20 min aarch64 LTO build | Medium | Medium | High | ✅ `fast` profile (installer default) ~4–6 min; prebuilt-binary fast path from Downloads + self-cache |
| E7.2 | Hot-path cost | Low | Low | Medium | ✅ Network/IO-bound by nature; `OnceLock` regex caches; bounded string scans |
| E7.3 | Serial underuse | Low | Low | High | ✅ `max_concurrent` parallel dispatch (default 2, opt-in higher) |

---

## T8 — Unexpected termination

```
T8
├─[OR] E8.1  Panic in production code (see T3/E3.1 for the serve blast radius)
│        └─[OR] B8.1.1 unwrap/expect on None/Err   B8.1.2 index out of bounds
│               B8.1.3 integer overflow (debug)     B8.1.4 non-exhaustive logic
└─[OR] E8.2  Unhandled signal / abrupt shutdown
```

| ID | Description | Likelihood | Impact | Detectability | Mitigation |
|----|-------------|-----------|--------|---------------|------------|
| B8.1.1 | `unwrap`/`expect` blows up | Very Low | High | High | ✅ Production `unwrap` surface ≈ 0 (rest are `#[cfg(test)]` / regex-on-static); `Result` end-to-end via `thiserror` |
| B8.1.2 | OOB index | Very Low | High | High | ✅ Slice/`.get()` discipline; arch tests iterate `ALL_TARGET_KINDS` |
| B8.1.3 | Overflow | Low | Low | High | ✅ `saturating_*`/`checked_*` in budget + checksum math; regression test for the ABN leading-zero overflow |
| B8.1.4 | Logic gap on new variant | Low | Medium | High | ✅ Exhaustive `match` (no catch-all) forces every new `TargetKind`/`EntityKind` through the compiler |
| E8.2 | Abrupt shutdown | Low | Low | High | ✅ Graceful shutdown on Ctrl-C + SIGTERM; persisted state survives restart |

---

## T9 — Build failure

```
T9
├─[OR] E9.1  Cross-compile breaks (aarch64-Android native deps)
├─[OR] E9.2  Flaky mobile-network build (cargo fetch / link)
├─[OR] E9.3  MSRV / toolchain drift
└─[OR] E9.4  Lint/format gate breaks CI
```

| ID | Description | Likelihood | Impact | Detectability | Mitigation |
|----|-------------|-----------|--------|---------------|------------|
| E9.1 | NDK clang missing for `ring`/SQLite | Low | High | High | ✅ Dedicated `aarch64-linux-android` CI job wires `$ANDROID_NDK_LATEST_HOME` clang (API 24) |
| E9.2 | Network flake on-device | Medium | Medium | High | ✅ Installer retries with backoff; `--locked`; prebuilt fast path avoids compiling entirely |
| E9.3 | MSRV drift | Low | Medium | High | ✅ Pinned `rust-version=1.88` + a dedicated MSRV CI job |
| E9.4 | fmt/clippy regression | Low | Low | High | ✅ `cargo fmt --check` + `clippy --all-targets -D warnings` gate every PR |

---

## T10 — Maintenance failure

```
T10
├─[OR] E10.1  Silent drift (code vs docs / registry vs catalogue)
├─[OR] E10.2  Config foot-gun (documented key no module reads)
└─[OR] E10.3  Hidden coupling reintroduced
```

| ID | Description | Likelihood | Impact | Detectability | Mitigation |
|----|-------------|-----------|--------|---------------|------------|
| E10.1 | Count/catalogue drift | Low | Low | High | ⚒ Engine-count drift fixed (13→17) + a test ties the module description to `ENGINES.len()`; ✅ `modules_md_lists_every_registered_module`. ⚒ README/INSTALL module-count drift fixed (now **118** everywhere); `readme_module_overview_count_matches_registry` ties the README headline count to `registry().len()` so the *headline* can't rot. ⚠ The README per-category *catalogue list* is **not** CI-guarded (only the headline count + `MODULES.md` are) — it had drifted to 98 of 118 and was re-completed in the 2026-06-17 doc audit; a list-completeness guard against `registry()` would prevent recurrence |
| E10.2 | Orphan key | Low | Low | High | ✅ `env_template_keys_are_all_consumed` fails CI on a documented-but-unread key |
| E10.3 | Layer coupling | Low | Medium | High | ✅ Source-scanning architecture tests fail CI on a forbidden import; the `core`→`util` allowlist is explicit and reviewed |

---

## T11 — Web UI failure

```
T11
├─[OR] E11.1  XSS (see T2/B2.2.1)
├─[OR] E11.2  SPA fails to load / render
├─[OR] E11.3  API contract mismatch (client vs server)
└─[OR] E11.4  Stale cached assets after upgrade
```

| ID | Description | Likelihood | Impact | Detectability | Mitigation |
|----|-------------|-----------|--------|---------------|------------|
| E11.1 | DOM XSS | Low | High | Medium | ✅ `esc()` discipline (see B2.2.1) + ⚒ CSP & security headers on every response |
| E11.2 | SPA load failure | Low | Medium | High | ✅ Single self-contained `include_str!`'d HTML + in-binary vendor bundle (no external CDN, no network to render) |
| E11.3 | Contract mismatch | Low | Medium | Medium | ✅ `tests/api.rs` exercises the endpoints; the unified-scan change kept `kind` optional (backward-compatible) |
| E11.4 | Stale assets | Low | Low | High | ✅ Vendor ETag = crate version + `must-revalidate` (no `immutable` on a stable URL) so an upgrade busts the cache |

---

## Cross-cutting single points of failure & latent defects

| # | SPOF / latent defect | Status |
|---|----------------------|--------|
| 1 | SQLite store (single file) — the one stateful SPOF | ✅ WAL + checkpoint; ⚒ `integrity_check` + WAL-size now reported by `hse doctor` |
| 2 | A module panic during `serve` | ✅ Contained — `panic="unwind"` + `catch_unwind` at dispatch degrade the module, not the process (see E3.1); the `to_lowercase()` slice class (T0.1/T0.2) is now **fixed** (boundary-safe `find_ascii_ci` + `proptest`), not just contained |
| 3 | In-repo OSINT output contains third-party PII | ✅ Accepted by design (E2.1); exposure governed by repo visibility, never by redaction |
| 4 | Scraping detector / selectors track moving third-party targets | ⚒ Hardened + data-driven this cycle; inherently needs upkeep |
| 5 | Crawler follows attacker-controlled discovered links (SSRF) | ✅ Mitigated — client-level `SsrfResolver` DNS filter + private-IP redirect guard (B2.3.2) |

---

## Findings register

**Mitigated this development cycle (⚒)**
1. SERP scraping resilience: data-driven anti-bot detector (broader + fewer false positives), reliable-engine selection by name (killed the `ENGINES[0/1/5]` index SPOF), engine-count drift fixed + guarded, panic-free `unwrap`, parse robustness. *(commit `132f2ec`)*
2. Unified auto-detected scan: `TargetKind::detect`, optional `kind` across CLI/API/live/SPA, with exhaustive tests. *(commit `934cbc8`)*
3. Web security headers: CSP (`default-src`/`connect-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'`, `base-uri 'self'`) + `X-Content-Type-Options: nosniff` + `X-Frame-Options: DENY` + `Referrer-Policy: no-referrer` on every response, via an outermost `map_response` layer; integration-tested on API + SPA. *(B2.2.1 / E11.1)*
4. Storage integrity diagnostic: `hse doctor` now runs `PRAGMA integrity_check` and reports the WAL high-water size, so on-disk corruption is detected explicitly. *(E5.1)*
5. Supply-chain advisory CI: `.github/workflows/audit.yml` runs `cargo audit` weekly + on dependency change + on dispatch; advisory-only (not a required check). *(E2.5)*

**Strong pre-existing controls (✅)** — `forbid(unsafe)`, CI-enforced layering +
no-silent-drift invariants, loopback bind + hardened CORS, **TOCTOU-safe SSRF
defense** (`SsrfResolver` DNS filter + private-IP redirect guard on every HTTP
client), RAII cancellation, concurrency semaphore, per-module timeout floor,
deterministic UIDs, graceful shutdown, prebuilt + fast build paths.

> **Correction (this revision):** an earlier draft listed B2.3.2 as an open
> "no SSRF egress denylist" gap. That was inaccurate — re-reading
> `util/http.rs` + `util/preflight.rs` confirmed a comprehensive, unit-tested
> SSRF defense already exists at the HTTP-client layer (above). The finding is
> reclassified as a satisfied control; no code change was warranted.

**Accepted risks (maintainer decision)**
- **E2.1 / E5.3 — in-repo OSINT output contains third-party PII.** Retained
  intentionally: faithful preservation of findings is the tool's function, and
  HSE never removes or redacts PII. *Who* can read it is governed solely by
  **repository visibility** — set the repo private (GitHub → Settings →
  Visibility) if the data should not be world-readable. No code-level
  remediation applies, and none is performed.

**Resolved since this analysis (was ⚠ — now ✅)**
1. **E3.1 panic class** — `panic="unwind"` + `catch_unwind` at dispatch bound a
   module panic's blast radius (it degrades the module, not `serve`), so the
   former "flip `abort`→`unwind`" recommendation is **done**; and the residual
   `to_lowercase()` byte-offset slice class is now **also closed** —
   `search_engines`, `au_electoral`, and `au_property` all route through the
   boundary-safe `find_ascii_ci`, machine-checked by `proptest` no-panic
   properties (PROBLEM_TREE §3.0 T0.1/T0.2, done); the 2026-06-17 re-audit found
   no remaining instance. **No open items remain in this register** — the live,
   prioritised robustness frontier is in [`PROBLEM_TREE.md`](PROBLEM_TREE.md)
   (currently **T2.8** unbounded response-body reads, **T2.9** SQL tie-breaks).

   Open engineering items are tracked centrally in `PROBLEM_TREE.md`; the trees
   above are a point-in-time analysis.

*Generated as part of a system audit; treat the trees as a point-in-time
analysis. For the current, prioritised issue list see
[`PROBLEM_TREE.md`](PROBLEM_TREE.md).*
