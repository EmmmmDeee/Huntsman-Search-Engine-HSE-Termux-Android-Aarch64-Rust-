# HSE Repository Architecture Audit

Scope: `/home/user/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-` (v1.40.0), read-only. `src/` totals **988 `.rs` files / 343,506 lines**; `tests/architecture.rs` alone is 4,310 lines and is the mechanical enforcer of everything in §2/§5.

---

## 1. External Dependency Map

`Cargo.toml`: **32 direct `[dependencies]`** (2 optional: `toml`, `time`) + **6 `[dev-dependencies]`**. `Cargo.lock` resolves to **369 packages** total (includes platform-conditional entries — `jni`/`windows-sys`/`wasm-bindgen` — that never compile on the actual Linux/Android targets, plus a `libfuzzer-sys` entry pulled in only because `deny.toml`'s `[graph] all-features = true` audit view turns on `rav1e`'s optional `fuzzing` feature — `deny.toml:9-12`, confirmed present at `Cargo.lock:1489`).

| Bucket | Crates | Notes |
|---|---|---|
| Async runtime | `tokio` (rt-multi-thread, macros, time, sync, process, io-util, net, fs, signal), `tokio-stream` (sync), `futures` | Hand-built runtime in `main.rs` (not `#[tokio::main]`) to cap blocking threads — see §3. |
| HTTP server | `axum` 0.8 (`default-features=false`; http1, json, query, tokio, original-uri), `tower-http` 0.7 (cors, compression-gzip) | Backs `hse serve`. Gzip via pure-Rust `flate2`/`miniz_oxide`, no C zlib (Cargo.toml:171-177). |
| HTTP client (outbound) | `reqwest` 0.12 (`default-features=false`; json, rustls-tls, stream, gzip) | **Deliberately pinned below 0.13** — 0.13's rustls feature would switch to `rustls-platform-verifier`, which reads the Android OS cert store via JNI through an app `Context` a Termux CLI process doesn't have; would break TLS on the primary target (Cargo.toml:117-138). |
| TLS | rustls + `webpki-roots` + `ring` (all transitive via reqwest/axum/hyper) | No OpenSSL/native-tls anywhere — an explicit architecture invariant (`lib.rs:12`, `README.md:540`). |
| DNS | `hickory-resolver` 0.26 (`default-features=false`, tokio) | `system-config` feature deliberately excluded, but `hickory-proto`/`hickory-net` still mandatorily pull `jni`/`jni-sys` on `cfg(target_os="android")` regardless of any HSE feature flag — documented, accepted upstream bloat (Cargo.toml:156-166). |
| Serialization | `serde` (derive), `serde_json`; `toml` (optional) | `toml`/`time` are `optional = true`, gated behind the `dep-cooldown` feature (Cargo.toml:218-222) — not in the normal build. |
| SQLite/storage | `rusqlite` 0.39 (`bundled`) | **Pinned below 0.40 on purpose** — 0.40→`libsqlite3-sys` 0.38 uses the unstable `cfg_select!` macro, breaking on MSRV 1.88 (Cargo.toml:132-138). `bundled` statically compiles SQLite's C amalgamation via the `cc` crate — the one C compilation in an otherwise pure-Rust dependency graph. |
| CLI parsing | `clap` 4 (derive, env) | |
| Crypto/hashing | `sha1` 0.11, `sha2` 0.11, `md-5` 0.11, `hex`, `base64` | Pure-Rust; no OpenSSL. |
| Text/pattern matching | `regex`, `aho-corasick` (promoted to direct dep for `util::scan`'s cached Teddy/SIMD automata), `memchr` (promoted for `util::html::decode_entities`) | Both promotions are "already-transitive, made explicit" (Cargo.toml:142-149). |
| Error/logging | `thiserror` 2, `async-trait`, `tracing`, `tracing-subscriber` (env-filter, json), `parking_lot` | |
| Misc | `url`, `dotenvy` (.env loading), `flate2` (CSV.GZ import stream-decompress), `csv`, `kamadak-exif` (pure-Rust EXIF, zero transitive deps) | |
| Image processing | `image` 0.25, `default-features=false` with a curated format allowlist (bmp/dds/ff/gif/hdr/ico/jpeg/png/pnm/qoi/tga/tiff/webp) | **Heaviest/most unusual dependency.** AVIF encode (`ravif`→`rav1e`, hand-written asm) and OpenEXR (`exr`) are explicitly dropped from default features — neither is used — but both remain resolvable in `Cargo.lock` as `image`'s optional deps (Cargo.toml:193-208), which is also how `libfuzzer-sys`/`rav1e` end up in the lock at all (see deny.toml note above). |
| Testing | `tempfile`, `tower` (0.5, util — axum router integration tests), `http` 1 | Dev-only. |
| Property/fuzz testing | `proptest` 1.11 (backs `proptest-regressions/`, 4 regression files), plus a **separate** `fuzz/` crate (own `Cargo.toml`+`Cargo.lock`, 2 targets: `ingest_text.rs`, `cert_der.rs`) — not part of this package's dependency graph | |
| Benchmarking | `criterion` 0.8.2, `default-features=false` (cargo_bench_support only, drops HTML-report plotting deps) | 2 benches: `scan_throughput`, `correlation_pass` (`harness=false`, Cargo.toml:73-82). |
| Dev/CI-only tooling | `toml`, `time` — both `optional=true`, feature-gated (`dep-cooldown`) | Compiled only for the `dep-cooldown` binary/tests, never in the Termux/aarch64 cross-build (Cargo.toml:34-63, 209-222). |

**Unusual transitive duplication** (visible directly in `Cargo.lock`, governed by `deny.toml`'s duplicate-version policy): `itertools`, `getrandom` (×3), `tower-http` (×2), `quick-error`, `windows-sys`, `r-efi` each resolve to two-or-more coexisting major versions.

**Edition / MSRV / Lints** — `Cargo.toml`:
```
edition      = "2024"
rust-version = "1.88"
```
`rust-toolchain.toml` separately pins `channel = "1.97.1"` for rustup-managed dev/CI builds (fmt/clippy determinism) — explicitly **not** the MSRV floor; a dedicated CI `msrv` job overrides back to 1.88 via `RUSTUP_TOOLCHAIN` (rust-toolchain.toml comment, lines 1-13).

```toml
[lints.rust]
unsafe_code = "forbid"          # Cargo.toml:90

[lints.clippy]
all = { level = "deny", priority = -1 }   # Cargo.toml:95
uninlined_format_args = "deny"
semicolon_if_nothing_returned = "deny"
explicit_iter_loop = "deny"
redundant_closure_for_method_calls = "deny"
cloned_instead_of_copied = "deny"
implicit_clone = "deny"
inefficient_to_string = "deny"
map_unwrap_or = "deny"
unnested_or_patterns = "deny"
```
`unsafe_code = "forbid"` is triple-redundant by design: Cargo manifest lint, `#![forbid(unsafe_code)]` in `src/lib.rs:39`, and implicitly checked by nothing else needing to check it (forbid can't be overridden). CI additionally passes `-D warnings` as a "belt-and-braces backstop" (Cargo.toml:84-87).

---

## 2. Internal Module Architecture Map

| Dir | `.rs` files | Immediate subdirs | Responsibility |
|---|---|---|---|
| `src/core` | 178 | 40 | Domain model + engine: entity/scan/event/module types, the BFS `ScanEngine` + dispatch/ranking/expansion (`engine/`, 18 files), the 121-rule `correlator` (45 files), relation graph, trust/confidence scoring, ATT&CK mapping, ROI/convex budget math, `StoragePort`/`EngineHost`/`ModuleRuntime` **trait contracts**. Module-agnostic and (mostly) storage/util-agnostic by construction — see enforced rules below. |
| `src/modules` | 482 (+12 non-`.rs` test fixtures) | 174 | ~175 OSINT provider integrations (shodan, hibp, virustotal, whois, github_user, etc.), one file/dir per module implementing `core::module::Module`. Each is normally a `name/{mod.rs,tests.rs}` pair. A few `pub(crate)` non-registered helpers (`breach_rich`, `device_fix`, `github_api`) share logic across sibling modules without themselves being dispatchable. README.md:267: **"175 modules — 136 free, 39 key-gated/paid"**, mechanically pinned to the live registry by `readme_module_overview_count_matches_registry` (`tests/architecture.rs:2215`). |
| `src/util` | 204 | 62 | Shared leaf utilities: HTTP client (`http/`, 8 files), DNS, key management (`keys/`, `key_pool/`, `key_vault/`, `key_harvest/`), geo (`geo/`, `geohash/`, `geometry/`), string/HTML/document parsing, egress proxy pool, `oathnet`/`see_know` breach-API clients, settings. Also hosts `UtilEngineHost` (`util/engine_host.rs`) — the concrete implementation of `core`'s `EngineHost` port. |
| `src/api` | 22 | 6 (`auth`, `handlers`, `routes`, `scan_export`, `scan_handlers`, `settings_handlers`) | axum HTTP layer: `AppState`, router/SPA-fallback (`routes/`), REST handlers, SSE, bearer-token auth for non-loopback binds. `scan_export/` builds CSV/report/GEXF renderings — see §5 for its cross-layer reuse. |
| `src/app` | 37 | 6 (`audit`, `cells`, `diff`, `doctor`, `export`, `import`) | **Composition root** — `app::runtime::build_runtime` is the sole place that opens `storage::Store`, constructs `EventBus`, and builds `ScanEngine::with_runtime_and_host(...)`, wiring in `UtilEngineHost` and the module registry. Also owns store-backed use cases shared by CLI and API: audit, benchmark, diff, doctor, gap, export, import, update-lifecycle, cells, signal. |
| `src/cli` | 32 (+1 `env_template.txt`) | 6 (`ingest`, `keys_cmd`, `live`, `provision`, `scan`, `serve`) | clap `Parser`/`Subcommand` grammar (`command.rs`) + dispatch (`mod.rs`); one file per subcommand family. `serve/` constructs the axum server by calling `app::runtime::build_runtime` and mounting `api::routes::router`. |
| `src/storage` | 9 | 0 | Single SQLite-WAL `Store` (rusqlite), split into `impl Store` blocks across `archive.rs`/`entities.rs`/`signal.rs`/`stealer_rows.rs`/`templates.rs`. Implements `core::port::StoragePort`. |
| `src/audit` | 5 | 0 | Pure, offline **scan self-audit** (noise/infra-pollution/missed-PII scorer). Its own doc comment explains it deliberately "lives at the crate root (not under `core`) so it may use both `core` and `util` without violating the core→util boundary" (`src/audit/mod.rs:17-18`). Wrapped by `app::audit::cmd_audit` for the CLI. |
| `src/selftest` | 3 | 0 | Offline self-validation suite (`hse selftest`, `hse diagnostics`, `hse serve` startup check, `GET /api/v1/selftest`) — real registry + throwaway temp DB, no network. |
| `src/ai` | 3 | 0 | The **one** sanctioned exception to "Runtime AI-independence": a minimal Ollama HTTP client (`ollama.rs`) + prompt/response orchestration (`analysis.rs`), reached only from `hse analyze` (`app::analyze`) and the separate `hse-ai-daemon` binary — never from `scan`/`serve`/`live`. |
| `src/web` | 0 (43 non-`.rs`) | 2 (`css`, `js`) | Hand-rolled JS/HTML/CSS SPA (no framework), ~552 KB total. Not compiled Rust — embedded into the `hse` binary via `include_str!("../../web/spa.html")` and `include_bytes!(...)` per JS/CSS file in `src/api/routes/mod.rs:119-320+`, then served gzip-compressed. |
| `src/bin` | 9 | 2 (`dep_cooldown`, `hse_ai_daemon`) | The two secondary binaries — see §3. |

### README's stated layering rule (verbatim, `README.md:17-22`)
> `src/app` is the public application/composition layer shared by the CLI and HTTP adapters. It exclusively owns concrete SQLite and engine construction, including shared runtime assembly and store-backed audit, benchmark, diff, doctor, and gap workflows; `app::update` owns the update lifecycle. CLI and API code provide transport and presentation only, and architecture tests prevent presentation code from importing CLI internals or concrete storage.

### Rules actually mechanically enforced by `tests/architecture.rs` (line-scanning import-boundary tests; each `#[test]` re-scans `src/` on every `cargo test`)

| Test | File:line | Rule |
|---|---|---|
| `core_does_not_import_storage_directly` | `tests/architecture.rs:52` | `src/core/**` may not contain `storage::Store` / `crate::storage` — must go through `StoragePort`. |
| `core_does_not_import_ai` | `:71` | `src/core/**` may not contain `crate::ai` / `use crate::ai`. |
| `api_does_not_import_storage_directly` | `:85` | `src/api/**` may not contain `crate::storage` / `storage::store`. |
| `api_does_not_import_cli` | `:96` | `src/api/**` may not contain `crate::cli`. |
| `app_does_not_import_cli` | `:108` | `src/app/**` may not contain `crate::cli`. |
| `application_layer_owns_runtime_composition` | `:119` | Positive assertion: `src/app/runtime.rs` **must** textually contain `Store::open(`, `ScanEngine::with_runtime_and_host(`, `registry()`, `module_runtime()`, `UtilEngineHost`. Negative half: `src/cli/**` and `src/api/**` must **not** contain `fn build_runtime(`, `ScanEngine::new(`, `ScanEngine::with_module_runtime(`, `ScanEngine::with_runtime_and_host(`, `Store::open(`, or `crate::storage` — i.e. presentation code may consume the runtime, never construct it. |
| `modules_do_not_import_engine_or_storage` | `:163` | `src/modules/**` may not contain `crate::core::engine` or `crate::storage`. |
| `util_does_not_import_upper_layers` | `:174` | `src/util/**` may not contain `crate::api`, `crate::cli`, `crate::modules`, `crate::selftest`, or `crate::storage`. |
| `core_does_not_import_util_directly` | `:194` | `src/core/**` may not contain `crate::util`, **except** an explicit, individually-justified allow-list of ~40 pure/offline leaf items (e.g. `util::geohash`, `util::geometry`, `util::oui`, `util::confusable`, `util::canonical`, `util::union_find`, `util::abn::*`, `util::address_au::*`, `util::hashcat::*`, `util::oathnet_batch`, `util::keys::resolve_key`, task-local scope setters `found_keys::with_scan`/`regional::with_regional`/`budget::with_scan`) — each justified inline as "no I/O, no state, no upward deps." The comment at `:509-523` records that the allow-list used to hide 4 real violations until the scanner itself was fixed; those were resolved via the `EngineHost` port rather than widening the list, and the list is now explicitly frozen ("shrink-only"). |
| `core_does_not_import_modules` | `:532` | `src/core/**` may not contain `crate::modules` — inverted via `core::module_runtime::ModuleRuntime`. |
| `module_runtime_has_no_process_global_installation` | `:545` | `src/core/module_runtime.rs` must not contain `OnceLock`, `static HOOKS`, or `fn install(` (no global singleton); `src/modules/mod.rs` must not contain `install_core_hooks`. |
| `storage_port_is_object_safe` | `:562` | Compile-time assertion that `&dyn StoragePort` is constructible. |
| `no_module_reads_an_http_body_without_a_size_cap` | `:2168` | `src/modules/**` and `src/core/**` may not contain `.text().await` (raw, uncapped `reqwest::Response::text()`); must use `util::http` helpers. |
| `no_inline_module_bodies_outside_allowed_exceptions` | `:2497` | Every `mod foo { ... }` body anywhere in `src/` must live in its own file, except `mod tests` and two named trivial wrappers (`src/lib.rs`'s `source_manifest`, `src/util/oathnet.rs`'s `paths`) — a repo-wide file-organization invariant, not layering per se, but enforced the same way. |
| `every_src_file_is_wired_into_the_module_tree` | `:3953` | Every `.rs` file under `src/` must be reachable from a `mod`/`include!` declaration somewhere — no orphan files. |

Mechanically, `#[cfg(test)] mod tests;`-declared **`tests.rs` files are skipped wholesale** by the scanner (`scan_dir`, `tests/architecture.rs:19-25`) — deliberately, since test code is allowed to reach into `util` and other layers for verification. One consequence (found by grep, not by the suite): `src/core/correlator/tests.rs:8365` imports `crate::api::scan_export::extract_au_location_fix`, and `src/core/leads/tests.rs:509` calls `crate::cli::parse_target_kind` — both real cross-layer references, invisible to every rule above by design, but confined to test code (not the shipped binary's dependency graph).

---

## 3. Entry Points

### `src/main.rs` (binary `hse`)
Builds a hand-rolled multi-thread tokio `Runtime` (`Builder::new_multi_thread().worker_threads(WORKER_THREADS=2).max_blocking_threads(MAX_BLOCKING_THREADS=16)`) instead of `#[tokio::main]`, specifically to bound tokio's default 512-thread blocking pool on a low-RAM Termux phone (`main.rs:6-17`, `lib.rs:114-120`). Installs a panic-hook guard (`install_broken_pipe_guard`) that exits 0 (instead of panicking with a backtrace) specifically for the benign `"failed printing to stdout: Broken pipe"` case (e.g. `hse scan | head`), while leaving `SIGPIPE` itself ignored so socket writes still surface as recoverable `EPIPE` errors rather than killing the process (`main.rs:25-51`). Then calls `runtime.block_on(cli::run())`.

### `src/bin/hse_ai_daemon/main.rs` (binary `hse-ai-daemon`)
Standalone, **ungated** (no Cargo feature) background poller — deliberately a separate binary, not an `hse` subcommand, so it can be started/stopped independently and an operator who never installs Ollama never runs any of this code (Cargo.toml:16-29). Gate-checks `settings::ai_daemon_enabled()` and a configured `--model`/`HUNTSMAN_OLLAMA_MODEL` before doing anything; opens the same `storage::Store` at `default_db_path()`; loops on a `tokio::time::interval` (default 60s, floor 15s via `HUNTSMAN_AI_POLL_INTERVAL_SECS`), each tick analyzing up to 5 pending scans via `ai::analysis::analyze_scan` — the exact function `hse analyze` calls, so the two entry points can't drift. Graceful shutdown on Ctrl-C/SIGTERM.

### `src/bin/dep_cooldown/main.rs` (binary `dep-cooldown`, feature-gated `required-features = ["dep-cooldown"]`)
Dev/CI-only supply-chain gate: parses `Cargo.lock` + `dep-cooldown.toml`, fetches each crates.io dependency's publish date, and fails if any dependency was published inside a cooldown window (default in `policy::DEFAULT_COOLDOWN_DAYS`) unless explicitly allow-listed — the rationale being that a compromised publish is most likely caught within days, so a cooldown buys detection time. An isolated fetch failure is a warning (fatal only under `--strict`); a **complete** fetch failure (0 of N verified) is always fatal regardless of `--strict`. Feature-gating keeps its `toml`/`time` deps out of the Termux/aarch64 cross-build entirely (verified per Cargo.toml's comment via `nm -D`/`strings` on the built `hse` binary).

### CLI subcommands (`src/cli/command.rs`, `#[derive(Subcommand)] enum Command`) — 29 variants
`scan`, `modules`, `build-sha` (hidden), `engines` (hidden), `query`, `config`, `diagnostics` (alias `diag`/`check`), `audit` (alias `score`), `benchmark`, `gaps`, `analyze`, `doctor` (hidden), `selftest` (hidden), `provision` (hidden, alias `setup`), `set-key` (hidden), `import`, `ingest`, `investigate`, `serve`, `keys` (own `KeysAction` sub-enum), `live`, `radar`, `export`, `diff`, `update` (alias `upgrade`), `oathnet-batch` (hidden, aliases `oathnet-queries`/`obatch`), `cells` (own `CellsAction` sub-enum), `signal`, `tidy` (alias `clean`). Several "hidden" commands (`doctor`, `selftest`, `engines`, `provision`, `set-key`) are kept only for scripting/Web-UI use, superseded by `diagnostics` for interactive use.

---

## 4. `build.rs`

Pure-`std` build script (no build-dependencies, preserving the no-native-deps constraint), doing two independent things:

1. **Source manifest generation** (`collect()`, `build.rs:116-139`): recursively walks `src/`, records `(relative_path, line_count)` for every `.rs` file, sorts by path for determinism, and writes `OUT_DIR/source_manifest.rs` as `pub const SOURCE_FILES: &[(&str,u32)]` + `SOURCE_TOTAL_LINES`. Consumed via `include!(...)` in `src/lib.rs:101-103` as `huntsman_search_engine::source_manifest`, feeding the diagnostics/debug bundle's "complete file inventory" claim. Emits a `cargo:rerun-if-changed` for every visited file **and** directory (a directory watch alone wouldn't catch edits to files in subdirectories — `build.rs:41-49`).
2. **Build provenance stamping** (`emit_build_provenance()`, `build.rs:68-114`): resolves the exact commit SHA (env override `HSE_BUILD_SHA` → `git rev-parse HEAD` → `"unknown"`, never fabricated) and a dirty-tree flag (`git status --porcelain`), emitted as `cargo:rustc-env=HSE_GIT_SHA`/`HSE_GIT_DIRTY`, surfaced as `huntsman_search_engine::BUILD_SHA`/`BUILD_DIRTY` in `lib.rs:59-95`. This is what lets `hse build-sha`/`install.sh`/`hse update` distinguish "this exact commit" from "same `Cargo.toml` version, different commit" — since the crate version alone doesn't change between merges.

---

## 5. Rough Internal Dependency Graph

```
                         ┌────────────────────────────────────────┐
                         │  bin/: hse (main.rs), hse-ai-daemon,    │
                         │  dep-cooldown  — thin process shells    │
                         └───────────────┬──────────────────────┬─┘
                                         │                      │
                     ┌───────────────────▼───────┐   ┌──────────▼─────────┐
                     │  cli/  (presentation)      │   │  ai/ (opt-in only) │
                     │  clap grammar + dispatch   │   │  ollama client +   │
                     └───────┬────────────────┬──┘   │  scan analysis     │
                             │                │       └──────────┬─────────┘
                             │      (serve/ingest/scan            │ depends on
                             │       reach api::scan_export)      ▼
                             ▼                ▼               core, util
                   ┌────────────────┐   ┌───────────┐
                   │  api/ (presen- │◄──┤  app/      │  (composition root)
                   │  tation: axum, │   │  build_runtime, audit/benchmark/
                   │  handlers,     │   │  diff/doctor/gap/export/import/
                   │  routes, SSE)  │   │  cells/signal/tidy/update       │
                   └───────┬────────┘   └───────┬─────────────┬──────────┘
                           │                    │             │
                           └────────┬───────────┘             │
                                    ▼                          ▼
                              core/ (engine, entity,      storage/ (SQLite,
                              correlator, ports:          implements StoragePort)
                              StoragePort / EngineHost /
                              ModuleRuntime — traits only)
                                    ▲            ▲
                                    │            │
                         modules/ ──┘            └── util/ (implements
                         (~175 OSINT              EngineHost via UtilEngineHost;
                         providers, implement      HTTP/DNS/keys/geo/etc.)
                         ModuleRuntime via
                         modules::module_runtime())

                    audit/, selftest/  — sit beside core/, freely use core + util
                    (audit/mod.rs:17-18 explicitly notes this placement is so it can
                     use both without tripping the core→util boundary check, since
                     that test only scans src/core/**)

                    web/  — not Rust; JS/CSS/HTML embedded into api/routes via
                    include_str!/include_bytes! at compile time (§2)
```

**Adjacency summary (arrow = "depends on"):**
- `bin/hse` → `cli`
- `bin/hse-ai-daemon` → `ai`, `storage`, `util::settings` (bypasses `cli`/`app` entirely — its own small `main`)
- `bin/dep-cooldown` → `util::http` only (a standalone dev tool; touches nothing else in the tree)
- `cli` → `app` (almost every subcommand), `api` (only `serve`, plus `scan_export` reuse — see below), `core`, `util`
- `api` → `core`, `util` (never `cli`, never `storage` directly, never `app` — all three mechanically enforced, §2)
- `app` → `core`, `storage`, `util`, `modules::{registry, module_runtime}` (the one place all three concrete pieces meet) — **and, in practice, `api`** (see finding below)
- `modules` → `core`, `util` (never `core::engine` or `storage` directly — enforced)
- `core` → nothing above it; a narrow, frozen allow-list of pure `util` leaves; ports (`StoragePort`, `EngineHost`, `ModuleRuntime`) are *implemented by* `storage`/`util`/`modules` respectively, i.e. the edge runs **inward**, not outward
- `util` → `core` only for the same port-implementation reason (`util::engine_host::UtilEngineHost impl core::engine_host::EngineHost`); never `api`/`cli`/`modules`/`selftest`/`storage` (enforced)
- `storage` → `core` (implements `StoragePort`); nothing else references `storage` except `app` and `storage`'s own tests
- `audit`, `selftest` → `core`, `util`, `storage` (read-only consumers, sit at crate-root level rather than under `core`)

### Where the layering is notably strict
- **Three inverted-dependency "ports"** are the architectural backbone: `core::port::StoragePort` (impl'd by `storage::Store`), `core::engine_host::EngineHost` (impl'd by `util::engine_host::UtilEngineHost`), `core::module_runtime::ModuleRuntime` (impl'd inside `modules::module_runtime()`). In each case `core` *names* the trait and the outer layer implements it, so the compiled dependency edge is `storage/util/modules → core`, never the reverse — this is what lets `core_does_not_import_{storage,util,modules}` hold as more than a naming convention.
- `application_layer_owns_runtime_composition` is unusually strict for a Rust codebase: it doesn't just forbid an import, it greps for specific *call expressions* (`Store::open(`, `ScanEngine::new(`, etc.) inside `cli/` and `api/`, and separately requires `app/runtime.rs` to contain specific tokens — a positive-and-negative pincer around exactly one file.
- The `core_does_not_import_util_directly` allow-list (`tests/architecture.rs:194-506`) is explicitly documented as "shrink-only": a past fix (`core::engine_host`) was added specifically so the exception list would **not** need to grow further, and the comment records that the list must never regrow without "a strictly stronger check in the same commit" (referencing `docs/AUTONOMY_CHARTER.md` INV-3).

### Where the layering looks violated (not caught by any test)
1. **`app` and `cli` both import `api::scan_export` in production code**, contradicting README's "CLI and API code provide transport and presentation only" framing for this one module:
   - `src/app/export/renderers.rs:85` — `crate::api::scan_export::entities_to_csv(...)`
   - `src/app/export/renderers.rs:608` — `crate::api::scan_export::extract_au_location_fix(...)`
   - `src/app/export/renderers.rs:1538` — `crate::api::scan_export::build_scan_report(...)`
   - `src/cli/ingest/mod.rs:477` — `use crate::api::scan_export::formula_guard;`

   No `app_does_not_import_api` test exists (only `app_does_not_import_cli` is checked, `tests/architecture.rs:108`), so this is unenforced. In effect, `api::scan_export` (CSV-injection guarding, report/GEXF shaping) functions as shared **business logic** consumed upward by the composition root, rather than being pure HTTP presentation — an organizational placement mismatch more than a functional problem (no cycle results, since `api` itself never imports `app`/`cli`).
2. **Test-only cross-layer reach**, invisible to the scanner by its own `tests.rs`-skip design (`tests/architecture.rs:19-25`): `src/core/correlator/tests.rs:8365` imports `crate::api::scan_export::extract_au_location_fix`, and `src/core/leads/tests.rs:509` calls `crate::cli::parse_target_kind` (legal — that function is `pub(super)` inside `cli/mod.rs`, whose `super` is the crate root, making it effectively crate-public). Neither affects the shipped binary's runtime dependency graph; both are test code verifying cross-module behavior.
3. **`src/audit`'s placement is a deliberate, documented exception**, not an accident: it sits beside `core/` (not under it) specifically so it can depend on both `core` and `util` "without violating the core→util boundary" — the boundary test only walks `src/core/**`, so `audit`'s own use of `util` is structurally outside its scope by construction (`src/audit/mod.rs:17-18`).

no fluff — all claims above are grep/read-verified against the paths and line numbers cited; nothing here was inferred from naming alone without checking the actual `use`/call sites.
