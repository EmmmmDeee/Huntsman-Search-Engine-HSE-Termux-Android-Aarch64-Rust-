# High-Risk Construct Audit — Huntsman Search Engine (HSE) v1.40.0

**Scope**: `src/` (988 `.rs` files, 343,506 lines), `build.rs`, `benches/`, `fuzz/` (separate crate). Read-only — no files modified, no build/test/clippy run.

---

## 1. Unsafe code

**Searched**: `grep -rn "unsafe"` (loose) then `grep -rnE '\bunsafe\s*(\{|fn |impl |trait )'` (strict — actual unsafe constructs only) across `src/`, `build.rs`, `benches/`, `fuzz/`.

| Search | Count |
|---|---|
| Loose `"unsafe"` text match, `src/` | 34 lines |
| Strict `unsafe {` / `unsafe fn` / `unsafe impl` / `unsafe trait`, anywhere in scope | **0** |

All 34 loose hits are either doc-comments explaining why unsafe was *avoided* (e.g. `src/util/oui/ieee.rs:103` — binary-searching a packed blob "without an alignment-safe transmute (unsafe, and the crate forbids it)"; `src/core/engine/circuit/mod.rs:48` — rejecting `libc::clock_gettime` for the same reason) or CSP header string literals containing the substring `'unsafe-inline'` (`src/api/routes/mod.rs:771-772`, `src/api/scan_handlers/analysis.rs:791`) — not Rust `unsafe` at all.

- `src/lib.rs:39` — `#![forbid(unsafe_code)]` (crate-wide, cannot be locally overridden by any `#[allow(unsafe_code)]`, unlike `deny`).
- `Cargo.toml` `[lints.rust] unsafe_code = "forbid"` mirrors the in-source attribute.
- `fuzz/Cargo.toml` has **no `[lints]` table at all** (verified: its 6 top-level tables are `[package]`, `[package.metadata]`, `[dependencies]`, `[dependencies.huntsman-search-engine]`, and two `[[bin]]`). It is deliberately *not* a workspace member of the root crate (documented inline: nightly-only libFuzzer/ASan instrumentation must not touch the stable 4-command CI gate), so it does not and cannot inherit the root's `forbid`. In principle a fuzz target could contain `unsafe`.
- In practice it doesn't: `fuzz/fuzz_targets/cert_der.rs` and `ingest_text.rs` are each a five-line `fuzz_target!` wrapper calling straight into the main crate's safe `fuzz_entry_parse_der` / `fuzz_entry_extract_text` entry points — zero `unsafe` keywords in either file.

**Verdict**: Benign — genuinely zero unsafe code, not just a declared-but-leaky policy. The one crate that *could* legally contain unsafe (fuzz/) doesn't either.

---

## 2. FFI / extern

**Searched**: `extern "C"`, `#[no_mangle]`, `#[repr(C)]` (all three: 0 hits anywhere in `src/`, `build.rs`, `benches/`, `fuzz/`); `[build-dependencies]` in `Cargo.toml`; `libc` as a direct dependency; `bindgen`/`cc` in the root manifest.

| Search | Count |
|---|---|
| `extern "C"` / `#[no_mangle]` / `#[repr(C)]` | 0 / 0 / 0 |
| `[build-dependencies]` section, root `Cargo.toml` | absent (build.rs is pure `std`) |
| `libc` as direct dependency | absent; `libc::` call sites in `src/` | 0 |

`build.rs` (6.3 KB) does two things, both pure `std`: (1) walks `src/` and emits a `SOURCE_FILES` manifest into `OUT_DIR` (`build.rs:1-45`), (2) shells out to the `git` binary via `std::process::Command` to stamp `HSE_GIT_SHA`/`HSE_GIT_DIRTY` (`build.rs:80-119`) — a subprocess call, not FFI.

Two **transitive** native-code paths exist, both explicitly called out in `Cargo.toml` comments as known/unavoidable:
- `rusqlite = { features = ["bundled"] }` (`Cargo.toml:132`) pulls `libsqlite3-sys` 0.37.0 and `cc` 1.4.0 (confirmed in `Cargo.lock:357,1505`) — this **does** compile a vendored C SQLite amalgamation at build time via `cc`. It is the one native-compilation step in an otherwise pure-Rust tree, and is pinned specifically to avoid an unstable-toolchain break (`Cargo.toml:126-131`).
- `hickory-resolver` mandatorily declares `jni` 0.22.4 (`Cargo.lock:1392`) as an Android-`cfg`'d dependency inside *its own* manifest for one unused `ProtoError::Jni` variant; HSE's `default-features = false` (`Cargo.toml:154-163`) strips hickory's own JNI-probing feature, but cannot remove the transitive crate from the dependency graph (documented at length, verified via `cargo tree`/`Cargo.lock`).

**Verdict**: Zero FFI/`extern`/`#[repr(C)]` in HSE's own code. The only native compilation in the tree is bundled-SQLite's `cc`-driven build, a deliberate, documented, single exception to the "no native deps" invariant stated in `src/lib.rs:11`.

---

## 3. Dynamic dispatch — the module-registry pattern

**Searched**: `dyn `, `Box<dyn`, `&dyn`, `Arc<dyn` across `src/`.

| Pattern | Count |
|---|---|
| `dyn ` (any form) | 144 |
| `Arc<dyn` | 88 |
| `&dyn` | 47 |
| `Box<dyn` | 3 |

This **is** the architecture. `src/core/module/mod.rs:149` defines:
```rust
#[async_trait]                                    // line 148
pub trait Module: Send + Sync {                   // line 149
    fn name(&self) -> &'static str;
    fn priority(&self) -> u8;
    fn accepts(&self, target: &Target) -> bool;
    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult>;  // line 160
    // ... ~12 more methods, all with sensible defaults (cost, timeout, category, consumes, produces, attack_techniques)
}
```
`#[async_trait]` (a proc-macro boxing the returned future) exists specifically so `Arc<dyn Module>` stays object-safe with an async method — native async-fn-in-trait isn't object-safe as of this edition.

The registry (`src/modules/mod.rs:347-544`) is:
```rust
static MODULE_REGISTRY: std::sync::LazyLock<Vec<Arc<dyn Module>>> = std::sync::LazyLock::new(|| {
    vec![ Arc::new(hibp::Hibp), Arc::new(shodan::Shodan), /* … */ ]
});
pub fn registry() -> Vec<Arc<dyn Module>> { MODULE_REGISTRY.clone() }  // line 546
```
**178** `Arc::new(...)` entries (`grep -c "Arc::new(" src/modules/mod.rs`), built exactly once per process; `registry()` clones the `Vec` (178 cheap refcount bumps, zero new heap allocations) — called from every HTTP scan-start (`src/api/scan_handlers/core.rs:997`). A dedicated CI test pins this: `module_registry_count_is_stable` (`tests/architecture.rs:583`, floor ≥150) and `module_names_are_unique` (`tests/architecture.rs:601`, since `m.name()` keys a `HashMap` elsewhere).

Dispatch walks the `Vec<Arc<dyn Module>>`, calling `.accepts()` then `.process()` inside a combined timeout+panic guard (`src/core/engine/dispatch.rs:833,880` and `:1179`; see §4). The same trait-object-DI shape recurs at two more layers: `Arc<dyn StoragePort>` (storage abstraction, e.g. `src/api/mod.rs:204`) and `Arc<dyn ModuleRuntime>` (`src/core/module_runtime.rs:24` — cross-cutting per-scan effects injected so `core` never imports `modules`, enforced by `tests/architecture.rs:532 core_does_not_import_modules`).

**Verdict**: Deliberate, single, heavily-tested plugin registry for ~178 independently-authored OSINT providers — not incidental trait-object sprawl.

---

## 4. Threading & async concurrency

**Searched**: `std::thread::spawn`, `tokio::spawn`, `spawn_blocking`, `rayon`, runtime construction in `main.rs`, `mpsc`/`oneshot`/`broadcast`, plus `Semaphore`/`JoinSet`/panic-containment as the concurrency mechanisms actually used to bound module fan-out.

| Construct | Count | Note |
|---|---|---|
| `std::thread::spawn` | 4 | **all 4 in test files only** (`util/atomic_file/tests.rs:34`, `util/keys/tests.rs:711`, `core/engine/tests.rs:3412`, `core/cancel/tests.rs:41`) — zero in production code |
| `tokio::spawn` | 52 | production: `ai/`, `api/`, `cli/serve`, `core/engine/{mod,writer}.rs`, `core/live/mod.rs` |
| `tokio::task::spawn_blocking` | 34 | wraps every sync rusqlite/fs op off the reactor |
| `rayon` (as a crate) | 0 | the one Cargo.toml hit is `image`'s `"rayon"` *feature name*, not a direct HSE dependency |
| `tokio::sync::Semaphore` | 37 | bounds concurrent scans + per-module fan-out |
| `tokio::task::JoinSet` | 28 | bounded-concurrency module dispatch |
| `mpsc::` | 4 | 1 production site: the DB-writer actor |
| `oneshot::` | 3 | same actor's flush barrier |
| `broadcast::` (tokio) | 80 lines, but only **1 real production channel** | everything else constructs throwaway test buses |

**Runtime setup** (`src/main.rs:1-21`) — hand-built, not `#[tokio::main]`, specifically to bound the blocking pool:
```rust
let runtime = tokio::runtime::Builder::new_multi_thread()
    .worker_threads(WORKER_THREADS)          // = 2  (src/lib.rs:112)
    .max_blocking_threads(MAX_BLOCKING_THREADS)  // = 16 (src/lib.rs:120)
    .enable_all().build()...
```
Comment: tokio's default blocking pool is 512 threads, which on a "low-RAM Termux/aarch64 phone" would let a burst of sync sqlite/fs work spawn hundreds of OS threads — deliberately capped for the target device.

**The one channel-based pattern** is a textbook single-writer actor serializing SQLite writes off the reactor (`src/core/engine/writer.rs`): `DbWriter { tx: mpsc::UnboundedSender<WriteCmd> }` (`writer.rs:90`), `spawn(...)` launches `writer_loop` via `tokio::spawn` (`writer.rs:98`), `flush()` sends a `WriteCmd::Flush(oneshot::Sender<()>)` and awaits the oneshot reply (`writer.rs:112,125`) as a completion barrier. The unbounded queue is deliberately unbounded — a bounded channel would force either silent event-drop (`try_send`) or an async producer that gains nothing (extensively justified in the module's own doc comment, `writer.rs:11-36`), and is bounded in practice by the scan's own entity cap.

**The one real `broadcast` channel** is the process-wide `EventBus` (`type EventBus = broadcast::Sender<Event>`, `src/core/event/mod.rs:12`), created exactly once at the composition root: `src/app/runtime.rs:34` `let (bus, _rx) = tokio::sync::broadcast::channel(bus_capacity);` — fanned out to SSE clients, CLI verbose mode, and live-session consumers.

**Panic containment for the plugin registry** (§3's other half): `run_module_guarded` (`src/core/engine/dispatch.rs:200-213`) wraps every module's `process()` future in `timeout(...).catch_unwind()`, converting a caught panic into an ordinary `Error::module(name, "panicked: …")` rather than unwinding into the `JoinSet`/loop. `catch_unwind`: 26 occurrences, `AssertUnwindSafe`: 7. This pairs with `Cargo.toml`'s `panic = "unwind"` (not `"abort"`) release profile, commented as deliberately preserving this containment for a long-lived `hse serve`.

**Verdict**: Disciplined, not ad hoc — one hand-sized runtime, `thread::spawn` confined to tests, `JoinSet`+`Semaphore` bound fan-out, exactly one dedicated actor for the one genuinely-serial resource, and a panic firewall around every third-party-shaped plugin call.

---

## 5. Shared mutable state

**Searched**: `Mutex<`, `RwLock<`, `static `, `LazyLock`, `OnceLock`/`OnceCell`, `Arc<Mutex`/`Arc<RwLock`, `Atomic*`; then a targeted std-vs-tokio-Mutex discipline check and spot-checks near `async fn` bodies.

| Construct | Count |
|---|---|
| `Mutex<` (all forms) | 43 |
| — `std::sync::Mutex` | 29 (26 production files + 3 test files; one production hit, `core/entity/mod.rs:11`, is a doc-comment stating a *non*-use) |
| — `tokio::sync::Mutex` | 5 (3 files: `see_know/web_dispatcher.rs`, `see_know/web_client_advanced.rs`, and a test-only guard in `wigle/tests.rs`) |
| — `parking_lot::Mutex` | remainder (`cli/serve/mod.rs:73`, `key_pool/pool.rs`, `circuit_breaker/mod.rs`, `egress/`, `storage/mod.rs`) |
| `RwLock<` | 7 — 3× `std::sync::RwLock` (module-level caches) + `parking_lot::RwLock` ×2 fields in `core/live/mod.rs:198-199` |
| `static ` | 100 (dominated by the per-function memoized `static X: OnceLock<Regex> = OnceLock::new();` idiom) |
| `LazyLock` | 105 |
| `OnceLock` | 43 |
| `OnceCell` | 3 — all one call site: `tokio::sync::OnceCell` for an async-populated cache (`modules/ip_reputation/mod.rs:89`, Tor exit-node list fetched once over the network) |
| `Arc<Mutex` | 8 |
| `Arc<RwLock` (literal substring) | 0 (the `RwLock`s are either bare statics or nested one level inside an outer `Arc<LiveInner>`) |
| `AtomicUsize`/`Bool`/`U64`/`U32`/`I64` | 53 |

**The std-vs-tokio Mutex split is deliberate and documented**, not incidental — this is the strongest single finding in this category. `src/api/mod.rs:213-226` (on `AppState::update_info: Arc<std::sync::Mutex<UpdateInfo>>`):

> "Deliberately `std::sync::Mutex`, NOT `parking_lot` — and precisely because the guard must NEVER be held across an `.await`... A std `MutexGuard` is `!Send`, so the compiler **REFUSES** to let it span an `.await` inside these `Send` spawned tasks — a compile-time guarantee... A `parking_lot` guard IS `Send` and would let exactly that mistake compile, so it is the more dangerous choice here, not the 'async-aware' one."

Spot-checked call sites confirm the practice matches the stated policy: `src/cli/serve/mod.rs:205-252` takes `update_info.lock()` only inside `if let Ok(mut info) = ...lock() { info.phase = ...; }` blocks sandwiched between `.await` points, never spanning one. `src/modules/search_engines/mod.rs:143-207` (`SESSION_EMPTY_COUNTS: LazyLock<Mutex<HashMap<...>>>`) is exercised only from plain (non-`async`) `fn`s, each a single chained `.lock()...` statement with the guard dropping at end-of-expression.

`parking_lot::Mutex`/`RwLock` (Send guards) are reserved for state that genuinely never crosses an await — e.g. `core/live/mod.rs:27` imports `parking_lot::RwLock` explicitly, and its `.read()`/`.write()` call sites (`live/mod.rs:231` etc.) are synchronous scoped blocks with an explicit `drop(sessions)` before any subsequent `.await`-calling method (`live/mod.rs:248`). `parking_lot::RwLock` guards being `Send` by default is true — but since it's used in a struct method calling only sync HashMap ops, the discipline holds by inspection, not by compiler force, which is exactly the asymmetry `api/mod.rs:213-226`'s comment calls out.

**Verdict**: The `std::sync::Mutex` vs `parking_lot`/`tokio::sync::Mutex` choice is a load-bearing, explicitly-reasoned safety mechanism (compiler-enforced no-hold-across-await for the two mutexes that live inside spawned async tasks), not a stylistic inconsistency.

---

## 6. Platform-specific / subprocess calls

**Searched**: `std::process::Command`/`tokio::process::Command`, `#[cfg(target_os`, `#[cfg(unix)]`, `#[cfg(android)]`, `libc` crate, `src/util/termux/`.

| Search | Count |
|---|---|
| `Command::new(` (std + tokio) | 30 |
| `#[cfg(target_os = ...)]` | **0**, anywhere in `src/`, `Cargo.toml` |
| `#[cfg(unix)]` | 20 |
| `#[cfg(android)]` / `#[cfg(windows)]` | 0 / 0 |
| `libc` crate — dependency / `libc::` calls | absent / 0 |

Despite the project's Android/Termux target, there is **no `target_os` conditional compilation anywhere** — Android-specific behavior is reached entirely two other ways:

1. **Subprocess to Termux's own CLI tools**, never JNI/NDK: `src/util/termux/mod.rs` (347 lines) bridges to `termux-location`, `termux-wifi-scaninfo`, `termux-telephony-cellinfo` via `tokio::process::Command` (`termux/mod.rs:293`, using `Command::new(cmd).args(args).kill_on_drop(true)`), with a two-tier failure cache distinguishing "binary won't spawn" (`ABSENT_TTL` = 5 min) from "invocation timed out" (exponential backoff ladder) — documented at length (`termux/mod.rs:1-42`) against a real bug where conflating the two silently blinded a running radar sweep. Non-Termux platforms simply fail to spawn and degrade to `None`.
2. **`#[cfg(unix)]`**, used exclusively for POSIX file-permission hardening, never business-logic branching:
   - `src/storage/mod.rs:384` `restrict_to_owner_only` — best-effort `chmod 0600` on the SQLite store + `-wal`/`-shm` files (holds PII + harvested keys).
   - `src/util/atomic_file/mod.rs:68` — `OpenOptionsExt::mode(0o600)` at file-create time; `mod.rs:53` — directory `fsync` after an atomic rename (ext4/f2fs durability on the Termux target).
   - `src/app/update.rs:420-430` — `self_restart()` via `std::os::unix::process::CommandExt::exec` to atomically replace the running process image on self-update, explicitly noting "`CommandExt::exec` is a safe function — it is not declared `unsafe`" (`update.rs:412`); a `#[cfg(not(unix))]` fallback (`update.rs:439-444`) just exits and asks the operator to restart.

Other `Command::new` call sites: `curl` (`util/curl_client`, `util/curl/mod.rs`, `util/egress/mod.rs` — an alternate HTTP transport for specific paid APIs where curl's own TLS stack is preferred), `tesseract` (`util/document_parse/ocr.rs` — OCR), `git`/`which` (`build.rs`, `app/update.rs`, `app/doctor/mod.rs` — self-update and environment diagnostics), plus test-only sentinels (`true`/`false`/`sleep`).

**Verdict**: Clean and low-risk — "platform-specific" here means shelling out to Termux's documented CLI sensors and narrowly-scoped POSIX permission calls, never conditional-compilation branching of core logic or native Android API surface.

---

## 7. Metaprogramming equivalents

**Searched**: `macro_rules!` definitions, `include!`/`include_str!`/`include_bytes!`, and whether `build.rs` generates code into `OUT_DIR`.

| Construct | Count |
|---|---|
| `macro_rules!` definitions | 4 |
| `include!(...)` (file inclusion, non-str/bytes) | 216 |
| `include_str!(...)` | 15 |
| `include_bytes!(...)` | 44 |
| `#[async_trait]` occurrences (proc-macro consumption) | 377 |

**`macro_rules!`** — all 4 are small, local, non-recursive, and each does something a plain function/constructor call could also do:
- `src/modules/username_search/sites.rs:67` and `src/modules/streaming_probe/sites.rs:44` — two independently-defined `macro_rules! s!` (same name, different modules) for terse `Site { .. }` literal tables (Maigret/Sherlock/WhatsMyName-style site-probe databases).
- `src/app/import/mod.rs:877` — `row!` wraps `note(output, format!(...))` for stdout/stderr routing based on `--output json`.
- `src/core/relation/builders.rs:1633` — `budget_spent!` is an early-return-on-deadline guard threaded through a fixed sequence of relation-derivation passes.

**`include!` (216 hits) is overwhelmingly one organizational convention**, not code generation: `#[cfg(test)] mod tests { include!("tests.rs"); }` at the bottom of nearly every source file (e.g. `src/core/module/mod.rs:482`, `src/modules/hibp/mod.rs`, `src/api/mod.rs:238`, ...). This keeps each module's tests in a sibling file while executing them inside the parent's own module scope (so `super::*` reaches private items) — functionally equivalent to `#[path = "tests.rs"] mod tests;` but chosen deliberately per repeated in-file comments (e.g. `src/core/coref/tests.rs:2`).

**`include_bytes!` (44)** is dominated by two deliberate binary-embedding choices:
- `src/api/routes/mod.rs:119-364` — the entire hand-rolled web SPA (HTML/CSS/~30 JS files) embedded into the binary for single-binary Termux deployment, e.g. `include_bytes!("../../web/js/views/live.js")` (`routes/mod.rs:339`).
- `src/util/oui/ieee.rs:32` — `const DATA: &[u8] = include_bytes!("ieee.bin");`, a hand-designed packed binary format (documented layout in `src/bin/gen_oui/main.rs:1-24` and `ieee.rs:1-26`) holding the ~39,000-entry IEEE MAC-vendor registry, binary-searched **in place** with manual little-endian byte reads (`le_u32`/`le_u16`, `ieee.rs:44-50`) rather than a `transmute` — explicitly because a transmute "is unsafe, and the crate forbids it" (`ieee.rs:103`). Chosen over a generated `const` array of ~20,000 `&'static str` (rejected for its multi-MB compile cost and per-string relocation cost on the Android target) or a runtime-parsed table (rejected for its decode/alloc cost on a phone). Regenerate/verify via `cargo run --bin gen-oui [-- --check]` (formerly `python3 scripts/gen_oui.py`, ported to Rust and byte-identity-verified against it).
- `src/modules/cert_intel/tests.rs:248` — a real self-signed DER certificate fixture, shared with the `cert_der` fuzz target's seed corpus.

**`build.rs` → `OUT_DIR` codegen**: exactly one generated file. `build.rs:24-38` writes `source_manifest.rs` (a `pub const SOURCE_FILES: &[(&str, u32)]` file-inventory + total-line-count constant) into `OUT_DIR`, consumed at `src/lib.rs:102`: `include!(concat!(env!("OUT_DIR"), "/source_manifest.rs"));` — a static data table for the debug bundle, not behavior-generating code.

**Verdict**: Metaprogramming is deliberately minimized — `macro_rules!` is trivial and rare, no proc-macro is authored in-repo (only consumed: `serde`/`thiserror`/`async_trait` derives), and the sole build-time codegen produces an inert data table.

---

## 8. Error handling shape

**Searched**: `src/core/error/mod.rs` for a top-level type; `thiserror::Error` derive usage count; representative modules (`hibp`, `shodan`) for how "missing key" / "bad key" / "network error" / "parse error" / "clean miss" are distinguished; `anyhow` usage.

| Search | Count |
|---|---|
| Files deriving `thiserror::Error` | **3** total |
| `anyhow` as a dependency | absent |

**One crate-wide error enum**, `src/core/error/mod.rs:5-35` (81 lines total), via `thiserror`:
```rust
pub enum Error {
    Storage(#[from] rusqlite::Error),
    Io(#[from] std::io::Error),
    Json(#[from] serde_json::Error),
    Http(String),          // NOT #[from] a live reqwest::Error — see below
    InvalidTarget(String),
    MissingKey(String),
    Module { module: String, message: String },
    RateLimited(String),   // distinct from a hard failure — see below
    Other(String),
}
pub type Result<T> = std::result::Result<T, Error>;   // line 79
```
`Http`'s conversion is hand-written rather than `#[from]` specifically for redaction: `From<reqwest::Error>` (`error/mod.rs:49-65`) calls `.without_url()` *before* converting, because request URLs embed API keys and PII in query strings and this error's `Display` reaches operator-visible sinks (SSE `ModuleError` events, the persisted dossier, `/api/v1/logs`) — "even code that does not go through the redaction helpers cannot leak a credential via `?`". `RateLimited` is kept distinct from a generic failure specifically so a 429 triggers backoff-and-retry rather than the same "abandon this provider for the scan" path a hard failure takes (`error/mod.rs:26-34`, citing a real prior bug where the two were conflated).

**Only 3 files use `thiserror::Error` at all**: the core `Error` above, plus two leaf/CLI-adjacent domain types that never enter the `Module::process` boundary — `DocumentParseError` (`src/util/document_parse/mod.rs:68-96`: `OcrUnavailable` vs `OcrTimeout{secs}` vs a captured nonzero exit code — three independently-actionable OCR failure modes) and `ExtractionError` (`src/util/entity_extractor/mod.rs:146-161`: config/pattern/validation, including a typed `ConfidenceFloor` variant "so callers can tell 'your threshold is unusable' from 'this extracted entity is malformed'"). `DocumentParseError: From<ExtractionError>` composes the two; both surface only at `hse ingest`'s CLI boundary (`src/cli/ingest/mod.rs:62,512`), never converted into `core::error::Error`.

**How the ~178 provider modules signal each failure class** — centralized in ~20 shared helpers under `src/util/http/` rather than each module hand-rolling a status cascade (spot-checked via `hibp` and `shodan`):
- **Missing key**: `ModuleContext::key(name)` (`core/module/mod.rs`) returns `Err(Error::MissingKey(name))` before any request is sent — a blank env value counts as absent, not just an unset one.
- **Invalid/exhausted key** (401/403/429, or a 200-with-in-body-failure some providers use instead): `note_keyed_error` (`util/http/fetch.rs:671`) calls `ctx.report_key_exhausted` to rotate the global key pool, while `keyed_ok_or_404` (`fetch.rs:748`, used at `modules/shodan/mod.rs:322`) still returns `Err` via `http_status_error` (`fetch.rs:686`) formatted as `Error::module(SRC, "HTTP {status}: {snippet}")`. `is_key_or_quota_message` (`fetch.rs:656`) additionally catches providers that report a burned key as `HTTP 200` with an in-body message.
- **Clean miss** (404, or a provider's documented "not found" code): `Ok(None)` / an empty `ModuleResult` — explicitly *not* an error (`fetch.rs:685` comment: "404 → host not in Shodan (clean miss)").
- **Transient rate-limit vs. exhausted quota**: `Error::RateLimited` (see above) vs. a normal `Err` — different downstream handling.
- **Transport failure**: any bare `?` on a `reqwest` call routes through the redacting `From<reqwest::Error>` automatically.
- **Parse/decode failure**: `json_decode` (`util/http/url.rs:55`) propagates `serde_json`'s error as `Error::Json`.
- (Tangential, same file) `error_cause_chain` (`util/http/url.rs:103`) walks a `reqwest::Error`'s `.source()` chain to recover the actual cause (TLS/DNS/timeout) that `.to_string()` alone discards, then redacts it — used for diagnostics rather than the typed `Error` itself.

**Verdict**: Exceptionally uniform. One error type for the whole module-facing surface, a shared and explicitly-reasoned vocabulary for "no key / bad key / rate-limited / clean miss / transport / parse", and only two narrow, non-overlapping exceptions for subsystems (OCR, extraction config) that sit outside the module-dispatch contract entirely.

---

## Cross-cutting observations

- `tests/architecture.rs` is a 4,309-line fitness-function suite enforcing exactly the invariants this audit independently confirmed by grep: layered-dependency direction (`core_does_not_import_modules:532`, `util_does_not_import_upper_layers:174`), registry integrity (`module_registry_count_is_stable:583`, `module_names_are_unique:601`), and even a deterministic-core/no-ML-dependency guard (`runtime_carries_no_ai_ml_inference_dependency:2320`). None of the 8 categories above were "undocumented" — every non-obvious choice (Mutex flavor, unbounded channel, packed binary blob, panic containment) carries an in-source rationale comment, which is itself a notable property for a from-scratch trust/port/refactor judgment.
- No category in this audit surfaced a construct needing scrutiny in the sense of "looks accidental or unexamined." The two closest to a genuine risk surface for a porting exercise are (a) the transitive `cc`/bundled-SQLite compilation step (§2) as the one non-pure-Rust build dependency, and (b) the sheer count of `std::sync::Mutex`/`parking_lot` mixing (§5) — mitigated in both cases by an explicit, verifiable design rationale rather than left implicit.
