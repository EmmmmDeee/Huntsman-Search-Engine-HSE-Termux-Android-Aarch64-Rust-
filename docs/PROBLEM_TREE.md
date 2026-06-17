# HSE — Problem Tree (engineering scope)

Scope: **functionality, features, bugs, errors, accuracy, performance, Rust code
quality, Termux/aarch64/no-root compatibility only.** Safety, privacy, legal,
licensing, terminology, and doc-prose findings are deliberately **excluded** here
(indexed under "Deferred" at the bottom for a later pass).

Every leaf is a *defined* problem: location, mechanism, impact, fix direction,
priority. Priorities: **P0** crash/data-corruption → fix first · **P1** breaks a
core guarantee (throughput, reproducibility, verified correctness) · **P2**
quality/robustness · **P3** minor.

---

## Root problem

> HSE is a feature-rich, unusually disciplined prototype, but its **runtime
> robustness, throughput, output-reproducibility, and verified correctness** have
> bounded gaps that cap reliability and performance. The gaps concentrate in five
> places: (B1) two untrusted-input panics, (B2) two non-deterministic outputs,
> (B3) blocking SQLite I/O on the async runtime, (B4) unverified core behaviour,
> and (B5/B6) maintainability debt and fragile scraper features.

---

## B1 — Bugs / crashes (correctness)

- **B1.1 [P0] `src/modules/au_electoral/parse.rs:14-15` (also `:30-37`)** — `find()`
  offset taken from the lowercased copy `lc` (line 11) is used to slice the
  *original* `text` (`&text[pos + …]`). `str::to_lowercase()` is **not**
  byte-length-preserving (`İ` U+0130 → 3 bytes, `ẞ`→`ß`, etc.), so a multibyte
  uppercase char before `"division of "`/`"enrolled in/for "` in the AEC/state-EC
  response shifts `pos` onto a non-char-boundary → **`str` index panic → module/
  scan abort**. Fix: search and slice the *same* string (operate on `lc`, re-case
  after), or use a boundary-safe case-insensitive find; `util::str_util::
  floor_char_boundary`/`truncate_safe` already exist for this.
- **B1.2 [P0] `src/modules/au_property/parse.rs:117-121`** — same class:
  `line.to_lowercase().find(&state_lc)` offset used to slice the original
  `line[..pos]` → panic on multibyte-uppercase property-portal HTML. Same fix.
- **B1.3 [P3] `src/modules/mylnikov/mod.rs:46`** — `range.unwrap_or(5000.0) as u64`
  on an untrusted, **un-range-validated** `f64` from Mylnikov JSON; a negative
  value wraps to a huge `u64` → accuracy misclassification (lands in the
  lowest-confidence bucket — conservative, no crash). Fix: validate/clamp before
  cast.
- **B1.4 [P3] `src/modules/reddit_user/mod.rs:164`** — `created_utc as u64`
  (`f64` epoch) drops the sub-second fraction and saturates negatives to 0;
  display-only `created_unix` attribute → cosmetic. Fix: `round`/document.
- **B1.5 [P3] `src/modules/dns_axfr/mod.rs:261`** — `label.len() as u8` truncates
  a label > 255 bytes. Unreachable on spec-valid input (labels ≤63, validated
  upstream); harden with an assert/guard for defence-in-depth.

## B2 — Determinism / reproducibility (a stated core invariant)

- **B2.1 [P1] `src/core/gexf/mod.rs:146`** — the shared-evidence edge label is
  `HashSet::intersection(...).collect::<Vec>()` joined **unsorted** into the GEXF
  `<edge label="…">` (emitted by `hse export --format gexf` and
  `GET /api/v1/scans/{id}/entities.gexf`). The label string varies run-to-run →
  breaks byte-stable/reproducible export. Fix: `sort()` the shared vec before
  `join(", ")`.
- **B2.2 [P2] `src/core/live/mod.rs:299`** — `LiveSessions::list()` collects
  `HashMap::values()` **unsorted** → `GET /api/v1/live` array order is
  non-deterministic. Inconsistent with the same file's `start()` eviction
  (`:220-228`), which already `min_by`+id-tiebreaks. Fix: sort by `id`/`started_at`.

## B3 — Performance / throughput (Termux ~2-worker reactor)

- **B3.1 [P1] `src/core/engine/mod.rs:132`** — `EventEmitter::emit` runs a
  **blocking** rusqlite `insert_event` (locks `Mutex<Connection>`) and is called
  from async `run`/`run_expansion` and from inside concurrently-spawned dispatch
  tasks (`dispatch.rs:787`), **once per entity** (hundreds per breach-heavy scan).
  → every event blocks a tokio worker on disk I/O + mutex, serializing the
  "concurrent" dispatch and stalling the reactor. Fix: feed events to a single
  async writer task over a channel (batch inserts), or `spawn_blocking`.
- **B3.2 [P1] `src/api/scan_handlers/mod.rs` (57,157-178,223,230,274,300,304,395)
  + `src/api/scan_export/mod.rs` (278,285,303,439)** — async axum handlers call
  synchronous rusqlite `Store` methods directly with **no `spawn_blocking`**. A
  slow query / WAL checkpoint / large `entities_for_scan` blocks a request worker
  and (via the shared Connection mutex) stalls all concurrent HTTP requests. Fix:
  `spawn_blocking` around Store calls, or a dedicated DB-actor task.
- **B3.3 [P2] `src/cli/export/environment.rs:41`** — blocking
  `std::process::Command::new("curl").output()` with **no `--max-time`**,
  reachable from the async debug-bundle export (`render_debug_bundle` →
  `render_environment`). A hung curl blocks the request worker indefinitely. Fix:
  `tokio::process` + timeout, or restrict to the sync CLI path.
- **B3.4 [P2] `src/util/http/client.rs:11` + ~8 `send().await` sites** — there is
  **no client-level total timeout** (only `connect_timeout`); 24 of ~32 fetch
  sites wrap in `tokio::time::timeout`, but ~8 do not — e.g.
  `web_crawler/crawl_util/mod.rs:251` (`fetch_robots`), `:232` (`resolve_seed`).
  A server that connects then stalls mid-body hangs the await forever. Fix: set a
  default `.timeout(...)` on the shared client, or wrap the stragglers.
- **B3.5 [P3] `src/util/diagnostics/{ledger.rs:21,analyse.rs:21}`** — blocking
  `std::fs::read_to_string`; confirm async reachability and move to `tokio::fs`
  if so.

## B4 — Test / correctness verification

- **B4.1 [P1] `src/core/correlator/rules/*`** — **12 AU correlation rules have no
  firing assertion** (tested only by id-presence-in-output, never that they
  actually produce a correlation): **AU-019, 020, 022, 023, 024, 025, 026, 028,
  029, 040, 041, 042**. A rule that silently stops firing passes CI; these are
  user-visible features. Fix: per-rule fixture tests asserting it fires with the
  expected severity + entity-uid set.
- **B4.2 [P2] `src/modules/exif_geo/parse.rs:8` `read_str`** — untested (needs a
  small EXIF fixture). Identity-bearing field extraction (Make/Model/Serial/
  Owner/Artist/Software) is unverified → a parse regression ships silently.
- **B4.3 [P2] `src/modules/cert_intel/mod.rs:186` `parse_certificate`** — untested
  (needs a DER fixture). SAN/issuer/org extraction unverified.
- **B4.4 [P2] ~50 module test files (88 assertions) assert only
  `assert!(!…is_empty())`** (hunter_io, gravatar, seon, numverify, fullcontact,
  psbdmp, onyphe, …) → confirm "something emitted" but not entity kind, value, or
  evidence correctness; structural regressions pass. Fix: strengthen to assert
  kind + value + key evidence attributes.

## B5 — Code quality / architecture / maintainability

- **B5.1 [P2] Layering breach: `core` imports `crate::modules` in production** —
  `src/core/engine/mod.rs` (8 sites incl. 241-243,247,254,461,908) +
  `src/core/engine/enrich.rs:240` — violates the CLAUDE.md invariant "core must
  NOT import modules". Worse, `tests/architecture.rs:140` *allowlists* those
  `modules::*` paths in the `core→util` guard (encoding the breach as expected),
  and no guard scans `core` for `crate::modules`. Fix: invert the dependency
  (register the needed hooks — `reset_budget`, `identify_api_key` — as
  trait objects/fn-pointers from the module registry into core), drop the
  allowlist entries, add a `core_does_not_import_modules` guard.
- **B5.2 [P2] `src/core/engine/dispatch.rs` (265,426,475,498,620) +
  `engine/mod.rs:878`** — 6× `#[allow(clippy::too_many_arguments)]`
  (`run_expansion` = 12 args; `dispatch_target` is an 8-arg pass-through). Fix:
  collect the per-scan mutable state (`scan_id, target, ctx, opts, entity_map,
  stats, dispatched`) into a `DispatchCtx`/`ScanState` struct; the 8-arg
  signatures and the wrapper collapse.
- **B5.3 [P2] Duplicated logic that can drift** — `is_freemail`/`FREEMAIL`
  (`util/oathnet_batch/helpers.rs:24` vs canonical `util/domains/mod.rs:142`);
  `nonempty` (`whoisxml/mod.rs:225` vs `util/str_util/mod.rs:14`); `country_name`
  (`phone_area_geo` vs `util/geohash/country.rs`). Two lists/tables that can
  disagree → inconsistent classification. Fix: route all callers through the
  canonical util.
- **B5.4 [P3] Dead/duplicated helper** — `util::stats::mode`/`mode_or` have **0
  non-test callers**; `wigle/mod.rs:556,570` reimplements them byte-for-byte. Fix:
  delete one copy; route wigle through `util::stats` (or remove the unused util).
- **B5.5 [P3] `KEY_ENV` convention inconsistency** — 26 key-gated modules define a
  `KEY_ENV` const (mixed `const`/`pub(crate)`/`pub(super)`); 7 skip it and
  hardcode the env literal inline (`virustotal, abuseipdb, api_key_probe,
  cell_intel, wifi_intel, contact_enrich, wigle`). An env-var rename can desync
  silently. Fix: standardize on a per-module const.

## B6 — Functionality reliability (features that may silently not work)

- **B6.1 [P2] Scraper-class modules are fragile** — `au_people` (whitepages/
  truepeoplesearch), `au_electoral`, `au_property`, `search_engines` (17 SERPs),
  `username_search` (300+ sites) all depend on spoofed-UA HTML parsing of
  frequently-changing third-party pages; `au_property` endpoints are noted as
  possibly speculative (may not work at all). High silent-breakage rate, and most
  have only `!is_empty()` or no fixture-backed parse tests. Fix: golden-fixture
  parser tests + per-source health/last-success telemetry so breakage is visible.
  *(Robustness only here; the legality of these sources is parked.)*
- **B6.2 [P3] `src/modules/mls/mod.rs:28` `DEFAULT_KEY = "test"`** — if `"test"`
  is not a live key, the module is effectively inert without `HUNTSMAN_MLS_KEY`
  (silent no-op feature). Fix: gate the module on a real key / surface a
  "needs key" status instead of a dummy default.
- **B6.3 [P3] `src/modules/gleif_lei/mod.rs:82`** — the ABN→LEI filter is
  acknowledged in-code as "unreliable" (falls back to feeding off Organisation
  entities) → known-degraded accuracy path. Fix: revisit the match key or
  down-rank its output.

---

## Verified sound (checked and cleared — do not re-investigate)

- **Injection:** `termux_cmd`, `util::curl`, `api_key_probe`, `curl_client` pass
  values as **argv** (no shell, no interpolation).
- **HTTP SSRF:** shared client uses an `SsrfResolver` (drops private IPs at
  resolve, TOCTOU-safe) + private-IP-refusing redirect policy; curl fallback pins
  a vetted public IP; literals gated by `url_host_is_private`.
- **TLS:** reqwest 0.12 rustls + webpki-roots; no `danger_accept_invalid_certs`.
- **Regex:** all 20 `Regex::new` sites are cached (`OnceLock`/`Lazy`) — no
  per-call recompilation.
- **Panics:** all other handed leads guarded — `abn:209` (`!is_empty()`),
  `util/html` decode (ASCII-boundary find), geometry median/footprint/circle
  (empty/zero/NaN-guarded), `address_au` (length-checked slices).
- **Concurrency:** every fan-out is semaphore-capped; no unbounded `JoinSet`.
- **Numeric:** confidence `clamp(0,1)`, corroboration `saturating_add`, divisions
  zero-guarded; `mode()` tie-breaks deterministically.
- **Portability:** **0 `unsafe`**, 0 arch-specific intrinsics, pure Rust; Termux
  sensor modules no-op cleanly off-device; `/proc/net/arp` read via async
  `tokio::fs`.
- **Registry:** all 118 modules registered & reconcile to dirs (no orphans);
  every module has test code, `produces()`, and a non-empty `attack_techniques()`.

## Deferred (out of current scope — revisit later)

Indexed so nothing is lost; **not** to be actioned in this pass.
- **Security:** hardcoded live default keys (`util/keys/constants.rs:137-158`),
  whois-referral raw-TCP SSRF, key-in-URL error/log leaks, cleartext-secret
  persistence/exposure, auto-dossier `0644` perms.
- **Privacy/Legal/Licensing:** real-PII test fixture & root `DOSSIER_*.md`,
  electoral-roll/whitepages/title scraping legality, GPL-3.0 `alertify` +
  missing `NOTICE`/attribution, unencrypted-at-rest, no authorised-use notice.
- **Terminology:** "operator" (282×) → user/analyst; `key_harvest` /
  `API_KEY_HUNTING_GUIDE.md` naming.
- **Docs:** module-count drift across README / `docs/MODULES.md` / CHANGELOG /
  `FAULT_TREE_ANALYSIS.md`.
