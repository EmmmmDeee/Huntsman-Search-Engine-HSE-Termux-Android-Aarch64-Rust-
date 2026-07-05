# Huntsman — Unified Problem & Capability Tree (living document)

> **One mission.** Make Huntsman the fastest, most correct, most *reproducible*
> offensive OSINT / GEOINT / NETINT engine that runs **on-device** (Termux,
> aarch64, no root), with a deliberate **Australian** bias, and **surpass
> SpiderFoot** (breadth, speed, correlation) and **Maltego** (entity linking)
> **without heavy in-app graphing** — by delivering the *analytic conclusion*
> deterministically instead of making an analyst pivot a graph by hand.
>
> Scope of this tree: **functionality & features only** — bugs, errors, accuracy,
> performance, code quality, capability gaps, Termux/aarch64 compatibility.
> Safety / privacy / legal / licensing / terminology / doc-prose are **out of
> scope here** (indexed under §7 *Deferred*, to be handled in a separate pass).

This is a **running document**: it is the single source of truth for what is
wrong, what is missing, and exactly how each is to be solved. It is **paired with
its dual, [`SOLUTION_TREE.md`](SOLUTION_TREE.md)** (organised by *what we build* —
so a primitive that closes many problems shows up as the leverage point it is). The
two are maintained **in lockstep** (see `SOLUTION_TREE` §0): a change touches both in
the same commit, analysis alternates **problem→solution** and **solution→problem**,
and **gap analysis** (`SOLUTION_TREE` §4) is the live bridge between them. Update
both in the same commit as the work (status flips + a line in each maintained log).
**Every change lands on `main`.**

---

## 1. Engineering doctrine — how every node below is solved

Planned and executed in the style of **Andrew Gallant (burntsushi)** — author of
`ripgrep`, `regex`, `aho-corasick`, `memchr`, `bstr`, `fst`, `csv`, `walkdir`,
`quickcheck`. The doctrine is not decoration; it dictates the *solution* on every
leaf:

1. **Measure, never guess.** Every performance claim is backed by a `criterion`
   benchmark and a profile. Hot paths are found, not assumed.
2. **Prove correctness by exhaustion.** Pure functions get unit tests *and*
   `proptest` properties ("for all inputs: no panic; output invariant under
   permutation; round-trips"). Every parser that eats untrusted bytes gets a
   `cargo-fuzz` target. A bug fixed without a test that would have caught it is
   not fixed.
3. **Finite automata for matching.** Multi-pattern scanning is `aho-corasick`
   (Teddy/SIMD), substring search is `memchr::memmem`, big static lookup tables
   are `fst` (memory-mapped finite-state transducers). No hand-rolled `.find()`
   offset arithmetic on transformed copies (that is exactly the T0 panic class).
4. **Bytes, not `String`, for input you don't control.** Untrusted HTML/JSON is
   handled with `bstr`/`&[u8]` so invalid UTF-8 and multibyte boundaries can
   never panic.
5. **Allocation-conscious, streaming, bounded memory.** This is a phone. Prefer
   zero-copy slices, reuse buffers, cap everything, stream don't slurp. `fst`
   keeps lookup tables flat in RAM.
6. **Minimal, pure-Rust dependencies.** No C, no native-TLS — Termux-safe.
   `aho-corasick`/`memchr` are *already in the tree via `regex`* (promoting them
   to direct deps is free); `bstr`/`fst` are tiny and pure-Rust;
   `proptest`/`criterion`/`arbitrary` are dev-only (zero runtime/binary cost).
   `#![forbid(unsafe_code)]` governs **our** crate only — vetted deps may use
   `unsafe`/SIMD internally.
7. **Determinism is a feature.** Same input → byte-identical output, always. It
   is what lets Huntsman beat Maltego without a graph and beat SpiderFoot on
   reproducibility. Guard it with property tests, not vigilance.
8. **Simple data structures over clever abstractions. Document everything.**

**Sequencing rationale (significance × severity):** stop the crashes (§3.0) →
restore the guarantees the product's identity rests on (§3.1) → lay the
primitives that make all later work fast *and* safe (§3.F) → pay down quality
debt (§3.2) → expand capability to surpass the competition (§4). Foundations
come before features on purpose: with the right primitives, the capability
program is cheap; without them, it is slow and fragile.

## 2. Legend & node schema

Status: `[ ]` open · `[~]` in progress · `[x]` done · `[-]` deferred.
Priority: **P0** crash/corruption · **P1** breaks a core guarantee · **P2**
quality/robustness · **P3** minor · **CAP** capability/feature.
Each node: **ID · statement · location · impact · → optimal solution · prio · status**.

Current baseline (grounded in the codebase, 2026-06-18): **126 modules** (93 free
· 28 key-gated · 5 paid) across 14 categories (Infrastructure 21, Geo 20, People
16, DnsRecon 13, Breach 11, Social 11, Email 6, Corporate 9, Phone 3, Web 5,
Sensor 4, Threat 3, Search/Other 2 each); 64 native correlation rules
(AU-001…AU-064); 0 `unsafe`; deterministic entity merge; SQLite store; SSE live;
axum SPA. Deps: `regex` in; **`proptest` 1.11 + `criterion` 0.8 direct (dev-only,
zero shipped cost — F.3); `aho-corasick` + `memchr` now direct deps (F.1,
`util::scan` + `util::html`); `bstr`, `fst`, `arbitrary` still NOT direct.**

---

## 3. The tree — defects & foundations (do these first, in order)

### 3.0 — Tier 0 · P0 correctness (crashes) — FIX FIRST

- **`[x]` T0.1 · `src/modules/au_electoral/parse.rs:14-15,30-37`** — `find()` on
  the lowercased copy `lc`, offset used to slice the **original** `text`.
  `to_lowercase()` is not byte-length-preserving (`İ`→3 bytes, …) → non-char-
  boundary `str` index **panic → scan abort** on multibyte-uppercase response
  HTML.
  → **Solution:** delete the offset-on-a-copy pattern. The markers are ASCII, so
  build a cached **`aho-corasick`** automaton (ASCII-case-insensitive) over
  `["division of ", "enrolled in ", "enrolled for "]` and search the original
  `&[u8]`; the returned offset is valid in the original. Walk the name with
  `char_indices` (boundary-safe). Add a `proptest` `fn(s in ".*") { let _ =
  extract_division(&s); }` (no panic for any input) **and** a `cargo-fuzz` target
  seeded with real AEC/ECQ HTML. **P0**
- **`[x]` T0.2 · `src/modules/au_property/parse.rs:117-121`** — same class:
  `line.to_lowercase().find(&state_lc)` offset slices the original `line[..pos]`.
  → **Solution:** identical — `memchr::memmem`/`aho-corasick` over the original
  bytes + boundary-safe walk; shared proptest+fuzz harness with T0.1. **P0**
- **`[x]` T0.3 · untrusted numeric casts** — `mylnikov/mod.rs:46`
  (`range.unwrap_or(5000.0) as u64` on un-validated `f64`; negative → huge u64 →
  misclassification), `reddit_user/mod.rs:164`, `dns_axfr/mod.rs:261`.
  → **Solution:** validate/clamp before cast (`f64::clamp` to a sane range,
  reject non-finite); a `proptest` over the JSON deserialiser asserting bounded
  output. **P3** (rolled here as the same "trust no input number" fix.)

### 3.1 — Tier 1 · P1 core guarantees

- **`[x]` T1.1 · Determinism** — `core/gexf/mod.rs:146` joins a `HashSet`-derived
  shared-source label **unsorted** into exported XML; `core/live/mod.rs:299`
  returns `HashMap::values()` **unsorted** to `GET /api/v1/live`.
  → **Solution:** `sort()` before emit in both. Then make it a *guarantee*: a
  `proptest` that permuting input entity/session order yields **byte-identical**
  render. Extend to a general "renderers are permutation-invariant" property over
  CSV/JSON/GEXF/dossier. **P1**
- **`[x]` T1.2 · Throughput (the on-device perf guarantee)** —
  `core/engine/mod.rs:154` runs blocking rusqlite `insert_event` **per entity**
  from async + spawned dispatch tasks; `api/scan_handlers` (8 sites) +
  `api/scan_export` (4) call sync `Store` on async workers with no
  `spawn_blocking`. On a ~2-worker Termux reactor this serialises "concurrent"
  work and stalls the loop.
  → **Solution:** a single **DB-writer actor** owning the `Connection`, fed by a
  bounded `mpsc`; producers `send` non-blocking; the actor batches inserts in one
  transaction. API reads go through `spawn_blocking` (or the actor + `oneshot`).
  **Measure it:** `criterion` bench of events/sec and p99 dispatch latency pinned
  to 2 worker threads, before/after; this becomes the published "fast on a phone"
  number. **P1** ◑ **API-read part shipped** (T2.2: the 11 heavy read/export
  handlers now `spawn_blocking`), but the 2026-06-17 deep re-audit found **two
  handlers still blocking the reactor**: `api/scan_handlers::scan_import` runs the
  upload parse + `upsert_entities_batch` + `derive_all` + a **full `Correlator::run`**
  synchronously in the handler future (`mod.rs:176`) **and bypasses `scan_semaphore`**
  (so concurrent 16 MB imports aren't bounded), and `api/handlers::stats:164` runs
  `list_scans(10_000)` + full-JSON deserialise on the reactor. → wrap both in
  `spawn_blocking` (gate `scan_import` behind `scan_semaphore`; fold `stats` into a
  SQL `GROUP BY status` aggregate); roll into the DB-writer-actor pass.
  ✅ **Cycle 2 (2026-06-17): `scan_import` + `stats` both fixed.** `scan_import`
  now acquires `scan_semaphore` before parsing, then dispatches all sync store
  work (`upsert_scan`, `upsert_entities_batch`, `derive_all`, `Correlator::run`)
  to `tokio::task::spawn_blocking`. `stats` wraps `list_scans(10_000)` in
  `spawn_blocking`. Remaining: the engine's per-entity `insert_event` + the full
  DB-writer actor (the planned long-term home for the write path).
  ✅ **Cycle 3 (2026-06-17): engine `insert_event` fixed with `block_in_place`.**
  `EventEmitter::emit` now clones the `Arc<StoragePort>` and wraps
  `store.insert_event(&event)` in `tokio::task::block_in_place`, moving the
  blocking rusqlite call off the async reactor thread. Requires multi-thread
  runtime (production: 2-worker `new_multi_thread`); `tests/halting.rs` (3 tests)
  + `tests/smoke.rs` (42 async tests) upgraded from default `current_thread` to
  `multi_thread, 2` flavor to match production and avoid a panic.
  ✅ **Cycle 10 (2026-06-17): DB-writer actor — T1.2 fully closed.**
  `block_in_place` per entity replaced by a dedicated `DbWriter` actor
  (`core/engine/writer.rs`): an unbounded-mpsc-backed tokio task that drains the
  queue in `spawn_blocking` chunks (up to 64 events per call), so `EventEmitter::emit`
  is fully non-blocking. `ScanEngine::new` spawns the actor; `run_with_ledger_inner`
  calls `writer.flush().await` after the last `ScanComplete` emit so the caller
  always sees a complete event log. The one sync test that created a `ScanEngine`
  (`recall_resolves_a_fullname_seed_despite_reformatting`) is now
  `#[tokio::test] async fn` (it already used Tokio broadcast). T1.2 `[~]`→`[x]`.
- **`[x]` T1.3 · Verified correctness — all dispatched rules have firing fixtures** —
  AU-019, 020, 022, 023, 024, 025, 026, 028, 029, 040, 041, 042 had per-rule firing
  assertions added (2026-06-17). AU-021 and AU-030 lacked direct firing tests
  entirely. The dispatch-table **meta-guard**
  (`every_dispatched_correlation_rule_has_a_firing_test` in `tests/architecture.rs`)
  now enumerates every entry in `RULES` + `RELATION_RULES` and verifies ≥1 positive
  firing assertion exists — a future `AU-060` without a firing fixture fails CI. All
  56 dispatched rules pass. `[x]` — fully closed.
- **`[x]` T1.4 · Architecture — `core` imports `crate::modules`** —
  `core/engine/mod.rs` (8 sites) + `enrich.rs:240`, violating the CLAUDE.md
  invariant; `tests/architecture.rs:140` *allowlists* the `modules::*` paths
  (laundering the breach); no guard scans `core`.
  → **Solution:** invert the edge — define a `core::registry::Hooks` struct of
  fn-pointers/trait objects (`reset_budgets`, `identify_api_key`, …) that the
  `modules` layer installs at startup; `core` calls through the hook, never
  `use crate::modules`. Remove the allowlist; add
  `tests/architecture.rs::core_does_not_import_modules` scanning `src/core/**`.
  **P1** (gates "highest-quality product": velocity & testability downstream.)
- **`[x]` T1.5 · `finalise_scan` still blocks one reactor worker at scan-end (LOW-MED)** —
  `finalise_scan` is a sync `fn` called directly from the async
  `run_with_ledger_inner`; it makes four blocking rusqlite calls in sequence:
  `upsert_entities_batch` (entity bulk persist), `upsert_scan` (scan record update),
  `persist_relations` (one SQL insert per edge in a loop), and `Correlator::run` (a
  full SQL correlation pass over all 56 rules, O(entities)). In CLI single-scan mode
  this is invisible (no concurrent work). In `hse serve`/`hse live` with multiple
  scans running concurrently, this blocks one of the 2 Termux reactor workers for
  O(entities) time during scan finalisation, delaying concurrent API requests (e.g.
  SSE pushes, other scan dispatch). Unlike the now-fixed per-entity `insert_event`
  hot path (T1.2: N separate `block_in_place` calls), these are O(1) bulk
  transactions — the blast radius is bounded to the scan-end window.
  → **Solution:** wrap `finalise_scan`'s body in `tokio::task::spawn_blocking`;
  `EventEmitter::emit` is already a non-blocking `submit` to the DB-writer actor, so
  the emitter clone passes safely into the `'static + Send` closure. The
  `writer.flush().await` barrier in `run_with_ledger_inner` must follow the
  `spawn_blocking` task's completion (guaranteed — `flush` is called after the
  `spawn_blocking` join resolves). **LOW-MED** (server-mode impact only; single-scan
  CLI-transparent). *Surfaced by cycle 11 S→P.*
  ✅ **Delivered (cycle 14, 2026-06-17): SOL-FINALISE-BLOCKING.** `finalise_scan`
  made `async fn`; body dispatched to `tokio::task::spawn_blocking` capturing
  `Arc::clone(&store)` + `emitter.clone()` + `cancelled` bool snapshot.
  `persist_relations` and `run_correlator` inlined into the closure (single
  call-sites, removed as methods). **Paired:** `SOLUTION_TREE` SOL-FINALISE-BLOCKING
  `[ ]`→`[x]` + §2/§3/§4/§5 updated — same commit.

### 3.F — Tier F · Foundations (build the primitives once; everything after is cheap)

- **`[~]` F.1 · Adopt the matching/automata toolkit** — parsers and the universal
  key/secret scanner currently hand-roll `.find()`/`.contains()`/`chars()` scans
  (slow, and the source of the T0 panic class).
  → **Solution:** promote **`memchr`** + **`aho-corasick`** to direct deps (free —
  already transitive via `regex`); add **`bstr`** for untrusted HTML. Create one
  `util::scan` module that owns cached `aho-corasick` automata for: the universal
  API-key scanner, HTML marker extraction, placeholder/denylist matching. All
  untrusted-byte scanning routes through it. Benchmark scan MB/s with `criterion`.
  **P1-enabler** ◑ **Substrate landed + first consumer (2026-06-17, SOL-F1).**
  Promoted **`aho-corasick`** to a direct dep (`memchr` deferred until a direct
  `memmem` consumer exists — promoting it unused would trip `cargo machete`); built
  **`util::scan::MatchSet`** (cached automaton: `is_match` "contains any" +
  leftmost-`find`, ASCII-CI variant, boundary-safe offsets) with unit tests + a
  `criterion` bench; routed the **first consumer** — the search-engine anti-bot
  `is_captcha_page` vendor-signature scan — through it, **byte-for-byte equivalent**
  (the 5 existing captcha tests, incl. the false-positive guard, pass unchanged).
  **+2 more consumers (2026-06-17):** the key-harvest `contains_excluded_context`
  gate (`new_ascii_ci` against the original — equivalent *and* drops a per-call
  `to_ascii_lowercase` alloc on a hot path) and wigle `is_generic_ssid`, both proven
  equivalent by their existing case-insensitivity tests.
  **+ prefix-table consumer (2026-06-17, cycle 4):** `util::scan::PrefixMatcher`
  (`LeftmostFirst`, `find_prefix`) + `PREFIX_GROUPS` map (handles same-prefix
  duplicate entries like `phc_`/`pk_live_`); `identify_vendor_api_key` O(N=170)
  `starts_with` loop replaced with O(1) aho-corasick + O(K≤2) group iteration.
  Intentional behavior change: specific-prefix min_len failure no longer cascades
  to a shorter generic prefix (quality improvement — prevents misclassification);
  proptest-backed + deterministic cascade-prevention test.
  **+ `au_electoral` HTML markers (2026-06-17, cycle 5):** `MatchSet::find_range`
  added to `util::scan`; `DIVISION_MARKER` + `ENROLLED_MARKERS` statics in
  `au_electoral/parse.rs`; two-pattern enrolled scan is one aho-corasick pass.
  **+ `address_au::state_code` state-name scan (2026-06-17, cycle 6):**
  `MatchSet::find_id` API added; `STATE_NAMES_MATCHER` static in `util/address_au`;
  replaces `to_lowercase()` + 8-way contains loop with one SIMD pass. The
  `au_property` path was examined and ruled out (single dynamic state string already
  known from `extract_state` — not a MatchSet target).
  **+ `memchr` direct dep + `decode_entities` SIMD byte scan (2026-06-17, cycle 12):**
  `memchr = "2"` promoted to a direct dep; `decode_entities` in `util/html/mod.rs` (the
  hot entity decoder on *every* scraped response body) replaces `s.contains('&')`,
  `rest.find('&')`, and `inner.find(';')` with `memchr(b'&', …)` / `memchr(b';', …)`
  SIMD byte searches. `&` and `;` are ASCII so byte offsets are valid char boundaries.
  *Remaining:* `bstr` adoption (no direct consumer yet — promote with first direct use).
- **`[~]` F.2 · `fst`-backed datasets (phone-first + de-duplication)** — many
  static tables are hand-coded `&[&str]`/`match` arms, several **duplicated**
  (freemail in `util/oathnet_batch` vs `util/domains`; `country_name` in
  `phone_area_geo` vs `util/geohash`; OUI; AU postcode/suburb; division→state;
  provider weights; domain denylists).
  → **Solution:** a `build.rs` step compiles `data/*.txt` source lists into
  `*.fst` (`fst::Set`/`Map`), embedded via `include_bytes!` and queried through
  one canonical `util::dataset` API. Result: **one** authoritative copy of each
  table (kills the B5.3 drift), **flat RAM** (memory-mapped FST — critical on a
  phone), O(key) lookups, and trivial fuzzy/prefix queries (Levenshtein automata)
  for free → directly powers typosquat/username-variant/suburb-matching.
  **P1-enabler** ◑ **De-dup goal met** (see T2.6): the drift-prone *shared* lists
  (freemail, country_name) are now single-sourced via delegation — `fst` is not
  needed for these (≈30–250 entries; memory-mapping buys nothing at that size).
  *Remaining (premise corrected, cycle 18):* the "large table" assumption was wrong —
  Huntsman uses curated subsets: OUI ≈111 entries (not the full IEEE registry ≈30k),
  AU postcode ≈72 entries, phone area codes ≈65 entries. At these sizes `fst` adds a
  heavy compile dep for zero on-device benefit; `fst` adoption is `[-]` (accepted-
  won't-build). Levenshtein fuzzy matching (suburb/username-variant) remains a future
  capability goal but can be pursued via a lighter mechanism.
- **`[~]` F.3 · Proof & measurement infrastructure** — was: no property testing,
  no fuzzing, only `#[ignore]` perf baselines.
  → **Solution:** add (dev-only, zero runtime cost): **`proptest`** suites for
  every pure function (parsers: no-panic; `Entity::absorb`: commutative +
  idempotent + clamped; geo: `parse_coords`↔`format` round-trip; `normalise_*`:
  idempotent); **`cargo-fuzz`** + **`arbitrary`** targets for *every* untrusted
  parser (html strip, all response parsers, dossier/txt/html import, `dns_axfr`
  wire, DER), seeded from `raw_archive` samples; **`criterion`** benches for
  dispatch throughput, the correlation pass (formalise the existing O(n²) guard),
  `aho-corasick` scan, and `fst` lookup. CI compiles benches (`--no-run`) and
  runs the fuzz corpora as regression tests. **P1-enabler** ✅ **proptest landed**
  (dev-dep, pinned 1.11): 13 properties pinning the T0-panic-class boundary
  guarantees (`find_ascii_ci`/`truncate_safe`/`char_window`/char-boundaries
  never slice mid-codepoint), `slugify`/`ascii_digits`/`truncate_display` charset
  + shape, `normalise` **idempotency for every kind** (UID-stability invariant),
  `derive_uid` determinism, and `geohash`/`parse_coords` totality + round-trip.
  Regression seeds committed. **Found + fixed a real bug** (`slugify` leaked raw
  non-ASCII/uppercase-accented chars into correlation tags). **`criterion` landed**
  too (dev-dep, lean — no plotters/rayon): `benches/scan_throughput.rs` measures
  the hottest pure parse-path scanners (`find_ascii_ci` hit/miss on a 14 KB body,
  `fold_ascii_lower`, `slugify`, `geohash`); CI compiles them (`--no-run`) so a
  perf-path API change can't rot them.
  **+import-parser proptest (2026-06-17, SOL-F3):** `parse_dossier`,
  `parse_oathnet_txt`, and `parse_oathnet_html` each get a `proptest!` no-panic
  property (`mod prop` in `cli/import/tests.rs`) over arbitrary Unicode strings
  (≤512 chars); also asserts every emitted entity value is non-empty. 3 new
  properties, 3,032 lib tests, gate green.
  *Remaining:* `cargo-fuzz` (nightly/libfuzzer — gate on a CI lane, not on-device
  aarch64); widen criterion to the correlation pass once a bench-visible entry
  point exists.

### 3.2 — Tier 2 · P2 robustness & quality

- **`[x]` T2.1 · HTTP timeouts** — `util/http/client.rs:11` sets no client-level
  total timeout; ~8 of ~32 `send().await` sites are unwrapped (`web_crawler`
  `fetch_robots:251`, `resolve_seed:232`, …) → a post-connect stall hangs forever.
  → **Solution:** set a default `.timeout(...)` on the shared client (belt-and-
  braces with the 24 explicit wraps) and wrap the stragglers. **P2**
- **`[x]` T2.2 · Blocking `curl` in async export** — `cli/export/environment.rs:41`
  blocks a request worker (no `--max-time`).
  → **Solution:** `tokio::process` + `--max-time` + `tokio::time::timeout`, or
  gate the env fingerprint to the sync CLI path. **P2**
- **`[x]` T2.3 · Fixture-test the binary parsers** — `exif_geo::read_str` and
  `cert_intel::parse_certificate` were untested against real binary input.
  → **Solution:** done — a real OpenSSL self-signed DER in
  `cert_intel/testdata/selfsigned.der` + a hand-built little-endian EXIF/TIFF
  (constructed in-test, reviewable) drive the parsers end-to-end. **The fixtures
  exposed two real bugs in `cert_intel`'s hand-rolled DER scanner — both fixed:**
  (1) `extract_sans_from_der` broke on the SAN extension's `OCTET STRING →
  SEQUENCE` wrappers, returning **zero** SANs on every real cert (its primary
  feature — TLS-SAN subdomain discovery — was dead on real input); now descends
  the wrappers with a proper DER length decoder. (2) `extract_serial_hex` returned
  the **version** INTEGER, not the serial; now skips the `[0] EXPLICIT` version
  wrapper. `extract_gps` (N/S/E/W sign handling) + `read_str` now covered via the
  TIFF. **P2** ✅ fixtures double as future F.3 fuzz seeds.
- **`[x]` T2.4 · Strengthen weak tests** — premise was an **over-count**: a grep of
  `assert!(!…is_empty())` returns 88 lines, but on inspection nearly all are a
  *guard* immediately paired with a content assertion (`assert_eq!(x[0], …)`,
  `.iter().any(|s| s == "<specific dork>")`, per-element kind/confidence loops,
  table-soundness invariants). They already assert **kind + value + key evidence**.
  → **Solution (done):** audited all 88; only **two** were genuinely
  sole-assertion-on-output — `ipinfo` non-CDN sanity counter-check and
  `email_header_geo`'s "two entities" test (count/kind unverified). Both upgraded
  to assert entity kind + value + tags/evidence. The fixture-corpus drift-detector
  idea folds into F.3. **P2** ✅ measured-not-assumed; 2 real gaps closed.
- **`[x]` T2.5 · Engine arg-bloat** — 6× `#[allow(too_many_arguments)]`
  (`run_expansion` = 11 args; `dispatch_target` 8-arg pass-through).
  → **Solution:** bundle per-scan mutable state into a `DispatchCtx`/`ScanState`
  struct; the wrapper and the allowlist entries vanish. **P2** ✅ Two bundles:
  `DispatchCx` (immutable `scan_id`/`target`/`opts`/`is_expansion`) + `DispatchState`
  (mutable `entity_map`/`stats`/`dispatched`) thread the 5 dispatch fns; the
  6th (`run_expansion`) takes an `ExpansionState` by value + destructures, so its
  400-line body is byte-identical. All 6 allows removed.
- **`[x]` T2.6 · De-duplicate helpers** — `is_freemail`/`FREEMAIL`, `nonempty`,
  `country_name`, dead `util::stats::mode`/`mode_or` (wigle reimplements it),
  inconsistent `KEY_ENV` (7 modules inline the literal).
  → **Solution:** route all callers to canonical `util` (datasets via F.2);
  delete dead copies; standardise `KEY_ENV` as a per-module const. **P2/P3** ✅ All
  genuine drift-prone duplicates resolved: dead `util::stats` deleted; `nonempty`
  delegated; `country_name` already delegated (`phone_area_geo` → canonical ISO
  table); and the last real one — `is_freemail` — now delegates to the
  authoritative ~60-entry `util::domains` list. Crucially this was **not** a blind
  merge: `oathnet_batch`'s 7-entry copy served a *second* purpose (the curated
  set to synthesise `{handle}@{provider}` emails — 60 would 8× the query
  fan-out), so the *predicate* was delegated while the *synthesis* set was kept
  and renamed `SYNTH_EMAIL_PROVIDERS`. `KEY_ENV` left as-is: each literal is
  module-local and cannot drift against another module, so it's a cosmetic style
  nit, not a duplication/drift risk.
- **`[ ]` T2.7 · Scraper resilience** — `au_people`, `au_electoral`, `au_property`,
  `search_engines` (17 SERPs), `username_search` (300+ sites) parse churning HTML;
  some endpoints speculative → high silent-breakage.
  → **Solution:** rewrite parsers on `bstr`/`aho-corasick` (F.1), back each with a
  **golden fixture** (saved real response) so a layout change fails a test, and
  add a per-source **health signal** (last-success, parse-rate) surfaced in
  `hse doctor` + the SPA; auto-flag a source "drifted" when parse-rate drops.
  **P2** *(robustness only; source legality is parked in §7.)*
- **`[x]` T2.8 · Unbounded response-body reads (on-device OOM / DoS)** *(fully closed 2026-06-17)* — several
  fetch paths buffer an *entire* response body into RAM with the size check applied
  only *after* the read (or no cap at all), bypassing the codebase's own
  `JSON_BODY_CAP` / `read_body_capped` discipline (§1.5 "cap everything, stream
  don't slurp"). On a phone a hostile or compromised endpoint can OOM the process.
  Surfaced by the 2026-06-17 critical re-audit:
  - **HIGH** `modules/exif_geo/mod.rs:158` — `resp.bytes().await` buffers the whole
    image *before* the `MAX_BYTES` check (the `Range: bytes=0-…` header is only a
    polite request a hostile image host can ignore). `target.value` is a
    scraper-discovered URL → attacker-controlled. → stream via
    `bytes_stream()` / `read_body_capped` and abort mid-stream past `MAX_BYTES`.
    ✅ **Fixed:** now streams via `bytes_stream()` and bails the moment the running
    total exceeds `MAX_BYTES`; a valid image under the cap parses exactly as before.
  - **HIGH** `modules/smtp_vrfy/mod.rs:280` — `BufReader::read_line` has no byte
    ceiling (only a 5 s timeout); a single newline-less line from a hostile MX
    buffers unbounded into a `String`. → cap with `(&mut reader).take(N).read_line`.
    ✅ **Fixed:** `read_line_timeout` now reads via `fill_buf`/`consume` on the
    original `BufReader` (no read-ahead loss) and stops at an 8 KiB ceiling or the
    newline; legitimate < 1 KiB replies are unchanged. Regression test
    `read_line_timeout_caps_a_giant_newline_less_line` (loopback, 100 KiB no-newline).
  - **MED** `util/http/url.rs:54` (`json_decode`) — `resp.json::<T>()` reads the full
    body uncapped, unlike its sibling `json_scanned` (which routes through
    `read_json_text` / `JSON_BODY_CAP`). ~24 call-sites inherit the gap (shodan,
    censys, dehashed, zoomeye, onyphe, leakix, …) plus direct `resp.json()` in
    `doh_resolver:310,322` and `wigle/account:95`. → route `json_decode` through
    `read_json_text` (one fix closes ~20 sites); patch the three direct callers.
    ✅ **Fixed:** `json_decode` now routes through `read_json_text` (32 MiB cap +
    raw-archive retention — same as `json_scanned`, minus key scanning); the two
    `doh_resolver` and one `wigle/account` direct callers now go through
    `json_decode`. All call-sites behaviour-preserving.
  - **MED** AU-gov HTML scrapers (`asic_director:287`, `au_electoral:114/136/158/180`,
    `au_people:368/389`, `au_property:125/149/172`) — `resp.text()` uncapped. → route
    through `http::read_body_capped(resp, ~1 MB)` (the pattern `web_crawler` uses).
    ✅ **Fixed:** all nine `resp.text().await` sites in the four AU-gov scrapers now
    route through `read_body_capped(resp, 1_000_000)`; let-chain `Ok(body)` arms
    changed to `Some(body)` (semantically identical — both short-circuit on
    transport error). Behaviour-preserving on any response ≤ 1 MB (all real
    AEC/ECQ/ASIC/whitepages responses are well under 500 KB).
  - **P3** `modules/hibp/mod.rs:325,428` — `count() as u32` on an untrusted-JSON
    breach vector; clamp before the cast (folds into the T0.3 "trust no input
    number" rule).
    ✅ **Fixed:** both `verified_count.max(1) as u32` sites replaced with
    `u32::try_from(verified_count.max(1)).unwrap_or(u32::MAX)` — saturates at
    `u32::MAX` instead of wrapping; the realistic range (< 1000 breaches) is
    entirely unaffected.
  - **LOW (local)** `cli/import/mod.rs:24` — `std::fs::read_to_string(path)` is
    **uncapped** on the CLI import path (`html.rs` then clones the whole file via
    `to_lowercase`), while the *web* upload path caps at `MAX_UPLOAD_BYTES` (16 MB,
    enforced twice). `hse import <hugefile>` can OOM the device. → share the
    `MAX_UPLOAD_BYTES` bound across both paths (`audit`/`diff`/`keys_cmd` reads are
    the same lower-risk class — operator's own files). Lower severity than the
    network reads: operator-supplied input, and the OOM is a clean abort not
    memory-unsafety. The import *parsers themselves are panic-safe* (codepoint-safe
    `truncate_safe`/`char_window`, no `unwrap` on input, fuzz-style
    `upload_dispatcher_never_panics_on_adversarial_input` test) — only the read
    size is unbounded. **P2** *(robustness/DoS hardening; ties directly to the §1.5
    bounded-memory doctrine and F.1's single capped-read substrate.)*
    ✅ **Fixed:** `cmd_import` now checks `std::fs::metadata(path).len()` against a
    local `MAX_IMPORT_BYTES = 16 MiB` constant before calling `read_to_string`.
    Returns a clean `Error::Other("file too large …")` for oversized files; the
    realistic-size path is byte-identical.
- **`[x]` T2.9 · Non-deterministic SQL read-back orderings** *(fixed 2026-06-17)* — four read queries
  lack a unique final tie-break, so equal-key rows can reorder between identical
  runs (violating the §1.7 determinism feature). The deep storage re-audit
  (2026-06-17) found two that matter **beyond cosmetics**:
  - `storage/mod.rs:307` (`latest_completed_scan`, `ORDER BY started_at DESC
    LIMIT 1`) — `started_at` is **1-second** resolution (`unix_now().as_secs()`),
    so two scans completing in the same second tie and SQLite picks one in
    unspecified order. This resolves `hse export/diff/audit latest` and the SPA's
    "open latest" → **the wrong scan can be selected** on repeated calls against an
    unchanged DB. Correctness, not just ordering.
  - `storage/mod.rs:285` (`list_scans`, `ORDER BY started_at DESC LIMIT ?1`) —
    same 1-s tie; backs `GET /api/v1/scans` + `stats`, so *which* scans appear
    (when more exist than the limit) and their order is non-deterministic.
  - `storage/entities.rs:255` (`entity_facets`, `ORDER BY COUNT(*) DESC`) and
    `:185` (`scan_ids_for_entity`, `ORDER BY observed_at DESC`) — UI-summary
    cosmetics only.
  Persisted scan output (engine-finalise + entity/correlation/relation read paths)
  is already totally ordered — re-verified clean. → add a unique final key to each
  (`, id ASC` / `, e.kind ASC` / `, scan_id ASC`); pair with a permutation test.
  **P2** (the `latest` case is wrong-scan selection; the other three P3.)
  ✅ **Fixed:** all four queries now carry a unique final key — `scans` →
  `, id DESC` (`latest_completed_scan` + `list_scans`), `entity_facets` →
  `, e.kind ASC`, `scan_ids_for_entity` → `, scan_id DESC`; regression test
  `latest_completed_scan_is_deterministic_on_same_second_ties`. Non-tie behaviour
  is byte-identical, so nothing is degraded.
- **`[x]` T2.10 · No schema version stamp (latent migration risk)** —
  `storage/mod.rs` evolves the SQLite schema **additively only** (`CREATE TABLE`/
  `INDEX IF NOT EXISTS`; no `ALTER TABLE`, no `PRAGMA user_version`, no version
  table). Fine today and a deliberate design, but there is **no path for a
  non-additive migration** (adding a `NOT NULL`, changing the `correlations`
  UNIQUE key, dropping a column) and no way to detect/upgrade an old on-disk DB —
  a future structural change would silently mismatch existing databases. → set
  `PRAGMA user_version` at create and gate any future structural change on an
  idempotent upgrade ladder. **P3 (latent — no current bug; advisory).**
  ✅ **Delivered (cycle 16, 2026-06-17): SOL-SCHEMA-VERSION.** `const SCHEMA_VERSION:
  i32 = 1` added; `Store::open` reads `PRAGMA user_version` after the DDL batch:
  stamps to `SCHEMA_VERSION` when 0 (fresh or pre-versioned DB); `tracing::warn!`
  when `>SCHEMA_VERSION` (forward-compat signal — a newer binary wrote this DB).
  **Paired:** `SOLUTION_TREE` SOL-SCHEMA-VERSION `[x]` + §3/§4/§5 — same commit.
- **`[~]` T2.11 · Concurrency — process-global state not isolated across the 8
  concurrent `serve` scans** — `hse serve` runs up to `MAX_CONCURRENT_SCANS = 8`
  scans at once, but several **process-global `static`s** are shared without
  per-scan isolation. The deep engine audit (2026-06-17) found three defects here;
  the `QuotaBudget` CAS primitive, the expansion/ROI/convex math, the circuit
  breaker, cancel-RAII, and key hot-injection were all re-verified **correct** —
  these are the sharing/call-site gaps, not the primitives:
  - **MED — paid overspend.** `util/oathnet/mod.rs:175-178` gates with
    `is_quota_exhausted() || !budget_remaining()` then unconditionally
    `budget_increment()` — the exact non-atomic check-then-increment that
    `QuotaBudget::try_increment` (CAS) was written to kill. `see_know` was migrated
    (`see_know/endpoints.rs:48,142` use `budget_try_increment`); **oathnet is the
    one site left on the racy path**, so two concurrent scans both pass the gate and
    both charge → **overspends the operator's *paid* OathNet daily cap**. → swap to
    `BUDGET.try_increment()` and drop the separate increment (one line, mirrors
    see_know). **P2** ✅ **Fixed:** oathnet now reserves via `budget_try_increment()`
    (CAS); the racy `remaining()`/`increment()` pair is gone. Regression test
    `budget_try_increment_enforces_a_finite_scan_cap`.
  - **MED — cross-scan credential contamination.** `util/found_keys/mod.rs` is a
    single process-global `Mutex<Sink>`; `drain()`/`reset()` are **unkeyed**, and
    the hook `modules::drain_found_key_entities(scan_id)` (`modules/mod.rs:145`)
    **accepts a `scan_id` but ignores it**. Under concurrent scans, scan B's start
    `reset_per_scan()` wipes scan A's in-progress keys (A reports zero), or B's
    `drain()` harvests A's keys into **B's** dossier (mis-attribution). Silent,
    non-deterministic loss/mis-attribution of a headline deliverable (leaked
    third-party keys); breaks per-scan provenance. → key the sink by `scan_id`
    (`HashMap<String, Sink>`) or scope it through `ModuleContext`; `drain`/`reset`
    must filter on the id the hook already threads. The see_know/wigle/oathnet
    `QuotaBudget` per-scan statics share the same `reset_scan`-zeroing
    contamination (collective per-scan overspend; the per-*session* ceiling still
    holds). **P2** ✅ **Fixed (the SOL-ISOLATE solution).** The sink is now keyed by
    `scan_id` via a `tokio::task_local` (`SCAN`) in `util::found_keys`: the engine
    wraps `run_with_ledger` **and** each spawned dispatch task (`dispatch.rs:736`,
    since task-locals don't cross `spawn`) in `found_keys::with_scan(scan_id, …)`, so
    `scan_body` — reached deep in the `raw_archive` chokepoint with no `scan_id` of
    its own — reads the ambient and writes to that scan's bucket; `reset`/`drain` key
    on the `scan_id` the hook already threads. The layering tension was resolved
    *not* by threading scan_id through the util HTTP layer, but by adding the **pure,
    no-I/O** `with_scan` as a documented `core → util` leaf in the
    `core_does_not_import_util_directly` allowlist (the established pattern — it sits
    beside `util::oathnet::reset_budget` etc.; reset/drain still go through the module
    hook because they bridge to `core::entity`, the scope does not). Isolation
    regression test `concurrent_scans_do_not_contaminate_each_others_found_keys` +
    the existing `key_chaining_{sequential,concurrent}_dispatch` integration tests
    (both green) prove per-scan attribution with no single-scan regression. The
    budget-static `reset_scan`-zeroing remains (folds into the same task-local later).
  - **LOW — bounded over-dispatch.** `core/engine/dispatch.rs:684-762` (concurrent
    path) judges the `max_entities` budget + the cross-correlation gate against
    round-start `entity_map.len()`, but merges happen only in the post-spawn
    consumer loop, so the count never advances mid-round → over-dispatches by up to
    one target's module set (the *sequential* path re-checks fresh, so the modes
    diverge). → re-check the live count in the consumer loop, or interleave
    `join_next` with spawning. **P3** ✅ **Fixed (the SOL-LIVE-DISPATCH-BUDGET
    solution).** `dispatch_target_concurrent`'s Phase-2 spawn loop now drains any
    already-finished sibling tasks via `JoinSet::try_join_next` (non-blocking) at
    the top of every iteration, finalising them through a new shared
    `absorb_dispatch_outcome` helper (also used by the trailing blocking
    `join_next` drain, so a result is finalised exactly once regardless of which
    loop collects it) — so `entity_map.len()` in the `max_entities` check is live
    mid-round, not the snapshot from before this target's spawn loop started.
    Regression test `concurrent_dispatch_stops_near_max_entities_not_after_the_full_module_set`
    (10 accepting modules, `max_entities: Some(1)`, `max_concurrent: 1` to force
    the interleave deterministically) fails against the unfixed code — all 10
    modules dispatch — and passes against the fix.
  **Root cause:** per-scan/per-session budgets and the key sink live in `static`s
  sized for a single in-process scan; `serve`'s concurrency (8) makes them shared
  mutable state. The clean fix is per-`scan_id` keying (or threading the state
  through `ModuleContext`), which also subsumes the budget-reset race. **P2**
- **`[x]` T2.12 · Periphery correctness bugs (CLI / diff / cache / pool)** — the
  2026-06-17 internals audit of the least-covered subsystems found a cluster of
  real but contained defects (the cores — key_pool rotation, crypto, proxy SSRF,
  budget, roi, timeline — verified clean, see §6):
  - **MED** `cli/keys_cmd/mod.rs:143-144` — `hse keys add <svc> KEY` for a
    *non-poolable* service prints "Adding anyway — key will be stored", but
    `pool.add` returns `false` (same non-poolable gate), so it falls to the `else`
    and prints the **false** "Key already exists in '{service}' pool" — the key is
    **silently dropped** and the command exits 0, contradicting its own output. →
    gate early (`find_service(..).is_none()` → `Err`), or return
    `{Added,Duplicate,NotPoolable}` and message/exit accordingly. **P2** ✅ **Fixed:**
    the CLI now checks `is_poolable_service` up front and returns a clear `Err`
    (non-zero exit, pointing at `set-key` for one-off keys) for a non-poolable
    service — no more silent drop + false "already exists".
  - **MED** `cli/provision/mod.rs:283-285,328` — `provision --verify` prints a `!`
    on a failed smoke scan / missing-key sub-test but returns `Ok(())` → **exit 0
    on failure**, so a CI/install gate treats a broken build as healthy. → track a
    `verify_ok` flag and `return Err` (or document it as informational and drop the
    pass/fail `✓`/`!` markers). **P2** ✅ **Fixed:** a `verify_ok` flag now tracks the
    smoke-scan completion + the missing-key assertion, and `provision --verify`
    returns `Err` (non-zero exit) on failure — a CI/install gate can rely on it.
  - **MED** `core/diff/mod.rs:94-121` — `diff_entities` iterates the raw input
    slices, not the deduped uid maps, so a side with two same-uid entities
    over-counts `common`/`added`/`removed`/`confidence_shifts`. DB-to-DB diffs are
    safe (uid is PK-unique), but the CLI JSON-snapshot path (`cli/diff/mod.rs:33`,
    `serde_json::from_str` with no dedup) makes a hand-edited/concatenated
    `before.json` trigger it → corrupted diff output. → iterate the deduped
    `HashMap` values (or dedup inputs by uid up front). **P2** ✅ **Fixed:**
    `diff_entities` now iterates the deduped uid maps; unique-uid input is
    byte-identical, dup-uid input counts once. Test `duplicate_uid_input_is_not_over_counted`.
  - **LOW-MED** `util/response_cache/mod.rs:70` — the `c.len() < cap` guard runs
    *before* `insert`, and re-inserting an existing key doesn't grow `len`, so once
    the cache is full an in-place **value refresh is rejected** → stale paid-API
    payload served for the rest of the process. → `if c.len() < cap ||
    c.contains_key(&key) { insert }`. **P3** ✅ **Fixed** (exactly so; test
    `full_cache_still_refreshes_an_existing_key`).
  - **LOW** misc: `key_pool/validation.rs:33-41` (a successful re-validation of an
    already-pooled `Untested` key doesn't promote the stored entry to `Active` —
    wastes a probe); `util/proxy/mod.rs:89` (`is_public_proxy` mis-parses
    *bracketless* IPv6 `host:port` — **SSRF stays closed**, just the wrong endpoint
    is used/dropped); `cli/provision/mod.rs:158` (`write_env_file` renames without
    `sync_all()` — crash could leave a zero-length `.env`; route through
    `util::atomic_file::write`); `cli/keys_cmd/mod.rs:473` (`import-tsv --validate`
    scoping is broken → re-validates *every* tsv-imported key, spending budget);
    `core/timeline/mod.rs:185` (pure-digit epochs not exactly 4/10/13 digits are
    silently dropped — a real date omitted, no crash); CLI exit-code contracts
    (`audit` always `Ok`) + `resolve_scan_id` accepting an incomplete scan. ✅
    **`diff` same-scan fixed (2026-06-17, cycle 3):** `cmd_diff` now returns
    `Err("both sides resolve to the same scan")` (non-zero exit) after the
    footgun `eprintln!` — previously fell through to `Ok(())`. Integration test
    `diff_wiring_self_compare_is_rejected_with_diagnostic` guards the new
    behaviour. **`audit` exit-code fixed (2026-06-17, cycle 5):** `cmd_audit`
    now returns `Err` after printing the report when any finding carries
    `Severity::Critical` or `Severity::High`, so `hse audit` exits non-zero
    on a problematic result. Test `empty_scan_triggers_high_severity_exit_path`
    guards it. **`resolve_scan_id` status-check fixed (2026-06-17, cycle 6):**
    explicit scan IDs for `Pending`/`Running`/`Failed`/`Aborted` scans now return
    `Err` with a diagnostic naming the status — only `Complete` scans are accepted
    (export/diff/audit on a non-complete scan was silent, misleading, or empty).
    Test `resolve_scan_id_rejects_incomplete_scans` guards it. T2.12 fully closed ✅.
    **P3.** *(All contained; none crash or corrupt persisted scan data.)*
- **`[x]` T2.13 · Dead "ROI" hint — dossier's "keyed/paid module(s) yielded
  nothing" line could never fire** *(found + fixed 2026-07-01)* —
  `cli/scan/dossier.rs::print_diagnostics` computed its wasted-spend hint by
  filtering `ScanDiagnostics::modules_by_yield` for `entities_emitted == 0`,
  but `util::diagnostics::analyse` builds that list **exclusively** from
  emitted entities' evidence sources (`by_source.entry(source)…` inside the
  per-entity loop) — a module that ran and found nothing is never inserted at
  all, so it never appears in the list *at zero*, it's simply **absent**. The
  filter's premise was structurally unsatisfiable: no scan, ever, could have
  populated it. Confirmed live: a real `hse scan --output dossier` against a
  low-signal domain ran 42 modules and printed the "Modules ranked by yield"
  table with exactly **one** row (the seed) — the other 41, including 11
  `KeyGated`/`Paid` modules that spent a budgeted call for nothing, were
  invisible to the hint, silently.
  → **Solution:** a new pure `zero_yield_keyed_or_paid_modules(events,
  cost_by_module)` reads the scan's own durable `ModuleDone { module, found }`
  events (`store.events_for_scan`, already tracked and persisted per module
  regardless of yield) instead of the yield-only-derived list. **P2**
  ✅ **Fixed:** same live domain scan re-run after the fix now prints `ROI: 11
  keyed/paid module(s) yielded nothing — consider --exclude
  dehashed,exa_search,hunter_io,intelx,leakix,netlas,onyphe,securitytrails,
  threatfox,whoisxml,zoomeye` — the exact 11 `KeyGated`/`Paid` modules from the
  same run that timed out or found nothing. 4 new unit tests on the pure
  helper (flags a zero-yield paid module; ignores one that found something;
  ignores a zero-yield *free* module — no spend to warn about; output is
  sorted/deduped). `print_dossier`'s now-8-argument signature was bundled into
  a `DossierArgs` struct (`clippy::too_many_arguments`) rather than
  `#[allow]`ed, mirroring the T2.5 `DispatchCx`/`DispatchState` precedent.
  **Addendum (2026-07-01, same root cause found twice more):**
  `util::diagnostics::analyse` itself carried two more `optimization_hints`
  conditions keyed on the identical unreachable `entities_emitted == 0`
  premise — a per-module `"module '{name}' returned 0 entities — consider
  excluding for this target kind"` and a scan-level `"scan exceeded 60s with
  at least one zero-yield module — tighten module_timeout_ms"`. Both were
  provably as dead as the ROI hint (same `modules_by_yield` construction), so
  both were **removed** rather than left as misleading code that claims a
  capability it cannot have — but neither was mechanically re-wired the way
  the ROI hint was. The 60s-hint COULD be, the same way (a single bounded,
  genuinely useful condition), but wasn't this cycle: pure `analyse()` can't
  reach the `StoragePort`-sourced events it would need (`util` may not depend
  on `core::port`), so a correct fix means either widening `analyse()`'s
  signature (16 existing call/test sites) or duplicating the event-fetch at
  every caller that surfaces hints — both bigger than this addendum, and
  deferred honestly rather than hacked. The per-module hint is a **further**
  design question, not just a wiring gap: fired correctly with real event
  data, a realistic multi-module scan (see the 42-module live run above)
  would flood the hints list with ~30 "returned 0 entities" lines for
  ordinary, expected zero-yield free modules — the exact noise-over-signal
  failure this codebase's precision doctrine exists to prevent (cf. the ROI
  hint's own deliberate `KeyGated`/`Paid`-only filter). Rewriting it
  correctly needs a real decision (cap it, cost-gate it like ROI, or drop the
  per-module form for a summary count), not a blind unwire. Renamed the one
  test whose name overclaimed what it verified:
  `analyse_emits_optimization_hints_for_zero_yield` (never actually exercised
  zero-yield handling — `analyse` could never see it) →
  `analyse_falls_back_to_a_hint_when_nothing_else_fires`.
- **`[ ]` T2.14 · Restore the two dead `analyse()` hints T2.13 removed, with a
  real design for the noise question** — `util::diagnostics::analyse` no
  longer emits a "scan exceeded 60s with a zero-yield module" hint or a
  per-module "returned 0 entities" hint (T2.13 addendum); both were
  unreachable dead code, honestly removed rather than left misleading, but
  neither was replaced. → **Solution:** either (a) widen `analyse`'s pure
  signature to accept the caller's already-fetched event data (touches 16
  existing call/test sites — a real but mechanical ripple), or (b) compute
  both at the caller layer (which already has `StoragePort` access) and
  append to `ScanDiagnostics.optimization_hints` post-call, mirroring T2.13's
  `zero_yield_keyed_or_paid_modules` pattern exactly. Either way, the
  scan-level 60s hint is a straightforward reinstatement; the per-module hint
  needs an explicit noise decision first — a 42-module scan can leave 30+
  modules at zero yield for a given target kind, which is normal, not
  noteworthy, so firing one line per module would flood the hints list.
  Candidates: cap to the worst N, cost-gate it like the ROI hint
  (`KeyGated`/`Paid` only), or replace the per-module enumeration with a
  bounded count ("N of M dispatched modules found nothing for this target
  kind"). **P3** *(advisory-only; nothing correctness-critical depends on
  either hint).*
- **`[x]` T2.15 · Silent multi-row deserialize/read failures (storage layer)**
  — every multi-row reader in `storage/` (`list_scans`, `correlations_for_scan`,
  `relations_for_scan`, `events_for_scan`, `entities_for_scan`,
  `entities_filtered`, `search_entities`'s FTS and LIKE paths — 8 sites total)
  chained a bare `.filter_map(|s| serde_json::from_str(&s).ok())` (and, one
  layer up, `.filter_map(Result::ok)` over the `query_map` iterator) to drop a
  corrupted or schema-drifted row with **zero trace** — the single-row getters
  (`get_scan`, `get_entity`) already propagate the identical failure via `?`,
  so multi-row and single-row reads silently disagreed on how loud a corrupt
  row should be, and an operator staring at a suspiciously short result page
  had no signal a row was ever dropped. Found by a code-grounded discovery
  pass across the storage layer. → **Solution:** two shared private helpers,
  `collect_rows` (SQL-extraction layer) and `deserialize_rows` (JSON layer),
  each emitting a `tracing::warn!` keyed by the caller's name before dropping
  the row; wired into all 8 call sites across `storage/mod.rs` and
  `storage/entities.rs`. The "one bad row must not fail the whole page"
  behaviour is unchanged — only the missing diagnostic is added. **P2**
- **`[x]` T2.16 · Silent chmod failure on the store's PII-bearing files** —
  `Store::open`'s owner-only (0600) restriction loop over the db file plus its
  `-wal`/`-shm` siblings did `let _ = std::fs::set_permissions(&p,
  owner_only.clone());`, discarding the `Result` with no `tracing::warn!` —
  unlike the FTS-rebuild best-effort step ~30 lines earlier in the same
  function, which is explicitly best-effort **and** never silent. Since the
  store "holds PII + harvested third-party keys" per the code's own comment,
  a failed chmod silently left the file at the process umask (often 0644,
  world-readable) with zero operator signal. Found by the same storage-layer
  discovery pass as T2.15. → **Solution:** extracted the loop into a private
  `restrict_to_owner_only(paths)` helper that logs a `tracing::warn!` keyed
  by the failing path before continuing — startup is still never blocked by a
  chmod failure, only made loud. **P2**

---

## 4. Capability program — surpass SpiderFoot & Maltego (CAP)

Grounded in the existing modules and the BUILD set of `OSINT_MATRIX_GAP_ANALYSIS`.
Each node: **current → target → solution**. Everything here is built on §3.F
primitives. AU bias and an offensive (active-collection) posture throughout.

- **`[~]` C1 · Correlation & identity depth — *the Maltego-without-graphs play***.
  *Current:* 61 native rules + deterministic GREATEST-merge identity. *Target:*
  out-link-analyse Maltego by delivering the *conclusion*, not a canvas.
  → **Solution:** (a) **transitive identity resolution** — if A↔B and B↔C share
  selectors, emit A↔C with decayed confidence (closure over the merge graph,
  property-tested for convergence & determinism); (b) a **"Connections" section**
  in the dossier that renders the strongest entity links as text (shared
  selectors, the path between two identities, the controller behind reused
  secrets) — graph-free link analysis, reproducible and scriptable; (c) deepen
  the **timeline** (already present) into a first-class output; (d) add the rule
  gaps the AU-0xx register implies. GEXF stays as the *optional* escape hatch for
  users who want a graph (covers Maltego's graph crowd without heavy in-app
  graphing). **CAP-high**
  *Delivered (cycle 26, 2026-06-20):* (a) **and** (b) landed on one shared,
  property-tested primitive. `core::relation::identity_paths` is the canonical
  deterministic shortest-typed-path finder over the relation graph (BFS, parallel
  edges collapse to a stable label, every pair computed once from its smaller-UID
  endpoint → byte-identical output under input permutation, proptested). AU-060
  (transitive identity closure) was **refactored to delegate** to it (Rule 4:
  one finder, so the rule and the rendered chain can never drift), and a new
  **CONNECTIONS** dossier section renders the shortest typed thread tying each
  identity back through the graph — the graph-free link-analysis conclusion, with
  each chain's weakest-edge confidence. *Remaining:* (c) first-class timeline
  output (footprint timeline shipped; widen), (d) further AU-0xx rule-gap fill,
  and the "controller behind reused secrets" link facet.
- **`[ ]` C2 · Performance & scale — *the SpiderFoot play***. *Current:* parallel
  Rust dispatch, no published numbers. *Target:* demonstrably faster than a
  Python engine, on a phone. → **Solution:** with F.3 benches + T1.2 throughput +
  F.2 flat-RAM datasets, publish a reproducible "N selectors, on-device, in T
  seconds, M MB RAM" benchmark; enforce streaming/bounded memory everywhere
  (cap+chunk, never slurp). SpiderFoot (CPython) structurally cannot match
  on-device aarch64 throughput. **CAP-high**
- **`[~]` C3 · Australian moat (BUILD, AU-biased)** — *Current:* `asic_director`,
  `abn_lookup`, `acnc`, `au_electoral`, `au_property`, `qld_unclaimed`,
  `au_people`, `gleif_lei`, AU phone/carrier/postcode geo. → **Solution
  (roadmap):** G5 harden `smtp_vrfy` (MX/SPF/catch-all → lift free email-verify
  confidence); G9 BYO-key **HLR/CNAM** phone module; **GNAF/AusPost** address
  validation → sharper geo; **AHPRA** health-practitioner register; **ACMA**
  radiocomms/spectrum licences (AU NETINT); fuller **ASIC/ABR** company graph;
  complete state **cadastre/property**; deeper **courts/AustLII**. All free or
  BYO-key, all AU-first. **CAP-high (AU bias)**
  *Delivered (2026-06-18, cycle 17):* G5 `smtp_vrfy` hardened — parallel
  `tokio::join!(resolve_mx, resolve_spf, resolve_dmarc)`, CatchAll confidence
  0.50→0.30; G9 `hlr_cnam` (HLR phone status + CNAM subscriber name, BYO
  `HUNTSMAN_HLR_KEY` + `HUNTSMAN_OPENCNAM_KEY`, priority 138, Phone); `ahpra`
  (AHPRA health-practitioner register HTML scrape, free, priority 86, People);
  `acma_rrl` (ACMA radiocommunications register, free, priority 48, Corporate,
  ATT&CK override T1591.001/T1591.002); `trove_au` (NLA Trove newspaper archive,
  BYO `HUNTSMAN_TROVE_KEY`, priority 57, Corporate). Also: `reddit_user` →
  Organisation entities for subreddits; `hacker_news` → Domain entities from
  Algolia submissions; `github_user` → `fetch_orgs` + `fetch_gists`. Module count
  119→124 (92 free · 27 key-gated · 5 paid).
  *Delivered (cycle 20, 2026-06-18): `austlii` — free AustLII court/legislation
  scraper; `FullName`/`Organisation` → `Url` + `Organisation`; Corporate-9; 125→126
  modules, 92→93 free.*
  *Remaining:* GNAF/AusPost address validation; fuller ASIC/ABR graph; state
  cadastre/property.
- **`[~]` C4 · NETINT depth** — *Current:* `dns_intel`, `cert_intel`, `crtsh`,
  `shodan` (free InternetDB), `censys`, `zoomeye`, `subdomain_takeover`,
  `waf_detect`, `portscan`, `bgpview`, `ripestat`. CDN/Cloudflare noise is already
  suppressed at 5 layers (range-based `is_cdn_edge_ip` v4+**v6**, the shared
  IP-geo trust gate, the expansion gate, storage-ranking demotion, infra-domain +
  challenge-page detection). → **Solution:** union subdomain discovery (brute ∪ CT
  ∪ passive); ASN/BGP → org/prefix pivots feeding correlation; passive-DNS/WHOIS
  history via `securitytrails` BYO-key (G7); faceted asset depth via
  `shodan`/`censys` keys (G6); broaden takeover fingerprints. **Cloudflare
  origin-unmasking** (turn the CDN from noise into a solved puzzle — surpasses
  Spiderfoot/Maltego): MX/SPF/TXT records (mail isn't proxied → origin leak),
  pre-onboarding passive-DNS history, SSL-cert-hash pivot on Censys/Shodan, and
  direct-connect subdomains (`cpanel.`/`ftp.`/`mail.`/`dev.` often non-proxied) →
  emit a tagged `origin-candidate` IP for the fronted domain. **CAP-med**
  *Delivered (2026-06-18, cycle 17):* `netlas` (Netlas.io host intel — ports,
  JARM, SSL cert emails, CVEs, ISP, geo, BYO `HUNTSMAN_NETLAS_KEY`, priority 79,
  Infrastructure); `censys` priority 35→78.
  *Delivered (confirmed cycle 20 S→P audit):* `securitytrails`
  (`HUNTSMAN_SECTRAILS_KEY`, Domain+IpAddress→Domain, subdomain enum + reverse-IP
  hostnames); ASN/BGP org/prefix pivots (`bgpview` + `ripestat` both present).
  *Remaining:* passive-DNS leg of subdomain union (brute ∪ CT already ship);
  Cloudflare/CDN cert-hash origin-unmasking.
- **`[~]` C5 · GEOINT convergence — *already ahead; widen the lead*** — *Current:*
  multi-source fusion (WiGLE + EXIF + cell + IP + address→coords) with AU-state
  attribution and convergence rules (AU-052/056/057/059). Neither competitor
  does this. → **Solution:** feed more sources into the confidence-weighted
  centroid; tighten the AU bounding-box/state precision; add movement/timeline
  geo; output a single best-estimate **with provenance + a confidence radius**.
  **CAP-med (differentiator)**
  *Delivered (cycle 19, 2026-06-18): `opencellid` — first-class key-gated module
  (`HUNTSMAN_OPENCELLID_KEY`); accepts `Coordinates`; queries OpenCelliD
  `getInArea` BBOX endpoint; emits `DeviceId` + `Coordinates` for every tower
  within ~1 km; `cache_ttl_secs=86400`; ATT&CK T1591.001+T1596. Previously
  OpenCelliD was only an internal helper inside `cell_intel` (not queryable as a
  standalone first-class module). 124→125 modules, Geo 19→20, 27→28 key-gated.
  Delivered (cycle 21, 2026-06-18): `cell_local` + `hse cells import` — free,
  offline peer to `opencellid`; imports a BYO OpenCelliD CSV/CSV.GZ dataset into
  `~/.huntsman/cell_towers.db` (WAL SQLite, 50k-row batched inserts); `cell_local`
  module accepts `Coordinates`, queries the local DB in `spawn_blocking`, emits
  `DeviceId` + `Coordinates` per tower; priority 66; silent no-op when DB absent
  so it never blocks scans on an unpopulated device. `hse cells` CLI: `status`,
  `import --file/--country/--key`, `clear`. 126→127 modules, 93→94 free, Geo 20→21.
  New S→P gap:* full AU dataset download requires OpenCelliD BYO key + manual
  trigger (no auto-scheduled re-sync yet).
  *Audit correction (2026-07-01):* **"provenance radius output" was already
  delivered** — cycle 29 (2026-06-20, `ac9114e4`) added `SynergyFix::radius_km`
  to the AU-059 synergy fix, and `d1507539` (2026-06-26) added
  `best_au_location_estimate`, a 6-rung precedence fallback so every AU-located
  scan (not just the multi-source synergy case) gets one headline "Best
  location estimate: `LAT,LON ± X km`" with its basis + confidence, in both the
  CLI dossier and the JSON export. Neither delivery was folded back into this
  line when it shipped — this bullet was simply never re-read against the code.
  *Delivered (2026-07-01):* **AU-059's dossier-headline fix now uses the
  confidence-weighted geometric median (Weiszfeld), not the plain
  `weighted_centroid`** — bringing it to parity with AU-057 and
  `diagnostics::cluster_coordinates`, which already used the more
  outlier-robust estimator. `au059_synergy_fix` now calls
  `weighted_geometric_median` (falling back to `weighted_centroid` only on the
  rare non-convergent/degenerate input, the same fallback the other two call
  sites use). Regression test
  `au059_synergy_fix_resists_a_single_high_confidence_outlier` proves it: two
  agreeing near-Sydney classes (64% of the weight) plus one higher-confidence
  Perth outlier (36%) — below the median's 50% breakdown point — must keep the
  fix anchored near Sydney; the plain centroid the old code computed lands at
  lon≈138.6 (a third of the way to Perth), the geometric median stays >145.
  Fails against the pre-fix code (produces the same lon≈138.6 as the plain
  centroid) and passes against the fix. Existing AU-059/AU-052/scan_export geo
  tests are unaffected (they all use tolerant range assertions on real,
  closely-clustered fixtures where the two estimators don't meaningfully
  diverge).
  *Remaining:* tighter AU bounding; movement/timeline geo.
- **`[ ]` C6 · Offensive edge** — *Current:* SERP exposure dorks, `portscan`,
  `subdomain_takeover`, `key_harvest`, breach/stealer presence + AU-047 reuse
  link. → **Solution:** broaden exposure-dork coverage; mature the
  **credential-reuse graph** (link accounts by shared salted hash / session token
  across sources); sharpen key-harvest precision via the F.1 `aho-corasick`
  scanner + entropy gate; richer stealer-log cross-referencing
  (`oathnet_pro`/`see_know` presence → pivot). Active, authorised collection.
  **CAP-med**
- **`[ ]` C7 · Output & forensics superiority** — *Current:* deterministic
  exports, evidence chains, auto-dossier, GEXF. → **Solution:** lock byte-stable
  determinism (T1.1 + proptest), make per-entity evidence chains and the dossier
  the auditable intelligence product, keep GEXF as the optional graph. This is a
  capability **neither** SpiderFoot nor Maltego offers (reproducible,
  machine-diffable intelligence). **CAP-med**
- **`[x]` C8 · Webcam, fan-subscription & adult-video platform identity (DELIVERED)**
  — *Problem:* `username_search` covers mainstream social/dev/gaming/music platforms
  only; webcam performers, fan-content creators, and adult-video contributors are an
  increasingly significant OSINT surface that the engine left entirely blind. A
  subject's streaming identity may be the only corroborating hit not already indexed
  by general-purpose social probers. Subjects who maintain activity in non-English
  markets (Russia, France, Germany, Eastern Europe, Japan, Spanish LATAM) routinely
  use region-specific platforms invisible to English-centric tooling.
  *Target:* enumerate username presence across the full specialist cam/fans/adult
  platform set — including international platforms used to hide behaviour from
  domestic or English-language observers — so a streaming identity is surfaced
  regardless of which region's platforms the subject chose. → **Solution:**
  `streaming_probe` — 42-site parallel HEAD/GET prober across three category buckets
  (`cam` 16, `fans` 18, `adult` 8); `StatusEq` HEAD for platforms with clean 404s;
  `StatusAndNotBody` GET for JS-rendered 200-for-all platforms (OnlyFans, Chaturbate);
  summary `Username` entity with `cam-identity-exposed`, `subscription-platform-found`,
  `adult-profile-found`, and `high-streaming-exposure` (≥3 platforms) tags;
  `ModuleCategory::Social` (MITRE T1593.001 + T1589.003); priority 108; 8 unit tests.
  **International coverage:** Runetki/Boosty (Russia/CIS), Cherry.tv/4Based (Eastern
  Europe), Mym (France/Francophone), MyDirtyHobby (Germany), JustForFans (LGBTQ+ intl),
  OhMyFans (Spanish LATAM), Cam.tv (Italy/Europe), Unlockd (UK), SuicideGirls (global
  alt), Iwara (Japan/3D). **CAP-high (identity breadth)** ✅
- **`[x]` C9 · Inter-scan entity cache / API cost governance** — *Problem:* every
  scan re-queries every applicable module unconditionally. For key-gated and paid
  modules (`netlas`, `censys`, `hlr_cnam`, `trove_au`, `shodan`, etc.) this
  consumes finite query allowances or real money on repeated scans of the same
  target. A subject scanned twice within 24 h pays Censys / Netlas twice for
  identical host data; a phone number queried twice in a week consumes two HLR
  credits for the same MSISDN. At scale (automated enrichment pipelines, recurring
  investigations) the cost is real and the waste is structural. → **Solution
  (sketch):** extend `StoragePort` with
  `lookup_entity_fresh(kind, value, max_age_secs) → Option<ModuleResult>` backed
  by the existing `raw_archive` table; modules self-register a per-class TTL (IP
  intel 24 h, WHOIS 72 h, breach data 7 d, phone HLR 24 h); the dispatch layer
  short-circuits with the cached result before calling the module. Per-scan
  isolation (SOL-ISOLATE) is preserved — the cache is a read-only pre-dispatch
  gate, not a write-path bypass. Policy: caching is opt-in per module; modules
  that produce time-sensitive data (live port scans, real-time CNAM) can set
  `max_age_secs = 0` to always go live. **CAP-high (cost + AU revenue model)**
  ✅ **Delivered (cycle 18, 2026-06-18): SOL-CACHE-INTERSCAN.** `raw_archive` SQLite
  table (`id TEXT PRIMARY KEY, archived_at INTEGER NOT NULL, ttl_secs INTEGER NOT
  NULL, result_json TEXT NOT NULL`); `StoragePort::{archive_module_result,
  lookup_module_result_fresh}` default-no-op trait methods; `Store` SQL
  implementation in `src/storage/archive.rs` (4 unit tests: round-trip, miss,
  overwrite, TTL=0 immediate-expire); `Module::cache_ttl_secs() → u64` trait method
  (default 0 = always live); `hlr_cnam` + `netlas` override to 86400 (24 h);
  `archive_key("module:target_kind:normalised_value")` helper; dispatch-layer
  pre-gate wired in both sequential (before `run_module_guarded`) and Phase 2
  concurrent (before `acquire_owned`) paths — cache hit increments `ModuleStats::
  cached`, replays archived entities, skips the live API call; post-call cache-store
  when `ttl > 0 && result non-empty`; `Scan::modules_cached` counter persisted.
  Schema snapshot test updated. **Paired:** `SOLUTION_TREE` SOL-CACHE-INTERSCAN
  `[ ]`→`[x]` + §3/§4/§5 — same commit.

---

## 5. Execution order (the queue)

1. **T0.1, T0.2** — kill the panics (small, self-contained). *(unblocks T2.7)*
2. **F.1, F.3** — land `aho-corasick`/`memchr`/`bstr` + `proptest`/`cargo-fuzz`/
   `criterion`. *(the substrate; makes 1 permanent and 3+ cheap)*
3. **T1.1, T1.2, T1.3, T1.4** — restore determinism, throughput, verification,
   layering.
4. **F.2** — `fst` datasets *(folds in T2.6 de-duplication)*.
5. **T2.1–T2.12** — robustness/quality (T2.8 unbounded reads, T2.9 SQL tie-breaks,
   T2.10 schema versioning, T2.11 concurrent-`serve` global-state isolation, T2.12
   periphery CLI/diff/cache bugs — added across the 2026-06-17 re-audits; T2.8 rides
   on F.1's capped-read substrate. T2.9 + the two T2.8 HIGH reads now fixed).
6. **C1 → C7** — capability program, AU-first, each gated on its §3.F primitive.

## 6. Verified sound (checked — do not re-investigate)

Injection (argv-only); HTTP SSRF (SsrfResolver + redirect policy + curl IP-pin);
TLS (rustls/webpki, no invalid-cert acceptance); all 20 `Regex::new` cached;
the other panic leads guarded (`abn:209`, html decode, geometry, `address_au`);
every fan-out semaphore-capped; confidence `clamp` + saturating corroboration;
deterministic merge; **0 `unsafe`**, 0 arch-specific code, Termux sensors no-op
cleanly off-device; all 118 modules registered with tests + `produces()` +
non-empty `attack_techniques()` (per-category default or override — the two
`Other`-category modules `api_key_probe`/`chain_intel` override their empty
default; a guard rejects any unmapped module).
**Re-confirmed by an independent multi-agent re-audit (2026-06-17):** the T0
`to_lowercase`/byte-offset panic class is fully closed (every untrusted-byte slice
routes through `find_ascii_ci`/`char_window`/`truncate_safe`/`floor_char_boundary`
or an ASCII-only byte scan), all non-test `unwrap`/`expect` are constant- or
guard-protected, the `#[allow]`s are all justified, error handling honours
"no silent failures", and every *persisted* output path is totally ordered.
A follow-up **deep storage/API audit (2026-06-17)** further confirmed: every SQL
query is parameterised (no value string-interpolated; FTS5 `MATCH` injection is
neutralised by quote-stripping + per-token quoting in `fts_prefix_query`), all
multi-statement writes are transaction-wrapped with the FTS index kept in-sync
in-txn, the SSE broadcast is bounded (1024-cap; lagging receivers drop frames —
never block or panic), request input can't panic a handler (no `unwrap` on
path/query/body; body-size bounded), loopback peer-checks gate every key/toggle
write, and CSV export defangs formula-injection. The import parsers are panic-safe
(codepoint-safe truncation, fuzz-tested). The residual gaps it surfaced are all
logged above: T2.8 unbounded reads (network + the CLI-import read size), T2.9
read-back tie-breaks (the `latest` one is wrong-scan selection), T1.2's two missed
reactor-blocking handlers (`scan_import`/`stats`), and T2.10 schema versioning
(latent).
A third pass (2026-06-17) deep-audited the **engine internals** and the **59
correlator rules**: the rule logic + the geo-math primitives (haversine,
monotone-chain hull, shoelace centroid, weighted Weiszfeld median, Welzl MEC) are
**correct**; expansion depth/rounds (no off-by-one / `MAX_DEPTH` overflow), the
ROI/convex math (total, no div-by-zero, NaN sorts last deterministically), the
circuit breaker, semaphore/cancel-RAII (no permit leak), and Phase-1→2 key
hot-injection (post-Phase-1 snapshot, no TOCTOU) all check out. The only defects it
found are **concurrency-isolation gaps** (T2.11: the oathnet paid-overspend race +
the found_keys cross-scan contamination) and one security finding (the SPA XSS,
§7) — not the algorithms.
A fifth pass (2026-06-17) audited the least-covered periphery and re-confirmed the
**cores are sound**: the `key_pool` rotation/round-robin + atomic 0600 persistence
(unique-temp + `sync_all` + `rename`), `core::crypto` (a total, panic-free
crypto-address shape classifier — hex blobs never misclassified as wallets),
`proxy`/`netrotate` (empty-pool guarded, round-robin correct, **SSRF stays closed**
— every proxy passes `is_private_addr`), the `QuotaBudget` CAS, and the
`data_broker`/`dependency`/`relation`/`roi`/`timeline` pure logic all check out. The
defects it found (T2.12) are all in the **periphery** — CLI command UX/exit codes,
the JSON-snapshot `diff` path, and the response cache — none crash or corrupt
persisted scan data. It also independently re-verified the T2.9 `latest` fix
(`ORDER BY started_at DESC, id DESC` is a true timestamp+PK sort, not lexical).

## 7. Deferred (out of scope here — separate pass)

Indexed only: **Security** — ✅ **FIXED (2026-06-17, was HIGH): one-click stored XSS
in the SPA**, `web/spa.html:1967` — a correlation-member `onclick` interpolated the
attacker-controllable `e.value` into a **JS-string literal inside an inline
handler**. `esc()`/`attr()` HTML-encode `'`→`&#39;`, but the HTML parser decodes it
back to `'` *before* the JS engine runs the `onclick`, so `e.value = ');alert(1)//`
breaks out and executes **same-origin** when the analyst clicks the member to pivot
(verified end-to-end). `script-src 'unsafe-inline'` permits the inline handler;
`connect-src 'self'` blocks *exfiltration* but not same-origin execution (reading
sensitive findings, driving the loopback API). The same pattern at `:1910` is
currently inert (its value is a SHA-256-hex `uid`). ✅ **Fixed:** both sinks now
render the value into a `data-pivot`/`data-uid` attribute (HTML-attr context, where
`esc()`/`attr()` *is* sufficient) read via `this.dataset` in the handler — no
attacker data enters the JS-string context. A full-SPA sweep confirms **zero**
remaining `on*`-handler interpolations; the pivot click behaviour is unchanged
(the `data-` value decodes to the same string), so nothing is degraded.
*(The rest of the SPA's `esc()`/`extLink()` discipline was verified sound — this
was the one dual-context
sink.)*

The **2026-06-17 security hardening pass** worked the rest of the §7 Security list
into concrete, verified findings (the SPA XSS above is fixed; these remain open —
security stays a deliberately separate track, and S1 needs *operator* action):

- **S1 · `[-]` ACCEPTED BY DESIGN (operator directive, 2026-06-17) — keys remain
  hardcoded while functional.** `util/keys/constants.rs:137-168` embeds five live
  keys (OathNet, HIBP, WiGLE user+token, enterprise SeekNow) so a fresh install
  works **zero-config, no signup** — a deliberate product feature. The operator has
  directed that **all functional keys stay embedded**; the exposure (public repo +
  `strings`-extractable binary ⇒ a shared quota) is an accepted trade-off on the
  owner's *own* credentials. **Not a defect — no de-embedding.** Recorded honestly
  for posterity, and the *"if functional"* clause is already mechanised: a key
  verified dead (HTTP 401) is swapped in place and demoted to a
  `SEEKNOW_SUPERSEDED_KEY*` slot (single source of truth in `constants.rs`), so the
  embedded set self-heals to whatever is currently live. Any free-tier-vs-paid split
  is likewise the operator's prerogative, not a tracked action.
- **S2 · `[x]` P1 (HIGH) — whois-referral SSRF (raw TCP/43 bypasses SsrfResolver).**
  `modules/whois/{mod.rs:97-104, client.rs:38-53}` follows the referral server taken
  **verbatim** from the (attacker-influenceable) WHOIS response —
  `TcpStream::connect(format!("{server}:43"))` or an embedded `host:port` — with
  **no validation**; the `SsrfResolver` only guards the reqwest client, not raw TCP.
  A registry/registrar in the chain (or a MITM on cleartext port 43) returns
  `refer: 127.0.0.1:6379` / `169.254.169.254:80` / `internal:8080`, turning HSE into
  an internal port-prober that also writes the query line to the target (the
  embedded `:port` widens it past 43; NAT64/link-local worsen it on Termux). → parse
  `host:port`, reject ports ≠ 43, resolve and drop any `util::preflight::is_private
  _addr` address (reuse `filter_public`), pin the connection to the vetted address,
  reject `is_local_domain` hosts. ✅ **Fixed (the SOL-SSRF-WHOIS solution):**
  `client::resolve_public_whois` now parses `host:port` (incl. `[v6]:port`), refuses
  any non-43 port, refuses `is_local_domain` hosts, and resolves to the first
  **public** address (`!is_private_addr`), returning a concrete `SocketAddr` that
  **pins** the dial (no resolve-then-connect rebind). `client::query` is generic so
  the referral path connects to that pinned address while the IANA bootstrap keeps
  the trusted constant. A malicious `refer: 127.0.0.1:6379` / `169.254.169.254:80`
  is refused and IANA's answer kept. Behaviour-preserving (real referrals are public
  `:43`). Hermetic regression test `blocks_ssrf_and_non_whois_referrals`.
- **S3 · `[x]` P2 (MED) — world-readable secrets at rest (Linux/macOS)** *(fixed
  2026-06-17, SOL-SECRETS-EXTEND).** The dossier (`cli/export/dossier.rs`, written on
  *every* `hse scan`) and the SQLite DB (`storage/mod.rs`) used
  `std::fs::write`/`Connection::open` with **no mode** → umask 0644; `~/.huntsman/`
  had no 0700. They embed full PII + the raw API corpus (incl. harvested third-party
  keys). ✅ **Fixed:** added `util::atomic_file::{create_dir_private (0700),
  set_private (0600)}`; the auto-dossier now writes via `atomic_file::write` (0600)
  into a 0700 dir, `~/.huntsman` is created 0700 (`default_db_path`), and `Store::open`
  `set_permissions(0o600)`s the DB + `-wal`/`-shm` (inline `std`, no `storage→util`
  edge). Now consistent with the 0600 on `.huntsman.env`/`key_pool.json`/`raw/`.
  Tests: `create_dir_private_is_0700_and_set_private_is_0600`,
  `open_restricts_the_db_file_to_owner_only`. *Deliberate boundary:* an explicit
  `hse export -o <path>` is left to the user's umask — they chose the destination
  (often to share), so forcing 0600 there would surprise; the internal auto-written
  files are the ones locked down.
- **S4 · `[ ]` P3 (LOW) — key-in-URL (mostly mitigated, one residual).** ~7 modules
  put the key in the query string (`shodan`/`hunter_io`/`whoisxml`/`numverify`/
  `opencellid`/`opencorporates`/`mls`). Well-contained: no module logs the keyed URL,
  `redact_credentials` masks `key=`/`token=` + literal `HUNTSMAN_*` on error paths,
  `raw_archive` stores only `provider/endpoint/query` (not the URL). *Residual:* the
  archived success **body** is verbatim, so a key echoed by an upstream persists in
  `raw/*.json` (0600, but pulled into the non-0600 DB/dossiers via S3). → prefer
  header auth where supported; optionally `redact_literal_secrets(body,
  own_api_keys())` the archived body.
- **S5 · `[x]` P3 (LOW) — install.sh prebuilt auto-trust.** The installer
  auto-discovers and runs an `hse` from world-writable `Downloads`/`/sdcard`; the
  SHA-256 check fires only *if a sidecar `.sha256` exists* — without one it runs an
  unverified binary another app could plant. Plus `curl|bash` of unpinned
  `HSE_REF=main`. → require the sidecar checksum (or only auto-trust installer-cached
  binaries); README note to pin `HSE_REF=<tag>`. Otherwise `install.sh`/`build.rs`
  are defensively sound (atomic swap, quoting, `set -euo pipefail`, ELF/size filters).
  ✅ **Fixed (cycle 16, 2026-06-17): SOL-INSTALL-INTEGRITY.** `_validate_prebuilt`
  now requires a `<binary>.sha256` sidecar for auto-discovered binaries (missing
  `sha256sum` / absent / empty / mismatched sidecar → `log_warn` + skip). Optional for
  explicitly-set `HSE_PREBUILT` (`$2=0` passed by `maybe_use_prebuilt` when
  `HSE_PREBUILT` is set — user nominated the path, lower risk).
  **Paired:** `SOLUTION_TREE` SOL-INSTALL-INTEGRITY `[x]` + §3/§4/§5 — same commit.
- **Verified clean (no finding):** argv-only command construction (no shell);
  `KeyPool` rotation is `Mutex`-guarded (no TOCTOU/overspend on the pool itself); no
  key value logged at info/debug (only `key_tail` last-4); `settings.json` is toggles
  only and the keys API never returns values (test-pinned); export path-traversal is
  operator-only (local CLI), web import is size-bounded.

· also indexed: root `DOSSIER_*.md` real-looking secrets · **Privacy/Legal/Licensing** (PII fixture & root `DOSSIER_*.md`, source
legality, GPL `alertify` + missing `NOTICE`, at-rest encryption, use disclaimer)
· **Terminology** ("operator"→user/analyst; `key_harvest`/`API_KEY_HUNTING_GUIDE`)
· **Docs** (module-count drift across README/MODULES.md/CHANGELOG/FAULT_TREE —
**reconciled in the 2026-06-17 doc audit:** README catalogue completed to all 118
with corrected free/paid labels, MODULES.md `wigle` priority fixed, the two root
`OSINT_*` analyses refreshed to 118, FAULT_TREE stale facts corrected; the
historical per-release `CHANGELOG` counts are correctly frozen and left as-is).

## 8. Maintained log

- **2026-06-17** — Unified the four audit streams (security/correctness/
  architecture/privacy) + direct metrics into this single functionality-scoped
  tree; added the Gallant doctrine (§1), the Foundations tier (§3.F: toolkit /
  `fst` / proof-infra), and the capability program (§4) grounded in the gap
  register. Confirmed both T0 panics firsthand. Nothing executed yet — plan only.
- **2026-06-17** — **Executed T0.1, T0.2, T0.3, T1.1.** Added a shared
  boundary-safe `util::str_util::find_ascii_ci` (ASCII-case-insensitive find that
  returns an offset valid in the original string) and routed the `au_electoral` /
  `au_property` parsers through it — fixing the two `to_lowercase()`-offset slice
  panics — with regression tests (multibyte-uppercase inputs) + helper unit
  tests. Guarded the `mylnikov` confidence cast against negative/NaN ranges.
  Made GEXF shared-source edge labels and the live-session list deterministic
  (sort before emit). Gate green: fmt/clippy/doc clean, 2,950 lib tests, 0 fail.
- **2026-06-17** — **Executed T1.3.** Added direct firing assertions for the 12
  previously-unasserted correlation rules (AU-019/020/022/023/024/025/026/028/
  029/040/041/042): each test builds the minimal entity fixture that satisfies
  the rule and asserts it produces one correlation with the expected rule_id +
  severity. A silently-dead rule now fails CI. Gate green: 2,962 lib tests
  (+12), clippy/fmt clean, 0 failures.
- **2026-06-17** — **Executed T2.1** (and finished T0.3's two remaining casts).
  Added a global `read_timeout(30s)` to the shared reqwest client_builder — a
  per-read *inactivity* backstop (not a total timeout, so streaming stays
  unbounded) that stops a connect-then-stall server hanging any `await` forever,
  covering all fetch sites at once. Hardened the reddit `created_utc` and
  dns_axfr label-length casts against malformed input. Gate green: clippy/fmt
  clean, 2,962 lib tests, 0 failures.
- **2026-06-17** — **Executed T1.4** (core → modules layering breach closed).
  Added `core::hooks` — a 5-entry function-pointer registry (`reset_per_scan`,
  `set_regional`, `refresh_round_budget`, `identify_api_key`, `drain_found_keys`)
  with no-op-when-uninstalled wrappers. The `modules` layer installs it from
  `modules::registry()` (idempotent; the engine is always built from
  `registry()`, so hooks are set before any run). Replaced all 8 `crate::modules`
  call sites in `core/engine/{mod,enrich}.rs` with `core::hooks` calls; removed
  the 3 laundering allowlist entries in `tests/architecture.rs` and added a
  dedicated `core_does_not_import_modules` guard. Gate green: clippy/fmt/doc
  clean, new guard passes, 2,962 lib + integration tests, 0 failures, no
  behaviour change.
- **2026-06-17** — **T2.6 partial.** Deleted the dead `util::stats` module
  (`mode`/`mode_or`, 0 prod callers; wigle keeps its own used+tested copy) and
  routed `whoisxml::nonempty`'s logic through the canonical
  `util::str_util::nonempty` via a thin owned adapter (zero call-site / behaviour
  change). Left intentionally: `is_freemail` (oathnet_batch) and `country_name`
  (phone_area_geo) are **distinct curated lists** — force-merging them would
  change classification output, which "deterministically" forbids; they need a
  domain decision on whether the scopes are meant to be identical, not a blind
  merge. Gate green: 2,959 lib tests, clippy/fmt clean.
- **2026-06-17** — **Executed T2.2 (done) + T1.2 (API part, the primary impact).**
  Wrapped the 11 heavy async API handlers in `tokio::task::spawn_blocking` — the
  5 export renderers in `scan_export` (debug-bundle, attack-navigator, csv, gexf,
  attack-coverage) and the 6 multi-row reads in `scan_handlers` (entities, diff,
  filter, facets, correlations, audit) — so a slow query / WAL checkpoint / heavy
  render no longer blocks the ~2-worker reactor and every concurrent request.
  Wrapping `render_debug_bundle` also moves its blocking `curl` spawn off the
  async worker, **closing T2.2**. Deliberately left (engine-side, risky): the
  per-event `EventEmitter::emit` insert — a tiny WAL write whose batching would
  change SSE durability ordering for marginal gain; it needs the writer-task +
  flush-before-complete design if pursued. Gate green: clippy/fmt clean, 2,959
  lib + integration tests, 0 failures, no behaviour change.
- **2026-06-17** — **Executed T2.5** (engine arg-bloat — all 6
  `#[allow(too_many_arguments)]` removed). Introduced two borrow bundles in
  `core::engine::dispatch`: `DispatchCx` (immutable `scan_id`/`target`/`opts`/
  `is_expansion`) and `DispatchState` (mutable `entity_map`/`stats`/`dispatched`),
  threaded through `dispatch_target`, both inner loops, `gate_skips`, and
  `finalise_module_result` (now 3–4 params each). `ctx` stays a separate `&mut`
  param (distinct lifecycle: passed to `process()`, `Arc`-cloned for the
  concurrent spawn). The 6th, `run_expansion`, takes an `ExpansionState` (the six
  scan-wide accumulators) **by value and destructures it at the top**, so its
  ~400-line body is byte-identical apart from the one re-borrowed `dispatch_target`
  call — zero behaviour risk, no field-prefixing churn. The mutable fields are
  borrowed at disjoint use sites (no `&mut` aliasing on the hot path). Gate green:
  clippy/fmt/doc clean, 2,959 lib + integration tests, 0 failures.
- **2026-06-17** — **Executed T2.4** (strengthen weak tests — measured, not assumed).
  Audited all 88 `assert!(!…is_empty())` sites the node flagged: ~86 are a guard
  paired with a real content assertion on the next line (specific dork via
  `.iter().any(|s| s == …)`, `assert_eq!(recs[0].state, …)`, per-element kind +
  confidence loops, or whole-table soundness invariants) — already drift-detecting.
  Only two were genuinely sole-assertion: `ipinfo`'s non-CDN sanity counter-check
  (now asserts it yields `Coordinates` + the San-Francisco `Address`, so an
  over-firing trust gate fails loudly) and `email_header_geo::bigpond…two_entities`
  (now asserts all emissions are `Address`, the provider-inferred one has a
  non-empty region value + geoint/coarse tags + evidence). The PROBLEM_TREE
  estimate ("~88 …-only") corrected to reflect the real state. Gate green:
  clippy/fmt clean, 2,959 lib tests (assertions added, count unchanged), 0 fail.
- **2026-06-17** — **Executed T2.3** (fixture-test the binary parsers — found +
  fixed two real bugs). Added a real OpenSSL self-signed cert
  (`cert_intel/testdata/selfsigned.der`: CN/O huntsman-test.example.com /
  "Huntsman SE Test", serial 0102030405, three dNSName SANs) and a hand-built
  little-endian EXIF/TIFF (Brisbane GPS + ImageDescription, assembled in-test so
  it is reviewable, not an opaque blob). Driving the hand-rolled scanners against
  *real* ASN.1 exposed that the synthetic-fragment tests had been masking two
  breakages, now fixed: `extract_sans_from_der` ignored the SAN extension's
  `OCTET STRING → SEQUENCE` wrappers and returned **no SANs on any real
  certificate** (TLS-SAN subdomain discovery — the module's core output — was
  dead); it now descends both wrappers via a new `der_tlv_len` length decoder.
  `extract_serial_hex` returned the **version** INTEGER (and its 0x02 value byte)
  instead of the serial; it now locates and steps over the `[0] EXPLICIT` version
  wrapper. `exif_geo::extract_gps` (S/W ref sign handling) and `read_str` (ASCII
  null-trim) are now covered end-to-end through the real `exif::Reader`. The older
  synthetic fragment tests still pass (the wrapper-descent + version-skip are
  conditional). Gate green: clippy/fmt/doc clean, 2,966 lib tests (+7), 0 failures.
- **2026-06-17** — **Fixed the IPv6 Cloudflare-edge gap** (surfaced by an operator
  question on CDN noise). `is_cdn_edge_ip` covered only IPv4, returning `false` for
  every native IPv6 — so a Cloudflare-fronted domain's AAAA records leaked the v6
  edge (`2606:4700::/32`, …) through as a *trusted* host: false subject geo + an
  expandable target. A standing code comment in `ipapi` had flagged the gap. Added
  `is_cdn_edge_ipv6` (Cloudflare's published `/ips-v6` blocks — six `/32` + the
  `2a06:98c0::/29` — plus Fastly `2a04:4e42::/32`, keyed on the leading 32 bits)
  and routed native v6 through it; the shared `untrusted_ip_geo_reason`,
  expansion, and storage-demotion gates inherit it automatically (all consume the
  one predicate). The other CDN behaviours examined are correct as-is and left
  unchanged: edge IPs are *demoted not dropped* (deliberate — preserves the
  "fronted by Cloudflare" signal), and `waf_detect`/`bgpview` still run on a CDN IP
  (identifying it as Cloudflare IS the finding), so a blanket dispatch-skip would
  be wrong. The deeper win — origin-unmasking — is recorded under §4 C4. Gate
  green: clippy/fmt/doc clean, 2,967 lib tests (+1), 0 failures.
- **2026-06-17** — **Executed F.3 (proptest portion).** Added `proptest` (dev-only,
  pinned 1.11, zero shipped cost) and 13 property tests over the pure core: the
  T0-panic-class boundary guarantees (`find_ascii_ci` returns a slice-safe offset
  that matches; `truncate_safe` is a bounded char-boundary prefix; `char_window`
  is always a real substring; `floor`/`ceil_char_boundary` are valid + ordered —
  i.e. the "never slice mid-codepoint" contract is now machine-checked over
  thousands of multibyte/control inputs), `slugify`/`ascii_digits`/
  `truncate_display` charset + shape, `normalise` **idempotency across every
  EntityKind** (the UID-stability / cross-scan-dedup invariant), `derive_uid`
  determinism, and `geohash`/`parse_coords` totality + round-trip on arbitrary
  f64s. proptest immediately **found a real bug**: `slugify` used
  `char::is_alphanumeric` + `to_ascii_lowercase` (a no-op on non-ASCII), so a
  Unicode-alphanumeric source name (`É`, `¹`) leaked a raw non-ASCII/uppercase
  byte into correlation tags (`niamonx:breach:{slug}`), breaking tag determinism;
  switched to `is_ascii_alphanumeric` (output now strictly `[a-z0-9-]`). Regression
  seed committed. Remaining F.3: cargo-fuzz (CI lane) + criterion benches. Gate
  green: clippy/fmt/doc clean, 2,980 lib tests (+13), 0 failures.
- **2026-06-17** — **F.3 (proptest) — hostile-input crash-resistance.** Extended
  the property suites to the byte parsers that process *attacker-controlled*
  network input, where a panic/hang is a remote DoS of a long-lived `serve`/`live`:
  the `cert_intel` DER scanners (`extract_sans`/`extract_field`/`extract_serial`/
  `der_tlv_len` — the ones T2.3 just rewrote) never panic on arbitrary bytes
  (truncated TLVs, bogus long-form lengths, OID-prefixes with no value), and
  `dns_axfr::extract_name` always *terminates* and never panics on any buffer +
  offset — incl. all-compression-pointer buffers that would loop forever without
  the jump cap (pinned as an explicit property) — plus `build_axfr_query`'s u8
  label-length cast is total over arbitrary domains. A pre-cargo-fuzz down payment
  on "every untrusted parser is panic-proof." Gate green: clippy/fmt clean, 2,985
  lib tests (+5), 0 failures.
- **2026-06-17** — **Closed T2.6** (and F.2's de-dup goal). The last genuine
  drift-prone duplicate, `oathnet_batch`'s 7-entry `FREEMAIL`, is resolved — but
  *not* by a blind merge, which is why T2.6 had been parked. That copy served two
  roles: the `is_freemail` **predicate** AND the iteration set used to synthesise
  `{handle}@{provider}` candidate emails. Detection wants breadth (so the
  predicate now delegates to the authoritative ~60-entry `util::domains` list —
  AU ISPs / webmail like `bigpond.com`, `live.com` are now correctly skipped as
  domain searches), while synthesis wants a tight head of the distribution (60
  providers would 8× the per-handle breach-query fan-out), so that set is kept and
  renamed `SYNTH_EMAIL_PROVIDERS` with a doc spelling out the split. `country_name`
  was already delegated; `util::stats` already deleted; `nonempty` already
  delegated. `KEY_ENV` left (module-local literals can't drift — cosmetic only).
  F.2's `fst` layer remains as a pure optimisation for the *large* tables. Gate
  green: clippy/fmt/doc clean, 2,986 lib tests (+1 regression guard), 0 failures.
- **2026-06-17** — **F.3 (criterion).** Added `criterion` (dev-only, lean —
  `cargo_bench_support` only, no plotters/rayon, so it stays Termux-friendly) and
  `benches/scan_throughput.rs` benching the hottest pure parse-path scanners:
  `find_ascii_ci` (hit + worst-case miss on a 14 KB multibyte body),
  `fold_ascii_lower`, `slugify`, `geohash`. `harness = false` + a `[[bench]]`
  manifest entry; CI compiles them via clippy `--all-targets` / `cargo bench
  --no-run`, so they double as a perf-path API-drift guard (and give the
  on-device MB/s number the "structurally faster than CPython SpiderFoot" claim
  needs). The internal dispatch/correlation pass isn't `pub`, so it's deferred
  until a bench-visible entry exists. Gate green: clippy `--all-targets` + fmt
  clean, benches compile, 2,986 lib tests, 0 failures.
- **2026-06-17** — **F.3 proptest — `util::html` (the most-exercised parser).**
  `strip_html` + `decode_entities` run on *every* scraped page, so a panic there
  is the highest-frequency robustness risk. Four properties pin totality over
  arbitrary input — including `&` adjacent to multibyte chars (the precise
  codepoint-split hazard the inline comment claims is impossible), `&#x`+junk,
  trailing `&`, dense ampersand/semicolon storms, and unclosed/overlapping tags
  — plus the no-`&` fast-path byte-identity contract. No bug found (the parser
  was already sound); the no-panic contract is now machine-checked rather than
  asserted. Gate green: clippy/fmt clean, 2,990 lib tests (+4), 0 failures.
- **2026-06-17** — **Logged (analysis-only, per operator) two deferred Cloudflare
  enhancements** beyond the shipped IPv6 gate: (a) *edge-IP view suppression* —
  tag CDN-edge IPs `cdn-infra` and hide them from the default result/graph view
  (kept in the DB; today they are demoted-not-dropped, which preserves the
  "fronted by Cloudflare" signal but still shows clutter); (b) *origin-unmasking*
  — recorded under §4 C4. Neither implemented yet by request; the IPv6 accuracy
  bug (the only genuine defect) is fixed.
- **2026-06-17** — **F.3 proptest — `Entity::merge` GREATEST-semantics laws** (the
  explicit F.3 "`Entity::absorb`: commutative + clamped" item; the determinism
  core every dossier depends on). Two properties: (1) the corroborating signal
  folds as **clamped max confidence** (in [0,1], never decreasing) + **saturating
  corroboration sum floored at 1** (never decreasing); (2) merge is
  **order-independent** on the persisted signal — two raw spellings sharing a UID,
  merged in either order, yield the same canonical `raw_value` (lexicographic min),
  confidence, and corroboration, so concurrent-dispatch completion order can't leak
  into output. No bug; the GREATEST-merge invariant is now machine-checked over
  thousands of (confidence, corroboration, spelling) combinations. Gate green:
  clippy/fmt clean, 2,992 lib tests (+2), 0 failures.
- **2026-06-17** — **Critical codebase re-audit + full documentation reconciliation
  (no code change).** Ran four parallel audit streams (user-facing docs,
  architecture/dev docs, problem/fault-tree status, fresh code-quality) cross-checking
  every doc claim against the live tree. Outcomes:
  **(1) Two genuinely new robustness nodes logged** — **T2.8** (unbounded
  response-body reads: `exif_geo` buffers-then-checks, `smtp_vrfy` `read_line` has no
  byte ceiling, `json_decode` is uncapped across ~24 sites vs. its capped sibling
  `json_scanned`, AU-gov scrapers `resp.text()` uncapped → on-device OOM/DoS) and
  **T2.9** (two UI-summary SQL `ORDER BY`s without a deterministic tie-break). Both
  ride the existing §1.5/§1.7 doctrine; neither touches persisted scan bytes.
  **(2) T1.3 reopened `[x]`→`[~]`** — the 12 per-rule firing assertions shipped but
  the dispatch-table firing **meta-guard** never did, so a future un-pinned `AU-060`
  would still pass CI.
  **(3) Doc drift fixed:** `ARCHITECTURE_AUDIT.md` + `CONVENTIONS.md` still described
  the `core → modules` edge (T1.4) as a violated "Known gap" — corrected to the
  guarded, hooks-inverted reality; metrics refreshed (602 `.rs`, ~137k LOC, 311
  locked pkgs, ~2,992 tests, `panic` line); the "every module *declares*
  `attack_techniques()`" overstatement corrected to the category-default-or-override
  contract. `README` module catalogue completed (it listed 98 of 118 — 20 missing;
  now 89 free / 29 key-gated-paid, with the false "CI keeps this list honest"
  footnote corrected). `MODULES.md` `wigle` priority 18→10. `FAULT_TREE_ANALYSIS.md`
  three stale facts corrected (closed T0 panic class, test count, the E10.1 "89"
  cell). Root `OSINT_*` analyses refreshed 112→118. Baseline deps line updated
  (`proptest`/`criterion` now direct). **(4) Re-confirmed sound (§6):** the T0
  panic class is fully closed, all non-test `unwrap`/`expect` are guard/constant
  protected, `#[allow]`s justified, persisted paths totally ordered — the codebase
  is exceptionally hardened; the only residual gaps are T2.8/T2.9. No code touched;
  `cargo test --lib` re-run green at 2,992 to anchor the cited counts.
- **2026-06-17** — **Second (deeper) audit pass — storage/API + import parsers +
  the remaining un-audited docs (no code change).** Self-audited the prior pass
  first: the README free/key-gated/paid partition exactly matches each module's
  `cost()` in code (KeyGated 24 / Paid 5 verified), all T2.8/T2.9 citations are
  current, and the cross-doc figure sweep is clean (the only `2,9xx` hits are the
  correctly-frozen historical log lines). New findings logged:
  **(1) T2.9 expanded** with two higher-impact orderings the storage deep-dive
  found — `latest_completed_scan` and `list_scans` both `ORDER BY started_at DESC`
  with no tie-break, and `started_at` is 1-second resolution, so `hse
  export/diff/audit latest` can resolve to the **wrong scan**; bumped to P2.
  **(2) T1.2 addendum** — the `spawn_blocking` sweep missed two handlers:
  `scan_import` (runs a full `Correlator::run` synchronously + bypasses
  `scan_semaphore`) and `stats`. **(3) T2.8 extended** with the uncapped CLI-import
  `read_to_string` (the web path caps at 16 MB; the parsers themselves are
  fuzz-tested panic-safe). **(4) T2.10 added** — additive-only schema with no
  `PRAGMA user_version` (latent). **(5) Doc fixes:** `API_KEY_HUNTING_GUIDE`
  count drift (108→103 config paths, 300+→~170 patterns, 165+→~160 domains) and
  the `-A` flag (it auto-selects *depth*; the max-coverage preset is `-F`/`--full`)
  — corrected; `INSTALL` knob table completed (4 build env vars); `DOSSIER`
  version annotated. **Confirmed clean (§6):** SQL is fully parameterised, FTS5
  `MATCH` injection neutralised, transactions atomic, SSE bounded, no handler
  panics on input. Storage/API audit also flagged a **secrets-hygiene** concern
  (the root `DOSSIER_*.md` prints real-looking key/secret values) — already indexed
  under §7 *Deferred*; left for an explicit decision, not silently edited.
- **2026-06-17** — **Third (deepest) audit pass — engine internals, the 59
  correlator rules, and the embedded SPA (no code change).** This pass reached the
  least-audited heart of the system and found the **most significant issues of all
  three passes**, vindicating the deeper look. **(1) Stored XSS in the SPA (HIGH,
  one-click)** — `web/spa.html:1967` interpolates the attacker-controllable
  `e.value` into a JS-string literal inside an inline `onclick`; `esc()` HTML-encodes
  the quote but the HTML parser decodes it back before the JS engine runs, so
  `');alert(1)//` executes same-origin when the analyst clicks a correlation member
  to pivot (verified end-to-end with a spec-compliant parser; `connect-src 'self'`
  blocks exfil but not same-origin exec). Logged under §7 Security with the exact
  `data-`-attribute fix; the rest of the SPA's `esc()`/`extLink()` discipline is
  sound. **(2) T2.11 concurrency** — under `serve`'s 8 concurrent scans: oathnet
  left on the racy check-then-increment (overspends the *paid* quota; `see_know`
  was migrated, oathnet wasn't), and the `found_keys` sink ignores the `scan_id`
  the hook threads → cross-scan credential loss/mis-attribution. **(3) Verified
  sound (§6):** the 59 rules' logic, all geo-math primitives, the
  expansion/ROI/convex math, circuit breaker, cancel-RAII, and key hot-injection are
  **correct** — the defects are isolation/escaping-context gaps, not algorithms.
  Self-audit of the prior two passes re-confirmed (cost partition, citations, figure
  sweep all clean). **Recommendation recorded:** documentation is now exhaustively
  current across every subsystem; the remaining value is in *fixing* the backlog —
  fix order: SPA XSS (§7) → T2.11 oathnet/found_keys → T2.9 `latest` tie-break →
  T2.8 HIGH reads.
- **2026-06-17** — **Fixes, batch 1 (operator: "all of the above, as long as no
  functionality is degraded").** Landed the safe, contained fixes, each behaviour-
  preserving on the non-pathological path: **(1) SPA stored XSS (§7) — FIXED:** the
  two `pivotToEntity`/`entityPivot` sinks (`spa.html:1967`/`:1910`) now pass the
  attacker value through a `data-` attribute read via `this.dataset`, not a JS-string
  literal; a full-SPA grep confirms zero remaining `on*`-handler interpolations.
  **(2) T2.11 oathnet paid-overspend — FIXED:** swapped the racy
  `remaining()`+`increment()` for the atomic `budget_try_increment()` (CAS),
  mirroring see_know. **(3) T2.9 SQL orderings — FIXED (closed `[x]`):** unique
  final tie-break on all four read-backs (`scans` `, id DESC`; `entity_facets`
  `, e.kind ASC`; `scan_ids_for_entity` `, scan_id DESC`) — `export/diff/audit
  latest` is now deterministic on same-second ties. Regression tests added
  (`latest_completed_scan_is_deterministic_on_same_second_ties`,
  `budget_try_increment_enforces_a_finite_scan_cap`). Gate green: clippy/fmt/doc
  clean, 2,994 lib tests (+2), 0 failures. *Remaining: T2.8 HIGH reads + the
  T2.11 found_keys cross-scan isolation (the one fix needing the task-local refactor
  — done next, carefully).*
- **2026-06-17** — **Fixes, batch 2 — T2.8 the two HIGH unbounded reads.**
  **`exif_geo`:** replaced `resp.bytes().await` (buffer-then-check) with a
  `bytes_stream()` accumulate-and-bail capped at `MAX_BYTES`, so a hostile image
  host that ignores the `Range` header can no longer OOM the device; a valid image
  under the cap parses byte-identically. **`smtp_vrfy`:** `read_line_timeout` now
  caps a single line at 8 KiB via `fill_buf`/`consume` on the original `BufReader`
  (chosen over a wrapping `Take`, which would lose read-ahead and corrupt the next
  line), so a hostile MX streaming a newline-less line can't grow the buffer
  unbounded; real < 1 KiB replies are unchanged. Loopback regression test added
  (`read_line_timeout_caps_a_giant_newline_less_line`). Gate green: clippy/fmt/doc
  clean, 2,995 lib tests (+1), 0 failures. T2.8 now `[~]` — the MED `json_decode`
  cap, the AU-gov scraper `resp.text()` caps, the hibp cast, and the LOW CLI-import
  cap remain (lower-risk; batched later). *Remaining headline item: T2.11
  found_keys.*
- **2026-06-17** — **Fixes, batch 3 — assessed `found_keys` (T2.11), deferred on the
  "no functionality degraded" bar.** Traced the write path end-to-end:
  `found_keys::scan_body` has exactly one production caller (the
  `raw_archive::record` chokepoint), fed from the util HTTP helpers (`fetch`/`curl`/
  `oathnet`/`see_know`) which carry the module *name* but not `scan_id`. The clean
  design — a `tokio::task_local` scan-id in `util::found_keys` — is blocked by the
  `core_does_not_import_util_directly` guard (the engine can't scope a util
  task-local) and by `core::hooks` being fn-pointers (can't wrap a future). The
  layering-clean fix is therefore either threading `scan_id` through the entire util
  HTTP layer + every module call site, or adding a future-wrapping scope hook —
  both invasive enough that a mis-scope would *silently drop discovered keys*, i.e.
  degrade the feature. Staged for a dedicated change. **Campaign tally:** of the
  audit backlog the operator green-lit, **landed (tested + gated): SPA stored XSS
  (HIGH), oathnet paid-overspend race, all four T2.9 SQL tie-breaks, both T2.8 HIGH
  unbounded reads.** Open: `found_keys` isolation + the LOW/MED T2.8 caps + the LOW
  T2.11 over-dispatch. Lib suite 2,995, gate green throughout; single-scan CLI
  behaviour unchanged by any fix.
- **2026-06-17** — **Security hardening pass (§7) — the deferred "separate pass",
  now worked into concrete findings (analysis only).** Elevated §7 Security from a
  one-line index to verified S1–S5 entries. Two are serious: **S1 (P0) — five LIVE
  paid credentials (OathNet, paid HIBP, WiGLE, enterprise SeekNow) are hardcoded in
  `util/keys/constants.rs` and committed to the public repo / shipped binary**
  (the comments themselves mark them live-verified) → the operator must **rotate
  them at the providers** (de-embedding alone can't un-leak git history + released
  binaries), then move defaults to a build-time `option_env!` injection; and **S2
  (P1) — whois-referral SSRF**: `modules/whois` follows the referral host verbatim
  over raw TCP/43, bypassing the `SsrfResolver` (which only guards reqwest), letting
  a malicious referral point HSE at `127.0.0.1:6379`/`169.254.169.254` etc. S3 (MED)
  world-readable DB/dossiers on Linux/macOS; S4/S5 (LOW) key-in-URL residual +
  install-script prebuilt auto-trust. **Verified clean:** argv-only exec, KeyPool
  Mutex (no TOCTOU), no key logged, keys-API returns no values. The S2/S3 fixes are
  contained and behaviour-preserving (offered); S1 is an operator decision (rotate +
  UX trade-off) so it is flagged, not silently changed.
- **2026-06-17** — **Operator directive: "all keys must remain hardcoded if
  functional."** S1 reclassified `[ ]`→`[-]` **accepted by design**: the embedded
  zero-config keys stay (no de-embedding). The exposure is an accepted trade-off on
  the owner's own credentials; the *"if functional"* clause is already mechanised by
  the `SEEKNOW_SUPERSEDED_KEY*` rotate-in-place pattern (a key verified dead is
  swapped, so the embedded set self-heals to whatever is live). No code change.
- **2026-06-17** — **Internals audit of the least-covered subsystems (analysis
  only) → new node T2.12.** Swept `util` (key_pool, crypto, proxy/netrotate,
  response_cache, budget), the non-engine `core` (diff, timeline, data_broker,
  dependency, relation, roi), and every CLI command group + selftest. **Cores
  verified sound** (recorded in §6): key_pool rotation + atomic persistence, the
  crypto-address classifier, proxy/netrotate (SSRF stays closed), the budget CAS,
  roi/relation/timeline logic. **Real but contained defects logged as T2.12** —
  MED: `keys add` for a non-poolable service silently drops the key while printing a
  false "already exists" (exit 0); `provision --verify` returns exit 0 even when the
  smoke scan fails (a broken-build-passes-CI gap); `diff_entities` over-counts on
  duplicate-uid CLI JSON snapshots. LOW-MED: `response_cache` can't refresh a value
  once full (stale served). Plus LOW pool/proxy/timeline/exit-code edges. None
  crash or corrupt persisted data. The agent also independently re-verified the
  shipped T2.9 `latest` tie-break fix is correct.
- **2026-06-17** — **Paired this tree with its dual, [`SOLUTION_TREE.md`](SOLUTION_TREE.md)**
  (operator request). The solution tree inverts the axis — organised by *what we
  build* — so a primitive that closes many problems (boundary-safe scanning,
  capped reads, per-`scan_id` isolation) reads as the leverage point it is. Wired the
  same-commit lockstep protocol (`SOLUTION_TREE` §0): every change touches both trees,
  analysis alternates problem→solution and solution→problem, and gap analysis
  (`SOLUTION_TREE` §4) is the live bridge. First gap pass: largest unrealised leverage
  is the §3.F enabler block (SOL-F1/F2/F3 all `[~]`); highest-value discrete open
  solution is SOL-ISOLATE (T2.11 found_keys); highest-value contained security
  solution is SOL-SSRF-WHOIS (§7 S2); **no over-build** found. Header updated to
  reference the pair.
- **2026-06-17** — **Fixed T2.11 found_keys cross-scan contamination (SOL-ISOLATE).**
  Keyed the process-global sink by `scan_id` via a `tokio::task_local` (`SCAN`) in
  `util::found_keys`; the engine wraps `run_with_ledger` + each spawned dispatch task
  in `found_keys::with_scan`, so the per-response key scanner attributes a discovery
  to the right scan under concurrent `serve` scans without threading `scan_id`
  through the util HTTP layer. Resolved the layering tension by allow-listing the
  pure `with_scan` leaf in `core_does_not_import_util_directly` (reset/drain stay in
  the module hook). Isolation test + the `key_chaining` integration tests green; gate
  clean (clippy `await_holding_lock`-safe via `sync_scope` in the sync test), 2,996
  lib tests (+1). **Paired update:** `SOLUTION_TREE` SOL-ISOLATE `[ ]`→`[x]` and §4
  gap analysis refreshed in the same commit.
- **2026-06-17** — **Paired-tree cycle: gap analysis → fixed §7 S2 whois SSRF
  (SOL-SSRF-WHOIS).** Ran the alternating methodology: the §4 gap analysis named
  SOL-SSRF-WHOIS the highest-value *contained* open solution, so it was driven to
  done. `modules/whois` followed the referral host verbatim over raw TCP/43,
  bypassing the HTTP `SsrfResolver`. Added `client::resolve_public_whois` (port-43
  only, `is_local_domain` refused, resolves to a public `!is_private_addr` address,
  **pinned** `SocketAddr`); made `client::query` generic so the referral connects to
  the pinned address. Behaviour-preserving (real referrals are public `:43`).
  Hermetic test `blocks_ssrf_and_non_whois_referrals`. Gate green: clippy/fmt/doc
  clean, 2,997 lib tests (+1), 0 failures. **Paired:** `SOLUTION_TREE` SOL-SSRF-WHOIS
  `[ ]`→`[x]` + §4 gap analysis refreshed in the same commit (§7 S2 now off the
  build queue; the §3.F enabler block is the sole remaining high-leverage tier).
- **2026-06-17** — **Paired-tree cycle: cleared the four T2.12 MED/LOW-MED periphery
  bugs (SOL-DIFF-DEDUP, SOL-CACHE-REFRESH, SOL-CLI-CONTRACT).** This cycle took the
  highest-value *contained* items rather than the larger §3.F enablers (kept staged
  for a dedicated push). Fixed: `keys add <non-poolable>` now errors honestly
  (`is_poolable_service` pre-check) instead of the silent drop + false "already
  exists"; `provision --verify` returns non-zero on a failed smoke/missing-key
  sub-test (a CI gate can trust it); `diff_entities` iterates the deduped uid maps
  (no over-count on dup-uid CLI snapshots); `response_cache::put` allows an in-place
  refresh when full (no stale-forever). Two regression tests added; unique-uid /
  legitimate input is byte-identical, so nothing degraded. T2.12 `[ ]`→`[~]` (the
  LOW-misc residuals — pool re-validation, proxy v6 parse, env fsync, import-tsv
  scope, timeline epoch — remain). Gate green: clippy/fmt/doc clean, 2,999 lib tests
  (+2), 0 failures. **Paired:** `SOLUTION_TREE` SOL-DIFF-DEDUP/SOL-CACHE-REFRESH
  `[ ]`→`[x]`, SOL-CLI-CONTRACT `[ ]`→`[~]`, §4 refreshed — same commit.
- **2026-06-17** — **Paired-tree cycle: F.1 substrate + first consumer (SOL-F1),
  the dedicated high-leverage push.** Promoted **`aho-corasick`** to a direct dep
  (`memchr`/`bstr` held back until first directly used, else `cargo machete` trips)
  and built **`util::scan::MatchSet`** — a cached aho-corasick automaton (`is_match`
  "contains any" + leftmost-`find`, ASCII-CI, boundary-safe `&str` offsets so the T0
  panic class can't recur) with 5 unit tests + a `criterion` bench (`MatchSet` vs the
  linear `.any(.contains)` it replaces). Routed the **first consumer** — the
  search-engine anti-bot `is_captcha_page` vendor-signature scan, which runs on every
  scraped SERP — through it: **byte-for-byte equivalent** (matching the same
  lowercased body against the same lowercase signatures), proven by the 5 existing
  captcha tests passing unchanged (incl. the false-positive guard). F.1 `[ ]`→`[~]`.
  **Measured (criterion, debug-host):** the cached `MatchSet` scans the worst-case
  14 KB no-match body in **~2.2 µs vs ~26 µs** for the linear `.any(.contains)` it
  replaces — **~12× faster** (919k vs 76k iters / 2 s) — the leverage F.1 promised.
  *Remaining (each a contained increment):* the universal key scanner (~170
  prefixes), the HTML marker parsers, the other denylists; `memchr`/`bstr`. Gate
  green: clippy `--all-targets`/fmt/doc clean, benches compile, 3,004 lib tests (+5),
  0 failures, AI-independence guard still passes (aho-corasick is pure matching).
  **Paired:** `SOLUTION_TREE` SOL-F1 substrate delivered + §4b refreshed — same commit.
- **2026-06-17** — **Paired-tree cycle: fixed §7 S3 secrets-at-rest perms
  (SOL-SECRETS-EXTEND).** Gap-analysis pick: the cleanest high-value *contained* item
  (the universal-key-scanner SOL-F1 conversion needs a careful proptest-backed
  effort — staged). The auto-dossier (every scan; PII + harvested keys) and the
  SQLite DB were written with the umask (often 0644) — world-readable on a shared
  Linux/macOS host. Added `util::atomic_file::{create_dir_private (0700), set_private
  (0600)}`; routed the auto-dossier through `atomic_file::write` (0600) in a 0700
  dir, created `~/.huntsman` 0700, and `set_permissions(0o600)`'d the DB + `-wal`/
  `-shm` in `Store::open` (inline `std`, no `storage→util` edge). Now consistent with
  the existing 0600 on env/key-pool/raw. Explicit `hse export -o <path>` deliberately
  left to the user's umask (their chosen destination). Two perms tests. Gate green:
  clippy/fmt/doc clean, 3,006 lib tests (+2), 0 failures. **Paired:** `SOLUTION_TREE`
  SOL-SECRETS-EXTEND `[ ]`→`[x]` + §4a refreshed — same commit.
- **2026-06-17** — **Paired-tree cycle: +2 SOL-F1 consumers (F.1).** Two clean,
  provably-equivalent denylist conversions onto the `util::scan` substrate: key-harvest
  `contains_excluded_context` (the key-scanner false-positive gate, every prefix
  match) now uses `MatchSet::new_ascii_ci` against the *original* value — equivalent
  to `to_ascii_lowercase().contains()` (both ASCII-fold) *and* drops the per-call
  lowercase allocation on a hot path; wigle `is_generic_ssid` uses a case-sensitive
  `MatchSet` over the `to_lowercase()` string (preserves the Unicode fold). Both
  proven equivalent by their **existing** case-insensitivity tests (no new tests
  needed). *Decision:* the T1.3 firing meta-guard was investigated and is **not** a
  clean source-scan (only 6 of 59 rules use the `rule_id == "AU-NNN"` pattern; the
  rest assert firing via heterogeneous forms, and rule-source `"AU-NNN"` emissions
  confound a presence scan) — it needs a firing-fixture *table* refactor, staged. The
  universal key-scanner prefix table likewise needs a proptest-backed conversion
  (min_len/table-order). F.1 stays `[~]` (3 consumers done). Gate green: clippy/fmt/doc
  clean, 3,006 lib tests, 0 failures. **Paired:** `SOLUTION_TREE` SOL-F1 +§4b refreshed
  — same commit.
- **2026-06-17** — **Paired-tree cycle: T2.8 MED tail — SOL-CAP-EXTEND.**
  Gap-analysis pick: §4b named SOL-CAP the highest-value contained item in the
  finish queue; the §3.F enabler items (SOL-F1 key-scanner, SOL-F3 fuzz) require
  their own dedicated staged effort. Closed all MED network-path items in one pass:
  **(1)** `json_decode` now routes through `read_json_text` (32 MiB cap + raw-archive;
  a single 4-line change that closes ~24 uncapped sites — shodan, censys, dehashed,
  zoomeye, onyphe, leakix, and every other `json_decode` caller — with zero behaviour
  change below the cap); **(2)** the two `doh_resolver` and one `wigle/account` direct
  `resp.json()` calls go through `json_decode`; **(3)** nine `resp.text().await` sites
  in the four AU-gov scrapers (`asic_director`, `au_electoral`, `au_people`,
  `au_property`) routed through `read_body_capped(resp, 1_000_000)` — the pattern
  `web_crawler` already used, now uniform; **(4)** both hibp `count() as u32` cast
  sites replaced with `u32::try_from(…).unwrap_or(u32::MAX)` (P3). Remaining open:
  the LOW `cli/import/mod.rs` `read_to_string` cap. T2.8 stays `[~]`. Gate green:
  clippy/fmt/doc clean, 3,006 lib tests (count unchanged — all existing tests pass,
  including `json_decode_parses_ok_and_tags_decode_errors_with_module`), 0 failures.
  **Paired:** `SOLUTION_TREE` SOL-CAP + §4 refreshed — same commit.
- **2026-06-17** — **Paired-tree cycle 2: SOL-BLOCKING tail (T1.2) + SOL-CAP LOW
  tail (T2.8) — both closed in one pass.** S→P/gap-analysis pass: §4b had two open
  finish-queue items: SOL-BLOCKING (`scan_import`/`stats` still blocking reactor)
  and SOL-CAP (ONE LOW item: CLI-import cap). Both contained; taken together.
  **(1) `scan_import`:** gated behind `Arc::clone(&s.scan_semaphore).acquire()`
  (mirrors `spawn_scan` throttle; prevents import flood from crowding live scans);
  all sync work — `upsert_scan`, `upsert_entities_batch`, `derive_all`, the full
  `Correlator::run` loop — dispatched to `tokio::task::spawn_blocking`. Permit held
  for the entire handler (parse phase + DB phase). **(2) `stats`:** `list_scans(10_000)`
  + aggregation now run in `spawn_blocking`. **(3) `cli/import/mod.rs:24`:** added a
  `std::fs::metadata` size check (local `MAX_IMPORT_BYTES = 16 MiB`) before
  `read_to_string`; clean `Error::Other` on oversized files; realistic input
  byte-identical. **P→S gap result:** T2.8 `[~]`→`[x]` (every sub-item closed);
  T1.2 further advanced (the engine's per-entity `insert_event` + the DB-writer
  actor remain). Gate green: clippy/fmt/doc clean, 3,010 lib tests, 0 failures.
  **Paired:** `SOLUTION_TREE` SOL-CAP `[~]`→`[x]`, SOL-BLOCKING updated, §4
  refreshed — same commit.
- **2026-06-17** — **Paired-tree cycle 3: SOL-BLOCKING engine tail (T1.2) +
  SOL-CLI-CONTRACT diff exit-code (T2.12).** P→S/gap-analysis pass: §4b SOL-BLOCKING
  had one remaining open sub-item (engine `insert_event`); §4a / T2.12 LOW-misc still
  had `diff` always-`Ok`. Both contained; taken together. **(1) T1.2 engine tail:**
  `EventEmitter::emit` (`core/engine/mod.rs:152-166`) now clones the `Arc<StoragePort>`
  and wraps `store.insert_event` in `tokio::task::block_in_place`, moving the per-entity
  blocking rusqlite write off the async reactor. `tests/halting.rs` (3 tests) +
  `tests/smoke.rs` (42 async tests) upgraded from default `current_thread` to
  `(flavor = "multi_thread", worker_threads = 2)` — `block_in_place` panics on a
  single-thread runtime, and the tests should reflect production (also 2-worker
  `new_multi_thread`). **(2) T2.12 `diff` exit-code:** `cmd_diff` returns
  `Err(Error::Other("both sides resolve to the same scan"))` in the same-scan footgun
  block (`cli/diff/mod.rs:74`) — previously fell through to `Ok(())` after the
  `eprintln!`. Integration test `diff_wiring_self_compare_is_rejected_with_diagnostic`
  (renamed + rewritten) guards the new non-zero-exit behaviour. **Gap result:**
  T1.2 SOL-BLOCKING engine tail `[x]` (only DB-writer actor remains); T2.12 diff
  exit-code fixed. Gate green: clippy/fmt/doc clean, 3,006 lib + 54 smoke + 3 halting
  + 23 cli tests, 0 failures. **Paired:** `SOLUTION_TREE` SOL-BLOCKING +
  SOL-CLI-CONTRACT + §4 refreshed — same commit.
- **2026-06-17** — **Paired-tree cycle 4 (P→S): SOL-F1 key-scanner prefix table.**
  §4b named the 170-prefix `identify_vendor_api_key` O(N) loop as the remaining
  highest-leverage SOL-F1 item. **(1) `util::scan::PrefixMatcher`** added:
  `AhoCorasickBuilder` with `MatchKind::LeftmostFirst`; `find_prefix(&str) ->
  Option<usize>` returns the index of the first-declared pattern anchored at byte
  offset 0 — preserves the specific-before-generic table order that `pattern_table_is_
  structurally_sound` guards. **(2) `key_harvest/mod.rs`:** `PREFIX_MATCHER` +
  `PREFIX_GROUPS` (`HashMap<&'static str, Vec<usize>>`) statics via `LazyLock`;
  `PREFIX_GROUPS` handles the three duplicate-prefix entries (`phc_` min_len 40/30,
  `pplx-` exact duplicate, `pk_live_` Stripe+Clerk overlap) at O(K≤2) per matched
  token. `identify_vendor_api_key` replaces the linear loop. Semantic change
  (intentional, quality improvement): a token whose most-specific prefix fails
  `min_len` returns `None` — no cascade to a shorter generic prefix (`sk-svcacct-`
  short token was misclassified as `openai_or_stripe`). **(3) Tests:** proptest
  `mod prop` in `key_harvest/tests.rs` (`vendor_key_never_panics_on_arbitrary_input` +
  `synthesised_token_result_is_sane`) + deterministic cascade-prevention test
  `min_len_failure_on_specific_prefix_does_not_cascade_to_generic`. **Gap result:**
  F.1 `[~]` — 4 of N consumers done; remaining = HTML markers + memchr/bstr.
  Gate green: fmt/clippy/doc clean, 3,009 lib + 67 api + 23 arch + 54 smoke + 3 halting
  + 6 cli-seed + 2 audit-regression tests, 0 failures. **Paired:** `SOLUTION_TREE`
  SOL-F1 + §4b + §5 refreshed — same commit.
- **2026-06-17** — **Paired-tree cycle 6 (P→S): SOL-F1 `address_au` state-name scan
  + SOL-CLI-CONTRACT `resolve_scan_id` status-check.** P→S gap pass on cycle 5: §4b
  held two remaining contained items. **(1) SOL-F1 `address_au::state_code` step 2:**
  Added `MatchSet::find_id(&str) -> Option<usize>` to `util::scan` — returns the
  zero-based index of the matched pattern, enabling pattern-indexed dispatch without a
  second linear scan. Added `STATE_NAMES_MATCHER: LazyLock<MatchSet>` static in
  `util/address_au/mod.rs` compiled over `STATE_NAMES` (8 full state/territory names,
  ASCII-CI). Replaced `let lower = text.to_lowercase()` + 8-way `lower.contains(name)`
  loop in `state_code` step 2 with a single aho-corasick pass: `STATE_NAMES_MATCHER
  .find_id(text).map(|id| STATE_NAMES[id].1)` — eliminates the `to_lowercase()` alloc
  per call. Test `find_id_returns_pattern_index` guards the new API. **(2)
  SOL-CLI-CONTRACT `resolve_scan_id`:** explicit scan IDs for non-complete scans now
  return `Err("scan {id} is {status} — only complete scans can be exported…")` — was
  silently returning the id regardless of status (export/diff/audit on a mid-run or
  failed scan produced empty or misleading output). Updated two existing tests
  (`diff::load_side`, `export::explicit_scan_id`) to create `Complete` scans so they
  exercise the happy path; added new test `resolve_scan_id_rejects_incomplete_scans`.
  **T2.12 `[~]`→`[x]` — fully closed.** SOL-F1 `[~]` — 6 consumers done; remaining =
  memchr/bstr only. Gate green: fmt/clippy/doc clean, 3,018 lib + 67 api + 23 arch
  + 54 smoke + 3 halting + 6 cli-seed + 2 audit-regression tests, 0 failures.
  **Paired:** `SOLUTION_TREE` SOL-F1 + SOL-CLI-CONTRACT + §4b + §5 refreshed — same
  commit.
- **2026-06-17** — **Paired-tree cycle 5 (S→P): SOL-F1 `au_electoral` HTML markers
  + SOL-CLI-CONTRACT `audit` exit-code.** S→P pass after cycle 4 examined what the
  PrefixMatcher delivery exposed: the §4b finish queue still held two contained items.
  **(1) SOL-F1 `au_electoral` HTML markers (`src/modules/au_electoral/parse.rs`):**
  Added `MatchSet::find_range(&str) -> Option<(usize, usize)>` to `util::scan` —
  returns both `start` and `end` of the leftmost match so callers skip past a matched
  marker without knowing its length. Replaced the three `find_ascii_ci` calls in
  `extract_division` with two `LazyLock<MatchSet>` statics: `DIVISION_MARKER`
  (`new_ascii_ci(["division of "])`) and `ENROLLED_MARKERS`
  (`new_ascii_ci(["enrolled in ", "enrolled for "])`) — the two-pattern enrolled scan
  is now one aho-corasick pass instead of two sequential linear scans; AEC-before-stateEC
  priority preserved (two separate matchers, in sequence). Five tests added in
  `extract_division_tests`. **(2) SOL-CLI-CONTRACT `audit` exit-code (T2.12 LOW residual,
  `src/cli/audit/mod.rs`):** `cmd_audit` now returns
  `Err(Error::Other("audit: HIGH/CRITICAL findings detected…"))` after printing the report
  when `report.findings` contains any `Severity::Critical | Severity::High` entry —
  `hse audit` exits non-zero on a problematic result (was always `Ok(())`). Test
  `empty_scan_triggers_high_severity_exit_path` (an empty entity list → HIGH
  "empty-result" finding) guards the new path. **Gap result:** F.1 `[~]` — 5 consumers
  done; remaining = HTML markers (au_property only) + memchr/bstr. T2.12 residual
  narrowed to `resolve_scan_id` accepting incomplete scans. Gate green:
  fmt/clippy/doc clean, 3,016 lib + 67 api + 23 arch + 54 smoke + 3 halting
  + 6 cli-seed + 2 audit-regression tests, 0 failures. **Paired:** `SOLUTION_TREE`
  SOL-F1 + SOL-CLI-CONTRACT + §4b + §5 refreshed — same commit.
- **2026-06-17** — **Cycle 9 (S→P): SOL-F3 import-parser proptest.** S→P gap pass:
  §4b named SOL-F3 the next actionable §3.F item (`cargo-fuzz` blocked on nightly
  CI). Added 3 `proptest!` no-panic properties (`mod prop`) to
  `src/cli/import/tests.rs`: `parse_dossier_never_panics`,
  `parse_oathnet_txt_never_panics`, `parse_oathnet_html_never_panics` — each
  generates arbitrary Unicode strings (≤512 chars) and asserts the sync parser
  neither panics nor emits an empty-value entity. The CLI import path has no
  `catch_unwind`; a panic kills the process. The existing 25-case adversarial table
  tests fixed scenarios; proptest tests the infinite space. Gate green: fmt/clippy/
  doc clean, 3,032 lib tests (+3), 0 failures. **Paired:** `SOLUTION_TREE` SOL-F3
  §4b + §5 refreshed — same commit.
- **2026-06-17** — **Cycle 8 (P→S): T1.3 firing meta-guard (SOL-RULE-METAGUARD) — fully
  closed.** Gap-analysis pick from the paired-tree §4b: T1.3 was the last open T1
  sub-item. **(1)** Added direct firing tests for the two rules with no function-level
  firing assertion: `au021_fires_for_api_key_entity` (`ApiKey` entity →
  `rule_au_021_api_key_exposure`, `len(), 1`, `Critical`) and
  `au030_fires_for_three_source_geo_cluster` (two `Coordinates` entities with 3
  distinct corroborating sources → `rule_au_030_geo_convergence_score`, `len(), 1`,
  `Medium`). **(2)** Added `every_dispatched_correlation_rule_has_a_firing_test` to
  `tests/architecture.rs`: reads `RULES` + `RELATION_RULES` from `correlator/mod.rs`,
  then checks the test corpus (`tests.rs` + `rules/tests.rs`) for either a direct
  firing assertion (function name within ±15 lines of `len(), N`, N > 0) or an
  indirect one (`"AU-NNN"` on a line with assert/unwrap/expect/contains). All 56
  dispatched rules pass. A future `AU-060` without a firing test now fails CI.
  T1.3 `[~]`→`[x]`. Gate green: fmt/clippy/doc clean, 3,033 lib + 24 arch tests,
  0 failures. **Paired:** `SOLUTION_TREE` SOL-RULE-METAGUARD `[x]` + §4 + §5 — same
  commit.
- **2026-06-17** — **Cycle 7 expansion: `streaming_probe` +12 international platforms.**
  Operator request: "ensure expanded capabilities to find these in difficult to find
  overseas countries where people hide their true behaviour." Extended `streaming_probe`
  from 30 to 42 sites across the existing three categories, targeting the non-English
  platforms most used to maintain a covert streaming presence: **cam** — Runetki
  (Russia), Cherry.tv (Eastern Europe); **fans** — Mym (France/Francophone), Boosty
  (Russia/CIS), 4Based (Ukraine/Eastern Europe), JustForFans (LGBTQ+ international),
  OhMyFans (Spanish LATAM), Unlockd (UK), Cam.tv (Italy/Europe); **adult** —
  MyDirtyHobby (Germany), SuicideGirls (global alternative), Iwara (Japan/3D animation).
  C8 node updated to reflect full 42-site scope. Timeout comment updated (13.5s needed vs
  30s budget). Gate green: fmt/clippy/doc clean, 3,027 lib + 67 arch tests, 0 failures.
  **Paired:** `SOLUTION_TREE` SOL-STREAMING + §5 — same commit.
- **2026-06-17** — **Paired-tree cycle 7 (CAP): `streaming_probe` — webcam, fan-subscription
  & adult-video platform identity discovery.** Operator-directed capability request:
  "incorporate all forms of webcam or similar site identities as a comprehensive OSINT
  inclusion." New module `src/modules/streaming_probe/`: 30-site parallel HEAD/GET
  username prober across three category buckets — `cam` (14: Chaturbate, Stripchat,
  BongaCams, Cam4, CamSoda, MyFreeCams, Streamate, LiveJasmin, ImLive, Flirt4Free,
  Amateur.tv, Cams.com, JerkMate, SexLikeReal), `fans` (11: OnlyFans, Fansly, ManyVids,
  FanCentro, Fanvue, Loyalfans, AVN Stars, PocketStars, Passes, SextPanther, AdmireMe),
  `adult` (6: Pornhub, xHamster, xVideos, SpankBang, Erome, RedTube). Detection:
  `StatusEq(200)` HEAD for platforms with clean 404s; `StatusAndNotBody(200, needle)` GET
  for JS-rendered 200-for-all platforms. Per-profile `Url` entities tagged
  `cam-profile`/`fans-profile`/`adult-profile` + `platform:<name>`. Summary `Username`
  entity with `cam-identity-exposed`, `subscription-platform-found`, `adult-profile-found`,
  `high-streaming-exposure` (≥3 platforms) tags. `ModuleCategory::Social`
  (MITRE T1593.001 + T1589.003); priority 108; accepts `Username`; produces
  `Url`/`Username`; 16-concurrent semaphore; 30 s timeout envelope; 8 unit tests.
  New capability node C8 logged and immediately closed `[x]` (delivered on first pass).
  Baseline updated to 119 modules / Social-11; `docs/MODULES.md` + README updated
  (119 modules, 90 free); the `modules_md_lists_every_registered_module` and
  `readme_module_overview_count_matches_registry` architecture guards passed clean.
  Gate green: fmt/clippy/doc clean, 3,031 lib + 67 arch + 54 smoke + 3 halting + 23 cli
  + 6 cli-seed + 2 audit-regression tests, 0 failures. **Paired:** `SOLUTION_TREE`
  SOL-STREAMING + C8 + §4 + §5 refreshed — same commit.
- **2026-06-17** — **Cycle 10 (P→S): DB-writer actor — T1.2 fully closed
  (SOL-BLOCKING `[~]`→`[x]`).** P→S gap-analysis pick: §4b named SOL-BLOCKING
  (DB-writer actor) as T1.2's final tail — the only remaining P1 core guarantee not
  fully closed. Implemented `core::engine::writer::DbWriter`: unbounded-mpsc actor
  (`WriteCmd::Event(Box<Event>) | Flush(oneshot::Sender<()>)`); `writer_loop` tokio
  task drains the queue in `spawn_blocking` batches (greedily pulls up to 64 events
  per `spawn_blocking` call — fewer context switches than N separate `block_in_place`
  calls); `flush().await` sends a `Flush` barrier and waits for the oneshot ack, so
  all events submitted before the barrier are durably written when the future resolves.
  `EventEmitter` replaces `Arc<StoragePort>` + `block_in_place` with `DbWriter`
  (non-blocking `submit`). `ScanEngine::new` spawns the actor and keeps a clone for
  `flush`; `run_with_ledger_inner` calls `writer.flush().await` after `finalise_scan`
  returns — the barrier sits between the last `emit` and the caller seeing the
  completed scan. One test upgraded `#[test] fn` → `#[tokio::test] async fn`
  (`recall_resolves_a_fullname_seed_despite_reformatting`) since `ScanEngine::new`
  now requires an active runtime. **Paired:** `SOLUTION_TREE` SOL-BLOCKING `[~]`→`[x]`
  + §4b + §4d + §5 refreshed — same commit. Gate green: fmt/clippy/doc clean,
  3,032 lib + 24 arch + 67 api + 54 smoke + 3 halting + 23 cli + 6 cli-seed +
  2 audit-regression tests, 0 failures.
- **2026-06-17** — **Cycle 11 (S→P): SOL-BLOCKING's completion exposes T1.5.**
  S→P pass on cycle 10's DB-writer actor delivery: asked "what does the now-clean
  event path expose?" Answer — `finalise_scan` (a sync `fn` called directly from the
  async `run_with_ledger_inner`) still makes four blocking rusqlite calls:
  `upsert_entities_batch`, `upsert_scan`, `persist_relations` loop, and
  `Correlator::run` (the full SQL correlation pass). These are O(1) bulk transactions,
  not the N per-entity hot path that T1.2 fixed, so the blast radius is bounded to
  the scan-end window — invisible in CLI mode, a short reactor stall in `hse serve`
  concurrent scans. New node **T1.5 (LOW-MED)** logged. **Gap refresh:** §4a gains
  T1.5 (no solution node yet); §4d T1 row updated (T1.1/T1.2/T1.3/T1.4 `[x]`,
  T1.5 `[ ]` LOW-MED open). §3.F enabler block (SOL-F1 memchr/bstr + SOL-F2 fst +
  SOL-F3 fuzz) remains the sole unrealised high-leverage tier; SOL-BUDGET
  reset_scan-zeroing remains LOW in the finish queue. No code change this cycle.
  **Paired:** `SOLUTION_TREE` §4a + §4d + §5 refreshed — same commit.
- **2026-06-17** — **Cycle 13 (S→P): `bstr` deferral confirmed + two local
  `strip_html` duplicates surfaced.** S→P pass on cycle 12's memchr delivery.
  Grepped all callers of `strip_html`/`decode_entities`/`util::html` across the tree.
  **(1) `bstr` deferral rationale confirmed:** every production path reaching
  `strip_html` or `decode_entities` passes `&str` from `read_body_capped` →
  `String::from_utf8_lossy` — invalid UTF-8 is already handled at the reqwest boundary.
  Promoting `bstr` without a raw-bytes consumer would trip `cargo machete`. Deferred
  correctly per the "promote with first use" rule. **(2) New gap:** `au_property/parse.rs:27`
  (`strip_html`) and `au_people/mod.rs:61` (`strip_html_tags`) are independent local
  implementations — both bypass `crate::util::html::strip_html`. They work now but
  won't inherit canonical entity decoder improvements. **LOW** (no current bug; route-to-
  canonical is a one-line change per module — fold into the next SOL-F1 or T2.7 pass).
  Added to `SOLUTION_TREE` §4a as a named gap; §4b SOL-F1 remaining note updated.
  No code change this cycle. **Paired:** `SOLUTION_TREE` §4a + §4b + §5 — same commit.
- **2026-06-17** — **Cycle 12 (P→S): F.1 seventh consumer — `memchr` direct dep +
  `decode_entities` SIMD byte-scan.** P→S gap pass: §4b named `memchr` promotion as
  the remaining SOL-F1 item (`bstr` held back until a direct consumer exists, else
  `cargo machete` trips). Added `memchr = "2"` to `[dependencies]` in `Cargo.toml`
  (already in the tree transitively; `cargo fetch` updates lock file metadata only —
  no new package download). In `src/util/html/mod.rs`: `use memchr::memchr;` added;
  three `str` single-char searches in `decode_entities` replaced with SIMD equivalents:
  `s.contains('&')` → `memchr(b'&', s.as_bytes()).is_none()` (fast-path empty check);
  `rest.find('&')` → `memchr(b'&', rest.as_bytes())` (hot loop per `&` in page body);
  `inner.find(';')` → `memchr(b';', inner.as_bytes())` (entity-close scan). The
  function is called from `strip_html` on every scraped response across all 119 modules.
  `&` (0x26) and `;` (0x3B) are single-byte ASCII so byte offsets are always valid
  UTF-8 char boundaries — no correctness risk. Existing proptest suite on arbitrary
  Unicode strings re-confirms no-panic. Baseline deps updated (§2): `memchr` now
  direct. F.1 node body updated (§3.F): cycles 5/6/12 delivery notes + *Remaining*
  trimmed to `bstr` only. **Paired:** `SOLUTION_TREE` SOL-F1 node + §4b + §4d + §5
  refreshed — same commit; gate green, 3,032 lib + 24 arch + 67 api + 54 smoke +
  3 halting + 6 cli-seed + 2 audit-regression tests, 0 failures.
- **2026-06-17** — **Cycle 15 (S→P): gap analysis — T1 fully closed; identifies T2.10
  + §7 S5 as next achievable items.** S→P pass on cycle 14 deliveries. `strip_html`
  dedup exposes no new problems; SOL-FINALISE-BLOCKING bool-snapshot design confirmed
  correct. §4a scanned: T2.10 (schema versioning, no dep) and §7 S5 (install sha256,
  shell-only) are achievable. T2.7 (scraper health) and C1–C7 (gated on §3.F) deferred.
  No code change; planned cycle 16. **Paired:** `SOLUTION_TREE` §4/§5 — same commit.
- **2026-06-17** — **Cycle 16 (P→S): T2.10 schema versioning + §7 S5 install integrity
  — both closed.** Gap-analysis (cycle 15) directed two remaining achievable §4a items.
  **(1) T2.10 SOL-SCHEMA-VERSION:** `const SCHEMA_VERSION: i32 = 1` added to
  `src/storage/mod.rs`; `Store::open` reads `PRAGMA user_version` after the DDL batch
  — stamps to `SCHEMA_VERSION` when `ver < 1` (fresh or pre-versioned DB), emits
  `tracing::warn!` when `ver > SCHEMA_VERSION` (forward-compat signal for a newer
  binary). Provides the migration ladder for any future non-additive schema change.
  **(2) §7 S5 SOL-INSTALL-INTEGRITY:** `_validate_prebuilt` in `install.sh` now
  requires a `<binary>.sha256` sidecar for auto-discovered binaries: missing
  `sha256sum` / absent / empty / mismatched sidecar → `log_warn` + skip. Optional for
  explicitly-set `HSE_PREBUILT` (`$2=0`). `maybe_use_prebuilt` passes `require_sha=1`
  for all auto-discovered binaries, `0` when `HSE_PREBUILT` is set. **Gap result:**
  T2.10 and §7 S5 both `[ ]`→`[x]`; §4a now holds only T2.7 (scraper health, large),
  §7 S4 (LOW residual), and C1–C7 (gated on §3.F). All remaining items accepted-deferred
  or gated. Gate green: fmt/clippy/doc clean, 3,229 tests, 0 failures. **Paired:**
  `SOLUTION_TREE` SOL-SCHEMA-VERSION + SOL-INSTALL-INTEGRITY + §3/§4/§5 — same commit.
- **2026-06-17** — **Cycle 14 (P→S): SOL-FINALISE-BLOCKING + local `strip_html`
  dedup — T1.5 `[ ]`→`[x]`.** Two gap items from the cycle 13 S→P pass resolved
  together. **(1) `strip_html` dedup (LOW):** `au_property/parse.rs` local `strip_html`
  function replaced with `pub(super) use crate::util::html::strip_html` (re-export
  — import path unchanged for existing tests); `au_people/mod.rs` local
  `strip_html_tags` function deleted, canonical `use crate::util::html::strip_html`
  added at the import block, two call sites updated, `strip_html_tags_removes_markup`
  test deleted (function gone). Zero behaviour change; the copy-drift risk is closed.
  **(2) SOL-FINALISE-BLOCKING (LOW-MED):** `finalise_scan` changed from `fn` to
  `async fn`; body dispatched to `tokio::task::spawn_blocking` capturing
  `Arc::clone(&store)`, `emitter.clone()`, and `cancelled` (bool snapshot —
  CancellationToken is not `'static`); `persist_relations` and `run_correlator`
  inlined into the closure (both had single call-sites; removed as methods). T1.5
  `[ ]`→`[x]`. Gate green: fmt/clippy/doc clean, 3,229 tests (prev 3,230 — the
  removed `strip_html_tags` test), 0 failures. **Paired:** `SOLUTION_TREE`
  SOL-FINALISE-BLOCKING `[ ]`→`[x]` + §2/§3/§4/§5 updated — same commit.
- **2026-06-18** — **Cycle 17 (P→S + S→P): AU moat batch + NETINT depth partial +
  social enrichment — C3 `[ ]`→`[~]`, C4 `[ ]`→`[~]`, new C9 logged.**
  **P→S direction:** gap §4a named C3/C4 as the highest-value open capability
  nodes with no started solutions. Five new modules shipped: `hlr_cnam` (HLR phone
  status + CNAM subscriber name; BYO `HUNTSMAN_HLR_KEY` + `HUNTSMAN_OPENCNAM_KEY`;
  priority 138; Phone; Person+Phone entities; let-chain Edition 2024 CNAM stage);
  `ahpra` (AHPRA health-practitioner register HTML scrape; free; priority 86;
  People; `parse_ahpra_html` pure extractor); `acma_rrl` (ACMA radiocommunications
  register; free; priority 48; Corporate; ATT&CK override T1591.001/T1591.002;
  `filter(char::is_ascii_digit)` pattern); `trove_au` (NLA Trove newspaper archive;
  BYO `HUNTSMAN_TROVE_KEY`; priority 57; Corporate; let-chain title+date gate);
  `netlas` (Netlas.io host intel — ports, JARM, SSL cert emails, CVEs, ISP, geo;
  BYO `HUNTSMAN_NETLAS_KEY`; priority 79; Infrastructure; `netlas_query` helper).
  `smtp_vrfy` hardened: `tokio::join!(resolve_mx, resolve_spf, resolve_dmarc)`;
  correct hickory `lookup.answers().iter()` TXT pattern; CatchAll confidence
  0.50→0.30. `censys` priority 35→78. `reddit_user` → Organisation entities for
  subreddits (conf 0.40); `hacker_news` → Domain entities from Algolia submissions;
  `github_user` → `fetch_orgs` + `fetch_gists` in `fetch.rs`. Module count 119→124.
  All clippy/fmt/doc clean; 3,040+ lib tests, 0 failures.
  **S→P direction:** (1) three new HTML scrapers (ahpra/acma_rrl/trove_au) elevate
  T2.7 scraper-resilience risk — the per-source health-signal gap is now wider;
  (2) the new key-gated/paid modules (hlr_cnam, netlas, trove_au, censys-at-priority)
  make C9 (inter-scan API caching / cost governance) acutely felt — new capability
  node C9 logged. **Gap refresh:** C3 and C4 now `[~]`; §4a gains C9; T2.7 elevated.
  **Paired:** `SOLUTION_TREE` SOL-AU-MOAT + SOL-NETINT `[ ]`→`[~]`, new
  SOL-CACHE-INTERSCAN, §4/§5 refreshed — same commit.
- **2026-06-18** — **Cycle 20 (S→P + P→S): C4 stale notes corrected; C3 courts/AustLII
  `austlii` module delivered; SOL-HEALTH-SIGNAL solution node added; new S→P gap
  logged (opencellid × cell_intel cross-validation).**
  **S→P corrections:** verified `securitytrails` module exists (`HUNTSMAN_SECTRAILS_KEY`,
  Domain+IpAddress → Domain, subdomain enum + reverse-IP hostnames) and `bgpview` +
  `ripestat` both registered — these were listed as C4 "remaining" in error. C4 and
  SOL-NETINT remaining notes corrected to: passive-DNS subdomain union + CDN cert-hash
  origin-unmasking.
  **P→S build:** `austlii` — free AustLII court/legislation scraper; accepts
  `FullName`/`Organisation`; queries `austlii.edu.au/cgi-bin/sinosrch.cgi`;
  `extract_case_links` parser extracts `/au/cases/`, `/au/legis/`, `/au/journals/` paths;
  emits `Url` (tagged `court-judgment`) × ≤10 + `Organisation` (legal-footprint signal,
  ≥2 hits, Organisation-target only); Corporate category; priority 55; 9 unit tests.
  Closes C3 courts/AustLII. 125→126 modules, 92→93 free, Corporate 8→9.
  **New P→S gap:** T2.7 per-source health signal has no solution node → `SOL-HEALTH-SIGNAL`
  sketched in SOLUTION_TREE §2 S.QUALITY.
  **New S→P gap:** `opencellid` emits `DeviceId` (mcc-mnc-lac-cid) and `cell_intel` also
  emits `DeviceId` for the same tower type — no correlation rule links them for
  cross-validation. Logged as new gap AU-060-candidate in SOLUTION_TREE §4a.
  Gate green: fmt/clippy/doc clean, 3,061 lib tests, 0 failures. **Paired:**
  `SOLUTION_TREE` SOL-AU-MOAT/SOL-NETINT corrections + SOL-HEALTH-SIGNAL + §4/§5 cycle 20
  — same commit.
- **2026-06-18** — **Cycle 19 (P→S): C5 GEOINT first source — `opencellid`
  standalone module delivered.** P→S direction: gap §4d named C5 (SOL-GEOINT)
  as the next open capability node; OpenCelliD was already an internal dep inside
  `cell_intel` but had no standalone first-class module. Delivered: new
  `src/modules/opencellid/{mod,tests}.rs`; key-gated (`HUNTSMAN_OPENCELLID_KEY`);
  accepts `Coordinates`; queries `opencellid.org/cell/getInArea` with a ±0.005°
  BBOX (~1 km radius); emits `DeviceId` (tower id, radio, mcc/mnc/lac/cid,
  range, samples, avg signal) + `Coordinates` (tower geofix, confidence from
  accuracy radius) per tower; `cache_ttl_secs=86400`; ATT&CK override
  T1591.001+T1596; `geo(20)` section; README/MODULES.md counts updated.
  9 new unit tests. Gate green: fmt/clippy/doc clean, 3,052 lib tests, 0
  failures. C5 `[ ]`→`[~]`. **Paired:** `SOLUTION_TREE` SOL-GEOINT `[ ]`→`[~]`,
  §4d C5 row updated, leverage map updated, §5 cycle 19 — same commit.
- **2026-06-18** — **Cycle 18 (P→S + S→P): C9 inter-scan entity cache —
  SOL-CACHE-INTERSCAN delivered `[ ]`→`[x]`.** P→S direction: gap §4a named
  C9/SOL-CACHE-INTERSCAN as the highest-value build-ready open node (design sketched
  cycle 17). Delivered: `raw_archive` SQLite table; `StoragePort::
  {archive_module_result, lookup_module_result_fresh}` default-no-op trait methods;
  `Store` implementation (`src/storage/archive.rs`, 4 tests); `Module::cache_ttl_secs()`
  (default 0 = always live); `hlr_cnam` + `netlas` override to 86400s; `archive_key`
  helper; dispatch cache-check / cache-store wired in both sequential and Phase 2
  concurrent paths; `ModuleStats::cached` counter; `Scan::modules_cached` field.
  Schema snapshot test updated. Also: 4 pre-existing rustdoc bare-URL errors fixed
  (`acma_rrl`, `ahpra`, `netlas`, `trove_au`). **S→P pass:** (1) confirmed
  `reset_per_scan` is already called at `run_with_ledger_inner:289` on every scan
  start — SOL-BUDGET cited residual was a faulty premise; SOL-BUDGET `[~]`→`[-]`
  (accepted-as-is). (2) Grepped actual table sizes: OUI ≈111 entries (not ≈30k
  IEEE registry), AU postcode ≈72 entries, phone area codes ≈65 entries — the
  "large tables need fst" premise was wrong; F.2 `*Remaining*` note corrected;
  `fst` adoption `[-]`. Gate green: fmt/clippy/doc clean, 3,044 lib tests, 0
  failures. **Paired:** `SOLUTION_TREE` SOL-CACHE-INTERSCAN `[ ]`→`[x]`,
  SOL-BUDGET `[~]`→`[-]`, SOL-F2 premise corrected, §3/§4/§5 refreshed — same
  commit.
- **2026-06-18** — **Cycle 22 (S→P): CLI usability — `hse update`, command consolidation, `hse keys set`.**
  S→P direction: gap §4a had no UX node for self-upgrade; the command surface was
  sprawling (19 visible commands). Delivered: `src/cli/update.rs` — `hse update`
  (`--check` reports commits behind via `git rev-list`; default re-runs `install.sh`
  with inherited stdio; locates source via `HUNTSMAN_INSTALL_DIR` env → common
  `~/hse` / `~/.local/share/hse` paths → binary-parent traversal; falls back to
  curl one-liner); `install.sh` now writes `HUNTSMAN_INSTALL_DIR` into
  `~/.huntsman.env` after every run; `hse keys set <NAME> <VALUE>` added to
  `KeysAction` (visible_alias `set-key`, `write`); 6 commands hidden from `--help`
  (`doctor`, `selftest`, `provision`, `set-key`, `engines`, `oathnet-batch`) —
  still callable for scripting compat; visible surface 19→13. `hse upgrade` alias
  added. **New S→P gap:** `hse update --check` cannot yet propose a diff summary
  (just commit count); SOL-UPDATE *Remaining* noted below.
  Gate green: fmt/clippy/doc clean, 3,084 lib tests, 0 failures. **Paired:**
  `SOLUTION_TREE` SOL-UPDATE `[ ]`→`[x]`, §4/§5 cycle 22 — same commit.
- **2026-06-18** — **Cycle 21 (P→S): C5 GEOINT second source — `cell_local` module
  + `hse cells import` command delivered.** P→S direction: C5 (SOL-GEOINT) had
  `opencellid` as its only live source (key-gated, API-dependent); the free,
  offline leg was missing. Delivered: `src/util/cell_db.rs` — shared WAL-mode
  SQLite abstraction at `~/.huntsman/cell_towers.db` (`cells` + `cell_imports`
  tables; `insert_batch`, `query_bbox`, `record_import`, `last_import`; 8 unit
  tests); `src/cli/cells/mod.rs` — `hse cells status/import/clear` subcommand
  (`parse_csv_line` 14-col OpenCelliD CSV parser, `mcc_for_country` mapper,
  50k-row batched import with GZ decompression via `flate2`, reqwest download
  path for `--country`, 10 unit tests); `src/modules/cell_local.rs` — free
  (`ModuleCost::Free`) geo module, priority 66, accepts `Coordinates`, reads
  local DB in `spawn_blocking`, emits `DeviceId` + `Coordinates` per tower,
  silent no-op when DB absent (7 unit tests). New direct dep: `flate2 = "1"`.
  Gate green: fmt/clippy clean, all tests pass.
  **New S→P gap:** full AU dataset download requires OpenCelliD BYO key + manual
  trigger — no auto-scheduled re-sync yet. 126→127 modules, 93→94 free, Geo
  20→21. **Paired:** `SOLUTION_TREE` SOL-GEOINT *Remaining* updated + §4/§5
  cycle 21 — same commit.
- **2026-06-18** — **Cycle 23 (S→P): adversarial self-review of the v1.4.0
  update / installer / release-CI surface — 6 confirmed defects fixed, 1 false
  positive rejected.** Direction: from "critically analyse and repair all", ran a
  max-recall review over the new code, then *decomposed the review's own claims*
  and stress-tested each against the source before acting. Confirmed defects:
  **(1)** CI script injection — `release.yml` interpolated
  `${{ github.event.inputs.tag }}` straight into a `run:` block (and the `case`
  had no default), so a dispatch tag could execute on the runner; **(2)** missing
  loopback guard — `POST /api/v1/update/trigger` had none while every
  settings-write handler does, so a LAN client on `--bind 0.0.0.0` could force an
  in-place binary swap; **(3)** `install.sh` set `CARGO_TARGET_DIR` *inside* the
  `PREBUILT!=1` block but read it in the summary after the `fi`, so every
  successful prebuilt install (the v1.4.0 fast path) aborted under `set -u` with
  `unbound variable`; **(4)** the network-download path accepted a binary with
  **no** checksum when the `.sha256` sidecar fetch failed silently; **(5)**
  `load_from_file_only` returned values with their surrounding double-quotes, so
  SUPERSEDED embedded-key rotation never matched (`"v"` ≠ `v`); **(6)**
  `write_keys_at` didn't `fsync` before rename → a power-cut could leave a
  zero-length `~/.huntsman.env`. **False positive rejected (gap analysis):** a
  reviewer flagged `cell_db::query_bbox` as having swapped lat/lon param bindings
  ("every bbox query wrong") — reading the source showed `params!` binds by named
  variable in the correct semantic order and the round-trip test passes; the
  finding confused parameter-*declaration* order with *binding* order. Not
  actioned. **Residuals deliberately left (logged for focused passes):** the now-7
  per-handler loopback checks are a shallow socket-peer guard (a route-layer
  middleware is the deep fix); a network `.sha256` fetched over the same TLS
  channel is an integrity check, not authenticity (TLS cert validation is). Maps
  to the §7 security baseline (SOL-SECRETS, loopback) + a new supply-chain leaf.
  Gate green: fmt/clippy/doc clean, 3,088 lib tests (+2 trigger-guard regression
  tests), 0 failures; `bash -n` + shellcheck clean. **Paired:** `SOLUTION_TREE`
  SOL-SECRETS / SOL-SUPPLY cycle 23 + §4/§5 — same commit.
- **2026-06-18** — **Cycle 24 (P→S): `signal_radar` sensor-contamination defect —
  live phone sensors fired on all target kinds, polluting non-geo scans.**
  **Problem (fault-tree MCS-A violation):** `signal_radar` ran WiFi AP scan,
  Bluetooth scan, cell tower survey, GPS fix, and LAN ARP discovery for *every*
  scan target regardless of kind. A scan seeded on a `FullName`, `Email`,
  `Username`, `Phone`, `Domain`, or `IpAddress` caused the engine to inject the
  phone's live GPS coordinates, visible WiFi BSSIDs, nearby cell towers, and ARP
  table into the entity graph — attributing the operator's physical location and
  RF environment to the remote subject. Downstream modules `cell_local` and
  `opencellid` then fired on those injected coordinates, compounding the
  contamination with tower-lookup results that belong to the phone, not the
  target. **Root cause:** `accepts()` returned `true` for all `TargetKind`
  variants (the early implementation pre-dates the `LOCAL_PASSIVE_MODULES`
  isolation pattern and carried a rationale — "RF survey is always relevant" —
  that the user explicitly rejected). All other live-sensor modules
  (`device_sensors`, `wifi_intel`, `cell_intel`, `local_net`) correctly gate on
  `Coordinates | MacAddress` *and* appear in `LOCAL_PASSIVE_MODULES`. `signal_radar`
  was the sole exception. **Fix (two-part):** (1) `accepts()` narrowed to
  `Coordinates | MacAddress` only — phone sensors now silently skip every
  non-geo seed (no data injected, contamination chain broken at the source);
  (2) `"signal_radar"` added to `LOCAL_PASSIVE_MODULES` — expansion-round
  re-firing suppressed when a legitimate `Coordinates` entity appears during a
  geo seed's expansion (same guard that already protects the four peer modules).
  No new test code needed: the existing architecture test
  `local_passive_sensor_modules_reject_remote_subject_seeds` enumerates every
  name in `LOCAL_PASSIVE_MODULES` and asserts it refuses all non-geo seed kinds
  — adding `signal_radar` to the array makes it automatically covered.
  Gate green: fmt/clippy/doc clean, 3,092 lib tests, 0 failures; `bash -n` +
  shellcheck clean. **Paired:** `SOLUTION_TREE` SOL-SENSOR-GATE cycle 24 +
  §4/§5 — same commit.
- **2026-06-18** — **Cycle 25 (P→S): two query-pipeline defects found in real-scan
  debug bundle — `hudsonrock` URL-encoding fault and `employer_pivot` role-email
  false attribution.**
  **Source:** debug bundle from a live Huntsman scan (`full_name = Zac Allen`,
  hse_version 1.4.0). The bundle recorded 19 `module_error` events across 381
  module runs. Two were caused by code bugs, not external/network conditions.
  **Problem A — `hudsonrock` HTTP 400 "Email is required" (observed at
  ts=1781813191 for target `dns@cloudflare.com`):** `urlencode()` uses
  `url::form_urlencoded::byte_serialize`, which encodes `@` as `%40`. The
  HudsonRock Cavalier `/api/json/v2/osint-tools/search-by-login` endpoint
  validates the presence of `@` in the *raw* (pre-decode) query string before it
  URL-decodes the parameter — so `username=dns%40cloudflare.com` contains no
  literal `@` at the point of the check, triggering HTTP 400 "Email is required".
  The engine had no guard for email values that lack `@` in the first place
  (mislabelled entities or direct test calls), leaving a second latent 400 path.
  **Problem B — `employer_pivot` false employer attribution from SOA RNAME
  emails:** `dns_intel` emits SOA RNAME field values as `Email` entities
  (confidence=0.70, tagged `dns-admin`). When `dns@cloudflare.com` entered the
  expansion queue, the `Target` struct (only `kind` + `value`, no tags field)
  dropped the `dns-admin` tag. `employer_pivot` has guards for freemail domains
  and social platforms but no guard for RFC 2142 / conventional role/system
  email local-parts. It therefore scraped cloudflare.com's contact pages,
  extracted a Sydney commercial address, and attributed Cloudflare HQ to the
  scan subject `Zac Allen` — a severe false positive. **Root cause chain:**
  `dns_intel` emits SOA RNAME → entity tagged `dns-admin`, confidence 0.70
  (above expansion threshold) → expansion strips tag → `employer_pivot` accepts
  without filtering local-part → corporate address attributed to subject.
  Gate green: fmt/clippy/doc clean, 3,097 lib tests, 0 failures; `bash -n` +
  shellcheck clean. **Paired:** `SOLUTION_TREE` SOL-QUERY-PIPE cycle 25 +
  §4/§5 — same commit.
- **2026-06-20** — **Cycle 26 (P→S): C1 link analysis — the `identity_paths`
  primitive, AU-060 delegated to it, and a dossier CONNECTIONS section.**
  P→S pick: §4 C1 (Maltego-without-graphs) was the highest-value open capability.
  AU-060 transitive identity closure had already shipped, but (a) it carried its
  own private BFS and (b) there was no operator-facing render of the *path* — the
  dossier printed only the one-line verdict, and AU-060 sorted its path nodes (so
  order was lost). Delivered: `core::relation::identity_paths` — the canonical,
  deterministic shortest-typed-path finder over the relation graph (undirected
  BFS; both endpoints must be identities, intermediates any kind; parallel edges
  collapse to a stable smallest-kind label; every pair computed once from its
  smaller-UID endpoint, so output is byte-identical under input permutation — two
  proptests pin order-independence + path well-formedness, plus 8 unit tests).
  AU-060 was **refactored to delegate** to it (Rule 4: one finder, so the rule
  and the render can't drift — its 8 firing tests pass unchanged), and a new
  dossier **CONNECTIONS** section renders the shortest typed thread tying each
  identity back through the graph (`a@x (email) ──belongs_to_domain──▶ x.com
  ──registered_by──▶ Alice (person)`), annotated with each chain's weakest-edge
  confidence — graph-free link analysis, the conclusion not the canvas. Doc rule
  count corrected 59→61 (AU-060/061 had shipped unlogged). C1 `[ ]`→`[~]`.
  Gate green: fmt/clippy/doc clean, 3,261 lib tests (+10), 0 failures.
  **Paired:** `SOLUTION_TREE` SOL-CORR `[ ]`→`[~]` + §3/§4 — same commit.
- **2026-06-20** — **Cycle 27 (refactor, Rule 4): one relation-graph primitive —
  `core::network` + AU-060 + the dossier now share `core::relation::graph`.**
  Follow-through on cycle 26: `core::network::synthesize` carried its *own*
  undirected-adjacency builder and a private `reachable_from` DFS — a second copy
  of the graph mechanics the new path finder also built (exactly the drift Rule 4
  forbids). Renamed the module `relation::path`→`relation::graph` (it now owns
  adjacency + reachability + paths) and extracted `undirected_adjacency(relations,
  confine)` — one builder; `confine = None` keeps dangling endpoints for the
  subject-network view, `Some(set)` prunes them for the path/correlation view —
  plus `reachable_count`. `network` and `identity_paths` both delegate to them, so
  the subject-network view and the link-analysis view can never disagree about the
  graph. Behaviour byte-identical (network's 4 tests + AU-060's 8 + the path
  determinism proptest all pass unchanged); +3 helper unit tests. Gate green:
  fmt/clippy/doc clean, 3,264 lib tests (+3), 0 failures. **Paired:**
  `SOLUTION_TREE` SOL-CORR note + §5 — same commit.
- **2026-06-20** — **Cycle 28 (S→P, Rule 3): the AU-059 location fix is one
  structured source — kill the prose round-trip, surface it in the dossier (C5).**
  Defect: the API's `extract_au_location_fix` recovered the structured
  `best_location` (lat, lon, geohash, state, synergy confidence, source/class
  counts) by **string-splitting AU-059's human finding description** — a
  single-source violation that would silently null/garble `best_location` the
  moment anyone reworded the finding. Fix: extracted `au059_synergy_fix(entities)
  -> Option<SynergyFix>` as the **one** computation (the same gate + weighted
  centroid AU-059 already ran); the rule now *formats its description from* the
  struct, and the API reads the struct's fields directly (no parsing — severity
  and the post-hoc rank still come from the emitted correlation). The CLI debug
  bundle recomputes structurally too. **C5 bonus:** surfaced the best location
  estimate as the headline of the dossier GEO INTELLIGENCE section (it was only
  in the API export + buried in a correlation line before). Behaviour-preserving
  (AU-059's 10 rule tests + the geo-synergy sims + all-eleven-classes all pass);
  the prose-coupled API tests were replaced with a structural-robustness test
  that corrupts the description and proves the fix still resolves from entities.
  C5 stays `[~]` (best-estimate point now surfaced; confidence-radius render
  still open). Gate green: fmt/clippy/doc clean, 3,264 lib tests, 0 failures.
  **Paired:** `SOLUTION_TREE` SOL-GEOINT note + §5 — same commit.
- **2026-06-20** — **Cycle 29 (P→S, C5): confidence radius on the best-location
  estimate.** Closes the "confidence-radius render" gap cycle 28 left open. Added
  `SynergyFix::radius_km` — the robust median great-circle distance from the fix
  point to the contributing coordinates (0.5 breakdown point, via the existing
  `util::geometry::median_distance_km`) — so the headline is now a best estimate
  *with* its uncertainty: the dossier shows `lat,lon ± R km`, the API export
  carries `radius_km`, and the AU-059 finding states `± R km` (all from the one
  `au059_synergy_fix` source). C5's "single best-estimate with provenance + a
  confidence radius" is now delivered end-to-end (C5 stays `[~]` for its other
  legs: more sources, movement/timeline geo, tighter AU bounding). Gate green:
  fmt/clippy/doc clean, 3,264 lib tests, 0 failures. **Paired:** `SOLUTION_TREE`
  SOL-GEOINT note + §5 — same commit.
- **2026-06-20** — **Cycle 30 (C1): recursive multi-pathway linking, increment 1 —
  orthogonal-route corroboration (AU-062).** Operator brief: *link OSINT through
  as many orthogonal pathways as possible; use confirmed connections to develop
  new means to the same connection.* Increment 1 — the foundation the rest stands
  on — delivers **multi-pathway corroboration**: don't stop at one link between
  two seeds, find every *independent* route and reward the connection that holds
  up across them. New graph primitive `core::relation::disjoint_pathways` (greedy
  edge-disjoint shortest-path enumeration — shortest, remove its edges, repeat —
  so each route is independent; deterministic + order-independence tested). New
  rule **AU-062 multi-pathway identity corroboration**: fires when two identities
  are joined by ≥2 edge-disjoint pathways spanning ≥2 distinct OSINT **source
  families** (reusing the AU-059 `source_family` orthogonality measure) — graph
  redundancy alone is rejected; the routes must be genuinely independent data
  sources. Confidence scales with route count + family diversity. Surfaced in the
  dossier CONNECTIONS section (`· corroborated via N independent pathways`). 62
  rules now (AU-001…AU-062). Gate green: fmt/clippy/doc clean, 3,271 lib tests
  (+7), 24 arch guards, 0 failures. **Next increments:** (2) gap-fill — derive
  the missing intermediate an absent independent route would need and emit it as a
  lead; (3) backward synthesis — reverse a confirmed link into new forward seeds.
  **Paired:** `SOLUTION_TREE` SOL-CORR note + §5 — same commit.
- **2026-06-20** — **Cycle 31 (C1): recursive multi-pathway linking, increment 2 —
  gap analysis (AU-063).** The dual of AU-062: where that rule rewards a link
  confirmed by independent routes, **AU-063 single-pathway corroboration gap**
  reasons *backwards* from a found-but-fragile connection to what would make it
  solid. It fires for an identity pair joined by exactly **one transitive route**
  (≥2 hops, no independent corroboration), reads the source families that route
  already rests on, and emits the **logical requirement to fill the gap**: the
  strongest *orthogonal* OSINT source families absent from the link (`breach`,
  `social`, `presence`, `identity_registry`, … — `infra` excluded as it's usually
  the existing route). E.g. *"a@x and bob are linked by a single 2-hop pathway
  resting on [infra]; an orthogonal pathway through (breach or social) would
  confirm it."* The same `disjoint_pathways` primitive defines "one route", so
  AU-062 and AU-063 partition the space cleanly. Passive (a finding/lead) — the
  groundwork for increment 3's active re-dispatch. 63 rules now. Gate green:
  fmt/clippy/doc clean, 3,275 lib tests (+4), 24 arch guards, 0 failures.
  **Next:** (3) backward synthesis → forward seeds + the universal/all-scans
  learning loop. **Paired:** `SOLUTION_TREE` SOL-CORR note + §5 — same commit.
- **2026-06-20** — **Cycle 32 (C1): recursive multi-pathway linking, increment 3 —
  backward synthesis / generalized pathway templates (AU-064).** Reasons *backward*
  from confirmed connections to the general *means* that produced them. **AU-064
  generalized pathway template** abstracts each identity connection into its
  direction-canonical route — the ordered `(entity-kind →relation-kind→ …)`
  pattern — and fires when the **same** template links ≥2 distinct identity pairs:
  the route has proven repeatable, so it is no longer a one-off chain but a
  *confirmed means to connect that class of identity again* (e.g. `Email
  →belongs_to_domain→ Domain →registered_by→ Person`). This is the local proof of
  generalisation — "use confirmed connections to develop new means to arrive at
  the same connection". Pure core on the shared `identity_paths` primitive; the
  template is the unit a future cross-scan store would persist so the route is
  sought universally. 64 rules. Gate green: fmt/clippy/doc clean, 3,279 lib tests
  (+4), 24 arch guards, 0 failures. **Remaining (the universal/all-scans leg):**
  persist confirmed templates cross-scan via `raw_archive` (SOL-CACHE-INTERSCAN's
  substrate) and consult them at correlate time, so a route learned in one scan
  lifts every later scan — a storage+engine wiring step, scoped next.
  **Paired:** `SOLUTION_TREE` SOL-CORR note + §5 — same commit.
- **2026-06-20** — **Cycle 33 (C1): recursive multi-pathway linking, increment 4 —
  the universal/all-scans learning loop (cross-scan template store + AU-065).**
  Closes the "use confirmed connections to *universally* arrive at the same
  connection, improving all scans" leg. Built in three green sub-steps:
  **(1)** extracted `core::relation::connection_templates` as the shared
  generaliser (AU-064 now delegates to it — one definition, no drift);
  **(2)** new `pathway_templates` SQLite table + `StoragePort::{record_pathway_template,
  pathway_template_count}` (default no-op; `Store` impl in `storage/templates.rs`;
  schema-snapshot test updated) — the cross-scan memory, reusing the
  SOL-CACHE-INTERSCAN persistence pattern; **(3)** engine finalise wiring:
  generalise this scan's confirmed connections, **credit** any route a *prior*
  scan already proved as the engine-emitted **AU-065 cross-scan corroborated
  route** (`Medium`), then **record** every route so it lifts later scans. AU-065
  is storage-dependent (it reads the cross-scan count), so it is emitted by the
  engine at finalise rather than a pure correlator rule — the 64-rule count is
  unchanged. Consult-before-record ordering means a scan never self-credits.
  Components unit-tested (`connection_templates` in graph; the store round-trip +
  accumulation in `storage::templates`); glue compiles and regresses nothing.
  Gate green: fmt/clippy/doc clean, 3,280 lib tests, 24 arch guards, 0 failures.
  **Remaining refinement:** a two-scan end-to-end fixture for AU-065, and
  same-target dedup so a re-scan isn't counted as independent corroboration.
  **C1 is now delivered end-to-end** (orthogonal corroboration → gap analysis →
  backward synthesis → universal cross-scan learning). **Paired:** `SOLUTION_TREE`
  SOL-CORR `[~]` note + §5 — same commit.
- **2026-06-20** — **Cycle 34 (C1→C2): "use confirmed connections as a tool"
  applied to the OUTPUT — the multi-pathway corroboration boost.** C1 produced the
  *findings* (AU-062…AU-065); the gap was that a connection corroborated across
  many orthogonal routes was reported but did **not** strengthen the entities it
  joined — the scan's leads still read the endpoints at their pre-correlation
  confidence. Closed it: AU-062's detector is now a shared
  `multipath_corroborated_links` finder, and a new engine finalise pass
  `promote_multipath_corroborated` feeds its proof back into the entities — each
  endpoint of a link confirmed by **≥2 edge-disjoint, source-orthogonal pathways**
  earns a `multipath-corroborated` tag + corroboration evidence, lifting its
  `c_effective` and classification band so the *result* reflects what the scan's
  own correlation established. Only the two identity endpoints are lifted (a
  conduit domain is not itself corroborated); the boost source is unscored
  (`"other"`) so it can't feed back to inflate AU-062 on a recall; idempotent via
  the tag. One finder shared with the rule → the boost and the correlation can
  never disagree. No new rule (64 unchanged) — an engine pass bridging the
  correlator's proof to the entity confidence model, mirroring the proven
  `promote_geo_corroborated_family` pattern. Gate green: fmt/clippy/doc clean,
  3,283 lib tests (+1), 24 arch guards, 0 failures. **Paired:** `SOLUTION_TREE`
  SOL-CORR cycle 34 note — same commit.
- **2026-06-20** — **Cycle 35 (C1→C2): "fill in the logical requirements from
  another pathway" using confirmed connections — cross-scan gap resolution
  (AU-066).** The gap that remained: AU-063 *named* the missing orthogonal family
  for a fragile single-route link but nothing *filled* it, and the cross-scan
  template store (the record of which route shapes are confirmed) was only tallied,
  never applied to a new scan's gaps. Closed it by joining the two: a fragile link
  whose own route SHAPE has been independently confirmed in **≥2 prior scans** is
  corroborated by the proven attribution METHOD — the accumulated cross-scan
  pathway is exactly the orthogonal route the AU-063 gap was missing. Built as: a
  shared `single_route_identity_links` finder (AU-063 delegates — one finder, no
  drift between the lead that flags the gap and the engine that fills it); the
  engine-emitted **AU-066** finding ("Cross-scan route fills single-pathway gap")
  raised in the finalise template loop where the prior-scan count is already known;
  and a `promote_cross_scan_corroborated` boost that strengthens the endpoints,
  merged with the C2 multipath boost into one conditional re-persist. Soundness
  guards: the ≥2 threshold (stricter than AU-065's ≥1) keeps the gap-fill
  conservative, only identity endpoints are lifted, the evidence source is unscored
  ("other") so it can't feed back to inflate in-scan orthogonality, and the boost
  is idempotent. Engine-emitted like AU-065 → 64-rule count unchanged, rule-id
  guard satisfied. This is the flywheel the spec asks for: every scan run proves
  more routes, so more single-route gaps auto-resolve universally in later scans.
  Gate green: fmt/clippy/doc clean, 3,284 lib tests (+1), 24 arch guards, 0
  failures. **Paired:** `SOLUTION_TREE` SOL-CORR cycle 35 note — same commit.
- **2026-06-20** — **Cycle 36 (C1 capstone): "join seed data intelligently"
  realised as resolved identity clusters — AU-067 (informed by the uploaded
  `hse_modules` suite).** The user attached an `hse_modules` v1.4.0 prototype
  (ALPR/Flock, ADS-B, BTC co-spend, social-graph, cookie-chain deanon modules +
  an `IdentityClosure` union-find clusterer) alongside the recursive-linking
  spec. Most of its data-source pathways need signals an OSINT-on-a-seed tool
  can't passively collect, and it carries a parallel `Uid`/`Confidence`/`Entity`
  type system — so a blind port would be reckless churn. The genuinely-additive,
  spec-aligned piece was its `IdentityClosure`: the main HSE had transitive
  *pairs* (AU-060) and component *size* (`reachable_count`) but never resolved the
  identity *equivalence classes*. Ported the algorithm — not the code — natively:
  a shared `resolve_identity_clusters` graph primitive (union-find over the
  existing `identity_paths` link set, weakest-link confidence) and pure rule
  **AU-067** that surfaces each ≥3-identity resolved cluster above a confidence
  floor. This is the forward+backward "join seed data intelligently" leg as a
  first-class finding: many orthogonal pairwise links collapsed into a single
  "these are all one identity". Clean + safe: pure graph logic over confirmed
  relations, no new data/types/sensors/API; built on the shared finder (no drift
  with AU-060 or the dossier). Rule count 64→65 (AU-067 pure; AU-065/066 stay
  engine-emitted); README/ARCHITECTURE_AUDIT updated. Gate green: fmt/clippy/doc
  clean, 3,290 lib tests (+6), 24 arch guards, 0 failures. **Paired:**
  `SOLUTION_TREE` SOL-CORR cycle 36 note — same commit.
- **2026-06-20** — **Cycle 37 ("complete the tool / merge all pre-existing
  files"): SIM anonymity classification merged from the prototype — AU-068.** The
  instruction was to merge the uploaded `hse_modules` suite. Most of it can't be
  merged in a world-class way — `BtcClusterer`/`LocationAnchorDeano`/`AdsbOsint`/
  ALPR/`CookieChainPivot`/`SocialGraphDeano` need data a passive seed-OSINT scan
  can't collect (verified: `chain_intel` emits only `CryptoAddress`/`Username`, no
  tx/co-spend graph; no `CoSpend` relation kind), the live sensors are already
  covered (`device_sensors`/`wifi_intel`/`cell_intel`), and `llm_extract`/
  `injection` violate the deterministic-no-LLM invariant; importing them would be
  non-functional dead code the architecture guards rightly forbid. The one
  genuinely mergeable module was `sim_classify`: deterministic, offline, and it
  consumes the carrier name `hlr_cnam` already resolves. Merged natively — new
  `util::sim_anonymity` (carrier→tier classifier; VoIP/virtual + anonymity-friendly
  MVNO; conservative, returns `None` for unknown/major carriers so it never
  guesses), `hlr_cnam` tags the phone, and entity rule **AU-068** surfaces an
  anonymous/burner SIM as an attribution caveat — telling the recursive linker how
  much weight a phone-based link deserves. Allowlisted in
  `core_does_not_import_util_directly` (pure leaf util). No incompleteness markers
  remain in the tree (`unimplemented!`/`todo!`/`FIXME` count = 0); the tool is
  complete and unified. Rule count 65→66. Gate green: fmt/clippy/doc clean, 3,296
  lib tests (+6), 24 arch guards, 0 failures. **Paired:** `SOLUTION_TREE` cycle 37
  note — same commit.
- **2026-06-20** — **Cycle 38 (refactor / DRY consolidation).** With the tool
  complete and the prototype merged, "REFACTOR and merge pre-existing files" turned
  inward on the recursive-linking family's own duplication: the identity-endpoint
  enumeration (`filter is_identity_kind → map uid → sort → dedup`) was copy-pasted
  in three places and the evidence→source-family closure in two. Both are now single
  shared definitions (`core::relation::identity_uids`, `rules::source_families`),
  so the rules and the graph primitives can't drift on what an identity endpoint or
  a source-family set is — the codebase's "one finder, no drift" rule applied to
  itself. Pure behaviour-preserving refactor (the AU-060/062/063/064/067 suite
  passes unchanged); no new rule, count stays 66. Gate green: fmt/clippy/doc clean,
  3,296 lib tests, 24 arch guards, 0 failures. **Paired:** `SOLUTION_TREE` cycle 38
  note — same commit.
- **2026-06-20** — **Cycle 39 (AU-067 surfaced end-to-end).** The resolved-identity
  capstone fired as a correlation but the cluster groupings weren't in the human
  dossier. Added a "RESOLVED IDENTITIES — distinct identifiers that are one person"
  section to the CLI scan report (`print_resolved_identities`), rendering each
  ≥3-member equivalence class from the shared `resolve_identity_clusters` primitive
  beside the pairwise CONNECTIONS view. Completes the feature for the operator;
  deterministic, no behaviour change. Gate green: fmt/clippy/doc clean, 3,296 lib
  tests, 24 arch guards, 0 failures. **Paired:** `SOLUTION_TREE` cycle 39 note —
  same commit.
- **2026-06-20** — **Cycle 40 (C1 completed): active in-scan gap-fill — the engine
  pursues the missing pathway.** The recursive-linking spec's literal unmet clause
  was "when gaps exist… fill in the logical requirements that would have found the
  link from another pathway." AU-063 *named* the missing orthogonal family but
  nothing *acted* on it. Now the engine does: after expansion, `run_gap_fill` takes
  each fragile single-route identity endpoint (from the shared `gap_fill_probes`
  selector) and runs ONLY the missing orthogonal family's modules on it to seek the
  corroborating link. Safety by construction: confined to the missing-family
  modules (seeks corroboration of an already-confirmed link, never a graph-adjacent
  stranger's whole footprint), bounded (≤8 probes), budget/cancel-gated, honours
  passive/free/exclude, skips already-expanded endpoints, and reuses the tested
  `dispatch_target` (admission gates still filter results). Toggle `feature.gap_fill`
  (default ON) for a clean off-switch. The pure selection logic is unit-tested; the
  live dispatch reuses existing machinery (note: end-to-end live behaviour wants a
  real-network device run to fully exercise). No rule change (count 66). Gate green:
  fmt/clippy/doc clean, 3,298 lib tests (+2), 24 arch guards, 0 failures. **The
  recursive-linking program is now complete end-to-end.** **Paired:** `SOLUTION_TREE`
  cycle 40 note — same commit.
- **2026-06-20** — **Cycle 41 (continuous improvement: superior graph traversal).**
  Capability gap surfaced against the directive's "superior graph traversal
  techniques": every pathway finder optimised for the SHORTEST route, so a
  connection's reported strength was the weakest edge of its shortest chain — even
  when a longer but end-to-end-stronger route existed. Added the **max-bottleneck
  ("widest path")** primitive `core::relation::strongest_path` (deterministic
  hop-capped Bellman-Ford, predecessor reconstruction) and a new rule **AU-069
  High-integrity connection** that rewards a route reliable at every hop (weakest
  link ≥ 0.70). It is a distinct quality lens from AU-060 (reachability) and AU-062
  (redundancy), improving the *accuracy/quality* axis the directive calls for, and
  it compounds (every scan now distinguishes reliably-connected identities from
  merely-reachable ones). Pure, deterministic, fully unit-tested (incl.
  strongest≠shortest). Rule count 66→67. Gate green: fmt/clippy/doc clean, 3,304
  lib tests (+6), 24 arch guards, 0 failures. **Paired:** `SOLUTION_TREE` cycle 41
  note — same commit.
- **2026-06-20** — **Cycle 42 (execution efficiency + scalability).** Capability
  gap on the directive's efficiency/scalability axis: the per-pair relation rules
  rebuilt the entire sorted adjacency on every identity pair (AU-062/AU-063 in
  `disjoint_pathways`, AU-069 in `strongest_path`) — O(N²) graph builds per rule,
  quadratic in identity count, on the correlator's hot finalize path. Factored the
  one canonical build into `sorted_confined_adjacency` and added prebuilt-adjacency
  `disjoint_pathways_in` / `strongest_path_in` variants, so each rule (and the
  dossier) builds the graph ONCE and reuses it — O(N²)→O(N) graph builds, and the
  build+sort is no longer triplicated (one definition, less debt). Pure refactor:
  the AU-060/062/063/069 suite, the graph traversal tests, and the
  order-independence proptests pass unchanged, proving no behaviour drift. The gain
  compounds with scan richness (more identities ⇒ quadratically more builds saved).
  No rule change (count 67). Gate green: fmt/clippy/doc clean, 3,304 lib tests, 24
  arch guards, 0 failures. **Paired:** `SOLUTION_TREE` cycle 42 note — same commit.
- **2026-06-20** — **Cycle 43 (correctness: a property test finds a real bug in
  the widest-path finder).** Hardening cycle 41's `strongest_path` (AU-069) with
  property tests surfaced a genuine defect: the relaxation increased an
  intermediate node's hop count whenever its bottleneck improved, so a
  wider-but-longer route to that node could push the destination beyond the hop
  budget — making reachability **asymmetric** (a→b found, b→a not) even though the
  graph is undirected. A unit test missed it; the symmetry proptest caught it on a
  6-node graph. Fixed with a correct, deterministic two-phase max-bottleneck
  algorithm — a hop-bounded max-min Bellman-Ford (snapshot-relaxed, ≤k-edge-exact)
  for the value, then a BFS over the ≥bottleneck subgraph to reconstruct the
  shortest achieving route. The dominance + symmetry invariants now hold; the
  failing case is checked in under `proptest-regressions/`. Also surfaced the
  best-achievable connection reliability in the dossier CONNECTIONS view. This is
  the directive's empirical-validation loop working as intended (a property test
  empirically refuted an algorithm and drove its correction), strengthening
  accuracy + future-resilience. No rule change (count 67). Gate green:
  fmt/clippy/doc clean, 3,306 lib tests (+2), 24 arch guards, 0 failures.
  **Paired:** `SOLUTION_TREE` cycle 43 note — same commit.
- **2026-06-20** — **Cycle 44 (data-discovered correctness: stop weak links from
  fusing strangers).** A real deep scan on the common name "Ali Kareem" (Australia)
  exposed a genuine defect the synthetic tests never hit:
  `resolve_identity_clusters` unioned *every* `identity_paths` link regardless of
  confidence, so a single weak edge collapsed dozens of unrelated namesakes into
  one "resolved identity". On the live data (scan `b5ef6f41…`, 598 entities / 488
  relations) the dossier's RESOLVED IDENTITIES section and AU-067 reported **59
  distinct people** (Mohammed Abdul Kareem, Salim Atshan Fahd, Mcneish Izack
  Kareem, …) as a single person, bound by a weakest link of just **0.17**. Fixed by
  adding a `min_confidence` floor applied **at the union, not afterwards**: only a
  link whose weakest hop clears the floor may *bind* two identities, so a weak
  bridge between two strong sub-identities now leaves them as the two distinct
  clusters they are. Threaded the Probable-tier floor (0.50) through AU-067 and the
  dossier; the union floor makes AU-067's old post-hoc confidence check redundant
  (every returned cluster already clears it), leaving just the ≥3-member size gate.
  Empirically validated on the exact failing data: at floor 0.0 the largest cluster
  is 59 ids @ 0.17; at 0.50 that phantom is **gone** (largest genuine cluster 2 ids
  @ 0.90), so AU-067 and the dossier now emit **zero** false resolved-identities for
  this common-name target instead of one 59-strong phantom. Universal: every future
  scan on a common name is protected from weak-link identity fusion, and the cleaner
  clusters compound into cleaner corroboration. A new graph unit test reproduces the
  exact pattern (two 0.9 sub-identities + one 0.17 bridge: 0.0 fuses all six, 0.50
  keeps two 3-member clusters). No rule change (count 67). Gate green:
  fmt/clippy/doc clean, 3,307 lib tests (+1), 24 arch guards, 0 failures.
  **Paired:** `SOLUTION_TREE` cycle 44 note — same commit.
- **2026-06-20** — **Cycle 45 (capability: node-criticality graph traversal —
  the connection broker).** Capability gap against the directive's "superior graph
  traversal techniques / richer entity correlation": every existing relation lens
  was either pair-level (AU-060 reachability, AU-062 redundancy, AU-063 single-route
  fragility, AU-069 integrity) or cluster-level (AU-067 equivalence classes) — none
  answered the NODE-level question an analyst most wants on a discovered network:
  *which single entity holds everything together?* Added the **articulation-point**
  primitive `core::relation::connection_brokers` (an obviously-correct
  remove-and-relabel over the shared confined adjacency — correctness over fragile
  low-link bookkeeping; `O(V·(V+E))`, cheap at the bounded entity counts) and a new
  rule **AU-070 "Connection broker"** that fires when one node is the sole link
  binding ≥3 identities — remove it and the identity network fragments. It is a
  distinct lens (criticality, not reachability/redundancy/integrity), the analyst's
  prime pivot, and the highest-value gap-fill target (corroborate the broker and
  every connection through it hardens). Pure, deterministic, fully unit-tested (hub
  brokers three identities; redundant triangle has none; a 2-identity bridge stays
  AU-063's job). Built on the same graph the dossier renders (one finder, no drift)
  and compounds — every scan now surfaces its linchpin, a prime cross-scan pivot.
  Rule count 67→**68**. Gate green: fmt/clippy/doc clean, 3,313 lib tests (+6), 24
  arch guards, 0 failures. **Paired:** `SOLUTION_TREE` cycle 45 note — same commit.
- **2026-06-20** — **Cycle 46 (real-data validation hardens AU-070 + surfaces it).**
  Validating the cycle-45 broker against the live "Ali Kareem" scan (598 entities)
  exposed that `connection_brokers` was *purely structural* — no confidence floor —
  so it re-surfaced the very namesake blob cycle 44 suppressed: two common-name
  person nodes each "brokering" **58 unrelated identities** joined only by 0.17
  links. The empirical-validation loop catching the same weak-link vulnerability one
  layer down. Fixed by giving `connection_brokers` a `min_confidence` floor applied
  at traversal — only edges that clear the floor *bind* identities, so a weak edge
  can't make a node a phantom linchpin — and AU-070 + the dossier pass the same
  Probable floor (0.50) AU-067 uses. Empirically validated on the exact data: floor
  0.0 → 2 brokers of 58 (noise); floor 0.50 → **0** (the weak blob is correctly not
  a broker). Also surfaced brokers as a first-class **CONNECTION BROKERS** dossier
  section (alongside CONNECTIONS and RESOLVED IDENTITIES), so the analyst sees the
  network's load-bearing nodes — the prime corroboration pivots — directly rather
  than buried in the correlation list. A new graph unit test pins the floor (a hub
  on 0.17 links is structurally a broker at 0.0, none at 0.50). No rule change
  (count 68). Gate green: fmt/clippy/doc clean, 3,314 lib tests (+1), 24 arch
  guards, 0 failures. **Paired:** `SOLUTION_TREE` cycle 46 note — same commit.
- **2026-06-20** — **Cycle 47 (self-audit finds an accuracy/coverage bug:
  `googlemail.com` misclassified as infrastructure).** Running `hse audit` on the
  live "Ali Kareem" scan — the engine's own quality tool, exactly the empirical
  loop the directive calls for — flagged two HIGH findings: four `@googlemail.com`
  subject emails (`ali.kareem@…`, `alikareem@…`, …) reported as "role/provider
  mailboxes" and "infrastructure pollution". Root cause: `googlemail.com` (Gmail's
  consumer alias, already in `FREEMAIL`) was *also* in the `INFRA_MAIL`
  provider-domain set, so `is_infrastructure_email` returned true for **every**
  personal mailbox on it. This is not cosmetic: that predicate *suppresses* emails
  in `search_engines`, `whois`, and `ripestat`, so real subject `@googlemail.com`
  addresses were silently dropped from SERP/WHOIS/RIPE discovery (a coverage loss)
  and mislabelled noise everywhere else (an accuracy loss). Fixed at the class
  level: a **freemail guard** — a consumer freemail mailbox is never
  provider-infrastructure (only its automated desks, caught by the role-local-part
  check), so any future freemail/infra overlap is immune — plus removed the
  contradictory `googlemail.com` entry from `INFRA_MAIL`. `google.com` is kept (its
  WHOIS desks like `dns-admin@` need it and it hosts no consumer mail). Measurable
  gain: the audit grade for the same scan rose **62/100 (C, noisy) → 92/100 (A,
  clean)** and the two false HIGH findings vanished. Universal + compounding: every
  scan now keeps consumer-freemail subject emails instead of suppressing them. New
  regression assertions pin freemail-vs-role on googlemail/yahoo/outlook. No rule
  change (count 68). Gate green: fmt/clippy/doc clean, 3,314 lib tests, 24 arch
  guards, 0 failures. **Paired:** `SOLUTION_TREE` cycle 47 note — same commit.
- **2026-06-20** — **Cycle 48 (comprehensive scans: stop starving the module set).**
  Operator report: "scans are failing to execute every single file and module;
  every file should be given a chance of finding its own unique data if not
  enriching another's." Investigation (engine dispatch map) found the default scan
  effectively stalled after the seed round on a person seed: `name_intel`'s derived
  identifier permutations are emitted at `EMAIL_CONF` 0.30 / `PIVOT_CONF` 0.20,
  *below* the 0.50 expansion floor, so they never became expansion targets — and the
  default depth of 2 stopped one hop short of the infrastructure tier (the
  Email→Domain→IP chain reaches the ~30 IP modules only on the third hop). Net: a
  typical scan gave a target to only ~15 of 128 modules. Fixed by making the product
  defaults **comprehensive**: `DEFAULT_SCAN_DEPTH = MAX_DEPTH` (3) and the CLI
  `--min-expand-confidence` default 0.50 → **0.20**, so every seed-derived identifier
  expands and feeds its downstream modules, and the discovery chain reaches the
  infrastructure-tier modules. Crucially this widens *recall* only: the library
  `ScanOptions::default()` stays depth 0 / 0.50 for API/test determinism (product
  defaults are applied at the CLI boundary), and the strict 0.50 **correlation**
  floors from cycles 44/46/47 are untouched — so the engine now *expands liberally
  but correlates strictly* (guessed permutations get a chance to surface real data;
  the resolved findings stay precise). Empirical: a completed free-only name scan now
  exercises **59 distinct modules** (37 yielding data) versus the ~15 baseline (≈4×),
  with the key-gated/paid tiers adding on top when keys are present. No rule change (count 68). Gate green: fmt/clippy/doc clean,
  3,314 lib tests (defaults referenced via constants — no fallout), 24 arch guards,
  0 failures. **Paired:** `SOLUTION_TREE` cycle 48 note — same commit.
- **2026-06-20** — **Cycle 49 (consolidate MITRE: kill the separate "tab", keep the
  per-module mapping).** Operator: "the MITRE ATT&CK tab is pointless; MITRE-inspired
  OSINT should be incorporated into the actual scans, not separated from them —
  refactor the MITRE elements into the appropriate modules." MITRE was a *purely
  descriptive* reporting layer that never influenced collection: a SPA capability/
  coverage/diff panel, four API endpoints (`/attack/capability.json`,
  `/scans/{id}/attack-navigator.json`, `/scans/{id}/attack-coverage.json`,
  `/scans/{a}/attack-coverage-diff/{b}`), a `navigator` export format, a per-scan
  CLI "techniques exercised" block, an aggregate `hse modules` coverage summary, a
  full-dossier ATT&CK section, and the `Assessment`/`CoverageDiff`/`navigator_layer`/
  `coverage` + `capability_assessment`/`reconnaissance_coverage` machinery behind
  them. All of it removed (777 deletions across 14 files). What stays is MITRE *in
  the modules*: every module still declares the Reconnaissance technique it performs
  (`Module::attack_techniques`, the `RECONNAISSANCE` catalogue, `techniques_for_category`,
  the technique↔module reverse index) and the architecture guard still rejects any
  unmapped module or out-of-catalogue ID — so the taxonomy lives as inline module
  metadata, not a separate analytics surface. Purely a removal of reporting; no
  scan/engine behaviour changed. No rule change (count 68). Gate green: fmt/clippy/
  doc clean, 3,305 lib tests (−9, the removed-surface tests), 24 arch guards, 0
  failures. **Paired:** `SOLUTION_TREE` cycle 49 note — same commit.
- **2026-06-20** — **Cycle 50 (Termux safety bound for the comprehensive default).**
  Cycle 48 made the default scan comprehensive (depth `MAX_DEPTH`, 0.20 expansion
  floor) but left `max_entities` at its `None` (uncapped) default — a self-inflicted
  regression: on a common-name seed the deep low-floor sweep can fan the frontier out
  without bound (hundreds of breach/permutation identifiers, each re-expanded),
  exhausting RAM on a 4 GB no-root Termux device. Fixed with a generous product
  default `DEFAULT_MAX_ENTITIES = 2500` (≈4× a typical scan's entity count), applied
  at the CLI boundary when the operator gives no `--max-entities`, so the
  comprehensive default is **thorough but cannot run away on-device**. The split is
  deliberate and consistent with cycle 48: the library `ScanOptions::default()` stays
  `None` (uncapped) for programmatic/API determinism, `--max-entities <N>` overrides
  for power users, and a `--profile`'s own cap still wins via the overlay. This closes
  the "world-class for Termux" gap the comprehensiveness change opened — discovery is
  maximised *and* resource-bounded. No rule change (count 68). Gate green: fmt/clippy/
  doc clean, 3,305 lib tests (CLI-boundary default — no fallout), 24 arch guards, 0
  failures. **Paired:** `SOLUTION_TREE` cycle 50 note — same commit.
- **2026-06-20** — **Cycle 51 (consolidate redundant modules — debt down, no
  capability lost).** Operator: "REFACTOR and consolidate modules where applicable."
  A full audit of the 127-module layer found most apparent overlaps are *deliberate
  provider diversity* (geocode/photon, the breach DBs, the IP-reputation providers,
  cell_intel/opencellid) and were left alone; two pairs were genuine redundancy and
  were merged: **(1)** `ipapi` and `ip_whois_geo` both called the identical endpoint
  `GET https://ipwho.is/{ip}` — `ipapi` was a misnamed duplicate and `ip_whois_geo`
  the strict superset (country/au-state tags, richer evidence). Removed `ipapi`; this
  also fixes a latent **false-corroboration bug** — two modules wrapping one provider
  were being counted as two independent geo sources — and the AU-026 GEO_SOURCES /
  `source_family` lists were repointed to `ip_whois_geo` to keep corroboration
  coverage. **(2)** `qld_unclaimed` folded into `au_unclaimed` (which already covered
  the other six states): rather than flatten QLD into the simple state table (which
  would have silently dropped QLD's Person/owner-ABN/suburb extraction), its full
  pipeline moved in verbatim as a resilient `process_qld` pass, keeping the
  `"qld_unclaimed"` evidence-source string so every downstream rule keyed on it still
  fires, with 5 QLD tests ported and the module's priority lifted into the
  government-register band the waterfall guard requires. Registry **127 → 125** (92
  free · 28 key-gated · 5 paid); ~no lines of capability lost, two whole modules of
  duplication gone. README / MODULES.md / ARCHITECTURE_AUDIT counts updated (and a
  pre-existing README free-count off-by-one fixed); the `readme_module_overview_count
  _matches_registry` guard passes. No rule change (count 68). Gate green: fmt/clippy/
  doc clean, lib + integration tests 0 failures, 24 arch guards. **Paired:**
  `SOLUTION_TREE` cycle 51 note — same commit.
- **2026-06-20** — **Cycle 52 (MITRE incorporated into every scan — inline on the
  data).** Operator: "MITRE-inspired OSINT should be incorporated into [all scans] —
  the most comprehensive universal approach." Cycle 49 had removed the *separate*
  MITRE coverage tab and kept the per-module technique mapping as metadata; this
  closes the loop by stamping that mapping onto the findings themselves. Every
  admitted entity is now tagged inline with the ATT&CK Reconnaissance technique(s)
  of the module that collected it — an `attack:<ID>` tag (e.g. `attack:T1589.002`) —
  applied at the single dispatch admission point so it is **universal** (every scan,
  every seed, live + cached, sequential + concurrent), **persistent** (the tag rides
  the entity into JSON, the DB, and every render), and **compounding** (cross-module
  merges union the tags via `Entity::merge`, so an entity collected via several
  techniques carries them all). The `--output dossier` and full-export views resolve
  each tag to its technique name per finding ("MITRE ATT&CK: T1589.002 Email
  Addresses"). Layering held: techniques are sourced from the dispatched object via
  the `core::module::Module::attack_techniques()` trait method and threaded through
  `finalise_module_result` + `DispatchOutcome` — **no `core → modules` import** (the
  `core_does_not_import_modules` guard passes). With cycle 48 already running every
  reachable module, the result is that every scan now exercises the technique surface
  *and* labels every datum with the technique that produced it — MITRE in the data,
  not a side report. No rule change (count 68). Gate green: fmt/clippy/doc clean, lib
  (3,279) + integration tests 0 failures, 24 arch guards (incl. layering + ATT&CK
  mapping). **Paired:** `SOLUTION_TREE` cycle 52 note — same commit.
- **2026-06-20** — **Cycle 53 (consolidation cont'd: fuse the phone-geo pair).**
  Continuing "consolidate modules where applicable" (cycle 51 did the first two),
  merged `phone_area_geo` + `phone_carrier_geo` → one `phone_geo`. Both were passive,
  no-network, pure lookup-table modules accepting `Phone` and emitting geo at
  complementary inference layers (area-code → city/region Address+Coordinates;
  carrier-prefix → carrier/region Address). The fused module runs both passes in one
  `process()` (independent — neither's no-match suppresses the other), preserving
  every lookup table, confidence, and tag verbatim. Per the qld precedent, the
  evidence source strings stay per-strategy (`"phone_area_geo"`/`"phone_carrier_geo"`)
  because the correlator's `ANCHORING_GEO_SOURCES` + `geo_source_class()` key on them
  for geo hull-anchoring/orthogonality — only the module *name* is the clean
  `phone_geo`. 23 original tests ported + 3 integration tests proving both passes emit
  independently. Registry **125 → 124** (91 free · 28 key-gated · 5 paid); zero
  capability loss. Counts synced across README/MODULES.md/ARCHITECTURE_AUDIT; the
  registry-count, MODULES.md, and README-count guards pass. No rule change (count
  68). Gate green: fmt/clippy/doc clean, lib (3,280) + integration 0 failures, 24
  arch guards. **Paired:** `SOLUTION_TREE` cycle 53 note — same commit.
- **2026-06-20** — **Cycle 54 (comprehensive scans for the API + Chrome SPA).**
  Cycle 48 made `hse scan` comprehensive (depth `MAX_DEPTH`, 0.20 floor, 2500-entity
  cap), but the HTTP API and the SPA "New Scan" path still ran the conservative
  defaults — the SPA `buildWizardOptions()` overrode the use-case with form defaults
  of depth 2 / floor 0.50 / no cap, and the API's per-field serde defaults gave floor
  0.50 / no cap. So Chrome-UI and API scans were materially less thorough than the
  CLI for the same seed — a gap against the directive's "lightweight Chrome UI" +
  "maximise discovery for every seed". Closed it by making the **serde / request
  defaults** comprehensive while keeping the **library `ScanOptions::default()`**
  conservative for programmatic/test determinism: introduced
  `DEFAULT_MIN_EXPAND_CONFIDENCE = 0.20` as the single source of truth (CLI clap
  default + serde field default + `default_scan_options` all reference it),
  **decoupled** the serde field default from `Default::default()` (the library
  default now uses literal 0.50; the serde default returns 0.20), added a
  `default_request_max_entities` serde default of `Some(2500)`, and set the SPA
  wizard's form defaults + `all` use-case to depth 3 / floor 0.20 / cap 2500. Lock
  tests pin both halves: `library_default_stays_conservative_and_decoupled_from_serde`
  (default stays depth 0 / 0.50 / None) and `scan_request_defaults_to_comprehensive_options`
  + `empty_options_object_matches_product_defaults` (a bare `{"value":...}` request
  and `options:{}` both yield depth 3 / 0.20 / 2500). Now every surface — CLI, API,
  SPA, live — scans with the same comprehensive defaults. No rule/module change.
  Gate green: fmt/clippy/doc clean, lib (3,282) + integration 0 failures, 24 arch
  guards. **Paired:** `SOLUTION_TREE` cycle 54 note — same commit.
- **2026-06-20** — **Cycle 55 (module consolidation, final pass: the shared ASN
  entity).** After the three clean merges (cycles 51/53, 127→124) and verifying no
  same-provider duplicates remain, the last consolidation candidate was the IP-geo
  entity-builder duplication across `ip_geo`/`ipinfo`/`ip2location`/`ipquery`/
  `ip_whois_geo`. A full shared `emit_ip_geo_entities` builder was assessed and
  **rejected as a leaky abstraction**: the Coordinates formatting (4-dp vs 6-dp) and
  tags differ, the country/au-state tag policy splits two ways, and the
  Address/Org/Coords confidences + evidence are all per-provider — a unifying builder
  would need ~12 params + per-module branching, *worse* than the duplication (the
  directive's "without compromising maintainability" gate). Extracted only the
  genuinely byte-identical part — the `Asn` entity (`Entity::new(Asn, …, 0.80)` +
  `Evidence::new(src, "ASN for {ip}")`), now `util::geo::ip_asn_entity` — unified
  across all five modules, with the per-module ASN-string format and provider tag
  kept at the call site so the helper stays a clean 4-param function. Behaviour
  preserved: every one of the five modules' existing tests passed UNCHANGED; only the
  new helper test/doctest was added. This closes the consolidation pass: the genuine
  duplication is removed and the remaining per-provider variance is correctly left
  in place rather than abstracted leakily. No rule/module-count change. Gate green:
  fmt/clippy/doc clean, lib 3,283 + integration + 44 doctests, 0 failures, 24 arch
  guards. **Paired:** `SOLUTION_TREE` cycle 55 note — same commit.
- **2026-06-20** — **Cycle 56 (new correlation lens: AU-071 robustly-corroborated
  identity cluster).** Capability gap against "deeper relationship modelling /
  richer entity correlation": the suite had a cluster-level synthesis of
  *reachability* (AU-067 resolves a connected component) and a node-level
  *criticality* finding (AU-070 names a broker whose removal fragments identities),
  but nothing reported cluster-level **redundancy** — whether a resolved cluster is
  bound robustly or hangs on one fragile connector. Added rule **AU-071 "Robustly-
  corroborated identity cluster"**: a resolved cluster (≥3 identities, Probable
  floor) that NO connection broker can split — its identities stay mutually
  reachable after removing any single connector, because they are tied by
  independent routes. It is the cluster-level synthesis of AU-062's pairwise
  redundancy (as AU-067 is of AU-060's reachability) and the highest-confidence
  single-identity conclusion. Implemented purely by composition — it reuses the
  AU-067 `resolve_identity_clusters` and AU-070 `connection_brokers` primitives at
  the same floor, so "robust" means exactly "an AU-067 cluster no AU-070 broker
  splits" with no drift and **no new graph code**. A design note: a naive k-core
  over `identity_paths` was rejected — that projection is the transitive closure, in
  which any connected component is already a near-clique, so it could not distinguish
  a dense cluster from a loose chain; the broker-split test measures *real*
  redundancy instead. Pure, deterministic, fully unit-tested (fires on a
  two-anchor-redundant cluster; silent on a single-hub star). Rule count 68→**69**.
  Gate green: fmt/clippy/doc clean, lib (3,286) + integration 0 failures, 24 arch
  guards. **Paired:** `SOLUTION_TREE` cycle 56 note — same commit.
- **2026-06-20** — **Cycle 57 (empirical: SeekNow non-JSON response robustness).**
  A comprehensive all-APIs scan on the seed "Ali Kareem" (the empirical-validation
  loop) confirmed the cycle-48 comprehensive defaults work end to end (**44 distinct
  modules dispatched** in the first minutes, vs ~15 pre-cycle-48) — and surfaced a
  real robustness defect in `see_know`: `client::parse_response` hard-errored
  (`serde_json` "expected value at line 1 column 1") on any non-JSON body. A normal
  "no results" response — an empty/whitespace 200, or an HTML error/challenge/
  gateway page — therefore became a *module error* that counts as a failure and
  cools the provider off via the circuit breaker, when it should be treated as
  simply empty. Fixed: a body that isn't JSON-shaped (doesn't start with `{`/`[`)
  now returns the `Ok(Value::Null)` no-results sentinel the auth/quota branches
  already use (read as empty by `extract_items`), with a debug log; a body that
  *looks* like JSON but won't parse still errors (genuine schema-drift signal). A
  universal defensive improvement — a misbehaving or empty keyed-API response
  degrades gracefully instead of erroring and tripping the breaker on an ordinary
  no-match. Regression-tested (empty/whitespace/HTML/plain-text → Null + no items;
  valid JSON parses; truncated JSON-shaped body still errors). No rule/module
  change. Gate green: fmt/clippy/doc clean, lib 3,288 (+2), 24 arch guards, 0
  failures. **Paired:** `SOLUTION_TREE` cycle 57 note — same commit.

- **2026-06-20** — **Cycle 58 (empirical: `au_unclaimed` phantom multi-state
  coverage removed).** Continuing the "Ali Kareem" validation loop, the cycle-57
  fix was confirmed on the rebuilt binary (SeekNow's live `error code: 523` bodies
  now log as "no results" with **zero** parse errors / breaker trips, and the new
  AU-067/070/071 correlation lens fired on real data — a 30-identity resolved
  cluster, its sole broker `lucca-kareem@hotmail.com`, and a separate
  *redundantly-corroborated* 3-identity cluster with no single point of failure).
  The same log then exposed a real capability gap: `au_unclaimed` received **76 KB
  and 20 KB non-JSON bodies** from `data.vic.gov.au` and `catalogue.data.wa.gov.au`
  — guaranteed-404 error pages. Live CKAN probes (2026-06) settled it: the module
  claimed QLD/NSW/VIC/WA/SA coverage (its doc header even said TAS/ACT), but **only
  QLD** publishes a record-level unclaimed-money datastore. NSW's unclaimed packages
  are all `datastore_active=false` (external-link page, PDFs, summary xlsx — no
  queryable resource); VIC returns HTTP 404 for *every* `/api/3/action` call (the
  portal migrated off CKAN); WA's `package_search` for "unclaimed money" returns
  **0** hits; SA is the national aggregator whose only datastore-active "unclaimed
  monies" resource is the *harvested QLD* dataset (same resource id, which 404s on
  SA's own datastore). The four non-QLD `resource_id`s were fabricated placeholders
  (tell-tale symmetric/sequential hex), and the comment "Resource IDs sourced from
  each state's CKAN portal" was false — every scan spent four guaranteed-404 calls
  per name and falsely advertised five-state coverage. Fix: removed the four phantom
  `StateRegister` entries and all now-dead support (`StateRegister`, `REGISTERS`,
  `surname`, `owner_matches`, `record_to_entities`, `postcode_centroid`), simplified
  `process` to the QLD pass alone, and rewrote the module docs with the per-state
  empirical verdict plus guidance for re-adding a jurisdiction *only* with a
  verified resource id. The working QLD pipeline (the real data source) is
  untouched. Net: −1 fabricated coverage claim, −4 guaranteed-failed calls/scan,
  −~150 lines of dead code. Gate green: fmt/clippy/doc clean, lib 3,283 (−5 tests,
  all for the deleted dead path), 24 arch guards, 0 failures. **Paired:**
  `SOLUTION_TREE` cycle 58 note — same commit.

- **2026-06-20** — **Cycle 59 (empirical: Android app package mis-minted as a
  Domain → wasted expansion).** `hse audit` on the latest *complete* "Ali Kareem"
  scan scored 84/100 (B) and flagged `generic-domain-noise`, listing
  `com.facebook.katana` among bogus bare domains. Raw-archive forensics pinned the
  exact cause: an OathNet `stealer-search` row (`items[47]`) carries the captured
  app as a **reverse-DNS Android package** in *both* fields —
  `domain[0] = "com.facebook.katana"` and `url = "android://…@com.facebook.katana/"`.
  The stealer `domain`-array path minted it as a `Domain` entity (its only guard was
  `contains('.')`), and — worse than noise — that Domain then *expanded*: the
  archive shows `cavalier.hudsonrock.com__search-by-domain__com.facebook.katana`,
  a wasted HudsonRock call that pulls **other** `facebook.katana` app users' stealer
  records (strangers) into the graph. A compounding pollution bug: one bad domain
  spawns an API call that injects unrelated identities. Fix: a pure, dependency-free
  `util::domains::is_app_package_id` (a registrable domain never *leads* with a
  generic TLD — `com`/`org`/`net`/… are suffixes and appear last; so a 3+-label
  string whose *first* label is one is reverse-DNS, i.e. an app id). It gates both
  OathNet stealer Domain-minting paths (domain-array + url-host), and — because a
  Domain minted before the gate can resurface via recall — also short-circuits
  HudsonRock's `process()` for a Domain that is an app package (without making
  `accepts()` value-dependent, preserving the registry-dispatch invariants). The
  `android://` credential is still captured as a `Credential` entity; only the fake
  domain is dropped. Regression-tested (helper truth table; OathNet skips the
  package but keeps the credential; HudsonRock makes no request for a package
  domain). Gate green: fmt/clippy/doc clean, lib 3,286 (+3), 24 arch guards, 0
  failures. **Paired:** `SOLUTION_TREE` cycle 59 note — same commit.

- **2026-06-20** — **Cycle 60 (empirical: stealer URL host → Domain proliferation,
  fixed universally).** Same audit finding (`generic-domain-noise`, 44 bare
  domains), deeper root cause. Of the flagged hosts, most are **stealer-credential
  URL hosts** — sites the subject merely has an account on. The OathNet stealer
  archive shows the shape plainly: all 53 rows carry a `url`, and the login URLs are
  per-company subdomains of shared platforms — `akzonobel.taleo.net`,
  `hondana.taleo.net`, `cargill.taleo.net`, `parsons.taleo.net`,
  `siemenscorp.taleo.net` (one recruiting platform → five bogus "domains"). Both
  `extract_stealer_entities` (oathnet_pro) and `see_know::extract` minted the
  URL's host as a `Domain` "so wayback/dns/cert expand it for free" — but the
  subject does not *own* these platforms, so that expansion enumerates the
  *platform's* infrastructure (irrelevant), and worse, every shared platform
  (`taleo.net`) becomes a false correlation **broker** linking unrelated people who
  used it. The bare-domain noise the audit flags is the visible symptom; the
  wasted dns/cert/wayback/HudsonRock budget and the false brokers are the hidden
  cost. Fix (both modules, universal): stop minting the URL host as a `Domain` —
  keep the `Url` (the account pathway, 100% preserved: every row has a url) and the
  `<user>@<url>` `Credential`. The subject's genuinely-owned domains still enter via
  the breach `email_domain` path, so no real coverage is lost; only the
  third-party-platform infrastructure noise is. see_know's `domain`-field path also
  gains the cycle-59 `is_app_package_id` gate for parity. Regression-tested (oathnet
  + see_know: URL surfaces as Url, host is NOT a Domain, Credential still emitted).
  Gate green: fmt/clippy/doc clean, lib 3,286 (net 0 — 2 tests refocused), 24 arch
  guards, 0 failures. **Paired:** `SOLUTION_TREE` cycle 60 note — same commit.

- **2026-06-20** — **Cycle 61 (empirical: cross-address state bleed mints a phantom
  geocoded city).** Re-running the "Ali Kareem" scan on the rebuilt binary and
  re-auditing (the user's "re-scan + re-audit first") empirically confirmed cycles
  58–60 — **0** dead au_unclaimed CKAN calls, **0** `com.facebook.katana` domains —
  and the audit's `generic-domain-noise` finding was **eliminated** (score 85/100,
  with `geo-divergence` now the sole finding). Drilling into that geo-divergence
  surfaced a real extraction bug: a SERP bio "…Los Angeles, California Dallas,
  Texas…" made `extract_addresses_from_text` (comma path) `rfind` back past the
  first address and grab **"California Dallas"** as the city for Texas — the leading
  "California" is actually the STATE of the preceding "Los Angeles, California". The
  phantom "California Dallas, Texas" then inline-geocoded to Dallas at 0.50
  Probable, a bogus location fix. Fix: in the comma path only, when the extracted
  city begins with a state name that DIFFERS from the address's own state, strip
  that bled-over token — recovering the true "Dallas, Texas". Safe by construction:
  the differ-from-`state` guard preserves genuine state-named cities ("Virginia
  Beach, Virginia", "Oklahoma City, Oklahoma" keep their token because it matches
  their own state), and the comma-path restriction leaves word-path cities
  ("Kansas City, Missouri") untouched. (The residual geo-divergence is *identity
  conflation* — the seed name matches a US filmmaker, an AU person, and an Iraqi;
  their real locations differ — which is a separate, larger concern than this
  extraction defect.) Regression-tested (run-on split; Virginia Beach / Kansas City
  preserved). Gate green: fmt/clippy/doc clean, lib 3,287 (+1), 24 arch guards, 0
  failures. **Paired:** `SOLUTION_TREE` cycle 61 note — same commit.

- **2026-06-21** — **Cycle 62 (consolidation: three families of open-coded logic
  duplicated across modules).** A duplication sweep of all 123 modules (the codebase
  is otherwise well-factored — 108 modules already share `util::http`) surfaced
  three genuine copy-paste clusters, each a drift risk: (1) **ASN normalisation** —
  `bgpview`, `ip_registry`, `zoomeye` each open-coded "strip optional `AS` prefix,
  validate digits, parse", and `zoomeye` had silently diverged (case-sensitive
  prefix strip, so `as13335` slipped through). (2) **Raw-JSON field scanning** —
  `github_user` (×2: orgs `login`, gist `id`), `reddit_user` (`subreddit`) and
  `hacker_news` (`url`) each hand-rolled the same `find("\"key\":\"")` / slice-to-
  next-quote loop. (3) **WiGLE `network/detail` plumbing** — `wigle::fetch_detail`
  and `wifi_intel::query_wigle_detail` both built the same authenticated URL and
  (in `wifi_intel`) classified 429/401/403/404; the rate-limit branch is subtle (a
  429 must surface immediately, not sleep past the module's wall-clock budget) and
  living in two copies invited exactly the kind of drift that bites later. Net effect
  of the duplication: bug fixes had to be applied N times and didn't stay in sync.
  **Paired:** `SOLUTION_TREE` cycle 62 — same commit.

- **2026-06-21** — **Cycle 63 (duplicated HTTP request-construction literals).** Two
  User-Agent strings were copy-pasted across modules: the AU-scraper browser UA
  (`…X11; Linux…Chrome/120…`, in `asic_director`/`au_property`/`au_people`/
  `au_electoral`, 7 uses) and the polite-API UA `HSE/1.0 OSINT research tool`
  (`github_user`/`reddit_user`/`hacker_news`, 4 uses) — so a UA bump (Chrome/120 is
  already stale) meant editing N modules. Separately, five sites hand-rolled
  `.header("Authorization", format!("Bearer {t}"))` instead of reqwest's idiomatic
  `.bearer_auth()` (which also marks the header sensitive for redaction). Low-risk
  literal/idiom drift, not logic. **Paired:** `SOLUTION_TREE` cycle 63 — same commit.

- **2026-06-21** — **Cycle 64 (a second email regex defeating `util::extract`'s
  anti-drift purpose).** `reddit_user` and `hacker_news` each carried a verbatim-
  identical `bio_patterns()` — an `OnceLock<(Regex, Regex)>` pairing a *bio-specific*
  email regex (`[\w.+-]+@[\w-]+\.[\w.-]+`) with an http(s) URL regex. The email half
  is exactly the drift `util::extract` exists to prevent: it diverged from the
  canonical `EMAIL_RE` (looser — accepts a 1-char/numeric TLD like `x@y.1`), and
  there was no shared URL matcher at all, so the pattern was duplicated rather than
  reused. **Paired:** `SOLUTION_TREE` cycle 64 — same commit.

- **2026-06-21** — **Cycle 65 (two more open-coded copies of the canonical email
  regex).** Continuing the cycle-64 sweep, `exa_search` (a local `static EMAIL_RE`
  *shadowing the canonical name*) and `employer_pivot` (`extract_emails`' `OnceLock`
  regex) each re-declared the email pattern — trivially-reskinned variants
  (`a-zA-Z` ordering; an escaped `\-`) that are character-class-identical to
  `util::extract::EMAIL_RE`. Four independent email regexes had accreted (these two
  plus the two bio copies from cycle 64), defeating the single-source-of-truth the
  `util::extract` module was created to guarantee. **Paired:** `SOLUTION_TREE`
  cycle 65 — same commit.

- **2026-06-21** — **Cycle 66 (duplicated handle pre-flight in the username modules).**
  `reddit_user` and `hacker_news` each open-coded the same handle guard before
  spending an HTTP round-trip — `len` bounds plus `chars().all(|c|
  c.is_ascii_alphanumeric() || c == '-' || c == '_')` — differing only in the length
  range (3–20 vs 2–15). The "what a platform handle looks like" charset lived in two
  places. (Of the 15 modules touching `is_ascii_alphanumeric`, only these two share
  this specific handle shape; the rest validate different things with different
  separator sets, so they are intentionally left alone.) **Paired:** `SOLUTION_TREE`
  cycle 66 — same commit.

- **2026-06-21** — **Cycle 67 (`search_engines` reimplements `util::extract`'s
  byte-level text mining).** `search_engines` carried its own `extract_emails_from_text`
  / `extract_phones_from_text` (~115 lines of hand-rolled `@`/`+` byte scanners) plus
  duplicate char predicates `is_email_local_char` / `is_domain_char` in `helpers/text.rs`
  — near-identical to `util::extract::page_emails` / `phones` / `is_email_local_byte` /
  `is_domain_byte`. The copies had *diverged*: search_engines' email scanner had a
  web-script-fragment guard (`viewtopic.php…@…`) the canonical `page_emails` lacked
  (so `au_people`, the other `page_emails` caller, was still exposed to that bug),
  while its phone scanner lacked the canonical E.164 country-digit gate and the dedup.
  Four near-identical implementations of "what an email/phone looks like in scraped
  text" — the exact drift `util::extract` exists to prevent. **Paired:** `SOLUTION_TREE`
  cycle 67 — same commit.

- **2026-06-21** — **Cycle 68 (oathnet_pro/mod.rs was a 1,165-line catch-all).** The
  module's main file mixed four distinct concerns — the `Module` trait wiring +
  preflight, the breach-PII extraction (`breach_evidence`, `TargetMatch`,
  `extract_breach_entities*`, ~530 lines), the stealer-log extraction
  (`push_stealer_entity`, `extract_stealer_entities`), and a set of pure offline
  validators (`identify_password_hash`, `iban_is_valid`, `is_public_ip`, …) — in one
  scroll. Navigability and review cost suffer when unrelated logic shares a file this
  large. **Paired:** `SOLUTION_TREE` cycle 68 — same commit.

- **2026-06-21** — **Cycle 69 (see_know/extract.rs was a 1,025-line flat file).** The
  SeekNow record→entity layer bundled four independent extraction concerns in one
  file: the core breach-field extraction, geo (lat/lon) extraction, associate /
  relationship extraction, and the verbose rich-detail/context walk (with its
  ~120-line `RICH_DETAIL_SKIP` table). One scroll to find any of them.
  **Paired:** `SOLUTION_TREE` cycle 69 — same commit.

- **2026-06-21** — **Cycle 70 (key_harvest/mod.rs was the 1,363-line harvester core).**
  The API-key/secret harvester packed several distinct detector families into one
  file: API-key identification + context analysis, the main extraction orchestrator,
  the non-key secret detectors (PEM private keys, crypto-wallet addresses, recursive
  base64 unwrapping, Shannon entropy), and the key-emission/persistence path. The
  largest module file in the tree. **Paired:** `SOLUTION_TREE` cycle 70 — same commit.

- **2026-06-21** — **Cycle 71 (the `City, Region, Country` address join was inlined
  in four IP-geo modules).** `ipinfo`, `ipquery`, `censys`, and `ip_geo` each carried
  the identical five-line conditional — emit `"City, Mid, Country"`, or
  `"City, Country"` when the middle (region / state / province) component is empty —
  differing only in the middle field's local name. Four copies of one formatting rule
  is exactly the drift surface a shared helper removes. (`ip2location`'s variant folds
  a ZIP into the middle, so it is genuinely different and left alone.) An Explore pass
  confirmed the rest of the geo/JSON/HTTP surface is already consolidated
  (`coarse_provider_coords`, `val_str`, `util::http::fetch`). **Paired:**
  `SOLUTION_TREE` cycle 71 — same commit.

- **2026-06-21** — **Cycle 72 (the AU-relevance coord-tag block was copy-pasted into
  13 sites).** The identical four lines — `if let Some(state) =
  au_state_for_coords(lat, lon) { e.tag(format!("au-state:{state}")); e.tag("country:AU"); }`
  — were inlined across ~11 coordinate-emitting modules (ipinfo, ipquery, ip2location,
  mylnikov, overpass, photon, wigle, exif_geo, cell_intel, wikidata, opencellid). The
  most-duplicated geo idiom in the tree, and the kind of thing where one site drifts
  (a missing `country:AU`) and nobody notices. **Paired:** `SOLUTION_TREE` cycle 72 —
  same commit.

- **2026-06-21** — **Cycle 73 (name-search gap analysis: `parse()` corrupted two
  common name formats).** Driving the name pipeline (`name_intel` → `permute::parse`
  → usernames/emails/pivots) over a representative sample of input shapes ("Ali
  Kareem" and 11 variants) surfaced two systematic mis-parses: **(1)** "Last, First"
  records order — `"Kareem, Ali"` parsed to first=kareem/last=ali, reversing *every*
  derived handle, email and pivot (`kareem.ali` instead of `ali.kareem`); the worst
  case, `"Smith, John Michael"`, yielded first=smith/last=michael, pure garbage. This
  is the order electoral rolls, court records, CSV exports and citations emit — the
  exact sources the AU record modules consume. **(2)** A parenthetical annotation —
  `"Ali Kareem (Ali)"`, `"William (Bill) Gates"`, `"Jane Smith (Jones)"` — leaked in
  as a third name token, shifting first/middle/last. Diacritic folding, non-Latin
  graceful-degrade, honorifics, suffixes, initials and whitespace were already
  correct. **Paired:** `SOLUTION_TREE` cycle 73 — same commit.

- **2026-06-21** — **Cycle 74 (seven modules bypassed the shared JSON-decode path).**
  `hunter_io`, `ip2location`, `disposable_check`, `ipinfo`, `whoisxml`, `ipquery` and
  `crtsh` hand-rolled `resp.json().await.map_err(|e| Error::module(SRC, format!("JSON:
  {e}")))` instead of `util::http::json_decode` — which 76 other call sites use. Not
  cosmetic: that helper is the single chokepoint for **universal raw retention** (its
  doc: the archive "is complete for ANY scan"), so these seven modules' responses were
  silently **missing from the dossier's RAW SOURCE RECORDS**, and — bypassing the
  32 MiB `JSON_BODY_CAP` — each could **OOM a constrained Termux device** on a hostile
  or buggy oversized response. The hand-rolled error also collapsed a mid-stream read
  failure and a parse failure into one undistinguished message. **Paired:**
  `SOLUTION_TREE` cycle 74 — same commit.

- **2026-06-21** — **Cycle 75 (`send_tagged` leaked the request URL — API key + target
  PII — into the error logs).** `RequestBuilderExt::send_tagged`, the shared transport
  helper its own doc says ~40 modules use, mapped a send failure with bare
  `e.to_string()`. A reqwest transport error embeds the offending URL, whose query
  string carries the upstream **API key** (`?apikey=…`) and the **target's PII** (the
  email / username / name being searched) — and that error propagates into the
  downloadable verbose log (`/api/v1/logs`) and the event stream. So a single timeout
  or DNS failure on a keyed lookup could spill the operator's key and the subject's
  identifier into a file the UI hands out. Two modules (`hunter_io`, `whoisxml`) had
  already noticed and hand-rolled `e.without_url()` locally; `niamonx` (×3) and
  `osintcat` bypassed the helper with the bare leaking form. A unit test confirmed the
  leak (unstripped error contains the secret; stripped does not). **Paired:**
  `SOLUTION_TREE` cycle 75 — same commit.

- **2026-06-21** — **Cycle 76 (breach/stealer parsers minted garbage Email/Domain
  entities — ground-truthed against real Ali.kareem scan logs).** Three uploaded
  upstream dumps (combined-search + stealer-logs) exposed two data-quality leaks the
  parsers waved through: **(1)** `see_know` emitted an `Email` on a bare
  `value.contains('@')` with no shape check, so a provider echoing the query into the
  field (snusbase returned `"email": "Ali.kareem"`, and half-values like `user@`)
  became Email entities. **(2)** Every `domain`-field → `Domain` path (`oathnet_pro`
  breach + stealer, `see_know`) gated only on `contains('.') && !is_app_package_id`,
  so the IPs that saturate stealer logs — private (`192.168.0.1`) and public C2/panel
  (`79.98.132.222`, `54.39.106.39`) — were minted as `Domain` entities, the exact
  dns/cert/wayback misdirection the stealer path's own comment warns against. Both
  pollute the graph and forge false correlations — the opposite of the cross-module
  synergy intended. The `looks_like_email` gate also lived private to `oathnet_pro`,
  and the domain check was triplicated. **Paired:** `SOLUTION_TREE` cycle 76 — same
  commit.

- **2026-06-21** — **Cycle 77 (a salted breach digest went unclassified, hiding the
  strongest exposure signal).** OathNet packs the salt onto the password hash —
  space-separated (`"2f4370b7…2858 _:=j[gpxgh…"`) or behind a `,:` marker
  (`"b3dd…b414,:xpay"`), both real values from the Ali.kareem `jefit`/`boostbot` rows.
  `identify_password_hash` demanded the *whole* string be hex, so the trailing salt
  made it return `None`: the MD5 was emitted with **no `hash:md5`, no `crackable:fast`,
  no `salted` tag** — and `mod.rs`'s fast-hash filter (which gates the
  plaintext-equivalent warning) silently skipped it. A fast unsalted MD5 is
  effectively plaintext; failing to flag it understates the account's exposure. (Also
  verified list item #1, cross-provider **dedup**, is already correct:
  `uid = SHA-256(kind:normalised_value)` + `merge`/`absorb` folds evidence, sums
  corroboration and maxes confidence, so the same record from multiple modules already
  collapses to one entity.) **Paired:** `SOLUTION_TREE` cycle 77 — same commit.

- **2026-06-21** — **Cycle 78 (the password slot is a dumping ground; both parsers
  trusted it).** Stealer/breach `password` fields routinely hold something other than
  a secret — the Ali.kareem logs have `password: [fail]` (a capture sentinel) and
  `password: ayilmazer486@gmail.com` (an email mis-stored in the slot). `oathnet_pro`'s
  plaintext-password gate only rejected the `UPGRADE_TO_SEE`/`REDACTED` *redaction*
  sentinels, so `[fail]` (len 6, varied) was minted as a `Password`; `see_know`'s gate
  was weaker still — bare `!pw.is_empty()`. Worse, the email-in-slot was minted as a
  `Password` by both, which **forges a reused-secret link (AU-047) across every row
  with that capture quirk** and discards a real address lead. The "is this value a
  secret?" decision was unwritten and inconsistent between the two parsers. **Paired:**
  `SOLUTION_TREE` cycle 78 — same commit.

- **2026-06-21** — **Cycle 79 (three text endpoints read their body unbounded).**
  `hackertarget`, `pwned_passwords` and `social_location` fetched plain-text bodies
  with a hand-rolled `resp.text().await.map_err(|e| Error::module(SRC, e.to_string()))`
  — **no size cap** (a hostile/misconfigured upstream could OOM a Termux device under
  the probe fan-out, the exact threat the JSON path already guards with the 32 MiB
  `JSON_BODY_CAP`) and **no credential redaction** in the transport-error path (the
  same leak class fixed in `send_tagged`). The capped reader existed only behind the
  JSON path (`read_json_text`, which also archives) and a *truncating* needle-checker
  (`read_body_capped`); neither fit a text endpoint that must error-not-truncate (a
  truncated Pwned-Passwords hash range would yield a false "not pwned") and must not
  bloat the archive with a generic payload. **Paired:** `SOLUTION_TREE` cycle 79 —
  same commit.

- **2026-06-21** — **Cycle 80 (a broad name search floods the page with stranger
  `candidate` entities — ground-truthed against HSE's own "Ali Kareem" debug
  bundle).** The uploaded HSE run (scan `9daad8…`, target `full_name = "Ali Kareem"`)
  exported an **empty CSV**, and the debug timeline shows why `oathnet_pro` was no
  help: its breach query returned **100 `pureincubation.com` rows — James Perry, James
  Smith, Marina × N, not one of them Ali** — and the page extractor minted **491
  entities** off them, every one a quarantined `candidate` at 0.25. That is ~5
  low-value entities per stranger row: correct in *kind* (the quarantine demotion from
  cycles 76/78 keeps them out of the default view and the correlator) but unbounded in
  *volume*. On a memory-constrained Termux device a single broad `full_name` page can
  therefore balloon the in-memory result with hundreds of strangers whose only purpose
  is a manual spot-check — a sample of a dozen serves that need as well as a hundred.
  The per-row identity match was also buried inside the per-record extractor, where the
  page loop could not see it to make a sampling decision. **Paired:** `SOLUTION_TREE`
  cycle 80 — same commit.

- **2026-06-21** — **Cycle 81 (a scan found 558 entities and exported ZERO — the
  empty-CSV data-loss, root-caused from HSE's own debug bundle).** The "Ali Kareem" run
  emitted **558 `entity_found` events** (oathnet_pro 491, name_intel 46, qld_unclaimed
  17, wikidata 2, social_probe 2) yet the dossier read `entities: 0`, `status: Running`,
  and the CSV was header-only. Root cause, traced end-to-end: entities live only in the
  in-memory `entity_map` and are written to the persisted `entities` table **once, at
  `finalise_scan`**; the CSV/dossier/JSON/API all read that table via
  `entities_for_scan`. The scan never finalised — two modules (`search_engines`,
  `signal_radar`) were still in-flight (radio/curl subprocesses) when the snapshot was
  taken, so `finalise_scan` had not run — leaving the table empty even though every
  finding was *already durably logged* in the real-time `events` table (the `DbWriter`
  actor persists each `EntityFound` the instant it is emitted; the debug bundle
  reconstructs all 558 from it). On Termux/Android — where the OS reclaims backgrounded
  processes and a flaky hardware-I/O module can stall a round for its full timeout —
  *any* interruption (hang, OOM-kill, app backgrounded, or simply exporting mid-scan)
  silently discards the entire result. A 558→0 cliff is the single largest quality
  defect a scan can have. **Paired:** `SOLUTION_TREE` cycle 81 — same commit.

- **2026-06-21** — **Cycle 82 (the headline entity asserted a breach hit the subject
  never had).** `oathnet_pro` always minted the subject as a 0.85 `breach`-tagged
  `Person`, with `countries`/`names`/`genders`/`dates_of_birth` aggregated over EVERY
  returned record — even when ZERO of them matched the subject. The engine pre-seeds a
  subject anchor and a re-emitted subject merges onto it by UID, so for "Ali Kareem"
  this stamped the subject's own headline node with the `breach` tag at 0.85 and dumped
  **56 countries and ~100 strangers' names** (`JAMES PERRY; James Smith; …`) into its
  evidence — from a page in which the subject appeared in *none* of the records. That is
  a fabricated exposure claim plus aggregate pollution merged onto the one node an
  analyst reads first: the precise opposite of an honest dossier, and it survived the
  candidate-flood cap because the parent is built off the whole page, not the per-row
  extraction. **Paired:** `SOLUTION_TREE` cycle 82 — same commit.

- **2026-06-21** — **Cycle 83 (the subject's login IP was dropped on the floor — and a
  private one would have been geo-noise).** The uploaded snusbase combined-search dumps
  carry the subject's login IP ONLY in a `lastip` field (no `ip`): real, public,
  subject-tied addresses like `142.204.244.67` and `37.236.187.22` on
  `ali.kareem95@gmail.com` / `ali.kareem`. Both breach extractors read `ip` alone, so
  the single strongest geolocation lead a breach row offers — where the account actually
  logged in from — was silently discarded for every snusbase-shaped record. Compounding
  it, `see_know`'s IP gate was a bare `ip.len() >= 7`, which would have admitted a
  private LAN address (`192.168.x`, CGNAT) as a `geolocation-lead` — un-geolocatable
  noise — had it read the field at all; the public-IP check existed only as a
  hand-rolled `pub(super)` fn inside `oathnet_pro`. **Paired:** `SOLUTION_TREE` cycle 83
  — same commit.

- **2026-06-21** — **Cycle 84 (the stealer endpoint dropped 100% of leaked
  credentials — wrong response shape).** The uploaded `Stealerlogs` dump for the subject
  is the see-know.eu `/stealer` response: `{ results: 0, victims: [ { log_id,
  credentials: [ { username, password, pwned_at } … ] } ] }` — a `victims[]` array with
  the logins nested one level down under `credentials[]`. The response normaliser
  `extract_items` recognised only the FLAT shapes (top-level array, `/data/items`,
  `/results` as an array, `/data` object); the stealer `results` is the scalar `0`, so
  the `/results` branch (which demands an *array*) falls through, no other branch matches
  `victims`, and the function returns an empty `Vec`. Net: every stealer credential the
  subject leaked — `ali` / `C0R4Pc1` / `Yontem2006` / `03320085` / … across the whole
  `credentials` array — was silently discarded before extraction even began. A stealer
  log's reason for existing is its credential set, and it was the one shape the parser
  couldn't see. **Paired:** `SOLUTION_TREE` cycle 84 — same commit.

- **2026-06-21** — **Cycle 85 (see_know is structurally UNREACHABLE on Termux — the
  paid source is killed before it can answer, every run).** see_know's `/search` has a
  ~55 s server-side cap and routinely answers in 50–60 s; the whole module is sized for
  that (curl 75 s < outer 78 s < module `max_timeout_ms` 80 s). But the engine's flat
  `TERMUX_MODULE_TIMEOUT_CAP_MS` (45 s) clamps EVERY module on Termux without a user
  override, and `termux_timeout_ms()` can only trim *below* the cap — there is no path
  above it. So on Termux/aarch64 — the platform HSE exists for, and exactly where the
  debug bundle ran (`termux: detected`, see_know `module_error: timeout` at precisely
  45 s) — see_know is aborted before the upstream ever responds, returning ZERO data on
  every phone scan. The operator's explicitly-enabled, highest-priority paid source is
  silently wasted, and because paid modules run serially in Phase 1 (key-discovery-first)
  the 45 s isn't just lost — it blocks the free fan-out behind it. Worse, cycles 83–84
  (lastip capture, victim-credential flattening) parse see_know data that, on the target
  platform, never arrives. The cap's own doc claimed 45 s "clears every legitimately-long
  module's happy path" — it never accounted for a module whose happy path is the server's
  own 55 s processing time. **Paired:** `SOLUTION_TREE` cycle 85 — same commit.

- **2026-06-21** — **Cycle 86 (the subject's demographics were captured but never
  surfaced or normalized).** see_know's `record_evidence` folds *every* record field onto
  the evidence chain, so DOB / gender / age technically survive — but only as raw,
  provider-keyed evidence attributes (`date_birth`, `birthdate`, `gender: "Male"`),
  inconsistently spelled across providers and buried beneath the entity. The headline
  `Person` node carries only the name; nothing promotes the demographics that actually
  anchor an identity to a first-class, queryable form, and a `gender:M` from one record
  can't fold with a `gender:male` from another because neither is normalized. The data is
  present in the dossier but an analyst has to dig per-record evidence to reconstruct what
  should read straight off the subject. **Paired:** `SOLUTION_TREE` cycle 86 — same commit.

- **2026-06-21** — **Cycle 87 (see_know minted same-name strangers as the subject — no
  target-match quarantine, and the matcher was unshared).** `oathnet_pro` demotes a
  breach row that does not identify the subject to a quarantined `candidate` lead
  (cycles 76/82) via its `TargetMatch`; `see_know` had **no such gate** — it emitted
  every record's email / username / person / phone / credentials at full 0.65–0.75
  confidence regardless of whether the row was the subject. A broad see_know name
  auto-detect that returns same-name strangers (a different "Ali Kareem", a namesake
  relative) therefore minted them AS the subject — the identical false-confidence flood
  oathnet had already fixed, now in the *primary* paid pool that cycle 85 just made
  reachable. Underneath it was a consolidation gap: the `TargetMatch` logic (and the
  `CANDIDATE_CONF` ceiling) lived only inside `oathnet_pro`, so the two breach pools
  judged "is this row the subject?" by different code — one had the answer, the other had
  none. **Paired:** `SOLUTION_TREE` cycle 87 — same commit.

- **2026-06-21** — **Cycle 88 (a less-geocodable address and provider-plumbing leaking as
  entities).** Two address/identity quality gaps surfaced by the dumps. **(a)** `oathnet_pro`
  composed its physical `Address` from `[street, city, state]` ONLY — dropping the
  `postal_code` the breach record carries (`23666` for HAMPTON, VA). A postcode-less
  address geocodes to the whole city instead of the ZIP centroid, throwing away the
  precision the downstream geocode + AU/geo-correlation chain runs on; the ZIP sat on the
  evidence, unused for placement. `see_know` already composes the full street→postal→
  country address, so the two pools emitted addresses at different precision from the same
  record shape. **(b)** `see_know`'s maximum-raw-data `rich_detail` pass turns every
  un-skipped scalar into an entity, but its skip list missed the **provider-internal record
  IDs** snusbase stamps on every row — `uid` and `migration_id` (the provider's own database
  keys, not the subject's) — so each record minted two `Other(...)` junk nodes, diluting the
  graph with plumbing that reads like intelligence. **Paired:** `SOLUTION_TREE` cycle 88 —
  same commit.

- **2026-06-21** — **Cycle 89 (the candidate-demotion was duplicated, and matching was
  tangled with tiering).** "Quarantine a non-matching record" — *cap confidence to 0.25
  and stamp the `candidate` tag* — was hand-written in THREE places: `oathnet_pro`'s
  `push_oathnet_entity` (inline per push), and `see_know`'s batch range-pass plus its
  trailing-domain push. Three copies of the same two lines, free to drift. Worse, the
  ceiling constant `CANDIDATE_CONF` lived in `util::target_match` — a module whose entire
  job is to answer *"does this row identify the subject?"* It never used the constant; the
  constant was only consumed by the callers doing the demotion. So a **matching** capability
  and an **entity-tier** capability were fused in one module, and the tier ceiling sat far
  from the confidence/tier model it belongs to (`core::entity`, beside `VERIFIED_MIN` /
  `PROBABLE_MIN`). Two orthogonal capabilities, neither cleanly owned. **Paired:**
  `SOLUTION_TREE` cycle 89 — same commit.

- **2026-06-21** — **Cycle 90 ("breached real-estate exclusively" had no mechanism — yet
  the real data already encoded the answer).** An AU-focused investigation wants to filter
  a scan to property/real-estate exposure, but the breach pools offered no way to do it:
  every hit carried its source database name (`dbname` / `source`) on the evidence, and
  nothing ever read it to classify the breach's *sector*. The signal was sitting unused.
  And working backwards from the actual "Ali Kareem" dumps shows it was *legible*: snusbase
  source DBs embed a category token — `0645_ZYNGA_COM_202M_GAMING_092019`,
  `1769_AITYPE_COM_75M_TECH_122017` (real values) follow
  `<id>_<NAME>_<TLD>_<SIZE>_<CATEGORY>_<MMYYYY>` — while oathnet sources are brand domains
  (`pureincubation.com`, a B2B data broker that must NOT be mislabelled as property). So
  the question "show me only the breached real-estate data" was answerable from data
  already in hand, and simply wasn't being asked of it. **Paired:** `SOLUTION_TREE` cycle 90
  — same commit.

- **2026-06-21** — **Cycle 91 (the sector capability was bolted onto two files, not wired
  to the engine).** Cycle 90 stamped `sector:<x>` per-module, in `oathnet_pro` and
  `see_know` only — but HSE has ~9 breach pools. `hibp`, `dehashed`, `intelx`,
  `hudsonrock`, `niamonx`, `osintcat`, `xposed_or_not` all tag `breach` and carry a source
  DB on their evidence (HIBP's `breach_name`/`breach_domain`, dehashed's `database`, …),
  yet none were sector-classified — so "breached real-estate exclusively" silently covered
  two pools and missed the rest. And the per-module shape doesn't scale: each current and
  future breach module would have to re-implement the same tag against its own source-field
  key, the exact per-site duplication the consolidation arc has been removing. The sector
  signal wasn't a *capability the engine applies*; it was two copies of a snippet. **Paired:**
  `SOLUTION_TREE` cycle 91 — same commit.

- **2026-06-21** — **Cycle 92 (sector classification had near-zero recall on the real
  corpus — proven by a live run).** A live scan of the real subject (`hse scan --kind
  full_name -v "Ali Kareem"`) returned 608 entities and **zero** `sector:` tags. Root cause,
  read straight off the data: `util::breach_sector::source_sector` only resolved (a)
  real-estate keywords and (b) snusbase *structured* tokens (`…_GAMING_…`) — and the
  structured-token pool (`see_know`) was **down (HTTP 523)** that run. Every other pool
  surfaces **bare brand names** — `oathnet` source domains (`neopets.com`, `dlh.net`,
  `tunngle.net`, `r2games.com`, …, overwhelmingly *gaming*) and `xposed_or_not`/`osintcat`
  `breach:<name>` tags (`zynga`, `tumblr`, `linkedin`, `adobe`, `myfitnesspal`) — none of
  which embed a category, so they all classified as `None`. The dominant true signal for
  this identity ("heavily a gamer") was discarded. Two compounding gaps: the classifier had
  no brand→sector knowledge, AND the cycle-91 pass never read `osintcat`'s dynamic
  `breach_<name>` keys or `xposed_or_not`'s comma-joined `breaches` list, so even a
  brand-aware classifier wouldn't have seen them. **Paired:** `SOLUTION_TREE` cycle 92 —
  same commit.

- **2026-06-25** — **Merge divergence with `origin/main` (a second batch of commits landed
  mid-flight).** While PR #207 ran cycles 1–45, `main` independently reshaped the same
  regions: the flat `core/correlator/rules/geo.rs` was split into a `geo/` subdirectory
  (`chain.rs`/`cluster.rs`/`jurisdiction.rs`/`profile.rs`), the rule id **AU-078 was
  reassigned** to a new `rule_au_078_hub_entity` in `identity/account.rs`, the
  `api/scan_handlers` god-module was broken into submodules, and
  `util/diagnostics/analyse.rs` switched its multi-source convergence test to a haversine
  distance. This branch had concurrently added `rule_au_078_cell_tower_dual_source` (a
  now-colliding id), `wants_infra` in `scan_handlers`, and the co-ownership builder —
  yielding 4 content/modify-delete conflicts. After the textual resolution, a single stray
  blank line at `scan_handlers/mod.rs:94` failed `cargo fmt --check`, halting the `check`
  CI job at its very first step before clippy/doc/test ever ran. **Paired:** `SOLUTION_TREE`
  — same commit.

- **2026-06-25** — **A 1.96-only clippy lint surfaced once the earlier gates cleared.** With
  `audit` and `fmt` previously aborting CI before clippy could run, the branch's 45 cycles of
  code had **never** completed a `clippy -D warnings` pass under CI's newer toolchain (1.96 vs
  the local 1.94). The first clean run flagged `clippy::map_unwrap_or` at
  `util/key_vault/mod.rs:213` (`.map(|n| n as u64).unwrap_or(0)`) — a lint absent from the
  local toolchain, exactly the CI/local skew CLAUDE.md warns about. Clippy reported "1 previous
  error", confirming it was the sole crate-wide violation. **Paired:** `SOLUTION_TREE` — same
  commit.

- **2026-07-01** — **T2.11's LOW bounded-over-dispatch closed.** The concurrent
  dispatcher's Phase-2 spawn loop now non-blockingly drains (`JoinSet::try_join_next`)
  any sibling module that finished since the last check, at the TOP of every loop
  iteration, so the `max_entities` cap reads a live `entity_map.len()` instead of the
  snapshot from before this target's spawn loop began. A new `absorb_dispatch_outcome`
  helper is shared by that interleave and the trailing blocking `join_next` drain, so
  a joined result is finalised exactly once regardless of which loop collects it.
  Regression test `concurrent_dispatch_stops_near_max_entities_not_after_the_full_module_set`
  (10 accepting modules, `max_concurrent: 1` to force the interleave deterministically,
  `max_entities: Some(1)`) proven to fail against the unfixed code (all 10 modules
  dispatched) and pass against the fix. T2.11 stays `[~]` — the budget-static
  `reset_scan`-zeroing sub-item is untouched by this change. **Paired:**
  `SOLUTION_TREE` SOL-LIVE-DISPATCH-BUDGET (new) `[x]` + §3/§4/§5 — same commit.

- **2026-07-01** — **S→P audit: C5's "provenance radius output" was already
  delivered; the node text just never caught up.** No node in §3/§4 had a small,
  safe, code-grounded next increment ready this cycle — §3.F's `bstr` remainder
  is explicitly blocked on a natural consumer that doesn't exist yet, and T2.7's
  golden-fixture work needs either a live fetch against a third-party site or a
  fixture that would only *look* real, both wrong for an unattended cycle — so
  this cycle re-read C5 against the actual shipped code instead of trusting its
  own "remaining" line. Two deliveries were already in `main`: cycle 29
  (2026-06-20) added `SynergyFix::radius_km` to AU-059's synergy fix (its own
  `SOLUTION_TREE` log entry already said "delivered end-to-end," but this node's
  text was never edited to match), and `d1507539` (2026-06-26) shipped
  `best_au_location_estimate` — a 6-rung fallback giving every AU-located scan a
  headline fix, not just the multi-source case — with a `CHANGELOG.md` entry
  that was never cross-referenced back into this tree. Corrected in place, with
  commit provenance; the real remaining legs (AU-059 using `weighted_centroid`
  instead of the more robust `weighted_geometric_median` already proven
  elsewhere in the codebase, AU bounding precision, movement/timeline geo) are
  kept exactly as they were. No code or test change; the CLAUDE.md gate was
  re-run anyway and is clean, as expected for a docs-only diff. **Paired:**
  `SOLUTION_TREE` SOL-GEOINT (§2) + §5 — same commit.

- **2026-07-01** — **C5's last flagged gap closed: AU-059 now uses the
  Weiszfeld geometric median, not a plain centroid.** The previous cycle's
  audit had explicitly named this the one real remaining leg of "Weiszfeld/
  Welzl centroid fusion" — AU-057 and `diagnostics::cluster_coordinates`
  already used `weighted_geometric_median`, but AU-059 (the function that
  actually drives the dossier's headline "Best location estimate" line) still
  used the plain `weighted_centroid`. Swapped it in, with the established
  centroid fallback for the rare non-convergent case. New regression test
  `au059_synergy_fix_resists_a_single_high_confidence_outlier`: 2 agreeing
  Sydney-area classes (64% of confidence-weighted mass) vs. 1 higher-confidence
  Perth outlier (36%, below the median's 50% breakdown point) — the median
  stays anchored near Sydney (lon>145) where the old centroid landed a third
  of the way to Perth (lon≈138.6, verified by computing the plain centroid
  directly in the same test for comparison). Proven against both directions:
  fails on the pre-fix code (identical lon≈138.6 to the plain centroid) and
  passes on the fix. Every pre-existing AU-052/AU-059/scan_export geo test
  still passes unchanged — they all use tolerant range assertions against
  tightly-clustered real-shaped fixtures where the two estimators don't
  meaningfully diverge, so this is a real precision improvement, not a
  behaviour change any existing test could have caught. Gate green: 4259 lib
  tests, fmt/clippy `--all-targets`/doc clean. **Paired:** `SOLUTION_TREE`
  SOL-GEOINT (§2) + §5 — same commit.

- **2026-07-01** — **T2.13 (new): the dossier's "ROI" wasted-spend hint was
  structurally dead code — found and closed same-cycle.** With T2.7's
  golden-fixture work blocked (needs either a live third-party fetch or a
  fabricated-looking fixture, wrong for an unattended cycle) and no other
  small open increment ready, this cycle's discovery pass (step 1d) read
  `cli/scan/dossier.rs`'s ROI hint against `util::diagnostics::analyse` and
  found the filter's premise unsatisfiable: `modules_by_yield` is built only
  from emitted entities, so a module that ran and found nothing is *absent*,
  never present-at-zero — the hint's `entities_emitted == 0` filter could
  never match anything, on any scan, ever. A live `hse scan --output dossier`
  confirmed it empirically before AND after the fix: pre-fix, 41 of 42
  dispatched modules (11 of them `KeyGated`/`Paid`, several timed out) were
  invisible to the yield table and the ROI line never printed; post-fix, the
  same scan re-run correctly prints all 11. New pure
  `zero_yield_keyed_or_paid_modules` reads the durable per-scan `ModuleDone`
  events instead — 4 new unit tests (flags a zero-yield paid module, ignores
  one that found something, ignores a zero-yield *free* module, output
  sorted/deduped). `print_dossier` picked up an 8th parameter to carry the
  store handle needed to read those events; bundled into a `DossierArgs`
  struct rather than `#[allow(too_many_arguments)]`, matching T2.5's
  `DispatchCx`/`DispatchState` precedent. Gate green: 4263 lib tests (+4),
  fmt/clippy `--all-targets`/doc clean; live CLI run verified both before and
  after. **Paired:** `SOLUTION_TREE` new node (§2 S.QUALITY) + §3/§5 — same
  commit.

- **2026-07-01** — **T2.13 addendum + new T2.14: the same dead-hint root
  cause existed twice more inside `analyse()` itself.** Re-reading the whole
  `optimization_hints` block that produced the ROI-hint bug (not just the one
  bug already fixed) found two more conditions keyed on the identical
  unreachable `entities_emitted == 0` premise, structurally impossible for
  the same reason. Removed both as confirmed-dead, misleading code rather
  than leave them implying a capability that cannot fire; did NOT mechanically
  restore them, because (a) `analyse()`'s pure signature can't reach the
  `StoragePort`-sourced events a correct fix needs without either a
  16-call/test-site signature change or duplicating the caller-side fetch,
  and (b) the per-module variant has a genuine, unresolved noise problem a
  live 42-module scan makes concrete — firing one line per ordinary zero-yield
  module would flood the hints list, the opposite of the signal the hint
  exists to give. Logged as new open **T2.14** (P3, advisory-only) with the
  concrete design options rather than force-fit either half this cycle.
  Renamed `analyse_emits_optimization_hints_for_zero_yield` →
  `analyse_falls_back_to_a_hint_when_nothing_else_fires` (the old name
  overclaimed what it verified). Gate green: 4263 lib tests (unchanged count —
  a removal + a rename), fmt/clippy `--all-targets`/doc clean; live CLI dossier
  output re-verified unaffected. **Paired:** `SOLUTION_TREE` SOL-ROI-HINT
  addendum + new SOL-HINT-NOISE (§2) + §3/§5 — same commit.

- **2026-07-01** — **S→P audit: `SOLUTION_TREE` §4a's "AU-060-candidate"
  cell-tower cross-validation gap (logged here at cycle 20, line ~1835) was
  stale.** `opencellid` × `cell_intel` `DeviceId` cross-validation shipped
  2026-06-30 (`770df4c9`) as **AU-084** — "Dual-source cell tower
  corroboration" (`rules::geo::cluster::rule_au_084_cell_tower_dual_source`),
  registered + 4-tested — one day before this note would otherwise still have
  called it unstarted. The originally-proposed number, `AU-060`, was also
  separately reassigned to "Transitive identity closure" in the interim, so
  the note doubly no longer matched reality. No PROBLEM_TREE node existed for
  this gap (it lived only in `SOLUTION_TREE` §4a); corrected there. Verified
  by reading the shipped rule + its dispatch registration + its tests, and
  `git log -S` for the delivery commit — not by inference. **Paired:**
  `SOLUTION_TREE` §4a + §5 — same commit.

- **2026-07-01** — **S→P audit: a fourth stale note — `hse update --check`
  already prints commit subject lines, not just a count.** Continuing the
  same sweep that found AU-084, `SOLUTION_TREE`'s SOL-UPDATE node and its
  twin §4a entry both still claimed `--check` shows a bare commit count; in
  the actual source, `cli/update.rs::changelog_lines` already runs `git log
  --oneline HEAD..@{u}` and `cmd_update` already prints up to 20 of its lines
  under the count. **Caveat this note gets right that the AU-084 one
  couldn't:** this repository's history starts at a single root commit
  (`770df4c9`, 857 files / 244,800 lines, no parent — an import), so no
  specific delivery cycle can honestly be attributed here via `git log`;
  worded the correction accordingly instead of implying a dated delivery.
  Genuine residual noted, not silently dropped: `changelog_lines`/
  `commits_behind` are untested against real `git` subprocess behaviour —
  `tempfile` (already a dev-dep) would support a local-repo-pair fixture,
  left as its own smaller follow-on. **Paired:** `SOLUTION_TREE` SOL-UPDATE +
  §4a + §5 — same commit.
- **2026-07-04** — **MITRE mapping precision: `subdomain_takeover` was labelled
  passive when it actively scans for a vulnerability.** Grounded audit of the
  active-collection modules' ATT&CK overrides (the operator-endorsed inline
  per-finding `attack:<ID>` tags are HSE's only MITRE surface — cycles 49/52 —
  so a wrong mapping mis-labels every finding it produces). `subdomain_takeover`
  resolves a dangling CNAME and HTTP-fingerprints the target to prove a cloud
  resource is claimable — an exploitable misconfiguration it emits as a
  `vulnerable` `Domain` (`build_entities`, `mod.rs:47-50`) — but mapped to the
  passive `T1590.001` *Domain Properties* the `DnsRecon` default inherits. That
  is Active Scanning, not passive metadata gathering. Added the missing
  catalogue entry **`T1595.002` Vulnerability Scanning** (`core::attack`,
  between `T1595.001` and `T1596`, keeping the id-sorted invariant) and remapped
  the module to it — mirroring `portscan`, the existing active-scanner override.
  `T1590.001` stays live (`typosquat` + the `DnsRecon` default still reference
  it), so nothing is orphaned. The audit confirmed the other active modules are
  already precise (`dns_axfr`→`T1590.002`, which ATT&CK itself lists zone
  transfers under; `waf_detect`→`T1590.006`+`T1596.004`; `api_key_probe`→
  `T1589.001`; `portscan`→`T1595`+`T1595.001`) — one genuine mislabel, not a
  sweep. Test delta: guard `attack_overrides_attribute_collection_modules_
  precisely` now pins `["T1595.002"]` (fails against the old `["T1590.001"]`),
  plus `active_scanning_family_is_catalogued` pins the new technique (fails when
  the catalogue lacked it). Gate green: fmt/clippy/doc clean, lib + integration
  tests 0 failures, arch guards incl. ATT&CK mapping + catalogue drift.
  **Paired:** `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **Correlator precision: two rules forged false identity links
  from non-personal selectors** (found by a grounded false-positive audit of the
  association/co-location rule family; both confirmed against current code, both
  the exact FP class this evidentiary engine ranks above missing coverage).
  **(1) AU-018** (`geo/profile.rs:3`, email↔location) gated the email side only
  on `kind == Email && confidence >= 0.60`, so a role/provider mailbox
  (`abuse@godaddy.com` from a WHOIS/RDAP registrant emitter) co-located with the
  subject's address as an "identity-location linkage" — the same FP AU-001/AU-045
  were patched for. Now applies the existing `core::validation::is_role_mailbox`
  gate (single-sourced with AU-001/AU-045/AU-002, no new vocabulary). **(2)
  AU-050** (`assoc.rs:283`, shared-phone associate cluster) grouped persons by
  `normalise_phone` digits with no line-type check — a shared `1800`/`13`/`1300`/
  `190x` business/service line (which `normalise_phone` happily keys, being a
  >=8-digit non-uniform run) linked unrelated people as "associates; a direct
  pivot to reach the subject." Now skips a group whose key classifies as
  `AuLineType::is_business_service` via the existing `au_phone_line_type`; a
  personal mobile/geographic line still links, non-AU numbers are unchanged (the
  AU classifier returns `None`), so no false negatives. Test delta:
  `au018_excludes_role_mailboxes_from_the_identity_location_link` and
  `au050_excludes_shared_business_and_service_lines` (each asserts the FP is gone
  *and* the true-positive still fires — fail-before/pass-after). Gate green:
  fmt/clippy/doc clean, 406 correlator lib tests + 30 arch guards, 0 failures.
  **Paired:** `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **Parse precision at the source: the two non-regex email
  admission paths were more permissive than the canonical `EMAIL_RE`** (found by
  a grounded false-positive audit of `util::extract`; the validator layer is
  otherwise excellent — ABN mod-89, ACN complement, the AU phone trunk guard all
  verified correct). `EMAIL_RE` (`extract/mod.rs:26`) requires a real TLD
  (`…\.[A-Za-z]{2,}`), but `looks_like_email` (the provider-`email`-field gate)
  only tested `host.contains('.')` and `page_emails` (the HTML byte-scanner) only
  `contains('.') && len > 3`. So `admin@10.0.0.1` (IP literal), `user@host.123`
  (numeric pseudo-TLD), `user@host.c` (1-char TLD) and `x@sub..example.com`
  (double-dot host) all minted a bogus `Email` entity — a false positive at the
  parse layer, which then compounds through every downstream correlation. Both
  paths now share one `host_has_alpha_tld` helper enforcing exactly the regex's
  domain validity (≥1 dot, no empty label, final label ≥2 ASCII letters), so a
  gate can never out-admit the scanner it is supposed to mirror. No valid address
  is newly rejected (every real address has an alphabetic TLD; the existing
  gmail/yahoo/`onet.eu` fixtures still pass). Test delta: the
  `looks_like_email_rejects_provider_field_junk` junk list gains the four invalid
  shapes (+ an `EMAIL_RE`-agreement cross-check), and
  `page_emails_rejects_ip_literal_and_numeric_tld_domains` pins the scanner path
  (each asserts the FP is gone and a real address in the same text still
  extracts). Gate green: fmt/clippy/doc clean, full suite 0 failures.
  **Paired:** `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **Parse precision cont'd: `extract::macs` carved a spurious
  48-bit MAC out of a longer EUI-64/hex run** (same `util::extract` FP-at-source
  audit as the email fix). `MAC_RE` is `\b`-anchored, but the separator after the
  6th octet satisfies the trailing `\b`, so an 8-octet identifier
  `aa:bb:cc:dd:ee:ff:00:11` (and the hyphen form) yielded a bogus
  `aa:bb:cc:dd:ee:ff` — a fabricated `MacAddress`/BSSID that `mylnikov`/`wigle`
  would then *geolocate* as a real router, injecting a phantom location signal.
  Rust's regex has no look-around, so the fix post-filters in `macs`: a match
  flanked by `<sep><hex>` (another octet immediately before — `2 hex + sep` — or
  after — `sep + hex`) is a fragment of a longer identifier and is dropped;
  bytes are ASCII so the edge indexing is boundary-safe. A genuine standalone MAC
  still extracts, including when wrapped in non-separator punctuation
  (`(aa:bb:cc:dd:ee:ff)`), and the existing space/`\n`-delimited fixtures are
  unaffected. Test delta: `macs_does_not_carve_a_48bit_mac_out_of_a_longer_eui64
  _run` pins both an 8-octet colon and hyphen run to empty *and* the
  punctuation-wrapped true positive (fail-before/pass-after). Gate green:
  fmt/clippy/doc clean, full suite 0 failures. **Paired:** `SOLUTION_TREE` §5 —
  same commit.
- **2026-07-04** — **GEOINT precision: AU state attribution was misclassifying
  border towns via overlapping first-match boxes** (the highest-leverage geo bug
  surfaced by the discovery pass; deferred one cycle so it could be done with a
  measured city fixture rather than guessed). `au_state_for_coords`
  (`util/geo/mod.rs`) tested overlapping rectangular state boxes in fixed order
  and returned the FIRST hit. QLD's box (`lat −29.18..−10`) and NSW's
  (`−37.51..−28.16`) overlap in `−29.18..−28.16`, and QLD was tested first — so
  Lismore (NSW, −28.81, north of the 29°S line but south of the coastal-border
  dip) and Goondiwindi read as QLD. NSW's box and VIC's (`−39.20..−33.98`) overlap
  in `−37.51..−33.98`, NSW first — so northern-Victorian towns (Shepparton,
  Wodonga) read as NSW. Replaced the overlapping-box scan with a **border-accurate
  partition**: the mainland is cut by Australia's real borders — the exact
  meridians `129°E`/`138°E`/`141°E` and the `26°S` parallel (all straight,
  authoritative), plus a piecewise-linear fit to the two non-straight borders
  (`qld_nsw_border_lat`: 29°S rising to ~28.2°S at Point Danger; `nsw_vic_border_lat`:
  the Murray's real meandering course through 11 anchors, then the surveyed
  Cape-Howe segment). ACT enclave and the Bass-Strait-isolated TAS box handled
  first. No caller depended on the old behaviour (all consume the state as a label
  or gate — e.g. `qld_cadastre` gates on `!= Some("QLD")` — so a more-correct
  answer only helps). Test delta:
  `au_state_for_coords_is_border_accurate_across_states` — a 40-town fixture
  spanning every state, weighted to the previously-broken bands, that both fixes
  the gross bugs and splits river-twin pairs (Mildura VIC/Wentworth NSW ~7 km,
  Wodonga VIC/Albury NSW ~4 km) correctly — the strongest evidence the border is
  real, not a box. Fails hard against the old code (Lismore→QLD, Shepparton→NSW),
  passes against the fit; the capitals test is unchanged. Gate green: fmt/clippy/
  doc clean, geo unit + doctest + full suite 0 failures. **Paired:**
  `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **Parse precision + de-duplication: IBAN validation ignored the
  ISO 13616 registered length, in two drifting copies.** `extract::ibans`/
  `iban_mod97_valid` (`util/extract/mod.rs`) and the duplicated
  `oathnet_pro::validate::iban_is_valid` both admitted any mod-97-valid string of
  length `15..=34` regardless of the country's fixed IBAN length — so a
  right-checksum wrong-length string (≈1/97 of a wrong-length run with a real
  country prefix) minted a phantom leaked bank account. Fixed by single-sourcing:
  a new `util::extract::iban_is_valid` pins the `CCkk` layout, the **registered
  per-country length** (an `iban_country_length` table of the ~80 ISO 13616
  countries; an unregistered code falls back to the `15..=34` spec range, so a
  registry addition is never a false negative), and the mod-97 checksum;
  `oathnet_pro` now delegates to it (drifting duplicate removed, mirroring its
  existing `pub(super) use …::looks_like_email` pattern). Layering holds (modules →
  util). Test delta: `iban_is_valid_enforces_registered_country_length` constructs
  a mod-97-valid GB string of the wrong length (18 ≠ 22) via the ISO check-digit
  formula and asserts the checksum passes (so the *length* gate is what rejects
  it — the fail-before/pass-after) while a correctly-sized GB and an
  unregistered-CC fallback still validate. Gate green: fmt/clippy/doc clean, lib +
  integration 0 failures (194 oathnet_pro tests unaffected by the delegation).
  **Paired:** `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **Robustness/reliability: durable + concurrency-safe atomic
  writes (two gaps, one on the most sensitive file).** Found by the resource-bounds
  audit; the storage layer is otherwise strong (uniformly capped body reads,
  `catch_unwind` module containment, SSRF gates). **(1)** `util::atomic_file::write`
  fsynced the temp file's *data* (`f.sync_all()`) but never the *parent directory*
  after `std::fs::rename` — so the rename (the directory entry now pointing `path`
  at the new inode) was not itself durable: a power-cut/OOM-kill right after rename
  returned can, on ext4/f2fs, lose it and leave the OLD file. Added a best-effort
  parent-directory fsync after every successful rename (unix; swallowed so it can
  never fail an otherwise-good write). Benefits every persisted store (settings,
  key_pool, dossiers). **(2)** The `~/.huntsman.env` **API-key vault**
  (`util/keys/io.rs::write_keys_at`) was a hand-rolled copy of the atomic-write
  dance with a **fixed** temp (`path.with_extension("env.tmp")`) — so two concurrent
  writers to one `$HOME` (overlapping scans harvesting keys; a `PUT` toggling a key
  mid-scan) both opened, truncated and interleaved into the *one* temp and could
  rename a corrupt/empty file over the vault, which the loader reads as "no keys"
  (silent total key loss). Routed it through `atomic_file::write` (unique pid+seq
  temp → self-contained writes; also inherits gap-1's durability and single-sources
  the logic; the now-dead `use std::io::Write` dropped). Layering holds (util→util).
  Test delta: `concurrent_vault_writes_never_corrupt_or_strand` — eight threads
  hammer one vault and assert it always stays a readable file holding the key, with
  no temp straggler (mirrors `atomic_file`'s own concurrency property test; fails
  against the fixed-temp code, passes against the shared writer). The existing
  key-vault round-trip/append/validation tests exercise the new path unchanged.
  Gate green: fmt/clippy/doc clean, lib + integration 0 failures. **Paired:**
  `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **MITRE mapping precision (operator-directed): a full-registry
  ATT&CK audit of all 160 modules, two genuine mis-mappings fixed.** Extracted
  every module's category + `attack_techniques()` and reviewed each against what
  the code actually collects; the layer is mostly precise (108 overrides already
  guard-pinned), and this pass corrects the two that were not. **(1) `dns_intel`**
  mapped only to DNS (T1590.002), but its `brute::brute_subdomains` iterates a
  146-label common-name dictionary resolving each candidate — active infrastructure
  probing from a wordlist, i.e. Active Scanning: **Wordlist Scanning (T1595.003)**,
  a technique the module performs but the catalogue lacked. Added T1595.003 to
  `RECONNAISSANCE` (after T1595.002, id-sorted) and mapped dns_intel to
  `["T1590.002", "T1595.003"]`. **(2) `opencellid`** claimed **DNS/Passive DNS
  (T1596.001)** despite querying the OpenCelliD *cell-tower* database with no DNS
  call anywhere in `process` — a wrong sub-technique. Dropped it, leaving the
  honest `["T1591.001", "T1596"]` (there is no cell-database sub-technique, so it
  stops at the T1596 parent). Both keep MITRE *inline on the data* (the settled
  cycle-49/52 doctrine) — no separate report. The bar for change was "the module
  demonstrably performs / does not perform the technique," so debatable
  conventions (the Infrastructure family's loose `T1591.002` ISP-as-business-
  relationship tag) were left untouched. Test delta: the precise-override guard
  now pins `dns_intel → [T1590.002, T1595.003]` and `opencellid → [T1591.001,
  T1596]` (each with a `contains`/`!contains` cross-check), and
  `active_scanning_family_is_catalogued` pins T1595.003; the
  `every_module_maps_to_valid_attack_reconnaissance_techniques` catalogue-drift
  guard confirms T1595.003 is now catalogued and referenced (not dead). Gate
  green: fmt/clippy/doc clean, lib + integration 0 failures incl. all ATT&CK
  guards. **Paired:** `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **Comprehensive audit (operator: "critically analyse and repair
  every element"): 6-subsystem parallel read-only audit, repairs shipping as
  gated cycles.** Fanned out auditors over web/API, export/serialization, engine/
  dispatch, storage/DB, HTTP/networking, and 10 complex module parsers; each
  verified findings against live code. Most subsystems are sound (no SQL
  injection, XSS, data races, determinism holes in export, or reachable parse
  panics). ~20 genuine defects surfaced, tracked and repaired in priority order.
  **Cycle 1 — storage resource-bounding.** The `raw_archive` inter-scan cache
  (`storage/archive.rs`) deleted nothing: expired rows were ignored on lookup but
  never removed, and there was no row cap — so a long-lived process scanning many
  distinct `(module, target)` pairs grew the table + DB/WAL without bound on a
  low-disk phone, the exact class `events`/`prune_events` guards. Added
  `Store::prune_raw_archive` (+ `StoragePort` default no-op) deleting past-TTL
  rows then capping to the newest `RAW_ARCHIVE_MAX_ROWS = 20 000`, wired at both
  `prune_events` call sites (startup `cli/mod.rs`, scan boundary `engine/mod.rs`).
  Also corrected the `low_confidence_evidence` doc, which asserted a `confidence`/
  `observed_at` index that deliberately does not exist (the method has no
  production caller, so an index would only tax every upsert — the honest fix is
  the doc, not a speculative index). Test `prune_deletes_expired_rows_and_caps_to
  _newest` (timing-independent: asserts the expiry + cap, not which rows survive).
  Gate green: fmt/clippy/doc clean, 81 storage tests + full suite 0 failures.
  **Paired:** `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **Comprehensive audit cycle 2/N: serve-layer security
  hardening (HIGH — CSRF) + two smaller serve fixes.** The web-audit found the
  layer otherwise strong (no SQLi, XSS, panics, determinism holes; DNS-rebind
  Host-allowlist correct) but with a genuine **CSRF** gap: every *bodyless*
  state-changing `POST` is a CORS simple request (no preflight), and only
  `scans/import` carried the `X-HSE-CSRF` guard — so a page in the operator's
  browser could cross-site drive `/update/trigger` (binary self-update +
  `exec()`), `/radar` + `/radar/live` (activate the phone's WiFi/BT/cell/GPS
  sensors — a privacy action), and `/scan/auto[/sweep]` (quota burn), plus
  `/scans/{id}/cancel|rerun`. The Host-allowlist only defeats DNS rebinding and
  CORS only blocks *reading* the response, not the side effect. Fixed with an
  `enforce_csrf` middleware on the whole `/api` router requiring `X-HSE-CSRF` on
  every mutating method (the one header a cross-site simple request can't set
  without triggering the preflight strict CORS rejects); the SPA gained a global
  `fetch` wrapper injecting it on all mutating calls, and the API test helpers +
  inline mutating requests send it. Two smaller items in the same cycle:
  `GET /api/v1/logs` (the TRACE ring buffer — scan targets + PII) lacked the
  `is_loopback()` gate its peer operator endpoints carry (added, so a LAN bind
  no longer streams it), and `scan_auto_sweep` de-duped targets on the per-call
  *unique* `scan_id` (a silent no-op) — now keys on `(kind, value)`. Test delta:
  `bodyless_mutating_post_requires_csrf_header` (a bodyless POST is 403 without
  the header, reaches the handler with it) + the existing
  `scan_import_requires_csrf_header` now also exercises the middleware; the
  `/logs` test injects a loopback peer and asserts a LAN peer is 403. Gate green:
  fmt/clippy/doc clean, 90 API tests + full suite 0 failures. **Paired:**
  `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **Comprehensive audit cycle 3/N: no-fabrication gates on three
  breach/stealer pools (HIGH — subject-attributed exposure claims).** The breach
  audit found three sources minting subject-attributed findings without proving
  the record identified the subject — the exact false-positive class the
  `TargetMatch` quarantine and `oathnet_pro`'s `breach_parent_entity` gate already
  guard against elsewhere. **(1) DeHashed** (`build_breach_entity`): pushed a 0.88
  `breach` headline onto the engine's pre-seeded subject anchor from *any*
  non-empty response, so a broad `name:` query (which returns same-name STRANGERS)
  merged a false breach hit + aggregate. Now returns `Option`: the loose `name`
  selector requires ≥1 target-matching row and counts/aggregates over those rows
  only; the identity-exact selectors (`email`/`username`/`phone`/`ip`/`domain`)
  match `value` exactly so the server `total` stays honest (incl. a count-only
  response). **(2) IntelX**: `username`/`full_name` run as an *unscoped text
  search* (a hit = a document merely contains the term), yet a `leaks` bucket
  stamped `breach` + `password-at-risk` on the subject anchor — a fabricated
  credential-exposure claim from a stranger's paste. New pure `exposure_tags(is_text_search, families)`
  withholds the strong exposure tags for text searches (neutral `intelx-source:*`
  only), and the entity rides at 0.55 (vs 0.86) with an `intelx-text-match` marker
  + "unvalidated text match" evidence note. **(3) HudsonRock**: admitted any dotted
  string as a victim IP (`!ip.contains('.')`), so a stealer log's LAN address
  (RFC1918/loopback/CGNAT) — or a non-IP like `unknown.host` — became a
  `geolocation-lead` fed to GEOINT (and every IPv6 was wrongly dropped). Extracted
  pure `victim_ip_entities` gating each candidate on `is_public_ip` (parses v4 +
  v6, rejects private/reserved), mirroring the gate `dehashed`'s record IPs use.
  Test delta: `name_headline_is_gated_on_a_real_subject_match`,
  `text_search_withholds_the_strong_exposure_tags`,
  `victim_ips_only_admit_routable_public_addresses` — each fail-before/pass-after.
  Gate green: fmt/clippy/doc clean, full suite 0 failures. **Paired:**
  `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **Comprehensive audit cycle 4/N: engine finalise/dispatch
  robustness — a panicking rule can't abort a scan; a cache replay can't reset the
  breaker.** Two engine-layer robustness gaps in the same finalise/dispatch flow.
  **(1)** The authoritative finalise-time correlation pass ran
  `Correlator::new(store).run(&scan.id)` UNGUARDED. The live incremental pass
  already wraps `correlate_entities` in `catch_unwind` (a rule panicking on
  adversarial persisted data — a slice-index bug over a crafted entity — is
  contained), but the finalise pass did not, so an identical panic there would
  unwind the whole finalise block, losing the terminal `ScanComplete` event AND
  the harvested API-key pool (the key-pool save + WAL checkpoint + events-prune all
  run AFTER the correlator in `finalise_scan`). Extracted pure
  `guarded_finalise_correlation(scan_id, run)` returning `Option` (`None` on
  error/panic → caller skips emission but the scan finalises), closing the
  asymmetry with the live pass. **(2)** `finalise_module_result` fed the circuit
  breaker `record_success` on EVERY `Ok(Ok(_))`, including inter-scan cache
  REPLAYS (which make no provider call). A replay clearing a soft-failure streak
  the live calls legitimately earned this scan would mask a degrading provider (or
  reset a soft-trip countdown), so a genuinely-failing source keeps getting
  re-dispatched. Added a `from_cache` param: the 3 cache-hit call sites pass
  `true` (skip the breaker success), the 3 real-dispatch sites pass `false`. A
  replay is now neither success nor failure to the breaker. Test delta:
  `finalise_correlation_pass_survives_a_panicking_rule` (a panicking closure is
  caught, not unwound) and `cache_replay_does_not_feed_the_circuit_breaker_success_path`
  (streak survives a replay → the 3rd real failure trips; a real dispatch clears
  it) — both fail-before/pass-after against pure/testable seams. Gate green:
  fmt/clippy/doc clean, full suite 0 failures. **Paired:** `SOLUTION_TREE` §5 —
  same commit.
- **2026-07-04** — **Comprehensive audit cycle 5/N: export completeness — the
  dossier silently dropped whole entity kinds, and GEXF left two injection points
  unescaped.** **(1)** `cli/scan/dossier.rs::print_dossier` iterated a FIXED
  `kind_order` allowlist and `continue`d past anything absent from it — so an
  entity whose kind wasn't listed NEVER printed. Four real `EntityKind`s
  (`cidr`, `ssid`, `tracking_id`, `crypto_address`) and every `other:<custom>` were
  omitted, hiding collected intel (a leaked crypto wallet, a captured Wi-Fi SSID, a
  tracking-pixel id) from the operator's primary human-readable output. Extracted a
  pure `order_dossier_kinds(by_kind)` that renders the curated kinds first, then
  EVERY remaining present kind in deterministic (BTreeMap key) order — nothing is
  dropped; added the four missing headers. **(2)** `core/gexf/mod.rs` wrote the node
  `kind` attvalue (`write_node`) and the `<description>` scan id (`write_preamble`)
  UNESCAPED, while the node label, tags, and edge labels were all already escaped.
  An `Other(<custom>)` kind is data-derived and can carry `<`/`&`/`"`, which would
  break that attribute and thus the whole `.gexf` in Gephi; both now pass through
  `xml_escape`. Test delta: `dossier_renders_every_present_kind_never_dropping_one`
  (every present kind — incl. `other:passport` — appears, curated order preserved)
  and `gexf_escapes_the_kind_attribute_and_the_scan_id`; the existing GEXF golden
  byte-stable test confirms metachar-free output is unchanged. Gate green:
  fmt/clippy/doc clean, full suite 0 failures. **Paired:** `SOLUTION_TREE` §5 —
  same commit.
- **2026-07-04** — **Comprehensive audit cycle 6/N: determinism + concurrency
  correctness — a stable Netlas JARM and a single-probe circuit breaker.** Two
  independent defects. **(1) Determinism.** `modules/netlas::build_entities`
  accumulated a host's JARM fingerprints in a `HashSet` and emitted ONE via
  `jarm_seen.iter().next()`. `HashSet` iteration order is randomised per process
  (SipHash with a random seed), so a host exposing several JARMs emitted a
  *different* `jarm_fingerprint` between otherwise-identical runs — a byte-identical
  -output violation (the same class the export layer guards against). Switched to
  `BTreeSet`, so `.iter().next()` is the lexicographically smallest fingerprint,
  deterministically. **(2) Concurrency.** `util::circuit_breaker::Breaker::allow`
  matched `Closed | HalfOpen => true`, so once an open host's cooldown elapsed and
  the first caller transitioned it to `HalfOpen`, EVERY concurrent caller in that
  window also got `true` — a thundering herd on a host that is very likely still
  down, defeating the single-trial-probe design. `HalfOpen` now returns `false`
  for concurrent callers (exactly one probe in flight); `retry_at` doubles as the
  probe deadline (set by a new `enter_half_open`), so a probe whose outcome is
  never recorded (a dropped/cancelled request) self-heals into a fresh probe one
  `COOLDOWN_SECS` later rather than wedging the breaker `HalfOpen` forever. Test
  delta: `build_entities_emits_a_deterministic_jarm_fingerprint` (3 out-of-order
  JARMs → the smallest); `half_open_admits_exactly_one_probe_and_self_heals_a_lost_outcome`
  + the existing `after_cooldown_allows_once_and_goes_half_open` updated to assert
  the second concurrent caller is denied. Gate green: fmt/clippy/doc clean, full
  suite 0 failures. **Paired:** `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **Comprehensive audit cycle 7/N: HTTP response-snippet buffers
  now bound peak memory against a single oversized chunk.** `util::http::fetch`'s
  `error_snippet` and `read_body_capped` both `buf.extend_from_slice(&bytes)` the
  WHOLE streamed chunk and then `buf.truncate(cap)` — so the cap only bounds `buf`
  *after* a chunk is fully copied in. A hostile/misconfigured upstream returning
  one multi-GB chunk (HTTP/1.1 chunked encoding permits arbitrary chunk sizes) is
  copied entirely into RAM before the truncate runs, an OOM risk on a low-RAM
  Termux device (worst under the `username_search` 32-way probe fan-out, where many
  such reads run at once). Extracted a shared pure `append_capped(buf, chunk, cap)`
  that copies at most `cap - buf.len()` bytes and returns whether the cap was
  reached, so `buf` is a real ceiling regardless of any one chunk's size; both
  readers now use it (single-sourcing the bound). Test delta: 3 unit tests on
  `append_capped` (one oversized chunk bounded to the cap; small chunks accumulate
  then trim exactly at the cap; no underflow when already full). Gate green:
  fmt/clippy/doc clean, full suite 0 failures. **Paired:** `SOLUTION_TREE` §5 —
  same commit. **This closes the comprehensive 6-subsystem audit's actioned
  backlog** (web/API, export, engine, storage, HTTP, module parsers) — 12 shipped
  repairs across 7 cycles; the remaining register items are LOW/defer-noted.
- **2026-07-04** — **Live end-to-end validation (T2.15, new): finalise stalled on
  a rich `full_name` scan — the two `O(identities²)` pairwise-pathway sweeps are now
  bounded.** Real-seed live testing of every target kind (self-test subject *Haigen
  Bamford* for identity kinds; public infrastructure for the rest — 8.8.8.8,
  github.com, AS15169, the BTC genesis address, …) found ALL 19 kinds run without a
  single panic and every module error was environmental (blocked cloud IP / no
  residential exit), but the `name` scan took **135–185 s at depth 0** and, on a
  cold/richer run, exceeded a 150 s external timeout. Instrumented phase timing
  isolated it precisely: two finalise passes each iterate every identity pair
  calling `disjoint_pathways_in` (depth-5, 4-path) — **AU-062**
  `multipath_corroborated_links` and **AU-063** `single_route_identity_links`. A
  broad name scan derives ~400 name-permutation identity entities → ~80 000 pairs →
  each sweep ~45 s (the enumeration `connection_templates` was only 207 ms; the
  pairwise sweeps were the cost). Both now share ONE deterministic
  `IDENTITY_PAIR_PROBE_CAP = 6 000` (in `core::relation::graph`, single-sourced so
  the two sweeps can't drift): `identity_uids` is sorted, so the cap is a
  deterministic prefix — byte-identical output preserved, NOT a wall-clock budget —
  and the signals are best-effort enhancement whose output was already capped, so a
  bounded subset degrades gracefully. **Measured before/after (real name scan):
  combined pathway phase 48 s → 8 s**; now bounded regardless of identity count; a
  typical ≲110-identity scan is still examined in full. Test delta:
  `single_route_links_are_pair_probe_capped_deterministically` +
  `multipath_links_are_pair_probe_capped_deterministically` (each via a testable
  `*_capped(…, max_pair_probes)` seam: cap 0 → empty, cap 1 → ≤1, deterministic
  prefix). Gate green: fmt/clippy/doc clean, full suite 0 failures. **Paired:**
  `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **Live validation (T2.16, new): three modules restored — two
  dead from upstream API drift, one tripping its own breaker.** Driving a REAL seed
  of every kind end-to-end (the definitive test — no unit test exercises a live
  upstream) caught three module faults invisible to the suite. **(1) HudsonRock**
  `search-by-login`: Cavalier renamed its query param `username`→`email`, so every
  request 400'd `"Email is required"` — the free keyless stealer source was fully
  dead. Extracted testable `search_by_login_url` using `email=` (curl-confirmed a
  known-infected address returns 5 stealer records; the old `%40`→`@` dance is
  obsolete on the `email=` endpoint). **(2) StackOverflow** `users?inname=`: the
  hard-coded `filter=!9Z(-x.hbL` now 400s `"Invalid filter specified"` — every
  lookup broken. Extracted `users_by_name_url` dropping the filter (the API default
  already returns `display_name`/`location`/`website_url`/`link`/`reputation`/
  `creation_date`, verified live — and a default filter can't be invalidated by an
  API revision the way a custom encoded one can). **(3) Bluesky** `getProfile`:
  a non-existent handle answers `400 {"message":"Profile not found"}` (not 404),
  which `fetch_json_or_404` propagates as a module error — and the engine's
  per-module breaker counts it a soft failure, so a name scan's handle fan-out
  trips the breaker after 3 misses and suppresses Bluesky for the REAL handles too.
  Added `util::http::fetch_json_or_absent` (generalised `fetch_json_inner`'s
  `map_404_to_none: bool` → `absent_statuses: &[u16]`; treats 400 **and** 404 as
  the clean negative, 429/5xx still errors) and routed Bluesky through it. Test
  delta: `search_by_login_uses_the_email_query_parameter`,
  `users_url_omits_the_invalid_custom_filter`, and
  `fetch_json_or_absent_maps_400_to_none_while_or_404_still_errors` (a one-shot
  local 400 server proving the split). All three re-verified LIVE against the real
  endpoints. Gate green: fmt/clippy/doc clean, full suite 0 failures. **Paired:**
  `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **Stale-marker correction: §7 S2 (P1 HIGH whois-referral SSRF)
  was fixed + tested but still shown `[ ]`.** The huntsman-cycle reads the trees to
  pick the highest-priority open work, so a P1 node marked open when its fix has
  shipped mis-directs the loop into re-investigating a done item. Verified the fix
  is genuinely present and complete — not merely claimed: `modules/whois/client.rs::resolve_public_whois`
  parses `host:port` (incl. `[v6]:port`), refuses any non-43 port and
  `is_local_domain` hosts, resolves to the first `!is_private_addr` address and
  returns a concrete `SocketAddr` that **pins** the dial; `mod.rs:284` routes the
  attacker-influenceable `refer:`/`whois:` referral through it while the trusted
  IANA bootstrap keeps its constant. Confirmed robust against the subtle bypass
  too: `is_private_addr` runs `to_canonical()` first (so `[::ffff:127.0.0.1]:43`
  collapses to loopback and is refused) plus an `embedded_ipv4` NAT64/6to4 check.
  The regression test `blocks_ssrf_and_non_whois_referrals` passes (loopback /
  link-local metadata / RFC1918 / v6-loopback / non-43 port / local-domain all
  refused; a public `:43` referral allowed and pinned). `SOLUTION_TREE`
  SOL-SSRF-WHOIS and §4a already recorded the delivery (2026-06-17); only this
  `PROBLEM_TREE` marker had drifted. Flipped `[ ]`→`[x]`; no code change.
  **Paired:** `SOLUTION_TREE` §5 (already `[x]`) — this commit records the
  reconciliation.
- **2026-07-04** — **Precision (T2.17, new): AU-081 asserted High "same
  individual" on a common full name — a confident false merge.**
  `rule_au_081_canonical_person_name_match` bridges two independently-sourced
  `Person` records that normalise to one canonical name, and emitted
  `Severity::High` "independently-sourced records for the same individual"
  **unconditionally** — no commonness discount, unlike every other identity/kin
  rule (AU-051, AU-061, `derive_kinship`, `derive_regional_kinship`, leads,
  `engine::passes`) which discounts a common surname because many unrelated
  people share it. So two strangers who each surface as "John Smith" (a breach
  dump + a proxycurl profile — different source families, so the independence
  gate passes) were merged at High into one asserted identity, mis-attributing
  each stranger's evidence to the other — the single worst outcome for an
  evidentiary tool, and the highest-volume false-merge vector in person OSINT.
  The docstring compounded it, claiming the token-count floor "excludes a
  known-common first name like John" when the floor only rejects <2-token names
  (so "John Smith", two common tokens, sailed through). Fix mirrors the AU-051
  discount at the emit site: `is_common` over the canonical name's tokens →
  common ⇒ `Severity::Medium` "a COMMON name many unrelated people share — a
  lead to VERIFY, not a confirmed merge"; distinctive ⇒ `Severity::High` "same
  individual" as before. Docstring corrected to describe the real gate. Test
  delta: `au081_common_name_is_a_medium_lead_not_a_high_assert` (two "John
  Smith"/"Smith John" from breach vs proxycurl → Medium + "VERIFY"; control
  "Haigen Bamford"/"Bamford Haigen" → High + "same individual"); the existing
  `au081_…_fires_on_cross_source_same_name` already asserts the distinctive-name
  High path and still passes. Gate green: fmt/clippy/doc clean, full suite 0
  failures. **Paired:** `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **Precision (T2.18, new): a third page email byte-scanner
  (`web_crawler`) still admitted IP-literal / numeric / 1-char-TLD hosts the
  canonical gate rejects.** `util::extract::host_has_alpha_tld` was introduced
  (gap_register 2026-07-04) as the single source of email-domain validity
  precisely so the two **non-regex** admission paths — `looks_like_email` (the
  provider-field gate) and `page_emails` (the `util` HTML byte-scanner) — could
  never out-admit the free-text `EMAIL_RE`. But a THIRD copy of the same
  byte-scan logic, `web_crawler::crawl_util::extract_emails`, was missed: it
  still gated on the old `domain.contains('.') && domain.len() > 3` heuristic
  (plus `validate_email_syntax`, which checks dot artifacts but **not** the TLD),
  so `admin@10.0.0.1` (IP literal), `user@host.123` (numeric TLD) and
  `user@host.c` (1-char TLD) each minted a bogus `Email` entity that then seeds
  permutations and fires co-location/reuse rules — a parse-layer false positive
  that compounds downstream, the class the doctrine says to kill at the source.
  Fix: made `host_has_alpha_tld` `pub` (module layer may use `util`) and routed
  `extract_emails` through it, dropping the weak inline gate; the docstring now
  names all three paths it single-sources. `validate_email_syntax` stays, so the
  combined gate (alpha-TLD **and** no dot artifacts) is the strictest of the
  three. Test delta:
  `email_extraction_rejects_ip_literal_and_numeric_or_short_tld_hosts` (all three
  junk hosts rejected, a real `ops@acme.com` alongside them still surfaces);
  fails against the old `len > 3` gate, passes against the fix. Gate green:
  fmt/clippy/doc clean, full suite 0 failures. **Paired:** `SOLUTION_TREE` §5 —
  same commit.
- **2026-07-04** — **MITRE precision (T2.19, new): `username_search` over-claimed
  ATT&CK T1589.003 (Employee Names) on every finding — the one presence
  enumerator the override pass missed.** Each admitted entity is stamped with its
  producing module's `attack:<ID>` techniques (`engine::dispatch`), so a per-finding
  `attack:` tag IS HSE's MITRE surface — the map's precision is the product's ATT&CK
  fidelity. The codebase's guard-encoded convention is exact: a module claims
  T1589.003 **iff it emits a real-name `Person`** (keybase/gravatar/DeHashed/IntelX
  keep it *because* they do; github_user/hacker_news/lobsters/nostr/reddit_user were
  overridden to DROP it as "over-claimed — no Person entity"). `username_search`
  ENUMERATES handle presence across 300+ sites and emits only `Url` + `Username`
  (`produces() = [Url, Username]`, zero `EntityKind::Person` in the module) — yet it
  had no override and inherited the raw `Social` default `["T1593.001", "T1589.003"]`,
  so every profile URL / username it emitted carried a false `attack:T1589.003`
  (Employee Names) claiming HSE gathered a person's name when it only confirmed a
  handle exists. It was simply skipped when its twins were corrected. Added the
  precise override `["T1593.001"]` (Social Media search only — no bio-email path, so
  no T1589.002 like reddit_user) with the guard assertion pinning it and forbidding a
  regression to T1589.003. Test delta: `attack_overrides_attribute_collection_modules_precisely`
  extended (assert_eq `username_search` → `["T1593.001"]` + `!contains("T1589.003")`);
  fails against the inherited default, passes against the override.
  **Follow-up noted, not swept (split-don't-sprawl):** five further un-overridden
  name-less `Social` modules — `discord_snowflake`, `fediverse`, `gaming_profile`,
  `streaming_probe`, `structured_id` — likely warrant the same audit (each emits no
  `Person`), but each has its own technique nuance (fediverse emits `Email`,
  structured_id a `MacAddress`) so each needs an individual judgement, not a blanket
  drop; left as a discrete follow-up rather than expanding this cycle. Gate green:
  fmt/clippy/doc clean, full suite 0 failures. **Paired:** `SOLUTION_TREE` §5 — same
  commit.
- **2026-07-04** — **GEOINT precision (C5): AU-059's class-diversity weight was a
  global scalar — a mathematical no-op — so the "best AU location" fix ignored
  per-point corroboration.** `au059_synergy_fix` (the source of the dossier's
  headline "best location estimate" and the API's `best_location` fields) computed
  `class_bonus = 1.0 + (classes.len() - 1) * 0.10` from the SCAN-WIDE distinct-class
  count and multiplied *every* point's weight by that same constant. A weighted
  geometric median (and the centroid fallback) is invariant to scaling all weights
  by one positive constant, so the bonus moved the fix **not at all** — yet its own
  comment claimed "a point corroborated across more orthogonal classes pulls
  proportionally more." The intended behaviour is real and desirable: a coordinate
  confirmed by several independent collection methods (a registry address *and* a
  photo GPS *and* a wifi sighting at one spot) should outweigh a single-class
  sighting. Fix: derive the bonus **per point** from *that entity's own* distinct
  anchoring geo classes (`corroborating_sources` → `geo_source_class`), so points
  with more orthogonal corroboration genuinely pull the median toward them; the
  comment now states why a global bonus would be a silent no-op. Deterministic
  (HashSet-len is order-independent); the existing outlier-robustness test still
  passes (its points are single-class, bonus 1.0 throughout). Test delta:
  `au059_class_diversity_bonus_is_per_point_not_a_global_no_op` — two scans differing
  ONLY in the eastern point's class SPAN (3 classes vs 1), holding its source count
  (hence `c_effective`) and every other point fixed; asserts the multi-class scan
  pulls the fix east, which is byte-identical to the single-class scan under the old
  global scalar (fail-before) and strictly east under the per-point bonus
  (pass-after). Gate green: fmt/clippy/doc clean, full suite 0 failures. **Paired:**
  `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **GEOINT precision (H5 doctrine): `coord_state` and AU-099 let
  infrastructure coordinates vote the subject's location — the two geo rules that
  never adopted the `is_infrastructure_geo` guard.** Surfaced by an
  adversarially-verified precision-discovery workflow (8 subsystem finders → refute-by-
  default verification; 14 confirmed defects, this the top-ranked). `coord_state`
  (`rules/geo/mod.rs`) and `rule_au_099_coordinate_reverse_geocode` gated only on
  `kind == Coordinates && confidence ≥ 0.50` — **no `is_infrastructure_geo`** — while
  every sibling location rule applies it (AU-018 `profile.rs:30`, AU-030
  `chain.rs:302`, AU-052/053/059 via `person_anchored_coords` `location/mod.rs:149`),
  and the file's own H5 test section is titled "infrastructure geo must not vote the
  subject's location." So a bare `ip_geo` coordinate (the datacentre behind the
  subject's domain — confidence 0.60, tagged `au-state:NSW`, no anchoring source)
  asserted `NSW` through `coord_state`, which feeds **AU-056** (jurisdiction
  cross-check), **AU-085** (phone-region), **AU-092** (breach-footprint) and **AU-098**
  (residency consensus): a Sydney server IP would manufacture a false AU-056
  "jurisdiction conflict" against the subject's real QLD address, and AU-099 would
  announce the datacentre as "the subject's coordinate fix." Fix: add the one guard
  every sibling already uses to both — `coord_state` returns `None` and AU-099 skips
  the entity when `is_infrastructure_geo(e)`. Test delta:
  `coord_state_excludes_bare_ip_geo_infrastructure_coordinate` and
  `au099_reverse_geocode_excludes_infrastructure_coordinates` (each: bare `ip_geo`
  coord → excluded, `exif_geo` control at the same point → included). Same-commit
  fixture reconciliation: 7 existing AU-056/085/092/098/099 tests built coordinates
  from a placeholder/non-anchoring source (`geo_normalize`, or no evidence) for what
  are real subject fixes — updated to carry a genuine anchoring source (`exif_geo` /
  `search_engines`), which a real subject coordinate always has, so only pure infra
  (ip_geo-only) coordinates are newly excluded. Gate green: fmt/clippy/doc clean, full
  suite 0 failures (4543). **Paired:** `SOLUTION_TREE` §5 — same commit. Remaining 13
  workflow-confirmed defects queued (task list + `gap_register`) for subsequent cycles.
- **2026-07-04** — **Export integrity: the `/graph.gexf` API export leaked
  quarantined `candidate` breach-victims as nodes, and every GEXF caller could emit
  dangling edges (two coupled workflow-confirmed defects, fixed as one).** The web
  GEXF endpoint (`api::scan_export::scan_export_gexf`) passed
  `store.entities_for_scan(id)` **unfiltered** to `entities_to_gexf`, so every
  quarantined `candidate` (a non-subject breach co-occurrence "stranger") became a
  labelled node — leaking a foreign breach-victim list under the subject's scan,
  which the CSV (`scan_entities_csv`), `report.json`, and CLI (`render_gexf`) exports
  all strip by default. But naively filtering candidates would have hit the second
  defect: `render_gexf` **already** dropped candidate *nodes* yet passed the *full*
  relation set, so any relation to a filtered candidate emitted an `<edge>`
  referencing an undeclared node id — structurally-invalid GEXF Gephi rejects. Fixed
  both at the right layers: (1) `entities_to_gexf` now builds the present-node-id set
  and emits a relation edge only when **both** endpoints are declared nodes — making
  "every edge references a declared node" a serializer invariant, so no caller
  (CLI or API) can produce a dangling edge regardless of the subset it passes; (2)
  `scan_export_gexf` filters `candidate` rows by default with a `?include_candidates=1`
  opt-in, matching the CSV endpoint's contract. Test delta:
  `gexf_drops_relation_edges_referencing_a_filtered_out_node` (a relation to a
  filtered node emits no dangling edge) and
  `scan_gexf_quarantines_candidate_nodes_by_default` (candidate absent by default,
  present with the opt-in). The GEXF golden byte-stable test is unaffected (its
  fixture has no absent-endpoint edges). Gate green: fmt/clippy/doc clean, full suite
  0 failures (4545). **Paired:** `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **No-fabrication precision: `streaming_probe` stamped a flat 0.92
  confidence and asserted a sensitive identity on every hit, including bare
  status-only detections.** Workflow-confirmed defect. The module fans out HTTP
  probes across ~43 cam / fan-subscription / adult-video platforms; 41 use
  `Detect::StatusEq(200)` (a HEAD/GET 200 alone) and only 2 use
  `Detect::StatusAndNotBody` (200 **and** the rendered body lacks the platform's
  "not found" marker). Every `Found` minted a `Url` at a hard-coded **0.92** and any
  cam/fans/adult hit stamped the summary `Username` with `cam-identity-exposed` /
  `subscription-platform-found` / `adult-profile-found` — but a status-only 200 is
  weak evidence: a soft-404, a CloudFlare interstitial, or a catch-all route all
  answer 200 for any handle, so a single unverified probe **fabricated a
  high-confidence, reputationally-sensitive "this person has a cam/adult identity"
  claim** — the exact over-confidence bug the sibling `username_search` already fixed
  with its `detection_strength` tiering. Fix mirrors the sibling: a new pure
  `detection_strength(detect) → (f64, bool)` gives a body-verified hit `(0.92,
  true)` and a status-only hit `(0.74, false)`; each `Url` now carries its tiered
  confidence and a `verified-detection` / `weak-detection` provenance tag; the
  strong exposure tags are gated on a **body-verified** hit in that category (a
  status-only-only category still surfaces its weak-tagged 0.74 URL — the lead isn't
  lost, only its unearned assertion); the summary records `hits_verified` /
  `hits_status_only`. The emit logic was extracted into a pure, testable
  `build_entities`. Test delta: `detection_strength_tiers_status_only_below_body_verified`
  and `build_entities_tiers_confidence_and_gates_exposure_on_verified` (a status-only
  cam hit → 0.74 + weak-detection + NO `cam-identity-exposed`; a body-verified hit →
  0.92 + verified-detection + the exposure tag). Gate green: fmt/clippy/doc clean,
  full suite 0 failures (4547). **Paired:** `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **False-merge precision: AU-046 fused EVERY platform-sourced
  identifier in the scan into every alias — the worst class, a wrong identity
  resolution.** Workflow-confirmed. `rule_au_046_cross_platform_identity_resolution`
  builds a single scan-wide `resolved` set — every `Email`/`Person` with a
  code/forum/social corroborating source — and attributed **all** of it, at
  `Severity::High`, to **every** alias, with (a) no tie between an identifier and the
  alias's actual account and (b) no role-mailbox gate. So a co-author's email surfaced
  from a different platform account, another alias's identifiers, or a `noreply@`
  support desk were all fused into a person's "resolves to N real-world identifiers"
  finding — the exact "unrelated strangers" fusion the docstring claimed it "can't"
  do. Fix scopes each resolution to the alias's OWN account(s): an identifier resolves
  to a given alias only when it shares ≥1 concrete corroborating **source** with that
  alias (the same platform module that confirmed the handle also surfaced the
  identifier), and role mailboxes are excluded (`core::validation::is_role_mailbox`,
  the AU-045 gate). `resolved` is now computed per-alias, not scan-wide, so cross-alias
  contamination is impossible; an alias with no own-account identifier no longer fires.
  Docstring corrected to describe the real (shared-source) linkage. Test delta:
  `au046_resolves_only_the_alias_own_account_identifiers` — an own-account email
  (shared source) resolves; a stranger from an unshared platform account and a
  `noreply@` role mailbox are both excluded; description counts exactly one identifier.
  The two existing AU-046 tests (whose emails share the alias's source) still pass. Gate
  green: fmt/clippy/doc clean, full suite 0 failures (4548). **Paired:** `SOLUTION_TREE`
  §5 — same commit.
- **2026-07-04** — **False-merge precision: AU-042 fused every `pgp-linked` email in
  the scan into one owner — unpartitioned by key — and fired on a single address.**
  Workflow-confirmed. `rule_au_042_pgp_email_identity` collected ALL `pgp-linked`
  `Email` entities scan-wide and emitted **one** `High` "a PGP key links N emails to
  one owner" over the whole set, firing whenever the set was non-empty. Two real
  defects: (1) **no key-fingerprint partition** — emails bound to two *different* PGP
  keys (two potentially-different people) were merged into a single asserted owner, a
  false identity merge; (2) **fires on one email** — a lone `pgp-linked` address
  produced a degenerate "links 1 email address to one owner" High assertion, though
  the docstring's contract is "two or more." The `pgp` module already stamps each
  `pgp-linked` email with a `key_fingerprint` evidence attribute, so the fix
  partitions on it: group the emails by fingerprint (deterministic `BTreeMap`
  fingerprint→address→uid), emit one finding PER KEY that binds **≥2 distinct
  addresses**, and name the fingerprint in the description; an email carrying several
  fingerprints belongs to each key it bound, and an email with no fingerprint is
  excluded (unattributable). Test delta: `au042_does_not_fuse_emails_from_two_distinct_keys`
  (key A binds two, key B binds two → two findings of two, never one of four),
  `au042_does_not_fire_for_a_single_pgp_linked_email` (a lone bound address does not
  fire), and the existing `au_042_groups_pgp_linked_emails` updated to attach the
  `key_fingerprint` a real `pgp` hit always carries. Gate green: fmt/clippy/doc clean,
  full suite 0 failures (4549). **Paired:** `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **MITRE precision: the five name-less `Social` modules over-claimed
  ATT&CK T1589.003 (Employee Names) on every finding — the deferred follow-up from the
  `username_search` fix, now closed.** Each admitted entity is stamped with its module's
  `attack:<ID>` techniques, and the guard-encoded convention is that a module claims
  T1589.003 iff it emits a real-name `Person`. `streaming_probe`, `gaming_profile`,
  `discord_snowflake`, `structured_id`, and `fediverse` are all `ModuleCategory::Social`
  with no override, so each inherited the default `["T1593.001", "T1589.003"]` — but
  none emits a `Person` (their `produces()` are `Url`/`Username`/`Email`/`MacAddress`),
  so every finding falsely claimed HSE gathered a person's name. Corrected each to its
  real collection: the three platform/handle modules (`streaming_probe`,
  `gaming_profile`, `discord_snowflake`) → `["T1593.001"]` (Social Media only);
  `fediverse` → `["T1589.002", "T1593.001"]` (it also emits profile emails, like nostr);
  and `structured_id` → `["T1592.001"]` (Gather Victim Host Information: Hardware) —
  it's an OFFLINE structured-ID decoder whose signal is the generating machine's MAC
  address in a UUIDv1, not a social search, so it drops BOTH inherited social techniques.
  Test delta: `attack_overrides_attribute_collection_modules_precisely` extended with a
  loop over the three `["T1593.001"]` modules plus explicit `fediverse` and
  `structured_id` assertions, each also `!contains("T1589.003")` (and `structured_id`
  `!contains("T1593.001")`). This closes the five-module follow-up noted in the
  `username_search` cycle; `username_variants` deliberately keeps T1589.003 (a conscious
  convention) and is untouched. Gate green: fmt/clippy/doc clean, full suite 0 failures
  (4549). **Paired:** `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **Parse-layer precision: the SeekNow stealer URL admission gate was
  weaker than its oathnet_pro twin — a bare `len >= 4`.** Workflow-confirmed
  single-source drift. `see_know::extract::extract_entities` mints the stealer `url` /
  `url_str` field as a `Url` entity on `url.len() >= 4` alone — no scheme, no host —
  while its sibling `oathnet_pro::stealer` (whose model the see_know comment claims to
  mirror: "exactly OathNet's stealer model") gates the identical field on
  `u.starts_with("http") && u.contains('.')`. So a native-app URI (`android://…`), a
  scheme-less fragment, or a capture sentinel ≥4 chars became a bogus `Url` node in
  see_know that oathnet_pro rejects — and a phantom `Url` misdirects the crawl / DNS /
  cert expansion that follows a captured login surface. Fixed by mirroring the twin's
  gate (trim, then `starts_with("http") && contains('.')`), single-sourcing the
  admission rule so the two stealer consumers can't drift again; the paired
  `<username>@<url>` `Credential` stays ungated (a login for a native-app surface is
  still a real credential), exactly as oathnet_pro keeps it. Test delta:
  `extract_entities_rejects_non_web_stealer_url_but_keeps_the_credential` (an
  `android://…` url mints no `Url` but still yields the `Credential`); the existing
  `extract_entities_spiders_stealer_url_into_pivots` (a real `https://` surface) still
  passes. Gate green: fmt/clippy/doc clean, full suite 0 failures (4550). **Paired:**
  `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **Correctness: two cross-scan-history idempotency probes used an
  unanchored substring match, silently dropping a genuine distinct link.** Two
  workflow-confirmed instances of the same bug in `core::engine::history`.
  `endpoint_has_cooccurrence` keyed idempotency on `ev.summary.contains(partner)` and
  `endpoint_has_relation_recall` on `contains(kind) && contains(partner)` — bare
  substrings — while the summaries they probe write the partner **backtick-delimited**
  (`` Co-occurred with `{partner}` `` / `` … to `{partner}` ``) and the kind
  **paren-delimited** (`(subdomain_of)`). So an entity already bridged to `` `alice2` ``
  made the probe report it as **already linked** to a *new* partner `alice` (a
  substring of `alice2`), so `link_cross_scan_cooccurrence` / `link_cross_scan_relations`
  skipped attaching the genuine `alice` co-occurrence/recall evidence — a real
  cross-investigation association lost whenever one partner's value is a substring of
  another's (common with numbered handles, `bob`/`bob2`, or a kind that is a substring
  of another). Fixed both to match the delimited token the summary actually writes
  (`` `{partner}` ``; `({kind})`), so only the exact partner/kind matches. Test delta:
  `idempotency_probes_match_the_delimited_partner_token_not_a_substring` (the recorded
  `alice2`/`bob2` still match — idempotency preserved — but the substrings `alice`/`bob`
  do not, so their links are no longer dropped); the existing idempotency tests still
  pass. Gate green: fmt/clippy/doc clean, full suite 0 failures (4551). **Paired:**
  `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **Parse-layer precision: the email byte-scanners' local-part class
  omitted `%`, truncating a `%`-containing mailbox.** Workflow-confirmed single-source
  drift. The canonical `EMAIL_RE` local class is `[A-Za-z0-9._%+-]` (includes `%`, and
  a unit test pins `with%percent@example.com` as a match), but both non-regex
  byte-scanners — `util::extract::is_email_local_byte` (used by `page_emails`) and its
  twin `web_crawler::crawl_util::is_email_char` — stopped at `%`, so
  `with%percent@example.com` was carved down to a fabricated `percent@example.com`.
  Added `%` to both predicates so they match the canonical class. Test delta:
  `page_emails_keeps_a_percent_in_the_local_part` and
  `email_extraction_keeps_a_percent_in_the_local_part` (each asserts the full
  `%`-mailbox survives and cross-checks `EMAIL_RE`). Gate green: fmt/clippy/doc clean,
  full suite 0 failures (4553). **Paired:** `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **Precision: `to_e164_au`'s bare-`61` branch fabricated an AU number
  from a foreign one — missing the ACMA trunk-digit gate its sibling has.**
  Workflow-confirmed. `core::validation::to_e164_au` has two AU-inference branches: the
  AU-local (`0` + 9 digits) branch requires a real ACMA national-significant-number lead
  (`matches!(compact[1], 2|3|4|5|7|8)`) — added earlier precisely to stop a foreign
  10-digit local number being re-typed as `+61…` — but the AU-international-without-`+`
  (`61` + 9 digits) branch gated only on `!nat.starts_with('0')`, so a foreign national
  number whose lead is `1`/`6`/`9` (e.g. a French mobile `0612345678` written as
  `61612345678`) was fabricated into `+61612345678`, a non-existent AU number (and its
  derived mobile/fixed-line/jurisdiction classification). Fixed by applying the SAME
  trunk-digit gate to the `61` branch (`matches!(nat[0], 2|3|4|5|7|8)`), single-sourcing
  the AU-lead rule across both inference paths. Test delta:
  `bare_61_prefix_requires_a_real_au_trunk_digit` (leads 1/6/9 rejected; 2/3/4/5/7/8
  still canonicalise); the existing `61412345678` international-form test still passes.
  Gate green: fmt/clippy/doc clean, full suite 0 failures (4554). **Paired:**
  `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **Dropped-field: DeHashed silently discarded an email mis-stored in
  the `password` slot — its two stealer/breach siblings recover it.** Workflow-confirmed.
  `dehashed::build`'s password loop guarded on `matches!(classify_credential_field(p),
  CredentialField::Secret)` only — no `Email` arm — so when the shared classifier
  (`util::extract::classify_credential_field`, which returns `Email` for a value that
  `looks_like_email`) flagged an email in the password field (a common stealer/breach
  quirk), DeHashed minted NOTHING: the lead was dropped. Both siblings recover it —
  `oathnet_pro::breach` and `see_know::extract` mint it as an `Email` at 0.45 tagged
  `recovered-from-password` (minting it as a `Password` would forge a reused-secret link
  across every row with the same quirk). Converted the DeHashed loop to the same
  three-arm `match` (Sentinel drop / Email recover / Secret mint), single-sourcing the
  policy so the three breach parsers don't drift on this field. Test delta:
  `email_in_the_password_slot_is_recovered_as_an_email_lead` (an email in `password` →
  an `Email` tagged `recovered-from-password`, NOT a `Password`); the existing
  plaintext-password test still passes. Gate green: fmt/clippy/doc clean, full suite 0
  failures (4555). **Paired:** `SOLUTION_TREE` §5 — same commit. **This closes the last
  actioned item of the 14 workflow-confirmed defects** (the remaining ones were fixed in
  the preceding cycles this arc); AU-059's class-diversity and the four geo/export/MITRE
  higher-leverage items shipped earlier.
- **2026-07-04** — **Full-fidelity (new arc, T2.19): the AU register scrapers `acma_rrl`
  and `ahpra` silently truncated results at 20 rows.** Surfaced by an
  adversarially-verified **fidelity-audit workflow** (5 finders for silent-truncation /
  dropped-field / downsample / placeholder / lossy-transform; 8 confirmed violations,
  these two the top-ranked). Both scrapers parse the full result table into an
  unbounded `Vec` (`parse_acma_html` / `parse_ahpra_html`) and then emit only
  `licences.iter().take(20)` / `practitioners.iter().take(20)` — a bare, undocumented,
  unlogged client-side cut with no server-side page-size parameter, so a large
  multi-licence org / 10 km coordinate-radius RRL search or a common-surname AHPRA
  search (Smith/Nguyen/Lee) silently drops every `Organisation`/`Person` beyond the
  20th (each carrying its licence/registration number and source). The only legitimate
  bound — `read_body_capped(resp, 512 KB)` — already limits parsed size; the `.take(20)`
  was pure loss with no memory/DoS rationale (unlike `austlii`'s `MAX_DOCS`, which is
  server-matched **and** surfaced). Fix extracts the emit into pure
  `build_licensee_entities` / `build_practitioner_entities` that emit EVERY parsed row,
  and `process` now `result.extend(...)`s them. Test delta:
  `build_licensee_entities_emits_every_parsed_row_not_just_20` and
  `build_practitioner_entities_emits_every_parsed_row_not_just_20` (25 rows in → 25
  entities out, the 25th present). Directly honours the operator's re-issued
  full-fidelity directive (no silent truncation/omission of results). Gate green:
  fmt/clippy/doc clean, full suite 0 failures (4557). **Paired:** `SOLUTION_TREE` §5 —
  same commit.
- **2026-07-04** — **Full-fidelity: `netlas` silently capped SSL SAN domains at 20 and
  extracted emails at 10 — its headline BFS pivots.** Fidelity-audit-workflow-confirmed.
  In the pure `build_entities`, `all_cert_domains` and `all_emails` are aggregated
  across every response item (cert subject email, cert emails, http emails, whois net
  emails; cert SAN domains), sort+deduped, then emitted through a bare
  `.iter().take(20)` (line 485) / `.iter().take(10)` (line 502) — no named constant, no
  comment, no log, no `domain_count`/`email_count` attribute. A multi-SAN / wildcard /
  shared-hosting certificate lists 50–100+ SAN domains and a busy host exposes >10
  distinct registrant/admin/tech/abuse contacts, so unique Domain pivots past #20 and
  Email pivots past #10 — the module's own documented "key differentiator … direct BFS
  pivot to breach stack" — were silently discarded. The BFS frontier budget is owned by
  the engine/scan orchestrator, not this leaf module, so the caps had no resource
  justification. Removed both (emit every unique deduped record). Test delta:
  `build_entities_emits_every_unique_san_domain_and_email` (25 SAN domains + 12 emails →
  25 `ssl-san` Domain + 12 `ssl-extracted` Email entities; fail-before: 20 + 10). This
  is distinct from the earlier Netlas JARM-determinism fix. Gate green: fmt/clippy/doc
  clean, full suite 0 failures (4558). **Paired:** `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **Full-fidelity: the `niamonx` ULP infostealer `login` was dropped
  entirely on Username/IpAddress scans.** Fidelity-audit-workflow-confirmed. In
  `emit_ulp`, a stealer-log record's `login` (the compromised account for a captured
  URL·LOGIN·PASS triple) was promoted to a pivot only when `useful = matches!(target_kind,
  Email | Domain)` — so on a `Username` scan (query `jsmith`, login `jsmith@gmail.com`)
  or an `IpAddress` scan (every account exfiltrated from the victim host) the login was
  not emitted as a pivot AND not stamped on the per-record evidence (which carried only
  `host`/`url`): the datum vanished. The `differs = !login.eq_ignore_ascii_case(query)`
  guard already suppresses the redundant query-equal value, so the target-kind gate was
  pure loss of genuinely-new identities. Fix: always stamp `login` on the record evidence
  (full fidelity, every kind), and promote it to a first-class `Email`/`Username` pivot
  on every target kind when it differs (removed the `useful` gate and the now-unused
  `target_kind` param). Test delta: `ulp_recovers_the_login_on_username_and_ip_scans` (a
  differing login on both a Username and an IpAddress scan → an `Email` pivot AND a
  `login` evidence attribute; fail-before: neither); the existing Email-scan pivot test
  still passes. Gate green: fmt/clippy/doc clean, full suite 0 failures (4559).
  **Paired:** `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **Full-fidelity: `entities_filtered()` silently capped every filtered
  browse query at 500 rows.** Fidelity-audit-workflow-confirmed. The
  `GET /scans/{id}/entities/filter` storage query (`storage::entities::entities_filtered`,
  line 349) appended a hardcoded `ORDER BY e.confidence DESC, e.uid ASC LIMIT 500`, while
  the handler exposes only `kind`/`q`/`min_confidence` and returns via `ok_list` with NO
  `limit`/`offset`/`total`/`has_more` — so on a breach-heavy scan whose filtered result
  exceeds 500 entities (routine for `kind=email` or a broad `q` over hundreds of rows) the
  lowest-confidence matches past rank 500 vanished from the browse view, with zero client
  signal, while the sibling `/entities/facets` still reported the true larger per-kind
  count (an observable inconsistency). The filtered set is a SUBSET of the canonical
  `entities_for_scan` (which backs `/entities`, CSV, `report.json`, GEXF) and is itself
  UNBOUNDED — so the 500 cap had no memory justification. `confidence DESC, uid ASC` is a
  total deterministic order (uid tie-break), so removing the LIMIT yields the complete
  deterministic result. Test delta:
  `entities_filtered_returns_the_complete_result_not_a_capped_500` (seed 600 email
  entities → 600 returned; fail-before: 500). Gate green: fmt/clippy/doc clean, full suite
  0 failures (4560). **Paired:** `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **Full-fidelity: SEON emitted only the FIRST per-platform display
  name; distinct name variants from other platforms were dropped.**
  Fidelity-audit-workflow-confirmed. `seon::entity_builders::build_email_entities`
  deserializes `AccountPresence.name` for every registered platform (facebook, twitter,
  linkedin, github — the `PERSON_PLATFORMS`) but minted a single `Person` via a
  `find_map` (line 116) that returned the FIRST platform whose name is non-empty, ≥3
  chars, and contains a space. So when SEON reports different self-reported name variants
  across platforms (facebook `Jon Smith`, linkedin `Jonathan A. Smith`, google `J Smith`),
  only the first surfaced — the fuller/alternate legal-name variants, genuine identity
  data, were silently discarded and never stamped on evidence. Fix: emit one `Person` per
  DISTINCT name (keyed by lowercased value in a deterministic `BTreeMap`), tagged with
  ALL platforms that reported it, evidence listing them; the same name on several
  platforms dedups to one Person carrying every platform tag. Test delta:
  `email_emits_a_person_for_each_distinct_reported_name` (facebook+twitter `Jon Smith`,
  linkedin `Jonathan A. Smith`, github `jsmith` → two distinct `Person`s, the shared name
  tagged both platforms, the space-less handle excluded; fail-before: one Person); the
  existing single-name Person test still passes. Gate green: fmt/clippy/doc clean, full
  suite 0 failures (4561). **Paired:** `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **Full-fidelity: AU-049 / AU-050 capped the reachable email/phone
  handles in their `entity_uids` at 8.** Fidelity-audit-workflow-confirmed (LOW). The
  shared-address (AU-049) and shared-phone (AU-050) association rules build the
  correlation's `entity_uids` in `Group::firing_uids()`, which did
  `uids.extend(self.handle_set.iter().take(8).cloned())` — a silent cap on the ACTUAL
  linkage the finding asserts (not a display string), so a household / share-house with
  more than 8 associated email/phone handles at one residence or on one line had handles
  9+ dropped from the finding, with no count surfaced. The comment showed the `.take(8)`
  was a bound a refactor merely preserved, not a deliberate DoS cap (unlike AU-037, which
  documents its truncate caps AND prints the full totals; the sibling AU-051 applies no
  handle cap at all). Fix: emit every reachable handle uid (`handle_set` is a `BTreeSet`,
  so they stay sorted/deterministic). Test delta:
  `au049_references_every_reachable_handle_not_a_capped_eight` (two persons + 10 emails at
  one residence → all 10 handle uids referenced; fail-before: 8). Gate green:
  fmt/clippy/doc clean, full suite 0 failures (4562). **Paired:** `SOLUTION_TREE` §5 —
  same commit. **This closes the fidelity-audit arc**: all 7 distinct confirmed
  silent-fidelity violations (register scrapers, netlas SAN/emails, niamonx ULP login,
  entities_filtered LIMIT, SEON names, AU-049/050 handles) are fixed.
- **2026-07-04** — **Full-fidelity: `github_user` capped the subject's own SSH public-key
  Credential entities at `.take(10)`.** Found by a direct post-audit grep sweep of the
  remaining `.take(N)` sites (not the 5-finder workflow, which did not reach it). The
  `fetch_ssh_keys` module read all of GitHub's `/users/{login}/keys` (the subject's own
  published keys — no false-attribution risk) but the emit loop did
  `result.extend(keys.iter().take(10).filter_map(...))`, silently dropping keys 11+ so they
  never became fingerprinted `Credential` artifacts. Each SSH public key is an independent
  AU-048 cross-account cryptographic pivot (the same key on two accounts proves one
  private-key holder), so the cap discarded exactly the strongest cross-account evidence the
  module exists to surface; a developer commonly registers more than ten keys. The sibling
  display evidence already surfaces the true `ssh_key_count` and a five-key sample (a
  JUSTIFIED, count-carrying sample — left intact), so only the correlatable-artifact path
  was lossy. Fix: extracted the `SshKey` row struct to module scope and a pure
  `ssh_key_entities(keys, scan_id, login)` that emits every parsed key (malformed/empty
  bodies still dropped by `ssh_fingerprint`, represented by omission, never a placeholder);
  `fetch_ssh_keys` now calls it. Test delta:
  `ssh_key_entities_emits_every_key_not_a_capped_ten` (15 distinct keys → 15 distinct
  Credential uids; fail-before: 10) plus a mixed valid/malformed/null case. Gate green:
  fmt/clippy/doc clean, full suite 0 failures (4563). **Paired:** `SOLUTION_TREE` §5 —
  same commit.
- **2026-07-04** — **Full-fidelity: `github_user` capped the subject's own commit-author
  emails at `.take(10)`.** Sibling of the SSH-keys cap, in the same module's `fetch_events`.
  The subject's public push events embed the `git` author email of each commit — one of the
  most reliable real-email→handle links in OSINT — and the module deduped them then emitted
  via `.take(10)`. My prior-cycle note had deferred this as a "false-attribution control,"
  but re-reading the code that was wrong: the comment says the cap is merely "to keep a busy
  account bounded," and it does NOT discriminate co-author addresses from the subject's (it
  applies identically to emails 1–10), so it is a silent resource bound, not a precision
  gate. It also has no real resource justification — the endpoint is already bounded to 30
  events (`per_page=30`), so the distinct-email set is naturally small. Result: distinct,
  real, subject-published addresses 11+ were silently dropped. Fix: moved the `GhEvent`/
  `GhPayload`/`GhCommit`/`GhCommitAuthor` structs to module scope and extracted a pure
  `commit_email_entities(events, scan_id, login)` that emits every DISTINCT usable address
  (dedup by normalised value; GitHub noreply/placeholder forms still dropped by
  `usable_commit_email` → absence by omission, never a placeholder; first-seen order over
  the newest-first event stream is deterministic). The evidence label ("Email from
  @{login}'s public commit author field") keeps provenance honest — it does not claim the
  address IS the subject — so surfacing every one adds fidelity without over-attributing.
  Any genuine co-author-attribution concern is a separate precision question (it would need
  an author-matches-login filter, which `.take(10)` never provided) and is not conflated
  here. Test delta: `commit_email_entities_emits_every_distinct_email_not_a_capped_ten` (15
  events, 15 distinct emails → 15 pivots in deterministic order; fail-before: 10) plus a
  dedup + placeholder-drop case. Gate green: fmt/clippy/doc clean, full suite 0 failures
  (4564). **Paired:** `SOLUTION_TREE` §5 — same commit.
- **2026-07-04** — **Full-fidelity: five social modules capped bio-extracted emails AND URLs
  at `.take(5)` each.** `bluesky_user`, `reddit_user`, `mastodon_user`, `lobsters` and
  `devto` each ran the identical copy-paste block: `extract::emails(bio).take(5)` and
  `URL_RE.find_iter(bio).trim_end_matches(…).dedup.take(5)`, silently dropping distinct
  emails/links 6+ from a profile bio (a link-tree-style bio genuinely lists many URLs). The
  cap is a copy-paste artifact, not a principled bound: the SAME codebase extracts emails
  from gist bodies and crawled pages *uncapped* (`github_user::fetch_gist_content`,
  `web_crawler`), and `reddit_user`'s own comments say "extract ALL emails/URLs" directly
  above the `.take(5)` that contradicts them. Since a bio is a small bounded field, the cap
  protects nothing the field size doesn't already. Fix (single logical change, §3
  single-sourcing): added a tested `util::extract::urls(text) -> Vec<String>` mirroring the
  existing `emails()` (trailing-punct-trimmed via `URL_RE`'s documented over-match, deduped
  on the trimmed value, first-occurrence order, **no cap**), then routed all five modules'
  bio scanners through `emails()` + `urls()` uncapped — deleting the ten `.take(5)` sites
  and the now-redundant per-module `seen_urls`/`trim_end_matches` loops (and three unused
  `URL_RE` imports). Each module keeps its own skip-list/confidence/entity emission. Test
  delta: `urls_extracts_all_distinct_trimmed_in_order_uncapped` (six distinct link-heavy-bio
  URLs, trimmed + deduped, in order; fail-before: a capped five); all five modules' existing
  tests still pass. Gate green: fmt/clippy/doc clean, full suite 0 failures (4565).
  **Paired:** `SOLUTION_TREE` §5 — same commit.
- **2026-07-05** — **Executed T2.15.** A fresh code-grounded discovery pass across the
  storage layer (post-fidelity-audit-arc) found every multi-row reader in `storage/`
  chaining a bare `.filter_map(...ok())` at both the SQL-extraction and JSON-deserialize
  layers — 8 sites across `list_scans`, `correlations_for_scan`, `relations_for_scan`,
  `events_for_scan`, `entities_for_scan`, `entities_filtered`, and both branches of
  `search_entities` — so a corrupted or schema-drifted row vanished with zero trace, unlike
  `get_scan`/`get_entity` which already propagate the identical failure via `?`. Fix: two
  shared private helpers in `storage/mod.rs`, `collect_rows` and `deserialize_rows`, each
  logging `tracing::warn!(context, error, ...)` before dropping a bad row; wired into all 8
  call sites (four in `storage/mod.rs`, four in `storage/entities.rs` via `super::`). The
  drop-one-bad-row-keep-the-rest behaviour is unchanged — only the missing diagnostic is
  added, so the regression test targets the log, not the (already-correct) output: a scoped
  `tracing` subscriber (mirroring `core::engine::tests`' `VecWriter` pattern) proves the
  warning fires and is keyed by the caller's name (fail-before: the pre-fix bare filter_map
  emitted no log at all), plus an end-to-end `list_scans` test proving a corrupt sibling row
  still doesn't fail the read. Test delta: +3 (`deserialize_rows_drops_corrupt_json_but_logs_
  the_failure`, `collect_rows_drops_sql_errors_but_logs_the_failure`,
  `list_scans_drops_a_corrupt_row_end_to_end_without_erroring`). Gate green: fmt/clippy/doc
  clean, full suite 0 failures (4385 lib tests). **Paired:** `SOLUTION_TREE` §5 — same
  commit.
- **2026-07-05** — **Executed T2.16.** Second item from the same storage-layer discovery
  pass as T2.15: `Store::open`'s owner-only (0600) chmod loop over the db file and its
  `-wal`/`-shm` siblings discarded the `Result` via `let _ = ...`, with no
  `tracing::warn!` — unlike the FTS-rebuild best-effort step ~30 lines earlier in the same
  function, which is explicitly best-effort AND never silent, and unlike T2.15's fix to the
  read paths just above. Since the store holds PII and harvested third-party keys per its
  own doc comment, a failed chmod silently left it at the process umask (often 0644,
  world-readable) with zero signal. Fix: extracted the loop into a private
  `restrict_to_owner_only(paths: &[String])` helper that logs a `tracing::warn!` keyed by
  the failing path on each failure; startup is still never blocked by a chmod failure, only
  made loud. Test delta: +1 (`restrict_to_owner_only_logs_when_a_chmod_fails`, unix-only —
  chmod on a nonexistent path reliably fails without a read-only-filesystem fixture;
  fail-before: the pre-fix `let _ = ...` produced no log at all). Gate green: fmt/clippy/doc
  clean, full suite 0 failures (4386 lib tests). **Paired:** `SOLUTION_TREE` §5 — same
  commit. **This closes the storage-layer discovery-pass arc** (T2.15 + T2.16); the
  remaining item from that pass (no actual migration-application mechanism behind
  `SCHEMA_VERSION`) is already correctly captured as T2.10's own stated P3/advisory
  residual — a version stamp + forward-compat warning were the delivered scope, and
  there is no live non-additive migration to apply yet, so no new node is warranted.
