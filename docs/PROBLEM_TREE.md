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
wrong, what is missing, and exactly how each is to be solved. Update it in the
same commit as the work (status flips + a line in §8 *Maintained log*).
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

Current baseline (grounded in the codebase, 2026-06-17): 118 modules across 14
categories (Infrastructure 20, Geo 19, People 15, DnsRecon 13, Breach 11, Social
10, Email 6, Corporate 6, Web 5, Sensor 4, Threat 3, Search/Phone/Other 2 each);
59 native correlation rules (AU-001…AU-059); 0 `unsafe`; deterministic entity
merge; SQLite store; SSE live; axum SPA. Deps: `regex` in; **`proptest` 1.11 +
`criterion` 0.8 now direct (dev-only, zero shipped cost — F.3); `aho-corasick`,
`memchr`, `bstr`, `fst`, `arbitrary` still NOT direct.**

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
- **`[~]` T1.2 · Throughput (the on-device perf guarantee)** —
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
- **`[~]` T1.3 · Verified correctness — 12 unasserted rules** — AU-019, 020, 022,
  023, 024, 025, 026, 028, 029, 040, 041, 042 are dispatched but **no test
  asserts they fire** (only id-presence is checked). A silently-dead rule passes
  CI.
  → **Solution:** a table-driven suite `[(id, build_fixture_entities, expect:
  {fires, severity, uid_set})]`; one assertion per rule. Add a **meta-guard**:
  every `AU-NNN` in the dispatch `RULES` table must have ≥1 firing fixture (so no
  future rule ships un-pinned). **P1** ◑ **Per-rule half done; meta-guard
  outstanding** (reopened from `[x]` in the 2026-06-17 doc audit): the 12 firing
  assertions shipped (`core/correlator/tests.rs`, each asserting `rule_id` +
  `severity`), so the named rules are pinned — but the meta-guard that forces a
  *future* `AU-NNN` to ship with a firing fixture was never built. The existing
  guards (`every_defined_correlation_rule_is_dispatched`,
  `correlation_rule_ids_match_their_function_number`) check wiring + id-correctness,
  not firing, so a new un-pinned `AU-060` would still pass CI. Stays `[~]` until the
  dispatch-table-enumerating firing meta-guard lands.
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

### 3.F — Tier F · Foundations (build the primitives once; everything after is cheap)

- **`[ ]` F.1 · Adopt the matching/automata toolkit** — parsers and the universal
  key/secret scanner currently hand-roll `.find()`/`.contains()`/`chars()` scans
  (slow, and the source of the T0 panic class).
  → **Solution:** promote **`memchr`** + **`aho-corasick`** to direct deps (free —
  already transitive via `regex`); add **`bstr`** for untrusted HTML. Create one
  `util::scan` module that owns cached `aho-corasick` automata for: the universal
  API-key scanner, HTML marker extraction, placeholder/denylist matching. All
  untrusted-byte scanning routes through it. Benchmark scan MB/s with `criterion`.
  **P1-enabler**
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
  *Remaining (pure optimisation, not correctness):* the genuinely **large** tables
  (OUI ≈30k, AU postcode/suburb) → `fst` for flat-RAM + Levenshtein fuzzy matching.
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
  perf-path API change can't rot them. *Remaining:* `cargo-fuzz` (nightly/libfuzzer
  — gate on a CI lane, not on-device aarch64); widen criterion to the correlation
  pass once a bench-visible entry point exists.

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
- **`[ ]` T2.8 · Unbounded response-body reads (on-device OOM / DoS)** — several
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
  - **HIGH** `modules/smtp_vrfy/mod.rs:280` — `BufReader::read_line` has no byte
    ceiling (only a 5 s timeout); a single newline-less line from a hostile MX
    buffers unbounded into a `String`. → cap with `(&mut reader).take(N).read_line`.
  - **MED** `util/http/url.rs:54` (`json_decode`) — `resp.json::<T>()` reads the full
    body uncapped, unlike its sibling `json_scanned` (which routes through
    `read_json_text` / `JSON_BODY_CAP`). ~24 call-sites inherit the gap (shodan,
    censys, dehashed, zoomeye, onyphe, leakix, …) plus direct `resp.json()` in
    `doh_resolver:310,322` and `wigle/account:95`. → route `json_decode` through
    `read_json_text` (one fix closes ~20 sites); patch the three direct callers.
  - **MED** AU-gov HTML scrapers (`asic_director:287`, `au_electoral:114/136/158/180`,
    `au_people:368/389`, `au_property:125/149/172`) — `resp.text()` uncapped. → route
    through `http::read_body_capped(resp, ~1 MB)` (the pattern `web_crawler` uses).
  - **P3** `modules/hibp/mod.rs:325,428` — `count() as u32` on an untrusted-JSON
    breach vector; clamp before the cast (folds into the T0.3 "trust no input
    number" rule).
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
- **`[ ]` T2.9 · Non-deterministic SQL read-back orderings** — four read queries
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
- **`[ ]` T2.10 · No schema version stamp (latent migration risk)** —
  `storage/mod.rs` evolves the SQLite schema **additively only** (`CREATE TABLE`/
  `INDEX IF NOT EXISTS`; no `ALTER TABLE`, no `PRAGMA user_version`, no version
  table). Fine today and a deliberate design, but there is **no path for a
  non-additive migration** (adding a `NOT NULL`, changing the `correlations`
  UNIQUE key, dropping a column) and no way to detect/upgrade an old on-disk DB —
  a future structural change would silently mismatch existing databases. → set
  `PRAGMA user_version` at create and gate any future structural change on an
  idempotent upgrade ladder. **P3 (latent — no current bug; advisory).**

---

## 4. Capability program — surpass SpiderFoot & Maltego (CAP)

Grounded in the existing modules and the BUILD set of `OSINT_MATRIX_GAP_ANALYSIS`.
Each node: **current → target → solution**. Everything here is built on §3.F
primitives. AU bias and an offensive (active-collection) posture throughout.

- **`[ ]` C1 · Correlation & identity depth — *the Maltego-without-graphs play***.
  *Current:* 59 native rules + deterministic GREATEST-merge identity. *Target:*
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
- **`[ ]` C2 · Performance & scale — *the SpiderFoot play***. *Current:* parallel
  Rust dispatch, no published numbers. *Target:* demonstrably faster than a
  Python engine, on a phone. → **Solution:** with F.3 benches + T1.2 throughput +
  F.2 flat-RAM datasets, publish a reproducible "N selectors, on-device, in T
  seconds, M MB RAM" benchmark; enforce streaming/bounded memory everywhere
  (cap+chunk, never slurp). SpiderFoot (CPython) structurally cannot match
  on-device aarch64 throughput. **CAP-high**
- **`[ ]` C3 · Australian moat (BUILD, AU-biased)** — *Current:* `asic_director`,
  `abn_lookup`, `acnc`, `au_electoral`, `au_property`, `qld_unclaimed`,
  `au_people`, `gleif_lei`, AU phone/carrier/postcode geo. → **Solution
  (roadmap):** G5 harden `smtp_vrfy` (MX/SPF/catch-all → lift free email-verify
  confidence); G9 BYO-key **HLR/CNAM** phone module; **GNAF/AusPost** address
  validation → sharper geo; **AHPRA** health-practitioner register; **ACMA**
  radiocomms/spectrum licences (AU NETINT); fuller **ASIC/ABR** company graph;
  complete state **cadastre/property**; deeper **courts/AustLII**. All free or
  BYO-key, all AU-first. **CAP-high (AU bias)**
- **`[ ]` C4 · NETINT depth** — *Current:* `dns_intel`, `cert_intel`, `crtsh`,
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
- **`[ ]` C5 · GEOINT convergence — *already ahead; widen the lead*** — *Current:*
  multi-source fusion (WiGLE + EXIF + cell + IP + address→coords) with AU-state
  attribution and convergence rules (AU-052/056/057/059). Neither competitor
  does this. → **Solution:** feed more sources into the confidence-weighted
  centroid; tighten the AU bounding-box/state precision; add movement/timeline
  geo; output a single best-estimate **with provenance + a confidence radius**.
  **CAP-med (differentiator)**
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

---

## 5. Execution order (the queue)

1. **T0.1, T0.2** — kill the panics (small, self-contained). *(unblocks T2.7)*
2. **F.1, F.3** — land `aho-corasick`/`memchr`/`bstr` + `proptest`/`cargo-fuzz`/
   `criterion`. *(the substrate; makes 1 permanent and 3+ cheap)*
3. **T1.1, T1.2, T1.3, T1.4** — restore determinism, throughput, verification,
   layering.
4. **F.2** — `fst` datasets *(folds in T2.6 de-duplication)*.
5. **T2.1–T2.9** — robustness/quality (T2.8 unbounded reads + T2.9 SQL tie-breaks
   added by the 2026-06-17 re-audit; T2.8 rides on F.1's capped-read substrate).
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

## 7. Deferred (out of scope here — separate pass)

Indexed only: **Security** (hardcoded default keys `util/keys/constants.rs:137`,
whois-referral SSRF, key-in-URL leaks, cleartext-secret persistence, dossier
perms) · **Privacy/Legal/Licensing** (PII fixture & root `DOSSIER_*.md`, source
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
