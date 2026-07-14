# Huntsman — Unified Tree of Solutions (living document)

> **Paired with [`PROBLEM_TREE.md`](PROBLEM_TREE.md).** The problem tree is organised
> by *what is wrong / missing*; this tree is the **dual**, organised by *what we
> build to make it right*. The point of inverting the axis: a single primitive often
> closes **many** problems at once (boundary-safe scanning kills the whole T0 panic
> class; one capped-read helper closes every unbounded-read site), and that leverage
> is invisible in a defect-ordered list but obvious here. Every solution node
> back-references the `PROBLEM_TREE` node(s) it closes, so the two read as one graph
> from either end.
>
> Shared mission (root of both trees): the fastest, most correct, most
> **reproducible** offensive OSINT / GEOINT / NETINT engine that runs **on-device**
> (Termux, aarch64, no root), with a deliberate **Australian** bias, surpassing
> SpiderFoot (breadth/speed/correlation) and Maltego (entity linking) **without**
> heavy in-app graphing — by delivering the analytic *conclusion* deterministically.

---

## 0. Operating protocol — how the pair stays in lockstep

This is the method the operator asked for: **keep both trees current at all times,
moving between them in alternating fashion, bridged by gap analysis.**

1. **Same-commit rule.** Any change that touches one tree touches the other in the
   *same commit*. A fix flips a `PROBLEM_TREE` status **and** advances the matching
   solution node + its §4 gap line. New problem ⇒ new (or extended) solution node.
   New/finished solution ⇒ re-run gap analysis. Both logs (§5 here, §8 there) get a
   dated line.
2. **The alternation (two directions, run on every pass):**
   - **Problem → Solution (P→S):** for each open/ new problem node, point to the
     solution that closes it. If none exists, that is a **coverage gap** (§4a) — the
     build queue.
   - **Solution → Problem (S→P):** for each delivered/partial solution, ask *what
     does it actually close, and what does it newly expose?* A shipped primitive
     often reveals the next problem (e.g. `spawn_blocking` for reads exposed the two
     write-path handlers it didn't cover). A solution that maps to **no** problem is
     a **speculative/over-build** candidate (§4c) — prune or justify.
3. **Gap analysis is the bridge, not a phase.** §4 is the live diff between the two
   trees: uncovered problems, unfinished solutions, and unjustified solutions. The
   diff *is* the prioritised work queue; when §4a and §4b are empty, the trees agree.
4. **Status legend (shared with `PROBLEM_TREE` §2).** `[ ]` open · `[~]` partial /
   in progress · `[x]` delivered · `[-]` accepted-as-is / won't-build. Leverage tag:
   **⚑ enabler** (closes a *class*, unblocks others) vs **leaf** (closes one node).
5. **Doctrine alignment.** Every solution is chosen per the engineering doctrine in
   `PROBLEM_TREE` §1 (measure-don't-guess · prove-by-exhaustion · finite automata ·
   bytes-not-`String` · bounded memory · minimal pure-Rust deps · determinism ·
   simple data structures). That doctrine *is* the solution palette; §1–§2 below
   instantiate it.

---

## 1. Solution doctrine — the palette (mirrors `PROBLEM_TREE` §1)

The Gallant/`burntsushi` primitives, read as the **means** rather than the rule:

| Primitive | The problem-class it dissolves | Where it lands |
|---|---|---|
| Boundary-safe byte scanning (`memchr`/`aho-corasick`, never offset-on-a-copy) | the T0 `to_lowercase`-slice panic class | SOL-BOUNDARY, SOL-F1 |
| Property + fuzz proof (`proptest`/`cargo-fuzz`) | "untested parser" / silent regressions | SOL-F3 ⚑ |
| Measure, never guess (`criterion`) | unfounded perf claims | SOL-F3 ⚑ |
| `fst` flat-RAM datasets | table drift + RAM on a phone | SOL-F2 ⚑ |
| Determinism by construction (sort-before-emit, SQL tie-breaks, GREATEST-merge) | reproducibility, the product's identity | SOL-MERGE, SOL-ORDER |
| Bounded / streaming memory (cap everything) | on-device OOM/DoS | SOL-CAP |
| Atomic reservations / per-scan isolation | concurrency overspend & contamination | SOL-BUDGET, SOL-ISOLATE |
| Layering guards + hook inversion | architectural rot | SOL-ARCH |
| Loopback + rustls + SSRF filter + 0600 | the security baseline | SOL-SSRF, SOL-SECRETS |

---

## 2. The tree — solutions by leverage tier (means → ends)

### S.FOUND — Foundational primitives ⚑ (build once; everything after is cheap)

- **`[~]` SOL-F1 · Matching/automata toolkit** ⚑ — promote `memchr` + `aho-corasick`
  to direct deps (free via `regex`), add `bstr` for untrusted HTML; one `util::scan`
  owning cached automata for the key scanner, HTML markers, denylists.
  *Closes / powers:* `PROBLEM_TREE` **F.1** (self), the **T0.1/T0.2** panic class at
  the root (not just patched — made structurally impossible), **T2.7** scraper
  rewrites, **T2.8** the capped scanners, **C6** key-harvest precision.
  *Delivered:* the boundary-safe shims (`find_ascii_ci`/`char_window`/`truncate_safe`)
  the T0 fixes used; **+ the substrate (2026-06-17):** `aho-corasick` promoted to a
  direct dep, `util::scan::MatchSet` (cached automaton — `is_match` "contains any" +
  leftmost-`find`, ASCII-CI, boundary-safe offsets) built with tests + a `criterion`
  bench, and the **first consumer** (the SERP anti-bot `is_captcha_page` signature
  scan) routed through it **byte-for-byte equivalent** (5 captcha tests pass); **+2
  more (2026-06-17):** key-harvest `contains_excluded_context` (`new_ascii_ci`,
  drops a hot-path alloc) and wigle `is_generic_ssid`, both proven by existing tests;
  **+ the key-scanner prefix table (2026-06-17, cycle 4):** `util::scan::PrefixMatcher`
  (`LeftmostFirst`, `find_prefix() -> Option<usize>`, anchored at offset 0); two statics
  in `key_harvest` (`PREFIX_MATCHER` + `PREFIX_GROUPS` for same-prefix duplicate entries);
  O(N=170) `starts_with` loop replaced with O(1) dispatch + O(K≤2) group iteration;
  intentional quality improvement (specific-prefix min_len failure no longer cascades
  to a shorter generic prefix); proptest (no-panic + synthesised-token sanity) +
  deterministic cascade-prevention test. **+ `au_electoral` HTML markers (2026-06-17,
  cycle 5):** `MatchSet::find_range` added to `util::scan` (returns `[start, end)` so
  callers skip past a marker without knowing its length); `DIVISION_MARKER` +
  `ENROLLED_MARKERS` statics in `au_electoral/parse.rs` replace three `find_ascii_ci`
  calls; two-pattern enrolled scan is one aho-corasick pass; five tests added.
  **+ `memchr` direct dep + `decode_entities` SIMD byte scan (2026-06-17, cycle 12):**
  `memchr = "2"` promoted to a direct dep (was transitive via `aho-corasick`/`regex`);
  `decode_entities` in `util/html/mod.rs` — the hot entity decoder called on *every*
  scraped response body — replaces `s.contains('&')`, `rest.find('&')`, and
  `inner.find(';')` with `memchr(b'&', …)` / `memchr(b';', …)` SIMD byte searches.
  `&` and `;` are single-byte ASCII so byte offsets equal char offsets in UTF-8 —
  the substitution is correct and boundary-safe. Gate green: 3,032 lib tests, 0 failures.
  *Gap (§4b):* `bstr` (no direct consumer yet → promote with first use).
  Contained — `bstr` promoted only when first directly used (else `cargo machete` trips).
- **`[~]` SOL-F2 · `fst`-backed datasets** ⚑ — `build.rs` compiles `data/*.txt` into
  memory-mapped `fst::Set`/`Map`, one canonical `util::dataset` API.
  *Closes / powers:* **F.2** (self), the **B5.3 table-drift** class, and Levenshtein
  fuzzy matching for typosquat / username-variants / suburb-matching.
  *Delivered:* the **de-dup goal** (T2.6) — drift-prone shared lists single-sourced by
  delegation. *Gap (premise corrected, cycle 18):* the "large table" assumption was
  wrong — Huntsman uses curated subsets (OUI ≈111 entries, AU postcode ≈72 entries,
  phone area codes ≈65 entries), not registry-scale tables; `fst` is overkill at these
  sizes and adds a heavy compile dep for no on-device benefit. `fst` adoption `[-]`
  (accepted-won't-build). Levenshtein fuzzy matching (suburb/username-variant) remains
  a future capability goal but can be pursued via a lighter mechanism.
- **`[~]` SOL-F3 · Proof & measurement infrastructure** ⚑ — `proptest` properties for
  every pure fn, `cargo-fuzz` for every untrusted parser, `criterion` for the hot
  paths; CI compiles benches + runs corpora.
  *Closes / powers:* **F.3** (self) and the *entire* "untested/unmeasured" class — it
  is the guard that keeps **T0.x/T1.1/T1.3/T2.3/T2.8/T2.9** from regressing.
  *Delivered:* `proptest` (boundary-safety, `normalise` idempotency, `Entity::merge`
  GREATEST-laws, geo round-trips, no-panic crash-resistance for every network parser)
  + `criterion` (`benches/scan_throughput.rs`). *Gap:* `cargo-fuzz` (nightly CI lane)
  and the dossier/txt/html **import** proptest are outstanding. **(§4b)**

### S.CORE — Correctness & determinism

- **`[x]` SOL-BOUNDARY · Boundary-safe string ops** — `util::str_util::find_ascii_ci`
  (offset valid in the original), `char_window`, `truncate_safe`, `floor/ceil_char_
  boundary`. *Closes:* **T0.1, T0.2** (+ the search_engines instance). Machine-checked
  by SOL-F3 proptests. ✅ delivered.
- **`[x]` SOL-MERGE · GREATEST-semantics identity merge** — `Entity::merge`/`absorb`:
  clamped-max confidence, saturating corroboration, lexicographic-min canonical
  spelling; UID = `SHA-256(kind:normalised)`. *Closes:* **T1.1** (the determinism
  core), the identity model behind **C1**. Order-independence proptested. ✅
- **`[x]` SOL-ORDER · Deterministic emission** — sort-before-emit (GEXF shared-source
  labels, live-session list) **and** a unique final SQL tie-break on every order-
  sensitive read-back (`scans … , id DESC`; `entity_facets … , e.kind ASC`;
  `scan_ids … , scan_id DESC`). *Closes:* **T1.1, T2.9**. Regression-tested
  (`latest_completed_scan_is_deterministic_on_same_second_ties`). ✅
- **`[x]` SOL-PANIC · Per-module panic containment** — `panic="unwind"` +
  `run_module_guarded` `catch_unwind` at the dispatch boundary → a panicking module
  degrades to zero results, never aborts `serve`. *Closes:* FTA **E3.1 / SPOF #2**.
  Combined with SOL-BOUNDARY the trigger class is also gone at the root. ✅
- **`[x]` SOL-ARCH · Architecture guards + hook inversion** — `core::hooks` fn-pointer
  registry inverts the `core→modules` edge; `tests/architecture.rs` guards
  `core→util`, `core→storage`, `core→modules`, `modules→engine/storage`, the registry,
  the README/MODULES counts, and AI-independence. *Closes:* **T1.4**. *Shaped*
  SOL-ISOLATE: the guard's documented-leaf allowlist is exactly how the engine got
  to scope the `util::found_keys` task-local (`with_scan`) without a layering breach. ✅
- **`[x]` SOL-RULE-METAGUARD · Correlation rule firing coverage** — direct firing
  tests for every dispatched correlation rule (`AU-021` one `ApiKey` entity → 1
  `Critical` finding; `AU-030` two `Coordinates` entities with 3 distinct sources →
  1 `Medium` finding — the only two of 56 rules without a prior direct assertion) +
  `every_dispatched_correlation_rule_has_a_firing_test` in `tests/architecture.rs`
  (enumerates all `rule_au_*` entries in `RULES` + `RELATION_RULES`; accepts either a
  direct `fn`-name + non-zero `len()` assert within ±15 lines, or an indirect
  `"AU-NNN"` reference on a line with `assert`/`unwrap`/`expect`/`contains(`).
  *Closes:* **T1.3** (all 56 dispatched rules proven to fire on their nominal input;
  guard rejects any future unmapped rule at CI time). ✅ delivered (cycle 8).
- **`[x]` SOL-OUTPUT-ESCAPE · Context-correct output encoding** — `esc()`/`attr()`
  (HTML), `extLink()` (href + scheme gate), CSV formula-defang; the SPA renders
  attacker values via `data-` attributes read with `this.dataset`, never a JS-string
  literal in an inline handler. *Closes:* the **§7 SPA stored XSS** (fixed). ✅

### S.RESOURCE — Concurrency, throughput & resource safety

- **`[x]` SOL-BLOCKING · Keep the 2-worker reactor unblocked** — `spawn_blocking`
  the heavy sync `Store`/render handlers; a dedicated **DB-writer actor**
  (`core/engine/writer::DbWriter`) owning the `insert_event` call path behind an
  unbounded `mpsc`. *Closes:* **T2.2** (done, incl. the debug-bundle `curl`),
  **T1.2** (fully closed — all write paths off the reactor). *+SOL-BLOCKING-EXTEND
  (2026-06-17):* `scan_import` now acquires `scan_semaphore` before parsing (mirrors
  `spawn_scan` throttle) and dispatches all sync DB work (`upsert_scan`,
  `upsert_entities_batch`, `derive_all`, `Correlator::run`) to `spawn_blocking`;
  `stats` wraps `list_scans(10_000)` in `spawn_blocking`. *+SOL-BLOCKING-ENGINE
  (2026-06-17):* `EventEmitter::emit` (`core/engine/mod.rs:152`) clones the
  `Arc<StoragePort>` and wraps `store.insert_event(&event)` in
  `tokio::task::block_in_place` — the per-entity blocking rusqlite write now leaves
  the async reactor. `tests/halting.rs` + `tests/smoke.rs` (45 async tests total)
  upgraded from `current_thread` to `(flavor = "multi_thread", worker_threads = 2)`
  to match production and avoid the `block_in_place`-on-single-thread panic.
  *+SOL-BLOCKING-ACTOR (2026-06-17, cycle 10):* `block_in_place` per entity replaced
  by `core::engine::writer::DbWriter` — an unbounded-mpsc tokio task draining the
  queue in `spawn_blocking` batches (≤64 events per call); `EventEmitter::emit`
  becomes a non-blocking `submit`; `run_with_ledger_inner` calls
  `writer.flush().await` after `finalise_scan` so all events (including ScanComplete)
  are durably written before the scan is returned. T1.2 `[~]`→`[x]`. ✅ fully closed.
- **`[x]` SOL-FINALISE-BLOCKING · `finalise_scan` off the async reactor** —
  `finalise_scan` made `async fn`; body dispatched to `tokio::task::spawn_blocking`
  capturing `Arc::clone(&store)`, `emitter.clone()`, and a `cancelled` bool snapshot
  (CancellationToken is not `'static` and cannot cross the closure's `'static` bound).
  `persist_relations` and `run_correlator` inlined into the closure (both had single
  call-sites; removed as methods). *Closes:* **T1.5** (`[ ]`→`[x]`). ✅ cycle 14.
- **`[x]` SOL-SCHEMA-VERSION · DB schema version stamp** — `const SCHEMA_VERSION: i32
  = 1` in `src/storage/mod.rs`; `Store::open` reads `PRAGMA user_version` after the
  DDL batch: `ver < SCHEMA_VERSION` → stamp (fresh or pre-versioned DB); `ver >
  SCHEMA_VERSION` → `tracing::warn!` (forward-compat signal — a newer binary wrote
  this DB). Provides a migration ladder for future non-additive schema changes without
  requiring an explicit migration table. *Closes:* **T2.10** (`[ ]`→`[x]`). ✅ cycle 16.
- **`[x]` SOL-STORAGE-DIAG · Multi-row storage reads log, not just drop, a
  corrupt row** — two shared private helpers in `src/storage/mod.rs`,
  `collect_rows` (SQL-extraction layer) and `deserialize_rows` (JSON layer),
  each `tracing::warn!`-logging the row's caller-supplied context and the
  underlying error before dropping it; every multi-row reader across
  `storage/mod.rs` and `storage/entities.rs` (`list_scans`,
  `correlations_for_scan`, `relations_for_scan`, `events_for_scan`,
  `entities_for_scan`, `entities_filtered`, `search_entities`'s FTS and LIKE
  paths — 8 sites) rewired onto them, replacing a bare
  `.filter_map(...ok())` that swallowed a corrupted/schema-drifted row with
  no trace. Brings multi-row reads to the same diagnostic standard the
  single-row getters (`get_scan`, `get_entity`) already had via `?`. *Closes:*
  **T2.15** (new). ✅ 3 tests: a scoped-subscriber (`VecWriter`, mirroring
  `core::engine::tests`) proof for each helper that the drop is both kept AND
  logged, plus an end-to-end `list_scans` proof a corrupt sibling row still
  doesn't fail the read.
- **`[x]` SOL-CHMOD-DIAG · The store's owner-only chmod now logs, not just
  swallows, a failure** — `Store::open`'s 0600 restriction loop over the db
  file and its `-wal`/`-shm` siblings discarded the `Result` via `let _ =
  ...`, unlike the FTS-rebuild best-effort step in the same function, which
  is explicitly best-effort AND never silent. Extracted a private
  `restrict_to_owner_only(paths: &[String])` helper that logs a
  `tracing::warn!` keyed by the failing path on each chmod failure; startup
  is still never blocked by it. *Closes:* **T2.16** (new). ✅ 1 test
  (`restrict_to_owner_only_logs_when_a_chmod_fails`, unix-only — a chmod on a
  nonexistent path reliably fails without a read-only-filesystem fixture).
- **`[x]` SOL-LATEST-SCAN-ERR · `latest_completed_scan` propagates a corrupt
  row as `Err`, not a misleading `Ok(None)`** — a follow-up grep sweep of
  `storage/mod.rs` (checking on an unresolvable background "fourth discovery
  pass" agent) found `latest_completed_scan` doing
  `stmt.query_row(...).ok()` then `.and_then(|s|
  serde_json::from_str(&s).ok())`, collapsing "no complete scan exists," "a
  genuine SQL error," and "the matched row's JSON is corrupt" into the same
  `Ok(None)` — unlike the sibling `get_scan`, which already propagates the
  identical failure via `?`. `resolve_scan_id` (`cli/mod.rs`, backing `hse
  export/diff/audit latest` and the SPA's "open latest scan") turns that
  `None` into "no completed scans in store," so a corrupted MOST-RECENT
  complete scan was misreported as an empty store. Rewrote it to mirror
  `get_scan`'s `rows.next()?...transpose()?` / `.map_err(Into::into)`
  structure exactly. *Closes:* **T2.17** (new) — this is a real wrong-result
  bug, not just a missing diagnostic like SOL-STORAGE-DIAG/SOL-CHMOD-DIAG. ✅
  1 test
  (`latest_completed_scan_errors_loudly_on_a_corrupt_row_instead_of_reporting_none`).
- **`[x]` SOL-EXPOSURE-DOB · `core::exposure`'s `DOB_KEYS` recognises
  Wikidata's own DOB spelling** — a direct follow-up on the previous cycle's
  logged "three independently-drifted DOB-key vocabularies" observation.
  `wikidata::builder` stamps a Person's date of birth as `birth_date` (its own
  canonical spelling, confirmed by direct grep), but `DOB_KEYS =
  ["date_of_birth", "dob"]` — whose own doc comment claims it tracks "the
  canonical keys the breach/dossier producers stamp" — never matched it, so a
  Wikidata-sourced DOB silently scored zero toward the Sensitive PII
  component (verified `GOV_ID_KEYS`/`FINANCIAL_KEYS` have no analogous gap —
  `oathnet_pro`'s producer-side normalisation tuples already resolve every
  raw provider spelling to the canonical keys those lists expect). *Closes:*
  a small standalone gap surfaced by, but distinct from, C1 (new node
  **T2.18**, not folded into C1 since the Exposure Index is a separate
  subsystem). ✅ 1 test
  (`sensitive_pii_recognises_wikidata_birth_date_spelling`). The broader
  3-way unification (with `breach_pii::DOB_KEYS`'s import-facing 8-spelling
  list) remains deferred — a real design decision, not mechanical.
- **`[x]` SOL-FILTER-CANDIDATE-LEAK · `/entities/filter` now applies the same
  candidate quarantine every sibling entity-listing endpoint enforces** — a
  background-agent discovery pass found `scan_entities_filter` never called
  `wants_candidates()` nor retained out `CANDIDATE`-tagged rows, unlike
  `scan_entities`, `scan_entities_csv`, `report.json`, and GEXF export, and
  `entities_filtered` has no tag-based `WHERE` clause to compensate — the same
  PII-leak shape as the GEXF candidate-node leak fixed 2026-07-04, on a route
  that fix didn't touch (confirmed by `git log -S"wants_candidates"`: the
  quarantine was retrofitted onto three read paths but never this
  pre-existing one). *Closes:* new node **T2.20**. ✅ 1 test
  (`scan_entities_filter_quarantines_candidate_entities_by_default`), fail-
  before confirmed (revert → test fails; diff-verified restore → test
  passes).
- **`[-]` SOL-BUDGET · Atomic quota reservation (accepted-as-is)** —
  `QuotaBudget::try_increment` (CAS, saturating session rollback) replaces every
  racy `remaining()`-then-`increment()`. *Closes:* **T2.11** (oathnet — done;
  mirrors see_know). *Gap re-assessed (cycle 18 S→P):* the cited residual —
  per-scan `reset_scan`-zeroing across concurrent scans — was based on a faulty
  premise: `reset_per_scan` is already called at `run_with_ledger_inner:289` on
  every scan start (verified cycle 18). The session ceiling bounds concurrent
  increments. Accepted `[-]`; no further action on the budget-statics path.
- **`[x]` SOL-CAP · Bounded / streaming reads** — `read_body_capped` /
  `read_json_text` (`JSON_BODY_CAP`), reqwest read-timeout backstop, the `exif_geo`
  `bytes_stream()` accumulate-and-bail, the `smtp_vrfy` 8 KiB line cap via
  `fill_buf`/`consume`. *Closes:* **T2.1** (timeouts), **T2.8** (all sub-items ✅).
  **+SOL-CAP-EXTEND (2026-06-17):** `json_decode` routes through `read_json_text`
  (closes ~24 uncapped MED sites ✅); nine AU-gov scraper `resp.text()` sites →
  `read_body_capped(resp, 1_000_000)` ✅; hibp `count() as u32` casts →
  `u32::try_from(…).unwrap_or(u32::MAX)` ✅. **+SOL-CAP-CLOSE (2026-06-17):**
  `cli/import/mod.rs:24` `read_to_string` now gated by `metadata().len()` check
  against `MAX_IMPORT_BYTES = 16 MiB` before read — T2.8 LOW closed. ✅ All T2.8
  sub-items done; **SOL-CAP is `[x]`** (T2.8 `[~]`→`[x]`).
- **`[x]` SOL-ISOLATE · Per-`scan_id` state isolation** — the `found_keys` sink is
  keyed by `scan_id` via a `tokio::task_local` (`SCAN`) the engine sets around
  `run_with_ledger` **and** each spawned dispatch task (task-locals don't cross
  `spawn`); `scan_body` reads the ambient, `reset`/`drain` key on it. *Closes:*
  **T2.11 found_keys** — the headline open item. ✅ The layering tension was resolved
  by allow-listing the **pure, no-I/O** `with_scan` leaf in
  `core_does_not_import_util_directly` (the established pattern — *not* by threading
  `scan_id` through the util HTTP layer). Isolation regression test +
  `key_chaining_{sequential,concurrent}_dispatch` integration tests green; no
  single-scan regression. *Residual (stale, corrected 2026-07-05):* this entry
  originally flagged the per-scan **budget** statics' `reset_scan`-zeroing as a
  pending follow-on — but SOL-BUDGET's own re-assessment the very next day
  (cycle 18) found that residual was a faulty premise (`reset_per_scan` already
  runs at every scan start) and accepted it `[-]`, with no further action
  needed. This note was never updated to reflect that, so it kept describing
  closed-out work as outstanding; see SOL-BUDGET for the actual disposition.
- **`[x]` SOL-LIVE-DISPATCH-BUDGET · Live `max_entities` check inside the
  concurrent spawn loop** — `dispatch_target_concurrent`'s Phase-2 loop now calls
  `JoinSet::try_join_next` (non-blocking) at the top of every iteration, absorbing
  any sibling module that already finished before re-checking the `max_entities`
  cap; a new `absorb_dispatch_outcome` helper does the archive+finalise work
  shared with the trailing blocking `join_next` drain, so a result is finalised
  exactly once regardless of which loop collects it. *Closes:* **T2.11 LOW
  bounded over-dispatch** (the sequential path already re-checked fresh per
  module — this brings the concurrent path to parity). Regression test
  `concurrent_dispatch_stops_near_max_entities_not_after_the_full_module_set`
  (`max_concurrent: 1` forces the interleave deterministically) fails against
  the pre-fix code (all 10 accepting modules dispatch) and passes against the
  fix. *Residual:* the budget-static `reset_scan`-zeroing (SOL-BUDGET's
  accepted-`[-]` note) is untouched by this change.

### S.SECURITY — Security controls (paired with `PROBLEM_TREE` §7)

- **`[x]` SOL-SSRF · Egress SSRF defence** — `SsrfResolver` DNS filter +
  private-IP redirect guard + curl IP-pin on the **HTTP** client. *Closes:* the
  reqwest-path SSRF (verified sound, §6). *Gap:* the **raw whois TCP/43** path
  bypasses it — see SOL-SSRF-WHOIS. **(§4a)**
- **`[x]` SOL-SSRF-WHOIS · Validate whois referrals** — `client::resolve_public_whois`
  parses `host:port` (incl. `[v6]:port`), refuses non-43 ports + `is_local_domain`
  hosts, resolves to a public `!is_private_addr` address, and returns a **pinned**
  `SocketAddr` (no resolve-then-connect rebind); `client::query` is generic so the
  referral dials the pinned address while IANA keeps the trusted constant.
  *Closes:* **§7 S2** (HIGH, contained). ✅ Behaviour-preserving (real referrals are
  public `:43`); hermetic regression test `blocks_ssrf_and_non_whois_referrals`.
- **`[x]` SOL-SECRETS · Secrets at rest** — `util::atomic_file::write` (0600 +
  unique-temp + `sync_all` + atomic rename) covers `.huntsman.env`, `key_pool.json`,
  `raw/`; **+ SOL-SECRETS-EXTEND (2026-06-17):** new `atomic_file::{create_dir_private
  (0700), set_private (0600)}`; the auto-dossier now writes 0600 in a 0700 dir,
  `~/.huntsman` is 0700, and `Store::open` `set_permissions(0o600)`s the DB +
  `-wal`/`-shm`. *Closes:* **§7 S3** + the env/pool/archive perms. ✅ tests
  `create_dir_private_is_0700_and_set_private_is_0600`,
  `open_restricts_the_db_file_to_owner_only`. *Deliberate boundary:* explicit
  `hse export -o <path>` respects the user's umask (their chosen, often-shared
  destination).
- **`[x]` SOL-REDACT · Credential redaction** — `redact_credentials` (param + literal
  `HUNTSMAN_*` passes) on error bodies/URLs; only `key_tail` (last-4) is ever logged.
  *Closes:* the key-in-URL **log** exposure (S4 mostly mitigated). *Gap (closed
  2026-07-12):* the archived success body isn't run through
  `redact_literal_secrets` on disk — and, investigated this cycle, that is a
  **deliberate operator policy** (`util::raw_archive`'s own doc comment: "never
  encrypted, hashed, or redacted" for the paid-data retention archive), not a
  gap to close by touching the archive file. The residual EXPOSURE was instead
  in the dossier's rendering of that archive: `cli::export::renderers::
  render_full`'s "RAW SOURCE RECORDS" section pretty-printed the raw body
  verbatim with no masking, and while the auto-written dossier is 0600, an
  explicit `hse export -o <path>` is deliberately left to the user's umask
  (this same node's note above) — so an upstream provider echoing our
  `api_key=…` back in its response body could ride a shared/exported dossier
  out to a world-readable file. Fixed at the render site, not the archive: new
  `render_raw_response_body` runs `redact_credentials` over the pretty-printed
  body before embedding it, leaving `raw/*.json` on disk byte-for-byte
  untouched. **§7 S4** ✅ fully closed.
- **`[x]` SOL-INSTALL-INTEGRITY · sha256 sidecar required for auto-discovered prebuilt** —
  `_validate_prebuilt` in `install.sh` accepts a second arg `require_sha` (default 1 for
  auto-discovered binaries, 0 for explicitly-set `HSE_PREBUILT`). When `require_sha=1`:
  `sha256sum` absence or missing/empty/mismatched sidecar → `log_warn` + skip (no
  silent trust of an unverified binary). `maybe_use_prebuilt` passes `require_sha=0`
  when `HSE_PREBUILT` is set (user explicitly nominated the path — lower risk), `1`
  otherwise. Closes the gap where another app could plant an unsigned binary in
  `Downloads`/`/sdcard` and have it run at install time.
  *Closes:* **§7 S5** (`[ ]`→`[x]`). ✅ cycle 16.
- **`[-]` SOL-EMBED · Zero-config embedded keys (accepted by design)** — embedded
  defaults via `ensure_hardcoded_keys`, single-sourced in `constants.rs`, with the
  `SEEKNOW_SUPERSEDED_KEY*` rotate-in-place mechanism so the set **self-heals to
  whatever is live**. *Addresses:* **§7 S1** — *operator directive: keys remain
  hardcoded while functional.* Won't-build (de-embed); the rotate-in-place pattern is
  the standing maintenance for the "if functional" clause. ✅ accepted.
- **`[x]` SOL-BIND · Loopback-only + CSP/CORS/Permissions-Policy** — `127.0.0.1`
  bind, `connect-src 'self'` (blocks exfil even past an injection), loopback
  peer-checks on key/toggle writes. *Closes:* the web-exposure baseline (verified
  sound, §6). ✅

### S.CAPABILITY — Surpass-the-competition program (paired with `PROBLEM_TREE` §4)

- **`[x]` SOL-STREAMING · Streaming/cam/fan/adult platform identity prober** — 42-site
  parallel HEAD/GET username prober across three category buckets (`cam` 16, `fans` 18,
  `adult` 8); `StatusEq(200)` HEAD for platforms with clean 404s; `StatusAndNotBody(200,
  needle)` GET for JS-rendered 200-for-all platforms (OnlyFans, Chaturbate); per-profile
  `Url` entities tagged `cam-profile`/`fans-profile`/`adult-profile` + `platform:<name>`;
  summary `Username` entity with `cam-identity-exposed`, `subscription-platform-found`,
  `adult-profile-found`, `high-streaming-exposure` (≥3 platforms) tags; `ModuleCategory::
  Social` (MITRE T1593.001 + T1589.003); priority 108; 16-concurrent semaphore; 30 s
  timeout envelope; `BROWSER_UA` to avoid Cloudflare scoring; 8 unit tests.
  **International expansion (42 sites total):** Runetki/Boosty (Russia/CIS),
  Cherry.tv/4Based (Eastern Europe), Mym (France/Francophone), MyDirtyHobby (Germany),
  JustForFans (LGBTQ+ intl), OhMyFans (Spanish LATAM), Cam.tv (Italy/Europe),
  Unlockd (UK), SuicideGirls (global alt), Iwara (Japan/3D).
  *Closes / powers:* **C8** (webcam/fan/adult platform presence including non-English
  markets — the identity surface `username_search` left uncovered). ✅ delivered.
- **`[~]` SOL-CORR · Correlation & identity depth** → **C1** (Maltego-without-graphs):
  transitive identity closure (property-tested convergence), a text "Connections"
  dossier section, first-class timeline, AU-0xx rule-gap fill. Built on SOL-MERGE.
  *Delivered (cycle 26):* the canonical `core::relation::identity_paths` primitive
  (deterministic shortest typed paths between identity entities, order-independence
  proptested) now backs **both** AU-060 transitive identity closure (refactored to
  delegate — one finder, no drift) **and** a new dossier **CONNECTIONS** section
  that renders the shortest typed thread between identities as text. *Remaining:*
  first-class timeline output + further AU-0xx rule-gap fill.
  *Delivered (cycle 27, 2026-07-05) — partial progress on timeline output:*
  `core::timeline::classify` recognises 8 more live evidence-attribute keys
  (verified via direct grep against `src/modules/`, not speculative) that
  first-party modules already stamp but the timeline silently never surfaced —
  `account_created`/`joined_at`/`discord_created_date`/`discord_created_unix_ms`/
  `uuid_created_date` → `AccountCreated` (previously unreachable dead code —
  the variant existed with a serde label but no key ever produced it),
  `birth_date` → `DateOfBirth`, `death_date`/`verified_at` → `Generic`,
  `first_pulse_created` → `FirstSeen`. *Remaining:* further AU-0xx rule-gap
  fill; the "controller behind reused secrets" link facet (needs a new
  `RelationKind` + a visibility decision on the correlator's private `Secret`
  primitive — assessed this cycle, too large for one commit); a
  single-sourcing follow-on for the three independently-drifted DOB-key lists
  (`breach_pii`, `exposure`, `timeline`) found during this investigation.
  *Delivered (cycle 28, 2026-07-05) — the reused-secret link facet.* New
  `RelationKind::SharesSecretWith` — the graph-native counterpart of the
  AU-047/AU-048/AU-106 "controller behind reused secrets" correlations.
  Widened the correlator's own `Secret`/`Secret::classify`
  (`rules::breach`) and `canonical_handle` (`rules::mod`) to
  `pub(in crate::core)`, re-exported from `correlator::mod` mirroring the
  already-established `gap_fill_probes`/`multipath_corroborated_links`
  pattern in the same file — Rule 4, one classifier, so the graph edge and
  the correlations can never disagree on admission. New
  `core::relation::builders::derive_reused_secret_link`, wired into
  `derive_all`, reuses `emit_pairwise` to emit a full pairwise clique (not a
  hub-and-spoke chain) over every identity entity a qualifying secret's
  evidence names. Updated the two exhaustive `RelationKind` matches in
  `core::network` the new variant forced. *Remaining:* only further AU-0xx
  rule-gap fill — the last of C1's four sub-items.
  *Delivered (2026-07-12) — the cycle-27-noted DOB-key single-sourcing
  follow-on, 2 of 3 lists:* `core::exposure`'s own `DOB_KEYS`/`GOV_ID_KEYS`
  had drifted to a narrow subset (3 of 9 DOB spellings; 5 of 22
  government-ID spellings) of `breach_pii`'s canonical AU-073/AU-074
  vocabularies, silently undercounting the exposure score for breach records
  using an un-mirrored spelling. `breach_pii` promoted to `pub(crate)`
  (mirroring `location`'s existing re-export pattern) and `exposure` now
  references `breach_pii::DOB_KEYS`/`GOV_IDS` directly — one canonical list
  each, structurally unable to drift again. `timeline::classify`'s list stays
  separate on purpose (a first-party-module-only event-reconstruction
  concern; several of `breach_pii`'s spellings are import-only and would
  wrongly fire reconstructed-DOB timeline events off arbitrary third-party
  breach dumps). 2 new regression tests, confirmed via `git stash` to fail
  against the pre-fix `exposure` module and pass against the fix.
  *Delivered (2026-07-12) — a sibling drift found while closing the above:*
  `core::exposure`'s Financial flag (`FINANCIAL_KEYS`) only recognised the
  bare `bank_account` spelling; AU-104's own `BANK_ACCOUNT_KEYS` in
  `breach_pii` has 4 more (`account_number`/`account_no`/`acct_number`/
  `acct_no`) that were never mirrored. `BANK_ACCOUNT_KEYS` promoted to
  `pub(crate)`; `exposure` now checks it directly alongside its own
  remaining `iban`/`card_number` literals, which correctly stay separate
  (AU-104 is BSB/domestic-account-number scoped, no card/IBAN concept at
  all). 1 new regression test, confirmed via `git stash` to fail pre-fix and
  pass post-fix.
  *Delivered (2026-07-13) — the `Cidr` rule-gap named in cycle 30's search,
  closing C1's last named thread:* new AU-112
  (`rule_au_112_shared_cidr_infrastructure`) reuses `util::spf`'s existing
  `Ipv4Cidr`/`Ipv6Cidr::contains` (built for SPF parsing, overflow-safe,
  tested) rather than re-implementing CIDR-containment maths — the exact
  prerequisite cycle 30 flagged as missing. An independently-discovered
  `IpAddress` entity found inside a `Cidr` entity from the same scan is a
  shared-hosting-infrastructure signal (Medium, infra not ownership), gated
  to narrow blocks (`/22` IPv4, `/48` IPv6) so a broad ISP/cloud allocation
  can't manufacture noise, and skipping pairs `netblock`'s host-expansion
  already makes explicit via its `cidr` evidence attribute. Added
  `prefix_len()` to both `util::spf` CIDR types and one new
  `core_does_not_import_util_directly` allow-list entry for `util::spf::`
  (same pure/leaf category as `util::geohash`/`util::geometry`). Live-
  verified against real `github.com` infrastructure via `dns_intel`/
  `ripestat`: fired correctly on genuine narrow-block containments
  (`140.82.112.3` in `140.82.112.0/24`), correctly silent on the same scan's
  broader `/17`/`/18` blocks. 6 new tests, 2 confirmed via a neutered-rebuild
  git-stash-style proof to fail pre-fix, pass post-fix. *Remaining:* `Ssid`
  (needs the import-extractor attribution change identified in cycle 30
  first — a two-part change, deliberately not pursued this cycle).
- **`[ ]` SOL-PERF-PUBLISH · Reproducible on-device benchmark** → **C2**: with SOL-F3
  benches + SOL-BLOCKING throughput + SOL-F2 flat-RAM, publish "N selectors, on a
  phone, in T s, M MB".
- **`[~]` SOL-AU-MOAT · Australian collection breadth** → **C3** (AHPRA/ACMA/GNAF/
  fuller ASIC, BYO-key HLR/CNAM). All free or BYO-key, AU-first.
  *Delivered (2026-06-18, cycle 17):* `hlr_cnam` (HLR + CNAM, BYO keys, priority
  138, Phone, Person+Phone entities); `ahpra` (AHPRA register HTML scrape, free,
  priority 86, People); `acma_rrl` (ACMA radiocommunications register, free,
  priority 48, Corporate, T1591.001/T1591.002 override); `trove_au` (NLA Trove
  newspaper archive, BYO `HUNTSMAN_TROVE_KEY`, priority 57, Corporate); `smtp_vrfy`
  hardened (parallel SPF+DMARC, CatchAll 0.50→0.30).
  *Delivered (cycle 20, 2026-06-18):* `austlii` — free AustLII court/legislation
  scraper; `FullName`/`Organisation` → `Url` (court-judgment) + `Organisation`
  (legal-footprint signal); Corporate-9; 125→126 modules, 93 free.
  *Remaining:* GNAF/AusPost; fuller ASIC/ABR graph; state cadastre/property.
- **`[~]` SOL-NETINT · CDN-origin unmasking + asset depth** → **C4**: union subdomain
  discovery, ASN/BGP pivots, passive-DNS/cert-hash origin candidates; v4+**v6**
  `is_cdn_edge_ip` already demotes the noise.
  *Delivered (2026-06-18, cycle 17):* `netlas` (Netlas.io host intel — ports, JARM,
  SSL cert emails, CVEs, ISP, geo; BYO `HUNTSMAN_NETLAS_KEY`; priority 79;
  Infrastructure; `netlas_query` helper + collapsible-if let-chains); `censys`
  priority 35→78.
  *Delivered (confirmed cycle 20 S→P audit):* `securitytrails`
  (`HUNTSMAN_SECTRAILS_KEY`, Domain+IpAddress → Domain, subdomain enum + reverse-IP
  hostnames — was listed as remaining in error); ASN/BGP org/prefix pivots (`bgpview`
  + `ripestat` both present — also listed in error).
  *Remaining:* passive-DNS leg of subdomain union (brute ∪ CT already ship);
  Cloudflare/CDN cert-hash origin-unmasking.
  *Delivered (2026-07-12) — the MX/SPF leg of CDN origin-unmasking, new
  correlator rule AU-111:* built from data two existing modules already
  collect, zero new external dependency. `waf_detect`'s CDN fingerprint
  (`waf-detected` + `waf:<Provider>` tags) combined with `dns_intel`'s SPF
  parse (an `IpAddress` tagged `spf`, given a new structured `domain`
  evidence attribute so the correlator matches it without parsing prose):
  when a domain sits behind one of 8 well-known global anycast CDNs and its
  SPF record authorises a mail-sender IP, that IP surfaces as a
  Medium-severity origin/hosting-network candidate (mail isn't proxied by a
  CDN edge). Deliberately excludes on-premise WAF appliances (F5 BIG-IP,
  Citrix NetScaler, Barracuda, ModSecurity) `waf_detect` also fingerprints,
  where the unmasking assumption doesn't hold. The original sketch's "emit a
  tagged `origin-candidate` IP" is realised as a correlation finding instead
  of a literal entity tag — the same mechanism every other cross-module
  AU-0xx inference in this codebase uses, since a rule function only
  borrows `&[Entity]` and can't retag an entity another module emitted. 5
  new regression tests, confirmed via `git stash` (compile error pre-fix,
  not a silent pass — the rule didn't exist). Gate green: fmt/clippy `-D
  warnings`/rustdoc clean, full suite 0 failures (4590 lib tests, +5).
  *Still remaining:* passive-DNS history; the SSL-cert-hash pivot (needs a
  live TLS handshake + a new provider query type — a materially bigger
  build, correctly left separate).
- **`[x]` SOL-CACHE-INTERSCAN · Inter-scan entity cache** → **C9**: `raw_archive`
  SQLite table (`id TEXT PRIMARY KEY, archived_at INTEGER NOT NULL, ttl_secs INTEGER
  NOT NULL, result_json TEXT NOT NULL`), keyed by `archive_key =
  "module:target_kind:normalised_value"`; `StoragePort::{archive_module_result(key,
  ttl_secs, &[Entity]), lookup_module_result_fresh(key) → Option<Vec<Entity>>}`
  default-no-op trait methods; `Store` SQL implementation in `src/storage/archive.rs`
  (4 unit tests: round-trip, miss, overwrite, TTL=0 immediate-expire); `Module::
  cache_ttl_secs() → u64` (default 0 = always live); `hlr_cnam` + `netlas` override
  to 86400 (24 h); dispatch-layer pre-gate wired in both sequential (before
  `run_module_guarded`) and Phase 2 concurrent (before `acquire_owned`) paths —
  cache hit increments `ModuleStats::cached`, replays archived entities, skips the
  live API call; post-call cache-store when `ttl > 0 && result non-empty`; `Scan::
  modules_cached` counter persisted to scan record. Policy: opt-in per module; zero
  default preserves all current live-query semantics; SOL-ISOLATE task-local
  isolation preserved (cache is a read-only pre-dispatch gate, not a write-path
  bypass). Schema snapshot test updated. ✅ delivered cycle 18.
  *Closes:* **C9** (`[ ]`→`[x]`). Enables operator cost control + revenue model.
- **`[~]` SOL-GEOINT · Confidence-weighted geo convergence** → **C5**: the Weiszfeld/
  Welzl fusion stack (verified correct, §6) widened with more sources + provenance +
  a confidence radius.
  *Partial (cycle 19, 2026-06-18):* `opencellid` standalone first-class module
  delivered — key-gated geo source that enumerates nearby cell towers from a
  `Coordinates` target via the OpenCelliD `getInArea` BBOX endpoint. Emits
  `DeviceId` + `Coordinates` per tower; confidence from accuracy radius;
  `cache_ttl_secs=86400`; ATT&CK T1591.001+T1596. Previously OpenCelliD was an
  internal helper only.
  *Partial (cycle 21, 2026-06-18):* `cell_local` + `hse cells import` delivered —
  free offline peer to `opencellid`. `src/util/cell_db.rs` WAL-mode SQLite
  abstraction; `hse cells` CLI (status/import --file|--country/clear, 50k-batch
  CSV import with GZ decompression via `flate2`); `cell_local` module (free, Geo,
  priority 66, `spawn_blocking` DB query, silent no-op when DB absent). 126→127
  modules, 93→94 free, Geo 20→21.
  *Audit correction (2026-07-01, S→P):* **"provenance radius output" was already
  delivered and this note was stale — two separate drifts, now both closed.**
  (1) Cycle 29 (2026-06-20, `ac9114e4`) added `SynergyFix::radius_km` to
  `au059_synergy_fix` and its own §5 log entry says outright "C5's 'best-estimate
  with provenance + confidence radius' delivered end-to-end" — but the §2 node
  text above (this bullet) was never edited to drop the item from its own
  `Remaining:` line, so the tree contradicted its own log. (2) `d1507539`
  (2026-06-26) then closed the remaining half of the claim — AU-059 only fires
  on ≥2 coordinates across ≥2 source classes, so the common single-signal scan
  still got no headline fix — by adding `best_au_location_estimate`, a 6-rung
  precedence fallback (documented in `CHANGELOG.md`'s `[Unreleased]` "Added")
  that was never cross-referenced back into either tree at all. Together they
  give EVERY AU-located scan one headline "Best location estimate:
  `LAT,LON ± X km`" with its basis and confidence, printed in the CLI dossier
  (`cli/scan/dossier.rs::print_diagnostics`) and structurally exposed via
  `api::scan_export::extract_au_location_fix` in the JSON export/API — exactly
  the "single best-estimate with provenance + a confidence radius" this node
  asks for. No code change this cycle — audit + doc correction only, closing
  the drift between the shipped code, the CHANGELOG, and this tree.
  *Delivered (2026-07-01):* **the geometric-median gap flagged above is closed.**
  `au059_synergy_fix` now calls `weighted_geometric_median` (Weiszfeld),
  falling back to `weighted_centroid` only on the rare non-convergent/
  degenerate case — the exact fallback idiom `LocationFix`/
  `cluster_coordinates` already established, so all three convergence call
  sites are now consistent. New regression test
  `au059_synergy_fix_resists_a_single_high_confidence_outlier` proves the
  behavioural difference directly: it computes the plain centroid inline for
  comparison, asserts the fixture actually pulls it toward the outlier
  (lon<145, sanity check), then asserts the real fix does NOT (lon>145) —
  fails against the pre-fix code (identical to the plain centroid, lon≈138.6)
  and passes against the fix. Every pre-existing geo test (AU-052, AU-059,
  `scan_export`) is unchanged because they use tolerant range assertions
  against tightly-clustered fixtures where the two estimators barely diverge —
  this closes a real precision gap, not a behaviour regression risk.
  *Delivered (2026-07-14) — first movement/timeline layer increment:*
  `exif_geo` has always stamped a `shot_time` evidence attribute (the photo's
  EXIF `DateTimeOriginal`/`DateTime` tag) onto every entity it emits,
  including the extracted `Coordinates` entity, but `core::timeline::classify`
  had no arm for it — the "movement/timeline layer" this node has named as
  remaining since cycle 19 turned out to already have a real, live, dated-geo
  signal with nothing consuming it. New `TimelineEventKind::LocationVisited`
  (distinct from `Generic`) + a `classify()` arm for `"shot_time"`, plus a
  second, independently-found defect: `timeline::parse_date` didn't accept
  EXIF's own `:`-separated date form (`"YYYY:MM:DD HH:MM:SS"`), so even a
  correctly-classified `shot_time` would have failed to parse — fixed by
  accepting `:` as a third date separator (safe: `parse_date` already isolates
  the date portion from the time component before separator detection runs).
  SPA `TL_KIND` map gained a `location_visited` entry so the new kind renders
  with its own icon/label rather than the generic "Event" fallback. Audited
  every other `Coordinates`-producing module (WiGLE, `cell_intel`,
  `opencellid`, the IP-geo family, `address_au`) for a similar per-observation
  timestamp attribute — none carry one today, so this is genuinely the one
  live signal available, not an invented mechanism. 3 new regression tests,
  git-stash-provable. Gate green: fmt/clippy `-D warnings`/rustdoc clean, full
  suite 0 failures (4626 lib tests, +3). **Paired:** `PROBLEM_TREE` C5
  (movement/timeline geo, first increment) + C1(c) (timeline-widening
  precedent this fix follows), §8 — same commit.
  *Remaining:* AU bounding precision; a true movement/PATH reconstruction
  layer that correlates multiple `LocationVisited` events into an actual
  chronology of places visited (the individual dated-location events now
  exist for the first time — connecting them into a path is the next
  increment); auto-scheduled re-sync of the local cell DB (currently requires
  manual `hse cells import` trigger).
- **`[~]` SOL-OFFENSIVE · Exposure & reuse graph** → **C6**: broaden SERP dorks,
  credential-reuse graph, `aho-corasick` (SOL-F1) key-harvest + entropy gate.
  *Audit correction (2026-07-12) — status was stale, `[ ]`→`[~]`:* the
  credential-reuse graph and the aho-corasick+entropy key-harvest gate are
  both already fully delivered (AU-047 already links every secret kind —
  salted hash, session token, plaintext password, crypto address, API key —
  unconditionally; `key_harvest` already uses SOL-F1's `MatchSet` +
  `shannon_entropy`), just never credited back to this node. *Remaining:*
  broader SERP exposure-dork coverage only (open-ended).
- **`[ ]` SOL-FORENSIC · Reproducible intelligence product** → **C7**: byte-stable
  exports + evidence chains as the auditable, machine-diffable deliverable.

### S.QUALITY — Periphery correctness (paired with `PROBLEM_TREE` T2.12)

- **`[x]` SOL-CLI-CONTRACT · Honest CLI result/exit semantics** — `keys add` now
  pre-checks `is_poolable_service` and `Err`s for a non-poolable service (no false
  "already exists" + silent drop) ✅; `provision --verify` returns non-zero on a
  failed smoke/missing-key sub-test ✅. *+SOL-CLI-CONTRACT-DIFF (2026-06-17):*
  `cmd_diff` returns `Err("both sides resolve to the same scan")` (non-zero exit)
  in the same-scan footgun block — previously fell through to `Ok(())`. Integration
  test `diff_wiring_self_compare_is_rejected_with_diagnostic` guards it ✅.
  *+SOL-CLI-CONTRACT-AUDIT (2026-06-17, cycle 5):* `cmd_audit` returns `Err` after
  printing the report when any finding carries `Severity::Critical | Severity::High`
  — `hse audit` was previously always `Ok(())` regardless of scan quality ✅. Test
  `empty_scan_triggers_high_severity_exit_path` guards it.
  *+SOL-CLI-CONTRACT-SCAN (2026-06-17, cycle 6):* `resolve_scan_id` now rejects
  non-`Complete` scans with `Err("scan {id} is {status} — only complete scans can be
  exported, diffed, or audited")` — previously returned the id regardless of status,
  allowing export/diff/audit on mid-run or failed scans ✅. Test
  `resolve_scan_id_rejects_incomplete_scans` guards it. *Closes:* **T2.12** (two MED
  CLI bugs + diff exit-code + audit exit-code + scan-id status-check). ✅ **Fully
  closed.**
- **`[x]` SOL-DIFF-DEDUP · uid-deduped diff** — `diff_entities` iterates the deduped
  `HashMap` values, so dup-uid CLI snapshots don't over-count; unique-uid input is
  byte-identical. *Closes:* **T2.12** diff over-count. ✅ test
  `duplicate_uid_input_is_not_over_counted`.
- **`[x]` SOL-CACHE-REFRESH · Allow in-place refresh when full** — `put` is now
  `len < cap || contains_key`, so a full cache still refreshes a key it holds.
  *Closes:* **T2.12** stale-cache. ✅ test `full_cache_still_refreshes_an_existing_key`.
- **`[x]` SOL-ROI-HINT · Read module yield from events, not the entities-only
  diagnostics list** — the dossier's "ROI: N keyed/paid module(s) yielded
  nothing" hint filtered `ScanDiagnostics::modules_by_yield` for
  `entities_emitted == 0`, but that list is built *exclusively* from emitted
  entities' evidence sources, so a module that ran and found nothing is never
  inserted — absent, not present-at-zero. The filter could never match, on
  any scan. New pure `zero_yield_keyed_or_paid_modules(events,
  cost_by_module)` reads the scan's own durable `ModuleDone { module, found }`
  events instead (already tracked per module regardless of yield — no new
  tracking added). *Closes:* **T2.13** (new). ✅ Verified live: a real `hse
  scan --output dossier` printed the hint correctly post-fix (11 wasted
  `KeyGated`/`Paid` modules named) after confirming pre-fix it never printed
  at all. 4 new unit tests on the pure helper. `print_dossier` bundled its new
  8th parameter into a `DossierArgs` struct rather than
  `#[allow(too_many_arguments)]`, per the T2.5 `DispatchCx`/`DispatchState`
  precedent.
  *Addendum (2026-07-01):* the same unreachable premise (`entities_emitted ==
  0` on `modules_by_yield`) was found twice more, INSIDE `analyse()` itself —
  a per-module "returned 0 entities" hint and a scan-level "60s + zero-yield"
  hint. Removed both as confirmed-dead rather than left misleading; not
  mechanically restored (see new **SOL-HINT-NOISE** below — this closes the
  ROI hint specifically, T2.14 tracks reinstating these two).
- **`[x]` SOL-HINT-NOISE · Reinstate `analyse()`'s two removed dead hints,
  with a real per-module noise decision** → **T2.14**: the scan-level "60s +
  zero-yield module" hint can be reinstated the same way SOL-ROI-HINT was
  (event-sourced, caller-side); the per-module "module X returned 0 entities"
  hint needs a design decision first — fired correctly on real event data, a
  realistic multi-module scan leaves dozens of modules at zero yield for any
  given target kind (normal, not noteworthy), so a naive per-module
  reinstatement would flood the hints list with the opposite of signal.
  Candidates: cap to worst-N, cost-gate like SOL-ROI-HINT
  (`KeyGated`/`Paid`-only), or collapse to a bounded summary count. **Built
  (2026-07-11):** `util::diagnostics::event_hints::append_event_sourced_hints`
  — the noise question resolved to the bounded-summary-count candidate, not
  cap-to-worst-N: one line ("N of M dispatched modules found nothing for this
  target kind") regardless of how many modules zero-yielded, plus the
  unchanged cost-gated 60s scan-level hint. Wired into both consumer call
  sites (dossier + JSON output); the third (`api/handlers`) has no observer
  for `analyse()`'s return value and was left alone. Live-verified on a real
  scan, not just unit tests. **(§5)**
- **`[~]` SOL-HEALTH-SIGNAL · Per-source scraper health surface** — add a
  `last_success_at` + `consecutive_failures` tracking column (or an in-process
  `AtomicU64` per source name) exposed via `hse doctor` and a SPA health panel;
  auto-flag a source "drifted" when `consecutive_failures ≥ N` or `parse_rate
  < threshold`. SOL-F1's `bstr`/aho-corasick rewrites underpin the parsers being
  stable enough to measure; each golden-fixture test (T2.7) becomes the
  acceptance criterion.
  *Closes / powers:* **T2.7** per-source health signal gap (currently no solution
  node). *Delivered (2026-07-11):* the "wait for the golden-fixture corpus first"
  premise was corrected — hard-failure detection needs no new tracking column
  and no dependency on SOL-F1's rewrites being done first, because the signal
  already exists: every dispatch already emits a persisted `ModuleDone`/
  `ModuleError` event, per scan, across every scan ever run. The gap was that
  nothing ever aggregated it ACROSS scan boundaries. New
  `Store::recent_module_outcome_events` (a bounded, newest-first cross-scan
  query, `events` already pruned to 7 days / 100k rows so this is naturally a
  rolling window) feeds a new pure `util::scraper_health::aggregate_source_health`
  (one pass, per-module trailing-failure streak + last success timestamp,
  deterministic name-sorted output) — no new table, no new column. Wired into
  `hse doctor`: reports source count tracked, flags any module with
  `consecutive_failures ≥ 3` (a single transient timeout doesn't page the
  operator; three does), shows its last success date and last error.
  *SPA panel delivered (2026-07-12):* new `GET /api/v1/health/scrapers`
  handler calls the same `aggregate_source_health` over
  `Store::recent_module_outcome_events`, routed through `StoragePort` (a new
  default-empty trait method — the API layer holds only `Arc<dyn
  StoragePort>`, never the concrete `Store`, so the aggregation that
  previously lived solely in the `hse doctor` CLI path needed a trait-level
  seam to reach the web server too). New "Scraper health" panel on the
  Engines page renders the same streak/last-success/last-error data `hse
  doctor` prints. Live-verified with zero console/page errors against this
  session's own real scan history. New integration test pins the honest-
  empty-state contract (0 tracked, 0 drifted for a fresh database).
  *Remaining:* the `parse_rate`/zero-yield leg — a module that runs to
  completion but silently returns fewer results because a page layout
  drifted (`ModuleDone{found:0}` on a source that used to yield) needs a
  per-source historical-yield baseline to distinguish from a genuinely
  empty target, which this slice deliberately did not invent under
  cycle-scope pressure.
  *Golden-fixture corpus — first slice delivered (2026-07-13):* one real
  engine, proving the pattern before the rest of the corpus (depth over
  breadth — all 17 `search_engines` engines + the three AU scrapers in one
  pass would be scope creep). A REAL Brave SERP fetched live for the
  canonical seed `Kylo4kylo`, checked in verbatim as `src/modules/
  search_engines/fetch/testdata/brave_kylo4kylo.html` (210 KB, unmodified —
  not a hand-crafted fragment like the existing inline-literal tests, which
  can't reproduce a real SvelteKit-shell/footer-chrome page's failure modes).
  New test `parse_results_extracts_from_a_real_brave_serp_capture` pins the
  parser's yield against this real page (exactly 26 organic results, three
  named hits present, zero engine-chrome leakage), git-stash-proven (neutering
  `parse_results` fails the test; restored, it passes). Gate green (4567 lib
  tests, +1). *Remaining corpus slices:* `au_people`/`au_electoral`/
  `au_property` (needs a privacy-safe capture — e.g. the AEC's real
  "not enrolled" response for a synthetic name, never a real citizen's
  record) and the other 16 `search_engines` engines (lower marginal value —
  same shared parser this fixture already exercises; Bing's `<cite>`-based
  format is the next-highest-value addition). **(§4a)**
  *Golden-fixture corpus — second slice delivered (2026-07-13):* Bing next,
  per the first slice's own stated priority — the highest-risk engine for a
  `<cite>`-format drift, a markup shape none of the other 16 engines use. A
  REAL Bing SERP fetched live for the canonical seed `Kylo4kylo`, checked in
  verbatim as `src/modules/search_engines/fetch/testdata/bing_kylo4kylo.html`
  (75 KB, unmodified). This particular live capture happens to return zero
  results actually about `Kylo4kylo` — Bing's own answer to this exact query
  was five unrelated ESPN links — an honestly-observed real result, not a
  fabricated one; the test's job (per T2.7's own doctrine) is only that
  every real result block a live page contains is extracted without silent
  drops or engine-chrome leakage, not relevance. New test
  `parse_results_extracts_from_a_real_bing_serp_capture` pins the parser's
  yield against this real page (exactly 5 organic results, three named
  hosts present, zero `bing.com` chrome leakage), git-stash-proven (neutering
  `parse_results` fails the test; restored, it passes). No production code
  change — `parse_results`'s existing href+`<cite>` extraction handled this
  real page correctly as-is. Gate green (4567 lib tests, +1). *Remaining
  corpus slices, unchanged:* `au_people`/`au_electoral`/`au_property` (needs
  a privacy-safe capture strategy) and the other 15 `search_engines` engines
  (lower marginal value — same shared parser two fixtures now exercise).
  *Parse-rate/zero-yield drift leg delivered (2026-07-13):* the second named
  increment — a module that completes without erroring but silently returns
  zero results, distinct from a genuinely-empty target. Reused the exact
  three-strikes shape the hard-failure leg validated rather than inventing a
  statistical baseline: `SourceHealth::is_yield_drifted()` requires BOTH
  `ever_yielded` (this source has found something, anywhere in the window)
  AND `consecutive_zero_yield >= YIELD_DRIFT_THRESHOLD` (3) — a source that
  has never yielded is never flagged (no matter how many zeros), a source
  whose newest run recovers has its trailing streak correctly closed at 0
  (not inflated by older zeros), and `ModuleError` events are skipped
  entirely (neither counted nor resetting — that failure mode is already
  `consecutive_failures`'s job). No new persistence: reuses
  `EventKind::ModuleDone`'s existing `found: usize` field. Wired into `hse
  doctor`'s "Scraper health" section, `GET /api/v1/health/scrapers`
  (`yield_drifted`/`yield_drift_threshold`), and the SPA Engines panel
  (second table). Deliberately zero-yield only — a *partial* yield-drop
  detector needs an average/median historical baseline and an
  unjustified drop-percentage threshold no real incident has yet
  demonstrated a need for; banked as a future increment if evidence
  appears, exactly as this leg itself was banked from the original
  hard-failure slice. Live-verified against the operator's own real scan
  history (97 tracked sources, 211 recent outcome events, via both `hse
  doctor` and a live `GET /api/v1/health/scrapers` call): both signals
  correctly report the honest empty state for this database — never
  fabricated. Git-stash-proven: neutering `is_yield_drifted` to always
  return `false` fails the positive-detection unit test; restored, it
  passes. 5 new unit tests plus the existing SPA-panel honest-empty-state
  API test extended to cover the new fields. Gate green: fmt/clippy `-D
  warnings`/rustdoc clean, full suite 0 failures (4572 lib tests, +5). Both
  SOL-HEALTH-SIGNAL legs T2.7's original sketch named (hard-failure,
  parse-rate) are now delivered; only the golden-fixture corpus's remaining
  slices stay open, each its own low-priority future increment. **(§4a)**
  *`au_electoral` corpus slice — premise refuted, real break found and fixed
  instead (2026-07-13):* the named next fixture slice ("the AEC's real
  'not enrolled' response for a synthetic name") assumed the AEC name-search
  endpoint still worked. It doesn't: two real `GET
  electorate.aec.gov.au/NameSearch.aspx` calls (a nonsense name, and a real
  enrolled public figure) both returned the identical generic "Temporarily
  Unavailable" error page — not query-specific, not transient. The AEC's
  actual current tool (`check.aec.gov.au`) confirmed why: it's been rebuilt
  as an address-based (postcode/suburb/street) multi-step flow with no
  name-search capability at all, a different input shape than this module
  takes — repointing is a distinct future capability, correctly not pursued
  this cycle. Fix: removed the dead AEC dispatch leg + its AEC-only
  `split_name` helper from `au_electoral::process()`, corrected
  `max_timeout_ms` 20,000→15,000 (3 EC lookups, not 4), updated the module
  doc comment with the live evidence. NSW/VIC/QLD untouched — unreachable
  from this sandbox (proxy-blocked), so honestly left unverified rather than
  guessed at. Live-verified: a real `hse scan --kind name --value "Anthony
  Albanese" --modules au_electoral` dispatch trace now shows zero connection
  attempts to `electorate.aec.gov.au`, only NSW→VIC→QLD in order. 2 new
  tests (a golden-fixture capture of the real retired-AEC error page pinning
  `extract_division` returns `None`; an exact-timeout regression), git-stash-
  proven against the unfixed 20,000 value. Gate green: fmt/clippy `-D
  warnings`/rustdoc clean, full suite 0 failures (4600 lib tests, net +1).
  **(§4a)** **Paired:** `PROBLEM_TREE` T2.7 (au_electoral AEC leg), §8 —
  same commit.
  *`au_people` corpus slice — a second real break, same root cause class
  (2026-07-13):* three real `GET whitepages.com.au/residential/search/
  {name}` calls (a nonsense name, the real common name "John Smith", and
  the bare search root) all returned a generic HTTP 404 — the site now
  serves a Nuxt.js client-rendered SPA with no server-rendered search form
  left, the same "legacy static URL retired for a client-rendered app"
  cause as the AEC finding. `process()` already gated the parse on
  `resp.status().is_success()`, so this only ever silently contributed
  nothing while paying a request/timeout cost. Removed the dead dispatch;
  deleted `parse_whitepages_html` + `clean_au_locality` outright (per this
  session's dead-code doctrine — a future repoint needs an entirely new
  parser for whatever data shape the real API returns, not a revived HTML
  one); corrected `max_timeout_ms` 12,000→6,000; fixed the Person-anchor's
  evidence `"source"` attribute (was hardcoded `"whitepages_au+tps_au"`,
  now wrong 100% of the time — corrected to `"tps_au"`). True People Search
  AU untouched — proxy-blocked from this sandbox. Live-verified: a real
  `hse scan --kind name --value "Anthony Albanese" --modules au_people`
  dispatch trace shows a connection attempt ONLY to
  `truepeoplesearch.com.au`, zero to `whitepages.com.au`. 7 dead tests
  removed, 1 new exact-timeout regression added (net −6), git-stash-proven
  against the unfixed 12,000 value. Gate green: fmt/clippy `-D
  warnings`/rustdoc clean, full suite 0 failures (4594 lib tests). **(§4a)**
  **Paired:** `PROBLEM_TREE` T2.7 (au_people White Pages AU leg), §8 — same
  commit.
  *Golden-fixture corpus — third slice delivered (2026-07-13):* resumed this
  in-progress node per the standing cycle's own step-1 priority (finish an
  open node before picking new work). Re-confirmed au_people/au_electoral/
  au_property are still proxy-blocked from this sandbox (fresh `curl`
  attempts against all three state ECs reproduced the same 502
  CONNECT-tunnel failure), so picked DuckDuckGo instead — reachable, and
  unlike Brave/Bing it exercises `parse_results`' primary `href=` path
  against DDG's own `uddg=`-wrapped redirect links, previously covered only
  by hand-written fragments, never a full real page. Fetched a REAL
  `html.duckduckgo.com/html/` response live for the canonical seed
  `Kylo4kylo`, checked in verbatim as `src/modules/search_engines/fetch/
  testdata/duckduckgo_kylo4kylo.html` (16 KB). New test
  `parse_results_extracts_from_a_real_duckduckgo_serp_capture` pins the
  exact 4 real hosts this capture contains (teamk4l.com, TikTok, YouTube, a
  Plex show page — honestly unrelated to `Kylo4kylo`, not fabricated) plus
  a zero-leaked-chrome/un-unwrapped-redirect check. Git-stash-proven:
  neutering `parse_results` to return early fails the test; restored, it
  passes. No production code change. Live-verified: a real `hse scan --kind
  name --value Kylo4kylo --modules search_engines` run dispatches
  DuckDuckGo live through this exact path (`ok_retry`, 2 real results),
  zero errors. Gate green: fmt/clippy `-D warnings`/rustdoc clean, full
  suite 0 failures (4600 lib tests, +1). *Remaining corpus slices,
  unchanged:* `au_people`/`au_electoral`/`au_property` (still proxy-blocked
  — needs the operator's own device) and the other 14 `search_engines`
  engines (lower marginal value — same shared parser three fixtures now
  exercise). **(§4a)** **Paired:** `PROBLEM_TREE` T2.7 (golden-fixture
  corpus, third slice), §8 — same commit.
  *Golden-fixture corpus — fourth slice delivered (2026-07-13): MetaGer, and
  a real false-positive defect on one of only THREE `RELIABLE_ENGINE_NAMES`.*
  Re-prioritised ahead of the remaining 14 lower-value engines this node's
  own prior slices named, because `metager` (with `swisscows`/`dogpile`) is
  the reliable core `pivot_engine_set` always unions in — the guaranteed
  floor of every scan's second-order pivot/recycle discovery pass — so a
  silent defect here has outsized real impact. Fetched a REAL MetaGer
  response live for `eingabe=Kylo4kylo` (following its redirect, matching
  the production `curl -L` fetch path exactly) and checked it in verbatim as
  `src/modules/search_engines/fetch/testdata/metager_kylo4kylo.html`
  (21 KB). Unlike the three prior slices, this one surfaced a genuine defect
  rather than confirming the happy path: ALL 30 raw hits `parse_results`
  extracted were MetaGer's own homepage/language-switcher/footer/about-page
  chrome (`metager.org`, the distinct-TLD `metager.de` subdomains
  `maps.metager.de`/`gitlab.metager.de`, `suma-ev.de` — MetaGer's own
  nonprofit operator, self-disclosed in the captured page's own "MetaGer is
  developed and run by our nonprofit organization, SUMA-EV" text — plus a
  hosting-provider sustainability credit and donation-affiliate widget link),
  none of it a genuine organic result — a false positive on every single
  MetaGer query, silently fabricating fake Domain/Url entities attributed to
  the scan subject. Root cause: none of these five domains were in
  `ENGINE_DOMAINS`. Fix: added all five (`helpers/urls.rs`). New test
  `parse_results_excludes_metagers_own_chrome_from_a_real_serp_capture`
  asserts EMPTY results from this real fixture — every hit is chrome, unlike
  the prior three slices' specific nonzero pins — git-stash-proven:
  reverting the `ENGINE_DOMAINS` addition leaks all 30 fake hits back
  through; restored, 0. The same investigation, run with the same rigor as
  the au_electoral/au_people findings above (two independent real queries —
  `Kylo4kylo` and Anthony Albanese — plus a GET/POST check), also confirmed
  the legacy `/meta/meta.ger3` endpoint this module targets is permanently
  dead: it unconditionally 302-redirects to the plain marketing homepage
  regardless of query/cookies/method, and MetaGer's own `robots.txt`
  explicitly `Disallow`s `/meta/` and `/*/meta/` — the identical "legacy
  endpoint retired for a client-rendered app" root cause already found twice
  in this same node (au_electoral's AEC leg, au_people's White Pages AU
  leg). *Deliberately NOT done this slice, to avoid scope creep on an
  already-substantial finding:* demoting `metager` out of
  `RELIABLE_ENGINE_NAMES` and correcting its now-disproven "100% hit, 0%
  blocked, 20 results/call" doc comment — a real, separate follow-on
  touching the pivot/recycle guaranteed-floor semantics and ~5 dependent
  test call sites (`reliable_engines_resolve_by_name`,
  `pivot_engine_set_unions_reliable_core_with_proven_and_is_deterministic`,
  and others asserting the 3-name reliable set), named explicitly as T2.7's
  next remaining item rather than bundled in here. Live-verified: a real
  `hse scan --kind name --value Kylo4kylo --modules search_engines` run now
  reports `metager: outcome=empty, results=0` (previously `ok` with 30 fake
  hits), confirmed zero `metager.org`/`suma-ev.de`/`hetzner.de`/
  `wecanhelp.de` entities in the scan output. Gate green: fmt/clippy `-D
  warnings`/rustdoc clean, full suite 0 failures (4614 lib tests, +1).
  *Remaining corpus slices, unchanged:* `au_people`/`au_electoral`/
  `au_property` (still proxy-blocked) and the other 14 `search_engines`
  engines. **(§4a)** **Paired:** `PROBLEM_TREE` T2.7 (golden-fixture corpus,
  fourth slice), §8 — same commit.
  *Named follow-on closed (2026-07-13): `metager` demoted from
  `RELIABLE_ENGINE_NAMES`.* The fourth slice's finding (permanently dead
  legacy endpoint) disproved the doc comment's "100% hit, 0% blocked, 20
  results/call" claim outright, not just made it stale. Demoted `metager`
  from the reliable core (3→2: `swisscows`, `dogpile` remain) — the
  guaranteed floor `pivot_engine_set` always falls back to — since it
  currently contributes zero genuine results; left it registered in
  `ENGINES` so the primary pass still tries it (now correctly yielding zero
  rather than 30 fake chrome-leak hits) in case a future cycle finds a
  working replacement endpoint. Updated the 4 dependent test call sites
  that hardcoded the 3-name reliable set
  (`reliable_engines_resolve_by_name`,
  `primary_engine_order_floats_reliable_and_proven_engines_first` — which
  used `metager` as its "declared late" example, now `swisscows` —,
  `pivot_engine_set_unions_reliable_core_with_proven_and_is_deterministic`).
  Live-verified: a real `hse scan --kind name --value Kylo4kylo --modules
  search_engines` run confirms `metager` is still dispatched normally in
  the primary pass, unaffected by this change — only the pivot/recycle
  floor's membership changed. Gate green: fmt/clippy `-D warnings`/rustdoc
  clean, full suite 0 failures (4615 lib tests, net 0 — 4 tests edited in
  place). **Paired:** `PROBLEM_TREE` T2.7 (reliable-core correction), §8 —
  same commit.
  *Golden-fixture corpus — fifth slice delivered (2026-07-13): Dogpile and
  Swisscows, now the entire reliable core.* With `metager` demoted, only 2
  engines remain in the guaranteed pivot/recycle floor — doubling the
  consequence of a defect on either. Real live captures for `Kylo4kylo`
  (followed through redirects exactly as the production fetch path does),
  checked in as `dogpile_kylo4kylo.html` (77 KB) /
  `swisscows_kylo4kylo.html` (86 KB), surfaced the SAME false-positive
  defect class as the MetaGer slice, on different chrome: Dogpile's own
  mascot "Arfie"'s Facebook page and all 4 of Swisscows' branded social
  handles (Facebook/Instagram/LinkedIn/Twitter) leaked through as fake
  organic hits. Unlike MetaGer's own-domain chrome, these sit on GENERIC
  third-party platforms a real target could also have a genuine profile
  on, so a blanket domain exclusion was not safe (it would create the
  opposite defect — hiding a real target's own social presence). Fix:
  added 5 specific full-path entries to `is_tracking_url` — the existing
  path-scoped exclusion mechanism this codebase already used for
  `dogpile.com/click`/`swisscows.com/api` — a full-URL-substring match on
  each known handle, never a bare-domain match. Two new tests pin all 5
  leaks closed against the real captures, git-stash-proven (reverting the
  additions leaks all 5 back through; restored, they pass). Live-verified:
  a real `hse scan --kind name --value Kylo4kylo --modules search_engines`
  run confirms both engines now correctly report `outcome: empty,
  results: 0`, zero trace of any excluded handle in the scan output. Gate
  green: fmt/clippy `-D warnings`/rustdoc clean, full suite 0 failures
  (4617 lib tests, +2). *Remaining corpus slices, unchanged:*
  `au_people`/`au_electoral`/`au_property` (still proxy-blocked) and the
  other 14 `search_engines` engines. **Paired:** `PROBLEM_TREE` T2.7
  (golden-fixture corpus, fifth slice), §8 — same commit.
  *New sub-node (2026-07-13): `extract_surrounding_text`'s straddling-block
  title leak, T2.88.* Found investigating the same real Swisscows capture:
  a genuinely separate title-QUALITY defect, not a symptom of the
  false-positive URL leak the sibling fifth-slice fix closes. An icon-only
  social link's title falls back to `extract_surrounding_text`'s fixed
  ±300-char window; this real page packs social icons back-to-back, so the
  window's left edge landed INSIDE the preceding icon's own
  `<svg><path d="…">` block — its opening tag sits outside the window, so
  `strip_inline_blocks` (which only recognises a complete tag pair fully
  contained in the slice it's given) never sees it, and the block's raw
  path/attribute data leaks through `strip_tags` as plain text. Could affect
  any of the 17 `search_engines` engines wherever an icon-only anchor sits
  near inline SVG, not just Swisscows. Fix: new
  `skip_straddling_inline_block` — a bounded (4,096-byte lookback) single
  forward scan alternating between "outside a block" (find the next
  `<svg`/`<style`/`<script`, whichever comes first) and "inside a block"
  (find that tag's own close) — correctly threads through any sequence of
  complete, back-to-back blocks (exactly what the real capture has) rather
  than a per-tag-type "last occurrence" scan that could mis-pick a closed
  block over a still-open earlier one. When the naive window start lands
  inside an unclosed block, it snaps forward past that block's close tag.
  A refactor-shaped repair: the fix lives entirely inside the existing
  windowing primitive, no new call sites, no behaviour change for the
  overwhelmingly common non-straddling case. 3 new regression tests: a
  synthetic fragment with a deliberately long (400-byte) SVG path so the
  straddle is genuinely reproduced rather than a short block the window
  would swallow whole (proving both the leak closes AND genuine nearby text
  is kept), plus the real Swisscows capture itself. Git-stash-proven:
  reverting the call site fails both; restored, both pass. Live-verified: a
  real `hse scan --kind name --value Kylo4kylo --modules search_engines` run
  completes cleanly, zero errors — honestly disclosed that this seed's own
  triggering URLs are already excluded pre-title-extraction by the sibling
  fix, so the real-capture-backed unit test is the direct evidence, not a
  live display. Gate green: fmt/clippy `-D warnings`/rustdoc clean, full
  suite 0 failures (4619 lib tests, +2). **Paired:** `PROBLEM_TREE` T2.88,
  §8 — same commit.
  *Golden-fixture corpus — sixth slice delivered (2026-07-14): Startpage,
  the first slice to exercise the `build_post` (POST) request path.*
  Fetched a REAL Startpage response live (`POST /sp/search`, matching
  `EngineSpec::build_post` exactly) and checked it in verbatim as
  `fetch/testdata/startpage_kylo4kylo.html` (197 KB). Surfaced the SAME
  false-positive defect class as the MetaGer/Dogpile/Swisscows slices:
  Startpage's own official social accounts (`x.com/startpage`,
  `instagram.com/startpage/`, `facebook.com/startpagesearch/`,
  `reddit.com/r/StartpageSearch/`) leaked through as fake organic hits
  alongside a genuine hit (`instagram.com/kylo4k/`) on the SAME platform as
  one of the excluded handles — direct evidence the fix excludes chrome
  without over-excluding a real result. Fixed with 4 full-path
  `is_tracking_url` entries (not a blanket domain exclusion). New test
  `parse_results_excludes_startpages_own_social_handles` asserts both, git-
  stash-proven (reverting the additions leaks all 4 back through; restored,
  it passes). Live-verified: a real `hse scan --kind name --value
  Kylo4kylo --modules search_engines` run completes cleanly, zero errors,
  zero trace of the excluded handles. Gate green: fmt/clippy `-D
  warnings`/rustdoc clean, full suite 0 failures (4620 lib tests, +1).
  *Investigated but deliberately deferred, to avoid scope creep on this
  already-complete slice:* the same real capture also showed 3 genuine
  (non-excluded) results with the WRONG title — "Visit in Anonymous View",
  Startpage's own adjacent proxy-link label, legitimately visible text
  belonging to the PRECEDING result card, not this one. Root cause:
  Startpage repeats the same `href` multiple times per result (an
  icon-only "favicon-link" wrapper first, the real titled link with actual
  text much later), and `extract_anchor_text` matches only the FIRST
  occurrence via a plain `html.find`, which is the textless icon wrapper —
  falling back to `extract_surrounding_text`'s fixed ±300-char window,
  which for this markup shape reaches backward into the tail of the
  PRECEDING card (close enough to be "nearby") rather than forward into
  this card's own real title (too far away to reach). A real, likely-
  general defect — any engine whose markup repeats an `href` for an
  icon-then-title pair could hit the same failure — named explicitly here
  as the next candidate rather than folded into this already-complete
  slice. *Closed 2026-07-14 — see the `extract_anchor_text` multi-occurrence
  fix below.* *Remaining corpus slices, unchanged:* `au_people`/
  `au_electoral`/`au_property` (still proxy-blocked) and the other 13
  `search_engines` engines. **Paired:** `PROBLEM_TREE` T2.7 (golden-fixture
  corpus, sixth slice), §8 — same commit.
  *`extract_anchor_text` multi-occurrence fix delivered (2026-07-14),
  closing the deferred title-extraction defect above:* the old
  first-occurrence-only `html.find(&search_dq)` scan hit a result's
  textless icon-wrapper anchor and stopped; confirmed against the unfixed
  code (`git stash` on the one file) to produce an empty title for the
  capture's Instagram result and "Visit in Anonymous View" — the PRECEDING
  card's own proxy-link label — for the other 3 genuine results. Fixed by
  walking every occurrence of the href in the document and keeping the LAST
  one with non-empty extracted text, matching the observed chrome-first,
  full-title-last document order (icon wrapper → short site-name anchor →
  display-URL anchor → the real `<h2>`-wrapped title, in that order, in the
  real capture) — the common single-occurrence case is unaffected. 2 new
  regression tests (a synthetic 4-occurrence case; a real-capture test
  pinning all 4 recovered titles exactly and asserting none contain
  "Anonymous View"), git-stash-proven by reverting the fix alone
  (reproduces the exact original empty/"Anonymous View" titles); restored,
  both pass. All 304 pre-existing `search_engines`-scoped tests continue to
  pass unchanged. Gate green: fmt/clippy `-D warnings`/rustdoc clean, full
  suite 0 failures (4634 lib tests, +2). **Paired:** `PROBLEM_TREE` T2.95,
  §8 — same commit.
  *`au_property` live-status correction + honest-failure fix delivered
  (2026-07-14), refuting the "still proxy-blocked" note above for this
  module specifically:* the sandbox's proxy reaches all three
  `au_property` portal root domains fine (`200`s), so unlike
  `au_people`/`au_electoral` (still genuinely `CONNECT`-`502`-blocked),
  `au_property`'s "proxy-blocked" label was stale — real requests to all
  three endpoints now return live `404`s from up servers: NSW's ELVIS
  path (root now serves an unrelated "SDT Explorer" SPA), VIC's WFS path
  (IIS "not found", root MapShareVic app itself live), QLD's title-search
  path (a genuine qld.gov.au 404 page). Same root-cause class as
  `au_electoral`'s AEC leg and `metager` — a legacy static endpoint
  retired for a client-rendered replacement — but here all THREE of the
  module's legs are down at once, so `process()`'s existing
  "fall through to the next leg" logic silently swallowed every failure
  into `Ok(ModuleResult::new())`, indistinguishable from a genuine
  "no property record for this person." Same defect shape as
  T2.48–T2.51 (`domainsdb`/`huggingface_user`/`sourceforge_user`/
  `opencorporates` silently dying when their providers moved). Fix: a new
  pure `all_legs_unreachable(any_leg_http_ok, found_any_entity)` tracks
  whether ANY leg's HTTP response itself succeeded, separate from whether
  parsing found a match; `process()` now returns a real `Error::module`
  (a genuine `ModuleError`, feeding the existing `consecutive_failures`
  health-signal streak this exact node built) only when every leg failed
  at the HTTP level AND nothing was found — a leg that succeeds but has no
  match for this name still returns the ordinary honest empty result,
  unchanged. Endpoint-replacement research for the three legs is
  deliberately NOT this slice's scope (a client-rendered SPA plus two
  separate WFS/CMS migrations each need their own investigation) — named
  explicitly as the remaining item, matching this node's own established
  slice-by-slice discipline. 3 new regression tests on the pure decision
  function (git-stash-proof: the pre-fix code has no such function, so
  reverting is a compile error, not merely a failing assertion); module
  doc comment corrected to the confirmed live status. Gate green:
  fmt/clippy `-D warnings`/rustdoc clean, full suite 0 failures (4621 lib
  tests, +3 — the net count reflects other concurrent work landed on this
  branch since the previous entry, not a regression). **Paired:**
  `PROBLEM_TREE` T2.7 (`au_property` honest-failure fix), §8 — same
  commit.
  *Golden-fixture corpus — seventh slice delivered (2026-07-14): you.com.*
  Swept live reachability of all 10 remaining un-fixtured `search_engines`
  engines from this sandbox: 8 confirmed blocked/unreachable at the HTTP
  layer (matching each engine's own documented live-scan stats), leaving
  `google` (a genuine JS-challenge interstitial, already correctly
  handled by the existing block detector) and `you` as the only two
  returning `200` with real content. A REAL `you.com` capture (`GET
  /search?q=Kylo4kylo&tbm=youchat`, exactly `EngineSpec::build_url`)
  checked in as `fetch/testdata/you_kylo4kylo.html` (55 KB) disproved
  `engines.rs`'s own doc comment — the real page is a Cloudflare-gated
  Next.js SPA with zero server-rendered `<a>` result anchors, not a
  "classic HTML view" — and surfaced a real chrome-leak: the capture's
  `<link rel="dns-prefetch" href="https://cdn.you.com"/>` leaked through
  `parse_results` as a fake organic hit because `you.com` was never in
  `ENGINE_DOMAINS`, the same false-positive class already fixed for
  MetaGer/Dogpile/Swisscows/Startpage. Fixed by adding `you.com` to
  `ENGINE_DOMAINS`; corrected the stale doc comment to record the
  confirmed Cloudflare-gated-SPA shape. 2 new regression tests
  (`is_captcha_page_detects_a_real_youcom_cloudflare_challenge_capture`,
  `parse_results_excludes_youcoms_own_cdn_chrome`), git-stash-proven
  (reverting the `ENGINE_DOMAINS` addition alone reproduces the leak).
  Live-verified: a real `hse scan --kind name --value Kylo4kylo --modules
  search_engines --depth 0` run reports `engine: you, outcome: blocked,
  results: 0`, zero `cdn.you.com` chrome anywhere in the scan output.
  Gate green: fmt/clippy `-D warnings`/rustdoc clean, full suite 0
  failures (4623 lib tests, +2). *Remaining corpus slices:*
  `au_people`/`au_electoral` (still genuinely proxy-blocked);
  `au_property` (three dead legs, no replacement endpoint found yet); the
  8 confirmed-unreachable-from-this-sandbox `search_engines` engines
  (`yahoo`/`aol`/`mojeek`/`yandex`/`ecosia`/`qwant`/`presearch`/`searx`).
  **Paired:** `PROBLEM_TREE` T2.7 (golden-fixture corpus, seventh slice —
  you.com), §8 — same commit.

- **`[x]` SOL-AUDIT-TEMPORAL-SCOPE · `hse audit`'s engine-health signal is
  gated to the audited scan's own era, not "right now"** → **T2.76**. Found
  by a cross-cutting PRIORITY-2 sweep of every cache/TTL/quota-budget/
  retry-backoff mechanism in the engine: `engine_health_signals()` blended
  the process-global, continuously-refreshed search-engine liveness cache
  into ANY scan's audit report with zero comparison to that scan's own
  completion time — a false positive when engines break after a clean
  scan, a false negative when engines recover after a scan that genuinely
  ran degraded. Fix: `scan_audit` reads the scan's own
  `finished_at`/`started_at` (free — folded into the existing
  `spawn_blocking` batch with entities/events) and a new pure
  `snapshot_still_relevant_to(checked_at, scan_reference_ts)` gates the
  cached snapshot to within 2× the health sweep's own declared refresh
  cadence — `search_engines::health::DEFAULT_REFRESH_SECS`, a new constant
  single-sourced between the health module and `cli/serve` (which
  previously hardcoded the same `900` as an independent literal) so the
  tolerance can never drift from the sweep's actual cadence. No new
  persistence, no invented threshold. A snapshot older than the scan
  (cache hasn't caught up yet) is never rejected — that's the cache being
  incomplete, already separately handled by `health::cached()` returning
  `None`. Live-verified against REAL, naturally-occurring conditions (no
  synthetic fixture, no clock manipulation): a real scan from ~2 hours
  earlier in this same session — genuinely past the 1,800s tolerance —
  audited immediately after a fresh live 17-engine sweep found this
  sandbox's real, currently-degraded network (11 blocked, 1 down, only 5
  up). Pre-fix this would have stamped that old scan's report with the
  current outage; post-fix, `GET /api/v1/scans/{id}/audit` correctly
  returned `engines_down: []`, `engines_blocked: []`,
  `engine_parser_defects: []`. Git-stash-proven: 4 new unit tests on the
  pure gate (shortly-after-scan keeps the signal; exactly 2× the interval
  is still relevant; weeks-later is correctly rejected — the exact
  false-positive scenario the finding named; a lagging cache is never
  rejected) — neutering the gate to always return `true` fails the
  weeks-later test; restored, passes. Gate green: fmt/clippy `-D
  warnings`/rustdoc clean, full suite 0 failures (4576 lib tests, +4).
  **Paired:** `PROBLEM_TREE` T2.76 — same commit.
  *WiGLE account-status leg delivered (2026-07-13, T2.77):* continuing the
  PRIORITY-2 sweep, a SIBLING stale-attribution bug in the same family —
  `wigle::account`'s `verified: Some(false)` latch (set as a side effect of
  a real 412 in `fetch.rs::classify_and_decode`) had no symmetric way back
  to `true`, so a long-lived process kept reporting the account as
  unverified (via `hse doctor`/`/api/v1/stats`) forever after one 412, even
  once the operator fixed it and every later query succeeded. Fix: new
  `account::mark_verified`, mirroring `mark_unverified` exactly, called
  from the success branch of `classify_and_decode` — same reactive
  learned-from-traffic channel, no new persistence. Live-verified against a
  REAL WiGLE account and a real public-landmark query (Sydney Opera House
  coordinates): `/api/v1/stats` went from `verified: null` to `verified:
  false` after a genuine HTTP 412 from this sandbox's actually-unverified
  account, confirming the existing half of the mechanism end-to-end against
  real traffic. Honestly disclosed: the NEW half (`mark_verified` firing
  from a real 200) wasn't live-reachable since the real account here is
  persistently unverified — verified instead via the git-stash-proven unit
  test `mark_verified_clears_a_stale_unverified_latch`. Gate green:
  fmt/clippy `-D warnings`/rustdoc clean, full suite 0 failures (4577 lib
  tests, +1). **Paired:** `PROBLEM_TREE` T2.77 — same commit.

- **`[x]` SOL-KEYHARVEST-RELOCATE · The universal foreign-API-key
  classifier lived nested inside one specific module, not `util`** →
  **T2.78**. Operator request: "REFACTOR and merge where it is
  advantageous." An Explore-agent mapping of `modules::oathnet_pro::
  key_harvest` found 12 real, non-test call sites across `util`, `api`,
  `cli`, and 5+ sibling `modules` — every layer reaching into one
  module's internals for a fully pure classifier
  (`identify_api_key`/`identify_vendor_api_key`/`key_value_tier`/
  `pattern_catalogue` — string/regex only, no OathNet-specific response
  shape), backwards from `cli`/`api` → `core` → `util` layering. The
  one real coupling (`emit.rs`'s `use super::SRC`) was also a live bug:
  `emit_key_with` stamped every emitted key's evidence source AND entity
  tag with `oathnet_pro`'s own `SRC`/`"oathnet-pro"` literal regardless of
  caller, so every key harvested from a `see_know` breach/stealer record
  was silently mislabeled as `oathnet_pro`-sourced. Fix: relocated the
  whole directory to `util::key_harvest` (`git mv`, zero logic change to
  the pure functions) — matching this project's established "promote a
  pure/leaf classifier into `util`" precedent (`util::geohash`,
  `util::geometry`, `util::domains`). `extract_api_keys_from_item`/
  `store_api_credential` gained an explicit `src` parameter (the caller's
  own `SRC` constant) — mirroring the ALREADY-established
  `modules::breach_rich::extract_rich_detail` "caller supplies its own
  source tag" convention this codebase already uses for the identical
  oathnet_pro/see_know sharing problem, so no new pattern was invented.
  Bundled `src`+`scan_id` into one `HarvestCtx` struct rather than let
  `emit_key_with` grow past clippy's argument-count lint — the same
  "bundle, don't `#[allow]`" discipline T2.5 established for
  `core::engine`'s dispatch functions. Updated all 12 real call sites;
  `oathnet_pro`/`see_know` now pass their own `SRC`. New regression test
  `emitted_key_is_attributed_to_the_caller_that_actually_found_it` asserts
  both the entity tag and `Evidence.source` correctly name the caller for
  `"oathnet_pro"` and `"see_know"` alike — git-stash-proven by reverting
  to the old hardcoded `"oathnet-pro"` tag, which fails the `see_know`
  case; restored, it passes. Live-verified: a real `hse scan --kind domain
  --value wikipedia.org --modules web_crawler` run completes cleanly
  end-to-end through the relocated `key_harvest::identify_api_key` call
  path (a real exposed `.well-known/security.txt` was discovered and
  scanned with zero errors). Gate green: fmt/clippy `-D warnings`/rustdoc
  clean, full suite 0 failures (4595 lib tests, +1). **Paired:**
  `PROBLEM_TREE` T2.78 — same commit.
  *Extended (2026-07-13) — `api_key_probe`'s duplicate live-validation
  table, T2.79:* the same "merge where advantageous" pass found
  `api_key_probe/probes.rs` independently duplicating `util::service_defs`
  (the table `key_pool::validation` already reads for the identical
  purpose), already drifted 3 ways: `securitytrails`, `virustotal`, and
  `greynoise` each tested a DIFFERENT URL in the two tables — one
  objectively wrong each time (confirmed by `api_key_probe`'s own code
  comments and each vendor's documented key-test endpoint). Also found
  `censys`'s env var pointed at `HUNTSMAN_CENSYS_KEY`, which exists
  nowhere else in the codebase. Extended `ServiceDef` with an optional
  `probe_parser` (the one genuinely per-vendor part) and derived the
  request generically from `test_url`+`key_header` via a new
  `request_for()`, deleting the entire duplicate table rather than
  reconciling it a second time — the 3 drifted URLs are now single-sourced
  and can't re-drift. WiGLE's (and censys's) real two-credential Basic-Auth
  limitation was explicitly documented as a pre-existing, out-of-scope gap
  in BOTH source tables, not silently half-fixed. Live-verified: a real
  `hse scan --kind apikey --modules api_key_probe` run against this
  operator's own real, currently-configured HIBP key produced byte-for-byte
  identical output before and after the merge (confirmed by reverting to
  the pre-merge code and re-running the identical live scan) — the same
  check also surfaced a separate, pre-existing `is_error_response`/
  `parse_info` false-positive gap, confirmed unchanged by the same
  before/after comparison and correctly logged as its own future finding
  rather than folded into this merge. New regression test pins the 3
  corrected URLs, git-stash-proven by reverting greynoise's URL, which
  fails it. Gate green: fmt/clippy `-D warnings`/rustdoc clean, full suite
  0 failures (4596 lib tests, +1). **Paired:** `PROBLEM_TREE` T2.79 — same
  commit.
  *Extended (2026-07-13) — merged web_crawler/username_search's duplicate
  key-tokenizers, T2.80:* concluding the same "merge where advantageous"
  pass, found `web_crawler::extract_api_keys_from_body` and
  `username_search::scan_text_for_keys` each hand-rolling the identical
  `body.split(whitespace/quote-chars)` + `16..=200`-char-window loop
  instead of reusing `found_keys::key_tokens` — the canonical tokenizer
  already used elsewhere for this exact job. Two real defects followed: a
  stricter length cap (200 vs `found_keys::MAX_TOKEN` = 4096, silently
  dropping any longer real key/PAT/JWT scraped from a page or profile
  body) and a narrower delimiter set (missing `>`, `<`, `=`, `;`, `,`,
  `&`, `?`, `{`, `}`, `[`, `]`, so a `token=VALUE`-shaped or JSON/HTML-
  embedded key stayed glued to surrounding text). Deleted both ad hoc
  loops; both functions now iterate
  `found_keys::key_tokens(body, found_keys::MAX_TOKEN)` directly, keeping
  only their own caller-specific metadata. New regression test proves a
  234-char BinaryEdge-shaped poolable key — longer than the old 200-char
  cap but under the real one — now survives the tokenizer and reaches
  `pool.add`, git-stash-proven by reverting to the old inline `16..=200`
  split, which fails it; restored, it passes. Gate green: fmt/clippy `-D
  warnings`/rustdoc clean, full suite 0 failures (4597 lib tests, +1).
  **Paired:** `PROBLEM_TREE` T2.80 — same commit.
  *Extended (2026-07-13) — `wayback` now proactively harvests keys from its
  own fetched bodies, T2.82:* operator instruction: "Focus on proactively
  harvesting APIs." Audited all 18 modules that fetch a response body
  against whether they also ran the universal `found_keys`/`key_harvest`
  classifier — only `web_crawler`/`username_search`/`search_engines` did.
  `wayback` was the clearest gap: it already downloads up to 10 archived
  contact/about/team snapshots per scan purely for email/phone mining, and
  an archived snapshot is exactly where a since-scrubbed leaked credential
  survives — zero extra network cost to also scan it. The other 15
  body-fetching modules were correctly left untouched: the AU government/
  regulator registries return official structured data (scanning them
  would be pure noise, not real coverage), and `cloud_storage` lists object
  filenames but never fetches object content (no body to scan yet —
  extending it is a bigger, separate future capability, not folded in here
  to avoid scope creep). Extracted the per-snapshot body-handling into a
  new pure, independently-testable `mine_keys_from_body()`, reusing the
  identical `found_keys::key_tokens`/`key_harvest::identify_api_key`/
  `key_pool` pipeline `web_crawler`/`username_search` already established.
  Each pooled hit carries wayback-specific provenance (`discovered_by:
  "wayback:<domain>"`, notes with the archive timestamp + original URL).
  New regression test proves a synthetic poolable key embedded in an
  archived-page body reaches `pool.add` with correct provenance —
  git-stash-proven by neutering the new function to a no-op, which fails
  it; restored, it passes. Live-verification note: `wayback` is already one
  of this sandbox's documented network-restricted sources; a real scan
  against it timed out reaching `web.archive.org`'s CDX API here but
  completed cleanly with a graceful `module error` (no panic/corruption) —
  confirming no regression to existing error handling, with the
  classify-and-pool logic itself proven by the git-stash-proven unit test
  rather than a fabricated live claim. Gate green: fmt/clippy `-D
  warnings`/rustdoc clean, full suite 0 failures (4601 lib tests, +1).
  **Paired:** `PROBLEM_TREE` T2.82 — same commit.
  *Extended (2026-07-13) — `hse doctor` can now detect a dead SeekNow key,
  T2.83:* operator instruction: "Focus on utilising seek to harvest and
  proactively discover API keys to use." `see_know`'s passive key-harvest
  wiring was already complete at both call sites (no undocumented endpoint
  to add — a prior dead-code sweep already removed speculative endpoint
  scaffolding). The real blocker, confirmed live: `base_url()` resolves to
  `see-know.icu`, reachable from this sandbox (unlike `.eu`, which the
  embedded key's own doc comment previously — incorrectly — blamed for
  "can't verify here"); a real `hse scan --modules see_know` run against
  `.icu` logs an `invalid_api_key` rejection via the actual production
  client — the embedded `SEEKNOW_DEFAULT_KEY` is confirmed dead, and this
  failure was completely silent (a scan just reports `found 0`). Fixed
  `query_credits` (the free `/credits` meta-query doctor can call from a
  fresh process) to classify+latch an auth-rejection via the same machinery
  `search`/`get_path` already use — previously it silently swallowed an
  auth error, so a process that only ever calls `query_credits` (exactly
  doctor's case) could never detect a dead key, despite
  `is_key_invalid()`'s own doc comment claiming this diagnostic already
  existed. New "SeekNow account" section in `hse doctor`, mirroring the
  existing WiGLE block. Refactored credits-body parsing into a pure
  `parse_credits_body`/`CreditsOutcome` (3-way `Data`/`AuthError`/
  `Unparseable`, kept distinct so a network blip can never be mistaken for
  a confirmed dead key). 5 new regression tests pin every classification
  path — git-stash-proven by neutering the `is_auth_error` check, which
  fails 2 of 5; restored, all pass. Live-verified end-to-end: a real `hse
  doctor` run against this operator's own actual `~/.huntsman.env` now
  prints "SeekNow account: INVALID — the configured key was rejected..." —
  the exact diagnostic that was silently missing before. Gate green:
  fmt/clippy `-D warnings`/rustdoc clean, full suite 0 failures (4606 lib
  tests, +5). **Paired:** `PROBLEM_TREE` T2.83 — same commit.
  *Extended (2026-07-13) — `hacker_news` now proactively harvests keys from
  its own fetched bio/submissions text, T2.84:* continuing the "proactively
  harvesting APIs" theme. Investigated the remaining candidates
  (`pypi_user`/`hacker_news`/`reddit_user`/`subdomain_takeover`/`pgp`);
  `hacker_news` was strongest — its Algolia `search` response (already
  fully fetched for `algolia_domain_entities`) carries a `comment_text`/
  `story_text` field per hit, live-confirmed via a direct query against
  `hn.algolia.com` (a real comment's full body was present verbatim) — real
  developer free text, the same category that justified `wayback`. The
  account bio (already deserialized into `HnUser.about`) is the same
  category at smaller scale. Fix: new `mine_keys_from_text(pool, text,
  username, source_label)` — reusing the identical `found_keys`/
  `key_harvest`/`key_pool` pipeline already established — called over the
  bio (label `"bio"`) and the raw Algolia body (label `"submissions"`),
  both already in memory, zero extra network cost. 2 new regression tests
  prove the two call sites are independently distinguishable by their
  `notes` label — git-stash-proven by neutering `mine_keys_from_text`,
  which fails both; restored, both pass. All 12 pre-existing `hacker_news`
  tests pass unchanged. Live-verified: a real `hse scan --kind username
  --value pg --modules hacker_news` run completes cleanly through both new
  call sites against a real 13-entity response and a real bio, zero
  errors — an honest true-negative. Gate green: fmt/clippy `-D
  warnings`/rustdoc clean, full suite 0 failures (4608 lib tests, +2).
  **Paired:** `PROBLEM_TREE` T2.84 — same commit.
  *Extended (2026-07-13) — `reddit_user` now proactively harvests keys from
  its own fetched bio/submitted text, T2.85 (last of the originally-named
  candidates):* `submitted.json` (already fully fetched for the existing
  subreddit extraction) is Reddit's analogue of HN's Algolia submissions —
  real, unmoderated post/self-text — the same category T2.84 justified.
  The profile bio (already deserialized, already mined for emails/URLs) is
  the same category at smaller scale. Fix: new `mine_keys_from_text(pool,
  text, username, source_label)` — reusing the identical `found_keys`/
  `key_harvest`/`key_pool` pipeline already established — called over the
  bio (label `"bio"`) and the raw `submitted.json` body (label
  `"submitted"`), both already in memory, zero extra network cost. 2 new
  regression tests (structurally identical to T2.84's) prove the two call
  sites are independently distinguishable by their `notes` label —
  git-stash-proven by neutering `mine_keys_from_text`, which fails both;
  restored, both pass. All 14 pre-existing `reddit_user` tests pass
  unchanged. Live-verification note: `reddit_user` is already one of this
  sandbox's documented network-restricted sources; a real `hse scan --kind
  username --value spez --modules reddit_user` run confirms Reddit's
  anti-bot layer 403s the first call before either new key-mining site
  runs — the module fails gracefully, no regression to existing error
  handling. Gate green: fmt/clippy `-D warnings`/rustdoc clean, full suite
  0 failures (4610 lib tests, +2). **Paired:** `PROBLEM_TREE` T2.85 — same
  commit.
  *Extended (2026-07-13) — `see_know`'s identity-pivot chase now harvests
  keys too, T2.87:* operator instruction: "Focus purely on utilising
  Oathnet and Seek-Know to find more API keys." Audited every item-
  processing loop in both providers: `oathnet_pro`'s breach-page and
  stealer-search loops both already harvest every row; `see_know`'s broad
  `/search` loop and per-seed endpoint-matrix loop both already harvest
  too — but its THIRD loop, `resolve_identity_pivots`'s discord/user +
  discord/to-roblox + gaming/steam pivot chase, did not. A real gap, not a
  stylistic inconsistency: this pivot chase is SeekNow's own doc comment's
  stated "unique value" over the free username stack (resolving a Discord
  snowflake / SteamID64 to its linked accounts), so a leaked credential in
  a linked account's own `password`/`token`/`note` field — structurally
  identical to what every other SeekNow endpoint already scans — was
  silently missed. Fix: split the pivot loop's per-item processing into a
  new `extract_pivot_entities`, separated from the network-calling
  `resolve_identity_pivots` for direct unit-testability (the same
  testability refactor this session already applies to every network-
  calling function), and added the identical `store_api_credential`/
  `extract_api_keys_from_item` calls the other two loops already make. New
  regression test feeds a synthetic `discord_user`-shaped item with an
  AWS-shaped key in its `token` field (the same fixture shape
  `util::key_harvest`'s own orchestrator tests use) and asserts an `ApiKey`
  entity with `service:aws` tag comes out. Git-stash-proven: neutering the
  two new lines leaves only a generic `Other("token")` entity, no `ApiKey`;
  restored, it passes. Live-verification note (honest disclosure): a real
  `hse scan --kind username --value Kylo4kylo --modules see_know` run
  confirms this sandbox's SeekNow key is still the T2.83-confirmed-dead key
  (`invalid_api_key`, found: 0), so the pivot chase cannot be exercised
  end-to-end here regardless of this fix — an environmental constraint,
  disclosed rather than hidden; the fix is proven by the git-stash-proven
  unit test instead. Gate green: fmt/clippy `-D warnings`/rustdoc clean,
  full suite 0 failures (4615 lib tests, +1). **Paired:** `PROBLEM_TREE`
  T2.87 — same commit.
  *Extended (2026-07-14) — `base_url()`'s default corrected from `.icu`
  back to `.eu`, T2.89:* the operator supplied real HSE debug logs from
  their own device (no PII from them used, only diagnostic signal — curl
  exit codes, module names, timestamps) showing `see_know` failing three
  times with `"curl exited 6"` (DNS resolution failure) against the `.icu`
  default T2.83 had promoted on a sandbox-only reachability probe, in the
  same real scan where `oathnet_pro`'s identical `CurlClient` machinery
  succeeded repeatedly — ruling out a device-wide DNS problem. The operator
  separately supplied real, freshly-generated SeekNow website exports whose
  own footer states the platform's domain as `see-know.eu`, matching every
  other reference to SeekNow already in this codebase except `base_url()`'s
  own hardcoded default. T2.83's sandbox probe is now understood to be
  contaminated by this environment's own outbound-proxy policy — reconfirmed
  this same cycle to fluctuate (both domains currently proxy-blocked here,
  where yesterday only `.eu` was) — so a real device's DNS failure is the
  stronger, ground-truth signal; `.icu` is also a TLD commonly caught by
  carrier/ISP abuse-reputation DNS filtering, which manifests exactly as the
  observed failure. Flipped the default; corrected the `SEEKNOW_DEFAULT_KEY`
  doc comment and every operator-facing `.icu` reference in
  `docs/SEEKNOW_SETUP.md` (including a FAQ entry that told operators to
  actively prefer `.icu`), `docs/PERFORMANCE_MONITORING.md`,
  `docs/SEEKNOW_INTEGRATION_SUMMARY.md`, and `.env.example`; left T2.83's own
  dated log entries in both trees and `gap_register.md` untouched — they
  were true when written. Strengthened
  `client_base_url_uses_endpoint_override_or_default` to pin the exact
  default host whenever no operator override is set — git-stash-proven by
  reverting `base_url()` alone, which fails (`.icu` returned); restored,
  passes. Gate green: fmt/clippy `-D warnings`/rustdoc clean, full suite 0
  failures (4620 lib tests — one existing test strengthened, no new test
  function). **Paired:** `PROBLEM_TREE` T2.89 — same commit.

- **`[x]` SOL-KEYHARVEST-UI · The T2.78–T2.85 harvest pipeline's own
  intelligence products — the permanent `key_vault` bank and `key_roi`
  cascade tiering — had no web-UI surface at all** → **T2.86**. Operator
  request, after a live demonstration of the harvest pipeline against real
  OathNet/SeekNow queries: "Make this its own independent feature with its
  own unique part of the UI. It must be extremely comprehensive and
  infallible." An Explore-agent map of the SPA/API architecture confirmed
  every `key_vault`/`key_roi` function was already `pub`, unit-tested, and
  reachable from `hse keys bank`/`hse doctor`, but zero API handlers or
  SPA views touched them — and that `hse doctor`'s live SeekNow/WiGLE
  account-health probes were CLI-only, with no HTTP equivalent. →
  **Solution:** one new handler module, `src/api/key_harvest_handlers.rs`,
  exposing `GET /api/v1/keys/harvest` (loopback-only, mirroring the
  existing `keys_status`/`keys_pool_get` guard) that composes three
  already-built primitives rather than inventing new aggregation: the
  vault's `total_count`/`osint_provider_census`/masked `osint_entries`
  (each row's ROI tier attached via `key_roi::classify`), the pool's
  per-service health (reusing `settings_handlers::summarize_pool`
  directly — no parallel implementation to drift), and a live SeekNow
  (`query_credits`/`is_key_invalid`) + WiGLE (`refresh_account_status`)
  probe identical to `hse doctor`'s own calls, plus OathNet's process-
  local `budget_snapshot`/`is_quota_exhausted` (OathNet has no live
  account endpoint — the response and the UI both label this explicitly
  as budget state, not a network probe, rather than implying a check that
  doesn't exist). Paired with a genuinely new SPA page — nav `<li>`,
  `router.js` case, `main.js` dispatcher case, and
  `src/web/js/views/key_harvest.js` — rather than a panel on an existing
  page, per the operator's explicit "its own unique part of the UI".
  Follows `opts.js`'s established best-effort-parallel-fetch + `.panel`
  composition pattern; every panel (account health, vault, pool) renders
  its own honest degraded state (unreachable/invalid/empty) instead of
  blanking the page, translating the operator's "infallible" into this
  project's actual no-overclaiming discipline: robust and honest about
  failure, not a literal absolute-perfection claim. **P2/capability.** 3
  new unit tests (`vault_block`/`pool_block`/`accounts_block`) assert the
  JSON shape is always well-formed against whatever vault/pool state the
  test box happens to have — including empty — and that a masked value is
  never empty (the regression this guards: accidentally serialising the
  raw `key_value` instead of running it through `mask_secret`). Live-
  verified three ways: `curl` against the real running server reproduced
  this operator's actual current account state (SeekNow key INVALID per
  T2.83, WiGLE unverified per T2.77's still-latched status, OathNet's real
  budget snapshot, an honestly-empty vault — no OSINT-provider keys
  harvested in this environment yet, a true negative not a bug); a
  headless-Chromium screenshot of `#/harvest` against the real server
  rendered all three panels correctly with zero console/page errors; the
  same headless pass over `#/dash`/`#/opts`/`#/engines` confirmed the new
  nav entry and route caused no regression. Gate green: fmt/clippy `-D
  warnings`/rustdoc clean, full suite 0 failures (4613 lib tests, +3).
  **Paired:** `PROBLEM_TREE` T2.86 — same commit.

- **`[x]` SOL-PROBE-CONFIDENCE-DEDUP · `username_search`, `social_probe`, and
  `streaming_probe` each independently hardcoded the identical presence-
  confidence tiering** → **T2.81**. Second operator refactor/merge pass
  ("REFACTOR and merge again"), following an Explore-agent sweep of the
  wider codebase now that the API-key pipeline (T2.78–T2.80) was fully
  covered. All three modules defined their own `detection_strength`
  function mapping a detection rule to the same `(0.92, verified) /
  (0.74, unverified)` tuple pair — full confidence when the rule actually
  inspected response BODY content for a positive/negative marker, a
  weaker unverified tier when it only matched a bare HTTP status code
  (since a soft-404/SPA-shell/login-wall can return 200 for any handle
  regardless of real existence) — each computed from a different
  per-module `Detect`/`Platform` type, with each doc comment explicitly
  cross-referencing the other two modules by name as the shared design's
  rationale. Fix: extracted the shared judgement into
  `util::probe_confidence::detection_strength(body_verified: bool) ->
  (f64, bool)`, matching this project's established "promote a pure/leaf
  classifier into `util`" precedent (`util::geohash`, `util::domains`,
  `util::key_harvest`). Each module's own `detection_strength` kept its
  existing per-module signature — a single shared signature across all
  three isn't possible, since `&Platform` and the two distinct `&Detect`
  enums are structurally different types — but now computes its own
  single boolean ("did this rule inspect the body?") and delegates,
  reducing each to a one-line wrapper. Regression-proven by corrupting the
  shared function (swapping which branch returns which tuple): 7 tests
  failed simultaneously — `util::probe_confidence`'s own 2 new unit tests
  plus 5 pre-existing tests spanning all 3 modules — proving the three
  modules are now genuinely single-sourced and can no longer silently
  drift apart from each other the way three independent copies could;
  restored, all pass. Live-verified: a real `hse scan --kind username
  --value octocat --modules username_search,social_probe,streaming_probe`
  run completes cleanly with both body-verified (0.92) and status-only
  (0.74) tiers correctly represented among the entities and correlator
  output, zero errors across all three merged call paths. Gate green:
  fmt/clippy `-D warnings`/rustdoc clean, full suite 0 failures (4599 lib
  tests, +2). **Paired:** `PROBLEM_TREE` T2.81 — same commit.

- **`[x]` SOL-UPDATE · Self-upgrade + CLI consolidation** — `hse update` locates
  `install.sh` via `HUNTSMAN_INSTALL_DIR` env (written by `install.sh` on every run),
  then `~/hse` / `~/.local/share/hse`, then binary-parent traversal; re-runs the
  installer with inherited stdio so progress is visible in Termux; `--check` reports
  commits behind (`git fetch` + `rev-list --count HEAD..@{u}`) without installing;
  falls back to printing the curl one-liner when no source found. `install.sh` now
  writes `HUNTSMAN_INSTALL_DIR` after every run. `hse upgrade` added as alias.
  `hse keys set <NAME> <VALUE>` absorbs the former top-level `set-key`.
  6 commands hidden from `--help` (`doctor`, `selftest`, `provision`, `set-key`,
  `engines`, `oathnet-batch`) — still callable for scripting compat; visible surface
  19→13. *Closes / powers:* UX self-sufficiency; no separate upgrade ceremony needed.
  *Correction (2026-07-01):* the "commit count only, no diff summary" remaining
  note is stale — `changelog_lines` (`cli/update.rs`) runs `git log --oneline
  HEAD..@{u}` and `--check` already prints up to 20 of its lines beneath the
  count. Predates this repo's single root commit (`770df4c9`), so — unlike
  most corrections this session — no specific delivery cycle can be
  attributed; it simply was never reconciled into this note.
  *Remaining (real), closed 2026-07-05:* `changelog_lines`/`commits_behind`
  had no test exercising the actual `git` subprocess calls — closed by
  **SOL-UPDATE-GIT-FIXTURE** below (new node **T2.21**).
  **(cycle 22)**
- **`[x]` SOL-UPDATE-GIT-FIXTURE · `commits_behind`/`changelog_lines` now
  proven against a real `git` subprocess, not just pure-logic tests** — the
  residual explicitly deferred in SOL-UPDATE's own 2026-07-01 correction.
  Built a local origin+clone fixture pair (plain directories, `tempfile`, no
  network): commits land on the "origin," `commits_behind`/`changelog_lines`
  are asserted against the "local" clone's real ahead/behind state. Along the
  way, corrected a wrong assumption in the test's own first draft — a second
  `commits_behind` call was expected to report 0 after a mere fetch, but it
  correctly still reports the same count (the function only ever fetches; it
  never advances local `HEAD` — only an explicit `git merge --ff-only @{u}`,
  mirroring what `install.sh`'s real `git pull` does, moves it). Also covers
  the no-configured-upstream case (`None`/empty, not a bogus count). Since
  there was no behavioural bug — the functions were already correct, only
  untested — the fail-before proof was adapted: temporarily reversed the
  `rev-list` range to `@{u}..HEAD`, confirmed the new fixture test failed,
  restored from a diff-verified backup. *Closes:* new node **T2.21**. ✅ 2
  tests (`commits_behind_and_changelog_lines_reflect_real_git_state`,
  `commits_behind_returns_none_without_a_configured_upstream`).
- **`[x]` SOL-GREYNOISE-KEYED · `greynoise` now uses the operator's
  configured key instead of silently ignoring it** — an operator-requested
  audit of every currently-configured `HUNTSMAN_*` key's wiring found the
  module's own doc comment claimed "Free, no API key required" with zero
  `ctx.key_opt` calls anywhere in the file: it always called the free
  `v3/community` endpoint regardless of a configured key. Rather than guess
  at an unverified richer-tier shape, reused the endpoint HSE's own
  `api_key_probe` key-validation probe already calls and trusts —
  `v3/ip/{ip}` with header `key`, confirmed fields `ip`/`seen`/
  `classification` — and mirrored the Shodan module's established
  free/paid dual-path pattern (`cost()` stays `Free`; a configured key
  upgrades the lookup, same policy). *Closes:* new node **T2.22**. ✅ 5
  tests (`paid_response_deserialization`,
  `paid_path_tags_seen_in_addition_to_the_shared_signal`,
  `paid_path_surfaces_a_seen_but_otherwise_unclassified_ip`,
  `paid_path_no_signal_at_all_yields_nothing`,
  `paid_path_still_yields_the_operator_organisation_pivot`), fail-before
  confirmed (reverted to the pre-fix file with the new tests still present
  — they fail to compile, referencing symbols the fix introduces). Live
  end-to-end validation against the real configured key was planned but
  blocked mid-cycle when the key disappeared from this environment's
  `~/.huntsman.env` (confirmed via `hse doctor`, 14→13 keys) for a reason
  audited and found NOT attributable to any code path in this repository
  (`hse keys validate`'s pool-only writes, `ensure_hardcoded_keys`'s
  narrower rewrite gate confirmed unfired via trace logs, and the test
  suite's isolated-temp-path-only writes were all ruled out); a mid-session
  container restart re-provisioning the environment is the more likely
  cause, disclosed as inconclusive rather than asserted. Shipped on the
  unit-test + already-verified-reference basis per explicit operator
  sign-off.
- **`[x]` SOL-USERNAME-SLUG-GATE · a compound business/place-name slug can no
  longer reach PROBABLE off a bare surname substring, then get recycled into
  a further search** — a real live self-test's dossier put an unrelated
  fishing-tackle retailer's Facebook slug (`tackle_world_lawnton`, named
  after the Lawnton, QLD suburb) into the correlator's single
  highest-confidence "resolved identity" cluster with the subject. Traced
  via a background agent to `score_username`'s Signal 1: a bare surname
  substring match on ANY candidate scored +3 (clearing PROBABLE) with no
  check that a compound candidate's other parts relate to the subject, and
  `recycle_entities` then re-queried verbatim with the false PROBABLE match,
  pulling the retailer's own pages into the graph. *Closes:* new node
  **T2.23**. ✅ 2 tests
  (`score_username_business_slug_containing_the_surname_stays_candidate`,
  `score_username_genuine_firstname_lastname_handle_still_reaches_probable`),
  fail-before confirmed. A too-broad first draft (any corroborating score
  counted as independent) broke the pre-existing
  `username_scoring_people_search` test — caught and narrowed to name only
  genuinely independent signals (people-search host, `site:` query) rather
  than widen the test to fit an imprecise gate. Explicitly scoped: closes
  the observed case and the general compound-slug shape, not free-text
  surname/place-name collision broadly.
- **`[x]` SOL-HN-DOMAIN-DETERMINISM · `hacker_news`'s Algolia-submissions
  domain extraction no longer leaks `HashSet` iteration order into emitted
  entity order** — a background discovery agent found the same
  determinism-leak shape already fixed for `reddit_user::fetch_submitted`
  (commit `d5adaefd`, this arc): distinct domains were deduplicated via
  `HashSet` then walked straight into `Vec<Entity>` with no sort step, so
  the identical submissions JSON could legally emit differently-ordered
  `Domain` entities (and a differently-ordered live `EntityFound` stream)
  across runs of the identical scan. Extracted the pure logic into
  `algolia_domain_entities(body, username, scan_id)` — dedup via `HashSet`
  as before, convert to `Vec`, `.sort_unstable()`, then map to entities —
  mirroring the `reddit_user` fix's exact shape. *Closes:* new node
  **T2.24**. ✅ 2 tests
  (`algolia_domain_entities_emits_all_distinct_domains_deterministically`,
  `algolia_domain_entities_no_urls_yields_nothing`), fail-before confirmed
  (reverted `mod.rs` to pre-fix `HEAD` with the new tests still present —
  they fail to compile, referencing a symbol the fix introduces).
- **`[x]` SOL-WEB-CRAWLER-ORDER-DETERMINISM · `web_crawler::build_entities`'s
  five `HashSet`-backed entity-emission sites (subdomains, external domains,
  emails, tracking IDs, phones) no longer leak `HashSet` iteration order**
  — a background agent, swept the module tree for the same shape right after
  T2.24 closed it in `hacker_news`, and found `web_crawler` had it at five
  sites in one function, worse than the single-site bugs already fixed.
  Tellingly, the same function already applies the correct pattern two lines
  above for its `frameworks`/`page_types` evidence-string attributes (`Vec`
  + `.sort_unstable()`) — the fix simply extends that already-established,
  already-proven-correct local pattern to the five entity sites that never
  received it. *Closes:* new node **T2.25**. ✅ 1 test
  (`build_entities_emits_domains_emails_tracking_ids_and_phones_sorted`),
  fail-before confirmed (reverted to pre-fix `HEAD` with the new test
  present — failed on the unsorted external-domain/email order).
- **`[x]` SOL-EMAIL-USERNAME-ORDER-DETERMINISM · `email_parse`'s derived
  username candidates no longer leak `HashSet` iteration order — a
  project-wide sweep confirms this bug class is now closed** — a background
  agent, tasked with sweeping ALL of `src/modules/` for the same shape before
  assuming three prior fixes had closed it, found a 4th instance:
  `candidates: HashSet<String>` (up to ~10 derived username spelling
  variants) walked straight into the emitted `Vec<Entity>` with no sort. The
  same sweep confirmed every other direct-`HashSet`-iteration site in
  `src/modules/**/*.rs` already sorts before use. *Closes:* new node
  **T2.26**. ✅ 1 test
  (`username_candidates_emerge_in_deterministic_sorted_order`), fail-before
  confirmed (reverted to pre-fix `HEAD` with the new test present —
  panicked on the unsorted order).
- **`[x]` SOL-GITHUB-ATTACK-COMPLETE · `github_user`'s ATT&CK override now
  covers every entity kind it actually produces, instead of replacing the
  whole category default with a single technique** — the module correctly
  argued for `T1593.003` (Code Repositories) over the Social default's
  `T1593.001`, but the override dropped `T1589.003` (Employee Names) and
  never covered the `Email`/`Organisation`/`Address`/`Coordinates`/
  `Credential` entities it also builds — corrupting the real per-finding
  `attack:<ID>` provenance `core::engine::dispatch` stamps on every admitted
  entity, sourced directly from this list. *Closes:* new node **T2.27**.
  ✅ 1 test
  (`attack_techniques_covers_every_entity_kind_this_module_produces`),
  fail-before confirmed. Also split `github_user` out of a pre-existing
  `tests/architecture.rs` pinning assertion it had been bundled into with
  `crates_io`/`npm_author` (confirmed those two are NOT affected — pure
  package-registry lookups). **Correction (same day):** a same-cycle
  follow-up initially flagged `crates_io` as declaring `Person` in
  `produces()` with no matching construction — refuted on a deeper read:
  `build_entities` does construct one, via the shared
  `profile_kit::person_from_name` helper. The earlier grep only checked for
  the literal `EntityKind::Person` construction inside the file itself and
  missed the indirection.
- **`[x]` SOL-DOCKERHUB-ATTACK-COMPLETE · `dockerhub_user`'s ATT&CK override
  now covers every entity kind it actually produces — the identical
  replace-instead-of-extend gap just fixed in `github_user`** — the
  override `&["T1593.003"]` alone left `Person` (`full_name`),
  `Organisation` (`company`), `Address`/`Coordinates` (`location`), and
  `Email` (`gravatar_email`) with no matching MITRE provenance. *Closes:*
  new node **T2.28**. ✅ 1 test
  (`attack_techniques_covers_every_entity_kind_this_module_produces`),
  fail-before confirmed. The same recurring shape was flagged across
  several other Social-category "profile lookup" modules (`codewars_user`,
  `mastodon_user`, `sourceforge_user`, `cpan_user`, `gitea_user`,
  `codeberg_user`, `huggingface_user`, `hexpm_user`) — logged as a scoped
  future sweep, not pursued in this commit.
- **`[x]` SOL-CODEWARS-ATTACK-COMPLETE · `codewars_user`'s ATT&CK override now
  covers every entity kind it actually produces — the 3rd instance of the
  same replace-instead-of-extend gap** — picked from T2.28's scoped
  future-sweep list; the override `&["T1593.003"]` alone left `Person`
  (`name`), `Organisation` (`clan`), and `Address`/`Coordinates` (`city`)
  with no matching MITRE provenance (no `Email` field on this API, so
  `T1589.002` correctly does not apply, unlike `dockerhub_user`). *Closes:*
  new node **T2.29**. ✅ 1 test
  (`attack_techniques_covers_every_entity_kind_this_module_produces`),
  fail-before confirmed. 7 modules remain on the scoped sweep list
  (`mastodon_user`, `sourceforge_user`, `cpan_user`, `gitea_user`,
  `codeberg_user`, `huggingface_user`, `hexpm_user`) for future cycles.
- **`[x]` SOL-MASTODON-ATTACK-COMPLETE · `mastodon_user`'s ATT&CK override
  now covers every entity kind it actually produces — a variant of the
  same gap on an already-correct base technique** — unlike the three prior
  fixes, `mastodon_user`'s existing `T1593.001` (Social Media) substitution
  was already correct (Mastodon genuinely is social media); the override was
  simply missing coverage for `Person` (`display_name`) and `Address`/
  `Coordinates` (a location-shaped profile field). *Closes:* new node
  **T2.30**. ✅ 1 test
  (`attack_techniques_covers_every_entity_kind_this_module_produces`),
  fail-before confirmed (tests live inline in `mod.rs`, so the buggy
  `attack_techniques()` body was reverted in place rather than the whole
  file). 6 modules remain on the scoped sweep list (`sourceforge_user`,
  `cpan_user`, `gitea_user`, `codeberg_user`, `huggingface_user`,
  `hexpm_user`) for future cycles.
- **`[x]` SOL-SOURCEFORGE-ATTACK-COMPLETE · `sourceforge_user`'s ATT&CK
  override now covers every entity kind it actually produces — the 5th
  instance, back to the code-hosting shape** — the override
  `&["T1589.002", "T1593.003"]` already correctly covered the Username and
  bio-extracted Email, but left `Person` (`display_name`) and `Address`/
  `Coordinates` (`location`) with no matching technique. *Closes:* new node
  **T2.31**. ✅ 1 test
  (`attack_techniques_covers_every_entity_kind_this_module_produces`),
  fail-before confirmed. 5 modules remain on the scoped sweep list
  (`cpan_user`, `gitea_user`, `codeberg_user`, `huggingface_user`,
  `hexpm_user`) for future cycles.
- **`[x]` SOL-NAMEINTEL-ATTACK-COMPLETE · `name_intel` never overrode
  `attack_techniques()` at all, silently inheriting the exact People
  category over/under-claim `pgp` already fixed** — the module emits a
  subject `Person` and derived speculative `Email` permutations with zero
  role/organisational logic anywhere, so the inherited default's
  `T1591.004` (Identify Roles) was over-claimed and `T1589.002` (Email
  Addresses) was never credited. *Closes:* new node **T2.32**. ✅ 1 test
  (`attack_techniques_matches_produced_entity_kinds`, replacing a
  pre-existing weak `is_empty()`-only test), fail-before confirmed. A
  parallel investigation into `permute::parse`'s honorific handling for
  2-token names ("Dr Ali", "John Jr") was REFUTED — `parse()`'s
  documented, tested "safety guard" behaviour, not a fabrication bug.
- **`[x]` SOL-UPDATE-POISON-CONSISTENT · `api::update_handlers`'s two
  update-finish sites now recover from a poisoned mutex the same way
  `try_start_update` already does, closing a permanent-wedge risk on the
  self-update status endpoint** — surfaced by an automated
  `copilot-pull-request-reviewer` comment on PR #215, independently
  verified: a bare `if let Ok(mut info) = update_info.lock()` at the two
  outcome-recording sites silently no-oped on a poisoned lock, which could
  strand `phase` at `Applying` forever (permanently rejecting every future
  update trigger via `try_start_update`'s own `Applying`-gate). Extracted a
  shared `set_phase()` helper using the identical poison-recovery pattern.
  Also applied a `gemini-code-assist` suggestion in the same commit:
  `hacker_news::algolia_domain_entities` (T2.24) now sorts-then-`dedup()`s
  a plain `Vec` instead of round-tripping through a `HashSet`, avoiding
  unnecessary hashing/allocation for the same deterministic output.
  *Closes:* new node **T2.33**. ✅ 1 test
  (`set_phase_recovers_from_a_poisoned_mutex`, poisons a real `Mutex` via
  `catch_unwind`), fail-before confirmed.
- **`[x]` SOL-WIGLE-412-GRACEFUL · `wigle`'s geo/SSID search paths no longer
  turn a known, already-documented account-unverified throttle into a
  `ModuleError`** — `fetch_wigle_typed`/`fetch_wigle_ssid` now special-case
  HTTP 412 into the same graceful `Ok(Resp{success:Some(false), ..})` path
  every other "WiGLE said no" outcome already takes, instead of propagating
  `Err` via `?`, and record the confirmed-unverified status into the account
  cache as a free side effect. The BSSID/detail path was independently
  confirmed already safe (swallows non-success via `.ok()`/`if let Ok(...)`)
  so was left untouched. A first design (tag the emitted entity with a
  caveat) was live-tested, found unreachable — a 412 on both bbox widths
  means no entity survives to tag — and reverted before shipping. *Closes:*
  new node **T2.34**. ✅ Live-verified (no unit-test harness exists for
  `process()`-level HTTP glue in this codebase): re-ran the same real scan,
  confirmed `"module error"` → `"done","found":0` in the event log.
- **`[x]` SOL-CEFF-TRANSPARENCY · `source_count()` — the count that actually
  drives `c_effective()` — is now visible everywhere `corroboration` (a
  different, raw per-module magnitude) is shown, and the SPA's client-side
  formula mirror excludes the same 5 sources the backend does, not 2** — the
  base `c_effective()` formula was already correct and tested (verified by
  research, not assumed); the real gap was that CSV export, the debug bundle
  / full dossier, and the SPA all displayed `corroboration` next to `c_eff`
  with nothing to tell a reader the two numbers are unrelated. Fixed across
  every surface in one commit: `render_full` prints `source_count` + a
  `note:` on divergence + per-evidence `(non-corroborating)` markers;
  `entities_to_csv` gained `source_count`/`corroborating_sources` columns;
  two stale `core::entity` doc comments (module + struct level) describing
  the old pure-multiplicative formula, plus the `corroboration` field's own
  doc comment which asserted it WAS the corroborating-source count, were
  rewritten to match reality; the SPA's `ENRICHMENT_SOURCES` JS set — missing
  `name_intel`/`payid`/`cross_scan_history` — now matches the backend's
  `is_non_corroborating_source` exactly, with a new drift-guard test
  (`spa_enrichment_sources_matches_backend_is_non_corroborating_source`) that
  reads the live backend constants, mirroring the existing `EVENT_TYPES`
  guard pattern so the two can't silently diverge again. *Closes:* new node
  **T2.35**. Opened **T2.36** (not yet solved) for the deeper cause of *why*
  so many unrelated addresses shared `corroboration=8` in the first place —
  a `search_engines` pivot-expansion bug, distinct from this display gap. ✅
  2 new tests (CSV divergence case, `render_full` note/marker case) + 1 new
  SPA drift-guard test.
- **`[x]` SOL-LOCATION-SEED-NO-REAFFIRM · `search_engines` no longer
  self-reaffirms a re-pivoted Address/Coordinates seed at flat 0.82
  confidence** — a function-scoped `location_seed` check
  (`matches!(target.kind, TargetKind::Address | TargetKind::Coordinates)`,
  hoisted from an existing inline use one call site down) now gates both the
  parent-entity construction (skipped entirely for a location seed, not
  merely demoted — a demoted parent would still unconditionally inflate
  `corroboration` via `absorb()` and union a stray `candidate` tag) and the
  `location_on_subject` snippet-address gate (short-circuits `false` for a
  location seed — confirmed via tokenization trace that the gate was
  tautologically true for an address value, since `terms.last()` is just the
  trailing postcode, which every indexing aggregator page reproduces
  verbatim). *Closes:* new node **T2.36**. ✅ 2 new tests
  (`location_seed_pivot_does_not_reaffirm_the_seed_at_0_82`,
  `identity_seed_still_gets_flat_parent_reaffirmation` — the latter proves no
  regression for genuine identity seeds). Two independent adversarial
  verification passes (one re-derived correctness from the code, one
  re-ran every gate command from scratch). Live-verified: a real `hse scan
  --kind address` with only `search_engines` enabled shows zero
  `search-enriched` tags and zero 0.82-confidence entities.
- **`[x]` SOL-SEEKNOW-SUBJECT-GATE · `see_know`'s `/search` breach-parent
  stamp now requires a genuine subject match, not just a non-empty result
  page** — the sibling instance of SOL-LOCATION-SEED-NO-REAFFIRM's bug shape,
  found by a deliberate cross-module sweep after T2.36 was root-caused (not
  a coincidence). `see_know` unconditionally minted a `confidence=0.85`
  `BREACH`-tagged parent whenever `/search` returned `total > 0` rows — the
  raw hit count, not a subject-match count — even though the per-record
  extraction path already demotes non-matching individual rows via
  `TargetMatch`, "mirroring oathnet_pro" per its own comment; that gate was
  never applied to the parent, reintroducing the exact bug `oathnet_pro`'s
  own `breach_parent_entity` already fixed (`matching.is_empty()`, not raw
  `total_returned`). New pure `search_subject_present(target_value, items)`
  reuses the same `TargetMatch` machinery and gates the parent identically to
  `oathnet_pro`'s proven pattern. *Closes:* new node **T2.37**. ✅ 1 new test
  (`search_subject_present_gates_on_a_real_match`: strangers don't open the
  gate, the subject's own row does, exact-selector kinds still match
  trivially, empty results never match). A sweep of all 39 non-test
  `target.to_entity(` call sites across every other module found no further
  instances — each independently re-verified against live code, not taken on
  trust; zero findings fabricated to manufacture false urgency.
- **`[x]` SOL-AU063-DOC-FIX · `correlator/rules/gap.rs`'s
  `AU063_DETAIL_MIN_CONF` doc comment corrected to match its own `.min()`
  gate** — found by a dedicated core/ doc-comment-vs-code drift sweep. The
  doc claimed a detail finding fires when "at least one endpoint is this
  confident"; the code requires BOTH (`min(ea,eb) >= 0.40`) — the logical
  opposite. A second instance of the identical drift, in the opposite
  direction, sat 175 lines below on the `Candidate` struct's inline comment,
  making the file internally self-contradictory. Both corrected to state the
  weaker-endpoint/`min` semantics the code actually implements. *Closes:* new
  node **T2.38**. ✅ Doc-only, zero behaviour change (verified: constant
  value, `.min()` call, and filter condition all untouched) — confirmed via
  `cargo doc` plus independent re-derivation of the pre-fix line numbers via
  `git show HEAD:...`, proving the citation was grounded in real code, not
  fabricated.
- **`[x]` SOL-AU039-SHARED-SOURCE · AU-039 wallet→identity attribution gated on
  a real co-location tie, not an arbitrary global anchor** — closes **T2.39**,
  the design decision the T2.38 sweep correctly declined to make blind. The
  deferred question ("what relatedness gates the anchor, and does the data
  model carry that provenance here?") was answered by investigating the entity
  model: `Entity::corroborating_sources()` already exposes each entity's
  independent evidence sources at this call site. The criterion is **a shared
  corroborating source** — some single module surfaced BOTH the wallet and the
  identity (a stealer log stamps the same `source` on an owner and their
  wallet). New `shares_corroborating_source(a, b)` helper (`rules/mod.rs`,
  built on `corroborating_sources()` so a replay/enrichment pass can't
  manufacture a tie — mirroring `source_families`' honesty rule) replaces the
  "smallest-UID `Person`/`Email` across the whole scan" anchor. Per wallet the
  rule now anchors to the source-tied identities (Person preferred over Email;
  every genuinely-tied identity of the preferred kind is reported, none
  singled out), and fires nothing when no identity shares a source — removing
  the arbitrariness rather than relocating it. Deterministic (pure function of
  source membership + UID order), so live and finalise passes agree. The two
  tests that encoded the buggy co-existence semantics were replaced by three
  (a genuine-tie positive with a no-shared-source negative; the T2.39
  regression that gives the bystander the smaller UID so the old pick would
  name them; and the person-preferred/report-each-tie case) — each fails
  against the unfixed rule and passes against the fix.
- **`[x]` SOL-SNIPPET-PII-SUBJECT-GATE · `search_engines`' email/phone
  snippet extraction gated on subject relevance, extending an
  already-proven check that simply hadn't reached them yet** — closes
  **T2.40**, found via an operator-supplied real scan (CSV export + debug
  bundle for "Riley Morley"): a completely unrelated Instagram bio's email
  (`pr@rileyjorja.com` — first name "Riley" only, no "Morley" anywhere)
  reached `PROBABLE 0.70` attributed to the subject because the snippet
  merely appeared among the results for a `"Riley Morley"` query. The fix
  didn't invent new logic: the address extractor in the SAME function
  (`build.rs`) already carried exactly the needed check
  (`location_on_subject`, built for an earlier live regression — "Cindy
  Haynes" trusting a "Cindy He" UNSW page's address) — it simply hadn't been
  extended to email/phone. Hoisted the check to run once per result before
  ANY snippet extraction, renamed `location_on_subject` →
  `result_names_the_subject` (never location-specific — it asks whether
  THIS result actually names the subject), and gated email + phone + address
  extraction on the single shared boolean, removing the duplicate
  definition. Byte-identical gate values for every existing caller
  (location seeds, single-token targets); the full pre-existing 290-test
  `search_engines` suite passed unmodified before 2 new tests were added:
  the T2.40 regression (an off-target result mints neither PII kind; an
  on-target result with the surname present still mints both — confirmed to
  fail against the unfixed code by reverting and re-running) and a
  single-token-target unaffected-by-the-gate guard.
- **`[x]` SOL-SPA-MODULE-SPLIT · Monolithic `spa.html` split into native ES
  modules, zero new dependencies** — closes **T2.41**. The 3999-line
  single-file SPA (310-line inline `<style>` + 3578-line inline `<script>`
  holding ~100 render functions) is now `src/web/css/app.css` plus 37
  `import`/`export` modules under `src/web/js/` (`state.js`, `helpers.js`,
  `api.js`, `router.js`, `main.js`, `timers.js`, `theme.js`,
  `js/views/*.js` per top-level page, `js/scan_info/*.js` per ScanInfo
  sub-tab), loaded via one `<script type="module">` tag — no bundler, no
  Node toolchain, matching the project's existing offline-first minimal-
  dependency doctrine. `spa.html` shrank to a 111-line shell. Every module
  stays `include_bytes!`-embedded (`APP_FILES`, paralleling `VENDOR_FILES`)
  so the binary is still self-contained; `/static/{file}` became
  `/static/{*file}` to serve nested module paths. Purely structural: same
  look, same behaviour. Verified three ways — (1) lossless extraction:
  reconstructed and `diff`-checked byte-identical against the pre-split
  file; (2) wiring: an automated import/export symbol-usage scan found 0
  missing and 0 unused imports across all 38 files, including confirming
  the 5 legitimate `main.js`-rooted circular imports are safe (each
  `render()` call site is inside a callback, never module top-level);
  (3) live, in headless Chromium against a real running scan — every
  top-level view and all 22 ScanInfo sub-tabs rendered with zero console/
  page errors, including the D3-graph tab's `nodesById` link-resolution
  path. The ~14 tests that used to scan the monolithic `SPA_HTML` string
  (10 in `src/api/routes/tests.rs`, 4 in `tests/api.rs`) were migrated to
  read the split module(s) directly — a new `app_file()` helper for the
  unit tests, a new `spa_bundle()` shell-plus-transitive-import crawler for
  the integration tests (the served `/` document is now just the shell, so
  content checks need the full module closure). 0 regressions; gate green.
- **`[x]` SOL-SPA-VENDOR-DROP · From-scratch dark-console design system;
  Bootstrap/jQuery/tablesorter/alertify dropped entirely** — closes
  **T2.42**. A follow-up user request ("Completely revamp the UI and
  REFACTOR it") asked for the visual layer SOL-SPA-MODULE-SPLIT
  deliberately preserved, and was open to dropping the vendor libraries
  outright. New `src/web/css/app.css` design system: CSS custom-property
  tokens on `:root` (dark is the base look; `.light-theme` is a small
  opt-out override block — no more per-component `body.dark-theme …{}`
  duplication), the same Bootstrap-era class vocabulary the ~40 view files'
  markup already used (`.row`/`.col-md-N`, `.btn`/`.btn-primary`,
  `.panel`/`.table`/`.label`/`.modal`/`.glyphicon-*`, …) redefined from
  scratch so none of those files' generated markup needed to change, and
  47 hand-authored inline-SVG-mask icons replacing the glyphicon icon
  font — which, audited while building the replacement, turned out to have
  never actually rendered: `bootstrap.min.css`'s `@font-face` pointed at a
  relative `../fonts/...` path the server never served, so every glyphicon
  had been invisible since the stack was first vendored (a real latent
  regression this incidentally fixes). New `src/web/js/ui.js`: vanilla-JS
  navbar-collapse, modal open/close/backdrop/Escape, a `sortableTable()`
  click-to-sort replacement for tablesorter, and `window.jQuery`/
  `window.alertify` shims matching the exact call contract every view file
  already used (`.success/.error/.warning/.notify/.confirm/.prompt`,
  `jQuery.fn.tablesorter` + `jQuery('#id').tablesorter(opts)`) — so again,
  no view file needed to change. D3 v3 stays vendored (a rendering engine,
  not a look dependency; every visual property of the graph is already
  this project's own code). Dropping alertify also closes a standing,
  never-resolved licensing question (`PROBLEM_TREE` §7 Deferred: "GPL
  `alertify` + missing `NOTICE`"). Also swept ~30 inline hardcoded hex
  literals across view files to `var(--text-muted)`/`var(--danger)`/etc.
  so they stay theme-aware, leaving only the genuinely theme-invariant ones
  (white-on-solid-badge text, the D3 legend's swatches which must match
  `NODE_COLOR` literally). Verified live in headless Chromium: every
  top-level view, all 22 ScanInfo sub-tabs (incl. the D3 graph against a
  real 454-entity/2785-correlation scan), the mobile navbar-collapse
  toggle, the About modal, the sortable-table click handler, and the
  toast/confirm/prompt replacements — all zero console/page errors. One
  real bug caught during that pass: `.btn-block` buttons overflowed their
  panel (missing `box-sizing: border-box`) — fixed with a universal
  `*,*::before,*::after` reset, screenshot-confirmed before/after. *Closes:*
  **T2.42**. ✅ 0 regressions; gate green (fmt/clippy `-D warnings`/rustdoc/
  full suite).
- **`[x]` SOL-WEAK-DETECTION-DISCOUNT · Correlator rules stop treating a
  status-only username guess as a confirmed/verified account** — closes
  **T2.43**. Found via a real OSINT scan (a Brisbane/QLD username-alias
  lookup): AU-055 fired `CRITICAL "Subject's own confirmed account(s)...
  primary sources the subject controls"` across 64–71 platforms that were
  almost entirely `weak-detection`-tagged (a bare HTTP-status match — a
  soft-404/SPA-shell fakes this for nearly any handle), and AU-003 reported
  `C_eff=1.000` "corroborated by 6 independent sources" for one guessed URL.
  Three fixes, one root cause each: (1) `webserver_banner` was re-emitting a
  `Url` target verbatim via `to_entity()` even though its own probe HEADs
  only the domain *root* (`extract_host_port` discards the path) — its
  domain-root evidence was landing on the path-specific entity, "confirming"
  a check that never happened; now rebased to a `Domain` entity keyed on the
  host it actually probed (new pure helper `banner_entity`, unit-tested).
  (2) AU-055/AU-038 now exclude `weak-detection`-tagged URLs from their
  "confirmed"/"verified" platform counts; AU-003 excludes weak-detection-only
  entities from "high cross-source corroboration"; AU-045 gained a new
  `strong_corroborating_families` helper (family classification is
  per-source, so the fix discounts per-evidence-record, not per-tag) since
  `username_search` (family "presence") and `social_probe` (family "social")
  both hitting the same unverified handle via a bare status check otherwise
  satisfied AU-045's "two distinct service families" bar despite neither
  being a real confirmation. (3) `social_probe` — a THIRD module doing the
  identical status-code-existence check on 30 of its 36 platforms with zero
  body-marker verification — had no weak/verified distinction at all; gained
  the same `detection_strength()` split (0.74 unverified / 0.92
  body-marker-verified) `username_search`/`streaming_probe` already use, so
  fixing the correlator alone wouldn't have closed the gap this module
  independently reopens. A genuinely `verified-detection` hit still fires
  every rule exactly as before. *Closes:* **T2.43**. ✅ 8 new regression
  tests (2 per AU rule + 2 `webserver_banner` + 2 `social_probe`), each
  confirmed via `git stash` to fail against its pre-fix rule and pass
  against the fix. Gate green: fmt/clippy `-D warnings`/rustdoc clean, full
  suite 0 failures.
- **`[x]` SOL-STALE-CACHE-BACKOFF · Cross-scan cache reset + rate-limit
  backoff for the paid API clients** → **T2.44**, direct response to an
  operator diagnostic request ("HSE... utilises old data" / "diagnose the
  Seek API['s]... frequency... before requiring... exponential back off").
  **(a) Stale cache:** `util::oathnet`/`util::see_know`'s `RESPONSE_CACHE`
  dedups identical queries *within one scan* (its own doc comment), but
  `reset_budget()` — called once per scan specifically so `hse serve`/`hse
  live` get fresh state each scan — never cleared it, so a long-lived
  process silently kept serving the FIRST scan's cached breach/stealer
  records for every later re-scan of the same value, forever. Both
  providers' `reset_budget()` now also clear their cache. **(b) Rate-limit
  conflated with quota exhaustion:** SeekNow's `{"error":"rate_limit"}` and
  OathNet's HTTP 429 (transient burst throttles, NOT exhausted credits)
  were classified identically to true daily-quota exhaustion, permanently
  latching the shared per-scan budget and silently abandoning the provider
  for the rest of the scan with zero backoff. A `RetryStrategy` construct
  with sensible parameters already existed in `see_know::orchestration` but
  was entirely dead code (zero call sites anywhere, confirmed by grep,
  across ~1,135 lines of `orchestration.rs`/`monitoring.rs`/
  `force_multiplier.rs` — left untouched this cycle, flagged as a separate,
  larger future decision). New `util::backoff::BackoffPolicy` — generic,
  pure, fully unit-tested exponential backoff with jitter, no new `rand`
  dependency (jitter from a freshly-constructed `RandomState`, randomised
  per construction) — reuses the dead `RETRY_STRATEGY`'s own parameters (3
  attempts, 2s→4s→8s, jittered) at a real, live call site. New
  `core::error::Error::RateLimited` variant lets a retry loop distinguish
  "back off and retry" from a hard failure; `see_know::client::Terminal`
  splits `RateLimited` out from `Quota`; both providers' request functions
  back off and retry (bounded) before falling back to the same
  quota-exhausted latch as before if backoff runs out. Also reconciled 3
  stale quota-figure doc comments against the real `enterprise_config.rs`
  numbers. *Investigated, no bug found:* module-dispatch "full spectrum"
  concern — every skip path in `core::engine::dispatch::
  module_skip_reason` is deliberate and disclosed; two intentional
  footguns named (process-global circuit breaker, persistent module
  toggle) but correctly left unchanged. ✅ 11 new regression tests (2
  cache-clear + 7 pure backoff + 2 rate-limit classification), the
  cache-clear and rate-limit tests each confirmed via `git stash` to fail
  pre-fix. Gate green: fmt/clippy `-D warnings`/rustdoc clean, full suite 0
  failures (4601 lib tests, +11).
- **`[x]` SOL-CIRCUIT-TOKEN-ANCHOR · Rate-limit classifier hardened against
  bare-substring false positives** → **T2.45**, surfaced by the background
  data-freshness/pacing audit. `core::engine::circuit::is_rate_limited`'s
  vocabulary included the bare single words `"exceeded"`/`"credit"` and
  unanchored `429`/`402` digit matching — each matches text with nothing to
  do with a rate limit: a tokio timeout's "deadline exceeded", scraped
  "credit card" content, or an echoed subject phone number merely
  *containing* 429/402 (`+61429551402`, a shape this project's own scans
  routinely surface). Any one coincidence hard-tripped a healthy module for
  the full 600s `RATE_LIMIT_COOLDOWN`, silently dropping every subsequent
  finding it would otherwise have produced for the rest of the scan. A fix
  for this exact defect existed on an unmerged sibling branch (`a5c5fac3`)
  but never reached `main` — confirmed via `git merge-base
  --is-ancestor`/`git branch --all --contains`. Reimplemented fresh this
  cycle (not cherry-picked): a curated `QUOTA_PROSE` list of distinctive
  multi-word compounds (`"too many requests"`, `"rate limit"`, `"quota"`,
  `"payment required"`, `"count exceeded"`, `"limit exceeded"`, `"requests
  exceeded"`, `"credit exhausted"`, `"out of credit"`, `"insufficient
  credit"`, `"credit exceeded"`) replaces the bare tokens; `429`/`402` now
  match only as a standalone token (message split on non-alphanumeric
  bytes). Anything not caught still falls through to the existing 3-strike
  soft-failure path, so a false negative here costs at most a retry or two,
  never a wrongly-benched healthy provider. ✅ 3 new regression tests (2
  pure-classifier, 1 full stateful `record_error`/`is_open` integration),
  all confirmed via `git stash` to fail pre-fix. Gate green: fmt/clippy `-D
  warnings`/rustdoc clean, full suite 0 failures (4604 lib tests, +3).
  Live-verified: real `hse` binary, real dispatch path, the project's own
  canonical acceptance-test seed (`Kylo4kylo`) — the exact coincidental
  false-positive substring was not naturally reproduced in that specific
  run, noted honestly rather than overclaimed as full live reproduction.
- **`[x]` SOL-SEARCH-LIVENESS-RESET · Per-scan reset for
  `search_engines::SESSION_EMPTY_COUNTS`** → **T2.46**, the second finding
  from the same background data-freshness/pacing audit, the same bug class
  as SOL-STALE-CACHE-BACKOFF's cache fix. `SESSION_EMPTY_COUNTS` (a
  process-global `Mutex<HashMap<..., EngineLiveness>>`) correctly silences
  an engine for the rest of ONE scan after a genuine consecutive-empty block
  streak, and correctly exempts a "proven live" engine from the aggressive
  threshold — but it was never wired into `modules::install_core_hooks`'s
  `reset_per_scan` hook, unlike `oathnet_pro`/`see_know`/`wigle`'s per-scan
  state (confirmed by directly reading the hook body). Under a long-lived
  `hse serve`/`hse live` process, both states leaked across scan boundaries:
  an engine silenced against target A stayed silenced against target B in a
  later scan, indefinitely, with no basis for assuming the failure carries
  over; the milder "proven live" leak costs extra retries rather than lost
  results. New `search_engines::reset_session_liveness()` clears the whole
  map; called from `reset_per_scan` alongside the existing three providers.
  ✅ 1 new regression test
  (`reset_session_liveness_clears_silenced_and_proven_state_across_scans`),
  confirmed via `git stash` as a compile error pre-fix (the function didn't
  exist yet, not a silent pass) and a runtime pass post-fix. Gate green:
  fmt/clippy `-D warnings`/rustdoc clean, full suite 0 failures (4605 lib
  tests, +1). Live-verified: a real `hse serve` process ran `reset_per_scan`
  — including the new call — cleanly across two distinct real scan IDs
  (`selftest`, then an issued API scan) with zero panics; reproducing the
  exact silence-then-unsilence symptom across a genuine block streak would
  need a longer live session than this pass covered, noted honestly rather
  than overclaimed — the guarantee itself (the map is fully cleared) is
  what the regression test pins regardless.
- **`[x]` SOL-WIGLE-RETRY-AFTER · WiGLE acts on its own real `Retry-After`
  instead of discarding it** → **T2.47**, the third and final finding from
  the same background data-freshness/pacing audit, re-confirmed this cycle
  against a fresh real-scan debug bundle the operator supplied.
  `fetch_wigle_typed`/`fetch_wigle_ssid` computed `retry_secs` from a 429's
  real `Retry-After` header purely to log it, then discarded the value and
  returned a hard error whose message embeds the standalone token `429` —
  so the shared per-module circuit breaker (correctly, post-T2.45)
  hard-trips WiGLE for the fixed 600s `RATE_LIMIT_COOLDOWN` regardless of
  what the server actually asked for, over-throttling whenever its real
  hint was shorter (WiGLE's documented burst limits reset well under
  600s). New `get_with_retry` — shared by both search endpoints, replacing
  the near-duplicated inline 429/412/error handling each previously
  carried verbatim — retries a 429 **once**, sleeping the server's real
  value bounded to a new `RATE_LIMIT_RETRY_CAP_SECS` (4s) so the sleep
  always fits inside the module's 20s `max_timeout_ms` even when several of
  its four sub-fetches (WiFi bbox, WiFi SSID, cell, Bluetooth) each hit
  their own 429 in the same `process()` call — mirroring the same "cap the
  server's real hint to the caller's own budget" discipline
  `util::http::handle_keyed_error` already established for keyed modules. A
  persistent 429 (the retry ALSO rate-limited) still degrades to
  `Error::RateLimited` and the prior module-error/circuit-breaker path — no
  infinite retrying, no change to T2.45's already-correct classification.
  ✅ 2 new regression tests
  (`get_with_retry_recovers_from_a_429_using_the_servers_real_retry_after`,
  `get_with_retry_gives_up_after_one_retry_on_a_persistent_429`) drive a
  REAL local `tokio::net::TcpListener` server — the same pattern
  `util::http::tests` already established for exactly this class of
  HTTP-status test, no new mock-server dependency — through the real,
  unmodified `get_with_retry` function over real sockets, both confirmed
  via `git stash` as a compile error pre-fix and a pass post-fix. Gate
  green: fmt/clippy `-D warnings`/rustdoc clean, full suite 0 failures
  (4607 lib tests, +2). Live-verified: a real `hse scan --kind coordinates`
  run against a real Brisbane target completed a genuine WiGLE round-trip
  to `api.wigle.net` through the fixed code path with zero errors; the live
  API did not itself return a 429 in this run, so the retry branch wasn't
  exercised live — deliberately forcing one against a real account would be
  abusive and was not attempted, named honestly as the fallback the
  local-server test covers instead.
- **`[x]` SOL-PROVIDER-OVERHAUL · Audit & repair the entire external
  provider-integration layer** → **T2.48** (first slice), an operator-directed
  program: "completely overhaul and automatically populate the entire API
  system" (scope confirmed via `AskUserQuestion` = external OSINT provider
  integrations; "populate" = wire in the tool's existing key machinery —
  embedded defaults / operator keys / `api_key_probe` / key pool — **not**
  external account registration or credential harvesting). Every keyed/paid
  provider client is to be checked against its live current contract
  (endpoint URL, auth scheme, anonymous-access policy, response shape) and
  repaired, with each provider its own focused, live-verified commit.
  **Slice 1 delivered — `domainsdb`:** a live probe caught the provider had
  disabled anonymous access (`401 "Anonymous access is disabled"`), and the
  module — registered `Free` — was silently swallowing the 401 on every scan
  and emitting nothing. Reclassified `Free`→`KeyGated`, registered
  `HUNTSMAN_DOMAINSDB_KEY` (KNOWN_KEYS + signup_hint), key resolved first
  (clean "needs key" skip when unset), `Authorization: Bearer` sent when
  configured, and a `401`/`403` on a configured key reported to the pool +
  loop-break instead of swallowed. ✅ 2 git-stash-proven tests; gate green
  (4608 lib tests, +1); live-verified against the REAL `api.domainsdb.info`
  (no-key clean skip on a real `github.com` scan; bogus-key → real Bearer
  dial → `403 {"Insufficient credits"}` broken-on after one zone).
  **Comprehensive live audit run (background agent):** every module's real
  external endpoint was live-probed. It confirmed **4 live breaks** —
  `domainsdb` (slice 1), `huggingface_user` (slice 2, below), `sourceforge_user`
  (legacy `/api/user/…/json` removed → Allura `/rest/u/{h}`),
  `opencorporates` (Free tier requires a key since 2023, silent no-op → needs
  key-gating), and `mls` (Mozilla Location Service decommissioned, `404` — a
  delete-or-repoint decision) — and cleared the rest of the free-tier
  external-API surface as healthy (bluesky/codeberg/gitea/gitlab/dockerhub/
  crates/pypi/rubygems/hexpm/npm/keybase/gravatar/hackertarget/rdap/photon/
  overpass/wayback/urlscan/… all live + expected shape). Proxy/transient
  ambiguities (bgpview, reddit DC-IP block, crt.sh 502s, austlii Cloudflare)
  were explicitly NOT called breaks.
  **Slice 2 delivered — `huggingface_user`:** HF migrated its profile API —
  `GET /api/users/{handle}` now `404`s for every real user — so the module
  emitted nothing on every username scan. Repointed to `…/{handle}/overview`
  (handle now in a `user` field, + `createdAt`, no email/website/twitter),
  rewrote the deserializer + identity guard, added the real `account_created`
  date as evidence, dropped the now-dead email/website/twitter extraction.
  ✅ real-`/overview`-body deser regression + 6 others, git-stash-proven;
  gate green (4607 lib tests); live-verified end-to-end — a real `julien-c`
  scan now emits **70 real entities** (was 0 pre-fix) carrying the real 2019
  account-creation date.
  **Slice 3 delivered — `sourceforge_user`:** SF removed its legacy
  `/api/user/username={h}/json` endpoint (now an HTML `404` for every real
  user), so the module emitted nothing on every scan. Repointed to the Allura
  `GET /rest/u/{handle}` — a richer shape (handle in `name`, real name in a
  matching `developers[]` record, plus `creation_date`, `external_homepage`,
  `socialnetworks[]`). Rewrote the deserializer, took the real name from the
  matching developer record (guarded against misattribution), added the
  account-created date as evidence and NEW homepage (Url+Domain) +
  social-account-URL extraction, dropped the now-absent bio-email/location
  extraction, updated `produces()`/`attack_techniques()`. ✅
  real-`/rest/u/`-body deser regression + 10 others, git-stash-proven; gate
  green (4610 lib tests, +3); live-verified end-to-end — a real `jonelo` scan
  recovers the confirmed handle, profile URL, and the real name "Johann N.
  Löfflmann" with the real 2011 creation date (was 0 pre-fix).
  **Slice 4 delivered — `opencorporates`:** OpenCorporates withdrew its
  keyless public tier (2023) — a keyless request now returns `401 {"Invalid
  Api Token"}` — but the module used `key_opt` at `Free`, firing a doomed
  request and swallowing the 401 into an empty result with no needs-key
  notice. Applied the T2.48 template: `Free`→`KeyGated`, `key_opt`→required
  `ctx.key(KEY_ENV)?` (clean "needs key" skip when unset), configured-key
  401/403 reported to the pool instead of swallowed. ✅ 2 tests
  (`module_metadata` asserts KeyGated + a missing-key process test),
  git-stash-proven (runtime assertion failure pre-fix); gate green (4611 lib
  tests); live-verified against the REAL API (no key → `skipped — needs key
  HUNTSMAN_OPENCORP_KEY` on a real `Atlassian` scan).
  **Slice 5 delivered — `mls` deleted (node now `[x]`):** Mozilla Location
  Service was permanently decommissioned (its `geolocate` endpoint 404s); the
  module swallowed the 404 into empty, so BSSID geolocation via it always
  produced nothing. Its own doc called it a redundant "third source alongside
  WiGLE and Mylnikov," and `mylnikov` (free, live) + `wigle` already cover the
  same `MacAddress`→`Coordinates` lookup — so it was deleted (no capability
  lost; a permanently-dead "looks built but isn't" module removed per the
  dead-code doctrine, rather than repointed into a duplicate of `mylnikov`).
  Removed the module + registry wiring + 2 doc-comment mentions, and
  reconciled the module counts across README/`MODULES.md` (`162`→`161`; tier
  split corrected for this deletion and the earlier domainsdb/opencorporates
  reclassifications). ✅ gate green (4601 lib tests; the two module-count
  arch-tests confirm 161); live-verified (`hse modules` no longer lists
  `mls`; `mylnikov`+`wigle` remain).
  **All five audit-confirmed breaks (T2.48–T2.52) are now closed**, so the
  node is complete `[x]` — the entire external provider-integration layer was
  live-audited and every confirmed break repaired or retired. (Provider APIs
  drift over time; a future live audit finding new breakage would open a
  fresh node rather than reopen this one.) **Paired:** `PROBLEM_TREE` T2.48
  (slice 1), T2.49 (slice 2), T2.50 (slice 3), T2.51 (slice 4), T2.52
  (slice 5) — each its own commit.

- **`[x]` SOL-CACHE-TEST-ISOLATION · Robust read-after-write on the
  process-global SeekNow cache in tests** → **T2.53**. Two `util::see_know`
  tests asserted a `cache_put` was observable before continuing, but
  `RESPONSE_CACHE` is a process-global `static` that any concurrent
  scan-running test clears via `reset_per_scan` — so the sanity read flaked
  (~1-in-3 full-suite runs). The in-file `BUDGET_TEST_LOCK` can't serialise
  against out-of-file clearers. Fixed by retrying the put/get up to 200× until
  the unique key is observed present, then keeping the real contract assertion
  (`reset_budget()` clears it — robust, as no other test puts the key)
  unchanged. ✅ diagnosed via a deterministic stress reproduction (since
  removed); full lib suite now passes 8/8 consecutive runs (was ~1-in-3
  flaky); gate green. Paired: `PROBLEM_TREE` T2.53 — same commit.

- **`[x]` SOL-PROVIDER-FIELD-DECODE · Fix dropped / mis-decoded real API
  fields on free, live-reachable provider modules** → **T2.54/T2.55/T2.56**
  (slices 1–3, cluster closed), a
  fresh discovery-pass cluster distinct from SOL-PROVIDER-OVERHAUL (which
  audited endpoint *reachability*; this audits field-level *decode
  correctness* against the live response shape). **Slice 1 delivered —
  `hexpm_user`:** its entire advertised enrichment was dead against the live
  hex.pm API — the top-level `email` (a real personal address) was never
  deserialised, and the `handles` map is keyed by display names (`"GitHub"`,
  `"X.com"`) with full-URL values, so the `match "github"/"twitter"` on the
  raw key never fired (the tests passed only on a fabricated shape). Added
  `email`+`inserted_at` (+`Email` entity, account-age evidence), matched
  handles on the lowercased key, extracted the handle from the URL value
  (`handle_from_link`), sorted the `HashMap` iteration for determinism, and
  updated `produces()`/`attack_techniques()`. ✅ real-body deser regression +
  10 others, git-stash-proven; gate green (4605 lib tests, +4); live-verified
  end-to-end — a real `wojtekmach` scan now recovers the email and the
  GitHub + X/Twitter cross-platform pivots (was neither pre-fix).
  **Slice 2 delivered — both Forgejo modules (`codeberg_user` + `gitea_user`):**
  the top-level `email` the identical Forgejo API returns is either a real
  address or a platform-minted masking placeholder (`user@noreply.codeberg.org`,
  `user@users.noreply.gitea.io`). `codeberg_user` never decoded the field at
  all (a real published address dropped on every scan); `gitea_user` emitted
  the masking placeholder verbatim as a false-positive Email finding. Added a
  single-sourced `util::domains::is_noreply_email_domain` (domain-label match,
  which the local-part role checks miss), added the `email` field + a filtered
  Email branch to `CbUser`, and gated `gitea_user`'s branch through the same
  filter so both siblings agree. ✅ 5 new tests (helper unit coverage + both
  modules' emit/skip/real-deser cases), git-stash-proven (codeberg tests
  fail to compile against the field-less struct; gitea no-reply test fails
  against the un-filtered branch); gate green (4610 lib tests, +5);
  live-verified — `gitea_user`/`techknowlogick` and `codeberg_user`/`earl-warren`
  (both `@noreply.*`) now emit NO Email for the placeholder.
  **Slice 3 delivered — `crates_io` (cluster closed):** the live
  `crates.io/api/v1/users/{login}` response carries a top-level `created_at`
  on every real account (confirmed `dtolnay` `2012-07-09T03:55:40Z`,
  `alexcrichton` `2009-03-19T19:31:50Z`), but `CrateUser` never decoded it —
  the account-age signal every sibling code-registry module records was
  dropped. Added `created_at` + emit it as the `created_at` evidence attr on
  the confirmed-username entity (empty-string guarded). ✅ 2 new tests
  (verbatim-live `dtolnay` deser regression + blank guard), git-stash-proven
  (`error[E0609]: no field created_at`); gate green (4612 lib tests, +2);
  live-verified — a real `dtolnay` scan's JSON export now carries the
  `created_at` attr (absent pre-fix). **No `[ ]` slices remain — all three
  live-reachable field-decode drifts (hexpm / codeberg+gitea / crates) are
  repaired.** **Paired:** `PROBLEM_TREE` T2.54 (slice 1) / T2.55 (slice 2) /
  T2.56 (slice 3) — each slice its own commit.
- **`[x]` SOL-CORRELATOR-INTEGRITY · Close manufactured-corroboration gaps
  found by an exhaustive rule-family audit** → **T2.57** (slice 1). A fresh
  discovery cluster distinct from SOL-CORR (which builds correlation *depth*);
  this audits the existing rule set's evidentiary *integrity* — that no rule
  lets a finding outrun its evidence. Method: one finder per rule family fanned
  out via the Workflow tool, each finding adversarially re-verified through two
  independent lenses (correctness + evidentiary-materiality), only double-lens
  CONFIRMED findings counted. **Slice 1 delivered — AU-081:**
  `rule_au_081_canonical_person_name_match` hand-rolled its two independence
  gates from the raw `evidence` list (source-string set + `source_family` set)
  with NO `is_non_corroborating_source` filter, diverging from every sibling
  (`source_families`/`source_count`/`corroborating_sources`). `name_intel`
  derives a `Person` from the seed and maps to the real `identity_registry`
  family, so a genuine record + a same-name `name_intel`-only entity cleared
  both gates and fired a High "same individual" bridge — the tool corroborating
  its own guess. Fixed by routing both gates through
  `Entity::corroborating_sources()` and adding a gate (0) rejecting any side
  with no corroborating source; labelled by the genuine source, not the
  enrichment pass. ✅ 2 adversarial tests (must-not-fire git-stash-proven to
  fire pre-fix; must-fire control that survives a name_intel-enriched side);
  gate green (4614 lib tests, +2). Real-evidence anchor: a live `name_intel`-only
  scan of "Ada Lovelace" confirmed the `name_intel`-sourced `Person` shape;
  the full cross-source firing was deliberately not staged against a real
  private individual (evidentiary/privacy), so it is unit-proven instead.
  **Slice 2 delivered — AU-056 + AU-085 (jurisdiction cross-checks):** the
  COORDINATE side of both excludes infrastructure geo (`coord_state` →
  `is_infrastructure_geo`) and so do the sibling AU-018/026/030 rollups, but the
  Address branch of both had NO such guard — so a `hosting`/`registrant`
  datacentre address ("Sydney NSW") manufactured a false jurisdiction agreement
  (or a false conflict against the subject's real interstate home). Added
  `&& !is_infrastructure_geo(e)` to both Address branches (twin omission = one
  fix). ✅ 2 must-not-fire tests git-stash-proven; gate green (4565 lib tests,
  +2). **Slice 3 delivered — AU-105 (credential reuse) under-counted SeekNow
  breaches:** `breach_of` read only `dbname`/`breach` else the module name, but
  the `see_know` extractor renames a record's raw `source` breach-name field to
  `source_db`, so every SeekNow breach collapsed to the bare module name — a
  password reused across two SeekNow breaches counted as ONE and the finding
  stayed silent (a false negative on a primary paid breach source). Extended
  `breach_of` to also read `source_db`. ✅ 1 must-fire test git-stash-proven;
  gate green (4566 lib tests, +1). **Slice 4 delivered — AU-048 (shared public
  key) over-stated the account count:** its firing guard correctly requires ≥2
  distinct `canonical_handle`s (treating "alice" + "alice@x.com" as one account),
  but the description reported `accounts.len()` (identifier spellings), so a key
  reused across alice's login + email + bob (3 spellings, 2 owners) claimed
  "controls 3 accounts" — a magnitude over-claim by the rule's own definition.
  Report `handles.len()` instead. ✅ 1 must-fire test git-stash-proven (reports
  "3" pre-fix); gate green (4567 lib tests, +1). *Remaining (banked for later
  cycles):* AU-017/030/099 among the audit's other candidate findings — one
  live-verified commit each. **Paired:** `PROBLEM_TREE` T2.57 (slice 1) / T2.65
  (slice 2) / T2.66 (slice 3) / T2.67 (slice 4) — each slice its own commit.
- **`[x]` SOL-DEADCODE-SWEEP · Resolve "looks built but isn't" dead code /
  unwired capability** → **T2.58** (slice 1). A per-directory sweep (one scanner
  per top-level module dir fanned out via the Workflow tool, each claimed-dead
  item adversarially re-verified by an agent trying to PROVE it live) targeting
  the trap the `dead_code` lint misses: a `pub` item in a `pub mod` compiles
  clean with zero consumers. **Slice 1 delivered — the `util::see_know`
  "enterprise optimization" scaffolding:** four `pub mod`s (`force_multiplier`,
  `monitoring`, `orchestration`, `endpoint_matrix`) that `mod.rs` re-exported
  nothing from and nothing consumed. The real import graph (NOT a bare grep —
  that FALSELY flagged the live `enterprise_config`, which `budget.rs` uses via
  `ENTERPRISE`, and matched a same-named struct field) showed all four unwired;
  each duplicates capability the live see_know client + engine already provide,
  and the one useful artefact (`RETRY_STRATEGY` backoff numbers) was already
  salvaged into `util::backoff` by T2.44. Decision: DELETE — ~1,529 lines + the
  obsolete, unreferenced `docs/HARDCODED_ENTERPRISE_OPTIMIZATION.md`;
  `enterprise_config` kept. ✅ The compiler proves the deletion safe (lib + full
  suite build clean, 4614 lib tests unchanged — the dead code had no live
  tests); gate green. **Slice 2 delivered — the `util::multi_api_*` "enterprise
  orchestration" subsystem:** four `pub mod`s (`multi_api_config`/
  `multi_api_workflows`/`multi_api_orchestrator`/`multi_api_integration_tests`,
  2,443 lines) from the same autonomous-validation experiment. Verified provably
  unwired — every public symbol has 0 refs outside the four files;
  `config`/`orchestrator` are consumed only by the `#[cfg(test)]`
  `integration_tests`, `workflows` by nothing. It re-implements from a hardcoded
  stale "12 paid APIs" table the orchestration/budgeting/chaining/dedup that
  `core::engine::dispatch` already does natively. Decision: DELETE (~2,443 lines
  + the obsolete `docs/MULTI_API_ENTERPRISE_ORCHESTRATION.md`). ✅ Compiler proves
  it safe (build clean); gate green (4569 lib tests, −45 — all removed tests
  lived in the deleted `integration_tests` and exercised only the dead code).
  **Slice 3 delivered — `util::autonomous_validation`:** the last island of the
  autonomous-validation experiment; its own doc-comment says it exists to
  "prove multi-API orchestration works end-to-end", i.e. it validated the
  `multi_api_*` orchestration deleted in slice 2, so it is now definitively
  dead. All 7 public symbols have 0 external refs; the module path is imported
  nowhere; it carried 9 self-referential tests. Decision: DELETE. ✅ Compiler
  proves it safe (build clean); gate green (4560 lib tests, −9 — all removed
  tests exercised only the deleted module). This closes the autonomous-validation
  experiment cleanup (slices 1–3 = see_know scaffolding + multi_api +
  autonomous_validation, ~4,000 dead lines removed). **Slice 4 delivered —
  `core::profiles::list_profiles` (the first WIRE-IN, not a delete):** the
  profile catalogue `(name, description)` had 0 callers despite its doc claiming
  the CLI/API rendered it, while the CLI's unknown-`--profile` error hand-typed
  a drifting name list that hid the descriptions. Decision: WIRE-IN (a real,
  useful capability) — the error now renders `list_profiles()` as
  `name — description`, single-sourcing the help. Proved against a REAL target
  (`hse scan … --profile bogus` prints all six profiles + descriptions,
  previously invisible); drift-guard test git-stash-proven. Gate green (4560 lib
  tests). **Slice 5 delivered — the dead consts in the surviving
  `see_know::enterprise_config` (finishes the see_know cleanup):** T2.58 kept
  the file for its live `ENTERPRISE` plan config, but it still carried 7
  speculative hardcoded tables (`WORKFLOWS`/`DAILY_RECOMMENDATIONS`/
  `API_KEY_PATTERNS`/`ENTITY_EXTRACTORS`/`MONITORING_THRESHOLDS`/`SLA`/
  `WORKFLOW_RECOMMENDATIONS`), each with a struct instantiated only by its own
  dead const — all 0-ref, all duplicating native capability. Decision: DELETE —
  trimmed to just `EnterprisePlan` + `ENTERPRISE` (~406 lines). ✅ Compiler +
  clippy `-D warnings` prove it safe (no field newly-unused); gate green (4560
  lib tests). **Slice 6 delivered — two isolated dead `pub fn`s
  (`util::curl::fetch_post`, `util::key_pool::pool::set_environment`):** 0-ref
  standalone helpers in live modules; `fetch_post` is the redundant `UA_MOBILE`
  POST variant (its `_with_ua` sibling stays live), `set_environment` duplicates
  the add-time path. Own-decision verification corrected two sweep mislabels
  (`shortest_path`/`validate_for_kind` are test-only/re-exported, not 0-ref —
  deferred). Decision: DELETE; compiler + clippy prove it safe. *Remaining
  dead-code backlog (banked):* `store_api_credential_from_item`
  (re-exported-but-uncalled, delete), `TACTIC_ID`/`TACTIC_NAME` (dead attack-vocab
  consts), and the wire-in-vs-delete judgement calls (`refresh_pool`/
  `prune_degraded`/`host_state`/`set_private`/`validate_for_kind`/`shortest_path`
  + `storage` low-confidence trio) — one careful decision each. **Slice 7
  delivered — the inert `util::proxy` rotation subsystem (a whole "looks built
  but isn't" trap):** a re-run wide sweep + hand-verification found
  `util::proxy::ProxyPool` constructed in every runtime and threaded into
  `ModuleContext.proxy_pool` with a doc claiming `next()` is called to rotate —
  but `refresh_pool` (the sole `pool.replace()` caller) has 0 call sites and
  `next()` has 0 call sites; no module, CLI flag, or route touches it. The
  earlier sweeps missed it because a `pub` FIELD never trips `dead_code`. The
  SSRF guards live in `util::preflight`/`util::http::ssrf` (not `util::proxy`),
  and the live `HUNTSMAN_SEARCH_PROXY` → `fetch_via_proxy` single-proxy path is
  independent — so the subsystem is self-contained. Decision: DELETE (full
  auto-harvest+rotation wire-in exceeds one safe pass and can't be proven against
  flaky free proxies; delete-unwired-scaffolding precedent). Removed
  `src/util/proxy/` (311 LOC), the field from `ModuleContext`/`AppState`, 8
  construction sites, ~45 test initializers, stale comments; TIGHTENED
  `tests/architecture.rs` (removed the now-dead `util::proxy` import exception —
  a strengthening). ✅ Compiler + clippy `--all-targets` prove completeness;
  live-verified the deletion left the pipeline intact — the rebuilt binary runs
  `hse selftest` 9/9 and `hse scan -v Kylo4kylo` dispatched 46 modules → 96
  entities. Gate green (4565 lib tests, −4 — the proxy module's own tests).
  *Backlog still banked:* shortest_path / validate_for_kind / prune_degraded /
  host_state / set_private (empirically redundant — DB already 0600) / TACTIC
  consts / store_api_credential_from_item. **Paired:**
  `PROBLEM_TREE` T2.58 (slice 1) / T2.59 (slice 2) / T2.60 (slice 3) / T2.61
  (slice 4) / T2.62 (slice 5) / T2.63 (slice 6) / T2.70 (slice 7) / T2.71
  (slice 8) / T2.72 (slice 9) / T2.73 (slice 10) / T2.74 (slice 11) — each
  slice its own commit.
  **Slice 8
  delivered — the second WIRE-IN: the scan-completion webhook that was
  configured but never fired.** The sweep
  surfaced `core::webhook::notify_scan_complete` (the fire-and-forget
  `scan_complete` POST) with zero callers — but NOT dead-to-delete:
  `webhook_url_from_env()` is wired (`cli/scan`/`cli/live` read
  `HUNTSMAN_WEBHOOK_URL` into `ScanOptions.webhook_url`), so a configured webhook
  stored the URL and silently never POSTed, and the module doc claimed the engine
  fired it. Decision: WIRE-IN (a genuine, useful, deterministically-provable
  feature). `finalise_scan` now fires the POST on the terminal state (in the async
  context after the `spawn_blocking` finalise, since the POST is async and the
  finalise is blocking), payload built from the completed scan, fire-and-forget
  (bounded 10 s, never errors). ✅ Proven against a REAL target: a local HTTP sink
  + `HUNTSMAN_WEBHOOK_URL` + `hse scan -v Kylo4kylo` captured the real POST
  (entity_count 141 / status aborted / correlations 7) where the pre-fix binary
  sent nothing; git-stash-proven regression test with a one-shot TCP sink.
  **Slice 9 delivered — the third WIRE-IN, and a mid-implementation re-scope:
  weak-findings triage, wired into `hse doctor` instead of the sweep's original
  `hse audit` suggestion.** `Store::low_confidence_evidence` (every stored
  entity below the review threshold, weakest-first, module-resolved) had zero
  callers despite being fully built and tested. Its own doc frames it as
  cross-scan triage ("the audit trail an LE/defence reviewer reads"); `hse
  audit` is per-scan, and the query has NO `scan_id` filter — wiring it there
  would blend unrelated scans' weak entities into one investigation's score,
  the wrong-scope contamination this project's correlator audits (AU-056/085,
  AU-105, T2.69) have repeatedly closed. Re-scoped to `hse doctor` — the
  established cross-scan dashboard (T2.7/SOL-HEALTH-SIGNAL is the precedent).
  New "Weak findings" section, pure `format_weak_findings` helper (query/
  presentation split), `EvidenceAnomaly` newly re-exported from `storage`
  (was unreachable outside its own private submodule). ✅ Live-proven FIRST: a
  fresh empty DB and a real 96-entity `Kylo4kylo` scan (all entities ≥0.40)
  BOTH correctly report "no weak findings" (honest-empty-state holds); a real
  name-seed scan hitting `name_intel`'s permutation-pivot path (0.20 conf)
  populates the section with "117 weak finding(s)," weakest-first, module
  resolved, capped at 20 + "and 97 more." THEN 3 git-stash-proven tests.
  **Slice 10 delivered — restoring a REAL, previously-fixed, previously-
  QUANTIFIED bug lost off a diverged branch.** `is_username_derived_name`
  (validation/placeholder.rs) was fully built with zero callers. Git
  archaeology: commit `63d13142` (2026-06-24) already fixed this — a real
  scan of `full_name = "rhino-ryno23 rhino-ryno23"` produced 123 entities,
  94% noise, because `EntityKind::Person → TargetKind::FullName` spawns a
  child scan on the garbage name — but that commit is not an ancestor of
  `main`; only the (since-refined, hyphen+digit not bare-hyphen) predicate
  survived, not the wiring. Both `oathnet_pro/breach.rs` AND
  `see_know/extract/mod.rs` share the identical unguarded Person-construction
  pattern (breach `full_name`/`display_name`/`name` → `Entity::new`, gated
  only on length/whitespace) — a live gap on `main`, not hypothetical.
  Decision: WIRE-IN at BOTH real construction sites (the historically-
  validated insertion point, closer to the source than a generic admission
  gate would be); dropped the predicate's permanently-unused
  `_query_value: &str` parameter (reserved "for future tightening" in the
  original commit, never read by either version of the body) since this is
  its first real caller. ✅ Live-verified: a real scan of `Kylo4kylo` ran
  cleanly through the fixed code with `oathnet_pro`/`see_know` enabled (both
  executed genuine network round-trips, zero regressions); honestly
  disclosed the exact garbage-name specimen wasn't organically reproducible
  in this sandbox today (SeekNow's embedded key provider-rejected; OathNet's
  live search returned 0 results this run) — so the git-stash-proven
  regression tests, built from the EXACT real value the 2026-06-24 incident
  observed (not invented), are the documented proof: 3 tests (the predicate;
  `oathnet_pro`'s extractor; `see_know`'s extractor), all failing when the
  predicate is neutered to always return `false`, all passing restored. Gate
  green: fmt/clippy `-D warnings`/rustdoc clean, full suite 0 failures (4573
  lib tests, +3). Paired: `PROBLEM_TREE` T2.73 — same commit.
  **Slice 11 delivered — a correct rejection with an under-informative
  message: `confusable::skeleton` had zero callers.** `Target::validate`
  correctly rejects a mixed-script homograph seed but only says "possible
  spoof," never naming what the value actually normalizes to — the data
  `skeleton()` already computes. Two enrichment designs assessed and
  rejected: enriching the admission-gate's `Option<&'static str>` reason
  would fragment `hse audit`'s `excluded_reasons` histogram (keyed on the
  exact string) into one bucket per distinct spoofed value; converting
  `validate`'s return type wholesale touches 27 `Err` arms for one arm's
  benefit. Decision: WIRE-IN, narrowly — a new `Target::validate_verbose()
  -> Result<(), Cow<'static, str>>` that calls `validate()` unchanged and
  enriches ONLY the homograph arm (matched against a shared
  `HOMOGRAPH_REASON` const, so the two can never textually drift) with the
  ASCII skeleton; every other rejection reuses `validate`'s exact message via
  `Cow::Borrowed` — zero new allocation on the other 26 arms. All 3 real call
  sites (`cli/scan`, `cli/live`, the HTTP API's `validated_target`) switched
  to the verbose form, 1 line each; `validate()` itself untouched. ✅
  Live-verified on all 3 real paths with a genuine real-world spoof (the
  textbook Cyrillic-`а` `pаypal.com` PayPal-phishing homograph): `hse scan`,
  `hse live`, and `POST /api/v1/scans` all now print "...possible spoof) —
  ascii skeleton: paypal.com" where they previously stopped short.
  Git-stash-proven regression test: neutering `validate_verbose`'s
  enrichment fails it; restored, it passes; also pins every OTHER rejection
  byte-identical to `validate`'s original message. Gate green: fmt/clippy
  `-D warnings`/rustdoc clean, full suite 0 failures (4574 lib tests, +1).
  Banked: the same enrichment at the admission-gate's mid-scan
  `confusable_homoglyph` drop needs a non-histogram-corrupting channel (a
  `tracing::debug!` line, or an additive `EventKind::EntityExcluded` field)
  — its own scoped decision. Paired: `PROBLEM_TREE` T2.74 — same commit.
  **Slice 12 delivered — cleared the banked 19-item DELETE batch, but
  re-verification at implementation time found 7 of the 19 misclassified.**
  All 19 re-confirmed zero-production-caller (5 commits had landed since the
  original sweep), but implementing each deletion surfaced two blind spots a
  per-directory rg-based reference count structurally cannot see: whether a
  "test-only" caller is the item's OWN dedicated test (safe to delete both
  together) or an ORACLE another kept function's test depends on (deleting it
  silently guts real coverage of a live function), and whether a "dead"
  accessor is genuinely redundant (as `set_private` — the DB is already 0600
  under umask 0022, per this same sweep's own T2.70 finding) or mirrors an
  ALREADY-WIRED sibling gate elsewhere with no substitute of its own (as
  `is_quota_exhausted`/`is_unverified`). Reclassified 7, KEPT unchanged:
  `rank_autonomous_targets` (the flat-ranking oracle two live tests compare
  `plan_autonomous_sweep`'s `diversity=0.0` output and
  `rank_identity_aware_targets`'s singleton case against); `host_state` (the
  only introspection surface the circuit-breaker tests use to assert
  `allow_host`/`record_failure`/`record_success`'s real Closed→Open→HalfOpen→
  Closed transitions); `is_quota_exhausted` (see_know) and `is_unverified`
  (wigle) — each documents an intended gate (mirroring `oathnet`'s
  already-wired quota latch) that is never actually checked before further
  billable/repeat lookups — a real unwired efficiency gap, not dead code,
  banked as its own future WIRE-IN rather than deleted or silently wired
  mid-batch; `LIVE_MAX_DEPTH`/`LIVE_DEFAULT_CONCURRENT` (grouped with the
  already-banked `LIVE_DEFAULT_THROTTLE_MS` WIRE-IN — deleting 2 of 3 sibling
  live-mode tuning constants while banking the third would be incoherent).
  Deleted the remaining 12, each confirmed genuinely redundant with capability
  fully preserved elsewhere: `confusable_report`, `autonomous_seed`,
  `shortest_path` (its tests re-pointed to `paths_between` so the MAX_HOPS-
  bound and self-path coverage survive), `validate_for_kind` (whole
  `composite.rs` file), `TACTIC_ID`/`TACTIC_NAME`, `DERIVED`,
  `store_api_credential_from_item`, `extract_first` (inlined as a private
  test helper over the live `extract_all` so its 4 regex-parsing tests keep
  their only coverage), `is_personal`, `is_bsb_shaped`, `set_private`, and
  `AuditEntity::confidence` — a write-only struct field. Fixing `confidence`
  surfaced a THIRD- and FOURTH-order finding: the original sweep's
  re-verification only checked `analysis.rs`/`events.rs`/`mod.rs` for reads
  and missed two more construction sites still setting the dead field —
  `cli/audit/mod.rs`'s CSV parser and `tests/audit_regression.rs`'s fixture
  builder — both fixed in the same pass. ✅ Live-verified the one behavioural
  surface touched (the `confidence` removal): a real `hse scan -k username -v
  Kylo4kylo` → `hse export --format csv` → `hse audit --csv` round-trip
  scored 92/100 with the correct 1-verified/0-probable/0-candidate tiers,
  confirming `c_effective` (the field that actually drives scoring) is
  untouched. Gate green: fmt/clippy `-D warnings`/rustdoc clean, full suite 0
  failures (4566 lib tests). Net −286 lines across 23 files. Paired:
  `PROBLEM_TREE` T2.75 — same commit.
- **`[x]` SOL-ROLE-MAILBOX-COMPOUND · Suppress provider-prefixed system
  mailboxes (DNS SOA / registrar desks) from posing as the subject's email** →
  **T2.68**. Found by a PRIORITY-5 LIVE end-to-end pass (real binary vs the
  canonical seed `Kylo4kylo`, then `hse audit`), not a self-audit:
  `awsdns-hostmaster@amazon.com` — the standard AWS Route53 SOA RNAME — was
  present as a subject email. `dns_intel` guards with `!is_infrastructure_email`
  → `is_role_localpart`, but that exact-matched only the WHOLE alphanumeric
  local-part, missing the compound `awsdns-hostmaster`. Fix: segment-match an
  UNAMBIGUOUS system-role token (`hostmaster`/`postmaster`/`abuse`/`dns`/… — NOT
  the business tokens, to never suppress a real subject email). ✅ Live-proven
  first (rebuilt binary: `dns_intel` on `amazon.com` now emits zero emails), THEN
  git-stash-proven regression test with no-false-positive controls; gate green
  (4568 lib tests, +1). *Banked:* WHOIS-registrant emitters (`whoisxml`/`netlas`/
  `ripestat`) emit registrant `privacy@`-style role mailboxes with no guard — a
  separate emitter-side fix. **Paired:** `PROBLEM_TREE` T2.68 — same commit.
- **`[x]` SOL-GEXF-COOCCURRENCE-RECORD · Co-occurrence edges key on the evidence
  RECORD, not the source name, so a fan-out probe can't clique its results** →
  **T2.69**. Found by a PRIORITY-5 LIVE export, not a self-audit: the canonical
  `Kylo4kylo` scan's `graph.gexf` had **2973 edges over 118 nodes** while every
  other view reports **39** typed relations. `write_shared_evidence_edges` drew a
  co-occurrence edge for every pair sharing a `corroborating_sources()` NAME, and
  `username_search` (one handle → ~70 platform probes, one entity each) was
  carried by 70 entities → a 70-clique = **2415 edges (81%)**; `social_probe`/
  `streaming_probe` two more. Independent existence-proofs of one selector are
  not a joint sighting — exactly the *"dense web of false 'related' clusters"*
  the function's doc-comment claims to avoid. Fix: new
  `Entity::corroborating_records()` returns the `(source, summary)` pairs (same
  `is_non_corroborating_source` filter); co-occurrence keys on shared RECORDS, so
  fan-out's distinct per-platform summaries draw no edge while a genuine
  same-breach (identical `("hibp","Breach 'Apollo'")`) or same-crawled-page record
  survives. Typed relations untouched. ✅ Live-proven first (rebuilt, re-exported
  the SAME stored scan: **2973 → 46 edges** — 39 typed relations + 7 real
  co-occurrence, still valid XML), THEN git-stash-proven regression test
  (`gexf_co_occurrence_is_record_level_not_source_level`); golden test
  byte-unchanged; `corroborating_sources()` + its correlator/coref/export callers
  untouched (new method, gexf-only). Gate green (4569 lib tests, +1). **Paired:**
  `PROBLEM_TREE` T2.69 — same commit.
- **`[x]` SOL-RANDOMIZED-MAC · Flag randomized/private MAC addresses instead of
  attributing them as real devices** → **T2.64**. Surfaced by a real
  1,643-device Android BLE-radar export the operator supplied: `util::oui::
  classify_mac` (live via `wigle`'s `MacAddress` tagging) had no concept of a
  locally-administered address (U/L bit `0x02`), so a randomized/private
  address (which modern phones, AirTags, etc. rotate every ~15 min) was tagged
  `vendor:Unknown` and could anchor a colocation/tracking claim it can't
  support. Added `DeviceClass::Randomized` + `is_locally_administered`;
  `classify_mac` now returns `Randomized` for LA addresses without a lookup, so
  `wigle` tags them `device:randomized`. ✅ 3 tests (git-stash-proven), gate
  green (4563 lib tests, +3). Validated on the real corpus: 698/1,643 (42%) are
  randomized (the source app had mislabelled 345 with a manufacturer — the exact
  false attribution now avoided); real MACs kept out of the repo, committed tests
  use synthetic addresses. *Follow-up (banked):* the colocation/identity rules
  (AU-032/AU-106) could additionally DOWN-WEIGHT or skip `device:randomized`
  entities so an ephemeral address never forms an identity cluster — a scoped
  next step. **Paired:** `PROBLEM_TREE` T2.64 — same commit.

### S.PROCESS — The methodology itself ⚑

- **`[x]` SOL-PAIRED-TREES · The problem/solution pair + gap analysis** ⚑ — *this
  document* + `PROBLEM_TREE.md`, maintained per §0. Closes the meta-problem "what is
  wrong and how it's solved live in different heads / drift apart."
- **`[x]` SOL-GATE · The verification gate** — `fmt --check` · `clippy --all-targets
  --locked -D warnings` · strict private-item rustdoc · `cargo test`; every fix lands
  with a regression test that fails against the unfixed code. ✅ (CLAUDE.md).
  *Extended (2026-07-12) — closed a hand-maintained-count drift class the
  gate itself couldn't catch:* the module-count guard
  (`readme_module_overview_count_matches_registry`) already tied README's
  module total to `modules::registry().len()`, but no equivalent existed for
  the correlator's rule count — which went stale within the same session
  (README still read 108 immediately after a rule addition brought the live
  split to 97 entity + 12 relation = 109; only `ARCHITECTURE_AUDIT.md` had
  been reconciled). New `pub fn core::correlator::rule_counts() ->
  (usize, usize)` + a new architecture test
  `readme_correlator_rule_count_matches_registry` ties the README prose to
  the live registry the same way, so this specific drift class can't recur
  silently. Confirmed via `git stash` to fail against the pre-fix (108)
  README text. Gate green: fmt/clippy `-D warnings`/rustdoc clean, full
  suite 0 failures (31 architecture tests, +1). Paired: `PROBLEM_TREE` §7
  Docs — same commit.
- **`[x]` SOL-AUDIT-CADENCE · Multi-agent adversarial re-audit** — parallel fan-out
  (parsers / storage-API / engine / correlator / SPA / security / internals) with
  honest "clean" verdicts; the source of T2.8–T2.12 and the §7 detail. ✅
  **Extended to operator-triggered real-scan review (2026-07-11):** a real
  scan's CSV export + debug bundle surfaced an apparent P1 evidentiary-integrity
  shape (a US breach-candidate address geo-corroborated at "~0 km" from an
  Australian subject anchor) — investigated by direct reproduction against
  HEAD rather than assumed. `core::geo_family::au_postcode()`/
  `distance_to_subject()` correctly return `None` for the exact real entity
  shape (a US 5-digit ZIP under `postal_code`/`addr_postal` keys, never the
  literal `postcode` key `au_postcode` requires): the bundle's own
  `hse_version`/module-count header shows it predates the current tree, so the
  visible defect is most likely already closed by the existing
  `au_postcode_ignores_a_leading_us_street_number` hardening. A second,
  related thread (two QLD family-candidate addresses also carrying
  `exact-name-match` despite neither visible register owner matching the
  subject's full name) reproduces the per-record classification
  (`au_unclaimed::qld_helpers::owner_matches_full_name`) as correct in
  isolation but could not be fully root-caused without the raw upstream CKAN
  response — logged honestly as unresolved (`PROBLEM_TREE` §6) rather than
  guessed at. Two new regression tests pin both verified-sound findings
  against the real data (`real_scan_us_breach_address_reproduction`,
  `per_record_address_tags_are_correct_before_any_merge`). No code changed —
  a clean-verdict investigation is a correct outcome, not a failed one.
- **`[x]` SOL-TERMUX-EXCLUSIVITY · A 5-agent parallel audit applying the
  SOL-AUDIT-CADENCE methodology to a single, project-defining question: does
  Huntsman actually stay inside its own "Termux, aarch64, no root" mission
  everywhere, and can it genuinely be operated exclusively through the web
  UI?** Operator instruction: "make it exclusively for Termux android
  aarch64 no root using the web UI." Fanned out 5 independent, read-only
  investigators before any code changed: root-requirement leaks (raw
  sockets, privileged ports, `sudo`/`su`, `/proc/sys` writes), non-Termux
  platform assumptions (hardcoded desktop paths, systemd/launchd, bind
  defaults, native-TLS deps), external-process dependencies (every
  `Command::new` call site's Termux-availability), CLI-vs-web-SPA feature
  parity, and loopback-bind/guard consistency across every sensitive route.
  Three came back genuinely clean — strong, converging evidence this
  codebase already internalises the constraint throughout (`is_termux()`,
  `$HOME`-relative paths everywhere, `#![forbid(unsafe_code)]` structurally
  ruling out raw sockets, a `DEFAULT_BIND` of `127.0.0.1:8080` pinned by an
  architecture test, every `TcpListener::bind` in the tree traced to exactly
  one production call site). Two produced real, fixed findings (T2.90:
  `settings_keys_get`'s missing loopback guard; T2.91: the dead `hcitool`
  Bluetooth fallback) — see `PROBLEM_TREE` T2.90/T2.91 for detail, same
  commit. The parity audit's own findings (most notably `hse cells` being
  100% CLI-only despite backing web-reachable Radar/`cell_intel` features)
  are real and substantial but deliberately deferred to a dedicated next
  node (T2.92) rather than rushed into this commit — the same "one unit of
  work per cycle" discipline every prior audit-derived fix in this tree has
  followed. Demonstrates the audit-fan-out pattern generalises beyond
  parser/storage/engine/correlator/SPA/security/internals (SOL-AUDIT-
  CADENCE's original scope) to a project's own mission-statement invariants
  — a reusable technique for any future "does the code still match what we
  claim it is" question. Gate green: fmt/clippy `-D warnings`/rustdoc clean,
  full suite 0 failures (4619 lib tests, net -1; 98 `tests/api.rs`
  integration tests, +1). **Paired:** `PROBLEM_TREE` T2.90/T2.91 — same
  commit.
  *Extended (2026-07-14) — `hse cells` cell-tower DB management is now
  reachable from the web UI, T2.92:* the deferred parity finding closed.
  `status|import|clear` was 100% CLI-only despite backing web-reachable
  features (Live Signal Radar, `cell_intel`) — the most severe gap the
  parity audit found, a functional limitation not a convenience one. New
  `GET /api/v1/cells/status` (ungated, matching `settings_toggles_get`'s
  precedent for non-secret aggregate data — a tower count and a local cache
  path carry none of the "which paid services are configured" sensitivity
  the keys-family routes gate), `POST /api/v1/cells/import` (loopback-only,
  the server-side download-by-country path — the CLI's first documented
  use case — reusing `update/trigger`'s exact async-trigger-plus-poll
  shape: 202 immediately, a detached task drives the download+import, the
  SPA polls status), `POST /api/v1/cells/clear` (loopback-only, requires
  explicit `{"confirm":true}` — the HTTP equivalent of the CLI's
  interactive "type 'yes'" prompt). Extracted 3 pure functions from
  `cli::cells` (`opencellid_filename`, `opencellid_download_url`,
  `clear_cells_db`) so the API calls the identical country→filename→URL
  and DB-clear logic the CLI already uses, not a duplicate — the same
  reuse-not-duplicate discipline this tree applies everywhere a CLI
  command gets a web equivalent. Raw local-file import deliberately stays
  CLI-only, named honestly as a follow-on: a browser upload path sized for
  a real multi-hundred-MB OpenCelliD extract needs its own bounded-
  streaming design, distinct from the existing 16 MB text-body upload
  route, and inventing one under this cycle's scope would risk exactly the
  kind of rushed, under-reviewed change this tree's discipline exists to
  avoid. New "Cell Tower Database" panel in Settings (status, country-code
  import with progress polling, confirm-gated clear). 19 new tests: 4 pin
  the pure helpers; the rest cover both handlers' loopback gating, the
  atomic import check-and-claim (refuses a concurrent second call while
  `Running`, allows a fresh one after a prior `Error`), empty-country and
  missing-confirm rejection, and the status shape on an empty DB; extended
  `tests/api.rs`'s closed-world SPA-endpoint guard with a `cells` probe.
  Live-verified end-to-end via headless Chromium against the real compiled
  binary: the panel renders the empty-DB state, the no-OpenCelliD-key
  import path fails gracefully — this same verification pass caught and
  fixed a real bug where the status message stayed stuck at "Starting
  import…" instead of clearing on error — and the clear-confirm-dialog →
  real DELETE → success-toast round-trip completes with zero uncaught JS
  errors. Gate green: fmt/clippy `-D warnings`/rustdoc clean, full suite 0
  failures (4632 lib tests, +13). **Paired:** `PROBLEM_TREE` T2.92 — same
  commit.
  *Extended (2026-07-14) — the New Scan wizard can now select a named scan
  profile, including `skiptrace`, T2.93:* the parity audit's other named
  finding closed. All 6 `core::profiles` presets were already accepted by
  `scan_create` (`resolve_profile`/`apply_profile_overlay` already wired
  in — `list_profiles()`'s own doc comment even said it was "available to
  the API/SPA profile picker"), but no route ever exposed the catalogue and
  the wizard's existing "By Use Case" radios are a genuinely different,
  SpiderFoot-style concept (module selection, not tuning presets) confirmed
  by inspection to be orthogonal, not a duplicate to retire — so `skiptrace`
  (the debtor-location profile) had zero web UI path, not even an
  imitation. New `GET /api/v1/scan/profiles` returns `list_profiles()` as
  JSON — the wizard's only source for the name/description list, so it
  can't drift from `resolve_profile`'s accepted set — and a new "Scan
  Profile" `<select>`, always visible above Advanced options, sends
  `profile:<name>` in the scan-create request when set; the SERVER'S
  existing overlay does all the tuning-field merging, so the wizard
  duplicates none of a profile's actual values client-side (a future
  profile tuning change can't silently drift out of sync with the SPA).
  New regression test pins the wire shape (all 6 names, non-empty
  descriptions), git-stash-proven by reverting the route registration
  (404s the probe); restored, passes. Live-verified end-to-end via headless
  Chromium against the real compiled binary: the `<select>` lists all 6
  real profiles, choosing `skiptrace` updates the inline description, and
  submitting a real scan (target `Kylo4kylo`, the project's own canonical
  consented test seed) produced a queued scan whose STORED options exactly
  matched `skiptrace()`'s tuning (`depth:3`, `min_expand_confidence:0.45`,
  `max_concurrent:4`, `max_entities:800`, `max_wall_time_secs:420`,
  `expansion_strategy:"geo_converge"`, `regional_search:true`, the full
  8-category `category_focus`) — confirmed via `GET /scans/{id}`, zero
  uncaught JS errors. Gate green: fmt/clippy `-D warnings`/rustdoc clean,
  full suite 0 failures (4632 lib tests unchanged net; 99 `tests/api.rs`
  integration tests, +1). **Paired:** `PROBLEM_TREE` T2.93 — same commit.
  *Extended (2026-07-14) — two false "equivalent to a CLI command" claims in
  the SPA corrected, T2.94:* a dedicated sweep for this exact defect class,
  run as a broader-net follow-up immediately after T2.93, checked every
  "equivalent to"/"same as"/"mirrors [a CLI command]" claim in
  `src/web/js/` against the real CLI code each one names — six matched
  genuinely (Scan Profile picker, wizard defaults, the Cells panel's
  already-self-caveated claim, Key Harvest's account-probe claim, the
  Benchmark tab, the scraper-health panel); two didn't, both because the
  web path does MORE than the bare CLI command it names, not less. (1)
  `state.js`'s "Complete (All)" preset claimed equivalence to `hse scan
  --full` but omitted `expand_all_identities:true` (confirmed against
  `src/cli/mod.rs`'s `Command::Scan` match arm); `--full`'s other implied
  flag, `include_infra`, was separately confirmed to be a post-scan
  report/display filter (`cli::scan::filter_infra_entities`), never a
  `ScanOptions` field at all, so there's nothing to add to a scan-creation
  preset for it — the web Browse tab simply has no display toggle yet, now
  honestly named as a gap rather than silently glossed over. (2) The Audit
  tab's footer claimed "Same audit as `hse audit --scan-id <id>`," but
  `scan_audit` unconditionally folds in stored-event signals (`fold_events`
  — no `--log` file needed, it reads the scan's own DB events) and the live
  engine-health cache, while the literally-named bare CLI invocation
  computes zero source-health signals without also passing `--log`. Fixed
  both by correcting the copy to state the true relationship, not by
  changing any computation — the web path's extra completeness in both
  cases is a virtue, not a defect to remove. No Rust changed; JS-only.
  Live-verified end-to-end via headless Chromium against the real compiled
  binary: submitting "Complete (All)" now includes
  `expand_all_identities:true` in the actual `POST /scans` body (confirmed
  via request interception); the Audit tab's rendered footer shows the
  corrected disclosure verbatim; zero console errors. Gate green: fmt/
  clippy `-D warnings`/rustdoc clean, full suite 0 failures (4632 lib
  tests, 99 `tests/api.rs` tests — both unchanged, no new Rust surface).
  **Paired:** `PROBLEM_TREE` T2.94 — same commit.
  *Extended (2026-07-14) — closed the last thread T2.94's own caveat named,
  T2.96:* tracing precisely where the missing `include_infra` toggle needed
  to live surfaced that `wants_infra` was fully implemented and tested but
  wired into exactly one handler, `scan_report_json` — Browse/CSV/GEXF/the
  debug bundle never filter `platform-infra` entities at all, so T2.94's
  "Browse tab" framing named the wrong surface; the JSON report download was
  the sole real gap, matching the CLI's own scope (`--include-infra` only
  ever reaches `render_report`). Added an `includeInfra` param to
  `API.reportUrl` and a checkbox in the scan-info header toggling the JSON
  link's `href` live; corrected T2.94's caveat wording to point at the
  now-closed gap. No Rust changed — purely SPA wiring onto an already-
  correct, already-tested server capability. Live-verified via headless
  Chromium against a real stored scan: checkbox renders, toggling flips the
  href between `report.json` and `report.json?include_infra=1`, zero
  console errors. Gate green: fmt/clippy `-D warnings`/rustdoc clean, full
  suite 0 failures (4632 lib tests, 99 `tests/api.rs` tests — both
  unchanged). **Paired:** `PROBLEM_TREE` T2.96 — same commit.

---

## 3. Leverage map — which solution closes which problems (the join)

| Solution | Problem nodes closed / powered | Status |
|---|---|---|
| SOL-F1 (automata) ⚑ | F.1 · T0.1/T0.2 (root) · T2.7 · T2.8 · C6 | `[~]` |
| SOL-F2 (`fst`) ⚑ | F.2 · B5.3 drift · typosquat/variants | `[~]` |
| SOL-F3 (proof) ⚑ | F.3 · guards T0.x/T1.1/T1.3/T2.3/T2.8/T2.9 | `[~]` |
| SOL-BOUNDARY | T0.1 · T0.2 | `[x]` |
| SOL-MERGE | T1.1 · C1 (identity core) | `[x]` |
| SOL-ORDER | T1.1 · T2.9 | `[x]` |
| SOL-PANIC | E3.1 / SPOF #2 | `[x]` |
| SOL-ARCH | T1.4 | `[x]` |
| SOL-OUTPUT-ESCAPE | §7 SPA XSS | `[x]` |
| SOL-BLOCKING | T2.2 · T1.2 (all write paths) | `[x]` |
| SOL-FINALISE-BLOCKING | T1.5 | `[x]` |
| SOL-SCHEMA-VERSION | T2.10 | `[x]` |
| SOL-STORAGE-DIAG | T2.15 | `[x]` |
| SOL-CHMOD-DIAG | T2.16 | `[x]` |
| SOL-LATEST-SCAN-ERR | T2.17 | `[x]` |
| SOL-EXPOSURE-DOB | T2.18 | `[x]` |
| SOL-FILTER-CANDIDATE-LEAK | T2.20 | `[x]` |
| SOL-INSTALL-INTEGRITY | §7 S5 | `[x]` |
| SOL-BUDGET | T2.11 oathnet (accepted-as-is) | `[-]` |
| SOL-CAP | T2.1 · T2.8 (all sub-items) | `[x]` |
| SOL-ISOLATE | T2.11 found_keys | `[x]` |
| SOL-LIVE-DISPATCH-BUDGET | T2.11 LOW over-dispatch | `[x]` |
| SOL-SSRF / -WHOIS | §6 (HTTP) · §7 S2 | `[x]`/`[x]` |
| SOL-SECRETS / -EXTEND | env/pool/archive · §7 S3 | `[x]`/`[x]` |
| SOL-REDACT | §7 S4 | `[x]` |
| SOL-EMBED | §7 S1 (accepted) | `[-]` |
| SOL-CLI-CONTRACT / -DIFF / -CACHE | T2.12 | `[x]`/`[x]`/`[x]` |
| SOL-ROI-HINT | T2.13 | `[x]` |
| SOL-HINT-NOISE | T2.14 | `[x]` |
| SOL-RULE-METAGUARD | T1.3 (dispatch firing coverage) | `[x]` |
| SOL-STREAMING | C8 | `[x]` |
| SOL-AU-MOAT | C3 | `[~]` |
| SOL-NETINT | C4 | `[~]` |
| SOL-CACHE-INTERSCAN | C9 | `[x]` |
| SOL-CORR | C1 | `[~]` |
| SOL-PERF-PUBLISH | C2 | `[ ]` |
| SOL-GEOINT | C5 | `[~]` |
| SOL-OFFENSIVE | C6 | `[~]` |
| SOL-FORENSIC | C7 | `[ ]` |
| SOL-HEALTH-SIGNAL | T2.7 (per-source health) | `[~]` |
| SOL-UPDATE | UX self-upgrade + CLI consolidation | `[x]` |
| SOL-UPDATE-GIT-FIXTURE | T2.21 | `[x]` |
| SOL-GREYNOISE-KEYED | T2.22 | `[x]` |
| SOL-USERNAME-SLUG-GATE | T2.23 | `[x]` |
| SOL-HN-DOMAIN-DETERMINISM | T2.24 | `[x]` |
| SOL-WEB-CRAWLER-ORDER-DETERMINISM | T2.25 | `[x]` |
| SOL-EMAIL-USERNAME-ORDER-DETERMINISM | T2.26 | `[x]` |
| SOL-GITHUB-ATTACK-COMPLETE | T2.27 | `[x]` |
| SOL-DOCKERHUB-ATTACK-COMPLETE | T2.28 | `[x]` |
| SOL-CODEWARS-ATTACK-COMPLETE | T2.29 | `[x]` |
| SOL-MASTODON-ATTACK-COMPLETE | T2.30 | `[x]` |
| SOL-SOURCEFORGE-ATTACK-COMPLETE | T2.31 | `[x]` |
| SOL-NAMEINTEL-ATTACK-COMPLETE | T2.32 | `[x]` |
| SOL-UPDATE-POISON-CONSISTENT | T2.33 | `[x]` |
| SOL-WIGLE-412-GRACEFUL | T2.34 | `[x]` |
| SOL-CEFF-TRANSPARENCY | T2.35 | `[x]` |
| SOL-LOCATION-SEED-NO-REAFFIRM | T2.36 | `[x]` |
| SOL-SEEKNOW-SUBJECT-GATE | T2.37 | `[x]` |
| SOL-AU063-DOC-FIX | T2.38 | `[x]` |
| SOL-AU039-SHARED-SOURCE | T2.39 | `[x]` |
| SOL-SNIPPET-PII-SUBJECT-GATE | T2.40 | `[x]` |

---

## 4. Gap analysis — the live diff between the trees (refreshed every pass)

> This section *is* the alternation made concrete. **4a** = problems with no started
> solution (P→S gaps, the build queue). **4b** = solutions begun but unfinished (the
> finish queue). **4c** = solutions with no problem (over-build — prune candidates).
> When 4a + 4b are empty, the two trees agree.

### 4a · Problems with NO solution yet started (P→S coverage gaps)
- ~~**T2.39**~~ — **delivered** ✅ (`SOL-AU039-SHARED-SOURCE`, 2026-07-11). The
  deferred design decision was resolved by investigating the data model:
  `Entity::corroborating_sources()` carries the provenance at this call site,
  so AU-039 now gates wallet→identity attribution on a **shared corroborating
  evidence source** (a real co-location tie) instead of the arbitrary global
  min-UID anchor. Off the open queue.
- **T2.7** scraper-health signal — **implemented, hard-failure leg (2026-07-11):**
  SOL-HEALTH-SIGNAL's `last_success_at`/`consecutive_failures` tracking and `hse
  doctor` surface are built, derived from the existing cross-scan event log (no
  new tracking table needed). *Remaining:* SPA panel, parse-rate/zero-yield-based
  drift detection, and the golden-fixture corpus (the other named T2.7 leg —
  rewrite parsers on `bstr`/`aho-corasick`, saved real responses per source).
  **Elevated (cycle 17):** ahpra/acma_rrl/trove_au/`austlii` widen the scraper
  surface; priority remains raised. *This §4a summary is stale on the SPA
  panel/parse-rate-drift items (both delivered 2026-07-12/13 — see the
  SOL-HEALTH-SIGNAL node's own text for the current, accurate state); kept
  verbatim rather than rewritten to avoid clobbering concurrent edits, per
  this pass's discovery.* **`au_property` leg (2026-07-14):** the golden-
  fixture corpus's `au_property` slice, previously logged as "still
  proxy-blocked," is confirmed reachable-but-dead (real live `404`s on all
  three legs) and now fails loudly (`Error::module`) instead of silently —
  see the `au_property` honest-failure fix in the SOL-HEALTH-SIGNAL node.
  Replacement endpoints for its three legs remain the real, still-open
  residual. **Golden-fixture corpus, seventh slice (2026-07-14):** you.com
  fixture added, disproving its own stale doc comment and fixing a real
  `ENGINE_DOMAINS` chrome-leak (`cdn.you.com`) — see the SOL-HEALTH-SIGNAL
  node's own text. 8 of 17 `search_engines` engines now have a golden
  fixture; the remaining 9 (`yahoo`/`aol`/`google`/`mojeek`/`yandex`/
  `ecosia`/`qwant`/`presearch`/`searx`) are confirmed blocked/unreachable
  from this sandbox this slice — a future cycle running from a
  residential/Termux IP could still fetch one.
- ~~**§7 S4**~~ — **delivered** ✅ (SOL-REDACT extended, 2026-07-12). Investigation
  found the archive FILE itself (`raw/*.json`) is deliberately never redacted
  (an explicit operator retention policy in `util::raw_archive`'s own doc
  comment), so the real residual was the dossier's *rendering* of that
  archive, which an explicit `hse export -o <path>` can carry out to a
  world-readable file. Fixed at the render site (`redact_credentials` over the
  pretty-printed body in `render_full`), archive file untouched. Off the open
  queue.
  *(T2.10/SOL-SCHEMA-VERSION + S5/SOL-INSTALL-INTEGRITY delivered cycle 16 — both off
  this queue. S2/SOL-SSRF-WHOIS + S3/SOL-SECRETS-EXTEND delivered 2026-06-17.)*
- **C8** — **delivered** ✅ (`SOL-STREAMING`, 2026-06-17). Off the open queue.
- **C9** — **delivered** ✅ (SOL-CACHE-INTERSCAN, cycle 18). Off the open queue.
- **C3** — `[~]` (SOL-AU-MOAT). `austlii` delivered cycle 20 (courts/AustLII closed).
  *Remaining:* GNAF/AusPost address validation; fuller ASIC/ABR graph; state
  cadastre/property.
- **C4** — `[~]` (SOL-NETINT). S→P audit cycle 20: `securitytrails`, `bgpview`, and
  `ripestat` were stale "remaining" notes — all three modules already registered.
  *Remaining:* passive-DNS history; CDN cert-hash origin pivot.
- **C5** — `[~]` (`opencellid` cycle 19 + `cell_local` + `hse cells import` cycle 21
  delivered; free offline DB leg now available; Weiszfeld/Welzl centroid + provenance
  radius + auto-sync still open).
- **C1** — `[~]` (SOL-CORR), corrected stale note (found cycle 27, 2026-07-05):
  this bullet previously read "none started," but C1/SOL-CORR has been
  in-progress since cycle 26 (`identity_paths` + CONNECTIONS) and advanced
  again this cycle (timeline `classify` widened). *Remaining:* further AU-0xx
  rule-gap fill; the "controller behind reused secrets" link facet.
- **C2/C7** — capability nodes; solutions sketched, none started (gated on
  the §3.F enablers landing first, by design).
- **C6** — `[~]` (SOL-OFFENSIVE), corrected stale note (found 2026-07-12):
  this bullet previously grouped C6 with "none started," but 2 of its 4
  named solution items (credential-reuse graph maturity, aho-corasick +
  entropy key-harvest precision) were already fully delivered — just never
  credited back to the node. *Remaining:* broader SERP exposure-dork
  coverage (open-ended); richer stealer-log cross-referencing.
- ~~**AU-060-candidate (cycle 20 S→P gap): `opencellid` × `cell_intel` cell-tower
  cross-validation.**~~ **Delivered, stale note (found 2026-07-01).** The gap was
  real when logged (cycle 20) but was built and shipped 2026-06-30
  (`770df4c9`) as **AU-084** — "Dual-source cell tower corroboration"
  (`rules::geo::cluster::rule_au_084_cell_tower_dual_source`), Low severity at
  1–2 dual-confirmed towers, Medium at ≥3, exactly the "medium-confidence
  corroboration when both modules fire for the same tower" signal this note
  asked for. `AU-060` itself was independently reassigned in the interim to
  "Transitive identity closure" (`rules::transitive`), so the number this
  note names no longer even refers to cell towers — a second reason the note
  was stale, not just "not yet started." Registered in the correlator's
  dispatch table, 4 dedicated tests
  (`au084_fires_when_both_sources_present`,
  `au084_does_not_fire_on_single_source`,
  `au084_medium_severity_for_three_or_more_towers`,
  `au084_ignores_non_cell_tower_device_ids`). Off the open queue.
- **cell_local auto-sync (new, cycle 21 S→P gap):** `hse cells import` requires a
  manual trigger and a BYO OpenCelliD key; no auto-scheduled re-sync exists. A
  recurring `hse cells import --country world` cron/daemon path would keep the local
  DB fresh without user intervention. No solution node yet.
  *Partially addressed (2026-07-12) — a lighter-weight step, not the full
  gap:* actually scheduling a re-sync needs cron/daemon infrastructure this
  codebase carries none of anywhere, and Termux/Android has no reliable
  persistent-process story to hang one off, so building a scheduler stays
  out of scope. What was buildable and real: the risk the gap names — a
  local dataset silently going stale with nothing to flag it (`hse cells
  status` shows the age but never calls it out) — is now surfaced. New
  `util::cell_db::is_stale`/`STALE_THRESHOLD_DAYS` (180 days) plus a "Cell
  tower database" section in `hse doctor`, mirroring T2.7's scraper-health
  signal exactly (tower count, import age, a `STALE` line past the
  threshold naming the fix command). Live-verified against a not-populated
  DB, a fresh import, and a fabricated 200-day-old import. 1 new regression
  test, gate green. **The scheduled-re-sync half of this gap remains open
  by design** (no scheduler infrastructure to build it on).
- ~~**hse update --check changelog (cycle 22 S→P gap): `--check` reports only a
  commit count, no subject lines.**~~ **Delivered, stale note (found
  2026-07-01).** `cli/update.rs::changelog_lines` runs exactly the suggested
  `git log --oneline HEAD..@{u}` and `cmd_update`'s `--check` branch already
  prints up to 20 of its lines beneath the commit count
  (`for line in changelog_lines(dir).iter().take(20)`). Present in the source
  as read this cycle; this repository's own history begins at its single
  root commit (`770df4c9`, 857 files / 244,800 lines in one commit — an
  import, not an incremental change), so — unlike the AU-084 correction
  above — no earlier delivery date or authoring cycle can be attributed from
  `git log` here; it simply predates this repo's history and was never
  reconciled into this note. **Residual, real gap — closed 2026-07-05:**
  `changelog_lines`/`commits_behind` were untested — no fixture exercised
  the actual `git` subprocess calls. Closed by **SOL-UPDATE-GIT-FIXTURE**
  (new node **T2.21**): a local origin+clone `tempfile` fixture pair proves
  both functions against real `git fetch`/`rev-list`/`log` output.

### 4b · Solutions begun but unfinished (the finish queue)
- **SOL-F1** — substrate + **seven** consumers landed (`is_captcha_page`,
  key-harvest `contains_excluded_context`, wigle `is_generic_ssid`, the
  **prefix-table `PrefixMatcher`** — 170 prefixes, `LeftmostFirst`, group map for
  same-prefix duplicates, proptest-backed — `au_electoral` HTML markers via
  `MatchSet::find_range`, `address_au::state_code` step-2 via `MatchSet::find_id`,
  and **`decode_entities`** — `memchr` direct dep promoted; `memchr(b'&', …)` /
  `memchr(b';', …)` replace `str::find`/`contains` on the hot page-body decode path).
  *Remaining:* `bstr` (no natural consumer yet — all scraped HTML arrives as `&str`
  via `read_body_capped`→`String::from_utf8_lossy`; `bstr` promotes only when a
  module takes raw `&[u8]` response bytes directly). Unblocks T2.7 + sharpens C6.
- **SOL-F2** — de-dup done; large-table premise corrected (cycle 18): OUI ≈111
  entries, AU postcode ≈72 entries, phone area codes ≈65 entries — `fst` is overkill
  at these sizes. `fst` adoption `[-]` (accepted-won't-build); Levenshtein fuzzy
  matching deferred to a lighter mechanism when needed.
- **SOL-F3** — proptest (str/entity/geo/html/cert/dns + import parsers) + criterion
  landed; only `cargo-fuzz` (nightly CI lane) left.
- **SOL-CAP** — ✅ fully closed (`[x]`). All T2.8 sub-items done (2 HIGH + MED
  network reads + hibp cast + CLI-import file cap). Removed from finish queue.
- **SOL-BUDGET** — ✅ accepted `[-]` (cycle 18 S→P): `reset_per_scan` already
  called at `run_with_ledger_inner:289`; cited residual was a faulty premise.
  Off the finish queue.

### 4c · Solutions with no problem (over-build — prune candidates)
- **None found.** Every solution node traces to ≥1 `PROBLEM_TREE` node or the shared
  mission. The codebase is lean (0 unused deps via `cargo machete`, 0 dead modules);
  the audit cadence (SOL-AUDIT-CADENCE) keeps deleting dead code (e.g. `util::stats`),
  which is the over-build guard working. Re-check each pass.

### 4d · Coverage snapshot (problem tier × solution status)
- **T0 (crashes):** fully solved (SOL-BOUNDARY + SOL-F3 guard). ✔
- **T1 (core guarantees):** T1.1/T1.2/T1.3/T1.4/T1.5 all solved — SOL-BLOCKING
  `[x]` (all write paths); SOL-FINALISE-BLOCKING `[x]` (cycle 14, T1.5 closed). ✔
- **§3.F (foundations):** all three `[~]` — the largest unrealised leverage block.
  `memchr` now a direct dep (cycle 12); remaining: `bstr` + `cargo-fuzz` (note:
  `fst` large-table adoption `[-]` — tables are curated subsets, not registry-scale).
- **T2 (robustness):** T2.1–T2.6 + T2.9 solved; **T2.8 fully closed** ✅;
  **T2.10 `[x]`** ✅ (SOL-SCHEMA-VERSION, cycle 16); **T2.12 fully closed** ✅;
  **T2.15 `[x]`** ✅ (SOL-STORAGE-DIAG, 2026-07-05); **T2.16 `[x]`** ✅
  (SOL-CHMOD-DIAG, 2026-07-05); **T2.17 `[x]`** ✅ (SOL-LATEST-SCAN-ERR,
  2026-07-05); **T2.18 `[x]`** ✅ (SOL-EXPOSURE-DOB, 2026-07-05); **T2.20
  `[x]`** ✅ (SOL-FILTER-CANDIDATE-LEAK, 2026-07-05); **T2.21 `[x]`** ✅
  (SOL-UPDATE-GIT-FIXTURE, 2026-07-05); **T2.22 `[x]`** ✅
  (SOL-GREYNOISE-KEYED, 2026-07-05); **T2.23 `[x]`** ✅
  (SOL-USERNAME-SLUG-GATE, 2026-07-05); **T2.24 `[x]`** ✅
  (SOL-HN-DOMAIN-DETERMINISM, 2026-07-05); **T2.25 `[x]`** ✅
  (SOL-WEB-CRAWLER-ORDER-DETERMINISM, 2026-07-05); **T2.26 `[x]`** ✅
  (SOL-EMAIL-USERNAME-ORDER-DETERMINISM, 2026-07-05); **T2.27 `[x]`** ✅
  (SOL-GITHUB-ATTACK-COMPLETE, 2026-07-05); **T2.28 `[x]`** ✅
  (SOL-DOCKERHUB-ATTACK-COMPLETE, 2026-07-05); **T2.29 `[x]`** ✅
  (SOL-CODEWARS-ATTACK-COMPLETE, 2026-07-05); **T2.30 `[x]`** ✅
  (SOL-MASTODON-ATTACK-COMPLETE, 2026-07-05); **T2.31 `[x]`** ✅
  (SOL-SOURCEFORGE-ATTACK-COMPLETE, 2026-07-05); **T2.32 `[x]`** ✅
  (SOL-NAMEINTEL-ATTACK-COMPLETE, 2026-07-05); **T2.33 `[x]`** ✅
  (SOL-UPDATE-POISON-CONSISTENT, 2026-07-05); T2.7 open;
  **T2.11 `[x]`** ✅ (2026-07-05: oathnet + found_keys/SOL-ISOLATE + LOW
  over-dispatch/SOL-LIVE-DISPATCH-BUDGET all closed; the one residual note
  (budget-static `reset_scan`-zeroing) was itself already accepted `[-]` by
  SOL-BUDGET back in cycle 18 — SOL-ISOLATE's own text just never caught up to
  that, corrected this cycle); T2.14 open (deferred noise design).
- **S.CORE sensor gate:** **SOL-SENSOR-GATE `[x]`** ✅ (cycle 24) — all six
  live-sensor modules now consistently gate on `Coordinates | MacAddress` and
  appear in `LOCAL_PASSIVE_MODULES`; non-geo scans receive zero phone-sensor
  data.
- **§7 (security):** XSS + S2 + S3 solved; S1 accepted; **S5 `[x]`** ✅
  (SOL-INSTALL-INTEGRITY, cycle 16); S4 residual open (LOW).
- **§4 (capability C1–C9):** C8 delivered ✅ (`streaming_probe`, 42-site webcam/fan/adult prober); **C9 delivered** ✅ (SOL-CACHE-INTERSCAN, cycle 18, `raw_archive` + dispatch cache gate); **C5 `[~]`** (SOL-GEOINT: `opencellid` cycle 19 + `cell_local`/`hse cells import` cycle 21 delivered, Weiszfeld geometric-median convergence delivered 2026-07-01 — stale here since, corrected 2026-07-05; movement/timeline layer's first increment (`shot_time`→`LocationVisited`) delivered 2026-07-14; AU bounding precision, a multi-event movement/path layer, and cell-DB auto-sync remaining); **C3 `[~]`** (SOL-AU-MOAT: hlr_cnam/ahpra/acma_rrl/trove_au/smtp_vrfy/`austlii` shipped, courts/AustLII closed; GNAF/ASIC/cadastre remaining); **C4 `[~]`** (SOL-NETINT: netlas + censys + securitytrails + bgpview + ripestat all shipped; passive-DNS history + CDN cert-hash origin remaining); **C1 `[~]`** (SOL-CORR: `identity_paths` + CONNECTIONS cycle 26, timeline `classify` widened cycle 27, `SharesSecretWith` reused-secret link cycle 28, AU-112 shared-CIDR-infrastructure rule 2026-07-13; only the `Ssid` rule-gap remains, blocked on an import-extractor change); C2/C6/C7 open by design, gated on §3.F. **SOL-UPDATE `[x]`** (cycle 22, `hse update`/upgrade + CLI consolidation 19→13 visible commands).

---

## 5. Maintained log (paired with `PROBLEM_TREE` §8)

- **2026-06-17** — **Created the tree of solutions** as the dual of the problem tree
  and wired the §0 paired-maintenance protocol (same-commit rule, P→S / S→P
  alternation, gap analysis as the bridge). Seeded every solution node from the real
  current state and back-referenced its `PROBLEM_TREE` node(s); ran the first full
  gap analysis (§4): the largest unrealised leverage is the §3.F enabler block
  (SOL-F1/F2/F3 all `[~]`), the highest-value discrete open solution is SOL-ISOLATE
  (T2.11 found_keys), and the highest-value *contained* security solution is
  SOL-SSRF-WHOIS (§7 S2). No over-build found (§4c empty). `PROBLEM_TREE` updated in
  the same commit to reference this file and the protocol.
- **2026-06-17** — **SOL-ISOLATE delivered `[ ]`→`[x]`** (the first solution-tree
  node driven to done under the paired protocol). The `found_keys` sink is keyed by
  `scan_id` via a `tokio::task_local` the engine scopes around `run_with_ledger` +
  each spawned dispatch task; the `core_does_not_import_util_directly` allowlist —
  i.e. SOL-ARCH — turned out to be the *enabler*, not the blocker (the pure
  `with_scan` leaf is allow-listed, so no util-HTTP-layer threading was needed).
  **S→P alternation result:** delivering SOL-ISOLATE closed T2.11's headline bullet
  and left only the LOW over-dispatch + the budget-static reset-zeroing (the latter
  now reuses this same ambient — a *new* small solution leaf, logged in §4b under
  SOL-BUDGET). Gap analysis refreshed: §4a/§4b no longer list found_keys; the §3.F
  enabler block (SOL-F1/F2/F3) is now the clear top of the finish queue. Paired:
  `PROBLEM_TREE` T2.11 + §8 updated in the same commit.
- **2026-06-17** — **Cycle run on request: gap analysis → SOL-SSRF-WHOIS `[ ]`→`[x]`.**
  Exercised the methodology rather than regenerating the tree. **P→S/gap step:** §4
  named SOL-SSRF-WHOIS the highest-value *contained* open solution, so it was driven
  to done — `client::resolve_public_whois` (port-43 only, `is_local_domain` refused,
  public-`!is_private_addr` resolve, pinned `SocketAddr`) closes the §7 S2 whois SSRF
  (raw TCP/43 had bypassed the HTTP `SsrfResolver`). Behaviour-preserving; hermetic
  test. **S→P/gap-refresh step:** §4a now lists only S3/S4/S5; §4d §7 row shows XSS+S2
  solved; with both SOL-ISOLATE and SOL-SSRF-WHOIS delivered, the **§3.F enabler
  block (SOL-F1 automata / SOL-F2 fst / SOL-F3 cargo-fuzz)** is the sole remaining
  high-leverage tier and the unambiguous next target. Paired: `PROBLEM_TREE` §7 S2 +
  §8 updated in the same commit; gate green, 2,997 lib tests.
- **2026-06-17** — **Cycle: cleared the contained S.QUALITY queue — SOL-DIFF-DEDUP
  `[ ]`→`[x]`, SOL-CACHE-REFRESH `[ ]`→`[x]`, SOL-CLI-CONTRACT `[ ]`→`[~]`.**
  **Deliberate gap-analysis choice:** SOL-F1 (top *leverage*) is a genuine
  large-scale refactor, so this cycle took the highest-value *contained* items
  instead (the methodology balances leverage against the "no large refactor rushed"
  rule), closing the four T2.12 MED/LOW-MED periphery bugs — `keys add` honest error,
  `provision --verify` non-zero exit, uid-deduped `diff`, full-cache refresh. Each
  behaviour-preserving on legitimate input + regression-tested. **Gap refresh:** §4d
  T2 row now "T2.12 mostly done"; the §3.F enabler block (SOL-F1/F2/F3) remains the
  sole high-leverage tier and is explicitly flagged as needing a *dedicated* cycle,
  not a rushed one — that's the honest next target. Paired: `PROBLEM_TREE` T2.12 + §8
  same commit; gate green, 2,999 lib tests.
- **2026-06-17** — **The dedicated SOL-F1 cycle: substrate + first consumer.** Took
  the flagged high-leverage item as its own cycle (not a rushed corner): `aho-corasick`
  → direct dep; `util::scan::MatchSet` cached automaton (tests + `criterion` bench);
  first consumer = the SERP anti-bot `is_captcha_page` scan, converted **byte-for-byte
  equivalent** (5 captcha tests unchanged). Scoped exactly as promised last cycle.
  `memchr`/`bstr` deliberately *not* promoted yet (no direct consumer → `cargo
  machete` would fail) — they land with their first use. SOL-F1 stays `[~]`: the
  *substrate* is the leverage unlock; the remaining consumers (universal key scanner,
  HTML markers, denylists) are now cheap, contained increments to route through it.
  **Gap refresh:** §4b SOL-F1 line updated from "no substrate" to "substrate landed,
  consumers remaining"; F.1/SOL-F1 is now the *only* partially-delivered enabler with
  a clear incremental path. Paired: `PROBLEM_TREE` F.1 `[ ]`→`[~]` + baseline deps +
  §8 — same commit; gate green, 3,004 lib tests, benches compile.
- **2026-06-17** — **Cycle: SOL-SECRETS-EXTEND `[ ]`→`[x]` (§7 S3).** Gap-analysis
  pick: the universal-key-scanner SOL-F1 conversion needs a proptest-backed effort
  (its `min_len`/table-order/entropy semantics aren't a clean aho-corasick swap), so
  it's staged like the substrate was; this cycle took the cleanest high-value
  *contained* item. Added `atomic_file::{create_dir_private, set_private}`; the
  auto-dossier (every scan; PII + harvested keys) and the SQLite DB are now 0600 in a
  0700 `~/.huntsman` — consistent with the existing env/pool/raw 0600. Explicit
  `export -o` left to the user's umask (deliberate boundary). Two perms tests.
  **Gap refresh:** §4a §7 now lists only S4/S5 (both LOW); §4d §7 row "XSS + S2 + S3
  solved". The only high-leverage tier left is §3.F (SOL-F1 consumers / SOL-F2 fst /
  SOL-F3 fuzz); the contained security queue is down to two LOW items. Paired:
  `PROBLEM_TREE` §7 S3 `[ ]`→`[x]` + §8 — same commit; gate green, 3,006 lib tests.
- **2026-06-17** — **Cycle: +2 SOL-F1 consumers (substrate reuse).** First ruled out
  two candidates by analysis: the **T1.3 firing meta-guard** isn't a clean source-scan
  (firing assertions are too heterogeneous to enumerate, and rule-source `"AU-NNN"`
  emissions confound a presence scan — it needs a fixture-table refactor), and the
  **key-scanner prefix table** needs a proptest-backed conversion (min_len/table-order).
  So took two clean, zero-risk denylist conversions onto `util::scan`:
  `contains_excluded_context` (hot key-gate; `new_ascii_ci` also drops an alloc) and
  `is_generic_ssid` — both proven by existing tests. **Gap refresh:** §4b SOL-F1 now
  "three consumers landed"; the remaining big item (key-scanner table) is explicitly
  tagged proptest-backed. SOL-F1 stays `[~]` — the substrate keeps paying off one
  contained, equivalence-proven consumer at a time. Paired: `PROBLEM_TREE` F.1 +§8 —
  same commit; gate green, 3,006 lib tests.
- **2026-06-17** — **Cycle: T2.8 MED tail — SOL-CAP-EXTEND.** Gap-analysis pick
  (P→S pass): §4b named SOL-CAP the highest-value *contained* finish-queue item —
  §3.F enablers need their own dedicated staged push. Closed all remaining MED
  network-read gaps in one pass: **`json_decode`** now routes through `read_json_text`
  (32 MiB cap + raw-archive retention; a 4-line change closing ~24 uncapped sites —
  every `json_decode` caller, including shodan, censys, dehashed, zoomeye, onyphe,
  leakix — behaviour-preserving, existing test unchanged); **three direct callers**
  (`doh_resolver:310/322`, `wigle/account:95`) route through `json_decode`; **nine
  AU-gov scraper** `resp.text()` sites routed through `read_body_capped(resp,
  1_000_000)` (`asic_director`, `au_electoral` ×4, `au_people` ×2, `au_property` ×3)
  — the `web_crawler` pattern, now uniform; both **hibp cast** sites →
  `u32::try_from(…).unwrap_or(u32::MAX)` (P3, saturating). **S→P gap-refresh:**
  SOL-CAP gap narrows to one LOW item (CLI-import cap); §4b SOL-CAP + §4d T2 row
  updated. The §3.F enabler block (SOL-F1 key-scanner / SOL-F2 fst / SOL-F3 fuzz)
  is confirmed the sole remaining high-leverage tier. Paired: `PROBLEM_TREE` T2.8 +
  §8 same commit; gate green, 3,006 lib tests, 0 failures.
- **2026-06-17** — **Cycle 2 (S→P): SOL-BLOCKING tail + SOL-CAP LOW tail — both
  closed.** §4b's two open finish items taken together (both contained, complementary):
  **(1) SOL-BLOCKING** — `scan_import` now acquires `s.scan_semaphore` before parsing
  (mirrors the `spawn_scan` throttle: import floods can no longer crowd out live scans
  on the 2-worker reactor); all sync DB work (`upsert_scan`, `upsert_entities_batch`,
  `crate::core::relation::derive_all` + loop, `Correlator::run` + loop) dispatched to
  `tokio::task::spawn_blocking` with the typed closure `move || -> core::error::Result<_>`.
  `stats` wraps `list_scans(10_000)` in `spawn_blocking`. **(2) SOL-CAP** — the final LOW
  item: `cli/import/mod.rs:24` `std::fs::read_to_string` now prefixed with a
  `std::fs::metadata().len()` guard (local `MAX_IMPORT_BYTES = 16 MiB`); realistic
  imports byte-identical. **SOL-CAP: `[~]`→`[x]`.** **S→P gap-refresh:** T2.8 fully
  closed; T1.2 further advanced (reactor clear of import/stats blocking; engine
  `insert_event` + DB-writer actor remain); §4b SOL-CAP removed from finish queue,
  SOL-BLOCKING updated; §4d T2 + T1 rows updated. The §3.F enabler block remains the
  sole remaining high-leverage tier. Paired: `PROBLEM_TREE` T2.8 `[~]`→`[x]`, T1.2
  cycle-2 note + §8 — same commit; gate green, 3,010 lib tests, 0 failures.
- **2026-06-17** — **Cycle 3 (P→S): SOL-BLOCKING engine tail (T1.2) +
  SOL-CLI-CONTRACT diff exit-code (T2.12).** P→S/gap-analysis identified two
  remaining contained items in §4b and T2.12 LOW-misc: **(1) SOL-BLOCKING engine
  tail** — `EventEmitter::emit` (`core/engine/mod.rs:152`) now clones the
  `Arc<dyn StoragePort>` and wraps `store.insert_event(&event)` in
  `tokio::task::block_in_place`: the per-entity blocking rusqlite write is no longer
  bare on the async reactor. Cascading fix: `tests/halting.rs` (3 tests) + all 42
  async tests in `tests/smoke.rs` upgraded from default `#[tokio::test]`
  (`current_thread`) to `#[tokio::test(flavor = "multi_thread", worker_threads = 2)]`
  — `block_in_place` panics on a single-thread runtime, and tests should reflect the
  2-worker `new_multi_thread` production runtime anyway. **(2) SOL-CLI-CONTRACT diff
  exit-code** — `cmd_diff` now `return Err(Error::Other("both sides resolve to the
  same scan"))` inside the footgun guard (`cli/diff/mod.rs:74`) instead of falling
  through to `Ok(())`; integration test `diff_wiring_self_compare_is_rejected_with_diagnostic`
  (renamed + rewritten) verifies the non-zero exit + stderr diagnostic. **P→S
  gap-refresh:** SOL-BLOCKING §4b updated (DB-writer actor is the sole remaining
  tail); SOL-CLI-CONTRACT residual narrowed (`audit` + incomplete-scan); §4d T1 +
  T2 rows updated. §3.F enabler block remains the highest-leverage unrealised tier.
  Paired: `PROBLEM_TREE` T1.2 cycle-3 note + T2.12 diff note + §8 — same commit;
  gate green, 3,006 lib + 54 smoke + 3 halting + 23 cli tests, 0 failures.
- **2026-06-17** — **Cycle 4 (P→S): SOL-F1 key-scanner prefix table.** §4b identified
  the 170-prefix `identify_vendor_api_key` O(N) `starts_with` loop as the remaining
  high-leverage SOL-F1 item. Delivered: `util::scan::PrefixMatcher` (`LeftmostFirst`,
  `find_prefix(&str) -> Option<usize>`, anchored at offset 0 — declaration order
  preserved, so specific-before-generic remains correct without a full linear scan);
  two statics in `key_harvest/mod.rs`: `PREFIX_MATCHER` (aho-corasick lookup) +
  `PREFIX_GROUPS` (pre-grouped indices for same-prefix duplicate entries — `phc_`
  has two at min_len 40/30, `pk_live_` covers Stripe+Clerk overlaps at O(K≤2) per
  matched token). The hot-path for non-matching tokens is now O(len(token)) vs O(N=170);
  matched tokens add only O(K) group iteration. Intentional quality improvement:
  a token whose most-specific prefix (lowest KEY_PATTERNS index) fails `min_len` returns
  `None` rather than cascading to a shorter generic prefix — short `sk-svcacct-` tokens
  were previously misclassified as `openai_or_stripe`; this is now `None`. Proven by:
  proptest `vendor_key_never_panics_on_arbitrary_input` (fuzz safety) +
  `synthesised_token_result_is_sane` (positive-case sanity) + deterministic
  `min_len_failure_on_specific_prefix_does_not_cascade_to_generic`. **Gap refresh:**
  §4b SOL-F1 updated (4 consumers; remaining = HTML markers + memchr/bstr); §4d §3.F
  unchanged (all `[~]` — HTML markers next). Paired: `PROBLEM_TREE` F.1 cycle-4 note
  + §8 — same commit; gate green, 3,009 lib + 67 api + 23 arch + 54 smoke + 3 halting
  + 6 cli-seed + 2 audit-regression tests, 0 failures.
- **2026-06-17** — **Cycle 6 (P→S): SOL-F1 `address_au` state-name scan +
  SOL-CLI-CONTRACT `resolve_scan_id` status-check — T2.12 fully closed.**
  P→S gap pass identified two remaining contained items in §4b and T2.12 LOW-misc.
  **(1) SOL-F1 sixth consumer — `address_au::state_code` step 2:** Added
  `MatchSet::find_id(&str) -> Option<usize>` (pattern index of leftmost match —
  complements `find_range`; enables pattern-indexed dispatch without a second table
  scan). Added `STATE_NAMES_MATCHER: LazyLock<MatchSet>` static (8-pattern ASCII-CI
  automaton over `STATE_NAMES`). Replaced `to_lowercase()` + 8-way `contains` loop
  with `find_id(text).map(|id| STATE_NAMES[id].1)` — one Teddy/SIMD pass, no alloc.
  Test `find_id_returns_pattern_index`. The au_property `extract_suburb_from_line`
  path was examined and ruled out (single dynamic state string already known from
  `extract_state` — not a MatchSet target). **(2) SOL-CLI-CONTRACT-SCAN
  `resolve_scan_id`:** `match` on `get_scan(raw)?` now additionally checks
  `scan.status != ScanStatus::Complete` and returns a `{status}`-named `Err` — was
  returning the id regardless of scan completeness. Updated two caller tests
  (`diff::load_side_tags`, `export::explicit_scan_id`) to create `Complete` scans;
  added `resolve_scan_id_rejects_incomplete_scans`. SOL-CLI-CONTRACT `[~]`→`[x]`
  (all four exit-code sub-items done). **Gap refresh:** §4b SOL-F1 "6 consumers;
  remaining = memchr/bstr only"; SOL-CLI-CONTRACT removed from finish queue; §4d T2
  "T2.12 fully closed ✅". §3.F enabler block remains the sole unrealised
  high-leverage tier. Paired: `PROBLEM_TREE` T2.12 + F.1 + §8 — same commit; gate
  green, 3,018 lib + 67 api + 23 arch + 54 smoke + 3 halting + 6 cli-seed + 2
  audit-regression tests, 0 failures.
- **2026-06-17** — **Cycle 5 (S→P): SOL-F1 `au_electoral` HTML markers +
  SOL-CLI-CONTRACT `audit` exit-code.** S→P pass on cycle 4 deliverables: §4b held
  two contained finish-queue items. **(1) SOL-F1 `au_electoral`:** extended
  `util::scan::MatchSet` with `find_range(&str) -> Option<(usize, usize)>` (leftmost
  match `[start, end)` — eliminates "what length was the marker?" arithmetic);
  `au_electoral/parse.rs` `extract_division` converted — `DIVISION_MARKER` +
  `ENROLLED_MARKERS` `LazyLock<MatchSet>` statics replace three `find_ascii_ci`
  calls; the two enrolled-marker patterns are now one aho-corasick pass (was two
  sequential linear scans); AEC-before-state-EC priority preserved (two matchers,
  in sequence). Five tests added (`extract_division_tests`). **(2)
  SOL-CLI-CONTRACT `audit`:** `cmd_audit` emits `Err` after printing when any finding
  is `Critical | High` (previously `Ok(())` regardless of score); test
  `empty_scan_triggers_high_severity_exit_path` guards the non-zero-exit path. **Gap
  refresh:** §4b SOL-F1 "5 consumers, remaining = au_property + memchr/bstr";
  SOL-CLI-CONTRACT residual = `resolve_scan_id` incomplete-scan only; §4d T2 row
  updated (audit exit-code now in the fixed column). §3.F enabler block remains the
  sole high-leverage unrealised tier. Paired: `PROBLEM_TREE` T2.12 + F.1 + §8 —
  same commit; gate green, 3,016 lib + 67 api + 23 arch + 54 smoke + 3 halting
  + 6 cli-seed + 2 audit-regression tests, 0 failures.
- **2026-06-17** — **Cycle 7 (CAP): SOL-STREAMING `[ ]`→`[x]` — streaming/cam/fan/adult
  platform identity prober.** Operator-directed capability request: "incorporate all forms
  of webcam or similar site identities as a comprehensive OSINT inclusion." Built and
  delivered `streaming_probe` in one pass — 30-site parallel HEAD/GET prober across
  `cam`/`fans`/`adult` categories; `StatusEq` HEAD for clean-404 platforms;
  `StatusAndNotBody` GET for JS-rendered 200-for-all platforms (OnlyFans, Chaturbate);
  summary `Username` entity with `cam-identity-exposed`/`subscription-platform-found`/
  `high-streaming-exposure` tags; `ModuleCategory::Social`, priority 108; 8 tests.
  **CAP→delivered on first pass.** **S→P gap-refresh:** C8 logged + immediately closed
  `[x]`; baseline updated to 119 modules / Social-11; `docs/MODULES.md` + README synced
  — the `modules_md_lists_every_registered_module` + `readme_module_overview_count_matches_registry`
  architecture guards pass clean. SOL-STREAMING added to leverage map; §4a C8 off the
  open queue; §4d capability row updated (C8 delivered ✅; C1–C7 open by design). §3.F
  enabler block remains the sole unrealised high-leverage tier. Paired:
  `PROBLEM_TREE` C8 + §8 — same commit; gate green, 3,031 lib + 67 arch + 54 smoke
  + 3 halting + 23 cli + 6 cli-seed + 2 audit-regression tests, 0 failures.
- **2026-06-17** — **Cycle 9 (S→P): SOL-F3 import-parser proptest.** Gap analysis:
  §4b named SOL-F3 as the next most actionable §3.F item — `cargo-fuzz` needs a
  nightly CI lane (blocked), but the import-parser proptest was a clean contained
  step. Added `mod prop` with 3 `proptest!` no-panic properties to
  `src/cli/import/tests.rs`: `parse_dossier_never_panics`,
  `parse_oathnet_txt_never_panics`, `parse_oathnet_html_never_panics` — each runs
  over arbitrary Unicode strings (≤512 chars) and additionally asserts every
  emitted entity value is non-empty. The three sync import parsers are the
  untrusted-input parsers most exposed to operator-supplied or web-uploaded data;
  the CLI path has no `catch_unwind`, so a panic kills the process. The existing
  25-case adversarial table (`upload_dispatcher_never_panics_on_adversarial_input`)
  can't exhaust arbitrary Unicode — proptest does. **S→P gap-refresh:** §4b
  SOL-F3 updated (import-parser proptest done; only `cargo-fuzz` left); F.3
  status unchanged (`[~]` — cargo-fuzz still outstanding). Paired: `PROBLEM_TREE`
  F.3 note + §8 — same commit; gate green, 3,032 lib + 24 arch + 54 smoke + 3
  halting tests, 0 failures.
- **2026-06-17** — **Cycle 8 (P→S): SOL-RULE-METAGUARD `[ ]`→`[x]` — T1.3 fully closed.**
  Gap-analysis pick: §4b T1.3 meta-guard was the last open T1 sub-item. **(1) Direct
  firing tests for AU-021 and AU-030** added to `src/core/correlator/tests.rs`:
  `au021_fires_for_api_key_entity` (one `ApiKey` entity → `len(), 1`, `Critical`) and
  `au030_fires_for_three_source_geo_cluster` (two Coordinates entities with 3 distinct
  corroborating sources across them → `len(), 1`, `Medium`). These were the only two
  of the 56 dispatched rules with no direct function-level firing assertion.
  **(2) `every_dispatched_correlation_rule_has_a_firing_test`** added to
  `tests/architecture.rs`: enumerates every `rule_au_*` entry in `RULES` +
  `RELATION_RULES` from `correlator/mod.rs`; for each, accepts (a) direct — function
  name in the test corpus within ±15 lines of a `len(), N` (N > 0) assertion, or
  (b) indirect — quoted `"AU-NNN"` on a line with `assert`/`.unwrap()`/`.expect()`/
  `contains(`. All 56 dispatched rules pass. Supporting helpers added:
  `correlator_tests_source()` (concatenates `tests.rs` + `rules/tests.rs`) and
  `has_nonzero_len_assert()`. **S→P gap-refresh:** SOL-RULE-METAGUARD added to
  leverage map `[x]`; §4b T1.3 item removed; §4d T1 row updated ("T1.3 solved").
  Paired: `PROBLEM_TREE` T1.3 `[~]`→`[x]` — same commit; gate green, 3,033 lib +
  24 arch + 54 smoke + 3 halting + 23 cli + 6 cli-seed + 2 audit-regression tests,
  0 failures.
- **2026-06-17** — **SOL-STREAMING expansion: +12 international sites (30→42).**
  Operator request: "find these in difficult to find overseas countries where people
  hide their true behaviour." Extended `streaming_probe` site table with the non-English
  platforms most used to maintain a covert streaming identity: Runetki, Cherry.tv (cam);
  Mym, Boosty, 4Based, JustForFans, OhMyFans, Unlockd, Cam.tv (fans);
  MyDirtyHobby, SuicideGirls, Iwara (adult). Each entry documented with its geographic
  significance and the subject-behaviour pattern it targets. Timeout comment updated
  (13.5s needed vs 30s; no change to the 30s constant). SOL-STREAMING description and
  C8 problem node updated to reflect 42-site scope. Gate green: fmt/clippy/doc clean,
  3,027 lib + 67 arch tests, 0 failures.
- **2026-06-17** — **Cycle 16 (P→S): SOL-SCHEMA-VERSION `[x]` + SOL-INSTALL-INTEGRITY
  `[x]` — T2.10 and §7 S5 both closed.** Two remaining §4a items from cycle 15's
  gap analysis. **(1) SOL-SCHEMA-VERSION:** `const SCHEMA_VERSION: i32 = 1` added to
  `src/storage/mod.rs`; `Store::open` reads `PRAGMA user_version` after the DDL batch
  — stamps when `ver < 1` (fresh / pre-versioned DB); `tracing::warn!` when `ver > 1`
  (future binary wrote this DB). Provides the forward-compat signal + migration ladder
  for any future non-additive change at zero on-disk cost. **(2) SOL-INSTALL-INTEGRITY:**
  `_validate_prebuilt` in `install.sh` now requires a `<binary>.sha256` sidecar for
  auto-discovered binaries (missing `sha256sum` / absent / empty / mismatched →
  `log_warn` + skip); optional for `HSE_PREBUILT` (`$2=0`). `maybe_use_prebuilt`
  wires the flag (`require_sha=1` auto-discovered, `0` when `HSE_PREBUILT` set).
  **Gap refresh:** §4a loses T2.10 and §7 S5 (both closed); only T2.7 (scraper health
  — large effort), §7 S4 (LOW residual), and C1–C7 (gated on §3.F) remain open. All
  remaining items accepted-deferred or gated. §4d T2 row gains T2.10 `[x]`; §7 row
  gains S5 `[x]`. Gate green: fmt/clippy/doc clean, 3,229 tests, 0 failures. Paired:
  `PROBLEM_TREE` T2.10 `[ ]`→`[x]` + §7 S5 `[ ]`→`[x]` + §8 cycle 16 log — same commit.
- **2026-06-17** — **Cycle 15 (S→P): gap analysis after cycle 14 — T1 tier confirmed
  fully closed; T2.10 + §7 S5 identified as next achievable items.** S→P pass on
  cycle 14's two deliveries. **(1) `strip_html` dedup:** no new problems — canonical
  `crate::util::html::strip_html` now covers all sites; no drift vector remains.
  **(2) SOL-FINALISE-BLOCKING:** `spawn_blocking` closure captures the `bool` snapshot
  correctly; CancellationToken lifetime resolved; reactor fully unblocked at
  scan boundaries. **§4 refresh:** scanned §4a for achievable items: T2.10 (schema
  version — no dep, small change) and §7 S5 (install sha256 — shell-only change) are
  the two remaining P→S-actionable items without large external blockers. T2.7 needs
  golden fixtures + health surface (large effort); C1–C7 gated on §3.F; §3.F itself
  needs nightly CI / large effort for remaining items (bstr + fst + cargo-fuzz).
  **Decision:** cycle 16 will implement T2.10 + §7 S5. No code change this cycle.
  Paired: `PROBLEM_TREE` §8 cycle 15 note — same commit.
- **2026-06-17** — **Cycle 14 (P→S): SOL-FINALISE-BLOCKING `[ ]`→`[x]` + local
  `strip_html` dedup — T1.5 fully closed.** Two gap items from cycle 13's S→P pass
  resolved together. **(1) `strip_html` dedup (LOW, contained):** `au_property/parse.rs`
  local `strip_html` replaced with `pub(super) use crate::util::html::strip_html`
  (re-export, import path unchanged for tests); `au_people/mod.rs` local `strip_html_tags`
  function deleted, canonical `use crate::util::html::strip_html` added, two call sites
  updated, `strip_html_tags_removes_markup` test deleted. Zero behaviour change; the
  copy-drift risk (future `decode_entities`/tag-stripping changes not propagating) is
  closed. **(2) SOL-FINALISE-BLOCKING (LOW-MED):** `finalise_scan` changed from
  `fn` to `async fn`; body dispatched to `tokio::task::spawn_blocking` capturing
  `Arc::clone(&store)`, `emitter.clone()`, and `cancelled` (bool snapshot — the
  CancellationToken is not `'static`); `persist_relations` and `run_correlator`
  inlined into the closure (both had single call-sites; removed as methods). T1.5
  `[ ]`→`[x]`. **Gap refresh:** §4a loses strip_html and T1.5 (both closed); §4b
  SOL-F1 remaining trimmed; §4d T1 row now "T1.1–T1.5 all closed ✔"; §3 leverage
  map gains SOL-FINALISE-BLOCKING row. Gate green: fmt/clippy/doc clean, 3,229 tests
  (prev 3,230 — one removed test), 0 failures. Paired: `PROBLEM_TREE` T1.5
  `[ ]`→`[x]` + §8 — same commit.
- **2026-06-17** — **Cycle 13 (S→P): memchr delivery exposes `bstr` deferral rationale
  + two local `strip_html` duplicates.** S→P pass on cycle 12's `decode_entities`
  change: grepped all callers of `strip_html` / `decode_entities` across the codebase.
  **Finding 1 (confirming):** `bstr` has no natural immediate consumer — every path that
  reaches `strip_html`/`decode_entities` receives `&str` produced by
  `read_body_capped` → `String::from_utf8_lossy`, which already handles invalid UTF-8
  at the boundary. `bstr` promotes only when a module is built to accept raw `&[u8]`
  response bytes directly (e.g. a future aho-corasick HTML extractor). The "promote with
  first use" rule is justified — `cargo machete` would correctly reject an unused dep.
  **Finding 2 (new gap):** `au_property/parse.rs:27` and `au_people/mod.rs:61` define
  their own `strip_html`/`strip_html_tags` functions instead of routing to
  `util::html::strip_html`. Both work correctly now, but any future change to the
  canonical entity decoder won't propagate. LOW (no current bug). Added to §4a as a
  named coverage gap (route-to-canonical = one-line change per module). **Gap refresh:**
  §4a gains local-strip_html-duplicate gap; §4b SOL-F1 "remaining" note updated with
  `bstr` rationale + the two module duplicates; no §4a removals. The §3.F enabler
  block (SOL-F1 `bstr` + SOL-F2 fst + SOL-F3 cargo-fuzz) remains the sole unrealised
  high-leverage tier. Next P→S candidate: **T1.5 / SOL-FINALISE-BLOCKING** (build the
  solution node + wrap `finalise_scan` in `spawn_blocking` — the last open T1 item with
  a known solution shape) OR the two local strip_html duplicates (LOW but trivial).
  Paired: `PROBLEM_TREE` §8 — same commit; no code change this cycle.
- **2026-06-17** — **Cycle 12 (P→S): SOL-F1 seventh consumer — `memchr` direct dep +
  `decode_entities` SIMD byte-scan acceleration.** P→S gap pass: §4b named `memchr`
  promotion as the remaining SOL-F1 item (`bstr` held back until a direct consumer
  exists). Promoted `memchr = "2"` to a direct dep in `Cargo.toml` (already in the
  tree transitively via `aho-corasick`/`regex` — no new package download; `cargo
  fetch` updates lock file metadata only). In `src/util/html/mod.rs`: added `use
  memchr::memchr;`; replaced `s.contains('&')` → `memchr(b'&', s.as_bytes()).is_none()`
  (early-exit check); `rest.find('&')` → `memchr(b'&', rest.as_bytes())` (hot loop
  across every `&` in a page body); `inner.find(';')` → `memchr(b';', inner.as_bytes())`
  (inner entity-close scan). `decode_entities` is the hot path for all scraped HTML —
  called from `strip_html` on every response — so the SIMD replacement has broad
  reach across all 119 modules that scrape. `&` and `;` are single-byte ASCII
  (0x26/0x3B) so their byte offsets are always valid char boundaries in UTF-8; the
  substitution is correct and no-panic (confirmed by the existing proptest suite on
  arbitrary Unicode strings). **S→P gap-refresh:** §2 SOL-F1 node updated (seventh
  consumer + gap trimmed to `bstr` only); §4b SOL-F1 "seven consumers, remaining =
  bstr"; §4d §3.F row notes `memchr` now direct. §3.F enabler block (SOL-F1 `bstr` +
  SOL-F2 fst + SOL-F3 cargo-fuzz) remains the sole unrealised high-leverage tier.
  Paired: `PROBLEM_TREE` F.1 node + baseline deps + §8 — same commit; gate green,
  3,032 lib + 24 arch + 67 api + 54 smoke + 3 halting + 6 cli-seed + 2
  audit-regression tests, 0 failures.
- **2026-06-17** — **Cycle 11 (S→P): SOL-BLOCKING delivery exposes T1.5 —
  `finalise_scan` reactor-blocking residual.** S→P pass on cycle 10's actor delivery:
  with the `insert_event` hot path (N per-entity `block_in_place` calls) now fully
  off the reactor, `finalise_scan` becomes the last identifiable sync-in-async site.
  It makes four blocking rusqlite calls: `upsert_entities_batch` (one WAL batch),
  `upsert_scan` (one row), `persist_relations` (one insert per edge), and
  `Correlator::run` (full SQL pass, O(entities)). All O(1) bulk transactions — the
  blast radius is bounded to the scan-end window and is invisible in CLI mode. In
  `hse serve`/`hse live` (concurrent scans), one worker stalls for the finalisation
  duration. **New node T1.5 (LOW-MED)** added to PROBLEM_TREE §3.1 (after T1.4) and
  §4a here. Solution shape is clear (wrap `finalise_scan` in `spawn_blocking`; the
  emitter is already non-blocking after cycle 10) but no solution node built yet.
  **Gap refresh:** §4a now lists T1.5; §4d T1 row updated (T1.1–T1.4 `[x]`, T1.5
  `[ ]` LOW-MED). §3.F enabler block (SOL-F1 memchr/bstr + SOL-F2 fst + SOL-F3
  cargo-fuzz) remains the sole unrealised high-leverage tier; SOL-BUDGET
  reset_scan-zeroing and SOL-F1/F2/F3 the remaining finish queue. No code change
  this cycle. Paired: `PROBLEM_TREE` T1.5 node + §8 — same commit; gate green
  (no code change).
- **2026-06-17** — **Cycle 10 (P→S): SOL-BLOCKING DB-writer actor — T1.2 fully closed
  (`[~]`→`[x]`).** `block_in_place` per entity in `EventEmitter::emit` replaced by
  `core::engine::writer::DbWriter` — a new `tokio::spawn`'d actor owning the
  `insert_event` call path behind an unbounded `mpsc`. Two command variants:
  `WriteCmd::Event(Box<Event>)` (boxed to satisfy `clippy::large_enum_variant` —
  `Event` is 224 B vs `Flush` 8 B) and `WriteCmd::Flush(oneshot::Sender<()>)`. The
  actor drains the channel in `spawn_blocking` batches (greedily pulls ≤64 events per
  call — one OS-thread transition per burst vs one per entity). `EventEmitter::emit`
  becomes a non-blocking `submit`; `run_with_ledger_inner` calls
  `writer.flush().await` after `finalise_scan` returns — FIFO channel guarantee ensures
  all events emitted before the flush (including `ScanComplete`) are durably written
  before the scan is returned. `finalise_scan` is `fn` (sync), so the barrier goes in
  its `async fn` caller. `DbWriter` is `Clone` (unbounded-sender clones point to the
  same actor task) so both `ScanEngine` and `EventEmitter` share the actor without an
  extra `Arc`. `recall_resolves_a_fullname_seed_despite_reformatting` upgraded from
  `#[test] fn` → `#[tokio::test] async fn` (body unchanged — sync — but `ScanEngine::
  new` now calls `tokio::spawn` internally, requiring a live Tokio runtime). **S→P
  gap-refresh:** §2 SOL-RULE-METAGUARD node added to S.CORE (was in leverage map only
  since cycle 8 — doc gap); §3 SOL-BLOCKING row `[~]`→`[x]`, "T1.2 (all write paths)";
  §4b SOL-BLOCKING removed from finish queue; §4d T1 row updated to "T1.1/T1.2/T1.3/
  T1.4 all solved". Paired: `PROBLEM_TREE` T1.2 `[~]`→`[x]` + cycle 10 note + §8 —
  same commit; gate green, 3,032 lib + 24 arch + 67 api + 54 smoke + 3 halting + 23
  cli + 6 cli-seed + 2 audit-regression tests, 0 failures.
- **2026-06-18** — **Cycle 17 (P→S + S→P): AU moat batch + NETINT depth partial —
  SOL-AU-MOAT + SOL-NETINT `[ ]`→`[~]`, new SOL-CACHE-INTERSCAN node logged.**
  **P→S direction:** gap §4a named C3 (Australian moat) and C4 (NETINT depth) as
  the highest-value open capability nodes. Delivered: `hlr_cnam` (HLR phone status
  + CNAM subscriber name; BYO `HUNTSMAN_HLR_KEY` + `HUNTSMAN_OPENCNAM_KEY`; priority
  138; Phone; Person + Phone entities; Edition 2024 let-chain CNAM stage — two
  independent HTTP legs without nested `if-let`); `ahpra` (AHPRA health-practitioner
  register HTML scrape; free; priority 86; People; `parse_ahpra_html` pure extractor
  + 8 unit tests); `acma_rrl` (ACMA radiocommunications register; free; priority 48;
  Corporate; ATT&CK override `["T1591.001","T1591.002"]`; `filter(char::is_ascii_digit)`
  idiomatic form); `trove_au` (NLA Trove newspaper archive; BYO `HUNTSMAN_TROVE_KEY`;
  priority 57; Corporate; let-chain `title && date` gate); `netlas` (Netlas.io host
  intel — ports, JARM, SSL cert emails, CVEs, ISP, geo; BYO `HUNTSMAN_NETLAS_KEY`;
  priority 79; Infrastructure; `netlas_query` helper; collapsible-if let-chains for
  geo + HTTP-email merges). Also: `smtp_vrfy` hardened (`tokio::join!` parallel
  SPF+DMARC, correct hickory `lookup.answers().iter()` TXT pattern, CatchAll
  0.50→0.30); `censys` priority 35→78; `reddit_user` → Organisation entities for
  subreddits (conf 0.40); `hacker_news` → Domain entities from Algolia submissions;
  `github_user` → `fetch_orgs` + `fetch_gists`. Module count 119→124 (92 free ·
  27 key-gated · 5 paid). All clippy/fmt/doc clean; 3,040+ lib tests, 0 failures.
  **S→P direction:** (1) three new HTML scrapers elevate T2.7 (scraper-health signal)
  — the per-source health surface is now wider and the gap is more acute; (2) the
  new key-gated/paid modules make C9 (inter-scan API caching / cost governance)
  structurally necessary — new problem node C9 logged in PROBLEM_TREE, new solution
  node SOL-CACHE-INTERSCAN sketched here (design: `lookup_entity_fresh` + `raw_archive`
  TTL gate + per-module-class TTLs, SOL-ISOLATE isolation preserved). **Gap refresh:**
  C3/C4 now `[~]`; §4a gains C9 + elevates T2.7; §4d capability row updated; leverage
  map split (SOL-CORR…SOL-FORENSIC row replaced by per-solution rows). Paired:
  `PROBLEM_TREE` C3/C4 `[ ]`→`[~]`, new C9, §8 cycle 17 note — same commit.
- **2026-06-18** — **Cycle 19 (P→S): SOL-GEOINT `[ ]`→`[~]` — `opencellid`
  first-class module delivered.** P→S direction: C5 (SOL-GEOINT) named as the
  next open capability node. Delivered: `src/modules/opencellid/{mod,tests}.rs`
  — key-gated (`HUNTSMAN_OPENCELLID_KEY`); accepts `Coordinates`; queries
  `opencellid.org/cell/getInArea` with ±0.005° BBOX (~1 km radius); emits
  `DeviceId` (tower id, radio type, mcc/mnc/lac/cid, range_m, samples,
  avg_signal_dbm) + `Coordinates` (tower geofix, confidence from accuracy radius)
  for every tower in the area; `cache_ttl_secs=86400`; ATT&CK override
  T1591.001+T1596 (geo + open technical database). Previously OpenCelliD was an
  internal non-queryable helper inside `cell_intel`; now a standalone BFS node.
  9 new unit tests. README/MODULES.md counts updated: 124→125 modules, Geo
  19→20, 27→28 key-gated. Gate green: fmt/clippy/doc clean, 3,052 lib tests, 0
  failures. **Gap refresh:** SOL-GEOINT `[ ]`→`[~]`; leverage map updated;
  §4a C5 now `[~]`; §4d capability row updated. Paired: `PROBLEM_TREE` C5
  `[ ]`→`[~]`, baseline counts updated, §8 cycle 19 — same commit.
- **2026-06-18** — **Cycle 18 (P→S + S→P): SOL-CACHE-INTERSCAN `[ ]`→`[x]` — C9
  inter-scan entity cache delivered.** **P→S direction:** gap §4a named C9/
  SOL-CACHE-INTERSCAN as the highest-value build-ready open node (design sketched
  cycle 17, no blockers). Delivered the full stack in one pass: `raw_archive` SQLite
  table DDL; `StoragePort::{archive_module_result, lookup_module_result_fresh}`
  default-no-op trait methods (zero-cost for all existing non-caching modules);
  `Store` SQL implementation in `src/storage/archive.rs` (`INSERT OR REPLACE` on
  write, `WHERE archived_at + ttl_secs > unixepoch()` fresh-check on read; 4 tests:
  round-trip, miss on unknown key, overwrite replaces previous, TTL=0 immediate-
  expire); `Module::cache_ttl_secs() -> u64` trait method (default 0 = always live);
  `hlr_cnam` + `netlas` override to 86400 (24 h); `archive_key("module:kind:
  normalised")` helper using the same normalisation as `dispatch_key`; dispatch
  pre-gate wired in both sequential (before `run_module_guarded`) and Phase 2
  concurrent (before `acquire_owned`) paths — cache hit increments
  `ModuleStats::cached`, replays archived `Vec<Entity>`, skips the live API call;
  post-call cache-store when `ttl > 0 && result non-empty`; `Scan::modules_cached`
  counter persisted. Schema snapshot test updated for `raw_archive` + its
  `sqlite_autoindex`. Also: 4 pre-existing rustdoc bare-URL errors fixed in the
  cycle 17 modules (`acma_rrl`, `ahpra`, `netlas`, `trove_au`).
  **S→P pass:** (1) verified `reset_per_scan` is already called at
  `run_with_ledger_inner:289` on every scan start — the cited SOL-BUDGET residual
  (`reset_scan`-zeroing across concurrent scans) was a faulty premise; SOL-BUDGET
  `[~]`→`[-]` (accepted-as-is; session ceiling bounds concurrent increments; no
  further action). (2) Grepped actual table sizes in the codebase: OUI ~111 entries
  (a curated subset, not the full IEEE registry ~30k), AU postcode ~72 entries,
  phone area codes ~65 entries — the "large tables need fst" premise was wrong at
  every cited table; `fst` adoption `[-]`; SOL-F2 and F.2 gap notes corrected.
  **Gap refresh:** §4a C9 off the open queue; §4b SOL-BUDGET off the finish queue
  (`[-]`), SOL-F2 premise corrected; §4d capability row gains C9; §3.F row
  removes "fst large tables" from remaining. Gate green: fmt/clippy/doc clean,
  3,044 lib tests, 0 failures. Paired: `PROBLEM_TREE` C9 `[ ]`→`[x]`, F.2
  premise corrected, §8 cycle 18 — same commit.
- **2026-06-18** — **Cycle 20 (S→P + P→S): C4 stale notes corrected; C3 courts/AustLII
  `austlii` module delivered; SOL-HEALTH-SIGNAL solution node sketched; new S→P gap
  logged (opencellid × cell_intel cross-validation AU-060).**
  **S→P corrections (audit):** grepped `src/modules/mod.rs` — `securitytrails`,
  `bgpview`, and `ripestat` all present in the registry; were listed as C4 "remaining"
  in error. SOL-NETINT remaining note corrected to: passive-DNS history + CDN cert-hash
  origin-unmasking. §4d C4 row updated accordingly.
  **P→S build — `austlii`:** free AustLII court/legislation scraper; accepts
  `FullName`/`Organisation`; queries `https://www.austlii.edu.au/cgi-bin/sinosrch.cgi`;
  `extract_case_links` parser filters `/au/cases/`, `/au/legis/`, `/au/journals/` paths;
  normalises relative hrefs to full URL; emits `Url` (tagged `court-judgment`, conf
  0.70) × ≤10 + `Organisation` (legal-footprint signal, ≥2 hits, conf 0.55); Corporate
  category; priority 55; `ModuleCost::Free`; no key required; 9 unit tests. Closes C3
  courts/AustLII remaining item. 125→126 modules, 92→93 free, Corporate 8→9.
  SOL-AU-MOAT remaining updated; §4a C3 + §4d C3 updated.
  **New S→P gap — T2.7:** per-source health signal has no solution node →
  SOL-HEALTH-SIGNAL sketched in §2 S.QUALITY (`last_success_at` +
  `consecutive_failures` tracking; `hse doctor` surface + SPA panel; auto-flag
  drifted source when consecutive_failures ≥ N or parse_rate < threshold). §4a T2.7
  note updated (partial coverage). Leverage map row added.
  **New S→P gap — AU-060:** `opencellid` and `cell_intel` both emit `DeviceId` for
  the same tower type with no correlation rule cross-validating them. Logged as §4a
  AU-060-candidate gap; no solution node yet.
  Gate green: fmt/clippy/doc clean, 3,061 lib tests, 0 failures. Paired:
  `PROBLEM_TREE` SOL-AU-MOAT/SOL-NETINT corrections + `austlii` baseline + §8 cycle 20
  — same commit.
- **2026-06-18** — **Cycle 22 (S→P): SOL-UPDATE `[ ]`→`[x]` — `hse update` +
  CLI consolidation delivered.**
  **S→P build:** `src/cli/update.rs` — `find_install_dir()` tries `HUNTSMAN_INSTALL_DIR`
  env → `~/.local/share/hse` / `~/hse` / `~/.hse` → 5-level binary-parent walk;
  `commits_behind()` runs `git fetch --quiet` then `rev-list --count HEAD..@{u}`;
  `cmd_update(check=true)` prints commits available without installing;
  `cmd_update(check=false)` runs `install.sh` via `tokio::task::spawn_blocking` with
  inherited stdio; `HSE_REF` env passed for `--ref` overrides. `install.sh` gains a
  `HUNTSMAN_INSTALL_DIR=...` upsert into `~/.huntsman.env`. `KeysAction::Set` added
  (`visible_alias = "set-key"` + `"write"`). 6 commands hidden: `doctor`, `selftest`,
  `provision`, `set-key`, `engines`, `oathnet-batch`; `hse upgrade` alias for
  `update`; visible surface 19→13. **SOL-UPDATE `[ ]`→`[x]`**; leverage map updated.
  **New S→P gap:** `--check` reports commit count only — no changelog summary. Logged
  in §4 for a future cycle. Gate green: fmt/clippy/doc clean, 3,084 lib tests,
  0 failures. Paired: `PROBLEM_TREE` cycle 22 entry + §4/§5 — same commit.
- **2026-06-18** — **Cycle 21 (P→S): SOL-GEOINT progress — `cell_local` + `hse cells
  import` delivered; free offline DB leg added to C5.**
  **P→S build:** `src/util/cell_db.rs` — shared WAL-mode SQLite DB helper at
  `~/.huntsman/cell_towers.db`; `CellRow` / `ImportRecord` structs; `open_rw()` /
  `open_ro()` connection helpers; `init_schema()` (WAL + NORMAL sync, `cells` +
  `cell_imports` tables, composite PK, geo + mcc indexes); `insert_batch()` (50k-row
  batched `INSERT OR REPLACE` in `unchecked_transaction`); `query_bbox()` (BETWEEN
  lat/lon, ORDER BY lat/lon, configurable LIMIT); `total_count()`, `count_by_mcc()`,
  `record_import()`, `last_import()`; 8 unit tests (round-trip, upsert, count,
  MCC group, import history, bbox limit).
  `src/cli/cells/mod.rs` — `hse cells` subcommand: `status` (total count, top-10 MCC
  breakdown, last import age); `import --file PATH` (direct CSV/CSV.GZ import with
  `flate2` GZ decompression, 50k-row batched with progress output) + `import --country
  CODE` (reqwest download via OpenCelliD API, falls back to manual-download message on
  failure); `clear [--yes]` (truncate cells + cell_imports with confirmation prompt).
  `parse_csv_line` handles 14-col OpenCelliD CSV; `mcc_for_country` maps ISO-3166-1
  alpha-2 codes and raw integers; 10 unit tests.
  `src/modules/cell_local.rs` — `CellLocal`; free (`ModuleCost::Free`); Geo category;
  priority 66; `max_timeout_ms()` 5000; accepts `Coordinates`; queries local DB in
  `tokio::task::spawn_blocking`; DELTA=0.005° BBOX (~556 m); emits `DeviceId`
  (tagged `cell-tower`, `cell-local`, `radio:<type>`) + `Coordinates` (confidence
  from `accuracy_to_confidence`); silent no-op when DB absent; 7 unit tests.
  New direct dep: `flate2 = "1"` (GZ decompression; `adler2`, `crc32fast`,
  `miniz_oxide`, `simd-adler32` pulled transitively). rusqlite pinned at 0.39
  (0.40 uses unstable `cfg_select!` on stable Rust — pre-existing branch constraint).
  **New S→P gap:** `hse cells import` requires a manual trigger + BYO OpenCelliD key;
  no auto-scheduled re-sync. Logged in §4a.
  126→127 modules, 93→94 free, Geo 20→21. Gate green: fmt/clippy clean, all tests pass.
  **Gap refresh:** §4a gains `cell_local auto-sync` gap; C5 remaining updated;
  §4d C5 row updated. Paired: `PROBLEM_TREE` C5 cycle 21 note + §8 cycle 21 — same
  commit.
- **2026-06-18** — **Cycle 23 (S→P): SOL-SECRETS reinforced + new SOL-SUPPLY
  (supply-chain integrity) leaf — six fixes from adversarial self-review.**
  **Solutions delivered:** **SOL-SUPPLY** (new) — CI workflows must pass
  user-controlled inputs through `env:` vars (never interpolate `${{ }}` into a
  `run:` body) and validate any value written to `GITHUB_OUTPUT` against a strict
  charset; release binaries fetched over the network must require their `.sha256`
  sidecar (integrity, not authenticity — TLS authenticates the origin) rather
  than silently degrading to a run-test-only check. **SOL-SECRETS** reinforced —
  the env-file reader strips the same surrounding quotes `write_keys_at` emits
  (so the read path agrees with `dotenvy`/`load` and SUPERSEDED rotation fires),
  and the writer `fsync`s before the atomic rename so a power-cut can't truncate
  `~/.huntsman.env`. **Loopback baseline** extended — `POST /update/trigger` now
  carries the same loopback-only gate as key writes, via a named, **tested**
  `reject_non_loopback()` helper (2 regression tests over LAN / `0.0.0.0` reject
  and v4/v6 loopback allow). **`install.sh` robustness** — `CARGO_TARGET_DIR` is
  initialised before the prebuilt guard so the summary never trips `set -u`, and
  the `HUNTSMAN_INSTALL_DIR` record is written with `grep`+`printf`+`chmod 0600`
  instead of `sed` (no metacharacter injection from the install path).
  **Process note:** this cycle's value came as much from *rejecting* a confident
  false positive (`query_bbox` "binding swap") by reading the source as from the
  six real fixes — the decompose-and-stress-test step is now part of the review
  doctrine. **Gap analysis (§4):** SOL-SUPPLY opens with two known residuals — a
  same-TLS-channel checksum is not authenticity (out-of-band signature would
  close it), and the per-handler loopback guard wants generalising into one
  route-layer middleware; both logged, neither blocking. Gate green:
  fmt/clippy/doc clean, 3,088 lib tests (+2), 0 failures; `bash -n` + shellcheck
  clean. Paired: `PROBLEM_TREE` §8 cycle 23 — same commit.
- **2026-06-18** — **Cycle 24 (P→S): SOL-SENSOR-GATE `[ ]`→`[x]` — `signal_radar`
  sensor isolation corrected; live phone sensors no longer fire on non-geo seeds.**
  **P→S build:** identified `signal_radar` as the sole `LOCAL_PASSIVE_MODULES`
  outlier — all peer sensor modules (`device_sensors`, `wifi_intel`, `cell_intel`,
  `local_net`) gate on `Coordinates | MacAddress` **and** appear in the isolation
  array; `signal_radar` did neither. **Two-part fix (S.CORE correctness):**
  (1) `src/modules/signal_radar/mod.rs` — `accepts()` changed from `true` (all
  targets) to `matches!(t.kind, TargetKind::Coordinates | TargetKind::MacAddress)`,
  with the MCS-A rationale documented in-place; `TargetKind` added to imports;
  (2) `src/core/engine/mod.rs` — `"signal_radar"` appended to
  `LOCAL_PASSIVE_MODULES`, enabling the existing dispatch gate to suppress
  expansion-round re-firing. **Zero additional test code:** the architecture test
  `local_passive_sensor_modules_reject_remote_subject_seeds` (iterates
  `LOCAL_PASSIVE_MODULES`, asserts refusal of all non-geo seed kinds + acceptance
  of `Coordinates`) now automatically covers `signal_radar`. **Contamination chain
  fully broken:** for any non-geo seed (email, name, username, phone, domain,
  IP) `signal_radar.accepts()` is `false` on the seed round; on expansion rounds
  where a legitimate `Coordinates` entity appears, the `LOCAL_PASSIVE_MODULES`
  gate suppresses re-firing. `cell_local` and `opencellid` now see only
  coordinates from legitimate external OSINT, never from phone sensors.
  **S→P gap from this cycle:** none — the fix is complete; the pattern is now
  consistently applied across all six live-sensor modules. **§4d update:**
  S.CORE sensor-gate row added. Gate green: fmt/clippy/doc clean, 3,092 lib
  tests, 0 failures; `bash -n` + shellcheck clean. Paired: `PROBLEM_TREE` §8
  cycle 24 — same commit.
- **2026-06-18** — **Cycle 25 (P→S): SOL-QUERY-PIPE — two query-pipeline defects
  from live-scan debug bundle corrected; `hudsonrock` URL encoding fixed and
  `employer_pivot` role-email false attribution eliminated.**
  **P→S build:** debug bundle from `full_name = Zac Allen` (hse_version 1.4.0)
  exposed two code bugs that produced `module_error` events and one false-positive
  entity. **Fix A — `hudsonrock` `@` preservation
  (`src/modules/hudsonrock/mod.rs`):** the Email arm of `process()` now (1) exits
  early with an empty `ModuleResult` when `target.value` contains no `@` (blocks
  the 400 on any mislabelled entity reaching `process()` directly); (2) calls
  `urlencode(&target.value).replace("%40", "@")` so the literal `@` is preserved
  in the raw query string — matching HudsonRock Cavalier's pre-decode validation
  requirement. Two new unit tests: `at_sign_preserved_in_encoded_url` (asserts the
  replacement fires and the result contains `@` not `%40`) and
  `email_without_at_sign_yields_empty_result` (asserts the guard exits without an
  HTTP request). **Fix B — `employer_pivot` role-email guard
  (`src/modules/employer_pivot/mod.rs`):** added `is_role_email_local(local: &str)
  -> bool` (an exhaustive `matches!` over 21 RFC 2142 / conventional system
  local-parts: `abuse`, `admin`, `administrator`, `billing`, `dns`, `hostmaster`,
  `info`, `legal`, `marketing`, `noc`, `noreply`, `no-reply`, `postmaster`,
  `privacy`, `sales`, `security`, `support`, `sysadmin`, `tech`, `webmaster`). In
  `process()`, immediately after the freemail / social-platform guard, a collapsed
  `let`-chain (`target.kind == TargetKind::Email && let Some((local, _)) =
  target.value.rsplit_once('@') && is_role_email_local(local)`) returns an empty
  result without fetching any URL. Three new unit tests:
  `role_email_local_parts_are_blocked` (all 21 entries), `real_user_local_parts_not_blocked`
  (real names pass through), `role_email_check_is_case_sensitive` (only lowercase
  is matched; callers must normalise). The `let`-chain form is required by the
  local `collapsible_if` lint (Edition 2024 feature, caught by `-D warnings`).
  **S→P gap from this cycle:** `dns_intel` emits SOA RNAME at confidence 0.70
  with a `dns-admin` tag, but the `Target` struct has no tags field — the tag is
  silently dropped at entity→target conversion. The employer_pivot guard (Fix B)
  is the correct defensive point (consumer-side), but a deeper fix would lower the
  SOA RNAME confidence below the expansion threshold or add a `role_email` flag to
  the entity kind rather than relying on tag preservation. Logged; not blocking.
  **§4 gap analysis:** SOL-QUERY-PIPE row added to §4d. Gate green:
  fmt/clippy/doc clean, 3,097 lib tests (+5 new), 0 failures; `bash -n` +
  shellcheck clean. Paired: `PROBLEM_TREE` §8 cycle 25 — same commit.
- **2026-06-20** — **Cycle 26 (P→S): SOL-CORR `[ ]`→`[~]` — C1 link analysis.**
  Gap pick: SOL-CORR (→ C1, Maltego-without-graphs) was the highest-value open
  capability solution. Delivered the canonical `core::relation::identity_paths`
  primitive — deterministic shortest typed paths between identity entities
  (undirected BFS, stable parallel-edge collapse, each pair computed once from its
  smaller-UID endpoint; order-independence + well-formedness proptested; 8 unit
  tests). Refactored AU-060 transitive identity closure to **delegate** to it (one
  finder, no drift — its 8 firing tests pass unchanged), and added a dossier
  **CONNECTIONS** section rendering the shortest typed thread between identities
  with each chain's weakest-edge confidence. Two of SOL-CORR's four sub-items are
  now done (transitive closure, property-tested + the text Connections section);
  first-class timeline output + further AU-0xx rule-gap fill remain. **S→P
  refresh:** leverage-map SOL-CORR `[~]`; C1 `[~]`. Gate green: fmt/clippy/doc
  clean, 3,261 lib tests (+10), 0 failures. Paired: `PROBLEM_TREE` C1 + §8
  cycle 26 — same commit.
- **2026-06-20** — **Cycle 27 (refactor, Rule 4): relation-graph primitive
  consolidation.** Extends cycle 26's SOL-CORR: extracted the shared
  `undirected_adjacency` + `reachable_count` into `core::relation::graph` (renamed
  from `path`) and routed `core::network::synthesize` through them, deleting its
  private adjacency loop + `reachable_from` DFS. One canonical relation-graph
  builder now backs the subject-network view, the AU-060 transitive rule, and the
  dossier CONNECTIONS section — they cannot drift ("delegate, never copy").
  Behaviour-preserving (network 4 + AU-060 8 + path determinism proptest
  unchanged); +3 helper tests. Gate green: 3,264 lib tests. Paired:
  `PROBLEM_TREE` §8 cycle 27 — same commit.
- **2026-06-20** — **Cycle 28 (S→P, Rule 3 + C5): one structured AU-059 location
  fix.** SOL-GEOINT / single-source: the API recovered `best_location`'s fields by
  parsing AU-059's finding prose. Extracted `au059_synergy_fix(entities)` as the
  sole computation — the rule formats its description *from* it and the API reads
  its fields directly (no string-splitting; severity/rank still from the
  correlation). Surfaced the best-estimate as the headline of the dossier GEO
  INTELLIGENCE section. Behaviour-preserving (AU-059 rule tests + geo-synergy sims
  + all-eleven-classes pass); replaced the prose-coupled API tests with a
  corrupt-the-description robustness test. SOL-GEOINT stays `[~]` (point surfaced;
  confidence-radius render open). Gate green: 3,264 lib tests. Paired:
  `PROBLEM_TREE` §8 cycle 28 — same commit.
- **2026-06-20** — **Cycle 29 (P→S, C5): confidence radius on the best location.**
  Added `SynergyFix::radius_km` (robust median distance from the fix to the
  contributing coords) so the best-estimate carries its uncertainty: dossier shows
  `± R km`, the API export carries `radius_km`, the finding states `± R km`. C5's
  "best-estimate with provenance + confidence radius" delivered end-to-end;
  SOL-GEOINT stays `[~]` for its remaining legs. Gate green: 3,264 lib tests.
  Paired: `PROBLEM_TREE` §8 cycle 29 — same commit.
- **2026-06-20** — **Cycle 30 (SOL-CORR, C1): multi-pathway corroboration —
  recursive-linking increment 1.** New `core::relation::disjoint_pathways`
  primitive (greedy edge-disjoint shortest-path enumeration; deterministic,
  order-independence tested) + new rule **AU-062**: two identities joined by ≥2
  edge-disjoint pathways across ≥2 distinct OSINT source families are flagged as
  multiply-corroborated (graph redundancy alone rejected). Reuses the AU-059
  `source_family` orthogonality measure and the shared `core::relation::graph`
  layer (so it can't drift from AU-060 or the dossier). Surfaced in the dossier
  CONNECTIONS view. 62 rules. SOL-CORR advances (orthogonal-pathway corroboration
  done; gap-fill + backward synthesis are increments 2–3). Gate green: 3,271 lib
  tests (+7). Paired: `PROBLEM_TREE` §8 cycle 30 — same commit.
- **2026-06-20** — **Cycle 31 (SOL-CORR, C1): gap analysis — recursive-linking
  increment 2.** New rule **AU-063** (`rules/gap.rs`): the dual of AU-062 — for an
  identity pair joined by a single transitive route, it reads the source families
  the route rests on and names the strongest *orthogonal* families absent from it
  (the logical requirement that would corroborate the link another way). Reuses
  `disjoint_pathways` so "one route" means exactly what AU-062's "many routes"
  does. Passive lead (a finding), the groundwork for active re-dispatch.
  SOL-CORR advances (orthogonal corroboration + gap analysis done; backward
  synthesis is increment 3). Gate green: 3,275 lib tests (+4). Paired:
  `PROBLEM_TREE` §8 cycle 31 — same commit.
- **2026-06-20** — **Cycle 32 (SOL-CORR, C1): backward synthesis — recursive-linking
  increment 3.** New rule **AU-064** (`rules/template.rs`): abstracts each confirmed
  identity connection into its direction-canonical pathway template
  (`entity-kind →relation-kind→ …`) and fires when one template links ≥2 distinct
  pairs — a route proven repeatable, a reusable means to reach that class of
  connection. Pure core on `identity_paths`; the template is the unit cross-scan
  persistence will store. SOL-CORR's in-scan link-analysis legs (orthogonal
  corroboration, gap analysis, generalisation) are now done; the universal
  cross-scan persistence (`raw_archive`-backed template store + correlate-time
  consult) is the remaining storage+engine leg. Gate green: 3,279 lib tests (+4).
  Paired: `PROBLEM_TREE` §8 cycle 32 — same commit.
- **2026-06-20** — **Cycle 33 (SOL-CORR, C1): universal cross-scan learning loop —
  recursive-linking increment 4.** Closes SOL-CORR's universal leg. (1) Shared
  `connection_templates` generaliser (AU-064 delegates). (2) New `pathway_templates`
  table + `StoragePort::{record_pathway_template, pathway_template_count}` (Store
  impl in `storage/templates.rs`, schema snapshot updated) — cross-scan memory on
  the SOL-CACHE-INTERSCAN pattern. (3) Engine finalise: generalise → credit a
  route any prior scan proved as the engine-emitted **AU-065** cross-scan finding
  → record every route. Consult-before-record means no self-crediting; AU-065 is
  storage-dependent so it's engine-emitted (not a pure rule, 64-rule count
  unchanged). **SOL-CORR `[~]`→`[x]`** — C1's link-analysis program (orthogonal
  corroboration, gap analysis, backward synthesis, universal learning) is
  delivered end-to-end. Gate green: 3,280 lib tests. Paired: `PROBLEM_TREE` §8
  cycle 33 — same commit.
- **2026-06-20** — **Cycle 34 (SOL-CORR, C1→C2): confirmed connections feed back
  into the entities — the corroboration boost.** C1 made the *findings*; this
  closes the loop so a confirmed connection measurably strengthens the scan's
  OUTPUT. (1) Extracted the multi-pathway test AU-062 already ran into a shared
  `correlator::multipath_corroborated_links` finder (≥2 edge-disjoint pathways
  across ≥2 orthogonal source families); the rule now delegates to it — one
  finder, no drift. (2) New engine finalise pass `promote_multipath_corroborated`
  (in `engine/passes.rs`, mirroring `promote_geo_corroborated_family`): for each
  corroborated link it tags both identity ENDPOINTS `multipath-corroborated` and
  stamps a `multipath_corroboration` evidence record, lifting corroboration →
  `c_effective` → classification band. Conduit intermediates are left alone; the
  boost source classifies as `"other"` so it never feeds back to inflate AU-062;
  idempotent via the tag. Best-effort, conditional re-persist (only when a link
  fires). No new rule (64 unchanged) — this is an engine pass bridging the
  correlator's proof to the entity confidence model. Gate green: 3,283 lib tests
  (+1), 24 arch guards, fmt/clippy/doc clean. Paired: `PROBLEM_TREE` §8 cycle 34 —
  same commit.
- **2026-06-20** — **Cycle 35 (SOL-CORR, C1→C2): cross-scan knowledge fills the
  gap — AU-066.** The keystone joining gap analysis to universal learning: AU-063
  *finds* a fragile single-route link and names the missing family; the cross-scan
  `pathway_templates` store *holds* which route shapes are historically proven;
  nothing yet used the latter to resolve the former. (1) Extracted AU-063's
  detection into a shared `single_route_identity_links` finder (the rule delegates;
  its 3 tests prove behaviour-preserving). (2) New engine-emitted **AU-066**
  ("Cross-scan route fills single-pathway gap"): in the finalise template loop, a
  fragile pair whose route shape is confirmed in **≥2 prior scans** (stricter than
  AU-065's ≥1) is corroborated by the proven attribution method itself — the
  accumulated cross-scan pathway is the orthogonal route the gap was missing.
  (3) New `promote_cross_scan_corroborated` pass tags + evidence-stamps those
  endpoints (`cross-scan-corroborated`), merged with the C2 multipath boost into a
  single conditional re-persist. Conservative + sound: ≥2 gate, endpoints only,
  unscored "other" evidence (no orthogonality feedback), idempotent. Engine-emitted
  like AU-065, so the 64-rule count is unchanged and the rule-id guard is
  satisfied (literal lives only in `engine/mod.rs`). The flywheel: every scan run
  proves more routes, so more gaps auto-resolve in later scans. Gate green: 3,284
  lib tests (+1), 24 arch guards, fmt/clippy/doc clean. Paired: `PROBLEM_TREE` §8
  cycle 35 — same commit.
- **2026-06-20** — **Cycle 36 (SOL-CORR, C1 capstone): resolved identity clusters
  — AU-067.** Mined from the uploaded `hse_modules` prototype's `IdentityClosure`
  (union-find transitive clustering with weakest-link confidence), re-expressed
  natively over `Entity`/`Relation` (no parallel type system). AU-060 reports a
  transitive *pair*; nothing collapsed all such pairs into the *equivalence class*
  — "{A,B,C,…} is one identity". (1) New shared graph primitive
  `core::relation::resolve_identity_clusters` — union-find over the `identity_paths`
  link set into connected components, each carrying the weakest-link confidence of
  the links that bind it (one finder with AU-060/the dossier, no drift). (2) New
  pure relation rule **AU-067** (`rules/resolved.rs`) delegating to it: fires for a
  resolved identity of ≥3 members (a 2-member cluster is one pair = AU-060) above a
  weakest-link floor, severity rising with size. Pure correlator rule → dispatched
  in `RELATION_RULES`, firing test added; rule count 64→**65** (AU-001…064, 067;
  AU-065/066 remain engine-emitted). The forward+backward "join seed data
  intelligently" leg made concrete: orthogonal pairwise links resolved into one
  identity. Gate green: 3,290 lib tests (+6), 24 arch guards, fmt/clippy/doc clean.
  Paired: `PROBLEM_TREE` §8 cycle 36 — same commit.
- **2026-06-20** — **Cycle 37 (prototype merge): SIM anonymity classification —
  AU-068.** "Merge all pre-existing files": audited the uploaded `hse_modules`
  prototype module-by-module; `sim_classify` was the one remaining genuinely
  mergeable, design-compatible piece (deterministic, offline, consumes data the
  tool already has). Ported the algorithm — not the code — natively: new pure
  `util::sim_anonymity` classifier (carrier name → PrepaidMvno/VoipVirtual tier,
  curated AU+US table, conservative — unknown/major carriers unclassified);
  `hlr_cnam` applies it to the `network` carrier it resolves, tagging the phone
  (`sim-voip`/`sim-mvno-prepaid`) + `sim_anonymity` evidence; new entity rule
  **AU-068** surfaces a VoIP/MVNO phone as an attribution caveat (a burner is a
  weak identity anchor — the linker weighs phone-based links accordingly).
  `util::sim_anonymity` added to the `core_does_not_import_util_directly` allowlist
  (pure leaf util, same category as `surnames`/`abn`). Rule count 65→**66**
  (AU-068 pure entity rule). The other prototype modules remain non-mergeable
  (uncollectable data / new EntityKinds+API / no-LLM invariant) — documented, not
  stubbed. Gate green: 3,296 lib tests (+6), 24 arch guards, fmt/clippy/doc clean.
  Paired: `PROBLEM_TREE` §8 cycle 37 — same commit.
- **2026-06-20** — **Cycle 38 (refactor, DRY): one definition for the recursive-
  linking primitives.** "REFACTOR and merge pre-existing files" applied to the
  link-analysis family's own duplication. Two helpers, each previously copy-pasted,
  are now single definitions: `core::relation::identity_uids` (sorted+deduped
  identity-endpoint UIDs — was inline in `identity_paths`, `multipath_corroborated_links`,
  `single_route_identity_links`) and `rules::source_families` (an entity's evidence
  source-family set — was the duplicated `families_of` body in `multipath`/`gap`).
  Behaviour-preserving: the full AU-060/062/063/064/067 suite + graph tests pass
  unchanged, proving no drift. Net −~40 lines, and the "one finder, no drift"
  invariant now covers the endpoint-enumeration and family-set steps too. No rule
  or behaviour change (count stays 66). Gate green: 3,296 lib tests, 24 arch
  guards, fmt/clippy/doc clean. Paired: `PROBLEM_TREE` §8 cycle 38 — same commit.
- **2026-06-20** — **Cycle 39 (AU-067 end-to-end): RESOLVED IDENTITIES in the
  dossier.** The AU-067 capstone existed as a correlation but the resolved
  equivalence classes weren't surfaced in the human report. Added
  `print_resolved_identities` to the CLI scan dossier — a "distinct identifiers that
  are one person" section beside CONNECTIONS, rendering each ≥3-member cluster from
  the shared `resolve_identity_clusters` primitive (so the grouping can't disagree
  with the pairwise threads or the AU-067 finding). Presentation completion of a
  feature; deterministic, reuses the tested primitive, no behaviour change. Gate
  green: 3,296 lib tests, 24 arch guards, fmt/clippy/doc clean. Paired:
  `PROBLEM_TREE` §8 cycle 39 — same commit.
- **2026-06-20** — **Cycle 40 (C1, active gap-fill): the engine now PURSUES the
  pathway AU-063 names.** Closes the last open leg of the recursive-linking spec —
  "fill in the logical requirements that would have found the link from another
  pathway." AU-063 only *named* the missing orthogonal family; now the engine acts
  on it. (1) Shared selector `gap_fill_probes` (in `rules/gap.rs`, reusing
  `single_route_identity_links` + the AU-063 absent-family logic) → each fragile-
  link identity endpoint + the families missing from it. (2) New engine pass
  `run_gap_fill` after expansion: for each probe it runs ONLY the missing-family
  modules on the gap endpoint (classified via the now `pub(in crate::core)`
  `source_family`), seeking corroboration of an already-confirmed link rather than
  a stranger's footprint. Reuses the tested `dispatch_target`; bounded (≤8 probes,
  budget/cancel-gated, honours passive/free/exclude, skips already-expanded
  endpoints) and **toggle-gated** `feature.gap_fill` (default ON). New entities
  flow into finalise normally. The selection logic is pure + unit-tested; the
  dispatch reuses existing tested machinery. No rule change (count 66). Gate green:
  3,298 lib tests (+2), 24 arch guards, fmt/clippy/doc clean. **SOL-CORR's full
  arc — orthogonal corroboration, gap analysis, backward synthesis, universal
  learning, cross-scan gap-fill, AND now active in-scan gap-fill — is delivered.**
  Paired: `PROBLEM_TREE` §8 cycle 40 — same commit.
- **2026-06-20** — **Cycle 41 (graph traversal, connection quality): max-bottleneck
  "strongest path" + AU-069.** A directive-named "superior graph traversal" gap:
  `identity_paths` only finds the *shortest* route, never the *most trustworthy*
  one. New `core::relation::strongest_path` finds the **widest path** (maximise the
  minimum edge confidence) via a deterministic, hop-capped Bellman-Ford relaxation
  with predecessor reconstruction — the route reliable at every hop, which may be
  longer than the shortest. New relation rule **AU-069** ("High-integrity
  connection") fires when the strongest route between two identities (≥2 hops) has
  every link ≥ 0.70 (High at ≥ 0.85) — a third quality lens complementing AU-060
  (reachability, shortest route) and AU-062 (redundancy, independent routes): this
  one is INTEGRITY (a single route trustworthy end to end). Pure + fully
  unit-tested (incl. the strongest≠shortest case). Rule count 66→**67**. Gate
  green: 3,304 lib tests (+6), 24 arch guards, fmt/clippy/doc clean. Paired:
  `PROBLEM_TREE` §8 cycle 41 — same commit.
- **2026-06-20** — **Cycle 42 (efficiency + DRY refactor): build the traversal
  graph once.** The per-pair relation rules each rebuilt and re-sorted the whole
  adjacency on EVERY pair — AU-062/AU-063 via `disjoint_pathways`, AU-069 via
  `strongest_path` — an O(N²) graph-build cost on the correlator's hot path that
  grows with identity count. Factored the build+sort into one
  `core::relation::sorted_confined_adjacency`, and split the per-pair finders into
  public (build + delegate) and **`*_in`** variants (`disjoint_pathways_in`,
  `strongest_path_in`) that take a prebuilt adjacency. Each rule (and the dossier
  CONNECTIONS view) now builds the graph ONCE and reuses it across all pairs:
  O(N²) graph builds → O(N). The read-only widest-path search reuses the shared
  adjacency directly; the mutating disjoint search clones it per call (still far
  cheaper than rebuild+resort). Also removes the build+sort duplicated across the
  three finders (one definition). Behaviour-preserving: the AU-060/062/063/069
  suite + the `disjoint_pathways`/`strongest_path` graph tests + the
  order-independence proptests all pass unchanged. No rule change (count 67). Gate
  green: 3,304 lib tests, 24 arch guards, fmt/clippy/doc clean. Paired:
  `PROBLEM_TREE` §8 cycle 42 — same commit.
- **2026-06-20** — **Cycle 43 (empirical validation finds + fixes a real bug;
  connection-quality surfacing).** Added property tests for `strongest_path` (the
  AU-069 widest-path primitive): a max-bottleneck **dominance** invariant (the
  widest route is never weaker than the shortest) and an undirected **symmetry**
  invariant. The symmetry proptest immediately FAILED — exposing a genuine bug:
  the single-array relaxation let an intermediate's hop count grow when its
  bottleneck improved (preferring a wider-but-longer route), which could push the
  destination past the hop budget → **asymmetric reachability**. Replaced it with a
  correct two-phase algorithm: (1) a hop-bounded max-min Bellman-Ford for the
  bottleneck VALUE (relaxing from each round's snapshot, honouring ≤k edges and
  order-independent), then (2) a BFS over the ≥bottleneck subgraph to reconstruct
  the shortest route achieving it. Both proptests + the existing unit tests now
  pass; the failing seed is checked in (`proptest-regressions/`). Also surfaced the
  **best-achievable reliability** (widest-route bottleneck) in the dossier
  CONNECTIONS view when it beats the shortest path's weakest edge. This is the
  directive's "empirically validated improvement" loop in action — a property test
  found a defect a unit test missed, and the fix is locked in. No rule change
  (count 67). Gate green: 3,306 lib tests (+2 proptests), 24 arch guards,
  fmt/clippy/doc clean. Paired: `PROBLEM_TREE` §8 cycle 43 — same commit.
- **2026-06-20** — **Cycle 44 (correctness from real data): a confidence floor at
  the identity-cluster union.** Running the engine on the common name "Ali Kareem"
  (Australia) — exactly the "test on numerous seeds" the directive calls for —
  surfaced a real fusion bug: `core::relation::resolve_identity_clusters` ran
  union-find over *every* `identity_paths` link with no confidence floor, so one
  weak edge fused unrelated namesakes into a single phantom identity (live: 59
  distinct people merged at weakest-link 0.17 in AU-067 + the dossier). Solution: a
  `min_confidence` parameter that gates the union itself — a link below the floor is
  simply absent from the equivalence relation, so a weak bridge between two strong
  sub-identities can no longer collapse them, and (because the floor gates the
  binding links) every returned cluster's weakest-link confidence is itself ≥ the
  floor. AU-067 and the dossier RESOLVED IDENTITIES view both pass the Probable
  floor (0.50), keeping the cluster-level conclusion consistent with the pairwise
  links and AU-060's own threshold (one finder, no drift). The change is universal
  and self-reinforcing: every common-name scan now resists weak-link fusion, and the
  tighter clusters feed cleaner downstream corroboration. Validated on the exact
  failing scan (`b5ef6f41…`): floor 0.0 → a 59-member cluster @ 0.17; floor 0.50 →
  it vanishes (largest genuine cluster 2 @ 0.90), i.e. zero phantom identities. New
  graph unit test pins the behaviour (0.17 bridge fuses at 0.0, stays split at
  0.50). No rule change (count 67). Gate green: 3,307 lib tests (+1), 24 arch
  guards, fmt/clippy/doc clean. Paired: `PROBLEM_TREE` §8 cycle 44 — same commit.
- **2026-06-20** — **Cycle 45 (graph traversal, node criticality): articulation
  points + AU-070 connection broker.** The pathway lenses answered pair- and
  cluster-level questions but never *which node is critical*. New primitive
  `core::relation::connection_brokers` finds the graph's **articulation points** in
  identity terms — the nodes whose removal disconnects identities otherwise linked
  only through them — by an obviously-correct remove-and-relabel (compare the
  identity partition with and without each node) rather than fragile low-link
  bookkeeping; it reuses the shared `sorted_confined_adjacency`, so it can't drift
  from the routes the dossier renders. New rule **AU-070 "Connection broker"** fires
  for a node that solely binds ≥3 identities (a 2-identity bridge stays AU-063's
  fragile-pair job), severity rising with fan-out. This is the fourth connection
  lens — REACHABILITY (AU-060), REDUNDANCY (AU-062), INTEGRITY (AU-069), and now
  CRITICALITY (AU-070) — and the most actionable: the broker is the analyst's prime
  pivot and the highest-leverage gap-fill target, since corroborating it hardens
  every connection that runs through it. Pure + fully unit-tested (hub brokers three;
  redundant triangle brokers none; 2-identity bridge below the floor). Compounds —
  every scan surfaces its linchpin as a prime cross-scan pivot. Rule count 67→**68**.
  Gate green: 3,313 lib tests (+6), 24 arch guards, fmt/clippy/doc clean. Paired:
  `PROBLEM_TREE` §8 cycle 45 — same commit.
- **2026-06-20** — **Cycle 46 (broker confidence floor + dossier surfacing).**
  Real-data validation of cycle 45 against the "Ali Kareem" scan showed the
  structural `connection_brokers` re-surfacing the namesake blob (two person nodes
  each "brokering" 58 strangers over 0.17 links) — the same weak-link failure cycle
  44 fixed for clustering, one layer down. Added a `min_confidence` floor to
  `connection_brokers` (and its `component_labels` BFS): only edges ≥ floor *bind*
  identities, mirroring `resolve_identity_clusters`. AU-070 and the dossier pass the
  Probable floor (0.50), so the broker view, the resolved-identity view, and AU-060's
  threshold all agree (one floor, no drift). Validated on the exact data: 2 brokers
  of 58 at floor 0.0 → **0** at 0.50. Also added a first-class **CONNECTION BROKERS**
  dossier section reusing the same floored primitive, so the load-bearing nodes —
  the prime pivots to corroborate — are delivered as an analytic conclusion next to
  CONNECTIONS and RESOLVED IDENTITIES, not left in the raw correlation list. New unit
  test pins the floor (a hub on 0.17 links: a broker at 0.0, none at 0.50).
  Compounds: every common-name scan now reports only trustworthy brokers. No rule
  change (count 68). Gate green: 3,314 lib tests (+1), 24 arch guards, fmt/clippy/doc
  clean. Paired: `PROBLEM_TREE` §8 cycle 46 — same commit.
- **2026-06-20** — **Cycle 47 (freemail guard in `is_infrastructure_email`).** The
  self-audit empirically surfaced an accuracy/coverage defect: `googlemail.com` sat
  in both `FREEMAIL` and the `INFRA_MAIL` provider set, so every personal mailbox on
  Gmail's alternate domain was classified as infrastructure — and that predicate
  *gates emission* in `search_engines`/`whois`/`ripestat`, silently dropping real
  subject emails. Solution: a freemail short-circuit in
  `util::domains::is_infrastructure_email` — a consumer freemail address is personal
  PII, never provider infrastructure, so only its role/automation desks (the
  `is_role_localpart` branch) are gated; the contradictory `googlemail.com` infra
  entry is removed. One small guard eliminates the whole freemail/infra-overlap class
  (gmail, googlemail, yahoo, outlook, …) across all four call-sites at once. Measured
  on the live scan: audit grade 62→**92**/100, both false-positive findings gone.
  Compounds: every future scan retains consumer-freemail subject mail it used to
  suppress. Regression assertions added (googlemail/yahoo/outlook personal = not
  infra; `abuse@googlemail.com` = still infra). No rule change (count 68). Gate
  green: 3,314 lib tests, 24 arch guards, fmt/clippy/doc clean. Paired:
  `PROBLEM_TREE` §8 cycle 47 — same commit.
- **2026-06-20** — **Cycle 48 (comprehensive product defaults).** To give every
  module a chance at a target (operator directive: "execute every single file and
  module… every file should be given a chance"), the `hse scan` defaults become
  comprehensive: `DEFAULT_SCAN_DEPTH = MAX_DEPTH` (3) so the Email→Domain→IP chain
  reaches the infrastructure tier, and the CLI `--min-expand-confidence` default
  drops 0.50 → 0.20 so name-derived identifier permutations (emitted at 0.20–0.30)
  expand instead of starving the pipeline after the seed round. The split is
  deliberate: **recall** widens (expansion floor 0.20) while **precision** is
  unchanged (the library default stays 0.50 for API/tests; the AU-067/070 correlation
  floors stay 0.50) — *expand liberally, correlate strictly*. `--recursive`'s
  `.min(0.40)` clamp means it now tracks the 0.20 default rather than raising it.
  Operators wanting a faster, shallower sweep set `--depth`/`--min-expand-confidence`
  explicitly. Measured: a completed free-only name scan now exercises 59 distinct
  modules (37 yielding data) — ≈4× the prior ~15; key-gated/paid tiers stack on top
  with keys. Compounds: every
  future scan, on any seed, now drives the full reachable module set. No rule change
  (count 68). Gate green: 3,314 lib tests, 24 arch guards, fmt/clippy/doc clean.
  Paired: `PROBLEM_TREE` §8 cycle 48 — same commit.
- **2026-06-20** — **Cycle 49 (MITRE consolidated into the modules).** Removed the
  entire separate MITRE ATT&CK reporting layer — SPA panels, four API endpoints, the
  `navigator` export, the CLI per-scan coverage block, the `hse modules` aggregate
  summary, the full-dossier ATT&CK section, and the `Assessment`/`CoverageDiff`/
  `navigator_layer`/`coverage`/`capability_assessment`/`reconnaissance_coverage`
  machinery (777 deletions, 14 files) — because it was a side-report that never
  shaped collection. The MITRE knowledge is retained where it belongs: as inline
  per-module metadata. Each `Module` still declares its Reconnaissance technique(s)
  via `attack_techniques()` over the `RECONNAISSANCE` catalogue +
  `techniques_for_category`, the technique↔module reverse index is kept, and the
  architecture guard still enforces the mapping — so "which collection technique
  does this module implement" is answerable from the module itself, with no separate
  tab to maintain or diverge. Behaviour-preserving for scans (pure surface removal);
  the gate proves nothing else moved. No rule change (count 68). Gate green: 3,305
  lib tests (−9 removed-surface tests), 24 arch guards, fmt/clippy/doc clean. Paired:
  `PROBLEM_TREE` §8 cycle 49 — same commit.
- **2026-06-20** — **Cycle 50 (`DEFAULT_MAX_ENTITIES` — comprehensive yet bounded).**
  Completes cycle 48: a new product-default entity ceiling (`DEFAULT_MAX_ENTITIES =
  2500`) applied at the CLI boundary when `--max-entities` is omitted, so the deep
  (MAX_DEPTH) low-floor (0.20) default sweep stays thorough but can never fan the
  frontier out far enough to OOM a 4 GB Termux device. Mirrors the cycle-48 pattern:
  the library/API default stays `None` (uncapped, deterministic); `--max-entities`
  and profile overlays override. The expansion loop already honours the cap
  (`budget_check` → `StopReason::MaxEntities`), so this is purely a safer default —
  maximising discovery while keeping the on-device resource guarantee the Termux
  target demands. No rule change (count 68). Gate green: 3,305 lib tests, 24 arch
  guards, fmt/clippy/doc clean. Paired: `PROBLEM_TREE` §8 cycle 50 — same commit.
- **2026-06-20** — **Cycle 51 (module consolidation: −2 redundant modules).**
  Audited all 127 modules for consolidation; kept genuinely-distinct providers
  separate (provider diversity is corroboration, not debt) and merged the two true
  redundancies. (1) Deleted `ipapi` — a misnamed duplicate of `ip_whois_geo` (both
  `GET https://ipwho.is/{ip}`); `ip_whois_geo` is the superset, so zero loss, and it
  removes a false "two independent sources" signal the duplicate created (AU-026 /
  `source_family` repointed to `ip_whois_geo`). (2) Folded `qld_unclaimed` into
  `au_unclaimed` as a full `process_qld` pass (not a lossy table row) — QLD's
  Person/ABN/suburb extraction preserved verbatim, evidence source string kept as
  `"qld_unclaimed"` for downstream-rule compatibility, 5 tests ported, priority
  raised into the government-register band. Registry 127 → **125**; docs/counts
  synced and the README-count guard passes. Demonstrates the directive's
  "minimise technical debt without compromising capability": two whole modules of
  duplication removed, every entity/source/test still produced. No rule change
  (count 68). Gate green: fmt/clippy/doc clean, lib + integration 0 failures, 24
  arch guards. Paired: `PROBLEM_TREE` §8 cycle 51 — same commit.
- **2026-06-20** — **Cycle 52 (ATT&CK technique stamped on every finding).** The
  universal form of "MITRE in the scans": at the single dispatch admission point
  (`finalise_module_result`), every admitted entity is tagged `attack:<ID>` with the
  producing module's Reconnaissance technique(s). Sourced from the dispatched object
  via the `Module::attack_techniques()` trait method (threaded through
  `DispatchOutcome` for the concurrent join), so **no `core → modules` import** is
  introduced — the layering guard stays green. Tags persist (JSON/DB) and the
  dossier + full export resolve them to technique names per entity; `Entity::merge`
  unions them so a multi-source entity carries every technique that found it.
  Together with cycle 48 (every reachable module runs) and cycle 49 (the separate tab
  removed, mapping kept), MITRE is now fully *in* the scan data on every seed, with
  zero side report. A new engine test drives the real admission path on both the
  sequential and concurrent dispatchers and asserts the stamp. No rule change
  (count 68). Gate green: fmt/clippy/doc clean, lib (3,279) + integration 0 failures,
  24 arch guards (incl. `core_does_not_import_modules`). Paired: `PROBLEM_TREE` §8
  cycle 52 — same commit.
- **2026-06-20** — **Cycle 53 (module consolidation: phone-geo pair → `phone_geo`).**
  Third consolidation merge: `phone_area_geo` + `phone_carrier_geo` fused into one
  passive `phone_geo` that runs both the area-code and carrier-prefix lookup passes
  in a single call. Behaviour-preserving (tables/confidences/tags verbatim; both
  passes independent), per-strategy evidence sources retained so the geo-anchoring
  correlator classification is unchanged, all 23 original tests ported + 3 new
  integration tests. Registry 125 → **124**; docs/counts synced and guarded. Same
  "debt down, capability intact" pattern as cycles 51 (ipapi, qld). No rule change
  (count 68). Gate green: fmt/clippy/doc clean, lib (3,280) + integration 0 failures,
  24 arch guards. Paired: `PROBLEM_TREE` §8 cycle 53 — same commit.
- **2026-06-20** — **Cycle 54 (API/SPA scans inherit the comprehensive defaults).**
  Unified the scan-default story across all surfaces. New `DEFAULT_MIN_EXPAND_CONFIDENCE
  = 0.20` constant is the single source of truth (CLI flag default, serde field
  default, and `default_scan_options` all reference it). The serde defaults are now
  comprehensive (depth `MAX_DEPTH`, floor 0.20, `default_request_max_entities` =
  Some(2500)) while `ScanOptions::default()` is **decoupled** and stays conservative
  (depth 0, floor 0.50, None) for library/test determinism — locked by a regression
  test. The SPA wizard's form defaults and `all` use-case were set to depth 3 / floor
  0.20 / cap 2500 (the `buildWizardOptions` override path is what mattered). Result:
  CLI, HTTP API, Chrome SPA, and live scans all run the same comprehensive sweep, so
  a seed scanned from the web UI is as thorough as one from `hse scan` — recall
  maximised everywhere, precision still governed by the strict correlation floors. No
  rule/module change. Gate green: fmt/clippy/doc clean, lib (3,282) + integration 0
  failures, 24 arch guards. Paired: `PROBLEM_TREE` §8 cycle 54 — same commit.
- **2026-06-20** — **Cycle 55 (`util::geo::ip_asn_entity` — the one clean IP-geo
  dedup).** Final consolidation pass. Rather than force a leaky per-provider
  entity-builder, extracted only the byte-identical `Asn` entity construction shared
  by all five IP-geo modules into `util::geo::ip_asn_entity(asn, src, ip, scan_id)`
  (Asn at fixed 0.80 + "ASN for {ip}" evidence). The genuinely-variant parts
  (Coordinates/Address/Org confidences, formatting, tag policy) stay in each module —
  abstracting them would have needed ~12 params and hurt maintainability. Behaviour
  is byte-for-byte preserved (all five modules' tests pass unchanged; new helper test
  + doctest added). Conservative-by-design: a small, honest dedup that improves
  consistency without introducing a leaky seam. Module count unchanged (124). Gate
  green: fmt/clippy/doc clean, lib 3,283 + integration + 44 doctests, 0 failures.
  Paired: `PROBLEM_TREE` §8 cycle 55 — same commit.
- **2026-06-20** — **Cycle 56 (AU-071 — robust identity cluster, the redundancy
  synthesis).** Fourth connection lens, completing the set: REACHABILITY (AU-060),
  REDUNDANCY-pairwise (AU-062), INTEGRITY (AU-069), CRITICALITY (AU-070), and now
  cluster-level REDUNDANCY (AU-071). A resolved cluster is "robust" iff no
  connection broker splits ≥2 of its members — removing any single connector leaves
  the identities mutually reachable. Composed entirely from existing primitives
  (`resolve_identity_clusters` + `connection_brokers` at the shared 0.50 floor): no
  new graph code, no drift, High severity (a redundantly-bound cluster is the
  strongest single-identity finding). Rejected a naive k-core approach because the
  `identity_paths` projection is a transitive closure (every component is already a
  near-clique, so k-core can't tell a dense cluster from a loose chain) — the
  broker-split test measures genuine redundancy. Pure + unit-tested (two-anchor
  cluster fires; single-hub star is silent). Rule count 68→**69**. Gate green: lib
  (3,286) + integration 0 failures, 24 arch guards, fmt/clippy/doc clean. Paired:
  `PROBLEM_TREE` §8 cycle 56 — same commit.
- **2026-06-20** — **Cycle 57 (SeekNow parse robustness, found empirically).** The
  all-APIs "Ali Kareem" validation scan both proved the comprehensive defaults
  (44 distinct modules dispatched) and exposed a defect: `see_know::client::
  parse_response` errored on a non-JSON body, so an ordinary empty/HTML/gateway "no
  results" response counted as a module failure and tripped the circuit breaker.
  Fix: a non-JSON-shaped body (not starting `{`/`[`) returns the `Ok(Value::Null)`
  no-results sentinel (same one the auth/quota branches use; `extract_items` reads
  it as empty), while a JSON-shaped-but-malformed body still errors (drift signal).
  Defensive + universal: any keyed-API empty/garbage response now degrades to "no
  results" rather than a breaker-tripping error. Regression-tested. No rule/module
  change. Gate green: lib 3,288 (+2), 24 arch guards, fmt/clippy/doc clean. Paired:
  `PROBLEM_TREE` §8 cycle 57 — same commit.

- **2026-06-20** — **Cycle 58 (`au_unclaimed` reduced to its verified QLD core).**
  Principle: *no fabricated coverage*. Empirically probing every state's live CKAN
  API (the "Ali Kareem" loop flagged 76 KB/20 KB non-JSON bodies from VIC/WA) proved
  only Queensland publishes a queryable unclaimed-money datastore — NSW has no
  datastore-active resource, VIC isn't on CKAN (404s), WA has no such dataset, and
  SA only mirrors the harvested QLD record. The four non-QLD `StateRegister` entries
  held fabricated `resource_id`s that 404'd every scan: phantom coverage that cost
  four guaranteed-failed network calls per name and a false five-state advertisement.
  Removed them and the now-dead generic-CKAN path (`StateRegister`, `REGISTERS`,
  `surname`, `owner_matches`, `record_to_entities`, `postcode_centroid`); `process`
  is now the single QLD pass, and the module docs carry the per-state empirical
  verdict so a future contributor re-adds a jurisdiction *only* with a verified
  resource id (QLD is the working template). The real QLD pipeline — joint-owner
  Persons, company Organisation pivots, postcode→geo, suburb enumeration — is
  unchanged. Durable wins: honest capability surface, less wall-time and breaker
  noise on Termux, ~150 fewer lines to maintain. Gate green: lib 3,283 (−5 dead-path
  tests), 24 arch guards, fmt/clippy/doc clean. Paired: `PROBLEM_TREE` cycle 58 —
  same commit.

- **2026-06-20** — **Cycle 59 (`is_app_package_id` — an app package is not a
  domain).** Principle surfaced by the audit + archive forensics: stealer logs name
  the app a credential was stolen from in reverse-DNS form (`com.facebook.katana`),
  which a bare `contains('.')` check happily mints as a `Domain` — that then burns a
  HudsonRock `search-by-domain` call returning *strangers'* records. New pure helper
  `util::domains::is_app_package_id`: 3+ labels whose first label is a generic TLD
  (`com`/`org`/`net`/`io`/`app`/`dev`) is reverse-DNS, because a real registrable
  domain carries its TLD *last*. No Public Suffix List dependency (consistent with
  the project's curated-suffix philosophy). Wired in three places: both OathNet
  stealer Domain-minting paths (so the junk never enters the graph) and a defensive
  short-circuit in HudsonRock `process()` (so a Domain recalled from before the gate
  still can't trigger the doomed call) — the latter without touching the
  value-independent `accepts()` the dispatch invariants depend on. Compounding win:
  kills both the noise *and* the noise-amplifying API expansion, on every future
  stealer-bearing scan. Regression-tested. Gate green: lib 3,286 (+3), 24 arch
  guards, fmt/clippy/doc clean. Paired: `PROBLEM_TREE` cycle 59 — same commit.

- **2026-06-20** — **Cycle 60 (a stealer host is an account, not an asset —
  universal).** Principle: a credential captured *on* a site means the subject has
  an account there, not that they own the domain. Both stealer extractors
  (`oathnet_pro::extract_stealer_entities` and `see_know::extract`) used to mint the
  login URL's host as a `Domain`, which (a) proliferated subdomains of shared
  platforms (`*.taleo.net`), (b) burned dns/cert/wayback/HudsonRock budget
  enumerating the *platform's* infrastructure, and (c) forged false correlation
  brokers across everyone who used that platform. Now both keep only the `Url`
  (the account pathway) and the `<user>@<url>` `Credential`; the host is no longer
  a Domain. Safe because every stealer row carries a `url` (so the pathway is fully
  preserved) and the subject's *own* domains arrive independently via the breach
  email-domain path. Mirrors SpiderFoot's account-vs-INTERNET_NAME distinction.
  Compounding: less noise, less wasted API expansion on Termux, and sharper
  correlation (no shared-platform mega-brokers) on every stealer-bearing scan.
  Regression-tested in both modules. Gate green: lib 3,286 (net 0), 24 arch guards,
  fmt/clippy/doc clean. Paired: `PROBLEM_TREE` cycle 60 — same commit.

- **2026-06-20** — **Cycle 61 (address extractor: don't let one address's state
  bleed into the next).** The re-scan + re-audit the user asked for confirmed cycles
  58–60 on fresh data (domain-noise finding gone, 85/100) and pointed at a clean
  extraction defect behind one geo outlier: a run-on bio "Los Angeles, California
  Dallas, Texas" yielded a phantom "California Dallas, Texas" because the comma-path
  city grab reached back across the first address and kept its trailing state.
  Fix: in the comma path, strip a leading state token from the city when it differs
  from the address's own state, recovering "Dallas, Texas". The differ-from-state
  guard is the safety: state-named cities whose token equals their state (Virginia
  Beach, Virginia; Oklahoma City, Oklahoma) are untouched, and word-path cities
  (Kansas City, Missouri) never enter this branch — so no gazetteer and no risk to
  the AU-geo core. Improves geocode precision (no bogus Probable city fixes) without
  altering the geo-confidence model. Note for the record: the remaining
  geo-divergence is driven by *identity conflation* (several real people share the
  seed name), a separate strand to tackle deliberately rather than via a geo
  heuristic. Regression-tested. Gate green: lib 3,287 (+1), 24 arch guards,
  fmt/clippy/doc clean. Paired: `PROBLEM_TREE` cycle 61 — same commit.

- **2026-06-21** — **Cycle 62 (consolidate three duplication clusters into `util`).**
  Single home for each, callers keep only their own filters/decoders:
  1. **`util::str_util::parse_asn(&str) -> Option<u64>`** — case-insensitive `AS`
     prefix, whitespace-tolerant, validated; rejects junk so callers don't build a
     garbage URL. Migrated `bgpview` / `ip_registry` / `zoomeye` (the last gains
     case-insensitive parsing it was missing).
  2. **`util::json::scan_string_field(body, key) -> Vec<String>`** — the raw-body
     `"key":"…"` scan, behaviour-preserving (skips numeric `"key":123`, value runs
     to next quote, empties dropped, order kept). Migrated `github_user` (orgs +
     gists), `reddit_user`, `hacker_news`; each keeps its own length-bound / dedup /
     domain-extract step at the call site.
  3. **`util::wigle`** (new submodule, alongside `util::oathnet` / `util::see_know`)
     — `detail_url(netid, kind)` + `get(...)` doing the shared auth and WiGLE status
     classification (429 → immediate Err with logged backoff, 401/403 → auth Err,
     404 → Ok(None), success → response for caller to decode). `wifi_intel`'s rich
     handling is preserved verbatim; `wigle::fetch_detail` keeps its swallow-to-None
     contract. ~127 lines of duplicated logic across 8 modules collapse to ~77 lines
     of shared, tested helpers (4 JSON-scan copies → 1, 3 ASN copies → 1, 2 WiGLE
     copies → 1). No module added/removed — registry count stable. Gate green: lib
     3,291 (+4), 24 arch guards, fmt/clippy(`--all-targets`)/doc clean. Paired:
     `PROBLEM_TREE` cycle 62 — same commit.

- **2026-06-21** — **Cycle 63 (centralise HTTP request-construction literals).**
  `util::http::UA_BROWSER` and `util::http::UA_OSINT` now hold the two duplicated
  User-Agents (single source of truth — the stale Chrome/120 bump is now one edit;
  `UA_BROWSER` doc cross-links `util::curl::UA_POOL` to keep the two UA homes
  distinct). Migrated all 11 call sites across `asic_director`, `au_property`,
  `au_people`, `au_electoral`, `github_user`, `reddit_user`, `hacker_news`. And the
  five `format!("Bearer {…}")` headers (`github_code_search`, `fullcontact`,
  `github_user`) became `.bearer_auth(…)` — identical header value, now also flagged
  sensitive for redaction. Behaviour-preserving; gate green: fmt/clippy(`--all-targets`)
  /doc clean, lib 3,291, 24 arch guards, 0 failures. Paired: `PROBLEM_TREE` cycle 63
  — same commit.

- **2026-06-21** — **Cycle 64 (fold the bio matchers into `util::extract`).** Added
  the canonical `util::extract::URL_RE` (the exact http(s) pattern, so trailing-
  punctuation behaviour is preserved — callers still `trim_end_matches`) and pointed
  both `reddit_user` and `hacker_news` at the existing canonical `EMAIL_RE` + the new
  `URL_RE`, deleting their duplicated `bio_patterns()` (and the now-unused `regex` /
  `OnceLock` imports). The bio email match now uses the one canonical definition
  (stricter, validated TLD) — the modules' bio tests pass unchanged, confirming the
  switch is behaviour-safe on real address shapes. Net: one email regex in the
  codebase, not two; a reusable URL matcher for future callers. Gate green: lib 3,292
  (+1), 24 arch guards, fmt/clippy(`--all-targets`)/doc clean. Paired: `PROBLEM_TREE`
  cycle 64 — same commit.

- **2026-06-21** — **Cycle 65 (point the last two email regexes at `EMAIL_RE`).**
  `exa_search` now imports `crate::util::extract::EMAIL_RE` (call site `find_iter`
  unchanged) with its local `static EMAIL_RE` deleted; `employer_pivot::extract_emails`
  uses the canonical matcher directly, dropping its `OnceLock` regex while keeping its
  domain filter (and no dedup, preserving behaviour). Both patterns were
  character-class-identical, so the swap is behaviour-preserving — full suite passes.
  `util::extract::EMAIL_RE` is now the sole email regex in the codebase. Gate green:
  lib 3,292, 24 arch guards, fmt/clippy(`--all-targets`)/doc clean. Paired:
  `PROBLEM_TREE` cycle 65 — same commit.

- **2026-06-21** — **Cycle 66 (`util::str_util::is_handle`).** One parameterised
  predicate — `is_handle(s, min, max)`: length in `min..=max` and every char ASCII-
  alphanumeric or `-`/`_` — now backs both `reddit_user` (3, 20) and `hacker_news`
  (2, 15), replacing the two open-coded multi-line guards. Byte length equals char
  count because the charset test rejects non-ASCII, so behaviour is preserved. The
  handle charset is defined once. Gate green: lib 3,293 (+1), 24 arch guards,
  fmt/clippy(`--all-targets`)/doc clean. Paired: `PROBLEM_TREE` cycle 66 — same commit.

- **2026-06-21** — **Cycle 67 (route `search_engines` text mining through
  `util::extract`).** First, the divergence was healed *upward*: the web-script
  fragment guard moved into `util::extract::page_emails` (new `SCRIPT_EXTS`), so the
  canonical miner now rejects `viewtopic.php…@…` for every caller — `au_people`
  included. Then `search_engines::extract_emails_from_text` / `extract_phones_from_text`
  became thin wrappers over `page_emails` / `phones`, keeping only their search-context
  cap + warning (so a pathological page can't mint an unbounded list); the ~115-line
  byte scanners and the duplicate `is_email_local_char` / `is_domain_char` predicates
  (plus their now-redundant tests) are gone. Net −100 lines. Behaviour is preserved
  for real input and strictly improved for junk (search_engines now also dedups,
  rejects `+0…` numbers and `.js` assets); all search_engines + au_people tests pass
  unchanged. Email/phone byte-mining now has one definition. Gate green: lib 3,290,
  24 arch guards, fmt/clippy(`--all-targets`)/doc clean. Paired: `PROBLEM_TREE`
  cycle 67 — same commit.

- **2026-06-21** — **Cycle 68 (split oathnet_pro/mod.rs into focused submodules).**
  `mod.rs` 1,165 → **350** lines, now just setup + the `Module` impl + preflight +
  the submodule wiring. Extracted: `breach.rs` (530 — breach-PII extraction +
  `TargetMatch` + the shared `push_oathnet_entity`), `stealer.rs` (160 — stealer-log
  leads), `validate.rs` (135 — the pure offline validators). Pattern: each submodule
  `use super::*`; section items promoted to `pub(super)`; `mod.rs` re-globs each
  (`use breach::*` …) so the `Module` impl, the sibling submodules, and the white-box
  `tests` (which call `extract_breach_entities`, `is_public_ip`, … via `super::*`) all
  resolve unchanged. Pure code movement — no module added/removed, registry stable,
  every oathnet test passes. Gate green: lib 3,290, 24 arch guards,
  fmt/clippy(`--all-targets`)/doc clean. Paired: `PROBLEM_TREE` cycle 68 — same commit.

- **2026-06-21** — **Cycle 69 (split see_know/extract.rs into an `extract/` module).**
  `extract.rs` → `extract/mod.rs` (1,025 → **472** lines: core breach extraction +
  `record_evidence` + the shared `push_breach_entity` + tests + wiring), with
  `geo.rs` (132), `associates.rs` (111) and `rich_detail.rs` (338) as siblings. The
  one-level-deeper nesting needed care: `extract_geo_entities` is called by the
  parent `see_know/mod.rs`, so it's declared `pub(in crate::modules::see_know)` and
  re-exported `pub(super)`; the intra-extract items (`extract_associates`,
  `extract_rich_detail`) stay `pub(super)` with private re-exports; `parse_coord`'s
  re-export is `#[cfg(test)]` (only the tests use it at parent level); and
  `push_context_entity`'s doc link to `push_breach_entity` is fully-qualified
  (`super::`) for the strict rustdoc lint. Pure code movement — registry stable, all
  see_know tests pass. Gate green: lib 3,290, 24 arch guards,
  fmt/clippy(`--all-targets`)/doc clean. Paired: `PROBLEM_TREE` cycle 69 — same commit.

- **2026-06-21** — **Cycle 70 (carve the self-contained detectors out of
  key_harvest/mod.rs).** mod.rs 1,363 → **972** lines. Extracted the two cohesive,
  low-coupling blocks as new siblings: `crypto.rs` (199 — `identify_pem_private_key`,
  `identify_crypto_address`, the recursive-base64 unwrap + `shannon_entropy`) and
  `emit.rs` (198 — `emit_key`/`emit_key_with` + the `store_api_credential*` writers).
  Promotions: the detectors to `pub(super)` (only `BASE64_DECODE_MAX_DEPTH` needed it
  for a white-box test); `emit_key*` to `pub(super)`; the public `store_api_credential*`
  re-exported with `pub use` so `key_harvest::store_api_credential` still resolves for
  the parent `oathnet_pro`. `emit.rs`'s doc link to `DetectionConfidence` (which stays
  in mod.rs) is fully-qualified. The interconnected identification/tier sections were
  left in place — their dense pub surface + 2,236-line test file make them higher-risk
  for lower return. Pure code movement, all tests pass. Gate green: lib 3,290, 24 arch
  guards, fmt/clippy(`--all-targets`)/doc clean. Paired: `PROBLEM_TREE` cycle 70 — same
  commit.

- **2026-06-21** — **Cycle 71 (single-source the IP-geo address join).** Added
  `util::geo::compose_address(city, region, country)` — drops an empty middle
  component so a city+country record reads `"City, Country"`, never `"City, , Country"`
  — with a doctest, and routed `ipinfo` / `ipquery` / `censys` / `ip_geo` through it
  (each keeps its own outer presence guard; only the inner format is shared). Behaviour
  identical: same strings, same entities. `ip2location` left alone (its branch folds a
  ZIP into the middle). Net −9 lines across 5 files, but the real win is one definition
  of the join rule instead of four. Gate green: lib 3,290 + the new doctest, 24 arch
  guards, fmt/clippy(`--all-targets`)/doc clean. Paired: `PROBLEM_TREE` cycle 71 — same
  commit.

- **2026-06-21** — **Cycle 72 (single-source the AU-relevance coord tag).** Added
  `util::geo::tag_au_state(&mut entity, lat, lon)` — tags `au-state:{STATE}` +
  `country:AU` when the fix is in an AU state, no-op otherwise — and routed **13**
  inlined call sites across 11 modules through it (regex-matched the exact both-tags
  block, so the `&& let`-chain forms and the lone `au-state`-only site in
  `search_engines` were left untouched — folding them in would have changed behaviour).
  `opencellid`'s now-unused `au_state_for_coords` import was dropped. Behaviour
  identical; net −27 lines. Gate green: lib 3,290, 24 arch guards,
  fmt/clippy(`--all-targets`)/doc clean. Paired: `PROBLEM_TREE` cycle 72 — same commit.

- **2026-06-21** — **Cycle 73 (teach `permute::parse` the two name formats it was
  corrupting).** Two small, pure helpers ahead of tokenisation, so every FullName
  search (the sole caller, `name_intel`, feeds the result into usernames + speculative
  emails + investigation pivots): **(1)** `reorder_comma_name` detects "Last, First
  \[Middle…\]" and returns natural order, with a clean fallback for the title/suffix
  case (`"Ali Kareem, PhD"` is *not* a reorder) and honorific/suffix stripping around
  the swap (`"Dr. Kareem, Ali Jr"` → `"Ali Kareem"`); now `parse("Kareem, Ali") ==
  parse("Ali Kareem")`. **(2)** `strip_bracketed` drops nested/mixed `()[]{}`
  annotations from the name tokens while the trailing-year number is still read from
  the raw string (`"Ali Kareem (1990)"` → year 1990, handle `ali.kareem`). +7 tests
  (incl. the canonical-identity round-trip and the corrected `handles_comma_separator`,
  whose old expectation *was* the bug). No new deps; allocation-light; Termux-safe.
  Gate green: lib 3,297, 24 arch guards, fmt/clippy(`--all-targets`)/doc clean. Paired:
  `PROBLEM_TREE` cycle 73 — same commit.

- **2026-06-21** — **Cycle 74 (route the seven JSON holdouts through
  `util::http::json_decode`).** Replaced each hand-rolled
  `resp.json().await.map_err(…"JSON: {e}")` with `crate::util::http::json_decode(SRC,
  resp).await?`, so all seven now share the capped + archived decode path: their
  responses land in the universal raw archive (dossier completeness), the 32 MiB body
  cap closes the Termux OOM vector, and read-vs-parse failures are reported distinctly.
  Dropped four now-unused `Error` imports (`ip2location`, `disposable_check`, `ipinfo`,
  `ipquery`); the other three still use `Error` elsewhere. Net −21 lines, behaviour for
  valid responses unchanged (same deserialised structs, same entities). Gate green: lib
  3,297, 24 arch guards, fmt/clippy(`--all-targets`)/doc clean. Paired: `PROBLEM_TREE`
  cycle 74 — same commit.

- **2026-06-21** — **Cycle 75 (strip the URL in `send_tagged`, the one chokepoint).**
  Changed the transport-error map to `e.without_url().to_string()`, so every one of the
  ~40 `send_tagged` callers — present and future — stops embedding the secret-bearing
  URL in the error that reaches the logs; the module name (the actually-useful context)
  is still attached. Pinned with a regression test that a key + email in the query
  string never appear in the mapped error. Then closed the two holdouts that bypassed
  the helper entirely with the bare leaking form: `niamonx` (×3) and `osintcat` now use
  `send_tagged(SRC)`, deleting their hand-rolled `map_err` (and wiring the
  `RequestBuilderExt` import). `hunter_io`/`whoisxml` were already safe via a local
  `without_url`; `cert_intel` is a raw-TLS connect (host:port, no query string) and
  unaffected. Net +36/−17. Gate green: lib 3,298, 24 arch guards,
  fmt/clippy(`--all-targets`)/doc clean. Paired: `PROBLEM_TREE` cycle 75 — same commit.

- **2026-06-21** — **Cycle 76 (one shared Email/Domain shape gate for every breach
  parser).** Promoted `looks_like_email` out of `oathnet_pro` into
  `util::extract::looks_like_email` (oathnet re-exports it, unchanged call sites), and
  added `util::domains::looks_like_domain` — the consolidation of the triplicated
  `contains('.') && !is_app_package_id` check **plus** an IP-literal reject and a
  TLD-bearing-final-label sanity check. Routed all four emission sites through them:
  `see_know`'s email field now validates shape (closing the `contains('@')`-only gap),
  and `oathnet_pro` breach + stealer + `see_know` domain paths now drop IP and
  app-package noise in one place. Result: a query echo (`Ali.kareem`) or a stealer
  router IP (`192.168.0.1`) can no longer enter the graph as an entity, so correlation
  sees only real addresses and registrable domains. Both helpers carry doctests; added
  two unit tests seeded directly from the uploaded scan logs (real addresses/domains as
  positives, the echo/IP/app-package noise as negatives). Behaviour for clean records
  unchanged. Gate green: lib 3,300, 24 arch guards, fmt/clippy(`--all-targets`)/doc
  clean. Paired: `PROBLEM_TREE` cycle 76 — same commit.

- **2026-06-21** — **Cycle 77 (classify a breach digest by its leading hex run).**
  Reworked `identify_password_hash`'s bare-digest arm to read the **leading hex run**
  and classify by its length (requiring any remainder to begin at a separator), so the
  OathNet `digest + salt` forms now resolve to `("md5", true)` instead of `None`; the
  prefixed-KDF path (bcrypt/argon2, whose option commas must not be mis-split) is
  untouched because it matches first. Paired with appended-salt detection in `breach.rs`
  (a leading bare-hex digest with a non-empty remainder past the first separator) so the
  `salted` signal is captured even when there is no dedicated `salt` field. Net effect:
  the `jefit` MD5 now carries `hash:md5` + `crackable:fast` + `salted`, and `mod.rs`'s
  fast-hash plaintext-equivalent filter sees it. +2 tests seeded from the real scan
  rows (combined forms, the separator guard, and an argon2 negative). Gate green: lib
  3,302, 24 arch guards, fmt/clippy(`--all-targets`)/doc clean. Paired: `PROBLEM_TREE`
  cycle 77 — same commit.

- **2026-06-21** — **Cycle 78 (one typed classifier for credential-field values).**
  Added `util::extract::CredentialField` (`Sentinel` / `Email` / `Secret`) +
  `classify_credential_field` + `is_placeholder_secret`, and routed both password
  parsers through it: `oathnet_pro/breach.rs` and `see_know/extract` now **drop** a
  capture sentinel, **recover** an email-in-slot as a 0.45 `Email` lead tagged
  `recovered-from-password` (instead of a junk `Password`), and only emit a genuine
  `Secret` — applying their own length/variety gate on top. `is_placeholder_secret`
  rejects redaction markers anywhere plus **bracketed** capture sentinels (`[fail]`,
  `<empty>`); the bracket requirement keeps a real-if-terrible `fail`/`null` password
  from being discarded. One decision point replaces two divergent inline gates (the
  enum makes the three outcomes explicit and reusable for future stealer modules).
  +2 tests seeded from the logs (sentinel/email/secret split; the breach end-to-end
  recovery + no-false-Password). Gate green: lib 3,304, 24 arch guards,
  fmt/clippy(`--all-targets`)/doc clean. Paired: `PROBLEM_TREE` cycle 78 — same commit.

- **2026-06-21** — **Cycle 79 (a capped, non-archiving `read_text` chokepoint).**
  Factored the erroring-cap streaming core out of `read_json_text` into a private
  `read_capped_or_err` (behaviour-identical for the ~25 JSON callers), and added
  `util::http::read_text` — the text counterpart to `json_decode`: bounded at
  `JSON_BODY_CAP`, transport errors module-tagged with credentials redacted, and
  **no archiving** (so a generic payload like a Pwned-Passwords hash range is not
  retained as a source record). Routed `hackertarget`, `pwned_passwords` and
  `social_location` through it, dropping two now-unused `Error` imports. Net effect:
  the three text endpoints gain the OOM cap + redaction the JSON path already had,
  with one fewer hand-rolled error tail each. +1 test. Gate green: lib 3,305, 24 arch
  guards, fmt/clippy(`--all-targets`)/doc clean. Paired: `PROBLEM_TREE` cycle 79 —
  same commit.

- **2026-06-21** — **Cycle 80 (cap the breach candidate flood; classify each row
  once).** Lifted the per-page breach loop out of `mod.rs::process` into
  `breach.rs::extract_breach_page`, the natural home beside `TargetMatch`,
  `extract_breach_entities_with` and `push_oathnet_entity`. It builds the match context
  once (the existing hoist), classifies each row once via `TargetMatch::matches`, and
  threads that single `bool` into `extract_breach_entities_with` — whose signature
  changed from `match_ctx: &TargetMatch` to `is_target_row: bool`, deleting the internal
  re-match so the identity decision now lives in exactly one place and is reused for both
  the quarantine demotion and the new sampling gate. **Target-matching rows are always
  extracted in full; non-matching strangers are sampled at most `MAX_CANDIDATE_ROWS`
  (= 20) per page**, cutting the worst-case candidate count ~5× (the Ali Kareem page's
  491 → ≤ ~100) while keeping a spot-check sample. API-key harvest
  (`store_api_credential` + `extract_api_keys_from_item`) stays **unconditional** for
  every row — a leaked tool credential is valuable regardless of the cap and is too rare
  to flood — and stays after PII extraction so per-row ordering is byte-identical for the
  uncapped path. The `#[cfg(test)]` wrapper computes the bool the same way, so every
  existing characterization test is unchanged. +1 test seeded from the exact failure
  (100 `pureincubation.com` strangers + 1 trailing real "Ali Kareem" row → candidate
  emails ≤ cap, and the target row still emitted at full confidence after the cap is
  spent). Gate green: lib 3,306, 24 arch guards, fmt/clippy(`--all-targets`)/doc clean.
  Paired: `PROBLEM_TREE` cycle 80 — same commit.

- **2026-06-21** — **Cycle 81 (recover a scan's entities from the durable event log).**
  Closed the 558→0 export cliff at the single point every reader shares —
  `Store::entities_for_scan`. When the `entities` table is empty for a scan (still
  running, interrupted, or killed before `finalise_scan` wrote it), the read now falls
  back to `entities_from_events`, which folds the scan's logged `EntityFound` entities
  by UID through the SAME `Entity::merge` the engine uses in-flight. Each event is a
  distinct *pre-merge* emission, folded **exactly once**, so corroboration sums
  correctly and is never double-counted — and because the fallback fires only on an
  empty table, a genuinely empty scan still returns empty and the common finalised read
  never pays for it. The authoritative display ranking (relevance → C_eff → confidence →
  uid) was lifted into a shared `sort_entities_for_display` so a recovered in-flight scan
  and a finalised one order identically. One change at the central read path =>
  CSV export, full dossier, JSON, and every API handler transparently recover what a
  scan found even when it never finalises. **Deliberately rejected** write-path
  incremental persistence: the store's upsert is a SUM-corroboration GREATEST-merge, so
  re-persisting an evolving entity (checkpoint + finalise) would double-count
  corroboration and corrupt tiering on *every* scan — the event-log reconstruction
  sidesteps that by merging once, at read time, off purely additive data. +1 test
  (logged events → recovered set; duplicate-UID corroboration summed once; empty scan
  stays empty; a finalised table is preferred over the log). Gate green: lib 3,307, 24
  arch guards, fmt/clippy(`--all-targets`)/doc clean. Paired: `PROBLEM_TREE` cycle 81 —
  same commit.

- **2026-06-21** — **Cycle 82 (an honest breach headline; one match pass for all three
  decisions).** New `breach_parent_entity` returns `None` when the subject appears in
  none of the returned records — so a stranger-only page no longer merges a false 0.85
  `breach` hit onto the engine's seed anchor (the anchor still represents the subject; a
  miss simply asserts nothing) — and, when the subject IS present, aggregates
  `countries`/`names`/`genders`/`dates_of_birth` over the MATCHING rows ONLY, plus an
  honest `hits` (matched) vs `records_returned` (page size) split. Consolidated the
  identity match into a SINGLE pass in `process`: `row_matches: Vec<bool>` is computed
  once and feeds the parent gate, the candidate-flood cap, and the per-row quarantine —
  `extract_breach_page` now takes the precomputed `row_matches` instead of rebuilding a
  `TargetMatch` (one source of truth; `TargetMatch::matches` promoted to `pub(super)`).
  Net effect: for the "Ali Kareem" page the subject node loses its fabricated breach
  tag and 100-stranger aggregate dump, while a genuine hit reads its own attributes
  cleanly. +1 test (zero-match → `None`; subject present → parent aggregates only the
  subject's row, `countries=AU` not the strangers' `ZZ`). Gate green: lib 3,308, 24 arch
  guards, fmt/clippy(`--all-targets`)/doc clean. Paired: `PROBLEM_TREE` cycle 82 — same
  commit.

- **2026-06-21** — **Cycle 83 (capture the login IP from any field; one shared
  public-IP gate).** Promoted `is_public_ip` into `util::preflight` beside `is_private_ip`
  — one definition (`parses && !private`) for every breach/stealer parser — and routed
  both extractors through it: `oathnet_pro`'s hand-rolled `pub(super) fn` became a
  re-export (dropping its now-empty `use super::*`), and `see_know`'s weak `len >= 7`
  gate was tightened to it, so a private LAN address can no longer masquerade as a
  geolocation lead. Both now iterate `["ip", "lastip", "last_ip"]`, emitting each
  DISTINCT public address as its own `geolocation-lead` (UID/`seen` dedup collapses the
  ip == lastip case), so snusbase-shaped records finally yield the subject's login
  location instead of nothing. Behaviour for clean `ip`-only records is unchanged. +2
  tests (public `lastip` → lead; private `lastip` rejected — one per module). Gate green:
  lib 3,310, 24 arch guards, fmt/clippy(`--all-targets`)/doc clean. Paired:
  `PROBLEM_TREE` cycle 83 — same commit.

- **2026-06-21** — **Cycle 84 (flatten stealer `victims[].credentials[]` so the logins
  survive).** Extended `extract_items` with a `victims` branch + a `flatten_victims`
  helper that turns each nested credential into a standalone item: one infected host (one
  victim / stealer log) shares its scalar context — `log_id`, host `ip` — with every
  credential it leaked, so each flattened item carries BOTH the login
  (`username`/`password`/`pwned_at`) and its provenance, and the existing field extractor
  consumes it unchanged (yielding a `Username`, a `Password`, and — via cycle 83 — the
  host IP as a geo lead). A victim with no `credentials` array still surfaces as one
  host-intel item so nothing is lost. The change is purely additive: every flat shape is
  matched first and unchanged, and an unknown shape still yields empty — so only the
  previously-dropped stealer set is affected. +2 tests (the real `results:0`/`victims`
  shape → 2 credential items inheriting `log_id`+`ip`; a credential-less victim → 1
  host item). Gate green: lib 3,312, 24 arch guards, fmt/clippy(`--all-targets`)/doc
  clean. Paired: `PROBLEM_TREE` cycle 84 — same commit.

- **2026-06-21** — **Cycle 85 (a per-module Termux cap exemption so see_know survives
  the clamp).** Added `Module::termux_timeout_cap_exempt()` (default `false`), threaded
  through `resolve_timeout` → `apply_termux_cap` (now a 4th parameter). A blanket cap
  raise was rejected: the cap was deliberately *lowered* 60→45 s to stop `search_engines`
  burning the phone's wall-time for zero results, so the fix had to be surgical — cap the
  wasteful modules, exempt the one whose slowness is the upstream's own server cap.
  `see_know` opts in and keeps its full 80 s budget on Termux (still finite, still above
  the 78 s curl outer so the response is actually observed), so the highest-priority paid
  source finally returns data on the platform HSE targets — making cycles 83–84's
  parsing reachable in production. Every other module is `false` and byte-identical;
  exemption only changes behaviour on Termux without a `--module-timeout` override. The
  trade is honest: the serial paid phase now spends ~55–60 s *productively* (data
  retrieved) instead of 45 s *wasted* (timeout, nothing) — decoupling that phase from the
  free fan-out is a noted follow-up, not this change. +2 tests (exempt keeps its budget
  while a non-exempt peer at the same value still clamps; see_know's exemption + curl-outer
  headroom locked). Gate green: lib 3,314, 24 arch guards, fmt/clippy(`--all-targets`)/doc
  clean — verified on the CI toolchain (rustc 1.96.0). Paired: `PROBLEM_TREE` cycle 85 —
  same commit.

- **2026-06-21** — **Cycle 86 (promote the subject's demographics to normalized,
  first-class tags).** New `identity_tags` helper reads DOB / gender / age across the key
  spellings the providers use (`date_birth` | `birthdate` | `date_of_birth` | `dob`;
  numeric-or-string `age`), normalizes them (gender collapses `male`/`m` → `M`,
  `female`/`f` → `F`; one canonical `dob:` regardless of source key) and stamps them as
  tags on the see_know `Person`. The dossier headline now reads
  `Ali Kareem [dob:1990-05-12] [gender:M] [age:34]` directly instead of leaving the
  demographics buried in raw-record evidence, and because tags merge by UID a value
  re-stated across records folds to one. Purely additive: a record with no demographics
  adds no tags (the `extract_entities` characterization test is unchanged), and the
  full-field evidence fold still carries the raw values as before. +1 test (normalization
  across key/value spellings; the no-demographics no-op). Gate green: lib 3,315, 24 arch
  guards, fmt/clippy(`--all-targets`)/doc clean — verified on rustc 1.96.0. Paired:
  `PROBLEM_TREE` cycle 86 — same commit.

- **2026-06-21** — **Cycle 87 (one shared target-matcher; quarantine see_know's
  strangers).** Promoted `TargetMatch` **and** the `CANDIDATE_CONF` quarantine ceiling
  out of `oathnet_pro` into `util::target_match` — one definition both breach pools
  share, so "is this row the subject?" is judged by identical code. The shared matcher's
  field list is the UNION of the providers' spellings (`phone`|`phone_number`,
  `name`|`full_name`), which only ever *confirms* a genuine row whichever key the upstream
  chose — a strict completeness gain for oathnet, whose own characterization suite is
  unchanged. `oathnet_pro` now imports it (local struct + const deleted). `see_know`
  computes `is_target` once per record and, when it does not match, demotes that record's
  identity / credential / raw-detail entities to `candidate` strength in a single range
  pass before `extract_associates` (which keeps its own `family-candidate` model), plus
  the trailing domain inline — so a same-name stranger survives as a low-confidence lead
  instead of masquerading as the subject. Subject rows and the common exact-match
  username/email/phone searches are byte-identical (is_target = true ⇒ no demotion). +7
  tests (6 matcher unit tests for the shared component; see_know stranger-demoted vs
  subject-full-confidence). Gate green: lib 3,322, 24 arch guards,
  fmt/clippy(`--all-targets`)/doc clean — verified on rustc 1.96.0. Paired:
  `PROBLEM_TREE` cycle 87 — same commit.

- **2026-06-21** — **Cycle 88 (postcode-qualified addresses; stop minting provider
  plumbing).** **(a)** `oathnet_pro`'s composed `Address` now appends `postal_code`
  (`HAMPTON, VA, 23666`), still gated on city/street so a bare ZIP can never form a
  standalone node — bringing it to parity with `see_know`'s street→postal→country
  composition and handing the geocoder a ZIP-centroid-precise value instead of a
  city-coarse one. **(b)** Added `uid` + `migration_id` to `see_know`'s `RICH_DETAIL_SKIP`
  so the catch-all no longer mints the provider's internal record keys as `Other(...)`
  nodes — one fewer junk entity per record, and the dossier stops carrying snusbase's
  database bookkeeping as findings. Both are surgical and additive: the only behaviour
  change is a more precise address string and the absence of two plumbing nodes; clean
  records are otherwise identical. +2 tests (the composed value carries the ZIP;
  `uid`/`migration_id` never become entities while the real person still does). Gate green:
  lib 3,324, 24 arch guards, fmt/clippy(`--all-targets`)/doc clean — verified on rustc
  1.96.0. Paired: `PROBLEM_TREE` cycle 88 — same commit.

- **2026-06-21** — **Cycle 89 (demotion as a first-class, orthogonal `Entity` capability;
  matching ⊥ tiering).** Promoted the candidate-quarantine into one method on the type it
  mutates — `Entity::demote_to_candidate()` (cap to `CANDIDATE_CONF`, stamp `candidate`,
  idempotent) — and moved `CANDIDATE_CONF` to `core::entity` beside the tier ladder it
  belongs to (documented `< PROBABLE_MIN`, so a demoted entity is *guaranteed* to classify
  `Candidate`). All three call sites — `oathnet_pro`'s push and `see_know`'s range pass +
  domain push — now call the one method; `util::target_match` is left as a *pure matcher*
  ("does this row identify the subject?") that no longer carries a confidence constant it
  never used. Net effect: the two orthogonal capabilities each have a single, correct home
  — `util::target_match` decides the match, `Entity` owns the tier mutation — and the
  demotion semantics can evolve (e.g. a corroboration cap) in exactly one place for every
  current and future pool. Behaviour is identical: the full breach/stealer characterization
  + quarantine suites pass unchanged. +1 `core::entity` test (cap / tag / idempotent /
  never-raise-lower-confidence), −1 relocated `util` constant test. Gate green: lib 3,324,
  24 arch guards, fmt/clippy(`--all-targets`)/doc clean — verified on rustc 1.96.0. Paired:
  `PROBLEM_TREE` cycle 89 — same commit.

- **2026-06-21** — **Cycle 90 (source→sector classification; "breached real-estate
  exclusively" as a filter, synergising both pools).** New `util::breach_sector::source_sector`,
  built *backwards from the real source-DB shapes*: it reads the embedded snusbase category
  (the second-from-last `_`-segment when the last is a date) and recognises real-estate /
  property brands + portals + CRMs (AU emphasis: realestate.com.au, Harcourts, LJ Hooker,
  PropertyTree, OnTheHouse, PEXA, …), returning a normalised sector slug or `None` (an
  unknown source is left untagged, never guessed). Both breach pools now stamp every entity
  `sector:<x>` from the `dbname`/`source` the evidence already carries — `oathnet_pro`'s
  `push_oathnet_entity` (full coverage; every breach kind flows through it) and `see_know`'s
  `push_breach_entity` — so the answer to "show me only the breached real-estate data" is the
  tag `sector:real-estate`, applied identically across both pools (one orthogonal classifier,
  no new feed, no blind scraping). Verified against the genuine dump values: `ZYNGA…`→`gaming`,
  `AITYPE…`→`tech`, `pureincubation.com`→`None` (correctly not property), and
  real-estate brands/categories→`real-estate`. Behaviour for sources that don't classify
  (every existing test fixture) is unchanged. +6 tests (4 classifier unit, 1 per pool).
  Gate green: lib 3,330, 24 arch guards, fmt/clippy(`--all-targets`)/doc clean — verified
  on rustc 1.96.0. Paired: `PROBLEM_TREE` cycle 90 — same commit.

- **2026-06-21** — **Cycle 91 (one universal chokepoint wires EVERY breach pool to the
  sector classifier).** Hoisted sector tagging out of the two modules into a single
  admission-time pass, `core::engine::enrich::tag_breach_sector`, run on every entity right
  beside the existing universal stamps (MITRE ATT&CK, geospatial enrichment) and BEFORE the
  `EntityFound` emit (so the event log + cycle-81 recovery carry it). Gated on the `breach`
  tag, it reads the source DB across all pools' evidence keys (`dbname`, `source`,
  `breach_name`, `breach_domain`, `database`, `database_name`, `source_db`) and stamps
  `sector:<x>` via `util::breach_sector` — so `oathnet_pro`, `see_know`, `hibp`, `dehashed`,
  `intelx`, `hudsonrock`, … and any FUTURE breach module are all wired by the one pass, for
  free. Removed cycle 90's now-redundant per-module tagging (and its two module tests),
  leaving a single mechanism. `util::breach_sector` was added to the `core → util` allowlist
  in `tests/architecture.rs` — it is a pure, dependency-free offline classifier (no state,
  no I/O), exactly the leaf category the guard already permits (`sim_anonymity`, `surnames`,
  `city_coords`). +2 engine tests (the multi-key wiring resolves real-estate whichever key
  a pool used; non-breach / unknown-source / idempotent no-ops); −2 superseded module tests.
  Gate green: lib 3,330, 24 arch guards, fmt/clippy(`--all-targets`)/doc clean — verified on
  rustc 1.96.0. Paired: `PROBLEM_TREE` cycle 91 — same commit.

- **2026-06-21** — **Cycle 92 (brand→sector knowledge + the last two bare-name pools, reshaped
  from a live run).** Working backwards from the real corpus: added a curated
  `KNOWN_SOURCE_SECTORS` table to `util::breach_sector`, mapping the actual breach
  brands/domains the live "Ali Kareem" graph surfaced (`neopets`→gaming, `tunngle`→gaming,
  `deezer`→media, `edmodo`→education, `jefit`→health, `fling`→adult, `tumblr`→social,
  `linkedin`→tech, …) plus the global long tail. Matching is whole-alnum-token, not
  substring, so a needle can never bleed across an unrelated token (`zyngamania.com`→`None`);
  resolution order is real-estate → structured category → known brand, each more conservative
  than a guess. Added a `media` slug to the structured vocabulary for consistency. Then
  finished the universal pass: `tag_breach_sector` now also reads `osintcat`'s dynamic
  `breach_<name>` keys and `xposed_or_not`'s `breaches` list, and collects EVERY distinct
  sector (multi-sector) rather than first-wins — an account in gaming+social+health breaches
  earns all three tags, so a single-sector filter never misses it. `Entity::tag` dedups, so
  the pass stays idempotent without the old early-return. +1 brand test (real corpus names),
  +1 engine test (osintcat + multi-sector xposed). Gate green: lib 3,332, fmt/clippy
  (`--all-targets`)/doc clean on rustc 1.96.0. Paired: `PROBLEM_TREE` cycle 92 — same commit.

- **2026-06-25** — **Resolved the `origin/main` merge as a union, preserving both sides.**
  Migrated `rule_au_078_cell_tower_dual_source` into the new `geo/cluster.rs` and renumbered
  it **AU-084** (AU-078 now belongs to main's `rule_au_078_hub_entity`), updating the
  dispatcher in `correlator/mod.rs` and every test reference; `git rm`'d the flat `geo.rs`
  whose other contents main had already split into `geo/`. Kept `wants_infra` in
  `scan_handlers/mod.rs` (the moved handler bodies now live in main's submodules, so only the
  helper `scan_export` depends on was retained). Took main's haversine
  `multi_source_convergence` (`proximity_graph[0].distance_km <= 5.0`, consistent with
  `cluster_coordinates`' `THRESHOLD_KM`) over HEAD's latitude-biased degree approximation.
  Unioned both correlator test sets (HEAD's AU-076/077 shared-registrant/hosting +
  main's AU-076–082). Ran `cargo fmt --all` to clear the stray blank line that broke CI.
  Full gate green locally: ~4,048 tests 0 failed, `clippy --all-targets -D warnings` clean,
  rustdoc lints clean, fmt clean. Paired: `PROBLEM_TREE` — same commit.

- **2026-06-25** — **Cleared the lone 1.96 clippy lint CI exposed.** Rewrote
  `util/key_vault::total_count`'s `.map(|n| n as u64).unwrap_or(0)` as the idiomatic
  `.map_or(0, |n| n as u64)` (semantically identical on a `Result`: map the `Ok`, default on
  `Err`). Since the local toolchain (1.94) lacks this lint, verified the edit with `cargo check
  --lib` and reasoned from clippy's "1 previous error" that this was the only crate-wide
  violation — no need to chase a toolchain install. A multiline scan for sibling
  `.map(…).unwrap_or(…)` shapes confirmed the rest are `.and_then`/`.or_else`/`.find_map`
  chains the lint does not target. Paired: `PROBLEM_TREE` — same commit.

- **2026-07-01** — **SOL-LIVE-DISPATCH-BUDGET delivered `[ ]`→`[x]`, closing
  T2.11's last open bullet.** **P→S step:** T2.11's LOW bounded-over-dispatch
  bullet had a fix already sketched ("re-check the live count in the consumer
  loop, or interleave `join_next` with spawning") but no solution node — picked
  as this cycle's unit of work per §5's execution order (T2 robustness, after
  T0/F/T1). Implemented the interleave option: `dispatch_target_concurrent`'s
  spawn loop now non-blockingly drains finished siblings
  (`JoinSet::try_join_next`) before each `max_entities` check, via a shared
  `absorb_dispatch_outcome` helper also used by the final blocking drain.
  **S→P step:** proven against the class it fixes, not just the fix — the new
  regression test fails on the pre-fix code (all 10 modules of a 10-module
  target dispatch despite `max_entities: Some(1)`) and passes after. **Gap
  refresh:** §3 leverage map gains the new row; §4d's T2 row now lists T2.11 as
  fully closed bar the already-accepted `[-]` budget-reset-zeroing note (no
  change there — SOL-BUDGET's cycle-18 finding stands). Paired: `PROBLEM_TREE`
  T2.11 + §8 updated in the same commit. Gate green (fmt/clippy `--all-targets`/
  doc/test clean).

- **2026-07-01** — **S→P audit: SOL-GEOINT's "provenance radius output" was
  already delivered, on two separate occasions, and the §2 node text never
  caught up.** No open node in either tree had a small, safe, code-grounded
  next increment this cycle (§3.F blocked on a natural trigger for `bstr`;
  T2.7's golden-fixture work needs either a live third-party fetch or a
  fabricated-looking fixture, both out of bounds for an unattended cycle) — so
  per step 1's discovery fallback this cycle re-read C5 against the actual
  shipped code and git history rather than trusting the tree's own "remaining"
  claim. Found: cycle 29 (2026-06-20) added the confidence radius to
  `au059_synergy_fix` and its OWN log entry declared "delivered end-to-end,"
  but the SOL-GEOINT node's `Remaining:` bullet was never edited to match; and
  `d1507539` (2026-06-26) closed the rest — a single-signal fallback fix for
  every scan, not just the multi-source case — shipping with a `CHANGELOG.md`
  entry that was never cross-referenced into either tree. Corrected the node
  text in place (§2) with full commit provenance; the genuinely-still-open
  legs (AU-059's use of `weighted_centroid` over the more robust
  `weighted_geometric_median`, AU bounding precision, movement/timeline geo,
  cell-DB auto-sync) are kept, unchanged. No code change, no test change — the
  gate was re-run anyway (fmt/clippy `--all-targets`/doc/test all still clean,
  as expected for a docs-only diff). Paired: `PROBLEM_TREE` C5 + §8 — same
  commit. This is the same class of correction as the cycle-20 stale-note audit
  (`securitytrails`/`bgpview`/`ripestat`) — keeping the trees honest is itself
  the unit of work when the trees, not the code, are what's behind.

- **2026-07-01** — **SOL-GEOINT: AU-059 upgraded from `weighted_centroid` to
  `weighted_geometric_median`, closing the one real leg the previous cycle's
  audit surfaced.** P→S pick: with AU-057 and `diagnostics::cluster_coordinates`
  already on the Weiszfeld geometric median, AU-059 — the function behind the
  dossier's headline "Best location estimate" — was the last of the three
  convergence call sites still using a plain weighted average. Swapped it in
  with the same `.or_else(weighted_centroid)` fallback the other two use for
  the rare non-convergent case. **S→P proof:** new test
  `au059_synergy_fix_resists_a_single_high_confidence_outlier` builds a fixture
  where a higher-confidence outlier holds 36% of the weight (below the
  median's 50% breakdown point) against a 64%-weight agreeing majority; it
  computes the plain centroid inline to prove the fixture is genuinely
  discriminating (centroid lands at lon≈138.6, a third of the way toward the
  outlier) before asserting the real fix does not follow it (lon>145). Fails
  on the pre-fix code, passes on the fix. Confirmed non-breaking: every
  existing AU-052/AU-059/`scan_export` geo test still passes, because they all
  assert tolerant ranges against tightly-clustered fixtures where the two
  estimators don't meaningfully diverge. Gate green: 4259 lib tests,
  fmt/clippy `--all-targets`/doc clean. Paired: `PROBLEM_TREE` C5 + §8 — same
  commit.

- **2026-07-01** — **New: SOL-ROI-HINT closes T2.13, a structurally-dead CLI
  hint found by this cycle's discovery pass.** With T2.7 blocked (golden
  fixtures need either a live third-party fetch or a fabricated-looking
  fixture) and no other open node offering a small, safe increment, step 1d's
  fallback applied: read `cli/scan/dossier.rs` against
  `util::diagnostics::analyse` rather than trusting either at face value.
  Found the dossier's "ROI: N keyed/paid module(s) yielded nothing" hint
  filtered `modules_by_yield` for `entities_emitted == 0` — a state that list
  can never contain, because `analyse` only ever inserts an entry when an
  entity's evidence names a source; a module that ran and found nothing is
  absent, not present-at-zero. Proven empirically, not just by inspection: a
  real `hse scan --output dossier` against a live low-signal domain, run
  BEFORE the fix, dispatched 42 modules (11 `KeyGated`/`Paid`) and printed a
  yield table with exactly one row — the hint never fired. New pure
  `zero_yield_keyed_or_paid_modules` reads the scan's own durable `ModuleDone`
  events instead (already tracked per module, nothing new to instrument); the
  SAME scan re-run after the fix correctly names all 11. 4 new unit tests on
  the pure function. `print_dossier` needed the store handle to read events,
  pushing it to 8 parameters — bundled into a `DossierArgs` struct rather than
  `#[allow(too_many_arguments)]`, mirroring T2.5's `DispatchCx`/
  `DispatchState`. Gate green: 4263 lib tests (+4), fmt/clippy
  `--all-targets`/doc clean; live CLI verified both sides of the fix. Paired:
  `PROBLEM_TREE` new T2.13 + §8 — same commit.

- **2026-07-01** — **S→P: re-reading the whole block that produced T2.13
  found the same dead premise twice more; removed both, opened T2.14 rather
  than force a fix with an unresolved noise question.** Having just root-caused
  one dead hint, this cycle deliberately re-read the REST of
  `analyse()`'s `optimization_hints` construction instead of stopping at the
  one instance already fixed — the same `entities_emitted == 0` premise
  appeared in a per-module hint and a scan-level 60s hint, both equally
  unreachable. Removed both (misleading dead code, not a capability). Did not
  mechanically restore them: `analyse()`'s pure signature can't reach the
  `StoragePort`-sourced events without a 16-call/test-site change, AND the
  per-module variant has a real, separate noise problem — a live 42-module
  scan run this cycle shows most modules land at zero yield for any given
  target kind, so firing one hint line per module would flood the list, not
  inform it. Opened **T2.14** / new **SOL-HINT-NOISE** with the concrete
  reinstatement options (event-source the 60s hint the same way SOL-ROI-HINT
  was fixed; cap/cost-gate/summarise the per-module one) rather than picking
  one under time pressure. Renamed the one test whose name overclaimed its
  coverage (`analyse_emits_optimization_hints_for_zero_yield` → `analyse_
  falls_back_to_a_hint_when_nothing_else_fires`). Gate green: 4263 lib tests
  (net unchanged — a removal + a rename), fmt/clippy `--all-targets`/doc
  clean; live dossier output re-verified unaffected. Paired: `PROBLEM_TREE`
  T2.13 addendum + new T2.14 + §8 — same commit.

- **2026-07-01** — **S→P audit: the §4a "AU-060-candidate" cell-tower
  cross-validation gap was stale — delivered a day earlier as AU-084, under
  a different number, and never checked off.** With T2.14's per-module noise
  question deliberately left for a future cycle (a real design decision, not
  a quick fix) and no other small increment ready, this cycle re-verified
  §4a's remaining open bullets against the code instead of trusting them.
  `opencellid` × `cell_intel` DeviceId cross-validation — logged as a gap at
  cycle 20 — was built 2026-06-30 (`770df4c9`) as
  `rule_au_084_cell_tower_dual_source`, registered in the dispatch table with
  4 tests, and its ORIGINAL proposed number (`AU-060`) had separately been
  reassigned to an unrelated rule (transitive identity closure) in the
  interim — so the note was doubly wrong, not just "not yet started." No code
  change; verified by reading `rules::geo::cluster.rs`, the correlator
  dispatch table, and `git log -S` for the delivery commit, not by inference.
  This is the third stale-note class found this session (after the cycle-20
  `securitytrails`/`bgpview`/`ripestat` audit and the C5 "provenance radius"
  audit two cycles ago) — confirms these gap-analysis sections need periodic
  re-verification against the code, not just against each other. Paired:
  `PROBLEM_TREE` §8 — same commit (no PROBLEM_TREE node existed for this gap;
  it was logged only in this tree's §4a).

- **2026-07-01** — **S→P audit: a fourth stale note, same session — SOL-UPDATE's
  "no diff summary" remaining note and the twin §4a "hse update --check
  changelog" gap were both already delivered.** Continuing the same
  re-verification-against-code sweep that found AU-084: `cli/update.rs`
  already has `changelog_lines` (runs the exact `git log --oneline
  HEAD..@{u}` the note proposed) wired into `--check`'s output (up to 20
  lines beneath the commit count). Corrected both the SOL-UPDATE node's
  `Remaining` bullet and the standalone §4a entry. **Important caveat, unlike
  the AU-084 correction:** this repository's entire history begins at one
  root commit (`770df4c9`, 857 files / 244,800 lines, no parent — an import,
  not incremental work), so nothing before it is attributable to a specific
  delivery cycle via `git log`; corrected the wording to say so honestly
  rather than imply a recent, dated delivery the evidence doesn't support.
  Left a genuine, smaller residual open: `changelog_lines`/`commits_behind`
  have no test against real `git` subprocess behaviour (`tempfile` is already
  a dev-dep for a local-repo-pair fixture) — noted as its own follow-on, not
  bolted onto this doc correction. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-ATTACK-INLINE sharpened: one genuine mislabel fixed in
  the per-finding ATT&CK layer.** The settled MITRE solution here is *inline on
  the data* (per-finding `attack:<ID>` tags; the separate coverage/Navigator
  surface was deliberately removed, cycles 49/52), so the precision of that
  layer *is* the deliverable — a wrong module→technique mapping mis-labels every
  finding it emits. Audited the active-collection modules against their ATT&CK
  overrides and found exactly one real defect: `subdomain_takeover` (an active
  dangling-CNAME vulnerability probe that emits a `vulnerable` `Domain`) mapped
  to passive `T1590.001` *Domain Properties*. Added `T1595.002` *Vulnerability
  Scanning* to the `core::attack` catalogue and remapped the module, mirroring
  the `portscan` active-scanner precedent; verified the other active modules
  (`dns_axfr`, `waf_detect`, `api_key_probe`, `portscan`) are already precise.
  Guard-pinned both directions. This is P→S alternation on a real, code-grounded
  precision gap — not a coverage-report rebuild (that solution stays retired).
  Gate green. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-FP-GATE extended: two more non-identity selectors
  excluded from association/linkage rules.** The doctrine's standing solution to
  the correlator's dominant risk is a *precision gate at admission* — never let a
  selector that isn't the subject's identity forge a link (the `is_role_mailbox`,
  `is_proxy_registrant`, salted-hash/entropy, and crowd-cap gates already in the
  tree). A grounded false-positive audit of the association family found two rules
  missing a gate they should have inherited: **AU-018** (email↔location) didn't
  apply `is_role_mailbox` (which AU-001/AU-045/AU-002 already do), and **AU-050**
  (shared-phone associates) didn't check line type, so a shared `1800`/`1300`/`13`/
  `190x` business desk clustered strangers. Both fixed by *reusing existing
  vocabulary* (`core::validation::is_role_mailbox`; `util::address_au::
  au_phone_line_type` + `AuLineType::is_business_service`) — single-sourced, no new
  predicates, each with a fail-before/pass-after test that also pins the
  true-positive survives. S→P alternation: closes two concrete FP leaves under the
  same-selector-hygiene theme without touching any rule's real signal. Gate green.
  Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-BOUNDARY reinforced at the email admission layer:
  single-sourced the domain-validity check across all three paths.** The doctrine
  holds that a datum is validated once, at admission, by one shared predicate
  (SOL-F1 / normalisation-defines-identity). `util::extract` had three email
  acceptors that had drifted apart: the free-text `EMAIL_RE` (strict, real TLD),
  the field gate `looks_like_email` (only `contains('.')`), and the HTML scanner
  `page_emails` (only `contains('.') && len>3`) — so the two non-regex gates
  admitted IP-literal / numeric-TLD / double-dot hosts the scanner rejects.
  Factored the regex's own domain rule into one `host_has_alpha_tld` helper and
  routed both non-regex gates through it — the vocabulary is now single-sourced
  and the gates provably cannot out-admit the scanner. Sound and strictly
  tightening (no real address has a non-alphabetic TLD, so zero false negatives),
  with fail-before/pass-after tests on both paths. Gate green. Paired:
  `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-BOUNDARY at the MAC extractor: a fragment guard around a
  boundary-limited regex.** `MAC_RE`'s `\b` anchoring can't tell a standalone MAC
  from the first six octets of a longer EUI-64 run (the separator satisfies the
  boundary), and Rust's regex engine has no look-around to express "not followed
  by another octet." The doctrine's answer when a finite-automaton match is
  necessarily approximate is a cheap deterministic post-filter at the byte level:
  `macs` now drops any match flanked by `<sep><hex>`, which is exactly the
  longer-run signal. Pure, allocation-free, boundary-safe (ASCII edges), and it
  only ever *removes* a fabricated MAC (a phantom BSSID `mylnikov`/`wigle` would
  otherwise geolocate) — never a real one. Fail-before/pass-after test on both
  colon and hyphen 8-octet runs plus a punctuation-wrapped true positive. Gate
  green. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-GEOINT sharpened: jurisdiction attribution moved from
  overlapping bounding boxes to a border-accurate partition.** The doctrine here
  is "measure, never guess" and determinism by construction; the old
  `au_state_for_coords` violated the first (a first-match scan of *overlapping*
  boxes is an arbitrary tie-break, not a measurement). Rebuilt it on Australia's
  real borders — the exact `129/138/141°E` meridians and `26°S` parallel, plus a
  piecewise-linear fit (`border_lat` over anchors tracing the actual line) for the
  QLD│NSW and NSW│VIC borders. The fit's anchors ARE the measurement (the Murray's
  real course, Point Danger, Cape Howe), and a 40-town fixture — including
  river-twin towns the fit splits correctly — is the validation. Pure,
  deterministic, no new deps, every existing caller strictly improved. S→P
  alternation: closes the highest-leverage geo-precision defect the audit found.
  Gate green. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-F1/single-source applied to IBAN validation: one
  validator, now length-accurate.** Two problems in one node — a precision gap
  (neither IBAN validator enforced the ISO 13616 registered length, so a
  checksum-lucky wrong-length string passed) and a drift risk (the logic was
  duplicated in `util::extract` and `oathnet_pro`). Both close together:
  `util::extract::iban_is_valid` becomes the single source (layout + registered
  length + mod-97), and `oathnet_pro` delegates. This is normalisation-defines-
  identity for a financial identifier — a valid IBAN is *exactly* a registered
  country code, its fixed length, and a passing checksum — expressed once. The
  unregistered-code fallback keeps the tightening zero-false-negative. Gate green.
  Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-BLOCKING/atomicity hardened: one durable, concurrency-safe
  atomic writer, and every sensitive write routed through it.** The doctrine's
  answer to torn/lost persisted state is a single hardened primitive
  (`util::atomic_file`): unique temp + fsync + rename. Two follow-ons close here.
  First, the primitive itself was missing the *parent-directory* fsync that makes
  the rename (not just the data) crash-durable — added best-effort. Second, the
  API-key vault had drifted into a hand-rolled fixed-temp copy that bypassed the
  primitive entirely (concurrency-corruptible); routed it back through
  `atomic_file::write`, so the most sensitive file gets uniqueness, mode 0600, the
  double fsync and single-sourcing at once. This is determinism/robustness by
  construction: a write either lands whole or not at all, under crash and under
  contention, expressed in one place. Validated by an eight-thread vault property
  test alongside `atomic_file`'s existing one. Gate green. Paired: `PROBLEM_TREE`
  §8 — same commit.
- **2026-07-04** — **SOL-ATTACK-INLINE broadened: full-registry mapping audit,
  catalogue gap closed.** Continuing the operator-endorsed "MITRE inline on the
  data" model (the separate report stays retired), audited all 160 modules'
  technique mappings and closed the two real gaps: added the missing **T1595.003
  Wordlist Scanning** technique (which `dns_intel`'s dictionary subdomain
  brute-force performs) to the catalogue and mapped it, and removed `opencellid`'s
  incorrect DNS/Passive-DNS tag (it queries a cell-tower database). Because the
  inline per-finding tag *is* the deliverable, the precision of the module→technique
  map is the precision of the product; guard-pinning both corrections keeps them
  from regressing to the category default. This is P→S/S→P alternation on the
  taxonomy itself — the mapping now matches what every module actually does, and
  the catalogue-drift guard proves no technique is dead or out-of-register. Gate
  green. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-AUDIT-CADENCE at scale + bound-everything applied to the
  cache.** A 6-subsystem parallel audit ("repair every element") confirmed the
  architecture is largely sound and surfaced ~20 real defects, now being repaired
  as gated cycles. First: the "bound everything, cap+chunk" doctrine had one
  unbounded store — `raw_archive` — which grew forever (expired rows ignored, not
  deleted; no cap). Closed with `prune_raw_archive` mirroring the `events` prune
  it should always have paralleled, at the same lifecycle points. The cache stays
  best-effort so the cap can never cost correctness, only a re-query. Determinism/
  crash-safety of the storage layer were re-verified sound in the same pass. Gate
  green. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-CSRF universalised: one guard covers every mutating
  endpoint, not just import.** The serve layer already had the right primitive
  (`scans/import`'s `X-HSE-CSRF` requirement — the header a cross-site simple
  request can't set without a preflight the strict CORS rejects) but applied it to
  a single handler. Lifted it into an `enforce_csrf` middleware on the whole `/api`
  router so the control is uniform and future-proof (a new mutating handler is
  covered automatically), with a global SPA `fetch` wrapper so same-origin calls
  keep working transparently. This is defence-by-construction: the guard can't be
  forgotten. Same cycle also gated the debug-log endpoint to loopback (matching its
  peer operator endpoints) and made the autonomous-sweep de-dup actually de-dup (on
  target identity, not the unique-per-call scan id). Web layer otherwise
  re-verified sound (SQLi/XSS/panics/determinism all clean). Gate green. Paired:
  `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-NOFAB extended: three more breach/stealer pools now prove
  the subject before asserting exposure.** The doctrine "a finding must identify the
  subject before it rides at full confidence" (already enforced by the shared
  `util::target_match::TargetMatch` quarantine and `oathnet_pro`'s
  `breach_parent_entity` zero-match gate) was missing from three pools. **DeHashed**
  now mirrors `breach_parent_entity` exactly — `build_breach_entity` returns
  `Option`, gating the loose `name:` headline on a real per-row match and keeping
  the identity-exact selectors' server total; **IntelX** got a new pure
  `exposure_tags` that withholds `breach`/`password-at-risk`/`paste-exposed` for the
  unscoped `text` searches (username/full-name) that can't validate the match,
  emitting neutral provenance and a lead-tier 0.55 entity instead; **HudsonRock**
  got a pure `victim_ip_entities` gating each victim IP on `is_public_ip` (the same
  gate `dehashed`'s record IPs use) so a LAN/reserved address never becomes a GEOINT
  `geolocation-lead`. Each fix is a *pure, unit-tested* helper (not buried in a
  network path), so the gate is provable fail-before/pass-after. Precision over
  coverage: a phantom breach headline, a stranger's paste tagged as the subject's
  leaked password, or a nowhere-geolocating private IP are exactly the fabricated
  findings an evidentiary product must never emit. Gate green. Paired:
  `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-ENGINE-ROBUST: the finalise/dispatch flow now fails safe
  in two more places.** Both fixes make a scan degrade gracefully rather than lose
  work. **Panic containment parity:** the live incremental correlation pass already
  guards `correlate_entities` with `catch_unwind`; the finalise-time `Correlator::run`
  did not, so a rule panicking on crafted persisted data would unwind the whole
  finalise block — losing `ScanComplete` and the harvested key pool. Lifted the
  guard into a pure `guarded_finalise_correlation` returning `Option` (`None` on
  error/panic → skip emission, still finalise). **Breaker honesty:** the circuit
  breaker exists to stop re-dispatching a genuinely-failing provider; feeding it a
  `record_success` for an inter-scan cache *replay* (no call was made) let a replay
  clear a real failure streak and keep a dead source in rotation. A `from_cache`
  flag now makes replays invisible to the breaker (neither success nor failure).
  Both are backed by *testable seams* — a panicking closure and a direct
  `finalise_module_result` drive — so the regression is provable, not just
  asserted in prose. Gate green. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-EXPORT-COMPLETE: the operator-facing exports no longer
  omit data or corrupt on a metachar.** Two export fixes. **Dossier completeness:**
  the human-readable `--output dossier` iterated a fixed kind allowlist and dropped
  every unlisted kind (`cidr`/`ssid`/`tracking_id`/`crypto_address` + all
  `other:*`), so a leaked crypto wallet or captured SSID never reached the analyst.
  A pure `order_dossier_kinds` renders the curated kinds first then a
  deterministic catch-all over the rest — the same "no silent drop" discipline the
  JSON/CSV/GEXF exports already have, brought to the dossier. **GEXF robustness:**
  the node `kind` attvalue and the `<description>` scan id were the last two
  unescaped sinks in an otherwise-escaped serializer; an `Other(<custom>)` kind
  with `<`/`&`/`"` would make the whole `.gexf` unparseable in Gephi. Routed both
  through `xml_escape`. Both fixes have pure/golden-backed tests
  (`order_dossier_kinds` unit test; the GEXF golden byte-stable test proves
  metachar-free output is untouched). Gate green. Paired: `PROBLEM_TREE` §8 —
  same commit.
- **2026-07-04** — **SOL-DETERMINISM + SOL-BREAKER-PROBE: a stable JARM and a
  one-at-a-time recovery probe.** Two correctness fixes. **Determinism:** Netlas
  chose the emitted JARM fingerprint from a `HashSet` (`.iter().next()`), whose
  order is process-randomised — so identical inputs produced different output. A
  `BTreeSet` makes the choice the smallest fingerprint, restoring byte-identical
  output (the guarantee the whole export/dossier layer depends on). **Breaker
  probe:** `util::circuit_breaker`'s `HalfOpen` admitted every concurrent caller,
  turning the one intended recovery probe into a herd against a still-down host;
  `HalfOpen` now admits exactly one probe and denies the rest, with `retry_at`
  re-used as a self-healing probe deadline so a lost outcome can't wedge the
  breaker. Both are pure, deterministic state machines with direct unit tests. Gate
  green. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-SNIPPET-CAP: the response-snippet readers bound memory at
  the chunk boundary, not after.** `error_snippet`/`read_body_capped` copied a
  whole streamed chunk into the buffer and truncated afterwards, so a single huge
  chunk defeated the cap before it applied. A shared pure `append_capped` copies
  only the bytes that fit under the cap — the ceiling now holds for any chunk size,
  and the logic is single-sourced (and unit-tested) rather than duplicated in two
  readers. Small, defence-in-depth hardening of an on-device tool's exposure to a
  hostile upstream. Gate green. Paired: `PROBLEM_TREE` §8 — same commit. This
  concludes the comprehensive-audit backlog (7 cycles, 12 repairs); remaining
  register items are LOW-priority / deliberately deferred.
- **2026-07-04** — **SOL-PAIRSWEEP-CAP: the finalise pairwise-pathway sweeps are
  bounded, found by real live testing.** End-to-end validation with a real seed of
  every target kind proved the engine robust (all 19 kinds run, zero panics, every
  error environmental) but exposed one real flaw: a `full_name` scan's finalise ran
  135–185 s because AU-062 (`multipath_corroborated_links`) and AU-063
  (`single_route_identity_links`) each swept `O(identities²)` pairs through
  `disjoint_pathways_in`, ~45 s apiece on the hundreds of name-permutation
  identities a broad name scan derives. A single shared `IDENTITY_PAIR_PROBE_CAP`
  (in `core::relation::graph`, the home of the pairwise primitive) now bounds both:
  a deterministic sorted-prefix cap that preserves byte-identical output while
  cutting the combined phase 48 s → 8 s (measured on the real scan). The bound lives
  in ONE place so the two sweeps that share the primitive can never disagree —
  the same single-sourcing discipline (`one finder, no drift`) the rules already
  follow for their detectors. Testable `*_capped` seams on both. Gate green.
  Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-LIVE-MODULES: three modules restored by real live testing.**
  End-to-end validation with real seeds is the only test that exercises a live
  upstream, and it caught three faults the whole unit suite missed: **HudsonRock**
  (param `username`→`email` drift, source fully dead → 400 "Email is required"),
  **StackOverflow** (hard-coded `filter=` now invalid → 400, every lookup broken),
  and **Bluesky** (a not-found handle returns 400, not 404, so the module errored
  and tripped its own engine breaker, suppressing the source for real handles). The
  first two are one-line URL corrections behind new testable helpers
  (`search_by_login_url`, `users_by_name_url`) that pin OUR contract so a future
  refactor can't silently reintroduce the stale param/filter; the third generalised
  `fetch_json_inner` to an `absent_statuses` set and added
  `fetch_json_or_absent` (400+404 → clean negative), a reusable primitive for the
  several APIs that signal "not found" with a 400. The lesson logged: **live
  end-to-end runs are a first-class part of validation** — upstream drift is only
  ever visible against the real service. All three re-verified live. Gate green.
  Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **Tree reconciliation: `PROBLEM_TREE` §7 S2 marker `[ ]`→`[x]`.**
  SOL-SSRF-WHOIS has been `[x]` here (and §4a has excluded S2) since its 2026-06-17
  delivery, but the paired `PROBLEM_TREE` S2 node kept its stale `[ ]` — a P1 HIGH
  reading as open work when its fix (`client::resolve_public_whois`, pinned public
  `:43` resolution + the `blocks_ssrf_and_non_whois_referrals` test) is present and
  passing. Verified the fix in code (not by trusting the node's own "✅ Fixed"
  claim), incl. the IPv4-mapped-IPv6 bypass case (`is_private_addr` canonicalises
  first). No code change — this cycle only reconciles the marker so the trees agree
  on what's done. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-CORR-NAMEDISCOUNT: AU-081 canonical-name match now
  discounts common names, mirroring the kin rules.** The free offline
  identity-bridge rule merged two independently-sourced `Person` records that
  normalise to one canonical name at `Severity::High` "same individual"
  unconditionally — the one identity rule with no commonness discount, so two
  unrelated "John Smith"s (breach + proxycurl, different families → past the
  independence gate) fused into one asserted person, cross-contaminating two
  strangers' evidence. The single highest-volume false-merge vector in person
  OSINT, and the exact failure the AU-051/AU-061/`derive_kinship` discount
  already guards against for shared surnames. Applied the same `is_common`
  discount at AU-081's emit site: a canonical name containing a common family
  token drops to `Severity::Medium` "a lead to VERIFY, not a confirmed merge";
  a distinctive name keeps its High "same individual" bridge. The overclaiming
  docstring (which falsely credited the token-count floor with excluding common
  first names) was corrected to describe the real gate. One place, mirroring an
  established pattern — no new vocabulary, no drift. Test:
  `au081_common_name_is_a_medium_lead_not_a_high_assert`. Gate green. Paired:
  `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-EMAIL-TLD-3RDCOPY: the `web_crawler` page email
  byte-scanner now shares the canonical alpha-TLD gate.** `host_has_alpha_tld`
  was single-sourced (2026-07-04) so the non-regex email admission paths could
  not out-admit `EMAIL_RE`, but a third copy of the byte-scan logic —
  `web_crawler::crawl_util::extract_emails` — was overlooked and still used the
  weak `contains('.') && len > 3` heuristic, admitting IP-literal
  (`admin@10.0.0.1`), numeric-TLD (`user@host.123`) and 1-char-TLD
  (`user@host.c`) hosts as bogus `Email` entities. Made `host_has_alpha_tld`
  `pub` (module→util is a permitted dependency) and routed the crawler scanner
  through it, keeping its existing `validate_email_syntax` dot-artifact check so
  the combined gate is the strictest of the three; the helper's docstring now
  enumerates all three consumers. A garbage email at the parse layer compounds
  through every downstream correlation (permutations, co-location/reuse rules,
  the exposure index), so closing the last permissive copy is the same
  "one gate, no drift" discipline as the original single-sourcing. Test:
  `email_extraction_rejects_ip_literal_and_numeric_or_short_tld_hosts`. Gate
  green. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-MITRE-USERNAMESEARCH: `username_search` no longer
  over-claims ATT&CK T1589.003 (Employee Names).** Per-finding `attack:<ID>` tags
  are HSE's only MITRE surface, so the module→technique map's precision is the
  product's ATT&CK fidelity. The guard-encoded convention is exact — a module
  claims T1589.003 iff it emits a real-name `Person` — and the prior override pass
  dropped it from github_user/hacker_news/lobsters/nostr/reddit_user for that
  reason, but missed `username_search`, which enumerates handle presence across
  300+ sites and emits only `Url` + `Username` (never a `Person`). It inherited
  the raw `Social` default `["T1593.001", "T1589.003"]`, so every finding falsely
  claimed HSE had gathered the subject's name. Added the precise override
  `["T1593.001"]` (Social Media search only — no bio-email path, unlike
  reddit_user) and pinned it in the `attack_overrides_..._precisely` guard,
  forbidding a regression to the default. Five further un-overridden name-less
  Social modules (discord_snowflake, fediverse, gaming_profile, streaming_probe,
  structured_id) are noted as a discrete follow-up — each emits no `Person` but
  carries its own technique nuance, so each needs an individual judgement rather
  than a blanket sweep. Test: `attack_overrides_attribute_collection_modules_precisely`
  extended. Gate green. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-GEOINT-PERPOINTCLASS (C5): AU-059's class-diversity
  weight is now per-point, not a global no-op.** `au059_synergy_fix` — the source
  of the dossier's headline "best AU location" and the API's `best_location`
  fields — boosted each coordinate's weight by a `class_bonus` derived from the
  scan-wide distinct-class count, applied identically to every point. A weighted
  geometric median is invariant to scaling all weights by one positive constant,
  so the bonus moved the fix not at all, despite its comment promising "a point
  corroborated across more orthogonal classes pulls proportionally more." The
  bonus is now computed per point from that entity's OWN distinct anchoring geo
  classes (`corroborating_sources` → `geo_source_class`), so a coordinate
  confirmed by several independent collection methods genuinely outweighs a
  single-class sighting and pulls the median toward it. Deterministic; the
  existing outlier-robustness test (single-class points) is unaffected. Test:
  `au059_class_diversity_bonus_is_per_point_not_a_global_no_op` — two scans
  differing only in the eastern point's class span, byte-identical under the old
  global scalar and strictly divergent under the per-point bonus. Gate green.
  Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-GEOINT-INFRAGUARD (H5): `coord_state` + AU-099 now apply
  the `is_infrastructure_geo` guard every sibling location rule uses.** An
  adversarially-verified precision-discovery workflow (8 finders, refute-by-default
  verification, 14 confirmed defects) top-ranked this: the two geo rules that vote
  the subject's location — `coord_state` (feeds AU-056/085/092/098) and
  `rule_au_099_coordinate_reverse_geocode` — gated only on `kind == Coordinates &&
  confidence ≥ 0.50`, omitting the infrastructure-geo exclusion that AU-018/026/030
  and AU-052/053/059 all apply and that the file's own H5 doctrine section mandates.
  A bare `ip_geo` datacentre coordinate therefore voted the subject's jurisdiction
  (a false AU-056 conflict against a real interstate address) and was announced by
  AU-099 as the subject's own fix. Added the one guard to both. Seven existing
  AU-056/085/092/098/099 fixtures that used a placeholder non-anchoring source for a
  real subject coordinate were reconciled in the same commit to carry a genuine
  anchoring source, so only pure infrastructure coordinates are newly excluded.
  Tests: `coord_state_excludes_bare_ip_geo_infrastructure_coordinate`,
  `au099_reverse_geocode_excludes_infrastructure_coordinates`. Gate green. Paired:
  `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-GEXF-CANDIDATE-INTEGRITY: the GEXF export no longer leaks
  candidate PII (API) or emits dangling edges (any caller).** Two coupled
  workflow-confirmed defects fixed as one. The web `/graph.gexf` handler passed the
  full entity set unfiltered, leaking quarantined `candidate` breach-victims as nodes
  — unlike the CSV/report/CLI exports that strip them by default. And `render_gexf`
  dropped candidate NODES but passed the full RELATION set, so a relation to a
  filtered node produced an `<edge>` referencing an undeclared node (invalid GEXF).
  Filtering candidates in the API path without addressing the second bug would have
  reproduced it there, so both were fixed at their correct layers: `entities_to_gexf`
  now emits a relation edge only when both endpoints are declared nodes (a serializer
  invariant that protects every caller), and `scan_export_gexf` filters candidates by
  default with a `?include_candidates=1` opt-in matching the CSV endpoint. The GEXF
  golden byte-stable test is unaffected. Tests:
  `gexf_drops_relation_edges_referencing_a_filtered_out_node`,
  `scan_gexf_quarantines_candidate_nodes_by_default`. Gate green. Paired:
  `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-STREAMPROBE-TIER: `streaming_probe` confidence is tiered by
  detection rigour and its sensitive exposure claims are gated on verified hits.** The
  cam/fans/adult platform prober stamped a flat 0.92 on every hit and asserted
  `cam-identity-exposed` on any hit — but 41 of 43 platforms detect on a bare
  status-200 (`Detect::StatusEq`), which a soft-404 / interstitial / catch-all route
  fakes, so one unverified probe fabricated a high-confidence, reputationally-sensitive
  identity claim. Mirrored the sibling `username_search` fix: a pure
  `detection_strength` returns `(0.92, true)` for a body-verified hit and `(0.74,
  false)` for a status-only one; each `Url` carries its tiered confidence plus a
  `verified-detection` / `weak-detection` tag; the strong exposure tags fire only on a
  body-verified hit in the category (weak-only categories still surface their 0.74
  URLs); the summary records `hits_verified` / `hits_status_only`. Emit logic extracted
  to a pure, testable `build_entities`. Tests:
  `detection_strength_tiers_status_only_below_body_verified`,
  `build_entities_tiers_confidence_and_gates_exposure_on_verified`. Gate green. Paired:
  `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-AU046-OWNACCOUNT: AU-046 resolves an alias only to its own
  account's identifiers, not every platform-sourced Email/Person in the scan.** The
  cross-platform identity-resolution rule built one scan-wide `resolved` set and
  attributed all of it, at High, to every alias — fusing a co-author's email, another
  alias's identifiers, or a role mailbox into a person's identity (a false merge, the
  worst class), despite the docstring claiming it couldn't. Now each identifier
  resolves to a given alias only when it shares ≥1 concrete corroborating SOURCE with
  that alias (the alias's own account surfaced it), and role mailboxes are excluded via
  `core::validation::is_role_mailbox` (the AU-045 gate). `resolved` is per-alias, so
  cross-alias contamination is impossible and an alias with no own-account identifier
  no longer fires. Docstring corrected. Test:
  `au046_resolves_only_the_alias_own_account_identifiers` (own-account email resolves;
  an unshared-source stranger and a `noreply@` role mailbox excluded). Gate green.
  Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-AU042-KEYPARTITION: AU-042 partitions pgp-linked emails by
  key fingerprint and requires two per key.** The rule fused ALL `pgp-linked` emails
  scan-wide into one High "one owner" finding and fired on a single address —
  merging emails from two distinct PGP keys (two potentially-different people) and
  emitting a degenerate one-address "identity link." The `pgp` module already stamps
  each pgp-linked email with a `key_fingerprint` evidence attribute; the rule now
  groups on it (deterministic BTreeMap fingerprint→address→uid), emits one finding
  per key binding ≥2 distinct addresses, and names the fingerprint. An email carrying
  several fingerprints belongs to each key; an email with none is excluded. Tests:
  `au042_does_not_fuse_emails_from_two_distinct_keys`,
  `au042_does_not_fire_for_a_single_pgp_linked_email`; the existing group test now
  attaches the fingerprint a real hit carries. Gate green. Paired: `PROBLEM_TREE` §8 —
  same commit.
- **2026-07-04** — **SOL-MITRE-SOCIAL5: the five name-less Social modules get precise
  ATT&CK overrides instead of the inherited T1589.003 (Employee Names).** Closes the
  follow-up from SOL-MITRE-USERNAMESEARCH. `streaming_probe`, `gaming_profile`,
  `discord_snowflake`, `structured_id`, `fediverse` were all `ModuleCategory::Social`
  with no override, inheriting `["T1593.001", "T1589.003"]`, but none emits a `Person`
  — so every finding falsely claimed a gathered name. Mapped each to its real
  collection: the three handle/platform modules → `["T1593.001"]`; `fediverse` →
  `["T1589.002", "T1593.001"]` (profile emails, like nostr); `structured_id` →
  `["T1592.001"]` (host Hardware — the UUIDv1 node MAC — it decodes IDs offline, it is
  not a social search, so both social techniques drop). Pinned in the
  `attack_overrides_..._precisely` guard. `username_variants` deliberately keeps
  T1589.003 and is untouched. Gate green. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-SEEKNOW-URLGATE: the SeekNow stealer URL admission gate now
  matches its oathnet_pro twin.** `see_know::extract` minted the stealer `url`/`url_str`
  field as a `Url` on a bare `len >= 4` — no scheme, no host — while the sibling
  `oathnet_pro::stealer`, whose model see_know's own comment claims to mirror, gates the
  identical field on `starts_with("http") && contains('.')`. So a native-app URI, a
  scheme-less fragment, or a sentinel ≥4 chars became a bogus `Url` node (which then
  misdirects crawl/DNS/cert expansion of a login surface) that oathnet_pro rejects.
  Applied the twin's gate (trim + scheme + dotted host), single-sourcing the admission
  rule; the paired `<username>@<url>` Credential stays ungated, as in oathnet_pro (a
  login for a native surface is still real). Test:
  `extract_entities_rejects_non_web_stealer_url_but_keeps_the_credential`. Gate green.
  Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-HISTORY-TOKENMATCH: the cross-scan-history idempotency probes
  match the delimited partner token, not a bare substring.** `endpoint_has_cooccurrence`
  and `endpoint_has_relation_recall` keyed idempotency on `summary.contains(partner)`
  (and `contains(kind)`) — unanchored substrings — while the summaries write the partner
  backtick-delimited and the kind paren-delimited. So an entity already linked to
  `` `alice2` `` was reported as already carrying a NEW link to `alice` (a substring), so
  the linker skipped attaching the genuine `alice` association — a real cross-scan link
  silently lost whenever one partner/kind is a substring of another (numbered handles,
  `bob`/`bob2`). Fixed both to match the delimited token (`` `{partner}` ``, `({kind})`).
  Test: `idempotency_probes_match_the_delimited_partner_token_not_a_substring`. Gate
  green. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-EMAIL-PERCENT: the email byte-scanners accept `%` in the local
  part, matching `EMAIL_RE`.** `util::extract::is_email_local_byte` (used by
  `page_emails`) and the `web_crawler::crawl_util::is_email_char` twin omitted `%`,
  truncating a `%`-containing mailbox (`with%percent@x` → `percent@x`) the canonical
  regex accepts whole. Added `%` to both. Tests:
  `page_emails_keeps_a_percent_in_the_local_part`,
  `email_extraction_keeps_a_percent_in_the_local_part`. Gate green. Paired:
  `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-E164-61TRUNK: `to_e164_au`'s bare-`61` branch applies the same
  ACMA trunk-digit gate as its AU-local sibling.** The local branch requires a real AU
  lead (2/3/4/5/7/8) to stop a foreign 10-digit number being re-typed as `+61…`, but the
  `61`+9-digit branch only excluded a leading `0`, so a foreign national number with lead
  1/6/9 (a French mobile `0612345678` → `61612345678`) was fabricated into a `+61` number.
  Applied the same trunk-digit gate to the `61` branch, single-sourcing the AU-lead rule.
  Test: `bare_61_prefix_requires_a_real_au_trunk_digit`. Gate green. Paired:
  `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-DEHASHED-PWEMAIL: DeHashed recovers an email mis-stored in the
  password slot instead of dropping it.** The password loop only had a `Secret` arm, so
  a value the shared classifier flags as `CredentialField::Email` (a common breach quirk)
  minted nothing — while `oathnet_pro` and `see_know` both recover it as an `Email` at
  0.45 tagged `recovered-from-password` (minting it as a Password would forge a
  reused-secret link). Converted the loop to the same three-arm match (Sentinel / Email /
  Secret), single-sourcing the policy across the three breach parsers. Test:
  `email_in_the_password_slot_is_recovered_as_an_email_lead`. Gate green. Paired:
  `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-FIDELITY-REGISTERS: acma_rrl + ahpra emit every parsed row, not
  the first 20.** A fidelity-audit workflow (silent-truncation / dropped-field finders,
  adversarially verified; 8 confirmed violations) top-ranked the two AU register
  scrapers: both parse the full result table into an unbounded Vec then emit only
  `.iter().take(20)` — a bare, unlogged client-side cut with no server-side page param,
  silently dropping licensees/practitioners 21..N (each carrying its licence/registration
  number). The real bound (`read_body_capped` 512 KB) already limits parsed size. Fix
  extracts the emit into pure `build_licensee_entities` / `build_practitioner_entities`
  that emit EVERY row; `process` extends the result with them. Tests:
  `build_licensee_entities_emits_every_parsed_row_not_just_20`,
  `build_practitioner_entities_emits_every_parsed_row_not_just_20`. Directly serves the
  operator's re-issued full-fidelity directive. Gate green. Paired: `PROBLEM_TREE` §8 —
  same commit.
- **2026-07-04** — **SOL-FIDELITY-NETLAS: netlas emits every unique SAN domain and
  extracted email.** The pure `build_entities` aggregated+deduped all cert SAN domains
  and all cert/http/whois emails, then cut them with a bare `.take(20)` / `.take(10)` —
  no constant, comment, log, or count attribute — silently dropping the module's own
  headline BFS pivots (a multi-SAN cert lists 50-100+ domains; a busy host exposes many
  contacts). The BFS frontier budget is the engine's, not this leaf module's, so the
  caps had no resource justification. Removed both. Test:
  `build_entities_emits_every_unique_san_domain_and_email`. Gate green. Paired:
  `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-FIDELITY-ULPLOGIN: the niamonx ULP login is recovered on every
  target kind.** `emit_ulp` promoted the stealer-log `login` to a pivot only for
  Email/Domain targets and never stamped it on evidence, so on Username/IpAddress scans a
  genuinely-new identity (a username's mapped email, a victim host's compromised accounts)
  was dropped entirely. The `differs` guard already suppresses the redundant query value,
  so the target-kind gate was pure loss. Now always stamp `login` on the record evidence
  and promote it to a pivot on every kind when it differs (removed the `useful` gate + the
  now-unused `target_kind` param). Test: `ulp_recovers_the_login_on_username_and_ip_scans`.
  Gate green. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-FIDELITY-FILTERLIMIT: `entities_filtered` returns the complete
  result, not a capped 500.** The filtered-entity storage query hardcoded `LIMIT 500` with
  no pagination/total/flag, silently dropping the lowest-confidence matches past rank 500
  — while the canonical `entities_for_scan` it subsets is unbounded and the facets endpoint
  reported the true larger count (an observable inconsistency). Removed the LIMIT; the
  `confidence DESC, uid ASC` order is already total/deterministic. Test:
  `entities_filtered_returns_the_complete_result_not_a_capped_500`. Gate green. Paired:
  `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-FIDELITY-SEONNAMES: SEON emits a Person for each distinct
  reported name.** `build_email_entities` minted one Person from the first platform with a
  valid name (a `find_map`), silently dropping the distinct name variants other identity
  platforms reported (a nickname on one, a full legal name on another). Now emits one
  Person per DISTINCT name (deterministic BTreeMap by lowercased value), tagged with all
  reporting platforms; identical names dedup to one Person carrying every platform tag.
  Test: `email_emits_a_person_for_each_distinct_reported_name`. Gate green. Paired:
  `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-FIDELITY-HANDLES: AU-049/AU-050 reference every reachable handle,
  not a capped 8.** `Group::firing_uids()` did `handle_set.iter().take(8)`, silently
  dropping email/phone handle uids 9+ from the correlation's `entity_uids` on a large
  household/shared-line cluster — a bound a refactor preserved, not a deliberate cap (the
  sibling AU-051 has none). Emit every handle uid (BTreeSet keeps them sorted). Test:
  `au049_references_every_reachable_handle_not_a_capped_eight`. Closes the fidelity-audit
  arc (7 confirmed violations fixed). Gate green. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-FIDELITY-SSHKEYS: `github_user` emits every published SSH public
  key, not a capped 10.** A direct post-audit grep sweep of the surviving `.take(N)` sites
  found `fetch_ssh_keys` emitting the subject's own SSH public keys as fingerprinted
  `Credential` artifacts through `keys.iter().take(10)` — silently dropping keys 11+, each of
  which is an independent AU-048 cross-account cryptographic pivot (the module's strongest
  link). Extracted the `SshKey` row to module scope and a pure `ssh_key_entities()` that
  emits every parsed key (malformed bodies still dropped by fingerprinting → represented by
  omission, not a placeholder); the display evidence's JUSTIFIED five-key sample with true
  `ssh_key_count` is untouched. Test: `ssh_key_entities_emits_every_key_not_a_capped_ten`
  (15 keys → 15 distinct Credential uids; fail-before: 10). Gate green (4563). Paired:
  `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-FIDELITY-COMMITEMAIL: `github_user` emits every distinct
  commit-author email, not a capped 10.** Sibling of SOL-FIDELITY-SSHKEYS in the same
  module. `fetch_events` deduped the commit-author emails from the subject's public push
  events then emitted `.take(10)` — a silent bound the comment admits is only "to keep a
  busy account bounded," with no resource justification (the endpoint is already capped to
  30 events) and no co-author discrimination (so not a precision gate, contra my prior-cycle
  deferral). Moved the `GhEvent` struct family to module scope and extracted a pure
  `commit_email_entities()` that emits every distinct usable address (noreply/placeholder
  forms still dropped by `usable_commit_email`; first-seen order over the newest-first
  stream is deterministic). Provenance-honest evidence ("from @login's commit author field")
  means full emission adds fidelity without over-attributing; any true co-author concern is
  a separate author-matches-login precision filter, not this cap. Test:
  `commit_email_entities_emits_every_distinct_email_not_a_capped_ten` (15 events → 15 pivots;
  fail-before: 10). Gate green (4564). Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-04** — **SOL-FIDELITY-BIOLINKS: five social modules emit every bio email/URL, not
  a capped 5, via a single-sourced `extract::urls()`.** `bluesky_user`, `reddit_user`,
  `mastodon_user`, `lobsters`, `devto` each carried the identical `emails(bio).take(5)` +
  `URL_RE.find_iter(bio)…dedup.take(5)` block, silently dropping bio emails/links 6+ — a
  copy-paste artifact (the same codebase extracts gist/page emails uncapped, and reddit's own
  comment says "extract ALL"). Added a tested `util::extract::urls()` mirroring `emails()`
  (trim + dedup + first-occurrence order, no cap), routed all five modules through
  `emails()`/`urls()` uncapped, and deleted the ten `.take(5)` sites plus redundant
  per-module dedup loops and three unused `URL_RE` imports. Test:
  `urls_extracts_all_distinct_trimmed_in_order_uncapped` (six distinct URLs → all six,
  trimmed/deduped/ordered; fail-before: five). Gate green (4565). Paired: `PROBLEM_TREE` §8 —
  same commit.
- **2026-07-05** — **SOL-STORAGE-DIAG: every multi-row storage read now logs, not just
  drops, a corrupt row.** A fresh code-grounded discovery pass across the storage layer (the
  fidelity-audit arc having closed) found 8 multi-row readers in `storage/mod.rs` and
  `storage/entities.rs` (`list_scans`, `correlations_for_scan`, `relations_for_scan`,
  `events_for_scan`, `entities_for_scan`, `entities_filtered`, `search_entities`'s FTS and
  LIKE paths) chaining a bare `.filter_map(...ok())` at both the SQL-extraction and
  JSON-deserialize layers, silently vanishing a corrupted or schema-drifted row with zero
  trace — unlike the single-row getters (`get_scan`, `get_entity`), which already propagate
  the identical failure via `?`. Added two shared private helpers, `collect_rows` and
  `deserialize_rows`, each `tracing::warn!`-logging the caller's context and the underlying
  error before dropping the row; rewired all 8 call sites onto them. The
  drop-one-bad-row-keep-the-rest behaviour is unchanged (a corrupt row must not fail the
  whole page) — only the missing diagnostic is added, so the regression tests target the
  log itself: a scoped `tracing` subscriber (`VecWriter`, mirroring
  `core::engine::tests::module_dispatch_is_logged_...`) proves each helper both keeps the
  good rows and emits a context-keyed warning (fail-before: the pre-fix bare filter_map kept
  the rows but logged nothing), plus an end-to-end `list_scans` test proving a corrupt
  sibling row still doesn't fail the read. Test delta: +3
  (`deserialize_rows_drops_corrupt_json_but_logs_the_failure`,
  `collect_rows_drops_sql_errors_but_logs_the_failure`,
  `list_scans_drops_a_corrupt_row_end_to_end_without_erroring`). Gate green (4385 lib
  tests). Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-05** — **SOL-CHMOD-DIAG: the store's owner-only chmod now logs, not just
  swallows, a failure.** Second item from the same storage-layer discovery pass as
  SOL-STORAGE-DIAG: `Store::open`'s 0600-restriction loop over the db file plus its
  `-wal`/`-shm` siblings discarded the `Result` via `let _ = std::fs::set_permissions(...)`,
  unlike the FTS-rebuild best-effort step in the same function (explicitly best-effort AND
  never silent) and unlike SOL-STORAGE-DIAG's read-path fix just above. Since the store
  holds PII and harvested third-party keys, a failed chmod silently left it at the process
  umask (often 0644, world-readable) with zero signal. Extracted a private
  `restrict_to_owner_only(paths: &[String])` helper that logs a `tracing::warn!` keyed by
  the failing path on each failure; startup is still never blocked by a chmod failure, only
  made loud. Test: `restrict_to_owner_only_logs_when_a_chmod_fails` (unix-only; a chmod on a
  nonexistent path reliably fails without a read-only-filesystem fixture; fail-before: the
  pre-fix `let _ = ...` produced no log at all). Gate green (4386 lib tests). **This closes
  the storage-layer discovery-pass arc** (SOL-STORAGE-DIAG + SOL-CHMOD-DIAG); the pass's
  remaining item (no migration-application mechanism behind `SCHEMA_VERSION`) is already
  T2.10's own stated P3/advisory residual, not a new gap. Paired: `PROBLEM_TREE` §8 — same
  commit.
- **2026-07-05** — **SOL-LATEST-SCAN-ERR: `latest_completed_scan` now propagates a corrupt
  row as `Err`, correcting the prior entry's "arc closed" claim.** A direct follow-up grep
  sweep of `storage/mod.rs` (prompted by checking on a background "fourth discovery pass:
  storage layer" agent whose task ID turned out unresolvable in this session) found one more
  instance of the same silent-swallow shape, and unlike SOL-STORAGE-DIAG/SOL-CHMOD-DIAG this
  one is a genuine wrong-result bug, not just a missing log. `latest_completed_scan` did
  `stmt.query_row(...).ok()` then `.and_then(|s| serde_json::from_str(&s).ok())`, collapsing
  "no complete scan exists," "a genuine SQL error," and "the matched row's JSON is corrupt"
  into the identical `Ok(None)` — unlike the sibling `get_scan` two functions above it, which
  already propagates the same failure via `?`. `resolve_scan_id` (`cli/mod.rs`, backing `hse
  export/diff/audit latest` and the SPA's "open latest scan") turns that `None` into "no
  completed scans in store," so a corrupted MOST-RECENT complete scan was silently reported
  as an empty store rather than surfacing the corruption. Rewrote it to mirror `get_scan`'s
  `rows.next()?...transpose()?` / `.map_err(Into::into)` structure exactly. Test:
  `latest_completed_scan_errors_loudly_on_a_corrupt_row_instead_of_reporting_none` (a
  `status='complete'` row with syntactically-valid-but-`Scan`-incompatible `data_json` →
  `Err`, not `Ok(None)`; fail-before: confirmed `Ok(None)` against the unfixed code). Gate
  green (4387 lib tests). A second follow-up grep across `storage/*.rs` for the same
  `.ok())`/`let _ = ` silent-swallow shapes found nothing further outside test cleanup code —
  this now genuinely closes the storage-layer sweep. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-05** — **Cycle 27: SOL-CORR advances on C1's timeline-output remaining item —
  `TimelineEventKind::AccountCreated` is no longer dead code, and 7 other live date keys are
  no longer silently dropped from the timeline.** With the storage sweep closed, picked C1
  (`[~]`, in-progress) over the open T2.7/T2.14 nodes per the loop's own priority order.
  `core::timeline::classify` maps evidence-attribute keys to timeline event kinds; a direct
  grep of every `.with_attr(...)` call across `src/modules/` (not a speculative gap) found 8
  live keys it never matched: `account_created` (`oathnet_pro`, `stackoverflow_user`),
  `joined_at` (`devto`), `discord_created_date`/`discord_created_unix_ms`
  (`discord_snowflake`'s decoded snowflake timestamp), `uuid_created_date`
  (`structured_id`'s decoded UUIDv1 timestamp), `birth_date`/`death_date` (`wikidata`'s
  Wikidata-claim dates — a DIFFERENT spelling than the canonical `date_of_birth` other
  modules normalise to), `verified_at` (`mastodon_user`'s profile-field verification
  timestamp), and `first_pulse_created` (`ip_reputation`'s OTX pulse earliest-report date).
  The `account_created` family's absence meant `TimelineEventKind::AccountCreated` — defined,
  documented, with its own `as_str()` label — was completely unreachable: no key ever
  produced it. Verified each value's format is `parse_date`-compatible before mapping
  (`utc_date`'s `YYYY-MM-DD`, raw ms-digit strings, ISO-8601 with fractional seconds) rather
  than assuming. Fix: widened `classify`'s match arms (account-creation family →
  `AccountCreated`; `birth_date` → `DateOfBirth`; `death_date`/`verified_at` → `Generic`;
  `first_pulse_created` → `FirstSeen`). Test: +3
  (`classify_maps_every_live_account_created_key_not_leaving_it_dead_code`,
  `classify_recognises_wikidata_and_mastodon_date_keys`,
  `reconstruct_surfaces_an_account_created_event_end_to_end` — fail-before: the end-to-end
  test showed 0 events instead of 1). Gate green (4390 lib tests). Also corrected a stale §4
  note ("C1/C2/C6/C7... none started") that had drifted since cycle 26 delivered
  `identity_paths`/CONNECTIONS. Investigation surfaced two genuine, deliberately-deferred
  follow-ons rather than scope-creeping them into this commit: (1) three independently-drifted
  DOB-key vocabularies (`breach_pii::DOB_KEYS`, `exposure::DOB_KEYS`,
  `timeline::classify`) — a real single-sourcing gap, but unifying them needs a design
  decision (the import-facing list may deliberately accept noisier spellings); (2) the
  "controller behind reused secrets" link facet needs a new `RelationKind` plus a visibility
  decision on the correlator's private `Secret` primitive — assessed and confirmed too large
  for one focused commit. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-05** — **SOL-EXPOSURE-DOB: the Exposure Index recognises Wikidata's own DOB
  spelling.** With C1's two remaining slices both genuinely too large/open-ended for one
  commit (an un-invented AU-0xx rule gap; the reused-secret `RelationKind` refactor),
  followed up on the previous cycle's own logged "three independently-drifted DOB-key
  vocabularies" observation instead — a concrete gap already surfaced by this project's own
  prior investigation, not a fresh speculative hunt. Confirmed by direct grep:
  `wikidata::builder` stamps a Person's DOB as `birth_date` (its own canonical spelling), but
  `core::exposure`'s `DOB_KEYS = ["date_of_birth", "dob"]` — whose own doc comment says it
  tracks "the canonical keys the breach/dossier producers stamp" — never matched it, so a
  Wikidata-sourced DOB silently scored 0 of the 7 points toward the Sensitive PII component,
  contradicting the constant's own documented intent. Also verified `GOV_ID_KEYS`/
  `FINANCIAL_KEYS` have no analogous gap (every raw provider spelling `oathnet_pro` sees
  already normalises to the canonical keys those lists expect). Fix: added `"birth_date"` to
  `DOB_KEYS`. New standalone node `T2.18` (not folded into C1 — the Exposure Index is a
  separate subsystem C1 doesn't cover). Test: `sensitive_pii_recognises_wikidata_birth_date_spelling`
  (a `birth_date`-only Person now scores 7/30; fail-before: confirmed 0/30 against the
  unfixed list). Gate green (4391 lib tests). The broader 3-way DOB-key unification (with
  `breach_pii::DOB_KEYS`'s import-facing 8-spelling list) remains correctly deferred as a
  real design decision. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-05** — **Cycle 28: SOL-CORR closes C1's "controller behind reused secrets"
  link facet — the design assessed and correctly deferred in cycle 27.** New
  `RelationKind::SharesSecretWith` — the graph-native counterpart of the AU-047
  (reused-secret) / AU-048 (shared key) / AU-106 (shared device) correlations, so
  `identity_paths`/CONNECTIONS can walk a proven shared-secret tie as a real edge
  instead of only reading it off a standalone correlation. Rather than duplicate the
  entropy/denylist precision logic those correlations already embody, widened the
  correlator's own `Secret`/`Secret::classify` (`core::correlator::rules::breach`) and
  `canonical_handle` (`core::correlator::rules::mod`) to `pub(in crate::core)`,
  re-exported from `correlator::mod` — mirroring the ALREADY-ESTABLISHED
  `gap_fill_probes`/`multipath_corroborated_links`/`source_family` pattern in the same
  file (found by inspection, not invented): Rule 4, one classifier/one folder, so the
  new edge and the correlations can never disagree on admission. New
  `core::relation::builders::derive_reused_secret_link`, wired into `derive_all`,
  reuses the existing `emit_pairwise` primitive to emit a full pairwise clique over
  every identity entity a qualifying secret's evidence names — a secret tying 3+
  accounts produces the complete clique, not a chain through one hub, so
  `identity_paths`' BFS finds the direct edge between any two of them. Updated the two
  exhaustive `RelationKind` matches in `core::network` (graph-view grouping; edge
  label) the new variant forced — clippy's own non-exhaustive-match error caught both,
  confirming no other match site needed updating. Test: +3
  (`derive_reused_secret_link_ties_two_accounts_sharing_a_salted_hash`,
  `derive_reused_secret_link_precision_gate_matches_au047_exactly`,
  `derive_reused_secret_link_emits_the_full_pairwise_clique` — fixtures mirror AU-047's
  own correlator test exactly; fail-before: 2 of 3 confirmed failing against a
  stubbed-empty function). Also ran `hse selftest` against the built binary (9/9 pass)
  per `docs/CONVENTIONS.md` §9. Gate green (4394 lib tests). **This closes C1's third
  and final remaining item** — (d) further AU-0xx rule-gap fill is C1's only open
  thread. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-05** — **Cycle 29: closed T2.11 — reconciled a stale cross-tree note, no
  code changed.** With no small, code-grounded gap left to point at for C1(d) and
  T2.7/T2.14 both blocked on design decisions, re-read this section's own
  SOL-BUDGET/SOL-ISOLATE/SOL-LIVE-DISPATCH-BUDGET entries (all three close a T2.11
  sub-item) closely and found a genuine drift: SOL-ISOLATE's entry (2026-06-17) and
  `PROBLEM_TREE` T2.11's own body both still described the "budget-static
  `reset_scan`-zeroing" as a pending follow-on, but SOL-BUDGET's own re-assessment
  the very next day (cycle 18, 2026-06-18) found that exact residual was a faulty
  premise (`reset_per_scan` already runs at every scan start) and accepted it `[-]`
  — no further action needed. Neither the T2.11 body nor SOL-ISOLATE's residual note
  was ever updated to reflect that, so both kept describing already-closed work as
  outstanding, an internal inconsistency within this very tree (SOL-BUDGET said
  "resolved," two sibling entries kept saying "pending"). Corrected SOL-ISOLATE's
  residual note to point at SOL-BUDGET's actual disposition, and flipped T2.11
  `[~]`→`[x]` in `PROBLEM_TREE` (all three of its real sub-items were long since
  `[x]`/✅; the one "residual" was independently resolved a day later by a sibling
  node — nothing left open). No code changed; full gate re-run to confirm the
  working tree is still green (unchanged from the prior commit, as expected).
  Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-05** — **Cycle 30: an honest, empty-handed AU-0xx rule-gap search for
  C1(d), plus a second stale-note fix (§4d's C5 line).** Cross-referenced every
  `EntityKind` variant against its usage inside `core::correlator::rules/`
  (recursively — an earlier non-recursive pass falsely flagged `TrackingId` as
  uncorrelated). `TrackingId` — refuted: `AU-044` already correlates it exactly
  as `web_crawler`'s own comment describes; verifying before building avoided
  shipping a duplicate rule. `Ssid` and `Cidr` both show genuinely zero
  correlator engagement, but neither is a mechanical slice: `Ssid` needs
  `cli/import::push_ssids` changed first to attribute each extracted SSID to
  its source record (currently a flat text scan, no per-account attribution);
  `Cidr` needs real CIDR-containment computation, a new capability. Both
  logged as scoped future candidates rather than pursued into the
  import/parsing layer this cycle. Separately, `§4d`'s C5 coverage-snapshot
  summary was found stale the same way T2.11's was last cycle — still saying
  "Weiszfeld/centroid fusion... remaining" a `PROBLEM_TREE`/SOL-GEOINT-confirmed
  4+ days after that work actually shipped (2026-07-01); corrected. No code
  changed this cycle. Gate re-run to confirm the working tree is unchanged and
  green. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-05** — **Cycle 31: SOL-FILTER-CANDIDATE-LEAK — `/entities/filter`
  no longer leaks quarantined candidates.** Cycle 30's direct C1(d) search came
  up empty for a mechanical slice, so rather than force a weak finding or run a
  third consecutive docs-only cycle, delegated a fresh discovery pass to a
  background agent (isolated worktree). It found a real, code-grounded gap:
  `scan_entities`/`scan_entities_csv`/`report.json`/GEXF all quarantine
  `candidate`-tagged entities by default via `wants_candidates()`, but
  `scan_entities_filter` never called it and `entities_filtered` has no
  tag-based filter of its own — a caller could bypass the quarantine every
  sibling endpoint enforces just by using the filter route. Same PII-leak
  shape as the GEXF candidate-node leak (2026-07-04), a different endpoint
  that fix never touched. Verified independently before writing any code:
  read all four call sites, confirmed no downstream layer re-applies the
  filter, confirmed via `git log -S"wants_candidates"` this route predates the
  quarantine mechanism (v1.0.0) and was simply never retrofitted, confirmed
  the existing `scan_entities_filter_returns_entities` test seeds no candidate
  entity so never exercised this path. Fix mirrors `scan_entities` exactly.
  Test: `scan_entities_filter_quarantines_candidate_entities_by_default`
  (`tests/api.rs`) — confirmed fail-before (reverted the fix in-place, test
  failed against the unfixed handler; restored from a diff-verified post-fix
  backup, test passed). *Closes:* new node **T2.20**. Gate green: fmt/clippy/
  doc clean, full suite 0 failures. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-05** — **Cycle 32: SOL-UPDATE-GIT-FIXTURE — closed the
  `cli::update` git-fixture test gap `SOL-UPDATE`'s own 2026-07-01
  correction explicitly deferred.** With T2.20 just closed, re-scanned §4a
  for the next already-scoped coverage gap rather than run another discovery
  pass — `changelog_lines`/`commits_behind` were untested against real `git`
  subprocess behaviour, confirmed by reading `cli/update.rs`'s test module
  directly (every existing test targets pure logic; none constructs a real
  repo). Built a local origin+clone fixture pair (`tempfile`, no network)
  proving both functions' actual ahead/behind counting and changelog
  formatting against genuine `git fetch`/`rev-list`/`log` output. The test's
  own first draft assumed a second `commits_behind` call would report 0
  behind after a mere fetch — wrong: the function only ever fetches, never
  advances local `HEAD`, so it correctly still reported the same count;
  corrected the test to `git merge --ff-only @{u}` between checks (mirroring
  what `install.sh`'s real `git pull` does) before asserting the caught-up
  state. Also covers the no-configured-upstream case. Since the functions
  were already correct — only untested — adapted the fail-before proof:
  temporarily reversed the `rev-list` range to `@{u}..HEAD`, confirmed the
  new fixture test failed, restored the original from a diff-verified
  backup. *Closes:* new node **T2.21**. Tests:
  `commits_behind_and_changelog_lines_reflect_real_git_state`,
  `commits_behind_returns_none_without_a_configured_upstream`. Gate green:
  fmt/clippy/doc clean, full suite 0 failures (4396 lib tests). Paired:
  `PROBLEM_TREE` §8 — same commit.
- **2026-07-05** — **Cycle 33: SOL-GREYNOISE-KEYED — the `greynoise` module
  now uses the operator's configured key instead of silently ignoring it.**
  An operator-requested audit of every currently-configured `HUNTSMAN_*`
  key's wiring — independent of the earlier background-agent pass — found
  `greynoise/mod.rs`'s own doc comment claiming "Free, no API key
  required," and confirmed by direct read: zero `ctx.key_opt` calls
  anywhere in the file, always calling the free `v3/community` endpoint.
  Rather than guess at an unverified richer-tier response shape (this
  project's standing anti-fabrication discipline), found the exact
  endpoint already proven live elsewhere in this codebase:
  `api_key_probe`'s own GreyNoise key-validation probe already calls the
  paid `v3/ip/{ip}` endpoint (header `key`) and parses `ip`/`seen`/
  `classification` from real responses — a genuine, already-verified
  reference, not speculation. Mirrored the Shodan module's established
  free/paid dual-path architecture exactly (`cost()` stays `Free`; a
  configured key upgrades the lookup). A live end-to-end validation was
  planned but blocked mid-cycle: the configured `HUNTSMAN_GREYNOISE_KEY`
  disappeared from this environment's `~/.huntsman.env` (confirmed via
  `hse doctor`, 14→13 keys, GreyNoise absent from both lists). Audited
  every code path in this repository that touches that file — `hse keys
  validate`'s pool-only writes (confirmed the "greynoise" pool entry it
  tested was an unrelated auto-harvested candidate key, not the real one),
  `ensure_hardcoded_keys`'s narrower OathNet/HIBP/WiGLE/SeekNow-only
  rewrite gate (confirmed via trace logs it never fired during this
  session's scans), and the test suite (confirmed every write path uses an
  isolated temp path, never the real file) — and found none of them
  explains it; disclosed the mid-session container restart as the more
  likely cause without asserting it as fact. Per explicit operator
  sign-off, shipped on the unit-test + already-verified-reference basis
  rather than continuing to block on an unavailable key. *Closes:* new
  node **T2.22**. Tests: `paid_response_deserialization`,
  `paid_path_tags_seen_in_addition_to_the_shared_signal`,
  `paid_path_surfaces_a_seen_but_otherwise_unclassified_ip`,
  `paid_path_no_signal_at_all_yields_nothing`,
  `paid_path_still_yields_the_operator_organisation_pivot` — fail-before
  confirmed (reverted to the pre-fix file with the new tests still
  present; they fail to compile, referencing symbols the fix introduces).
  Gate green: fmt/clippy/doc clean, full suite 0 failures (4401 lib
  tests). Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-05** — **Cycle 34: SOL-USERNAME-SLUG-GATE — a real false-positive
  observed in a live self-test, traced to its exact root cause and closed.**
  The earlier "Brett Lawnton" self-test's own dossier put an unrelated
  fishing-tackle retailer (`tackle_world_lawnton`, a Facebook slug named
  after the Lawnton, QLD suburb) into the correlator's single
  highest-confidence "resolved identity" cluster alongside the subject —
  real evidence, not a speculative precision concern. Dispatched a
  background agent to trace the exact mechanism: `score_username`'s Signal 1
  (`search_engines/helpers/entity/mod.rs`) scored a bare surname-substring
  match on ANY candidate at +3, immediately clearing the PROBABLE threshold,
  with no check that a compound candidate's non-anchor parts (`tackle`,
  `world`) relate to the subject at all; `recycle_entities` then re-queried
  every reliable engine verbatim with any ≥0.40-confidence `Username`,
  which is exactly what pulled the retailer's own pages into the graph.
  Confirmed no existing guard covers this (the correlator's
  `GENERIC_HANDLES` denylist is a different module, never consulted by
  `search_engines`, and only excludes role-mailbox words). Gated Signal 1 so
  a compound candidate whose non-anchor parts match neither the subject's
  given nor surname is capped at CANDIDATE unless independently
  corroborated by people-search host provenance or an explicit `site:`
  query — deliberately excluding co-occurrence/stem-similarity from
  counting as independent, since both are themselves surname-substring-
  driven (a business page about itself naturally contains its own name
  too, so letting them override would re-admit the same confound). A
  too-broad first draft (any corroborating score total counted as
  independent) broke the pre-existing `username_scoring_people_search` test
  — a legitimate `"jerome_despal"` handle on `peekyou.com` with an
  unenumerated real surname ("despal") — caught immediately and narrowed to
  name the genuinely independent signals explicitly rather than widen the
  test to fit an imprecise gate. *Closes:* new node **T2.23**. Tests:
  `score_username_business_slug_containing_the_surname_stays_candidate`
  (fail-before confirmed: scored 7/PROBABLE against the unfixed function),
  `score_username_genuine_firstname_lastname_handle_still_reaches_probable`
  (proves the fix doesn't over-broadly demote real compound handles).
  Explicitly scoped: closes the observed case and the general
  compound-business-slug shape, not free-text surname/place-name collision
  broadly (a single-token business slug identical to the surname still
  slips through — a materially bigger gazetteer/NER-pass design change,
  tracked separately, not claimed as fixed here). Gate green: fmt/clippy/
  doc clean, full suite 0 failures (4403 lib tests). Paired: `PROBLEM_TREE`
  §8 — same commit.
- **2026-07-05** — **Cycle 35: SOL-HN-DOMAIN-DETERMINISM — `hacker_news`'s
  Algolia-submissions domain extraction leaked `HashSet` iteration order
  into emitted entity order.** A background discovery agent swept the module
  tree for the same determinism-leak shape already closed for
  `reddit_user::fetch_submitted` (commit `d5adaefd`, this arc) and found
  `hacker_news::fetch_algolia_submissions` had the identical bug: distinct
  domains parsed from a user's Algolia HN-submissions search response were
  deduplicated via `HashSet` and then walked straight into `Vec<Entity>`
  with no ordering step, so the identical submissions JSON could legally
  emit differently-ordered `Domain` entities (and a differently-ordered live
  `EntityFound` stream) across runs of the identical scan — purely an
  artefact of the process's randomised `HashSet` seed, not the input data.
  Independently re-verified by direct read of
  `src/modules/hacker_news/mod.rs` before touching any code. Extracted the
  pure logic into `algolia_domain_entities(body, username, scan_id)` —
  dedup via `HashSet` as before, convert to `Vec`, `.sort_unstable()`, then
  map to entities — mirroring the `reddit_user` fix's exact shape, keeping
  the HTTP-fetching `fetch_algolia_submissions` a thin wrapper around the
  new pure, unit-testable helper. *Closes:* new node **T2.24**. Tests:
  `algolia_domain_entities_emits_all_distinct_domains_deterministically`
  (7 URLs across 6 distinct domains in deliberately non-alphabetical order;
  asserts the output emerges sorted and every entity carries the
  `hn-submission` tag), `algolia_domain_entities_no_urls_yields_nothing` —
  fail-before confirmed (reverted `mod.rs` to pre-fix `HEAD` with the new
  tests still present in `tests.rs`; both failed to compile, referencing
  `algolia_domain_entities`, a symbol that doesn't exist without the fix).
  Gate green: fmt/clippy/doc clean, full suite 0 failures (4405 lib tests).
  Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-05** — **Cycle 36: SOL-WEB-CRAWLER-ORDER-DETERMINISM —
  `web_crawler::build_entities` had the same determinism-leak shape at FIVE
  sites in one function.** Immediately after T2.24 closed the identical bug
  in `hacker_news`, dispatched a background agent to sweep the rest of the
  module tree for the same shape rather than assume it was isolated — found
  `web_crawler` had it worse: `subdomains`, `external_domains`, `emails`,
  `tracking_ids` (a `HashSet<(String, String)>`), and `phones` are each
  aggregated into a `HashSet` across the whole BFS crawl, then every one is
  iterated straight into `state.result.extend(...)` with no sort step —
  five independent non-determinism sites spanning the module's four
  dominant entity kinds (`Domain`, `Email`, `TrackingId`, `Phone`). The
  telling detail: the SAME function already gets this right two lines
  above, for its `frameworks`/`page_types` evidence-string attributes
  (`Vec` + `.sort_unstable()` before `.join()`) — proving the sort-before-
  emission pattern was already known and deliberate in this exact file, and
  the five entity sites simply never received it. Independently
  re-verified by direct read of `src/modules/web_crawler/mod.rs` before
  touching any code, confirming all five sites exactly as the agent cited.
  Applied that identical, already-proven local pattern to all five sites:
  collect the `HashSet` into a `Vec` (tuple refs for `tracking_ids`, whose
  `Ord` sorts by id then provider), `.sort_unstable()`, then map to
  entities. *Closes:* new node **T2.25**. Tests:
  `build_entities_emits_domains_emails_tracking_ids_and_phones_sorted`
  (deliberately non-alphabetical `HashSet` insertion order across all five
  fields; asserts subdomains-then-external-domains, emails, phones, and
  tracking IDs each emerge sorted) — fail-before confirmed (reverted
  `mod.rs` to pre-fix `HEAD` with the new test present; failed on the
  unsorted external-domain/email order). A first draft of the test's `set()`
  helper used `.map(|s| s.to_string())`, which the newer clippy lint table
  flagged as `redundant_closure_for_method_calls`; corrected to
  `.map(ToString::to_string)`. Gate green: fmt/clippy/doc clean, full suite
  0 failures (4406 lib tests). Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-05** — **Cycle 37: SOL-EMAIL-USERNAME-ORDER-DETERMINISM —
  `email_parse`'s derived-username `HashSet` was a 4th instance of the same
  determinism-leak bug class; a project-wide sweep confirms it is now
  closed.** Rather than assume three prior fixes (`reddit_user`,
  `hacker_news`, `web_crawler`) had already closed every instance,
  dispatched a background agent to sweep the ENTIRE `src/modules/` tree for
  the same shape before pivoting to a different bug category. Found
  `email_parse::process`'s `candidates: HashSet<String>` — up to ~10 derived
  username spelling variants (detagged, digit-stripped, separator-collapsed,
  separator-split, plus five initial-blend forms for a two-token
  `firstname.lastname`-shaped local part) — walked straight into
  `result.extend(candidates.into_iter().map(...))` with no sort step, so the
  module's own headline Username-derivation output could legally emit in a
  different order run-to-run. The existing
  `derives_multiple_username_candidates` test only asserted `.contains(...)`
  membership, never order, so it never caught this. The same sweep
  independently confirmed every other direct-`HashSet`-iteration site in
  `src/modules/**/*.rs` is already safe — `hibp::mod.rs`'s
  `all_data_classes` and `search_engines::build.rs`'s `engines_hit` both
  already collect-then-sort before use — closing this bug class
  project-wide (pending any future module introducing a fresh instance).
  Applied the identical minimal in-place fix used for `web_crawler`: collect
  `candidates` into a `Vec<String>`, `.sort_unstable()`, then map to
  entities — no function extraction needed, since insertion order carried
  no meaning here (a bag of derived spelling variants). *Closes:* new node
  **T2.26**. Tests:
  `username_candidates_emerge_in_deterministic_sorted_order` (a two-token
  corporate local part exercising every derivation branch; asserts the
  emitted usernames equal their own sorted form) — fail-before confirmed
  (reverted `mod.rs` to pre-fix `HEAD` with the new test present; panicked
  on the unsorted `HashSet` order). Gate green: fmt/clippy/doc clean, full
  suite 0 failures (4407 lib tests). Paired: `PROBLEM_TREE` §8 — same
  commit.
- **2026-07-05** — **Cycle 38: SOL-GITHUB-ATTACK-COMPLETE — `github_user`'s
  ATT&CK override replaced instead of extended the category default,
  silently dropping real MITRE provenance for 5 of its 6 produced entity
  kinds.** With the `HashSet`-order-leak bug class confirmed closed
  project-wide, a background agent widened its sweep to TODO markers,
  dropped Deserialize fields, newer-clippy shapes, and stale ATT&CK
  mappings, surfacing this in the last category. The module's own comment
  correctly argued for `T1593.003` (Code Repositories) over the Social
  default's `T1593.001` (Social Media) — a genuinely right call for a
  GitHub profile — but `&["T1593.003"]` replaced the WHOLE default array
  instead of substituting just that one technique, so `T1589.003` (Employee
  Names) silently vanished even though `process()` unconditionally builds a
  `Person` from the real name. Independently re-verifying by direct read
  surfaced a bigger gap than the agent's initial finding: `github_user`
  also builds `Organisation` (company + org membership), `Address`/
  `Coordinates` (location), and `Credential` (SSH-key fingerprints) — none
  of which had ANY matching technique — and `Email` (published/gist/commit
  emails) was never covered even before this override, since it was never
  in the Social default either. Confirmed via `core::engine::dispatch` this
  corrupts real per-finding provenance, not just documentation: every
  admitted entity is stamped `attack:<ID>` sourced directly from
  `attack_techniques()`. Cross-referenced the module's code-repository
  siblings `crates_io`/`npm_author` — confirmed NOT affected (pure
  package-registry lookups, no Person/Organisation/Address collection) —
  but found a different, unrelated gap in `crates_io` along the way: it
  declares `Person` in `produces()` but never constructs one anywhere in
  the file. Logged as a deferred candidate for a future cycle rather than
  fixed here — a different bug shape on an unrelated module, out of this
  cycle's scope. Declared the precise, complete set (`T1589.001`,
  `T1589.002`, `T1589.003`, `T1591.001`, `T1591.002`, `T1593.003`), each
  backed by a real catalogued ID and a matching entity-emission code path,
  following the established "superset of the default" convention already
  used by `fullcontact`/`hunter_io`/`oathnet_pro`/`pgp`. *Closes:* new node
  **T2.27**. Tests:
  `attack_techniques_covers_every_entity_kind_this_module_produces` —
  fail-before confirmed (reverted `mod.rs` to pre-fix `HEAD`; panicked on
  the missing `T1589.001` assertion). Also split `github_user` out of a
  pre-existing `tests/architecture.rs` pinning assertion that had bundled
  it with `crates_io`/`npm_author` under one shared expectation, into its
  own assertion reflecting the corrected, larger set — the two
  package-registry siblings' narrower expectation is untouched. Gate green:
  fmt/clippy/doc clean, full suite 0 failures (4408 lib tests), architecture
  suite 30/30. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-05** — **Cycle 39 (doctrine hygiene): refuted the `crates_io`
  "Person" gap logged one commit earlier; no code changed.** Picked up the
  lead Cycle 38 had logged as a ready-scoped deferred candidate rather than
  starting a fresh discovery pass. Reading `crates_io::build_entities` in
  full found it DOES construct a `Person` — via the shared
  `profile_kit::person_from_name` helper — exactly matching the module's
  own doc comment. The earlier finding was a literal-string grep for
  `EntityKind::Person` inside `crates_io/mod.rs` alone, which cannot see a
  construction performed by a shared helper in another file. Corrected the
  SOL-GITHUB-ATTACK-COMPLETE node body and the paired `PROBLEM_TREE` T2.27
  note in place. Mirrors the earlier `TrackingId`/AU-044 refutation:
  verifying independently before building avoided shipping a fix for a
  problem that didn't exist. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-05** — **Cycle 40: SOL-DOCKERHUB-ATTACK-COMPLETE —
  `dockerhub_user` had the identical replace-instead-of-extend
  `attack_techniques()` gap just fixed in `github_user`.** A background
  agent swept other Social-category "profile lookup" modules for the same
  shape and found `dockerhub_user`'s override was `&["T1593.003"]` alone,
  while `build_entities` demonstrably constructs `Person` (via
  `profile_kit::person_from_name` from `full_name`), `Organisation` (from
  `company`), `Address`/`Coordinates` (via
  `profile_kit::location_address`/`location_coordinates` from `location`),
  and `Email` (from `gravatar_email`) — 4 of the module's 5 produced entity
  kinds carried no matching MITRE provenance. Independently re-verified by
  direct read of `dockerhub_user/mod.rs` line-by-line before touching any
  code, confirming every cited construction path is real, live code
  reachable from genuine Docker Hub API fields, not aspirational. Declared
  the precise, complete set — `T1589.002` (Email Addresses), `T1589.003`
  (Employee Names), `T1591.001` (Determine Physical Locations), `T1591.002`
  (Business Relationships), `T1593.003` (Code Repositories) — mirroring
  `github_user`'s exact fix shape (no `T1589.001`: unlike `github_user`,
  `dockerhub_user` emits no `Credential` entities). *Closes:* new node
  **T2.28**. Tests:
  `attack_techniques_covers_every_entity_kind_this_module_produces` —
  fail-before confirmed (reverted `mod.rs` to pre-fix `HEAD`; panicked on
  the missing `T1589.002` assertion). No `tests/architecture.rs` pinning
  assertion referenced `dockerhub_user`, so no cross-module update was
  needed. The same recurring shape was flagged across several other
  Social-category "profile lookup" modules (`codewars_user`,
  `mastodon_user`, `sourceforge_user`, `cpan_user`, `gitea_user`,
  `codeberg_user`, `huggingface_user`, `hexpm_user`) — logged as a scoped
  future sweep rather than pursued in this same commit; `dockerhub_user`
  was the single largest, most cleanly verified instance. Gate green:
  fmt/clippy/doc clean, full suite 0 failures (4409 lib tests), architecture
  suite 30/30. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-05** — **Cycle 41: SOL-CODEWARS-ATTACK-COMPLETE —
  `codewars_user` was the 3rd instance of the same replace-instead-of-extend
  `attack_techniques()` gap.** Picked from T2.28's scoped future-sweep list,
  surveying each of the 8 candidates' `attack_techniques()`/`produces()`
  pair before selecting the largest remaining verified gap. The override
  `&["T1593.003"]` alone left `Person` (via `profile_kit::person_from_name`
  from the API's `name` field), `Organisation` (from `clan`), and
  `Address`/`Coordinates` (via `profile_kit::location_address`/
  `location_coordinates` from `city`) with no matching MITRE provenance —
  independently re-verified line-by-line before touching any code. No
  `Email` field exists on the Codewars API, so `T1589.002` correctly does
  not apply here, unlike `dockerhub_user`. Declared the precise, complete
  set — `T1589.003`, `T1591.001`, `T1591.002`, `T1593.003` — mirroring the
  prior two fixes' shape, scoped to only what this module's fields support.
  *Closes:* new node **T2.29**. Tests:
  `attack_techniques_covers_every_entity_kind_this_module_produces` —
  fail-before confirmed (reverted `mod.rs` to pre-fix `HEAD`; panicked on
  the missing `T1589.003` assertion). No `tests/architecture.rs` pinning
  assertion referenced `codewars_user`. 7 modules remain on the scoped
  sweep list (`mastodon_user`, `sourceforge_user`, `cpan_user`,
  `gitea_user`, `codeberg_user`, `huggingface_user`, `hexpm_user`) for
  future cycles — one independently-verified module per cycle by design.
  Gate green: fmt/clippy/doc clean, full suite 0 failures (4410 lib tests),
  architecture suite 30/30. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-05** — **Cycle 42: SOL-MASTODON-ATTACK-COMPLETE —
  `mastodon_user` was a variant of the same gap, on an already-correct base
  technique.** Continuing the scoped sweep list, deliberately picked
  `mastodon_user` next: unlike the three prior fixes, its existing override
  `&["T1589.002", "T1593.001"]` already kept the correct `T1593.001`
  (Social Media) — Mastodon genuinely is social media, unlike the
  code-hosting modules mis-declared as Social — testing whether the fix
  pattern generalises beyond "swap in T1593.003." Independent line-by-line
  verification of `build_entities` confirmed the override was still missing
  a `Person` (via `profile_kit::person_from_name` from `display_name`) and
  an `Address`/`Coordinates` (from a profile field matching
  `looks_like_location_field`); no `Organisation` entities are built here,
  so `T1591.002` correctly does not apply. Extended the existing correct
  pair rather than replacing it: added `T1589.003` (Employee Names) and
  `T1591.001` (Determine Physical Locations). Because `mastodon_user`'s
  tests live inline in `mod.rs` (no separate `tests.rs`), the fail-before
  step required reverting only the `attack_techniques()` function body in
  place — reverting the whole file would also have deleted the new test —
  confirmed against the isolated buggy function, then restored via a
  diff-verified whole-file backup. *Closes:* new node **T2.30**. Tests:
  `attack_techniques_covers_every_entity_kind_this_module_produces` —
  fail-before confirmed (panicked on the missing `T1589.003` assertion). No
  `tests/architecture.rs` pinning assertion referenced `mastodon_user`. 6
  modules remain on the scoped sweep list (`sourceforge_user`, `cpan_user`,
  `gitea_user`, `codeberg_user`, `huggingface_user`, `hexpm_user`) for
  future cycles. Gate green: fmt/clippy/doc clean, full suite 0 failures
  (4411 lib tests), architecture suite 30/30. Paired: `PROBLEM_TREE` §8 —
  same commit.
- **2026-07-05** — **Cycle 43: SOL-SOURCEFORGE-ATTACK-COMPLETE —
  `sourceforge_user` was the 5th instance of the same under-declared-coverage
  gap, back to the code-hosting shape.** Continuing the scoped sweep list;
  the override `&["T1589.002", "T1593.003"]` already correctly covered the
  Username (Code Repositories) and bio-extracted Email. Independent
  line-by-line verification of `build_entities` confirmed a `Person` (via
  `profile_kit::person_from_name` from `display_name`) and an `Address`/
  `Coordinates` (via `profile_kit::location_address`/
  `location_coordinates` from `location`) with no matching technique; no
  `Organisation` entities are built here, so `T1591.002` correctly does not
  apply. Extended the existing correct pair: added `T1589.003` (Employee
  Names) and `T1591.001` (Determine Physical Locations). *Closes:* new node
  **T2.31**. Tests:
  `attack_techniques_covers_every_entity_kind_this_module_produces` —
  fail-before confirmed (reverted `mod.rs` to pre-fix `HEAD`; panicked on
  the missing `T1589.003` assertion). No `tests/architecture.rs` pinning
  assertion referenced `sourceforge_user`. 5 modules remain on the scoped
  sweep list (`cpan_user`, `gitea_user`, `codeberg_user`,
  `huggingface_user`, `hexpm_user`) for future cycles. Gate green:
  fmt/clippy/doc clean, full suite 0 failures (4412 lib tests), architecture
  suite 30/30. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-05** — **Cycle 44: SOL-NAMEINTEL-ATTACK-COMPLETE — `name_intel`
  had NO `attack_techniques()` override at all, silently inheriting the
  exact over/under-claim `pgp` already fixed.** `hse selftest`/`hse
  diagnostics` both ran clean, so pivoted to a direct code-grounded
  discovery pass on `name_intel` — one of the highest-yield/noisiest
  modules flagged in earlier "Brett Lawnton" scan diagnostics. Found the
  module never overrides `attack_techniques()`, inheriting the full
  `People` default (`T1589.003` + `T1591.004`) — the identical shape
  `pgp`'s own comment documents: a Person + Email-producing module
  over-claiming Identify Roles with zero role/organisational logic
  anywhere, never crediting Email Addresses. Confirmed by full read of
  `mod.rs`/`permute/mod.rs`. A parallel investigation into
  `permute::parse`'s honorific-handling for degenerate 2-token names ("Dr
  Ali", "John Jr") — which initially looked like a name-fabrication bug —
  was REFUTED on closer reading: `suffix_not_stripped_from_two_word_name`
  already pins this as deliberate, tested "safety guard" behaviour.
  Declared the precise pair `["T1589.002", "T1589.003"]`, identical to
  `pgp`'s established fix; the search-pivot `Url` entities earn no
  separate technique (unexecuted offline links, mirroring
  `employer_pivot`'s precedent). *Closes:* new node **T2.32**. Tests:
  replaced the pre-existing weak `attack_techniques_non_empty` test (which
  would have passed against the buggy inherited default too) with
  `attack_techniques_matches_produced_entity_kinds` — fail-before confirmed
  (reverted `mod.rs` to pre-fix `HEAD`; panicked on the missing
  `T1589.002` assertion). No `tests/architecture.rs` pinning assertion
  referenced `name_intel`. Gate green: fmt/clippy/doc clean, full suite 0
  failures (4412 lib tests — a 1-for-1 test replacement, not a net
  addition), architecture suite 30/30. Paired: `PROBLEM_TREE` §8 — same
  commit.
- **2026-07-05** — **Cycle 45: SOL-UPDATE-POISON-CONSISTENT — fixed a
  poisoned-mutex inconsistency in `api::update_handlers` surfaced by
  automated PR review, plus a minor efficiency tweak.** Subscribed to PR
  #215's activity and found two unresolved review threads.
  `copilot-pull-request-reviewer` flagged that `try_start_update`'s
  poison-recovery policy wasn't mirrored at the two update-finish sites
  (`Ok(()) => Restarting`, `Err(e) => Error(...)`), which used a bare
  `if let Ok(mut info) = update_info.lock() { .. }` — silently no-oping on
  a poisoned lock. Independently verified: this could strand `phase` at
  `Applying` forever, permanently blocking every future update trigger via
  `try_start_update`'s own gate, with no operator-visible error. Extracted
  a shared `set_phase()` helper using the same poison-recovery pattern and
  routed both finish-sites through it. Separately, `gemini-code-assist`
  flagged `hacker_news::algolia_domain_entities` (T2.24)'s
  `HashSet`-round-trip-then-sort as unnecessary allocation/hashing for a
  result that ends up sorted anyway; rewrote it as `Vec` →
  `sort_unstable()` → `dedup()` — identical deterministic output, confirmed
  by the pre-existing determinism test passing unmodified. *Closes:* new
  node **T2.33**. Tests: `set_phase_recovers_from_a_poisoned_mutex` (poisons
  a real `Mutex` via `catch_unwind` around a panicking lock guard) —
  fail-before confirmed (reverted `set_phase`'s body to the bare
  `if let Ok(...)` pattern in place; the poisoned-mutex assertion failed).
  Gate green: fmt/clippy/doc clean, full suite 0 failures (4413 lib tests),
  architecture suite 30/30. Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-06** — **Fault-tree re-audit repairs (nodes FT.1–FT.8).** An
  11-branch multi-agent fault-tree re-run of T1–T11 (every finding
  adversarially verified) surfaced 8 residual defects, all fixed this commit:
  a path-embedded own-API-key leak into the raw archive (`describe_url` now
  excludes `keys::own_api_keys()` from every URL label), a cache-replay
  observation mis-attribution that dropped a finding from a re-scanned target
  (`dispatch.rs` re-stamps replayed entities to the current `scan_id`), the
  typosquat session-dedup set never reset per scan (wired into
  `reset_per_scan`), `au_postcode` reading a stray value digit-run as a
  postcode on non-Address kinds (value-scan gated to Address), CSV
  formula-guard corruption on export→re-import (guard stripped on import),
  cell-tower IDs mis-detected as Phone (detector reordered), a reactor-blocking
  `report.json` handler (`spawn_blocking`), and O(k·n) inline-block stripping
  on untrusted SERP bytes (now O(n)). Three trace-phase candidates were
  REJECTED by adversarial verification rather than fabricated into fixes. Gate
  green: fmt/clippy `-D warnings`/rustdoc clean, full suite 0 failures (4425
  lib tests, +3), architecture suite green. Paired: `PROBLEM_TREE` §8 — same
  commit.
- **2026-07-06** — **Fault-tree loop round 2 (FT.9–FT.13; FT.14 deferred).**
  Second fault-tree pass (FT.1–FT.8 + prior fixes excluded); 6 of 11 branches
  came back empty — the tree is converging. 5 defects fixed this commit: a
  stored XSS→RCE in the SPA autonomous-scan toast (now `esc()`s the seed like
  every other render site), the `hse radar` pivot/sweep running without the
  entity ceiling every other scan path carries (now `max_entities:
  Some(DEFAULT_MAX_ENTITIES)` + `clamp_depth`, closing an on-device OOM), a
  UTF-8-BOM misroute that dropped every entity on a BOM-prefixed import (BOM
  now stripped in the detector and at both body entry points), and two
  residual reactor-blocking event-log reads (`scan_audit`, `scan_events_history`
  → `spawn_blocking`). One confirmed defect — a coarse `ip_geo` coordinate
  anchoring the subject's location — was DEFERRED (FT.14): the obvious
  `is_infrastructure_geo` gate would wrongly exclude legitimate live-sensor GPS
  fixes, so it needs a device-sensor bypass + fixture reconciliation, logged
  for a focused follow-up rather than shipped with a regression. Gate green:
  fmt/clippy `-D warnings`/rustdoc clean, full suite 0 failures (4426 lib
  tests, +1), architecture suite green. Paired: `PROBLEM_TREE` §8 — same
  commit.
- **2026-07-06** — **Fault-tree loop round 3 (FT.15–FT.19).** Third
  adversarial fault-tree pass (all prior FT fixes excluded); the tree is
  converging — 5 confirmed, independently-verified root-cause defects, all
  fixed this commit: (FT.15) `scan_identities` ran an unbounded O(n²)
  coreference resolution on the async reactor after offloading only the entity
  read — an imported dossier could freeze a worker for minutes with OOM risk;
  the compute now runs inside the same `spawn_blocking` closure as the read.
  (FT.16) `rule_au_053_out_of_area_location` clustered coordinates in caller
  iteration order, so the live (HashMap-ordered) and finalise passes produced
  divergent, non-dedupable AU-053 rows; now sorts by uid first, matching
  AU-017/AU-027. (FT.17) the CSV anti-formula-injection guard wasn't
  invertible — a genuine leading-apostrophe value lost its apostrophe on
  re-import; `csv_escape` now also guards a leading `'` and the importer strips
  exactly one, a true bijection with a round-trip proptest. (FT.18) the
  cross-scan module-stats ledger's unsynchronised read-modify-write lost
  concurrent scan accumulations; now serialised by a process-global
  poison-tolerant mutex. (FT.19) `GET /keys/status` leaked per-service
  key-pool inventory to LAN peers under a non-loopback bind; now carries the
  same loopback gate as the sibling `keys_pool_get`, with a non-loopback 403
  test. Rejected candidates were not fabricated into fixes. Gate green:
  fmt/clippy `-D warnings`/rustdoc (private items) clean, full suite 0 failures
  (4432 lib tests, +7; +1 API test), architecture suite green. Paired:
  `PROBLEM_TREE` §8 — same commit.

- **2026-07-11** — **SOL-HINT-NOISE built, T2.14 closed.** Built
  `util::diagnostics::event_hints::append_event_sourced_hints` from
  `Event`/`ModuleCost` — the ground truth a pure entity-only `analyse()`
  structurally cannot see, since a dispatched module that found nothing never
  appears in `modules_by_yield`. The per-module noise question (open since
  2026-07-01) resolved to the bounded-summary-count candidate: one line ("N
  of M dispatched modules found nothing for this target kind") rather than
  cap-to-worst-N or a per-module enumeration, so a 42-module scan with 30
  zero-yield modules produces one line, not thirty. The scan-level 60s hint
  kept its existing cost-gate (`KeyGated`/`Paid`-only via the relocated
  `keyed_or_paid_zero_yield_modules`, moved out of `cli/scan/dossier.rs` into
  the same new module so both hints and both consumer call sites — dossier
  text output and the JSON output path — share one implementation instead of
  drifting). The third `analyse()` call site (`api/handlers/mod.rs`) discards
  the return value entirely (ledger-persist side effect only, no reader), so
  it was deliberately left unenriched. Same commit swept a pre-existing
  clippy backlog (32 errors / 10 files, confirmed via `git stash` to predate
  this change) uncovered while proving the full gate green — see
  `PROBLEM_TREE` §8 for the fix-by-fix breakdown. Live-verified: built `hse`
  and ran a real `hse scan --kind coords --output json`; `optimization_hints`
  read `"4 of 12 dispatched modules found nothing for this target kind"`.
  Gate green: fmt/clippy `-D warnings`/rustdoc (private items, bare-URL,
  invalid-HTML-tag lints) clean, full suite 0 failures (4554 lib tests).
  Paired: `PROBLEM_TREE` §8 — same commit.

- **2026-07-11** — **SOL-WIGLE-412-GRACEFUL built, T2.34 closed same cycle.**
  Live evidence (the operator's own WiGLE account page, plus a real `hse
  scan --kind coords` logging `HTTP 412 Precondition Failed` from `wigle`)
  surfaced this, not a discovery sweep. First fix attempt — tag the emitted
  entity with an "account unverified" caveat, piggybacked on the module's
  existing cell/bluetooth `tokio::join!` — was live-tested and found
  unreachable: a 412 on both the tight and wide bbox attempts means geo
  search returns nothing at all, so there is no entity left to tag. Reverted
  before shipping rather than land a design that looked right but was dead
  code in the exact case it claimed to fix — caught by actually running it,
  not by trusting the design. Root-caused instead: `fetch_wigle_typed`/
  `fetch_wigle_ssid` treat any non-2xx as `Err`, propagating out of
  `process()` via `?`; the BSSID/detail path (`fetch_detail`/`util::wigle::
  get`, and `wifi_intel::query_wigle_detail`) was independently confirmed
  unaffected, already swallowing non-success gracefully. Both fetch
  functions now special-case HTTP 412 into `Ok(Resp{success:Some(false),
  ..})` — the same "WiGLE said no" path every other unsuccessful outcome
  already takes — and record `verified:Some(false)` into the account cache
  as a free side effect of traffic already being made, no dedicated poll
  needed. *Closes:* new node **T2.34**. ✅ No unit-test harness exists for
  `process()`-level HTTP glue in this codebase (verified: no mock-HTTP
  dev-dependency, no other module's `process()` is unit-tested this way
  either), so verification was live: re-ran the identical scan, confirmed
  `"module error"` → `"done","found":0`, and confirmed the T2.14 zero-yield
  summary line picked up the change (3 of 12 → 4 of 12) — the two fixes
  compose correctly, since a module that errors is invisible to the
  zero-yield count but a module that cleanly finds nothing is not. Gate
  green: fmt/clippy `-D warnings`/rustdoc clean, full suite 0 failures
  (4554 lib tests, unchanged). Paired: `PROBLEM_TREE` §8 — same commit.

- **2026-07-11** — **SOL-CEFF-TRANSPARENCY built, T2.35 closed; T2.36 opened
  (deeper, not yet solved).** Triggered by the operator supplying a real
  scan's CSV export and full debug bundle as evidence, not a sweep. Two
  research passes established ground truth before any fix: `c_effective()`
  itself is correct, deterministic, and already regression-tested — it uses
  `source_count()` (distinct non-enrichment sources), not the raw
  `corroboration` field (a per-module magnitude, summed unconditionally on
  merge, by design). The real gap: nothing ever showed the reader
  `source_count()` next to the confusingly-similar-looking `corroboration`.
  Fixed in `render_full` (debug bundle + full dossier: `source_count` printed,
  a `note:` line on divergence, per-evidence non-corroborating markers),
  `entities_to_csv` (`source_count`/`corroborating_sources` columns), and 3
  stale `core::entity` doc comments describing the wrong (old
  pure-multiplicative, or flatly incorrect) formula. Separately — found while
  tracing the same investigation — the SPA's client-side `effC()` mirror
  used an `ENRICHMENT_SOURCES` set of 2 entries where the backend's real
  exclusion list has 5, so Browse could render a higher tier than the
  server's own classification for an entity corroborated only by
  `name_intel`/`payid`/`cross_scan_history`; fixed to match exactly, with a
  new drift-guard test reading the live backend constants (mirrors the
  existing `EVENT_TYPES` pattern). Investigating WHY so many unrelated
  addresses shared `corroboration=8` in the first place led to a second,
  deeper research pass that found the true root cause is NOT in the
  breach-ingestion module (`oathnet_pro` correctly seeds `corroboration: 1`
  per entity) but in `search_engines`' pivot-expansion path, which stamps a
  flat, content-blind `confidence=0.82` parent entity onto any re-queried
  target with no relevance check — opened as new **T2.36**, deliberately not
  fixed in this commit (a real design decision — mirroring an existing
  relevance gate the module already has elsewhere for a different code path
  — not a quick patch). Gate green: fmt/clippy `-D warnings`/rustdoc clean,
  full suite 0 failures (4557 lib tests). Paired: `PROBLEM_TREE` §8 — same
  commit.

- **2026-07-11** — **SOL-LOCATION-SEED-NO-REAFFIRM + SOL-SEEKNOW-SUBJECT-GATE
  built; T2.36 closed, new T2.37 opened and closed same cycle.** Run as a
  multi-phase workflow given the scope and evidentiary-integrity stakes:
  parallel investigation (tokenization trace of `location_on_subject` for an
  Address seed; a first sweep of `target.to_entity(` across every module;
  the existing `build_entities` test idiom) fed a single implementation pass,
  which was then independently adversarially verified twice — one pass
  re-derived correctness from the code and traced concrete cases by hand,
  the other re-ran every gate command from scratch rather than trusting the
  implementer's report. `search_engines/build.rs` now gates its
  parent-entity re-affirmation AND its snippet-address extraction on a
  function-scoped `location_seed` check; the fix SKIPS reaffirmation for a
  location seed rather than demoting it, since a demoted parent sharing the
  seed's UID would still unconditionally inflate `corroboration` via
  `absorb()`. A dedicated post-fix sweep (independently re-verifying every
  candidate against live code, not trusting the sweep pass's citations)
  found exactly one further real instance — `see_know`'s `/search` path,
  gated on raw hit count instead of a genuine subject match — fixed
  identically to how this codebase's own `oathnet_pro` module already fixed
  the same shape once before. All other 37 `target.to_entity(` call sites
  were checked and correctly cleared; the sweep explicitly declined to
  fabricate findings where none existed. Live-verified beyond the test
  suite: a real `hse scan --kind address` shows zero `search-enriched` tags
  and zero 0.82-confidence entities where the unfixed code would have shown
  both. Gate green: fmt/clippy `-D warnings`/rustdoc clean, full suite 0
  failures (4560 lib tests, +3). Paired: `PROBLEM_TREE` §8 — same commit.

- **2026-07-11** — **SOL-AU063-DOC-FIX built, T2.38 closed; new T2.39 opened,
  deliberately not solved.** Second precision-sweep workflow this cycle: 4
  parallel discovery passes (`core/` doc-drift, `util/` doc-drift + shared
  confidence-bug check, a 22-of-108 correlator-rule spot-check, and a
  TODO/unjustified-`#[allow]`/risky-`unwrap()` sweep) → triage → implement →
  independent verification. Near-clean result: dozens of formulas and
  thresholds across `core/` and `util/` (ABN/ACN checksums, `health_score`
  weights, shoelace centroid, Haversine, ~20 correlator thresholds) verified
  to match their doc comments exactly; zero TODO/FIXME/HACK markers
  repo-wide; all 10 `#[allow(...)]` suppressions read in context and
  confirmed justified; the 2 production `unwrap()` sites in `core`/`modules`
  confirmed genuinely guarded, no concrete panic scenario articulable for
  either. One real, self-contradictory doc-comment pair found and fixed
  (`gap.rs`'s `AU063_DETAIL_MIN_CONF` doc said "at least one endpoint," the
  code's own `.min()` gate requires both — and a second copy of the same
  drift, in the opposite direction, sat 175 lines below). One real,
  evidence-grounded logic weakness found and DELIBERATELY not patched blind:
  AU-039 attributes a wallet to an arbitrary anchor identity with zero
  relatedness check, proven by the rule's own test — opened as T2.39 rather
  than rushed, since a real fix needs a relatedness-criterion design decision
  this sweep correctly declined to invent unilaterally. No findings
  fabricated across either the T2.36/T2.37 sweep or this one to manufacture
  urgency where none existed. Gate green: fmt/clippy `-D warnings`/rustdoc
  clean, full suite 0 failures (4560 lib tests, unchanged — doc-only fix).
  Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-11** — **SOL-AU039-SHARED-SOURCE built, T2.39 closed** — resolving
  the very design decision the previous entry deferred. Investigating the
  entity model answered both open questions the T2.38 sweep declined to
  guess: the provenance IS carried at this call site
  (`Entity::corroborating_sources()`), and the right relatedness criterion is
  a **shared corroborating evidence source** (some single module surfaced both
  the wallet and the identity — a stealer log stamps the same `source` on an
  owner and their wallet). New `shares_corroborating_source(a, b)` helper
  (`rules/mod.rs`, built on `corroborating_sources()` so a replay/enrichment
  pass can't manufacture a tie — the same honesty rule `source_families`
  already enforces) replaces AU-039's "smallest-UID identity across the whole
  scan" anchor. Per wallet the rule now reports each source-tied identity
  (Person preferred over Email, none singled out) and fires nothing when no
  identity shares a source — removing the arbitrariness the deferral warned an
  ad-hoc "pick a different anchor" fix would merely relocate. Deterministic
  (pure function of source membership + UID order), so live and finalise
  passes agree. The two tests that encoded the buggy co-existence semantics
  were replaced by three (genuine-tie positive + no-shared-source negative;
  the T2.39 regression that gives the bystander the smaller UID so the old
  pick would name them; person-preferred/report-each-tie) — each fails against
  the unfixed rule, passes against the fix. Gate green: fmt/clippy
  `-D warnings`/rustdoc clean, full suite 0 failures (4561 lib tests, +1 net).
  Paired: `PROBLEM_TREE` §8 — same commit.
- **2026-07-11** — **SOL-HEALTH-SIGNAL built (hard-failure leg), T2.7 elevated
  `[ ]`→`[~]`.** The sketch's own premise was wrong on inspection: it assumed
  a new tracking column and a wait on SOL-F1's parser rewrites; neither was
  needed, since the engine already persists `ModuleDone`/`ModuleError` per
  dispatch on every scan — the real gap was that nothing aggregated it ACROSS
  scans. New `Store::recent_module_outcome_events` (bounded, newest-first,
  cross-scan, backed by a new `idx_events_type` index) is a naturally rolling
  window off the existing 7-day/100k-row event-retention policy. New pure
  `util::scraper_health::aggregate_source_health` walks it once, tracking a
  per-module trailing-failure streak and last-success timestamp,
  deterministically name-sorted. `is_drifted()` at `consecutive_failures ≥ 3`
  (three strikes, not one — a transient blip shouldn't page the operator).
  Wired into a new "Scraper health" section of `hse doctor`. 9 new tests (7
  pure aggregation + 1 storage-level SQL-filter/order/limit test), plus the
  pre-existing exact-schema enumeration test updated for the new index — a
  real schema addition, not a stale assertion. Live-verified: a real `hse
  doctor` run renders the section correctly against the operator's own
  database (honestly empty for this DB, not fabricated). *Remaining:* SPA
  panel, parse-rate/zero-yield drift detection (needs a per-source yield
  baseline, deliberately not guessed at), and the golden-fixture corpus (T2.7's
  other leg). Gate green: fmt/clippy `-D warnings`/rustdoc clean, full suite 0
  failures (4569 lib tests, +8). Paired: `PROBLEM_TREE` §8, T2.7 `[ ]`→`[~]`
  — same commit.
- **2026-07-11** — **SOL-SNIPPET-PII-SUBJECT-GATE built, new T2.40 closed same
  cycle.** Triggered by an operator-supplied real scan (CSV + debug bundle,
  target "Riley Morley"): `pr@rileyjorja.com`, belonging to an unrelated
  Instagram account, reached PROBABLE 0.70 attributed to the subject from a
  single off-target snippet. Root cause: `search_engines/build.rs`'s
  email/phone extraction had no subject-relevance check at all, while its
  OWN address extractor a few lines below already carried one
  (`location_on_subject`) built for an earlier live regression ("Cindy
  Haynes"/"Cindy He"). The fix reused the existing, already-proven check
  rather than inventing a new one: hoisted it to run once per result before
  any snippet extraction, renamed to `result_names_the_subject` (never
  location-specific), and gated email + phone + address on the single shared
  boolean — removing the duplicate definition. Byte-identical for every
  existing caller; the pre-existing 290-test `search_engines` suite passed
  unmodified before 2 new tests were added, one of which reproduces the exact
  real-scan false positive and is confirmed to fail against the unfixed code
  via `git stash`. Live-verified: `hse selftest` 9/9 clean. Gate green:
  fmt/clippy `-D warnings`/rustdoc clean, full suite 0 failures (4571 lib
  tests, +2). Paired: `PROBLEM_TREE` §8, new T2.40 `[x]` — same commit.
- **2026-07-11** — **SOL-AUDIT-CADENCE extended: an apparent P1
  evidentiary-integrity shape from the same real scan investigated and
  confirmed sound against HEAD.** The operator's debug bundle showed US
  breach-candidate addresses (5-digit ZIPs) geo-corroborated at "~0 km"
  from the real Australian subject anchor. Direct reproduction (the exact
  real entity: US Address, `postal_code`/`addr_postal` evidence keys, plus
  the exact real QLD `exact-name-match` anchor) confirms
  `core::geo_family::au_postcode()`/`distance_to_subject()` correctly
  return `None`, not `0`, against current HEAD — the bundle's own
  `hse_version`/module-count header shows it predates this tree, so the
  visible defect is most likely already closed by the existing
  `au_postcode_ignores_a_leading_us_street_number` hardening. A second
  thread (two QLD family-candidate addresses also carrying
  `exact-name-match` with neither visible owner matching the subject)
  reproduces `au_unclaimed`'s per-record classification as correct in
  isolation; the coexistence in the live bundle could not be fully
  root-caused without the raw upstream CKAN response and is logged
  honestly as unresolved (`PROBLEM_TREE` §6) rather than guessed at. Two
  new regression tests pin both verified-sound findings against the real
  data. No code changed — a clean-verdict investigation is a correct
  outcome. Gate green: fmt/clippy `-D warnings`/rustdoc clean, full suite 0
  failures (4573 lib tests, +2). Paired: `PROBLEM_TREE` §6 sixth pass —
  same commit.
- **2026-07-11** — **SOL-SPA-MODULE-SPLIT: split the monolithic 3999-line
  `spa.html` into `src/web/css/app.css` + 37 native ES modules under
  `src/web/js/`, closing T2.41.** Requested as a one-large-effort
  structural UI refactor (same look, same behaviour, no new build
  toolchain — plain `<script type="module">`, zero new dependencies,
  matching the project's minimal-dependency doctrine). `spa.html` is now a
  111-line shell; every module is still `include_bytes!`-embedded
  (`APP_FILES`, alongside `VENDOR_FILES`) so the release binary stays
  self-contained, served from the new wildcard route `/static/{*file}`.
  Verified lossless (diff-checked reconstruction), verified wired (0
  missing/unused imports across all 38 files via an automated symbol scan,
  including the 5 safe `main.js`-rooted circular imports), and live-
  verified in headless Chromium against a real running scan — every
  top-level view and all 22 ScanInfo sub-tabs render with zero console/
  page errors. Migrated the ~14 tests that scanned the old monolithic
  `SPA_HTML` string to read the split modules (`app_file()` in
  `src/api/routes/tests.rs`, `spa_bundle()` in `tests/api.rs`) — 0
  regressions. Gate green: fmt/clippy `-D warnings`/rustdoc clean, full
  suite 0 failures. Paired: `PROBLEM_TREE` T2.41, §8 — same commit.
- **2026-07-11** — **SOL-SPA-VENDOR-DROP: from-scratch dark-console design
  system + vanilla-JS compatibility layer replace Bootstrap/jQuery/
  tablesorter/alertify entirely, closing T2.42.** The user's follow-up
  request ("Completely revamp the UI and REFACTOR it") asked for the
  visual layer the prior structural split had deliberately left alone, and
  was open to dropping the vendor libraries outright. New `app.css`: dark-
  first CSS custom-property tokens, a `.light-theme` opt-out override
  block, the pre-existing Bootstrap-era class vocabulary redefined from
  scratch (so none of the ~40 view files' markup changed), 47 inline-SVG-
  mask icons replacing a glyphicon icon font that — audited while building
  the replacement — turned out to have never rendered at all (a real
  latent bug incidentally fixed). New `ui.js`: vanilla navbar-collapse,
  modal handling, a sortable-table replacement, and `window.jQuery`/
  `window.alertify` shims matching every view file's existing call
  contract exactly, so no view file needed a call-site change either. D3
  v3 stays vendored (a rendering engine, not a look dependency). Dropping
  alertify also resolved a standing licensing question (`PROBLEM_TREE` §7:
  GPL alertify + missing NOTICE). Live-verified in headless Chromium
  across every view, all 22 ScanInfo sub-tabs (incl. the D3 graph against
  a real 454-entity/2785-correlation scan), mobile nav collapse, the About
  modal, sortable tables, and toast/confirm/prompt dialogs — zero console/
  page errors; one real `box-sizing` overflow bug found and fixed along
  the way (screenshot-confirmed before/after). Gate green: fmt/clippy `-D
  warnings`/rustdoc clean, full suite 0 failures. Paired: `PROBLEM_TREE`
  T2.42, §8 — same commit.
- **2026-07-11** — **SOL-WEAK-DETECTION-DISCOUNT: AU-003/AU-038/AU-045/
  AU-055 no longer treat a status-only username guess as a confirmed/
  verified account, closing T2.43.** Found via a real OSINT scan (Brisbane/
  QLD username-alias lookup) that produced a `CRITICAL` "confirmed
  accounts" finding across 64–71 platforms and a `C_eff=1.000` "6
  independent sources" claim, both built almost entirely from
  `weak-detection`-tagged (bare HTTP-status) hits. Three root causes fixed:
  `webserver_banner` mis-attributing a domain-root-only check to a
  path-specific `Url` entity (now rebased to `Domain`, keyed on the actually-
  probed host, via a new pure `banner_entity` helper); the four AU rules
  checking only the profile tag and never the accompanying weak-detection
  one (AU-003/AU-055 now exclude weak-detection entities/hits outright;
  AU-045 gained `strong_corroborating_families`, discounting per-evidence-
  record since family classification is per-source, not per-tag); and
  `social_probe` — a third module doing the identical check with zero
  weak/verified distinction across most of its platforms — gaining the same
  `detection_strength()` split its siblings already use. A genuinely
  `verified-detection` hit still fires every rule unchanged. 8 new
  regression tests, each confirmed via `git stash` to fail pre-fix and pass
  post-fix. Gate green: fmt/clippy `-D warnings`/rustdoc clean, full suite 0
  failures. Paired: `PROBLEM_TREE` T2.43, §8 — same commit.
- **2026-07-12** — **SOL-HEALTH-SIGNAL extended: the SPA panel leg, closing
  the last "CLI-only for now" gap on T2.7's health signal.** New `GET
  /api/v1/health/scrapers` handler + a "Scraper health" panel on the Engines
  page render the same cross-scan failure-streak data `hse doctor` already
  printed. Reaching it from the API layer needed a new default-empty
  `StoragePort::recent_module_outcome_events` trait method, since `AppState`
  only ever holds `Arc<dyn StoragePort>`. Live-verified against this
  session's own real scan history, zero console/page errors. New
  integration test pins the honest-empty-state contract. Gate green:
  fmt/clippy `-D warnings`/rustdoc clean, full suite 0 failures. Paired:
  `PROBLEM_TREE` T2.7, §8 — same commit.
- **2026-07-12** — **SOL-CORR extended: 2 of the 3 independently-drifted
  DOB-key vocabularies (2026-07-05's deferred follow-on) single-sourced.**
  `core::exposure`'s `DOB_KEYS`/`GOV_ID_KEYS` were a narrower, drifted copy
  of AU-073/AU-074's canonical vocabularies in `breach_pii` (3/9 DOB
  spellings; 5/22 government-ID spellings) — undercounting the exposure
  score for breach records using an un-mirrored spelling like
  `tax_file_number` or `date_birth`. `breach_pii` promoted to `pub(crate)`
  (mirroring `location`'s existing re-export pattern); `exposure` now
  references it directly instead of keeping a separate copy.
  `timeline::classify`'s list stays separate on purpose (scoped to
  first-party module spellings only; several `breach_pii` spellings are
  import-only). 2 new regression tests, confirmed via `git stash` to fail
  pre-fix and pass post-fix. Gate green: fmt/clippy `-D warnings`/rustdoc
  clean, full suite 0 failures. Paired: `PROBLEM_TREE` C1, §8 — same
  commit.
- **2026-07-12** — **SOL-CORR extended again: a sibling drift in
  `exposure`'s Financial flag, found while closing the DOB/gov-ID cycle
  above.** `FINANCIAL_KEYS` only recognised the bare `bank_account`
  spelling; AU-104's own `BANK_ACCOUNT_KEYS` in `breach_pii` has 4 more
  (`account_number`/`account_no`/`acct_number`/`acct_no`) that were never
  mirrored, silently undercounting the exposure score for a breach record
  using one of them. `BANK_ACCOUNT_KEYS` promoted to `pub(crate)`;
  `exposure` now checks it directly, keeping only its own `iban`/
  `card_number` literals (no `breach_pii` equivalent — AU-104 is BSB/
  domestic-account-number scoped). 1 new regression test, confirmed via
  `git stash` to fail pre-fix and pass post-fix. Gate green: fmt/clippy `-D
  warnings`/rustdoc clean, full suite 0 failures (4583 lib tests, +1).
  Paired: `PROBLEM_TREE` C1, §8 — same commit.
- **2026-07-12** — **§4a cell_local auto-sync gap partially addressed: `hse
  doctor` now flags a stale local cell-tower database.** The full gap (a
  scheduled re-sync) needs cron/daemon infrastructure this codebase has
  none of, and Termux/Android has no reliable persistent-process story to
  hang one off — so that half stays open by design. The other half — the
  dataset silently going stale with nothing to flag it — was real and
  buildable: new `util::cell_db::is_stale`/`STALE_THRESHOLD_DAYS` (180
  days) plus a "Cell tower database" section in `hse doctor`, mirroring
  T2.7's scraper-health signal (tower count, import age, a `STALE` line
  naming the fix command). Live-verified against a not-populated DB, a
  fresh import, and a fabricated 200-day-old import — all three render
  honestly. 1 new regression test. Gate green: fmt/clippy `-D
  warnings`/rustdoc clean, full suite 0 failures (4584 lib tests, +1).
  Paired: `PROBLEM_TREE` C5, §8 — same commit.
- **2026-07-12** — **SOL-REDACT extended, closing §7 S4: the dossier's
  embedded raw-archive body is now redacted at render time, archive file
  untouched.** Investigating S4's suggested fix surfaced a policy conflict:
  `util::raw_archive`'s own doc comment declares the on-disk `raw/*.json`
  retention "never encrypted, hashed, or redacted" — a deliberate operator
  directive for paid-for data, not an oversight. Redacting the archive file
  itself would violate that. The real residual was one step downstream:
  `render_full`'s "RAW SOURCE RECORDS" section embeds the archived body
  verbatim, and an explicit `hse export -o <path>` is deliberately left to
  the user's umask (unlike the auto-written 0600 dossier), so an echoed
  `api_key=…` could leave the device via a shared/exported dossier. Fixed at
  that render site: new `render_raw_response_body` runs the existing
  `redact_credentials` over the pretty-printed body before embedding it. 1
  new regression test (structural `api_key=` masking, no env mutation —
  deterministic under parallel test execution). Gate green: fmt/clippy `-D
  warnings`/rustdoc clean, full suite 0 failures (4585 lib tests, +1).
  Paired: `PROBLEM_TREE` S4, §8 — same commit.
- **2026-07-12** — **SOL-NETINT extended: the MX/SPF leg of CDN
  origin-unmasking, new correlator rule AU-111.** Built from two signals
  already collected — `waf_detect`'s CDN fingerprint and `dns_intel`'s SPF
  parse (given a new structured `domain` evidence attribute) — with zero
  new external dependency. Fires only for 8 well-known global anycast CDNs
  (Cloudflare, Akamai, Fastly, CloudFront, Sucuri, Incapsula, StackPath,
  KeyCDN), deliberately excluding the on-premise WAF appliances the same
  module fingerprints (F5 BIG-IP, Citrix NetScaler, Barracuda, ModSecurity)
  where the unmasking assumption doesn't hold — precision over recall. A
  correlation finding, not a literal `origin-candidate` entity tag (a rule
  function only borrows `&[Entity]`; matches every other cross-module
  AU-0xx inference in this codebase). 5 new regression tests, confirmed via
  `git stash` — a compile error pre-fix (the rule didn't exist), not a
  silent pass. Gate green: fmt/clippy `-D warnings`/rustdoc clean, full
  suite 0 failures (4590 lib tests, +5). Correlator rule count 108→109,
  reconciled in `ARCHITECTURE_AUDIT.md`. Still remaining on C4: passive-DNS
  history, SSL-cert-hash pivot. Paired: `PROBLEM_TREE` C4, §8 — same commit.
- **2026-07-12** — **SOL-OFFENSIVE/C6 status corrected `[ ]`→`[~]`: 2 of its
  4 named solution items were already delivered, uncredited.** Investigated
  while looking for C6's genuinely remaining work (this cycle's next unit
  after AU-111). AU-047's own doc comment already names salted-hash/
  session-token/plaintext-password/crypto-address/API-key as its complete
  linkable-secret set, consumed unconditionally by `Secret::classify` +
  the rule itself; `key_harvest` already uses SOL-F1's aho-corasick
  `MatchSet` (`contains_excluded_context`) and a Shannon entropy gate
  (`shannon_entropy`). *Genuinely remaining:* broader SERP exposure-dork
  coverage (open-ended) and richer stealer-log cross-referencing (no
  dedicated pivot mechanism found). No code change — pure status-accuracy
  correction, mirroring the C1/C5/AU-060-candidate stale-note corrections
  this register has made before. Paired: `PROBLEM_TREE` C6 — same commit.
- **2026-07-12** — **SOL-GATE extended: guarded the correlator rule-count
  drift class, found stale within this same session.** AU-111 (previous
  cycle) brought the live split to 97 entity + 12 relation = 109, but only
  `ARCHITECTURE_AUDIT.md` was reconciled — README's own "Deterministic
  correlator: 108 rules..." line went unnoticed until this cycle's
  orientation pass. Unlike the module count
  (`readme_module_overview_count_matches_registry`), no equivalent guard
  existed. New `pub fn core::correlator::rule_counts() -> (usize, usize)` +
  new architecture test `readme_correlator_rule_count_matches_registry`
  close the gap the same way. Confirmed via `git stash` to fail against the
  pre-fix (108) README text. Gate green: fmt/clippy `-D warnings`/rustdoc
  clean, full suite 0 failures (31 architecture tests, +1). Paired:
  `PROBLEM_TREE` §7 Docs — same commit.
- **2026-07-12** — **New SOL-STALE-CACHE-BACKOFF: fixed a real cross-scan
  stale-data bug and a rate-limit/quota-exhaustion conflation in
  `util::oathnet`/`util::see_know`, direct response to an operator
  diagnostic request.** `RESPONSE_CACHE` (both providers) dedups
  within-scan queries per its own doc comment, but `reset_budget()` never
  cleared it — a long-lived `hse serve`/`hse live` process silently kept
  returning the FIRST scan's cached breach/stealer records for every later
  re-scan, indefinitely. Both `reset_budget()`s now clear the cache too.
  Separately, a transient rate-limit (SeekNow `rate_limit`, OathNet 429)
  was classified identically to true quota exhaustion, permanently
  latching the shared budget for the rest of the scan with zero backoff —
  a `RetryStrategy` construct with the right-looking parameters already
  existed in `orchestration.rs` but was entirely dead code (zero call
  sites across ~1,135 lines of `orchestration.rs`/`monitoring.rs`/
  `force_multiplier.rs`, confirmed by grep — left untouched, flagged
  separately). New `util::backoff::BackoffPolicy` (generic, pure, fully
  tested, no new `rand` dependency) + `core::error::Error::RateLimited`
  give both providers' retry loops a real, live exponential backoff,
  reusing the dead constant's own numbers. 3 stale quota-figure doc
  comments reconciled against `enterprise_config.rs`. Also investigated
  the "full spectrum of modules" half of the report and found no bug — all
  dispatch skip paths are deliberate and disclosed. 11 new regression
  tests, cache-clear and rate-limit-classification ones each confirmed via
  `git stash` to fail pre-fix. Gate green: fmt/clippy `-D warnings`/rustdoc
  clean, full suite 0 failures (4601 lib tests, +11). Paired: `PROBLEM_TREE`
  T2.44 — same commit.
- **2026-07-12** — **New SOL-CIRCUIT-TOKEN-ANCHOR: hardened
  `core::engine::circuit::is_rate_limited` against bare-substring false
  positives, a regression surfaced by the background data-freshness/pacing
  audit.** The vocabulary's bare `"exceeded"`/`"credit"` tokens and
  unanchored `429`/`402` digit matching could hard-trip a healthy module for
  600s on pure coincidence — a tokio timeout's "deadline exceeded", scraped
  "credit card" text, or an echoed subject phone number merely containing
  429/402. A fix for this had already been written and tested on an
  unmerged sibling branch (`a5c5fac3`) but never landed on `main` —
  confirmed via `git merge-base --is-ancestor` (fails) and `git branch --all
  --contains` (only the sibling). Reimplemented fresh this cycle rather
  than cherry-picked, so the fix is authored and reviewed under this
  cycle's own hand: a curated `QUOTA_PROSE` list of multi-word compounds
  replaces the bare tokens, and `429`/`402` now match only as a standalone,
  non-alphanumeric-delimited token. Anything else still falls through to
  the existing 3-strike soft-failure path. 3 new regression tests (2
  pure-classifier, 1 full `record_error`/`is_open` stateful integration),
  all confirmed via `git stash` to fail pre-fix. Gate green: fmt/clippy `-D
  warnings`/rustdoc clean, full suite 0 failures (4604 lib tests, +3).
  Live-verified against the real `hse` binary and the project's canonical
  acceptance-test seed (`Kylo4kylo`); the exact coincidental false-positive
  substring was not naturally reproduced in that specific live run, noted
  honestly rather than overclaimed. Paired: `PROBLEM_TREE` T2.45 — same
  commit.
- **2026-07-12** — **New SOL-SEARCH-LIVENESS-RESET: `search_engines::
  SESSION_EMPTY_COUNTS` never reset per-scan — the second finding from the
  same background data-freshness/pacing audit, the same bug class as
  SOL-STALE-CACHE-BACKOFF.** The process-global engine-liveness map
  correctly silences a block-streaking engine and correctly exempts a
  proven-live one within one scan, but was never cleared by
  `modules::install_core_hooks`'s `reset_per_scan`, unlike
  `oathnet_pro`/`see_know`/`wigle`'s per-scan state — confirmed by reading
  the hook body directly. Under a long-lived `hse serve`/`hse live` process
  both a silencing and a proven-live exemption leaked across scan
  boundaries: an engine silenced against one target stayed silenced against
  a later, different target indefinitely. New `search_engines::
  reset_session_liveness()` clears the whole map; wired into
  `reset_per_scan` alongside the existing three providers. 1 new regression
  test, confirmed via `git stash` as a compile error pre-fix (the function
  didn't exist) and a runtime pass post-fix. Gate green: fmt/clippy `-D
  warnings`/rustdoc clean, full suite 0 failures (4605 lib tests, +1).
  Live-verified: a real `hse serve` process ran `reset_per_scan` — including
  the new call — cleanly across two distinct real scan IDs with zero
  panics; reproducing the exact silence-then-unsilence symptom across a
  genuine block streak would need a longer live session than this pass
  covered, noted honestly rather than overclaimed. Paired: `PROBLEM_TREE`
  T2.46 — same commit.
- **2026-07-12** — **New SOL-PROVIDER-OVERHAUL (`[~]`): began the
  operator-directed "overhaul the entire external provider-integration layer"
  program; first slice repaired `domainsdb`.** Scope confirmed via
  `AskUserQuestion` — external OSINT provider integrations, "populate" =
  wire in the tool's existing key machinery, not external account
  registration or credential harvesting. A live probe of the real
  `api.domainsdb.info` caught that the provider had disabled anonymous
  access (`401 "Anonymous access is disabled"`), and the module — registered
  `Free` — silently swallowed that 401 on every scan and emitted nothing.
  Reclassified `Free`→`KeyGated`, registered `HUNTSMAN_DOMAINSDB_KEY`
  (KNOWN_KEYS + signup_hint), key resolved first (clean "needs key" skip
  when unset), `Authorization: Bearer` sent when configured, `401`/`403` on
  a configured key reported to the pool + loop-break instead of swallowed.
  2 git-stash-proven tests; gate green (4608 lib tests, +1); live-verified
  against the REAL provider (no-key clean skip on a real `github.com` scan;
  bogus-key → real Bearer dial → `403 {"Insufficient credits"}` broken-on
  after one zone). Remaining: audit the other ~32 keyed/paid provider
  clients for the same live-contract breakage class (tracked). Paired:
  `PROBLEM_TREE` T2.48 — same commit.
- **2026-07-12** — **SOL-PROVIDER-OVERHAUL slice 2: repaired
  `huggingface_user` after HF migrated its profile API endpoint; a
  comprehensive live audit mapped the rest of the layer.** The background
  audit live-probed every module's real external endpoint and confirmed 4
  breaks (domainsdb ✅, huggingface_user ✅ here, sourceforge_user +
  opencorporates + mls tracked) while clearing the rest of the free-tier
  external-API surface as healthy. `huggingface_user`'s
  `GET /api/users/{handle}` now 404s for every real user (live-confirmed
  against julien-c/osanseviero/clem/thomwolf); `fetch_json_or_404` mapped
  that to `Ok(None)`, so the module silently emitted nothing on every scan.
  The live endpoint is `…/{handle}/overview`, whose shape moved the handle to
  a `user` field and added `createdAt` while dropping the public email/
  website/twitter fields entirely. Repointed the endpoint, rewrote the
  `HfUser` deserializer + identity guard, added the real `account_created`
  date as evidence, and removed the now-dead email/website/twitter
  extraction (updating `produces()` to match). Real-`/overview`-body deser
  regression + 6 others, git-stash-proven (compile error pre-fix). Gate
  green: fmt/clippy `-D warnings`/rustdoc clean, full suite 0 failures (4607
  lib tests). Live-verified end-to-end against the REAL API: a real
  `julien-c` scan now emits 70 real entities (was 0 pre-fix), carrying the
  real 2019 account-creation date. Paired: `PROBLEM_TREE` T2.49 — same
  commit.
- **2026-07-12** — **SOL-PROVIDER-OVERHAUL slice 3: repaired + enriched
  `sourceforge_user` after SF removed its legacy user API.**
  `GET /api/user/username={h}/json` now returns SourceForge's HTML 404 for
  every real user (live-confirmed against `jonelo`), read as a clean "no such
  user," so the module emitted nothing on every scan. The live Allura
  endpoint `GET /rest/u/{handle}` is a richer shape: handle in `name`, real
  name in the matching `developers[]` record, plus `creation_date`,
  `external_homepage`, `socialnetworks[]`. Repointed the endpoint, rewrote
  `SfUser` (+ `SfSocial`/`SfDeveloper`), took the real name from the matching
  developer record (guarded against misattributing a non-matching record),
  added the account-created date as evidence and NEW homepage (Url+Domain) +
  social-account-URL extraction, dropped the now-absent bio-email/location
  extraction, and updated `produces()`/`attack_techniques()` (email/location
  techniques removed; `T1593.001` social added). 11 tests (was 8), incl. a
  real-`/rest/u/`-body deser regression + a non-matching-developer guard,
  git-stash-proven (compile error pre-fix). Gate green: fmt/clippy `-D
  warnings`/rustdoc clean, full suite 0 failures (4610 lib tests). Live-verified
  end-to-end against the REAL API: a real `jonelo` scan recovers the confirmed
  handle, profile URL, and the real name "Johann N. Löfflmann" (from
  `developers[].name`) with the real 2011-03-12 creation date — was 0 pre-fix.
  Paired: `PROBLEM_TREE` T2.50 — same commit.
- **2026-07-12** — **SOL-PROVIDER-OVERHAUL slice 4: key-gated `opencorporates`
  (same class as domainsdb).** OpenCorporates withdrew its keyless public tier
  (2023) — a keyless request now returns `401 {"Invalid Api Token"}` — but the
  module used `key_opt` at `Free`, firing a doomed request and swallowing the
  401 into an empty result with no needs-key notice. Applied the T2.48
  template: `Free`→`KeyGated`, `key_opt`→required `ctx.key(KEY_ENV)?` (clean
  "needs key" skip when unset), and a configured-key 401/403 reported to the
  key pool for rotation instead of swallowed. 2 tests (`module_metadata` now
  asserts KeyGated — a runtime assertion git-stash-proven to fail against the
  pre-fix `Free`; + a missing-key process test). Gate green: fmt/clippy `-D
  warnings`/rustdoc clean, full suite 0 failures (4611 lib tests).
  Live-verified against the REAL API: no key → `dispatch` then `skipped —
  needs key HUNTSMAN_OPENCORP_KEY` on a real `Atlassian` organisation scan;
  `--free-only` filters it out up front. Paired: `PROBLEM_TREE` T2.51 — same
  commit.
- **2026-07-12** — **SOL-PROVIDER-OVERHAUL slice 5 (node `[~]`→`[x]`): deleted
  the decommissioned `mls` module, closing the audit's confirmed break-set
  (T2.48–T2.52).** Mozilla retired MLS; its `geolocate` endpoint 404s and the
  module swallowed that into empty, so BSSID geolocation via it always
  produced nothing. Its own doc called it a redundant "third source alongside
  WiGLE and Mylnikov," and `mylnikov` (free, live) + `wigle` already cover the
  identical `MacAddress`→`Coordinates` lookup — so it was deleted rather than
  repointed into a duplicate. Removed the module + registry wiring + 2 stale
  doc-comment mentions, and reconciled the module counts across
  README/`MODULES.md` (`162`→`161`, tier split corrected for this deletion and
  the earlier domainsdb/opencorporates Free→KeyGated reclassifications; `mls`
  row removed; stale free→key_gated labels fixed). Gate green: fmt/clippy `-D
  warnings`/rustdoc clean, full suite 0 failures (4601 lib tests; the two
  module-count arch-tests confirm the live registry is 161). Live-verified:
  `hse modules` no longer lists `mls`, while `mylnikov` + `wigle` remain.
  With all five audit-confirmed breaks now repaired or retired, the entire
  external provider-integration layer has been live-audited and reconciled;
  the node is complete. Paired: `PROBLEM_TREE` T2.52 — same commit.
- **2026-07-12** — **New SOL-CACHE-TEST-ISOLATION: fixed two flaky
  `util::see_know` cache tests — a real CI-reliability defect surfaced during
  the provider overhaul.** A full `cargo test` run failed once on
  `reset_budget_clears_the_cross_module_response_cache` (~1-in-3 repro).
  `RESPONSE_CACHE` is a process-global `static` cleared by any concurrent
  scan-running test (via `reset_per_scan`), so two tests' read-after-write on
  it could be cleared out from under them; the in-file `BUDGET_TEST_LOCK`
  can't serialise against out-of-file clearers (confirmed via a deterministic
  stress reproduction, since removed). Fixed by retrying the put/get until the
  unique key is observed present, keeping the real contract assertion
  unchanged. Gate green; the full lib suite, previously ~1-in-3 flaky, now
  passes 8/8 consecutive runs (4601 lib tests). Paired: `PROBLEM_TREE` T2.53 —
  same commit.
- **2026-07-12** — **New SOL-PROVIDER-FIELD-DECODE slice 1: restored
  `hexpm_user`'s email + GitHub/X cross-platform pivots, dead against the live
  API.** A fresh discovery pass (field-level decode correctness, distinct from
  the endpoint-reachability provider overhaul) found the top-level `email` was
  never deserialised and the `handles` map is keyed by display names
  (`"GitHub"`, `"X.com"`) with full-URL values — so the module's advertised
  enrichment silently produced nothing (its tests passed only on a fabricated
  lowercase-key/bare-handle shape). Added `email`+`inserted_at` (+`Email`
  entity, account-age evidence), matched handles on the lowercased key,
  extracted the handle from the URL value via a new `handle_from_link`,
  sorted the `HashMap` iteration for determinism, and updated
  `produces()`/`attack_techniques()`. 11 tests (was 7), incl. a real-body
  deser regression + direct `handle_from_link` tests, git-stash-proven
  (compile error pre-fix). Gate green: fmt/clippy `-D warnings`/rustdoc clean,
  full suite 0 failures (4605 lib tests). Live-verified end-to-end against the
  REAL API: a real `wojtekmach` scan recovers `wojtek@wojtekmach.pl` and the
  GitHub + X/Twitter pivots (was neither pre-fix). Remaining in the cluster:
  `codeberg_user`, `crates_io`. Paired: `PROBLEM_TREE` T2.54 — same commit.
- **2026-07-12** — **SOL-PROVIDER-FIELD-DECODE slice 2: fixed both Forgejo
  modules' handling of the top-level profile `email` — a dropped field on
  `codeberg_user`, a false-positive finding on `gitea_user`.** The identical
  Forgejo API (Codeberg + Gitea) returns a top-level `email` that is either a
  real address or a platform-minted masking placeholder
  (`user@noreply.codeberg.org`, `user@users.noreply.gitea.io`) when the user
  hides their email. Confirmed live on both hosts (`earl-warren`,
  `techknowlogick`). `codeberg_user` had no `email` field at all, so a real
  published address was silently dropped; `gitea_user` emitted the masking
  placeholder verbatim as an Email finding — a fabricated contact pivot, exactly
  what this evidentiary tool must not produce. The masking lives in the DOMAIN,
  so the existing local-part role/infra checks missed it. Added a single-sourced
  `util::domains::is_noreply_email_domain` (matches any `noreply`/`no-reply`/
  `donotreply` domain label), added the `email` field + a filtered Email branch
  to `codeberg_user`, and gated `gitea_user`'s existing branch through the same
  filter so both siblings agree. 5 new tests (helper unit coverage +
  emit/skip/real-deser on both modules), git-stash-proven (codeberg tests fail
  to compile against the field-less struct; gitea no-reply test fails against
  the un-filtered branch). Gate green: fmt/clippy `-D warnings`/rustdoc clean,
  full suite 0 failures (4610 lib tests, +5). Live-verified: both hosts' real
  `@noreply.*` users now emit NO Email for the placeholder. Remaining in the
  cluster: `crates_io`. Paired: `PROBLEM_TREE` T2.55 — same commit.
- **2026-07-12** — **SOL-PROVIDER-FIELD-DECODE slice 3 (node closed):
  `crates_io` dropped the account-creation date every sibling code-registry
  module records.** The live `crates.io/api/v1/users/{login}` response carries
  a top-level `created_at` on every real account (confirmed against `dtolnay`
  `2012-07-09T03:55:40Z` and `alexcrichton` `2009-03-19T19:31:50Z`), but
  `CrateUser` never deserialised it — so the account-age signal that
  `gitea_user`/`codeberg_user` (`created`) and `hexpm_user` (`inserted_at`)
  all surface was silently dropped. Added `created_at` to `CrateUser` and emit
  it as the `created_at` evidence attr on the confirmed-username entity
  (empty-string guarded, matching the `avatar_url`/`name` attr pattern);
  refreshed the module-doc example JSON to the real shape. 2 new tests
  (`deserialises_real_shape_and_surfaces_created_at`, a verbatim-live `dtolnay`
  body; + a blank-`created_at` guard), git-stash-proven (`error[E0609]: no
  field created_at on type &CrateUser`). Gate green: fmt/clippy `-D
  warnings`/rustdoc clean, full suite 0 failures (4612 lib tests, +2).
  Live-verified end-to-end: a real `dtolnay` scan's JSON export now carries
  `"created_at": "2012-07-09T03:55:40Z"` on the username evidence (absent
  pre-fix). This closes the SOL-PROVIDER-FIELD-DECODE cluster — all three
  live-reachable field-decode drifts (hexpm / codeberg+gitea / crates)
  repaired. Paired: `PROBLEM_TREE` T2.56 — same commit.
- **2026-07-12** — **New SOL-CORRELATOR-INTEGRITY slice 1: AU-081 counted the
  tool's own name derivation as an independent record — manufactured
  corroboration in the identity core.** An exhaustive correlator
  evidentiary-integrity audit (one finder per rule family fanned out via the
  Workflow tool, each finding adversarially re-verified through two independent
  lenses — correctness + evidentiary-materiality) found that
  `rule_au_081_canonical_person_name_match` built its two independence gates by
  hand from the raw `evidence` list (source-string set + `source_family` set)
  with NO `is_non_corroborating_source` filter, diverging from every sibling
  (`source_families`/`source_count`/`corroborating_sources`) that build the
  honest cross-correlation set precisely to exclude the deterministic
  self-enrichment passes. `name_intel` DERIVES a `Person` from the seed name and
  maps to the real `identity_registry` family, so a genuine record
  (`github_user`→"code" / `oathnet_pro`→"breach") plus a same-name
  `name_intel`-only entity cleared both gates (different source string, different
  family) and fired a High "independently-sourced records for the same
  individual" — the tool corroborating its own guess, the exact "finding
  outruns its evidence" failure this engine forbids. Fixed by routing both gates
  through `Entity::corroborating_sources()` and adding a gate (0) that skips when
  either side has no corroborating source at all; the match is now labelled by
  its first genuine source, never the enrichment pass. Uses only already-collected
  data. 2 adversarial tests: must-not-fire (`github_user`+`name_intel`-only →
  empty; git-stash-proven to FIRE against the pre-fix rule) and a must-fire
  control (a real code+breach match survives even when `name_intel` also
  enriched one side, and is labelled by the genuine source). Gate green:
  fmt/clippy `-D warnings`/rustdoc clean, full suite 0 failures (4614 lib tests,
  +2). Real-evidence anchor: a live `name_intel`-only scan of the public figure
  "Ada Lovelace" confirmed the module emits a `Person` sourced solely by
  `name_intel` (the full cross-source firing was NOT staged against a real
  private individual — evidentiary/privacy — the firing path is unit-proven).
  The audit banked further candidates (AU-017/030/048/056/085/099/105) for later
  cycles; this cycle closes exactly one gap. Paired: `PROBLEM_TREE` T2.57 — same
  commit.
- **2026-07-12** — **New SOL-DEADCODE-SWEEP slice 1: deleted the dead
  `util::see_know` "enterprise optimization" scaffolding — 4 unwired `pub mod`s
  that looked built but reached no live call site.** A per-directory dead-code
  sweep (one scanner per top-level module dir fanned out via the Workflow tool,
  each claimed-dead item adversarially re-verified by an agent trying to PROVE
  it live) targeting the trap the `dead_code` lint misses: a `pub` item in a
  `pub mod` compiles clean with zero consumers. Resolves the decision T2.44
  explicitly deferred. `util::see_know` declared five `pub mod`s but `mod.rs`
  re-exported nothing from four. Tracing the REAL import graph (a bare grep
  falsely flagged the live `enterprise_config`, which `budget.rs` consumes via
  `ENTERPRISE`, and matched a same-named struct field + unrelated comments):
  `orchestration` has zero consumers; `endpoint_matrix` is used only by the dead
  `orchestration`; `force_multiplier`/`monitoring` have zero path-refs anywhere
  incl. tests. All four duplicate live capability (a hardcoded endpoint table,
  an API-key cascade, an execution planner, an enterprise metrics dashboard) the
  real see_know client (`budget`/`client`/`endpoints`) + the engine already
  provide; the one useful artefact (`RETRY_STRATEGY` backoff numbers) was already
  salvaged into `util::backoff` by T2.44. Decision: DELETE (wiring would invent
  consumers for redundant speculative scaffolding). Removed
  `force_multiplier.rs`/`monitoring.rs`/`orchestration.rs`/`endpoint_matrix.rs`
  (~1,529 lines) + their `pub mod` decls + the obsolete, unreferenced
  `docs/HARDCODED_ENTERPRISE_OPTIMIZATION.md`; `enterprise_config` kept. The
  compiler proves the deletion safe (lib + full suite build clean). Gate green:
  fmt/clippy `-D warnings`/rustdoc clean, full suite 0 failures (4614 lib tests,
  unchanged — the dead code had no live tests). No live run applies — the code
  was unreachable, which IS the finding; the compiler-proved-safe deletion +
  green suite are the documented verification (an explicit exception to the
  live-run preference, since there is no reachable path to exercise). The sweep
  banked `util::multi_api_*` dead consts/module and the dead fns
  `fetch_post`/`refresh_pool`/`set_environment` for later cycles. Paired:
  `PROBLEM_TREE` T2.58 — same commit.
- **2026-07-12** — **SOL-DEADCODE-SWEEP slice 2: deleted the dead
  `util::multi_api_*` "enterprise orchestration" subsystem — 2,443 lines of
  parallel reimplementation wired to zero production call sites.** Four `pub
  mod`s (`multi_api_config`/`multi_api_workflows`/`multi_api_orchestrator`/
  `multi_api_integration_tests`) from the same earlier autonomous-validation
  experiment as slice 1 (T2.58). Verified provably unwired: every public symbol
  (`generate_multi_api_plan`, `MultiApiOrchestrator`, `ADVANCED_WORKFLOWS`,
  `BUDGET_ALLOCATION`, `API_RELIABILITY`, …) has 0 references outside the four
  files; `config`/`orchestrator` are consumed only by the `#[cfg(test)]`
  `integration_tests` module, and `workflows` by nothing at all. The subsystem
  re-implements, from a hardcoded stale "12 paid APIs" table, the
  orchestration/budgeting/intelligent-chaining/entity-dedup that
  `core::engine::dispatch` already does natively against the live 160+ module
  registry — so its passing integration tests gave false assurance of real,
  exercised capability. Decision: DELETE (wiring would replace the live engine's
  orchestration with a hardcoded parallel planner predating the current
  registry — a massive change duplicating live capability). Removed the four
  files (~2,443 lines) + their `pub mod` decls + the obsolete, unreferenced
  `docs/MULTI_API_ENTERPRISE_ORCHESTRATION.md` (514 lines). The compiler proves
  the deletion safe (lib + full suite build clean). Gate green: fmt/clippy
  `-D warnings`/rustdoc clean, full suite 0 failures (4569 lib tests, −45 —
  every removed test lived in the deleted `integration_tests` and exercised ONLY
  the deleted code; no production test lost). No live run applies — the code was
  unreachable, which IS the finding; the compiler-proved-safe deletion + green
  suite are the documented verification (an explicit exception to the live-run
  preference — no reachable path exists to exercise). Banked for later cycles:
  `util::autonomous_validation` (a separate self-contained dead island) + the
  dead fns `fetch_post`/`refresh_pool`/`set_environment`. Paired: `PROBLEM_TREE`
  T2.59 — same commit.
- **2026-07-12** — **SOL-DEADCODE-SWEEP slice 3: deleted the dead
  `util::autonomous_validation` module — the last island of the
  autonomous-validation experiment.** A single self-contained file whose own
  doc-comment states it exists to "prove multi-API orchestration works
  end-to-end" — i.e. it validated the `multi_api_*` orchestration deleted in
  slice 2, so it is now definitively dead. Verified all 7 public symbols
  (`OsintEntity`, `AutonomousValidationReport`, `parse_osint_entity`,
  `detect_apis_from_entities`, `find_dedup_candidates`, `find_correlation_groups`,
  `validate_orchestration`) have 0 references outside the file; the module path
  is imported nowhere; it carried 9 self-referential tests. Decision: DELETE —
  the subsystem it validated is gone, and its dedup/correlation heuristics are a
  toy parallel to the real `core::correlator` + GREATEST-merge identity model.
  Removed the file + its `pub mod` decl. The compiler proves the deletion safe
  (lib + full suite build clean). Gate green: fmt/clippy `-D warnings`/rustdoc
  clean, full suite 0 failures (4560 lib tests, −9 — every removed test lived in
  the deleted module and exercised only it; no production test lost). No live
  run applies — the code was unreachable (that IS the finding). This closes the
  autonomous-validation experiment cleanup: slices 1–3 (see_know scaffolding /
  multi_api / autonomous_validation) removed ~4,000 dead lines total. Backlog
  banked: `enterprise_config` dead consts, scattered dead/wire-in fns, and
  `core`/`storage`/`modules` items surfaced by the sweep. Paired: `PROBLEM_TREE`
  T2.60 — same commit.
- **2026-07-12** — **SOL-DEADCODE-SWEEP slice 4: wired the unused
  `core::profiles::list_profiles` catalogue into the CLI — the sweep's first
  WIRE-IN decision (not a delete).** `list_profiles()` returns every scan
  profile as `(name, one-line description)`; its doc-comment claimed the CLI
  `--help` / API-SPA picker rendered it, but the sweep found 0 callers — the
  wiring never existed. Meanwhile the CLI's unknown-`--profile` error hand-typed
  its own name list ("try: recommended, passive, footprint, investigate, fast,
  skiptrace"), a copy that would drift the next time a profile is added and that
  never surfaced the descriptions. Unlike the T2.58–T2.60 scaffolding this is a
  REAL capability that should be reachable, so the decision is WIRE-IN, not
  delete: the error now renders `list_profiles()` as `name — description` lines,
  so the help is sourced from the single catalogue `resolve_profile` is checked
  against AND tells the operator what each profile does. Proved against a REAL
  target: `hse scan --kind username --value testuser --profile bogus` prints all
  six profiles with their descriptions (previously invisible anywhere in the
  CLI) — genuine new observable output through the now-live path, not a synthetic
  no-op. Extended `apply_named_profile_rejects_unknown_name` into a drift guard
  (asserts every `list_profiles()` name AND description appears), git-stash-proven
  to fail against the pre-wire hardcoded error (which carried no descriptions).
  Gate green: fmt/clippy `-D warnings`/rustdoc clean, full suite 0 failures
  (4560 lib tests). Paired: `PROBLEM_TREE` T2.61 — same commit.
- **2026-07-12** — **SOL-DEADCODE-SWEEP slice 5: trimmed dead scaffolding consts
  from the surviving `see_know::enterprise_config` — finishes the see_know
  cleanup.** T2.58 kept this file because `budget.rs` reads its `ENTERPRISE`
  plan config, but it still carried 7 speculative hardcoded tables (`WORKFLOWS`,
  `DAILY_RECOMMENDATIONS`, `API_KEY_PATTERNS`, `ENTITY_EXTRACTORS`,
  `MONITORING_THRESHOLDS`, `SLA`, `WORKFLOW_RECOMMENDATIONS`), each with its own
  dedicated struct (`ScanProfile`/`DailyRecommendation`/`ApiKeyPattern`/
  `EntityExtractor`/`MonitoringThreshold`/`ServiceLevelAgreement`/
  `WorkflowRecommendation`) instantiated only by that dead const. Verified every
  const AND struct has 0 references outside the file; they duplicate capability
  HSE has natively (`API_KEY_PATTERNS`/`ENTITY_EXTRACTORS` overlap
  `util::found_keys`/`oathnet_pro::key_harvest` + `core::entity` extraction;
  `WORKFLOWS`/`WORKFLOW_RECOMMENDATIONS` overlap `core::profiles`). Decision:
  DELETE — trimmed the file to just the live `EnterprisePlan` struct +
  `ENTERPRISE` const (~406 lines removed). The compiler + clippy `-D warnings`
  prove the trim safe (build clean, and clippy confirms no `EnterprisePlan`
  field became newly-unused). Gate green: fmt/clippy/rustdoc clean, full suite 0
  failures (4560 lib tests, unchanged — the dead consts had no tests). No live
  run applies (unreachable data — that IS the finding). This finishes the
  see_know cleanup: T2.58 removed the four dead submodules, T2.62 removes the
  dead consts from the one kept file, leaving it 100% live. Paired:
  `PROBLEM_TREE` T2.62 — same commit.
- **2026-07-12** — **SOL-DEADCODE-SWEEP slice 6: deleted two isolated dead
  `pub fn`s (`util::curl::fetch_post`, `util::key_pool::pool::set_environment`).**
  Standalone helpers in otherwise-live modules (so the `dead_code` lint never
  fired), 0 references anywhere including tests. `fetch_post` is the redundant
  `UA_MOBILE` POST variant — its `_with_ua` sibling is live in `search_engines`,
  so `curl_exec`'s POST path stays; `set_environment` post-hoc reassigns a pool
  key's environment label, which is already set at key-add time. Own-decision
  verification corrected two sweep mislabels in the same area:
  `core::path::shortest_path` and `core::validation::validate_for_kind` are NOT
  0-ref (test-only and re-exported respectively), so they were deferred as their
  own wire-in-vs-delete steps rather than deleted blind. Decision: DELETE (both
  are redundant, neither a capability gap). Compiler + clippy `-D warnings` prove
  it safe (no cascade of newly-dead helpers). Gate green: fmt/clippy/rustdoc
  clean, full suite 0 failures (4560 lib tests, unchanged — no tests referenced
  them). No live run applies (unreachable code — that IS the finding). Paired:
  `PROBLEM_TREE` T2.63 — same commit.
- **2026-07-12** — **SOL-DEADCODE-SWEEP slice 7: deleted the inert proxy-rotation
  subsystem — a whole "looks built but isn't" trap the earlier sweeps missed
  because it hides behind a `pub` FIELD, not a `dead_code` lint.** A re-run wide
  reference-count sweep + hand-verification found `util::proxy::ProxyPool`
  constructed as `ProxyPool::new()` in every runtime (scan/serve/live/radar/
  provision/api) and threaded into `ModuleContext.proxy_pool` with a doc-comment
  asserting "modules call `ctx.proxy_pool.next()` to rotate" — but NOTHING fills
  the pool (`refresh_pool`, the sole `pool.replace()` caller, has 0 call sites)
  and NOTHING reads it (`next()` has 0 call sites; no module, CLI flag, or
  route). A stale `search_engines/fetch` comment claimed a proxy-pool fallback
  that was never wired; the real live proxy path is the independent
  `HUNTSMAN_SEARCH_PROXY` → `util::curl::fetch_via_proxy` single upstream, which
  stays. The SSRF guards live in `util::preflight`/`util::http::ssrf`, NOT
  `util::proxy`, so the subsystem is self-contained. Decision: DELETE — wiring
  auto-harvest+rotation fully (fill on startup AND route every module's HTTP
  through `next()`, then validate against live proxies) exceeds one safe pass and
  can't be reliably proven (free-proxy harvesting is flaky), and the doctrine's
  precedent is to delete unwired scaffolding. Removed `src/util/proxy/` (311
  LOC), the field from `ModuleContext`/`AppState`, all 8 construction sites, ~45
  test-harness initializers, and the stale comments; TIGHTENED
  `tests/architecture.rs` by removing the now-obsolete `util::proxy::ProxyPool`
  exception to "core must not import util" (a strengthening, never a weaken).
  Compiler + clippy `-D warnings` across `--all-targets` prove the removal
  complete (no dangling refs, no newly-dead cascade). ✅ Live-verified (a deletion
  has no wire-in run, but the field was threaded through every dispatch, so the
  live scan path IS the proof): the rebuilt binary runs `hse selftest` 9/9 and
  `hse scan -v Kylo4kylo` dispatched 46 modules → 96 entities — the
  `ModuleContext` pipeline intact without the field. Gate green: fmt/clippy/
  rustdoc clean, full suite 0 failures (4565 lib tests, −4 — the proxy module's
  own tests, deleted with it). Paired: `PROBLEM_TREE` T2.70 — same commit.
- **2026-07-12** — **SOL-DEADCODE-SWEEP slice 8: wired in the scan-completion
  webhook that was configured but never fired (the second WIRE-IN, counterpart to
  the T2.70 sweep).** `core::webhook::notify_scan_complete` — the fire-and-forget
  POST of a `scan_complete` JSON (scan id, target, entity/correlation counts,
  status) — had zero callers. But it was NOT dead-to-delete: `webhook_url_from_env()`
  is wired (`cli/scan`/`cli/live` read `HUNTSMAN_WEBHOOK_URL` into
  `ScanOptions.webhook_url`), so an operator who set the env var got the URL
  stored and NOTHING else — the last step, the actual POST, was missing, and the
  module's own doc claimed the engine fired it on completion. Decision: WIRE-IN
  (a genuine, useful, deterministically-provable integration point). `finalise_scan`
  now fires `notify_scan_complete` once the scan reaches a terminal state, if
  `scan.options.webhook_url` is set. It runs in the async context AFTER the
  `spawn_blocking` finalise (the POST is async, the finalise is blocking), builds
  the payload from the completed scan (`scan.target` / `scan.entity_count` /
  `scan.status` + the store's correlation count), and stays fire-and-forget
  (bounded 10 s, never errors) so a dead endpoint can't stall or fail the scan.
  Fires for every terminal state; the `status` field distinguishes complete /
  aborted / failed. ✅ Proven against a REAL target (per the directive): a local
  HTTP sink + `HUNTSMAN_WEBHOOK_URL=http://127.0.0.1:PORT/hook … hse scan -v
  Kylo4kylo` captured the real POST — `{"event":"scan_complete","target_value":
  "kylo4kylo","entity_count":141,"status":"aborted","correlations_count":7,…}` —
  where the pre-fix binary sent nothing. THEN a git-stash-proven regression test
  (`scan_completion_fires_the_configured_webhook`: a one-shot local TCP sink + a
  real `engine.run` with `webhook_url` set asserts the `scan_complete` POST
  arrives; against the unwired engine the `recv_timeout` elapses and the test
  fails); the test pins `regional_search: false` so its live scan can't race the
  `search_engines::build_queries` unit tests on the process-global regional flag.
  Gate green: fmt/clippy `-D warnings`/rustdoc clean, full suite 0 failures (4566
  lib tests, +1). Paired: `PROBLEM_TREE` T2.71 — same commit.
- **2026-07-13** — **SOL-HEALTH-SIGNAL: T2.7's golden-fixture corpus, first
  slice — a REAL Brave SERP capture proving the pattern before the rest of
  the corpus.** The node's other named leg ("saved real responses per
  scraper, so a layout change fails a test deterministically") spans 17
  `search_engines` engines plus three AU scrapers; landing all of them in one
  cycle is breadth over depth, so this slice does ONE real engine first. Live
  Brave SERP fetch for the canonical seed `Kylo4kylo`, checked in verbatim as
  `src/modules/search_engines/fetch/testdata/brave_kylo4kylo.html` (210 KB,
  unmodified — not a hand-crafted fragment like the module's existing
  inline-literal tests, which can't reproduce a real SvelteKit-shell /
  footer-chrome page's failure modes). New test
  `parse_results_extracts_from_a_real_brave_serp_capture` pins the parser's
  yield against this real page: exactly 26 organic results, three specific
  known hits present (Instagram/Wikipedia/YouTube), zero engine-chrome
  leakage. Git-stash-proven: neutering `parse_results` to return early fails
  the test; restored, it passes. Gate green: fmt/clippy `-D warnings`/rustdoc
  clean, full suite 0 failures (4567 lib tests, +1). No PII concern — public
  SERP for the project's own consented canonical seed; the one email/phone
  the capture happens to contain is a Vienna restaurant's own public
  Tripadvisor business listing, not a private individual's data. Remaining
  corpus slices (each its own future cycle): the AU scrapers (needs a
  privacy-safe capture — e.g. the AEC's real "not enrolled" response for a
  guaranteed-no-match synthetic name, never a real citizen's record) and the
  other 16 `search_engines` engines (lower marginal value — they share the
  identical parser this fixture already exercises; Bing's distinct
  `<cite>`-based format is the next-highest-value addition). Paired:
  `PROBLEM_TREE` T2.7 — same commit.
- **2026-07-13** — **SOL-DEADCODE-SWEEP slice 9: wired weak-findings triage into
  `hse doctor`, re-scoping the sweep's original `hse audit` suggestion.**
  `Store::low_confidence_evidence` (every stored entity below the review
  threshold, weakest-first, module-resolved) was fully built and tested with
  zero callers. Its own doc frames it as cross-scan triage ("the audit trail
  an LE/defence reviewer reads to find what should NOT yet be trusted"); `hse
  audit` scores one scan/source and the query has NO `scan_id` filter at all,
  so wiring it there would blend unrelated scans' weak entities into a single
  investigation's evidentiary score — the wrong-scope contamination this
  project's correlator audits (AU-056/AU-085, AU-105, T2.69's GEXF
  co-occurrence fix) have repeatedly closed elsewhere. Decision: WIRE-IN, into
  `hse doctor` instead — the established cross-scan operator dashboard
  (T2.7/SOL-HEALTH-SIGNAL's scraper-health signal is the direct precedent: same
  "query, impure" / "format, pure and testable" split, same already-open
  `Store` handle reused). New "Weak findings" section right after Scraper
  health; new pure `format_weak_findings(&[EvidenceAnomaly]) -> String` caps
  the printed list at 20 rows with a remainder count; `EvidenceAnomaly`
  newly re-exported from `storage` (`pub use entities::EvidenceAnomaly;` —
  it was unreachable outside its own private `mod entities;` before this).
  ✅ Live-proven FIRST (per the cycle's order): a fresh empty DB correctly
  reports "no weak findings"; a real 96-entity `Kylo4kylo` username scan
  (every entity ≥0.40 confidence) ALSO correctly reports "no weak findings" —
  the honest-empty-state contract holds, nothing fabricated; a real name-seed
  scan that genuinely triggers `name_intel`'s permutation-pivot path
  (`PIVOT_CONF = 0.20`, below the 0.30 threshold) makes the section populate
  with real data: "117 weak finding(s)," weakest-first, `name_intel` correctly
  resolved as the producing module, capped at 20 rows + "and 97 more." THEN 3
  git-stash-proven regression tests on the pure formatter (empty case;
  weakest-first + confidence/module/uid/date rendering; the 20-row cap +
  remainder count — neutering the formatter to always return the empty
  message fails the two non-empty-case tests, restored it passes). Gate green:
  fmt/clippy `-D warnings`/rustdoc clean, full suite 0 failures (4570 lib
  tests, +3). Paired: `PROBLEM_TREE` T2.72 — same commit.
- **2026-07-13** — **SOL-DEADCODE-SWEEP slice 10: restored a real,
  previously-fixed, previously-quantified bug that got lost off a diverged
  branch — `oathnet_pro`/`see_know` minting a spurious Person from a
  doubled-username breach `full_name`.** `is_username_derived_name` was fully
  built with zero callers. Git archaeology found commit `63d13142`
  (2026-06-24, "reject username-derived Person entities from breach full_name
  field") had already fixed this exact bug with a real call site and a
  passing test, quantified by a real live scan: target `full_name =
  "rhino-ryno23 rhino-ryno23"` produced 123 entities, 94% noise —
  `EntityKind::Person → TargetKind::FullName` spawns a child scan that runs
  free-text search AND `name_intel` permutation on the garbage name. That
  commit sits on a branch that is not an ancestor of `main`, so only the
  predicate survived into HEAD (since refined: hyphen+digit, not bare-hyphen
  — a real improvement, `"Smith-Jones"` no longer false-positives) — the
  wiring, the guard, and the paired tree entries (P-USERNAME-NAME /
  SOL-USERNAME-NAME) did not. Both `oathnet_pro/breach.rs` AND
  `see_know/extract/mod.rs` share the identical unguarded pattern (breach
  `full_name`/`display_name`/`name` → `Entity::new(EntityKind::Person, ...)`,
  gated only on length/whitespace) — a live gap on `main` right now, not
  hypothetical. Decision: WIRE-IN at BOTH real construction sites — not the
  generic `dispatch.rs` admission gate a first pass considered, but the
  historically-validated insertion point at each module's own
  entity-construction site (closer to the source, no wasted allocation).
  Also dropped the predicate's permanently-unused second parameter
  (`_query_value: &str` — reserved "for future tightening" in the original
  commit, never read by either version of the body, and no current call site
  has anything meaningful to pass) since this cycle is its first real caller
  — simplified to `is_username_derived_name(name: &str) -> bool`. ✅
  Live-verified: rebuilt the binary and ran a real scan of the canonical seed
  `Kylo4kylo` with `oathnet_pro`/`see_know` explicitly enabled through the
  fixed code — both modules executed a genuine network round-trip with zero
  panics/regressions. Honestly disclosed (per the live-check discipline): the
  exact garbage-`full_name` specimen was not organically reproducible in this
  sandbox today — SeekNow's embedded key is currently provider-rejected
  (`invalid_api_key`) and OathNet's live search for `kylo4kylo` returned 0
  results this run, so no real breach record was available to test the guard
  against live. Rather than fabricate a trigger, this relies on the
  git-stash-proven regression tests as the documented exception — each built
  from the EXACT real-world value the original 2026-06-24 incident observed
  live (`"rhino-ryno23 rhino-ryno23"`), not invented: 3 tests (the predicate
  itself; `oathnet_pro`'s extractor; `see_know`'s extractor — each asserting
  the doubled/slug name mints NO Person while a real two-token name still
  does), git-stash-proven by neutering the predicate to always return
  `false` (all 3 fail; restored, all pass). Gate green: fmt/clippy `-D
  warnings`/rustdoc clean, full suite 0 failures (4573 lib tests, +3).
  Paired: `PROBLEM_TREE` T2.73 — same commit.
- **2026-07-13** — **SOL-DEADCODE-SWEEP slice 11: a spoofed-domain seed was
  correctly rejected but the operator was never told what it normalizes to —
  `confusable::skeleton` had zero callers.** `Target::validate` already
  correctly rejects a mixed-script homograph seed (Cyrillic-`а` `pаypal.com`)
  but only says "possible spoof," never naming the ASCII form — data
  `skeleton()` already computes; its only prior caller, `confusable_report`,
  is itself dead (superseded by the boolean `is_confusable_mixed_script` at
  every real call site). Two enrichment designs assessed and rejected: (a)
  enriching the admission-gate's `Option<&'static str>` reason
  (`dispatch.rs`'s `admission_rejection`) would corrupt `hse audit`'s
  `excluded_reasons` histogram (`audit/events.rs:15-17` counts occurrences
  keyed on the EXACT reason string; a per-value dynamic skeleton would
  fragment one "confusable_homoglyph: N" bucket into N one-off buckets); (b)
  converting `Target::validate`'s return type wholesale (27 `Err` arms) to
  carry dynamic detail would touch a function with 3 live callers for one
  arm's benefit. Decision: WIRE-IN, narrowly — a new `Target::validate_verbose()
  -> Result<(), Cow<'static, str>>` that calls `validate()` unchanged and
  enriches ONLY the homograph arm (matched against a shared
  `HOMOGRAPH_REASON` const so the two can never textually drift) with `—
  ascii skeleton: {value normalized}`; every other rejection stays
  `Cow::Borrowed` — zero new allocation on the other 26 arms. All 3 real call
  sites (`cli/scan`, `cli/live`, the HTTP API's `validated_target`) switched
  to the verbose form, 1 line each; `validate()` itself untouched. ✅
  Live-verified on all 3 real paths with a genuine real-world spoof target —
  Cyrillic-`а` `pаypal.com`, the textbook PayPal-phishing homograph: `hse
  scan -k domain -v pаypal.com`, `hse live -k domain -v pаypal.com`, and
  `POST /api/v1/scans` with the same value all now print "...possible spoof)
  — ascii skeleton: paypal.com" where they previously stopped short. THEN the
  git-stash-proven regression test
  (`validate_verbose_names_the_ascii_skeleton_for_a_homograph`): neutering
  `validate_verbose`'s enrichment fails it; restored, it passes; also pins
  every OTHER rejection byte-identical to `validate`'s original message
  (`assert_eq!` between the two calls). Gate green: fmt/clippy `-D
  warnings`/rustdoc clean, full suite 0 failures (4574 lib tests, +1). Banked
  (deliberately out of scope this cycle): the same enrichment at the
  admission-gate's mid-scan `confusable_homoglyph` drop needs a
  non-histogram-corrupting channel (a `tracing::debug!` line, or an additive
  `EventKind::EntityExcluded` field) — its own scoped decision. Paired:
  `PROBLEM_TREE` T2.74 — same commit.
- **2026-07-12** — **New SOL-RANDOMIZED-MAC: the OUI classifier now flags
  randomized (private) MAC addresses instead of attributing them as real
  devices.** Surfaced by a real 1,643-device Android BLE-radar export the
  operator supplied. `util::oui::classify_mac` — live via `wigle`'s `MacAddress`
  tagging — had no concept of a locally-administered address (U/L bit `0x02` on
  the first octet), so a randomized / private address (the kind iOS 8+/Android
  10+ phones, AirTags/SmartTags rotate every ~15 min) was tagged `vendor:Unknown`
  and could anchor a colocation/tracking claim it cannot support (its bytes are
  random, its lifetime ~15 min). Added `DeviceClass::Randomized` and a reusable
  `is_locally_administered(mac) -> Option<bool>`; `classify_mac` detects the U/L
  bit and returns `Randomized`/"Randomized (private)" WITHOUT an OUI lookup, so
  `wigle` now tags such an entity `device:randomized`. 3 new tests (LA-set →
  Randomized; universally-administered control still resolves its vendor and
  stays Unregistered-not-Randomized; helper⇄classifier agreement), git-stash-
  proven — the must-flag test fails against a neutered classifier. Gate green:
  fmt/clippy `-D warnings`/rustdoc clean, full suite 0 failures (4563 lib tests,
  +3). Validated against the REAL corpus: the same U/L criterion the shipped fn
  implements splits the 1,643 real devices into 698 randomized (42%) / 945
  real-OUI, and the source app had itself mislabelled 345 randomized devices with
  a manufacturer — the exact false attribution HSE now avoids. Real MACs kept OUT
  of the repo (committed tests use synthetic addresses; the real-data validation
  ran ad-hoc). Paired: `PROBLEM_TREE` T2.64 — same commit.
- **2026-07-12** — **SOL-CORRELATOR-INTEGRITY slice 2: AU-056/AU-085 no longer
  let an infrastructure address vote the subject's jurisdiction.** The
  jurisdiction cross-checks reconcile a coordinate state against an address state
  (AU-056) or a phone region (AU-085). The coordinate side runs through
  `coord_state`, which excludes infrastructure geo (`is_infrastructure_geo` —
  HOSTING / WHOIS-`registrant` / `infra:` tags), and the sibling AU-018/026/030
  rollups exclude it too — but the Address branch of BOTH AU-056 and AU-085 had
  no such guard, so a datacentre/registrant address (`hosting`-tagged "Sydney
  NSW" from urlscan, or a WHOIS registrant location) entered the address-state
  set and manufactured a false jurisdiction agreement, or a false conflict /
  broken-unanimity downgrade against the subject's real interstate home. The
  existing tests covered the coordinate side + the rollups, masking the open
  address branch. Confirmed by the PRIORITY-3 correlator audit (double-lens) and
  re-verified in code. Fix: added `&& !is_infrastructure_geo(e)` to the Address
  branch of both rules — the twin omission is one coherent fix, mirroring
  `coord_state` and the rollups. 2 adversarial must-not-fire tests
  (`au_056_infrastructure_address_does_not_vote_jurisdiction`,
  `au_085_infrastructure_address_does_not_corroborate_phone_region`),
  git-stash-proven to FIRE against the pre-fix rules; the existing agreement
  tests are the must-fire controls. Gate green: fmt/clippy `-D warnings`/rustdoc
  clean, full suite 0 failures (4565 lib tests, +2). Paired: `PROBLEM_TREE`
  T2.65 — same commit.
- **2026-07-12** — **SOL-CORRELATOR-INTEGRITY slice 3: AU-105 under-counted
  distinct breaches from the SeekNow provider — a drifted breach-name vocabulary
  suppressed credential-reuse findings.** AU-105 fires when a secret recurs
  across ≥2 DISTINCT breaches; the breach a record belongs to comes from
  `breach_of(ev)`, which read only the `dbname`/`breach` attrs else fell back to
  the evidence source field (the module name). But the `see_know` extractor's
  full-fidelity fold renames a record's raw `source` breach-name field to
  `source_db` (so it can't clobber the provenance `source` attr). So a SeekNow
  record whose breach name lived in `source`/`source_db` was invisible to
  `breach_of`, and every such breach collapsed to the bare module name
  `see_know`: a password genuinely reused across two SeekNow breaches counted as
  ONE, and AU-105 — "one of the most actionable people-centric findings" per its
  own doc — stayed silent. `dbname`-stamping providers (OathNet/stealer) were
  unaffected; a see_know-specific vocab drift. Fix: extended `breach_of` to also
  read `source_db`, so SeekNow breach names are recovered and distinct-breach
  counting is correct across providers. 1 must-fire test
  (`au105_reads_the_see_know_source_db_breach_name`: a password reused across two
  `source_db` breaches now fires High with both names) git-stash-proven to stay
  silent against the pre-fix `breach_of`; the existing `dbname`-based tests are
  the controls. Gate green: fmt/clippy `-D warnings`/rustdoc clean, full suite 0
  failures (4566 lib tests, +1). Paired: `PROBLEM_TREE` T2.66 — same commit.
- **2026-07-12** — **SOL-CORRELATOR-INTEGRITY slice 4: AU-048 over-stated the
  account count from identifier spellings.** The shared-public-key rule fires
  Critical when a reused key proves one person controls ≥2 accounts. Its firing
  guard is sound — it folds each identifier to a `canonical_handle` and requires
  ≥2 DISTINCT handles, explicitly treating (per its own comment) "alice" +
  "alice@x.com" as ONE account — but the description reported `accounts.len()`
  (the count of distinct identifier SPELLINGS), so a key reused across alice's
  login + email + bob (3 spellings, 2 owners) claimed "controls 3 accounts" when,
  by the rule's own account definition, it is 2 — the magnitude outran the
  evidence. Fix: report `handles.len()` (the distinct-controller count the guard
  already computes) in the description, keeping the identifier list as the
  supporting evidence. 1 must-fire test
  (`au048_reports_distinct_controllers_not_identifier_spellings`: alice
  login+email + bob → "controls 2 accounts") git-stash-proven to report "3"
  against the pre-fix code; the existing firing/guard tests are unchanged
  controls. Gate green: fmt/clippy `-D warnings`/rustdoc clean, full suite 0
  failures (4567 lib tests, +1). Paired: `PROBLEM_TREE` T2.67 — same commit.
- **2026-07-12** — **New SOL-ROLE-MAILBOX-COMPOUND: a DNS SOA admin mailbox
  leaked into a scan as the subject's email — found by the PRIORITY-5 LIVE
  pass.** Driving the real release binary against the canonical seed `Kylo4kylo`
  and running `hse audit` on the result surfaced `awsdns-hostmaster@amazon.com`
  (and a WHOIS `privacy@…`) present as if they were the subject's email.
  `dns_intel` DOES guard its SOA-RNAME email emission with
  `!is_infrastructure_email` (`resolve.rs:139`), but that delegates to
  `is_role_localpart`, which exact-matched only the alphanumeric-stripped WHOLE
  local-part — so the compound `awsdns-hostmaster` (`awsdnshostmaster` ≠
  `hostmaster`, the STANDARD AWS Route53 SOA format) slipped through and the
  provider's DNS desk polluted the subject graph (it then gets breach-checked and
  identity-clustered). Fix: `is_role_localpart` now also matches an UNAMBIGUOUS
  system-role token (`hostmaster`/`postmaster`/`webmaster`/`namehost`/
  `mailerdaemon`/`noreply`/`donotreply`/`abuse`/`dns`/`nic`) as a
  hyphen/dot/underscore-delimited SEGMENT — deliberately NOT the business tokens
  (`info`/`contact`/`sales`), which a real subject local-part can legitimately
  contain, so a genuine subject email is never suppressed. Live-proven FIRST (per
  PRIORITY-5's order): rebuilt the binary and ran `hse scan --kind domain --value
  amazon.com --modules dns_intel` — the SOA is still processed (soa/dns-admin
  tags present) but ZERO Email entities are emitted, the `awsdns-hostmaster`
  address suppressed where the earlier real Kylo4kylo scan's audit had it present.
  THEN the regression test
  (`role_localpart_matches_provider_prefixed_system_mailboxes`, git-stash-proven
  to fail pre-fix, with negative controls — `jane-info`/`john.contact`/`sam-sales`
  — locking the no-false-positive design). Gate green: fmt/clippy `-D warnings`/
  rustdoc clean, full suite 0 failures (4568 lib tests, +1). Banked (2nd finding,
  same audit): WHOIS-registrant emitters (`whoisxml`/`netlas`/`ripestat`) emit
  registrant emails with no infra/role guard, so `privacy@…` leaks even though
  `is_role_localpart("privacy")` is already true — a separate emitter-side fix.
  Paired: `PROBLEM_TREE` T2.68 — same commit.
- **2026-07-12** — **New SOL-GEXF-COOCCURRENCE-RECORD: a fan-out probe cliqued
  its own results in the GEXF export — found by the PRIORITY-5 LIVE export.**
  Exporting the canonical `Kylo4kylo` scan's `graph.gexf` gave **2973 edges over
  118 nodes** while metrics/relations/network all report **39** typed relations.
  `write_shared_evidence_edges` drew a co-occurrence edge for every entity pair
  sharing a `corroborating_sources()` NAME; `username_search` — which probes ONE
  handle across ~70 platforms and emits a distinct per-platform entity — was
  carried by 70 entities, wiring them into a complete 70-clique = **2415 edges
  (81%)**, with `social_probe`/`streaming_probe` two more cliques. Those are
  independent existence-proofs of one selector, NOT a joint sighting — exactly
  the "dense web of false 'related' clusters that swamps the genuine structure in
  Gephi" the function's own doc-comment claims to avoid; the claim contradicted
  the live artifact. Fix: co-occurrence keys on the evidence RECORD — new
  `Entity::corroborating_records()` returns the `(source, summary)` pairs (still
  filtered by `is_non_corroborating_source`), and two entities co-occur only when
  they share an IDENTICAL record. Fan-out's distinct per-platform summaries no
  longer clique; a genuine joint record (both selectors in one breach dump —
  identical `("hibp","Breach 'Apollo'")` — or the same crawled page) is shared
  verbatim, so the real edge survives; typed relations are untouched. Live-proven
  FIRST (per PRIORITY-5's order): rebuilt and re-exported the SAME stored scan —
  **2973 → 46 edges** (all 39 typed relations kept — same_identity 16 /
  derived_from 11 / hosted_on 9 / …; + 7 genuine co-occurrence: hibp same-breach
  ×5, same search-result ×1, multipath ×1), still well-formed XML. THEN the
  git-stash-proven regression test
  (`gexf_co_occurrence_is_record_level_not_source_level`: same source name but
  different per-platform summaries must NOT co-occur — fails pre-fix; same source
  AND summary → exactly one edge), the byte-stable golden test unchanged
  (identical summaries), and the coarse `gexf_creates_edges_for_shared_sources`
  test refined to `gexf_creates_edges_for_a_shared_evidence_record`.
  `corroborating_sources()` and its many correlator/coref/export callers are
  untouched (new method, gexf-only). Gate green: fmt/clippy `-D warnings`/rustdoc
  clean, full suite 0 failures (4569 lib tests, +1). Paired: `PROBLEM_TREE` T2.69
  — same commit.
- **2026-07-13** — **SOL-DEADCODE-SWEEP slice 12: cleared the banked 19-item
  DELETE batch — but re-verification at implementation time found 7 of the 19
  misclassified, not truly dead.** Re-ran the reference count on all 19
  candidates (5 commits had landed since the original sweep); all 19
  reconfirmed zero-production-caller. But implementing the deletions one by
  one surfaced what a per-directory rg-based sweep structurally can't see:
  whether a "test-only" reference is the item's OWN dedicated test (safe to
  delete together) or an ORACLE another kept function's test depends on
  (deleting it silently guts real coverage), and whether a "dead" accessor is
  genuinely redundant elsewhere (`set_private` — already established, DB is
  0600 under umask 0022) or mirrors an already-wired sibling gate with no
  substitute of its own (`is_quota_exhausted`/`is_unverified`, unlike
  `oathnet`'s analogous already-checked quota latch). Reclassified 7, KEPT:
  `rank_autonomous_targets` (flat-ranking oracle 2 live tests compare
  `plan_autonomous_sweep`/`rank_identity_aware_targets` against),
  `host_state` (sole introspection surface for the circuit-breaker's real
  Closed→Open→HalfOpen→Closed transitions), `is_quota_exhausted` (see_know)
  and `is_unverified` (wigle) — each a genuine unwired efficiency gate,
  banked as its own future WIRE-IN rather than deleted or wired mid-batch,
  and `LIVE_MAX_DEPTH`/`LIVE_DEFAULT_CONCURRENT` (grouped with the
  already-banked `LIVE_DEFAULT_THROTTLE_MS` WIRE-IN — deleting 2 of 3 sibling
  tuning constants while banking the third would be incoherent). Deleted the
  remaining 12 (`confusable_report`, `autonomous_seed`, `shortest_path` —
  tests re-pointed to `paths_between` so MAX_HOPS-bound/self-path coverage
  survive — `validate_for_kind`/`composite.rs`, `TACTIC_ID`/`TACTIC_NAME`,
  `DERIVED`, `store_api_credential_from_item`, `extract_first` — inlined as a
  private test helper over the live `extract_all` — `is_personal`,
  `is_bsb_shaped`, `set_private`, and the write-only `AuditEntity::confidence`
  field). Fixing `confidence` found 2 MORE construction sites the original
  sweep's re-verification missed (`cli/audit/mod.rs`'s CSV parser,
  `tests/audit_regression.rs`'s fixture) — both fixed in the same pass.
  Live-verified the one behavioural surface touched: a real `hse scan -k
  username -v Kylo4kylo` → `hse export --format csv` → `hse audit --csv`
  round-trip scored 92/100 with the correct 1-verified/0-probable/0-candidate
  tiers, confirming `c_effective` (the field that actually drives scoring) is
  untouched. Gate green: fmt/clippy `-D warnings`/rustdoc clean, full suite 0
  failures (4566 lib tests). Net −286 lines, 23 files. Paired: `PROBLEM_TREE`
  T2.75 — same commit.
- **2026-07-13** — **SOL-HEALTH-SIGNAL: T2.7's golden-fixture corpus, second
  slice — a REAL Bing SERP, per the first slice's own named priority (the
  highest `<cite>`-format drift risk).** Fetched live for the canonical seed
  `Kylo4kylo`, checked in verbatim as `testdata/bing_kylo4kylo.html` (75 KB).
  This exact capture happens to return zero results actually about
  `Kylo4kylo` — Bing's own real answer was five unrelated ESPN links —
  disclosed honestly as observed, not re-fetched or adjusted to look better:
  the new test only asserts extraction correctness (exactly 5 results, 3
  pinned real hosts, zero `bing.com` chrome), never relevance, which stays
  the correlator/audit's job. Git-stash-proven: neutering `parse_results`
  fails the test; restored, it passes. No production code change needed —
  the existing href+`<cite>` extraction handled this real page correctly
  as-is. Gate green: fmt/clippy `-D warnings`/rustdoc clean, full suite 0
  failures (4567 lib tests, +1). *Remaining corpus slices, unchanged:*
  `au_people`/`au_electoral`/`au_property` and the other 15 `search_engines`
  engines. Paired: `PROBLEM_TREE` T2.7 (second slice) — same commit.
- **2026-07-13** — **SOL-HEALTH-SIGNAL: T2.7's parse-rate/zero-yield drift
  leg — a module that completes without erroring but silently returns zero
  results, distinct from a genuinely-empty target.** Reused the exact
  three-strikes shape the hard-failure leg validated instead of inventing a
  statistical baseline: `is_yield_drifted()` requires BOTH `ever_yielded`
  (this source has found something, anywhere in the window) AND
  `consecutive_zero_yield >= YIELD_DRIFT_THRESHOLD` (3) — never flags a
  source that's never yielded, correctly closes the trailing streak at 0
  when the newest run recovers, and skips `ModuleError`s entirely (already
  `consecutive_failures`'s job). No new persistence — reuses
  `EventKind::ModuleDone`'s existing `found: usize`. Wired into `hse
  doctor`, `GET /api/v1/health/scrapers`, and the SPA Engines panel.
  Deliberately zero-yield only — a partial yield-drop detector needs an
  unjustified drop-percentage threshold, banked for a future increment if
  evidence appears. Live-verified against the operator's own real scan
  history (97 sources, 211 events, via `hse doctor` and a live HTTP call):
  honest empty state on both signals. Git-stash-proven: neutering
  `is_yield_drifted` fails the positive-detection test; restored, it
  passes. Gate green: fmt/clippy `-D warnings`/rustdoc clean, full suite 0
  failures (4572 lib tests, +5). Both SOL-HEALTH-SIGNAL legs T2.7's
  original sketch named are now delivered; only the golden-fixture corpus's
  remaining slices stay open. Paired: `PROBLEM_TREE` T2.7 (parse-rate leg)
  — same commit.
- **2026-07-13** — **New SOL-AUDIT-TEMPORAL-SCOPE: `hse audit`'s
  engine-health signal was blending CURRENT conditions into ANY scan's
  historical report — found by a cross-cutting PRIORITY-2 sweep of every
  cache/TTL/quota-budget/retry-backoff mechanism in the engine.**
  `engine_health_signals()` read the process-global, continuously-refreshed
  search-engine liveness cache with zero comparison to the audited scan's
  own completion time — false positive when engines break after a clean
  scan, false negative when engines recover after a scan that genuinely
  ran degraded. Fix: `scan_audit` now reads the scan's own
  `finished_at`/`started_at` (free — folded into the existing
  `spawn_blocking` batch) and a new pure `snapshot_still_relevant_to()`
  gates the cached snapshot to within 2× the health sweep's own declared
  refresh cadence (new `health::DEFAULT_REFRESH_SECS`, single-sourced with
  `cli/serve`'s previously-independent `900` literal) — no invented
  threshold, no new persistence. Live-verified against REAL,
  naturally-occurring conditions: a real ~2-hour-old scan from this
  session, audited immediately after a fresh live sweep found this
  sandbox's genuinely degraded network (11 blocked, 1 down of 17 engines)
  — pre-fix this would have stamped that old scan's report with the
  current outage; post-fix, the mismatched-era snapshot is honestly
  omitted. Git-stash-proven: 4 new unit tests on the pure gate; neutering
  it to always return `true` fails the weeks-later test; restored, passes.
  Gate green: fmt/clippy `-D warnings`/rustdoc clean, full suite 0 failures
  (4576 lib tests, +4). Paired: `PROBLEM_TREE` T2.76 — same commit.
- **2026-07-13** — **SOL-AUDIT-TEMPORAL-SCOPE, WiGLE account-status leg
  (T2.77): a sibling stale-attribution bug in the same PRIORITY-2 family.**
  `wigle::account`'s `verified: Some(false)` latch (set by a real 412 in
  `fetch.rs::classify_and_decode`) had no way back to `true`, so a
  long-lived process kept reporting the account unverified forever after
  one 412, even after the operator fixed it and later queries succeeded.
  Fix: new `mark_verified`, mirroring `mark_unverified`, called from the
  success branch — same reactive channel, no new persistence. Live-verified
  against a REAL WiGLE account and a real public-landmark query (Sydney
  Opera House coordinates): `/api/v1/stats` went from `verified: null` to
  `verified: false` after a genuine 412 from this sandbox's
  actually-unverified account, confirming the existing half end-to-end.
  Honestly disclosed: the NEW half wasn't live-reachable (the real account
  here is persistently unverified) — verified via the git-stash-proven unit
  test instead. Gate green: fmt/clippy `-D warnings`/rustdoc clean, full
  suite 0 failures (4577 lib tests, +1). Paired: `PROBLEM_TREE` T2.77 —
  same commit.
- **2026-07-13** — **SOL-CORR: AU-112 closes the `Cidr` rule-gap from cycle
  30's search, reusing `util::spf`'s CIDR-containment maths.** New
  `rule_au_112_shared_cidr_infrastructure`: an independently-discovered
  `IpAddress` entity found inside a `Cidr` entity from the same scan is a
  shared-hosting-infrastructure signal, gated to narrow blocks only (`/22`
  IPv4, `/48` IPv6) so a broad ISP/cloud allocation can't manufacture noise,
  skipping pairs `netblock` already makes explicit. Reused
  `util::spf::Ipv4Cidr`/`Ipv6Cidr` (built for SPF parsing, already tested)
  rather than duplicating containment maths in `core` — added the two
  missing `prefix_len()` accessors and one new architecture allow-list entry
  for `util::spf::` (same pure/leaf category as `util::geohash`/
  `util::geometry`, not a weakened guard). Live-verified against real
  `github.com` infrastructure via `dns_intel`/`ripestat`: fired on genuine
  containments (`140.82.112.3` in `140.82.112.0/24`), correctly silent on
  the same scan's broader `/17`/`/18` blocks. 6 new tests, 2 confirmed via a
  neutered-rebuild git-stash-style proof to fail pre-fix, pass post-fix.
  Gate green: fmt/clippy `-D warnings`/rustdoc clean, full suite 0 failures
  (4599 lib tests, +6; correlator rule count 109→110). Paired: `PROBLEM_TREE`
  C1 — same commit.
- **2026-07-14** — **SOL-HEALTH-SIGNAL: T2.7's golden-fixture corpus,
  seventh slice — you.com.** Swept live reachability of all 10 remaining
  un-fixtured `search_engines` engines from this sandbox: 8 confirmed
  blocked/unreachable at the HTTP layer, leaving `google` (a genuine
  JS-challenge interstitial, already correctly handled) and `you` as the
  only two returning real content. A REAL `you.com` capture disproved
  `engines.rs`'s own doc comment (claimed a "classic HTML view"; it's
  actually a Cloudflare-gated Next.js SPA with zero server-rendered `<a>`
  anchors) and surfaced a real chrome-leak: the capture's own
  `dns-prefetch` link to `cdn.you.com` leaked through `parse_results` as a
  fake organic hit because `you.com` was never in `ENGINE_DOMAINS` — the
  same false-positive class already fixed for MetaGer/Dogpile/Swisscows/
  Startpage. Fixed by adding `you.com` to `ENGINE_DOMAINS`; corrected the
  stale doc comment. 2 new regression tests, git-stash-proven (reverting
  the `ENGINE_DOMAINS` addition alone reproduces the leak). Live-verified:
  a real `hse scan --kind name --value Kylo4kylo --modules search_engines
  --depth 0` run reports `engine: you, outcome: blocked, results: 0`, zero
  `cdn.you.com` chrome anywhere in the scan output. Gate green: fmt/clippy
  `-D warnings`/rustdoc clean, full suite 0 failures (4623 lib tests, +2).
  Paired: `PROBLEM_TREE` T2.7 (golden-fixture corpus, seventh slice —
  you.com), §8 — same commit.
- **2026-07-14** — **SOL-GEOINT: movement/timeline geo's first increment —
  `exif_geo`'s `shot_time` was live evidence with nothing consuming it.**
  C5's own text has named "movement/timeline layer" as remaining since cycle
  19; investigating it found `exif_geo` already stamps a `shot_time`
  attribute (the photo's EXIF `DateTimeOriginal`/`DateTime` tag) onto every
  entity it emits, including the extracted `Coordinates` entity — a real
  dated-location fact — but `core::timeline::classify` had no arm for it, so
  it was silently invisible to the footprint timeline: the same
  "defined-but-never-wired" defect class the 2026-07-05 `AccountCreated`
  fix closed for an identity key, now found on a geo key. Fixed by adding
  `TimelineEventKind::LocationVisited` (kept distinct from `Generic` — a
  dated place is a materially more useful fact than an unclassified date)
  and mapping `"shot_time"` to it. A second, independently-found defect:
  `exif_geo::parse::read_str` returns the EXIF tag's ASCII value verbatim
  (`"YYYY:MM:DD HH:MM:SS"`, colon-separated date — EXIF's own format, not
  ISO), but `timeline::parse_date` only recognised `-`/`/` as date
  separators, so even a correctly-classified `shot_time` would still have
  silently failed to parse. Fixed by accepting `:` as a third separator —
  safe because `parse_date` already isolates the date portion from any
  `HH:MM:SS` time component before separator detection runs. Audited every
  other `Coordinates`-producing module (WiGLE, `cell_intel`, `opencellid`,
  the IP-geo family, `address_au`) for a similar per-observation timestamp
  attribute — none carry one today, so this is genuinely the one live
  dated-geo signal in the codebase, not an invented mechanism; a true
  multi-event movement/path layer stays open, now buildable for the first
  time since the underlying dated events exist. SPA `TL_KIND` map
  (`timeline.js`) gained a `location_visited` entry so the new kind renders
  with its own icon/label instead of the generic "Event" fallback. 3 new
  regression tests: `classify_recognises_exif_shot_time_as_location_visited`,
  `parse_date_accepts_the_real_exif_datetime_format`, and
  `reconstruct_surfaces_a_location_visited_event_from_a_real_exif_shot_time`
  (full pipeline, real evidence shape) — git-stash-provable, since the
  pre-fix `classify` has no `shot_time` arm at all. Gate green: fmt/clippy
  `-D warnings`/rustdoc clean, full suite 0 failures (4626 lib tests, +3).
  Paired: `PROBLEM_TREE` C5 (movement/timeline geo, first increment) + C1(c)
  (timeline-widening precedent), §8 — same commit.
