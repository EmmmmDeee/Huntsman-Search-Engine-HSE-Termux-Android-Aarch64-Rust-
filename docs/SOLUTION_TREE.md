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
  *Closes:* the key-in-URL **log** exposure (S4 mostly mitigated). *Gap:* the archived
  **success body** isn't run through `redact_literal_secrets` — **§7 S4** residual. ◑
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
  *Remaining:* AU bounding precision; movement/timeline layer; auto-scheduled
  re-sync of the local cell DB (currently requires manual `hse cells import`
  trigger).
- **`[ ]` SOL-OFFENSIVE · Exposure & reuse graph** → **C6**: broaden SERP dorks,
  credential-reuse graph, `aho-corasick` (SOL-F1) key-harvest + entropy gate.
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
- **`[ ]` SOL-HINT-NOISE · Reinstate `analyse()`'s two removed dead hints,
  with a real per-module noise decision** → **T2.14**: the scan-level "60s +
  zero-yield module" hint can be reinstated the same way SOL-ROI-HINT was
  (event-sourced, caller-side); the per-module "module X returned 0 entities"
  hint needs a design decision first — fired correctly on real event data, a
  realistic multi-module scan leaves dozens of modules at zero yield for any
  given target kind (normal, not noteworthy), so a naive per-module
  reinstatement would flood the hints list with the opposite of signal.
  Candidates: cap to worst-N, cost-gate like SOL-ROI-HINT
  (`KeyGated`/`Paid`-only), or collapse to a bounded summary count. *Gap:* not
  yet started. **(§4a)**
- **`[ ]` SOL-HEALTH-SIGNAL · Per-source scraper health surface** — add a
  `last_success_at` + `consecutive_failures` tracking column (or an in-process
  `AtomicU64` per source name) exposed via `hse doctor` and a SPA health panel;
  auto-flag a source "drifted" when `consecutive_failures ≥ N` or `parse_rate
  < threshold`. SOL-F1's `bstr`/aho-corasick rewrites underpin the parsers being
  stable enough to measure; each golden-fixture test (T2.7) becomes the
  acceptance criterion.
  *Closes / powers:* **T2.7** per-source health signal gap (currently no solution
  node). *Gap:* not yet started — implementation deferred until the golden-fixture
  golden-fixture corpus (T2.7 parser rewrites) is in place. **(§4a)**

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
- **`[x]` SOL-BITBUCKET-ATTACK-COMPLETE · `bitbucket_user`'s
  `attack_techniques()` no longer fabricates a technique claim while
  omitting two real ones** — a multi-angle discovery sweep re-surfaced the
  `dockerhub_user`/T2.28 scoped-sweep list (5 modules) plus 10 more
  previously-uncatalogued instances of the identical shape; independently
  re-verified `bitbucket_user` as the single most faulty instance before
  fixing it (the only one of the 16 with a genuine over-claim, not just an
  omission): the override `&["T1589.002", "T1593.003"]` claimed Email
  Addresses on a fabricated basis (no `Email` entity exists anywhere in
  `BbUser`/`build_entities`) while omitting `T1589.003` (Person from
  `display_name`) and `T1591.001` (Address/Coordinates from `location`),
  both real, unit-tested construction paths. Declared the precise, complete
  set: `T1589.003`, `T1591.001`, `T1593.003` (no `T1591.002`: no
  `Organisation` entities are built here). *Closes:* new node **T2.34**. ✅ 1
  test (`attack_techniques_covers_every_entity_kind_this_module_produces`),
  fail-before confirmed by reverting just the function body in place.
- **`[x]` SOL-CO-OWNERSHIP-ORDER-DETERMINISM · `derive_co_ownership`'s two
  `HashMap` groupings (shared registrant, shared dedicated IP) no longer
  leak iteration order into the persisted `SameOperator` relation
  sequence** — the 5th instance of the `web_crawler`/T2.25 bug class, found
  by the same discovery sweep that surfaced T2.34, and the first in the
  relation-derivation layer. Every sibling `derive_*` builder in the same
  file ends with `sort_edges(&mut out)`; `derive_co_ownership` was the one
  exception, and the correlator's own twin logic for this exact grouping
  (`rules::org`'s AU-109/AU-110) already sorts group keys before iterating —
  `derive_co_ownership` never received the same fix. Measured the leak
  directly: a test feeding the identical logical input (3 registrant + 3
  dedicated-IP groups) in forward vs. reversed order returned the same 6
  relations in different orders against the unfixed code. Mirrored
  `rules::org`'s exact pattern at both sites: collect+sort the group keys,
  then iterate the sorted order and `.remove()` each group — no change to
  pair membership, confidence, or the global dedup. *Closes:* new node
  **T2.35**. ✅ 1 test
  (`co_ownership_multi_group_emission_order_is_independent_of_input_order`),
  fail-before confirmed. Relation (107)/engine (115)/correlator (422) suites
  unaffected.
- **`[x]` SOL-RUBYGEMS-ATTACK-COMPLETE · `rubygems_user`'s
  `attack_techniques()` no longer fabricates an Email-Addresses claim while
  omitting the real Employee-Names technique** — continuing the
  `dockerhub_user`/T2.28 scoped-sweep list T2.34 left open, the 2nd genuine
  over-claim instance in that list (matching the shape T2.34 fixed for
  `bitbucket_user`). The override `&["T1589.002", "T1593.003"]` claimed
  Email Addresses on a fabricated basis (`RgGem`/`build_entities` never
  construct an `EntityKind::Email` anywhere) while omitting `T1589.003`
  (Person from each name in the `authors` field, via
  `profile_kit::person_from_name`, already unit-tested by
  `emits_person_from_multi_word_author`). Independently read `npm_author`/
  `crates_io` (both build the identical homepage/repository-derived
  `Url`/`Domain`/cross-platform-`Username` pivot shape) to confirm the
  established convention declares no dedicated technique for that pivot,
  only for the registry `Username` itself — so no technique was invented
  for `rubygems_user`'s own homepage/GitHub-pivot fields either. Declared
  the precise set: `T1589.003`, `T1593.003` (dropping the fabricated
  `T1589.002`). *Closes:* new node **T2.36**. ✅ 1 test
  (`attack_techniques_covers_every_entity_kind_this_module_produces_and_no_more`),
  fail-before confirmed by writing it against the unfixed override first.
- **`[x]` SOL-GITLAB-ATTACK-COMPLETE · `gitlab_user`'s `attack_techniques()`
  now declares all five techniques `build_entities` actually earns** —
  continuing the scoped-sweep list T2.36 left open. Unlike T2.34/T2.36,
  this instance's existing `T1589.002` (Email Addresses) claim is genuine
  (bio emails really are extracted into `EntityKind::Email` entities) — a
  pure omission, not a fabrication: `build_entities` also constructs a
  `Person` (real `name`, needs T1589.003), an `Organisation`
  (self-reported `organization`, needs T1591.002), and an
  `Address`/`Coordinates` (`location`, needs T1591.001), all three real,
  already-unit-tested paths, none credited. Declared the precise, complete
  set: `T1589.002`, `T1589.003`, `T1591.001`, `T1591.002`, `T1593.003`.
  *Closes:* new node **T2.37**. ✅ 1 test
  (`attack_techniques_covers_every_entity_kind_this_module_produces`),
  fail-before confirmed by writing it against the unfixed override first.
- **`[x]` SOL-CPAN-ATTACK-COMPLETE · `cpan_user`'s `attack_techniques()` now
  declares all four techniques `build_entities` actually earns** —
  continuing the scoped-sweep list T2.37 left open. Like `gitlab_user`, the
  existing `T1589.002` (Email Addresses) claim is genuine (public `email`
  list entries AND biography-embedded emails both become real
  `EntityKind::Email` entities) — a pure omission, not a fabrication:
  `build_entities` also constructs a `Person` (real `name`, needs
  T1589.003) and an `Address`/`Coordinates` (`location`, needs T1591.001),
  both real, already-unit-tested paths, neither credited. No
  `Organisation` entities are built here, so T1591.002 correctly does not
  apply. Declared the precise, complete set: `T1589.002`, `T1589.003`,
  `T1591.001`, `T1593.003`. *Closes:* new node **T2.38**. ✅ 1 test
  (`attack_techniques_covers_every_entity_kind_this_module_produces`),
  fail-before confirmed by writing it against the unfixed override first.
- **`[x]` SOL-GITEA-ATTACK-COMPLETE · `gitea_user`'s `attack_techniques()`
  now declares all four techniques `build_entities` actually earns** —
  continuing the scoped-sweep list T2.38 left open. Like `gitlab_user`/
  `cpan_user`, the existing `T1589.002` (Email Addresses) claim is genuine
  (public `email` field AND `description`-embedded emails both become real
  `EntityKind::Email` entities) — a pure omission, not a fabrication:
  `build_entities` also constructs a `Person` (real `full_name`, needs
  T1589.003) and an `Address`/`Coordinates` (`location`, needs T1591.001),
  both real, already-unit-tested paths, neither credited. No
  `Organisation` entities are built here, so T1591.002 correctly does not
  apply. Declared the precise, complete set: `T1589.002`, `T1589.003`,
  `T1591.001`, `T1593.003`. *Closes:* new node **T2.39**. ✅ 1 test
  (`attack_techniques_covers_every_entity_kind_this_module_produces`),
  fail-before confirmed by writing it against the unfixed override first.
- **`[x]` SOL-CODEBERG-ATTACK-COMPLETE · `codeberg_user`'s
  `attack_techniques()` now declares all four techniques `build_entities`
  actually earns** — continuing the scoped-sweep list T2.39 left open.
  Preceded by an 11-agent Workflow verification sweep across the entire
  remaining candidate list, confirming zero new fabrication instances
  beyond `bitbucket_user`/T2.34 and `rubygems_user`/T2.36 (all 11 are pure
  omissions), and surfacing that `huggingface_user` needs a 3rd technique
  (T1591.002, Organisation) and `crates_io`/`npm_author` each carry a
  `tests/architecture.rs` pin that will need updating alongside their
  eventual fix. Like `gitlab_user`/`cpan_user`/`gitea_user`, the existing
  `T1589.002` (Email Addresses) claim is genuine (biography-embedded
  emails become real `EntityKind::Email` entities) — a pure omission, not
  a fabrication: `build_entities` also constructs a `Person` (real
  `full_name`, needs T1589.003) and an `Address`/`Coordinates`
  (`location`, needs T1591.001), both real, already-unit-tested paths,
  neither credited. No `Organisation` entities are built here, so
  T1591.002 correctly does not apply. Declared the precise, complete set:
  `T1589.002`, `T1589.003`, `T1591.001`, `T1593.003`. *Closes:* new node
  **T2.40**. ✅ 1 test
  (`attack_techniques_covers_every_entity_kind_this_module_produces`),
  fail-before confirmed by writing it against the unfixed override first.
- **`[x]` SOL-HUGGINGFACE-ATTACK-COMPLETE · `huggingface_user`'s
  `attack_techniques()` now declares all four techniques `build_entities`
  actually earns — the largest remaining gap in the scoped-sweep queue**
  — continuing the scoped-sweep list T2.40 left open. Its override
  `&["T1593.003"]` was genuine (a confirmed Hugging Face profile
  Username), but omitted a `Person` from the real `fullname` field
  (T1589.003), an `Email` from the public `email` field (T1589.002), and
  an `Organisation` for each `orgs[]` membership (T1591.002) — all three
  real, already-unit-tested paths, none credited. `HfUser` has no
  `location` field, so T1591.001 correctly does not apply. Declared the
  precise, complete set: `T1589.002`, `T1589.003`, `T1591.002`,
  `T1593.003`. *Closes:* new node **T2.41**. ✅ 1 test
  (`attack_techniques_covers_every_entity_kind_this_module_produces`),
  fail-before confirmed by writing it against the unfixed override first.

### S.PROCESS — The methodology itself ⚑

- **`[x]` SOL-PAIRED-TREES · The problem/solution pair + gap analysis** ⚑ — *this
  document* + `PROBLEM_TREE.md`, maintained per §0. Closes the meta-problem "what is
  wrong and how it's solved live in different heads / drift apart."
- **`[x]` SOL-GATE · The verification gate** — `fmt --check` · `clippy --all-targets
  --locked -D warnings` · strict private-item rustdoc · `cargo test`; every fix lands
  with a regression test that fails against the unfixed code. ✅ (CLAUDE.md).
- **`[x]` SOL-AUDIT-CADENCE · Multi-agent adversarial re-audit** — parallel fan-out
  (parsers / storage-API / engine / correlator / SPA / security / internals) with
  honest "clean" verdicts; the source of T2.8–T2.12 and the §7 detail. ✅

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
| SOL-REDACT | §7 S4 | ◑ |
| SOL-EMBED | §7 S1 (accepted) | `[-]` |
| SOL-CLI-CONTRACT / -DIFF / -CACHE | T2.12 | `[x]`/`[x]`/`[x]` |
| SOL-ROI-HINT | T2.13 | `[x]` |
| SOL-HINT-NOISE | T2.14 | `[ ]` |
| SOL-RULE-METAGUARD | T1.3 (dispatch firing coverage) | `[x]` |
| SOL-STREAMING | C8 | `[x]` |
| SOL-AU-MOAT | C3 | `[~]` |
| SOL-NETINT | C4 | `[~]` |
| SOL-CACHE-INTERSCAN | C9 | `[x]` |
| SOL-CORR | C1 | `[~]` |
| SOL-PERF-PUBLISH | C2 | `[ ]` |
| SOL-GEOINT | C5 | `[~]` |
| SOL-OFFENSIVE | C6 | `[ ]` |
| SOL-FORENSIC | C7 | `[ ]` |
| SOL-HEALTH-SIGNAL | T2.7 (per-source health) | `[ ]` |
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
| SOL-BITBUCKET-ATTACK-COMPLETE | T2.34 | `[x]` |
| SOL-CO-OWNERSHIP-ORDER-DETERMINISM | T2.35 | `[x]` |
| SOL-RUBYGEMS-ATTACK-COMPLETE | T2.36 | `[x]` |
| SOL-GITLAB-ATTACK-COMPLETE | T2.37 | `[x]` |
| SOL-CPAN-ATTACK-COMPLETE | T2.38 | `[x]` |
| SOL-GITEA-ATTACK-COMPLETE | T2.39 | `[x]` |
| SOL-CODEBERG-ATTACK-COMPLETE | T2.40 | `[x]` |
| SOL-HUGGINGFACE-ATTACK-COMPLETE | T2.41 | `[x]` |

---

## 4. Gap analysis — the live diff between the trees (refreshed every pass)

> This section *is* the alternation made concrete. **4a** = problems with no started
> solution (P→S gaps, the build queue). **4b** = solutions begun but unfinished (the
> finish queue). **4c** = solutions with no problem (over-build — prune candidates).
> When 4a + 4b are empty, the two trees agree.

### 4a · Problems with NO solution yet started (P→S coverage gaps)
- **Multi-angle discovery sweep (2026-07-08, closing T2.34) — 24 further
  candidates found and independently adversarially verified against the
  actual code.** The determinism leak (`derive_co_ownership`) **delivered
  2026-07-08** (SOL-CO-OWNERSHIP-ORDER-DETERMINISM, closing T2.35, see §5).
  `rubygems_user`'s fabricated-claim instance **delivered 2026-07-08**
  (SOL-RUBYGEMS-ATTACK-COMPLETE, closing T2.36, see §5). `gitlab_user`'s
  pure-omission instance **delivered 2026-07-08** (SOL-GITLAB-ATTACK-COMPLETE,
  closing T2.37, see §5). `cpan_user`'s pure-omission instance **delivered
  2026-07-08** (SOL-CPAN-ATTACK-COMPLETE, closing T2.38, see §5).
  `gitea_user`'s pure-omission instance **delivered 2026-07-08**
  (SOL-GITEA-ATTACK-COMPLETE, closing T2.39, see §5). `codeberg_user`'s
  pure-omission instance **delivered 2026-07-08** (SOL-CODEBERG-ATTACK-COMPLETE,
  closing T2.40, see §5), preceded by an 11-agent independent verification
  sweep across the whole remaining candidate list that confirmed zero new
  fabrication instances beyond `bitbucket_user`/T2.34 and
  `rubygems_user`/T2.36. `huggingface_user`'s pure-omission instance
  (the largest remaining gap) **delivered 2026-07-08**
  (SOL-HUGGINGFACE-ATTACK-COMPLETE, closing T2.41, see §5). **17
  remaining, deliberately left for future cycles** (one unit at a time by
  design): attack-mapping-completeness cluster (9, same
  replace-instead-of-extend shape as `bitbucket_user`/T2.34, all
  independently re-verified 2026-07-08): `hexpm_user`/`launchpad_user`/
  `pypi_user`/`bluesky_user` (missing T1589.003 alone), `devto` (missing
  T1589.003/T1591.001), `crates_io`/`npm_author` (missing
  T1589.003/T1589.002 respectively; each carries a `tests/architecture.rs`
  pin — `attack_overrides_attribute_collection_modules_precisely` —
  asserting their exact technique array with a comment claiming "no
  Person/Organisation/Address collection" that is factually stale for
  both; fixing either requires updating that pin's expected array in the
  same commit), `stackoverflow_user` (replace-instead-of-extend dropped
  T1589.003), `steam_profile` (no override at all yet, inherits the bare
  Social default — needs a brand-new override added, not a modification —
  missing T1591.001 for its location-derived Address/Coordinates).
  Other angles: `asic_persons` silently drops the CKAN `total` field
  `acnc_charities`/`au_unclaimed` both already capture; `core::attack::
  TACTIC_ID`/`TACTIC_NAME` are `pub const` with zero references anywhere;
  `util::key_pool::pool::KeyPool::set_environment` has zero call sites
  (every sibling mutator is wired into `hse keys`); 3 newer-clippy-toolchain
  lints (`rules::location`'s redundant `fix.uids.clone()`;
  `rules::mod::entities_of_kind` and `relation::builders::
  link_by_shared_attribute` both take `EntityKind`/`Option<EntityKind>` by
  value when only ever compared by reference); 2 silent error-swallowing
  sites (`core::engine::mod.rs`'s AU-065/066 pathway-template block discards
  3 storage results with no tracing; `api::scan_handlers::core::scan_import`
  swallows relation/correlation persistence failures with no logging,
  unlike its own sibling handling elsewhere). The proxy-pool-subsystem
  finding (harvested proxies never wired to any consumer) was excluded from
  this list — assessed as needing a real design/policy decision, the same
  "defer" bucket as T2.7/T2.14, not a mechanical fix.
- **`ANCHORING_GEO_SOURCES` allowlist omissions (found closing FT.14,
  2026-07-08) — CLOSED, all 5 candidates resolved.** `wifi_intel` delivered
  (SOL-WIFI-INTEL-ANCHOR: identical `bssid_locate`→`wigle` API mechanism the
  merge history confirms it absorbed). `mls` delivered (SOL-MLS-ANCHOR: its
  own doc comment names it a third corroboration source alongside the
  allowlisted `wigle`/`mylnikov`, identical `MacAddress`-only `accepts()`).
  `cell_intel`/`cell_local` REFUTED (both resolve `Coordinates` via the same
  OpenCelliD database the already-excluded `opencellid` queries, or an even
  coarser MCC-centroid fallback — not first-party telemetry). `qld_cadastre`
  REFUTED, 2026-07-08: `accepts()` restricted to `TargetKind::Coordinates`
  only — it enriches an ALREADY-established coordinate with cadastral
  metadata, never independently discovers or names-ties a location; the same
  "coordinate-keyed enrichment" shape as `au_geo` from the FT.14 fix.
  `employer_pivot` REFUTED, 2026-07-08: no allowlisted peer shares its
  mechanism (unlike `wifi_intel`/`mls`) — the allowlisted business-registry
  sources all derive their subject↔business link from a formal GOVERNMENT
  REGISTER, while `employer_pivot` scrapes an arbitrary discovered `Email`-
  domain/`Domain` target's public contact pages, a categorically weaker,
  unverified linkage its own code comment documents a real misattribution
  from (`dns@cloudflare.com` → Cloudflare's Sydney HQ). The engine's
  wrong-identity gate covers only `Username`/`Person`, not `Email`/`Domain`,
  so no person-identity check backs this linkage beyond the generic
  expansion floor. This list is now off the open queue.
- **`employer_pivot`'s `Domain`-target path had no person-linkage guard —
  DELIVERED 2026-07-08 (SOL-EMPLOYER-PIVOT-INFRA-GUARD, see §5).** Found
  refuting the allowlist candidate above; closed same day. A bare `Domain`
  target reaching this module (e.g. a nameserver `rdap_domain`/`whois` both
  surface as a first-class `Domain` entity) had no guard against being an
  infrastructure provider, only the generic expansion floor. Fixed via a new
  shared `util::domains::is_infra_provider_domain`, applied to BOTH target
  kinds; the Email-path's independently-maintained `is_role_email_local` was
  consolidated onto the single-sourced `is_infrastructure_email` in the same
  commit (3 words — `noc`/`sysadmin`/`tech` — it had that the shared list was
  missing were merged in, closing a second, smaller drift gap discovered
  while comparing the two lists). Off the open queue.
- **T2.14** (new, 2026-07-01) — the two `analyse()` hints T2.13 removed as
  dead code: SOL-HINT-NOISE sketched (event-sourced reinstatement for the
  60s hint; cap/cost-gate/summarise decision needed for the per-module hint).
  Not yet started.
- **T2.7** scraper-health signal — **partially covered (cycle 20):** SOL-HEALTH-SIGNAL
  node now sketched (`last_success_at` + `consecutive_failures` tracking, `hse doctor`
  surface + SPA panel); full implementation still open. **Elevated (cycle 17):**
  ahpra/acma_rrl/trove_au/`austlii` widen the scraper surface; priority remains raised.
- **§7 S4** — SOL-REDACT residual: archived success body not run through
  `redact_literal_secrets` (LOW). Contained.
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
- **C2/C6/C7** — capability nodes; solutions sketched, none started (gated on
  the §3.F enablers landing first, by design).
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
  (SOL-UPDATE-POISON-CONSISTENT, 2026-07-05); **T2.34 `[x]`** ✅
  (SOL-BITBUCKET-ATTACK-COMPLETE, 2026-07-08); **T2.35 `[x]`** ✅
  (SOL-CO-OWNERSHIP-ORDER-DETERMINISM, 2026-07-08); **T2.36 `[x]`** ✅
  (SOL-RUBYGEMS-ATTACK-COMPLETE, 2026-07-08); **T2.37 `[x]`** ✅
  (SOL-GITLAB-ATTACK-COMPLETE, 2026-07-08); **T2.38 `[x]`** ✅
  (SOL-CPAN-ATTACK-COMPLETE, 2026-07-08); **T2.39 `[x]`** ✅
  (SOL-GITEA-ATTACK-COMPLETE, 2026-07-08); **T2.40 `[x]`** ✅
  (SOL-CODEBERG-ATTACK-COMPLETE, 2026-07-08); **T2.41 `[x]`** ✅
  (SOL-HUGGINGFACE-ATTACK-COMPLETE, 2026-07-08); T2.7 open;
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
- **§4 (capability C1–C9):** C8 delivered ✅ (`streaming_probe`, 42-site webcam/fan/adult prober); **C9 delivered** ✅ (SOL-CACHE-INTERSCAN, cycle 18, `raw_archive` + dispatch cache gate); **C5 `[~]`** (SOL-GEOINT: `opencellid` cycle 19 + `cell_local`/`hse cells import` cycle 21 delivered, Weiszfeld geometric-median convergence delivered 2026-07-01 — stale here since, corrected 2026-07-05; AU bounding precision, movement/timeline layer, and cell-DB auto-sync remaining); **C3 `[~]`** (SOL-AU-MOAT: hlr_cnam/ahpra/acma_rrl/trove_au/smtp_vrfy/`austlii` shipped, courts/AustLII closed; GNAF/ASIC/cadastre remaining); **C4 `[~]`** (SOL-NETINT: netlas + censys + securitytrails + bgpview + ripestat all shipped; passive-DNS history + CDN cert-hash origin remaining); **C1 `[~]`** (SOL-CORR: `identity_paths` + CONNECTIONS cycle 26, timeline `classify` widened cycle 27, `SharesSecretWith` reused-secret link cycle 28; only AU-0xx rule-gap fill remains); C2/C6/C7 open by design, gated on §3.F. **SOL-UPDATE `[x]`** (cycle 22, `hse update`/upgrade + CLI consolidation 19→13 visible commands).

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
  for a focused follow-up rather than shipped with a regression — **closed
  2026-07-08, see below.** Gate green:
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
- **2026-07-08** — **SOL-SUBJECT-ANCHOR (new): closes FT.14 — `subject_fixes`
  now agrees with the correlator's own person-anchor gate instead of trusting
  a bare confidence score.** New `core::geo_family::is_subject_anchor_coord`:
  a `Coordinates` entity anchors the subject only via (1) the `device-sensor`
  tag (on-device GPS/network telemetry, bypasses the confidence floor — the
  bypass round-2 identified as missing from a naive `is_infrastructure_geo`
  reuse), or (2) `confidence >= SUBJECT_FIX_MIN` AND a
  `corroborating_sources()` member the correlator's own
  `is_anchoring_geo_source` already recognises as person-anchoring. Reuses
  the existing `pub(crate)` re-export at `correlator::mod` rather than
  duplicating the allowlist — one classifier for `is_infrastructure_geo`
  (AU-052/053/059), the engine's expansion-ranking bonus, and now
  `subject_fixes`, so the three can never silently disagree on which sources
  locate the person. A full audit of every `Coordinates`-constructing module
  found the fix closes the same bug class in `ip_geo`, `ip2location`,
  `netlas`, `geo_intel`, `overpass`, `opencellid`/`cell_intel`/`cell_local`,
  `mls`, `wifi_intel`, `employer_pivot`, `au_geo`/`qld_cadastre`, and
  `wikidata`'s P625 claim — all reach or exceed `SUBJECT_FIX_MIN` without
  being genuine person-anchors — while every allowlisted source
  (`geocode`/`photon`/`exif_geo`/`wigle`/`mylnikov`/`opencorporates`/
  `gleif_lei`/`asic_director`/…) and every `device-sensor`-tagged fix keeps
  anchoring unchanged. **New P→S gap logged, deliberately not fixed here**
  (§4a): `wifi_intel`, `cell_intel`, `mls`, `qld_cadastre`, and
  `employer_pivot` look like `ANCHORING_GEO_SOURCES` omissions rather than
  deliberate exclusions given their kinship to already-listed siblings
  (`wigle`, `au_property`) — widening that allowlist changes AU-052/053/059
  too, a distinct change needing its own review, not folded in here. Test
  delta: +1 (fail-before confirmed by reverting the new gate to the bare
  confidence check in place). Six pre-existing test fixtures (three files)
  standing in for "a confirmed GPS fix" with no evidence source were updated
  to carry the `device-sensor` tag `signal_radar`/`device_sensors` actually
  apply. Gate green: fmt/clippy `-D warnings`/rustdoc (private items) clean,
  full suite 0 failures (4443 lib tests), architecture suite green (30/30).
  **Paired:** `PROBLEM_TREE` §8 — same commit.
- **2026-07-08** — **SOL-WIFI-INTEL-ANCHOR (new): `wifi_intel` added to
  `ANCHORING_GEO_SOURCES`, closing the first of the 5 allowlist-omission gaps
  §4a logged earlier the same day.** Independently re-verified rather than
  trusting the earlier gap note: `wifi_intel::process()`'s BSSID-geolocation
  phase calls the same `wigle::query_wigle_detail` trilateration endpoint the
  standalone, already-allowlisted `wigle` module calls, and both modules share
  the identical `Coordinates | MacAddress | Ssid` `accepts()` restriction —
  `wigle`'s allowlist membership already covers this exact "self-triggered
  WiFi triangulation" shape. `docs/MODULES.md`'s module-history table confirms
  `wifi_intel` is the direct merge successor of a `bssid_locate` module that
  did the identical resolution; `git log -S` over the allowlist file found
  neither name was ever listed, so this was a plain omission carried through
  the merge, not a regression caused by it. One-line addition to
  `ANCHORING_GEO_SOURCES` (used by `is_infrastructure_geo` for
  AU-052/053/059/AU-018 and the engine's expansion-ranking bonus) — no new
  visibility, no new function, the existing single-sourced allowlist just
  gained its rightful member. Full suite confirms no consumer regressed: the
  two pre-existing `wifi_intel` references in `correlator/tests.rs` are
  `MacAddress` entities (unaffected, since the source check only gates
  `Coordinates`), and no test anywhere constructed a `wifi_intel`-sourced
  `Coordinates` entity expecting exclusion. **§4a refreshed:** `cell_intel`/
  `cell_local`/`mls`/`qld_cadastre`/`employer_pivot` remain open, each needing
  its own field-level verification rather than a batch add. Test delta: +1
  (`wifi_intel_bssid_resolution_is_person_anchoring_like_wigle`, fail-before
  confirmed by reverting the allowlist addition in place). Gate green:
  fmt/clippy `-D warnings`/rustdoc (private items) clean, full suite 0
  failures (4444 lib tests), architecture suite green (30/30). **Paired:**
  `PROBLEM_TREE` §8 — same commit.
- **2026-07-08** — **SOL-MLS-ANCHOR (new): `mls` joins `ANCHORING_GEO_SOURCES`
  — the 2nd of the 5 gaps logged closing FT.14. Also refutes the 3rd
  candidate, `cell_intel`/`cell_local`.** `modules/mls/mod.rs`'s own doc
  comment states it is used "as a third corroboration source alongside WiGLE
  and Mylnikov," and independently confirmed `accepts()` restricts it to
  `TargetKind::MacAddress` — the identical BSSID-only contract `wigle`/
  `mylnikov` already anchor with; all three resolve a BSSID against a
  different crowd-sourced position database (WiGLE / Mylnikov / Mozilla
  Location Service). One-line allowlist addition, no test anywhere relied on
  `mls` being excluded. **`cell_intel`/`cell_local` investigated and
  REFUTED**, not delivered: the §4a note's premise (kinship with
  `signal_radar`/`device_sensors`) did not survive reading the actual code —
  `cell_intel`'s own doc comment shows its `Coordinates` value comes from the
  SAME OpenCelliD database the already-excluded `opencellid` module queries
  (or an even coarser MCC-centroid fallback), and `cell_local` is explicitly
  an offline cache of that same database, gated on an EXISTING `Coordinates`
  target (enrichment of an already-anchored point, not an independent fix —
  same shape as `au_geo`/`qld_cadastre` from the FT.14 fix). Neither is a
  first-party device fix; allowlisting them would reopen the exact
  `ip_geo`/`opencellid` bug class FT.14 closed. §4a corrected in place to
  record the refutation. Test delta: +1
  (`mls_bssid_triangulation_is_person_anchoring_like_wigle_and_mylnikov`,
  fail-before confirmed by reverting the allowlist addition in place — the
  new test panicked on `assert!(is_anchoring_geo_source("mls"))`; restored,
  it passed). Full correlator/engine/geo_family suites confirm no consumer
  regressed. **§4a refreshed:** only `qld_cadastre`/`employer_pivot` remain
  open on this list. Gate green: fmt/clippy `-D warnings`/rustdoc (private
  items) clean, full suite 0 failures (4445 lib tests), architecture suite
  green (30/30). **Paired:** `PROBLEM_TREE` §8 — same commit.
- **2026-07-08 — no code change.** Closed the FT.14 follow-up gap list's
  last two candidates by direct-evidence refutation, and logged one new,
  distinct, deliberately-deferred finding. **`qld_cadastre` REFUTED:**
  `accepts()` is `TargetKind::Coordinates`-only and its own doc comment
  states it emits no ownership link — it enriches an already-established
  coordinate, the same "coordinate-keyed enrichment" shape the FT.14 fix
  already excluded for `au_geo`; no independent signal, no allowlist change.
  **`employer_pivot` REFUTED:** has no allowlisted mechanism-identical peer
  (unlike `wifi_intel`/`mls`) — the allowlisted business-registry sources
  all derive subject↔business linkage from a formal government register,
  while `employer_pivot` scrapes an arbitrary discovered `Email`-domain/
  `Domain` target's contact pages, a linkage its own code comment documents
  a real past misattribution from (`dns@cloudflare.com` → Cloudflare's
  Sydney HQ); the engine's wrong-identity gate covers only `Username`/
  `Person`, leaving no person-identity check on this path at all. Allowing
  it into `ANCHORING_GEO_SOURCES` risks reopening the exact bug class FT.14
  closed via a different vector — refused. **New gap logged, deliberately
  not fixed this cycle:** `employer_pivot`'s `Domain`-target path has no
  analogue to its `Email`-path's role-account guard, so a bare, incidentally-
  discovered domain gets no person-linkage check at all — a distinct
  target-gating question, scoped for a future cycle rather than folded in
  here to avoid scope creep on an unrelated design question (§4a). The
  original 5-candidate gap list this cycle closes out is fully resolved: 2
  delivered (`wifi_intel`, `mls`), 3 refuted (`cell_intel`/`cell_local`
  together, `qld_cadastre`, `employer_pivot`). Gate re-run to confirm the
  working tree is still green (fmt/clippy/doc clean, full suite 0 failures,
  4445 lib tests, architecture suite 30/30 — unchanged from the prior
  commit, as expected for a no-code-change reconciliation). **Paired:**
  `PROBLEM_TREE` §8 — same commit.
- **2026-07-08 — SOL-EMPLOYER-PIVOT-INFRA-GUARD (new): closes the
  `employer_pivot` `Domain`-target gap this cycle's own earlier note found.**
  Investigated what the missing check would even look for rather than
  assuming a shape: found `rdap_domain::build_ns_entity` (0.80 confidence,
  `rdap-ns`/`ns` tags) and `whois`'s nameserver loop (0.82, `whois-ns` tag)
  both surface a scanned domain's own nameservers as first-class `Domain`
  entities, comfortably above the default 0.50 expansion floor, with no
  exclusion anywhere in `core` and the wrong-identity gate covering only
  `Username`/`Person` (confirmed by direct read) — a concrete, reachable
  vector for the exact "infra provider misattributed as the subject's
  employer" bug the already-fixed `dns@cloudflare.com` case closed for
  `Email` targets, but via `Domain` targets instead. `whois::process()`
  already gates its own email emission through the single-sourced
  `util::domains::is_infrastructure_email` (role local-part OR CDN/
  registrar/cloud/ESP domain) — a strictly more capable check
  `employer_pivot`'s own, independently-maintained `is_role_email_local`
  (local-part only) never used. Extracted the domain-only half into new
  `util::domains::is_infra_provider_domain` (reused internally by
  `is_infrastructure_email` so the two can't drift), and wired it into a new
  `employer_pivot::should_skip_pivot(target, domain)` applied to BOTH target
  kinds. While consolidating, compared the two role-word lists field-by-field
  and found `is_role_email_local`'s 20 words matched
  `util::domains::is_role_localpart`'s EXCEPT `noc`/`sysadmin`/`tech` —
  merged those 3 into the shared list (a second, smaller drift gap the
  comparison surfaced, incidentally strengthening `whois`/`ripestat` too,
  which share the same list) before switching `employer_pivot`'s `Email`
  path onto `is_infrastructure_email` and deleting `is_role_email_local`.
  Confirmed strictly no coverage loss (all 20 words re-verified covered) and
  the switch is case-insensitive where the old helper was deliberately
  case-sensitive — strictly more protective, never less. Full call-site
  check: `whois`/`ripestat`/`rdap_domain` suites unaffected. Test delta: +6
  net (removed 3 tests for the deleted function, added 5 `should_skip_pivot`
  tests incl. the nameserver-target regression — fail-before confirmed by
  reverting the new check in place — plus 2 new `util::domains` tests for
  the extracted function and the 3 merged words). Gate green: fmt/clippy
  `-D warnings`/rustdoc (private items) clean, full suite 0 failures (4449
  lib tests, +4), architecture suite green (30/30). **Paired:**
  `PROBLEM_TREE` §8 — same commit.
- **2026-07-08 — SOL-BITBUCKET-ATTACK-COMPLETE: closes T2.34 via a
  multi-angle discovery sweep (6 independent angles, 25 findings
  independently adversarially verified against the actual code).** With the
  FT.14 follow-up gap list fully closed and no in-progress node, ran a fresh
  code-grounded discovery pass per the loop's own priority order. Selected
  `bitbucket_user` from the largest cluster (attack-mapping completeness,
  16 modules of the `dockerhub_user`/T2.28 replace-instead-of-extend shape)
  as the single most faulty instance: unlike its 15 siblings, which only
  OMIT techniques, `bitbucket_user` actively CLAIMED `T1589.002` (Email
  Addresses) on a fabricated basis (`BbUser`/`build_entities` never
  constructs an `Email` entity anywhere — confirmed by direct read, not the
  sweep's summary alone) while omitting `T1589.003` (Person from
  `display_name`) and `T1591.001` (Address/Coordinates from `location`),
  both real, unit-tested paths. Declared the precise, complete set:
  `T1589.003`, `T1591.001`, `T1593.003`. Test: +1
  (`attack_techniques_covers_every_entity_kind_this_module_produces`,
  fail-before confirmed by reverting the function body in place). No
  `tests/architecture.rs` cross-module pin referenced `bitbucket_user`.
  **§4a gains 24 further independently-verified candidates** from this same
  sweep (15 more attack-mapping instances, a `derive_co_ownership`
  determinism leak, `asic_persons`'s dropped CKAN `total` field, 2 unwired
  items, 3 newer-clippy-toolchain lints, 2 silent-error-swallowing sites) —
  all deliberately deferred to future one-at-a-time cycles; the proxy-pool
  subsystem finding was excluded as needing a design decision (T2.7/T2.14
  bucket). Gate green: fmt/clippy `-D warnings`/rustdoc (private items)
  clean, full suite 0 failures (4450 lib tests, +1), architecture suite
  green (30/30). **Paired:** `PROBLEM_TREE` §8 — same commit.
- **2026-07-08 — SOL-CO-OWNERSHIP-ORDER-DETERMINISM: closes T2.35
  (retroactively completing this §5 pairing — the prior commit's
  `PROBLEM_TREE` §8 entry claimed it but this entry was omitted from that
  commit; found and fixed as this cycle's first step, before any new work,
  per the loop's own dirty-tree-finish-first rule).** `derive_co_ownership`'s
  two `HashMap` groupings (shared registrant, shared dedicated IP) leaked
  Rust's randomised iteration order into the persisted `SameOperator`
  relation sequence — the 5th instance of the `web_crawler`/T2.25
  determinism-leak class, and the first in the relation-derivation layer.
  Every sibling `derive_*` builder in the same file ends with
  `sort_edges(&mut out)`; this was the one exception, and the correlator's
  own twin logic for the identical grouping (`rules::org`'s AU-109/AU-110)
  already guarded this exact case. Measured the leak directly: a test
  feeding the identical logical input in forward vs. reversed order
  returned the same 6 relations in different orders against the unfixed
  code. Mirrored `rules::org`'s exact pattern at both sites: sort the group
  keys before iterating. Test: +1
  (`co_ownership_multi_group_emission_order_is_independent_of_input_order`),
  fail-before confirmed. Relation (107)/engine (115)/correlator (422) suites
  unaffected. Gate green: fmt/clippy `-D warnings`/rustdoc (private items)
  clean, full suite 0 failures (4451 lib tests, +1), architecture suite
  green (30/30). **Paired:** `PROBLEM_TREE` §8 — same commit.
- **2026-07-08 — SOL-RUBYGEMS-ATTACK-COMPLETE: closes T2.36, continuing the
  `dockerhub_user`/T2.28 scoped-sweep list T2.34 left open.** `rubygems_user`
  was the 2nd genuine over-claim instance in that list (the same shape T2.34
  fixed for `bitbucket_user`): its override `&["T1589.002", "T1593.003"]`
  claimed Email Addresses on a fabricated basis (`RgGem`/`build_entities`
  never construct an `EntityKind::Email` anywhere — confirmed by direct
  read) while omitting `T1589.003` (Person from each name in `authors`, via
  `profile_kit::person_from_name`, already unit-tested by
  `emits_person_from_multi_word_author`). Independently read `npm_author`/
  `crates_io` (identical homepage/repository-derived `Url`/`Domain`/
  cross-platform-`Username` pivot shape) to confirm neither declares a
  technique for that pivot, only for the registry `Username` itself, so no
  technique was invented for `rubygems_user`'s own homepage/GitHub-pivot
  fields. Declared the precise set: `T1589.003`, `T1593.003` (dropping the
  fabricated `T1589.002`). Test: +1
  (`attack_techniques_covers_every_entity_kind_this_module_produces_and_no_more`,
  fail-before confirmed by writing it against the unfixed override first).
  No `tests/architecture.rs` cross-module pin referenced `rubygems_user`.
  **§4a's attack-mapping-completeness cluster now 14, down from 15**
  (`gitlab_user`, `cpan_user`, `gitea_user`, `codeberg_user`,
  `huggingface_user`, `hexpm_user`, `devto`, `crates_io`, `npm_author`,
  `stackoverflow_user`, `steam_profile`, `launchpad_user`, `pypi_user`,
  `bluesky_user` remain, deliberately deferred to future one-at-a-time
  cycles). Gate green: fmt/clippy `-D warnings`/rustdoc (private items)
  clean, full suite 0 failures (4452 lib tests, +1), architecture suite
  green (30/30). **Paired:** `PROBLEM_TREE` §8 — same commit.
- **2026-07-08 — SOL-GITLAB-ATTACK-COMPLETE: closes T2.37, continuing the
  scoped-sweep list T2.36 left open.** `gitlab_user` was a pure-omission
  instance, not a fabrication like T2.34/T2.36: its existing
  `T1589.002` (Email Addresses) claim is genuine (bio emails really are
  extracted via `profile_kit::bio_emails` into `EntityKind::Email` —
  confirmed by direct read), but its override
  `&["T1589.002", "T1593.003"]` omitted three real, already-unit-tested
  construction paths: a `Person` from the real `name` field (T1589.003), an
  `Organisation` from the self-reported `organization` field (T1591.002),
  and an `Address`/`Coordinates` from `location` (T1591.001). Declared the
  precise, complete set: `T1589.002`, `T1589.003`, `T1591.001`, `T1591.002`,
  `T1593.003`. Test: +1
  (`attack_techniques_covers_every_entity_kind_this_module_produces`,
  fail-before confirmed by writing it against the unfixed override first).
  No `tests/architecture.rs` cross-module pin referenced `gitlab_user`.
  **§4a's attack-mapping-completeness cluster now 13, down from 14**
  (`cpan_user`, `gitea_user`, `codeberg_user`, `huggingface_user`,
  `hexpm_user`, `devto`, `crates_io`, `npm_author`, `stackoverflow_user`,
  `steam_profile`, `launchpad_user`, `pypi_user`, `bluesky_user` remain,
  deliberately deferred to future one-at-a-time cycles). Gate green:
  fmt/clippy `-D warnings`/rustdoc (private items) clean, full suite 0
  failures (4453 lib tests, +1), architecture suite green (30/30).
  **Paired:** `PROBLEM_TREE` §8 — same commit.
- **2026-07-08 — SOL-CPAN-ATTACK-COMPLETE: closes T2.38, continuing the
  scoped-sweep list T2.37 left open.** `cpan_user` was another
  pure-omission instance, like `gitlab_user`: its existing `T1589.002`
  (Email Addresses) claim is genuine — `build_entities` extracts BOTH the
  public `email` list AND biography-embedded emails
  (`profile_kit::bio_emails`) into real `EntityKind::Email` entities,
  confirmed by direct read — but its override `&["T1589.002", "T1593.003"]`
  omitted two real, already-unit-tested construction paths: a `Person`
  from the real `name` field (T1589.003) and an `Address`/`Coordinates`
  from `location` (T1591.001). No `Organisation` entities are built here,
  so T1591.002 correctly does not apply. Declared the precise, complete
  set: `T1589.002`, `T1589.003`, `T1591.001`, `T1593.003`. Test: +1
  (`attack_techniques_covers_every_entity_kind_this_module_produces`,
  fail-before confirmed by writing it against the unfixed override first).
  No `tests/architecture.rs` cross-module pin referenced `cpan_user`.
  **§4a's attack-mapping-completeness cluster now 12, down from 13**
  (`gitea_user`, `codeberg_user`, `huggingface_user`, `hexpm_user`, `devto`,
  `crates_io`, `npm_author`, `stackoverflow_user`, `steam_profile`,
  `launchpad_user`, `pypi_user`, `bluesky_user` remain, deliberately
  deferred to future one-at-a-time cycles). Gate green: fmt/clippy
  `-D warnings`/rustdoc (private items) clean, full suite 0 failures (4454
  lib tests, +1), architecture suite green (30/30). **Paired:**
  `PROBLEM_TREE` §8 — same commit.
- **2026-07-08 — SOL-GITEA-ATTACK-COMPLETE: closes T2.39, continuing the
  scoped-sweep list T2.38 left open.** `gitea_user` was another
  pure-omission instance, like `gitlab_user`/`cpan_user`: its existing
  `T1589.002` (Email Addresses) claim is genuine — `build_entities`
  extracts BOTH the public `email` field AND `description`-embedded emails
  (`profile_kit::bio_emails`) into real `EntityKind::Email` entities,
  confirmed by direct read — but its override `&["T1589.002", "T1593.003"]`
  omitted two real, already-unit-tested construction paths: a `Person`
  from the real `full_name` field (T1589.003) and an `Address`/
  `Coordinates` from `location` (T1591.001). No `Organisation` entities
  are built here, so T1591.002 correctly does not apply. Declared the
  precise, complete set: `T1589.002`, `T1589.003`, `T1591.001`,
  `T1593.003`. Test: +1
  (`attack_techniques_covers_every_entity_kind_this_module_produces`,
  fail-before confirmed by writing it against the unfixed override first).
  No `tests/architecture.rs` cross-module pin referenced `gitea_user`.
  **§4a's attack-mapping-completeness cluster now 11, down from 12**
  (`codeberg_user`, `huggingface_user`, `hexpm_user`, `devto`, `crates_io`,
  `npm_author`, `stackoverflow_user`, `steam_profile`, `launchpad_user`,
  `pypi_user`, `bluesky_user` remain, deliberately deferred to future
  one-at-a-time cycles). Gate green: fmt/clippy `-D warnings`/rustdoc
  (private items) clean, full suite 0 failures (4455 lib tests, +1),
  architecture suite green (30/30). **Paired:** `PROBLEM_TREE` §8 — same
  commit.
- **2026-07-08 — SOL-CODEBERG-ATTACK-COMPLETE: closes T2.40, continuing
  the scoped-sweep list T2.39 left open.** Ultracode was on this cycle, so
  ran an 11-agent Workflow verification sweep first — one independent
  agent per remaining candidate (`codeberg_user`, `huggingface_user`,
  `hexpm_user`, `devto`, `crates_io`, `npm_author`, `stackoverflow_user`,
  `steam_profile`, `launchpad_user`, `pypi_user`, `bluesky_user`), each
  tracing `build_entities` directly rather than trusting the gap list.
  Result: all 11 confirmed pure omissions — no new fabrication instances
  beyond `bitbucket_user`/T2.34 and `rubygems_user`/T2.36. Two facts
  surfaced for future cycles: `huggingface_user` genuinely builds an
  `Organisation` from `orgs[]` (needs T1591.002 in addition to
  T1589.002/T1589.003 — a 3-technique gap); `crates_io`/`npm_author` each
  carry a `tests/architecture.rs` pin whose expected-array assertion (with
  a now-stale "no Person/Organisation/Address collection" comment) will
  need updating alongside their eventual fix. `codeberg_user` was another
  pure-omission instance, like `gitlab_user`/`cpan_user`/`gitea_user`: its
  existing `T1589.002` (Email Addresses) claim is genuine —
  `build_entities` extracts `description`-embedded emails
  (`profile_kit::bio_emails`) into real `EntityKind::Email` entities,
  confirmed by direct read — but its override
  `&["T1589.002", "T1593.003"]` omitted two real, already-unit-tested
  construction paths: a `Person` from the real `full_name` field
  (T1589.003) and an `Address`/`Coordinates` from `location` (T1591.001).
  No `Organisation` entities are built here, so T1591.002 correctly does
  not apply. Declared the precise, complete set: `T1589.002`, `T1589.003`,
  `T1591.001`, `T1593.003`. Test: +1
  (`attack_techniques_covers_every_entity_kind_this_module_produces`,
  fail-before confirmed by writing it against the unfixed override first).
  No `tests/architecture.rs` cross-module pin referenced `codeberg_user`.
  **§4a's attack-mapping-completeness cluster now 10, down from 11**
  (`huggingface_user`, `hexpm_user`, `devto`, `crates_io`, `npm_author`,
  `stackoverflow_user`, `steam_profile`, `launchpad_user`, `pypi_user`,
  `bluesky_user` remain, deliberately deferred to future one-at-a-time
  cycles). Gate green: fmt/clippy `-D warnings`/rustdoc (private items)
  clean, full suite 0 failures (4456 lib tests, +1), architecture suite
  green (30/30). **Paired:** `PROBLEM_TREE` §8 — same commit.
- **2026-07-08 — SOL-HUGGINGFACE-ATTACK-COMPLETE: closes T2.41, continuing
  the scoped-sweep list T2.40 left open — the largest remaining gap in the
  queue.** Independently re-read `src/modules/huggingface_user/mod.rs` in
  full before touching anything, treating both the gap list's and the
  prior cycle's verification sweep's finding as unproven until
  re-confirmed directly. Its override `&["T1593.003"]` was genuine (a
  confirmed Hugging Face profile Username), but `build_entities` also
  demonstrably constructs a `Person` from the real `fullname` field
  (needs T1589.003), an `Email` from the public `email` field when made
  visible (needs T1589.002), and an `Organisation` for each `orgs[]`
  membership (needs T1591.002) — all three real, already-unit-tested
  paths, none credited. `HfUser` has no `location` field, so T1591.001
  correctly does not apply. Declared the precise, complete set:
  `T1589.002`, `T1589.003`, `T1591.002`, `T1593.003`. Test: +1
  (`attack_techniques_covers_every_entity_kind_this_module_produces`,
  fail-before confirmed by writing it against the unfixed override first).
  No `tests/architecture.rs` cross-module pin referenced
  `huggingface_user`. **§4a's attack-mapping-completeness cluster now 9,
  down from 10** (`hexpm_user`, `devto`, `crates_io`, `npm_author`,
  `stackoverflow_user`, `steam_profile`, `launchpad_user`, `pypi_user`,
  `bluesky_user` remain, deliberately deferred to future one-at-a-time
  cycles). Gate green: fmt/clippy `-D warnings`/rustdoc (private items)
  clean, full suite 0 failures (4457 lib tests, +1), architecture suite
  green (30/30). **Paired:** `PROBLEM_TREE` §8 — same commit.
