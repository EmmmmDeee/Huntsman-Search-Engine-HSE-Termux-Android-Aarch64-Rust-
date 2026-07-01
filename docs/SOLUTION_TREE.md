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
  GREATEST-laws, geo round-trips, no-panic crash-resistance for every network parser,
  **+ the dossier/txt/html import proptest** — `cli/import/tests.rs::prop`, 3
  properties over `parse_dossier`/`parse_oathnet_txt`/`parse_oathnet_html`, delivered
  2026-06-17, this note's own "outstanding" claim was stale until corrected
  2026-07-01) + `criterion` (`benches/scan_throughput.rs`) + the correlation pass's
  own deliberately-non-criterion perf harness (`core::correlator::perf` —
  `#[cfg(test)]`, `std::time::Instant`-based, explicitly chosen over `criterion` to
  avoid a heavy transitive dep on the minimal-dependency Termux build; catches an
  O(n²) rule reintroduction the same way `criterion` would have, at zero extra
  dependency cost — a *better*-justified close of the "widen criterion to the
  correlation pass" item this note used to list as a gap, not a shortfall). Running
  that guard while reconciling this note found it genuinely FAILING — fixed as new
  `PROBLEM_TREE` T2.22 / `SOLUTION_TREE` SOL-AU087-INDEX, same commit. *Gap:*
  `cargo-fuzz` (nightly CI lane) is the sole remaining item — genuinely open,
  deferred: wiring a new CI lane is a higher-blast-radius, shared-system change this
  autonomous loop doesn't take without explicit operator sign-off. **(§4b)**

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
  single-scan regression. *Residual:* the per-scan **budget** statics'
  `reset_scan`-zeroing folds into the same ambient later (LOW).
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
  *Closes:* the key-in-URL **log** exposure (S4 mostly mitigated).
  *Gap closed (2026-07-01):* investigated the sketched fix ("run the archived
  success body through `redact_literal_secrets`") before implementing it
  verbatim — found `crate::util::raw_archive`'s own module doc carries an
  explicit, quoted operator directive ("must always be retained in their raw
  form... never encrypted, hashed, or redacted") that sketch would have
  violated; the sketch's "0600, but pulled into the non-0600 DB/dossiers via
  S3" premise is also now stale, since S3 (below) already made the dossier
  0600. The GENUINE residual is different: `hse export -o <path>` deliberately
  leaves permissions to the user's umask (S3's own documented boundary, since
  the operator is explicitly choosing to share that file), and the full
  dossier's RAW SOURCE RECORDS section embeds the archived body verbatim into
  that exportable copy — a provider echoing the request URL/params back could
  leak the OPERATOR's OWN key into a shared export. Fixed the correctly-scoped
  half: `raw_archive`'s on-disk file is untouched (policy honoured); a new
  `redact_own_keys` (`cli/export/renderers.rs`) masks only the operator's OWN
  keys (`own_api_keys()`) in the dossier's derived, exportable copy, reusing
  `redact_literal_secrets` (widened `pub(super)`→`pub(crate)`). 2 new
  regression tests (masks the operator's own echoed key; leaves genuine
  target/foreign data untouched), `git stash`-confirmed non-vacuous.
  *Closes:* **§7 S4** (`[ ]`→`[x]`). ✅
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
  that renders the shortest typed thread between identities as text.
  *Correction (2026-07-01, found during a discovery pass):* "Remaining:
  first-class timeline output" was stale — `src/core/timeline/mod.rs` (+
  `tests.rs`) already ships a full, tested `reconstruct()` engine (10
  `TimelineEventKind` variants — breach exposure, domain registration/
  expiry, account creation, incorporation/dissolution, first/last seen,
  date of birth, generic — dependency-free date parsing, sorted
  oldest-first), wired into the CLI full dossier's "TIMELINE (N events)"
  section (`cli/scan/dossier.rs`). *Remaining:* further AU-0xx rule-gap
  fill; the "controller behind reused secrets" link facet (PROBLEM_TREE
  C1's own text); wider timeline consumers beyond the full dossier (e.g.
  the SPA, the JSON export) if warranted.
- **`[~]` SOL-PERF-PUBLISH · Reproducible on-device benchmark** → **C2**: with SOL-F3
  benches + SOL-BLOCKING throughput + SOL-F2 flat-RAM, publish "N selectors, on a
  phone, in T s, M MB".
  *First real data point delivered (2026-07-01):* `web_crawler`'s BFS crawl loop
  now fetches same-round batches of up to 8 queued pages concurrently
  (`crawl_util::fetch_batch`, mirroring `probe_config_leaks`'s
  `Semaphore`/`JoinSet` shape) instead of one page at a time, with results
  reassembled by original round position so page-visit order and the 60-page
  cap stay deterministic under concurrent completion timing (§1.7/§5). Live
  A/B against a real 47-page site: 17.1s (pre-fix, sequential) → 5.3s
  (this fix), ~3.2× faster, byte-identical output (47 pages, 53 internal
  links). 5 new tests. *Remaining:* the actual reproducible "N selectors, T
  seconds, M MB RAM" published benchmark suite — this is one measured
  increment toward it, not the deliverable itself.
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
  *Correction (2026-07-01, found during a discovery pass):* "state
  cadastre/property" in *Remaining* below was stale — `au_property`
  (registered, wired module) already queries NSW Spatial/ELVIS, VIC
  MapShare, and QLD Globe cadastral/land-title portals for owner-name
  matches, exactly that capability.
  *Remaining:* GNAF/AusPost; fuller ASIC/ABR graph; broader state
  cadastral coverage beyond NSW/VIC/QLD (e.g. SA/WA/TAS land-title
  portals) if warranted.
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
  *Delivered (2026-07-01, the honest scoped increment of the "cell DB
  auto-sync" remainder below):* **`hse cells status` now warns on a stale
  local snapshot.** Investigated whether genuine unattended re-sync (a
  cron/daemon path) was buildable this cycle before assuming so: `hse`
  has no daemon/background-process infrastructure anywhere — every
  subcommand including `cells import` is one-shot, and the only long-lived
  process (`hse serve`) is foreground/opt-in — so literal "auto-sync"
  needs either new daemon infrastructure (a large architectural addition,
  not appropriate unprompted in one cycle) or an OS-level cron example (a
  docs/shell deliverable, not a code fix). Found the real, small increment
  available without either: `hse cells status` already read the last
  import's age but applied no judgement to it. New pure
  `staleness_warning(age_secs) -> Option<String>`
  (`src/cli/cells/mod.rs`) prints a warning + remediation hint above a
  90-day threshold (OpenCelliD publishes no fixed dump cadence, so this is
  advisory, not a hard cutoff). 4 new regression tests, `git
  stash`-confirmed non-vacuous (the tests don't compile against the
  unfixed code, since the new items don't exist yet). Live-verified
  against a real imported DB: fresh import → no warning; the same DB with
  `imported_at` backdated 91 days → the exact warning text. `hse
  selftest` 9/9 unaffected.
  *Remaining:* AU bounding precision; movement/timeline layer; genuine
  unattended cell-DB re-sync (a cron/daemon path) still needs either new
  daemon infrastructure `hse` doesn't have or an OS-cron documentation
  deliverable — neither attempted; staleness DETECTION is now solved,
  staleness PREVENTION (auto re-import) is not.
- **`[~]` SOL-OFFENSIVE · Exposure & reuse graph** → **C6**: broaden SERP dorks,
  credential-reuse graph, `aho-corasick` (SOL-F1) key-harvest + entropy gate.
  *Correction (2026-07-01, found during a discovery pass):* the marker was
  stale at `[ ]` (fully not started) — the `aho-corasick` key-harvest +
  entropy gate sub-item is already shipped:
  `oathnet_pro::key_harvest::is_likely_real_key` combines a cached
  aho-corasick context-exclusion pass (`util::scan::MatchSet`, SOL-F1)
  with a Shannon-entropy ≥3.5 threshold, its own doc comment confirming
  "One cached `aho-corasick` pass via `util::scan` (SOL-F1)". *Remaining:*
  broaden SERP-dork coverage; mature the credential-reuse graph (link
  accounts by shared salted hash/session token across sources).
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
  (`KeyGated`/`Paid`-only), or collapse to a bounded summary count.
  ✅ **Scan-level leg delivered (2026-07-01).** `cli/scan/dossier.rs` gained
  `scan_ran_long_with_a_zero_yield_module(wall_time_ms, events)` — reads the
  scan's own `ModuleDone { found: 0, .. }` events (same source as
  `zero_yield_keyed_or_paid_modules`); `print_diagnostics` appends the
  original wording ("scan exceeded 60s with at least one zero-yield module —
  tighten module_timeout_ms") to `diag.optimization_hints` when it holds. 4
  new unit tests, incl. the 60s boundary (`>`, not `>=`).
  ✅ **Per-module leg resolved, not rebuilt (2026-07-01).** The noise
  decision surfaced a bigger defect in the exact mechanism this leg would
  have duplicated: `AdaptiveRouting::recommended_skips` — see new
  **SOL-LEDGER-ZERO-YIELD** below. With that fixed, the properly-throttled
  (`≥5` scans, `≥80%` rate) cross-scan signal now actually fires, which is a
  strictly better answer than a noisy, statistically-weak per-scan
  per-module hint would have been. `SOL-HINT-NOISE` `[~]`→`[x]`, both legs
  closed; T2.14 `[~]`→`[x]`.
- **`[x]` SOL-LEDGER-ZERO-YIELD · Fix the cross-scan ledger's dead
  zero-yield tracking** → **T2.15** (found while investigating
  SOL-HINT-NOISE): `ledger::persist_ledger` only ever iterated
  `modules_by_yield` — built exclusively from emitted entities, so a
  zero-yield module was structurally invisible to it, meaning
  `LedgerEntry::zero_yield_rate` could never be anything but its `Default`
  0.0 for ANY module, silently disabling `recommended_skips` since the
  ledger feature was introduced. Split `persist_ledger`'s pure mutation core
  into `update_ledger(ledger, modules, zero_yield_modules, kinds)` (no I/O,
  directly unit-testable) taking a **separate** `zero_yield_modules: &[String]`
  list; new pure `analyse::zero_yield_module_names(events, modules_by_yield)`
  computes it from the scan's own `ModuleDone` events (same premise as
  SOL-ROI-HINT/SOL-HINT-NOISE). Moved the `persist_ledger` call **out of**
  `analyse()` — it has no `StoragePort` access to compute the diff — to the
  3 real call sites (`cli/scan/dossier.rs`, `cli/scan/mod.rs`'s `--output
  json` branch, `api/handlers/mod.rs`'s post-scan hook), which pairs a
  bonus fix: `analyse()`'s 13 unit tests no longer silently mutate the real
  on-disk `$HOME/.huntsman/module_stats.json` (they never should have).
  9 new unit tests. **Verified live**, not just by inspection: the
  pre-existing real `module_stats.json` (20 historical scans) showed
  `zero_yield_rate: 0.0` on every one of 11 real modules tracked (only a
  hand-crafted `synthetic` test entry had a nonzero rate) — proving the bug
  in production data. A real `hse scan -k domain -v wikipedia.org
  --free-only --passive-only` run after the fix correctly recorded
  `geo_domain_classifier` (dispatched, `found: 0`) as `zero_yield_scans: 1,
  zero_yield_rate: 1.0` in the ledger — absent from `modules_by_yield` in
  the same scan's JSON output, exactly as designed.
- **`[x]` SOL-CONSUMES-DELEGATE · Single-source `Module::consumes()`'s
  default onto `consumes_via_probe`** → **T2.16** (found by a fresh
  discovery pass): the trait default duplicated the identical probe-filter
  logic inline instead of calling the already-existing, already-tested
  `consumes_via_probe` free function — making that function dead outside
  its own tests, despite its own doc comment claiming it was "the default
  body." Widened `consumes_via_probe<M: Module + ?Sized>(m: &M)` (from
  `&dyn Module`) so it's callable both by concrete stub types and from
  inside `consumes()`'s own default body, where `self: &Self` must stay
  possibly-unsized (adding `Self: Sized` to `consumes()` to allow the
  unsized coercion would remove it from `dyn Module`'s vtable, breaking
  every `&dyn Module`/`Arc<dyn Module>` call site). New regression test
  `module_consumes_default_delegates_to_consumes_via_probe` pins the
  invariant directly. 1 new test; behaviour-preserving (both copies
  computed identically before the fix — this closes a drift *risk*, not an
  observed dispatch bug).
- **`[x]` SOL-CRAWL-CONCURRENCY · Reconcile `web_crawler`'s doc-claimed
  concurrency with its actual sequential BFS loop** → **T2.17**: the module
  doc claimed "4 concurrent requests" but `process()`'s crawl loop fetches
  one URL at a time. ✅ **Resolved via option (a) (2026-07-01):** corrected
  the module doc (`src/modules/web_crawler/mod.rs` lines 5-9, 28-38) to
  state the crawl loop is sequential (one request in flight), contrasting
  it explicitly with the genuinely-16-way-concurrent config-leak probe in
  the same file so the two subsystems can't be conflated again. Option (b)
  (build real concurrency, mirroring `probe_config_leaks`'s
  `Semaphore`/`JoinSet`) is real perf value but needs deliberate care to
  keep page-visit order — and which pages fall inside the page cap —
  deterministic under concurrent completion timing; not forced into a
  doc-only cycle. Folded into **C2**'s solution text as a concrete, scoped
  future increment rather than left as an orphan node. Doc-only; no code
  behaviour change, no new test (consistent with this session's other pure
  doc-audit corrections).
- **`[x]` SOL-VICTIM-TRUNCATION · Surface OathNet-JSON per-victim import
  caps instead of silently dropping the excess** → **T2.18**: `parse_
  oathnet_json`'s 5 per-victim field caps (device IPs/emails/HWIDs/Discord
  IDs/device users) fed `ImportStats` counters that only ever counted
  post-cap emitted entities, so a truncated import reported as a complete
  one with zero signal anywhere. Verified real via an adversarial
  3-lens-per-candidate workflow re-checking this alongside two sibling
  candidates a prior cycle's discovery fan-out surfaced but never acted on
  (`push_macs`/`push_ibans`/`push_ssids` dedup-before-cap in
  `cli/import/mod.rs`, and `zoomeye`'s unexposed true-match-count) — both
  siblings had their own impact lens rate them as NOT genuinely reachable
  (deduplicated-unique-value caps are unrealistic to hit; ZoomEye's cap is
  essentially unreachable AND the raw response is archived verbatim
  regardless), while this candidate's accuracy AND impact lenses
  independently agreed it was real, with no contradiction — the
  differentiator that made it the pick. ✅ **Fixed.** New
  `note_if_truncated(stats, len, cap)` helper in `json.rs`, called once per
  site before its existing `.take(N)` loop; new `ImportStats::
  victim_fields_truncated: usize` counter surfaced as a conditional
  `"WARNING: N victim field(s) truncated…"` line in `print_import_stats`
  and a `victim_fields_truncated` field in the `--output json` envelope.
  The caps themselves are untouched (bounded-memory protection against a
  hostile/malformed export is correct and intentional) — only the silent
  drop is fixed. 2 new `#[tokio::test]`s on `parse_oathnet_json` directly
  (a truncated fixture asserts the entity counts stay exactly capped AND
  the counter fires; an under-cap fixture asserts the counter stays
  silent). **Verified live**, not just by inspection: `hse import
  <fixture.json> --output json` against a synthetic victim record with 25
  device_emails + 8 hwids printed `WARNING: 2 victim field(s)
  truncated…` to the human summary and `"victim_fields_truncated": 2` in
  the JSON envelope, entities correctly capped at 20/5; a second fixture
  under every cap produced no warning line at all.
- **`[x]` SOL-CHAIN-TXCOUNT · Saturate the Esplora combined tx-count sum**
  → **T2.19**: `enrich_esplora` summed two untrusted, explorer-supplied
  `u64` tx counts with plain `+`, while the exact same struct's
  `funded_txo_sum`/`spent_txo_sum` two lines above already applied this
  project's own "never trust an input number" rule. `overflow-checks =
  true` (this project's dev/test default) panics on a crafted/corrupted
  response; `[profile.release]` (what `hse` actually ships) silently wraps
  to a bogus small `tx_count` — a wrong finding presented as fact, reachable
  by any ordinary BTC/LTC `CryptoAddress` scan (stealer/breach data
  routinely contains clipboard-hijacked wallet addresses) against a
  misbehaving upstream, no adversarial intent required. ✅ **Fixed.**
  Extracted a pure `combined_tx_count(chain, mempool) -> u64` helper
  (`chain.saturating_add(mempool)`), mirroring this file's own
  `format_units`/`build_evidence` pure-helper pattern so the fix is
  directly unit-testable without mocking `enrich_esplora`'s HTTP call. 2
  new tests (saturation at `u64::MAX`; normal-range sanity). Verified the
  regression test is non-vacuous: `git stash`-ed the fix and re-ran the
  test — it doesn't exist against the unfixed code.
- **`[x]` SOL-TEST-NAME-OVERCLAIM · Fix 2 tests whose names promise
  "stable"/"complete" coverage their bodies don't verify** → **T2.20**:
  `module_registry_count_is_stable` (`tests/architecture.rs:296-303`)
  asserted only a one-sided floor (`>= 75`), not stability;
  `to_json_is_stable_and_complete` (`src/audit/tests.rs:217-235`) called
  `to_json()` once (no stability check) and asserted only 4 of the 11
  top-level JSON keys (no completeness check). ✅ **Fixed, via a stronger
  third option than either originally sketched.** (1) Added a
  `HashSet`-based duplicate-name check alongside the existing floor —
  catches the exact "bad merge silently duplicates modules" scenario
  without a fragile hand-maintained exact count (matching this codebase's
  own established avoidance of that fragility, e.g.
  `modules_md_lists_every_registered_module`'s content-membership check
  rather than a count pin). (2) Verified `to_json()`'s real implementation
  (`src/audit/types.rs`) emits exactly 11 top-level keys and asserted all
  11 are present; added a second `to_json()` call on the same report with
  `assert_eq!` against the first — the actual stability check the name
  always promised. Both changes strengthen existing test bodies (no new
  test count); verified logically sound and passing cleanly against the
  real, known-correct registry/report (30/30 architecture tests green,
  live registry has zero duplicate module names).
- **`[x]` SOL-ATTACK-TACTIC · Wire the dead `TACTIC_ID`/`TACTIC_NAME`
  constants into the full dossier renderer** → **T2.21**:
  `core::attack::TACTIC_ID`/`TACTIC_NAME` (`"TA0043"`/`"Reconnaissance"`)
  were declared and documented for exactly this purpose but had zero call
  sites anywhere in `src/` — `render_full` printed per-entity
  `"MITRE ATT&CK: <id>"` lines but never stated the tactic those techniques
  roll up to, the same dead-code-that-claims-to-do-something family as
  T2.13/T2.14/T2.15/T2.16. ✅ **Fixed.** `render_full`
  (`src/cli/export/renderers.rs`) now emits an `"ATT&CK     : TA0043
  (Reconnaissance) — see per-entity \"MITRE ATT&CK:\" lines below"` header,
  gated on at least one entity carrying an `attack:`-prefixed tag so the
  header never claims tactic coverage a scan's data doesn't have — the same
  false-capability-claim guard T2.13 established elsewhere. 2 new tests in
  `src/cli/export/tests.rs`, both against a real `rusqlite`-backed `Store`
  (not mocked): header present + correct text when a technique is tagged;
  header absent when nothing is tagged. Verified non-vacuous via
  `git stash`/`pop` (the new test functions don't exist against the
  unfixed code).
- **`[x]` SOL-AU087-INDEX · Index AU-087's Person ride-along instead of a
  per-domain nested scan** → **T2.22**: `rule_au_087_shared_org_email_domain`
  reintroduced the AU-034-class O(n²) correlator-pass regression — its
  "ride-along" step scanned every `Person` entity against every address in
  every qualifying org-domain cluster via `identity_overlaps` (an
  O(len×len) substring-DP call per pair), an O(domains × persons ×
  addresses) blowup that dominated ~90% of the whole pass's wall-time at
  n=2000 (17.06× scaling vs a healthy ~4× for every other rule). Caught by
  the correlation pass's own committed regression guard
  (`core::correlator::perf::pass_is_subquadratic`), which had simply never
  been run recently since `#[ignore]`d tests aren't part of the default
  `cargo test` gate. ✅ **Fixed.** `identity_overlaps(a, b)` returns true
  iff the two normalised strings share a substring of ≥
  `IDENTITY_OVERLAP_MIN` (4) chars — exactly "share a common 4-gram" once
  both sides reach that length. Built a `Person` index ONCE (a `HashMap<[u8;
  4], Vec<uid>>` of 4-grams, plus a short-name exact-match side table
  mirroring `identity_overlaps`' own short-input fallback) instead of
  re-scanning every Person per domain; each address now probes the index in
  ~O(local-part length) instead of O(persons). `IDENTITY_OVERLAP_MIN`
  re-exported from `core::scan` (was private to `classify`) so the rule
  references the same constant rather than a duplicated magic `4`.
  Byte-identical firing behaviour proven, not assumed: all 4 pre-existing
  AU-087 tests pass unchanged + 1 new test pinning the short-name
  exact-vs-substring edge case. `git stash` confirmed `pass_is_subquadratic`
  fails (ratio 11.24×) against the unfixed code and passes (ratio ~4.0×,
  3 repeat runs) against the fix; absolute cost at n=2000 also fell ~220ms
  → ~38ms. Live-verified via `hse selftest`'s real DB-round-trip correlator
  check (still fires 3 rules, unchanged).
- **`[x]` SOL-DISPATCH-HANG · Bound three independent O(n²)/unbounded hot
  paths in the engine's expansion/gap-fill/correlation tail** → **T2.23**:
  a synthetic worst-case scan (8-wide fan-out module, depth 12) hung for
  9+ minutes (killed, never completed) at `max_entities: 1000`, traced to
  three independent causes: (1) lineage attribution diffed a full
  `entity_map` snapshot per dispatch (O(entity_map.len()) per dispatch)
  instead of tracking newly-inserted UIDs at their single insertion point;
  (2) `run_gap_fill` called the fully unbounded `core::relation::
  derive_all` instead of the budget-bounded `derive_all_within` the
  finalise pass three call sites later in the same file already uses; (3)
  three correlator relation-rules (`single_route_identity_links`/AU-063,
  `multipath_corroborated_links`/AU-062,
  `rule_au_069_high_integrity_connection`) each independently ran an
  unguarded O(pairs) nested loop over every identity-entity pair — a
  THIRD instance of the T2.22/AU-034 "per-rule nested scan dominates the
  pass" bug family, confirming it as systemic across the graph-analysis
  rule family, not one-off. Measured at 401 synthetic identity entities:
  AU-062 alone 24.8s, AU-069 alone 18.9s, dominating a 45s
  `Correlator::run` finalise pass. ✅ **Fixed**, three coordinated changes:
  (1) `DispatchState` (`core/engine/dispatch.rs`) gained a `new_uids: &mut
  Vec<String>` field, populated by `finalise_module_result` at the one
  real insertion point — O(1) amortised per new entity; all three
  `entity_map`-diffing call sites in `core/engine/mod.rs` now read it
  directly, which also IMPROVES determinism (a `Vec` in emission order,
  not a `HashMap`'s iteration order filtered post hoc). (2) `run_gap_fill`
  now reuses the existing `DERIVE_BUDGET` constant, matching the
  already-established finalise-pass pattern rather than inventing a new
  one. (3) A new, deterministic (not wall-clock — correlation rules must
  stay reproducible, the same reasoning `correlate_incremental`'s own doc
  comment already gives) `MAX_IDENTITY_UIDS_FOR_PAIRWISE_SEARCH = 200`
  ceiling in `core::relation::graph` (next to `identity_uids`, whose own
  doc comment already named it "the canonical endpoint set every
  pair-wise link-analysis pass iterates"), applied to all three offending
  functions: above the ceiling, the affected search returns no findings
  from that pass rather than blocking. 3 new regression tests (one per
  fixed rule file, 201 synthetic identity entities, asserts empty), `git
  stash`-confirmed non-vacuous. **Live-verified empirically**: the same
  `bench_end_to_end_scan_scaling` baseline that hung now completes — 1000
  entities in 10.3s, 2000 in 34.3s, 4000 in 129.4s (bounded, predictable —
  versus 9+ minutes and still climbing, killed, before the fix). Adversarial
  9-agent verify workflow confirmed the fix correct with no blocking
  issues; found honest residuals logged as new T2.24 rather than silently
  dropped (see below) plus two non-blocking architectural notes (the two
  `DERIVE_BUDGET` windows are independent/additive not shared, and
  `run_gap_fill`'s bounded derivation lacks a dedicated unit test though
  its effect is proven end-to-end).
- **`[x]` SOL-BROKER-CEILING · Deterministic node-count ceiling on
  `connection_brokers`' O(V·(V+E)) articulation search** → **T2.24**:
  `connection_brokers` (`src/core/relation/graph.rs`, shared by AU-070,
  AU-071, and the dossier CLI's CONNECTION BROKERS section) had no bound
  on the total graph-node count it searches — one baseline BFS
  (`component_labels`) plus one MORE full BFS per candidate node (any node
  with ≥2 binding edges). Empirically confirmed catastrophic on a dense
  hub-and-spoke identity graph (many identities sharing a handful of hubs
  — a realistic OSINT shape T2.23's tree-shaped benchmark never
  exercised): 1.6s at 240 graph nodes, 14.4s at 480, worse than cubic. ✅
  **Fixed:** new `pub const MAX_GRAPH_NODES_FOR_BROKER_SEARCH = 300`
  (deterministic, not wall-clock — the same T2.23-established
  reproducibility reasoning), applied ONCE inside `connection_brokers`
  itself rather than duplicated at each call site, so all three consumers
  inherit the fix automatically. Above the ceiling: empty result (a
  conservative false-negative), plus a `tracing::warn!` log line. 2 new
  regression tests (`graph.rs` primitive-level, `broker.rs` AU-070
  rule-level, both above the ceiling by one node), `git stash`-confirmed
  non-vacuous. **Live-verified**: the same diagnostic that measured 14.4s
  at 480 nodes now completes in 90ms; 960 nodes in 376ms; 300 nodes (at
  the ceiling, still runs the full search) stays bounded at 3.55s. **Found
  a real, honest residual while verifying, not silently dropped:** AU-071
  calls `resolve_identity_clusters` (→ `identity_paths`) BEFORE its
  `connection_brokers` call, and that OTHER call independently took 3.48s
  on the same graph shape — T2.24's own original "AU-060/`identity_paths`
  is additive, lower urgency, unconfirmed" framing is now confirmed wrong
  on this point. Logged as new T2.25 rather than scope-crept into this
  commit (a differently-keyed primitive needing its own dedicated
  measurement, per this project's "measure before fixing" discipline) —
  AU-070 and the dossier CLI's CONNECTION BROKERS section are FULLY
  protected by this fix; AU-071 is PARTIALLY protected (its
  `connection_brokers` half only). **Independently adversarially reviewed**
  (15 agents: 3 area reviews × their own refutation passes) before
  shipping — correctness and determinism/style clean; the coverage review
  caught T2.25's first draft under-listing `identity_paths`'s real
  consumer set (missing `engine::rank_identity_aware_targets`'s live
  `scan_auto` HTTP path and one of the dossier CLI's two affected
  sections), corrected in T2.25's `PROBLEM_TREE` text before this commit.
- **`[x]` SOL-IDENTITY-PATH-CEILING · Two independent ceilings bounding
  `identity_paths`' two independent cost axes** → **T2.25**:
  `identity_paths` (`src/core/relation/graph.rs`) runs one BFS per
  identity entity, then a nested `start`/`dest` loop checking reachability
  for every identity PAIR — TWO separate unguarded cost axes (identity
  count, and total graph node count), both inherited by all SEVEN
  downstream consumers: AU-060 (direct), AU-064/the engine's cross-scan
  pathway-template learning (via `connection_templates`), AU-067/AU-071
  (via `resolve_identity_clusters`), the dossier CLI's CONNECTIONS/
  RESOLVED IDENTITIES sections, and — reachable from a live, repeatable
  HTTP endpoint, not just an on-demand CLI render —
  `engine::rank_identity_aware_targets` via `scan_auto`. Empirically
  confirmed the FIRST axis via a dedicated dense hub-and-spoke measurement
  (hub count scaled proportionally with identity count): ~1.7s at 200
  identity entities, ~4.1s at 221, ~14.9s at 400. ✅ **First fix:** reused
  the EXISTING `MAX_IDENTITY_UIDS_FOR_PAIRWISE_SEARCH` (200) rather than
  invent a third constant — its worst case at the boundary (~1.5–1.7s)
  lands in the same "low single-digit seconds" band SOL-BROKER-CEILING's
  own ceiling did. A 3-area, 21-agent adversarial review (required before
  shipping, since this touches a shared core primitive with multiple
  consumers) then caught a REAL, MAJOR gap the proportional-hub-count
  measurement had masked: the identity-count ceiling bounds only the
  O(identity_count²) pair-reconstruction term, but `identity_paths` ALSO
  runs one full BFS per identity — a SEPARATE cost in total graph node
  count, independent of identity count. Three verifiers independently
  reproduced it: 20 identities against 8,000 non-identity nodes (an
  ordinary shape — real identities enriched with breach-derived
  URLs/IPs/credentials) took ~5.6s, sailing straight through the
  200-identity ceiling. ✅ **Second fix, same cycle, not deferred:** a new
  `MAX_IDENTITY_PATHS_SEARCH_UNITS = 50_000`, bounding the PRODUCT
  `identity_count × total_graph_nodes` — the actual quantity the dominant
  BFS cost scales with — measured directly at the worst case within the
  first ceiling (200 identities, node counts 250–500 → 2.1s–13.8s) to
  size the value. Both ceilings apply together; each catches a case the
  other misses. Applied INSIDE `identity_paths` itself; verified directly
  (not just assumed) that `resolve_identity_clusters` AND
  `connection_templates` both delegate their entire cost to
  `identity_paths`, so all seven consumers inherit both fixes with no
  per-call-site duplication — the review's coverage pass also caught that
  `connection_templates`/AU-064 was itself missing from this node's
  first-draft consumer list (already protected in practice, but
  undocumented; corrected). 5 new regression tests (the primitive on each
  axis, `resolve_identity_clusters` directly, `connection_templates`
  directly, and AU-060's rule), `git stash`-confirmed non-vacuous against
  both guards removed together. **Live-verified** on both axes:
  identity-count — 201 entities (one past that ceiling) fell from an
  extrapolated ~4s+ to ~120µs, 200 (at the ceiling) stays ~1.45s;
  search-unit — the reviewers' exact 20-identity/8,000-node case fell
  from ~5.6s to ~483µs, 20 identities against 2,000 nodes (under the
  ceiling) still runs in ~1.1s. `hse selftest`'s correlator check
  unchanged (3 rules fire).
- **`[x]` SOL-AHPRA-TRUNCATION · Surface the true row count above `ahpra`'s
  20-result emit cap** → **T2.26**: `Registers-of-Practitioners.aspx` has
  no page-size/limit query param, so the response already holds every
  matching row; `process()` did `practitioners.iter().take(20)` with no
  record of the true count anywhere. AHPRA is the national register for
  ALL registered health practitioners in Australia — a common-surname
  search (routine, non-adversarial) can easily exceed 20 matches, so an
  operator got a silently-incomplete result indistinguishable from a
  complete one. Found by a 6-angle multi-agent discovery pass (run after
  confirming T2.7/C1/C6/C7 were still genuinely blocked/gated), verified
  real by 3 independent adversarial refuters before being actioned. ✅
  **Fixed:** extracted a pure `build_practitioner_entities` (mirroring
  `opencorporates`'s established `build_company_entities`/
  `build_officer_entities` split) that captures the true row count BEFORE
  the `.take(20)` cap and attaches it as `total_matches` on every emitted
  entity's evidence — the SAME established pattern `opencorporates`,
  `gleif_lei`, `acnc_charities`, `au_unclaimed`, and `api_key_probe`
  already use, not a bespoke mechanism. 2 new regression tests (above the
  cap: `total_matches` is the true count, not 20; under the cap: reports
  its own count), `git stash`-confirmed non-vacuous. Gate green: 4308 lib
  tests (4306→4308, +2), fmt/clippy/strict-rustdoc clean, full
  `cargo test` green, `hse selftest` 9/9. **The same discovery pass found
  three structurally-identical instances** (`acma_rrl`, `crtsh`,
  `bgpview`) and two unrelated bug families (dead/unwired diagnostic
  accessors; test-name-overclaim) — logged as new T2.27–T2.31 rather than
  fixed in this same commit, keeping the unit of work to one module.
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
  ✅ **Test coverage closed (2026-07-01).** `commits_behind`/`changelog_lines`
  now have real fixture-driven tests (`cli/update.rs`): a `tempfile` upstream
  repo + a real `git clone`, with signing/identity config set per-repo so the
  test is hermetic regardless of the host's global git config (this
  environment has `commit.gpgsign=true` set globally, which would otherwise
  fail every test commit). 3 new tests drive the actual `git` binary — no
  mocked subprocess output: new commits pushed upstream are correctly
  counted and listed newest-first; an up-to-date clone reports 0/empty; a
  non-repo directory reports `None`/empty. No `Remaining` left on this node.
  **(cycle 22; test-coverage closed same session as the doc corrections)**

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
| SOL-LEDGER-ZERO-YIELD | T2.15 | `[x]` |
| SOL-CONSUMES-DELEGATE | T2.16 | `[x]` |
| SOL-CRAWL-CONCURRENCY | T2.17 | `[x]` |
| SOL-VICTIM-TRUNCATION | T2.18 | `[x]` |
| SOL-CHAIN-TXCOUNT | T2.19 | `[x]` |
| SOL-TEST-NAME-OVERCLAIM | T2.20 | `[x]` |
| SOL-ATTACK-TACTIC | T2.21 | `[x]` |
| SOL-AU087-INDEX | T2.22 | `[x]` |
| SOL-DISPATCH-HANG | T2.23 | `[x]` |
| SOL-BROKER-CEILING | T2.24 | `[x]` |
| SOL-IDENTITY-PATH-CEILING | T2.25 | `[x]` |
| SOL-AHPRA-TRUNCATION | T2.26 | `[x]` |
| SOL-RULE-METAGUARD | T1.3 (dispatch firing coverage) | `[x]` |
| SOL-STREAMING | C8 | `[x]` |
| SOL-AU-MOAT | C3 | `[~]` |
| SOL-NETINT | C4 | `[~]` |
| SOL-CACHE-INTERSCAN | C9 | `[x]` |
| SOL-CORR | C1 | `[~]` |
| SOL-PERF-PUBLISH | C2 | `[~]` |
| SOL-GEOINT | C5 | `[~]` |
| SOL-OFFENSIVE | C6 | `[~]` |
| SOL-FORENSIC | C7 | `[ ]` |
| SOL-HEALTH-SIGNAL | T2.7 (per-source health) | `[ ]` |
| SOL-UPDATE | UX self-upgrade + CLI consolidation | `[x]` |

---

## 4. Gap analysis — the live diff between the trees (refreshed every pass)

> This section *is* the alternation made concrete. **4a** = problems with no started
> solution (P→S gaps, the build queue). **4b** = solutions begun but unfinished (the
> finish queue). **4c** = solutions with no problem (over-build — prune candidates).
> When 4a + 4b are empty, the two trees agree.

### 4a · Problems with NO solution yet started (P→S coverage gaps)
- **T2.26** — **delivered** ✅ (2026-07-01, `ahpra` `total_matches` signal —
  see `PROBLEM_TREE`). Off the open queue.
- **T2.27** (new, 2026-07-01) — `acma_rrl` has the same unsignalled
  20-result truncation T2.26 just fixed for `ahpra`. No solution node yet;
  fix is the same established `total_matches` pattern, just not yet
  applied to this module.
- **T2.28** (new, 2026-07-01) — `crtsh` truncates to 200 entities with no
  total-count signal. No solution node yet.
- **T2.29** (new, 2026-07-01) — `bgpview` caps IPv4 prefixes at 20 with no
  total-count signal, and never deserializes `ipv6_prefixes` at all (a
  second, distinct gap). No solution node yet.
- **T2.30** (new, 2026-07-01) — three diagnostic/catalogue accessors
  (`see_know::is_key_invalid`, `core::profiles::list_profiles`,
  `core::path::shortest_path`) are documented as feeding a specific
  consumer that never actually calls them — the T2.13/14/15/16/21 "dead
  code that claims to do something" family. No solution node yet.
- **T2.31** (new, 2026-07-01) — four tests (`src/util/oui/tests.rs`,
  `src/modules/xposed_or_not/tests.rs`, `src/util/key_pool/tests.rs`,
  `src/modules/api_key_probe/tests.rs`) whose names promise more coverage
  than their bodies verify — the T2.20 family, found in modules not
  previously audited for it. No solution node yet.
- **T2.25** — **delivered** ✅ (SOL-IDENTITY-PATH-CEILING, 2026-07-01). Off
  the open queue.
- **T2.7** scraper-health signal — **partially covered (cycle 20):** SOL-HEALTH-SIGNAL
  node now sketched (`last_success_at` + `consecutive_failures` tracking, `hse doctor`
  surface + SPA panel); full implementation still open. **Elevated (cycle 17):**
  ahpra/acma_rrl/trove_au/`austlii` widen the scraper surface; priority remains raised.
- **§7 S4** — **delivered** ✅ (SOL-REDACT extended, 2026-07-01 — the
  correctly-scoped fix, not the originally-sketched one; see SOL-REDACT
  above). Off the open queue.
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
- **C1** — `[~]` (SOL-CORR, cycle 26: `identity_paths` + CONNECTIONS dossier
  section delivered; timeline engine already shipped too, per the
  2026-07-01 correction above — remaining is rule-gap fill + the
  reused-secrets controller facet). **C6** — `[~]` (SOL-OFFENSIVE,
  2026-07-01 correction: aho-corasick key-harvest + entropy gate already
  shipped; remaining is SERP-dork breadth + the credential-reuse graph).
  **C7** — still genuinely `[ ]`, gated on the §3.F enablers landing
  first, by design.
- **C2** — `[~]` (SOL-PERF-PUBLISH). **Delivered (2026-07-01):** the concrete
  scoped increment identified while resolving T2.17 — genuinely
  parallelising `web_crawler`'s BFS crawl loop (`crawl_util::fetch_batch`,
  mirroring `probe_config_leaks`'s `Semaphore`/`JoinSet` pattern) — is done,
  with a live-measured ~3.2× wall-clock speedup and identical output.
  *Remaining:* the published "N selectors, T seconds, M MB RAM" reproducible
  benchmark itself, still gated on the §3.F enablers (SOL-F3 benches,
  SOL-F2 flat-RAM) landing first.
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
- **cell_local auto-sync (cycle 21 S→P gap) — partially covered (2026-07-01):**
  `hse cells import` requires a manual trigger and a BYO OpenCelliD key; no
  auto-scheduled re-sync exists. Investigated feasibility before building:
  genuine unattended re-sync (a cron/daemon path) needs either new daemon
  infrastructure `hse` doesn't have (every subcommand is one-shot; `hse
  serve` is the only long-lived process and is foreground/opt-in) or an
  OS-level cron example (a docs deliverable, not a code fix) — architecturally
  analogous to T2.7's blocked status, not attempted this cycle. Delivered the
  honest increment available without either: `hse cells status` now warns
  when the local snapshot exceeds 90 days old (SOL-GEOINT, folded into the
  existing node above). *Remaining:* the cron/daemon path itself.
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
  reconciled into this note. **Residual closed (2026-07-01):** see
  SOL-UPDATE above — `commits_behind`/`changelog_lines` now have real
  fixture-driven tests. Off the open queue.

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
- **SOL-HINT-NOISE** — ✅ fully closed (`[x]`, 2026-07-01). Scan-level leg:
  `scan_ran_long_with_a_zero_yield_module` event-sourced reinstatement in
  `cli/scan/dossier.rs`. Per-module leg: resolved as superseded by
  SOL-LEDGER-ZERO-YIELD (the properly-throttled `recommended_skips` now
  actually works) rather than rebuilt as a noisier, weaker per-scan hint.
  Removed from finish queue.
- **SOL-LEDGER-ZERO-YIELD** — ✅ fully closed (`[x]`, 2026-07-01). Removed
  from finish queue.

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
  **T2.13/T2.14/T2.15/T2.16/T2.17/T2.18/T2.19/T2.20/T2.21/T2.22/T2.23/T2.24/
  T2.25 `[x]`** ✅ (SOL-ROI-HINT, SOL-HINT-NOISE, SOL-LEDGER-ZERO-YIELD,
  SOL-CONSUMES-DELEGATE, SOL-CRAWL-CONCURRENCY, SOL-VICTIM-TRUNCATION,
  SOL-CHAIN-TXCOUNT, SOL-TEST-NAME-OVERCLAIM, SOL-ATTACK-TACTIC,
  SOL-AU087-INDEX, SOL-DISPATCH-HANG, SOL-BROKER-CEILING,
  SOL-IDENTITY-PATH-CEILING — the dead-hint/dead-ledger/dead-delegation/
  false-doc/silent-truncation/unguarded-arithmetic/overclaimed-test-coverage/
  dead-constant/reintroduced-O(n²)-or-worse-unguarded-graph-search bug
  family, all closed — with T2.25 closing the LAST open thread in this
  family (and, in the process, its own OWN two-axis gap — found by
  adversarial review before shipping, fixed the same cycle), seven
  consumer surfaces across two primitives now covered by two shared,
  reused ceilings — three ceilings total: pairwise-count, graph-node-
  count, and node-times-identity-count); **T2.26 `[x]`** ✅ (2026-07-01,
  `ahpra`'s `total_matches` truncation signal — a discovery-pass find,
  fixed same-day); **T2.27/T2.28/T2.29 `[ ]`** (new, 2026-07-01 —
  `acma_rrl`/`crtsh`/`bgpview` share T2.26's silent-truncation shape,
  correctly deferred to keep the unit of work small); **T2.30/T2.31 `[ ]`**
  (new, 2026-07-01 — dead/unwired diagnostic accessors and test-name-
  overclaim instances, the established T2.13-16/21 and T2.20 families
  respectively, found in previously-unaudited modules); T2.7 open
  (blocked for an unattended cycle); **T2.11 `[x]`**
  ✅ (2026-07-01, status-marker reconciliation — oathnet +
  found_keys/SOL-ISOLATE + LOW over-dispatch/SOL-LIVE-DISPATCH-BUDGET all
  closed; the one residual, the `QuotaBudget` per-scan `reset_scan()`-zeroing
  across concurrent scans, is SOL-BUDGET's already-accepted `[-]` note — the
  per-*session* ceiling still bounds total spend, no further action
  planned).
- **S.CORE sensor gate:** **SOL-SENSOR-GATE `[x]`** ✅ (cycle 24) — all six
  live-sensor modules now consistently gate on `Coordinates | MacAddress` and
  appear in `LOCAL_PASSIVE_MODULES`; non-geo scans receive zero phone-sensor
  data.
- **§7 (security):** XSS + S2 + S3 solved; S1 accepted; **S5 `[x]`** ✅
  (SOL-INSTALL-INTEGRITY, cycle 16); **S4 `[x]`** ✅ (SOL-REDACT extended,
  2026-07-01 — `redact_own_keys` masks the operator's own echoed key in the
  dossier's exportable RAW SOURCE RECORDS copy; `raw_archive`'s own
  never-redact policy stays untouched). §7 fully closed.
- **§4 (capability C1–C9):** C8 delivered ✅ (`streaming_probe`, 42-site webcam/fan/adult prober); **C9 delivered** ✅ (SOL-CACHE-INTERSCAN, cycle 18, `raw_archive` + dispatch cache gate); **C5 `[~]`** (SOL-GEOINT: `opencellid` cycle 19 + `cell_local`/`hse cells import` cycle 21 + cell-DB staleness warning 2026-07-01 delivered, Weiszfeld/centroid fusion + genuine unattended cron/daemon re-sync remaining); **C3 `[~]`** (SOL-AU-MOAT: hlr_cnam/ahpra/acma_rrl/trove_au/smtp_vrfy/`austlii`/`au_property` shipped, courts/AustLII + state cadastre closed; GNAF/ASIC/broader-cadastre remaining); **C4 `[~]`** (SOL-NETINT: netlas + censys + securitytrails + bgpview + ripestat all shipped; passive-DNS history + CDN cert-hash origin remaining); **C2 `[~]`** (SOL-PERF-PUBLISH: `web_crawler` BFS crawl loop now fetches same-round batches concurrently, ~3.2× measured speedup, 2026-07-01; the published benchmark itself remains gated on §3.F); **C1 `[~]`** (SOL-CORR: `identity_paths`/CONNECTIONS + the timeline engine both already shipped, per the 2026-07-01 correction; rule-gap fill + reused-secrets facet remaining); **C6 `[~]`** (SOL-OFFENSIVE, 2026-07-01 correction: aho-corasick key-harvest + entropy gate already shipped; SERP-dork breadth + credential-reuse graph remaining); C7 still `[ ]`, gated on §3.F by design. **SOL-UPDATE `[x]`** (cycle 22, `hse update`/upgrade + CLI consolidation 19→13 visible commands).

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

- **2026-07-01** — **SOL-HINT-NOISE's scan-level leg delivered `[ ]`→`[~]`,
  closing T2.14's "straightforward" half.** **P→S step:** T2.14 had a fix
  already sketched (event-source the 60s hint the same way SOL-ROI-HINT
  read `ModuleDone` events instead of `modules_by_yield`) — picked as this
  cycle's unit of work per §5's execution order (T2 robustness, no
  higher-priority open/in-progress node had a small, safe increment
  ready: T2.7 stays blocked on real fixture sourcing, T2.11's sole
  remainder is the already-accepted `[-]` SOL-BUDGET note, §3.F's `bstr`
  leg has no natural consumer yet). Implemented
  `scan_ran_long_with_a_zero_yield_module(wall_time_ms, events)` in
  `cli/scan/dossier.rs`, called from `print_diagnostics` right after the
  ROI-hint's own event fetch, appending the restored wording to
  `diag.optimization_hints` post-`analyse()`-call (exactly the caller-side
  append option (b) T2.14 specified). **S→P step:** 4 new unit tests prove
  the boundary is a strict `>` (60_000ms does not fire, 61_000ms does) and
  that a module which found something never triggers it, mirroring
  `zero_yield_keyed_or_paid_modules`'s existing test shape. **Gap refresh:**
  §4a loses its T2.14 entry (no longer "not yet started"); §4b gains the
  SOL-HINT-NOISE row with its remaining per-module leg; leverage-map row
  `[ ]`→`[~]`. The per-module "returned 0 entities" hint stays open — its
  noise-control decision (cap-to-worst-N / cost-gate like SOL-ROI-HINT /
  bounded-summary-count) is a real design choice, not a mechanical
  reinstatement, and forcing one under this increment would repeat the
  exact "force-fit under time pressure" mistake T2.14 was opened to avoid.
  Paired: `PROBLEM_TREE` T2.14 + §8 updated in the same commit. Gate green
  (fmt/clippy `--all-targets`/doc clean, 4267 lib tests, full `cargo test`
  green).

- **2026-07-01** — **SOL-HINT-NOISE's per-module leg resolved by fixing a
  bigger bug it would have duplicated; new SOL-LEDGER-ZERO-YIELD closes
  T2.15.** **P→S step:** picked T2.14's remaining node (an in-progress `[~]`
  node from the prior cycle, priority-1 per §5's own instructions) to make
  the per-module noise decision the addendum deferred. Investigating it —
  "does a properly-throttled version of this signal already exist?" — found
  `AdaptiveRouting::recommended_skips` (`zero_yield_rate ≥ 0.80` over `≥5`
  scans), which is exactly the statistically-sound version of what the
  per-module hint wanted. Reading its data path found it was **itself**
  dead: `ledger::persist_ledger` only ever received `modules_by_yield`
  (built exclusively from emitted entities, per T2.13/T2.14's own finding),
  so `zero_yield_scans` could never increment for ANY module — a fourth
  instance of the identical unreachable-premise bug family, this one
  corrupting the persistent cross-scan ledger rather than a single hint.
  **Verified live before fixing**, not just by static reading: the real
  `$HOME/.huntsman/module_stats.json` (20 historical scans, 11 real modules)
  showed `zero_yield_rate: 0.0` on every single real module — only a
  hand-crafted `synthetic` test entry had ever recorded a nonzero rate.
  **Fix:** split `persist_ledger`'s mutation into a pure, unit-testable
  `update_ledger(ledger, modules, zero_yield_modules, kinds)`; new pure
  `analyse::zero_yield_module_names(events, modules_by_yield)` computes the
  zero-yield diff from the scan's own `ModuleDone` events (the T2.13/T2.14
  event-sourced pattern, applied a third time). Moved the `persist_ledger`
  call **out of** `analyse()` — a pure function with no `StoragePort`
  access — to the 3 real call sites; this also fixes a latent hermeticity
  bug for free, since the old unconditional call meant every one of
  `analyse()`'s 13 unit tests silently mutated the real on-disk ledger on
  every `cargo test` run. **S→P step:** 9 new unit tests (4 on
  `update_ledger`, including a module that fails 5 scans straight reaching
  `zero_yield_rate: 1.0`, the exact `recommended_skips` threshold input; 5
  on `zero_yield_module_names`'s diff logic). **Verified live again after
  fixing:** `hse scan -k domain -v wikipedia.org --free-only --passive-only`
  correctly recorded the dispatched, zero-yield `geo_domain_classifier` in
  the ledger (`zero_yield_scans: 1, zero_yield_rate: 1.0`) while it stayed
  correctly absent from the same scan's `modules_by_yield` JSON output —
  proving both halves of the fix at once. Ledger restored to its
  pre-verification state afterward (a courtesy, not required). **Gap
  refresh:** SOL-HINT-NOISE `[~]`→`[x]` (both legs now closed — the
  per-module leg resolved as superseded, not rebuilt); new
  SOL-LEDGER-ZERO-YIELD `[x]`; §4b loses both rows; leverage-map gains the
  new row; §4d's T2 row lists T2.13/T2.14/T2.15 together. Paired:
  `PROBLEM_TREE` T2.14 addendum + new T2.15 + §8 updated in the same
  commit. Gate green (fmt/clippy `--all-targets`/doc clean, 4276 lib tests,
  full `cargo test` green — 4267→4276, +9).

- **2026-07-01** — **Closed SOL-UPDATE's last real residual: `commits_behind`/
  `changelog_lines` had zero test coverage of the actual `git` subprocess
  calls.** **P→S step:** with T2.7 still blocked for an unattended cycle
  (needs a live third-party fetch or a fixture that would only look real)
  and no other in-progress node open, picked the concrete, well-scoped
  follow-on §4a had flagged twice already (the cycle-22 and 2026-07-01 doc
  corrections both named it explicitly as the correct-sized next step,
  rather than re-litigating either correction). Added `cli/update.rs` test
  helpers (`init_repo`, `commit`, `clone`) that drive a REAL `git` binary
  against `tempfile` temp directories — a genuine upstream repo plus a real
  `git clone`, not a mocked subprocess. Had to set `commit.gpgsign=false`
  per test repo: this environment's global git config has
  `commit.gpgsign=true`, which would otherwise fail every test commit — a
  real hermeticity trap a naive fixture would have hit. **S→P step:** 3 new
  tests prove real behaviour, not assumed behaviour: new commits pushed
  upstream after a clone are correctly counted (`Some(2)`) and listed
  newest-first by `changelog_lines`; an up-to-date clone reports `Some(0)`/
  empty; a plain (non-git) directory reports `None`/empty. **Gap refresh:**
  §4a's `hse update --check changelog` entry loses its residual (fully off
  the open queue); SOL-UPDATE's `Remaining` bullet removed. Paired:
  `PROBLEM_TREE` §8 — same commit (no dedicated PROBLEM_TREE node exists for
  SOL-UPDATE; it lives only in the maintained log, per cycle-22 precedent).
  Gate green (fmt/clippy `--all-targets`/doc clean, 4279 lib tests
  (4276→4279, +3), full `cargo test` green).

- **2026-07-01** — **New: SOL-CONSUMES-DELEGATE closes T2.16 (a dead
  function behind a false doc comment); new SOL-CRAWL-CONCURRENCY logs
  T2.17 (found, not fixed).** **P→S step:** with every in-progress node
  either closed or genuinely blocked (T2.7's golden-fixture work; T2.11's
  accepted residual; F.1-3's remaining legs each lack a natural trigger),
  ran a fresh code-grounded discovery pass per step 1's fallback — a
  multi-angle fan-out (dead-code hunting, doc-comment-vs-implementation
  audits across core/util/modules, `.take(N)` truncation review,
  `to_lowercase()`+offset re-audit for more instances of the T0.1/T0.2 bug
  class) rather than a single linear read, since the codebase is large
  enough that one search angle misses real findings the others catch.
  **Found two real issues**, picked the smaller for this cycle:
  `core/dependency/mod.rs::consumes_via_probe`'s doc comment claimed it was
  "the default body for `Module::consumes()`," but `core/module/mod.rs`'s
  actual trait default independently re-implemented the identical filter
  inline, never calling it — confirmed by grep: the function's only callers
  outside its own definition were its two unit tests. Two live copies of
  dispatch-critical logic (feeds the per-scan dispatch index and the
  richness factor every recursive expansion round reads) is exactly the
  single-sourced-vocabularies violation `docs/CONVENTIONS.md` §3 exists to
  prevent. **S→P step:** widened `consumes_via_probe` to
  `<M: Module + ?Sized>(m: &M)` (from `&dyn Module`) so `consumes()`'s
  default body can call it as `self` without needing a `Self: Sized` bound
  that would remove the method from `dyn Module`'s vtable and break every
  `&dyn Module`/`Arc<dyn Module>` call site (verified this the hard way —
  the naive `&dyn Module` version failed to compile with exactly that
  error). New regression test
  `module_consumes_default_delegates_to_consumes_via_probe` pins the
  invariant so a future edit can't quietly reintroduce the duplicate.
  The second finding — `web_crawler`'s doc claims "4 concurrent requests"
  but the BFS crawl loop is plain sequential — was deliberately NOT fixed
  this cycle: correcting the doc is trivial, but building the real
  concurrency needs deliberate care to keep page-visit order deterministic
  under concurrent completion timing (§1.7), a bigger, riskier change than
  this cycle's one-focused-commit scope allows. Logged as new open T2.17 /
  SOL-CRAWL-CONCURRENCY with both solution options spelled out, rather than
  either force-fixing it under time pressure or silently dropping it.
  **Gap refresh:** §4a gains T2.17; leverage-map gains both new rows; §4d's
  T2 row lists T2.16 among the closed dead-code/false-doc-comment family and
  T2.17 alongside T2.7 as open. Paired: `PROBLEM_TREE` new T2.16/T2.17 + §8
  — same commit. Gate green (fmt/clippy `--all-targets`/doc clean, 4280 lib
  tests (4279→4280, +1), full `cargo test` green).

- **2026-07-01** — **SOL-CRAWL-CONCURRENCY delivered `[ ]`→`[x]`, closing
  T2.17 — the doc-fix half of last cycle's deferred design decision.**
  **P→S step:** with T2.7 still blocked, T2.11 down to its accepted-`[-]`
  residual, and F.1-3's remaining legs each lacking a natural trigger, T2.17
  (the only genuinely open node) was picked, and this cycle made the design
  call its own text had left open: fix the doc now, track the bigger build
  separately rather than force either extreme (building unreviewed
  concurrency under time pressure, or leaving a known-false doc claim
  sitting unfixed indefinitely). Corrected `web_crawler`'s module doc (crawl
  bullet + "Termux-friendly" bullet) to state the BFS crawl is sequential
  (one request in flight), explicitly contrasting it with the genuinely
  16-way-concurrent `probe_config_leaks` in the same file. **S→P step:**
  folded the deferred "build real concurrency" option into **C2**'s
  solution text as a concrete, scoped, not-yet-started increment — naming
  the exact pattern to mirror (`probe_config_leaks`'s `Semaphore`/`JoinSet`)
  and the exact hazard a future implementer must design around (keeping
  page-visit order, and therefore which pages land inside the 60-page cap,
  deterministic under concurrent completion timing, §1.7) — rather than
  letting the idea evaporate once the node closed. Doc-only; no code
  behaviour change, so no new test — the same category as this session's
  other pure doc-audit corrections. **Gap refresh:** §4a loses its T2.17
  entry; leverage-map row `[ ]`→`[x]`; §4d's T2 row folds T2.17 into the
  closed dead-code/false-doc family; C1/C2/C6/C7's bundled §4a note gains
  C2's concrete increment. Paired: `PROBLEM_TREE` T2.17 `[ ]`→`[x]` + C2
  solution text + §8 — same commit. Gate green (fmt/clippy
  `--all-targets`/doc clean, 4280 lib tests — unchanged, no code change —
  full `cargo test` green).

- **2026-07-01** — **New: SOL-VICTIM-TRUNCATION closes T2.18 — OathNet-JSON
  stealer-victim import caps silently dropped data with zero record
  anywhere, via a workflow that adversarially re-verified 3 prior-cycle
  discovery candidates instead of trusting the original single-agent
  report.** **P→S step:** last cycle's fresh-discovery fan-out surfaced
  three `.take(N)` truncation candidates but only one (T2.16) got fixed;
  the other three (`push_macs`/`push_ibans`/`push_ssids`,
  `import_json_caps`, `zoomeye`) sat unverified and un-acted-on. Rather
  than re-running discovery from scratch (redundant with last cycle's
  already-thorough sweep) or picking blind, ran a Workflow: 3 independent
  lenses (accuracy, real-world impact, fix scope) per candidate, then a
  synthesis agent picked the strongest. **S→P step:** the synthesis was
  decisive — `import_json_caps` (`cli/import/json.rs`) was the only
  candidate where BOTH the accuracy and impact lenses independently agreed
  it was a genuine, reachable bug; the other two had internally
  contradicting lenses (accuracy said real, impact said not-actually-
  reachable-in-practice for each), which the synthesis correctly weighed as
  lower confidence rather than picking by coin-flip. Implemented exactly
  the fix the scope lens sketched: `note_if_truncated` helper, a new
  `ImportStats::victim_fields_truncated` counter, surfaced in both the
  human summary and the JSON envelope, cap values untouched. 2 new
  `#[tokio::test]`s. **Verified live twice**, not just by inspection: a
  real `hse import <fixture> --output json` run against a synthetic victim
  record with 25 device_emails + 8 hwids printed the WARNING line and
  `"victim_fields_truncated": 2` while entities stayed capped at 20/5; a
  second, under-cap fixture produced no warning at all — proving both the
  positive and negative case. Kept the two rejected candidates' verified
  reasoning in `PROBLEM_TREE` T2.18's own text rather than silently
  dropping them, so a future cycle doesn't re-litigate them without new
  evidence. **Gap refresh:** leverage-map gains the new row; §4d's T2 row
  folds T2.18 into the closed bug family. Paired: `PROBLEM_TREE` new T2.18
  + §8 — same commit. Gate green (fmt/clippy `--all-targets`/doc clean,
  4282 lib tests (4280→4282, +2), full `cargo test` green).

- **2026-07-01** — **New: SOL-CHAIN-TXCOUNT closes T2.19 (untrusted
  Esplora tx-count sum could panic or silently wrap); new
  SOL-TEST-NAME-OVERCLAIM logs T2.20 (2 misleadingly-named tests, found not
  fixed).** **P→S step:** with ultracode off, ran a single-Agent (not
  multi-agent Workflow) fresh discovery pass explicitly steered away from
  every angle already swept this session (doc-comment-vs-code,
  `.take(N)` truncation, `to_lowercase()`-offset, dead-code/duplicate-
  delegation) — instead: TODO/FIXME markers, `#[allow]` masking, unguarded
  `unwrap`/`expect` in `cli`/`api`, sort-comparator NaN panics, unchecked
  arithmetic on untrusted input (the T0.3 class), and test-name overclaims.
  The agent's own sub-fan-out (unprompted, its own tool choice) surfaced
  two candidates independently and consistently: `chain_intel`'s
  `tx_count` sum, and two test names promising "stable"/"complete"
  coverage their bodies don't deliver. **S→P step:** picked the tx-count
  bug as this cycle's unit — a genuine correctness/evidentiary-integrity
  gap (a wrong on-chain finding presented as fact in release builds),
  higher-severity than a test-coverage-quality gap, and matching the
  established, previously-fixed T0.3 "trust no input number" pattern
  exactly (the sibling `funded_txo_sum`/`spent_txo_sum` fields two lines
  above already apply it). Fixed via a pure, directly-testable
  `combined_tx_count` helper (mirroring `chain_intel`'s own established
  pure-helper convention) rather than patching the arithmetic inline, so
  the regression test needs no HTTP mocking. Confirmed non-vacuous by
  `git stash`-ing the fix and re-running the test suite: the new test
  doesn't exist against the unfixed code. The test-name finding was
  smaller and lower-severity (test-quality, not a runtime bug) — logged as
  new T2.20 with a concrete fix sketch for each test rather than
  force-fixing two unrelated things in one commit, or silently dropping a
  real, well-corroborated finding (independently reached by the agent's
  own separate sub-searches). **Gap refresh:** §4a gains T2.20;
  leverage-map gains both new rows; §4d's T2 row lists T2.19 among the
  closed bug family and T2.20 alongside T2.7 as open. Paired:
  `PROBLEM_TREE` new T2.19/T2.20 + §8 — same commit. Gate green (fmt/clippy
  `--all-targets`/doc clean, 4284 lib tests (4282→4284, +2), full `cargo
  test` green).

- **2026-07-01** — **SOL-TEST-NAME-OVERCLAIM delivered `[ ]`→`[x]`,
  closing T2.20 — the smaller, deliberately-deferred finding from last
  cycle's discovery pass.** **P→S step:** T2.20 was the only genuinely
  open node (T2.7 still blocked; T2.11 down to its accepted `[-]`
  residual; F.1-3's remaining legs each lacking a natural trigger; the CAP
  nodes' remaining items are each a real new-capability build, too large
  for one unattended cycle) — picked exactly as flagged. **S→P step:**
  rather than mechanically applying either originally-sketched option,
  chose a third, stronger one for the module-registry test: added a
  duplicate-name check (`HashSet`) alongside the existing floor, which
  directly catches the "bad merge silently duplicates modules" scenario
  the name promises to guard against, without introducing the FIRST
  hand-maintained exact-count pin in this codebase (a fragility this
  codebase's own `modules_md_lists_every_registered_module` deliberately
  avoids via a content-membership check instead) — judged more consistent
  with established convention than either sketch. For the audit-JSON test,
  read `to_json()`'s real implementation directly rather than trusting the
  prior cycle's "~9-10 keys" estimate — confirmed exactly 11 top-level
  keys — and added both a completeness check (all 11 present) and a
  genuine stability check (two calls on the same report, `assert_eq!`).
  Both fixes strengthen existing test bodies (no new test count added);
  the standard "fails against unfixed code" proof doesn't map cleanly here
  since the underlying `registry()`/`to_json()` were never broken, only
  under-tested — verified instead that the strengthened assertions are
  logically sound and pass cleanly against the real, known-correct
  registry/report (30/30 architecture tests green; the live registry has
  zero duplicate module names). **Gap refresh:** §4a loses its T2.20
  entry (now empty of open P→S gaps in the T-series); leverage-map row
  `[ ]`→`[x]`; §4d's T2 row folds T2.20 into the closed bug family — T2.7
  is now the ONLY open T-series node, and it remains genuinely blocked for
  an unattended cycle. Paired: `PROBLEM_TREE` T2.20 `[ ]`→`[x]` + §4a/§4d/§5
  — same commit. Gate green (fmt/clippy `--all-targets`/doc clean, 4284
  lib tests — unchanged, no new tests, existing bodies strengthened — full
  `cargo test` green, 30/30 architecture tests).

- **2026-07-01** — **New: SOL-ATTACK-TACTIC delivered `[x]`, closing
  T2.21 — a dead-constant finding from a fresh discovery pass steered away
  from every bug angle already swept this arc.** **P→S step:** T2.7
  remained the sole open T-series node and still genuinely blocked (no
  live third-party fetch available unattended), so ran discovery along two
  new angles this cycle explicitly hadn't tried yet: live scan inspection
  and unwired/dead constants. The dead-constant angle paid off:
  `core::attack::TACTIC_ID`/`TACTIC_NAME` were declared with purpose-stating
  doc comments (`/// Human name of [TACTIC_ID]`) but `grep -rn
  "TACTIC_ID\|TACTIC_NAME" src` showed zero call sites — the same
  dead-code-that-claims-to-do-something family as T2.13/T2.14/T2.15/T2.16.
  **S→P step:** the natural consumer already existed — `render_full`
  printed per-entity `"MITRE ATT&CK: <id>"` lines but never stated the
  overarching tactic. Wired both constants into a new header line, gated on
  at least one entity carrying an `attack:`-prefixed tag so the header
  never claims tactic coverage a scan's data doesn't have (the same
  false-capability-claim guard T2.13 established — printing it
  unconditionally would have been a new instance of the exact bug class
  this fix's own sibling nodes exist to eliminate). 2 new regression tests
  in `src/cli/export/tests.rs`, both against a real `rusqlite`-backed
  `Store` (not mocked) — the actual `hse export --format full`/`debug` call
  path. Confirmed non-vacuous via `git stash`/`pop` (the new test functions
  don't exist against the unfixed code). **Gap refresh:** leverage-map
  gains the new row (`[x]` from creation — found-and-fixed same cycle, no
  §4a entry needed); §4d's T2 row folds T2.21 into the closed dead-code bug
  family. T2.7 remains the sole open T-series node. Paired: `PROBLEM_TREE`
  new T2.21 `[x]` + §8 — same commit. Gate green: fmt/clippy
  `--all-targets --locked -D warnings`/strict-rustdoc clean, 4286 lib tests
  (4284→4286, +2) and 63 doctests, full `cargo test` green.

- **2026-07-01** — **T2.11 `[~]`→`[x]` — status-marker reconciliation, no
  code change.** **P→S step:** T2.11 was the sole remaining in-progress
  (`[~]`) node in either tree, so priority-1 of the cycle protocol picked it
  over starting new discovery. On inspection, all three of its sub-items
  were already closed (SOL-BUDGET's oathnet CAS fix, SOL-ISOLATE's
  `scan_id`-keyed found_keys sink, SOL-LIVE-DISPATCH-BUDGET's live
  `max_entities` re-check) and the fourth — the `QuotaBudget` per-scan
  `reset_scan()`-zeroing across concurrent scans — was already re-examined
  and accepted `[-]` in cycle 18 (this same file's SOL-BUDGET node), with
  the reasoning that the per-*session* ceiling (never touched by
  `reset_scan()`, checked atomically in `try_increment()`'s CAS) bounds
  total spend regardless of scan-level contamination. `PROBLEM_TREE`'s
  T2.11 entry, though, still carried its original `[~]` marker and a
  closing "Root cause" paragraph describing per-`scan_id` keying as
  outstanding work — stale relative to the conclusion this file already
  reached and shipped two cycles ago. **S→P step:** re-verified the cycle-18
  claim against the CURRENT source rather than trusting the old note
  verbatim — `run_with_ledger_inner` (`core/engine/mod.rs:306`) still calls
  `reset_per_scan(&scan.id)` unconditionally on every scan start, reached
  by the `hse serve` concurrent path via `engine.run`
  (`api/handlers/mod.rs:133`); `session_count` is still never touched by
  `reset_scan()` (`util/budget/mod.rs:216-220`). The claim holds. Rewrote
  `PROBLEM_TREE` T2.11's closing paragraph to state the resolution plainly
  and flipped its marker to `[x]`; no `SOLUTION_TREE` node needed changing
  (SOL-BUDGET/-ISOLATE/-LIVE-DISPATCH-BUDGET were already correctly `[-]`/
  `[x]`/`[x]`) beyond the §4d coverage-snapshot line. **Gap refresh:** §4d's
  T2 row now states T2.11 `[x]` instead of "mostly done." No leverage-map
  change (all three rows already correctly reflected their own status; only
  the *parent* node's rollup was stale). Paired: `PROBLEM_TREE` T2.11
  `[~]`→`[x]` + §8 — same commit. Doc-only; no code or test changed, so no
  new gate run beyond confirming the already-green state (4286 lib tests,
  63 doctests, fmt/clippy/rustdoc clean) still holds.

- **2026-07-01** — **SOL-PERF-PUBLISH `[ ]`→`[~]` — the concrete C2
  increment flagged during T2.17 is delivered: `web_crawler`'s BFS crawl
  loop is now genuinely concurrent.** **P→S step:** with T2.11 closed and
  T2.7 still blocked, priority-3 ("a concrete gap from `SOLUTION_TREE` §4")
  found exactly one item sized right for one focused commit: the C2
  increment this file already scoped in detail two cycles ago — same-round
  concurrent fetching for the BFS crawl, mirroring `probe_config_leaks`'s
  proven `Semaphore`/`JoinSet` pattern, with the determinism design already
  sketched (fetch one batch concurrently, reassemble by original position,
  not completion order). Every other open item (F.1/F.2's remaining legs,
  C1/C3/C4/C5/C6/C7's larger builds) was either explicitly deferred, gated
  on unmet prerequisites, or too large for one commit. **S→P step:** added
  `crawl_util::fetch_batch` — spawns a `JoinSet` over a same-round batch
  (capped at 8, `remaining_budget.min(CRAWL_CONCURRENCY)` so `max_pages` can
  never be exceeded), then reassembles outcomes indexed by ORIGINAL position
  regardless of which fetch completes first. `process()`'s crawl loop now
  selects a batch (visited/SSRF/robots checks unchanged, still per-URL
  synchronous pre-filters), fetches it via `fetch_batch`, then processes
  results in that fixed order — extraction, link discovery, and
  `notable_pages` all stay exactly as deterministic as the old sequential
  loop, just applied per-round instead of per-page. The 200ms
  "Termux-friendly" delay moved from per-page to per-round (pacing rounds,
  not individual requests, now that a round's requests are concurrent).
  5 new tests: 3 directly exercise `fetch_batch` against a local
  multi-connection mock TCP server (`spawn_delay_server`) — genuine
  concurrency proven via wall-clock (4×250ms pages finish in well under
  500ms), order-preservation proven by making page 0 the SLOWEST responder
  and page 2 the fastest and asserting `outcomes[i]` still matches page `i`
  regardless, plus an unreachable-URL failure case; confirmed via
  `git stash` that all 3 don't exist against the unfixed code. Could NOT
  test the full `process()` loop end-to-end against a local mock server —
  the SSRF egress guard (`url_host_is_private`) correctly blocks any
  loopback/private seed URL, and weakening it for testability was never on
  the table — so verified the whole module for real instead: a live A/B
  against `quotes.toscrape.com` (47 pages, 53 internal links) ran 17.1s on
  the pre-fix sequential build and 5.3s on this fix (reproducible across
  repeat runs), for BYTE-IDENTICAL crawl output (same page/link/framework/
  security-header counts) — a ~3.2× wall-clock improvement with zero
  behavioural drift, the strongest form of live verification available
  given the guard that must stay intact. **Gap refresh:** §4a's C2 entry
  updated from "not yet started" to delivered-with-remainder (the published
  benchmark suite itself, still gated on §3.F); §4d's capability row
  updated; leverage-map row `[ ]`→`[~]`. Paired: `PROBLEM_TREE` C2
  `[ ]`→`[~]` + §8 — same commit. Gate green: fmt/clippy
  `--all-targets --locked -D warnings`/strict-rustdoc clean, 4289 lib tests
  (4286→4289, +3), full `cargo test` green.

- **2026-07-01** — **New: SOL-AU087-INDEX closes T2.22 (an AU-034-class
  O(n²) regression in AU-087, found while finishing F.3's in-progress
  node); SOL-F3's stale "criterion for the correlation pass" gap
  corrected to its already-delivered, better-justified close.** **P→S
  step:** with T2.11 and C2 both closed last cycle, F.3 was the sole
  remaining in-progress (`[~]`) node — priority 1 ("finish an in-progress
  node") picked it. F.3's own "remaining" text named two items:
  `cargo-fuzz` (needs a new CI lane — deferred, a higher-blast-radius
  shared-system change this loop doesn't take unprompted) and "widen
  criterion to the correlation pass once a bench-visible entry point
  exists." Investigating the second found `core::correlator::perf` already
  covers exactly this, deliberately WITHOUT `criterion` — its own doc
  comment explains why (avoiding a heavy transitive dep on the
  minimal-dependency Termux build) — a stale note, not an open gap.
  **Running the existing guard to confirm it still holds is what surfaced
  the real finding:** `pass_is_subquadratic --ignored` FAILED, consistently,
  11.1–11.5× scaling for a 4× entity increase against a 9× ceiling. A
  temporary per-rule scratch profile (not committed) isolated the cause to
  `rule_au_087_shared_org_email_domain` alone (17.06× scaling, ~90% of the
  whole pass's cost at n=2000) — every other rule scaled a healthy ~4×.
  **S→P step:** root cause was AU-087's Person "ride-along" step doing a
  full nested scan (every Person × every address in every qualifying
  domain cluster) via `identity_overlaps`, the exact "per-rule nested scan
  dominates the pass" bug class `AU-034` was already fixed for once.
  Fixed via a one-time index rather than a bounded/capped workaround:
  `identity_overlaps`'s "substring ≥ IDENTITY_OVERLAP_MIN(4) chars" check
  is mathematically equivalent to "shares a common 4-gram" once both sides
  reach that length, so a `HashMap<[u8;4], Vec<uid>>` gram index (+ a
  short-name exact-match side table for the `identity_overlaps` short-input
  fallback) replaces the O(persons) per-address scan with an O(1)-average
  lookup — byte-identical firing behaviour, not an approximation.
  `IDENTITY_OVERLAP_MIN` re-exported from `core::scan` (was private) so the
  fix references the canonical constant instead of a duplicated `4`.
  Verified via `git stash`: the guard fails (11.24×) against the unfixed
  code, passes (~4.0×, 3 repeat runs) against the fix — the standard
  "fails-then-passes" regression proof, using a pre-existing test rather
  than a new one, matching AU-034's own precedent (no dedicated per-rule
  scaling test exists for AU-034 either — the whole-pass guard IS the
  regression test for this bug class). 1 new correctness test for the
  gram-index rewrite's short-name edge case; all 4 pre-existing AU-087
  tests pass unchanged. Live-verified via `hse selftest`'s real
  DB-round-trip correlator check. **Gap refresh:** SOL-F3's node text
  corrected (import proptest was ALSO stale-marked "outstanding" there
  despite being delivered 2026-06-17 — fixed in the same pass since it's
  the same node); leverage-map gains the new SOL-AU087-INDEX row; §4d's T2
  row folds T2.22 into the closed bug family. Paired: `PROBLEM_TREE` new
  T2.22 `[x]` + F.3 correction + §8 — same commit. Gate green: fmt/clippy
  `--all-targets --locked -D warnings`/strict-rustdoc clean, 4290 lib tests
  (4289→4290, +1), full `cargo test` green.

- **2026-07-01** — **New: SOL-DISPATCH-HANG closes T2.23 (a 9+-minute
  unbounded scan hang across three independent O(n²)/unbounded hot paths);
  new T2.24 logged (not fixed) for two related-but-unconfirmed residuals
  found during adversarial review.** **P→S step:** with T2.7 the sole
  remaining open T-series node and F.1–F.3/C1–C5 all `[~]` with only
  explicitly-deferred remainders, a fresh discovery pass ran the codebase's
  own existing `#[ignore]`d perf baselines — the exact angle that found
  T2.22, applied again. `core::engine::tests::bench_end_to_end_scan_
  scaling` (never previously run to completion) hung 9+ minutes at its
  first data point (1000 entities) and was killed. **S→P step:** temporary
  binary-search instrumentation across the whole post-expansion scan tail
  found three independent causes — a full-`entity_map` lineage diff per
  dispatch, an unbounded `derive_all` call in `run_gap_fill` (the ACTUAL
  finalise pass three call sites later already uses the bounded
  `derive_all_within`), and three correlator relation-rules
  (AU-062/AU-063/AU-069) each independently running an unguarded O(pairs)
  nested loop over identity-entity pairs — a THIRD instance of the
  T2.22/AU-034 bug family, confirming it systemic across the graph-analysis
  rule family. Fixed all three with the SMALLEST correct primitive for
  each: direct UID tracking at the insertion point (not a diff), reuse of
  the existing `DERIVE_BUDGET` constant (not a new one), and one new shared
  `MAX_IDENTITY_UIDS_FOR_PAIRWISE_SEARCH` ceiling applied to all three
  offending functions (deliberately entity-count-keyed, not wall-clock, to
  preserve correlation-rule reproducibility). 3 new regression tests,
  `git stash`-confirmed non-vacuous. **Live-verified empirically** — the
  SAME hung baseline now completes: 1000 entities 10.3s, 2000 34.3s, 4000
  129.4s (bounded, versus 9+ minutes and climbing, killed, before). Then
  **spent a full adversarial-verification workflow** (3 independent area
  reviewers + their own refutation passes, 9 agents total) BEFORE closing
  the cycle, given the change touches core dispatch/correlator logic —
  found the implementation itself correct with zero blocking issues, and
  surfaced honest residuals rather than a clean bill of health: two
  independent (not shared) `DERIVE_BUDGET` windows (additive worst-case,
  not compounding — pre-existing, not a regression), `run_gap_fill`'s
  bounded derivation lacking its own dedicated unit test (mitigated by the
  primitive's separate test plus this fix's end-to-end proof), and —
  substantively — **two more relation-rules (AU-070/AU-071) sharing a
  DIFFERENT unguarded graph-size-dependent cost** (`connection_brokers`,
  keyed on total graph-node count, not identity pairs) plus AU-060
  (`identity_paths`, additive not combinatorial). Neither showed
  catastrophic cost in this cycle's own measurements and neither is a
  drop-in fit for the new guard (different cost keys) — logged as new
  T2.24 for a future cycle's own dedicated measurement rather than
  mechanically copying this cycle's fix onto an unverified different shape.
  **Gap refresh:** leverage-map gains SOL-DISPATCH-HANG `[x]`; §4a gains
  new T2.24 (no solution started); §4d's T2 row folds T2.23 into the
  closed bug family and adds T2.24 as open. Paired: `PROBLEM_TREE` new
  T2.23 `[x]` + new T2.24 `[ ]` + §8 — same commit (also backfilled T2.22's
  missing §8 entry, found while writing this one — see that entry's own
  note). Gate green: fmt/clippy `--all-targets --locked -D warnings`/
  strict-rustdoc clean, 4293 lib tests (4290→4293, +3), full `cargo test`
  green.

- **2026-07-01** — **New: SOL-BROKER-CEILING closes T2.24's
  `connection_brokers` half (14.4s+ and climbing on a dense hub-and-spoke
  identity graph); new T2.25 split out honestly for the OTHER half of
  T2.24's original scope, found real while verifying this fix.** Finishing
  T2.24, the sole in-progress residual left by T2.23's own adversarial
  review. First built a temporary diagnostic test reproducing the DENSE
  hub-and-spoke shape T2.23's tree-shaped benchmark never exercised, and
  measured `connection_brokers` directly: confirmed catastrophic (1.6s at
  240 graph nodes, 14.4s at 480, worse than cubic) — settling T2.24's own
  "unconfirmed" framing for this half. Fixed with a new deterministic
  `MAX_GRAPH_NODES_FOR_BROKER_SEARCH = 300` ceiling (graph-node-count-keyed,
  not wall-clock, mirroring `MAX_IDENTITY_UIDS_FOR_PAIRWISE_SEARCH`'s
  established reproducibility reasoning), applied once inside
  `connection_brokers` itself rather than duplicated across its three call
  sites (AU-070, AU-071, the dossier CLI), so all three inherit the fix
  automatically. 2 new regression tests, `git stash`-confirmed non-vacuous
  (fail at ~3.5–5s elapsed against the unfixed code, pass under 100ms
  against the fix). **Live-verified**: the same diagnostic that measured
  14.4s at 480 nodes now completes in 90ms; 960 nodes in 376ms; 300 nodes
  (at the ceiling) stays bounded at 3.55s. While proving AU-071 fully safe
  post-fix, found it ISN'T — its `resolve_identity_clusters` call (→
  `identity_paths`) runs BEFORE `connection_brokers` and independently
  took 3.48s on the same 301-node graph shape, meaning T2.24's own
  "AU-060/`identity_paths` is additive, lower urgency, unconfirmed"
  framing was wrong on that point. Rather than silently declare AU-071
  safe or scope-creep a second, differently-keyed primitive's fix into
  this commit, split the residual out as new T2.25 with the concrete
  measurement already in hand. **Independently adversarially reviewed**
  (15 agents: 3 area reviews × their own refutation passes) before
  shipping, given the change touches a shared core relation-graph
  primitive with three consumers — correctness and determinism/style
  clean; the coverage review correctly caught that T2.25's first draft
  under-listed `identity_paths`'s consumer set (three named, not the real
  four — missing `engine::rank_identity_aware_targets`'s live `scan_auto`
  HTTP path, and one of the dossier CLI's two affected sections), fixed in
  `PROBLEM_TREE`'s T2.25 text before this commit rather than shipped
  inaccurate. **Gap refresh:** leverage-map gains
  SOL-BROKER-CEILING `[x]`; §4a's T2.24 gap entry is replaced by T2.25;
  §4d's T2 row folds T2.24 into the closed bug family and adds T2.25 as
  open. Paired: `PROBLEM_TREE` T2.24 `[x]` + new T2.25 `[ ]` + §8 — same
  commit. Gate green: fmt/clippy `--all-targets --locked -D warnings`/
  strict-rustdoc clean, 4295 lib tests (4293→4295, +2), full `cargo test`
  green.

- **2026-07-01** — **New: SOL-IDENTITY-PATH-CEILING closes T2.25 —
  `identity_paths` had TWO independent unguarded cost axes, not one; the
  second was found and fixed by this cycle's own adversarial review
  before shipping.** Finishing T2.25, the sole in-progress residual left
  by T2.24's own adversarial review. T2.25's sketch left one open
  question: reuse the existing identity-count ceiling, or design a
  bespoke one — undecided without a dedicated measurement at larger
  identity counts than the single 221-entity data point T2.24's
  verification happened to produce. Built that dedicated diagnostic
  (dense hub-and-spoke shape, hub count scaled proportionally with
  identity count, 50–400 identity entities) and measured `identity_paths`
  directly: ~1.7s at 200 (right at the existing ceiling), ~4.1s at 221,
  ~14.9s at 400. Reused the EXISTING `MAX_IDENTITY_UIDS_FOR_PAIRWISE_
  SEARCH` (200) rather than invent a third constant — worst case at the
  boundary (~1.5–1.7s) lands in the same "low single-digit seconds" band
  SOL-BROKER-CEILING's own ceiling did. A 3-area, 21-agent adversarial
  review (required before shipping, since this touches a shared core
  primitive with multiple consumers) then caught a REAL, MAJOR gap the
  proportional-hub-count measurement had masked: the identity-count
  ceiling bounds only the O(identity_count²) pair-reconstruction term,
  but `identity_paths` ALSO runs one full BFS per identity — a SEPARATE
  cost in total graph node count, independent of identity count. Three
  verifiers independently reproduced it: 20 identities against 8,000
  non-identity nodes (an ordinary shape — real identities enriched with
  breach-derived URLs/IPs/credentials) took ~5.6s, sailing straight
  through the 200-identity ceiling. Fixed in the SAME cycle rather than
  deferred to yet another node (the same primitive already being fixed,
  not a distinct one): a new `MAX_IDENTITY_PATHS_SEARCH_UNITS = 50_000`,
  bounding the PRODUCT `identity_count × total_graph_nodes` — the actual
  quantity the dominant BFS cost scales with — measured directly at the
  worst case within the first ceiling (200 identities, node counts
  250–500 → 2.1s–13.8s) to size the value. Verified directly (not just
  assumed) that `resolve_identity_clusters` AND `connection_templates`
  both delegate their entire cost to `identity_paths`, so both new guards
  automatically cover all SEVEN downstream consumers: AU-060 (direct),
  AU-064/the engine's cross-scan pathway-template learning (via
  `connection_templates`), AU-067/AU-071 (via `resolve_identity_
  clusters`), the dossier CLI's CONNECTIONS/RESOLVED IDENTITIES sections,
  and `engine::rank_identity_aware_targets` (reachable from the live
  `scan_auto` HTTP endpoint). The review's coverage pass also caught that
  `connection_templates`/AU-064 was itself missing from this node's
  first-draft consumer list — already protected in practice, but
  undocumented; corrected here. 5 new regression tests (the primitive on
  each axis, `resolve_identity_clusters` directly, `connection_templates`
  directly, and AU-060's rule), `git stash`-confirmed non-vacuous against
  both guards removed together. **Live-verified** on both axes:
  identity-count — 201 entities (one past that ceiling) fell from an
  extrapolated ~4s+ to ~120µs, 200 (at the ceiling) stays ~1.45s;
  search-unit — the reviewers' exact 20-identity/8,000-node case fell
  from ~5.6s to ~483µs, 20 identities against 2,000 nodes (under the
  ceiling) still runs in ~1.1s. `hse selftest`'s correlator check
  unchanged (3 rules fire). **Gap refresh:** leverage-map gains
  SOL-IDENTITY-PATH-CEILING `[x]`; §4a's T2.25 gap entry closes; §4d's T2
  row folds T2.25 into the closed bug family — the T2.22–T2.25 arc is now
  fully closed, seven consumer surfaces across two primitives protected
  by three shared, deterministic ceilings (pairwise-count, graph-node-
  count, and node-times-identity-count). Paired: `PROBLEM_TREE`
  T2.25 `[x]` + §8 — same commit. Gate green: fmt/clippy `--all-targets
  --locked -D warnings`/strict-rustdoc clean, 4300 lib tests
  (4295→4300, +5), full `cargo test` green.

- **2026-07-01** — **SOL-GEOINT extended (stays `[~]`): `hse cells status`
  now warns on a stale local cell-tower snapshot — the honest, scoped
  half of the "cell_local auto-sync" S→P gap that's actually buildable
  this cycle.** With T2.25 closed and T2.7 still blocked, a discovery
  pass over §4a's ungated gaps found this one concrete, no-code-yet item.
  Investigated feasibility FIRST rather than assuming: `hse` has no
  daemon/background-process infrastructure anywhere (every subcommand,
  including `cells import`, is one-shot; the only long-lived process,
  `hse serve`, is foreground/opt-in), so literal "auto-sync" (a
  cron/daemon path) needs either inventing new daemon infrastructure (a
  large architectural addition, not appropriate unprompted in one cycle)
  or an OS-level cron example (a docs/shell deliverable, not a code fix)
  — architecturally analogous to T2.7's blocked status. Rather than force
  either or silently skip the gap, delivered the real increment inside
  it: `hse cells status` already read the last import's age but applied
  no judgement — an operator relying on a long-forgotten snapshot got no
  signal their coverage might be stale. New pure
  `staleness_warning(age_secs) -> Option<String>`
  (`src/cli/cells/mod.rs`), warning above a 90-day threshold. 4 new
  regression tests, `git stash`-confirmed non-vacuous. Live-verified
  against a real imported DB: fresh import → no warning; the same DB
  backdated 91 days → the exact warning text. `hse selftest` 9/9
  unaffected. **Gap refresh:** §4a's "cell_local auto-sync" entry marked
  partially covered, remainder narrowed to the cron/daemon path itself;
  §4d's C5 row notes the staleness-warning delivery. Paired: `PROBLEM_TREE`
  C5 node updated (SOL-GEOINT extended) + §8 — same commit. Gate green:
  fmt/clippy `--all-targets --locked -D warnings`/strict-rustdoc clean,
  4304 lib tests (4300→4304, +4), full `cargo test` green.

- **2026-07-01** — **SOL-REDACT extended, closing §7 S4 — but by
  investigating the node's own sketch before implementing it, not
  mechanically. Found the sketch would have violated an explicit,
  quoted operator policy; delivered the correctly-scoped fix instead.**
  With T2.25 and the C5 auto-sync increment both shipped, S4 was the next
  concrete, unblocked, no-live-network `[ ]` item. Read
  `crate::util::raw_archive`'s own module doc before touching it — found
  it carries a verbatim-quoted operator directive ("Data that is paid for
  must be kept in absolute completeness... never encrypted, hashed, or
  redacted") that S4's own sketch (redact the archived body) would have
  directly violated. Also found S4's stated risk premise ("0600, but
  pulled into the non-0600 DB/dossiers via S3") is now stale — S3 already
  made the dossier 0600. Traced the GENUINE remaining exposure instead:
  `hse export -o <path>` deliberately leaves permissions to the user's
  umask (S3's own documented boundary, since the operator is explicitly
  choosing to share that file), and the full dossier's RAW SOURCE RECORDS
  section embeds the archived body verbatim into that exportable copy —
  so a provider echoing the request URL/params back could leak the
  OPERATOR's OWN key into a shared export, distinct from the third-party
  evidentiary data the "never redact" policy protects. Fixed the
  correctly-scoped half: `raw_archive`'s on-disk file stays untouched
  (policy honoured); new `redact_own_keys` (`cli/export/renderers.rs`)
  masks only the operator's OWN keys (`own_api_keys()`) in the dossier's
  derived, exportable copy, reusing `redact_literal_secrets` (widened
  `pub(super)`→`pub(crate)` in `util::http::redact`, alongside its sibling
  `redact_credentials`). 2 new regression tests (masks the operator's own
  echoed key; leaves genuine target/foreign data — a leaked password, a
  victim email — untouched), `git stash`-confirmed non-vacuous. **Gap
  refresh:** leverage-map SOL-REDACT ◑→`[x]`; §4a's S4 entry closes; §4d's
  §7 row shows S4 `[x]` — §7 fully closed. Paired: `PROBLEM_TREE` §7 S4
  `[ ]`→`[x]` + §8 — same commit. Gate green: fmt/clippy `--all-targets
  --locked -D warnings`/strict-rustdoc clean, 4306 lib tests
  (4304→4306, +2), all 30 `tests/architecture.rs` guards pass, full
  `cargo test` green, `hse selftest` 9/9.

- **2026-07-01** — **New: SOL-AHPRA-TRUNCATION closes T2.26 (`ahpra`'s
  silent 20-result truncation) — the smallest, highest-leverage pick from
  a 6-angle, 54-agent discovery pass run to verify the backlog was
  genuinely exhausted before checkpointing.** With T2.25, C5's auto-sync
  increment, and §7 S4 all closed last cycle, step 1's orient pass found
  only genuinely-blocked (T2.7) or gated-by-design (C1/C6/C7 — though see
  below) work remaining, so — per the standing protocol's own priority
  (4) — ran a fresh, code-grounded, multi-angle discovery pass rather than
  assume the backlog was exhausted from that alone. Six independent
  angles (ignored-tests, dead-or-unwired accessors, test-name-overclaim,
  silent-truncation-or-caps, stale-tree-claims, newer-clippy-lints), each
  independently verified by 3 adversarial refuters, surfaced **14
  confirmed-real findings** (of 16 raw candidates) — far from a genuine
  stopping point. Picked the single highest-leverage one to fix this
  cycle: `ahpra`'s national health-practitioner register scraper silently
  truncated at 20 results with no signal, the same "reported success,
  actually incomplete" evidentiary-completeness class T2.18 already
  established as real severity. Fixed by extracting a pure
  `build_practitioner_entities` that attaches the TRUE row count as
  `total_matches` — the SAME established pattern 5 other modules already
  use (`opencorporates`, `gleif_lei`, `acnc_charities`, `au_unclaimed`,
  `api_key_probe`), not a bespoke mechanism. 2 new regression tests, `git
  stash`-confirmed non-vacuous. **The other 13 confirmed findings were
  NOT silently dropped** — logged honestly as new backlog: three
  structurally-identical truncation bugs (T2.27 `acma_rrl`, T2.28
  `crtsh`, T2.29 `bgpview`), a dead/unwired-accessor triple (T2.30, the
  established T2.13-16/21 family), a test-name-overclaim quadruple (T2.31,
  the established T2.20 family), and three STALE tree claims corrected
  IN PLACE this same commit (no code change needed): SOL-CORR's
  "Remaining: first-class timeline output" (already shipped,
  `core::timeline`), SOL-AU-MOAT's "state cadastre/property" (already
  shipped, `au_property`), and SOL-OFFENSIVE/C6's `[ ]` marker (the
  aho-corasick key-harvest + entropy gate sub-item was already shipped —
  flipped to `[~]`, and C1 was ALSO found still marked as if ungated
  despite its own cycle-26 deliverables, corrected alongside it). **Gap
  refresh:** leverage-map gains SOL-AHPRA-TRUNCATION `[x]`, SOL-OFFENSIVE
  ◦→`[~]`; §4a gains T2.26 (closed) + T2.27-T2.31 (new, open); §4d's C1/C6
  markers corrected, T2 row gains T2.26. Paired: `PROBLEM_TREE` new T2.26
  `[x]` + T2.27-T2.31 `[ ]` + C1/C6 corrections + §8 — same commit. Gate
  green: fmt/clippy `--all-targets --locked -D warnings`/strict-rustdoc
  clean, 4308 lib tests (4306→4308, +2), full `cargo test` green, `hse
  selftest` 9/9.
