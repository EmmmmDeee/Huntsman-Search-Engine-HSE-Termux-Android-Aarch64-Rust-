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
  *Remaining:* Weiszfeld/Welzl centroid fusion; AU bounding precision;
  movement/timeline layer; provenance radius output; auto-scheduled re-sync of
  the local cell DB (currently requires manual `hse cells import` trigger).
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
  *Remaining:* `--check` shows commit count only — no diff summary yet.
  **(cycle 22)**

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
| SOL-SSRF / -WHOIS | §6 (HTTP) · §7 S2 | `[x]`/`[x]` |
| SOL-SECRETS / -EXTEND | env/pool/archive · §7 S3 | `[x]`/`[x]` |
| SOL-REDACT | §7 S4 | ◑ |
| SOL-EMBED | §7 S1 (accepted) | `[-]` |
| SOL-CLI-CONTRACT / -DIFF / -CACHE | T2.12 | `[x]`/`[x]`/`[x]` |
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

---

## 4. Gap analysis — the live diff between the trees (refreshed every pass)

> This section *is* the alternation made concrete. **4a** = problems with no started
> solution (P→S gaps, the build queue). **4b** = solutions begun but unfinished (the
> finish queue). **4c** = solutions with no problem (over-build — prune candidates).
> When 4a + 4b are empty, the two trees agree.

### 4a · Problems with NO solution yet started (P→S coverage gaps)
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
- **C1/C2/C6/C7** — capability nodes; solutions sketched, none started (gated on
  the §3.F enablers landing first, by design).
- **AU-060 (new, cycle 20 S→P gap):** `opencellid` emits `DeviceId` (tower MCC/MNC/
  LAC/CID) and `cell_intel` also emits `DeviceId` for the same tower type — no
  correlation rule cross-validates them. Candidate rule AU-060: medium-confidence
  corroboration signal when both modules fire for the same tower. No solution node yet.
- **cell_local auto-sync (new, cycle 21 S→P gap):** `hse cells import` requires a
  manual trigger and a BYO OpenCelliD key; no auto-scheduled re-sync exists. A
  recurring `hse cells import --country world` cron/daemon path would keep the local
  DB fresh without user intervention. No solution node yet.
- **hse update --check changelog (new, cycle 22 S→P gap):** `--check` reports only
  the number of commits available — no commit subject lines or diff summary. A future
  pass could run `git log --oneline HEAD..@{u}` and surface the messages so the user
  can decide whether to update without manually `git log`-ing. No solution node yet.

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
  T2.7 open; T2.11 mostly done (oathnet + found_keys/SOL-ISOLATE; LOW over-dispatch +
  budget-reset-zeroing remain).
- **S.CORE sensor gate:** **SOL-SENSOR-GATE `[x]`** ✅ (cycle 24) — all six
  live-sensor modules now consistently gate on `Coordinates | MacAddress` and
  appear in `LOCAL_PASSIVE_MODULES`; non-geo scans receive zero phone-sensor
  data.
- **§7 (security):** XSS + S2 + S3 solved; S1 accepted; **S5 `[x]`** ✅
  (SOL-INSTALL-INTEGRITY, cycle 16); S4 residual open (LOW).
- **§4 (capability C1–C9):** C8 delivered ✅ (`streaming_probe`, 42-site webcam/fan/adult prober); **C9 delivered** ✅ (SOL-CACHE-INTERSCAN, cycle 18, `raw_archive` + dispatch cache gate); **C5 `[~]`** (SOL-GEOINT: `opencellid` cycle 19 + `cell_local`/`hse cells import` cycle 21 delivered, Weiszfeld/centroid fusion + auto-sync remaining); **C3 `[~]`** (SOL-AU-MOAT: hlr_cnam/ahpra/acma_rrl/trove_au/smtp_vrfy/`austlii` shipped, courts/AustLII closed; GNAF/ASIC/cadastre remaining); **C4 `[~]`** (SOL-NETINT: netlas + censys + securitytrails + bgpview + ripestat all shipped; passive-DNS history + CDN cert-hash origin remaining); C1/C2/C6/C7 open by design, gated on §3.F. **SOL-UPDATE `[x]`** (cycle 22, `hse update`/upgrade + CLI consolidation 19→13 visible commands).

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
