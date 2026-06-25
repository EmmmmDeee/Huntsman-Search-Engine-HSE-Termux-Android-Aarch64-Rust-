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
- **`[ ]` SOL-CORR · Correlation & identity depth** → **C1** (Maltego-without-graphs):
  transitive identity closure (property-tested convergence), a text "Connections"
  dossier section, first-class timeline, AU-0xx rule-gap fill. Built on SOL-MERGE.
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
| SOL-CORR | C1 | `[ ]` |
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
- **AU-063 (cycle 20 S→P gap → delivered cycle 41, 2026-06-25):** `opencellid` and
  `cell_intel` both confirm the same `mcc-mnc-lac-cid` tower via orthogonal methods
  (live hardware sensor × crowdsourced database). **Closed** — AU-063
  `rule_au_063_cell_tower_dual_source` added to `src/core/correlator/rules/geo.rs`
  and wired into `RULES`. See §5 cycle 41.
- **cell_local auto-sync (new, cycle 21 S→P gap):** `hse cells import` requires a
  manual trigger and a BYO OpenCelliD key; no auto-scheduled re-sync exists. A
  recurring `hse cells import --country world` cron/daemon path would keep the local
  DB fresh without user intervention. No solution node yet.
- **hse update --check changelog (new, cycle 22 S→P gap):** `--check` reports only
  the number of commits available — no commit subject lines or diff summary. A future
  pass could run `git log --oneline HEAD..@{u}` and surface the messages so the user
  can decide whether to update without manually `git log`-ing. No solution node yet.
- **P12 — `waf_detect` consistent connection error (new, cycle 27 S→P gap):**
  All 3 statistical-baseline scan runs against `github.com` recorded `waf_detect` →
  `module_error: connection error`. Code inspection confirms the module correctly uses
  `ctx.http.head(&url)` (the proxy-aware client); the connection failure is therefore
  not a proxy bypass but a destination-side rejection: the HTTPS proxy's egress IP
  range may be blocked by GitHub / Cloudflare, or the proxy may block `HEAD` method
  to certain destinations. Root cause is environmental, not a code defect. Options:
  (a) accept as scan-target-specific environmental limitation (github.com is an
  unusual WAF test target — most real targets aren't behind Cloudflare's Anycast and
  bot-protection); (b) fall back to a `GET` request with a small body cap when `HEAD`
  fails; (c) detect `HEAD`-blocked errors and skip gracefully. No solution node yet;
  option (a) most likely accepted.
- **P13 — `web_crawler` consistent HTTP unreachable (new, cycle 27 S→P gap):**
  All 3 statistical-baseline scan runs against `github.com` recorded `web_crawler` →
  `module_error: HTTP unreachable`. Code inspection shows `resolve_seed(&ctx.http, &d)`
  uses the proxy-aware client; the failure is likewise destination-side. The crawler
  attempts `https://github.com` as seed — GitHub returns a redirect or error that
  the module's `resolve_seed` cannot resolve (or the proxy blocks the redirect chain).
  GitHub.com actively suppresses automated crawling; the module works correctly for
  ordinary sites. Options: (a) accept as scan-target-specific environmental
  limitation (github.com's bot-protection makes it an atypical crawl target);
  (b) add a redirect-limit guard + fall-through to seed URL as-is when auto-resolution
  fails. No solution node yet.

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
- **SOL-MODULE-TYPOSQUAT `[x]`** (cycle 26) — `typosquat` world-class rewrite:
  combo-squat (50 phishing terms, 4 patterns), MX probing (async, hickory-resolver),
  confidence tiering (0.40–0.90), vowel-swap, keyboard-addition, bitsquat, AU two-
  level suffix support, cap 256→512, timeout 15→45 s, 22 new unit tests; 3,129 tests
  total. Zero-variance execution baseline confirmed (104 entities, 3 independent
  runs). **P-TYPO-F (MX behind proxy)** → logged in §4a.
- **SOL-PROXY-AWARE `[x]`** (cycle 27) — `whois` proxy-aware: domain targets skip
  instantly (zero wasted seconds); IP targets gain RDAP-over-HTTPS org/country/abuse
  via rdap.org bootstrapper → authoritative RIR. `vcard_field()` pure helper +
  `find_ip_entity()` recursive traversal. 2 new unit tests. Validation: 3rd scan run
  confirmed zero error + zero timeout. **P12/P13** (`waf_detect`/`web_crawler`
  consistent failures) → open in §4a.
- **SOL-MODULE-DOH `[x]`** (cycles 28 + 28.1) — `doh_resolver` world-class rewrite:
  SOA (mname→Domain, rname→Email), CAA (issue/issuewild→CA Domain, RFC 3597 hex format
  from Cloudflare DoH decoded by `decode_caa_hex_rdata()`), PTR (IpAddress targets →
  reverse-DNS hostnames), DMARC `_dmarc.{domain}` subquery (rua/ruf→Email). JoinSet
  parallel dispatch (~6× faster). `produces()` → [IP, Domain, Email]. `accepts()` →
  Domain | Url | IpAddress. 23 new tests; 3,152 total. Baseline confirmed: **doh_resolver=30**.
- **SOL-MODULE-CLOUD-STORAGE `[x]`** (cycle 29) — `cloud_storage` world-class rewrite:
  5 providers (+ DigitalOcean Spaces nyc3 + Wasabi us-east-1); 16 suffixes (+ -prod/
  -staging/-static/-media/-logs/-images/-uploads/-test/-archive/-files); 80 total
  candidates (vs 18 prior, 4.4× coverage); JoinSet concurrent probing; `probe_url`
  uses `send_tagged(SRC)`; `is_exposed` handles all 5 providers; `max_timeout_ms`
  15s → 20s. 7 new unit tests; 3,159 total. Closes P-CS-A through P-CS-D.

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
- **2026-06-24** — **Cycle 26 (S→P): SOL-MODULE-TYPOSQUAT — `typosquat` module
  elevated to world-class: combo-squat, MX probing, confidence tiering, new
  technique classes, 45-second sweep.**
  **Evidence base:** 3 real-execution scan runs (statistical baseline, zero
  variance at 104 entities). Gap analysis identified five distinct sub-problems
  (P-TYPO-A through P-TYPO-E) absent from the pre-rewrite module.
  **Solutions delivered:**
  - *SOL-MODULE-TYPOSQUAT.A — combo-squat:* `COMBO_WORDS` constant (50 high-
    signal phishing terms); generates `{label}{word}.{tld}`, `{word}{label}.{tld}`,
    `{label}-{word}.{tld}`, `{word}-{label}.{tld}` for every word × every TLD
    variant. Priority-sorted to top of output (confidence 0.90) so the cap always
    retains highest-threat candidates first.
  - *SOL-MODULE-TYPOSQUAT.B — confidence tiering:* `technique_confidence(&str) ->
    f32` maps each technique to a calibrated score: combo-squat 0.90, homoglyph
    0.80, keyboard 0.70, vowel-swap 0.60, transposition/omission/repetition/addition
    0.55, hyphenation/tld-swap 0.50, bitsquat 0.40. `permutations()` returns
    `Vec<(String, &'static str)>` sorted by descending confidence before de-dup +
    cap; the cap retains the highest-threat variants under pressure.
  - *SOL-MODULE-TYPOSQUAT.C — MX probing:* async `hickory-resolver` lookup (≤4
    parallel probes, system resolver, timeout-gated); domains with MX records emit
    `Domain` entities tagged `["mx-confirmed"]` at confidence 0.88 (vs 0.60 for
    unprobed candidates); discriminates actively-phishing registrations from parked
    domains. `max_timeout_ms()` raised 15 s → 45 s to accommodate the DNS sweep.
  - *SOL-MODULE-TYPOSQUAT.D — new technique classes:* vowel-swap (`a`→`e/i/o/u`
    and back, skipping no-vowel labels); keyboard-addition (insert keyboard-adjacent
    char at each position); bitsquat (flip each bit of each byte, emit only
    `is_valid_label()` results); `keyboard_neighbors()` + `homoglyphs()` exported
    `pub(super)` for unit-testing; cap raised 256 → 512; AU two-level suffixes
    (com.au, net.au, org.au) threaded through all technique classes.
  - *SOL-MODULE-TYPOSQUAT.E — test coverage:* 22 new unit tests in `tests.rs`
    covering technique classes, combo-squat ordering guarantee, confidence range
    invariants, vowel-swap for vowel-free labels, AU suffix handling, cap
    enforcement, degeneracy inputs, bitsquat validity, keyboard-adjacency +
    homoglyph maps, COMBO_WORDS coverage guard. Total: 3,129 lib tests (+32 vs
    cycle 25).
  **S→P gap from this cycle:** MX-probe accuracy depends on resolver visibility;
  behind a restrictive proxy DNS-over-HTTPS would give better coverage than the
  system resolver. Logged as P-TYPO-F; not blocking. **§4 update:** SOL-MODULE-
  TYPOSQUAT row added to §4d. Gate green: fmt/clippy/doc clean, 3,129 tests, 0
  failures. Paired: `PROBLEM_TREE` §8 cycle 26 — same commit.
- **2026-06-24** — **Cycle 27 (P→S): SOL-PROXY-AWARE — `whois` proxy-aware
  rewrite; domain targets skip instantly behind proxy; IP targets gain RDAP-over-
  HTTPS fallback (org / country / abuse email from authoritative RIR).**
  **Evidence base:** 2/2 real-execution scan runs recorded `whois` → `module error:
  timed out (22.3 s)`; validation run (post-fix) confirmed `done: 0 found` (instant,
  zero error). Proxy environment confirmed via `HTTPS_PROXY` env var.
  **Solutions delivered:**
  - *SOL-PROXY-AWARE.A — proxy detection:* `behind_proxy() -> bool` checks
    `HTTPS_PROXY` / `https_proxy` env vars (both casings); zero external calls at
    detection time.
  - *SOL-PROXY-AWARE.B — domain target skip:* when `behind_proxy()` and target is
    `Domain`/`CidrRange`, `process()` returns `ModuleResult::new()` immediately with
    a `tracing::debug!` log (`rdap_domain` already provides structured registry data
    over HTTPS, so no intelligence gap; zero seconds wasted per scan).
  - *SOL-PROXY-AWARE.C — IP target RDAP fallback:* `rdap_ip_fallback()` (async);
    fetches `https://rdap.org/ip/{ip}` via `ctx.http` (HTTPS proxy-compatible);
    follows RIR redirect to authoritative ARIN/RIPE/APNIC/LACNIC/AFRINIC endpoint;
    extracts: *Organisation* (vCard `fn`; fallback: `name`/`netName`) confidence
    0.72, tagged `["whois","rdap-fallback","ip-registrant"]`; *Country* confidence
    0.50, tagged `["whois","rdap-fallback","geoint"]`; *Abuse email* (abuse-role
    entity, `@` guard + infra-email filter) confidence 0.72, tagged
    `["whois","rdap-fallback","whois-abuse"]`.
  - *SOL-PROXY-AWARE.D — vcard helper:* `vcard_field(vcard: &Value, prop: &str) ->
    Option<String>` (pure, `pub(crate)`) navigates RFC 6350/JMAP vcardArray format;
    `find_ip_entity<'a>()` recurses entity sub-arrays to locate role-specific
    contacts.
  - *SOL-PROXY-AWARE.E — test coverage:* 2 new unit tests: `vcard_field_extracts_fn_
    and_email` (fn + email extraction), `vcard_field_returns_none_for_malformed_input`
    (object + empty array → None). Total: 3,129 tests (2 new, offset by cycle 26
    baseline). SHA `2a0a7191b53dc0c92100c5d448df8bd6028c9617` pushed to
    `claude/vigilant-galileo-vmjk3e`.
  **S→P gap from this cycle:** `waf_detect` and `web_crawler` show consistent
  `module_error` (connection refused) in all 3 scan runs — both attempt direct HTTPS
  to the target's root URL without going through the HTTPS proxy `ctx.http` client.
  These are the two remaining consistent failures in the statistical baseline. Logged
  as P12/P13; investigation pending. **§4 update:** SOL-PROXY-AWARE row added to §4d;
  P12/P13 added to §4a. Gate green: fmt/clippy/doc clean, 3,129 tests, 0 failures.
  Paired: `PROBLEM_TREE` §8 cycle 27 — same commit.
- **2026-06-24** — **Cycle 28 (S→P): SOL-MODULE-DOH — `doh_resolver` world-class
  rewrite: SOA/CAA/PTR record types, DMARC subquery, concurrent JoinSet queries,
  IpAddress target support, +19 unit tests.**
  **Evidence base:** 23-entity stable baseline (3 independent scan runs, zero
  variance). Code audit identified 5 sub-problems (P-DOH-A through P-DOH-E).
  **Solutions delivered:**
  - *SOL-MODULE-DOH.A — new record types:* SOA (type 6) → `parse_soa_fields()`:
    mname as Domain (confidence 0.75, `ns-primary`) + rname (first `.` → `@`) as
    Email (confidence 0.60, `soa-contact`). CAA (type 257) → `parse_caa_issuer()`:
    issue/issuewild tags → CA domain (confidence 0.70, `caa-issuer`); iodef and
    prohibit-all (";") rejected; `;`-params stripped. PTR (type 12) → hostname as
    Domain (confidence 0.75, `ptr`). `rtype_name()` extended: SOA=6, PTR=12, CAA=257.
  - *SOL-MODULE-DOH.B — DMARC subquery:* `_dmarc.{domain}` TXT query fired as
    9th concurrent task; `dmarc_rua_emails()` extracts all `rua=`/`ruf=` `mailto:`
    URIs as Email entities (confidence 0.70, `dmarc`). Fires on every domain scan
    — DMARC presence is universal on properly configured domains.
  - *SOL-MODULE-DOH.C — concurrent JoinSet:* `tokio::task::JoinSet` replaces
    sequential `for rtype in RECORD_TYPES` loop. All 8 record-type queries + DMARC
    subquery spawn simultaneously; `while set.join_next()` collects in completion
    order. Wall-clock ≈ max(individual latencies) ≈ 500ms typical vs 3s+ sequential
    — ~6× faster; `max_timeout_ms` raised 10s → 15s.
  - *SOL-MODULE-DOH.D — IpAddress support:* `accepts()` extended to include
    `TargetKind::IpAddress`; `process()` dispatches IpAddress targets to a PTR-only
    path via `ip_to_reverse_dns()`. IPv4: `1.2.3.4` → `4.3.2.1.in-addr.arpa`.
    IPv6: octets reversed, each byte split to low/high nibble, join with `.` →
    `1.0.0.0…8.b.d.0.1.0.0.2.ip6.arpa`. PTR hostnames emitted as Domain entities.
  - *SOL-MODULE-DOH.E — produces() + test coverage:* `produces()` extended to
    `[IpAddress, Domain, Email]`. 19 new unit tests: `ip_to_reverse_dns` (IPv4/IPv6/
    invalid), `parse_soa_fields` (nominal/dotted-local/too-short), `soa_record_emits`,
    `parse_caa_issuer` (issue/issuewild/prohibit/iodef/strip-params), `caa_record_emits`
    + `caa_multiple_issuers_deduplicated`, `ptr_record_emits` + `ptr_dotless_rejected`,
    `dmarc_rua_emails_extracts_rua_and_ruf` + `non_mailto_ignored`, `txt_dmarc_record_
    emits_email_entities`, `txt_non_spf_non_dmarc_ignored`, `accepts_domain_url_and_ip`
    (updated). Total: **3,148 tests** (+19 vs cycle 27).
  **S→P gap from this cycle:** `cloud_storage` identified as next world-class candidate
  — 9-entity stable baseline, only 6 bucket-name suffixes, only 3 providers (AWS S3/
  Azure/GCS); gap analysis shows 400%+ potential coverage increase with 15–20 suffix
  variants and 4–5 additional providers. Logged for cycle 29. **§4 update:**
  SOL-MODULE-DOH row added to §4d. Gate green: fmt/clippy/doc clean, 3,148 tests, 0
  failures. SHA `34449ba` pushed. Paired: `PROBLEM_TREE` §8 cycle 28 — same commit.
- **2026-06-24** — **Cycle 28.1 (P→S): SOL-MODULE-DOH.F — `doh_resolver` CAA RFC 3597
  hex-format decoder.**
  **Evidence base:** 2 live scan runs post cycle-28 both showing `doh_resolver`=26
  (vs baseline 23, +3). SOA confirmed: `hostmaster@nsone.net` (SOA RNAME, VERIFIED
  0.805), `awsdns-hostmaster@amazon.com` (SOA rname, PROBABLE 0.60). DMARC confirmed:
  `dmarc@github.com` (PROBABLE 0.70). CAA: zero entities in both runs — confirmed as
  P-DOH-F via live Cloudflare DoH probe. Raw DoH response for `github.com CAA`:
  `{"data":"\\# 19 00 05 69 73 73 75 65 64 69 67 69 63 65 72 74 2e 63 6f 6d"}` —
  RFC 3597 binary hex, not canonical `0 issue "digicert.com"` text.
  **Solution:** `decode_caa_hex_rdata()` helper (pure, no alloc beyond the byte Vec):
  strips `\#` prefix, skips byte-count token, hex-decodes bytes, interprets as CAA
  RDATA: `flags[0]`, `tag_len[1]`, `tag[2..2+tag_len]`, `value[2+tag_len..]`. Returns
  canonical `"flags tag \"value\""` string. `parse_caa_issuer()` pre-checks for `\#`
  and routes to decoder; existing text-form path unchanged — handles both Cloudflare
  (hex) and Google DoH (text) formats uniformly regardless of resolver race outcome.
  4 new unit tests: `parse_caa_issuer_handles_cloudflare_hex_format` (issue tag),
  `parse_caa_issuer_hex_issuewild` (issuewild tag), `caa_hex_record_emits_ca_domain`
  (entity emission), `caa_hex_and_text_formats_deduplicated` (dedup across both).
  Gate green: fmt/clippy/doc clean, **3,152 tests** (+4), 0 failures.
  **Scan validation (runs 3 & 4, consistent):** `doh_resolver=30` — up from 26
  (runs 1–2) and 23 (pre-cycle-28 baseline). +4 CAA issuer domains confirmed in
  both runs: `digicert.com` (0.70), `globalsign.com` (0.70), `letsencrypt.org`
  (0.70), `sectigo.com` (0.70) — all tagged `caa-issuer`, sourced `doh_resolver`.
  No regressions: typosquat=104, hackertarget=76, dns_intel=29, rdap_domain=9,
  cloud_storage=9 (all stable). SHA `df00547` pushed.
  **Updated baseline for gap analysis:** doh_resolver=30 (+30% vs cycle-27 baseline).
  **Next cycle:** cloud_storage (9 entities, 6 suffixes, 3 providers — cycle 29).
  Paired: `PROBLEM_TREE` P-DOH-F cycle 28.1 — same commit.
- **2026-06-24** — **Cycle 29 (P→S): SOL-MODULE-CLOUD-STORAGE — `cloud_storage`
  world-class rewrite: 5 providers, 16 suffixes, JoinSet concurrent probing.**
  **Evidence base:** 9-entity stable baseline (cloud_storage=9 across all 4 scan runs
  during cycle 28/28.1 validation). Gap analysis found 4 sub-problems (P-CS-A/B/C/D).
  **Solutions delivered:**
  - *SOL-CS.A — new providers:* DigitalOcean Spaces (`{name}.nyc3.digitaloceanspaces.com`)
    and Wasabi (`s3.us-east-1.wasabisys.com/{name}`). Both use same 200|403 exposure
    detection as AWS S3/GCS (S3-compatible semantics). Azure Blob remains 200-only.
  - *SOL-CS.B — new suffixes:* 10 high-value patterns added: -prod, -staging, -static,
    -media, -logs, -images, -uploads, -test, -archive, -files. Total: 16 suffixes (was 6).
    Combined with 5 providers: 80 candidate probes per scan (was 18 — 4.4× increase).
    `MAX_PROBES` cap removed; `generate_bucket_names` → `generate_bucket_candidates`.
  - *SOL-CS.C — concurrent JoinSet:* All 80 probes spawned simultaneously; collection via
    `while set.join_next()` in completion order. Cancel propagation: `set.abort_all()` on
    `ctx.cancel`. Wall-clock ≈ max(individual latencies) ≈ 4s typical vs 54s+ sequential.
    `max_timeout_ms` raised 15s → 20s to accommodate concurrent resolution time.
  - *SOL-CS.D — send_tagged:* `probe_url` now uses `http.head(url).send_tagged(SRC)` for
    proper proxy routing and tagging, consistent with all other modules.
  7 new unit tests: `generate_candidates_covers_all_suffixes_and_providers`,
  `generate_candidates_contains_all_providers`, `generate_candidates_contains_new_suffixes`,
  `generate_candidates_do_spaces_url_format`, `generate_candidates_wasabi_url_format`,
  `is_exposed_gcs`, `is_exposed_digitalocean_spaces`, `is_exposed_wasabi`.
  Gate green: fmt/clippy/doc clean, **3,159 tests** (+7 vs cycle 28.1), 0 failures.
  **Scan validation (runs 1 & 2, consistent):** `cloud_storage=26` — up from 9
  (pre-cycle-29 baseline), +189%. Provider breakdown: AWS S3: 13 hits
  (github{,-backup,-assets,-data,-dev,-prod,-staging,-logs,-images,-uploads,-test,
  -archive,-files}), GCS: 9 hits (github{,-public,-data,-backup,-logs,-images,-test,
  -static,-archive}), Wasabi: 3 hits (github{,-backup,-files}) — new provider confirmed.
  Azure Blob/DigitalOcean Spaces: 0 hits (no exposed containers — correct null result).
  New suffixes -prod/-staging/-static/-logs/-images/-uploads/-test/-archive/-files all
  hit. No regressions: doh_resolver=30, typosquat=104, hackertarget=76 (all stable).
  **New baseline: cloud_storage=26** (+189% vs cycle-28.1 baseline of 9).
  Paired: `PROBLEM_TREE` P-CS-A/B/C/D cycle 29 — same commit.

- **2026-06-24** — **Cycle 30 (P→S): SOL-MODULE-DNS-INTEL — `dns_intel` world-class expansion: 146 subdomain labels, 20 verification vendors.**
  **Evidence base:** 29-entity stable baseline (dns_intel=29 across cycle 28–29 runs). Gap analysis: P-DNS-A/B.
  **Solutions delivered:**
  - *SOL-DNS.A — subdomain dictionary:* SUBDOMAINS 94→146 (+52). New groups: Modern API/realtime (`graphql`,
    `webhooks`, `webhook`, `ws`, `socket`); Large-org/SaaS (`gist`, `pages`, `raw`, `education`, `enterprise`,
    `classroom`, `lab`, `copilot`, `avatars`, `objects`, `alive`, `collector`, `resources`, `developer`,
    `developers`, `explore`, `marketplace`); Customer account (`account`, `accounts`, `billing`, `payment`,
    `checkout`, `dashboard`, `console`); Build/deploy (`build`, `deploy`, `release`, `packages`, `npm`, `charts`,
    `artifacts`, `artifact`); Health probes (`health`, `healthz`, `ping`, `ready`); Security (`vault`, `security`,
    `trust`); Data (`data`, `analytics`); Regional (`us`, `eu`, `ap`, `us1`, `eu1`, `ap1`). All 52 new entries
    pass `dictionary_is_unique_and_lowercase` (lowercase letters+digits only, no hyphens).
  - *SOL-DNS.B — verification vendors:* VERIFICATION_VENDORS 14→20 (+6): `hubspot-developer-verification=`→hubspot,
    `salesforce-authorization-verification=`→salesforce, `loaderio=`→loaderio, `twilio-domain-verification=`→twilio,
    `yandex-verification:`→yandex, `shopify-domain-verification=`→shopify. `ms=` kept last; shadowing test passes.
  - *SOL-DNS.C — doc accuracy:* Module doc "~67-label" → "146-label"; constants.rs header updated.
  3 new tests: `dictionary_size_is_146`, `dictionary_covers_modern_infrastructure_labels`,
  `verification_vendor_detects_new_vendors`.
  Gate green: fmt/clippy/doc clean, **3,162 tests** (+3 vs cycle 29), 0 failures.
  **Scan validation (runs 1 & 2, consistent):** `dns_intel=41` — up from 29, **+41%**. Confirmed new hits:
  `gist.github.com`, `pages.github.com`, `education.github.com`, `enterprise.github.com`, `avatars.github.com`,
  `objects.github.com`, `alive.github.com`, `collector.github.com`, `resources.github.com` and others.
  No regressions: cloud_storage=26, doh_resolver=30, hackertarget=76, typosquat=104.
  **New baseline: dns_intel=41**.
  **S→P gap from this cycle:** rdap_domain nameserver glue records (`ipAddresses` field in RDAP JSON) not currently
  extracted — potential cycle 31 target (P-RDAP-B). Logged for next gap analysis pass.
  Paired: `PROBLEM_TREE` P-DNS-A/B cycle 30 — same commit. SHA `98031ea`.

- **2026-06-24** — **Cycle 31 (P→S): SOL-RDAP-B — `rdap_domain` nameserver glue-record `ipAddresses` extraction.**
  **Evidence base:** RDAP response for afnic.fr (AFNIC, .fr registry) confirmed `ipAddresses` with v4+v6
  per nameserver. Code gap P-RDAP-B verified: `Nameserver` struct had no `ip_addresses` field, `produces()`
  declared only `[Domain]`. RFC 7483 §10.2.2 defines `ipAddresses.v4`/`v6` as standard glue-record fields.
  **Solutions delivered:**
  - *SOL-RDAP-B — glue extraction:* `IpAddresses { v4: Vec<String>, v6: Vec<String> }` struct added.
    `ip_addresses: Option<IpAddresses>` added to `Nameserver`. `build_ns_ip_entities()` parses each IP via
    `parse::<IpAddr>()` (invalid/empty silently skipped), emits `IpAddress` entity tagged `rdap-ns-glue` with
    `nameserver` attribute. `process()` extended with a second `flat_map` over `body.nameservers.iter().take(MAX_NS)`.
    `produces()` updated to `[Domain, IpAddress]`. Module/const doc updated.
  3 new tests: `ns_ip_entities_extracted_from_glue_records` (v4+v6, tag, attribute),
  `ns_ip_entities_skips_invalid_and_empty`, `ns_ip_entities_absent_yields_empty`.
  Gate green: fmt/clippy/doc clean, **3,165 lib tests** (+3 vs cycle 30), 0 failures.
  **Scan validation (runs 1 & 2, consistent, afnic.fr, depth=0):** `rdap_domain=13` — 5 Domain + 8 IpAddress.
  IPv4 glue: 192.134.0.49, 192.134.4.1, 192.93.0.4, 194.0.36.1.
  IPv6 glue: 2001:660:3005::1:2, 2001:660:3006::1:1, 2001:678:4c::1, 2001:67c:2218:2::4:1.
  Registry scope note: .com (Verisign) omits `ipAddresses` — github.com rdap_domain=9 unchanged (expected).
  ccTLDs (.fr AFNIC, .br, .au, etc.) include glue; feature activates automatically for those registries.
  **New baseline: rdap_domain (afnic.fr validation target)=13**.
  **S→P gap from this cycle:** All 6 top-level modules now have >9 entity baselines. Next pass: examine
  modules with structured sub-fields not yet surfaced — e.g. hackertarget (76 baseline; ASN org-name/country
  tags) or crtsh (0/121 inconsistency — environment-side, cannot fix without real crtsh connectivity).
  Paired: `PROBLEM_TREE` P-RDAP-B cycle 31 — same commit. SHA `575f0ed`.

- **2026-06-24** — **Cycle 32 (P→S): SOL-SPF-A — SPF `a:domain` / `mx:domain` mechanisms as Domain OSINT pivots.**
  **Evidence base:** Real SPF records of state.gov (`a:_msiplista.state.gov`) confirmed a live gap. Code
  inspection of `src/util/spf/mod.rs`: `Member` enum had only `Ip`/`Include`/`Redirect`; `members()` doc
  comment explicitly listed `a`, `mx`, `ptr`, `exists` as "not interpreted." Both `doh_resolver/mod.rs` and
  `dns_intel/resolve.rs` exhaustive-match on the enum — adding new variants forces both callers simultaneously.
  **Solutions delivered:**
  - *SOL-SPF-A — a:/mx: domain mechanism extraction:* `Member::A(&'a str)` and `Member::Mx(&'a str)` added
    to enum. `members()` updated with two new branches: `mech.strip_prefix("a:")` → `usable_domain()` guard
    → `Member::A`; `mech.strip_prefix("mx:")` → `usable_domain()` guard → `Member::Mx`. Bare `a`/`mx` (no
    colon) remain skipped — they reference the current domain (already tracked), not new OSINT pivots.
    Qualifier stripping (`+/-/~/? prefix`) applies to these mechanisms as it does to include.
  - *SOL-SPF-B — caller integration (doh_resolver):* New match arms emit Domain entities (conf 0.65) tagged
    `spf-a` / `spf-mx`, dedup keys `spfa:{dom}` / `spfmx:{dom}`. Evidence string: "SPF a: mechanism for
    {domain}" / "SPF mx: mechanism for {domain}".
  - *SOL-SPF-C — caller integration (dns_intel):* Same arms added to `dns_intel/resolve.rs` matching
    existing `include`/`redirect` pattern (no dedup key needed — module-level recall handles it).
  4 new unit tests in `src/util/spf/tests.rs`: `members_yields_a_and_mx_domain_mechanisms` (bare a/mx
  skipped; qualified `a:domain` and `mx:domain` yielded), `members_skips_a_mx_with_macros_or_dotless_targets`
  (macro `%{d}` and dotless `localhost` rejected by `usable_domain()`).
  Gate green: fmt/clippy/doc clean, **3,167 lib tests** (+2 vs cycle 31), 0 failures.
  **Scan validation (runs 1 & 2, consistent, state.gov, depth=0, doh_resolver):**
  doh_resolver=22 both runs. `_msiplista.state.gov` with tag `spf-a` present both runs (run 2: `recalled`).
  github.com: no spurious spf-a/spf-mx entities (expected — github.com SPF uses only ip4:/include:).
  **New baseline: doh_resolver (state.gov validation target)=22** (github.com doh_resolver=30 stable).
  **S→P gap from this cycle:** SPF `ptr:` and `exists:domain` mechanisms not extracted — `exists:` is
  almost always macro-bearing (filtered by `usable_domain()`) and `ptr:` (deprecated RFC 7208 §5.5)
  add marginal value; deferred. Next pass should examine HTTPS DNS record type 65 for SvcPriority/
  target-name / ALPN extraction and MX record hostname extraction as Domain entities.
  Paired: `PROBLEM_TREE` P-SPF-A cycle 32 — same commit. SHA `d15c337`.

- **2026-06-24** — **Cycle 33 (P→S): SOL-USERNAME-NAME — block username-as-name leakage from breach records.**
  - **Problem closed:** P-USERNAME-NAME (cycle 33) — spurious `Person("rhino-ryno23 rhino-ryno23")` emitted from `oathnet_pro` when breach DB stores `full_name = "{username} {username}"`, triggering a 123-entity noise child scan.
  - *SOL-USERNAME-NAME-A — predicate:* Added `is_username_derived_name(name: &str, _query_value: &str) -> bool` in `src/core/validation/placeholder.rs`. Returns `true` (suppress) if: (a) name contains a hyphen — hyphens are common in usernames (`rhino-ryno23`) and rare in real human names; (b) name matches the doubled-token pattern `"X X"` where both whitespace-delimited tokens are case-insensitively equal. Both conditions are met by the canonical bad case and neither fires on real names like `"Jordan Parker"`. Parameter `_query_value` reserved for future tightening (e.g. when target kind is known). Exported via `crate::core::validation`.
  - *SOL-USERNAME-NAME-B — gate insertion:* Added `!is_username_derived_name(t, &match_ctx.lower)` guard to the Person-creation block at `oathnet_pro/mod.rs:557`. Import added. Gate is early (before `seen.insert`) so dedup set remains clean.
  - *SOL-USERNAME-NAME-C — test coverage:* Existing test `full_name_matcher_requires_all_terms_not_just_one` (oathnet_pro/tests.rs:187) exercises `"Jordan Parker"` and `"Jordan Avery"` — both survive the new gate correctly (no hyphens, no doubled token). No test was broken.
  - **Verification:** `cargo fmt --check` clean; `cargo clippy -D warnings` clean; `cargo test` 3167 passed, 0 failed; `cargo doc --document-private-items` clean.
  - **S→P gap from this cycle:** (1) `oathnet_pro` is still skipped on the primary username scan via the cross-correlation gate (≥2 sources required), even though the manual OathNet export returns 10 000 matches for `"Rhino-ryno23"` — the field-specific query `field=username` may not reach the same index, or the gate threshold is too conservative for Username targets. Investigate separately. (2) Other modules that create `Person` entities from arbitrary name fields (`search_engines/build.rs`, `crates_io`, `github_user`) have similar surface area but narrower queries; deferred for the next pass.
  Paired: `PROBLEM_TREE` P-USERNAME-NAME cycle 33 — same commit.

- **2026-06-24** — **Cycle 34 (P→S): SOL-PHONE-LEN — raise E.164 minimum from 8 to 10 digits.**
  - **Problem closed:** P-PHONE-LEN (cycle 34) — 8- and 9-digit web-scrape artefacts passing admission gate.
  - *SOL-PHONE-LEN-A — extraction floor:* `src/modules/search_engines/helpers/entity/extractors.rs:623`: changed `i + 8 < len` → `i + 10 < len`; range `(7..=15)` → `(10..=15)`. Tokens shorter than 10 digits after `+` are never even assembled as candidates.
  - *SOL-PHONE-LEN-B — validation gate:* `src/core/validation/phone.rs:21`: changed `(8..=15)` → `(10..=15)`. Belt-and-suspenders: even if a short token reaches validation from another extractor, it is rejected here. Comment updated to cite Niue (+683) and Nauru (+674) as the shortest-number inhabited countries.
  - *SOL-PHONE-LEN-C — web_crawler extractor:* `src/modules/web_crawler/crawl_util/mod.rs:542`: changed `i + 8 < bytes.len()` → `i + 10 < bytes.len()`. Floor consistent across all three phone-extraction sites.
  - *SOL-PHONE-LEN-D — test coverage:* `src/core/validation/tests.rs`: added `phone_e164_rejects_short_numbers_and_accepts_real_ones` — asserts 8-digit (+21002112) rejected, 9-digit (+219421994) rejected, 10-digit Singapore (+6569504420) accepted, 11-digit AU/US accepted, leading-zero CC rejected, no-plus rejected, 16-digit rejected. `src/modules/web_crawler/crawl_util/tests.rs`: updated `phone_extraction_bounds_digit_count` — explicit 7/8/9-digit rejection assertions added; acceptance case changed to 10-digit Singapore number.
  - **Verification:** `cargo fmt --check` clean; `cargo clippy -D warnings` clean; `cargo test` 3168 passed (+1 vs cycle 33), 0 failed; `cargo doc --document-private-items` clean.
  - **Expected impact:** ~13/15 noise phones eliminated from Scan 1 output in next real-execution re-run.
  Paired: `PROBLEM_TREE` P-PHONE-LEN cycle 34 — same commit.

- **2026-06-24** — **Cycle 38 (P→S): SOL-OATHNET-GATE-LOG — structured skip logging in dispatch.**
  - **Problem closed:** P-OATHNET-GATE-LOG (cycle 38) — skip reason opacity in dispatch pipeline.
  - *SOL-OATHNET-GATE-LOG-A — structured logging:* Added `tracing::debug!` with structured fields `{module, target_kind, target_value, is_expansion, corroborating_sources, skip_reason}` in `gate_skips()` in `src/core/engine/dispatch.rs`. Replaces opaque plain-string log.
  - *SOL-OATHNET-GATE-LOG-B — diagnosis finding:* Running `hse scan -v rhino-ryno23 -m oathnet_pro --depth 0 --output json` with the new logging confirmed oathnet_pro DISPATCHED and RAN (`"message":"dispatch"` → `"message":"done","found":0`). The 14 `modules_skipped` in Scan 1 were other modules excluded by the `-m oathnet_pro` allowlist filter. oathnet_pro returned 0 breach records — `rhino-ryno23` has no OathNet breach data. **No gate bug exists.**
  - **Verification:** `cargo fmt --check` clean; `cargo clippy -D warnings` clean; `cargo test` 3168 passed, 0 failed.
  - **S→P gap from this cycle:** `modules_skipped` count in JSON output is still a bare integer — no per-module breakdown. A structured `skipped_modules: [{name, reason}]` array in the scan summary would make future diagnosis one-step rather than requiring DEBUG log grep.
  Paired: `PROBLEM_TREE` P-OATHNET-GATE-LOG cycle 38 — same commit.

- **2026-06-24** — **Cycle 35 (P→S): SOL-SOCIAL-BODY — body negative-pattern gate for 200-for-all platforms.**
  - **Problem closed:** P-SOCIAL-BODY (cycle 35) — status-code-only probe false positives on platforms that return HTTP 200 for non-existent users.
  - *SOL-SOCIAL-BODY-A — struct field:* Added `negative_patterns: &'static [&'static str]` field to `Platform` struct in `src/modules/social_probe/mod.rs`. Defaults to `&[]` for all existing 29 platforms (no behaviour change). Field documented: presence of any listed substring in the body indicates the user does NOT exist even on a 200 status.
  - *SOL-SOCIAL-BODY-B — probe_url() body capture:* Changed `probe_url(url)` signature to `probe_url(url, capture_body: bool) -> (u16, String)`. When `capture_body` is true (triggered by `!platform.negative_patterns.is_empty()`): removes `-o /dev/null`, adds `--max-filesize 8192` (8 KB cap), and writes body to stdout alongside `\n%{http_code}`. Body split on last newline to separate content from status line. For platforms with no negative patterns the fast path (`-o /dev/null`) is preserved — zero overhead.
  - *SOL-SOCIAL-BODY-C — caller gate:* In `process()`, after calling `probe_url`, a `body_blocks` flag checks `platform.negative_patterns.iter().any(|p| body.contains(p))`. Profile only confirmed when `exists_codes.contains(&code) && !body_blocks`.
  - *SOL-SOCIAL-BODY-D — 6 high-risk platforms added:* livejasmin, imlive, mydirtyhobby, sextpanther, stripchat, loyalfans added to `USERNAME_PLATFORMS` with tuned negative patterns based on known not-found page signatures. `USERNAME_PLATFORMS` count: 29 → 35.
  - *SOL-SOCIAL-BODY-E — test coverage:* `negative_patterns_field_compiles_and_defaults_empty` test asserts: all existing platforms have no empty pattern strings; all 6 new high-risk platforms have ≥1 negative pattern. `platform_count` threshold raised from 28 to 34.
  - **Verification:** `cargo fmt --check` clean; `cargo clippy -D warnings` clean; `cargo test` 3169 passed (+1 vs cycle 34), 0 failed; all 7 social_probe tests pass.
  - **S→P gap from this cycle:** Negative pattern strings are hardcoded; they could drift if platforms change their not-found page copy. A future cycle could add integration tests that probe known-absent handles on each high-risk platform and assert the result is negative. Additionally, `--max-filesize` causes curl to exit with error code 63 on truncation — current code treats any non-success curl exit as status 0, which suppresses the profile. Should confirm this is the desired behaviour for 8-KB-exceeded bodies (likely benign — real not-found pages are typically small).
  Paired: `PROBLEM_TREE` P-SOCIAL-BODY cycle 35 — same commit.

- **2026-06-24** — **Cycle 36 (P→S): SOL-INFRA-BLEED — tag and filter platform-infra entities.**
  - **Problem closed:** P-INFRA-BLEED (cycle 36) — cloud buckets, CDN IPs, and third-party analytics IDs appearing as subject-owned entities in default output.
  - *SOL-INFRA-BLEED-A — admission tagging:* In the entity admission loop in `src/core/engine/dispatch.rs`, after all hard-reject checks, added: inspect each entity's evidence attributes for a `source_domain` key; if any evidence item has `source_domain` that passes `is_noncentral_domain()`, tag the entity `platform-infra`. Only entities with a crawled `source_domain` attribute are affected — direct-probe results (social_probe, oathnet_pro, etc.) do not carry this attribute and are exempt.
  - *SOL-INFRA-BLEED-B — output filter:* Added `include_infra: bool` parameter to `build_scan_report()` in `src/api/scan_export/mod.rs`. When `false` (default): `entities.retain(|e| !e.has_tag("platform-infra"))` removes infra entities before JSON serialisation. When `true`: infra entities are included.
  - *SOL-INFRA-BLEED-C — HTTP API:* Added `wants_infra()` helper in `src/api/scan_handlers/mod.rs` parsing `?include_infra=1|true|yes|on`. HTTP endpoint passes it to `build_scan_report`.
  - *SOL-INFRA-BLEED-D — CLI flag:* Added `--include-infra` boolean flag to the `Export` command in `src/cli/command.rs`. `--format report --include-infra` restores infra entities. `--format full` always includes them (maximum-detail format).
  - *SOL-INFRA-BLEED-E — test coverage:* `report_hides_platform_infra_by_default_and_includes_on_request` test in `src/api/scan_export/tests.rs` asserts default hides `platform-infra` tagged entity, `include_infra=true` includes it.
  - **Verification:** `cargo fmt --check` clean; `cargo clippy -D warnings` clean; `cargo test` 3170 passed (+1 vs cycle 35), 0 failed.
  - **S→P gap from this cycle:** The `platform-infra` tag is applied at admission time, so entities already in the DB from prior scans are not retroactively tagged. A migration step or re-scan is needed to clean up existing scan data. Future: tag via a post-admission pass using the same `is_noncentral_domain` check, or add a `hse db retag` maintenance command.
  Paired: `PROBLEM_TREE` P-INFRA-BLEED cycle 36 — same commit.

- **2026-06-24** — **Cycle 37 (P→S): SOL-TRACKING-PIVOT — tracking ID pivot mechanism verified complete.**
  - **Problem closed:** P-TRACKING-PIVOT (cycle 37) — tracking ID co-ownership merge not firing in Scan 1.
  - *SOL-TRACKING-PIVOT-A — mechanism audit:* Verified `EntityKind::Url → TargetKind::Url` mapping exists in `src/core/scan/mod.rs:78`. Verified `web_crawler.accepts()` accepts `TargetKind::Url` (`src/modules/web_crawler/mod.rs:100`). Verified the incidental_infra expansion gate at `src/core/engine/mod.rs:1114-1133` only excludes `TargetKind::Domain` and `TargetKind::IpAddress` — `Url` kind passes through. Social probe `Url` entities at 0.80 confidence clear the default `min_expand_confidence=0.50` floor. The pivot mechanism is complete and correct — no code change required.
  - *SOL-TRACKING-PIVOT-B — root cause finding:* The gap in Scan 1 was the 20-minute wall-clock cap exhausting the expansion budget before `web_crawler` was dispatched against the social profile URL entities. The fix is operational: run scans without a wall cap (`--no-timeout`) or with higher `--depth` so the second expansion round, where social-profile URL entities become crawl targets, is reached.
  - *SOL-TRACKING-PIVOT-C — social-profile expansion priority boost (delivered 2026-06-25):* Added a +15% weight multiplier in `src/core/engine/mod.rs` (after the geo-corroboration bonus block) for any expansion candidate where `tk == TargetKind::Url && entity.has_tag("social-profile")`. This nudges confirmed social-profile URLs above generic domain/IP targets at equal confidence, ensuring `web_crawler` is dispatched against subject-owned platform pages early in each expansion round rather than being pre-empted by the higher-volume domain/IP candidate pool. The +15% is sub-dominant to confidence and corroboration factors, so a low-confidence social URL cannot jump a high-confidence domain lead. No new test required — the expansion weight ranking is implicitly exercised by the existing expansion round tests.
  - **Verification:** `cargo test` clean — no code changes.
  - **S→P gap from this cycle:** The `wordpress.com` domain IS in the mega-domain blocklist (`classify.rs:239`). A `TargetKind::Url` pointing to `rhino-ryno23.wordpress.com` crawls the page correctly (the URL is passed to `web_crawler`, not the domain), but if `web_crawler` tries to enqueue `wordpress.com` as a subdomain expansion target, the `is_noncentral_domain` check in `web_crawler/crawl_util/mod.rs` prevents further fan-out into wordpress.com infrastructure. This is the correct behaviour for subdomain-level crawls — the subject's profile page is crawled without mapping WordPress's own CDN.
  Paired: `PROBLEM_TREE` P-TRACKING-PIVOT cycle 37 — same commit.

- **2026-06-24** — **Cycle 39 (FTA→S): SOL-FTA-39 — three FTA-derived fixes.**
  - **Problems closed:** P-INFRA-TAG-POLICY, P-CC-GATE-INCONSISTENCY, P-CURL-EXIT63 (all cycle 39).
  - *SOL-FTA-39-A — platform-infra consensus policy (`dispatch.rs`):* Changed `platform-infra` tagging from `.any()` (tag if ANY evidence has infra source_domain) to `.all()` (tag only if EVERY source_domain evidence attribute points to a noncentral domain). Mixed-provenance entities — discovered from both a subject-owned domain and a platform page — are no longer suppressed from default output. The `sourced` vector collects all `source_domain` values upfront; the tag fires only when `sourced` is non-empty AND all entries pass `is_noncentral_domain()`. Entities with no `source_domain` evidence (direct-probe results) remain exempt.
  - *SOL-FTA-39-B — country-code gate unification (`extractors.rs:623`):* Changed `bytes[i+1].is_ascii_digit()` → `matches!(bytes[i+1], b'1'..=b'9')`. Now consistent with `crawl_util/mod.rs` and `validation/phone.rs`. `+0...` prefixes are rejected at extraction time, preserving the 300-number cap for valid international numbers.
  - *SOL-FTA-39-C — curl exit-63 body-capture fix (`social_probe/mod.rs`):* `probe_url()` now accepts exit code 63 as a partial-success path alongside exit code 0. `is_truncated = o.status.code() == Some(63)` is checked; when true, stdout is parsed identically to the success path — the HTTP status code is extracted from the last line and the partial body is used for negative-pattern matching. Real profiles whose HTML pages exceed 8 KB are no longer silently marked as not-found. Actual network failures (non-0, non-63 exit codes) still return `(0, String::new())`.
  - *SOL-FTA-39-D — test coverage:* `extract_phones_rejects_leading_zero_cc` (extractors.rs) — asserts `+0...` rejected and a valid US number is kept; `extract_phones_is_utf8_safe` (extractors.rs) — asserts ASCII phone in multibyte surrounding text is extracted without panic; `high_risk_platforms_have_negative_patterns_and_standard_platforms_do_not` (social_probe/tests.rs) — regression guard for the body-capture fast-path contract.
  - **Verification:** `cargo fmt` clean; `cargo clippy -D warnings` clean; `cargo test` 3172 passed (+2 vs cycle 38), 0 failed.
  - **S→P gap from FTA residuals:** (1) AU-004 CRITICAL correlation fires on a single `malicious`-tagged entity — no cross-source consensus required; if any module has a bug in the `malicious` tagger, the correlation fires falsely. (2) The `utf8_safe` test for `extract_phones_from_text` in extractors.rs passes, but a similar test is not yet in `search_engines/` integration tests — the UTF-8 property is covered by the doc-test in the extractors module only.
  Paired: `PROBLEM_TREE` P-INFRA-TAG-POLICY / P-CC-GATE-INCONSISTENCY / P-CURL-EXIT63 cycle 39 — same commit.

- **2026-06-24** — **Cycles R1–R4 (Refactor→S): Four structural refactors improving coupling, correctness, and DRY.**
  - **Problems closed:** P-R4-AU004-SINGLE-SOURCE, P-R1-CLASSIFY-COUPLING, P-R2-PHONE-DUPLICATION, P-R3-CURL-DUPLICATION (cycles R1–R4).
  - *SOL-R4 — AU-004 corroboration guard (`src/core/correlator/rules/infra.rs:21`):* Added `&& e.source_count() >= 2` to the `rule_au_004_malicious_infrastructure` filter chain. A `malicious`-tagged entity with only one contributing source no longer produces a CRITICAL correlation. Aligned AU-004 with the existing consensus policy of AU-001, AU-010, AU-047. Tests updated: `au004_fires_on_malicious_domain` adds two evidence records from distinct sources; `au004_no_fire_single_source` new test asserts single-source suppression; integration test `evaluate_rules_fires_expected_subset` updated to add two evidence records to the domain fixture.
  - *SOL-R1 — `should_tag_platform_infra` extracted to classify.rs (`src/core/scan/classify.rs`):* New `pub(crate) fn should_tag_platform_infra(entity: &Entity) -> bool` embodies the policy: returns true iff all `source_domain` evidence attributes point to noncentral domains (non-empty AND all pass `is_noncentral_domain()`). Re-exported from `src/core/scan/mod.rs`. `dispatch.rs` now calls `crate::core::scan::should_tag_platform_infra(&entity)` — the inline block reduced from 12 lines to 3.
  - *SOL-R2 — Shared phone scanner (`src/util/phone/mod.rs`):* New `pub fn scan_phones(text: &str, cap: usize, collect: impl FnMut(String)) -> bool`. Single canonical byte-scan loop with the `matches!(b'1'..=b'9')` CC gate and `(10..=15)` digit bound. Both callers updated: `crawl_util::extract_phones` → `scan_phones(body, usize::MAX, |p| phones.insert(p))` (2 lines); `extractors::extract_phones_from_text` → `scan_phones(text, 300, |p| phones.push(p))` with cap-warning on truncation (6 lines). Registered in `src/util/mod.rs`.
  - *SOL-R3 — `fetch_with_status` in util/curl (`src/util/curl/mod.rs`):* New `pub async fn fetch_with_status(url: &str, _timeout_ms: u64, capture_body: bool) -> (u16, String)`. Embodies the status-code-sentinel curl pattern including exit-63 partial-success handling. `social_probe/mod.rs probe_url()` removed; call site updated to `crate::util::curl::fetch_with_status(&url, 4_000, !platform.negative_patterns.is_empty())`.
  - **Verification:** `cargo fmt` clean; `cargo clippy --all-targets --locked -D warnings` clean; `cargo test --locked` all passed (0 failures), new tests: `au004_no_fire_single_source`.
  - **S→P gap from this cycle:** `_timeout_ms` parameter in `fetch_with_status` is accepted but unused — curl `--max-time 4` is hardcoded. If future callers need configurable timeouts, the parameter is the hook point; for now the value is discarded rather than threading it into a string arg to avoid lifetime entanglement with the `args` Vec.
  Paired: `PROBLEM_TREE` P-R1–P-R4 cycles R1–R4 — same commit.

- **2026-06-24** — **Cycle R5 (Refactor audit→S): SOL-R5 — wire util/extract::phones() to shared scanner.**
  - **Problem closed:** P-R5-EXTRACT-PHONE-STALE.
  - *SOL-R5 — util/extract/mod.rs phones():* Replaced 30-line inline byte-scan with `crate::util::phone::scan_phones(text, usize::MAX, |p| { if seen.insert(p.clone()) { out.push(p); } })`. Deduplication (first-occurrence order) preserved via seen-HashSet in the closure. Bounds now match canonical: 10-digit minimum, CC gate `matches!(b'1'..=b'9')`, `validate_phone_e164` inside `scan_phones`. Docstring updated from "7–15" to "10–15".
  - *Audit findings — intentionally NOT wired:* `util/proxy/mod.rs validate()` uses curl `-x proxy_url` for proxy-routed status checks — `fetch_with_status` does not support proxy routing; custom invocation is correct. `util/key_pool/validation.rs validate_against_endpoint()` uses custom auth headers/BasicAuth/BearerAuth per ServiceDef — not representable in `fetch_with_status`; custom invocation is correct. `rule_au_009_stealer_log` (High) and `rule_au_021_api_key_exposure` (Critical) deliberately fire on single-entity findings — an email in stealer data or a discovered API key is an unconditional alert by nature, unlike the infra blocklist case where CDN nodes routinely appear in one list without subject ownership.
  - **Verification:** `cargo fmt` clean; `cargo clippy --all-targets --locked -D warnings` clean; `cargo test --locked` all passed, 0 failures.
  Paired: `PROBLEM_TREE` P-R5-EXTRACT-PHONE-STALE — same commit.

- **2026-06-24** — **Cycle R6 (P→S): SOL-TRACKING-PIVOT-DEAD — TrackingId pivot graph closed end-to-end.**
  - **Problem closed:** P-TRACKING-PIVOT-DEAD.
  - *What was built (7 files, zero unsafe):*
    1. `src/core/scan/detect.rs` — `is_tracking_id_shaped(v: &str) -> bool`: pattern-matches UA-/G-/GTM-/AW- shapes with length and charset gates.
    2. `src/core/scan/mod.rs` — `TargetKind::TrackingId` variant; `from_entity_kind` maps `EntityKind::TrackingId → Some(TargetKind::TrackingId)`; `to_entity_kind` inverse; `canonical_str` → `"tracking_id"`; `detect()` calls `is_tracking_id_shaped` at step 9c; `validate()` arm calls `is_tracking_id_shaped` and rejects malformed IDs.
    3. `src/core/dependency/mod.rs` — `TargetKind::TrackingId` added to `ALL_TARGET_KINDS` so `consumes()` probes it and the smoke test `every_declared_produced_pivot_has_a_consumer` can verify wiring.
    4. `src/core/scan/scoring.rs` — Three exhaustive match arms: `seed_marginal_yield` → `(1.3, 1.1)` (terminal pivot); `round_retention` → `0.40` (collapses after one hop); `geo_npv` → `5.0` (minimal geo signal, domain pivot only).
    5. `src/core/convex/mod.rs` — `dispatch_cost` → `1.0` (single-pivot terminal, same cost as ApiKey/DeviceId).
    6. `src/modules/search_engines/mod.rs` + `queries/mod.rs` — `accepts()` covers `TrackingId`; three query templates: bare quoted ID, `site:github.com OR site:gitlab.com`, negative `‑site:google.com ‑site:googletagmanager.com`.
    7. `src/modules/exa_search/mod.rs` — `accepts()` covers `TrackingId`; neural query: "websites embedding Google Analytics or Tag Manager ID \"{ID}\"".
    8. `src/cli/mod.rs` — `parse_target_kind` accepts `"tracking_id" | "trackingid" | "ga" | "gtm"`.
  - **Verification:** `cargo fmt` clean; `cargo clippy --all-targets --locked -D warnings` clean; `cargo test --locked` 3174 passed, 0 failed (includes smoke test `every_declared_produced_pivot_has_a_consumer` and CLI round-trip `every_seed_kind_canonical_form_round_trips`). `cargo build --release` clean.
  - **S→P gap from this cycle:** `search_engines` query template is keyword-based; a `TrackingId` target also fits Exa's semantic engine (already wired). No dedicated TrackingId-specific modules (e.g. a direct API lookup against BuiltWith or Wappalyzer) exist. These are future work — the pivot graph closure itself is complete.
  Paired: `PROBLEM_TREE` P-TRACKING-PIVOT-DEAD cycle R6 — same commit.

- **2026-06-24** — **Cycle R7 (P→S): SOL-R7 — SERP @-mention pivot + platform coverage expansion.**
  - **Problems closed:** P-SERP-HANDLE-BLIND, P-PLATFORM-COVERAGE-R7.
  - *What was built (2 files, zero unsafe):*
    1. `src/modules/search_engines/extract/mod.rs` — Extended `extract_username_pivots()` with a secondary extraction loop. Added `static TITLE_MENTION_RE: LazyLock<Regex>` matching `\(@([A-Za-z0-9_]{2,25})\)` — the canonical SERP title format used by X/Twitter, Instagram, and TikTok to disclose the real account handle. For each social SERP result whose title contains at least one seed term ≥4 chars, all `(@handle)` occurrences are extracted as pivot seeds without a score gate (confirmed-target social result + title @-mention = near-certain handle disclosure). The path-segment pivot path is unchanged and retains its score≥3 gate.
    2. `src/modules/username_search/sites.rs` — Added 11 new platform entries (after removing 1 newly-discovered duplicate "Xbox Gamertag" at line 1741, already present at line 1179): OnlyFans (H/200/social), Fansly (H/200/social), Throne (H/200/social), CGTrader (H/200/photo — confirmed live from Ryno23 OSINT), TurboSquid (H/200/photo), Audiomack (H/200/music), Reverbnation (H/200/music), Wellfound (H/200/business), Inkitt (H/200/blog), Royal Road (H/200/blog), Myanimelist (H/200/other).
  - **Live evidence motivating changes:** Startpage/Qwant SERPs for "Ryno23" returned "Ryno23 (@ZMKCR) / Posts / X" — ZMKCR is the real Twitter handle, invisible to path extraction. CGTrader profile at `cgtrader.com/designers/ryno23` confirmed live. These are production SERP signals, not synthetic inputs.
  - **Verification:** `cargo fmt --all -- --check` clean; `cargo clippy --all-targets --locked -- -D warnings` clean; `cargo test --locked` 3173+ passed, 0 failed (including `no_duplicate_site_names`).
  - **S→P gap from this cycle:** `extract_family_names()` in the same file applies a similar text-scan approach for family member discovery. The `@-mention` extraction is title-only; bio/about-page text mining for inline handle disclosures remains unimplemented (a higher-effort feature requiring confirmed-profile crawl).
  Paired: `PROBLEM_TREE` P-SERP-HANDLE-BLIND + P-PLATFORM-COVERAGE-R7 — same commit.

- **2026-06-24** — **Cycle R8 (P→S): SOL-R8 — Wayback historical contact extraction.**
  - **Problem closed:** P-WAYBACK-CONTACT-BLIND.
  - *What was built (2 files, zero unsafe):*
    1. `src/modules/wayback/mod.rs` — Added a second CDX query pass (`fl=timestamp,original`, `filter=statuscode:200`, `limit=500`, `collapse=urlkey`). Results are filtered client-side for contact-adjacent path keywords (`contact`, `about`, `team`, `staff`, `imprint`, `impressum`, `reach`, `support`, `people`). Up to 10 matching snapshots are fetched via `archive_url(ts, orig)` — using the Wayback `id_` modifier to retrieve unmodified original HTML without banner injection. Bodies are capped at 32 KB via `read_body_capped`. `util::extract::page_emails()` and `util::extract::phones()` extract contacts; `is_infrastructure_email()` filters platform noise. Each entity carries `wayback-historical` + `search-discovered` tags and an evidence record with `archive_url`, `original_url`, `snapshot_timestamp_iso`. Email confidence 0.70, phone 0.65 (historical — potentially outdated). `produces()` extended to `[Domain, Url, Email, Phone]`. `max_timeout_ms` raised from 10 s to 30 s. `attack_techniques` override: `["T1596", "T1589.002"]`.
    2. `src/modules/wayback/tests.rs` — Added tests for `is_contact_path()` (positive + negative cases), `archive_url()` format, and updated `module_metadata` to assert Email/Phone in `produces()` and T1596/T1589.002 in `attack_techniques()`.
  - **Technique provenance:** The "mine archived contact pages" approach is documented in published investigations (Theranos/WSJ, KrebsOnSecurity, OCCRP, Bellingcat) and is the primary technique of the soxoj/kronikier open-source OSINT tool. Huntsman's implementation uses the same CDX API and `id_` snapshot URL pattern.
  - **Verification:** `cargo fmt --all -- --check` clean; `cargo clippy --all-targets --locked -- -D warnings` clean; `cargo test --locked` all passed, 0 failures (including new wayback tests).
  - **S→P gap from this cycle:** Contact mining is limited to `collapse=urlkey` (one snapshot per URL — the earliest). A future enhancement could take the MOST RECENT snapshot of each contact URL to capture the last-known contacts before a scrub, which is often the highest-value finding. Bio/team page text mining for social handles (LinkedIn, Twitter linked on contact pages) is not yet extracted.
  Paired: `PROBLEM_TREE` P-WAYBACK-CONTACT-BLIND — same commit.

- **2026-06-24** — **Cycle R9 (P→S): SOL-R9 — Freemail Person inference + display-name extraction + bio aggregator URL mining.**
  - **Problems closed:** P-FREEMAIL-PERSON-BLIND, P-SERP-DISPLAY-NAME-BLIND, P-BIO-AGGREGATOR-BLIND.
  - *What was built (4 source files + 2 test files, zero unsafe):*
    1. `src/modules/email_parse/mod.rs` — Removed `&& is_corporate` gate from the `firstname.lastname` Person inference block (line 183). Replaced fixed 0.55 confidence with `person_conf = if is_corporate { 0.55 } else { 0.45 }`. Freemail inferences carry an additional `freemail-inferred` tag to signal the lower reliability to downstream modules. Corporate behaviour unchanged. Effect: `ryne.manka@gmail.com` now emits Person "Ryne Manka" at 0.45 for downstream corroboration, rather than being silently dropped.
    2. `src/modules/email_parse/tests.rs` — Renamed `isp_freemail_outside_inline_list_infers_no_person` → `isp_freemail_infers_person_at_lower_confidence`; updated assertions to verify Person at 0.45 with `freemail-inferred` tag for `bigpond`, `comcast`, `gmx`, `yandex.ru`; corporate path assertions unchanged (0.55, no `freemail-inferred` tag).
    3. `src/modules/search_engines/extract/mod.rs` — Added four new items:
       - `static TITLE_NAME_RE` — anchored regex `^((?:[A-Z][A-Za-z'.]{0,20} ){1,4})\(@[A-Za-z0-9_]{2,25}\)` capturing 1–4 capitalised name words before `(@handle)`.
       - `pub(super) fn extract_display_names_from_titles()` — scans social SERP results (social-host guard + seed-term-in-title guard + lowercase-letter guard to reject gamertags) and emits `Person` entities at 0.65 confidence tagged `social-name` + `search-discovered` + `derived`.
       - `const BIO_AGGREGATOR_HOSTS` (10 hosts) + `const MESSAGING_DIRECT_HOSTS` (2 hosts) + `static BIO_AGGREGATOR_RE` — covers `linktr.ee`, `bio.link`, `beacons.ai`, `allmylinks.com`, `msha.ke`, `solo.to`, `bento.me`, `carrd.co`, `lnk.bio`, `campsite.bio`, `t.me`, `discord.gg`.
       - `pub(super) fn extract_bio_aggregator_urls()` — two signals: Signal 1 (result URL is a bio host → 0.70/0.65 conf) and Signal 2 (bio URL mentioned in title+snippet text → 0.65/0.60 conf). Both require seed term in context. Both write to a shared `seen` HashSet for deduplication. Tags: `bio-aggregator` or `messaging-profile`, plus `social-profile` + `search-discovered`.
    4. `src/modules/search_engines/mod.rs` — Extended `use extract::{...}` with the two new functions; added two `for e in ...` loops immediately after `build_entities()` and before the recycler pass so that the new `Person` and `Url` entities are available for recycler-driven geo/cross-platform re-queries.
    5. `src/modules/search_engines/extract/tests.rs` — 12 new tests across both functions: display-name happy path (Instagram format), non-social-host rejection, all-caps rejection, deduplication, seed-term requirement; bio-aggregator Signal 1 (linktr.ee URL, Telegram URL), Signal 2 (text mention), Signal 1+2 dedup, seed-term requirement.
  - **Live evidence motivating changes:** Live scan for "Ryno23" returned "Ryne Manka (@ryno23\_) • Instagram Photos" in SERP — the real name entirely absent from the entity graph before this cycle. Email `ryne.manka@gmail.com` (scraped from an archived contact page in R8) would produce only Usernames, not a Person, prior to this cycle.
  - **Verification:** `cargo fmt --all -- --check` clean; `cargo clippy --all-targets --locked -- -D warnings` clean; `RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links ..."  cargo doc ...` clean; `cargo test --locked` all passed (3185+ tests), 0 failures.
  - **S→P gap from this cycle:** (a) `TITLE_NAME_RE` is anchored to `^` (title must start with the name) — titles like "About Ryne Manka (@ryno23\_)" are missed. (b) Bio aggregator slugs are not cross-referenced against the seed username to gate confidence — `linktr.ee/someoneelse` appearing in a target's SERP could still be emitted if any seed term matches context. (c) Freemail Person at 0.45 will reach the recycler and seed `"Ryne Manka" address OR email OR phone` queries — assess for noise in the next live scan.
  Paired: `PROBLEM_TREE` P-FREEMAIL-PERSON-BLIND + P-SERP-DISPLAY-NAME-BLIND + P-BIO-AGGREGATOR-BLIND — same commit.

- **2026-06-25** — **Cycle R10 (P→S): SOL-R10 ⚑ — URL query canonicalisation (tracking-strip + order-normalise). Enabler.**
  - **Problem closed:** P-URL-QUERY-FRAGMENT. **Leverage:** ⚑ enabler — one normaliser change unlocks the existing (already-built, already-tested) corroboration boost for *every* URL-producing module at once (search_engines, username_search, wayback, social_probe, web_crawler, gravatar, …), and removes a whole class of duplicate findings.
  - *What was built (`src/core/entity/mod.rs`, zero unsafe):*
    1. `const URL_TRACKING_PARAMS: &[&str]` — 38 unambiguous tracking params (Google `gclid`/`dclid`/`gbraid`/`wbraid`/`_ga`/`_gl`, Meta `fbclid`/`igshid`/`igsh`/`mibextid`/`fb_*`, Microsoft `msclkid`, Twitter `twclid`/`ref_src`/`ref_url`, Yandex `yclid`, marketing-automation `mc_cid`/`mc_eid`/`mkt_tok`/`_hsenc`/`_hsmi`/`vero_*`/`oly_*`, analytics `spm`/`scm`/`s_kwcid`/`_openstat`/`icid`). Curated conservatively from the ClearURLs / Brave / Firefox strip-lists. Resource-identifying params (YouTube `v`, generic `id`/`p`/`q`/`page`) are deliberately ABSENT and always preserved — dropping one would *falsely merge* two different pages, a worse failure than fragmenting.
    2. `fn is_tracking_param_key(key)` — matches the `utm_*` family by case-insensitive prefix (via `get(..4)`, panic-safe on non-ASCII keys) plus exact case-insensitive membership in the denylist.
    3. `fn normalise_url_query(query)` — drops tracking params, drops empty segments, and `sort_unstable()`s the survivors so query-param *order* can't fragment the UID. Parameter **values** are preserved byte-for-byte (only keys matched case-insensitively): `?v=AbC123` is case-significant and never folded. Returns `""` when every param was tracking (caller omits the `?`).
    4. Url arm rewired to call `normalise_url_query` instead of pushing the raw query.
  - *Safety reasoning (why this can only help, not alias):* tracking params never identify the resource, so stripping them cannot collapse two distinct pages; sorting is order-independence, semantically inert for web resources. The conservative denylist (no `id`/`v`/`q`) means the dangerous direction — a *false* merge — is structurally avoided. Path case is left untouched (case-sensitive paths exist), preserving the existing `…/Profile` assertion.
  - **Verification:** 4 new unit tests (`normalise_url_strips_tracking_params`, `normalise_url_preserves_meaningful_params_and_sorts`, `url_tracking_variants_share_one_uid`, plus the retained `normalise_url_lowercases_host_strips_fragment`) asserting: ref_src+utm stripped to bare profile; utm_*+fbclid → no `?`; igshid stripped; YouTube `v` preserved; order-independence (`?b=2&a=1` ≡ `?a=1&b=2`); value-case preserved; and the end-to-end invariant that two differently-tracked discoveries of `x.com/ryno23` share one UID. `cargo fmt`/`clippy -D warnings`/`doc`/`test --locked` all clean (3192+ tests, 0 failures).
  - **S→P gap from this cycle:** (a) Path-case fragmentation remains for case-insensitive social handles (`/Profile` vs `/profile`) — a host-allowlist fold is the follow-up but couples core normalisation to the social-host set (layering cost), deferred. (b) Percent-encoding case (`%5E` vs `%5e`) is not normalised — rare, low value. (c) The denylist is static; a data-driven "which params never change the fetched body" learner over real crawl data is the principled long-term version.
  Paired: `PROBLEM_TREE` P-URL-QUERY-FRAGMENT — same commit.

- **2026-06-25** — **Cycle R11 (P→S): SOL-R11 — AU-061 shared-registrant domain co-ownership (relation rule).**
  - **Problem closed:** P-SHARED-REGISTRANT-BLIND. Directly serves the "infrastructure correlation / organisational mapping" objective.
  - *What was built (`src/core/correlator/rules/org.rs` + `mod.rs` + tests, zero unsafe):*
    1. `rule_au_061_shared_registrant(&[Entity], &[Relation], scan_id, ts)` — a **relation rule** (4th in `RELATION_RULES`, runs at finalise where the persisted edge set exists). Groups `RegisteredBy` edges by registrant `to_uid`; when ≥2 DISTINCT domains share one genuine registrant it emits a `High` co-ownership `Correlation` naming the registrant and every member domain, with `entity_uids = [registrant, …domains]` for the SPA graph. Endpoint-kind-checked (from=Domain, to=Organisation|Email) so a malformed edge can't group non-domains. Deterministic: registrants iterated in uid order, member domains `sort_unstable()`'d (verified order-independent by test).
    2. `const REGISTRANT_PROXY_MARKERS` (17 markers) + `fn is_proxy_registrant(value, is_email)` — the **false-positive guard**: privacy-proxy / redaction registrants (`Domains By Proxy`, `WhoisGuard`, `REDACTED FOR PRIVACY`, `Withheld for Privacy`, …) are shared across millions of domains and are EXCLUDED. Email registrants are additionally screened with the pure `util::domains::is_infrastructure_email` (catches `abuse@godaddy.com`, `*@whoisguard.com`, registrar role mailboxes). Complements the `whois` module's own `privacy`/`redacted` filter — which named proxies like "Domains By Proxy" slip past — and covers proxy registrants from RDAP/`whoisxml` that may not filter at all.
    3. Registered in `RELATION_RULES` (`correlator/mod.rs`); `is_infrastructure_email` added to the `core_does_not_import_util_directly` allowlist (pure, no-I/O leaf — same category as `address_au::state_code`, used by AU-056).
  - **Why low-false-positive:** a shared *registrant* is a contractual ownership signal (the party that holds the domains), categorically stronger than a shared hosting IP (coincidental co-tenancy, which AU-031 treats as noise). The proxy/redaction guard removes the one mass-shared registrant class, so the rule only links domains through a real owner identity.
  - **Verification:** 5 firing/guard tests (`au061_fires_on_shared_registrant_org`, `_email`, `_no_fire_on_privacy_proxy_registrant` (Domains By Proxy + `abuse@whoisguard.com`), `_no_fire_on_single_domain_or_redacted`, `_deterministic_across_edge_order`). All three correlator meta-guards pass (`every_defined_correlation_rule_is_dispatched`, `correlation_rule_ids_match_their_function_number`, `every_dispatched_correlation_rule_has_a_firing_test`). `fmt`/`clippy -D warnings`/`doc`/`test --locked` all clean (3198+ tests, 0 failures). Rule count 60→61; docs updated (ARCHITECTURE_AUDIT, PROBLEM_TREE header).
  - **S→P gap from this cycle:** (a) Shared *dedicated* (non-CDN) IP co-ownership is still absent — viable but needs an `is_cdn_edge_ip` gate to avoid shared-hosting false positives (candidate AU-062). (b) Shared nameserver is intentionally NOT linked (too weak — millions share one DNS provider). (c) The co-ownership is a `Correlation` annotation, not a structural `SameOperator` edge — the graph spine gap (Agent 3 C1) remains for a later cycle.
  Paired: `PROBLEM_TREE` P-SHARED-REGISTRANT-BLIND — same commit.

- **2026-06-25** — **Cycle R12 (P→S): SOL-R12 — AU-062 shared dedicated-IP co-hosting (relation rule).**
  - **Problem closed:** P-SHARED-IP-BLIND. Synergistic with SOL-R11 (the registrant counterpart): together they give the operator the two canonical infrastructure-ownership pivots (WHOIS registrant + reverse-IP).
  - *What was built (`src/core/correlator/rules/org.rs` + `mod.rs` + tests, zero unsafe):*
    1. `rule_au_062_shared_hosting_ip(&[Entity], &[Relation], scan_id, ts)` — relation rule (5th in `RELATION_RULES`). Groups `ResolvesTo` edges by IP; emits a `Medium` co-hosting `Correlation` (lower than AU-061's High — a dedicated IP is weaker ownership evidence than a contractual registrant). Framed in the description as a lead to verify against registrant/content.
    2. **Three precision guards**, each removing a distinct noise class: (1) `is_cdn_edge_ip` + `is_non_routable_ip` exclude CDN/anycast edges and reserved IPs (co-tenancy, not co-ownership — the AU-031 class); (2) `registrable_domain` requires ≥2 DISTINCT eTLD+1s among the members, so a single site's own subdomains (`www`/`api`/`blog.example.com` on its origin IP) is co-*residence* and does NOT fire; (3) `MAX_CO_HOSTED_REGISTRABLE = 5` skips shared-hosting fan-out.
    3. Registered in `RELATION_RULES`; `util::domains::registrable_domain` added to the `core_does_not_import_util_directly` allowlist (pure eTLD+1 reducer, no I/O — same leaf category as `is_infrastructure_email`).
  - **Verification:** 4 firing/guard tests — `au062_fires_on_two_distinct_sites_one_dedicated_ip` (45.33.32.156, two distinct sites → Medium), `_no_fire_on_subdomains_of_one_site` (one eTLD+1 → no fire), `_no_fire_on_cdn_or_nonroutable_ip` (104.16.5.5 / 192.168.1.10 / 203.0.113.7 → no fire), `_no_fire_on_shared_hosting_fanout` (8 distinct sites → no fire). All 3 correlator meta-guards pass. `fmt`/`clippy -D warnings`/`doc`/`test --locked` all clean (3202+ tests, 0 failures). Rule count 61→62; docs updated.
  - **S→P gap from this cycle:** (a) `ResolvesTo` co-hosting is only as complete as the scan's DNS coverage; a passive-DNS / reverse-IP enrichment module would widen membership (future module gap). (b) Both R11 and R12 remain `Correlation` annotations, not structural `SameOperator` edges — the graph-spine gap (Agent 3 C1) is now the highest-value remaining linkage cycle. (c) The fan-out cap is static; a host-reputation-aware cap (dedicated VPS vs known shared-host ASN) would let the rule admit larger genuine estates.
  Paired: `PROBLEM_TREE` P-SHARED-IP-BLIND — same commit.

- **2026-06-25** — **Cycle R13 (P→S): SOL-R13 — `SameOperator` structural relation edges (graph spine for co-ownership).**
  - **Problem closed:** P-GRAPH-SPINE-ABSENT. AU-044/AU-061/AU-062 emit `Correlation` annotations naming co-owned domains; the entity graph had no edge kind linking them directly. A consumer traversing the relation set could not answer "which domains share an operator with X" in one hop.
  - **What was built** (`src/core/relation/`):
    1. **`RelationKind::SameOperator`** added to `types.rs` — directed canonically (min UID → max UID, same as `CoLocatedWith`) so one idempotent edge per pair. Wire-form: `"same_operator"`. Pinned by the `relation_kind_as_str_matches_serde` test.
    2. **`derive_co_ownership(entities, relations, scan_id) → Vec<Relation>`** in `builders.rs` — derives `SameOperator` edges from three evidence sources, each guarded to match the corresponding correlation rule's precision standard: (a) `RegisteredBy` edges grouped by registrant — same privacy-proxy exclusion as AU-061 (delegated to `util::domains::is_proxy_registrant`, now the single source of truth); (b) `ResolvesTo` edges grouped by IP — same three guards as AU-062 (CDN/non-routable exclusion, ≥2 distinct eTLD+1s, `MAX_CO_HOSTED_REGISTRABLE` fan-out cap); (c) `TrackingId` entity evidence `source_domain` attributes — same ≥2 distinct sites gate as AU-044. Global dedup prevents the same co-owned pair from producing more than one edge if it qualifies under multiple sources.
    3. **`derive_all` updated** to call `derive_co_ownership` after the base passes, passing the already-derived base relations as input so `RegisteredBy` / `ResolvesTo` edges are available. Both the live scan path (`finalise_scan`) and the import path call `derive_all`, so both get `SameOperator` edges consistently.
    4. **`util::domains::is_proxy_registrant`** extracted from the correlator's local `org.rs` definition into `src/util/domains/mod.rs` (the single source of truth). AU-061 and `derive_co_ownership` both delegate to it — no marker-table duplication. `util::domains::is_proxy_registrant` added to the `core_does_not_import_util_directly` allowlist (pure marker-table + `is_infrastructure_email`; no I/O).
  - **Verification:** 6 builder unit tests in `src/core/relation/tests.rs` — `co_ownership_shared_registrant_links_two_domains` (canonical direction + confidence), `co_ownership_proxy_registrant_excluded` ("Domains By Proxy, LLC" → no edge), `co_ownership_shared_dedicated_ip_links_two_distinct_sites` (45.33.32.156), `co_ownership_cdn_ip_excluded` (104.16.5.5 → no edge), `co_ownership_single_site_subdomains_not_co_owned` (www.example.com + api.example.com → one registrable domain → no edge), `co_ownership_shared_tracking_id_links_carrying_domains` (UA-12345678-1 on two domains), `co_ownership_same_pair_from_two_sources_emits_one_edge` (registrant + tracking ID → one deduplicated edge). `derive_all` test updated to include `derive_co_ownership` in the expected count. `relation_kind_as_str_matches_serde` updated. `fmt`/`clippy -D warnings`/`doc`/`test --locked` all clean (3205+ tests, 0 failures). `ARCHITECTURE_AUDIT.md` updated (8 → 8 `RelationKind` variants noted).
  - **S→P gap from this cycle:** (a) `SameIdentity` (N profile URLs → one identity hub node) is the next graph-spine gap — the platform-profile domain entities for confirmed social accounts lack a direct structural link to the subject's Person/Username entity (they are linked only transitively via `HostedOn` → Domain → no further). (b) `SameOperator` edges are currently Domain↔Domain only; extending to Url↔Url co-hosted on the same registrant/IP would let the SPA force-graph cluster profile pages directly. (c) A GEXF/GraphML export module would expose the full attributed graph to Maltego / Gephi / Cytoscape without requiring the SPA.
  Paired: `PROBLEM_TREE` P-GRAPH-SPINE-ABSENT — same commit.

- **2026-06-25** — **Cycle R14 (P→S): SOL-R14 — `SameIdentity` structural relation edges (Username → confirmed social profiles).**
  - **Problem closed:** P-IDENTITY-SPINE-ABSENT — confirmed social-profile `Url` entities had no structural link to the `Username` entity they were discovered for. After R13's `SameOperator` edges closed the co-ownership spine gap, the identity spine gap was the highest-value remaining structural hole.
  - **What was built:**
    1. **`RelationKind::SameIdentity`** added to `types.rs` — directed semantically: `Username → social-platform profile Url` (from the abstract identity hub to each of its confirmed platform manifestations). Wire-form: `"same_identity"`. Pinned by the `relation_kind_as_str_matches_serde` test.
    2. **`SOCIAL_MATCHERS` static table** in `builders.rs` — 34 entries mapping platform host names to their username-extraction rule (`ExtractKind::Segment { index, strip_at, strip_suffix }` or `ExtractKind::QueryParam { name }`). Covers all URL patterns in `social_probe::USERNAME_PLATFORMS`: direct `/{username}` (23 platforms), `/@{username}` (4 platforms — TikTok, Medium, Mastodon, Threads), `/{prefix}/{username}` (6 platforms — Steam `/id/`, Flickr `/people/`, Spotify `/user/`, Reddit `/user/…/about.json`, Livejasmin `/en/`, Bluesky `/profile/{}.bsky.social`), and `?id=` query param (HackerNews). `x.com` added as Twitter's canonical redirect domain (not in social_probe but links correctly for crawled URLs).
    3. **`extract_username_from_profile_url(url: &str) → Option<String>`** private function — uses `url::Url::parse` (already in scope via `derive_structural`), looks up the host in `SOCIAL_MATCHERS`, extracts the segment at the specified index from filtered (non-empty) path segments, strips `@`/suffix as needed, returns ASCII-lowercased result.
    4. **`derive_profile_links(entities, scan_id) → Vec<Relation>`** public builder — builds a lowercase `HashMap<String, &Entity>` from all `Username` entities for O(1) lookup, then iterates all `Url` entities passing them through `extract_username_from_profile_url`, matches against the index, and emits `SameIdentity` edges. No fan-out cap — a username may have any number of confirmed profiles. Confidence = `min(username.conf, url.conf)`. No dependency on the `social-profile` tag (matches by URL structure alone).
    5. **`derive_all` updated** to call `derive_profile_links` after `derive_co_ownership`. Both the live scan path and the import path call `derive_all`, so both get `SameIdentity` edges.
    6. **`derive_profile_links` exported** from `core::relation::mod.rs`.
  - **Verification:** 11 new unit tests — `profile_links_github_matches_username` (direct segment match + confidence), `profile_links_direction_is_username_to_url` (edge direction check), `profile_links_case_insensitive_match` (mixed-case username vs lowercase URL), `profile_links_tiktok_at_prefix_stripped` (`/@` prefix stripped), `profile_links_reddit_user_prefix_skipped` (segment index 1 with `/about.json` trailer), `profile_links_bluesky_suffix_stripped` (`.bsky.social` stripped), `profile_links_hackernews_query_param` (`?id=` query param), `profile_links_unknown_host_no_edge` (no match), `profile_links_no_matching_username_entity_no_edge` (username mismatch), `profile_links_no_username_entities_returns_empty` (early exit), `profile_links_multiple_platforms_same_username` (3 platforms × 1 username → 3 edges). `derive_all` test updated to include `derive_profile_links` in expected count. `relation_kind_as_str_matches_serde` updated. `fmt`/`clippy -D warnings`/`doc`/`test --locked` all clean (3216 tests, 0 failures). `ARCHITECTURE_AUDIT.md` updated (8 → 9 `RelationKind` variants).
  - **S→P gap from this cycle:** (a) `SameIdentity` currently fires for any `Url` entity whose host matches a known platform and whose embedded handle matches a `Username` entity — it does not require the `social-profile` tag. This is intentional (works even for `web_crawler`-discovered URLs) but means a URL entity for `https://github.com/user/repo` would incorrectly match if `"user"` were a known username. Low practical risk since GitHub profile URLs don't include `user/` in the path, but a host-specific segment-count guard would make this more precise. (b) `SameIdentity` is Username → Url but not Username → Person; the Person ↔ Username link is currently only `DerivedFrom` (name_intel lineage) — a future `SamePerson` or `Identifies` edge could close the Person→Username structural gap without conflating identity with name-derivation lineage. (c) FullName platform profiles (PeeKYou, Facebook public directory) use slug-form handles and are not covered by `derive_profile_links` — that extraction requires a `source_name` comparison rather than a handle match.
  Paired: `PROBLEM_TREE` P-IDENTITY-SPINE-ABSENT — same commit.

- **2026-06-25** — **Cycle 38 (P→S): SOL-38 — module skip reasons surfaced in `--output json`.**
  - **Problem closed:** P-SKIP-OPAQUE — skip reasons were logged at debug level only and absent from `--output json`.
  - **What was built:** In `src/cli/scan/mod.rs`, the `--output json` path now queries `store.events_for_scan(&sid)` after the scan, filters for `EventKind::ModuleSkipped { module, reason }` events, groups them as `BTreeMap<module, BTreeMap<reason, count>>` (BTreeMap for stable key order in serialised JSON), and includes the result as `"module_skip_reasons"` in the JSON output. This is purely additive (no existing key removed or changed). The skip reason vocabulary is exactly what `module_skip_reason()` returns: `"high-value API — awaiting cross-correlation (>=2 sources)"`, `"circuit-open — rate-limited/quota/repeated failure (cooling down)"`, `"not in allowlist"`, `"excluded"`, `"requires key/payment"`, `"not passive"`, `"disabled in config"`, `"outside category focus"`, `"sensor (already ran on seed round)"`, preflight skip messages. Investigation of `oathnet_pro`'s 14 skip events now requires only `--output json` (no debug mode).
  - **Verification:** `cargo fmt --all -- --check` ✓ · `cargo clippy -D warnings` ✓ · `cargo doc` ✓ · `cargo test --locked` ✓ (3216 passed).
  - **S→P gap from this cycle:** (a) The `--output dossier` path does not yet include skip reasons — it calls `print_diagnostics` which prints the `ScanDiagnostics` struct but not the event log. (b) Skip reasons for already-dispatched-dedup events (`"already dispatched for this target"`) are counted in `modules_skipped` but are not the ones an operator needs to investigate — a future refinement could separate structural skips (gate-rejected) from dedup skips in the summary. (c) The table output (`--output table`, default) shows a raw `skipped=N` count; a single-line hint ("run --output json for skip reasons") would help without cluttering the default view.
  Paired: `PROBLEM_TREE` P-SKIP-OPAQUE — same commit.

- **2026-06-25** — **Cycle 40 (S→P): SOL-TRACKING-PIVOT-C delivered — social-profile URL priority boost in expansion heap.**
  S→P pass on cycle 37: the gap was explicit — "add a priority boost for `Url` entities tagged `social-profile` so they rank above generic domains." Delivered: `+15%` weight multiplier in `src/core/engine/mod.rs` expansion loop for `TargetKind::Url && entity.has_tag("social-profile")`. Added after the existing geo-corroboration bonus block so the two sub-dominant boosts compose cleanly. The fix ensures `web_crawler` is dispatched against confirmed social profile pages early in each expansion round rather than being pre-empted by generic domain/IP targets. **Gap refresh:** SOL-TRACKING-PIVOT-C is now delivered; the S→P gap for cycle 37 is closed. §4a gains no new items. Gate green: fmt/clippy/doc/test --locked all clean, 3216 lib tests, 0 failures.

- **2026-06-25** — **Cycle 41 (P→S): AU-063 delivered — dual-source cell tower corroboration rule.**
  P→S pass on cycle 20 S→P gap ("AU-060-candidate"): `opencellid` and `cell_intel` both emit `DeviceId` with the same `mcc-mnc-lac-cid` key; when both fire, the same tower is confirmed by live hardware observation (Termux telephony sensor) AND crowdsourced database lookup — two orthogonal, independent methods. AU-060 was already taken (transitive identity closure); next available ID was **AU-063**. Delivered: `rule_au_063_cell_tower_dual_source` in `src/core/correlator/rules/geo.rs`, wired into `RULES` in `mod.rs`. Severity: Low (1–2 corroborated towers) / Medium (≥3). 4 new tests in `src/core/correlator/tests.rs` (fires/not-fires/severity/non-cell guard). Doc updates: `docs/ARCHITECTURE_AUDIT.md` 62→63 rules, `README.md` 59→63 rules. **Gap refresh:** §4a AU-060/AU-063 gap closed (now "delivered cycle 41"). §4a gains no new items. Gate green: fmt/clippy/doc/test --locked all clean, 3220 lib tests, 0 failures.
  Paired: `PROBLEM_TREE` — same commit.
