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
  that the T0 fixes used. *Gap:* the deps aren't promoted and there's no `util::scan`
  module yet — the automata leverage is unrealised. **(§4b)**
- **`[~]` SOL-F2 · `fst`-backed datasets** ⚑ — `build.rs` compiles `data/*.txt` into
  memory-mapped `fst::Set`/`Map`, one canonical `util::dataset` API.
  *Closes / powers:* **F.2** (self), the **B5.3 table-drift** class, and Levenshtein
  fuzzy matching for typosquat / username-variants / suburb-matching.
  *Delivered:* the **de-dup goal** (T2.6) — drift-prone shared lists single-sourced by
  delegation. *Gap:* the genuinely large tables (OUI ≈30k, AU postcode/suburb) are
  still hand-coded `match` arms; `fst` itself not adopted. **(§4b)**
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
  the README/MODULES counts, and AI-independence. *Closes:* **T1.4**; *constrains*
  SOL-ISOLATE (a util task-local can't be scoped from core — see §4b). ✅
- **`[x]` SOL-OUTPUT-ESCAPE · Context-correct output encoding** — `esc()`/`attr()`
  (HTML), `extLink()` (href + scheme gate), CSV formula-defang; the SPA renders
  attacker values via `data-` attributes read with `this.dataset`, never a JS-string
  literal in an inline handler. *Closes:* the **§7 SPA stored XSS** (fixed). ✅

### S.RESOURCE — Concurrency, throughput & resource safety

- **`[~]` SOL-BLOCKING · Keep the 2-worker reactor unblocked** — `spawn_blocking`
  the heavy sync `Store`/render handlers; (planned) a single **DB-writer actor**
  owning the `Connection` behind a bounded `mpsc`. *Closes:* **T2.2** (done, incl.
  the debug-bundle `curl`), **T1.2** (API-read part done). *Gap:* `scan_import` +
  `stats` still run sync on the reactor, and the engine's per-entity `insert_event`
  + the writer-actor remain. **(§4b)**
- **`[~]` SOL-BUDGET · Atomic quota reservation** — `QuotaBudget::try_increment`
  (CAS, saturating session rollback) replaces every racy `remaining()`-then-
  `increment()`. *Closes:* **T2.11** (oathnet — done; mirrors see_know). *Gap:* the
  per-scan `reset_scan`-zeroing across concurrent scans is the same root as
  SOL-ISOLATE. **(§4b)**
- **`[x]` SOL-CAP · Bounded / streaming reads** — `read_body_capped` /
  `read_json_text` (`JSON_BODY_CAP`), reqwest read-timeout backstop, the `exif_geo`
  `bytes_stream()` accumulate-and-bail, the `smtp_vrfy` 8 KiB line cap via
  `fill_buf`/`consume`. *Closes:* **T2.1** (timeouts), **T2.8** (the two HIGH reads —
  done). *Gap (tracked under SOL-CAP-EXTEND):* the MED `json_decode`/AU-scraper caps,
  the hibp cast, the CLI-import cap remain. **(§4b)**
- **`[ ]` SOL-ISOLATE · Per-`scan_id` state isolation** — key the `found_keys` sink
  and the per-scan budget statics by `scan_id` so 8 concurrent `serve` scans don't
  contaminate each other. *Closes:* **T2.11** (found_keys — the headline open item).
  *Design + blocker recorded in PROBLEM_TREE T2.11:* needs either a future-wrapping
  `core::hooks` scope or `scan_id` threaded through the util HTTP layer (the
  `core_does_not_import_util_directly` guard blocks a naive task-local). **(§4a/b)**

### S.SECURITY — Security controls (paired with `PROBLEM_TREE` §7)

- **`[x]` SOL-SSRF · Egress SSRF defence** — `SsrfResolver` DNS filter +
  private-IP redirect guard + curl IP-pin on the **HTTP** client. *Closes:* the
  reqwest-path SSRF (verified sound, §6). *Gap:* the **raw whois TCP/43** path
  bypasses it — see SOL-SSRF-WHOIS. **(§4a)**
- **`[ ]` SOL-SSRF-WHOIS · Validate whois referrals** — before connecting to a
  referral server, parse `host:port`, reject ports ≠ 43, drop `is_private_addr`
  addresses (reuse `filter_public`), pin the connection, reject `is_local_domain`.
  *Closes:* **§7 S2** (HIGH, contained). Planned. **(§4a)**
- **`[x]/[ ]` SOL-SECRETS · Secrets at rest** — `util::atomic_file::write` (0600 +
  unique-temp + `sync_all` + atomic rename) covers `.huntsman.env`, `key_pool.json`,
  `raw/`. *Closes:* the env/pool/archive perms. *Gap (SOL-SECRETS-EXTEND):* the
  dossier/export/DB writes use bare `std::fs::write`/`Connection::open` (0644) and
  `~/.huntsman` isn't 0700 — **§7 S3** (MED). Planned. **(§4a)**
- **`[x]` SOL-REDACT · Credential redaction** — `redact_credentials` (param + literal
  `HUNTSMAN_*` passes) on error bodies/URLs; only `key_tail` (last-4) is ever logged.
  *Closes:* the key-in-URL **log** exposure (S4 mostly mitigated). *Gap:* the archived
  **success body** isn't run through `redact_literal_secrets` — **§7 S4** residual. ◑
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

- **`[ ]` SOL-CORR · Correlation & identity depth** → **C1** (Maltego-without-graphs):
  transitive identity closure (property-tested convergence), a text "Connections"
  dossier section, first-class timeline, AU-0xx rule-gap fill. Built on SOL-MERGE.
- **`[ ]` SOL-PERF-PUBLISH · Reproducible on-device benchmark** → **C2**: with SOL-F3
  benches + SOL-BLOCKING throughput + SOL-F2 flat-RAM, publish "N selectors, on a
  phone, in T s, M MB".
- **`[ ]` SOL-AU-MOAT · Australian collection breadth** → **C3** (AHPRA/ACMA/GNAF/
  fuller ASIC, BYO-key HLR/CNAM). All free or BYO-key, AU-first.
- **`[ ]` SOL-NETINT · CDN-origin unmasking + asset depth** → **C4**: union subdomain
  discovery, ASN/BGP pivots, passive-DNS/cert-hash origin candidates; v4+**v6**
  `is_cdn_edge_ip` already demotes the noise.
- **`[ ]` SOL-GEOINT · Confidence-weighted geo convergence** → **C5**: the Weiszfeld/
  Welzl fusion stack (verified correct, §6) widened with more sources + provenance +
  a confidence radius.
- **`[ ]` SOL-OFFENSIVE · Exposure & reuse graph** → **C6**: broaden SERP dorks,
  credential-reuse graph, `aho-corasick` (SOL-F1) key-harvest + entropy gate.
- **`[ ]` SOL-FORENSIC · Reproducible intelligence product** → **C7**: byte-stable
  exports + evidence chains as the auditable, machine-diffable deliverable.

### S.QUALITY — Periphery correctness (paired with `PROBLEM_TREE` T2.12)

- **`[ ]` SOL-CLI-CONTRACT · Honest CLI result/exit semantics** — make `keys add`
  return `{Added,Duplicate,NotPoolable}` (no false "already exists" + silent drop);
  `provision --verify` return non-zero on a failed smoke scan; define an exit-code
  contract for `audit`/`diff`. *Closes:* **T2.12** (the two MED CLI bugs).
- **`[ ]` SOL-DIFF-DEDUP · uid-deduped diff** — iterate the deduped `HashMap` values
  (or dedup inputs) in `diff_entities`. *Closes:* **T2.12** diff over-count.
- **`[ ]` SOL-CACHE-REFRESH · Allow in-place refresh when full** — `len < cap ||
  contains_key`. *Closes:* **T2.12** stale-cache.

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
| SOL-BLOCKING | T2.2 · T1.2 (partial) | `[~]` |
| SOL-BUDGET | T2.11 oathnet | `[~]` |
| SOL-CAP | T2.1 · T2.8 (2 HIGH) | `[x]`/`[~]` |
| SOL-ISOLATE | T2.11 found_keys | `[ ]` |
| SOL-SSRF / -WHOIS | §6 (HTTP) · §7 S2 | `[x]`/`[ ]` |
| SOL-SECRETS / -EXTEND | env/pool/archive · §7 S3 | `[x]`/`[ ]` |
| SOL-REDACT | §7 S4 | ◑ |
| SOL-EMBED | §7 S1 (accepted) | `[-]` |
| SOL-CLI-CONTRACT / -DIFF / -CACHE | T2.12 | `[ ]` |
| SOL-CORR…SOL-FORENSIC | C1–C7 | `[ ]` |

---

## 4. Gap analysis — the live diff between the trees (refreshed every pass)

> This section *is* the alternation made concrete. **4a** = problems with no started
> solution (P→S gaps, the build queue). **4b** = solutions begun but unfinished (the
> finish queue). **4c** = solutions with no problem (over-build — prune candidates).
> When 4a + 4b are empty, the two trees agree.

### 4a · Problems with NO solution yet started (P→S coverage gaps)
- **T2.10** schema versioning — *no* solution node exists beyond the advisory; the
  cleanest is a `SOL-SCHEMA-VERSION` (set `PRAGMA user_version` at create + an
  idempotent upgrade ladder). **Latent, no current bug** → deliberately unbuilt; add
  the node only if a non-additive migration is ever needed.
- **T2.7** scraper-health signal — covered *in principle* by SOL-F1 (parser rewrites)
  but the per-source health surface (last-success/parse-rate in `doctor`+SPA) has no
  solution node. Gap.
- **§7 S2 / S3 / S4 / S5** — solution nodes exist (SOL-SSRF-WHOIS, -SECRETS-EXTEND,
  -REDACT residual, the install checksum) but are **unstarted**. Contained; awaiting
  the operator's prioritisation (S2 the highest).
- **C1–C7** — capability nodes; solutions sketched, none started (gated on the §3.F
  enablers landing first, by design).

### 4b · Solutions begun but unfinished (the finish queue)
- **SOL-F1** — boundary shims shipped; deps not promoted, no `util::scan`. *Biggest
  remaining leverage* (unblocks T2.7 + sharpens C6).
- **SOL-F2** — de-dup done; `fst` for the large tables outstanding.
- **SOL-F3** — proptest + criterion landed; `cargo-fuzz` + import-parser proptest left.
- **SOL-BLOCKING** — API reads done; `scan_import`/`stats` handlers + the engine
  DB-writer actor left (T1.2).
- **SOL-CAP** — 2 HIGH reads done; MED `json_decode`/AU-scraper caps + hibp cast + CLI
  import cap left (T2.8 tail).
- **SOL-ISOLATE** — designed, blocked on the layering decision (T2.11 found_keys).
- **SOL-BUDGET** — oathnet done; the budget-reset-zeroing folds into SOL-ISOLATE.
- **T1.3 meta-guard** — the 12 firing assertions shipped; the dispatch-table
  firing meta-guard (a `SOL-RULE-METAGUARD` leaf) is unbuilt.

### 4c · Solutions with no problem (over-build — prune candidates)
- **None found.** Every solution node traces to ≥1 `PROBLEM_TREE` node or the shared
  mission. The codebase is lean (0 unused deps via `cargo machete`, 0 dead modules);
  the audit cadence (SOL-AUDIT-CADENCE) keeps deleting dead code (e.g. `util::stats`),
  which is the over-build guard working. Re-check each pass.

### 4d · Coverage snapshot (problem tier × solution status)
- **T0 (crashes):** fully solved (SOL-BOUNDARY + SOL-F3 guard). ✔
- **T1 (core guarantees):** T1.1/T1.4 solved; T1.2 partial (SOL-BLOCKING); T1.3 partial.
- **§3.F (foundations):** all three `[~]` — the largest unrealised leverage block.
- **T2 (robustness):** T2.1–T2.6 + T2.9 solved; T2.8 partial; T2.7/T2.10/T2.12 open;
  T2.11 partial (oathnet done, found_keys/SOL-ISOLATE pending).
- **§7 (security):** XSS solved; S1 accepted; S2–S5 open with solutions named.
- **§4 (capability C1–C7):** open by design, gated on §3.F.

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
