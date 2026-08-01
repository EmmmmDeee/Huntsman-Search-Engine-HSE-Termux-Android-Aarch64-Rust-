# HSE — Strategic Operational Blueprint

**Date:** 2026-08-01
**Status:** Living planning document — decision points and priorities, not a
static feature log. Re-derive counts/coverage from the running software
(`hse modules`, `hse selftest`, `tests/architecture.rs`) rather than trusting
numbers here once they age; Part 6 exists specifically to guard against this
document becoming the next instance of the drift it documents.
**Scope:** Project-wide. Distinct from
[`IMPLEMENTATION_BLUEPRINT.md`](IMPLEMENTATION_BLUEPRINT.md), which is a
narrower, dated file-structure plan for the SeekNow integration alone.
**Evidence basis:** a systematic six-axis audit run against this codebase on
2026-08-01 (32 research agents, each finding independently adversarially
re-verified against source before being trusted), the resulting fix commit
(`f0b173471`), and a 7-agent pre-commit review of that diff before it shipped.
Every claim below traces to one of those three passes or to a file this
document names — nothing here is invented to fill space.

---

## Executive Scorecard

| Subsystem | Maturity | Evidence | Residual risk |
|---|---|---|---|
| OSINT module breadth | High | ~168 modules, 132 free/keyless; 12 candidate expansions checked this session, 10 rejected as already-covered (real signal the catalogue is close to saturated for obvious keyless sources) | Diminishing returns on "add more sources"; the 2 surviving candidates (§4) are genuinely novel, not duplicative |
| MITRE ATT&CK weave | High, now corrected | Complete Enterprise matrix as reference data; every module mapped; sampled ~45 unpinned modules this session, found 3 genuine mismatches (fixed), everything else correct | Coverage is enforced by architecture tests for *presence*; *semantic correctness* still relies on periodic sampling like this session's, not full automation |
| Deterministic correlator | High | 121 rules, zero LLM/fuzzy matching, not touched by this audit (out of scope, no findings either way) | Not independently re-verified this session — a candidate for a future audit axis |
| Reactor / dispatch architecture | High, one real bug fixed | Circuit breaker, health tracking, timeout guarding, egress pool all read and traced; one genuine cross-scan race found and fixed; one confirmed-but-deferred concurrency gap remains (§3.1) | §3.1 is the single highest-severity open item in this document |
| Web UI (dark-console SPA) | High, several fixes applied | Viewport/safe-area handling, mobile card-restacking, consistent error-toast discipline all verified sound; 9 concrete defects found and fixed, 3 residual "minor" items from pre-commit re-review addressed same session | 3 orphaned renderers (§3.2) are a live product-decision gap, not a code-quality one |
| Termux/aarch64 optimization | High | Release profile, worker-thread tuning, TLS/DB stack, zero-AI-dependency guarantee all independently re-verified against actual files, not assumed from docs | aarch64 cross-compile itself unverifiable in this sandbox (§7) — real CI, not this session, is the check of record |
| Testing & CI discipline | High | 4,300+ tests, architecture-invariant tests, zero orphaned `#[cfg(test)]` modules (914/914 files reachable, independently re-derived), clippy/fmt enforced in `[lints]` | None found this session |
| Documentation discipline | Medium — the one real gap | 4 independent stale-claim instances found and fixed from a single grep-and-verify pass | Structural, not incidental — see §6 |

Read across the row: HSE is strong on **engineering rigor** (tests,
architecture invariants, deterministic design) and **breadth** (modules,
ATT&CK, correlator), and its one systemic weak point is **documentation
half-life** — comments and status reports that were true when written and
simply outlived the code. That is the single most leveraged thing to fix
structurally, not repeatedly by hand.

---

## Part 1: Where HSE actually stands

**HSE is a mature platform, not an early-stage project.** ~168 OSINT modules,
121 deterministic correlator rules, 4,300+ tests, a complete MITRE ATT&CK
Enterprise matrix woven into every finding, a from-scratch dark-console web
UI, and a `#![forbid(unsafe_code)]`, zero-AI/ML-dependency, Termux-native
architecture — the last of these is not a claim taken on faith; it's enforced
by `tests/architecture.rs::runtime_carries_no_ai_ml_inference_dependency`,
which scans `Cargo.lock` against a denylist and fails the build if an
AI/ML/vector-DB crate enters the tree.

The audit's verdict, independently reached across four of six axes (reactor
architecture, ATT&CK correctness sampling, Termux optimization claims,
dead-code/test-reachability), was **no defects found** — the codebase's
self-documentation about its own rigor held up when someone actually checked
it line by line rather than trusted the README.

The two axes that *did* surface real, confirmed findings — reactor/dispatch
concurrency and web UI accessibility — are not signs of a shaky foundation;
they're the normal residue of fast iteration on a project already this
large. Twelve confirmed findings were fixed same-session across two commits
(`f0b173471`, plus two further fixes applied after the pre-commit review
caught them). Four were deliberately left for a human call rather than
silently patched — Part 3.

---

## Part 2: Technical Debt Register

A register, not prose, so items can be tracked, aged, and closed
individually rather than re-discovered from scratch next time someone audits
this codebase.

| ID | Item | Severity | Effort | Blast radius | Status |
|---|---|---|---|---|---|
| TD-1 | Synchronous `Store` calls on async worker threads (dispatch hot path + per-round persist) | High | Medium–Large | 2 files, ~15 call sites | **Open** — needs a scoped session, §3.1 |
| TD-2 | 3 orphaned scan-info renderers incl. Exposure Index panel | Low (dead code) / Medium (feature gap) | Small once decided | 4 files (3 renderers + their CSS) | **Open** — needs a product call, §3.2 |
| TD-3 | SeekNow observability gaps (no live HTTP test seam, no latency/cache-hit instrumentation, no load testing, no plan-tier detection) | Medium | Large, phased | `util/see_know/`, `modules/see_know/` | **Open, not re-verified** — carried from `SEEKNOW_GAP_ANALYSIS.md`, §4 |
| TD-4 | Documentation half-life (comments/reports outliving the code they describe) | Medium, structural | Small per-instance, needs a *process* not a fix | Project-wide | **Partially open** — 4 known instances fixed, no standing detection yet, §6 |
| TD-5 | `finalise_module_result`'s `MissingKey` arm recomputes `normalise_target` inline instead of reusing the per-target hoist | Trivial | Trivial | 1 call site, `dispatch.rs` | **Open, deliberately not fixed** — a correctness no-op flagged by pre-commit review, real but not worth the diff churn on its own; bundle with the next dispatch.rs touch |
| TD-6 | Modal focus/backdrop state was a module-level singleton | Low | Small | `ui.js` | **Closed** this session — moved to per-modal-element state |
| TD-7 | 3 Enterprise-gated SeekNow Discord endpoints unbuilt | Low (deliberate) | N/A until unblocked | `see_know` | **Blocked, not debt** — correctly deferred pending plan-tier verification HSE currently can't perform |

---

## Part 3: Decisions the maintainer needs to make

### 3.1 Synchronous SQLite calls on the async reactor's worker threads
**What:** `dispatch.rs` and `engine/mod.rs` call `Store`'s synchronous
rusqlite methods directly from `async fn`s on the hot per-module dispatch
path and the per-round checkpoint/correlation-persist path — never wrapped
in `tokio::task::spawn_blocking`. Concretely: `lookup_module_result_fresh`
(dispatch.rs, 3 call sites) and `archive_module_result` via
`archive_if_eligible` (dispatch.rs, 3 call sites) on the per-module path;
`checkpoint_entities`→`upsert_entities_batch`, `correlate_incremental`→
`upsert_correlation`, and `recall_prior_entities`'s three calls
(`scan_ids_for_entity`, `search_entities`, `entities_filtered`) on the
per-round path in `engine/mod.rs`. `finalise_scan` and the `DbWriter` actor
both already wrap their rusqlite calls this way, with doc comments
explaining exactly why: on the deliberately-tuned `WORKER_THREADS=2`
runtime, a blocked SQLite write (a WAL checkpoint fsync, a throttled Android
storage device under thermal pressure) stalls a worker thread for its
duration, degrading every concurrently-running scan sharing that runtime —
not just the one doing the write.

**Implementation sketch:**
1. Introduce one shared helper — e.g. `async fn on_store<T: Send + 'static>(store: Arc<Store>, f: impl FnOnce(&Store) -> T + Send + 'static) -> T` wrapping `tokio::task::spawn_blocking` — rather than hand-wrapping each of the ~15 call sites individually. A shared helper means this class of bug (a new call site added later, forgetting the wrap) becomes structurally harder to reintroduce.
2. Wrap the dispatch-hot-path calls first (`lookup_module_result_fresh`, `archive_module_result` via `archive_if_eligible`) — highest call frequency, most direct exposure to the failure mode described in TD-1.
3. Then the per-round calls in `engine/mod.rs` — lower frequency (once per round, not once per module), but `checkpoint_entities`/`correlate_incremental` do more work per call (batch upserts, the full correlator pass), so individual stalls are longer even if rarer.
4. Add an architecture-test invariant once the wrap is in place — this codebase already encodes exactly this class of guarantee as tests (`core_does_not_import_storage_directly`, `no_module_reads_an_http_body_without_a_size_cap`, etc.). A test that greps `core/engine/` for `self.store.` / `store.` calls not immediately preceded by `spawn_blocking` in the same function would catch a future regression the same way `finalise_scan`'s own doc comment couldn't.

**Recommendation:** the single highest-priority follow-up in this document.
Scope as its own session — not a bolt-on to unrelated work — given the
`Send`-bound and ordering-preservation care required (the round loop's
"checkpoint completes before the next round starts" guarantee must survive
the refactor).

### 3.2 Three orphaned scan-info UI tabs
**What:** `src/web/js/scan_info/{relations,status,info}.js` are complete,
working renderers — including a calibrated 0–100 "Exposure Index" panel in
`info.js` whose own comment says it exists specifically because "the web
console... was the one consumer that never showed it" — but none are
imported anywhere. `report.js`'s own comment documents a deliberate
consolidation into 15 other sub-renderers that doesn't include these three.
Two dead CSS rule groups (`.kbar-*`, part of the `.cls`/`.c-VERIFIED` family)
are downstream of `status.js` specifically being orphaned — they resolve
automatically once this decision lands.

**Evaluation checklist before deciding:**
1. Diff what `relations.js`/`status.js` actually render against what
   `report.js`'s current 15 sub-renderers show for the same scan — if it's a
   true subset, delete with confidence.
2. For `info.js`'s Exposure Index specifically: check whether the score it
   computes is available anywhere else in the UI (API response inspection,
   `hse export --format full`) — if the *data* is exposed but not the
   *panel*, that's a stronger case for restoring it than rebuilding from
   scratch, since the computation already exists and is tested.
3. If restoring: the panel needs a real tab entry in `index.js`'s dispatcher
   and the nav-tabs UL in `spa.html` — both currently absent, so this is a
   "re-wire," not a one-line import fix.

**Recommendation:** default toward restoring the Exposure Index
specifically — it's a named, purpose-built feature with no other surface
showing it, which is a stronger signal of an accidental omission than of
deliberate supersession. `relations.js`/`status.js` are more plausibly true
duplicates; the diff in step 1 should settle it in minutes.

### 3.3 `SEEKNOW_GAP_ANALYSIS.md`'s frozen status
This session added a historical-snapshot banner rather than correcting its
stale 18/24-endpoint numbers, because `IMPLEMENTATION_BLUEPRINT.md`
explicitly marks it "UNCHANGED: Reference document" — a deliberate freeze,
as best this session could tell from available evidence. Three honest
options, in order of how much they cost:
- **Keep frozen + banner (current state).** Zero further cost; preserves
  the report as a dated historical artifact.
- **Correct the numbers in place.** Current wired count is 20/24; only the
  three Enterprise-gated Discord endpoints remain unbuilt, deliberately.
  Turns it from "historical" into "living," which then re-enters the TD-4
  half-life risk pool unless someone commits to keeping it current.
- **Delete it, keep only `SEEKNOW_SETUP.md`.** Removes the redundancy
  entirely, at the cost of losing the original gap-analysis methodology as
  a reference for how to run a similar analysis again.

**Recommendation:** keep frozen. The banner already fixes the actual harm
(a reader being misled); correcting numbers in a doc explicitly marked
"reference" just recreates the maintenance burden Part 6 already flags as
the project's real weak point.

---

## Part 4: Candidate expansion — new capability

Two candidates survived the audit's "already covered?" check (twelve other
plausible additions — Tor exit-relay checks, SOA-record admin-email
decoding, TLS cert org-field extraction, tracking-ID cross-domain
correlation, cloud-bucket enumeration, sanctions/PEP aggregation, and six
more — were verified as already implemented and rejected as redundant):

| Candidate | Confidence | Effort | What it adds | Why it's distinct |
|---|---|---|---|---|
| **PeeringDB integration** (ASN targets) | Medium | Small | Facility/peering-policy/NOC-contact organizational profile via one keyless `api.peeringdb.com` GET | `bgpview`/`ripestat` cover routing-table data only; PeeringDB's facility-declaration layer is a different data model entirely |
| **Document metadata harvesting** (FOCA/Metagoofil-style) | High | Large | PDF Info-dictionary + OOXML `docProps` fields (Author, Company, Producer, internal paths) from documents `search_engines`/`name_intel` already dork for | Distinct from `exif_geo` (images only, different metadata schema) and `web_crawler` (explicitly treats these formats as opaque binary today) |

**Sequencing guidance:**
- **PeeringDB first.** It mirrors `bgpview`/`ripestat`'s existing shape
  closely enough to reuse their patterns almost directly: a `TargetKind::Asn`
  acceptor, `ModuleCategory::Infrastructure`, and an ATT&CK tag set similar
  to `ripestat`'s (`T1590.005` + likely `T1591.002` for the facility/NOC
  organisation) — small, low-risk, immediately consistent with existing
  conventions.
- **Document metadata second, as its own scoped session.** It needs a new
  parsing surface (PDF trailer/xref, zip+XML for OOXML) this codebase
  doesn't currently have — genuinely new capability, not a variation on an
  existing pattern, so it deserves dedicated design time rather than being
  squeezed into a session already carrying other work. The existing (but
  currently unused) `pdf = "0.10"` dependency may or may not be reusable for
  the PDF half; worth checking before reaching for a hand-rolled parser.

Beyond these two, `SEEKNOW_GAP_ANALYSIS.md`'s carried-forward Phase 3/4 items
(not re-verified this session — treat as "last known open"): no live HTTP
client seam for SeekNow integration testing, no plan-tier auto-detection
(which blocks TD-7's Enterprise endpoints from ever being safely built), no
per-endpoint latency/cache-hit-ratio instrumentation, no concurrent-scan load
testing at any verified scale, no OpenAPI schema. None of these are urgent —
SeekNow is "operationally sound" per that report and this session's own
probing surfaced no functional problems beyond the two doc-drift issues
already fixed — but they're worth naming so they don't silently vanish now
that the more visible endpoint-coverage gap is closed.

---

## Part 5: Phased roadmap

A synthesis of Parts 2–4 into sequence, not just a priority list — later
phases assume earlier ones are either done or explicitly skipped.

**Phase A — Close the loop on this session's findings (near-term, small):**
- Decide §3.2 (dead tabs) and §3.3 (frozen doc) — both are same-day
  decisions once the evaluation checklists are run
- If restoring the Exposure Index: re-wire it into `index.js`/`spa.html`

**Phase B — Reactor hardening (near-term, focused):**
- TD-1 / §3.1: the `spawn_blocking` wrap, as its own scoped session per the
  implementation sketch above
- TD-5: fold the trivial `normalise_target` re-hoist into the same session
  since it touches the same file

**Phase C — Selective capability expansion (mid-term):**
- Build PeeringDB (small, low-risk)
- Scope and build document metadata harvesting as its own session

**Phase D — SeekNow observability (mid-term, only if SeekNow's real-world
usage volume justifies the investment):**
- Live HTTP client test seam first — it's the prerequisite that makes the
  rest of this phase's items independently testable rather than trusted on
  faith
- Plan-tier auto-detection, then (only if a confirmed Enterprise key becomes
  available) the three deferred Discord endpoints
- Latency/cache-hit instrumentation and concurrent-scan load testing

**Phase E — Standing governance (ongoing, starts now):**
- Part 6's recurring drift audit, on a cadence, starting with the next
  version bump

---

## Part 6: A standing practice, not a one-time audit

Four instances of stale self-documentation surfaced from one systematic
pass: a function doc claiming a feature was "never wired" after it had
shipped live, a module doc calling adaptive routing unbuilt after
`--adaptive` landed, an API reference marking a live module as an
unintegrated candidate, and the SeekNow gap report itself. None were
malicious or careless — each was accurate *when written* and simply outlived
the feature it described. That ratio — real, evidence-based drift found
essentially everywhere anyone looked carefully — means the failure mode is
structural, not incidental: this codebase changes fast enough that doc
comments and status reports outlive the code they describe, and nothing
currently catches it except a human (or agent) happening to read both the
claim and the code side by side.

**Concrete recurring-audit template**, reusable as-is against a cadence
(before each version bump, or quarterly):
1. Grep `src/` and `docs/` for staleness markers: `"not yet"`, `"never
   built"`, `"not implemented"`, `"not currently"`, `"coming soon"`, `TODO`,
   and any N-of-M coverage count (`\d+/\d+`, `\d+ of \d+`).
2. For every hit, read the code it describes and verify the claim against
   current behavior — not against the comment's own confidence.
3. Discard hits that are still accurate (most will be — this isn't a
   presumption of rot, it's a check for it).
4. Fix confirmed drift directly; for anything ambiguous (a deliberately
   frozen historical doc, an intentionally-unbuilt feature), leave it but
   make the "why" explicit rather than silent, the way §3.3's banner does.

This is cheap relative to the value: this session found real, shipped
inaccuracies in developer-facing documentation with a handful of targeted
greps once someone looked, in well under an hour of agent time. Left
unaddressed, at this project's size and pace, staleness compounds silently
and erodes exactly the "running software is the source of truth" discipline
`CLAUDE.md` establishes as the project's own standard.

---

## Part 7: Why this architecture is a real strategic asset

Worth stating plainly, since it's easy to lose sight of while working
through a debt register: HSE's constraint set is unusual, and the
unusualness is the point, not an accident. Most on-device or mobile-capable
OSINT tooling picks one of three paths — require root, offload to the
cloud, or lean on an LLM/embedding stack for entity extraction and
correlation. HSE does none of the three, and that's independently enforced,
not just claimed: `#![forbid(unsafe_code)]` crate-wide, a build-failing
architecture test if any AI/ML/vector-DB dependency enters `Cargo.lock`, and
a deterministic, no-fuzzy-matching correlator (121 rules, zero LLM
involvement) that makes every correlation explainable and reproducible —
the same input always produces the same output, auditable line-by-line back
to the rule that fired.

That combination is genuinely rare, and it's the right one for exactly the
use cases this tool targets: authorized security, fraud-prevention,
due-diligence, and investigative work where an analyst needs to *explain*
why the tool concluded what it concluded, not just trust a score. An
LLM-based correlator cannot offer that; a cloud-offload tool cannot offer
the no-data-leaves-the-device guarantee a sensitive investigation needs; a
root-requiring tool cannot run on the stock, unmodified phone most operators
actually carry. The strategic implication: capability expansion (Part 4)
should keep optimizing within this constraint set rather than treating it
as friction to engineer around — it's the differentiator, not the tax.

---

## Part 8: Bottom line

HSE does not need a rebuild, a new architecture, or a rescue plan. It needs:
a decision on §3.1–3.3, a build order for §4's two candidates, and a light
recurring process per Part 6. Everything else audited this session — the
module registry, the ATT&CK weave, the reactor's core design, the Termux
tuning — held up under adversarial scrutiny, twice (once from the audit,
again from the pre-commit review of the fixes). The highest-leverage next
work is finishing what's already been found, in the sequence Part 5 lays
out, not searching for more.
