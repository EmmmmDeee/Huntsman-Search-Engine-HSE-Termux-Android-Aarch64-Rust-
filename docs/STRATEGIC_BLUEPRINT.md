# HSE — Strategic Operational Blueprint

**Date:** 2026-08-01
**Status:** Living planning document — decision points and priorities, not a
static feature log. Re-derive counts/coverage from the running software
(`hse modules`, `hse selftest`, `tests/architecture.rs`) rather than trusting
numbers here once they age; that drift is exactly what Part 4 exists to guard
against.
**Scope:** Project-wide. Distinct from
[`IMPLEMENTATION_BLUEPRINT.md`](IMPLEMENTATION_BLUEPRINT.md), which is a
narrower, dated file-structure plan for the SeekNow integration alone.

---

## Part 1: Where HSE actually stands

This assessment is evidence-based: it reflects a systematic six-axis audit
run against this codebase on 2026-08-01 (32 research agents + independent
adversarial re-verification of every candidate finding, followed by a 7-agent
pre-commit review of the resulting diff), not aspiration.

**HSE is a mature platform, not an early-stage project.** ~168 OSINT modules,
121 deterministic correlator rules, 4,300+ tests, a complete MITRE ATT&CK
Enterprise matrix woven into every finding, a from-scratch dark-console web
UI, and a `#![forbid(unsafe_code)]`, zero-AI/ML-dependency, Termux-native
architecture. The audit's own verdict, independently reached across four of
six axes (reactor architecture, ATT&CK correctness sampling, Termux
optimization claims, dead-code/test-reachability), was **no defects found** —
the codebase's self-documentation about its own rigor holds up when someone
actually checks it.

The two axes that *did* surface real, confirmed findings — reactor/dispatch
concurrency and web UI accessibility — are not signs of a shaky foundation;
they're the normal residue of fast iteration on a project already this large.
Nine of those findings were fixed same-session (see the `f0b173471` commit).
Four were deliberately left for a human call, not silently patched — that
list is Part 2 below.

**The recurring pattern worth naming:** four separate stale self-documentation
claims surfaced this session (a function doc claiming a feature was "never
wired" after it had shipped live, a module doc calling adaptive routing
unbuilt after `--adaptive` landed, an API reference marking a live module as
an unintegrated candidate, and the SeekNow gap report itself). None were
malicious or careless — each was accurate *when written* and simply outlived
the feature it described. This is systemic, not a one-off, which is why
Part 4 proposes a standing practice rather than treating it as closed.

---

## Part 2: Decisions the maintainer needs to make

These are flagged, not fixed, because they require judgment this session
couldn't supply — either a design/product call, or verification against
something (a live API key's plan tier, an intended UX) unavailable offline.

### 2.1 Synchronous SQLite calls on the async reactor's worker threads
**What:** `dispatch.rs` and `engine/mod.rs` call `Store`'s synchronous
rusqlite methods (`lookup_module_result_fresh`, `archive_module_result`,
`upsert_entities_batch`, `upsert_correlation`, and three more) directly from
`async fn`s on the hot per-module dispatch path and the per-round
checkpoint/correlation-persist path — never wrapped in `tokio::task::
spawn_blocking`. `finalise_scan` and the `DbWriter` actor both do wrap their
rusqlite calls this way, with doc comments explaining exactly why: on the
deliberately-tuned `WORKER_THREADS=2` runtime, a blocked SQLite write (WAL
checkpoint fsync, a throttled Android storage device) stalls a worker thread
for its duration, degrading every other concurrently-running scan sharing
that runtime.
**Why deferred:** confirmed real by two independent audit passes, but the
fix touches ~15 call sites across two files and needs careful handling —
`spawn_blocking` closures must capture `Store` in a way that's `Send`, and
the round-loop's ordering guarantees (checkpoint completing before the next
round starts) must be preserved. Rushing this risks a subtler bug than the
one it fixes.
**Recommendation:** treat as the top-priority follow-up. Scope it as its
own session: wrap the dispatch-hot-path calls first (highest frequency),
verify with a targeted concurrency test, then the per-round calls in
`engine/mod.rs`.

### 2.2 Three orphaned scan-info UI tabs
**What:** `src/web/js/scan_info/{relations,status,info}.js` are complete,
working renderers — including a calibrated 0–100 "Exposure Index" panel in
`info.js` whose own comment says it exists specifically because "the web
console... was the one consumer that never showed it" — but none are
imported anywhere. `report.js`'s own comment documents a deliberate
consolidation into 15 other sub-renderers that doesn't include these three.
**Why deferred:** this is a product decision, not a bug fix. Two honest
readings: (a) the consolidation intentionally superseded them and they're
dead weight to delete, or (b) they were meant to be re-wired after the
consolidation and that step was simply missed — the Exposure Index panel in
particular reads as a real gap given its own comment's stated purpose.
**Recommendation:** the Exposure Index is the one worth a default toward
restoring — it's a named, purpose-built feature with no other surface
showing it. `relations.js`/`status.js` are more plausibly true duplicates of
what `report.js` already renders; worth a two-minute side-by-side diff of
what each shows before deciding.

### 2.3 Two candidate new OSINT modules
Both survived the audit's "already covered?" check (twelve other plausible
candidates were rejected as redundant against existing modules) and are
scoped enough to build directly:

- **Document metadata harvesting** (FOCA/Metagoofil-style): no module
  extracts PDF Info-dictionary or OOXML `docProps` fields (Author, Company,
  Producer, internal paths) from documents `search_engines`/`name_intel`
  already dork for via `filetype:pdf|docx|xlsx`. Distinct from `exif_geo`
  (images only) and `web_crawler` (explicitly treats these as opaque
  binary). **High confidence, larger lift** — needs a small pure-Rust
  PDF-trailer parser and a zip+XML reader for OOXML, new dependencies not
  currently in the tree.
- **PeeringDB integration** for ASN targets: `bgpview`/`ripestat` cover
  routing-table data; neither surfaces PeeringDB's distinct
  facility/peering-policy/NOC-contact layer. **Medium confidence, small
  lift** — one keyless JSON GET (`api.peeringdb.com`), closely mirrors the
  existing `bgpview`/`ripestat` module shape.
**Recommendation:** PeeringDB is the better next pick — small, low-risk,
non-redundant. Document metadata harvesting is higher-value but should be
its own scoped session given the new-parser surface area.

### 2.4 `SEEKNOW_GAP_ANALYSIS.md`'s frozen status
This session added a historical-snapshot banner rather than correcting its
stale 18/24-endpoint numbers, because `IMPLEMENTATION_BLUEPRINT.md`
explicitly marks it "UNCHANGED: Reference document" — a deliberate freeze,
as best this session could tell. If that wasn't actually the intent, the
numbers themselves should be corrected instead (current wired count is
20/24; only the three Enterprise-gated Discord endpoints remain unbuilt,
deliberately, since HSE's embedded keys aren't confirmed Enterprise-tier).

---

## Part 3: What's still open from the SeekNow gap analysis

`SEEKNOW_GAP_ANALYSIS.md` (2026-07-22) documented a phased plan beyond
endpoint wiring. This session verified and closed the Phase 1 endpoint items
(`/status`, and confirmed `/search/deep` was already live) but did **not**
independently re-verify whether the Phase 3/4 items below are still open —
they're carried forward from that report's own text, not re-checked against
current code. Treat as "last known open," not "confirmed still open":

- No live HTTP client seam for SeekNow integration testing (tests still use
  mocked/synthetic responses)
- No plan-tier auto-detection (blocks conditional Enterprise endpoint
  exposure — relevant to §2.3's Discord endpoints)
- No per-endpoint latency/cache-hit-ratio instrumentation
- No concurrent-scan load testing (10+ simultaneous scans, unverified at
  any scale)
- No OpenAPI schema, no expanded troubleshooting guide

None of these are urgent — SeekNow is "operationally sound" per that report
and this session's own probing didn't surface functional problems in it
beyond the two doc-drift issues already fixed. They're listed here so they
don't silently vanish from view now that the more visible endpoint-coverage
gap is closed.

---

## Part 4: A standing practice, not a one-time audit

Four instances of stale self-documentation surfaced from one systematic
pass. That ratio — real, evidence-based drift found essentially everywhere
anyone looked carefully — suggests the failure mode is structural: this
codebase changes fast enough that doc comments and status reports outlive
the code they describe, and nothing currently catches it except a human (or
agent) happening to read both the claim and the code side by side.

**Recommendation:** run the same class of audit — grep for staleness
markers ("not yet", "never built", "not implemented", stale N-of-M counts),
verify each hit against current code, fix confirmed drift — on a recurring
cadence (a natural fit: before each version bump, or quarterly). This is
cheap relative to the value: this session's occurrence found real, shipped
inaccuracies in developer-facing documentation with a handful of targeted
greps once someone looked. Left unaddressed, at this project's size and
pace, staleness compounds silently and erodes exactly the "running software
is the source of truth" discipline `CLAUDE.md` establishes.

---

## Part 5: Bottom line

HSE does not need a rebuild, a new architecture, or a rescue plan. It needs:
a decision on §2.1–2.4, a pick between §2.3's two candidates, and a light
recurring process per Part 4. Everything else audited this session — the
module registry, the ATT&CK weave, the reactor's core design, the Termux
tuning — held up under adversarial scrutiny. The highest-leverage next work
is finishing what's already been found, not searching for more.
