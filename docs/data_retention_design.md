# HSE Data Retention & Enrichment — architecture and lawful basis

**Status:** design for review (not legal advice — the compliance section needs a
qualified review before any retention policy ships). Author: autonomous dev loop.

This responds to the goal: *"retain queried/unique data permanently, enrich it
offline, organise it intelligently, and prioritise the data that empowers all
other data asymmetrically — from the perspective of enrichment potential."*

The headline finding: **most of this already exists in HSE** as the cross-scan
*intelligence flywheel*. The work is not to build a retention engine from scratch —
it is to (a) understand what is already retained, (b) make the enrichment-priority
explicit and queryable, and (c) bound the whole thing inside a lawful basis so the
asset survives diligence instead of becoming a liability.

---

## 1. The lawful basis (read this first — it shapes everything below)

The instinct "I queried it, enriched it, therefore I may retain and resell it" does
**not** hold for the *raw* third-party data, and building on that assumption is
value-destroying (revoked keys, failed M&A diligence, regulatory exposure). Two
separate things must not be conflated:

| Layer | What it is | Retain? | Resell? |
|-------|-----------|---------|---------|
| **Raw provider responses** (HIBP, breach pools, registries, paid APIs) | Licensed third-party data | Only as each provider's ToS permits (most forbid caching/redistribution) | **No** — enrichment does not launder source licence terms |
| **First-party derived work product** (HSE's entities, relations, correlations, dossiers, the cross-scan graph) | HSE's *own* analytical output | Yes | Yes — this is the genuine asset |
| **Personal data inside either layer** | PII about real people | Governed by privacy law regardless of "ownership" | Subject to lawful-basis, minimisation, retention-limit and subject-rights duties |

**The sellable asset is the derived intelligence layer, never the cached licence.**
HSE's value is the *graph* — the cross-investigation linkage and the precision of
its correlations — not a re-hosted copy of someone else's breach corpus.

Personal-data guardrails that must be designed in, not bolted on:
- **Lawful basis + purpose limitation** — retention tied to a stated investigative
  purpose; not "retain everything forever because it might be useful."
- **Data minimisation** — retain the *derived link* (which scans share an
  identifier) preferentially over bulk raw PII.
- **Retention limits + deletion** — per-category TTLs and a working delete path
  (subject erasure, and purge of stale low-value rows).
- **Security at rest** — already enforced: `~/.huntsman` tree is owner-only (0700
  dir / 0600 files), SQLite local, no cloud. Keep it that way for any retained PII.

---

## 2. What already exists — the cross-scan flywheel

HSE already retains and compounds across scans. Nothing here is hypothetical; the
code references are current.

- **Persistent local store.** The WAL SQLite database persists every scan's
  `entities`, `relations`, `correlations`, `evidence` and `events` — the dossier is
  not discarded at scan end. (`src/storage/`, `core::engine::dispatch` persist path.)
- **Same-subject recall.** `ScanEngine::recall_prior_entities`
  (`core/engine/mod.rs`) replays a prior scan of the *same* seed back into a new run,
  so a re-scan starts from everything previously learned.
- **Cross-investigation bridging.** `link_cross_scan_history`
  (`core/engine/history/mod.rs`) asks, for each specific identifier in the current
  scan, whether any *earlier, different-subject* scan recorded the same value, and
  tags the recurrence — "turning a pile of isolated scans into one connected
  intelligence base" (its own doc comment).
- **Co-occurrence linkage.** `link_cross_scan_cooccurrence` links entities that
  appeared together across investigations; `link_cross_scan_relations` carries the
  typed edges across.
- **Cross-scan corroboration.** `promote_cross_scan_corroborated`
  (`core/engine/passes.rs`) lifts a finding that independent investigations agree on.
- **Provenance honesty.** All of the above attach `CROSS_SCAN_SOURCE` /
  `RECALL_SOURCE` evidence that is deliberately *non-corroborating* — a recurrence
  is a surfaced LINK, not a confidence bump (this is exactly the over-credit the
  AU-010 / AU-062-063 / GEXF fixes this branch enforced everywhere).

**Conclusion:** the "retain + enrich offline" engine is already built and already
disciplined about not double-counting itself.

## 3. The enrichment-priority model — already encoded, make it explicit

The request "prioritise the data that empowers all other data asymmetrically" maps
directly onto `is_cross_scan_candidate` (`core/engine/history/mod.rs:61`), which
*already* selects the high-leverage join keys and rejects the low-leverage noise:

| Tier | Kinds | Why they enrich asymmetrically |
|------|-------|--------------------------------|
| **Strong join keys** | Email, Phone, CryptoAddress (conf ≥ 0.40) | Globally unique → a single match bridges two whole investigations |
| **Distinctive identity** | Username ≥ 4 chars, Person (full name), *specific* Address | Distinctive enough to link, gated against generic/coarse forms |
| **Rejected (anti-priority)** | infra domains, name-permutations, coarse geo (postcode/suburb), already-recalled nodes | Shared by thousands → linking on them manufactures false bridges |

This is the right model: **value follows joinability**, and the distinctiveness
gates (surname commonness, handle quality, specific-vs-coarse address — all hardened
on this branch) are what stop the asset from filling with coincidental links.

## 4. Gap to the "independent enrichment asset" vision — concrete next steps

What is *not* yet built, in priority order. Each is implementable inside the
existing rusqlite/WAL pattern with no new crates:

1. **An enrichment-leverage index.** A persisted, queryable score per retained
   identifier = (distinctiveness × cross-scan degree). The data exists (cross-scan
   degree is already computed transiently); persisting it turns "which of my held
   identifiers is most valuable" into a `SELECT`. *Builds on:* the
   `low_confidence_evidence` query pattern (P3, already shipped) + `is_cross_scan_candidate`.
2. **Retention-policy layer.** Per-category TTL + a `purge(before, min_leverage)`
   path so low-value rows age out and high-leverage links are kept — both a
   compliance control (retention limits) and a Termux footprint control.
3. **Provenance/licence tagging at the row.** Mark each retained datum with its
   source-licence class (first-party-derived vs provider-licensed vs user-supplied)
   so the resale boundary in §1 is *enforced by the schema*, not by memory — an
   export can then mechanically exclude provider-licensed rows.
4. **Subject-erasure path.** A `forget(identifier)` that removes an identifier and
   its derived links — required for lawful PII retention and cheap given UID keying.

## 5. What this is worth

The asset is the **graph + its precision**, compounding per scan via §2 and ranked
by §3. The valuation lever is not volume of cached data (a liability) but
**joinability × correctness**: every precision fix on this branch (no false CRITICALs,
no over-credited links, no junk identities) directly raises the asset's quality,
because a wrong link in a retained graph compounds into every future investigation.
Retention multiplies precision — which is why precision had to come first.

---

*Implementation note: items in §4 are sequenced so each is a self-contained,
test-backed change within the existing storage layer (the §1 guardrails gate §4.3
and §4.4). None requires runtime/network execution to build or test.*
