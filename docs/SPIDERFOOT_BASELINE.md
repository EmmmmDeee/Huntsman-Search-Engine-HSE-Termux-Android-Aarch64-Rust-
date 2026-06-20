# SpiderFoot Baseline — the competitor HSE must supersede (living document)

> **Purpose.** [SpiderFoot](https://github.com/smicallef/spiderfoot) is the reference
> OSINT-automation framework and HSE's standing baseline: the minimum bar every release
> must clear, and a competitor HSE is built to *supersede* across the dimensions below.
>
> **What this is — and is not.** This is a **capability comparison** grounded in two
> verifiable sources: SpiderFoot's publicly documented design, and HSE's own source tree
> (every HSE claim cites a module or test you can inspect). It is **not** a fabricated
> performance benchmark. Where a dimension is a *capability* difference (a feature one
> tool has and the other lacks) it is asserted as fact. Where it is a *performance*
> difference (how fast / how much on live data), the structural reason is given but the
> measured figure is deferred to a live A/B — see [§4](#4-how-superiority-is-measured).
> Per HSE's Empirical Truth Gate, no measured number is claimed without that A/B.

---

## 1. The baseline: SpiderFoot at a glance (verifiable design)

| Property | SpiderFoot |
|---|---|
| Language / runtime | Python 3 (interpreter + virtualenv + dependency tree) |
| Data-source modules | ~200 (its principal strength: breadth of third-party API integrations) |
| Correlation | Rule engine (v4.0+), ~37 hand-written YAML rules |
| Graph analytics | **None** — node-link visualisation + GEXF export, but no centrality, shortest-path, community detection, or cross-scan correlation |
| Confidence model | Risk flags per data type; no calibrated, cross-source confidence tiering |
| Interfaces | Web UI, CLI (`sfcli`), REST-style API |
| Storage | SQLite |
| Constrained-env focus | General desktop/server; not optimised for Termux Android aarch64 (no-root) |

These are SpiderFoot's documented, real characteristics. The columns below show where HSE
already exceeds them, and the one place it does not yet.

---

## 2. Dimension-by-dimension (the directive's benchmark axes)

Each HSE claim links to the code that makes it true.

### 2.1 Multi-hop discovery depth — **HSE supersedes (capability)**
- *SpiderFoot:* spiders and expands, but exposes no depth metric and offers **no
  pathfinding** — you cannot ask "how is A connected to B?" or "how deep does the seed
  reach?".
- *HSE:* `core::path` finds the shortest connection chain **and** edge-disjoint
  alternatives between any two entities — **within a scan and across the whole local
  database** (`connect_cross_scan`) — and `core::metrics::reachability` reports the
  seed-anchored per-hop discovery-depth histogram (`reached_at_hop`, `max_depth`).
  HSE both *traverses* and *quantifies* multi-hop; SpiderFoot does neither.

### 2.2 Relationship accuracy / false-positive reduction — **HSE supersedes (capability)**
- *SpiderFoot:* binary, rule-based correlation; no calibrated confidence.
- *HSE:* a cross-source confidence model (`c_effective`, VERIFIED/PROBABLE/CANDIDATE
  tiers, multi-source corroboration) plus precision-gated derivation — namesake demotion
  (`geo_family`), distinctive-surname weighting (`util::surnames`), and crowd-caps that
  drop privacy-proxy registrants and directory pages (`derive_shared_selector`,
  `derive_co_mention`). Accuracy is *scored*, not assumed.

### 2.3 Graph completeness / coverage — **HSE supersedes (capability)**
- *SpiderFoot:* edges come from its correlation rules; results are largely a flat list.
- *HSE:* 14 relation builders emit 12 typed relation kinds — infrastructure (subdomain,
  DNS, WHOIS), identity (handles, ownership, residency), and human-network (kinship,
  co-residence, **co-mention**, **shared-selector affiliation**, **`SameAs` reflexive
  identity**) — fed by a cross-scan historical flywheel (recurrence → co-occurrence →
  relation recall). Coverage is measured by `linked_entity_fraction`, `graph_density`,
  and `reachable_fraction`.

### 2.4 Graph intelligence — **HSE supersedes (capability; SpiderFoot has none)**
- *HSE only:* betweenness-centrality **pivot detection** (`core::pivot`), exact
  **cut-vertex & bridge analysis** (`core::graph`, one iterative Hopcroft–Tarjan pass)
  that names the network's *single points of failure* — the entities and the lone links
  whose removal fragments the graph, the sharp binary question betweenness only
  approximates — **community detection** (`core::community`, label propagation), **trust
  propagation** (`core::trust`, damped personalized-PageRank), and **near-duplicate
  resolution** (`core::resolve`). All read structural intelligence off one shared,
  deterministic graph primitive (`core::graph`). SpiderFoot ships no equivalent.

### 2.5 Scan speed / efficiency & 2.6 Resource usage — **HSE supersedes (structural; figure pending A/B)**
- *SpiderFoot:* Python interpreter + dependency tree.
- *HSE:* a single static **Rust** binary (edition 2024, `#![forbid(unsafe_code)]`) with
  bounded-concurrent dispatch and an ROI marginal-yield cutoff (`core::roi`). Rust vs
  Python and static-binary vs interpreter+venv are verifiable architectural facts that
  make HSE structurally leaner and faster; the *measured* multiplier is an A/B output,
  not asserted here.

### 2.7 Constrained-environment scalability — **HSE supersedes (capability)**
- *HSE:* first-class **Termux Android aarch64, no-root** target — bounded recursion and
  memory, no native-root assumptions, deterministic execution (≈3 358 tests pin
  byte-identical output). This is HSE's design centre and outside SpiderFoot's.

---

## 3. Honest gap — where HSE does **not** yet clearly supersede

**Raw data-source breadth.** SpiderFoot's ~200 modules exceed HSE's **128**. SpiderFoot
integrates more third-party APIs by sheer count. HSE deliberately trades count for a
free/keyless-first posture *and* the graph-intelligence layer above (more *insight per
data point*), but the integration-count gap is real and is the standing item to close:
add high-value collectors over time without regressing the keyless-first or determinism
guarantees. This gap is tracked here precisely so HSE's superiority claim stays honest.

---

## 4. How superiority is measured

HSE ships the reproducible instrument: **`hse benchmark [--scan-id <id|latest>] [--json]`**
(and `GET /api/v1/scans/{id}/benchmark`) emits a consolidated scorecard — discovery depth,
graph coverage, corroboration, density, structural fragility (cut vertices / bridges),
throughput, module reliability, pivot count — across the axes above.

A formal A/B is: run SpiderFoot and HSE on an **identical seed under identical network
conditions**, capture each tool's scorecard, and diff field-by-field
(`hse benchmark --json > hse.json`). HSE wins the *capability* axes (§2.1–2.4, 2.7) by
construction; the *performance* axes (§2.5–2.6) are confirmed by that run. This document
records the structural case; the live A/B records the numbers.

---

## 5. Maintenance

Update this file whenever a release changes the comparison: a new graph primitive
strengthens §2.4, new collectors narrow §3, and an executed A/B replaces "pending" in
§2.5–2.6 with a cited measurement. The superiority claim is only as honest as this
document is current.
