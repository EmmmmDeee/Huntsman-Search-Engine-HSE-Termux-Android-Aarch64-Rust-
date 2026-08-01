# The Ultimate Huntsman — Architecture & Capability Roadmap

**Status:** living design document · **Scope:** the whole engine ·
**Governing law:** [`OPERATIONAL_CONSTITUTION.md`](OPERATIONAL_CONSTITUTION.md),
[`PERSISTENT_INTELLIGENCE.md`](PERSISTENT_INTELLIGENCE.md), and
[`../SECURITY.md`](../SECURITY.md)

> This document separates **what exists today** (observation — verifiable in the
> running software: `hse modules`, `hse selftest`, `hse diagnostics`, the source
> tree) from **what is proposed** (the roadmap). A proposed capability is never
> described as if it already ships. Where a claim is quantitative it is either
> traceable to the code or explicitly marked as a target.

---

## 1. What "ultimate" means here

The brief is to make HSE *"the ultimate version … a more powerful and aggressive
alternative to SpiderFoot,"* on Termux/aarch64, no root, driven from a web UI, in
proficient Rust. Read against this repository's constitution, that resolves to a
precise, honest objective:

**Maximise the breadth, depth, recall, and *usefulness* of lawfully-collectable,
publicly-available intelligence per unit of on-device budget — and make every
result correlated, explainable, and interoperable — without ever adding
offensive capability.**

"Aggressive" is therefore a statement about **collection thoroughness and
analytic depth**, not intrusion:

| "Aggressive" **means** (in-scope) | "Aggressive" **never means** (out-of-scope) |
|---|---|
| More independent sources answering the same question | Unauthorised access / authentication bypass |
| Deeper autonomous pivoting and correlation | Exploitation, RCE, injection, credential *use* |
| Higher recall on public breach/paste/registry data | Mass-targeting, harassment, stalking infrastructure |
| Better ranking so the budget buys the highest-value leads first | Persistence, C2, malware, evasion of defences |
| Interoperability with the defensive TI ecosystem | Anything whose *primary* use is offensive |

This boundary is not a footnote — it is the product. See [§9](#9-anti-goals).

---

## 2. Current state (observed)

HSE is already a mature, single-binary OSINT/GEOINT/NETINT platform. The
following are observations from the source tree and the running CLI, not
aspirations:

- **~180 collection modules** behind one `Module` trait
  (`src/core/module/mod.rs`), registered in one place
  (`src/modules/mod.rs`); the authoritative list is `hse modules`. Coverage
  spans DNS/CT/WHOIS, IP/ASN/BGP infrastructure, breach/paste/stealer corpora,
  ~30 social/developer-profile platforms, corporate & sanctions registries,
  phone/email/name intelligence, geolocation (incl. keyless BSSID/cell), and
  on-device Termux sensors (GPS/Wi-Fi/cell/ARP).
- **Autonomous, depth-bounded expansion** with a wrong-identity gate, a proven
  halting bound, and a full *exclusion ledger* — every pivot the engine declines
  is recorded with a reason (`src/core/engine/`, `tests/halting.rs`).
- **A deterministic correlator** — 120+ rules, graph-aware, no LLM/fuzzy
  matching (`src/core/correlator/`).
- **Value-aware dispatch**: convex (barbell/optionality) budget allocation, ROI
  pruning, capability-aware skipping of provably-dead sources, and a live
  capability probe (`src/core/convex/`, `src/core/roi/`, `src/core/engine/health/`).
- **Embedded web UI** (`hse serve`, loopback-only) — a hand-rolled dark-console
  SPA with a D3 force graph, SSE live event log, and in-browser key management
  (`src/web/`, `src/api/`).
- **Storage & query**: SQLite via a `StoragePort` trait (Strangler-Fig
  decoupling), FTS5 cross-scan entity search, an inter-scan cache, and a raw
  response archive (`src/core/port/`, `src/storage/`).
- **Analysis & QA surfaces**: self-audit/scorecard, benchmark, gap analysis,
  diff, exposure index, and a self-diagnosing debug bundle.
- **Exports**: JSON, CSV, GEXF (Gephi), a JSON report, and full/debug dossiers —
  **and, as of this change, a STIX 2.1 bundle** ([§7](#7-shipped-in-this-change)).
- **Interoperability with MITRE ATT&CK**: the full Enterprise matrix is carried
  as static data and every finding is stamped inline with the Reconnaissance
  technique that collected it (`src/core/attack/`).
- **Hard architecture invariants**, enforced by `tests/architecture.rs` and
  `src/lib.rs`: `#![forbid(unsafe_code)]`; rustls + bundled-SQLite only (no
  OpenSSL, no C deps); **no AI/ML/LLM/vector/embedding runtime dependency** —
  every result is deterministic Rust reproducible on-device; layered dependency
  direction (`core → modules → util`, presentation is transport-only).

**Honest reading:** the Termux/no-root/web-UI/Rust constraints in the brief are
already satisfied to a high standard. The leverage for "ultimate" is therefore
*not* re-plumbing — it is **more and better collection, sharper correlation, and
first-class interoperability**, all within the invariants above.

---

## 3. HSE vs SpiderFoot — an honest comparison

| Dimension | SpiderFoot (OSS) | HSE today | Assessment |
|---|---|---|---|
| Deployment | Python daemon + web server | Single static Rust binary, Termux/aarch64 no-root | **HSE ahead** on-device |
| Module count | ~200 `sfp_*` | ~180 (`hse modules`) | Comparable; see [§4](#4-roadmap) |
| Recursion | Depth-bounded, event-typed | Depth-bounded **+ convex/ROI value ordering + exclusion ledger** | **HSE ahead** |
| Correlation | ~37 correlation rules (v4) | 120+ deterministic, graph-aware rules | **HSE ahead** |
| Determinism/repro | Not a design goal | Byte-deterministic exports; no AI runtime dep | **HSE ahead** |
| Data model | Event graph | Entity + typed-relation + evidence-chain graph | **HSE ahead** on provenance |
| Interop export | CSV/JSON/GEXF; **no STIX/MISP in OSS** | CSV/JSON/GEXF/report + **STIX 2.1** (this change) | **HSE now ahead** |
| TAXII / MISP push | HX (paid) only | Not yet (roadmap [§4.C](#c-interoperability--the-defensive-ti-ecosystem)) | **Gap → roadmap** |
| Passive DNS / CT breadth | Broad | Broad, but addable sources exist | Parity; [§4.A](#a-collection-maximise-breadth--recall) |
| Threat-actor / TTP modelling | Limited | ATT&CK-stamped findings | **HSE ahead** |

The takeaway is not "HSE wins everywhere" — it is that HSE's *architecture*
(deterministic, provenance-first, value-ranked, on-device) is a stronger base to
build "the ultimate version" on than a daemon-oriented scanner, and the
remaining gaps are concrete and addressable.

---

## 4. Roadmap — the tracks that make it "ultimate"

Each track lists *why it matters*, *what it adds*, and *how it stays inside the
invariants*. Tracks are independent; ordering within a track is priority.

### A. Collection — maximise breadth & recall

The single largest lever on "data retrieval to the fullest extent" is more
**independent, keyless** sources, because independent corroboration is what
turns a candidate into a verified finding under the correlator's math.

- **CommonCrawl URL index** (`commoncrawl`, keyless): query the CC index for
  every archived URL under a domain — a large endpoint/subdomain/parameter
  surface no single CT or scrape reaches. Fixture-tested parser; live fetch
  bounded like every other network module.
- **PeeringDB** (`peeringdb`, keyless) — **shipped** ([§7](#7-shipped-in-this-change)):
  ASN → operating organisation, website, IRR AS-SET, and network profile — the
  organisational attribution the BGP/RIR modules don't carry.
- **`.well-known` / security.txt / robots / sitemap / RSS discovery**
  (`well_known`, keyless): enumerate a domain's *declared* endpoints and contact
  channels — cheap, high-signal footprinting.
- **DNSBL / reputation-over-DNS** (`dnsbl`, keyless): parallel blocklist lookups
  for an IP/domain via DoH — reputation without an API key.
- **Favicon / content hashing for pivoting** (`favicon_hash`, keyless compute):
  emit an mmh3 favicon hash and common content hashes as *pivotable entities*
  (a Shodan/Censys favicon pivot the operator can run when keyed).
- **Certificate & CT breadth**: additional CT logs and reverse-cert pivots to
  raise subdomain recall.

*Invariant fit:* every item is public-data collection, keyless-first,
pure-Rust/rustls, and unit-tested against captured fixtures (no live network in
CI) — exactly how the existing ~180 modules are built and tested.

### B. Correlation & reasoning — sharper, still deterministic

- **Cross-scan entity resolution** at the store layer: promote the FTS index
  into a persistent identity graph so a new scan inherits corroboration from
  every prior scan of the same selectors (bounded, deterministic).
- **Temporal correlation**: first/last-seen deltas across scans surfaced as
  findings (account creation windows, infra churn) — the raw timestamps already
  ride on every entity/evidence record.
- **Confidence calibration report**: expose the `C_eff` inputs per finding so an
  analyst can audit *why* a tier was assigned (the data exists; this is a view).

### C. Interoperability — the defensive TI ecosystem

- **STIX 2.1 bundle export** — **shipped** ([§7](#7-shipped-in-this-change)).
- **MISP event export/push**: map entities/relations to MISP objects & galaxy
  clusters; optional push to a MISP instance the operator configures.
- **TAXII 2.1 collection endpoint**: serve a scan's STIX bundle over TAXII so a
  SIEM/CTI platform can *pull* on a schedule — turns `hse serve` into a TI feed.
- **OpenCTI / STIX round-trip**: verify ingestion against OpenCTI's connector.

*Invariant fit:* all serialisation is pure and deterministic; any push is an
explicit, operator-configured, outbound action gated like every other network
call (and, being outward-facing, confirmed before first use).

### D. Web UI — make the depth legible

- **STIX/MISP download + preview** (STIX download **shipped** in the header).
- **Saved investigations & watchlists**: a first-class UI over the existing
  `live`/`radar`/`diff` machinery, with change-diff alerting.
- **Graph analytics in-browser**: expose the already-computed k-core / coreness /
  articulation-point structure as filters, not just node colour.
- **Report builder**: one-click, redaction-aware client dossier (PDF/HTML) from
  the existing report renderer.

### E. Performance & resilience on-device

- **Adaptive concurrency** keyed to observed latency/battery (extends the
  existing Termux timeout caps).
- **Resumable scans** across process death (checkpoint the frontier) — critical
  on a phone Android may kill mid-scan.
- **Result-cache tiering** to spend paid quota only on genuinely-new selectors
  (the radar ledger already prototypes this).

---

## 5. Design principles the "ultimate version" must not break

1. **Determinism over cleverness.** Identical input ⇒ identical output. It is
   what makes findings auditable, diffable, and trustworthy. No runtime AI.
2. **Provenance is mandatory.** Every entity carries its evidence chain; every
   export can be traced to a source. New capability that can't explain itself
   doesn't ship.
3. **Keyless-first, on-device, no root, no C deps.** The phone is the target
   platform, not an afterthought.
4. **Value per unit budget.** A phone has finite battery, data, wall-time, and
   quota. Cheap high-optionality leads run before expensive terminal fan-out.
5. **Defensive-only, always.** [§9](#9-anti-goals).
6. **One trait, one registry.** A new source is a one-file `Module` addition;
   the engine learns nothing bespoke.

---

## 6. How a new capability lands (the contract)

A new collection module is, by construction, a small and safe change:

1. `src/modules/<name>/mod.rs` implements `Module` (`name`, `accepts`,
   `process`, `cost`, `category`, `description`, `produces`, `attack_techniques`).
2. `pub mod <name>;` + one `Arc::new(...)` in `src/modules/mod.rs`.
3. Fixture-based unit tests (no live network) + a live-drift test if it fetches.
4. CI (`cargo fmt` / `clippy -D warnings` / `cargo test` / the architecture &
   smoke guards) enforces descriptions, ATT&CK-id validity, registration, and
   the layering rules automatically.

Nothing else in the codebase needs to know the module exists — which is why
"more sources" is a *sustainable* way to grow, not a maintenance cliff.

---

## 7. Shipped in this change

Two concrete steps land with this document: **STIX 2.1 interop** (Track C) and a
new keyless **PeeringDB** collection module (Track A), plus the honest
API-validation approach that proves them.

### 7.1 PeeringDB — a new keyless API, incorporated & proven

`src/modules/peeringdb/` adds ASN → network-operator attribution: the operating
organisation's name, public website, IRR AS-SET, and network profile
(type/scope/peering-policy, announced-prefix counts), from the public,
keyless PeeringDB API (`/api/net?asn={n}`). It answers *"who runs this ASN?"* —
turning a bare `AS13335` discovered deep in an infrastructure sweep into a named
`Organisation` and a pivotable `Url` the corporate/people rules can pick up.

It is built to the module contract in [§6](#6-how-a-new-capability-lands-the-contract):
the response→entity mapping is a pure function (`net_entities`) unit-tested
against captured PeeringDB fixtures, so the integration logic is **proven
deterministically without a live call** — the same way every one of HSE's ~180
modules is tested. Registered in one line; the README count moves to 169.

### 7.2 STIX 2.1 interop

STIX 2.1 is the OASIS standard the defensive
TI ecosystem speaks (MISP, OpenCTI, TheHive, ATT&CK Workbench, every TAXII 2.1
server). Emitting it makes an HSE scan directly ingestible by an operator's
SIEM/CTI platform instead of hand-transcribed.

**What it does** (`src/core/stix/`, exposed via CLI and HTTP):

- `hse export <scan-id> --format stix` — byte-identical to the HTTP endpoint.
- `GET /api/v1/scans/{id}/stix.json` — client-safe download (source names
  redacted like every other web export).
- A **STIX** button in the web scan header, beside CSV/JSON/GEXF.

**Mapping** — each entity becomes the closest native STIX object (`ipv4-addr`,
`ipv6-addr`, `domain-name`, `url`, `email-addr`, `mac-addr`, `user-account`,
`autonomous-system`, `identity` for people/orgs, `location` for coordinates) or
a custom `x-huntsman-artifact` SCO otherwise; typed relations become
`relationship` SROs; correlator findings become `note` SDOs; a framing `report`
SDO ties the scan together, attributed to a stable HSE producer `identity`.
Every object also carries HSE's own confidence, classification, generation,
source-count, tags, and **ATT&CK technique ids** as STIX custom (`x_huntsman_*`)
properties, so no signal is lost.

**Why it's safe & in-invariant:** pure, offline, deterministic — **content-derived
UUIDs** (SHA-256 of each entity's own deterministic uid, shaped to a valid
UUIDv5) and **timestamps from the scan's own immutable clock**, so re-exporting
an unchanged scan is byte-identical and diffable. The serialiser lives in `core`
beside `gexf`, shared byte-for-byte between the CLI and the API. Referential
integrity is guaranteed (an SRO is emitted only when both endpoints are present;
a note only when ≥1 child survives), and it is covered by unit tests for shape,
mapping, determinism, and reference resolution.

### 7.3 Incorporating & proving the APIs — the honest method

The brief asks to *"incorporate and test/validate/prove all APIs that
supercharge HSE."* HSE already integrates a large external-API roster (the
keyless and key-gated providers in `hse modules`); "incorporate" here means
**grow that roster and prove every integration**. Two kinds of proof exist, and
this repository uses both — the constitution forbids substituting one for the
other or fabricating either:

1. **Deterministic proof of the integration *logic* (in CI, offline).** Every
   module's response→entity mapping is a pure function tested against captured
   provider fixtures — `net_entities` for PeeringDB, `asn_prefix_entities` /
   `ip_entities` for BGPView, and so on for all ~180 modules. This proves the
   parser, the field mapping, and the entity/evidence shape are correct *without
   a live call*, so CI stays hermetic and reproducible. Run it with
   `cargo test`.
2. **Live proof of the endpoint *liveness* (on-device, operator-run).** Whether
   a provider is actually up and unchanged is a runtime fact that a live request
   settles — which is why HSE already ships the machinery for it:
   - `hse doctor --live` / `GET /api/v1/capabilities/probe` — fires one bounded
     request per keyless module at its real endpoint and reports
     **alive / empty / unreachable / drift** per module.
   - `hse diagnostics` — environment + module self-test + search-engine liveness
     in one pass.
   - the cross-scan **scraper-health** signal + the system debug bundle — surface
     a provider that has silently drifted (completes but stopped returning data).

**What cannot be honestly done here, and isn't:** this development sandbox has no
operator API keys and its egress is proxied, so a *live* call to a third-party
provider cannot be exercised — and per the Operational Constitution, a live
result must never be *simulated* and presented as real. Live validation is
therefore delegated to the on-device tools above, which the operator runs where
the keys and network actually are. What *is* proven here, in-repo and re-runnable,
is the deterministic integration logic of every module — including the new
PeeringDB one — via `cargo test`.

---

## 8. Success measures

"Ultimate" is measurable, not vibes. The repo already carries the instruments
(`hse benchmark`, `hse audit`, `hse gaps`). Targets for the roadmap:

- **Recall:** more independent sources corroborating each verified finding
  (benchmark's corroboration dimension trends up).
- **Value density:** higher useful-entities-per-dispatch under a fixed phone
  budget (convex/ROI telemetry).
- **Interoperability:** a scan ingests cleanly into MISP/OpenCTI via STIX with
  zero manual fixup (validated against a real instance).
- **Explainability:** every exported finding traces to its evidence and its
  ATT&CK technique (already true; must stay true).
- **On-device robustness:** a long scan survives an Android background kill
  (resumable scans).

---

## 9. Anti-goals

Per [`../SECURITY.md`](../SECURITY.md) and `CLAUDE.md`, HSE is **defensive-only**.
The "ultimate version" explicitly does **not** add — and this document must not
be read as endorsing — any capability whose primary purpose is:

- unauthorised access, authentication bypass, or exploitation;
- credential *use* (as opposed to lawful exposure assessment), password
  cracking-as-attack, or account takeover;
- persistence, command-and-control, malware, or defence evasion;
- mass-targeting, harassment, stalking, or surveillance of individuals without a
  lawful basis.

Collection is bounded to lawfully-accessible, publicly-available information.
Every scan requires the operator to have a lawful basis. Power here is *breadth,
depth, correlation, and interoperability* — never intrusion.

---

*This is a design document. Proposed items are proposals until they ship with
code and tests; when one lands, move it into [§2](#2-current-state-observed) and
cite the module/test that proves it.*
