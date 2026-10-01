# ATT&CK Capability Ledger (v0) — HSE

Frontier **self-verifying capability claims** ledger for Huntsman Search Engine.
This is **not** an attack toolkit and does not implement offensive ATT&CK
techniques, payloads, phishing, host intrusion, ransomware, or C2.

## Frontier mandate

Build a **self-verifying** capability system, **not** a static coverage map.

Evidence chain per capability:

`OBJECTIVE → CAPABILITY → METHOD → RUST COMPONENT → SOURCE → EXECUTION →
OUTPUT → PROVENANCE → CORROBORATION → TEST → BENCHMARK → REGRESSION →
VERIFIED STATUS`

Statuses: `VERIFIED` / `PARTIAL` / `UNVERIFIED` / `NOT APPLICABLE`

**NO SUFFICIENT EVIDENCE = NO VERIFIED CAPABILITY.**

`CapabilityStatus::Verified` cannot be set from static seed data. There is no
manual Navigator promotion API. Status is always computed by `derive_status`.
Evidence, dependency, **freshness**, or **reproducibility** failure
auto-downgrades a prior Verified derivation to Unverified.

## NEVER infer Verified from ATT&CK mapping alone

The following are **not** evidence that a capability is Verified:

| Artifact | Why it is not Verified |
|---|---|
| `Module::attack_techniques()` / module→technique maps | Structural reachability only |
| `core::attack::Coverage` / `coverage_fraction` / entity_count heat | Collection-reach map, not evidence chain |
| `core::attack::navigator_layer` | **Coverage heatmap** export (intensity), not ledger status |
| `docs/REQUIREMENTS_LEDGER.md` `VERIFIED` rows | Human REQ ledger — different domain |
| `core::assurance` Assured / maturity ladder | Control maturity, not ATT&CK capability rows |

**Coverage ≠ Verified.** ATT&CK is the **canonical interoperability map**, not a
methodological ceiling. Methods (D3FEND, STIX/TAXII, Bayesian, graph, geo,
temporal, VOI, …) may later compete via `CapabilityRow::method_id`; status
remains **derive-only** from evidence links.

## Separation from other ledgers

| System | Role |
|---|---|
| `core::capability` (this) | Self-verifying technique claims + derive_status + ledger Navigator |
| `core::attack::Coverage` + `attack::navigator_layer` | Recon collection-reach heatmap (keep both; do not replace) |
| `docs/REQUIREMENTS_LEDGER.md` | Human REQ-* verification notes |
| `core::assurance` | Domain control maturity ladder |

## Statuses

| Status | Meaning |
|---|---|
| Verified | Full mandatory evidence links present and healthy (incl. freshness + reproducibility) |
| Partial | Some but not all mandatory links |
| Unverified | In-scope claim without enough evidence, or hard failure (failed test / broken regression / stale / unreproducible) |
| NotApplicable | Explicitly out of product scope (omission ≠ N/A) |

Hard-fail fields on `CapabilityEvidenceLinks` (force Unverified):

- non-empty `failed_test_ids`
- `regression_ok == false` with any evidence activity
- `freshness_ok == false`
- `reproducibility_ok == false`

`freshness_ok` / `reproducibility_ok` default **true** on empty links so seed
rows stay Unverified (not hard-failed).

`Verified` also requires at least one `regression_lock_ids` entry. A bare
`regression_ok = true` with no lock artifact is not a REGRESSION link, so the
claim stays `Partial`.

## Evidence ladder (`EvidenceLevel`)

Claim strength is capped by `CapabilityEvidenceLinks::evidence_level`. Order
(weak → strong):

`Assertion < Derived < Primary < IndependentCorroboration < DirectObservation <
Reproduction < EndToEndDemonstration`

- Empty / seed links default to `Assertion`.
- v0 `Verified` requires **full mandatory links** **and**
  `evidence_level >= EvidenceLevel::MIN_FOR_VERIFIED`
  (`IndependentCorroboration`).
- `derive_status` never accepts `Verified` below that floor (even with complete
  link fields). Ladder ordering is covered by unit tests in `capability.rs`.

**Catalog presence ≠ capability. Mapping ≠ Verified.** ATT&CK catalogue
membership, `Module::attack_techniques()`, Coverage heatmaps, and Navigator
coverage export are not inputs to `derive_status`.

## Applicable scope (OSINT-first)

Default product surface: **OSINT in Rust** (passive recon / Termux sensing /
public harvest). A claim is InScope only when it can be **executed, tested, and
reproduced** under present constraints; otherwise leave Unverified or mark
NotApplicable.

Closed sources, active scanning, and credential collection are
`ClaimScope::NotApplicable` unless a lawful, testable in-tree method exists.
Omission ≠ N/A — N/A rows are curated stubs.

## Seed v0

`CapabilityLedger::seed_v0()` registers curated enterprise technique IDs as
**claim placeholders** with **empty** links:

- InScope OSINT / Termux / recon rows start **Unverified** (`verified_count() == 0`)
- NotApplicable stubs for phishing / cred dump / scripting / remote services /
  ransomware / C2 stay N/A even if links are later attached
- Every row has a `method_id` (e.g. `recon.collection`, `sensing.termux`) for
  future frontier method competition

Extend the seed only with defensive claim placeholders and corresponding Rust
component paths. Adding a technique never ships attack steps.

## Navigator (capability ledger layer)

`CapabilityLedger::navigator_layer(name, domain, version)` emits ATT&CK
Navigator layer 4.x compatible JSON (`serde_json::Value`). Colors/scores come
**only** from derived status. Label clearly: this is a **capability ledger
layer**, not a coverage heatmap.

| Status | Score | Color |
|---|---:|---|
| Verified | 100 | `#31a354` |
| Partial | 50 | `#fec44f` |
| Unverified | 10 | `#de2d26` |
| NotApplicable | 0 | `#bdbdbd` |

## How to extend

1. Add a `CapabilityClaimSpec` to `seed_v0` (or `insert_row` at runtime) with a
   `method_id` and optional `objective`.
2. Attach evidence via `set_links`, `apply_identity_geoint_evidence_v1`, or
   `apply_identity_evidence_v1` when a real defensive evidence chain exists.
3. Use `invalidate_test` / `invalidate_freshness` / `invalidate_reproducibility`
   to demonstrate auto-downgrade.
4. Re-export Navigator JSON from the ledger — never hand-edit scores/colors.
5. Content-address evidence with `evidence_links_content_hash` / `evidence_provenance_binding` when persisting or comparing chains (hash ≠ Verified).
6. Never promote via Coverage / module maps / REQ ledger.

Until a full evidence chain exists for a technique, **Verified count stays 0**.

## First OSINT evidence claim (GEOINT / T1614)

`seed_v0()` still ships **empty** links (`verified_count() == 0`). Attach the
first honest evidence chain with:

```rust
let mut ledger = CapabilityLedger::seed_v0();
apply_identity_geoint_evidence_v1(&mut ledger)?;
assert_eq!(ledger.status_of("T1614"), Some(CapabilityStatus::Verified));
assert_eq!(ledger.verified_count(), 1);
```

- **Winner:** offline GEOINT on `T1614` → `util/geo` + `util/geohash`
  (`method_id = geoint.offline`).
- **Evidence level:** `IndependentCorroboration` via two channels — coord parse
  / validity unit tests, and haversine Sydney↔Melbourne known-distance tests
  (no live network; no Termux device required).
- **Runner-up (first claim):** people-centric identity — landed as the second
  claim below after rebinding seed `T1589` off dirty `modules/stolen_tax`.
- **Not claimed:** live Termux location observation (needs device) — remains a
  separate Unverified sensing path.

`test_ids` are stable `module::tests::fn_name` strings matching real `#[test]`
functions. Invalidate any cited test → auto-downgrade (Navigator loses green).

v1 limits:

- `passed_test_ids` are declared by the fixture. The ledger does not run tests,
  so it does not read their results. A unit test in `capability.rs` checks that
  every cited `test_id` still resolves to a real `#[test] fn` in the tree. A
  failing cited test also fails `cargo test`, which is a merge gate. Binding
  status to an execution receipt (test output plus the tested revision) is
  future work.
- **Scope of a Verified mapping.** On `T1614` and `T1589`, Verified means the
  named offline *method* (`geoint.offline` and `identity.canonicalize`) is
  evidenced. It does **not** claim end-to-end *System Location Discovery* or
  *Gather Victim Identity Information*. ATT&CK is the interoperability key
  here, not a statement of full technique coverage (see "Mapping ≠ Verified"
  above).

## Second OSINT evidence claim (identity / T1589)

Seed `T1589` is **rebound** from `modules/stolen_tax` / `recon.breach` to
`util/canonical` / `identity.canonicalize` so Verified does not couple to dirty
breach WIP. Attach the second honest evidence chain with:

```rust
let mut ledger = CapabilityLedger::seed_v0();
apply_identity_evidence_v1(&mut ledger)?;
assert_eq!(ledger.status_of("T1589"), Some(CapabilityStatus::Verified));
assert_eq!(ledger.verified_count(), 1);

// Both claims:
apply_identity_geoint_evidence_v1(&mut ledger)?;
apply_identity_evidence_v1(&mut ledger)?;
assert_eq!(ledger.verified_count(), 2);
```

- **Winner:** offline identity canonicalize on `T1589` → `util/canonical`
  (`method_id = identity.canonicalize`).
- **Evidence level:** `IndependentCorroboration` via two channels — email
  mailbox fold (gmail/googlemail fixtures) and person-name tokenization
  (hyphen/apostrophe + edge-punctuation fixtures).
- **Runner-up:** `util/identity` demographic tags (`identity_tags`) — deferred
  (breach-schema oriented; lower independence vs email+name).
- **Rejected:** inventing Verified on dirty `modules/stolen_tax` / `recon.breach`.
- **Not claimed:** live breach harvest, credential collection, or network
  victim enumeration.

## Hashed evidence / provenance binding (v1)

Verified claims are no longer Assertion-tier on the **evidence-store** axis:
`CapabilityEvidenceLinks` are content-addressed.

```rust
use hse::core::capability::{
    evidence_links_canonical_json, evidence_links_content_hash,
    evidence_links_provenance_binding, apply_identity_geoint_evidence_v1,
    apply_identity_evidence_v1, CapabilityLedger,
};

let mut ledger = CapabilityLedger::seed_v0();
apply_identity_geoint_evidence_v1(&mut ledger)?;
apply_identity_evidence_v1(&mut ledger)?;

let h = ledger.evidence_content_hash("T1614").unwrap(); // 64-hex sha256
let b = ledger.evidence_provenance_binding("T1614").unwrap();
// b == "prov-geoint-offline-fixture-v1|sha256:{h}"
assert_eq!(h.len(), 64);
assert_eq!(ledger.verified_count(), 2); // hashing does not invent Verified
```

| API | Role |
|---|---|
| `EVIDENCE_CONTENT_HASH_SCHEMA` | `hse.capability.evidence_links.v1` schema tag |
| `evidence_links_canonical_json` | Deterministic JSON (fixed key order; vec order preserved) |
| `evidence_links_content_hash` / `CapabilityEvidenceLinks::content_hash` | SHA-256 lowercase hex of canonical UTF-8 |
| `evidence_links_provenance_binding` / `…::provenance_binding` | `{claim_id}\|sha256:{hash}` (or `sha256:{hash}`) |
| `CapabilityRow::evidence_content_hash` / `CapabilityLedger::evidence_content_hash` | Live row/ledger accessors (recomputed; no stale cache) |

**Competition (this pass):** (A) content-addressed hash of links — **winner**
(offline, sha2 already in-tree, tamper-falsifiable, Termux-safe); (B) minimal
STIX 2.x bundle export from Verified rows — deferred (interop value, larger
surface, does not bind evidence bytes as tightly); (C) reuse unrelated in-tree
sha2 fingerprints (`key_pool`, `query_pack`) — rejected (wrong domain).

**Honesty:** content hash is **not** an input to `derive_status`. Mutating any
hashed field changes the digest; apply helpers still derive Verified from
links alone. Seed `verified_count()` remains 0 until apply.

## Limiting factor (next)

After hashed-evidence binding: (1) only **two** Verified techniques (seed still
ships `verified_count() == 0` until apply); (2) Termux sensing claims
(`T1016.002` / related) need device or recorded sensor fixtures for
DirectObservation+; (3) minimal STIX 2.x export from Verified ledger rows still
absent; (4) breach-recon path remains unbound from Verified until a lawful
clean evidence chain exists outside dirty WIP.
