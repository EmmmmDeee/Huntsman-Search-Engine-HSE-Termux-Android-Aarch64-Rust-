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
2. Attach evidence via `set_links` when a real defensive evidence chain exists.
3. Use `invalidate_test` / `invalidate_freshness` / `invalidate_reproducibility`
   to demonstrate auto-downgrade.
4. Re-export Navigator JSON from the ledger — never hand-edit scores/colors.
5. Never promote via Coverage / module maps / REQ ledger.

Until a full evidence chain exists for a technique, **Verified count stays 0**.

## Limiting factor (post-v0)

v0's highest-impact limiting factor was **absence of this ledger**. After
accept, the next limiting factor is: **zero techniques with real evidence
chains** (`verified_count` stays 0 until a full chain exists).

**Recommended next claim (highest OSINT gain under constraints):** attach a
real in-tree test evidence chain for either a **people-centric identity**
claim (e.g. seed `T1589`) **or** a **GEOINT** claim (Termux location /
geo family), with `evidence_level >= IndependentCorroboration`. Do not expand
seed surface first; do not invent Verified from mapping alone.
