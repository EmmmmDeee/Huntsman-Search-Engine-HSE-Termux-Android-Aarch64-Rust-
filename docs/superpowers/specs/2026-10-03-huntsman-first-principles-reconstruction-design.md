# Huntsman First-Principles Reconstruction Design

Date: 2026-10-03
Status: design specification
Scope: architecture and migration contract; no implementation changes

## 1. Objective

Reconstruct Huntsman into the strongest verifiably achievable local-first evidence-retrieval and investigation system for unprivileged Android/Termux ARM64 and conventional Linux/Railway deployment.

The system MUST maximize verified system-wide capability and long-term value rather than module count, row count, provider count, code reuse, or architectural novelty.

Preserve proven capability, evidence, data, tests, provenance, domain knowledge, and operational lessons. No implementation, abstraction, dependency, directory structure, algorithm, or architectural choice survives merely because it already exists.

## 2. Hard constraints

1. Rust implementation for the deployed engine; no runtime LLM dependency.
2. One deployable primary binary for Termux, even if the source becomes a workspace.
3. No root requirement on Android.
4. Evidence and provenance MUST survive normalization and derivation.
5. Derived, duplicated, mirrored, aggregated, or correlated material MUST NOT manufacture independent evidentiary roots.
6. Credentials MUST NOT cross an origin or authority boundary without explicit authorization.
7. Consequential policy and invariants MUST be non-bypassable by provider adapters or presentation layers.
8. Unknown state MUST remain unknown; absence of evidence is not evidence of absence without a demonstrated coverage model.
9. Capability claims MUST be bounded to the verification state actually demonstrated.
10. Migration MUST preserve valuable proven behavior or explicitly record why it is intentionally superseded.

## 3. Acceptance criteria

The reconstruction is accepted only when:

- every material capability has one explicit owner and contract;
- every material current/legacy component has a recorded disposition: PRESERVE, MIGRATE, REIMPLEMENT, REPLACE, or REMOVE;
- raw acquisitions are immutable or content-addressed before normalization where source terms permit retention;
- observations, assertions, inferences, and claims are distinguishable in the data model;
- independent evidence roots are explicitly modeled and ancestry is preserved;
- provider policy covers authentication, egress, rate/quota, spend, retention, display, export, and redistribution constraints;
- provider selection can use measured marginal value rather than static module priority alone;
- provider overlap and aggregator information loss are measurable;
- interrupted writes and process failure cannot silently corrupt accepted state;
- consequential execution can be deterministically replayed from recorded inputs where feasible;
- CLI and local Web UI use the same application/domain services;
- external formats such as STIX, ATT&CK Navigator, SpiderFoot, or Maltego are adapters over canonical internal state, not internal truth models;
- Linux tests, Android cross-build checks, and actual Termux handset verification are distinct proof states;
- no obsolete compatibility or transitional path remains after its replacement satisfies its proof obligations;
- no known feasible alternative offers materially greater verified system-wide value at acceptable cost/risk.

## 4. Target capability model

Huntsman is organized around capabilities, not provider modules.

Required first-class capabilities:

1. **Acquisition** — obtain bounded responses/artifacts from local sensors, public sources, APIs, files, and authorized providers.
2. **Evidence preservation** — retain source identity, upstream lineage, timestamps, hashes, and acquisition context.
3. **Normalization** — convert provider-specific responses into typed observations without creating new evidence roots.
4. **Entity extraction** — derive canonical entities and relationships while retaining raw values.
5. **Ancestry and independence** — track derivation DAGs and determine genuinely independent root support.
6. **Resolution** — merge or link identities only under explicit non-compensatory policies and defeater checks.
7. **Correlation** — discover useful relationships without confusing correlation with corroboration.
8. **Planning** — select the next action/provider by expected decision value, cost, freshness, novelty, optionality, and uncertainty reduction.
9. **Policy** — enforce egress, authorization, licensing, cost, caching, retention, and export rules before execution.
10. **Persistence** — provide crash-safe structured state, immutable raw evidence, schema migration, and deterministic export.
11. **Verification** — expose machine-readable proof obligations and verification states.
12. **Interop** — emit external formats only from evidence-gated canonical state.
13. **Presentation** — CLI and local Web UI as thin clients of one application service.
14. **Platform integration** — isolate Termux/Linux/Railway-specific sensors and system services behind narrow traits.

## 5. Architectural boundaries

Adopt a Rust workspace as compile-time architecture while retaining one primary deployable binary.

Proposed boundaries:

```text
crates/
  hse-domain       stable domain vocabulary and canonical types
  hse-evidence     artifacts, observations, assertions, inference, ancestry
  hse-policy       authorization, egress, spend, retention/export/licensing gates
  hse-provider     provider contracts, manifests, adapters, normalization boundary
  hse-runtime      bounded execution, scheduling, cancellation, retries, circuits
  hse-planner      adaptive action selection and provider tournament logic
  hse-graph        entity/relation graph and indexing
  hse-resolution   identity/entity resolution and defeaters
  hse-store        persistence, journal, immutable artifacts, migrations
  hse-formats      STIX, ATT&CK Navigator, SpiderFoot, Maltego, JSON/CSV adapters
  hse-platform     Termux/Linux/Railway platform capabilities
  hse-testkit      deterministic transports, fixtures, replay, fuzz/property helpers
  hse-app          application service used by CLI and Web UI
```

This decomposition is a target, not dogma. A boundary survives only if it reduces coupling, improves testability/replaceability, or protects an invariant. Boundaries that do not earn those benefits MUST be merged.

## 6. Core contracts

### 6.1 Acquisition contract

A provider or local source may return only acquisition results and typed observations. It MUST NOT directly create trusted entities, corroboration counts, verified claims, or ATT&CK assertions.

Conceptual contract:

```rust
trait Provider {
    fn capabilities(&self) -> &ProviderCapabilities;
    fn plan(&self, selector: &Selector, ctx: &ExecutionContext) -> Result<QueryPlan>;
    fn execute(&self, plan: &QueryPlan, transport: &dyn Transport) -> Result<ProviderResponse>;
    fn normalize(&self, response: ProviderResponse) -> Result<Vec<Observation>>;
}
```

Exact Rust signatures are deferred to implementation planning; semantics are normative.

### 6.2 Evidence contract

Separate:

- **Artifact** — immutable acquired material or content-addressed external reference.
- **Observation** — directly observed fact extracted from an artifact/source response.
- **Assertion** — normalized proposition supported by one or more observations.
- **Inference** — proposition derived through explicit reasoning/transformation.
- **Claim** — proposition admitted under a proof policy.

Every downstream object MUST remain traceable to its root acquisition(s).

### 6.3 Evidence-root contract

Each root records, where available:

```text
root_id
acquisition_id
provider
upstream_provider
upstream_dataset
original_source
provider_record_id
artifact_hash
source_uri
observed/event time
source publication time
provider ingest time
retrieved time
query/selector
provenance chain
```

A transformation edge changes representation, not independence.

### 6.4 Policy contract

Policy is consulted before execution and before retention/export. It governs:

```text
query authorization
authentication authority
egress destination
redirect handling
rate/quota budget
monetary budget
retry permission
cache permission
raw-body retention
field display
artifact export
redistribution/OEM rights
recursive pivoting
```

Provider adapters MUST NOT bypass policy.

### 6.5 Verification contract

Track at least:

```text
CLAIMED
IMPLEMENTED
UNIT_VERIFIED
INTEGRATION_VERIFIED
PLATFORM_VERIFIED
LIVE_OBSERVED
OPERATIONALLY_VERIFIED
```

A capability may advance only when claim-specific proof obligations are satisfied.

## 7. Invariants

1. One underlying evidentiary root counts at most once for independent corroboration.
2. Missing/unknown ancestry fails closed for claims that require independent roots.
3. Credentials discovered in evidence are not authentication authority.
4. Authentication material never follows a redirect across an unauthorized origin.
5. A challenge/WAF/rate-limit page is not a positive result.
6. HTTP success alone is not evidence of semantic success.
7. Failed or partial parsing is never silently converted to a valid-zero result.
8. Provider record volume is not a confidence multiplier without independence evidence.
9. Inference never upgrades the directness of its premises.
10. External interoperability mappings require explicit implemented bindings.
11. Persistent writes used for accepted state are atomic or transactional and corruption-detectable.
12. Release/platform claims must name the platform and verification level actually exercised.

## 8. Provider model

Replace descriptive-only provider metadata with a versioned executable capability/policy manifest.

Required fields include:

```text
provider identity and API version
supported selectors
returned evidence classes
authentication scheme
query and pagination semantics
rate/quota semantics
cost model
historical depth
provenance granularity
known upstream relationships
cache permission
retention permission
display permission
export permission
redistribution/OEM permission
terms/source URLs and review date
schema version
last fixture validation
last live validation
```

Static priors MAY cold-start planning but MUST yield to measured performance.

## 9. Adaptive execution model

Do not fan out indiscriminately.

The planner selects actions using expected marginal value derived from:

- probability of a novel independent root;
- expected information/decision value;
- freshness advantage;
- provenance quality;
- selector relevance;
- measured reliability;
- overlap with already queried providers;
- monetary and quota cost;
- latency and resource cost;
- downstream optionality;
- uncertainty reduction.

Provider lifecycle:

```text
UNVERIFIED -> PROBE -> SHADOW -> CHALLENGER -> CORE
                         |          |          |
                         v          v          v
                      DEGRADED -> DORMANT -> REJECTED/QUARANTINED
```

Transitions require measured evidence, not labels.

## 10. Aggregator and overlap analysis

The engine MUST distinguish query provider from upstream evidence source.

For upstream data available both directly and through an aggregator, compute retention/coverage metrics such as:

```text
aggregator retention = useful upstream information retained indirectly
                       / useful upstream information available directly
```

The metric MUST include field richness, freshness, provenance, pagination/coverage, and artifact availability, not row count alone.

A duplicated record observed through multiple aggregators remains one root unless independent acquisition can be demonstrated.

## 11. Persistence model

The existing bounded JSON session store is suitable evidence for safe small-state persistence but is not presumed sufficient for the full engine.

Target persistence consists of:

1. immutable/content-addressed raw-artifact storage where permitted;
2. append-only acquisition/event journal;
3. transactional structured indexes/materialized views;
4. explicit schema versioning and migrations;
5. deterministic export/replay metadata.

Candidate storage engines MUST be benchmarked on Termux/Linux for crash recovery, corruption behavior, memory use, binary size, migration complexity, and indexed performance before selection. Familiarity is not sufficient justification.

## 12. Runtime/network model

The current blocking `ureq` model is a hypothesis, not a permanent constraint.

Compare at minimum:

- bounded blocking worker-pool design;
- bounded asynchronous design with equivalent rustls/TLS policy.

Measure on representative Android/Linux conditions:

```text
RSS
binary size
CPU/battery proxy
connection reuse
p50/p95 latency
throughput under slow endpoints
cancellation behavior
failure isolation
implementation complexity
cross-build reliability
```

Retain whichever produces greater verified net value. No async or blocking ideology.

## 13. Cryptography and ledger

Preserve the versioned hash-chain ledger semantics if they continue to satisfy proof needs.

Challenge the custom in-tree SHA-256 implementation against a mature pure-Rust cryptographic implementation. Existing ledger versions MUST remain independently verifiable. Any algorithm or serialization change requires a new explicit ledger version; never silently reinterpret historical hashes.

## 14. Application and presentation

`hse-app` owns use-case orchestration. CLI and Web UI call the same application layer.

No evidence, policy, provider-selection, identity-resolution, or claim-admission rule may exist only in CLI or UI code.

## 15. External interoperability

STIX, ATT&CK Navigator, SpiderFoot, Maltego, MISP-like, CSV, JSONL, and graph exports are adapters over canonical internal state.

External schemas MUST NOT define internal truth. ATT&CK technique claims remain explicitly bound and evidence-gated.

## 16. Platform boundary

Platform-dependent functionality is isolated behind narrow contracts such as:

```text
NetworkTransport
SensorProvider
LocationProvider
WifiProvider
BleProvider
Filesystem
Clock
RandomSource
```

Provide Termux/Linux implementations and deterministic test doubles as required. Core evidence/planning logic MUST not depend on Termux APIs directly.

## 17. Verification architecture

Replace the large hand-wired CLI `check()` as the long-term proof owner with a machine-readable proof registry while preserving its verified invariants.

Each proof obligation records:

```text
id
requirement
claim
required evidence level
test/measurement source
dependencies
failure semantics
last verified commit/platform
known limitations
```

Expose verification through one application capability, e.g. `hse verify`, with machine-readable output.

Tests are organized by purpose:

```text
contract/
property/
differential/
provider/
integration/
replay/
platform/
acceptance/
```

Add fuzzing and malformed-response fixtures to parser boundaries as implementation reaches them.

## 18. Platform proof ladder

Treat these as distinct states:

```text
Linux unit/integration tests
-> Android aarch64 cross-build
-> ELF/interpreter verification
-> Termux install
-> on-device self-test
-> on-device local integration tests
-> controlled live-provider probe
-> resource/performance benchmark
```

Cross-build success alone MUST NOT be described as Termux operational verification.

## 19. Initial disposition of current architecture

| Current element | Initial disposition | Reason |
| --- | --- | --- |
| `evidence_ancestry` semantics | MIGRATE/PRESERVE invariant | Correctly prevents mirrors/derivations manufacturing witnesses |
| non-compensatory identity merge gate | MIGRATE | Strong epistemic invariant |
| guarded egress | MIGRATE | Proven boundary worth preserving |
| credential-origin authority | MIGRATE | Prevents discovered secrets becoming authority |
| bounded/atomic filesystem helpers | PRESERVE/MIGRATE | Valuable low-level safety primitive |
| hash-chain ledger concept | PRESERVE, re-evaluate implementation | Useful proof primitive; crypto implementation remains challengeable |
| HIBP client | MIGRATE into provider architecture | Valuable implemented capability, wrong long-term ownership boundary |
| `ModuleSpec` | REPLACE | Metadata interface is not sufficient execution/evidence contract |
| current `ProviderDescriptor` | REIMPLEMENT | Preserve useful economics concepts; add rights/provenance/schema semantics |
| `service_defs.rs` | REPLACE | Mixes probe/auth/registry concerns and static endpoint knowledge |
| `Entity`/`Evidence` | MIGRATE/REIMPLEMENT | Strong provenance intent; split artifact/observation/assertion/inference semantics |
| JSON `Store` | PRESERVE for bounded session state; REPLACE as primary evidence store | Scope mismatch |
| `main.rs::check()` | MIGRATE to proof registry | Valuable checks, wrong architectural owner |
| flat `src/*.rs` namespace | REPLACE incrementally | Weak ownership/boundaries at current scale |
| one-crate source architecture | REPLACE if workspace boundaries pass value test | One deployed binary remains required |
| current CLI behavior | MIGRATE under acceptance/differential tests | Preserve proven UX/contracts, not implementation |
| Android CI | PRESERVE and extend | Strong existing proof asset |
| blocking-only network architecture | CHALLENGE | Must win benchmark rather than survive by assumption |
| custom SHA-256 | CHALLENGE, likely replace | Must justify bespoke cryptography |
| duplicated legacy archives/extractions in active tree | MIGRATE provenance then remove active duplication if recoverability remains guaranteed | Reduce search/cognitive contamination without losing evidence |

This table is provisional. Each row is subject to proof during implementation.

## 20. Migration strategy

Use a strangler reconstruction, not a flag-day rewrite.

For each coherent capability:

```text
DEFINE ACCEPTANCE
-> establish legacy/current baseline
-> implement target contract behind isolation boundary
-> differential/property/integration verification
-> falsification and regression checks
-> migrate valuable state
-> switch ownership
-> remove superseded path
```

No legacy path remains "temporarily" without an explicit retirement condition.

Do not migrate a subsystem merely because the target architecture names a crate for it. Migration begins only when the new boundary has a concrete acceptance advantage or protects a required invariant.

## 21. Goodhart and anti-proxy rules

The following are explicitly non-objectives unless they causally improve accepted outcomes:

- maximizing module/provider count;
- maximizing returned rows;
- maximizing code churn or percentage rewritten;
- maximizing test count/coverage percentage without stronger proof;
- maximizing abstraction/decomposition;
- maximizing benchmark throughput while harming correctness, provenance, or handset viability;
- preserving API compatibility with obsolete behavior absent demonstrated value;
- minimizing line count at the expense of explicit invariants.

Every optimization metric must retain a stated link to the true objective.

## 22. Failure model

The design assumes and tests for:

- malformed/truncated provider responses;
- HTTP/WAF/rate-limit/auth ambiguity;
- provider schema drift;
- stale or conflicting evidence;
- duplicated/syndicated upstream sources;
- process interruption during persistence;
- retry storms and circuit failures;
- clock/timestamp uncertainty;
- unavailable credentials or changed entitlements;
- resource pressure on low-memory Android;
- partial platform capability availability;
- corrupt or incompatible persisted state;
- invalid migration assumptions;
- planner priors becoming stale;
- metrics being gamed by high-volume low-value providers.

Failure MUST degrade explicitly and locally where possible; it must not silently upgrade evidence or fabricate completion.

## 23. Completion condition

The reconstruction is complete only when all material acceptance criteria are verified, all consequential retained elements have evidence-backed dispositions, transitional implementations are retired, platform claims are accurately bounded, and no remaining feasible action has positive expected net value material to the objective.

The governing principle is:

> Preserve the objective. Make every implementation and architectural choice—legacy or new—earn its place through evidence.
