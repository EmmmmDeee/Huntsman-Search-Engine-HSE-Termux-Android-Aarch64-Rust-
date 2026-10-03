# Provenance-Rooted Claim Kernel — Design

Date: 2026-10-03
Status: canonical design candidate; implementation not yet begun
Baseline: `1ea6c3048e533829da37dc8f305efb7fa3037b19`

## 1. Objective

Reconstruct Huntsman's evidentiary decision kernel so that consequential claims advance only when explicit, versioned, claim-specific proof obligations are satisfied by auditable evidence. Preserve verified platform capability, legacy oracles, tests, provenance, guarded I/O/network boundaries, Android build proof, and domain logic; replace only semantics that cannot justify their claims.

The kernel optimizes for **justified decision state**, not provider count, retrieval count, finding count, confidence score, or module yield.

## 2. Non-goals

This design does not:

- create a second scheduler or replace the existing ROI/dispatch authority;
- restore the legacy monolith;
- create a parallel `evidence_fusion` truth system;
- make live provider access mandatory for tests;
- let provider-specific code decide claim truth;
- infer causal independence that the evidence cannot establish;
- use an LLM at runtime;
- claim handset execution from cross-compilation alone.

## 3. Constraints

1. Primary deployment remains unprivileged Android/Termux aarch64.
2. Runtime core remains deterministic Rust and bounded for mobile resources.
3. Existing guarded `egress` / `http` / `fetch` / `keys` ownership boundaries remain authoritative.
4. Existing legacy snapshots remain read-only differential oracles.
5. Unknown provenance, dependency, identity, chronology, scope, authority, applicability, or coverage remains unknown.
6. Missing information cannot strengthen a claim.
7. Duplicates, transformations, correlations, aggregation, or derivations cannot create independent evidence.
8. Consequential invariants must be enforced below provider and caller control.
9. Claim assessment must remain reproducible from evidence plus versioned reasoning policy.
10. Existing production behavior changes only after shadow comparison and claim-specific acceptance evidence.

## 4. Acceptance criteria

The reconstruction is accepted only when all of the following are demonstrated:

### 4.1 Epistemic correctness

- Unknown ancestry cannot increase independent support.
- Copying one artifact through N providers remains one evidentiary route.
- Derived assertions inherit roots, assumptions, dependency domains, temporal limits, and defeaters from their premises.
- No universal source-count threshold can verify a claim lacking a mandatory evidence class.
- Apparent conflicts are semantically and temporally classified before becoming contradiction/defeat.
- Removing provenance, adding uncertainty, truncating proof search, or invalidating premises cannot strengthen a conclusion.
- Negative evidence is admitted only when collection capability, applicability, scope, completeness, and temporal relevance justify it.

### 4.2 Traceability

Every consequential claim can expose:

- the exact proposition;
- governing predicate and verification-policy versions;
- supporting and defeating assertions;
- source artifacts and provenance roots;
- dependency domains;
- derivations and method versions;
- material assumptions;
- minimal proof environments;
- unresolved blockers;
- temporal and coverage state;
- conditions that would weaken, defeat, supersede, or falsify it.

### 4.3 Architectural integrity

- One canonical provenance authority exists.
- One canonical claim-assessment authority exists.
- Provider count remains diagnostic only.
- Confidence/utility scores may rank exploration but cannot directly promote claim truth.
- Intelligence reasoning exports blockers/information requirements to the existing ROI engine; it does not schedule collection itself.

### 4.4 Platform verification

- Host/MSRV tests, clippy, format, deterministic artifact checks, and Android aarch64 cross-build remain green.
- Android cross-build remains explicitly distinct from real Termux handset execution.
- Handset execution is not marked verified until actually executed on the target device.

## 5. Current-state disposition

### PRESERVE

- guarded network/credential/file I/O boundaries;
- immutable legacy archives and differential-oracle tests;
- `EvidenceAncestryGraph` fail-closed missing-parent/cycle handling and iterative traversal;
- ancestry-aware `IdentityResolutionDecision` non-compensatory merge gate;
- deterministic graph, timeline, metrics, coverage, assurance, dependency, ATT&CK, export, and utility components that already satisfy their local contracts;
- Android API-24 aarch64 cross-build/ELF/interpreter/checksum path;
- current ROI/termination ownership.

### MIGRATE

- `EvidenceAncestryGraph` into the single provenance authority;
- `IdentityResolutionDecision` onto claim/proof-policy consumption;
- current confidence/eval outputs into exploration and ranking inputs only;
- provider coverage into richer observation-capability semantics;
- rebuilt relation/correlator rules incrementally into typed assertions and claim contributions.

### REIMPLEMENT

- `SourceLineage` semantics;
- claim promotion/rejection;
- contradiction handling;
- proof-state representation;
- derived-evidence root propagation;
- negative-evidence admission;
- invalidation/truth maintenance.

### REPLACE

- `origin_id.unwrap_or(source_id)` as an independence key;
- universal `2 sources => Supported`, `3 + confidence => Verified` promotion;
- caller-supplied conclusion confidence as an adjudication gate;
- contradiction-present => automatic rejection;
- provider coverage expressed only as clean-negative/failed/not-attempted for epistemic use;
- duplicate ancestry representations that can drift independently.

### REMOVE

- provider count from epistemic promotion semantics;
- any future parallel evidence-fusion subsystem;
- any assumption that different providers or labels prove independent origin;
- any path where a derived assertion can increase provenance-root count.

## 6. First-principles model

The canonical flow is:

```text
COLLECTION
  -> RETRIEVAL ARTIFACT
  -> PROVENANCE DAG
  -> ASSERTION
  -> CLAIM CONTRIBUTION
  -> MINIMAL PROOF ENVIRONMENT
  -> VERSIONED CLAIM POLICY
  -> CLAIM ASSESSMENT
  -> BLOCKERS / ALTERNATIVES / COVERAGE
  -> DECISION-RELEVANT INFORMATION REQUIREMENTS
  -> EXISTING ROI ENGINE
```

No layer may silently collapse into another.

## 7. Core data contracts

### 7.1 RetrievalArtifact

Represents one retrieved object or response, not an independent witness.

Required properties:

- stable artifact id;
- provider/collector id;
- native record id when available;
- evidence class;
- retrieval time;
- content digest when safe and useful;
- provenance node id;
- parser/extractor version.

Provider replicas remain separate retrievals but may resolve to the same provenance root.

### 7.2 Provenance graph

`EvidenceAncestryGraph` becomes the basis of a richer provenance DAG rather than competing with `SourceLineage`.

A provenance node must distinguish at least:

- primary observation/artifact;
- dataset/corpus;
- publication/provider replica;
- deterministic derivation;
- retrieval.

It must preserve explicit parentage and known dependency domains. Missing parentage is unresolved, never converted to source independence.

The model may record known domains such as artifact, dataset, incident, upstream source, collector, sensor family, or derivation. It must not assert causal independence merely because no common cause is recorded.

### 7.3 Assertion

An assertion is a proposition extracted from an artifact or derived from other assertions. It is not yet an accepted claim.

Required fields include:

- assertion id;
- subject;
- versioned predicate id;
- object;
- temporal validity/observation time;
- extraction basis;
- artifact or premise references;
- provenance roots/dependency domains derived from the graph;
- method/version metadata.

### 7.4 Claim

A claim is the exact proposition under adjudication.

Claims use versioned predicate identifiers rather than arbitrary provider labels, for example:

- `artifact.contains_identifier`;
- `identity.account.exists`;
- `identity.account.used_by`;
- `identity.account.controlled_by`;
- `location.subject.resides_at`;
- `location.subject.observed_at`;
- `exposure.credential`;
- `exposure.session`;
- `organisation.domain.owns`.

The predicate registry defines subject/object types, temporal semantics, incompatibility rules, and verification-policy id.

### 7.5 ClaimContribution

Links an assertion to a claim and records its claim-relative evidentiary role.

It distinguishes support from defeat and records directness, identity binding, authority/applicability, temporal fit, and relevant assumptions. Source-level authority alone cannot automatically transfer to every proposition extracted from that source.

### 7.6 Defeaters

Defeat is structured, not a generic contradiction flag:

- `Rebut`: supports an incompatible proposition;
- `Undermine`: attacks a premise/source/artifact/identity binding;
- `Undercut`: attacks a derivation or reasoning method;
- `Supersede`: establishes a newer state without falsifying historical truth;
- `Compatible`: both propositions may hold;
- `UnknownRelation`: compatibility cannot yet be determined.

Only unresolved, claim-relevant defeats influence epistemic acceptance.

### 7.7 MinimalProofEnvironment

The proof environment is the minimal auditable justification for a claim state.

It contains:

- assertion ids;
- provenance-root ids;
- dependency-domain ids;
- derivation ids;
- material assumption ids.

Supersets that add no proving power are removed by subsumption. Alternative minimal environments are preserved independently.

### 7.8 Assumptions

Material assumptions are first-class and defeasible. Examples:

- two records identify the same subject;
- two corpus labels denote different origins;
- a record is current enough for a current-state claim;
- a parser field mapping is correct;
- provider provenance metadata faithfully identifies its upstream artifact.

An unresolved material assumption may block advancement where the governing policy requires its resolution.

## 8. Claim policy

Claim truth is not determined by a universal source threshold.

A versioned `VerificationPolicy` defines non-compensatory obligations such as:

- mandatory evidence classes;
- directness requirement;
- identity-binding requirement;
- temporal requirement;
- authority requirement;
- provenance-completeness requirement;
- minimum assumption-free proof environments when appropriate;
- admissible unresolved assumptions;
- required coverage conditions;
- consequence/criticality level.

Examples:

- `artifact.contains_identifier` may be established by one authenticated direct artifact assertion;
- `identity.account.controlled_by` requires control/ownership binding or equivalently strong claim-specific evidence;
- `location.subject.observed_at` requires fresh subject-locating evidence and cannot be satisfied by infrastructure location;
- a registry fact may be established by an authoritative primary registry record without arbitrary source-count padding.

Evidence quantity cannot compensate for a failed mandatory obligation.

## 9. Claim assessment

Do not use one scalar confidence as the truth authority.

Assessment keeps orthogonal states:

### Epistemic

- Candidate
- Supported
- Verified
- Contested
- Underdetermined
- Refuted

### Temporal

- Current
- Historical
- Stale
- Superseded
- Unknown

### Coverage

- Complete
- MateriallyComplete
- Partial
- Failed
- Unknown

The assessment also exposes satisfied obligations, blockers, minimal proof environments, defeaters, competing explanations, and reasoning-policy versions.

Exploration/ROI scores remain separate inputs to collection prioritization.

## 10. Proof invariants

These are non-bypassable:

1. **Unknown is non-positive.** Unknown ancestry or applicability cannot create support or independence.
2. **Duplication is idempotent.** Additional copies cannot strengthen proof.
3. **Derivation is non-generative.** `roots(output)` cannot exceed the union of premise roots.
4. **Information loss is non-strengthening.** Removing provenance, temporal context, or dependency information cannot strengthen a claim.
5. **Defeat is preserved.** Undefeated rebuttals, underminers, and undercutters cannot disappear inside aggregate scoring.
6. **Negative evidence is capability-gated.** No-result is negative evidence only when the source could observe the phenomenon under sufficient scope, completeness, and time relevance.
7. **Invalidation propagates.** A dependent conclusion cannot survive invalidation of a required foundation.
8. **Truncation is conservative.** Resource-bounded proof search may weaken or mark incomplete; it cannot strengthen.
9. **Policy is versioned.** Reproducibility requires both data and reasoning versions.
10. **Provider diversity is not proof diversity.** Provider count is diagnostic only.

## 11. Truth maintenance

Maintain reverse indexes from:

- artifact -> assertions;
- assertion -> contributions/claims;
- claim -> inferences/hypotheses;
- derivation/policy/provenance nodes -> dependants.

When a foundation changes, mark dependants dirty and recompute them deterministically. Recompute only the affected subgraph where possible.

An assessment must never retain a stronger state after its surviving proof environments cease to satisfy policy.

## 12. Coverage and negative evidence

Replace binary provider coverage for epistemic use with an observation-capability record that can represent:

- evidence classes the source can observe;
- query/subject scope;
- temporal scope;
- completeness/partiality;
- freshness;
- outcome: positive, clean negative, partial, failed, not attempted, not applicable.

A clean negative affects a claim only when the policy deems that source capable and the specific query sufficiently covers the proposition.

Collection failure remains failure, not negative evidence.

## 13. Hypotheses and discrimination

For material ambiguity, retain viable competing explanations rather than only accumulating confirmation for the leading one.

Blockers and alternatives produce decision-relevant information requirements. The intelligence kernel exports these requirements; the existing ROI engine ranks actions.

An action is dominated when no plausible result can:

- satisfy a mandatory obligation;
- change a consequential claim state;
- remove a material assumption;
- resolve provenance/dependency;
- defeat or establish a viable alternative;
- resolve a material defeater;
- close consequential coverage.

No new scheduler is introduced.

## 14. Resource model

Proof reasoning must remain bounded for Termux.

Use deterministic maps/sets where serialized order matters and indexed graph traversal with memoized/root-set computation. Avoid pairwise O(n^2) lineage comparison when a graph/index can answer the same question linearly or near-linearly.

If minimal-environment enumeration threatens combinatorial explosion, apply deterministic limits to environment count/cardinality/derivation depth. Crossing a limit marks the assessment incomplete; truncation cannot promote a claim.

## 15. Migration boundary

Do not flip production semantics immediately.

### Phase A — semantic repair

- introduce failing tests proving unknown ancestry currently over-credits independence;
- route independence queries through the canonical provenance graph;
- remove `source_id` fallback as proof of independence;
- prevent conclusion-confidence/source-count promotion from being treated as proof.

### Phase B — typed assertions and policy

- add predicate registry, assertions, contributions, proof obligations, and assessments;
- adapt current intelligence records into the new model;
- retain current live behavior as the comparison baseline.

### Phase C — shadow adjudication

Run legacy/current and new assessment paths over the same fixtures/scans. Compare:

- promotions/demotions;
- unresolved ancestry;
- duplicate-source collapse;
- contradiction classification;
- identity-resolution outcomes;
- computational cost;
- regressions in useful recall.

Do not migrate production promotion until differences are understood and accepted claim-by-claim.

### Phase D — production cutover

Only after acceptance evidence:

- make claim policy the sole epistemic promotion authority;
- keep confidence/ROI for exploration and prioritization;
- retire superseded source-count promotion paths;
- preserve compatibility readers only where migration requires them.

## 16. First decisive falsification tests

### Test 1 — unknown ancestry must not create independence

Given:

```text
A.source_id = provider-a; A.origin = UNKNOWN
B.source_id = provider-b; B.origin = UNKNOWN
```

Both support the same claim.

Required: independent support does not become `2`; the assessment exposes unresolved ancestry and cannot advance solely because the source ids differ.

### Test 2 — missing evidence class cannot be compensated by count

Given three or more supporting records and any caller-supplied confidence, a claim whose policy requires an unsatisfied mandatory evidence class must not become Verified.

### Test 3 — disagreement is not automatically rejection

A temporally compatible or differently scoped assertion must classify as compatible/superseding/underdetermined as appropriate, not automatically reject the claim.

### Test 4 — derived support cannot manufacture roots

For every derived assertion, output roots are a subset of the union of premise roots.

### Test 5 — information loss cannot strengthen

Removing provenance, adding unknown dependency, truncating proof search, or invalidating a premise must never increase epistemic state.

These tests precede implementation and become permanent regression properties.

## 17. Verification matrix

A claim of completion requires fresh evidence for each applicable layer:

1. Unit/property tests for invariants.
2. Differential tests against preserved legacy/current oracles.
3. Integration tests for artifact -> provenance -> assertion -> claim flow.
4. Determinism/reproducibility tests for policy/versioned assessments.
5. `cargo test --locked`.
6. `cargo clippy --all-targets -- -D warnings`.
7. `cargo fmt --check`.
8. `cargo run --locked -- check` with `git diff --exit-code -- var/`.
9. Android aarch64 cross-build plus ELF/interpreter/checksum verification.
10. Real Termux handset execution separately, when available.
11. Authorized live-provider tests only where needed to prove provider-specific behavior; offline fake-transport tests remain the default regression path.

Passing tests prove only what they exercise. Host, cross-build, handset, and live-provider evidence remain distinct verification states.

## 18. Superseded designs

This spec supersedes the earlier proposed standalone evidence-fusion v1/v2 designs and the intermediate v3-v5 formulations. Their useful principles are incorporated here, but they are not separate implementation targets.

The governing rule is:

> Prove claims; do not score them into existence. Preserve uncertainty, provenance, dependencies, assumptions, temporal meaning, defeaters, and derivation history. Advance only to the strongest state demonstrably supported by surviving minimal proof environments under the applicable versioned policy, and translate every material blocker into a decision-relevant information requirement for the existing ROI engine.
