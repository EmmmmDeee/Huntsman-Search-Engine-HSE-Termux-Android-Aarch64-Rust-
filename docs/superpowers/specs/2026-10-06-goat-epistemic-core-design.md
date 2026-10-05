# Huntsman GOAT Epistemic Core — Canonical Design

Date: 2026-10-06
Status: approved architectural direction; canonical superseding design candidate
Baseline inspected: `cc183b10810ab358837b90d25605bf436edd928d`
Supersedes where conflicting: `docs/superpowers/specs/2026-10-03-provenance-claim-kernel-design.md`
Preserves all stronger, compatible invariants from the 2026-10-03 design.

## 1. Objective

Turn Huntsman's existing provenance/claim machinery into one production-grade epistemic authority that can answer, reproducibly and conservatively:

1. what was attempted;
2. what was retrieved or observed;
3. what artifact or upstream origin the observation derives from;
4. what proposition the observation supports, defeats, or leaves unresolved;
5. whether an apparent negative result is actually admissible negative evidence;
6. whether two pieces of support are proven independent, known dependent, or unresolved;
7. what proof obligations remain unsatisfied;
8. what additional collection action could materially change the decision state.

The system optimizes for **verified decision quality**, not source count, finding count, HTTP success, visual similarity, provider diversity, confidence score, or raw recall.

## 2. Non-goals

This design does not:

- add a second truth system beside the existing provenance/claim kernel;
- add a second scheduler beside the existing ROI/dispatch authority;
- restore the legacy monolith;
- require an LLM at runtime;
- require a graph database, distributed log, or heavyweight event platform;
- claim that a successful query proves completeness of the searched universe;
- treat different providers, domains, labels, or root-family strings as automatic proof of causal independence;
- claim legal chain-of-custody merely because artifacts are hashed;
- make live external providers mandatory for deterministic tests;
- allow provider-specific code to decide final claim truth;
- allow missing information, truncation, or unknown provenance to strengthen a conclusion.

## 3. Existing verified foundation to preserve

The current repository already contains important pieces of the target architecture and they remain authoritative unless this design explicitly strengthens them.

### 3.1 Typed source outcomes

`src/source_outcome.rs` already distinguishes successful retrieval, validated zero, auth failures, WAFs, transport failures, drift, anomalies, dead sources, and inconclusive outcomes. It correctly refuses to treat an unvalidated zero or HTTP 2xx as verified success.

Preserve this boundary. Retrieval outcome remains a statement about execution, not claim truth.

### 3.2 Provider-neutral collection envelopes

`src/collection.rs` already separates collection events from raw observations. Preserve this separation and extend it rather than replacing it.

### 3.3 Mandatory evidence provenance

`src/entity.rs` already makes provenance mandatory for evidence records. Preserve the canonical source-family hardening and non-corroborating-source rules.

### 3.4 Canonical ancestry graph

`src/evidence_ancestry.rs` already prevents derivations without parents, fails closed on missing parents and cycles, canonicalizes source families, and collapses copied reports onto common ancestry when that ancestry is known.

Preserve iterative traversal, deterministic containers, and fail-closed behavior.

### 3.5 Claim-specific verification

`src/claim_policy.rs` already separates verification from exploration/confidence scoring and enforces explicit obligations such as minimum proven roots, resolved ancestry, required evidence natures, blocking defeaters, and proof-environment completeness.

Preserve the principle that confidence and provider count cannot directly promote claim truth.

## 4. Governing epistemic laws

These laws are non-bypassable below provider and caller control.

1. **Retrieval is not truth.** A successful fetch proves only that a retrieval contract succeeded.
2. **Zero is not universal absence.** A validated zero proves only that one sufficiently understood query returned no matching rows in its observable scope.
3. **Negative evidence is capability-gated.** A no-result can weaken a claim only if the source could have observed the proposition under adequate applicability, scope, completeness, temporal relevance, and query correctness.
4. **Unknown independence is not independence.** Lack of a recorded common cause cannot create independent support.
5. **Duplication is idempotent.** Copies, mirrors, reposts, transforms, screenshots, provider replicas, and repeated retrievals cannot manufacture additional proof roots.
6. **Derivation is non-generative.** A derived assertion cannot acquire provenance roots or evidentiary authority absent from its premises.
7. **Information loss is non-strengthening.** Removing provenance, scope, time, dependency, integrity, or method information cannot strengthen a claim.
8. **Truncation is conservative.** Resource bounds may weaken or mark incomplete; they cannot strengthen.
9. **Proof obligations are non-compensatory.** Quantity cannot compensate for a missing mandatory evidence class, identity binding, authority requirement, temporal condition, integrity requirement, or coverage condition.
10. **Defeaters survive aggregation.** Rebuttals, underminers, undercutters, and unresolved relations cannot disappear inside a scalar score.
11. **Invalidation propagates.** Dependent claims and derivations must weaken when required foundations fail.
12. **Policy is versioned.** Claim assessment is reproducible only from evidence plus explicit reasoning-policy versions.

## 5. Canonical architecture

```text
COLLECTION REQUEST
  -> RETRIEVAL ATTEMPT
  -> RETRIEVAL ARTIFACT / OBSERVATION
  -> PROVENANCE + DERIVATION DAG
  -> TYPED ASSERTION
  -> CLAIM CONTRIBUTION
  -> MINIMAL PROOF ENVIRONMENT(S)
  -> VERSIONED VERIFICATION POLICY
  -> CLAIM ASSESSMENT
  -> BLOCKERS / DEFEATERS / COVERAGE / ALTERNATIVES
  -> DECISION-RELEVANT INFORMATION REQUIREMENTS
  -> EXISTING ROI / DISPATCH ENGINE
```

No layer may silently collapse into another.

## 6. RetrievalAttempt: reproducible execution evidence

Introduce a canonical immutable retrieval-attempt record. `CollectionEvent` may remain the compatibility/runtime envelope, but every consequential attempt must be projectable into this richer record.

Required fields:

```rust
struct RetrievalAttempt {
    id: RetrievalAttemptId,
    scan_id: String,
    provider_id: String,
    surface: Option<String>,
    target_fingerprint: String,
    query_fingerprint: String,
    parent_artifact_id: Option<ArtifactId>,
    transformation: Option<TransformationRecipe>,
    started_at_unix: u64,
    finished_at_unix: u64,
    locale: Option<String>,
    region: Option<String>,
    interface_mode: Option<String>,
    collector_version: String,
    parser_version: String,
    outcome: SourceOutcomeKind,
    result_count: Option<u32>,
    truncated: bool,
    response_artifact_id: Option<ArtifactId>,
}
```

### 6.1 Query fingerprint

The query fingerprint must be derived from the normalized effective query contract, not merely a human-readable search term. Where applicable it includes:

- target;
- filters;
- pagination bounds;
- result mode;
- selected surface/endpoint;
- relevant region/locale;
- transformation/crop identifier;
- provider-contract version.

Secrets and bearer credentials must never enter the fingerprint material.

### 6.2 Transformations

A derived query asset such as an image crop, normalized phone number, OCR extraction, decompressed document, keyframe, resized image, or canonicalized identifier must name its parent artifact and deterministic transformation recipe/version where reproducible.

A transformation can create a new artifact but never a new evidentiary root merely by existing.

## 7. RetrievalArtifact: content-addressed observation objects

Introduce or complete one canonical artifact model representing retrieved or locally derived objects.

Minimum fields:

```rust
struct RetrievalArtifact {
    id: ArtifactId,
    sha256: String,
    byte_len: u64,
    media_type: Option<String>,
    observed_at_unix: u64,
    retrieval_attempt_id: Option<RetrievalAttemptId>,
    provenance_node_id: EvidenceNodeId,
    parent_artifact_id: Option<ArtifactId>,
    transform_version: Option<String>,
    storage_locator: Option<String>,
}
```

The artifact id should be deterministic where safe and practical. Raw content need not be retained indefinitely when privacy, storage, provider terms, or mobile constraints make retention undesirable; the metadata and digest remain sufficient for integrity checks when content retention is prohibited or unnecessary.

## 8. Provenance DAG: causal provenance, not label diversity

Evolve `EvidenceAncestryGraph` into the single canonical provenance authority rather than creating a parallel graph.

### 8.1 Node kinds

Add explicit semantic node kinds:

```rust
enum ProvenanceNodeKind {
    PrimaryArtifact,
    Dataset,
    Publication,
    ProviderReplica,
    Retrieval,
    Transformation,
    DeterministicDerivation,
}
```

### 8.2 Edge kinds

Where useful, distinguish relations such as:

- `RetrievedFrom`;
- `CopiedFrom`;
- `DerivedFrom`;
- `ExtractedFrom`;
- `PublishedFrom`;
- `TransformedFrom`;
- `ContainedIn`.

The initial implementation may encode edge semantics compactly if a richer edge object would create unnecessary migration cost, but the logical distinction must be preserved in the canonical model.

### 8.3 Independence state

Replace the assumption that disjoint recorded roots prove independence.

Canonical result:

```rust
enum IndependenceState {
    ProvenIndependent,
    KnownDependent,
    Unknown,
}
```

Rules:

- known shared provenance root -> `KnownDependent`;
- explicit, validated evidence of distinct causal origins -> `ProvenIndependent`;
- merely different provider ids, source-family labels, URLs, domains, datasets, or currently disjoint recorded root labels -> `Unknown` unless an independence rule/policy proves otherwise;
- missing ancestry -> `Unknown`;
- provenance cycle or invalid graph -> assessment error/fail closed, never independent.

The default system must prefer under-crediting independence to inventing it.

## 9. ObservationCapability: source capability contracts

Introduce versioned capability contracts describing what a source can and cannot observe.

```rust
struct ObservationCapability {
    provider_id: String,
    version: u32,
    observable_predicates: BTreeSet<PredicateId>,
    evidence_classes: BTreeSet<EvidenceNature>,
    subject_scope: SubjectScope,
    temporal_scope: TemporalScope,
    completeness: CompletenessClass,
    freshness: FreshnessClass,
    negative_evidence_capable: bool,
}
```

Capability contracts must be conservative. Unknown completeness remains unknown. Marketing claims or undocumented assumptions cannot silently become capability guarantees.

Provider drift can invalidate or downgrade capability state until reverified.

## 10. Negative-evidence admission

`SourceOutcomeKind::ValidZero` remains an execution outcome, not automatically negative evidence.

Introduce a claim-relative decision:

```rust
enum NegativeEvidenceDecision {
    Admissible,
    Inadmissible,
    Indeterminate,
}
```

A zero may become admissible negative evidence only when all policy-required dimensions are satisfied:

- the queried source is capable of observing the proposition;
- the target/query maps correctly to the proposition;
- temporal scope is relevant;
- coverage/completeness is sufficient;
- freshness is sufficient;
- the attempt was not truncated;
- the provider contract validated the zero;
- no material drift, WAF, auth, quota, parser, schema, or interaction failure contaminated the attempt;
- the governing claim policy permits negative inference from that capability class.

Examples:

- `HIBP returned zero breaches for this account at T` may be established when the query contract is validated.
- `This account has never appeared in any breach` is not established merely by a HIBP zero.
- `Reverse-image engine X returned no exact indexed match for crop Y at T` may be established.
- `This image has never appeared online` is not established by that result.

## 11. Assertions and claim contributions

Retain the 2026-10-03 typed-assertion model and make all provider output pass through it before consequential claim adjudication.

An assertion must identify:

- subject;
- versioned predicate;
- object/value;
- time or temporal interval;
- extraction/verification method;
- artifact/premise references;
- provenance node(s);
- relevant assumptions;
- integrity state;
- whether it is direct, derived, or negative evidence.

A `ClaimContribution` records claim-relative support or defeat and the dimensions that matter for that claim, including directness, identity binding, authority, temporal fit, applicability, and assumptions.

## 12. VerificationPolicy v2

Extend the current `VerificationPolicy` without reintroducing scalar truth scoring.

Target obligations:

```rust
struct VerificationPolicy {
    id: String,
    version: u32,
    required_evidence_classes: BTreeSet<EvidenceNature>,
    directness_requirement: DirectnessRequirement,
    identity_binding_requirement: IdentityBindingRequirement,
    authority_requirement: AuthorityRequirement,
    temporal_requirement: TemporalRequirement,
    provenance_requirement: ProvenanceRequirement,
    integrity_requirement: IntegrityRequirement,
    coverage_requirement: CoverageRequirement,
    independence_requirement: IndependenceRequirement,
    negative_evidence_policy: NegativeEvidencePolicy,
    admissible_assumptions: AssumptionPolicy,
    required_verification_methods: BTreeSet<VerificationMethodId>,
}
```

Compatibility fields from the current policy may remain while migration is in progress, but the verification-capable path must eventually use the richer obligations.

## 13. Orthogonal assessment state

Do not collapse truth into one confidence value.

A consequential claim assessment should expose at least:

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

### Provenance

- Resolved
- Partial
- Unknown

### Integrity

- Verified
- Unverified
- Failed

Exploration confidence remains permitted for ranking collection actions and UI prioritization only.

## 14. Defeaters and contradictions

Preserve structured defeat from the 2026-10-03 design:

- `Rebut`;
- `Undermine`;
- `Undercut`;
- `Supersede`;
- `Compatible`;
- `UnknownRelation`.

A disagreement is not automatically a contradiction. Temporal, scope, subject-resolution, and predicate compatibility must be evaluated before defeat affects the claim.

## 15. Proof environments

Continue using bounded minimal proof environments.

Each environment records only the material justification required for a claim state:

- assertion ids;
- provenance nodes/roots;
- explicit independence evidence where required;
- dependency domains;
- derivations;
- assumptions;
- coverage/capability predicates;
- integrity predicates.

Subsumed supersets are removed. Alternative minimal proof environments remain distinct.

If enumeration exceeds deterministic limits, mark proof incomplete and prevent strengthening.

## 16. Tamper-evident audit trail

For consequential artifact/provenance/assessment mutations, maintain an append-only digest chain over canonical audit records:

```text
entry[n].previous_digest = digest(entry[n-1])
entry[n].digest = SHA256(canonical(entry[n] without digest) || previous_digest)
```

This provides tamper evidence and reproducibility checks. It must be described as tamper-evident audit provenance, not automatically as legal chain-of-custody.

Audit-chain corruption must fail verification explicitly rather than being silently repaired.

## 17. Media and reverse-image intelligence as a consumer

The OSINT Combine lesson becomes a general consumer of the epistemic core rather than a special truth system.

Target image flow:

```text
input image
 -> SHA-256 / dimensions / media metadata
 -> EXIF/XMP/IPTC where present
 -> OCR / visible text / watermark candidates
 -> optional perceptual fingerprints
 -> deterministic derived crops / transforms
 -> retrieval attempts across available visual-search surfaces
 -> retrieved pages/assets
 -> provenance DAG
 -> chronology assertions
 -> exact/near/similar classification
 -> claim assessment
```

Required semantic distinction:

- exact/near duplicate evidence;
- visual similarity lead;
- OCR/text pivot;
- model hypothesis;
- page-containing-image evidence;
- earliest observed publication;
- confirmed/probable source only when proof obligations are satisfied.

`No exact matches` is never automatically `original`, `unique`, or `never published`.

External AI/geolocation predictions, when ingested, remain hypotheses or derived assertions requiring independent verification. Huntsman's runtime core remains LLM-free.

## 18. Resource model for Termux

The design must remain viable on unprivileged Android aarch64.

Prefer:

- safe Rust;
- SQLite for durable indexed state;
- compact typed ids;
- adjacency lists rather than a graph database;
- `BTreeMap`/`BTreeSet` where deterministic serialization matters;
- memoized root/dependency calculations;
- bounded proof-environment enumeration;
- incremental dirty-subgraph recomputation;
- optional artifact-body retention with mandatory metadata/digest retention where lawful and useful.

Avoid O(n^2) global comparisons when indexed ancestry/dependency structures can answer the same question near-linearly.

## 19. Truth maintenance and invalidation

Maintain reverse indexes sufficient to recompute only affected state:

- retrieval attempt -> artifact;
- artifact -> assertions;
- provenance node -> artifacts/assertions;
- assertion -> claim contributions;
- capability contract -> affected negative contributions;
- policy version -> claim assessments;
- assumption -> dependent proof environments;
- claim -> downstream hypotheses/inferences.

When any foundation is invalidated, stale, superseded, drifted, corrupted, or reclassified, mark dependants dirty and recompute deterministically.

No cached stronger assessment may survive after its last satisfying proof environment disappears.

## 20. First decisive falsification tests

Implementation begins with tests that fail on the current semantics where appropriate.

### Test A — disjoint labels do not prove independence

Two support nodes with different provider/source-family labels but no explicit causal-independence evidence must return `IndependenceState::Unknown`, not independent support count two.

### Test B — known shared origin is dependent

Two provider replicas derived from one primary artifact must return `KnownDependent` and contribute at most one independent proof route.

### Test C — explicit independent origins can verify independence

Two authenticated primary records with explicit non-overlapping origin evidence satisfying the independence policy may return `ProvenIndependent`.

### Test D — valid zero is not automatically negative evidence

`SourceOutcomeKind::ValidZero` without a sufficient capability contract must produce `NegativeEvidenceDecision::Indeterminate` or `Inadmissible`, never claim defeat.

### Test E — failed retrieval cannot become negative evidence

WAF, auth failure, rate limit, transport failure, schema drift, parser drift, truncation, or inconclusive execution cannot weaken an existence claim as if the provider returned a clean negative.

### Test F — weaker capability cannot strengthen a claim

Downgrading completeness, freshness, temporal scope, or applicability must never make negative evidence stronger.

### Test G — duplicate/transform invariance

Adding N mirrors, screenshots, crops, normalized copies, or provider replicas of the same root cannot increase proven independence.

### Test H — information-loss monotonicity

Removing provenance, independence evidence, integrity proof, temporal precision, identity binding, or coverage cannot strengthen epistemic state.

### Test I — truncation monotonicity

Truncating proof or collection may preserve or weaken state, never strengthen it.

### Test J — invalidation propagation

Invalidating a required artifact, capability contract, premise, provenance edge, or audit-chain segment must weaken every dependent proof environment and assessment appropriately.

## 21. Migration sequence

### Phase 1 — semantic hardening

- introduce `IndependenceState`;
- stop treating disjoint recorded root families as automatically proven independent;
- preserve current behavior in a diagnostic/shadow path for differential comparison;
- add falsification/property tests.

### Phase 2 — retrieval reproducibility

- add `RetrievalAttempt` and artifact digests;
- project existing `CollectionEvent`/`RawObservation` into the richer model;
- preserve compatibility readers/writers where required;
- ensure secrets never enter fingerprints or persisted diagnostics.

### Phase 3 — capability-gated negatives

- add `ObservationCapability` and `NegativeEvidenceDecision`;
- migrate clean-negative semantics source-by-source;
- default unknown providers/capabilities to non-admissible or indeterminate negative evidence.

### Phase 4 — policy v2

- extend claim-specific obligations for directness, identity binding, authority, temporal fit, integrity, coverage, and independence;
- keep exploration scores separate;
- run new adjudication in shadow mode against current fixtures/scans.

### Phase 5 — truth maintenance and audit integrity

- add reverse invalidation indexes;
- add append-only audit digest chain;
- verify deterministic recomputation and corruption detection.

### Phase 6 — media intelligence consumer

- implement image/document artifact processing and reverse-search orchestration only after the epistemic substrate is stable;
- route exact/near/similar/OCR/model outputs through ordinary assertions and policies.

### Phase 7 — production cutover

Cut over only when claim-by-claim differential results are understood, regressions are accepted, and verification gates pass.

## 22. Verification gates

A completion claim requires fresh evidence for every applicable layer:

1. unit tests for new types and policy logic;
2. property/metamorphic tests for monotonicity and duplication invariants;
3. integration tests for collection -> attempt -> artifact -> provenance -> assertion -> claim -> assessment;
4. differential tests against current behavior and preserved legacy oracles;
5. deterministic serialization/replay tests;
6. corruption tests for artifact digests and audit chain;
7. migration/compatibility tests for persisted state;
8. `cargo fmt --check`;
9. `cargo clippy --locked --all-targets --all-features -- -D warnings` where repository CI contract permits;
10. `cargo test --locked`;
11. release build verification;
12. Android aarch64 cross-build under the repository's pinned/toolchain contract;
13. explicit separation between cross-build success and real handset execution;
14. real Termux handset verification before claiming handset runtime behavior verified.

## 23. Acceptance criteria

This design is successfully implemented only when Huntsman can demonstrate all of the following:

- it can reproduce the material conditions of a consequential retrieval attempt without persisting secrets;
- an execution zero cannot silently become universal absence;
- negative evidence requires a validated, claim-relevant capability contract;
- different providers do not automatically become independent witnesses;
- unknown independence remains unknown;
- known shared ancestry collapses duplicate proof routes;
- derivations and transformations cannot manufacture roots;
- every consequential claim exposes satisfied obligations and blockers;
- missing mandatory proof dimensions cannot be compensated by quantity or confidence;
- resource truncation and information loss cannot strengthen claims;
- invalidations propagate deterministically;
- artifact and audit integrity failures are visible and fail closed;
- proof replay is deterministic under the same evidence and policy versions;
- mobile resource bounds remain enforced;
- no runtime LLM is required;
- existing verified useful capability is preserved unless a deliberately stricter epistemic rule demotes an unsupported conclusion.

## 24. Decision

Adopt **Approach B: complete and harden the existing canonical epistemic kernel**.

Do not create a parallel evidence-fusion subsystem. Do not start with provider proliferation or image-engine automation. The implementation order is:

```text
PROVEN INDEPENDENCE
 -> REPRODUCIBLE RETRIEVAL ATTEMPTS
 -> ARTIFACT INTEGRITY
 -> CAPABILITY-GATED NEGATIVE EVIDENCE
 -> VERIFICATION POLICY V2
 -> TRUTH MAINTENANCE / AUDIT CHAIN
 -> MEDIA / REVERSE-IMAGE CONSUMERS
```

This order maximizes cross-system benefit and minimizes the risk of attaching more collectors to insufficient evidence semantics.
