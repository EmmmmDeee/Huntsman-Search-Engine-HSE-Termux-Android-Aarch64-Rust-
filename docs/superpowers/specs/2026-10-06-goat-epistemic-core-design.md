# Huntsman GOAT Epistemic Core — Canonical Design

Date: 2026-10-06
Status: Approach B selected; written specification pending user review
Baseline inspected: `cc183b10810ab358837b90d25605bf436edd928d`
Supersedes where conflicting: `docs/superpowers/specs/2026-10-03-provenance-claim-kernel-design.md`
Preserves all stronger compatible invariants from the 2026-10-03 design.

## 1. Objective

Turn Huntsman's existing provenance/claim machinery into one production-grade epistemic authority that can answer, reproducibly and conservatively:

1. what was attempted;
2. what was retrieved or observed;
3. what artifact or upstream origin an observation derives from;
4. what proposition it supports, defeats, or leaves unresolved;
5. whether an apparent negative result is admissible negative evidence;
6. whether two proof routes are proven distinct, known dependent, or unresolved;
7. what proof obligations remain unsatisfied; and
8. what additional collection action could materially change the decision state.

Optimize for **verified decision quality**, not provider count, finding count, HTTP success, visual similarity, confidence score, or raw recall.

## 2. Non-goals

Do not:

- add a second truth system beside the existing provenance/claim kernel;
- add a second scheduler beside the existing ROI/dispatch authority;
- restore the legacy monolith;
- require an LLM at runtime;
- require a graph database or distributed event platform;
- treat a successful query as proof of global completeness;
- treat different providers, URLs, domains, datasets, labels, or root-family strings as automatic proof-route independence;
- claim legal chain-of-custody merely because artifacts are hashed;
- make live providers mandatory for deterministic tests;
- let provider-specific code decide final claim truth; or
- allow missing information, truncation, or unknown provenance to strengthen a conclusion.

## 3. Existing foundation to preserve

### 3.1 Typed source outcomes

`src/source_outcome.rs` already separates `Success`, `ValidZero`, auth/WAF/transport failures, drift, anomalies, dead sources, and `Inconclusive`. Preserve the rule that an HTTP 2xx or unvalidated zero is not verified success.

Retrieval outcome remains a statement about execution, not claim truth.

### 3.2 Provider-neutral collection envelopes

`src/collection.rs` already separates collection events from raw observations. Extend that boundary rather than replacing it.

### 3.3 Mandatory evidence provenance

`src/entity.rs` already makes provenance mandatory for evidence and hardens source-family counting. Preserve it.

### 3.4 Canonical ancestry graph

`src/evidence_ancestry.rs` already rejects parentless derivations, fails closed on missing parents and cycles, canonicalizes source families, and collapses known common ancestry. Preserve iterative traversal and deterministic containers.

### 3.5 Claim-specific verification

`src/claim_policy.rs` already separates verification from exploration/confidence scoring and enforces explicit obligations. Preserve the rule that confidence and provider count cannot directly promote claim truth.

## 4. Governing epistemic laws

1. **Retrieval is not truth.** A successful fetch proves only that its retrieval contract succeeded.
2. **Zero is not universal absence.** A validated zero proves only that one understood query returned no matching rows in its observable scope.
3. **Negative evidence is capability-gated.** A no-result may weaken a claim only when applicability, scope, completeness, temporal relevance, freshness, and query correctness justify that inference.
4. **Unknown proof-route independence is not independence.** Lack of a recorded common cause cannot create corroboration.
5. **Duplication is idempotent.** Copies, mirrors, reposts, transforms, screenshots, provider replicas, and repeated retrievals cannot manufacture proof routes.
6. **Derivation is non-generative.** A derived assertion cannot acquire roots, authority, or integrity absent from its premises.
7. **Information loss is non-strengthening.** Removing provenance, scope, time, dependency, integrity, or method information cannot strengthen a claim.
8. **Truncation is conservative.** Resource bounds may preserve or weaken state; they cannot strengthen it.
9. **Proof obligations are non-compensatory.** Quantity cannot replace a missing mandatory evidence class, identity binding, authority requirement, temporal condition, integrity condition, coverage condition, or independence condition.
10. **Defeaters survive aggregation.** Material rebuttals, underminers, undercutters, and unresolved relations cannot disappear inside scalar scoring.
11. **Invalidation propagates.** Dependent conclusions must weaken when required foundations fail.
12. **Policy is versioned.** Assessment must be reproducible from evidence plus explicit policy/method versions.

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

Introduce a canonical immutable retrieval-attempt record. `CollectionEvent` may remain a compatibility/runtime envelope, but every consequential attempt must be projectable into the richer form.

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

Derive the fingerprint from the normalized effective query contract, including applicable target, filters, pagination bounds, result mode, selected endpoint/surface, region/locale, transformation identifier, and provider-contract version.

Credentials, secrets, bearer tokens, cookies, or other secret material must never enter fingerprint input or persisted diagnostics.

### 6.2 Transformations

A crop, normalized identifier, OCR extraction, decompressed document, keyframe, resized image, or other derived query asset names its parent artifact plus deterministic recipe/version where reproducible.

Transformation can create an artifact; it cannot create an independent proof route merely by existing.

## 7. RetrievalArtifact: content-addressed observation objects

Use one canonical artifact model for retrieved or locally derived objects.

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

Artifact ids must be deterministic when the source material safely permits it. Raw bytes may be omitted or expired for privacy, storage, provider-contract, or mobile-resource reasons; retained metadata must not imply that discarded bytes remain independently verifiable.

## 8. Provenance DAG: causal provenance, not label diversity

Evolve `EvidenceAncestryGraph` into the sole canonical provenance authority rather than creating a parallel graph.

### 8.1 Node kinds

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

### 8.2 Relation semantics

The canonical model must be able to distinguish at least: `RetrievedFrom`, `CopiedFrom`, `DerivedFrom`, `ExtractedFrom`, `PublishedFrom`, `TransformedFrom`, and `ContainedIn`.

The first implementation may encode relation semantics on adjacency records rather than introduce a heavyweight edge object, but relation meaning must be explicit and versioned before it is used for proof.

### 8.3 Proof-route relationship

Replace the current assumption that disjoint recorded root families imply independent support.

```rust
enum IndependenceState {
    ProvenIndependent,
    KnownDependent,
    Unknown,
}
```

Rules:

- known shared provenance root -> `KnownDependent`;
- missing ancestry, invalid ancestry, or merely disjoint provider/source-family labels -> `Unknown`;
- `ProvenIndependent` requires an explicit `IndependenceEvidence` record accepted by a versioned policy;
- a cycle or invalid graph fails closed and can never produce `ProvenIndependent`.

### 8.4 IndependenceEvidence

Independence is itself a claim requiring a basis; it is never inferred merely from absence of a recorded shared root.

```rust
struct IndependenceEvidence {
    left_root: EvidenceNodeId,
    right_root: EvidenceNodeId,
    basis: IndependenceBasis,
    method_id: String,
    method_version: u32,
    supporting_artifact_ids: BTreeSet<ArtifactId>,
    observed_at_unix: u64,
}

enum IndependenceBasis {
    DistinctAuthenticatedPrimaryOrigins,
    DistinctDirectSensorObservations,
    ExplicitUpstreamProvenance,
    OtherVersionedRule(String),
}
```

A basis is admissible only when its method contract demonstrates distinct proof origins for the specific claim domain. Distinct hashes, websites, provider ids, domains, timestamps, or source-family strings alone are insufficient.

`OtherVersionedRule` is fail-closed: an unknown rule version never establishes independence.

The term `ProvenIndependent` means **proven distinct proof routes under the governing policy**, not statistical independence of all possible hidden causes.

### 8.5 Compatibility boundary

Existing `root_families`, `are_independent`, and `independent_support_count` may remain temporarily for diagnostics and legacy differential tests, but after Phase 1 they must not be consumed by verification-capable claim promotion unless routed through the new tri-state relationship and independence policy.

## 9. ObservationCapability: source capability contracts

Introduce conservative versioned capability contracts.

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

Unknown completeness remains unknown. Marketing claims and undocumented assumptions cannot become capability guarantees. Provider drift invalidates or downgrades affected capability state until reverified.

## 10. Negative-evidence admission

`SourceOutcomeKind::ValidZero` remains an execution outcome, not automatically negative evidence.

```rust
enum NegativeEvidenceDecision {
    Admissible,
    Inadmissible,
    Indeterminate,
}
```

A zero becomes admissible negative evidence only when all policy-required dimensions pass:

- the source can observe the proposition;
- query/target mapping is correct;
- temporal scope is relevant;
- completeness/coverage is sufficient;
- freshness is sufficient;
- the attempt was not truncated;
- the provider contract validated the zero;
- no material drift, WAF, auth, quota, transport, parser, schema, or interaction failure contaminated the attempt; and
- claim policy permits negative inference from that capability class.

Examples:

- `HIBP returned zero breaches for this account at T` may be established by a validated query contract.
- `This account has never appeared in any breach` is not established by that zero.
- `Reverse-image engine X returned no exact indexed match for crop Y at T` may be established.
- `This image has never appeared online` is not established by that result.

## 11. Assertions and claim contributions

Retain the typed-assertion model from the 2026-10-03 design. Consequential provider output must pass through it before claim adjudication.

An assertion identifies subject, versioned predicate, object/value, time/interval, extraction or verification method, artifact/premise references, provenance nodes, material assumptions, integrity state, and whether it is direct, derived, or negative evidence.

`ClaimContribution` records claim-relative support/defeat plus directness, identity binding, authority, temporal fit, applicability, assumptions, and negative-evidence admissibility where relevant.

## 12. VerificationPolicy v2

Extend the current policy without reintroducing scalar truth scoring.

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

Compatibility fields may remain during migration, but the verification-capable path ultimately uses the richer obligations.

## 13. Orthogonal assessment state

Do not collapse claim state into one confidence value.

Expose at least:

- **Epistemic:** Candidate, Supported, Verified, Contested, Underdetermined, Refuted.
- **Temporal:** Current, Historical, Stale, Superseded, Unknown.
- **Coverage:** Complete, MateriallyComplete, Partial, Failed, Unknown.
- **Provenance:** Resolved, Partial, Unknown.
- **Integrity:** Verified, Unverified, Failed.

Exploration confidence remains permitted for search ranking and UI prioritization only.

## 14. Defeaters and contradictions

Preserve structured defeat: `Rebut`, `Undermine`, `Undercut`, `Supersede`, `Compatible`, and `UnknownRelation`.

Disagreement is not automatically contradiction. Evaluate temporal compatibility, scope, subject resolution, and predicate compatibility before defeat affects a claim.

## 15. Proof environments

Continue bounded minimal proof environments. A proof environment contains only material justification: assertion ids, provenance nodes/roots, required `IndependenceEvidence`, dependency domains, derivations, assumptions, capability/coverage predicates, and integrity predicates.

Remove subsumed supersets. Preserve alternative minimal environments independently. Hitting deterministic bounds marks proof incomplete and blocks strengthening.

## 16. Tamper-evident audit trail

For consequential artifact/provenance/assessment mutations, maintain an append-only digest chain over canonical audit records:

```text
entry[n].previous_digest = digest(entry[n-1])
entry[n].digest = SHA256(canonical(entry[n] without digest) || previous_digest)
```

This provides tamper evidence and reproducibility checks, not an automatic legal chain-of-custody claim. Corruption must fail verification explicitly rather than be silently repaired.

## 17. Media and reverse-image intelligence as a consumer

Treat the OSINT Combine lesson as a consumer of the epistemic core, not a special truth system.

```text
input image
 -> SHA-256 / dimensions / media metadata
 -> EXIF/XMP/IPTC where present
 -> OCR / visible text / watermark candidates
 -> optional perceptual fingerprints
 -> deterministic crops / transforms
 -> retrieval attempts across available visual-search surfaces
 -> retrieved pages/assets
 -> provenance DAG
 -> chronology assertions
 -> exact/near/similar classification
 -> claim assessment
```

Keep exact/near duplicate evidence, visual-similarity leads, OCR pivots, model hypotheses, page-containing-image evidence, earliest-observed publication, and source-provenance claims semantically separate.

`No exact matches` never automatically means `original`, `unique`, or `never published`.

External AI/geolocation predictions, if ingested, remain hypotheses or derived assertions requiring independent verification. Runtime remains LLM-free.

## 18. Resource model for Termux

Remain viable on unprivileged Android aarch64. Prefer safe Rust, SQLite, compact typed ids, adjacency lists, deterministic maps/sets where serialized order matters, memoized root/dependency calculations, bounded proof enumeration, incremental dirty-subgraph recomputation, and optional artifact-body retention.

Avoid O(n^2) global comparison where indexed ancestry/dependency structures can answer the same question near-linearly.

## 19. Truth maintenance and invalidation

Maintain reverse indexes sufficient for affected-subgraph recomputation:

- retrieval attempt -> artifact;
- artifact -> assertions;
- provenance node -> artifacts/assertions;
- assertion -> claim contributions;
- independence evidence -> affected proof environments;
- capability contract -> affected negative contributions;
- policy version -> assessments;
- assumption -> dependent proof environments;
- claim -> downstream hypotheses/inferences.

When a foundation is invalidated, stale, superseded, drifted, corrupted, or reclassified, mark dependants dirty and recompute deterministically. No cached stronger state may survive after its last satisfying proof environment disappears.

## 20. First decisive falsification tests

### A — disjoint labels do not prove independence

Different provider/source-family labels without admissible `IndependenceEvidence` -> `Unknown`, not two independent proof routes.

### B — known shared origin is dependent

Two replicas of one primary artifact -> `KnownDependent` and at most one independent route.

### C — explicit proof-route independence can be established

Two roots plus admissible `IndependenceEvidence` satisfying the governing method/policy -> `ProvenIndependent`.

### D — valid zero is not automatically negative evidence

`ValidZero` without sufficient capability -> `Indeterminate` or `Inadmissible`, never claim defeat.

### E — failed retrieval cannot become negative evidence

WAF, auth failure, rate limit, transport failure, drift, truncation, or inconclusive execution cannot masquerade as a clean negative.

### F — weaker capability cannot strengthen a claim

Downgrading completeness, freshness, temporal scope, or applicability can only preserve or weaken negative evidentiary force.

### G — duplicate/transform invariance

Adding N mirrors, screenshots, crops, normalized copies, or provider replicas of one root cannot increase proven distinct proof routes.

### H — information-loss monotonicity

Removing provenance, independence evidence, integrity proof, temporal precision, identity binding, or coverage cannot strengthen epistemic state.

### I — truncation monotonicity

Truncating proof or collection cannot strengthen state.

### J — invalidation propagation

Invalidating a required artifact, capability contract, premise, provenance edge, independence record, or audit-chain segment weakens dependent proof environments and assessments as required.

## 21. Migration sequence

### Phase 1 — semantic hardening

- add `IndependenceState`, `IndependenceEvidence`, and versioned independence-method validation;
- change verification-capable assessment so disjoint root labels alone never satisfy independence;
- keep legacy `are_independent` / support-count behavior only as diagnostic compatibility oracles;
- add property/falsification tests before production cutover.

**Phase-1 cutover gate:** no verification-capable claim path may call legacy boolean/count independence APIs directly.

### Phase 2 — retrieval reproducibility

- add `RetrievalAttempt` and artifact digests;
- project existing `CollectionEvent` / `RawObservation` into the richer model;
- preserve compatibility readers/writers where required;
- prove secrets cannot enter fingerprints or persisted diagnostics.

### Phase 3 — capability-gated negatives

- add `ObservationCapability` and `NegativeEvidenceDecision`;
- migrate clean-negative semantics source-by-source;
- default unknown capabilities to indeterminate/inadmissible negative evidence.

### Phase 4 — policy v2

- extend obligations for directness, identity binding, authority, temporal fit, integrity, coverage, and independence;
- keep exploration scores separate;
- run new adjudication in shadow mode against current fixtures/scans.

### Phase 5 — truth maintenance and audit integrity

- add reverse invalidation indexes;
- add append-only audit digest chain;
- verify deterministic recomputation and corruption detection.

### Phase 6 — media intelligence consumer

- implement image/document artifact processing and reverse-search orchestration only after the substrate is stable;
- route exact/near/similar/OCR/model outputs through ordinary assertions and policies.

### Phase 7 — production cutover

Cut over only when claim-by-claim differential results are understood, intended strictness changes are accepted, and verification gates pass.

## 22. Verification gates

Completion requires fresh evidence for each applicable layer:

1. unit tests for new types and policy logic;
2. property/metamorphic tests for monotonicity and duplication invariants;
3. integration tests for collection -> attempt -> artifact -> provenance -> assertion -> claim -> assessment;
4. differential tests against current behavior and preserved legacy oracles;
5. deterministic serialization/replay tests;
6. corruption tests for artifact digests and audit chain;
7. migration/compatibility tests for persisted state;
8. `cargo fmt --check`;
9. clippy under the repository's pinned CI contract with warnings denied;
10. `cargo test --locked`;
11. release build verification;
12. Android aarch64 cross-build under the pinned toolchain contract;
13. explicit separation of cross-build success from real handset execution; and
14. real Termux handset verification before claiming handset runtime behavior verified.

## 23. Acceptance criteria

Implementation is accepted only when Huntsman demonstrates all of the following:

- material conditions of consequential retrieval attempts are reproducible without persisting secrets;
- execution zero cannot silently become universal absence;
- negative evidence requires a validated claim-relevant capability contract;
- different providers do not automatically become independent witnesses;
- unknown proof-route relationship remains unknown;
- known shared ancestry collapses duplicate proof routes;
- `ProvenIndependent` requires explicit admissible independence evidence;
- derivations and transformations cannot manufacture roots;
- every consequential claim exposes satisfied obligations and blockers;
- missing mandatory proof dimensions cannot be compensated by quantity or confidence;
- resource truncation and information loss cannot strengthen claims;
- invalidations propagate deterministically;
- artifact/audit integrity failures are visible and fail closed;
- proof replay is deterministic under the same evidence and policy versions;
- mobile resource bounds remain enforced;
- no runtime LLM is required; and
- verified useful capability is preserved unless deliberately stricter epistemic rules demote unsupported conclusions.

## 24. Decision

Adopt **Approach B: complete and harden the existing canonical epistemic kernel**.

Do not create a parallel evidence-fusion subsystem and do not begin with provider proliferation or image-engine automation.

Implementation order:

```text
PROVEN PROOF-ROUTE INDEPENDENCE
 -> REPRODUCIBLE RETRIEVAL ATTEMPTS
 -> ARTIFACT INTEGRITY
 -> CAPABILITY-GATED NEGATIVE EVIDENCE
 -> VERIFICATION POLICY V2
 -> TRUTH MAINTENANCE / AUDIT CHAIN
 -> MEDIA / REVERSE-IMAGE CONSUMERS
```

This sequence maximizes cross-system benefit while minimizing the risk of attaching more collectors to insufficient evidence semantics.
