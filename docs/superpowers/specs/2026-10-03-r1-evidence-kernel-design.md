# R1 — Evidence Kernel and Canonical Domain Contracts

Date: 2026-10-03
Status: design specification
Parent: `2026-10-03-huntsman-first-principles-reconstruction-design.md`

## Objective

Establish the smallest stable semantic core that every later Huntsman subsystem can depend on: canonical domain types, explicit evidence layers, source-independence semantics, deterministic identities, and migration adapters from the current reconstruction.

R1 changes semantics and ownership boundaries only. It does not migrate providers, network execution, persistence, UI, planner, or claim-admission policy.

## Decision

Use a strangler boundary: introduce `hse-domain` and `hse-evidence` as workspace crates while keeping the current root package/binary operational as the differential oracle.

Alternatives rejected:

1. **Extend current `Entity`/`Evidence` in place** — lowest churn, but preserves conflation of direct observations, derivations, provenance and confidence; later migrations remain coupled to the flat crate.
2. **Immediate full replacement** — cleanest nominally, but creates an unnecessary regression cliff and destroys the strongest differential oracle.
3. **Two new semantic crates plus adapters** — selected. It creates a real compile-time boundary while preserving current behavior until replacement proof obligations are met.

The two-crate split itself remains falsifiable. If it creates coupling or duplication without protecting an invariant, merge it before broader migration.

## Boundaries

### `hse-domain`

Owns stable vocabulary only:

- `Selector` and selector kind
- `Entity`, `EntityRef`, `EntityKind`
- `Relation`, `RelationKind`
- `EvidenceValue`
- explicit temporal values/ranges, including unknown
- deterministic canonicalization and domain IDs

It MUST NOT depend on provider, transport, persistence, CLI/UI, or platform code.

### `hse-evidence`

Owns:

- `ArtifactRef`
- `AcquisitionId`
- `EvidenceNodeId`
- `RootIdentity` / `IndependentRootKey`
- `EquivalenceKey`
- `EvidenceRoot`
- `Observation`
- `Assertion`
- `Inference`
- `Claim` representation
- ancestry DAG and root-support analysis
- migration-facing evidence adapters/contracts

It depends on `hse-domain`, not on providers, transport, storage, UI, or platform code.

## Evidence layers

The following are distinct types, not flags on one record:

1. **Artifact** — acquired material or a stable reference to it.
2. **Observation** — a directly observed fact extracted from an acquisition/artifact.
3. **Assertion** — a normalized proposition supported by observations.
4. **Inference** — a derived proposition whose premises and transformation/rule are explicit.
5. **Claim** — a proposition presented to a later proof/admission system. R1 models the object but does not decide verification/admission; that belongs to R2.

No layer may silently upgrade evidentiary directness.

## Record identity, equivalence, and evidentiary independence

These are three different questions and MUST use different types.

### Record identity

Every evidence record has a unique `EvidenceNodeId`. It identifies the record only. It conveys neither equivalence nor independence.

### Equivalence / deduplication

`EquivalenceKey` records evidence capable of showing that two records may represent the same underlying material, for example:

- identical content digest;
- an explicitly shared upstream record identifier;
- a validated canonical source-artifact identifier.

An equivalence key may collapse support. It can never create independent support.

Critically:

> Same hash can establish sameness; different hashes cannot establish independence.

Modified, reformatted, truncated, enriched, or partially copied mirrors may have different bytes while still deriving from one root.

### Independent root identity

`RootIdentity` is one of:

- `Established { root_namespace, root_id }`
- `Unresolved`

`Established` is permitted only when provenance establishes that the identifier names the **underlying evidentiary root**, not merely a query-provider result, reseller row, mirror, retrieval, or transformation. The precise admission rules for provider-specific root bindings are supplied later by provider/provenance contracts; R1 defines the fail-closed semantic boundary.

Only `Established` can produce an `IndependentRootKey`. `Unresolved` contributes traceability but **zero proven independence**.

Two distinct `Established` root identities count separately only when no known ancestry/equivalence relation collapses them. Where available evidence cannot establish whether two apparent roots are independent, independence remains unresolved.

Consequences:

- two aggregators returning the same known underlying record count as one root;
- two transformations of one artifact count as one root;
- identical content reached through two sources may prove sameness, never two witnesses;
- differing content hashes do not prove two witnesses;
- differing query-provider or reseller record IDs do not prove two witnesses;
- two acquisitions with no provable root identity remain unresolved, not automatically independent;
- provider count, acquisition count, URL count, and record count never substitute for source independence.

## Evidence root

`EvidenceRoot` records, where known:

- root identity / independent-root key
- equivalence keys
- acquisition ID
- query provider
- upstream provider
- upstream dataset
- original source
- provider record ID
- artifact reference/hash
- source URI
- event/observation time
- source publication time
- provider ingest time
- retrieval time
- selector/query context
- provenance path

Unknown fields remain explicit `None`/unknown states; zero/empty sentinel values are forbidden for epistemically meaningful unknowns.

## Artifact reference

R1 models retention without choosing a persistence engine:

- `Retained { digest, byte_len, media_type }`
- `External { uri, digest }`
- `MetadataOnly { reason }`

This allows later policy to forbid raw retention without destroying provenance semantics.

Artifact digests are equivalence evidence; they do not by themselves establish independent-root identity.

## Ancestry contract

The evidence graph is a validated DAG.

Invariants:

1. derived nodes require at least one parent;
2. missing parents fail closed;
3. cycles are invalid;
4. traversal is iterative, not recursively stack-bound;
5. derivation preserves root support but never creates another independent root;
6. equivalence links may reduce root support but never increase it;
7. root-support analysis returns known independent roots plus unresolved support;
8. any decision requiring N independent roots fails closed if unresolved load-bearing support is needed to reach N.

Current hardened `evidence_ancestry` behavior is the differential oracle, not the permanent implementation.

## Proposition model

Assertions, inferences and claims use a provider-neutral proposition:

- subject: `EntityRef`
- predicate: stable validated identifier/newtype
- object: `EvidenceValue`

Provider-specific response schemas do not enter `hse-domain`.

## Deterministic identities

New domain/evidence record IDs use a versioned, domain-separated SHA-256 preimage with explicit length-prefixing. IDs MUST NOT depend on JSON key order, map iteration order, process state, wall-clock time, or random values.

Use a mature pure-Rust SHA-256 implementation for new IDs unless implementation evidence defeats it. This does **not** alter or reinterpret existing versioned ledger hashes.

Ordered serialization uses deterministic collections (`BTreeMap`/`BTreeSet` or equivalent canonical ordering). Persistent/wire structures include an explicit schema version where compatibility matters.

A deterministic record ID remains only a record ID; hashing a record never upgrades it to an independent root.

## Migration contract

Adapters migrate current `Entity`, `Evidence`, `EvidenceProvenance`, ancestry records, and ledger claim references without asserting stronger evidence than the old state proves.

Rules:

- preserve raw and canonical entity values;
- preserve legacy IDs as migration metadata when needed; do not make them the new canonical-ID algorithm by default;
- preserve summaries, attributes, source/provider labels, scan identifiers, timestamps, and ancestry links;
- current ancestry nodes map to the new DAG when valid;
- evidence lacking enough information to establish underlying root identity migrates as `RootIdentity::Unresolved`;
- `source_family`, provider name, URL, retrieval ID, content inequality, or acquisition count alone is insufficient to invent an independent root;
- known hashes/aliases may become equivalence keys without being promoted to independence keys;
- legacy ledger claims preserve their historical ledger reference/hash; R1 does not rewrite ledger history;
- every unmapped legacy field must be explicitly reported by adapter tests rather than silently dropped.

A conservative semantic difference from current `source_count()` is acceptable only when documented by a differential test and when it prevents unsupported corroboration.

## Proof obligations / acceptance

R1 is accepted only when executable tests demonstrate:

1. a mirror/diamond derivation graph yields one independent root;
2. two genuinely established independent roots yield two;
3. unresolved roots do not satisfy an independent-root threshold;
4. derived-without-parent, missing-parent and cyclic graphs are rejected;
5. the same known underlying record reached through two aggregators deduplicates to one root;
6. separate acquisitions without sufficient root identity remain unresolved rather than becoming independent by provider count;
7. identical content via different provider paths can collapse support;
8. different content hashes alone do not create independent support;
9. different provider/reseller record IDs alone do not create independent support;
10. semantically identical canonical inputs produce identical record IDs;
11. length-prefix/domain separation prevents concatenation-boundary ambiguity;
12. unknown time remains unknown through serialization round-trip;
13. deterministic serialization is independent of insertion order;
14. current evidence migration preserves every mapped value and explicitly accounts for unmapped data;
15. current canonicalization/entity behavior has differential coverage, with intentional divergences documented;
16. the new crates have no provider/network/storage/UI dependencies;
17. the existing root test suite remains green;
18. new crates build/test on Rust 1.87 and stable and remain compatible with the existing Android aarch64 build path.

## Adversarial and stress cases

Tests must include:

- deep ancestry chains and diamonds;
- duplicate IDs and malformed serialized graphs;
- empty/whitespace provenance identifiers;
- Unicode canonicalization cases already supported by the current system;
- conflicting timestamps and explicit unknown time;
- reordered maps/sets;
- same content via multiple provider paths;
- different encodings or partial copies of the same underlying material;
- same provider with genuinely distinct, root-bound upstream records;
- distinct provider IDs pointing to the same underlying root;
- large but bounded ancestry graphs sufficient to falsify recursive/algorithmic blowups.

## Non-goals

R1 does not:

- choose the final database;
- redesign HTTP/runtime;
- migrate or add providers;
- implement provider licensing policy;
- define provider-specific criteria for establishing a root identity;
- implement adaptive provider selection;
- replace the CLI/Web UI;
- assign ATT&CK techniques;
- claim Termux operational verification.

## Retirement gate

R1 does not delete current `Entity`, `Evidence`, `evidence_ancestry`, or ledger code merely because replacements exist.

A current path may be retired only after all consumers relevant to R1 are migrated or wrapped, differential/acceptance tests pass, and removing it cannot reduce proven capability. Remaining cleanup belongs to the later owning reconstruction unit, primarily R9/R12.

## Completion condition

R1 is complete when the new semantic contracts are implemented, migration is loss-accounted, source independence is fail-closed and demonstrably stronger than provider/record-count corroboration, the existing root system remains regression-clean, and no unresolved R1 design alternative has greater expected verified value.