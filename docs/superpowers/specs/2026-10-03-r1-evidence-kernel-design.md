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
- `RootBasis` / `IndependentRootKey`
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

## Record identity versus evidentiary independence

This distinction is normative.

Every evidence record has a unique node identity. That identity MUST NOT imply an independent evidentiary root.

`RootBasis` is one of:

- `UpstreamRecord { namespace, record_id }`
- `ContentHash { sha256 }`
- `Composite { namespace, canonical_parts }`
- `Unresolved`

Only the first three can derive an `IndependentRootKey`. `Unresolved` contributes traceability but **zero proven independence**.

Consequences:

- two aggregators returning the same known upstream record count as one root;
- two transformations of one artifact count as one root;
- two acquisitions with no provable common or distinct upstream identity remain unresolved, not automatically two roots;
- provider count and acquisition count never substitute for source independence.

## Evidence root

`EvidenceRoot` records, where known:

- root basis / independent-root key
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

## Ancestry contract

The evidence graph is a validated DAG.

Invariants:

1. derived nodes require at least one parent;
2. missing parents fail closed;
3. cycles are invalid;
4. traversal is iterative, not recursively stack-bound;
5. derivation preserves root support but never creates another independent root;
6. root-support analysis returns both known independent roots and unresolved support;
7. any decision requiring N independent roots fails closed if unresolved load-bearing support is needed to reach N.

Current hardened `evidence_ancestry` behavior is the differential oracle, not the permanent implementation.

## Proposition model

Assertions, inferences and claims use a provider-neutral proposition:

- subject: `EntityRef`
- predicate: stable validated identifier/newtype
- object: `EvidenceValue`

Provider-specific response schemas do not enter `hse-domain`.

## Deterministic identities

New domain/evidence IDs use a versioned, domain-separated SHA-256 preimage with explicit length-prefixing. IDs MUST NOT depend on JSON key order, map iteration order, process state, wall-clock time, or random values.

Use a mature pure-Rust SHA-256 implementation for new IDs unless implementation evidence defeats it. This does **not** alter or reinterpret existing versioned ledger hashes.

Ordered serialization uses deterministic collections (`BTreeMap`/`BTreeSet` or equivalent canonical ordering). Persistent/wire structures include an explicit schema version where compatibility matters.

## Migration contract

Adapters migrate current `Entity`, `Evidence`, `EvidenceProvenance`, ancestry records, and ledger claim references without asserting stronger evidence than the old state proves.

Rules:

- preserve raw and canonical entity values;
- preserve legacy IDs as migration metadata when needed; do not make them the new canonical-ID algorithm by default;
- preserve summaries, attributes, source/provider labels, scan identifiers, timestamps, and ancestry links;
- current ancestry nodes map to the new DAG when valid;
- evidence lacking enough information to establish independent root identity migrates as `RootBasis::Unresolved`;
- `source_family` alone is insufficient to invent an independent root;
- legacy ledger claims preserve their historical ledger reference/hash; R1 does not rewrite ledger history;
- every unmapped legacy field must be explicitly reported by adapter tests rather than silently dropped.

A conservative semantic difference from current `source_count()` is acceptable only when documented by a differential test and when it prevents unsupported corroboration.

## Proof obligations / acceptance

R1 is accepted only when executable tests demonstrate:

1. a mirror/diamond derivation graph yields one independent root;
2. two demonstrably independent roots yield two;
3. unresolved roots do not satisfy an independent-root threshold;
4. derived-without-parent, missing-parent and cyclic graphs are rejected;
5. the same underlying known record reached through two aggregators deduplicates to one root;
6. separate acquisitions without sufficient root identity remain unresolved rather than becoming independent by provider count;
7. semantically identical canonical inputs produce identical IDs;
8. length-prefix/domain separation prevents concatenation-boundary ambiguity;
9. unknown time remains unknown through serialization round-trip;
10. deterministic serialization is independent of insertion order;
11. current evidence migration preserves every mapped value and explicitly accounts for unmapped data;
12. current canonicalization/entity behavior has differential coverage, with intentional divergences documented;
13. the new crates have no provider/network/storage/UI dependencies;
14. the existing root test suite remains green;
15. new crates build/test on Rust 1.87 and stable and remain compatible with the existing Android aarch64 build path.

## Adversarial and stress cases

Tests must include:

- deep ancestry chains and diamonds;
- duplicate IDs and malformed serialized graphs;
- empty/whitespace provenance identifiers;
- Unicode canonicalization cases already supported by the current system;
- conflicting timestamps and explicit unknown time;
- reordered maps/sets;
- same content via multiple provider paths;
- same provider with genuinely distinct upstream records;
- large but bounded ancestry graphs sufficient to falsify recursive/algorithmic blowups.

## Non-goals

R1 does not:

- choose the final database;
- redesign HTTP/runtime;
- migrate or add providers;
- implement provider licensing policy;
- implement adaptive provider selection;
- replace the CLI/Web UI;
- assign ATT&CK techniques;
- claim Termux operational verification.

## Retirement gate

R1 does not delete current `Entity`, `Evidence`, `evidence_ancestry`, or ledger code merely because replacements exist.

A current path may be retired only after all consumers relevant to R1 are migrated or wrapped, differential/acceptance tests pass, and removing it cannot reduce proven capability. Remaining cleanup belongs to the later owning reconstruction unit, primarily R9/R12.

## Completion condition

R1 is complete when the new semantic contracts are implemented, migration is loss-accounted, root independence is fail-closed and demonstrably stronger than provider-count corroboration, the existing root system remains regression-clean, and no unresolved R1 design alternative has greater expected verified value.