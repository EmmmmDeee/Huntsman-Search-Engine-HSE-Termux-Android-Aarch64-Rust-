# Huntsman Reconstruction Program Decomposition

Date: 2026-10-03
Status: companion to the first-principles reconstruction design

The umbrella architecture is intentionally too large for one implementation plan. Reconstruction therefore proceeds through independently reviewable, falsifiable subprojects. Each subproject receives its own design/spec, implementation plan, TDD cycle, migration gate, and retirement condition before implementation begins.

## Ordering principle

Order by dependency leverage and information value, not by visibility or provider count. Establish stable semantics and proof boundaries before migrating providers or adding new integrations.

## Subprojects

### R1 — Evidence kernel and canonical domain contracts

Scope:
- Artifact / Observation / Assertion / Inference / Claim separation.
- EvidenceRoot and acquisition identity.
- ancestry and source-independence semantics.
- canonical Selector, Entity, Relation, time/provenance types.
- migration adapters from current `Entity`, `Evidence`, `evidence_ancestry`, and ledger records.

Acceptance:
- mirrors/derivations cannot manufacture independent roots;
- every migrated current evidence record remains traceable;
- deterministic serialization and IDs are specified and tested;
- current valuable entity/evidence behavior passes differential tests;
- no provider, UI, or persistence implementation is required to prove the domain contract.

Why first: every later provider, planner, persistence, and verification decision depends on these semantics.

### R2 — Proof registry and verification-state model

Scope:
- machine-readable proof obligations;
- verification-state transitions;
- migration of `main.rs::check()` invariants;
- release/platform claim boundaries.

Acceptance:
- existing check invariants are represented without weakening them;
- each capability can report demonstrated state and limitations;
- cross-build, handset, live, and operational proof remain distinct.

### R3 — Policy and authority boundary

Scope:
- guarded egress;
- authentication authority and redirect rules;
- spend/quota/retry/cache gates;
- retention/display/export/redistribution policy model.

Acceptance:
- providers cannot bypass policy;
- current egress and credential-origin guarantees survive differential tests;
- policy decisions are deterministic and auditable.

### R4 — Persistence and replay substrate

Scope:
- immutable/content-addressed artifact layer where permitted;
- acquisition/event journal;
- structured transactional indexes;
- crash recovery, migrations, replay metadata.

Acceptance:
- interrupted writes cannot silently corrupt accepted state;
- deterministic replay from recorded acquisitions is demonstrated where source retention permits;
- candidate storage engines are benchmarked on Linux and Android constraints before selection;
- bounded JSON session storage is retained only for the use cases it still wins.

### R5 — Runtime/transport execution boundary

Scope:
- Transport abstraction;
- cancellation, retries, timeouts, circuits, concurrency;
- blocking-vs-async/hybrid benchmark.

Acceptance:
- current network safety semantics survive;
- winning runtime is selected by measured Termux/Linux net value rather than ideology;
- malformed/WAF/rate-limit/auth ambiguity stays fail-closed.

### R6 — Provider contract and manifest system

Scope:
- typed Provider contract;
- versioned capability/policy manifests;
- selector schemas, pagination, costs, rights, provenance granularity;
- replacement of `ModuleSpec`, `ProviderDescriptor`, and `service_defs.rs` responsibilities.

Acceptance:
- a provider returns acquisitions/observations only, never trusted claims;
- manifests are schema-validated;
- unknown cost/rights remain unknown and fail conservatively where required;
- provider-specific code cannot bypass policy or provenance requirements.

### R7 — First provider migrations

Order:
1. HIBP, because a substantial tested client already exists and provides a strong differential oracle.
2. one simple public/keyless source to validate the minimal adapter path.
3. one upstream breach/stealer source and one aggregator to validate evidence-root/overlap semantics.

Acceptance per provider:
- fixture tests;
- schema-drift failure tests;
- policy/auth tests;
- normalization provenance tests;
- live verification only when explicitly authorized and available;
- current behavior retained only where it remains correct.

### R8 — Adaptive planner and provider tournament

Scope:
- expected marginal-value action selection;
- measured provider reliability, novelty, overlap, freshness and cost;
- lifecycle states UNVERIFIED/PROBE/SHADOW/CHALLENGER/CORE/DEGRADED/DORMANT/REJECTED.

Acceptance:
- planner cannot increase independent-root count from duplicated upstream data;
- static priors yield to measured evidence;
- high-volume duplicate providers cannot win through row count alone;
- deterministic replay can reproduce planner decisions given the same recorded state.

### R9 — Graph, correlation and resolution migration

Scope:
- entity/relation graph;
- identity resolution;
- temporal/geographic defeaters;
- correlation separated from corroboration.

Acceptance:
- current non-compensatory merge protections survive;
- correlation never silently upgrades evidence independence;
- conflicting evidence remains explicit.

### R10 — Interoperability and presentation

Scope:
- STIX, ATT&CK Navigator, SpiderFoot, Maltego, JSON/CSV/graph adapters;
- shared application service for CLI and minimal local Web UI.

Acceptance:
- external schemas do not define canonical truth;
- ATT&CK mappings remain explicit and evidence-gated;
- CLI and Web UI have no duplicated investigation/policy logic;
- existing valuable CLI contracts have differential coverage.

### R11 — Platform capabilities and Termux operational proof

Scope:
- Termux/Linux platform traits and implementations;
- BLE/Wi-Fi/location/sensor integration where supported;
- installer/release path;
- real handset proof ladder.

Acceptance:
- Android cross-build remains green;
- actual Termux install/self-test is separately evidenced;
- resource usage is benchmarked on target-class hardware;
- unsupported device capabilities degrade explicitly rather than fabricating results.

### R12 — Legacy retirement and repository normalization

Scope:
- final per-element dispositions;
- remove superseded implementation paths;
- replace active-tree archive duplication with provenance manifests/recoverable release/history references if recovery remains guaranteed;
- remove migration adapters whose consumers are gone.

Acceptance:
- no unresolved material disposition remains;
- no transitional compatibility layer remains without positive verified value;
- current and historical evidence remains recoverable and attributable;
- final repository represents the surviving architecture rather than its migration history.

## Cross-cutting gates for every subproject

Every subproject must:

1. define claim-specific proof obligations before code;
2. establish current/legacy baseline where comparable;
3. compare preservation, migration, and greenfield alternatives;
4. begin implementation with a failing test or equivalent executable proof obligation;
5. verify the smallest coherent end-to-end slice;
6. attempt falsification and stress relevant failure modes;
7. check affected regressions;
8. retain only verified positive-net-value changes;
9. migrate valuable state/provenance before retirement;
10. delete the inferior path when its replacement is proven.

## Program stop rule

Stop only when all material acceptance criteria in the umbrella design are verified, no unresolved material disposition remains, no feasible positive-value reconstruction action remains, or a hard external blocker/verified infeasibility prevents further progress.

## First executable unit

R1 — Evidence kernel and canonical domain contracts — is the first implementation unit because it defines the semantics every subsequent subsystem must consume. No provider/runtime/storage migration should precede it unless new evidence shows another ordering has materially higher expected value.
