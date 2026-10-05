# Huntsman Runtime Integration Spine — Design

Date: 2026-10-05
Status: Approved design, awaiting implementation-plan review
Base: `22be0defe24cdc04daf216cdb2dae358535f5c3c`
Branch: `refactor/integration-spine-2026-10-05`

## Objective

Wire the largest coherent set of reconstructed Huntsman modules into real, testable runtime data/control flow without manufacturing dependencies merely to increase module-count metrics.

The target state is a Rust-first composition architecture in which existing classification, validation, source routing, provider economics, guarded collection, provenance, lineage, identity resolution, graph analytics, cross-scan analysis, intelligence reporting, metrics, gap analysis, termination, persistence, and export capabilities participate in one bounded investigation pipeline.

The acceptance target is not “every source file imports another source file.” The target is:

- every retained production module is either runtime-reachable, an intentional adapter/leaf, or explicitly documented as reference-only;
- every newly connected module contributes externally meaningful behavior;
- removing a materially required connection causes an integration or architecture test to fail;
- provenance, independence, confidence, failure, resource, and evidence invariants survive end-to-end;
- the resulting pipeline remains viable on Termux/Android ARM64.

## Non-goals

This tranche does not:

- force all modules into one call graph;
- turn `main.rs` into an orchestration god-module;
- introduce a plugin runtime or event-bus framework without evidence it is needed;
- treat source routes as evidence;
- equate provider wrappers with independent upstream origins;
- weaken bounded-resource constraints to gain superficial integration;
- merge legacy/reference-only code solely to raise reachability counts;
- add `unsafe` code;
- add a heavyweight runtime or dependency graph framework.

## Architectural decision

Introduce one upper-layer composition root, provisionally `src/pipeline.rs`, that owns investigation orchestration while keeping lower-level modules pure and independently testable.

The central flow is:

```text
InvestigationInput
  -> classify/canonicalize/validate
  -> Target
  -> dependency/module graph
  -> provider economics + ROI
  -> source/service routing
  -> guarded collector/fetch boundary
  -> source outcome + coverage
  -> ObservationBatch
  -> Entity/Evidence normalization
  -> ancestry + lineage
  -> identity/coreference/correlation
  -> relations
  -> AnalysisSnapshot
  -> graph/cross-scan/intelligence/metrics/gaps/pivots
  -> termination
  -> persistence/exports
  -> PipelineOutcome
```

The pipeline is a coordinator, not a replacement for domain modules.

## Core invariants

### 1. Collector identity is not upstream-origin identity

A collector/provider wrapper does not create an independent evidence lineage. A record must preserve enough origin information to distinguish:

```text
collector -> upstream provider -> dataset/artifact -> observation
```

Corroboration counts roots, not relay hops.

### 2. Discovery routes are not evidence

`source_registry` routes remain lead-generation actions only. A generated URL cannot support a claim until fetched/observed material passes the normal evidence/provenance path.

### 3. Failure is not a negative finding

`source_outcome` and `coverage` remain authoritative for distinguishing:

- observed;
- clean negative;
- unavailable;
- not attempted;
- failed;
- scoped/not applicable.

Only actual clean negatives are negative evidence candidates. A timeout, WAF, rate limit, missing credential, unsupported target, or truncated run cannot become “no result.”

### 4. Confidence is not proof

No integration layer may promote a claim solely because a numeric confidence threshold was crossed. Verification state remains dependent on evidence quality, independent provenance, contradiction state, and explicit policy.

### 5. Bounded work is structural

The pipeline owns explicit limits for:

- queued targets;
- entities;
- relations;
- provider dispatches;
- response body bytes;
- archive captures;
- cross-scan frontier;
- cross-scan visited scans;
- expansion depth;
- export bytes;
- optional network concurrency.

Truncation must be surfaced in `PipelineOutcome` and cannot masquerade as completeness.

### 6. Determinism where practical

Pure transformations use stable ordering. Sets/maps should prefer deterministic ordered structures where output ordering or reproducibility matters.

### 7. Existing security boundaries remain lower-layer concerns

The pipeline calls the existing guarded HTTP/fetch/egress/credential machinery. It does not recreate origin checking, credential placement, private-address blocking, response classification, redaction, or bounded file I/O.

## Primary types

### `InvestigationInput`

Represents an explicit seed investigation.

Candidate fields:

```rust
pub struct InvestigationInput {
    pub scan_id: String,
    pub seeds: Vec<String>,
    pub mode: InvestigationMode,
}
```

Raw seeds are classified by existing indicator/entity classification logic rather than caller-specified type assertions wherever possible.

### `PipelineLimits`

All resource ceilings live in one immutable policy object.

Candidate fields:

```rust
pub struct PipelineLimits {
    pub max_targets: usize,
    pub max_entities: usize,
    pub max_relations: usize,
    pub max_dispatches: usize,
    pub max_archive_captures: usize,
    pub max_cross_scan_frontier: usize,
    pub max_cross_scan_visited: usize,
    pub max_generation: u32,
    pub max_concurrent: usize,
}
```

Defaults must target constrained Android/Termux execution, not desktop abundance.

### `DispatchPlan`

A deterministic planned action, derived from:

- `dependency::ModuleGraph`;
- module/provider metadata;
- provider access/cost state;
- ROI utility;
- source registry/service definitions;
- duplication/previous-dispatch state;
- entity confidence and source count;
- quota/budget constraints.

The plan records why an action was selected or excluded.

### `CollectionEvent`

A common event envelope for provider/module execution outcomes. It is the bridge between collectors and `coverage`/analysis.

It must capture at minimum:

- scan ID;
- provider/module ID;
- target;
- outcome class;
- finding count;
- truncation flag;
- timing metadata;
- safe credential fingerprint if relevant;
- upstream-origin metadata when available.

### `ObservationBatch`

Contains raw normalized observations before entity-resolution/graph inference. It must retain complete provenance and any ancestry identifiers.

### `AnalysisSnapshot`

Immutable batch of:

```text
entities
relations
coverage
ancestry
lineage state
cross-scan metadata
```

Graph consumers operate from this snapshot rather than independently reconstructing subtly different world states.

### `InvestigationReport`

Aggregates externally meaningful analysis:

- intelligence report;
- scan metrics;
- gap report;
- pivot ranking;
- cross-scan category/history;
- provider coverage verdict;
- termination status;
- truncation/resource-limit state.

### `PipelineOutcome`

Owns the final result plus explicit incompleteness/failure metadata. Success means the pipeline completed its bounded objective, not that every possible provider was queried.

## Wiring groups

### A. Input and target normalization

Wire:

```text
classifier
canonical
validation
textnorm
au_id
address_au
postcode_au
geohash/geoint as applicable
entity
```

The resulting target/entity values must use existing canonicalization logic. Invalid or non-actionable values become typed rejection outcomes, not silent drops.

### B. Planning and dispatch economics

Wire:

```text
dependency
module
roi
source_registry
service_defs
key_health/keys
circuit
termination
```

`dependency::ModuleGraph` supplies what can consume/produce a target. Provider descriptors supply access/cost/reliability/optionality. `roi` ranks the economically and informationally strongest dispatches. `source_registry` contributes lightweight public/account lead routes. `service_defs` contributes keyed-provider capabilities and credential probes.

A single dispatch planner should prevent parallel competing definitions of provider eligibility.

### C. Guarded collection boundary

Wire:

```text
http
egress
fetch
source_outcome
classifier/classify
redact
fsio where persistence is needed
```

Existing request/response and credential-origin protections remain authoritative.

Collectors convert provider-specific responses into `CollectionEvent` + observations. They do not write directly into final confidence/identity state.

### D. Evidence/provenance normalization

Wire:

```text
entity
confidence
evidence_ancestry
lineage
assurance
validation
credential_origin
coverage
```

Every normalized observation must be able to answer:

- what was observed;
- by which collector;
- from which upstream origin/dataset when known;
- when;
- what transformation occurred;
- whether it is direct or inferred;
- which ancestry root(s) support it.

### E. Identity and correlation

Wire:

```text
identity
identity_resolution
resolve
coref
correlator
relation
union_find
```

Automatic identity merge remains conservative. Duplicate wrappers or mirrored datasets cannot manufacture independence. Contradictions and invalid/missing probabilities remain explicit hold states.

### F. Graph-analysis fan-out

Wire the normalized snapshot once into:

```text
graph
community
profiles
timeline
exposure
leads
pivot
cross_scan
metrics
gap
intelligence
```

`intelligence::build_intelligence_report()` already composes several of these. The pipeline should extend that composition rather than duplicate it.

Where graph construction is expensive enough to matter, build once and pass a shared/borrowed graph view to downstream consumers. Do not redesign all APIs solely to eliminate negligible reconstruction cost; measure first.

### G. Archive intelligence

Wire:

```text
archive
collector(s) for Wayback/Common Crawl
canonical
entity
lineage
analysis snapshot
```

`ArchiveCapture` records are merged deterministically by URL identity and dataset. Archive-interest classes are prioritization metadata only.

Archive-derived entities should normally include URL/domain/document observations with provenance identifying archive source, dataset/collection, capture time, and source URL.

### H. Persistence and export

Wire the final bounded state into:

```text
session
store
ledger
json
stix
navigator
gexf
snake_graph
```

All exporters consume the same final snapshot/report. Presentation layers may filter, but they cannot alter evidentiary truth.

## CLI integration

`main.rs` remains a thin shell.

Add one high-level investigation command rather than embedding orchestration logic directly in command handlers. A candidate interface is:

```text
huntsman-recon investigate <SEED> [SEED ...]
```

The command should:

1. build `InvestigationInput`;
2. load/default `PipelineLimits`;
3. construct the composition root;
4. execute the bounded pipeline;
5. serialize a concise human summary;
6. persist/export only through existing bounded/atomic paths.

Existing low-level diagnostic commands (`fetch`, `sources`, `classify`, etc.) remain useful for causal debugging and should not be removed merely because a high-level path exists.

## Reachability policy

Add an architecture/repository test that classifies every production Rust module into one of:

- runtime-reachable;
- adapter;
- exporter;
- pure reusable leaf;
- intentionally offline diagnostic;
- legacy/reference-only.

A production module that is none of these is an orphan and fails the architecture test.

This is a stronger invariant than “listed in `lib.rs`.”

The test should be data-driven through a small manifest or explicit static classification table, not a brittle source-code parser pretending to understand Rust call graphs.

## Migration sequence

### Tranche 1 — Composition skeleton

- add pipeline types and bounded limits;
- wire pure input normalization;
- wire graph-analysis snapshot/report composition;
- add end-to-end in-memory fixture test.

No network behavior is required for first proof.

### Tranche 2 — Planning

- compose dependency/module/ROI/source/service logic;
- emit deterministic dispatch plans;
- prove budget/quota/duplicate/unsupported providers are excluded for the correct reason.

### Tranche 3 — Collector bridge

- define common collection events/observation batches;
- adapt existing collector/archive paths incrementally;
- preserve source-outcome classifications and truncation.

### Tranche 4 — Evidence + identity

- normalize all collected observations through one evidence path;
- connect ancestry/lineage/coverage;
- connect conservative identity resolution and relations.

### Tranche 5 — Persistence/export

- make session/ledger/store/STIX/Navigator/GEXF/JSON consume the same snapshot/report;
- remove duplicate orchestration paths only after differential verification.

### Tranche 6 — Reachability cleanup

- classify every production module;
- wire useful orphans;
- explicitly retain justified leaves/adapters;
- delete or migrate genuinely dead/superseded production files only with proof.

## Testing strategy

### Unit

Preserve existing unit suites. Add focused tests only for new pipeline-policy logic.

### Integration

At minimum:

1. seed -> target -> dispatch plan;
2. observation -> evidence -> lineage;
3. duplicate/mirrored origins do not increase independence;
4. independent origins can raise corroboration;
5. failed/unavailable providers do not become clean negatives;
6. entities/relations -> graph/intelligence/metrics/gaps/pivots;
7. archive capture -> normalized archive entity/provenance;
8. final report -> all selected exporters from the same state.

### Adversarial

Test:

- malformed seeds;
- Unicode/confusable values;
- duplicate observations;
- contradictory observations;
- source-family spoofing;
- missing upstream origin;
- cyclic ancestry;
- huge provider result count;
- queue saturation;
- archive capture cap;
- cross-scan frontier cap;
- exhausted quota;
- unknown paid-provider cost;
- WAF/challenge responses;
- credential-origin mismatch;
- repeated execution determinism;
- truncation propagation.

### Differential

For every orchestration path being replaced, compare old and new outputs on fixed fixtures. Intentional differences require explicit tests explaining why the new behavior is superior.

### Resource

Assert hard ceilings structurally where possible. Add benchmark/resource instrumentation only where it can change the Termux viability decision.

## Completion gate

This integration tranche is complete only when all of the following are demonstrated on the exact branch head:

- `cargo fmt --check` passes on stable;
- strict stable Clippy passes;
- Rust 1.87 tests pass;
- stable tests pass;
- Android AArch64 release build and ELF verification pass;
- committed-artifact stability passes;
- architecture/reachability tests pass;
- representative in-memory end-to-end investigation passes;
- at least one representative real guarded collection path passes where credentials/network are legitimately available, otherwise remains explicitly unverified rather than simulated;
- provenance/independence adversarial tests pass;
- resource truncation is surfaced correctly;
- exporters consume one shared final state;
- no material capability from the verified base is silently lost.

## Expected outcome

The likely result is not literally every Rust file calling every other Rust file. The desired result is a significantly denser and more useful executable system where roughly 30–50 currently semi-isolated modules participate through a small number of stable architectural seams.

The composition root provides one place to answer:

- what Huntsman is doing;
- why it chose each action;
- what evidence was produced;
- whether sources are independent;
- what remains unknown or unqueried;
- what analysis was derived;
- whether resource limits truncated the result;
- how the final artifacts relate to the underlying observations.

That is the maximum-coherent wiring strategy: increase runtime integration while decreasing accidental coupling.