# Capability Runtime Reconstruction — Design

Date: 2026-10-03

## Objective

Reconstruct Huntsman into the strongest verifiably achievable evidence-retrieval and correlation system for unprivileged Termux/Android ARM64, while preserving proven capability, tests, evidence semantics, provenance and useful domain knowledge. Legacy and current structure are both hypotheses. A capability exists only when it is executable through the production path and its claimed state has claim-specific proof.

## Constraints

- Rust only in the runtime; no runtime LLM.
- Android/Termux aarch64 without root is a primary platform.
- Rust 1.87 remains the minimum supported version until evidence justifies raising it.
- Keep the current blocking `ureq`/rustls transport unless a measured workload proves async materially superior.
- Network and credentials are allowed only through explicit guarded boundaries; credential material must never be promoted from evidence into authentication authority.
- The two legacy archives and byte-identical extracted trees remain immutable provenance/oracle material.
- No external catalogue or provider implementation is copied in a way that changes the repository's licensing obligations without an explicit licensing decision.
- Public search pivots, provider count, module count and catalogue breadth are not evidence of investigative capability.

## Acceptance

Acceptance is layered; a stronger state cannot be inferred from a weaker one.

1. **Implemented** — code compiles and its unit contract is exercised.
2. **Integrated** — a seed traverses the production registry/planner/executor path with deterministic fake transports, producing provenance-bearing observations and derived seeds while enforcing budgets and failure semantics.
3. **Platform verified** — the release binary runs on an actual supported Termux/Android aarch64 handset. Cross-compilation alone does not satisfy this.
4. **Live verified** — representative public/authorized providers accept real queries and their responses are parsed through the same production path. Reachability alone is insufficient.
5. **Operationally verified** — bounded repeated runs demonstrate resource, retry, drift, cache, termination and recovery behavior without evidence inflation or hidden uncontrolled cost.

The reconstruction is accepted only when no material objective-critical path relies on disconnected metadata, synthetic provider reachability or unverified legacy behavior.

## Derived capabilities

The minimum architecture must provide:

- typed seed classification and canonicalisation, including ambiguity without forced single-label certainty;
- one authoritative capability registry describing what can actually run;
- one execution contract covering local, HTTP API/page, DNS, sensor and pivot-only capabilities;
- guarded transport, credential-origin, budget, rate-limit, cache and circuit-breaker enforcement;
- explicit source outcomes that distinguish unreachable, WAF/challenge, authentication failure, rate limit, contract/parser drift, valid zero, inconclusive and useful result;
- mandatory observation provenance and evidence ancestry;
- deterministic derivation of entities/relations/seeds without manufacturing independent support;
- frontier planning based on executable capabilities and measured/declared cost, not provider-count proxies;
- claim-specific evidence and identity-resolution gates;
- source health/yield observations separated from truth claims;
- explicit termination and partial-completion reasons;
- reproducible verification artifacts and a narrow operator CLI/API surface.

## Boundaries

### Pure domain

Classification, canonicalisation, entity/relation models, ancestry, confidence, identity-resolution policy, correlation, planning decisions and termination remain pure where practical.

### Execution boundary

Every executable external capability receives an `ExecutionContext` and a typed `Seed`. Network access is available only through the shared guarded transport/fetch boundary carried by that context. Local/sensor capabilities must declare that they do not use network transport.

### Evidence boundary

Only parsed observations with provenance may enter evidence-bearing entity/relation paths. A generated URL, a provider descriptor, a successful TCP/HTTP connection or a catalogue entry is never evidence of the investigated claim.

### Credential boundary

Provider credentials originate only from operator-approved configuration. Evidence containing secrets or tokens can be fingerprinted/redacted but cannot become authority.

## Contracts

### Seed

A seed has a `SeedKind`, canonical value and origin. Candidate/ambiguous classifications may produce multiple seeds, but confidence does not itself confer evidentiary weight.

### Capability descriptor

One descriptor owns the capability's identity, accepted seed kinds, emitted entity/seed kinds, category, retrieval mode, access/cost class, transformation policy, recursion policy, cache/rate policy, provenance policy and verification state.

### Capability execution

`Capability::execute(context, seed)` returns a `CapabilityResult` containing an explicit `SourceOutcome`, observations, derived seeds/entities/relations and execution metrics. Errors and outcomes are distinct: a failed transport cannot be represented as a valid empty result.

### Pivot-only capabilities

`PivotOnly` capabilities may emit discovery leads but can never emit evidence-bearing observations. This invariant must be enforced by type/validation at the registry/execution boundary, not by documentation alone.

### Verification state

Provider/capability verification is explicit and timestamped. Initial ladder:

`ReferenceOnly -> Reachable -> QueryAccepted -> ResultParsed -> EvidenceVerified`

No transition occurs without evidence for that exact state. State may regress when later observations defeat it.

## Non-bypassable invariants

1. External network execution uses the guarded transport/fetch path; no provider-specific raw HTTP bypass.
2. Credentials never cross their approved origin and are never logged as values.
3. Every evidence-bearing observation records provider/capability identity, retrieval time, source locator, parser/contract version or equivalent provenance, and root ancestry/family.
4. Derived evidence inherits ancestry; transformation, duplication, correlation and aggregation create zero new independent roots.
5. `PivotOnly` output cannot satisfy a claim proof obligation.
6. Failed transport, WAF, auth failure, rate limit, truncation, parser drift and unknown coverage cannot be converted into negative/absence evidence.
7. Paid or unknown-cost execution requires an explicit budget/policy decision; unknown cost fails closed when a budget is active.
8. ATT&CK/STIX/Navigator claims require explicit verified bindings; catalogue vocabulary never creates a binding.
9. Identity merges remain reversible and non-compensatory where mandatory evidence classes are missing or ancestry is unresolved.
10. A provider contributes to runtime coverage/richness only if a production capability is registered and executable; descriptors alone do not count.

## Data model

The first stable runtime surface is intentionally small:

- `SeedKind`, `Seed`
- `CapabilityDescriptor`
- `RetrievalMode`
- `AccessClass` / cost policy
- `ValueTransform`
- `EvidenceRole`
- `VerificationState`
- `Capability`
- `ExecutionContext`
- `CapabilityResult`
- `Observation` / provenance reference
- `ExecutionMetrics`

Existing `Entity`, `Evidence`, `EvidenceProvenance`, `SourceOutcome`, ancestry, ledger and relation types remain authoritative until a failing proof obligation requires replacement.

## Execution model

1. Accept raw operator seed.
2. Classify/canonicalise into one or more typed seeds without inventing certainty.
3. Query the authoritative capability registry for compatible executable capabilities.
4. Filter through policy: access, credentials, budget, recursion, prior attempts, source health/quarantine and operator restrictions.
5. Rank by expected decision value using observed yield/reliability/cost where available; unknown values remain unknown rather than receiving optimistic defaults.
6. Execute the best positive-value capability.
7. Classify source outcome before interpreting results.
8. Parse and attach provenance/ancestry.
9. Admit new entities/relations/seeds only through their validation/evidence contracts.
10. Update frontier, source-health observations and budgets.
11. Re-rank and repeat until verified fixed point, budget/policy bound, fatal error/cancel, or no remaining positive-value action.

Concurrency is not a first-version requirement. Blocking execution is retained until benchmarks show parallel/async execution improves verified objective value enough to offset Android memory, scheduling and complexity cost.

## Failure model

- Network unreachable: retry/backoff policy; never absence evidence.
- WAF/challenge: source health event; do not request credentials by inference.
- Authentication rejected: isolate credential/provider state; do not poison parser health.
- Rate limited: bounded retry respecting server delay; do not retry sooner.
- Contract/parser drift: quarantine or downgrade capability state; preserve raw bounded diagnostic metadata where safe.
- Valid zero: accepted only when the provider contract explicitly establishes zero semantics.
- Truncated/malformed response: error/inconclusive, never valid zero.
- Duplicate/mirror data: same root family; no additional corroboration.
- Identity contradiction: blocks automatic merge and propagates to dependent conclusions.
- Resource/budget exhaustion: explicit partial termination with remaining frontier preserved.
- Crash/restart: checkpointing is introduced only after the execution engine exists and a concrete recovery proof obligation is defined.

## Architecture decision

### Selected: strangler reconstruction inside the current single crate

Preserve the proven core and replace disconnected provider abstractions with one capability runtime. Migrate current adapters incrementally. Old surfaces remain temporary oracles/adapters and are removed only after equivalent or better production-path behavior is proven.

### Rejected: restore the v1.41 monolith

It restores breadth quickly but also restores large unverified provider/runtime/UI surfaces, known historical defects, duplicated ownership and a high Android operational burden. Legacy breadth is evidence of useful domain knowledge, not proof the architecture should return.

### Rejected for now: greenfield multi-crate/workspace rewrite

It offers cleaner packaging but imposes migration, build and cognitive cost before package boundaries have demonstrated objective benefit. The selected contract permits later extraction if measured coupling/compile/runtime evidence justifies it.

### Rejected: continue adding isolated registries/modules

The current tree already has separate `dependency::Module`, `module::ModuleSpec/ProviderDescriptor`, keyed `ServiceDef`, and `SourceDescriptor` surfaces. Current production source search found no provider implementations of `Module` or `ModuleSpec`, so metadata breadth can increase without executable coverage. Continuing this path is a Goodhart failure.

## Material disposition

| Existing element | Decision | Proof/rationale |
| --- | --- | --- |
| immutable legacy archives + extracted trees | PRESERVE | provenance and differential oracle; pinned by tests |
| `egress` / `http` / `fetch` | PRESERVE | guarded shared transport, redirect and credential-origin behavior already exercised |
| `keys` / `credential_origin` | PRESERVE | explicit authority, fingerprint/redaction boundaries |
| ledger v2 / `fsio` | PRESERVE | collision/atomicity/symlink defects already falsified and repaired |
| `source_outcome` | PRESERVE | causal outcome semantics prevent HTTP-success/absence conflation |
| evidence ancestry / identity-resolution / confidence | PRESERVE | independent-root and non-compensatory semantics are objective-critical |
| canonical/validation/domain/geo/RF pure modules | PRESERVE, re-test at integration boundaries | useful verified pure capability; no need to rewrite for fashion |
| HIBP client | MIGRATE behind `Capability` | meaningful existing executor with fake-transport evidence; live/Termux still unverified |
| DNS/postcode online adapters | MIGRATE behind `Capability` | already use shared `Transport`; good first adapters |
| PR #671 source routes | MIGRATE as `PivotOnly` capabilities | useful discovery routes, but URLs are leads only |
| `service_defs::ServiceDef` | MIGRATE then RETIRE | useful probe/auth metadata; currently separate registry |
| `module::ProviderDescriptor` economics | MIGRATE selectively then RETIRE old owner | keep explicit cost/access/cache/rate concepts; remove unjustified default priors |
| `dependency::ModuleGraph` concept | REIMPLEMENT | retain producer/consumer reachability idea, derive from actual registered capabilities rather than synthetic probe values |
| `dependency::Module` + `module::ModuleSpec` dual traits | REPLACE | split ownership and no production implementations |
| default 0.5 provider priors | REMOVE from decisions | unsupported precision can influence ranking without observation |
| source/provider count as richness | REPLACE | count only executable registered capabilities and later observed useful coverage |
| `check` | PRESERVE as regression gate, REPLACE as acceptance proxy | deterministic and useful, but not platform/live/operational proof |
| static in-code assurance evidence | MIGRATE to proof inventory | self-description must not certify runtime/live state |
| broad public module surface | MIGRATE gradually | avoid churn before runtime; later expose a narrower stable facade |
| 542 legacy provider files | TRIAGE, not mass-port | migrate only capabilities whose measured expected value exceeds maintenance/operational cost |
| partial relation/correlator families | PRESERVE proven subsets; reimplement only decision-useful gaps | parity is not an objective; claim-specific benefit must justify complexity |

## Proof obligations for the first slice

The first implementation slice succeeds only if:

1. A single capability descriptor can represent a current pivot route without losing its access/execution/evidence semantics.
2. Source-specific value transformation fixes global-normalisation errors: GitHub may use bare usernames while exact web search may preserve `@`; domains canonicalise before provider routing.
3. A `PivotOnly` capability is structurally prevented from producing evidence-bearing observations.
4. Registry coverage is derived from registered capabilities, not synthetic values or descriptor count elsewhere.
5. Existing `sources` CLI behavior remains available through the new contract with stricter input handling.
6. Tests first fail against the pre-contract tree, then pass after implementation.
7. Stable/MSRV tests, strict Clippy, artifact invariants and Android cross-build remain green.

## Verification strategy

- Unit/property/differential tests for pure contracts and transforms.
- Integration tests with fake `Transport` for execution and source-outcome semantics.
- CI on Rust 1.87 and stable with `-D warnings` and artifact invariants.
- Android aarch64 release cross-build and ELF validation on every reconstruction PR.
- Later: actual Termux handset smoke, selected live-provider contract tests, bounded repeated operational runs and resource measurements.
- Every verification artifact identifies the exact commit it establishes; older green runs do not prove newer heads.

## Migration order

1. Establish unified capability contract and registry; migrate PR #671 pivots.
2. Add deterministic planner/executor with fake capabilities, budgets and frontier termination.
3. Migrate HIBP, DNS and postcode adapters through the runtime.
4. Attach health/yield telemetry to real executions; replace heuristic priors with observations or explicit unknowns.
5. Rank and migrate additional providers by incremental verified yield/decision value, not legacy breadth.
6. Re-evaluate relation/correlator gaps using measured investigation value and false-link/false-merge regressions.
7. Complete handset/live/operational verification; only then promote the relevant assurance states.

## Non-goals for the first slice

- mass-porting the 542 legacy provider files;
- restoring legacy UI/API/async runtime;
- introducing a database/checkpoint system before an execution engine creates a demonstrated need;
- claiming Termux runtime or live-provider verification from CI cross-builds;
- changing evidence standards to make more findings appear verified.
