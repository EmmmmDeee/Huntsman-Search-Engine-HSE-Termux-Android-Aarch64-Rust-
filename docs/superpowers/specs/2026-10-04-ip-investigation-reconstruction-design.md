# IP Investigation Reconstruction Design

Date: 2026-10-04
Status: design for review
Branch: `design/ip-investigation-reconstruction-20261004`

## Objective

Reconstruct Huntsman's IP-investigation capability from the current verified `huntsman-recon` core into the strongest evidence-gated, resource-bounded IP investigation system justified by the repository and platform constraints.

The system must turn an IPv4/IPv6 input into a temporally explicit, provenance-preserving infrastructure assessment without treating an IP address as a person or provider count as independent corroboration.

## Verified baseline

The current crate already provides reusable foundations that should be preserved unless implementation proves otherwise:

- guarded network access through `egress`, `http`, and `fetch`;
- credential-origin controls and bounded key handling;
- `Entity`, `Evidence`, and mandatory `EvidenceProvenance`;
- ancestry-aware evidence independence and identity-resolution gates;
- source outcome/failure classification;
- module/provider cost and access descriptors;
- dependency graph and target-kind primitives including `IpAddress` and `Asn`;
- hash-chain/evidence-integrity utilities;
- explicit termination and evaluation primitives;
- Android/Termux aarch64 build proof in CI.

The current binary does **not** expose an IP-investigation command. Most rich IP providers remain only in the immutable legacy snapshot. Legacy includes useful provider/domain knowledge such as BGPView/RDAP, IP geolocation, passive DNS, service/reputation, and VPN/proxy/Tor-related modules, but those modules are not current operational capability.

## Constraints

- Rust only; preserve the single-crate architecture unless evidence justifies changing it.
- Minimum Rust version remains 1.87 unless a higher version produces verified net benefit sufficient to justify migration.
- Non-root Termux/Android ARM64 is a first-class target.
- Preserve Railway/Docker compatibility where current packaging supports it.
- No runtime LLM dependency.
- Preserve guarded public-network egress by default.
- Prefer passive/publicly indexed observations; active probing is not required for initial acceptance.
- Never embed unavailable credentials or pretend live provider reachability.
- Do not modify immutable legacy snapshots.

## Acceptance

The first accepted slice is complete when:

```text
huntsman-recon ip <PUBLIC_IP> [--json] [--deep] [--evidence]
```

can, subject to source availability, coherently produce:

1. canonical IPv4/IPv6 validation and special/private/reserved classification;
2. RDAP/RIR allocation and operator context;
3. ASN/prefix/routing context;
4. reverse DNS;
5. infrastructure classification with explicit unknowns;
6. at least one additional independent enrichment class from historical DNS, certificate intelligence, service intelligence, reputation/threat context, anonymization context, or geolocation;
7. source-specific observation/retrieval time;
8. provenance and source-dependency information;
9. contradictions and provider failures without converting them to negative evidence;
10. JSON/machine-readable output derived from the same investigation state as human output;
11. bounded execution with deterministic stopping;
12. offline fixture tests plus live verification where network availability permits.

No acceptance claim may exceed the verification layer actually demonstrated.

## Non-bypassable invariants

1. **IP address is not a person.** Infrastructure, organization, account, and human attribution are distinct proof classes.
2. **Historical does not mean current.** Every time-bearing observation retains event/observation time separately from retrieval time.
3. **No result is not absence.** Empty response, provider failure, unsupported coverage, and verified absence are distinct states.
4. **Provider count is not evidence independence.** Mirrors and shared upstream datasets count as one evidentiary lineage.
5. **Derivation creates no witness.** Derived claims inherit upstream dependencies, weaknesses, uncertainty, and temporal bounds.
6. **Failure is explicit.** Authentication failure, rate limit, timeout, schema drift, parse failure, empty result, and stale result cannot silently collapse into a clean/negative finding.
7. **Resource pressure reduces breadth, not semantic integrity.** A bounded investigation may stop early but cannot weaken provenance/temporal rules.

## Alternatives considered

### A. Restore the legacy monolith IP stack wholesale

Advantages: fastest route to breadth; large historical provider catalogue.

Rejected as the primary approach because it reintroduces a second architecture, duplicates current guarded networking/evidence rules, revives legacy coupling, and would require revalidating large amounts of code whose operational state is not current.

### B. Add a thin `ip` command with direct provider calls

Advantages: small initial diff; easy demo.

Rejected because it would duplicate fetch, provenance, provider economics, failure semantics, and orchestration. It would optimize visible feature delivery rather than durable investigative capability.

### C. Preserve the reconstructed core and selectively reimplement/port IP capabilities behind one investigation boundary

**Selected.** It preserves verified primitives while allowing strong legacy domain knowledge and provider parsers to be migrated only after each earns its place through tests and live evidence.

## Architecture

Add an `ip` subsystem with four narrow layers.

### 1. Domain model (`src/ip/model.rs`)

Own IP-specific semantics independent of providers:

- `IpTarget`: validated canonical `IpAddr` plus routability/special-range classification.
- `IpObservation`: provider observation with typed subject, payload, observation/event time, retrieval time, provenance lineage, freshness, and optional raw-evidence digest.
- `IpObservationKind`: allocation, ASN, prefix, reverse DNS, historical DNS, certificate, service, reputation, anonymization, geolocation, classification.
- `IpFailure`: normalized failure classes.
- `IpClaim`: derived claim with supporting observation IDs, contradicting IDs, dependency IDs, validity state, and proof state.
- `TemporalState`: current, recent, historical, stale, unknown-current, invalidated.
- `IpInvestigation`: target, observations, failures, claims, pivots considered, budget use, and termination reason.

Do not encode arbitrary numeric confidence as proof. If a score is useful for action ordering, keep it separate from claim status.

### 2. Provider boundary (`src/ip/provider.rs`)

Define a provider interface over the existing guarded request layer rather than permitting provider-specific network clients.

Each provider declares:

- provider/source identity;
- capability classes;
- supported target types;
- access/cost descriptor;
- historical-depth class;
- known upstream lineage where known;
- request construction;
- response parsing into typed observations or explicit failure.

Production providers receive an injected `Transport`/fetch boundary so all parser tests run offline.

### 3. Providers (`src/ip/providers/`)

Port or reimplement providers in value order, not legacy order.

Initial set:

1. **RDAP** — keyless base allocation/operator/RIR evidence. Prefer standards-based RIR bootstrap/discovery or a bounded standards endpoint implementation; do not hard-code one RIR as universal truth.
2. **BGP/ASN** — migrate the useful BGPView/RIPENCC-style logic only after current endpoint/schema verification. Produce ASN/prefix observations, not human attribution.
3. **Reverse DNS** — local/system resolver path or provider path with explicit semantics and bounded failure.
4. **One complementary enrichment family** chosen by verified marginal value and current reachability: CT/certificate intelligence, passive DNS, geolocation, reputation, or Tor/anonymization.

Additional legacy providers remain candidates, not requirements. Each must pass its own proof obligation before registration.

### 4. Orchestrator (`src/ip/orchestrator.rs`)

Run provider actions adaptively rather than calling everything.

Maintain a bounded frontier of candidate actions. Rank actions using decision-relevant factors already represented in current provider metadata:

- unresolved claim value;
- probability of useful result;
- evidence independence;
- freshness/historical value;
- provider reliability/health;
- quota/cost;
- latency/resource burden;
- duplicate-upstream penalty;
- graph/pivot expansion cost.

The precise ranking formula is implementation detail and must be tested for invariants rather than treated as truth.

Default mode performs the minimum base investigation. `--deep` continues while a material positive-net-value action remains and budget permits.

## Data flow

```text
CLI IP
  -> validate/canonicalize
  -> create IpInvestigation
  -> enqueue mandatory base actions
  -> guarded fetch/provider parse
  -> normalized IpObservation + Evidence/ancestry
  -> update claims/contradictions/temporal state
  -> generate candidate pivots
  -> rank against remaining budget
  -> repeat until acceptance/budget/fixed-point/blocker
  -> render human or JSON output from the same investigation object
```

No provider may write final attribution conclusions directly.

## Reuse / migration disposition

### Preserve

- `egress`, `http`, `fetch`, `keys`, `credential_origin`;
- `entity` evidence/provenance primitives;
- `evidence_ancestry` and lineage independence rules;
- `source_outcome` failure semantics where applicable;
- `module` provider economics and access descriptors;
- `dependency` target/module graph concepts;
- `sha256`, ledger/evidence integrity utilities;
- CI/Termux build proof.

### Migrate / extend

- `TargetKind::IpAddress` / `Asn` into the new provider dispatch boundary;
- legacy provider domain knowledge, schemas, fixtures, and parsing logic after falsification;
- legacy validation rules for non-routable/anycast/CDN geolocation caveats only where current tests support them.

### Reimplement

- provider adapters against the current guarded fetch layer;
- IP temporal observation model;
- IP-specific orchestration and termination;
- contradiction-aware classification;
- CLI/report rendering.

### Do not restore wholesale

- monolith engine/module runtime;
- legacy credential/network plumbing;
- active port-scanning behavior as part of initial acceptance;
- provider-specific confidence values treated as proof;
- direct IP-to-person attribution.

## CLI

Extend the current executable rather than creating a second binary:

```text
huntsman-recon ip <IP> [--json] [--deep] [--evidence]
```

Possible later options, only if they earn value:

```text
--budget CALLS
--max-depth N
--providers
--timeline
```

Do not proliferate flags before the base investigation state and output contract are stable.

## Failure semantics

Normalize at least:

- invalid input;
- unsupported address/scope;
- DNS/network failure;
- timeout;
- auth required/rejected;
- rate limit/quota;
- provider error;
- schema/parse failure;
- empty observation;
- stale observation;
- partial result.

A partial investigation remains renderable. Exit status should distinguish invalid invocation from partial source availability; provider failure should not automatically fail the whole command when useful evidence exists.

## Evidence and temporal semantics

Every consequential observation should carry enough data to audit:

- source/provider;
- source family/upstream lineage where known;
- request/query identifier without secrets;
- observation/event time when supplied;
- retrieval time;
- normalized payload;
- optional raw/canonical payload digest;
- ancestry/dependency links.

Reuse existing `Evidence`/`EvidenceProvenance` rather than creating a competing provenance model. Add IP-specific fields only where the generic model cannot express required semantics cleanly.

## Testing strategy

Use TDD for each slice.

### Pure/unit tests

- IPv4/IPv6 canonicalization;
- private/reserved/special ranges;
- temporal-state transitions;
- source independence and duplicate lineage;
- null-result versus failure semantics;
- contradiction preservation;
- budget/termination invariants;
- no IP-to-person claim construction path.

### Provider fixture tests

For every provider:

- successful response;
- empty response;
- malformed/truncated body;
- schema drift fixture;
- auth/rate-limit/server failure where applicable;
- IPv6 where supported;
- stale/historical timestamp handling.

### Integration tests

- base `ip` command using injected/local fixture transport;
- deterministic JSON output;
- partial provider failure with useful remaining output;
- duplicate upstream evidence does not become independent corroboration;
- historical observation never renders as current;
- deep mode respects budget and stops at fixed point.

### Live verification

Where network access permits, run representative public addresses chosen to demonstrate distinct states (for example public resolver/cloud/Tor only where the current status is independently known). Record live verification separately from fixture/integration status.

### Regression

Run:

```text
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo run -- check
```

Verify `var/` remains unchanged unless an intentional accepted contract change requires regeneration.

## Implementation sequence

1. Add failing acceptance tests for `ip` CLI and invariant behavior.
2. Implement pure IP model/target validation.
3. Implement provider contract and fixture transport integration using existing guarded fetch abstractions.
4. Implement RDAP provider and prove end-to-end base evidence.
5. Implement ASN/BGP and reverse-DNS capability.
6. Add claim/contradiction/temporal aggregation.
7. Add bounded orchestrator and `--deep` semantics.
8. Add one complementary enrichment family selected by current reachability and independence value.
9. Add human/JSON rendering from one state object.
10. Run falsification/regression/live verification; repair or roll back failures.
11. Only then evaluate further provider migration.

## Proof obligations

### IP command exists

Established only when CLI integration tests invoke the real binary and parse output/exit status.

### RDAP works

Established by parser fixtures plus at least one live public-IP retrieval if network access permits. Fixture-only state remains integration-verified, not live-verified.

### Evidence independence works

Established when two observations from one declared upstream lineage count as one root and two genuinely distinct roots remain distinct.

### Temporal correctness works

Established when historical fixtures cannot produce a `current` claim and retrieval time cannot silently substitute for event time.

### Deep orchestration works

Established when a deterministic test demonstrates that action ranking changes after evidence arrives, duplicate/low-value actions are suppressed, budgets are respected, and fixed-point termination occurs.

### Termux support works

Established only by the existing Android cross-build plus a handset run for this command. Until handset execution occurs, report platform verification accordingly.

## Stop conditions

Stop implementation only on verified acceptance, no material positive-net-value action, verified infeasibility under valid constraints, or a hard external blocker.

Do not treat compilation, parser fixtures, provider HTTP 200, or plausible output as end-to-end verification.
