# Huntsman Search Engine — End-to-End Refactor Program Design

**Date:** 2026-09-29
**Repository:** `EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-`
**Audited base:** `feef60ab48ffe4be599c2ef0f678600cdaffc2aa`
**Primary production target:** Android → Termux → ARM64/aarch64, no root
**Implementation language:** Rust for Huntsman logic; non-Rust only where an external platform requires configuration or host glue
**Runtime LLM dependency:** None
**Program mode:** compatibility-preserving architectural canonicalization, not a big-bang rewrite

## 1. Objective

Refactor Huntsman end-to-end into one authoritative, evidence-gated, adaptive retrieval and intelligence system while preserving verified working capability and eliminating duplicated authorities, staged-but-unused semantics, memory-dependent correctness rules, false corroboration, weak failure classification, and unverified superiority claims.

The refactor must assimilate prior accepted ChatGPT-derived Huntsman work only when it remains compatible with the current repository and the latest governing constraints.

The desired production loop is:

```text
SEED / REQUEST
→ CANONICAL QUERY
→ PROVIDER CONTRACT + CAPABILITY ROUTING
→ TYPED EXECUTION OUTCOME
→ IMMUTABLE OBSERVATION
→ NORMALIZATION
→ ENTITY CANDIDATE RESOLUTION
→ EVIDENCE + PROVENANCE ANCESTRY
→ CLAIM / HYPOTHESIS LEDGER
→ CONTRADICTION + INDEPENDENCE ANALYSIS
→ CONFIDENCE / EPISTEMIC STATE
→ CORRELATION
→ ROI / VOI SCHEDULER
→ NEXT-BEST PIVOT
→ COMMIT
→ REPEAT UNTIL EXPLICIT TERMINATION
```

The refactor succeeds only when this loop is exercised by the live production engine rather than existing merely as disconnected design types or documentation.

## 2. Non-negotiable invariants

1. **No fabricated findings.** Production findings must originate from real observations. Synthetic or generated data is test-harness-only.
2. **No assumed provider contracts.** Endpoint paths, parameters, response fields, status semantics, authentication, quotas, and commercial-use claims require authoritative documentation or observed responses.
3. **No runtime LLM.**
4. **Rust owns Huntsman policy.** Shell/YAML/JavaScript may exist only where the host platform or UI requires them; correctness semantics remain Rust-owned whenever technically feasible.
5. **Termux Android aarch64 is the production authority for device claims.** Host CI can establish algorithmic correctness but cannot establish Termux performance or sensor capability.
6. **One authoritative implementation per capability.** No parallel scheduler, evidence model, provider registry, confidence engine, or duplicated policy table may survive unless independently justified.
7. **Provenance is immutable evidence ancestry, not a presentation field.**
8. **Derived or copied evidence never becomes independent corroboration merely because another module emitted it.**
9. **Identity ambiguity must remain representable.** The engine may retain unresolved or contradictory candidates rather than force a merge.
10. **Infrastructure location is not human location.**
11. **Credential discovery is evidence, never automatic authentication authority.** Detected credentials may be classified and banked as evidence but must not be silently promoted into active provider credentials.
12. **Persistence changes are migration-safe, restart-safe, and reversible.**
13. **Existing operator credentials and `~/.huntsman` state survive installation, update, migration, and rollback.
14. **Repository success is not device success.**
15. **No capability or superiority claim exceeds demonstrated evidence.**
16. **No semantic production cutover occurs without a characterized old path, a failing test for the new requirement, and an explicit rollback boundary.**
17. **`unsafe_code = "forbid"` remains intact.**
18. **The live `core::roi` + engine round loop remains the sole scheduling authority.**

## 3. Current-state findings that drive this program

### 3.1 Staged intelligence is stronger than live promotion semantics

`src/core/intelligence.rs` already models claims, evidence, inferences, hypotheses, source lineage, temporal validity, geographic basis, contradiction, and independent-lineage promotion. It explicitly states that production scans do not construct an `IntelligenceLedger`; production still promotes through `Entity::confidence`.

This is the largest architectural gap: Huntsman's strongest epistemic model is not yet the live decision authority.

### 3.2 Source health is persistent but causally weak

The current scraper-health path persists outcomes across scans and is consumed by engine dispatch, doctor, API, UI, and debug export. Its central classifications are currently:
- trailing `ModuleError` streak;
- trailing zero-yield completions from a source that previously yielded.

This is useful operationally but cannot reliably distinguish transport, authentication, rate limit, WAF, redirect, protocol, schema, parser, semantic, true-zero, and upstream-outage conditions.

### 3.3 Provider metadata is already canonical enough to extend

`ProviderDescriptor` is already shared by modules, routing, cost gates, and ROI logic. Replace-or-parallel-registry designs are rejected. The refactor extends this contract instead.

### 3.4 Architecture-audit already establishes the Rust direction

The existing `architecture-audit` binary replaced an older Python architecture audit and derives runtime graph state from the actual system. Repository-level invariant checking belongs with this Rust-native audit capability rather than in a new Python/Bash subsystem.

### 3.5 Current configuration contains memory-dependent correctness rules

Verified examples include:
- duplicated auto-update skip policy in production and tests with a literal “keep in sync” instruction;
- normal CI Rust-version literals repeated beside `rust-toolchain.toml`;
- Binaryen/wasm-opt version/checksum consumers that require synchronization;
- Docker Rust builder compatibility with the repository toolchain.

These become first-class architectural invariants or automatically checked compatibility contracts.

### 3.6 Evaluation architecture is designed but not incorporated

The accepted `hse eval` design already specifies:
- M* deterministic manual-replay baseline;
- R retrieval-only condition;
- F full Huntsman condition;
- feature ablations;
- sealed truth inaccessible to condition execution;
- deterministic statistics and bootstrap intervals;
- false-merge / cascade hard gates;
- explicit `PROMOTE | REPAIR | REPLACE | ROLLBACK | HOLD`;
- host-verified versus device-verified validity classes.

This design is adopted into the refactor program.

## 4. Program decomposition

The full request is too large for one safe implementation cycle. It is decomposed into dependency-ordered subprojects. Each subproject receives its own approved design, implementation plan, TDD cycle, regression evidence, and rollback boundary.

### P0 — Baseline, invariants, and executable architecture truth

Purpose:
- make the repository itself capable of rejecting known architecture drift;
- establish a reproducible baseline before semantic changes;
- convert repeated “remember / keep in sync” rules into Rust-owned invariants;
- reconcile all prior ChatGPT requirements into a machine-readable execution ledger.

Outputs:
- Rust-native repository invariant engine integrated with `architecture-audit`;
- one executable source of truth for invariant disposition;
- auto-update skip policy single-sourced;
- Rust toolchain compatibility invariant;
- Binaryen build identity invariant;
- Docker/toolchain compatibility invariant;
- current CI/workflow health captured without inventing success;
- outstanding work ledger with `SATISFIED | PARTIAL | IMPLEMENT | SUPERSEDED | REJECTED | BLOCKED`.

No intelligence semantics change in P0.

### P1 — Evidence and claim production integration

Purpose:
- move the strongest existing epistemic model into the live scan path without an uncontrolled semantic jump.

Sequence:
1. preserve and verify the existing read-only persisted-scan `IntelligenceLedger` projection;
2. characterize current `Entity::confidence` and correlator promotion behavior;
3. add side-by-side production shadow evaluation;
4. persist ledger projection and discrepancies without affecting operator-visible promotion;
5. prove mapping, lineage, independence, contradiction, and migration behavior;
6. cut over narrowly only after benchmark evidence and explicit gates pass.

The prior immediate full cutover proposal remains rejected until shadow evidence proves equivalence or superiority.

### P2 — Typed source execution and causal health

Replace the generic failure reduction with a shared typed outcome taxonomy.

Minimum states:

```text
SUCCESS
VALID_ZERO
AUTH_REQUIRED
AUTH_REJECTED
RATE_LIMITED
BOT_WAF
DNS_FAILURE
CONNECT_FAILURE
TLS_FAILURE
TTFB_TIMEOUT
BODY_TIMEOUT
UPSTREAM_4XX
UPSTREAM_5XX
REDIRECT_CHANGED
PROTOCOL_DRIFT
INTERACTION_DRIFT
SCHEMA_DRIFT
PARSER_DRIFT
SEMANTIC_DRIFT
ZERO_YIELD_ANOMALY
CONFIRMED_DEAD
INCONCLUSIVE
```

Requirements:
- transport and provider semantics remain distinct;
- zero results are not automatically absence;
- HTTP success is not query success;
- query success is not parser success;
- parser success is not entity correctness;
- all causal states are serializable and persisted;
- quarantine/retry policy consumes typed cause rather than a generic streak alone;
- doctor/API/UI/debug reuse the same model;
- positive, negative, protocol, and parser-fixture canaries prevent silent drift.

### P3 — Entity resolution, provenance ancestry, and reversible identity

Introduce a canonical evidence-backed resolution state:

```text
MATCH
PROBABLE
POSSIBLE
NON_MATCH
CONTRADICTED
UNRESOLVED
```

Requirements:
- supporting and contradicting evidence are explicit;
- temporal and geographic compatibility participate without becoming absolute identity proof;
- common names and weak identifiers cannot independently force merges;
- infrastructure locations do not become subject locations;
- merge decisions preserve reversible provenance so later evidence can split an incorrect cluster;
- false-merge risk is measured separately from retrieval yield.

Evidence independence becomes ancestry-based:
- mirrors, recall, derived identifiers, deterministic enrichments, copied breach records, and shared upstream datasets are grouped by lineage;
- corroboration is computed across independent ancestry, not raw module count.

### P4 — Provider contracts, rights, and drift-resilient retrieval

Extend existing `ProviderDescriptor`; do not create a parallel registry.

Add where justified:
- query contract;
- positive / valid-zero semantics;
- authentication state;
- source lineage / upstream family;
- expected schema/protocol identity;
- reliability prior and observed reliability;
- cost and quota semantics;
- historical depth;
- cache and recursive-use policy;
- commercial/licensing metadata with explicit unknown state;
- provenance requirements;
- source-specific health classifier.

Verified provider contract changes must use official documentation or observed responses.

Known source-drift work such as HudsonRock schema migration, AHPRA interaction behavior, redirects, Reddit rate limiting, Wayback timeouts, and Anubis labels is handled here only after current provider behavior is re-derived.

### P5 — Scheduler, budgeting, and termination semantics

Retain `core::roi` and the existing engine round loop as the only scheduler.

Strengthen it with:
- typed work items;
- explicit delayed/retry work;
- source-health aware expected value;
- evidence novelty / information gain;
- provider cost;
- identity-risk penalty;
- coverage gap value;
- resource budgets;
- persistent restart state where justified.

Termination becomes explicit:

```text
FixedPoint
MaxDepth
TimeLimit
RequestBudget
ProviderBudget
ResourceLimit
MarginalGainLimit
Cancelled
FatalError
```

`FixedPoint` is valid only when no admissible, delayed, in-flight, or derivable novel work remains.

No second frontier or scheduler is permitted.

### P6 — Evidence-first geo/radar integration

Adopt the selected `EvidenceFirstGeo` principle:
- strong independently corroborated identity/evidence must outrank weak proximity;
- GEOINT is a bounded contribution rather than an overriding score;
- prior selected cap is retained as an evaluation candidate, not asserted correct until `hse eval` verifies it;
- existing `GeoConverge` remains an explicit operator-selectable strategy until replacement is proven superior.

Radio Signal Radar:
- distinguish sensor executable missing, permission denied, bridge failure, timeout, genuine empty observation, cached data, provider data, and HSE error;
- no fabricated fallback observations;
- local BLE/Wi-Fi/GNSS/Termux sensor evidence and WiGLE/cell-provider evidence share the same provenance and uncertainty model;
- actual Android sensor consumption requires device verification.

### P7 — Native competitive evaluation

Implement accepted Rust-native `hse eval`.

Core conditions:
- **M\*** — frozen deterministic manual-replay baseline, never described as a live human;
- **R** — retrieval/parsing/provenance with linkage/recursive intelligence disabled;
- **F** — full production-capable Huntsman;
- **A** — controlled ablations.

Hard requirements:
- condition-isolated databases and mutable state;
- sealed truth inaccessible to condition execution;
- scoring only after immutable result finalization;
- deterministic suite hashes and result hashes;
- false merge / false split / cascade metrics;
- provider comparability and completeness gates;
- worst-decile and tail-risk reporting;
- exact verdict: `PROMOTE`, `REPAIR`, `REPLACE`, `ROLLBACK`, or `HOLD`;
- no automatic production default change from evaluation output;
- no superiority claim from host-only performance data.

`hse benchmark` remains the authoritative scorecard for one scan; `hse eval` is the higher-level controlled comparison framework.

### P8 — Storage, API, CLI, UI, installer, release, and device convergence

After core semantics stabilize:
- persist new models through canonical storage with explicit migrations;
- retain old data readability or provide deterministic migration;
- expose claim state, contradictions, source health, ancestry, temporal validity, and confidence explanation through existing API/UI surfaces;
- keep UI minimal and entity-first;
- preserve SpiderFoot compatibility where already supported;
- fix outstanding mobile accessibility issues only when tied to touched UI surfaces;
- preserve one canonical install/update path;
- preserve credentials atomically across update/reinstall;
- bind release source, binary, checksums, provenance, and installer selection to the exact revision;
- verify Railway/generic Linux separately from Termux;
- require real Termux aarch64 evidence for device acceptance.

## 5. Reconciliation of outstanding prior ChatGPT work

The following dispositions are canonical for this program.

| Prior item | Disposition | Program location |
|---|---|---|
| Rust-only Huntsman logic | ADOPT | Global invariant |
| Android/Termux/aarch64/no-root first-class | ADOPT | Global + P8 |
| No runtime LLM | ADOPT | Global invariant |
| Immediate full IntelligenceLedger semantic cutover | REJECT FOR NOW | P1 staged shadow/cutover |
| Read-only persisted IntelligenceLedger projection | ADOPT / VERIFY CURRENT STATE | P1 |
| Independent-lineage claim promotion | ADOPT | P1/P3 |
| `EvidenceFirstGeo` default candidate | ADOPT AS EVALUATION CANDIDATE | P6/P7 |
| Unbounded GEOINT dominance | REJECT | P6 |
| Second scheduler / `BoundedFrontier` alongside live ROI | REJECT | P5 |
| Native Rust architectural invariant compiler | ADOPT | P0 |
| Python/Bash invariant engine | SUPERSEDED | P0 |
| `hse eval` M*/R/F/ablation design | ADOPT | P7 |
| Sealed-truth type boundary | ADOPT | P7 |
| Catastrophic false-merge gate | ADOPT | P3/P7 |
| Automatic use of discovered credentials | REJECT | Global/P4 |
| Automatic credential harvesting as evidence | ADOPT WITH REDACTION + NO AUTO-AUTH | P4 |
| LeakBase duplicate provider | REJECT | Already registered |
| LeakBase-aware exposure parsing with secret suppression | IMPLEMENT IF STILL MISSING | P4 |
| Semantic source outcome taxonomy | ADOPT | P2 |
| Generic 3-error / 3-zero health as sole truth | SUPERSEDE | P2 |
| Provider rights/commercial metadata | ADOPT WITH UNKNOWN STATE | P4/P7 |
| Query-pack expansion to 10 providers | DEFER UNTIL P2-P4 CONTRACTS | P4/P7 |
| Radio/sensor bridge verification | ADOPT | P6/P8 |
| WiGLE/cell functionality claimed without device proof | REJECT | P6/P8 |
| Credential persistence atomicity | ADOPT | P8 |
| Release exact-SHA/provenance binding | ADOPT | P8 |
| CI/release/security/trust-boundary outstanding defects | IMPORT INTO EXECUTION LEDGER | P0/P8 |
| Historical one-off bug reports/PR defects | RE-DERIVE BEFORE FIXING | P0 then owning tranche |
| Heavy new graph UI | REJECT | P8 |
| Existing minimal UI + shared Rust/WASM semantics | ADOPT | P8 |
| Runtime superiority claims without benchmark evidence | REJECT | P7 |

## 6. Outstanding defect import policy

Historical ChatGPT findings and old PR notes are leads, not automatically current defects.

P0 imports each outstanding item with:
- source/date;
- affected path;
- original evidence;
- current reproduction status;
- current disposition.

Only a current reproduction, current code-path proof, authoritative contract mismatch, or current failing test promotes a lead into an implementation defect.

This applies to previously reported:
- Linux CI failures;
- bench-smoke failures;
- live API-drift failures;
- release trust-boundary findings;
- outage-classifier work;
- CertSpotter budgets/errors;
- curl redaction;
- API 429 handling;
- DER parsing;
- cancellation races;
- identity/phone token boundaries;
- attribution/completeness issues;
- pre-push receipt/hook edge cases;
- UI/accessibility issues;
- Railway deployment failures;
- provider-label corrections.

No stale issue is “fixed” solely because a prior assistant once reported it.

## 7. Data model direction

### Observation

An immutable statement of what one execution observed.

Required concepts:
- source/provider identity;
- query identity;
- raw-response provenance reference or hash;
- extraction method/version;
- observed time;
- original source time when known;
- execution outcome;
- source lineage;
- verification status.

### Evidence

Evidence wraps an observation or documented derivation and carries ancestry.

An evidence node can name parents but cannot erase them.

### Claim

A proposition about an entity or relationship.

Claim promotion is computed from evidence state; callers do not set “verified” arbitrarily.

### Hypothesis

A competing explanatory state retained until discriminating evidence resolves it.

### Entity resolution

Entity linkage is a decision with provenance, not an irreversible mutation without explanation.

## 8. Confidence model

Do not replace current confidence with a new opaque scalar.

Decompose confidence into inspectable dimensions where materially useful:
- source authority;
- transport integrity;
- query execution integrity;
- response validity;
- extraction confidence;
- identifier strength;
- entity-match probability;
- temporal compatibility;
- geographic compatibility;
- corroboration strength;
- lineage independence;
- contradiction strength;
- freshness;
- provenance completeness.

A compatibility scalar may remain for existing callers/UI, but it is a projection of these states rather than an independent authority.

## 9. Failure-layer invariant

The system must not collapse these layers:

```text
BUILD SUCCESS
≠ PROCESS EXECUTION
≠ NETWORK SUCCESS
≠ HTTP SUCCESS
≠ QUERY EXECUTION
≠ RESPONSE VALIDITY
≠ PARSER SUCCESS
≠ RESULT EXTRACTION
≠ ENTITY RESOLUTION
≠ CORROBORATION
≠ VERIFIED FINDING
```

Every diagnostic or benchmark claim must identify which layer it actually proves.

## 10. Persistence and migration

Rules:
- additive schema changes first;
- migration transaction or explicit rollback;
- migration idempotency;
- restart after migration;
- old-data read tests;
- no credential-value logging;
- no silent state deletion;
- evaluation conditions use isolated stores;
- new evidence/claim state must not corrupt existing scan history.

A semantic cutover that cannot be represented compatibly receives a schema/version boundary rather than silently reinterpreting old rows.

## 11. Testing strategy

Every subproject uses:

```text
REPRODUCE
→ FAILING TEST
→ MINIMAL CHANGE
→ PASS TARGETED TEST
→ FALSIFY
→ REGRESS
→ COMPARE BASELINE
→ RETAIN OR ROLLBACK
```

Required families as applicable:
- unit;
- integration;
- property;
- parser fixture;
- mutation/negative;
- architecture invariants;
- migration;
- restart/recovery;
- deterministic replay;
- fuzz;
- live contract probes;
- Android cross-build;
- real Termux runtime;
- resource-budget tests.

No test may pass vacuously because its protected surface disappeared.

## 12. Verification validity classes

Every material acceptance record declares one:

### Repository-verified
Code/build/test/static invariant only.

### Host-verified
Executed on supported non-Android host.

### Cross-build-verified
Successfully built for `aarch64-linux-android`, not executed there.

### Device-verified
Executed on real Android + Termux + aarch64.

No lower validity class is promoted linguistically into a higher one.

## 13. Rollback discipline

Every semantic tranche must identify:
- previous authoritative behavior;
- migration boundary;
- feature/config switch where practical;
- rollback data compatibility;
- exact regression signal that triggers rollback.

Rollback is preferred over rationalizing an unexplained material regression.

## 14. Release discipline

A releasable refactor state requires:
- exact source revision recorded;
- source/binary revision match;
- deterministic build metadata where feasible;
- checksum verification;
- release artifact provenance;
- installer selects the intended release/revision;
- update path preserves state;
- clean install;
- idempotent reinstall;
- upgrade from supported prior state;
- rollback verification;
- Termux device acceptance.

## 15. Resource constraints

The live system must remain appropriate for an Android handset in roughly the established HSE resource class.

Changes must avoid:
- unbounded graph expansion;
- unbounded event retention in memory;
- unbounded provider concurrency;
- copying large raw corpora unnecessarily;
- heavyweight runtime ML/LLM dependencies.

Benchmarks record wall time, requests, memory where measurable, storage growth, and provider cost.

## 16. Completion definition

The program is complete only when:

1. the execution ledger has no unresolved high-value item incorrectly represented as complete;
2. staged intelligence semantics are either production-authoritative or explicitly retained as non-authoritative with benchmark justification;
3. source failures are causally typed;
4. identity resolution is evidence-backed and reversible;
5. ancestry prevents false independent corroboration;
6. one scheduler governs expansion and termination;
7. provider contracts are machine-readable and validated;
8. `hse eval` can empirically compare relevant candidate states;
9. exact release/device verification succeeds;
10. current operator workflows and stored data have no material unexplained regression;
11. no supported capability claim exceeds its validity class.

## 17. Stop conditions for each tranche

Stop only on:
- verified acceptance;
- verified infeasibility;
- hard external blocker;
- non-positive marginal decision value.

A green build alone is not acceptance.

## 18. Program order

```text
P0 BASELINE + INVARIANTS
→ P1 EVIDENCE SHADOW INTEGRATION
→ P2 TYPED SOURCE HEALTH
→ P3 IDENTITY + ANCESTRY
→ P4 PROVIDER CONTRACTS
→ P5 SCHEDULER + TERMINATION
→ P6 GEO/RADAR
→ P7 COMPETITIVE EVAL
→ P8 STORAGE/API/UI/INSTALL/RELEASE/DEVICE CONVERGENCE
```

Tranches may overlap only where their state is independent and verification evidence cannot contaminate another tranche.

## 19. Explicit exclusions

This program does not:
- rewrite Huntsman in another language;
- create a second “v2” product tree;
- use an LLM inside runtime;
- auto-authenticate with discovered credentials;
- invent source contracts;
- silently merge unresolved identities;
- treat a source returning zero as proof of absence without contract support;
- claim device performance from CI/Linux;
- replace working architecture merely because a new design is more elegant;
- expand source count before evidence correctness and source-health foundations can measure the added value.

## 20. Decision

Adopt incremental canonicalization.

Preserve proven working paths until their replacements pass adversarial and regression gates. Convert staged high-value architecture into live authority through shadow operation and controlled cutover. Use the native evaluation framework to decide whether major semantic changes should be promoted rather than relying on design confidence alone.
