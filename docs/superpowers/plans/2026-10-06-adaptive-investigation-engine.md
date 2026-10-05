# Huntsman Adaptive Investigation Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn Huntsman from predominantly predetermined collection into a bounded, deterministic, provenance-preserving adaptive investigation engine that discovers and executes useful evidence-dependent pivots without allowing controller scores, similarity, or collection failure to become evidence.

**Architecture:** Add a small `adaptive` control plane over Huntsman's existing entity, evidence, lineage, pipeline, registry, and persistence machinery. The controller converts unresolved evidence state into typed information requirements, generates compatible candidate actions, removes redundant/dominated actions, executes the best admissible action under hard budgets, ingests results through the existing evidence pipeline, and replans. Adjudication remains downstream of ordinary evidence/provenance rules: adaptation controls *where to look next*, never *what is true*.

**Tech Stack:** Rust; existing Tokio/SQLite/application stack only; existing entity/evidence/provenance/lineage/pipeline/registry abstractions; no runtime LLM; no new dependency unless an existing primitive cannot implement a required invariant.

**Spec:** `docs/superpowers/specs/2026-10-03-provenance-claim-kernel-design.md` plus this plan's explicit controller/adjudication firewall and acceptance scenario.

## Global Constraints

- Target remains Android Termux ARM64/aarch64, userland, no root.
- Runtime implementation is Rust; shell is permitted only for build/test/device orchestration.
- Safe Rust first; `unsafe` requires separately demonstrated necessity and safety invariants.
- Preserve existing static-scan behavior when adaptive execution is disabled.
- Reuse canonical entity/evidence/provenance/lineage state; do not introduce a competing evidence graph or entity store.
- Unknown provenance, identity, chronology, dependency, scope, authority, applicability, or coverage remains unknown.
- Missing information, controller scores, model output, similarity, source failure, and retrieval absence cannot strengthen or weaken a target-world claim without admissible evidence.
- Duplicate/repackaged observations sharing an evidentiary root do not create independent corroboration.
- Every recursive investigation has hard action, depth, request, wall-time, concurrency, and per-entity limits.
- All adaptive decisions are auditable: policy version, candidate set, rejection reason, selected action, dependencies, cost estimate, and outcome are retained.
- No raw finding-count objective. Optimization targets useful state change and decision-relevant evidence under epistemic constraints.

## Review Focus

1. **Cycles and explosive fan-out:** repeated aliases/entities must terminate under fingerprinting and budgets rather than recurse indefinitely. Task 6 owns adversarial cycle/fan-out tests.
2. **False identity joins:** a tempting username/email similarity must remain a candidate pivot rather than silently merge identities. Tasks 3 and 9 own explicit false-correlation fixtures.
3. **Common-root duplication:** mirrors/repackagers must not create corroboration or redundant actions. Task 5 owns ancestry/deduplication tests.
4. **Source failure and absence:** blocked/down/key-missing/timeout must replan collection without becoming negative target evidence. Task 8 owns failure-injection tests.
5. **Crash/restart:** completed actions must not repeat after restart, while unfinished admissible work resumes. Task 10 owns kill/restart persistence tests.

---

## Delivery Strategy

Ship in four independently reviewable milestones. Do not begin a later milestone until the preceding milestone's acceptance gate is green.

- **M1 — Adaptive substrate (Tasks 1–4):** types, requirements, pivots, dry-run frontier. No recursive network execution.
- **M2 — Safe closed loop (Tasks 5–7):** provenance-root dedupe, bounded executor, deterministic selection. First deployable adaptive mode.
- **M3 — Resilience and falsification (Tasks 8–10):** source-health replanning, competing hypotheses, durable restart.
- **M4 — Policy competition (Tasks 11–13):** telemetry, replay/evaluation, guarded rollout and final end-to-end proof.

Each task is one reviewer-sized transaction: RED test → minimum implementation → targeted verification → relevant regression verification → commit.

---

### Task 1: Freeze Baseline and Feature Gate

**Files:**
- Create: `tests/adaptive_baseline.rs`
- Modify: `src/config.rs` (or the existing canonical scan-options type if different after inspection)
- Modify: `src/pipeline.rs` only at the existing scan orchestration boundary

**Interfaces:**
- Produces: `AdaptiveMode::{Disabled, DryRun, Execute}` exposed through the canonical scan configuration.
- Invariant: `Disabled` is the default and produces the same externally observable scan behavior as the pre-adaptive baseline.

- [ ] **Step 1: Write the failing baseline test** `adaptive_disabled_preserves_static_scan_contract`: run the smallest deterministic existing fixture twice, once with the pre-existing/default configuration and once with `AdaptiveMode::Disabled`; assert identical canonical entities/evidence/provenance roots and identical module invocation set.
- [ ] **Step 2: Run** `cargo test --test adaptive_baseline adaptive_disabled_preserves_static_scan_contract -- --nocapture`; expect failure because adaptive mode does not exist.
- [ ] **Step 3: Add** `pub enum AdaptiveMode { Disabled, DryRun, Execute }` with `Default = Disabled` to the canonical scan-options/configuration type; thread it to orchestration without changing execution.
- [ ] **Step 4: Re-run the targeted test**; expect PASS.
- [ ] **Step 5: Run** `cargo test --all-features`; expect no pre-existing regression.
- [ ] **Step 6: Commit** `feat(adaptive): add non-regressing adaptive mode gate`.

### Task 2: Define the Controller Domain Model

**Files:**
- Create: `src/adaptive/mod.rs`
- Create: `src/adaptive/requirement.rs`
- Create: `src/adaptive/action.rs`
- Create: `src/adaptive/budget.rs`
- Modify: `src/lib.rs`
- Test: unit tests colocated with the new modules

**Interfaces:**
- Produces: `RequirementId`, `InformationRequirement`, `ActionFingerprint`, `CandidateAction`, `ActionOutcome`, `InvestigationBudget`, `BudgetUsage`.
- `CandidateAction` references existing entity/evidence/provenance identifiers; it does not contain a claim-confidence mutation.

- [ ] **Step 1: Write failing tests** proving: stable action fingerprints for semantically identical normalized actions; distinct fingerprints for different module/query/entity tuples; budget refusal at each hard limit; and no API on `CandidateAction` capable of mutating evidence/claim state.
- [ ] **Step 2: Run** `cargo test adaptive:: -- --nocapture`; expect compile/test failure.
- [ ] **Step 3: Implement the minimum domain types** with serde derives only if existing persisted types use serde; keep ordering/hash semantics deterministic.
- [ ] **Step 4: Re-run** `cargo test adaptive:: -- --nocapture`; expect PASS.
- [ ] **Step 5: Run** `cargo clippy --all-targets --all-features -- -D warnings`.
- [ ] **Step 6: Commit** `feat(adaptive): define investigation control types`.

### Task 3: Generate Typed Information Requirements Without Identity Promotion

**Files:**
- Create: `src/adaptive/requirement_generator.rs`
- Modify: `src/adaptive/mod.rs`
- Test: `tests/adaptive_requirements.rs`

**Interfaces:**
- Consumes: canonical entity/evidence types and `InformationRequirement` from Task 2.
- Produces: `fn requirements_for_entity(...) -> Vec<InformationRequirement>` (use the repository's exact canonical entity/evidence references after inspection).
- Required initial pivot kinds: email, username, domain, phone, company, IP.

- [ ] **Step 1: Write failing fixture tests**: email yields domain/username/exposure requirements; username yields account-reuse/code/social requirements; domain yields DNS/registration/certificate/archive requirements; ambiguous same-username observations for two entities do **not** merge them.
- [ ] **Step 2: Run** `cargo test --test adaptive_requirements -- --nocapture`; expect failure.
- [ ] **Step 3: Implement deterministic requirement generation** using typed/canonical attributes only; preserve source evidence IDs as dependencies.
- [ ] **Step 4: Add the Review Focus false-identity test** `similar_username_is_pivot_not_identity` and make it pass without weakening identity rules.
- [ ] **Step 5: Run targeted tests plus** `cargo test --all-features`.
- [ ] **Step 6: Commit** `feat(adaptive): derive typed investigation requirements`.

### Task 4: Map Requirements to a Dry-Run Frontier

**Files:**
- Create: `src/adaptive/frontier.rs`
- Create: `src/adaptive/capability.rs`
- Modify: canonical module registry only to expose read-only capability metadata if not already available
- Test: `tests/adaptive_frontier.rs`

**Interfaces:**
- Produces: `CapabilityDescriptor` and `InvestigationFrontier`.
- Produces: `fn candidates_for(requirement, capabilities, state) -> Vec<CandidateAction>`.
- `DryRun` records candidates/rejections but performs zero additional network/module execution.

- [ ] **Step 1: Write failing tests** mapping each Task-3 requirement kind to compatible fixture capabilities and rejecting incompatible capabilities.
- [ ] **Step 2: Write failing dry-run test** asserting adaptive candidates are observable/auditable while the module invocation count remains identical to static mode.
- [ ] **Step 3: Run** `cargo test --test adaptive_frontier -- --nocapture`; expect failure.
- [ ] **Step 4: Implement capability descriptors/frontier generation** by adapting the existing registry rather than creating a second module registry.
- [ ] **Step 5: Re-run targeted tests and baseline non-regression test**; expect PASS.
- [ ] **Step 6: Commit** `feat(adaptive): build dry-run investigation frontier`.

**M1 acceptance gate:** adaptive-disabled is behaviorally non-regressing; dry-run generates explainable actions without executing them; false identity similarity remains unresolved.

---

### Task 5: Provenance-Root Deduplication and Dominance

**Files:**
- Create: `src/adaptive/filter.rs`
- Modify: `src/adaptive/frontier.rs`
- Reuse: `src/lineage.rs`, canonical provenance helpers
- Test: `tests/adaptive_dedup.rs`

**Interfaces:**
- Produces: `ActionDisposition::{Admissible, Duplicate, Dominated, AlreadyExecuted, DependencyBlocked, BudgetBlocked}`.
- Produces: deterministic filtering over action fingerprints and relevant provenance roots.

- [ ] **Step 1: Write failing tests** where multiple observations from the same upstream root propose equivalent actions; assert one admissible action and explicit rejection reasons for the rest.
- [ ] **Step 2: Add a failing common-root test** where two providers/repackagers share ancestry; assert they are not counted as independent corroboration and do not manufacture two equivalent pivots.
- [ ] **Step 3: Run** `cargo test --test adaptive_dedup -- --nocapture`; expect failure.
- [ ] **Step 4: Implement root-aware filtering** by consuming existing lineage/provenance APIs; do not copy provenance into a controller-owned graph.
- [ ] **Step 5: Re-run targeted tests and provenance/claim-kernel tests**; expect PASS.
- [ ] **Step 6: Commit** `feat(adaptive): deduplicate pivots by lineage and dominance`.

### Task 6: Bounded Recursive Executor

**Files:**
- Create: `src/adaptive/executor.rs`
- Modify: `src/pipeline.rs` at one orchestration seam
- Test: `tests/adaptive_executor.rs`

**Interfaces:**
- Produces: `AdaptiveExecutor` operating only when `AdaptiveMode::Execute`.
- Consumes: existing module execution path; all returned observations re-enter the existing pipeline before new requirements are generated.
- Hard bounds: depth, actions, requests, wall time, concurrency, actions-per-entity; defaults must be conservative and explicit in code/config.

- [ ] **Step 1: Write a failing three-hop fixture** `a_unlocks_b_unlocks_c_without_predeclared_chain`; only A is available initially, A's observation creates B's requirement, B creates C's requirement.
- [ ] **Step 2: Write failing cycle test** `a_to_b_to_a_terminates_by_fingerprint`.
- [ ] **Step 3: Write failing fan-out/budget tests** for every hard limit and assert termination reason is recorded.
- [ ] **Step 4: Run** `cargo test --test adaptive_executor -- --nocapture`; expect failure.
- [ ] **Step 5: Implement the minimum loop**: execute → ingest through canonical pipeline → detect useful state change → regenerate requirements/frontier → filter → continue until bounded stop.
- [ ] **Step 6: Run executor tests under Tokio's deterministic/test-time facilities where applicable; run** `cargo test --all-features`.
- [ ] **Step 7: Commit** `feat(adaptive): execute bounded evidence-driven pivots`.

### Task 7: Deterministic Action Selection and Explanation

**Files:**
- Create: `src/adaptive/policy.rs`
- Create: `src/adaptive/audit.rs`
- Modify: `src/adaptive/executor.rs`
- Test: `tests/adaptive_policy.rs`

**Interfaces:**
- Produces: `trait AdaptivePolicy { fn select(&self, state: &AdaptiveState, actions: &[CandidateAction]) -> Option<ActionFingerprint>; }` (adjust borrowed state name to actual Task-2 type).
- Initial policy is lexicographic, not a universal confidence score: blocking requirement → discriminating value → novel provenance root → operational availability → cheaper equivalent → estimated cost/yield → remaining budget.
- Produces auditable selection/rejection records including `policy_version`.

- [ ] **Step 1: Write failing table tests** for every lexicographic precedence rule, including ties resolved deterministically.
- [ ] **Step 2: Write failing firewall test** proving changing controller priority cannot directly change existing evidence/claim adjudication.
- [ ] **Step 3: Run** `cargo test --test adaptive_policy -- --nocapture`; expect failure.
- [ ] **Step 4: Implement `DeterministicPolicyV1` and audit records** without floating-point pseudo-precision where no calibrated probabilities exist.
- [ ] **Step 5: Re-run policy, executor, and claim/provenance tests**; expect PASS.
- [ ] **Step 6: Commit** `feat(adaptive): select and explain next investigation action`.

**M2 acceptance gate:** a non-hard-coded multi-hop investigation executes autonomously, terminates under cycles/fan-out, preserves provenance ancestry, and cannot use controller priority as evidence. This is the first production-capable adaptive mode behind an explicit feature gate.

---

### Task 8: Source-Health-Aware Replanning Without Negative-Evidence Leakage

**Files:**
- Create: `src/adaptive/availability.rs`
- Modify: `src/adaptive/filter.rs`
- Modify: `src/adaptive/executor.rs`
- Integrate: existing doctor/source-health state
- Test: `tests/adaptive_replan.rs`

**Interfaces:**
- Produces availability states compatible with existing source-health semantics; do not invent a parallel health database.
- Execution failure updates capability/action state, not target-world proposition state.

- [ ] **Step 1: Write failing tests** injecting blocked, drifted, key-missing, timeout, and hard-down outcomes into the preferred capability.
- [ ] **Step 2: Assert** the controller selects the strongest remaining admissible alternative and the target claim/evidence state is unchanged by the collection failure itself.
- [ ] **Step 3: Run** `cargo test --test adaptive_replan -- --nocapture`; expect failure.
- [ ] **Step 4: Implement health-aware filtering/replanning** using the canonical source-health representation.
- [ ] **Step 5: Run targeted tests plus doctor/source-health regression tests**.
- [ ] **Step 6: Commit** `feat(adaptive): replan around unavailable sources`.

### Task 9: Competing Hypotheses and Discriminating Requirements

**Files:**
- Create: `src/adaptive/hypothesis.rs`
- Modify: `src/adaptive/requirement_generator.rs`
- Modify: `src/adaptive/policy.rs`
- Test: `tests/adaptive_hypotheses.rs`

**Interfaces:**
- Produces: `HypothesisId`, `Hypothesis`, `Prediction`, `Defeater`, `DiscriminatingRequirement`.
- Hypotheses reference evidence; they are not evidence.
- Policy may prioritize a discriminating requirement but cannot adjudicate the hypothesis.

- [ ] **Step 1: Write failing false-correlation fixture** with H1=same identity and H2=coincidental username reuse; provide shared predictions plus one discriminating observation.
- [ ] **Step 2: Assert before discrimination** that identity remains unresolved and the discriminating requirement outranks redundant confirmation.
- [ ] **Step 3: Assert after contrary evidence** that the false merge never occurs and the rival remains/prevails according to the existing adjudication mechanism rather than controller score.
- [ ] **Step 4: Run** `cargo test --test adaptive_hypotheses -- --nocapture`; expect failure.
- [ ] **Step 5: Implement minimal hypothesis/prediction/defeater representation and requirement generation**.
- [ ] **Step 6: Run targeted tests, identity-resolution tests, and full suite**.
- [ ] **Step 7: Commit** `feat(adaptive): prioritize falsifying evidence`.

### Task 10: Durable Investigation Continuation

**Files:**
- Create: `src/adaptive/store.rs`
- Modify: existing SQLite migration/schema through the repository's canonical migration mechanism
- Modify: `src/adaptive/executor.rs`
- Test: `tests/adaptive_restart.rs`

**Interfaces:**
- Persist only controller state not already canonical elsewhere: frontier/action fingerprints, requirements, budget usage, hypothesis references, policy version, outcomes, stop/reopen reason.
- Evidence/entities remain referenced by canonical IDs; never duplicated into adaptive tables.

- [ ] **Step 1: Write failing restart test**: execute A, persist B as pending, terminate executor, reconstruct from SQLite, assert A is not re-executed and B resumes.
- [ ] **Step 2: Write failing stale-policy/schema test** asserting incompatible persisted controller state fails closed or migrates explicitly rather than silently changing semantics.
- [ ] **Step 3: Run** `cargo test --test adaptive_restart -- --nocapture`; expect failure.
- [ ] **Step 4: Add minimal migration/store and transaction boundaries**; mark action completion atomically with the state needed to prevent duplicate execution after restart.
- [ ] **Step 5: Re-run restart tests and existing DB/migration tests**.
- [ ] **Step 6: Commit** `feat(adaptive): persist and resume investigation frontier`.

**M3 acceptance gate:** preferred-source failure causes replanning without negative-evidence leakage; false correlations are actively challenged; crash/restart resumes without repeating completed actions.

---

### Task 11: Outcome Telemetry Without Goodharting Adjudication

**Files:**
- Create: `src/adaptive/telemetry.rs`
- Modify: `src/adaptive/executor.rs`
- Test: `tests/adaptive_telemetry.rs`

**Interfaces:**
- Record controller-performance observations: action kind, capability, pivot kind, latency, execution outcome, useful-state-change boolean, novel-root count, cost class, policy version.
- Explicitly exclude these telemetry values from target-world evidence/adjudication APIs.

- [ ] **Step 1: Write failing firewall test** showing telemetry changes cannot alter an existing claim/evidence result.
- [ ] **Step 2: Write failing aggregation tests** for latency, failure rate, useful-state-change rate, and novel-root yield with zero/empty samples represented as unknown rather than fabricated certainty.
- [ ] **Step 3: Implement telemetry persistence/read model** using existing persistence conventions.
- [ ] **Step 4: Run targeted and full tests**.
- [ ] **Step 5: Commit** `feat(adaptive): measure controller outcomes safely`.

### Task 12: Replay Harness and Policy Competition

**Files:**
- Create: `src/adaptive/replay.rs`
- Create: `tests/fixtures/adaptive/` with deterministic synthetic/replayed cases
- Create: `tests/adaptive_replay.rs`
- Optional modify: CLI only if an existing diagnostics/test command is the correct repository pattern

**Interfaces:**
- Compare `Static`, `DeterministicPolicyV1`, and future candidate policies against the same immutable replay cases.
- Primary measures: decisive requirements resolved, novel independent roots, false identity merges, redundant requests, actions/time to equivalent evidence state, failure recovery, correct abstention.

- [ ] **Step 1: Add immutable fixtures** for clean multi-hop discovery, duplicate-root trap, false-identity trap, source-failure replan, cycle/fan-out, and unresolved/abstain case.
- [ ] **Step 2: Write failing comparison tests** asserting V1 improves at least one investigation-efficiency outcome over Static while producing zero epistemic-regression fixture failures.
- [ ] **Step 3: Implement deterministic replay and comparison report**; do not use raw finding count as the winner criterion.
- [ ] **Step 4: Run replay suite twice** and assert byte/stable-order equivalent report where timestamps are excluded/normalized.
- [ ] **Step 5: Commit** `test(adaptive): add policy replay and regression oracle`.

### Task 13: End-to-End Acceptance, Device Verification, and Guarded Rollout

**Files:**
- Create/modify: one integration fixture under the repository's established integration-test location
- Modify: `scripts/termux-runtime-acceptance.sh` only to add adaptive smoke acceptance after host tests prove the contract
- Modify: user-facing configuration/docs for `Disabled`, `DryRun`, `Execute`

**Interfaces:**
- Acceptance chain must not encode the complete A→B→C source sequence in advance.
- Production default remains `Disabled` until host + Termux evidence supports changing it.

- [ ] **Step 1: Build the decisive fixture**: initial target → A exposes alias → alias unlocks B → B exposes domain → domain unlocks C → C supplies discriminating evidence; include a tempting false identity, common-root duplicate, and preferred-source failure.
- [ ] **Step 2: Assert** autonomous discovery of the chain, intact provenance ancestry, no duplicate corroboration, rejection/preservation of the false identity as evidence dictates, replanning after source failure, bounded termination, and an auditable reason for every executed/rejected action.
- [ ] **Step 3: Run targeted integration test**, then `cargo fmt --check`, `cargo check --all-targets --all-features`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-features`.
- [ ] **Step 4: Attempt to break it** with malformed attributes, empty state, stale state, duplicate state, cycles, maximum budgets, cancellation, timeout, restart, unavailable dependencies, and repeated execution/idempotency.
- [ ] **Step 5: Extend Termux acceptance minimally** to run one bounded `DryRun` and one deterministic local/fixture-backed adaptive execution that requires no external provider availability; verify process/resource termination and restart.
- [ ] **Step 6: Run the real ARM64 Termux acceptance transaction**; record exact commit, binary hash, environment, commands, outcomes, and residual gaps.
- [ ] **Step 7: Compare final diff to baseline**; remove accidental refactors/dependencies, confirm adaptive-disabled non-regression, and confirm no controller metric enters adjudication.
- [ ] **Step 8: Commit** `feat(adaptive): verify end-to-end adaptive investigation`.

**M4/final acceptance gate:** Huntsman autonomously discovers an evidence-dependent path not specified at scan start, rejects or preserves ambiguous identity according to admissible evidence rather than controller score, does not double-count shared roots, replans around collection failure, survives restart, terminates under hard budgets, remains non-regressing when disabled, and passes real-device Termux acceptance.

---

## Promotion Policy

Promotion is evidence-gated:

1. `Disabled` remains default through M1–M3.
2. After M2 host verification, `DryRun` may be exposed for observational evaluation.
3. After M4 host + handset verification, `Execute` may be explicitly opt-in.
4. Making `Execute` default requires prospective evidence that it improves objective-relevant investigation outcomes without increasing false identity merges, provenance violations, negative-evidence leakage, uncontrolled resource use, or static-mode regressions.
5. Any regression in an epistemic invariant blocks promotion regardless of speed, yield, or finding count.

## Stop / Rollback Conditions

Stop and repair/rollback the affected milestone if any of these occurs:

- controller output directly changes claim strength without new admissible evidence;
- evidence/entities are duplicated into a competing adaptive source of truth;
- shared ancestry is counted as independent corroboration;
- source failure or no-result becomes target-world negative evidence by default;
- adaptive-disabled behavior materially diverges from baseline;
- recursion can exceed configured bounds or evade fingerprint cycle detection;
- restart repeats an action already transactionally recorded complete;
- a candidate policy wins only by changing its own evaluation criterion.

## Final Proof Obligations

The implementation is **VERIFIED COMPLETE** only when all are demonstrated at the same revision:

- static-mode non-regression;
- deterministic dry-run frontier;
- non-hard-coded multi-hop adaptive execution;
- provenance-root-aware deduplication;
- identity ambiguity propagation;
- controller/adjudication firewall;
- bounded recursion and deterministic termination;
- source-failure replanning without negative-evidence leakage;
- falsification/discriminating-evidence behavior;
- durable restart without duplicate completed actions;
- replayable policy comparison under fixed criteria;
- full Rust quality gates;
- actual Termux ARM64 acceptance.

Anything less must be reported as **PARTIALLY VERIFIED**, with the exact unsatisfied proof obligations named.
