# Huntsman GOAT Adaptive Investigation Engine — Design Specification

**Status:** Approved architectural direction; normative design for the adaptive investigation work.

## 1. Objective

Evolve Huntsman into a Rust-native, LLM-free, bounded autonomous investigation system that maintains the strongest defensible investigation state attainable under current evidence, capabilities, constraints, resources, and time.

Huntsman must dynamically decide what to investigate next, discover useful evidence-dependent paths that were not specified at scan start, challenge attractive explanations, replan around source failure, and stop when additional investigation has no positive decision value.

Adaptation controls **where Huntsman looks next**. Only admissible evidence and the existing evidence/provenance/adjudication machinery control **what Huntsman may conclude**.

## 2. Non-negotiable invariants

1. **Controller/adjudication firewall.** Priority, prediction, similarity, expected value, model output, learned policy, or heuristic score cannot directly strengthen or weaken a target-world proposition.
2. **Unknown remains unknown.** Missing provenance, identity, chronology, dependency, coverage, scope, authority, or applicability cannot silently become support or opposition.
3. **No evidentiary laundering.** Parsing, correlation, transformation, entity resolution, inference, synthesis, replay, or modeling creates no new evidentiary origin.
4. **Count roots, not copies.** Shared evidentiary ancestry cannot manufacture independent corroboration.
5. **Similarity is not identity.** Ambiguous identity remains represented as competing states until discriminating evidence resolves it sufficiently.
6. **Collection failure is operational evidence.** Timeout, block, drift, missing key, or no response updates the capability model; it is not target-world negative evidence by default.
7. **Absence requires detectability.** A no-result becomes probative only under an explicit justified coverage/detectability model.
8. **Bounded autonomy.** Every investigation has hard depth, action, request, wall-time, concurrency, fan-out, and per-entity limits.
9. **Auditable control.** Every material controller decision records candidate actions, rejection reasons, selected action, dependencies, policy version, estimated costs, and observed outcome.
10. **Historical integrity.** Preserve justified-then versus justified-now and the policy/evidence state responsible for consequential decisions.
11. **Non-regression.** Adaptive-disabled operation preserves verified static behavior.
12. **No self-certification by goalpost movement.** Candidate policies compete against frozen criteria and cannot certify themselves by changing those criteria.

Any violation is a release blocker regardless of yield, speed, coverage, or benchmark score.

## 3. Architectural principle

Do not create a second evidence graph, entity database, provenance store, module registry, or claim system.

The adaptive engine is a **control plane** over Huntsman's canonical state. It references canonical IDs and sends all observations back through the ordinary ingestion/evidence path before replanning.

## 4. Seven-plane model

### 4.1 Evidence plane

Canonical target-world observations and their justification context:

- artifacts and observations;
- evidence/provenance roots;
- transformations and derivations;
- identity bindings and ambiguities;
- temporal validity;
- coverage/detectability state;
- contradictions and defeaters;
- dependency/invalidation edges.

This plane is authoritative for evidentiary state.

### 4.2 Investigation-state plane

A compact world model referencing canonical evidence:

- known entities and typed attributes;
- unresolved information requirements;
- open/closed investigative questions;
- completed and pending action fingerprints;
- resource budget and usage;
- current stop/reopen conditions.

It contains no duplicate target-world evidence.

### 4.3 Hypothesis plane

Preserve materially viable alternatives rather than forcing early collapse.

A hypothesis records:

- proposition/state;
- supporting evidence references;
- opposing evidence references;
- predictions;
- incompatible observations;
- shared predictions;
- assumptions;
- defeaters;
- discriminating requirements;
- current adjudication reference.

Hypotheses are analytical objects, never evidence.

Identity resolution uses the same mechanism. For a reused username, plausible states can include same person, collision, impersonation, recycled account, or organizational/shared account.

### 4.4 Frontier plane

Translate unresolved requirements into possible investigative actions.

A candidate action records:

- capability/module;
- normalized query;
- relevant entity/requirement;
- evidentiary dependencies;
- expected possible outcomes;
- expected state changes;
- source availability;
- estimated resource cost;
- reversibility;
- provenance-root novelty potential;
- discrimination potential;
- action fingerprint.

Candidate actions cannot mutate claim state.

### 4.5 Decision/control plane

Select the next action using the strongest justified method available.

Initial policy is deterministic and lexicographic:

1. resolve a blocking requirement;
2. discriminate consequential competing hypotheses/identities;
3. obtain a genuinely novel evidentiary root;
4. prefer operationally available capabilities;
5. eliminate equivalent/dominated actions;
6. prefer lower cost/risk/delay where expected state change is comparable;
7. preserve option value and remaining budget.

Later calibrated prediction may estimate useful state transition, source success, novel-root yield, discrimination, latency, cost, fan-out, and downstream option value. These estimates influence action selection only.

### 4.6 Execution plane

Execute selected capabilities through existing Huntsman module paths with bounded concurrency, cancellation, timeout, retry policy, and resource accounting.

Every result returns through canonical ingestion before the controller can observe a state change.

### 4.7 Meta-control plane

Improve Huntsman's investigative strategy without contaminating target-world evidence.

Maintain a separate system-performance loop:

`execution outcome → controller telemetry → replay/holdout evaluation → candidate policy comparison → guarded replacement`

Meta-control may change policies, capability priors, cost estimates, and scheduling strategy. It may not directly change target-world evidence or adjudication.

## 5. Two-loop separation

### World loop

`canonical evidence → unresolved requirement/hypothesis → candidate actions → selection → execution → canonical ingestion → recomputation`

### System loop

`controller outcomes → telemetry → evaluation → policy challenger → fixed-criterion comparison → retain/rollback`

The loops connect only through explicit dependencies. A parser benchmark is evidence about the system, not the target. A target observation is evidence about the target, not proof that the controller is reliable.

## 6. Counterfactual action planning

Before executing a material action, the controller represents plausible outcome classes:

- positive observation;
- null/no-result under known coverage;
- contradictory observation;
- operational failure;
- ambiguous observation.

For each outcome, determine what investigation state could legitimately change.

If no plausible outcome can materially change a proof environment, hypothesis, identity state, information requirement, decision, or future action, eliminate the action as dominated.

Operational failure changes capability state, not the target proposition.

## 7. Proof environments

For consequential propositions, retain minimal auditable justification environments: the smallest evidence + assumption/dependency set sufficient under the applicable policy.

Maintain multiple independent minimal environments when available. Remove redundant supersets. Invalidation of a root or assumption recomputes only dependent environments and downstream conclusions.

This representation supports precise recursive invalidation without converting the controller into a confidence graph.

## 8. Information requirements

A requirement exists only when:

1. a material uncertainty, blocker, defeater, contradiction, identity ambiguity, temporal gap, provenance gap, dependency gap, or coverage gap exists;
2. a plausible resolution route exists; and
3. at least one plausible outcome could materially change adjudication, decision, or future action.

Unknown alone does not force collection.

Initial deterministic pivot families:

- email → domain, username, public exposure;
- username → account reuse, code, social/public channels;
- domain → DNS, registration, certificates, archives;
- phone → normalization and admissible public-number sources;
- company → corporate/director/domain relationships;
- IP → network/hosting/reputation context.

A pivot is an investigative possibility, not an identity assertion.

## 9. Provenance-root-aware action filtering

Before scheduling:

1. normalize action;
2. compute fingerprint;
3. reject already-completed equivalent action;
4. detect equivalent expected evidentiary roots;
5. detect dominated action;
6. check dependencies;
7. check source availability;
8. check all budgets;
9. check cycle/fan-out constraints;
10. admit or record explicit rejection reason.

A repeated retrieval, mirror, republisher, transformation, or model-derived representation cannot create independence unless independent ancestry is demonstrated.

## 10. Bounded adaptive executor

Required hard controls:

- `max_depth`;
- `max_actions`;
- `max_requests`;
- `max_wall_time`;
- `max_concurrency`;
- `max_actions_per_entity`;
- `max_frontier_width`;
- `max_retries_per_action`;
- global cancellation token.

Action fingerprint minimally includes capability/module, normalized query, relevant entity/requirement, and policy semantics/version where necessary.

Cycle detection and budget enforcement are correctness requirements, not performance optimizations.

## 11. Hypothesis-preserving identity resolution

Never collapse ambiguous identity merely because a similarity threshold is high.

Represent matching attributes, conflicts, uniqueness, temporal/geographic compatibility, alternative identities, provenance dependencies, and residual ambiguity.

Generate discriminating requirements from the strongest live alternatives. Prefer observations predicted differently by those alternatives over repeated observations they all predict.

Dependent propositions inherit unresolved material identity uncertainty.

## 12. Active falsification

Before consequential acceptance, identify the strongest credible rival and seek the cheapest admissible observation with high decision-reversing/discriminating value.

The controller rewards discrimination, not confirmation volume.

When evidence damages the leading explanation, update the investigation model and downstream dependencies; do not defend the prior conclusion.

## 13. Source-health-aware replanning

Integrate the canonical source-health state. Availability transitions such as blocked, drifted, key-missing, down, timeout, or rate-limited modify action feasibility/cost and trigger replanning.

They do not by themselves oppose the target proposition.

When the preferred route fails, preserve unaffected verified state, invalidate only the execution route, choose the strongest remaining admissible action, and continue if positive value remains.

## 14. Persistence and crash semantics

Persist only controller-owned state:

- requirements;
- frontier/action fingerprints;
- pending/running/completed action state;
- budget usage;
- hypothesis references;
- policy version;
- action outcomes;
- stop/reopen conditions;
- audit decisions.

Reference canonical evidence/entities by ID.

Action completion and the state required to prevent duplicate execution must be transactionally consistent. After restart, completed actions do not repeat; unfinished admissible work is reconstructed; incompatible policy/schema state fails closed or migrates explicitly.

## 15. Telemetry and predictive policy

Controller telemetry may record:

- capability/module;
- pivot kind;
- latency;
- execution success/failure class;
- useful-state-change outcome;
- novel-root count;
- discrimination outcome;
- fan-out;
- resource cost;
- policy version.

Zero/empty samples remain unknown; do not manufacture calibrated probabilities.

Predictive models are permitted only after deterministic behavior and replay evaluation exist. Runtime remains LLM-free. Candidate predictors must demonstrate out-of-sample improvement and zero epistemic-invariant regression before promotion.

## 16. Goodhart-resistant objective hierarchy

Lexicographic objective:

1. epistemic invariants / no material false advancement;
2. consequential decision quality;
3. decision-relevant evidence/discrimination gain;
4. resource efficiency;
5. operational throughput.

Raw finding count, source count, graph size, coverage percentage, confidence, and hit rate are diagnostic proxies only.

A policy that doubles yield but creates a false identity merge loses.

## 17. Policy competition and safe self-improvement

Compare incumbent and challenger on immutable replay/holdout/prospective cases using frozen acceptance criteria.

Core measures:

- consequential requirements resolved;
- novel independent evidentiary roots;
- false identity merges;
- provenance violations;
- negative-evidence leakage;
- redundant requests;
- actions/time/resources to equivalent defensible state;
- recovery from source failure;
- correct abstention;
- termination correctness.

A challenger may propose better evaluation criteria but cannot use them to certify its own superiority. Criterion changes require independent review and a higher burden.

## 18. Adversarial evidence model

Where material, assume observations may be forged, planted, poisoned, coordinated, selectively disclosed, misattributed, synthetically generated, or optimized to influence search/ranking.

Source diversity alone is insufficient. Examine common causes, incentives, ancestry, transformation paths, and correlated manipulation.

Track investigator-induced evidence where Huntsman's own queries/probes/publication could alter the observed environment. Such evidence cannot later masquerade as independent evidence of the pre-intervention world.

## 19. GOAT adversarial benchmark

The decisive benchmark contains, in one bounded investigation:

- an initial target with no predeclared complete path;
- an observation that unlocks an unknown alias;
- alias-dependent second-stage capability;
- domain/identifier unlocked by that stage;
- a third-stage discriminating observation;
- two people sharing a plausible identifier;
- deliberate impersonation or recycled identity;
- stale historical evidence;
- copied/repackaged common-root evidence;
- circular attribution;
- a poisoned/misleading observation;
- contradictory authoritative records requiring scope/time comparison;
- a preferred source becoming unavailable mid-run;
- a no-result with inadequate coverage that must remain non-probative;
- a genuine negative-evidence case with explicit sufficient detectability/coverage;
- cheap and expensive competing investigative routes;
- graph cycle and explosive fan-out traps;
- cancellation and crash/restart;
- post-hoc invalidation of an upstream evidence root.

Huntsman receives only the initial target, capabilities, evidence policy, and resource policy. The complete source/action sequence is not hard-coded.

It passes only if it:

1. autonomously discovers a useful multi-hop path;
2. preserves provenance ancestry;
3. does not manufacture corroboration from common roots;
4. preserves ambiguous identity until discriminated;
5. actively seeks evidence capable of defeating the leading explanation;
6. distinguishes operational failure from target-world evidence;
7. replans around unavailable sources;
8. treats absence correctly according to detectability/coverage;
9. terminates under every hard bound;
10. resumes after restart without duplicating completed actions;
11. propagates upstream invalidation to dependent conclusions;
12. produces an auditable explanation for material actions and conclusions.

## 20. Promotion stages

- **Disabled:** exact static behavior; permanent fallback.
- **DryRun:** compute/audit frontier and choices; execute no extra actions.
- **Execute-Experimental:** bounded adaptive execution, explicitly opt-in.
- **Execute-Verified:** allowed only after host replay/integration gates and real Termux ARM64 acceptance pass on the same revision.
- **Default Adaptive:** requires prospective evidence of superior objective outcomes with no epistemic-invariant regression and an immediate rollback path.

## 21. Stop, suspend, and reopen

Stop an investigation when acceptance is satisfied or no available action has positive expected decision value.

Suspend when useful action is blocked by current capabilities/constraints. Record exact blockers and reopening conditions.

Reopen only on material change in evidence, identity, time, dependencies, policy, capability, constraints, consequence, or decision context.

Residual uncertainty alone is not a reason to continue.

## 22. Definition of verified completion

The adaptive engine is not `VERIFIED COMPLETE` until the same revision demonstrates:

- static-mode non-regression;
- controller/adjudication firewall;
- deterministic dry-run frontier;
- non-hard-coded multi-hop discovery;
- provenance-root deduplication;
- hypothesis-preserving identity behavior;
- active falsification/discriminating-evidence behavior;
- bounded recursive termination;
- source-health replanning without negative-evidence leakage;
- correct absence handling;
- transactional crash/restart continuation;
- recursive invalidation;
- auditable decisions;
- fixed-criterion policy competition;
- adversarial benchmark pass;
- full Rust quality gates;
- actual Android Termux ARM64 acceptance.

Anything less is reported as `PARTIALLY VERIFIED` with exact missing proof obligations.

## 23. North-star law

Maintain the strongest defensible model of the investigation. Identify which consequential uncertainty matters next. Determine which admissible observation can most efficiently discriminate the viable states. Acquire it through the strongest available bounded action. Challenge its origin and interpretation. Propagate only what it legitimately changes. Preserve uncertainty that evidence cannot resolve. Continuously improve investigative strategy without allowing optimization, multiplicity, inference, or automation to manufacture knowledge.
