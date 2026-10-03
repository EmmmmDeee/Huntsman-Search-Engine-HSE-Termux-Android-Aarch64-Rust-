# Operational Decision Kernel Design

## Objective

Turn the reconstructed core's existing ROI, dependency, source-outcome, lineage, and termination primitives into a pure deterministic action-selection kernel. The kernel must select one eligible action or terminate, emit an inspectable decision record, perform no I/O, and require no runtime LLM.

## Boundaries

- Preserve existing pure reconstructed-core modules and no-root Termux constraints.
- Hard eligibility precedes optimization; ineligible actions never receive selection priority.
- Provider/source count is not evidentiary independence. Independence must come from independent lineage roots or an explicit conservative unknown.
- Decision and execution remain separate.
- Same state plus same candidates yields the same decision.
- Unknown inputs remain explicit and must not silently become optimistic.
- Live dispatch wiring is out of scope until the pure policy passes its proof obligations.

## Control path

```text
CURRENT VERIFIED STATE
+
UNRESOLVED PROOF OBLIGATIONS
+
CANDIDATE ACTIONS
        ↓
HARD ELIGIBILITY
        ↓
DOMINANCE ELIMINATION
        ↓
EXPECTED DECISION VALUE
        ↓
DETERMINISTIC RANKING
        ↓
SELECT / TERMINATE
        ↓
DECISION RECORD
```

## Acceptance

The slice is accepted only if tests demonstrate:

- source count alone cannot manufacture independence;
- lineage-derived independent-root count can affect independence explicitly;
- ineligible actions are never selected regardless of utility;
- missing dependency, permission, feasibility, precondition, or explicit block makes an action ineligible;
- dominated actions are removed before ranking;
- selection is deterministic with stable tie-breaking;
- best eligible EDV <= 0 terminates;
- decision records contain eligibility/rejection reasons, component scores, ranking, and termination reason;
- the module is compiled/exported from the crate;
- the full Rust test/clippy/fmt and Android aarch64 CI remain green.
