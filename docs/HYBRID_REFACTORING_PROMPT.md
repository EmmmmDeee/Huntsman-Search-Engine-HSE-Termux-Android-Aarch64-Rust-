# HSE Hybrid Refactoring Operator

Executable prompt. Not a literature review. Bind it to one opportunity,
run the loop, stop at a gate. Do not spray.

This file is the refactoring operator only. It does not supersede
`AGENTS.md` (issued agent query) or `RULE.md` (evidence law).

Provenance (methods kept only where they compose without fighting):

| Role in this hybrid | Method | Source |
|---|---|---|
| Control loop | Planner → Generator → Compiler → Tester → reflect | RefAgent, arXiv:2511.03153 |
| Inner quality pass | Recursive criticism and improvement (RCI) beats one-shot | EMR study, arXiv:2510.26480 |
| Safety | LLM detects; a verified engine / tests reapply. Freeform rewrite is a proposal, not an accept | RefactoringMirror, arXiv:2411.04444 |
| Identification | Name the Fowler subcategory; narrow the search space (15.6% → 86.7%) | Liu et al., arXiv:2411.04444 |
| Instruction shape | Motive + procedure + transformation objective per type | Fowler-instruction strategies, arXiv:2510.03914 |
| Scope | Atomic before compound. Compound is the main failure mode | SWE-Refactor, arXiv:2602.03712 |
| Cross-file reuse | Cluster shared structure, sample K, rerank on compression × correctness | Librarian, arXiv:2506.11058 |
| Hallucination filter | Static feasibility ∩ semantic relevance ∩ self-consistent critique | MM-assist, arXiv:2503.20934 |
| Systematic edits | Code the transform from I/O examples; do not one-shot rewrite the tree | arXiv:2410.08806 |
| Stop rule | Iterate until metrics stabilize; further passes add churn | Iterative readability, arXiv:2602.21833 |

Rejected as non-synergistic here: fine-tuning (no training loop),
unbounded multi-class sweeps (RefAgent project-wide default),
readability-only loops that trade structure for comments.

---

## 0. Bindings (this repository)

- Language: Rust. The type system is the first refactoring engine.
- Evidence law: `RULE.md`. A refactor that changes emitted claims is a
  behavior change, not a refactor.
- Agent law: owner-issued FRONTIER-MODEL directive in `AGENTS.md`.
- Compiler agent: `cargo check` / `cargo clippy --all-targets` on the
  affected package and feature set.
- Tester agent: the smallest existing test that would fail if behavior
  moved; then the relevant `cargo test` slice. Do not invent greenness.
- Platform: Termux aarch64 remains the acceptance host for platform-
  dependent behavior. Host-check is not Termux-accept.
- One operator: update this file in place. Do not add a sibling spec.

---

## 1. Planner (run once per opportunity)

Fill every line. Empty line = stop.

```
TARGET_PATHS:
SMELL / LIMITING FACTOR:          (one)
FOWLER_SUBCATEGORY:               (one primary; optional second only if atomic-composed)
MOTIVE:
PROCEDURE:                        (numbered, behavior-preserving)
TRANSFORMATION_OBJECTIVE:
INVARIANTS_UNCHANGED:
INTENDED_BREAKAGE:                (none unless named)
STATIC_FEASIBILITY:               (compile-visible: visibility, ownership, trait bounds)
SEMANTIC_RELEVANCE:               (why this site, not a neighbor)
CLUSTER?:                         (yes only if ≥2 files share the same structure)
K_SAMPLES:                        (1 unless CLUSTER; then 2–3, rerank)
SUCCESS_METRICS:                  (test slice, clippy, smell count, LOC of the site)
ROLLBACK:                         (git path)
```

Allowed primary subcategories on HSE (narrow set):

- Extract Function / Extract Module
- Inline Function / Inline Module
- Rename
- Move Function / Move Module
- Replace Duplicate with Call / Canonical Implementation
- Introduce Newtype / Make Invalid States Unrepresentable
- Collapse Layer / Remove Dead Abstraction
- Encapsulate / Narrow Visibility

If the change is not one of these, it is not this operator. Use the
Frontier directive’s ordinary engineering loop instead.

---

## 2. Generator

Produce the smallest diff that executes PROCEDURE.

Rules:

1. Propose, then apply through the verified path (compiler + tests).
   Do not accept an LLM rewrite that the compiler and tests have not
   seen.
2. If the same edit repeats across files, stop and code a transform
   (script, `sed` with proof, or a rustc/syn tool) from 2–3 I/O
   examples. Run the transform. Do not hand-edit the 4th copy.
3. If CLUSTER, sample K independent diffs, score each with
   `correctness first, then deleted duplication, then simplicity`.
   Keep one.
4. Do not widen visibility, add `unwrap()`, add `unsafe`, or add a
   crate to make the diff shorter.
5. Delete the replaced implementation in the same change.

---

## 3. RCI (mandatory inner loop)

After the first diff:

```
CRITICIZE:
- What behavior could this have changed that tests do not cover?
- What second source of truth did this leave behind?
- What invalid state can the new types still represent?
- Would deleting this abstraction still pass SUCCESS_METRICS?

IMPROVE: only issues the critic can point to in the diff.
STOP when a pass changes nothing material, or when metrics bounce.
Max 3 RCI cycles. Churn after that is a failed candidate.
```

---

## 4. Gates (any miss = reject / repair / rollback)

- Compiles for the affected package and features.
- Named test slice passes.
- No new `unsafe` without a soundness contract.
- No second authority file for the same contract.
- Invariants listed in the plan still hold.
- Replaced code is gone.
- Compound refactoring was not smuggled in as “cleanup”.

---

## 5. Accept record

```
SUBCATEGORY:
PATHS:
EVIDENCE:          (commands + outcomes)
RCI_CYCLES:
REJECTED_ALTERNATIVES:
RESIDUAL:
```
