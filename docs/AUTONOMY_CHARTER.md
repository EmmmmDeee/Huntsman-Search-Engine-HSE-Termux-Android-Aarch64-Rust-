# Autonomy Charter — the autonomous engineering loop's immutable core

> **Scope note.** This document governs how an automated contributor (Claude
> Code) *engineers this repository* under an unattended, recursive loop. It is
> **not** about running the shipped product unattended — that is
> [`AUTONOMY.md`](AUTONOMY.md). Keep the two separate.

This charter is the **non-self-modifiable core** the loop re-loads verbatim at
the start of every cycle. The loop's controller prompt may regenerate its own
per-cycle state, but it may **never** rewrite the invariants below. Where this
charter and a running check disagree, the check wins and the *prompt* is fixed —
never this charter's guarantees.

It sits under, and never overrides, the binding specs it inherits from:

- [`OPERATIONAL_CONSTITUTION.md`](OPERATIONAL_CONSTITUTION.md) — truthfulness
  outranks presentation; separate observation from inference; confidence follows
  evidence; never fabricate. Its Order of Precedence wins every conflict.
- [`PERSISTENT_INTELLIGENCE.md`](PERSISTENT_INTELLIGENCE.md) — carry validated
  findings forward; treat every failure/contradiction as diagnostic; don't close
  an investigation while material uncertainty is still reducible.
- [`../SECURITY.md`](../SECURITY.md) — defensive-only posture.

A guard test (`tests/autonomy_charter.rs`) fails CI if any invariant marker or
cycle stage below is removed, so no guardrail can be lost by a quiet edit.

---

## Immutable invariants (refusal conditions — violate none, ever)

- **INV-1 — Never fabricate.** No invented evidence, measurements, sources, or
  certainty. If you did not run it, say so. CI is ground truth, not your claim.
  Report failing checks with their real output, not around them.
- **INV-2 — Never regress.** Every cycle leaves `origin/main` green under the
  **full** gate (`scripts/gate.sh`). The cross-build and MSRV pin are
  authoritative in CI where this host can't run them.
- **INV-3 — Never weaken the ratchet.** No deleted assertion, no new
  `#[allow]`/`#[ignore]`, no lowered threshold, no removed public-surface
  coverage — unless replaced by a strictly stronger check in the same commit. A
  tripped architecture invariant is a design decision to raise, not to silence.
- **INV-4 — Never commit red, and never merge red**, and never expand a unit's
  scope mid-commit. One unit = one PR = one squash-merge, on CI-green only.
- **INV-5 — Defensive-only.** Add no capability whose primary use is
  unauthorized access, exploitation, persistence, credential theft, or evasion.
  MITRE ATT&CK is integrated for detection/mapping/threat-modeling only (see
  below); never build the offensive techniques themselves.
- **INV-6 — Secrets and personal data stay out.** API keys live only in an
  untracked `~/.huntsman.env`; they never enter git, source, tests, commits,
  PRs, or chat. Location/medical/contact data is never committed.
- **INV-7 — Truthfulness outranks presentation.** A hedged, correct answer beats
  a clean, overconfident one. Unknowns and assumptions are stated at the point
  they affect the work.

---

## MITRE ATT&CK — defensive integration scope (standing workstream)

ATT&CK is treated as **threat-informed defense**, end to end:

1. **Map** existing HSE correlator rules, detections, and exposure signals to
   ATT&CK technique IDs; keep a coverage matrix.
2. **Measure** coverage and gaps against the OSINT / breach-intelligence /
   GEOINT threat model this tool actually serves.
3. **Close** gaps by adding *detections* and threat-model correlations for
   uncovered techniques — asset discovery, exposure assessment, detection,
   remediation.
4. **Emit** ATT&CK-tagged findings so downstream defenders can pivot.

If a "gap" can only be closed by building attacker capability, it is
out-of-scope by **INV-5**: log it in the ledger as rejected and move on.

---

## Cycle protocol (ordered; each cycle is atomic at the PR boundary)

The loop runs these stages in order. All are load-bearing; none may be skipped.

1. **RECONCILE** — reconcile reality first (crash-safety): fetch, inspect
   `origin/main`, open PRs, and CI. Resolve any in-flight PR (drive to
   green→merge, or diagnose+report) before starting new work. Sync the working
   branch to `origin/main`.
2. **SENSE** — derive current state from authoritative sources only, never from
   recall: build and query the binary (`hse --help`, `hse modules`,
   `hse selftest`, `hse diagnostics`), read `scripts/gate.sh`, read `git log`
   since the last cycle. Cite every fact to its source.
3. **SELECT** — find the highest-leverage unit via *delegated coverage* (fan out
   readers across subsystems; hold conclusions, not file dumps). Adversarially
   **verify** each candidate against real source (default: not-a-defect unless
   the code plainly shows it). Rank survivors: correctness on hot/live-data
   paths ▸ architectural debt ▸ coverage gaps ▸ docs. Dedup against the ledger.
   Pick exactly one. If nothing clears the leverage bar, **escalate** scope
   (deeper audit, an untouched subsystem, the perf/fuzz/property-test frontier)
   rather than ship filler — and say plainly that marginal value was low.
4. **PROVE** — red-then-green. Write the failing test first and capture its real
   failure output; then implement the smallest correct fix.
5. **GATE** — run the full `scripts/gate.sh`; report every check as PASS / FAIL /
   SKIP-with-reason from real output.
6. **SHIP** — commit with a precise red→green message, push, open one PR to
   `main`, drive CI to green (re-diagnose and re-kick on failure; address review
   comments by verify-then-fix), squash-merge on green.
7. **RECORD** — append the outcome to the ledger below: unit shipped, leverage
   rationale, evidence, and any candidate rejected-with-reason.
8. **REFRESH** — regenerate only the controller prompt's per-cycle state block,
   display the full updated prompt in a fenced box, then begin the next cycle at
   RECONCILE. This charter's core is copied verbatim, never rewritten.

---

## Ledger (append-only record of shipped and rejected units)

Each cycle appends one row. Rejected candidates are recorded too, so they are
not re-proposed. This is committed state, not memory.

Rows are written **one cycle in arrears**: a cycle's row records its PR number,
which only exists after SHIP, so cycle *N* records cycle *N−1*. This keeps every
row factual rather than predicting an unassigned number.

| Cycle | Date | PR | Unit | Leverage rationale | Evidence | Rejected-with-reason |
|------:|------|----|------|--------------------|----------|----------------------|
| — | 2026-08-02 | — | Charter established | Foundation for the never-regress recursive loop | `tests/autonomy_charter.rs` guards every invariant/stage | — |
| 2 | 2026-08-03 | #330 | Guard `.env.example`, the last unguarded provisioning surface | It was the only one of four provisioning surfaces with no guard, and had already drifted (`HUNTSMAN_ALIENVAULT_KEY` documented everywhere else but not there). With cycle 1 this makes all four mechanically self-maintaining. | Red: `module(s) read a key the repo-root .env.example never documents … ["HUNTSMAN_ALIENVAULT_KEY"]`. Green: architecture 40. Copilot review (`split_once('=')`, sorted output) verified real and folded in. | Reverse check (documented ⇒ consumed): rejected — would false-positive on 5 config knobs + 9 reserved keys and pressure deleting real operator docs. |
| 1 | 2026-08-02 | #329 | Close the key-guard blind spot that hid `HUNTSMAN_GITHUB_TOKEN` | Guard saw only `const …ENV` declarations, so inline `key_opt("…")` reads were exempt — a registered, poolable credential read by 3 live modules was invisible to Settings, `hse provision` and `hse doctor`. Fixing the detector closes the whole bug class, not one instance. | Red: `module(s) read a key env_template.txt never mentions … ["HUNTSMAN_GITHUB_TOKEN"]`. Green: architecture 40, util::keys 29, app::doctor 13. Confirmed end-to-end — `hse doctor` now ranks it `[multiplier]`. | Adding `/stealer` to `ENDPOINT_COSTS` (earlier cycle): rejected — endpoint is live-verified 404 and never called, so a cost row would be dead config contradicting its removal. |

<!-- New ledger rows are appended above this line by the RECORD stage. -->
