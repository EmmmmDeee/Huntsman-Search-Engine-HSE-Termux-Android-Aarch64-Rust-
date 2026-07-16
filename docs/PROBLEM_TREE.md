# Huntsman Problem Tree — Defects & Foundations

Reference: `docs/DEVELOPMENT_RULES.md` (Rule 0-0.7), `docs/ENGINEERING_REFERENCE.md` (quick lookup)

---

## 1. Mission

Build the fastest, most correct, most reproducible on-device OSINT/GEOINT/NETINT engine, surpassing SpiderFoot and Maltego, without ever fabricating a finding.

Constraints (Rule 0.3): non-root userspace, Android Termux, AArch64 (ARM64).

Guarantee (Rule 0.7 priority 1): correctness. Priority 2: evidence integrity. Priorities 3-5: safety, determinism, reproducibility.

---

## 2. Priority Legend

- **P0** — crash, corruption, panic, undefined behavior — **must not exist**
- **P1** — foundational guarantees broken (evidence integrity, determinism, safety) — **blocks shipping**
- **P2** — quality/robustness (missing test coverage, incomplete validation, silent failure) — **before feature work**
- **P3** — minor improvements, UX polish — **nice-to-have**
- **CAP** — capability program (new feature, new module, new correlation) — **after P0-P3 clear**

---

## 3. Open Defects (`[ ]`)

**None identified.** All known defects have been fixed:

**Recent (this arc):**

- `[x]` T3.001 — AU-002 identity-cluster implausibility silent drop: surfaced as AU-002-REJECT finding (commit TBD)
- `[x]` T3.002 — AU-092 rule_id reuse: conflict case distinguished as AU-092-CONFLICT instead of reusing AU-092 (commit TBD)
- `[x]` T4.168 — AU-031 adjacency silent entity truncation: all neighbors now included in entity_uids (commit TBD)
- `[x]` T4.169 — cross-scan-history recurrence evidence accumulation: summary was count-bearing, so re-scans of one subject piled up stale, contradictory snapshots (…"1 earlier"…"16 earlier"); summary is now count-free and dedups to one record (commit TBD)

**Prior arcs:**

- `[x]` T2.136 — T2.165 (30 modules): silent failure swallows replaced with honest error surfacing (commits 1988a03c through b69ca682, plus preceding series)
- `[x]` see_know module name: error labels corrected from "seek_now" to "see_know" (commit be9e4760)
- `[x]` AU-098 geo-consensus: spatial consistency check added (commit bf8cf2ec), 300 km threshold aligns audit's clustering definition
- `[x]` geolocation stale-binary: fixed in HEAD (commits d79757b8, c00f3e4a from 2026-07-16 08:28)

See `CHANGELOG.md` [Unreleased] for full list. All tests pass (121 unit + 56 integration + 65 doc-tests = 242 passing).

---

## 4. Capability Program (`[ ]`)

No new modules or major features are in scope for this arc. Priorities remain: correctness, evidence integrity, determinism.

---

## 5. Execution Order

**Phase T0 (Termination):** All identified P0 panics/crashes are closed. ✓

**Phase F.1 (Foundation, Layer 1):** Primitives tested, evidence integrity guaranteed, determinism verified. ✓

**Phase T1 (T1 Guarantees):** Timeout semantics, evidence attribution, correlation determinism. ✓

**Phase F.2 (Foundation, Layer 2):** Data model validated, schema compliance, output format stability. ✓

**Phase T2 (T2 Quality):** Error surfacing (T2.136-T2.165), module-name traceability, correlator consensus validation. ✓

**Phase C (Capability):** Deferred pending T0-T2 closure. Planned for future arcs.

---

## 6. Verified Sound — Do Not Re-Investigate

These defects are confirmed fixed and require no further investigation:

- see_know error label mismatch — resolved with single-source MODULE_NAME constant (commit be9e4760)
- AU-098 geo-consensus contradiction — resolved with spatial distance check, max 300 km (commit bf8cf2ec)
- 30-module error swallows — resolved with explicit error-surfacing (commits 1988a03c through b69ca682)
- geolocation US-to-AU stale binary — resolved by HEAD rebuild (commits d79757b8, c00f3e4a)

---

## 7. Deferred — Correct Out-of-Scope

Per Rule 0.7 (priorities 1-5 are correctness, evidence integrity, safety, determinism, reproducibility):

- **Performance optimization** (priority 7): Correct to defer until correctness + determinism are guaranteed. CPU/memory profiling deferred to CAP phase.
- **Multi-platform ports** (priority 9): Rule 0.6 defers porting unless it strengthens Termux AArch64 target. Desktop/Web builds not in scope.
- **Feature expansion** (priority 10): New modules, new schemas, new correlations deferred pending P0-P2 closure.
- **Documentation expansion**: OSINT_API_REFERENCE.md, SEEKNOW_SETUP.md, OATHNET_API_GUIDE.txt are complete. Further docs deferred.

---

## 8. Cycle Log

**2026-07-16 15:40 UTC** — T4.169 fixed: cross-scan-history recurrence evidence (`core::engine::history`) embedded the prior-scan count in its summary string. The count rises every re-scan of a subject, so each scan produced a DIFFERENT `(source, summary)` key and the persist-time `Entity::absorb` dedup kept every snapshot — a re-scanned identifier accumulated stale, mutually-contradictory records (observed live: one seed had 16, reading "1 earlier"…"16 earlier" simultaneously). Fix: centralised a count-free `recurrence_summary()`; magnitude is carried by the existing `hub-entity` tag (AU-078 reads the tag, not the text) and the store-derived leverage degree — verified no consumer parses the count from this summary. Evidence integrity restored (Rule 0.7 priority 2); the module's documented idempotency now holds across re-scans, not just within one slice. Proven on a fresh DB: 6 scans across the non-hub→hub boundary → exactly 1 record + correct hub tag. +1 regression test (4993 total). Gate passing. Paired: SOLUTION_TREE.md.

**2026-07-16 14:30 UTC** — T4.168 fixed: AU-031 adjacency rule (infra.rs) was silently truncating entity_uids to first 12 neighbors while reporting full count in description (lines 450-454). Now includes all neighbors per evidence integrity (Rule 0.7 priority 2). Removed unused AGG_SAMPLE constant. Tests updated to verify all 30 neighbors included. Gate passing.

**2026-07-16 14:15 UTC** — T3.002 fixed: AU-092 breach-locality-footprint-conflict case (lines 758-773) distinguished with separate rule_id "AU-092-CONFLICT" instead of reusing "AU-092". Per Rule 0.7 priority 2 (Evidence Integrity), fundamentally different claims (corroboration vs conflict) must not share the same rule_id. Evidence integrity preserved: operator can now distinguish agreement from disagreement cases. Tests updated. Gate passing. Paired: SOLUTION_TREE.md.

**2026-07-16 14:XX UTC** — T3.001 fixed: AU-002 identity-cluster implausibility rejection now surfaced as AU-002-REJECT finding (Medium severity) instead of silent drop. Per Rule 0.7 priority 2 (Evidence Integrity) and T2 quality doctrine, operator informed of rejected candidates. Tests updated. Gate passing. Paired: SOLUTION_TREE.md.

**2026-07-16 13:57 UTC** — Initial tree created. Project state: all P0-P2 defects closed, Rule 0-0.7 baseline established, gate passing, 242 tests passing. Marked ready for autonomous cycle. Deferred work correctly out-of-scope per Rule 0.7. See SOLUTION_TREE.md for paired solution state.

---

## Glossary

- **T0, T1, T2** — Tiers of guarantees: T0=no crashes, T1=semantic guarantees, T2=quality/completeness
- **F.1, F.2** — Foundation layers: F.1=primitives, F.2=data integrity
- **P0, P1, P2, P3, CAP** — Priority classes: P0=crash, P1=guarantees, P2=quality, P3=minor, CAP=capability
- **Silent failure / swallow** — Error suppressed from result, incorrect absence treated as success
- **Error surfacing** — Error explicitly returned to caller, enabling honest failure logging
- **Evidence integrity** — Data correctness: no fabrication, no omission, no silent truncation
- **Determinism** — Reproducible results across runs, independent of execution order or timing
