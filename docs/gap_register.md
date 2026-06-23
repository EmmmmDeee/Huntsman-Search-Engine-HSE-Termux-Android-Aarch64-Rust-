# Gap Register — autonomous improvement log

Running log of source-intelligence improvements, one line per change: **what / why
(LE-defence evidentiary or OSINT-quality value) / test result**. Newest at the top.

> **Baseline note (honest reconciliation).** The autonomous protocol that seeded this
> loop stated a CURRENT STATE of `v9.0.0 · 8,239 LOC · 29 modules · 46 tests` and an
> `LlmAuditRecord` priority. That describes a different codebase. This repository is
> **v1.9.0 · ~172k LOC · 124 modules · 3,539 lib + integration tests**, and it carries a
> **guard-enforced no-AI/ML/LLM invariant** (`runtime_carries_no_ai_ml_inference_dependency`),
> so there are no runtime LLM call boundaries to audit — that priority is inapplicable and
> was not built (it would be a dead field, failing this register's own quality bar). The
> loop is therefore run against the **real** baseline, on genuine improvements, keeping the
> actual 3,539-test suite green.

| Date | Change | Why (evidentiary / OSINT quality) | Tests |
|------|--------|-----------------------------------|-------|
| 2026-06-23 | AU-061 (family geo-corroboration) now commonness-gates its Critical escalation: a COMMON subject surname caps at High (not Critical) and softens the "relatives" wording. Relocated `subject_surname` from `engine::passes` to `core::geo_family` as the single shared source. | **Wrong-attribution (Critical false kin).** Within `FAMILY_GEO_KM` (150 km) the existing namesake pass doesn't fire (it guards only >800 km), so three unrelated "Smith"s in one metro catchment were asserted Critical "household of relatives". A common surname makes shared-region co-location weak evidence — now a High lead to verify; a distinctive surname keeps the strong Critical signal. Mirrors the AU-051 / kinship commonness gates. | 3542 ✅ |
| 2026-06-23 | Closed admission-gate placeholder gaps: `is_placeholder_email_local` now rejects `test`/`redacted`/`placeholder` local-parts, and `is_placeholder_username` rejects `redacted`/`placeholder`. Updated the one smoke fixture that used `test@contoso.com` as a real target. | **Anti-garbage-promotion.** `test@gmail.com`, `redacted@…`, the `redacted` handle were admitted as real entities — polluting the graph and falsely corroborating. The admission gate doesn't consult the role-mailbox path, so these slipped through. Exact-match (separator-stripped) only, so real handles that merely contain the token (`tester`, `firstnations`, `redactedtruth`) are untouched. | 3540 ✅ |
| 2026-06-23 | Extended the invisible-noise strip to the `Username` and `Domain` normalize arms via one shared `strip_format_noise` helper (BOM/ZWSP/ZWNJ/ZWJ/WJ), borrowing on the clean path so the hot normalize path doesn't allocate. | **Identity integrity, made uniform.** The same BOM/zero-width fragmentation that hit emails also forks a `Username` (`\u{feff}@handle`) and a `Domain` (`\u{feff}example.com`) into a second UID. One helper now guarantees the three identity kinds dedup consistently — no kind is a fragmentation gap. | 3540 ✅ |
| 2026-06-23 | `core::entity::normalise` (Email) now strips invisible format/zero-width noise (BOM U+FEFF, ZWSP U+200B, ZWNJ/ZWJ/WJ) and treats control chars (NUL, …) as value terminators. | **Identity integrity / anti-fragmentation.** A BOM-prefixed or ZWSP-embedded address (common in UTF-8-BOM exports and dirty breach dumps) keyed the *same* mailbox to a *different* SHA-256 UID, splitting one person's footprint across two nodes — corrupting corroboration counts and the evidence chain. Now the clean and noisy spellings share one UID. | 3539 ✅ |
