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
| 2026-06-23 | `core::entity::normalise` (Email) now strips invisible format/zero-width noise (BOM U+FEFF, ZWSP U+200B, ZWNJ/ZWJ/WJ) and treats control chars (NUL, …) as value terminators. | **Identity integrity / anti-fragmentation.** A BOM-prefixed or ZWSP-embedded address (common in UTF-8-BOM exports and dirty breach dumps) keyed the *same* mailbox to a *different* SHA-256 UID, splitting one person's footprint across two nodes — corrupting corroboration counts and the evidence chain. Now the clean and noisy spellings share one UID. | 3539 ✅ |
