# Huntsman Development Rules

Core principles for pragmatic, measurement-driven, performance-obsessed development in the HSE codebase.

## Rule 1: Complete Files Only – No Partial Work

**Core Principle**: Every file shipped must be complete, production-ready, and internally coherent. Partial edits, stubs, or half-finished implementations create technical debt that compounds.

- Write the entire function, module, or refactor in one pass; never leave `TODO`, `FIXME`, or `unimplemented!()` in production code.
- A file's visibility (public/private), dependencies (imports), and exports (pub use, re-exports) must be complete and justified.
- If a task is too large for one commit, split it explicitly: mark the node `[~]` in PROBLEM_TREE, ship the first half, then ship the second half in the next cycle—never ship incomplete work and call it done.
- Complete tests accompany complete code; a function without a test that exercises both happy path and edge cases is incomplete.

**Enforcement**: `cargo fmt`, `cargo clippy`, `cargo doc` must pass on every file. If a file doesn't compile or tests don't run, it doesn't ship.

---

## Rule 2: Aggressive Workaround Culture – Ruthless Pragmatism

**Core Principle**: Prefer a working solution that ships today over a theoretically perfect one that ships in three cycles. Optimization obsession without measurement is waste.

- A one-off `if` statement that solves the bug is better than a 200-line abstraction that "might help future code."
- Don't refactor surrounding code unless it directly unblocks the change. No "while we're here" cleanups.
- Don't add helper functions, trait impls, or macros until the third identical use; two instances can live with duplication.
- Performance gut-checks (Amdahl's Law, cache-line alignment, allocation counts) beat theoretical elegance. If a brute-force loop is faster than a fancy algorithm on real data, ship the loop.
- Comments explaining *why* a workaround exists are valuable; comments explaining *what* the code does are noise—good names say what; context says why.

**Enforcement**: Every cycle, measure. Use `criterion.rs` benchmarks for hot paths; use `perf record` for whole-program profiles. No optimization without numbers.

---

## Rule 3: Synthetic Fixtures for Automated Tests; Live APIs for Production

**Core Principle**: Automated test suites MUST be deterministic, reproducible, and measurable. Live API calls contaminate all three with network variance and upstream changes.

**Automated Tests** (the default):
- Use established synthetic seeds: `Kylo4kylo` for people, `test-domain.invalid` for domains, `TEST-NET 192.0.2.0/24` for IPs, `example.com`/`example.org` for hosts.
- Every test is bit-for-bit reproducible between runs. Zero non-determinism. No `rand::random()`, no `Instant::now()`, no network calls.
- Fixtures are hardcoded JSON or inline Rust constants; they never change, so test failures point to code, not upstream.
- All stats, performance claims, and regression analysis depend on deterministic tests. Live tests corrupt the data.

**Integration Tests** (exceptional):
- If a bug reproduces only against real upstream data and can't be simulated, write a `#[ignore]` test documenting the case and mark it manual-run-only.
- Never include live API calls in the automated suite without `#[ignore]`.

**Production Code** (live APIs required):
- HSE's search engine must fetch real data from real APIs—that's the entire point. `reqwest`, `tokio`, `hyper` make this reliable.
- Live API errors (timeouts, rate limits, 404s) are handled in production; they're never handled in test code.

**Why**: 
- Determinism enables reproducible debugging and performance measurement.
- Live tests hide the real code variance under network variance; you can't optimize what you can't measure.
- Upstream API changes break live tests; fixtures never break.
- CI/CD must be reliable; flaky tests from network jitter waste developer time.

**Enforcement**: `cargo test` must pass with 100% determinism. Any test making a network call must have `#[ignore]` and a comment explaining why.

---

## Rule 4: Andrew Gallant Craftsmanship – Performance Obsession + Pragmatism

**Core Principle**: Write code like Andrew Gallant writes regex engines—obsess over performance, measure relentlessly, ship ruthlessly, and never accept waste.

- Every hot loop is a candidate for measurement. Use `perf`, `flamegraph`, or micro-benchmarks to prove an optimization is real.
- Allocation is waste. Prefer stack to heap; prefer borrowed to owned. `Vec::with_capacity()` before loops. `String::reserve()` before appends.
- Cache locality matters. Struct field order, loop iteration patterns, and data layout affect real performance.
- Premature optimization is a myth—measurement is the only truth. If the data says optimize, optimize. If it says ship as-is, ship.
- No "nice-to-have" abstractions. No generics for hypothetical future use. No inheritance hierarchies disguised as traits.
- Readable code is fast code. Clarity beats cleverness. A simple loop is faster to read, faster to debug, and often faster to execute.

**Enforcement**: Every performance claim is backed by a benchmark. Every loop is profiled before claiming efficiency. No optimization without evidence.

---

## Rule 5: Maximum File Synergy – Link and Leverage Everything

**Core Principle**: No module is an island. Every file must synergize with related code—shared vocabularies, reused types, consistent patterns.

- A new module uses the existing `Entity`, `Evidence`, `Target` vocabulary; it doesn't invent new types.
- Constants (MAX_HITS, confidence baselines, timeout values) are defined once and reused everywhere. Duplicated magic numbers are bugs waiting to happen.
- Test patterns are consistent: `#[test] fn name_describes_single_behavior()`. Reuse test fixtures and helpers.
- Error handling is centralized: `core::error::Result<T>` everywhere, no ad-hoc Option returns in module boundaries.
- Module metadata (name, priority, cost, attack_techniques, produces/accepts) are complete and synchronized; they're the contract between dispatch and the module.

**Enforcement**: `grep -r "magic_number"` or `grep -r "const UNNAMED"` catches violations. Every module's test count should match the module's feature surface. Clippy's `missing_docs` and `single_match` lint catch synergy violations.

---

## Rule 6: Recursive Expansion – Exploit Every Pivot Aggressively

**Core Principle**: HSE's power comes from pivoting: an email spawns a domain, a domain spawns IPs, an IP spawns whois contacts, contacts spawn more emails. Maximize this.

- Every `Entity` is a potential seed for downstream modules. Passive DNS pivots (A, AAAA, MX, NS, CNAME) are not "nice extras"—they're mandatory expansion fuel.
- Entity kind production (`produces()`) and consumption (`accepts()`) are the dispatch graph's skeleton. An IP entity must trigger modules that accept IPs; a domain entity must trigger modules that query that domain.
- Truncation signaling (MAX_HITS, MAX_RECORDS, MAX_SECRETS) must surface pivot counts so the operator knows what was capped. Evidence attributes (total_dns_records, secrets_captured) enable statistical analysis.
- Expansion weight is everything: a module that returns 50 IPs from one domain query has 50x the dispatch leverage of one returning 1 Email. Measure this; prioritize high-ROI modules.
- Recursive searches (find contacts, then search those contacts' other domains) are enabled by clean entity vocabulary and consistent tagging (breach, threat_intel, resolved, passive-dns).

**Enforcement**: Every module's test includes at least one pivot scenario. Truncation gaps (capped at MAX_X without signaling) are bugs, not features. Expansion weight is tracked in `SOLUTION_TREE` module-priority section.

---

## Rule 7: Data-Driven Improvement – Measure Everything, Trust Numbers

**Core Principle**: Never ship an optimization or capability without evidence. Intuition is noise; data is truth.

- Every code change comes with before/after metrics: test count, compilation time, binary size, runtime performance on fixed seeds.
- Module ROI is scored by `expansion_weight = (entities_produced / dispatch_calls)`. High-ROI modules get priority; low-ROI modules get aggressive simplification.
- Confidence scores are calibrated against real outcomes: if a module's 0.75-confidence entities have a 60% accuracy rate in manual spot-checks, adjust. Don't guess.
- Performance budgets exist: if `cargo build --release` takes >30s, it's a regression. If tests take >60s, it's actionable. Track these in CI.
- Deprecation decisions are data-driven: if a module produces <1 entity per 100 searches, it's a candidate for removal.

**Enforcement**: Every cycle's `gap_register.md` entry includes: `test count after`, `performance delta`, `expansion weight`, `why this matters`. No entry without evidence.

---

## Rule 8: Maximize Autonomy – Design for Self-Guided Improvement

**Core Principle**: The codebase must guide the next developer (or automated tool) toward the right fix without hand-holding.

- Error types are rich and specific. `Result<T, ModuleError>` carries context: which module, which target, which phase, what rate limit hit. Not a generic `Err("api call failed")`.
- Module metadata is complete and up-to-date: `priority()`, `cost()`, `category()`, `attack_techniques()`. A new dispatcher can read these and make smart routing decisions.
- Test names are precise: `truncation_at_max_secrets_is_surfaced()` says exactly what's being tested. No `test_comb_search_works()`.
- Evidence attributes are consistent and complete: every entity has `source`, `timestamp` (if relevant), and totals/capped flags for truncation. A future tool can build statistics on this.
- The architecture doctrine (layering: cli/api → core → util; one module per file; single-sourced vocab) is non-negotiable. It enables predictability.

**Enforcement**: New modules must pass `tests/architecture.rs` checks. Missing `attack_techniques()` fails CI. Vague test names trigger reviewer push-back.

---

## Rule 9: Autonomous Debugging – Design Reproducibility In

**Core Principle**: When a bug appears in production, the code must allow offline reproduction with zero network calls.

- Every module's `process()` function is pure or has a seam for testing: input (Target, context) → output (ModuleResult). State mutations are tracked.
- Truncation signaling (Rule 6) is mandatory: if a module caps at MAX_X, it marks evidence and tags the entity. The operator never guesses why 50 results surfaced instead of 500.
- Deterministic randomness is a contradiction: either use fixed seeds (for simulation) or live data (for production). Never mix.
- Timestamp handling is explicit: if a result changes based on `Instant::now()`, it's documented in evidence. If it's deterministic, fixtures prove it.
- Regression tests are co-located with the bug they fix: if a module over-attributed strangers' credentials, that test lives in the module forever.

**Enforcement**: Any feature that passes locally but flakes in CI is a red flag. The code must explain *why* a result surfaced; evidence is not optional.

---

## Rule 10: No Fabrication, Ever – This Is Not Optional

**Core Principle**: HSE is an evidentiary tool. A false positive is worse than a missed lead. Never fabricate, never speculate, never invent.

- Fixtures are either established test seeds (Kylo4kylo) or null/empty. Never invent a real third party's PII. Never mock a WHOIS response with made-up data.
- An entity's confidence score reflects real calibration: if you don't have evidence for 0.80, use 0.50. Don't guess.
- Attribution is exact or absent: if a credential's email substring matches 100 domains, don't attribute it to all 100. The `line_matches_target()` filter prevents this.
- A module that can't answer correctly stays silent. Empty results are acceptable; fabricated results are not.
- Evidence attributes tell the truth: if MAX_RECORDS=30 and you hit 150, say so (total_dns_records=150, dns_records_capped=true). Don't hide it.

**Enforcement**: Every entity must trace to real upstream data (API response, file parse, network fetch). Fixtures are the only exception, and they're hardcoded and auditable.

---

## Rule 11: Measurement Integrity – Statistical Analysis Is Sacred

**Core Principle**: HSE's code improvements must be measurable. Live test data contaminates every statistical claim; reproducible fixtures enable honest measurement.

- Before/after comparisons are meaningless without deterministic baselines. If Test A passes with live APIs and Test B passes with fixtures, you can't claim B is faster.
- Performance regression detection depends on stable test suites. If a test flakes 5% of the time due to network variance, you can't spot a 2% regression.
- Expansion weight calculation (entities_produced / dispatch_calls) requires accurate, reproducible counts. Live tests hide the real counts under de-duplication and network retries.
- Confidence calibration requires reproducible evaluations. If you re-run the same fixture 10 times and get different results, the code is non-deterministic and the calibration is garbage.

**Enforcement**: Every optimization claim is backed by 10 runs of the same fixture with mean and stddev. Any stddev >2% in a deterministic test is a red flag. Performance regressions are caught automatically in CI.

---

## Rule 12: Module Composition – No Dead Weight

**Core Principle**: Every module earns its place by producing high-ROI entities that enable downstream pivots.

- A module that produces only the seed entity (no pivots, no enrichment) is a candidate for removal.
- A module that produces 1 entity per 1000 searches has negative ROI and should be simplified or cut.
- Passive DNS (A, AAAA, MX, NS, CNAME) from threat intel modules (VirusTotal) is mandatory—they're high-ROI pivots.
- Truncation caps (MAX_DNS_RECORDS, MAX_SECRETS, etc.) must surface entity counts so future optimization can target high-value pivots first.
- Module categories (Breach, Threat, People, Domain, Geo) must align with their output. A Breach module produces Email/Password; a Threat module produces Domain/IP enrichment.

**Enforcement**: Every module's `produces()` output is tested. Every truncation cap is logged with entity counts. Modules with <0.1 pivot rate per search are flagged for review.

---

These 12 rules form the architecture of HSE's development culture: pragmatic, measurement-driven, ruthlessly optimized, and uncompromising on accuracy.
