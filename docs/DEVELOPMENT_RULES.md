# HSE Development Rules — Standing Core Doctrine

Nine standing core rules govern all Huntsman Search Engine development. These are not advisory; they are the foundation of correctness, reliability, and OSINT fidelity. Every commit, every cycle, every improvement must honor these principles or it fails the project's mission.

---

## 1. Complete Files Only

**Every file written is full, compatible, and deployable. No stubs, partial implementations, or "TODO" markers in shipped code.**

- Write complete functionality or nothing at all.
- A new module ships with all required methods (name, description, priority, accepts, produces, process, max_timeout_ms, category, attack_techniques, cost).
- A utility function ships with comprehensive error handling, edge cases, and tests.
- Every shipped file must work in context immediately; it must not require downstream fixes to be useful.
- Exceptions: Tests may be incomplete during development (marked with `#[ignore]`); documentation stubs are acceptable during writing; temporary branches for mid-cycle work are allowed. But nothing reaches `main` (or the designated branch) incomplete.

**Why**: Incomplete code accumulates technical debt, creates false signals in CI, and damages confidence in the codebase. A complete, testable unit of work is the smallest atomic change worth recording in git.

---

## 2. Aggressive Workaround Culture

**Upon any failure or shortcoming, aggressively attempt workarounds until a solution is found that supersedes anything existent.**

- Lint failures? Don't disable the lint—refactor the code to satisfy it.
- A module's output format doesn't align with others? Unify the pattern across all instances, not just the one that broke.
- A test reveals a subtle bug in a dependency you can't modify? Fix the call site, add a guard, or rearchitect to avoid the hazard—don't work around it inline and move on.
- Performance regression in a query? Profile, optimize, and ship the faster solution—not a workaround that hides the problem.

**Why**: Workarounds are debt markers. Every workaround that enters the codebase is a small lie about what the system actually does. Over time, workarounds hide real problems and make the codebase brittle. Aggressive resolution keeps the system honest and maintainable.

---

## 3. Real Live Validation, Never Fabricated Data

**Seed entities come from fresh searches or established test seeds (e.g., `Kylo4kylo`). Live API calls are preferred. Zero mocks, zero invented PII, zero fabricated findings.**

- Every fixture or test data point must either:
  - Come from a live, consented query (a real Shodan search, a real WHOIS lookup, a real CKAN call).
  - Use an established, long-lived test seed (Kylo4kylo for people data, established dummy domains for DNS queries).
  - Be synthetic and clearly marked as such (a fake email address of the form `test_12345@example.invalid`, a UUID, a dummy IP from TEST-NET).
- Never invent a real third party's PII or simulate their existence in fixtures.
- Never mock an API response to hide a real failure.
- Never fabricate a finding (a breach, a credential, a threat) to satisfy a test or demo.

**Why**: HSE is an OSINT tool. False positives are worse than missed findings. Every entity must trace back to a real source or a clearly synthetic test seed. Fabricated data breeds fabricated findings, which destroy the tool's credibility and harm real investigations.

---

## 4. Andrew Gallant's Rust Craftsmanship

**Performance-first, clean abstractions, thorough error handling, minimal-unsafe discipline, excellent documentation, practical patterns (ripgrep's standard).**

- Prefer performance-optimal solutions over convenience APIs, but always measure. No premature optimization; optimize only where profiling shows the cost.
- Write abstractions that solve a real problem, not theoretical ones. If two places use a pattern, unify it; if only one place needs it, keep it local.
- Handle errors explicitly. No silent swallows (`Err(_) => {}`); every failure path must either propagate the error, log it with context, or make a deliberate choice to ignore it (with a comment explaining why).
- Unsafe code is forbidden (`#![forbid(unsafe_code)]`). No exceptions. The safety guarantees of Rust are non-negotiable.
- Write code as though someone else (or future-you) will need to understand it in six months. Prefer clarity over clever.
- Follow ripgrep's coding style: minimal allocations, explicit error types, composable building blocks, relentless testing.

**Why**: HSE runs on potentially untrusted network data and produces findings that inform real investigations. Poor performance wastes researcher time; poor error handling hides bugs; unsafe code introduces exploitable vulnerabilities. Craftsmanship is the difference between a toy tool and an enterprise OSINT platform.

---

## 5. Maximum File Synergy

**All files linked, vocabularies single-sourced, shared utilities reused, patterns consistent across the codebase.**

- Every domain-specific vocabulary (entity kinds, tags, evidence attributes, module categories, ATT&CK techniques) is defined in one place and imported everywhere.
- Every common utility (URL parsing, email validation, JSON parsing, HTTP client building) lives in `util/` and is imported by any module that needs it. Don't reimplement.
- Every pattern (module structure, entity building, evidence attachment, error surfacing) is consistent. A new module looks like the last one; a fix to one module's pattern applies to all.
- Cross-module references are explicit and bidirectional where needed (e.g., if module A produces entities that module B consumes, both know about the relationship).
- Refactor for consistency. If you notice two modules doing the same thing differently, unify them.

**Why**: A codebase fractures when each module is an island. Synergy reduces bugs (fewer reimplementations = fewer bugs per concept), makes changes propagate cleanly (fix the utility; all modules benefit), and makes the code readable (patterns are predictable). See `docs/CONVENTIONS.md` for the vocabulary and pattern bank.

---

## 6. Outdo Spiderfoot Recursively

**More modules, deeper correlation, aggressive recursive entity expansion, intelligent multi-level searching.**

- HSE's advantage is not any single module but the recursive web of correlations.
- When a module discovers an entity (email, domain, phone), that entity becomes a seed for other modules. An email → PGP key lookup → alternate emails on that key → scan those → contact extraction → new phones. Chains extend 3–5 levels.
- Every module that produces an entity kind should ask: "What other modules can consume this and discover new signals?" If a gap exists, write the consumer module.
- Use the expansion scoring (geo_npv, entity kind weights) to prioritize which entities to expand and how aggressively.
- Intelligent recursion means: don't expand everything (infinite loop risk); prioritize high-signal expansions; stop when confidence or freshness signals drop.

**Why**: Spiderfoot and Maltego are useful but operate largely breadth-first and surface-level. HSE's edge is correlation depth: the ability to pivot through multiple OSINT layers and surface hidden relationships. Aggressive recursion finds the signals competitors miss.

---

## 7. Data-Driven Continuous Improvement

**Organize and retain results for statistical analysis, algorithm refinement, technique evolution. Every scan generates signal for tomorrow's optimization.**

- Every scan produces structured results (entities, confidence scores, source provenance, execution time, module hit rates).
- Accumulate and analyze these results to identify:
  - Which modules have the highest signal (most entities confirmed by multiple sources).
  - Which confidence thresholds correspond to true vs. false positives.
  - Which entity kinds are underutilized (produced often but rarely consumed/expanded).
  - Which queries are slow (module-level and overall).
  - Which ATT&CK techniques are most frequent in findings.
- Use these insights to tune:
  - Module priorities (high-signal modules run first).
  - Confidence baselines (calibrate to ground truth).
  - Expansion strategies (if an entity kind rarely leads to new discoveries, deprioritize its expansion).
  - Query strategies (combine multiple search modalities for reliability).
- Document every major optimization in commit messages and the solution tree log.

**Why**: OSINT is an empirical discipline. The queries that work best, the correlations that matter most, the techniques that yield real intelligence—these are discovered through data, not intuition. A system that improves itself based on evidence is more reliable and more powerful than one frozen at design time.

---

## 8. Maximize Autonomy in All Possible Ways

**The tool should operate with minimal user intervention, requiring configuration only for credentials and optional advanced tuning.**

- HSE must run scans end-to-end with a single command: `hse scan <target>`. No manual steps, no prompts for each module.
- Intelligent defaults: if a module is free and has no key configured, use it; if it's keyed and the key is missing, skip it and continue.
- Parallelization and scheduling should be automatic. The tool decides how many modules to run concurrently based on system resources and module dependencies.
- Error recovery should be automatic where possible: retry transient network failures; skip modules that are temporarily unavailable; continue the scan even if one module fails.
- Autonomous diagnosis: when the scan finishes, the tool should surface what succeeded, what failed, why, and suggestions for fixing failures (missing keys, network problems, data issues).
- Autonomous optimization: the tool should tune itself based on observed performance (module priority, confidence thresholds, expansion depth).

**Why**: Manual OSINT investigation is slow and error-prone. Autonomy is the difference between a tool and a chore. Users should think about *what to search*, not *how to search it*.

---

## 9. Unified Autonomous Debugging That Improves Perpetually

**Incorporate comprehensive debugging and self-diagnosis that continuously evolves.**

- Every scan should include a debug bundle: timestamps, module execution order, which entities were produced, which modules they were expanded into, which relations were confirmed by correlator rules, final confidence scores for each entity.
- The debug bundle should be structured so it can be analyzed programmatically: JSON, not free-form logs.
- Errors should be captured with full context: the input that caused the error, the module that failed, the exact error message, the HTTP status if it was a network failure, the stack location.
- When the same error occurs repeatedly across scans, HSE should recognize the pattern and either:
  - Auto-correct it (if it's a known issue with a known fix, apply the fix).
  - Surface it to the user as an actionable diagnosis (e.g., "module X expects a key but none is configured; run `hse config` to add one").
  - Build a hypothesis about the root cause and log it for analysis.
- After each scan, HSE should analyze the debug bundle and ask:
  - Which modules had the best ROI (entities produced / execution time)?
  - Which entity kinds were discovered most often?
  - Which correlations were confirmed most frequently?
  - Where did the scan slow down?
  - Which modules produced entities that no other module consumed (unused signals)?
- Use these analyses to refine future scans: adjust priorities, skip low-ROI modules for similar targets, suggest new search strategies.

**Why**: Debugging is not a one-time activity; it's continuous. Every scan teaches the tool something. A system that learns from its own failures, explains its reasoning, and improves itself with each run is far more valuable than a static tool.

---

## Integration with Other Documentation

- **`CONVENTIONS.md`**: Details on code style, layering, module structure, vocabulary definitions, and testing standards.
- **`PROBLEM_TREE.md`**: The open issues, prioritized by impact and sequenced by dependency.
- **`SOLUTION_TREE.md`**: The implemented solutions, paired with their problems and verified sound.
- **`gap_register.md`**: The log of every cycle—what was fixed, why, what tests confirm it, why what remains is deferred.

These rules are the *how*; those documents are the *what* and *why*.

---

## Enforcement

These rules are non-negotiable. Every commit, every pull request, every release is measured against them:

1. **Completeness**: Is every file in this commit deployable?
2. **Workarounds**: Does it work around a problem, or does it solve it?
3. **Data fidelity**: Are all entities traced to real sources or established test seeds?
4. **Craftsmanship**: Does it follow ripgrep's standard? Is unsafe code absent?
5. **Synergy**: Are utilities reused? Are patterns consistent?
6. **Recursion**: Does it expand entities intelligently?
7. **Data-driven**: Are the decisions informed by empirical evidence?
8. **Autonomy**: Can the user run this with minimal configuration?
9. **Debugging**: Does it surface errors clearly and improve itself?

A commit that violates one rule is a regression, not progress. It is better to defer a feature than to ship it incompletely or with fabricated test data. It is better to refactor three times to find the clean solution than to ship a workaround and move on.

HSE's ambition is to be the fastest, most correct, most reproducible OSINT engine, surpassing SpiderFoot and Maltego. These nine rules are how.

---

**Last updated**: 2026-07-16  
**Established by**: Development team  
**Status**: Standing core doctrine
