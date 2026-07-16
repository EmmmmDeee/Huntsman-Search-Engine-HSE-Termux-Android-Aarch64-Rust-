# HSE Development Rules — Standing Core Doctrine

**METHOD: Andrew Gallant**

Nine standing core rules govern all Huntsman Search Engine development. These are not advisory; they are the foundation of correctness, reliability, and OSINT fidelity. Every commit, every cycle, every improvement must honor these principles or it fails the project's mission.

This doctrine is written and enforced with the uncompromising pragmatism of ripgrep's author: performance obsession, ruthless scope discipline, relentless user-centric design, and aggressive intolerance for waste.

---

## 1. Ship Working Code or Don't Ship

**Every file is production-ready the moment it lands on the branch. Full functionality, tested, no stubs, no "TODO", no placeholders. Ship it to users or throw it away.**

- A module is useless if it's 90% done. Either finish it or delete the branch and start over.
- Every module must have: name, description, priority, accepts, produces, process, max_timeout_ms, category, attack_techniques, cost. No exceptions.
- A utility function must handle its edge cases the first time. Refactor it later if needed, but ship it working today.
- Tests are mandatory before shipping. Run the full gate (fmt, clippy, doc, test, selftest). Fail even one? Don't commit.
- No "TODO" comments in shipped code. If you don't have time to do it, don't write the comment; just don't do it.
- Exceptions: Temporary branches for in-progress work are fine. Tests can be marked `#[ignore]`. But the moment it touches the designated branch, it ships complete or it doesn't ship.

**Why**: Incomplete code is a lie. It pretends to be done but isn't. It breaks the build. It wastes time. It teaches people to ignore warnings. Ship working code, or don't ship. This is non-negotiable.

---

## 2. No Workarounds—Fix It or Cut It

**When code fails to pass the gate, fix the code. Don't disable the lint, don't add a comment, don't work around it. Either solve the problem or remove the change.**

- Clippy warning? Refactor the code. All of it if necessary. The lint is right.
- Module output format doesn't match the pattern? Go back and unify all instances. Yes, all of them. That's not extra work; that's the actual work.
- Test fails? Find the root cause. Is it the test? Is it the code? Is it the design? Fix the real problem, not the symptom.
- Performance regression? Profile it. Don't guess. If optimization is needed, do it. If it can't be optimized to acceptable speed, cut the feature. Slow code is dead code.
- Dependency bug that you can't fix upstream? Rearchitect your call site to avoid it. Don't layer workarounds; just don't call the broken method.

**Why**: Workarounds are compound interest on debt. They multiply. The first one seems harmless. The tenth one makes the codebase unreadable. There are only two categories of code: code that works correctly, and code that doesn't belong in the repo. Workarounds blur that line until the entire codebase is a lie.

---

## 3. Real Data Only—No Mocks, No Fabrication, Ever

**Every test uses live API calls, established test seeds (Kylo4kylo), or clearly synthetic data. No mocks. No invented PII. No fabricated findings. Full stop.**

- Test data must come from one of three sources:
  1. **Live queries**: Real Shodan searches, real WHOIS lookups, real CKAN calls. Make the call; keep the response as a fixture if needed.
  2. **Established seeds**: Kylo4kylo for people data. Standard dummy domains for DNS. Known-safe test IPs. These are trusted fixtures.
  3. **Synthetic, clearly marked**: `test_12345@example.invalid` (not a real domain). UUIDs. TEST-NET IPs (192.0.2.0/24, etc.). These must be obviously fake.
- Never invent a real person's name, email, phone, or PII to populate a test. Never simulate a real company's existence in a fixture. Never create a realistic-looking but fake email address from a real domain.
- Never mock an API. If the API is down or broken, skip the test with `#[ignore]`, don't fake the response.
- Never fabricate a finding (a breach, a credential, a threat) to make a test pass or demo look good.
- If you need test data and can't get it live, write `#[ignore]` on the test and document why. Don't fake it.

**Why**: HSE is an intelligence tool. False positives can cause real harm. Every finding must trace to a real source or be obviously synthetic. The moment we fabricate test data, we've lied to ourselves about what the tool does. And if the tool lies in tests, it will lie in production.

---

## 4. Ruthless Performance, Explicit Error Handling, No Unsafe Code

**Code must be fast. Errors must be clear. Unsafe code is forbidden. No exceptions to any of these.**

**Performance:**
- Measure before optimizing, but optimize aggressively. Ripgrep is fast because it was designed to be fast from day one.
- Prefer allocation-free solutions. Preallocate when you know the size. Use references; avoid cloning.
- Profile the hot paths. A 10% speedup in a path that runs 1M times per scan is worth two days of work.
- Reject features that are too slow. If a module takes 30 seconds for one query and its module runs 100 times in a scan, that's 50 minutes wasted. Cut it.
- Network I/O is your enemy. Batch requests. Reuse connections. Cache aggressively. A module that makes 100 sequential requests will be slow no matter how fast the CPU is.

**Error Handling:**
- Every `Result` must either be propagated with `?` or deliberately handled. No `Err(_) => {}` without a comment explaining why.
- When you ignore an error, write the reason in one line. "Ignore parse errors; we expect some rows to be malformed." Not an empty handler.
- Design for clarity. An error message should tell you what went wrong, where, and what to do about it. Not "failed"; "failed to fetch example.com: 404 Not Found".
- Propagate errors up. Don't catch a transport error and return an empty result and pretend everything is fine. The caller needs to know.

**Safety:**
- `#![forbid(unsafe_code)]` is absolute. No `unsafe`, no exceptions, no comments saying "but this is safe because...". Use Rust's safety guarantees or rewrite the code.
- If you're tempted to use `unsafe`, you've hit a design problem. Solve the design problem.

**Clarity:**
- Write code that's easy to understand the first time. If a future reader has to ask "why did they do it this way?", you wrote it wrong.
- Explicit types. Explicit error handling. Explicit bounds. Let the compiler help you.
- No clever tricks. No "this works because of Rust's orphan rules and monomorphization." Write boring code that works.

**Why**: HSE processes untrusted network data and produces findings that guide real investigations. Slow code = lost research time = bad UX = users abandoning the tool. Wrong error handling = silent failures = missed security signals. Unsafe code = exploitable bugs = compromised data. Craftsmanship isn't optional; it's the difference between a tool people use and a tool that collects dust.

---

## 5. One Definition, Everywhere—No Duplication Allowed

**Every vocabulary, utility, and pattern is defined once and imported everywhere. Duplication is a bug.**

**Vocabularies:**
- Entity kinds, tags, evidence attributes, module categories, ATT&CK techniques: defined once in `core/`, imported everywhere.
- Don't define a new tag in a module. Import it from `core::tags`.
- Don't invent a new module category. Use the existing ones or add it to `core/` so all modules can use it.
- If you see the same string in two modules, extract it to a constant in `util/`.

**Utilities:**
- URL parsing, email validation, domain classification, JSON handling, HTTP client building: all live in `util/`.
- Don't reimplement URL parsing in a module. Import `util::url_util::parse_url`.
- Don't write email validation twice. Import `util::extract::looks_like_email`.
- If you write a utility and it's useful, move it to `util/` and import it from `util/`.

**Patterns:**
- Every module follows the same structure: types, pure functions, Module impl.
- Every entity is built the same way: Entity::new(), tags, evidence, push.
- Every error is surfaced the same way: either propagate it or log it with context.
- A new module should be indistinguishable from the last one in structure. The difference should be the data it processes, not how it processes it.

**Refactoring for Consistency:**
- When you see two modules doing the same thing differently, stop and unify them.
- When you see the same logic in three modules, extract it to `util/`.
- When a pattern appears in more than one place, it belongs in the architecture, not the module.
- This is not optional. This is part of the work.

**Cross-Module Relationships:**
- If module A produces EmailAddress entities and module B consumes them, both should document that relationship.
- If module A's output is a common input to module B, C, and D, the expansion weight should reflect that.
- Relationships should be explicit in code or comments, not implicit.

**Why**: Duplication is where bugs hide. Fix a bug in one copy; it lives in three others. Add a feature; you have to add it to every copy. Inconsistent patterns make code hard to read and harder to change. One definition, everywhere, is the only way to stay sane.

---

## 6. Recursive Expansion—No Stone Unturned, But Stop When the Gains Dry Up

**HSE wins through correlation depth, not breadth. Expand aggressively, measure relentlessly, stop when ROI collapses.**

**The Expansion Strategy:**
- Every discovered entity is a seed for the next layer. Email → PGP keys → alternate emails → rescan → contact extraction → new phones. Chains extend 3–5 levels.
- Every module that produces an entity kind must ask: "What other modules consume this?" If there's a gap, write the module.
- Use expansion scoring (entity weights, geo_npv, confidence) to prioritize. High-confidence, high-signal entities expand first.
- Don't expand everything uniformly. A domain with high correlation weight expands differently than a random IP.

**When to Expand:**
- Always expand high-confidence entities (0.80+). These are high-signal.
- Expand medium-confidence entities (0.60–0.79) when they link to high-signal consumers (domain → look-alike domain searches).
- Don't expand low-confidence entities (< 0.60) unless they're the only lead on the target.

**When to Stop:**
- Stop when confidence drops below 0.50. A 0.45-confidence entity expanded into a 0.60-confidence module doesn't yield useful findings.
- Stop when an entity has been expanded 3 times and produced no new high-confidence entities. You're chasing ghosts.
- Stop when the time cost exceeds the signal gain. If expanding an entity takes 10 seconds and yields only low-confidence results, skip it.
- Stop when an expansion produces duplicate entities. Once you've found email@example.com, finding it again via a different path is noise, not signal.

**Measurement:**
- Track expansion ROI: how many new high-confidence entities per expansion unit.
- Track which modules have the best ROI. Prioritize them.
- If a module consistently produces entities that expand poorly, deprioritize it or cut it.
- Data-driven expansion, not theoretical. Every expansion must earn its time.

**Why**: Recursive expansion is HSE's edge over Spiderfoot. But infinite recursion is death by a thousand cuts. The art is knowing when to dig and when to stop. The tool that expands intelligently is faster, smarter, and more credible than the tool that expands everything and drowns the user in noise.

---

## 7. Measure Everything, Optimize Ruthlessly, Never Guess

**Every scan is data. Accumulate it, analyze it, optimize based on it. Intuition is not allowed.**

**What to Measure:**
- Per-module: runtime (ms), entities produced, entities with confidence > 0.70, entities expanded downstream, ROI (entities / time).
- Per-entity: confidence score, source module, how many other modules produced it (validation signal), whether it was expanded, what expansions yielded.
- Per-correlation: which relation rules fired, which entities converged in the correlator, which correlations were human-validated (ground truth).
- Per-scan: total time, parallel efficiency, memory usage, which modules were bottlenecks.

**Analysis:**
- Which modules are fast and produce high-signal entities? Prioritize them; run them early.
- Which modules are slow? Is the slowness justified by signal? If not, deprioritize or cut the module.
- Which confidence thresholds correspond to true vs. false positives in ground truth? Tune the baselines.
- Which entity kinds are produced often but expanded rarely? Either improve the downstream modules or stop producing them.
- Which expansion patterns yield the most new high-confidence entities? Double down on those patterns.

**Optimization:**
- Use the data to decide priorities. Don't guess. Run module X first if data shows it yields 5× ROI of module Y.
- If an entity kind produces 1000 results but only 10 are ever expanded, something is wrong. Either fix the producer or kill it.
- If a module takes 5 minutes and produces one entity, cut it. Time spent on low-ROI modules is time not spent on high-ROI work.
- If parallel execution isn't scaling linearly, find the bottleneck and fix it. Network I/O? Shared locks? Fix it or redesign.

**Iteration:**
- Run a scan. Collect the data. Analyze. Optimize. Commit. Repeat.
- Every optimization should be justified by data, not by intuition or "best practices."
- If data shows your assumption was wrong, change the code. Data wins; assumptions lose.
- Document every major optimization in commit messages and the solution tree log so the next person knows why the code is structured this way.

**Why**: Intuition is a poor guide to performance and correctness. Two modules that "feel" similar in speed might have 10x different ROI. An entity kind that "should" be useful might produce noise. Only data tells the truth. A system that measures, analyzes, and optimizes based on evidence is faster, smarter, and more credible than one built on intuition.

---

## 8. Zero Configuration, Maximum Autonomy—The Tool Works Out of the Box

**Users should never have to think about how to run a scan. They think about what to search. HSE handles everything else.**

**Zero Configuration:**
- `hse scan <target>` should work immediately. No config files, no environment setup, no API key prompts.
- Free modules (CKAN, DNS, public archives) run by default. Keyed modules are skipped if the key is missing; the scan continues.
- If a module is temporarily down, skip it and move on. Don't block the scan.
- If a network request fails, retry with backoff. Three strikes and the module is skipped.

**Intelligent Defaults:**
- Parallelism is automatic: run as many modules concurrently as CPU cores allow, respecting rate limits and dependencies.
- Expansion depth is automatic: expand high-ROI entities, stop when confidence or gains dry up.
- Confidence thresholds are baked in; no tuning needed for 95% of users.
- Module priorities are data-driven: high-ROI modules run first.

**Error Handling:**
- A module fails? Skip it, log why, continue. The scan doesn't stop.
- A network request fails? Retry automatically. Three retries, then skip.
- A module times out? Skip it. Slow modules are dead weight; don't wait for them.
- A parsing error? Skip the malformed response; continue with what worked.

**Autonomous Diagnosis:**
- When the scan finishes, HSE reports:
  - What succeeded and how many entities were produced.
  - What failed and why (module timeout, network error, missing key, parse failure).
  - What can be fixed (e.g., "add HUNTSMAN_VIRUSTOTAL_KEY for 5x more results").
  - Performance summary: which modules were fastest, which were slowest, where the bottlenecks are.
- The output is formatted for humans: clear, actionable, not a wall of JSON.

**User Experience:**
- The tool feels instant. If the scan takes 30 seconds, 25 of them are network I/O (unavoidable). The tool doesn't waste the other 5 on overhead.
- If a user has a slow connection, the tool adapts. Fewer concurrent requests. Longer timeouts. Still completes.
- If a user adds a new API key, the tool automatically uses it on the next scan without restarting.
- The tool learns from feedback: if a user marks a finding as false positive, that data informs future confidence calibration.

**Why**: Ripgrep doesn't ask you to configure fuzzy matching; it's just fast. HSE shouldn't ask users to configure priorities or thresholds; it should just work. Autonomy is the difference between a tool people reach for and a tool that stays on the shelf.

---

## 9. Self-Aware, Self-Improving Debugging—The Tool Learns From Every Scan

**HSE must know what it did, why it did it, and whether it worked. It must learn and improve with every scan.**

**Debug Capture:**
- Every scan produces a structured debug bundle: JSON, not logs. Timestamps, module execution order, every entity produced, every expansion path, every correlator rule fired, every error.
- Errors capture full context: the input, the module, the exact error message, HTTP status, the request that failed. Not just "network error"; "failed to fetch api.example.com/v1/users at 12:34:56: HTTP 503, retried 3 times".
- The debug bundle is immutable and retained. Old scans teach you about patterns.

**Pattern Recognition:**
- When the same error occurs 3+ times across scans, HSE recognizes it and either:
  - Auto-corrects if there's a known fix (e.g., "module X times out on slow networks; add 2s to the timeout").
  - Surfaces it as an actionable diagnosis (e.g., "module X failed 5 times; you're missing HUNTSMAN_X_KEY").
  - Logs it with a hypothesis for human analysis.
- Errors cluster by module, target type, and time of day. If module X always fails at 3 PM, you've found a rate-limiting issue.

**Scan Analysis:**
After each scan, HSE analyzes itself:
- ROI per module: entities produced / execution time. Modules with 0.01 entities/ms are dead weight; modules with 10 entities/ms are worth prioritizing.
- Confidence distribution: are the confidence scores realistic? If 90% of findings are 0.50 (baseline), you're producing noise.
- Expansion paths: which entity kinds expanded the most? Which died at depth 1? Which led to high-confidence convergences?
- Bottlenecks: where does time go? Network I/O? Module overhead? JSON parsing?
- Unused signals: which modules produced entities that no other module consumed? Either kill the producer or write a consumer.

**Self-Improvement:**
- Use the analysis to optimize future scans:
  - Adjust module priorities based on ROI. Run high-ROI modules first.
  - Adjust expansion depth for entity kinds: low-signal kinds expand less; high-signal kinds expand more.
  - Adjust parallelism: if network is the bottleneck, don't spawn more threads.
  - Adjust confidence thresholds: if the ground truth shows a module is consistently optimistic, lower its baseline.
- These adjustments are per-target-type and per-user. A domain scan might prioritize DNS; a person scan might prioritize social media.
- The tool suggests new strategies: "Your last 10 scans on domains consistently missed typosquatting; try the domainsdb module." "Your PII leaks are from social search; profile.io is worth enabling."

**User Visibility:**
- The debug bundle is downloadable. Users can inspect it, understand the scan, verify the findings.
- The debug bundle is machine-readable. Customers can build their own analyses, tune the tool for their needs.
- HSE's reasoning is transparent. The user sees which module produced which entity, which correlations were confirmed, why confidence was high or low.

**Iteration:**
- Every scan teaches HSE something. The more you use it, the smarter it gets.
- Feedback loops: if a user marks a finding as false positive, that signal informs confidence calibration for future scans.
- The tool doesn't plateau; it improves with every scan.

**Why**: A static tool is eventually superseded. A tool that learns from its failures, understands its own behavior, and improves with every scan becomes indispensable. Self-awareness is the difference between a hammer and a power drill.

---

## Integration with Other Documentation

- **`CONVENTIONS.md`**: Details on code style, layering, module structure, vocabulary definitions, and testing standards.
- **`PROBLEM_TREE.md`**: The open issues, prioritized by impact and sequenced by dependency.
- **`SOLUTION_TREE.md`**: The implemented solutions, paired with their problems and verified sound.
- **`gap_register.md`**: The log of every cycle—what was fixed, why, what tests confirm it, why what remains is deferred.

These rules are the *how*; those documents are the *what* and *why*.

---

## Enforcement

These rules are non-negotiable and absolute. Every commit, pull request, and release is gated against them:

1. **Completeness**: Is every file deployable? Run the full gate (fmt, clippy, doc, test, selftest). Fail even one? Don't commit.
2. **No Workarounds**: Does it solve the problem, or hide it? Lint failure? Refactor the code. Test fails? Fix the root cause. Performance regression? Optimize or cut the feature.
3. **Data Fidelity**: Are all entities traced to live sources or Kylo4kylo? Zero mocks. Zero fabrication. One false finding poisons the whole tool.
4. **Craftsmanship**: Ripgrep standard or better. No unsafe code. No silent error swallows. Performance measured and optimized. Code is clear or it's wrong.
5. **Synergy**: Utilities reused? Patterns consistent? Vocabularies single-sourced? One definition, everywhere. If you're writing the same logic in two places, you've already lost.
6. **Intelligent Recursion**: Expand high-signal entities. Stop when ROI collapses. Measure expansion ROI. Kill low-ROI modules.
7. **Data-Driven**: Every decision backed by measurement. Intuition is not allowed. If data says you're wrong, you're wrong.
8. **Autonomy**: `hse scan <target>` works out of the box. No configuration, no prompts, no manual tuning. Free modules run by default.
9. **Self-Improvement**: Every scan generates data. HSE learns and improves. Errors are recognized and auto-corrected. Patterns are detected and exploited.

**Gating Criteria:**
- **Commits**: Every commit must pass fmt, clippy, doc, test, and selftest. Every commit is measured against all nine rules. A commit that violates one is rejected, not fixed.
- **Features**: A feature is done when it's shipped, tested, and documented. "90% done" is 100% useless. Finish it or delete it.
- **Data**: Every test uses live data or Kylo4kylo. Fabricated findings are cause for revert.
- **Performance**: If a module takes > 5 seconds per query on reasonable hardware, it's too slow. Optimize or cut it.
- **Coverage**: If a module produces entities that no other module consumes, it's dead code. Kill it or write a consumer.

**On Violations:**
- A single violation is a revert. Not a discussion, not a comment, not a "we'll fix it later." Revert and start over.
- Repeat violations by the same author warrant a conversation about priorities and fit.
- Systemic violations (e.g., a whole module that ignores rule 7) are fatal. The module is cut.

**What You Can't Do:**
- You can't add `#[allow(clippy::*)]` without a comment explaining why, for that specific line only.
- You can't use `Err(_) => {}` without a comment.
- You can't mock an API. Use live data or skip the test.
- You can't ship a feature that's slower than a known alternative.
- You can't add a module that produces entities no other module consumes.
- You can't ignore test failures and commit anyway.

**What You Must Do:**
- Run the full gate before every commit. All four checks, no shortcuts.
- Write at least one test that fails against the unfixed code and passes against the fix.
- Document the "why" in the commit message and in code comments.
- Measure performance for anything that touches I/O or CPU.
- Refactor for consistency. If you see duplication, unify it.

**The Standard:**
These rules define what "done" means. A feature that violates one rule is not done. A commit that doesn't pass the gate is not done. A module that produces unused entities is not done. Don't commit "done" code unless it's actually done.

---

## Philosophy

This is the Andrew Gallant doctrine: ruthless pragmatism, relentless measurement, aggressive optimization, and zero tolerance for waste. Ripgrep didn't become the fastest text searcher by accident or by shipping "good enough" code. It became fast because Gallant measured, optimized, and refused to ship anything that didn't earn its place.

HSE's ambition is to be the fastest, most correct, most reproducible OSINT engine, surpassing SpiderFoot and Maltego without ever fabricating a finding. These nine rules, enforced absolutely, are how.

**Ship working code or don't ship. Solve problems or cut scope. Measure everything. Optimize ruthlessly. Learn and improve. Never stop.**

---

**Last updated**: 2026-07-16  
**Philosophy**: Andrew Gallant (ripgrep)  
**Status**: Absolute, non-negotiable doctrine  
**Violations**: Zero tolerance, immediate revert
