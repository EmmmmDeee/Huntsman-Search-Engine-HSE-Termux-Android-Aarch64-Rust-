# Android-only cloud refactoring controller

Baseline at creation: `290efe2eadd1d59da631aef578547a5f614f1064` (2026-10-30). Refresh `origin/main` before implementation; do not treat this SHA as permanently current.

## Objective
Enable an Android-phone-only maintainer to coordinate repository-scale Rust refactoring through a browser-based coding agent, GitHub pull requests and CI, with physical Termux acceptance kept distinct from cloud tests.

## Operating contract
1. Inspect the actual repository and CI before changing code. Preserve working changes and keep main installable.
2. Inventory modules, entry points, consumers, public contracts and test fixtures. Build a compact dependency and invariant map; retrieve source per change instead of placing the whole repository in one prompt.
3. Prioritise evidence integrity: parsing, canonical identity, confidence, provenance, persistence, correlation, recursion and cross-scan gates.
4. Characterise current behaviour and write negative/adversarial tests before each refactor. In particular, name-only similarity must not independently establish identity; unverified observations must not be silently promoted; provenance must survive transformations.
5. Change one dependency-connected slice at a time on an isolated branch. Avoid broad rewrites and duplicated abstractions.
6. Validate with applicable commands, including `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`. Record failures and baseline differences; never claim a command ran when it did not.
7. Use existing GitHub Actions workflows for supported cloud checks. Cross-compilation/emulation is **not** proof of physical Android Termux success. Require device verification before asserting it.
8. Open reviewable pull requests with scope, exact base/head SHAs, test evidence, risks, rollback and next action. Do not auto-merge unverified work.
9. No runtime LLM dependency, mandatory paid API, root access or unnecessary new dependency.

## Phone-only execution
- In Android Chrome, open https://chatgpt.com/codex or https://github.com/codespaces and select this repository.
- Ask the agent to read this file and inspect the current main branch.
- Delegate one isolated refactor increment; review the resulting diff and CI from GitHub mobile.
- On Termux, validate the merged candidate on physical AArch64 hardware when practical.
- Free cloud/model usage is quota-limited; do not assume unrestricted access or native Android compatibility for desktop coding agents.

## First agent task
"Inspect latest main, map the source-to-evidence-to-correlation pipeline and its existing tests, identify one demonstrable high-impact architectural defect, write a failing regression test, implement the smallest correct Rust fix, run applicable checks, and open a draft PR with exact evidence. If no defect is demonstrated, report the strongest supported next investigation rather than inventing one."

## Evidence ledger template
| Base SHA | Component | Invariant | Reproduction | Patch | Checks | Device status | PR | Next |
|---|---|---|---|---|---|---|---|---|
| 290efe2eadd1d59da631aef578547a5f614f1064 | Initial setup | No behavioural change | Not applicable | Documentation only | Not executed | Not executed | Pending | Run first coding-agent investigation |
