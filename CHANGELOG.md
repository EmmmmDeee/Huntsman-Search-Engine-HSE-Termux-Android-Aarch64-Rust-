# Changelog

All notable changes to this project are documented here. Format per [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Added

- T3 quality: AU-002 identity-cluster implausibility rejection signaling as AU-002-REJECT finding

### Changed

- AU-002 rule now surfaces MAX_PER_KIND limit-exceeded cases as Medium-severity rejection findings instead of silent drops
- AU-092 rule now distinguishes conflict case with separate rule_id "AU-092-CONFLICT" (was previously reusing "AU-092")

### Fixed

- AU-002 silent drop when entity counts exceed plausibility limits: now signals rejection per Rule 0.7 priority 2 (Evidence Integrity)
- AU-092 rule_id reuse: breach-locality-footprint-conflict findings now use distinct "AU-092-CONFLICT" to prevent evidence integrity violation of using same rule_id for fundamentally different claims (agreement vs disagreement)
- AU-031 adjacency silent entity truncation: rule now includes all neighbors in entity_uids instead of silently truncating to first 12 (AGG_SAMPLE) when reporting fan-out aggregates
- Cross-scan-history recurrence evidence accumulation: the summary embedded the prior-scan count, so re-scanning one subject accumulated stale, contradictory snapshots ("recorded in 1 earlier scan" … "16 earlier") in its persisted evidence; the summary is now count-free and re-scans dedup to a single record (hub magnitude preserved via the `hub-entity` tag)

---

## Previous [Unreleased] (RETIRED — merged to infrastructure commit 2691cb5d)

### Added

- Engineering reference quick-lookup guide (`docs/ENGINEERING_REFERENCE.md`) with decision matrix and enforcement checklist
- Planning tree documents (`docs/PROBLEM_TREE.md`, `docs/SOLUTION_TREE.md`, `docs/gap_register.md`) for autonomous development cycle
- Spatial consistency check for AU-098 geo-consensus findings: suppresses findings when coordinate-based consensus states scatter beyond 300 km

### Changed

- Development rules refactored as foundational engineering baseline (Rule 0-0.7) with explicit priorities
- see_know module error labels: corrected from mismatched "seek_now" to registered "see_know" module name
- 30+ modules (T2.136-T2.165): migrated from silent failure swallows to explicit error surfacing:
  - `app_links`, `abn_lookup`, `asic_banned_orgs`, `asic_business_names`, `asic_persons`
  - `au_geo`, `au_seifa`, `chain_intel`, `cloud_storage`, `comb_search`
  - `dns_axfr`, `domainsdb`, `gaming_profile`, `geocode`, `intelx`
  - `keybase`, `leakix`, `opencellid`, `onyphe`, `pgp`
  - `portscan`, `qld_cadastre`, `ripestat`, `sanctions_ofac`, `smtp_vrfy`
  - `social_probe`, `subdomain_takeover`, `typosquat`, `url_extract`, `urlhaus`
  - `virustotal`, `wayback`, `web_crawler`, `webserver_banner`, `wikidata`, `wigle`, `zoomeye`

### Fixed

- Geolocation geocoder: US person geocoded to Melbourne — fixed with updated binary (commits d79757b8, c00f3e4a)
- Error attribution chain: module names now consistent across all error paths for operator debugging

### Verified

- All tests passing (121 unit + 56 integration + 65 doc-tests = 242 total)
- Verification gate passing: `cargo fmt`, `cargo clippy`, `cargo doc`, `cargo test`
- Evidence integrity preserved: no fabrication, no omission, no silent truncation
- Determinism verified: reproducible results across runs, no test flakiness

---

## Rationale

Per Rule 0.7 (Decision Hierarchy), all changes prioritize:

1. **Correctness** — code must work (all tests pass, gate passing)
2. **Evidence Integrity** — data must be valid (no silent failures, explicit error attribution, honest consensus validation)
3. **Safety** — no undefined behavior (`#![forbid(unsafe_code)]`)
4. **Determinism** — reproducible results (no flaky tests, no ordering leaks)
5. **Reproducibility** — repeatable across runs (deterministic sorts, tie-breaks, no HashMap iteration leaks)

Later priorities (6-10: simplicity, performance, maintainability, portability, convenience) are deferred until P0-P2 defects are closed.

---

## Archive

Older changes documented in `git log`. Use `git log --oneline` to view commit history with scope tags:

- `fix(...)` — bug fixes (correctness, evidence integrity)
- `test(...)` — test additions or fixes
- `docs(...)` — documentation updates
- `refactor(...)` — code restructuring without behavior change
- `feat(...)` — new functionality (deferred to CAP phase)

---

## Next Steps

Per `docs/gap_register.md`, the next cycle will:

1. Monitor for new defects from real-world use
2. Evaluate any user-reported issues
3. Defer CAP (capability program) work until new evidence surfaces
4. Maintain gate passing: all tests, lints, doc builds, determinism checks
