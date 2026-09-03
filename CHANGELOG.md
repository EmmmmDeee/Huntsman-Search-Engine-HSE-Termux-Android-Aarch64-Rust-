# Changelog

All notable changes to this project are documented here. Format per [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Added

- T3 quality: AU-002 identity-cluster implausibility rejection signaling as AU-002-REJECT finding
- `Module::is_derivation()`: a module declares that its output is a deterministic transform of data already in the graph (parser, canonicaliser, permutation generator, offline decoder). An architecture test pins the declaration to `hse_core::ENRICHMENT_ONLY_SOURCES` in both directions, so the "does this source corroborate?" fact has one enforced authority instead of a hand-maintained list.
- `util::paths::isolate_for_tests()` + `tests/common::isolate_home()`: integration-test crates (where `cfg!(test)` is false in the linked library) now redirect the whole `~/.huntsman` layout at a per-process temp dir; an architecture test pins that no production code can call it.

### Changed

- AU-002 rule now surfaces MAX_PER_KIND limit-exceeded cases as Medium-severity rejection findings instead of silent drops
- AU-092 rule now distinguishes conflict case with separate rule_id "AU-092-CONFLICT" (was previously reusing "AU-092")
- `GET /api/v1/health` is exempt from the non-loopback bearer-token gate (GET only; every other verb on the path stays gated). The Railway/container deployment (`hse serve --bind 0.0.0.0`) could never pass its own credential-less `healthcheckPath` probe before this; `railway.json` is now pinned to `api::auth::HEALTH_PATH` by test.
- `hse config <key> on|off` now validates the key with the same `modules::is_known_toggle_key` the `PUT /api/v1/settings/toggles` handler uses (its private duplicate is gone) and exits non-zero on an unknown key instead of persisting a silent no-op.
- WiGLE BSSID lookups probe the two corpora an address can belong to (WiFi via `network/detail?type=WIFI`, Bluetooth via its own `/api/v2/bluetooth/detail`) — two billed requests per dispatch, not three.
- `Store::checkpoint_truncate()` now returns `Err` when SQLite reports the TRUNCATE checkpoint blocked by a concurrent reader; `hse tidy` and the finalise housekeeping no longer report a WAL truncation that did not happen.

### Fixed

- WiGLE cell/Bluetooth intelligence was fabricated from WiFi rows (RULE.md's own cautionary case, still live): `/api/v2/network/search` has no `type` parameter, so `?type=cell` / `?type=bluetooth` were ignored and WiFi results were labelled as cell-carrier and Bluetooth-beacon findings. Each corpus now goes to its own documented endpoint (`/api/v2/cell/search`, `/api/v2/bluetooth/search`) with only documented parameters, verified against `https://api.wigle.net/swagger.json` and pinned by test.
- OathNet search sessions never engaged: `init_session` parsed `session.id`, a field the documented `POST /service/search/init` response (`{ "search_id": "…" }`) does not carry, so every breach+stealer pair cost two lookups of the paid quota instead of one. The documented field is parsed and the assumed shape is pinned as rejected.
- Stale SPA/wasm after every in-place upgrade: the `/static` ETag was the crate version, which the `main`-tracking upgrade path (`install.sh`, the in-app updater) never bumps, so a browser revalidating after an upgrade was told 304 and kept old JS/wasm against a new API. Each asset now carries a strong, content-derived ETag (SHA-256 of the served bytes); a stale version tag is served the new bytes.
- `scripts/wasm_ui_drift_check.sh` builds from one fixed absolute path on every host: the regenerated wasm depended on the checkout location (cargo's metadata hash includes the absolute path of the out-of-workspace `hse-core` path dependency), which made CI's byte-exact check fail on an artifact that reproduced locally. The script also gains `--write`, the single regeneration procedure.
- Five misleading tests: the non-2xx-collapse lint now scans the bound-variable guard shape too (17 guards were unscanned; 39 now); the env-knob scanner sees wrapper/constant/clap shapes and `KNOWN_HSE_KNOBS` lists every live `HSE_*` knob (`HSE_SQLITE_CACHE_KB`, `HSE_SQLITE_MMAP`, `HSE_RESOURCE_PROFILE`, `HSE_PROVIDER_COST_*`, `HSE_BIND`, `HSE_AUTH_TOKEN`); the wake-lock guards cover the `hse-ai` wrapper and are derived from `install.sh`'s heredocs; the AI-independence test states what it enforces and a new lock pins that `src/ai` never turns model output into an entity/evidence/correlation; `pool_keys_fill_empty_env_slots` asserts `merge_pool_into_env` over a local pool instead of polluting the global one.
- The TEMPORARY `wasm_test.html` diagnostic page (71 KB, synthetic identities incl. a `gmail.com` address) shipped in every binary at `/static/wasm_test.html`, and the wasm start-up `render_proof()` that fed it baked fixture strings into the shipped wasm; both are removed (every view is ported; the checks live in wasm-ui's unit tests).
- `scripts/gate.sh` only runs the wasm-ui drift check under binaryen `version_108` — the build that produced the committed `pkg/` — and the drift script refuses any other build; the pin lives in one place (`WASM_OPT_PIN`).
- Customer exports leaked provider brands spelled as prose: the redactor matched `pwned_passwords` but not "Pwned Passwords" in the evidence summary. Every breach-category source is now matched in its snake_case, spaced and hyphenated spellings.
- Offline derivation modules counted as independent corroborating sources: `phone_intl` + `phone_au` + `phone_geo` re-emitting a seed phone gave it `source_count() == 3` and a "corroborated by 3 independent source(s)" finding from zero external observations. All twelve offline derivation modules (`email_parse`, `username_variants`, `email_canonical`, `phone_*`, `email_locale`, `email_header_geo`, `geo_domain_classifier`, `discord_snowflake`, `structured_id`, `breach_timezone`) are now `ENRICHMENT_ONLY_SOURCES`; their evidence is kept and shown but never inflates `source_count`/`c_effective`.
- Persisted `corroboration` double-counted on every re-persist: the store merged a re-persisted entity with `Entity::merge`, whose `absorb` sums the magnitude, and the engine re-persists the same accumulated entity several times per scan (seed checkpoint, per-round dirty set, finalise, promotion pass). A seed observed exactly once reached disk with corroboration 4. Same-scan re-persists are now GREATEST-merged (idempotent); a distinct scan's observation still accumulates.
- Integration tests wrote into the developer's real `~/.huntsman`: every completed `tests/api.rs` scan appended synthetic module statistics to the real `module_stats.json` (observed: 102 fixture "seed" scans, the input to `hse scan --adaptive`), one test overwrote the real `settings.json`, and the smoke key-chaining fixture banked a fake `shodan` key into the real `key_pool.json` — a test fixture escaping the harness. `tests/cli_seed_validation.rs`'s `run` helper now also isolates `HOME` like its siblings.
- AU-002 silent drop when entity counts exceed plausibility limits: now signals rejection per Rule 0.7 priority 2 (Evidence Integrity)
- AU-092 rule_id reuse: breach-locality-footprint-conflict findings now use distinct "AU-092-CONFLICT" to prevent evidence integrity violation of using same rule_id for fundamentally different claims (agreement vs disagreement)
- AU-031 adjacency silent entity truncation: rule now includes all neighbors in entity_uids instead of silently truncating to first 12 (AGG_SAMPLE) when reporting fan-out aggregates
- Cross-scan-history recurrence evidence accumulation: the summary embedded the prior-scan count, so re-scanning one subject accumulated stale, contradictory snapshots ("recorded in 1 earlier scan" … "16 earlier") in its persisted evidence; the summary is now count-free and re-scans dedup to a single record (hub magnitude preserved via the `hub-entity` tag)
- Cross-scan co-occurrence and relation-recall evidence accumulation (same class): both summaries embedded a rising "across N earlier scan(s)" count and accumulated stale records across re-scans; both are now count-free with magnitude carried by the `hub-cooccurrence` / `cross-scan-relation` tags (AU-080 severity is unchanged — driven by the tag, not the count)

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
