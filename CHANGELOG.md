# Changelog

All notable changes to this project are documented here. Format per [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Added

- Provider coverage is recorded, and silence is no longer mistaken for a negative. `core::intelligence` gains `ProviderOutcome` — observed, clean-negative, not-attempted, or failed, each unresolved case naming its reason — and the ledger refuses to reject a claim while any provider bearing on it never actually answered. A source that broke, ran out of quota, or was never configured can no longer be counted as having said no. Coverage is checkpointed with the ledger, so a resumed scan still knows what it is owed, and older checkpoints still load.
- A location can no longer claim precision its basis never had. Every `LocationBasis` carries an honest floor (a directly observed fix down to 10 m; an IP-derived one no tighter than 25 km), and an assertion below its floor is now invalid instead of being stored as though it were a doorway. Bases that locate the *subject* are marked apart from those that locate something merely associated with them — an egress, a registered office, an administrative area. Two locations are never averaged: they narrow to the tighter constraint when they overlap, and are preserved as an explicit, cross-linked conflict when they do not.
- The headline location estimate no longer claims precision none of its sources had. A fix fused from several sightings reported the spread between them as its radius, so two city-grain signals that happened to agree closely — a search-snippet geocode and a social-profile bio both naming the same city — produced a ± 0.2 km answer from sources good to 5 km at best. The fused radius is now floored at the finest contributing observation: agreement corroborates the area, it does not synthesise a street.
- The headline location now says whether it observed the subject or a place associated with them. A registered office, a breached postcode, an ISP allocation block and an area-code region are all real places that can be right about the address and wrong about the person; only a handset fix, a photo's GPS, or the Wi-Fi access points the subject's device can see are sightings of the subject. `report.json` carries the verdict as `best_location.locates_subject_directly` and the dossier prints an explicit note under any fix that did not.
- A scan now reports what it managed to ASK, not only what it found. `report.json`, the CLI dossier and the web console's Summary tab each carry the same provider-coverage block, derived from the scan's own dispatch events: which providers answered, which broke, which were never queried, and why. Without it a thin result was ambiguous — a sweep that queried everything and found little and one where a third of its providers failed rendered identically, and only the first is evidence of absence. Coverage that is simply unknown (an old scan whose event log has been pruned) is reported as unknown, never as a clean bill of health.
- New endpoint `GET /api/v1/scans/{id}/coverage`, feeding the console's Provider Coverage panel.
- The Ollama removal is now complete: the LoRA training tooling under `scripts/finetune/`, a dormant daemon poll method on the storage port and three stale comments were still in the tree, and the removal lock now scans the whole live tree, by path and by content, so a leftover or a quiet re-add fails CI. `hse export/diff/audit latest` resolves the latest scan through the indexed status column instead of a JSON full scan.
- The Ollama / local-AI integration is gone: the `hse analyze` command, the `hse-ai-daemon` binary, the `hse-ai` wrapper, the `feature.ai_daemon` toggle and the installer's model bootstrap. It was opt-in, off by default and never touched by a scan — and its disk probe was what killed the installer on a real device. Existing databases are unaffected.
- `hse report` replaces three separate commands with one that answers the whole question. `audit`, `benchmark` and `gaps` are three lenses on the same completed scan; `hse report --scan-id latest` now runs all three. The individual commands still work for scripts. The visible command list is down from 21 to 19.
- A first install on a clean Termux no longer throws away the prebuilt binary and compiles from source. Revision resolution used `git`, but ran before the step that installs git — so on a fresh device it always failed, the downloaded and sha256-verified binary was always rejected as unverifiable, and every new user paid for a full on-device Rust build. It now resolves the revision over curl when git is absent.
- The installer no longer says a downloaded binary is "built from a different commit" when it could not determine the commit at all; it now distinguishes a mismatch from an unverifiable one and names the flags that override it.
- A successful install no longer reports failure. One `df -Pm` in the optional local-AI step — a flag Termux's `df` does not support, as the installer's own preflight comment already noted — killed the whole script under `set -e`, so an install where every step succeeded ended in "Installation failed (exit 1)" and `hse update` in an error. The optional step can no longer fail the install at all.
- `hse doctor` no longer counts unfilled template slots as configured keys. On a fresh install it reported "62 keys loaded" with zero real values, and — worse — hid the entire list of keys worth acquiring, because a name being present counted as it being set. It now reports what is actually usable and shows the 54 keys still to register.
- `hse doctor` no longer reports "no modules currently show a failure streak" directly above a list of sources that are failing. That line reads a per-process tracker which is always empty in a `doctor` run, because doctor never dispatches anything — so it was a constant, not a measurement. It now says it wasn't measured and points at the section with the recorded outcomes, while still reporting a real all-clear when a process actually ran modules.
- HSE no longer tells you to renew API keys you never set. Unfilled template slots were being handed to providers as credentials, and the resulting 401s were reported back as "configured key rejected — replace or renew". Placeholders are now barred at the point any pooled key is handed out, whichever way it got into the pool.
- Unfilled key slots are no longer added to the rotation pool, so `hse keys validate` no longer spends live requests probing placeholder text and reporting providers as rejecting credentials you never supplied.
- SeekNow's within-scan response cache is now actually within-scan. Keyed globally, a concurrent scan could be served records another scan had fetched — provider output attributed to a scan that never made the call — and starting a scan wiped a running one's cache.
- Typosquat findings are no longer lost between concurrent scans. The module's within-scan dedup was a single shared set, so once one scan had covered a domain a second scan running at the same time silently produced nothing for it. The set is now per scan.
- Two SeekNow latches that were documented as per-scan were in fact process-wide, so concurrent scans in a long-lived `hse serve` interfered: the first scan to probe the quota left every sibling pinned to the un-scaled default cap, and one scan hitting a rejected key made every sibling report a failure it never saw. Both now live in the same per-scan state the other quota flags use.
- The same double-counting is fixed for Wi-Fi and network registry data, and a build check now catches the next instance. `wifi_intel` resolves access points through WiGLE and `ip_registry` reads the same BGPView endpoints as the standalone modules for those providers; findings from each are now attributed to the database they came from. The check found the BGPView case on its first run.
- A cell tower's position is no longer counted twice. `cell_intel` geolocates towers by querying OpenCelliD, and the standalone `opencellid` module queries the same database with the same key for the same towers — so the identical position arrived under two source names, merged, and read as two independent sources agreeing. It is now attributed to the database it came from, so retrieving one record twice no longer raises confidence. The tower's radio detection, which really is an independent observation, is unaffected.
- The benchmark report now says whether its own scorecard is safe to compare against another run's. A run whose providers had no credential yields fewer entities for a reason that has nothing to do with the configuration being tested, and the two scorecards looked identical; `hse benchmark`, the API and the console now carry the caveat, above the numbers rather than below them.
- Provider coverage separates what BROKE from what the scan simply did not ask. Narrowing a sweep is ordinary — an allowlist, a category focus, free-only — so a single "incomplete" count would look alarming on every scan and be ignored on all of them. The report, the API, the dossier and the console now say "every available provider answered; N were out of scope" when nothing is wrong, and reserve the warning for providers that could not be used.
- Skipped modules now record WHY they were skipped as a structured class rather than only as prose, so a provider that was deduped because it already ran, or one that could never have answered about a private address, is no longer reported as a coverage gap. Only two of the four kinds of skip — the operator narrowing the sweep, and a provider that could not be used — leave a provider owing an answer.
- Consolidated onto one intelligence model. The `core::claim` and `core::geo_confidence` layers added earlier in this cycle duplicated `core::intelligence`, which landed separately with a stronger source-lineage model, and have been removed; only the parts above, which `core::intelligence` genuinely lacked, were carried across.
- GEOINT frontier preference: the dispatch-utility model gains a bounded `W_GEO` term (0.25, against `W_INFO` 3.0) derived from each module's own declared outputs and category, so geolocatable work is attempted ahead of otherwise-equal alternatives without ever outranking stronger evidence. Visible in the dispatch explanation and wired at the live call site.


- T3 quality: AU-002 identity-cluster implausibility rejection signaling as AU-002-REJECT finding
- `Module::is_derivation()`: a module declares that its output is a deterministic transform of data already in the graph (parser, canonicaliser, permutation generator, offline decoder). An architecture test pins the declaration to `hse_core::ENRICHMENT_ONLY_SOURCES` in both directions, so the "does this source corroborate?" fact has one enforced authority instead of a hand-maintained list.
- `util::paths::isolate_for_tests()` + `tests/common::isolate_home()`: integration-test crates (where `cfg!(test)` is false in the linked library) now redirect the whole `~/.huntsman` layout at a per-process temp dir; an architecture test pins that no production code can call it.

### Changed

- The dormant second scheduler in `core::intelligence` (`BoundedFrontier` and its checkpoint) is deleted; `core::roi` and the engine round loop are the one scheduler. The provider-coverage code the product actually uses moved to its own module, `core::coverage`. What remains in `core::intelligence` is the staged claim ledger, and its doc now says so.
- `hse doctor` reports the egress proxy pool when one is configured: it refreshes the pool in-process and prints usable/total and one redacted line per proxy. An all-dead pool is a doctor failure, because a configured pool never falls back to a direct connection.
- The installer retires the local-AI leftovers an older release put on the device: the `hse-ai` wrapper (stopped first), its pid/log, and the `HUNTSMAN_OLLAMA_MODEL` line in `~/.huntsman.env`; the database drops the orphaned `scan_analysis` table on open. `.env.example` no longer documents the removed subsystem.
- The SeekNow per-scan cap now reaches the module layer through `ModuleRuntime` like every other module mutation, so an engine built without modules no longer writes into the process-wide budget.
- AU-002 rule now surfaces MAX_PER_KIND limit-exceeded cases as Medium-severity rejection findings instead of silent drops
- AU-092 rule now distinguishes conflict case with separate rule_id "AU-092-CONFLICT" (was previously reusing "AU-092")
- `GET /api/v1/health` is exempt from the non-loopback bearer-token gate (GET only; every other verb on the path stays gated). The Railway/container deployment (`hse serve --bind 0.0.0.0`) could never pass its own credential-less `healthcheckPath` probe before this; `railway.json` is now pinned to `api::auth::HEALTH_PATH` by test.
- `hse config <key> on|off` now validates the key with the same `modules::is_known_toggle_key` the `PUT /api/v1/settings/toggles` handler uses (its private duplicate is gone) and exits non-zero on an unknown key instead of persisting a silent no-op.
- WiGLE BSSID lookups probe the two corpora an address can belong to (WiFi via `network/detail?type=WIFI`, Bluetooth via its own `/api/v2/bluetooth/detail`) — two billed requests per dispatch, not three.
- `Store::checkpoint_truncate()` now returns `Err` when SQLite reports the TRUNCATE checkpoint blocked by a concurrent reader; `hse tidy` and the finalise housekeeping no longer report a WAL truncation that did not happen.

### Fixed

- Fifteen keyed modules reported a missing API key as "searched, found nothing". Coverage counted them as having answered, so `is_exhaustive()` could vouch for a sweep nobody made. They now report the missing key, which coverage records as not attempted.
- Four read endpoints bypassed the candidate quarantine every sibling enforces by default: `GET /scans/{id}/path`, `/communities`, `/trust` and `/gaps` ran the raw entity/relation set through path search, community detection, trust propagation and gap analysis, so an unverified same-name breach record the correlator had quarantined could be returned by value as a path node, join or name a community, be ranked, or be reported as an actionable "orphan" — without `?include_candidates=1`. All four are gated now (`connect_cross_scan` gates its own cross-scan graph).
- `report.json` now resolves against itself: a correlation's `entity_uids` always name entities in the same document. A platform-infra entity a finding references (AU-004 on a compromised hosting IP) is restored under the default `include_infra=false`; a finding on a hidden candidate is dropped.
- Five silent key failures, the class the SeekNow fix above closed: Numverify's and SEON's HTTP-200 error envelopes, BuiltWith's `Errors[]` (codes -2/-3/-5), a domainsdb `429` across the whole zone sweep, and `github_user` never sending the configured token on its profile, SSH-key and events calls. Each now reports the key to the pool and surfaces an error naming the provider's own detail instead of reading as "found nothing".
- AU-108 (breach-listed cross-platform footprint) was blind to `github`/`tiktok`/`reddit` handles: its hand-copied platform list had fallen behind `breach_rich`'s. Both read one constant (`core::breach_platforms`).
- AU-058's ratemyagent slug parser rejected every single-token agent/business name (`century21-bondi-12345`) against its own documented shape.
- `domainsdb` described itself as "(free, no key)" beside `cost: key_gated` in the module listing.

- WiGLE cell/Bluetooth intelligence was fabricated from WiFi rows (RULE.md's own cautionary case, still live): `/api/v2/network/search` has no `type` parameter, so `?type=cell` / `?type=bluetooth` were ignored and WiFi results were labelled as cell-carrier and Bluetooth-beacon findings. Each corpus now goes to its own documented endpoint (`/api/v2/cell/search`, `/api/v2/bluetooth/search`) with only documented parameters, verified against `https://api.wigle.net/swagger.json` and pinned by test.
- OathNet search sessions: `init_session` reads the session id at `data.session.id`, the path the provider's live reference documents ("The returned `session.id` should be passed as `search_id` to all subsequent service calls"). An earlier change in this release had switched the parse to a flat `search_id` on the strength of the in-repo `docs/OATHNET_API_GUIDE.txt`, which was wrong in three places (now corrected, source cited); the previously shipped `/data/session/id` read was right and is restored as the only accepted shape.
- SeekNow reported a rejected API key (`invalid_api_key` / `plan_required`, HTTP 401) as "searched, found nothing" for every seed of the scan: the rejection was answered with an empty result at the transport layer and only a single log line at latch time said otherwise. Each seed now returns a module error naming the cause and its remedy (`util::see_know::KeyRejection::guidance()`, one text behind the warning and the error); a seed with real evidence keeps it, and an empty seed with no rejection stays a clean negative. `hse doctor`'s SeekNow section prints the same cause and remedy (a `plan_required` key is told to fix its plan, not to swap the key).
- `pwned_passwords` tagged its finding `breach` and summarised it as "value seen in N breach(es)". HIBP's k-Anonymity range check says the target string appears N times as a *password* in the corpus, not that the account was breached — yet the `breach` tag fed AU-016/AU-019/AU-022, the email-risk rule and the breach-geo promotion pass. The finding is now `pwned-password` + `used-as-password` with a summary that says exactly that, a `password_occurrences` attribute, and a Username confidence capped at HIGH_PLUS.
- `redact_credentials` masked only `HUNTSMAN_*` environment values in upstream error bodies; a key from the rotation pool (`hse keys add`, the Settings pool endpoints) never lives in the environment, so one echoed by a provider error reached the persisted events table and the SSE stream verbatim. Every pooled key value (any status) is now masked too.
- Under a long-lived `hse serve`, one scan's finalise-time event prune (newest 100 000 rows kept, globally) could delete a still-running scan's own earliest events — its `ScanStart` and early `ModuleDone` rows, which feed the export's module tally, the diagnostics view and `events.log`. Events of a scan that is still pending/running and started within the 7-day retention window are now exempt from both cuts; finished scans and a killed process's stale `running` row are pruned as before.
- SeekNow's transport/parse errors were labelled `seek_now`, a second name for the module the registry calls `see_know`; because the shareable-export redactor derives its brand list from the registry, `[seek_now] …` rows in an exported events log escaped redaction. One registered name (`util::see_know::SRC`) now labels every error from both layers, pinned by an architecture test.
- The key-write 403 (`settings/keys` PUT, `keys/pool/add|revoke|rotate`) told operators to restart with `hse serve --allow-key-write`, a flag that does not exist (writes are on by default; the switch is `--no-key-write`). One helper now produces the body, and an API test checks every `--flag` it names against the CLI definition.
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
