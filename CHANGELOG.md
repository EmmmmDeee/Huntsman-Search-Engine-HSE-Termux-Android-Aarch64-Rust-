# Changelog

All notable changes to this project are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
project versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is `0.x`, the public API may change at any point — minor
versions can include breaking changes; patch versions are bug-fix-only.

## [Unreleased]

### Performance

- **Batched entity persistence.** `ScanEngine::finalise_scan` now writes a
  scan's entities through `Store::upsert_entities_batch` in a single WAL
  transaction instead of one transaction per entity, collapsing N fsyncs into
  one — a material win on low-power aarch64. On a batch error it falls back to
  per-entity upserts, preserving the prior continue-on-error resilience
  semantics (partial persist → `Complete` with an error note; nothing
  persisted → `Failed`). `StoragePort::upsert_entities_batch` now takes
  `&[Entity]` so the caller retains ownership for the fallback.

### Changed

- **Correlator AU-019 now reports each breach cluster's true time window.**
  The rule single-linkage-chains breaches whose consecutive gaps are ≤30 days,
  so a cluster can span far longer than 30 days end to end — yet every firing
  was described as "clustered within 30 days", misleading the analyst on the
  "coordinated compromise" signal. Each cluster now carries its actual
  `start…end` dates and reports the real span (e.g. "3 breach entities span
  2023-01-01…2023-02-10 (40-day window, consecutive gaps ≤30d)"). Detection
  semantics are unchanged. Tests: `au_019_reports_true_window_span_not_a_fixed_30_days`,
  `au_019_requires_at_least_three_breaches`.

### Fixed

- **Correlator AU-003 counts distinct sources, not the observation tally (no
  more inflated "N independent sources" claims).** "High cross-source
  corroboration" gated on and reported `Entity::corroboration` — a saturating
  counter that grows on every re-observation, including repeat runs of the
  *same* module and repeated scans of the same target. Live execution showed
  `name_to_username` alone driving `corroboration=11` on derived usernames,
  which AU-003 then reported as "11 independent sources" — a false intelligence
  claim. It now gates on and reports `evidence_sources().len()` (the
  deduplicated distinct-source set), so a single module re-emitting an entity
  can never read as cross-source agreement. Verified live: AU-003 now reports
  source counts that exactly match each entity's distinct evidence sources.
  Tests: `au_003_counts_distinct_sources_not_observation_tally`,
  `au_003_respects_per_kind_source_thresholds`, and the `mod.rs` integration
  test updated to build real evidence sources.
- **Correlator AU-002 identity cluster gates on confidence (fewer false
  Criticals).** The rule raised a **Critical** "Email + Username + Phone
  co-located" correlation whenever a scan contained at least one of each kind,
  with no confidence floor — so a scan that surfaced an unrelated email and
  phone alongside `name_to_username`'s speculative 0.35-confidence derived
  usernames produced a Critical false positive, and dumped every low-quality
  lead into the cluster. It now requires each facet at Probable confidence
  (≥0.50, matching AU-020) and includes only qualifying entities in the
  cluster. Regression tests: `au_002_ignores_speculative_low_confidence_leads`
  (proven to fail without the gate), `au_002_fires_and_includes_only_qualifying_entities`.
- **Correlator AU-019 breach clustering now uses exact calendar arithmetic.**
  `date_diff_days` approximated with `y*365 + m*30 + d`, which drifts by up to
  ~5 days near month/year boundaries (e.g. `2020-01-01 → 2020-12-31` computed
  as 360 days instead of 365), mis-deciding the rule's "≤ 30 days apart"
  threshold at exactly those edges. It now computes days since the civil
  epoch (Howard Hinnant's `days_from_civil`, dependency-free, leap-year
  correct) and rejects out-of-range month/day components so a malformed value
  can't masquerade as a near neighbour and extend a cluster. The leading
  `YYYY-MM-DD` is also now extracted with a char-safe `get(..10)` instead of a
  raw byte slice. Regression tests: `date_diff_days_is_calendar_exact`,
  `…is_symmetric`, `…rejects_malformed_or_out_of_range`,
  `breach_cluster_uses_exact_30_day_boundary`.
- **`opencorporates` treats auth failures as empty, not as module errors.**
  OpenCorporates retired its keyless free tier — the search endpoint now
  returns `401 Invalid Api Token` without a token (confirmed live). The module
  only soft-handled 404/429 and surfaced every other non-2xx as an error, so a
  keyless `name`/`org`/`abn` scan logged a spurious `module error` and inflated
  `modules_errored` on every run. 401/403 now degrade to an empty result (an
  expected "needs key" outcome), via a unit-tested `status_is_soft_empty`
  classifier; the stale "free tier is generous" doc note is corrected.
  Regression test `auth_and_no_match_statuses_are_soft_empty` fails on the old
  404/429-only behaviour and passes on the fix.
- **CLI logs no longer corrupt `--output json` on stdout.** The tracing
  subscriber used `tracing_subscriber::fmt()`, whose default writer is
  **stdout** — so `hse scan … --output json > file.json` (and other piped
  output) had INFO log lines prepended, making the result fail every JSON
  parser. Surfaced by live execution of a `"Jordan Meyer"` scan, where the
  captured stdout began with a tracing timestamp instead of `{`. Logs now go
  to **stderr** (`.with_writer(std::io::stderr)`); stdout carries only command
  output. New integration test `scan_json_stdout_is_clean_and_parseable`
  (tests/cli_io.rs) spawns the binary and asserts stdout is clean JSON while
  the per-module INFO line appears on stderr — it fails on the old writer.
- **Two more byte-slice panics on untrusted input (sweep, round 2).**
  - `search_engines::generate_username_variants` produced its truncation
    variant with `lower[..lower.len()-1]`. The `>= 5` guard stops an underflow
    but not a mid-codepoint slice, so a pivoted handle ending in a multi-byte
    char (e.g. `andré`) aborted the binary. Now drops the last *character* via
    `String::pop()`. Proven by execution: the regression test panics at
    `mod.rs:830` on the old slice and passes on the fix.
  - `oathnet_pro` password-hint redaction read `&pw[..1]` / `&pw[pw.len()-1..]`
    on untrusted breach-data passwords (frequently non-ASCII). Now uses
    char-safe `str_util::{first_char,last_char}`.
  Adds the `str_util::last_char` helper (unit-tested). Regression test:
  `username_variant_non_ascii_truncation_does_not_panic`.
- **Swept the byte-slice panic class across the codebase.** Following the
  `name_to_username` fix, three more sites sliced strings on raw byte indices
  that are not guaranteed char boundaries, each panicking — and under
  `panic = "abort"` aborting the binary — on non-ASCII input:
  - `diagnostics::analyse` lineage preview sliced `&e.value[..57]`; entity
    values routinely hold non-ASCII names/IDNs/breach strings. Now uses the
    existing char-safe `str_util::truncate_safe` (also a DRY win). Proven by
    execution: the regression test panics at `diagnostics.rs:527` on the old
    slice and passes on the fix.
  - `search_engines::build_queries` built a first-initial via
    `&first.to_lowercase()[..1]` (panicked on a multi-byte leading codepoint
    in a 3-part name).
  - `search_engines::extract_family_names` derived an email-local surname with
    `local[1..]` and title-cased with `lastname[..1]`/`&lastname[1..]`
    (panicked when the local part or surname began with a multi-byte char).
  New shared, codepoint-safe helpers `str_util::first_char` and
  `str_util::title_case` (with unit tests) back the fixes; `name_to_username`
  now reuses `first_char` instead of its own copy. ASCII behaviour is
  unchanged (`"Jordan Meyer"` still yields the identical 7 usernames).
  Regression tests: `build_queries_non_ascii_three_part_name_does_not_panic`,
  `extract_family_names_non_ascii_surname_does_not_panic`,
  `analyse_long_non_ascii_value_preview_does_not_panic`, plus `str_util` tests.
- **`name_to_username` no longer panics (and, under `panic = "abort"`,
  crashes the whole binary) on non-ASCII names.** Initial-letter derivations
  sliced the first *byte* (`&first[..1]`), which is not a char boundary when a
  name part begins with a multi-byte UTF-8 codepoint — so a `name` seed like
  `Émile Zola`, `José Ángel Núñez`, or `Øystein` aborted the scan mid-dispatch
  (proven by execution: exit 101 at `name_to_username.rs:96`). Initials are now
  extracted by Unicode scalar (`first_char`), producing well-formed handles
  (`ézola`, `jánúñez`, …). ASCII output is byte-for-byte unchanged. Regression
  tests: `non_ascii_name_does_not_panic`, `non_ascii_middle_initial_is_char_safe`.
- **ROI top-K gate no longer permanently eliminates the long tail it trims.**
  In `--max-roi` expansion, every candidate was inserted into the per-scan
  `visited` set *during candidate construction*, but the top-K gate
  (`K = 2×max_concurrent + 8`) truncates the candidate list *afterward*.
  Candidates ranked below K were therefore marked visited yet never
  dispatched — silently and permanently amputated from the recursion tree,
  so a target trimmed in round 1 could never be reconsidered in a later round
  even after it gained corroboration that would have lifted it above the gate.
  Targets are now committed to `visited` only at dispatch time, so the top-K
  gate *defers* the long tail (its documented intent) instead of eliminating
  it. Behaviour is unchanged when `--max-roi` is off (no truncation occurs).
  Regression test: `roi_top_k_defers_rather_than_eliminates_candidates`.

### Added

- **Per-module cost telemetry in the dossier.** `hse scan --output dossier`
  now shows each module's cost tier (`free` / `key` / `paid`) in the "modules
  ranked by yield" table and flags keyed/paid modules that yielded nothing
  this scan (`ROI: … consider --exclude …`), making the ROI tuning loop
  self-explanatory to operators.
- **`consumes()`/`accepts()` integrity test.** A registry-wide regression test
  (`module_consumes_covers_probed_accepts`) now fails CI if any module's
  `consumes()` declaration omits a `TargetKind` its `accepts()` matches —
  closing a silent-under-dispatch gap where the O(1) dispatch index would
  never serve a mis-declared module for that kind.
- **Typed entity relations (graph engine, first slice).** New `core::relation`
  module adds first-class attribution edges between entities: a `Relation`
  model + `relations` table + `StoragePort::{upsert_relation,
  relations_for_scan}` (idempotent on a deterministic edge id, cascade-deleted
  with the scan). A deterministic post-scan builder derives `SubdomainOf`
  (Domain→closest parent), `BelongsToDomain` (Email→Domain), and `HostedOn`
  (Url→Domain) edges; these are persisted by `finalise_scan` and surfaced in
  `hse scan --output json` and the dossier's RELATIONS section. Pure open math
  — no inference.
- **Lineage relations (`DerivedFrom`).** Autonomous expansion now records the
  attribution chain as graph edges: as `run_expansion` dispatches each
  candidate, it attributes every newly-surfaced entity back to the parent
  entity it expanded (`child ──DerivedFrom──▶ parent`). Captured via a
  read-only before/after diff localised to the expansion loop — no change to
  dispatch behaviour — and persisted alongside the structural edges.
  (Evidence-derived semantic edges remain a planned follow-on.)
- **Typed edges in the GEXF export.** `hse export … --format gexf` and
  `GET /api/v1/scans/{id}/graph.gexf` now emit the typed `Relation` edges
  (labelled by kind, weighted by confidence) alongside the existing
  shared-evidence co-occurrence edges, so the full attribution graph opens
  directly in Gephi / Cytoscape.
- **Geo co-location relations (`CoLocatedWith`).** `derive_colocation` links
  Coordinates entities within 1 km of each other (Haversine via `util::geohash`)
  with a `CoLocatedWith` edge — the same place surfaced by independent sources.
  Self-contained deterministic geo math (no module coupling); one
  canonically-directed edge per close pair, persisted with the other relations
  and exported to GEXF.
- **Graph-aware correlator rule (AU-031).** The correlator now runs a separate
  pass over the typed relation edges. `AU-031 — Adjacency to known-bad
  infrastructure` flags a benign entity one edge away from a node tagged
  malicious / threat-intel / vulnerable (e.g. a subdomain of a malicious apex,
  or an entity derived from a flagged node) — a finding the flat entity list
  and tag-only rules can't produce. New graph rules slot into `RELATION_RULES`
  without changing the 30 entity rules.
- **Graph cluster rule (AU-032).** `AU-032 — Geographic co-location cluster`
  walks the `CoLocatedWith` edges (connected components) and reports each
  cluster of 3+ coordinates that transitively converge within 1 km — the
  graph-structural signal the pairwise geo rules don't surface.
- **Relation edges in the Web UI + `/relations` endpoint.** New
  `GET /api/v1/scans/{id}/relations` JSON endpoint; the SPA's D3 force-graph now
  draws the typed relation edges as distinct dashed links (relation kind shown
  on hover), alongside the seed-star and correlation links. The attribution
  graph is now visible in every read path — CLI dossier, JSON, GEXF, and web UI.
- **DNS resolution relations (`ResolvesTo`).** `derive_resolution` links a
  Domain to an IpAddress when the IP entity's DNS evidence references that
  domain. Robust by design — it matches the IP's evidence attribute *values*
  and summary tokens against known Domain entities rather than coupling to a
  specific module's attribute key, so it captures both `dns_intel` (attribute)
  and `doh_resolver` (summary) shapes.
- **WHOIS registration relations (`RegisteredBy`).** `derive_registration`
  links a Domain to its registrant Organisation/Email when the Domain's WHOIS
  evidence references one that exists as an entity. Same value-match robustness
  as resolution (matches entity values, not attribute keys); the registrar
  self-excludes since `whois` only emits the registrant org/email as entities.
  Closes the relation taxonomy (structural + lineage + co-location + resolution
  + registration).

## [1.0.0] — 2026-05-27

### Added

- **11 new OSINT orchestration modules** — module count 52 → 63:
  - `seon` (pri 95, key-gated) — Email/phone cross-platform presence
    detection across 250+ services via SEON API.
  - `keybase` (pri 100, free) — Identity graph with cryptographic proofs.
    Pivots from username to linked Twitter, GitHub, Reddit, HN, DNS accounts.
  - `emailrep` (pri 90, key-gated) — Email reputation scoring: breach
    exposure, blacklists, social media profiles via EmailRep.
  - `epieos` (pri 92, key-gated) — Email-to-identity resolution: Google
    profile ID, Maps reviews for chronolocation, Skype handle.
  - `proxycurl` (pri 88, paid) — LinkedIn profile extraction: full
    employment history, education, certifications, personal contacts.
  - `photon` (pri 20, free) — Komoot Photon geocoder for independent
    forward/reverse geocoding corroboration alongside Nominatim.
  - `mylnikov` (pri 17, free) — No-auth BSSID-to-coordinates WiFi
    geolocation. Complements WiGLE when keys are exhausted.
  - `overpass` (pri 15, free) — OpenStreetMap infrastructure query:
    cell towers, substations, surveillance cameras within 500m of coords.
  - `sunrise_sunset` (pri 10, free) — Solar phase timestamps (sunrise,
    sunset, twilight) for chronolocation of imagery.
  - `opencorporates` (pri 80, free) — Australian company/director search
    with AU jurisdiction focus. Cross-references directors and shell-company
    links against the global OpenCorporates dataset.
  - `pwned_passwords` (pri 115, free) — HIBP Pwned Passwords k-Anonymity
    check: SHA-1 range API verifies if a credential hash appears in known
    breach compilations without exposing the full hash.

- **`github_user` enhancement** — SSH public key retrieval
  (`/users/{login}/keys`) and public event activity analysis
  (`/users/{login}/events/public`) with peak working hour extraction.

- **5 new correlator rules** (AU-023 through AU-027):
  - AU-023: Cross-platform identity convergence (Person confirmed by ≥2
    independent identity sources: keybase, github_user, proxycurl, etc.)
  - AU-024: Multi-signal email fraud indicator (converging risk signals:
    suspicious + breach, suspicious + disposable, breach + disposable)
  - AU-025: Corporate registry linked to identity (OpenCorporates
    Organisation co-located with Person entities)

- **Proactive key harvest** — 4 new service domains wired into OathNet
  stealer credential harvest: seon.io, epieos.com, nubela.co,
  opencorporates.com.

- **Infrastructure**: 4 new `KNOWN_KEYS`, 4 new `service_defs`, `sha1`
  crate dependency, updated env templates (install.sh + env_template.txt).

## [0.9.0] — 2026-05-23

### Added

- **`xposed_or_not`** breach module (pri 128). Free, keyless. Queries
  `https://api.xposedornot.com/v1/check-email/<email>` for the list of
  named breaches an address appears in (never credentials). With this
  module the dormant **AU-001** correlator rule (multi-source breach
  corroboration, severity Critical) finally activates — `hudsonrock` +
  `xposed_or_not` together meet the ≥2-source threshold on any
  free-only configuration.
- **`username_search`** (pri 110). Sherlock / Maigret-style. Fans out
  parallel HTTP probes against ~30 popular sites (GitHub, Reddit,
  Mastodon, Keybase, Twitch, Patreon, Lobsters, Hacker News, Telegram,
  …). Per-site timeout 2.5 s, all probes concurrent via
  `futures::join_all`. Emits one `Url` per platform plus a summary
  `Username` entity with the cross-platform count.
- **`github_user`** (pri 108). Public GitHub REST profile lookup, no
  key (60 req/hr unauthenticated). Emits Username metadata + optional
  Person (real name) + optional Email (when published) + optional Url
  (personal site).
- **`gravatar`** (pri 85). MD5 of the email → `gravatar.com/{hash}.json`.
  Confirms an email is in active use; surfaces display name, location,
  linked URLs when published.
- **`wayback`** (pri 38). Wayback CDX API. Snapshot count + first /
  last-seen timestamps (ISO formatted) for a domain — confirms a
  domain isn't newly-registered.
- **`reverse_dns`** (pri 29). IpAddress → PTR via Cloudflare. Emits one
  Domain entity per PTR result tagged `ptr`.
- **`bgpview`** (pri 25). Accepts Asn and IpAddress. Closes the ASN
  target gap (was 0 modules). Holder, country, RIR, allocation date,
  contact emails, website.
- **`phone_intl`** (pri 140). Pure-offline E.164 parse + 175-country
  prefix table (longest-prefix-first so the NANP and Caribbean
  +1-NNN ranges resolve correctly). Closes the Phone target gap
  (was 0 modules).
- **`Module::max_timeout_ms() -> u64`** trait method with default
  `MODULE_TIMEOUT_MS` (3 s). Modules that legitimately need more
  (`gps_fix` → 20 s, `whois` → 10 s) override; engine consults the
  override when the user hasn't pinned `--timeout`. User override
  still wins.
- **`util::http::error_snippet(resp) -> String`** helper. Reads up
  to 200 chars of the response body for HTTP error messages,
  collapses newlines, returns `<empty>` / `<unreadable>` sentinels.
  Every HTTP-based module now embeds the snippet in
  `Error::module(...)` so `HTTP 400` events tell the operator
  *why*, not just *what*.

### Changed

- `dns_resolver` upgraded from A / MX / TXT to A / AAAA / MX / NS / SOA /
  TXT. Lookups run concurrently via `tokio::join!`. SOA emits primary
  NS + serial + intervals and decodes the RNAME field into a real
  `Email` entity tagged `dns-admin` (RFC 1035 §3.3.13). NS records
  emit Domain entities tagged `ns` so DNS chaining picks them up at
  `depth>=1`. TXT auto-tags the parent Domain `spf` / `dkim` /
  `dmarc` / `google-verified` / `ms-verified` when matching markers
  appear.
- `whois` extracts 18 fields instead of 6: adds registrar IANA ID +
  URL + updated date + admin/tech/abuse contact emails + status
  flags + DNSSEC state + registrant org/country/state. Each contact
  email and each nameserver becomes a discrete entity for autonomous
  expansion. Status flags (`clientTransferProhibited`,
  `pendingDelete`, `redemptionPeriod`, …) become entity tags.
- `alienvault_otx` augments pulse count with the top 5 pulse names,
  the deduplicated tag set (capped at 20), the top pulse's adversary,
  the most recent TLP marking, and the earliest pulse-created
  timestamp. Auto-tags `ti:malware` / `ti:apt` / `ti:phishing` etc.
- Shared HTTP User-Agent bumped from the slug `HSE/0.8.0` to the
  RFC 7231 §5.5.3 form `huntsman-search-engine/0.9.0 (+https://...)`.
  Anti-bot WAFs (HudsonRock's cavalier among them) routinely 400 on
  short slug UAs.
- `ip_geo`'s 4xx branch no longer silently swallows the failure
  (ip-api.com's 45 req/min rate-limit was invisible). Now surfaces
  as a real `module_error`, consistent with every other HTTP module.
- `hse modules` CLI `ACCEPTS` column now includes `asn` (was missing
  from the target-kind probe list so ASN-only modules looked like
  they accepted nothing).
- Module count: 13 → 21.

### Fixed

- **Engine killed long-running modules at 3 s ceiling.** `gps_fix`
  on Termux 0.118.x called `termux-location` with an internal 15 s
  timeout, but the engine's `tokio::time::timeout(3_000)` wrapper
  fired first → `WARN timeout module="gps_fix"` every iteration.
  `Module::max_timeout_ms()` lets the module declare its own
  ceiling; the engine honours it when the user hasn't pinned a
  global `--timeout`. Two regression tests in `tests/smoke.rs`
  enforce both the new behaviour and the user-override precedence.
- **`install.sh` aborted on Termux 0.118.x** during the disk-space
  sanity check with `awk: fatal: attempt to access field -2`.
  `df -m $HOME` on Android can emit a row with too few fields, and
  the unconditional `$(NF-2)` becomes a negative field index — fatal
  under `set -euo pipefail`. Reproduced end-to-end on a real device
  (`TERMUX_VERSION=0.118.3`, aarch64, Android SDK 34). The awk
  script now guards `NF >= 4`, the pipeline is wrapped in `{...} ||
  true`, and a `DISK_AVAIL_MB -eq 0` branch prints "could not read
  free disk space — skipping check" instead of falsely claiming
  "Only 0MB free". Earlier PR #4 "robust df parsing" fix only
  handled the *wrap-long-filesystem-name* case — this closes the
  *short-row-on-Android* gap.

### Changed (docs)

- `install.sh` post-install footer now leads with the **Web UI quick
  start** (`hse serve` + `http://127.0.0.1:8080` opened in Chrome) —
  that's the headline use case on Termux. `hse live` joined the CLI
  section.
- `docs/INSTALL.md` "Verifying the install" snippet refreshed
  (0.2.0 → 0.9.0; module count refreshed; added a web-UI smoke test).
- `docs/ROADMAP.md` — added the missing v0.5.0 (Live mode) and v0.8.0
  (Parallel module dispatch) entries; both were marked still-planned
  even though they shipped. "After 1.0" + non-goals unchanged.
- `docs/MODULES.md` — catalogue heading bumped v0.6 → v0.8.
- `docs/TROUBLESHOOTING.md` — added the awk-NF-2 failure mode with
  the workaround pointing at the manual install path.

### Coverage matrix (after)

  Email      hudsonrock + xposed_or_not + email_to_username + gravatar  (4)
  Username   username_search + github_user                              (2)
  Phone      phone_intl                                                 (1) ← was 0
  Domain     hudsonrock + alienvault_otx + crtsh + dns_resolver
             + whois + wayback                                          (6)
  IpAddress  alienvault_otx + whois + reverse_dns + ip_geo + bgpview    (5) ← +2
  Asn        bgpview                                                    (1) ← was 0
  + 6 Termux sensors fire on any target (passive, no-op without
    termux-api)

### Architecture invariants — unchanged

`#![forbid(unsafe_code)]`; rustls + bundled-sqlite only (`md-5`
added for Gravatar — pure-Rust, no native code); GREATEST entity
merge; SHA-256 deterministic UIDs;
`C_eff = clamp(C × (1 + 0.15 × ln(corroboration)), 0, 1)`;
classification derived, never stored; no credentials in evidence
(`xposed_or_not` returns breach company names, never passwords).

> Note: the [Unreleased] section that lived here through May 23
> contained PR #8/#9 review-feedback notes (security: WHOIS read
> cap + SPA XSS + CORS hardening; correctness: persist-failure
> scan-status + termux_cmd kill-on-drop + cli/live event match;
> performance: LiveSession.scan_ids HashSet + WHOIS find_referral
> zero-alloc; API consistency: ModuleCost serde; memory leaks:
> LiveInner pruning). All of those items were squash-merged into
> the v0.8.0 release commit (PR #9) and so are part of 0.8.0
> functionally. The detailed bullet list lives in the PR #9 merge
> commit message.

## [0.8.0] — 2026-05-23

### Added
- **Parallel module dispatch.** `ScanOptions::max_concurrent` has been a
  documented field since v0.1 but was never honoured — the engine ran
  modules sequentially. Now, when `max_concurrent > 0`, the engine spawns
  up to that many module tasks in flight at once via
  `tokio::sync::Semaphore` + `tokio::task::JoinSet`. Wall-time on a
  scan with N accepting modules drops from `sum(module_durations)` to
  roughly `max(module_durations) × ceil(N / max_concurrent)`.
- Default remains `max_concurrent = 0` → sequential, byte-identical to
  v0.1–v0.7. The change is fully opt-in.

### Notes
- The sequential and concurrent paths share all module filter logic
  (allowlist, exclude, free_only, passive_only, accepts) so behaviour
  differs only in scheduling.
- Event ordering: with concurrent dispatch, `ModuleStart` events from
  different modules interleave with each other and with `EntityFound`
  events from faster modules. Each event is self-describing (`type` +
  `module`), so SSE consumers handle this transparently. CLI tracing
  logs will look interleaved — accepted trade-off for the speedup.
- 94 tests pass (84 lib + 10 integration); +3 new integration tests
  cover: concurrent execution is faster than sequential (4 × 200 ms
  modules with max_concurrent=4 complete in < 600 ms instead of > 800 ms);
  semaphore cap is respected (6 modules with max_concurrent=2 never see
  peak in-flight > 2); max_concurrent=0 still uses the sequential path
  (peak in-flight stays exactly 1).
- Release binary stays at 4.8 MB stripped — `JoinSet` / `Semaphore` are
  in the existing tokio feature set, no dependency added.

## [0.7.0] — 2026-05-23

### Added
- **Junction table `entity_observations(entity_uid, scan_id, observed_at)`**
  replaces the v0.2 last-scan-wins semantics that hid entities from
  older scans after a re-scan.
- New store methods:
  - `Store::scan_ids_for_entity(uid)` — every scan that observed this
    entity, most recent first.
  - `Store::observation_count(uid)` — cheap "seen in N scans" aggregate.

### Changed
- `Store::entities_for_scan(scan_id)` now joins through the junction
  table; returns every entity that scan observed regardless of which
  scan currently "owns" the legacy `entities.scan_id` column.
- `Store::upsert_entity` wraps its insert + observation row in a
  transaction so the two stay in lock-step.

### Fixed
- **Re-scanning the same target no longer hides the entity from older
  scans.** Empirically verified end-to-end:
  ```
  hse scan --kind email --value test@example.com (twice, 2s apart)
  scan 138c779a  via_junction=1  via_old_column=0   ← previously broken
  scan f8957375  via_junction=1  via_old_column=1
  observations table: 2 rows, 1 distinct entity
  ```

### Migration
- On `Store::open` a one-time idempotent backfill populates
  `entity_observations` from the existing `entities` table:
  `INSERT OR IGNORE ... SELECT uid, scan_id, observed_at FROM entities`.
  Existing databases gain multi-scan tracking from the moment they
  next see an entity upsert; pre-v0.7 entities keep their single
  recorded observation.

### Notes
- 84 tests pass (77 lib + 7 integration); +4 new junction-table tests
  cover: entity observed by two scans appears in both; `scan_ids_for_entity`
  returns all observers newest-first; entity only in scan A doesn't leak
  into scan B; re-observing the same (uid, scan_id) pair is idempotent.
- Release binary stays at 4.8 MB stripped — no new deps, ~80 lines of
  new code in `store.rs`.

## [0.6.0] — 2026-05-23

### Added
- **Six Termux sensor modules** for on-device GEOINT enrichment. All
  `is_passive() == true`, all `cost() == Free`, all accept any target
  (sensors are environmental — they fire on every scan unless excluded).
  Off-device or with `termux-api` uninstalled, the four `termux-*`
  binary-based modules no-op cleanly (no `module_error` events).
  - `arp_scan` (pri 58) — parses `/proc/net/arp`. No termux-api needed.
    Emits one `IpAddress` + one `MacAddress` per complete ARP row.
    Tagged `local-arp`.
  - `net_interfaces` (pri 55) — reads `/sys/class/net/*/address` and
    `/operstate`. No termux-api needed. Emits one `MacAddress` per
    non-loopback interface. Tagged `local-interface`.
  - `wifi_scan` (pri 65) — calls `termux-wifi-scaninfo`. One
    `MacAddress` per visible AP, evidence carries SSID / frequency /
    RSSI. Tagged `wifi-ap`.
  - `wifi_connect` (pri 70) — calls `termux-wifi-connectioninfo`. The
    connected AP as a `MacAddress` (tagged `wifi-connected`) plus the
    device's local IP on that network as an `IpAddress` (tagged
    `local-wifi`). Filters out the `02:00:00:00:00:00` MAC-restricted
    placeholder and `0.0.0.0` disconnected-state IP.
  - `gps_fix` (pri 68) — calls `termux-location -p network -r once`
    (network provider, fast indoor fix). Emits one `Coordinates`
    entity. Confidence 0.90 for GPS provider, 0.65 for network, tagged
    `geoint` and `provider:<network|gps>`.
  - `cell_survey` (pri 62) — calls `termux-telephony-cellinfo`. One
    `DeviceId` entity per registered cell tower keyed
    `<mcc>-<mnc>-<lac|tac>-<cid>`. Evidence includes radio type
    (lte/gsm/umts/nr), dBm, ASU, level. Handles `mcc`/`mnc` arriving
    as either string or integer (varies by Android version).
- **New helper** `src/util/termux.rs::termux_cmd(cmd, args, timeout_ms)`.
  Returns `Option<Vec<u8>>` — `None` for not-found / non-zero exit /
  timeout, so sensor modules can short-circuit with a single `?`-style
  match. Same helper used by all four `termux-*` modules.

### Changed
- Module count 7 → 13. Default scans on a Termux device with
  `termux-api` installed now pick up environmental WiFi / GPS / cell
  context as enrichment. Off-device, only the file-reading sensors
  (`arp_scan` if `/proc/net/arp` exists, `net_interfaces` if
  `/sys/class/net` exists) contribute.
- Recommended pattern when sensors are unwanted: `hse scan ...
  --exclude arp_scan,net_interfaces,wifi_scan,wifi_connect,gps_fix,cell_survey`
  or use the allowlist `--modules` flag to opt in specifically.

### Notes
- 80 tests pass (73 lib + 7 integration); +18 new sensor-module tests
  cover passive/free flags, accepts() for any target, and parse-fixture
  output for arp_scan, wifi_scan, wifi_connect, gps_fix, cell_survey.
- Release binary 4.7 MB → 4.8 MB stripped (six small modules +
  termux_cmd helper).
- No new external dependencies (`tokio::process::Command` was already
  in the tokio feature set from v0.1).

## [0.5.0] — 2026-05-23

### Added
- **Live mode** (`src/core/live.rs`). Re-run a scan on a fixed interval,
  with the same `ScanOptions` and the same engine path (expansion +
  correlator included). Sessions are tokio tasks tracked in an in-memory
  registry; cancellation is via `Arc<AtomicBool>` — no extra dependency.
- New types: `LiveOptions { interval_secs, iterations }`, `LiveSession`,
  `LiveStatus`, `LiveRequest`, `LiveScanner` (cheap-to-clone `Arc` wrapper).
- New event variants:
  - `LiveStart { live_id, target_kind, target_value, interval_secs }`
  - `LiveTick { live_id, iteration, scan_id }`
  - `LiveStop { live_id, reason }`
- HTTP endpoints:
  - `POST   /api/v1/live` — start a session (returns `live_id`)
  - `GET    /api/v1/live` — list active/completed sessions
  - `GET    /api/v1/live/{id}` — single session record
  - `DELETE /api/v1/live/{id}` — request graceful stop
  - `GET    /api/v1/live/{id}/events` — SSE stream that demultiplexes
    both live-level events and the events of every scan the session has
    spawned, so observers see the full picture per iteration.
- CLI subcommand: `hse live --kind … --value … [--interval N] [--iterations N]
  [--depth N] [--free-only] [--passive-only] [--modules CSV]`. Prints
  events as compact JSON to stdout until Ctrl-C.
- SPA: new **Live** tab (sits between Scan and Entities). Form mirrors the
  HTTP request payload (target + interval + iterations + ScanOptions
  knobs); Start/Stop buttons; iteration counter; rolling event log fed
  by the live SSE stream.

### Fixed (ported from PR #6 v0.4 review)
These fixes originated as review feedback on the v0.4 PR and apply equally
to v0.5 since the live engine reuses the same code paths. Cherry-picked
onto this branch so the v0.5 PR isn't merged with regressions.
- **Severity sort was broken**: `Severity::to_string()` produced
  `"CRITICAL"` but `correlations_for_scan` ORDER BY matched `'critical'`,
  so every row hit `ELSE 4` and sort was a no-op. Added
  `Severity::as_canonical()` returning the lowercase form; storage now
  uses that, keeping the column / serde JSON / SQL ORDER BY in sync.
- **scan_id inconsistency CLI vs API**: API used
  `format!("{:?}", kind).to_lowercase()` ("ipaddress"), CLI used the raw
  user-provided `--kind` value ("ip"). Same target → different scan_ids.
  Added `TargetKind::canonical_str()` returning the snake_case form,
  used by every `scan_id()` caller (including the new live module).
- **CORS permissive on non-loopback bind**: `router(state, bind)` now
  inspects the bind address and applies restrictive CORS when not bound
  to loopback. Two new unit tests cover the detector.
- **alienvault_otx swallowed 429 / 5xx**: now only 404 is treated as
  "no findings"; other non-2xx statuses surface as `module_error` events.
- **whois parser allocated per line per key**: replaced `to_lowercase()`
  with a zero-allocation `eq_ignore_ascii_case` prefix check.
- **SPA `min_expand_confidence` rejected 0**: explicit `Number.isFinite`
  check instead of `|| 0.75` falsy fallback.
- **SPA entity-merge dropped tags**: now union-merges tags by UID.

### Implementation notes
- Each tick spawns a fresh scan via `engine.run()`. Scan IDs are
  generated by the existing `scan_id()` (which mixes `unix_now()` so
  back-to-back ticks get distinct IDs).
- Cancellation polls every 250 ms while sleeping the interval, so a Stop
  request takes at most that long to take effect even on long intervals.
- The SSE handler demultiplexes by `event.scan_id == live_id ||
  scanner.session_owns_scan(live_id, event.scan_id)` — newly-spawned
  scans show up in real time without subscribing per scan.
- Sessions are in-memory only (lost on restart, by design). Persistence
  deferred to v0.7+.
- 62 tests pass (55 lib + 7 integration); +4 new live-module tests,
  +2 new `is_loopback_bind` tests (cherry-picked).
- Release binary stays at 4.7 MB stripped — no new deps.

## [0.4.0] — 2026-05-23

### Added
- **Correlator** (`src/core/correlator.rs`). Rule-based post-scan analysis
  that runs synchronously after every scan completes and emits one
  `Correlation` per firing rule. Rules are pure functions over the
  collected entities; adding a rule is a 10-line append to
  `evaluate_rules`. Initial rule set:
  - `AU-001` Multi-source breach corroboration (Critical) — email in ≥2
    distinct breach sources. Dormant in v0.4 (only `hudsonrock` is a
    breach source so far); activates as v0.5+ adds more.
  - `AU-002` Identity cluster (High) — Email + Username + Phone all
    co-located in the same scan.
  - `AU-003` High cross-source corroboration (Medium) — any entity with
    `corroboration ≥ 3` independent sources reporting the same fact.
  - `AU-010` Infrastructure consensus (Medium) — Domain or IP confirmed
    by ≥3 distinct module sources at the evidence level.
- New `Severity` enum (`Low < Medium < High < Critical`), persisted to
  the `correlations` SQLite table with severity-sorted retrieval.
- `EventKind::CorrelationFound { correlation }` and
  `EventKind::CorrelationsDone { count }` event variants — surfaced via
  SSE so the SPA renders correlations live as they fire.
- `GET /api/v1/scans/{id}/correlations` endpoint.
- SPA: new **Correlate** tab with severity-coloured cards. Correlations
  also live-stream into the scan log during the run.
- CLI: `hse scan` table output now includes a correlations section
  beneath the entities. `--output json` adds a `correlations` field.
- Two new free modules:
  - `alienvault_otx` (Free, no key) — accepts `ip` and `domain`. Queries
    AlienVault OTX for threat-intel pulse count. Adds a third source
    that contributes to `AU-010` consensus.
  - `whois` (Free, no key) — raw whois protocol over TCP port 43 (works
    in Termux with no root). Follows IANA referrals once, parses
    registrar / dates / nameservers / registrant email.

### Changed
- Module registry grew 5 → 7. Default scans now hit OTX and whois
  alongside the existing modules, so AU-010 can plausibly fire on
  popular domains (crtsh + dns_resolver + whois + OTX = 4 sources).
- Schema: added `correlations` table with a `UNIQUE(scan_id, rule_id,
  description)` constraint so re-running the correlator on the same scan
  is idempotent.

### Notes
- 56 tests pass (49 lib + 7 integration); 14 of those are new
  (10 correlator rule tests, 4 new module accepts/cost tests).
- Release binary 4.6 MB → 4.7 MB stripped.
- No new external dependencies — `whois` uses `tokio::net::TcpStream`,
  `alienvault_otx` reuses the existing rustls reqwest client.

## [0.3.0] — 2026-05-23

### Added
- **HTTP server + minimal SPA + Server-Sent Events.** New `hse serve`
  subcommand boots an axum 0.8 server bound to `127.0.0.1:8080` (localhost
  only — no LAN exposure by design). Open `http://127.0.0.1:8080` in
  Chrome / Firefox on the device.
- New CLI flag: `hse serve --bind <HOST:PORT>` (env `HSE_BIND`).
- HTTP API (`/api/v1/...`):
  - `GET /health`, `GET /version`
  - `GET /modules` — full registry with cost / passive flags
  - `POST /scans` — create a scan with full `ScanOptions` body
  - `GET /scans` — recent history (capped at 200)
  - `GET /scans/{id}` — single scan record
  - `GET /scans/{id}/entities` — entities discovered by the scan
  - `GET /scans/{id}/events` — Server-Sent Events stream (live progress)
- New embedded SPA at `src/web/spa.html` — single self-contained file
  (no CDN, no JS frameworks, ~520 lines including inline CSS + JS):
  - Scan tab with full `ScanOptions` form (incl. expansion knobs)
  - Live module-progress log fed by SSE
  - Entities tab with kind filter + value search + sortable columns
  - History tab (clickable to reload past scans)
  - Modules tab listing the registry with priority / cost / passive badges
- `tower_http::cors::CorsLayer::permissive()` (safe because we bind to
  loopback only).
- Graceful shutdown on `SIGINT` / `SIGTERM` via `tokio::signal`.

### Changed
- New dependencies: `axum 0.8`, `tower 0.5`, `tower-http 0.6`,
  `tokio-stream 0.1` (sync feature), `futures 0.3`. All rustls-compatible,
  no native-TLS, no openssl, no C-linked deps.
- Release binary 4.3 MB → 4.6 MB stripped (axum + tower bring ~300 KB).

### Notes
- No new core data-model changes; the existing `ScanOptions` /
  `EventBus` / `ScanEngine` carry the HTTP server with zero refactors.
- SSE stream closes when the client disconnects; no auto-close on
  `ScanComplete` for v0.3 — browser `EventSource` handles teardown
  cleanly when the user navigates away.

### Fixed
- CI: MSRV bumped 1.85 → 1.88 to match the `let_chains` feature actually
  used by the engine. Updated `Cargo.toml` `rust-version`, the dedicated
  CI MSRV job, the installer's `RUST_MIN_VERSION`, and all doc / badge
  references.
- CI: four clippy-deny-warnings findings introduced in the v0.2.0 +
  docs/installer PR.
  - `clippy::large_enum_variant` on `Command::Scan` — annotated with
    `#[allow]` (intentional: the variant is the full `ScanOptions`
    surface as clap-derived flags; boxing each field would obscure the
    one-flag-per-field mapping).
  - `clippy::print_literal` in `cli::cmd_scan` — `"CLASS"` moved into
    the format string.
  - `clippy::unnecessary_sort_by` × 2 — `cli::cmd_modules` and
    `ScanEngine::new` switched to `sort_by_key(|m| Reverse(m.priority()))`.
- CI: `install.sh` shellcheck warnings.
  - SC2154: `trap '...' EXIT` body refactored to a named `on_exit()`
    function so shellcheck sees the `rc` assignment.
  - SC2059: every `printf "${COLOUR}...${NC}\n"` rewritten to
    `printf '%s...%s\n' "$COLOUR" "$NC"`.
  - SC1091: `# shellcheck source=/dev/null` directive on `source
    "$HOME/.cargo/env"`.
- `install.sh`: the system-clock hint was an unrunnable awk command
  (single-quote / double-quote escaping was wrong, and the suggested
  `date -s '$(...)'` quoting would have been treated as literal anyway).
  Replaced with two clearer hints (Android Settings, or manual
  `date -s 'YYYY-MM-DD HH:MM:SS'`).
- `install.sh`: disk-space probe was vulnerable to empty `df` output
  yielding a non-numeric `DISK_AVAIL_MB`. Now validates with a regex
  before the arithmetic comparison.

### Added
- Single-shot installer script (`install.sh`) with full Termux aarch64
  support, dependency installation, retry-with-backoff, clock / disk /
  RAM sanity checks, idempotent re-install, and post-install verification.
- GitHub Actions CI: `cargo fmt`, `cargo check`, `cargo clippy -D warnings`,
  `cargo test`, MSRV check (1.85), and `install.sh` shellcheck.
- Issue templates (bug report, feature request) and PR template enforcing
  the architecture invariants.
- Dual MIT / Apache-2.0 license files (Rust ecosystem standard).
- Documentation tree under `docs/`:
  - `INSTALL.md` — every install path + every known Termux quirk.
  - `USAGE.md` — full CLI reference with examples.
  - `MODULES.md` — module catalogue with cost / target / synergy notes.
  - `ARCHITECTURE.md` — design decisions and invariants.
  - `TROUBLESHOOTING.md` — Termux-specific failure modes and workarounds.
  - `ROADMAP.md` — version-by-version delivery plan.
  - `DESIGN.md` — long-term north-star spec (moved from `CLAUDE.md`).
- `SECURITY.md` (security model + responsible disclosure).
- `CONTRIBUTING.md` (how to add a module, code style, commit format).
- `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1).

### Changed
- `CLAUDE.md` (5,099-line design north-star) moved to `docs/DESIGN.md`.
- `README.md` rewritten to industry-standard format with badges, short
  quick-start, and links into `docs/`.

## [0.2.0] — 2026-05-23

### Added
- **Autonomous expansion engine** (`ScanEngine::run_expansion`). When
  `ScanOptions::depth > 0`, each round picks high-confidence entities
  produced so far, converts them to scan targets via
  `TargetKind::from_entity_kind`, and re-dispatches every accepting module.
  Five free modules now chain automatically into a domain → subdomain →
  IP → geo enumeration without manual command stitching.
- `TargetKind::from_entity_kind()` / `to_entity_kind()` — bidirectional
  mapper with explicit unscannable kinds (Organisation, MacAddress,
  Credential, Password, …).
- `ScanOptions` fields: `min_expand_confidence` (default 0.75 = Verified
  tier), `max_entities`, `max_wall_time_secs`. All serde-defaulted.
- `EventKind::ExpansionTick { depth, queued, visited }` and
  `EventKind::ExpansionStop { reason }` for observers.
- CLI flags on `hse scan`: `--depth`, `--min-expand-confidence`,
  `--max-entities`, `--max-wall-time`.
- Five new integration tests covering expansion depth, threshold filtering,
  budget enforcement, cycle detection.

### Fixed
- `Store::upsert_entity` was preserving the old `scan_id` column on
  conflict, so re-scanning a target left `entities_for_scan(new_sid)`
  returning zero. Last-scan-wins semantics are correct for v0.2; a
  junction table for full multi-scan tracking is deferred to v0.7+.

### Notes
- No new dependencies. No new files. ~120 lines added to `engine.rs`.
- Binary still 4.3 MB stripped.

## [0.1.0] — 2026-05-23

### Added
- Foundation: `core` (entity, error, scan, event, module trait, engine),
  `util` (rustls HTTP, key loading, scan-id), `storage` (SQLite WAL).
- Five free modules — `hudsonrock`, `crtsh`, `dns_resolver`, `ip_geo`,
  `email_to_username`.
- CLI: `scan` / `modules` / `doctor` subcommands surfacing the full
  `ScanOptions` API.
- `#![forbid(unsafe_code)]` and Termux-first defaults
  (`$HOME/.huntsman/huntsman.db`, `WORKER_THREADS = 2`,
  release profile `opt-level=z` + `lto` + `strip` → 4.3 MB binary).
- 31 unit tests + 2 integration smoke tests, all passing.
- Architecture invariants enforced:
  - rustls + bundled-sqlite only (no openssl, no native TLS, no C deps)
  - GREATEST-semantics entity merge
  - SHA-256 deterministic UIDs
  - `C_eff = clamp(C × (1 + 0.15 × ln(corroboration)), 0, 1)`
  - Classification derived, never stored
  - Passwords / credentials never written to evidence

[Unreleased]: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases/tag/v0.9.0
[0.8.0]: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases/tag/v0.8.0
[0.7.0]: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases/tag/v0.7.0
[0.6.0]: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases/tag/v0.6.0
[0.5.0]: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases/tag/v0.5.0
[0.4.0]: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases/tag/v0.4.0
[0.3.0]: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases/tag/v0.3.0
[0.2.0]: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases/tag/v0.2.0
[0.1.0]: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases/tag/v0.1.0
