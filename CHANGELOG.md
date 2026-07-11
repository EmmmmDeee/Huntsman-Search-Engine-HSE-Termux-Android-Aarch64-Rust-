# Changelog

All notable changes to this project are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
project versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is `0.x`, the public API may change at any point — minor
versions can include breaking changes; patch versions are bug-fix-only.

## [Unreleased]

### Added
- **`optimization_hints` regains two event-sourced signals a pure entity-only
  scan analysis structurally cannot see: a cost-gated "scan exceeded 60s with
  a zero-yield keyed/paid module" hint, and a bounded per-scan summary line
  ("N of M dispatched modules found nothing for this target kind").** Both
  read `Event`/`ModuleCost` directly rather than the derived entity set, so a
  dispatched module that found nothing is now visible in the dossier and JSON
  output instead of silently vanishing. Available in both `hse scan --output
  dossier` and `--output json`.
- **`hse update --check`'s git plumbing (`commits_behind`, `changelog_lines`)
  is now proven against a real `git` subprocess, not just pure-logic tests.**
  A local origin+clone fixture pair (no network) exercises the actual
  `git fetch`/`rev-list`/`log` calls behind the ahead/behind count and the
  one-line changelog, including the no-upstream-configured case. Dev-only,
  zero shipped cost. Regression tests
  `commits_behind_and_changelog_lines_reflect_real_git_state`,
  `commits_behind_returns_none_without_a_configured_upstream`.
- **A proven "reused secret" tie between two accounts is now a walkable graph
  edge, not just a standalone correlation finding.** When the correlator
  proves two accounts share a controller via a reused, individuating secret
  (a salted hash, session token, wallet address, API key, or a
  cross-source-corroborated password), that tie is now also emitted as a
  first-class relation between the two identities — so the dossier's
  CONNECTIONS section and the graph export can walk it like any other
  relationship, not just read it off a separate finding. A secret tying
  three or more accounts links every pair directly, not just a chain through
  one of them. Regression tests
  `derive_reused_secret_link_ties_two_accounts_sharing_a_salted_hash`,
  `derive_reused_secret_link_precision_gate_matches_au047_exactly`,
  `derive_reused_secret_link_emits_the_full_pairwise_clique`.
- **AU data depth — two registries/sources now surface data they fetched and dropped
  (verified by a partitioned dropped-field/un-modelled sweep; the strict
  deserialized-but-dropped class was confirmed exhausted across infra and
  identity/breach modules first).**
  - **`austlii` emits every fetched court/legislation reference, not just the first
    10.** The request asks AustLII for `results=20` and `extract_case_links` applies
    no cap, but the emit loop took only `.take(10)` — silently dropping up to half a
    subject's Australian court-judgment / legislation `Url` hits. A hoisted
    `MAX_DOCS = 20` now drives the request param, the take, and the org summary, so
    every reference becomes a `court-judgment` `Url` (no-omission directive). The
    emission was refactored into a pure `build_entities` and unit-tested.
  - **`wigle` now emits each WiFi AP's OWN observed position and stops mislabelling
    it.** The WiFi geo path built its only `Coordinates` from the QUERY centre and
    tagged every returned BSSID with `coordinates = <query point>`, using each AP's
    real `trilat`/`trilong` only as a ranking distance — while the cell/BSSID paths
    already emit per-record coordinates. The densest WiGLE source was discarding its
    own geoint. A new pure `wifi_ap_entities` fixes the BSSID coordinate to the AP's
    own trilaterated position and emits each located AP as a first-class
    `wifi-observed`/`geoint` `Coordinates` node (AU-state tagged, null-island/`0,0`
    rejected via `geo::is_valid_coords`). Unit-tested.
- **Execution-order perfection: the primary search-engine pass now schedules
  reliable/proven engines FIRST under the concurrency limit.** The primary pass
  fans out to engines `ENGINE_CONCURRENCY` (6) at a time, but iterated `ENGINES`
  in raw declaration order — and the reliable core (`metager`/`swisscows`/
  `dogpile`) is declared *late*, so it never made the first concurrency batch and
  was the first cut when the per-query deadline fired. A new pure
  `order_engines_for_primary` floats the reliable core plus every engine PROVEN
  productive this run (`ever_hit`, the same liveness signal the pivot pass already
  trusts) to the front, so under a tight budget the engines whose results actually
  land fill the early slots. A stable partition (declaration order preserved within
  each group); the batch is still name-sorted downstream, so only *which* engines
  complete under a deadline changes, never the persisted result order. This serves
  both directives at once — perfected execution order AND maximised free scraping
  under the same budget — with no added requests. Unit-tested (reliable/proven
  float first, partition holds, declaration order preserved, empty sets are a
  no-op).
- **Adversarial-discovery sweep — eight code-grounded potentiations (every one a
  field the engine already fetched/produced but dropped, or a free signal in reach).**
  - **`breach_rich` no longer poisons the graph with absence/redaction markers.**
    The shared rich-detail pass minted `Organisation`/`Address`/`Username`/`Other`
    nodes from a SQL-NULL `\N` or a provider redaction placeholder
    (`UPGRADE_TO_SEE_FULL`/`REDACTED`) — two records each carrying `\N` in `company`
    would both yield `Organisation("\N")` and falsely co-occur. A new
    `is_absent_marker` (`is_null_sentinel` ∪ `is_placeholder_secret`) now guards
    every value-bearing loop (name/org/device/social/address + catch-all). Highest
    groundedness; fires for every breach provider that routes through the pass.
  - **`abn_lookup` stops truncating the flagship AU government register.** Name
    matches were capped at 10 and trading names at 5 against a no-server-cap ABR
    endpoint; both now use named ceilings (`MAX_NAME_HITS=100`,
    `MAX_TRADING_NAMES=25`) matching every sibling AU register — no ranked result
    omitted.
  - **`search_engines` now mines the profile-root hosts it already dorks.** The
    `is_social_host` allow-list omitted a dozen hosts whose first path segment IS
    the handle (`gitlab.com`, `bitbucket.org`, `t.me`, `vk.com`, `ok.ru`,
    `keybase.io`, `about.me`, `dev.to`, `twitch.tv`) — the query ladder asked
    engines for them, but every returned handle was discarded before any
    Username/cross-platform-pivot/confirmed-profile/display-name extraction.
    Navigation-prefixed hosts (steam/stackoverflow/gravatar) deliberately excluded.
  - **AU-106 (shared-device identity) now consumes the breach device signals it was
    starved of.** Hardware serials / IMEIs (`imei`/`serial`/`serial_number`/
    `device_serial`) are re-typed from inert `Other` to first-class `DeviceId`
    (and added to `RICH_DETAIL_SKIP` so no duplicate `Other` leaks), and the rule
    now also links on a stealer-logged router BSSID (a `device`-tagged
    `MacAddress`) — gated so a LAN/Wi-Fi MAC never links strangers. A shared
    globally-unique IMEI/serial or router BSSID across ≥2 accounts is the strongest
    single-device co-location proof. Well-known BIOS/SMBIOS placeholder serials
    (`To Be Filled By O.E.M.`, `System Serial Number`, `Default string`, …) and
    trivial all-zero/broadcast MACs are rejected at the producer
    (`is_placeholder_fingerprint`) so a non-unique placeholder can never link two
    unrelated machines.
  - **`trove_au` emits Url sources for all 20 fetched articles** (was `take(10)`
    against an `n=20` request — half the dated newspaper-mention pivots were
    dropped), and carries each article's publishing-masthead id (`titleId`) as
    `masthead_id` provenance.
  - **`netlas` surfaces three `fields=*` fields it decoded and dropped**: the SSL
    certificate's issuing CA (`ssl_issuer`), the HTTP page `<title>` (`http_title`,
    often the owning org/product), and the HTTP `status_code` (`http_status`) — all
    folded onto the IP entity's evidence. The post-decode body was refactored into
    a pure, unit-tested `build_entities`.
  - **`gravatar` carries the owner's self-asserted link label** (`UrlEntry.title`,
    e.g. "Blog"/"Portfolio") as `link_title` evidence on each personal-URL entity
    (was deserialized then dropped).
  - **`produces()` declarations corrected to match emissions** (graph-observability
    accuracy): `crtsh` declares the issuing-CA `Organisation` it emits;
    `oathnet_pro` declares the `ApiKey`+`CryptoAddress` its shared key-harvest path
    emits; `see_know` adds the `CryptoAddress` it was missing.
  All eight are offline, deterministic, and regression-tested; surfaced by a
  multi-modal finder sweep with per-finding adversarial verification against the
  real code and the architecture invariants.
- **Two new correlator rules + one potentiation mine breach data the engine already
  held but never synthesised.**
  - **AU-107 — subject's breach-stated employer/affiliation.** A breach/stealer
    record's `company`/`employer` field becomes a `breach`-tagged `Organisation` at
    0.50 — below AU-022's 0.60 co-location gate, so it was never named. AU-107 names
    each distinct breach-stated employer with the source(s) asserting it (Medium for
    one source, High for ≥2 independent) — the people-centric, stated-relationship
    complement to the registry corporate links. Keys on the `breach` tag, requires
    a real name, de-dupes by canonical name, runs on the confirmed view.
  - **AU-108 — breach-listed cross-platform handle footprint.** `breach_rich` mints
    `platform:handle` Usernames (`twitter:alice`, `telegram:…`) that were only
    merged, never reported. AU-108 fires when breach data lists the subject's
    accounts across ≥2 DISTINCT platforms (allow-listed to breach_rich's set, so an
    epieos `google:<id>` is ignored) — a stated footprint to corroborate against
    live discovery (Medium).
  - **AU-101 now counts phone/email facets from breach evidence ATTRIBUTES**, not
    only first-class entities — a record carrying the subject's phone/email in an
    attribute that never became its own entity now contributes its facet (counted
    once per class, no double-count), so an attribute-only footprint can reach the
    resolution threshold.
  All wired into RULES with firing + precision tests.
- **`epieos` surfaces the Google account id as a pivot (`google:<id>` Username),
  not just an evidence attr.** The id was deserialized, tagged `google-account`,
  and confined to evidence — now it is a first-class `Username` (the
  `platform:handle` convention breach_rich/keybase use) that the cross-platform
  username rules can link on. Regression-tested.
- **`hibp` attaches the per-breach FULL-FIDELITY detail to the EMAIL entity, not
  only the derived Domains.** The pure `breach_evidence` (description, dates, logo,
  data classes) and `tag_breach_quality` (`breach-fabricated`/`breach-sensitive`/…)
  helpers were applied only to the derived `Domain` entities, so an email scan —
  the common case — dropped the rich per-breach record. They are now applied to the
  email entity too (the summary evidence stays the headline; these add the detail).
- **AU government-register extraction depth — four registries now emit data they
  fetched and dropped (the no-omission directive).**
  - `qld_cadastre` emitted only the FIRST intersecting parcel (`features.next()`),
    silently dropping the rest at a boundary / strata / stacked-cadastre point. It
    now emits every parcel (bounded), so each lot/plan survives (the engine's
    value-merge unions the per-parcel `lotplan:` tags).
  - `au_unclaimed` parsed `SenderName` — the employer/estate/insurer that LODGED
    the money — into evidence and dropped it, leaving its own T1591.002 Business
    Relationships promise unfulfilled. It now mines the sender for company names
    and emits each as a `sender-company` Organisation that pivots into
    abn_lookup/opencorporates.
  - `asic_business_names` read `BN_STATE_OF_REG` into evidence but, unlike every
    sibling AU registry, never turned it into geo. It now emits a `"{state},
    Australia"` Address tagged `au-state`/`country:AU` so the jurisdiction reaches
    the AU geo correlators.
  - `asic_persons` built register Addresses with no `au-state`/`country:AU` tag and
    no Coordinates. They are now jurisdiction-tagged and inline-geocoded (offline
    gazetteer), so register addresses enter the AU geo correlators like every other
    AU module.
  All four are struct-field-grounded, deterministic, and regression-tested.
- **New correlator rule AU-106 — a shared device fingerprint links accounts to one
  controller.** The device-level analogue of AU-047 (reused secret) and AU-048
  (shared key): a hardware/machine fingerprint (`hwid`/`machine_id`, surfaced as a
  `DeviceId` by the breach/stealer rich-detail extractor) recorded against ≥2
  DISTINCT identities means those accounts were used on the SAME physical machine —
  almost certainly one person. A stealer log captures every credential saved on one
  machine, so the fingerprint ties the owner's otherwise-separate accounts together;
  the same fingerprint across two breaches ties the machine's user across them. This
  `DeviceId` shape was produced all along but no rule consumed it for identity.
  Precision gates mirror AU-047/048: the fingerprint must be substantial (≥12 chars
  — a real hardware id, not a short/generic hostname like `USER-PC`), the accounts
  must fold to ≥2 DISTINCT canonical handles (so an email and its matching username
  from one record can't self-fire), and it runs on the confirmed (candidate-filtered)
  view so a co-occurrence stranger's machine never links the subject. High (not
  Critical) — a household/shared machine is a rare confound. Regression-tested
  (fires on a shared hwid across two handles; rejects a short hostname; rejects an
  email+matching-username from one record).
- **`see_know` breach/stealer hashes now get the same offline hash intelligence as
  DeHashed/OathNet.** Its credential path minted a bare `Password` entity for a
  leaked hash and stopped there, while the sibling pools classify and crack it. It
  now applies `util::hashcat`: a hash value gains `hash:<algo>` + `crackable:fast|slow`
  tags, an appended salt is flagged `salted`, and a common-password digest is
  reverse-looked-up offline (`crack_common`) — surfacing the recovered plaintext as
  a first-class `Password` node tagged `cracked`/`from-hash`. Pure, no network, no
  GPU (Termux-safe); a plaintext password is unaffected (`identify_hash` → `None`).
  Regression-tested (md5 of a common password → algorithm/crackable/cracked tags +
  the recovered plaintext; a plaintext password gains no hash tags).
- **`trove_au` now emits each newspaper article as a pivotable `Url` source instead
  of dropping it.** `TroveArticle` deserialized `id`/`title_id`/`snippet`/`url` but
  the module folded only the first five headlines into one org-evidence attribute
  and threw the rest away — including the direct Trove article link. Each article's
  `url` is now a `Url` entity tagged `trove`/`newspaper-archive`/`source-document`,
  carrying the title/date/snippet/id on its evidence (the no-omission directive), so
  a dated Australian newspaper mention becomes a navigable, correlatable artifact.
  Capped, http-only, deduped, deterministic. The extraction was refactored into a
  pure `build_entities` and unit-tested (org + per-article Url, dedup, url-less
  skip, no-hits empty).
- **`hlr_cnam` now preserves the two phone fields the providers returned and it
  dropped (the no-omission directive).** `HlrResp.msisdn` — the HLR provider's
  AUTHORITATIVE canonical international number, which can differ from the queried
  local-format number — and `CnamResp.number` — the exact PSTN number CNAM resolved
  the subscriber name against — were both deserialized and silently discarded. The
  msisdn is now carried as `msisdn` evidence on the verified phone (so the
  provider-normalised form survives), and the resolved number as `cnam_number`
  evidence on the subscriber `Person` (tying the name to the precise number). The
  inline extraction was refactored into pure `build_hlr_entities`/`build_cnam_person`
  helpers (matching `numverify`'s convention) and unit-tested.
- **Domain seeds get a progressive subdomain-walk dork.** Subdomain discovery rode
  on a single `site:{v} -site:www.{v}` dork; a second dork now also excludes the
  common subdomains (`mail`/`blog`/`shop`/`m`), pushing the engine to reveal the
  long-tail subdomains the first never reaches — a classic free SERP subdomain
  walk, static and deterministic. Query-shape tested.
- **Search snippets are now mined for the subject's OTHER profile links, not just
  emails/phones/addresses.** `build_entities` already extracted Email/Phone/
  Address/Org/ABN from each result's title+snippet but harvested usernames only
  from the result URL — so a snippet that named the subject's other profiles
  ("also at `https://github.com/alice`") dropped them. A new pure
  `extract_urls_from_text` pulls `http(s)` URLs embedded in the snippet body, and
  each is mined two ways: (a) any whose path carries a target term becomes a `Url`
  pivot — a confirmed profile (handle path == seed on a canonical host) at high
  confidence, every other path-match candidate-quarantined (stricter than the
  result-URL path, so an incidentally-linked page can't masquerade as the
  subject's own); (b) the social-host ones additionally run through the SAME
  `is_social_host` + `score_username` gate the result-URL path uses (weak
  term-overlap scores stay candidate-quarantined), emitting `Username` entities.
  Both tagged `snippet-link`, deduped against the result-URL pass. Zero extra HTTP
  — the snippet is already fetched — and no new confirmed-tier noise surface
  (identical/stricter precision gates). New unit test (URL extraction + punctuation
  trim + dedup) and wiring tests (snippet GitHub handle + confirmed-profile Url
  surfaced; non-matching link rejected; non-canonical path-match stays candidate);
  full gate.
- **Free search-engine scraping maximised — denser pages, deeper paging, the
  federated social cluster, and every proven-live engine in the pivot/recycle
  passes.** Four keyless, deterministic, Termux-safe levers on `search_engines`:
  (1) the per-engine result ceiling rose 20→30 to KEEP rows already on the page —
  `bing`/`google`/`yahoo` already request 30 per page, so the old cap fetched then
  discarded 10 at zero HTTP cost (`google &num`/`yahoo &n` lifted to 30 with their
  pagination offsets kept in lockstep); (2) `MAX_PAGES` 2→3 pulls one more page
  from the six engines with a PROVEN paginator (the keyless `paginate: None`
  engines are untouched), each extra page self-clamping to the deadline so deeper
  paging can never overrun the Termux time budget; (3) a federated/new-social
  `site:bsky.app OR site:mastodon.social OR site:threads.net` dork added to the
  Username, FullName and Email-local-part ladders, with those hosts added to
  `SOCIAL_HOSTS` so the pivot/confirmed-profile passes mine their handles; (4) the
  second-order username-pivot and entity-recycle passes now fan out across the
  reliable core PLUS every engine PROVEN LIVE this scan (via the session
  `ever_hit` liveness map), instead of only three static engines — multiplying
  cross-platform linkage through the engines that actually produced results,
  bounded by a fan-out cap and the per-request deadline. New deterministic unit
  test (`pivot_engine_set` union/sort/cap/fallback) and the full gate.
- **Cross-representation credential linking — a plaintext leaked in one breach now
  bridges to the SAME password leaked as a HASH in another.** AU-105 recomputes the
  MD5/SHA-1/SHA-256/SHA-512 digests of every UNCOMMON plaintext password already in
  hand (`util::hashcat::digests_of`) and, in a second pass, unifies a leaked hash
  that matches one of them with that plaintext's reuse group. So an account whose
  breach leaked the cleartext and an account whose breach leaked only the digest of
  the same password are recognised as one reused secret across both breaches
  (graded High — the plaintext is known). It is a dictionary match (MITRE ATT&CK
  T1110.002) over the scan's OWN recovered secrets — never a brute force, no GPU,
  no network, adding ZERO query noise (pure offline synthesis of results already
  collected). Common passwords are excluded from the bridge (a shared
  `md5("password")` is a collision, not a link), so the synergy only strengthens
  precise links. Termux aarch64 / no-root safe. Proven by new tests (the
  plaintext→hash bridge spanning two breaches, `digests_of` round-trip,
  case-insensitive common-password membership) and the full gate.
- **Offline hash intelligence (`util::hashcat`) — a "hashcat-lite" that empowers
  raw breach hashes without a GPU, a network call, or root (Termux aarch64 safe).**
  A new shared module turns a raw password digest into intelligence three ways:
  (1) `identify_hash` classifies the algorithm and crackability (fast unsalted
  MD5/SHA-family ≈ plaintext vs a slow adaptive KDF) and `is_salted` flags an
  appended salt — the single definition every breach provider now shares (OathNet's
  classifier delegates to it); (2) `crack_common` resolves a fast unsalted digest
  to its plaintext when it is the MD5/SHA-1/SHA-256/SHA-512 of a common password,
  by a reverse-lookup table built once offline at first use (only already-public
  weak passwords resolve; salted/strong hashes return `None`); (3) `is_common_collision`
  is the noise-reduction corollary. The recovered plaintext is surfaced as a
  first-class node by **DeHashed and OathNet** (the hash entity tagged
  `hash:<algo>` / `crackable:fast|slow` / `salted` / `cracked`), and — crucially —
  **AU-105 (credential-reuse identity link) now skips a hash whose plaintext is a
  common password**: the same `md5("password")` recurs for unrelated people, so
  grouping on it would manufacture false reuse links. Hash intelligence here both
  enriches (exposure) and DE-NOISES (precise linking). Conceptually MITRE ATT&CK
  T1110.002 (Password Cracking) applied to reconnaissance T1589.001 (Credentials).
  Proven by new unit tests (algorithm classification, salt detection, a full
  round-trip of every listed password across all four digests, the famous
  `md5("password")`, the DeHashed crack→plaintext path, and the AU-105
  common-collision skip) and the full gate (clippy `-D warnings`, 4173 lib tests).
- **DeHashed now surfaces the FULL breach record — including the password hash —
  for entity linking and reverse search.** Previously the module bound only
  `database_name` and dropped every credential under a "no-credentials-in-evidence
  invariant", so the very data DeHashed exists to provide (the `hashed_password`
  digest and plaintext `password`) never reached the graph — defeating hash-based
  entity linking and reverse search. DeHashed now extracts every record to parity
  with `oathnet_pro` / `see_know`: identity (email / username / phone / Person /
  IP), the credential secret as first-class `Password` entities (the hash tagged
  `password-hash`, a reverse-searchable node), and the full long tail via the
  shared `breach_rich` pass — with EVERY raw field preserved verbatim on each
  record's evidence (nothing redacted or truncated). v2's array-wrapped fields
  (`"email": ["…"]`, multi-value records) are handled: every value surfaces, and a
  single hash flattens to the bare digest so it matches the same hash from another
  provider. A broad `name` search's same-name strangers are demoted to quarantined
  `candidate` leads (retained for transparency, never the subject), exactly as the
  other breach pools do. **AU-105 (credential-reuse identity link) now also reads
  the `hashed_password` key**, so the same digest from DeHashed and OathNet groups
  as one reuse signal — cross-source hash linking. Proven by new unit tests
  (identity+hash surfaced and carried as the AU-105 attribute, stranger
  quarantine, multi-value arrays) and the full gate (clippy `--all-targets -D
  warnings`, 4166 lib tests).
- **Shared maximum-raw-data extractor brings OathNet stealer logs to parity with
  SeekNow (`util`-style functional refactor).** SeekNow's verbose "long tail"
  pass — device fingerprints (HWID / MAC / hostname → `DeviceId`/`MacAddress`),
  employer, extra social handles, multi-part addresses, and a catch-all that
  turns *every remaining scalar field* into an `Other(field)` node — was
  module-private to `see_know`, while `oathnet_pro`'s stealer path surfaced only
  Url / Email / Domain / Credential and left the defining payload of an
  infostealer log (the captured machine fingerprint and detail tail) buried in
  evidence. That pass is now a single shared, source-parameterised
  `modules::breach_rich::extract_rich_detail`: `see_know` delegates to it
  (byte-for-byte identical output — its full test suite is unchanged) and
  `oathnet_pro`'s stealer extractor now calls it too, so both paid pools mine the
  identical field set and can't drift. The deliberate stealer-URL policy is
  preserved on both sides (the capture URL stays a `Url`; its host is **not**
  minted as a `Domain`, avoiding the platform-infrastructure expansion and
  cross-victim false-correlation that was empirically rejected). Proven: shared
  unit tests (device fingerprints as non-`breach` context, catch-all vs noise
  suppression, source-tag parameterisation), a new oathnet stealer
  characterization, see_know's unchanged suite, and the full gate (clippy
  `--all-targets -D warnings`, fmt, 4145 lib tests).
- **Fully autonomous investigation — no seed input required.** The New Scan UI no
  longer forces the operator to choose a target: a new "Auto-Investigate" button
  (and `POST /api/v1/scan/auto`) ranks every entity the platform has already
  collected by cross-investigation leverage, auto-selects the highest-value
  pivotable identifier, and runs a comprehensive scan on it — zero input. Falls
  back to `HUNTSMAN_DEFAULT_SEED`, and returns a clear 422 with guidance (never an
  error) only when the intelligence base is genuinely empty. The manual seed form
  remains as an optional refinement, never required. The seed selector
  (`autonomous_seed`) is pure and deterministic.
- **Single-signal best-location estimate — a headline geolocation answer for
  every scan.** The cross-class synergy fix (AU-059) only fires on ≥2 coordinates
  across ≥2 source classes, so the COMMON single-signal scan got no headline
  location. `best_au_location_estimate` now always returns the finest AU fix
  available, by precedence: multi-source synergy → most-confident confirmed
  coordinate → name-matched address postcode centroid → breach/register postcode
  — each with its precision radius, nearest locality, state, and the basis it was
  derived from. Surfaced in the dossier's GEO INTELLIGENCE as the single-signal
  fallback so every located subject gets an Interpol-style "where, and how
  precisely" answer. Pure and deterministic. Also wired into the API/JSON geo
  export (`best_location`), so the web/JSON surface carries the same headline fix
  (with `basis`, `radius_km`, `locality`) when AU-059 doesn't fire — not just Null.

### Fixed
- **`wigle` geo/SSID search no longer reports a known, already-documented
  WiGLE account-throttle (unverified email) as a module error.** WiGLE
  answers those two endpoints with HTTP 412 rather than a 200 with a
  thinner result set when the configured account's email isn't verified —
  now handled the same way every other "WiGLE said no" outcome already is:
  a clean zero-yield result, with the account's unverified state recorded
  for `hse doctor` / `/api/v1/stats` as a side effect. The BSSID/detail
  lookup path was unaffected and needed no change.
- **The self-update mechanism can no longer wedge itself into a permanent
  "applying" state.** Two sites that record the outcome of a triggered
  update (success → restarting, failure → error) silently did nothing if
  the shared status mutex was ever poisoned, unlike the check-and-claim
  gate which already recovers from poisoning — a poisoned mutex would have
  left every future update trigger permanently rejected with no
  diagnosable error. Both sites now use the same poison-recovery policy.
  Regression test `set_phase_recovers_from_a_poisoned_mutex`.
- **`name_intel`'s ATT&CK mapping no longer silently inherits an incorrect
  category default.** The module never overrode `attack_techniques()`,
  so it inherited the full People-category pair — over-claiming "Identify
  Roles" (this module has no role/organisational logic anywhere) while
  never crediting "Email Addresses" for the speculative emails it derives
  from a name. Now declares the same precise pair already used by `pgp`
  for an identical Person+Email shape. Regression test
  `attack_techniques_matches_produced_entity_kinds`.
- **`sourceforge_user`'s ATT&CK mapping now covers every entity kind the
  module actually produces.** The fifth instance of the same
  under-declared-coverage gap: its override already correctly credited the
  Username lookup and bio-extracted emails, but silently dropped the
  technique for the Person and Address/Coordinates entities it also builds
  from a profile's display name and self-reported location. Regression test
  `attack_techniques_covers_every_entity_kind_this_module_produces`.
- **`mastodon_user`'s ATT&CK mapping now covers every entity kind the
  module actually produces.** Unlike the sibling fixes above, its override
  had the correct base technique ("Social Media," since Mastodon genuinely
  is social media) but was still missing coverage for the Person and
  Address/Coordinates entities it also builds from a display name and a
  self-reported location field. Regression test
  `attack_techniques_covers_every_entity_kind_this_module_produces`.
- **`codewars_user`'s ATT&CK mapping now covers every entity kind the
  module actually produces.** The third instance of the same
  replace-instead-of-extend gap: its override declared only "Code
  Repositories," silently dropping the technique for the Person,
  Organisation, and Address/Coordinates entities it also builds from a
  Codewars profile's real name, clan, and city. Regression test
  `attack_techniques_covers_every_entity_kind_this_module_produces`.
- **`dockerhub_user`'s ATT&CK mapping now covers every entity kind the
  module actually produces.** The same replace-instead-of-extend gap just
  fixed in `github_user`: its override declared only "Code Repositories,"
  silently dropping the technique for the Person, Organisation, Address/
  Coordinates, and Email entities it also builds from a Docker Hub profile's
  real name, company, location, and Gravatar email. Regression test
  `attack_techniques_covers_every_entity_kind_this_module_produces`.
- **`github_user`'s ATT&CK mapping now covers every entity kind the module
  actually produces.** Its override correctly swapped the Social category's
  default "Social Media" technique for the more precise "Code Repositories"
  one, but replaced the entire default array in doing so — silently dropping
  the technique for the Person, Email, Organisation, Address/Coordinates,
  and Credential entities it also builds. Every admitted entity is stamped
  with the technique(s) that collected it, so this was a real per-finding
  MITRE-provenance gap, not just documentation. Regression test
  `attack_techniques_covers_every_entity_kind_this_module_produces`.
- **`email_parse`'s derived `Username` entities are now emitted in a
  deterministic order.** The set of candidate username spelling variants
  (detagged, digit-stripped, collapsed, split, plus initial-blend forms for
  a two-token local part) was deduplicated via a `HashSet` and iterated
  straight into the emitted entity list with no sort step — the same
  determinism-leak class already fixed for `reddit_user`, `hacker_news`, and
  `web_crawler`. A project-wide sweep confirms this was the last remaining
  instance. Regression test
  `username_candidates_emerge_in_deterministic_sorted_order`.
- **`web_crawler`'s Domain, Email, Tracking-ID, and Phone entities are now
  emitted in a deterministic order.** Five separate `HashSet`-backed
  aggregations (subdomains, external domains, emails, web-analytics tracking
  IDs, phone numbers) from a page crawl were each iterated straight into the
  emitted entity list with no sort step — the same determinism-leak class
  just fixed for `hacker_news`, but at five sites in one function instead of
  one. All five now emerge sorted, matching the pattern the same function
  already used for its framework/page-type attributes. Regression test
  `build_entities_emits_domains_emails_tracking_ids_and_phones_sorted`.
- **`hacker_news`'s Algolia-submissions domain lookup now emits `Domain`
  entities in a deterministic order.** The distinct domains linked from a
  user's Hacker News submissions were deduplicated via a `HashSet` and then
  walked straight into the emitted entity list with no ordering step, so
  identical submissions could legally produce differently-ordered entities
  (and a differently-ordered live event stream) across separate runs of the
  same scan, purely from the process's randomised hash-iteration order — the
  same determinism-leak class already fixed for `reddit_user`. Domains now
  emerge sorted. Regression tests
  `algolia_domain_entities_emits_all_distinct_domains_deterministically`,
  `algolia_domain_entities_no_urls_yields_nothing`.
- **A search-derived username matching only a subject's surname substring no
  longer reaches PROBABLE confidence and gets recycled into a further
  search.** A real self-test scan showed an unrelated business's Facebook
  slug (named after the same-spelled suburb as the subject's surname)
  reaching the correlator's highest-confidence identity cluster, because a
  compound candidate's other, unrelated parts were never checked against
  the subject's actual name before the match was treated as strong evidence
  and used to launch further searches. A genuine `firstname_lastname`-style
  handle is unaffected. Regression tests
  `score_username_business_slug_containing_the_surname_stays_candidate`,
  `score_username_genuine_firstname_lastname_handle_still_reaches_probable`.
- **The `greynoise` module now uses a configured `HUNTSMAN_GREYNOISE_KEY`
  instead of silently ignoring it.** The module always called GreyNoise's
  free Community endpoint, even when a key was configured — an operator
  who registered for one got no additional capability. It now upgrades to
  GreyNoise's keyed `v3/ip` lookup when a key is present, matching the
  Shodan module's existing free/paid pattern. Regression tests
  `paid_response_deserialization`,
  `paid_path_tags_seen_in_addition_to_the_shared_signal`,
  `paid_path_surfaces_a_seen_but_otherwise_unclassified_ip`,
  `paid_path_no_signal_at_all_yields_nothing`,
  `paid_path_still_yields_the_operator_organisation_pivot`.
- **`GET /scans/{id}/entities/filter` no longer leaks quarantined `candidate`
  entities.** Every other entity-listing surface (`/entities`, the CSV
  export, `report.json`, and the GEXF graph export) hides non-subject breach
  co-occurrence rows by default and only returns them with
  `?include_candidates=1` — but the filtered-view endpoint never applied
  that quarantine, so a caller could see a foreign breach victim's data
  simply by adding a `kind`/`min_confidence`/`q` query parameter. It now
  applies the same default-hide/opt-in behaviour as the other endpoints.
  Regression test
  `scan_entities_filter_quarantines_candidate_entities_by_default`.
- **The Exposure Index now recognises Wikidata's own date-of-birth spelling.**
  The Sensitive PII component scores a date-of-birth disclosure only for a
  fixed set of evidence-attribute spellings, which omitted the spelling the
  Wikidata module actually uses — so a subject's Wikidata-sourced date of
  birth silently contributed nothing to their exposure score. Regression
  test `sensitive_pii_recognises_wikidata_birth_date_spelling`.
- **The reconstructed timeline no longer silently drops account-creation,
  birth/death, profile-verification, and threat-intel first-seen dates that
  several modules already collect.** Eight evidence-attribute keys —
  including the account-creation family that left the documented
  `AccountCreated` timeline event kind completely unreachable — were never
  recognised by the timeline's date classifier, so an OathNet/StackOverflow
  account-creation date, a Discord-snowflake- or UUID-decoded creation
  timestamp, a Wikidata birth/death date, a Mastodon profile verification
  date, and an OTX pulse's earliest-report date all vanished from the
  chronology with no signal. All eight now appear. Regression tests
  `classify_maps_every_live_account_created_key_not_leaving_it_dead_code`,
  `classify_recognises_wikidata_and_mastodon_date_keys`,
  `reconstruct_surfaces_an_account_created_event_end_to_end`.
- **Resolving the "latest" scan no longer reports an empty store when the most
  recent completed scan is actually corrupted.** `hse export`/`diff`/`audit
  latest` and the SPA's "open latest scan" all resolve through a lookup that
  silently treated a database read error or a corrupted scan record the same
  as "no completed scans exist," so a genuinely corrupted latest scan
  produced a misleading "nothing to export" instead of a diagnosable error.
  It now surfaces the underlying failure, matching how looking up a scan by
  ID already behaves. Regression test
  `latest_completed_scan_errors_loudly_on_a_corrupt_row_instead_of_reporting_none`.
- **The store's owner-only permission lockdown now logs, rather than silently
  swallows, a failure.** `Store::open` restricts the database file (and its
  WAL/SHM siblings) to owner-only (0600) since it holds PII and harvested
  API keys, but discarded the result of that chmod with no diagnostic —
  unlike a nearby best-effort step in the same function, which already logs
  its failures. A failed chmod could silently leave the store at the
  process umask, often world-readable, with no signal. It now logs a
  warning naming the file. Regression test
  `restrict_to_owner_only_logs_when_a_chmod_fails`.
- **Storage reads now log a corrupted or schema-drifted row instead of silently
  dropping it.** Eight multi-row readers (`list_scans`, `correlations_for_scan`,
  `relations_for_scan`, `events_for_scan`, `entities_for_scan`,
  `entities_filtered`, and both `search_entities` code paths) discarded any row
  that failed SQL extraction or JSON deserialization with zero trace — unlike
  the single-row getters, which already surface the same failure as an error.
  Two shared helpers now log a warning naming the caller before dropping the
  row; the well-formed rows still come back exactly as before. Regression
  tests `deserialize_rows_drops_corrupt_json_but_logs_the_failure`,
  `collect_rows_drops_sql_errors_but_logs_the_failure`, and
  `list_scans_drops_a_corrupt_row_end_to_end_without_erroring`.
- **Curl-subprocess failures (see_know, oathnet) now report WHY, not just an exit code.**
  `CurlClient::exec` ran curl with `-s` (silent) but not `-S`/`--show-error`, so curl
  suppressed its own diagnostic text on failure alongside the progress meter — every
  `[seek_now] curl exited N` / `[oathnet] curl exited N` log line carried a bare numeric
  code with no indication of which host failed to resolve, connect, or verify. Added `-S`
  so curl's one-line diagnostic (`curl: (6) Could not resolve host: …`) is restored into
  `stderr`, which the existing failure branch already captures and reports — output shape
  is unchanged on success. Regression-tested against a network-unreachable target.
- **SeekNow embedded default key rotated** to the operator-supplied `seek-fd18f1db…` key,
  with the prior default demoted into the superseded-key chain so any env file carrying it
  upgrades in place on next run (no operator action needed). Not live-verified from this
  build environment — its own outbound network policy rejects `see-know.eu` independent of
  the key; verify with `hse doctor` on the operator's own device.
- **Bluesky, Reddit, Mastodon, Lobsters and Dev.to profile scans now surface every email
  and link in a subject's bio, not just the first five of each.** All five modules ran the
  same copy-pasted extraction that capped bio emails and URLs at five apiece — even though a
  link-tree-style bio routinely lists more, and the same engine already extracts emails from
  gist bodies and crawled pages without any cap. A shared, deduplicated URL extractor
  (`extract::urls`, mirroring the existing email extractor) now backs all five, and every
  distinct address and link is emitted (duplicates still collapse; ordering is
  deterministic). Regression test `urls_extracts_all_distinct_trimmed_in_order_uncapped`.
- **GitHub user lookups now emit every distinct commit-author email from the subject's
  public push events, not just the first 10.** Each address published in the subject's own
  commit author fields is a high-value real-email pivot, but the module deduplicated them
  and then kept only the first 10 — a cap the code comment admitted was merely "to keep a
  busy account bounded," even though the events endpoint is already limited to 30 events.
  Every distinct usable address is now emitted (GitHub's privacy/noreply placeholders are
  still dropped, never replaced with a placeholder; duplicates still collapse to one).
  Regression test `commit_email_entities_emits_every_distinct_email_not_a_capped_ten`.
- **GitHub user lookups now emit every one of the subject's published SSH public keys as a
  correlatable artifact, not just the first 10.** Each key was fingerprinted into a
  `Credential` entity so that the same public key found on two accounts merges into one
  artifact carrying both logins — the strongest cross-account link there is — but the emit
  loop stopped at 10, silently dropping the keys of anyone who has registered more. Every
  published key is now emitted (malformed key bodies are still skipped, never replaced with
  a placeholder); the human-readable evidence's true key count and sample are unchanged.
  Regression test `ssh_key_entities_emits_every_key_not_a_capped_ten`.
- **Shared-address and shared-phone associations (AU-049/AU-050) now reference every
  reachable email/phone handle, not just the first 8.** The correlation's linked-entity
  list capped the reachable handles at 8, so a large household or share-house with more
  than 8 associated email/phone identifiers at one residence or line dropped the rest from
  the finding with no indication. Every reachable handle is now referenced. Regression test
  `au049_references_every_reachable_handle_not_a_capped_eight`.
- **SEON now surfaces every distinct self-reported name, not just the first platform's.**
  When SEON reports a person's display name across several identity platforms (e.g. a
  nickname on one, a fuller legal name on another), the module emitted only the first and
  silently dropped the rest. It now emits one Person entity per distinct name, tagged with
  every platform that reported it (identical names dedup to one). Regression test
  `email_emits_a_person_for_each_distinct_reported_name`.
- **The entity filter/browse query now returns every matching entity, not a silent cap of
  500.** `GET /scans/{id}/entities/filter` applied a hardcoded `LIMIT 500` with no
  pagination, total, or truncation flag, so a scan whose filtered result exceeded 500
  entities silently hid the lowest-confidence matches — even though the facet counts beside
  the list reported the true larger number, and the unfiltered entity endpoint returns the
  complete set unbounded. The cap is removed; the result is fully ordered and complete.
  Regression test `entities_filtered_returns_the_complete_result_not_a_capped_500`.
- **Infostealer (ULP) logins are now recovered on username and IP-address scans, not only
  email/domain scans.** A stealer-log record's captured login (the compromised account for
  a URL) was promoted to a pivot entity only when the scan target was an email or domain —
  so a username scan (whose login is the email the handle maps to) or an IP scan (whose
  logins are the accounts compromised on that victim host) silently discarded it, storing
  not even an evidence trace. The login is now always stamped on the record evidence and
  promoted to a pivot on every target kind when it differs from the query. Regression test
  `ulp_recovers_the_login_on_username_and_ip_scans`.
- **Netlas now surfaces every SSL SAN domain and extracted contact email, not just the
  first 20/10.** The module aggregated and de-duplicated all certificate SAN domains and
  all cert/HTTP/WHOIS emails, then silently emitted only the first 20 domains and first 10
  emails — dropping the module's headline expansion pivots for a multi-SAN certificate or a
  host with many contacts. Both caps are removed; every unique record is emitted (BFS
  breadth is bounded by the engine, not this module). Regression test
  `build_entities_emits_every_unique_san_domain_and_email`.
- **The ACMA Radiocommunications Register and AHPRA practitioner-register scrapers now
  return every matching record, not just the first 20.** Both parsed the full result
  table but then emitted only the first 20 rows — a silent client-side cap with no
  server-side page limit and no operator signal — so a large multi-licence organisation,
  a coordinate-radius licence search, or a common-surname health-practitioner search
  silently dropped every result beyond the 20th. They now emit every parsed row (the
  response body is already size-bounded upstream). Regression tests
  `build_licensee_entities_emits_every_parsed_row_not_just_20` and
  `build_practitioner_entities_emits_every_parsed_row_not_just_20`.
- **DeHashed now recovers an email mis-stored in the password field instead of dropping it.**
  When a breach record puts an email in the `password` slot (a common quirk), DeHashed
  previously minted nothing — while the oathnet_pro and see_know breach parsers both recover
  it as an email lead. DeHashed now does the same (emitting it as an `Email` tagged
  `recovered-from-password` rather than as a password, which would forge a reused-secret
  link). Regression test `email_in_the_password_slot_is_recovered_as_an_email_lead`.
- **`to_e164_au` no longer fabricates an Australian number from a foreign one written in
  the `61…` international form.** The AU-local branch already rejected a leading-zero number
  whose trunk digit isn't a real ACMA lead (2/3/4/5/7/8), but the equivalent `61`+9-digit
  branch only checked for a leading zero — so a foreign national number with an invalid AU
  lead (e.g. a French mobile written `61612345678`) was re-typed as `+61612345678`. Both
  branches now apply the same trunk-digit gate. Regression test
  `bare_61_prefix_requires_a_real_au_trunk_digit`.
- **Email addresses with a `%` in the local part are no longer truncated.** The two
  non-regex email byte-scanners (`page_emails` and the web crawler's) stopped scanning the
  local part at a `%`, even though the canonical email regex includes it — so
  `with%percent@example.com` was carved down to `percent@example.com`. Both now accept `%`,
  matching the canonical local-part class. Regression tests
  `page_emails_keeps_a_percent_in_the_local_part` and
  `email_extraction_keeps_a_percent_in_the_local_part`.
- **Cross-scan history links are no longer dropped when one partner's value is a substring
  of another's.** The idempotency probes that decide whether an entity already carries a
  co-occurrence or relation-recall link matched the partner (and relation kind) as a bare
  substring of the stored summary, so an entity already linked to `alice2` was treated as
  already linked to a new partner `alice`, and the genuine `alice` link was never attached.
  The probes now match the delimited token the summary actually writes (the backtick-wrapped
  partner and paren-wrapped kind), so only the exact partner/kind counts. Regression test
  `idempotency_probes_match_the_delimited_partner_token_not_a_substring`.
- **The SeekNow stealer parser no longer mints non-web URIs as URL entities.** It accepted
  any stealer `url` field of length ≥ 4 as a `Url`, while the equivalent oathnet_pro stealer
  parser requires an `http(s)` scheme and a dotted host — so a native-app URI or scheme-less
  fragment became a bogus URL node that then misdirected crawl/DNS/certificate expansion. It
  now applies the same scheme+host gate as its sibling; the paired `username@url` credential
  is still captured (a login for a native surface remains a real credential). Regression test
  `extract_entities_rejects_non_web_stealer_url_but_keeps_the_credential`.
- **Five more modules no longer over-claim MITRE ATT&CK T1589.003 (Employee Names).**
  `streaming_probe`, `gaming_profile`, `discord_snowflake`, `structured_id`, and
  `fediverse` inherited the Social category's default technique set including Employee
  Names, but none emits a real-name Person entity, so every finding falsely claimed a
  gathered name. Each now declares its real collection: the three handle/platform modules
  map to `T1593.001` (Social Media); `fediverse` adds `T1589.002` (it emits profile
  emails); and `structured_id` — an offline structured-ID decoder whose signal is the
  generating machine's MAC address in a UUIDv1 — maps to `T1592.001` (Host Hardware),
  dropping the social-search techniques entirely. Pinned by the
  `attack_overrides_attribute_collection_modules_precisely` guard.
- **PGP-key identity linkage (AU-042) no longer fuses two distinct keys' emails into one
  owner, and no longer fires on a single address.** The rule collected every `pgp-linked`
  email in the scan and asserted, at High severity, that all of them belong to one owner —
  even when they were bound to different PGP keys (i.e. potentially different people) — and
  fired even for a single email ("links 1 email address to one owner"). It now partitions
  the emails by the key fingerprint each carries and emits one finding per key that binds
  two or more addresses, so each finding reflects exactly what one key proves. Regression
  tests `au042_does_not_fuse_emails_from_two_distinct_keys` and
  `au042_does_not_fire_for_a_single_pgp_linked_email`.
- **Cross-platform identity resolution (AU-046) no longer fuses unrelated strangers into
  an alias's identity.** The rule collected every platform-sourced email/name in the whole
  scan and attributed all of them, at High severity, to every alias — so a co-author's
  email from a different platform account, a second alias's identifiers, or a `noreply@`
  role mailbox were mis-merged into a person's resolved identity. It now resolves an alias
  only to identifiers its own account(s) published (those sharing a corroborating source
  with the alias) and excludes role mailboxes, matching the linkage the rule's
  documentation already described. Regression test
  `au046_resolves_only_the_alias_own_account_identifiers`.
- **`streaming_probe` no longer fabricates a high-confidence cam/adult identity from an
  unverified HTTP 200.** The webcam / fan-subscription / adult-video prober stamped a
  flat 0.92 confidence on every hit and asserted a sensitive identity (`cam-identity-exposed`,
  `subscription-platform-found`, `adult-profile-found`) on the subject even when the
  detection was a bare status-200 — which a soft-404, CloudFlare interstitial, or catch-all
  route returns for any handle. It now tiers confidence by detection rigour (0.92 for a
  body-verified hit, 0.74 for a status-only lead), tags each URL `verified-detection` or
  `weak-detection`, and only asserts the sensitive category-exposure tags when a
  body-verified hit backs them — mirroring the confidence tiering the sibling
  `username_search` already applies. Regression tests
  `detection_strength_tiers_status_only_below_body_verified` and
  `build_entities_tiers_confidence_and_gates_exposure_on_verified`.
- **The GEXF graph export no longer leaks quarantined candidate breach-victims, and no
  GEXF export can emit dangling edges.** The `/graph.gexf` API endpoint passed every
  entity — including quarantined `candidate` breach co-occurrence "strangers" — to the
  serializer, leaking a foreign breach-victim list under the subject's scan, while the
  CSV, `report.json`, and CLI GEXF exports all strip candidates by default. The API
  export now filters them by default (opt in with `?include_candidates=1`, matching the
  CSV endpoint). Separately, the GEXF serializer now emits a relation edge only when both
  of its endpoints are present as nodes, so a caller that passes a filtered entity subset
  (which the candidate-stripping exports do) can no longer produce an `<edge>` that
  references an undeclared node — previously the CLI GEXF export did exactly that,
  yielding structurally-invalid GEXF. Regression tests
  `gexf_drops_relation_edges_referencing_a_filtered_out_node` and
  `scan_gexf_quarantines_candidate_nodes_by_default`.
- **Infrastructure coordinates can no longer vote the subject's location or jurisdiction
  (`coord_state`, AU-099).** The subject's AU-state resolver `coord_state` (which feeds the
  AU-056/085/092/098 jurisdiction and residency rules) and the AU-099 reverse-geocoder
  admitted *any* confirmed coordinate, including bare IP-geo/hosting fixes that locate a
  datacentre or domain owner rather than the person — while every sibling location rule
  (AU-018/026/030, AU-052/053/059) already excludes them via `is_infrastructure_geo`, and
  the module's own doctrine section requires it. So a Sydney-datacentre server IP behind the
  subject's domain would assert NSW and manufacture a false "jurisdiction conflict" against
  the subject's real interstate address, and AU-099 would announce the datacentre as the
  subject's own GPS fix. Both rules now apply the `is_infrastructure_geo` guard. Regression
  tests `coord_state_excludes_bare_ip_geo_infrastructure_coordinate` and
  `au099_reverse_geocode_excludes_infrastructure_coordinates`.
- **The "best AU location" estimate now weights a coordinate by its own cross-class
  corroboration (AU-059).** The cross-seed geo-synergy fix — the source of the
  dossier's headline location estimate and the API's `best_location` fields — boosted
  each point's weight by a class-diversity bonus computed from the scan-wide distinct
  class count, applied identically to every point. A weighted geometric median is
  invariant to scaling all weights by one constant, so the bonus was a silent no-op:
  a coordinate corroborated by three independent collection methods was weighted
  exactly like a lone single-source point, contrary to the rule's stated intent. The
  bonus is now derived per point from that entity's own distinct orthogonal geo source
  classes, so better-corroborated coordinates genuinely pull the estimate toward them.
  Regression test `au059_class_diversity_bonus_is_per_point_not_a_global_no_op`.
- **`username_search` no longer over-claims MITRE ATT&CK T1589.003 (Employee Names)
  on its findings.** Every admitted entity is stamped with its producing module's
  ATT&CK Reconnaissance techniques as inline `attack:<ID>` tags, so the map's
  precision is the product's ATT&CK fidelity. The established convention is that a
  module claims T1589.003 (Employee Names) only if it emits a real-name `Person`
  entity — github_user, hacker_news, lobsters, nostr and reddit_user were all
  overridden to drop it for exactly this reason. `username_search` enumerates handle
  presence across 300+ sites and emits only `Url` and `Username`, never a `Person`,
  but was missed in that pass and inherited the raw `Social` default
  `["T1593.001", "T1589.003"]` — so every finding falsely claimed a name had been
  gathered. It now declares the precise `["T1593.001"]` (Social Media search only),
  pinned by the `attack_overrides_attribute_collection_modules_precisely` guard.
- **The web crawler no longer mines IP-literal / numeric-TLD / 1-char-TLD hosts as
  bogus email addresses.** `util::extract::host_has_alpha_tld` is the single-sourced
  definition of a valid email domain (≥1 dot, no empty label, a final label of ≥2
  ASCII letters), shared by the provider-field gate `looks_like_email` and the HTML
  byte-scanner `page_emails` so neither can admit an address the canonical `EMAIL_RE`
  would reject. A third copy of the byte-scan logic — `web_crawler`'s page email
  extractor — was overlooked and still used a weak `contains('.') && len > 3` gate
  (with a syntax check that validates dot placement but not the TLD), so
  `admin@10.0.0.1`, `user@host.123` and `user@host.c` each minted a bogus `Email`
  entity that then poisoned correlation (name/handle permutations, co-location and
  credential-reuse rules, the exposure index). `host_has_alpha_tld` is now public and
  the crawler routes through it, so all three admission paths share one gate.
  Regression test `email_extraction_rejects_ip_literal_and_numeric_or_short_tld_hosts`.
- **A common full name is no longer asserted as a confirmed identity merge (AU-081).**
  The free offline identity-bridge rule `AU-081` links two independently-sourced
  `Person` records that normalise to the same canonical name — but emitted
  `Severity::High` "records for the same individual" *unconditionally*, the one
  identity rule with no common-name discount. So two unrelated "John Smith"s (say
  a breach dump and a proxycurl profile — different source families, so the
  independence gate is satisfied) fused into a single asserted person,
  cross-attributing each stranger's evidence to the other: the highest-volume
  false-merge vector in person OSINT and the worst outcome for an evidentiary
  tool. It now applies the same `is_common` discount the kin rules already use
  (AU-051/AU-061/`derive_kinship`): a canonical name containing a common family
  token drops to `Severity::Medium` "a COMMON name many unrelated people share —
  a lead to VERIFY, not a confirmed merge", while a distinctive name keeps its
  High "same individual" bridge. The rule's docstring, which had falsely claimed
  the token-count floor excluded common first names, was corrected. Regression
  test `au081_common_name_is_a_medium_lead_not_a_high_assert`.
- **Three modules restored — two broken outright by upstream API drift, one
  spuriously tripping its breaker — all found by real live testing.** Driving a
  real seed of every target kind end-to-end surfaced three live faults no unit
  test could catch: **(1) HudsonRock** stealer-login lookup — Cavalier renamed its
  query parameter from `username` to `email`, so every login request returned
  HTTP 400 `"Email is required"`; the module (a free, keyless stealer source) was
  completely dead. Now uses `email=` (verified live: a known-infected address
  returns its stealer records). **(2) StackOverflow user search** — the hard-coded
  `filter=!9Z(-x.hbL` is now rejected with HTTP 400 `"Invalid filter specified"`,
  breaking every lookup; dropped it, since the API's default filter already returns
  every field the module reads (verified live). **(3) Bluesky user** — a
  non-existent handle answers with HTTP 400 `"Profile not found"` (not 404), which
  propagated as a module error and, after a few misses in a name scan's handle
  fan-out, tripped the engine's per-module breaker and suppressed Bluesky for the
  *real* handles too. Added `util::http::fetch_json_or_absent` (treats 400 **and**
  404 as the clean "no such resource" negative; 429/5xx still surface) and routed
  Bluesky through it. Each fix has a regression test (a testable URL/​fetch seam),
  and all three were re-verified live against the real endpoints.
- **Finalise no longer stalls on a rich name scan — the two `O(identities²)`
  pairwise-pathway sweeps are now bounded.** Live end-to-end testing (a real
  `full_name` seed) surfaced a scan taking 135–185 s and, on a cold/richer run,
  exceeding a 150 s external timeout. Phase timing pinned it to two finalise
  passes that each iterate every identity pair calling `disjoint_pathways_in`
  (depth-5, 4-path search): **AU-062** multipath corroboration
  (`multipath_corroborated_links`) and **AU-063** single-route gap detection
  (`single_route_identity_links`). A broad name scan derives HUNDREDS of
  name-permutation identity entities (~400 → ~80 000 pairs), so the sweeps ran
  ~45 s **each**. Both now share one deterministic `IDENTITY_PAIR_PROBE_CAP`
  (6 000 pairs): because `identity_uids` is sorted, the cap yields a deterministic
  prefix (byte-identical output preserved, unlike a wall-clock budget), and the
  signals are best-effort enhancement (corroboration boosts / the gap lead) whose
  output was already capped, so a bounded subset degrades gracefully. Measured:
  the combined pathway phase dropped **48 s → 8 s**, and it is now bounded
  regardless of identity count. A typical multi-source scan (≲110 identities) is
  still examined in full.
- **HTTP response-snippet buffers now bound peak memory against a single
  oversized chunk.** `error_snippet` and `read_body_capped` extended their buffer
  by the WHOLE streamed chunk and truncated *afterwards*, so a hostile upstream
  sending one multi-GB chunk was fully copied into RAM before the cap ever applied
  — a memory-exhaustion risk on a low-RAM Termux device, worst under the
  `username_search` 32-way probe fan-out. A shared `append_capped` helper now
  copies at most `cap - buf.len()` bytes, so the buffer is a real ceiling
  regardless of any one chunk's size.
- **Determinism + concurrency correctness — Netlas emits a stable JARM, and the
  per-host circuit breaker admits exactly one recovery probe.** (1) Netlas
  accumulated a host's JARM fingerprints in a `HashSet` but surfaced only one via
  `jarm_seen.iter().next()` — and `HashSet` iteration order is randomised per
  process, so a multi-JARM host emitted a *different* `jarm_fingerprint` between
  otherwise-identical runs, breaking the byte-identical-output guarantee. Switched
  to a `BTreeSet` so the lexicographically smallest fingerprint is chosen
  deterministically. (2) `util::circuit_breaker`'s `HalfOpen` state returned `true`
  for **every** caller, so once a host's cooldown elapsed, all concurrent requests
  were admitted at once — a thundering herd on a host that is very likely still
  down, instead of the single trial probe the design intends. `HalfOpen` now denies
  concurrent callers (exactly one probe in flight); `retry_at` doubles as a probe
  deadline so a probe whose outcome is never recorded self-heals into a fresh probe
  one cooldown later rather than wedging the breaker.
- **Export completeness — the dossier no longer silently drops entire entity
  kinds, and GEXF escapes two more injection points.** (1) The `--output dossier`
  renderer iterated a FIXED kind allowlist, so any entity whose kind wasn't listed
  — `cidr`, `ssid`, `tracking_id`, `crypto_address`, and every `other:<custom>` —
  never appeared in the operator's dossier, hiding real collected intel (a leaked
  crypto wallet, a captured SSID, a tracking pixel id). A pure `order_dossier_kinds`
  now renders the curated kinds first and then **every** remaining present kind in
  deterministic order, so the dossier is a complete view of the working set;
  headers were added for the four newly-surfaced kinds. (2) GEXF wrote the node
  `kind` attvalue and the `<description>` scan id UNESCAPED — an `Other(<custom>)`
  kind carrying `<`/`&`/`"` (data-derived) would break the whole `.gexf` in Gephi;
  both now pass through `xml_escape` (the node label, tags, and edge labels already
  did). The golden byte-stable test confirms no change for metachar-free output.
- **Engine finalise/dispatch robustness — a panicking correlation rule can no
  longer abort a scan, and a cache replay no longer feeds the circuit breaker.**
  (1) The authoritative finalise-time correlation pass ran `Correlator::run`
  *unguarded*, so a rule panicking on adversarial persisted data (a slice-index
  bug over a crafted entity) would unwind the whole finalise block — losing the
  terminal `ScanComplete` event **and** the API-key pool the scan harvested. It
  is now wrapped in `catch_unwind` (via `guarded_finalise_correlation`),
  degrading a caught panic to "no finalise correlations," exactly as the live
  incremental pass already does. (2) `finalise_module_result` recorded a
  circuit-breaker success on every `Ok(Ok(_))` — including inter-scan cache
  REPLAYS, which make no provider call. A replay spuriously clearing a failure
  streak the live calls earned this scan would mask a degrading provider (or
  reset a soft-trip countdown); replays now pass `from_cache = true` and skip the
  breaker's success path — a replay is neither success nor failure to the breaker.
- **No-fabrication gates on three breach/stealer pools — no more phantom
  subject-exposure claims.** Three paid/free intelligence sources minted
  subject-attributed findings without proving the record identified the subject:
  (1) **DeHashed** pushed a 0.88 `breach` "breach-presence headline" onto the
  engine's pre-seeded subject anchor from *any* non-empty response, so a broad
  `name:` query — which returns same-name STRANGERS — merged a false breach hit;
  the headline is now gated (mirroring `oathnet_pro::breach_parent_entity`): the
  loose `name` selector requires ≥1 row that actually matches the subject and
  counts only those rows, while the identity-exact selectors
  (`email`/`username`/`phone`/`ip`/`domain`) keep the server total. (2) **IntelX**
  runs `username`/`full_name` as an *unscoped text search* (a hit means a document
  merely contains the term), yet tagged the subject `breach` + `password-at-risk`
  whenever a `leaks` bucket appeared — fabricating a credential-exposure claim
  from a stranger's paste; text searches now withhold the strong exposure tags
  (emitting neutral `intelx-source:*` provenance instead), ride at lead confidence
  (0.55 vs 0.86), and carry an `intelx-text-match` marker. (3) **HudsonRock**
  admitted any dotted string as a victim-device IP (`!ip.contains('.')`), so a
  stealer log's LAN address (RFC1918/loopback/CGNAT) became a `geolocation-lead`
  fed to GEOINT; each candidate is now gated on `is_public_ip` (parses v4 **and**
  v6, rejects private/reserved), matching the gate `dehashed` already applies.
- **Serve-layer hardening — CSRF on every mutating endpoint, loopback-only debug
  logs, and a real autonomous-sweep de-dup.** (1) **CSRF:** every bodyless
  state-changing `POST` (`/update/trigger` — a binary self-update + `exec()` —
  `/scan/auto`, `/scan/auto/sweep`, `/scans/{id}/cancel|rerun`, `/radar`,
  `/radar/live`) was a CORS *simple request* with no preflight and no CSRF guard,
  so a page open in the same browser could drive them cross-site (`scans/import`
  already required the header, but nothing else did). A middleware now requires
  `X-HSE-CSRF` on every mutating method across `/api`; the SPA injects it
  transparently via a global `fetch` wrapper, and CLI/API clients send
  `-H 'X-HSE-CSRF: 1'`. (2) **Debug logs:** `GET /api/v1/logs` streams the
  TRACE-level ring buffer (scan targets + discovered PII) and lacked the
  `is_loopback()` gate the key-pool/settings endpoints carry — added, so a LAN
  bind no longer exposes it. (3) `scan_auto_sweep`'s target de-dup keyed on the
  per-call-unique `scan_id` (a silent no-op) — now de-dups on the `(kind, value)`
  target identity.
- **`raw_archive` inter-scan cache grew without bound — added pruning.** The
  cache ignored expired rows on lookup but never *deleted* them, and had no row
  cap, so scanning many distinct `(module, target)` pairs over time grew the
  table (and the DB/WAL) unbounded on a low-disk device — the very failure the
  `events` table already prevents via `prune_events`. A new `prune_raw_archive`
  deletes past-TTL rows and caps the newest `RAW_ARCHIVE_MAX_ROWS` (20 000),
  called at startup and each scan boundary alongside the events prune. The cache
  is best-effort, so evicting a still-fresh row only costs a re-query. (Also
  corrected the `low_confidence_evidence` doc, which claimed a `confidence`/
  `observed_at` index that deliberately does not exist.)
- **MITRE ATT&CK mapping precision — two modules' inline technique tags
  sharpened.** `dns_intel` resolves live DNS records (T1590.002) but *also*
  actively brute-forces subdomains against a 146-label dictionary, which is
  Active Scanning: **Wordlist Scanning (T1595.003)** — a technique the module
  performed but never declared, now added to the catalogue and mapped.
  `opencellid` queries a cell-tower geolocation database and makes no DNS query,
  yet claimed **DNS/Passive DNS (T1596.001)**; that mis-attribution is dropped,
  leaving the honest Search Open Technical Databases (T1596) → Physical Locations
  (T1591.001). Sharpens the per-finding `attack:` provenance both modules stamp.
- **Durable, concurrency-safe writes for the API-key vault; the shared atomic
  writer now commits the rename to disk.** Two robustness gaps: (1)
  `atomic_file::write` fsynced the temp file's data but never the parent
  directory, so on a power-cut/OOM-kill right after the rename returned, ext4/f2fs
  (the Termux targets) could lose the rename and leave the old file — now the
  parent directory is fsynced (best-effort) after every rename, committing it. (2)
  The `~/.huntsman.env` API-key vault was written by a hand-rolled copy of the
  atomic-write dance with a **fixed** temp name (`env.tmp`), so two concurrent
  writers (overlapping scans harvesting keys, a `PUT` toggling a key mid-scan)
  could truncate and interleave into the one temp and rename a corrupt file over
  the vault — read by the loader as empty, silently dropping every key. The vault
  now writes through the shared `atomic_file::write` (unique temp + 0600 + double
  fsync + rename), fixing the corruption and single-sourcing the logic. A
  concurrency property test hammers the vault from eight threads and asserts it is
  never emptied/torn and leaves no straggler. `extract::ibans` and the duplicated
  `oathnet_pro::validate::iban_is_valid` both accepted any mod-97-valid string of
  length 15–34, regardless of the fixed per-country IBAN length ISO 13616 defines
  (`GB` 22, `DE` 22, `FR` 27, …) — so a right-checksum but wrong-length string
  (≈1 in 97 of any wrong-length run with a real country prefix) was minted as a
  leaked bank account. A single `util::extract::iban_is_valid` now pins the
  `CCkk` layout, the registered length (unregistered country codes fall back to
  the 15–34 spec range, never a false negative), and the mod-97 checksum;
  `oathnet_pro` delegates to it, removing the drifting duplicate. Financial-intel
  findings are now genuine accounts, not checksum-lucky noise.
- **AU state attribution misclassified border towns via overlapping first-match
  bounding boxes.** `au_state_for_coords` tested overlapping rectangular state
  boxes in a fixed order and returned the first hit, so every town in the QLD∩NSW
  and NSW∩VIC overlap bands read as the box tested first — e.g. Lismore (a NSW
  town north of 29°S) and Goondiwindi read as QLD, and northern-Victorian towns
  (Shepparton, Wodonga) read as NSW. It now partitions the mainland by
  Australia's **actual borders**: the exact meridians 129°E (WA│NT/SA), 138°E
  (NT/SA│QLD) and 141°E (SA│NSW/VIC) and the 26°S parallel, with the two
  non-straight borders — QLD│NSW (29°S rising to Point Danger) and NSW│VIC (the
  Murray River + the Cape Howe segment) — fit piecewise to their real course.
  Validated by a 40-town fixture spanning all states, including river-twin pairs
  a few km apart (Mildura/Wentworth, Albury/Wodonga) that the fit now splits
  correctly. Every caller (`au_location_corroboration`, `best_au_location_estimate`,
  the `qld_cadastre` gate, IP/cell/WiFi geo tags) gets a sharper, more honest
  jurisdiction. This is a hint, not proof; sub-km river-twin points may still flip.
- **`extract::macs` carved a spurious 48-bit MAC out of a longer EUI-64 / hex
  run.** The MAC regex is word-boundary-anchored, but the separator after the
  6th octet satisfies the boundary, so an 8-octet identifier like
  `aa:bb:cc:dd:ee:ff:00:11` (or the hyphen form) yielded a bogus
  `aa:bb:cc:dd:ee:ff` — a fabricated MAC entity that would then be geolocated
  as if it were a real router BSSID. `macs` now rejects a match flanked by
  `<sep><hex>` on either side (another octet before or after), so a genuine
  standalone MAC still extracts (including when wrapped in non-separator
  punctuation) while a fragment of a longer identifier does not.
- **Two non-regex email-admission paths admitted addresses the canonical
  free-text matcher rejects — false positives at the source.** `EMAIL_RE`
  requires a real TLD (`…\.[A-Za-z]{2,}`), but the provider-field gate
  `looks_like_email` only checked `host.contains('.')` and the HTML byte-scanner
  `page_emails` only checked `contains('.') && len > 3`, so `admin@10.0.0.1`
  (IP literal), `user@host.123` (numeric pseudo-TLD), `user@host.c` (one-char
  TLD) and `x@sub..example.com` (double-dot host) each minted a bogus `Email`
  entity that then poisoned correlation. Both paths now share a single
  `host_has_alpha_tld` helper enforcing exactly the regex's domain validity
  (≥1 dot, no empty label, a final label of ≥2 ASCII letters), so a gate can
  never be more permissive than the scanner. No valid address is newly rejected
  (every real address has an alphabetic TLD). Both admitted a non-personal selector into a rule
  that treats its members as tied to the subject, manufacturing false positives
  — the class of error this evidentiary engine ranks above missing coverage.
  - **AU-018 (email ↔ physical-location linkage) admitted role mailboxes.** A
    role/provider mailbox (`abuse@`, `noreply@`, `registrar@`, …) is a shared
    organisational desk surfaced through WHOIS/RDAP, never the subject — yet
    AU-018 co-located it with the subject's address as an "identity-location
    linkage," the same false positive AU-001/AU-045 were already patched for
    (`abuse@godaddy.com`). It now applies the existing
    `core::validation::is_role_mailbox` gate, exactly as AU-001/AU-045/AU-002 do.
  - **AU-050 (shared-phone associate cluster) fired on business/service lines.**
    A shared freephone/local-rate/premium line (`1800`/`13`/`1300`/`190x`) is a
    company desk many unrelated people legitimately reach — grouping two of them
    as "associates; a direct pivot to reach the subject" is a false link. It now
    skips a group whose number classifies as `AuLineType::is_business_service`
    (reusing the existing `au_phone_line_type`); a personal mobile/geographic
    line still links people, and non-AU numbers are unaffected. The module actively resolves a subdomain's dangling CNAME and
  HTTP-probes the target to prove a cloud resource is unclaimed/claimable — an
  exploitable misconfiguration it reports as a `vulnerable` Domain — yet it
  mapped to the passive `T1590.001` *Domain Properties* the DnsRecon category
  default inherits, mis-describing every finding's inline `attack:` provenance
  tag. It now maps to a new catalogue entry **`T1595.002` Active Scanning:
  Vulnerability Scanning** (the technique it actually performs), mirroring
  `portscan`, the other active scanner that overrides its passive category
  default. Sharpens the per-finding ATT&CK labelling that is the engine's only
  MITRE surface; the `attack_overrides_attribute_collection_modules_precisely`
  architecture guard now pins the corrected mapping, and a catalogue test pins
  the new technique. No scan/engine behaviour changed. `hse scan --output dossier` is supposed to warn
  "N keyed/paid module(s) yielded nothing — consider --exclude …" when a
  budgeted API call returned nothing, but the check filtered a diagnostics
  list that only ever contains modules which emitted at least one entity — a
  module that ran and found nothing was structurally absent from it, not
  present with a zero count, so the warning never printed. It now reads the
  scan's own `ModuleDone` events (already recorded per module regardless of
  yield) instead, and correctly names every wasted `KeyGated`/`Paid` module —
  verified against a real scan both before the fix (silent) and after
  (correctly listed 11).
- **AU-059's headline location fix gave a single disagreeing sighting undue
  leverage over the majority (`PROBLEM_TREE` C5).** `au059_synergy_fix` — the
  function behind the dossier's "Best location estimate" line — averaged all
  contributing coordinates with a plain confidence-weighted centroid, so a
  single high-confidence but wrong-location sighting could drag the headline
  fix proportionally to its own weight, regardless of how many other
  independent sources agreed with each other. Now uses the confidence-weighted
  geometric median (Weiszfeld) instead, matching the outlier-robust estimator
  AU-057 and the spatial-clustering diagnostics already used: a minority
  sighting can no longer move the fix past what the majority's spatial
  agreement allows. Regression-tested with a fixture where a 36%-weight
  outlier is proven (by computing the old plain-centroid result inline for
  comparison) to have pulled the old fix a third of the way toward it, while
  the new fix stays anchored to the 64%-weight majority.
- **Concurrent scans could dispatch a whole extra target's worth of modules past
  `max_entities` (`PROBLEM_TREE` T2.11 LOW).** `dispatch_target_concurrent`'s
  spawn loop judged the entity-budget cap against the count from before this
  target's spawn loop began — completed sibling results were only merged in
  the trailing blocking drain, which ran AFTER every accepting module had
  already been spawned, so the check never saw them mid-round. The sequential
  path already re-checked the live count before every module; the concurrent
  path did not, so a `max_concurrent > 0` scan could overshoot the operator's
  stated cap by an entire target's module set (real network calls, real
  budget). Fixed with a non-blocking `JoinSet::try_join_next` drain at the top
  of every spawn-loop iteration, sharing a new `absorb_dispatch_outcome`
  helper with the trailing drain so a result is finalised exactly once.
  Regression-tested: `max_concurrent: 1` forces the interleave
  deterministically, proven to fail against the unfixed code (all 10 of 10
  modules dispatch despite `max_entities: Some(1)`) and pass against the fix.
- **`contact_enrich` computed the WRONG Gravatar hash — a guaranteed miss for any
  email with capitals or whitespace.** The lookup hashed the RAW email value (the
  `normalised` binding was named for normalisation it never did), but the
  gravatar.com spec hashes the email TRIMMED + LOWERCASED. So `Jane.Doe@Example.com`
  (or any address a user typed with capitals / a trailing space) produced a hash
  that never resolved to its real Gravatar — a silent 404. Now hashed in canonical
  form via a pure `gravatar_hash`, regression-tested against the official
  gravatar.com example vector (`MyEmailAddress@example.com ` →
  `0bc83cb571cd1c50ba6f3e8a78ef1346`) and the case/whitespace variants that must
  converge to it.
- **`nostr` no longer spends a guaranteed-404 NIP-05 request on freemail seeds.**
  The twin of the `fediverse` fix: the NIP-05 path probes
  `https://<domain>/.well-known/nostr.json` for an email seed, but a freemail
  provider serves no such document (the code comment already admitted "404 every
  ordinary mail domain"). It now skips the probe for freemail domains
  (`util::domains::is_freemail`) while still probing custom domains that might
  self-host NIP-05. Regression-tested.
- **`fediverse` no longer spends a guaranteed-404 WebFinger request on freemail
  seeds.** The module probes `https://<domain>/.well-known/webfinger` for an email
  seed, but a freemail provider (gmail/outlook/yahoo/…) runs no WebFinger server,
  so the probe is a certain miss — and freemail is the majority of email seeds, so
  the module was burning an 8 s request per scan on a metered Termux radio for
  nothing. It now skips the probe for freemail domains (`util::domains::is_freemail`)
  while still probing custom domains, which MIGHT be self-hosted instances.
  Regression-tested (freemail skipped, custom/instance domains still probed).
- **`psbdmp` now actually marks the SEED identity as paste-exposed, not just the
  orphan paste URLs.** The module's doc-comment promised to "mark the seed as
  paste-exposed so the correlator can corroborate it", but `extract` only ever
  emitted pastebin `Url` entities — so AU-043 counted the pastes while the
  subject's own email/username/domain carried no exposure tag and no temporal
  signal. It now also re-emits the seed identity (which merges by value into the
  target entity) tagged `paste-exposed` + `breach`, carrying the paste count and
  the EARLIEST paste date (lexical min over the API's ISO date strings —
  deterministic, no clock). The exposure and its temporal anchor now attach to the
  subject's record and are visible to identity-level breach correlation, not just
  to the URL-counting AU-043. `produces()` widened to Email/Username/Domain
  accordingly. Regression-tested (seed emitted + tagged + dated across all three
  seed kinds, order-independent earliest-date) and the full gate.
- **Reused-secret identity merge now links USERNAME-keyed accounts, not just
  emails (AU-047).** The rule's own documentation promised to tie identities on a
  shared unique secret "(the email/username the breach record carries)", but the
  implementation counted only distinct *emails* to fire — so a unique salted hash
  shared across two distinct usernames (the very common `username` + hash dump
  shape, with no email) went unlinked, a dead end for handle reverse-search. An
  account is now identified by its email local-part **or** its username, both
  folded to one canonical handle (the AU-048 scheme); ≥2 distinct handles fire the
  link. The fold preserves the original single-record safety — an email and its
  matching username from ONE record collapse to one handle and cannot self-fire a
  phantom "2 accounts" link — while two genuinely different handles sharing the
  unique secret now merge regardless of breach count. No new false-positive surface:
  the salted-hash / entropy / common-password precision gates are unchanged, and the
  rule still runs only on the confirmed (quarantine-filtered) view. Regression-tested
  (username-keyed merge, same-record self-link resistance, email↔different-username
  cross-pivot) and the full gate.
- **Offline geocoder: a US ZIP+4 add-on is no longer read as an AU postcode.**
  Follow-up to the foreign-street-number fix below. `util::city_coords` anchors on
  the address's final numeric run, but a US ZIP+4 (`NNNNN-NNNN`) ends in a 4-digit
  run — the `+4` extension — so `"… , NV, 89436-9322"` resolved `9322` to the QLD
  region (Brisbane). Real evidence: debug bundle entity [21] geocoded two ZIP+4
  breach addresses to Brisbane. `au_postcode_in` now rejects a trailing 4-digit run
  immediately preceded by `<5 digits>-` (a ZIP+4 add-on, never an AU postcode),
  while a genuine `"… QLD 4217"` still resolves. Regression-tested from the captured
  ZIP+4 addresses.
- **Search-engine evidence: titles/snippets no longer leak SVG path data or HTML
  attribute soup.** `search_engines` rendered garbled `page_title`/`snippet`
  evidence — observed across multiple real results (debug bundle entities [187]
  `beitbirth`, `saucecreativeagency`): an inline result-icon `<svg>` whose path data
  carries a stray `>` desynchronised the tag scanner and dumped `…5.09083Z"
  fill="#6573ff"` into the title, and the snippet slice began *inside* the `<a …>`
  tag, dumping its `rel`/`target`/`aria-label`/`class` attributes as text. `strip_tags`
  now removes `<svg>`/`<style>`/`<script>` subtrees wholesale and treats a tag
  opening as a word boundary (so adjacent elements no longer fuse into
  `Facebookhttps…`), and `extract_snippet_near` advances past the enclosing tag
  only when the anchor sits inside one. Regression-tested from the captured SERP
  markup.
- **`name_intel`: the `source_name` evidence attribute records the cleaned name,
  not the raw target.** A re-expansion pass can feed a quote/comma-contaminated
  breach Person value (`"Matthew Diegmann",`) back in as the target; `name_intel`
  wrote it verbatim into `source_name`, so on merge the attribute accumulated the
  junk `"Matthew Diegmann",; Matthew Diegmann` (observed on 27 of 49 `source_name`
  lines). It now records `display_full()` — the quote/comma-stripped reconstruction
  the clean seed also produces — so the attribute is identical across runs and never
  contaminates.
- **Breach extraction: the SQL `\N` NULL sentinel is no longer admitted as data.**
  MySQL/Postgres dumps write `\N` for an absent column (303 such name fields in one
  real SeekNow export); `val_str` admitted it as a non-empty string, so `breach_rich`
  composed a `"\N \N"` Person and surfaced `\N` long-tail/country nodes. A shared
  `util::json::is_null_sentinel` now treats `\N` as absent at the `breach_rich`
  name-compose and catch-all paths and the `see_know` country path. Exact match, so
  a real surname `Null` or the province `Nan` is never dropped. Regression-tested.
- **Exposure Index: a CONFIRMED subject breach is now counted, not scored zero.**
  The breach component tallied distinct corpora only from the `dbname` evidence
  key — the key the per-record *co-occurrence* rows use, and those rows are
  non-subject candidates that are already excluded from the confirmed set. The
  subject's OWN aggregate breach hit carries its corpus name under `top_dbnames`
  (oathnet_pro) or `breaches` (xposed_or_not), so in a real scan (debug bundle,
  scan `90b936dc…`) a subject confirmed in the TLDRtech breach by BOTH sources
  scored `Breach exposure 0/35 — no named breach corpus appearances`, understating
  the headline index by 12 points despite a `password_risk` flag on the same
  finding. The component now reads every corpus key, splits the comma-separated
  lists, and folds spelling variants of one corpus (`tldr.tech` / `TLDRtech`) to a
  single count so it is neither missed nor double-counted. Regression tests seeded
  from the captured evidence shape; full gate (fmt, clippy `--all-targets -D
  warnings`, rustdoc lints, 4156 lib tests).
- **Offline geocoder: a foreign STREET NUMBER is no longer misread as an
  Australian postcode.** `util::city_coords` resolved an address by scanning for a
  4-digit token and treating it as an AU postcode. On an overseas address the real
  postal code is a 5-digit ZIP (no 4-digit token), so the geocoder grabbed the
  leading 4-digit *street number* and mapped it to an Australian region — minting a
  false `Coordinates` entity. Real execution evidence (debug bundle, scan
  `90b936dc…`): of nine US breach-record addresses turned into coordinates, **seven
  (78%)** landed in Australia — "5528 North 73rd Avenue, Glendale, AZ" → South
  Australia, "1019 Winston Dr, Jefferson City, MO" → Sydney, "3145 Rochambeau Ave,
  Bronx, NY" → Melbourne — while the two with a tabulated US city (Miami, Las Vegas)
  resolved correctly. The fix anchors the embedded-postcode fallback on the address's
  *final* numeric run (an AU postcode comes LAST, the street number LEADS) and gates
  it behind a non-AU-country guard, so a foreign suburb earns no coordinate rather
  than borrowing an Australian one. The identical root-cause class was fixed in two
  sibling paths that consume the same breach data: `address_au::state_code` (its
  bare-postcode rung was attributing a US street number's range to an AU state, e.g.
  Arizona → "SA") and `core::geo_family::au_postcode` (the family geo-corroboration
  postcode reader). Proven by regression tests in all three modules seeded from the
  verbatim captured addresses, plus the full gate (fmt, clippy `--all-targets -D
  warnings`, lib tests).
- **best-location estimate: a coordinate's `lat,lon` digits are no longer
  misread as a postcode.** The postcode rung excluded a token like `…,151.2093`
  → "2093"; `Coordinates` are now excluded from that rung (a coordinate's location
  is the dedicated coordinate rung), so a lat/lon can never produce a bogus
  residential-postcode fix in the dossier or the API export.
- **Breach-candidate geo re-promotion — "return to old data when downstream adds
  credibility" for breach records.** A name search quarantines every same-name
  breach/stealer row as a `candidate` (it may be a namesake). When a later round
  independently confirms the subject's own location, a same-name breach candidate
  whose locality resolves to within one metro (25 km) of that fix is lifted out of
  quarantine (dropped `candidate`, raised to Probable, stamped `breach-corroborated`)
  so the leaked email/phone/address become first-class, correlatable, graded
  findings instead of hidden candidates. Conservative and non-circular: the anchor
  is only a confirmed (non-candidate) location, the radius is tight, family
  candidates are left to AU-061, and it is idempotent. Runs every expansion round
  (the per-round reconsideration) and at finalise.
- **Debug bundle: correlation rule histogram.** The CORRELATIONS section now opens
  with a `rule_id × count × share` histogram, sorted by frequency, so a single rule
  dominating the output (the permutation-flood failure mode) is visible at a glance
  instead of needing a manual grep — the fastest anomaly signal for a diagnosing
  tool (human or Claude). Deterministic; the byte-reproducibility guarantee holds.

### Changed
- **AU government-register result caps raised so no genuine API result is
  omitted.** Several AU open-data modules silently dropped real records beyond a
  small rank: QLD unclaimed-money (`MAX_RECORDS` 20), ASIC persons/banned (`5`),
  ASIC business names (`8`), ACNC charities (`20`), and GLEIF LEI (`10`) — each
  bounding both the CKAN/GLEIF query `limit` and the rows emitted. They now fetch
  and surface up to 100 (the per-row name classifiers still gate quality), so a
  subject's full register footprint reaches the graph (directive: never omit an
  API-derived AU government result). The multiplicative geo fan-outs in QLD
  unclaimed (postcodes→suburbs) are raised to a generous-but-bounded 25 each so a
  real set is never truncated without putting a low-RAM device on a pathological
  enumeration path; the global per-scan entity cap remains the ultimate safety.
  that all canonicalise to the same handle, so the per-pair emission produced an
  N×M flood of identical High findings (observed: 80 rows for one subject). It now
  emits ONE finding per canonical handle, listing every email form and every
  username form it unifies — the full identity cluster in a single, more useful
  row, no value lost. Validated: the same `Matthew Diegmann` scan dropped AU-076
  from 80 → 2; combined with the AU-063 consolidation, total correlations fell
  501 → 41 (≈92% noise removed) with every finding preserved.
- **AU-063 (single-pathway corroboration gap) is consolidated — Interpol-grade
  signal-to-noise.** It emitted one Low finding per fragile link, so a broad name
  scan's dozens of low-confidence permutation links flooded the dossier (observed:
  404 AU-063 rows, 80% of all correlations). It now details only the gaps worth
  corroborating first (the weaker endpoint at ≥0.40, capped at 25, strongest
  first) and consolidates the speculative tail into ONE summary naming how many
  remain and the orthogonal source that would corroborate the most — no gap is
  lost. Validated end-to-end: the same `Matthew Diegmann` scan dropped AU-063 from
  404 → 22 and total correlations 501 → 119.

### Fixed
- **Scans no longer freeze at the seed→expansion boundary.** The live per-round
  correlation pass was unbudgeted on the assumption the working set is "small";
  with `feature.recall` injecting a large prior graph it ran for many seconds
  every round and presented as a frozen scan stuck in `Running`. The per-round
  pass now defers to the authoritative wall-clock-bounded finalise pass above a
  working-set threshold, so a round can never stall. (Validated end-to-end: a
  fresh `Matthew Diegmann` self-test now expands name→email/username/address and
  reaches a terminal status instead of hanging.)

### Changed
- **`feature.recall` now defaults OFF — every scan is a fresh start.** Prior-scan
  entities are no longer pre-loaded into a new scan's working set (the source of
  "archaic data in current scans"); the store still fully RETAINS everything and
  cross-scan corroboration still runs. `hse config feature.recall on` to opt in.

### Added
- **Per-round reconsideration — "return to old data when downstream adds
  credibility".** The free/offline re-promotion passes (geo-corroborated family,
  multi-pathway corroboration) now run at the start of every expansion round, not
  only at finalise, so a lead the scan had set aside is lifted above the
  expansion floor and expands as soon as later rounds make it credible —
  autonomously, idempotently.

## [1.12.0] — 2026-06-26

### Added
- **Continuous autonomous Live Signal Radar** — the radar is now a single,
  zero-input button. `POST /api/v1/radar/live` starts a continuous live session
  that re-runs only the on-device passive sensors (`signal_radar`,
  `device_sensors`, `wifi_intel`, `cell_intel`, `local_net`), enumerating the
  device's ambient signals (Wi-Fi APs, Bluetooth, cell towers, GPS/last-known
  fix, local network) in real time as they appear and change. No target, no
  seed, no interval — every parameter is fixed server-side; same `feature.live_radar`
  activation wall as the one-shot sweep (kept for API back-compat).
- Radar GPS sensors degrade to the phone's passively-cached last-known location
  (`-r last`) so a fix is established with no fresh lock; cached fixes are tagged
  `fix-age:last-known`.
- AU-103 — autonomous device self-location: fuses the passively-collected
  on-device signals into the operator device's own position (offline
  reverse-geocoded), with a roaming / spoofed-GPS cross-check; no seed input.
- AU-101 — identity-resolution breadth; AU-102 + `util::address_au::au_phone_line_type`
  — portability-proof phone line-type intelligence; AU-104 + `util::bsb` —
  Australian bank-account / institution exposure from an exposed BSB.

### Changed
- Web UI: removed the radar's forced "Seed type" choice — the Live Signal Radar
  requires no input whatsoever; one tap starts the continuous passive-signal sweep.
- `feature.live_radar` now defaults **ON** (armed): the radar is the operator's own
  deliberate action, so it needs no prior opt-in — a single button press runs it.
  The toggle is now a kill-switch (set OFF to refuse the radar). The safety
  invariant is unchanged: seed scans never set `allow_live_sensors`, so they can
  never run the device sensors regardless of this default.

## [1.11.0] — 2026-06-25

### Added
- `gaming_profile` module — free, keyless Roblox + Minecraft (Java) profile
  resolution via each platform's own public API.
- `comb_search` module — free, keyless leaked-credential search over the public
  COMB index, with strict exact-match attribution (no substring over-claiming).
- Dynamic SeekNow quota probe — the per-round scan cap auto-scales to the
  operator's actual plan tier.
- Integrated pipeline-quality work: social-probe body validation,
  infrastructure-entity separation, controlled-subdomain tracking-ID pivot,
  `hse doctor`, `--output json` diagnostics, raw-archive secret redaction, and
  Weiszfeld/Welzl geo-centroid fusion.

### Changed
- **Relicensed** from `MIT OR Apache-2.0` to a proprietary "all rights reserved"
  licence; `publish = false` blocks crates.io redistribution.
- Foundation de-duplication onto single-source helpers (`keyed_ok_or_404`,
  `looks_like_email` email-minting gate, `merge_pool_into_env`, allocation-free
  subdomain check) and dead-code removal.
- Registry grows to **147 modules (114 free)**.

### Fixed
- rust-1.96 `map_unwrap_or` clippy error in `key_vault::total_count` — restores
  green CI on `main`.

## [1.9.0] — 2026-06-23

### Added

- **Target Exposure Index** — a calibrated `0–100` rollup of how exposed a subject
  is, with a transparent per-component breakdown. Competitors (SpiderFoot) flag risk
  per finding; HSE already computes the inputs, so the new `core::exposure` module
  *aggregates* them — breach-corpus breadth, sensitive-PII disclosure
  (government ID / DOB / financial / cleartext credential), confirmed-identifier
  spread, and the correlator's own Critical/High verdicts — into one explainable
  number (`MINIMAL`…`CRITICAL`). It counts only corroborated findings
  (`c_effective ≥ 0.5`), so the speculative name-permutation guesses a name scan
  emits by the dozen never inflate it. Surfaced as the dossier headline and in the
  `hse scan --output json` payload (`"exposure"`). Pure, deterministic, core-only.

### Fixed

- **IPv6 stealer-log victim addresses are no longer dropped.** The TXT importer
  gated victim IPs on `contains('.')`, discarding every IPv6 address; it now parses
  each token as an `IpAddr` (keeping both families, including a victim's private LAN
  IP) and skips only the unspecified / `0.x` placeholder.
- **A PO box is no longer treated as a residence.** `is_specific_residence` accepted
  `PO Box 123, …` as a dwelling, so the household/kin correlators (AU-049/051) could
  fuse the unrelated people who share one mail drop into a false household. The
  PO-box / GPO-box / locked-bag / private-bag forms are now rejected (matched on
  alphanumerics so every punctuation variant collapses); a real street in a suburb
  that merely contains "box" (Box Hill) is unaffected.

## [1.8.4] — 2026-06-23

### Fixed

- **Shared-surname kin (AU-051) is a High lead, not a Critical assertion, for common
  surnames.** The rule reported Critical "likely relatives; kin pivot to reach the
  subject" for *any* two same-surname people at one residence. But an apartment tower
  or share-house whose unit numbers are absent from the data collapses unrelated
  co-residents onto one residence key, and a common surname (Smith, Nguyen, …) makes
  that coincidence likely — so the confident "relatives" claim was often false. A
  common surname now fires as a **High lead to verify**; a distinctive surname keeps
  the Critical kin signal. (Same `is_common` discount the kinship/leads/engine paths
  apply.)
- **Dossier import no longer drops the first section of a "UTF-8 with BOM" file.** The
  BOM (U+FEFF, the Excel/Notepad default encoding) is not whitespace, so `str::trim`
  left it on the first line — turning the `EMAILS:` section header into
  `\u{feff}EMAILS:`, which matched no section, silently discarding the entire first
  section and its entries. A single leading BOM is now stripped at ingest.

## [1.8.3] — 2026-06-23

### Fixed

- **Transitive identity closure (AU-060) honours the relation builders' damps.** The
  rule asserted an identity link for any 2–4 hop path with no confidence floor, so a
  chain routed through a deliberately-damped lead-grade edge — a bare-surname
  `derive_kinship` link (`min(conf) × 0.5`), a co-mention/affiliation lead — surfaced
  as a confirmed transitive identity, cross-linking same-surname strangers to the
  subject. It now applies a weakest-link `>= 0.50` floor (mirroring AU-067, reusing
  the `min_confidence` the path finder already computes): a chain through a sub-0.50
  lead is suppressed; an all-strong-edge chain still fires.
- **Common surnames no longer manufacture kinship edges.** `derive_kinship` paired
  every two Persons sharing a surname with no commonness gate, producing O(n²) false
  "associate" edges from a single popular name (ten "Smith"s → 45 edges). It now skips
  a common surname (Smith, Jones, Nguyen, …) — mirroring the `is_common` discount the
  leads/engine paths already apply — while a distinctive surname still links. Genuine
  relatives of a common-surname subject still surface through the evidence-grounded
  co-residence and declared-association passes.

## [1.8.2] — 2026-06-23

### Fixed

- **Bare non-display ISO country codes no longer become phantom addresses.** The
  `Address` fragment gate rejected a bare 2-letter country code only when it was
  one of the ~54 countries in the human-readable `country_name_for_iso` table, so
  every *other* ISO 3166-1 alpha-2 code (`PK`, `BD`, `VE`, `IR`, `BG`, `HR`, `LT`,
  `LV`, `EE`, `LK`, `QA`, …) still slipped through and corroborated across hundreds
  of unrelated breach co-occurrence rows into a VERIFIED phantom address — the exact
  `US`-at-corroboration-106 pathology the gate was added to close. It now rejects
  *every* bare 2-letter alpha token; the country still survives on the `country:XX`
  tag and evidence attributes.
- **Search-discovered usernames require the surname, not just a given name.**
  `score_username` granted the PROBABLE tier (0.55) on *any* term overlap, so a
  stranger sharing only the target's first name (`jordan_blake` for a "Jordan
  Meyers" scan) was emitted as a confirmed handle and fed to the correlator. A
  multi-part-name target now needs its surname (the distinctive anchor) — or
  people-search provenance — to reach PROBABLE, mirroring `url_matches_target`;
  first-name-only evidence stays a quarantined CANDIDATE.
- **AU state classification is whole-word, not substring.** Prose around an
  Australian place name routinely contains `ser{vic}e`, `{act}ed`, `fan{tas}tic`,
  which a bare substring scan read as VIC / ACT / TAS and stamped a wrong
  jurisdiction onto the address (feeding the AU-056 cross-check and geo-divergence
  logic). The 2–3 letter abbreviations are now matched as whole tokens.
- **Numeric breach fields are no longer silently dropped.** The shared JSON reader
  accepted only string values, so a breach row encoding `discordid` (always a
  64-bit int), `phone_number` or `postal_code` as a JSON *number* lost the Discord
  pivot, the phone lead, and the postcode entirely. A coercing reader
  (`val_str_coerce`) now recovers numeric scalars on the breach extraction paths.
- **Household / associate correlators fire on live breach scans.** AU-049
  (household), AU-050 (shared phone line) and AU-051 (same-surname kin) cluster
  Persons by an `address` / `phone` attribute on their evidence, but the live
  `oathnet_pro` breach module never stamped those attributes (it emitted standalone
  Address/Phone entities and split `city`/`state`/`postal_code` attrs instead) — so
  the three pivots fired only on hand-imported text dossiers, never on a real scan.
  Breach evidence now carries a `phone` attr and a street-anchored `address` attr
  (gated to a specific residence so a shared city can't fuse strangers into a false
  household).

## [1.8.1] — 2026-06-23

### Fixed

- **Re-observed evidence no longer loses newly-discovered attributes.**
  `Entity::absorb`'s `(source, summary)` evidence dedup was first-wins *drop*, so
  when the same source re-observed an entity with the same summary but NEW
  attributes (an updated breach dump, a richer re-scan), the new record was
  discarded and its fields silently lost — across both the in-memory scan merge
  and the recall/persist path (both use `merge`). It now MERGES the incoming
  attributes into the matching record (keys it lacks are added; a key both set
  resolves to the lexicographically smaller value, so the fold stays
  merge-order-independent and idempotent). The dedup — no phantom corroboration
  from a repeat observation — is otherwise unchanged.
- **Dossier import parser aligned with the breach-PII rules' field variants.** The
  AU-073/074/075 rules each scan several field-name variants (e.g. `birthday`,
  `centrelink`, `husband`/`wife`); the parser only preserved a subset, so a dump
  using a common variant had its field dropped and the rule never fired. The
  parser's preserve-set now covers every key the three rules scan.

## [1.8.0] — 2026-06-23

### Added

Breach/stealer PII intelligence — three people-centric correlator rules that mine
the structured fields breach, stealer-log and other leak modules already store as
evidence attributes but never surfaced as findings. All run on the confirmed
(candidate-filtered, quarantine-excluded) view, so breach co-occurrence strangers
can't leak in. Proven end-to-end: an imported breach dossier fires all three.

- **AU-073 Subject date of birth** — extracts and normalises DOB from breach
  records and reports each distinct value with its independent-source count
  (≥2 agree → High; single → Medium). DOB is the strongest disambiguator between
  same-name people, so conflicting DOBs surface separately rather than being
  silently merged — directly attacking the namesake failure class.
- **AU-074 Australian government-ID exposure** — detects a leaked TFN / Medicare
  / Centrelink CRN / driver-licence / passport by breach field key, confirmed by
  format+checksum (TFN mod-11, Medicare mod-10) so a mislabelled number can't
  fabricate a CRITICAL finding. The value is masked in the finding; the full
  value stays in evidence (operator full-fidelity). The most serious
  identity-theft signal (the Optus/Medibank exposure class).
- **AU-075 Named associate** — surfaces a relative/associate stated in a breach or
  stealer record (spouse, next-of-kin, emergency contact, the stealer-log owner)
  — a declared tie the geo/surname family rules (AU-049/051/061) can't reach.

To feed these on every source, the breach-PII fields are now preserved through
the **oathnet_pro** allowlist and the **dossier import parser** (both previously
dropped unmapped fields); `see_know` and the JSON import already preserved them.

## [1.7.0] — 2026-06-22

### Added

- **AU-072 — Consolidated PayID payment-identity surface.** The v1.6.0 `payid`
  module tags each PayID-eligible identifier (email/phone/ABN) individually; this
  correlator rule consolidates them. Once a subject carries two or more PayID
  handles it fires a finding, because the aggregate is the signal — each handle
  is an independent NPP confirm-payee route to the **same** registered
  account-holder name, so multiple handles both widen the de-anonymisation
  surface and cross-confirm the name. A register-resolvable ABN among them lifts
  the severity to High (its holder name is resolvable from the public register
  now). Runs on the confirmed view, so speculative name-permuted addresses never
  inflate the count; `entity_uids` are the full member set sorted by uid (the
  AU-039 determinism discipline). This completes the "use PayID for OSINT pivots"
  capability — recognition (v1.6.0) plus the actionable correlation.

## [1.6.0] — 2026-06-22

### Added

- **PayID OSINT pivots** (`payid` module, #126 — free, passive, People category).
  PayID (Australia's NPP) maps a memorable identifier — email, mobile/phone, ABN,
  or Org ID — to a bank account, and the *confirm-payee* step returns the
  registered **account-holder name**, so a lone phone or email pivots to a real
  legal name. The module recognises which discovered identifiers are
  PayID-eligible, normalises them to canonical NPP form (lower-cased email,
  `+61…` E.164 phone, 11-digit ABN), and annotates them as confirm-payee pivots
  with the operator step that reveals the name. The **ABN** PayID is flagged
  `payid:registry-resolvable` — its holder name equals the ABN's registered
  entity name, which `abn_lookup`/`opencorporates` already resolve lawfully from
  the public register (the one PayID type whose name needs no banking app).
  Deliberately **offline**: there is no public PayID resolution API, so the module
  never contacts a bank/NPP endpoint and never auto-resolves a name from a
  phone/email (that appears only inside the operator's own banking app). `payid`
  is enrichment-only, so PayID-shape annotates an identifier without ever
  inflating its confidence tier.

### Fixed

- **`dns_intel` SOA admin email treated as the subject.** The SOA RNAME admin
  contact — always a role/zone mailbox (`hostmaster@`, `dns@`, an infra-domain
  desk) — was emitted as a discrete Email entity and identity-clustered as the
  subject's PII (a live domain-heavy scan surfaced dozens). It is now gated
  through `is_infrastructure_email`, mirroring whois/ripestat/search_engines; a
  genuine personal admin on a non-infra domain is still kept.

## [1.5.1] — 2026-06-22

Accuracy and robustness fixes from an adversarial review of a live v1.5.0
`full_name = Cindy Haynes` scan (plus dedicated panic-safety and determinism
sweeps). Three corrected flaws were producing **materially wrong intelligence**;
all are gate-verified (fmt, clippy `-D warnings`, full suite, MSRV 1.88, rustdoc).

### Fixed

- **Namesake location false-attribution.** A name search returns fuzzy
  namesakes, and the per-result snippet extractors trusted every result's text
  with no subject gate — a "Dr Cindy **He**" UNSW staff page was attributed to
  "Cindy Haynes", injecting a false "Sydney, NSW" address + coordinate that drove
  a wrong-state AU-056 jurisdiction and a 700 km geo-divergence. `url_matches_target`
  now requires the distinctive **surname** for a multi-part name (not any term),
  and snippet address extraction is gated on the surname appearing in the result.
- **Phantom VERIFIED country "address".** A bare ISO country code ("US") reached
  corroboration=106 by aggregating the shared `country` field across hundreds of
  unrelated breach co-occurrence rows, surfacing as a confirmed US address for a
  QLD subject. A bare country code is now refused at admission (the country
  survives on its tag/attributes).
- **Speculative permutations resurrected by recall.** Name-permuted emails
  (`cindy.haynes@{gmail,hotmail,…}`) were shown VERIFIED with no real
  confirmation: `source_count`'s stored-field fallback (meant for evidence-less
  synthetic entities) also fired for entities whose evidence was all
  non-corroborating, and `recall` ratchets that field up every re-scan. The
  fallback is now reserved for genuinely evidence-less entities; an all-`recall`/
  enrichment entity counts as one source and stays at its base tier.
- **Correlator determinism** — every `entity_uids` `take(N)` over a HashMap-ordered
  collection (AU-022/025/027/037) now uses the full member set or a
  sort-before-cap, so the live and finalise passes agree and containment-dedup
  folds them instead of persisting duplicate rows.
- **`cert_intel` out-of-bounds panic** on an attacker-controlled leaf certificate
  whose version-wrapper sits at the buffer tail — the serial-length read is now
  bounds-checked.
- **Email value normalisation** strips a literal breach-escape tail
  (`…@gmail.com\r\n`) so the clean and dirty forms share one UID.

## [1.5.0] — 2026-06-22

Unifies two parallel development lines and ships the combined result as one
install-ready release (**125 modules — 92 free · 28 key-gated · 5 paid**;
3,492 lib tests):

- the **module-consolidation refactor** (127 → 124 modules with no capability
  lost — `phone_area_geo`+`phone_carrier_geo` → `phone_geo`, `qld_unclaimed`
  folded into `au_unclaimed`, IP-geo/ASN unified into `util::geo::ip_asn_entity`,
  seven JSON holdouts routed through the shared `json_decode`), and
- the **graph-analytics / cross-scan intelligence suite** — a shared `Graph`
  primitive with community detection (deterministic label propagation),
  cut-vertex/bridge detection, betweenness-centrality **pivot-node** detection,
  connection-/path-discovery between entities and **across separate scans**,
  damped **trust propagation**, near-duplicate **entity resolution**,
  **discovery-gap** analysis, the universal entity **classifier** (every output
  re-injectable as a seed), a consolidated **`hse benchmark`** scorecard (+ its
  HTTP twin and a forward-only scan-plan preview), and history-aware lead
  prioritisation.

Plus a **dependency refresh** (tower-http 0.6 → 0.7; 26 transitive crates to
their latest Rust-1.88-compatible versions) and **five data-quality fixes**
verified against real-scan debug bundles: structured exports (CSV/JSON/GEXF) now
honour the breach-co-occurrence quarantine (H1); `name_intel` name-permutations
no longer self-corroborate into AU-003/AU-034 (H3); WHOIS-registrant / hosting /
IP-geo locations no longer vote the subject's address in AU-018/026/030 (H5);
`rdap_domain` reduces a host to its registrable domain before querying (M5); and
a confusable-homograph / gibberish admission gate drops breach-dump spam
"names" (L5).

### Added

- **Test-coverage & proof-infrastructure expansion (~2,995 lib tests passing).**
  Added direct unit tests for previously-untested pure functions across the tree
  — `signal_radar/gps`, search-engine/email/fullcontact helpers, the `util`
  (`oathnet`, `key_pool`, `key_roi`, `oathnet_batch`), `storage`, `cli`
  import/export, and the `core` correlator/engine/entity/timeline/crypto layers
  (parsers, classifiers, confidence math, determinism) — plus, under
  PROBLEM_TREE **F.3**, `proptest` property suites (boundary-safety, `normalise`
  idempotency, `Entity::merge` GREATEST-semantics + order-independence, geo
  round-trips, and no-panic crash-resistance for every network-facing byte parser)
  and lean `criterion` scan-throughput benches (`benches/scan_throughput.rs`),
  both dev-only with zero shipped cost.
- **`docs/PROBLEM_TREE.md` — a single, prioritised, living problem + capability
  tree** (functionality scope), with an optimal solution on every node and a
  capability program to surpass SpiderFoot/Maltego without heavy graphing.

### Fixed

- **Security & concurrency hardening (PROBLEM_TREE §7 / T2.8 / T2.9 / T2.11).**
  Fixed a **one-click stored XSS in the Web UI** — two correlation-pivot handlers
  interpolated an attacker-controllable entity value into an inline `onclick`
  JS-string literal (where HTML-entity escaping is the *wrong* escaping, so a
  crafted value broke out and executed same-origin on click); both now pass the
  value through a `data-` attribute read via `this.dataset`, and a full-SPA sweep
  confirms no remaining inline-handler interpolations. Closed a **paid-quota
  overspend race** — `oathnet` used a non-atomic check-then-increment that two
  concurrent `serve` scans could both pass; it now reserves atomically (CAS),
  matching `see_know`. Made four SQL read-backs **deterministic** with a unique
  tie-break — `hse export/diff/audit latest` could otherwise resolve to a
  different scan when two completed in the same one-second window. Capped two
  **unbounded response reads** that a hostile host could use to OOM the device
  (`exif_geo` now streams and bails at its size cap instead of buffering the whole
  body; `smtp_vrfy` caps a reply line at 8 KiB). Every fix preserves behaviour on
  legitimate input and ships with a regression test.

- **Update / installer / release-CI hardening (PROBLEM_TREE cycle 23 — six
  defects from an adversarial self-review of the v1.4.0 surface).** Closed a
  **CI script-injection** path — `release.yml` interpolated the
  `workflow_dispatch` tag input directly into a `run:` block; inputs now flow
  through `env:` vars, the resolved tag is validated against the git-refname
  charset before it reaches `GITHUB_OUTPUT` (blocking newline output-injection),
  and the event `case` gained a fail-closed default. Added the **loopback-only
  guard** to `POST /api/v1/update/trigger` (it was missing while every
  settings-write handler has it, so a client reaching a `--bind 0.0.0.0` server
  could force an in-place binary swap) via a named, tested `reject_non_loopback`
  helper. Fixed three `install.sh` bugs: `CARGO_TARGET_DIR` was set only inside
  the source-build branch but read in the summary, so **every successful prebuilt
  install aborted** under `set -u`; a failed `.sha256` sidecar download silently
  fell back to run-test-only validation (the network path now **requires** the
  checksum); and the `HUNTSMAN_INSTALL_DIR` record used `sed`, which a path
  containing `&`/`|`/`\` could corrupt (now `grep`+`printf`+`chmod 0600`). In the
  key store, `load_from_file_only` now strips the surrounding double-quotes the
  writer emits (SUPERSEDED embedded-key rotation silently never matched), and
  `write_keys_at` `fsync`s before the atomic rename so a power-cut can't leave a
  zero-length `~/.huntsman.env`. A reviewer-flagged `cell_db::query_bbox`
  "lat/lon binding swap" was investigated and **rejected as a false positive**
  (the bindings are correct; the round-trip test proves it). +2 regression tests.

- **`hudsonrock` URL-encoding fix and `employer_pivot` role-email guard
  (PROBLEM_TREE cycle 25 / SOL-QUERY-PIPE).** Two code bugs found from a real-scan
  debug bundle (`full_name = Zac Allen`, hse_version 1.4.0). **(A) `hudsonrock`
  HTTP 400:** `urlencode()` encoded `@` as `%40`; HudsonRock Cavalier's
  `search-by-login` validates `@` presence in the raw (pre-decode) query string, so
  `dns%40cloudflare.com` triggered "Email is required". Fixed by
  `.replace("%40", "@")` after encoding + an early-exit guard for any email value
  lacking `@`. **(B) `employer_pivot` false attribution:** `dns@cloudflare.com`
  (a SOA RNAME address emitted by `dns_intel` at confidence 0.70) had its
  `dns-admin` tag stripped at entity→target conversion (the `Target` struct has no
  tags field). With no role-email guard, `employer_pivot` scraped cloudflare.com's
  contact pages and attributed the Cloudflare Sydney HQ address to scan subject Zac
  Allen — a severe false positive. Fixed by `is_role_email_local()` (21 RFC 2142 /
  conventional system local-parts) with a `let`-chain guard at the top of
  `process()`. +5 unit tests covering both fixes. 3,097 lib tests, 0 failures.

- **Sensor contamination fix — `signal_radar` no longer fires on non-geo target
  seeds (PROBLEM_TREE cycle 24 / SOL-SENSOR-GATE).** `signal_radar` ran WiFi,
  Bluetooth, cell, GPS, and LAN-ARP sensors for *every* scan target regardless of
  kind (email, name, phone, domain, IP, …), injecting the operator's physical
  RF environment into unrelated scans and attributing the phone's GPS fix, visible
  APs, and nearby cell towers to the remote subject. Downstream geo modules
  (`cell_local`, `opencellid`) then fired on those injected coordinates, compounding
  the contamination. Two-part fix: `signal_radar::accepts()` narrowed to
  `Coordinates | MacAddress` only (matching the established pattern of all five peer
  live-sensor modules); `"signal_radar"` added to `LOCAL_PASSIVE_MODULES` in
  `core::engine` to suppress expansion-round re-firing. No new test code required:
  the existing `local_passive_sensor_modules_reject_remote_subject_seeds`
  architecture test now automatically covers `signal_radar`.

- **Correctness & robustness hardening (PROBLEM_TREE T0–T2).** Closed the
  `to_lowercase()` byte-offset slice **panic class** (T0.1/T0.2) —
  `au_electoral`/`au_property`/`search_engines` now route through a boundary-safe
  `find_ascii_ci`, so multibyte-uppercase response HTML can no longer abort a
  scan; hardened untrusted numeric casts (T0.3); made GEXF exports and the
  live-session list **deterministic** (T1.1); added firing assertions for 12
  previously-unasserted correlation rules (T1.3); inverted the `core → modules`
  layering via a `core::hooks` registry, now guarded (T1.4); added a global HTTP
  read-timeout backstop (T2.1); moved the heavy blocking API/export handlers off
  the 2-worker async reactor via `spawn_blocking` (T1.2/T2.2). A real-certificate
  fixture exposed and fixed **two genuine `cert_intel` DER bugs** (T2.3): SAN
  discovery returned **zero SANs on every real certificate** (its core
  subdomain-discovery feature was dead), and the serial read returned the
  version field. Also fixed a `slugify` bug that leaked non-ASCII/uppercase bytes
  into correlation tags, and **gated IPv6 Cloudflare/Fastly anycast edges** in
  `is_cdn_edge_ip` (a fronted domain's native AAAA records were being trusted as
  origin hosts → false subject geo + an expandable target).

### Changed

- **Documentation accuracy sweep — every doc reconciled to ground truth.**
  Converged all docs on the authoritative counts (**118 modules = 89 free · 24
  key-gated · 5 paid**, **59 rules** AU-001…AU-059, v1.4.0, rusqlite 0.39,
  reqwest 0.12). Fixed stale module names (`dns_resolver`→`dns_intel`,
  `email_to_username`→`name_intel`, the consolidated sensor modules), `*.rs`→
  directory path-rot, the `panic="unwind"` facts (correcting `FAULT_TREE`'s
  inverted premise), re-bucketed the `MODULES.md` catalogue (the AU `People`
  modules), and regenerated `ARCHITECTURE_AUDIT.md` as a current-state reference.
  A follow-up **2026-06-17 multi-agent doc audit** re-reconciled the whole set:
  corrected the stale `core → modules` "Known gap" in `ARCHITECTURE_AUDIT`/
  `CONVENTIONS` (T1.4 is done + guarded), **completed the README per-category
  catalogue** (it listed only 98 of 118 modules), fixed `MODULES.md`'s `wigle`
  priority (18→10), corrected several USAGE command/flag descriptions
  (`diagnostics`, `export` formats, the non-existent `--regional` flag, the
  missing `set-key`), refreshed metrics (`.rs`/LOC/locked-pkg/test counts), and
  logged two new robustness nodes (**T2.8** unbounded response-body reads,
  **T2.9** non-deterministic UI-summary SQL orderings).
- **Neutralised militarised framing in code comments** to neutral OSINT
  terminology (SpiderFoot/Maltego-aligned); no behaviour change.

- **New `onyphe` module — ONYPHE cyber-defence search (key-gated).** Wires up
  the `HUNTSMAN_ONYPHE_KEY` that was registered in the service registry but had
  no consuming module (a held key doing nothing). Queries ONYPHE's API v2
  `summary/ip/{ip}` and `summary/domain/{domain}` endpoints (lowercase `bearer`
  auth) and extracts geolocation (coordinates + city/country), the ASN + operator
  org, resolved IPs, and passive-DNS hostnames/subdomains. The parser is
  **schema-tolerant by design** — it walks ONYPHE's heterogeneous `@category`
  result documents as raw JSON and pulls whatever identifying fields are present
  (`location` "lat,lon" string *or* separate `latitude`/`longitude`; `hostname`/
  `domain` as string *or* array), so it degrades to fewer entities rather than
  failing on ONYPHE's per-category / per-plan shape variance. Emitted domains
  pass through `is_noncentral_domain`, so a resolver's CDN/mega host can't
  pollute the graph. Brings the catalogue to **118 modules (89 free · 24
  key-gated · 5 paid)**. The live response shape should be confirmed once on a
  real key — the request/auth/endpoints follow ONYPHE's documented v2 schema.

- **Wolfram-verified ground-truth tests for the GEOINT location-fusion
  estimators.** The geometric median (Weiszfeld), its confidence-weighted form,
  and the minimum enclosing circle are the engine's critical "where is the
  subject" estimators, so their optima are now pinned to values computed
  independently in **Wolfram Language** — `FindArgMin` over the projected
  distance sum for the medians, `BoundingRegion[…,"MinDisk"]` for the circle —
  over the same equirectangular frame the code uses. The Rust implementations
  reproduce Wolfram's optima exactly for the Chebyshev centres and to ~1e-6° for
  the medians (no production change was needed — the algorithms were already
  correct), including a singularity case where a dominant high-confidence
  sighting *is* the weighted Weber point. A future refactor that drifts either
  estimator off its optimum now has to disagree with Wolfram to pass CI.
- **Built-in OathNet batch query generator (`hse oathnet-batch`).** A new
  command + pure `util::oathnet_batch` generator that expands a single seed into
  a large, de-duplicated array of distinct OathNet queries across three axes:
  **surface** (breach, plus the stealer corpus for login-indexable selectors),
  **selector field** (the seed's native field plus derived ones — an email's
  local part becomes a `username` search and its domain a `domain` search), and
  **value permutation** (names and email local parts fan out into the handle
  shapes real accounts use — `first.last`, `flast`, `firstl`, reversed and
  middle-name blends; phone numbers fan out into their digit-only / AU-E.164 /
  `+`-prefixed formats). A `john.doe@example.com` seed generates ~20+ distinct
  queries; a full name, ~12+. The generator is pure and deterministic (seed
  queries first, then derived, exact duplicates collapsed), so the plan can be
  previewed for free — `hse oathnet-batch -v <seed>` prints the plan and spends
  nothing; `--execute` dispatches it, bounded by the shared per-session OathNet
  budget (the per-scan cap is lifted for the deliberate batch, but the session
  ceiling still caps daily spend). Flags: `--no-stealer`, `--no-permute`,
  `--synthesize-emails`, `--max`, `--page-size`, `--json`. The generator's public
  API carries runnable doc examples, its guarantees (determinism, seed-first
  ordering, de-duplication, well-formed/bounded output) are documented *and*
  enforced by invariant tests, and malformed email hosts are guarded — a stray
  `@` (from a double-`@` address) or a dotless host is no longer searched as a
  domain.

### Changed

- **`ipapi` IP-geolocation moved to ipwho.is over HTTPS (was HTTP-only
  ip-api.com).** The free ip-api.com tier is HTTP-only, so every IP the module
  geolocated travelled in cleartext — on the phone target, a network observer
  could read which IPs the device was investigating. Worse, `ip_geo` *also* used
  ip-api.com, so the correlator counted the same provider twice as if it were
  two independent sources ("two sources agree on location"). `ipapi` now uses
  **ipwho.is** (HTTPS, free, no key): the IP-geo query is encrypted, and `ip_geo`
  (kept on ip-api.com for its proxy/hosting/mobile flags) and `ipapi` are now
  genuinely independent providers, so geo corroboration is real. Trade-off:
  ipwho.is exposes no proxy/hosting flags or reverse-DNS, so `ipapi` no longer
  tags those or emits a PTR `Domain` (both still come from `ip_geo` / `dns_intel`
  respectively). Response shape verified against the live API.

- **Airtight, offline-by-construction local web console (Termux/phone
  hardening).** The embedded UI already shipped a strict CSP, security-header
  middleware, vendored same-origin assets, and a `data:` favicon — so it makes
  no external requests. This locks that guarantee so it can't silently regress
  and tightens it for the phone:
  - Added a restrictive **`Permissions-Policy`** denying every powerful browser
    feature (camera, microphone, geolocation, USB, Bluetooth, serial, HID, MIDI,
    motion sensors, payment) with empty `()` allowlists, plus `interest-cohort=()`.
    The SPA uses none of these APIs, so denial is free; on the phone target it
    means a hypothetical injection still can't reach the device's sensors.
  - Added source-level tripwires: the CSP is asserted to name **no** external
    origin or `*` wildcard (closing the hole that a substring check like
    `contains("connect-src 'self'")` leaves open against
    `connect-src 'self' https://exfil`), every CSP directive token is checked to
    be `'self'`/`'unsafe-inline'`/`'none'`/`data:` only, and the embedded SPA is
    scanned to prove it auto-loads no external `<script>`/`<link>`/`<img>`
    resource (the scanner is itself tested against a CDN sample). The served
    `Permissions-Policy` is asserted in the API integration tests.

- **Intelligence X selector coverage widened to match the API.** IntelX
  auto-classifies a search term across its full `SelectorType` table, but the
  module only accepted email / username / phone / name / domain / IP. It now
  also accepts **URL, CIDR, MAC address, and crypto (Bitcoin) address** — all
  kinds IntelX has dedicated selectors for and that other modules already emit
  as entities, so an expansion can now pivot them through IntelX. Coverage is
  defined once in a new single-sourced `intelx_selector` map that drives
  `accepts` (and is documented + exhaustively tested, including a compile-time
  tripwire that forces any newly-added `TargetKind` to be classified); kinds
  IntelX cannot resolve (ASN, coordinates, ABN/ACN, organisation, address, API
  key) are still declined so a paid query is never wasted. `produces` was
  extended to match. No change to the (already-correct) two-phase search/poll.

- **Single-sourced the OathNet query vocabulary.** The surface↔path mapping
  (`Surface`) and the target-kind↔selector-field mapping (`selector_field`,
  `stealer_indexable`) now live once in `util::oathnet` and are consumed by both
  the `oathnet_pro` scan module and the new `oathnet_batch` generator, instead
  of each re-encoding the field names (`email`/`username`/`q`/`ip`/`domain`) and
  the breach/stealer routing. As part of this, `oathnet_pro::process` lost its
  inline kind→field `match`: the field comes from `selector_field`, and the
  per-kind junk gates were extracted into a pure, separately-tested
  `should_skip_preflight`. Behaviour is unchanged (a batch plan for a sample
  email still generates the same 23 queries); the win is that adding a kind or
  renaming a field updates both consumers at once.

- **DeHashed module migrated to the v2 API.** DeHashed sunset the v1
  `GET https://api.dehashed.com/search` endpoint (HTTP Basic with an account
  email + key) — it now returns **404**, so the module was dead for everyone.
  It now calls `POST https://api.dehashed.com/v2/search` with the key in a
  `Dehashed-Api-Key` header and a JSON body (`{"query","page","size"}`). v2 is
  **key-only**, so the obsolete `HUNTSMAN_DEHASHED_USER` account-email variable
  is removed across the module, `KNOWN_KEYS`, the env templates, and the
  service registry (its GET-based key validator can't probe a POST-only
  endpoint, so the two now-unprobeable DeHashed service defs were dropped
  rather than left mis-reporting valid keys as invalid). Response parsing
  follows the v2 shape: `database_name` is read as an array (folded into the
  top-databases aggregate), the new top-level `balance` is surfaced as
  `credit_balance`, and the v1-only `obtained_from`/`created_at` aggregates are
  dropped. The no-credentials-in-evidence invariant is preserved and now
  regression-tested against the real v2 wire shape (an entry's
  `password`/`hashed_password` are never bound). Note: DeHashed v2 requires an
  **active search subscription** in addition to API credits — without it the
  endpoint returns `401 "You need a search subscription and API credits to use
  the API"`, which the module now surfaces verbatim.

### Fixed

- **Stopped two modules from emitting shared-infrastructure domains as
  entities (CRITICAL dossier pollution).** On-device scans flagged
  *infrastructure-pollution* — provider/platform domains that map a third
  party's estate, not the subject, inflating the entity set and correlations.
  Two emitters bypassed the authoritative `is_noncentral_domain` gate:
  - `social_probe` emitted each confirmed platform's **apex domain**
    (`instagram.com`, `tiktok.com`, `twitch.tv`, `pinterest.com`, `threads.net`)
    as a `Domain` entity "for infrastructure expansion" — dragging the scan into
    mapping the platform's own DNS/CDN. The profile URL + handle (the actual
    findings) are still emitted; only mega/social/infra apexes are now
    suppressed, so a niche or self-hosted host that might belong to the subject
    still surfaces.
  - `email_parse` gated its extracted mail domain on the narrow freemail list
    only, so providers in the authoritative set but absent from it — ISP webmail
    (`rr.com`), regional providers (`web.de`), data brokers (`peekyou.com`) —
    leaked as `Domain` entities. It now also consults `is_noncentral_domain`; a
    genuine corporate/self-owned mail domain is unaffected.

  Both paths are pinned by regression tests.

- **Finished the `signal_radar` module's integration so the build is green.**
  The real-time multi-sensor radar module was registered but its supporting
  declarations had not caught up, leaving three architecture-guard tests red:
  it claimed MITRE ATT&CK sub-technique **`T1592.001` (Hardware)** — the correct
  mapping for the Bluetooth / WiFi MAC and cell-radio identifiers it collects —
  but that ID was absent from the `core::attack` Reconnaissance catalogue; it
  was missing from `docs/MODULES.md`; and the README headline module count still
  read 113. Added `T1592.001 (Hardware)` to the catalogue (sorted between
  `T1592` and `T1592.002`), listed `signal_radar` in the MODULES.md `sensor`
  section, and bumped every operator-facing count to the live registry size
  (**114 modules — 89 free · 20 key-gated · 5 paid**). `cargo test --all` is
  green again.
- **Repaired dead module references in the web-UI scan presets.** The New-Scan
  use-case presets selected their module set by name, and seven names had rotted
  past module renames/merges — `dns_resolver` / `reverse_dns` / `dns_brute` /
  `ip_rdap` (Footprint) and `alienvault_otx` / `tor_exit_check` /
  `email_to_username` (Investigate) — so those modules silently dropped out of
  the preset with no error, quietly shrinking coverage in Chrome. Each is now
  mapped to its current equivalent (the DNS trio → `dns_intel` / `doh_resolver`
  / `dns_axfr`, `ip_rdap` → `rdap_domain`, `alienvault_otx` → `threatfox`,
  `tor_exit_check` → `greynoise`, `email_to_username` → `email_parse`). A new
  `spa_scan_preset_modules_are_all_registered` guard test pins every preset name
  to the live registry so this class of drift fails CI instead of degrading the
  UI unnoticed.
- **Corrected stale figures in `docs/INSTALL.md`** — the verification snippet
  cited `hse 1.3.0` (now `1.4.0`), `92 modules` (now `114`), a non-existent
  `email_to_username` module in the example scan (now `email_parse`), and an
  outdated web-UI tab list; the smoke test now names the real nav tabs
  (Dashboard, New Scan, Scans, Live, Engines, Settings).

- **WiGLE account introspection now actually detects the email-unverified
  throttle.** `refresh_account_status` deserialised the `/api/v2/profile/user`
  response with the wrong field names — it read `user`/`verified`, but the
  WiGLE `Person` object (per the published swagger schema, confirmed live)
  names them `userid` and `emailVerified`. Both therefore always parsed to
  `None`, so `is_unverified()` could never fire and `hse doctor` reported
  `email-verified: unknown — /profile/user not reachable` even when the
  endpoint was reachable and the account was plainly unverified — defeating
  the entire purpose of the check (WiGLE silently throttles DB queries until
  the email is confirmed). The parser now reads the real fields and trims the
  trailing space WiGLE pads onto `userid`. Additionally, the second poll to
  `/api/v2/profile/apiUsage` was removed: that path has never existed (it
  always 404'd), so the `daily_api_calls`/`monthly_api_calls` fields it fed
  were structurally always `null`. They are dropped from `WigleAccountStatus`,
  the `/api/v1/stats` `wigle.account` block, and `hse doctor` output. Locked in
  with a regression test that parses the real `Person` wire shape.

## [1.4.0] — 2026-06-09

### Added

- **Five-method "hardest-to-find people" lane.** A coherent set of correlation
  rules for the intersection of *works on a target who is hiding* and *works on
  the average person*: **AU-047** reused-secret identity linkage (a globally
  unique salted hash / key seen against ≥2 emails links them), **AU-048** shared
  public-key linkage (cryptographic proof of one controller), **AU-049**
  shared-address household, **AU-050** shared-phone association, and **AU-051**
  shared-surname kin (likely relatives). Fed by new keyless harvesters —
  GitHub commit-author email extraction and SSH-key fingerprints — and by
  promoting a breach record's `address` to a first-class `Address` entity. Every
  link is precision-gated (unique artifacts / distinct named people only) so it
  never fuses unrelated strangers.

- **Convex geographic location toolkit (`util::geometry`).** Pure, deterministic,
  dependency-free computational geometry over coordinates: convex hull (Andrew's
  monotone chain), minimum enclosing circle (Welzl — the Chebyshev centre),
  geometric median (Weiszfeld — now **confidence-weighted** and
  **equirectangular-corrected** for longitude anisotropy), weighted centroid,
  point-in-hull, a robust median-distance radius, and a `LocationFix` bundle.
  Surfaced by **AU-052** (geographic area of operation — the footprint plus a
  robust+confidence-weighted location fix with both a robust and a worst-case
  radius) and **AU-053** (out-of-area location anomaly via hull membership). A
  positive **person-anchor gate** keeps infrastructure coordinates (CDN /
  datacenter, IP/WHOIS geo, chronolocation, Overpass map POIs) out of a subject's
  footprint — hardened against two live scans where they would otherwise have
  manufactured a fictitious location.

- **Convex (optionality / barbell) budget allocation (`--convex-budget`).** Opt-in
  expansion re-weighting (`core::convex`) by a convexity premium for heavy-tailed
  upside over per-kind dispatch cost, steering the bounded Termux budget toward
  cheap, high-optionality identity leads and away from saturated infrastructure.
  Off by default — the base expected-value ranking is unchanged.

- **`name_intel` email recall ranked by P(handle) × P(provider).** The email
  permuter no longer sprays one handle shape across every provider before trying
  the next; it ranks the full handle×provider cross-product by the product of
  handle commonality and provider market share, and the default provider set
  covers the mainstream consumer mailboxes (incl. older demographics — `live.com`,
  `aol.com`). Spends the bounded budget where the median person's real address
  actually lives.

- **Full pipeline transparency — no black-box decisions.** Every pivot the
  expansion engine *declines* to follow now emits an `entity_excluded` event with
  a precise reason: `below_min_expand_confidence`, `roi_saturated`,
  `identity_mismatch`, `non_routable_ip`, `incidental_infra`, and the two
  previously-silent cases `non_pivotable_kind` and `already_dispatched_this_scan`.
  Admission-time rejections (`bogus_ip`, `placeholder_artifact`, `fragment_value`)
  — previously dropped silently — now emit the same event. A scan can no longer
  discard a lead without saying why.

- **`--expand-all-identities` scan flag (implied by `--full`).** Lifts the
  wrong-identity gate so *every* discovered username/person expands, including
  uncorroborated single-source aliases that share no handle overlap with the
  subject — maximum recall when the operator would rather over-collect and prune
  by hand. The gate stays on by default (focused scans), and every suppressed
  alias is still logged as `identity_mismatch`. The decision is now a pure,
  unit-tested `scan::is_wrong_identity_pivot`.

- **Self-audit surfaces the recursion exclusion ledger.** `hse audit` and the
  web **Audit** panel fold a scan's `entity_excluded`/`expansion_stop` events into
  an `expansion` block (per-reason counts + stop reasons) and raise two findings:
  `recursion-recall` (escalates to MEDIUM when the wrong-identity gate dominated
  the kept graph — with the `--expand-all-identities` remedy) and an INFO
  `expansion-ledger` for expected dedup/terminal-kind exclusions. A golden
  regression benchmark (`tests/audit_regression.rs`) pins the score and finding
  set so a scoring change must be deliberately re-blessed.

### Fixed

- **Truncated `@gmail`-style fragments are rejected at the source.** A new shared
  `validation::is_fragment_value` rejects domain-less emails, dotless hosts and
  `@`-prefixed handles at the admission boundary, so an unverifiable fragment
  never enters the graph or reaches the UI. The auditor independently flags any
  that slip through (`fragment-values`).

- **`@handle` and `handle` are now one identity.** Username normalisation strips a
  leading `@` sigil, so a profile scraped as `@jordanavery` and one parsed as
  `jordanavery` dedup to a single UID instead of fragmenting into two — and
  the `@`-prefixed copy no longer trips the fragment auditor.

- **No false geolocation from CDN/anycast edge IPs in `ipquery`/`ip2location`.**
  Both modules emitted Coordinates + Address for Cloudflare/Fastly edge IPs at
  0.58–0.68 confidence — the datacenter's location, not the subject's — seeding
  false "geolocation convergence". They now apply the same `is_cdn_edge_ip` guard
  `ip_geo`/`ipinfo` already use, skipping the false geo while keeping the
  legitimate ASN/ISP-org infrastructure entities. All four IP-geo modules log the
  skip so a dropped fix is never silent.

- **Search-result evidence is preserved, not silently truncated.** Title/snippet
  preview caps were raised (200→500 / 800→4000 chars) and, when content still
  exceeds them, `*_truncated` + `*_full_len` attributes are recorded so a finding
  is never implied complete; the key-phrase is extracted from the full snippet,
  not the preview. Recycled address/email/phone findings now carry full source
  attribution (page title, snippet, originating query, surrounding-text context).
  Email/phone extraction caps were raised 10× and the ceiling is logged.

### Performance

- **Correlation rule AU-034 (handle reuse) is now linear, not quadratic.** It
  re-derived `canonical_handle` for every email *inside* the per-username loop —
  O(U×E) string allocations — and profiling showed it accounted for ~98% of the
  entire correlation pass, which runs after every expansion round. Emails are
  now bucketed by their canonical local-part handle once (O(E)); each username
  resolves its matches with a single hash lookup. Measured on a synthetic mixed
  entity set, the full correlation pass dropped from 127 ms to 10 ms at 5 000
  entities (12.7×) and now scales linearly with entity count — a per-round stall
  a broad breach/stealer scan on a phone would otherwise hit repeatedly.
  Behaviour is unchanged (the matched set was already order-independent, and the
  existing AU-034 tests — including multi-email grouping — still pass).

- **Web UI responses are gzip-compressed (`tower-http` `CompressionLayer`).**
  The embedded SPA (~118 KB) and vendored asset bundle (~528 KB) were served
  uncompressed on every cold load — the dominant web-UI cost on a phone's mobile
  link. gzip brings the SPA to under 60 KB on the wire (~4×) and applies to
  large scan-result JSON exports too. The gzip backend is `flate2`/`miniz_oxide`
  — pure Rust, no C/zlib dependency, preserving the no-native-libs Termux build.
  `CompressionLayer`'s default predicate skips already-small bodies and
  `text/event-stream`, so the SSE live-scan stream is never buffered or
  compressed (would stall the live event log). The existing vendor-asset
  ETag/`304` revalidation is unchanged, so warm loads still skip the body
  entirely. Two contract tests guard it: the SPA arrives gzip-encoded and
  materially smaller for a gzip-capable client, and the SSE stream stays
  identity-encoded.

### Security

- **SSRF guard blocks reserved Class E (240.0.0.0/4).** `preflight::is_private_addr`
  rejected RFC1918, loopback, link-local (incl. cloud metadata), CGNAT, 0/8,
  multicast and broadcast, but not the reserved-for-future 240.0.0.0/4 range
  (multicast only covers 224–239; broadcast only `255.255.255.255`). A target in
  240–254.x is non-globally-routable and is now denied, consistent with the
  guard's deny-non-public stance. Public space just below (223.x) stays allowed.
  Covers both bare-v4 and IPv4-embedded-in-IPv6 (NAT64/6to4/compat) paths via the
  shared `is_private_v4`. Tested.

- **GEXF export strips XML-illegal control characters.** `xml_escape` escaped
  the five XML metacharacters but passed control bytes through verbatim. An entity
  value carrying a stray C0 control char (breach dumps and scraped pages do)
  produced a `.gexf` that Gephi/any XML parser rejects *wholesale* — one dirty
  value breaking the entire export. The serializer now drops the C0 controls XML
  1.0 forbids (keeping tab/LF/CR) and the U+FFFE/U+FFFF noncharacters; legal C1
  controls are preserved. Tested.

- **Saving an API key with a space no longer corrupts env-file loading.**
  `write_keys` (the web Settings "save keys" path) validated values against
  newlines/quotes but wrote them **unquoted** (`KEY=value`), and `validate_value`
  permits spaces — so saving e.g. `HUNTSMAN_DEFAULT_SEED=John Smith` produced a
  line `dotenvy` cannot parse. Because `load()` ignores the parse Result, that one
  bad line breaks loading of keys after it in the file. Values are now written
  double-quoted (`KEY="value"`), which round-trips spaces and `#`; since dotenvy
  processes escapes inside double quotes, `validate_value` additionally rejects a
  literal backslash (alongside the existing `"`/control-char rejection) so the
  quoted value round-trips byte-for-byte. Verified by a write→`dotenvy` round-trip
  test across plain/space/`#`/`=` values. Existing unquoted lines are still
  preserved verbatim; only keys the UI writes are quoted.

- **Redirect SSRF guard now catches IPv6-literal hops.** The HTTP client's
  redirect policy fed `Url::host_str()` straight to `is_private_ip`, but `url`
  2.5 returns IPv6 literals *bracketed* (`[::1]`), which fails the `IpAddr`
  parse and returned `false` — so a public site could `3xx` the client onto an
  IPv6-literal internal address (loopback `[::1]`, ULA, link-local, or
  IPv4-mapped/NAT64 cloud-metadata `[::ffff:169.254.169.254]`). The DNS-resolver
  SSRF filter does not cover this path because IP-literal hops are dialled
  without a lookup. The guard now strips brackets before the parse, mirroring
  `preflight::url_host_is_private`. Bare-v4 hops and public IPv6 hops are
  unaffected. Regression-tested across loopback/ULA/link-local/mapped/NAT64.

### Fixed

- **`see_know` no longer emits raw record sub-structures as entities.** The
  catch-all that surfaces every leftover field as an `Other(field)` node
  stringified nested JSON objects/arrays too — so a domain record's `dns` map
  (`{"A":[…],"AAAA":[…]}`) and WHOIS metadata (`registrar`/`created`/`updated`/
  `expires`/`status`/`nameservers`) became junk graph nodes whose value was an
  unusable JSON blob. The catch-all now surfaces **scalar** fields only (its
  documented intent), and the domain WHOIS/RDAP field names are skip-listed
  (surfaced as Domain *attributes* by `rdap_domain`/`whoisxml`). Verified live:
  a `--full` scan that emitted 7 `Other`/blob entities now emits 0, with the real
  breach/stealer intel (passwords, api keys, persons) surfacing cleanly.

- **SPF parsing honours mechanism qualifiers.** `spf::members` matched `ip4:` /
  `ip6:` / `include:` with a bare `strip_prefix`, so a mechanism carrying a
  qualifier — `+`/`-`/`~`/`?` (RFC 7208 §4.6.1), e.g. `-ip4:192.0.2.0/24` or
  `?include:_spf.example.com` — failed the match and was silently dropped,
  costing the DNS modules (`dns_intel`, `doh_resolver`) real IP/include pivots
  from any record that qualifies its mechanisms. The optional leading qualifier
  is now stripped before the mechanism match; the `redirect=` modifier (which
  takes no qualifier) is unchanged. Tested across all four qualifiers.

- **Username people-search provenance requires a host-label boundary.** The
  `score_username` people-search signal used `host.ends_with(provider)`, so an
  unrelated host ending with a provider string mid-label (`myspokeo.com`,
  `notwhitepages.com`) wrongly earned the +3 provenance boost. It now matches the
  host itself or a subdomain (`host == p || host.ends_with(".{p}")`) — the same
  dot-boundary predicate the aggregator-suppression check in the same file
  already used. Tested.

- **AXFR subdomain harvest rejects out-of-zone names and is case-insensitive.**
  `attempt_axfr` kept any record whose lowercased name `ends_with(domain)`, so a
  hostile/buggy server could inject an out-of-zone name (`evilexample.com` for a
  zone `example.com`), and a case difference between the queried zone and a
  returned record could drop a legitimate subdomain. It now keeps a record only
  when it is a true subdomain (`ends_with(".{zone}")` with the zone lowercased
  once). Defensive; behaviour unchanged for well-formed transfers.

- **`email_header_geo` corporate-provider detection matches at a label boundary.**
  `detect_corporate_provider` used a plain `domain.contains(token)` over the
  regional ISP brand tokens, so an unrelated domain containing a provider token
  mid-label was mis-attributed a country — `campbell.net` → Bell Canada,
  `platt.net` → AT&T, `foxcox.net` → Cox, `brisksky.com` → Sky UK. The token must
  now *begin a host label* (start, or after a separator), so subdomains and the
  providers' several TLDs (`bigpond.com.au`/`bigpond.net.au`, `mail.bigpond.com`)
  still match while the mid-label fragments do not. Mirrors the existing
  dot-boundary handling for `CONSUMER_PROVIDERS`. Tested.

- **`identify_service_from_url` matches at host-label boundaries, not any
  substring.** It tagged a stealer/breach record's source service with a plain
  `url.contains(domain)`, so a host that merely *contained* a known service
  domain mid-label was mis-tagged — `passwordhashes.com` → `hashes`,
  `hashes.community` → `hashes`, `snusbase.com.au` → `snusbase`. Matching is now
  host-label-aware (left boundary must not be a label char, so subdomains like
  `api.snusbase.com` still match; right boundary must end the host, so a longer
  label or different TLD does not), while staying substring-based so messy
  breach-record URLs without a scheme/port/path still resolve. Tested.

- **`riskiq.net` is tagged `riskiq`, not `passivetotal` (dead-data fix).** The
  API-service-domain table listed `riskiq.net` twice — once in the PassiveTotal
  cluster and once (correctly) in the RiskIQ cluster. Since `identify_service_from_url`
  returns the first substring match, the PassiveTotal duplicate shadowed the real
  entry, so every `riskiq.net` URL in a stealer/breach record was mis-tagged and
  the `riskiq` entry was dead. Removed the stray duplicate; `riskiq.net` now
  resolves to `riskiq` (its own brand), and PassiveTotal is still detected via
  `passivetotal.org`. Regression-tested, plus a new structural guard (above).

- **`url_util::host_only` keeps a bracketed IPv6 literal intact.** It dropped the
  `:port` by splitting on the first colon, which truncated an IPv6-literal
  authority (`[2606:4700::1]:443`) to `[2606` — the inner colons are part of the
  address, not a port delimiter. Downstream callers then keyed on the corrupted
  host: the whois query, the Wayback CDX lookup, and the raw-archive provider
  label. A bracketed literal is now returned whole (brackets included, matching
  `Url::host_str`); scheme/path/port handling for every other host is unchanged.
  Tested.

- **curl fallback no longer refuses every IPv6-literal target.** The SSRF pin
  (`ssrf_resolve_pin`) fed `Url::host_str()` to `tokio::net::lookup_host`, but
  IPv6 literals come back *bracketed* (`[2606:…]`) and `getaddrinfo` rejects the
  brackets — so the lookup failed and **all** IPv6-literal URLs (public ones
  included) were refused on the curl path, while IPv4 literals got a pointless
  `--resolve host:port:host` (curl dials a literal directly; there is no name to
  rewrite). IP-literal hosts are now vetted in-process (brackets stripped, parsed,
  checked against the private/reserved set) and accepted with no `--resolve` arg;
  private/reserved literals — including `[::1]`, ULA, and IPv4-mapped metadata —
  still fail closed. Hostname pinning is unchanged. Regression-tested.

- **Entity search escapes the LIKE escape character.** The `search_entities`
  LIKE fallback (used when FTS5 yields nothing) escaped `%` and `_` under
  `ESCAPE '\'` but not `\` itself, so a backslash in the query consumed the
  following character — searching `\` matched a literal `%` and missed real
  backslashes (e.g. a Windows path). The escape char is now escaped first.
  Wrong-results bug, not a crash (the FTS path and parameterisation were already
  safe); regression-tested via the fallback.
- **AU-016 breach-IP→geolocation chain no longer matches a substring IP.** It
  linked a breach IP to a coordinate when the coordinate's evidence summary
  *contained* the IP string — but `"11.2.3.45".contains("1.2.3.4")` is `true`, so
  a breach IP could falsely chain to the coordinates of an unrelated IP that
  contains it as a substring (a spurious `High` finding). Matching is now
  anchored: a hit flanked by an IP-extending char (digit or `.`) is rejected,
  while a legitimate boundary (`"1.2.3.4: City"`, `"1.2.3.4:8080"`) still matches.
  Regression-tested.
- **AU-019 temporal breach clusters are bounded to a real 30-day window.** The
  rule reports breaches "clustered within 30 days" (potential coordinated
  compromise, `High`), but it measured the gap between *consecutive* sorted dates
  and rolled the reference forward each step — so a chain like Jan 1 / Jan 30 /
  Feb 28 / Mar 30 (each pair ≤30 days) collapsed into one ~88-day "cluster",
  contradicting the claim. The 30-day window is now anchored to each cluster's
  earliest date, so every reported cluster genuinely spans ≤30 days. Stricter
  (fewer false coordinated-compromise findings on slow rolling activity);
  regression-tested with both a real tight cluster and the chained case.
- **Hex hash/key blobs are no longer misclassified as Bitcoin wallets.**
  `core::crypto::classify_crypto_address` documents that a 32/64-char hex blob
  must stay a key, but the legacy-BTC branch (`1…`/`3…`, 26–35 base58) broke it:
  base58 excludes only `0` among the hex digits, so a 32-char MD5 with no `0` and
  a `1`/`3` lead satisfied `all(is_base58)` and resolved to `crypto_btc`. With
  ~13% of MD5s lacking a `0`, that mis-minted ~1–2% of password hashes as
  cryptocurrency wallets — polluting the entity graph and firing the crypto
  correlators on hashes. The prefix-less/short base58 branches now reject
  all-ASCII-hex candidates (a genuine base58 address is never all-hex,
  `p < (15/58)²⁶`); `0x`-ETH and bech32 are prefix-disambiguated and untouched.
  Proved by an exhaustive test (no all-hex string of any length/lead digit is
  ever classified) while the real BTC/ETH examples still resolve.
- **`abn::company_names` keeps the "& Co" idiom attached in a syndicate.**
  It split joint-owner strings on `&`, but that `&` is also part of a single
  company name: `"Ashton & Co Pty Ltd & Berg Pty Ltd"` split into a bogus
  standalone `"Co Pty Ltd"` (which itself passes `looks_like_company`), so the
  ABN register was queried for the wrong name. A segment whose first word is
  `CO`/`COMPANY` is now rejoined to its predecessor before the syndicate split;
  single `"& Co"` companies and genuine multi-company syndicates are unchanged.
  Regression-tested.
- **Company legal-form detection survives trailing punctuation.**
  `abn::looks_like_company` matched suffixes (`LIMITED`, `LTD`, `INC`, `NL`,
  `& CO`, …) as space-bounded tokens, so a form as the final token followed by
  punctuation — `"ACME HOLDINGS LIMITED."`, `"WIDGETS LTD;"`, `"ACME INC,"` —
  failed the match and the owner was misread as an individual, suppressing the
  ABN/ACN resolvers for a real company. Punctuation (except `&`, which is part of
  `"& CO"`) now folds to spaces before matching; the canonical suffix list also
  shed its period variants as a result. No regression — the word-boundary safety
  cases (`INCANDESCENT`, `ALTDORF`) and `"& CO"` handling still hold; coverage
  added for the punctuation forms.
- **Entity UID normalisation is now idempotent for domains (repeated `www.`).**
  The `Domain` arm of `normalise` stripped only the *first* leading `www.` label,
  so `www.www.foo.com` normalised to `www.foo.com` — which itself re-normalised to
  `foo.com`. Because the normalised value keys the UID, a host that was re-emitted
  or re-normalised could shift UID and fail to dedup against the same host seen
  once. The strip now consumes *all* consecutive leading `www.` labels in a single
  pass, so the result is a fixed point (`normalise(normalise(v)) == normalise(v)`).
  Found and locked down by two new cross-kind invariant tests — idempotency for
  **every** `EntityKind` and case-fold invariance for the folded kinds
  (Email/Username/Domain) — over an adversarial corpus (non-ASCII capitals,
  `+tag` emails, mixed-case URLs, coordinates, MAC/IPv6 forms). These guards are
  what surfaced the bug and now prevent the whole class from recurring.
- **Entity UID normalisation folds non-ASCII uppercase, so internationalised
  emails/usernames dedup correctly.** `normalise` (which keys every entity's UID)
  had an `Email | Username` fast path that returned the value unchanged whenever
  it contained no *ASCII* uppercase byte. A value whose only capital was
  non-ASCII — a German/Scandinavian name like `Ölaf`, a Cyrillic/Greek handle, or
  Turkish dotted `İstanbul` — therefore skipped case-folding entirely, while its
  all-caps spelling (`ÖLAF`) folded normally. The two spellings got different
  UIDs, so one real identity fragmented into separate entities that never merged
  or corroborated. Folding is now total (`str::to_lowercase`, full Unicode) — the
  same bug class as the earlier `email_locale`/`email_header_geo` fixes, here in
  the core dedup path. The removed fast path also still allocated, so it bought
  nothing. Regression-tested across Latin-1, Greek, and Turkish capitals.
- **`email_locale` matches mixed-case names instead of silently missing them.**
  Its surname-suffix and given-name detection compared an *un-lowercased* email
  local part against all-lowercase pattern tables (`first == "guillaume"`,
  `last.ends_with("sson")`), and `Target::validate` doesn't case-fold the email —
  so the everyday `Guillaume.Martin@…` / `ERIK.JOHANSSON@…` forms detected no
  locale at all (only the lowercase spellings the tests happened to use worked).
  The name parts are now folded with `to_lowercase` (Unicode, so the `ström` /
  `oğlu` suffixes fold too) before matching. Regression-tested.
- **`email_header_geo` folds the email domain before matching.** The same class
  of bug as `email_locale`: the domain after `@` was tested against the
  lowercase ccTLD / regional-provider tables (`ends_with(".com.au")`,
  `contains("bigpond")`) without case-folding, so a mixed-case
  `User@Bigpond.COM.AU` geolocated to nothing. DNS labels are case-insensitive
  (RFC 4343), so the domain is now lowercased first. Regression-tested.
- **IP/WiFi-geo providers no longer emit out-of-range or non-finite
  coordinates.** Six coarse-geolocation modules — `ip_geo`, `ipinfo`, `ipapi`,
  `ip2location`, `ipquery`, `wigle` — gated their `Coordinates` entity on a bare
  `lat.abs() > 0.01 && lon.abs() > 0.01` (and `ip_geo` on nothing at all). That
  dropped null island but silently let a malformed provider `loc` like
  `500,999`, `inf,inf`, or `NaN` through as a *high-confidence* fix — exactly the
  false-fix that poisons the geo-cluster correlator, and the reason
  `util::geo::is_valid_coords` exists. They now share a new
  `util::geo::is_plausible_provider_coord`, which folds the range/finite
  validity check in with the null-island band so the gap can't reopen in one
  module at a time. The eight modules already on `is_valid_coords` are
  unchanged. Unit-tested (range, finite, and band cases).
- **Forward geocoders validate their coordinates too.** `geocode`, `photon`,
  `overpass`, and `mls` turned an external lat/lon straight into a `Coordinates`
  entity without a range/finite check — the same straggler gap. They now gate on
  `is_valid_coords` (the *no-band* form: geocoding a real equatorial place is
  legitimate, so the IP-provider null-island band must not apply here). A
  malformed geometry or null-island fix is dropped instead of surfaced.
  Regression-tested via `photon::build_forward`.
- **OUI classifier recognises Tesla's `DC:44:27` prefix again.** One entry in
  the curated `util::oui` table was mis-typed as a 7-character `"DC44271"`.
  `classify_mac` extracts the first **6** hex digits of a MAC and compares for
  equality, so this prefix could never match any input — a Tesla on the
  `DC:44:27` OUI silently classified as `Unregistered`. Corrected to `"DC4427"`
  (its real IEEE registration) and guarded by a new structural test
  (`oui_table_prefixes_are_well_formed`) asserting every table prefix is exactly
  6 uppercase-hex chars, so a future typo fails the suite instead of going dark.
- **`geo_intel` no longer geolocates Caribbean phone numbers to the United
  States.** Its `phone_prefix_to_country` only scanned 1-3 digit dialling codes,
  but the Caribbean NANP territories share country code +1 with a *4-digit* prefix
  (`1242` Bahamas, `1876` Jamaica, …) — so every such number fell through to `1`
  and was placed at the US centroid, an actively-misleading wrong-country fix. It
  now defers the +1 question to `phone_intl::match_country` (the single source of
  truth, which knows the 4-digit codes) and returns `None` for a non-US/CA NANP
  territory rather than a wrong US location. `phone_intl::match_country` is now
  `pub(crate)` so the two modules share one prefix table instead of diverging.
  Regression-tested.
- **`web_crawler` phone extraction now shares the canonical E.164 validity rule.**
  It accepted `7..=15` digits while `core::validation::validate_phone_e164`
  requires `8..=15`, so the crawler could surface a too-short `+1 234567` that the
  rest of the system rejects. Acceptance now goes through `validate_phone_e164`
  itself — one definition of "valid E.164", no crawler-only false positives.
  Unit-tested at the 7-vs-8-digit boundary.
- **`web_crawler` email extraction now shares the canonical syntax validator.**
  The byte-scan's ad-hoc "local non-empty" check let through malformed runs it can
  grab from page text — `john..doe@example.com` (consecutive dots),
  `.lead@example.com` / `trail.@example.com` (edge dots) — as bogus `Email`
  entities. Acceptance now also passes `core::validation::validate_email_syntax`
  (the same one-`@`/no-edge-or-consecutive-dot/bounded-local definition used
  system-wide), while keeping the extraction-specific TLD-length, total-length and
  asset-extension filters. Unit-tested.
- **`web_crawler` email extraction stopped leaking modern asset filenames.** The
  scanner filtered retina/asset filenames that look like emails (`logo@2x.png`)
  but only for `.png/.jpg/.gif/.css/.js` — so `logo@2x.webp`, `icon@3x.svg`,
  `hero@2x.jpeg`, `fav@2x.ico` and web-font files were extracted as bogus `Email`
  entities that pollute the graph. The filter is now a complete, data-driven
  `ASSET_EXTENSIONS` list. It **deliberately excludes `.zip` and `.mov`**, which
  became real gTLDs in 2023 — so a genuine `someone@archive.zip` address is still
  captured. Unit-tested both directions.
- **OpenRouter API keys were mis-classified as OpenAI/Stripe.** The `sk-or-`
  prefix (OpenRouter) was declared *after* the generic `sk-` stem in the
  key-harvest pattern table, and `identify_api_key` returns the first
  declaration-order prefix match — so every `sk-or-…` key resolved to the generic
  `sk-` → `openai_or_stripe` instead of `openrouter`. Moved `sk-or-` above the
  stem. Found by the new structural test below.
- **Removed an unreachable duplicate `glpat-` pattern.** The key-harvest table
  had two `glpat-` entries with identical prefix and `min_len` (`gitlab_pat` and
  `gitlab`); the second was dead. Kept the precise `gitlab_pat` label (`glpat-` is
  a GitLab Personal Access Token). No behaviour change. (The `pk_live_`
  Stripe-vs-Clerk overlap is left as-is — a genuine cross-provider prefix
  collision, not an in-tree defect.)

### Added

- **Active TCP-connect port scan (`portscan`) — the active counterpart to the
  passive IP intel.** For an `IpAddress` target it does a bounded, polite connect
  scan of ~23 common service ports (1.5 s/port × 16 concurrent), re-emits the IP
  with an `open_ports` evidence attribute, and emits a `Url` entity for each open
  web port (`http(s)://ip:port`) so `web_crawler`/`webserver_banner` enrich the
  live service. Pairs with `netblock` (CIDR → host IPs → port sweep). **Non-passive**
  (skipped under `--passive-only`); pure tokio, no API, no native deps, no root;
  refuses non-routable/reserved IPs so it can't be aimed at internal space. Tested
  (shape, sorted/unique port table, IPv6 URL bracketing, a real localhost
  open/closed detection, and the non-routable guard).

- **`hse scan --full` — the no-compromise complete scan (CLI + Web UI parity).**
  One option that auto-detects the seed kind and runs EVERY module (overriding
  `--free-only`/`--passive-only`/`--modules`), expands to MAX_DEPTH (3) at the
  Probable floor, and disables ROI pruning so nothing is skipped. Aliases
  `--complete`/`--everything`. The Web UI's "Complete (All)" use-case now sends
  the identical options (`depth 3, min_expand_confidence 0.40, max_roi off`), so
  the two front-ends are functionally equivalent for the flagship scan.

- **Installer shows live build progress.** Output is piped to `tee` (not a TTY),
  which made cargo suppress its progress bar — so the multi-minute final compile
  looked frozen and people Ctrl-C'd it. The installer now forces
  `CARGO_TERM_PROGRESS_WHEN=always` (live per-crate progress) and prints a
  heartbeat ("still compiling — do NOT interrupt") every 20 s during the silent
  final-crate codegen. The ticker is cleaned up on every exit path.

- **`hse diagnostics` — one command for all health checks.** Runs `doctor`
  (environment) + `selftest` (modules/core) + `engines` (search-engine liveness)
  in a single banner-sectioned pass, exiting non-zero if any section fails.
  Aliases: `diag`, `check`. The individual commands remain (the Web UI/API still
  call them). `provision` gains a `setup` alias. Verified live: a real scan of
  `jordanavery@gmail.com` returned a breach-source correlation (AU-001) and
  derived-handle/social pivots; a name scan surfaced breach passwords (AU-037);
  the Web UI's scan-detail endpoints (entities/correlations/relations, CSV +
  GEXF export) all serve real data.
- **Typosquat / lookalike-domain discovery (`typosquat`, dnstwist-style,
  pure-Rust).** A `Domain` target now generates lookalike permutations —
  omission, transposition, repetition, keyboard-adjacent replacement, ASCII
  homoglyph, hyphenation, bitsquatting, and TLD swap (with `.com.au`/`.net.au`/
  `.org.au` AU focus) — then resolves each via the shared DNS resolver and emits
  a `Domain` entity **only for registered (resolving) lookalikes**, tagged with
  the technique. A registered brand lookalike is a phishing/brand-abuse lead the
  expansion loop then enriches (WHOIS, certs, web-crawl). Pure permutation core
  (bounded at 128, unit-tested across every class) + bounded concurrent
  resolution; no API, no native deps (Termux-clean).
- **CIDR netblock targeting (SpiderFoot-parity "scan a network range").** A scan
  target can now be a CIDR block — new `TargetKind::Cidr` / `EntityKind::Cidr`,
  auto-detected from `a.b.c.d/n` (and `--kind cidr`). The new `netblock` module
  (pure, offline, no API) expands it into host `IpAddress` entities — bounded at
  1024 with a `truncated` flag on the parent for wider blocks — which the
  expansion loop then sweeps through the full IP-enrichment stack (geo,
  reputation, reverse-DNS, banner). IPv6 blocks surface only the network base
  (host space too large to enumerate); RFC5737 documentation IPs are filtered
  downstream as non-real. Tested (expansion, network-bit normalisation, cap +
  truncation, `/32`, IPv6, rejection) and verified end-to-end
  (`10.0.0.0/30` → 4 hosts).
- **Shared web-analytics ID → common-ownership correlation (SpiderFoot-parity
  "affiliate" pivot).** `web_crawler` now extracts web-analytics / tracking
  identifiers from page HTML — Google Analytics (`UA-`/`G-`), Tag Manager
  (`GTM-`), AdSense (`ca-pub-`), Facebook Pixel, Yandex Metrica, Hotjar — as a new
  first-class `EntityKind::TrackingId` (bare-numeric IDs are provider-prefixed so
  two providers can't collide). A new correlation rule **AU-044** fires when the
  same id appears on ≥2 distinct sites: a shared analytics/ads id is strong
  evidence the sites share an owner/operator. Pure-regex over already-crawled
  bodies — no API, no native deps (Termux-clean). Tested (extractor across all
  six providers; rule fires only across multiple sites). This closes the main
  capability gap vs SpiderFoot's web-analytics affiliate discovery.
- **`exif_geo` now extracts device + owner identity, not just GPS (code-only
  cross-correlation).** The pure-Rust EXIF reader (`kamadak-exif`, no API)
  previously emitted only a `Coordinates` entity and *only when the image carried
  GPS* — discarding everything for the common metadata-stripped-of-location case.
  It now also recovers, independently of GPS:
  * a **`DeviceId`** when a camera **serial** is present (`BodySerialNumber`/
    `LensSerialNumber`) — a unique cross-image anchor, so the same serial in two
    photos links them to one physical camera (and usually owner). Make+model
    alone is deliberately *not* an anchor (millions share `Apple iPhone 13`);
  * a **`Person`** from `CameraOwnerName`/`Artist` — the owner named in metadata,
    a real identity lead (kept below the expansion floor, but correlatable with
    same-named Person entities from the search/breach modules);
  * richer evidence (serial, lens, software, owner, shot-time) on every entity.
  This is the cross-correlation the free search-engine scrapers feed: they surface
  image URLs as `Url` entities, the expansion loop dispatches them here, and the
  Coordinates/DeviceId/Person results fuse into the graph via the correlator —
  all on-device, no external service. Tested (`device_fingerprint`, `clean_owner`).
- **Cross-function invariant test for the domain helpers.** Beyond per-case
  examples, a generative test builds a host corpus (every base × single- and
  multi-label suffix × subdomain depth) and asserts the *relationships* between
  `registrable_domain`, `is_or_subdomain_of`, and `is_proper_subdomain_of`: the
  registrable domain is always an equal-or-subdomain of its host, `registrable_domain`
  is idempotent, proper-subdomain implies equal-or-subdomain, and equal-or-subdomain
  is exactly `equal OR proper-subdomain`. Catches a future change to one helper
  that silently desyncs from another.
- **No-silent-drift guard: the TXT verification-vendor table has no shadowed
  entries.** `verification_vendor` returns the first prefix match in declaration
  order, so an earlier prefix that is a prefix of a later, different-vendor entry
  shadows it (its records would mis-attribute). The table's soundness test now
  also asserts the specific-before-generic ordering — the same check the key-prefix
  table has, and the invariant the `ms=`-goes-last comment previously maintained
  only by hand. Currently clean; preventive against future vendor additions.
- **No-silent-drift guard: the API-service-domain table has no shadowed entries.**
  `identify_service_from_url` returns the first table entry whose domain is a
  *substring* of the URL, so an earlier entry that is a substring of a later,
  different-service entry makes the later one dead (every matching URL is tagged
  with the earlier service). A new test (`service_domain_table_has_no_shadowed_entries`)
  flags any such pair — the same dead-data class the key-prefix table's
  `pattern_table_is_structurally_sound` already guards. This is the check the
  `riskiq.net` duplicate (below) would have failed.
- **Coverage for `search_engines::build_entities` domain classification.** The
  orchestration that turns raw search hits into entities had direct tests for
  aggregator suppression and profile-URL corroboration, but not for the domain
  branch: a host under the target domain → `SUBDOMAIN` (conf 0.70); any other
  registrable domain → `EXTERNAL` (conf 0.45); each carrying the count of
  *distinct engines* that returned its URL. A new test pins all three couplings
  (with a `.com.au` target so the multi-label-suffix path is exercised) and that
  the two branches stay mutually exclusive. No behaviour change — coverage for
  previously-untested orchestration logic.
- **No-silent-drift guard: each rule's `rule_id` matches its function number.**
  A copy-pasted rule that keeps the source rule's id (e.g. `rule_au_037` emitting
  `"AU-036"`) compiles and fires but mis-attributes the correlation; worse, the
  id is the dedup/ranking key, so two rules sharing one id collide silently. A
  new test (`correlation_rule_ids_match_their_function_number`) checks every
  emitted `"AU-NNN"` against its enclosing `rule_au_NNN_*` function, covering both
  the `rule_id: "AU-NNN".into()` and `Correlation::new("AU-NNN", …)` forms.
  Currently clean (all 44 emissions across 43 rules match); preventive.
- **No-silent-drift guard: every correlation rule must be dispatched.** A
  `pub(super) fn rule_au_*` defined in `correlator/rules.rs` but never added to
  the `RULES` / `RELATION_RULES` arrays in `mod.rs` compiles cleanly (the glob
  `use rules::*;` references it, so it isn't even a dead-code warning) and
  silently never fires — the analyst just never sees that correlation. A new test
  (`every_defined_correlation_rule_is_dispatched`) parses both files and asserts
  every defined rule is wired in. This is the correlator analog of
  `every_declared_module_is_registered` — the same failure mode that once left
  `pwned_passwords` dead at runtime. Currently clean (all 43 rules dispatched);
  preventive against future additions.
- **Well-formedness + ISO-consistency guard for the `geo_domain_classifier`
  tables.** Both lookups (`classify_by_known_service`, `classify_by_cctld`)
  compare against a *lowercased* domain, so any of the 122 `GEO_SERVICES` /
  `CCTLD_MAP` entries carrying an uppercase letter would silently never match —
  the same dead-data failure mode as the OUI typo above. A new test asserts
  every pattern is lowercase and well-shaped (ccTLDs start with `.`; service
  domains carry an interior dot), every ISO code is two uppercase letters, and a
  given code names exactly one country across both tables. Currently clean;
  preventive against future additions.
- **`dns_intel` now discloses SaaS vendor relationships from domain-verification
  TXT records.** Publishing a `…-domain-verification=` record proves an org has
  onboarded a given vendor — real OSINT for mapping its tech/vendor stack. The
  module previously recognised only Google and Microsoft; the detection is now a
  curated, case-insensitive `VERIFICATION_VENDORS` table (Google, Facebook, Apple,
  Atlassian, Adobe, Stripe, DocuSign, Dropbox, Zoom, GlobalSign, Pinterest, Cisco,
  Microsoft) surfaced as a namespaced `verified:<vendor>` tag (was the ad-hoc
  `google-verified` / `ms-verified`). A wrong prefix simply never matches, so the
  table fails safe. Unit-tested.
- **Ordering guard for the `phone_area_geo` area-code tables.** `lookup_area_code`
  returns the first area code a national number starts with, so — as with the
  international country table — an earlier code that prefixes a later one shadows
  that city (the hazard bites the variable-length GB/DE tables). A new test asserts
  the within-table and country-prefix ordering plus per-entry well-formedness
  across all seven country tables. Currently clean; preventive against future
  additions.
- **Credential-safety guards for the live key-validation probes
  (`api_key_probe`).** These probes transmit a *live secret API key* to each
  service's validation endpoint, so two new tests lock down that the table stays
  safe: every probe URL is `https://` (a plaintext endpoint would leak the key to
  on-path observers — it holds today, this stops a future `http://` entry) and
  every probe actually carries the key (in the URL or a header, else it would send
  an unauthenticated request and report a valid key as invalid); plus a uniqueness
  guard so no two probes share a service or env var (which would shadow one
  another or validate a key against the wrong endpoint).
- **Structural-invariant guard for the API-key pattern table
  (`oathnet_pro::key_harvest`).** A new `pattern_table_is_structurally_sound` test
  asserts, table-wide, that every entry is well-formed (non-empty prefix/service,
  `min_len` exceeding the prefix) and — crucially — that no more-specific prefix
  is shadowed by an earlier generic stem of a *different* service (the
  mis-classification class above). It generalises the previous hand-picked
  sk-/gh- whitebox check to all ~170 patterns and any future addition. (Exact
  same-prefix provider collisions like Stripe vs Clerk `pk_live_`, which ordering
  cannot resolve, are deliberately out of scope.)
- **Data-integrity guards for the `username_search` site table.** The 1600-line
  hand-maintained `SITES` table now has two CI-enforced invariants: every probe
  URL is `https://` (a plaintext probe would leak the searched handle to on-path
  observers — it held already, but nothing guarded it), and every `Site::cat` is
  one of a canonical `CATEGORIES` allow-list (so a typo like `socail` or an
  undocumented bucket fails CI instead of silently mis-classifying). Writing the
  allow-list surfaced real drift: the table had grown to **18** categories while
  the doc comment still listed 13 — `media`, `crowdfunding`, `education`, `travel`
  and `sharing` were undocumented; the canonical set now reflects reality.

- **`validate_phone_e164` rejects a country code beginning with `0`.** The
  validator's doc promised it checks "the country code in the conventional 1-3
  digit range", but the implementation only required digits + a length of 8–15, so
  `+0123456789` passed despite being invalid E.164 (ITU-T E.164 country codes never
  begin with `0`). Added the leading-zero check (new `e164.cc_leading_zero`
  reason), aligning the code with its documented contract. Unit-tested.
- **`parse_address` no longer mistakes a street number for a postcode.** The
  postal-code scanner examined every whitespace token of every comma-part, so a
  multi-digit street number — the *leading* token of a street part like
  `1234 Smith St` — was captured as `postal_code` (a plausible-but-wrong 4-digit
  AU postcode / 5-digit US ZIP). A real postcode trails its part (`QLD 4000`,
  `4000`), so only the **last** token of each part is now a candidate; the
  street-name tokens that follow a leading number disqualify it. Address parsing
  feeds geocode/overpass, so this removes a wrong structured field from `Address`
  entities. Regression-tested (incl. a street number that coincides with a real
  trailing postcode), and `util::geohash` gains coverage for `haversine_km` and
  `reverse_country_iso`'s US-subregion aliasing.
- **Registrable-domain extraction now handles multi-label public suffixes.**
  `web_crawler` and `search_engines` each carried an identical naive "last two
  labels" extractor, so `shop.example.com.au` collapsed to the bare suffix
  `com.au` and `a.b.co.uk` to `co.uk` — mis-grouping **every** `.com.au`/`.org.au`/
  `.gov.au`/`.co.uk` site, which for an AU-focused tool means the external-domain
  set a crawl produces was frequently wrong. Both now call one shared, tested
  `util::domains::registrable_domain` backed by a small curated multi-label-suffix
  table (the `.au` second levels + common international ones) — deliberately *not*
  a full Public Suffix List, honouring the project's no-heavyweight-dependency
  constraint while fixing the cases its data actually contains. (This revisits a
  previously-documented "deliberate 2-label, no-PSL" simplification: the original
  objection was to the PSL dependency, which a ~40-entry curated table does not
  introduce.) The suffix table is asserted sorted for its `binary_search`. An SPF record
  can delegate its whole policy to another domain via the `redirect=` modifier
  (RFC 7208 §6) — a genuine related-domain pivot that `dns_intel`/`doh_resolver`
  previously ignored, just as they had ignored `ip6:`. `util::spf::members` gains a
  `Redirect` variant (and the `Member` `match` in both modules is now exhaustive by
  construction, so neither can silently skip it again); the target is emitted as a
  `Domain` tagged `spf-redirect`. The include/redirect domain filter also now skips
  SPF macro members (`%{…}`), which never resolve to a literal domain. Unit-tested.
- **`search_engines` AU region detection no longer false-positives on US `61x`
  phone numbers.** `detect_region` treated any phone whose digits merely *started*
  with `61` as Australian (country code 61), so a US number in the `610`/`612`/…
  area codes (`610-555-1234` → `6105551234`) wrongly triggered AU-specific dorks
  when regional search was enabled. The bare-`61` path now requires full
  international length (61 + 9 national digits = 11) to read as the country code;
  `+61` stays unambiguous. Unit-tested against a US `610` number and AU forms.
- **`hse import` no longer panics displaying a multi-byte entity value.** The
  text listing truncated each value with a byte slice `&value[..len.min(70)]`;
  since an entity value is arbitrary text (a non-ASCII name/address), a value over
  70 bytes whose 70th byte fell mid-codepoint would panic the command. Switched to
  the existing char-boundary-safe `str_util::truncate_safe`. (Found by sweeping the
  tree for the same byte-slice class as the username-variant panic below; the
  other `&s[..len.min(N)]` sites all operate on ASCII hex IDs / geohashes / keys.)
- **`search_engines` username-variant generation no longer panics on a
  multi-byte handle.** `generate_username_variants` produced its truncation
  variant with a byte slice `lower[..len-1]`, which panics when the handle ends in
  a multi-byte codepoint (e.g. `andré`) by cutting mid-character — the same
  boundary hazard the module's name-dork builder already guards against. The last
  *char* is now dropped instead. The previously-untested 473-line `queries.rs`
  gains coverage of separator swaps, trailing-digit and truncation variants, the
  digit-terminated skip, multibyte non-panic (incl. an all-non-ASCII handle), and
  `detect_region`'s Australian-seed detection.
- **`search_engines` family-name extraction now works for `initial.surname@`
  emails.** `extract_family_names` derived the surname from an `Email` target by
  dropping the first character (the likely first-initial), but for the very common
  `j.smith@…` / `j_smith@…` forms it kept the separator — `lastname` became
  `".smith"`, which never equalled the alphanumeric-trimmed words it is compared
  against, so **no household/family leads were ever produced for those addresses**.
  The leading separator is now stripped (`j.smith` → `smith`); `jsmith` is
  unchanged. The previously-untested function (293-line `extract.rs`) gains unit
  coverage of the FullName path, both email forms, the short-surname rejection,
  multibyte-surname title-casing/dedup, and the non-applicable kinds.
- **`doh_resolver` now reconstructs chunked (multi-string) TXT records.** A TXT
  record is one or more character-strings (RFC 1035 §3.3.14); the DoH JSON
  resolvers return a multi-string record as space-separated double-quoted chunks
  (`"v=spf1 ip4:… " "include:… -all"`). The old `trim_matches('"')` stripped only
  the outer quotes, leaving stray `" "` boundaries that mangled the token at each
  chunk split — so a long (chunked) SPF record lost members. A new pure
  `unquote_txt` concatenates the chunk contents with no separator (per the RFC),
  decoding `\"`/`\\` escapes; bare single strings pass through. Unit-tested,
  including a chunked SPF record parsing end-to-end into its ip4 + include members.
- **`dns_intel` SOA-RNAME→email now unescapes the local part (RFC 1035 §8).** The
  decoder correctly *skipped* a backslash-escaped dot when finding the local-part /
  domain split, but never removed the escaping from the result — so
  `hostmaster\.ops.example.com` produced `hostmaster\.ops@example.com` (stray
  backslash) instead of `hostmaster.ops@example.com`. A new pure
  `unescape_dns_label` decodes both `\X` literal escapes (the common `\.`) and
  `\DDD` decimal byte escapes; both it and the dotted-local-part path are
  unit-tested.
- **`dns_intel` DMARC report addresses now strip the RFC 7489 `!size` suffix.** A
  DMARC `rua=`/`ruf=` report URI may be suffixed with an optional maximum report
  size (`mailto:dmarc@example.com!10m`, RFC 7489 §6.2); the parser kept it
  verbatim, so the surfaced `Email` entity was malformed (`dmarc@example.com!10m`).
  The `rua`/`ruf` extraction is pulled into the pure, unit-tested
  `dmarc_report_addresses` (splits the size suffix, keeps only `mailto:` URIs with
  a plausible address), replacing the inline loop in `process`.
- **SPF mechanism parsing unified into `util::spf`, fixing two divergences.**
  `dns_intel` and `doh_resolver` each hand-rolled a `v=spf1` parser, and they had
  already drifted: `dns_intel` matched the version tag case-insensitively (correct
  per RFC 7208 §4.5) while `doh_resolver` used a case-sensitive `starts_with`, and
  **both silently dropped every `ip6:` mechanism** despite the modules tagging
  A/AAAA results `ipv4`/`ipv6`. Both now call one tested `util::spf` primitive
  (`is_spf` + a `members` iterator yielding `ip4:`/`ip6:` addresses — CIDR stripped,
  IPv6 colons preserved — and dotted `include:` domains, skipping bare/blank
  mechanisms). `doh_resolver` thereby gains case-insensitive SPF detection and both
  modules gain IPv6 authorised-sender extraction. Each module keeps its own
  dedup/entity/tagging; the IP evidence label is corrected to "SPF authorised
  sender".

- **Correlation rule AU-038 — verified cross-platform identity.** `search_engines`
  tags a `Url` `confirmed-profile` when the searched handle is the exact path on a
  canonical social host (the target's own, engine-verified profile). AU-038 fires
  when ≥2 such confirmed profiles span distinct platforms — a strong, verified
  cross-platform identity — naming the platforms. It complements AU-011 (which
  needs `username_search`'s platform count): AU-038 synthesises the cross-platform
  identity from the search-engine signal alone, so a search-engines-only scan
  still surfaces it. Pure entity-scan logic, deterministic, unit-tested.
- **Correlation rule AU-037 — plaintext credential exposure.** The breach/stealer
  modules surface the canonical leaked secret as a first-class `Password` /
  `Credential` entity, but no rule synthesised them into an alert (only `ApiKey`,
  via AU-021). AU-037 now fires **Critical** when any are present — the single
  most actionable OSINT finding — linking the secret entities (capped) plus the
  affected identity (emails/usernames) so the operator sees *whose* credentials
  leaked. It reports only counts; the raw secret values stay in the entities
  (full-fidelity, nothing redacted) and are never copied into correlation text.
- **Universal toggleability (SpiderFoot-style on/off switches), persisted.** A new
  capability-toggle store (`~/.huntsman/settings.json`, atomic write, mode 0600,
  in-process cache) lets any capability be switched on or off **without a
  rebuild**, managed by the new `hse config` command (`hse config` lists every
  toggle; `hse config <key> <on|off>` sets one). Only *overrides* are stored, so
  an unset toggle resolves to its in-code default and a new toggle defaults
  sanely on an old settings file.
  - **Per-engine toggles** — disable a noisy/blocked search engine with
    `hse config engine.<name> off`; the search dispatch, priority and liveness
    probe all honour it.
  - **Per-module toggles** — disable any of the 92 modules across *all* scans with
    `hse config module.<name> off` (re-enable with `on`). A disabled module is
    skipped at the scan gate (reason `disabled in config`) and never touches the
    network. `module.<name>` keys default on, so unset modules behave exactly as
    before.
  - **Feature toggles.** Capability switches that aren't a single engine or
    module now live in the same registry. The first is `feature.regional`
    (default **off**): a persistent, web-/CLI-manageable default for autonomous
    region-scoped search. A scan goes regional when **either** the per-scan
    `--regional` flag is set **or** `feature.regional` is on, so an operator can
    set the standing baseline once (`hse config feature.regional on`) while the
    flag still forces it on for a one-off scan.
  - **Web Settings panel + toggle API.** The dashboard's Settings page now renders
    the full capability catalogue (features + every engine + module) as a
    click-to-flip grid with an **instant filter box** and a live per-group
    "*N* on" tally (so the ~110-switch list — 1 feature + 17 engines + 92 modules
    — stays navigable), backed by `GET /api/v1/settings/toggles` (the catalogue
    with live state) and `PUT /api/v1/settings/toggles` (`{key, enabled}`). Writes
    are loopback-only and bounded to known `feature.*`/`engine.*`/`module.*` keys;
    no `--allow-key-write` needed since a toggle holds no secret. Toggling in the
    UI takes effect on the next scan with no restart.
- **Search-engine liveness panel + structured health log.** A new `hse engines`
  command (and `--json`) probes every keyless engine concurrently and reports
  `Up` / `Blocked` / `Down`, surfaced live in the web SPA at `#/engines` and over
  `GET /api/v1/engines/health`. `hse serve` runs a startup sweep and a periodic
  background refresh (`HUNTSMAN_ENGINE_HEALTH_SECS`, default 900s); each probe
  emits a structured `huntsman::engine_health` event into the shared debug-log
  ring buffer alongside the other module logs. The web `#/engines` panel now
  also carries an **inline Enable/Disable control per engine** (wired to the
  toggle API): it merges the probe sweep with the full engine roster so disabled
  engines stay visible (and re-enablable), and its Up/Blocked/Down/Disabled
  tallies are computed from that merged roster so they stay consistent the
  instant a toggle flips, even before the next background sweep. The **CLI `hse
  engines`** matches: disabled engines are listed as `disabled` (table and
  `--json`, the latter with `"enabled": false`), with the same
  `up + blocked + down + disabled = total` tally.
- **Runtime AI-independence charter + CI guard.** Documented and now mechanically
  enforced that the compiled `hse` binary carries **no** AI / ML / LLM /
  cloud-inference / agent / vector-DB / embedding dependency: every runtime
  capability is deterministic, documented Rust whose findings reproduce
  identically on Termux aarch64 (non-root), Linux and CI with no AI or
  network-inference available. AI is a development-time accelerator only. New
  guard `tests/architecture.rs::runtime_carries_no_ai_ml_inference_dependency`
  parses `Cargo.lock` and fails the build if such a crate enters the dependency
  tree; its blocklist was broadened (TensorFlow, Torch FFI, `llm-chain`, ONNX
  `rten`, text-embeddings, ChromaDB, mistral-rs) for defence in depth. Charter +
  reproducibility/enforcement notes: `docs/RUNTIME_INDEPENDENCE.md`. (Re-verified
  after this session's work — the tree is still clean: 0 of 277 crates are AI/ML,
  no new dependency was added, and deterministic-output runs are byte-identical.)

### Changed

- **Every module now declares `produces()` (dependency-graph consistency).** 11
  modules (`hudsonrock`, `xposed_or_not`, `dehashed`, `intelx`, `pwned_passwords`,
  `urlhaus`, `leakix`, `ipqs`, `emailrep`, `virustotal`, `wayback`) relied on the
  empty-default `produces()`, leaving their outputs undeclared and their
  pivot-chain blank in the UI dependency graph. Each now declares the exact
  `EntityKind`s it emits (read from its `process()` — the enriched re-emitted
  target plus any children, matching the convention the other ~90 modules
  already follow). Metadata-only — no behaviour change; the full suite is
  unchanged. All 101 modules now declare their outputs.

- **Subdomain matching is centralised in `util::domains::is_or_subdomain_of` /
  `is_proper_subdomain_of`.** The "host is `X` or a subdomain of `X`" test was
  hand-rolled as `host == d || host.ends_with(&format!(".{d}"))` in ~9 places —
  re-allocating a `String` per check, and the source of several recent boundary
  bugs where a site diverged into a bare `ends_with` (matching `notexample.com`
  against `example.com`). Both predicates now live in one tested, allocation-free
  helper, and the call sites (`search_engines`, `oathnet_pro`, `hackertarget`,
  `web_crawler`, `cert_intel`, `dns_axfr`, `domains::is_social_platform`) delegate
  to it. Behaviour-preserving; the full suite is unchanged.

- **Shared CKAN `datastore_search` envelope (`util::ckan`).** The two
  Australian open-data register modules (`acnc_charities` on `data.gov.au`,
  `qld_unclaimed` on `data.qld.gov.au`) had byte-identical copies of the CKAN
  response structs (`success`/`result`/`total`/`records`) and the defensive
  `field_str` helper (text passes through, numbers/bools are stringified,
  null/empty/missing → `None`). CKAN's envelope is a fixed API contract, not a
  per-portal shape, so the copies could only ever drift, never legitimately
  differ — they now live once in `util::ckan`, alongside a
  `datastore_search_url` builder that url-encodes the full-text query (so a
  name containing `&`/`=` can't inject extra parameters — previously re-derived
  in each module's `query_url`). Covered by a focused test module
  (numeric-field stringification, `success=false`, lenient defaults, query
  encoding). Future CKAN-backed registers reuse the surface instead of
  re-deriving the parser. Behaviour-preserving.
- **Single source for the mobile-Chrome User-Agent.** The exact same
  Android/Chrome UA string was hard-coded in four places — `util::curl::UA_MOBILE`
  (canonical), `username_search`'s `BROWSER_UA`, `curl_client`'s `DEFAULT_UA`, and
  an inline `social_probe` curl arg. The three duplicates now reference
  `util::curl::UA_MOBILE`, so bumping the Chrome version (or the device
  fingerprint) is a one-line change that can't leave a module behind.
  Behaviour-preserving (all four were byte-identical).
- **`phone_area_geo` reuses the canonical ISO→country-name table.** Its private
  8-entry `country_name` match is replaced by a delegation to
  `geohash::country_name_for_iso` (55 countries) — every ISO the module's area
  tables use is covered with identical names, so it's behaviour-preserving and
  removes a divergent copy.
- **Consolidated digit-only string normalisation into `util::str_util::ascii_digits`.**
  The `s.chars().filter(char::is_ascii_digit).collect()` idiom was re-derived inline
  in ~9 places (phone parsing, ABN/ACN/LEI, target detection); they now share one
  `#[must_use]`, unit-tested definition. Behaviour-preserving.
- **Guarded three SPF/address parse paths against blank-value entities** (PR #104
  review). `doh_resolver` now skips a bare `ip4:` / `ip4:/24` (empty IP) and
  requires SPF `include:` hosts to be non-empty and dotted — matching the
  MX/NS/CNAME rule its own doc promised; `opencorporates` trims the registered
  address before the length-floor check so a whitespace-only address can't
  normalise into a blank `Address` entity. Each is covered by a new unit test.
- **Factored URL host extraction onto a shared `url_util::host_only` primitive.**
  `host_from_url` and the inline scheme/path/port stripping in `wayback` and
  `whois` each re-implemented the same parse; they now share one borrowing,
  policy-free `host_only(&str) -> &str` (strip scheme, drop path + port), with the
  case-fold/dot-requirement layered on only where each caller needs it
  (`host_from_url` lowercases and requires a dot; `wayback` lowercases; `whois`
  keeps the host verbatim). Unit-tested. Behaviour-preserving.
- **De-duplicated the `nonempty` optional-string helper into `util::str_util`.**
  Seven modules (`proxycurl`, `domainsdb`, `seon`, `epieos`, `bgpview`, `photon`,
  `threatfox`) each carried a byte-identical private
  `nonempty(&Option<String>) -> Option<&str>` (trim + treat-blank-as-absent); they
  now share one `#[must_use]`, unit-tested definition, so the "surface the value
  only if the upstream actually sent one" semantics can't drift between providers.
  Behaviour-preserving.
- **`mylnikov` brought up to the module spec.** The range→confidence banding and
  the BSSID-location entity assembly are extracted out of `process` into the pure,
  IO-free `confidence_for_range` and `build_location_entity` (the latter folding in
  the coordinate-validity gate and returning `None` for missing/invalid fixes).
  Adds unit coverage of every confidence band at its exact boundary (incl. the
  missing-range default), the high-confidence entity build with range evidence,
  the missing-range attribute omission, and rejection of missing-component /
  Null-Island / out-of-range coordinates. Behaviour-preserving.
- **`doh_resolver` brought up to the module spec.** The ~100-line per-record-type
  classifier (the deeply-nested A/AAAA/MX/NS/TXT-SPF/CNAME matcher) and the
  target-domain resolution are extracted out of `process` into the pure, IO-free
  `records_for_type` and `target_domain`, with the queried record set lifted to a
  named constant (`RECORD_TYPES`). `process` keeps only the per-type fetch loop and
  cancellation. Adds unit coverage of URL/domain resolution, A/AAAA IP tagging, the
  MX last-field/dot rules, SPF `ip4:`/`include:` extraction (with CIDR stripping
  and non-SPF TXT ignored), NS/CNAME trailing-dot trimming, and the
  type-prefixed cross-record dedup (an A-record IP and an SPF `ip4:` of the same
  value stay distinct while intra-run repeats collapse). Behaviour-preserving.
- **`overpass` brought up to the module spec.** The OSM-node infrastructure
  classification and the entity fan-out are extracted out of `process` into the
  pure, IO-free `classify_element` (tags → category, with the six discriminating
  tag-pairs collapsed behind one `is(k, v)` helper) and `build_entities` (the
  summary `Coordinates` entity carrying the node count + per-category breakdown,
  plus one entity per located node), with the per-node cap promoted to a named
  constant (`MAX_NODES`). Adds unit coverage of every classification category
  (including the generic fallback), the summary+nodes emission with deterministic
  category breakdown and name/operator/osm_id evidence, and the
  cap-nodes-but-count-all-in-summary behaviour. Behaviour-preserving.
- **`ipinfo` brought up to the module spec.** The five-entity fan-out
  (`Coordinates` from a non-null-island `loc`, `Address` from city/region/country,
  `Organisation` + the leading `Asn` parsed from the `org` string, and the PTR
  `Domain` from a dotted `hostname`) is extracted out of `process` into the pure,
  IO-free `build_entities`, with the null-island coordinate threshold promoted to
  a named constant (`MIN_COORD_MAGNITUDE`). Adds unit coverage of the full
  five-entity record, null-island/sub-threshold `loc` rejection, the region-absent
  address form, an `org` without an `AS…` prefix yielding no `Asn`, and a dotless
  hostname not becoming a `Domain`. Behaviour-preserving.
- **`sunrise_sunset` brought up to the module spec.** The ~55-line solar-phase
  entity assembly is extracted out of `process` into the pure, IO-free
  `build_solar_entity` (date/lat/lon plus every present timestamp and the
  polymorphic `day_length`, whose numeric-vs-string normalisation is the subtle
  part), with the nine repeated `with_attr` blocks collapsed into one table-driven
  loop. Adds unit coverage of the entity build for both the numeric (`formatted=0`)
  and string (default-endpoint) `day_length` forms with absent-phase omission, and
  — importantly — the previously-untested `civil_from_days` date arithmetic
  (epoch, pre-epoch, month rollover, the 2000 leap day, a current date), the one
  piece of non-trivial pure logic in the file. Behaviour-preserving.
- **`crtsh` brought up to the module spec.** The CT-log query construction and
  the certificate-entry→entity mapping are extracted out of `process` into the
  pure, IO-free `build_query` and `build_entities` (SAN/common-name splitting,
  wildcard skipping, cross-response dedup, subdomain classification + confidence,
  highest-confidence capping), with the email-length floor and result cap promoted
  to named constants (`MIN_EMAIL_LEN`, `MAX_ENTITIES`). **Fixes a latent
  case-sensitivity bug**: the subdomain check compared a lower-cased SAN against
  the raw target value, so a mixed-case target (`Example.com`) mis-scored its own
  subdomains as unrelated (0.45 instead of 0.75); the base is now case-folded.
  Adds unit coverage of per-kind query shaping, subdomain/dedup/wildcard handling,
  the case-insensitive base match, SAN-email surfacing above the length floor, and
  the highest-confidence-first cap. Behaviour-preserving except the case-fold fix.
- **`webserver_banner` brought up to the module spec.** The inline URL/host/port
  parsing is extracted out of `process` into the pure, IO-free `extract_host_port`
  (returning `None` for an unparseable URL or empty/path-shaped host). Test
  coverage is broadened from the two stack-tag spot checks to the full fingerprint
  surface: every `apply_stack_tags` signature (nginx/apache/iis/cloudflare-via-
  Server-or-cf-ray/aws-cloudfront/fastly/wordpress/drupal/php/aspnet), the
  case-insensitive + quiet-on-unknown behaviour, `capture_headers`'
  fingerprint-only/non-empty filtering, and the host/port extraction across
  URL+port, bare-domain, and junk inputs. Behaviour-preserving.
- **`opencorporates` brought up to the module spec.** The per-company fan-out
  (the `Organisation` plus a `validated` `Address` and an AU `AbnAcn`
  company-number entity) is extracted out of `process` into the pure, IO-free
  `build_company_entities`, with the page size and address-length floor promoted
  to named constants (`PER_PAGE`, `MIN_ADDRESS_LEN`, the former also replacing a
  hardcoded `per_page=5` in the query) and the eight repeated `with_attr` blocks
  collapsed into one table-driven loop. Adds unit coverage of the full AU triple
  (org+address+company-number), the non-AU case (no `AbnAcn`, no `country:AU`/
  `active` tags), the short-address/missing-number optional-drop path, and
  blank/whitespace-name rejection. Also now trims whitespace-only names (which the
  old empty-only check let through). Behaviour-preserving.
- **`urlhaus` brought up to the module spec.** The ~80-line host-threat
  aggregation (malicious-URL count, reference, first/last-seen window, third-party
  blocklist verdicts, online/offline URL split, distinct threat families, and the
  top URL tags by frequency) is extracted out of `process` into the pure, IO-free
  `build_threat_entity`, with the two list caps promoted to named constants
  (`MAX_THREATS` / `MAX_TAGS`). The threat-family list is now **deterministic** —
  the previous early-break-on-insert took whichever distinct families happened to
  appear first in URLhaus's URL order; it now takes the lexically-first
  `MAX_THREATS` regardless of input order (byte-identical-output invariant). Adds
  unit coverage of the full aggregation (counts, window, blocklists, online/offline
  split, threat sort, frequency-ranked tags), the determinism-under-cap property,
  and the no-URLs-array omission path. Behaviour-preserving except the threat-list
  determinism fix.
- **`rdap_domain` brought up to the module spec.** The RDAP record→entity
  mapping is extracted out of `process` into two pure, IO-free builders:
  `build_domain_entity` (status-phrase `status:` tags, event dates grouped by
  slugified action, deduplicated contact *role* names, DNSSEC delegation state,
  nameserver list) and `build_ns_entity` (one Domain per nameserver, blank-name
  rejection), with the nameserver cap lifted to a module-level `MAX_NS` constant.
  Adds unit coverage of status slugging, repeated-action event grouping, role
  dedup (reinforcing the never-raw-PII invariant), signed/unsigned DNSSEC, the
  bare-record optional-omission path, and nameserver normalisation/rejection;
  `slugify` keeps its existing tests. Behaviour-preserving.
- **`dehashed` brought up to the module spec.** The two pure pieces of `process`
  are extracted and tested: `selector_for` (target-kind → DeHashed query
  selector, returning `None` for unsupported kinds) and `build_breach_entity`
  (the aggregate-only entity mapping — total hit count vs returned rows, top
  databases by frequency with the `database_name`→`obtained_from` fallback, the
  created-at range, and the breach tags). The database cap becomes a named
  constant (`MAX_DATABASES`). Adds unit coverage asserting `selector_for` answers
  for exactly the kinds `accepts` admits, the full aggregation (server total
  exceeding returned rows, source-fallback frequency ranking, created-at range),
  and the count-only response that omits the optional aggregates — reinforcing
  the no-credentials-in-evidence invariant at the unit level. Behaviour-preserving.
- **`wayback` brought up to the module spec.** Both pure pieces of `process` are
  extracted and tested: `extract_domain` (URL scheme/path/port stripping +
  lowercasing) and `build_entity` (the CDX-rows → archive-entity mapping —
  snapshot count, earliest/most-recent bookend timestamps raw + ISO, and the
  status-code distribution, returning `None` for a header-only/unarchived
  response). Adds unit coverage of the URL-host extraction, the empty/header-only
  no-entity case, and the snapshot-count/bookend/status-distribution summary,
  plus the previously-missing `Url`-kind `accepts` assertion. `iso_from_cdx`
  keeps its existing tests. Behaviour-preserving.
- **`smtp_vrfy` brought up to the module spec.** The five-way outcome→entity
  mapping (no-MX plus the SMTP valid/invalid/catch-all/unreachable verdicts),
  previously open-coded as five near-identical `Entity::new` blocks split across
  `process`, is folded into one pure, IO-free `build_entity` driven by a unified
  `SmtpVerdict` enum (the old `SmtpResult` renamed and given a `NoMx` variant so
  the no-MX path is no longer a special-cased early return). Confidence/tag/
  evidence selection is now a single `match`, with `mx_host` attached whenever an
  MX was found and `smtp_code` only on a rejection. Adds unit coverage of every
  verdict (tags, confidence, evidence attributes) plus the deliverability-ladder
  ordering invariant (valid > catch-all > invalid > unreachable), alongside the
  existing async metadata/no-MX integration tests. Behaviour-preserving.
- **`securitytrails` brought up to the module spec.** Both response→entity
  mappings — the subdomain enumeration (`{label}.{domain}` qualification +
  parent-count evidence) and the reverse-IP associated-record path (trailing-dot
  trim and rejection of blanks, bare IP-literal PTRs, and dotless single labels)
  — are extracted out of the IO-bound `subdomain_search` / `reverse_ip` methods
  into the pure, IO-free `build_subdomain_entity` / `build_associated_entity`,
  with the reverse-IP record cap promoted to a named constant
  (`MAX_REVERSE_RECORDS`). Replaces the two trivial accepts/cost tests with unit
  coverage of host qualification, blank-label skipping, trailing-dot trimming,
  and the full non-hostname rejection set (v4/v6 literals, dotless labels). Also
  corrects the module-doc IP endpoint (`/v1/ips/list`, matching the code, not the
  stale `/v1/ips/nearby/`). Behaviour-preserving.
- **`ipqs` brought up to the module spec.** The ~75-line reputation mapping
  (fraud-score risk band, the proxy/vpn/tor/crawler/disposable/leaked/recent-abuse
  signal tags, the `country:<CC>` tag, and the per-field evidence across all three
  IP/email/phone sub-APIs) is extracted out of `process` into the pure, IO-free
  `build_reputation_entity`. The two risk thresholds become named constants
  (`HIGH_RISK_SCORE` / `ELEVATED_RISK_SCORE`) and the seven repeated
  `== Some(true)` tag blocks collapse into one data-driven loop. Replaces the two
  trivial accepts/cost tests with unit coverage of the high-risk IP path,
  threshold-exact risk banding, the email field/tag surface, and the
  missing-score default with IP-field omission. Behaviour-preserving.
- **`leakix` brought up to the module spec.** The ~90-line exposure-event
  summarisation (top event types / sources / protocols by frequency, the sorted
  open-port set, the earliest/most-recent timestamp window, and the `leak` /
  `ssh-exposed` tags) is extracted out of `process` into the pure, IO-free
  `build_exposure_entity`, with the top-N and port caps promoted to named
  constants and the repeated services∪leaks iteration collapsed behind a single
  closure (removing four interim `Vec` allocations). Replaces the two trivial
  accepts/cost tests with unit coverage of the count/port/window summary,
  case-insensitive `ssh-exposed` tagging, services-only attribute omission, and
  the port cap. Behaviour-preserving.
- **`threatfox` brought up to the module spec.** The ~90-line IOC aggregation
  (malware families / IOC + threat types / context tags folded into capped,
  deduplicated, deterministically-ordered attribute lists, plus max analyst
  confidence and the outer first/last-seen window) is extracted out of `process`
  into the pure, IO-free `build_ioc_entity`, with the list caps promoted to named
  constants and empty/whitespace fields filtered through a shared `nonempty`
  helper. Replaces the two trivial accepts/cost tests with unit coverage of the
  single-IOC mapping, cross-batch aggregation (dedup + sort + max-confidence +
  outer window), sparse-record attribute omission, and the family/tag caps.
  Behaviour-preserving.
- **`disposable_check` brought up to the module spec.** The throwaway-email
  verdict→entity mapping is extracted from `process` into the pure, IO-free
  `build_email_entity`, and the stringly-typed `disposable` field is parsed
  through `is_disposable` — affirmative-`true`-only and **fail-open**, so a
  malformed verdict can no longer brand a real address as a throwaway. The
  confidence split (disposable 0.20 vs legit 0.75) and the always-present
  `disposable=<bool>` evidence attribute are now named constants and unit-tested
  (verdict parsing, tags, confidence, evidence, and the disposable-<-legit
  ordering invariant), replacing the two trivial accepts/cost tests. Also
  declares `produces()` (Email) to match its peers. Behaviour-preserving.
- **Codebase-wide dependency refresh.** Updated the full locked dependency graph
  to current versions and bumped the direct majors, all verified green (fmt,
  `clippy -D warnings`, the entire test suite, `cargo deny`, `cargo machete`,
  binary DB integrity):
  - **`rusqlite` 0.31 → 0.40** (libsqlite3-sys 0.38) — newer bundled SQLite, no
    source changes needed; the only effect is `PRAGMA optimize` now materialising
    the planner statistics tables (`sqlite_stat1`/`sqlite_stat4`) at open, which
    improves query plans. DB integrity-checks clean before and after writes.
  - **`thiserror` 1 → 2** — also removes the duplicate 1.x/2.x split from the
    tree (nothing else pulled 1.x).
  - **RustCrypto hashes `sha1` / `sha2` / `md-5` 0.10 → 0.11** (digest 0.11),
    bumped in lockstep. digest 0.11 dropped the `io::Write` impl for hashers; the
    one `write!(hasher, …)` site (`derive_uid`) now feeds the identical bytes via
    `update`, so **entity UIDs stay byte-identical** (verified — dedup/correlation
    and the SHA-1 HIBP k-anonymity / MD5 gravatar paths all unchanged).
  - 26 semver-compatible updates via `cargo update` (hyper 1.9 → 1.10, http,
    socket2, icu_\*, zerocopy, uuid, log, …).
  - **`reqwest` deliberately held at 0.12** (current & supported, 0.12.28).
    Evaluated 0.13 in depth and pinned 0.12 on purpose: 0.13's `rustls` feature
    moves trust to `rustls-platform-verifier`, which on Android reads the OS cert
    store over JNI through an app `Context` a **Termux CLI process does not have**
    — it would break TLS on the primary target. The self-contained ring +
    webpki-roots stack works identically on Termux/Linux/CI; a 0.13 move must
    re-create it (`rustls-no-provider` + a hand-built `ClientConfig`) and be
    validated on a device first. Rationale recorded inline in `Cargo.toml`.
- **Search URL findings now credit cross-engine agreement.** The domain branch of
  the search-result builder already set `corroboration = <distinct engines>`, but
  the URL branch did not — so a profile independently returned by, say, 7 engines
  carried `corroboration = 1` and stayed at base confidence, no matter how
  unanimous. URL entities (most importantly the elevated `confirmed-profile`
  URLs) now take the same per-URL engine count, so a confirmed profile agreed on
  by ≥2 engines crosses into the **Verified** tier via `c_effective`. The
  highest-value findings finally reflect how strongly the engines agree.
- **Suppress people-search / username-aggregator domains from search findings.** A
  statistical pass over a live `kylo4kylo` run found ~15 of 84 result domains were
  people-search aggregators (spokeo, peekyou, nuwber, whitepages, pipl, …) — the
  search's OWN dork targets (`site:peekyou.com`), never the subject's asset, yet
  emitted as bare `Domain` findings (noise). A new `is_search_tooling_domain` set
  now drops those bare domains; the *specific* profile URL on an aggregator
  (`peekyou.com/<handle>`) and genuine external domains are still kept. Cuts the
  per-person-search domain noise materially with no loss of signal.
- **Confirmed-profile detection — the target's own profile is elevated.** When a
  username search returns the searched handle's *own* page on a canonical social
  host (the handle is the URL's first path segment, e.g. seed `kylo4kylo` →
  `https://x.com/kylo4kylo`, `https://github.com/kylo4kylo`), that `Url` entity is
  now emitted at **0.85** and tagged `confirmed-profile` — the strongest
  username-search finding — instead of the generic 0.50 used for a page that
  merely contains the handle. With one corroborating source it crosses into the
  Verified tier, so the actual answer (the profiles) rises above incidental
  results. Covers the handle-first platforms (x/twitter, instagram, github,
  tiktok, pinterest, facebook, …); deterministic, no extra requests.
- **Potentiated username scoring — alias variants outrank co-occurrence noise.**
  The search module's `score_username` now adds a handle-similarity signal that
  BOOSTS (rather than only acting as a `score == 0` fallback): a candidate that
  shares the seed's alphabetic STEM (seed `kylo4kylo` → stem `kylo` →
  `kylocool630`) or has ≥0.25 bigram overlap (`jdespal` ↔ `jaydes`) is treated as
  a likely alias of the SAME person. So a seed-resembling handle that also
  co-occurs reaches PROBABLE (0.55) while an unrelated handle that merely
  co-occurred on the page (e.g. `khloekardashian` next to `kylo4kylo`) stays
  CANDIDATE (0.30). The stem check matters because the digits in a handle dilute
  bigram overlap below threshold, hiding real variants from the old logic.
- **Expansion no longer deep-dives incidentally-discovered platform domains
  (person-scan signal-to-noise).** When a recursive scan surfaced a mega-domain
  (twitter.com, pinterest.com, github.com, …) as a *discovered* entity, depth-1+
  expansion re-scanned it and mapped the **platform's** own DNS/mail
  infrastructure (NS/MX/SOA → dozens of generic domains like `*.twtrdns.net`,
  `aspmx.l.google.com`), burying the real leads and burning the round budget. A
  discovered mega-domain is now skipped as an expansion target **unless it is the
  seed itself** (so investigating `facebook.com` directly still expands it). The
  existing 0.15× mega-domain weight dampening is unchanged; this is a hard gate
  that also applies without `--max-roi`. Surfaced by the standard `Kylo4kylo`
  run, which had pulled in 127 such infrastructure domains.
- **Free multi-engine search now leads the scan waterfall.** The keyless
  `search_engines` module (17 engines, no API key) was promoted from priority 25
  to **113** so a scan opens with broad, free, geolocation-neutral discovery
  before any keyed/paid module spends quota — high-quality leads from free
  resources first, exactly as an analyst would start.
- **Geolocation-neutral queries by default + opt-in regional searching.** Search
  dorks no longer pin a region (DuckDuckGo `kl=wt-wt`, no Yandex `lr`); autonomous
  region-specific dorks (e.g. AU ccTLD/directory queries) are added only when
  `--regional` is passed (default **off**), keeping results location-neutral
  unless the operator opts in. The username arm was rebuilt as a broad→narrow
  dork ladder (bare → exact-phrase → intent → `intitle`/`inurl` → `site:`).
- **`skipped` is now shown in the standard scan summary** (`modules: … run, …
  errored, … skipped`), so excluding or disabling a module is observable without
  `--output json`.

### Fixed

- **Restored a buildable tree on stable + MSRV — `rusqlite` pinned back to 0.39.**
  The earlier `rusqlite 0.40` bump pulled `libsqlite3-sys 0.38`, whose build
  script uses the still-unstable `cfg_select!` macro (rust-lang/rust#115585).
  That is a hard compile error on the project's MSRV (1.88) **and** on current
  stable toolchains that have not yet stabilised the feature — i.e. the whole
  project failed to build on the primary target. Pinned `rusqlite = 0.39`
  (`libsqlite3-sys 0.37`), which builds on 1.88+, with a guard comment so the
  bump is not reintroduced before `cfg_select!` lands on/below our MSRV. The
  bundled-SQLite schema (incl. `sqlite_stat1`/`sqlite_stat4`) is byte-identical,
  so no storage behaviour changes.
- **Expansion no longer deep-dives shared third-party infrastructure (the domain
  flood at its root).** The same real name-scan accumulated **683 domains, 599 of
  them (88%) from `hackertarget`** — a *reverse-IP lookup on two Cloudflare edge
  IPs* returned 480+ co-tenant strangers (`mysenprints.com` 290, `30shine.com`
  160, a merch/tee tail), and *subdomain enumeration on shared mail/DNS infra*
  (`secureserver.net`, `sendgrid.net`, `ns*.dnsmadeeasy.com`) added the rest —
  none of it about the subject. Two new engine expansion gates, alongside the
  existing mega-domain and non-routable-IP gates, stop this at the source:
  - `validation::is_cdn_edge_ip` — a discovered **CDN-edge IP** (Cloudflare's
    published ranges + Fastly) is not expanded, so no reverse-IP lookup floods
    the scan with co-tenants. Decided by IP *range*, not a `cdn` tag, so it holds
    before any reverse-IP module runs (no ordering race).
  - `scan::is_infra_domain` / `is_noncentral_domain` — shared managed-DNS,
    registrar, CDN-apex and ESP/mail domains (and AWS Route 53 `awsdns-*`
    nameservers) join mega-domains as non-central: skipped as incidental
    (non-seed) expansion targets, so their estates aren't subdomain-enumerated.
  Both still expand when the candidate **is the seed** (investigating that
  property directly). On that scan this takes domains **683 → ~84** (the
  legitimate DNS/profile-derived domains survive) and removes the AU-003/AU-010
  infrastructure-corroboration noise that rode on the flood. +3 tests.
- **Threat correlations now respect explicit benign-infrastructure verdicts
  (kills the shared-edge false-positive explosion).** A real name-scan produced
  **883 correlations, 792 (90%) of them AU-031 "malicious adjacency"** — driven
  by four flagged shared-infra parents: two Cloudflare CDN IPs (271 + 249
  co-hosted domains) and two ESP/mail domains (`secureserver.net` 146,
  `sendgrid.net` 122). The Cloudflare IPs were tagged `vulnerable` by a CVE scan
  of the *shared* edge **while simultaneously catalogued `greynoise-riot` /
  `greynoise-benign`** — the data already knew they were benign infrastructure.
  A shared `is_benign_infra` veto now makes a GreyNoise RIOT/benign verdict
  override the blocklist/scanner tags on the same node across **AU-004 / AU-008 /
  AU-015 / AU-031** (the veto tags are IP-only, so a malicious *domain* behind a
  CDN is untouched). For shared infra that carries *no* such verdict (the ESP
  domains), AU-031 keeps a fan-out backstop: >8 distinct neighbours collapse to
  one aggregate (Medium, or **High when the reason is `malicious`** so a genuine
  large malicious cluster stays loud) instead of N rows. On that scan: the two
  Cloudflare IPs are exonerated everywhere (their 520 AU-031 rows **and** two
  false AU-008 "exposed service" rows vanish), the two ESP domains aggregate
  (268 → 2), so **AU-031 792 → 6** and the dossier **883 → ~95** — ground truth,
  not a fan-out guess. Deterministic; +3 regression tests.
- **`github_user`'s `top_event_types` finding was non-reproducible.** The recent-
  activity summary ranked event types from a `HashMap` by count with no tiebreak,
  so tied counts (and thus which types landed in the top 3, and their order) came
  out in the HashMap's randomised order — identical GitHub activity produced
  different `top_event_types` evidence across runs. Extracted to a pure
  `top_event_types` helper that breaks ties by name (deterministic) and pinned it
  with a test. (Found auditing the highest-synergy modules; `see_know` — the
  single most connective module — was already clean: it parses via safe
  `serde_json` accessors with no slicing, `unwrap`, or HashMap output.)
- **Diagnostics JSON was not byte-reproducible across runs (charter:
  reproducibility).** The self-optimization report (`--output json` / dossier)
  serialised two `HashMap` fields (`source_confidence`, `entity_kind_counts`) —
  whose iteration order std randomises per instance — and several rankings built
  from HashMaps then sorted by a non-unique key (`modules_by_yield`,
  `cross_source_overlap`, adaptive `historical_rank`), whose ties kept the random
  order. So identical inputs produced different JSON bytes, defeating any
  hash/diff/cache of a report and the "findings reproduce identically" guarantee.
  The maps are now `BTreeMap` (sorted keys) and every such ranking has a stable
  secondary-key tiebreak. A new test asserts the (history-independent) diagnostics
  are byte-identical for identical inputs. (`adaptive_routing` is intentionally
  history-dependent — it reads + updates the persisted ledger — but its own
  ranking order is now deterministic too.) The same fix is applied to the core
  findings: `Evidence.attributes` (the verbatim per-record key/values surfaced
  for every entity in `--output json` / the dossier) is now a `BTreeMap`, so an
  entity's evidence serialises in a stable, sorted, hashable order.
- **UTF-8 panic deriving a dork from an internationalised email (silently voided
  `search_engines`).** The email-to-lastname dork derivation dropped the local
  part's first *byte* (`local[1..]`), which panics on a non-ASCII local part
  (e.g. `élise@…`) by splitting the leading codepoint — contained by the module
  guard, but it silently voided the whole `search_engines` result for that email
  target. Now drops the first *character*. Regression-tested with several
  multibyte local parts. (A module-wide sweep for the same fixed-offset
  byte-slice / `String::truncate` class found no other reachable cases — the
  remaining slices are on `&[u8]`, length-checked, ASCII-gated, or `Vec`.)
- **UTF-8 panic when capping a crawled page body (silently voided `web_crawler`).**
  `web_crawler` byte-sliced each fetched page to a fixed 64 KiB cap with a raw
  `body[..BODY_CAP]`, which panics when that byte lands mid-codepoint — i.e. on
  any UTF-8 page (emoji / CJK / accents) larger than the cap. The module runs
  under `catch_unwind`, so rather than crashing it **silently discarded every
  `web_crawler` finding** for such a scan (a "nothing omitted" violation). Now
  capped at the nearest char boundary via `str_util::truncate_safe`, which gained
  a dedicated char-boundary test. (Audit of `web_crawler`'s other byte-slices
  found them safe — they index on ASCII-gated scans / `find()` offsets.)
- **Irrelevant "what is HTTPS" pages surfaced for unrelated searches.** Because the
  search module accepts `Url` targets, a URL discovered during expansion (e.g.
  `…/learning/ssl/why-use-https`) was split into search terms — including
  structural tokens like `https`/`www`/`ssl`/a TLD — and `https` (≥4 chars) then
  matched *every* HTTPS-explainer page's path in the relevance gate, admitting
  generic Wikipedia/Cloudflare/etc. definition pages as results. `target_terms`
  now drops a small set of structural web stopwords (`http(s)`, `www`, `ssl`/`tls`,
  common TLDs and file extensions), so they neither pollute dork queries nor match
  unrelated pages. Regression-tested via the gate. (Found in the standard
  `Kylo4kylo` run.)
- **False-positive usernames mined from non-profile social subdomains.** The
  username extractor treated *any* subdomain of a social host as a profile host
  (blanket suffix match), so it pulled junk handles out of CDN/marketing/API
  paths — `pic.twitter.com/<imageid>` → `dhyaqlzo9k`,
  `business.pinterest.com/getting-started`, `create.pinterest.com/creators`
  (all seen in the standard `Kylo4kylo` run). `is_social_host` now accepts only
  the canonical profile-serving hosts — the social root domain or its
  `www`/`m`/`mobile` alias — and the navigation-path blocklist gained
  `creator(s)`, `download`, `followers`/`following`, `foryou` (more platform
  navigation paths confirmed as false positives in a follow-up live run). Real
  profiles (`twitter.com/handle`, `www.pinterest.com/handle`,
  `m.facebook.com/handle`) are unaffected; the noisy candidates are gone.
- **Distinct search results were collapsed when they differed only by query
  string.** The dedup / cross-engine-corroboration key stripped the *entire* query
  (`canonicalize_url`), so `…/watch?v=A` and `…/watch?v=B` (or `…?id=1` vs `…?id=2`)
  mapped to the same key — the second was dropped as a duplicate and the
  corroboration count was inflated across genuinely different pages. Per the
  "no result omitted" rule, the key now keeps content-bearing params (distinct
  pages stay distinct) and strips only known tracking/analytics params
  (`utm_*`, `fbclid`, `gclid`, …), with the kept params sorted so ordering can't
  defeat dedup. The stored URL is unchanged; only the dedup key is affected.
- **Search result URLs were silently truncated at the first query parameter.** The
  multi-engine search parser ran every extracted URL through `form_urlencoded`,
  which splits on `&`/`=` — so a clean result link like
  `https://youtube.com/watch?v=abc123&t=5s` was stored as
  `https://youtube.com/watch?v` (video id and the rest of the query string lost).
  This corrupted any result pointing at a query-parameterised page (videos,
  `?id=`/`?u=` profile and article URLs) and broke the "results in full, complete
  URLs" guarantee. The decode is now applied **only** to percent-encoded redirect
  targets (e.g. Google `/url?q=https%3A%2F%2F…`); an already-clean `http(s)://` URL
  is stored byte-for-byte. Percent-encoded targets still decode losslessly.
  Regression-tested both paths. (Found via the standard `Kylo4kylo` live run.)
- **Panic in `hse import` on a crafted TXT export (slice index out of order).** The
  stealer-log TXT importer sliced `&body[infected_marker .. osint_marker]` without
  checking the markers' order; a file with `=== OSINT ENRICHMENT` positioned before
  `=== INFECTED MACHINES` made `end < start` and panicked (`slice index starts at N
  but ends at M`), aborting the whole `hse import` command (the CLI path has no
  `catch_unwind`). The section-end marker is now sought *after* the start marker, so
  the slice is always well-formed; regression-tested. (Found by an audit for panics
  outside the per-module `catch_unwind` guard, which otherwise came back clean — the
  scan/correlator/API paths uniformly use `.get()`/`unwrap_or`/`saturating_*`.)
- **Concurrent-write races in the persisted JSON stores (toggle store + key pool).**
  Both used a *fixed* temp filename (`settings.json.tmp` / `key_pool.json.tmp`)
  before the atomic rename, so two near-simultaneous writers could truncate and
  interleave into the same temp and rename a torn (corrupt) file into place — which
  the loaders then treat as empty/corrupt, silently dropping every saved override
  (and, for the key pool, every harvested API key). These stores genuinely race:
  the toggle store is web-writable (`PUT /api/v1/settings/toggles`) and the key
  pool is written by modules harvesting during overlapping scans in `hse serve`.
  Both now go through a new shared `util::atomic_file::write` helper that uses a
  **unique** temp per write (pid + a process-local counter), fsyncs, atomically
  renames, and removes the temp on any error — so the rename is always over a
  complete snapshot and a failed write leaves no straggler. Covered by new
  concurrency tests (8 writers hammering one path stay valid + leave no temp).

## [1.3.0] — 2026-06-03

### Added

- **Three keyless, free public-records modules** that deepen the ABN/ACN +
  people graph and cross-correlate on-the-fly (registry 89 → 92), each
  live-validated end-to-end:
  - `acnc_charities` — the federal **ACNC** Register of Australian Charities
    (~65k orgs, `data.gov.au` CKAN) → Organisation / **ABN** / Address / Domain.
  - `gleif_lei` — the **GLEIF** Global LEI Index (~2.7M legal entities) →
    Organisation / **ABN-ACN** (AU `registeredAs`) / Address; an *independent*
    corroborator of the corporate graph (raises `c_effective` via noisy-OR).
  - `wikidata` — the **Wikidata** knowledge graph → Person / Organisation +
    official-website Domain + social-handle Usernames (feeds `username_search`).

### Changed

- **Bounded tokio's blocking-thread pool for Termux (memory footprint).** `main`
  now builds the runtime by hand and caps `max_blocking_threads` at **16**
  (tokio's default is **512**), so a burst of synchronous sqlite / filesystem
  work can't spawn hundreds of OS threads on a low-RAM aarch64 phone. HSE is
  network/IO-bound on its 2-worker runtime, so the cap never serialises a
  realistic workload. Together with the sensor-seed scoping below — which stops
  waking the GPS/Wi-Fi/cell radios on identity scans — this is the session's
  Termux footprint/battery win.

### Fixed

- **Critical UTF-8 byte-slice panics on untrusted data + an API-key leak into the
  persisted event log (security & robustness pass).** A three-front audit
  (core/web, modules, storage/security) surfaced a recurring crash class —
  byte-slicing untrusted strings at a fixed offset that can land mid-codepoint
  (the release profile is `panic = "unwind"` with a per-module `catch_unwind`, so
  a panic *inside* a module is contained but silently voids its results, while a
  panic *outside* the guard kills the scan/live task or the CLI command):
  - `correlator/rule_au_019` sliced an upstream `breach_date` at byte 10 — it runs
    outside the module guard, so a non-ASCII date killed the whole scan/live task
    (live sessions left stuck `Running` forever). Now char-boundary safe.
  - `hse scan` finalisation (`diagnostics`) and `hse import` crashed on entity
    values / import fields with a multi-byte char near the truncation offset.
  - `oathnet_pro` (breach/stealer parsing) and `search_engines` query-building
    sliced untrusted bytes; guard-caught, but each silently voided the module's
    whole result for the scan. All converted to char-boundary-safe truncation.
  - `http::redact_credentials` masked only `name=value` query params, so an API
    key carried in a URL *path* (e.g. IPQS `/api/json/ip/<KEY>/…`) echoed in an
    upstream error body was persisted to the `events` table and streamed over SSE
    in cleartext. A second pass now masks any configured `HUNTSMAN_*` secret
    verbatim, wherever it appears.

- **Coarse geo & name-permutation guesses no longer masquerade as corroborated
  findings (scan-quality pass).** A `name` scan surfaced a pile of postcode
  suburbs, bare postcodes and derived handles in the **Probable** tier and lit
  up ~20 spurious correlations — all rooted in one defect plus three module
  fan-outs:

  - **`geo_normalize` was counted as an independent corroborating source.** The
    geospatial enrichment pass attaches a geohash/timezone/parsed-address
    evidence record to *every* `Coordinates`/`Address`, which inflated their
    `source_count` to 2 — silently lifting single-source coarse geo from its
    base confidence into the **Probable** tier via the agreement model, and
    firing the corroboration correlator rules once per such entity (**AU-003**
    on every address/centroid, **AU-014** on every centroid, **AU-030** across
    the set). It is now excluded from the corroboration count via a new
    `Entity::corroborating_sources` (consumed by `source_count`, AU-014 and
    AU-030) while remaining in the evidence chain and `evidence_sources` for
    display. The Web UI `sourceCount` mirrors the exclusion so the Browse
    tier/confidence match the backend.

  - **`qld_unclaimed` suburb fan-out (#1).** A surname-broadened search
    enumerated *every* suburb of *every* matched postcode — including relatives'
    — as a Probable `Address`. Suburb enumeration is now restricted to the
    seeded person's own **exact-name** postcode(s) (new `exact_postcodes`), and
    the candidate suburbs + postcode centroids are emitted at Candidate
    confidence (0.30) tagged `coarse`.

  - **Bare postcodes ranked like precise addresses (#3).** A
    `"QLD 4552, Australia"` postcode-only `Address` is a coarse region, not a
    residence — it now stays a Candidate-tier, `coarse`-tagged `Address` (exact
    0.38 still ranks above family 0.32); its evidentiary weight lives in the
    unclaimed-money evidence chain, not in a false precise-address tier.

  - **`name_intel` permutation flood (#2).** The speculative email fan-out is
    capped tighter (`MAX_EMAILS` 16 → 8), bare single-token handles
    (`first`/`last` alone) are dropped as non-distinguishing, and the primary
    username weight is lowered (0.42 → 0.38) so *every* derived handle sits in
    the **Candidate** tier — matching the module's documented "low-confidence
    candidate" contract — until a discovery module observes it live (then the
    second source lifts it and AU-035 fires). Recurse on permutations with
    `--min-expand-confidence 0.35`.

  - **Regression-guarded.** A ground-truth correlator test reconstructs the
    operator's `name` scan and pins it at the four real correlations (person
    corroboration, peekyou infra consensus + AU-003, local Wi-Fi) — never the
    28 the `geo_normalize` phantom source used to fabricate — and asserts AU-003
    never flags a coarse geo entity. A `name_intel` test pins every derived
    handle in the Candidate tier.

- **Web UI confidence/tier matched to the engine.** The Browse table computed
  its effective confidence as the multiplicative boost only, but the backend's
  authoritative `c_effective()` — which drives the real tier, expansion and CSV
  export — is the *stronger* of that and an independent-agreement (noisy-OR)
  term added to the core *after* the SPA, so Browse silently **under-reported**
  genuinely multi-source entities (showing Probable where the engine classified
  Verified). The SPA now mirrors `c_effective` exactly, so the tier you see in
  Browse matches the engine, the Correlations view and the CSV.

- **Operator's own device data no longer attributed to the subject (fault-tree
  cut set MCS-A).** The local sensor modules — `device_sensors`, `wifi_intel`,
  `cell_intel`, `local_net` — had `accepts(_) -> true`, so the **seed round** of
  *every* scan ran them and injected the **operator's** GPS, Wi-Fi APs, cell
  towers and ARP table into the **subject's** graph (e.g. a precise device GPS
  fix surfacing as the subject's `Verified` location on a `name` scan). They now
  engage only on a deliberately-local seed (`coordinates` / `mac`); expansion was
  already gated for `LOCAL_PASSIVE_MODULES`, so this closes the seed-round path
  without affecting explicit local/RF recon. Pinned by per-module scoping tests
  and a registry-level invariant so a future sensor module can't reopen the cut.
  *(Solution-tree node S-A1 — the dominant residual the fault-tree analysis
  surfaced. Platform-scaffolding exclusion (S-E1) and inferred quarantine (S-D1)
  remain as follow-ups.)*

- **A panicking module can no longer abort the whole process (error-tree
  ECS-1).** Every module's `process()` now runs behind
  `engine::run_module_guarded`, which wraps the timed future in
  `std::panic::catch_unwind` and maps a panic to a normal, counted module error
  — so a hostile or schema-drifted upstream that trips an `unwrap`/out-of-bounds
  slice is contained exactly like a returned error instead of unwinding into the
  dispatch loop / a `JoinSet` task. The `release` & `fast` profiles switch
  `panic = "abort"` → `"unwind"` so the guard can catch (every other size win —
  opt-level=s, LTO, codegen-units=1, strip — is retained); on a long-lived `hse
  serve` this closes a remote-DoS vector. Verified live: the `kylo4kylo` scan
  ran through `github_user`/`pwned_passwords` transport errors with no abort.

- **`username_search` no longer reports a blocked sweep as a confirmed absence
  (error-tree M6).** It now counts *inconclusive* (blocked / unreachable) vs
  *definitive* not-found probes; with zero hits **and** ≥50% of the 334 site
  probes blocked (WAF / rate-limit / no egress) it returns an
  `inconclusive: N/M …` error instead of a silent `found=0`, and the
  per-platform summary carries `sites_not_found` / `sites_inconclusive`
  breakdowns. Verified live: from a blocked IP the `kylo4kylo` sweep now reports
  `inconclusive: 334/334 …` rather than a misleading zero.

- **HTTP foundation hardened (fault-tree pass on `src/util/http.rs`, the client
  every network module sits on).** Five faults:
  - **OOM (F-A):** `fetch_json` / `fetch_keyed_json` / `json_scanned` buffered the
    *entire* body via `resp.text()` — the exact multi-GB risk `read_body_capped`
    / `error_snippet` already guard, but the JSON paths didn't. Now streamed
    through a 32 MiB cap that errors past the ceiling.
  - **Masked outage (F-B):** a reqwest transport failure that fell through to the
    curl fallback and *also* failed returned `Ok(None)` — which
    `fetch_json_or_404` callers (HudsonRock, Gravatar, OTX, XposedOrNot, BGPView)
    read as a definitive "not found", silently turning a network outage into a
    clean empty result. Now a proper error.
  - **Latent panic (F-C):** the 429 log sliced the key by *byte* index
    (`&key[len-4..]`), which panics when a non-ASCII (harvested) key splits a
    UTF-8 char. Replaced with a char-safe `key_tail`.
  - **Robustness (F-D):** `error_snippet` reported a readable body as
    `<unreadable>` when the 8 KiB cap split a multibyte char — now lossy-decoded.
  - **Doc (F-E):** corrected the `redact_credentials` `key=` comment to match its
    actual (deliberately over-redacting, safe-direction) behaviour.
  New unit tests for the char-safe tail and the redaction behaviour; full suite +
  `clippy -D warnings` green.

- **curl fallback hardened (fault-tree pass on `src/util/curl.rs`, the subprocess
  fetch the HTTP layer drops to).** Six faults:
  - **OOM (B1):** an unbounded `cmd.output()` buffered the entire body — bounded
    with `--max-filesize` 32 MiB (a no-Content-Length stream stays bounded by the
    outer timeout + `kill_on_drop`).
  - **Dropped responses (B2):** strict `from_utf8` discarded any non-UTF-8 body
    (ISO-8859-1 HTML) as a failure — now lossy-decoded, matching `http.rs`.
  - **Dead config tier (B5):** `fetch_pooled` read `HUNTSMAN_PROXY` — a typo of
    the codebase-wide `HUNTSMAN_SEARCH_PROXY` (used nowhere else), so that tier
    never fired; removed (the env-proxy intent is already covered by the direct
    tier inside `curl_exec`).
  - **Drift risk (B6):** the direct and proxied curl paths duplicated ~25 lines of
    arg-building — unified into one `curl_exec(.., proxy_override)` so the SSRF
    pin / proto limits / size cap / headers live in exactly one place.
  - **Inconsistency (B7):** empty proxy-tier bodies leaked as `Some("")` — now a
    miss like the direct tier.
  - **Untested security path (B8):** added the first tests for the SSRF connect-
    pin (refuses RFC1918 / loopback / link-local metadata, pins a public host).
  - One residual documented in-file (**B3**): `curl -L` re-resolves a cross-host
    redirect itself, so redirect-hop IPs aren't vetted in the fallback — reqwest
    is the redirect-vetted primary; fully closing it needs a Rust-side redirect
    loop rather than disabling the redirects the search engines rely on.

- **`hse serve` hardened (fault-tree pass on `src/cli/serve.rs` — the localhost web-UI server).**
  - The startup self-test now runs in a **background task** so the server binds and serves
    immediately instead of blocking on it — the Chrome UI is reachable at once on a low-power device.
  - A `localhost:<port>` bind is pinned to `127.0.0.1:<port>`: `TcpListener` binds a single resolved
    address, so `localhost`→`::1` while Chrome connects to `127.0.0.1` (or vice-versa) was a silent
    "can't connect".
  - Binding a **non-loopback** address now logs a prominent LAN-exposure warning (the localhost-only
    bind is the architecture invariant).
  - Shutdown-signal handlers **degrade gracefully** (log + pend) instead of panicking when a handler
    can't be installed — a failed install no longer crashes the server.
  - `bind` failures carry **actionable hints** (port-in-use / permission / address-not-available — the
    port-in-use case is the common on-device cause). New unit tests for normalisation, loopback
    detection, and the error hints.

- **Proxy pool hardened (fault-tree pass on `src/util/proxy.rs`).** Four faults
  in the free-proxy harvester/validator:
  - **SSRF (B1):** harvested candidates were only length/`:`-checked, so a poisoned
    source could inject `127.0.0.1` / `169.254.169.254` / RFC1918 endpoints that
    the fetcher would then `curl -x` through (proxying via a local/internal
    service). New `is_public_proxy` filter drops private/reserved/non-numeric
    hosts at harvest **and** inside `validate` (defence in depth).
  - **Un-hardened path (B2):** a second, private `curl_get` lacked `--proto` /
    `--max-filesize` / used strict UTF-8 — replaced with the hardened
    `util::curl::fetch`, so source fetches inherit the SSRF pin, size cap and
    lossy decode, and the duplicate is gone.
  - **Resource exhaustion (B3):** `refresh_pool` spawned one validation task per
    candidate → dozens of concurrent `curl` processes on a phone. Now
    semaphore-bounded to 8 concurrent validations.
  - **Coverage (B4):** added an offline test for the public-proxy filter.

- **SSRF foundation closed against IPv4-in-IPv6 bypasses (fault-tree pass on
  `src/util/preflight.rs`).** `is_private_addr` — the predicate every SSRF guard
  (HTTP DNS filter, curl pin, proxy filter, serve loopback check) now relies on —
  classified v6 forms that *embed* a routable IPv4 as public:
  - **NAT64 `64:ff9b::/96`** — Android cellular networks commonly run NAT64/464XLAT,
    so a host resolving to `64:ff9b::<private-v4>` (e.g. `…::a9fe:a9fe` =
    `169.254.169.254`) routed to the embedded internal address while being treated
    as public. **Now decoded and judged by the IPv4 rules** (the highest-impact,
    environment-specific gap).
  - **6to4 `2002::/16`** and deprecated **IPv4-compatible `::a.b.c.d`** embedded-v4
    likewise decoded (IPv4-mapped `::ffff:` was already handled via `to_canonical`).
  - **`0.0.0.0/8`** ("this network") now fully covered, not just `0.0.0.0` — the
    doc had claimed `/8` while the code only caught the single unspecified address.
  New tests for NAT64 / 6to4 / IPv4-compatible (private embedded → rejected, public
  embedded → allowed) and the `0.0.0.0/8` range.

- **Web-UI asset caching fixed (fault-tree pass on `src/api/routes.rs`).**
  - **Stale UI after upgrade:** the SPA HTML was served with no `Cache-Control`, so
    Chrome could heuristically cache it and show an old UI after an `hse` upgrade.
    Now served `Cache-Control: no-cache` (revalidate each load; the document is
    tiny and same-origin).
  - **Wasted mobile bandwidth:** `vendor_handler` set an ETag + `must-revalidate`
    but never handled `If-None-Match`, so it re-sent the full ~510 KB vendor
    bundle on every post-`max-age` revalidation (the ETag was decorative). It now
    answers a matching conditional request with **304 Not Modified** (new
    `if_none_match_hit` helper, unit-tested).
  - *Noted (not changed here):* `is_loopback_bind` is duplicated in `routes.rs`
    and `serve.rs` and diverges on the (invalid) port-less `::1` — a candidate for
    consolidation into a shared helper.

## [1.2.0] — 2026-06-01

### Changed

- **Graceful key UX — unconfigured optional modules no longer look like
  failures.** A module that needs an API key you haven't set returned
  `Err(MissingKey)`, which the engine counted as a **module error** (the
  `virustotal … missing key` noise in your scan). The engine now special-cases
  `MissingKey` into a clean **`ModuleSkipped`** event with an actionable, mostly-
  free signup hint (e.g. *"needs API key HUNTSMAN_VIRUSTOTAL_KEY — VirusTotal,
  free key at …"*), tracked in a new **`modules_skipped`** scan-summary counter
  distinct from `modules_errored`. `hse doctor` now lists every unset key with
  its free-signup URL, and `hse provision --verify` detects missing keys via the
  new skip event. A `keys::signup_hint` registry maps ~30 providers to their
  (mostly free) signup pages.

- **`keybase` identity module reinvigorated.** It already pivoted a username to
  its cryptographically-verified linked accounts, but discarded the verified
  `service_url` of each proof and only recognised 4 platforms. It now surfaces
  every proof's verified profile URL as a first-class `Url` entity, recognises
  `gitlab`/`mastodon`/`facebook`/`twitch`, normalises website proofs to their
  host, and tags verified links `verified`. The proof→entity mapping was
  extracted into a pure `extract_proofs` and is now unit-tested (it had no
  extraction test before). A roster audit confirmed all 89 modules are wired and
  the free-API coverage (Keybase, Wayback, ip2location, ip_geo/ipinfo/ipapi,
  cert_intel, hackertarget, dns_intel, rdap, social_probe, username_search, …)
  is already comprehensive — the scan's "failing" modules were the junk/noise
  fixed below plus key-gated providers awaiting their (mostly free) keys.

### Fixed

- **Documentation / placeholder values polluting scans (`example.com` & co.).**
  `example.com` (and `.org`/`.net`), `jordan@example.com`, `http://example.com`,
  the `example` username, `John Doe`, … now never enter the graph. The existing
  `is_local_domain` check only caught the `.example`/`.test`/`.invalid` TLDs —
  **not** the RFC 2606 second-level `example.com`, which is why a name-permuted
  `example.com` got fully resolved into DNS/RDAP/WHOIS/IP infrastructure (with an
  OTX threat-intel blob attached). A new `validation::is_placeholder_entity` is
  enforced at the engine's admission gate (next to the bogus-IP filter) so it
  covers every module, and `Target::validate` rejects placeholder domains/emails
  at the seed boundary. Matched on whole DNS labels (so `exampleshop.com` is
  untouched). Per the operator's rule, inherently-unique secrets — passwords,
  API keys, raw credentials — are exempt even if they contain "example".

- **CLI seeds weren't validated (`hse scan`/`hse live`).** `Target::validate`
  rejected placeholders only on the HTTP API path; the CLI built the target and
  dispatched without validating, so `hse scan --kind domain --value example.com`
  still ran every module against a reserved domain. Both `cmd_scan` and the
  `live` command now validate the seed first (rejecting placeholders and other
  malformed targets), guarded by a binary-spawning integration test.

- **AlienVault OTX threat-intel tag noise.** `ip_reputation` aggregated every
  pulse's `tags` (hashes, filenames, single chars, freeform notes), sorted them
  **alphabetically** and kept the first 50 — surfacing a junk blob (`.cc`,
  `0007`, `MD5 Hash: …`, "NSO Group" all jumbled, as seen on the `example.com`
  scan). Tags are now ranked by frequency across pulses and filtered to clean,
  meaningful threat categories (≤12); pulse names capped at 5; the freeform
  `adversary` paragraph trimmed to the group name.

- **`urlhaus` 401-failing on every host.** abuse.ch deprecated anonymous access
  in 2024, so URLhaus returned `HTTP 401` for every query. It now sends the free
  abuse.ch `Auth-Key` (read from `HUNTSMAN_ABUSECH_KEY`, falling back to the
  ThreatFox key since it's the same account key) and **skips cleanly when no key
  is set** instead of erroring — no more 401 noise. Register a free key once at
  `auth.abuse.ch` to enable URLhaus + ThreatFox + MalwareBazaar together.

### Changed

- **`see_know` module de-monolithed.** Extracted the SeekNow endpoint matrix
  (the `EndpointCall` spec table, the per-target `plan_endpoints`, the
  free-covered single-origin quota filter `effective_plan`, and the concurrent
  `dispatch_plan` fan-out) out of the 1.2k-line `mod.rs` into a focused
  `endpoints.rs`, mirroring the existing `pivots.rs` split. `mod.rs` now owns
  only orchestration + response extraction (1264 → 897 lines); the dependency
  direction stays one-way (`mod → {endpoints, pivots}`). Pure code-movement —
  no behaviour change; the 10 endpoint unit tests moved with their code and a
  whole-codebase debug sweep (unwrap/panic audit, log-site review, clippy)
  confirmed the tree is otherwise healthy.

### Fixed

- **Breach-dump junk flooding name/identity scans (~88% of results were
  strangers).** A broad `oathnet_pro` search — especially on a `full_name` —
  returns breach rows for many different people. The ingester only confidence-
  gated phone/person/IP rows; **emails, usernames, domains, and social handles
  from non-matching rows were emitted at full 0.70 confidence with no
  `candidate` tag**, so a "Jordan Avery" scan surfaced 90+ unrelated
  bank-employee emails and 78 unrelated bank/credit-union domains as if they
  were the target's. The relevance gate is now centralised and applied to
  **every** breach-derived kind, and `full_name` (and other multi-term) targets
  must match **all** name terms in a single field — so `"Matthew Parker"` no
  longer counts as `"Jordan Avery"` on the shared first name. Non-matching
  rows are preserved as quarantined `candidate` leads (demoted to 0.25), never
  discarded. On the reported scan this takes the default view from 445 → ~53
  entities (~88% junk → ~0%).

- **Correlation engine fusing unrelated entities into "critical" clusters.**
  `candidate`-tagged entities (the non-target breach rows above, plus
  unconfirmed permutations and search-only guesses) now never enter
  correlation — they can't assert relationships. On top of that, `AU-002`
  ("Identity cluster") gained a confidence floor and a dump-size backstop: it
  no longer blindly fuses **every** email + username + phone in a scan into one
  CRITICAL identity (179 unrelated entities on the reported scan), and won't
  fire when any bucket exceeds a plausible single-identity size. Net: the 84
  correlations (86% of them noise) collapse to the genuinely-corroborated few,
  and the 78 unconnected domains stop being linked.

- **`see_know` (SeekNow / "Seek EU") silently doing nothing.** The shared curl
  client only checks curl's process exit code, and curl exits `0` on an HTTP
  401 — so an `{"error":"invalid_api_key"}` response was treated as a
  successful, empty result and SeekNow looked like it "found nothing" on every
  seed. It now detects the auth-rejection envelope, logs an **actionable
  warning once** ("set a valid key in UI Settings / `HUNTSMAN_SEEKNOW_KEY`"),
  fast-fails the remaining ~160 doomed lookups for that scan, and re-tests the
  key each new scan so a corrected key recovers without a restart.
  *(Diagnosis: the bundled key is currently rejected by see-know.eu — a valid
  key must be supplied for SeekNow to return data.)*

- **Target values keeping shell/CSV quoting.** A `full_name` target submitted as
  `"Jordan Avery"` (literal quotes) reached the pipeline with the quotes
  intact, polluting every name-derived permutation. Targets are now sanitised at
  the input boundary — surrounding quotes (incl. smart quotes) and stray list
  punctuation are stripped before normalisation.

- **Log flood on CLI scans.** Every event emission logged `broadcast dropped
  (no subscribers)` at TRACE when no SSE client was attached — the normal case
  for `hse scan`/`live` from the terminal — producing one line per entity
  (hundreds on a breach-heavy scan) that buried the real output. The event is
  already durably persisted (the CLI reads the store, not the bus), so a missing
  live subscriber is now a silent no-op.

### Added

- **`include_candidates` query toggle on the entity list and JSON report.**
  `GET /scans/{id}/entities` and `GET /scans/{id}/report.json` now **hide
  quarantined `candidate` entities by default** (the clean, confirmed-footprint
  view); pass `?include_candidates=1` to get the full set including speculative
  leads. The CLI `hse export --format report` likewise defaults to the
  confirmed-only dossier.

- **Prebuilt-binary fast path in `install.sh` (primary; build is the fallback).**
  The installer now scans Downloads / shared storage for a precompiled aarch64
  `hse`, validates it (size + ELF magic + optional `.sha256` + a noexec-safe
  run-test), and installs it directly — skipping the Rust toolchain and the
  source build entirely (seconds, no build). If none is found it builds from
  source as before, and then **caches the freshly-built binary back to
  Downloads** as `hse-aarch64-linux-android` (+ `.sha256`), so the next
  install — this device after a wipe, or another aarch64 phone — takes the
  instant prebuilt path. Override with `HSE_PREBUILT=/abs/path`, add a search
  dir with `HSE_DOWNLOADS`, or force a build with `HSE_PREFER_BUILD=1`.

### Performance

- **Fast on-device build profile.** The `release` profile's single-threaded LTO
  link (`codegen-units=1`, `lto=true`) makes an on-phone build take ~15-20 min;
  the new `[profile.fast]` (`lto=false`, `codegen-units=16`, `opt-level=2`) cuts
  that to ~4-6 min for a ~35% larger binary and a negligible runtime cost (HSE
  is network/IO-bound). `install.sh` now defaults to `fast` on Termux
  (`HSE_BUILD_PROFILE=release` or `HSE_FULL_BUILD=1` for the smallest artifact),
  and the build step prints the chosen profile + ETA.

### Added

- **Real-time radar mode** — a continuous, toggleable sweep that is *not*
  aggressive with the APIs. Enabled via `live.radar` (Web UI Settings → Live
  "Radar" toggle, `POST /api/v1/live`, or `hse live --radar`), it persists ONE
  keyed-module dispatch ledger across every sweep through the new
  `ScanEngine::run_with_ledger`, so a paid/keyed module never re-queries a seed
  an earlier sweep already covered. Each sweep spends API budget only on
  genuinely NEW seeds (the free modules still re-run and keep surfacing leads);
  toggle on with start, off with stop. Classic live re-scan (re-query
  everything each interval) remains the default when the flag is off. Also
  upgraded the confidence model — `c_effective` now takes the stronger of the
  legacy multiplicative boost and an independent-agreement (noisy-OR) floor, so
  cross-source corroboration drives confidence toward certainty.

## [1.1.0] — 2026-06-01

### Added

- **Self-validation harness** (`hse selftest`, `GET /api/v1/selftest`, and a
  Settings → Diagnostics button). One offline suite validates every module and
  core feature — registry integrity, the dispatch-index↔`accepts()` invariant,
  `consumes()` coverage, an all-module metadata probe, core scoring maths, key
  load, an end-to-end storage+correlator round-trip, log-capture wiring, and the
  Termux environment. Runs automatically (`hse selftest` exits non-zero on
  failure; `hse serve` runs it at startup and logs a summary) and on demand.
- **Downloadable verbose debug logs.** A bounded in-memory ring buffer tees a
  clean copy of the default TRACE-level logs, served as a text attachment at
  `GET /api/v1/logs` / the Settings "Download debug log" button.
- **Statistical yield-curve expansion depth.** `--auto` depth is now chosen by a
  geometric marginal-yield model (`m(d) = m₁·q^(d−1)`, cut at the engine's own
  `dE/dDispatch` floor) grounded in real scan telemetry, replacing hand-tuned
  constants that the `MAX_DEPTH` clamp had silently flattened to a uniform 3.
- **Corroboration-weighted pivot ranking.** Expansion weight gains an uncapped
  `1 + 0.25·ln(source_count)` factor so cross-corroborated leads expand first
  (recovering the signal `c_effective`'s 1.0 clamp had erased), plus a
  `max_roi` relative-knee cut that drops the long tail below 5 % of the round's
  leader.
- **Iterative multi-hop identity pivots (SeekNow).** Discord/Steam ID resolution
  now chases linked-account chains (discord → roblox → steam → …) across bounded
  hops within budget, instead of a single pass — closing cross-platform identity
  graphs inside one scan.
- **Settings → API keys is editable by default.** The loopback-only key-write
  endpoint is on out of the box (`--no-key-write` to disable); SeekNow and Exa
  now appear in the Settings grid.
- **Offline AU postcode gazetteer fallback** so validated locality geo (e.g. QLD
  4552 — Maleny/Booroobin/Conondale) still resolves when the network lookup is
  unreachable on a flaky mobile connection.
- **All-in-one installer converges in-place:** `./install.sh` run from inside an
  existing clone now upgrades that clone rather than maintaining a second one.

### Performance

- **Termux sensor fast-fail.** `util::termux::termux_cmd` now caches a tool that
  times out or won't spawn as unavailable for 5 min and short-circuits it — so
  an ungranted location/telephony/wifi permission costs its full timeout at most
  once every few minutes instead of ~20-30 s of dead wait on **every** scan
  (`device_sensors` + `wifi_intel` + `cell_intel`). Re-probes after the TTL so a
  later-granted permission is still picked up.

### Changed

- **SeekNow spends paid quota only where free can't reach.** The single-origin
  presence endpoints (github/twitter/reddit/tiktok/roblox/xbox/minecraft) are
  filtered out — `username_search` (600+ sites), `social_probe` and
  `search_engines` already cover them for free — leaving SeekNow's lookups for
  breach/stealer/history aggregation and ID resolution. Per-scan budget raised
  to 160. Embedded SeekNow key refreshed and **auto-rotated** in existing
  keystores.
- **Termux timeouts trimmed.** Per-module Termux cap 60 s → 45 s and a new
  `termux_timeout_ms()` (search_engines → 30 s, finalising partials instead of a
  hard kill) reclaim ~tens of seconds/scan previously burned for zero results.
- **`see_know` module refactored** — identity-pivot primitives extracted to
  `pivots.rs`; the endpoint matrix (`get_path`) now retries a transient
  transport error once (same budget slot).

### Fixed

- **hudsonrock** no longer fires a doomed `HTTP 400` on bare-username seeds
  (accepts Email/Domain only — value-independent, satisfying both dispatch
  invariants); **opencorporates** keyless `401/403` is a clean skip, not a WARN.

## [1.0.1] — 2026-06-01

### Security

- **Closed an IPv4-mapped IPv6 SSRF-filter bypass.** `util::preflight::is_private_addr`
  — the single predicate behind every SSRF chokepoint (the reqwest DNS filter
  `http::SsrfResolver`, the redirect-hop gate, the curl `--resolve` pin, and the
  engine's `Url`-target admission gate `url_host_is_private`) — range-tested the
  raw address, so an IPv4-mapped IPv6 literal or `AAAA` record such as
  `::ffff:169.254.169.254` parsed as `V6`, missed every v6 reserved-range check,
  and was treated as **public** — reaching the underlying IPv4 host (cloud
  metadata, loopback, RFC1918) the OS connects an IPv4-mapped address to. The
  predicate now canonicalises with `IpAddr::to_canonical()` before testing, so a
  mapped address is judged by the v4 arm; `::1`, `::`, ULA/link-local and real
  public v6 are untouched. Because the check is centralised, the one-line fix
  closes the bypass on all four paths at once. New regression tests pin the
  mapped-private and mapped-public cases, proven by reverting the fix in place.

### Fixed

- **`redact_credentials` no longer mojibakes non-ASCII error text.** The
  credential-masking pass — which scrubs `?api_key=…`-style secrets out of
  upstream error bodies before they reach module errors and logs — copied
  non-matching input one byte at a time as `byte as char`, reinterpreting every
  multi-byte UTF-8 sequence as Latin-1. The secret was still masked, but a
  provider's localised error (`clé API invalide`), an IDN host, or an em-dash
  surfaced as `clÃ©` / `â`. It now assembles output on a byte buffer and decodes
  once; redacted runs are ASCII-delimited (`name=` … `& \n \r "` / EOF), so
  verbatim byte-runs never split a char and the result is valid UTF-8 by
  construction. Masking is byte-identical on ASCII input (the six existing tests
  pass unchanged); a new test pins credential-masked **and** non-ASCII-preserved.

### Added

- **`email_canonical` module — canonical-mailbox normalisation (free, offline).**
  Emits the provably-equivalent canonical address for an `Email` seed so the
  same mailbox written several ways collapses to one identity node instead of
  fragmenting the graph: `+tag` subaddressing is stripped (`jdoe+news@x.com` →
  `jdoe@x.com`, as supported by Gmail / Microsoft / Fastmail / Proton / iCloud),
  Gmail dot-blindness is applied (`j.doe@gmail.com` → `jdoe@gmail.com`), and the
  `googlemail.com` alias folds to `gmail.com`. Pure string transform — no
  network, no new deps. Because the result is a documented routing equivalence
  (not a guess), it is emitted at 0.80 — above the 0.50 expansion floor — so a
  `--depth 1+` scan pivots the whole email pipeline (`hibp`, `hunter_io`,
  `epieos`, …) onto the canonical mailbox; an already-canonical seed emits
  nothing. Directly serves cross-correlation: the shared canonical address
  accumulates corroboration where the look-alike variants were weak singletons.
  Brings the registry to **89 modules**; 10 unit tests cover each equivalence
  and the already-canonical / malformed-address paths.

- **`username_variants` module — alternate-handle derivation (free, offline).**
  Turns a discovered `Username` seed into the handful of high-likelihood
  alternate handles a target reuses across platforms, feeding `username_search`,
  `social_probe`, `github_user`, and `keybase` at `--depth 1+`. Pure string
  transforms — no network, no new deps. Two *normalisation* families only,
  never speculative additions: **separator swaps** (`john.doe` → `john_doe` /
  `john-doe` / `johndoe`, the same handle for each platform's punctuation
  rules) and **de-decoration** (strip a trailing disambiguator `jdoe1990` →
  `jdoe`, or separator-bounded vanity tokens `the_real_jdoe` / `jdoe_official`
  → `jdoe`). A plain, undecorated handle yields nothing — there is no
  defensible transform and `username_search` already probes the exact handle —
  and additions like `jdoe1` are deliberately not produced (noise). Variants
  are emitted as 0.42 *candidates* (below the 0.50 expansion floor) so a
  `--depth` scan never auto-spends on a guess; they enrich the graph and feed
  the new AU-034 handle-reuse correlator, crossing the floor only when an
  independent source corroborates them. Output is capped at 12 per seed for
  Termux. Brings the registry to **88 modules**; 11 unit tests cover every
  transform and suppression path.

- **`AU-034` — handle-reuse identity link (username ↔ email).** A new
  cross-correlation rule: when a discovered `Username` and the local-part of a
  discovered `Email` share the same separator-insensitive handle (`jmeyers` ↔
  `jmeyers@gmail.com` — dots/underscores/hyphens folded and Gmail `+tag`
  suffixes stripped), they are linked as one identity. This is the everyday
  analyst pivot the kind-specific rules don't make (AU-011 is one username
  across many platforms; AU-020/AU-023 cluster `Person` entities). Gated to
  stay quiet: the handle must be ≥4 chars and neither a placeholder (`admin`)
  nor a role mailbox (`info@`, `support@`, …), and the username plus its
  matched emails must carry ≥2 *distinct* evidence sources between them — so a
  single module that mints both a candidate username and a candidate email from
  one seed (e.g. `name_intel`) can't self-correlate; the reuse must be
  independently observed (mirroring the ≥2-source gate AU-001/AU-023 use).
  Brings the correlator to 34 rules. Six unit tests cover the match, the
  separator/`+tag` folding, multi-email grouping, and every suppression path.

- **`AU-035` — inferred handle confirmed in the wild.** Closes the
  derivation→discovery loop: a `Username` that was first *derived* by inference
  (a `name_intel` permutation, an `email_parse` local-part, or a
  `username_variants` handle) and then *independently observed* on a real
  platform (`username_search`, `github_user`, `keybase`, `social_probe`, …) is
  surfaced as a high-value identity hit — a guessed handle that turned out to
  exist. Both an inference source and a discovery source must be present on the
  same merged entity, so a handle that was only observed (an ordinary find) or
  only guessed (an unconfirmed candidate) does not fire; distinct from AU-011
  (one handle across many platforms) and AU-034 (username ↔ email handle reuse).
  This is the payoff the derivation modules set up but no rule rewarded. Brings
  the correlator to **35 rules**; three unit tests pin the confirm path and both
  single-source suppression paths.

- **`AU-036` — email alias convergence (one mailbox).** Closes the
  `email_canonical` loop the way AU-035 closes handle derivation: when ≥2
  distinct addresses fold to the *same* canonical mailbox (e.g.
  `j.doe@gmail.com` and `jdoe+news@gmail.com` both → `jdoe@gmail.com`), they
  are aliases of one inbox — a strong same-person link and useful intel in
  itself. The rule reads the canonical `Email` entity's accumulated
  `email_canonical` evidence (each record carries the `source_email` it was
  folded from; the per-source summaries survive the merge dedup) and fires at
  ≥2 distinct sources — no module logic duplicated. Brings the correlator to
  **36 rules**; three unit tests cover the convergence, the single-alias no-op,
  and non-canonical evidence.

- **Hard `MAX_DEPTH=3` recursion ceiling, enforced at every operator boundary.**
  `ScanOptions::clamp_depth()` caps operator-requested expansion depth (CLI
  `scan`/`--recursive`/`--auto`, the HTTP scan-create/batch path, and live
  sessions) at `MAX_DEPTH` (3), warning once when it clamps. The engine already
  cannot infinite-loop (visited-set + entity budget + wall-time watchdog — see
  `tests/halting.rs`); this is a Termux resource guard so a stray `--depth 1000`
  can't fan the frontier out exponentially on a phone. `--recursive` now targets
  the ceiling (was 7) and `optimal_depth` (`--auto`) is clamped too; the engine
  core stays uncapped so the halting proofs still drive it at high depth.

- **`AU-033` — Australian business identity correlation (ABN/ACN ↔ organisation).**
  Links an ABN/ACN registration to the registered organisation(s) it belongs to
  when both surface from an Australian registry (`abn_lookup`/`opencorporates`),
  closing the registry-chain gap those modules produced but no rule joined.
  Organisations are gated on a registry tag so unrelated org names don't link.

- **Registered the orphaned `pwned_passwords` module.** It was fully implemented
  (free HIBP k-anonymity breach check) but never in `registry()` — dead at
  runtime. Now registered (87 modules) with a `every_declared_module_is_registered`
  guard test so it can't silently regress.

- **`name_intel` — NAMINT-style name intelligence (offline).** A faithful,
  bounded port of the methodology in [NAMINT](https://seintpl.github.io/NAMINT/)
  that supersedes the thin `name_to_username` module (12 naïve patterns, usernames
  only). From a `FullName` seed — and an optional trailing year/number, e.g.
  `"Jordan Leigh Meyers 1987"` — it derives, with **no network calls and zero new
  dependencies** (`md-5`/`hex`/`url` were already vendored):
  - up to 24 scored **usernames** (`first.last`, `flast`, `firstl`, reversed,
    hyphen/underscore joins, middle-initial blends, year suffixes), best-first by a
    real-world-frequency weight — feeding `username_search`, `social_probe`,
    `github_user`, `keybase`;
  - up to 16 speculative **emails** crossing the highest-signal handle shapes with
    a provider set (NAMINT's iCloud/Yahoo/Hotmail plus Gmail/Outlook/Proton,
    overridable via `HUNTSMAN_EMAIL_DOMAINS`) — feeding the entire email pivot
    pipeline (`hibp`, `hunter_io`, `epieos`, `emailrep`, `disposable_check`,
    `email_parse`), each carrying its **Gravatar** avatar URL (`MD5(email)`);
  - up to 18 ready-to-click **search-query pivots** (Google web/face/email/phone/
    document/paste dorks, Bing, DuckDuckGo, Yandex face, LinkedIn, Facebook, X,
    Instagram, TikTok, GitHub, WhatsMyName, Epieos) as `Url` entities.

  Permutations are emitted as low-confidence *candidates* (usernames ≤ 0.42,
  emails 0.30, pivots 0.20) — deliberately below the default `min_expand_confidence`
  (0.50), so a `--depth` scan never auto-spends API budget on guesses while the
  entities still enrich the graph and feed the correlator's identity-surface rules.
  To pivot on them, lower the floor (`--min-expand-confidence 0.40 --depth 1`).
  Output is `MAX_*`-capped so a single name target generates constant-bounded work
  — important on low-power Termux/aarch64. 26 new unit/integration tests; suite
  green.

- **Clickable URL entities + evidence in the Web UI.** The Browse table now
  linkifies `http(s)` entity values and evidence attributes (`target="_blank"
  rel="noopener noreferrer"`, `javascript:`/`data:` left inert and escaped), so
  `name_intel` search pivots and Gravatar URLs are one click away — matching
  SpiderFoot's URL-event affordance and NAMINT's link-generator workflow.

- **Synchronized FTS5 full-text entity index (the indexing layer, from #90).**
  Entity search was a substring `value LIKE '%q%'` scan — no tokenization, no
  relevance, no word-order independence. Added a contentless-external SQLite FTS5
  table (`entities_fts`, `unicode61`, `prefix='2 3'`) maintained **inside the same
  transaction** as every entity write, so the index can never drift from the graph;
  it backfills pre-existing rows on open. `search_entities` now runs a ranked FTS
  `MATCH` (bm25 + confidence tiebreak) over per-token prefix queries with a `LIKE`
  fallback for infix queries, upgrading `GET /api/v1/search` and the Web UI search
  to tokenized, word-order-independent, ranked results with zero caller changes.
  No new deps (FTS5 ships in bundled SQLite); ARM64-friendly.

### Changed

- **Bounded the SQLite WAL footprint on aarch64 (from #90).** `PRAGMA
  wal_autocheckpoint=512` (~2 MB) plus `Store::checkpoint_truncate()` (a
  `wal_checkpoint(TRUNCATE)` run at each scan boundary in `finalise_scan`) keep the
  live `-wal` file from high-water-marking and holding under a long-lived `serve`/
  `live` process on a 4 GB phone. Exposed on `StoragePort` with a default no-op for
  non-WAL backends.

- **`name_intel` handles diacritics: `José` → `jose`, not `jos`.** The handle
  tokeniser now folds Latin diacritics to their base ASCII letter via the
  shared `util::str_util::fold_ascii_lower` (é→e, ü→u, ł→l, ç→c, ß→ss, æ→ae,
  …) instead of dropping the accented character outright, so migrant/EU names
  (common in AU OSINT) derive the matchable handle real platforms use. Non-Latin
  scripts (Cyrillic/CJK) have no ASCII fold and still yield no handle — the name
  parses for display-name search pivots only. Revives the previously-orphaned
  `fold_ascii_lower` helper (its only caller, `name_to_username`, was removed).

- **Refactored the recursion core's duplicated key-cascade and skip-emit.** The
  hot-inject key-cascade — the mechanism that makes recursion compound (a key one
  module discovers becomes usable by the next module and the next round) — was
  copy-pasted in three places (`run_expansion` per-round refresh, plus the
  sequential and concurrent dispatchers' per-module inject), and the
  `ModuleSkipped` event was hand-built at six call sites. Extracted a single
  `hot_inject_keys(&mut keys)` (idempotent, gap-filling) and an `emit_skipped`
  helper. Behaviour-preserving: which keys land in `ctx` and which skip events
  fire is unchanged (the only delta is `run_expansion` now logs hot-injects too,
  matching the dispatchers — observable scan behaviour is identical). Proven by
  the `key_chaining_*` smoke tests and the engine suite, full run unchanged at
  1353.

- **Termux-aware per-module timeout cap so a slow upstream can't stall a phone
  scan.** Audit of `max_timeout_ms` found a handful of modules legitimately set
  very long timeouts (search_engines 120 s, api_key_probe 90 s, hibp/web_crawler
  60 s) — fine on desktop, but on a low-power, metered, often-flaky mobile
  connection a single such module can hang the whole scan for minutes.
  `resolve_timeout` now clamps any module to 60 s **only on Termux and only when
  the operator hasn't pinned `--module-timeout`** (an explicit timeout is honoured
  verbatim; desktop is unchanged). Split into a pure `apply_termux_cap` with a
  unit test covering desktop pass-through, Termux clamping of the 90/120 s
  offenders, short-timeout pass-through, and user-override precedence. (Verified
  in the same pass that absent external binaries already degrade fast: the
  curl-subprocess modules return `None` on an immediate spawn error rather than
  burning their timeout, so a minimal Termux without `curl`/`termux-api` doesn't
  hang.)

### Fixed

- **Aggregate correlations no longer persist a duplicate row per expansion round.**
  Rules whose member set grows each round (AU-002/013/018/019/…) defeated both
  the in-memory (rule_id+uids) and DB (rule_id+description) dedup keys.
  `Store::upsert_correlation` now dedups by **set containment**: a superset
  supersedes the stale subset row, a subset/equal is skipped, disjoint clusters
  coexist — correct for singleton aggregates, multi-cluster aggregates and pair
  rules alike, no schema change. Deterministic test pins it.

- **Web UI: the Dashboard no longer crashes on load and the search box works.**
  `renderDash` called a non-existent `API.stats()` (the default landing page
  showed only an error banner); the global entity search hand-mutated `S.route`
  in a shape `render()` discarded, so FTS results never displayed. Added
  `API.stats`/`API.search` and a real `#/search` route; added a Relations
  provenance tab and clickable correlation drill-in.

- **ROI saturation prune counts distinct sources, not summed magnitude.**
  `roi::is_saturated` read the inflated `corroboration` field, so an 8-row
  single-source hit was wrongly pruned from expansion under `--max-roi`; it now
  uses `source_count()` like the rest of the engine.

- **`--value` accepts a leading `-` so southern-hemisphere coordinates scan (from #90).**
  `hse scan --kind coordinates --value "-27.47,153.02"` (Brisbane) aborted with
  clap's *unexpected argument '-2'*; the scan/live `--value` args now set
  `allow_hyphen_values`, so a negative latitude is taken as the value. A real
  AU-OSINT failure mode (the entire southern hemisphere has negative latitude).

- **Module synergy graph made truthful: completed `produces()` across ~60
  modules.** Empirical audit of the producer→consumer graph (via
  `/api/v1/modules/graph`) found the dispatch index is built from `consumes()`
  (so runtime expansion always worked), but the `produces()` declarations that
  drive the *displayed* synergy graph were absent on 62 modules — the default
  returns `&[]` ("hasn't declared its outputs yet"). So the graph the operator
  navigates in Chrome under-reported producers (e.g. `abn_acn` showed
  produced-by-nobody while `abn_lookup`/`opencorporates` both emit it). Declared
  the real outputs for every module that emits entities (driven by each module's
  `Entity::new(EntityKind::…)` sites), fixing partial declarations
  (`search_engines` +Coordinates/AbnAcn, `social_probe` +Domain, `shodan`/
  `device_sensors` +IpAddress, `qld_unclaimed` +Coordinates) and adding full
  `produces()` to ~55 others (whois, github_user, keybase, the IP-geo family,
  the DNS/reputation modules, …). Modules declaring ≥1 output went from ~24 to
  **75/86**; hub-producer counts roughly tripled (address 8→32, domain 9→31,
  coordinates 8→22, organisation 9→20, person 5→15). New invariant test
  `every_declared_produced_pivot_has_a_consumer` proves every produced pivot
  kind has a consumer (zero dead-ends) and guards against future drift.

### Added

- **`util::postcode_au` + suburb-level enumeration for `qld_unclaimed`.** The
  register carries only a 4-digit postcode, but a QLD postcode is not one place —
  `4552` spans Maleny, Landsborough, Booroobin, Conondale, Witta and more.
  Probing established that data.qld's locality datasets are spatial-only
  (`datastore_active=false`, shapefiles/WMS) and a Nominatim postcode query
  returns a single centroid, so neither enumerates; **Zippopotam**
  (`api.zippopotam.us/au/{pc}`, keyless JSON) does — it returns each locality
  with a lat/lon. New `util::postcode_au` resolves a postcode to its localities
  (best-effort: any failure → empty, so the module degrades to the bare
  postcode). `qld_unclaimed` now expands each distinct result postcode (capped at
  6 lookups × 8 suburbs) into a postcode-centroid `Coordinates` anchor plus one
  suburb-precise, individually geocodable `Address` per locality
  (`"Maleny, QLD 4552, Australia"`), tagged `candidate-suburb` at low confidence
  (below the 0.50 expansion floor) since the owner is in *one* of them — depth
  for disambiguation, not auto-expansion. Pure parse + entity-build are
  unit-tested against the real 4552 payload (which enumerates Booroobin).

- **`util::abn` — shared, checksum-validated ABN/ACN identification, wired into
  the OSINT graph.** Probing established the ABR ABN Lookup web service is
  strictly GUID-gated (both `AbnDetails` and `MatchingNames` reject any call
  without a registered GUID), so there is no keyless name→ABN lookup; the
  existing key-gated `abn_lookup` remains the only direct resolver. Instead,
  ABNs are *incorporated algorithmically*: a new `util::abn` validates an ABN by
  its ATO modulus-89 weighted checksum and — newly — an ACN by its ASIC
  check-digit (the prior search-engine extractor validated ABNs but accepted any
  9-digit number next to the word "acn"; that path now requires the ACN
  check-digit too). `looks_like_company` detects corporate legal forms (PTY LTD /
  LIMITED / LTD / INC / NL / & CO) at word boundaries. `qld_unclaimed` now uses
  it to emit an `Organisation` entity for company-form unclaimed-money owners, so
  the engine's expansion pivots them into `abn_lookup`/`opencorporates` and
  resolves the ABN/ACN — connecting the unclaimed-money graph to the federal
  business registry. Canonical-value unit tests (ATO ABN 51824753556; ASIC ACN
  000000019) pin both checksums and the company/individual split.

- **`qld_unclaimed` module — Queensland Public Trustee unclaimed-money register
  (free, keyless).** Searches the Public Trustee's unclaimed-monies register
  (money owed from deceased estates, insurance refunds, payroll remainders,
  government refunds, …) for a `FullName`/`Organisation` seed via the Queensland
  Open Data Portal's CKAN `datastore_search` API — public, weekly-refreshed, no
  key. For each matching record it emits the owner's lodged postcode as a
  geocodable `Address` (so the existing geocode→coordinates pipeline can pivot on
  it), carrying owner, amount, sender, date and reference number as evidence;
  records without a usable postcode still surface as an `unclaimed_money` finding
  so nothing is dropped. A pure `records_to_entities` transform is unit-tested
  against the register's real JSON shape (incl. CKAN numeric-field coercion and
  the no-postcode path). Exactly the Australian people-centric public-records
  source the charter targets; brings the registry to 87 modules.

  Query strategy (refined against live data): the register's full-text search
  ANDs multi-word terms, so a full-name seed alone misses the deceased-estate
  funds owed to *relatives* (same surname, different given name). The module
  therefore runs a **two-tier query** — an exact full-name probe whose rows lead
  (so the seeded person's own record can't be capped out behind a common
  surname's namesakes) merged ahead of a broadened **surname** probe for family
  recall — then classifies each row `exact-name-match` vs `family-candidate`,
  weighting confidence so common-surname noise (verified to stay at C_eff 0.40,
  below the 0.50 expansion floor) is surfaced but never auto-expanded.
  Reconnaissance note: QLD is the only AU jurisdiction that publishes its full
  per-owner unclaimed-money register as a queryable open dataset — NSW/VIC expose
  aggregates only, WA/ASIC are search-portal-gated — so this is deliberately a
  single-jurisdiction module, not the first of N state clones.

### Removed

- **Deleted two dead `pub fn`s (~110 lines).** `util::see_know::credits` and
  `util::oathnet::harvest_credentials` had zero call sites anywhere in the crate
  (binary, lib, or tests) and were never re-exported — `harvest_credentials` was
  left orphaned when the pre-scan OathNet harvest was disabled, and `credits`
  was aspirational (its doc described a quota-gating use that no caller ever
  wired up). `clippy -D warnings` can't flag unused `pub` items in a lib, which
  is why they survived. Removal verified clean: build + `clippy -D warnings`
  stay green (no private helper orphaned) and the full suite is unchanged at
  1326 passed, confirming nothing depended on them. Analysed-but-kept: all deps
  are used; the `#[allow(dead_code)]` annotations are on deliberate API-response
  struct fields (documentation of the wire shape); the duplicated hardcoded keys
  are intentional per the operator's standing instruction.

- **Stripped non-functional governance + narrative docs.** Removed the process
  "rules and regulations" that carry no build or runtime effect: governance docs
  (`CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `SECURITY.md`) and the `.github/` PR +
  issue templates; and the narrative/charter docs (`docs/BLUEPRINT.md`,
  `docs/DESIGN.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`). Functional code is
  untouched — all 87 modules, the 32 correlator rules, `#![forbid(unsafe_code)]`,
  the CI workflow, the architecture-invariant tests, the LICENSEs, this CHANGELOG,
  and the operational docs (`USAGE`, `INSTALL`, `MODULES`, `TROUBLESHOOTING`,
  `API_KEY_HUNTING_GUIDE`, `OATHNET_API_GUIDE`) remain. README's doc index was
  updated to drop the two now-deleted links. Build + full test suite unchanged
  (1326 green), proving nothing in code/tests depended on the removed files.

### Fixed

- **`install.sh` header no longer understates the Rust requirement.** The banner
  comment claimed "rustc 1.85+" while the script itself enforces 1.88 (`ver_ge
  "$RUST_MAJ_MIN" "1.88"`), matching `Cargo.toml`'s `rust-version`, the README
  badge, the CI MSRV job, and `docs/INSTALL.md`. A user reading the header would
  believe 1.85–1.87 works, but the `cargo build --release --locked` hard-fails
  under 1.88; aligned the comment to 1.88 so the installer's stated and enforced
  requirements agree.

- **CI green under Rust 1.96 stable: collapsed a nested `if` clippy now rejects.**
  `clippy::collapsible_match` (enforced under `-D warnings`) became stricter in
  1.96.0 and flagged an arm in `tests/smoke.rs` whose body was solely an
  `if marker_start.is_none()` guard — collapsed into the match guard
  (`… if module == "expansion_marker" && marker_start.is_none() =>`),
  behaviour-identical (first expansion-marker still wins; later ones fall to
  `_`). The failure only appeared on CI because its `stable` toolchain had
  advanced past the local one; updated local to 1.96.0 to reproduce.

- **`events.history` and `graph.gexf` now 404 for unknown scans (PR #87 review).**
  Both sub-resource handlers skipped the `scan_missing` guard that the other
  `/scans/{id}/…` endpoints use, so an unknown scan id returned `200` with an
  empty events list / empty-graph GEXF document — the misleading "found nothing"
  response the guard exists to eliminate. Added the early-return to both and
  extended `sub_resource_endpoints_404_for_unknown_scan` to cover them so the
  consistency invariant can't silently regress.

- **Timeline date parser no longer accepts a malformed time as midnight (PR #87
  review).** In `parse_date`, when a `T`/space time part was present but its
  components failed to parse (e.g. `2019-03-15Tinvalid`), each fell back to `0`
  via `unwrap_or(0)`, so validation passed and the value was accepted as
  `00:00:00`. The hour is now mandatory and the minute mandatory-when-present
  (a present-but-unparseable component rejects the whole timestamp). Seconds
  stay lenient on purpose — `split(':')` glues a timezone offset onto that token
  (`00+05` from `+05:00`), so strict parsing there would wrongly reject valid
  offset timestamps. New test covers malformed rejection, hour/minute-only
  validity, and offset tolerance.

- **see_know `/search` transient empties no longer poison the scan; curl errors
  are diagnosable.** The name/auto `/search` path intermittently returns
  `total:0` for records that exist (server-side cap races). Previously that empty
  was cached, so every later lookup of the same query returned nothing for the
  life of the process — and when curl itself failed, the module logged an opaque
  `[seek_now] curl failed`. Two fixes: (1) `cache_put` now refuses to memoise an
  empty result (covers `/search` *and* every `get_path` endpoint), and `search`
  retries once on a transient empty; (2) the shared `CurlClient` now reports
  curl's exit code + a trimmed stderr snippet (`curl exited 28: …`) instead of
  `curl failed`. Live `hse scan --kind name --value "Jordan Meyer" --modules
  see_know` now returns 185 entities on a single attempt where it intermittently
  returned 0. Regression tests pin both invariants (empty-never-cached;
  error-carries-exit-code), each proven by reverting the fix in place.

### Changed

- **Added a `bad_request` response helper, collapsing 10 open-coded 400 sites.**
  `internal_error` and `not_found` already existed as shared response builders,
  but every `400` was hand-written as `(StatusCode::BAD_REQUEST, Json(json!({
  "error": … })))` — ten times across the scan/live/search/settings handlers,
  each an opportunity for an inconsistent body shape. Introduced
  `bad_request(impl Into<String>)` (accepts `&str` literals and `format!`/`String`
  messages alike) and routed all ten through it; the open-coded `BAD_REQUEST`
  count in `src/api` drops from 10 to 1 (the helper). Behaviour-preserving — the
  status and `{"error": …}` body are byte-identical, proven by the existing API
  tests that assert the exact 400 responses (`*_rejects_invalid_target`, the
  filter length-guards, the batch size guards). Suite unchanged at 1334.

- **Unified target validation across the scan- and live-create endpoints.**
  `live_create` (`POST /live`) repeated the same `Target::new` + `validate()` +
  `invalid target: …` error construction that the scan path already had, so the
  admission rule and its error wording lived in two places and could drift.
  Extracted `validated_target(kind, value) -> Result<Target, String>` as the
  single source of truth; both `build_scan_from_request` and `live_create` now
  funnel through it. Added a unit test for the accept/reject-prefix behaviour.
  Behaviour-preserving: the `live_create_rejects_invalid_target` and
  `scan_create_*` end-to-end API tests pass unchanged. Suite +1 at 1334.

- **De-duplicated scan construction shared by `scan_create` and `scan_batch`.**
  Both the single-scan `POST /scans` and the batch `POST /scans/batch` handlers
  carried an identical eight-line sequence — target construction, `validate()`
  (with the same `invalid target: …` error string), deterministic `scan_id`
  derivation, `profile`→options resolution, and `Scan::new().with_options()` —
  differing only in how each reports a bad item (HTTP 400 vs a per-item JSON
  error). Lifted that into a pure `build_scan_from_request(req) -> Result<(Scan,
  Target), String>` that both call, so the validation/id/profile rules can no
  longer drift between the two entry points. Added unit tests for the valid
  (deterministic id) and invalid (error-prefix) paths. Behaviour-preserving: the
  existing `scan_create_*` end-to-end API tests pass unchanged. Suite +2 at 1333.

- **Extracted the dashboard's scan-stats aggregation into a pure, unit-tested
  function.** The `/stats` handler (which feeds the SPA dashboard's Total Scans /
  Entities / status-breakdown cards) interleaved its summation loop — per-status
  histogram + entity/dedup totals — with store I/O and JSON assembly, so the
  arithmetic was only reachable through the full async handler + a live store.
  Pulled it into a pure `aggregate_scan_stats(&[Scan]) -> ScanStatsAgg` (the
  handler now destructures the result), and added a unit test covering the
  multi-status histogram, the running totals, and the empty-input case. Not a
  line-count play (handler 60→56) — a separation-of-concerns / testability one,
  matching the codebase's pure-function pattern. Behaviour-preserving: the
  existing `/stats` end-to-end API tests pass unchanged. Suite +1 at 1331.

- **Refactored `Store::open` (102→27-line body) behind a schema characterisation
  test.** The SQLite bootstrap — the most Termux-essential function, run on every
  launch — was a 102-line body dominated by an inline DDL string, with the two
  env-tunable pragma reads duplicating the same `env::var().and_then().unwrap_or()`
  dance. Lifted the static schema into a `SCHEMA_DDL` constant and the idempotent
  observation backfill into `BACKFILL_OBSERVATIONS_SQL`, and extracted an
  `env_i64` helper for the pragma reads; `open` is now a short orchestrator and
  the schema lives in one greppable place. Behaviour-preserving: pragmas + schema
  still execute in a single batch, and a new characterisation test
  (`open_produces_exact_schema_and_pragmas`) pins the exact `sqlite_master` table/
  index set plus `foreign_keys=ON` / `journal_mode=WAL` — verified passing before
  the refactor, still passing after. Suite +1 at 1330.

- **Refactored `entities_to_gexf` (109→30-line body) behind a byte-exact golden
  test.** The GEXF graph export (the SpiderFoot-style "Export GEXF" the Graph tab
  now offers) was one monolithic function that also inlined the uid-truncation
  three times instead of calling the existing `short_uid` helper. Split it into
  focused, single-purpose writers — `write_preamble`, `write_node`,
  `write_relation_edge`, `write_shared_evidence_edges` — and routed every node/
  edge id through `short_uid`, removing the duplication. Behaviour-preserving:
  added a characterisation test (`gexf_golden_output_is_byte_stable`) that pins
  the *exact* document for a deterministic input (uids are `SHA-256(kind:value)`)
  before the refactor; it still passes byte-for-byte after. Suite +1 at 1329.

- **Scan Results page: SpiderFoot-style bar chart in the summary + phone-density
  fix.** Two refinements to the page operators spend the most time on. (1) The
  Status tab's "Entities by type" panel — previously a table with a bare
  percentage column — now draws a proportional horizontal bar per type (scaled to
  the largest type, brand-cyan fill, percentage overlaid), matching SpiderFoot
  4.0's summary visualisation so the data-element distribution is scannable at a
  glance; dark-theme aware. (2) The four scan-summary cards (Entities /
  Correlations / Started / Duration) were `col-sm-3` with no `col-xs` class, so on
  a phone they stacked 4×1 — added `col-xs-6` for a compact 2×2 grid (same fix as
  the dashboard cards). SPA-only; suite unchanged at 1328.

- **Dashboard KPI cards sit 2×2 on a phone instead of one tall column.** The four
  stat cards (Total Scans / Entities / Modules / Live Sessions) were `col-md-3
  col-sm-6` with no `col-xs` class, so below Bootstrap 3's 768px breakpoint each
  went full-width — four large cards stacked vertically, pushing the rest of the
  dashboard far down on a Chrome-on-Android screen. Added `col-xs-6` so they form
  a compact 2×2 grid on phones (still 4-up on desktop, 2-up on tablet). The three
  taller content panels below keep full-width stacking, which suits their height.
  SPA-only; suite unchanged at 1328.

- **Global entity search hardened against Android-Chrome keyboard corruption.**
  The seed-target input already disabled autocomplete/autocorrect/autocapitalize
  + spellcheck (case/spelling-sensitive OSINT values must pass through verbatim),
  but the navbar global search — which queries the same entity values against the
  backend `/search` endpoint — did not, so on a phone the soft keyboard could
  autocorrect `jdoe`→`Joe` or inject capitals/spaces before the query was sent.
  Applied the same four attributes to `#global-q` for consistency. (SQLite `LIKE`
  is ASCII-case-insensitive so capitalisation alone was absorbed, but autocorrect
  substitution genuinely corrupted queries.) SPA-only; suite unchanged at 1328.

- **Import bogus-IP/domain filtering now runs in a single pass (PR #87 review).**
  The stealer-log import dropped bogus IP-kind entities and IP-literals
  mis-classified as domains in two consecutive `retain` calls; since the
  predicates apply to disjoint entity kinds, they're merged into one traversal
  (behaviour-identical) to avoid a second full pass + element shift on large
  imports. Both rationale comments are preserved.

- **Exposed the GEXF graph export in the browser UI (was backend-only).** The
  `GET /scans/{id}/graph.gexf` endpoint — Gephi-compatible graph export with a
  proper `Content-Disposition: attachment` filename — was fully wired in the
  backend but had **zero** reference anywhere in the SPA: no button, no URL
  helper, so a Chrome user could never reach it (SpiderFoot 4.0 offers exactly
  this graph export). Added an `API.gexfUrl(id)` helper and an "Export GEXF"
  download button in the Graph tab controls, beside Re-layout / Reset view —
  SpiderFoot's contextual location for graph export. Verified the download
  serves `application/xml` with `attachment; filename="hse-gexf-<id>.gexf"`, so
  Chrome-on-Android saves it with a sensible name. SPA-only; suite unchanged at
  1327 passed.

- **Favicon + address-bar theming for Chrome-on-Android; `/favicon.ico` no longer
  returns the SPA HTML.** Chrome (especially on Android) requests `/favicon.ico`
  unconditionally; with no handler it fell through to the SPA fallback and
  returned the entire HTML document as an "image" (≈70 KB, `text/html`, blank tab
  icon, console error). Added (1) an inline SVG `<link rel="icon">` in the SPA
  head — a hunting-crosshair in the brand cyan (`#07aef1`) on the navbar dark
  (`#222`) — so modern Chrome uses it directly and skips the `/favicon.ico`
  request entirely; (2) a `<meta name="theme-color" content="#222222">` so the
  Android Chrome address bar matches the dark navbar; and (3) a dedicated
  `GET /favicon.ico` route serving the same 319-byte SVG with
  `Content-Type: image/svg+xml` for any client that still asks. New test
  `favicon_returns_svg_not_html` asserts it's SVG, not the SPA document. Fully
  offline (no extra binary asset). Suite +1 at 1327 passed.

- **Wide data tables now scroll horizontally on Chrome-on-Android.** The Browse
  element table (8 columns: Type/Value/C_eff/Corr/Tier/Tags/Sources/Observed) and
  the Scans table (7 columns) previously overflowed a phone viewport, forcing a
  body-level horizontal scroll that dragged the fixed navbar and crushed columns.
  Both are now wrapped in Bootstrap 3's `.table-responsive` (the same pattern
  SpiderFoot 4.0 uses), so on narrow screens the table itself scrolls within its
  panel while the page chrome stays put. Narrow 2–3 column summary tables (Status
  rollups, Info key/value) are left unwrapped as they already fit. SPA-only;
  suite unchanged at 1326 passed.

- **D3 force graph is now pan/zoomable — usable on Chrome-on-Android.** The graph
  previously supported only node-drag, so on a phone screen a multi-node layout
  could not be panned or zoomed (it overflowed the SVG with no way to reach
  off-screen nodes). `buildD3Graph` now nests all links/nodes in a `zoom-container`
  `<g>` driven by `d3.behavior.zoom` (`scaleExtent [0.2, 5]`), which is touch-aware
  in d3 v3: pinch-to-zoom and one-finger pan work natively in Chrome on Android,
  mouse-wheel + drag-canvas on desktop — matching SpiderFoot 4.0's zoomable graph.
  A node `mousedown` `stopPropagation` keeps node-drag from also panning the
  canvas; double-click-zoom is disabled to avoid fighting the layout. Added a
  "Reset view" button (recentres/rescales via a 250 ms transition) and a corner
  hint ("Drag nodes · pinch or scroll to zoom · drag canvas to pan"), both
  dark-theme aware. SPA-only; suite unchanged at 1326 passed.

- **Browse tab gains a SpiderFoot 4.0-style data-element rollup table.** Above
  the entity element list, `renderBrowse` now renders a `Data Element | Unique |
  Total` summary table (`#browse-rollup`) computed from `S.entities`: Unique is
  the per-kind entity count, Total is the per-kind sum of `corroboration`,
  mirroring SpiderFoot's Browse rollup (unique values vs total data elements).
  Rows are sorted by Unique descending and are clickable — clicking a type drives
  the existing `#b-kind` dropdown + `refresh()` to drill the element list down to
  that type (clicking the active type toggles back to All), reusing the filter
  infrastructure rather than adding a parallel path. SPA-only change (re-embedded
  via `include_str!`); no Rust logic touched, suite unchanged at 1326 passed.

- **search_engines FullName dork set extracted to a pure `build_queries_fullname`.**
  `build_queries` was a 331-line per-`TargetKind` match whose FullName arm alone
  was ~100 lines of person-centric Google dorks (social/professional, AU
  people-search & court/registry surfaces, news, diaspora platforms,
  email-discovery). Lifted that arm verbatim into a pure
  `build_queries_fullname(&str) -> Vec<String>` that the dispatch arm delegates
  to, dropping `build_queries` from 331 to 213 lines. This is the API-free
  recursive-discovery layer, so it's now unit-testable in isolation: a new test
  asserts the helper output equals the dispatch output exactly (verbatim
  extraction) plus single-token vs multi-part behaviour. Behaviour-identical;
  the existing FullName query tests stay green.

- **whois response parsing extracted to a pure `parse_whois`.** The ~55-line
  block in `Whois::process` that parsed a raw WHOIS body into 17 typed fields
  (registrar/dates/registrant/nameservers/statuses/dnssec) is now a pure
  `parse_whois(&str) -> WhoisFields` that `process` destructures, taking the
  method from 304 to 268 lines and making the parser unit-testable against
  canned WHOIS text (no TCP/43). Two new tests cover the field extraction and
  the `@`-required email-placeholder filtering. Behaviour-identical (same field
  keys, same precedence, same `@` filter).

- **oathnet_pro stealer-entity tagging centralised; extraction characterised.**
  `extract_stealer_entities` repeated the stealer-context tail
  (`tag("oathnet-pro") + tag("stealer") + [extra] + add_evidence + push`) across
  its login-email/domain/credential blocks. Added a `push_stealer_entity` helper
  for that base (deliberately distinct from `push_oathnet_entity` — the stealer
  context does NOT carry the `breach` tag, except the email-array kind which
  reuses `push_oathnet_entity` for its `[breach, oathnet-pro, stealer]`). A
  characterization test pins the two distinct tag bases in exact order, written
  green before the change. Behaviour-identical; the function had no coverage.

- **oathnet_pro breach-entity tagging centralised; extraction characterised.**
  Applied the same cleanup as `see_know` to `oathnet_pro::extract_breach_entities`:
  its thirteen per-field blocks each repeated `tag(breach) + tag("oathnet-pro")
  + [record-specific tag] + add_evidence(ev.clone()) + push`. Lifted that into a
  `push_oathnet_entity(result, e, ev, extra_tags)` helper, with `extra_tags`
  preserving the exact serialised tag order (`candidate`, `geolocation-lead`,
  `discord`, `linkedin`, `email-domain`, `password-hash`, …). Added two
  characterization tests that pin the **exact ordered tag vectors** for every
  kind (and the non-target `candidate` path) — written green against the
  pre-refactor code, so any reordered/dropped tag fails. Behaviour-identical;
  the function had no test coverage before.

- **see_know coordinate parsing extracted to `parse_coord`.** The lat/lon
  extraction in `extract_geo_entities` was two 10-line `or_else` ladders that
  each tried a JSON number then a numeric string across the candidate keys
  (`latitude`/`lat`, `longitude`/`lon`/`lng`). Replaced with a single
  `parse_coord(item, keys)` helper preserving the exact "first present key, read
  as f64 else parse its string" semantics, taking `extract_geo_entities` from
  128 to 111 lines. Added `extract_geo_entities_characterization` (f64 + string
  coords, out-of-range rejection, location/timezone/ASN/org endpoint-gating,
  WHOIS registrant) written green before the change. Behaviour-identical.

- **see_know breach-entity tagging centralised; extraction characterised.** The
  nine per-field blocks in `extract_entities` each repeated the same tail —
  `tag(breach) + tag("see-know") + add_evidence(ev.clone()) + push`. Lifted that
  policy into a single `push_breach_entity(result, e, ev, extra_tags)` helper so
  the breach-tagging rule has one source of truth (Domain stays the documented
  exception — infrastructure, not a leaked credential, so no `breach` tag). Added
  an `extract_entities_characterization` test that pins the full output (kinds,
  values, per-kind tag policy) and was written/green *before* the refactor.
  Behaviour-identical; live "Jordan Meyer" still returns the same 185 entities.

- **see_know pre-flight skip logic extracted to a testable predicate.** The
  ~38-line per-target-kind junk-seed skip block inside `SeekNow::process` (local
  domains, too-short/all-digit/placeholder usernames, under-length phones/names,
  private IPs, unsupported kinds) is now a pure `should_skip_seed(kind, value)`
  function with its own unit test, shrinking `process()` from 147 to 112 lines.
  Behaviour-identical (same conditions, same early-return); live "Jordan Meyer"
  still returns 185 entities.

- **see_know endpoint dispatch is now table-driven.** Each of the 19 typed
  SeekNow endpoints used to be encoded in four places — an `EndpointCall`
  variant, a 19-arm `label()` match, a 19-arm `invoke()` match, and a
  near-identical `util::see_know` wrapper that did nothing but
  `get_path(path, &[(param, value)])`. Collapsed the per-endpoint truth into a
  single `EndpointCall::spec() -> (label, path, param)` table that drives both
  `label()` and `invoke()` (the latter calling the now-`pub(crate)` `get_path`
  directly), and removed the 16 single-use wrappers. The two Discord bridges
  keep named wrappers because pivot discovery calls them outside the planner.
  Behaviour-preserving: identical labels/paths/params, 37 see_know tests green,
  and live `see_know` on the "Jordan Meyer" name seed still returns the same 185
  entities (1 person, 96 emails, 81 phones, 6 addresses). Net −81 lines.

### Fixed

- **see_know name/auto search no longer times out on every query.** The
  see-know.eu name/auto `/search` path has a ~55s server-side cap and returns
  real data in 50–60s, but the `seek_now` curl client was budgeted at 12s curl
  / 15s outer and the module's `max_timeout_ms` at 45s — so every name search
  hit a curl timeout-exit (28) and surfaced as an opaque `[seek_now] curl
  failed` with zero entities. Raised the budget above the cap: 75s curl, 78s
  outer (curl < outer so curl's own exit code is observed), and an 80s module
  timeout. Live `hse scan --kind name --value "Jordan Meyer"` now returns 185
  entities (1 person, 96 emails, 81 phones, 6 addresses) where it previously
  returned 0. Fast endpoints are unaffected — `--max-time` is a ceiling, not a
  wait. Two regression tests pin the ordering (curl > server cap; outer > curl;
  module ≥ outer) so the budget can't silently regress.

### Performance

- **Batched entity persistence.** `ScanEngine::finalise_scan` now writes a
  scan's entities through `Store::upsert_entities_batch` in a single WAL
  transaction instead of one transaction per entity, collapsing N fsyncs into
  one — a material win on low-power aarch64. On a batch error it falls back to
  per-entity upserts, preserving the prior continue-on-error resilience
  semantics (partial persist → `Complete` with an error note; nothing
  persisted → `Failed`). `StoragePort::upsert_entities_batch` now takes
  `&[Entity]` so the caller retains ownership for the fallback.

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
