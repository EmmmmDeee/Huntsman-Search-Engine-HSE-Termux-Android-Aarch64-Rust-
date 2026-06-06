# Changelog

All notable changes to this project are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
project versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is `0.x`, the public API may change at any point — minor
versions can include breaking changes; patch versions are bug-fix-only.

## [Unreleased]

### Added

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
  `candidate` tag**, so a "Matthew Diegmann" scan surfaced 90+ unrelated
  bank-employee emails and 78 unrelated bank/credit-union domains as if they
  were the target's. The relevance gate is now centralised and applied to
  **every** breach-derived kind, and `full_name` (and other multi-term) targets
  must match **all** name terms in a single field — so `"Matthew Parker"` no
  longer counts as `"Matthew Diegmann"` on the shared first name. Non-matching
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
  `"Matthew Diegmann"` (literal quotes) reached the pipeline with the quotes
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
