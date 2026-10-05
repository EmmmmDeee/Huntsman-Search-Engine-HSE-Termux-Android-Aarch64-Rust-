# Architecture

Target design for the first-principles reconstruction of Huntsman as the single package `huntsman-recon`. Every statement about the code is labelled. **CURRENT** means it is true of the repository tree containing this document and can be checked in `src/`, `tests/` or CI. **PLANNED** means it is a target that no code on `main` implements yet. The CAPABILITIES status column is CURRENT, MIGRATION POLICY is a rule set for every reconstruction PR, and ORDERED BACKLOG is PLANNED. `tests/architecture_doc.rs` checks the module map against the module tree `src/lib.rs` compiles (layer placement, the "Not compiled" row, upward edges and cycles), the section order, and the CAPABILITIES rows (pinned numbers and names, statuses, acceptance criteria and counts).

The capability oracle is git commit `7dca720` (root crate `huntsman-search-engine` v1.41.0, binary `hse`, published as pre-release `main-7dca720`, the newest `hse` build and the default of `.github/scripts/install-termux.sh`). `legacy/hse-monolith-v1.41.0/` is a different, earlier snapshot of the same monolith (its `src/` differs from `7dca720` in 677 paths: 56 present in only one tree, 621 with different bytes). It is used for per-file accounting in `docs/DISPOSITIONS.md`, and as the oracle only where `7dca720` lacks a path (`src/modules/au_people/` and `src/modules/au_electoral/`, both deleted in #635). Nothing under `legacy/` is ever modified.

## OBJECTIVE

CURRENT: `huntsman-recon` is an offline-tested core with a guarded fetch layer and a skip-tested `people` CLI over keyless ASIC registers. It is **not** a people-centric OSINT tool yet. Email, username and phone lookups do not work:
- `email`, `username`, `phone`, `resolve` and `scan` exit 64 (`unknown command`), as do `investigate` and `serve`.
- `search` without `DIR` searches a built-in 2-document fixture.
- The provider and parser clients (`hibp`, `atproto`, `mediawiki`, `dns`, `service_defs` and others) have no caller outside their own tests. `ckan` is called by `asic_persons`; `people_cli` is the `people NAME` front-end (skip path tested; live CKAN not run in CI) and feeds evidence through `lineage::resolve_with_lineage`.
- Identity resolution runs only on literal fixtures inside `check`.
- Commit `f0a1c64c` removed all legacy providers (195 provider directories and 10 top-level files under `src/modules/` at `7dca720`) and the `scan`, `investigate` and `serve` commands.

PLANNED: a Termux-native CLI where a person selector goes in, keyless and operator-keyed sources are collected through one guarded network path, responses become evidence whose lineage comes from the response data, identities are resolved by a non-compensatory merge rule, and the result is saved, verifiable with `verify`, and printed with stable exit codes. Every capability of `hse` at `7dca720` is restored with a differential test against it; none is removed or dropped silently.

## CAPABILITIES

Every row's acceptance criteria include **D** and **N**:
- **D**: a differential test against legacy `hse` 7dca720 output on the same recorded inputs (see VERIFICATION).
- **N**: no dropped, truncated or misattributed results relative to that output.
- **L**: one live run against the real source, with a receipt (command, UTC time, response hash, exit code) tied to the commit SHA.
- **S**: Security & Secrets Bot review, required for every boundary and secrets change.

CURRENT: no row meets **D** yet. The one differential test on `main`, `tests/lineage_legacy.rs` (#679), covers part of row 9: legacy `core::breach_consensus` grouping and thresholds on nine recorded fixtures. There is no general differential harness. "REGRESSION" marks a capability that `hse` at `7dca720` exposed and `main` does not.

Status counts: REIMPLEMENTED 2, PARTIAL 12, NOT YET REBUILT 9 (21 of 23 rows are regressions).

| # | Capability | Legacy source (`7dca720` unless noted) | Status on main | Owner | Acceptance criteria |
| --- | --- | --- | --- | --- | --- |
| 1 | Person lookup by email | `hse scan -k email`; `src/cli/scan/`, `src/modules/{email_parse,email_canonical,emailrep,gravatar}` | NOT YET REBUILT. REGRESSION: `email` exits 64 | Software Development Bot | D, N, L. `email ADDR` runs the full pipeline (BACKLOG 1) |
| 2 | Person lookup by username | `scan -k username`; `src/modules/{username_search,username_variants,github_user,bluesky_user}` | NOT YET REBUILT. REGRESSION: `username` exits 64; `atproto` helpers have no caller | Software Development Bot | D, N, L. Variant expansion matches legacy |
| 3 | Person lookup by phone | `scan -k phone`; `src/modules/{phone_au,phone_intl,phone_geo}` | NOT YET REBUILT. REGRESSION: `phone` exits 64 | Software Development Bot | D, N, L. E.164 canonicalisation matches legacy |
| 4 | AU people registers by name | `src/modules/{asic_persons,asic_director}`; `au_people`, `au_electoral` from `legacy/` | PARTIAL. REGRESSION: `people NAME` exists (`people_cli` over `asic_persons`, lineage on emitted evidence); skip path tested; two-token names query CKAN but have no live receipt and are not run in CI; no save/`verify` yet; `asic_director`, `au_people` and `au_electoral` are not rebuilt | REFACTOR Bot (port), Software Development Bot (source) | D, N, L. `asic_persons` is keyless (data.gov.au CKAN) |
| 5 | HIBP breach lookup | `src/modules/hibp/` | PARTIAL. REGRESSION: `src/hibp/` is a library tested only on a fake transport; no CLI arm; never run live | Software Development Bot | D, N, L (operator key), S. No key in output, logs or artifacts |
| 6 | stolen.tax breach search | `src/modules/stolen_tax/` (keyed) | NOT YET REBUILT. REGRESSION | REFACTOR Bot | D, N, L (operator key), S |
| 7 | Domain recon (crt.sh, DNS, SPF, DMARC) | `src/modules/crtsh/` and the DNS/mail modules | PARTIAL. REGRESSION: `dns`, `spf`, `dmarc`, `tlsrpt`, `recon` have no caller; crt.sh not rebuilt | REFACTOR Bot | D, N, L. crt.sh is keyless |
| 8 | Unified, recursive and batch scan | `hse scan` (auto kind, `--depth`, `--input-file`), `hse batch` | NOT YET REBUILT. REGRESSION: `scan` exits 64 | REFACTOR Bot | D, N. Same seeds give the same entity set as legacy at each depth |
| 9 | Identity resolution on collected evidence | `src/core/{resolve,coref,correlator}/`, `hse-core` | PARTIAL. REGRESSION: library only, fixtures in `check`; `lineage` derives families from response fields and holds a candidate with no probability (#679, `docs/LINEAGE.md`), but no collector feeds it | REFACTOR Bot | D, N. One dataset via two collectors gives one root family and no auto-merge |
| 10 | Response cache and source pacing | `src/util/{response_cache,circuit_breaker,backoff.rs}` | PARTIAL. REGRESSION: `circuit` is not reachable from the binary; its only non-test caller is `recon::host_key` (`src/recon.rs:32`), and `recon` has no caller | Software Development Bot | D, N. A cache hit returns the identical evidence and lineage |
| 11 | Saved results, export, diff | `src/storage/`, `hse export`, `hse diff` | PARTIAL. REGRESSION: `ledger` and `verify` work for `check` claims only; `store`, `gexf`, `diff` have no CLI | Software Development Bot | D, N. Save, reload and `verify` round-trip byte-identically |
| 12 | Offline utilities: `geo`, `geohash`, `coarsen`, `id` | `src/util/{geo,geohash,abn,bsb}/`, `src/util/redact.rs` | REIMPLEMENTED | Software Development Bot | D, N. Legacy vectors replayed through the CLI |
| 13 | Guarded fetch and outcome classification: `fetch`, `classify` | no `hse` subcommand; module-internal HTTP and WAF detection | REIMPLEMENTED | Software Development Bot | D, N, S. The same outcome per recorded response |
| 14 | Key management | `hse keys {set,add,list,export,import-json,revoke,rotate,validate,remove,status,bank,services,import-tsv,health,prune}` (`src/cli/keys_cmd/mod.rs`), `set-key`, `provision` | PARTIAL. REGRESSION: `keys FILE` lists slots and fingerprint prefixes only, with none of the legacy subcommands; `fetch` auto-loads `~/.huntsman.env` (`Keys::resolve`, #674) | Software Development Bot | D, N, S. No value ever printed |
| 15 | Web meta-search | `hse query`, `dorkus`, `query-pack`, `engines` | NOT YET REBUILT. REGRESSION: `search` is local-only | Software Development Bot | D, N, L |
| 16 | Entity extraction from text | `hse investigate`, `ingest`, `import` | PARTIAL. REGRESSION: the binary calls `classifier::classify` only from `sources`, on one selector (#671); `classifier::extract` and `classify_module` have no CLI | REFACTOR Bot | D, N. No text leaves the device |
| 17 | Web UI and HTTP API | `hse serve`; `src/{web,api}/` | NOT YET REBUILT. REGRESSION | REFACTOR Bot | D, N, S. Loopback bind by default |
| 18 | Radio and device sensing | `hse radar`, `live`, `cells`, `signal`; `src/modules/{termux_sensor,device_cell}.rs` | PARTIAL. REGRESSION: `radar`, `rf`, `oui` have no CLI and no sensor input; the binary uses only `geoint::parse_latlon` (`geo`, `geohash`) and `geoint::haversine_m` (`geo`, `check` gate 2) (`src/main.rs:23`) | REFACTOR Bot | D, N |
| 19 | ATT&CK and assurance reports | `hse attack`, `assurance`, `bsi`, `report`, `audit`, `benchmark`, `gaps` | PARTIAL. REGRESSION: Navigator/STIX only from `check`; `assurance`, `benchmark`, `gap` are compiled (#675) but have no CLI | REFACTOR Bot | D, N |
| 20 | Diagnostics and self-test | `hse diagnostics`, `doctor`, `selftest`, `build-sha` | PARTIAL. REGRESSION: `check` runs gates 2–11 on fixtures; no install or provider diagnostics | Fix This Bullshit Bot | D, N |
| 21 | Module catalogue and config | `hse modules`, `config` | NOT YET REBUILT. REGRESSION: `module`, `service_defs` have no CLI | REFACTOR Bot | D, N. Every listed module is reachable |
| 22 | Self-update and release | `hse update`; `release.yml` (deleted in `f0a1c64c`) | PARTIAL. REGRESSION: `.github/workflows/release.yml` (#672) publishes a `main-<sha7>` pre-release of `huntsman-recon` on every `main` push; it has no tag trigger, no stable release and no SBOM, and moves `latest` only when `PROMOTE_RECON_TO_LATEST` is `true`; no `update` command | Fix This Bullshit Bot | D, N. Asset is `huntsman-recon` built from the tagged SHA |
| 23 | Remaining subcommands | `hse sf`, `oathnet-batch`, `tidy` | NOT YET REBUILT. REGRESSION | REFACTOR Bot | D, N |

## ARCHITECTURE

CURRENT. One package, one library (`src/lib.rs`) and one binary (`src/main.rs`, no CLI framework). The table is the module map: every module `src/lib.rs` declares appears in exactly one layer row. A module may use modules in its own layer or a lower one, never a higher one. Dependencies are the `crate::` paths (`use`, `pub use`, groups and inline paths, plus `super::` paths that reach the crate root) in compiled code outside `#[cfg(test)]`; `tests/architecture_doc.rs` recomputes them and fails if either line below is wrong:
- Upward edges: none.
- Dependency cycles: `address_au`–`canonical`–`domains`–`textnorm`–`validation` (L3); `attack`–`attack_catalog` (L5).

| Layer | Modules | Role |
| --- | --- | --- |
| L0 primitives | `error`, `sha256`, `json`, `timefmt`, `union_find`, `tags`, `xml`, `uid`, `stage`, `event`, `fsio`, `signals`, `place`, `geohash`, `redact`, `termination`, `circuit`, `oui_ieee`, `oui`, `radar` | Pure helpers, bounded file I/O (`fsio`), retry and cache state (`circuit`) |
| L1 evidence core | `evidence_ancestry`, `confidence`, `identity_resolution`, `resolve`, `eval` | Ancestry graph, independent-family counting, merge gate, scoring |
| L2 network boundary | `classify`, `source_outcome`, `egress`, `credential_origin`, `http`, `keys`, `fetch`, `fetch_cli` | The only network path (see BOUNDARIES) |
| L3 normalisation | `textnorm`, `canonical`, `validation`, `domains`, `address_au`, `postcode_au`, `au_id`, `breach`, `archive`, `spf`, `dmarc`, `tlsrpt` | Canonical forms, validators and record parsers; `archive` models archive-URL identity and deterministic capture aggregation over `canonical`; `postcode_au` also has one postcode lookup over an injected `http::Transport` (its only crate dependency is `http`), and `au_id` re-exports it (`src/au_id.rs:13`) |
| L4 source clients | `ckan`, `mediawiki`, `atproto`, `dns`, `hibp`, `service_defs`, `key_health`, `scraper_health`, `recon` | Request builders and response parsers. Only `dns`, `hibp` and `service_defs` send, each over a transport passed in, except `hibp::HibpClient::production`, which builds its own `UreqTransport` (see BOUNDARIES) |
| L5 entity model and analysis | `entity`, `identity`, `relation`, `graph`, `coref`, `correlator`, `cross_scan`, `dependency`, `module`, `attack`, `attack_catalog`, `exposure`, `profiles`, `leads`, `timeline`, `community`, `diff`, `path`, `pivot`, `intelligence`, `classifier`, `classify_module`, `lineage`, `assurance`, `benchmark`, `coverage`, `diamond`, `gap`, `metrics`, `roi`, `trust`, `source_registry`, `pipeline`, `planner`, `asic_persons`, `people_cli` | Entities, evidence, relations, correlation rules; lineage from response data and the merge-rule front-end (`lineage`); assurance, coverage and gap reports; offline `LeadOnly` search routes per entity kind (`source_registry`); keyless ASIC people-register collector (`asic_persons`); `people` collection front-end (`people_cli`) |
| L6 GEOINT and RF | `geo`, `geometry`, `rf`, `geoint` | Coordinates, places, RF sightings |
| L7 records and outputs | `ledger`, `session`, `store`, `stix`, `navigator`, `search`, `gexf`, `snake_graph` | Hash-chained ledger, session store, exports, local search |
| Binary | `main` | Dispatch for the 12 commands; calls L0, L1, L2, L3, L5, L6 and L7 directly, never L4 |

PLANNED: a collector layer between L4 and L5 that turns a selector into source requests and a source response into `entity::Evidence` plus an `evidence_ancestry` node. It is the missing causal boundary named in the audit. The binary reaches L4 only through it.

## BOUNDARIES

CURRENT:
- The only socket-opening code is `http::UreqTransport` (blocking `ureq` 3, rustls). No other module imports `ureq` or opens a `TcpStream`/`UdpSocket`; other uses of `std::net` are address types only.
- `UreqTransport` resolves through `GuardedResolver`, which drops every address `egress::EgressPolicy` refuses. The default is `PublicOnly`, applied to the resolved addresses that are connected to, which defeats DNS rebinding. A refusal maps to exit 77.
- The transport never follows redirects (`max_redirects(0)`). `fetch::fetch` follows them; it attaches its `credential` argument only on the origin of the first URL (`src/fetch.rs:141-145`), and on a cross-origin hop it drops every header that `http::is_sensitive_header` names (`src/fetch.rs:272-275`).
- A `fetch::Credential` is built only from a `credential_origin::AuthenticationAuthority` (`src/fetch.rs:48`), and nothing converts a `DiscoveredCredential` into one, so a secret found in collected data cannot become a `fetch` credential. Two library paths put a secret into a request themselves and call `fetch` with `credential: None`; neither has a non-test caller:
  - `hibp`: `src/hibp/client.rs:436` sets the `hibp-api-key` header from `ApiKey::expose()`, and `hibp::oauth::exchange_code` and `refresh` put the authorization code or refresh token in a form body (`src/hibp/oauth.rs:382-445`). Origin protection is `hibp::trusted_url` (`src/hibp/mod.rs:38`: `https`, port 443, no userinfo or fragment, host `haveibeenpwned.com` or `api.pwnedpasswords.com`) plus an exact `https://haveibeenpwned.com:443` origin check (`src/hibp/client.rs:419`, `src/hibp/oauth.rs:458-464`). `hibp::send` disables redirects (`max_redirects: 0`, `src/hibp/mod.rs:19-27`).
  - `service_defs::probe_service` (`src/service_defs.rs:465`) places its `key: &str` argument as the service's `KeyPlacement` says (`build_probe_request`, `:349`) and sends it to the service's fixed `test_url` with the default 5 redirects; a key in a header is dropped on a cross-origin hop, because every header placement name in the registry contains `key` or is `Authorization`.
- Bodies are read under a byte cap and flagged `truncated`. Sensitive headers never appear in `Debug` output, and diagnostics pass through `redact::scrub_secrets`.
- `keys` refuses a keys file that group or others can access (`mode & 0o077 != 0`; 600 or stricter passes) and prints slot names and fingerprint prefixes, never values.
- Without `--keys`, a `fetch` that requests a credential reads `$HOME/.huntsman.env` through `Keys::resolve` (`src/keys.rs:245`, called at `src/main.rs:223`), only for an absolute `HOME`. The file is not read, with one stderr warning, if `lstat` shows a symlink, a non-regular file, an owner other than the effective uid (or the uid cannot be read), or `mode & 0o077 != 0`. It is read through the opened descriptor, which must have the device/inode `lstat` saw and pass the same checks. A file that passes but is malformed, not UTF-8, over 64 KiB or fails with an I/O error other than not found makes the `fetch` exit 66 (`tests/env_autoload.rs`).
- Library code that sends takes its transport as an argument: `fetch::fetch` (`T: Transport + ?Sized`), `dns::resolve_with_pool` and `resolve_with_config`, `postcode_au::localities_with` (`T: Transport`), `service_defs::probe_service` (`T: Transport + ?Sized`), `asic_persons::lookup` (`T: Transport + ?Sized`), `people_cli::run` (`T: Transport + ?Sized`), the `hibp::oauth` functions (`&dyn Transport`) and `hibp::HibpClient::new` and `with_config` (`Arc<dyn Transport + Send + Sync>`). The one exception is `HibpClient::production` (`src/hibp/client.rs:154-161`), which builds its own `UreqTransport` with the default egress policy. Tests inject fakes; the `fetch` and `people` commands build `UreqTransport` in `src/main.rs`.

PLANNED: every new source goes through `fetch` and the guarded transport; no module adds a second HTTP client. Gap to close: `hibp` and `service_defs::probe_service` send keys through a `fetch::Credential` built from an `AuthenticationAuthority` instead of setting them themselves, and `HibpClient::production` takes its transport from the caller. Every change to `egress`, `http`, `fetch`, `keys`, `credential_origin`, `hibp` key handling or `build.rs` requires Security & Secrets Bot review.

## CONTRACTS

CURRENT:
- `http::Transport::send(&Request) -> Result<Response, TransportFailure>`. A non-2xx status is a `Response`, not an error.
- `fetch` returns a typed `source_outcome::SourceOutcomeKind` and never "found": a 200 is `Inconclusive` until a parser produces rows, and a challenge page is `BotWaf` at any status.
- `source_outcome::recommended_action` maps an outcome to `Accept`, `Retry`, `Backoff`, `RequireCredential`, `Quarantine`, `RequireContractVerification` or `Investigate`.
- `identity_resolution::IdentityResolutionDecision::allows_automatic_merge` is `hold_reasons(..).is_empty()` and non-compensatory: one contradiction, a temporal or geographic conflict, unknown ancestry, or a missing, non-finite, out-of-range or below-floor probability blocks the merge regardless of support. Each failed condition is returned as a `HoldReason`, in a fixed order (`docs/LINEAGE.md`).
- `lineage::resolve_with_lineage` returns every observation and every candidate in input order, each candidate `AutoMerge` or `Held { reasons }`; it drops nothing.
- `ledger`: each entry's hash covers the previous hash plus the claim. `verify` prints `entries`, `admitted` and `tip`, and exits 65 on a broken chain.
- CLI exit codes: 0 success, 64 usage, 65 bad data or broken ledger, 66 unreadable input, 69 no response, 74 artifact write failure, 77 egress refusal; `check` uses 2–11 for its gates. `tests/readme.rs` enforces these.

PLANNED:
- Collector contract: `collect(selector, &dyn Transport) -> (SourceOutcomeKind, Vec<Evidence>)`. Zero rows with a `Success` outcome is `ValidZero`, not a failure.
- Each people-lookup command documents and tests the same exit-code set.

## INVARIANTS

CURRENT:
- `#![deny(unsafe_code)]`; clippy `pedantic` is warn and CI denies warnings.
- A challenge page is never a result. A self-labelled ATT&CK technique never enters Navigator or STIX (`check` gates).
- `check` regenerates `var/*.json` byte-identically (CI runs `git diff --exit-code -- var/`).
- Canonical extracted legacy trees are file-count pinned by `tests/legacy_reference.rs`; original root-ZIP SHA-256/Git identities and a recoverable commit are recorded in `docs/ARCHIVE_PROVENANCE.md`, and `tests/repository_hygiene.rs` forbids opaque root snapshots from returning.
- The README examples, usage line, exit codes and gate range match the binary (`tests/readme.rs`); `docs/DISPOSITIONS.md` counts match `legacy/` (`tests/dispositions.rs`); this file's module map, dependency claims and capability rows match `src/` (`tests/architecture_doc.rs`).
- Every `.rs` file under `src/` is compiled (#675); `tests/architecture_doc.rs` fails on a file the module tree does not reach.
- In `lineage`, mirrors of one named dataset count as one family whatever the collectors are called, and record URLs, record ids and collector names never create a family (`tests/lineage_merge_rule.rs`, `tests/lineage_independence_adversarial.rs`).
- Automatic merge requires a present, finite probability in `[0, 1]` at or above the policy floor; `probability: None` holds the candidate (`HoldReason::ProbabilityMissing`).

PLANNED:
- Every collector's output goes through `lineage`, so mirrors of one dataset count as one source end to end.
- Collectors supply a calibrated match probability; `lineage` supplies none.
- No result reaches output without a lineage root.

## DATA

CURRENT:
- `entity::Entity` carries `entity::Evidence`; each `Evidence` has an `EvidenceProvenance` (`source`, `source_family`, `scan_id`, `recorded_at_unix`) and an optional `ancestry_node`.
- `evidence_ancestry::EvidenceAncestryNode` has `id`, `source_family`, `parents` and `derived`. `canonical_family` only normalises case and whitespace. Callers set these fields, except `lineage::resolve_with_lineage`, which builds the graph from `Evidence::attributes`.
- Lineage (#679, `docs/LINEAGE.md`): `lineage::Lineage::of` takes the family from the first non-blank response field among `dbname`, `breach`, `source_db`, `database_name` and `dataset`, or `registry` only from a collector in `VERIFIED_REGISTRY_SOURCES` (currently `abn_lookup`), matched on the family recomputed from an ASCII `provenance.source`, never the stored `source_family` (#684, `src/lineage.rs:142-145`); never from the collector name, `source_url` or `source_id`. Each family is one root `lineage:<family>`, so two collectors relaying one dataset share one root. A response that names no dataset, or several in one field, is kept and contributes zero families.
- Files: `check` writes `var/ledger.json`, `var/navigator.json` and `var/stix-bundle.json`. `store` writes bounded (1 MiB) JSON sessions atomically and refuses symlinks. `hibp::oauth` token files are mode 600.

PLANNED, lineage: collectors fill those fields from the response data: the dataset or breach identifier the response reports (for example the HIBP breach `Name`, a CKAN `resource_id`, a crt.sh log entry), plus any upstream the response itself names. A response that names no dataset gets a root derived from the source origin and the response hash, marked `derived: false`, which cannot by itself justify an automatic merge (today it contributes zero families). Dataset names are not yet canonicalised for Unicode confusables or zero-width characters (`docs/LINEAGE.md`, trust boundary).

## EXECUTION

CURRENT:
- Target: Termux on Android aarch64, no root. CI cross-builds `aarch64-linux-android` (API 24, NDK) with MSRV 1.87, checks the ELF is AArch64 with interpreter `/system/bin/linker64`, and uploads a 14-day artifact on main pushes.
- No async runtime: `ureq` is blocking, and no module depends on `tokio` or `async fn`. Dependencies are `serde`, `serde_json`, `thiserror` and `ureq`.
- Paths are relative to the working directory (`var/`); there is no hard-coded workspace path.
- Not verified: a handset run of the `huntsman-recon` binary. Since #672 every `main` push publishes a `main-<sha7>` pre-release of `huntsman-recon` (`.github/workflows/release.yml`), whose release notes claim no handset run. `.github/scripts/install-termux.sh` installs the legacy `hse` from `main-7dca720` by default and `huntsman-recon` only with `HUNTSMAN_CHANNEL=recon`.

PLANNED: sources run sequentially, or on bounded `std::thread` workers if measured to be necessary, with pacing from `circuit`. No async runtime is added.

## FAILURE MODEL

CURRENT:
- Network failures are typed outcomes (`DnsFailure`, `ConnectFailure`, `TlsFailure`, `TtfbTimeout`, `BodyTimeout`, `RateLimited`, `AuthRequired`, `AuthRejected`, `BotWaf`, `Upstream4xx`, `Upstream5xx`, the drift kinds and others), not panics or empty results.
- Library errors (`error::Error`) have no fail-open path. Ancestry with a missing node or a cycle fails closed: unknown ancestry is not independence.
- `hibp` bounds 429 retries, treats truncated or malformed bodies as errors, and fails closed on missing entitlement flags.
- A failure is never reported as `hits=0`: an unreadable `search` directory exits 66.

PLANNED: a source failure is recorded per source with its outcome and does not abort other sources; the command exits non-zero only if no source produced a usable outcome. A truncated body never yields evidence.

## VERIFICATION

CURRENT gates (CI `ci.yml`, toolchains 1.87 and stable, owned by Fix This Bullshit Bot):
- `cargo fmt --check` and `cargo clippy --all-targets --locked -- -D warnings` (stable).
- `cargo test --locked`: unit tests, `tests/accept.rs`, `cli.rs`, `http_local.rs` (loopback sockets only), `legacy_reference.rs`, `readme.rs`, `dispositions.rs`, `android_ci.rs`, `hibp_build.rs`, `architecture_doc.rs`, `lineage_merge_rule.rs`, `lineage_legacy.rs`, `lineage_independence_adversarial.rs`, `release_ci.rs`, `env_autoload.rs`, `source_registry_cli.rs`, `source_registry_metadata.rs`.
- `cargo run -- check`, then `git diff --exit-code -- var/`.
- The Android aarch64 cross-build.
- `.github/workflows/release.yml`, not `ci.yml` (#672): before any `main-<sha7>` pre-release is published, the build-time HIBP key embed must be empty, the binary must contain the `huntsman-recon` usage line, and `.github/scripts/scan-for-keys.sh` must report zero findings. PRs that touch the release path get the same checks as a dry run.

PLANNED, differential tests against legacy `7dca720`:
1. Record the upstream response for a capability once (bytes plus SHA-256, with credentials scrubbed).
2. Produce the legacy output by running the `7dca720` module (from a `git worktree` of `7dca720`, outside this crate) on the recorded response, and commit it with a manifest naming `7dca720`, the module and the response hash.
3. In `cargo test`, feed the same recorded response to the new code through a fake `Transport`, and compare entity sets keyed by kind and canonical value.
4. Fail on any legacy result that is missing (dropped), shortened (truncated) or attributed to a different source or dataset (misattributed). An intentional difference needs a reviewed allow-list entry with a reason, such as a fixed legacy defect.
5. CI never builds or runs legacy; it checks the committed goldens.

PLANNED, live receipts: one run per source against the real service, recording the command, UTC time, response hash and exit code, tied to the commit SHA. Not run in CI.

## MIGRATION POLICY

Rules for every reconstruction PR from this one on:
- Restoration only. NO removals until there is a differential test against legacy `7dca720` covering the capability being replaced.
- One capability per PR, with its tests, its README example (enforced by `tests/readme.rs`) and its CAPABILITIES row update.
- Port behaviour, not structure: legacy is the oracle, not a source to copy wholesale. Async code is rewritten as blocking code over `http::Transport`.
- Every boundary or secrets change gets Security & Secrets Bot review. Every PR needs a non-author cross-review before merge.
- REFACTOR Bot owns this policy, the lineage and merge rule, and provider migration.

## ORDERED BACKLOG

PLANNED, in this order. "In flight" means work has started on that branch and is not on `main` yet; "Done" names the PR that put it on `main`.
1. People-lookup pipeline, end to end: CLI command, fetch, provider, parse, evidence, merge decision, saved file, `verify`, output and exit codes. It needs at least one keyless public people source (candidate: `asic_persons` over data.gov.au CKAN) and one live keyless run with a receipt tied to the commit. Done: the lineage and merge rule, as a library (#679, REFACTOR Bot). In flight: the HIBP CLI PR (`feat/hibp-cli`, Software Development Bot); `asic_persons` plus `people_cli` (this branch, REFACTOR Bot) — skip path and fake-transport lineage tested; no save/`verify` and no live run yet.
2. Port `au_people`, `asic_director` and HIBP first, each with a differential test against legacy output. `asic_persons` emit/name/controller behaviour is covered by fake-transport unit tests; D/L against live CKAN remain open.
3. stolen.tax and crt.sh (`feat/recon-stolen-tax-v2-crtsh`, in flight).
4. Compile the 8 orphan modules (G8). Done: #675.
5. The rest of CAPABILITIES, ranked by user value.
