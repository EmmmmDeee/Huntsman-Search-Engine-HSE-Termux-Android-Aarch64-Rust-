# Target architecture (Stage 1 inventory + Stage 2 shim plan)

Status: **PLANNED** design plus a **CURRENT** inventory recomputed at `main` tip `65c7ba9d7` (2026-11-01, Australia/Brisbane). Stage 2 on this branch adds empty-home re-export shims only (`src/{core,infrastructure,evidence,application,web}/mod.rs`); it moves no leaf module and creates no `analysis/` or `collection/` directory (name clash with `src/analysis.rs` / `src/collection.rs`). The authoritative, test-enforced module map, capability matrix (CURRENT/PLANNED) and layer rules remain in the root [`ARCHITECTURE.md`](../ARCHITECTURE.md), checked by `tests/architecture_doc.rs`. If the two disagree, the root document and its test win.

> **Inventory freshness (2026-11-01):** Recomputed against `origin/main` tip `65c7ba9d7` ("fix(itunes): fail closed on malformed search envelopes and unusable results (#1609)"). **276** leaf modules are declared in `src/lib.rs` (275 `pub mod` leaves plus private `test_support`), versus 233 at the Stage 1 snapshot `2bc6d0f` and 238 at the previous refresh `92d5b6151` (2026-10-27). Added since `2bc6d0f`: `gitlab_user`, `mitm_guard`, `network_selector`, `tiktok_public_contact`, `wayback_cdx`, plus 38 since `92d5b6151` (listed below). None removed. Counts, the module→home map, the target tree and the radio/edge notes below match this tip. The root capability matrix is untouched. The five Stage 2 shim modules (`core`, `infrastructure`, `evidence`, `application`, `web`) are extra `pub mod` lines that re-export existing leaves and are not counted in the leaf inventory.

## Goal

A pure-Rust modular monolith, one package (`huntsman-recon`), feature-oriented internal modules under `src/`:

`core/`, `infrastructure/`, `evidence/`, `collection/`, `analysis/`, `application/`, `web/`, `cli/`.

Constraints carried into every stage: no new crates, no runtime LLM, Termux AArch64 rootless, the Android AArch64 cross-build stays green, and full backward compatibility through `src/lib.rs` re-exports (every current `huntsman_recon::<module>` path keeps resolving), unchanged CLI grammar, JSON output and on-disk ledger/session/store formats.

## Dependency direction (PLANNED)

```
cli ──► web ──► application ──► analysis ──► evidence ──► core
                     │                          ▲
                     └──► collection ───────────┘
                              │
                              └──► infrastructure ──► core
```

| Home | May depend on |
| --- | --- |
| `core` | nothing inside the crate |
| `evidence` | `core` (shared immutable evidence contracts) |
| `infrastructure` | `core` only (guarded transport, egress, keys, fetch) |
| `collection` | `core`, `evidence`, `infrastructure` |
| `analysis` | `core`, `evidence` only — operates on immutable observations, never on the network |
| `application` | everything below; coordinates collection → evidence → analysis → storage |
| `web` | `application` and below |
| `cli` | everything; the binary adapter (`src/main.rs`, `src/cli/`) stays the only process boundary |

No cycles at any granularity. Resources (bodies, batches, generations, stacks, workers) stay bounded as they are today.

## Target directory tree (PLANNED; Stage 2 shims only for five homes)

```
src/
  core/                  # Stage 2 shim: re-exports L0/L3 leaves (+ network_selector)
  infrastructure/
    mod.rs               # Stage 2 shim: re-exports L2 leaves
    network/             # PLANNED later: http, fetch, egress, deadline, …
    platform/            # PLANNED later: keys, credential_origin, …
    providers/           # PLANNED later: api_leg, module_selection, …
    storage/             # PLANNED later: (none yet; store stays application)
  evidence/              # Stage 2 shim: re-exports L1 leaves
  collection/            # NOT created in Stage 2 — name clash with src/collection.rs
  analysis/              # NOT created in Stage 2 — name clash with src/analysis.rs
    mitm/                # PLANNED later: fold mitm_guard here after the clash is resolved
  application/           # Stage 2 shim: re-exports L7 record/orchestration leaves
  web/                   # Stage 2 shim: re-exports scan_api, serve_probe, web_server
  cli/                   # already exists (binary adapters); no Stage 2 change
```

**Fold plan for `analysis.rs` / `collection.rs`:** Stage 2 must not add `src/analysis/mod.rs` or `src/collection/mod.rs`. Rust would treat those directories as the `analysis` / `collection` modules and hide the existing `src/analysis.rs` / `src/collection.rs` files. Later stages absorb each leaf by renaming `src/analysis.rs` → `src/analysis/mod.rs` (same for `collection`) and moving peer files underneath, keeping `pub use` so `crate::analysis` and `crate::collection` paths stay stable. Until then, collectors and analysis leaves stay at their current flat paths; `mitm_guard` stays flat under `collection` in the proposed-home map (target `analysis/mitm/` is documentation only).

## Current → proposed home (inventory)

276 leaf modules are declared in `src/lib.rs` at `65c7ba9d7` (275 `pub mod` plus private `test_support`). Proposed homes reuse the Stage 1 mapping at `2bc6d0f`, extended by the same rules for modules added since: root L0/L3 → `core`, L1 → `evidence`, L2 → `infrastructure`, L4/L6 → `collection`, L5 → `analysis`, L7 → `application`, then corrected so L5 modules that send through `fetch`/`http`/`api_leg` move to `collection`, `*_cli` adapters to `cli`, and the serve listener/API to `web`.

**New since `2bc6d0f` (assignment rule):**
- `network_selector` → `core` — L3 pure grammar; depends only on `canonical`.
- `mitm_guard` → `collection` — L6 RF/Wi-Fi advisory; peer of `wifi_radar` (target later: `analysis/mitm/` after the clash fold).
- `gitlab_user` → `collection` — network collector via `fetch`/`http` (same correction as `github_user`).
- `tiktok_public_contact` → `collection` — same.

| Proposed home | Count | Modules |
| --- | --- | --- |
| `src/core/` | 47 | `address_au`, `au_id`, `base64`, `canonical`, `circuit`, `clock`, `concurrent`, `directive_lock`, `dmarc`, `dns_wire`, `domains`, `engineering_command`, `environment`, `error`, `exit`, `fsio`, `geohash`, `html_text`, `json`, `lookup_args`, `md5`, `netblock`, `network_selector`, `oui`, `oui_ieee`, `pattern`, `phone_intl`, `postcode_au`, `radar`, `redact`, `scan_batch`, `sha256`, `spf`, `stage`, `stdio_failure`, `tags`, `termination`, `test_support`, `textnorm`, `timefmt`, `tlsrpt`, `union_find`, `username_variants`, `validation`, `value_syntax`, `x509`, `yaml_lite` |
| `src/evidence/` | 5 | `confidence`, `evidence_ancestry`, `identity_resolution`, `resolve`, `retrieval_artifact` |
| `src/infrastructure/` | 10 | `api_leg`, `classify`, `credential_origin`, `deadline`, `egress`, `fetch`, `http`, `keys`, `module_selection`, `source_outcome` |
| `src/collection/` | 112 | `abuseipdb`, `acnc`, `asic_director`, `asic_persons`, `atproto`, `base_rpc`, `blockchain`, `bluesky_user`, `cell_radar`, `censys`, `certspotter`, `ckan`, `collection`, `collector`, `common_crawl`, `crates_io`, `crtsh`, `dehashed`, `dns`, `dns_filter`, `dnsbl`, `docker_hub_user`, `docmeta`, `domain_lifecycle`, `duolingo`, `eth_rpc`, `evm_rpc`, `exa`, `exif`, `federated_osint`, `geoint`, `github_repos`, `github_user`, `gitlab_user`, `gleif`, `gravatar`, `greynoise`, `hacker_news`, `hackertarget`, `hibp`, `hudsonrock`, `hunter`, `indicator_legs`, `indicator_sources`, `internetdb`, `ipinfo`, `ipqs`, `isc`, `itunes`, `key_import`, `keybase`, `kickbox`, `leakix`, `lobsters`, `lookup_report`, `maltiverse`, `mastodon_user`, `mitm_guard`, `mnemonic`, `netlas`, `nominatim`, `npm_author`, `numverify`, `oathnet`, `opencellid`, `openpgp_keys`, `opensky`, `osint_area_risk`, `osint_casework`, `otx`, `peeringdb`, `phishstats`, `pipeline_limits`, `planner`, `provider_credentials`, `public_osint`, `pulsedive`, `rdap`, `rdap_legs`, `recon`, `recursion`, `rf`, `rhinser_catalog`, `ripestat`, `robtex`, `routing_context`, `sec_edgar`, `securitytrails`, `seeknow`, `seeknow_collector`, `service_defs`, `shodan`, `solana_rpc`, `source_registry`, `stac`, `stolen_tax`, `stopforumspam`, `submd`, `threat_feeds`, `threatfox`, `tiktok_public_contact`, `urlhaus`, `urlscan`, `virustotal`, `wayback_cdx`, `web_query`, `whoxy`, `wifi_radar`, `wigle`, `wikidata`, `wikipedia`, `xposedornot` |
| `src/analysis/` | 51 | `analysis`, `apk_intel`, `archived_page`, `attack`, `attack_catalog`, `attack_reporting`, `benchmark`, `breach_hybrid`, `claim_coverage`, `claim_policy`, `classifier`, `commercial_readiness`, `community`, `coref`, `correlator`, `coverage`, `cross_scan`, `dependency`, `diagnostics`, `differential`, `entity`, `entity_reality`, `exposure`, `gap`, `graph`, `identity`, `intelligence`, `leads`, `lineage`, `meta_plan`, `metrics`, `module`, `pipeline`, `pivot`, `profiles`, `proof`, `relation`, `research_route`, `rhinser_nfc`, `rhinser_workspace`, `roi`, `scan_artifact`, `scan_route`, `sf_compat`, `sf_correlate`, `sf_country`, `sf_elements`, `sf_types`, `shadow_assessment`, `timeline`, `trafficking_intel` |
| `src/application/` | 29 | `artifacts`, `doctor`, `docx`, `dossier_view`, `evidence_register`, `gexf`, `graph_exec`, `ledger`, `lookup_modules`, `lookup_save`, `navigator`, `osint_blueprint`, `run_history`, `runtime`, `scan_alert`, `scan_compare`, `scan_coverage`, `scan_export`, `scan_retention`, `scan_search`, `scan_service`, `scan_store`, `scan_uncertainty`, `search`, `session`, `snake_graph`, `stix`, `store`, `xlsx` |
| `src/web/` | 4 | `scan_api`, `serve_events`, `serve_probe`, `web_server` |
| `src/cli/` | 18 | `asn_cli`, `attack_cli`, `crypto_cli`, `domain_cli`, `email_cli`, `exposure_cli`, `fetch_cli`, `gleif_cli`, `ip_cli`, `itunes_cli`, `netblock_cli`, `network_cli`, `nominatim_cli`, `people_cli`, `phone_cli`, `seeknow_cli`, `username_cli`, `wikidata_cli` |

Counts by home, `2bc6d0f` → `92d5b6151` → `65c7ba9d7`: core 45→46→47, evidence 5→5→5, infrastructure 10→10→10, collection 84→88→112, analysis 46→46→51, application 24→24→29, web 3→3→4, cli 16→16→18; total 233→238→276.

Notable outliers:
- 35 modules mapped today to L5 (entity model and analysis) are network collectors (`asic_*`, `*_user`, `crtsh`, `certspotter`, `dehashed`, `stolen_tax`, `oathnet`, `nominatim`, `dnsbl`, `dns_filter`, `planner`, `recursion`, `collector`, `collection`, …). Moving them to `collection` is the largest Stage 2+ change.
- 16 `*_cli` front-ends are library modules, not binary code; several are called from library modules (`lookup_modules`, `scan_route`, `asic_persons`).
- Name clashes: `src/analysis.rs` and `src/collection.rs` already exist as modules; the new directories must absorb them (`analysis/mod.rs`, `collection/mod.rs`) with re-exports, not shadow them. Stage 2 therefore skips those two homes.
- `radar` (L0) is persistence for `radar track`, not a pure primitive.
- `test_support` stays private in `lib.rs` and is listed under `core` for inventory only; Stage 2 shims do **not** re-export it.

## Edges and violations of the proposed graph

Edge inventory: ~1,519 module-level `crate::` edges among the 276 leaf modules (heuristic text scan at `65c7ba9d7`, `#[cfg(test)]` tails stripped). The root map's CURRENT statement — one upward edge `resolve` (L1) → `lineage` (L5), no cycles — is the test-enforced truth for the current layering. Against the *proposed* graph the heuristic scan finds (bucket sizes at this tip):

| From → to | Edges (approx) |
| --- | --- |
| collection → analysis | 74 |
| analysis → collection | 16 |
| analysis → cli | 5 |
| analysis → infrastructure | 4 |
| core → analysis | 3 |
| collection → cli | 3 |
| core → infrastructure | 3 |
| application → cli | 2 |
| application → web | 2 |
| infrastructure → analysis | 1 |
| core → application | 1 |
| core → collection | 1 |
| core → evidence | 1 |
| evidence → analysis | 1 |

Notes: collection → analysis is mostly collectors building `entity`/`relation` values (Stage 7); `wigle → scan_route` is gone (`wigle` → `network_selector`); `evidence → analysis` is the documented `resolve` → `lineage` exception.

Cycles against the *current* L0–L7 layering: **none**. Authoritative: `tests/architecture_doc.rs` (`dependencies_match_the_stated_layering`) and root `ARCHITECTURE.md` (`Dependency cycles: none.`). The heuristic scan above sizes proposed-home cross edges only; it is not a cycle oracle .

## Wi-Fi / cell / RF coupling (Stage 2 input)

At `65c7ba9d7`, `mitm_guard` is on `main` (L6; advisory, evidence-gated Wi-Fi assessment; no packet injection). The radio surface (heuristic `crate::` edges, production sources):

| Module | Proposed home | Uses (notable) | Used by |
| --- | --- | --- | --- |
| `radar` | `core` | `fsio` | `web_server`, `wifi_radar` |
| `wifi_radar` | `collection` | `cell_radar`, `error`, `mitm_guard`, `radar`, `rf`, `textnorm`, `timefmt` | `web_server` |
| `cell_radar` | `collection` | `error`, `rf`, `textnorm`, `timefmt` | `web_server`, `wifi_radar` |
| `rf` | `collection` | `canonical`, `error`, `textnorm`, `timefmt` | `cell_radar`, `mitm_guard`, `wifi_radar`, `wigle` |
| `mitm_guard` | `collection` | `rf` | `wifi_radar` |
| `wigle` | `collection` | `environment`, `fetch`, `http`, `keys`, `network_selector`, `provider_credentials`, `redact`, `rf`, `source_outcome` | `network_cli` |
| `network_selector` | `core` | `canonical` | `research_route`, `scan_route`, `wigle` |
| `opensky` | `collection` | `entity`, `error`, `fetch`, `geohash`, `http`, `source_outcome`, `timefmt` | `lookup_modules`, `lookup_save`, `nominatim_cli` |
| `osint_area_risk` | `collection` | `error`, `geoint`, `osint_casework` | `web_server` |

Stage 2 notes: (1) `wifi_radar → cell_radar` couples two acquisitions; serving-cell placement for `radar track` should move into an `application` coordinator so radio acquisitions are siblings. (2) `radar` (track log) belongs with storage, not `core`. (3) `rf` sighting types are immutable observations and belong in `evidence`. (4) **`wigle → scan_route` is resolved** on this tip (`wigle` → `network_selector`); keep the architecture_boundaries guard. (5) `web_server` still reaches `radar`/`wifi_radar`/`cell_radar` directly; route through `application`. (6) `mitm_guard` now depends only on `rf`; the `wifi_radar` ↔ `mitm_guard` mutual edge seen at `92d5b6151` is gone (`wifi_radar` → `mitm_guard` remains). (7) New geo leaves `opensky` (collection) and `osint_area_risk` (L6, reached from `web_server`) add no radio-module coupling. No BLE work is in scope.

## Stage plan (10 stages)

Every stage is one PR max, preserves the CAPABILITIES table and CURRENT/PLANNED labels in root `ARCHITECTURE.md`, keeps `tests/architecture_doc.rs` green, and claims no verification without a receipt at the exact commit. Facade `pub use` paths in `src/lib.rs` remain until a later explicit deprecation stage.

1. **Stage 1 (inventory in this document).** Inventory, proposed homes, edge/violation list, Wi-Fi/RF coupling notes. Documentation only — no code moves.
2. **Stage 2 (shims on this branch).** Create `src/{core,infrastructure,evidence,application,web}/` with `mod.rs` re-export skeletons; keep every leaf at its current path. **Do not** create `analysis/` or `collection/` directories. Update root map rows only as needed so the five shim modules are placed; add runtime disposition rows for the shims.
3. **Stage 3 — move `core`.** Relocate L0/L3 leaves into `src/core/`; re-export from `lib.rs`; AArch64 cross-build + architecture tests green.
4. **Stage 4 — move `evidence`.** Relocate L1 evidence contracts into `src/evidence/`.
5. **Stage 5 — move `infrastructure`.** Relocate L2 network boundary into `src/infrastructure/` (and later `network/`/`platform/`/`providers/` subdirs); no second HTTP client.
6. **Stage 6 — radio / Wi-Fi decoupling.** Split `wifi_radar`/`cell_radar`; move `radar` track storage out of core; move `rf` toward evidence; stop `web_server` reaching radio modules directly; keep `mitm_guard` depending only on `rf`. (`wigle → scan_route` already broken via `network_selector`.) No BLE.
7. **Stage 7 — move `collection`.** Absorb `src/collection.rs` into `src/collection/mod.rs`, then relocate L4/L6 clients plus the network collectors.
8. **Stage 8 — move `analysis`.** Absorb `src/analysis.rs` into `src/analysis/mod.rs`; relocate remaining analysis; fold `mitm_guard` toward `analysis/mitm/` only after the clash fold.
9. **Stage 9 — `application` / `web` / `cli`.** Relocate L7 + serve/API; break `application/analysis → *_cli` edges by lifting shared logic out of CLI adapters.
10. **Stage 10 — enforce proposed graph.** Replace L0–L7 pins with the eight homes; fail CI on upward edges/cycles against the new graph; keep CAPABILITIES matrix unchanged unless improved with exact-revision evidence.

Stages 2–10 each require: architecture_doc + architecture_boundaries green, Android AArch64 cross-build green, key-scan 0 new findings on changed files, 0 review threads, merge with `gh pr merge --merge --match-head-commit`.
