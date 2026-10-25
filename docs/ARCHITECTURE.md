# Target architecture (Stage 1 inventory)

Status: **PLANNED** design plus a **CURRENT** inventory taken at `main` commit `2bc6d0f38a00b6b7b331823f89f9188237a81e47` (#1109). The authoritative, test-enforced module map, capability matrix (CURRENT/PLANNED) and layer rules remain in the root [`ARCHITECTURE.md`](../ARCHITECTURE.md), checked by `tests/architecture_doc.rs`. This document changes no code, moves no module and supersedes nothing there; if the two disagree, the root document and its test win.

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

## Current → proposed home (inventory)

233 modules are declared in `src/lib.rs` at `2bc6d0f` (232 in the root map plus `test_support`). Proposed homes are derived from the current root layer (L0/L3 → `core`, L1 → `evidence`, L2 → `infrastructure`, L4/L6 → `collection`, L5 → `analysis`, L7 → `application`), then corrected: L5 modules that send through `fetch`/`http`/`api_leg` move to `collection`, `*_cli` adapters to `cli`, and the serve listener/API to `web`.

| Proposed home | Count | Modules |
| --- | --- | --- |
| `src/core/` | 45 | `address_au`, `au_id`, `base64`, `canonical`, `circuit`, `clock`, `concurrent`, `directive_lock`, `dmarc`, `dns_wire`, `domains`, `engineering_command`, `environment`, `error`, `exit`, `fsio`, `geohash`, `json`, `lookup_args`, `md5`, `netblock`, `oui`, `oui_ieee`, `pattern`, `phone_intl`, `postcode_au`, `radar`, `redact`, `scan_batch`, `sha256`, `spf`, `stage`, `stdio_failure`, `tags`, `termination`, `test_support`, `textnorm`, `timefmt`, `tlsrpt`, `union_find`, `username_variants`, `validation`, `value_syntax`, `x509`, `yaml_lite` |
| `src/evidence/` | 5 | `confidence`, `evidence_ancestry`, `identity_resolution`, `resolve`, `retrieval_artifact` |
| `src/infrastructure/` | 10 | `api_leg`, `classify`, `credential_origin`, `deadline`, `egress`, `fetch`, `http`, `keys`, `module_selection`, `source_outcome` |
| `src/collection/` | 84 | `abuseipdb`, `asic_director`, `asic_persons`, `atproto`, `blockchain`, `bluesky_user`, `cell_radar`, `censys`, `certspotter`, `ckan`, `collection`, `collector`, `crtsh`, `dehashed`, `dns`, `dns_filter`, `dnsbl`, `docmeta`, `domain_lifecycle`, `duolingo`, `exa`, `exif`, `geoint`, `github_user`, `gravatar`, `greynoise`, `hackertarget`, `hibp`, `hudsonrock`, `hunter`, `indicator_legs`, `indicator_sources`, `internetdb`, `ipinfo`, `ipqs`, `isc`, `itunes`, `key_import`, `keybase`, `kickbox`, `leakix`, `lookup_report`, `maltiverse`, `mastodon_user`, `mnemonic`, `netlas`, `nominatim`, `numverify`, `oathnet`, `opencellid`, `openpgp_keys`, `otx`, `phishstats`, `pipeline_limits`, `planner`, `provider_credentials`, `pulsedive`, `rdap`, `rdap_legs`, `recon`, `recursion`, `rf`, `ripestat`, `robtex`, `securitytrails`, `seeknow`, `seeknow_collector`, `service_defs`, `shodan`, `source_registry`, `stolen_tax`, `stopforumspam`, `submd`, `threat_feeds`, `threatfox`, `urlhaus`, `urlscan`, `virustotal`, `web_query`, `whoxy`, `wifi_radar`, `wigle`, `wikipedia`, `xposedornot` |
| `src/analysis/` | 46 | `analysis`, `attack`, `attack_catalog`, `attack_reporting`, `benchmark`, `breach_hybrid`, `claim_coverage`, `claim_policy`, `classifier`, `commercial_readiness`, `community`, `coref`, `correlator`, `coverage`, `cross_scan`, `dependency`, `diagnostics`, `differential`, `entity`, `entity_reality`, `exposure`, `gap`, `graph`, `identity`, `intelligence`, `leads`, `lineage`, `meta_plan`, `metrics`, `module`, `pipeline`, `pivot`, `profiles`, `proof`, `relation`, `roi`, `scan_artifact`, `scan_route`, `sf_compat`, `sf_correlate`, `sf_country`, `sf_elements`, `sf_types`, `shadow_assessment`, `timeline`, `trafficking_intel` |
| `src/application/` | 24 | `artifacts`, `doctor`, `dossier_view`, `evidence_register`, `gexf`, `graph_exec`, `ledger`, `lookup_modules`, `lookup_save`, `navigator`, `run_history`, `runtime`, `scan_compare`, `scan_export`, `scan_search`, `scan_service`, `scan_store`, `scan_uncertainty`, `search`, `session`, `snake_graph`, `stix`, `store`, `xlsx` |
| `src/web/` | 3 | `scan_api`, `serve_probe`, `web_server` |
| `src/cli/` | 16 | `asn_cli`, `attack_cli`, `crypto_cli`, `domain_cli`, `email_cli`, `exposure_cli`, `fetch_cli`, `ip_cli`, `itunes_cli`, `netblock_cli`, `network_cli`, `nominatim_cli`, `people_cli`, `phone_cli`, `seeknow_cli`, `username_cli` |

Notable outliers:
- 35 modules mapped today to L5 (entity model and analysis) are network collectors (`asic_*`, `*_user`, `crtsh`, `certspotter`, `dehashed`, `stolen_tax`, `oathnet`, `nominatim`, `dnsbl`, `dns_filter`, `planner`, `recursion`, `collector`, `collection`, ...). Moving them to `collection` is the largest Stage 2+ change.
- 16 `*_cli` front-ends are library modules, not binary code; several are called from library modules (`lookup_modules`, `scan_route`, `asic_persons`).
- Name clashes: `src/analysis.rs` and `src/collection.rs` already exist as modules; the new directories must absorb them (`analysis/mod.rs`, `collection/mod.rs`) with re-exports, not shadow them.
- `radar` (L0) is persistence for `radar track`, not a pure primitive.

## Edges and violations of the proposed graph

Edge inventory: ~1,300 module-level `crate::` edges among the 233 modules (heuristic text scan, `#[cfg(test)]` tails stripped). The root map's CURRENT statement — one upward edge `resolve` (L1) → `lineage` (L5), no cycles — is the test-enforced truth for the current layering. Against the *proposed* graph the heuristic scan finds:

| From → to | Edges | Examples | Stage |
| --- | --- | --- | --- |
| analysis → infrastructure | 101 | resolved by moving the 35 collectors above into `collection` | 2+ |
| analysis → collection | 41 | `asic_persons → ckan`, `crtsh → recon`, `dehashed → hibp` | 2+ |
| application → cli | 12 | `lookup_modules → *_cli` | 3 |
| analysis → cli | 4 | `asic_persons → people_cli`, `scan_route → {exposure,nominatim,people}_cli` | 3 |
| core → infrastructure / analysis / evidence | 8 | `canonical → {egress, classifier, evidence_ancestry}`, `tlsrpt → http` | 2 |
| core → application | 1 | `lookup_args → lookup_save` | 2 |
| infrastructure → analysis | 1 | `module_selection → module` | 2 |
| evidence → analysis | 1 | `resolve → lineage` (the documented exception) | 2 |
| collection → analysis | 1 | `wigle → scan_route` | 2 |
| application → web | 1 | `doctor → serve_probe` | 3 |

Cycles: none. This is the authoritative result of `tests/architecture_doc.rs` (`dependencies_match_the_stated_layering`, passing at `2bc6d0f`), which the root map states as `Dependency cycles: none.` The heuristic scan above is only used to size cross-home edges; it is not a cycle oracle.

## Wi-Fi / cell / RF coupling (Stage 2 input)

No MITM code exists in `src/` at `2bc6d0f` (no `mitm` identifier); Wi-Fi MITM screening is proposed separately in open PRs #1402/#1403 and is out of Stage 1 scope. The radio surface is:

| Module | Layer now | Uses | Used by |
| --- | --- | --- | --- |
| `radar` | L0 | `fsio` | `wifi_radar`, `web_server` |
| `wifi_radar` | L6 | `cell_radar`, `rf`, `radar`, `oui`, `textnorm`, `error` | `web_server` |
| `cell_radar` | L6 | `rf`, `textnorm`, `error` | `wifi_radar`, `web_server` |
| `rf` | L6 | `canonical`, `timefmt` | `wifi_radar`, `cell_radar`, `wigle` |
| `oui` / `oui_ieee` | L0 | — | `wifi_radar`, `network_cli` |
| `wigle` | L6 | `fetch`, `http`, `keys`, `provider_credentials`, `scan_route`, ... | `network_cli`, `lookup_modules` |
| `opencellid` | L4 | `api_leg`, `indicator_sources`, `keys` | `network_cli`, `indicator_legs` |
| `network_cli` | L6 | `wigle`, `opencellid`, `oui`, `indicator_legs`, `lookup_report`, `scan_route` | `lookup_modules` |

Stage 2 notes: (1) `wifi_radar → cell_radar` couples two acquisitions; the serving-cell placement for `radar track` should move into an `application` coordinator so `collection/radio/{wifi,cell}` are siblings. (2) `radar` (track log) belongs with storage, not `core`. (3) `rf` sighting types are immutable observations and belong in `evidence`. (4) `wigle → scan_route` is the only collection → analysis edge in the radio slice. (5) `web_server` reaches `radar`/`wifi_radar`/`cell_radar` directly; route through `application`. No BLE work is in scope.

## Stage plan (10 stages)

Every stage is one PR max, preserves the CAPABILITIES table and CURRENT/PLANNED labels in root `ARCHITECTURE.md`, keeps `tests/architecture_doc.rs` green, and claims no verification without a receipt at the exact commit. Facade `pub use` paths in `src/lib.rs` remain until a later explicit deprecation stage.

1. **Stage 1 (this document).** Inventory, proposed homes, edge/violation list, Wi-Fi/RF coupling notes. Documentation only — no code moves.
2. **Stage 2 — directory shims.** Create empty `src/{core,infrastructure,evidence,collection,analysis,application,web}/` with `mod.rs` re-export skeletons; keep every module at its current path. Update root map/`PINNED_LAYERS` only if a new wrapper module is declared.
3. **Stage 3 — move `core`.** Relocate L0/L3 leaves into `src/core/`; re-export from `lib.rs`; AArch64 cross-build + architecture tests green.
4. **Stage 4 — move `evidence`.** Relocate L1 evidence contracts into `src/evidence/`; keep immutable-observation APIs stable.
5. **Stage 5 — move `infrastructure`.** Relocate L2 network boundary (`http`, `fetch`, `egress`, `keys`, …) into `src/infrastructure/`; no second HTTP client.
6. **Stage 6 — radio / Wi-Fi decoupling.** Split `wifi_radar`/`cell_radar` into sibling collection acquisitions; move `radar` track storage out of core; move `rf` sighting types toward evidence; break `wigle → scan_route`; stop `web_server` reaching radio modules directly. No MITM/BLE in this stage unless already on `main`.
7. **Stage 7 — move `collection`.** Relocate L4/L6 clients plus the 35 L5 network collectors into `src/collection/`.
8. **Stage 8 — move `analysis`.** Relocate remaining L5 analysis onto immutable observations only (no network deps).
9. **Stage 9 — `application` / `web` / `cli`.** Relocate L7 + serve/API; break `application/analysis → *_cli` edges by lifting shared logic out of CLI adapters.
10. **Stage 10 — enforce proposed graph.** Replace L0–L7 pins in `tests/architecture_doc.rs` with the eight homes; fail CI on upward edges/cycles against the new graph; keep CAPABILITIES matrix unchanged unless improved with exact-revision evidence.

Stages 2–10 each require: architecture_doc + architecture_boundaries green, Android AArch64 cross-build green, key-scan 0, 0 review threads, merge with `gh pr merge --merge --match-head-commit`.
