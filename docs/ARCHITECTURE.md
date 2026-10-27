# Target architecture (Stage 1 inventory + Stage 2 shim plan)

Status: **PLANNED** design plus a **CURRENT** inventory recomputed at `main` tip `92d5b6151` (2026-10-27, Australia/Brisbane). Stage 2 on this branch adds empty-home re-export shims only (`src/{core,infrastructure,evidence,application,web}/mod.rs`); it moves no leaf module and creates no `analysis/` or `collection/` directory (name clash with `src/analysis.rs` / `src/collection.rs`). The authoritative, test-enforced module map, capability matrix (CURRENT/PLANNED) and layer rules remain in the root [`ARCHITECTURE.md`](../ARCHITECTURE.md), checked by `tests/architecture_doc.rs`. If the two disagree, the root document and its test win.

> **Inventory freshness (2026-10-27):** Recomputed against `origin/main` tip `92d5b6151` ("Require RustSec audit before merging pull requests (#1435)"). Compared with the Stage 1 snapshot at `2bc6d0f` (233 modules): **238** modules are declared in `src/lib.rs` (237 `pub mod` plus private `test_support`). Added since the snapshot: `gitlab_user`, `mitm_guard`, `network_selector`, `tiktok_public_contact`, `wayback_cdx`. None removed. Counts, the module→home map, the target tree and the radio/edge notes below match this tip. The root capability matrix is untouched. Stage 2 shim modules (`core`, `infrastructure`, `evidence`, `application`, `web`) are additional `pub mod` lines that re-export existing leaves; they are not counted in the 238 leaf inventory.

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

238 leaf modules are declared in `src/lib.rs` at `92d5b6151` (237 `pub mod` plus private `test_support`). Proposed homes reuse the Stage 1 mapping at `2bc6d0f`, extended by the same rules for modules added since: root L0/L3 → `core`, L1 → `evidence`, L2 → `infrastructure`, L4/L6 → `collection`, L5 → `analysis`, L7 → `application`, then corrected so L5 modules that send through `fetch`/`http`/`api_leg` move to `collection`, `*_cli` adapters to `cli`, and the serve listener/API to `web`.

**New since `2bc6d0f` (assignment rule):**
- `network_selector` → `core` — L3 pure grammar; depends only on `canonical`.
- `mitm_guard` → `collection` — L6 RF/Wi-Fi advisory; peer of `wifi_radar` (target later: `analysis/mitm/` after the clash fold).
- `gitlab_user` → `collection` — network collector via `fetch`/`http` (same correction as `github_user`).
- `tiktok_public_contact` → `collection` — same.
- `wayback_cdx` → `collection` — same.

| Proposed home | Count | Modules |
| --- | --- | --- |
| `src/core/` | 46 | `address_au`, `au_id`, `base64`, `canonical`, `circuit`, `clock`, `concurrent`, `directive_lock`, `dmarc`, `dns_wire`, `domains`, `engineering_command`, `environment`, `error`, `exit`, `fsio`, `geohash`, `json`, `lookup_args`, `md5`, `netblock`, `network_selector`, `oui`, `oui_ieee`, `pattern`, `phone_intl`, `postcode_au`, `radar`, `redact`, `scan_batch`, `sha256`, `spf`, `stage`, `stdio_failure`, `tags`, `termination`, `test_support`, `textnorm`, `timefmt`, `tlsrpt`, `union_find`, `username_variants`, `validation`, `value_syntax`, `x509`, `yaml_lite` |
| `src/evidence/` | 5 | `confidence`, `evidence_ancestry`, `identity_resolution`, `resolve`, `retrieval_artifact` |
| `src/infrastructure/` | 10 | `api_leg`, `classify`, `credential_origin`, `deadline`, `egress`, `fetch`, `http`, `keys`, `module_selection`, `source_outcome` |
| `src/collection/` | 88 | `abuseipdb`, `asic_director`, `asic_persons`, `atproto`, `blockchain`, `bluesky_user`, `cell_radar`, `censys`, `certspotter`, `ckan`, `collection`, `collector`, `crtsh`, `dehashed`, `dns`, `dns_filter`, `dnsbl`, `docmeta`, `domain_lifecycle`, `duolingo`, `exa`, `exif`, `geoint`, `github_user`, `gitlab_user`, `gravatar`, `greynoise`, `hackertarget`, `hibp`, `hudsonrock`, `hunter`, `indicator_legs`, `indicator_sources`, `internetdb`, `ipinfo`, `ipqs`, `isc`, `itunes`, `key_import`, `keybase`, `kickbox`, `leakix`, `lookup_report`, `maltiverse`, `mastodon_user`, `mitm_guard`, `mnemonic`, `netlas`, `nominatim`, `numverify`, `oathnet`, `opencellid`, `openpgp_keys`, `otx`, `phishstats`, `pipeline_limits`, `planner`, `provider_credentials`, `pulsedive`, `rdap`, `rdap_legs`, `recon`, `recursion`, `rf`, `ripestat`, `robtex`, `securitytrails`, `seeknow`, `seeknow_collector`, `service_defs`, `shodan`, `source_registry`, `stolen_tax`, `stopforumspam`, `submd`, `threat_feeds`, `threatfox`, `tiktok_public_contact`, `urlhaus`, `urlscan`, `virustotal`, `wayback_cdx`, `web_query`, `whoxy`, `wifi_radar`, `wigle`, `wikipedia`, `xposedornot` |
| `src/analysis/` | 46 | `analysis`, `attack`, `attack_catalog`, `attack_reporting`, `benchmark`, `breach_hybrid`, `claim_coverage`, `claim_policy`, `classifier`, `commercial_readiness`, `community`, `coref`, `correlator`, `coverage`, `cross_scan`, `dependency`, `diagnostics`, `differential`, `entity`, `entity_reality`, `exposure`, `gap`, `graph`, `identity`, `intelligence`, `leads`, `lineage`, `meta_plan`, `metrics`, `module`, `pipeline`, `pivot`, `profiles`, `proof`, `relation`, `roi`, `scan_artifact`, `scan_route`, `sf_compat`, `sf_correlate`, `sf_country`, `sf_elements`, `sf_types`, `shadow_assessment`, `timeline`, `trafficking_intel` |
| `src/application/` | 24 | `artifacts`, `doctor`, `dossier_view`, `evidence_register`, `gexf`, `graph_exec`, `ledger`, `lookup_modules`, `lookup_save`, `navigator`, `run_history`, `runtime`, `scan_compare`, `scan_export`, `scan_search`, `scan_service`, `scan_store`, `scan_uncertainty`, `search`, `session`, `snake_graph`, `stix`, `store`, `xlsx` |
| `src/web/` | 3 | `scan_api`, `serve_probe`, `web_server` |
| `src/cli/` | 16 | `asn_cli`, `attack_cli`, `crypto_cli`, `domain_cli`, `email_cli`, `exposure_cli`, `fetch_cli`, `ip_cli`, `itunes_cli`, `netblock_cli`, `network_cli`, `nominatim_cli`, `people_cli`, `phone_cli`, `seeknow_cli`, `username_cli` |

Diff vs `2bc6d0f` counts (old → new): core 45→46, evidence 5→5, infrastructure 10→10, collection 84→88, analysis 46→46, application 24→24, web 3→3, cli 16→16; total 233→238.

Notable outliers:
- 35 modules mapped today to L5 (entity model and analysis) are network collectors (`asic_*`, `*_user`, `crtsh`, `certspotter`, `dehashed`, `stolen_tax`, `oathnet`, `nominatim`, `dnsbl`, `dns_filter`, `planner`, `recursion`, `collector`, `collection`, …). Moving them to `collection` is the largest Stage 2+ change.
- 16 `*_cli` front-ends are library modules, not binary code; several are called from library modules (`lookup_modules`, `scan_route`, `asic_persons`).
- Name clashes: `src/analysis.rs` and `src/collection.rs` already exist as modules; the new directories must absorb them (`analysis/mod.rs`, `collection/mod.rs`) with re-exports, not shadow them. Stage 2 therefore skips those two homes.
- `radar` (L0) is persistence for `radar track`, not a pure primitive.
- `test_support` stays private in `lib.rs` and is listed under `core` for inventory only; Stage 2 shims do **not** re-export it.

## Edges and violations of the proposed graph

Edge inventory: ~1,373 module-level `crate::` edges among the 238 leaf modules (heuristic text scan at `92d5b6151`, `#[cfg(test)]` tails stripped). The root map's CURRENT statement — one upward edge `resolve` (L1) → `lineage` (L5), no cycles — is the test-enforced truth for the current layering. Against the *proposed* graph the heuristic scan finds (bucket sizes at this tip):

| From → to | Edges (approx) | Examples | Stage |
| --- | --- | --- | --- |
| collection → analysis | 61 | collectors → `entity`/`relation`/…; **`wigle → scan_route` is gone** (`wigle` → `network_selector`) | 2/6/7 |
| analysis → collection | 29 | residual L5 collectors still mapped analysis→collection in root | 7 |
| application → cli | 2 | `lookup_modules` → `*_cli` | 3/9 |
| analysis → cli | 8 | `scan_route` / collectors → `*_cli` | 3/9 |
| core → infrastructure / analysis / evidence / collection / application | 10 | `canonical` / `tlsrpt` / `lookup_args` outliers | 2 |
| infrastructure → analysis / collection | 5 | `module_selection` → `module`, … | 2 |
| evidence → analysis | 2 | `resolve` → `lineage` (documented exception) | 2 |
| application → web | 1 | `doctor` → `serve_probe` | 3 |
| collection → cli | 2 | residual | 9 |

Cycles against the *current* L0–L7 layering: **none**. Authoritative: `tests/architecture_doc.rs` (`dependencies_match_the_stated_layering`) and root `ARCHITECTURE.md` (`Dependency cycles: none.`). The heuristic scan above sizes proposed-home cross edges only; it is not a cycle oracle (it also sees same-home mutual uses such as `wifi_radar` ↔ `mitm_guard`).

## Wi-Fi / cell / RF coupling (Stage 2 input)

At `92d5b6151`, `mitm_guard` is on `main` (L6; advisory, evidence-gated Wi-Fi assessment; no packet injection). The radio surface (heuristic `crate::` edges, production sources):

| Module | Proposed home | Uses (notable) | Used by |
| --- | --- | --- | --- |
| `radar` | `core` | `fsio`, `rf` | `wifi_radar`, `web_server` |
| `wifi_radar` | `collection` | `cell_radar`, `rf`, `radar`, `mitm_guard`, … | `web_server`, `mitm_guard` |
| `cell_radar` | `collection` | `rf`, `textnorm`, `error` | `wifi_radar`, `web_server` |
| `rf` | `collection` | `canonical`, `timefmt` | `wifi_radar`, `cell_radar`, `wigle`, `mitm_guard`, `radar` |
| `oui` / `oui_ieee` | `core` | — | `network_cli` |
| `mitm_guard` | `collection` | `rf`, `wifi_radar` | `wifi_radar` (mutual) |
| `wigle` | `collection` | `fetch`, `http`, `keys`, `network_selector`, `rf`, … | `network_cli` |
| `network_selector` | `core` | `canonical` | `wigle`, `scan_route` (re-export) |
| `opencellid` | `collection` | `api_leg`, `indicator_sources`, `keys` | `network_cli` |
| `network_cli` | `cli` | `wigle`, `opencellid`, `oui`, `scan_route`, … | `lookup_modules` |

Stage 2 notes: (1) `wifi_radar → cell_radar` couples two acquisitions; serving-cell placement for `radar track` should move into an `application` coordinator so radio acquisitions are siblings. (2) `radar` (track log) belongs with storage, not `core`. (3) `rf` sighting types are immutable observations and belong in `evidence`. (4) **`wigle → scan_route` is resolved** on this tip (`wigle` → `network_selector`); keep the architecture_boundaries guard. (5) `web_server` still reaches `radar`/`wifi_radar`/`cell_radar` directly; route through `application`. (6) `wifi_radar` ↔ `mitm_guard` is a same-home mutual edge; leave until Stage 6. No BLE work is in scope.

## Stage plan (10 stages)

Every stage is one PR max, preserves the CAPABILITIES table and CURRENT/PLANNED labels in root `ARCHITECTURE.md`, keeps `tests/architecture_doc.rs` green, and claims no verification without a receipt at the exact commit. Facade `pub use` paths in `src/lib.rs` remain until a later explicit deprecation stage.

1. **Stage 1 (inventory in this document).** Inventory, proposed homes, edge/violation list, Wi-Fi/RF coupling notes. Documentation only — no code moves.
2. **Stage 2 (shims on this branch).** Create `src/{core,infrastructure,evidence,application,web}/` with `mod.rs` re-export skeletons; keep every leaf at its current path. **Do not** create `analysis/` or `collection/` directories. Update root map rows only as needed so the five shim modules are placed; add runtime disposition rows for the shims.
3. **Stage 3 — move `core`.** Relocate L0/L3 leaves into `src/core/`; re-export from `lib.rs`; AArch64 cross-build + architecture tests green.
4. **Stage 4 — move `evidence`.** Relocate L1 evidence contracts into `src/evidence/`.
5. **Stage 5 — move `infrastructure`.** Relocate L2 network boundary into `src/infrastructure/` (and later `network/`/`platform/`/`providers/` subdirs); no second HTTP client.
6. **Stage 6 — radio / Wi-Fi decoupling.** Split `wifi_radar`/`cell_radar`; move `radar` track storage out of core; move `rf` toward evidence; stop `web_server` reaching radio modules directly; untangle `wifi_radar` ↔ `mitm_guard`. (`wigle → scan_route` already broken via `network_selector`.) No BLE.
7. **Stage 7 — move `collection`.** Absorb `src/collection.rs` into `src/collection/mod.rs`, then relocate L4/L6 clients plus the network collectors.
8. **Stage 8 — move `analysis`.** Absorb `src/analysis.rs` into `src/analysis/mod.rs`; relocate remaining analysis; fold `mitm_guard` toward `analysis/mitm/` only after the clash fold.
9. **Stage 9 — `application` / `web` / `cli`.** Relocate L7 + serve/API; break `application/analysis → *_cli` edges by lifting shared logic out of CLI adapters.
10. **Stage 10 — enforce proposed graph.** Replace L0–L7 pins with the eight homes; fail CI on upward edges/cycles against the new graph; keep CAPABILITIES matrix unchanged unless improved with exact-revision evidence.

Stages 2–10 each require: architecture_doc + architecture_boundaries green, Android AArch64 cross-build green, key-scan 0 new findings on changed files, 0 review threads, merge with `gh pr merge --merge --match-head-commit`.
