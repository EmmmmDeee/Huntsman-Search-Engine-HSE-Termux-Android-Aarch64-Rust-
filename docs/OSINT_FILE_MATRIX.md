# Huntsman OSINT file matrix and canonical ownership

This matrix inventories existing Rust paths observed on `main` on 2026-11-03. It defines proposed ownership boundaries, **not** proof that every provider or device capability works. The main branch moves independently; revalidate paths before merging.

## Ownership matrix

| Discipline | Canonical candidates (existing files) | Input / output contract | Verification gate |
| --- | --- | --- | --- |
| GEOINT | `src/geoint.rs`, `src/geohash.rs` | Operator-provided WGS84 points → validated coordinates, great-circle distances and bearings | Dateline, poles, invalid and antipodal fixtures; no invented position |
| HUMINT (public, consent-based) | `src/identity.rs`, `src/identity_resolution.rs` | Publicly attributable statements → separately sourced identity claims | Do not infer identity from username alone; provenance and contradiction tests |
| NETINT | `src/network_selector.rs`, `src/network_cli.rs` | Authorised domains/IPs → bounded network observations | SSRF/egress guard, timeout and cancellation tests |
| Wireless / device | `src/wifi_radar.rs`, `src/cell_radar.rs`, `src/radar.rs` | Permission-gated Android observations → timestamped radio evidence | Missing permission, unsupported hardware, no-root fallback; no exact-location inference from RSSI |
| Search | `src/search.rs`, `src/web_query.rs`, `src/scan_search.rs` | Normalised query → source-specific results | Real live canaries per engine; blocked/empty/error distinguished |
| Provider contracts | `src/source_registry.rs`, `src/source_outcome.rs`, `src/provider_credentials.rs` | Registered capability + scoped credentials → typed outcome | Missing-key, throttling, stale and schema-drift tests; never log secrets |
| Entity pivots | `src/entity.rs`, `src/pivot.rs`, `src/entity_reality.rs` | Source-backed claims → typed, reversible entity edges | False-positive and ambiguous-match regression tests |
| Evidence and lineage | `src/evidence_register.rs`, `src/evidence_ancestry.rs`, `src/evidence/` | Raw observation → immutable source reference, timestamps and verification state | Reproducible hashes, deduplication, conflict and stale-evidence fixtures |
| Cross-INT correlation | `src/orthogonal_osint.rs`, `src/federated_osint.rs` | Independent evidence edges → attributed candidate correlations | Independence checks; correlated copies never count as independent corroboration |
| Public casework | `src/osint_casework.rs`, `src/public_osint.rs` | Authorised case inputs → auditable, exportable results | Data minimisation, redaction controls and access checks |
| API / Web UI | `src/web_server.rs`, `src/web_server/`, `src/web_ui.html` | Canonical application state → local HTTP endpoints and phone-friendly views | Route contract, browser tests, loopback default and bounded payloads |
| CLI | `src/cli/mod.rs`, `src/cli/` | Same application services → structured CLI responses | CLI/API parity and exit-code tests |

## Canonical refactor rules

1. **One authoritative implementation per operation.** Keep provider adapters separate, but route parsing, canonical entity IDs, evidence decisions and output rendering through shared services. Do not delete competing modules until callers and tests are enumerated.
2. **Evidence first.** Persist source URL or source identifier, observed-at timestamp, retrieval status, original content hash, transformation lineage, licence/access restrictions and verification state. Distinguish OBSERVED from CORROBORATED and VERIFIED.
3. **Cross-discipline synergy without unsupported inference.** GEOINT coordinates can correlate with public geotagged events and authorised wireless observations; HUMINT claims may connect to NETINT domain ownership only when independently corroborated. No phone-number-to-GPS or RSSI-to-precise-address claims.
4. **Provider health is not provider coverage.** Record each adapter as CONFIGURED, LIVE_VERIFIED, BLOCKED, RATE_LIMITED, AUTH_REQUIRED, SCHEMA_DRIFT, EMPTY_VALID, FAILED or NOT_TESTED, with last checked time and reproducible evidence. Missing credentials never imply a successful query.
5. **Rootless Android AArch64 is the acceptance platform.** Rust core, Bash orchestration only; no root, runtime LLM or Railway. Limit concurrency, memory, response size, disk retention and retry budgets; use cancellation and SQLite transactional persistence.
6. **Autonomy is bounded and recoverable.** Idempotent scheduling, per-provider backoff, checkpointed jobs, offline queue, watchdog, graceful restart and verified rollback. Never perform intrusive scans or access non-public personal data without authorisation.
7. **One UI state model.** Web UI and CLI must consume the same typed case/evidence/provider state; never maintain parallel truth stores.
8. **Merge discipline.** Rebase against current `main`, check overlapping open PRs, retain review history, run formatting/Clippy/tests, native and cross-target builds, QEMU, browser/API checks, security audit and actual Termux handset acceptance. CI, QEMU, hosted and physical Android are separate evidence classes.

## Priority integration order

P0: preserve existing behavior; fix provider evidence binding, network egress guards, source-outcome truthfulness and bounded execution.

P1: consolidate source registry, canonical entities, evidence lineage, search query contracts and API/CLI parity.

P2: integrate GEOINT and public HUMINT with NETINT and wireless observations through typed, provenance-limited correlation edges.

P3: improve mobile Web UI case graphs, map layers, source-health panels, job controls, audit exports and recovery controls.

## Acceptance record for each merge

Record: canonical main SHA; PR head SHA; changed files; exact CI run IDs; Rust toolchain; host/cross/QEMU/physical handset environment; provider canary timestamps; tests passed/failed; binary hash; rollback point; known gaps. Never report 100% coverage without an exhaustive, timestamped, reproducible inventory.
