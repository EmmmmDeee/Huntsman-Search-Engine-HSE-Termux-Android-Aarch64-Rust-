# HUNTSMAN — OSINT file ownership and capability matrix

The matrix is compiled into `huntsman-recon` from `src/osint_matrix.rs`. It has no separate file
to keep in step.

| Surface | What it gives |
|---|---|
| `huntsman-recon osint matrix` | One line per capability group: priority, id, discipline, mode, implementation status, its owner files and `modules=` the reachable modules in it. |
| `huntsman-recon osint matrix --json` and `GET /api/osint/matrix` | Every group in full, with its inputs, outputs, synergies, limitation and modules, and the counts. |

**What keeps it true.** The tests in `src/osint_matrix.rs` check that:
- every file a group names exists, and the group's owner file is among them;
- every synergy names a group;
- every reachable module (`module::reachable_modules`, the list `/api/modules` and the web UI
  show) sits in exactly one group, and every module a group names is reachable.

A module added without a group fails those tests, as does a group naming a module that is gone.

`implementation` is source-code status, never a runtime or availability observation.

## Canonical interfaces: one implementation, multiple surfaces

| Discipline | Primary Rust file owners | Synergy and evidence contract | Existing surface |
|---|---|---|---|
| GEOINT | `src/geoint.rs`, `src/geohash.rs`, `src/nominatim.rs`, `src/stac.rs`, `src/opensky.rs` | A dated point, scene footprint, aircraft or public address is contextual geography, never proof of someone's presence. | Place lookup, Web UI, saved-scan analysis |
| NETINT | `src/dns.rs`, `src/rdap.rs`, `src/ripestat.rs`, `src/network_selector.rs` | Public DNS, RDAP, BGP and regional infrastructure estimates can corroborate domain/network *facts*, not the subscriber or operator's whereabouts. | Network lookup, evidence graph |
| Public HUMINT | `src/identity_resolution.rs`, `src/username_cli.rs`, `src/osint_casework.rs` | Attribution requires explicit published cross-links; no pretexting, private messages, namesake merges or unconsented elicitation. | Username, person, case and analysis interfaces |
| RF environment | `src/wifi_radar.rs`, `src/cell_radar.rs`, `src/opencellid.rs` | Only consented snapshots with sample time, provenance and uncertainty; never assumed live device tracking. | Existing radar CLI/Web UI |
| Archives/search | `src/archived_page.rs`, `src/common_crawl.rs`, `src/web_query.rs` | Publication/capture timestamps and source URL; absent search result means unknown. | Public-source CLI/Web UI |
| Evidence fusion | `src/orthogonal_osint.rs`, `src/evidence_ancestry.rs`, `src/analysis.rs` | The ancestry graph exclusively assesses independent support; modality counts cannot do so. | `report.orthogonal` already rendered by Analysis panel |
| Rhinser | `src/rhinser_native.rs`, `src/rhinser_catalog.rs`, `src/rhinser_workspace.rs` | Operator-supplied offline captures and catalogue leads are not proof of live hardware access. | Existing OSINT CLI/Web UI |

## Consolidation policy

1. Reuse `orthogonal_osint::discover` and `analysis::analyze_snapshot`; do not create a second intelligence planner.
2. New GEOINT and public HUMINT proposals are **read-only**, deterministic and bounded to `MAX_OPPORTUNITIES`; they never make extra network calls or promote claims.
3. Keep `huntsman-recon` as the single canonical pure-Rust runtime, with no root, new dependency or runtime LLM on Android AArch64 Termux.
4. Existing Web UI's Analysis tab reads the same serialized `orthogonal` report; no additional endpoints, unguarded network access, or duplicate HTML client state are required.
5. For complete autonomy, only approved workloads may execute through existing bounded collectors, budgets, timeouts, state checkpoints, failure isolation and termination gates. Proposals alone are not executed scans.
6. Do not confuse a group's file or module list with tested functionality, an enabled API credential, or verified source observations.

## Acceptance gates

- `cargo fmt --all -- --check`
- `cargo test --locked --test orthogonal_osint`
- `cargo run --locked -p xtask -- gate full`
- GitHub Actions Android AArch64 cross-build, QEMU library tests, Web UI/browser, CodeQL and RustSec
- Real unprivileged Termux handset operation is a separate unverified gate until performed.
