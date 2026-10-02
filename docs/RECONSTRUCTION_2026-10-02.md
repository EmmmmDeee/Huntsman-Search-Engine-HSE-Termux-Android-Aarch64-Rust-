# Reconstruction decision — 2026-10-02

Target, independent of the tree: an unprivileged offline Rust core that records an RCVF session, refuses an unsupported claim, resolves identity only on a shared email or handle, computes geodesic distance and co-location, seals claims in a hashed ledger, and emits STIX and an ATT&CK Navigator layer only from entries that pass the gate.

## Disposition

| Legacy | Decision | Why |
| --- | --- | --- |
| `src/` recorder (huntsman v1) | MIGRATE contract, REIMPLEMENT | Terminate gaps and refuse-to-claim earned survival. Clap CLI and config reader did not; no second consumer. |
| `hse-level1` classifier | MIGRATE invariant | 429 beats a vendor string. A challenge page is Blocked, never a result. JSON quoting a vendor path is not a wall. |
| HSE zip (1730 entries) | PRESERVE as evidence, do not absorb | Different binary, credentials, live providers. D9 stands. |
| SeekNow / see-know.ru keyless | REMOVE from target | NOT APPLICABLE. Paid API. No scrape. |
| Public SearXNG JSON | Not in crate | UNVERIFIED from this egress (403/429). |

## Acceptance executed

`CARGO_TARGET_DIR=/tmp/huntsman-recon-target cargo test` — 13 passed (11 unit, 2 integration).

`cargo run` — Brisbane–Sydney haversine 732379 m inside the 700–760 km band. Navigator techniques=1. SeekNow row excluded.

Workspace mount is noexec for build scripts. That is an environment limit, not a crate defect.

## What this does not show

No Termux aarch64 run. No live harvest. No survey-grade geodesy. No TAXII exchange. Catalog presence is not a score.
