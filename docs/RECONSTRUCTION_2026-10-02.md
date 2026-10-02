# Reconstruction decision — 2026-10-02

Target: an unprivileged offline Rust core that records an RCVF session, refuses an unsupported claim, resolves identity only on a shared email or handle, computes geodesic distance and co-location, seals claims in a hashed ledger, and emits STIX or an ATT&CK Navigator layer only when this crate implements that technique.

Search is local retrieval over operator-supplied documents. Every query term must match. A challenge page or a 429 is not a hit. Paid SeekNow and public SearXNG JSON are not sources.

A verified capability is not a technique score. The binding table is empty. Haversine is not T1591. Challenge classification is not T1592.

## Disposition

| Legacy | Decision | Why |
| --- | --- | --- |
| v1 recorder | MIGRATE contract | Terminate gaps earned survival. Clap CLI did not. |
| Level-1 classifier | MIGRATE invariant | 429 beats a vendor string. A challenge page is Blocked. |
| HSE monolith | REMOVE from current tree | History retained. Credentials and live providers do not earn a place. |
| Self-assigned T1591 layer | REPLACE | Unsupported acceptance. Gate now requires an implemented binding. |
| SeekNow keyless | REMOVE | NOT APPLICABLE. |
| Public SearXNG JSON | Not in crate | UNVERIFIED (403/429). |

## Acceptance

`cargo test` — 17 passed on 2026-10-02 follow-on (15 unit, 2 accept). `huntsman-recon check` — techniques=0, Brisbane–Sydney 732379 m. `geo` prints the same distance. Operator directory search skips non-text and challenge pages.

No Termux run. No live harvest. No survey-grade geodesy. Catalog presence is not a score.
