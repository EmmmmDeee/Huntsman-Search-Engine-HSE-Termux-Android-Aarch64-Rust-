# Reconstruction decision — 2026-10-02

Target: an unprivileged offline Rust core that records an RCVF session, refuses an unsupported claim, resolves identity only on a shared email or handle, computes geodesic distance and co-location, seals claims in a hashed ledger, and emits STIX or an ATT&CK Navigator layer only when this crate implements that technique.

Search is local retrieval over operator-supplied documents. Every query term must match. A challenge page or a 429 is not a hit. Paid SeekNow and public SearXNG JSON are not sources.

A verified capability is not a technique score. The binding table is empty. Haversine is not T1591. Challenge classification is not T1592.

## Disposition

| Legacy | Decision | Why |
| --- | --- | --- |
| v1 recorder | MIGRATE contract | Terminate gaps earned survival. Clap CLI did not. |
| Level-1 classifier | MIGRATE invariant | 429 beats a vendor string. A challenge page is Blocked. |
| HSE monolith | REMOVE from current tree | History retained (incl. zip archives at `91f2533`). Credentials and live providers do not earn a place. |
| Self-assigned T1591 layer | REPLACE | Unsupported acceptance. Gate now requires an implemented binding. |
| SeekNow keyless | REMOVE | NOT APPLICABLE. |
| Public SearXNG JSON | Not in crate | UNVERIFIED (403/429). |

## Acceptance

`cargo test` — 17 passed on 2026-10-02 follow-on (15 unit, 2 accept; superseded by the second pass below). `huntsman-recon check` — techniques=0, Brisbane–Sydney 732379 m. `geo` prints the same distance. Operator directory search skips non-text and challenge pages.

No Termux run. No live harvest. No survey-grade geodesy. Catalog presence is not a score.

## Second pass — falsification results

Each fix below started with a test that failed against the previous code.

| Capability | Defect found | Decision |
| --- | --- | --- |
| Ledger hash | The preimage joined fields with `\n`, so `claim="a\nb", source="c"` and `claim="a", source="b\nc"` hashed the same. `None` and `Some("")` technique also hashed the same. | REIMPLEMENT: length-prefixed v2 preimage with the domain tag `huntsman-ledger-v2`. The layout is pinned by a test and cross-checked against Python `hashlib`. v1 ledgers are refused; the only one was the `check` artifact, which `check` regenerates. |
| Store / ledger IO | The store header said "No symlinks" but nothing enforced it. Size was checked through `metadata` and then read separately. Writes were not atomic. | REPLACE with `src/fsio.rs`: refuses symlinks, reads through `take(max+1)`, writes a temp file then renames it. |
| Search | ASCII-only splitting turned `zürich` into `rich`, which produced a false hit. An unreadable directory printed `hits=0`. A repeated query term doubled the score. | REIMPLEMENT: Unicode tokens, `load_dir` returns `Result` with skipped files and reasons, query terms deduplicated. |
| Identity | `x@.` was accepted as an email and merged two people. Links were matched to clusters by id string, so duplicate ids leaked links into the wrong cluster. | REIMPLEMENT: validate domain labels, compute keys once, attribute links by index. |
| GEOINT | `colocated` overflowed `i64` on extreme timestamps. The suspected NaN from haversine at antipodes was falsified: 0 of 5M samples, because `sqrt(1+1ulp)` rounds to 1. | `abs_diff` for time deltas. Clamp `h` only as a guard. |
| Session | An uppercase-hex tip passed the format check but could never satisfy `bound_to`. | Accept lowercase hex only. |
| `var/stix-bundle.json` | Stale: it held a T1591 indicator that the current gate forbids. | `check` now regenerates all three artifacts. Tests require them to match `check` output byte for byte. |
| `recon/` | Duplicate crate that did not compile (it declared modules that do not exist). | REMOVE. |
| Legacy zip archives (7.4 MB) | Contradicted "only current version". | REMOVE from the tree; kept in history at `91f2533`. |

Verification: `cargo test` gives 33 passed (28 unit, 3 accept, 2 CLI). Tests pass on MSRV 1.87 and on stable. `clippy --all-targets -D warnings` with pedantic is clean. `cargo fmt --check` is clean. CI runs all of these and fails if `check` changes `var/`.

Still unresolved: no Termux handset run. The ATT&CK binding table is still empty, so the STIX indicator shape (`malicious-activity`) has never been exercised against a real binding.

## Third pass — zip contents

Both archives were extracted from `91f2533` and judged item by item.

**`Huntsman-Search-Engine-HSE-…-main.zip`** is the HSE v1.41.0 monolith (1727 files, network providers, credential handling, Rust 1.98). It is not restored. It conflicts with this crate's contract of no network client and no paid source, and the overlay's own `VERIFICATION.json` says it was never compiled against it.

**`Huntsman-HSE-EndToEnd-Refactor-feef60a.zip`** is the refactor overlay. Its `VERIFICATION.json` reported cargo, fmt, clippy, and tests as BLOCKED, so none of it had been compiled before this pass. It was imported verbatim first (21 tests passed), then attacked.

| Overlay item | Disposition | Falsification evidence (test failed on the overlay code, passes now) |
| --- | --- | --- |
| `source_outcome` | REIMPLEMENT | A 403 Cloudflare page mapped to `AuthRejected` → `RequireCredential`. Added `classify_fetch(status, body)`, which reuses `classify::is_challenge`; a status-only 403 is `Upstream4xx`. `success(0)` auto-accepted as `ValidZero`; it is now `Inconclusive` and `valid_zero()` must be explicit. A differential test is run against `classify::classify_response`. |
| `evidence_ancestry` | REIMPLEMENT | A diamond DAG was walked exponentially (the test hung). A derived node with no parent was accepted as a root. `"  Adobe   2013 "` and `"ADOBE 2013"` counted as two families. Now an iterative three-colour DFS (200k-deep chain, no stack overflow), `DerivedWithoutParent`, and `canonical_family` (breach-corpus normalisation from patch 0007). A missing parent fails closed. |
| `identity_resolution` | REIMPLEMENT | Two mirrors of one dump labelled with different family strings passed the two-source merge gate. Support is now a list of ancestry node ids. `allows_automatic_merge(&graph, policy)` counts independent root families, is non-compensatory, and fails closed on unknown ancestry. |
| `termination` | REIMPLEMENT | An unused bound hid a true fixed point. Fatal error and cancel win; an empty frontier wins over bounds; delayed retry work is never a fixed point. |
| `credential_origin` | REIMPLEMENT | `fingerprint: String` accepted a raw password, including via serde. Now a `CredentialFingerprint` that holds only 64 lowercase hex (domain-tagged SHA-256, equality key only), with Debug redacted. There is still no conversion to `AuthenticationAuthority`. |
| `eval/` (model, score, stats, verdict, integrity) | MIGRATE + fix | NaN completeness propagated into the score. `+∞` primary gain promoted. Both now hold or zero. `as usize` / `as f64` casts were replaced (32-bit truncation). `integrity` uses the in-tree `sha256`. |
| `architectural_invariants`, `bin/architecture_audit`, patch 0004 | NOT APPLICABLE | Enforce monolith directory layout (`src/core`, `src/modules`) that does not exist here. CI clippy `-D warnings` plus tests are this crate's invariant gate. |
| `cli/update.rs`, patch 0001 (self-update) | REMOVE | Network self-update contradicts the no-network contract. |
| Patches 0003 (core registration), 0006 (LeakBase HTML import), 0008 (Termux artifact CI) | NOT APPLICABLE | Target files exist only in the monolith. |
| Patch 0007 | PARTIAL | Only the breach-corpus canonicalisation was adopted (`canonical_family`). |
| `revalidation-required/` 0100, 0110, 0140, `superseded-reference` | NOT ADOPTED | The overlay itself marks them do-not-batch-promote. The 5 % geo cap is unvalidated. Superseded by definition. |

`check` gate 5 holds the integrated contract: a 403 challenge is `BotWaf` and never demands credentials; two mirrors of one dump cannot auto-merge, while two independent roots can; delayed retry work is not a fixed point.
