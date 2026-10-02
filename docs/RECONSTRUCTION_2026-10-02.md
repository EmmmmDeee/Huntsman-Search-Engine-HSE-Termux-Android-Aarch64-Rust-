# Reconstruction decision — 2026-10-02

Passes are recorded in order; a later pass supersedes an earlier one. In particular, the seventh pass reversed the second: the legacy zip archives are back in the repository root and extracted into `legacy/`, and network access is allowed through the guarded `egress`/`http`/`fetch`/`keys` layer.

Target: an unprivileged Rust core that records an RCVF session, refuses an unsupported claim, resolves identity only on a shared email or handle, computes geodesic distance and co-location, seals claims in a hashed ledger, and emits STIX or an ATT&CK Navigator layer only when this crate implements that technique.

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

**`Huntsman-Search-Engine-HSE-…-main.zip`** is the HSE v1.41.0 monolith (1727 files, network providers, credential handling, Rust 1.98). It is not restored. It conflicts with this crate's contract of no paid source, and the overlay's own `VERIFICATION.json` says it was never compiled against it.

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

## Fourth pass — falsification results

Each fix started with a test that failed on the previous code (or a CLI reproduction, for the first row).

| Capability | Defect found | Decision |
| --- | --- | --- |
| Classifier | `looks_like_document` sliced the body at a byte offset. A body that starts with `{` or `[`, carries a vendor string, and has a multibyte character spanning byte 5, 6 or 14 panicked. `search DIR` crashed on such an operator file (`{"éé":"datadome"}`). | REIMPLEMENT: compare bytes through `get(..n)`. |
| Search CLI | A query with no searchable term (`""`, `a`, `- !`) printed `hits=0`, the same class of lie as the unreadable directory. | Exit 64 with a message. |
| Search loader | `NOTES.TXT` and `NOTES.MD` were skipped without a word. | Extension match is case-insensitive. |
| Technique id | `T1595.` (trailing dot) and five-digit ids passed `valid_technique`. ATT&CK enterprise ids are `T` plus exactly four digits. | REIMPLEMENT: strict shape. |
| Session | A partial terminate stored any string as the ledger tip, and `bound_to` then accepted it. | A partial tip is empty or a lowercase 64-hex hash. |
| STIX / Navigator | The exporters had never run, because the binding table is empty. The STIX pattern dropped single quotes and left backslashes raw, so a trailing backslash broke the pattern. | `bundle_with` / `layer_with` / `admits_interop_with` take an explicit table. Tests exercise a bound entry: UUID shape, version and variant nibbles, escaping. Production still uses the empty table. |

Verification: `cargo test` gives 71 unit, 3 accept, 4 CLI, all passing. `clippy --all-targets -D warnings` and `cargo fmt --check` are clean. `check` leaves `var/` unchanged.

Still unresolved: no Termux handset run. The binding table is still empty, so no technique is claimed. Handle-only identity merging in `identity::resolve` ignores platform scope: the same handle on two platforms merges. That is the documented contract, and the ancestry-aware gate in `identity_resolution` is the stricter path. It was not changed here.

## Fifth pass — overlay modules

Each fix started with a test that failed on the previous code.

| Capability | Defect found | Decision |
| --- | --- | --- |
| `evidence_ancestry` | The graph derived `Deserialize`, so a stored graph skipped `insert`. A parentless derivation, an empty family, or a map key that differs from the node id loaded, and the parentless derivation counted as a root family (`""`). | REIMPLEMENT: deserialisation goes through `insert` and checks key against id. Serialised shape is unchanged. |
| `eval::decide` | A negative `cost_ratio` passed the `<= max_cost_ratio` gate, so a nonsense measurement could promote. | Negative cost ratio is `Hold`. |

Falsified, no change: `sha256` matches Python `hashlib` for every length 0..300. Cluster pair scoring is order-independent because members are a sorted set. Non-finite policy thresholds fail safe (`Repair` or `Hold`, never `Promote`).

Verification: 73 unit, 3 accept, 4 CLI tests pass; clippy `-D warnings` and `cargo fmt --check` are clean; `check` leaves `var/` unchanged.

## Sixth pass — monolith utilities rebuilt

The third pass judged the monolith zip as a whole and did not restore it. This pass goes file by file for the pure, offline parts that fit the contract (no network, no credentials, no I/O). Each was read from `91f2533`, then rebuilt rather than copied. Legacy tests and doc examples are kept as a differential oracle; where the legacy behaviour was wrong, the test says so.

| Legacy file | New module | Decision | Defect found in legacy, and evidence |
| --- | --- | --- | --- |
| `util/abn`, `util/bsb` | `au_id` | REIMPLEMENT | Every non-digit byte was ignored, so `5182 hello 4753556` validated as an ABN and `0 6 2 hello 000` as a BSB. Now only single spaces or hyphens between digits. Property test: every single-digit error in 400 generated valid ABNs is caught (mod-89 weights are coprime to 89). The ACN check digit is shown to have a blind spot (weight 5, change of 2), so a valid ACN is weaker evidence. |
| `util/geohash/encode` | `geohash` | REIMPLEMENT | Precision was clamped silently (0 became 1, 99 became 12) and there was no decoder. Now an error, plus `decode`. Properties: every hash round-trips through its cell centre, cells nest by prefix, corners stay inside their cell. Reference vectors were cross-checked against an independent Python encoder; my first hand-written vector was wrong and the cross-check caught it. |
| `hse-core` `c_effective`, `Classification` | `confidence` | REIMPLEMENT | The doubt kept per extra source was a fixed 0.65, so five independent sources of confidence 0.05 reached 0.83 (Verified), and a zero-confidence claim also reached it. Doubt now shrinks no faster than the source's own doubt (`max(0.65, 1 - C)`). Differential test over a 1000 x 40 grid: identical to legacy for `C >= 0.35`, never more generous below. Also `n` can come from `evidence_ancestry` root families, so mirrors count once. NaN is 0. Depth decay refuses a base above 1. |
| `util/redact` | `redact` | REIMPLEMENT | Secrets were replaced one at a time, so a secret inside a longer one left the longer half exposed, partly overlapping secrets left tails, and a secret equal to part of the mask re-matched. Now one pass over the original text, overlapping and touching spans merged. Coordinates are range-checked (legacy accepted `999,999`). |

New CLI: `id TOKEN`, `geohash LAT,LON [PRECISION]`, `coarsen LAT,LON`. `check` gate 10 exercises all four modules.

Not rebuilt, with reason: `util/http`, `util/curl*`, `util/preflight`, `core/engine`, and all of `src/modules` need a network client or credentials. `util/domains` (registrable domain) and `core/validation` are the next pure candidates; `domains` needs a public-suffix decision that has not been made. `postcode_au` centroid tables are bulk data with no provenance in the zip.

Verification: 103 unit, 3 accept, 5 CLI tests pass on stable and on MSRV 1.87. `clippy --all-targets -D warnings` and `cargo fmt --check` are clean. `check` leaves `var/` unchanged.

## Seventh pass: contract change and consolidation

- The offline, no-credentials restriction is lifted. Network access is allowed through one guarded layer: `egress` (public addresses only unless the operator opts out), `http` (bounded, rustls, `Transport` trait), `fetch` (manual redirects; credentials never leave the origin they were approved for), `keys` (placeholders are not keys; values never printed). `check` gate 11 decides these rules without a socket.
- Both legacy archives are permanent reference: kept in the repository root and extracted byte-identically into `legacy/`; `tests/legacy_reference.rs` pins their hashes and file counts.
- Parallel rebuilds merged duplicated helpers into single owners (canonical forms, domains, dates, coordinates, module metadata). Per-file accounting: `docs/DISPOSITIONS.md`.
- Not finished: remaining legacy `core/correlator` and `core/relation` files (see dispositions), and `modules/*` network providers.

## Eighth pass: CI and repository organisation

- `main` CI failed on `test (stable)`: Rust 1.99 clippy added `assert_is_empty`, which rejects 39 bare `assert!(x.is_empty())` / `assert!(!x.is_empty())` test assertions under `-D warnings`. Each now prints the offending value (or context) on failure. Clean on Rust 1.99, 1.98 and MSRV 1.87.
- `README.md` said the archives lived only in git history; it now matches the seventh pass and maps the tree.
- `docs/DISPOSITIONS.md` is one document with one section per area. The entity section was a work log; it is replaced by the per-file table formerly in `docs/dispositions/entity.md` (now removed), with the missing `core/correlator/rules/location/mod.rs` row added. The intro claimed every legacy file was accounted for; 895 of 1146 monolith `src/` files are not, and a new section counts them by area (first published as 894; see the ninth pass).
- Initial PR review found #663 empty and #665 targeting the retired release workflow. The owner subsequently continued #662 with REFACTOR: its HIBP library is now ported to `src/hibp` on the blocking `http`/`fetch`/`keys` boundary, explicitly opt-in, without restoring the monolith. The old decision to close #662 is superseded. Legacy snapshots and root archives remain unchanged.

## Ninth pass: proof paths for documentation claims

Documentation is a set of claims. Until this pass, nothing tied the README or the disposition counts to an observation. Falsifying them found three that were wrong:

| Claim | Defeating observation | Decision |
| --- | --- | --- |
| README: "`check` uses 2–10 for its individual gates" | `src/main.rs` also has gate 11 (egress, origin, placeholder, URL redaction) | Now 2–11. Gate 11 is described next to the fetch layer. |
| README exit codes: 64, 65, 66, 74 | `fetch` exits 69 with no response (closed local port) and 77 when the egress policy refuses (`127.0.0.1`) | Now documented. |
| DISPOSITIONS: 894 unlisted, `util` 115 | The eighth-pass count used substring matching, so `util/mod.rs` matched other paths. Matching on the first table cell gives 895 and 116. | Now 895 and 116. |

New proof paths. Each test was run against the documents before the fix and failed on exactly the claims above. Each was then mutation-checked: 8 of 8 document mutations fail the build (dropped or broken example, invented or dropped exit code, wrong gate range, absent or dropped legacy row, wrong total).

- `tests/readme.rs`: runs every README example in a scratch directory (all except the internet `fetch`) and requires exit 0 with output. README examples and CLI usage must name the same commands, in both directions. Each documented exit code has an offline scenario that produces it, and the documented codes must equal the `EX_*` constants. The gate range must equal the `gate(N, …)` codes in `src/main.rs`.
- `tests/dispositions.rs`: every legacy row names a file that exists in `legacy/`. The "Not yet dispositioned" table and total are recomputed from `legacy/`.

Evidence state of the claims touched in passes eight and nine:

| Claim | State | Evidence and its limit |
| --- | --- | --- |
| Rust 1.99 clippy lints fixed | LIVE-OBSERVED on the branch | CI runs 36992324680 and 36992599045 green (1.87 + stable). Not yet observed on `main`: that needs a merge. Valid until the next stable clippy adds a lint. |
| README examples run | TESTED, CI-enforced | `tests/readme.rs`. The internet `fetch` example is not run; the fetch layer is proven against a local server in `tests/http_local.rs`. |
| Documented exit codes are produced | TESTED, CI-enforced | One offline scenario per code. |
| `check` gate failure codes 2–11 | IMPLEMENTED, range TESTED | The range matches the source. No test injects a fault to observe each gate's failure exit. |
| Disposition counts | TESTED, CI-enforced | Recomputed from `legacy/` on every test run. |
| HIBP #662 reconstructed-layout port | OFFLINE-VERIFIED | `src/hibp` exports blocking REST v3, free password ranges and OAuth PKCE; fake-transport tests cover endpoints, plan gating, retry, secret redaction and private persistence. No live API or handset acceptance is claimed. Earlier close-#662 judgement is superseded by the owner's REFACTOR continuation. |
| No Termux/aarch64 handset run | Unchanged: not CLAIMED | — |
