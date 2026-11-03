# Huntsman — canonical OSINT source-file matrix

## Immutable baseline
Git tree **0f3a306a7c664c5f39c781da5d1f0870b8ba3287**, **1460** entries, **1360** files, non-truncated. These are source-tree facts, NOT a live provider audit. The TSV is a snapshot of the tree **before** this change; new/updated files are not included until inventory regeneration.

- [Every repository file with Git blob SHA, byte count and heuristic discipline](OSINT_FILE_MATRIX.tsv)
- [15 canonical discipline mappings and cross-pivots](OSINT_DISCIPLINE_MATRIX.json)

## Canonical ownership
| Discipline | Priority | Canonical owner | Adjacent intelligence |
|---|---|---|---|
| GEOINT | focus | `src/geoint.rs` | NETINT / DOCINT / IMINT |
| HUMINT | focus | `src/osint_casework.rs` | SOCMINT / DOCINT / GEOINT |
| NETINT | focus | `src/network_cli.rs` | GEOINT / CYBINT |
| SOCMINT | standard | `src/public_osint.rs` | HUMINT / WEBINT |
| IMINT | standard | `src/exif.rs` | GEOINT / DOCINT |
| SIGINT | standard | `src/wifi_radar.rs` | NETINT / GEOINT |
| CYBINT | standard | `src/indicator_sources.rs` | NETINT / TECHINT |
| WEBINT | standard | `src/search.rs` | SOCMINT / DOCINT |
| DOCINT | standard | `src/docmeta.rs` | HUMINT / GEOINT |
| FININT | standard | `src/blockchain.rs` | NETINT / DOCINT |
| TECHINT | standard | `src/source_intel.rs` | NETINT / CYBINT |
| IDINT | standard | `src/identity_resolution.rs` | HUMINT / EVIDENCE |
| EVIDENCE | critical | `src/evidence_register.rs` | GEOINT / HUMINT / NETINT |
| ORTHOGONAL | critical | `src/orthogonal_osint.rs` | EVIDENCE / NETINT |
| WEBUI | critical | `src/web_server.rs` | EVIDENCE / ORTHOGONAL |

## Consolidation contract
- **One evidence truth:** Keep `evidence_register` and `evidence_register/matrix` as source-by-finding evidence authorities; `evidence_ancestry` alone evaluates independence.
- **One modality-gap authority:** Keep `orthogonal_osint`; its suggestions are not executed lookups or proof of coverage.
- **One place authority:** `geoint` interprets operator-supplied/public locations only; neither IP addresses nor radio strength prove an individual's whereabouts.
- **One HUMINT lead owner:** `osint_casework` for attributed public sources and consented statements, carrying capture date, source URL and uncertainty.
- **One network metadata gateway:** `network_cli`, then canonical `rdap`, `dns`, `asn_cli`. Do not bypass existing guardrails.
- **One UI route:** `GET /api/osint/matrix`, static and read-only; existing bearer/Host protections apply. Browser fetches on explicit request.
- **No runtime LLM, no root, no new dependencies.** No automatic provider calls or scans have been added by this matrix.
- **No person-tracking escalation:** identity and location assertions require lawful, independent, documented corroboration; no covert HUMINT or private-person whereabouts inference.

## Verification acceptance
```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
curl -fsS http://127.0.0.1:8080/api/osint/matrix
```
CI success is not equivalent to an on-device Termux AArch64 run. The file matrix makes no claim of autonomous end-to-end live collection. All dynamic collection remains governed by existing modules, operator authorisation, keys, budgets and rate limits.
