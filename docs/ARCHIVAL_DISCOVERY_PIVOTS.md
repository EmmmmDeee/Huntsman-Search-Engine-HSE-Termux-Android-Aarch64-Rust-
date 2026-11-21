# Provenance-gated archival and legal discovery pivots

This addition extends the **existing** `source_registry::routes_for` authority. Its URLs are discoverable through existing planning and CLI discovery flows; no new HTTP client, Web UI endpoint, runtime dependency, collector or paid API call is introduced.

## Added source families

| ID | Official reference | Discovery mode |
| --- | --- | --- |
| `au_qld_bdm_history` | https://www.familyhistory.bdm.qld.gov.au/ | Public indexed lead |
| `au_qld_archives` | https://www.qld.gov.au/recreation/arts/heritage/archives/ways-to-search/search-the-archivessearch-catalogue | Public indexed lead |
| `au_slq_history` | https://www.slq.qld.gov.au/collections/family-history/family-history-eresources-and-indexes | Public indexed lead |
| `au_naa_namesearch` | https://www.naa.gov.au/help-your-research/getting-started/recordsearch-overview/namesearch | Public indexed lead |
| `au_austlii` | https://www.austlii.edu.au/ | Public indexed lead |
| `uk_tna_discovery` | https://discovery.nationalarchives.gov.uk/ | Public indexed lead |
| `global_familysearch_index` | https://www.familysearch.org/ | Account-gated indexed lead |

The UK National Archives catalogue uses its documented `_q` query parameter; the other links use *public search-engine site restrictions*, not undocumented archive endpoints. A search result is only an unverified lead. Absence of an indexed result does not establish absence of a registration, archive item, legal case, or descendant. The official reference URL is retained separately to allow direct manual catalogue searching.

## API extension contracts

- **FamilySearch**: official developer portal https://developers.familysearch.org/ and https://developers.familysearch.org/main/docs/getting-started. API calls require an app key and appropriate OAuth authorization. Do not infer that the public index route authorizes collection of living-person records, and never put an access token in search URLs or Git.
- **UK National Archives Discovery**: official API documentation https://discovery.nationalarchives.gov.uk/API/Help. This change uses its public catalogue UI, **not** untested API calls. A future API collector must reuse Huntsman's `Transport`, `fetch`, `SourceExecutionOutcome` and evidence ancestry contracts.
- **Queensland historical BDM**: official historical-search guide https://www.qld.gov.au/family/family-history-research/guide. The registry is a human-accessible historical index, not an assumed unauthenticated API.

## Safety and acceptance

- No plaintext secrets, breach queries or inferred family edges are emitted.
- Control characters and raw inputs over 512 UTF-8 bytes are refused **before trim**.
- Archive pivots accept only `Person` and `Organisation`; not `Credential`, `ApiKey`, `DeviceId`, email, username or infrastructure selectors.
- `EvidenceRole::LeadOnly` is mandatory; index repetition never constitutes independent corroboration.
- Offline acceptance: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --test source_registry_archival_pivots --locked`, `cargo test --workspace --locked`, exact-head Android AArch64 and Web UI checks.
- No physical Termux device acceptance or live archive query has been performed by this patch.
