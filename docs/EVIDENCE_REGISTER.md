# HUNTSMAN evidence register — source-preserving and delta-first

The register is derived from the existing saved scan. It does not create another database, make HTTP calls on export, or promote self-reported information into verified facts.

## CLI

~~~sh
huntsman-recon scans run example.org -k domain --json
huntsman-recon scans evidence SCAN_ID -f raw -o evidence.txt
huntsman-recon scans evidence SCAN_ID --json -o evidence.json
huntsman-recon scans evidence LATER_ID --delta EARLIER_ID -f raw -o delta.txt
~~~

## Web API

~~~http
GET /api/scans/SCAN_ID/evidence?format=raw
GET /api/scans/SCAN_ID/evidence?format=json
GET /api/scans/LATER_ID/evidence?baseline=EARLIER_ID&format=json
~~~

The CLI and embedded Web API share one deterministic Rust evidence implementation, with no new runtime dependency or embedded LLM. The API only reads stopped scans whose results were saved. Comparison requires equal target and lookup kind. Exported files use the existing private atomic writer.

## Evidence and delta rules

- Retain entire saved entities, source execution outcomes, SpiderFoot elements, correlations, lineage and termination reasons. This is not a substitute for camera originals or raw HTTP bodies not collected by upstream providers.
- Record identifiers are SHA-256-derived from type and stable keys; repeated provider executions use module plus ordinal.
- Record links are bidirectional where an explicit parent/element/entity/correlation reference resolves. Never invent a personal identity link from similarity.
- FULL_REGISTER includes all records without a baseline.
- Added, removed and changed retain their complete corresponding raw record. Removed records come from the baseline.
- Reobserved means the only differences are per-run bookkeeping fields: scan_id, created, observed_at_unix or recorded_at_unix. All original field values remain in RAW_DATA.
- Unchanged means identical serialized raw data; unchanged records are counted but omitted in baseline/delta mode.
- NO_MATERIAL_CHANGE does not establish source correctness or freshness.
- Explicit false-positive markings are preserved, not suppressed.
- Reported source and confidence fields must not be treated as independent corroboration.

## Evidence limits and integrity

- Every emitted raw record includes its full original stored JSON and a raw-data SHA-256.
- Missing source URLs, retrieval dates, independent proofs, and relationships remain absent, never invented.
- Limit 4,096 records per scan and 8 MiB of report output. Any over-limit condition fails without partial output or silent truncation. Original saved scans are unaffected.
- Export is offline; run a new normal scan to obtain newer observations. No background polling is implied.
- The existing Web API bind/authentication policies still apply. Sensitive scans should remain on loopback or use an appropriate authentication token.
- This initial integration does not add universal crawling, remote image fetching, or autonomous scheduling; it builds directly on the provider sources already supported by Huntsman.

## Verification

Review CI before merging. Required checks include formatting, Rust tests, clippy where enabled and Termux AArch64 build checks. Do not equate an open pull request or pending check with a verified release.

## Sparse source-by-finding matrix

Use the same saved evidence elements as the evidence register. No live calls,
additional database, inference model or runtime LLM is involved.

~~~sh
huntsman-recon scans matrix SCAN_ID -f raw -o matrix.txt
huntsman-recon scans matrix SCAN_ID --json -o matrix.json
~~~

~~~http
GET /api/scans/SCAN_ID/matrix?format=json
GET /api/scans/SCAN_ID/matrix?format=raw
~~~

The Scan page's Evidence menu exports Matrix JSON and Matrix TXT.

The matrix is sparse: rows are exact (type, value) pairs, columns are the
module labels saved on source elements, cells contain explicit element IDs,
observed counts and operator false-positive counts. Rows are ordered
deterministically; record IDs are stable SHA-256-derived keys. Mixed
false-positive markings are surfaced, not interpreted as factual conflict.
Modules with recorded executions but no saved element rows remain visible
as a coverage gap, not proof that no results exist.

Important: different module labels do not establish independent upstream
sources, and matching value strings never establish personal identity.
Original source claims, upstream verification, timestamps, and independent
corroboration cannot be inferred from mere record counts.

Inputs are bounded to 4,096 evidence elements; exported outputs are bounded
to 8 MiB and fail rather than silently truncate. This is an offline analysis
over stopped, saved scans; fresh findings still require a normal scan.

### Lossless normalization and terminal-safe raw exports

The primary matrix axis is **still exact** (type, original value). For ASCII
`DOMAIN_NAME` and `INTERNET_NAME` only, an additional comparison candidate
lowercases ASCII letters and removes one optional terminal DNS root dot.
Entries with the same comparison candidate are cross-referenced under
`normalization_candidates` with their original exact values and stable record
IDs. Candidates are not merged, authenticated, or asserted to be equivalent.
Other types (including personal names, email local parts, Unicode domain
strings, IP addresses and free text) remain entirely untouched.

`ROOT` repeats the scan target and is not a source finding. Such entries
remain in the original evidence register and saved scan, but are explicitly
counted as `root_elements_excluded_from_matrix`; `matrix_elements` counts the
non-root elements. `recorded_elements = matrix_elements +
root_elements_excluded_from_matrix`.

The raw TXT export includes normalization cross-references and retains
machine-readable JSON for each exact observation. Unsafe Unicode controls
(including bidi overrides) are escaped without changing the decoded JSON
values, preventing a provider-supplied value from misleading terminal display.
No new network calls, data migrations, credentials or dependencies are needed.
