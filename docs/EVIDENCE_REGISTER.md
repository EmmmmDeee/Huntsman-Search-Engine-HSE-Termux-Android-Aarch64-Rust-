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
