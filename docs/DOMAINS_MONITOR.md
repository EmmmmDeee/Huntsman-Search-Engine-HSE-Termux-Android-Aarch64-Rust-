# Domains-Monitor plain-text feed: offline, evidence-scoped matching

This is an **opt-in** adapter for domain-only lists downloaded separately from
[Domains-Monitor](https://domains-monitor.com/api2/). The provider documents
`/api/v1/TOKEN/get/full/list/text/`,
`/api/v1/TOKEN/get/dailyupdate/list/text/`, and
`/api/v1/TOKEN/get/dailyremove/list/text/`. Here `TOKEN` is a placeholder,
**not** a credential to paste into a public report. An authenticated request
places its actual API token inside the URL **path**. Huntsman deliberately does **not** download that URL
using a generic client: the token must not enter logs, redirects or scan
provenance. No token, billing plan, or new dependency is required for local
matching.

## Invocation

```sh
huntsman-recon domain-feed match full /path/to/domains.txt --as-of 2025-07-06 example.com other.example
huntsman-recon domain-feed match dailyupdate /path/to/dailyupdate.txt --as-of 2026-11-20 example.com
huntsman-recon domain-feed match dailyremove /path/to/dailyremove.txt --as-of 2026-11-20 example.com
# The digest must come from a separately trusted manifest, not the same file:
huntsman-recon domain-feed match full /path/to/domains.txt --as-of 2025-07-06 --expect-sha256 YOUR_64_HEX_DIGIT_HASH example.com
```

Download **plain text**, not a ZIP or gzip archive. Known compressed
signatures are rejected even when the reader exposes one byte at a time, to
avoid misreporting absence. Files with zero valid domain records (including
empty, comment-only and HTML/error-page files) are refused instead of being
treated as negative search results. A UTF-8 byte-order mark is accepted only
at the beginning of the first line, while its original bytes remain in the hash. The `--as-of` date is operator-provided, not obtained or
verified from the file; use the date the provider actually assigns the export.
The tool reads the whole file once with a constant-size row buffer, matches
up to 1,024 deduplicated canonical query domains, and computes SHA-256 over
every original byte (including line endings). A duplicate domain counts as
multiple occurrences but yields one ordered query result. It needs no root,
background daemon or runtime LLM and preserves existing scans and providers.

The JSON output contains `source_claim` and `source_authenticated=false`,
dataset kind, snapshot date, raw-file SHA-256, byte/row counts, per-domain
membership and occurrence counts. A malformed or oversized row is counted,
never silently converted to a domain. `file_parse_complete` describes only
whether all rows in the supplied file were parsed, **not** global coverage.
Matched names have `status="present"`. Unmatched names have
`status="not_observed_in_supplied_file"` only when every row was parsed;
otherwise their status is `"unresolved_due_to_invalid_rows"` and
`listed=null`, because a bad row might contain the missing name. The `listed`
field is `true` for observed membership, `false` only for clean local-file
nonmatches, and `null` when the file cannot establish even a clean nonmatch.
None of those statuses means **unregistered globally**. Lists are not
complete proof of global registration, entity ownership, site activity,
availability or maliciousness. `dailyupdate` and `dailyremove` label the
provider's claimed snapshot events, not a direct registry observation.

For 275–350 million lines, query all relevant names in **one** invocation
to avoid rescanning the multi-gigabyte file. The source file is read-only; no
massive in-RAM index is built and no file is rewritten. The CLI checks the
file's size, modification time and (on Unix/Android) device, inode and change
time before and after reading, detecting many concurrent replacements or
modifications. Those checks are **not** a cryptographic authenticity guarantee.
Use `--expect-sha256 HEX` to compare every original byte against an expected
64-digit SHA-256 digest, supplied by a *separately trusted* source. Uppercase
or lowercase hex is accepted. Invalid digests are rejected at argument parsing;
a digest mismatch is a data error and emits no JSON findings. A digest copied
from the same untrusted download is not an authenticity check.

## Verification and limitations

Run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked domain_feed
cargo test --test domain_feed_cli --locked
```

Regression fixtures cover case-folding, duplicate rows, CRLF and final rows
without newlines, a row longer than 512 bytes split across buffer boundaries,
invalid UTF-8, detailed/URL rows, ZIP and gzip refusal (including one-byte
read buffers), UTF-8 BOM handling, empty/invalid exports, file-parse
uncertainty, SHA-256 manifest matching/mismatch, invalid dates, symlinks and
stdout suppression on errors. The provider is not contacted in these tests.

This adapter does **not** yet implement authenticated API fetch, incremental
checkpointed imports, persistent indexed matching, saved-scan evidence-graph
merge, or a Web UI/API route. Those changes require verifying the provider
response contract, licensing, an owner-supplied API entitlement and a
secret-safe URL-path credential strategy in the shared transport.
