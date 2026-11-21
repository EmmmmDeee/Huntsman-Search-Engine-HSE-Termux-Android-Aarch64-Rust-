# Domains-Monitor plain-text feed: offline, evidence-scoped matching

This is an **opt-in** adapter for domain-only lists downloaded separately from
[Domains-Monitor](https://domains-monitor.com/api2/). The provider documents
`get/full/list/text/`, `get/dailyupdate/list/text/`, and
`get/dailyremove/list/text/`. An authenticated request places its API token
inside the URL **path**. Huntsman deliberately does **not** download that URL
using a generic client: the token must not enter logs, redirects or scan
provenance. No token, billing plan, or new dependency is required for local
matching.

## Invocation

```sh
huntsman-recon domain-feed match full /path/to/domains.txt --as-of 2025-07-06 example.com other.example
huntsman-recon domain-feed match dailyupdate /path/to/dailyupdate.txt --as-of 2026-11-20 example.com
huntsman-recon domain-feed match dailyremove /path/to/dailyremove.txt --as-of 2026-11-20 example.com
```

Download **plain text**, not a ZIP archive. An archive is rejected to avoid
misreporting absence. The `--as-of` date is operator-provided, not obtained or
verified from the file; use the date the provider actually assigns the export.
The tool reads the whole file once with a constant-size row buffer, matches
up to 1,024 deduplicated canonical query domains, and computes SHA-256 over
every original byte (including line endings). A duplicate domain counts as
multiple occurrences but yields one ordered query result. It needs no root,
background daemon or runtime LLM and preserves existing scans and providers.

The JSON output contains `source_claim` and `source_authenticated=false`,
dataset kind, snapshot date, raw-file SHA-256, byte/row counts, per-domain
membership and occurrence counts. A malformed or oversized row is counted,
never silently converted to a domain. A missing name means **not observed in
this particular local file**, never **unregistered globally**. Lists are not
complete proof of global registration, entity ownership, site activity,
availability or maliciousness. `dailyupdate` and `dailyremove` label the
provider's claimed snapshot events, not a direct registry observation.

For 275–350 million lines, query all relevant names in **one** invocation
to avoid rescanning the multi-gigabyte file. The source file is read-only; no
massive in-RAM index is built and no file is rewritten.

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
invalid UTF-8, detailed/URL rows, ZIP refusal, invalid dates, symlinks and
stdout suppression on errors. The provider is not contacted in these tests.

This adapter does **not** yet implement authenticated API fetch, incremental
checkpointed imports, persistent indexed matching, saved-scan evidence-graph
merge, or a Web UI/API route. Those changes require verifying the provider
response contract, licensing, an owner-supplied API entitlement and a
secret-safe URL-path credential strategy in the shared transport.
