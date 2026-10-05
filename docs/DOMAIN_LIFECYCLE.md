# Domain lifecycle analysis

`domain-lifecycle` compares imported observations offline. It does not search for or purchase expired domains, collect classifications, or infer ownership transfer. Registration availability and ownership remain `unknown`.

```bash
cargo run --locked -- domain-lifecycle analyze docs/domain-lifecycle-example.json --as-of 1000 --output report.json
```

The example contains synthetic DNS observations. It demonstrates the command, not a live finding. Omit `--output` to emit JSON on stdout. Input is limited to 2 MiB and 4096 observations. Outputs use bounded atomic writes, and an existing input file cannot be selected as the output through a path alias. Invalid input produces no report; a failed analysis leaves any previous report untouched.

## Input

The strict envelope has `schema_version: 1`, an exact `domain`, and `observations`. Unknown fields are errors. Each observation requires:

| Field | Meaning |
|---|---|
| `id` | Stable observation identifier; repeated identical rows deduplicate, conflicting duplicate IDs reject the input |
| `host` | Exact domain; case and trailing dots normalize; subdomains and `www` are not collapsed |
| `provider` | Collector/provider identity |
| `upstream` | Shared origin/dataset identity asserted by the importer; not independently authenticated |
| `source_url` | Absolute HTTP(S) provenance URL; no fetching occurs |
| `retrieved_at` | Unix seconds, no later than the explicit `--as-of` time |
| `event_at` | Unix seconds or null; must not follow retrieval; null is retained as a coverage gap |
| `outcome` | `success`, `challenge`, `timeout`, `rate_limited`, `authentication_failure`, `parse_drift`, `unavailable`, or `not_found` |
| `truncated` | Explicit boolean; truncated observations cannot support changes |
| `kind` | `dns`, `content_digest`, `category`, or `registration_status` |
| `scope` | DNS record type, exact content URL, vendor/taxonomy identifier, or registry status scope |
| `value` | Observation value; for DNS, one complete record per line; for content, SHA-256 hex |

DNS supports A, AAAA, NS, MX, TXT and SOA. Sets are sorted and deduplicated; IP addresses normalize, and NS/MX name case and terminal dots normalize. Content scopes must identify the input's exact host. Use separate upstream/scope identities when content extraction, MIME, taxonomy version, or collector representation changes make values incomparable. Content digests represent comparable successful page bytes supplied by the importer, not challenge pages or failed responses.

## Output and limits of interpretation

The report includes a deterministic normalized timeline, evidence-linked change findings, contradictions, coverage gaps and explicit unknown ownership/availability. The normalized timeline is not a byte-for-byte copy of the original input; retain the input for raw provenance.

Comparisons stay within kind, scope and upstream. Failed and truncated observations never support change findings. Values observed at the same event time that disagree create a conflict; the entire affected series is withheld from change analysis rather than selecting a winner. Identical rows from one origin never imply independent corroboration. No confidence score or independent-source count is emitted.

Findings describe infrastructure observations, content digests, classifications or registration statuses changing between two snapshots. They do not prove causality, continuous state between snapshots, semantic repurposing, stale reputation, malicious use, domain purchasability or common ownership. Each finding supplies evidence IDs, alternatives and an invalidation condition. Re-analysis after supporting evidence is removed withdraws dependent changes.

The importer supplies source identity, timestamps and outcome classification. This module validates structure and comparability, not the truth of those assertions. It does not admit findings into the evidence ledger or increase MITRE ATT&CK coverage automatically.

## Verification and next boundary

CLI tests exercise real binary execution, shuffled-input determinism, evidence references, exact-host validation, future dates, duplicate IDs, upstream separation, conflicting states, digest scope, DNS representation equivalence, failed/truncated observations, input preservation, observation bounds and evidence removal.

Live DNS/archive adapters, authoritative RDAP collection, historical ownership evidence, vendor classification collection, semantic page comparison, recurring scheduling and Android runtime validation remain separate work. An offline test is not proof that those collectors work.
