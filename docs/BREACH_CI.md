# Breach-led OSINT candidate planning and Confidence Index

This is a **local, offline planner and evidence-metadata ranker**. It does not make breach API calls, read stolen credential values, infer that lookalike identities are one person, or verify source records. Run only on your accounts, verified owned domains, or another explicitly authorised investigation.

## Commands

```sh
huntsman-recon breach-ci plan email alice@example.org --purpose own-account
huntsman-recon breach-ci plan username John.Doe --purpose authorized-engagement
huntsman-recon breach-ci plan name "Jane Mary Smith" --purpose authorized-engagement
huntsman-recon breach-ci names reviewed-names.txt --purpose authorized-engagement
huntsman-recon breach-ci plan domain example.org --purpose authorized-engagement
huntsman-recon breach-ci rank findings.json
huntsman-recon breach-ci enrich recursive-report.json
```

The planning commands generate bounded source-check proposals sorted by **investigative priority**. Full-name planning accepts one complete name or every unique name in a local UTF-8 file (up to 128 full names and 16 KiB); blank lines and comments are ignored, and case-insensitive duplicates collapse without merging actual people. Name plans use Huntsman's shared full-name validator, preserve given first/middle/last name tokens, and emit public name-discovery routes only. They **do not** submit names to breach providers, derive email addresses or handles, or assign breach findings to namesakes. A reviewed name still requires independently verified exact identifiers before any authorised breach API lookup. Username variants are further prioritised using bounded, allocation-free, case-insensitive Levenshtein distance (up to 64 bytes); this rank is a search-order heuristic, not identity confidence. They return `confidence_index: null`, `state: not_queried`. This is deliberate: a source not queried cannot establish a finding or CI score. The planner uses the existing DeHashed selector validation, avoids wildcards and multi-field sweeps, and uses `username_variants::variants` for at most 12 deterministic username variants. Each variant must still pass DeHashed's exact-selector rules. Email local parts are **not** mutated. A domain is **not** expanded to guessed personal accounts.

For actual authorised searches, use the existing `huntsman-recon exposure ADDRESS` or `huntsman-recon dehashed search --email|--username|--domain VALUE --purpose PURPOSE` paths, honouring credentials, credits, egress controls and provider terms. The exposure command already folds configured breach providers into one query chain; do not run duplicated paid provider queries merely because a plan lists several sources.

## Conditional OSINT synergy

An exact email breach observation may justify examining source breach-incident metadata and independently verified public ownership or infrastructure records. A username observation may justify checking a public account at its **exact observed** profile URL. A domain observation may justify DNS/MX, certificate transparency, RDAP, Wayback and passive-DNS research. None of these independently proves that a named individual owns an account. More providers copying the same leaked dataset must not be counted as multiple independent observations.

The planner's source order is a conditional **search priority**, not an empirically established hit probability. Authorised API availability, subscription restrictions, data provenance, and provider terms can change the usable source order.

## Ranked evidence: JSON input

```json
[
  {
    "id": "case-a",
    "exact_identifier": true,
    "fuzzy_match": false,
    "primary_record": true,
    "original_dataset_ids": ["dataset-root-a", "dataset-root-b"],
    "temporal_consistency": true,
    "contradicted": false
  },
  {
    "id": "case-b",
    "exact_identifier": false,
    "fuzzy_match": true,
    "primary_record": false,
    "original_dataset_ids": ["dataset-root-a"],
    "temporal_consistency": false,
    "contradicted": true
  }
]
```

Only **opaque case IDs** and **opaque original-dataset lineage IDs** are accepted, never emails, names, passwords, password hashes, phone numbers, addresses or raw breached records. Source ancestry must be manually reviewed before inclusion; a source label is not proof of independence. Input is a regular file of at most 256 KiB; at most 128 findings with up to eight original-lineage ID entries per finding. The command rejects duplicate case IDs and unknown JSON fields.

The **CI** is an intentionally uncalibrated ordinal evidence-quality heuristic, **not a probability or verification verdict**:

- Exact identifier 35 points; otherwise 12.
- Original primary record 22; otherwise 8.
- Each extra distinct, operator-attested original dataset root adds 9, at most three extras.
- Coherent source-reported temporal evidence adds 10.
- Contradiction subtracts 30 and caps the score at 39.
- Fuzzy/ambiguous matching caps CI at 55.
- Secondary-only observations cap CI at 70.

The maximum achievable score is 94, but **no score automatically upgrades the evidence state**. Source-root independence, authenticity, recency and identity cannot be proved from this metadata alone. All ranked results explicitly report `operator_asserted_not_independently_verified`. CI ordering is descending; ties are broken by opaque ID to guarantee reproducibility.

## Known-only recursive enrichment

The **offline** breach-ci enrich RECURSIVE_REPORT.json command accepts a complete
JSON document from huntsman-recon scan --recurse ... --json, bounded to
1 MiB, 1,024 entities, 4,096 lineage edges and 64 accepted seeds.
It does **not** launch another scan or call any breach or OSINT API.

An exact public domain, publicly routable IP, ASN or netblock becomes a
*follow-up candidate* only if it appears in the existing report and has
at least one non-inferred source-specific observation. Operator echoes,
synthetic/derived sources and breach-collector observations do not qualify.
Name-search leads are never expanded, even when they contain domains.
No personal name, residential address, phone, email, username or leaked
identifier is automatically followed.

The planner excludes identifiers already present among accepted seeds or
lookup origins of recorded lineage edges. **Zero-hit dispatched lookups
may not appear in lineage**; review the execution log before rerunning.
Candidates are deduplicated, deterministically ordered and limited to 128.
The output carries a truncation flag inherited from the input.

Follow-up **priority**, not CI: domain 95, IP 80, ASN 70, netblock 60.
These numbers are not confidence scores, breach-hit probabilities or
proof. confidence_index stays null until source-independent evidence
metadata has been reviewed under breach-ci rank. A count of collector
labels never proves independently established underlying sources.
No person identity or relationship is asserted, no ledger is changed.

Store case files privately. The CLI checks regular-file snapshots and
rejects symlinks and common file-replacement races; it cannot authenticate
the evidence contained in the file.

## Source-cited relationship cluster analysis

Run the offline command `huntsman-recon breach-ci clusters SOURCE_CITED_RELATIONSHIPS.json` to traverse only explicitly documented associations. It preserves every complete public HTTPS source URL, deduplicates original dataset roots, separates disputed links, keeps namesakes distinct, and returns deterministic full-name clusters and multi-hop paths ranked by uncalibrated CI. No inferred direct relationships, person ownership, criminal association or live breach requests. Full input contract and synthetic fixture: [RELATIONSHIP_CLUSTERS.md](RELATIONSHIP_CLUSTERS.md).

## Verification and limitations

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked breach_ci
cargo test --workspace --locked
```

This feature currently supports offline planning, CI ranking and known-only follow-up proposals, not live multi-provider fuzzy search, automatic person identity resolution, name-based credential search, API-key discovery, or automatic proof of source independence. The HSE CI runner must execute and pass against the exact feature commit before merge; native Android AArch64 testing is also required.
