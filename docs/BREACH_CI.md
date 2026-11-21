# Breach-led OSINT candidate planning and Confidence Index

This is a **local, offline planner and evidence-metadata ranker**. It does not make breach API calls, read stolen credential values, infer that lookalike identities are one person, or verify source records. Run only on your accounts, verified owned domains, or another explicitly authorised investigation.

## Commands

```sh
huntsman-recon breach-ci plan email alice@example.org --purpose own-account
huntsman-recon breach-ci plan username John.Doe --purpose authorized-engagement
huntsman-recon breach-ci plan domain example.org --purpose authorized-engagement
huntsman-recon breach-ci rank findings.json
```

The first three commands generate bounded exact provider-check proposals sorted by **investigative priority**. They return `confidence_index: null`, `state: not_queried`. This is deliberate: a source not queried cannot establish a finding or CI score. The planner uses the existing DeHashed selector validation, avoids wildcards and multi-field sweeps, and uses `username_variants::variants` for at most 12 deterministic username variants. Each variant must still pass DeHashed's exact-selector rules. Email local parts are **not** mutated. A domain is **not** expanded to guessed personal accounts.

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

## Verification and limitations

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked breach_ci
cargo test --workspace --locked
```

This feature currently supports offline planning and ranking only, not live multi-provider fuzzy search, API-key discovery, or automatic proof of source independence. The HSE CI runner must execute and pass against the exact feature commit before merge; native Android AArch64 testing is also required.
