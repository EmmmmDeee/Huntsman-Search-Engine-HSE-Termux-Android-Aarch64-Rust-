# Orthogonal OSINT acquisition gaps

Huntsman's shared `analysis::analyze_snapshot` report now includes
`orthogonal`, a **read-only and bounded proposal list** for different
collection *modalities* not represented in the current snapshot.

A source modality is **not** an independent source, and a proposed
collection is not an executed search. An absent modality is only an
**evidence-coverage gap**, not an observed negative.

## Data flow

`pipeline::AnalysisSnapshot.entities` and `.ancestry` feed the
single `orthogonal_osint::discover` implementation. The shared
`correlator::source_family` classifies observed collector categories;
`lineage::Lineage::of` interprets admissible upstream dataset or
verified registry fields; and
`evidence_ancestry::proven_independent_route_count` is the *only*
authority that may report proven-independent proof routes.

The analysis fan-out, standard report JSON, and recursive
`recurse --json` / text outputs all reuse that one result. They must
never implement alternative source-independence estimates.

## Forms suggested

| Entity kind | Acquisition modalities to check |
| --- | --- |
| Domain, URL | infrastructure, code metadata, indexed/archived web |
| Email | authorised breach notices, public mail/key metadata, code |
| Username | public code, forums, social, platform presence |
| Organisation, ABN/ACN | authoritative register, dated public search, code |
| IP, ASN, netblock | infrastructure attribution, historical indexes |
| Person | official public records and dated public search |
| MAC, SSID | consented, explicitly aged radio observations |

These are **hypothesis classes** to investigate. The module does not
assert that a provider is configured, reachable or authorised. A
broad collector class can contain several distinct techniques: one
`infra` observation does not prove RDAP, CT and DNS are all covered.

## Evidence integrity

- A copied breach corpus mirrored through multiple collectors remains
  one *declared upstream family*. Declared lineage is not itself proof.
- An unrecognised or inferred source does not satisfy a modality.
- The verified ABR registry origin is admitted only through the
  existing source-aware registry lineage gate. A forged stored
  `source_family` label cannot pass it.
- Independence depends on explicit ancestry evidence. Missing,
  invalid or bounded ancestry remains non-proving.
- Results are deterministic across input ordering, grouped by
  entity UID and capped at 192 opportunities. The `omitted_opportunities`
  count and `truncated` flag disclose the overflow.
- No new provider requests, API keys, identity merges, confidence
  promotions, geolocation assertions, credentials or storage writes
  are introduced.

## Verification

```bash
cargo fmt --all -- --check
cargo test --locked --test orthogonal_osint
cargo run --locked -p xtask -- gate full
```

The tests cover copied breach-corpus lineage, attempted registry
spoofing, inferred-source exclusion, deterministic ordering, output
bounds and the end-to-end shared analysis JSON contract.

Android AArch64 and Chromium verification must use the repository's
CI workflow, and real device behaviour requires a separate Termux
run. Cloud compilation is not evidence of a successful device scan.
