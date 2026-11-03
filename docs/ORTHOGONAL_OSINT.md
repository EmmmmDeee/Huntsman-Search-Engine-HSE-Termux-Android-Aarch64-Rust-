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
`correlator::source_family` classifies established collector categories; a
narrow `orthogonal_osint::acquisition_modality` adapter additionally recognises
live providers without changing the correlator's identity-related source
families or using user-supplied `source_family` values;
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
| Organisation, ABN/ACN | community knowledge graph (separate from official registry), authoritative register, dated public search, code |
| IP, ASN, netblock | infrastructure attribution, historical indexes |
| Person | community knowledge graph, official public records, dated search and public human-source statements |
| Coordinates | geocoding/satellite GEOINT, dated transport, public NETINT, consented RF and archives |
| MAC, SSID | consented, explicitly aged radio observations |

The `human_public` acquisition class is limited to attributable published material or consented submissions; it does not perform human elicitation, impersonation or account matching. Coordinate `netint` suggestions are about public infrastructure coverage, never person location. `nominatim`, `stac` and `opensky` are classified as acquisition metadata sources only, and never prove who was present. Existing Web UI analysis renders the shared `orthogonal` report with no parallel engine.

These are **hypothesis classes** to investigate. The module does not
assert that a provider is configured, reachable or authorised. A
broad collector class can contain several distinct techniques: one
`infra` observation does not prove RDAP, CT and DNS are all covered.

## Evidence integrity

- A copied breach corpus mirrored through multiple collectors remains
  one *declared upstream family*. Declared lineage is not itself proof.
- An unrecognised or inferred source does not satisfy a modality.
- Genuine collector identifiers such as `wikidata`, `peeringdb`, `crtsh`, `certspotter`, `wayback_cdx` and `bluesky_user` satisfy their respective *acquisition* modality when source evidence is recorded. Wikidata is `knowledge_graph`, **not** an authoritative identity registry; PeeringDB is `infra` rather than proof of a network operator's identity.
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
