# Lineage and the automatic-merge rule

Owners: `src/lineage.rs` (lineage from response data, the resolution contract) and
`src/identity_resolution.rs` (the merge rule, `IdentityResolutionDecision::hold_reasons`).
`check` exercises both as part of gate 5.

## Lineage comes from the response

A collector is a relay, not an origin. `lineage::Lineage::of(&Evidence)` reads the
upstream identity from the parsed response fields in `Evidence::attributes`. It never
reads `Evidence::provenance.source` (the collector name). The first field with a
non-blank value decides (`lineage::LINEAGE_FIELDS`):

| Field | Kind | Note |
| --- | --- | --- |
| `dbname`, `breach`, `source_db` | dataset | Legacy `breach_corpus_key` spellings, in its order |
| `database_name`, `dataset` | dataset | |
| `registry` | registry | |
| `source_url`, `source_id` | source | URLs canonicalised with `canonical::canonical_url` |

The family key is the canonical value: whitespace collapsed, lowercased (`evidence_ancestry::canonical_family`). It has no kind prefix, so the same name counts once whatever field it arrived in. Collectors copy these fields from the response verbatim. For an HIBP breach model, `Name` goes to `breach`.

- **Unattributed**: the response names no upstream. The observation is kept and contributes zero families.
- **Ambiguous**: the deciding field carries several distinct upstreams (a combo list). The observation is kept and contributes zero families, because one record cannot independently attest two origins.

`resolve_with_lineage` builds the ancestry graph from this. Each distinct family becomes one root, `lineage:<family>`, and each observation becomes a derived relay node under its root. Two collectors relaying one dataset therefore share one root and count as one independent family. Observation ids may not be empty, duplicated, or start with `lineage:`. Any of those rejects the whole input, so nothing is dropped.

## The merge rule

`IdentityResolutionDecision::hold_reasons(graph, policy)` is the single authority. `allows_automatic_merge` is defined as `hold_reasons(..).is_empty()`. An automatic merge needs all of these:

- the uids are non-empty and distinct, and the node ids are non-empty;
- the policy floor `min_match_probability` is itself finite and in `[0, 1]`;
- a match probability is **present**, finite, in `[0, 1]`, and at least `min_match_probability`;
- the state is `Match`;
- there are no contradicting nodes and no temporal or geographic conflict;
- at least `min_independent_support_families` (minimum 1) independent root families are found, with every supporting node known and acyclic.

Every failed condition is reported as a `HoldReason`, in a fixed order (`InvalidPolicy` for a floor that is NaN, infinite or outside `[0, 1]`, `ProbabilityMissing`, `ProbabilityInvalid { value }`, `ProbabilityBelowThreshold`, `NotAMatch`, `Contradicted`, `TemporalConflict`, `GeographicConflict`, `UnknownAncestry`, `InsufficientIndependentFamilies { found, required }`, `InvalidCandidate`). A held candidate is returned with its reasons. It is never dropped.

### Threshold and legacy parity

`AutoMergePolicy::default()` is 2 independent families and `p >= 0.90`. Both values are taken from the legacy `hse` oracle at 7dca720, `core::breach_consensus`:

- `ConsensusResult::is_corroborated` requires `source_count() >= 2` distinct corpora.
- `supported_ceiling` gives 0.70 for one corpus (below `VERIFIED_MIN` 0.75), 0.90 for two, and 1.0 for three or more.

So the merge floor is the confidence legacy allows a two-corpus finding to state. `tests/lineage_legacy.rs` asserts both values against the captured oracle output.

## Library contract for collection front-ends

```rust
use huntsman_recon::lineage::{resolve_with_lineage, Observation, Resolution, MergeOutcome};
use huntsman_recon::identity_resolution::{AutoMergePolicy, IdentityResolutionDecision};

let resolution: Resolution = resolve_with_lineage(
    observations,             // Vec<Observation { id, evidence }>, one per parsed record
    candidates,               // Vec<IdentityResolutionDecision>; supporting = observation ids
    AutoMergePolicy::default(),
)?;                           // Err(LineageError): invalid policy floor, or empty, reserved or duplicate ids
```

`Resolution` contains `policy`, `observations` (every input, unchanged, with its `Lineage`, in input order) and `candidates` (every input decision, unchanged, in input order, each with `independent_families`, `unattributed_support` and `outcome: AutoMerge | Held { reasons }`). It round-trips through serde JSON. JSON has no NaN, so a NaN probability reloads as `null`, but the saved reason keeps `"NaN"`. A support id that is not an observation, including a root id, holds the candidate as `UnknownAncestry`. The original decision is still validated, and reasons come in the same order as `hold_reasons`, because both use one rule core (`hold_reasons_given`).

This layer supplies no probability. A caller with no calibrated match probability passes `None` and gets a held candidate.

## Differential test against legacy

`tests/fixtures/legacy_7dca720_breach_consensus.json` records nine fixture identities and the outcomes the 7dca720 code produced on them: `breach_corpus_key` per record, `confirming_sources`, `is_corroborated` and `supported_ceiling`. They were captured by running `run_consensus_pass` in an exported oracle tree; the method is in the file. Recon matches legacy's grouping and corroboration verdict on six fixtures. These differences are intentional and pinned:

| Fixture | Legacy | Recon | Reason |
| --- | --- | --- | --- |
| `unattributed_collectors` | 2 corpora (collector names) | 0 families | Legacy falls back to the collector name when a record names no corpus. Lineage must come from the response. |
| `case_and_whitespace_variant` | 2 (`Adobe`, `ADOBE `) | 1 | Recon canonicalises families, so formatting cannot create a second family. |
| `dump_plus_registry` | 1 (breach corpora only) | 2 | Legacy consensus only counts breach sources. Recon counts any upstream the response names. |
| every fixture, probability absent | graded with no probability | held, `ProbabilityMissing` | Legacy grades corroboration and never auto-merges. Recon auto-merges only with a present, in-range probability. |
