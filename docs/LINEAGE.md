# Lineage and the automatic-merge rule

Owners: `src/lineage.rs` (lineage from response data, the resolution contract) and
`src/identity_resolution.rs` (the merge rule, `IdentityResolutionDecision::hold_reasons`).
`check` exercises both as part of gate 5.

## Lineage comes from the response

A collector is a relay, not an origin. `lineage::Lineage::of(&Evidence)` derives the
upstream identity from parsed response fields in `Evidence::attributes`; the collector
name never becomes an evidence family. Collector identity may only gate whether a
source-class-specific field is admissible. The first admissible field with a non-blank
value decides (`lineage::LINEAGE_FIELDS`):

| Field | Kind | Note |
| --- | --- | --- |
| `dbname`, `breach`, `source_db` | dataset | Legacy `breach_corpus_key` spellings, in its order |
| `database_name`, `dataset` | dataset | Adapter-provided upstream dataset identity |
| `registry` | registry | Counted only for collectors in `VERIFIED_REGISTRY_SOURCES`; currently `abn_lookup` (ABR) |

`source_url` and `source_id` are deliberately **not** lineage fields. They are record
locators and cannot manufacture independent families by changing a row id, URL path,
HTTP scheme, `www` prefix, or trailing slash.

The family key is the canonical value: whitespace collapsed and lowercased
(`evidence_ancestry::canonical_family`). It has no kind prefix, so the same canonical
name counts once whatever admissible field it arrived in. For an HIBP breach model,
`Name` goes to `breach`.

- **Unattributed**: the response names no admissible upstream. The observation is kept and contributes zero families.
- **Ambiguous**: the deciding field carries several distinct upstreams (a combo list). The observation is kept and contributes zero families, because one record cannot independently attest two origins.

`resolve_with_lineage` builds the ancestry graph from this. Each distinct family becomes
one root, `lineage:<family>`, and each attributed observation becomes a derived relay node
under its root. Two collectors relaying one named dataset therefore share one root and
count as one independent family. Observation ids may not be empty, duplicated, or start
with `lineage:`. Any of those rejects the whole input, so nothing is silently dropped.

### Trust boundary

Dataset fields are currently trusted at the adapter boundary. A collector may legitimately
aggregate several independent upstream datasets (for example two distinct breach corpora),
so collector count is not used as a substitute for upstream independence. This also means
a defective adapter that assigns false or adversarially distinct dataset names can overstate
independence. That residual risk is explicit: automatic merge additionally requires a
calibrated probability and all merge-rule gates, but this layer does not cryptographically
prove dataset identity.

Registry lineage is stricter because its source class is explicit: a `registry` attribute
counts only when the collector is bound in `VERIFIED_REGISTRY_SOURCES`. An arbitrary
provider claiming `registry=...` remains preserved evidence but contributes zero families.

Current canonicalisation collapses whitespace and case. Unicode confusables and zero-width
characters are not yet normalized as equivalent dataset names. Treat adapter-origin
validation and stronger identifier canonicalisation as separate hardening work, not as
capabilities already provided here.

## The merge rule

`IdentityResolutionDecision::hold_reasons(graph, policy)` is the single authority.
`allows_automatic_merge` is defined as `hold_reasons(..).is_empty()`. An automatic merge
needs all of these:

- the uids are non-empty and distinct, and the node ids are non-empty;
- the policy floor `min_match_probability` is itself finite and in `[0, 1]`;
- a match probability is **present**, finite, in `[0, 1]`, and at least `min_match_probability`;
- the state is `Match`;
- there are no contradicting nodes and no temporal or geographic conflict;
- at least `min_independent_support_families` (minimum 1) independent root families are found, with every supporting node known and acyclic.

Every failed condition is reported as a `HoldReason`, in fixed order:
`InvalidPolicy`, `InvalidCandidate`, `ProbabilityMissing`, `ProbabilityInvalid { value }`,
`ProbabilityBelowThreshold`, `NotAMatch`, `Contradicted`, `TemporalConflict`,
`GeographicConflict`, `UnknownAncestry`, `InsufficientIndependentFamilies { found, required }`.
A held candidate is returned with its reasons. It is never dropped.

### Threshold and legacy parity

`AutoMergePolicy::default()` is 2 independent families and `p >= 0.90`. Both values are
taken from the legacy `hse` oracle at 7dca720, `core::breach_consensus`:

- `ConsensusResult::is_corroborated` requires `source_count() >= 2` distinct corpora.
- `supported_ceiling` gives 0.70 for one corpus (below `VERIFIED_MIN` 0.75), 0.90 for two, and 1.0 for three or more.

So the merge floor is the confidence legacy allows a two-corpus finding to state.
`tests/lineage_legacy.rs` asserts both values against the captured oracle output.

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

`Resolution` contains `policy`, `observations` (every input, unchanged, with its `Lineage`,
in input order) and `candidates` (every input decision, unchanged, in input order, each
with `independent_families`, `unattributed_support` and `outcome: AutoMerge | Held { reasons }`).
It round-trips through serde JSON. JSON has no NaN, so a NaN probability reloads as `null`,
but the saved reason keeps `"NaN"`. A support id that is not an observation, including a
root id, holds the candidate as `UnknownAncestry`.

For fully attributed support, `lineage::assess` delegates to
`IdentityResolutionDecision::hold_reasons(graph, policy)`, so the production graph rule is
exercised directly. Where support is partly unattributed or unknown, it uses the same
ordered rule core with the explicit family count/error so preserved but non-countable
evidence cannot silently become a root.

`CandidateOutcome.independent_families` lists the known attributed roots even when another
support id is unknown; the outcome remains held as `UnknownAncestry`, so the list must not
be read as a successful adjudication by itself.

This layer supplies no probability. A caller with no calibrated match probability passes
`None` and gets a held candidate.

## Differential test against legacy

`tests/fixtures/legacy_7dca720_breach_consensus.json` records nine fixture identities and
the outcomes the 7dca720 code produced on them: `breach_corpus_key` per record,
`confirming_sources`, `is_corroborated` and `supported_ceiling`. They were captured by
running `run_consensus_pass` in an exported oracle tree; the method is in the file. Recon
matches legacy's grouping and corroboration verdict on six fixtures. These differences are
intentional and pinned:

| Fixture | Legacy | Recon | Reason |
| --- | --- | --- | --- |
| `unattributed_collectors` | 2 corpora (collector names) | 0 families | Legacy falls back to the collector name when a record names no corpus. Lineage must come from the response. |
| `case_and_whitespace_variant` | 2 (`Adobe`, `ADOBE `) | 1 | Recon canonicalises families, so formatting cannot create a second family. |
| `dump_plus_registry` | 1 (breach corpora only) | 2 | `abn_lookup` is explicitly bound to the authoritative ABR registry path; the registry family is therefore admitted independently of the breach dataset. |
| every fixture, probability absent | graded with no probability | held, `ProbabilityMissing` | Legacy grades corroboration and never auto-merges. Recon auto-merges only with a present, in-range probability. |

The adversarial lineage suite additionally pins the fail-closed cases that motivated the
review repair: record URLs and row ids contribute zero families; an unverified provider's
`registry` field contributes zero; verified `abn_lookup` + ABR can contribute a registry
root; and two explicitly named upstream datasets may still be represented through one
aggregating collector.
