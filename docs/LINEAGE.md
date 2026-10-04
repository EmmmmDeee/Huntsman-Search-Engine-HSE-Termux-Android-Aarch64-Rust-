# Lineage and the automatic-merge rule

Owners: `src/lineage.rs` (lineage from response data, the resolution contract) and
`src/identity_resolution.rs` (the merge rule, `IdentityResolutionDecision::hold_reasons`).
`check` exercises both as part of gate 5, in two halves that both run:

- lineage half (`check_lineage_gate`): observations go through `resolve_with_lineage`;
  two collectors relaying one dump are one family and held, a dump plus a verified
  registry auto-merges, a missing or NaN probability holds, and every observation comes
  back unchanged;
- graph half (`check_ancestry_graph_gate`): a hand-built `EvidenceAncestryGraph` with an
  explicit parent chain (two mirrors under one dump) and a root that supports a
  candidate directly (a registry), checked through `allows_automatic_merge`, the path
  `resolve::automatic_clusters` takes. Two mirrors must not merge; a mirror plus the
  registry must.

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
The gate recomputes the collector's family from `provenance.source` on every call and
never reads the stored `provenance.source_family`. That field is deserialized from saved
data, so a tampered local record with `source: "hibp"` and `source_family: "abn_lookup"`
is not registry-class: its `registry` field contributes zero families, and the record is
still returned unchanged. The collector name must also be ASCII before it is compared:
Unicode lowercasing folds some non-ASCII letters onto ASCII (KELVIN SIGN U+212A becomes
`k`), so `abn_loo\u{212A}up` would otherwise match `abn_lookup`. Lookalike spellings
such as CYRILLIC SMALL LETTER A U+0430 (`\u{0430}bn_lookup`) are different strings and do
not match.

Dataset-name canonicalisation collapses whitespace and case only. Unicode confusables and
zero-width characters are not normalised, so `Adobe` and `\u{0410}dobe` (CYRILLIC CAPITAL
LETTER A) are two dataset families. Legacy 7dca720 also counts them as 2, so this is not a
regression. The collector-name ASCII rule above is separate: it decides only whether a
collector is a verified registry source. It never normalises, compares or rejects dataset
values. Treat adapter-origin validation and stronger dataset-name canonicalisation as
separate hardening work, not as capabilities already provided here.

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
| Entity count, tampered: `hibp` x2, 2nd stored `source_family: "spoof-corpus"` [E] | 1 (raw sources) | 1 (main: 2) | Stricter than main, equal to legacy. A stored family no longer becomes a corroboration key. |
| Entity count, tampered: `hibp` x2, 2nd stored `source_family: "abn_lookup"` [E] | 1 | 1 (main: 2) | Stricter than main, equal to legacy. |
| Entity count, tampered: `hibp` x3, stored `a`, `b`, `c` [E] | 1 | 1 (main: 3) | Stricter than main, equal to legacy. |
| Entity count, tampered: `hibp` + `dehashed`, `dehashed` stored `source_family: "hibp"` [E] | 2 | 2 (main: 1) | Looser than main, equal to legacy. A copied stored family can no longer collapse two real collectors either. |
| Entity set, tampered: `hibp` + `search_engines` stored `source_family: "dehashed"` [E] | 2 {`hibp`, `search_engines`} | same (main: 2 {`dehashed`, `hibp`}) | Same count; the set names the real collector again, equal to legacy. |
| Entity set, tampered: lone `hibp` stored `source_family: "recall"` [E] | 1 {`hibp`} | same (main: 1 {}, via the stored-strength fallback) | Same count; a stored non-corroborating family no longer hides the real collector, equal to legacy. |
| Entity count, saved record with **no** stored family: `HIBP` + `hibp` (also ` hibp ` + `hibp`, `Recall` + `hibp`) [E] | 2 | 2 (unchanged) | Not changed. Canonicalising the raw `source` here would give 1, which legacy does not do, so it is not adopted; flagged for Chief. |
| every fixture, probability absent | graded with no probability | held, `ProbabilityMissing` | Legacy grades corroboration and never auto-merges. Recon auto-merges only with a present, in-range probability. |
| `dehashed`, two `source_url` domains, no dataset field [1] | 1 corpus (falls back to collector name), not corroborated | 0 families, held | Stricter count, same verdict. Record locators are not lineage (`source_url` is not a lineage field). |
| `dehashed`, `source_id` `row-1` / `row-2`, no dataset field [1] | 1 corpus (falls back to collector name), not corroborated | 0 families, held | Stricter count, same verdict. Row ids are record locators, not lineage. |

[1] From Fix This Bullshit Bot's post-merge legacy comparison on #679, which ran legacy
7dca720 against merged main bd0ccad with every input at probability 0.99. These cases are
not in the fixture file. The recon values were rechecked against the current code. The
same fail-closed behaviour is pinned by `record_urls_cannot_mint_independent_families` and
`record_ids_cannot_mint_independent_families` in `tests/lineage_independence_adversarial.rs`.

The same comparison found these cases equal:

- `hibp` `breach: "Adobe"` + `hibp` `source_db: "company registry"`: legacy 2 corpora,
  corroborated; recon 2 families, AutoMerge. A dataset field can still name a second
  dataset from the same collector, as in legacy.
- One collector citing two named datasets (`dehashed` `dbname` `Adobe` + `LinkedIn`, pinned
  by `two_explicit_datasets_from_one_collector_remain_independent`): legacy 2, recon 2. This
  matches legacy, so it is not a loosening. A one-collector-one-family rule would be a
  tightening. It is not adopted, pending Chief's decision.
- `Adobe` vs the Cyrillic lookalike `\u{0410}dobe`: legacy 2, recon 2. Neither normalises
  dataset names (see the trust boundary above).

[E] `Entity::source_count` / `Entity::corroborating_sources` on a saved entity whose stored
`provenance.source_family` disagrees with `provenance.source` (Security low finding on
#684). Each row was run through legacy 7dca720 (capture method in
`tests/fixtures/legacy_7dca720_breach_consensus.json`, which it reproduced on all nine
fixtures), main (94668e43, and again at deb48f12 after #684 merged, with identical
results) and this change. Legacy has no `source_family` field and counts
raw `source` strings. `EvidenceProvenance::corroboration_key` now keys a record that has a
stored family on `canonical_provenance_family(source)`, and a record without one on its raw
`source`; the stored value itself is never a key. Pinned by `tests/corroboration_key.rs`,
including the two threshold effects a spoofed second family had on main: at confidence
0.64-0.74 it lifted Probable to Verified (tested at 0.65, 0.70 and 0.74), AU-003 fired at
any confidence from 0.64 up, and at 0.85 the entity was marked saturated.
Unchanged by this change, compared for completeness:

- Honest records, the nine fixtures, (a)-(g), the Cyrillic and Kelvin-sign collectors:
  identical on main and here.
- Honest `hibp` + `HIBP`: legacy 2, recon 1 on main and here. `EvidenceProvenance::new`
  stores the canonical family, so honest case variants were already one source.
- Residual, flagged for Chief with the no-stored-family row: two `HIBP` records where only
  one has its stored family removed count as 2 (`HIBP`, `hibp`) on main and here; legacy 1.
  Canonicalising records without a stored family would close it but change the row above.

The adversarial lineage suite additionally pins the fail-closed cases that motivated the
review repair: record URLs and row ids contribute zero families; an unverified provider's
`registry` field contributes zero; a tampered record whose stored `source_family` claims
`abn_lookup` contributes zero; a collector spelled with Cyrillic lookalikes or a
case-folding sign (`\u{0430}bn_lookup`, `abn_loo\u{212A}up`) is not a verified registry
source; verified `abn_lookup` + ABR can contribute a registry root; and two explicitly
named upstream datasets may still be represented through one aggregating collector.
