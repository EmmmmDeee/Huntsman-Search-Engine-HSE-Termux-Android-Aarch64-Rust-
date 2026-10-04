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

The adversarial lineage suite additionally pins the fail-closed cases that motivated the
review repair: record URLs and row ids contribute zero families; an unverified provider's
`registry` field contributes zero; a tampered record whose stored `source_family` claims
`abn_lookup` contributes zero; a collector spelled with Cyrillic lookalikes or a
case-folding sign (`\u{0430}bn_lookup`, `abn_loo\u{212A}up`) is not a verified registry
source; verified `abn_lookup` + ABR can contribute a registry root; and two explicitly
named upstream datasets may still be represented through one aggregating collector.

## stolen.tax redirects, key scope and failure text vs legacy 764ce8e

Legacy is the 764ce8e restore on the old tree (`1dfb5c9d`, base `98c77fd`). Its
same-site rule is `src/util/http/ssrf.rs`: `MAX_REDIRECT_HOPS = 10` (`:33`) counts the
original request, so at most 9 redirects; `redirect_verdict` (`:119-137`) stops a hop
to a private address, a hop that is not `same_site` with the first URL, and an https
to http hop; `same_site` (`:69-85`) is equal hosts or equal registrable domains
(vendored PSL; for `stolen.tax` that is `stolen.tax` or any subdomain), ignoring
port and scheme. A stopped hop left the 3xx as the path's failure.

| Behaviour | Legacy | Recon | Status | Tests |
| --- | --- | --- | --- | --- |
| Same-site redirects | Followed up to 9 redirects within the site (`ssrf.rs:33`, `:69-85`, `:119-137`); off-site, private-address and https to http hops stopped, the 3xx failed the path | `fetch::RedirectPolicy::SameSite { site: "stolen.tax" }`, `stolen_tax::MAX_REDIRECTS = 9`; a refused hop is not sent and the path fails with `HTTP 302 (RedirectChanged); redirect refused: <why>`, or `…; redirect limit reached (9 followed)` | Parity, decided by Chief (restored) | `redirect_same_site_https_hop_is_followed_and_its_evidence_kept`, `redirect_subdomain_hop_is_followed_without_the_key`, `redirect_port_change_is_followed_without_the_key`, `redirect_userinfo_trick_is_another_host_and_never_gets_the_key`, `redirect_http_downgrade_is_refused_before_any_request`, `redirect_chain_stops_at_the_monolith_hop_limit`, `redirect_slow_same_site_chain_stops_at_the_lookup_deadline`, `same_site_follows_the_monolith_s_redirect_verdict`, `an_unusable_location_is_a_refused_hop_under_same_site` |
| Key scope on redirects | reqwest drops `Authorization` once a hop changes host or port and never restores it; a subdomain or another port on the same site was still followed, without it; URL userinfo was not stripped | The key goes only to the exact origin `https://stolen.tax:443` (`Credential::only_for_origin(stolen_tax::KEY_ORIGIN)`): stripped (sensitive headers and the custom key header) from every other hop, never re-attached after a hop leaves the origin; userinfo is dropped from every redirect target so ureq cannot mint `Authorization: Basic` from it | Tightening | `a_pinned_credential_goes_only_to_its_origin_and_never_back_after_leaving`, `a_custom_key_header_is_stripped_off_origin_even_if_the_caller_set_it`, `userinfo_is_dropped_from_a_redirect_target`, `redirect_subdomain_hop_is_followed_without_the_key`, `redirect_port_change_is_followed_without_the_key`, `redirect_userinfo_trick_is_another_host_and_never_gets_the_key` |
| Tightening (4): failure text | Quoted the response: `HTTP 429 Too Many Requests: rate limited`, `HTTP 500 Internal Server Error: upstream error`; a decode error carried `serde_json`'s display text plus the body's first 80 characters, or an HTML page's title (`src/util/http/url.rs:76-92`) | Status and kind only (`HTTP 429 (RateLimited) after 3 attempts`, `HTTP 401 (AuthRejected)`). A decode failure is `could not decode response: <syntax\|data\|eof\|io> error at line L column C` (`serde_json::Error::classify()` plus position, never its display text or the body). A provider's in-body `error` words are scrubbed of the key first, then cut to 120 characters on a character boundary, then control characters are replaced (U+FFFD); scrubbing first means a key straddling the cut cannot survive as a partial key | Tightening (Security ruling) | `a_decode_error_names_its_category_and_position_never_the_body`, `a_long_provider_error_is_cut_to_120_chars`, `the_key_is_scrubbed_from_a_provider_error_before_it_is_cut` |
| 429 log line | `tracing::warn!("429 rate-limited on key …{key_tail}, …")` logged the key's last 4 characters (`src/util/http/fetch.rs:792-797`) | No log line; no part of the key is logged | Improvement | none (nothing is logged) |
| Cancel check | `ctx.cancel.is_cancelled()` before each attempt (`src/util/http/fetch.rs:1365`) | No per-attempt cancel check; the 120 s lookup deadline bounds the lookup | Difference, pending sign-off | none |
| Zero-budget retry | Slept and retried until the engine timeout killed the module | A retry with no budget left is not sent and not counted: `HTTP 429 (RateLimited) after N of 3 attempts; the 120s lookup budget ran out before the next one` | Part of difference (1), pending sign-off | `a_retry_with_no_budget_left_is_not_sent_or_counted` |
