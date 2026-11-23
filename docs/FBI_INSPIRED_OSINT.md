# FBI-inspired, evidence-led public OSINT in Huntsman

**Status:** design and operating guide, not an FBI affiliation or an assertion that all capabilities below are implemented. Only public or operator-authorised sources; no law-enforcement-only access, impersonation, covert contact, live person tracking, credential harvesting or active probing of investigation targets.

## 1. Mission and authoritative ownership

Build a **case-first investigation workflow** on top of Huntsman's existing Rust source adapters, evidence ledger, identity gate and localhost Web UI. A search result is a lead; a first-party document establishes its own publication, not all underlying allegations. Separate **who was named**, **what was alleged**, **what a court decided**, **what was observed**, and **what remains unknown**.

Keep one canonical implementation for each function; do not create another case graph or independent HTTP client.

| Function | Existing code / interface | Rule |
|---|---|---|
| Official wanted notices | `src/public_osint.rs`, `public-osint notices QUERY`, `people NAME` | Notice must name the query in title or an alias; record stable notice URL, dates and source outcome |
| News and archive discovery | `public-osint dossier QUERY`, `src/web_query.rs`, `src/archived_page.rs` | Capture article's publication and archive timestamps separately from event time |
| Public person and organisation references | `src/people_cli.rs`, `src/identity_resolution.rs`, `src/gleif.rs`, `src/sec_edgar.rs`, `src/icij_offshore.rs` | Same-name records remain independent until reliable identifier links exist |
| Case chronology, claims and conflicts | `src/osint_casework.rs`, `osint case FILE` | Chronology and contradictions are retained; nothing silently promoted to fact |
| Provenance and independent support | `src/source_outcome.rs`, `src/evidence_ancestry.rs`, `src/orthogonal_osint.rs` | Syndicated copies are not independent corroboration |
| Provider availability and API capability | `src/module.rs`, `src/source_profile.rs`, `osint matrix --json` | Advertise provider support separately from current reachability and authenticated entitlement |
| Guarded HTTP | `src/fetch.rs`, `src/http.rs` | Reuse one bounded, rate-aware transport; no target-facing probes |
| Exposure/breach disclosures | `src/hibp.rs`, `src/xposedornot.rs`, `src/breach_hybrid.rs` | Respect authorisation; metadata and aggregate exposure do not prove identity or criminal involvement |

## 2. Investigative workflow

1. **Intake**: capture the question, case identifier, permissible subject scope, jurisdiction, as-of time, expected output and stopping conditions. Lock an immutable raw-source reference where lawfully available.
2. **Official seed**: retrieve the issuing authority's public notice or court record. Match stable document IDs and titles/aliases. Keep notice category, issue/update date, stated reward, and document URL; do not infer guilt from being listed.
3. **Independent enrichment**: corroborate case numbers, company IDs, docket IDs, forfeiture orders, sanctions identities and beneficial-owner claims against primary registries. Preserve jurisdiction, record date, decision status and source host.
4. **Hypothesis management**: maintain competing explanations, affirmative evidence, disconfirming evidence, unresolved gaps and temporal dependencies. Separate source excerpts from analytical inference.
5. **Evidence-aware pivots**: follow typed, provenance-backed identifiers only. A shared family name, surname, email prefix, IP, address or username alone does not justify person/entity collapse.
6. **Adversarial review**: challenge each result for namesakes, recycled publications, incomplete pagination, altered notices, mirror/syndication dependence and conflicts across jurisdictions.
7. **Report**: produce a reproducible, chronological case dossier with source-by-source outcomes and explicit unknowns. Present tips to the issuing authority; no attempts to apprehend or approach a person.

## 3. FBI Wanted API: completeness is a first-class invariant

Official documentation: https://www.fbi.gov/wanted/api
Public endpoint: https://api.fbi.gov/wanted/v1/list

The API exposes `items`, `total` and a `page` query parameter. Current Huntsman requests `title=QUERY&pageSize=20` and inspects only the first page. A first-page nonmatch **cannot** be treated as a definitive zero if `total > items.len()` or if `total` is missing. Existing valid records may remain useful leads with a prominent incomplete-coverage diagnostic.

The associated source fix:
- rejects contradictory `total < items.len()` as schema drift;
- classifies no-match results with missing/unexamined pages as `inconclusive`, never `valid_zero`;
- preserves first-page observations but records omitted result counts;
- exercises matching, nonmatching, missing total and contradictory-total cases offline.

**Next step (not implemented):** bounded `page` traversal within a configured per-case request/time budget, checking page identity and stable `uid`, deduplicating by notice URL/UID, and treating interrupted traversal as incomplete. Rate limits and event reporting must remain visible.

## 4. Evidence and decision model

A case observation should retain:

```text
case_id, source_id, source_url, upstream_record_id, retrieved_at_utc,
published_at_utc, event_at_utc, last_modified_at_utc, observed_fields,
source_outcome, raw_payload_hash, derived_claims, limitations
```

Separate each claim's `status` from its `priority`:
- **Candidate**: a search match that has not passed identity checks.
- **Observed**: a source actually published a specific record.
- **Corroborated**: at least two independent underlying sources support the precise claim.
- **Verified**: primary records or equivalent independently reviewable evidence establish the bounded claim.
- **Conflicted, stale or rejected**: contradicting records, time expired, or disconfirmed identity.

**Never score truth by the number of search results.** A lead-priority score is only a work-queue heuristic, not a probability of guilt, identity, or location.

Suggested internal queue score (0–100; not yet implemented):
- Directly relevant primary document or stable identifier: 0–30.
- Source freshness with explicit event and collection times: 0–15.
- Independent underlying corroboration: 0–25.
- Falsifiable, bounded investigative next step: 0–20.
- Clear legal access, provenance and reproducibility: 0–10.

Require a reviewer to approve any person-level attribution or proposed external disclosure.

## 5. Highest-value source families

| Source family | Mode | What it can prove |
|---|---|---|
| FBI Wanted API and issuing-agency notices | Public, keyless | Publication of an official notice and its currently stated fields |
| DOJ and court decisions, dockets and forfeiture notices | Public records; some court systems require accounts/fees | Allegations, judicial decisions, asset/legal chronology as applicable |
| FBI IC3 public reports | Public aggregates | Cybercrime trends, not identities or individual cases |
| FBI Crime Data Explorer / NIBRS | Public aggregate/incident statistics under availability rules | Historical crime reporting trends; not a live individual-tracking database |
| OFAC, UN, EU sanctions | Public lists | Listing status and structured identifiers as of the list update |
| GLEIF, SEC EDGAR, Companies House, ICIJ Offshore Leaks | Public or licence-controlled | Corporate filings and documented association claims, not automatic beneficial control |
| GDELT, web, archives | Public search discovery | Indexed articles and historical captures; assertions require origin verification |
| HIBP/XposedOrNot and other breach services | Public catalogue; personal queries subject to authorisation | Published exposure metadata; no automatic person attribution |
| WHOIS/RDAP, CT, DNS | Public | Network infrastructure/registration observations, not a person's whereabouts |

**Explicit exclusions:** NCIC/CJIS restricted data, law-enforcement-only databases, private communications, password dumps, purchased stolen credentials, concealed surveillance, and physical-target tracking.

## 6. Operator quick start (existing interfaces)

```sh
huntsman-recon public-osint notices "Ruja Ignatova"
huntsman-recon public-osint dossier "OneCoin"
huntsman-recon people "Ruja Ignatova"
huntsman-recon osint matrix --json
huntsman-recon osint plan "OneCoin"
```

The outputs are independent leads. Run `osint case FILE` on an authorised, locally prepared casework file to review claims, chronology and conflicts. Consult `huntsman-recon osint --help` for casework file grammar. The exact CLI/API schema must be validated on the user's installed version before treating it as accepted.

## 7. Acceptance / release gates

1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets --locked -- -D warnings`
3. `cargo test --workspace --locked`
4. `cargo gate full` (repository's canonical CI gate)
5. Native rootless Termux AArch64 compilation and `huntsman-recon check` on the target phone
6. Deterministic fake-transport tests: pagination overflow, missing total, contradictory counts, cross-identity confusion, 429/5xx and schema drift
7. Live-provider smoke tests only with allowed quotas and no claims of complete data coverage

Do not merge or assert full support until the CI gate, source attribution and Android acceptance are verifiably passing. Neither an FBI source URL nor a case timeline confers legal authority.
