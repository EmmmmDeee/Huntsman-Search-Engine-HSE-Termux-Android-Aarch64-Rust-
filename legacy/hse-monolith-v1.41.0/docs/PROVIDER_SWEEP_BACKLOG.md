# Provider sweep backlog — round 3 (Pass 17 discovery)

One finder per chunk read all 134 provider modules no earlier pass had covered,
against a six-point checklist derived from the defect classes already fixed on
this branch. Findings then went to 3-lens adversarial verification.

**Verification was cut short by a model usage limit**, not by the findings: 9 were
verified unanimously, 1 was refuted, and 43 never reached a verifier. The 43 are
recorded here as UNVERIFIED — they are leads, not findings, and none may be acted
on or reported as a defect until it has been re-derived from the source. Most
restate the class this branch has already fixed eight times (a failed lookup
reading as a clean negative), which is a reason to check them, not to believe them.

Directive framing: a module that reports "found nothing" when it actually failed
violates ABSENCE OF EASY EVIDENCE ≠ ABSENCE OF A NEXUS; the identity-attribution
leads violate IDENTIFIER MATCH ≠ ENTITY IDENTITY. `core::claim::Support::Failed`
is the type that makes the first class impossible to express once modules adopt it.

## Confirmed (3/3 adversarial verification) — actionable

| # | Module | Finding |
|---|---|---|
| 0 | `src/modules/asic_business_names/mod.rs` | asic_business_names: truncation signal can never fire and total_matches under-reports (CKAN r.total discarded) |
| 1 | `src/modules/acma_rrl/mod.rs` | acma_rrl: mid-body transport failure collapses into an empty result (false 'no licence' negative) |
| 2 | `src/modules/ahpra/mod.rs` | ahpra: mid-body transport failure collapses into an empty result (false 'not a registered practitioner' negative) |
| 4 | `src/modules/au_property/mod.rs` | au_property: a body-read failure after a 2xx is still tallied as LegOutcome::Ok |
| 5 | `src/modules/auspost/mod.rs` | auspost: response struct contradicts the live Postcode Search JSON shape — every real response fails to decode |
| 6 | `src/modules/bitcoin/mod.rs` | bitcoin: /txs failure discards the already-fetched ledger reading, contrary to the module's own comment and the or_hard_failure rule |
| 7 | `src/modules/austlii/mod.rs` | austlii: 404 on the fixed sinosrch.cgi path is treated as a clean "no legal records" miss |
| 8 | `src/modules/austlii/mod.rs` | austlii: body-read transport failure after a 2xx collapses to an empty result |
| 9 | `src/modules/chess_profile/mod.rs` | chess_profile: every upstream failure (429/5xx/transport/breaker short-circuit) on BOTH platforms collapses to an empty ModuleResult |

## Refuted by verification — do not act

| # | Module | Claim |
|---|---|---|
| 3 | `src/modules/au_property/mod.rs` | au_property: NSW leg's 308→SPA redirect lands as a 200 and reads as "register consulted, no records" |

## Unverified leads (43) — re-derive before believing

| # | Module | Lead |
|---|---|---|
| 10 | `src/modules/dns_axfr/mod.rs` | dns_axfr: when no nameserver could be reached at all, the module reports "no zone-transfer exposure" — the exact fail-open its own doc comment forbids |
| 11 | `src/modules/data_gov_au/mod.rs` | data_gov_au: HTTP 404 from CKAN package_search is mapped to a clean "no matching agency" — but CKAN never 404s for a zero-match, and the module's own doc says a 404 means the endpoint path is wrong |
| 12 | `src/modules/comb_search/mod.rs` | comb_search: ProxyNova COMB signals a miss with 200 `{count:0, lines:[]}`, never 404 — mapping 404 to "not in COMB" turns an endpoint outage into a clean negative breach claim |
| 13 | `src/modules/comb_search/mod.rs` | comb_search: for a Username target, the subject's own Username entity is tagged `breach` and enriched with "N leaked credential line(s)" from strangers' same-local-part accounts, while the doc says username matches are candidate-quarantined |
| 14 | `src/modules/crossref_search/mod.rs` | crossref_search: doc claims an author/affiliation-name search but the request is the generic all-fields `query=`, so works ABOUT a name (or merely mentioning it) are minted as the subject's works |
| 15 | `src/modules/crates_io/mod.rs` | crates_io: a failure on the second (crate-listing) request discards the already-confirmed user entities from the first request |
| 16 | `src/modules/device_sensors/wifi.rs` | device_sensors/wifi.rs: absent sensor readings are asserted as literal 0 / "<hidden>" in evidence, contradicting the contract the sibling device_fix.rs states for the same sensor family |
| 17 | `src/modules/fofa/mod.rs` | FOFA HTTP-200 `error:true` envelope (dead key / quota) collapses to a clean empty result and never reaches the key pool |
| 18 | `src/modules/gaming_profile/mod.rs` | gaming_profile swallows every transport/HTTP failure on both platforms, so a total outage reads as 'no Roblox/Minecraft account' |
| 19 | `src/modules/doh_resolver/mod.rs` | doh_resolver never checks the HTTP status: a Cloudflare 400 `{"error":…}` body decodes as NOERROR/zero-records and is treated as an authoritative negative |
| 20 | `src/modules/exa_search/mod.rs` | exa_search sends snake_case body keys and reads snake_case response fields that Exa's documented API does not use (`numResults`, `contents.text.maxCharacters`, `publishedDate`) |
| 21 | `src/modules/europepmc_search/mod.rs` | europepmc_search maps a 404 on a fixed search endpoint to a clean miss, though Europe PMC signals 'no hits' as HTTP 200 / hitCount 0 |
| 22 | `src/modules/greynoise/mod.rs` | greynoise keyed path decodes the wrong /v3/ip schema — a configured key silently turns every IP into a clean negative |
| 23 | `src/modules/github_commits/mod.rs` | github_commits collapses every non-2xx — 5xx outage, 401 on a revoked token, 502/503 search degradation — into an empty ModuleResult |
| 24 | `src/modules/launchpad_user/mod.rs` | launchpad_user resolves Launchpad TEAMS as people — a team slug is minted as a confirmed user handle and its display name as a Person |
| 25 | `src/modules/ip_registry/mod.rs` | ip_registry's BGPView upstream no longer exists (api.bgpview.io is NXDOMAIN) — ASN targets always hard-error and the IP path silently loses its announcing-ASN/prefix/operator half |
| 26 | `src/modules/osintcat/mod.rs` | osintcat: after a passing credits preflight, failure of all three data endpoints collapses to a clean 'no footprint, no breach' negative (no or_hard_failure) |
| 27 | `src/modules/overpass/mod.rs` | overpass: an HTTP-200 `remark` runtime error (query timeout / memory limit) is read as 'no infrastructure within 500m' |
| 28 | `src/modules/mastodon_user/mod.rs` | mastodon_user: instance-probe failures are dropped without a log and a partial sweep (1 answered, 9 failed) still returns a clean negative for all ten instances |
| 29 | `src/modules/mylnikov/mod.rs` | mylnikov: every in-body `result` code other than 200 — not just the 404 miss — is folded into 'BSSID not located', and the provider's `desc` is never read |
| 30 | `src/modules/plc_directory/resolve.rs` | plc_directory: audit-log fetch failure (5xx/429/transport/breaker) collapses into 'no PLC history' clean miss |
| 31 | `src/modules/ripestat/mod.rs` | ripestat: every RIPEstat sub-fetch error is .ok()'d and the empty result is returned without or_hard_failure — a total outage reads as a clean negative |
| 32 | `src/modules/qld_cadastre/mod.rs` | qld_cadastre: ArcGIS HTTP-200 error envelope decodes to `features: []` and is reported as 'no cadastral parcel at this point' |
| 33 | `src/modules/pypi_user/mod.rs` | pypi_user: an XML-RPC `<fault>` (HTTP 200 — PyPI's rate-limit and deprecation signal) parses to zero package pairs and is reported as 'user has no packages / not on PyPI' |
| 34 | `src/modules/phone_geo/data.rs` | phone_geo: area-code pass geolocates a bare national number with no international marker — a US (817)/(813)/(814) number is minted as a Kyoto/Tokyo/Yokohama, Japan Address + Coordinates |
| 35 | `src/modules/sanctions_ofac/list.rs` | sanctions_ofac: Consolidated (non-SDN) list rows are merged untagged and every hit is reported as an 'OFAC SDN list match' with register = 'Specially Designated Nationals (SDN) List' |
| 36 | `src/modules/pgp/mod.rs` | pgp: a transport error while streaming the keyserver body is reported as 'no PGP key for this email' |
| 37 | `src/modules/rubygems_user/mod.rs` | rubygems_user: the GitHub org/user segment of every gem's `source_code_uri` is minted as the subject's Username at HIGH_PLUS, attributing third-party org accounts to the handle |
| 38 | `src/modules/social_probe/mod.rs` | social_probe mints a 0.92 'verified-detection' adult/cam profile from an EMPTY body when the page exceeds curl's 8 KB cap |
| 39 | `src/modules/shodan/mod.rs` | shodan (keyless InternetDB path) swallows 429/5xx/transport failures into an empty 'no ports, no CVEs' result |
| 40 | `src/modules/stolen_tax/mod.rs` | stolen_tax maps any non-key in-body error envelope (success:false) to a clean empty result on a key-gated paid lookup |
| 41 | `src/modules/smtp_vrfy/mod.rs` | smtp_vrfy tags a 4yz transient SMTP reply (greylisting, 452, 421) as smtp-invalid |
| 42 | `src/modules/social_location/mod.rs` | social_location parses the body of ANY status (403/429/5xx) with no status gate, collapsing a refusal into 'no location' |
| 43 | `src/modules/sunrise_sunset/mod.rs` | sunrise_sunset turns the provider's documented UNKNOWN_ERROR (server-side failure) into a clean empty result |
| 44 | `src/modules/stackoverflow_user/mod.rs` | stackoverflow_user attributes the FIRST reputation-sorted display-name match's website, location and cross-SE footprint to the seed handle (display names are not unique) |
| 45 | `src/modules/structured_id/mod.rs` | structured_id's ObjectID decoder mints an 'account-age' date from roughly one in five arbitrary 24-hex tokens, contradicting the module's own no-fabrication claim |
| 46 | `src/modules/trove_au/mod.rs` | trove_au decodes the Trove v2 response shape (`response.zone[]`) from the v3 endpoint, so every search silently reads as zero hits |
| 47 | `src/modules/whois/mod.rs` | whois parses IANA's TLD record as the target domain's WHOIS when the referral hop fails, minting fabricated registration data and 13 root-server `whois-ns` Domain entities |
| 48 | `src/modules/urlscan/mod.rs` | urlscan attributes third-party pages' IPs, domains, countries and ASNs to a Domain target because `domain:` matches any contacted resource domain |
| 49 | `src/modules/urlscan/mod.rs` | urlscan reads `verdicts.malicious` from search hits, which never carry `verdicts` — the documented `urlscan-malicious` tag can never fire |
| 50 | `src/modules/urlhaus/mod.rs` | urlhaus never reports a 429 on the configured Auth-Key to the pool (and folds a rejected key into a clean empty result) |
| 51 | `src/modules/wiki_geosearch/mod.rs` | wiki_geosearch treats a MediaWiki HTTP-200 `error` envelope as "no nearby places" |
| 52 | `src/modules/wikidata/mod.rs` | wikidata treats a MediaWiki HTTP-200 `error` envelope on `wbsearchentities` as "no matching item" |
