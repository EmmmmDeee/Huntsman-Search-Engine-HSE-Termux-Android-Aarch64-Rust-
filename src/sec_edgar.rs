//! SEC EDGAR people/corporate lookup. Keyless -- the public US Securities and Exchange Commission
//! EDGAR APIs (`GET https://efts.sec.gov/LATEST/search-index` full-text search over filings, then
//! `GET https://data.sec.gov/submissions/CIK##########.json` for a filer profile).
//!
//! A `people NAME` lookup ([`crate::people_cli`]) that names a person or company with SEC filings
//! also queries EDGAR, beside the ASIC registers, Wikidata and the ACNC charity register. The
//! full-text search over insider forms (3, 4, 5) resolves the name to the Central Index Keys (CIKs)
//! of the filers whose published filing name actually matches, and each matched CIK's submissions profile
//! is folded in as a candidate: the filer as an [`EntityKind::Person`] or [`EntityKind::Organisation`]
//! (a name match in an authoritative register, never a confirmed identity of the queried person),
//! its official website as an [`EntityKind::Domain`] and [`EntityKind::Url`] pivot, and its business
//! and mailing [`EntityKind::Address`] the geocoder can forward-geocode. The entity's LEI is kept as
//! a verbatim correlation key that joins the wired `gleif` leg; its CIK, tickers, exchanges, SIC,
//! former names and category ride as evidence. Every published field is kept verbatim; nothing is
//! redacted.
//!
//! EDGAR needs no key or login; its only fair-access requirement is a declared, contactable
//! User-Agent (a missing or generic one is refused with 403) and a bounded request rate. This client
//! sends an honest tool-identifying User-Agent naming the project -- never a browser impersonation
//! and never a person's private contact.
//!
//! Evidence integrity is fail-closed, mirroring `gleif` and `acnc`: a challenge page, a truncated
//! body or an unreadable/contract-breaking envelope is schema drift, never evidence; only a filer
//! whose published filing name matches the queried name becomes a candidate, so a loose full-text rank never
//! fabricates an unrelated filer onto the name; a submissions document whose own CIK is not the
//! requested one is schema drift, never attributed. An empty search is a clean zero -- most people
//! have no EDGAR presence, so a zero result is the honest common answer, never a failure. The filer
//! candidates are tagged [`crate::tags::NAME_SEARCH_LEAD`], so [`crate::recursion`] keeps a
//! name-matched filer as a visible lead but never auto-dispatches it onto a potentially unrelated
//! third party, whatever the operator's expansion floor.

use serde::Deserialize;

use crate::canonical::canonical_domain;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Transport, percent_encode_unreserved};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::textnorm::{name_tokens, whole_word_token_match};
use crate::value_syntax::host_only;

pub const SOURCE: &str = "sec_edgar";
const EFTS_BASE: &str = "https://efts.sec.gov/LATEST/search-index";
const SUBMISSIONS_BASE: &str = "https://data.sec.gov/submissions";
const DATASET: &str = "SEC EDGAR";

/// The honest, contactable User-Agent EDGAR's fair-access policy requires: the tool and a project
/// URL where the operator can be reached, never a browser impersonation and never a person's private
/// email. EDGAR refuses a missing or generic User-Agent with 403, so this is sent on every request.
pub const SEC_USER_AGENT: &str = concat!(
    "huntsman-recon/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-)"
);

/// Insider forms the full-text search is scoped to: initial ownership (3), changes (4) and annual
/// statements (5) -- where a person appears as an officer, director or 10% owner.
const INSIDER_FORMS: &str = "3,4,5";
/// The most name-matched filers to deepen, so a common name cannot fan out into an unbounded number
/// of submissions requests.
const MAX_FILERS: usize = 5;
/// The most full-text hits scanned for distinct matched filers.
const MAX_HITS: usize = 40;

/// A filer candidate: a name match in an authoritative filing index, not a confirmed identity of the
/// queried person.
const FILER_CONF: f64 = 0.55;
/// The filer's official website.
const WEBSITE_CONF: f64 = 0.50;
/// A registered business or mailing address.
const ADDRESS_CONF: f64 = 0.55;

/// One name lookup on SEC EDGAR.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

/// The full-text search envelope: `{hits: {total: {value}, hits: [{_source}]}}`.
#[derive(Debug, Deserialize)]
struct EftsResp {
    hits: Option<EftsHits>,
}

#[derive(Debug, Deserialize)]
struct EftsHits {
    // A missing hits array is schema drift, not an observed empty index.
    hits: Option<Vec<EftsHit>>,
}

#[derive(Debug, Deserialize)]
struct EftsHit {
    #[serde(default, rename = "_source")]
    source: Option<EftsSource>,
}

#[derive(Debug, Deserialize)]
struct EftsSource {
    #[serde(default)]
    ciks: Vec<String>,
    #[serde(default)]
    display_names: Vec<String>,
}

/// The submissions profile envelope (the fields modelled; EDGAR sends more, kept verbatim where read).
#[derive(Debug, Deserialize)]
struct Submission {
    #[serde(default)]
    cik: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "entityType")]
    entity_type: Option<String>,
    #[serde(default)]
    sic: Option<String>,
    #[serde(default, rename = "sicDescription")]
    sic_description: Option<String>,
    #[serde(default)]
    ein: Option<String>,
    #[serde(default)]
    lei: Option<String>,
    #[serde(default)]
    website: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default, rename = "stateOfIncorporation")]
    state_of_incorporation: Option<String>,
    #[serde(default)]
    tickers: Vec<String>,
    #[serde(default)]
    exchanges: Vec<String>,
    #[serde(default)]
    phone: Option<String>,
    #[serde(default, rename = "formerNames")]
    former_names: Vec<FormerName>,
    #[serde(default)]
    addresses: Option<Addresses>,
}

#[derive(Debug, Deserialize)]
struct FormerName {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Addresses {
    #[serde(default)]
    business: Option<Addr>,
    #[serde(default)]
    mailing: Option<Addr>,
}

#[derive(Debug, Deserialize)]
struct Addr {
    #[serde(default)]
    street1: Option<String>,
    #[serde(default)]
    street2: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default, rename = "stateOrCountry")]
    state_or_country: Option<String>,
    #[serde(default, rename = "zipCode")]
    zip_code: Option<String>,
    #[serde(default, rename = "countryCode")]
    country_code: Option<String>,
}

/// A filer the full-text search matched to the queried name: its CIK and the name EDGAR publishes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MatchedFiler {
    cik: String,
    display_name: String,
}

fn request(url: String) -> Request {
    Request::get(url)
        .header("accept", "application/json")
        .header("user-agent", SEC_USER_AGENT)
}

fn options() -> FetchOptions {
    FetchOptions::no_redirects().paced()
}

/// The full-text search URL for `name` over the insider forms. The quoted phrase is percent-encoded.
/// **Pure.**
#[must_use]
pub fn search_url(name: &str) -> String {
    format!(
        "{EFTS_BASE}?q=%22{}%22&forms={INSIDER_FORMS}",
        percent_encode_unreserved(name.trim())
    )
}

/// The submissions-profile URL for a 10-digit zero-padded CIK. `cik` is validated as ten digits
/// before this is built, so it needs no escaping. **Pure.**
#[must_use]
pub fn submissions_url(cik: &str) -> String {
    format!("{SUBMISSIONS_BASE}/CIK{cik}.json")
}

/// Look up `name` on SEC EDGAR: resolve it to matching filers through the full-text search, then fold
/// in each matched filer's submissions profile as a candidate.
///
/// A name with fewer than two alphabetic tokens makes no request (mirroring the other people-leg
/// registers; `people_cli` enforces the same name shape upstream).
///
/// # Errors
///
/// [`Error::Network`] when egress blocks a request.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    name: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    if name_tokens(name).len() < 2 {
        return Ok(miss(SourceExecutionOutcome::valid_zero(SOURCE, now_unix)));
    }

    let searched = fetch(
        transport,
        request(search_url(name)),
        None,
        &options(),
        SOURCE,
        now_unix,
    )?;
    let filers = match interpret_search(&searched, name, now_unix) {
        Ok(filers) => filers,
        Err(outcome) => return Ok(miss(outcome)),
    };
    if filers.is_empty() {
        return Ok(miss(
            SourceExecutionOutcome::valid_zero(SOURCE, now_unix).with_http_status(200),
        ));
    }

    let mut entities = Vec::new();
    // The real verdict of the last matched filer whose submissions profile could not be read, so an
    // all-unreadable result reports the true status and kind (a 429, 503, challenge or timeout keeps
    // its own), never a fabricated HTTP 200. Entities are NOT merged here: `people_cli` scopes each
    // filer by its CIK and merges after, so two same-name distinct-CIK filers stay distinct.
    let mut unreadable: Option<SourceExecutionOutcome> = None;
    for filer in filers.iter().take(MAX_FILERS) {
        let fetched = match fetch(
            transport,
            request(submissions_url(&filer.cik)),
            None,
            &options(),
            SOURCE,
            now_unix,
        ) {
            Ok(fetched) => fetched,
            // An egress block on a submissions request: keep candidates already built; only when
            // none were does the leg surface the network error, never a fabricated zero.
            Err(err) => {
                if entities.is_empty() {
                    return Err(err);
                }
                break;
            }
        };
        if !build_from_submission(&fetched, filer, scan_id, &mut entities) {
            unreadable = Some(fetched.outcome.clone());
        }
    }

    let outcome = if !entities.is_empty() {
        SourceExecutionOutcome::success(SOURCE, now_unix, entities.len()).with_http_status(200)
    } else if let Some(outcome) = unreadable {
        // A matched filer whose submissions profile could not be read: the real per-request verdict
        // (its own status and kind) stands, so a 429/503/challenge/timeout is never a fabricated 200.
        outcome
    } else {
        SourceExecutionOutcome::valid_zero(SOURCE, now_unix).with_http_status(200)
    };
    Ok(Report { entities, outcome })
}

/// A report that found nothing, carrying only its outcome. **Pure.**
fn miss(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

/// The distinct filers the full-text search matched to the queried name, most-frequent first, or the
/// outcome of a search that named nothing usable. A 404 or an empty hits array is a clean zero; a
/// missing hits array or an unreadable body is schema drift. **Pure.**
fn interpret_search(
    fetched: &Fetched,
    query: &str,
    now_unix: u64,
) -> Result<Vec<MatchedFiler>, SourceExecutionOutcome> {
    if let Some(response) = &fetched.response {
        if response.status == 404 && fetched.outcome.kind == SourceOutcomeKind::Upstream4xx {
            return Err(SourceExecutionOutcome::valid_zero(SOURCE, now_unix)
                .with_http_status(response.status));
        }
    }
    let response = whole_response(fetched, "EDGAR search")?;
    answer(fetched, "EDGAR search")?;
    let resp: EftsResp = decode_json(response, SOURCE, now_unix, "EDGAR search")?;
    let Some(hits) = resp.hits.and_then(|h| h.hits) else {
        return Err(SourceExecutionOutcome::failed(
            SOURCE,
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            "EDGAR search response lacked the required hits array",
        ));
    };
    Ok(matched_filers(&hits, query))
}

/// The distinct name-matched filers across the scanned hits, in first-seen order. Each hit lists its
/// filing's entities as index-aligned `ciks` and `display_names`; only an entity whose published
/// name matches the queried name as whole words is kept, so a co-filed issuer or an unrelated
/// full-text rank is never attributed to the query. **Pure.**
fn matched_filers(hits: &[EftsHit], query: &str) -> Vec<MatchedFiler> {
    let mut filers: Vec<MatchedFiler> = Vec::new();
    for hit in hits.iter().take(MAX_HITS) {
        let Some(source) = hit.source.as_ref() else {
            continue;
        };
        for (cik, display_name) in source.ciks.iter().zip(source.display_names.iter()) {
            let Some(cik) = canonical_cik(cik) else {
                continue;
            };
            let name = filer_name(display_name);
            if !whole_word_token_match(name, query) {
                continue;
            }
            if filers.iter().any(|existing| existing.cik == cik) {
                continue;
            }
            filers.push(MatchedFiler {
                cik,
                display_name: name.to_owned(),
            });
        }
    }
    filers
}

/// `cik` as a canonical 10-digit CIK when it is one (EDGAR already zero-pads them), else `None`.
/// **Pure.**
fn canonical_cik(cik: &str) -> Option<String> {
    let trimmed = cik.trim();
    (trimmed.len() == 10 && trimmed.bytes().all(|b| b.is_ascii_digit())).then(|| trimmed.to_owned())
}

/// The filer's name from an EDGAR `display_name`: everything before the first two-space group that
/// introduces a `(TICKER)` or `(CIK ...)` suffix. **Pure.**
fn filer_name(display_name: &str) -> &str {
    display_name
        .split("  (")
        .next()
        .unwrap_or(display_name)
        .trim()
}

/// Build the candidate for one matched filer from its submissions profile, appending to `entities`
/// and returning whether the filer entity was emitted. A 404, an unreadable or truncated body, or a
/// document whose own CIK is not the requested one emits nothing and returns `false` (fail-closed):
/// the filer is simply not deepened, never fabricated. **Pure.**
fn build_from_submission(
    fetched: &Fetched,
    filer: &MatchedFiler,
    scan_id: &str,
    entities: &mut Vec<Entity>,
) -> bool {
    let Some(response) = &fetched.response else {
        return false;
    };
    if !fetched.outcome.kind.is_accepted()
        && fetched.outcome.kind != SourceOutcomeKind::Inconclusive
    {
        return false;
    }
    if response.truncated {
        return false;
    }
    let Ok(submission) = crate::http::parse_json_body::<Submission>(response) else {
        return false;
    };
    // The document must be the requested filer's own profile; a mismatched CIK is schema drift.
    if submission.cik.as_deref().and_then(canonical_cik).as_deref() != Some(filer.cik.as_str()) {
        return false;
    }
    let name = submission
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or(filer.display_name.as_str())
        .to_owned();
    let evidence = filer_evidence(&submission, filer, &name, scan_id);

    let mut filer_entity = Entity::new(filer_kind(&submission), &name, FILER_CONF, scan_id);
    filer_entity.tag(SOURCE);
    filer_entity.tag("sec-edgar");
    filer_entity.tag("us");
    filer_entity.tag("country:US");
    filer_entity.tag(crate::tags::NAME_SEARCH_LEAD);
    filer_entity.tag(crate::tags::CANDIDATE);
    filer_entity.add_evidence(evidence);
    entities.push(filer_entity);

    push_website(&submission, &name, scan_id, entities);
    push_addresses(&submission, &name, scan_id, entities);
    true
}

/// Whether the submissions profile describes a company (an operating entity, or one with tickers,
/// exchanges or a real SIC) or an individual. Company signals are positive; their absence leaves an
/// individual filer. Either way the entity is only ever a candidate. **Pure.**
fn filer_kind(submission: &Submission) -> EntityKind {
    let operating = submission
        .entity_type
        .as_deref()
        .is_some_and(|kind| kind.eq_ignore_ascii_case("operating"));
    let has_market = !submission.tickers.is_empty() || !submission.exchanges.is_empty();
    let has_sic = submission
        .sic
        .as_deref()
        .map(str::trim)
        .is_some_and(|sic| !sic.is_empty() && sic != "0000");
    if operating || has_market || has_sic {
        EntityKind::Organisation
    } else {
        EntityKind::Person
    }
}

/// The shared evidence for every entity of one filer: its CIK and every modelled profile field, kept
/// verbatim (no redaction). **Pure.**
fn filer_evidence(
    submission: &Submission,
    filer: &MatchedFiler,
    name: &str,
    scan_id: &str,
) -> Evidence {
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(SOURCE, scan_id),
        format!(
            "SEC EDGAR filer {name} (CIK {}): a filing-index name match, a candidate to review, not a confirmed identity",
            filer.cik
        ),
    )
    .with_attr("dataset", DATASET)
    .with_attr("cik", &filer.cik)
    .with_optional_attrs([
        ("entity_type", trimmed(submission.entity_type.as_deref())),
        ("sic", trimmed(submission.sic.as_deref())),
        ("sic_description", trimmed(submission.sic_description.as_deref())),
        ("ein", trimmed(submission.ein.as_deref())),
        ("lei", trimmed(submission.lei.as_deref())),
        ("category", trimmed(submission.category.as_deref())),
        (
            "state_of_incorporation",
            trimmed(submission.state_of_incorporation.as_deref()),
        ),
        ("phone", trimmed(submission.phone.as_deref())),
    ]);
    if !submission.tickers.is_empty() {
        evidence = evidence.with_attr("tickers", join_trimmed(&submission.tickers));
    }
    if !submission.exchanges.is_empty() {
        evidence = evidence.with_attr("exchanges", join_trimmed(&submission.exchanges));
    }
    let former = former_names(submission);
    if !former.is_empty() {
        evidence = evidence.with_attr("former_names", former.join(", "));
    }
    evidence
}

/// The filer's official website as a [`EntityKind::Url`] and its host as a [`EntityKind::Domain`]
/// pivot into the wired domain-recon cluster, when the profile publishes one. **Pure.**
fn push_website(submission: &Submission, name: &str, scan_id: &str, entities: &mut Vec<Entity>) {
    let Some(website) = trimmed(submission.website.as_deref()) else {
        return;
    };
    let mut url = Entity::new(EntityKind::Url, website, WEBSITE_CONF, scan_id);
    url.tag(SOURCE);
    url.tag("sec-edgar");
    url.tag("official-website");
    url.tag(crate::tags::NAME_SEARCH_LEAD);
    url.add_evidence(website_evidence(name, website, scan_id));
    entities.push(url);

    if let Some(domain) = canonical_domain(host_only(website)) {
        let mut entity = Entity::new(EntityKind::Domain, &domain, WEBSITE_CONF, scan_id);
        entity.tag(SOURCE);
        entity.tag("sec-edgar");
        entity.tag("official-website");
        entity.tag(crate::tags::NAME_SEARCH_LEAD);
        entity.add_evidence(website_evidence(name, website, scan_id));
        entities.push(entity);
    }
}

fn website_evidence(name: &str, website: &str, scan_id: &str) -> Evidence {
    Evidence::new(
        EvidenceProvenance::for_scan(SOURCE, scan_id),
        format!("Official website of SEC EDGAR filer {name} (a lead to review, not an automatically dispatched pivot)"),
    )
    .with_attr("website", website)
    .with_attr("filer", name)
}

/// The filer's business and mailing addresses as [`EntityKind::Address`] pivots the geocoder can
/// forward-geocode; identical flattened addresses dedup through [`merge_by_uid`]. **Pure.**
fn push_addresses(submission: &Submission, name: &str, scan_id: &str, entities: &mut Vec<Entity>) {
    let Some(addresses) = submission.addresses.as_ref() else {
        return;
    };
    for (addr, role) in [
        (addresses.business.as_ref(), "business"),
        (addresses.mailing.as_ref(), "mailing"),
    ] {
        let Some(flat) = addr.and_then(flatten_address) else {
            continue;
        };
        let mut address = Entity::new(EntityKind::Address, &flat, ADDRESS_CONF, scan_id);
        address.tag(SOURCE);
        address.tag("sec-edgar");
        address.tag(format!("sec-edgar-{role}-address"));
        address.add_evidence(
            Evidence::new(
                EvidenceProvenance::for_scan(SOURCE, scan_id),
                format!("{role} address of SEC EDGAR filer {name}"),
            )
            .with_attr("address", &flat)
            .with_attr("address_role", role)
            .with_attr("filer", name),
        );
        entities.push(address);
    }
}

/// One address flattened to a single line the geocoder can read: street lines then city, state or
/// country, zip and country code, each non-empty part once, comma-separated. `None` when every part
/// is blank. **Pure.**
fn flatten_address(addr: &Addr) -> Option<String> {
    let parts = [
        addr.street1.as_deref(),
        addr.street2.as_deref(),
        addr.city.as_deref(),
        addr.state_or_country.as_deref(),
        addr.zip_code.as_deref(),
        addr.country_code.as_deref(),
    ];
    let flat = parts
        .into_iter()
        .flatten()
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(", ");
    (!flat.is_empty()).then_some(flat)
}

/// The filer's former names, each non-empty and trimmed, kept verbatim for coreference. **Pure.**
fn former_names(submission: &Submission) -> Vec<String> {
    submission
        .former_names
        .iter()
        .filter_map(|former| trimmed(former.name.as_deref()))
        .map(str::to_owned)
        .collect()
}

/// The non-empty trimmed strings of `values`, comma-joined. **Pure.**
fn join_trimmed(values: &[String]) -> String {
    values
        .iter()
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

/// `value` trimmed, when it is present and not blank. **Pure.**
fn trimmed(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|text| !text.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{ScriptedTransport, json_ok};

    // A realistic EFTS search envelope for "elon musk" over insider forms: the person is co-filed
    // with the issuer, so a hit lists both, index-aligned.
    const SEARCH: &str = r#"{"hits":{"total":{"value":2,"relation":"eq"},"hits":[
        {"_index":"edgar_file","_id":"a:1.xml","_source":{
            "ciks":["0001494730","0001318605"],
            "display_names":["Musk Elon  (CIK 0001494730)","Tesla, Inc.  (TSLA)  (CIK 0001318605)"],
            "form":"4","file_date":"2026-06-11"}}
    ]}}"#;

    // The individual filer's submissions profile: no tickers/sic -> Person.
    const PERSON: &str = r#"{"cik":"0001494730","name":"Musk Elon","entityType":"","sic":"","sicDescription":"",
        "ein":"","lei":null,"website":"","category":"","stateOfIncorporation":"","tickers":[],"exchanges":[],
        "phone":"","formerNames":[],
        "addresses":{"business":{"street1":"1 Rocket Rd","street2":null,"city":"Hawthorne","stateOrCountry":"CA","zipCode":"90250","countryCode":null},
        "mailing":{"street1":"1 Rocket Rd","street2":null,"city":"Hawthorne","stateOrCountry":"CA","zipCode":"90250","countryCode":null}}}"#;

    // A company filer's profile: operating + tickers + website -> Organisation with rich pivots.
    const COMPANY_SEARCH: &str = r#"{"hits":{"total":{"value":1,"relation":"eq"},"hits":[
        {"_source":{"ciks":["0000320193"],"display_names":["Apple Inc.  (AAPL)  (CIK 0000320193)"],"form":"4","file_date":"2026-10-29"}}
    ]}}"#;
    const COMPANY: &str = r#"{"cik":"0000320193","name":"Apple Inc.","entityType":"operating","sic":"3571",
        "sicDescription":"Electronic Computers","ein":"942404110","lei":"HWUPKR0MPOU8FGXBT394","website":"https://www.apple.com",
        "category":"Large accelerated filer","stateOfIncorporation":"CA","tickers":["AAPL"],"exchanges":["Nasdaq"],
        "phone":"(408) 996-1010","formerNames":[{"name":"APPLE COMPUTER INC"}],
        "addresses":{"business":{"street1":"ONE APPLE PARK WAY","street2":null,"city":"CUPERTINO","stateOrCountry":"CA","zipCode":"95014","countryCode":null},
        "mailing":{"street1":"ONE APPLE PARK WAY","street2":null,"city":"CUPERTINO","stateOrCountry":"CA","zipCode":"95014","countryCode":null}}}"#;

    fn has(report: &Report, kind: &EntityKind, value: &str) -> bool {
        report
            .entities
            .iter()
            .any(|entity| entity.kind == *kind && entity.raw_value == value)
    }

    fn filer<'a>(report: &'a Report, kind: &EntityKind) -> &'a Entity {
        report
            .entities
            .iter()
            .find(|entity| entity.kind == *kind)
            .expect("a filer entity")
    }

    #[test]
    fn a_matched_person_yields_a_person_candidate_with_address() {
        let transport = ScriptedTransport::new(vec![Ok(json_ok(SEARCH)), Ok(json_ok(PERSON))]);
        let report = lookup(&transport, "elon musk", "scan-edgar", 1).expect("runs");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        // The person is a Person candidate; the co-filed issuer Tesla is NOT attributed to the query.
        assert!(has(&report, &EntityKind::Person, "Musk Elon"));
        assert!(
            !report
                .entities
                .iter()
                .any(|entity| entity.raw_value.contains("Tesla")),
            "the co-filed issuer must not be attributed to a person-name query: {:#?}",
            report.entities
        );
        assert!(
            report
                .entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Address
                    && entity.raw_value.contains("Hawthorne"))
        );
    }

    #[test]
    fn the_person_candidate_is_tagged_a_name_search_lead() {
        let transport = ScriptedTransport::new(vec![Ok(json_ok(SEARCH)), Ok(json_ok(PERSON))]);
        let report = lookup(&transport, "elon musk", "scan-edgar", 1).expect("runs");
        let person = filer(&report, &EntityKind::Person);
        assert!(
            person.has_tag(crate::tags::NAME_SEARCH_LEAD),
            "a filing-index name match must be a reviewable lead, never auto-dispatched: {:?}",
            person.tags
        );
        // A name match is a candidate, never a confirmed identity.
        assert!(person.confidence < 0.9, "{}", person.confidence);
    }

    #[test]
    fn a_company_profile_yields_an_organisation_with_website_domain_and_lei() {
        let transport =
            ScriptedTransport::new(vec![Ok(json_ok(COMPANY_SEARCH)), Ok(json_ok(COMPANY))]);
        let report = lookup(&transport, "apple inc", "scan-edgar", 1).expect("runs");
        assert!(has(&report, &EntityKind::Organisation, "Apple Inc."));
        // The website is both a Url and a Domain lead into the wired domain-recon cluster.
        assert!(has(&report, &EntityKind::Url, "https://www.apple.com"));
        assert!(has(&report, &EntityKind::Domain, "www.apple.com"));
        assert!(
            report
                .entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Address
                    && entity.raw_value.contains("CUPERTINO"))
        );
        // The LEI is kept verbatim as a correlation key that joins the gleif leg.
        let org = filer(&report, &EntityKind::Organisation);
        let evidence = org.evidence.first().expect("org evidence");
        assert_eq!(
            evidence.attributes.get("lei").map(String::as_str),
            Some("HWUPKR0MPOU8FGXBT394")
        );
        assert_eq!(
            evidence.attributes.get("tickers").map(String::as_str),
            Some("AAPL")
        );
    }

    #[test]
    fn a_fulltext_rank_hit_on_an_unrelated_filer_is_not_attributed() {
        // The full-text index ranks loosely: a filing whose filers do not bear the queried name as
        // whole words must never be minted onto the name.
        let unrelated = r#"{"hits":{"total":{"value":1,"relation":"eq"},"hits":[
            {"_source":{"ciks":["0000111111"],"display_names":["Rivertown Holdings LLC  (CIK 0000111111)"],"form":"4"}}
        ]}}"#;
        let transport = ScriptedTransport::new(vec![Ok(json_ok(unrelated))]);
        let report = lookup(&transport, "elon musk", "scan-edgar", 1).expect("runs");
        assert!(report.entities.is_empty(), "{:#?}", report.entities);
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
        // Only the search ran; no submissions request for an unmatched filer.
        assert_eq!(transport.seen.borrow().len(), 1);
    }

    #[test]
    fn a_submissions_cik_mismatch_is_not_attributed() {
        // The submissions document must be the requested filer's own profile; a document whose CIK
        // is a different filer is schema drift, never minted onto the matched name.
        let wrong = r#"{"cik":"0009999999","name":"Someone Else Inc","entityType":"operating","tickers":["XXX"]}"#;
        let transport = ScriptedTransport::new(vec![Ok(json_ok(SEARCH)), Ok(json_ok(wrong))]);
        let report = lookup(&transport, "elon musk", "scan-edgar", 1).expect("runs");
        assert!(
            !report
                .entities
                .iter()
                .any(|entity| entity.raw_value.contains("Someone Else")),
            "a CIK-mismatched submissions document must not be attributed: {:#?}",
            report.entities
        );
        // No readable profile for the matched filer -> inconclusive, never a fabricated success.
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Inconclusive);
    }

    #[test]
    fn two_distinct_cik_filers_with_one_name_stay_two_candidates() {
        // Same-name, distinct-CIK filers are common on insider forms. The leg must not fuse them
        // into one entity before people_cli scopes each by its CIK, or distinct real filers and
        // their evidence would be conflated under a single identity.
        let search = r#"{"hits":{"total":{"value":2,"relation":"eq"},"hits":[
            {"_source":{"ciks":["0001111111","0002222222"],
             "display_names":["Smith John  (CIK 0001111111)","Smith John  (CIK 0002222222)"]}}
        ]}}"#;
        let one = r#"{"cik":"0001111111","name":"Smith John","entityType":"","tickers":[],"exchanges":[]}"#;
        let two = r#"{"cik":"0002222222","name":"Smith John","entityType":"","tickers":[],"exchanges":[]}"#;
        let transport = ScriptedTransport::new(vec![
            Ok(json_ok(search)),
            Ok(json_ok(one)),
            Ok(json_ok(two)),
        ]);
        let report = lookup(&transport, "john smith", "scan-edgar", 1).expect("runs");
        let people = report
            .entities
            .iter()
            .filter(|entity| entity.kind == EntityKind::Person)
            .count();
        assert_eq!(
            people, 2,
            "two distinct-CIK filers sharing a name must not be fused: {:#?}",
            report.entities
        );
        // Each carries its own CIK, so people_cli's CIK scoping keeps them distinct downstream.
        let cik = |value: &str| {
            report.entities.iter().any(|entity| {
                entity
                    .evidence
                    .iter()
                    .any(|ev| ev.attributes.get("cik").map(String::as_str) == Some(value))
            })
        };
        assert!(
            cik("0001111111") && cik("0002222222"),
            "{:#?}",
            report.entities
        );
    }

    #[test]
    fn a_submissions_rate_limit_is_not_reported_as_a_clean_zero() {
        // A matched filer whose submissions request is throttled must surface the real verdict,
        // never a fabricated HTTP 200 "matched but empty" that masks the throttle.
        let rate_limited = crate::http::Response {
            status: 429,
            headers: Vec::new(),
            body: b"{}".to_vec(),
            truncated: false,
        };
        let transport = ScriptedTransport::new(vec![Ok(json_ok(SEARCH)), Ok(rate_limited)]);
        let report = lookup(&transport, "elon musk", "scan-edgar", 1).expect("runs");
        assert!(report.entities.is_empty(), "{:#?}", report.entities);
        // The real throttle verdict must stand: not an accepted answer, and not the old fabricated
        // "inconclusive, HTTP 200, matched but empty" that masked the throttle.
        assert!(
            !report.outcome.kind.is_accepted(),
            "a throttled submissions fetch must not read as an accepted answer: {:?}",
            report.outcome.kind
        );
        assert_ne!(
            report.outcome.kind,
            SourceOutcomeKind::Inconclusive,
            "the throttle must not be masked as an inconclusive non-answer: {:?}",
            report.outcome
        );
    }

    #[test]
    fn a_single_token_name_makes_no_request() {
        let transport = ScriptedTransport::new(vec![]);
        let report = lookup(&transport, "musk", "scan-edgar", 1).expect("runs");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
        assert!(
            transport.seen.borrow().is_empty(),
            "no request for one token"
        );
    }

    #[test]
    fn an_empty_search_is_a_clean_zero() {
        let empty = r#"{"hits":{"total":{"value":0,"relation":"eq"},"hits":[]}}"#;
        let transport = ScriptedTransport::new(vec![Ok(json_ok(empty))]);
        let report = lookup(&transport, "nobody atall", "scan-edgar", 1).expect("runs");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn a_missing_hits_array_is_schema_drift_not_a_clean_zero() {
        let drift = r#"{"took":5,"timed_out":false}"#;
        let transport = ScriptedTransport::new(vec![Ok(json_ok(drift))]);
        let report = lookup(&transport, "elon musk", "scan-edgar", 1).expect("runs");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn the_sec_user_agent_names_the_tool_and_a_project_contact_not_a_person() {
        // EDGAR 403s a missing/generic UA; the client must declare a contactable tool UA, and must
        // never leak a person's private contact.
        assert!(SEC_USER_AGENT.starts_with("huntsman-recon/"));
        assert!(SEC_USER_AGENT.contains("github.com"));
        assert!(
            !SEC_USER_AGENT.contains('@'),
            "the User-Agent must not carry a personal email"
        );
    }

    #[test]
    fn filer_name_strips_the_ticker_and_cik_suffixes() {
        assert_eq!(filer_name("Musk Elon  (CIK 0001494730)"), "Musk Elon");
        assert_eq!(
            filer_name("Tesla, Inc.  (TSLA)  (CIK 0001318605)"),
            "Tesla, Inc."
        );
        assert_eq!(filer_name("Plainname"), "Plainname");
    }

    #[test]
    fn the_search_url_quotes_and_encodes_the_name() {
        assert_eq!(
            search_url("Elon Musk"),
            "https://efts.sec.gov/LATEST/search-index?q=%22Elon%20Musk%22&forms=3,4,5"
        );
    }
}
