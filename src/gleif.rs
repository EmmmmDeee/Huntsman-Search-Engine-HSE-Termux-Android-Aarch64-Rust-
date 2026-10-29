//! GLEIF Legal Entity Identifier lookup. Keyless -- the official public GLEIF API
//! (`GET /api/v1/lei-records/{LEI}`, or `GET /api/v1/lei-records?filter[fulltext]={q}` for free text).
//!
//! The Global Legal Entity Identifier Foundation runs the authoritative public register of LEIs: a
//! 20-character code identifying a legal entity. This source turns a query -- an LEI, or a company
//! name resolved to its top matching record -- into the registered entity. The record's legal name
//! is an [`EntityKind::Organisation`] (a candidate to review, never a confirmed real-world identity),
//! its legal and headquarters addresses are [`EntityKind::Address`] pivots the geocoder can
//! forward-geocode, and an Australian entity's local registration number is a checksum-validated
//! [`EntityKind::AbnAcn`] that feeds the ASIC director correlation.
//!
//! This wires three dangling pathways to a real producer: the `gleif_lei` source id the correlator's
//! `identity_registry` family already references, the `LEI` structured-field type, and the
//! `legal_entity_identifier` (P1278) pivot Wikidata emits.
//!
//! Evidence integrity is fail-closed, mirroring the merged `wikidata`/`crates_io` hardening: a record
//! is accepted only when the response envelope is a `lei-records` object whose `id` (or
//! `attributes.lei`) is exactly the requested LEI -- a mismatched or malformed envelope is schema
//! drift, never a positive entity, and an unknown LEI (404) or an empty search is a clean zero. Every
//! registry field is kept verbatim as evidence; nothing is redacted and no classification is invented.

use serde::Deserialize;

use crate::au_id::is_valid_acn;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{DEFAULT_USER_AGENT, Request, Transport, percent_encode_unreserved};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::textnorm::ascii_digits;

pub const SOURCE: &str = "gleif_lei";
const PUBLIC_BASE: &str = "https://api.gleif.org";
const DATASET: &str = "GLEIF";

/// An LEI is exactly 20 ASCII alphanumeric characters (ISO 17442).
const LEI_LEN: usize = 20;

/// The registered legal name: an official register record, a candidate to review.
const ORG_CONF: f64 = 0.60;
/// A registered legal or headquarters address.
const ADDRESS_CONF: f64 = 0.60;
/// An Australian local registration number that is a checksum-valid ACN.
const ACN_CONF: f64 = 0.72;

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

/// The by-LEI envelope: `{data: {type, id, attributes}}`.
#[derive(Debug, Deserialize)]
struct RecordResp {
    #[serde(default)]
    data: Option<LeiRecord>,
}

/// The fulltext-search envelope: `{data: [{type, id, attributes}, ...]}`.
#[derive(Debug, Deserialize)]
struct SearchResp {
    // A missing data collection is schema drift, not an observed empty registry.
    data: Vec<LeiRecord>,
}

#[derive(Debug, Deserialize)]
struct LeiRecord {
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    attributes: Option<Attributes>,
}

#[derive(Debug, Deserialize)]
struct Attributes {
    #[serde(default)]
    lei: Option<String>,
    #[serde(default)]
    entity: Option<LegalEntity>,
    #[serde(default)]
    registration: Option<Registration>,
    #[serde(default)]
    bic: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct LegalEntity {
    #[serde(default, rename = "legalName")]
    legal_name: Option<LocalName>,
    #[serde(default, rename = "otherNames")]
    other_names: Option<Vec<OtherName>>,
    #[serde(default, rename = "legalAddress")]
    legal_address: Option<Addr>,
    #[serde(default, rename = "headquartersAddress")]
    headquarters_address: Option<Addr>,
    #[serde(default, rename = "registeredAt")]
    registered_at: Option<Node>,
    #[serde(default, rename = "registeredAs")]
    registered_as: Option<String>,
    #[serde(default)]
    jurisdiction: Option<String>,
    #[serde(default, rename = "legalForm")]
    legal_form: Option<Node>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default, rename = "creationDate")]
    creation_date: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LocalName {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OtherName {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Addr {
    #[serde(default, rename = "addressLines")]
    address_lines: Option<Vec<String>>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default, rename = "postalCode")]
    postal_code: Option<String>,
}

/// A GLEIF `{id: "..."}` reference node (registration authority, legal form).
#[derive(Debug, Deserialize)]
struct Node {
    #[serde(default)]
    id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Registration {
    #[serde(default)]
    status: Option<String>,
    #[serde(default, rename = "initialRegistrationDate")]
    initial_registration_date: Option<String>,
    #[serde(default, rename = "lastUpdateDate")]
    last_update_date: Option<String>,
    #[serde(default, rename = "nextRenewalDate")]
    next_renewal_date: Option<String>,
    #[serde(default, rename = "managingLou")]
    managing_lou: Option<String>,
    #[serde(default, rename = "corroborationLevel")]
    corroboration_level: Option<String>,
}

/// `query` as a canonical LEI when it is one: trimmed, exactly 20 ASCII alphanumeric characters,
/// upper-cased. Otherwise `None` (the query is free text for the search path). **Pure.**
#[must_use]
pub fn as_lei(query: &str) -> Option<String> {
    let trimmed = query.trim();
    (trimmed.len() == LEI_LEN && trimmed.bytes().all(|byte| byte.is_ascii_alphanumeric()))
        .then(|| trimmed.to_ascii_uppercase())
}

/// The `/api/v1/lei-records/{LEI}` URL. `lei` is already validated as 20 ASCII alphanumerics, so it
/// needs no escaping. **Pure.**
#[must_use]
pub fn record_url(lei: &str) -> String {
    format!("{PUBLIC_BASE}/api/v1/lei-records/{lei}")
}

/// The `/api/v1/lei-records?filter[fulltext]={q}` URL (bracketed keys percent-encoded). **Pure.**
#[must_use]
pub fn search_url(query: &str) -> String {
    format!(
        "{PUBLIC_BASE}/api/v1/lei-records?filter%5Bfulltext%5D={}&page%5Bsize%5D=5",
        percent_encode_unreserved(query.trim())
    )
}

fn request(url: String) -> Request {
    Request::get(url)
        .header("accept", "application/vnd.api+json")
        .header("user-agent", DEFAULT_USER_AGENT)
}

fn options() -> FetchOptions {
    FetchOptions::no_redirects().paced()
}

/// Look up one legal entity on GLEIF by LEI, or by free-text name (search, then its top record).
///
/// # Errors
/// Returns a network-boundary error when the guarded fetch refuses a URL.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    query: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let lei = match as_lei(query) {
        Some(lei) => lei,
        None => match resolve_by_name(transport, query, now_unix)? {
            Ok(lei) => lei,
            Err(outcome) => return Ok(miss(outcome)),
        },
    };
    let fetched = fetch(
        transport,
        request(record_url(&lei)),
        None,
        &options(),
        SOURCE,
        now_unix,
    )?;
    let (mut entities, outcome) = interpret_record(&fetched, &lei, scan_id, now_unix);
    merge_by_uid(&mut entities);
    Ok(Report { entities, outcome })
}

/// Resolve a free-text name to the LEI of its top matching record, or an outcome explaining why not
/// (an empty or unreadable search). The outer `Result` carries only a network-boundary error.
fn resolve_by_name<T: Transport + ?Sized>(
    transport: &T,
    query: &str,
    now_unix: u64,
) -> Result<Result<String, SourceExecutionOutcome>, Error> {
    let fetched = fetch(
        transport,
        request(search_url(query)),
        None,
        &options(),
        SOURCE,
        now_unix,
    )?;
    Ok(interpret_search(&fetched, now_unix))
}

/// A report that found nothing, carrying only its outcome. **Pure.**
fn miss(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

/// The LEI of the top search hit, or the outcome of a search that named nothing usable. A 404 or an
/// empty `data` array is a clean zero; a 200 whose top hit is not a `lei-records` object with a
/// 20-character id is schema drift. **Pure.**
fn interpret_search(fetched: &Fetched, now_unix: u64) -> Result<String, SourceExecutionOutcome> {
    if let Some(response) = &fetched.response {
        if response.status == 404 && fetched.outcome.kind == SourceOutcomeKind::Upstream4xx {
            return Err(SourceExecutionOutcome::valid_zero(SOURCE, now_unix)
                .with_http_status(response.status));
        }
    }
    let response = whole_response(fetched, "GLEIF search")?;
    answer(fetched, "GLEIF search")?;
    let resp: SearchResp = decode_json(response, SOURCE, now_unix, "GLEIF search")?;
    let Some(top) = resp.data.into_iter().next() else {
        return Err(
            SourceExecutionOutcome::valid_zero(SOURCE, now_unix).with_http_status(response.status)
        );
    };
    match validated_lei(&top) {
        Some(lei) => Ok(lei),
        None => Err(SourceExecutionOutcome::failed(
            SOURCE,
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            "GLEIF search hit was not a lei-records object with a 20-character id",
        )),
    }
}

/// The entities of a confirmed record, with the outcome. A 404 is a clean zero; a malformed envelope
/// or a record whose LEI is not the requested one is schema drift, never attributed to the query.
/// **Pure.**
fn interpret_record(
    fetched: &Fetched,
    requested_lei: &str,
    scan_id: &str,
    now_unix: u64,
) -> (Vec<Entity>, SourceExecutionOutcome) {
    if let Some(response) = &fetched.response {
        if response.status == 404 && fetched.outcome.kind == SourceOutcomeKind::Upstream4xx {
            return (
                Vec::new(),
                SourceExecutionOutcome::valid_zero(SOURCE, now_unix)
                    .with_http_status(response.status),
            );
        }
    }
    let response = match whole_response(fetched, "GLEIF record") {
        Ok(response) => response,
        Err(outcome) => return (Vec::new(), outcome),
    };
    if let Err(outcome) = answer(fetched, "GLEIF record") {
        return (Vec::new(), outcome);
    }
    let resp: RecordResp = match decode_json(response, SOURCE, now_unix, "GLEIF record") {
        Ok(resp) => resp,
        Err(outcome) => return (Vec::new(), outcome),
    };
    let schema_drift = |detail: &'static str| {
        SourceExecutionOutcome::failed(
            SOURCE,
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            detail,
        )
    };
    let Some(record) = resp.data else {
        return (
            Vec::new(),
            schema_drift("GLEIF response carried no data object"),
        );
    };
    if record.kind.as_deref() != Some("lei-records") {
        return (
            Vec::new(),
            schema_drift("GLEIF data was not a lei-records object"),
        );
    }
    // The record must positively confirm the requested LEI and contradict nothing: every LEI the
    // envelope carries (its `id` and its `attributes.lei`) must be exactly the requested one. A
    // self-inconsistent envelope -- one field the request, the other a different LEI -- is rejected,
    // never trusted on the field that matches while labelled from the one that does not.
    let present_leis: Vec<String> = [
        canonical_lei(record.id.as_deref()),
        canonical_lei(record.attributes.as_ref().and_then(|a| a.lei.as_deref())),
    ]
    .into_iter()
    .flatten()
    .collect();
    if present_leis.is_empty() || present_leis.iter().any(|lei| lei.as_str() != requested_lei) {
        return (
            Vec::new(),
            schema_drift(
                "GLEIF record carried no LEI, or one that does not match or contradicts the requested LEI",
            ),
        );
    }
    let entities = build_entities(&record, requested_lei, scan_id);
    let outcome = SourceExecutionOutcome::success(SOURCE, now_unix, entities.len())
        .with_http_status(response.status);
    (entities, outcome)
}

/// `value` as a canonical LEI -- trimmed, exactly 20 ASCII alphanumeric characters, upper-cased --
/// or `None` when it is absent or not LEI-shaped. **Pure.**
fn canonical_lei(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|lei| lei.len() == LEI_LEN && lei.bytes().all(|b| b.is_ascii_alphanumeric()))
        .map(str::to_ascii_uppercase)
}

/// The LEI a `lei-records` object confirms: its own `id`, or `attributes.lei`, as a canonical code.
/// **Pure.**
fn validated_lei(record: &LeiRecord) -> Option<String> {
    if record.kind.as_deref() != Some("lei-records") {
        return None;
    }
    canonical_lei(record.id.as_deref())
        .or_else(|| canonical_lei(record.attributes.as_ref().and_then(|a| a.lei.as_deref())))
}

/// Build the report entities from a confirmed record: the legal name as an `Organisation`, its legal
/// and headquarters addresses as `Address` pivots, and an Australian local registration number as a
/// checksum-valid `AbnAcn`. **Pure** -- unit-testable off JSON fixtures.
fn build_entities(record: &LeiRecord, lei: &str, scan_id: &str) -> Vec<Entity> {
    let mut entities = Vec::new();
    let Some(entity) = record.attributes.as_ref().and_then(|a| a.entity.as_ref()) else {
        return entities;
    };
    let evidence = record_evidence(record, lei, scan_id);
    add_organisation(entity, &evidence, scan_id, &mut entities);
    add_addresses(entity, &evidence, scan_id, &mut entities);
    add_acn(entity, &evidence, scan_id, &mut entities);
    entities
}

/// The shared evidence for every entity of one record: its LEI and every registry field, kept
/// verbatim (no redaction). **Pure.**
fn record_evidence(record: &LeiRecord, lei: &str, scan_id: &str) -> Evidence {
    let attributes = record.attributes.as_ref();
    let entity = attributes.and_then(|a| a.entity.as_ref());
    let registration = attributes.and_then(|a| a.registration.as_ref());

    let legal_name = entity.and_then(|e| e.legal_name.as_ref()).and_then(name_of);
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(SOURCE, scan_id),
        legal_name.map_or_else(
            || format!("GLEIF legal entity {lei}: a public register record, a candidate to review"),
            |name| {
                format!(
                    "GLEIF legal entity {name} ({lei}): a public register record, a candidate to review, not a confirmed identity"
                )
            },
        ),
    )
    .with_attr("dataset", DATASET)
    .with_attr("lei", lei);

    evidence = evidence.with_optional_attrs([
        ("legal_name", legal_name),
        (
            "jurisdiction",
            entity.and_then(|e| trimmed(e.jurisdiction.as_deref())),
        ),
        (
            "entity_status",
            entity.and_then(|e| trimmed(e.status.as_deref())),
        ),
        (
            "category",
            entity.and_then(|e| trimmed(e.category.as_deref())),
        ),
        (
            "legal_form",
            entity
                .and_then(|e| e.legal_form.as_ref())
                .and_then(|n| trimmed(n.id.as_deref())),
        ),
        (
            "registered_at",
            entity
                .and_then(|e| e.registered_at.as_ref())
                .and_then(|n| trimmed(n.id.as_deref())),
        ),
        (
            "registered_as",
            entity.and_then(|e| trimmed(e.registered_as.as_deref())),
        ),
        (
            "creation_date",
            entity.and_then(|e| trimmed(e.creation_date.as_deref())),
        ),
        (
            "registration_status",
            registration.and_then(|r| trimmed(r.status.as_deref())),
        ),
        (
            "initial_registration_date",
            registration.and_then(|r| trimmed(r.initial_registration_date.as_deref())),
        ),
        (
            "last_update_date",
            registration.and_then(|r| trimmed(r.last_update_date.as_deref())),
        ),
        (
            "next_renewal_date",
            registration.and_then(|r| trimmed(r.next_renewal_date.as_deref())),
        ),
        (
            "managing_lou",
            registration.and_then(|r| trimmed(r.managing_lou.as_deref())),
        ),
        (
            "corroboration_level",
            registration.and_then(|r| trimmed(r.corroboration_level.as_deref())),
        ),
    ]);

    if let Some(aliases) = other_names(entity) {
        evidence = evidence.with_attr("other_names", aliases);
    }
    if let Some(bics) = bic_codes(attributes) {
        evidence = evidence.with_attr("bic", bics);
    }
    evidence
}

/// The legal name as an `Organisation` (a candidate, never a confirmed identity), tagged by
/// jurisdiction when known. **Pure.**
fn add_organisation(
    entity: &LegalEntity,
    evidence: &Evidence,
    scan_id: &str,
    entities: &mut Vec<Entity>,
) {
    let Some(name) = entity.legal_name.as_ref().and_then(name_of) else {
        return;
    };
    let mut org = Entity::new(EntityKind::Organisation, name, ORG_CONF, scan_id);
    org.tag(SOURCE);
    org.tag("gleif");
    org.tag("lei");
    if let Some(country) = country_tag(entity) {
        org.tag(country);
    }
    org.add_evidence(evidence.clone());
    entities.push(org);
}

/// The legal and headquarters addresses as `Address` pivots the geocoder can forward-geocode;
/// identical flattened addresses dedup through [`merge_by_uid`]. **Pure.**
fn add_addresses(
    entity: &LegalEntity,
    evidence: &Evidence,
    scan_id: &str,
    entities: &mut Vec<Entity>,
) {
    for (addr, role) in [
        (entity.headquarters_address.as_ref(), "headquarters"),
        (entity.legal_address.as_ref(), "legal"),
    ] {
        let Some(flat) = addr.and_then(flatten_address) else {
            continue;
        };
        let mut address = Entity::new(EntityKind::Address, &flat, ADDRESS_CONF, scan_id);
        address.tag(SOURCE);
        address.tag("gleif");
        address.tag(format!("gleif-{role}-address"));
        if let Some(country) = country_tag(entity) {
            address.tag(country);
        }
        address.add_evidence(evidence.clone().with_attr("address_role", role));
        entities.push(address);
    }
}

/// An Australian entity's local registration number as a checksum-valid `AbnAcn` -- the pivot that
/// feeds the ASIC director correlation. A non-AU jurisdiction or a number that is not a valid 9-digit
/// ACN emits nothing (fail-closed). **Pure.**
fn add_acn(entity: &LegalEntity, evidence: &Evidence, scan_id: &str, entities: &mut Vec<Entity>) {
    if !is_australian(entity) {
        return;
    }
    let Some(registered_as) = entity.registered_as.as_deref() else {
        return;
    };
    // Validate the number as ASIC writes it (its strict single-separator grouping), not a digit
    // subsequence scraped out of arbitrary text, before minting a corroborated ACN.
    let registered_as = registered_as.trim();
    if !is_valid_acn(registered_as) {
        return;
    }
    let digits = ascii_digits(registered_as);
    if digits.len() != 9 {
        return;
    }
    let mut acn = Entity::new(EntityKind::AbnAcn, &digits, ACN_CONF, scan_id);
    acn.tag(SOURCE);
    acn.tag("gleif");
    acn.tag("acn");
    acn.tag("country:AU");
    acn.add_evidence(
        evidence
            .clone()
            .with_attr("acn", &digits)
            .with_attr("type", "ACN"),
    );
    entities.push(acn);
}

/// A local name's non-empty trimmed `name`. **Pure.**
fn name_of(local: &LocalName) -> Option<&str> {
    trimmed(local.name.as_deref())
}

/// `value` trimmed, when it is present and not blank. **Pure.**
fn trimmed(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|text| !text.is_empty())
}

/// The entity's other (alias) names, comma-joined and kept verbatim as evidence. **Pure.**
fn other_names(entity: Option<&LegalEntity>) -> Option<String> {
    let names: Vec<&str> = entity
        .and_then(|e| e.other_names.as_ref())
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|other| trimmed(other.name.as_deref()))
        .collect();
    (!names.is_empty()).then(|| names.join(", "))
}

/// The entity's Bank Identifier Codes, comma-joined and kept verbatim as evidence. **Pure.**
fn bic_codes(attributes: Option<&Attributes>) -> Option<String> {
    let codes: Vec<&str> = attributes
        .and_then(|a| a.bic.as_ref())
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(String::as_str)
        .map(str::trim)
        .filter(|code| !code.is_empty())
        .collect();
    (!codes.is_empty()).then(|| codes.join(", "))
}

/// Whether the entity's jurisdiction is Australian (`AU`, or an `AU-...` subdivision). **Pure.**
fn is_australian(entity: &LegalEntity) -> bool {
    entity.jurisdiction.as_deref().is_some_and(|jurisdiction| {
        let jurisdiction = jurisdiction.trim();
        jurisdiction.eq_ignore_ascii_case("AU")
            || jurisdiction
                .get(..3)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("AU-"))
    })
}

/// A `country:XX` tag from the entity's jurisdiction's leading ISO country code. **Pure.**
fn country_tag(entity: &LegalEntity) -> Option<String> {
    let jurisdiction = trimmed(entity.jurisdiction.as_deref())?;
    let code = jurisdiction
        .split('-')
        .next()
        .unwrap_or(jurisdiction)
        .trim();
    (code.len() == 2 && code.bytes().all(|b| b.is_ascii_alphabetic()))
        .then(|| format!("country:{}", code.to_ascii_uppercase()))
}

/// One address flattened to a single line the geocoder can read: address lines then city, region,
/// postal code and country, each non-empty part once, comma-separated. `None` when every part is
/// blank. **Pure.**
fn flatten_address(addr: &Addr) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    if let Some(lines) = addr.address_lines.as_ref() {
        parts.extend(lines.iter().map(String::as_str));
    }
    parts.push(addr.city.as_deref().unwrap_or_default());
    parts.push(addr.region.as_deref().unwrap_or_default());
    parts.push(addr.postal_code.as_deref().unwrap_or_default());
    parts.push(addr.country.as_deref().unwrap_or_default());
    let flat = parts
        .into_iter()
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(", ");
    (!flat.is_empty()).then_some(flat)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{ScriptedTransport, json_ok};

    // dtolnay is not a company; this is a realistic GLEIF shape for an Australian entity.
    const RECORD: &str = r#"{"data":{"type":"lei-records","id":"5493001KJTIIGC8Y1R12","attributes":{
        "lei":"5493001KJTIIGC8Y1R12",
        "entity":{
            "legalName":{"name":"Example Holdings Pty Ltd","language":"en"},
            "otherNames":[{"name":"Example Group","language":"en","type":"TRADING_OR_OPERATING_NAME"}],
            "legalAddress":{"addressLines":["Level 1, 100 Collins Street"],"city":"Melbourne","region":"AU-VIC","country":"AU","postalCode":"3000"},
            "headquartersAddress":{"addressLines":["Level 1, 100 Collins Street"],"city":"Melbourne","region":"AU-VIC","country":"AU","postalCode":"3000"},
            "registeredAt":{"id":"RA000014"},
            "registeredAs":"004085616",
            "jurisdiction":"AU",
            "legalForm":{"id":"H1UM"},
            "category":"GENERAL",
            "status":"ACTIVE",
            "creationDate":"1990-01-01T00:00:00Z"
        },
        "registration":{"status":"ISSUED","initialRegistrationDate":"2015-01-01T00:00:00Z","lastUpdateDate":"2026-01-01T00:00:00Z","nextRenewalDate":"2027-01-01T00:00:00Z","managingLou":"EVK05KS7XY1DEII3R011","corroborationLevel":"FULLY_CORROBORATED"},
        "bic":["EXMPAU2S"]
    }}}"#;

    fn report_of(body: &str, query: &str) -> Report {
        let transport = ScriptedTransport::new(vec![Ok(json_ok(body))]);
        lookup(&transport, query, "scan-gleif", 1).expect("lookup runs")
    }

    fn has(report: &Report, kind: &EntityKind, value: &str) -> bool {
        report
            .entities
            .iter()
            .any(|entity| entity.kind == *kind && entity.raw_value == value)
    }

    fn org_attr<'a>(report: &'a Report, key: &str) -> Option<&'a str> {
        report
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Organisation)
            .and_then(|e| e.evidence.first())
            .and_then(|ev| ev.attributes.get(key))
            .map(String::as_str)
    }

    #[test]
    fn a_self_contradictory_envelope_is_schema_drift() {
        // `id` and `attributes.lei` disagree: the request matches one field, the other is a
        // different valid LEI. A record that contradicts itself is rejected -- never trusted on the
        // field that matches while labelled from the one that does not.
        let split = r#"{"data":{"type":"lei-records","id":"OTHERVALIDLEI00000XX","attributes":{"lei":"5493001KJTIIGC8Y1R12","entity":{"legalName":{"name":"Victim Corp"}}}}}"#;
        let report = report_of(split, "5493001KJTIIGC8Y1R12");
        assert!(report.entities.is_empty(), "{:#?}", report.entities);
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn the_evidence_lei_is_the_confirmed_request_not_a_record_field() {
        // Only `attributes.lei` is present and it matches; the evidence is still labelled with the
        // confirmed requested LEI, never left blank or taken from a malformed id.
        let attr_only = r#"{"data":{"type":"lei-records","attributes":{"lei":"5493001KJTIIGC8Y1R12","entity":{"legalName":{"name":"Attr Only Pty Ltd"},"jurisdiction":"AU"}}}}"#;
        let report = report_of(attr_only, "5493001KJTIIGC8Y1R12");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(has(&report, &EntityKind::Organisation, "Attr Only Pty Ltd"));
        assert_eq!(org_attr(&report, "lei"), Some("5493001KJTIIGC8Y1R12"));
    }

    #[test]
    fn a_registration_number_with_embedded_letters_mints_no_acn() {
        // Digit extraction must not defeat the ACN's strict validation: a value that is not a clean
        // ASIC-formatted number is rejected even if its digit subsequence would checksum.
        let messy = r#"{"data":{"type":"lei-records","id":"5493001KJTIIGC8Y1R12","attributes":{"lei":"5493001KJTIIGC8Y1R12","entity":{"legalName":{"name":"Messy Reg Pty Ltd"},"registeredAs":"0a0b4085616","jurisdiction":"AU"}}}}"#;
        let report = report_of(messy, "5493001KJTIIGC8Y1R12");
        assert!(has(&report, &EntityKind::Organisation, "Messy Reg Pty Ltd"));
        assert!(
            !report.entities.iter().any(|e| e.kind == EntityKind::AbnAcn),
            "a non-ASIC-formatted registration number must not mint an ACN: {:#?}",
            report.entities
        );
    }

    #[test]
    fn as_lei_accepts_only_a_twenty_character_alphanumeric_code() {
        assert_eq!(
            as_lei(" 5493001kjtiigc8y1r12 "),
            Some("5493001KJTIIGC8Y1R12".to_owned())
        );
        assert!(as_lei("Example Holdings").is_none());
        assert!(as_lei("5493001KJTIIGC8Y1R1").is_none()); // 19 chars
        assert!(as_lei("5493001KJTIIGC8Y1R12X").is_none()); // 21 chars
        assert!(as_lei("5493001-JTIIGC8Y1R12").is_none()); // non-alphanumeric
    }

    #[test]
    fn the_urls_carry_the_lei_and_encoded_query() {
        assert_eq!(
            record_url("5493001KJTIIGC8Y1R12"),
            "https://api.gleif.org/api/v1/lei-records/5493001KJTIIGC8Y1R12"
        );
        assert_eq!(
            search_url("Example Holdings"),
            "https://api.gleif.org/api/v1/lei-records?filter%5Bfulltext%5D=Example%20Holdings&page%5Bsize%5D=5"
        );
    }

    #[test]
    fn a_confirmed_record_emits_organisation_address_and_acn() {
        let report = report_of(RECORD, "5493001KJTIIGC8Y1R12");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(has(
            &report,
            &EntityKind::Organisation,
            "Example Holdings Pty Ltd"
        ));
        assert!(has(
            &report,
            &EntityKind::Address,
            "Level 1, 100 Collins Street, Melbourne, AU-VIC, 3000, AU"
        ));
        // The AU registeredAs is a checksum-valid ACN pivot for the ASIC correlation.
        assert!(has(&report, &EntityKind::AbnAcn, "004085616"));
        // Every registry field is kept verbatim as evidence.
        assert_eq!(org_attr(&report, "lei"), Some("5493001KJTIIGC8Y1R12"));
        assert_eq!(org_attr(&report, "registration_status"), Some("ISSUED"));
        assert_eq!(
            org_attr(&report, "managing_lou"),
            Some("EVK05KS7XY1DEII3R011")
        );
        assert_eq!(org_attr(&report, "other_names"), Some("Example Group"));
        assert_eq!(org_attr(&report, "bic"), Some("EXMPAU2S"));
        // The two identical addresses dedup to one entity.
        let addresses = report
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Address)
            .count();
        assert_eq!(addresses, 1, "{:#?}", report.entities);
    }

    #[test]
    fn free_text_resolves_through_search_then_the_record() {
        let search = r#"{"data":[{"type":"lei-records","id":"5493001KJTIIGC8Y1R12","attributes":{"lei":"5493001KJTIIGC8Y1R12"}}]}"#;
        let transport = ScriptedTransport::new(vec![Ok(json_ok(search)), Ok(json_ok(RECORD))]);
        let report = lookup(&transport, "Example Holdings", "scan", 1).expect("runs");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(has(
            &report,
            &EntityKind::Organisation,
            "Example Holdings Pty Ltd"
        ));
    }

    #[test]
    fn an_unknown_lei_is_a_clean_negative() {
        let transport = ScriptedTransport::new(vec![Ok(crate::http::Response {
            status: 404,
            headers: Vec::new(),
            body: b"{\"errors\":[{\"status\":\"404\"}]}".to_vec(),
            truncated: false,
        })]);
        let report = lookup(&transport, "5493001KJTIIGC8Y1R12", "scan", 1).expect("runs");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn an_empty_search_is_a_clean_negative() {
        let report = report_of(r#"{"data":[]}"#, "no such company anywhere");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn missing_search_data_is_schema_drift_not_a_clean_negative() {
        let report = report_of(r#"{"meta":{"total":0}}"#, "no such company anywhere");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn a_record_for_a_different_lei_is_schema_drift_not_a_confirmation() {
        let other = r#"{"data":{"type":"lei-records","id":"OTHERLEI00000000000X","attributes":{"lei":"OTHERLEI00000000000X","entity":{"legalName":{"name":"Someone Else Ltd"}}}}}"#;
        let report = report_of(other, "5493001KJTIIGC8Y1R12");
        assert!(report.entities.is_empty(), "{:#?}", report.entities);
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn a_wrong_envelope_type_is_schema_drift() {
        let wrong = r#"{"data":{"type":"fund-records","id":"5493001KJTIIGC8Y1R12","attributes":{"lei":"5493001KJTIIGC8Y1R12"}}}"#;
        let report = report_of(wrong, "5493001KJTIIGC8Y1R12");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn a_response_without_a_data_object_is_schema_drift() {
        let report = report_of(r#"{"meta":{"foo":1}}"#, "5493001KJTIIGC8Y1R12");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn a_non_australian_entity_emits_no_acn() {
        let us = r#"{"data":{"type":"lei-records","id":"5493001KJTIIGC8Y1R12","attributes":{"lei":"5493001KJTIIGC8Y1R12","entity":{"legalName":{"name":"US Example Inc"},"registeredAs":"004085616","jurisdiction":"US-DE"}}}}"#;
        let report = report_of(us, "5493001KJTIIGC8Y1R12");
        assert!(has(&report, &EntityKind::Organisation, "US Example Inc"));
        assert!(
            !report.entities.iter().any(|e| e.kind == EntityKind::AbnAcn),
            "{:#?}",
            report.entities
        );
    }

    #[test]
    fn an_australian_entity_with_a_checksum_invalid_number_emits_no_acn() {
        let bad = r#"{"data":{"type":"lei-records","id":"5493001KJTIIGC8Y1R12","attributes":{"lei":"5493001KJTIIGC8Y1R12","entity":{"legalName":{"name":"Bad ACN Pty Ltd"},"registeredAs":"123456789","jurisdiction":"AU"}}}}"#;
        let report = report_of(bad, "5493001KJTIIGC8Y1R12");
        assert!(has(&report, &EntityKind::Organisation, "Bad ACN Pty Ltd"));
        assert!(
            !report.entities.iter().any(|e| e.kind == EntityKind::AbnAcn),
            "a checksum-invalid registration number must not be minted as an ACN: {:#?}",
            report.entities
        );
    }

    #[test]
    fn distinct_legal_and_headquarters_addresses_both_surface() {
        let two = r#"{"data":{"type":"lei-records","id":"5493001KJTIIGC8Y1R12","attributes":{"lei":"5493001KJTIIGC8Y1R12","entity":{"legalName":{"name":"Two Address Pty Ltd"},"jurisdiction":"AU","legalAddress":{"addressLines":["1 Legal St"],"city":"Sydney","region":"AU-NSW","country":"AU","postalCode":"2000"},"headquartersAddress":{"addressLines":["2 HQ Rd"],"city":"Perth","region":"AU-WA","country":"AU","postalCode":"6000"}}}}}"#;
        let report = report_of(two, "5493001KJTIIGC8Y1R12");
        assert!(has(
            &report,
            &EntityKind::Address,
            "1 Legal St, Sydney, AU-NSW, 2000, AU"
        ));
        assert!(has(
            &report,
            &EntityKind::Address,
            "2 HQ Rd, Perth, AU-WA, 6000, AU"
        ));
    }
}
