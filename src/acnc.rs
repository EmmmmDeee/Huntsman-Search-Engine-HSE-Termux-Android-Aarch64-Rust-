//! ACNC Charity Register over data.gov.au CKAN — Australia's register of registered charities.
//! Keyless. Blocking.
//!
//! A `people NAME` lookup ([`crate::people_cli`]) that names a charity or not-for-profit also
//! queries the ACNC register through [`crate::fetch::fetch`] and an injected
//! [`crate::http::Transport`], beside the ASIC person/company registers (`asic_persons`,
//! `asic_director`) and `Wikidata`. It emits the charity as an [`EntityKind::Organisation`]
//! candidate — a name match in an authoritative register, never a confirmed identity of the queried
//! person — its ABN as an [`EntityKind::AbnAcn`] identifier (a precise Australian business number
//! kept as a correlation key; the ASIC and GLEIF legs key on the 9-digit ACN, so an 11-digit ABN
//! does not auto-join those), its official website as an [`EntityKind::Domain`] pivot, and its
//! registered address as [`EntityKind::Address`] and a postcode-derived [`EntityKind::Coordinates`].
//! Every published field — size, purposes, beneficiaries, operating states — is kept verbatim as
//! evidence; nothing is redacted.
//!
//! Evidence integrity is fail-closed, mirroring `asic_persons`: a challenge page, truncated body or
//! a `success: false` CKAN envelope is never turned into evidence, and only a record whose charity
//! name actually matches the queried name (a whole-word token match on `Charity_Legal_Name` or
//! `Other_Organisation_Names`) becomes an entity, so a fuzzy full-text rank never fabricates an
//! unrelated charity onto the name. The website `Domain` is tagged [`crate::tags::NAME_SEARCH_LEAD`],
//! so [`crate::recursion`] keeps a name-matched charity's site as a visible lead but never
//! auto-dispatches it onto a potentially unrelated third party, whatever the operator's floor.

use serde_json::{Map, Value};

use crate::address_au;
use crate::au_id::is_valid_abn;
use crate::canonical::canonical_domain;
use crate::ckan::{self, field};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid};
use crate::error::Error;
use crate::fetch::{self, FetchOptions, Fetched};
use crate::http::{self, Request, Transport};
use crate::postcode_au;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, classify_fetch};
use crate::textnorm::name_tokens;
use crate::value_syntax::host_only;

pub const SRC: &str = "acnc";
const CKAN_BASE: &str = "https://data.gov.au/data/api/3/action";
/// The ACNC "Datasets" charity register resource on `data.gov.au`. If the ACNC republishes under a
/// new resource id, the lookup fails closed (a `success: false` envelope becomes schema drift, not
/// a fabricated zero result) until this constant is updated.
pub(crate) const CHARITY_RES: &str = "eb1e6be4-5b13-4feb-b28e-388bf7c26f93";
const MAX_HITS: usize = 100;

/// A registered charity: a candidate name match in an authoritative register, not a confirmed
/// identity of the queried person.
const CONF_ORG: f64 = 0.60;
/// The charity's ABN: a precise correlation key, but attributed to the query only as strongly as
/// the charity name match.
const CONF_ABN: f64 = 0.60;
/// The charity's official website: a candidate pivot — the site is the register's, but the charity
/// is only a name match to the query. It is emitted tagged [`crate::tags::NAME_SEARCH_LEAD`], so
/// [`crate::recursion`] keeps it as a visible lead but never auto-dispatches it onto a potentially
/// unrelated third party, whatever the operator's expansion floor.
const CONF_DOMAIN: f64 = 0.55;
const CONF_ADDRESS: f64 = 0.55;
const CONF_COORDS: f64 = 0.45;

/// One name lookup on the ACNC charity register.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

/// Look up `name` on the ACNC charity register.
///
/// A name with fewer than two alphabetic tokens of length ≥ 2 makes no request (mirroring the other
/// people-leg registers; `people_cli` enforces the same name shape upstream). Only records whose
/// charity name matches the queried name are emitted.
///
/// # Errors
///
/// [`Error::Network`] when egress blocks the request.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    name: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    if name_tokens(name).len() < 2 {
        return Ok(Report {
            entities: Vec::new(),
            outcome: SourceExecutionOutcome::valid_zero(SRC, now_unix),
        });
    }

    let options = FetchOptions {
        max_redirects: fetch::DEFAULT_MAX_REDIRECTS,
        ..FetchOptions::default()
    };
    let url = ckan::datastore_search_url(CKAN_BASE, CHARITY_RES, name, MAX_HITS);
    let request = Request::get(url).header("accept", "application/json");
    let fetched = fetch::fetch(transport, request, None, &options, SRC, now_unix)?;
    let (outcome, records) = parse(now_unix, fetched);

    let mut entities = Vec::new();
    let matched: Vec<&Map<String, Value>> = records
        .iter()
        .filter(|rec| charity_name_matches(rec, name))
        .take(MAX_HITS)
        .collect();
    for rec in &matched {
        emit_charity(rec, scan_id, &mut entities);
    }
    merge_by_uid(&mut entities);

    let outcome = reconcile(outcome, matched.len(), now_unix);
    Ok(Report { entities, outcome })
}

/// Interpret the CKAN response: a truncated body, non-2xx status or malformed/`success: false`
/// envelope is a fail-closed non-answer with no records; a clean envelope yields its records and a
/// truncation note when the page was cut short of the total.
fn parse(now_unix: u64, fetched: Fetched) -> (SourceExecutionOutcome, Vec<Map<String, Value>>) {
    let drift = |kind: SourceOutcomeKind, status: Option<u16>, detail: String| {
        let mut outcome = SourceExecutionOutcome::success(SRC, now_unix, 0);
        outcome.kind = kind;
        outcome.found = None;
        outcome.http_status = status;
        outcome.detail = Some(detail);
        (outcome, Vec::new())
    };

    let Some(response) = fetched.response else {
        return (fetched.outcome, Vec::new());
    };
    if response.truncated {
        return drift(
            SourceOutcomeKind::ParserDrift,
            Some(response.status),
            "truncated CKAN body is not evidence".to_owned(),
        );
    }
    let body = response.text();
    let kind = classify_fetch(response.status, &body);
    if kind != SourceOutcomeKind::Inconclusive {
        let mut outcome = fetched.outcome;
        outcome.kind = kind;
        outcome.found = None;
        return (outcome, Vec::new());
    }
    let parsed: ckan::Response = match http::parse_json_body(&response) {
        Ok(parsed) => parsed,
        Err(err) => {
            return drift(
                SourceOutcomeKind::ParserDrift,
                Some(response.status),
                err.to_string(),
            );
        }
    };
    match ckan::check_envelope(parsed, SRC) {
        Err(err) => drift(
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            err.to_string(),
        ),
        Ok(None) => drift(
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            "CKAN response had no result envelope".to_owned(),
        ),
        Ok(Some(result)) => {
            let outcome = if result.records.is_empty() {
                SourceExecutionOutcome::valid_zero(SRC, now_unix)
            } else {
                SourceExecutionOutcome::success(SRC, now_unix, result.records.len())
            }
            .with_http_status(response.status);
            let outcome = match result.truncation() {
                Some(note) => outcome.with_detail(note),
                None => outcome,
            };
            (outcome, result.records)
        }
    }
}

/// Reconcile the register's page verdict with the locally matched charity names. A cut-off page can
/// show a positive match but cannot prove absence.
fn reconcile(
    mut outcome: SourceExecutionOutcome,
    matched: usize,
    now_unix: u64,
) -> SourceExecutionOutcome {
    if !outcome.kind.is_accepted() {
        return outcome;
    }
    let partial = outcome.detail.take();
    let status = outcome.http_status.unwrap_or(200);
    if matched == 0 {
        if let Some(note) = partial {
            SourceExecutionOutcome::observed(
                SRC,
                now_unix,
                SourceOutcomeKind::Inconclusive,
                Some(status),
                Some(0),
                note,
            )
        } else {
            SourceExecutionOutcome::valid_zero(SRC, now_unix).with_http_status(status)
        }
    } else {
        let mut found =
            SourceExecutionOutcome::success(SRC, now_unix, matched).with_http_status(status);
        if let Some(note) = partial {
            found = found.with_detail(note);
        }
        found
    }
}

/// Whether this record matches the queried name as whole words against ONE of its individual
/// published names — its legal name, or any single alternate name split out of the multi-value
/// `Other_Organisation_Names` field. Matching each name separately (never the concatenated blob)
/// stops a query token drawn from one alternate name and another token from a different alternate
/// name from jointly admitting a charity that bears neither name, so a loose full-text rank cannot
/// fabricate an unrelated charity onto the queried name.
fn charity_name_matches(rec: &Map<String, Value>, query: &str) -> bool {
    candidate_names(rec)
        .iter()
        .any(|name| crate::textnorm::whole_word_token_match(name, query))
}

/// Each individual name the register publishes for this charity: its legal name as a whole, and
/// each alternate name split out of `Other_Organisation_Names` on the register's multi-value
/// separators. The legal name is never split (one legal name may itself contain a comma).
fn candidate_names(rec: &Map<String, Value>) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(legal) = field(rec, "Charity_Legal_Name") {
        names.push(legal);
    }
    if let Some(alternates) = field(rec, "Other_Organisation_Names") {
        for piece in alternates.split(['\n', ';', ',']) {
            let piece = piece.trim();
            if !piece.is_empty() {
                names.push(piece.to_owned());
            }
        }
    }
    names
}

fn provenance(scan_id: &str) -> EvidenceProvenance {
    EvidenceProvenance::for_scan(SRC, scan_id)
}

/// The matched charity as entities: the organisation, its ABN, its official website `Domain`, and
/// its registered address and postcode-derived coordinates. Every published field is kept verbatim.
fn emit_charity(rec: &Map<String, Value>, scan_id: &str, out: &mut Vec<Entity>) {
    let Some(legal_name) = field(rec, "Charity_Legal_Name") else {
        return;
    };

    let mut ev = Evidence::new(
        provenance(scan_id),
        format!("ACNC registered charity: {legal_name} (a register name match, not a confirmed identity)"),
    )
    .with_attr("register", "ACNC Charity Register")
    .with_attr("dataset", "ACNC Charity Register");
    // Keep every field the register published for this charity, verbatim under its own key —
    // its size, registration and establishment dates, operating jurisdictions, charitable
    // purposes and beneficiary classes included. Nothing is redacted or reduced to an allowlist;
    // a field the register leaves null is simply absent (not emitted), and the raw Y value of a
    // flag is kept as published. Only the CKAN datastore internals are skipped: the per-row `_id`
    // and the full-text search `rank`, which are not charity data.
    for key in rec.keys() {
        if key == "_id" || key == "rank" {
            continue;
        }
        if let Some(value) = field(rec, key) {
            ev = ev.with_attr(key.as_str(), value);
        }
    }

    let mut org = Entity::new(EntityKind::Organisation, &legal_name, CONF_ORG, scan_id);
    org.tag("au");
    org.tag("acnc");
    org.tag("charity");
    org.tag("country:AU");
    org.add_evidence(ev);
    out.push(org);

    if let Some(abn) = field(rec, "ABN").filter(|value| is_valid_abn(value)) {
        let mut entity = Entity::new(EntityKind::AbnAcn, &abn, CONF_ABN, scan_id);
        entity.tag("au");
        entity.tag("acnc");
        entity.tag("abn");
        entity.tag("country:AU");
        entity.add_evidence(
            Evidence::new(
                provenance(scan_id),
                format!("ABN of ACNC charity {legal_name}"),
            )
            .with_attr("abn", &abn)
            .with_attr("charity_legal_name", &legal_name),
        );
        out.push(entity);
    }

    if let Some(website) = field(rec, "Charity_Website") {
        if let Some(domain) = canonical_domain(host_only(&website)) {
            let mut entity = Entity::new(EntityKind::Domain, &domain, CONF_DOMAIN, scan_id);
            entity.tag("au");
            entity.tag("acnc");
            entity.tag("charity-website");
            entity.tag(crate::tags::NAME_SEARCH_LEAD);
            entity.add_evidence(
                Evidence::new(
                    provenance(scan_id),
                    format!(
                        "Official website of ACNC charity {legal_name} (a lead to review, not an \
                         automatically dispatched pivot)"
                    ),
                )
                .with_attr("website", &website)
                .with_attr("charity_legal_name", &legal_name),
            );
            out.push(entity);
        }
    }

    push_address(rec, &legal_name, scan_id, out);
}

/// The charity's registered address and its postcode-derived coordinates, when present.
fn push_address(rec: &Map<String, Value>, legal_name: &str, scan_id: &str, out: &mut Vec<Entity>) {
    let parts: Vec<String> = [
        "Address_Line_1",
        "Address_Line_2",
        "Address_Line_3",
        "Town_City",
        "State",
        "Postcode",
        "Country",
    ]
    .into_iter()
    .filter_map(|key| field(rec, key))
    .collect();
    if parts.is_empty() {
        return;
    }
    let addr = parts.join(" ");
    let state = address_au::state_code(&addr);
    let mut address = Entity::new(EntityKind::Address, &addr, CONF_ADDRESS, scan_id);
    address.tag("au");
    address.tag("acnc");
    address.tag("charity-address");
    address.tag("country:AU");
    if let Some(state) = state {
        address.tag(format!("au-state:{state}"));
    }
    address.add_evidence(
        Evidence::new(
            provenance(scan_id),
            format!("Registered address of ACNC charity {legal_name}"),
        )
        .with_attr("address", &addr)
        .with_attr("source", "acnc-register"),
    );
    out.push(address);

    let Some(pcode) = field(rec, "Postcode") else {
        return;
    };
    let Some((lat, lon)) = postcode_au::offline_centroid(&pcode) else {
        return;
    };
    let coord_val = format!("{lat:.4},{lon:.4}");
    let mut coords = Entity::new(EntityKind::Coordinates, &coord_val, CONF_COORDS, scan_id);
    coords.tag("au");
    coords.tag("acnc");
    coords.tag("addr-derived");
    coords.tag(crate::tags::GEOINT);
    coords.tag("country:AU");
    if let Some(state) = state {
        coords.tag(format!("au-state:{state}"));
    }
    coords.add_evidence(
        Evidence::new(
            provenance(scan_id),
            format!("Geocoded register address of ACNC charity {legal_name}"),
        )
        .with_attr("source_address", &addr),
    );
    out.push(coords);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{ScriptedTransport, json_ok};

    // A realistic ACNC datastore_search envelope for "smith family", trimmed to the modelled fields.
    const SMITH: &str = r#"{"success":true,"result":{"total":1,"records":[{
        "_id":24196,"ABN":"28000030179","Charity_Legal_Name":"The Smith Family",
        "Other_Organisation_Names":null,"Address_Line_1":"L17 2 Market St","Town_City":"Sydney",
        "State":"NSW","Postcode":"2000","Country":"Australia","Charity_Website":"thesmithfamily.com.au",
        "Registration_Date":"03/12/2012","Charity_Size":"Large","Number_of_Responsible_Persons":"13",
        "Operates_in_NSW":"Y","Operates_in_VIC":"Y","PBI":"Y"
    }]}}"#;

    fn report_of(body: &str, name: &str) -> Report {
        let transport = ScriptedTransport::new(vec![Ok(json_ok(body))]);
        lookup(&transport, name, "scan-acnc", 1).expect("lookup runs")
    }

    fn has(report: &Report, kind: &EntityKind, value: &str) -> bool {
        report
            .entities
            .iter()
            .any(|entity| entity.kind == *kind && entity.raw_value == value)
    }

    fn org(report: &Report) -> &Entity {
        report
            .entities
            .iter()
            .find(|entity| entity.kind == EntityKind::Organisation)
            .expect("the charity organisation is an entity")
    }

    #[test]
    fn a_matched_charity_yields_org_abn_website_and_address() {
        let report = report_of(SMITH, "smith family");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(has(&report, &EntityKind::Organisation, "The Smith Family"));
        assert!(has(&report, &EntityKind::AbnAcn, "28000030179"));
        // The official website is a Domain pivot into the wired domain-recon cluster.
        assert!(has(&report, &EntityKind::Domain, "thesmithfamily.com.au"));
        // The registered address and its postcode-derived coordinates surface for geocoding.
        assert!(report.entities.iter().any(
            |entity| entity.kind == EntityKind::Address && entity.raw_value.contains("Sydney")
        ));
        assert!(
            report
                .entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Coordinates)
        );
        // Every published field is kept verbatim on the organisation evidence, under its own
        // register key — nothing is an allowlist.
        let evidence = org(&report).evidence.first().expect("org evidence");
        assert_eq!(
            evidence.attributes.get("Charity_Size").map(String::as_str),
            Some("Large")
        );
        // Operating-state flags are kept verbatim; a flag the register leaves unset is simply
        // absent (not redacted, and never misreported as operating).
        assert_eq!(
            evidence
                .attributes
                .get("Operates_in_NSW")
                .map(String::as_str),
            Some("Y")
        );
        assert_eq!(
            evidence
                .attributes
                .get("Operates_in_VIC")
                .map(String::as_str),
            Some("Y")
        );
        assert_eq!(evidence.attributes.get("Operates_in_QLD"), None);
    }

    #[test]
    fn the_charity_is_a_candidate_never_a_confirmed_identity() {
        // The organisation is a register name match, so its confidence stays a modest candidate
        // level, well below a confirmed-identity threshold — a calibration regression is caught.
        let report = report_of(SMITH, "smith family");
        let org = org(&report);
        assert!(
            (org.confidence - CONF_ORG).abs() < f64::EPSILON && org.confidence < 0.9,
            "the charity must stay a candidate: {}",
            org.confidence
        );
    }

    #[test]
    fn the_website_domain_is_tagged_a_name_search_lead() {
        // A name-matched charity's website must be a reviewable lead that a recursive scan never
        // auto-dispatches, whatever the operator's floor: it carries the shared NAME_SEARCH_LEAD
        // tag that `recursion` refuses.
        let report = report_of(SMITH, "smith family");
        let domain = report
            .entities
            .iter()
            .find(|entity| entity.kind == EntityKind::Domain)
            .expect("website domain");
        assert!(
            domain.has_tag(crate::tags::NAME_SEARCH_LEAD),
            "the charity website must be tagged a name-search lead: {:?}",
            domain.tags
        );
    }

    #[test]
    fn a_fulltext_rank_hit_on_an_unrelated_charity_is_not_attributed() {
        // CKAN full-text search ranks loosely: a record that does not actually bear the queried
        // name as whole words must never be minted onto the name.
        let unrelated = r#"{"success":true,"result":{"total":1,"records":[{
            "_id":5,"ABN":"11111111111","Charity_Legal_Name":"Rivertown Historical Society",
            "Charity_Website":"rivertown.example"
        }]}}"#;
        let report = report_of(unrelated, "smith family");
        assert!(report.entities.is_empty(), "{:#?}", report.entities);
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn tokens_split_across_two_alternate_names_do_not_match() {
        // Other_Organisation_Names holds multiple distinct trading names. A query must match ONE
        // whole name, not draw one token from each of two different names — otherwise an unrelated
        // charity bearing neither name is fabricated onto the person.
        let two_names = r#"{"success":true,"result":{"total":1,"records":[{
            "_id":8,"ABN":"28000030179","Charity_Legal_Name":"Rivertown Arts Incorporated",
            "Other_Organisation_Names":"Grace Community Op Shop; Hope Street Markets"
        }]}}"#;
        let report = report_of(two_names, "grace hope");
        assert!(
            report.entities.is_empty(),
            "a query matched across two different alternate names must not attribute the charity: {:#?}",
            report.entities
        );
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn an_alternate_name_match_is_attributed() {
        // A charity whose published Other_Organisation_Names bears the queried name matches too.
        let aka = r#"{"success":true,"result":{"total":1,"records":[{
            "_id":6,"ABN":"28000030179","Charity_Legal_Name":"TSF Operations Ltd",
            "Other_Organisation_Names":"The Smith Family"
        }]}}"#;
        let report = report_of(aka, "smith family");
        assert!(has(
            &report,
            &EntityKind::Organisation,
            "TSF Operations Ltd"
        ));
    }

    #[test]
    fn a_single_token_name_makes_no_request() {
        // The people leg keys on a NAME; a one-token query makes no request, mirroring the ASIC
        // registers (and `people_cli` enforces the same upstream).
        let transport = ScriptedTransport::new(vec![]);
        let report = lookup(&transport, "smith", "scan-acnc", 1).expect("runs");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
        assert!(
            transport.seen.borrow().is_empty(),
            "no request for one token"
        );
    }

    #[test]
    fn a_success_false_envelope_is_schema_drift_not_a_clean_zero() {
        // A bad resource id or portal error returns success=false: fail closed as schema drift,
        // never a fabricated empty result.
        let report = report_of(r#"{"success":false}"#, "smith family");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn an_empty_register_result_is_a_clean_zero() {
        let report = report_of(
            r#"{"success":true,"result":{"total":0,"records":[]}}"#,
            "smith family",
        );
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn a_malformed_abn_is_not_minted() {
        // A charity whose ABN fails the ABN checksum must not mint an AbnAcn entity, though the
        // organisation still stands.
        let bad_abn = r#"{"success":true,"result":{"total":1,"records":[{
            "_id":7,"ABN":"12345678901","Charity_Legal_Name":"The Smith Family"
        }]}}"#;
        let report = report_of(bad_abn, "smith family");
        assert!(has(&report, &EntityKind::Organisation, "The Smith Family"));
        assert!(
            !report
                .entities
                .iter()
                .any(|entity| entity.kind == EntityKind::AbnAcn),
            "a checksum-invalid ABN must not be minted: {:#?}",
            report.entities
        );
    }
}
