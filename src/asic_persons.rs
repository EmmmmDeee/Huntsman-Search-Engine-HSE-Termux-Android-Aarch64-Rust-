//! ASIC people registers over data.gov.au CKAN — banned/disqualified persons,
//! financial advisers, and credit representatives. Keyless. Blocking.
//!
//! The three registers are queried sequentially through [`crate::fetch::fetch`]
//! and an injected [`crate::http::Transport`]. Challenge pages, truncated bodies,
//! and `success: false` CKAN envelopes are never turned into evidence. The binary
//! exposes `people NAME` through [`crate::people_cli`], which also runs
//! `asic_director`, `au_people` and `au_electoral`. Tests use a fake transport;
//! the live CKAN path is not run in CI.

use serde_json::{Map, Value};

use crate::address_au;
use crate::au_id::{is_valid_abn, is_valid_acn, looks_like_company};
use crate::ckan::{self, field};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::error::Error;
use crate::fetch::{self, FetchOptions, Fetched};
use crate::http::{self, Request, Transport};
use crate::postcode_au;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, classify_fetch};
use crate::textnorm::{title_case, whole_word_token_match};

const SRC: &str = "asic_persons";
const CKAN_BASE: &str = "https://data.gov.au/data/api/3/action";
const BANNED_RES: &str = "741da9e3-7e0c-458e-830c-c518698e1788";
const ADVISER_RES: &str = "91d80440-5787-46fc-99de-0c1d93e6cc9f";
const CREDIT_RES: &str = "999d9e92-df2c-4d6d-b580-321dcd205292";
const MAX_HITS: usize = 100;

const CONF_PERSON: f64 = 0.60;
const CONF_LICENSEE: f64 = 0.62;
const CONF_CONTROLLER: f64 = 0.58;
const CONF_ADDRESS: f64 = 0.55;
const CONF_COORDS: f64 = 0.45;

/// One name lookup across the three ASIC people registers.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

/// Look up `name` on the three ASIC people registers.
///
/// A name with fewer than two alphabetic tokens of length ≥ 2 makes no request.
/// Egress refusals are [`Error::Network`]. A total register outage with no
/// entities is [`Error::Invalid`]. A validated empty answer is an empty report.
///
/// # Errors
///
/// [`Error::Network`] when egress blocks a request. [`Error::Invalid`] when every
/// register that was queried failed and no entity was emitted.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    name: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    if name_tokens(name).len() < 2 {
        return Ok(Report {
            entities: Vec::new(),
            outcomes: Vec::new(),
        });
    }

    let options = FetchOptions {
        max_redirects: fetch::DEFAULT_MAX_REDIRECTS,
        ..FetchOptions::default()
    };
    let mut entities = Vec::new();
    let mut outcomes = Vec::new();
    let mut hard_failure: Option<Error> = None;

    for spec in [
        Register {
            module: "asic_persons.banned",
            resource: BANNED_RES,
            name_field: "BD_PER_NAME",
            emit: emit_banned,
        },
        Register {
            module: "asic_persons.advisers",
            resource: ADVISER_RES,
            name_field: "ADV_NAME",
            emit: emit_adviser,
        },
        Register {
            module: "asic_persons.credit",
            resource: CREDIT_RES,
            name_field: "CRED_REP_NAME",
            emit: emit_credit_rep,
        },
    ] {
        let (mut outcome, records) = query_register(
            transport,
            &options,
            spec.module,
            spec.resource,
            name,
            now_unix,
        )?;
        if !outcome.kind.is_accepted() {
            let detail = outcome
                .detail
                .clone()
                .unwrap_or_else(|| format!("{} failed", spec.module));
            hard_failure.get_or_insert(Error::Invalid(detail));
        }
        let matched: Vec<&Map<String, Value>> = records
            .iter()
            .filter(|rec| record_name_matches(rec, spec.name_field, name))
            .take(MAX_HITS)
            .collect();
        if outcome.kind.is_accepted() {
            outcome = if matched.is_empty() {
                SourceExecutionOutcome::valid_zero(spec.module, now_unix)
                    .with_http_status(outcome.http_status.unwrap_or(200))
            } else {
                SourceExecutionOutcome::success(spec.module, now_unix, matched.len())
                    .with_http_status(outcome.http_status.unwrap_or(200))
            };
        }
        for rec in matched {
            (spec.emit)(rec, scan_id, &mut entities);
        }
        outcomes.push(outcome);
    }

    merge_by_uid(&mut entities);
    if entities.is_empty() {
        if let Some(err) = hard_failure {
            return Err(err);
        }
    }
    Ok(Report { entities, outcomes })
}

struct Register {
    module: &'static str,
    resource: &'static str,
    name_field: &'static str,
    emit: fn(&Map<String, Value>, &str, &mut Vec<Entity>),
}

fn query_register<T: Transport + ?Sized>(
    transport: &T,
    options: &FetchOptions,
    module: &'static str,
    resource: &str,
    name: &str,
    now_unix: u64,
) -> Result<(SourceExecutionOutcome, Vec<Map<String, Value>>), Error> {
    let url = ckan::datastore_search_url(CKAN_BASE, resource, name, MAX_HITS);
    let request = Request::get(url).header("accept", "application/json");
    let fetched = fetch::fetch(transport, request, None, options, module, now_unix)?;
    Ok(parse_register(module, now_unix, fetched))
}

fn parse_register(
    module: &'static str,
    now_unix: u64,
    fetched: Fetched,
) -> (SourceExecutionOutcome, Vec<Map<String, Value>>) {
    let some_status = |kind: SourceOutcomeKind, status: Option<u16>, detail: Option<String>| {
        let mut outcome = SourceExecutionOutcome::success(module, now_unix, 0);
        outcome.kind = kind;
        outcome.found = None;
        outcome.http_status = status;
        outcome.detail = detail;
        (outcome, Vec::new())
    };

    let Some(response) = fetched.response else {
        return (fetched.outcome, Vec::new());
    };
    if response.truncated {
        return some_status(
            SourceOutcomeKind::ParserDrift,
            Some(response.status),
            Some("truncated CKAN body is not evidence".into()),
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
            return some_status(
                SourceOutcomeKind::ParserDrift,
                Some(response.status),
                Some(err.to_string()),
            );
        }
    };
    match ckan::check_envelope(parsed, module) {
        Err(err) => some_status(
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            Some(err.to_string()),
        ),
        Ok(None) => (
            SourceExecutionOutcome::valid_zero(module, now_unix).with_http_status(response.status),
            Vec::new(),
        ),
        Ok(Some(result)) if result.records.is_empty() => (
            SourceExecutionOutcome::valid_zero(module, now_unix).with_http_status(response.status),
            Vec::new(),
        ),
        Ok(Some(result)) => {
            let found = result.records.len();
            (
                SourceExecutionOutcome::success(module, now_unix, found)
                    .with_http_status(response.status),
                result.records,
            )
        }
    }
}

fn merge_by_uid(entities: &mut Vec<Entity>) {
    let mut merged: Vec<Entity> = Vec::new();
    for entity in entities.drain(..) {
        if let Some(existing) = merged.iter_mut().find(|seen| seen.uid == entity.uid) {
            existing.absorb(entity);
        } else {
            merged.push(entity);
        }
    }
    *entities = merged;
}

fn name_tokens(full: &str) -> Vec<String> {
    full.split(|c: char| !c.is_alphabetic())
        .filter(|token| token.len() >= 2)
        .map(str::to_ascii_lowercase)
        .collect()
}

fn record_name_matches(rec: &Map<String, Value>, name_field: &str, full_name: &str) -> bool {
    let Some(name) = field(rec, name_field) else {
        return false;
    };
    whole_word_token_match(&name, full_name)
}

fn norm_name(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_uppercase()
}

fn classify_linked(name: &str) -> (EntityKind, String) {
    if looks_like_company(name) {
        (EntityKind::Organisation, name.trim().to_string())
    } else {
        (EntityKind::Person, humanise_name(name))
    }
}

fn parse_controllers(raw: &str) -> Vec<(String, Option<String>)> {
    raw.split('~')
        .filter_map(|part| {
            let part = part.trim();
            let name = part.split('[').next().unwrap_or(part).trim();
            if name.len() < 3 {
                return None;
            }
            let ceased = part
                .split_once("Date Ceased:")
                .and_then(|(_, rest)| rest.split(']').next())
                .map(str::trim)
                .filter(|date| !date.is_empty())
                .map(str::to_string);
            Some((name.to_string(), ceased))
        })
        .collect()
}

fn provenance(scan_id: &str) -> EvidenceProvenance {
    EvidenceProvenance::for_scan(SRC, scan_id)
}

fn emit_banned(rec: &Map<String, Value>, scan_id: &str, out: &mut Vec<Entity>) {
    let Some(raw_name) = field(rec, "BD_PER_NAME") else {
        return;
    };
    let person_name = humanise_name(&raw_name);
    let mut ev = Evidence::new(
        provenance(scan_id),
        format!("ASIC banned/disqualified: {person_name}"),
    )
    .with_attr("register", "ASIC Banned & Disqualified Persons")
    .with_attr("dataset", "ASIC Banned & Disqualified Persons")
    .with_attr("matched_name", &raw_name);
    for (key, attr) in [
        ("BD_PER_TYPE", "ban_type"),
        ("BD_PER_START_DT", "ban_start"),
        ("BD_PER_END_DT", "ban_end"),
        ("BD_PER_DOC_NUM", "document_no"),
        ("BD_PER_COMMENTS", "comments"),
    ] {
        if let Some(value) = field(rec, key) {
            ev = ev.with_attr(attr, value);
        }
    }

    let mut person = Entity::new(EntityKind::Person, &person_name, CONF_PERSON, scan_id);
    person.tag("au");
    person.tag("asic");
    person.tag("asic-banned");
    person.tag("regulatory-action");
    person.add_evidence(ev);
    out.push(person);

    push_address(
        rec,
        "BD_PER_ADD_LOCAL",
        "BD_PER_ADD_STATE",
        "BD_PER_ADD_PCODE",
        &person_name,
        "asic-banned",
        scan_id,
        out,
    );
}

#[allow(clippy::too_many_lines)]
fn emit_adviser(rec: &Map<String, Value>, scan_id: &str, out: &mut Vec<Entity>) {
    let Some(raw_name) = field(rec, "ADV_NAME") else {
        return;
    };
    let person_name = humanise_name(&raw_name);
    let has_discipline = field(rec, "ADV_DA_TYPE").is_some();

    let mut ev = Evidence::new(
        provenance(scan_id),
        format!("ASIC financial adviser: {person_name}"),
    )
    .with_attr("register", "ASIC Financial Advisers")
    .with_attr("dataset", "ASIC Financial Advisers")
    .with_attr("matched_name", &raw_name);
    for (key, attr) in [
        ("ADV_ROLE", "adviser_role"),
        ("OVERALL_REGISTRATION_STATUS", "registration_status"),
        ("ADV_NUMBER", "adviser_number"),
        ("ADV_FIRST_PROVIDED_ADVICE", "first_advice"),
        ("LICENCE_NAME", "licensee"),
        ("LICENCE_NUMBER", "afs_licence_no"),
        ("LICENCE_CONTROLLED_BY", "licensee_controlled_by"),
        ("REP_APPOINTED_BY", "appointed_by"),
        ("REP_APPOINTED_NUM", "authorised_rep_no"),
        ("ADV_DA_TYPE", "disciplinary_action"),
        ("ADV_DA_DESCRIPTION", "disciplinary_detail"),
    ] {
        if let Some(value) = field(rec, key) {
            ev = ev.with_attr(attr, value);
        }
    }

    let mut person = Entity::new(EntityKind::Person, &person_name, CONF_PERSON, scan_id);
    person.tag("au");
    person.tag("asic");
    person.tag("asic-financial-adviser");
    if has_discipline {
        person.tag("regulatory-action");
        person.tag("disciplinary-action");
    }
    person.add_evidence(ev);
    out.push(person);

    let licensee = field(rec, "LICENCE_NAME");
    if let Some(licensee) = &licensee {
        let mut org = Entity::new(EntityKind::Organisation, licensee, CONF_LICENSEE, scan_id);
        org.tag("au");
        org.tag("asic");
        org.tag("afs-licensee");
        let mut oev = Evidence::new(
            provenance(scan_id),
            format!("AFS licensee of adviser {person_name}"),
        )
        .with_attr("licensee", licensee);
        if let Some(no) = field(rec, "LICENCE_NUMBER") {
            oev = oev.with_attr("afs_licence_no", no);
        }
        org.add_evidence(oev);
        out.push(org);
    }

    if let Some(raw) = field(rec, "LICENCE_CONTROLLED_BY") {
        for (name, ceased) in parse_controllers(&raw) {
            let (kind, value) = classify_linked(&name);
            let mut ent = Entity::new(kind, &value, CONF_CONTROLLER, scan_id);
            ent.tag("au");
            ent.tag("asic");
            ent.tag("afs-licensee-controller");
            let mut cev = Evidence::new(
                provenance(scan_id),
                format!(
                    "Controls AFS licensee {} (adviser {person_name})",
                    licensee.as_deref().unwrap_or("(unknown)")
                ),
            )
            .with_attr("relationship", "licence_controlled_by");
            if let Some(licensee) = &licensee {
                cev = cev.with_attr("controls_licensee", licensee);
            }
            if let Some(date) = ceased {
                ent.tag("ceased");
                cev = cev.with_attr("date_ceased", date);
            }
            ent.add_evidence(cev);
            out.push(ent);
        }
    }

    if let Some(appby) = field(rec, "REP_APPOINTED_BY") {
        let n = norm_name(&appby);
        let is_self = n == norm_name(&raw_name);
        let is_licensee = licensee.as_deref().is_some_and(|l| n == norm_name(l));
        if !is_self && !is_licensee && looks_like_company(&appby) {
            let mut org = Entity::new(EntityKind::Organisation, &appby, CONF_PERSON, scan_id);
            org.tag("au");
            org.tag("asic");
            org.tag("authorised-rep-firm");
            let mut aev = Evidence::new(
                provenance(scan_id),
                format!("Appointed {person_name} as authorised rep"),
            )
            .with_attr("relationship", "rep_appointed_by");
            if let Some(num) = field(rec, "REP_APPOINTED_NUM") {
                aev = aev.with_attr("authorised_rep_no", num);
            }
            org.add_evidence(aev);
            out.push(org);
        }
    }

    for (key, label) in [
        ("ADV_ABN", "adviser"),
        ("LICENCE_ABN", "licensee"),
        ("REP_APPOINTED_ABN", "rep_appointer"),
    ] {
        if let Some(abn) = field(rec, key).filter(|a| is_valid_abn(a)) {
            let mut e = Entity::new(EntityKind::AbnAcn, &abn, CONF_LICENSEE, scan_id);
            e.tag("au");
            e.tag("asic");
            e.add_evidence(
                Evidence::new(
                    provenance(scan_id),
                    format!("{label} ABN from ASIC adviser record of {person_name}"),
                )
                .with_attr("abn", &abn)
                .with_attr("role", label),
            );
            out.push(e);
        }
    }

    push_address(
        rec,
        "ADV_ADD_LOCAL",
        "ADV_ADD_STATE",
        "ADV_ADD_PCODE",
        &person_name,
        "asic-financial-adviser",
        scan_id,
        out,
    );
}

fn emit_credit_rep(rec: &Map<String, Value>, scan_id: &str, out: &mut Vec<Entity>) {
    let Some(raw_name) = field(rec, "CRED_REP_NAME") else {
        return;
    };
    let person_name = humanise_name(&raw_name);

    let mut ev = Evidence::new(
        provenance(scan_id),
        format!("ASIC credit representative: {person_name}"),
    )
    .with_attr("register", "ASIC Credit Representatives")
    .with_attr("dataset", "ASIC Credit Representatives")
    .with_attr("matched_name", &raw_name);
    for (key, attr) in [
        ("CRED_REP_NUM", "credit_rep_number"),
        ("CRED_LIC_NUM", "credit_licence_no"),
        ("CRED_REP_START_DT", "authorised_from"),
        ("CRED_REP_END_DT", "authorised_to"),
        ("CRED_REP_EDRS", "dispute_scheme"),
    ] {
        if let Some(value) = field(rec, key) {
            ev = ev.with_attr(attr, value);
        }
    }

    let mut person = Entity::new(EntityKind::Person, &person_name, CONF_PERSON, scan_id);
    person.tag("au");
    person.tag("asic");
    person.tag("asic-credit-rep");
    person.add_evidence(ev);
    out.push(person);

    if let Some(id) = field(rec, "CRED_REP_ABN_ACN").filter(|a| is_valid_abn(a) || is_valid_acn(a))
    {
        let mut e = Entity::new(EntityKind::AbnAcn, &id, CONF_PERSON, scan_id);
        e.tag("au");
        e.tag("asic");
        e.tag("asic-credit-rep");
        e.add_evidence(
            Evidence::new(
                provenance(scan_id),
                format!("ABN/ACN of credit representative {person_name}"),
            )
            .with_attr("abn_acn", &id),
        );
        out.push(e);
    }

    push_address(
        rec,
        "CRED_REP_LOCALITY",
        "CRED_REP_STATE",
        "CRED_REP_PCODE",
        &person_name,
        "asic-credit-rep",
        scan_id,
        out,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_address(
    rec: &Map<String, Value>,
    local_key: &str,
    state_key: &str,
    pcode_key: &str,
    person: &str,
    tag: &str,
    scan_id: &str,
    out: &mut Vec<Entity>,
) {
    let parts: Vec<String> = [local_key, state_key, pcode_key]
        .into_iter()
        .filter_map(|k| field(rec, k))
        .collect();
    if parts.is_empty() {
        return;
    }
    let addr = parts.join(" ");
    let sc = address_au::state_code(&addr);
    let mut a = Entity::new(EntityKind::Address, &addr, CONF_ADDRESS, scan_id);
    a.tag("au");
    a.tag("asic");
    a.tag(tag);
    a.tag("country:AU");
    if let Some(state) = sc {
        a.tag(format!("au-state:{state}"));
    }
    a.add_evidence(
        Evidence::new(
            provenance(scan_id),
            format!("Registered address for {person}"),
        )
        .with_attr("address", &addr)
        .with_attr("source", "asic-register"),
    );
    out.push(a);

    let Some(pcode) = field(rec, pcode_key) else {
        return;
    };
    let Some((lat, lon)) = postcode_au::offline_centroid(&pcode) else {
        return;
    };
    let coord_val = format!("{lat:.4},{lon:.4}");
    let mut c = Entity::new(EntityKind::Coordinates, &coord_val, CONF_COORDS, scan_id);
    c.tag("au");
    c.tag("asic");
    c.tag("addr-derived");
    c.tag("geoint");
    c.tag("country:AU");
    if let Some(state) = sc {
        c.tag(format!("au-state:{state}"));
    }
    c.add_evidence(
        Evidence::new(
            provenance(scan_id),
            format!("Geocoded register address for {person}"),
        )
        .with_attr("source_address", &addr),
    );
    out.push(c);
}

fn humanise_name(s: &str) -> String {
    let reordered = match s.split_once(',') {
        Some((surname, first)) => format!("{} {}", first.trim(), surname.trim()),
        None => s.trim().to_string(),
    };
    title_case(&reordered.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    use crate::http::{Response, TransportFailure};
    use crate::textnorm::ascii_digits;

    const BANNED: &str = r##"{
  "BD_PER_NAME":"ABBOTT, BILL","BD_PER_TYPE":"Banned Securities",
  "BD_PER_START_DT":"29/03/1994","BD_PER_END_DT":"29/03/1999",
  "BD_PER_DOC_NUM":"#004289112","BD_PER_ADD_LOCAL":"TEMPLESTOWE LOWER",
  "BD_PER_ADD_STATE":"VIC","BD_PER_ADD_PCODE":"3107","BD_PER_COMMENTS":"No comment made"}"##;

    const ADVISER: &str = r#"{
  "ADV_NAME":"CITIZEN, JANE","ADV_ROLE":"Authorised Representative",
  "OVERALL_REGISTRATION_STATUS":"Current","ADV_NUMBER":"123456",
  "LICENCE_NAME":"Acme Financial Pty Ltd","LICENCE_NUMBER":"234567",
  "ADV_ABN":"51 824 753 556","LICENCE_ABN":"53004085616",
  "ADV_ADD_LOCAL":"SYDNEY","ADV_ADD_STATE":"NSW","ADV_ADD_PCODE":"2000",
  "ADV_DA_TYPE":"","ADV_DA_DESCRIPTION":""}"#;

    const ADVISER_LINKED: &str = r#"{
  "ADV_NAME":"POPOV, MARSEL","ADV_ROLE":"Authorised Representative",
  "OVERALL_REGISTRATION_STATUS":"Current",
  "LICENCE_NAME":"VIRIDIAN ADVISORY PTY LTD","LICENCE_NUMBER":"34605438042",
  "LICENCE_CONTROLLED_BY":"NATIONAL AUSTRALIA BANK LIMITED [Date Ceased: 21/08/2023] ~ MLC WEALTH LIMITED",
  "REP_APPOINTED_BY":"VIRIDIAN FINANCIAL GROUP LTD","REP_APPOINTED_NUM":"000315094",
  "REP_APPOINTED_ABN":"67 605 994 741"}"#;

    const CREDIT: &str = r#"{
  "CRED_REP_NAME":"SMITH, JOHN ANDREW","CRED_REP_NUM":"563552","CRED_LIC_NUM":"385487",
  "CRED_REP_ABN_ACN":"004085616","CRED_REP_START_DT":"30/10/2024",
  "CRED_REP_LOCALITY":"BERWICK","CRED_REP_STATE":"VIC","CRED_REP_PCODE":"3806","CRED_REP_EDRS":"AFCA"}"#;

    fn rec(json: &str) -> Map<String, Value> {
        serde_json::from_str(json).expect("record")
    }

    fn display_eq(entity: &Entity, expected: &str) -> bool {
        entity.raw_value.eq_ignore_ascii_case(expected)
            || entity.value.eq_ignore_ascii_case(expected)
    }

    fn org_named<'a>(entities: &'a [Entity], name: &str) -> Option<&'a Entity> {
        entities
            .iter()
            .find(|e| e.kind == EntityKind::Organisation && display_eq(e, name))
    }

    #[test]
    fn banned_emits_adverse_person_and_address() {
        let mut entities = Vec::new();
        emit_banned(&rec(BANNED), "scan", &mut entities);

        let person = entities
            .iter()
            .find(|x| x.kind == EntityKind::Person)
            .expect("person");
        assert_eq!(person.raw_value, "Bill Abbott");
        assert!(person.has_tag("asic-banned") && person.has_tag("regulatory-action"));
        assert!(person.evidence.iter().any(|ev| {
            ev.attributes
                .get("ban_type")
                .is_some_and(|v| v == "Banned Securities")
        }));
        assert!(entities.iter().any(|x| x.kind == EntityKind::Address
            && x.value.eq_ignore_ascii_case("TEMPLESTOWE LOWER VIC 3107")));
    }

    #[test]
    fn adviser_emits_person_licensee_abns_and_address() {
        let mut entities = Vec::new();
        emit_adviser(&rec(ADVISER), "scan", &mut entities);

        let person = entities
            .iter()
            .find(|x| x.kind == EntityKind::Person)
            .expect("person");
        assert_eq!(person.raw_value, "Jane Citizen");
        assert!(person.has_tag("asic-financial-adviser"));
        assert!(!person.has_tag("disciplinary-action"));

        assert!(entities.iter().any(|x| x.kind == EntityKind::Organisation
            && display_eq(x, "Acme Financial Pty Ltd")
            && x.has_tag("afs-licensee")));
        let abns: Vec<String> = entities
            .iter()
            .filter(|x| x.kind == EntityKind::AbnAcn)
            .map(|x| ascii_digits(&x.value))
            .collect();
        assert!(abns.contains(&"51824753556".to_string()));
        assert!(abns.contains(&"53004085616".to_string()));
        let addr = entities
            .iter()
            .find(|x| {
                x.kind == EntityKind::Address && x.value.eq_ignore_ascii_case("SYDNEY NSW 2000")
            })
            .expect("registered address");
        assert!(
            addr.has_tag("au-state:NSW") && addr.has_tag("country:AU"),
            "register address must carry its AU jurisdiction"
        );
        assert!(
            entities
                .iter()
                .any(|x| x.kind == EntityKind::Coordinates && x.has_tag("au-state:NSW")),
            "postcode 2000 must geocode via the offline gazetteer"
        );
    }

    #[test]
    fn two_registers_same_postcode_dedup_to_one_coordinates_entity() {
        let banned = rec(
            r#"{"BD_PER_NAME":"ABBOTT, BILL","BD_PER_TYPE":"Banned Securities",
        "BD_PER_ADD_LOCAL":"SYDNEY","BD_PER_ADD_STATE":"NSW","BD_PER_ADD_PCODE":"2000"}"#,
        );
        let adviser = rec(
            r#"{"ADV_NAME":"CITIZEN, JANE","ADV_ROLE":"Authorised Representative",
        "OVERALL_REGISTRATION_STATUS":"Current","ADV_ADD_LOCAL":"Sydney CBD","ADV_ADD_STATE":"NSW","ADV_ADD_PCODE":"2000"}"#,
        );
        let mut entities = Vec::new();
        emit_banned(&banned, "scan", &mut entities);
        emit_adviser(&adviser, "scan", &mut entities);
        let raw_coords = entities
            .iter()
            .filter(|e| e.kind == EntityKind::Coordinates)
            .count();
        assert_eq!(raw_coords, 2, "two Sydney 2000 addresses must both geocode");
        merge_by_uid(&mut entities);
        let coords = entities
            .iter()
            .filter(|e| e.kind == EntityKind::Coordinates)
            .count();
        assert_eq!(coords, 1, "same centroid must merge: {entities:?}");
    }

    #[test]
    fn adviser_with_disciplinary_action_is_flagged() {
        let mut m = rec(ADVISER);
        m.insert("ADV_DA_TYPE".into(), Value::String("Banning Order".into()));
        m.insert(
            "ADV_DA_DESCRIPTION".into(),
            Value::String("Banned for 3 years".into()),
        );
        let mut entities = Vec::new();
        emit_adviser(&m, "scan", &mut entities);
        let person = entities
            .iter()
            .find(|x| x.kind == EntityKind::Person)
            .expect("person");
        assert!(person.has_tag("regulatory-action") && person.has_tag("disciplinary-action"));
        assert!(
            person
                .evidence
                .iter()
                .any(|ev| ev.attributes.contains_key("disciplinary_action"))
        );
    }

    #[test]
    fn adviser_emits_licensee_controllers_and_distinct_appointer() {
        let mut entities = Vec::new();
        emit_adviser(&rec(ADVISER_LINKED), "scan", &mut entities);

        assert!(
            org_named(&entities, "VIRIDIAN ADVISORY PTY LTD")
                .expect("licensee")
                .has_tag("afs-licensee")
        );

        let nab = org_named(&entities, "NATIONAL AUSTRALIA BANK LIMITED")
            .expect("current-then-ceased controller");
        assert!(nab.has_tag("afs-licensee-controller") && nab.has_tag("ceased"));
        assert!(
            nab.evidence[0]
                .attributes
                .get("date_ceased")
                .is_some_and(|d| d == "21/08/2023")
        );
        let mlc = org_named(&entities, "MLC WEALTH LIMITED").expect("second controller");
        assert!(mlc.has_tag("afs-licensee-controller") && !mlc.has_tag("ceased"));

        let appointer =
            org_named(&entities, "VIRIDIAN FINANCIAL GROUP LTD").expect("appointing firm");
        assert!(appointer.has_tag("authorised-rep-firm"));
        assert!(
            appointer.evidence[0]
                .attributes
                .get("authorised_rep_no")
                .is_some_and(|n| n == "000315094")
        );

        let abns: Vec<String> = entities
            .iter()
            .filter(|x| x.kind == EntityKind::AbnAcn)
            .map(|x| ascii_digits(&x.value))
            .collect();
        assert!(
            abns.contains(&"67605994741".to_string()),
            "rep_appointer ABN"
        );
    }

    #[test]
    fn self_appointment_and_licensee_appointer_are_not_separate_firms() {
        let mut m = rec(ADVISER);
        m.insert(
            "REP_APPOINTED_BY".into(),
            Value::String("CITIZEN, JANE".into()),
        );
        let mut entities = Vec::new();
        emit_adviser(&m, "scan", &mut entities);
        assert!(
            !entities.iter().any(|x| x.has_tag("authorised-rep-firm")),
            "a self-appointment must not surface as an appointing firm"
        );

        let mut m2 = rec(ADVISER);
        m2.insert(
            "REP_APPOINTED_BY".into(),
            Value::String("Acme Financial Pty Ltd".into()),
        );
        let mut entities2 = Vec::new();
        emit_adviser(&m2, "scan", &mut entities2);
        assert!(
            !entities2.iter().any(|x| x.has_tag("authorised-rep-firm")),
            "an appointer equal to the licensee must not be duplicated as a firm"
        );
    }

    #[test]
    fn individual_controller_is_typed_as_person_not_org() {
        let mut m = rec(ADVISER);
        m.insert(
            "LICENCE_CONTROLLED_BY".into(),
            Value::String("MELISSA  GOODIN".into()),
        );
        let mut entities = Vec::new();
        emit_adviser(&m, "scan", &mut entities);

        let controller = entities
            .iter()
            .find(|x| x.has_tag("afs-licensee-controller"))
            .expect("controller entity");
        assert_eq!(controller.kind, EntityKind::Person);
        assert_eq!(controller.raw_value, "Melissa Goodin");
        assert!(
            !entities
                .iter()
                .any(|x| x.kind == EntityKind::Organisation && x.has_tag("afs-licensee-controller")),
            "an individual controller must not be an Organisation"
        );
    }

    #[test]
    fn parse_controllers_splits_and_strips_ceased_markers() {
        let parsed = parse_controllers(
            "NATIONAL AUSTRALIA BANK LIMITED [Date Ceased: 21/08/2023] ~ MLC WEALTH LIMITED [Date Ceased: 20/05/2021]",
        );
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "NATIONAL AUSTRALIA BANK LIMITED");
        assert_eq!(parsed[0].1.as_deref(), Some("21/08/2023"));
        assert_eq!(parsed[1].0, "MLC WEALTH LIMITED");
        assert_eq!(parsed[1].1.as_deref(), Some("20/05/2021"));

        let one = parse_controllers("SOME PARENT PTY LTD");
        assert_eq!(one, vec![("SOME PARENT PTY LTD".to_string(), None)]);
        let none = parse_controllers("  ~  ~ AB");
        assert!(none.is_empty(), "{none:?}");
    }

    #[test]
    fn credit_rep_emits_person_abn_and_address() {
        let mut entities = Vec::new();
        emit_credit_rep(&rec(CREDIT), "scan", &mut entities);
        let person = entities
            .iter()
            .find(|x| x.kind == EntityKind::Person)
            .expect("person");
        assert_eq!(person.raw_value, "John Andrew Smith");
        assert!(person.has_tag("asic-credit-rep"));
        assert!(person.evidence.iter().any(|ev| {
            ev.attributes
                .get("credit_licence_no")
                .is_some_and(|v| v == "385487")
        }));
        assert!(
            entities
                .iter()
                .any(|x| x.kind == EntityKind::AbnAcn && ascii_digits(&x.value) == "004085616")
        );
        assert!(
            entities.iter().any(|x| x.kind == EntityKind::Address
                && x.value.eq_ignore_ascii_case("BERWICK VIC 3806"))
        );
    }

    #[test]
    fn checksum_invalid_abn_or_acn_is_not_emitted_as_a_pivot() {
        let mut adv = rec(ADVISER);
        adv.insert("ADV_ABN".into(), Value::String("11111111111".into()));
        let mut entities = Vec::new();
        emit_adviser(&adv, "scan", &mut entities);
        assert!(
            !entities
                .iter()
                .any(|x| x.kind == EntityKind::AbnAcn && ascii_digits(&x.value) == "11111111111"),
            "a checksum-invalid ABN must not be emitted as a pivot"
        );
        assert!(
            entities
                .iter()
                .any(|x| x.kind == EntityKind::AbnAcn && ascii_digits(&x.value) == "53004085616")
        );

        let mut cred = rec(CREDIT);
        cred.insert("CRED_REP_ABN_ACN".into(), Value::String("111111111".into()));
        let mut entities2 = Vec::new();
        emit_credit_rep(&cred, "scan", &mut entities2);
        assert!(
            !entities2.iter().any(|x| x.kind == EntityKind::AbnAcn),
            "a checksum-invalid ACN must not be emitted as a pivot"
        );
    }

    #[test]
    fn name_matching_is_order_independent_and_token_complete() {
        let tokens = name_tokens("Bill Abbott");
        assert_eq!(tokens, vec!["bill".to_string(), "abbott".to_string()]);
        assert!(record_name_matches(
            &rec(BANNED),
            "BD_PER_NAME",
            "Bill Abbott"
        ));
        assert!(!record_name_matches(
            &rec(BANNED),
            "BD_PER_NAME",
            "John Smith"
        ));
        assert_eq!(name_tokens("Madonna").len(), 1);
    }

    #[test]
    fn name_matching_is_whole_word_not_substring() {
        let greenwood = rec(r#"{"BD_PER_NAME":"GREENWOOD, ALEXANDRA"}"#);
        assert!(
            !record_name_matches(&greenwood, "BD_PER_NAME", "Al Green"),
            "\"al\"/\"green\" must not match as substrings of \"Alexandra\"/\"Greenwood\""
        );
        assert!(record_name_matches(
            &greenwood,
            "BD_PER_NAME",
            "Alexandra Greenwood"
        ));
    }

    #[test]
    fn humanise_name_reorders_and_titlecases() {
        assert_eq!(humanise_name("ABBOTT, BILL"), "Bill Abbott");
        assert_eq!(humanise_name("CITIZEN, JANE MARY"), "Jane Mary Citizen");
        assert_eq!(humanise_name("Jane Citizen"), "Jane Citizen");
    }

    fn envelope(records: &str) -> String {
        format!(r#"{{"success":true,"result":{{"records":[{records}]}}}}"#)
    }

    fn json_ok(body: &str) -> Response {
        Response {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.as_bytes().to_vec(),
            truncated: false,
        }
    }

    struct Fake {
        by_id: RefCell<HashMap<String, Result<Response, TransportFailure>>>,
        seen: RefCell<Vec<String>>,
    }

    impl Fake {
        fn new(script: HashMap<String, Result<Response, TransportFailure>>) -> Self {
            Self {
                by_id: RefCell::new(script),
                seen: RefCell::default(),
            }
        }
    }

    impl Transport for Fake {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.seen.borrow_mut().push(request.url.clone());
            let id = request
                .url
                .split("resource_id=")
                .nth(1)
                .and_then(|rest| rest.split('&').next())
                .expect("CKAN resource_id");
            self.by_id
                .borrow_mut()
                .remove(id)
                .unwrap_or_else(|| panic!("unexpected resource {id}"))
        }
    }

    fn empty_script() -> HashMap<String, Result<Response, TransportFailure>> {
        let empty = json_ok(r#"{"success":true,"result":{"records":[]}}"#);
        HashMap::from([
            (BANNED_RES.into(), Ok(empty.clone())),
            (ADVISER_RES.into(), Ok(empty.clone())),
            (CREDIT_RES.into(), Ok(empty)),
        ])
    }

    #[test]
    fn single_token_name_makes_no_request() {
        let fake = Fake::new(empty_script());
        let report = lookup(&fake, "Madonna", "t", 1).expect("no-op");
        let entities = &report.entities;
        assert!(entities.is_empty(), "{entities:?}");
        let seen = fake.seen.borrow();
        assert!(seen.is_empty(), "{seen:?}");
    }

    #[test]
    fn lookup_emits_banned_person_from_scripted_ckan() {
        let mut script = empty_script();
        script.insert(BANNED_RES.into(), Ok(json_ok(&envelope(BANNED))));
        let fake = Fake::new(script);
        let report = lookup(&fake, "Bill Abbott", "scan", 1).expect("lookup");
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Person && e.has_tag("asic-banned")),
            "expected banned person: {:?}",
            report.entities
        );
        assert_eq!(fake.seen.borrow().len(), 3);
        assert!(
            report
                .outcomes
                .iter()
                .any(|o| o.module == "asic_persons.banned" && o.kind == SourceOutcomeKind::Success)
        );
        assert!(
            report
                .outcomes
                .iter()
                .filter(|o| o.module != "asic_persons.banned")
                .all(|o| o.kind == SourceOutcomeKind::ValidZero)
        );
    }

    #[test]
    fn ckan_success_false_is_not_empty_absence() {
        let fail = json_ok(r#"{"success":false}"#);
        let fake = Fake::new(HashMap::from([
            (BANNED_RES.into(), Ok(fail.clone())),
            (ADVISER_RES.into(), Ok(fail.clone())),
            (CREDIT_RES.into(), Ok(fail)),
        ]));
        let err = lookup(&fake, "Bill Abbott", "scan", 1).expect_err("outage");
        assert!(
            matches!(err, Error::Invalid(ref msg) if msg.contains("success=false")),
            "{err}"
        );
    }

    #[test]
    fn truncated_body_is_not_evidence() {
        let mut truncated = json_ok(&envelope(BANNED));
        truncated.truncated = true;
        let empty = json_ok(r#"{"success":true,"result":{"records":[]}}"#);
        let fake = Fake::new(HashMap::from([
            (BANNED_RES.into(), Ok(truncated)),
            (ADVISER_RES.into(), Ok(empty.clone())),
            (CREDIT_RES.into(), Ok(empty)),
        ]));
        let err = lookup(&fake, "Bill Abbott", "scan", 1).expect_err("truncated");
        assert!(matches!(err, Error::Invalid(_)), "{err}");
    }

    #[test]
    fn challenge_page_is_not_a_register_miss() {
        let challenge = Response {
            status: 200,
            headers: vec![("content-type".into(), "text/html".into())],
            body: b"<html>Just a moment... cf-browser-verification checking your browser</html>"
                .to_vec(),
            truncated: false,
        };
        let empty = json_ok(r#"{"success":true,"result":{"records":[]}}"#);
        let fake = Fake::new(HashMap::from([
            (BANNED_RES.into(), Ok(challenge)),
            (ADVISER_RES.into(), Ok(empty.clone())),
            (CREDIT_RES.into(), Ok(empty)),
        ]));
        let err = lookup(&fake, "Bill Abbott", "scan", 1).expect_err("waf");
        assert!(matches!(err, Error::Invalid(_)), "{err}");
    }
}
