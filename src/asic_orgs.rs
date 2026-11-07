//! ASIC organisation registers over data.gov.au CKAN — the Company Dataset, the Business Names
//! Dataset, Banned and Disqualified Organisations, AFS licensees and credit licensees. Keyless.
//! Blocking.
//!
//! One query is a name, a nine-digit ACN or an eleven-digit ABN. A name matches a record only when
//! every query token is a whole word of the registered name; an ACN or ABN matches only a record
//! carrying exactly that checksum-valid number, so a full-text rank can never attach an unrelated
//! company. Each register runs through the shared fail-closed [`crate::ckan::query_datastore`] path:
//! a challenge page, truncated body or `success: false` envelope is never evidence, and a page cut
//! short of its total never proves absence.
//!
//! A company keeps its ACN, ABN, type, class, status and registration dates verbatim, and a former
//! name stays an attribute of the company under its current name. A business name is a trading name
//! registered to the ABN holder, so its ABN is the pivot that links it to that holder. A banned
//! organisation is a regulatory action and is tagged as one. Every record is a register entry to
//! review, never a confirmed identity or a finding about any person.

use serde_json::{Map, Value};

use crate::au_id::{is_valid_abn, is_valid_acn};
use crate::ckan::{self, field};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid};
use crate::error::Error;
use crate::http::Transport;
use crate::source_outcome::SourceExecutionOutcome;
use crate::textnorm::{ascii_digits, whole_word_token_match};

pub const SRC: &str = "asic_orgs";
const CKAN_BASE: &str = "https://data.gov.au/data/api/3/action";
pub(crate) const COMPANY_RES: &str = "5c3914e6-413e-4a2c-b890-bf8efe3eabf2";
pub(crate) const BUSINESS_NAME_RES: &str = "55ad4b1c-5eeb-44ea-8b29-d410da431be3";
pub(crate) const BANNED_ORG_RES: &str = "ced03961-e6f7-4263-895a-0fd1d7996043";
pub(crate) const AFS_LICENSEE_RES: &str = "1fc2b334-74ae-4588-85aa-83e3a8c9f2cc";
pub(crate) const CREDIT_LICENSEE_RES: &str = "35953a01-a9a8-4609-8566-c9fa7de465d3";
const MAX_HITS: usize = 100;

const CONF_ORG: f64 = 0.70;
const CONF_ID: f64 = 0.72;

/// One query across the ASIC organisation registers.
pub type Report = crate::lookup_report::LookupReport;

/// What one query asks: a registered number, or the words of a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    Acn(String),
    Abn(String),
    Name(String),
}

impl Query {
    /// Classify `raw`: digits (spaces allowed) forming a checksum-valid ACN or ABN are that number;
    /// anything else with at least one alphanumeric word is a name. `None` for an empty query or a
    /// number that fails its checksum. **Pure.**
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        let compact: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
        if !compact.is_empty() && compact.bytes().all(|b| b.is_ascii_digit()) {
            return match compact.len() {
                9 if is_valid_acn(&compact) => Some(Self::Acn(compact)),
                11 if is_valid_abn(&compact) => Some(Self::Abn(compact)),
                _ => None,
            };
        }
        raw.chars()
            .any(char::is_alphanumeric)
            .then(|| Self::Name(raw.to_owned()))
    }

    fn search_text(&self) -> &str {
        match self {
            Self::Acn(id) | Self::Abn(id) | Self::Name(id) => id,
        }
    }
}

/// One organisation register: where it lives, which columns identify a record, and how a matched
/// row becomes entities.
struct Register {
    module: &'static str,
    resource: &'static str,
    name_fields: &'static [&'static str],
    acn_field: Option<&'static str>,
    abn_field: Option<&'static str>,
    emit: fn(&Map<String, Value>, &str, &mut Vec<Entity>),
}

const REGISTERS: [Register; 5] = [
    Register {
        module: "asic_orgs.companies",
        resource: COMPANY_RES,
        name_fields: &["Company Name", "Current Name"],
        acn_field: Some("ACN"),
        abn_field: Some("ABN"),
        emit: emit_company,
    },
    Register {
        module: "asic_orgs.business_names",
        resource: BUSINESS_NAME_RES,
        name_fields: &["BN_NAME"],
        acn_field: None,
        abn_field: Some("BN_ABN"),
        emit: emit_business_name,
    },
    Register {
        module: "asic_orgs.banned",
        resource: BANNED_ORG_RES,
        name_fields: &["BD_ORG_NAME"],
        acn_field: Some("BD_ORG_ACN"),
        abn_field: None,
        emit: emit_banned_org,
    },
    Register {
        module: "asic_orgs.afs_licensees",
        resource: AFS_LICENSEE_RES,
        name_fields: &["AFS_LIC_NAME"],
        // One column holds the licensee's ABN or ACN.
        acn_field: Some("AFS_LIC_ABN_ACN"),
        abn_field: Some("AFS_LIC_ABN_ACN"),
        emit: emit_afs_licensee,
    },
    Register {
        module: "asic_orgs.credit_licensees",
        resource: CREDIT_LICENSEE_RES,
        name_fields: &["CRED_LIC_NAME"],
        acn_field: Some("CRED_LIC_ABN_ACN"),
        abn_field: Some("CRED_LIC_ABN_ACN"),
        emit: emit_credit_licensee,
    },
];

/// Look up `query` on the ASIC organisation registers. A register that cannot be asked the
/// query's kind (a business name has no ACN; a banned organisation has no ABN) is not asked.
///
/// # Errors
/// [`Error::Network`] when egress refuses a request. [`Error::Invalid`] when every register asked
/// failed and no entity was emitted.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    query: &Query,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let mut report = Report::default();
    let mut hard_failure: Option<Error> = None;
    for spec in REGISTERS.iter().filter(|spec| asks(spec, query)) {
        let (outcome, records) = match ckan::query_datastore(
            transport,
            CKAN_BASE,
            spec.module,
            spec.resource,
            query.search_text(),
            MAX_HITS,
            now_unix,
        ) {
            Ok(answer) => answer,
            Err(err @ Error::Network(_)) => return Err(err),
            Err(err) => {
                let failed =
                    SourceExecutionOutcome::inconclusive(spec.module, now_unix, err.to_string());
                hard_failure.get_or_insert(err);
                (failed, Vec::new())
            }
        };
        if !outcome.kind.is_accepted() {
            hard_failure.get_or_insert_with(|| {
                Error::Invalid(
                    outcome
                        .detail
                        .clone()
                        .unwrap_or_else(|| format!("{} failed", spec.module)),
                )
            });
        }
        let matched: Vec<&Map<String, Value>> = records
            .iter()
            .filter(|rec| record_matches(spec, rec, query))
            .take(MAX_HITS)
            .collect();
        let outcome = ckan::reconcile_matches(outcome, matched.len(), spec.module, now_unix);
        for rec in matched {
            (spec.emit)(rec, scan_id, &mut report.entities);
        }
        report.outcomes.push(outcome);
    }
    merge_by_uid(&mut report.entities);
    if report.entities.is_empty() && !report.outcomes.iter().any(|o| o.kind.is_accepted()) {
        if let Some(err) = hard_failure {
            return Err(err);
        }
    }
    Ok(report)
}

/// Whether `spec` holds the identifier `query` asks for. **Pure.**
fn asks(spec: &Register, query: &Query) -> bool {
    match query {
        Query::Acn(_) => spec.acn_field.is_some(),
        Query::Abn(_) => spec.abn_field.is_some(),
        Query::Name(_) => true,
    }
}

/// Whether `rec` is the record `query` names: the exact number in its ACN or ABN column, or every
/// query token as a whole word of one of its name columns. **Pure.**
fn record_matches(spec: &Register, rec: &Map<String, Value>, query: &Query) -> bool {
    let id_is = |column: Option<&str>, id: &str| {
        column
            .and_then(|column| field(rec, column))
            .is_some_and(|value| ascii_digits(&value) == id)
    };
    match query {
        Query::Acn(id) => id_is(spec.acn_field, id),
        Query::Abn(id) => id_is(spec.abn_field, id),
        Query::Name(name) => spec
            .name_fields
            .iter()
            .filter_map(|column| field(rec, column))
            .any(|registered| whole_word_token_match(&registered, name)),
    }
}

fn provenance(scan_id: &str) -> EvidenceProvenance {
    EvidenceProvenance::for_scan(SRC, scan_id)
}

fn with_fields(mut ev: Evidence, rec: &Map<String, Value>, pairs: &[(&str, &str)]) -> Evidence {
    for (column, attr) in pairs {
        if let Some(value) = field(rec, column) {
            ev = ev.with_attr(*attr, value);
        }
    }
    ev
}

/// A checksum-valid ACN or ABN from `column` as an `AbnAcn` pivot. **Pure.**
fn push_id(
    rec: &Map<String, Value>,
    column: &str,
    holder: &str,
    tag: &str,
    scan_id: &str,
    out: &mut Vec<Entity>,
) {
    let Some(id) = field(rec, column)
        .map(|raw| ascii_digits(&raw))
        .filter(|id| is_valid_acn(id) || is_valid_abn(id))
    else {
        return;
    };
    let mut e = Entity::new(EntityKind::AbnAcn, &id, CONF_ID, scan_id);
    e.tag("au");
    e.tag("asic");
    e.tag(tag);
    e.add_evidence(
        Evidence::new(
            provenance(scan_id),
            format!("{column} of {holder} on an ASIC register"),
        )
        .with_attr("abn_acn", &id)
        .with_attr("holder", holder),
    );
    out.push(e);
}

fn emit_company(rec: &Map<String, Value>, scan_id: &str, out: &mut Vec<Entity>) {
    let Some(registered) = field(rec, "Company Name") else {
        return;
    };
    // The dataset keeps one row per name a company has held; `Current Name` is set on a former
    // name's row. The company is the entity under its current name, the former name evidence.
    let current = field(rec, "Current Name").unwrap_or_else(|| registered.clone());
    let former = (current != registered).then_some(registered.as_str());
    let mut ev = Evidence::new(
        provenance(scan_id),
        format!("ASIC registered company: {current}"),
    )
    .with_attr("register", "ASIC Company Dataset")
    .with_attr("dataset", "ASIC Company Dataset")
    .with_attr("matched_name", &registered)
    .with_optional_attrs([("former_name", former)]);
    ev = with_fields(
        ev,
        rec,
        &[
            ("ACN", "acn"),
            ("ABN", "abn"),
            ("Type", "company_type"),
            ("Class", "company_class"),
            ("Sub Class", "company_subclass"),
            ("Status", "status"),
            ("Date of Registration", "registered_on"),
            ("Date of Deregistration", "deregistered_on"),
            ("Previous State of Registration", "previous_state"),
            ("Current Name Start Date", "current_name_since"),
        ],
    );
    let mut org = Entity::new(EntityKind::Organisation, &current, CONF_ORG, scan_id);
    org.tag("au");
    org.tag("asic");
    org.tag("asic-company");
    if field(rec, "Status").is_some_and(|status| status.eq_ignore_ascii_case("DRGD")) {
        org.tag("deregistered");
    }
    org.add_evidence(ev);
    out.push(org);
    push_id(rec, "ACN", &current, "asic-company", scan_id, out);
    push_id(rec, "ABN", &current, "asic-company", scan_id, out);
}

fn emit_business_name(rec: &Map<String, Value>, scan_id: &str, out: &mut Vec<Entity>) {
    let Some(name) = field(rec, "BN_NAME") else {
        return;
    };
    let ev = with_fields(
        Evidence::new(
            provenance(scan_id),
            format!("ASIC registered business name: {name}"),
        )
        .with_attr("register", "ASIC Business Names")
        .with_attr("dataset", "ASIC Business Names")
        .with_attr("matched_name", &name),
        rec,
        &[
            ("BN_STATUS", "status"),
            ("BN_REG_DT", "registered_on"),
            ("BN_CANCEL_DT", "cancelled_on"),
            ("BN_STATE_OF_REG", "state_of_registration"),
            ("BN_STATE_NUM", "state_number"),
            ("BN_ABN", "holder_abn"),
        ],
    );
    let mut org = Entity::new(EntityKind::Organisation, &name, CONF_ORG, scan_id);
    org.tag("au");
    org.tag("asic");
    org.tag("asic-business-name");
    org.add_evidence(ev);
    out.push(org);
    push_id(rec, "BN_ABN", &name, "asic-business-name", scan_id, out);
}

fn emit_banned_org(rec: &Map<String, Value>, scan_id: &str, out: &mut Vec<Entity>) {
    let Some(raw) = field(rec, "BD_ORG_NAME") else {
        return;
    };
    // The register writes some names with a non-breaking space; the entity keeps plain spaces.
    let name = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let ev = with_fields(
        Evidence::new(
            provenance(scan_id),
            format!("ASIC banned/disqualified organisation: {name}"),
        )
        .with_attr("register", "ASIC Banned and Disqualified Organisations")
        .with_attr("dataset", "ASIC Banned and Disqualified Organisations")
        .with_attr("matched_name", &raw),
        rec,
        &[
            ("BD_ORG_TYPE", "ban_type"),
            ("BD_ORG_START_DT", "ban_start"),
            ("BD_ORG_END_DT", "ban_end"),
            ("BD_ORG_COMMENT", "comments"),
            ("BD_ORG_ACN", "acn"),
        ],
    );
    let mut org = Entity::new(EntityKind::Organisation, &name, CONF_ORG, scan_id);
    org.tag("au");
    org.tag("asic");
    org.tag("asic-banned-org");
    org.tag("regulatory-action");
    org.add_evidence(ev);
    out.push(org);
    push_id(rec, "BD_ORG_ACN", &name, "asic-banned-org", scan_id, out);
}

/// One licence register row: the licensee `Organisation` with its verbatim licence fields, its
/// ABN/ACN pivot and its registered address. A licence is a permission ASIC granted, never a
/// finding about the licensee. **Pure.**
fn emit_licensee(
    rec: &Map<String, Value>,
    scan_id: &str,
    out: &mut Vec<Entity>,
    licence: &Licence,
) {
    let Some(name) = field(rec, licence.name) else {
        return;
    };
    let ev = with_fields(
        Evidence::new(provenance(scan_id), format!("{}: {name}", licence.title))
            .with_attr("register", licence.title)
            .with_attr("dataset", licence.title)
            .with_attr("matched_name", &name),
        rec,
        licence.attrs,
    );
    let mut org = Entity::new(EntityKind::Organisation, &name, CONF_ORG, scan_id);
    org.tag("au");
    org.tag("asic");
    org.tag(licence.tag);
    org.add_evidence(ev);
    out.push(org);
    push_id(rec, licence.id, &name, licence.tag, scan_id, out);
    let (local, state, pcode) = licence.address;
    crate::asic_persons::push_address(rec, local, state, pcode, &name, licence.tag, scan_id, out);
}

/// The columns of one licence register.
struct Licence {
    title: &'static str,
    tag: &'static str,
    name: &'static str,
    id: &'static str,
    address: (&'static str, &'static str, &'static str),
    attrs: &'static [(&'static str, &'static str)],
}

fn emit_afs_licensee(rec: &Map<String, Value>, scan_id: &str, out: &mut Vec<Entity>) {
    emit_licensee(
        rec,
        scan_id,
        out,
        &Licence {
            title: "ASIC AFS Licensees",
            tag: "asic-afs-licensee",
            name: "AFS_LIC_NAME",
            id: "AFS_LIC_ABN_ACN",
            address: (
                "AFS_LIC_ADD_LOCAL",
                "AFS_LIC_ADD_STATE",
                "AFS_LIC_ADD_PCODE",
            ),
            attrs: &[
                ("AFS_LIC_NUM", "afs_licence_no"),
                ("AFS_LIC_ABN_ACN", "abn_acn"),
                ("AFS_LIC_START_DT", "licensed_from"),
                ("AFS_LIC_PRE_FSR", "pre_fsr_licence"),
                ("AFS_LIC_CONDITION", "authorisations"),
            ],
        },
    );
}

fn emit_credit_licensee(rec: &Map<String, Value>, scan_id: &str, out: &mut Vec<Entity>) {
    emit_licensee(
        rec,
        scan_id,
        out,
        &Licence {
            title: "ASIC Credit Licensees",
            tag: "asic-credit-licensee",
            name: "CRED_LIC_NAME",
            id: "CRED_LIC_ABN_ACN",
            address: ("CRED_LIC_LOCALITY", "CRED_LIC_STATE", "CRED_LIC_PCODE"),
            attrs: &[
                ("CRED_LIC_NUM", "credit_licence_no"),
                ("CRED_LIC_ABN_ACN", "abn_acn"),
                ("CRED_LIC_STATUS", "status"),
                ("CRED_LIC_START_DT", "licensed_from"),
                ("CRED_LIC_END_DT", "licensed_to"),
                ("CRED_LIC_AFSL_NUM", "afs_licence_no"),
                ("CRED_LIC_EDRS", "dispute_scheme"),
                ("CRED_LIC_BN", "business_names"),
                ("CRED_LIC_AUTHORISATIONS", "authorisations"),
            ],
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Request, Response, TransportFailure};
    use crate::source_outcome::SourceOutcomeKind;
    use crate::test_support::json_ok;
    use std::cell::RefCell;

    /// Live rows captured from data.gov.au on 2026-11-04.
    const COMPANY: &str = r#"{"Company Name":"LOVINI HOLDINGS PTY LTD","ACN":"000000019","Type":"APTY","Class":"LMSH","Sub Class":"PROP","Status":"REGD","Date of Registration":"08/01/1990","Date of Deregistration":null,"Previous State of Registration":"NSW","State Registration number":"46869041","Modified since last report":null,"Current Name Indicator":null,"ABN":"89000000019","Current Name":"MONAKA PTY LTD","Current Name Start Date":"28/01/2016"}"#;
    const BUSINESS_NAME: &str = r#"{"REGISTER_NAME":"BUSINESS NAMES","BN_NAME":"A Cut Above Painting & Texture Coating","BN_STATUS":"Registered","BN_REG_DT":"04/12/2019","BN_CANCEL_DT":null,"BN_STATE_NUM":null,"BN_STATE_OF_REG":null,"BN_ABN":"86634681397"}"#;
    const BANNED: &str = "{\"REGISTER_NAME\":\"Banned and Disqualified Organisations\",\"BD_ORG_ACN\":\"081402379\",\"BD_ORG_NAME\":\"AUSTRALIAN BUSINESS INSURANCE ADVISERS (ABIA)\u{a0}PTY LTD\",\"BD_ORG_TYPE\":\"Australian Financial Services banning\",\"BD_ORG_URL\":\"Not available\",\"BD_ORG_START_DT\":\"07/11/2006\",\"BD_ORG_END_DT\":\"07/11/2008\",\"BD_ORG_COMMENT\":\"No comment made\"}";

    fn envelope(records: &[&str]) -> String {
        format!(
            r#"{{"success":true,"result":{{"total":{},"records":[{}]}}}}"#,
            records.len(),
            records.join(",")
        )
    }

    /// Answers each register by its resource id, and records what it was asked.
    struct Fake {
        answers: Vec<(&'static str, Response)>,
        seen: RefCell<Vec<String>>,
    }

    impl Transport for Fake {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.seen.borrow_mut().push(request.url.clone());
            self.answers
                .iter()
                .find(|(res, _)| request.url.contains(res))
                .map(|(_, response)| response.clone())
                .ok_or_else(|| TransportFailure {
                    kind: SourceOutcomeKind::ConnectFailure,
                    detail: format!("unscripted {}", request.url),
                    blocked: false,
                })
        }
    }

    fn fake(company: &[&str], business: &[&str], banned: &[&str]) -> Fake {
        Fake {
            answers: vec![
                (COMPANY_RES, json_ok(&envelope(company))),
                (BUSINESS_NAME_RES, json_ok(&envelope(business))),
                (BANNED_ORG_RES, json_ok(&envelope(banned))),
                (AFS_LICENSEE_RES, json_ok(&envelope(&[]))),
                (CREDIT_LICENSEE_RES, json_ok(&envelope(&[]))),
            ],
            seen: RefCell::default(),
        }
    }

    fn org<'a>(report: &'a Report, name: &str) -> Option<&'a Entity> {
        report
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Organisation && e.raw_value == name)
    }

    fn attr<'a>(entity: &'a Entity, key: &str) -> Option<&'a str> {
        entity
            .evidence
            .first()
            .and_then(|ev| ev.attributes.get(key))
            .map(String::as_str)
    }

    #[test]
    fn a_query_is_a_checksummed_number_or_a_name() {
        assert_eq!(
            Query::parse("000 000 019"),
            Some(Query::Acn("000000019".into()))
        );
        assert_eq!(
            Query::parse("89000000019"),
            Some(Query::Abn("89000000019".into()))
        );
        assert_eq!(Query::parse("000000018"), None, "bad ACN checksum");
        assert_eq!(Query::parse("12345"), None, "neither an ACN nor an ABN");
        assert_eq!(Query::parse("Monaka"), Some(Query::Name("Monaka".into())));
        assert_eq!(Query::parse("   "), None);
    }

    #[test]
    fn a_company_is_its_current_name_with_the_former_name_and_both_numbers() {
        let transport = fake(&[COMPANY], &[], &[]);
        let report = lookup(&transport, &Query::Name("Lovini Holdings".into()), "s", 1).unwrap();
        let company = org(&report, "MONAKA PTY LTD").expect("company under its current name");
        assert_eq!(
            attr(company, "former_name"),
            Some("LOVINI HOLDINGS PTY LTD")
        );
        assert_eq!(attr(company, "status"), Some("REGD"));
        assert_eq!(attr(company, "registered_on"), Some("08/01/1990"));
        assert!(company.has_tag("asic-company"));
        assert!(!company.has_tag("deregistered"));
        for id in ["000000019", "89000000019"] {
            assert!(
                report
                    .entities
                    .iter()
                    .any(|e| e.kind == EntityKind::AbnAcn && e.raw_value == id),
                "{id}"
            );
        }
    }

    #[test]
    fn an_acn_query_matches_only_that_number_and_skips_the_register_without_one() {
        let other = COMPANY.replace("000000019", "000000027");
        let transport = fake(&[&other, COMPANY], &[], &[]);
        let report = lookup(&transport, &Query::Acn("000000019".into()), "s", 1).unwrap();
        let orgs: Vec<_> = report
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Organisation)
            .collect();
        assert_eq!(orgs.len(), 1, "{orgs:?}");
        // Business names carry no ACN, so an ACN query never asks that register.
        let seen = transport.seen.borrow();
        assert!(
            !seen.iter().any(|url| url.contains(BUSINESS_NAME_RES)),
            "{seen:?}"
        );
        // Companies, banned organisations and both licence registers hold an ACN.
        assert_eq!(report.outcomes.len(), 4);
    }

    #[test]
    fn a_business_name_links_to_its_holder_by_abn() {
        let transport = fake(&[], &[BUSINESS_NAME], &[]);
        let report = lookup(
            &transport,
            &Query::Name("Cut Above Painting".into()),
            "s",
            1,
        )
        .unwrap();
        let bn = org(&report, "A Cut Above Painting & Texture Coating").expect("business name");
        assert!(bn.has_tag("asic-business-name"));
        assert_eq!(attr(bn, "holder_abn"), Some("86634681397"));
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::AbnAcn && e.raw_value == "86634681397")
        );
    }

    #[test]
    fn a_banned_organisation_is_a_regulatory_action_with_plain_spaces() {
        let transport = fake(&[], &[], &[BANNED]);
        let report = lookup(
            &transport,
            &Query::Name("Business Insurance Advisers".into()),
            "s",
            1,
        )
        .unwrap();
        let banned = org(
            &report,
            "AUSTRALIAN BUSINESS INSURANCE ADVISERS (ABIA) PTY LTD",
        )
        .expect("banned organisation");
        assert!(banned.has_tag("regulatory-action"));
        assert_eq!(
            attr(banned, "ban_type"),
            Some("Australian Financial Services banning")
        );
    }

    #[test]
    fn a_full_text_hit_without_every_query_word_is_not_a_match() {
        let transport = fake(&[COMPANY], &[BUSINESS_NAME], &[]);
        let report = lookup(&transport, &Query::Name("Monaka Painting".into()), "s", 1).unwrap();
        assert!(report.entities.is_empty(), "{:?}", report.entities);
        assert!(
            report
                .outcomes
                .iter()
                .all(|o| o.kind == SourceOutcomeKind::ValidZero)
        );
    }

    #[test]
    fn a_deregistered_company_is_tagged() {
        let gone = COMPANY.replace("\"REGD\"", "\"DRGD\"");
        let report = lookup(
            &fake(&[&gone], &[], &[]),
            &Query::Name("Monaka".into()),
            "s",
            1,
        )
        .unwrap();
        assert!(
            org(&report, "MONAKA PTY LTD")
                .unwrap()
                .has_tag("deregistered")
        );
    }

    #[test]
    fn every_register_failing_is_an_error_not_an_empty_answer() {
        let fail = json_ok(r#"{"success":false}"#);
        let transport = Fake {
            answers: vec![
                (COMPANY_RES, fail.clone()),
                (BUSINESS_NAME_RES, fail.clone()),
                (BANNED_ORG_RES, fail.clone()),
                (AFS_LICENSEE_RES, fail.clone()),
                (CREDIT_LICENSEE_RES, fail),
            ],
            seen: RefCell::default(),
        };
        assert!(lookup(&transport, &Query::Name("Monaka".into()), "s", 1).is_err());
    }

    /// Trimmed from the live AFS licensee row for `KORDAMENTHA ADVISORY PTY LTD` on 2026-11-04.
    const AFS_LICENSEE: &str = r#"{"REGISTER_NAME":"AFS Licence","AFS_LIC_NUM":"441845","AFS_LIC_NAME":"KORDAMENTHA ADVISORY PTY LTD","AFS_LIC_ABN_ACN":"31163147680","AFS_LIC_START_DT":"03/10/2013","AFS_LIC_PRE_FSR":null,"AFS_LIC_ADD_LOCAL":"MELBOURNE","AFS_LIC_ADD_STATE":"VIC","AFS_LIC_ADD_PCODE":"3000","AFS_LIC_ADD_COUNTRY":"Australia","AFS_LIC_CONDITION":"1. Provide financial product advice"}"#;

    #[test]
    fn an_afs_licensee_keeps_its_licence_abn_and_address() {
        let transport = Fake {
            answers: vec![
                (COMPANY_RES, json_ok(&envelope(&[]))),
                (BUSINESS_NAME_RES, json_ok(&envelope(&[]))),
                (BANNED_ORG_RES, json_ok(&envelope(&[]))),
                (AFS_LICENSEE_RES, json_ok(&envelope(&[AFS_LICENSEE]))),
                (CREDIT_LICENSEE_RES, json_ok(&envelope(&[]))),
            ],
            seen: RefCell::default(),
        };
        let report = lookup(&transport, &Query::Abn("31163147680".into()), "s", 1).unwrap();
        let licensee = org(&report, "KORDAMENTHA ADVISORY PTY LTD").expect("AFS licensee");
        assert!(licensee.has_tag("asic-afs-licensee"));
        assert!(!licensee.has_tag("regulatory-action"));
        assert_eq!(attr(licensee, "afs_licence_no"), Some("441845"));
        assert_eq!(
            attr(licensee, "authorisations"),
            Some("1. Provide financial product advice")
        );
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Address && e.raw_value == "MELBOURNE VIC 3000")
        );
        assert!(
            report
                .outcomes
                .iter()
                .any(|o| o.module == "asic_orgs.afs_licensees"
                    && o.kind == SourceOutcomeKind::Success)
        );
    }
}
