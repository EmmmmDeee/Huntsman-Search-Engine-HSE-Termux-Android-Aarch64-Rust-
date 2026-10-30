//! End-to-end front-end for `huntsman-recon phone`.
//!
//! Canonicalises explicit international numbers and recognised Australian local
//! numbers, resolves country metadata, and enriches Australian numbers with the
//! numbering-plan line type and coarse allocation region, and holds `+1` numbers to the North
//! American Numbering Plan (validity, local and international forms, class and the area code's
//! country), all offline ([`run`]). With
//! `HUNTSMAN_NUMVERIFY_KEY` set, [`run_keyed`] then asks Numverify for the carrier, line type
//! and location, and every indicator source for a number whose key is set (`IPQualityScore` with
//! `HUNTSMAN_IPQS_KEY`); without a key it makes no request and is exactly [`run`].

use std::path::PathBuf;

use crate::address_au::{self, AuLineType};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid};
use crate::error::Error;
use crate::http::Transport;
use crate::indicator_legs;
use crate::indicator_sources::Indicator;
use crate::keys::Keys;
use crate::lookup_args::LookupTokens;
use crate::lookup_report;
use crate::numverify;
use crate::phone_intl;
use crate::source_outcome::SourceExecutionOutcome;

pub const PHONE_USAGE: &str = "usage: huntsman-recon phone NUMBER [--save FILE]";
pub const PHONE_HELP: &str = "\
phone NUMBER [--save FILE]
Canonicalise a phone number offline, resolve its international dialling prefix, and enrich Australian numbers with numbering-plan line type and coarse region. A +1 number is held to the North American Numbering Plan: one the plan cannot hold (an area code or exchange beginning 0 or 1, an N11 code, a reserved area code) is refused with the rule it breaks; otherwise it gets its local (NPA) NXX-XXXX and international +1 NPA NXX XXXX forms, whether it is geographic, toll-free, premium or another service code, the country or territory its area code belongs to (Canada, the Caribbean countries and US territories by list, the United States otherwise), and a flag for the 555-0100 to 555-0199 numbers set aside for fiction. With HUNTSMAN_NUMVERIFY_KEY set it also asks Numverify (APILayer) for the carrier, line type and location, and with HUNTSMAN_IPQS_KEY set IPQualityScore for line type, carrier and fraud score; without a key no request is made. --save FILE writes an unverified ledger that verify can reload.";

const PHONE_CONFIDENCE: f64 = 0.90;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhoneArgs {
    pub phone: String,
    pub save: Option<PathBuf>,
}

impl PhoneArgs {
    /// # Errors
    /// Missing/repeated arguments, unknown options, or a phone value that cannot
    /// be canonicalised without guessing a country.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let (raw, save) = LookupTokens::single(args, "phone needs exactly one NUMBER")?;
        let phone = phone_intl::canonicalize(&raw).ok_or_else(|| {
            Error::invalid_value(
                "phone must be explicit international form or a recognised Australian number",
            )
        })?;
        Ok(Self { phone, save })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PhoneRun {
    Printed { text: String, report: Report },
    Failed(String),
}

#[must_use]
pub fn run(phone: &str, now_unix: u64) -> PhoneRun {
    let Some(canonical) = phone_intl::canonicalize(phone) else {
        return PhoneRun::Failed(
            "phone must be explicit international form or a recognised Australian number".into(),
        );
    };
    let (Some((_, mut iso, mut country_name)), Some(prefix)) = (
        phone_intl::country_of(&canonical),
        phone_intl::calling_code(&canonical),
    ) else {
        return PhoneRun::Failed("unknown international dialling prefix".into());
    };
    // A +1 number is held to the North American Numbering Plan, and its area code, not the
    // shared +1, says which of the plan's countries it belongs to.
    let nanp = match phone_intl::nanp(&canonical) {
        Some(Ok(nanp)) => Some(nanp),
        Some(Err(rule)) => return PhoneRun::Failed(format!("not a NANP number: {rule}")),
        None => None,
    };
    if let Some((region_iso, region_name, _)) = nanp.as_ref().and_then(|nanp| nanp.region) {
        (iso, country_name) = (region_iso, region_name);
    }

    let scan_id = crate::entity::scan_id("phone", &canonical);
    let mut entity = Entity::new(EntityKind::Phone, &canonical, PHONE_CONFIDENCE, &scan_id);
    entity.tag("e164");
    entity.tag(format!("country:{iso}"));
    entity.add_evidence(
        Evidence::new(
            EvidenceProvenance::for_scan("phone_intl", &scan_id),
            format!("Phone {canonical} → {country_name}"),
        )
        .with_attr("country_code", prefix)
        .with_attr("country_iso", iso)
        .with_attr("country_name", country_name)
        .with_attr(
            "national_number",
            canonical
                .trim_start_matches('+')
                .strip_prefix(prefix)
                .unwrap_or_default(),
        ),
    );

    let mut outcomes = vec![SourceExecutionOutcome::success("phone_intl", now_unix, 1)];

    // Every plan is consulted for every number and answers for its own, so a phone scan's Sources
    // table names all three plans, and a plan that does not hold the number says so in its row
    // instead of leaving none.
    if iso == "AU" {
        enrich_au(&canonical, &scan_id, &mut entity);
        outcomes.push(SourceExecutionOutcome::success(AU_SOURCE, now_unix, 1));
    } else {
        outcomes.push(
            SourceExecutionOutcome::valid_zero(AU_SOURCE, now_unix).with_detail(format!(
                "+{prefix} is not Australia's +61, so the Australian plan holds no reading of it"
            )),
        );
    }
    if let Some(nanp) = &nanp {
        enrich_nanp(nanp, &scan_id, &mut entity);
        outcomes.push(SourceExecutionOutcome::success(NANP_SOURCE, now_unix, 1));
    } else {
        outcomes.push(
            SourceExecutionOutcome::valid_zero(NANP_SOURCE, now_unix).with_detail(format!(
                "+{prefix} is not the North American Numbering Plan's +1, so the plan holds no reading of it"
            )),
        );
    }

    let report = Report {
        entities: vec![entity],
        outcomes,
    };
    match render(&report) {
        Ok(text) => PhoneRun::Printed { text, report },
        Err(message) => PhoneRun::Failed(message),
    }
}

/// [`run`], then the Numverify leg and every indicator source for the number that `keys` enables
/// and the transport's lookup asks ([`Transport::runs_module`]).
#[must_use]
pub fn run_keyed<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    phone: &str,
    now_unix: u64,
) -> PhoneRun {
    let offline = run(phone, now_unix);
    let mut report = match offline {
        PhoneRun::Printed { report, .. } => report,
        failed @ PhoneRun::Failed(_) => return failed,
    };
    let Some(entity) = report.entities.first_mut() else {
        return PhoneRun::Failed("phone lookup produced no entity".into());
    };
    let (canonical, scan_id) = (entity.raw_value.clone(), entity.scan_id.clone());
    let indicator = Indicator::Phone(&canonical);
    let numverify_asked = transport.runs_module(numverify::API.source);
    let numverify_wanted = numverify_asked && numverify::API.wanted(keys);
    if numverify_asked && !numverify_wanted {
        // Asked without its key: no request, and the row that says so, as every keyed leg leaves.
        report.outcomes.push(SourceExecutionOutcome::not_configured(
            numverify::API.source,
            now_unix,
        ));
    }
    if numverify_wanted {
        let api = &numverify::API;
        let outcome = match numverify::verify(transport, keys, &canonical, now_unix) {
            Ok(v) => {
                numverify_evidence(entity, &v);
                SourceExecutionOutcome::success(api.source, now_unix, 1).with_http_status(200)
            }
            Err(err) => err.outcome(api, now_unix),
        };
        report.outcomes.push(outcome);
    }
    let legs = indicator_legs::run(transport, keys, indicator, &scan_id, now_unix);
    report.entities.extend(legs.entities);
    report.outcomes.extend(legs.outcomes);
    merge_by_uid(&mut report.entities);
    match render(&report) {
        Ok(text) => PhoneRun::Printed { text, report },
        Err(message) => PhoneRun::Failed(message),
    }
}

fn numverify_evidence(entity: &mut Entity, v: &numverify::Verification) {
    if !v.valid {
        entity.tag("invalid-number");
    }
    if let Some(line) = v.line_type.as_deref() {
        entity.tag(format!("carrier-line:{line}"));
    }
    let summary = match (v.valid, v.carrier.as_deref()) {
        (false, _) => "Numverify: not a valid assigned number".to_owned(),
        (true, Some(carrier)) => format!("Numverify: carrier {carrier}"),
        (true, None) => "Numverify: valid number, carrier not given".to_owned(),
    };
    let evidence = Evidence::new(
        EvidenceProvenance::for_scan(numverify::SOURCE, &entity.scan_id),
        summary,
    )
    .with_attr("valid", v.valid.to_string())
    .with_optional_attrs([
        ("carrier", v.carrier.as_deref()),
        ("line_type", v.line_type.as_deref()),
        ("location", v.location.as_deref()),
        ("country_iso", v.country_code.as_deref()),
        ("country_name", v.country_name.as_deref()),
        ("country_prefix", v.country_prefix.as_deref()),
        ("local_format", v.local_format.as_deref()),
        ("international_format", v.international_format.as_deref()),
    ])
    .with_attr("raw_answer", v.raw_answer.as_str());
    entity.add_evidence(evidence);
}

fn enrich_au(canonical: &str, scan_id: &str, entity: &mut Entity) {
    let Some((line_type, label)) = address_au::au_phone_line_type(canonical) else {
        return;
    };

    entity.tag("au-phone");
    entity.tag(format!("line:{}", line_type.slug()));
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(AU_SOURCE, scan_id),
        format!("Australian numbering-plan classification: {label}"),
    )
    .with_attr("line_type", line_type.slug())
    .with_attr("numbering_plan", "ACMA");

    match line_type {
        AuLineType::Mobile => {
            entity.tag("mobile");
            evidence = evidence.with_attr(
                "note",
                "mobile is non-geographic; current carrier is not inferred offline",
            );
        }
        AuLineType::GeographicFixed => {
            entity.tag("geographic");
            if let Some((region, region_name, states)) = address_au::au_phone_region(canonical) {
                entity.tag(format!("au-region:{region}"));
                evidence = evidence
                    .with_attr("au_region", region_name)
                    .with_attr("au_region_states", states.join(", "));
            }
        }
        AuLineType::Voip => {
            entity.tag("non-geographic");
        }
        AuLineType::Freephone | AuLineType::LocalRate | AuLineType::Premium => {
            entity.tag("non-geographic");
            entity.tag("service-number");
        }
    }

    entity.add_evidence(evidence);
}

/// Evidence source for the offline North American Numbering Plan reading.
/// The label the Australian numbering-plan reading records its evidence and outcome under.
pub const AU_SOURCE: &str = "phone_au";

/// The label the North American Numbering Plan reading records its evidence and outcome under.
pub const NANP_SOURCE: &str = "phone_nanp";

/// What the North American Numbering Plan says about a `+1` number: its national and
/// international forms, its class, its area code's country, and whether it is one of the
/// numbers set aside for fiction. Nothing here names a carrier or a subscriber.
fn enrich_nanp(nanp: &phone_intl::Nanp, scan_id: &str, entity: &mut Entity) {
    entity.tag("nanp");
    entity.tag(format!("line:{}", nanp.class.slug()));
    let summary = match nanp.class {
        phone_intl::NanpClass::Geographic => format!("NANP area code {}", nanp.npa),
        phone_intl::NanpClass::TollFree => format!("NANP toll-free code {}", nanp.npa),
        phone_intl::NanpClass::Premium => format!("NANP premium-rate code {}", nanp.npa),
        phone_intl::NanpClass::NonGeographic(purpose) => {
            format!("NANP non-geographic code {}: {purpose}", nanp.npa)
        }
    };
    let mut evidence = Evidence::new(EvidenceProvenance::for_scan(NANP_SOURCE, scan_id), summary)
        .with_attr("numbering_plan", "NANP")
        .with_attr("area_code", &nanp.npa)
        .with_attr("exchange", &nanp.nxx)
        .with_attr("line_number", &nanp.line)
        .with_attr("local_format", nanp.local())
        .with_attr("international_format", nanp.international())
        .with_attr("line_type", nanp.class.slug());
    if let Some((iso, name, listed)) = nanp.region {
        evidence = evidence.with_attr("area_code_country", name).with_attr(
            "area_code_country_basis",
            if listed {
                format!("area code {} is assigned to {iso}", nanp.npa)
            } else {
                format!(
                    "area code {} is in no list of Canada's or another plan country's codes",
                    nanp.npa
                )
            },
        );
    }
    if nanp.fictional {
        entity.tag("fictional");
        evidence = evidence.with_attr(
            "note",
            "555-0100 to 555-0199 are reserved for fiction and assigned to no one",
        );
    }
    if nanp.class != phone_intl::NanpClass::Geographic {
        entity.tag("non-geographic");
    }
    entity.add_evidence(evidence);
}

/// The report as every lookup prints it ([`lookup_report::render`]): each entity, every evidence
/// row with its attributes (so the national and international forms show), then the outcomes.
fn render(report: &Report) -> Result<String, String> {
    lookup_report::render(&report.entities, &report.outcomes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_outcome::SourceOutcomeKind;

    #[test]
    fn parse_accepts_au_local_and_save() {
        let parsed =
            PhoneArgs::parse(&["0412 345 678".into(), "--save".into(), "phone.json".into()])
                .unwrap();
        assert_eq!(parsed.phone, "+61412345678");
        assert_eq!(parsed.save, Some(PathBuf::from("phone.json")));
    }

    #[test]
    fn parse_rejects_ambiguous_foreign_national_number() {
        assert!(PhoneArgs::parse(&["415-555-2671".into()]).is_err());
    }

    #[test]
    fn au_mobile_is_canonical_and_non_geographic() {
        match run("0412 345 678", 1) {
            PhoneRun::Printed { report, .. } => {
                let entity = &report.entities[0];
                assert_eq!(entity.raw_value, "+61412345678");
                assert!(entity.has_tag("country:AU"));
                assert!(entity.has_tag("line:mobile"));
                assert!(entity.has_tag("mobile"));
                assert!(!entity.tags.iter().any(|tag| tag.starts_with("au-region:")));
            }
            PhoneRun::Failed(message) => panic!("{message}"),
        }
    }

    #[test]
    fn au_fixed_line_emits_coarse_region_only() {
        match run("(07) 3739 4511", 1) {
            PhoneRun::Printed { report, .. } => {
                let entity = &report.entities[0];
                assert!(entity.has_tag("line:geographic"));
                assert!(entity.has_tag("au-region:north-east"));
                assert_eq!(
                    entity.evidence[1].attributes.get("au_region_states"),
                    Some(&"QLD".to_owned())
                );
            }
            PhoneRun::Failed(message) => panic!("{message}"),
        }
    }

    #[test]
    fn numverify_runs_only_with_its_key_and_adds_carrier_evidence() {
        use crate::test_support::OneResponse;
        let transport = OneResponse::json(
            200,
            r#"{"valid":true,"number":"61412345678","country_code":"AU","location":"","carrier":"Telstra Corporation Ltd","line_type":"mobile"}"#,
        );
        let text = |run: PhoneRun| match run {
            PhoneRun::Printed { text, .. } => text,
            PhoneRun::Failed(message) => panic!("{message}"),
        };
        // No key: the offline lookup, plus one row per keyed leg saying it was not asked, in the
        // order the legs run (numverify, then the keyed indicator source for phones).
        let unkeyed = text(run_keyed(&transport, &Keys::default(), "0412 345 678", 1));
        let (skipped, rest): (Vec<&str>, Vec<&str>) = unkeyed
            .lines()
            .partition(|line| line.contains("\tnot_configured\t"));
        let suffix = format!(
            "\tnot_configured\tfound=none\tdetail={}",
            crate::source_outcome::NO_KEY_DETAIL
        );
        assert_eq!(
            skipped,
            [format!("numverify{suffix}"), format!("ipqs{suffix}")],
            "{unkeyed}"
        );
        assert_eq!(
            rest.join("\n") + "\n",
            text(run("0412 345 678", 1)),
            "no key: the offline lookup and nothing else"
        );
        assert!(transport.response.borrow().is_some(), "no key: no request");

        let keys = Keys::parse(&format!(
            "{}=numverify-test-key-0123456789\n",
            numverify::KEY_SLOT
        ))
        .unwrap();
        match run_keyed(&transport, &keys, "0412 345 678", 1) {
            PhoneRun::Printed { text, report } => {
                let entity = &report.entities[0];
                assert!(entity.has_tag("carrier-line:mobile"));
                assert!(entity.evidence_sources().contains("numverify"));
                assert!(text.contains("numverify\tsuccess\tfound=1"), "{text}");
                assert!(!text.contains("numverify-test-key"));
            }
            PhoneRun::Failed(message) => panic!("{message}"),
        }
    }

    #[test]
    fn a_refused_numverify_key_is_reported_not_called_success() {
        use crate::test_support::OneResponse;
        let transport =
            OneResponse::json(401, r#"{"message":"Invalid authentication credentials"}"#);
        let keys = Keys::parse(&format!(
            "{}=numverify-test-key-0123456789\n",
            numverify::KEY_SLOT
        ))
        .unwrap();
        match run_keyed(&transport, &keys, "+44 20 7183 8750", 1) {
            PhoneRun::Printed { text, .. } => {
                assert!(text.contains("numverify\tauth_rejected"), "{text}");
                assert!(text.contains("phone_intl\tsuccess\tfound=1"), "{text}");
            }
            PhoneRun::Failed(message) => panic!("{message}"),
        }
    }

    #[test]
    fn explicit_foreign_number_resolves_country_without_au_tags() {
        match run("+44 20 7183 8750", 1) {
            PhoneRun::Printed { report, .. } => {
                let entity = &report.entities[0];
                assert!(entity.has_tag("country:GB"));
                assert!(!entity.has_tag("au-phone"));
                // The plans that do not hold a British number still answer, each in its own row.
                let rows: Vec<(&str, SourceOutcomeKind)> = report
                    .outcomes
                    .iter()
                    .map(|outcome| (outcome.module.as_str(), outcome.kind))
                    .collect();
                assert_eq!(
                    rows,
                    [
                        ("phone_intl", SourceOutcomeKind::Success),
                        (AU_SOURCE, SourceOutcomeKind::ValidZero),
                        (NANP_SOURCE, SourceOutcomeKind::ValidZero),
                    ]
                );
                assert!(
                    report.outcomes[1]
                        .detail
                        .as_deref()
                        .is_some_and(|detail| detail.starts_with("+44 is not Australia's +61")),
                    "{:?}",
                    report.outcomes[1].detail
                );
            }
            PhoneRun::Failed(message) => panic!("{message}"),
        }
    }

    #[test]
    fn ipqs_runs_for_a_number_with_its_key_alone() {
        use crate::test_support::OneResponse;
        let transport = OneResponse::json(
            200,
            r#"{"success":true,"valid":true,"fraud_score":90,"VOIP":true,"carrier":"Example Mobile","line_type":"VOIP","country":"AU"}"#,
        );
        let keys = Keys::parse(&format!(
            "{}=ipqs-test-key-0123456789\n",
            crate::ipqs::KEY_SLOT
        ))
        .unwrap();
        match run_keyed(&transport, &keys, "0412 345 678", 1) {
            PhoneRun::Printed { text, report } => {
                assert!(text.contains("ipqs\tsuccess"), "{text}");
                // Numverify was asked and has no key: no request, and the row that says so.
                assert!(text.contains("numverify\tnot_configured"), "{text}");
                assert!(
                    report.outcomes.iter().any(|o| o.module == "numverify"
                        && o.kind == SourceOutcomeKind::NotConfigured
                        && o.detail.as_deref() == Some(crate::source_outcome::NO_KEY_DETAIL)),
                    "{:?}",
                    report.outcomes
                );
                assert!(!text.contains("ipqs-test-key"));
                assert_eq!(
                    report
                        .entities
                        .iter()
                        .filter(|e| e.kind == EntityKind::Phone)
                        .count(),
                    1,
                    "the IPQS evidence lands on the one phone entity"
                );
                assert!(report.entities[0].evidence_sources().contains("ipqs"));
            }
            PhoneRun::Failed(message) => panic!("{message}"),
        }
        assert!(transport.response.borrow().is_none(), "one request made");
    }

    /// The plan's reading of a +1 number derives from the number itself, as `phone_intl`'s and
    /// `phone_au`'s do, so it corroborates nothing: a NANP number is as unconfirmed as an
    /// Australian one, and no view counts the plan as an independent source. The plan is also a
    /// module the catalogue knows, so the Sources table, By Module and the ATT&CK coverage name it.
    #[test]
    fn the_numbering_plan_is_enrichment_not_an_independent_source() {
        let PhoneRun::Printed {
            report: toronto, ..
        } = run("+1 (416) 555-0199", 1)
        else {
            panic!("a Toronto number prints");
        };
        let nanp = &toronto.entities[0];
        assert!(
            nanp.evidence
                .iter()
                .any(|evidence| evidence.provenance.source == NANP_SOURCE)
        );
        assert_eq!(
            nanp.corroborating_sources(),
            std::collections::BTreeSet::new()
        );
        let PhoneRun::Printed { report: sydney, .. } = run("+61 412 345 678", 1) else {
            panic!("an Australian mobile prints");
        };
        let au = &sydney.entities[0];
        assert_eq!(au.corroborating_sources(), nanp.corroborating_sources());
        assert_eq!(au.source_count(), nanp.source_count());
        // Each scan's Sources table names all three plans, the one that holds the number as a
        // success and the other as a valid zero that says why.
        let kinds = |report: &Report| -> Vec<(String, SourceOutcomeKind)> {
            report
                .outcomes
                .iter()
                .map(|outcome| (outcome.module.clone(), outcome.kind))
                .collect()
        };
        assert_eq!(
            kinds(&toronto),
            [
                ("phone_intl".to_owned(), SourceOutcomeKind::Success),
                (AU_SOURCE.to_owned(), SourceOutcomeKind::ValidZero),
                (NANP_SOURCE.to_owned(), SourceOutcomeKind::Success),
            ]
        );
        assert_eq!(
            kinds(&sydney),
            [
                ("phone_intl".to_owned(), SourceOutcomeKind::Success),
                (AU_SOURCE.to_owned(), SourceOutcomeKind::Success),
                (NANP_SOURCE.to_owned(), SourceOutcomeKind::ValidZero),
            ]
        );
        assert!(
            crate::module::reachable_modules()
                .iter()
                .any(|module| module.name == NANP_SOURCE && !module.network)
        );
        assert!(
            crate::lookup_modules::offline_runs(crate::scan_route::ScanKind::Phone)
                .contains(&NANP_SOURCE)
        );
    }

    /// A +1 number gets `PhoneInfoga`'s fields and more: its national and international forms, its
    /// class, its area code's country (not just "NANP"), and a fiction flag; a number the plan
    /// cannot hold is refused with the rule it breaks instead of being taken as valid.
    #[test]
    fn a_nanp_number_carries_its_forms_class_and_country_and_a_broken_one_is_refused() {
        let PhoneRun::Printed { text, report } = run("+1 (416) 555-0199", 1) else {
            panic!("a Toronto number prints");
        };
        let phone = &report.entities[0];
        assert!(phone.has_tag("country:CA"), "{:?}", phone.tags);
        assert!(phone.has_tag("nanp") && phone.has_tag("line:geographic"));
        assert!(phone.has_tag("fictional"));
        let plan = phone
            .evidence
            .iter()
            .find(|evidence| evidence.provenance.source == NANP_SOURCE)
            .expect("the plan's reading");
        assert!(plan.attr_values("local_format").eq(["(416) 555-0199"]));
        assert!(
            plan.attr_values("international_format")
                .eq(["+1 416 555 0199"])
        );
        assert!(plan.attr_values("area_code_country").eq(["Canada"]));
        // The calling code is +1, and the national number is all ten digits after it.
        let intl = &phone.evidence[0];
        assert!(
            intl.attr_values("country_code").eq(["1"]),
            "{:?}",
            intl.attributes
        );
        assert!(intl.attr_values("national_number").eq(["4165550199"]));
        // The report prints the plan's attributes, so the forms are on screen, not only saved.
        for row in [
            "attribute\tlocal_format\t(416) 555-0199",
            "attribute\tinternational_format\t+1 416 555 0199",
            "attribute\tarea_code_country\tCanada",
        ] {
            assert!(text.contains(row), "{row} missing from {text}");
        }

        let PhoneRun::Printed { report, .. } = run("+1 800 555 0100", 1) else {
            panic!("a toll-free number prints");
        };
        assert!(report.entities[0].has_tag("line:toll-free"));
        assert!(report.entities[0].has_tag("non-geographic"));

        match run("+1 123 555 0100", 1) {
            PhoneRun::Failed(why) => assert!(why.contains("cannot begin with 0 or 1"), "{why}"),
            other @ PhoneRun::Printed { .. } => {
                panic!("a +1 number with area code 123 was accepted: {other:?}")
            }
        }
        // A +1 number of the wrong length is parsed and refused by the plan, which says why.
        for short_or_long in ["+1 202 555 010", "+1 202 555 01000"] {
            match run(short_or_long, 1) {
                PhoneRun::Failed(why) => {
                    assert!(
                        why.contains("ten digits after +1"),
                        "{short_or_long}: {why}"
                    );
                }
                other @ PhoneRun::Printed { .. } => {
                    panic!("{short_or_long} was accepted: {other:?}")
                }
            }
        }
    }
}
