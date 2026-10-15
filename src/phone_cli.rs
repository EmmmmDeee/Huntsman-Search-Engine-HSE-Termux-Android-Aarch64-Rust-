//! End-to-end front-end for `huntsman-recon phone`.
//!
//! Canonicalises explicit international numbers and recognised Australian local
//! numbers, resolves country metadata, and enriches Australian numbers with the
//! numbering-plan line type and coarse allocation region, all offline ([`run`]). With
//! `HUNTSMAN_NUMVERIFY_KEY` set, [`run_keyed`] then asks Numverify for the carrier, line type
//! and location, and every indicator source for a number whose key is set (`IPQualityScore` with
//! `HUNTSMAN_IPQS_KEY`); without a key it makes no request and is exactly [`run`].

use std::fmt::Write as _;
use std::path::PathBuf;

use crate::address_au::{self, AuLineType};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid};
use crate::error::Error;
use crate::http::Transport;
use crate::indicator_legs;
use crate::indicator_sources::Indicator;
use crate::keys::Keys;
use crate::lookup_args::LookupTokens;
use crate::lookup_report::{entity_row, evidence_row, outcome_row};
use crate::numverify;
use crate::phone_intl;
use crate::source_outcome::SourceExecutionOutcome;

pub const PHONE_USAGE: &str = "usage: huntsman-recon phone NUMBER [--save FILE]";
pub const PHONE_HELP: &str = "\
phone NUMBER [--save FILE]
Canonicalise a phone number offline, resolve its international dialling prefix, and enrich Australian numbers with numbering-plan line type and coarse region. With HUNTSMAN_NUMVERIFY_KEY set it also asks Numverify (APILayer) for the carrier, line type and location, and with HUNTSMAN_IPQS_KEY set IPQualityScore for line type, carrier and fraud score; without a key no request is made. --save FILE writes an unverified ledger that verify can reload.";

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
        let LookupTokens { positional, save } = LookupTokens::split(args)?;

        if positional.len() != 1 {
            return Err(Error::Invalid("phone needs exactly one NUMBER".into()));
        }

        let phone = phone_intl::canonicalize(&positional[0]).ok_or_else(|| {
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
    let Some((prefix, iso, country_name)) = phone_intl::country_of(&canonical) else {
        return PhoneRun::Failed("unknown international dialling prefix".into());
    };

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

    if iso == "AU" {
        enrich_au(&canonical, &scan_id, &mut entity);
        outcomes.push(SourceExecutionOutcome::success("phone_au", now_unix, 1));
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

/// [`run`], then the Numverify leg and every indicator source for the number that `keys` enables.
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
    let numverify_wanted = numverify::API.wanted(keys);
    if !numverify_wanted && indicator_legs::planned(indicator, keys).is_empty() {
        return match render(&report) {
            Ok(text) => PhoneRun::Printed { text, report },
            Err(message) => PhoneRun::Failed(message),
        };
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
        EvidenceProvenance::for_scan("phone_au", scan_id),
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

fn render(report: &Report) -> Result<String, String> {
    let mut out = format!("entities={}\n", report.entities.len());
    for entity in &report.entities {
        writeln!(out, "{}", entity_row(entity, &entity.raw_value))
            .map_err(|error| error.to_string())?;
        for evidence in &entity.evidence {
            writeln!(out, "{}", evidence_row(evidence)).map_err(|error| error.to_string())?;
        }
    }
    for outcome in &report.outcomes {
        writeln!(out, "{}", outcome_row(outcome)).map_err(|error| error.to_string())?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            text(run_keyed(&transport, &Keys::default(), "0412 345 678", 1)),
            text(run("0412 345 678", 1)),
            "no key: exactly the offline lookup"
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
                assert_eq!(report.outcomes.len(), 1);
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
                assert!(!text.contains("numverify"), "{text}");
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
}
