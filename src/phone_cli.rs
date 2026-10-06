//! End-to-end offline front-end for `huntsman-recon phone`.
//!
//! Canonicalises explicit international numbers and recognised Australian local
//! numbers, resolves country metadata, and enriches Australian numbers with the
//! numbering-plan line type and coarse allocation region. No network I/O.

use std::fmt::Write as _;
use std::path::PathBuf;

use crate::address_au::{self, AuLineType};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::error::Error;
use crate::phone_intl;
use crate::source_outcome::SourceExecutionOutcome;
use crate::uid;

pub const PHONE_USAGE: &str = "usage: huntsman-recon phone NUMBER [--save FILE]";
pub const PHONE_HELP: &str = "\
phone NUMBER [--save FILE]
Canonicalise a phone number offline, resolve its international dialling prefix, and enrich Australian numbers with numbering-plan line type and coarse region. --save FILE writes an unverified ledger that verify can reload.";

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
        let mut positional = Vec::new();
        let mut save = None;
        let mut it = args.iter();

        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--save" => {
                    if save.is_some() {
                        return Err(Error::Invalid("only one --save".into()));
                    }
                    let path = it
                        .next()
                        .cloned()
                        .ok_or_else(|| Error::Invalid("--save needs a value".into()))?;
                    if path.is_empty() || path.starts_with("--") {
                        return Err(Error::Invalid("--save needs a file path".into()));
                    }
                    save = Some(PathBuf::from(path));
                }
                flag if flag.starts_with("--") => {
                    return Err(Error::Invalid(format!("unknown option {flag}")));
                }
                value => positional.push(value.to_owned()),
            }
        }

        if positional.len() != 1 {
            return Err(Error::Invalid("phone needs exactly one NUMBER".into()));
        }

        let phone = phone_intl::canonicalize(&positional[0]).ok_or_else(|| {
            Error::Invalid(
                "phone must be explicit international form or a recognised Australian number"
                    .into(),
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

    let scan_id = uid::scan_id("phone", &canonical);
    let mut entity = Entity::new(
        EntityKind::Phone,
        &canonical,
        PHONE_CONFIDENCE,
        &scan_id,
    );
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
        writeln!(
            out,
            "{}\t{}\t{:.2}\t{}",
            entity.kind,
            entity.raw_value,
            entity.confidence,
            entity.tags.join(",")
        )
        .map_err(|error| error.to_string())?;
        for evidence in &entity.evidence {
            writeln!(
                out,
                "evidence\t{}\t{}",
                evidence.provenance.source,
                evidence.summary
            )
            .map_err(|error| error.to_string())?;
        }
    }
    for outcome in &report.outcomes {
        writeln!(
            out,
            "{}\tsuccess\tfound={}",
            outcome.module,
            outcome.found.unwrap_or_default()
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_au_local_and_save() {
        let parsed = PhoneArgs::parse(&[
            "0412 345 678".into(),
            "--save".into(),
            "phone.json".into(),
        ])
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
}
