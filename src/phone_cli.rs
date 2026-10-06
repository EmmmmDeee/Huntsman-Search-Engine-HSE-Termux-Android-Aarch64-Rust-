//! Offline front-end for `huntsman-recon phone`.
//!
//! The selector is canonicalised through the repository's strict E.164/AU
//! normaliser. Explicit international syntax is preserved as an E.164 fact;
//! Australian numbers also receive line-type and fixed-line region enrichment
//! from the shared ACMA-derived helpers.

use std::fmt::Write as _;
use std::path::PathBuf;

use crate::address_au::{self, AuLineType};
use crate::canonical::canonical_phone;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::error::Error;
use crate::evidence_ancestry::EvidenceNodeId;
use crate::identity_resolution::AutoMergePolicy;
use crate::lineage::{Lineage, Observation, ObservedLineage, UpstreamKind, resolve_with_lineage};
use crate::uid;

pub const PHONE_USAGE: &str = "usage: huntsman-recon phone NUMBER [--save FILE]";
pub const PHONE_HELP: &str = "\
phone NUMBER [--save FILE]
Canonicalise NUMBER to strict E.164 where possible and add deterministic Australian line-type/region facts. --save FILE writes an unverified ledger that verify can reload.";

const E164_CONF: f64 = 0.96;
const AU_CONF: f64 = 0.94;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub entities: Vec<Entity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhoneArgs {
    pub raw: String,
    pub phone: String,
    pub save: Option<PathBuf>,
}

impl PhoneArgs {
    /// # Errors
    /// Invalid or missing number, repeated `--save`, or an unknown option.
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
        let raw = positional[0].trim().to_owned();
        let phone = canonical_selector(&raw)
            .ok_or_else(|| Error::Invalid("invalid phone number".into()))?;
        Ok(Self { raw, phone, save })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PhoneRun {
    Printed { text: String, report: Report },
    Failed(String),
}

#[must_use]
pub fn run(raw: &str) -> PhoneRun {
    let Some(phone) = canonical_selector(raw) else {
        return PhoneRun::Failed("invalid phone number".into());
    };
    let scan_id = uid::scan_id("phone", &phone);
    let mut entities = vec![seed_entity(&phone, &scan_id)];

    if explicit_international(raw) {
        entities.push(e164_entity(&phone, &scan_id));
    }
    if phone.starts_with("+61") {
        entities.push(au_entity(&phone, &scan_id));
    }
    merge_by_uid(&mut entities);
    let report = Report { entities };

    match render(&report) {
        Ok(text) => PhoneRun::Printed { text, report },
        Err(message) => PhoneRun::Failed(message),
    }
}

fn canonical_selector(raw: &str) -> Option<String> {
    if let Some(phone) = canonical_phone(raw) {
        return Some(phone);
    }
    let trimmed = raw.trim();
    let digits: String = trimmed
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    let international = digits.strip_prefix("00")?;
    let candidate = format!("+{international}");
    crate::validation::validate_phone_e164(&candidate)
        .valid
        .then_some(candidate)
}

fn seed_entity(phone: &str, scan_id: &str) -> Entity {
    let mut entity = Entity::new(EntityKind::Phone, phone, 0.99, scan_id);
    entity.tag("seed");
    entity.tag("e164");
    entity.add_evidence(
        Evidence::new(
            EvidenceProvenance::for_scan("seed", scan_id),
            "operator-supplied phone selector",
        )
        .with_attr("canonical_e164", phone),
    );
    entity
}

fn e164_entity(phone: &str, scan_id: &str) -> Entity {
    let mut entity = Entity::new(EntityKind::Phone, phone, E164_CONF, scan_id);
    entity.tag("e164");
    entity.tag("international");
    entity.add_evidence(
        Evidence::new(
            EvidenceProvenance::for_scan("phone_intl", scan_id),
            format!("Explicit international phone syntax canonicalised as {phone}"),
        )
        .with_attr("dataset", "ITU E.164 syntax")
        .with_attr("canonical_e164", phone)
        .inferred(),
    );
    entity
}

fn au_entity(phone: &str, scan_id: &str) -> Entity {
    let mut entity = Entity::new(EntityKind::Phone, phone, AU_CONF, scan_id);
    entity.tag("au-phone");
    entity.tag("country:AU");

    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan("phone_au", scan_id),
        format!("Australian numbering-plan classification for {phone}"),
    )
    .with_attr("dataset", "ACMA Australian Numbering Plan")
    .with_attr("country_iso", "AU")
    .with_attr("canonical_e164", phone)
    .inferred();

    if let Some((line_type, label)) = address_au::au_phone_line_type(phone) {
        entity.tag(format!("line:{}", line_type.slug()));
        evidence = evidence
            .with_attr("line_type", line_type.slug())
            .with_attr("line_type_label", label);
        add_line_shape_tags(&mut entity, line_type);
    }

    if let Some((region, region_name, states)) = address_au::au_phone_region(phone) {
        entity.tag("geographic");
        entity.tag(format!("au-region:{region}"));
        evidence = evidence
            .with_attr("au_region", region_name)
            .with_attr("au_region_states", states.join(", "));
    }

    entity.add_evidence(evidence);
    entity
}

fn add_line_shape_tags(entity: &mut Entity, line_type: AuLineType) {
    match line_type {
        AuLineType::Mobile => entity.tag("mobile"),
        AuLineType::GeographicFixed => entity.tag("geographic"),
        AuLineType::Voip => entity.tag("non-geographic"),
        AuLineType::Freephone | AuLineType::LocalRate | AuLineType::Premium => {
            entity.tag("non-geographic");
            entity.tag("service-number");
        }
    }
}

fn explicit_international(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.starts_with('+') {
        return true;
    }
    let digits: String = trimmed
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    digits.starts_with("00")
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
    }
    append_lineage(report, &mut out)?;
    Ok(out)
}

fn append_lineage(report: &Report, out: &mut String) -> Result<(), String> {
    let observations = observations(report);
    let resolution = resolve_with_lineage(observations, Vec::new(), AutoMergePolicy::default())
        .map_err(|error| error.to_string())?;
    writeln!(out, "lineage={}", resolution.observations.len()).map_err(|error| error.to_string())?;
    for item in &resolution.observations {
        writeln!(out, "{}", lineage_line(item)).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn observations(report: &Report) -> Vec<Observation> {
    report
        .entities
        .iter()
        .enumerate()
        .flat_map(|(entity_index, entity)| {
            entity
                .evidence
                .iter()
                .enumerate()
                .map(move |(evidence_index, evidence)| Observation {
                    id: EvidenceNodeId(format!("{}:{entity_index}:{evidence_index}", entity.uid)),
                    evidence: evidence.clone(),
                })
        })
        .collect()
}

fn lineage_line(item: &ObservedLineage) -> String {
    let id = &item.observation.id.0;
    match &item.lineage {
        Lineage::Upstream { kind, family, .. } => {
            format!("{id}\t{}\t{family}", upstream_kind_label(*kind))
        }
        Lineage::Unattributed => format!("{id}\tunattributed"),
        Lineage::Ambiguous { field, values } => {
            format!("{id}\tambiguous\t{field}\t{}", values.join(";"))
        }
    }
}

const fn upstream_kind_label(kind: UpstreamKind) -> &'static str {
    match kind {
        UpstreamKind::Dataset => "dataset",
        UpstreamKind::Registry => "registry",
        UpstreamKind::Source => "source",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_au_local_and_save() {
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
    fn rejects_ambiguous_foreign_national_number() {
        assert!(PhoneArgs::parse(&["202-555-0100".into()]).is_err());
    }

    #[test]
    fn au_mobile_is_canonical_and_classified() {
        match run("0412 345 678") {
            PhoneRun::Printed { text, report } => {
                assert!(text.contains("+61412345678"), "{text}");
                assert!(text.contains("line:mobile"), "{text}");
                assert!(text.contains("lineage="), "{text}");
                let phone = report.entities.first().unwrap();
                assert!(phone.has_tag("country:AU"));
                assert!(phone.has_tag("mobile"));
            }
            PhoneRun::Failed(message) => panic!("{message}"),
        }
    }

    #[test]
    fn au_fixed_line_gets_region_without_coordinates() {
        match run("+61 2 9876 5432") {
            PhoneRun::Printed { report, .. } => {
                let phone = report.entities.first().unwrap();
                assert!(phone.has_tag("au-region:central-east"));
                assert!(phone.has_tag("geographic"));
                assert!(!report
                    .entities
                    .iter()
                    .any(|entity| entity.kind == EntityKind::Coordinates));
            }
            PhoneRun::Failed(message) => panic!("{message}"),
        }
    }

    #[test]
    fn foreign_e164_is_kept_but_not_claimed_as_au() {
        match run("+44 20 7183 8750") {
            PhoneRun::Printed { report, .. } => {
                let phone = report.entities.first().unwrap();
                assert_eq!(phone.raw_value, "+442071838750");
                assert!(phone.has_tag("international"));
                assert!(!phone.has_tag("country:AU"));
            }
            PhoneRun::Failed(message) => panic!("{message}"),
        }
    }

    #[test]
    fn nanp_collision_is_not_au_service_line() {
        match run("+1 800 555 1234") {
            PhoneRun::Printed { report, .. } => {
                let phone = report.entities.first().unwrap();
                assert!(!phone.has_tag("country:AU"));
                assert!(!phone.has_tag("line:freephone"));
            }
            PhoneRun::Failed(message) => panic!("{message}"),
        }
    }
}
