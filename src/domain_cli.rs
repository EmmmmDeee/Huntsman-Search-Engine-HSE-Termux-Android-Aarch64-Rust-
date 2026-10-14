//! End-to-end front-end for `huntsman-recon domain` and the domain arm of `scan`.
//!
//! Runs crt.sh certificate transparency and DNS record lookups in sequence for a
//! single domain, then the keyed legs whose key is configured: `VirusTotal` reputation
//! (`HUNTSMAN_VIRUSTOTAL_KEY`) and Hunter.io published addresses (`HUNTSMAN_HUNTER_KEY`), then
//! every domain source in [`crate::indicator_legs::SOURCES`] (Shodan DNS, Pulsedive, `LeakIX`,
//! `ThreatFox`, Whoxy WHOIS). A keyed leg without its key makes no request and reports nothing;
//! a configured key always runs its leg. Every result set is combined into one entity list and
//! rendered report.

use std::path::PathBuf;

use crate::canonical::canonical_domain;
use crate::crtsh::{self, CrtShError};
use crate::dns;
use crate::entity::Entity;
use crate::entity::{EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::http::{Transport, UreqTransport};
use crate::hunter;
use crate::indicator_legs;
use crate::indicator_sources::Indicator;
use crate::keys::Keys;
use crate::lookup_args::LookupTokens;
use crate::lookup_report;
use crate::recon::ReconTargetKind;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::virustotal;

pub const DOMAIN_USAGE: &str = "usage: huntsman-recon domain DOMAIN [--save FILE]";

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainArgs {
    pub domain: String,
    pub save: Option<PathBuf>,
}

impl DomainArgs {
    /// # Errors
    /// Invalid or missing domain, repeated `--save`, or an unknown option.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let LookupTokens { positional, save } = LookupTokens::split(args)?;
        if positional.len() != 1 {
            return Err(Error::Invalid("domain needs exactly one DOMAIN".into()));
        }
        let domain = canonical_domain(&positional[0])
            .ok_or_else(|| Error::invalid_value("invalid domain"))?;
        Ok(Self { domain, save })
    }
}

pub enum DomainRun {
    Printed { text: String, report: Report },
    Network(String),
    Failed(String),
}

#[must_use]
pub fn run<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    domain: &str,
    now_unix: u64,
) -> DomainRun {
    let Some(domain) = canonical_domain(domain) else {
        return DomainRun::Failed("invalid domain".into());
    };

    let mut entities = Vec::new();
    let mut outcomes = Vec::new();
    let mut sections = Vec::new();

    match crtsh::lookup(transport, ReconTargetKind::Domain, &domain, "domain_cli") {
        Ok(report) => {
            let count = report.entities.len();
            entities.extend(report.entities);
            outcomes.push(SourceExecutionOutcome::success("crtsh", now_unix, count));
            sections.push(format!("crtsh: {count} certificate-transparency entities"));
        }
        Err(CrtShError::Refused(reason)) => {
            outcomes.push(SourceExecutionOutcome::failed(
                "crtsh",
                now_unix,
                SourceOutcomeKind::EntitlementDenied,
                None,
                &reason,
            ));
            sections.push(format!("crtsh: refused ({reason})"));
        }
        Err(error) => {
            let message = error.to_string();
            outcomes.push(SourceExecutionOutcome::failed(
                "crtsh",
                now_unix,
                SourceOutcomeKind::Inconclusive,
                None,
                &message,
            ));
            sections.push(format!("crtsh: unavailable ({message})"));
        }
    }

    let dns_transport = UreqTransport::new(&dns::transport_config());
    match dns::lookup_domain(&dns_transport, &domain) {
        Some(report) => {
            let rendered = report.render();
            let answer_count = report.answers.len();
            outcomes.push(SourceExecutionOutcome::success(
                "dns",
                now_unix,
                answer_count,
            ));
            sections.push(rendered);
        }
        None => {
            outcomes.push(SourceExecutionOutcome::failed(
                "dns",
                now_unix,
                SourceOutcomeKind::Inconclusive,
                None,
                "bad domain",
            ));
        }
    }

    keyed_legs(
        transport,
        keys,
        &domain,
        now_unix,
        &mut entities,
        &mut outcomes,
    );
    merge_by_uid(&mut entities);

    let any_results = !entities.is_empty()
        || outcomes
            .iter()
            .any(|o| o.kind.is_accepted() && o.found.unwrap_or(0) > 0);
    if !any_results {
        return DomainRun::Failed(format!("no results for domain {domain}"));
    }

    let mut text = match lookup_report::render(&entities, &outcomes) {
        Ok(rendered) => rendered,
        Err(msg) => return DomainRun::Failed(msg),
    };
    for section in &sections {
        text.push_str(section);
        if !section.ends_with('\n') {
            text.push('\n');
        }
    }

    DomainRun::Printed {
        text,
        report: Report { entities, outcomes },
    }
}

/// The provider legs: `VirusTotal` and Hunter.io when their keys are configured, then the
/// indicator sources that apply.
fn keyed_legs<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    domain: &str,
    now_unix: u64,
    entities: &mut Vec<Entity>,
    outcomes: &mut Vec<SourceExecutionOutcome>,
) {
    let scan_id = crate::entity::scan_id("domain", domain);
    if virustotal::API.wanted(keys) {
        let api = &virustotal::API;
        match virustotal::lookup(
            transport,
            keys,
            virustotal::Object::Domain,
            domain,
            now_unix,
        ) {
            Ok(Some(report)) => {
                entities.push(virustotal_entity(domain, &scan_id, &report));
                outcomes.push(SourceExecutionOutcome::success(api.source, now_unix, 1));
            }
            Ok(None) => outcomes.push(SourceExecutionOutcome::valid_zero(api.source, now_unix)),
            Err(err) => outcomes.push(err.outcome(api, now_unix)),
        }
    }
    if hunter::API.wanted(keys) {
        outcomes.push(hunter_leg(
            transport, keys, domain, &scan_id, now_unix, entities,
        ));
    }
    let legs = indicator_legs::run(
        transport,
        keys,
        Indicator::Domain(domain),
        &scan_id,
        now_unix,
    );
    entities.extend(legs.entities);
    outcomes.extend(legs.outcomes);
}

fn virustotal_entity(domain: &str, scan_id: &str, report: &virustotal::Report) -> Entity {
    let mut entity = Entity::new(EntityKind::Domain, domain, 0.90, scan_id);
    if report.malicious > 0 {
        entity.tag(crate::tags::MALICIOUS);
    }
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(virustotal::SOURCE, scan_id),
        format!(
            "VirusTotal: {} of {} engines flag the domain",
            report.flagged(),
            report.flagged() + report.harmless + report.undetected
        ),
    )
    .with_attr("malicious", report.malicious.to_string())
    .with_attr("suspicious", report.suspicious.to_string())
    .with_attr("reputation", report.reputation.to_string())
    .with_optional_attrs([("registrar", report.registrar.as_deref())]);
    if !report.categories.is_empty() {
        evidence = evidence.with_attr("categories", report.categories.join(","));
    }
    if let Some(created) = report.creation_date {
        evidence = evidence.with_attr("creation_date_unix", created.to_string());
    }
    entity.add_evidence(evidence);
    entity
}

/// Hunter's published addresses at `domain`: one email entity each, the organisation Hunter
/// names, and the domain's address pattern. Confidence follows Hunter's own, capped below a
/// confirmed observation.
fn hunter_leg<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    domain: &str,
    scan_id: &str,
    now_unix: u64,
    entities: &mut Vec<Entity>,
) -> SourceExecutionOutcome {
    let api = &hunter::API;
    let search = match hunter::search(transport, keys, domain, now_unix) {
        Ok(search) => search,
        Err(err) => return err.outcome(api, now_unix),
    };
    let evidence = |summary: String| {
        Evidence::new(
            EvidenceProvenance::for_scan(hunter::SOURCE, scan_id),
            summary,
        )
    };
    for address in &search.addresses {
        let confidence = f64::from(address.confidence) / 100.0 * 0.80;
        let e = evidence("Address Hunter.io found published for the domain".into())
            .with_attr("domain", domain)
            .with_attr("hunter_confidence", address.confidence.to_string())
            .with_attr("public_sources", address.sources.to_string())
            .with_optional_attrs([
                ("type", address.kind.as_deref()),
                ("name", address.name.as_deref()),
                ("position", address.position.as_deref()),
            ]);
        push_entity(
            entities,
            EntityKind::Email,
            &address.email,
            confidence,
            scan_id,
            e,
            &[],
        );
    }
    if let Some(org) = search.organization.as_deref() {
        let e = evidence("Organisation Hunter.io names for the domain".into())
            .with_attr("domain", domain);
        push_entity(
            entities,
            EntityKind::Organisation,
            org,
            0.60,
            scan_id,
            e,
            &[],
        );
    }
    if let Some(pattern) = search.pattern.as_deref() {
        let e = evidence(format!("Hunter.io address pattern: {pattern}"))
            .with_attr("email_pattern", pattern);
        push_entity(entities, EntityKind::Domain, domain, 0.90, scan_id, e, &[]);
    }
    let outcome = if search.addresses.is_empty() {
        SourceExecutionOutcome::valid_zero(api.source, now_unix)
    } else {
        SourceExecutionOutcome::success(api.source, now_unix, search.addresses.len())
    }
    .with_http_status(200);
    match search.truncation() {
        Some(note) => outcome.with_detail(note),
        None => outcome,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_outcome::SourceOutcomeKind;
    use crate::test_support::OneResponse;

    const HUNTER_KEY: &str = "hunter-test-key-0123456789abcdef";
    const SEARCH: &str = r#"{"data":{"domain":"example.com","pattern":"{first}.{last}","organization":"Example Corp","emails":[{"value":"ada.lovelace@example.com","type":"personal","confidence":90,"sources":[{"domain":"example.org"}],"first_name":"Ada","last_name":"Lovelace","position":"Engineer"},{"value":"info@example.com","type":"generic","confidence":70,"sources":[]}]},"meta":{"results":2}}"#;

    fn keys() -> Keys {
        match Keys::parse(&format!("{}={HUNTER_KEY}\n", hunter::KEY_SLOT)) {
            Ok(keys) => keys,
            Err(error) => panic!("fixture keys parse: {error}"),
        }
    }

    #[test]
    fn hunter_addresses_become_email_pivots_with_the_organisation() {
        let transport = OneResponse::json(200, SEARCH);
        let mut entities = Vec::new();
        let outcome = hunter_leg(&transport, &keys(), "example.com", "scan", 1, &mut entities);
        assert_eq!(outcome.kind, SourceOutcomeKind::Success);
        assert_eq!(outcome.found, Some(2));
        let emails: Vec<&str> = entities
            .iter()
            .filter(|e| e.kind == EntityKind::Email)
            .map(|e| e.value.as_str())
            .collect();
        assert_eq!(emails, ["ada.lovelace@example.com", "info@example.com"]);
        assert!(
            entities
                .iter()
                .any(|e| e.kind == EntityKind::Organisation && e.raw_value == "Example Corp")
        );
        let ada = &entities[0];
        assert!((ada.confidence - 0.72).abs() < 1e-9, "{}", ada.confidence);
        assert_eq!(
            ada.evidence[0]
                .attributes
                .get("position")
                .map(String::as_str),
            Some("Engineer")
        );
    }

    #[test]
    fn a_hunter_refusal_is_its_own_outcome() {
        let transport = OneResponse::json(401, r#"{"errors":[{"id":"authentication_failed"}]}"#);
        let mut entities = Vec::new();
        let outcome = hunter_leg(&transport, &keys(), "example.com", "scan", 1, &mut entities);
        assert_eq!(outcome.kind, SourceOutcomeKind::AuthRejected);
        assert!(entities.is_empty());
        assert!(!outcome.detail.unwrap_or_default().contains(HUNTER_KEY));
    }

    #[test]
    fn a_flagged_domain_is_tagged_malicious() {
        let report = virustotal::Report {
            malicious: 3,
            harmless: 50,
            registrar: Some("Example Registrar".into()),
            categories: vec!["phishing".into()],
            ..virustotal::Report::default()
        };
        let entity = virustotal_entity("example.com", "scan", &report);
        assert!(entity.has_tag(crate::tags::MALICIOUS));
        assert_eq!(
            entity.evidence[0].summary,
            "VirusTotal: 3 of 53 engines flag the domain"
        );
    }
}
