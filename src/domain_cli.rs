//! End-to-end front-end for `huntsman-recon domain` and the domain arm of `scan`.
//!
//! Runs crt.sh certificate transparency and DNS record lookups in sequence for a
//! single domain, combining both result sets into one entity list and rendered report.

use std::path::PathBuf;

use crate::canonical::canonical_domain;
use crate::crtsh::{self, CrtShError};
use crate::dns;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::error::Error;
use crate::http::Transport;
use crate::lookup_args::LookupTokens;
use crate::lookup_report;
use crate::recon::ReconTargetKind;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

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
    Printed {
        text: String,
        report: Report,
    },
    Network(String),
    /// Every source failed, so nothing is known about the domain (not a zero result).
    Unavailable(String),
    Failed(String),
}

#[must_use]
pub fn run<T: Transport + ?Sized>(transport: &T, domain: &str, now_unix: u64) -> DomainRun {
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

    // DoH requests carry their own timeout, which the transport caps, so the caller's
    // transport (and its egress policy) serves DNS as it serves crt.sh.
    let dns_report = dns::lookup_domain(transport, &domain);
    if let Some(report) = &dns_report {
        entities.extend(dns_entities(report, "domain_cli"));
    }
    let (outcome, section) = dns_outcome(dns_report, now_unix);
    outcomes.push(outcome);
    if let Some(section) = section {
        sections.push(section);
    }

    let any_results = !entities.is_empty()
        || outcomes
            .iter()
            .any(|o| o.kind.is_accepted() && o.found.unwrap_or(0) > 0);
    if !outcomes.iter().any(|o| o.kind.is_accepted()) {
        return DomainRun::Unavailable(format!(
            "no source answered for domain {domain}: {}",
            sections.join("; ")
        ));
    }
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

/// Entities the DNS answers establish: A/AAAA addresses, and NS/MX hosts (a null MX `.` names
/// no host and is skipped). TXT answers stay in the rendered section; they are records, not
/// entities.
fn dns_entities(report: &dns::DomainDns, scan_id: &str) -> Vec<Entity> {
    let mut entities = Vec::new();
    for answer in &report.answers {
        let provider = answer.answer.server.provider;
        for record in &answer.answer.records {
            let found = match answer.record_type {
                dns::RecordType::A | dns::RecordType::Aaaa => record
                    .parse::<std::net::IpAddr>()
                    .ok()
                    .map(|ip| (EntityKind::IpAddress, ip.to_string())),
                dns::RecordType::Ns => canonical_domain(record.trim_end_matches('.'))
                    .map(|host| (EntityKind::Domain, host)),
                dns::RecordType::Mx => record
                    .split_whitespace()
                    .nth(1)
                    .and_then(|host| canonical_domain(host.trim_end_matches('.')))
                    .map(|host| (EntityKind::Domain, host)),
                dns::RecordType::Soa | dns::RecordType::Txt | dns::RecordType::Ptr => None,
            };
            let Some((kind, value)) = found else { continue };
            let mut entity = Entity::new(kind, &value, 0.9, scan_id);
            entity.add_evidence(
                Evidence::new(
                    EvidenceProvenance::for_scan("dns", scan_id),
                    format!(
                        "{} {} -> {value} ({provider})",
                        answer.record_type.as_str(),
                        answer.name
                    ),
                )
                .with_attr("record_type", answer.record_type.as_str())
                .with_attr("name", &answer.name)
                .with_attr("resolver", provider),
            );
            entities.push(entity);
        }
    }
    crate::entity::merge_by_uid(&mut entities);
    entities
}

/// The DNS source's outcome and rendered section. A lookup whose every query failed is a
/// failed source, never a zero-answer success.
fn dns_outcome(
    report: Option<dns::DomainDns>,
    now_unix: u64,
) -> (SourceExecutionOutcome, Option<String>) {
    let Some(report) = report else {
        return (
            SourceExecutionOutcome::failed(
                "dns",
                now_unix,
                SourceOutcomeKind::Inconclusive,
                None,
                "bad domain",
            ),
            None,
        );
    };
    let section = Some(report.render());
    // Every query answered NXDOMAIN or empty: the domain definitively has no records.
    if report.answers.is_empty()
        && !report.failures.is_empty()
        && report
            .failures
            .iter()
            .all(|failure| failure.error.kind == dns::ResolveErrorKind::Empty)
    {
        return (SourceExecutionOutcome::valid_zero("dns", now_unix), section);
    }
    if let Some(first) = report
        .failures
        .first()
        .filter(|_| report.answers.is_empty())
    {
        let detail = format!(
            "all {} DNS queries failed; first {} {}: {} ({})",
            report.failures.len(),
            first.record_type.as_str(),
            first.name,
            first.error.kind.as_str(),
            first.error.detail
        );
        let outcome = SourceExecutionOutcome::failed(
            "dns",
            now_unix,
            SourceOutcomeKind::Inconclusive,
            None,
            &detail,
        );
        return (outcome, section);
    }
    (
        SourceExecutionOutcome::success("dns", now_unix, report.answers.len()),
        section,
    )
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::{DomainRun, run};
    use crate::entity::EntityKind;
    use crate::http::{Request, Response, Transport, TransportFailure};
    use crate::source_outcome::SourceOutcomeKind;

    /// Answers `DoH` requests by record type from a fixed table (anything else is NXDOMAIN) and
    /// fails everything else (`crt.sh`) with no response.
    struct Fake {
        answers: Vec<(&'static str, &'static str)>,
        sent: Cell<usize>,
    }

    impl Fake {
        fn new(answers: Vec<(&'static str, &'static str)>) -> Self {
            Self {
                answers,
                sent: Cell::new(0),
            }
        }
    }

    fn down() -> TransportFailure {
        TransportFailure {
            kind: SourceOutcomeKind::ConnectFailure,
            detail: "down".into(),
            blocked: false,
        }
    }

    impl Transport for Fake {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.sent.set(self.sent.get() + 1);
            if !request.url.contains("dns") {
                return Err(down());
            }
            if self.answers.is_empty() {
                return Err(down());
            }
            let body = self
                .answers
                .iter()
                .find(|(qtype, _)| {
                    request.url.contains(&format!("type={qtype}&"))
                        || request.url.ends_with(&format!("type={qtype}"))
                })
                .map_or(r#"{"Status":3}"#, |(_, body)| *body);
            Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: body.as_bytes().to_vec(),
                truncated: false,
            })
        }
    }

    #[test]
    fn dns_goes_through_the_injected_transport() {
        let fake = Fake::new(Vec::new());
        let _ = run(&fake, "example.com", 1);
        // crt.sh plus every DoH attempt reached the fake; nothing went to the real network.
        assert!(
            fake.sent.get() > 7,
            "only {} requests reached the fake",
            fake.sent.get()
        );
    }

    #[test]
    fn every_source_failing_is_unavailable_not_no_results() {
        let fake = Fake::new(Vec::new());
        match run(&fake, "example.com", 1) {
            DomainRun::Unavailable(message) => {
                assert!(message.contains("no source answered"), "{message}");
            }
            DomainRun::Printed { text, .. } => panic!("printed: {text}"),
            DomainRun::Network(m) | DomainRun::Failed(m) => panic!("{m}"),
        }
    }

    #[test]
    fn a_domain_with_no_records_is_a_valid_zero_not_an_outage() {
        // Every DoH query answers NXDOMAIN; crt.sh is down.
        let fake = Fake::new(vec![("NONE", "")]);
        match run(&fake, "nonexistent.example", 1) {
            DomainRun::Failed(message) => assert!(message.contains("no results"), "{message}"),
            DomainRun::Printed { text, .. } => panic!("printed: {text}"),
            DomainRun::Unavailable(m) | DomainRun::Network(m) => panic!("{m}"),
        }
    }

    #[test]
    fn dns_answers_become_entities_with_crtsh_down() {
        let fake = Fake::new(vec![
            (
                "A",
                r#"{"Status":0,"Answer":[{"type":1,"data":"192.0.2.10"}]}"#,
            ),
            (
                "MX",
                r#"{"Status":0,"Answer":[{"type":15,"data":"10 Mail.Example.COM."},{"type":15,"data":"0 ."}]}"#,
            ),
            (
                "NS",
                r#"{"Status":0,"Answer":[{"type":2,"data":"ns1.example.net."}]}"#,
            ),
        ]);
        match run(&fake, "example.com", 1) {
            DomainRun::Printed { text, report } => {
                assert!(text.contains("192.0.2.10"), "{text}");
                let found: Vec<(EntityKind, String)> = report
                    .entities
                    .iter()
                    .map(|e| (e.kind.clone(), e.value.clone()))
                    .collect();
                for want in [
                    (EntityKind::IpAddress, "192.0.2.10"),
                    (EntityKind::Domain, "mail.example.com"),
                    (EntityKind::Domain, "ns1.example.net"),
                ] {
                    assert!(
                        found.iter().any(|(k, v)| *k == want.0 && v == want.1),
                        "missing {want:?} in {found:?}"
                    );
                }
                // The null MX names no host.
                assert_eq!(found.len(), 3, "{found:?}");
                assert!(
                    report
                        .entities
                        .iter()
                        .all(|e| e.evidence.iter().all(|ev| ev.provenance.source == "dns"))
                );
            }
            DomainRun::Unavailable(m) | DomainRun::Network(m) | DomainRun::Failed(m) => {
                panic!("{m}")
            }
        }
    }
}
