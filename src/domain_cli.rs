//! End-to-end front-end for `huntsman-recon domain` and the domain arm of `scan`.
//!
//! Runs crt.sh and Cert Spotter certificate transparency and DNS record lookups in sequence
//! for a single domain, combining the result sets into one entity list (names both CT indexes
//! report merge into one entity) and rendered report.

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
use crate::subdomain_takeover;
use crate::waf_fingerprint;

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

    let (found, outcome, section) = certspotter_source(transport, &domain, now_unix);
    entities.extend(found);
    outcomes.push(outcome);
    sections.push(section);

    let (found, outcome, section) = rdap_source(transport, &domain, now_unix);
    entities.extend(found);
    outcomes.push(outcome);
    sections.push(section);

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

    // Subdomain takeover detection: probe discovered subdomains for takeover vulnerabilities.
    let (takeover_entities, takeover_outcome, takeover_section) =
        subdomain_takeover_detection(transport, &entities, &domain, now_unix);
    entities.extend(takeover_entities);
    if let Some(outcome) = takeover_outcome {
        outcomes.push(outcome);
    }
    if let Some(section) = takeover_section {
        sections.push(section);
    }

    // WAF/CDN fingerprinting: identify infrastructure by HTTP response signatures.
    let (fingerprint_entities, fingerprint_outcome, fingerprint_section) =
        infrastructure_fingerprinting(transport, &domain, now_unix);
    entities.extend(fingerprint_entities);
    if let Some(outcome) = fingerprint_outcome {
        outcomes.push(outcome);
    }
    if let Some(section) = fingerprint_section {
        sections.push(section);
    }

    crate::entity::merge_by_uid(&mut entities);
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

/// The Cert Spotter CT index for `domain`: its entities, outcome and report section. A run that
/// stopped at the page cap is a success marked partial, never presented as complete.
fn certspotter_source<T: Transport + ?Sized>(
    transport: &T,
    domain: &str,
    now_unix: u64,
) -> (Vec<Entity>, SourceExecutionOutcome, String) {
    match crate::certspotter::lookup(transport, domain, "domain_cli") {
        Ok(report) => {
            let count = report.entities.len();
            let outcome = if report.complete {
                SourceExecutionOutcome::success("certspotter", now_unix, count)
            } else {
                SourceExecutionOutcome::observed(
                    "certspotter",
                    now_unix,
                    SourceOutcomeKind::Success,
                    None,
                    Some(count),
                    format!("partial: stopped at {} pages", report.pages),
                )
            };
            let partial = if report.complete { "" } else { " (partial)" };
            let section = format!("certspotter: {count} certificate-transparency names{partial}");
            (report.entities, outcome, section)
        }
        Err(failure) => {
            let section = format!("certspotter: unavailable ({})", failure.detail);
            let outcome = SourceExecutionOutcome::failed(
                "certspotter",
                now_unix,
                failure.kind,
                failure.http_status,
                failure.detail,
            );
            (Vec::new(), outcome, section)
        }
    }
}

/// The domain's RDAP registration record: registrar and nameserver entities, outcome and report
/// section. An unregistered name (RDAP 404) is a valid zero.
fn rdap_source<T: Transport + ?Sized>(
    transport: &T,
    domain: &str,
    now_unix: u64,
) -> (Vec<Entity>, SourceExecutionOutcome, String) {
    match crate::rdap::lookup(transport, domain, "domain_cli") {
        Ok(report) if !report.registered => (
            Vec::new(),
            SourceExecutionOutcome::valid_zero("rdap", now_unix),
            "rdap: not registered".into(),
        ),
        Ok(report) => {
            let count = report.entities.len();
            let section = format!("rdap: {count} registration entities");
            (
                report.entities,
                SourceExecutionOutcome::success("rdap", now_unix, count),
                section,
            )
        }
        Err(failure) => {
            let section = format!("rdap: unavailable ({})", failure.detail);
            let outcome = SourceExecutionOutcome::failed(
                "rdap",
                now_unix,
                failure.kind,
                failure.http_status,
                failure.detail,
            );
            (Vec::new(), outcome, section)
        }
    }
}

/// Entities the DNS answers establish: A/AAAA addresses, and NS/MX hosts (a null MX `.` names
/// no host and is skipped). TXT answers stay in the rendered section; they are records, not
/// entities.
fn dns_entities(report: &dns::DomainDns, scan_id: &str) -> Vec<Entity> {
    let mut entities = Vec::new();
    for answer in &report.answers {
        entities.extend(answer_entities(
            &answer.name,
            answer.record_type,
            &answer.answer,
            scan_id,
        ));
    }
    crate::entity::merge_by_uid(&mut entities);
    entities
}

/// The entities one DNS answer establishes, each carrying `dns` provenance. **Pure.**
fn answer_entities(
    name: &str,
    record_type: dns::RecordType,
    answer: &dns::ResolveAnswer,
    scan_id: &str,
) -> Vec<Entity> {
    let provider = answer.server.provider;
    let mut entities = Vec::new();
    for record in &answer.records {
        let found = match record_type {
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
                format!("{} {name} -> {value} ({provider})", record_type.as_str()),
            )
            .with_attr("record_type", record_type.as_str())
            .with_attr("name", name)
            .with_attr("resolver", provider),
        );
        entities.push(entity);
    }
    entities
}

/// Hosts resolved per [`resolve_hosts`] call; the rest are counted in `skipped`.
pub const MAX_RESOLVED_HOSTS: usize = 32;
/// Queries that may fail outright, with nothing resolved yet, before resolution stops: a
/// resolver outage must not cost every remaining query its full timeout.
const FAILURES_BEFORE_ABORT: usize = 4;

/// What [`resolve_hosts`] did.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct HostResolution {
    /// Address entities, `dns` provenance.
    pub entities: Vec<Entity>,
    /// Hosts that got a definitive answer (addresses or none).
    pub resolved: usize,
    /// `HOST TYPE: reason` for each query that failed outright.
    pub failures: Vec<String>,
    /// In-scope hosts not attempted: over [`MAX_RESOLVED_HOSTS`], or after an abort.
    pub skipped: usize,
}

/// Resolve the A and AAAA records of every in-scope subdomain (`Domain` entities tagged
/// `subdomain`) among `entities`, as `SpiderFoot`'s `sfp_dnsresolve` resolves discovered hosts.
/// Hosts are taken in sorted order, at most [`MAX_RESOLVED_HOSTS`]; an empty or NXDOMAIN answer
/// is a definitive zero; resolution stops after [`FAILURES_BEFORE_ABORT`] outright failures with
/// nothing resolved, and every host it did not reach is counted, never dropped silently.
#[must_use]
pub fn resolve_hosts<T: Transport + ?Sized>(
    transport: &T,
    entities: &[Entity],
    scan_id: &str,
) -> HostResolution {
    let hosts: std::collections::BTreeSet<&str> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain && e.has_tag(crate::tags::SUBDOMAIN))
        .map(|e| e.value.as_str())
        .collect();
    let mut out = HostResolution::default();
    for (index, host) in hosts.iter().enumerate() {
        if index == MAX_RESOLVED_HOSTS
            || (out.resolved == 0 && out.failures.len() >= FAILURES_BEFORE_ABORT)
        {
            out.skipped = hosts.len() - index;
            break;
        }
        let mut definitive = false;
        for record_type in [dns::RecordType::A, dns::RecordType::Aaaa] {
            let query = dns::ResolveQuery {
                name: (*host).to_owned(),
                record_type,
            };
            match dns::resolve_with_pool(transport, &query) {
                Ok(answer) => {
                    definitive = true;
                    out.entities
                        .extend(answer_entities(host, record_type, &answer, scan_id));
                }
                Err(error) if error.kind == dns::ResolveErrorKind::Empty => definitive = true,
                Err(error) => out.failures.push(format!(
                    "{host} {}: {}",
                    record_type.as_str(),
                    error.kind.as_str()
                )),
            }
        }
        if definitive {
            out.resolved += 1;
        }
    }
    crate::entity::merge_by_uid(&mut out.entities);
    out
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
            if !request.url.contains("type=") {
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

    /// Answers `DoH` by host name: a matching `(name, type, body)` row, else NXDOMAIN; with
    /// `down`, every request fails to connect.
    struct ByName {
        rows: Vec<(&'static str, &'static str, &'static str)>,
        down: bool,
        sent: Cell<usize>,
    }

    impl Transport for ByName {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.sent.set(self.sent.get() + 1);
            if self.down {
                return Err(down());
            }
            let body = self
                .rows
                .iter()
                .find(|(name, qtype, _)| {
                    request.url.contains(&format!("name={name}&"))
                        && (request.url.contains(&format!("type={qtype}&"))
                            || request.url.ends_with(&format!("type={qtype}")))
                })
                .map_or(r#"{"Status":3}"#, |(_, _, body)| *body);
            Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: body.as_bytes().to_vec(),
                truncated: false,
            })
        }
    }

    fn host(value: &str, subdomain: bool) -> crate::entity::Entity {
        let mut entity = crate::entity::Entity::new(EntityKind::Domain, value, 0.75, "s");
        if subdomain {
            entity.tag(crate::tags::SUBDOMAIN);
        }
        entity
    }

    #[test]
    fn discovered_subdomains_resolve_to_address_entities() {
        let transport = ByName {
            rows: vec![
                (
                    "a.example.com",
                    "A",
                    r#"{"Status":0,"Answer":[{"type":1,"data":"10.0.0.5"}]}"#,
                ),
                (
                    "a.example.com",
                    "AAAA",
                    r#"{"Status":0,"Answer":[{"type":28,"data":"2001:db8::5"}]}"#,
                ),
                (
                    "other.example.net",
                    "A",
                    r#"{"Status":0,"Answer":[{"type":1,"data":"192.0.2.9"}]}"#,
                ),
            ],
            down: false,
            sent: Cell::new(0),
        };
        let entities = [
            host("a.example.com", true),
            host("gone.example.com", true),
            host("other.example.net", false),
        ];
        let out = super::resolve_hosts(&transport, &entities, "s");
        let ips: Vec<&str> = out.entities.iter().map(|e| e.value.as_str()).collect();
        assert_eq!(ips, vec!["10.0.0.5", "2001:db8::5"]);
        // The NXDOMAIN host is a definitive answer; the external name is never queried.
        assert_eq!(out.resolved, 2);
        assert!(out.failures.is_empty() && out.skipped == 0, "{out:?}");
        assert!(
            out.entities
                .iter()
                .all(|e| e.evidence.iter().all(|ev| ev.provenance.source == "dns"))
        );
    }

    #[test]
    fn resolution_is_capped_and_the_rest_counted() {
        let transport = ByName {
            rows: Vec::new(),
            down: false,
            sent: Cell::new(0),
        };
        let entities: Vec<crate::entity::Entity> = (0..=super::MAX_RESOLVED_HOSTS)
            .map(|i| host(&format!("h{i:02}.example.com"), true))
            .collect();
        let out = super::resolve_hosts(&transport, &entities, "s");
        assert_eq!(out.resolved, super::MAX_RESOLVED_HOSTS);
        assert_eq!(out.skipped, 1);
    }

    #[test]
    fn a_resolver_outage_stops_resolution_early() {
        let transport = ByName {
            rows: Vec::new(),
            down: true,
            sent: Cell::new(0),
        };
        let entities: Vec<crate::entity::Entity> = (0..10)
            .map(|i| host(&format!("h{i}.example.com"), true))
            .collect();
        let out = super::resolve_hosts(&transport, &entities, "s");
        // Two hosts' A and AAAA failed outright, then the remaining eight were not attempted.
        assert_eq!(out.failures.len(), 4, "{out:?}");
        assert_eq!(out.skipped, 8);
        assert_eq!(out.resolved, 0);
    }
}

/// Subdomain takeover detection: probe discovered subdomains for vulnerabilities.
/// Extracts Domain entities that are subdomains, probes them for takeover signatures,
/// and returns any findings as entities with evidence.
/// Returns None for outcomes to avoid affecting domain scan success/failure determination;
/// these findings are supplementary to core DNS/CT sources.
fn subdomain_takeover_detection<T: Transport + ?Sized>(
    transport: &T,
    entities: &[Entity],
    root_domain: &str,
    _now_unix: u64,
) -> (Vec<Entity>, Option<SourceExecutionOutcome>, Option<String>) {
    // Extract subdomains: Domain entities where the value is a subdomain of root_domain
    let subdomains: Vec<String> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain)
        .map(|e| e.value.as_str())
        .filter(|value| *value != root_domain && value.ends_with(&format!(".{root_domain}")))
        .map(|s| s.to_owned())
        .collect();

    if subdomains.is_empty() {
        return (Vec::new(), None, None);
    }

    // Run takeover detection on subdomains
    let findings = subdomain_takeover::detect_in_subdomains(transport, &subdomains);

    // Convert findings into entities with evidence
    let mut result_entities = Vec::new();
    for finding in &findings {
        let mut entity = Entity::new(EntityKind::Domain, &finding.subdomain, 0.95, "subdomain_takeover");
        let evidence = subdomain_takeover::finding_to_evidence(finding, "domain_cli");
        entity.add_evidence(evidence);
        result_entities.push(entity);
    }

    if result_entities.is_empty() {
        return (Vec::new(), None, None);
    }

    let count = result_entities.len();
    let section = format!(
        "subdomain_takeover: {}/{} subdomains vulnerable",
        count, subdomains.len()
    );

    // Return entities but no outcome to avoid affecting overall domain scan success determination
    (result_entities, None, Some(section))
}

/// Infrastructure fingerprinting: detect WAF/CDN and web server technologies.
/// Probes the target domain's HTTP headers for known signatures and reports findings.
/// Returns None for outcomes to avoid affecting domain scan success/failure determination;
/// these findings are supplementary to core DNS/CT sources.
fn infrastructure_fingerprinting<T: Transport + ?Sized>(
    transport: &T,
    domain: &str,
    _now_unix: u64,
) -> (Vec<Entity>, Option<SourceExecutionOutcome>, Option<String>) {
    // Try HTTPS first, fallback to HTTP
    let findings = waf_fingerprint::fingerprint_domain(transport, domain);

    if findings.is_empty() {
        return (Vec::new(), None, None);
    }

    // Convert findings to entities
    let mut result_entities = Vec::new();
    for finding in &findings {
        let mut entity = Entity::new(
            EntityKind::Other,
            &format!("{} ({})", finding.detected_service, finding.category),
            finding.confidence,
            "waf_fingerprint",
        );

        let mut evidence = Evidence::new(
            EvidenceProvenance::for_scan("waf_fingerprint", "domain_cli"),
            format!("Infrastructure detected: {}", finding.detected_service),
        );
        evidence
            .attributes
            .insert("category".to_owned(), finding.category.clone());
        evidence
            .attributes
            .insert("confidence".to_owned(), finding.confidence_level().to_owned());
        evidence
            .attributes
            .insert("url".to_owned(), finding.url.clone());

        if !finding.headers_matched.is_empty() {
            evidence.attributes.insert(
                "headers".to_owned(),
                finding.headers_matched.join("; "),
            );
        }

        entity.add_evidence(evidence);
        result_entities.push(entity);
    }

    let count = result_entities.len();
    let section = format!("waf_fingerprint: {} infrastructure technologies detected", count);

    // Return entities but no outcome to avoid affecting overall domain scan success determination
    (result_entities, None, Some(section))
}
