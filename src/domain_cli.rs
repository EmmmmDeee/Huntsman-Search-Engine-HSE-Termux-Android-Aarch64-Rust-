//! End-to-end front-end for `huntsman-recon domain` and the domain arm of `scan`.
//!
//! Runs crt.sh and Cert Spotter certificate transparency (see [`crate::certspotter`]: every
//! certificate logged for the domain and its subdomains, each in full), DNS record and RDAP
//! registration lookups (see [`crate::rdap_legs`]), the domain blocklists Spiderfoot asks over the
//! system resolver (see [`crate::dnsbl`]) and the filtering resolvers (see [`crate::dns_filter`])
//! in sequence for a single domain, then the keyed legs whose key is configured: `VirusTotal`
//! reputation (`HUNTSMAN_VIRUSTOTAL_KEY`) and Hunter.io published addresses (`HUNTSMAN_HUNTER_KEY`), then
//! every domain source in [`crate::indicator_legs::SOURCES`] (Shodan DNS, Pulsedive, Netlas, OTX, urlscan.io, Robtex,
//! `HackerTarget`, `LeakIX`, `URLhaus`, `SecurityTrails`,
//! `ThreatFox`, Whoxy WHOIS). A keyed leg without its key makes no request and reports nothing;
//! a configured key always runs its leg. Last, every subdomain the legs found is resolved, as
//! Spiderfoot's `sfp_dnsresolve` does (see `resolve`). Every result set is combined into one
//! entity list and rendered report.
//!
//! Every leg, DNS included, sends through the one transport the caller hands in. The DNS leg's
//! records are entities like any other leg's findings: each address, mail exchanger, name
//! server, delegated SPF domain and report mailbox the domain publishes is one, tied to the
//! domain, and the domain's own DNS evidence lists its addresses under `ip`, the attribute the
//! resolution relation (and so the shared-hosting rule) reads.
//!
//! When it has no entity to show and no source answered, the lookup ends from its rows through
//! [`crate::source_outcome::SourceReach`]: a request refused before sending is a refusal (exit
//! 77), otherwise no usable response (exit 69); any entity or answered source makes it print.

use std::path::PathBuf;

use crate::canonical::{canonical_domain, canonical_email, canonical_ip};
use crate::certspotter;
use crate::crtsh::{self, CrtShError};
use crate::dns::{self, DomainDns, RESOLVE_SOURCE, RecordType, ResolveErrorKind};
use crate::dns_filter;
use crate::dnsbl::{self, Subject};
use crate::entity::Entity;
use crate::entity::{EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::http::{Transport, TransportConfig};
use crate::hunter;
use crate::indicator_legs;
use crate::indicator_sources::Indicator;
use crate::keys::Keys;
use crate::lookup_args::LookupTokens;
use crate::lookup_report;
use crate::recon::ReconTargetKind;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, SourceReach, SourceRun};
use crate::spf::Mechanism;
use crate::tags;
use crate::threat_feeds::{self, Feeds};
use crate::virustotal;

mod resolve;

pub const DOMAIN_USAGE: &str = "usage: huntsman-recon domain DOMAIN [--save FILE]";

/// The DNS leg's module name, on its outcome row and its evidence.
const DNS_SOURCE: &str = "dns";
const CRTSH_SOURCE: &str = "crtsh";
/// The queried domain, as the keyed legs hold it.
const DOMAIN_CONFIDENCE: f64 = 0.90;
/// An address, host or mailbox the domain's own records name: its zone published it.
const RECORD_CONFIDENCE: f64 = 0.85;
/// An address or host a provider last saw the domain's records or certificate name: an earlier
/// observation than the zone's own answer.
const SEEN_CONFIDENCE: f64 = 0.80;

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
        let (raw, save) = LookupTokens::single(args, "domain needs exactly one DOMAIN")?;
        let domain =
            canonical_domain(&raw).ok_or_else(|| Error::invalid_value("invalid domain"))?;
        Ok(Self { domain, save })
    }
}

pub type DomainRun = SourceRun<Report>;

/// Transport settings for a domain lookup: crt.sh's timeout and body limit, the largest any of
/// its legs needs, so a popular domain's certificate list is read whole.
#[must_use]
pub fn transport_config() -> TransportConfig {
    crtsh::transport_config()
}

/// Run every domain leg for `domain`, then check it and everything the legs found against the
/// threat `feeds`. Keyed legs run only when `keys` holds their key, and each leg only when the
/// transport's lookup asks its module ([`Transport::runs_module`]).
#[must_use]
pub fn run<T: Transport + ?Sized + Sync>(
    transport: &T,
    keys: &Keys,
    feeds: &Feeds,
    domain: &str,
    now_unix: u64,
) -> DomainRun {
    let Some(domain) = canonical_domain(domain) else {
        return DomainRun::Failed("invalid domain".into());
    };

    let scan_id = crate::entity::scan_id("domain", &domain);
    let mut found = Report::default();
    let mut sections = Vec::new();

    if transport.runs_module(CRTSH_SOURCE) {
        sections.push(crtsh_leg(
            transport, &domain, &scan_id, now_unix, &mut found,
        ));
    }
    if transport.runs_module(certspotter::SOURCE) {
        let certificates = certspotter::lookup(transport, keys, &domain, &scan_id, now_unix);
        found.entities.extend(certificates.entities);
        found.outcomes.push(certificates.outcome);
    }
    let Resolved {
        resolvers_up,
        unfiltered,
    } = dns_leg(
        transport,
        &domain,
        &scan_id,
        now_unix,
        &mut found,
        &mut sections,
    );

    let registration = crate::rdap_legs::domain(transport, &domain, &scan_id, now_unix);
    found.entities.extend(registration.entities);
    if let Some(outcome) = registration.outcome {
        found.outcomes.push(outcome);
    }
    let seen = crate::mnemonic::domain(transport, &domain, &scan_id, now_unix);
    found.entities.extend(seen.entities);
    if let Some(outcome) = seen.outcome {
        found.outcomes.push(outcome);
    }
    let (listed, rows) = dnsbl::check(transport, Subject::Domain(&domain), &scan_id, now_unix);
    found.entities.extend(listed);
    found.outcomes.extend(rows);
    let (blocked, rows) = dns_filter::check(transport, &domain, &unfiltered, &scan_id, now_unix);
    found.entities.extend(blocked);
    found.outcomes.extend(rows);
    keyed_legs(transport, keys, &domain, &scan_id, now_unix, &mut found);
    let hosts = resolve::hosts(&found.entities, &domain);
    if resolvers_up && !hosts.is_empty() && transport.runs_module(RESOLVE_SOURCE) {
        let resolved = resolve::resolve(transport, &domain, &hosts, &scan_id, now_unix);
        found.entities.extend(resolved.entities);
        found.outcomes.push(resolved.outcome);
        sections.push(resolved.section);
    }
    threat_feeds::check_found(
        feeds,
        threat_feeds::Subject::Name(domain.clone()),
        &mut found.entities,
        &mut found.outcomes,
        &scan_id,
        now_unix,
    );
    let Report {
        mut entities,
        outcomes,
    } = found;
    merge_by_uid(&mut entities);
    tag_lookalikes(&domain, &mut entities);

    // A source that answered "nothing known" answered: its zero row is the result, so the lookup
    // ends from its rows only when it has no entity to show. It reads them through `SourceReach`,
    // like ip: a request refused before sending is a refusal (exit 77), else no usable response
    // (exit 69), as the README's exit codes say.
    let reach = if entities.is_empty() {
        SourceReach::of(&outcomes)
    } else {
        SourceReach::Answered
    };
    if let Some(run) = reach.unanswered(&format!("no source answered for domain {domain}")) {
        return run;
    }
    // Offline, so it never turns a lookup no source answered into a result.
    if let Some(policy) = registry_policy(&domain, &scan_id) {
        entities.push(policy);
        merge_by_uid(&mut entities);
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

/// Tags each other registered domain the lookup found whose name is one edit or one look-alike
/// character from the domain's own, as `githuh.com` is to `github.com`. Hosts under the domain
/// and other names in its own registered domain are never look-alikes. **Pure.**
fn tag_lookalikes(domain: &str, entities: &mut [Entity]) {
    let Some(own) = crate::domains::registrable_domain(domain) else {
        return;
    };
    let label = |registered: &str| registered.split('.').next().unwrap_or("").to_owned();
    let own_label = label(&own);
    for entity in entities
        .iter_mut()
        .filter(|entity| entity.kind == EntityKind::Domain)
    {
        let Some(registered) = crate::domains::registrable_domain(&entity.value) else {
            continue;
        };
        if registered != own && crate::validation::is_lookalike(&label(&registered), &own_label) {
            entity.tag(tags::LOOKALIKE);
        }
    }
}

/// Evidence source for what a namespace's registry requires of whoever holds a name in it.
const REGISTRY_POLICY_SOURCE: &str = "registry_policy";

/// The domain as its registry's eligibility rules describe it: `.gov.au` names are held only by
/// government bodies (and `nsw.gov.au` by New South Wales's), `.id.au` only by natural persons,
/// `.edu.vn` only by education institutions. It is what the namespace requires, not who holds
/// this name, so it says nothing about a person. **Pure.**
fn registry_policy(domain: &str, scan_id: &str) -> Option<Entity> {
    let (class, rule) = crate::address_au::au_domain_registrant(domain)
        .or_else(|| crate::domains::vn_domain_registrant(domain))?;
    let state = crate::address_au::au_gov_domain_state(domain)
        .or_else(|| crate::address_au::au_edu_domain_state(domain));
    let summary = match state {
        Some(state) => format!("Registry policy: held by {rule}, of {state}"),
        None => format!("Registry policy: held by {rule}"),
    };
    let evidence = Evidence::new(
        EvidenceProvenance::for_scan(REGISTRY_POLICY_SOURCE, scan_id),
        summary,
    )
    .with_attr("registrant_class", class)
    .with_optional_attrs([("registrant_state", state)]);
    let mut entity = Entity::new(EntityKind::Domain, domain, DOMAIN_CONFIDENCE, scan_id);
    entity.add_evidence(evidence);
    entity.tag(format!("registrant:{class}"));
    Some(entity)
}

/// What the domain's own resolution told the legs after it.
struct Resolved {
    /// Whether the resolvers answered the domain's own queries; when none did, its hosts are not
    /// asked either. A lookup that does not ask `dns` cannot tell, so it asks them.
    resolvers_up: bool,
    /// The domain's own addresses, which a filtering resolver's missing answer is read against.
    unfiltered: dns_filter::Unfiltered,
}

/// The `dns` leg: the domain's records, its entities and its report section. A lookup that does
/// not ask `dns` sends none of its queries; when it asks a filtering resolver, the filters' own
/// unfiltered answer is asked instead, as that is what they are read against.
fn dns_leg<T: Transport + ?Sized>(
    transport: &T,
    domain: &str,
    scan_id: &str,
    now_unix: u64,
    found: &mut Report,
    sections: &mut Vec<String>,
) -> Resolved {
    if !transport.runs_module(DNS_SOURCE) {
        let filtered = dns_filter::FILTERS
            .iter()
            .any(|filter| transport.runs_module(filter.source));
        return Resolved {
            resolvers_up: true,
            unfiltered: if filtered {
                dns_filter::Unfiltered::ask(transport, domain)
            } else {
                dns_filter::Unfiltered::Unanswered("not asked".to_owned())
            },
        };
    }
    let Some(records) = dns::lookup_domain(transport, domain) else {
        found.outcomes.push(SourceExecutionOutcome::failed(
            DNS_SOURCE,
            now_unix,
            SourceOutcomeKind::Inconclusive,
            None,
            "bad domain",
        ));
        return Resolved {
            resolvers_up: false,
            unfiltered: dns_filter::Unfiltered::Unanswered("not a name to ask".to_owned()),
        };
    };
    let unfiltered = dns_filter::Unfiltered::from_records(&records);
    // The DNS outcome row carries the resolver failure's reason, read like any other row.
    let resolvers_up = resolver_failure(&records).is_none();
    found.outcomes.push(dns_outcome(&records, now_unix));
    found.entities.extend(dns_entities(&records, scan_id));
    sections.push(records.render());
    Resolved {
        resolvers_up,
        unfiltered,
    }
}

/// The crt.sh leg: the names in certificates logged for the domain. Returns its report line.
fn crtsh_leg<T: Transport + ?Sized>(
    transport: &T,
    domain: &str,
    scan_id: &str,
    now_unix: u64,
    found: &mut Report,
) -> String {
    match crtsh::lookup(transport, ReconTargetKind::Domain, domain, scan_id) {
        Ok(report) => {
            let count = report.entities.len();
            found.entities.extend(report.entities);
            // crt.sh answered with its list of logged certificates; an empty list is "none".
            found.outcomes.push(if count == 0 {
                SourceExecutionOutcome::valid_zero(CRTSH_SOURCE, now_unix)
            } else {
                SourceExecutionOutcome::success(CRTSH_SOURCE, now_unix, count)
            });
            format!("crtsh: {count} certificate-transparency entities")
        }
        Err(error) => {
            // The row carries the reason; `SourceReach` reads a refusal as exit 77 and a
            // no-response as exit 69. The section line keeps its "refused"/"unavailable" wording.
            let detail = error.to_string();
            let kind = match &error {
                CrtShError::Refused(_) => SourceOutcomeKind::RefusedBeforeSending,
                CrtShError::NoResponse(kind) => *kind,
                _ => SourceOutcomeKind::Inconclusive,
            };
            found.outcomes.push(SourceExecutionOutcome::failed(
                CRTSH_SOURCE,
                now_unix,
                kind,
                None,
                &detail,
            ));
            match &error {
                CrtShError::Refused(reason) => format!("crtsh: refused ({reason})"),
                _ => format!("crtsh: unavailable ({detail})"),
            }
        }
    }
}

/// The provider legs: `VirusTotal` and Hunter.io when their keys are configured, then the
/// indicator sources that apply.
fn keyed_legs<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    domain: &str,
    scan_id: &str,
    now_unix: u64,
    found: &mut Report,
) {
    if virustotal::API.runs(transport, keys) {
        let api = &virustotal::API;
        match virustotal::lookup(
            transport,
            keys,
            virustotal::Object::Domain,
            domain,
            now_unix,
        ) {
            Ok(Some(report)) => {
                found
                    .entities
                    .extend(virustotal_entities(domain, scan_id, &report));
                found
                    .outcomes
                    .push(SourceExecutionOutcome::success(api.source, now_unix, 1));
            }
            Ok(None) => found
                .outcomes
                .push(SourceExecutionOutcome::valid_zero(api.source, now_unix)),
            Err(err) => found.outcomes.push(err.outcome(api, now_unix)),
        }
    }
    if hunter::API.runs(transport, keys) {
        let outcome = hunter_leg(
            transport,
            keys,
            domain,
            scan_id,
            now_unix,
            &mut found.entities,
        );
        found.outcomes.push(outcome);
    }
    let legs = indicator_legs::run(
        transport,
        keys,
        Indicator::Domain(domain),
        scan_id,
        now_unix,
    );
    found.entities.extend(legs.entities);
    // Each indicator row carries its own reason; `SourceReach` reads them like the other legs'.
    found.outcomes.extend(legs.outcomes);
}

/// The first query that no resolver answered, when the zone answered none of them: neither a
/// record nor its own "no such name" or "no such record". `None` once one query was answered.
/// **Pure.**
fn resolver_failure(records: &DomainDns) -> Option<&dns::QueryFailure> {
    if !records.answers.is_empty() {
        return None;
    }
    // Among the failures that are not the zone's own "no record", the DNS leg is refused only when
    // every one was refused, so take the first that was not refused, else the first.
    let answered = || {
        records
            .failures
            .iter()
            .filter(|failure| failure.error.kind != ResolveErrorKind::Empty)
    };
    answered()
        .find(|failure| failure.error.kind != ResolveErrorKind::Refused)
        .or_else(|| answered().next())
}

/// The DNS leg's outcome. `found` counts the records the zone returned. A zone that answered
/// every query with "no such name" or "no such record" is a validated zero; when no resolver
/// answered at all the outcome says why, never a zero. Queries that failed beside answered ones
/// are named in `detail`. **Pure.**
fn dns_outcome(records: &DomainDns, now_unix: u64) -> SourceExecutionOutcome {
    if let Some(failure) = resolver_failure(records) {
        let kind = failure.error.kind.outcome_kind();
        let detail = format!(
            "no resolver answered: {} queries failed, the first {} {}: {}",
            records.failures.len(),
            failure.record_type.as_str(),
            failure.error.kind.as_str(),
            failure.error.detail
        );
        return SourceExecutionOutcome::failed(DNS_SOURCE, now_unix, kind, None, detail);
    }
    let count: usize = records
        .answers
        .iter()
        .map(|answer| answer.answer.records.len())
        .sum();
    if count == 0 {
        return SourceExecutionOutcome::valid_zero(DNS_SOURCE, now_unix);
    }
    let outcome = SourceExecutionOutcome::success(DNS_SOURCE, now_unix, count);
    let unanswered: Vec<String> = records
        .failures
        .iter()
        .filter(|failure| failure.error.kind != ResolveErrorKind::Empty)
        .map(|failure| {
            format!(
                "{} {} {}",
                failure.record_type.as_str(),
                failure.name,
                failure.error.kind.as_str()
            )
        })
        .collect();
    if unanswered.is_empty() {
        outcome
    } else {
        outcome.with_detail(format!("unanswered: {}", unanswered.join(", ")))
    }
}

/// The entities the domain's DNS records name, the domain first; none when no record came back.
/// The domain's evidence lists every address it resolves to under `ip` (a non-public one too, as
/// published), its mail exchangers under `mx`, its name servers under `ns` and the domains its
/// SPF policy delegates to under `spf_include`, and each TXT, DMARC and TLS-RPT record is
/// evidence of its own; its SPF and DMARC posture are tags. Each public address, host, report
/// mailbox and report URL is an entity whose evidence names the domain and the record type, so
/// the resolution relation links the domain to its addresses. **Pure.**
fn dns_entities(records: &DomainDns, scan_id: &str) -> Vec<Entity> {
    if records.answers.is_empty() {
        return Vec::new();
    }
    let mut zone = ZoneFindings::new(&records.domain, scan_id);
    for answer in &records.answers {
        for record in &answer.answer.records {
            zone.record(answer, record);
        }
    }
    if let Some(spf) = &records.spf {
        zone.spf(spf);
    }
    if let Some(dmarc) = &records.dmarc {
        zone.dmarc(dmarc);
    }
    if let Some(tlsrpt) = &records.tlsrpt {
        zone.tlsrpt(tlsrpt);
    }
    zone.finish()
}

/// One domain's DNS records as entities, built by [`dns_entities`].
struct ZoneFindings<'a> {
    domain: &'a str,
    scan_id: &'a str,
    apex: Entity,
    /// What the domain's own DNS evidence lists, in record order: (attribute, value).
    listed: Vec<(&'static str, String)>,
    found: Vec<Entity>,
}

impl<'a> ZoneFindings<'a> {
    fn new(domain: &'a str, scan_id: &'a str) -> Self {
        Self {
            domain,
            scan_id,
            apex: Entity::new(EntityKind::Domain, domain, DOMAIN_CONFIDENCE, scan_id),
            listed: Vec::new(),
            found: Vec::new(),
        }
    }

    fn evidence(&self, summary: String) -> Evidence {
        Evidence::new(
            EvidenceProvenance::for_scan(DNS_SOURCE, self.scan_id),
            summary,
        )
    }

    /// Evidence for an entity a record of the domain names.
    fn named(&self, record_type: &str, summary: String) -> Evidence {
        self.evidence(summary)
            .with_attr("domain", self.domain)
            .with_attr("record_type", record_type)
    }

    fn push(&mut self, kind: EntityKind, value: &str, evidence: Evidence, tags: &[&str]) {
        push_entity(
            &mut self.found,
            kind,
            value,
            RECORD_CONFIDENCE,
            self.scan_id,
            evidence,
            tags,
        );
    }

    /// The host a record names, listed under `attr` as published (lower case, no root dot); an
    /// empty name such as a null MX is skipped. It is a domain entity only in canonical form, so
    /// a service name such as `_spf.example.net` is listed without becoming a pivot.
    fn host(&mut self, attr: &'static str, raw: &str, evidence: Evidence) {
        let (name, is_sub) = crate::domains::classify_domain_candidate(raw, self.domain);
        if name.is_empty() {
            return;
        }
        if canonical_domain(&name).is_some() {
            let subdomain: &[&str] = if is_sub { &[tags::SUBDOMAIN] } else { &[] };
            self.push(EntityKind::Domain, &name, evidence, subdomain);
        }
        self.listed.push((attr, name));
    }

    fn record(&mut self, answer: &dns::QueryAnswer, record: &str) {
        let record_type = answer.record_type.as_str();
        let domain = self.domain;
        match answer.record_type {
            RecordType::A | RecordType::Aaaa => {
                let raw = record.trim();
                let public = canonical_ip(raw);
                self.listed
                    .push(("ip", public.clone().unwrap_or_else(|| raw.to_owned())));
                if let Some(ip) = public {
                    let evidence = self
                        .named(record_type, format!("{record_type} record of {domain}"))
                        .with_attr("resolver", answer.answer.server.provider);
                    self.push(EntityKind::IpAddress, &ip, evidence, &[]);
                }
            }
            RecordType::Mx => {
                let (preference, exchanger) = mx_parts(record);
                let evidence = self
                    .named(record_type, format!("Mail exchanger of {domain}"))
                    .with_optional_attrs([("mx_preference", preference)]);
                self.host("mx", exchanger, evidence);
            }
            RecordType::Ns => {
                let evidence = self.named(record_type, format!("Name server of {domain}"));
                self.host("ns", record, evidence);
            }
            RecordType::Txt => {
                let label = if answer.name == domain {
                    "TXT"
                } else if answer.name.starts_with("_dmarc.") {
                    "DMARC"
                } else {
                    "TLS-RPT"
                };
                let evidence = self
                    .evidence(format!("{label} record: {record}"))
                    .with_attr("record_type", label);
                self.apex.add_evidence(evidence);
            }
            RecordType::Soa => {
                let Some(soa) = dns::parse_soa(record) else {
                    return;
                };
                self.listed.push(("soa_serial", soa.serial.to_string()));
                let evidence = self.named(record_type, format!("Primary name server of {domain}"));
                self.host("soa_primary_ns", &soa.primary_ns, evidence);
                self.responsible(&soa.responsible);
            }
            RecordType::Ptr => {}
        }
    }

    /// The SOA's responsible mailbox, listed as published and kept as an entity only when it is
    /// the domain's own (see [`Self::own_mailbox`]).
    fn responsible(&mut self, mailbox: &str) {
        let summary = format!("Mailbox responsible for the {} zone", self.domain);
        self.mailbox_record("SOA", "soa_mailbox", summary, mailbox);
    }

    /// The SPF posture as tags, and each domain the policy includes or redirects to.
    fn spf(&mut self, spf: &crate::spf::SpfRecord) {
        self.apex.tag(spf.all_policy().tag());
        for issue in spf.issues() {
            self.apex.tag(issue.tag());
        }
        let delegated = spf
            .directives
            .iter()
            .filter_map(|(_, mechanism)| match mechanism {
                Mechanism::Include(target) => Some(target.as_str()),
                _ => None,
            })
            .chain(spf.redirect.as_deref());
        for target in delegated {
            let summary = format!("Domain the SPF policy of {} delegates to", self.domain);
            let evidence = self.named("SPF", summary);
            self.host("spf_include", target, evidence);
        }
    }

    /// The DMARC posture as tags, and the mailboxes that receive its reports.
    fn dmarc(&mut self, dmarc: &crate::dmarc::DmarcRecord) {
        self.apex
            .tag(dmarc.policy.map_or("dmarc:missing", |policy| policy.tag()));
        for issue in dmarc.issues() {
            self.apex.tag(issue.tag());
        }
        for mailbox in &dmarc.rua {
            self.mailbox("DMARC", "aggregate", mailbox);
        }
        for mailbox in &dmarc.ruf {
            self.mailbox("DMARC", "failure", mailbox);
        }
    }

    /// The mailboxes and URLs that receive the domain's TLS reports.
    fn tlsrpt(&mut self, tlsrpt: &crate::tlsrpt::TlsRptRecord) {
        for mailbox in &tlsrpt.emails {
            self.mailbox("TLS-RPT", "TLS", mailbox);
        }
        for url in &tlsrpt.urls {
            let summary = format!("TLS report endpoint of {}", self.domain);
            let evidence = self.named("TLS-RPT", summary);
            self.push(EntityKind::Url, url, evidence, &[]);
        }
    }

    fn mailbox(&mut self, record_type: &str, reports: &str, mailbox: &str) {
        let summary = format!(
            "Mailbox that receives {reports} reports for {}",
            self.domain
        );
        self.mailbox_record(record_type, "report_mailbox", summary, mailbox);
    }

    /// A mailbox a record names, listed under `attr` as published, and an e-mail entity only
    /// when it is the domain's own.
    fn mailbox_record(
        &mut self,
        record_type: &str,
        attr: &'static str,
        summary: String,
        raw: &str,
    ) {
        let Some(email) = canonical_email(raw) else {
            return;
        };
        self.listed.push((attr, email.clone()));
        if self.own_mailbox(&email) {
            let evidence = self.named(record_type, summary);
            self.push(EntityKind::Email, &email, evidence, &[]);
        }
    }

    /// Whether a mailbox sits in the looked-up domain or below it. A DNS host's `hostmaster@`
    /// or a DMARC vendor's report mailbox is named by every zone that uses the service, and as
    /// an entity it would bridge each of those lookups to the others; a domain above is no
    /// safer, as it can be a shared suffix such as `github.io`.
    fn own_mailbox(&self, email: &str) -> bool {
        let mailbox_domain = email.rsplit_once('@').map_or("", |(_, domain)| domain);
        let domain = self.domain.to_ascii_lowercase();
        canonical_domain(mailbox_domain).is_some()
            && crate::domains::is_or_subdomain_of(mailbox_domain, &domain)
    }

    fn finish(self) -> Vec<Entity> {
        let Self {
            domain,
            scan_id,
            mut apex,
            listed,
            found,
        } = self;
        if !listed.is_empty() {
            let summary = format!("DNS records of {domain}");
            let mut evidence =
                Evidence::new(EvidenceProvenance::for_scan(DNS_SOURCE, scan_id), summary);
            for (attr, value) in listed {
                evidence = evidence.with_attr(attr, value);
            }
            apex.add_evidence(evidence);
        }
        let mut out = Vec::with_capacity(found.len() + 1);
        out.push(apex);
        out.extend(found);
        out
    }
}

/// An MX record's preference and exchanger: `10 mx.example.com.` gives
/// `(Some("10"), "mx.example.com.")`. **Pure.**
fn mx_parts(record: &str) -> (Option<&str>, &str) {
    let record = record.trim();
    match record.split_once(char::is_whitespace) {
        Some((preference, exchanger)) if preference.parse::<u16>().is_ok() => {
            (Some(preference), exchanger.trim())
        }
        _ => (None, record),
    }
}

/// `VirusTotal`'s report as the domain's evidence, every detail and the whole answer on it, and
/// each address and host name its last DNS records and HTTPS certificate name as a pivot.
fn virustotal_entities(domain: &str, scan_id: &str, report: &virustotal::Report) -> Vec<Entity> {
    let mut entity = Entity::new(EntityKind::Domain, domain, DOMAIN_CONFIDENCE, scan_id);
    if report.malicious > 0 {
        entity.tag(crate::tags::MALICIOUS);
    }
    let provenance = || EvidenceProvenance::for_scan(virustotal::SOURCE, scan_id);
    let mut evidence = Evidence::new(
        provenance(),
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
    for (name, value) in &report.details {
        evidence = evidence.with_attr(name.as_str(), value.as_str());
    }
    let addresses: Vec<String> = report
        .addresses
        .iter()
        .filter_map(|raw| canonical_ip(raw))
        .collect();
    for address in &addresses {
        evidence = evidence.with_attr("ip", address.as_str());
    }
    entity.add_evidence(evidence.with_attr("raw_answer", report.raw_answer.as_str()));
    let mut entities = vec![entity];
    for address in &addresses {
        let evidence = Evidence::new(
            provenance(),
            format!("Address in VirusTotal's last DNS records of {domain}"),
        )
        .with_attr("domain", domain);
        push_entity(
            &mut entities,
            EntityKind::IpAddress,
            address,
            SEEN_CONFIDENCE,
            scan_id,
            evidence,
            &[],
        );
    }
    for (role, raw) in &report.hosts {
        let (name, is_sub) = crate::domains::classify_domain_candidate(raw, domain);
        if name == domain || canonical_domain(&name).is_none() {
            continue;
        }
        let summary = if role == "certificate" {
            format!("Name on the HTTPS certificate VirusTotal last saw for {domain}")
        } else {
            format!(
                "{} record of {domain} in VirusTotal's last DNS records",
                role.to_ascii_uppercase()
            )
        };
        let evidence = Evidence::new(provenance(), summary)
            .with_attr("domain", domain)
            .with_attr("record_type", role.to_ascii_uppercase());
        let subdomain: &[&str] = if is_sub { &[tags::SUBDOMAIN] } else { &[] };
        push_entity(
            &mut entities,
            EntityKind::Domain,
            &name,
            SEEN_CONFIDENCE,
            scan_id,
            evidence,
            subdomain,
        );
    }
    entities
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

    /// The domain lookup, with no threat feed consulted: the feeds' own tests cover them.
    fn run<T: Transport + ?Sized + Sync>(
        transport: &T,
        keys: &Keys,
        domain: &str,
        now_unix: u64,
    ) -> DomainRun {
        super::run(transport, keys, &Feeds::none(), domain, now_unix)
    }

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
        let entities = virustotal_entities("example.com", "scan", &report);
        let entity = &entities[0];
        assert!(entity.has_tag(crate::tags::MALICIOUS));
        assert_eq!(
            entity.evidence[0].summary,
            "VirusTotal: 3 of 53 engines flag the domain"
        );
    }

    use std::sync::Mutex;

    use crate::http::{Request, Response, TransportFailure};
    use crate::relation::RelationKind;
    use crate::test_support::Refusing;

    /// `example.com`'s documented IANA addresses: public, so they are real address entities.
    const IPV4: &str = "93.184.215.14";
    const IPV6: &str = "2606:2800:21f:cb07:6820:80da:af6b:8b2c";

    /// One zone served the way the DNS JSON API answers (`Status` 0 with the records of the
    /// queried type, 0 with none when the name has other records, 3 when it has none at all), and
    /// crt.sh's answer. Every request is recorded. Any other host, and the resolvers when
    /// `resolvers_down`, fail with no response, as an unreachable source would.
    struct Zone {
        records: Vec<(String, &'static str, String)>,
        crtsh: Option<&'static str>,
        resolvers_down: bool,
        seen: Mutex<Vec<String>>,
    }

    impl Zone {
        fn new(records: &[(&str, &'static str, &str)]) -> Self {
            Self {
                records: records
                    .iter()
                    .map(|(name, kind, data)| ((*name).to_owned(), *kind, (*data).to_owned()))
                    .collect(),
                crtsh: Some("[]"),
                resolvers_down: false,
                seen: Mutex::new(Vec::new()),
            }
        }

        /// The documented zone of `domain`: two addresses, a mail exchanger in the zone, an
        /// outside name server, an SPF policy that delegates, and DMARC and TLS-RPT policies.
        fn published(domain: &str) -> Self {
            let dmarc = format!("_dmarc.{domain}");
            let tls = format!("_smtp._tls.{domain}");
            let mx = format!("10 mx.{domain}.");
            Self::new(&[
                (domain, "A", IPV4),
                (domain, "AAAA", IPV6),
                (domain, "MX", &mx),
                (domain, "NS", "ns1.dns-host.net."),
                (
                    domain,
                    "SOA",
                    "ns1.dns-host.net. hostmaster.example.com. 2026102301 7200 3600 1209600 300",
                ),
                (
                    domain,
                    "TXT",
                    r#""v=spf1 include:_spf.mail-host.net include:spf.mail-host.net -all""#,
                ),
                (domain, "TXT", r#""site-verification=abc123""#),
                (
                    &dmarc,
                    "TXT",
                    r#""v=DMARC1; p=reject; rua=mailto:dmarc@reports.example.net,mailto:dmarc@example.com""#,
                ),
                (
                    &tls,
                    "TXT",
                    r#""v=TLSRPTv1; rua=mailto:tlsrpt@reports.example.net""#,
                ),
            ])
        }

        fn requests(&self, prefix: &str) -> usize {
            self.seen
                .lock()
                .expect("request log")
                .iter()
                .filter(|url| url.starts_with(prefix))
                .count()
        }

        fn doh(&self, url: &str) -> Response {
            let query = url.split_once('?').map_or("", |(_, query)| query);
            let param = |key: &str| {
                query
                    .split('&')
                    .find_map(|pair| pair.strip_prefix(key)?.strip_prefix('='))
                    .unwrap_or("")
            };
            let (name, kind) = (param("name"), param("type"));
            let code = match kind {
                "A" => 1,
                "NS" => 2,
                "MX" => 15,
                "SOA" => 6,
                "TXT" => 16,
                "AAAA" => 28,
                _ => 0,
            };
            let answers: Vec<String> = self
                .records
                .iter()
                .filter(|(n, k, _)| n == name && *k == kind)
                .map(|(_, _, data)| {
                    serde_json::json!({ "name": name, "type": code, "data": data }).to_string()
                })
                .collect();
            let status = if self.records.iter().any(|(n, _, _)| n == name) {
                0
            } else {
                3
            };
            json_ok(&format!(
                r#"{{"Status":{status},"Answer":[{}]}}"#,
                answers.join(",")
            ))
        }
    }

    impl Transport for Zone {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.seen
                .lock()
                .expect("request log")
                .push(request.url.clone());
            let resolver = dns::resolver_config()
                .name_servers
                .iter()
                .any(|server| request.url.starts_with(server.doh_url));
            if request.url.starts_with("https://crt.sh/") {
                if let Some(body) = self.crtsh {
                    return Ok(json_ok(body));
                }
            } else if resolver && !self.resolvers_down {
                return Ok(self.doh(&request.url));
            }
            Err(TransportFailure {
                kind: SourceOutcomeKind::DnsFailure,
                detail: "offline".into(),
                blocked: false,
            })
        }
    }

    fn json_ok(body: &str) -> Response {
        crate::test_support::json_ok(body)
    }

    fn printed(zone: &Zone, domain: &str) -> Report {
        match run(zone, &Keys::default(), domain, 1) {
            DomainRun::Printed { report, .. } => report,
            DomainRun::Network(message) => panic!("network: {message}"),
            DomainRun::Failed(message) => panic!("failed: {message}"),
        }
    }

    fn entity<'a>(report: &'a Report, kind: &EntityKind, value: &str) -> Option<&'a Entity> {
        report
            .entities
            .iter()
            .find(|entity| entity.kind == *kind && entity.value == value)
    }

    fn dns_row(report: &Report) -> &SourceExecutionOutcome {
        report
            .outcomes
            .iter()
            .find(|outcome| outcome.module == "dns")
            .expect("a dns outcome row")
    }

    /// Every address, host and mailbox the zone publishes is an entity tied to the domain, and
    /// the DNS leg asked the resolvers through the transport the lookup was handed. Before, the
    /// records were printed only, and the leg opened its own connection to the real resolvers.
    #[test]
    fn the_records_a_domain_publishes_are_entities_of_the_lookup() {
        let zone = Zone::published("example.com");
        let report = printed(&zone, "example.com");

        // Eight queries for the domain's own records, then A and AAAA for its mail exchanger.
        assert_eq!(zone.requests("https://cloudflare-dns.com/dns-query?"), 10);
        for ip in [IPV4, IPV6] {
            let address = entity(&report, &EntityKind::IpAddress, ip).expect("address entity");
            let evidence = &address.evidence[0];
            assert_eq!(evidence.provenance.source, "dns");
            assert_eq!(
                evidence.attr_values("domain").collect::<Vec<_>>(),
                ["example.com"]
            );
        }
        let mx = entity(&report, &EntityKind::Domain, "mx.example.com").expect("mail exchanger");
        assert!(mx.has_tag(crate::tags::SUBDOMAIN));
        // The zone names a mail exchanger it publishes no address for.
        assert!(mx.has_tag(crate::tags::UNRESOLVED));
        assert_eq!(
            mx.evidence[0]
                .attr_values("mx_preference")
                .collect::<Vec<_>>(),
            ["10"]
        );
        for host in ["ns1.dns-host.net", "spf.mail-host.net"] {
            assert!(
                entity(&report, &EntityKind::Domain, host).is_some(),
                "{host}"
            );
        }
        // A service name is listed as published, but it is not a domain pivot.
        assert!(entity(&report, &EntityKind::Domain, "_spf.mail-host.net").is_none());
        // The zone's own mailboxes are entities; a report vendor's, named by every zone that
        // uses the vendor, is kept as published but never becomes one.
        for mailbox in ["dmarc@example.com", "hostmaster@example.com"] {
            assert!(
                entity(&report, &EntityKind::Email, mailbox).is_some(),
                "{mailbox}"
            );
        }
        for mailbox in ["dmarc@reports.example.net", "tlsrpt@reports.example.net"] {
            assert!(
                entity(&report, &EntityKind::Email, mailbox).is_none(),
                "{mailbox}"
            );
        }

        let apex = entity(&report, &EntityKind::Domain, "example.com").expect("the domain");
        let records = apex
            .evidence
            .iter()
            .find(|evidence| {
                evidence.provenance.source == "dns" && evidence.attributes.contains_key("ip")
            })
            .expect("the domain's DNS evidence");
        assert_eq!(records.attr_values("ip").collect::<Vec<_>>(), [IPV4, IPV6]);
        assert_eq!(
            records.attr_values("mx").collect::<Vec<_>>(),
            ["mx.example.com"]
        );
        assert_eq!(
            records.attr_values("ns").collect::<Vec<_>>(),
            ["ns1.dns-host.net"]
        );
        assert_eq!(
            records.attr_values("soa_primary_ns").collect::<Vec<_>>(),
            ["ns1.dns-host.net"]
        );
        assert_eq!(
            records.attr_values("soa_serial").collect::<Vec<_>>(),
            ["2026102301"]
        );
        assert_eq!(
            records.attr_values("report_mailbox").collect::<Vec<_>>(),
            [
                "dmarc@reports.example.net",
                "dmarc@example.com",
                "tlsrpt@reports.example.net"
            ]
        );
        assert_eq!(
            records.attr_values("spf_include").collect::<Vec<_>>(),
            ["_spf.mail-host.net", "spf.mail-host.net"]
        );
        assert!(apex.has_tag("spf:hardfail"));
        assert!(apex.has_tag("dmarc:reject"));
        assert!(
            apex.evidence
                .iter()
                .any(|evidence| evidence.summary == "TXT record: site-verification=abc123")
        );

        let row = dns_row(&report);
        assert_eq!(row.kind, SourceOutcomeKind::Success);
        assert_eq!(row.found, Some(9));
    }

    /// A DNS host's `hostmaster@` mailbox is on every zone it serves, so it is kept as published
    /// but never becomes an e-mail entity that would tie those zones together; a mailbox in the
    /// domain or below it does, and one above it does not (it may be a shared suffix's).
    #[test]
    fn an_soa_mailbox_is_an_entity_only_inside_the_looked_up_domain() {
        let soa = |domain: &str, mailbox: &str| {
            let zone = Zone::new(&[(
                domain,
                "SOA",
                &format!("ns1.dns-host.net. {mailbox} 7 7200 3600 1209600 300"),
            )]);
            printed(&zone, domain)
        };
        let report = soa("example.com", "hostmaster.dns-host.net.");
        assert!(entity(&report, &EntityKind::Email, "hostmaster@dns-host.net").is_none());
        let apex = entity(&report, &EntityKind::Domain, "example.com").expect("the domain");
        assert!(apex.evidence.iter().any(|evidence| {
            evidence
                .attr_values("soa_mailbox")
                .eq(["hostmaster@dns-host.net"])
        }));

        let report = soa("example.com", r"dns\.admin.lists.example.com.");
        assert!(entity(&report, &EntityKind::Email, "dns.admin@lists.example.com").is_some());

        let report = soa("shop.github.io", "hostmaster.github.io.");
        assert!(entity(&report, &EntityKind::Email, "hostmaster@github.io").is_none());

        let report = soa("example.com", "hostmaster.notexample.com.");
        assert!(entity(&report, &EntityKind::Email, "hostmaster@notexample.com").is_none());
    }

    /// A name the lookup finds in another registered domain one edit or one look-alike
    /// character from the domain's own is tagged; the domain's own hosts and unrelated names
    /// are not.
    #[test]
    fn a_name_one_edit_from_the_domain_is_a_lookalike() {
        let domain = "github.com";
        let zone = Zone::new(&[
            (domain, "A", IPV4),
            (domain, "NS", "ns1.githuh.com."),
            (domain, "NS", "ns2.dns-host.net."),
            (domain, "MX", "10 mx.github.com."),
        ]);
        let report = printed(&zone, domain);
        let tagged = |host: &str| {
            entity(&report, &EntityKind::Domain, host)
                .unwrap_or_else(|| panic!("{host}"))
                .has_tag(tags::LOOKALIKE)
        };
        assert!(tagged("ns1.githuh.com"));
        assert!(!tagged("ns2.dns-host.net"));
        assert!(!tagged("mx.github.com"));
        assert!(!tagged("github.com"));
    }

    /// `shop`'s own addresses, beside the domain's.
    const SHOP_V4: &str = "93.184.215.34";
    const SHOP_V6: &str = "2606:2800:21f:cb07:6820:80da:af6b:8b2d";

    /// A domain whose certificates name a host with public addresses, one with a private
    /// address, one with other records but no address and one with no records at all.
    fn hosts_report() -> Report {
        let mut zone = Zone::new(&[
            ("example.com", "A", IPV4),
            ("shop.example.com", "A", SHOP_V4),
            ("shop.example.com", "AAAA", SHOP_V6),
            ("intranet.example.com", "A", "10.0.0.5"),
            ("legacy.example.com", "TXT", "\"retired\""),
        ]);
        zone.crtsh = Some(
            r#"[{"name_value":"shop.example.com"},{"name_value":"intranet.example.com"},{"name_value":"legacy.example.com"},{"name_value":"gone.example.com"}]"#,
        );
        printed(&zone, "example.com")
    }

    /// Each host a lookup finds is resolved, as Spiderfoot's `sfp_dnsresolve` resolves every
    /// `INTERNET_NAME`: its public addresses are entities tied to the host, every address it
    /// resolves to is listed on it, and a host with no address is tagged unresolved. Before, a
    /// domain scan's subdomains were names only: no address of `shop` was found unless it was the
    /// apex's own.
    #[test]
    fn the_hosts_a_lookup_finds_are_resolved_as_sfp_dnsresolve_does() {
        let report = hosts_report();
        for (ip, record_type) in [(SHOP_V4, "A"), (SHOP_V6, "AAAA")] {
            let address = entity(&report, &EntityKind::IpAddress, ip).expect("shop's address");
            let evidence = &address.evidence[0];
            assert_eq!(evidence.provenance.source, RESOLVE_SOURCE);
            assert_eq!(
                evidence.summary,
                format!("{record_type} record of shop.example.com")
            );
            assert_eq!(
                evidence.attr_values("domain").collect::<Vec<_>>(),
                ["shop.example.com"]
            );
            assert_eq!(
                evidence.attr_values("resolver").collect::<Vec<_>>(),
                ["Cloudflare"]
            );
        }
        let resolved = |host: &str| {
            let found = entity(&report, &EntityKind::Domain, host).expect(host);
            let listed: Vec<String> = found
                .evidence
                .iter()
                .flat_map(|evidence| evidence.attr_values("resolved_ip"))
                .map(str::to_owned)
                .collect();
            (found.has_tag(crate::tags::UNRESOLVED), listed)
        };
        assert_eq!(
            resolved("shop.example.com"),
            (false, vec![SHOP_V4.into(), SHOP_V6.into()])
        );
        // A private address is listed as published, but it is not an address pivot.
        assert_eq!(
            resolved("intranet.example.com"),
            (false, vec!["10.0.0.5".into()])
        );
        assert!(entity(&report, &EntityKind::IpAddress, "10.0.0.5").is_none());
        // A name with other records but no address, and a name with no records at all.
        assert_eq!(resolved("legacy.example.com"), (true, Vec::new()));
        assert_eq!(resolved("gone.example.com"), (true, Vec::new()));

        let row = report
            .outcomes
            .iter()
            .find(|outcome| outcome.module == RESOLVE_SOURCE)
            .expect("a dnsresolve row");
        assert_eq!(row.kind, SourceOutcomeKind::Success);
        assert_eq!(row.found, Some(3));
        assert_eq!(
            row.detail.as_deref(),
            Some("2 of 4 hosts resolved, 2 unresolved")
        );
    }

    /// In the saved scan a resolved address is the host's child, the host resolves to it for the
    /// relation builder, and a name that does not resolve is `INTERNET_NAME_UNRESOLVED`, so
    /// Spiderfoot's "host only from certificate transparency" rule names only the live hosts, as
    /// it does in Spiderfoot. Before, it named every certificate name, dead ones included.
    #[test]
    fn a_resolved_host_is_its_addresses_parent_and_a_dead_one_is_unresolved() {
        let report = hosts_report();
        let relations = crate::relation::derive_all(&report.entities, "resolve");
        let shop = entity(&report, &EntityKind::Domain, "shop.example.com").expect("shop");
        let shop_v4 = entity(&report, &EntityKind::IpAddress, SHOP_V4).expect("shop's address");
        assert!(relations.iter().any(|relation| {
            relation.kind == RelationKind::ResolvesTo
                && relation.from_uid == shop.uid
                && relation.to_uid == shop_v4.uid
        }));

        let target = crate::sf_elements::Target {
            value: "example.com",
            kind: "INTERNET_NAME",
        };
        let elements = crate::sf_elements::elements(target, &report.entities, 1);
        let of = |data: &str| -> Vec<&crate::sf_elements::DataElement> {
            elements
                .iter()
                .filter(|element| element.data == data)
                .collect()
        };
        for host in ["legacy.example.com", "gone.example.com"] {
            assert!(
                of(host)
                    .iter()
                    .all(|element| element.kind == "INTERNET_NAME_UNRESOLVED"),
                "{host}: {:?}",
                of(host)
            );
        }
        let shop_ids: Vec<&str> = of("shop.example.com")
            .iter()
            .map(|element| element.id.as_str())
            .collect();
        let address = of(SHOP_V4);
        assert_eq!(address.len(), 1, "{address:?}");
        assert_eq!(address[0].kind, "IP_ADDRESS");
        assert_eq!(address[0].module, RESOLVE_SOURCE);
        assert!(
            shop_ids.contains(&address[0].source.as_deref().unwrap_or_default()),
            "the address is shop's child: {address:?}"
        );

        let rule: Vec<_> = crate::sf_correlate::shipped()
            .iter()
            .filter(|rule| rule.id == "host_only_from_certificatetransparency")
            .cloned()
            .collect();
        let mut named: Vec<String> = crate::sf_correlate::run(&rule, &elements)
            .into_iter()
            .map(|finding| finding.title)
            .collect();
        named.sort();
        assert_eq!(
            named,
            [
                "Host found only in certificate transparency: intranet.example.com",
                "Host found only in certificate transparency: shop.example.com",
            ]
        );
    }

    /// Two live lookups whose domains share an address give the relation builder a `resolves_to`
    /// link for each and fire the shared-hosting rule (AU-110), as a saved scan with that DNS
    /// evidence already did. Before, a live lookup carried no address, so neither ever fired.
    #[test]
    fn two_lookups_on_one_address_fire_the_shared_hosting_rule() {
        let mut entities = Vec::new();
        for domain in ["alpha-shop.com", "beta-shop.org"] {
            let zone = Zone::new(&[(domain, "A", IPV4)]);
            entities.extend(printed(&zone, domain).entities);
        }
        merge_by_uid(&mut entities);

        let relations = crate::relation::derive_all(&entities, "two-lookups");
        let resolves = relations
            .iter()
            .filter(|relation| relation.kind == RelationKind::ResolvesTo)
            .count();
        assert_eq!(resolves, 2, "{relations:?}");

        let report = crate::analysis::analyze_snapshot(&crate::pipeline::AnalysisSnapshot {
            entities,
            relations: Vec::new(),
            coverage: Vec::new(),
            ancestry: crate::evidence_ancestry::EvidenceAncestryGraph::default(),
            truncated: false,
        });
        let fired: Vec<&str> = report
            .correlations
            .iter()
            .map(|correlation| correlation.rule_id.as_str())
            .collect();
        assert!(fired.contains(&"AU-110"), "rules that fired: {fired:?}");
    }

    /// A zone that answers "no such name" to every query is a validated zero; resolvers that all
    /// fail are a failure that says why, with no count. Before, both were the same empty row.
    #[test]
    fn a_name_with_no_records_is_a_zero_and_a_resolver_outage_is_not() {
        let crtsh = r#"[{"name_value":"mail.gone-shop.com"}]"#;
        let mut nxdomain = Zone::new(&[]);
        nxdomain.crtsh = Some(crtsh);
        let row = dns_row(&printed(&nxdomain, "gone-shop.com")).clone();
        assert_eq!(row.kind, SourceOutcomeKind::ValidZero);

        let mut outage = Zone::published("gone-shop.com");
        outage.crtsh = Some(crtsh);
        outage.resolvers_down = true;
        let report = printed(&outage, "gone-shop.com");
        let row = dns_row(&report);
        assert!(!row.kind.is_accepted(), "{row:?}");
        assert_eq!(row.found, None);
        assert!(
            row.detail
                .as_deref()
                .is_some_and(|detail| detail.starts_with("no resolver answered")),
            "{row:?}"
        );
        assert!(entity(&report, &EntityKind::IpAddress, IPV4).is_none());
    }

    /// A name crt.sh has no certificates for and DNS has no records for is a result: the lookup
    /// prints its zero rows. crt.sh's empty list is its answer for a name with no logged
    /// certificates, a validated zero. Before, the crt.sh row was `inconclusive`, as if crt.sh had
    /// not answered, and the lookup failed with "no results for domain" (exit 69, "no usable
    /// response") although every source had answered.
    #[test]
    fn a_name_nothing_is_known_about_prints_its_zero_rows() {
        let report = printed(&Zone::new(&[]), "gone-shop.com");
        assert!(report.entities.is_empty(), "{:?}", report.entities);
        for source in ["crtsh", "dns"] {
            let row = report
                .outcomes
                .iter()
                .find(|outcome| outcome.module == source)
                .unwrap_or_else(|| panic!("a {source} outcome row"));
            assert_eq!(row.kind, SourceOutcomeKind::ValidZero, "{row:?}");
            assert_eq!(row.found, Some(0));
        }
    }

    /// When no source answers, the lookup fails with the first reason (exit 69, "no usable
    /// response"), or is a refusal (exit 77) when the egress policy refused a request. Before, it
    /// said "no results for domain" whatever the cause, which reads as a real zero.
    #[test]
    fn a_lookup_no_source_answered_fails_and_says_why() {
        let mut zone = Zone::published("example.com");
        zone.crtsh = None;
        zone.resolvers_down = true;
        match run(&zone, &Keys::default(), "example.com", 1) {
            DomainRun::Failed(message) => assert_eq!(
                message,
                "no source answered for domain example.com: crtsh: no response (DnsFailure)"
            ),
            DomainRun::Printed { text, .. } => panic!("printed: {text}"),
            DomainRun::Network(message) => panic!("network: {message}"),
        }

        match run(&Refusing, &Keys::default(), "example.com", 1) {
            DomainRun::Network(message) => {
                assert!(message.starts_with("crtsh: request refused: "), "{message}");
            }
            DomainRun::Printed { text, .. } => panic!("printed: {text}"),
            DomainRun::Failed(message) => panic!("failed: {message}"),
        }
    }

    /// crt.sh refused before sending is a `refused_before_sending` row whose detail names the
    /// refusal, not the `entitlement_denied` it used to read as.
    #[test]
    fn a_refused_crtsh_leg_is_a_refused_before_sending_row() {
        let mut found = Report::default();
        let line = crtsh_leg(&Refusing, "example.com", "scan", 1, &mut found);
        assert!(line.starts_with("crtsh: refused ("), "{line}");
        assert_eq!(found.outcomes.len(), 1);
        assert_eq!(
            found.outcomes[0].kind,
            SourceOutcomeKind::RefusedBeforeSending
        );
        assert!(
            found.outcomes[0]
                .detail
                .as_deref()
                .is_some_and(|d| d.starts_with("crtsh: request refused: ")),
            "{:?}",
            found.outcomes[0].detail
        );
    }

    /// A name in a namespace with registrant rules carries them, offline, beside what the
    /// sources found; a name in an open namespace carries none; and the rules never turn a
    /// lookup no source answered into a result.
    #[test]
    fn a_restricted_namespace_carries_its_registrant_rule() {
        let domain = "health.nsw.gov.au";
        let report = printed(&Zone::new(&[(domain, "A", IPV4)]), domain);
        let apex = entity(&report, &EntityKind::Domain, domain).expect("the domain");
        assert!(apex.has_tag("registrant:government"));
        let policy = apex
            .evidence
            .iter()
            .find(|evidence| evidence.provenance.source == REGISTRY_POLICY_SOURCE)
            .expect("the registry's rule");
        assert!(policy.attr_values("registrant_state").eq(["NSW"]));
        assert!(
            policy.summary.contains("government body"),
            "{}",
            policy.summary
        );

        let domain = "example.edu.vn";
        let report = printed(&Zone::new(&[(domain, "A", IPV4)]), domain);
        let apex = entity(&report, &EntityKind::Domain, domain).expect("the domain");
        assert!(apex.has_tag("registrant:education"));

        let report = printed(&Zone::published("example.com"), "example.com");
        assert!(report.entities.iter().all(|entity| {
            entity
                .evidence
                .iter()
                .all(|evidence| evidence.provenance.source != REGISTRY_POLICY_SOURCE)
        }));

        let mut zone = Zone::published("example.gov.au");
        zone.crtsh = None;
        zone.resolvers_down = true;
        assert!(matches!(
            run(&zone, &Keys::default(), "example.gov.au", 1),
            DomainRun::Failed(_)
        ));
    }
}
