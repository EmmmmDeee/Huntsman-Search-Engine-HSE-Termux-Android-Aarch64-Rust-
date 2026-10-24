//! End-to-end front-end for `huntsman-recon ip` and the ip arm of `scan`.
//!
//! Runs the IP legs in order for one public address: reverse DNS (the PTR records of the address,
//! as Spiderfoot's `sfp_dnsresolve` asks), the network's RDAP registration (see
//! [`crate::rdap_legs`]), Mnemonic passive DNS (every record its sensors saw with the address; see
//! [`crate::mnemonic`]), Shodan `InternetDB` (open ports, hostnames, CPEs, known CVEs), `RIPEstat`
//! (covering prefix and origin AS), `GreyNoise` Community (internet
//! scanner or benign service), then the keyed legs whose key is configured: `AbuseIPDB` (abuse
//! reports) and `VirusTotal` (engine verdicts), then every IP source in
//! [`crate::indicator_legs::SOURCES`] (Shodan, Pulsedive, Netlas, OTX, urlscan.io, `IPinfo`, Robtex,
//! `HackerTarget`, `StopForumSpam`, `LeakIX`, `ThreatFox`, `URLhaus`,
//! `IPQualityScore`). Each leg adds evidence to the one address entity; hostnames, origin AS
//! numbers, their holders and the network's domain become pivots. A configured key always runs
//! its leg.
//!
//! A private, loopback, documentation or otherwise non-public address is refused before any
//! request: nothing public is known about it, and asking would only disclose it.
//!
//! When no source answered, the lookup ends from its rows through
//! [`crate::source_outcome::SourceReach`]: a request refused before sending is a refusal (exit
//! 77), otherwise no usable response (exit 69); any source that answered makes it print.

use std::net::IpAddr;
use std::path::PathBuf;

use crate::abuseipdb;
use crate::address_au::AuNetworkKind;
use crate::api_leg::{Api, LegError};
use crate::canonical::{canonical_domain, canonical_ip};
use crate::dns::{self, RESOLVE_SOURCE, ResolveErrorKind};
use crate::dnsbl::{self, Subject};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::greynoise;
use crate::http::Transport;
use crate::indicator_legs;
use crate::indicator_sources::Indicator;
use crate::internetdb;
use crate::keys::Keys;
use crate::lookup_args::LookupTokens;
use crate::lookup_report;
use crate::ripestat;
use crate::source_outcome::{SourceExecutionOutcome, SourceReach, SourceRun};
use crate::tags;
use crate::threat_feeds::{self, Feeds};
use crate::virustotal;

pub const IP_USAGE: &str = "usage: huntsman-recon ip ADDRESS [--save FILE]";
pub const IP_HELP: &str = "\
ip ADDRESS [--save FILE]
Look up one public IPv4 or IPv6 address: the names its PTR records carry, its network's RDAP registration (range, holder, contacts and the record as published), the names Mnemonic passive DNS saw answering with the address, open ports, hostnames, CPEs and known CVEs from Shodan InternetDB, the covering prefix and origin AS from RIPEstat (and whether an Australian consumer provider or AARNet holds that AS), internet-scanner status from GreyNoise Community (IPv4 only), threat risk from Pulsedive, scan data from Netlas, threat pulses from AlienVault OTX, public page scans from urlscan.io, hostname, network and city from IPinfo, the route and passive DNS names from Robtex, domains hosted on the address from HackerTarget, forum-spam reports from StopForumSpam, and listings on the Spamhaus ZEN, SpamCop, UCEPROTECT, DroneBL, SORBS and SURBL blocklists over the system resolver, all keyless. The address and every name the lookup found are checked against the threat feeds Spiderfoot downloads (abuse.ch Feodo Tracker and URLhaus, AlienVault IP Reputation, blocklist.de, botvrij.eu, CINS Army, CoinBlocker, CyberCrime-Tracker, Emerging Threats, GreenSnow, OpenPhish, PhishTank, Steven Black's hosts, Tor's exit relays, VoIPBL and VXVault), each downloaded once and kept in $HUNTSMAN_HOME/feeds, else ~/.huntsman/feeds, until it is older than Spiderfoot keeps it. With HUNTSMAN_ABUSEIPDB_KEY set it adds AbuseIPDB abuse reports, with HUNTSMAN_VIRUSTOTAL_KEY VirusTotal engine verdicts, with HUNTSMAN_SHODAN_KEY Shodan services, with HUNTSMAN_LEAKIX_KEY LeakIX exposed services and leaks, with HUNTSMAN_THREATFOX_KEY ThreatFox IOCs, with HUNTSMAN_ABUSECH_KEY URLhaus malware URLs (IPv4 only), and with HUNTSMAN_IPQS_KEY the IPQualityScore fraud score and proxy/VPN flags; HUNTSMAN_GREYNOISE_KEY, HUNTSMAN_PULSEDIVE_KEY and HUNTSMAN_NETLAS_KEY raise those limits. A leg whose key is not set makes no request, and a key that is set always runs its leg. A private, loopback, documentation or other non-public address is refused before any request. --save FILE writes an unverified ledger that verify can reload. Makes network requests.";

/// Confidence of the queried address itself.
const SEED_CONFIDENCE: f64 = 0.90;
/// Confidence of a pivot a provider attributes to the address.
const PIVOT_CONFIDENCE: f64 = 0.60;
/// Confidence of a name the address's own reverse zone publishes: its operator named it, though
/// the name is not checked to resolve back.
const PTR_CONFIDENCE: f64 = 0.80;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpArgs {
    pub ip: String,
    pub save: Option<PathBuf>,
}

impl IpArgs {
    /// # Errors
    /// A missing or repeated address, an unknown option, or a value that is not a public address.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let (raw, save) = LookupTokens::single(args, "ip needs exactly one ADDRESS")?;
        let ip =
            canonical_ip(&raw).ok_or_else(|| Error::invalid_value("not a public IP address"))?;
        Ok(Self { ip, save })
    }
}

pub type IpRun = SourceRun<Report>;

/// One leg's result, folded into the report. How the lookup ends when no leg answered is decided
/// from the rows by [`SourceReach`], not from a side channel.
struct Lookup<'a> {
    ip: &'a str,
    scan_id: &'a str,
    now_unix: u64,
    report: Report,
}

impl Lookup<'_> {
    fn evidence(&self, api: &Api, summary: impl Into<String>) -> Evidence {
        Evidence::new(
            EvidenceProvenance::for_scan(api.source, self.scan_id),
            summary,
        )
    }

    /// Evidence on the address itself, with its tags.
    fn on_address(&mut self, evidence: Evidence, tags: &[&str]) {
        push_entity(
            &mut self.report.entities,
            EntityKind::IpAddress,
            self.ip,
            SEED_CONFIDENCE,
            self.scan_id,
            evidence,
            tags,
        );
    }

    fn pivot(&mut self, kind: EntityKind, value: &str, evidence: Evidence) {
        push_entity(
            &mut self.report.entities,
            kind,
            value,
            PIVOT_CONFIDENCE,
            self.scan_id,
            evidence,
            &[],
        );
    }

    fn hostname(&mut self, api: &Api, host: &str, summary: &str) {
        if let Some(domain) = canonical_domain(host) {
            let evidence = self.evidence(api, summary).with_attr("ip", self.ip);
            self.pivot(EntityKind::Domain, &domain, evidence);
        }
    }

    fn found(&mut self, api: &Api, count: usize) {
        self.report.outcomes.push(
            SourceExecutionOutcome::success(api.source, self.now_unix, count).with_http_status(200),
        );
    }

    fn nothing(&mut self, api: &Api) {
        self.report
            .outcomes
            .push(SourceExecutionOutcome::valid_zero(
                api.source,
                self.now_unix,
            ));
    }

    fn failed(&mut self, api: &Api, err: &LegError) {
        self.report.outcomes.push(err.outcome(api, self.now_unix));
    }
}

/// Run every IP leg for `ip`, then check it and everything the legs found against the threat
/// `feeds`. Keyed legs run only when `keys` holds their key, and each leg only when the
/// transport's lookup asks its module ([`Transport::runs_module`]).
#[must_use]
pub fn run<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    feeds: &Feeds,
    ip: &str,
    now_unix: u64,
) -> IpRun {
    let Some(ip) = canonical_ip(ip) else {
        return IpRun::Failed("not a public IP address".into());
    };
    let scan_id = crate::entity::scan_id("ip", &ip);
    let mut lookup = Lookup {
        ip: &ip,
        scan_id: &scan_id,
        now_unix,
        report: Report::default(),
    };

    if transport.runs_module(RESOLVE_SOURCE) {
        ptr_leg(transport, &mut lookup);
    }
    let registration = crate::rdap_legs::ip(transport, &ip, &scan_id, now_unix);
    lookup.report.entities.extend(registration.entities);
    lookup.report.outcomes.extend(registration.outcome);
    let seen = crate::mnemonic::ip(transport, &ip, &scan_id, now_unix);
    mnemonic_leg(&mut lookup, seen);
    if internetdb::API.runs(transport, keys) {
        match internetdb::lookup(transport, &ip, now_unix) {
            Ok(Some(host)) => internetdb_leg(&mut lookup, &host),
            Ok(None) => lookup.nothing(&internetdb::API),
            Err(err) => lookup.failed(&internetdb::API, &err),
        }
    }
    if ripestat::API.runs(transport, keys) {
        // Both calls run whatever the other returns, so a failed call costs the other nothing.
        let routing = ripestat::lookup(transport, &ip, now_unix);
        let place = ripestat::geolocation(transport, &ip, now_unix);
        if let Ok(place) = &place {
            ripestat_place_leg(&mut lookup, place);
        }
        match routing {
            Ok(routing) => ripestat_leg(&mut lookup, &routing),
            Err(err) => lookup.failed(&ripestat::API, &err),
        }
        if let Err(err) = &place {
            lookup.failed(&ripestat::API, err);
        }
    }
    if greynoise::answers_for(&ip) && greynoise::API.runs(transport, keys) {
        match greynoise::lookup(transport, keys, &ip, now_unix) {
            Ok(Some(sighting)) => greynoise_leg(&mut lookup, &sighting),
            Ok(None) => lookup.nothing(&greynoise::API),
            Err(err) => lookup.failed(&greynoise::API, &err),
        }
    }
    if let Ok(address) = ip.parse() {
        let (listed, rows) = dnsbl::check(transport, Subject::Address(address), &scan_id, now_unix);
        lookup.report.entities.extend(listed);
        lookup.report.outcomes.extend(rows);
    }
    if abuseipdb::API.runs(transport, keys) {
        match abuseipdb::lookup(transport, keys, &ip, now_unix) {
            Ok(check) => abuseipdb_leg(&mut lookup, &check),
            Err(err) => lookup.failed(&abuseipdb::API, &err),
        }
    }
    if virustotal::API.runs(transport, keys) {
        match virustotal::lookup(transport, keys, virustotal::Object::Ip, &ip, now_unix) {
            Ok(Some(report)) => virustotal_leg(&mut lookup, &report),
            Ok(None) => lookup.nothing(&virustotal::API),
            Err(err) => lookup.failed(&virustotal::API, &err),
        }
    }

    let legs = indicator_legs::run(transport, keys, Indicator::Ip(&ip), &scan_id, now_unix);
    let Lookup { mut report, .. } = lookup;
    report.entities.extend(legs.entities);
    report.outcomes.extend(legs.outcomes);
    if let Ok(address) = ip.parse() {
        threat_feeds::check_found(
            feeds,
            threat_feeds::Subject::Address(address),
            &mut report.entities,
            &mut report.outcomes,
            &scan_id,
            now_unix,
        );
    }
    merge_by_uid(&mut report.entities);
    // The CLI's exit codes (ARCHITECTURE.md): a request refused before sending is 77, no usable
    // response 69. One authority reads the rows: no accepted row and one refused is a refusal,
    // else the first transport failure or other reason is "no source answered".
    if let Some(run) =
        SourceReach::of(&report.outcomes).unanswered(&format!("no source answered for ip {ip}"))
    {
        return run;
    }
    match lookup_report::render(&report.entities, &report.outcomes) {
        Ok(text) => IpRun::Printed { text, report },
        Err(message) => IpRun::Failed(message),
    }
}

/// Reverse DNS over the `DoH` resolvers and the lookup's transport, as Spiderfoot's
/// `sfp_dnsresolve` reverse-resolves every address: the address's evidence lists each PTR record
/// as published under `ptr`, and each name in canonical form is a domain pivot whose evidence
/// names the address. No PTR record is a validated zero.
fn ptr_leg<T: Transport + ?Sized>(transport: &T, lookup: &mut Lookup<'_>) {
    let Ok(address) = lookup.ip.parse::<IpAddr>() else {
        return;
    };
    let outcome = match dns::lookup_ptr(transport, address) {
        Ok(answer) => {
            let found = reverse(lookup.ip, &answer, lookup.scan_id);
            lookup.on_address(found.address, &[]);
            for (domain, evidence) in found.names {
                push_entity(
                    &mut lookup.report.entities,
                    EntityKind::Domain,
                    &domain,
                    PTR_CONFIDENCE,
                    lookup.scan_id,
                    evidence,
                    &[tags::PTR],
                );
            }
            SourceExecutionOutcome::success(RESOLVE_SOURCE, lookup.now_unix, answer.records.len())
        }
        Err(error) if error.kind == ResolveErrorKind::Empty => {
            SourceExecutionOutcome::valid_zero(RESOLVE_SOURCE, lookup.now_unix)
        }
        Err(error) => SourceExecutionOutcome::failed(
            RESOLVE_SOURCE,
            lookup.now_unix,
            error.kind.outcome_kind(),
            None,
            format!(
                "no resolver answered the PTR query: {}: {}",
                error.kind.as_str(),
                error.detail
            ),
        ),
    };
    lookup.report.outcomes.push(outcome);
}

/// What an address's PTR records say: the address's evidence, listing every record as published,
/// and each name in canonical form with evidence that names the address.
pub(crate) struct Reverse {
    pub address: Evidence,
    pub names: Vec<(String, Evidence)>,
}

/// The evidence a PTR answer for `ip` makes. **Pure.**
pub(crate) fn reverse(ip: &str, answer: &dns::ResolveAnswer, scan_id: &str) -> Reverse {
    let resolver = answer.server.provider;
    let evidence = |summary: String| {
        Evidence::new(
            EvidenceProvenance::for_scan(RESOLVE_SOURCE, scan_id),
            summary,
        )
        .with_attr("record_type", "PTR")
        .with_attr("resolver", resolver)
    };
    let mut address = evidence(format!("PTR records of {ip}"));
    let mut names = Vec::new();
    for record in &answer.records {
        let name = record.trim().trim_end_matches('.');
        address = address.with_attr("ptr", name);
        if let Some(domain) = canonical_domain(name) {
            names.push((
                domain,
                evidence(format!("PTR record of {ip}")).with_attr("ip", ip),
            ));
        }
    }
    Reverse { address, names }
}

fn join<T: ToString>(items: &[T]) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Mnemonic's passive DNS: its entities and its outcome row. A refused or silent leg's row carries
/// the reason, which [`SourceReach`] reads when no leg answered.
fn mnemonic_leg(lookup: &mut Lookup<'_>, seen: crate::mnemonic::Leg) {
    lookup.report.entities.extend(seen.entities);
    lookup.report.outcomes.extend(seen.outcome);
}

fn internetdb_leg(lookup: &mut Lookup<'_>, host: &internetdb::Host) {
    let api = &internetdb::API;
    let mut tags = Vec::new();
    if !host.vulns.is_empty() {
        tags.push(tags::VULNERABLE);
    }
    let mut evidence = lookup.evidence(
        api,
        format!(
            "Shodan InternetDB: {} open port(s), {} known CVE(s)",
            host.ports.len(),
            host.vulns.len()
        ),
    );
    for (key, values) in [
        ("cpes", host.cpes.join(",")),
        ("tags", host.tags.join(",")),
        ("vulns", host.vulns.join(",")),
        ("ports", join(&host.ports)),
    ] {
        if !values.is_empty() {
            evidence = evidence.with_attr(key, values);
        }
    }
    lookup.on_address(evidence, &tags);
    for name in &host.hostnames {
        lookup.hostname(
            api,
            name,
            "Hostname Shodan InternetDB records for the address",
        );
    }
    lookup.found(api, 1 + host.hostnames.len());
}

fn ripestat_leg(lookup: &mut Lookup<'_>, routing: &ripestat::Routing) {
    let api = &ripestat::API;
    if !routing.says_anything() {
        lookup.nothing(api);
        return;
    }
    let evidence = routing.attributes().into_iter().fold(
        lookup.evidence(api, routing.summary()),
        |evidence, (key, value)| evidence.with_attr(key, value),
    );
    lookup.on_address(evidence, &[]);
    for origin in routing.public_origins() {
        let asn = format!("AS{}", origin.asn);
        let evidence = lookup
            .evidence(api, "Origin AS of the prefix covering the address")
            .with_attr("ip", lookup.ip)
            .with_optional_attrs([
                ("prefix", routing.prefix.as_deref()),
                ("holder", origin.holder.as_deref()),
            ]);
        lookup.pivot(EntityKind::Asn, &asn, evidence);
        if let Some((operator, kind)) = origin.holder.as_deref().and_then(au_operator) {
            let (summary, tag) = match kind {
                AuNetworkKind::Consumer => (
                    format!("{asn} is {operator}'s, an Australian consumer internet provider"),
                    tags::AU_CONSUMER_ISP,
                ),
                AuNetworkKind::Academic => (
                    format!("{asn} is {operator}'s, Australia's research and education network"),
                    tags::AU_ACADEMIC_NETWORK,
                ),
            };
            let evidence = lookup
                .evidence(api, summary)
                .with_attr("asn", &asn)
                .with_attr("network_operator", operator);
            lookup.on_address(evidence, &[tag]);
        }
        if let Some(holder) = origin.holder.as_deref() {
            let evidence = lookup
                .evidence(api, format!("Holder of {asn}"))
                .with_attr("asn", &asn);
            lookup.pivot(EntityKind::Organisation, holder, evidence);
        }
    }
    lookup.found(api, routing.origins.len().max(1));
}

/// The Australian operator an origin AS holder names. `RIPEstat` writes a holder as
/// `HANDLE - Name` (`ASN-TELSTRA - Telstra Limited`): the handle is structured, the name free
/// text, so a common word such as `belong` names an operator only in the handle. **Pure.**
fn au_operator(holder: &str) -> Option<(&'static str, AuNetworkKind)> {
    let (handle, name) = holder.split_once(" - ").unwrap_or(("", holder));
    crate::address_au::au_network_operator_split(handle, name)
}

/// Where `RIPEstat` places the address, as one record on it. Its outcome is the routing leg's, so
/// a place adds no outcome row of its own.
fn ripestat_place_leg(lookup: &mut Lookup<'_>, place: &ripestat::Geolocation) {
    if !place.says_anything() {
        return;
    }
    let evidence = lookup
        .evidence(&ripestat::API, "Where RIPEstat places the address")
        .with_attr("locations", place.summary());
    lookup.on_address(evidence, &[]);
}

fn greynoise_leg(lookup: &mut Lookup<'_>, sighting: &greynoise::Sighting) {
    let api = &greynoise::API;
    let mut tags = Vec::new();
    if sighting.noise {
        tags.push("internet-scanner");
    }
    if sighting.riot {
        tags.push("benign-service");
    }
    if sighting.classification.as_deref() == Some("malicious") {
        tags.push(tags::MALICIOUS);
    }
    let summary = match (sighting.noise, sighting.riot) {
        (true, _) => "GreyNoise: seen scanning the internet",
        (false, true) => "GreyNoise: known benign business service",
        (false, false) => "GreyNoise: known to GreyNoise, not scanning",
    };
    let evidence = lookup
        .evidence(api, summary)
        .with_attr("noise", sighting.noise.to_string())
        .with_attr("riot", sighting.riot.to_string())
        .with_optional_attrs([
            ("classification", sighting.classification.as_deref()),
            ("name", sighting.name.as_deref()),
            ("last_seen", sighting.last_seen.as_deref()),
            ("link", sighting.link.as_deref()),
            ("message", sighting.message.as_deref()),
        ])
        .with_attr("raw_answer", sighting.raw_answer.as_str());
    lookup.on_address(evidence, &tags);
    lookup.found(api, 1);
}

fn abuseipdb_leg(lookup: &mut Lookup<'_>, check: &abuseipdb::Check) {
    let api = &abuseipdb::API;
    let mut tags = Vec::new();
    if check.confidence >= 50 {
        tags.push(tags::MALICIOUS);
    }
    if check.tor {
        tags.push(tags::TOR_EXIT);
    }
    let mut evidence = lookup
        .evidence(
            api,
            format!(
                "AbuseIPDB: abuse confidence {}%, {} report(s) in {} days",
                check.confidence,
                check.total_reports,
                abuseipdb::MAX_AGE_DAYS
            ),
        )
        .with_attr("abuse_confidence", check.confidence.to_string())
        .with_attr("total_reports", check.total_reports.to_string())
        .with_attr("distinct_reporters", check.distinct_reporters.to_string())
        .with_attr("tor", check.tor.to_string())
        .with_optional_attrs([
            ("last_reported", check.last_reported.as_deref()),
            ("country", check.country.as_deref()),
            ("usage_type", check.usage_type.as_deref()),
            ("isp", check.isp.as_deref()),
            ("network_domain", check.domain.as_deref()),
            ("country_name", check.country_name.as_deref()),
        ]);
    if let Some(allow_listed) = check.allow_listed {
        evidence = evidence.with_attr("allow_listed", allow_listed.to_string());
    }
    if let Some(public) = check.public {
        evidence = evidence.with_attr("public", public.to_string());
    }
    if let Some(version) = check.ip_version {
        evidence = evidence.with_attr("ip_version", version.to_string());
    }
    for category in &check.categories {
        evidence = evidence.with_attr("report_categories", category.as_str());
    }
    for report in &check.reports {
        evidence = evidence.with_attr("reports", report.as_str());
    }
    if check.reports_unread {
        evidence = evidence.with_attr(
            "reports_unread",
            "the answer with every report is past the body limit",
        );
    }
    let evidence = evidence.with_attr("raw_answer", check.raw_answer.as_str());
    lookup.on_address(evidence, &tags);
    if let Some(domain) = check.domain.as_deref() {
        lookup.hostname(
            api,
            domain,
            "Domain AbuseIPDB gives for the address's network",
        );
    }
    for name in &check.hostnames {
        lookup.hostname(api, name, "Hostname AbuseIPDB records for the address");
    }
    lookup.found(api, 1);
}

fn virustotal_leg(lookup: &mut Lookup<'_>, report: &virustotal::Report) {
    let api = &virustotal::API;
    let tags: &[&str] = if report.malicious > 0 {
        &[tags::MALICIOUS]
    } else {
        &[]
    };
    let mut evidence = lookup
        .evidence(
            api,
            format!(
                "VirusTotal: {} of {} engines flag the address",
                report.flagged(),
                report.flagged() + report.harmless + report.undetected
            ),
        )
        .with_attr("malicious", report.malicious.to_string())
        .with_attr("suspicious", report.suspicious.to_string())
        .with_attr("reputation", report.reputation.to_string())
        .with_optional_attrs([
            ("as_owner", report.as_owner.as_deref()),
            ("network", report.network.as_deref()),
            ("country", report.country.as_deref()),
        ]);
    if let Some(asn) = report.asn {
        evidence = evidence.with_attr("asn", format!("AS{asn}"));
    }
    if !report.categories.is_empty() {
        evidence = evidence.with_attr("categories", report.categories.join(","));
    }
    for (name, value) in &report.details {
        evidence = evidence.with_attr(name.as_str(), value.as_str());
    }
    lookup.on_address(
        evidence.with_attr("raw_answer", report.raw_answer.as_str()),
        tags,
    );
    for (role, name) in &report.hosts {
        let summary = if role == "certificate" {
            "Name on the HTTPS certificate VirusTotal last saw at the address".to_owned()
        } else {
            format!(
                "{} record VirusTotal last saw for the address",
                role.to_ascii_uppercase()
            )
        };
        lookup.hostname(api, name, &summary);
    }
    lookup.found(api, 1);
}

#[cfg(test)]
mod tests;
