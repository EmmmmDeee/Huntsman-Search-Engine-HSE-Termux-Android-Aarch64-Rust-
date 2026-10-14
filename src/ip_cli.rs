//! End-to-end front-end for `huntsman-recon ip` and the ip arm of `scan`.
//!
//! Runs the IP legs in order for one public address: Shodan `InternetDB` (open ports, hostnames,
//! CPEs, known CVEs), `RIPEstat` (covering prefix and origin AS), `GreyNoise` Community (internet
//! scanner or benign service), then the keyed legs whose key is configured: `AbuseIPDB` (abuse
//! reports) and `VirusTotal` (engine verdicts), then every IP source in
//! [`crate::indicator_legs::SOURCES`] (Shodan, Pulsedive, Netlas, OTX, urlscan.io, `IPinfo`, `LeakIX`, `ThreatFox`, `URLhaus`,
//! `IPQualityScore`). Each leg adds evidence to the one address entity; hostnames, origin AS
//! numbers, their holders and the network's domain become pivots. A configured key always runs
//! its leg.
//!
//! A private, loopback, documentation or otherwise non-public address is refused before any
//! request: nothing public is known about it, and asking would only disclose it.

use std::path::PathBuf;

use crate::abuseipdb;
use crate::api_leg::{Api, LegError};
use crate::canonical::{canonical_domain, canonical_ip};
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
use crate::source_outcome::SourceExecutionOutcome;
use crate::tags;
use crate::virustotal;

pub const IP_USAGE: &str = "usage: huntsman-recon ip ADDRESS [--save FILE]";
pub const IP_HELP: &str = "\
ip ADDRESS [--save FILE]
Look up one public IPv4 or IPv6 address: open ports, hostnames, CPEs and known CVEs from Shodan InternetDB, the covering prefix and origin AS from RIPEstat, internet-scanner status from GreyNoise Community threat risk from Pulsedive, scan data from Netlas, threat pulses from AlienVault OTX, public page scans from urlscan.io and hostname, network and city from IPinfo, all keyless. With HUNTSMAN_ABUSEIPDB_KEY set it adds AbuseIPDB abuse reports, with HUNTSMAN_VIRUSTOTAL_KEY VirusTotal engine verdicts, with HUNTSMAN_SHODAN_KEY Shodan services, with HUNTSMAN_LEAKIX_KEY LeakIX exposed services and leaks, with HUNTSMAN_THREATFOX_KEY ThreatFox IOCs, with HUNTSMAN_ABUSECH_KEY URLhaus malware URLs, and with HUNTSMAN_IPQS_KEY the IPQualityScore fraud score and proxy/VPN flags; HUNTSMAN_GREYNOISE_KEY, HUNTSMAN_PULSEDIVE_KEY and HUNTSMAN_NETLAS_KEY raise those limits. A leg whose key is not set makes no request, and a key that is set always runs its leg. A private, loopback, documentation or other non-public address is refused before any request. --save FILE writes an unverified ledger that verify can reload. Makes network requests.";

/// Confidence of the queried address itself.
const SEED_CONFIDENCE: f64 = 0.90;
/// Confidence of a pivot a provider attributes to the address.
const PIVOT_CONFIDENCE: f64 = 0.60;

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
        let LookupTokens { positional, save } = LookupTokens::split(args)?;
        if positional.len() != 1 {
            return Err(Error::Invalid("ip needs exactly one ADDRESS".into()));
        }
        let ip = canonical_ip(&positional[0])
            .ok_or_else(|| Error::invalid_value("not a public IP address"))?;
        Ok(Self { ip, save })
    }
}

pub enum IpRun {
    Printed { text: String, report: Report },
    Network(String),
    Failed(String),
}

/// One leg's result, folded into the report.
struct Lookup<'a> {
    ip: &'a str,
    scan_id: &'a str,
    now_unix: u64,
    report: Report,
    network: Option<String>,
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
        if let LegError::Transport(_) = err {
            self.network
                .get_or_insert_with(|| format!("{}: {err}", api.source));
        }
        self.report.outcomes.push(err.outcome(api, self.now_unix));
    }
}

/// Run every IP leg for `ip`. Keyed legs run only when `keys` holds their key.
#[must_use]
pub fn run<T: Transport + ?Sized>(transport: &T, keys: &Keys, ip: &str, now_unix: u64) -> IpRun {
    let Some(ip) = canonical_ip(ip) else {
        return IpRun::Failed("not a public IP address".into());
    };
    let scan_id = crate::entity::scan_id("ip", &ip);
    let mut lookup = Lookup {
        ip: &ip,
        scan_id: &scan_id,
        now_unix,
        report: Report::default(),
        network: None,
    };

    match internetdb::lookup(transport, &ip, now_unix) {
        Ok(Some(host)) => internetdb_leg(&mut lookup, &host),
        Ok(None) => lookup.nothing(&internetdb::API),
        Err(err) => lookup.failed(&internetdb::API, &err),
    }
    match ripestat::lookup(transport, &ip, now_unix) {
        Ok(routing) if routing.origins.is_empty() => lookup.nothing(&ripestat::API),
        Ok(routing) => ripestat_leg(&mut lookup, &routing),
        Err(err) => lookup.failed(&ripestat::API, &err),
    }
    match greynoise::lookup(transport, keys, &ip, now_unix) {
        Ok(Some(sighting)) => greynoise_leg(&mut lookup, &sighting),
        Ok(None) => lookup.nothing(&greynoise::API),
        Err(err) => lookup.failed(&greynoise::API, &err),
    }
    if abuseipdb::API.wanted(keys) {
        match abuseipdb::lookup(transport, keys, &ip, now_unix) {
            Ok(check) => abuseipdb_leg(&mut lookup, &check),
            Err(err) => lookup.failed(&abuseipdb::API, &err),
        }
    }
    if virustotal::API.wanted(keys) {
        match virustotal::lookup(transport, keys, virustotal::Object::Ip, &ip, now_unix) {
            Ok(Some(report)) => virustotal_leg(&mut lookup, &report),
            Ok(None) => lookup.nothing(&virustotal::API),
            Err(err) => lookup.failed(&virustotal::API, &err),
        }
    }

    let legs = indicator_legs::run(transport, keys, Indicator::Ip(&ip), &scan_id, now_unix);
    let Lookup {
        mut report,
        mut network,
        ..
    } = lookup;
    report.entities.extend(legs.entities);
    report.outcomes.extend(legs.outcomes);
    network = network.or(legs.network);
    merge_by_uid(&mut report.entities);
    let collected = report.outcomes.iter().any(|o| o.kind.is_accepted());
    if !collected {
        return match network {
            Some(message) => IpRun::Network(message),
            None => IpRun::Failed(format!("no source answered for ip {ip}")),
        };
    }
    match lookup_report::render(&report.entities, &report.outcomes) {
        Ok(text) => IpRun::Printed { text, report },
        Err(message) => IpRun::Failed(message),
    }
}

fn join<T: ToString>(items: &[T]) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
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
    let asns: Vec<String> = routing
        .origins
        .iter()
        .map(|o| format!("AS{}", o.asn))
        .collect();
    let evidence = lookup
        .evidence(api, format!("Announced by {}", asns.join(", ")))
        .with_attr("origin_asns", asns.join(","))
        .with_optional_attrs([
            ("prefix", routing.prefix.as_deref()),
            ("registry_block", routing.block.as_deref()),
        ]);
    lookup.on_address(evidence, &[]);
    for origin in &routing.origins {
        let asn = format!("AS{}", origin.asn);
        let evidence = lookup
            .evidence(api, "Origin AS of the prefix covering the address")
            .with_attr("ip", lookup.ip)
            .with_optional_attrs([
                ("prefix", routing.prefix.as_deref()),
                ("holder", origin.holder.as_deref()),
            ]);
        lookup.pivot(EntityKind::Asn, &asn, evidence);
        if let Some(holder) = origin.holder.as_deref() {
            let evidence = lookup
                .evidence(api, format!("Holder of {asn}"))
                .with_attr("asn", &asn);
            lookup.pivot(EntityKind::Organisation, holder, evidence);
        }
    }
    lookup.found(api, routing.origins.len());
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
        ]);
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
        tags.push("tor-exit");
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
        ]);
    if let Some(allow_listed) = check.allow_listed {
        evidence = evidence.with_attr("allow_listed", allow_listed.to_string());
    }
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
    lookup.on_address(evidence, tags);
    lookup.found(api, 1);
}

#[cfg(test)]
mod tests;
