//! End-to-end front-end for `huntsman-recon network`, the network arm of `scan`, and the IP,
//! netblock and AS targets of `sf`.
//!
//! An IP target gets reverse DNS (`dns`) and its Team Cymru origin prefix and AS (`cymru`); a
//! netblock target gets the origin of its network address; an AS target gets its registration.
//! Every source runs over the injected transport through the `DoH` pool and reports its own
//! outcome: one failing source is recorded and the rest still answer, and the run is
//! unavailable only when no source answered.

use std::net::IpAddr;
use std::path::PathBuf;

use crate::cymru;
use crate::dns::{self, ResolveError, ResolveErrorKind};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::error::Error;
use crate::http::Transport;
use crate::lookup_args::LookupTokens;
use crate::lookup_report;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const NETWORK_USAGE: &str = "usage: huntsman-recon network IP|CIDR|ASN [--save FILE]";

pub const NETWORK_HELP: &str = "network IP|CIDR|ASN [--save FILE]
Map an IPv4/IPv6 address, a CIDR netblock, or an AS number (AS13335 or ASN13335) through
DNS-over-HTTPS: reverse DNS for an address, and Team Cymru's announced prefix and origin AS for
an address or netblock, or the registration of an AS. Each source reports its own outcome; the
run fails (69) only when no source answered. --save writes an unverified ledger verify reloads.";

/// One parsed network selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkTarget {
    Ip(IpAddr),
    /// Network address (host bits cleared) and prefix length.
    Netblock(IpAddr, u8),
    Asn(u32),
}

impl NetworkTarget {
    /// An IP address, a CIDR netblock, or `AS<n>`/`ASN<n>` (case-insensitive, `n` > 0).
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if let Ok(ip) = raw.parse::<IpAddr>() {
            return Some(Self::Ip(ip));
        }
        if raw.contains('/') {
            return cymru::parse_prefix(raw).map(|(network, bits)| Self::Netblock(network, bits));
        }
        let upper = raw.to_ascii_uppercase();
        let digits = upper
            .strip_prefix("ASN")
            .or_else(|| upper.strip_prefix("AS"))?;
        if digits.is_empty() || digits.len() > 10 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        digits
            .parse::<u32>()
            .ok()
            .filter(|asn| *asn != 0)
            .map(Self::Asn)
    }

    /// The canonical selector text: `192.0.2.1`, `192.0.2.0/24`, `AS64500`.
    #[must_use]
    pub fn canonical(&self) -> String {
        match self {
            Self::Ip(ip) => ip.to_string(),
            Self::Netblock(network, bits) => format!("{network}/{bits}"),
            Self::Asn(asn) => format!("AS{asn}"),
        }
    }

    fn kind(&self) -> EntityKind {
        match self {
            Self::Ip(_) => EntityKind::IpAddress,
            Self::Netblock(..) => EntityKind::Netblock,
            Self::Asn(_) => EntityKind::Asn,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkArgs {
    pub target: String,
    pub save: Option<PathBuf>,
}

impl NetworkArgs {
    /// # Errors
    /// A missing or invalid target, repeated `--save`, or an unknown option.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let LookupTokens { positional, save } = LookupTokens::split(args)?;
        if positional.len() != 1 {
            return Err(Error::Invalid(
                "network needs exactly one IP, CIDR or ASN".into(),
            ));
        }
        let target = NetworkTarget::parse(&positional[0])
            .ok_or_else(|| Error::invalid_value("not an IP address, CIDR netblock or AS number"))?;
        Ok(Self {
            target: target.canonical(),
            save,
        })
    }
}

pub enum NetworkRun {
    Printed {
        text: String,
        report: Report,
    },
    /// No source answered, so nothing is known about the target (not a zero result).
    Unavailable(String),
    Failed(String),
}

/// Parse `selector` and run [`run_target`].
#[must_use]
pub fn run<T: Transport + ?Sized>(transport: &T, selector: &str, now_unix: u64) -> NetworkRun {
    match NetworkTarget::parse(selector) {
        Some(target) => run_target(transport, target, now_unix),
        None => NetworkRun::Failed("not an IP address, CIDR netblock or AS number".into()),
    }
}

/// Look up one parsed target through every source that applies to it.
#[must_use]
pub fn run_target<T: Transport + ?Sized>(
    transport: &T,
    target: NetworkTarget,
    now_unix: u64,
) -> NetworkRun {
    let label = target.canonical();
    let scan_id = crate::entity::scan_id("network", &label);
    let mut seed = Entity::new(target.kind(), &label, 1.0, &scan_id);
    seed.add_evidence(Evidence::new(
        EvidenceProvenance::for_scan("seed", &scan_id),
        "scan target",
    ));
    let mut entities = vec![seed];
    let mut outcomes = Vec::new();
    let mut record = |module: &str, result: Result<Vec<Entity>, ResolveError>| match result {
        Ok(found) => {
            outcomes.push(if found.is_empty() {
                SourceExecutionOutcome::valid_zero(module, now_unix)
            } else {
                SourceExecutionOutcome::success(module, now_unix, found.len())
            });
            entities.extend(found);
        }
        Err(error) => outcomes.push(SourceExecutionOutcome::failed(
            module,
            now_unix,
            outcome_kind(error.kind),
            None,
            format!("{}: {}", error.kind.as_str(), error.detail),
        )),
    };
    match target {
        NetworkTarget::Ip(ip) => {
            record("dns", ptr_entities(transport, ip, &scan_id));
            record("cymru", origin_entities(transport, ip, &scan_id));
        }
        NetworkTarget::Netblock(network, _) => {
            record("cymru", origin_entities(transport, network, &scan_id));
        }
        NetworkTarget::Asn(asn) => record("cymru", as_entities(transport, asn, &scan_id)),
    }
    // Registry ownership from the RIR: the registrant, the allocated blocks, abuse contacts.
    let rdap = match target {
        NetworkTarget::Ip(ip) | NetworkTarget::Netblock(ip, _) => {
            crate::rdap::lookup_ip(transport, ip, &scan_id)
        }
        NetworkTarget::Asn(asn) => crate::rdap::lookup_autnum(transport, asn, &scan_id),
    };
    match rdap {
        Ok(report) => {
            outcomes.push(if report.entities.is_empty() {
                SourceExecutionOutcome::valid_zero("rdap", now_unix)
            } else {
                SourceExecutionOutcome::success("rdap", now_unix, report.entities.len())
            });
            entities.extend(report.entities);
        }
        Err(failure) => outcomes.push(SourceExecutionOutcome::failed(
            "rdap",
            now_unix,
            failure.kind,
            failure.http_status,
            format!("{}: {}", failure.kind.as_str(), failure.detail),
        )),
    }
    if !outcomes.iter().any(|outcome| outcome.kind.is_accepted()) {
        let failures: Vec<String> = outcomes
            .iter()
            .map(|o| format!("{}: {}", o.module, o.detail.as_deref().unwrap_or("failed")))
            .collect();
        return NetworkRun::Unavailable(format!(
            "no source answered for {label}: {}",
            failures.join("; ")
        ));
    }
    crate::entity::merge_by_uid(&mut entities);
    match lookup_report::render(&entities, &outcomes) {
        Ok(text) => NetworkRun::Printed {
            text,
            report: Report { entities, outcomes },
        },
        Err(message) => NetworkRun::Failed(message),
    }
}

/// The failed-source outcome for a resolver failure, in the shared taxonomy.
fn outcome_kind(kind: ResolveErrorKind) -> SourceOutcomeKind {
    match kind {
        ResolveErrorKind::Timeout => SourceOutcomeKind::TtfbTimeout,
        ResolveErrorKind::BotWaf => SourceOutcomeKind::BotWaf,
        ResolveErrorKind::RateLimited => SourceOutcomeKind::RateLimited,
        ResolveErrorKind::Upstream | ResolveErrorKind::Empty | ResolveErrorKind::Truncated => {
            SourceOutcomeKind::Inconclusive
        }
    }
}

fn ptr_entities<T: Transport + ?Sized>(
    transport: &T,
    ip: IpAddr,
    scan_id: &str,
) -> Result<Vec<Entity>, ResolveError> {
    Ok(dns::lookup_ptr(transport, ip)?
        .into_iter()
        .map(|name| {
            let mut host = Entity::new(EntityKind::Domain, &name, 0.9, scan_id);
            host.add_evidence(
                Evidence::new(
                    EvidenceProvenance::for_scan("dns", scan_id),
                    format!("PTR {} -> {name}", dns::reverse_name(ip)),
                )
                .with_attr("address", ip.to_string()),
            );
            host
        })
        .collect())
}

/// The announced prefixes covering `ip` and the ASes that originate them.
fn origin_entities<T: Transport + ?Sized>(
    transport: &T,
    ip: IpAddr,
    scan_id: &str,
) -> Result<Vec<Entity>, ResolveError> {
    let mut entities = Vec::new();
    for origin in cymru::lookup_origin(transport, ip)? {
        let asns: Vec<String> = origin.asns.iter().map(|asn| format!("AS{asn}")).collect();
        let summary = format!(
            "{} announces {} covering {ip} ({}, {}, allocated {})",
            asns.join(" "),
            origin.prefix,
            origin.country,
            origin.registry,
            origin.allocated
        );
        let mut block = Entity::new(EntityKind::Netblock, &origin.prefix, 0.9, scan_id);
        block.add_evidence(
            Evidence::new(EvidenceProvenance::for_scan("cymru", scan_id), &summary)
                .with_attr("address", ip.to_string())
                .with_attr("country", &origin.country)
                .with_attr("registry", &origin.registry),
        );
        entities.push(block);
        for asn in asns {
            let mut owner = Entity::new(EntityKind::Asn, &asn, 0.9, scan_id);
            owner.add_evidence(
                Evidence::new(EvidenceProvenance::for_scan("cymru", scan_id), &summary)
                    .with_attr("prefix", &origin.prefix),
            );
            entities.push(owner);
        }
    }
    Ok(entities)
}

fn as_entities<T: Transport + ?Sized>(
    transport: &T,
    asn: u32,
    scan_id: &str,
) -> Result<Vec<Entity>, ResolveError> {
    Ok(cymru::lookup_as(transport, asn)?
        .map(|info| {
            let mut owner = Entity::new(EntityKind::Asn, format!("AS{asn}"), 0.9, scan_id);
            owner.add_evidence(
                Evidence::new(
                    EvidenceProvenance::for_scan("cymru", scan_id),
                    format!(
                        "AS{asn} {} ({}, {}, allocated {})",
                        info.name, info.country, info.registry, info.allocated
                    ),
                )
                .with_attr("as_name", &info.name)
                .with_attr("country", &info.country)
                .with_attr("registry", &info.registry),
            );
            owner
        })
        .into_iter()
        .collect())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;

    use super::*;
    use crate::http::{Request, Response, TransportFailure};

    /// Answers requests from a queue in order; an empty queue is a connection failure.
    struct Fake {
        bodies: RefCell<VecDeque<&'static str>>,
    }

    impl Fake {
        fn new(bodies: &[&'static str]) -> Self {
            Self {
                bodies: RefCell::new(bodies.iter().copied().collect()),
            }
        }
    }

    impl Transport for Fake {
        fn send(&self, _request: &Request) -> Result<Response, TransportFailure> {
            self.bodies
                .borrow_mut()
                .pop_front()
                .map(|body| Response {
                    status: 200,
                    headers: Vec::new(),
                    body: body.as_bytes().to_vec(),
                    truncated: false,
                })
                .ok_or_else(|| TransportFailure {
                    kind: SourceOutcomeKind::ConnectFailure,
                    detail: "down".into(),
                    blocked: false,
                })
        }
    }

    const NX: &str = r#"{"Status":3}"#;
    const SERVFAIL: &str = r#"{"Status":2}"#;

    fn printed(run: NetworkRun) -> Report {
        match run {
            NetworkRun::Printed { report, .. } => report,
            NetworkRun::Unavailable(m) | NetworkRun::Failed(m) => panic!("{m}"),
        }
    }

    fn values(report: &Report) -> Vec<(EntityKind, String)> {
        report
            .entities
            .iter()
            .map(|e| (e.kind.clone(), e.raw_value.clone()))
            .collect()
    }

    #[test]
    fn targets_parse_canonically() {
        let cases = [
            ("1.1.1.1", Some("1.1.1.1")),
            ("2606:4700::1111", Some("2606:4700::1111")),
            ("192.0.2.77/24", Some("192.0.2.0/24")),
            ("as13335", Some("AS13335")),
            ("ASN13335", Some("AS13335")),
            ("13335", None),
            ("AS0", None),
            ("192.0.2.0/33", None),
            ("example.com", None),
        ];
        for (raw, want) in cases {
            assert_eq!(
                NetworkTarget::parse(raw).map(|t| t.canonical()).as_deref(),
                want,
                "{raw}"
            );
        }
    }

    #[test]
    fn an_ip_gets_reverse_dns_netblock_and_origin_as() {
        let fake = Fake::new(&[
            r#"{"Status":0,"Answer":[{"type":12,"data":"one.one.one.one."}]}"#,
            r#"{"Status":0,"Answer":[{"type":16,"data":"\"13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11\""}]}"#,
            r#"{"services":[[["1.0.0.0/8"],["https://rdap.apnic.net/"]]]}"#,
            r#"{"objectClassName":"ip network","handle":"1.1.1.0 - 1.1.1.255","name":"APNIC-LABS",
                "startAddress":"1.1.1.0","endAddress":"1.1.1.255","cidr0_cidrs":[{"v4prefix":"1.1.1.0","length":24}],
                "entities":[{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","APNIC Research and Development"]]],
                  "entities":[{"roles":["abuse"],"vcardArray":["vcard",[["fn",{},"text","IRT-APNICRANDNET-AU"],["email",{},"text","helpdesk@apnic.net"]]]}]}]}"#,
        ]);
        let report = printed(run(&fake, "1.1.1.1", 1));
        let found = values(&report);
        for want in [
            (EntityKind::IpAddress, "1.1.1.1"),
            (EntityKind::Domain, "one.one.one.one"),
            (EntityKind::Netblock, "1.1.1.0/24"),
            (EntityKind::Asn, "AS13335"),
        ] {
            assert!(
                found.iter().any(|(k, v)| *k == want.0 && v == want.1),
                "missing {want:?} in {found:?}"
            );
        }
        let modules: Vec<(&str, SourceOutcomeKind)> = report
            .outcomes
            .iter()
            .map(|o| (o.module.as_str(), o.kind))
            .collect();
        assert_eq!(
            modules,
            vec![
                ("dns", SourceOutcomeKind::Success),
                ("cymru", SourceOutcomeKind::Success),
                ("rdap", SourceOutcomeKind::Success)
            ]
        );
        // The registrant and the abuse contact nested inside it, from the RIR record.
        assert!(
            found.contains(&(
                EntityKind::Organisation,
                "APNIC Research and Development".into()
            )),
            "{found:?}"
        );
        assert!(
            found.contains(&(EntityKind::Email, "helpdesk@apnic.net".into())),
            "{found:?}"
        );
    }

    #[test]
    fn a_failed_source_is_an_outcome_not_a_lost_run() {
        let fake = Fake::new(&[NX, NX, NX, SERVFAIL, SERVFAIL, SERVFAIL]);
        let report = printed(run(&fake, "192.0.2.7", 1));
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::ValidZero);
        assert_eq!(report.outcomes[1].module, "cymru");
        assert!(!report.outcomes[1].kind.is_accepted());
        assert_eq!(
            values(&report),
            vec![(EntityKind::IpAddress, "192.0.2.7".to_string())]
        );
    }

    #[test]
    fn no_source_answering_is_unavailable() {
        let fake = Fake::new(&[]);
        match run(&fake, "AS64500", 1) {
            NetworkRun::Unavailable(message) => {
                assert!(
                    message.contains("no source answered for AS64500"),
                    "{message}"
                );
            }
            NetworkRun::Printed { text, .. } => panic!("printed: {text}"),
            NetworkRun::Failed(m) => panic!("{m}"),
        }
    }

    #[test]
    fn an_as_record_merges_into_the_target() {
        let fake = Fake::new(&[
            r#"{"Status":0,"Answer":[{"type":16,"data":"\"13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US\""}]}"#,
        ]);
        let report = printed(run(&fake, "AS13335", 1));
        assert_eq!(report.entities.len(), 1);
        assert!(
            report.entities[0]
                .evidence
                .iter()
                .any(|e| e.summary.contains("CLOUDFLARENET, US"))
        );
    }

    #[test]
    fn a_netblock_queries_its_network_address() {
        let fake = Fake::new(&[
            r#"{"Status":0,"Answer":[{"type":16,"data":"\"64500 | 192.0.2.0/24 | AU | apnic | 2001-01-01\""}]}"#,
        ]);
        let report = printed(run_target(
            &fake,
            NetworkTarget::Netblock(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24),
            1,
        ));
        assert!(
            values(&report).contains(&(EntityKind::Asn, "AS64500".to_string())),
            "{:?}",
            values(&report)
        );
    }
}
