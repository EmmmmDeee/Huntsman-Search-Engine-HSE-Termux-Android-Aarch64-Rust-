//! End-to-end front-end for `huntsman-recon netblock` and the netblock arm of `scan`: one public
//! address block, Spiderfoot's `NETBLOCK_OWNER` (`NETBLOCKV6_OWNER`) target.
//!
//! Runs, for the block, its RDAP registration (the smallest registered network that holds all of
//! it, see [`crate::rdap_legs`]), `RIPEstat` routing (the announced prefix that covers it and the
//! AS numbers that originate it), and reverse DNS of every address in it, as Spiderfoot's
//! `sfp_dnsresolve` does for a netblock target with its default limits: a block of at most 256
//! addresses (an IPv4 /24, an IPv6 /120) is swept over the `DoH` resolvers, several addresses at a
//! time, and a larger block's row says it was not swept and why. Each address with a PTR record is
//! an address entity in the block, every record listed as published, and each name a domain
//! tagged `ptr` whose evidence names its address.
//!
//! A block whose first address is private, loopback, documentation or otherwise non-public is
//! refused before any request, as the `ip` lookup refuses such an address.

use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::PathBuf;

use crate::api_leg::LegError;
use crate::canonical::{canonical_ip, canonical_netblock};
use crate::dns::{self, RESOLVE_SOURCE, ResolveErrorKind};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::http::Transport;
use crate::lookup_args::LookupTokens;
use crate::lookup_report;
use crate::netblock::Netblock;
use crate::rdap_legs;
use crate::ripestat;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, SourceRun};
use crate::tags;
use crate::threat_feeds::{self, Feeds};

pub const NETBLOCK_USAGE: &str = "usage: huntsman-recon netblock CIDR [--save FILE]";
pub const NETBLOCK_HELP: &str = "\
netblock CIDR [--save FILE]
Look up one public IPv4 or IPv6 address block, written ADDRESS/PREFIX (host bits are cleared, so 1.1.1.7/24 is 1.1.1.0/24): its RDAP registration (the network that holds it, its holder, contacts and the record as published), the announced prefix covering it and its origin AS from RIPEstat, and the PTR records of every address in a block of at most 256 addresses (a /24 or an IPv6 /120, Spiderfoot's limits), all keyless. The block and every address and name found in it are checked against the threat feeds Spiderfoot downloads (abuse.ch Feodo Tracker and URLhaus, AlienVault IP Reputation, blocklist.de, botvrij.eu, CINS Army, CoinBlocker, CyberCrime-Tracker, Emerging Threats, GreenSnow, OpenPhish, PhishTank, Steven Black's hosts, Tor's exit relays, VoIPBL and VXVault): a block is listed by every listed address or block inside or around it. Each feed is downloaded once and kept in $HUNTSMAN_HOME/feeds, else ~/.huntsman/feeds, until it is older than Spiderfoot keeps it. A block whose first address is private, loopback, documentation or otherwise non-public is refused before any request. --save FILE writes an unverified ledger that verify can reload. Makes network requests.";

/// Host bits of the largest block whose addresses are swept: 256 addresses, Spiderfoot's
/// `sfp_dnsresolve` defaults (`maxnetblock` 24, `maxv6netblock` 120).
pub const MAX_SWEEP_HOST_BITS: u8 = 8;

/// Confidence of the queried block itself.
const SEED_CONFIDENCE: f64 = 0.90;
/// Confidence of an origin AS or its holder, as the `ip` lookup has it.
const PIVOT_CONFIDENCE: f64 = 0.60;
/// Confidence of an address in the block that its reverse zone names, and of each name.
const PTR_CONFIDENCE: f64 = 0.80;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetblockArgs {
    pub netblock: String,
    pub save: Option<PathBuf>,
}

impl NetblockArgs {
    /// # Errors
    /// [`Error::Invalid`] for a missing or extra argument, [`Error::InvalidValue`] for a value
    /// that is not a public block.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let (raw, save) = LookupTokens::single(args, "netblock needs exactly one CIDR")?;
        let netblock = canonical_netblock(&raw)
            .ok_or_else(|| Error::invalid_value("not a public address block (ADDRESS/PREFIX)"))?;
        Ok(Self { netblock, save })
    }
}

pub type NetblockRun = SourceRun<Report>;

/// Look up `netblock`, then check it and every address and name found in it against the threat
/// `feeds`. Each leg runs only when the transport's lookup asks its module
/// ([`Transport::runs_module`]).
#[must_use]
pub fn run<T: Transport + ?Sized + Sync>(
    transport: &T,
    feeds: &Feeds,
    netblock: &str,
    now_unix: u64,
) -> NetblockRun {
    let Some(block) = canonical_netblock(netblock).and_then(|value| Netblock::parse(&value)) else {
        return NetblockRun::Failed("not a public address block".into());
    };
    let value = block.to_string();
    let scan_id = crate::entity::scan_id("netblock", &value);
    let mut report = Report::default();
    let mut network = None;

    let registration = rdap_legs::netblock(transport, block, &scan_id, now_unix);
    report.entities.extend(registration.entities);
    report.outcomes.extend(registration.outcome);
    if transport.runs_module(ripestat::SOURCE) {
        // Both calls run whatever the other returns, so a failed call costs the other nothing.
        let place = ripestat::geolocation(transport, &value, now_unix);
        match ripestat::lookup(transport, &value, now_unix) {
            Ok(routing) if !routing.says_anything() => report.outcomes.push(
                SourceExecutionOutcome::valid_zero(ripestat::SOURCE, now_unix),
            ),
            Ok(routing) => routing_leg(&mut report, &value, &scan_id, &routing, now_unix),
            Err(err) => {
                if let LegError::Transport(_) = err {
                    network = Some(format!("{}: {err}", ripestat::SOURCE));
                }
                report.outcomes.push(err.outcome(&ripestat::API, now_unix));
            }
        }
        match place {
            Ok(place) => place_leg(&mut report, &value, &scan_id, &place),
            Err(err) => {
                if let LegError::Transport(_) = err {
                    network.get_or_insert_with(|| format!("{}: {err}", ripestat::SOURCE));
                }
                report.outcomes.push(err.outcome(&ripestat::API, now_unix));
            }
        }
    }
    if transport.runs_module(RESOLVE_SOURCE) {
        let swept = sweep(transport, block, &scan_id, now_unix);
        report.entities.extend(swept.entities);
        report.outcomes.push(swept.outcome);
    }
    threat_feeds::check_found(
        feeds,
        threat_feeds::Subject::Block(block),
        &mut report.entities,
        &mut report.outcomes,
        &scan_id,
        now_unix,
    );

    merge_by_uid(&mut report.entities);
    if !report.outcomes.iter().any(|o| o.kind.is_accepted()) {
        return match network {
            Some(message) => NetblockRun::Network(message),
            None => NetblockRun::Failed(format!("no source answered for netblock {value}")),
        };
    }
    match lookup_report::render(&report.entities, &report.outcomes) {
        Ok(text) => NetblockRun::Printed { text, report },
        Err(message) => NetblockRun::Failed(message),
    }
}

/// Where `RIPEstat` places the block, as one record on it. Its outcome is the routing leg's, so a
/// place adds no outcome row of its own.
fn place_leg(report: &mut Report, block: &str, scan_id: &str, place: &ripestat::Geolocation) {
    if !place.says_anything() {
        return;
    }
    let evidence = Evidence::new(
        EvidenceProvenance::for_scan(ripestat::SOURCE, scan_id),
        "Where RIPEstat places the block",
    )
    .with_attr("locations", place.summary());
    push_entity(
        &mut report.entities,
        EntityKind::Netblock,
        block,
        SEED_CONFIDENCE,
        scan_id,
        evidence,
        &[],
    );
}

/// Everything `RIPEstat` says about the block on it ([`ripestat::Routing::attributes`]), and each
/// public origin AS and its holder as a pivot tied to the block.
fn routing_leg(
    report: &mut Report,
    block: &str,
    scan_id: &str,
    routing: &ripestat::Routing,
    now_unix: u64,
) {
    let evidence = |summary: String| {
        Evidence::new(
            EvidenceProvenance::for_scan(ripestat::SOURCE, scan_id),
            summary,
        )
    };
    let announced = routing
        .attributes()
        .into_iter()
        .fold(evidence(routing.summary()), |evidence, (key, value)| {
            evidence.with_attr(key, value)
        });
    push_entity(
        &mut report.entities,
        EntityKind::Netblock,
        block,
        SEED_CONFIDENCE,
        scan_id,
        announced,
        &[],
    );
    for origin in routing.public_origins() {
        let asn = format!("AS{}", origin.asn);
        let found = evidence("Origin AS of the prefix covering the block".into())
            .with_attr("netblock", block)
            .with_optional_attrs([
                ("prefix", routing.prefix.as_deref()),
                ("holder", origin.holder.as_deref()),
            ]);
        push_entity(
            &mut report.entities,
            EntityKind::Asn,
            &asn,
            PIVOT_CONFIDENCE,
            scan_id,
            found,
            &[],
        );
        if let Some(holder) = origin.holder.as_deref() {
            let held = evidence(format!("Holder of {asn}")).with_attr("asn", asn.as_str());
            push_entity(
                &mut report.entities,
                EntityKind::Organisation,
                holder,
                PIVOT_CONFIDENCE,
                scan_id,
                held,
                &[],
            );
        }
    }
    report.outcomes.push(
        SourceExecutionOutcome::success(ripestat::SOURCE, now_unix, routing.origins.len().max(1))
            .with_http_status(200),
    );
}

/// What sweeping the block found: its entities and the `dnsresolve` row.
struct Swept {
    entities: Vec<Entity>,
    outcome: SourceExecutionOutcome,
}

/// The PTR records of every public address in `block`, when it holds at most 256.
fn sweep<T: Transport + ?Sized + Sync>(
    transport: &T,
    block: Netblock,
    scan_id: &str,
    now_unix: u64,
) -> Swept {
    let Some(addresses) = block.addresses(MAX_SWEEP_HOST_BITS) else {
        return Swept {
            entities: Vec::new(),
            outcome: SourceExecutionOutcome::failed(
                RESOLVE_SOURCE,
                now_unix,
                SourceOutcomeKind::Inconclusive,
                None,
                format!(
                    "{block} holds 2^{} addresses; reverse DNS sweeps a block of at most 256 \
                     (a /24, or a /120 of IPv6), as Spiderfoot does",
                    block.host_bits()
                ),
            ),
        };
    };
    let public: Vec<(IpAddr, String)> = addresses
        .into_iter()
        .filter_map(|address| canonical_ip(&address.to_string()).map(|ip| (address, ip)))
        .collect();
    let answers = dns::ask_all(
        &public,
        |(address, _)| dns::lookup_ptr(transport, *address),
        |answer| matches!(answer, Err(error) if error.kind != ResolveErrorKind::Empty),
    );
    let block_value = block.to_string();
    let mut tally = Tally {
        addresses: public.len(),
        ..Tally::default()
    };
    let mut entities = Vec::new();
    for ((_, ip), answer) in public.iter().zip(answers) {
        match answer {
            Some(Ok(answer)) => {
                tally.named += 1;
                tally.records += answer.records.len();
                let found = crate::ip_cli::reverse(ip, &answer, scan_id);
                push_entity(
                    &mut entities,
                    EntityKind::IpAddress,
                    ip,
                    PTR_CONFIDENCE,
                    scan_id,
                    found.address.with_attr("netblock", block_value.as_str()),
                    &[],
                );
                for (domain, evidence) in found.names {
                    push_entity(
                        &mut entities,
                        EntityKind::Domain,
                        &domain,
                        PTR_CONFIDENCE,
                        scan_id,
                        evidence,
                        &[tags::PTR],
                    );
                }
            }
            Some(Err(error)) if error.kind == ResolveErrorKind::Empty => tally.unnamed += 1,
            Some(Err(error)) => {
                tally.failed += 1;
                tally
                    .first_failure
                    .get_or_insert((error.kind, error.detail));
            }
            None => {}
        }
    }
    Swept {
        entities,
        outcome: tally.outcome(&block_value, now_unix),
    }
}

/// How the block's addresses came out.
#[derive(Default)]
struct Tally {
    addresses: usize,
    named: usize,
    records: usize,
    unnamed: usize,
    failed: usize,
    first_failure: Option<(ResolveErrorKind, String)>,
}

impl Tally {
    /// Success with the record count; a validated zero when no address asked has a record; failed,
    /// with why, when no address was answered. **Pure.**
    fn outcome(&self, block: &str, now_unix: u64) -> SourceExecutionOutcome {
        let not_asked = self.addresses - self.named - self.unnamed - self.failed;
        if self.named + self.unnamed == 0 {
            let (kind, detail) = self
                .first_failure
                .clone()
                .unwrap_or((ResolveErrorKind::Upstream, "no address was asked".into()));
            return SourceExecutionOutcome::failed(
                RESOLVE_SOURCE,
                now_unix,
                kind.outcome_kind(),
                None,
                format!(
                    "no resolver answered: {} of {} addresses in {block} failed, the first {}: \
                     {detail}",
                    self.failed,
                    self.addresses,
                    kind.as_str()
                ),
            );
        }
        let outcome = if self.records == 0 {
            SourceExecutionOutcome::valid_zero(RESOLVE_SOURCE, now_unix)
        } else {
            SourceExecutionOutcome::success(RESOLVE_SOURCE, now_unix, self.records)
        };
        let mut detail = format!(
            "{} of {} addresses in {block} have PTR records",
            self.named, self.addresses
        );
        if self.failed > 0 {
            let _ = write!(detail, ", {} unanswered", self.failed);
        }
        if not_asked > 0 {
            let _ = write!(
                detail,
                ", {not_asked} not asked after the resolvers stopped answering"
            );
        }
        outcome.with_detail(detail)
    }
}

#[cfg(test)]
mod tests;
