//! End-to-end front-end for `huntsman-recon asn` and the AS arm of `scan`: one public AS number,
//! Spiderfoot's `BGP_AS_OWNER` target.
//!
//! Runs, for the AS, at once: its RDAP registration (see [`crate::rdap_legs`]: the record as
//! published, its holder and contacts), three `RIPEstat` calls, as Spiderfoot's `sfp_ripe`
//! reads them, and its [`crate::peeringdb`] profile (the operator's self-published organisation,
//! website, peering policy and traffic, with every peering address it publishes at a public
//! Internet exchange as an [`crate::entity::EntityKind::IpAddress`] pivot). `as-overview` names the
//! holder and the registry block the number came from.
//! `announced-prefixes` lists every prefix the AS announces, each a netblock entity (Spiderfoot's
//! `NETBLOCK_OWNER` or `NETBLOCKV6_OWNER` under an AS target) with every window the collectors
//! saw it in. `asn-neighbours` lists every AS adjacent to it in the collected BGP paths, its side
//! and how widely it was seen, each public one an AS entity: `sfp_ripe` fetches these and drops
//! them.
//! Nothing is capped: an AS that announces thousands of prefixes is reported with all of them.
//!
//! A reserved, private-use or documentation AS number is refused before any request.
//!
//! When no source answered, the lookup ends from its rows through
//! [`crate::source_outcome::SourceReach`]: a request refused before sending is a refusal (exit
//! 77), otherwise no usable response (exit 69); any source that answered makes it print.

use std::fmt::Write as _;
use std::path::PathBuf;

use crate::api_leg::LegError;
use crate::canonical::canonical_asn;
use crate::concurrent;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::http::Transport;
use crate::lookup_args::LookupTokens;
use crate::lookup_report;
use crate::peeringdb;
use crate::rdap_legs;
use crate::ripestat::{self, AsOverview, Neighbours, Prefixes};
use crate::source_outcome::{
    EndpointAnswer, Joined, SourceExecutionOutcome, SourceOutcomeKind, SourceReach, SourceRun,
};

pub const ASN_USAGE: &str = "usage: huntsman-recon asn AS-NUMBER [--save FILE]";
pub const ASN_HELP: &str = "\
asn AS-NUMBER [--save FILE]
Look up one public autonomous system, written AS13335, ASN13335 or 13335: its RDAP registration (the record as published, its holder and contacts), its holder and registry block, every prefix it announces with the windows it was seen (each an address block), every public AS adjacent to it in BGP paths with its side, and its PeeringDB profile (its operator organisation, website, peering policy and traffic) with every peering address it publishes at a public Internet exchange (each an IP pivot), all keyless from RDAP, RIPEstat and PeeringDB. A reserved, private-use or documentation AS number is refused before any request. --save FILE writes an unverified ledger that verify can reload. Makes network requests.";

/// The largest answer read for one call: the announced prefixes of the largest networks run to
/// several megabytes, and every one is kept.
pub const MAX_BODY: usize = 64 * 1024 * 1024;

/// Confidence of the AS itself and of its holder.
const SEED_CONFIDENCE: f64 = 0.90;
/// Confidence of a prefix the collectors saw the AS announce.
const PREFIX_CONFIDENCE: f64 = 0.85;
/// Confidence of a neighbour seen in the collected paths.
const NEIGHBOUR_CONFIDENCE: f64 = 0.60;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnArgs {
    pub asn: String,
    pub save: Option<PathBuf>,
}

impl AsnArgs {
    /// # Errors
    /// [`Error::Invalid`] for a missing or extra argument, [`Error::InvalidValue`] for a value
    /// that is not a public AS number.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let (raw, save) = LookupTokens::single(args, "asn needs exactly one AS number")?;
        let asn = canonical_asn(&raw)
            .ok_or_else(|| Error::invalid_value("not a public AS number (AS13335)"))?;
        Ok(Self { asn, save })
    }
}

pub type AsnRun = SourceRun<Report>;

/// What the three `RIPEstat` calls answered.
struct Routing {
    overview: Result<AsOverview, LegError>,
    prefixes: Result<Prefixes, LegError>,
    neighbours: Result<Neighbours, LegError>,
}

/// Look up `asn`, each leg only when the transport's lookup asks its module
/// ([`Transport::runs_module`]).
#[must_use]
pub fn run<T: Transport + ?Sized + Sync>(transport: &T, asn: &str, now_unix: u64) -> AsnRun {
    let Some((value, number)) =
        canonical_asn(asn).and_then(|value| Some((value.clone(), value[2..].parse::<u32>().ok()?)))
    else {
        return AsnRun::Failed("not a public AS number".into());
    };
    let scan_id = crate::entity::scan_id("asn", &value);
    let ((routing, registration), peering) = concurrent::pair(
        || {
            concurrent::pair(
                || {
                    transport.runs_module(ripestat::SOURCE).then(|| {
                        let (overview, (prefixes, neighbours)) = concurrent::pair(
                            || caught(|| ripestat::as_overview(transport, number, now_unix)),
                            || {
                                concurrent::pair(
                                    || {
                                        caught(|| {
                                            ripestat::announced_prefixes(
                                                transport, number, now_unix,
                                            )
                                        })
                                    },
                                    || caught(|| ripestat::neighbours(transport, number, now_unix)),
                                )
                            },
                        );
                        Routing {
                            overview,
                            prefixes,
                            neighbours,
                        }
                    })
                },
                || rdap_legs::asn(transport, number, &scan_id, now_unix),
            )
        },
        || {
            transport
                .runs_module(peeringdb::SOURCE)
                .then(|| peeringdb::lookup(transport, number, &scan_id, now_unix))
        },
    );

    let mut report = Report::default();
    report.entities.extend(registration.entities);
    report.outcomes.extend(registration.outcome);
    if let Some(routing) = routing {
        routing_entities(&mut report, &value, &scan_id, &routing, now_unix);
    }
    if let Some(result) = peering {
        fold_peeringdb(&mut report, result, now_unix);
    }
    merge_by_uid(&mut report.entities);
    if let Some(run) =
        SourceReach::of(&report.outcomes).unanswered(&format!("no source answered for {value}"))
    {
        return run;
    }
    match lookup_report::render(&report.entities, &report.outcomes) {
        Ok(text) => AsnRun::Printed { text, report },
        Err(message) => AsnRun::Failed(message),
    }
}

/// A call's answer; a call that panicked is an answer that could not be read.
fn caught<R>(call: impl FnOnce() -> Result<R, LegError>) -> Result<R, LegError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(call))
        .unwrap_or_else(|_| Err(LegError::Decode("the call panicked".into())))
}

/// Fold the `PeeringDB` leg into the report: its entities and one outcome on success, or an
/// accounted failure outcome so [`SourceReach`] still reasons about the leg. A blocked egress is a
/// refusal before sending, matching how the `ripestat` and `rdap` legs classify one, so an
/// all-refused AS scan stays a refusal; any other error is inconclusive.
fn fold_peeringdb(report: &mut Report, result: Result<peeringdb::Report, Error>, now_unix: u64) {
    match result {
        Ok(found) => {
            report.entities.extend(found.entities);
            report.outcomes.push(found.outcome);
        }
        Err(Error::Network(msg)) => report.outcomes.push(SourceExecutionOutcome::failed(
            peeringdb::SOURCE,
            now_unix,
            SourceOutcomeKind::RefusedBeforeSending,
            None,
            msg,
        )),
        Err(error) => report.outcomes.push(SourceExecutionOutcome::failed(
            peeringdb::SOURCE,
            now_unix,
            SourceOutcomeKind::Inconclusive,
            None,
            error.to_string(),
        )),
    }
}

/// The holder, prefixes and neighbours as entities, and the one `ripestat` row that says what
/// each call answered. How the lookup ends when no call answered is read from that row by
/// [`SourceReach`], not returned here.
fn routing_entities(
    report: &mut Report,
    asn: &str,
    scan_id: &str,
    routing: &Routing,
    now_unix: u64,
) {
    let evidence = |summary: String| {
        Evidence::new(
            EvidenceProvenance::for_scan(ripestat::SOURCE, scan_id),
            summary,
        )
    };
    // How many entities each call that answered gave, in the order the row lists them:
    // as-overview, announced-prefixes, asn-neighbours.
    let mut counts = [0; 3];
    let mut said = Vec::new();
    if let Ok(overview) = &routing.overview {
        counts[0] = overview_entities(report, asn, scan_id, overview);
        said.push(match &overview.holder {
            Some(holder) => format!("as-overview: held by {holder}"),
            None => "as-overview: no holder".to_owned(),
        });
    }
    if let Ok(prefixes) = &routing.prefixes {
        let (mut v4, mut v6) = (0, 0);
        for announced in &prefixes.prefixes {
            if announced.prefix.contains(':') {
                v6 += 1;
            } else {
                v4 += 1;
            }
            let mut seen = evidence(format!("Announced by {asn}")).with_attr("announced_by", asn);
            for (start, end) in &announced.timelines {
                seen = seen.with_attr("seen", format!("{start}/{end}"));
            }
            push_entity(
                &mut report.entities,
                EntityKind::Netblock,
                &announced.prefix,
                PREFIX_CONFIDENCE,
                scan_id,
                seen,
                &[],
            );
        }
        counts[1] = prefixes.prefixes.len();
        let mut line = format!("announced-prefixes: {v4} IPv4 and {v6} IPv6");
        if let (Some(start), Some(end)) = (&prefixes.query_start, &prefixes.query_end) {
            let _ = write!(line, " from {start} to {end}");
        }
        said.push(line);
    }
    if let Ok(neighbours) = &routing.neighbours {
        counts[2] = neighbour_entities(report, asn, scan_id, neighbours);
        let side = |relation: &str| {
            neighbours
                .neighbours
                .iter()
                .filter(|neighbour| neighbour.relation == relation)
                .count()
        };
        let mut line = format!(
            "asn-neighbours: {} left, {} right, {} uncertain",
            side("left"),
            side("right"),
            side("uncertain")
        );
        if let Some(day) = &neighbours.query_start {
            let _ = write!(line, " on {day}");
        }
        said.push(line);
    }
    let errors = [
        ("as-overview", routing.overview.as_ref().err()),
        ("announced-prefixes", routing.prefixes.as_ref().err()),
        ("asn-neighbours", routing.neighbours.as_ref().err()),
    ];
    for (call, error) in &errors {
        if let Some(error) = error {
            said.push(format!("{call} failed: {error}"));
        }
    }
    let detail = said.join("; ");
    let answers: [EndpointAnswer; 3] = std::array::from_fn(|call| match errors[call].1 {
        Some(error) => EndpointAnswer::Failed(error.outcome_kind()),
        None if counts[call] > 0 => EndpointAnswer::Found(counts[call]),
        None => EndpointAnswer::Absent,
    });
    let outcome = match Joined::of(&answers) {
        Joined::Found(found) => SourceExecutionOutcome::success(ripestat::SOURCE, now_unix, found)
            .with_http_status(200)
            .with_detail(detail),
        Joined::Absent => SourceExecutionOutcome::valid_zero(ripestat::SOURCE, now_unix)
            .with_http_status(200)
            .with_detail(detail),
        // Every call failed: the row takes the failure the join chose, as its `LegError` reads,
        // so a rate limit keeps its retry time. Reading the kind (not the `LegError` variant) is
        // what the phase-5 token rule relies on.
        Joined::Unanswered { index, .. } => match errors[index].1 {
            Some(error) => error.outcome(&ripestat::API, now_unix).with_detail(detail),
            None => SourceExecutionOutcome::inconclusive(ripestat::SOURCE, now_unix, detail),
        },
        // A call found nothing beside one that failed: the failed call may hold what the others
        // do not, so the AS is not shown to have none.
        Joined::Inconclusive => {
            SourceExecutionOutcome::inconclusive(ripestat::SOURCE, now_unix, detail)
        }
    };
    report.outcomes.push(outcome);
}

/// The AS's holder and registry block on the AS, and the holder as an organisation tied to it.
fn overview_entities(
    report: &mut Report,
    asn: &str,
    scan_id: &str,
    overview: &AsOverview,
) -> usize {
    let evidence = |summary: String| {
        Evidence::new(
            EvidenceProvenance::for_scan(ripestat::SOURCE, scan_id),
            summary,
        )
    };
    let mut summary = format!("{asn} routing overview");
    if let Some(holder) = &overview.holder {
        let _ = write!(summary, ", held by {holder}");
    }
    if let Some(desc) = &overview.block_desc {
        let _ = write!(summary, ", {desc}");
    }
    summary.push_str(if overview.announced {
        ", announced"
    } else {
        ", not announced"
    });
    let described = evidence(summary)
        .with_attr("announced", overview.announced.to_string())
        .with_optional_attrs([
            ("holder", overview.holder.as_deref()),
            ("registry_block", overview.block.as_deref()),
            ("registry_block_desc", overview.block_desc.as_deref()),
            ("registry", overview.block_name.as_deref()),
        ]);
    push_entity(
        &mut report.entities,
        EntityKind::Asn,
        asn,
        SEED_CONFIDENCE,
        scan_id,
        described,
        &[],
    );
    let Some(holder) = overview.holder.as_deref() else {
        return 0;
    };
    push_entity(
        &mut report.entities,
        EntityKind::Organisation,
        holder,
        SEED_CONFIDENCE,
        scan_id,
        evidence(format!("Holder of {asn}")).with_attr("asn", asn),
        &[],
    );
    1
}

/// Each neighbour that is a public AS number as an AS, with its side and how widely the adjacency
/// was seen. A reserved number in an AS path, such as `AS23456` (`AS_TRANS`) or a private AS, is
/// no AS of its own, as for an origin.
fn neighbour_entities(
    report: &mut Report,
    asn: &str,
    scan_id: &str,
    neighbours: &Neighbours,
) -> usize {
    let mut found = 0;
    for neighbour in &neighbours.neighbours {
        let value = format!("AS{}", neighbour.asn);
        if value == asn || !crate::canonical::is_public_asn(neighbour.asn) {
            continue;
        }
        let seen = Evidence::new(
            EvidenceProvenance::for_scan(ripestat::SOURCE, scan_id),
            format!(
                "BGP neighbour of {asn}, {} of it in the collected AS paths",
                neighbour.relation
            ),
        )
        .with_attr("neighbour_of", asn)
        .with_attr("relation", neighbour.relation.as_str())
        .with_attr("power", neighbour.power.to_string())
        .with_attr("v4_peers", neighbour.v4_peers.to_string())
        .with_attr("v6_peers", neighbour.v6_peers.to_string());
        push_entity(
            &mut report.entities,
            EntityKind::Asn,
            &value,
            NEIGHBOUR_CONFIDENCE,
            scan_id,
            seen,
            &[],
        );
        found += 1;
    }
    found
}

#[cfg(test)]
mod tests;
