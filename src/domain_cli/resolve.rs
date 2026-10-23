//! Address resolution of the hosts a domain lookup found in its zone, as Spiderfoot's
//! `sfp_dnsresolve` resolves every `INTERNET_NAME` a scan finds.
//!
//! Each subdomain any leg named (a certificate, a mail exchanger, a passive-DNS source) is asked
//! for its A and AAAA records through the lookup's own transport, several hosts at a time. Every
//! public address a host resolves to is an address entity whose evidence names the host, so the
//! address is the host's child as Spiderfoot's event tree has it; the host's own evidence lists
//! every address it resolved to (a non-public one too, as published) under `resolved_ip`, which the
//! resolution relation reads. A host whose zone answered both queries with "no such name" or "no
//! such record" is tagged [`tags::UNRESOLVED`], Spiderfoot's `INTERNET_NAME_UNRESOLVED`.

use std::collections::BTreeSet;

use crate::canonical::{canonical_domain, canonical_ip};
use crate::dns::{self, RESOLVE_SOURCE, RecordType, ResolveErrorKind, ResolveQuery};
use crate::domains::is_proper_subdomain_of;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, push_entity};
use crate::http::Transport;
use crate::source_outcome::SourceExecutionOutcome;
use crate::tags;

use super::{DOMAIN_CONFIDENCE, RECORD_CONFIDENCE};

/// The most hosts one lookup resolves, two queries each. A host past it is still an entity of
/// the lookup; the outcome row counts it as not resolved.
const MAX_RESOLVED_HOSTS: usize = 512;
/// A name that does not resolve: weaker than one that does, never stronger than its finder's.
const UNRESOLVED_CONFIDENCE: f64 = 0.50;

/// What resolving the lookup's hosts found: entities to add, the leg's outcome and its line of the
/// printed report.
pub(super) struct Resolved {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
    pub section: String,
}

/// One host's answer.
#[derive(Debug, Clone, PartialEq)]
enum HostAnswer {
    /// Each record: its type, the address as published and the resolver that answered.
    Addresses(Vec<(RecordType, String, &'static str)>),
    /// The zone answered both queries with no record.
    Unresolved,
    /// No resolver answered a query, and no record came back: the error kind and detail.
    Failed(ResolveErrorKind, String),
}

/// The hosts below `domain` that `entities` name, each once, in name order; the domain itself
/// is resolved by the DNS leg. **Pure.**
pub(super) fn hosts(entities: &[Entity], domain: &str) -> Vec<String> {
    entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Domain)
        .map(|entity| entity.value.as_str())
        .filter(|host| is_proper_subdomain_of(host, domain))
        .filter(|host| canonical_domain(host).as_deref() == Some(*host))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(str::to_owned)
        .collect()
}

/// Resolve `hosts` (at most [`MAX_RESOLVED_HOSTS`]) and turn the answers into entities tied to
/// `domain`'s scan.
pub(super) fn resolve<T: Transport + ?Sized + Sync>(
    transport: &T,
    domain: &str,
    hosts: &[String],
    scan_id: &str,
    now_unix: u64,
) -> Resolved {
    let asked = &hosts[..hosts.len().min(MAX_RESOLVED_HOSTS)];
    let answers = resolve_all(asked, |host| resolve_host(transport, host));
    let mut tally = Tally {
        hosts: hosts.len(),
        ..Tally::default()
    };
    let mut entities = Vec::new();
    for (host, answer) in asked.iter().zip(&answers) {
        match answer {
            Some(HostAnswer::Addresses(records)) => {
                tally.resolved += 1;
                tally.addresses += records.len();
                host_entities(&mut entities, domain, host, records, scan_id);
            }
            Some(HostAnswer::Unresolved) => {
                tally.unresolved += 1;
                let evidence = resolve_evidence(scan_id, format!("{host} has no A or AAAA record"))
                    .with_attr("domain", domain);
                push_entity(
                    &mut entities,
                    EntityKind::Domain,
                    host,
                    UNRESOLVED_CONFIDENCE,
                    scan_id,
                    evidence,
                    &[tags::SUBDOMAIN, tags::UNRESOLVED],
                );
            }
            Some(HostAnswer::Failed(kind, detail)) => {
                tally.failed += 1;
                tally.first_failure.get_or_insert((*kind, detail.clone()));
            }
            None => tally.aborted += 1,
        }
    }
    Resolved {
        entities,
        outcome: tally.outcome(now_unix),
        section: tally.section(),
    }
}

fn resolve_evidence(scan_id: &str, summary: String) -> Evidence {
    Evidence::new(
        EvidenceProvenance::for_scan(RESOLVE_SOURCE, scan_id),
        summary,
    )
}

/// A resolved host's evidence, listing every address, and each public address as an entity
/// whose evidence names the host.
fn host_entities(
    entities: &mut Vec<Entity>,
    domain: &str,
    host: &str,
    records: &[(RecordType, String, &'static str)],
    scan_id: &str,
) {
    let mut resolved = resolve_evidence(
        scan_id,
        format!("{host} resolves to {} addresses", records.len()),
    )
    .with_attr("domain", domain);
    for (record_type, address, resolver) in records {
        let record_type = record_type.as_str();
        resolved = resolved.with_attr("resolved_ip", address.as_str());
        let Some(ip) = canonical_ip(address) else {
            continue;
        };
        let evidence = resolve_evidence(scan_id, format!("{record_type} record of {host}"))
            .with_attr("domain", host)
            .with_attr("record_type", record_type)
            .with_attr("resolver", *resolver);
        push_entity(
            entities,
            EntityKind::IpAddress,
            &ip,
            RECORD_CONFIDENCE,
            scan_id,
            evidence,
            &[],
        );
    }
    push_entity(
        entities,
        EntityKind::Domain,
        host,
        DOMAIN_CONFIDENCE,
        scan_id,
        resolved,
        &[tags::SUBDOMAIN],
    );
}

/// The host's A and AAAA records. A query the zone answered with no record counts as answered;
/// the host fails only when a query got no answer and none returned a record.
fn resolve_host<T: Transport + ?Sized>(transport: &T, host: &str) -> HostAnswer {
    let mut records = Vec::new();
    let mut failure = None;
    for record_type in [RecordType::A, RecordType::Aaaa] {
        let query = ResolveQuery {
            name: host.to_owned(),
            record_type,
        };
        match dns::resolve_with_pool(transport, &query) {
            Ok(answer) => records.extend(answer.records.into_iter().map(|record| {
                (
                    record_type,
                    record.trim().to_owned(),
                    answer.server.provider,
                )
            })),
            Err(error) if error.kind == ResolveErrorKind::Empty => {}
            Err(error) => {
                failure.get_or_insert((error.kind, error.detail));
            }
        }
    }
    match (records.is_empty(), failure) {
        (false, _) => HostAnswer::Addresses(records),
        (true, None) => HostAnswer::Unresolved,
        (true, Some((kind, detail))) => HostAnswer::Failed(kind, detail),
    }
}

/// `answer` for each host, several at a time, in `hosts` order (see [`dns::ask_all`]).
fn resolve_all<F>(hosts: &[String], answer: F) -> Vec<Option<HostAnswer>>
where
    F: Fn(&str) -> HostAnswer + Sync,
{
    dns::ask_all(
        hosts,
        |host| answer(host),
        |result| matches!(result, HostAnswer::Failed(..)),
    )
}

/// How the hosts came out.
#[derive(Default)]
struct Tally {
    hosts: usize,
    resolved: usize,
    addresses: usize,
    unresolved: usize,
    failed: usize,
    aborted: usize,
    first_failure: Option<(ResolveErrorKind, String)>,
}

impl Tally {
    /// Hosts never asked: past [`MAX_RESOLVED_HOSTS`], or after the resolvers stopped answering.
    fn not_asked(&self) -> usize {
        self.hosts - self.resolved - self.unresolved - self.failed
    }

    /// Success with the address count; a validated zero when every host asked had no record;
    /// failed, with why, when no host was answered. **Pure.**
    fn outcome(&self, now_unix: u64) -> SourceExecutionOutcome {
        if self.resolved + self.unresolved == 0 {
            let (kind, detail) = self
                .first_failure
                .clone()
                .unwrap_or((ResolveErrorKind::Upstream, "no host was asked".into()));
            return SourceExecutionOutcome::failed(
                RESOLVE_SOURCE,
                now_unix,
                kind.outcome_kind(),
                None,
                format!(
                    "no resolver answered: {} of {} hosts failed, the first {}: {detail}",
                    self.failed,
                    self.hosts,
                    kind.as_str()
                ),
            );
        }
        let outcome = if self.addresses == 0 {
            SourceExecutionOutcome::valid_zero(RESOLVE_SOURCE, now_unix)
        } else {
            SourceExecutionOutcome::success(RESOLVE_SOURCE, now_unix, self.addresses)
        };
        outcome.with_detail(self.counts())
    }

    fn counts(&self) -> String {
        let mut parts = vec![format!(
            "{} of {} hosts resolved",
            self.resolved, self.hosts
        )];
        if self.unresolved > 0 {
            parts.push(format!("{} unresolved", self.unresolved));
        }
        if self.failed > 0 {
            parts.push(format!("{} unanswered", self.failed));
        }
        let not_asked = self.not_asked();
        if self.aborted > 0 {
            parts.push(format!(
                "{} not asked after the resolvers stopped answering",
                self.aborted
            ));
        }
        if not_asked > self.aborted {
            parts.push(format!(
                "{} not asked past the {MAX_RESOLVED_HOSTS}-host limit",
                not_asked - self.aborted
            ));
        }
        parts.join(", ")
    }

    fn section(&self) -> String {
        format!(
            "{RESOLVE_SOURCE}: {} addresses; {}",
            self.addresses,
            self.counts()
        )
    }
}

#[cfg(test)]
mod tests;
