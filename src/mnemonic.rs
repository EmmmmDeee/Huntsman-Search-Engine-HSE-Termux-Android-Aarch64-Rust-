//! Mnemonic passive DNS: every DNS answer Mnemonic's sensors have recorded for a domain or an
//! address, Spiderfoot's `sfp_mnemonic`.
//!
//! A lookup is a keyless `GET https://api.mnemonic.no/pdns/v3/{query}`, [`PAGE`] records a page
//! and at most [`MAX_PAGES`] pages, as Spiderfoot asks it. Every record is kept on the queried
//! indicator as published: the name, the type, the answer, when it was first and last seen, how
//! many times, its TTL range, its TLP and its flags. For a domain, each public address one of its
//! names answered with is an address, each name under it a name, and each name a CNAME, MX or NS
//! record points to a name it uses; for an address, each name that answered with it is a site
//! hosted there. Reverse-zone and wildcard records stay on the indicator only.
//!
//! Spiderfoot drops a record last seen more than 180 days ago by its `lastSeenTimestamp`, which
//! Mnemonic now leaves at 0 for many records, so those are all dropped. Here every record is
//! kept whatever its age, with its dates read from `firstSeenTimestamp` and `lastSeenTimestamp`
//! when Mnemonic set them, else from when it created and last updated the record.

use std::fmt::Write as _;
use std::net::IpAddr;

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, LegError};
use crate::canonical::{canonical_domain, canonical_ip};
use crate::domains::is_or_subdomain_of;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::http::Transport;
use crate::keys::Keys;
use crate::source_outcome::SourceExecutionOutcome;

pub const SOURCE: &str = "mnemonic";
pub const API: Api = Api {
    source: SOURCE,
    provider: "api.mnemonic.no",
    origin: "https://api.mnemonic.no:443",
    key: None,
};
/// Records asked for a page, as Spiderfoot asks.
pub const PAGE: usize = 500;
/// Pages asked at most, as Spiderfoot asks.
pub const MAX_PAGES: usize = 2;
/// Confidence of a name or address passive DNS ties to the indicator: it was true when seen.
const SEEN_CONFIDENCE: f64 = 0.60;

/// One page of answers.
#[derive(Debug, Deserialize)]
struct Page {
    /// How many records Mnemonic holds for the query, all pages together.
    #[serde(default)]
    count: usize,
    #[serde(default)]
    data: Vec<Record>,
}

/// One passive DNS record, as Mnemonic publishes it. Times are Unix milliseconds; 0 is unset.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub query: String,
    pub answer: String,
    pub rrtype: String,
    #[serde(default)]
    pub rrclass: Option<String>,
    #[serde(default)]
    pub times: Option<u64>,
    #[serde(default)]
    pub min_ttl: Option<u64>,
    #[serde(default)]
    pub max_ttl: Option<u64>,
    #[serde(default)]
    pub first_seen_timestamp: Option<i64>,
    #[serde(default)]
    pub last_seen_timestamp: Option<i64>,
    #[serde(default)]
    pub created_timestamp: Option<i64>,
    #[serde(default)]
    pub last_updated_timestamp: Option<i64>,
    #[serde(default)]
    pub tlp: Option<String>,
    #[serde(default)]
    pub flags: Vec<String>,
}

impl Record {
    /// When the record was first seen: Mnemonic's first-seen time, else when it created the
    /// record. **Pure.**
    #[must_use]
    pub fn first_seen(&self) -> Option<String> {
        when(self.first_seen_timestamp, self.created_timestamp)
    }

    /// When the record was last seen: Mnemonic's last-seen time, else when it last updated the
    /// record. **Pure.**
    #[must_use]
    pub fn last_seen(&self) -> Option<String> {
        when(self.last_seen_timestamp, self.last_updated_timestamp)
    }

    /// The record on one line, everything it holds. **Pure.**
    #[must_use]
    pub fn line(&self) -> String {
        let mut line = format!("{} {} {}", self.query, self.rrtype, self.answer);
        let mut notes = Vec::new();
        match (self.first_seen(), self.last_seen()) {
            (Some(first), Some(last)) => notes.push(format!("seen {first} to {last}")),
            (Some(first), None) => notes.push(format!("first seen {first}")),
            (None, Some(last)) => notes.push(format!("last seen {last}")),
            (None, None) => {}
        }
        if let Some(times) = self.times {
            notes.push(format!("{times} times"));
        }
        match (self.min_ttl, self.max_ttl) {
            (Some(min), Some(max)) if min == max => notes.push(format!("TTL {min}")),
            (Some(min), Some(max)) => notes.push(format!("TTL {min}-{max}")),
            (Some(ttl), None) | (None, Some(ttl)) => notes.push(format!("TTL {ttl}")),
            (None, None) => {}
        }
        if let Some(class) = self.rrclass.as_deref().filter(|c| !c.is_empty()) {
            notes.push(format!("class {class}"));
        }
        if let Some(tlp) = self.tlp.as_deref().filter(|t| !t.is_empty()) {
            notes.push(format!("TLP {tlp}"));
        }
        if !self.flags.is_empty() {
            notes.push(self.flags.join(", "));
        }
        if !notes.is_empty() {
            let _ = write!(line, " ({})", notes.join("; "));
        }
        line
    }

    fn evidence(&self, source_attr: (&'static str, &str), scan_id: &str) -> Evidence {
        let mut evidence = Evidence::new(
            EvidenceProvenance::for_scan(SOURCE, scan_id),
            format!("passive DNS: {}", self.line()),
        )
        .with_attr(source_attr.0, source_attr.1)
        .with_attr("name", &self.query)
        .with_attr("rrtype", &self.rrtype)
        .with_attr("answer", &self.answer);
        if let Some(first) = self.first_seen() {
            evidence = evidence.with_attr("first_seen", first);
        }
        if let Some(last) = self.last_seen() {
            evidence = evidence.with_attr("last_seen", last);
        }
        if let Some(times) = self.times {
            evidence = evidence.with_attr("times", times.to_string());
        }
        evidence
    }
}

/// A Unix-millisecond time as `YYYY-MM-DDTHH:MM:SSZ`, the first that is set. **Pure.**
fn when(first: Option<i64>, second: Option<i64>) -> Option<String> {
    first
        .filter(|ms| *ms > 0)
        .or(second.filter(|ms| *ms > 0))
        .map(|ms| crate::timefmt::format_unix(ms.div_euclid(1_000)))
}

/// What Mnemonic holds for one query: the records read and how many it holds in all.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Answers {
    pub records: Vec<Record>,
    pub count: usize,
    /// Why a later page could not be read, when one could not.
    pub cut_short: Option<String>,
}

/// Every record Mnemonic holds for `query`, up to [`MAX_PAGES`] pages.
///
/// # Errors
/// The first page's failure; a later page's failure keeps what was read and says why in
/// [`Answers::cut_short`].
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    query: &str,
    now_unix: u64,
) -> Result<Answers, LegError> {
    let mut answers = Answers::default();
    for page in 0..MAX_PAGES {
        let url = format!(
            "https://api.mnemonic.no/pdns/v3/{query}?limit={PAGE}&offset={}",
            page * PAGE
        );
        let read =
            api_leg::get(transport, &API, &Keys::default(), &url, now_unix).and_then(|answer| {
                match answer {
                    Answer::Body(body) | Answer::NotFound(body) => api_leg::decode::<Page>(&body),
                }
            });
        let read = match read {
            Ok(read) => read,
            Err(err) if page == 0 => return Err(err),
            Err(err) => {
                answers.cut_short = Some(format!("page {} could not be read: {err}", page + 1));
                break;
            }
        };
        let full = read.data.len() >= PAGE;
        answers.count = answers.count.max(read.count);
        answers.records.extend(read.data);
        if !full || answers.records.len() >= answers.count {
            break;
        }
    }
    answers.count = answers.count.max(answers.records.len());
    Ok(answers)
}

/// The leg's entities, its outcome row and, when the lookup failed, why.
#[derive(Debug, Default)]
pub struct Leg {
    pub entities: Vec<Entity>,
    pub outcome: Option<SourceExecutionOutcome>,
    pub error: Option<LegError>,
}

/// Passive DNS for `domain`: every record on the domain, each public address its names answered
/// with, each name under it, and each name a CNAME, MX or NS record of its names points to.
#[must_use]
pub fn domain<T: Transport + ?Sized>(
    transport: &T,
    domain: &str,
    scan_id: &str,
    now_unix: u64,
) -> Leg {
    if !transport.runs_module(SOURCE) {
        return Leg::default();
    }
    leg(lookup(transport, domain, now_unix), now_unix, |answers| {
        domain_entities(domain, answers, scan_id)
    })
}

/// Passive DNS for `ip`: every record on the address, and each name that answered with it.
#[must_use]
pub fn ip<T: Transport + ?Sized>(transport: &T, ip: &str, scan_id: &str, now_unix: u64) -> Leg {
    if !transport.runs_module(SOURCE) {
        return Leg::default();
    }
    let Ok(address) = ip.parse::<IpAddr>() else {
        return Leg::default();
    };
    leg(lookup(transport, ip, now_unix), now_unix, |answers| {
        ip_entities(address, answers, scan_id)
    })
}

fn leg(
    answers: Result<Answers, LegError>,
    now_unix: u64,
    entities: impl FnOnce(&Answers) -> Vec<Entity>,
) -> Leg {
    let answers = match answers {
        Ok(answers) => answers,
        Err(err) => {
            return Leg {
                entities: Vec::new(),
                outcome: Some(err.outcome(&API, now_unix)),
                error: Some(err),
            };
        }
    };
    if answers.records.is_empty() {
        return Leg {
            entities: Vec::new(),
            outcome: Some(SourceExecutionOutcome::valid_zero(SOURCE, now_unix)),
            error: None,
        };
    }
    let mut entities = entities(&answers);
    merge_by_uid(&mut entities);
    let outcome = SourceExecutionOutcome::success(SOURCE, now_unix, answers.records.len())
        .with_http_status(200);
    Leg {
        entities,
        outcome: Some(outcome),
        error: None,
    }
}

/// The queried indicator with every record on it. **Pure.**
fn seed(kind: EntityKind, value: &str, answers: &Answers, scan_id: &str) -> Entity {
    let lines: Vec<String> = answers.records.iter().map(Record::line).collect();
    let mut summary = format!(
        "Mnemonic passive DNS holds {} records for {value}",
        answers.count
    );
    if answers.records.len() < answers.count {
        let _ = write!(summary, "; the first {} are kept", answers.records.len());
    }
    let mut evidence = Evidence::new(EvidenceProvenance::for_scan(SOURCE, scan_id), summary)
        .with_attr("passive_dns", lines.join(" | "))
        .with_attr("passive_dns_records", answers.count.to_string())
        .with_attr("passive_dns_read", answers.records.len().to_string());
    if let Some(why) = &answers.cut_short {
        evidence = evidence.with_attr("passive_dns_cut_short", why);
    }
    let mut entity = Entity::new(kind, value, SEED_CONFIDENCE, scan_id);
    entity.add_evidence(evidence);
    entity
}

/// Confidence of the queried indicator.
const SEED_CONFIDENCE: f64 = 0.90;

/// A host name in canonical form, or `None` for a reverse-zone or wildcard name. **Pure.**
fn host(name: &str) -> Option<String> {
    canonical_domain(name).filter(|name| !is_or_subdomain_of(name, "arpa"))
}

fn is_address_type(rrtype: &str) -> bool {
    rrtype.eq_ignore_ascii_case("a") || rrtype.eq_ignore_ascii_case("aaaa")
}

/// Entities a domain's records give. **Pure.**
fn domain_entities(domain: &str, answers: &Answers, scan_id: &str) -> Vec<Entity> {
    let mut entities = vec![seed(EntityKind::Domain, domain, answers, scan_id)];
    for record in &answers.records {
        let Some(name) = host(&record.query) else {
            continue;
        };
        if !is_or_subdomain_of(&name, domain) {
            continue;
        }
        let evidence = record.evidence(("domain", domain), scan_id);
        if name != domain {
            push_entity(
                &mut entities,
                EntityKind::Domain,
                &name,
                SEEN_CONFIDENCE,
                scan_id,
                evidence.clone(),
                &[],
            );
        }
        let rrtype = record.rrtype.to_ascii_lowercase();
        if is_address_type(&rrtype) {
            if let Some(address) = canonical_ip(&record.answer) {
                push_entity(
                    &mut entities,
                    EntityKind::IpAddress,
                    &address,
                    SEEN_CONFIDENCE,
                    scan_id,
                    evidence,
                    &[],
                );
            }
        } else if matches!(rrtype.as_str(), "cname" | "mx" | "ns") {
            let target = record
                .answer
                .split_whitespace()
                .last()
                .and_then(host)
                .filter(|target| target != domain);
            if let Some(target) = target {
                push_entity(
                    &mut entities,
                    EntityKind::Domain,
                    &target,
                    SEEN_CONFIDENCE,
                    scan_id,
                    evidence,
                    &[],
                );
            }
        }
    }
    entities
}

/// Entities an address's records give. **Pure.**
fn ip_entities(address: IpAddr, answers: &Answers, scan_id: &str) -> Vec<Entity> {
    let value = address.to_string();
    let mut entities = vec![seed(EntityKind::IpAddress, &value, answers, scan_id)];
    for record in &answers.records {
        if !is_address_type(&record.rrtype) {
            continue;
        }
        if record.answer.trim().parse::<IpAddr>().ok() != Some(address) {
            continue;
        }
        let Some(name) = host(&record.query) else {
            continue;
        };
        push_entity(
            &mut entities,
            EntityKind::Domain,
            &name,
            SEEN_CONFIDENCE,
            scan_id,
            record.evidence(("ip", &value), scan_id),
            &[],
        );
    }
    entities
}

#[cfg(test)]
mod tests;
