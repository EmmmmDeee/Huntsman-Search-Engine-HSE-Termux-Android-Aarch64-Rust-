//! Offline, conservative comparison of imported domain observations.
//! Imported provenance is an assertion, not source authentication. No network I/O.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_domain;
use crate::error::Error;
use crate::http::parse_http_uri;

pub const MAX_INPUT_BYTES: u64 = 2_097_152;
pub const MAX_OBSERVATIONS: usize = 4096;
pub const USAGE: &str = "domain-lifecycle analyze INPUT.json --as-of UNIX_SECONDS [--output REPORT.json]\nOffline comparison of imported observations; makes no network requests. Ownership and registration availability remain unknown.";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    Dns,
    ContentDigest,
    Category,
    RegistrationStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Challenge,
    Timeout,
    RateLimited,
    AuthenticationFailure,
    ParseDrift,
    Unavailable,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub id: String,
    pub host: String,
    pub provider: String,
    /// Explicit shared origin. Providers repeating this dataset do not form
    /// independent evidence or separate change series.
    pub upstream: String,
    pub source_url: String,
    pub retrieved_at: u64,
    pub event_at: Option<u64>,
    pub outcome: Outcome,
    pub truncated: bool,
    pub kind: ObservationKind,
    /// DNS record type; exact page URL; vendor taxonomy; registry status scope.
    pub scope: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub schema_version: u32,
    pub domain: String,
    pub observations: Vec<Observation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub kind: &'static str,
    pub scope: String,
    pub upstream: String,
    pub before: String,
    pub after: String,
    pub interval: [u64; 2],
    pub evidence_ids: Vec<String>,
    pub alternatives: Vec<&'static str>,
    pub invalidation: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Conflict {
    pub kind: ObservationKind,
    pub scope: String,
    pub upstream: String,
    pub event_at: u64,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Gap {
    pub evidence_id: String,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub domain: String,
    pub as_of: u64,
    pub ownership: &'static str,
    pub availability: &'static str,
    pub evidence_basis: &'static str,
    pub timeline: Vec<Observation>,
    pub findings: Vec<Finding>,
    pub conflicts: Vec<Conflict>,
    pub coverage_gaps: Vec<Gap>,
}

fn invalid(message: &str) -> Error {
    Error::Invalid(message.into())
}

fn bounded_text(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn exact_domain(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.starts_with('.') || raw.ends_with("..") || raw.chars().any(char::is_whitespace) {
        return None;
    }
    canonical_domain(raw.strip_suffix('.').unwrap_or(raw))
}

fn dns_record(scope: &str, raw: &str) -> Result<String, Error> {
    match scope {
        "A" => raw
            .parse::<std::net::Ipv4Addr>()
            .map(|ip| ip.to_string())
            .map_err(|_| invalid("invalid IPv4 DNS record")),
        "AAAA" => raw
            .parse::<std::net::Ipv6Addr>()
            .map(|ip| ip.to_string())
            .map_err(|_| invalid("invalid IPv6 DNS record")),
        "NS" => exact_domain(raw).ok_or_else(|| invalid("invalid nameserver record")),
        "MX" => {
            let fields: Vec<_> = raw.split_whitespace().collect();
            if fields.len() != 2 {
                return Err(invalid("MX needs priority and host"));
            }
            let priority = fields[0]
                .parse::<u16>()
                .map_err(|_| invalid("invalid MX priority"))?;
            let host = if fields[1] == "." && priority == 0 {
                ".".to_owned()
            } else {
                exact_domain(fields[1]).ok_or_else(|| invalid("invalid MX host"))?
            };
            Ok(format!("{priority} {host}"))
        }
        _ => Ok(raw.to_owned()),
    }
}

fn validate(o: &mut Observation, domain: &str, as_of: u64) -> Result<(), Error> {
    o.host = exact_domain(&o.host).ok_or_else(|| invalid("invalid observation host"))?;
    if o.host != domain {
        return Err(invalid(
            "observation host differs from the exact input domain",
        ));
    }
    if !bounded_text(&o.id, 256)
        || !bounded_text(&o.provider, 256)
        || !bounded_text(&o.upstream, 256)
        || !bounded_text(&o.scope, 2048)
        || o.value.len() > 16_384
        || o.value.chars().any(|c| c.is_control() && c != '\n')
        || o.source_url.len() > 4096
        || parse_http_uri(&o.source_url).is_err()
    {
        return Err(invalid(
            "invalid, missing or oversized observation provenance/payload",
        ));
    }
    if o.retrieved_at > as_of || o.event_at.is_some_and(|t| t > o.retrieved_at) {
        return Err(invalid(
            "observation time is in the future or follows retrieval",
        ));
    }
    // Failure payloads remain coverage information, not interpreted values.
    if o.outcome != Outcome::Success || o.truncated {
        return Ok(());
    }
    if o.value.trim().is_empty() {
        return Err(invalid("successful observation needs a nonempty value"));
    }
    match o.kind {
        ObservationKind::Dns => {
            o.scope.make_ascii_uppercase();
            if !matches!(o.scope.as_str(), "A" | "AAAA" | "NS" | "MX" | "TXT" | "SOA") {
                return Err(invalid("unsupported DNS record scope"));
            }
            // Each line is one record. Reordering and duplicate records are not changes.
            let records: BTreeSet<String> = o
                .value
                .lines()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| dns_record(&o.scope, s))
                .collect::<Result<_, Error>>()?;
            o.value = records.into_iter().collect::<Vec<_>>().join("\n");
        }
        ObservationKind::ContentDigest => {
            let uri = parse_http_uri(&o.scope)?;
            if uri.host().and_then(exact_domain).as_deref() != Some(domain)
                || o.value.len() != 64
                || !o.value.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(invalid(
                    "content digest needs exact-host URL and SHA-256 hex value",
                ));
            }
            o.value.make_ascii_lowercase();
        }
        ObservationKind::Category | ObservationKind::RegistrationStatus => {}
    }
    Ok(())
}

/// Validation is all-or-nothing. Failed/truncated observations remain in the
/// timeline but cannot support change findings. No inference crosses datasets.
pub fn analyze(mut input: Input, as_of: u64) -> Result<Report, Error> {
    if input.schema_version != 1 || input.observations.len() > MAX_OBSERVATIONS {
        return Err(invalid("unsupported schema or observation limit exceeded"));
    }
    let domain = exact_domain(&input.domain).ok_or_else(|| invalid("invalid input domain"))?;
    let mut by_id = BTreeMap::new();
    for o in &mut input.observations {
        validate(o, &domain, as_of)?;
        if let Some(previous) = by_id.insert(o.id.clone(), o.clone()) {
            if previous != *o {
                return Err(invalid("duplicate observation ID has conflicting content"));
            }
        }
    }
    let mut timeline: Vec<_> = by_id.into_values().collect();
    timeline.sort_by_key(|o| (o.event_at, o.retrieved_at, o.id.clone()));
    let mut report = Report {
        schema_version: 1,
        domain,
        as_of,
        ownership: "unknown",
        availability: "unknown",
        evidence_basis: "imported assertions; provenance is not authenticated; changes describe observations, not causality",
        timeline,
        findings: Vec::new(),
        conflicts: Vec::new(),
        coverage_gaps: Vec::new(),
    };
    type SeriesKey = (ObservationKind, String, String);
    let mut series: BTreeMap<SeriesKey, BTreeMap<u64, Vec<&Observation>>> = BTreeMap::new();
    for o in &report.timeline {
        let reason = if o.truncated {
            Some("truncated")
        } else if o.outcome != Outcome::Success {
            Some("collection did not succeed")
        } else if o.event_at.is_none() {
            Some("event time unknown")
        } else {
            None
        };
        if let Some(reason) = reason {
            report.coverage_gaps.push(Gap {
                evidence_id: o.id.clone(),
                reason,
            });
            continue;
        }
        if let Some(time) = o.event_at {
            series
                .entry((o.kind.clone(), o.scope.clone(), o.upstream.clone()))
                .or_default()
                .entry(time)
                .or_default()
                .push(o);
        }
    }
    for ((kind, scope, upstream), times) in series {
        let mut conflicted = false;
        for (&time, rows) in &times {
            let values: BTreeSet<_> = rows.iter().map(|o| &o.value).collect();
            if values.len() > 1 {
                conflicted = true;
                report.conflicts.push(Conflict {
                    kind: kind.clone(),
                    scope: scope.clone(),
                    upstream: upstream.clone(),
                    event_at: time,
                    evidence_ids: rows.iter().map(|o| o.id.clone()).collect(),
                });
            }
        }
        // A conflicted series cannot silently choose a winner or bridge a conflict.
        if conflicted {
            continue;
        }
        let snapshots: Vec<_> = times.into_iter().collect();
        for pair in snapshots.windows(2) {
            let ((before_time, before), (after_time, after)) = (&pair[0], &pair[1]);
            if before[0].value == after[0].value {
                continue;
            }
            let (label, alternatives) = finding_details(&kind);
            report.findings.push(Finding {
                kind: label, scope: scope.clone(), upstream: upstream.clone(),
                before: before[0].value.clone(), after: after[0].value.clone(),
                interval: [*before_time, *after_time],
                evidence_ids: before.iter().chain(after.iter()).map(|o| o.id.clone()).collect(),
                alternatives,
                invalidation: "withdraw if supporting observations are removed, contradicted or found incomparable; no continuous state between snapshots is established",
            });
        }
    }
    Ok(report)
}

fn finding_details(kind: &ObservationKind) -> (&'static str, Vec<&'static str>) {
    match kind {
        ObservationKind::Dns => (
            "infrastructure_change",
            vec![
                "routine hosting or DNS administration",
                "collector representation drift",
            ],
        ),
        ObservationKind::ContentDigest => (
            "content_digest_change",
            vec![
                "ordinary page update or redesign",
                "dynamic content or collection differences",
            ],
        ),
        ObservationKind::Category => (
            "classification_change",
            vec!["vendor taxonomy or policy update", "site content change"],
        ),
        ObservationKind::RegistrationStatus => (
            "registration_status_change",
            vec![
                "routine registry lifecycle transition",
                "source representation change",
            ],
        ),
    }
}
