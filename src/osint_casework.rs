//! Source-first offline OSINT case review. No remote service or identity inference.
//! A report records user-supplied assertions; it does not establish independent facts.

use std::collections::{BTreeMap, BTreeSet};
use serde::{Deserialize, Serialize};
use crate::error::Error;
use crate::sha256::{sha256, hex32};

pub const MAX_CASE_BYTES: usize = 256 * 1024;
const MAX_ROWS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub id: String,
    pub subject: String,
    pub predicate: String,
    pub value: String,
    pub source_url: String,
    pub source_root: String,
    pub observed_at_unix: u64,
    #[serde(default)]
    pub event_at_unix: Option<i64>,
    #[serde(default)]
    pub content_sha256: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseInput {
    pub case_id: String,
    pub observations: Vec<Observation>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Receipt {
    pub id: String,
    pub source_url: String,
    pub source_root: String,
    pub url_host: String,
    pub observed_at_unix: u64,
    pub metadata_sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClaimReview {
    pub subject: String,
    pub predicate: String,
    pub event_at_unix: Option<i64>,
    pub values: Vec<String>,
    pub observation_ids: Vec<String>,
    pub declared_roots: Vec<String>,
    pub url_hosts: Vec<String>,
    pub status: &'static str,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TimelineCue {
    pub event_at_unix: i64,
    pub id: String,
    pub subject: String,
    pub predicate: String,
    pub value: String,
    pub source_url: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NextAction {
    pub priority: u8,
    pub objective: &'static str,
    pub subject: String,
    pub predicate: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaseReview {
    pub case_id: String,
    pub observations: usize,
    pub receipts: Vec<Receipt>,
    pub claims: Vec<ClaimReview>,
    pub timeline: Vec<TimelineCue>,
    pub next_actions: Vec<NextAction>,
    pub evidence_status: &'static str,
}

fn field(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn normal(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}
/// Refuse secret-bearing user-provided URLs that could leak into exported dossiers.
/// # Errors
/// Invalid or credential-bearing URLs.
pub(crate) fn validate_public_source_url(value: &str) -> Result<(), Error> {
    if !field(value, 2048) || !value.starts_with("https://") {
        return Err(Error::invalid("source URL must use HTTPS"));
    }
    let uri = crate::http::parse_http_uri(value)
        .map_err(|_| Error::invalid("invalid evidence URL"))?;
    if uri.scheme_str() != Some("https") || uri.host().is_none()
        || uri.authority().is_some_and(|a| a.as_str().contains('@'))
    {
        return Err(Error::invalid("credential-bearing or invalid evidence URL"));
    }
    if uri.query().is_some_and(|query| query.split('&').any(|param| {
        let key = param.split('=').next().unwrap_or("").to_ascii_lowercase();
        ["key", "token", "secret", "password", "authorization", "auth"]
            .iter().any(|term| key.contains(term))
    })) {
        return Err(Error::invalid("sensitive parameter in evidence URL"));
    }
    Ok(())
}
fn receipt_hash(row: &Observation) -> String {
    let mut bytes = b"huntsman-case-metadata-v1\0".to_vec();
    for text in [&row.id, &row.subject, &row.predicate, &row.value,
        &row.source_url, &row.source_root]
    {
        bytes.extend_from_slice(&(text.len() as u64).to_be_bytes());
        bytes.extend_from_slice(text.as_bytes());
    }
    bytes.extend_from_slice(&row.observed_at_unix.to_be_bytes());
    if let Some(at) = row.event_at_unix {
        bytes.push(1);
        bytes.extend_from_slice(&at.to_be_bytes());
    } else {
        bytes.push(0);
    }
    if let Some(hash) = &row.content_sha256 {
        bytes.extend_from_slice(&(hash.len() as u64).to_be_bytes());
        bytes.extend_from_slice(hash.as_bytes());
    } else {
        bytes.extend_from_slice(&0u64.to_be_bytes());
    }
    hex32(&sha256(&bytes))
}
/// Analyze imported source records with deterministic receipts, conflicts and chronology.
/// Values at different event times do not conflict.
/// # Errors
/// Invalid imported records.
pub fn review(input: &CaseInput) -> Result<CaseReview, Error> {
    if !field(&input.case_id, 128) || input.observations.len() > MAX_ROWS {
        return Err(Error::invalid("invalid case name or too many records"));
    }
    let mut ids = BTreeSet::new();
    let mut grouped: BTreeMap<(String, String, Option<i64>), Vec<&Observation>> = BTreeMap::new();
    let mut receipts = Vec::new();
    let mut timeline = Vec::new();
    for row in &input.observations {
        if !field(&row.id, 128) || !field(&row.subject, 512)
            || !field(&row.predicate, 128) || !field(&row.value, 4096)
            || !field(&row.source_root, 256) || !ids.insert(row.id.as_str())
        {
            return Err(Error::invalid("missing, duplicate or unbounded observation field"));
        }
        validate_public_source_url(&row.source_url)?;
        if row.content_sha256.as_ref().is_some_and(|hash| hash.len() != 64
            || !hash.bytes().all(|c| c.is_ascii_hexdigit()))
        {
            return Err(Error::invalid("invalid document digest"));
        }
        let url_host = crate::http::parse_http_uri(&row.source_url)
            .ok().and_then(|uri| uri.host().map(str::to_ascii_lowercase))
            .unwrap_or_default();
        receipts.push(Receipt {
            id: row.id.clone(), source_url: row.source_url.clone(),
            source_root: row.source_root.clone(), url_host,
            observed_at_unix: row.observed_at_unix,
            metadata_sha256: receipt_hash(row),
        });
        grouped.entry((normal(&row.subject), normal(&row.predicate), row.event_at_unix))
            .or_default().push(row);
        if let Some(at) = row.event_at_unix {
            timeline.push(TimelineCue {event_at_unix: at, id: row.id.clone(),
                subject: row.subject.clone(), predicate: row.predicate.clone(),
                value: row.value.clone(), source_url: row.source_url.clone()});
        }
    }
    receipts.sort_by(|a,b| a.id.cmp(&b.id));
    timeline.sort_by(|a,b| (a.event_at_unix, &a.id).cmp(&(b.event_at_unix, &b.id)));
    let mut claims = Vec::new();
    let mut next_actions = Vec::new();
    for ((subject, predicate, event_at_unix), rows) in grouped {
        let values: BTreeSet<_> = rows.iter().map(|r| normal(&r.value)).collect();
        let roots: BTreeSet<_> = rows.iter().map(|r| normal(&r.source_root)).collect();
        let hosts: BTreeSet<_> = rows.iter().filter_map(|r|
            crate::http::parse_http_uri(&r.source_url).ok()
                .and_then(|uri| uri.host().map(str::to_ascii_lowercase))).collect();
        let observation_ids: BTreeSet<_> = rows.iter().map(|r| r.id.clone()).collect();
        let (status, priority, objective) = if values.len() > 1 {
            ("conflicting_accounts", 1, "resolve_competing_source_claims")
        } else if roots.len() == 1 {
            ("single_declared_origin", 2, "seek_independent_primary_source")
        } else {
            ("multiple_declared_origins_unverified", 3, "verify_publication_independence")
        };
        claims.push(ClaimReview {subject: subject.clone(), predicate: predicate.clone(),
            event_at_unix, values: values.into_iter().collect(),
            observation_ids: observation_ids.into_iter().collect(),
            declared_roots: roots.into_iter().collect(), url_hosts: hosts.into_iter().collect(),
            status});
        next_actions.push(NextAction {priority, objective, subject, predicate});
    }
    next_actions.sort_by(|a,b| (a.priority, &a.subject, &a.predicate)
        .cmp(&(b.priority, &b.subject, &b.predicate)));
    Ok(CaseReview {case_id: input.case_id.clone(), observations: receipts.len(),
        receipts, claims, timeline, next_actions,
        evidence_status: "unverified_source_assertions_not_independent_corroboration"})
}
/// Parse an input with strict JSON schema and a 256 KiB memory bound.
/// # Errors
/// Oversized input or invalid case record.
pub fn review_json(bytes: &[u8]) -> Result<CaseReview, Error> {
    if bytes.len() > MAX_CASE_BYTES {
        return Err(Error::invalid("OSINT case exceeds 256 KiB"));
    }
    let input: CaseInput = serde_json::from_slice(bytes)
        .map_err(|_| Error::invalid("invalid case JSON"))?;
    review(&input)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn one_origin_is_not_corroboration_and_conflicts_have_priority() {
        let json = br#"{"case_id":"demo","observations":[
          {"id":"a","subject":"example","predicate":"owner","value":"Alice","source_url":"https://example.org/1","source_root":"registry","observed_at_unix":1,"event_at_unix":12},
          {"id":"b","subject":"example","predicate":"owner","value":"Bob","source_url":"https://example.org/2","source_root":"registry","observed_at_unix":2,"event_at_unix":12}
        ]}"#;
        let report = review_json(json).unwrap();
        assert_eq!(report.claims[0].status, "conflicting_accounts");
        assert_eq!(report.next_actions[0].priority, 1);
        assert_eq!(report.timeline.len(), 2);
    }
    #[test]
    fn refuses_credentials_and_duplicates() {
        let json = br#"{"case_id":"demo","observations":[
          {"id":"a","subject":"x","predicate":"y","value":"z","source_url":"https://user:pw@example.org","source_root":"x","observed_at_unix":1}
        ]}"#;
        assert!(review_json(json).is_err());
    }
}
