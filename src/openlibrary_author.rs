//! Bounded public Open Library authorship *leads*, not person/identity matches.
//!
//! One guarded, keyless HTTPS request uses Open Library's published Authors API.
//! Two catalogue entries with the same display name remain two distinct leads.
//! No account ownership, biography, date of birth, or family relationship is inferred.

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_name;
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Transport, append_query_param};
use crate::people_cli;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const SRC: &str = "openlibrary_author";
pub const MAX_LEADS: usize = 5;
const API: &str = "https://openlibrary.org/search/authors.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Lead {
    pub id: String,
    pub name: String,
    pub url: String,
    pub work_count: Option<u64>,
    pub top_work: Option<String>,
    pub status: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub leads: Vec<Lead>,
    pub outcome: SourceExecutionOutcome,
    pub total_reported: Option<usize>,
    pub total_exact: bool,
    pub truncated: bool,
}

#[derive(Debug, Deserialize)]
struct Envelope {
    #[serde(rename = "numFound")]
    num_found: Option<usize>,
    #[serde(rename = "numFoundExact")]
    num_found_exact: Option<bool>,
    docs: Option<Vec<Author>>,
}

#[derive(Debug, Deserialize)]
struct Author {
    key: Option<String>,
    name: Option<String>,
    work_count: Option<u64>,
    top_work: Option<String>,
}

/// Preserve source errors when this optional acquisition leg is unreachable.
/// Other people-discovery facets must keep their own outcomes and leads.
#[must_use]
pub fn unavailable(now_unix: u64, reason: &str) -> Report {
    Report {
        leads: Vec::new(),
        outcome: SourceExecutionOutcome::inconclusive(SRC, now_unix, reason),
        total_reported: None,
        total_exact: false,
        truncated: false,
    }
}

fn valid_author_id(id: &str) -> bool {
    let Some(numbers) = id.strip_prefix("OL").and_then(|id| id.strip_suffix('A')) else {
        return false;
    };
    (1..=16).contains(&numbers.len()) && numbers.bytes().all(|byte| byte.is_ascii_digit())
}

/// Search the public author catalogue once. Results are candidates, not verified
/// connections to the name entered; no secondary person pivots are performed.
///
/// # Errors
/// Invalid/unbounded input or failure at the guarded HTTP transport boundary.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    raw_name: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    if raw_name.len() > 120
        || raw_name
            .chars()
            .any(|character| character.is_control() || matches!(character, '"' | '\\' | '<' | '>'))
    {
        return Err(Error::Invalid("invalid bounded bibliographic author name".into()));
    }
    let name = canonical_name(raw_name);
    if !people_cli::is_name(&name) {
        return Err(Error::Invalid("bibliography requires a full personal name".into()));
    }
    let url = append_query_param(
        &append_query_param(API, "q", &name),
        "limit",
        &MAX_LEADS.to_string(),
    );
    let fetched = fetch(
        transport,
        Request::get(url)
            .header("accept", "application/json")
            .header("user-agent", crate::http::DEFAULT_USER_AGENT),
        None,
        &FetchOptions::no_redirects().paced(),
        SRC,
        now_unix,
    )?;
    Ok(interpret(&fetched, now_unix).unwrap_or_else(|outcome| Report {
        leads: Vec::new(),
        outcome,
        total_reported: None,
        total_exact: false,
        truncated: false,
    }))
}

/// One immutable response. Any malformed author row fails closed and leaks no
/// misleading subset; partial but well-formed searches preserve truncation.
fn interpret(fetched: &Fetched, now_unix: u64) -> Result<Report, SourceExecutionOutcome> {
    let response = whole_response(fetched, "Open Library")?;
    answer(fetched, "Open Library")?;
    let envelope: Envelope = decode_json(response, SRC, now_unix, "Open Library")?;
    let drift = |kind, detail: &str| {
        SourceExecutionOutcome::failed(SRC, now_unix, kind, Some(response.status), detail)
    };
    let (Some(total), Some(docs)) = (envelope.num_found, envelope.docs) else {
        return Err(drift(
            SourceOutcomeKind::SchemaDrift,
            "Open Library author response lacks numFound or docs",
        ));
    };
    let exact = envelope.num_found_exact == Some(true);
    if docs.is_empty() {
        if total == 0 && exact {
            return Ok(Report {
                leads: Vec::new(),
                outcome: SourceExecutionOutcome::valid_zero(SRC, now_unix)
                    .with_http_status(response.status),
                total_reported: Some(0),
                total_exact: true,
                truncated: false,
            });
        }
        return Err(drift(
            if total > 0 {
                SourceOutcomeKind::ZeroYieldAnomaly
            } else {
                SourceOutcomeKind::Inconclusive
            },
            "Open Library empty page is not a contract-validated zero",
        ));
    }
    if total < docs.len() {
        return Err(drift(
            SourceOutcomeKind::SchemaDrift,
            "Open Library documents exceed reported total",
        ));
    }
    let mut leads = Vec::new();
    for author in docs.iter().take(MAX_LEADS) {
        let (Some(id), Some(name)) = (author.key.as_deref(), author.name.as_deref()) else {
            return Err(drift(
                SourceOutcomeKind::SchemaDrift,
                "Open Library author row missing id or name",
            ));
        };
        let name = name.trim();
        if !valid_author_id(id)
            || name.is_empty()
            || name.chars().any(char::is_control)
        {
            return Err(drift(
                SourceOutcomeKind::SchemaDrift,
                "Open Library author row has invalid id or name",
            ));
        }
        leads.push(Lead {
            id: id.to_owned(),
            name: name.to_owned(),
            url: format!("https://openlibrary.org/authors/{id}"),
            work_count: author.work_count,
            top_work: author.top_work.clone(),
            status: "unverified_bibliographic_name_search_lead",
        });
    }
    let truncated = docs.len() > MAX_LEADS || total > leads.len() || !exact;
    Ok(Report {
        outcome: SourceExecutionOutcome::success(SRC, now_unix, leads.len())
            .with_http_status(response.status),
        leads,
        total_reported: Some(total),
        total_exact: exact,
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{OneResponse, ScriptedTransport};

    #[test]
    fn distinct_catalogue_authors_with_same_name_are_not_merged() {
        let body = r#"{"numFound":2,"numFoundExact":true,"docs":[
            {"key":"OL776398A","name":"Ada Lovelace","work_count":4,"top_work":"Ada: The Enchantress of Numbers"},
            {"key":"OL8288549A","name":"Ada Lovelace","work_count":3}
        ]}"#;
        let report = lookup(&OneResponse::json(200, body), "Ada Lovelace", 1).unwrap();
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert_eq!(report.outcome.found, Some(2));
        assert_eq!(report.leads.len(), 2);
        assert_ne!(report.leads[0].id, report.leads[1].id);
        assert!(!report.truncated);
        assert!(report
            .leads
            .iter()
            .all(|lead| lead.status == "unverified_bibliographic_name_search_lead"));
    }

    #[test]
    fn absence_requires_exact_zero_and_schema_conflicts_are_not_misses() {
        for body in [
            r#"{"numFound":1,"numFoundExact":true,"docs":[]}"#,
            r#"{"numFound":0,"numFoundExact":false,"docs":[]}"#,
            r#"{"numFound":0,"docs":[]}"#,
            r#"{"numFound":1,"numFoundExact":true,"docs":[{"name":"Ada Lovelace"}]}"#,
            r#"{"numFound":0,"numFoundExact":true,"docs":[{"key":"OL776398A","name":"Ada Lovelace"}]}"#,
        ] {
            let report = lookup(&OneResponse::json(200, body), "Ada Lovelace", 1).unwrap();
            assert!(!report.outcome.is_accepted(), "{body}");
            assert!(report.leads.is_empty(), "{body}");
        }
        let zero = lookup(
            &OneResponse::json(200, r#"{"numFound":0,"numFoundExact":true,"docs":[]}"#),
            "Ada Lovelace",
            1,
        )
        .unwrap();
        assert_eq!(zero.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn nonzero_upstream_total_is_explicitly_incomplete_not_a_negative() {
        let body = r#"{"numFound":18,"numFoundExact":true,"docs":[
            {"key":"OL776398A","name":"Ada Lovelace"}
        ]}"#;
        let report = lookup(&OneResponse::json(200, body), "Ada Lovelace", 1).unwrap();
        assert_eq!(report.total_reported, Some(18));
        assert!(report.truncated);
        assert_eq!(report.leads.len(), 1);
        assert_eq!(report.outcome.found, Some(1));
    }

    #[test]
    fn unsafe_selector_never_creates_a_network_request() {
        let transport = ScriptedTransport::new(Vec::new());
        for selector in ["Ada", "Ada\nLovelace", "Ada <Lovelace>", "Ada \"Lovelace\""] {
            assert!(lookup(&transport, selector, 1).is_err(), "{selector:?}");
        }
        assert!(transport.seen.borrow().is_empty());
    }
}