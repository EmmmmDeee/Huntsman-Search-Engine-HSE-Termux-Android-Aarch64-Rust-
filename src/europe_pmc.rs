//! Europe PMC public biomedical-literature discovery for Huntsman/HSE.
//!
//! One bounded, anonymous HTTPS REST request. A publication hit is a source-indexed
//! lead, not verification of the article's scientific claims, an author's identity,
//! an affiliation, or the subject of the operator's query. Never pivot on bylines.
//! No runtime LLM, new crate, credentials, paginated crawl or unbounded fan-out.

use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::Value;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Transport, append_query_param};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const SOURCE: &str = "europe_pmc";
pub const SEARCH_URL: &str = "https://www.ebi.ac.uk/europepmc/webservices/rest/search";
const MAX_RESULTS: usize = 8;
const MAX_QUERY_BYTES: usize = 160;
const MAX_TITLE_BYTES: usize = 512;
const MAX_FIELD_BYTES: usize = 2_048;

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub query: String,
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
    pub hit_count: Option<u64>,
    pub truncated: bool,
    pub evidence_role: &'static str,
}

fn empty(query: &str, outcome: SourceExecutionOutcome) -> Report {
    Report {
        query: query.to_owned(),
        entities: Vec::new(),
        outcomes: vec![outcome],
        hit_count: None,
        truncated: false,
        evidence_role: "unverified_scholarly_publication_leads",
    }
}

/// Refuse control characters before trimming (including a hidden leading newline).
fn checked_query(raw: &str) -> Result<&str, Error> {
    if raw.is_empty() || raw.len() > MAX_QUERY_BYTES || raw.chars().any(char::is_control) {
        return Err(Error::invalid("Europe PMC query must be 1..160 bytes, without controls"));
    }
    let value = raw.trim();
    if value.is_empty() {
        return Err(Error::invalid("Europe PMC query must not be blank"));
    }
    Ok(value)
}

fn clean<'a>(value: Option<&'a Value>, max_bytes: usize) -> Option<&'a str> {
    let value = value?.as_str()?.trim();
    (!value.is_empty()
        && value.len() <= max_bytes
        && !value.chars().any(char::is_control))
    .then_some(value)
}

/// Only canonical, path-safe article IDs are used to construct source URLs.
fn valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn valid_source(source: &str) -> bool {
    (1..=10).contains(&source.len())
        && source
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

fn optional_field(mut ev: Evidence, row: &Value, key: &str, dest: &str) -> Evidence {
    if let Some(value) = row.get(key) {
        match clean(Some(value), MAX_FIELD_BYTES) {
            Some(text) => ev = ev.with_attr(dest, text),
            None => ev = ev.with_attr("metadata_not_retained", key),
        }
    }
    ev
}

/// Parse a complete source response with fail-closed schema and zero semantics.
fn interpret(
    fetched: &Fetched,
    query: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, SourceExecutionOutcome> {
    let response = whole_response(fetched, "Europe PMC")?;
    answer(fetched, "Europe PMC")?;
    let data: Value = decode_json(response, SOURCE, now_unix, "Europe PMC")?;
    let drift = |kind, detail: &'static str| {
        SourceExecutionOutcome::failed(SOURCE, now_unix, kind, Some(response.status), detail)
    };

    if data.get("errCode").is_some() || data.get("error").is_some() {
        return Err(drift(
            SourceOutcomeKind::SemanticDrift,
            "Europe PMC returned an error envelope instead of literature results",
        ));
    }
    let request = data.get("request");
    if request
        .and_then(|r| r.get("queryString"))
        .and_then(Value::as_str)
        != Some(query)
        || request
            .and_then(|r| r.get("pageSize"))
            .and_then(Value::as_u64)
            != Some(MAX_RESULTS as u64)
        || request
            .and_then(|r| r.get("resultType"))
            .and_then(Value::as_str)
            != Some("lite")
    {
        return Err(drift(
            SourceOutcomeKind::SchemaDrift,
            "Europe PMC response lacks matching query, page size or result type",
        ));
    }

    let Some(total) = data.get("hitCount").and_then(Value::as_u64) else {
        return Err(drift(
            SourceOutcomeKind::SchemaDrift,
            "Europe PMC response lacks an integer hitCount",
        ));
    };
    let Some(rows) = data.pointer("/resultList/result").and_then(Value::as_array) else {
        return Err(drift(
            SourceOutcomeKind::SchemaDrift,
            "Europe PMC response lacks resultList.result array",
        ));
    };
    if rows.len() > MAX_RESULTS || (rows.len() as u64) > total {
        return Err(drift(
            SourceOutcomeKind::SchemaDrift,
            "Europe PMC article list exceeds requested page or reported hit count",
        ));
    }
    if rows.is_empty() {
        if total == 0 {
            return Ok(Report {
                query: query.to_owned(),
                entities: Vec::new(),
                outcomes: vec![
                    SourceExecutionOutcome::valid_zero(SOURCE, now_unix)
                        .with_http_status(response.status),
                ],
                hit_count: Some(0),
                truncated: false,
                evidence_role: "unverified_scholarly_publication_leads",
            });
        }
        return Err(drift(
            SourceOutcomeKind::ZeroYieldAnomaly,
            "Europe PMC reports matches but returned an empty requested page",
        ));
    }

    let mut entities = Vec::with_capacity(rows.len());
    let mut ids = BTreeSet::new();
    for row in rows {
        let (Some(id), Some(source), Some(title)) = (
            clean(row.get("id"), 64),
            clean(row.get("source"), 10),
            clean(row.get("title"), MAX_TITLE_BYTES),
        ) else {
            return Err(drift(
                SourceOutcomeKind::SchemaDrift,
                "Europe PMC article lacks a bounded id, source or title",
            ));
        };
        if !valid_id(id) || !valid_source(source) || !ids.insert((source, id)) {
            return Err(drift(
                SourceOutcomeKind::SchemaDrift,
                "Europe PMC article ID/source is invalid or repeated",
            ));
        }
        let url = format!("https://europepmc.org/article/{source}/{id}");
        let mut evidence = Evidence::new(
            EvidenceProvenance::for_scan(SOURCE, scan_id),
            "Europe PMC literature index hit; publication and byline are leads, not independently verified identity, attribution or scientific claims",
        )
        .with_attr("source_url", &url)
        .with_attr("article_id", id)
        .with_attr("record_source", source)
        .with_attr("title", title)
        .with_attr("source_query", query)
        .with_attr("evidence_role", "unverified_scholarly_publication_lead");

        for (key, attr) in [
            ("doi", "doi"),
            ("pmid", "pmid"),
            ("pmcid", "pmcid"),
            ("authorString", "printed_bylines_unverified"),
            ("journalTitle", "journal_title"),
            ("pubType", "publication_type"),
            ("firstPublicationDate", "first_publication_date"),
            ("pubYear", "publication_year"),
            ("isOpenAccess", "open_access_flag"),
        ] {
            evidence = optional_field(evidence, row, key, attr);
        }
        if let Some(count) = row.get("citedByCount").and_then(Value::as_u64) {
            evidence = evidence.with_attr("reported_citation_count", count.to_string());
        }
        push_entity(
            &mut entities,
            EntityKind::Url,
            &url,
            0.35,
            scan_id,
            evidence,
            &["europe-pmc", "biomedical", "literature-lead"],
        );
    }
    let found = entities.len();
    Ok(Report {
        query: query.to_owned(),
        entities,
        outcomes: vec![
            SourceExecutionOutcome::success(SOURCE, now_unix, found)
                .with_http_status(response.status),
        ],
        hit_count: Some(total),
        truncated: total > found as u64,
        evidence_role: "unverified_scholarly_publication_leads",
    })
}

/// One guarded Europe PMC REST call, without a credential or automated pivots.
///
/// # Errors
/// A malformed query or an outbound transport refusal.
pub fn search<T: Transport + ?Sized>(
    transport: &T,
    query: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let query = checked_query(query)?;
    let mut url = append_query_param(SEARCH_URL, "query", query);
    for (key, value) in [
        ("format", "json"),
        ("resultType", "lite"),
        ("pageSize", "8"),
    ] {
        url = append_query_param(&url, key, value);
    }
    let fetched = fetch(
        transport,
        Request::get(url)
            .header("accept", "application/json")
            .header("user-agent", crate::http::DEFAULT_USER_AGENT),
        None,
        &FetchOptions::no_redirects().paced(),
        SOURCE,
        now_unix,
    )?;
    Ok(interpret(&fetched, query, scan_id, now_unix)
        .unwrap_or_else(|outcome| empty(query, outcome)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::OneResponse;

    fn body(rows: &str, hits: u64) -> String {
        format!(
            r#"{{"version":"6.9","hitCount":{hits},
            "request":{{"queryString":"gene editing","resultType":"lite",
                        "pageSize":8,"sort":"","synonym":false}},
            "resultList":{{"result":{rows}}}}}"#
        )
    }

    #[test]
    fn publication_leads_do_not_become_people_or_verified_claims() {
        let records = r#"[{"id":"42994815","source":"MED","pmid":"42994815",
            "doi":"10.1038/s41586-026-11233-9",
            "title":"In Vivo Gene Editing",
            "authorString":"Mizoguchi T, DeNizio JE",
            "pubYear":"2026","journalTitle":"Nature","citedByCount":0}]"#;
        let report = search(
            &OneResponse::json(200, &body(records, 25)),
            "gene editing",
            "scan-epmc",
            10,
        )
        .expect("search");
        assert_eq!(report.entities.len(), 1);
        assert_eq!(report.hit_count, Some(25));
        assert!(report.truncated);
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::Success);
        assert_eq!(report.entities[0].kind, EntityKind::Url);
        assert_eq!(
            report.entities[0].raw_value,
            "https://europepmc.org/article/MED/42994815"
        );
        let evidence = &report.entities[0].evidence[0];
        assert_eq!(
            evidence.attributes.get("printed_bylines_unverified").map(String::as_str),
            Some("Mizoguchi T, DeNizio JE")
        );
        assert!(report.entities.iter().all(|entity| entity.kind != EntityKind::Person));
    }

    #[test]
    fn zero_only_when_explicit_query_matched_complete_empty_page() {
        let zero = search(
            &OneResponse::json(200, &body("[]", 0)),
            "gene editing",
            "scan-epmc",
            10,
        )
        .expect("search");
        assert_eq!(zero.outcomes[0].kind, SourceOutcomeKind::ValidZero);
        for payload in [
            body("[]", 3),
            body(r#"[{"id":"1","source":"MED","title":"A"}]"#, 0),
            r#"{"hitCount":0,"resultList":{"result":[]}}"#.to_owned(),
            body(r#"[{"id":"1","source":"MED"}]"#, 1),
            body(r#"[{"id":"../escape","source":"MED","title":"A"}]"#, 1),
            body(r#"[{"id":"1","source":"MED","title":"A"},
                     {"id":"1","source":"MED","title":"B"}]"#, 2),
        ] {
            let report = search(
                &OneResponse::json(200, &payload),
                "gene editing",
                "scan-epmc",
                10,
            )
            .expect("search");
            assert!(report.entities.is_empty(), "misleading result from {payload}");
            assert!(!report.outcomes[0].kind.is_accepted(), "{payload}");
        }
    }

    #[test]
    fn a_result_for_a_different_query_never_creates_an_entity() {
        let rows = r#"[{"id":"1","source":"MED","title":"Unrelated Result"}]"#;
        let mismatch = search(
            &OneResponse::json(200, &body(rows, 1)),
            "different query",
            "scan-epmc",
            10,
        )
        .expect("search");
        assert!(mismatch.entities.is_empty());
        assert_eq!(mismatch.outcomes[0].kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn upstream_error_envelopes_are_not_valid_zero_results() {
        let error = r#"{"errCode":500,"errMsg":"upstream temporarily unavailable",
            "hitCount":0,
            "request":{"queryString":"gene editing","resultType":"lite","pageSize":8},
            "resultList":{"result":[]}}"#;
        let report = search(
            &OneResponse::json(200, error),
            "gene editing",
            "scan-epmc",
            10,
        )
        .expect("search");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::SemanticDrift);
        assert!(!report.outcomes[0].kind.is_accepted());
    }

    #[test]
    fn raw_input_controls_are_rejected_before_trimming() {
        assert!(checked_query("\n gene editing").is_err());
        assert!(checked_query("gene\t editing").is_err());
        assert!(checked_query("   ").is_err());
        assert!(checked_query(&"x".repeat(161)).is_err());
        assert!(checked_query("gene editing").is_ok());
    }
}
