//! Bounded academic OSINT leads from the OpenAlex authors and Crossref works APIs.
//!
//! Public catalogue metadata is not evidence of a person's identity or authorship.
//! Every output is a source-scoped Document/URL lead tagged to block recursive
//! name-only pivots. No credential, new HTTP client, or runtime dependency is used.

use serde_json::Value;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Transport, append_query_param, percent_encode_unreserved};
use crate::lookup_report::{LookupReport, SourceReport};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const OPENALEX_SOURCE: &str = "openalex_author";
pub const CROSSREF_SOURCE: &str = "crossref_works";
const OPENALEX_API: &str = "https://api.openalex.org/authors";
const CROSSREF_API: &str = "https://api.crossref.org/works";
const LIMIT: usize = 5;
const MAX_QUERY_BYTES: usize = 120;

/// Check the original bytes, before trimming, so controls cannot vanish.
fn checked_query(raw: &str) -> Result<&str, Error> {
    if raw.len() > MAX_QUERY_BYTES
        || raw
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '\\' | '<' | '>'))
    {
        return Err(Error::invalid(
            "scholarly query must be 1..120 UTF-8 bytes without controls, quotes or HTML delimiters",
        ));
    }
    let query = raw.trim();
    if query.is_empty() {
        return Err(Error::invalid("scholarly query cannot be empty"));
    }
    Ok(query)
}

/// Two independent catalogue queries, with no identity coalescing.
///
/// A successful source reports catalogue search matches, not verified
/// attribution to the search subject. One provider's error never hides the
/// other provider's result. There is no automatic follow-on request.
///
/// # Errors
/// Invalid query input; individual network failures become typed outcomes.
pub fn search<T: Transport + ?Sized>(
    transport: &T,
    raw_query: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<LookupReport, Error> {
    let query = checked_query(raw_query)?;
    let mut result = LookupReport::default();
    for (source, leg) in [
        (
            OPENALEX_SOURCE,
            openalex(transport, query, scan_id, now_unix),
        ),
        (
            CROSSREF_SOURCE,
            crossref(transport, query, scan_id, now_unix),
        ),
    ] {
        match leg {
            Ok(report) => {
                result.entities.extend(report.entities);
                result.outcomes.push(report.outcome);
            }
            Err(error) => result.outcomes.push(SourceExecutionOutcome::of_leg_error(
                source, now_unix, &error,
            )),
        }
    }
    merge_by_uid(&mut result.entities);
    Ok(result)
}

fn read_json(
    fetched: &Fetched,
    source: &str,
    display: &str,
    now_unix: u64,
) -> Result<(Value, u16), SourceExecutionOutcome> {
    let response = whole_response(fetched, display)?;
    answer(fetched, display)?;
    let body: Value = decode_json(response, source, now_unix, display)?;
    Ok((body, response.status))
}

fn drift(source: &str, now_unix: u64, status: u16, problem: &str) -> SourceExecutionOutcome {
    SourceExecutionOutcome::failed(
        source,
        now_unix,
        SourceOutcomeKind::SchemaDrift,
        Some(status),
        problem,
    )
}

fn page_result(
    source: &str,
    now_unix: u64,
    status: u16,
    total: u64,
    page_rows: usize,
    entities: Vec<Entity>,
) -> SourceReport {
    let count = entities.len();
    if count == 0 {
        let kind = if total == 0 {
            SourceExecutionOutcome::valid_zero(source, now_unix)
        } else {
            SourceExecutionOutcome::failed(
                source,
                now_unix,
                SourceOutcomeKind::ZeroYieldAnomaly,
                Some(status),
                "provider reported matches but returned no usable lead",
            )
        };
        return SourceReport {
            entities,
            outcome: kind.with_http_status(status),
        };
    }
    let mut outcome =
        SourceExecutionOutcome::success(source, now_unix, count).with_http_status(status);
    if total > page_rows as u64 {
        outcome = outcome.with_detail("first bounded page only; more catalogue matches exist");
    }
    SourceReport { entities, outcome }
}

fn openalex<T: Transport + ?Sized>(
    transport: &T,
    query: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<SourceReport, Error> {
    let url = append_query_param(
        &append_query_param(OPENALEX_API, "search", query),
        "per_page",
        &LIMIT.to_string(),
    );
    let fetched = fetch(
        transport,
        Request::get(url)
            .header("accept", "application/json")
            .header("user-agent", crate::http::DEFAULT_USER_AGENT),
        None,
        &FetchOptions::no_redirects().paced(),
        OPENALEX_SOURCE,
        now_unix,
    )?;
    Ok(interpret_openalex(&fetched, query, scan_id, now_unix).unwrap_or_else(SourceReport::miss))
}

fn interpret_openalex(
    fetched: &Fetched,
    query: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<SourceReport, SourceExecutionOutcome> {
    let (body, status) = read_json(fetched, OPENALEX_SOURCE, "OpenAlex", now_unix)?;
    let total = body.pointer("/meta/count").and_then(Value::as_u64);
    let rows = body.get("results").and_then(Value::as_array);
    let (Some(total), Some(rows)) = (total, rows) else {
        return Err(drift(
            OPENALEX_SOURCE,
            now_unix,
            status,
            "missing OpenAlex count or results",
        ));
    };
    if rows.len() > LIMIT || total < rows.len() as u64 {
        return Err(drift(
            OPENALEX_SOURCE,
            now_unix,
            status,
            "inconsistent OpenAlex result counts",
        ));
    }
    if rows.is_empty() && total > 0 {
        return Err(SourceExecutionOutcome::failed(
            OPENALEX_SOURCE,
            now_unix,
            SourceOutcomeKind::ZeroYieldAnomaly,
            Some(status),
            "OpenAlex reports matches but returned an empty page",
        ));
    }
    let mut entities = Vec::with_capacity(rows.len());
    for row in rows {
        let id = row.get("id").and_then(Value::as_str);
        let label = row.get("display_name").and_then(Value::as_str);
        let (Some(id), Some(label)) = (id, label) else {
            return Err(drift(
                OPENALEX_SOURCE,
                now_unix,
                status,
                "OpenAlex author missing id or name",
            ));
        };
        let author_id = id.strip_prefix("https://openalex.org/A");
        let valid_id = author_id
            .is_some_and(|n| (1..=20).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_digit()));
        if !valid_id
            || label.trim().is_empty()
            || label.len() > 240
            || label.chars().any(char::is_control)
        {
            return Err(drift(
                OPENALEX_SOURCE,
                now_unix,
                status,
                "invalid OpenAlex author id or name",
            ));
        }
        let mut evidence = Evidence::new(
            EvidenceProvenance::for_scan(OPENALEX_SOURCE, scan_id),
            "OpenAlex author search lead; matching name does not prove identity",
        )
        .with_attr("query", query)
        .with_attr("source_url", id)
        .with_attr("display_name", label)
        .with_attr("attribution", "unverified_name_search_lead");
        if let Some(works) = row.get("works_count").and_then(Value::as_u64) {
            evidence = evidence.with_attr("works_count", works.to_string());
        }
        if let Some(orcid) = row.get("orcid").and_then(Value::as_str) {
            if orcid.starts_with("https://orcid.org/")
                && orcid.len() <= 64
                && !orcid.chars().any(char::is_control)
            {
                evidence = evidence.with_attr("orcid_claim", orcid);
            }
        }
        push_entity(
            &mut entities,
            EntityKind::Url,
            id,
            0.35,
            scan_id,
            evidence,
            &[crate::tags::CANDIDATE, crate::tags::NAME_SEARCH_LEAD],
        );
    }
    Ok(page_result(
        OPENALEX_SOURCE,
        now_unix,
        status,
        total,
        rows.len(),
        entities,
    ))
}

fn crossref<T: Transport + ?Sized>(
    transport: &T,
    query: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<SourceReport, Error> {
    let url = append_query_param(
        &append_query_param(CROSSREF_API, "query.author", query),
        "rows",
        &LIMIT.to_string(),
    );
    let fetched = fetch(
        transport,
        Request::get(url)
            .header("accept", "application/json")
            .header("user-agent", crate::http::DEFAULT_USER_AGENT),
        None,
        &FetchOptions::no_redirects().paced(),
        CROSSREF_SOURCE,
        now_unix,
    )?;
    Ok(interpret_crossref(&fetched, query, scan_id, now_unix).unwrap_or_else(SourceReport::miss))
}

// Build a canonical DOI resolver URL without treating a third-party result as
// a network target. The suffix is path-encoded and cannot inject a query, host
// or fragment into the generated evidence URL.
fn doi_url(raw: &str) -> Option<String> {
    let (prefix, suffix) = raw.split_once('/')?;
    let number = prefix.strip_prefix("10.")?;
    if !(4..=12).contains(&number.len())
        || !number.bytes().all(|b| b.is_ascii_digit())
        || suffix.is_empty()
        || suffix.len() > 240
        || suffix.chars().any(char::is_control)
    {
        return None;
    }
    let components: Vec<String> = suffix.split('/').map(percent_encode_unreserved).collect();
    if suffix
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return None;
    }
    Some(format!("https://doi.org/{prefix}/{}", components.join("/")))
}

fn interpret_crossref(
    fetched: &Fetched,
    query: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<SourceReport, SourceExecutionOutcome> {
    let (body, status) = read_json(fetched, CROSSREF_SOURCE, "Crossref", now_unix)?;
    let total = body
        .pointer("/message/total-results")
        .and_then(Value::as_u64);
    let rows = body.pointer("/message/items").and_then(Value::as_array);
    let (Some(total), Some(rows)) = (total, rows) else {
        return Err(drift(
            CROSSREF_SOURCE,
            now_unix,
            status,
            "missing Crossref count or items",
        ));
    };
    if body.get("status").and_then(Value::as_str) != Some("ok")
        || rows.len() > LIMIT
        || total < rows.len() as u64
    {
        return Err(drift(
            CROSSREF_SOURCE,
            now_unix,
            status,
            "inconsistent Crossref result envelope",
        ));
    }
    if rows.is_empty() && total > 0 {
        return Err(SourceExecutionOutcome::failed(
            CROSSREF_SOURCE,
            now_unix,
            SourceOutcomeKind::ZeroYieldAnomaly,
            Some(status),
            "Crossref reports matches but returned an empty page",
        ));
    }
    let mut entities = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(doi) = row.get("DOI").and_then(Value::as_str) else {
            return Err(drift(
                CROSSREF_SOURCE,
                now_unix,
                status,
                "Crossref work missing DOI",
            ));
        };
        let Some(url) = doi_url(doi) else {
            return Err(drift(
                CROSSREF_SOURCE,
                now_unix,
                status,
                "Crossref work contains invalid DOI",
            ));
        };
        let title = row
            .get("title")
            .and_then(Value::as_array)
            .and_then(|titles| titles.first())
            .and_then(Value::as_str)
            .unwrap_or("Untitled Crossref work");
        if title.len() > 1000 || title.chars().any(char::is_control) {
            return Err(drift(
                CROSSREF_SOURCE,
                now_unix,
                status,
                "Crossref work has invalid title",
            ));
        }
        let evidence = Evidence::new(
            EvidenceProvenance::for_scan(CROSSREF_SOURCE, scan_id),
            "Crossref query.author publication lead; authorship is unverified",
        )
        .with_attr("query", query)
        .with_attr("doi", doi)
        .with_attr("title", title)
        .with_attr("source_url", &url)
        .with_attr("attribution", "unverified_author_query_lead");
        push_entity(
            &mut entities,
            EntityKind::Document,
            &url,
            0.3,
            scan_id,
            evidence,
            &[crate::tags::CANDIDATE, crate::tags::NAME_SEARCH_LEAD],
        );
    }
    Ok(page_result(
        CROSSREF_SOURCE,
        now_unix,
        status,
        total,
        rows.len(),
        entities,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{OneResponse, ScriptedTransport, json_ok};

    const OPENALEX_SAMPLE: &str = r#"{"meta":{"count":2},"results":[{"id":"https://openalex.org/A1234567890","display_name":"Alex Example","works_count":9,"orcid":"https://orcid.org/0000-0001-0000-0001"}]}"#;
    const CROSSREF_SAMPLE: &str = r#"{"status":"ok","message":{"total-results":2,"items":[{"DOI":"10.1234/research.one","title":["Example paper"]}]}}"#;

    #[test]
    fn scoped_two_api_leads_keep_separate_provenance_and_limits() {
        let transport = ScriptedTransport::new(vec![
            Ok(json_ok(OPENALEX_SAMPLE)),
            Ok(json_ok(CROSSREF_SAMPLE)),
        ]);
        let report = search(&transport, "Alex Example", "academic-scan", 123).unwrap();
        assert_eq!(report.entities.len(), 2);
        assert_eq!(report.outcomes.len(), 2);
        assert!(
            report
                .outcomes
                .iter()
                .all(|o| o.kind == SourceOutcomeKind::Success)
        );
        assert!(report.outcomes.iter().all(|o| o.detail.is_some()));
        assert!(
            report
                .entities
                .iter()
                .all(|e| e.tags.contains(&crate::tags::NAME_SEARCH_LEAD.to_string()))
        );
        let urls = transport.seen.borrow();
        assert_eq!(urls.len(), 2);
        assert!(urls[0].url.starts_with("https://api.openalex.org/authors?"));
        assert!(urls[1].url.starts_with("https://api.crossref.org/works?"));
        assert!(urls[0].url.contains("per_page=5"));
        assert!(urls[1].url.contains("rows=5"));
    }

    #[test]
    fn only_complete_zero_envelopes_prove_zero_catalogue_matches() {
        let oa = OneResponse::json(200, r#"{"meta":{"count":0},"results":[]}"#);
        let cr = OneResponse::json(
            200,
            r#"{"status":"ok","message":{"total-results":0,"items":[]}}"#,
        );
        assert_eq!(
            openalex(&oa, "Alex Example", "s", 1).unwrap().outcome.kind,
            SourceOutcomeKind::ValidZero
        );
        assert_eq!(
            crossref(&cr, "Alex Example", "s", 1).unwrap().outcome.kind,
            SourceOutcomeKind::ValidZero
        );
        for body in [
            r#"{"meta":{"count":4},"results":[]}"#,
            r#"{"meta":{},"results":[]}"#,
            r#"{"meta":{"count":0},"results":[{"id":"https://openalex.org/A1","display_name":"X"}]}"#,
            r#"{"meta":{"count":1},"results":[{"id":"https://evil.example/A1","display_name":"X"}]}"#,
        ] {
            let report = openalex(&OneResponse::json(200, body), "Alex Example", "s", 1).unwrap();
            assert!(!report.outcome.is_accepted(), "{body}");
            assert!(report.entities.is_empty());
        }
    }

    #[test]
    fn rejects_crossref_schema_drift_and_doi_injection() {
        for body in [
            r#"{"status":"ok","message":{"total-results":1,"items":[]}}"#,
            r#"{"status":"error","message":{"total-results":0,"items":[]}}"#,
            r#"{"status":"ok","message":{"total-results":1,"items":[{"DOI":"10.1234/../evil"}]}}"#,
            r#"{"status":"ok","message":{"total-results":1,"items":[{"DOI":"https://evil.example"}]}}"#,
        ] {
            let report = crossref(&OneResponse::json(200, body), "Alex Example", "s", 1).unwrap();
            assert!(!report.outcome.is_accepted(), "{body}");
            assert!(report.entities.is_empty());
        }
        assert_eq!(
            doi_url("10.1234/topic?x=1#y"),
            Some("https://doi.org/10.1234/topic%3Fx%3D1%23y".to_owned())
        );
    }

    #[test]
    fn invalid_query_never_reaches_the_network() {
        let transport = ScriptedTransport::new(Vec::new());
        for input in [
            "",
            " ",
            "Alex\nExample",
            "Alex\tExample",
            "Alex <Example>",
            "Alex \"Example\"",
        ] {
            assert!(search(&transport, input, "s", 1).is_err());
        }
        assert!(transport.seen.borrow().is_empty());
    }

    #[test]
    fn one_failed_source_cannot_erase_the_other_sources_evidence() {
        let transport = ScriptedTransport::new(vec![
            Ok(crate::http::Response {
                status: 401,
                headers: Vec::new(),
                body: Vec::new(),
                truncated: false,
            }),
            Ok(json_ok(CROSSREF_SAMPLE)),
        ]);
        let report = search(&transport, "Alex Example", "s", 1).unwrap();
        assert_eq!(report.outcomes.len(), 2);
        assert!(!report.outcomes[0].is_accepted());
        assert_eq!(report.outcomes[1].kind, SourceOutcomeKind::Success);
        assert_eq!(report.entities.len(), 1);
    }
}
