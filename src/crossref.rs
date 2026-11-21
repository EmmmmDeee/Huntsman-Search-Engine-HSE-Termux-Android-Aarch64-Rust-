//! Crossref scholarly metadata discovery through the shared guarded transport.
//!
//! Crossref entries establish that bibliographic metadata was registered, not
//! that an author is the searched person or that a publication's claims are true.
//! A Crossref record is a bounded discovery lead, never identity corroboration.

use std::collections::BTreeSet;
use std::time::Duration;

use serde_json::Value;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Transport, append_query_param};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const SOURCE_ID: &str = "crossref_works";
const API_URL: &str = "https://api.crossref.org/works";
const MAX_ITEMS: usize = 10;
const MAX_DOI_BYTES: usize = 255;
const MAX_TITLE_BYTES: usize = 1024;

/// A single metadata query without pagination or authentication.
#[must_use]
pub fn query_url(query: &str) -> String {
    let url = append_query_param(API_URL, "query.bibliographic", query);
    let url = append_query_param(&url, "rows", "10");
    append_query_param(
        &url,
        "select",
        "DOI,URL,title,publisher,type,container-title",
    )
}

/// DOI metadata must resolve through the canonical Crossref DOI URL, not through
/// an arbitrary domain supplied by a third-party metadata record.
fn valid_doi_url(doi: &str, url: &str) -> bool {
    if doi.len() > MAX_DOI_BYTES {
        return false;
    }
    let Some(rest) = doi.strip_prefix("10.") else {
        return false;
    };
    let Some((registrant, suffix)) = rest.split_once('/') else {
        return false;
    };
    !registrant.is_empty()
        && registrant.bytes().all(|byte| byte.is_ascii_digit())
        && !suffix.is_empty()
        && !doi
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace() || matches!(ch, '#' | '?' | '\\'))
        && url == format!("https://doi.org/{doi}")
}

fn safe_metadata<'a>(row: &'a Value, name: &str) -> Option<&'a str> {
    row.get(name)
        .and_then(Value::as_str)
        .filter(|text| text.len() <= 512 && !text.chars().any(char::is_control))
}

fn parse(body: &[u8], scan_id: &str, now: u64) -> (Vec<Entity>, SourceExecutionOutcome) {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return (
            Vec::new(),
            SourceExecutionOutcome::failed(
                SOURCE_ID,
                now,
                SourceOutcomeKind::ParserDrift,
                Some(200),
                "Crossref response is not JSON",
            ),
        );
    };
    if value.get("status").and_then(Value::as_str) != Some("ok") {
        return (
            Vec::new(),
            SourceExecutionOutcome::failed(
                SOURCE_ID,
                now,
                SourceOutcomeKind::SemanticDrift,
                Some(200),
                "Crossref did not confirm an ok response",
            ),
        );
    }
    let message = value.get("message");
    let rows = message
        .and_then(|v| v.get("items"))
        .and_then(Value::as_array);
    let total = message
        .and_then(|v| v.get("total-results"))
        .and_then(Value::as_u64);
    let (Some(rows), Some(total)) = (rows, total) else {
        return (
            Vec::new(),
            SourceExecutionOutcome::failed(
                SOURCE_ID,
                now,
                SourceOutcomeKind::SchemaDrift,
                Some(200),
                "Crossref result fields are missing or invalid",
            ),
        );
    };

    let mut entities = Vec::new();
    let mut seen = BTreeSet::new();
    let mut omitted = rows.len().saturating_sub(MAX_ITEMS);
    for row in rows.iter().take(MAX_ITEMS) {
        let doi = row.get("DOI").and_then(Value::as_str);
        let url = row.get("URL").and_then(Value::as_str);
        let title = row
            .get("title")
            .and_then(Value::as_array)
            .and_then(|titles| titles.first())
            .and_then(Value::as_str);
        let (Some(doi), Some(url), Some(title)) = (doi, url, title) else {
            omitted += 1;
            continue;
        };
        if title.trim().is_empty()
            || title.len() > MAX_TITLE_BYTES
            || title.chars().any(char::is_control)
            || !valid_doi_url(doi, url)
            || !seen.insert(doi.to_ascii_lowercase())
        {
            omitted += 1;
            continue;
        }

        let mut evidence = Evidence::new(
            EvidenceProvenance::for_scan(SOURCE_ID, scan_id),
            "Crossref bibliographic metadata; authorship and claims not independently verified",
        )
        .with_attr("source_url", url)
        .with_attr("title", title)
        .with_attr("doi", doi);

        for (key, attribute) in [("publisher", "publisher"), ("type", "work_type")] {
            if let Some(value) = safe_metadata(row, key) {
                evidence = evidence.with_attr(attribute, value);
            }
        }
        if let Some(journal) = row
            .get("container-title")
            .and_then(Value::as_array)
            .and_then(|values| values.first())
            .and_then(Value::as_str)
            .filter(|value| value.len() <= 512 && !value.chars().any(char::is_control))
        {
            evidence = evidence.with_attr("container_title", journal);
        }

        push_entity(
            &mut entities,
            EntityKind::Document,
            url,
            0.35,
            scan_id,
            evidence,
            &["publication_lead", "unverified"],
        );
    }
    merge_by_uid(&mut entities);
    if !entities.is_empty() {
        let mut outcome =
            SourceExecutionOutcome::success(SOURCE_ID, now, entities.len()).with_http_status(200);
        if omitted != 0 {
            outcome =
                outcome.with_detail(format!("{omitted} invalid, duplicate or over-limit records omitted"));
        }
        return (entities, outcome);
    }
    if omitted == 0 && total == 0 {
        (
            entities,
            SourceExecutionOutcome::valid_zero(SOURCE_ID, now).with_http_status(200),
        )
    } else {
        (
            entities,
            SourceExecutionOutcome::failed(
                SOURCE_ID,
                now,
                SourceOutcomeKind::SchemaDrift,
                Some(200),
                "Crossref returned unvalidated or unexamined results",
            ),
        )
    }
}

/// Collect one Crossref bibliographic page, bounded to 10 works, via Huntsman's
/// existing transport, public-egress and outcome gates. No keys or redirects.
pub fn search<T: Transport + ?Sized>(
    transport: &T,
    query: &str,
    scan_id: &str,
    now: u64,
) -> (Vec<Entity>, SourceExecutionOutcome) {
    let request =
        Request::get_json(query_url(query)).with_timeout(Duration::from_secs(16));
    let fetched = match fetch(
        transport,
        request,
        None,
        &FetchOptions::no_redirects().paced(),
        SOURCE_ID,
        now,
    ) {
        Ok(response) => response,
        Err(_) => {
            return (
                Vec::new(),
                SourceExecutionOutcome::refused_before_sending(
                    SOURCE_ID,
                    now,
                    "guarded Crossref request was refused",
                ),
            );
        }
    };
    let Some(response) = fetched.response else {
        return (Vec::new(), fetched.outcome);
    };
    if response.truncated {
        return (
            Vec::new(),
            SourceExecutionOutcome::failed(
                SOURCE_ID,
                now,
                SourceOutcomeKind::ParserDrift,
                Some(response.status),
                "Crossref response exceeded configured byte limit",
            ),
        );
    }
    if response.status != 200 {
        return (Vec::new(), fetched.outcome);
    }
    parse(&response.body, scan_id, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::OneResponse;

    #[test]
    fn query_uses_only_bounded_bibliographic_fields() {
        let url = query_url("historical geology");
        assert!(url.starts_with("https://api.crossref.org/works?"));
        assert!(url.contains("query.bibliographic=historical%20geology"));
        assert!(url.contains("rows=10"));
        assert!(url.contains("select="));
    }

    #[test]
    fn canonical_doi_is_a_lead_and_spoofed_domains_are_discarded() {
        let fake = OneResponse::json(
            200,
            r#"{"status":"ok","message":{"total-results":2,"items":[
                {"DOI":"10.1234/genuine","URL":"https://doi.org/10.1234/genuine",
                 "title":["Research"],"publisher":"Publisher","container-title":["Journal"]},
                {"DOI":"10.1234/spoof","URL":"https://doi.org.evil.example/10.1234/spoof",
                 "title":["Research"]}
            ]}}"#,
        );
        let (entities, outcome) = search(&fake, "Research", "scan", 100);
        assert_eq!(outcome.kind, SourceOutcomeKind::Success);
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].kind, EntityKind::Document);
        assert_eq!(entities[0].value, "https://doi.org/10.1234/genuine");
        assert_eq!(entities[0].evidence[0].provenance.source, SOURCE_ID);
        assert_eq!(
            entities[0].evidence[0].attributes.get("doi").map(String::as_str),
            Some("10.1234/genuine")
        );
    }

    #[test]
    fn valid_zero_is_not_schema_or_semantic_drift() {
        let valid = br#"{"status":"ok","message":{"total-results":0,"items":[]}}"#;
        let invalid = br#"{"status":"ok","message":{"total-results":1,"items":[]}}"#;
        let failed = br#"{"status":"error","message":{"total-results":0,"items":[]}}"#;
        assert_eq!(parse(valid, "s", 1).1.kind, SourceOutcomeKind::ValidZero);
        assert_eq!(parse(invalid, "s", 1).1.kind, SourceOutcomeKind::SchemaDrift);
        assert_eq!(parse(failed, "s", 1).1.kind, SourceOutcomeKind::SemanticDrift);
    }

    #[test]
    fn missing_required_fields_cannot_become_a_zero() {
        let bad = br#"{"status":"ok","message":{"total-results":0}}"#;
        assert_eq!(parse(bad, "s", 1).1.kind, SourceOutcomeKind::SchemaDrift);
    }
}
