//! CKAN `datastore_search` response helpers, and the one fail-closed query path every CKAN
//! register collector (`asic_persons`, `asic_orgs`, `acnc`) shares: fetch, interpret the envelope,
//! and reconcile the page verdict with the records a collector matched locally.

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::error::Error;
use crate::fetch::{self, FetchOptions, Fetched};
use crate::http::{self, Request, Transport};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, classify_fetch};

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Response {
    #[serde(default)]
    pub success: Option<bool>,
    #[serde(default)]
    pub result: Option<ResultSet>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ResultSet {
    #[serde(default)]
    pub total: Option<u64>,
    #[serde(default)]
    pub records: Vec<Map<String, Value>>,
}

impl ResultSet {
    /// Why this page is not the whole answer, or `None` when it is.
    #[must_use]
    pub fn truncation(&self) -> Option<String> {
        let total = self.total?;
        (total > self.records.len() as u64).then(|| {
            format!(
                "partial: read the first {} of {total} matching records; absence of a record \
                 here is not evidence of absence",
                self.records.len()
            )
        })
    }
}

#[must_use]
pub fn field_str(record: &Map<String, Value>, key: &str) -> Option<String> {
    let rendered = match record.get(key)? {
        Value::String(value) => value.trim().to_string(),
        Value::Null => return None,
        other => other.to_string(),
    };
    if rendered.is_empty() {
        None
    } else {
        Some(rendered)
    }
}

#[must_use]
pub fn field(record: &Map<String, Value>, key: &str) -> Option<String> {
    field_str(record, key).filter(|value| !value.eq_ignore_ascii_case("null"))
}

#[must_use]
pub fn datastore_search_url(action_base: &str, resource_id: &str, q: &str, limit: usize) -> String {
    format!(
        "{action_base}/datastore_search?resource_id={resource_id}&q={}&limit={limit}",
        crate::http::percent_encode_component(q)
    )
}

/// # Errors
///
/// Returns [`crate::Error::Invalid`] when the CKAN envelope explicitly reports
/// `success=false`.
pub fn check_envelope(response: Response, module: &str) -> Result<Option<ResultSet>, crate::Error> {
    if response.success == Some(false) {
        Err(crate::Error::Invalid(format!(
            "{module}: CKAN datastore_search returned success=false (bad resource id or portal error)"
        )))
    } else {
        Ok(response.result)
    }
}

/// The records one register's search returned, after [`parse_datastore`].
pub type Records = Vec<Map<String, Value>>;

/// Search one `datastore_search` resource for `q`, keyless, and interpret the answer with
/// [`parse_datastore`].
///
/// # Errors
/// [`Error::Network`] when the guarded fetch refuses the request before sending.
pub fn query_datastore<T: Transport + ?Sized>(
    transport: &T,
    action_base: &str,
    module: &str,
    resource: &str,
    q: &str,
    limit: usize,
    now_unix: u64,
) -> Result<(SourceExecutionOutcome, Records), Error> {
    let options = FetchOptions {
        max_redirects: fetch::DEFAULT_MAX_REDIRECTS,
        ..FetchOptions::default()
    };
    let url = datastore_search_url(action_base, resource, q, limit);
    let request = Request::get(url).header("accept", "application/json");
    let fetched = fetch::fetch(transport, request, None, &options, module, now_unix)?;
    Ok(parse_datastore(module, now_unix, fetched))
}

/// Interpret a `datastore_search` response. A truncated body, a challenge or non-2xx page, or a
/// malformed or `success: false` envelope is a fail-closed non-answer with no records; a clean
/// envelope yields its records, and a truncation note when the page was cut short of the total.
/// **Pure.**
#[must_use]
pub fn parse_datastore(
    module: &str,
    now_unix: u64,
    fetched: Fetched,
) -> (SourceExecutionOutcome, Records) {
    let drift = |kind: SourceOutcomeKind, status: Option<u16>, detail: String| {
        let mut outcome = SourceExecutionOutcome::success(module, now_unix, 0);
        outcome.kind = kind;
        outcome.found = None;
        outcome.http_status = status;
        outcome.detail = Some(detail);
        (outcome, Vec::new())
    };
    let Some(response) = fetched.response else {
        return (fetched.outcome, Vec::new());
    };
    if response.truncated {
        return drift(
            SourceOutcomeKind::ParserDrift,
            Some(response.status),
            "truncated CKAN body is not evidence".to_owned(),
        );
    }
    let body = response.text();
    let kind = classify_fetch(response.status, &body);
    if kind != SourceOutcomeKind::Inconclusive {
        let mut outcome = fetched.outcome;
        outcome.kind = kind;
        outcome.found = None;
        return (outcome, Vec::new());
    }
    let parsed: Response = match http::parse_json_body(&response) {
        Ok(parsed) => parsed,
        Err(err) => {
            return drift(
                SourceOutcomeKind::ParserDrift,
                Some(response.status),
                err.to_string(),
            );
        }
    };
    match check_envelope(parsed, module) {
        Err(err) => drift(
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            err.to_string(),
        ),
        Ok(None) => drift(
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            "CKAN response had no result envelope".to_owned(),
        ),
        Ok(Some(result)) => {
            let outcome = if result.records.is_empty() {
                SourceExecutionOutcome::valid_zero(module, now_unix)
            } else {
                SourceExecutionOutcome::success(module, now_unix, result.records.len())
            }
            .with_http_status(response.status);
            let outcome = match result.truncation() {
                Some(note) => outcome.with_detail(note),
                None => outcome,
            };
            (outcome, result.records)
        }
    }
}

/// Reconcile a register's page verdict with the `matched` records a collector kept locally. A page
/// cut short of the total can show a positive match but never proves absence, so a cut page with
/// no match is inconclusive rather than a clean zero. **Pure.**
#[must_use]
pub fn reconcile_matches(
    mut outcome: SourceExecutionOutcome,
    matched: usize,
    module: &str,
    now_unix: u64,
) -> SourceExecutionOutcome {
    if !outcome.kind.is_accepted() {
        return outcome;
    }
    let partial = outcome.detail.take();
    let status = outcome.http_status.unwrap_or(200);
    if matched == 0 {
        if let Some(note) = partial {
            SourceExecutionOutcome::observed(
                module,
                now_unix,
                SourceOutcomeKind::Inconclusive,
                Some(status),
                Some(0),
                note,
            )
        } else {
            SourceExecutionOutcome::valid_zero(module, now_unix).with_http_status(status)
        }
    } else {
        let mut found =
            SourceExecutionOutcome::success(module, now_unix, matched).with_http_status(status);
        if let Some(note) = partial {
            found = found.with_detail(note);
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(json: &str) -> Map<String, Value> {
        serde_json::from_str(json).expect("record")
    }

    #[test]
    fn renders_fields_and_urls() {
        let rec = record(r#"{"Name":"  ACME  ","PCode":4000,"Null":"null","Active":true}"#);
        assert_eq!(field_str(&rec, "Name").as_deref(), Some("ACME"));
        assert_eq!(field_str(&rec, "PCode").as_deref(), Some("4000"));
        assert_eq!(field(&rec, "Null"), None);
        assert_eq!(field_str(&rec, "Active").as_deref(), Some("true"));
        assert_eq!(
            datastore_search_url(
                "https://data.gov.au/data/api/3/action",
                "abc-123",
                "a&limit=9999&x=y",
                5,
            ),
            "https://data.gov.au/data/api/3/action/datastore_search?resource_id=abc-123&q=a%26limit%3D9999%26x%3Dy&limit=5"
        );
    }

    #[test]
    fn check_envelope_distinguishes_errors_from_empty_results() {
        let err: Response = serde_json::from_str(r#"{"success":false}"#).expect("response");
        let msg = check_envelope(err, "ckan_test")
            .expect_err("must error")
            .to_string();
        assert!(msg.contains("ckan_test"));
        assert!(msg.contains("success=false"));

        for body in [r#"{"success":true}"#, r"{}"] {
            let response: Response = serde_json::from_str(body).expect("response");
            assert!(check_envelope(response, "ckan_test").expect("ok").is_none());
        }
    }

    #[test]
    fn truncation_names_a_page_cut_short_of_the_total() {
        let page = |total: Option<u64>, records: usize| ResultSet {
            total,
            records: vec![Map::new(); records],
        };
        assert_eq!(
            page(Some(340), 100).truncation().as_deref(),
            Some(
                "partial: read the first 100 of 340 matching records; absence of a record here \
                 is not evidence of absence"
            )
        );
        assert_eq!(page(Some(100), 100).truncation(), None);
        assert_eq!(page(None, 100).truncation(), None);
        assert_eq!(page(Some(0), 0).truncation(), None);
    }
}
