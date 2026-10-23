//! CKAN `datastore_search` response helpers.

use serde::Deserialize;
use serde_json::{Map, Value};

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
pub fn check_envelope(
    response: Response,
    module: &'static str,
) -> Result<Option<ResultSet>, crate::Error> {
    if response.success == Some(false) {
        Err(crate::Error::Invalid(format!(
            "{module}: CKAN datastore_search returned success=false (bad resource id or portal error)"
        )))
    } else {
        Ok(response.result)
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
