//! CKAN `datastore_search` response envelope + field helpers.
//!
//! Several Australian open-data registers expose their datasets through CKAN's
//! `action/datastore_search` API — `data.gov.au` (the ACNC charities register),
//! `data.qld.gov.au` (the Public Trustee unclaimed-monies register), and others
//! the charter targets. The JSON envelope and the defensive field
//! stringification are identical across every one of them (it's a fixed CKAN API
//! contract, not per-portal), so they live here once rather than being
//! re-implemented — and re-tested — in each module.

use serde::Deserialize;
use serde_json::{Map, Value};

/// The CKAN `action/datastore_search` response envelope.
///
/// CKAN action endpoints return HTTP 200 even on application errors (bad
/// resource id, datastore offline, rate-limit), signalling failure via
/// `success: false`. Both fields are captured (rather than only `result`) so a
/// caller can surface an application error instead of silently treating a
/// missing `result` as "no findings".
#[derive(Debug, Deserialize)]
pub struct Response {
    #[serde(default)]
    pub success: Option<bool>,
    #[serde(default)]
    pub result: Option<ResultSet>,
}

/// The `result` object of a [`Response`]: the matched record set plus the total
/// match count.
///
/// Records are returned with CKAN-inferred field types (text vs numeric), so
/// they are kept as raw JSON objects and read defensively via [`field_str`]
/// rather than risking a deserialize failure on a numerically-typed column
/// (an `ABN`/`Amount`/`PCode` that the datastore happens to type as a number).
#[derive(Debug, Deserialize)]
pub struct ResultSet {
    #[serde(default)]
    pub total: Option<u64>,
    #[serde(default)]
    pub records: Vec<Map<String, Value>>,
}

/// Stringify a CKAN field value (text stays as-is, numbers/bools are rendered,
/// null/missing → `None`) and trim it; empty becomes `None`.
#[must_use]
pub fn field_str(rec: &Map<String, Value>, key: &str) -> Option<String> {
    let s = match rec.get(key)? {
        Value::String(s) => s.trim().to_string(),
        Value::Null => return None,
        other => other.to_string(),
    };
    if s.is_empty() { None } else { Some(s) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(json: &str) -> Map<String, Value> {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn field_str_trims_text_and_treats_empty_as_absent() {
        let rec = record(r#"{"Name":"  ACME  ","Blank":"   ","Empty":""}"#);
        assert_eq!(field_str(&rec, "Name").as_deref(), Some("ACME"));
        // Whitespace-only and empty strings collapse to None.
        assert_eq!(field_str(&rec, "Blank"), None);
        assert_eq!(field_str(&rec, "Empty"), None);
    }

    #[test]
    fn field_str_stringifies_numbers_and_bools() {
        // CKAN may type a column as a JSON number/bool; it must still render to a
        // usable string rather than being dropped (the bug `field_str` guards).
        let rec = record(r#"{"PCode":4000,"Amount":99.5,"Active":true}"#);
        assert_eq!(field_str(&rec, "PCode").as_deref(), Some("4000"));
        assert_eq!(field_str(&rec, "Amount").as_deref(), Some("99.5"));
        assert_eq!(field_str(&rec, "Active").as_deref(), Some("true"));
    }

    #[test]
    fn field_str_null_and_missing_are_none() {
        let rec = record(r#"{"Present":"x","Null":null}"#);
        assert_eq!(field_str(&rec, "Null"), None);
        assert_eq!(field_str(&rec, "Absent"), None);
        assert_eq!(field_str(&rec, "Present").as_deref(), Some("x"));
    }

    #[test]
    fn response_captures_application_error() {
        // HTTP 200 + success=false (bad resource id / portal error) must be
        // visible, with no `result`, so callers can surface it rather than
        // reporting "no findings".
        let err: Response =
            serde_json::from_str(r#"{"success":false,"error":{"message":"Resource not found"}}"#)
                .unwrap();
        assert_eq!(err.success, Some(false));
        assert!(err.result.is_none());
    }

    #[test]
    fn response_parses_normal_result_set() {
        let ok: Response = serde_json::from_str(
            r#"{"success":true,"result":{"total":2,"records":[
                {"_id":1,"Owner":"A"},
                {"_id":2,"Owner":"B","Amount":4.5}
            ]}}"#,
        )
        .unwrap();
        assert_eq!(ok.success, Some(true));
        let res = ok.result.expect("result present");
        assert_eq!(res.total, Some(2));
        assert_eq!(res.records.len(), 2);
        // Records survive as raw JSON objects (numeric Amount kept as a number,
        // ready for field_str to stringify on demand).
        assert_eq!(field_str(&res.records[1], "Amount").as_deref(), Some("4.5"));
    }

    #[test]
    fn response_defaults_are_lenient() {
        // A bare/empty object must deserialize (every field is `#[serde(default)]`)
        // so a truncated or unexpected body degrades to "no findings", not a parse
        // error that masks the miss.
        let empty: Response = serde_json::from_str("{}").unwrap();
        assert_eq!(empty.success, None);
        assert!(empty.result.is_none());
        let no_total: ResultSet = serde_json::from_str(r#"{"records":[]}"#).unwrap();
        assert_eq!(no_total.total, None);
        assert!(no_total.records.is_empty());
    }
}
