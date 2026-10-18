//! Hudson Rock Cavalier: keyless domain-level infostealer intelligence.
//!
//! One lookup is one GET to Cavalier's public search-by-domain endpoint.
//! Results are domain-wide aggregates; this source deliberately does not claim they identify a
//! particular email address. The raw provider response is retained for auditability.

use crate::api_leg::{self, Answer, Api, LegError};
use crate::http::{Transport, percent_encode_component};
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, Source};
use crate::keys::Keys;

pub const SOURCE: &str = "hudsonrock";
pub const API: Api = Api {
    source: SOURCE,
    provider: "cavalier.hudsonrock.com",
    origin: "https://cavalier.hudsonrock.com:443",
    key: None,
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Domain],
    lookup,
};

/// The request URL for a domain. Pure.
#[must_use]
pub fn url(domain: &str) -> String {
    format!(
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={}",
        percent_encode_component(domain)
    )
}

/// Look up domain-level aggregates.
///
/// # Errors
/// Returns the typed API-leg error, or a decode error for malformed JSON or missing/invalid
/// aggregate counts. Email indicators are intentionally not accepted because these counts are
/// domain-wide and must not be attributed to an individual account.
pub fn lookup(
    transport: &dyn Transport,
    keys: &Keys,
    indicator: Indicator<'_>,
    now_unix: u64,
) -> Result<Option<Finding>, LegError> {
    let Indicator::Domain(domain) = indicator else {
        return Ok(None);
    };
    match api_leg::get(transport, &API, keys, &url(domain), now_unix)? {
        Answer::Body(body) => decode(&body),
        Answer::NotFound(_) => Ok(None),
    }
}

/// Decode one answer. Pure.
///
/// # Errors
/// Returns LegError::Decode when the response is not UTF-8 JSON with numeric aggregate
/// counts. A valid zero-count response is a clean negative.
pub fn decode(body: &[u8]) -> Result<Option<Finding>, LegError> {
    let text =
        std::str::from_utf8(body).map_err(|_| LegError::Decode("answer is not UTF-8".into()))?;
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|_| LegError::Decode("answer is not JSON".into()))?;
    let employees = value
        .get("total_employees")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| LegError::Decode("missing or invalid total_employees".into()))?;
    let users = value
        .get("total_users")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| LegError::Decode("missing or invalid total_users".into()))?;
    if employees == 0 && users == 0 {
        return Ok(None);
    }
    let mut finding = Finding::new(format!("Hudson Rock: {employees} employees, {users} users"))
        .attr("employees", employees.to_string())
        .attr("users", users.to_string())
        .attr("raw_answer", text);
    if let Some(stealers) = value.get("stealers").and_then(|v| v.as_array()) {
        finding = finding.attr("stealers", stealers.len().to_string());
    }
    Ok(Some(finding))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_domain_aggregate_counts_and_raw_response() {
        let body = br#"{"total_employees":5,"total_users":10,"stealers":[]}"#;
        let finding = decode(body).unwrap().unwrap();
        assert!(finding.summary.contains("5 employees"));
        assert!(finding.attrs.iter().any(|(k, v)| *k == "raw_answer" && v.contains("total_users")));
        assert_eq!(INTEL.kinds, &[IndicatorKind::Domain]);
    }

    #[test]
    fn valid_zero_is_a_clean_negative() {
        assert!(decode(br#"{"total_employees":0,"total_users":0}"#).unwrap().is_none());
    }

    #[test]
    fn malformed_aggregate_is_not_silently_reported_as_zero() {
        assert!(decode(br#"{"status":"ok"}"#).is_err());
        assert!(decode(b"not JSON").is_err());
    }

    #[test]
    fn query_is_domain_encoded() {
        assert!(url("example.com").ends_with("domain=example.com"));
        assert!(url("example.com/a").contains("%2F"));
    }
}
