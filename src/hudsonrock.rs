//! Hudson Rock Cavalier: keyless infostealer intelligence for a domain or an email address.
//!
//! The domain leg is one GET to Cavalier's public search-by-domain endpoint; its results are
//! domain-wide aggregates, so this source deliberately does not claim they identify a particular
//! account, and the raw provider response is retained for auditability.
//!
//! The email leg is one GET to the public search-by-email endpoint. An address with no infection
//! answers `200` with an empty `stealers` list, a clean zero (verified 2026-10-29). When records
//! exist, only non-credential breach metadata is kept -- how many infostealer records name the
//! address, the distinct stealer families, the first and last compromise dates, and the
//! corporate/user service counts. Stolen credentials, logins, machine names and host addresses in
//! the record are never deserialized and never stored, so no secret leaves this boundary.

use std::collections::HashSet;

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, LegError};
use crate::http::{Transport, percent_encode_component};
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, Source};
use crate::keys::Keys;
use crate::tags;

pub const SOURCE: &str = "hudsonrock";
pub const API: Api = Api {
    source: SOURCE,
    provider: "cavalier.hudsonrock.com",
    origin: "https://cavalier.hudsonrock.com:443",
    key: None,
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Domain, IndicatorKind::Email],
    lookup,
};

/// The request URL for a domain. **Pure.**
#[must_use]
pub fn url(domain: &str) -> String {
    format!(
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={}",
        percent_encode_component(domain)
    )
}

/// The request URL for an email address. **Pure.**
#[must_use]
pub fn email_url(email: &str) -> String {
    format!(
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={}",
        percent_encode_component(email)
    )
}

/// Look up domain-level aggregates, or one address's infostealer records.
///
/// # Errors
/// Returns the typed API-leg error, or a decode error for malformed JSON, a missing aggregate
/// count (domain) or a missing `stealers` list (email). Domain counts are deliberately not
/// attributed to an individual account.
pub fn lookup(
    transport: &dyn Transport,
    keys: &Keys,
    indicator: Indicator<'_>,
    now_unix: u64,
) -> Result<Option<Finding>, LegError> {
    match indicator {
        Indicator::Domain(domain) => {
            match api_leg::get(transport, &API, keys, &url(domain), now_unix)? {
                Answer::Body(body) => decode(&body),
                Answer::NotFound(_) => Ok(None),
            }
        }
        Indicator::Email(email) => lookup_email(transport, keys, email, now_unix),
        _ => Ok(None),
    }
}

/// Look up one address's infostealer records. An empty selector asks nothing -- the endpoint
/// answers `400` to it -- so it is a clean zero before any request.
///
/// # Errors
/// The typed API-leg error, or a decode error for a body without a `stealers` list. A `404` is a
/// failed lookup, never a zero: the clean answer is a `200` with an empty list.
fn lookup_email(
    transport: &dyn Transport,
    keys: &Keys,
    email: &str,
    now_unix: u64,
) -> Result<Option<Finding>, LegError> {
    let email = email.trim();
    if email.is_empty() {
        return Ok(None);
    }
    match api_leg::get(transport, &API, keys, &email_url(email), now_unix)? {
        Answer::Body(body) => decode_email(&body),
        Answer::NotFound(_) => Err(LegError::Unexpected(404)),
    }
}

/// Decode one domain answer. **Pure.**
///
/// # Errors
/// Returns `LegError::Decode` when the response is not UTF-8 JSON with numeric aggregate
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
    // Provider responses can contain nested infostealer records. Never persist the raw
    // document: it may contain credentials, host identifiers or other private fields.
    let mut finding = Finding::new(format!("Hudson Rock: {employees} employees, {users} users"))
        .attr("employees", employees.to_string())
        .attr("users", users.to_string());
    if let Some(stealers) = value.get("stealers").and_then(|v| v.as_array()) {
        finding = finding.attr("stealers", stealers.len().to_string());
    }
    Ok(Some(finding))
}

/// One address answer: top-level service counts and a `stealers` list. Only the fields named here
/// are read; every other field the provider returns -- stolen credentials, logins, machine name,
/// host address -- is ignored by the deserializer, so no secret is ever kept.
#[derive(Deserialize)]
struct EmailAnswer {
    #[serde(default)]
    stealers: Option<Vec<StealerRecord>>,
    #[serde(default)]
    total_corporate_services: Option<u64>,
    #[serde(default)]
    total_user_services: Option<u64>,
}

/// The non-credential fields of one infostealer record. The stolen-credential array, logins,
/// machine name and host address are deliberately absent, so they are never deserialized or stored.
#[derive(Deserialize)]
struct StealerRecord {
    #[serde(default)]
    stealer_family: Option<String>,
    #[serde(default)]
    date_compromised: Option<String>,
}

/// Decode one address answer, keeping only non-credential breach metadata. **Pure.**
///
/// # Errors
/// `LegError::Decode` when the body is not JSON carrying a `stealers` list. An empty list is a
/// clean negative.
pub fn decode_email(body: &[u8]) -> Result<Option<Finding>, LegError> {
    let answer: EmailAnswer = api_leg::decode(body)?;
    let Some(stealers) = answer.stealers else {
        return Err(LegError::Decode("missing stealers list".into()));
    };
    if stealers.is_empty() {
        return Ok(None);
    }
    let count = stealers.len();
    let mut families: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for record in &stealers {
        if let Some(family) = api_leg::clean(record.stealer_family.as_deref()) {
            if seen.insert(family.clone()) {
                families.push(family);
            }
        }
    }
    // Blank dates are dropped, not sorted to the front: an empty string would otherwise become
    // `first_compromised` and then vanish when the attribute writer trims it, leaving a real
    // `last_compromised` with no `first`.
    let mut dates: Vec<&str> = stealers
        .iter()
        .filter_map(|record| record.date_compromised.as_deref())
        .map(str::trim)
        .filter(|date| !date.is_empty())
        .collect();
    dates.sort_unstable();
    let mut finding = Finding::new(format!(
        "Hudson Rock: the address appears in {count} infostealer record{}",
        if count == 1 { "" } else { "s" }
    ))
    .attr("stealer_records", count.to_string())
    .opt_attr("first_compromised", dates.first().copied())
    .opt_attr("last_compromised", dates.last().copied())
    .tag(tags::BREACH);
    if !families.is_empty() {
        finding = finding.list_attr("stealer_families", &families);
    }
    if let Some(corporate) = answer.total_corporate_services.filter(|count| *count > 0) {
        finding = finding.attr("corporate_services", corporate.to_string());
    }
    if let Some(user) = answer.total_user_services.filter(|count| *count > 0) {
        finding = finding.attr("user_services", user.to_string());
    }
    Ok(Some(finding))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_aggregates_never_persist_nested_credentials() {
        let body = br#"{"total_employees":5,"total_users":10,"stealers":[{"credentials":[{"password":"SENTINEL_PASSWORD_83","username":"private@example.test"}],"computer_name":"PRIVATE_HOST_83","ip":"203.0.113.83"}]}"#;
        let finding = decode(body).unwrap().unwrap();
        assert!(finding.summary.contains("5 employees"));
        assert!(
            finding
                .attrs
                .iter()
                .any(|(k, v)| *k == "employees" && v == "5")
        );
        assert!(
            finding
                .attrs
                .iter()
                .any(|(k, v)| *k == "users" && v == "10")
        );
        assert!(
            finding
                .attrs
                .iter()
                .any(|(k, v)| *k == "stealers" && v == "1")
        );
        assert!(!finding.attrs.iter().any(|(k, _)| *k == "raw_answer"));
        for secret in [
            "SENTINEL_PASSWORD_83",
            "private@example.test",
            "PRIVATE_HOST_83",
            "203.0.113.83",
        ] {
            assert!(!finding.summary.contains(secret));
            assert!(!finding.attrs.iter().any(|(_, v)| v.contains(secret)));
        }
    }

    #[test]
    fn valid_zero_is_a_clean_negative() {
        assert!(
            decode(br#"{"total_employees":0,"total_users":0}"#)
                .unwrap()
                .is_none()
        );
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

    #[test]
    fn the_source_answers_for_a_domain_and_an_email() {
        assert_eq!(INTEL.kinds, &[IndicatorKind::Domain, IndicatorKind::Email]);
    }

    /// The live clean shape (verified 2026-10-29): a 200 with an empty `stealers` list.
    #[test]
    fn email_clean_answer_is_a_valid_zero() {
        let clean = br#"{"message":"This email address is not associated with a computer infected by an info-stealer.","stealers":[],"total_corporate_services":0,"total_user_services":0}"#;
        assert!(matches!(decode_email(clean), Ok(None)));
    }

    #[test]
    fn email_records_keep_metadata_and_never_a_stolen_secret() {
        let body = br#"{"stealers":[
            {"stealer_family":"RedLine","date_compromised":"2022-03-01T00:00:00.000Z","computer_name":"VICTIM-PC","ip":"203.0.113.9","credentials":[{"url":"https://portal.example.com","username":"victim@example.com","password":"SUPERSECRET123"}]},
            {"stealer_family":"Raccoon","date_compromised":"2024-07-09T00:00:00.000Z","credentials":[{"password":"hunter2"}]}
        ],"total_corporate_services":2,"total_user_services":7}"#;
        let finding = decode_email(body).unwrap().unwrap();
        assert!(
            finding.summary.contains("2 infostealer records"),
            "{}",
            finding.summary
        );
        assert_eq!(finding.tags, [tags::BREACH]);
        let attr = |key: &str| {
            finding
                .attrs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(attr("stealer_records"), Some("2"));
        assert_eq!(attr("first_compromised"), Some("2022-03-01T00:00:00.000Z"));
        assert_eq!(attr("last_compromised"), Some("2024-07-09T00:00:00.000Z"));
        assert_eq!(attr("corporate_services"), Some("2"));
        assert_eq!(attr("user_services"), Some("7"));
        assert_eq!(attr("stealer_families"), Some("RedLine,Raccoon"));
        // The scrub: none of these planted markers (a password, login, machine name or host
        // address the provider record would carry) survives into the finding anywhere.
        for planted in [
            "SUPERSECRET123",
            "hunter2",
            "victim@example.com",
            "VICTIM-PC",
            "203.0.113.9",
            "portal.example.com",
        ] {
            assert!(
                !finding.summary.contains(planted)
                    && !finding.attrs.iter().any(|(_, v)| v.contains(planted)),
                "leaked {planted}: {finding:?}"
            );
        }
    }

    #[test]
    fn email_without_a_stealers_list_is_schema_drift() {
        assert!(matches!(
            decode_email(br#"{"message":"x"}"#),
            Err(LegError::Decode(_))
        ));
        assert!(matches!(
            decode_email(b"not json"),
            Err(LegError::Decode(_))
        ));
    }

    #[test]
    fn email_blank_dates_do_not_erase_a_real_first_compromised() {
        // A blank `date_compromised` must be dropped, not sorted ahead of a real date and then
        // trimmed away: `first_compromised` must still be the earliest real date.
        let body = br#"{"stealers":[{"date_compromised":""},{"date_compromised":"2024-07-09T00:00:00.000Z"}]}"#;
        let finding = decode_email(body).unwrap().unwrap();
        let attr = |key: &str| {
            finding
                .attrs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(attr("first_compromised"), Some("2024-07-09T00:00:00.000Z"));
        assert_eq!(attr("last_compromised"), Some("2024-07-09T00:00:00.000Z"));
        assert_eq!(attr("stealer_records"), Some("2"));
    }

    #[test]
    fn an_empty_email_asks_nothing() {
        // The endpoint answers 400 to an empty selector, so the leg never sends for one: a
        // refusing transport is never reached, and the result is a clean zero.
        let looked = lookup(
            &crate::test_support::Refusing,
            &Keys::default(),
            Indicator::Email("   "),
            1,
        );
        assert!(matches!(looked, Ok(None)), "{looked:?}");
    }

    #[test]
    fn a_404_on_the_email_endpoint_is_a_failure_not_a_zero() {
        let transport = crate::test_support::OneResponse::json(404, r#"{"detail":"Not Found"}"#);
        let looked = lookup(
            &transport,
            &Keys::default(),
            Indicator::Email("a@example.com"),
            1,
        );
        assert!(
            matches!(looked, Err(LegError::Unexpected(404))),
            "{looked:?}"
        );
    }

    #[test]
    fn email_query_is_encoded() {
        assert!(email_url("a+b@example.com").contains("%2B"));
        assert!(email_url("a+b@example.com").contains("%40"));
        assert!(email_url("a@example.com").contains("search-by-email?email="));
    }
}
