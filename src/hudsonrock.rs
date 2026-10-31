//! Hudson Rock Cavalier: keyless infostealer intelligence for a domain or an email address.
//!
//! The domain leg is one GET to Cavalier's public search-by-domain endpoint. It answers `200`
//! with how many of the domain's employees, users and third parties an infostealer compromised
//! (`employees`, `users`, `third_parties`), all zero for a domain it holds nothing on (verified
//! 2026-10-31). The results are domain-wide aggregates, so this source deliberately does not claim
//! they identify a particular account, and the raw provider response is never kept: it lists the
//! URLs the stolen credentials were for. A `404` is a failed lookup, never a zero: the host
//! answers `404` for a path it does not serve.
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
/// Returns the typed API-leg error, `LegError::Unexpected(404)` for a `404` from either endpoint,
/// or a decode error for malformed JSON, a missing aggregate count (domain) or a missing
/// `stealers` list (email). Domain counts are deliberately not attributed to an individual
/// account.
pub fn lookup(
    transport: &dyn Transport,
    keys: &Keys,
    indicator: Indicator<'_>,
    now_unix: u64,
) -> Result<Option<Finding>, LegError> {
    match indicator {
        Indicator::Domain(domain) => lookup_domain(transport, keys, domain, now_unix),
        Indicator::Email(email) => lookup_email(transport, keys, email, now_unix),
        _ => Ok(None),
    }
}

/// Look up the aggregates of the domain `domain` is registered under. Cavalier holds them by
/// registrable domain and answers all zero for a host below one (`www.tesla.com` answers zero
/// where `tesla.com` answers its counts, verified 2026-10-31), so a host is asked as its
/// registrable domain, and its finding names that domain (`registrable_domain`).
///
/// # Errors
/// The typed API-leg error, `LegError::Unexpected(404)` for a `404`, or a decode error.
fn lookup_domain(
    transport: &dyn Transport,
    keys: &Keys,
    domain: &str,
    now_unix: u64,
) -> Result<Option<Finding>, LegError> {
    let registered =
        crate::domains::registrable_domain(domain).unwrap_or_else(|| domain.to_owned());
    let finding = match api_leg::get(transport, &API, keys, &url(&registered), now_unix)? {
        Answer::Body(body) => decode(&body)?,
        Answer::NotFound(_) => return Err(LegError::Unexpected(404)),
    };
    Ok(finding.map(|mut finding| {
        if registered != domain {
            finding.summary = format!(
                "{} (asked for {registered}, the domain {domain} is registered under)",
                finding.summary
            );
            finding = finding.attr("registrable_domain", &registered);
        }
        finding
    }))
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
/// All three counts zero is a clean negative. Otherwise the finding keeps them, their `total`,
/// when an employee and a user were last compromised, and the stealer families with how many
/// compromises each took, most first. The URLs the credentials were for (`data`, `stats`) are
/// not read, nor the password-strength figures or the antivirus list; `totalStealers` counts
/// Cavalier's whole database, not the domain.
///
/// # Errors
/// Returns `LegError::Decode` when the response is not UTF-8 JSON with numeric `employees`,
/// `users` and `third_parties` counts.
pub fn decode(body: &[u8]) -> Result<Option<Finding>, LegError> {
    let text =
        std::str::from_utf8(body).map_err(|_| LegError::Decode("answer is not UTF-8".into()))?;
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|_| LegError::Decode("answer is not JSON".into()))?;
    let count = |key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| LegError::Decode(format!("missing or invalid {key}")))
    };
    let employees = count("employees")?;
    let users = count("users")?;
    let third_parties = count("third_parties")?;
    if employees == 0 && users == 0 && third_parties == 0 {
        return Ok(None);
    }
    let text_of = |key: &str| value.get(key).and_then(serde_json::Value::as_str);
    let mut families: Vec<(&str, u64)> = value
        .get("stealerFamilies")
        .and_then(serde_json::Value::as_object)
        .map(|families| {
            families
                .iter()
                .filter(|(name, _)| name.as_str() != "total")
                .filter_map(|(name, count)| Some((name.as_str(), count.as_u64()?)))
                .filter(|(_, count)| *count > 0)
                .collect()
        })
        .unwrap_or_default();
    families.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let mut finding = Finding::new(format!(
        "Hudson Rock: {employees} employees, {users} users and {third_parties} third parties \
         compromised by infostealers"
    ))
    .attr("employees", employees.to_string())
    .attr("users", users.to_string())
    .attr("third_parties", third_parties.to_string())
    .opt_attr(
        "total",
        value
            .get("total")
            .and_then(serde_json::Value::as_u64)
            .map(|total| total.to_string()),
    )
    .opt_attr(
        "last_employee_compromised",
        text_of("last_employee_compromised"),
    )
    .opt_attr("last_user_compromised", text_of("last_user_compromised"));
    if !families.is_empty() {
        let names: Vec<&str> = families.iter().map(|(name, _)| *name).collect();
        let counts: Vec<String> = families
            .iter()
            .map(|(name, count)| format!("{name}={count}"))
            .collect();
        finding = finding
            .list_attr("stealer_families", &names)
            .list_attr("stealer_family_counts", &counts);
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

    /// A domain answer in the live shape (verified 2026-10-31; the values here are synthetic).
    const DOMAIN_ANSWER: &str = r#"{
        "antiviruses":{"total":4,"found":50.0,"not_found":25.0,"free":25.0,"list":[{"count":2,"name":"Windows Defender [ON]"}]},
        "applications":[{"keyword":"sso"}],
        "data":{
            "all_urls":[{"occurrence":4,"type":"Employee","url":"https://sso.example.com/login?token=SENTINEL_TOKEN_31"}],
            "clients_urls":[{"occurrence":9,"type":"User","url":"https://auth.example.com/signin"}],
            "employees_urls":[{"occurrence":4,"type":"Employee","url":"https://sso.example.com/login?token=SENTINEL_TOKEN_31"}]
        },
        "employeePasswords":{"has_stats":true,"too_weak":{"perc":50.0,"qty":1},"weak":{"perc":50.0,"qty":1},"medium":{"perc":0.0,"qty":0},"strong":{"perc":0.0,"qty":0},"totalPass":2},
        "employees":3,
        "is_shopify":false,
        "last_employee_compromised":"2026-09-18T00:00:00.000Z",
        "last_user_compromised":"2026-10-28T14:46:10.000Z",
        "logo":"https://cdn.example.net/logo",
        "stats":{"clients_count":[9],"clients_urls":["https://auth.example.com/signin"],"employees_count":[4],"employees_urls":["https://sso.example.com/login?token=SENTINEL_TOKEN_31"],"totalEmployees":1,"totalUsers":1},
        "stealerFamilies":{"total":15,"Lumma":6,"RedLine":9,"Vidar":0},
        "thirdPartyDomains":[{"domain":"thirdparty.example.net","occurrence":2}],
        "third_parties":2,
        "total":17,
        "totalStealers":37109871,
        "totalUrls":3,
        "userPasswords":{"has_stats":false},
        "users":12
    }"#;

    fn attr<'a>(finding: &'a Finding, key: &str) -> Option<&'a str> {
        finding
            .attrs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn a_domain_answer_keeps_its_aggregates_and_never_a_url_it_lists() {
        let finding = decode(DOMAIN_ANSWER.as_bytes()).unwrap().unwrap();
        assert_eq!(
            finding.summary,
            "Hudson Rock: 3 employees, 12 users and 2 third parties compromised by infostealers"
        );
        assert_eq!(attr(&finding, "employees"), Some("3"));
        assert_eq!(attr(&finding, "users"), Some("12"));
        assert_eq!(attr(&finding, "third_parties"), Some("2"));
        assert_eq!(attr(&finding, "total"), Some("17"));
        assert_eq!(
            attr(&finding, "last_employee_compromised"),
            Some("2026-09-18T00:00:00.000Z")
        );
        assert_eq!(
            attr(&finding, "last_user_compromised"),
            Some("2026-10-28T14:46:10.000Z")
        );
        assert_eq!(attr(&finding, "stealer_families"), Some("RedLine,Lumma"));
        assert_eq!(
            attr(&finding, "stealer_family_counts"),
            Some("RedLine=9,Lumma=6")
        );
        assert!(finding.pivots.is_empty());
        for kept_out in [
            "SENTINEL_TOKEN_31",
            "sso.example.com",
            "auth.example.com",
            "thirdparty.example.net",
            "37109871",
        ] {
            assert!(
                !finding.summary.contains(kept_out)
                    && !finding.attrs.iter().any(|(_, v)| v.contains(kept_out)),
                "kept {kept_out}: {finding:?}"
            );
        }
    }

    /// The live answer for a domain Cavalier holds nothing on (verified 2026-10-31).
    #[test]
    fn valid_zero_is_a_clean_negative() {
        let clean = br#"{"data":{"employees_urls":[],"clients_urls":[],"all_urls":[]},"employees":0,"is_shopify":false,"logo":"https://cdn.example.net/logo","stats":{"totalEmployees":0,"totalUsers":0,"employees_urls":[],"clients_urls":[],"employees_count":[],"clients_count":[]},"third_parties":0,"total":0,"totalStealers":37109871,"totalUrls":0,"users":0}"#;
        assert!(decode(clean).unwrap().is_none());
    }

    #[test]
    fn third_parties_alone_are_no_clean_negative() {
        let body = br#"{"employees":0,"users":0,"third_parties":4,"total":4}"#;
        let finding = decode(body).unwrap().unwrap();
        assert_eq!(attr(&finding, "third_parties"), Some("4"));
    }

    #[test]
    fn malformed_aggregate_is_not_silently_reported_as_zero() {
        assert!(decode(br#"{"status":"ok"}"#).is_err());
        assert!(decode(b"not JSON").is_err());
        // Counts the endpoint does not send are no answer, and neither is a count missing.
        assert!(decode(br#"{"total_employees":0,"total_users":0}"#).is_err());
        assert!(decode(br#"{"employees":0,"users":0}"#).is_err());
        assert!(decode(br#"{"employees":"3","users":0,"third_parties":0}"#).is_err());
    }

    /// Cavalier answers all zero for a host below a registrable domain, so a host is asked as the
    /// domain it is registered under, and the finding names that domain; a registrable domain is
    /// asked as itself.
    #[test]
    fn a_host_is_asked_as_the_domain_it_is_registered_under() {
        let prefix = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain";
        let transport = crate::test_support::RoutedTransport::new(&[(prefix, 200, DOMAIN_ANSWER)]);
        let finding = lookup(
            &transport,
            &Keys::default(),
            Indicator::Domain("www.shop.example.co.uk"),
            1,
        )
        .unwrap()
        .unwrap();
        assert_eq!(transport.urls(), [url("example.co.uk")]);
        assert_eq!(attr(&finding, "registrable_domain"), Some("example.co.uk"));
        assert!(
            finding.summary.ends_with(
                "(asked for example.co.uk, the domain www.shop.example.co.uk is registered under)"
            ),
            "{}",
            finding.summary
        );

        let transport = crate::test_support::RoutedTransport::new(&[(prefix, 200, DOMAIN_ANSWER)]);
        let finding = lookup(
            &transport,
            &Keys::default(),
            Indicator::Domain("example.com"),
            1,
        )
        .unwrap()
        .unwrap();
        assert_eq!(transport.urls(), [url("example.com")]);
        assert_eq!(attr(&finding, "registrable_domain"), None);
    }

    /// The host answers `404` for a path it does not serve, as it would after the endpoint moved.
    #[test]
    fn a_404_on_the_domain_endpoint_is_a_failure_not_a_zero() {
        let transport = crate::test_support::OneResponse::json(404, r#"{"detail":"Not Found"}"#);
        let looked = lookup(
            &transport,
            &Keys::default(),
            Indicator::Domain("example.com"),
            1,
        );
        assert!(
            matches!(looked, Err(LegError::Unexpected(404))),
            "{looked:?}"
        );
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
