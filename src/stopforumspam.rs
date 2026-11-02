//! `StopForumSpam`: how often one email address or IP address has been reported for forum spam.
//!
//! One lookup is one keyless `GET https://api.stopforumspam.org/api?{email|ip}=VALUE&json`. Kept:
//! whether the value appears, how many reports it has, when it was last reported, the service's
//! confidence score, and for an address whether it is a Tor exit, its origin AS (also an ASN
//! pivot), its country, and for IPv6 the prefix the service counts the reports under
//! (`normalized`, such as `2a0b:f4c2::` for `2a0b:f4c2::1`). A value with no reports is a valid
//! zero.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, LegError};
use crate::http::{Transport, percent_encode_component};
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, PivotKind, Source};
use crate::keys::Keys;
use crate::tags;

pub const SOURCE: &str = "stopforumspam";
pub const API: Api = Api {
    source: SOURCE,
    provider: "stopforumspam.org",
    origin: "https://api.stopforumspam.org:443",
    key: None,
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Email, IndicatorKind::Ip],
    lookup,
};

#[derive(Deserialize)]
struct Body {
    success: u8,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    email: Option<Entry>,
    #[serde(default)]
    ip: Option<Entry>,
}

// StopForumSpam has returned both JSON numbers and decimal strings for confidence.
// Reject other types and non-finite strings rather than losing evidence as a false zero.
#[derive(Deserialize)]
#[serde(untagged)]
enum ConfidenceWire {
    Number(f64),
    Decimal(String),
}

fn deserialize_confidence<'de, D>(deserializer: D) -> Result<Option<f64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;

    Option::<ConfidenceWire>::deserialize(deserializer)?
        .map(|raw| {
            let value = match raw {
                ConfidenceWire::Number(value) => value,
                ConfidenceWire::Decimal(text) => text
                    .parse::<f64>()
                    .map_err(|_| D::Error::custom("invalid StopForumSpam confidence decimal"))?,
            };
            if !value.is_finite() {
                Err(D::Error::custom("non-finite StopForumSpam confidence"))
            } else if !(0.0..=100.0).contains(&value) {
                Err(D::Error::custom("StopForumSpam confidence outside 0..=100"))
            } else {
                Ok(value)
            }
        })
        .transpose()
}

/// One queried value's record. Verify any echoed `value` against the target; never retain it in evidence.
#[derive(Deserialize)]
struct Entry {
    #[serde(default)]
    value: Option<String>,
    // Both counters are required: an absent field must not manufacture a valid zero.
    appears: u8,
    frequency: u64,
    #[serde(default)]
    lastseen: Option<String>,
    #[serde(default, deserialize_with = "deserialize_confidence")]
    confidence: Option<f64>,
    #[serde(default)]
    torexit: u8,
    #[serde(default)]
    asn: Option<u64>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    normalized: Option<String>,
}

/// The request URL for `indicator`, or `None` when it is not an email or IP address. **Pure.**
#[must_use]
pub fn url(indicator: Indicator<'_>) -> Option<String> {
    let (field, value) = match indicator {
        Indicator::Email(email) => ("email", email),
        Indicator::Ip(ip) => ("ip", ip),
        _ => return None,
    };
    Some(format!(
        "https://api.stopforumspam.org/api?{field}={}&json",
        percent_encode_component(value)
    ))
}

/// Look `indicator` up; an email or IP address is a `StopForumSpam` lookup.
///
/// # Errors
/// The [`LegError`] that stopped the lookup.
pub fn lookup(
    transport: &dyn Transport,
    keys: &Keys,
    indicator: Indicator<'_>,
    now_unix: u64,
) -> Result<Option<Finding>, LegError> {
    let Some(url) = url(indicator) else {
        return Ok(None);
    };
    match api_leg::get(transport, &API, keys, &url, now_unix)? {
        Answer::Body(body) => decode(&body, indicator),
        Answer::NotFound(_) => Err(LegError::Unexpected(404)),
    }
}

// A provider's echoed target is not evidence about some other indicator.
// Email local parts are case-sensitive; only the DNS domain is case-insensitive.
fn matches_echo(indicator: Indicator<'_>, echoed: &str) -> bool {
    match indicator {
        Indicator::Email(email) => match (echoed.rsplit_once('@'), email.rsplit_once('@')) {
            (Some((echo_local, echo_domain)), Some((local, domain))) => {
                echo_local == local && echo_domain.eq_ignore_ascii_case(domain)
            }
            _ => echoed == email,
        },
        Indicator::Ip(ip) => match (
            echoed.parse::<std::net::IpAddr>(),
            ip.parse::<std::net::IpAddr>(),
        ) {
            (Ok(echo), Ok(target)) => echo == target,
            _ => false,
        },
        _ => false,
    }
}

/// One answer body for `indicator`. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented shape or reports a failure.
pub fn decode(body: &[u8], indicator: Indicator<'_>) -> Result<Option<Finding>, LegError> {
    let body: Body = api_leg::decode(body)?;
    if body.success != 1 {
        let reason = api_leg::clean(body.error.as_deref())
            .unwrap_or_else(|| "the service reported a failure".into());
        return Err(LegError::Decode(format!("StopForumSpam: {reason}")));
    }
    let (entry, what) = match indicator {
        Indicator::Email(_) => (body.email, "address"),
        Indicator::Ip(_) => (body.ip, "IP address"),
        _ => return Ok(None),
    };
    let Some(entry) = entry else {
        return Err(LegError::Decode(
            "answer has no record for the value".into(),
        ));
    };
    // Check the echoed indicator even for zero reports: a different target is not a valid zero.
    // Keep both the request and the provider's echoed value out of error messages and findings.
    if entry
        .value
        .as_deref()
        .is_some_and(|echoed| !matches_echo(indicator, echoed))
    {
        return Err(LegError::Decode(
            "StopForumSpam: echoed value does not match requested indicator".into(),
        ));
    }
    // The provider's documented no-match response is exactly appears=0/frequency=0.
    // Inconsistent flags or unsupported appears values establish neither presence nor absence.
    if entry.appears > 1 || (entry.appears == 0) != (entry.frequency == 0) {
        return Err(LegError::Decode(
            "StopForumSpam: contradictory appears/frequency counters".into(),
        ));
    }
    if entry.appears == 0 {
        return Ok(None);
    }
    let last = api_leg::clean(entry.lastseen.as_deref());
    let confidence = entry.confidence.map(|c| format!("{c:.2}"));
    let country = api_leg::clean(entry.country.as_deref()).map(|c| c.to_ascii_uppercase());
    let normalized = api_leg::clean(entry.normalized.as_deref());
    let mut finding = Finding::new(format!(
        "StopForumSpam: the {what} has {} spam report{}{}",
        entry.frequency,
        if entry.frequency == 1 { "" } else { "s" },
        last.as_deref()
            .map_or_else(String::new, |l| format!(", last on {l}"))
    ))
    .attr("reports", entry.frequency.to_string())
    .opt_attr("last_reported", last.as_deref())
    .opt_attr("confidence", confidence.as_deref())
    .tag("spam-reported")
    .tag_if(entry.torexit == 1, tags::TOR_EXIT)
    .opt_attr("country", country.as_deref())
    .opt_attr("normalized", normalized.as_deref());
    if let Some(asn) = entry.asn.filter(|a| *a > 0) {
        finding = finding.attr("asn", format!("AS{asn}")).pivot(
            PivotKind::Asn,
            format!("AS{asn}"),
            "Origin AS StopForumSpam gives for the address",
        );
    }
    Ok(Some(finding))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded for `185.220.101.1` and `test@example.com` on 2026-10-14.
    const RECORDED: &str = r#"{"success":1,"ip":{"value":"185.220.101.1","appears":1,"frequency":91,"lastseen":"2026-10-13 07:37:12","torexit":1,"asn":60729,"country":"de","confidence":95.29},"email":{"value":"test@example.com","appears":1,"frequency":2,"lastseen":"2026-09-14 16:30:38","confidence":0.56}}"#;

    #[test]
    fn a_reported_ip_keeps_count_last_report_confidence_and_the_tor_tag() {
        let f = decode(RECORDED.as_bytes(), Indicator::Ip("185.220.101.1"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        assert_eq!(
            f.summary,
            "StopForumSpam: the IP address has 91 spam reports, last on 2026-10-13 07:37:12"
        );
        assert_eq!(f.tags, ["spam-reported", tags::TOR_EXIT]);
        assert!(
            f.attrs
                .iter()
                .any(|(k, v)| *k == "confidence" && v == "95.29")
        );
    }

    #[test]
    fn a_reported_ip_keeps_its_origin_as_and_country() {
        let f = decode(RECORDED.as_bytes(), Indicator::Ip("185.220.101.1"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        assert!(
            f.attrs.contains(&("asn", "AS60729".into())),
            "{:?}",
            f.attrs
        );
        assert!(f.attrs.contains(&("country", "DE".into())), "{:?}", f.attrs);
        assert!(
            f.pivots
                .iter()
                .any(|p| p.kind == PivotKind::Asn && p.value == "AS60729"),
            "{:?}",
            f.pivots
        );
    }

    #[test]
    fn an_ipv6_report_keeps_the_prefix_it_is_counted_under() {
        // Recorded for `2a0b:f4c2::1` on 2026-10-15.
        let body = r#"{"success":1,"ip":{"value":"2a0b:f4c2::1","appears":1,"frequency":41,"lastseen":"2026-10-13 19:25:50","asn":60729,"country":"de","normalized":"2a0b:f4c2::","confidence":90.11}}"#;
        let f = decode(body.as_bytes(), Indicator::Ip("2a0b:f4c2::1"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        assert!(
            f.attrs.contains(&("normalized", "2a0b:f4c2::".into())),
            "{:?}",
            f.attrs
        );
        assert!(f.attrs.contains(&("asn", "AS60729".into())));
    }

    #[test]
    fn a_reported_email_reads_its_own_record_and_does_not_echo_the_address() {
        let f = decode(RECORDED.as_bytes(), Indicator::Email("test@example.com"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        assert_eq!(f.tags, ["spam-reported"]);
        assert!(!format!("{f:?}").contains("test@example.com"));
    }

    #[test]
    fn live_decimal_string_confidence_keeps_the_report_and_does_not_echo_the_email() {
        // Reproduced from the public API for the reserved example-domain indicator
        // test@example.com on 2026-11-03. The previous f64-only field rejected it.
        let body = r#"{"success":1,"email":{"value":"test@example.com","appears":1,"frequency":3,"lastseen":"2026-10-31 11:47:01","confidence":"40.00"}}"#;
        let finding = decode(body.as_bytes(), Indicator::Email("test@example.com"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("string-encoded confidence must decode"));
        assert_eq!(
            finding.summary,
            "StopForumSpam: the address has 3 spam reports, last on 2026-10-31 11:47:01"
        );
        assert!(finding.attrs.contains(&("reports", "3".into())));
        assert!(finding.attrs.contains(&("confidence", "40.00".into())));
        assert!(!format!("{finding:?}").contains("test@example.com"));
    }

    #[test]
    fn malformed_confidence_cannot_be_silently_accepted_as_absence() {
        for malformed in [
            r#""invalid""#,
            r#""NaN""#,
            "true",
            "{}",
            "[]",
            "-0.01",
            "100.01",
            r#""-0.01""#,
            r#""100.01""#,
        ] {
            let body = format!(
                r#"{{"success":1,"email":{{"appears":1,"frequency":3,"confidence":{malformed}}}}}"#
            );
            assert!(
                matches!(
                    decode(body.as_bytes(), Indicator::Email("test@example.com")),
                    Err(LegError::Decode(_))
                ),
                "malformed confidence must fail closed: {malformed}"
            );
        }
    }

    #[test]
    fn confidence_range_boundaries_preserve_both_wire_formats() {
        for (wire, expected) in [
            ("0", "0.00"),
            (r#""0""#, "0.00"),
            ("100", "100.00"),
            (r#""100.00""#, "100.00"),
        ] {
            let body = format!(
                r#"{{"success":1,"email":{{"appears":1,"frequency":3,"confidence":{wire}}}}}"#
            );
            let finding = decode(body.as_bytes(), Indicator::Email("test@example.com"))
                .ok()
                .flatten()
                .unwrap_or_else(|| panic!("valid confidence boundary must decode: {wire}"));
            assert!(
                finding.attrs.contains(&("confidence", expected.to_owned())),
                "unexpected confidence for {wire}"
            );
        }
    }

    #[test]
    fn an_unreported_value_is_a_valid_zero_and_a_failure_is_an_error() {
        let none = r#"{"success":1,"ip":{"value":"8.8.8.8","frequency":0,"appears":0,"asn":15169,"country":"us"}}"#;
        assert!(matches!(
            decode(none.as_bytes(), Indicator::Ip("8.8.8.8")),
            Ok(None)
        ));
        let failed = r#"{"success":0,"error":"invalid ip"}"#;
        assert!(matches!(
            decode(failed.as_bytes(), Indicator::Ip("8.8.8.8")),
            Err(LegError::Decode(m)) if m.contains("invalid ip")
        ));
    }

    #[test]
    fn missing_or_conflicting_report_counters_are_not_evidence() {
        for record in [
            r#"{"appears":0,"frequency":2}"#,
            r#"{"appears":1,"frequency":0}"#,
            r#"{"appears":2,"frequency":3}"#,
            r#"{"appears":0}"#,
            r#"{"frequency":0}"#,
            r"{}",
        ] {
            let body = format!(r#"{{"success":1,"ip":{record}}}"#);
            assert!(
                matches!(
                    decode(body.as_bytes(), Indicator::Ip("8.8.8.8")),
                    Err(LegError::Decode(_))
                ),
                "missing or contradictory provider counters must fail closed: {record}"
            );
        }
    }

    #[test]
    fn echoed_value_mismatch_is_not_attributed_to_the_target() {
        for (body, indicator) in [
            (
                r#"{"success":1,"email":{"value":"other@example.com","appears":1,"frequency":3}}"#,
                Indicator::Email("test@example.com"),
            ),
            (
                r#"{"success":1,"email":{"value":"other@example.com","appears":0,"frequency":0}}"#,
                Indicator::Email("test@example.com"),
            ),
            (
                r#"{"success":1,"ip":{"value":"8.8.4.4","appears":0,"frequency":0}}"#,
                Indicator::Ip("8.8.8.8"),
            ),
            (
                r#"{"success":1,"email":{"value":"TEST@example.com","appears":1,"frequency":3}}"#,
                Indicator::Email("test@example.com"),
            ),
        ] {
            let result = decode(body.as_bytes(), indicator);
            assert!(
                matches!(&result, Err(LegError::Decode(_))),
                "an echoed mismatch must not establish target evidence: {indicator:?}"
            );
            assert!(
                !format!("{result:?}").contains("other@example.com"),
                "do not expose echoed values in diagnostic errors"
            );
        }
    }

    #[test]
    fn echo_verification_allows_equal_ip_addresses_and_email_domains() {
        let ipv6 = r#"{"success":1,"ip":{"value":"2001:0db8:0:0::1","appears":1,"frequency":1}}"#;
        assert!(matches!(
            decode(ipv6.as_bytes(), Indicator::Ip("2001:db8::1")),
            Ok(Some(_))
        ));
        let email =
            r#"{"success":1,"email":{"value":"test@EXAMPLE.COM","appears":1,"frequency":1}}"#;
        assert!(matches!(
            decode(email.as_bytes(), Indicator::Email("test@example.com")),
            Ok(Some(_))
        ));
    }

    #[test]
    fn only_email_and_ip_build_a_url_and_the_value_is_encoded() {
        assert_eq!(
            url(Indicator::Email("a+b@example.com")).as_deref(),
            Some("https://api.stopforumspam.org/api?email=a%2Bb%40example.com&json")
        );
        assert!(url(Indicator::Domain("example.com")).is_none());
    }
}
