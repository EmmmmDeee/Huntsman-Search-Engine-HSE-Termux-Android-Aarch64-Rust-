//! `StopForumSpam`: how often one email address or IP address has been reported for forum spam.
//!
//! One lookup is one keyless `GET https://api.stopforumspam.org/api?{email|ip}=VALUE&json`. Kept:
//! whether the value appears, how many reports it has, when it was last reported, the service's
//! confidence score, and (for an address) whether it is a Tor exit. A value with no reports is a
//! valid zero.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, LegError};
use crate::http::{Transport, percent_encode_component};
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, Source};
use crate::keys::Keys;

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

/// One queried value's record; `value` echoes the query and is not kept.
#[derive(Deserialize)]
struct Entry {
    #[serde(default)]
    appears: u8,
    #[serde(default)]
    frequency: u64,
    #[serde(default)]
    lastseen: Option<String>,
    #[serde(default)]
    confidence: Option<f64>,
    #[serde(default)]
    torexit: u8,
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
    if entry.appears == 0 {
        return Ok(None);
    }
    let last = api_leg::clean(entry.lastseen.as_deref());
    let confidence = entry.confidence.map(|c| format!("{c:.2}"));
    Ok(Some(
        Finding::new(format!(
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
        .tag_if(entry.torexit == 1, "tor-exit"),
    ))
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
        assert_eq!(f.tags, ["spam-reported", "tor-exit"]);
        assert!(
            f.attrs
                .iter()
                .any(|(k, v)| *k == "confidence" && v == "95.29")
        );
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
    fn only_email_and_ip_build_a_url_and_the_value_is_encoded() {
        assert_eq!(
            url(Indicator::Email("a+b@example.com")).as_deref(),
            Some("https://api.stopforumspam.org/api?email=a%2Bb%40example.com&json")
        );
        assert!(url(Indicator::Domain("example.com")).is_none());
    }
}
