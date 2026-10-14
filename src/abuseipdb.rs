//! `AbuseIPDB` check: community abuse reports for one IP (free key, 1,000 checks a day).
//!
//! One lookup is one `GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90`
//! with the key in the `Key` header. It runs only when `HUNTSMAN_ABUSEIPDB_KEY` is set. The answer
//! is the provider's confidence score (0 to 100), report counts over the window, the network's
//! usage type, ISP and domain, and whether the address is a Tor exit or allow-listed.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::http::{Transport, percent_encode_component};
use crate::keys::Keys;

pub const SOURCE: &str = "abuseipdb";
pub const KEY_SLOT: &str = crate::environment::ABUSEIPDB_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "abuseipdb.com",
    origin: "https://api.abuseipdb.com:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Header("Key"),
        required: true,
    }),
};
/// Days of reports the check covers.
pub const MAX_AGE_DAYS: u32 = 90;

/// What `AbuseIPDB` says about one address.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Check {
    pub confidence: u8,
    pub total_reports: u64,
    pub distinct_reporters: u64,
    pub last_reported: Option<String>,
    pub country: Option<String>,
    pub usage_type: Option<String>,
    pub isp: Option<String>,
    pub domain: Option<String>,
    pub hostnames: Vec<String>,
    pub tor: bool,
    pub allow_listed: Option<bool>,
}

#[derive(Deserialize)]
struct Envelope {
    data: Data,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Data {
    abuse_confidence_score: u8,
    #[serde(default)]
    total_reports: u64,
    #[serde(default)]
    num_distinct_users: u64,
    #[serde(default)]
    last_reported_at: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    usage_type: Option<String>,
    #[serde(default)]
    isp: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    hostnames: Vec<String>,
    #[serde(default)]
    is_tor: bool,
    #[serde(default)]
    is_whitelisted: Option<bool>,
}

/// The request URL for `ip`. **Pure.**
#[must_use]
pub fn url(ip: &str) -> String {
    format!(
        "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays={MAX_AGE_DAYS}",
        percent_encode_component(ip)
    )
}

/// Check `ip` with the key in `keys`.
///
/// # Errors
/// [`LegError::MissingKey`] before any request when no key is configured; otherwise the
/// [`LegError`] that stopped the lookup.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    ip: &str,
    now_unix: u64,
) -> Result<Check, LegError> {
    match api_leg::get(transport, &API, keys, &url(ip), now_unix)? {
        Answer::Body(body) => decode(&body),
        Answer::NotFound(_) => Err(LegError::Unexpected(404)),
    }
}

/// One answer body as a check. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented `data` object.
pub fn decode(body: &[u8]) -> Result<Check, LegError> {
    let data = api_leg::decode::<Envelope>(body)?.data;
    if data.abuse_confidence_score > 100 {
        return Err(LegError::Decode("confidence score above 100".into()));
    }
    let mut hostnames: Vec<String> = data
        .hostnames
        .iter()
        .filter_map(|h| api_leg::clean(Some(h)))
        .collect();
    hostnames.sort();
    hostnames.dedup();
    Ok(Check {
        confidence: data.abuse_confidence_score,
        total_reports: data.total_reports,
        distinct_reporters: data.num_distinct_users,
        last_reported: api_leg::clean(data.last_reported_at.as_deref()),
        country: api_leg::clean(data.country_code.as_deref()),
        usage_type: api_leg::clean(data.usage_type.as_deref()),
        isp: api_leg::clean(data.isp.as_deref()),
        domain: api_leg::clean(data.domain.as_deref()),
        hostnames,
        tor: data.is_tor,
        allow_listed: data.is_whitelisted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `check` example of the `AbuseIPDB` v2 documentation (docs.abuseipdb.com).
    const DOCUMENTED: &str = r#"{"data":{"ipAddress":"118.25.6.39","isPublic":true,"ipVersion":4,"isWhitelisted":false,"abuseConfidenceScore":100,"countryCode":"CN","usageType":"Data Center/Web Hosting/Transit","isp":"Tencent Cloud Computing (Beijing) Co. Ltd","domain":"tencent.com","hostnames":[],"isTor":false,"totalReports":1,"numDistinctUsers":1,"lastReportedAt":"2018-12-20T20:55:14+00:00"}}"#;
    /// Recorded without a key on 2026-10-14 (HTTP 401).
    const REFUSED: &str = r#"{"errors":[{"detail":"Authentication failed. Your API key is either missing, incorrect, or revoked. Note: The APIv2 key differs from the APIv1 key.","status":401}]}"#;

    #[test]
    fn the_documented_answer_decodes() {
        let check = decode(DOCUMENTED.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(check.confidence, 100);
        assert_eq!(check.total_reports, 1);
        assert_eq!(check.distinct_reporters, 1);
        assert_eq!(check.country.as_deref(), Some("CN"));
        assert_eq!(check.domain.as_deref(), Some("tencent.com"));
        assert_eq!(check.allow_listed, Some(false));
        assert!(!check.tor);
    }

    #[test]
    fn an_error_body_is_not_a_clean_address() {
        assert!(decode(REFUSED.as_bytes()).is_err());
    }

    #[test]
    fn the_url_carries_the_window_and_no_key() {
        assert_eq!(
            url("1.2.3.4"),
            "https://api.abuseipdb.com/api/v2/check?ipAddress=1.2.3.4&maxAgeInDays=90"
        );
    }
}
