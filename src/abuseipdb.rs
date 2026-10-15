//! `AbuseIPDB` check: community abuse reports for one IP (free key, 1,000 checks a day).
//!
//! One lookup is one
//! `GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose` with the key
//! in the `Key` header. It runs only when `HUNTSMAN_ABUSEIPDB_KEY` is set. The answer is the
//! provider's confidence score (0 to 100), report counts over the window, the network's usage
//! type, ISP and domain, whether the address is public, a Tor exit or allow-listed, and (asked for
//! with `verbose`) every report: when, which abuse categories, the reporter's id and country and
//! their comment. All of it is kept, with the whole answer as `raw_answer`. An answer whose
//! `ipAddress` is not the address looked up (however either is written) is refused.

use serde::Deserialize;
use std::net::IpAddr;

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
    pub country_name: Option<String>,
    pub public: Option<bool>,
    pub ip_version: Option<u8>,
    /// Each report in answer order: `reported at | categories | reporter | comment`.
    pub reports: Vec<String>,
    /// Each abuse category reported, by name, with how many reports give it, most first.
    pub categories: Vec<String>,
    /// The whole answer as compact JSON.
    pub raw_answer: String,
    /// The answer with every report was past the body limit, so this is the check without them.
    pub reports_unread: bool,
}

#[derive(Deserialize)]
struct Envelope {
    data: Data,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Data {
    ip_address: String,
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
    #[serde(default)]
    country_name: Option<String>,
    #[serde(default)]
    is_public: Option<bool>,
    #[serde(default)]
    ip_version: Option<u8>,
    #[serde(default)]
    reports: Vec<Reported>,
}

/// One report, as `verbose` lists it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Reported {
    #[serde(default)]
    reported_at: Option<String>,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    categories: Vec<u16>,
    #[serde(default)]
    reporter_id: Option<u64>,
    #[serde(default)]
    reporter_country_code: Option<String>,
    #[serde(default)]
    reporter_country_name: Option<String>,
}

/// The name `AbuseIPDB` gives category `id` (<https://www.abuseipdb.com/categories>). **Pure.**
#[must_use]
pub const fn category_name(id: u16) -> Option<&'static str> {
    Some(match id {
        1 => "DNS Compromise",
        2 => "DNS Poisoning",
        3 => "Fraud Orders",
        4 => "DDoS Attack",
        5 => "FTP Brute-Force",
        6 => "Ping of Death",
        7 => "Phishing",
        8 => "Fraud VoIP",
        9 => "Open Proxy",
        10 => "Web Spam",
        11 => "Email Spam",
        12 => "Blog Spam",
        13 => "VPN IP",
        14 => "Port Scan",
        15 => "Hacking",
        16 => "SQL Injection",
        17 => "Spoofing",
        18 => "Brute-Force",
        19 => "Bad Web Bot",
        20 => "Exploited Host",
        21 => "Web App Attack",
        22 => "SSH",
        23 => "IoT Targeted",
        _ => return None,
    })
}

/// Category `id` by name, or `category {id}` for one this list does not know. **Pure.**
fn category(id: u16) -> String {
    category_name(id).map_or_else(|| format!("category {id}"), str::to_owned)
}

/// One report as a row: `reported at | categories | reporter id (country) | comment`, a
/// comment's line breaks as spaces and a part the report leaves empty left out. **Pure.**
fn report_row(report: &Reported) -> String {
    let categories: Vec<String> = report.categories.iter().map(|id| category(*id)).collect();
    let country = report
        .reporter_country_name
        .as_deref()
        .or(report.reporter_country_code.as_deref());
    let reporter = match (report.reporter_id, country) {
        (Some(id), Some(country)) => format!("reporter {id} ({country})"),
        (Some(id), None) => format!("reporter {id}"),
        (None, Some(country)) => format!("reporter in {country}"),
        (None, None) => String::new(),
    };
    let comment = report
        .comment
        .as_deref()
        .map(|c| c.split_whitespace().collect::<Vec<_>>().join(" "))
        .unwrap_or_default();
    [
        report.reported_at.clone().unwrap_or_default(),
        categories.join(", "),
        reporter,
        comment,
    ]
    .iter()
    .filter_map(|part| api_leg::clean(Some(part)))
    .collect::<Vec<_>>()
    .join(" | ")
}

/// The request URL for `ip`, asking for every report. **Pure.**
#[must_use]
pub fn url(ip: &str) -> String {
    format!("{}&verbose", summary_url(ip))
}

/// The request URL for `ip` without the report list. **Pure.**
#[must_use]
pub fn summary_url(ip: &str) -> String {
    format!(
        "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays={MAX_AGE_DAYS}",
        percent_encode_component(ip)
    )
}

/// Check `ip` with the key in `keys`, asking for every report. When the answer with every report
/// is past the body limit, the check is asked again without them and says so
/// ([`Check::reports_unread`]), so the score and counts are never lost to the list's length.
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
    match check(transport, keys, &url(ip), ip, now_unix) {
        Err(LegError::TooLarge) => {
            let mut summary = check(transport, keys, &summary_url(ip), ip, now_unix)?;
            summary.reports_unread = true;
            Ok(summary)
        }
        answered => answered,
    }
}

fn check<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    url: &str,
    ip: &str,
    now_unix: u64,
) -> Result<Check, LegError> {
    match api_leg::get(transport, &API, keys, url, now_unix)? {
        Answer::Body(body) => decode(&body, ip),
        Answer::NotFound(_) => Err(LegError::Unexpected(404)),
    }
}

/// One answer body as the check on `ip`. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented `data` object or is about another
/// address.
pub fn decode(body: &[u8], ip: &str) -> Result<Check, LegError> {
    let whole: serde_json::Value = api_leg::decode(body)?;
    let data = api_leg::decode::<Envelope>(body)?.data;
    if !matches!(
        (data.ip_address.trim().parse::<IpAddr>(), ip.parse::<IpAddr>()),
        (Ok(answered), Ok(asked)) if answered == asked
    ) {
        return Err(LegError::Decode("answer names another address".into()));
    }
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
    let mut counts: Vec<(u16, usize)> = Vec::new();
    for id in data.reports.iter().flat_map(|r| &r.categories) {
        match counts.iter_mut().find(|(seen, _)| seen == id) {
            Some((_, n)) => *n += 1,
            None => counts.push((*id, 1)),
        }
    }
    counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
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
        country_name: api_leg::clean(data.country_name.as_deref()),
        public: data.is_public,
        ip_version: data.ip_version,
        reports: data.reports.iter().map(report_row).collect(),
        categories: counts
            .iter()
            .map(|(id, n)| format!("{} ({n})", category(*id)))
            .collect(),
        raw_answer: whole.to_string(),
        reports_unread: false,
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
        let check = decode(DOCUMENTED.as_bytes(), "118.25.6.39").unwrap_or_else(|e| panic!("{e}"));
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
        assert!(decode(REFUSED.as_bytes(), "118.25.6.39").is_err());
    }

    #[test]
    fn a_check_on_another_address_is_refused_not_reported() {
        let keys = Keys::parse(&format!("{KEY_SLOT}=abuseipdb-test-key\n"))
            .unwrap_or_else(|e| panic!("keys: {e}"));
        let looked_up = |ip: &str, body: &str| {
            lookup(
                &crate::test_support::OneResponse::json(200, body),
                &keys,
                ip,
                1,
            )
        };
        let got = looked_up("8.8.8.8", DOCUMENTED);
        assert!(matches!(got, Err(LegError::Decode(_))), "{got:?}");
        let unnamed = r#"{"data":{"abuseConfidenceScore":100,"totalReports":3}}"#;
        let got = looked_up("118.25.6.39", unnamed);
        assert!(matches!(got, Err(LegError::Decode(_))), "{got:?}");
        // The same address, however it is written, is the subject.
        let full =
            r#"{"data":{"ipAddress":"2606:4700:4700:0:0:0:0:1111","abuseConfidenceScore":0}}"#;
        assert!(looked_up("2606:4700:4700::1111", full).is_ok());
    }

    #[test]
    fn the_url_carries_the_window_and_no_key() {
        assert_eq!(
            url("1.2.3.4"),
            "https://api.abuseipdb.com/api/v2/check?ipAddress=1.2.3.4&maxAgeInDays=90&verbose"
        );
    }
}
