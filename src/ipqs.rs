//! `IPQualityScore`: fraud score and proxy, VPN, Tor and abuse flags for one public IP.
//!
//! One lookup is one `GET https://ipqualityscore.com/api/json/ip?ip={ip}&strictness=0`, run
//! whenever `HUNTSMAN_IPQS_KEY` is set (free tier: 1,000 lookups a month). The key goes in the
//! `key` query parameter, added as the request is sent, never in the URL path where IPQS's
//! documented path form would put it. IPQS answers HTTP 200 for its own errors, with
//! `success: false` and a `message`: a bad key is reported as a rejected key and spent credits as
//! a plan refusal, never as a zero.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::http::{Transport, percent_encode_component};
use crate::indicator_sources::{Finding, Indicator, PivotKind, Source};
use crate::keys::Keys;
use crate::tags;

pub const SOURCE: &str = "ipqs";
pub const KEY_SLOT: &str = crate::environment::IPQS_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "ipqualityscore.com",
    origin: "https://ipqualityscore.com:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Query("key"),
        required: true,
    }),
};
pub const INTEL: Source = Source {
    api: &API,
    ip: true,
    domain: false,
    lookup,
};
/// IPQS's own threshold for a high-risk address.
pub const HIGH_RISK_SCORE: u8 = 85;

#[derive(Deserialize)]
#[allow(clippy::struct_excessive_bools)]
struct Body {
    success: bool,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    fraud_score: Option<u8>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(rename = "ISP", default)]
    isp: Option<String>,
    #[serde(rename = "ASN", default)]
    asn: Option<u32>,
    #[serde(default)]
    organization: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    connection_type: Option<String>,
    #[serde(default)]
    abuse_velocity: Option<String>,
    #[serde(default)]
    proxy: bool,
    #[serde(default)]
    vpn: bool,
    #[serde(default)]
    tor: bool,
    #[serde(default)]
    recent_abuse: bool,
    #[serde(default)]
    bot_status: bool,
    #[serde(default)]
    is_crawler: bool,
    #[serde(default)]
    mobile: bool,
}

/// The request URL for `ip`. **Pure.**
#[must_use]
pub fn url(ip: &str) -> String {
    format!(
        "https://ipqualityscore.com/api/json/ip?ip={}&strictness=0",
        percent_encode_component(ip)
    )
}

/// Look `indicator` up; a domain is not an IPQS IP lookup.
///
/// # Errors
/// The [`LegError`] that stopped the lookup.
pub fn lookup(
    transport: &dyn Transport,
    keys: &Keys,
    indicator: Indicator<'_>,
    now_unix: u64,
) -> Result<Option<Finding>, LegError> {
    let Indicator::Ip(ip) = indicator else {
        return Ok(None);
    };
    match api_leg::get(transport, &API, keys, &url(ip), now_unix)? {
        Answer::Body(body) => decode(&body).map(Some),
        Answer::NotFound(_) => Err(LegError::Unexpected(404)),
    }
}

/// The error an IPQS `success: false` message means. **Pure.**
fn refusal(message: Option<&str>) -> LegError {
    let message = message.unwrap_or_default().to_ascii_lowercase();
    if message.contains("key") {
        LegError::Unauthorized
    } else if message.contains("credit")
        || message.contains("quota")
        || message.contains("exceeded")
    {
        LegError::Forbidden
    } else {
        LegError::Decode(format!(
            "ipqs refused: {}",
            api_leg::clean(Some(&message)).unwrap_or_default()
        ))
    }
}

/// One answer body. **Pure.**
///
/// # Errors
/// The refusal `success: false` means, or [`LegError::Decode`] for another shape.
pub fn decode(body: &[u8]) -> Result<Finding, LegError> {
    let body: Body = api_leg::decode(body)?;
    if !body.success {
        return Err(refusal(body.message.as_deref()));
    }
    let score = body
        .fraud_score
        .filter(|s| *s <= 100)
        .ok_or_else(|| LegError::Decode("success without a fraud score of 0 to 100".into()))?;
    let flags: Vec<&str> = [
        (body.proxy, "proxy"),
        (body.vpn, "vpn"),
        (body.tor, "tor"),
        (body.recent_abuse, "recent_abuse"),
        (body.bot_status, "bot"),
        (body.is_crawler, "crawler"),
        (body.mobile, "mobile"),
    ]
    .into_iter()
    .filter_map(|(set, name)| set.then_some(name))
    .collect();
    let mut finding = Finding::new(format!(
        "IPQualityScore: fraud score {score}{}",
        if flags.is_empty() {
            String::new()
        } else {
            format!(", {}", flags.join(", "))
        }
    ))
    .attr("fraud_score", score.to_string())
    .list_attr("flags", &flags)
    .opt_attr("connection_type", body.connection_type.as_deref())
    .opt_attr("abuse_velocity", body.abuse_velocity.as_deref())
    .opt_attr("isp", body.isp.as_deref())
    .opt_attr("org", body.organization.as_deref())
    .opt_attr("country", body.country_code.as_deref())
    .opt_attr("city", body.city.as_deref())
    .tag_if(score >= HIGH_RISK_SCORE, tags::MALICIOUS)
    .tag_if(body.vpn, "vpn")
    .tag_if(body.proxy, "proxy")
    .tag_if(body.tor, "tor-exit");
    if let Some(asn) = body.asn.filter(|a| *a > 0) {
        finding = finding.attr("asn", format!("AS{asn}")).pivot(
            PivotKind::Asn,
            format!("AS{asn}"),
            "AS IPQualityScore gives for the address",
        );
    }
    if let Some(host) = body.host.as_deref() {
        finding = finding.pivot(
            PivotKind::Domain,
            host,
            "Hostname IPQualityScore gives for the address",
        );
    }
    Ok(finding)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The documented proxy-detection response shape (IPQS documentation), filled for a VPN exit.
    const DOCUMENTED: &str = r#"{"success":true,"message":"Success","fraud_score":88,"country_code":"NL","region":"North Holland","city":"Amsterdam","ISP":"Example Hosting","ASN":64500,"organization":"Example Hosting B.V.","is_crawler":false,"timezone":"Europe/Amsterdam","mobile":false,"host":"vpn-exit-7.example.net","proxy":true,"vpn":true,"tor":false,"active_vpn":true,"active_tor":false,"recent_abuse":true,"bot_status":false,"connection_type":"Data Center","abuse_velocity":"high","zip_code":"N/A","latitude":52.37,"longitude":4.89,"request_id":"abc123"}"#;
    /// Recorded with an invalid key on 2026-10-14 (HTTP 200).
    const INVALID_KEY: &str = r#"{"success":false,"message":"Invalid or unauthorized key. Please check the API key and try again.","request_id":"lbwl7AvoAc","api_version":2}"#;

    #[test]
    fn the_documented_answer_keeps_score_flags_and_pivots() {
        let f = decode(DOCUMENTED.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            f.summary,
            "IPQualityScore: fraud score 88, proxy, vpn, recent_abuse"
        );
        assert_eq!(f.tags, [tags::MALICIOUS, "vpn", "proxy"]);
        assert!(f.attrs.contains(&("asn", "AS64500".into())));
        assert!(f.pivots.iter().any(|p| p.value == "vpn-exit-7.example.net"));
    }

    #[test]
    fn success_false_is_a_refusal_never_a_zero() {
        assert_eq!(decode(INVALID_KEY.as_bytes()), Err(LegError::Unauthorized));
        let spent = r#"{"success":false,"message":"You have insufficient credits to make this query.","request_id":"x"}"#;
        assert_eq!(decode(spent.as_bytes()), Err(LegError::Forbidden));
    }

    #[test]
    fn the_url_carries_no_key() {
        assert_eq!(
            url("1.1.1.1"),
            "https://ipqualityscore.com/api/json/ip?ip=1.1.1.1&strictness=0"
        );
    }
}
