//! `IPQualityScore`: fraud scoring for one public IP, email address or phone number.
//!
//! One lookup is one `GET https://www.ipqualityscore.com/api/json/{ip|email|phone}?{kind}={value}`
//! with the key in the documented `ipqs-key` header, run whenever `HUNTSMAN_IPQS_KEY` is set
//! (free tier: 1,000 lookups a month, shared by the three kinds). The key never goes in the URL
//! path, where IPQS's other documented form would put it. IPQS answers HTTP 200 for its own
//! errors, with `success: false` and a `message`: a bad key is reported as a rejected key and
//! spent credits as a plan refusal, never as a zero.
//!
//! An address gives the fraud score, proxy/VPN/Tor/abuse flags (and whether the VPN or Tor exit
//! is active now), ISP, AS, hostname, city, region, postcode, time zone and position; the
//! position is also a coordinates pivot. An email
//! gives validity, deliverability, disposable/honeypot/leaked flags, first-seen and domain age,
//! and any names or numbers IPQS associates with it. A number gives validity, line type, carrier,
//! VOIP/prepaid/risky/leaked flags and region.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::canonical::canonical_coordinates;
use crate::http::{Transport, percent_encode_component};
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, PivotKind, Source};
use crate::keys::Keys;
use crate::tags;

pub const SOURCE: &str = "ipqs";
pub const KEY_SLOT: &str = crate::environment::IPQS_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "ipqualityscore.com",
    origin: "https://www.ipqualityscore.com:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Header("ipqs-key"),
        required: true,
    }),
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[
        IndicatorKind::Ip,
        IndicatorKind::Email,
        IndicatorKind::Phone,
    ],
    lookup,
};
/// IPQS's own threshold for a high-risk indicator.
pub const HIGH_RISK_SCORE: u8 = 85;
/// Most associated names or numbers kept.
const MAX_ASSOCIATED: usize = 10;

#[derive(Deserialize)]
struct Envelope {
    success: bool,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    fraud_score: Option<u8>,
}

#[derive(Deserialize)]
#[allow(clippy::struct_excessive_bools)]
struct IpBody {
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    zip_code: Option<String>,
    #[serde(default)]
    timezone: Option<String>,
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
    #[serde(default)]
    active_vpn: bool,
    #[serde(default)]
    active_tor: bool,
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

#[derive(Deserialize)]
#[allow(clippy::struct_excessive_bools)]
struct EmailBody {
    #[serde(default)]
    valid: bool,
    #[serde(default)]
    disposable: bool,
    #[serde(default)]
    honeypot: bool,
    #[serde(default)]
    leaked: bool,
    #[serde(default)]
    recent_abuse: bool,
    #[serde(default)]
    suspect: bool,
    #[serde(default)]
    catch_all: bool,
    #[serde(default)]
    frequent_complainer: bool,
    #[serde(default)]
    deliverability: Option<String>,
    #[serde(default)]
    smtp_score: Option<i8>,
    #[serde(default)]
    first_seen: Option<Stamp>,
    #[serde(default)]
    domain_age: Option<Stamp>,
    #[serde(default)]
    associated_names: Option<Associated>,
    #[serde(default)]
    associated_phone_numbers: Option<Associated>,
}

#[derive(Deserialize)]
struct Stamp {
    #[serde(default)]
    iso: Option<String>,
}

#[derive(Deserialize)]
struct Associated {
    #[serde(default, alias = "phone_numbers")]
    names: Vec<String>,
}

#[derive(Deserialize)]
#[allow(clippy::struct_excessive_bools)]
struct PhoneBody {
    #[serde(default)]
    valid: bool,
    #[serde(default)]
    active: Option<bool>,
    #[serde(rename = "VOIP", default)]
    voip: bool,
    #[serde(default)]
    prepaid: Option<bool>,
    #[serde(default)]
    risky: bool,
    #[serde(default)]
    leaked: bool,
    #[serde(default)]
    spammer: bool,
    #[serde(default)]
    recent_abuse: bool,
    #[serde(default)]
    carrier: Option<String>,
    #[serde(default)]
    line_type: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    region: Option<String>,
}

/// The request URL for `indicator`, `None` for a domain. **Pure.**
#[must_use]
pub fn url(indicator: Indicator<'_>) -> Option<String> {
    let kind = match indicator {
        Indicator::Ip(_) => "ip",
        Indicator::Email(_) => "email",
        Indicator::Phone(_) => "phone",
        Indicator::Domain(_) => return None,
    };
    Some(format!(
        "https://www.ipqualityscore.com/api/json/{kind}?{kind}={}",
        percent_encode_component(indicator.value())
    ))
}

/// Look `indicator` up.
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
        Answer::Body(body) => decode(&body, indicator).map(Some),
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

fn flags(pairs: &[(bool, &'static str)]) -> Vec<&'static str> {
    pairs
        .iter()
        .filter_map(|(set, name)| set.then_some(*name))
        .collect()
}

fn summary(what: &str, score: u8, flags: &[&str]) -> String {
    if flags.is_empty() {
        format!("IPQualityScore {what}: fraud score {score}")
    } else {
        format!(
            "IPQualityScore {what}: fraud score {score}, {}",
            flags.join(", ")
        )
    }
}

/// One answer body for `indicator`. **Pure.**
///
/// # Errors
/// The refusal `success: false` means, or [`LegError::Decode`] for another shape.
pub fn decode(body: &[u8], indicator: Indicator<'_>) -> Result<Finding, LegError> {
    let envelope: Envelope = api_leg::decode(body)?;
    if !envelope.success {
        return Err(refusal(envelope.message.as_deref()));
    }
    let score = envelope
        .fraud_score
        .filter(|s| *s <= 100)
        .ok_or_else(|| LegError::Decode("success without a fraud score of 0 to 100".into()))?;
    let finding = match indicator {
        Indicator::Ip(_) => ip(&api_leg::decode(body)?, score),
        Indicator::Email(_) => email(&api_leg::decode(body)?, score),
        Indicator::Phone(_) => phone(&api_leg::decode(body)?, score),
        Indicator::Domain(_) => return Err(LegError::Decode("no domain lookup".into())),
    };
    Ok(finding
        .attr("fraud_score", score.to_string())
        .tag_if(score >= HIGH_RISK_SCORE, tags::MALICIOUS))
}

fn ip(body: &IpBody, score: u8) -> Finding {
    let set = flags(&[
        (body.proxy, "proxy"),
        (body.vpn, "vpn"),
        (body.tor, "tor"),
        (body.recent_abuse, "recent_abuse"),
        (body.bot_status, "bot"),
        (body.is_crawler, "crawler"),
        (body.mobile, "mobile"),
        (body.active_vpn, "active_vpn"),
        (body.active_tor, "active_tor"),
    ]);
    let mut finding = Finding::new(summary("IP", score, &set))
        .list_attr("flags", &set)
        .opt_attr("connection_type", body.connection_type.as_deref())
        .opt_attr("abuse_velocity", body.abuse_velocity.as_deref())
        .opt_attr("isp", body.isp.as_deref())
        .opt_attr("org", body.organization.as_deref())
        .opt_attr("country", body.country_code.as_deref())
        .opt_attr("city", body.city.as_deref())
        .opt_attr("region", body.region.as_deref())
        .opt_attr("postal_code", known(body.zip_code.as_deref()))
        .opt_attr("timezone", body.timezone.as_deref())
        .tag_if(body.vpn, "vpn")
        .tag_if(body.proxy, "proxy")
        .tag_if(body.tor, "tor-exit");
    let position = body
        .latitude
        .zip(body.longitude)
        .and_then(|(lat, lon)| canonical_coordinates(&format!("{lat},{lon}")));
    if let Some(position) = position {
        finding = finding.attr("coordinates", &position).pivot(
            PivotKind::Coordinates,
            position,
            "Position IPQualityScore gives for the address",
        );
    }
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
    finding
}

/// `value` unless IPQS wrote `N/A`, its word for a field it has no value for.
fn known(value: Option<&str>) -> Option<&str> {
    value.filter(|v| !v.trim().eq_ignore_ascii_case("n/a"))
}

fn associated(list: Option<&Associated>) -> Vec<String> {
    list.map(|a| {
        a.names
            .iter()
            .filter_map(|n| api_leg::clean(Some(n)))
            .take(MAX_ASSOCIATED)
            .collect()
    })
    .unwrap_or_default()
}

fn email(body: &EmailBody, score: u8) -> Finding {
    let set = flags(&[
        (!body.valid, "invalid"),
        (body.disposable, "disposable"),
        (body.honeypot, "honeypot"),
        (body.leaked, "leaked"),
        (body.recent_abuse, "recent_abuse"),
        (body.suspect, "suspect"),
        (body.catch_all, "catch_all"),
        (body.frequent_complainer, "frequent_complainer"),
    ]);
    Finding::new(summary("email", score, &set))
        .list_attr("flags", &set)
        .attr("valid", body.valid.to_string())
        .opt_attr("deliverability", body.deliverability.as_deref())
        .opt_attr("smtp_score", body.smtp_score.map(|s| s.to_string()))
        .opt_attr(
            "first_seen",
            body.first_seen.as_ref().and_then(|s| s.iso.as_deref()),
        )
        .opt_attr(
            "domain_created",
            body.domain_age.as_ref().and_then(|s| s.iso.as_deref()),
        )
        .list_attr(
            "associated_names",
            &associated(body.associated_names.as_ref()),
        )
        .list_attr(
            "associated_numbers",
            &associated(body.associated_phone_numbers.as_ref()),
        )
        .tag_if(body.leaked, tags::PASSWORD_AT_RISK)
        .tag_if(body.disposable, "disposable")
}

fn phone(body: &PhoneBody, score: u8) -> Finding {
    let set = flags(&[
        (!body.valid, "invalid"),
        (body.active == Some(false), "inactive"),
        (body.voip, "voip"),
        (body.prepaid == Some(true), "prepaid"),
        (body.risky, "risky"),
        (body.leaked, "leaked"),
        (body.spammer, "spammer"),
        (body.recent_abuse, "recent_abuse"),
    ]);
    let mut finding = Finding::new(summary("phone", score, &set))
        .list_attr("flags", &set)
        .attr("valid", body.valid.to_string())
        .opt_attr("carrier", body.carrier.as_deref())
        .opt_attr("line_type", body.line_type.as_deref())
        .opt_attr("country", body.country.as_deref())
        .opt_attr("region", body.region.as_deref())
        .tag_if(body.voip, "voip");
    if let Some(carrier) = body.carrier.as_deref() {
        finding = finding.pivot(
            PivotKind::Organisation,
            carrier,
            "Carrier IPQualityScore gives for the number",
        );
    }
    finding
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The documented proxy-detection response shape (IPQS documentation), filled for a VPN exit.
    const IP: &str = r#"{"success":true,"message":"Success","fraud_score":88,"country_code":"NL","region":"North Holland","city":"Amsterdam","ISP":"Example Hosting","ASN":64500,"organization":"Example Hosting B.V.","is_crawler":false,"timezone":"Europe/Amsterdam","mobile":false,"host":"vpn-exit-7.example.net","proxy":true,"vpn":true,"tor":false,"active_vpn":true,"active_tor":false,"recent_abuse":true,"bot_status":false,"connection_type":"Data Center","abuse_velocity":"high","zip_code":"N/A","latitude":52.37,"longitude":4.89,"request_id":"abc123"}"#;
    /// The documented email-validation response fields, filled for a leaked address.
    const EMAIL: &str = r#"{"valid":true,"timed_out":false,"disposable":false,"first_name":"Ada","deliverability":"high","smtp_score":3,"overall_score":4,"catch_all":false,"generic":false,"common":true,"dns_valid":true,"honeypot":false,"frequent_complainer":false,"suspect":false,"recent_abuse":false,"fraud_score":40,"leaked":true,"suggested_domain":"N/A","domain_velocity":"low","domain_trust":"trusted","user_activity":"high","associated_names":{"status":"Enterprise Plus or higher required.","names":[]},"associated_phone_numbers":{"status":"Enterprise Plus or higher required.","phone_numbers":[]},"first_seen":{"human":"3 years ago","timestamp":1600000000,"iso":"2020-09-13T12:26:40-04:00"},"domain_age":{"human":"20 years ago","timestamp":1000000000,"iso":"2001-09-08T21:46:40-04:00"},"success":true,"spam_trap_score":"none","risky_tld":false,"spf_record":true,"dmarc_record":true,"sanitized_email":"ada@example.com","result_type":"valid","mx_records":["mx.example.com"],"request_id":"r1","a_records":["93.184.216.34"]}"#;
    /// The phone-validation response fields, filled for a prepaid VOIP number.
    const PHONE: &str = r#"{"message":"Phone is valid.","success":true,"formatted":"+61412345678","local_format":"0412 345 678","valid":true,"fraud_score":90,"recent_abuse":true,"VOIP":true,"prepaid":true,"risky":true,"active":true,"carrier":"Example Mobile","line_type":"VOIP","country":"AU","region":"NSW","city":"Sydney","leaked":false,"spammer":false,"request_id":"r2"}"#;
    /// Recorded with an invalid key on 2026-10-14 (HTTP 200).
    const INVALID_KEY: &str = r#"{"success":false,"message":"Invalid or unauthorized key. Please check the API key and try again.","request_id":"lbwl7AvoAc","api_version":2}"#;

    #[test]
    fn the_documented_ip_answer_keeps_score_flags_and_pivots() {
        let f = decode(IP.as_bytes(), Indicator::Ip("1.2.3.4")).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            f.summary,
            "IPQualityScore IP: fraud score 88, proxy, vpn, recent_abuse, active_vpn"
        );
        assert_eq!(f.tags, ["vpn", "proxy", tags::MALICIOUS]);
        assert!(f.attrs.contains(&("asn", "AS64500".into())));
        assert!(f.pivots.iter().any(|p| p.value == "vpn-exit-7.example.net"));
    }

    #[test]
    fn the_documented_ip_answer_keeps_where_the_address_is() {
        let f = decode(IP.as_bytes(), Indicator::Ip("1.2.3.4")).unwrap_or_else(|e| panic!("{e}"));
        assert!(f.attrs.contains(&("region", "North Holland".into())));
        assert!(f.attrs.contains(&("timezone", "Europe/Amsterdam".into())));
        assert!(
            f.attrs
                .contains(&("coordinates", "52.370000,4.890000".into()))
        );
        assert!(
            f.attrs.iter().all(|(k, _)| *k != "postal_code"),
            "IPQS's N/A is no postcode"
        );
        assert!(
            f.pivots
                .iter()
                .any(|p| p.kind == PivotKind::Coordinates && p.value == "52.370000,4.890000")
        );
    }

    #[test]
    fn an_email_answer_keeps_leak_and_first_seen() {
        let f = decode(EMAIL.as_bytes(), Indicator::Email("ada@example.com"))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(f.summary, "IPQualityScore email: fraud score 40, leaked");
        assert!(
            f.attrs
                .contains(&("first_seen", "2020-09-13T12:26:40-04:00".into()))
        );
        assert!(f.attrs.contains(&("deliverability", "high".into())));
        assert_eq!(f.tags, [tags::PASSWORD_AT_RISK]);
    }

    #[test]
    fn a_phone_answer_keeps_line_type_and_carrier() {
        let f = decode(PHONE.as_bytes(), Indicator::Phone("+61412345678"))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(f.summary.contains("voip, prepaid, risky"));
        assert!(f.attrs.contains(&("line_type", "VOIP".into())));
        assert!(f.tags.contains(&tags::MALICIOUS));
        assert!(f.pivots.iter().any(|p| p.kind == PivotKind::Organisation));
    }

    #[test]
    fn success_false_is_a_refusal_never_a_zero() {
        assert_eq!(
            decode(INVALID_KEY.as_bytes(), Indicator::Ip("1.2.3.4")),
            Err(LegError::Unauthorized)
        );
        let spent = r#"{"success":false,"message":"You have insufficient credits to make this query.","request_id":"x"}"#;
        assert_eq!(
            decode(spent.as_bytes(), Indicator::Email("a@b.example")),
            Err(LegError::Forbidden)
        );
    }

    #[test]
    fn the_url_carries_the_value_and_no_key() {
        assert_eq!(
            url(Indicator::Ip("1.1.1.1")),
            Some("https://www.ipqualityscore.com/api/json/ip?ip=1.1.1.1".into())
        );
        assert_eq!(
            url(Indicator::Phone("+61412345678")),
            Some("https://www.ipqualityscore.com/api/json/phone?phone=%2B61412345678".into())
        );
        assert_eq!(url(Indicator::Domain("example.com")), None);
    }
}
