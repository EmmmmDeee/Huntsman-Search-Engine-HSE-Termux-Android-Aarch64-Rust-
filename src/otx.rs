//! `AlienVault` OTX: the community threat pulses that name one IP or domain.
//!
//! One lookup is one `GET https://otx.alienvault.com/api/v1/indicators/{IPv4|IPv6|domain}/{value}/general`.
//! OTX answers without a key; with `HUNTSMAN_OTX_KEY` set the key goes in the `X-OTX-API-KEY`
//! header and the account's limit applies. Kept: how many pulses name the indicator, their names
//! and tags, the malware families and adversaries they attribute, the industries they target,
//! OTX's own validations (allow-listed, Tor exit and the like), and for an address its AS and
//! country. No pulse and no validation is a valid zero.

use serde::Deserialize;
use serde_json::Value;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::http::{Transport, percent_encode_component};
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, PivotKind, Source};
use crate::keys::Keys;
use crate::tags;

pub const SOURCE: &str = "otx";
pub const KEY_SLOT: &str = crate::environment::OTX_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "otx.alienvault.com",
    origin: "https://otx.alienvault.com:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Header("X-OTX-API-KEY"),
        required: false,
    }),
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Ip, IndicatorKind::Domain],
    lookup,
};
/// Most pulse, tag and family names kept in one attribute.
const MAX_NAMES: usize = 10;

#[derive(Deserialize)]
struct Body {
    indicator: String,
    #[serde(default)]
    asn: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    pulse_info: Option<PulseInfo>,
    #[serde(default)]
    validation: Vec<Validation>,
}

#[derive(Deserialize, Default)]
struct PulseInfo {
    #[serde(default)]
    count: u64,
    #[serde(default)]
    pulses: Vec<Pulse>,
    #[serde(default)]
    related: Option<Related>,
}

#[derive(Deserialize)]
struct Pulse {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    malware_families: Vec<Value>,
    #[serde(default)]
    adversary: Option<String>,
    #[serde(default)]
    modified: Option<String>,
}

#[derive(Deserialize, Default)]
struct Related {
    #[serde(default)]
    alienvault: Option<Group>,
    #[serde(default)]
    other: Option<Group>,
}

#[derive(Deserialize, Default)]
struct Group {
    #[serde(default)]
    adversary: Vec<String>,
    #[serde(default)]
    malware_families: Vec<String>,
    #[serde(default)]
    industries: Vec<String>,
}

#[derive(Deserialize)]
struct Validation {
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

/// The request URL for `indicator`, or `None` for a kind OTX is not asked about. **Pure.**
#[must_use]
pub fn url(indicator: Indicator<'_>) -> Option<String> {
    let section = match indicator {
        Indicator::Ip(ip) if ip.contains(':') => "IPv6",
        Indicator::Ip(_) => "IPv4",
        Indicator::Domain(_) => "domain",
        Indicator::Email(_)
        | Indicator::Phone(_)
        | Indicator::Cell(_)
        | Indicator::MacAddress(_) => return None,
    };
    Some(format!(
        "https://otx.alienvault.com/api/v1/indicators/{section}/{}/general",
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
        Answer::Body(body) => decode(&body, indicator),
        Answer::NotFound(_) => Ok(None),
    }
}

/// Distinct cleaned names, at most [`MAX_NAMES`].
fn distinct<'a>(values: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for value in values.filter_map(|v| api_leg::clean(Some(v))) {
        if !out.contains(&value) && out.len() < MAX_NAMES {
            out.push(value);
        }
    }
    out
}

/// A malware family as OTX lists it on a pulse: a name, or an object with a `display_name`.
fn family_name(value: &Value) -> Option<&str> {
    match value {
        Value::String(s) => Some(s),
        Value::Object(o) => o.get("display_name").and_then(Value::as_str),
        _ => None,
    }
}

/// One answer body for `indicator`. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented shape or names another indicator.
pub fn decode(body: &[u8], indicator: Indicator<'_>) -> Result<Option<Finding>, LegError> {
    let body: Body = api_leg::decode(body)?;
    if !body.indicator.eq_ignore_ascii_case(indicator.value()) {
        return Err(LegError::Decode("answer names another indicator".into()));
    }
    let info = body.pulse_info.unwrap_or_default();
    if info.count == 0 && body.validation.is_empty() {
        return Ok(None);
    }
    let related = info.related.unwrap_or_default();
    let groups: Vec<Group> = [related.alienvault, related.other]
        .into_iter()
        .flatten()
        .collect();
    let families = distinct(
        info.pulses
            .iter()
            .flat_map(|p| p.malware_families.iter().filter_map(family_name))
            .chain(
                groups
                    .iter()
                    .flat_map(|g| g.malware_families.iter().map(String::as_str)),
            ),
    );
    let adversaries = distinct(
        info.pulses
            .iter()
            .filter_map(|p| p.adversary.as_deref())
            .chain(
                groups
                    .iter()
                    .flat_map(|g| g.adversary.iter().map(String::as_str)),
            ),
    );
    let industries = distinct(
        groups
            .iter()
            .flat_map(|g| g.industries.iter().map(String::as_str)),
    );
    let pulses = distinct(info.pulses.iter().filter_map(|p| p.name.as_deref()));
    let pulse_tags = distinct(
        info.pulses
            .iter()
            .flat_map(|p| p.tags.iter().map(String::as_str)),
    );
    let validations = distinct(
        body.validation
            .iter()
            .filter_map(|v| v.name.as_deref().or(v.source.as_deref())),
    );
    let allowlisted = body.validation.iter().any(|v| {
        v.name
            .as_deref()
            .is_some_and(|n| n.to_ascii_lowercase().contains("whitelist"))
    });
    let last = info
        .pulses
        .iter()
        .filter_map(|p| p.modified.as_deref())
        .max();
    let mut finding = Finding::new(format!("OTX: named in {} pulse(s)", info.count))
        .attr("pulse_count", info.count.to_string())
        .list_attr("pulses", &pulses)
        .list_attr("pulse_tags", &pulse_tags)
        .list_attr("malware_families", &families)
        .list_attr("adversaries", &adversaries)
        .list_attr("targeted_industries", &industries)
        .list_attr("validations", &validations)
        .opt_attr("last_pulse", last)
        .opt_attr("country", body.country_code.as_deref())
        .tag_if(
            !families.is_empty() || !adversaries.is_empty(),
            tags::MALICIOUS,
        )
        .tag_if(info.count > 0, "threat-reported")
        .tag_if(allowlisted, "allowlisted");
    if let Some((asn, org)) = body.asn.as_deref().and_then(|a| a.split_once(' ')) {
        finding = finding
            .pivot(PivotKind::Asn, asn, "Origin AS OTX gives for the address")
            .pivot(
                PivotKind::Organisation,
                org,
                "AS holder OTX gives for the address",
            );
    }
    Ok(Some(finding))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded without a key for a Tor exit on 2026-10-14 (pulses trimmed to two).
    const TOR_EXIT: &str = r#"{"whois":"http://whois.domaintools.com/185.220.101.1","reputation":0,"indicator":"185.220.101.1","type":"IPv4","type_title":"IPv4","asn":"AS208294 cia triad security llc","country_code":"DE","pulse_info":{"count":50,"pulses":[{"id":"5a7e3e70c44e7b48947593a7","name":"Webscanners 2018-02-09  thru current day","tags":["webscanner, bruteforce, web app attack","probing","webscan","scanning"],"malware_families":[],"adversary":"","created":"2018-02-10T00:36:00.396000","modified":"2026-10-14T15:06:19.514000","TLP":"white"},{"id":"6acf984af42a81561422a1af","name":"Anonymization_Network | Oct 15, 2026 | Part 1/4","tags":["anonymization_network"],"malware_families":[{"id":"Mirai","display_name":"Mirai","target":null}],"adversary":"","created":"2026-10-14T14:57:14.536000","modified":"2026-10-14T14:57:14.536000","TLP":"white"}],"references":[],"related":{"alienvault":{"adversary":[],"malware_families":[],"industries":[]},"other":{"adversary":[],"malware_families":[],"industries":["Finance","Defense"]}}},"validation":[{"source":"tor_exits","message":"IP Associated with Tor Exit Nodes","name":"IP Assosciated with Tor Exit Nodes"}]}"#;
    /// Recorded without a key for `example.com` on 2026-10-14 (trimmed).
    const ALLOWLISTED: &str = r#"{"sections":["general"],"indicator":"example.com","type":"domain","validation":[{"source":"majestic","message":"Whitelisted domain example.com","name":"Whitelisted domain"}],"pulse_info":{"count":0,"pulses":[],"references":[],"related":{"alienvault":{"adversary":[],"malware_families":[],"industries":[]},"other":{"adversary":[],"malware_families":[],"industries":[]}}}}"#;

    #[test]
    fn a_recorded_answer_keeps_pulses_families_and_the_as() {
        let f = decode(TOR_EXIT.as_bytes(), Indicator::Ip("185.220.101.1"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        assert_eq!(f.summary, "OTX: named in 50 pulse(s)");
        assert!(f.attrs.contains(&("malware_families", "Mirai".into())));
        assert!(
            f.attrs
                .contains(&("targeted_industries", "Finance,Defense".into()))
        );
        assert!(f.tags.contains(&tags::MALICIOUS));
        assert!(
            f.pivots
                .iter()
                .any(|p| p.kind == PivotKind::Asn && p.value == "AS208294")
        );
    }

    #[test]
    fn an_allowlisted_domain_is_reported_and_an_unknown_one_is_a_zero() {
        let f = decode(ALLOWLISTED.as_bytes(), Indicator::Domain("example.com"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        assert_eq!(f.tags, ["allowlisted"]);
        let empty =
            r#"{"indicator":"zz.example","pulse_info":{"count":0,"pulses":[]},"validation":[]}"#;
        assert_eq!(
            decode(empty.as_bytes(), Indicator::Domain("zz.example")),
            Ok(None)
        );
        assert!(decode(ALLOWLISTED.as_bytes(), Indicator::Domain("other.example")).is_err());
    }

    #[test]
    fn the_url_names_the_section_for_each_kind() {
        assert_eq!(
            url(Indicator::Ip("2001:db8::1")).as_deref(),
            Some("https://otx.alienvault.com/api/v1/indicators/IPv6/2001%3Adb8%3A%3A1/general")
        );
        assert_eq!(url(Indicator::Email("a@b.example")), None);
    }
}
