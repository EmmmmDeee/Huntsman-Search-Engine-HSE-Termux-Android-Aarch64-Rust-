//! abuse.ch `ThreatFox`: indicators of compromise that name one IP or domain.
//!
//! One lookup is one `POST https://threatfox-api.abuse.ch/api/v1/` with
//! `{"query":"search_ioc","search_term":…}` and the abuse.ch key in the `Auth-Key` header, run
//! whenever `HUNTSMAN_THREATFOX_KEY` is set (free with an abuse.ch account). `ThreatFox` stores an
//! address as `ip:port`, so the search is its wildcard search and only IOCs that are exactly the
//! indicator, the indicator with a port, or a URL on the domain are kept. `no_result` is a valid
//! zero; an unknown key is refused by HTTP status before the body is read.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::circuit::host_of;
use crate::http::Transport;
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, Source};
use crate::keys::Keys;
use crate::tags;

pub const SOURCE: &str = "threatfox";
pub const KEY_SLOT: &str = crate::environment::THREATFOX_KEY_ENV;
pub const URL: &str = "https://threatfox-api.abuse.ch/api/v1/";
pub const API: Api = Api {
    source: SOURCE,
    provider: "abuse.ch",
    origin: "https://threatfox-api.abuse.ch:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Header("Auth-Key"),
        required: true,
    }),
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Ip, IndicatorKind::Domain],
    lookup,
};
/// Most malware family names kept in one attribute.
const MAX_NAMES: usize = 10;

#[derive(Deserialize)]
struct Body {
    query_status: String,
    #[serde(default)]
    data: serde_json::Value,
}

#[derive(Deserialize)]
struct Ioc {
    #[serde(rename = "ioc")]
    value: String,
    #[serde(default)]
    threat_type: Option<String>,
    #[serde(default)]
    malware_printable: Option<String>,
    #[serde(default)]
    confidence_level: Option<u8>,
    #[serde(default)]
    first_seen: Option<String>,
    #[serde(default)]
    last_seen: Option<String>,
}

/// The request body for `indicator`. **Pure.**
#[must_use]
pub fn body(indicator: Indicator<'_>) -> serde_json::Value {
    serde_json::json!({"query": "search_ioc", "search_term": indicator.value(), "exact_match": false})
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
    match api_leg::post_json(transport, &API, keys, URL, &body(indicator), now_unix)? {
        Answer::Body(body) => decode(&body, indicator),
        Answer::NotFound(_) => Err(LegError::Unexpected(404)),
    }
}

/// Whether the IOC `ioc` names `indicator` itself. **Pure.**
fn names(ioc: &str, indicator: Indicator<'_>) -> bool {
    let value = indicator.value();
    if ioc.eq_ignore_ascii_case(value) {
        return true;
    }
    match indicator {
        Indicator::Ip(ip) => {
            ioc.strip_prefix(ip).is_some_and(|rest| {
                rest.strip_prefix(':')
                    .is_some_and(|p| p.bytes().all(|b| b.is_ascii_digit()))
            }) || ioc
                .strip_prefix('[')
                .and_then(|r| r.strip_prefix(ip))
                .is_some_and(|rest| rest.starts_with("]:"))
        }
        Indicator::Cell(_)
        | Indicator::MacAddress(_)
        | Indicator::Email(_)
        | Indicator::Phone(_) => false,
        Indicator::Domain(domain) => {
            ioc.contains("://") && host_of(ioc).is_some_and(|h| h.eq_ignore_ascii_case(domain))
        }
    }
}

/// One answer body for `indicator`. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for another shape or a `query_status` other than `ok` or `no_result`.
pub fn decode(body: &[u8], indicator: Indicator<'_>) -> Result<Option<Finding>, LegError> {
    let body: Body = api_leg::decode(body)?;
    match body.query_status.as_str() {
        "ok" => {}
        "no_result" => return Ok(None),
        other => {
            return Err(LegError::Decode(format!(
                "query_status {}",
                api_leg::clean(Some(other)).unwrap_or_default()
            )));
        }
    }
    let iocs: Vec<Ioc> = serde_json::from_value(body.data)
        .map_err(|_| LegError::Decode("data is not a list of IOCs".into()))?;
    let matching: Vec<&Ioc> = iocs.iter().filter(|i| names(&i.value, indicator)).collect();
    if matching.is_empty() {
        return Ok(None);
    }
    let mut malware: Vec<String> = Vec::new();
    let mut threats: Vec<String> = Vec::new();
    for ioc in &matching {
        for (list, value) in [
            (&mut malware, &ioc.malware_printable),
            (&mut threats, &ioc.threat_type),
        ] {
            if let Some(v) = api_leg::clean(value.as_deref()) {
                if !list.contains(&v) && list.len() < MAX_NAMES {
                    list.push(v);
                }
            }
        }
    }
    let confidence = matching.iter().filter_map(|i| i.confidence_level).max();
    let first = matching
        .iter()
        .filter_map(|i| i.first_seen.as_deref())
        .min();
    let last = matching
        .iter()
        .filter_map(|i| i.last_seen.as_deref().or(i.first_seen.as_deref()))
        .max();
    let iocs: Vec<&str> = matching
        .iter()
        .map(|i| i.value.as_str())
        .take(MAX_NAMES)
        .collect();
    Ok(Some(
        Finding::new(format!(
            "ThreatFox: {} IOC(s){}",
            matching.len(),
            if malware.is_empty() {
                String::new()
            } else {
                format!(", {}", malware.join(", "))
            }
        ))
        .list_attr("malware", &malware)
        .list_attr("threat_types", &threats)
        .list_attr("iocs", &iocs)
        .opt_attr("max_confidence", confidence.map(|c| c.to_string()))
        .opt_attr("first_seen", first)
        .opt_attr("last_seen", last)
        .tag(tags::MALICIOUS),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The documented `search_ioc` answer shape, with the near-miss a wildcard search returns.
    const DOCUMENTED: &str = r#"{"query_status":"ok","data":[{"id":"12","ioc":"94.103.84.81:8080","threat_type":"botnet_cc","threat_type_desc":"Indicator that identifies a botnet command&control server (C&C)","ioc_type":"ip:port","ioc_type_desc":"ip:port combination that is used for botnet Command&control (C&C)","malware":"win.dridex","malware_printable":"Dridex","malware_alias":null,"malware_malpedia":"https://malpedia.caad.fkie.fraunhofer.de/details/win.dridex","confidence_level":50,"first_seen":"2021-03-08 12:28:13 UTC","last_seen":null,"reference":"","reporter":"abuse_ch","tags":["dridex"],"malware_samples":[]},{"id":"13","ioc":"94.103.84.812:443","threat_type":"botnet_cc","malware_printable":"Other","confidence_level":75,"first_seen":"2021-03-09 00:00:00 UTC"}]}"#;

    #[test]
    fn only_iocs_that_are_the_address_are_kept() {
        let f = decode(DOCUMENTED.as_bytes(), Indicator::Ip("94.103.84.81"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("documented body must decode"));
        assert_eq!(f.summary, "ThreatFox: 1 IOC(s), Dridex");
        assert!(f.attrs.contains(&("max_confidence", "50".into())));
        assert_eq!(f.tags, [tags::MALICIOUS]);
    }

    #[test]
    fn a_url_ioc_names_its_domain() {
        assert!(names(
            "https://bad.example/x.exe",
            Indicator::Domain("bad.example")
        ));
        assert!(!names(
            "https://notbad.example/",
            Indicator::Domain("bad.example")
        ));
        assert!(names("bad.example", Indicator::Domain("bad.example")));
        assert!(!names("1.2.3.45:80", Indicator::Ip("1.2.3.4")));
    }

    #[test]
    fn no_result_is_a_zero_and_other_statuses_are_errors() {
        let none = r#"{"query_status":"no_result","data":"Your search did not yield any results"}"#;
        assert_eq!(decode(none.as_bytes(), Indicator::Ip("1.1.1.1")), Ok(None));
        let bad = r#"{"query_status":"illegal_search_term","data":null}"#;
        assert!(decode(bad.as_bytes(), Indicator::Ip("1.1.1.1")).is_err());
        assert_eq!(
            decode(DOCUMENTED.as_bytes(), Indicator::Ip("10.9.8.7")),
            Ok(None)
        );
    }
}
