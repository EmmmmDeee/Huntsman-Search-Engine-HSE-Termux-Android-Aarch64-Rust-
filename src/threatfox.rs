//! abuse.ch `ThreatFox`: indicators of compromise that name one IP or domain.
//!
//! One lookup is one `POST https://threatfox-api.abuse.ch/api/v1/` with
//! `{"query":"search_ioc","search_term":…}` and the abuse.ch key in the `Auth-Key` header, run
//! whenever `HUNTSMAN_THREATFOX_KEY` is set (free with an abuse.ch account). `ThreatFox` stores an
//! address as `ip:port`, so the search is its wildcard search and only IOCs that are exactly the
//! indicator, the indicator with a port, or a URL on the domain are kept. `no_result` is a valid
//! zero; an unknown key is refused by HTTP status before the body is read.
//!
//! Everything about the matching IOCs is kept: each IOC whole as JSON in `raw_iocs`, and, across
//! them, every IOC value, malware name, Malpedia id, alias and link, threat and IOC type, tag,
//! reference, reporter and sample SHA-256, the highest confidence, and the first and last sighting.

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
    #[serde(default, rename = "ioc_type")]
    kind: Option<String>,
    #[serde(default)]
    malware: Option<String>,
    #[serde(default)]
    malware_printable: Option<String>,
    #[serde(default)]
    malware_alias: Option<String>,
    #[serde(default)]
    malware_malpedia: Option<String>,
    #[serde(default)]
    reference: Option<String>,
    #[serde(default)]
    reporter: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    malware_samples: Option<Vec<Sample>>,
    #[serde(default)]
    confidence_level: Option<u8>,
    #[serde(default)]
    first_seen: Option<String>,
    #[serde(default)]
    last_seen: Option<String>,
}

#[derive(Deserialize)]
struct Sample {
    #[serde(default)]
    sha256_hash: Option<String>,
}

/// Add `value` to `list` unless it is blank or already there. **Pure.**
fn push_distinct(list: &mut Vec<String>, value: Option<&str>) {
    if let Some(value) = api_leg::clean(value) {
        if !list.contains(&value) {
            list.push(value);
        }
    }
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
    let records: Vec<serde_json::Value> = serde_json::from_value(body.data)
        .map_err(|_| LegError::Decode("data is not a list of IOCs".into()))?;
    let mut matching: Vec<(Ioc, serde_json::Value)> = Vec::new();
    for record in records {
        let ioc: Ioc = serde_json::from_value(record.clone())
            .map_err(|_| LegError::Decode("data is not a list of IOCs".into()))?;
        if names(&ioc.value, indicator) {
            matching.push((ioc, record));
        }
    }
    if matching.is_empty() {
        return Ok(None);
    }
    Ok(Some(finding(&matching)))
}

/// Everything the matching IOCs say, across them all, and each one whole. **Pure.**
fn finding(matching: &[(Ioc, serde_json::Value)]) -> Finding {
    let mut iocs: Vec<String> = Vec::new();
    let mut malware: Vec<String> = Vec::new();
    let mut malware_ids: Vec<String> = Vec::new();
    let mut aliases: Vec<String> = Vec::new();
    let mut malpedia: Vec<String> = Vec::new();
    let mut threats: Vec<String> = Vec::new();
    let mut ioc_types: Vec<String> = Vec::new();
    let mut ioc_tags: Vec<String> = Vec::new();
    let mut references: Vec<String> = Vec::new();
    let mut reporters: Vec<String> = Vec::new();
    let mut samples: Vec<String> = Vec::new();
    for (ioc, _) in matching {
        push_distinct(&mut iocs, Some(&ioc.value));
        push_distinct(&mut malware, ioc.malware_printable.as_deref());
        push_distinct(&mut malware_ids, ioc.malware.as_deref());
        push_distinct(&mut aliases, ioc.malware_alias.as_deref());
        push_distinct(&mut malpedia, ioc.malware_malpedia.as_deref());
        push_distinct(&mut threats, ioc.threat_type.as_deref());
        push_distinct(&mut ioc_types, ioc.kind.as_deref());
        for tag in ioc.tags.iter().flatten() {
            push_distinct(&mut ioc_tags, Some(tag));
        }
        push_distinct(&mut references, ioc.reference.as_deref());
        push_distinct(&mut reporters, ioc.reporter.as_deref());
        for sample in ioc.malware_samples.iter().flatten() {
            push_distinct(&mut samples, sample.sha256_hash.as_deref());
        }
    }
    let confidence = matching
        .iter()
        .filter_map(|(i, _)| i.confidence_level)
        .max();
    let first = matching
        .iter()
        .filter_map(|(i, _)| i.first_seen.as_deref())
        .min();
    let last = matching
        .iter()
        .filter_map(|(i, _)| i.last_seen.as_deref().or(i.first_seen.as_deref()))
        .max();
    let raw = serde_json::Value::Array(matching.iter().map(|(_, r)| r.clone()).collect());
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
    .list_attr("malware_ids", &malware_ids)
    .list_attr("malware_aliases", &aliases)
    .list_attr("malpedia", &malpedia)
    .list_attr("threat_types", &threats)
    .list_attr("ioc_types", &ioc_types)
    .list_attr("iocs", &iocs)
    .list_attr("ioc_tags", &ioc_tags)
    .list_attr("references", &references)
    .list_attr("reporters", &reporters)
    .list_attr("sample_sha256", &samples)
    .opt_attr("max_confidence", confidence.map(|c| c.to_string()))
    .opt_attr("first_seen", first)
    .opt_attr("last_seen", last)
    .attr("raw_iocs", raw.to_string())
    .tag(tags::MALICIOUS)
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
    fn a_matching_ioc_keeps_every_field_the_answer_gives() {
        let f = decode(DOCUMENTED.as_bytes(), Indicator::Ip("94.103.84.81"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("documented body must decode"));
        let attr = |key: &str| {
            f.attrs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(attr("iocs"), Some("94.103.84.81:8080"));
        assert_eq!(attr("malware_ids"), Some("win.dridex"));
        assert_eq!(
            attr("malpedia"),
            Some("https://malpedia.caad.fkie.fraunhofer.de/details/win.dridex")
        );
        assert_eq!(attr("ioc_types"), Some("ip:port"));
        assert_eq!(attr("ioc_tags"), Some("dridex"));
        assert_eq!(attr("reporters"), Some("abuse_ch"));
        assert_eq!(attr("first_seen"), Some("2021-03-08 12:28:13 UTC"));
        let raw = attr("raw_iocs").unwrap_or_else(|| panic!("no raw_iocs: {:?}", f.attrs));
        assert!(raw.starts_with(r#"[{"confidence_level":50,"#), "{raw}");
        assert!(raw.contains(r#""threat_type_desc":"Indicator that identifies a botnet command&control server (C&C)""#));
        assert!(
            !raw.contains("94.103.84.812"),
            "the near-miss is not this address: {raw}"
        );
    }

    #[test]
    fn every_matching_ioc_is_kept() {
        let records: Vec<String> = (0..12)
            .map(|n| {
                format!(
                    r#"{{"ioc":"94.103.84.81:{}","threat_type":"botnet_cc","malware_printable":"Family {n}","tags":null,"malware_samples":[{{"sha256_hash":"{n:064x}"}}]}}"#,
                    8000 + n
                )
            })
            .collect();
        let body = format!(r#"{{"query_status":"ok","data":[{}]}}"#, records.join(","));
        let f = decode(body.as_bytes(), Indicator::Ip("94.103.84.81"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("body must decode"));
        let list = |key: &str| {
            f.attrs
                .iter()
                .find(|(k, _)| *k == key)
                .map_or(0, |(_, v)| v.split(',').count())
        };
        assert_eq!(list("iocs"), 12);
        assert_eq!(list("malware"), 12);
        assert_eq!(list("sample_sha256"), 12);
        assert_eq!(list("ioc_tags"), 0, "a null tag list is no tags");
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
