//! Maltiverse: the threat-intelligence record of one IP address or host name.
//!
//! One lookup is one keyless `GET https://api.maltiverse.com/ip/{ip}` or `/hostname/{name}`,
//! Spiderfoot's `sfp_maltiverse`. Kept whole: Maltiverse's classification, every blacklist entry
//! (its source, description, labels, sighting count and first and last sightings), every flag it
//! sets (known attacker, C&C, Tor or VPN node, open proxy, phishing, sinkhole), its tags, the AS,
//! registrant, place and coordinates, the counts of domains and malicious URLs tied to it and, for
//! a host name, every address it has resolved to. A `malicious` classification is malicious, as
//! `sfp_maltiverse` reports it, and `suspicious` is marked so. A `404` is a valid zero.
//!
//! Maltiverse records a host name the first time anyone asks about it, as it does for Spiderfoot.

use serde_json::{Map, Value};

use crate::api_leg::{self, Answer, Api, LegError};
use crate::http::{Transport, percent_encode_component};
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, PivotKind, Source};
use crate::keys::Keys;
use crate::tags;

pub const SOURCE: &str = "maltiverse";
pub const API: Api = Api {
    source: SOURCE,
    provider: "maltiverse.com",
    origin: "https://api.maltiverse.com:443",
    key: None,
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Ip, IndicatorKind::Domain],
    lookup,
};
/// The flags Maltiverse sets, by the name each is kept under when true.
const FLAGS: [(&str, &str); 13] = [
    ("is_known_attacker", "known attacker"),
    ("is_known_scanner", "known scanner"),
    ("is_cnc", "command and control"),
    ("is_distributing_malware", "distributing malware"),
    ("is_phishing", "phishing"),
    ("is_storing_phishing", "storing phishing"),
    ("is_iot_threat", "IoT threat"),
    ("is_mining_pool", "mining pool"),
    ("is_open_proxy", "open proxy"),
    ("is_tor_node", "Tor node"),
    ("is_vpn_node", "VPN node"),
    ("is_sinkhole", "sinkhole"),
    ("is_cdn", "CDN"),
];
/// The scalar fields kept as they are, by the attribute each is kept under.
const FIELDS: [(&str, &str); 19] = [
    ("as_name", "as_name"),
    ("registrant_name", "registrant"),
    ("address", "address"),
    ("city", "city"),
    ("postal_code", "postal_code"),
    ("country_code", "country"),
    ("creation_time", "first_recorded"),
    ("modification_time", "last_modified"),
    ("scoring_executed_time", "scored"),
    ("last_online_time", "last_online"),
    ("is_alive", "alive"),
    ("is_hosting", "hosting"),
    ("number_of_domains_resolving", "domains_resolving"),
    (
        "number_of_blacklisted_domains_resolving",
        "blacklisted_domains_resolving",
    ),
    (
        "number_of_whitelisted_domains_resolving",
        "whitelisted_domains_resolving",
    ),
    (
        "number_of_online_malicious_urls_allocated",
        "online_malicious_urls",
    ),
    (
        "number_of_offline_malicious_urls_allocated",
        "offline_malicious_urls",
    ),
    ("entropy", "entropy"),
    ("tld", "tld"),
];

/// The request URL for `indicator`, or `None` when it is not an IP address or host name. **Pure.**
#[must_use]
pub fn url(indicator: Indicator<'_>) -> Option<String> {
    let (path, value) = match indicator {
        Indicator::Ip(ip) => ("ip", ip),
        Indicator::Domain(name) => ("hostname", name),
        _ => return None,
    };
    Some(format!(
        "https://api.maltiverse.com/{path}/{}",
        percent_encode_component(value)
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

/// A scalar as text: a string, number or flag as written, anything else `None`. **Pure.**
fn text(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(text) => api_leg::clean(Some(text)),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

/// The strings of a list field. **Pure.**
fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(|item| text(Some(item))).collect())
        .unwrap_or_default()
}

/// One blacklist entry as `source: description (labels; N sightings; first..last; refs)`.
/// **Pure.**
fn listing(entry: &Value) -> Option<String> {
    let source = text(entry.get("source"))?;
    let mut out = source;
    if let Some(description) = text(entry.get("description")) {
        out = format!("{out}: {description}");
    }
    let mut detail = strings(entry.get("labels"));
    if let Some(count) = text(entry.get("count")) {
        detail.push(format!("{count} sightings"));
    }
    let (first, last) = (text(entry.get("first_seen")), text(entry.get("last_seen")));
    if first.is_some() || last.is_some() {
        detail.push(format!(
            "{}..{}",
            first.unwrap_or_default(),
            last.unwrap_or_default()
        ));
    }
    for reference in entry
        .get("ref")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(id) = text(Some(reference)) {
            detail.push(format!("ref {id}"));
        }
    }
    for reference in entry
        .get("external_references")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(id) = text(reference.get("external_id")) {
            detail.push(id);
        }
    }
    if !detail.is_empty() {
        out = format!("{out} ({})", detail.join("; "));
    }
    Some(out)
}

/// One answer body for `indicator`. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not a JSON object or names another indicator.
pub fn decode(body: &[u8], indicator: Indicator<'_>) -> Result<Option<Finding>, LegError> {
    let record: Map<String, Value> = api_leg::decode(body)?;
    let named = match indicator {
        Indicator::Ip(_) => text(record.get("ip_addr")),
        _ => text(record.get("hostname")),
    };
    if !named.is_some_and(|named| named.eq_ignore_ascii_case(indicator.value())) {
        return Err(LegError::Decode("answer names another indicator".into()));
    }
    let classification = text(record.get("classification")).unwrap_or_else(|| "unknown".into());
    let listings: Vec<String> = record
        .get("blacklist")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(listing)
        .collect();
    let flags: Vec<&str> = FLAGS
        .iter()
        .filter(|(key, _)| record.get(*key).and_then(Value::as_bool) == Some(true))
        .map(|(_, name)| *name)
        .collect();
    let malicious = classification.eq_ignore_ascii_case("malicious");
    let mut finding = Finding::new(format!(
        "Maltiverse: classified {classification}, on {} blacklist{}",
        listings.len(),
        if listings.len() == 1 { "" } else { "s" }
    ))
    .attr("classification", &classification)
    .attr("blacklist", listings.join(" | "))
    .list_attr("flags", &flags)
    .list_attr("maltiverse_tags", &strings(record.get("tag")))
    .tag_if(malicious, tags::MALICIOUS)
    .tag_if(
        classification.eq_ignore_ascii_case("suspicious"),
        "suspicious",
    );
    if malicious {
        finding = finding.attr("malicious", "1");
    }
    for (key, name) in FIELDS {
        finding = finding.opt_attr(name, text(record.get(key)));
    }
    if let Some(location) = record.get("location") {
        if let (Some(lat), Some(lon)) = (text(location.get("lat")), text(location.get("lon"))) {
            finding = finding.attr("location", format!("{lat},{lon}"));
        }
    }
    if let Some(asn) = text(record.get("as_number")) {
        finding = finding.attr("asn", &asn).pivot(
            PivotKind::Asn,
            format!("AS{}", asn.trim_start_matches(['A', 'S', 'a', 's'])),
            "AS Maltiverse places the indicator in",
        );
    }
    let resolved: Vec<String> = record
        .get("resolved_ip")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let ip = text(entry.get("ip_addr"))?;
            Some(match text(entry.get("timestamp")) {
                Some(seen) => format!("{ip} ({seen})"),
                None => ip,
            })
        })
        .collect();
    finding = finding.attr("resolved", resolved.join(" | "));
    for entry in record
        .get("resolved_ip")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(ip) = text(entry.get("ip_addr")) {
            finding = finding.pivot(
                PivotKind::Ip,
                ip,
                "Address Maltiverse saw the name resolve to",
            );
        }
    }
    Ok(Some(finding))
}

#[cfg(test)]
mod tests;
