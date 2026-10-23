//! Internet Storm Center (SANS ISC, `DShield`): what its sensors and feeds know of one IPv4
//! address.
//!
//! One lookup is one keyless `GET https://isc.sans.edu/api/ip/{ip}?json`, Spiderfoot's
//! `sfp_isc`. Kept whole: the reports and targets the sensors logged and their dates, ISC's risk
//! and comment, every threat feed that lists the address with when it first and last did, the
//! SSH and web-log activity its honeypots saw from it, its network, AS, abuse contact and cloud.
//! An address the sensors logged attacking, or the honeypots saw trying SSH logins or web
//! requests, is malicious, as `sfp_isc` reports it. One with no record at all is a valid zero;
//! one with only its network still comes back, unmarked.

use serde::Deserialize;
use serde_json::Value;

use crate::api_leg::{self, Answer, Api, LegError};
use crate::http::Transport;
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, PivotKind, Source};
use crate::keys::Keys;
use crate::tags;

pub const SOURCE: &str = "isc";
pub const API: Api = Api {
    source: SOURCE,
    provider: "isc.sans.edu",
    origin: "https://isc.sans.edu:443",
    key: None,
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Ipv4],
    lookup,
};

#[derive(Deserialize)]
struct Body {
    ip: Record,
}

/// One address's record; `number` echoes the query.
#[derive(Deserialize)]
struct Record {
    number: Value,
    #[serde(default)]
    count: Value,
    #[serde(default)]
    attacks: Value,
    #[serde(default)]
    mindate: Value,
    #[serde(default)]
    maxdate: Value,
    #[serde(default)]
    updated: Value,
    #[serde(default)]
    comment: Value,
    #[serde(default)]
    maxrisk: Value,
    #[serde(default)]
    asabusecontact: Value,
    #[serde(default)]
    r#as: Value,
    #[serde(default)]
    asname: Value,
    #[serde(default)]
    ascountry: Value,
    #[serde(default)]
    assize: Value,
    #[serde(default)]
    network: Value,
    #[serde(default)]
    cloud: Value,
    #[serde(default)]
    clouddetails: Value,
    #[serde(default)]
    threatfeeds: Value,
    #[serde(default)]
    ssh: Value,
    #[serde(default)]
    weblogs: Value,
}

/// The request URL for `indicator`, or `None` when it is not an IP address. **Pure.**
#[must_use]
pub fn url(indicator: Indicator<'_>) -> Option<String> {
    match indicator {
        Indicator::Ip(ip) => Some(format!("https://isc.sans.edu/api/ip/{ip}?json")),
        _ => None,
    }
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

/// A count, zero when absent or not a number. **Pure.**
fn count(value: &Value) -> u64 {
    api_leg::scalar(value)
        .and_then(|text| text.parse().ok())
        .unwrap_or(0)
}

/// An object's fields as `key=value` by name; nested values as JSON. **Pure.**
fn fields(value: &Value) -> Option<String> {
    let Value::Object(map) = value else {
        return api_leg::scalar(value);
    };
    let parts: Vec<String> = map
        .iter()
        .filter(|(_, value)| !value.is_null())
        .map(|(key, value)| match api_leg::scalar(value) {
            Some(text) => format!("{key}={text}"),
            None => format!("{key}={value}"),
        })
        .collect();
    (!parts.is_empty()).then(|| parts.join(", "))
}

/// Each listing feed as `name (first..last)`. **Pure.**
fn feeds(value: &Value) -> Vec<String> {
    let Value::Object(map) = value else {
        return Vec::new();
    };
    map.iter()
        .map(|(name, seen)| {
            let first = api_leg::scalar(&seen["firstseen"]).unwrap_or_default();
            let last = api_leg::scalar(&seen["lastseen"]).unwrap_or_default();
            if first.is_empty() && last.is_empty() {
                name.clone()
            } else {
                format!("{name} ({first}..{last})")
            }
        })
        .collect()
}

/// One answer body for `indicator`. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented shape or names another address.
pub fn decode(body: &[u8], indicator: Indicator<'_>) -> Result<Option<Finding>, LegError> {
    let Body { ip: record } = api_leg::decode(body)?;
    if api_leg::scalar(&record.number).as_deref() != Some(indicator.value()) {
        return Err(LegError::Decode("answer names another address".into()));
    }
    let (reports, targets) = (count(&record.count), count(&record.attacks));
    let feeds = feeds(&record.threatfeeds);
    let ssh = fields(&record.ssh);
    let weblogs = fields(&record.weblogs);
    let network = api_leg::scalar(&record.network);
    if reports == 0
        && targets == 0
        && feeds.is_empty()
        && network.is_none()
        && ssh.is_none()
        && weblogs.is_none()
    {
        return Ok(None);
    }
    let honeypots = count(&record.ssh["attempts"]) + count(&record.weblogs["count"]);
    let attacked = reports > 0 || targets > 0 || honeypots > 0;
    let mut finding = Finding::new(format!(
        "ISC: {reports} report{} against {targets} target{}, listed by {} threat feed{}",
        plural(reports),
        plural(targets),
        feeds.len(),
        plural(feeds.len() as u64),
    ))
    .attr("reports", reports.to_string())
    .attr("targets", targets.to_string())
    .opt_attr("first_reported", api_leg::scalar(&record.mindate))
    .opt_attr("last_reported", api_leg::scalar(&record.maxdate))
    .opt_attr("updated", api_leg::scalar(&record.updated))
    .opt_attr("risk", api_leg::scalar(&record.maxrisk))
    .opt_attr("comment", api_leg::scalar(&record.comment))
    .list_attr("threat_feeds", &feeds)
    .opt_attr("ssh", ssh)
    .opt_attr("weblogs", weblogs)
    .opt_attr("network", network)
    .opt_attr("as_name", api_leg::scalar(&record.asname))
    .opt_attr("as_country", api_leg::scalar(&record.ascountry))
    .opt_attr("as_size", api_leg::scalar(&record.assize))
    .opt_attr("abuse_contact", api_leg::scalar(&record.asabusecontact))
    .opt_attr("cloud", api_leg::scalar(&record.cloud))
    .opt_attr("cloud_details", fields(&record.clouddetails))
    .tag_if(attacked, tags::MALICIOUS);
    if attacked {
        finding = finding.attr("malicious", (reports + honeypots).max(1).to_string());
    }
    if let Some(asn) = api_leg::scalar(&record.r#as) {
        finding = finding.attr("asn", &asn).pivot(
            PivotKind::Asn,
            format!("AS{asn}"),
            "AS ISC places the address in",
        );
    }
    Ok(Some(finding))
}

const fn plural(count: u64) -> &'static str {
    if count == 1 { "" } else { "s" }
}

#[cfg(test)]
mod tests;
