//! Internet Storm Center (SANS ISC, `DShield`): what its sensors and feeds know of one IP address.
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
    kinds: &[IndicatorKind::Ip],
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

/// A scalar as text: a number or string as written, anything else `None`. **Pure.**
fn text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => api_leg::clean(Some(text)),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

/// A count, zero when absent or not a number. **Pure.**
fn count(value: &Value) -> u64 {
    text(value).and_then(|text| text.parse().ok()).unwrap_or(0)
}

/// An object's fields as `key=value` by name; nested values as JSON. **Pure.**
fn fields(value: &Value) -> Option<String> {
    let Value::Object(map) = value else {
        return text(value);
    };
    let parts: Vec<String> = map
        .iter()
        .filter(|(_, value)| !value.is_null())
        .map(|(key, value)| match text(value) {
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
            let first = text(&seen["firstseen"]).unwrap_or_default();
            let last = text(&seen["lastseen"]).unwrap_or_default();
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
    if text(&record.number).as_deref() != Some(indicator.value()) {
        return Err(LegError::Decode("answer names another address".into()));
    }
    let (reports, targets) = (count(&record.count), count(&record.attacks));
    let feeds = feeds(&record.threatfeeds);
    let ssh = fields(&record.ssh);
    let weblogs = fields(&record.weblogs);
    let network = text(&record.network);
    if reports == 0 && targets == 0 && feeds.is_empty() && network.is_none() && ssh.is_none() {
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
    .opt_attr("first_reported", text(&record.mindate))
    .opt_attr("last_reported", text(&record.maxdate))
    .opt_attr("updated", text(&record.updated))
    .opt_attr("risk", text(&record.maxrisk))
    .opt_attr("comment", text(&record.comment))
    .list_attr("threat_feeds", &feeds)
    .opt_attr("ssh", ssh)
    .opt_attr("weblogs", weblogs)
    .opt_attr("network", network)
    .opt_attr("as_name", text(&record.asname))
    .opt_attr("as_country", text(&record.ascountry))
    .opt_attr("as_size", text(&record.assize))
    .opt_attr("abuse_contact", text(&record.asabusecontact))
    .opt_attr("cloud", text(&record.cloud))
    .opt_attr("cloud_details", fields(&record.clouddetails))
    .tag_if(attacked, tags::MALICIOUS);
    if attacked {
        finding = finding.attr("malicious", (reports + honeypots).max(1).to_string());
    }
    if let Some(asn) = text(&record.r#as) {
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
