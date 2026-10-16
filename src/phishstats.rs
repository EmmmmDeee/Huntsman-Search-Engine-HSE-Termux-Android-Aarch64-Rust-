//! `PhishStats`: phishing URLs reported on one IP address.
//!
//! One lookup is keyless `GET https://api.phishstats.info/api/phishing?_where=(ip,eq,{ip})`,
//! newest first, a page of 100 at a time up to [`MAX_PAGES`], Spiderfoot's `sfp_phishstats`.
//! Every phishing URL reported on the address is kept whole, with every field `PhishStats` gives
//! it: where it redirects, when it was reported, its score, title, host, TLS certificate, HTTP
//! server, open ports, abuse contact and how often the address and host have been seen.
//! An address with a reported URL is malicious, as `sfp_phishstats` reports it, and each host the
//! URLs were served from is a pivot. An address with none is a valid zero.

use serde_json::{Map, Value};

use crate::api_leg::{self, Answer, Api, LegError};
use crate::http::Transport;
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, PivotKind, Source};
use crate::keys::Keys;
use crate::tags;

pub const SOURCE: &str = "phishstats";
pub const API: Api = Api {
    source: SOURCE,
    provider: "phishstats.info",
    origin: "https://api.phishstats.info:443",
    key: None,
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Ip],
    lookup,
};
/// Reports a page holds, the most the API gives at once.
pub const PAGE: usize = 100;
/// Most pages one lookup reads; an address with more says so.
pub const MAX_PAGES: usize = 10;
/// The request URL for page `page` (from 0) of `indicator`'s reports, or `None` when it is not
/// an IP address. **Pure.**
#[must_use]
pub fn url(indicator: Indicator<'_>, page: usize) -> Option<String> {
    match indicator {
        Indicator::Ip(ip) => Some(format!(
            "https://api.phishstats.info/api/phishing?_where=(ip,eq,{ip})&_sort=-id&_size={PAGE}&_p={page}"
        )),
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
    let mut rows = Vec::new();
    for page in 0..MAX_PAGES {
        let Some(url) = url(indicator, page) else {
            return Ok(None);
        };
        let body = match api_leg::get(transport, &API, keys, &url, now_unix)? {
            Answer::Body(body) => body,
            Answer::NotFound(_) => return Err(LegError::Unexpected(404)),
        };
        let page = decode_page(&body, indicator)?;
        let full = page.len() >= PAGE;
        rows.extend(page);
        if !full {
            return Ok(finding(&rows, false));
        }
    }
    Ok(finding(&rows, true))
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

/// One report as `URL (field=value, ...)`, with every field it has but the address asked about,
/// by name. **Pure.**
fn report(row: &Map<String, Value>) -> Option<String> {
    let url = text(row.get("url"))?;
    let fields: Vec<String> = row
        .iter()
        .filter(|(field, _)| !matches!(field.as_str(), "url" | "ip"))
        .filter_map(|(field, value)| text(Some(value)).map(|value| format!("{field}={value}")))
        .collect();
    Some(if fields.is_empty() {
        url
    } else {
        format!("{url} ({})", fields.join(", "))
    })
}

/// One page of reports for `indicator`. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not a list of reports, or a report on another address.
pub fn decode_page(
    body: &[u8],
    indicator: Indicator<'_>,
) -> Result<Vec<Map<String, Value>>, LegError> {
    let rows: Vec<Map<String, Value>> = api_leg::decode(body)?;
    if rows
        .iter()
        .any(|row| text(row.get("ip")).is_some_and(|ip| ip != indicator.value()))
    {
        return Err(LegError::Decode("answer reports another address".into()));
    }
    Ok(rows)
}

/// What the reports `rows` say of the address, `None` for none; `more` when the last page read
/// was full. **Pure.**
#[must_use]
pub fn finding(rows: &[Map<String, Value>], more: bool) -> Option<Finding> {
    let reports: Vec<String> = rows.iter().filter_map(report).collect();
    if reports.is_empty() {
        return None;
    }
    let latest = rows.iter().find_map(|row| text(row.get("date")));
    let mut finding = Finding::new(format!(
        "PhishStats: {} phishing URL{} reported on the address{}",
        reports.len(),
        if reports.len() == 1 { "" } else { "s" },
        latest
            .as_deref()
            .map_or_else(String::new, |date| format!(", latest on {date}"))
    ))
    .attr("malicious", reports.len().to_string())
    .attr("phishing_urls", reports.join(" | "))
    .opt_attr("last_reported", latest)
    .tag(tags::MALICIOUS)
    .tag("phishing");
    if more {
        finding = finding.attr("more_reports", "true");
    }
    for row in rows {
        if let Some(host) = text(row.get("host")) {
            finding = finding.pivot(
                PivotKind::Domain,
                host,
                "Host PhishStats reports serving phishing from the address",
            );
        }
    }
    Some(finding)
}

#[cfg(test)]
mod tests;
