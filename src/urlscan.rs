//! urlscan.io: public scans of web pages that involve one IP or domain.
//!
//! One lookup is one `GET https://urlscan.io/api/v1/search/?q={domain|ip}:"{value}"&size=10`.
//! urlscan.io answers searches without a key; with `HUNTSMAN_URLSCAN_KEY` set the key goes in the
//! `API-Key` header and the account's quota applies. Kept: how many scans match, when the newest
//! ran, and from each of the newest ten the page's domain, address, AS, server and urlscan's
//! verdict. Scanned URLs are not kept: their query strings can carry other people's tokens. No
//! match is a valid zero.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::http::{Transport, percent_encode_component};
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, PivotKind, Source};
use crate::keys::Keys;
use crate::tags;

pub const SOURCE: &str = "urlscan";
pub const KEY_SLOT: &str = crate::environment::URLSCAN_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "urlscan.io",
    origin: "https://urlscan.io:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Header("API-Key"),
        required: false,
    }),
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Ip, IndicatorKind::Domain],
    lookup,
};
/// Scans read per search.
pub const LIMIT: usize = 10;
/// Most server names kept in one attribute.
const MAX_NAMES: usize = 10;

#[derive(Deserialize)]
struct Body {
    #[serde(default)]
    results: Vec<Scan>,
    #[serde(default)]
    total: Option<u64>,
}

#[derive(Deserialize)]
struct Scan {
    #[serde(default)]
    page: Option<Page>,
    #[serde(default)]
    task: Option<Task>,
    #[serde(default)]
    verdicts: Option<Verdicts>,
}

#[derive(Deserialize)]
struct Page {
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    asn: Option<String>,
    #[serde(default)]
    asnname: Option<String>,
    #[serde(default)]
    server: Option<String>,
}

#[derive(Deserialize)]
struct Task {
    #[serde(default)]
    time: Option<String>,
}

#[derive(Deserialize)]
struct Verdicts {
    #[serde(default)]
    overall: Option<Overall>,
}

#[derive(Deserialize)]
struct Overall {
    #[serde(default)]
    malicious: bool,
}

/// The search URL for `indicator`, or `None` for a kind urlscan.io is not asked about. **Pure.**
#[must_use]
pub fn url(indicator: Indicator<'_>) -> Option<String> {
    let field = match indicator {
        Indicator::Ip(_) => "ip",
        Indicator::Domain(_) => "domain",
        Indicator::Email(_) | Indicator::Phone(_) | Indicator::Cell(_) | Indicator::MacAddress(_) => return None,
    };
    let query = format!("{field}:\"{}\"", indicator.value());
    Some(format!(
        "https://urlscan.io/api/v1/search/?q={}&size={LIMIT}",
        percent_encode_component(&query)
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
        Answer::NotFound(_) => Err(LegError::Unexpected(404)),
    }
}

/// One search page for `indicator`. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented shape.
pub fn decode(body: &[u8], indicator: Indicator<'_>) -> Result<Option<Finding>, LegError> {
    let body: Body = api_leg::decode(body)?;
    if body.results.is_empty() {
        return Ok(None);
    }
    let scans = &body.results[..body.results.len().min(LIMIT)];
    let total = body.total.unwrap_or(scans.len() as u64);
    let malicious = scans
        .iter()
        .filter(|s| {
            s.verdicts
                .as_ref()
                .and_then(|v| v.overall.as_ref())
                .is_some_and(|o| o.malicious)
        })
        .count();
    let newest = scans
        .iter()
        .filter_map(|s| s.task.as_ref().and_then(|t| t.time.as_deref()))
        .max();
    let pages: Vec<&Page> = scans.iter().filter_map(|s| s.page.as_ref()).collect();
    let mut servers: Vec<String> = Vec::new();
    for server in pages
        .iter()
        .filter_map(|p| api_leg::clean(p.server.as_deref()))
    {
        if !servers.contains(&server) && servers.len() < MAX_NAMES {
            servers.push(server);
        }
    }
    let mut finding = Finding::new(format!(
        "urlscan.io: {total} public scan(s), {malicious} of the newest {} judged malicious",
        scans.len()
    ))
    .attr("scan_count", total.to_string())
    .attr("malicious_scans", malicious.to_string())
    .list_attr("servers", &servers)
    .opt_attr("newest_scan", newest)
    .tag_if(malicious > 0, tags::MALICIOUS)
    .tag_if(total > scans.len() as u64, "truncated");
    for page in pages {
        if let Some(domain) = page.domain.as_deref() {
            if !domain.eq_ignore_ascii_case(indicator.value()) {
                finding = finding.pivot(
                    PivotKind::Domain,
                    domain,
                    "Page domain in a urlscan.io scan involving the indicator",
                );
            }
        }
        if let Some(ip) = page.ip.as_deref() {
            if ip != indicator.value() {
                finding = finding.pivot(
                    PivotKind::Ip,
                    ip,
                    "Page address in a urlscan.io scan involving the indicator",
                );
            }
        }
        if let Some(asn) = page.asn.as_deref() {
            finding = finding.pivot(
                PivotKind::Asn,
                asn,
                "AS serving a page in a urlscan.io scan involving the indicator",
            );
        }
        if let Some(name) = page.asnname.as_deref() {
            finding = finding.pivot(
                PivotKind::Organisation,
                name,
                "AS holder serving a page in a urlscan.io scan involving the indicator",
            );
        }
    }
    Ok(Some(finding))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded without a key for `domain:example.com` on 2026-10-14 (one result, a second added
    /// with a malicious verdict; `task.url` with its token-carrying query kept to prove it is
    /// dropped).
    const RECORDED: &str = r#"{"results":[{"canonical":{"task":{"url":"glamours-designs.com/v6g/bf166c"},"page":{"url":"example.com"}},"task":{"visibility":"public","method":"manual","domain":"glamours-designs.com","apexDomain":"glamours-designs.com","time":"2026-10-14T15:05:47.894Z","uuid":"01a13af2-9db2-737d-b351-623c2b84b921","url":"https://glamours-designs.com/v6g/bf166c?e5b5=L3YzL3NpZ25pbi9pZGVudGlmaWVy"},"stats":{"uniqIPs":2,"uniqCountries":2,"dataLength":2956,"encodedDataLength":2610,"requests":3},"page":{"server":"cloudflare","redirected":"off-domain","ip":"104.20.23.154","mimeType":"text/html","title":"Example Domain","url":"https://example.com/","domain":"example.com","apexDomain":"example.com","asnname":"CLOUDFLARENET - Cloudflare, Inc., US","asn":"AS13335","status":"200"},"verdicts":null,"_id":"01a13af2-9db2-737d-b351-623c2b84b921","result":"https://urlscan.io/api/v1/result/01a13af2-9db2-737d-b351-623c2b84b921/","sort":[1791990347894,"01a13af2"]},{"task":{"time":"2026-10-13T01:00:00.000Z"},"page":{"server":"nginx","ip":"203.0.113.9","domain":"login-example.test","asn":"AS64500","asnname":"EXAMPLE-AS"},"verdicts":{"overall":{"malicious":true,"score":100}}}],"total":5906,"took":56,"has_more":false,"search_date_limit_days":30}"#;

    #[test]
    fn a_recorded_page_keeps_counts_verdicts_and_pivots_but_no_url() {
        let f = decode(RECORDED.as_bytes(), Indicator::Domain("example.com"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        assert_eq!(
            f.summary,
            "urlscan.io: 5906 public scan(s), 1 of the newest 2 judged malicious"
        );
        assert!(f.attrs.contains(&("servers", "cloudflare,nginx".into())));
        assert!(f.tags.contains(&tags::MALICIOUS) && f.tags.contains(&"truncated"));
        let text = format!("{f:?}");
        assert!(!text.contains("e5b5") && !text.contains("bf166c"), "{text}");
        assert!(
            f.pivots
                .iter()
                .any(|p| p.kind == PivotKind::Domain && p.value == "login-example.test")
        );
        assert!(
            !f.pivots.iter().any(|p| p.value == "example.com"),
            "the indicator is not its own pivot"
        );
    }

    #[test]
    fn no_scan_is_a_zero_and_the_query_is_quoted() {
        let empty = r#"{"results":[],"total":0,"took":49,"has_more":false}"#;
        assert_eq!(
            decode(empty.as_bytes(), Indicator::Ip("192.0.2.1")),
            Ok(None)
        );
        assert!(decode(b"<html>", Indicator::Ip("192.0.2.1")).is_err());
        assert_eq!(
            url(Indicator::Ip("2001:db8::1")).as_deref(),
            Some("https://urlscan.io/api/v1/search/?q=ip%3A%222001%3Adb8%3A%3A1%22&size=10")
        );
    }
}
