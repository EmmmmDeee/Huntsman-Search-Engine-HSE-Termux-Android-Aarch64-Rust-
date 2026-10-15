//! urlscan.io: public scans of web pages that involve one IP or domain.
//!
//! One lookup is one `GET https://urlscan.io/api/v1/search/?q={domain|ip}:"{value}"&size=100`.
//! urlscan.io answers searches without a key; with `HUNTSMAN_URLSCAN_KEY` set the key goes in the
//! `API-Key` header and the account's quota applies. A hundred is the most one search page gives
//! without a key (checked 2026-10-15). No match is a valid zero. Every search answer carries
//! `results`, empty when nothing matched (checked 2026-10-15): a JSON body without it, such as an
//! error or quota notice, is drift.
//!
//! Everything about the listed scans is kept: each scan whole as JSON in `raw_scans`, and, across
//! them, how many matched, the oldest and newest, every submitted and final URL, page title,
//! status, MIME type, server, TLS issuer, country, redirect kind, apex domain, scan id, result
//! and screenshot link, and urlscan's verdicts and highest score. Each page's domain, address,
//! AS and AS holder, and each submitted domain, are pivots.

use std::collections::HashSet;

use serde::Deserialize;
use serde_json::Value;

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
/// Scans asked for per search: the most one page gives without a key.
pub const LIMIT: usize = 100;

#[derive(Deserialize)]
struct Body {
    results: Vec<Value>,
    #[serde(default)]
    total: Option<u64>,
    #[serde(default)]
    has_more: Option<bool>,
}

#[derive(Deserialize)]
struct Scan {
    #[serde(default)]
    page: Option<Page>,
    #[serde(default)]
    task: Option<Task>,
    #[serde(default)]
    verdicts: Option<Verdicts>,
    #[serde(default)]
    result: Option<String>,
    #[serde(default)]
    screenshot: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Page {
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    apex_domain: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    asn: Option<String>,
    #[serde(default)]
    asnname: Option<String>,
    #[serde(default)]
    server: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    status: Option<Value>,
    #[serde(default)]
    mime_type: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    tls_issuer: Option<String>,
    #[serde(default)]
    redirected: Option<Value>,
}

#[derive(Deserialize)]
struct Task {
    #[serde(default)]
    time: Option<String>,
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    domain: Option<String>,
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
    #[serde(default)]
    score: Option<f64>,
}

/// The search URL for `indicator`, or `None` for a kind urlscan.io is not asked about. **Pure.**
#[must_use]
pub fn url(indicator: Indicator<'_>) -> Option<String> {
    let field = match indicator {
        Indicator::Ip(_) => "ip",
        Indicator::Domain(_) => "domain",
        Indicator::Email(_) | Indicator::Phone(_) => return None,
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

/// Cleaned values in the order first seen, each once. **Pure.**
#[derive(Default)]
struct Distinct {
    values: Vec<String>,
    seen: HashSet<String>,
}

impl Distinct {
    fn push(&mut self, value: Option<&str>) {
        if let Some(value) = api_leg::clean(value) {
            if self.seen.insert(value.clone()) {
                self.values.push(value);
            }
        }
    }

    /// A string, number or boolean urlscan.io gives, as text.
    fn push_scalar(&mut self, value: Option<&Value>) {
        match value {
            Some(Value::String(s)) => self.push(Some(s)),
            Some(v @ (Value::Number(_) | Value::Bool(_))) => self.push(Some(&v.to_string())),
            _ => {}
        }
    }
}

/// What the listed scans say, across them all. **Pure.**
#[derive(Default)]
struct Scans {
    malicious: usize,
    best_score: Option<f64>,
    oldest: Option<String>,
    newest: Option<String>,
    urls: Distinct,
    page_urls: Distinct,
    titles: Distinct,
    statuses: Distinct,
    mime_types: Distinct,
    servers: Distinct,
    tls_issuers: Distinct,
    countries: Distinct,
    redirects: Distinct,
    apex_domains: Distinct,
    scan_ids: Distinct,
    results: Distinct,
    screenshots: Distinct,
}

impl Scans {
    fn read(scans: &[Scan]) -> Self {
        let mut out = Self::default();
        for scan in scans {
            if let Some(overall) = scan.verdicts.as_ref().and_then(|v| v.overall.as_ref()) {
                out.malicious += usize::from(overall.malicious);
                if let Some(score) = overall.score {
                    out.best_score = Some(out.best_score.map_or(score, |best| best.max(score)));
                }
            }
            if let Some(task) = &scan.task {
                if let Some(time) = task.time.as_deref() {
                    if out.oldest.as_deref().is_none_or(|t| time < t) {
                        out.oldest = Some(time.to_owned());
                    }
                    if out.newest.as_deref().is_none_or(|t| time > t) {
                        out.newest = Some(time.to_owned());
                    }
                }
                out.urls.push(task.url.as_deref());
                out.scan_ids.push(task.uuid.as_deref());
            }
            if let Some(page) = &scan.page {
                out.page_urls.push(page.url.as_deref());
                out.titles.push(page.title.as_deref());
                out.statuses.push_scalar(page.status.as_ref());
                out.mime_types.push(page.mime_type.as_deref());
                out.servers.push(page.server.as_deref());
                out.tls_issuers.push(page.tls_issuer.as_deref());
                out.countries.push(page.country.as_deref());
                out.redirects.push_scalar(page.redirected.as_ref());
                out.apex_domains.push(page.apex_domain.as_deref());
            }
            out.results.push(scan.result.as_deref());
            out.screenshots.push(scan.screenshot.as_deref());
        }
        out
    }

    fn into_finding(self, finding: Finding) -> Finding {
        finding
            .attr("malicious_scans", self.malicious.to_string())
            .opt_attr("max_verdict_score", self.best_score.map(|s| s.to_string()))
            .opt_attr("oldest_scan", self.oldest)
            .opt_attr("newest_scan", self.newest)
            .list_attr("urls", &self.urls.values)
            .list_attr("page_urls", &self.page_urls.values)
            .list_attr("page_titles", &self.titles.values)
            .list_attr("page_statuses", &self.statuses.values)
            .list_attr("mime_types", &self.mime_types.values)
            .list_attr("servers", &self.servers.values)
            .list_attr("tls_issuers", &self.tls_issuers.values)
            .list_attr("page_countries", &self.countries.values)
            .list_attr("redirects", &self.redirects.values)
            .list_attr("apex_domains", &self.apex_domains.values)
            .list_attr("scan_ids", &self.scan_ids.values)
            .list_attr("result_links", &self.results.values)
            .list_attr("screenshots", &self.screenshots.values)
            .tag_if(self.malicious > 0, tags::MALICIOUS)
    }
}

/// The domains, addresses and networks a scan names, except the indicator itself. **Pure.**
fn pivots(mut finding: Finding, scans: &[Scan], indicator: Indicator<'_>) -> Finding {
    let other = |value: &str| !value.eq_ignore_ascii_case(indicator.value());
    for scan in scans {
        if let Some(domain) = scan.task.as_ref().and_then(|t| t.domain.as_deref()) {
            if other(domain) {
                finding = finding.pivot(
                    PivotKind::Domain,
                    domain,
                    "Submitted domain of a urlscan.io scan involving the indicator",
                );
            }
        }
        let Some(page) = &scan.page else { continue };
        if let Some(domain) = page.domain.as_deref().filter(|d| other(d)) {
            finding = finding.pivot(
                PivotKind::Domain,
                domain,
                "Page domain in a urlscan.io scan involving the indicator",
            );
        }
        if let Some(ip) = page.ip.as_deref().filter(|ip| other(ip)) {
            finding = finding.pivot(
                PivotKind::Ip,
                ip,
                "Page address in a urlscan.io scan involving the indicator",
            );
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
    finding
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
    let scans = body
        .results
        .iter()
        .map(Scan::deserialize)
        .collect::<Result<Vec<Scan>, _>>()
        .map_err(|e| LegError::Decode(format!("unexpected scan shape: {e}")))?;
    let listed = scans.len() as u64;
    let total = body.total.unwrap_or(listed).max(listed);
    let read = Scans::read(&scans);
    let mut finding = Finding::new(format!(
        "urlscan.io: {total} public scan(s), {} of the newest {listed} judged malicious",
        read.malicious
    ))
    .attr("scan_count", total.to_string())
    .attr("scans_listed", listed.to_string())
    .tag_if(total > listed || body.has_more == Some(true), "truncated");
    finding = read.into_finding(finding);
    finding = pivots(finding, &scans, indicator);
    Ok(Some(
        finding.attr("raw_scans", Value::Array(body.results).to_string()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded without a key for `domain:example.com` on 2026-10-14 (one result, a second added
    /// with a malicious verdict).
    const RECORDED: &str = r#"{"results":[{"canonical":{"task":{"url":"glamours-designs.com/v6g/bf166c"},"page":{"url":"example.com"}},"task":{"visibility":"public","method":"manual","domain":"glamours-designs.com","apexDomain":"glamours-designs.com","time":"2026-10-14T15:05:47.894Z","uuid":"01a13af2-9db2-737d-b351-623c2b84b921","url":"https://glamours-designs.com/v6g/bf166c?e5b5=L3YzL3NpZ25pbi9pZGVudGlmaWVy"},"stats":{"uniqIPs":2,"uniqCountries":2,"dataLength":2956,"encodedDataLength":2610,"requests":3},"page":{"server":"cloudflare","redirected":"off-domain","ip":"104.20.23.154","mimeType":"text/html","title":"Example Domain","url":"https://example.com/","domain":"example.com","apexDomain":"example.com","asnname":"CLOUDFLARENET - Cloudflare, Inc., US","asn":"AS13335","status":"200"},"verdicts":null,"_id":"01a13af2-9db2-737d-b351-623c2b84b921","result":"https://urlscan.io/api/v1/result/01a13af2-9db2-737d-b351-623c2b84b921/","sort":[1791990347894,"01a13af2"]},{"task":{"time":"2026-10-13T01:00:00.000Z"},"page":{"server":"nginx","ip":"203.0.113.9","domain":"login-example.test","asn":"AS64500","asnname":"EXAMPLE-AS"},"verdicts":{"overall":{"malicious":true,"score":100}}}],"total":5906,"took":56,"has_more":false,"search_date_limit_days":30}"#;

    fn value<'a>(f: &'a Finding, key: &str) -> Option<&'a str> {
        f.attrs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn a_recorded_page_keeps_counts_verdicts_urls_and_pivots() {
        let f = decode(RECORDED.as_bytes(), Indicator::Domain("example.com"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        assert_eq!(
            f.summary,
            "urlscan.io: 5906 public scan(s), 1 of the newest 2 judged malicious"
        );
        for (key, expected) in [
            ("scan_count", "5906"),
            ("scans_listed", "2"),
            ("malicious_scans", "1"),
            ("max_verdict_score", "100"),
            ("oldest_scan", "2026-10-13T01:00:00.000Z"),
            ("newest_scan", "2026-10-14T15:05:47.894Z"),
            (
                "urls",
                "https://glamours-designs.com/v6g/bf166c?e5b5=L3YzL3NpZ25pbi9pZGVudGlmaWVy",
            ),
            ("page_urls", "https://example.com/"),
            ("page_titles", "Example Domain"),
            ("page_statuses", "200"),
            ("mime_types", "text/html"),
            ("servers", "cloudflare,nginx"),
            ("redirects", "off-domain"),
            ("apex_domains", "example.com"),
            ("scan_ids", "01a13af2-9db2-737d-b351-623c2b84b921"),
            (
                "result_links",
                "https://urlscan.io/api/v1/result/01a13af2-9db2-737d-b351-623c2b84b921/",
            ),
        ] {
            assert_eq!(value(&f, key), Some(expected), "{key}: {:?}", f.attrs);
        }
        assert!(f.tags.contains(&tags::MALICIOUS) && f.tags.contains(&"truncated"));
        let domains: Vec<&str> = f
            .pivots
            .iter()
            .filter(|p| p.kind == PivotKind::Domain)
            .map(|p| p.value.as_str())
            .collect();
        assert_eq!(domains, ["glamours-designs.com", "login-example.test"]);
        assert!(
            !f.pivots.iter().any(|p| p.value == "example.com"),
            "the indicator is not its own pivot"
        );
    }

    #[test]
    fn every_listed_scan_is_kept_whole() {
        let f = decode(RECORDED.as_bytes(), Indicator::Domain("example.com"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        let raw: Value =
            serde_json::from_str(value(&f, "raw_scans").unwrap_or_default()).unwrap_or_default();
        assert_eq!(raw.as_array().map(Vec::len), Some(2));
        assert_eq!(raw[0]["stats"]["requests"], 3);
        assert_eq!(
            raw[0]["canonical"]["task"]["url"],
            "glamours-designs.com/v6g/bf166c"
        );
        assert_eq!(raw[1]["verdicts"]["overall"]["score"], 100);
    }

    #[test]
    fn a_status_given_as_a_number_is_kept_as_text() {
        let body = r#"{"results":[{"page":{"status":404,"redirected":null}}],"total":1}"#;
        let f = decode(body.as_bytes(), Indicator::Ip("192.0.2.1"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("a scan with a numeric status must decode"));
        assert_eq!(value(&f, "page_statuses"), Some("404"));
        assert_eq!(value(&f, "redirects"), None);
        assert!(!f.tags.contains(&"truncated"));
    }

    #[test]
    fn a_json_answer_without_results_is_drift_not_no_scans() {
        for body in [
            "{}",
            r#"{"message":"Search is temporarily unavailable","status":503}"#,
            r#"{"results":null,"total":0}"#,
        ] {
            let decoded = decode(body.as_bytes(), Indicator::Domain("example.com"));
            assert!(
                matches!(decoded, Err(LegError::Decode(_))),
                "{body}: {decoded:?}"
            );
        }
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
            Some("https://urlscan.io/api/v1/search/?q=ip%3A%222001%3Adb8%3A%3A1%22&size=100")
        );
    }
}
