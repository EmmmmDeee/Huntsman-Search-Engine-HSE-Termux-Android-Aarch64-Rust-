//! Shodan: what Shodan's crawlers saw on one public IP, and the DNS records it holds for a domain.
//!
//! An IP is one `GET https://api.shodan.io/shodan/host/{ip}` (free with any key, no query
//! credits). A domain is one `GET https://api.shodan.io/dns/domain/{domain}`, which spends one
//! query credit. Both run whenever `HUNTSMAN_SHODAN_KEY` is set; Shodan takes the key only as the
//! `key` query parameter, which [`crate::fetch`] adds as the request is sent. A `404` whose body
//! is Shodan's JSON `{"error": …}` is its "no information available", a valid zero; any other
//! `404` (the HTML page Shodan serves for a path it does not have) is a failed lookup.
//!
//! Everything is kept. For an address: the answer without its banners as JSON in `raw_host`,
//! every service banner whole in `raw_banners`, and read out of them the ports, tags, CVEs, the
//! organisation, ISP, AS and OS, the place (city, region, postcode, country, area and DMA codes,
//! and the position as `coordinates`), and from the banners every service with its product and
//! version, CPE, crawler module, HTTP title, server, redirect, component, WAF and favicon hash,
//! TLS subject, issuer, expiry, fingerprint, versions, JARM and JA3S, SSH fingerprint and HASSH,
//! device type, OS, cloud, each CVE with its CVSS score, the verified and known-exploited ones,
//! the highest score, and the first and newest banner times. Host names, banner names, TLS
//! subject names that are not addresses, the AS and the organisation are pivots, and so is the
//! position when Shodan names its city: a position with no city is a country's centre, which
//! would tie unrelated addresses together. When the whole answer is longer than the transport's
//! body limit, the lookup asks again with `minify=true`, which leaves the banners out, and says
//! so in `banners_omitted`. For a domain: the whole answer as JSON in `raw_answer`, every
//! subdomain, every record as `name TYPE value` (TXT and every other type), the newest
//! `last_seen`, and the addresses and names it resolves to as pivots.

use std::collections::HashSet;

use serde::Deserialize;
use serde_json::Value;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::canonical::canonical_coordinates;
use crate::http::Transport;
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, PivotKind, Source};
use crate::keys::Keys;
use crate::tags;

pub const SOURCE: &str = "shodan";
pub const KEY_SLOT: &str = crate::environment::SHODAN_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "shodan.io",
    origin: "https://api.shodan.io:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Query("key"),
        required: true,
    }),
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Ip, IndicatorKind::Domain],
    lookup,
};

/// Why an address's banners are missing when the lookup had to ask for the minified answer.
pub const BANNERS_OMITTED: &str =
    "Shodan's whole answer is longer than the body limit; asked again with minify=true";

#[derive(Deserialize)]
struct Host {
    ip_str: String,
    #[serde(default)]
    ports: Vec<u16>,
    #[serde(default)]
    hostnames: Vec<String>,
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    vulns: Vec<String>,
    org: Option<String>,
    isp: Option<String>,
    asn: Option<String>,
    os: Option<String>,
    country_code: Option<String>,
    country_name: Option<String>,
    city: Option<String>,
    last_update: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
}

#[derive(Deserialize)]
struct Dns {
    domain: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    subdomains: Vec<String>,
    #[serde(default)]
    data: Vec<Record>,
    #[serde(default)]
    more: bool,
}

#[derive(Deserialize)]
struct Record {
    #[serde(default)]
    subdomain: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    value: String,
    last_seen: Option<String>,
}

/// The request URL for `indicator`, `None` for a kind this source does not answer. **Pure.**
#[must_use]
pub fn url(indicator: Indicator<'_>) -> Option<String> {
    match indicator {
        Indicator::Ip(ip) => Some(format!("https://api.shodan.io/shodan/host/{ip}")),
        Indicator::Domain(domain) => Some(format!("https://api.shodan.io/dns/domain/{domain}")),
        Indicator::Email(_)
        | Indicator::Phone(_)
        | Indicator::Cell(_)
        | Indicator::MacAddress(_) => None,
    }
}

/// The URL of an address's answer without its banners. **Pure.**
#[must_use]
pub fn minified_url(ip: &str) -> String {
    format!("https://api.shodan.io/shodan/host/{ip}?minify=true")
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
    match (
        api_leg::get(transport, &API, keys, &url, now_unix),
        indicator,
    ) {
        (Err(LegError::TooLarge), Indicator::Ip(ip)) => {
            let answer = api_leg::get(transport, &API, keys, &minified_url(ip), now_unix)?;
            Ok(decode(answer, indicator)?.map(|f| f.attr("banners_omitted", BANNERS_OMITTED)))
        }
        (answer, _) => decode(answer?, indicator),
    }
}

/// One answer for `indicator`. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented shape or is about something else;
/// [`LegError::Unexpected`] for a `404` that is not Shodan's JSON "no information" answer.
pub fn decode(answer: Answer, indicator: Indicator<'_>) -> Result<Option<Finding>, LegError> {
    let body = match answer {
        Answer::NotFound(body) => {
            return match api_leg::decode::<NoInfo>(&body) {
                Ok(_) => Ok(None),
                Err(_) => Err(LegError::Unexpected(404)),
            };
        }
        Answer::Body(body) => body,
    };
    match indicator {
        Indicator::Ip(ip) => host(api_leg::decode(&body)?, ip).map(Some),
        Indicator::Domain(domain) => dns(&api_leg::decode(&body)?, domain),
        Indicator::Email(_)
        | Indicator::Phone(_)
        | Indicator::Cell(_)
        | Indicator::MacAddress(_) => Ok(None),
    }
}

/// Shodan's error body; on a `404` it says it holds nothing on the subject.
#[derive(Deserialize)]
struct NoInfo {
    #[serde(rename = "error")]
    _error: String,
}

/// The scalar at `pointer` in `value` as text, as [`api_leg::scalar`] reads it; `None` when
/// absent. **Pure.**
fn text(value: &Value, pointer: &str) -> Option<String> {
    value.pointer(pointer).and_then(api_leg::scalar)
}

/// Every string in the list at `pointer` in `value`. **Pure.**
fn texts<'a>(value: &'a Value, pointer: &str) -> impl Iterator<Item = &'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

/// The attributes read out of the banners, in the order they are written.
const BANNER_LISTS: [&str; 28] = [
    "services",
    "products",
    "cpes",
    "modules",
    "info",
    "device_types",
    "banner_os",
    "http_titles",
    "http_servers",
    "http_redirects",
    "http_components",
    "waf",
    "favicon_hashes",
    "tls_subjects",
    "tls_issuers",
    "tls_expires",
    "tls_fingerprints",
    "tls_versions",
    "jarm",
    "ja3s",
    "ssh_fingerprints",
    "hassh",
    "cloud_providers",
    "cloud_regions",
    "cloud_services",
    "cve_scores",
    "verified_vulns",
    "kev_vulns",
];

/// What every banner of an address says, across them all, each value once and none dropped.
#[derive(Default)]
struct Banners {
    lists: Vec<(&'static str, Vec<String>)>,
    seen: HashSet<(&'static str, String)>,
    names: Vec<String>,
    max_cvss: Option<(f64, String)>,
    first: Option<String>,
    newest: Option<String>,
}

impl Banners {
    fn read(banners: &[Value]) -> Self {
        let mut read = Self {
            lists: BANNER_LISTS.iter().map(|key| (*key, Vec::new())).collect(),
            ..Self::default()
        };
        for banner in banners {
            read.banner(banner);
        }
        read
    }

    fn add(&mut self, key: &'static str, value: Option<&str>) {
        let Some(value) = api_leg::clean(value) else {
            return;
        };
        if self.seen.insert((key, value.clone())) {
            if let Some((_, values)) = self.lists.iter_mut().find(|(k, _)| *k == key) {
                values.push(value);
            }
        }
    }

    fn add_text(&mut self, key: &'static str, banner: &Value, pointer: &str) {
        self.add(key, text(banner, pointer).as_deref());
    }

    fn banner(&mut self, banner: &Value) {
        self.service(banner);
        for (key, pointer) in [
            ("modules", "/_shodan/module"),
            ("info", "/info"),
            ("device_types", "/devicetype"),
            ("banner_os", "/os"),
            ("http_titles", "/http/title"),
            ("http_servers", "/http/server"),
            ("http_redirects", "/http/location"),
            ("waf", "/http/waf"),
            ("favicon_hashes", "/http/favicon/hash"),
            ("tls_subjects", "/ssl/cert/subject/CN"),
            ("tls_issuers", "/ssl/cert/issuer/O"),
            ("tls_issuers", "/ssl/cert/issuer/CN"),
            ("tls_expires", "/ssl/cert/expires"),
            ("tls_fingerprints", "/ssl/cert/fingerprint/sha256"),
            ("jarm", "/ssl/jarm"),
            ("ja3s", "/ssl/ja3s"),
            ("ssh_fingerprints", "/ssh/fingerprint"),
            ("hassh", "/ssh/hassh"),
            ("cloud_providers", "/cloud/provider"),
            ("cloud_regions", "/cloud/region"),
            ("cloud_services", "/cloud/service"),
        ] {
            self.add_text(key, banner, pointer);
        }
        for pointer in ["/cpe23", "/cpe"] {
            for cpe in texts(banner, pointer) {
                self.add("cpes", Some(cpe));
            }
        }
        for version in texts(banner, "/ssl/versions") {
            self.add("tls_versions", Some(version));
        }
        if let Some(components) = banner
            .pointer("/http/components")
            .and_then(Value::as_object)
        {
            for name in components.keys() {
                self.add("http_components", Some(name));
            }
        }
        if let Some(vulns) = banner.get("vulns").and_then(Value::as_object) {
            for (cve, detail) in vulns {
                self.vuln(cve, detail);
            }
        }
        for pointer in ["/hostnames", "/domains"] {
            self.names.extend(texts(banner, pointer).map(str::to_owned));
        }
        if let Some(subject) = banner
            .pointer("/ssl/cert/subject/CN")
            .and_then(Value::as_str)
        {
            let name = subject
                .trim()
                .trim_start_matches("*.")
                .trim_end_matches('.');
            // A certificate can name an address; that is not a host name to pivot on.
            if !name.is_empty() && name.parse::<std::net::IpAddr>().is_err() {
                self.names.push(name.to_owned());
            }
        }
        if let Some(time) = banner.get("timestamp").and_then(Value::as_str) {
            self.saw(time);
        }
    }

    /// `port/transport product version`, and the product with its version. **Pure.**
    fn service(&mut self, banner: &Value) {
        let product = text(banner, "/product");
        let version = text(banner, "/version");
        let software: Vec<&str> = [product.as_deref(), version.as_deref()]
            .into_iter()
            .flatten()
            .collect();
        let software = software.join(" ");
        if let Some(port) = banner.get("port").and_then(Value::as_u64) {
            let transport = banner
                .get("transport")
                .and_then(Value::as_str)
                .unwrap_or("tcp");
            let service = format!("{port}/{transport} {software}");
            self.add("services", Some(service.trim_end()));
        }
        self.add("products", Some(&software));
    }

    fn vuln(&mut self, cve: &str, detail: &Value) {
        let score = text(detail, "/cvss");
        let entry = score
            .as_deref()
            .map_or_else(|| cve.to_owned(), |score| format!("{cve} {score}"));
        self.add("cve_scores", Some(&entry));
        if detail.get("verified").and_then(Value::as_bool) == Some(true) {
            self.add("verified_vulns", Some(cve));
        }
        if detail.get("kev").and_then(Value::as_bool) == Some(true) {
            self.add("kev_vulns", Some(cve));
        }
        if let (Some(value), Some(score)) = (detail.get("cvss").and_then(Value::as_f64), score) {
            if self.max_cvss.as_ref().is_none_or(|(max, _)| value > *max) {
                self.max_cvss = Some((value, score));
            }
        }
    }

    /// Shodan writes every banner time in one ISO 8601 form, so the text orders as the time.
    fn saw(&mut self, time: &str) {
        if self.first.as_deref().is_none_or(|first| time < first) {
            self.first = Some(time.to_owned());
        }
        if self.newest.as_deref().is_none_or(|newest| time > newest) {
            self.newest = Some(time.to_owned());
        }
    }

    fn has_vulns(&self) -> bool {
        self.lists
            .iter()
            .any(|(key, values)| *key == "cve_scores" && !values.is_empty())
    }

    fn into_finding(self, mut finding: Finding) -> Finding {
        for (key, values) in &self.lists {
            finding = finding.list_attr(key, values);
        }
        finding = finding
            .opt_attr("max_cvss", self.max_cvss.map(|(_, score)| score))
            .opt_attr("first_banner", self.first)
            .opt_attr("newest_banner", self.newest);
        for name in &self.names {
            finding = finding.pivot(
                PivotKind::Domain,
                name,
                "Name a Shodan banner records for the address",
            );
        }
        finding
    }
}

/// The place Shodan gives for the address: attributes, and the position as a pivot when a city
/// is named. **Pure.**
fn place(mut finding: Finding, host: &Host, raw: &Value) -> Finding {
    let city = host.city.as_deref().filter(|c| !c.trim().is_empty());
    finding = finding
        .opt_attr("country", host.country_code.as_deref())
        .opt_attr("country_name", host.country_name.as_deref())
        .opt_attr("region", text(raw, "/region_code"))
        .opt_attr("city", city)
        .opt_attr("postal_code", text(raw, "/postal_code"))
        .opt_attr("area_code", text(raw, "/area_code"))
        .opt_attr("dma_code", text(raw, "/dma_code"));
    let position = host
        .latitude
        .zip(host.longitude)
        .and_then(|(lat, lon)| canonical_coordinates(&format!("{lat},{lon}")));
    if let Some(position) = position {
        finding = finding.attr("coordinates", &position);
        if city.is_some() {
            finding = finding.pivot(
                PivotKind::Coordinates,
                position,
                "Position Shodan gives for the address's city",
            );
        }
    }
    finding
}

fn host(mut raw: Value, ip: &str) -> Result<Finding, LegError> {
    let banners = match raw.as_object_mut().and_then(|o| o.remove("data")) {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(banners)) => banners,
        Some(_) => return Err(LegError::Decode("banners are not a list".into())),
    };
    let host: Host = api_leg::decode_value(&raw)?;
    if host.ip_str.parse::<std::net::IpAddr>().ok() != ip.parse().ok() {
        return Err(LegError::Decode("answer names another address".into()));
    }
    let mut ports = host.ports.clone();
    ports.sort_unstable();
    ports.dedup();
    let ports: Vec<String> = ports.iter().map(ToString::to_string).collect();
    let read = Banners::read(&banners);
    let mut finding = Finding::new(format!(
        "Shodan: {} open port(s){}",
        ports.len(),
        host.org
            .as_deref()
            .map_or_else(String::new, |org| format!(", {org}"))
    ))
    .list_attr("ports", &ports)
    .list_attr("shodan_tags", &host.tags)
    .list_attr("vulns", &host.vulns)
    .opt_attr("org", host.org.as_deref())
    .opt_attr("isp", host.isp.as_deref())
    .opt_attr("asn", host.asn.as_deref())
    .opt_attr("os", host.os.as_deref())
    .opt_attr("last_update", host.last_update.as_deref())
    .tag_if(!host.vulns.is_empty() || read.has_vulns(), tags::VULNERABLE)
    .tag_if(host.tags.iter().any(|t| t == "vpn"), "vpn")
    .tag_if(host.tags.iter().any(|t| t == "tor"), tags::TOR_EXIT);
    finding = place(finding, &host, &raw);
    for name in host.hostnames.iter().chain(&host.domains) {
        finding = finding.pivot(
            PivotKind::Domain,
            name,
            "Hostname Shodan records for the address",
        );
    }
    finding = read.into_finding(finding);
    if let Some(asn) = host.asn.as_deref() {
        finding = finding.pivot(PivotKind::Asn, asn, "AS Shodan records for the address");
    }
    if let Some(org) = host.org.as_deref() {
        finding = finding.pivot(
            PivotKind::Organisation,
            org,
            "Organisation Shodan records for the address",
        );
    }
    finding = finding.attr("raw_host", raw.to_string());
    if !banners.is_empty() {
        finding = finding.attr("raw_banners", Value::Array(banners).to_string());
    }
    Ok(finding)
}

fn dns(raw: &Value, domain: &str) -> Result<Option<Finding>, LegError> {
    let dns: Dns = api_leg::decode_value(raw)?;
    if !dns.domain.eq_ignore_ascii_case(domain) {
        return Err(LegError::Decode("answer names another domain".into()));
    }
    if dns.data.is_empty() && dns.subdomains.is_empty() {
        return Ok(None);
    }
    let subdomains: Vec<String> = dns
        .subdomains
        .iter()
        .map(|sub| format!("{sub}.{domain}"))
        .collect();
    let records: Vec<String> = dns
        .data
        .iter()
        .map(|r| {
            let name = if r.subdomain.is_empty() {
                domain.to_owned()
            } else {
                format!("{}.{domain}", r.subdomain)
            };
            format!("{name} {} {}", r.kind, r.value)
                .trim_end()
                .to_owned()
        })
        .collect();
    let newest = dns.data.iter().filter_map(|r| r.last_seen.as_deref()).max();
    let mut finding = Finding::new(format!(
        "Shodan DNS: {} subdomain(s), {} record(s)",
        dns.subdomains.len(),
        dns.data.len()
    ))
    .attr("subdomain_count", dns.subdomains.len().to_string())
    .attr("record_count", dns.data.len().to_string())
    .list_attr("subdomains", &subdomains)
    .list_attr("records", &records)
    .opt_attr("last_seen", newest)
    .list_attr("shodan_tags", &dns.tags)
    .tag_if(dns.more, "truncated");
    for sub in &subdomains {
        finding = finding.pivot(
            PivotKind::Domain,
            sub,
            "Subdomain Shodan DNS holds for the domain",
        );
    }
    for record in &dns.data {
        let kind = match record.kind.as_str() {
            "A" | "AAAA" => PivotKind::Ip,
            "CNAME" | "MX" | "NS" => PivotKind::Domain,
            _ => continue,
        };
        let summary = if record.subdomain.is_empty() {
            "Record Shodan DNS holds for the domain"
        } else {
            "Record Shodan DNS holds for a subdomain"
        };
        finding = finding.pivot(kind, &record.value, summary);
    }
    Ok(Some(finding.attr("raw_answer", raw.to_string())))
}

#[cfg(test)]
mod tests;
