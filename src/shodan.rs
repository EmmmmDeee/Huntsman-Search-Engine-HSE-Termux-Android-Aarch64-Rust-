//! Shodan: what Shodan's crawlers saw on one public IP, and the DNS records it holds for a domain.
//!
//! An IP is one `GET https://api.shodan.io/shodan/host/{ip}?minify=true` (free with any key, no
//! query credits). A domain is one `GET https://api.shodan.io/dns/domain/{domain}`, which spends
//! one query credit. Both run whenever `HUNTSMAN_SHODAN_KEY` is set; Shodan takes the key only as
//! the `key` query parameter, which [`crate::fetch`] adds as the request is sent. A `404` is
//! Shodan's "no information available", a valid zero.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::http::Transport;
use crate::indicator_sources::{Finding, Indicator, PivotKind, Source};
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
    ip: true,
    domain: true,
    lookup,
};

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
    city: Option<String>,
    last_update: Option<String>,
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
}

/// The request URL for `indicator`. **Pure.**
#[must_use]
pub fn url(indicator: Indicator<'_>) -> String {
    match indicator {
        Indicator::Ip(ip) => format!("https://api.shodan.io/shodan/host/{ip}?minify=true"),
        Indicator::Domain(domain) => format!("https://api.shodan.io/dns/domain/{domain}"),
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
    decode(
        api_leg::get(transport, &API, keys, &url(indicator), now_unix)?,
        indicator,
    )
}

/// One answer for `indicator`. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented shape or is about something else.
pub fn decode(answer: Answer, indicator: Indicator<'_>) -> Result<Option<Finding>, LegError> {
    let body = match answer {
        Answer::NotFound(_) => return Ok(None),
        Answer::Body(body) => body,
    };
    match indicator {
        Indicator::Ip(ip) => host(api_leg::decode(&body)?, ip).map(Some),
        Indicator::Domain(domain) => dns(&api_leg::decode(&body)?, domain),
    }
}

fn host(host: Host, ip: &str) -> Result<Finding, LegError> {
    if host.ip_str.parse::<std::net::IpAddr>().ok() != ip.parse().ok() {
        return Err(LegError::Decode("answer names another address".into()));
    }
    let mut ports = host.ports;
    ports.sort_unstable();
    ports.dedup();
    let ports: Vec<String> = ports.iter().map(ToString::to_string).collect();
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
    .opt_attr("country", host.country_code.as_deref())
    .opt_attr("city", host.city.as_deref())
    .opt_attr("last_update", host.last_update.as_deref())
    .tag_if(!host.vulns.is_empty(), tags::VULNERABLE)
    .tag_if(host.tags.iter().any(|t| t == "vpn"), "vpn")
    .tag_if(host.tags.iter().any(|t| t == "tor"), "tor-exit");
    for name in host.hostnames.iter().chain(&host.domains) {
        finding = finding.pivot(
            PivotKind::Domain,
            name,
            "Hostname Shodan records for the address",
        );
    }
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
    Ok(finding)
}

fn dns(dns: &Dns, domain: &str) -> Result<Option<Finding>, LegError> {
    if !dns.domain.eq_ignore_ascii_case(domain) {
        return Err(LegError::Decode("answer names another domain".into()));
    }
    if dns.data.is_empty() && dns.subdomains.is_empty() {
        return Ok(None);
    }
    let mut finding = Finding::new(format!(
        "Shodan DNS: {} subdomain(s), {} record(s)",
        dns.subdomains.len(),
        dns.data.len()
    ))
    .attr("subdomain_count", dns.subdomains.len().to_string())
    .attr("record_count", dns.data.len().to_string())
    .list_attr("shodan_tags", &dns.tags)
    .tag_if(dns.more, "truncated");
    for sub in &dns.subdomains {
        finding = finding.pivot(
            PivotKind::Domain,
            format!("{sub}.{domain}"),
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
    Ok(Some(finding))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded for `1.1.1.1` on 2026-10-14 (`minify=true`).
    const HOST: &str = r#"{"city": "Brisbane", "region_code": "QLD", "os": null, "tags": ["vpn"], "ip": 16843009, "isp": "Cloudflare, Inc.", "area_code": null, "longitude": 153.0175, "last_update": "2026-10-14T13:08:08.277809", "ports": [161, 2082, 80, 53, 443], "latitude": -27.48159, "hostnames": ["one.one.one.one", "wifi.sl.se"], "country_code": "AU", "country_name": "Australia", "domains": ["sl.se", "one.one"], "org": "APNIC Research and Development", "data": [], "asn": "AS13335", "ip_str": "1.1.1.1"}"#;
    /// Recorded for `example.com` on 2026-10-14 (records trimmed to eight).
    const DNS: &str = r#"{"domain":"example.com","tags":["dmarc","ipv6","spf"],"subdomains":["_dmarc","k2._domainkey","www"],"data":[{"subdomain":"","type":"A","options":{"ttl":300},"value":"104.20.23.154","last_seen":"2026-10-14T09:39:50.360000"},{"subdomain":"","type":"A","options":{"ttl":300},"value":"172.66.147.243","last_seen":"2026-10-14T09:39:50.360000"},{"subdomain":"","type":"AAAA","options":{"ttl":300},"value":"2606:4700:10::6814:179a","last_seen":"2026-10-14T09:37:37.893000"},{"subdomain":"","type":"MX","options":{"priority":0,"ttl":300},"value":"","last_seen":"2026-10-14T07:09:08.020000"},{"subdomain":"","type":"NS","options":{"ttl":84887},"value":"elliott.ns.cloudflare.com","last_seen":"2026-10-13T22:12:02.444000"},{"subdomain":"","type":"TXT","options":{"ttl":300},"value":"_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9","last_seen":"2026-10-14T07:03:17.936000"}],"more":false}"#;
    /// Shodan's documented answer for an address it has nothing on (HTTP 404).
    const NO_INFO: &str = r#"{"error": "No information available for that IP."}"#;

    #[test]
    fn a_recorded_host_gives_ports_org_and_pivots() {
        let finding = decode(Answer::Body(HOST.into()), Indicator::Ip("1.1.1.1"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded host must decode"));
        assert!(finding.summary.contains("5 open port(s)"));
        assert!(
            finding
                .attrs
                .contains(&("ports", "53,80,161,443,2082".into()))
        );
        assert!(finding.attrs.contains(&("asn", "AS13335".into())));
        assert_eq!(finding.tags, ["vpn"]);
        let domains: Vec<&str> = finding
            .pivots
            .iter()
            .filter(|p| p.kind == PivotKind::Domain)
            .map(|p| p.value.as_str())
            .collect();
        assert_eq!(
            domains,
            ["one.one.one.one", "wifi.sl.se", "sl.se", "one.one"]
        );
        assert!(finding.pivots.iter().any(|p| p.kind == PivotKind::Asn));
    }

    #[test]
    fn a_recorded_dns_answer_gives_subdomains_and_record_targets() {
        let finding = decode(Answer::Body(DNS.into()), Indicator::Domain("example.com"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded dns must decode"));
        let pivots: Vec<(PivotKind, &str)> = finding
            .pivots
            .iter()
            .map(|p| (p.kind, p.value.as_str()))
            .collect();
        assert!(pivots.contains(&(PivotKind::Domain, "www.example.com")));
        assert!(pivots.contains(&(PivotKind::Ip, "104.20.23.154")));
        assert!(pivots.contains(&(PivotKind::Ip, "2606:4700:10::6814:179a")));
        assert!(pivots.contains(&(PivotKind::Domain, "elliott.ns.cloudflare.com")));
        assert!(
            !pivots.iter().any(|(_, v)| v.starts_with("_k2n1")),
            "TXT is not a pivot"
        );
    }

    #[test]
    fn a_404_is_nothing_known_and_another_subject_is_refused() {
        assert_eq!(
            decode(
                Answer::NotFound(NO_INFO.into()),
                Indicator::Ip("203.0.113.9")
            ),
            Ok(None)
        );
        assert!(decode(Answer::Body(HOST.into()), Indicator::Ip("8.8.8.8")).is_err());
        assert!(decode(Answer::Body(DNS.into()), Indicator::Domain("example.org")).is_err());
    }

    #[test]
    fn the_url_never_holds_the_key() {
        assert_eq!(
            url(Indicator::Ip("1.1.1.1")),
            "https://api.shodan.io/shodan/host/1.1.1.1?minify=true"
        );
        assert_eq!(
            url(Indicator::Domain("example.com")),
            "https://api.shodan.io/dns/domain/example.com"
        );
    }
}
