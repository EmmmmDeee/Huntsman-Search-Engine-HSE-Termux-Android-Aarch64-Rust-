//! Netlas: what Netlas's internet scans hold for one IP or domain.
//!
//! One lookup is one `GET https://app.netlas.io/api/host/{indicator}/`, for a domain or an IPv4
//! address: given an IPv6 address the endpoint answers about netlas.io itself. Netlas answers without a
//! key at a low daily limit; with `HUNTSMAN_NETLAS_KEY` set (a free Community key) the key goes in
//! the `X-API-Key` header and the limit is the account's. An address gives open ports, software,
//! reverse DNS, domains seen on it, privacy flags (VPN, proxy, Tor), IOC listings and the WHOIS
//! AS and network; a domain gives its DNS records, ports, software, IOC listings and subdomains.
//! WHOIS contact phones and postal addresses are not decoded.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::http::Transport;
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, PivotKind, Source};
use crate::keys::Keys;

pub const SOURCE: &str = "netlas";
pub const KEY_SLOT: &str = crate::environment::NETLAS_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "netlas.io",
    origin: "https://app.netlas.io:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Header("X-API-Key"),
        required: false,
    }),
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Ipv4, IndicatorKind::Domain],
    lookup,
};
/// Most distinct names kept in one attribute.
const MAX_NAMES: usize = 15;

#[derive(Deserialize)]
struct Body {
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    ports: Vec<Port>,
    #[serde(default)]
    software: Vec<Software>,
    #[serde(default)]
    ptr: Vec<String>,
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    domains_count: Option<u64>,
    #[serde(default)]
    privacy: Option<Privacy>,
    #[serde(default)]
    ioc: Vec<Ioc>,
    #[serde(default)]
    whois: Option<Whois>,
    #[serde(default)]
    dns: Option<Dns>,
    #[serde(default)]
    related_domains: Vec<String>,
    #[serde(default)]
    related_domains_count: Option<u64>,
}

#[derive(Deserialize)]
struct Port {
    port: u16,
    #[serde(default)]
    protocol: Option<String>,
}

#[derive(Deserialize)]
struct Software {
    #[serde(default)]
    tag: Vec<Tag>,
}

#[derive(Deserialize)]
struct Tag {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    fullname: Option<String>,
}

#[derive(Deserialize, Default)]
struct Privacy {
    #[serde(default)]
    is_vpn: bool,
    #[serde(default)]
    is_proxy: bool,
    #[serde(default)]
    is_tor: bool,
}

#[derive(Deserialize)]
struct Ioc {
    #[serde(default)]
    threat: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    lseen: Option<String>,
}

#[derive(Deserialize)]
struct Whois {
    #[serde(default)]
    asn: Option<WhoisAsn>,
    #[serde(default)]
    net: Option<WhoisNet>,
}

#[derive(Deserialize)]
struct WhoisAsn {
    #[serde(default)]
    number: Vec<String>,
    #[serde(default)]
    name: Option<String>,
}

/// Only the network's name, range and country: contact phones and addresses are not decoded.
#[derive(Deserialize)]
struct WhoisNet {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    range: Option<String>,
    #[serde(default)]
    country: Option<String>,
}

#[derive(Deserialize, Default)]
struct Dns {
    #[serde(default)]
    a: Vec<String>,
    #[serde(default)]
    aaaa: Vec<String>,
    #[serde(default)]
    mx: Vec<String>,
    #[serde(default)]
    ns: Vec<String>,
}

/// The request URL for `indicator`. **Pure.**
#[must_use]
pub fn url(indicator: Indicator<'_>) -> String {
    format!("https://app.netlas.io/api/host/{}/", indicator.value())
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

fn distinct(values: impl Iterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for value in values {
        if !out.contains(&value) && out.len() < MAX_NAMES {
            out.push(value);
        }
    }
    out
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
    let mut body: Body = api_leg::decode(&body)?;
    if !is_about(&body, indicator) {
        return Err(LegError::Decode("answer names another indicator".into()));
    }
    let mut ports: Vec<u16> = body.ports.iter().map(|p| p.port).collect();
    ports.sort_unstable();
    ports.dedup();
    let ports: Vec<String> = ports.iter().map(ToString::to_string).collect();
    let protocols = distinct(
        body.ports
            .iter()
            .filter_map(|p| api_leg::clean(p.protocol.as_deref())),
    );
    let software = distinct(
        body.software
            .iter()
            .flat_map(|s| &s.tag)
            .filter_map(|t| api_leg::clean(t.fullname.as_deref().or(t.name.as_deref()))),
    );
    let threats = distinct(
        body.ioc
            .iter()
            .flat_map(|i| &i.threat)
            .filter_map(|t| api_leg::clean(Some(t))),
    );
    let ioc_tags = distinct(
        body.ioc
            .iter()
            .flat_map(|i| &i.tags)
            .filter_map(|t| api_leg::clean(Some(t))),
    );
    let ioc_last = body.ioc.iter().filter_map(|i| i.lseen.as_deref()).max();
    let privacy = body.privacy.take().unwrap_or_default();
    let dns = body.dns.take().unwrap_or_default();
    let mut finding = Finding::new(format!(
        "Netlas: {} open port(s), {} IOC listing(s)",
        ports.len(),
        body.ioc.len()
    ))
    .list_attr("ports", &ports)
    .list_attr("protocols", &protocols)
    .list_attr("software", &software)
    .list_attr("ioc_threats", &threats)
    .list_attr("ioc_tags", &ioc_tags)
    .opt_attr("ioc_last_seen", ioc_last)
    .opt_attr("domains_seen", body.domains_count.map(|c| c.to_string()))
    .opt_attr(
        "subdomains_seen",
        body.related_domains_count.map(|c| c.to_string()),
    )
    .tag_if(!body.ioc.is_empty(), "suspicious")
    .tag_if(privacy.is_vpn, "vpn")
    .tag_if(privacy.is_proxy, "proxy")
    .tag_if(privacy.is_tor, "tor-exit");
    if let Some(whois) = body.whois.take() {
        if let Some(net) = whois.net {
            finding = finding
                .opt_attr("network", net.name.as_deref())
                .opt_attr("range", net.range.as_deref())
                .opt_attr("country", net.country.as_deref());
        }
        if let Some(asn) = whois.asn {
            for number in &asn.number {
                finding = finding.pivot(
                    PivotKind::Asn,
                    number,
                    "AS Netlas WHOIS gives for the address",
                );
            }
            if let Some(name) = asn.name.as_deref() {
                finding = finding.attr("as_name", name).pivot(
                    PivotKind::Organisation,
                    name,
                    "Holder of the address's AS in Netlas WHOIS",
                );
            }
        }
    }
    Ok(Some(record_pivots(finding, &body, &dns)))
}

/// Whether `body` is Netlas's answer for `indicator`. **Pure.**
fn is_about(body: &Body, indicator: Indicator<'_>) -> bool {
    match indicator {
        Indicator::Ip(ip) => body
            .ip
            .as_deref()
            .is_some_and(|s| s.parse::<std::net::IpAddr>().ok() == ip.parse().ok()),
        Indicator::Domain(domain) => body
            .domain
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case(domain)),
        Indicator::Email(_) | Indicator::Phone(_) => false,
    }
}

/// `finding` with the names and addresses Netlas records for the indicator. **Pure.**
fn record_pivots(mut finding: Finding, body: &Body, dns: &Dns) -> Finding {
    for name in &body.ptr {
        finding = finding.pivot(
            PivotKind::Domain,
            name,
            "Reverse DNS name Netlas records for the address",
        );
    }
    for name in body.domains.iter().chain(&body.related_domains) {
        finding = finding.pivot(
            PivotKind::Domain,
            name,
            "Domain Netlas saw on the indicator",
        );
    }
    for ip in dns.a.iter().chain(&dns.aaaa) {
        finding = finding.pivot(
            PivotKind::Ip,
            ip,
            "Address in the domain's DNS records (Netlas)",
        );
    }
    for host in dns.ns.iter().chain(&dns.mx) {
        let host = host.split_whitespace().last().unwrap_or(host);
        finding = finding.pivot(
            PivotKind::Domain,
            host,
            "Name or mail server in the domain's DNS records (Netlas)",
        );
    }
    finding
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded without a key for `1.1.1.1` on 2026-10-14 (lists trimmed, WHOIS raw text dropped).
    const IP: &str = r#"{"ip":"1.1.1.1","type":"ip","ports":[{"protocol":"https","prot4":"tcp","port":2096,"prot7":"http"},{"protocol":"http","prot4":"tcp","port":2095,"prot7":"http"},{"protocol":"https","prot4":"tcp","port":443,"prot7":"http"}],"ptr":["one.one.one.one"],"domains":["mail.ex36524.com","www.fifty2collective.com"],"domains_count":39071,"privacy":{"is_vpn":false,"is_proxy":false,"is_tor":false},"organization":"ORG-ARAD1-AP","geo":{"is_anycast":true,"ip":"1.1.1.0/24","registered_country":"AU"},"software":[{"tag":[{"name":"cloudflare","fullname":"Cloudflare","category":["CDN"]}],"uri":"http://1.1.1.1:80/"}],"ioc":[{"lseen":"2024-12-12T00:00Z","fseen":"2024-12-12T00:00Z","domain":"1.1.1.1","threat":["iocontrol"],"tags":["c2"],"score":{"total":56.0}}],"whois":{"asn":{"number":["13335"],"registry":"apnic","country":"AU","name":"CLOUDFLARENET - Cloudflare","cidr":"1.1.1.0/24"},"net":{"country":"AU","name":"APNIC-LABS","organization":"ORG-ARAD1-AP","range":"1.1.1.0 - 1.1.1.255","contacts":{"phones":["+61-7-38583100"]},"address":"PO Box 3646"},"abuse":"helpdesk@apnic.net"}}"#;
    /// Recorded without a key for `example.com` on 2026-10-14 (lists trimmed).
    const DOMAIN: &str = r#"{"domain":"example.com","type":"domain","ports":[{"protocol":"http","prot4":"tcp","port":80,"prot7":"http"},{"prot4":"tcp","protocol":"https","port":443,"prot7":"http"}],"dns":{"a":["172.66.147.243","104.20.23.154"],"aaaa":["2606:4700:10::6814:179a"],"ns":["elliott.ns.cloudflare.com","hera.ns.cloudflare.com"],"txt":["v=spf1 -all"]},"related_domains":["sqlsiak.example.com","gec.example.com"],"related_domains_count":96289,"ioc":[]}"#;

    fn finding(body: &str, indicator: Indicator<'_>) -> Finding {
        decode(Answer::Body(body.into()), indicator)
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"))
    }

    #[test]
    fn a_recorded_address_keeps_ports_ioc_and_as_but_no_contacts() {
        let f = finding(IP, Indicator::Ip("1.1.1.1"));
        assert_eq!(f.summary, "Netlas: 3 open port(s), 1 IOC listing(s)");
        assert!(f.attrs.contains(&("ports", "443,2095,2096".into())));
        assert!(f.attrs.contains(&("ioc_tags", "c2".into())));
        assert!(f.attrs.contains(&("domains_seen", "39071".into())));
        assert_eq!(f.tags, ["suspicious"]);
        let text = format!("{f:?}");
        assert!(
            !text.contains("38583100") && !text.contains("PO Box"),
            "{text}"
        );
        assert!(
            f.pivots
                .iter()
                .any(|p| p.kind == PivotKind::Asn && p.value == "13335")
        );
        assert!(f.pivots.iter().any(|p| p.value == "one.one.one.one"));
    }

    #[test]
    fn a_recorded_domain_gives_records_and_subdomains() {
        let f = finding(DOMAIN, Indicator::Domain("example.com"));
        let pivots: Vec<(PivotKind, &str)> = f
            .pivots
            .iter()
            .map(|p| (p.kind, p.value.as_str()))
            .collect();
        assert!(pivots.contains(&(PivotKind::Ip, "104.20.23.154")));
        assert!(pivots.contains(&(PivotKind::Domain, "hera.ns.cloudflare.com")));
        assert!(pivots.contains(&(PivotKind::Domain, "gec.example.com")));
        assert!(f.tags.is_empty());
    }

    #[test]
    fn another_subject_is_refused_and_404_is_a_zero() {
        assert!(decode(Answer::Body(IP.into()), Indicator::Ip("8.8.8.8")).is_err());
        assert!(decode(Answer::Body(DOMAIN.into()), Indicator::Ip("1.1.1.1")).is_err());
        assert_eq!(
            decode(Answer::NotFound(Vec::new()), Indicator::Ip("1.1.1.1")),
            Ok(None)
        );
    }
}
