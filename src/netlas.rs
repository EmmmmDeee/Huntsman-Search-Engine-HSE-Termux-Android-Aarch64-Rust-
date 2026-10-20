//! Netlas: what Netlas's internet scans hold for one IP or domain.
//!
//! One lookup is one `GET https://app.netlas.io/api/host/{indicator}/`, for a domain or an IPv4
//! address: given an IPv6 address the endpoint answers about netlas.io itself. Netlas answers without a
//! key at a low daily limit; with `HUNTSMAN_NETLAS_KEY` set (a free Community key) the key goes in
//! the `X-API-Key` header and the limit is the account's. Netlas answers a domain it has never
//! scanned with `200` and only the name, a valid zero, and gives a `404` only for a path it does
//! not have (both checked 2026-10-15): a `404` is not an answer.
//!
//! Everything in the answer is kept: the whole answer as JSON in `raw_answer`, WHOIS text and
//! scan sources included. Read out of it: for an address, open ports and their services,
//! software with its categories and URIs, reverse DNS, domains seen on it, privacy flags (VPN,
//! proxy, Tor), anycast, the organisation, IOC listings (threats, tags, URLs, first and last
//! sighting, highest score, notes) and the WHOIS AS, network and its contacts; for a domain, its
//! DNS records (TXT included), ports, software, IOC listings, subdomains, and the WHOIS
//! registrar, dates, status and registrant organisation, country and email.

use serde::Deserialize;
use serde_json::Value;

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
    whois: Option<Value>,
    #[serde(default)]
    dns: Option<Dns>,
    #[serde(default)]
    related_domains: Vec<String>,
    #[serde(default)]
    related_domains_count: Option<u64>,
}

#[derive(Deserialize)]
struct Port {
    #[serde(rename = "port")]
    number: u16,
    #[serde(default)]
    protocol: Option<String>,
    /// `tcp` or `udp`.
    #[serde(default, rename = "prot4")]
    transport: Option<String>,
}

#[derive(Deserialize)]
struct Software {
    #[serde(default)]
    tag: Vec<Tag>,
    #[serde(default)]
    uri: Option<String>,
}

#[derive(Deserialize)]
struct Tag {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    fullname: Option<String>,
    #[serde(default)]
    category: Option<Vec<String>>,
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
    #[serde(default)]
    fseen: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    score: Option<IocScore>,
    #[serde(default)]
    fp: Option<IocNote>,
}

#[derive(Deserialize)]
struct IocScore {
    #[serde(default)]
    total: Option<f64>,
}

#[derive(Deserialize)]
struct IocNote {
    #[serde(default)]
    descr: Option<String>,
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
    #[serde(default)]
    txt: Vec<String>,
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

/// Cleaned values in the order first seen, each once. **Pure.**
fn distinct<'a>(values: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    values
        .into_iter()
        .filter_map(|v| api_leg::clean(Some(v)))
        .filter(|v| seen.insert(v.clone()))
        .collect()
}

/// The text at `pointer` in `value`, its lines and runs of spaces joined by one space (the raw
/// answer keeps the layout). A number or boolean is written as text. **Pure.**
fn text(value: &Value, pointer: &str) -> Option<String> {
    let raw = match value.pointer(pointer)? {
        Value::String(s) => s.clone(),
        v @ (Value::Number(_) | Value::Bool(_)) => v.to_string(),
        _ => return None,
    };
    let joined = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    (!joined.is_empty()).then_some(joined)
}

/// The texts at `pointer` in `value`: a list of them, or one. **Pure.**
fn texts<'a>(value: &'a Value, pointer: &str) -> Vec<&'a str> {
    match value.pointer(pointer) {
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
        Some(Value::String(s)) => vec![s.as_str()],
        _ => Vec::new(),
    }
}

/// One answer for `indicator`. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented shape or is about something else.
pub fn decode(answer: Answer, indicator: Indicator<'_>) -> Result<Option<Finding>, LegError> {
    let body = match answer {
        Answer::NotFound(_) => return Err(LegError::Unexpected(404)),
        Answer::Body(body) => body,
    };
    let raw: Value = api_leg::decode(&body)?;
    let mut body = Body::deserialize(&raw)
        .map_err(|e| LegError::Decode(format!("unexpected response shape: {e}")))?;
    if !is_about(&body, indicator) {
        return Err(LegError::Decode("answer names another indicator".into()));
    }
    if holds_nothing(&body, &raw) {
        return Ok(None);
    }
    let mut ports: Vec<u16> = body.ports.iter().map(|p| p.number).collect();
    ports.sort_unstable();
    ports.dedup();
    let ports: Vec<String> = ports.iter().map(ToString::to_string).collect();
    let privacy = body.privacy.take().unwrap_or_default();
    let dns = body.dns.take().unwrap_or_default();
    let anycast = raw.pointer("/geo/is_anycast") == Some(&Value::Bool(true));
    let mut finding = Finding::new(format!(
        "Netlas: {} open port(s), {} IOC listing(s)",
        ports.len(),
        body.ioc.len()
    ))
    .list_attr("ports", &ports)
    .opt_attr("organization", text(&raw, "/organization"))
    .opt_attr("geo_prefix", text(&raw, "/geo/ip"))
    .opt_attr("registered_country", text(&raw, "/geo/registered_country"))
    .list_attr("dns_txt", &distinct(dns.txt.iter().map(String::as_str)))
    .opt_attr("domains_seen", body.domains_count.map(|c| c.to_string()))
    .opt_attr(
        "subdomains_seen",
        body.related_domains_count.map(|c| c.to_string()),
    )
    .tag_if(!body.ioc.is_empty(), "suspicious")
    .tag_if(privacy.is_vpn, "vpn")
    .tag_if(privacy.is_proxy, "proxy")
    .tag_if(privacy.is_tor, "tor-exit")
    .tag_if(anycast, "anycast");
    finding = services(finding, &body);
    finding = listings(finding, &body.ioc);
    if let Some(whois) = body.whois.take() {
        finding = network_whois(finding, &whois);
        finding = domain_whois(finding, &whois);
    }
    finding = record_pivots(finding, &body, &dns);
    Ok(Some(finding.attr("raw_answer", raw.to_string())))
}

/// The ports' services and the software Netlas fingerprinted. **Pure.**
fn services(finding: Finding, body: &Body) -> Finding {
    let protocols = distinct(body.ports.iter().filter_map(|p| p.protocol.as_deref()));
    let port_services: Vec<String> = body
        .ports
        .iter()
        .map(|p| {
            format!(
                "{}/{}/{}",
                p.number,
                p.transport.as_deref().unwrap_or("?"),
                p.protocol.as_deref().unwrap_or("?")
            )
        })
        .collect();
    let tags = || body.software.iter().flat_map(|s| &s.tag);
    let software = distinct(tags().filter_map(|t| t.fullname.as_deref().or(t.name.as_deref())));
    let categories = distinct(
        tags()
            .flat_map(|t| t.category.iter().flatten())
            .map(String::as_str),
    );
    let uris = distinct(body.software.iter().filter_map(|s| s.uri.as_deref()));
    finding
        .list_attr("protocols", &protocols)
        .list_attr(
            "port_services",
            &distinct(port_services.iter().map(String::as_str)),
        )
        .list_attr("software", &software)
        .list_attr("software_categories", &categories)
        .list_attr("software_uris", &uris)
}

/// Everything the IOC listings say, across them all. **Pure.**
fn listings(finding: Finding, ioc: &[Ioc]) -> Finding {
    let threats = distinct(ioc.iter().flat_map(|i| &i.threat).map(String::as_str));
    let tags = distinct(ioc.iter().flat_map(|i| &i.tags).map(String::as_str));
    let urls = distinct(ioc.iter().filter_map(|i| i.url.as_deref()));
    let notes = distinct(
        ioc.iter()
            .filter_map(|i| i.fp.as_ref().and_then(|n| n.descr.as_deref())),
    );
    let first = ioc.iter().filter_map(|i| i.fseen.as_deref()).min();
    let last = ioc.iter().filter_map(|i| i.lseen.as_deref()).max();
    let best = ioc
        .iter()
        .filter_map(|i| i.score.as_ref().and_then(|s| s.total))
        .reduce(f64::max);
    finding
        .list_attr("ioc_threats", &threats)
        .list_attr("ioc_tags", &tags)
        .list_attr("ioc_urls", &urls)
        .list_attr("ioc_notes", &notes)
        .opt_attr("ioc_first_seen", first)
        .opt_attr("ioc_last_seen", last)
        .opt_attr("ioc_max_score", best.map(|s| s.to_string()))
}

/// The WHOIS AS and network of an address, with the network's contacts. **Pure.**
fn network_whois(mut finding: Finding, whois: &Value) -> Finding {
    finding = finding
        .opt_attr("abuse_email", text(whois, "/abuse"))
        .opt_attr("network", text(whois, "/net/name"))
        .opt_attr("range", text(whois, "/net/range"))
        .opt_attr("country", text(whois, "/net/country"))
        .opt_attr("net_organization", text(whois, "/net/organization"))
        .opt_attr("net_handle", text(whois, "/net/handle"))
        .opt_attr("net_description", text(whois, "/net/description"))
        .opt_attr("net_address", text(whois, "/net/address"))
        .list_attr("net_cidr", &distinct(texts(whois, "/net/cidr")))
        .list_attr(
            "net_emails",
            &distinct(texts(whois, "/net/contacts/emails")),
        )
        .list_attr(
            "net_phones",
            &distinct(texts(whois, "/net/contacts/phones")),
        )
        .opt_attr("net_updated", text(whois, "/net/updated"))
        .opt_attr("as_registry", text(whois, "/asn/registry"))
        .opt_attr("as_country", text(whois, "/asn/country"))
        .list_attr("as_cidr", &distinct(texts(whois, "/asn/cidr")));
    for number in texts(whois, "/asn/number") {
        finding = finding.pivot(
            PivotKind::Asn,
            number,
            "AS Netlas WHOIS gives for the address",
        );
    }
    if let Some(name) = text(whois, "/asn/name") {
        finding = finding.attr("as_name", &name).pivot(
            PivotKind::Organisation,
            name,
            "Holder of the address's AS in Netlas WHOIS",
        );
    }
    finding
}

/// The WHOIS registration of a domain. **Pure.**
fn domain_whois(finding: Finding, whois: &Value) -> Finding {
    finding
        .opt_attr("registrar", text(whois, "/registrar/name"))
        .opt_attr("registrar_email", text(whois, "/registrar/email"))
        .opt_attr("registrar_url", text(whois, "/registrar/referral_url"))
        .opt_attr("created", text(whois, "/created_date"))
        .opt_attr("updated", text(whois, "/updated_date"))
        .opt_attr("expires", text(whois, "/expiration_date"))
        .list_attr("domain_status", &distinct(texts(whois, "/status")))
        .list_attr(
            "whois_name_servers",
            &distinct(texts(whois, "/name_servers")),
        )
        .opt_attr(
            "registrant_organization",
            text(whois, "/registrant/organization"),
        )
        .opt_attr("registrant_country", text(whois, "/registrant/country"))
        .opt_attr("registrant_email", text(whois, "/registrant/email"))
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
        Indicator::Email(_)
        | Indicator::Phone(_)
        | Indicator::Cell(_)
        | Indicator::MacAddress(_) => false,
    }
}

/// Whether an answer about the indicator holds nothing to report: no port, software, name,
/// listing, WHOIS, DNS record, organisation or privacy flag. **Pure.**
fn holds_nothing(body: &Body, raw: &Value) -> bool {
    let no_dns = body.dns.as_ref().is_none_or(|d| {
        d.a.is_empty()
            && d.aaaa.is_empty()
            && d.mx.is_empty()
            && d.ns.is_empty()
            && d.txt.is_empty()
    });
    let no_whois = body
        .whois
        .as_ref()
        .is_none_or(|w| w.as_object().is_none_or(serde_json::Map::is_empty));
    let no_flag = body
        .privacy
        .as_ref()
        .is_none_or(|p| !(p.is_vpn || p.is_proxy || p.is_tor));
    body.ports.is_empty()
        && body.software.is_empty()
        && body.ptr.is_empty()
        && body.domains.is_empty()
        && body.domains_count.unwrap_or(0) == 0
        && body.ioc.is_empty()
        && body.related_domains.is_empty()
        && body.related_domains_count.unwrap_or(0) == 0
        && raw.get("organization").is_none_or(Value::is_null)
        && no_dns
        && no_whois
        && no_flag
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

    /// Recorded without a key for `1.1.1.1` on 2026-10-14 (lists trimmed, WHOIS raw text left out).
    const IP: &str = r#"{"ip":"1.1.1.1","type":"ip","ports":[{"protocol":"https","prot4":"tcp","port":2096,"prot7":"http"},{"protocol":"http","prot4":"tcp","port":2095,"prot7":"http"},{"protocol":"https","prot4":"tcp","port":443,"prot7":"http"}],"ptr":["one.one.one.one"],"domains":["mail.ex36524.com","www.fifty2collective.com"],"domains_count":39071,"privacy":{"is_vpn":false,"is_proxy":false,"is_tor":false},"organization":"ORG-ARAD1-AP","geo":{"is_anycast":true,"ip":"1.1.1.0/24","registered_country":"AU"},"software":[{"tag":[{"name":"cloudflare","fullname":"Cloudflare","category":["CDN"]}],"uri":"http://1.1.1.1:80/"}],"ioc":[{"lseen":"2024-12-12T00:00Z","fseen":"2024-12-12T00:00Z","domain":"1.1.1.1","threat":["iocontrol"],"tags":["c2"],"score":{"total":56.0}}],"whois":{"asn":{"number":["13335"],"registry":"apnic","country":"AU","name":"CLOUDFLARENET - Cloudflare","cidr":"1.1.1.0/24"},"net":{"country":"AU","name":"APNIC-LABS","organization":"ORG-ARAD1-AP","range":"1.1.1.0 - 1.1.1.255","contacts":{"phones":["+61-7-38583100"]},"address":"PO Box 3646"},"abuse":"helpdesk@apnic.net"}}"#;
    /// Recorded without a key for `example.com` on 2026-10-14 (lists trimmed).
    const DOMAIN: &str = r#"{"domain":"example.com","type":"domain","ports":[{"protocol":"http","prot4":"tcp","port":80,"prot7":"http"},{"prot4":"tcp","protocol":"https","port":443,"prot7":"http"}],"dns":{"a":["172.66.147.243","104.20.23.154"],"aaaa":["2606:4700:10::6814:179a"],"ns":["elliott.ns.cloudflare.com","hera.ns.cloudflare.com"],"txt":["v=spf1 -all"]},"related_domains":["sqlsiak.example.com","gec.example.com"],"related_domains_count":96289,"ioc":[]}"#;

    fn finding(body: &str, indicator: Indicator<'_>) -> Finding {
        decode(Answer::Body(body.into()), indicator)
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"))
    }

    fn value<'a>(f: &'a Finding, key: &str) -> Option<&'a str> {
        f.attrs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn a_recorded_address_keeps_ports_ioc_as_network_and_contacts() {
        let f = finding(IP, Indicator::Ip("1.1.1.1"));
        assert_eq!(f.summary, "Netlas: 3 open port(s), 1 IOC listing(s)");
        for (key, expected) in [
            ("ports", "443,2095,2096"),
            (
                "port_services",
                "2096/tcp/https,2095/tcp/http,443/tcp/https",
            ),
            ("software", "Cloudflare"),
            ("software_categories", "CDN"),
            ("software_uris", "http://1.1.1.1:80/"),
            ("ioc_threats", "iocontrol"),
            ("ioc_tags", "c2"),
            ("ioc_first_seen", "2024-12-12T00:00Z"),
            ("ioc_max_score", "56"),
            ("domains_seen", "39071"),
            ("organization", "ORG-ARAD1-AP"),
            ("geo_prefix", "1.1.1.0/24"),
            ("registered_country", "AU"),
            ("abuse_email", "helpdesk@apnic.net"),
            ("network", "APNIC-LABS"),
            ("net_organization", "ORG-ARAD1-AP"),
            ("net_address", "PO Box 3646"),
            ("net_phones", "+61-7-38583100"),
            ("as_registry", "apnic"),
            ("as_country", "AU"),
            ("as_cidr", "1.1.1.0/24"),
            ("as_name", "CLOUDFLARENET - Cloudflare"),
        ] {
            assert_eq!(value(&f, key), Some(expected), "{key}: {:?}", f.attrs);
        }
        assert_eq!(f.tags, ["suspicious", "anycast"]);
        assert!(
            f.pivots
                .iter()
                .any(|p| p.kind == PivotKind::Asn && p.value == "13335")
        );
        assert!(f.pivots.iter().any(|p| p.value == "one.one.one.one"));
    }

    #[test]
    fn the_whole_answer_is_kept_raw() {
        let f = finding(IP, Indicator::Ip("1.1.1.1"));
        let raw: Value =
            serde_json::from_str(value(&f, "raw_answer").unwrap_or_default()).unwrap_or_default();
        assert_eq!(
            raw["whois"]["net"]["contacts"]["phones"][0],
            "+61-7-38583100"
        );
        assert_eq!(raw["software"][0]["tag"][0]["category"][0], "CDN");
        assert_eq!(raw["ioc"][0]["score"]["total"], 56.0);
    }

    #[test]
    fn a_domain_whois_keeps_its_registration() {
        // Recorded without a key for `netlas.io` on 2026-10-15 (WHOIS only, statistics left out).
        let body = r#"{"domain":"netlas.io","type":"domain","whois":{"server":"whois.namecheap.com","extension":"io","last_updated":"2024-06-28T17:04:24.429Z","registrar":{"phone":"+1.9854014545","referral_url":"http://www.namecheap.com","name":"NAMECHEAP INC","id":"1068","email":"abuse@namecheap.com"},"whois_server":"whois.namecheap.com","level":2,"name_servers":["pdns1.registrar-servers.com","pdns2.registrar-servers.com"],"expiration_date":"2026-11-06T08:10:14.820Z","zone":"io","domain":"netlas.io","updated_date":"2022-09-28T09:38:39.210Z","created_date":"2020-11-06T08:10:14.820Z","registrant":{"country":"IS","province":"Capital Region","city":"Reykjavik","organization":"Privacy service provided by Withheld for Privacy ehf","name":"Redacted for Privacy","postal_code":"101","email":"07da1849e7814858a31ea085d9e8c099.protect@withheldforprivacy.com"},"status":["clienttransferprohibited"]}}"#;
        let f = finding(body, Indicator::Domain("netlas.io"));
        for (key, expected) in [
            ("registrar", "NAMECHEAP INC"),
            ("registrar_email", "abuse@namecheap.com"),
            ("registrar_url", "http://www.namecheap.com"),
            ("created", "2020-11-06T08:10:14.820Z"),
            ("updated", "2022-09-28T09:38:39.210Z"),
            ("expires", "2026-11-06T08:10:14.820Z"),
            ("domain_status", "clienttransferprohibited"),
            (
                "whois_name_servers",
                "pdns1.registrar-servers.com,pdns2.registrar-servers.com",
            ),
            (
                "registrant_organization",
                "Privacy service provided by Withheld for Privacy ehf",
            ),
            ("registrant_country", "IS"),
            (
                "registrant_email",
                "07da1849e7814858a31ea085d9e8c099.protect@withheldforprivacy.com",
            ),
        ] {
            assert_eq!(value(&f, key), Some(expected), "{key}: {:?}", f.attrs);
        }
        let raw = value(&f, "raw_answer").unwrap_or_default();
        assert!(raw.contains("Reykjavik"), "{raw}");
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
        assert_eq!(value(&f, "dns_txt"), Some("v=spf1 -all"));
        assert!(f.tags.is_empty());
    }

    #[test]
    fn another_subject_is_refused() {
        assert!(decode(Answer::Body(IP.into()), Indicator::Ip("8.8.8.8")).is_err());
        assert!(decode(Answer::Body(DOMAIN.into()), Indicator::Ip("1.1.1.1")).is_err());
    }

    #[test]
    fn a_404_is_a_path_netlas_lacks_not_a_zero() {
        // Recorded for `https://app.netlas.io/api/nosuchpath/1.1.1.1/` on 2026-10-15.
        let page = "<!doctype html>\n<html lang=\"en\">\n<head>\n  <title>Not Found</title>\n</head>\n<body>\n  <h1>Not Found</h1><p>The requested resource was not found on this server.</p>\n</body>\n</html>\n";
        let transport = crate::test_support::OneResponse::with_headers(
            404,
            &[("content-type", "text/html")],
            page,
        );
        let looked_up = lookup(&transport, &Keys::default(), Indicator::Ip("1.1.1.1"), 1);
        assert!(
            matches!(looked_up, Err(LegError::Unexpected(404))),
            "{looked_up:?}"
        );
    }

    #[test]
    fn a_domain_netlas_never_scanned_is_a_zero_not_an_empty_finding() {
        // Recorded without a key on 2026-10-15 for a name no one has registered.
        let unseen = r#"{"related_domains_count":0,"related_domains_query":"(domain:*.huntsman-nonexistent-zz9q4.com AND NOT domain:huntsman-nonexistent-zz9q4.com)","domain":"huntsman-nonexistent-zz9q4.com","type":"domain","source":[]}"#;
        let decoded = decode(
            Answer::Body(unseen.into()),
            Indicator::Domain("huntsman-nonexistent-zz9q4.com"),
        );
        assert!(matches!(decoded, Ok(None)), "{decoded:?}");
        // An address Netlas only has WHOIS for is still reported: the network is a finding.
        let whois_only = r#"{"ip":"223.255.255.1","type":"ip","domains":[],"domains_count":0,"privacy":{"is_vpn":false,"is_proxy":false,"is_tor":false},"whois":{"net":{"name":"Debogon-prefix","country":"AU","range":"223.255.255.0 - 223.255.255.255"}}}"#;
        let decoded = decode(
            Answer::Body(whois_only.into()),
            Indicator::Ip("223.255.255.1"),
        );
        assert!(matches!(decoded, Ok(Some(_))), "{decoded:?}");
    }
}
