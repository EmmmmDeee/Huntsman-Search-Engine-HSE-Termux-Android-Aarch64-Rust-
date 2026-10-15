//! Pulsedive: community threat-intelligence risk for one IP or domain.
//!
//! One lookup is one `GET https://pulsedive.com/api/info.php?indicator={value}`. Pulsedive
//! answers without a key at a low limit; with `HUNTSMAN_PULSEDIVE_KEY` set the key goes in the
//! `key` query parameter (added as the request is sent) and the limit is the account's.
//!
//! Everything the answer gives is kept. The finding carries the overall risk, every risk factor
//! with its level, every linked threat (category and risk) and feed (organisation and category),
//! the ports, protocols, technologies and host types seen, the redirects, the community comments,
//! and when Pulsedive added, updated, saw, probed and retired the indicator. Each `properties`
//! group (WHOIS, geo, DNS, TLS, HTTP, page meta, banners, cookies, DOM) is kept whole as JSON in
//! a `raw_<group>` attribute, and the parts that name something else are read out: the position
//! (a coordinates pivot), city, region and postcode; the origin AS (an ASN pivot); the network or
//! registrant organisation (an organisation pivot), net name, route and registrar; the PTR host
//! name, A, NS and MX records and TLS certificate names (domain and IP pivots); and the TLS
//! subject, issuer, validity, fingerprints and JARM, the HTTP server and status, and the page
//! title.
//!
//! Pulsedive writes an empty object as `[]` (`"attributes":[]` for an indicator with no
//! attributes); that is read as empty, not as a different answer. A `404` with the body
//! `{"error":"Indicator not found."}` is a valid zero; any other `404` is a failure.

use std::collections::BTreeMap;

use serde::de::{Deserializer, IgnoredAny};
use serde::{Deserialize, de};
use serde_json::Value;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::canonical::canonical_coordinates;
use crate::http::{Transport, percent_encode_component};
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, PivotKind, Source};
use crate::keys::Keys;
use crate::tags;

pub const SOURCE: &str = "pulsedive";
pub const KEY_SLOT: &str = crate::environment::PULSEDIVE_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "pulsedive.com",
    origin: "https://pulsedive.com:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Query("key"),
        required: false,
    }),
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Ip, IndicatorKind::Domain],
    lookup,
};

#[derive(Deserialize)]
struct Body {
    indicator: String,
    risk: String,
    #[serde(default)]
    risk_recommended: Option<String>,
    #[serde(default)]
    retired: Option<String>,
    #[serde(default)]
    stamp_added: Option<String>,
    #[serde(default)]
    stamp_updated: Option<String>,
    #[serde(default)]
    stamp_seen: Option<String>,
    #[serde(default)]
    stamp_probed: Option<String>,
    #[serde(default)]
    stamp_retired: Option<String>,
    #[serde(default)]
    submissions: Option<u64>,
    #[serde(default)]
    umbrella_rank: Option<u64>,
    #[serde(default)]
    umbrella_domain: Option<String>,
    #[serde(default)]
    riskfactors: Vec<Labelled>,
    #[serde(default, deserialize_with = "object_or_empty")]
    redirects: Redirects,
    #[serde(default)]
    threats: Vec<Labelled>,
    #[serde(default)]
    feeds: Vec<Labelled>,
    #[serde(default)]
    comments: Vec<Comment>,
    #[serde(default, deserialize_with = "object_or_empty")]
    attributes: BTreeMap<String, Value>,
    #[serde(default, deserialize_with = "object_or_empty")]
    properties: BTreeMap<String, Value>,
}

/// A risk factor, threat or feed: its name and the labels Pulsedive gives it.
#[derive(Deserialize)]
struct Labelled {
    #[serde(default, alias = "description")]
    name: Option<String>,
    #[serde(default)]
    risk: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    organization: Option<String>,
}

#[derive(Deserialize, Default)]
struct Redirects {
    #[serde(default)]
    from: Vec<Linked>,
    #[serde(default)]
    to: Vec<Linked>,
}

#[derive(Deserialize)]
struct Linked {
    #[serde(default)]
    indicator: Option<String>,
}

#[derive(Deserialize)]
struct Comment {
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    stamp_added: Option<String>,
}

/// An object, or `[]`, Pulsedive's spelling of an empty object, as `T`'s default.
fn object_or_empty<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum ObjectOrList<T> {
        Object(T),
        List(Vec<IgnoredAny>),
    }
    match Option::<ObjectOrList<T>>::deserialize(deserializer)? {
        None => Ok(T::default()),
        Some(ObjectOrList::Object(value)) => Ok(value),
        Some(ObjectOrList::List(items)) if items.is_empty() => Ok(T::default()),
        Some(ObjectOrList::List(_)) => Err(de::Error::custom("a list where an object belongs")),
    }
}

/// The request URL for `indicator`. **Pure.**
#[must_use]
pub fn url(indicator: Indicator<'_>) -> String {
    format!(
        "https://pulsedive.com/api/info.php?indicator={}",
        percent_encode_component(indicator.value())
    )
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

/// `name (label / label)` for each item with a name, the labels it has in that order.
fn labelled(items: &[Labelled], labels: fn(&Labelled) -> [Option<&str>; 2]) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| {
            let name = api_leg::clean(item.name.as_deref())?;
            let labels: Vec<String> = labels(item)
                .into_iter()
                .filter_map(api_leg::clean)
                .collect();
            Some(if labels.is_empty() {
                name
            } else {
                format!("{name} ({})", labels.join(" / "))
            })
        })
        .collect()
}

/// Every string a JSON value holds: itself, or each string or number in a list. **Pure.**
fn strings(value: Option<&Value>) -> Vec<String> {
    let one = |v: &Value| match v {
        Value::String(s) => api_leg::clean(Some(s)),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    };
    match value {
        Some(Value::Array(items)) => items.iter().filter_map(one).collect(),
        Some(other) => one(other).into_iter().collect(),
        None => Vec::new(),
    }
}

/// The first string of `group[key]`, unless Pulsedive wrote that it withholds it.
fn first(group: Option<&Value>, key: &str) -> Option<String> {
    strings(group.and_then(|g| g.get(key)))
        .into_iter()
        .find(|v| !v.to_ascii_uppercase().contains("REDACTED"))
}

/// The attribute that keeps a `properties` group whole, or `None` for a group this does not name.
fn raw_key(group: &str) -> Option<&'static str> {
    Some(match group {
        "whois" => "raw_whois",
        "geo" => "raw_geo",
        "dns" => "raw_dns",
        "ssl" => "raw_ssl",
        "http" => "raw_http",
        "meta" => "raw_meta",
        "banners" => "raw_banners",
        "cookies" => "raw_cookies",
        "dom" => "raw_dom",
        _ => return None,
    })
}

/// The attribute name for an `attributes` list, or `None` for one this does not name.
fn attribute_key(name: &str) -> Option<&'static str> {
    Some(match name {
        "port" => "ports",
        "protocol" => "protocols",
        "technology" => "technologies",
        "hosttype" => "host_types",
        _ => return None,
    })
}

/// One answer for `indicator`. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented shape or is about something else,
/// and [`LegError::Unexpected`] for a `404` that is not the "not found" answer.
pub fn decode(answer: Answer, indicator: Indicator<'_>) -> Result<Option<Finding>, LegError> {
    let body = match answer {
        Answer::NotFound(body) => return not_found(&body),
        Answer::Body(body) => body,
    };
    let body: Body = api_leg::decode(&body)?;
    if !body.indicator.eq_ignore_ascii_case(indicator.value()) {
        return Err(LegError::Decode("answer names another indicator".into()));
    }
    let risk = api_leg::clean(Some(&body.risk)).unwrap_or_else(|| "unknown".into());
    let mut finding = Finding::new(format!(
        "Pulsedive: risk {risk}, {} linked threat(s), {} feed(s)",
        body.threats.len(),
        body.feeds.len()
    ))
    .attr("risk", &risk)
    .opt_attr("risk_recommended", body.risk_recommended.as_deref())
    .list_attr(
        "threats",
        &labelled(&body.threats, |t| {
            [t.category.as_deref(), t.risk.as_deref()]
        }),
    )
    .list_attr(
        "feeds",
        &labelled(&body.feeds, |f| {
            [f.organization.as_deref(), f.category.as_deref()]
        }),
    )
    .list_attr(
        "risk_factors",
        &labelled(&body.riskfactors, |r| [r.risk.as_deref(), None]),
    )
    .opt_attr("first_added", body.stamp_added.as_deref())
    .opt_attr("updated", body.stamp_updated.as_deref())
    .opt_attr("last_seen", body.stamp_seen.as_deref())
    .opt_attr("last_probed", body.stamp_probed.as_deref())
    .opt_attr("retired", body.retired.as_deref())
    .opt_attr("retired_on", body.stamp_retired.as_deref())
    .opt_attr("submissions", body.submissions.map(|n| n.to_string()))
    .opt_attr("umbrella_rank", body.umbrella_rank.map(|r| r.to_string()))
    .tag_if(
        matches!(risk.as_str(), "high" | "critical"),
        tags::MALICIOUS,
    )
    .tag_if(risk == "medium", "suspicious");
    finding = attributes(redirects_and_comments(finding, &body), &body.attributes);
    if let Some(domain) = body.umbrella_domain.as_deref() {
        if !domain.eq_ignore_ascii_case(indicator.value()) {
            finding = finding.pivot(
                PivotKind::Domain,
                domain,
                "Domain Pulsedive ranks for the indicator",
            );
        }
    }
    finding = properties(finding, &body.properties);
    Ok(Some(finding))
}

/// `finding` with the redirects and community comments of `body`. **Pure.**
fn redirects_and_comments(finding: Finding, body: &Body) -> Finding {
    let indicators = |links: &[Linked]| -> Vec<String> {
        links
            .iter()
            .filter_map(|r| api_leg::clean(r.indicator.as_deref()))
            .collect()
    };
    let comments: Vec<String> = body
        .comments
        .iter()
        .filter_map(|c| {
            let text = api_leg::clean(c.comment.as_deref())?;
            Some(match api_leg::clean(c.stamp_added.as_deref()) {
                Some(when) => format!("{text} ({when})"),
                None => text,
            })
        })
        .collect();
    finding
        .list_attr("redirects_to", &indicators(&body.redirects.to))
        .list_attr("redirects_from", &indicators(&body.redirects.from))
        .list_attr("comments", &comments)
}

/// `finding` with every `attributes` list: the ones this names as their own attributes, the
/// rest whole as JSON in `raw_attributes`. **Pure.**
fn attributes(mut finding: Finding, attributes: &BTreeMap<String, Value>) -> Finding {
    let mut other = serde_json::Map::new();
    for (name, values) in attributes {
        match attribute_key(name) {
            Some(key) => finding = finding.list_attr(key, &strings(Some(values))),
            None => {
                other.insert(name.clone(), values.clone());
            }
        }
    }
    if other.is_empty() {
        finding
    } else {
        finding.attr("raw_attributes", Value::Object(other).to_string())
    }
}

/// `finding` with every `properties` group kept whole and the parts that name something else
/// read out. **Pure.**
fn properties(finding: Finding, properties: &BTreeMap<String, Value>) -> Finding {
    property_pivots(
        read_out(raw_groups(finding, properties), properties),
        properties,
    )
}

/// `finding` with each `properties` group whole as JSON. **Pure.**
fn raw_groups(mut finding: Finding, properties: &BTreeMap<String, Value>) -> Finding {
    let mut other_groups = serde_json::Map::new();
    for (group, value) in properties {
        match raw_key(group) {
            Some(key) => finding = finding.attr(key, value.to_string()),
            None => {
                other_groups.insert(group.clone(), value.clone());
            }
        }
    }
    if !other_groups.is_empty() {
        finding = finding.attr("raw_properties", Value::Object(other_groups).to_string());
    }
    finding
}

/// `finding` with the plain facts the `properties` groups give as attributes. **Pure.**
fn read_out(finding: Finding, properties: &BTreeMap<String, Value>) -> Finding {
    let geo = properties.get("geo");
    let whois = properties.get("whois");
    let dns = properties.get("dns");
    let ssl = properties.get("ssl");
    let http = properties.get("http");
    let meta = properties.get("meta");
    finding
        .opt_attr("country", first(geo, "countrycode"))
        .opt_attr("region", first(geo, "region"))
        .opt_attr("city", first(geo, "city"))
        .opt_attr("postal_code", first(geo, "zip"))
        .opt_attr("isp", first(geo, "isp"))
        .opt_attr("netname", first(whois, "netname"))
        .opt_attr(
            "route",
            first(whois, "route").or_else(|| first(whois, "++cidr")),
        )
        .opt_attr("inetnum", first(whois, "inetnum"))
        .opt_attr("registrar", first(whois, "registrar"))
        .opt_attr("created", first(whois, "creation date"))
        .opt_attr(
            "expires",
            first(whois, "registrar registration expiration date"),
        )
        .opt_attr("hostname", first(dns, "ptr"))
        .opt_attr("tls_subject", first(ssl, "subject"))
        .opt_attr("tls_issuer", first(ssl, "issuer"))
        .opt_attr("tls_valid_from", first(ssl, "valid"))
        .opt_attr("tls_expires", first(ssl, "expires"))
        .opt_attr("tls_fingerprint", first(ssl, "fingerprint"))
        .opt_attr("tls_sha256", first(ssl, "++sha256"))
        .opt_attr("jarm", first(ssl, "++jarm"))
        .opt_attr("http_server", first(http, "server"))
        .opt_attr("http_status", first(http, "++code"))
        .opt_attr("page_title", first(meta, "++title"))
}

/// `finding` with what the `properties` groups name as pivots. **Pure.**
fn property_pivots(mut finding: Finding, properties: &BTreeMap<String, Value>) -> Finding {
    let geo = properties.get("geo");
    let whois = properties.get("whois");
    let dns = properties.get("dns");
    let ssl = properties.get("ssl");
    let position = first(geo, "lat")
        .zip(first(geo, "long"))
        .and_then(|(lat, lon)| canonical_coordinates(&format!("{lat},{lon}")));
    if let Some(position) = position {
        finding = finding.attr("coordinates", &position).pivot(
            PivotKind::Coordinates,
            position,
            "Position Pulsedive gives for the indicator",
        );
    }
    let asns = strings(geo.and_then(|g| g.get("asn")))
        .into_iter()
        .chain(strings(whois.and_then(|w| w.get("origin"))));
    for asn in asns {
        finding = finding.pivot(PivotKind::Asn, asn, "AS Pulsedive gives for the indicator");
    }
    let organisation = first(whois, "org-name").or_else(|| first(whois, "registrant organization"));
    if let Some(organisation) = organisation {
        finding = finding.attr("organisation", &organisation).pivot(
            PivotKind::Organisation,
            organisation,
            "Organisation the WHOIS record Pulsedive gives names",
        );
    }
    for host in strings(dns.and_then(|d| d.get("ptr"))) {
        finding = finding.pivot(
            PivotKind::Domain,
            host,
            "Host name the address's PTR record gives, per Pulsedive",
        );
    }
    for address in strings(dns.and_then(|d| d.get("a"))) {
        finding = finding.pivot(
            PivotKind::Ip,
            address,
            "Address the domain resolves to, per Pulsedive",
        );
    }
    for server in strings(dns.and_then(|d| d.get("ns"))) {
        finding = finding.pivot(
            PivotKind::Domain,
            server,
            "Name server of the domain, per Pulsedive",
        );
    }
    for server in strings(dns.and_then(|d| d.get("mx"))) {
        // An MX record may carry its preference first: `10 mx.example.com`.
        let host = server.rsplit(' ').next().unwrap_or(&server).to_owned();
        finding = finding.pivot(
            PivotKind::Domain,
            host,
            "Mail server of the domain, per Pulsedive",
        );
    }
    for name in strings(ssl.and_then(|s| s.get("domain"))) {
        finding = finding.pivot(
            PivotKind::Domain,
            name,
            "Name on the TLS certificate Pulsedive saw",
        );
    }
    finding
}

/// A `404`: the "not found" answer is a valid zero, anything else a failure. **Pure.**
fn not_found(body: &[u8]) -> Result<Option<Finding>, LegError> {
    #[derive(Deserialize)]
    struct Miss {
        error: String,
    }
    match api_leg::decode::<Miss>(body) {
        Ok(miss)
            if miss
                .error
                .trim()
                .eq_ignore_ascii_case("Indicator not found.") =>
        {
            Ok(None)
        }
        _ => Err(LegError::Unexpected(404)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded without a key for `1.1.1.1` on 2026-10-15 (lists and property groups trimmed).
    const IP: &str = r#"{"qid":null,"iid":100939,"indicator":"1.1.1.1","type":"ip","risk":"none","risk_recommended":"none","manualrisk":0,"retired":null,"stamp_added":"2017-10-18 02:34:59","stamp_updated":"2026-10-15 10:40:01","stamp_seen":"2026-10-15 10:40:01","stamp_probed":"2024-06-08 10:35:41","stamp_retired":null,"recent":0,"submissions":41,"umbrella_rank":4641,"umbrella_domain":"one.one.one.one","riskfactors":[{"rfid":60,"description":"found in threat feeds","risk":"medium"},{"rfid":50,"description":"hosted on common ISP","risk":"none"}],"redirects":{"from":[],"to":[{"iid":3864715,"indicator":"https://stats.g.doubleclick.net/r/collect"},{"iid":6783369,"indicator":"https://www.google.co.uk/ads/ga-audiences"}]},"threats":[{"tid":90,"name":"Adware","category":"pup","risk":"low","stamp_linked":"2020-04-05 19:32:53"},{"tid":431,"name":"CryptoMining","category":"general","risk":"low","stamp_linked":"2020-10-14 21:10:20"},{"tid":305,"name":"LDAP DDoS","category":"attack","risk":"unknown","stamp_linked":"2018-12-11 19:24:14"}],"feeds":[{"fid":11,"name":"Bad IPs","category":"attack","organization":"badIPs","pricing":"free","stamp_linked":"2018-07-15 22:11:56"},{"fid":4,"name":"C&C IPs","category":"malware","organization":"Bambenek Consulting","pricing":null,"stamp_linked":"2020-09-08 13:00:09"}],"comments":[{"cid":529563,"comment":"Killnet Update 20220617","stamp_added":"2022-06-17 09:10:12"}],"attributes":{"hosttype":["Name Server"],"port":["443","53","80","8080","8081","8443"],"protocol":["DNS","DNS-over-TLS","FTP"],"technology":["Amazon Web Services","CloudFlare","DigiCert"]},"properties":{"whois":{"source":"APNIC","country":["AU","ZZ"],"inetnum":"1.1.1.0 - 1.1.1.255","netname":"APNIC-LABS","org-name":"APNIC Research and Development","route":"1.1.1.0/24","origin":"AS13335","abuse-mailbox":"helpdesk@apnic.net"},"geo":{"asn":"AS13335","country":["Australia","Unknown Region"],"countrycode":["AU","ZZ"],"address":["6 Cordelia St","PO Box 3646","Australia","South Brisbane, QLD 4101"],"org":["Cloudflare, Inc.","ORG-ARAD1-AP"]},"http":{"server":"cloudflare","++code":"200"},"meta":{"++title":"1.1.1.1 — The free app that makes your Internet faster."},"dns":{"ptr":"one.one.one.one"},"banners":{"53":"\u0005\u0004\u0000\u0000"},"dom":{"screenshot":"https://sandbox.pulsedive.com/screenshots/a44e8f91f2032a85ae34c097c1fa5cd2.jpeg"},"ssl":{"++jarm":"27d27d27d00027d00042d43d00041df04c41293ba84f6efe3a613b22f983e6"}}}"#;
    /// Recorded without a key for `pulsedive.com` on 2026-10-15 (property groups trimmed).
    const DOMAIN: &str = r#"{"iid":53929,"indicator":"pulsedive.com","type":"domain","risk":"none","risk_recommended":"none","retired":null,"stamp_added":"2017-10-04 01:20:55","stamp_seen":"2026-10-15 08:51:46","umbrella_rank":null,"umbrella_domain":null,"riskfactors":[{"rfid":70,"description":"Linked IPs return PTR records","risk":"none"},{"rfid":74,"description":"SPF record present","risk":"none"}],"threats":[],"feeds":[],"attributes":{"port":["443","80"],"protocol":["HTTP","HTTPS"],"technology":["Apache","Apache HTTP Server","DMARC","Font Awesome","Google Workspace","HSTS","Let's Encrypt","Open Graph","PHP","SPF"]},"redirects":{"from":[],"to":[{"iid":642010,"indicator":"https://pulsedive.com/"}]},"properties":{"whois":{"domain name":"pulsedive.com","registrar":"Squarespace Domains II LLC","creation date":"2016-11-11T21:18:19Z","registrar registration expiration date":"2026-11-11T21:18:19Z","registrant organization":"Pulsedive","name server":["ns2.digitalocean.com","ns1.digitalocean.com","ns3.digitalocean.com"]},"dns":{"a":"45.55.106.210","ns":["ns2.digitalocean.com","ns3.digitalocean.com","ns1.digitalocean.com"],"mx":["alt3.aspmx.l.google.com","alt4.aspmx.l.google.com"]},"ssl":{"subject":"/CN=pulsedive.com","domain":["pulsedive.com","www.pulsedive.com"],"issuer":"/C=US/O=Let's Encrypt/CN=YR2","valid":"2026-08-26 06:04:03","expires":"2026-11-24 06:04:02","fingerprint":"1a43d16e3383ab4ed8aee762dd3b36792763d9446d63fda7d1e4acb11aa913c6","++jarm":"2ad2ad16d2ad2ad00042d42d000000c33a20aec889d430cbd148294f584a77"},"geo":{"countrycode":"US","region":"NJ","country":"United States of America","address":"REDACTED FOR PRIVACY","zip":"REDACTED FOR PRIVACY","city":"REDACTED FOR PRIVACY","org":"Pulsedive"}}}"#;
    /// Recorded without a key for `45.155.205.233` on 2026-10-15: `"attributes":[]`.
    const EMPTY_ATTRIBUTES: &str = r#"{"qid":null,"iid":30377744,"indicator":"45.155.205.233","type":"ip","risk":"unknown","risk_recommended":"unknown","manualrisk":0,"retired":"No recent activity","stamp_added":"2021-12-13 13:50:44","stamp_updated":"2024-01-05 14:10:53","stamp_seen":"2023-10-03 06:58:19","stamp_probed":"2022-10-02 19:10:20","stamp_retired":"2024-01-05 14:10:53","recent":0,"submissions":4,"umbrella_rank":null,"umbrella_domain":null,"riskfactors":[],"redirects":{"from":[],"to":[]},"threats":[],"feeds":[],"comments":[],"attributes":[],"properties":{"geo":{"country":"Russian Federation","countrycode":"RU","region":"St.-Petersburg","city":"St Petersburg","lat":"59.9417","long":"30.3096","isp":"Proton66 OOO","org":"Proton66 OOO","asn":"AS198953"}}}"#;
    /// Recorded without a key for an unknown domain on 2026-10-14 (HTTP 404).
    const NOT_FOUND: &str = r#"{"error":"Indicator not found."}"#;

    fn finding(body: &str, indicator: Indicator<'_>) -> Finding {
        decode(Answer::Body(body.into()), indicator)
            .unwrap_or_else(|e| panic!("recorded body must decode: {e}"))
            .unwrap_or_else(|| panic!("recorded body is a finding"))
    }

    fn attr<'a>(finding: &'a Finding, key: &str) -> Option<&'a str> {
        finding
            .attrs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
    }

    fn pivots(finding: &Finding, kind: PivotKind) -> Vec<&str> {
        finding
            .pivots
            .iter()
            .filter(|p| p.kind == kind)
            .map(|p| p.value.as_str())
            .collect()
    }

    #[test]
    fn a_recorded_answer_keeps_risk_threats_feeds_and_their_labels() {
        let f = finding(IP, Indicator::Ip("1.1.1.1"));
        assert!(
            f.summary
                .contains("risk none, 3 linked threat(s), 2 feed(s)")
        );
        assert_eq!(
            attr(&f, "threats"),
            Some("Adware (pup / low),CryptoMining (general / low),LDAP DDoS (attack / unknown)")
        );
        assert_eq!(
            attr(&f, "feeds"),
            Some("Bad IPs (badIPs / attack),C&C IPs (Bambenek Consulting / malware)")
        );
        assert_eq!(
            attr(&f, "risk_factors"),
            Some("found in threat feeds (medium),hosted on common ISP (none)")
        );
        assert_eq!(attr(&f, "ports"), Some("443,53,80,8080,8081,8443"));
        assert_eq!(attr(&f, "host_types"), Some("Name Server"));
        assert_eq!(attr(&f, "first_added"), Some("2017-10-18 02:34:59"));
        assert_eq!(attr(&f, "last_probed"), Some("2024-06-08 10:35:41"));
        assert_eq!(attr(&f, "submissions"), Some("41"));
        assert_eq!(
            attr(&f, "redirects_to"),
            Some(
                "https://stats.g.doubleclick.net/r/collect,https://www.google.co.uk/ads/ga-audiences"
            )
        );
        assert_eq!(
            attr(&f, "comments"),
            Some("Killnet Update 20220617 (2022-06-17 09:10:12)")
        );
        assert!(f.tags.is_empty(), "risk none is not malicious");
    }

    #[test]
    fn every_property_group_is_kept_and_what_it_names_is_read_out() {
        let f = finding(IP, Indicator::Ip("1.1.1.1"));
        for group in [
            "raw_whois",
            "raw_geo",
            "raw_http",
            "raw_meta",
            "raw_dns",
            "raw_banners",
            "raw_dom",
            "raw_ssl",
        ] {
            assert!(attr(&f, group).is_some(), "{group} missing: {:?}", f.attrs);
        }
        assert!(
            attr(&f, "raw_whois")
                .is_some_and(|w| w.contains(r#""abuse-mailbox":"helpdesk@apnic.net""#)),
            "{:?}",
            attr(&f, "raw_whois")
        );
        assert_eq!(
            attr(&f, "raw_banners"),
            Some(r#"{"53":"\u0005\u0004\u0000\u0000"}"#)
        );
        assert_eq!(attr(&f, "netname"), Some("APNIC-LABS"));
        assert_eq!(attr(&f, "route"), Some("1.1.1.0/24"));
        assert_eq!(attr(&f, "inetnum"), Some("1.1.1.0 - 1.1.1.255"));
        assert_eq!(attr(&f, "country"), Some("AU"));
        assert_eq!(attr(&f, "hostname"), Some("one.one.one.one"));
        assert_eq!(attr(&f, "http_server"), Some("cloudflare"));
        assert_eq!(attr(&f, "http_status"), Some("200"));
        assert_eq!(
            attr(&f, "page_title"),
            Some("1.1.1.1 — The free app that makes your Internet faster.")
        );
        assert_eq!(
            attr(&f, "jarm"),
            Some("27d27d27d00027d00042d43d00041df04c41293ba84f6efe3a613b22f983e6")
        );
        assert_eq!(pivots(&f, PivotKind::Asn), ["AS13335"]);
        assert_eq!(
            pivots(&f, PivotKind::Organisation),
            ["APNIC Research and Development"]
        );
        assert_eq!(pivots(&f, PivotKind::Domain), ["one.one.one.one"]);
    }

    #[test]
    fn a_domain_answer_names_its_records_certificate_names_and_registrant() {
        let f = finding(DOMAIN, Indicator::Domain("pulsedive.com"));
        assert_eq!(pivots(&f, PivotKind::Ip), ["45.55.106.210"]);
        assert_eq!(
            pivots(&f, PivotKind::Domain),
            [
                "ns2.digitalocean.com",
                "ns3.digitalocean.com",
                "ns1.digitalocean.com",
                "alt3.aspmx.l.google.com",
                "alt4.aspmx.l.google.com",
                "pulsedive.com",
                "www.pulsedive.com"
            ]
        );
        assert_eq!(pivots(&f, PivotKind::Organisation), ["Pulsedive"]);
        assert_eq!(attr(&f, "registrar"), Some("Squarespace Domains II LLC"));
        assert_eq!(attr(&f, "created"), Some("2016-11-11T21:18:19Z"));
        assert_eq!(attr(&f, "expires"), Some("2026-11-11T21:18:19Z"));
        assert_eq!(attr(&f, "tls_issuer"), Some("/C=US/O=Let's Encrypt/CN=YR2"));
        assert_eq!(attr(&f, "tls_subject"), Some("/CN=pulsedive.com"));
        assert_eq!(attr(&f, "tls_expires"), Some("2026-11-24 06:04:02"));
        assert_eq!(attr(&f, "region"), Some("NJ"));
        assert_eq!(attr(&f, "city"), None, "REDACTED FOR PRIVACY is not a city");
        assert!(
            attr(&f, "raw_geo").is_some_and(|g| g.contains("REDACTED FOR PRIVACY")),
            "the raw group keeps what Pulsedive wrote"
        );
        assert_eq!(
            attr(&f, "technologies"),
            Some(
                "Apache,Apache HTTP Server,DMARC,Font Awesome,Google Workspace,HSTS,Let's Encrypt,Open Graph,PHP,SPF"
            )
        );
    }

    #[test]
    fn an_empty_object_written_as_a_list_is_read_as_empty() {
        let f = finding(EMPTY_ATTRIBUTES, Indicator::Ip("45.155.205.233"));
        assert!(
            f.summary
                .contains("risk unknown, 0 linked threat(s), 0 feed(s)")
        );
        assert_eq!(attr(&f, "ports"), None);
        assert_eq!(attr(&f, "retired"), Some("No recent activity"));
        assert_eq!(attr(&f, "retired_on"), Some("2024-01-05 14:10:53"));
        assert_eq!(attr(&f, "city"), Some("St Petersburg"));
        assert_eq!(attr(&f, "isp"), Some("Proton66 OOO"));
        assert_eq!(attr(&f, "coordinates"), Some("59.941700,30.309600"));
        assert_eq!(pivots(&f, PivotKind::Coordinates), ["59.941700,30.309600"]);
        assert_eq!(pivots(&f, PivotKind::Asn), ["AS198953"]);
        let attributes = EMPTY_ATTRIBUTES.replace(r#""attributes":[]"#, r#""attributes":["x"]"#);
        assert!(matches!(
            decode(
                Answer::Body(attributes.into()),
                Indicator::Ip("45.155.205.233")
            ),
            Err(LegError::Decode(_))
        ));
    }

    #[test]
    fn an_attribute_or_group_this_does_not_name_is_still_kept() {
        let body = IP
            .replace(r#""hosttype":"#, r#""tld":["io"],"hosttype":"#)
            .replace(
                r#""properties":{"#,
                r#""properties":{"newgroup":{"k":"v"},"#,
            );
        let f = finding(&body, Indicator::Ip("1.1.1.1"));
        assert_eq!(attr(&f, "raw_attributes"), Some(r#"{"tld":["io"]}"#));
        assert_eq!(
            attr(&f, "raw_properties"),
            Some(r#"{"newgroup":{"k":"v"}}"#)
        );
    }

    #[test]
    fn high_risk_is_malicious() {
        let body = IP.replace(
            r#""risk":"none","risk_recommended""#,
            r#""risk":"high","risk_recommended""#,
        );
        assert_eq!(
            finding(&body, Indicator::Ip("1.1.1.1")).tags,
            [tags::MALICIOUS]
        );
    }

    #[test]
    fn not_found_is_a_valid_zero_another_404_a_failure_and_another_indicator_refused() {
        assert_eq!(
            decode(
                Answer::NotFound(NOT_FOUND.into()),
                Indicator::Domain("zz.example")
            ),
            Ok(None)
        );
        assert_eq!(
            decode(
                Answer::NotFound(b"<html>Not Found</html>".to_vec()),
                Indicator::Domain("zz.example")
            ),
            Err(LegError::Unexpected(404))
        );
        assert!(decode(Answer::Body(IP.into()), Indicator::Ip("8.8.8.8")).is_err());
    }
}
