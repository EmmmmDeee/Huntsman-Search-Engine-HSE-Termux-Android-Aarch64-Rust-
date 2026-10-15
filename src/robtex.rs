//! Robtex: routing and passive DNS for one IP address or domain.
//!
//! An address is one keyless `GET https://freeapi.robtex.com/ipquery/{ip}`; a domain is one
//! keyless `GET https://freeapi.robtex.com/pdns/forward/{domain}`, which answers one JSON record
//! per line. An address with no route or names, or a domain with no records, is a valid zero.
//! Robtex answers both with `200` (`{"status":"ok","act":[]}`, `[]`) and gives a `404` only for an
//! endpoint it does not have (checked 2026-10-15): a `404` is not an answer. An address goes into
//! the path as written, colons included: Robtex does not decode `%3A` there, and answered an IPv6
//! address written that way as one it knew nothing about (checked 2026-10-15).
//!
//! Everything is kept. For an address: the whole answer as JSON in `raw_answer`, and read out of
//! it the BGP route and its description, the origin AS with its name and description, the WHOIS
//! description, the city and country, and every name passive and active DNS has seen pointing at
//! the address, with the newest sighting of each kind; each name is a domain pivot. For a domain:
//! every record whole in `raw_records`, the record count, the first and newest sightings, the
//! addresses (A, AAAA) and names (NS, MX, CNAME) it resolved to, each also a pivot, and every
//! other record (TXT and the rest) as `TYPE data`.

use serde::Deserialize;
use serde_json::Value;

use crate::api_leg::{self, Answer, Api, LegError};
use crate::http::{Transport, percent_encode_component};
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, PivotKind, Source};
use crate::keys::Keys;

pub const SOURCE: &str = "robtex";
pub const API: Api = Api {
    source: SOURCE,
    provider: "robtex.com",
    origin: "https://freeapi.robtex.com:443",
    key: None,
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Ip, IndicatorKind::Domain],
    lookup,
};

#[derive(Deserialize)]
struct IpBody {
    status: String,
    #[serde(default, rename = "as")]
    asn: Option<u64>,
    #[serde(default)]
    asname: Option<String>,
    #[serde(default)]
    asdesc: Option<String>,
    #[serde(default)]
    whoisdesc: Option<String>,
    #[serde(default)]
    bgproute: Option<String>,
    #[serde(default)]
    routedesc: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    country: Option<String>,
    /// Passive DNS: names seen pointing at the address.
    #[serde(default)]
    pas: Vec<Seen>,
    /// Active DNS: names that resolve to the address now.
    #[serde(default)]
    act: Vec<Seen>,
}

#[derive(Deserialize)]
struct Seen {
    o: String,
    #[serde(default)]
    t: Option<u64>,
}

/// One passive DNS record line.
#[derive(Deserialize)]
struct Record {
    rrdata: String,
    rrtype: String,
    #[serde(default)]
    time_first: Option<u64>,
    #[serde(default)]
    time_last: Option<u64>,
}

/// The request URL for `indicator`, or `None` when it is not an address or domain. **Pure.**
#[must_use]
pub fn url(indicator: Indicator<'_>) -> Option<String> {
    match indicator {
        Indicator::Ip(ip) => ip
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| format!("https://freeapi.robtex.com/ipquery/{ip}")),
        Indicator::Domain(domain) => Some(format!(
            "https://freeapi.robtex.com/pdns/forward/{}",
            percent_encode_component(domain)
        )),
        _ => None,
    }
}

/// Look `indicator` up; an address or domain is a Robtex lookup.
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
        Answer::Body(body) => match indicator {
            Indicator::Domain(domain) => decode_forward(&body, domain),
            _ => decode_ip(&body),
        },
        Answer::NotFound(_) => Err(LegError::Unexpected(404)),
    }
}

/// A Unix time Robtex gives, written as the crate writes times. **Pure.**
fn when(unix: Option<u64>) -> Option<String> {
    unix.and_then(|t| i64::try_from(t).ok())
        .map(crate::timefmt::format_unix)
}

/// One `ipquery` answer body. **Pure.**
///
/// # Errors
/// [`LegError::RateLimited`] when Robtex says so; [`LegError::Decode`] for any other refusal or
/// a body that is not the documented shape.
pub fn decode_ip(body: &[u8]) -> Result<Option<Finding>, LegError> {
    let raw: Value = api_leg::decode(body)?;
    let body = IpBody::deserialize(&raw)
        .map_err(|e| LegError::Decode(format!("unexpected response shape: {e}")))?;
    match body.status.as_str() {
        "ok" => {}
        "ratelimited" => return Err(LegError::RateLimited { retry_after: None }),
        other => {
            let other = api_leg::clean(Some(other)).unwrap_or_default();
            return Err(LegError::Decode(format!("Robtex status {other}")));
        }
    }
    let asname = api_leg::clean(body.asname.as_deref());
    let route = api_leg::clean(body.bgproute.as_deref());
    let passive = distinct(body.pas.iter().map(|s| s.o.as_str()));
    let active = distinct(body.act.iter().map(|s| s.o.as_str()));
    if route.is_none() && body.asn.is_none() && passive.is_empty() && active.is_empty() {
        return Ok(None);
    }
    let asn = body.asn.map(|n| format!("AS{n}"));
    let mut finding = Finding::new(format!(
        "Robtex: {}{}",
        route.as_deref().unwrap_or("no route"),
        match (&asn, &asname) {
            (Some(a), Some(n)) => format!(" via {a} {n}"),
            (Some(a), None) => format!(" via {a}"),
            _ => String::new(),
        }
    ))
    .opt_attr("route", route.as_deref())
    .opt_attr("route_description", body.routedesc.as_deref())
    .opt_attr("asn", asn.as_deref())
    .opt_attr("as_name", asname.as_deref())
    .opt_attr("as_description", body.asdesc.as_deref())
    .opt_attr("whois_description", body.whoisdesc.as_deref())
    .opt_attr("city", body.city.as_deref())
    .opt_attr("country", body.country.as_deref())
    .list_attr("passive_names", &passive)
    .opt_attr(
        "passive_last_seen",
        when(body.pas.iter().filter_map(|s| s.t).max()),
    )
    .list_attr("active_names", &active)
    .opt_attr(
        "active_last_seen",
        when(body.act.iter().filter_map(|s| s.t).max()),
    );
    if let Some(asn) = &asn {
        finding = finding.pivot(
            PivotKind::Asn,
            asn,
            "Origin AS Robtex gives for the address",
        );
    }
    for name in &passive {
        finding = finding.pivot(
            PivotKind::Domain,
            name,
            "Name passive DNS at Robtex saw pointing at the address",
        );
    }
    for name in &active {
        finding = finding.pivot(
            PivotKind::Domain,
            name,
            "Name active DNS at Robtex resolves to the address",
        );
    }
    Ok(Some(finding.attr("raw_answer", raw.to_string())))
}

/// One `pdns/forward` answer body for `domain`: one JSON record per line. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a line that is not a record.
pub fn decode_forward(body: &[u8], domain: &str) -> Result<Option<Finding>, LegError> {
    let text = std::str::from_utf8(body)
        .map_err(|_| LegError::Decode("answer is not UTF-8".into()))?
        .trim();
    if text.is_empty() || text == "[]" {
        return Ok(None);
    }
    let mut raw: Vec<Value> = Vec::new();
    let mut first: Option<u64> = None;
    let mut newest: Option<u64> = None;
    let mut addresses: Vec<String> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    let mut others: Vec<String> = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let value: Value = api_leg::decode(line.as_bytes())?;
        let record = Record::deserialize(&value)
            .map_err(|e| LegError::Decode(format!("unexpected record shape: {e}")))?;
        raw.push(value);
        first = match (first, record.time_first) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        newest = newest.max(record.time_last);
        let data = record.rrdata.trim_end_matches('.');
        match record.rrtype.as_str() {
            "A" | "AAAA" => addresses.push(data.to_owned()),
            "NS" | "MX" | "CNAME" => {
                if !data.eq_ignore_ascii_case(domain) {
                    names.push(data.to_owned());
                }
            }
            other => others.push(format!("{other} {data}")),
        }
    }
    let count = raw.len();
    let addresses = distinct(addresses.iter().map(String::as_str));
    let names = distinct(names.iter().map(String::as_str));
    let mut finding = Finding::new(format!(
        "Robtex: {count} passive DNS record{} for the domain",
        if count == 1 { "" } else { "s" }
    ))
    .attr("records", count.to_string())
    .opt_attr("first_seen", when(first))
    .opt_attr("last_seen", when(newest))
    .list_attr("addresses", &addresses)
    .list_attr("names", &names)
    .list_attr(
        "other_records",
        &distinct(others.iter().map(String::as_str)),
    );
    for address in &addresses {
        finding = finding.pivot(
            PivotKind::Ip,
            address,
            "Address passive DNS at Robtex saw the domain resolve to",
        );
    }
    for name in &names {
        finding = finding.pivot(
            PivotKind::Domain,
            name,
            "Name server, mail exchanger or alias passive DNS at Robtex saw for the domain",
        );
    }
    Ok(Some(
        finding.attr("raw_records", Value::Array(raw).to_string()),
    ))
}

/// Distinct cleaned names, every one, without a trailing dot. **Pure.**
fn distinct<'a>(values: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    values
        .filter_map(|value| api_leg::clean(Some(value.trim_end_matches('.'))))
        .filter(|value| seen.insert(value.to_ascii_lowercase()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded for `185.220.101.1` on 2026-10-14, shortened to three passive names.
    const IP: &str = r#"{"status":"ok","city":"Brandenburg","country":"DE","as":60729,"bgproute":"185.220.101.0/24","asname":"TORSERVERS-NET","asdesc":"TORSERVERS-NET","routedesc":"Zwiebelfreunde","pas":[{"o":"berlin01.tor-exit.artikel10.org","t":1791993600},{"o":"proxy36.ddnsfree.com","t":1791993600},{"o":"berlin01.tor-exit.artikel10.org","t":1791993600}]}"#;

    /// Recorded for `example.com` on 2026-10-14, shortened.
    const FORWARD: &str = concat!(
        r#"{"rrname":"example.com","rrdata":"hera.ns.cloudflare.com","rrtype":"NS","time_first":1642103570,"time_last":1791993600,"count":8}"#,
        "\n",
        r#"{"rrname":"example.com","rrdata":"2606:4700:10::6814:179a","rrtype":"AAAA","time_first":1775807518,"time_last":1791993600,"count":8}"#,
        "\n",
        r#"{"rrname":"example.com","rrdata":"104.20.23.154","rrtype":"A","time_first":1775807518,"time_last":1791993600,"count":8}"#,
        "\n",
        r#"{"rrname":"example.com","rrdata":"v=spf1 -all","rrtype":"TXT","time_first":1775807518,"time_last":1791993500,"count":8}"#,
        "\n"
    );

    #[test]
    fn an_address_keeps_route_as_and_distinct_passive_names_as_pivots() {
        let f = decode_ip(IP.as_bytes())
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        assert_eq!(
            f.summary,
            "Robtex: 185.220.101.0/24 via AS60729 TORSERVERS-NET"
        );
        let domains: Vec<&str> = f
            .pivots
            .iter()
            .filter(|p| p.kind == PivotKind::Domain)
            .map(|p| p.value.as_str())
            .collect();
        assert_eq!(
            domains,
            ["berlin01.tor-exit.artikel10.org", "proxy36.ddnsfree.com"]
        );
        assert!(
            f.pivots
                .iter()
                .any(|p| p.kind == PivotKind::Asn && p.value == "AS60729")
        );
    }

    #[test]
    fn a_rate_limit_and_an_unknown_status_are_errors() {
        assert!(matches!(
            decode_ip(br#"{"status":"ratelimited"}"#),
            Err(LegError::RateLimited { .. })
        ));
        assert!(matches!(
            decode_ip(br#"{"status":"nope"}"#),
            Err(LegError::Decode(_))
        ));
    }

    fn value<'a>(f: &'a Finding, key: &str) -> Option<&'a str> {
        f.attrs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn an_address_keeps_every_description_and_the_whole_answer() {
        let f = decode_ip(IP.as_bytes())
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        for (key, expected) in [
            ("route", "185.220.101.0/24"),
            ("route_description", "Zwiebelfreunde"),
            ("asn", "AS60729"),
            ("as_name", "TORSERVERS-NET"),
            ("as_description", "TORSERVERS-NET"),
            ("city", "Brandenburg"),
            ("country", "DE"),
            (
                "passive_names",
                "berlin01.tor-exit.artikel10.org,proxy36.ddnsfree.com",
            ),
        ] {
            assert_eq!(value(&f, key), Some(expected), "{key}: {:?}", f.attrs);
        }
        assert!(value(&f, "passive_last_seen").is_some_and(|t| t.starts_with("2026-10-")));
        let raw: Value =
            serde_json::from_str(value(&f, "raw_answer").unwrap_or_default()).unwrap_or_default();
        assert_eq!(raw["pas"].as_array().map(Vec::len), Some(3));
    }

    #[test]
    fn a_domain_keeps_addresses_names_and_every_other_record() {
        let f = decode_forward(FORWARD.as_bytes(), "example.com")
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        assert_eq!(f.summary, "Robtex: 4 passive DNS records for the domain");
        let ips: Vec<&str> = f
            .pivots
            .iter()
            .filter(|p| p.kind == PivotKind::Ip)
            .map(|p| p.value.as_str())
            .collect();
        assert_eq!(ips, ["2606:4700:10::6814:179a", "104.20.23.154"]);
        assert!(
            f.pivots
                .iter()
                .any(|p| p.kind == PivotKind::Domain && p.value == "hera.ns.cloudflare.com")
        );
        assert_eq!(value(&f, "other_records"), Some("TXT v=spf1 -all"));
        assert!(value(&f, "first_seen").is_some_and(|t| t.starts_with("2022-01-")));
        let raw: Value =
            serde_json::from_str(value(&f, "raw_records").unwrap_or_default()).unwrap_or_default();
        assert_eq!(raw.as_array().map(Vec::len), Some(4));
        assert_eq!(raw[0]["count"], 8);
    }

    #[test]
    fn a_404_is_an_endpoint_robtex_lacks_not_a_valid_zero() {
        // Recorded for `https://freeapi.robtex.com/nosuchpath/1.1.1.1` on 2026-10-15.
        let unknown = r#"{"status":"error","message":"Unknown endpoint"}"#;
        for indicator in [Indicator::Ip("1.1.1.1"), Indicator::Domain("example.com")] {
            let transport = crate::test_support::OneResponse::json(404, unknown);
            let looked_up = lookup(&transport, &Keys::default(), indicator, 1);
            assert!(
                matches!(looked_up, Err(LegError::Unexpected(404))),
                "{indicator:?}: {looked_up:?}"
            );
        }
        // What Robtex answers for an address it knows nothing about, recorded the same day.
        let unseen = br#"{"status":"ok","act":[]}"#;
        assert!(matches!(decode_ip(unseen), Ok(None)));
    }

    /// Answers as Robtex did on 2026-10-15: the record for `2606:4700:4700::1111` written as is
    /// (shortened), and "nothing known" for anything else, such as that address with its colons
    /// percent-encoded.
    struct AsRobtexAnswered;

    impl Transport for AsRobtexAnswered {
        fn send(
            &self,
            request: &crate::http::Request,
        ) -> Result<crate::http::Response, crate::http::TransportFailure> {
            let body = if request.url == "https://freeapi.robtex.com/ipquery/2606:4700:4700::1111" {
                r#"{"status":"ok","city":"","country":"US","as":13335,"bgproute":"2606:4700:4700::/48","asname":"Cloudflare","asdesc":"CLOUDFLARENET","whoisdesc":"Cloudflare, Inc.","routedesc":"Cloudflare","pas":[{"o":"yoctianos.ca","t":1792058298}]}"#
            } else {
                r#"{"status":"ok","act":[]}"#
            };
            Ok(crate::test_support::json_ok(body))
        }
    }

    #[test]
    fn an_ipv6_address_is_looked_up_as_written() {
        let looked_up = lookup(
            &AsRobtexAnswered,
            &Keys::default(),
            Indicator::Ip("2606:4700:4700::1111"),
            1,
        );
        let f = looked_up
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("Robtex knows the address"));
        assert_eq!(
            f.summary,
            "Robtex: 2606:4700:4700::/48 via AS13335 Cloudflare"
        );
    }

    #[test]
    fn an_empty_forward_answer_is_a_valid_zero_and_urls_encode_the_value() {
        assert!(matches!(decode_forward(b"[]", "example.com"), Ok(None)));
        assert!(matches!(decode_forward(b"\n", "example.com"), Ok(None)));
        assert_eq!(
            url(Indicator::Domain("example.com")).as_deref(),
            Some("https://freeapi.robtex.com/pdns/forward/example.com")
        );
        assert!(url(Indicator::Email("a@example.com")).is_none());
    }
}
