//! `HackerTarget`: hosts under one domain, and domains hosted on one IP address.
//!
//! A domain is one `GET https://api.hackertarget.com/hostsearch/?q={domain}`, answering
//! `host,address` lines; an address is one `GET https://api.hackertarget.com/reverseiplookup/?q={ip}`,
//! answering one host per line; it refuses an IPv6 address ("error check your search parameter"),
//! so the source answers for IPv4 addresses only. Both answer without a key at a small daily limit; with
//! `HUNTSMAN_HACKERTARGET_KEY` set, the key goes in the `apikey` query parameter (added as the
//! request is sent) and the membership limit applies. Everything is kept: every line of the
//! answer as a JSON list in `raw_answer`, how many distinct hosts there are, every one of them
//! in `names`, and for a domain every distinct address in `addresses` and every `host address`
//! pair in `host_addresses`. Each host and address is also a pivot. The service answers its
//! errors as text with status 200: a spent quota is a rate limit, and "no
//! records" or an unresolvable host is a valid zero. Anything else must be the list itself: a
//! `host,address` line per host for a domain, a domain name per line for an address. A body
//! with no such line (an HTML or JSON page, or nothing at all) is drift, and so is a 404, which
//! the service gives only for a path it does not have (checked 2026-10-15), never "not found".

use std::collections::HashSet;
use std::net::IpAddr;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::canonical::canonical_domain;
use crate::http::{Transport, percent_encode_component};
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, PivotKind, Source};
use crate::keys::Keys;

pub const SOURCE: &str = "hackertarget";
pub const KEY_SLOT: &str = crate::environment::HACKERTARGET_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "hackertarget.com",
    origin: "https://api.hackertarget.com:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Query("apikey"),
        required: false,
    }),
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Domain, IndicatorKind::Ipv4],
    lookup,
};

/// The request URL for `indicator`, or `None` when it is not a domain or address. **Pure.**
#[must_use]
pub fn url(indicator: Indicator<'_>) -> Option<String> {
    let (path, value) = match indicator {
        Indicator::Domain(domain) => ("hostsearch", domain),
        Indicator::Ip(ip) => ("reverseiplookup", ip),
        _ => return None,
    };
    Some(format!(
        "https://api.hackertarget.com/{path}/?q={}",
        percent_encode_component(value)
    ))
}

/// Look `indicator` up; a domain or address is a `HackerTarget` lookup.
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

/// One answer body for `indicator`. **Pure.**
///
/// # Errors
/// [`LegError::RateLimited`] for a spent quota; [`LegError::Decode`] for any other error text,
/// a body that is not UTF-8, or one with no host line.
pub fn decode(body: &[u8], indicator: Indicator<'_>) -> Result<Option<Finding>, LegError> {
    let text = std::str::from_utf8(body)
        .map_err(|_| LegError::Decode("answer is not UTF-8".into()))?
        .trim();
    let first = text
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if first.is_empty() {
        return Err(LegError::Decode("HackerTarget: empty answer".into()));
    }
    if first.starts_with("no ") || first == "error invalid host" {
        return Ok(None);
    }
    if first.starts_with("api count exceeded") {
        return Err(LegError::RateLimited { retry_after: None });
    }
    if first.starts_with("error") {
        let reason = api_leg::clean(Some(&first)).unwrap_or_default();
        return Err(LegError::Decode(format!("HackerTarget: {reason}")));
    }
    let (Indicator::Domain(own) | Indicator::Ip(own)) = indicator else {
        return Ok(None);
    };
    let mut records = 0usize;
    let mut lines: Vec<&str> = Vec::new();
    let mut hosts = Distinct::default();
    let mut addresses = Distinct::default();
    let mut pairs = Distinct::default();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        lines.push(line);
        let Some((host, address)) = record(line, indicator) else {
            continue;
        };
        records += 1;
        let host = api_leg::clean(Some(host));
        let address = api_leg::clean(Some(address));
        if let Some(host) = host.as_deref().filter(|h| !h.eq_ignore_ascii_case(own)) {
            hosts.push(host);
        }
        if let Some(address) = address.as_deref() {
            addresses.push(address);
            if let Some(host) = host.as_deref() {
                pairs.push(&format!("{host} {address}"));
            }
        }
    }
    if records == 0 {
        return Err(LegError::Decode(
            "HackerTarget: the answer is not a host list".into(),
        ));
    }
    if hosts.values.is_empty() && addresses.values.is_empty() {
        return Ok(None);
    }
    let total = hosts.values.len();
    let (what, why) = match indicator {
        Indicator::Ip(_) => ("domain", "Domain HackerTarget finds hosted on the address"),
        _ => ("host", "Host HackerTarget finds under the domain"),
    };
    let mut finding = Finding::new(format!(
        "HackerTarget: {total} {what}{}",
        if total == 1 { "" } else { "s" }
    ))
    .attr("hosts", total.to_string())
    .list_attr("names", &hosts.values)
    .list_attr("addresses", &addresses.values)
    .list_attr("host_addresses", &pairs.values)
    .attr("raw_answer", serde_json::Value::from(lines).to_string());
    let (hosts, addresses) = (hosts.values, addresses.values);
    for host in &hosts {
        finding = finding.pivot(PivotKind::Domain, host, why);
    }
    for address in &addresses {
        finding = finding.pivot(
            PivotKind::Ip,
            address,
            "Address HackerTarget finds for a host under the domain",
        );
    }
    Ok(Some(finding))
}

/// Values in the order first given, each once (hosts compared without case). **Pure.**
#[derive(Default)]
struct Distinct {
    values: Vec<String>,
    seen: HashSet<String>,
}

impl Distinct {
    fn push(&mut self, value: &str) {
        if self.seen.insert(value.to_ascii_lowercase()) {
            self.values.push(value.to_owned());
        }
    }
}

/// One line of the list as `(host, address)`, or `None` when it is not one: for a domain a
/// `host,address` line whose address is an IP address, for an address a domain name. **Pure.**
fn record<'a>(line: &'a str, indicator: Indicator<'_>) -> Option<(&'a str, &'a str)> {
    match indicator {
        Indicator::Domain(_) => {
            let (host, address) = line.split_once(',')?;
            (!host.trim().is_empty() && address.trim().parse::<IpAddr>().is_ok())
                .then_some((host, address))
        }
        _ => canonical_domain(line).map(|_| (line, "")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded for `github.com` on 2026-10-14, shortened.
    const HOSTS: &str = "github.com,140.82.112.4\naccelerator.github.com,185.199.110.153\naccessibility.github.com,185.199.111.153\naccessibility.github.com,185.199.111.153\n";

    /// Recorded for `93.184.215.14` on 2026-10-14, shortened.
    const REVERSE: &str = "dango.ge\ndlai.link\nstick.to\n";

    #[test]
    fn a_domain_keeps_distinct_hosts_and_addresses_but_not_itself() {
        let f = decode(HOSTS.as_bytes(), Indicator::Domain("github.com"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        assert_eq!(f.summary, "HackerTarget: 2 hosts");
        let hosts: Vec<&str> = f
            .pivots
            .iter()
            .filter(|p| p.kind == PivotKind::Domain)
            .map(|p| p.value.as_str())
            .collect();
        assert_eq!(
            hosts,
            ["accelerator.github.com", "accessibility.github.com"]
        );
        assert_eq!(
            f.pivots.iter().filter(|p| p.kind == PivotKind::Ip).count(),
            3
        );
    }

    #[test]
    fn a_domain_keeps_every_host_address_pair_and_the_whole_answer() {
        let f = decode(HOSTS.as_bytes(), Indicator::Domain("github.com"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        let value = |key: &str| {
            f.attrs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(
            value("host_addresses"),
            Some(
                "github.com 140.82.112.4,accelerator.github.com 185.199.110.153,accessibility.github.com 185.199.111.153"
            )
        );
        assert_eq!(
            value("addresses"),
            Some("140.82.112.4,185.199.110.153,185.199.111.153")
        );
        let raw: Vec<String> = value("raw_answer")
            .and_then(|raw| serde_json::from_str(raw).ok())
            .unwrap_or_default();
        assert_eq!(raw.len(), 4, "every line, the repeated one too");
        assert_eq!(raw[0], "github.com,140.82.112.4");
    }

    #[test]
    fn every_host_is_kept_and_counted_once() {
        let lines: Vec<String> = (0..300)
            .flat_map(|n| {
                let address = n % 200;
                [
                    format!("host-{n}.example.com,192.0.2.{address}"),
                    format!("HOST-{n}.example.com,192.0.2.{address}"),
                ]
            })
            .collect();
        let body = lines.join("\n");
        let f = decode(body.as_bytes(), Indicator::Domain("example.com"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("a long list must decode"));
        assert_eq!(f.summary, "HackerTarget: 300 hosts");
        let count = |key: &str| {
            f.attrs
                .iter()
                .find(|(k, _)| *k == key)
                .map_or(0, |(_, v)| v.split(',').count())
        };
        assert_eq!(count("names"), 300);
        assert_eq!(count("addresses"), 200);
        assert_eq!(count("host_addresses"), 300);
        assert!(!f.tags.contains(&"truncated"));
    }

    #[test]
    fn an_address_lists_the_domains_hosted_on_it() {
        let f = decode(REVERSE.as_bytes(), Indicator::Ip("93.184.215.14"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        assert_eq!(f.summary, "HackerTarget: 3 domains");
        assert!(f.pivots.iter().all(|p| p.kind == PivotKind::Domain));
    }

    #[test]
    fn error_text_is_a_zero_a_rate_limit_or_an_error() {
        let d = Indicator::Domain("example.com");
        assert!(matches!(decode(b"error invalid host", d), Ok(None)));
        assert!(matches!(decode(b"No records found", d), Ok(None)));
        assert!(matches!(
            decode(b"API count exceeded - Increase Quota with Membership", d),
            Err(LegError::RateLimited { .. })
        ));
        assert!(matches!(
            decode(b"error check your search parameter", d),
            Err(LegError::Decode(_))
        ));
    }

    /// The page the service gives for a path it does not have, recorded 2026-10-15.
    const NOT_FOUND_PAGE: &str = "<!doctype html>\n<html lang=en>\n<title>404 Not Found</title>\n<h1>Not Found</h1>\n<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>\n";

    #[test]
    fn a_page_that_is_not_a_host_list_is_drift_never_hosts_or_a_zero() {
        for indicator in [
            Indicator::Domain("example.com"),
            Indicator::Ip("93.184.215.14"),
        ] {
            for body in [
                NOT_FOUND_PAGE,
                "{\"error\": \"maintenance\"}",
                "Service temporarily unavailable, please retry",
                "",
                " \n",
            ] {
                let decoded = decode(body.as_bytes(), indicator);
                assert!(
                    matches!(decoded, Err(LegError::Decode(_))),
                    "{indicator:?} {body:?}: {decoded:?}"
                );
            }
        }
        // A line that is not a record does not void the records beside it.
        let mixed = "www.example.com,172.66.147.243\n<!-- cached -->\n";
        let f = decode(mixed.as_bytes(), Indicator::Domain("example.com"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("the record line must decode"));
        assert_eq!(f.summary, "HackerTarget: 1 host");
    }

    #[test]
    fn a_404_is_a_path_the_service_lacks_not_an_empty_answer() {
        let transport = crate::test_support::OneResponse::with_headers(
            404,
            &[("content-type", "text/html; charset=utf-8")],
            NOT_FOUND_PAGE,
        );
        let looked_up = lookup(
            &transport,
            &Keys::default(),
            Indicator::Domain("example.com"),
            1,
        );
        assert!(
            matches!(looked_up, Err(LegError::Unexpected(404))),
            "{looked_up:?}"
        );
        assert_eq!(
            LegError::Unexpected(404).outcome_kind(),
            crate::source_outcome::SourceOutcomeKind::Upstream4xx
        );
    }

    #[test]
    fn urls_encode_the_value_and_ignore_other_kinds() {
        assert_eq!(
            url(Indicator::Ip("2001:db8::1")).as_deref(),
            Some("https://api.hackertarget.com/reverseiplookup/?q=2001%3Adb8%3A%3A1")
        );
        assert!(url(Indicator::Email("a@example.com")).is_none());
    }
}
