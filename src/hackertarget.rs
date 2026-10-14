//! `HackerTarget`: hosts under one domain, and domains hosted on one IP address.
//!
//! A domain is one `GET https://api.hackertarget.com/hostsearch/?q={domain}`, answering
//! `host,address` lines; an address is one `GET https://api.hackertarget.com/reverseiplookup/?q={ip}`,
//! answering one host per line. Both answer without a key at a small daily limit; with
//! `HUNTSMAN_HACKERTARGET_KEY` set, the key goes in the `apikey` query parameter (added as the
//! request is sent) and the membership limit applies. Kept: how many hosts there are, and up to
//! [`MAX_NAMES`] of them (and, for a domain, their distinct addresses), each also a pivot. The
//! service answers its errors as text with status 200: a spent quota is a rate limit, and "no
//! records" or an unresolvable host is a valid zero.

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
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
    kinds: &[IndicatorKind::Domain, IndicatorKind::Ip],
    lookup,
};

/// Hosts and addresses kept per finding; the count covers all of them.
const MAX_NAMES: usize = 25;

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
        Answer::NotFound(_) => Ok(None),
    }
}

/// One answer body for `indicator`. **Pure.**
///
/// # Errors
/// [`LegError::RateLimited`] for a spent quota; [`LegError::Decode`] for any other error text
/// or a body that is not UTF-8.
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
    if first.is_empty() || first.starts_with("no ") || first == "error invalid host" {
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
    let mut total = 0usize;
    let mut hosts: Vec<String> = Vec::new();
    let mut addresses: Vec<String> = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let (host, address) = line.split_once(',').unwrap_or((line, ""));
        if let Some(host) = api_leg::clean(Some(host)).filter(|h| !h.eq_ignore_ascii_case(own)) {
            if !hosts.iter().any(|h| h.eq_ignore_ascii_case(&host)) {
                total += 1;
                if hosts.len() < MAX_NAMES {
                    hosts.push(host);
                }
            }
        }
        if let Some(address) = api_leg::clean(Some(address)) {
            if !addresses.contains(&address) && addresses.len() < MAX_NAMES {
                addresses.push(address);
            }
        }
    }
    if total == 0 && addresses.is_empty() {
        return Ok(None);
    }
    let (what, why) = match indicator {
        Indicator::Ip(_) => ("domain", "Domain HackerTarget finds hosted on the address"),
        _ => ("host", "Host HackerTarget finds under the domain"),
    };
    let mut finding = Finding::new(format!(
        "HackerTarget: {total} {what}{}",
        if total == 1 { "" } else { "s" }
    ))
    .attr("hosts", total.to_string())
    .list_attr("names", &hosts)
    .list_attr("addresses", &addresses)
    .tag_if(total > hosts.len(), "truncated");
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

    #[test]
    fn urls_encode_the_value_and_ignore_other_kinds() {
        assert_eq!(
            url(Indicator::Ip("2001:db8::1")).as_deref(),
            Some("https://api.hackertarget.com/reverseiplookup/?q=2001%3Adb8%3A%3A1")
        );
        assert!(url(Indicator::Email("a@example.com")).is_none());
    }
}
