//! sub.md: keyless passive subdomain enumeration.
//!
//! One lookup is one `GET https://api.sub.md/v1/search?apex={domain}`.
//! No key for 50 queries/day. Returns plain-text subdomains, one per line.
//! Combines Certificate Transparency, passive DNS, and X.509 data.
//! HTTP 429 is a rate limit.
//!
//! Runs alongside crt.sh and `HackerTarget`. Everything the answer holds is kept as `raw_answer`.

use crate::api_leg::{self, Answer, Api, LegError};
use crate::http::{Transport, percent_encode_component};
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, PivotKind, Source};
use crate::keys::Keys;

pub const SOURCE: &str = "submd";
pub const API: Api = Api {
    source: SOURCE,
    provider: "sub.md",
    origin: "https://api.sub.md:443",
    key: None,
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Domain],
    lookup,
};

/// Hosts kept per finding; the count covers all of them.
const MAX_NAMES: usize = 100;

/// The request URL for a domain. **Pure.**
#[must_use]
pub fn url(domain: &str) -> String {
    format!(
        "https://api.sub.md/v1/search?apex={}",
        percent_encode_component(domain)
    )
}

/// Look the domain up.
///
/// # Errors
/// The [`LegError`] that stopped the lookup.
pub fn lookup(
    transport: &dyn Transport,
    keys: &Keys,
    indicator: Indicator<'_>,
    now_unix: u64,
) -> Result<Option<Finding>, LegError> {
    let Indicator::Domain(domain) = indicator else {
        return Ok(None);
    };
    let url = url(domain);
    match api_leg::get(transport, &API, keys, &url, now_unix)? {
        Answer::Body(body) => decode(&body, domain),
        Answer::NotFound(_) => Ok(None),
    }
}

/// One answer body. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not UTF-8.
pub fn decode(body: &[u8], domain: &str) -> Result<Option<Finding>, LegError> {
    let text = std::str::from_utf8(body)
        .map_err(|_| LegError::Decode("answer is not UTF-8".into()))?
        .trim();
    if text.is_empty() {
        return Ok(None);
    }
    let suffix = format!(".{}", domain.to_ascii_lowercase());
    let mut hosts: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in text.lines() {
        let host = line.trim();
        if host.is_empty() {
            continue;
        }
        let lower = host.to_ascii_lowercase();
        if !lower.ends_with(&suffix) || seen.contains(&lower) {
            continue;
        }
        seen.insert(lower);
        if hosts.len() < MAX_NAMES {
            if let Some(clean) = api_leg::clean(Some(host)) {
                hosts.push(clean);
            }
        }
    }
    let total = seen.len();
    if total == 0 {
        return Ok(None);
    }
    let mut finding = Finding::new(format!(
        "sub.md: {total} subdomain{}",
        if total == 1 { "" } else { "s" }
    ))
    .attr("hosts", total.to_string())
    .list_attr("names", &hosts)
    .tag_if(total > hosts.len(), "truncated");
    for host in &hosts {
        finding = finding.pivot(
            PivotKind::Domain,
            host,
            "Subdomain sub.md finds under the domain",
        );
    }
    finding = finding.attr("raw_answer", text);
    Ok(Some(finding))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_text_answer_keeps_hosts_and_raw() {
        let body = b"www.example.com\napi.example.com\nmail.example.com\n";
        let f = decode(body, "example.com").unwrap().unwrap();
        assert!(f.summary.contains('3'));
        assert!(
            f.attrs
                .iter()
                .any(|(k, v)| *k == "raw_answer" && v.contains("www.example.com"))
        );
    }

    #[test]
    fn case_and_duplicates_are_folded() {
        let body = b"WWW.EXAMPLE.COM\nwww.example.com\n";
        let f = decode(body, "example.com").unwrap().unwrap();
        assert!(f.summary.contains('1'));
    }

    #[test]
    fn a_suffix_without_boundary_is_rejected() {
        let body = b"notexample.com\n";
        assert!(decode(body, "example.com").unwrap().is_none());
    }

    #[test]
    fn empty_or_unrelated_is_none() {
        assert!(decode(b"", "example.com").unwrap().is_none());
        assert!(decode(b"other.com\n", "example.com").unwrap().is_none());
    }
}
