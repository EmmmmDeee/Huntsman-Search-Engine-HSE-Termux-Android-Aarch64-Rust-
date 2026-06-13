//! Pure domain-to-geography inference helpers.

use super::tables::{CCTLD_REGIONS, REGIONAL_PROVIDERS};

pub(super) struct DomainGeo {
    pub(super) region: &'static str,
    pub(super) confidence: f64,
    pub(super) reason: &'static str,
}

pub(super) fn infer_geo_from_email_domain(domain: &str) -> Option<DomainGeo> {
    // AU ccTLDs (.com.au, .net.au, .org.au, .edu.au, .gov.au) are strong country
    // signals — raised from 0.48 to 0.52 so they cross the 0.50 expansion floor
    // and feed the geo-correlation chain.
    CCTLD_REGIONS
        .iter()
        .find(|&&(tld, _)| domain.ends_with(tld))
        .map(|&(tld, region)| DomainGeo {
            region,
            confidence: if tld.ends_with(".au") { 0.52 } else { 0.48 },
            reason: "country-code TLD",
        })
}

pub(super) fn detect_corporate_provider(domain: &str) -> Option<(&'static str, &'static str)> {
    REGIONAL_PROVIDERS
        .iter()
        .find(|&&(pattern, _, _)| domain_has_label_prefix(domain, pattern))
        .map(|&(_, provider, region)| (provider, region))
}

/// True if `pattern` (a provider brand token such as `bigpond` or `tpg.com`)
/// begins a host label in `domain` — i.e. it occurs at the start, or right after
/// a label separator. Unlike the suffix-anchored `CONSUMER_PROVIDERS` check, the
/// regional brand tokens carry no fixed TLD (`bigpond` → `bigpond.com.au`,
/// `bigpond.net.au`), so the match stays substring-based but must start a label.
///
/// The left boundary is the fix for the mid-label false positives a plain
/// `contains` produced: `campbell.net` does not match `bell.net`, `platt.net`
/// does not match `att.net`, while `bigpond.com.au` and `mail.bigpond.com`
/// (subdomain) still match.
fn domain_has_label_prefix(domain: &str, pattern: &str) -> bool {
    let h = domain.as_bytes();
    let mut from = 0;
    while let Some(rel) = domain[from..].find(pattern) {
        let at = from + rel;
        // Start of string, or the preceding char cannot be part of a label
        // (`.`/`/`/`@`/… qualify; an alphanumeric or `-` means we are mid-label).
        let starts_label = at == 0 || {
            let p = h[at - 1];
            !(p.is_ascii_alphanumeric() || p == b'-')
        };
        if starts_label {
            return true;
        }
        from = at + 1;
    }
    false
}
