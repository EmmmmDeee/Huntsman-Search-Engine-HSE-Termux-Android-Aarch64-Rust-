//! Pure domain-to-geography inference helpers.

use super::tables::{CCTLD_REGIONS, REGIONAL_PROVIDERS};

/// A region inferred from an email domain, with the confidence and the human
/// `reason` that produced it (for the emitted evidence).
pub(super) struct DomainGeo {
    pub(super) region: &'static str,
    pub(super) confidence: f64,
    pub(super) reason: &'static str,
}

/// Infer a region from an email domain's **country-code TLD** (`.com.au` → AU,
/// etc.). AU ccTLDs are weighted `0.52` — deliberately above the confidence::MEDIUM expansion
/// floor so the inferred region feeds the geo-correlation chain — versus `0.48`
/// for other ccTLDs. `None` when the domain carries no recognised ccTLD.
pub(super) fn infer_geo_from_email_domain(domain: &str) -> Option<DomainGeo> {
    CCTLD_REGIONS
        .iter()
        .find(|&&(tld, _)| domain.ends_with(tld))
        .map(|&(tld, region)| DomainGeo {
            region,
            confidence: if tld.ends_with(".au") { 0.52 } else { 0.48 },
            reason: "country-code TLD",
        })
}

/// Map a domain whose host carries a **regional ISP/provider brand**
/// (`bigpond` → Telstra/AU, `tpg` → TPG/AU, …) to its `(provider, region)`, even
/// when the brand uses a generic TLD. Brand-prefix matched ([`domain_has_label_prefix`])
/// so `campbell.net` is not mistaken for `bell.net`. `None` for an unrecognised
/// provider.
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

#[cfg(test)]
mod label_prefix_tests {
    use super::domain_has_label_prefix;

    #[test]
    fn matches_at_start_of_domain() {
        assert!(domain_has_label_prefix("bigpond.com.au", "bigpond"));
        assert!(domain_has_label_prefix("tpg.com.au", "tpg.com"));
    }

    #[test]
    fn matches_after_label_separator_as_subdomain() {
        assert!(domain_has_label_prefix("mail.bigpond.com", "bigpond"));
    }

    #[test]
    fn rejects_mid_label_false_positives() {
        assert!(!domain_has_label_prefix("campbell.net", "bell.net"));
        assert!(!domain_has_label_prefix("platt.net", "att.net"));
    }

    #[test]
    fn rejects_when_pattern_absent() {
        assert!(!domain_has_label_prefix("example.com", "bigpond"));
    }

    #[test]
    fn rejects_when_preceding_char_is_hyphen() {
        assert!(!domain_has_label_prefix("my-att.net", "att.net"));
    }
}
