//! Extract the host (full hostname including subdomains) from a `Url` seed — pure offline, zero
//! network. Discovered URLs (from Gravatar, Wikidata, contact profiles, code
//! repos, breach records) are first-class entities that expand to `TargetKind::Url`,
//! but several downstream modules (`doh_resolver`, `wayback`, `cert_intel`,
//! `crtsh`) accept `TargetKind::Domain` directly and would be skipped unless
//! the domain is explicitly surfaced as its own `Domain` entity.
//!
//! This module bridges that gap: for every URL target it emits the bare host as
//! a `Domain` entity at high confidence (the URL was already observed — its host
//! is a proven fact). The Domain entity then seeds the full domain intelligence
//! stack in the next expansion round (`doh_resolver`, `rdap_domain`, `whois`,
//! `cert_intel`, `crtsh`, `subdomain_takeover`, …) without any paid quota.
//!
//! Bare IPv4 / IPv6 hosts are emitted as `IpAddress` instead — they carry no
//! domain-stack value but feed the IP intelligence stack (`geo_intel`,
//! `abuseipdb`, `shodan`, `ripestat`, …).
//!
//! Deliberately *no network* — confidence is derived from the URL's presence in
//! the graph, not from a live check. Priority 97 runs before costly domain
//! modules so the Domain seed is ready in the same expansion round.

use async_trait::async_trait;

use crate::core::{confidence, 
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "url_extract";

/// Confidence of the extracted domain. High — the URL that contains it was
/// already an observed entity, so the host is a proven fact, not a guess.
const DOMAIN_CONF: f64 = confidence::HIGH_PLUSPLUS;

pub struct UrlExtract;

/// Return the bare host of `url` and a flag indicating whether it looks like an
/// IP address (`true`) or a domain name (`false`).
///
/// Returns `None` when no usable host can be extracted (e.g. bare paths,
/// single-label hosts, malformed input).
fn extract_host(url: &str) -> Option<(String, bool)> {
    let host = crate::util::url_util::host_from_url(url)?;
    // IPv6 literals may or may not have brackets stripped by host_from_url;
    // use the presence of `:` as the canonical signal.
    let clean = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let is_ipv6 = host.contains(':');
    let is_ipv4 = !is_ipv6
        && clean.split('.').count() == 4
        && clean
            .split('.')
            .all(|seg| !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit()));
    Some((clean, is_ipv6 || is_ipv4))
}

#[async_trait]
impl Module for UrlExtract {
    fn name(&self) -> &'static str {
        "url_extract"
    }

    fn description(&self) -> &'static str {
        "URL dissection — extracts the host domain or IP to seed the full domain/IP intelligence stack next round"
    }

    fn priority(&self) -> u8 {
        97
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Url)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Web
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Domain, EntityKind::IpAddress];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let Some((host, is_ip)) = extract_host(&target.value) else {
            return Ok(result);
        };
        // Skip known platform/hosting domains — they are not the subject's infrastructure.
        if !is_ip && super::profile_kit::PLATFORM_HOSTS.contains(&host.as_str()) {
            return Ok(result);
        }
        let kind = if is_ip {
            EntityKind::IpAddress
        } else {
            EntityKind::Domain
        };
        let mut e = Entity::new(kind, &host, DOMAIN_CONF, &ctx.scan_id);
        e.tag("derived");
        e.tag("url-extracted");
        e.add_evidence(
            Evidence::new(SRC, format!("Host extracted from URL '{}'", target.value))
                .with_attr("source_url", &target.value)
                .with_attr("derivation", "url_host_extraction"),
        );
        result.push(e);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::Target;

    fn host(url: &str) -> Option<(String, bool)> {
        extract_host(url)
    }

    #[test]
    fn extracts_domain() {
        let (h, ip) = host("https://github.com/jdoe/repo").unwrap();
        assert_eq!(h, "github.com");
        assert!(!ip);
    }

    #[test]
    fn extracts_subdomain() {
        let (h, ip) = host("https://api.example.org/v1/users").unwrap();
        assert_eq!(h, "api.example.org");
        assert!(!ip);
    }

    #[test]
    fn extracts_ipv4() {
        let (h, ip) = host("http://192.168.1.1/admin").unwrap();
        assert_eq!(h, "192.168.1.1");
        assert!(ip);
    }

    #[test]
    fn rejects_single_label() {
        // host_from_url returns None when no dot is present.
        assert!(host("http://localhost/foo").is_none());
    }

    #[test]
    fn accepts_url_target() {
        let m = UrlExtract;
        assert!(m.accepts(&Target::new(TargetKind::Url, "https://x.com/a")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }
}
