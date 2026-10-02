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

use crate::core::{
    confidence,
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
///
/// Uses [`crate::util::url_util::host_only`] rather than the shared
/// `host_from_url` — that helper's "must contain a `.`" gate is the right
/// contract for its other ~30 domain-only callers, but it silently discards
/// every bare IPv6 literal without an embedded IPv4 address (the overwhelming
/// majority of real IPv6 addresses have no `.` at all), which would make this
/// module's own documented "bare IPv4/IPv6 hosts are emitted as `IpAddress`"
/// behavior unreachable for real-world IPv6 hosts. Delegating IP recognition
/// to `Ipv4Addr`/`Ipv6Addr`'s own parsers (rather than a hand-rolled
/// dot-count-and-all-digits check) also fixes a second latent bug: the old
/// check accepted any 4 dot-separated all-digit segments as IPv4 with no
/// octet-range validation, so a malformed host like `999.999.999.999` was
/// wrongly classified as a probeable IP address and would have been handed
/// to the IP-intelligence stack (`geo_intel`, `abuseipdb`, `shodan`, …) as if
/// it were real.
fn extract_host(url: &str) -> Option<(String, bool)> {
    let raw = crate::util::url_util::host_only(url);
    if raw.is_empty() {
        return None;
    }
    let clean = raw
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_lowercase();
    if clean.parse::<std::net::Ipv4Addr>().is_ok() || clean.parse::<std::net::Ipv6Addr>().is_ok() {
        return Some((clean, true));
    }
    if !clean.contains('.') {
        return None;
    }
    Some((clean, false))
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

    /// Pure transform of data already in the graph — no observation of its
    /// own, so its evidence never counts as a corroborating source (see
    /// `Module::is_derivation` / `ENRICHMENT_ONLY_SOURCES`).
    fn is_derivation(&self) -> bool {
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Url)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Web
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Deliberately no network (doc comment): no site fetch/search (T1594)
        // or host fingerprinting (T1592.002) — process() only parses an
        // already-observed URL's host into Domain/IpAddress: T1590.001/.005.
        &["T1590.001", "T1590.005"]
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
        let (h, ip) = host("https://github.com/jdoe/repo").expect("should succeed");
        assert_eq!(h, "github.com");
        assert!(!ip);
    }

    #[test]
    fn extracts_subdomain() {
        let (h, ip) = host("https://api.example.org/v1/users").expect("should succeed");
        assert_eq!(h, "api.example.org");
        assert!(!ip);
    }

    #[test]
    fn extracts_ipv4() {
        let (h, ip) = host("http://192.168.1.1/admin").expect("should succeed");
        assert_eq!(h, "192.168.1.1");
        assert!(ip);
    }

    #[test]
    fn extracts_a_bare_ipv6_literal_with_no_embedded_ipv4() {
        // Regression: `host_from_url`'s shared "must contain a `.`" domain
        // gate silently discards a bare IPv6 literal before this module's
        // own IPv6-recognition logic ever ran, so real-world IPv6 hosts
        // (which almost never contain a `.`) were never emitted as
        // `IpAddress` despite the module doc explicitly promising that.
        let (h, ip) = host("http://[2001:db8::1]/path").expect("should succeed");
        assert_eq!(h, "2001:db8::1");
        assert!(ip);
    }

    #[test]
    fn extracts_ipv4_mapped_ipv6() {
        let (h, ip) = host("https://[::ffff:192.0.2.128]:8443/x").expect("should succeed");
        assert_eq!(h, "::ffff:192.0.2.128");
        assert!(ip);
    }

    #[test]
    fn a_malformed_dotted_quad_with_out_of_range_octets_is_not_misclassified_as_ipv4() {
        // Regression: the old check only verified 4 dot-separated all-digit
        // segments, with no octet-range validation, so a nonsensical host
        // like this was wrongly tagged `IpAddress` and would have been
        // handed to real IP-intelligence lookups as if it were valid.
        let (h, ip) = host("http://999.999.999.999/x").expect("should succeed");
        assert_eq!(h, "999.999.999.999");
        assert!(!ip, "not a valid IPv4 address — octets exceed 255");
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
