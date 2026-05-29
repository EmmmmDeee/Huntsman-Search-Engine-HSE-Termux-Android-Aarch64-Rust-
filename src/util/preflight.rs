//! Shared pre-flight validators for API-quota-spending modules.
//!
//! Modules that hit external paid APIs (`see_know`, `oathnet_pro`,
//! future providers) all need to reject obviously-junk targets
//! before burning a query. Centralised here so the policy stays
//! consistent across providers — a value that's a "placeholder
//! username" for SeekNow must be one for OathNet too.

/// True if `ip` should be skipped for an external IPv4-only lookup
/// (rate-limited public APIs that don't yet support IPv6 — ip-api.com,
/// ipinfo.io, ipquery.io etc.).
///
/// Combines the three rejection cases that every IPv4-targeting
/// module previously hand-rolled inline: empty input, an IPv6 form
/// the IPv4-only URL fmt would mangle, and any private / reserved
/// range that won't return meaningful intel. Single call replaces
/// the `if ip.is_empty() || ip.contains(':') { ... }` boilerplate.
pub fn should_skip_external_ipv4(ip: &str) -> bool {
    let trimmed = ip.trim();
    if trimmed.is_empty() || trimmed.contains(':') {
        return true;
    }
    is_private_ip(trimmed)
}

/// True if `ip` should be skipped for an external lookup that supports
/// either IPv4 or IPv6. Used by the engine's universal dispatcher gate
/// — modules whose upstream supports v6 (shodan, censys, RDAP, etc.)
/// should NOT have public IPv6 silently rejected.
///
/// Rejection cases:
///   - empty / whitespace
///   - private / reserved IPv4 (10/8, 172.16/12, 192.168/16, 127/8,
///     169.254/16, CGNAT 100.64/10, multicast, broadcast)
///   - private / reserved IPv6 (loopback, unspecified, multicast,
///     unique-local fc00::/7, link-local fe80::/10)
///
/// Returns FALSE for fully-public IPv6 like `2606:4700:4700::1111`.
pub fn should_skip_external_ip(ip: &str) -> bool {
    let trimmed = ip.trim();
    if trimmed.is_empty() {
        return true;
    }
    is_private_ip(trimmed)
}

/// True if the IP string is one of the private / reserved ranges
/// that won't yield meaningful intel from external lookup APIs.
///
/// Covers IPv4 loopback (127/8), private (10/8, 172.16/12, 192.168/16),
/// link-local (169.254/16), broadcast, unspecified (0/8), multicast,
/// and the CGNAT range (100.64/10), plus IPv6 loopback (::1),
/// unspecified (::), multicast (ff00::/8), unique-local (fc00::/7),
/// and link-local (fe80::/10).
///
/// Returns false for any string that doesn't parse as an IP — callers
/// that want stricter shape rejection should validate separately.
pub fn is_private_ip(ip: &str) -> bool {
    let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
        return false;
    };
    match addr {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
                // CGNAT (100.64.0.0/10)
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64)
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Unique-local (fc00::/7)
                || (v6.octets()[0] == 0xfc || v6.octets()[0] == 0xfd)
                // Link-local (fe80::/10)
                || (v6.octets()[0] == 0xfe && (v6.octets()[1] & 0xC0) == 0x80)
        }
    }
}

/// Returns `Some(reason)` if `ip` falls in a government / military or otherwise
/// sensitive reserved range that must **never** be probed, validated, or routed
/// through (e.g. when sourcing proxies). Conservative and best-effort: it denies
/// all private/reserved space *and* the well-documented IANA `/8` blocks
/// allocated to the US Department of Defense. A complete global government-range
/// map is not publicly enumerable, so this covers the prominent, well-known
/// cases plus all reserved space rather than claiming completeness.
pub fn sensitive_range_reason(ip: &str) -> Option<&'static str> {
    let addr = ip.trim().parse::<std::net::IpAddr>().ok()?;
    if is_private_ip(ip) {
        return Some("private/reserved range");
    }
    if let std::net::IpAddr::V4(v4) = addr {
        let o = v4.octets();
        // IANA /8 blocks allocated to the US Department of Defense.
        const DOD_SLASH8: &[u8] = &[6, 7, 11, 21, 22, 26, 28, 29, 30, 33, 55, 214, 215];
        if DOD_SLASH8.contains(&o[0]) {
            return Some("US DoD / government range");
        }
        if o[0] >= 240 {
            return Some("reserved (240.0.0.0/4)");
        }
        if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
            return Some("benchmarking (198.18.0.0/15)");
        }
        if v4.is_documentation() {
            return Some("documentation range");
        }
    }
    None
}

/// True if the domain is one of the IANA-reserved special-use names
/// (RFC 6761 / 6762) that should never reach external intel APIs.
///
/// Comparison is case-insensitive and tolerant of trailing-dot
/// canonical form.
pub fn is_local_domain(domain: &str) -> bool {
    let d = domain.strip_suffix('.').unwrap_or(domain);
    let d_lc = d.to_ascii_lowercase();
    d_lc == "localhost"
        || d_lc.ends_with(".local")
        || d_lc.ends_with(".lan")
        || d_lc.ends_with(".internal")
        || d_lc.ends_with(".home")
        || d_lc.ends_with(".arpa")
        || d_lc.ends_with(".test")
        || d_lc.ends_with(".invalid")
        || d_lc.ends_with(".example")
        || d_lc.ends_with(".localhost")
}

/// True if the string is one of the placeholder usernames that breach
/// corpora pad records with (e.g. `"admin"`, `"test"`, `"n/a"`).
///
/// Generous superset of the two former in-module lists in
/// `modules/see_know` and `modules/oathnet_pro` — combining them
/// ensures both providers reject the same noise.
pub fn is_placeholder_username(u: &str) -> bool {
    let lower = u.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "anonymous"
            | "anon"
            | "user"
            | "admin"
            | "test"
            | "testing"
            | "demo"
            | "guest"
            | "root"
            | "username"
            | "default"
            | "example"
            | "null"
            | "undefined"
            | "none"
            | "n/a"
            | "na"
            | "unknown"
            | "tbd"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── sensitive_range_reason (gov / reserved deny-list) ──────────────────

    #[test]
    fn sensitive_ranges_are_denied() {
        // US DoD /8 blocks.
        for ip in [
            "6.1.2.3",
            "7.0.0.1",
            "11.22.33.44",
            "22.1.1.1",
            "55.9.9.9",
            "214.0.0.1",
        ] {
            assert!(
                sensitive_range_reason(ip).is_some(),
                "{ip} should be denied (DoD)"
            );
        }
        // Reserved / benchmarking / private.
        assert!(sensitive_range_reason("240.0.0.1").is_some());
        assert!(sensitive_range_reason("198.18.0.5").is_some());
        assert!(sensitive_range_reason("10.0.0.1").is_some());
        assert!(sensitive_range_reason("127.0.0.1").is_some());
    }

    #[test]
    fn ordinary_public_ips_are_allowed() {
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "203.0.113.1".trim_end(),
            "45.33.32.156",
        ] {
            // (203.0.113.0/24 is documentation → denied; use a real public one)
            if ip == "203.0.113.1" {
                continue;
            }
            assert!(
                sensitive_range_reason(ip).is_none(),
                "{ip} should be allowed"
            );
        }
        // Non-IPs don't match (caller validates shape separately).
        assert!(sensitive_range_reason("not-an-ip").is_none());
    }

    // ── is_private_ip ──────────────────────────────────────────────────────

    #[test]
    fn private_v4_rejected() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.1.1",
            "255.255.255.255",
            "0.0.0.0",
            "224.0.0.1",
            "100.64.0.1", // CGNAT
            "100.127.255.255",
        ] {
            assert!(is_private_ip(ip), "expected {ip} private");
        }
    }

    #[test]
    fn public_v4_accepted() {
        for ip in ["1.1.1.1", "8.8.8.8", "203.0.113.5", "13.107.42.14"] {
            assert!(!is_private_ip(ip), "expected {ip} public");
        }
    }

    #[test]
    fn private_v6_rejected() {
        for ip in ["::1", "::", "ff00::1", "fc00::1", "fd12::1", "fe80::1"] {
            assert!(is_private_ip(ip), "expected {ip} private");
        }
    }

    #[test]
    fn public_v6_accepted() {
        assert!(!is_private_ip("2606:4700:4700::1111"));
        assert!(!is_private_ip("2001:4860:4860::8888"));
    }

    #[test]
    fn non_ip_strings_return_false() {
        assert!(!is_private_ip(""));
        assert!(!is_private_ip("not-an-ip"));
        assert!(!is_private_ip("999.999.999.999"));
    }

    // ── should_skip_external_ipv4 ───────────────────────────────────────

    #[test]
    fn should_skip_combines_empty_v6_and_private_cases() {
        // Empty / whitespace
        assert!(should_skip_external_ipv4(""));
        assert!(should_skip_external_ipv4("   "));
        // IPv6 (URL-fmt would break on IPv4-only APIs)
        assert!(should_skip_external_ipv4("::1"));
        assert!(should_skip_external_ipv4("2001:db8::1"));
        // Private v4
        assert!(should_skip_external_ipv4("10.0.0.1"));
        assert!(should_skip_external_ipv4("192.168.1.1"));
        assert!(should_skip_external_ipv4("127.0.0.1"));
        assert!(should_skip_external_ipv4("100.64.0.1")); // CGNAT
    }

    #[test]
    fn should_skip_lets_public_v4_through() {
        assert!(!should_skip_external_ipv4("1.1.1.1"));
        assert!(!should_skip_external_ipv4("8.8.8.8"));
        assert!(!should_skip_external_ipv4("13.107.42.14"));
    }

    // ── should_skip_external_ip (v6-tolerant universal gate) ──────────────

    #[test]
    fn should_skip_external_ip_rejects_empty_and_private() {
        assert!(should_skip_external_ip(""));
        assert!(should_skip_external_ip("  "));
        assert!(should_skip_external_ip("10.0.0.1"));
        assert!(should_skip_external_ip("192.168.1.1"));
        assert!(should_skip_external_ip("127.0.0.1"));
        assert!(should_skip_external_ip("::1"));
        assert!(should_skip_external_ip("fc00::1"));
        assert!(should_skip_external_ip("fe80::1"));
    }

    #[test]
    fn should_skip_external_ip_lets_public_v6_through() {
        // Public IPv6 must NOT be rejected by the universal gate —
        // modules like shodan/censys/RDAP support v6 lookups.
        assert!(!should_skip_external_ip("2606:4700:4700::1111"));
        assert!(!should_skip_external_ip("2001:4860:4860::8888"));
    }

    #[test]
    fn should_skip_external_ip_lets_public_v4_through() {
        assert!(!should_skip_external_ip("1.1.1.1"));
        assert!(!should_skip_external_ip("8.8.8.8"));
    }

    // ── is_local_domain ────────────────────────────────────────────────────

    #[test]
    fn local_domains_rejected() {
        for d in [
            "localhost",
            "localhost.",
            "LOCALHOST",
            "router.local",
            "host.lan",
            "intra.internal",
            "device.home",
            "anything.arpa",
            "site.test",
            "x.invalid",
            "y.example",
            "z.localhost",
        ] {
            assert!(is_local_domain(d), "expected {d} local");
        }
    }

    #[test]
    fn public_domains_accepted() {
        for d in [
            "example.com",
            "google.com",
            "sub.target-company.com.au",
            "wikipedia.org",
        ] {
            assert!(!is_local_domain(d), "expected {d} public");
        }
    }

    // ── is_placeholder_username ───────────────────────────────────────────

    #[test]
    fn known_placeholders_rejected() {
        for u in [
            "admin",
            "Admin",
            "ADMIN",
            "test",
            "testing",
            "user",
            "anonymous",
            "anon",
            "demo",
            "guest",
            "root",
            "username",
            "default",
            "example",
            "null",
            "undefined",
            "none",
            "n/a",
            "na",
            "unknown",
            "tbd",
        ] {
            assert!(is_placeholder_username(u), "expected {u} placeholder");
        }
    }

    #[test]
    fn real_usernames_accepted() {
        for u in [
            "alice",
            "jordanleighmeyers",
            "j_doe23",
            "h4ck3r",
            "BobSmith",
        ] {
            assert!(!is_placeholder_username(u), "expected {u} real");
        }
    }
}
