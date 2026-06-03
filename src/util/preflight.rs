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
///     169.254/16, CGNAT 100.64/10, 0.0.0.0/8, multicast, broadcast)
///   - private / reserved IPv6 (loopback, unspecified, multicast,
///     unique-local fc00::/7, link-local fe80::/10), AND v6 forms that
///     embed a routable IPv4 (IPv4-mapped, NAT64, 6to4, IPv4-compatible)
///     whose embedded v4 is private/reserved.
///
/// Returns FALSE for fully-public IPv6 like `2606:4700:4700::1111`.
pub fn should_skip_external_ip(ip: &str) -> bool {
    let trimmed = ip.trim();
    if trimmed.is_empty() {
        return true;
    }
    is_private_ip(trimmed)
}

/// Core SSRF predicate over a resolved [`std::net::IpAddr`]. Returns true for
/// any address that won't yield meaningful external intel AND that a client must
/// not be tricked into connecting to internally.
///
/// IPv4: loopback (127/8) / RFC1918 (10/8, 172.16/12, 192.168/16) / link-local
/// (169.254/16, incl. cloud metadata) / CGNAT (100.64/10) / "this network"
/// (0.0.0.0/8) / broadcast / multicast.
///
/// IPv6: loopback (::1) / unspecified (::) / multicast (ff00::/8) / unique-local
/// (fc00::/7) / link-local (fe80::/10).
///
/// **Embedded-IPv4 v6 forms.** Several v6 representations carry an IPv4 address
/// the host may route to the underlying v4 — including internal ranges. These
/// are decoded and judged by the IPv4 rules, closing an SSRF bypass:
///   * IPv4-mapped `::ffff:a.b.c.d` — folded by [`to_canonical`] before the match
///     (so `::ffff:169.254.169.254` hits the v4 arm);
///   * **NAT64** `64:ff9b::a.b.c.d` — Android cellular networks commonly run
///     NAT64/464XLAT, so `64:ff9b::<private-v4>` is a real on-device SSRF vector;
///   * **6to4** `2002:<v4>::/48`;
///   * deprecated **IPv4-compatible** `::a.b.c.d`.
///
/// Shared by the string host gate and the HTTP client's SSRF DNS filter.
pub fn is_private_addr(addr: std::net::IpAddr) -> bool {
    match addr.to_canonical() {
        std::net::IpAddr::V4(v4) => is_private_v4(v4),
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Unique-local (fc00::/7)
                || (v6.octets()[0] == 0xfc || v6.octets()[0] == 0xfd)
                // Link-local (fe80::/10)
                || (v6.octets()[0] == 0xfe && (v6.octets()[1] & 0xC0) == 0x80)
                // v6 forms embedding a routable IPv4 (NAT64 / 6to4 /
                // IPv4-compatible): judge the embedded v4 by the v4 rules.
                || embedded_ipv4(v6).is_some_and(is_private_v4)
        }
    }
}

/// IPv4 reserved/private/unroutable predicate (the v4 half of
/// [`is_private_addr`]; also used to judge IPv4 addresses embedded in v6).
fn is_private_v4(v4: std::net::Ipv4Addr) -> bool {
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_unspecified()
        || v4.is_multicast()
        // "This network" 0.0.0.0/8 (RFC 1122) — `is_unspecified` only catches
        // 0.0.0.0, but the whole /8 is reserved/unroutable.
        || v4.octets()[0] == 0
        // CGNAT (100.64.0.0/10)
        || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64)
}

/// Extract the IPv4 address embedded in a v6 address that the host may route to
/// the underlying v4 — NAT64 (`64:ff9b::/96`), 6to4 (`2002::/16`), and the
/// deprecated IPv4-compatible (`::a.b.c.d`). IPv4-MAPPED (`::ffff:/96`) is
/// already folded by `to_canonical` before [`is_private_addr`]'s V6 arm.
fn embedded_ipv4(v6: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    let o = v6.octets();
    let v4 = |a, b, c, d| std::net::Ipv4Addr::new(a, b, c, d);

    // NAT64 well-known prefix 64:ff9b::/96 → low 32 bits are the v4.
    if o[0] == 0x00
        && o[1] == 0x64
        && o[2] == 0xff
        && o[3] == 0x9b
        && o[4..12].iter().all(|&b| b == 0)
    {
        return Some(v4(o[12], o[13], o[14], o[15]));
    }

    // 6to4 2002::/16 → bits 16..48 hold the v4.
    if o[0] == 0x20 && o[1] == 0x02 {
        return Some(v4(o[2], o[3], o[4], o[5]));
    }

    // Deprecated IPv4-compatible ::a.b.c.d (top 96 bits zero). `::` and `::1`
    // are already handled by the unspecified/loopback checks before this is
    // reached; exclude `::` defensively so it isn't reported as 0.0.0.0.
    if o[..12].iter().all(|&b| b == 0) {
        let cand = v4(o[12], o[13], o[14], o[15]);
        if !cand.is_unspecified() {
            return Some(cand);
        }
    }

    None
}

/// String form of [`is_private_addr`]. Non-IP strings (hostnames) return false
/// — those are vetted at resolution time by the HTTP client's SSRF DNS filter.
pub fn is_private_ip(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>()
        .map(is_private_addr)
        .unwrap_or(false)
}

/// True if `host` is configured network infrastructure — a proxy
/// (`HUNTSMAN_SEARCH_PROXY` / `HUNTSMAN_PROXY`) or a rotation DNS resolver
/// (`HUNTSMAN_DNS_RESOLVERS`) — and therefore must never be scanned AS a target:
/// we route *through* these hosts, we don't investigate them. Returns `false`
/// when no rotation infrastructure is configured (default behaviour unchanged).
/// Thin env-reading wrapper over the pure [`crate::util::netrotate`] matcher.
pub fn is_infrastructure_host(host: &str) -> bool {
    crate::util::netrotate::host_matches_infra(
        host,
        &crate::util::netrotate::configured_infra_hosts(),
    )
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
    fn zero_network_v4_rejected() {
        // 0.0.0.0/8 ("this network", RFC 1122) is reserved/unroutable — not just
        // the single 0.0.0.0 caught by `is_unspecified`.
        for ip in ["0.0.0.0", "0.1.2.3", "0.255.255.255"] {
            assert!(is_private_ip(ip), "expected {ip} private (0.0.0.0/8)");
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
    fn ipv4_mapped_private_v6_rejected() {
        // IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is connected by the OS to the
        // underlying IPv4 address, so the v4 reserved ranges must apply.
        // Without canonicalisation these parse as V6, slip past every v6
        // check, and reach internal hosts — a classic SSRF-filter bypass.
        for ip in [
            "::ffff:127.0.0.1",       // loopback
            "::ffff:10.0.0.1",        // RFC1918
            "::ffff:192.168.1.1",     // RFC1918
            "::ffff:172.16.0.1",      // RFC1918
            "::ffff:169.254.169.254", // cloud-metadata
            "::ffff:100.64.0.1",      // CGNAT
            "::ffff:a9fe:a9fe",       // hex form of 169.254.169.254
        ] {
            assert!(is_private_ip(ip), "expected IPv4-mapped {ip} private");
        }
    }

    #[test]
    fn ipv4_mapped_public_v6_accepted() {
        // A mapped *public* address must still pass — canonicalisation only
        // reclassifies, it doesn't blanket-block the mapped range.
        assert!(!is_private_ip("::ffff:8.8.8.8"));
        assert!(!is_private_ip("::ffff:1.1.1.1"));
    }

    #[test]
    fn nat64_embedded_private_v4_rejected() {
        // Android cellular networks commonly run NAT64 (64:ff9b::/96); a host
        // resolving to a NAT64 address that embeds an internal v4 must be
        // refused (it routes to the embedded v4 on-device).
        for ip in [
            "64:ff9b::7f00:1",    // 127.0.0.1
            "64:ff9b::a00:1",     // 10.0.0.1
            "64:ff9b::c0a8:101",  // 192.168.1.1
            "64:ff9b::a9fe:a9fe", // 169.254.169.254 (cloud metadata)
            "64:ff9b::6440:1",    // 100.64.0.1 (CGNAT)
        ] {
            assert!(is_private_ip(ip), "expected NAT64 {ip} private");
        }
        // NAT64 wrapping a PUBLIC v4 resolves to that public host → allowed.
        assert!(
            !is_private_ip("64:ff9b::808:808"),
            "NAT64 8.8.8.8 is public"
        );
        assert!(
            !is_private_ip("64:ff9b::101:101"),
            "NAT64 1.1.1.1 is public"
        );
    }

    #[test]
    fn sixtofour_and_compat_embedded_private_v4_rejected() {
        // 6to4 (2002::/16) embeds the v4 in bits 16..48.
        assert!(is_private_ip("2002:7f00:1::"), "6to4 127.0.0.1");
        assert!(is_private_ip("2002:a9fe:a9fe::"), "6to4 169.254.169.254");
        assert!(!is_private_ip("2002:808:808::"), "6to4 8.8.8.8 is public");
        // Deprecated IPv4-compatible ::a.b.c.d.
        assert!(is_private_ip("::127.0.0.1"), "compat loopback");
        assert!(is_private_ip("::169.254.169.254"), "compat metadata");
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
        // NAT64 embedding metadata is refused by the universal gate too.
        assert!(should_skip_external_ip("64:ff9b::a9fe:a9fe"));
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
