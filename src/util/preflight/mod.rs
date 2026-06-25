//! Shared pre-flight validators for API-quota-spending modules.
//!
//! Modules that hit external paid APIs (`see_know`, `oathnet_pro`,
//! future providers) all need to reject obviously-junk targets
//! before burning a query. Centralised here so the policy stays
//! consistent across providers — a value that's a "placeholder
//! username" for SeekNow must be one for OathNet too.

/// Strip the brackets that `url` 2.5 wraps around IPv6 literals in `host_str()`
/// (`[::1]` → `::1`). A non-bracketed string is returned unchanged.
///
/// This is the single source-of-truth for IPv6-bracket removal: any caller that
/// parses `Url::host_str()` into an `IpAddr` needs this or every IPv6-literal
/// target fails to parse, silently returning a "not-private" verdict — an SSRF
/// bypass.
pub fn unbracket_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host)
}

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
/// (fc00::/7) / link-local (fe80::/10) / deprecated site-local (fec0::/10).
///
/// **Embedded-IPv4 v6 forms.** Several v6 representations carry an IPv4 address
/// the host may route to the underlying v4 — including internal ranges. These
/// are decoded and judged by the IPv4 rules, closing an SSRF bypass:
///   * IPv4-mapped `::ffff:a.b.c.d` — folded by [`std::net::IpAddr::to_canonical`] before the match
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
                // Deprecated site-local (fec0::/10, RFC 3879) — withdrawn, but
                // legacy gear still routes it as internal space, and the
                // link-local mask (& 0xC0 == 0x80) does NOT cover it, so
                // fec0::1 previously classified as public.
                || (v6.octets()[0] == 0xfe && (v6.octets()[1] & 0xC0) == 0xC0)
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
        // Class E "reserved for future use" (240.0.0.0/4, RFC 1112) — not
        // globally routable, so an SSRF guard denies it (multicast 224/4 and the
        // broadcast address are already covered above; this closes 240–254.x).
        || v4.octets()[0] >= 240
}

/// Extract the IPv4 address embedded in a v6 address that the host may route to
/// the underlying v4 — NAT64 (well-known `64:ff9b::/96` and the RFC 8215
/// local-use `64:ff9b:1::/48`), 6to4 (`2002::/16`), and the deprecated
/// IPv4-compatible (`::a.b.c.d`). IPv4-MAPPED (`::ffff:/96`) is already folded
/// by `to_canonical` before [`is_private_addr`]'s V6 arm.
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

    // Local-use NAT64 prefix 64:ff9b:1::/48 (RFC 8215) — reserved specifically
    // for PRIVATE-network NAT64 deployments, so it is exactly the embedded-v4
    // SSRF vector this function exists to close; only the well-known /96 was
    // decoded before. RFC 6052's /48 layout places the v4 around the zero `u`
    // octet (o[8]): high half at octets 6–7, low half at 9–10.
    if o[0] == 0x00 && o[1] == 0x64 && o[2] == 0xff && o[3] == 0x9b && o[4] == 0x00 && o[5] == 0x01
    {
        return Some(v4(o[6], o[7], o[9], o[10]));
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
    ip.parse::<std::net::IpAddr>().is_ok_and(is_private_addr)
}

/// True only for a parseable, **publicly routable** IP literal: the single
/// gate every breach/stealer extractor uses to decide whether an `ip` /
/// `lastip` field is a geolocatable lead. A hostname, a malformed value, or any
/// private/loopback/link-local/CGNAT address returns false, so a LAN login-IP
/// never becomes geo-noise. Consolidates the identical check previously
/// hand-rolled in `oathnet_pro` (and absent from `see_know`, which accepted any
/// 7+-char string).
pub fn is_public_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok() && !is_private_ip(s)
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

/// SSRF egress guard for a whole URL: `true` when `url`'s host is a
/// private/reserved **IP literal** (loopback, RFC1918, link-local incl. the
/// `169.254.169.254` cloud-metadata endpoint, ULA, …) or an IANA local domain.
///
/// This is the IP-literal counterpart to the HTTP client's DNS-resolver SSRF
/// filter. The resolver vets *hostnames* at connect time, but an IP-literal URL
/// (`http://169.254.169.254/`, `http://127.0.0.1:8080/`) is dialled directly by
/// hyper without a lookup, so it never reaches the resolver. Any site that
/// fetches a **discovered** URL outside engine target-validation (e.g. the web
/// crawler following links extracted from a page) must apply this guard so the
/// IP-literal path cannot reach an internal service. Hostnames return `false`
/// here — they are the resolver's responsibility, not this function's.
pub fn url_host_is_private(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url.trim()) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    // `url` 2.5 returns IPv6 `host_str` WITH brackets (`[::1]`); strip them so
    // the `IpAddr` parse inside `is_private_ip` fires.
    let bare = unbracket_host(host);
    is_private_ip(bare) || is_local_domain(bare)
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
            | "redacted"
            | "placeholder"
    )
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
