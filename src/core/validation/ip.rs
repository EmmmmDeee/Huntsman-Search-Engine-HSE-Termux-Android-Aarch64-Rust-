use std::net::IpAddr;

/// The "can never be a real host *anywhere*" ranges shared by [`is_bogus_ip`]
/// and [`is_non_routable_ip`]: RFC5737 documentation (`192.0.2.0/24`,
/// `198.51.100.0/24`, `203.0.113.0/24`), RFC2544 benchmarking (`198.18.0.0/15`),
/// IETF-protocol (`192.0.0.0/24`), the deprecated 6to4 relay (`192.88.99.0/24`,
/// RFC 7526), this-host (`0.0.0.0/8`), reserved/future (`240.0.0.0/4`, which
/// also covers the v4 broadcast), IPv6 documentation (`2001:db8::/32` plus the
/// RFC 9637 `3fff::/20` allocation), and IPv6 benchmarking (`2001:2::/48`).
/// IPv4-mapped IPv6 spellings (`::ffff:a.b.c.d`) classify as their v4 address.
///
/// Single source of truth for the documentation/reserved set so the two callers
/// can never drift on which ranges count — a new RFC reservation is added here
/// once and both `is_bogus_ip` and `is_non_routable_ip` pick it up.
fn is_documentation_or_reserved(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 0                                            // 0.0.0.0/8 this-host
                || o[0] >= 240                                   // 240/4 reserved/future + broadcast
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)       // 192.0.0.0/24 IETF protocol
                || (o[0] == 192 && o[1] == 0 && o[2] == 2)       // 192.0.2.0/24 TEST-NET-1
                || (o[0] == 192 && o[1] == 88 && o[2] == 99)     // 192.88.99.0/24 6to4 relay (deprecated, RFC 7526)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)    // 198.51.100.0/24 TEST-NET-2
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)     // 203.0.113.0/24 TEST-NET-3
                || (o[0] == 198 && (o[1] & 0xFE) == 18) // 198.18.0.0/15 benchmarking
        }
        IpAddr::V6(v6) => {
            // An IPv4-mapped spelling (::ffff:192.0.2.1) is the SAME address as
            // its v4 form and must classify identically — otherwise the v6
            // spelling of a documentation IP walks straight through the gate.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_documentation_or_reserved(&IpAddr::V4(v4));
            }
            let o = v6.octets();
            (o[0] == 0x20 && o[1] == 0x01 && o[2] == 0x0d && o[3] == 0xb8) // 2001:db8::/32 doc
                || (o[0] == 0x3f && o[1] == 0xff && (o[2] & 0xF0) == 0)    // 3fff::/20 doc (RFC 9637)
                || (o[0] == 0x20 && o[1] == 0x01 && o[2] == 0 && o[3] == 2
                    && o[4] == 0 && o[5] == 0) // 2001:2::/48 benchmarking (RFC 5180)
        }
    }
}

/// True if `s` parses to a non-routable or otherwise un-queryable IP. Covers
/// RFC1918 private, loopback, link-local, CGN, broadcast, unspecified,
/// multicast, IPv6 ULA — **plus** every documentation/reserved range in
/// [`is_documentation_or_reserved`] (RFC5737 TEST-NETs, RFC2544 benchmarking,
/// IETF protocol, this-host, reserved/future, IPv6 documentation). No external
/// OSINT source can resolve any of these, so the engine must never pivot on
/// them.
pub fn is_non_routable_ip(s: &str) -> bool {
    let Ok(addr) = s.parse::<IpAddr>() else {
        return false;
    };
    // Unmap an IPv4-mapped spelling (::ffff:192.168.1.1) so it classifies
    // exactly like its v4 form — the v6 branch below has no private/CGN logic,
    // so the mapped spelling of a private address would otherwise pass.
    let addr = match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(addr, IpAddr::V4),
        v4 => v4,
    };
    // Documentation/reserved ranges (shared with is_bogus_ip) PLUS the private /
    // local addresses that a non-routable check additionally rejects.
    if is_documentation_or_reserved(&addr) {
        return true;
    }
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
                || (o[0] == 100 && (o[1] & 0xC0) == 64) // CGN 100.64/10
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (o[0] == 0xfc || o[0] == 0xfd)         // ULA fc00::/7
                || (o[0] == 0xfe && (o[1] & 0xC0) == 0x80) // link-local fe80::/10
        }
    }
}

/// True if `s` is an IPv4 address inside a major CDN's anycast edge range
/// (Cloudflare's published ranges + Fastly's primary block).
///
/// A CDN edge IP fronts thousands of unrelated sites, so a reverse-IP /
/// co-hosting lookup on it returns a flood of co-tenant strangers (a real
/// person-scan pulled 480+ such domains — and then each one's subdomains —
/// through two Cloudflare edges). The engine therefore does not expand a
/// discovered CDN-edge IP as a target: its geo/reputation belong to the CDN, not
/// the subject, and reverse-IP on it is pure noise. This is decided by IP RANGE,
/// not by a `cdn`/`cloudflare` tag, so it holds BEFORE any reverse-IP module runs
/// in the same round — no tag-ordering race. IPv6 returns `false` (the reverse-IP
/// modules here are v4-only and the v6 CDN space is impractical to enumerate).
///
/// Cloudflare ranges are stable and authoritative (`cloudflare.com/ips-v4`); a
/// stray IP that drifts out of the list simply isn't gated (graceful, never a
/// false skip of a non-CDN host).
pub fn is_cdn_edge_ip(s: &str) -> bool {
    // The v4 ranges below, with an IPv4-mapped v6 spelling (::ffff:104.16.0.1)
    // unmapped first so it gates identically to its v4 form. Native v6
    // addresses return false by design (see above).
    let v4 = match s.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4,
        Ok(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4,
            None => return false,
        },
        Err(_) => return false,
    };
    let o = v4.octets();
    // Cloudflare (cloudflare.com/ips-v4) keyed on the first octet; Fastly's
    // primary anycast block (151.101.0.0/16) is the lone non-Cloudflare entry.
    match o[0] {
        104 => (o[1] & 0xF8) == 16 || (o[1] & 0xFC) == 24, // 104.16/13 + 104.24/14
        172 => (o[1] & 0xF8) == 64,                        // 172.64.0.0/13
        162 => (o[1] & 0xFE) == 158,                       // 162.158.0.0/15
        173 => o[1] == 245 && (o[2] & 0xF0) == 48,         // 173.245.48.0/20
        141 => o[1] == 101 && (o[2] & 0xC0) == 64,         // 141.101.64.0/18
        108 => o[1] == 162 && (o[2] & 0xC0) == 192,        // 108.162.192.0/18
        190 => o[1] == 93 && (o[2] & 0xF0) == 240,         // 190.93.240.0/20
        188 => o[1] == 114 && (o[2] & 0xF0) == 96,         // 188.114.96.0/20
        197 => o[1] == 234 && (o[2] & 0xFC) == 240,        // 197.234.240.0/22
        198 => o[1] == 41 && (o[2] & 0x80) == 128,         // 198.41.128.0/17
        131 => o[1] == 0 && (o[2] & 0xFC) == 72,           // 131.0.72.0/22
        103 => {
            (o[1] == 21 && (o[2] & 0xFC) == 244)           // 103.21.244.0/22
                || (o[1] == 22 && (o[2] & 0xFC) == 200)    // 103.22.200.0/22
                || (o[1] == 31 && (o[2] & 0xFC) == 4) // 103.31.4.0/22
        }
        151 => o[1] == 101, // Fastly 151.101.0.0/16
        _ => false,
    }
}

/// Reason an IP's geolocation must NOT be attributed to the **subject** — its
/// coordinates describe infrastructure, not a person — or `None` when the
/// location can be trusted as the subject's own. Today that is a CDN/anycast
/// edge ([`is_cdn_edge_ip`]): its geo resolves to the answering datacenter.
///
/// This is the single shared gate every IP-geolocation module consults before
/// emitting `Coordinates`/`Address`, so the trust policy — and any future rule
/// (bogon ranges, known hosting blocks) — lives in one place and applies
/// uniformly across providers instead of being re-derived per module. Risk-aware
/// providers (e.g. `ipquery`, which knows VPN/Tor/proxy/datacenter flags) layer
/// their extra signals on top of this base reason. **Pure.**
#[must_use]
pub fn untrusted_ip_geo_reason(s: &str) -> Option<&'static str> {
    if is_cdn_edge_ip(s) {
        return Some("cdn/anycast edge");
    }
    None
}

/// True if `s` parses to an IP that can **never** be a real host *anywhere*:
/// RFC5737 documentation (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`),
/// RFC2544 benchmarking (`198.18.0.0/15`), IETF-protocol (`192.0.0.0/24`),
/// "this-host" (`0.0.0.0/8`), reserved/future (`240.0.0.0/4`), and IPv6
/// documentation (`2001:db8::/32`).
///
/// Unlike [`is_non_routable_ip`] this **deliberately excludes** RFC1918 private,
/// loopback, link-local, CGN and multicast — addresses that local sensors
/// (`local_net`, `device_sensors`, `wifi_intel`) legitimately surface on-device.
/// It is therefore safe to drop matches at *entity admission* without losing any
/// real local-network finding; only addresses scraped from documentation/examples
/// (e.g. `192.0.2.1` lifted off a tutorial page) are rejected.
pub fn is_bogus_ip(s: &str) -> bool {
    // Exactly the documentation/reserved set — no private/loopback/local ranges,
    // which on-device sensors legitimately surface (see the doc comment above).
    s.parse::<IpAddr>()
        .is_ok_and(|addr| is_documentation_or_reserved(&addr))
}
