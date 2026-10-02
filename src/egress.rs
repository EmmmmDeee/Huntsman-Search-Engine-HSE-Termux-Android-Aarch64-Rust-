//! Egress policy: which addresses a fetch may connect to.
//!
//! The crate talks to the network, so the question is not "may it" but "to whom".
//! A hostname that resolves to a loopback, private, link-local or metadata address
//! turns a fetch into a probe of the operator's own network. The decision is pure so
//! it can be tested exhaustively; the transport applies it to the *resolved*
//! addresses it is about to connect to, which also defeats DNS rebinding.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Where a fetch is allowed to connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EgressPolicy {
    /// Globally routable unicast addresses only.
    #[default]
    PublicOnly,
    /// Anything. For the operator's own LAN, lab hosts and loopback test servers.
    Unrestricted,
}

impl EgressPolicy {
    #[must_use]
    pub fn permits(self, ip: IpAddr) -> bool {
        match self {
            Self::PublicOnly => is_public_ip(ip),
            Self::Unrestricted => true,
        }
    }
}

/// True when `ip` is a globally routable unicast address.
///
/// Conservative: ranges reserved for documentation, benchmarking, translation and
/// tunnelling are refused because a legitimate public service never lives there,
/// and an embedded IPv4 address (mapped, compatible, NAT64, 6to4) is judged by the
/// IPv4 address it carries.
#[must_use]
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0 // "this network", incl. 0.0.0.0
        || ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local() // 169.254/16 incl. cloud metadata
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || (a == 100 && (64..=127).contains(&b)) // CGNAT 100.64/10
        || (a == 192 && b == 0 && c == 0) // IETF protocol assignments
        || (a == 198 && (b == 18 || b == 19)) // benchmarking 198.18/15
        || a >= 240) // reserved 240/4
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4() {
        // ::ffff:a.b.c.d and the deprecated ::a.b.c.d
        return is_public_v4(v4);
    }
    let seg = ip.segments();
    if seg[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return is_public_v4(embedded_v4(seg[6], seg[7])); // NAT64 64:ff9b::/96
    }
    if seg[0] == 0x2002 {
        return is_public_v4(embedded_v4(seg[1], seg[2])); // 6to4
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (seg[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
        || (seg[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        || (seg[0] & 0xffc0) == 0xfec0 // deprecated site-local fec0::/10
        || (seg[0] == 0x2001 && seg[1] == 0) // Teredo 2001::/32
        || (seg[0] == 0x2001 && seg[1] == 0xdb8) // documentation
        || (seg[0] == 0x0100 && seg[1..4] == [0, 0, 0])) // discard-only 100::/64
}

fn embedded_v4(hi: u16, lo: u16) -> Ipv4Addr {
    let [a, b] = hi.to_be_bytes();
    let [c, d] = lo.to_be_bytes();
    Ipv4Addr::new(a, b, c, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test address")
    }

    #[test]
    fn private_loopback_and_metadata_ranges_are_refused() {
        for s in [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "127.0.0.1",
            "127.255.255.254",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "192.0.0.8",
            "192.0.2.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "febf::1",
            "fec0::1",
            "ff02::1",
            "2001::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "::10.0.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b::a9fe:a9fe",
            "2002:7f00:1::1",
            "2002:c0a8:101::1",
            "100::1",
        ] {
            assert!(!is_public_ip(ip(s)), "{s} must not be public");
        }
    }

    #[test]
    fn ordinary_public_addresses_are_allowed() {
        for s in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "172.15.255.255",
            "172.32.0.1",
            "100.63.255.255",
            "100.128.0.1",
            "198.17.255.255",
            "198.20.0.1",
            "223.255.255.255",
            "2606:4700:4700::1111",
            "2a00:1450:4001::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2002:808:808::1",
        ] {
            assert!(is_public_ip(ip(s)), "{s} should be public");
        }
    }

    #[test]
    fn boundaries_of_the_172_16_block_are_exact() {
        assert!(is_public_ip(ip("172.15.255.255")));
        assert!(!is_public_ip(ip("172.16.0.0")));
        assert!(!is_public_ip(ip("172.31.255.255")));
        assert!(is_public_ip(ip("172.32.0.0")));
    }

    #[test]
    fn policy_selects_the_check() {
        let lo = ip("127.0.0.1");
        assert!(!EgressPolicy::default().permits(lo));
        assert!(!EgressPolicy::PublicOnly.permits(lo));
        assert!(EgressPolicy::Unrestricted.permits(lo));
        assert!(EgressPolicy::PublicOnly.permits(ip("1.1.1.1")));
    }

    #[test]
    fn every_ipv4_address_in_private_and_reserved_slash8s_is_refused_on_a_grid() {
        for a in [0u8, 10, 127, 224, 240, 255] {
            for b in (0..=255u8).step_by(17) {
                for c in (0..=255u8).step_by(51) {
                    assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(a, b, c, 1))));
                }
            }
        }
    }
}
