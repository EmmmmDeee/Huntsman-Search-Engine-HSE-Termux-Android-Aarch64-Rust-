//! Address blocks in CIDR form: the one place Huntsman parses a block, tests whether it holds an
//! address, writes it canonically and lists its addresses. Every module that reads a block uses
//! it, among them SPF `ip4`/`ip6` mechanisms, the RDAP bootstrap and leg, the `netblock` lookup,
//! the threat feeds, the correlation rules' `subnet` match, canonical forms and the classifier.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An IPv4 block as written: the address keeps its host bits, as an SPF `ip4:` mechanism may.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Cidr {
    addr: Ipv4Addr,
    prefix: u8,
}

impl Ipv4Cidr {
    /// `ADDRESS[/PREFIX]`; a bare address is a /32. **Pure.**
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let (addr_raw, prefix_raw) = raw.split_once('/').unwrap_or((raw, "32"));
        let addr: Ipv4Addr = addr_raw.trim().parse().ok()?;
        let prefix: u8 = prefix_raw.trim().parse().ok()?;
        (prefix <= 32).then_some(Self { addr, prefix })
    }

    fn mask(self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix)
        }
    }

    #[must_use]
    pub fn contains(self, ip: Ipv4Addr) -> bool {
        let mask = self.mask();
        (u32::from(ip) & mask) == (u32::from(self.addr) & mask)
    }

    #[must_use]
    pub fn prefix_len(self) -> u8 {
        self.prefix
    }

    /// The block's first address: the address with its host bits cleared.
    #[must_use]
    pub fn network(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) & self.mask())
    }
}

/// An IPv6 block as written: the address keeps its host bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Cidr {
    addr: Ipv6Addr,
    prefix: u8,
}

impl Ipv6Cidr {
    /// `ADDRESS[/PREFIX]`; a bare address is a /128. **Pure.**
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let (addr_raw, prefix_raw) = raw.split_once('/').unwrap_or((raw, "128"));
        let addr: Ipv6Addr = addr_raw.trim().parse().ok()?;
        let prefix: u8 = prefix_raw.trim().parse().ok()?;
        (prefix <= 128).then_some(Self { addr, prefix })
    }

    fn mask(self) -> u128 {
        if self.prefix == 0 {
            0
        } else {
            u128::MAX << (128 - self.prefix)
        }
    }

    #[must_use]
    pub fn contains(self, ip: Ipv6Addr) -> bool {
        let mask = self.mask();
        (u128::from(ip) & mask) == (u128::from(self.addr) & mask)
    }

    #[must_use]
    pub fn prefix_len(self) -> u8 {
        self.prefix
    }

    /// The block's first address: the address with its host bits cleared.
    #[must_use]
    pub fn network(self) -> Ipv6Addr {
        Ipv6Addr::from(u128::from(self.addr) & self.mask())
    }
}

/// A block of either family, written canonically as its first address and prefix length, as
/// Spiderfoot writes a `NETBLOCK_OWNER` or `NETBLOCKV6_OWNER`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Netblock {
    V4(Ipv4Cidr),
    V6(Ipv6Cidr),
}

impl Netblock {
    /// `ADDRESS/PREFIX`, IPv4 or IPv6, with the host bits cleared: `192.0.2.7/24` is
    /// `192.0.2.0/24`. A bare address is not a block. **Pure.**
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let (addr, prefix) = raw.trim().split_once('/')?;
        let prefix: u8 = prefix.trim().parse().ok()?;
        match addr.trim().parse::<IpAddr>().ok()? {
            IpAddr::V4(addr) => (prefix <= 32).then(|| {
                let block = Ipv4Cidr { addr, prefix };
                Self::V4(Ipv4Cidr {
                    addr: block.network(),
                    prefix,
                })
            }),
            IpAddr::V6(addr) => (prefix <= 128).then(|| {
                let block = Ipv6Cidr { addr, prefix };
                Self::V6(Ipv6Cidr {
                    addr: block.network(),
                    prefix,
                })
            }),
        }
    }

    /// The block's first address.
    #[must_use]
    pub fn network(self) -> IpAddr {
        match self {
            Self::V4(block) => IpAddr::V4(block.network()),
            Self::V6(block) => IpAddr::V6(block.network()),
        }
    }

    #[must_use]
    pub fn prefix_len(self) -> u8 {
        match self {
            Self::V4(block) => block.prefix_len(),
            Self::V6(block) => block.prefix_len(),
        }
    }

    /// The bits of an address the block leaves free: 32 or 128 less the prefix length.
    #[must_use]
    pub fn host_bits(self) -> u8 {
        match self {
            Self::V4(block) => 32 - block.prefix_len(),
            Self::V6(block) => 128 - block.prefix_len(),
        }
    }

    #[must_use]
    pub fn contains(self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4(block), IpAddr::V4(ip)) => block.contains(ip),
            (Self::V6(block), IpAddr::V6(ip)) => block.contains(ip),
            _ => false,
        }
    }

    /// Every address in the block, first to last, when it has at most `max_host_bits` host bits;
    /// `None` for a larger block. **Pure.**
    #[must_use]
    pub fn addresses(self, max_host_bits: u8) -> Option<Vec<IpAddr>> {
        let bits = self.host_bits();
        if bits > max_host_bits || bits >= 32 {
            return None;
        }
        let count = 1_u32 << bits;
        Some(match self {
            Self::V4(block) => {
                let first = u32::from(block.network());
                (0..count)
                    .map(|offset| IpAddr::V4(Ipv4Addr::from(first + offset)))
                    .collect()
            }
            Self::V6(block) => {
                let first = u128::from(block.network());
                (0..count)
                    .map(|offset| IpAddr::V6(Ipv6Addr::from(first + u128::from(offset))))
                    .collect()
            }
        })
    }
}

impl fmt::Display for Netblock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network(), self.prefix_len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(raw: &str) -> IpAddr {
        raw.parse().expect("an address")
    }

    #[test]
    fn cidr_math_is_safe() {
        assert!(
            Ipv4Cidr::parse("0.0.0.0/0")
                .expect("cidr")
                .contains("1.2.3.4".parse().expect("ip"))
        );
        assert!(
            Ipv6Cidr::parse("::/0")
                .expect("cidr")
                .contains("2001:db8::1".parse().expect("ip"))
        );
        assert!(Ipv4Cidr::parse("10.0.0.0/33").is_none());
    }

    #[test]
    fn a_block_is_written_as_its_first_address_and_prefix() {
        for (raw, canonical) in [
            ("192.0.2.77/24", "192.0.2.0/24"),
            (" 198.51.101.9/22 ", "198.51.100.0/22"),
            ("2001:DB8:0:0:0:0:0:1/32", "2001:db8::/32"),
            ("2606:4700:4700::1111/120", "2606:4700:4700::1100/120"),
            ("0.0.0.0/0", "0.0.0.0/0"),
        ] {
            let block = Netblock::parse(raw).expect(raw);
            assert_eq!(block.to_string(), canonical, "{raw}");
        }
        for raw in [
            "192.0.2.1",
            "192.0.2.0/33",
            "2001:db8::/129",
            "example.com/24",
            "/24",
        ] {
            assert_eq!(Netblock::parse(raw), None, "{raw}");
        }
    }

    #[test]
    fn a_small_block_lists_every_address_and_a_large_one_none() {
        let block = Netblock::parse("192.0.2.4/30").expect("a block");
        assert_eq!(
            block.addresses(8),
            Some(vec![
                ip("192.0.2.4"),
                ip("192.0.2.5"),
                ip("192.0.2.6"),
                ip("192.0.2.7")
            ])
        );
        assert_eq!(
            Netblock::parse("192.0.2.0/24")
                .expect("a /24")
                .addresses(8)
                .map(|all| all.len()),
            Some(256)
        );
        assert_eq!(
            Netblock::parse("192.0.0.0/23").expect("a /23").addresses(8),
            None
        );
        let v6 = Netblock::parse("2001:db8::/126").expect("a v6 block");
        assert_eq!(v6.addresses(8).map(|all| all[3]), Some(ip("2001:db8::3")));
        assert_eq!(
            Netblock::parse("2001:db8::/64")
                .expect("a /64")
                .addresses(8),
            None
        );
        assert!(block.contains(ip("192.0.2.6")) && !block.contains(ip("192.0.2.8")));
        assert!(!block.contains(ip("2001:db8::1")));
    }
}
