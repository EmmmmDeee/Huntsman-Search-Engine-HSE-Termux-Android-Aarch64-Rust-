//! CIDR netblock → host IP expansion.
//!
//! SpiderFoot-parity capability: a scan target that is a network block
//! (`192.0.2.0/24`, `2001:db8::/120`) is enumerated into its constituent host
//! IPs, each emitted as an `IpAddress` entity. The expansion loop then runs the
//! full IP-enrichment stack (geo, reputation, reverse-DNS, banner, …) over every
//! host — turning a single netblock seed into a swept range.
//!
//! Pure, no API, no native deps (Termux-clean). Bounded: at most [`MAX_HOSTS`]
//! addresses are emitted so a wide block (or a `/0`) can't flood the graph; the
//! parent `Cidr` entity is tagged `truncated` when the block exceeds the cap.
//! IPv6 blocks are never enumerated (the host space is astronomical) — only the
//! network base address is surfaced.

use std::net::{Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "netblock";

/// Hard cap on emitted host IPs per block. 1024 covers a `/22` (the largest
/// block a single operator typically owns end-to-end) while bounding the work a
/// `/8` seed would otherwise generate. The scan's own `max_entities` budget is a
/// second backstop.
const MAX_HOSTS: usize = 1024;

pub struct Netblock;

#[async_trait]
impl Module for Netblock {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Expand a CIDR network block into its host IP addresses for sweeping"
    }

    fn priority(&self) -> u8 {
        // Above the IP-enrichment modules so the block is expanded into hosts
        // before those run, but it is passive and offline so ordering is loose.
        60
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Cidr)
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::IpAddress];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let Some((hosts, total, truncated)) = expand_cidr(target.value.trim(), MAX_HOSTS) else {
            return Ok(result);
        };

        let block = target.value.trim();
        for ip in hosts {
            let mut e = Entity::new(EntityKind::IpAddress, &ip, 0.70, &ctx.scan_id);
            e.tag("netblock-member");
            e.add_evidence(
                Evidence::new(SRC, format!("Host {ip} in network block {block}"))
                    .with_attr("cidr", block),
            );
            result.push(e);
        }
        if truncated {
            // Surface the cap on the parent so the operator knows the sweep was
            // bounded (the block has `total` addresses; only MAX_HOSTS emitted).
            let mut e = Entity::new(EntityKind::Cidr, block, 0.80, &ctx.scan_id);
            e.tag("truncated");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Block {block} has {total} addresses; expansion capped at {MAX_HOSTS}"),
                )
                .with_attr("total_addresses", total.to_string())
                .with_attr("emitted", MAX_HOSTS.to_string()),
            );
            result.push(e);
        }
        Ok(result)
    }
}

/// Expand a CIDR string into up to `cap` host-IP strings. Returns
/// `(ips, total_addresses, truncated)`, or `None` if the input is not a valid
/// CIDR. IPv6 blocks yield only the network base address (`total = 1`) — the
/// host space is too large to enumerate. **Pure.**
fn expand_cidr(cidr: &str, cap: usize) -> Option<(Vec<String>, u64, bool)> {
    let (ip, prefix) = cidr.split_once('/')?;
    let prefix: u8 = prefix.trim().parse().ok()?;

    match ip.trim().parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(v4) => {
            if prefix > 32 {
                return None;
            }
            let bits = 32 - u32::from(prefix);
            let mask = if bits == 32 { 0 } else { (!0u32) << bits };
            let base = u32::from(v4) & mask;
            let total: u64 = 1u64 << bits;
            let count = total.min(cap as u64);
            let ips = (0..count)
                .map(|i| Ipv4Addr::from(base.wrapping_add(i as u32)).to_string())
                .collect();
            Some((ips, total, total > cap as u64))
        }
        std::net::IpAddr::V6(v6) => {
            if prefix > 128 {
                return None;
            }
            // Do not enumerate v6 (host space is astronomical); surface only the
            // network base so the block still yields a scannable IP entity.
            let bits = 128 - u32::from(prefix);
            let mask: u128 = if bits == 128 { 0 } else { (!0u128) << bits };
            let base = u128::from(v6) & mask;
            Some((vec![Ipv6Addr::from(base).to_string()], 1, false))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_small_v4_block_fully() {
        let (ips, total, trunc) = expand_cidr("192.0.2.0/30", 1024).unwrap();
        assert_eq!(total, 4);
        assert!(!trunc);
        assert_eq!(
            ips,
            vec!["192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"]
        );
    }

    #[test]
    fn normalises_host_bits_to_network() {
        // A non-network address with host bits set expands from the *network*
        // address of its block: the /30 containing .5 is 192.0.2.4/30 (.4–.7).
        let (ips, _, _) = expand_cidr("192.0.2.5/30", 1024).unwrap();
        assert_eq!(
            ips,
            vec!["192.0.2.4", "192.0.2.5", "192.0.2.6", "192.0.2.7"]
        );
    }

    #[test]
    fn caps_large_block_and_flags_truncation() {
        let (ips, total, trunc) = expand_cidr("10.0.0.0/16", 1024).unwrap();
        assert_eq!(total, 65_536);
        assert!(trunc);
        assert_eq!(ips.len(), 1024);
        assert_eq!(ips[0], "10.0.0.0");
        assert_eq!(ips[1023], "10.0.3.255");
    }

    #[test]
    fn slash_32_is_single_host() {
        let (ips, total, trunc) = expand_cidr("8.8.8.8/32", 1024).unwrap();
        assert_eq!((total, trunc), (1, false));
        assert_eq!(ips, vec!["8.8.8.8"]);
    }

    #[test]
    fn v6_yields_only_network_base() {
        let (ips, total, trunc) = expand_cidr("2001:db8::5/120", 1024).unwrap();
        assert_eq!((total, trunc), (1, false));
        assert_eq!(ips, vec!["2001:db8::"]);
    }

    #[test]
    fn rejects_non_cidr() {
        assert!(expand_cidr("not-a-cidr", 1024).is_none());
        assert!(expand_cidr("192.0.2.0/33", 1024).is_none());
        assert!(expand_cidr("8.8.8.8", 1024).is_none());
    }
}
