//! CIDR netblock → host IP expansion.
//!
//! SpiderFoot-parity capability: a scan target that is a network block
//! (`192.0.2.0/24`, `2001:db8::/120`) is enumerated into its constituent host
//! IPs, each emitted as an `IpAddress` entity. The expansion loop then runs the
//! full IP-enrichment stack (geo, reputation, reverse-DNS, banner, …) over every
//! host — turning a single netblock seed into a swept range.
//!
//! Pure, no API, no native deps (Termux-clean). Bounded: at most [`MAX_HOSTS`]
//! addresses are emitted so a wide block (or a `/0`) can't flood the graph. A
//! block that exceeds the cap is declared incomplete to the coverage layer
//! ([`ModuleResult::mark_truncated_of`]) and its parent `Cidr` entity carries
//! the same note, tagged `truncated`. An IPv6 block that fits the cap (`/118`
//! and longer — the `/120` above) is enumerated like an IPv4 one; a wider IPv6
//! block surfaces only its network base address, since sweeping the first
//! thousand addresses of a `/64` says nothing about the rest of it.

use std::net::{Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;

use crate::core::{
    confidence,
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
        "Netblock expansion — enumerates a CIDR block into its host IP addresses for sweeping"
    }

    fn priority(&self) -> u8 {
        // Above the IP-enrichment modules so the block is expanded into hosts
        // before those run, but it is passive and offline so ordering is loose.
        60
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Pure offline CIDR expansion — no scan database is queried, so the
        // Infrastructure default T1596.005 (Scan Databases) does not apply.
        // Enumerating the host addresses in a network block is IP address
        // reconnaissance (T1590.005) only.
        &["T1590.005"]
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Cidr)
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::IpAddress, EntityKind::Cidr];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let Some((hosts, total, truncated)) = expand_cidr(target.value.trim(), MAX_HOSTS) else {
            return Ok(result);
        };

        let block = target.value.trim();
        result.extend(hosts.into_iter().map(|ip| {
            let mut e = Entity::new(
                EntityKind::IpAddress,
                &ip,
                confidence::HIGH_PLUS,
                &ctx.scan_id,
            );
            e.tag("netblock-member");
            e.add_evidence(
                Evidence::new(SRC, format!("Host {ip} in network block {block}"))
                    .with_attr("cidr", block),
            );
            e
        }));
        if truncated {
            let emitted = result.len();
            // The provider-level declaration the coverage layer reads. A
            // private `truncated` tag on the parent was the only signal before,
            // and nothing outside this file reads that tag.
            result.mark_truncated_of(
                emitted,
                total,
                &format!("the host-expansion cap of {MAX_HOSTS}"),
            );
            // And the per-block note on the parent, for the operator reading it.
            let mut e = Entity::new(
                EntityKind::Cidr,
                block,
                confidence::HIGH_PLUSPLUS,
                &ctx.scan_id,
            );
            e.tag("truncated");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Block {block} has {total} addresses; expansion capped at {emitted}"),
                )
                .with_attr("total_addresses", total.to_string())
                .with_attr("emitted", emitted.to_string()),
            );
            result.push(e);
        }
        Ok(result)
    }
}

/// Expand a CIDR string into up to `cap` host-IP strings. Returns
/// `(ips, total_addresses, truncated)`, or `None` if the input is not a valid
/// CIDR. `total_addresses` is exact (`u128`: an IPv6 `/0` holds `2^128`,
/// saturated to `u128::MAX`). An IPv6 block that fits `cap` is enumerated in
/// full; a wider one yields only its network base address, and is truncated.
/// **Pure.**
fn expand_cidr(cidr: &str, cap: usize) -> Option<(Vec<String>, u128, bool)> {
    let (ip, prefix) = cidr.split_once('/')?;
    let prefix: u8 = prefix.trim().parse().ok()?;
    let cap_u = cap as u128;

    match ip.trim().parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(v4) => {
            if prefix > 32 {
                return None;
            }
            let bits = 32 - u32::from(prefix);
            let mask = if bits == 32 { 0 } else { (!0u32) << bits };
            let base = u32::from(v4) & mask;
            let total: u128 = 1u128 << bits;
            let count = total.min(cap_u);
            let ips = (0..count)
                .map(|i| Ipv4Addr::from(base.wrapping_add(i as u32)).to_string())
                .collect();
            Some((ips, total, total > cap_u))
        }
        std::net::IpAddr::V6(v6) => {
            if prefix > 128 {
                return None;
            }
            let bits = 128 - u32::from(prefix);
            let mask: u128 = if bits == 128 { 0 } else { (!0u128) << bits };
            let base = u128::from(v6) & mask;
            let total = 1u128.checked_shl(bits).unwrap_or(u128::MAX);
            if total <= cap_u {
                // Small enough to sweep like an IPv4 block — the `/120` the
                // module header advertises, which was never enumerated before.
                let ips = (0..total)
                    .map(|i| Ipv6Addr::from(base + i).to_string())
                    .collect();
                return Some((ips, total, false));
            }
            // Do not enumerate a wide v6 block: surface only the network base
            // so it still yields a scannable IP entity, and say it is partial.
            Some((vec![Ipv6Addr::from(base).to_string()], total, true))
        }
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
