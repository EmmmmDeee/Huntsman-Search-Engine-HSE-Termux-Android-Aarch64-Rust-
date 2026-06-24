//! Unified DNS intelligence module — resolution, brute-force, CAA, reverse,
//! and blocklist checks dispatched by target kind:
//!
//! **Domain targets** (sequential):
//!   1. *Resolution* — A / AAAA / MX / NS / SOA / TXT lookups via `tokio::join!`.
//!   2. *Subdomain brute-force* — 146-label common-name dictionary, bounded
//!      to 12 concurrent lookups.
//!   3. *CAA inspection* — RFC 8659 Certification Authority Authorization.
//!
//! **IpAddress targets** (sequential):
//!   1. *Reverse DNS* — PTR record lookup.
//!   2. *Blocklist (DNSBL)* — 8 well-known DNS-based blocklists.
//!
//! All lookups use `crate::util::dns::shared_resolver()` (Cloudflare).
//! No API keys, no HTTP, no rate limits.
//!
//! Evidence source for every finding: `"dns_intel"`.

mod brute;
mod constants;
mod helpers;
mod resolve;
#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::core::{
    entity::EntityKind,
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

use self::brute::brute_subdomains;
use self::resolve::{blocklist_check, lookup_caa, resolve_records, reverse_lookup};

pub(super) const SRC: &str = "dns_intel";
pub(super) const MAX_CONCURRENT_BRUTE: usize = 12;

// ---------------------------------------------------------------------------
// Module struct + trait impl
// ---------------------------------------------------------------------------

pub struct DnsIntel;

#[async_trait]
impl Module for DnsIntel {
    fn name(&self) -> &'static str {
        "dns_intel"
    }

    fn description(&self) -> &'static str {
        "DNS intelligence: resolution, subdomain brute-force, blocklist, reverse DNS, and CAA"
    }

    fn priority(&self) -> u8 {
        31
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Domain | TargetKind::IpAddress | TargetKind::Url
        )
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Live DNS records — ATT&CK Gather Victim Network Information: DNS (T1590.002).
        &["T1590.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] =
            &[EntityKind::IpAddress, EntityKind::Domain, EntityKind::Email];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        15_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        match target.kind {
            TargetKind::Domain => process_domain(target, ctx).await,
            TargetKind::IpAddress => process_ip(target, ctx).await,
            TargetKind::Url => {
                if let Some(host) = crate::util::url_util::host_from_url(&target.value) {
                    let synth = Target::new(TargetKind::Domain, host);
                    process_domain(&synth, ctx).await
                } else {
                    Ok(ModuleResult::new())
                }
            }
            _ => Ok(ModuleResult::new()),
        }
    }
}

// ---------------------------------------------------------------------------
// Domain pipeline: resolver → brute → CAA
// ---------------------------------------------------------------------------

async fn process_domain(target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
    let mut result = ModuleResult::new();

    // 1. Full DNS resolution (A/AAAA/MX/NS/SOA/TXT)
    let resolver_result = resolve_records(target, ctx).await?;
    result.extend(resolver_result);

    // 2. Subdomain brute-force
    let brute_result = brute_subdomains(target, ctx).await?;
    result.extend(brute_result);

    // 3. CAA record inspection
    let caa_result = lookup_caa(target, ctx).await?;
    result.extend(caa_result);

    Ok(result)
}

// ---------------------------------------------------------------------------
// IP pipeline: reverse DNS → blocklist
// ---------------------------------------------------------------------------

async fn process_ip(target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
    let mut result = ModuleResult::new();

    // 1. Reverse DNS (PTR)
    let ptr_result = reverse_lookup(target, ctx).await?;
    result.extend(ptr_result);

    // 2. DNSBL check
    let bl_result = blocklist_check(target, ctx).await?;
    result.extend(bl_result);

    Ok(result)
}
