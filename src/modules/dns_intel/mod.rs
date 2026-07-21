//! Unified DNS intelligence module — resolution, brute-force, structural
//! permutation, CAA, reverse, and blocklist checks dispatched by target kind:
//!
//! **Domain targets** (sequential):
//!   1. *Resolution* — A / AAAA / MX / NS / SOA / TXT lookups via `tokio::join!`.
//!   2. *Subdomain brute-force* — 146-label common-name dictionary, bounded
//!      to 12 concurrent lookups.
//!   3. *Structural permutation* — `altdns`-class enumeration: once a target
//!      IS an already-discovered subdomain (≥3 labels), generate structural
//!      siblings of its own leftmost label (numeric neighbours, environment/
//!      stage prefixes and suffixes, separator normalisation) and resolve
//!      them. Recurses automatically across the whole scan — see `permute`'s
//!      module doc.
//!   4. *SRV service-discovery* — RFC 2782 `_service._proto.domain` records
//!      (AD domain controllers, mail/collaboration, VoIP, …), apex-only. Each
//!      resolved target host is a new Domain pivot. See `srv`'s module doc.
//!   5. *DKIM selectors* — RFC 6376 `<selector>._domainkey.domain` probing for
//!      mail-vendor attribution and weak-key surfacing, apex-only. See `dkim`.
//!   6. *CAA inspection* — RFC 8659 Certification Authority Authorization.
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
mod dkim;
mod helpers;
mod permute;
mod resolve;
// Re-exported so `doh_resolver` (the primary DNS transport on Termux) reuses the
// same CAA `iodef`→entity mapping instead of duplicating it.
pub(crate) use resolve::iodef_entities;
mod resolve_batch;
mod srv;
#[cfg(test)]
mod tests;
mod wildcard;

use async_trait::async_trait;

use crate::core::{
    entity::EntityKind,
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

use self::brute::brute_subdomains;
use self::dkim::dkim_enumerate;
use self::permute::permute_subdomains;
use self::resolve::{blocklist_check, lookup_caa, resolve_records, reverse_lookup};
use self::srv::srv_enumerate;

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
        "DNS intelligence sweep — resolution, subdomain brute-force, blocklist checks, reverse DNS, and CAA enumeration"
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
        // Two techniques, because this module does two things. Resolving the live
        // A/AAAA/MX/NS/SOA/TXT records (and reverse PTR / DNSBL) is Gather Victim
        // Network Information: DNS (T1590.002). But it ALSO actively brute-forces
        // subdomains against a 146-label common-name dictionary
        // (`brute::brute_subdomains` over `SUBDOMAINS`) — iteratively probing
        // infrastructure from a wordlist, which is Active Scanning: Wordlist
        // Scanning (T1595.003), not a passive database lookup.
        &["T1590.002", "T1595.003"]
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

    // 2. Subdomain brute-force (generic common-name dictionary)
    let brute_result = brute_subdomains(target, ctx).await?;
    result.extend(brute_result);

    // 3. Structural permutation of the CURRENT target's own leftmost label
    // (a no-op on the bare apex; fires once this target is itself a discovered
    // subdomain — including one the brute-force pass just found, or one the
    // engine re-dispatches from a prior round). See `permute` module doc.
    let permute_result = permute_subdomains(target, ctx).await?;
    result.extend(permute_result);

    // 4. SRV service-discovery enumeration (apex-only; a no-op on subdomains).
    // Exposes the concrete host:port of enterprise services — AD domain
    // controllers, mail/collab, VoIP — each a new Domain pivot. See `srv` doc.
    let srv_result = srv_enumerate(target, ctx).await?;
    result.extend(srv_result);

    // 5. DKIM selector enumeration (apex-only). Probes common selectors at
    // <selector>._domainkey.<domain> to attribute the mail platform/vendor and
    // surface weak signing keys. See `dkim` module doc.
    let dkim_result = dkim_enumerate(target, ctx).await?;
    result.extend(dkim_result);

    // 6. CAA record inspection
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
