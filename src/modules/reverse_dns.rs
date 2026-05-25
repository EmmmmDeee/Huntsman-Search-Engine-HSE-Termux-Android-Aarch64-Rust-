//! Reverse-DNS lookup. Free, no key.
//!
//! Accepts `IpAddress`, queries PTR records via Cloudflare's resolver,
//! and emits one Domain entity per PTR result tagged `ptr`. The PTR
//! record is the only standardised mechanism for going from an IP back
//! to a hostname — strong evidence for AU-010 (infrastructure consensus)
//! when the same IP is later confirmed by `whois` and `dns_resolver`.

use async_trait::async_trait;
use std::net::IpAddr;

use hickory_resolver::proto::rr::RData;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::dns::shared_resolver;

pub struct ReverseDns;

#[async_trait]
impl Module for ReverseDns {
    fn name(&self) -> &'static str {
        "reverse_dns"
    }

    fn priority(&self) -> u8 {
        // Same band as dns_resolver — runs alongside the forward lookup
        // so the SPA shows them as a pair.
        29
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let ip: IpAddr = match target.value.parse() {
            Ok(ip) => ip,
            Err(_) => return Ok(ModuleResult::new()),
        };

        let resolver = shared_resolver();
        let lookup = match resolver.reverse_lookup(ip).await {
            Ok(l) => l,
            // NXDOMAIN / no PTR / network error → no findings rather than
            // module error. The vast majority of public IPs lack PTRs.
            Err(_) => return Ok(ModuleResult::new()),
        };

        let mut result = ModuleResult::new();
        for record in lookup.answers() {
            let RData::PTR(ptr) = &record.data else {
                continue;
            };
            let host_raw = ptr.0.to_ascii();
            let host = host_raw.trim_end_matches('.');
            if host.is_empty() {
                continue;
            }
            let mut e = Entity::new(EntityKind::Domain, host, 0.85, &ctx.scan_id);
            e.tag(crate::core::tags::PTR);
            e.add_evidence(
                Evidence::new("reverse_dns", format!("PTR record for {ip}"))
                    .with_attr("record_type", "PTR")
                    .with_attr("ip", target.value.as_str()),
            );
            result.push(e);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_ip() {
        let m = ReverseDns;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
    }
}
