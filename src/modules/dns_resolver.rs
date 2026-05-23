//! DNS resolver via Cloudflare. Yields A → IpAddress, MX → Domain, TXT → enriched parent.

use async_trait::async_trait;
use hickory_resolver::{
    TokioAsyncResolver,
    config::{ResolverConfig, ResolverOpts},
};

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

pub struct DnsResolver;

#[async_trait]
impl Module for DnsResolver {
    fn name(&self) -> &'static str {
        "dns_resolver"
    }

    fn priority(&self) -> u8 {
        30
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());

        let domain = &target.value;
        let mut result = ModuleResult::new();

        // A records
        if let Ok(lookup) = resolver.lookup_ip(domain.as_str()).await {
            for ip in lookup.iter() {
                let mut e = Entity::new(EntityKind::IpAddress, ip.to_string(), 0.95, &ctx.scan_id);
                e.add_evidence(
                    Evidence::new("dns_resolver", format!("A record for {domain}"))
                        .with_attr("record_type", "A")
                        .with_attr("domain", domain),
                );
                result.push(e);
            }
        }

        // MX records
        if let Ok(lookup) = resolver.mx_lookup(domain.as_str()).await {
            for mx in lookup.iter() {
                let host = mx.exchange().to_ascii();
                let host = host.trim_end_matches('.').to_string();
                if !host.is_empty() {
                    let mut e = Entity::new(EntityKind::Domain, &host, 0.85, &ctx.scan_id);
                    e.tag("mx");
                    e.add_evidence(
                        Evidence::new("dns_resolver", format!("MX record for {domain}"))
                            .with_attr("record_type", "MX")
                            .with_attr("priority", mx.preference().to_string()),
                    );
                    result.push(e);
                }
            }
        }

        // TXT records → enrich parent
        if let Ok(lookup) = resolver.txt_lookup(domain.as_str()).await {
            let txts: Vec<String> = lookup.iter().map(|t| t.to_string()).collect();
            if !txts.is_empty() {
                let mut dom = Entity::new(EntityKind::Domain, domain, 0.90, &ctx.scan_id);
                dom.add_evidence(
                    Evidence::new("dns_resolver", format!("{} TXT records", txts.len()))
                        .with_attr("txt_records", txts.join(" | ")),
                );
                result.push(dom);
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_domain_only() {
        let m = DnsResolver;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x")));
    }
}
