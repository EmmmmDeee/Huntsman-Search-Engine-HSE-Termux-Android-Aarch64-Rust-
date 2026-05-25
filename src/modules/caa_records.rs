use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::dns::shared_resolver;
use hickory_resolver::proto::rr::{RData, RecordType};

pub struct CaaRecords;

#[async_trait]
impl Module for CaaRecords {
    fn name(&self) -> &'static str {
        "caa_records"
    }

    fn description(&self) -> &'static str {
        "DNS CAA record inspection for domain certificate policy"
    }

    fn priority(&self) -> u8 {
        29
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let domain = target.value.trim();
        if domain.is_empty() {
            return Ok(ModuleResult::new());
        }
        let resolver = shared_resolver();

        let lookup = match resolver.lookup(domain, RecordType::CAA).await {
            Ok(l) => l,
            Err(_) => return Ok(ModuleResult::new()),
        };

        let mut issuers: Vec<String> = Vec::new();
        let mut wildcards: Vec<String> = Vec::new();
        let mut iodefs: Vec<String> = Vec::new();

        for record in lookup.answers() {
            let RData::CAA(caa) = &record.data else {
                continue;
            };
            let value = String::from_utf8_lossy(&caa.value).into_owned();
            match caa.tag.to_ascii_lowercase().as_str() {
                "issue" => issuers.push(value),
                "issuewild" => wildcards.push(value),
                "iodef" => iodefs.push(value),
                _ => {}
            }
        }

        if issuers.is_empty() && wildcards.is_empty() && iodefs.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut entity = Entity::new(EntityKind::Domain, domain, 0.85, &ctx.scan_id);
        entity.tag("caa");
        let mut ev = Evidence::new(
            "caa_records",
            format!(
                "CAA policy published: {} issuer(s), {} wildcard issuer(s)",
                issuers.len(),
                wildcards.len()
            ),
        );
        if !issuers.is_empty() {
            ev = ev.with_attr("issue", issuers.join(","));
        }
        if !wildcards.is_empty() {
            ev = ev.with_attr("issuewild", wildcards.join(","));
        }
        if !iodefs.is_empty() {
            ev = ev.with_attr("iodef", iodefs.join(","));
        }
        entity.add_evidence(ev);

        let mut result = ModuleResult::new();
        result.push(entity);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_domain() {
        let m = CaaRecords;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }
}
