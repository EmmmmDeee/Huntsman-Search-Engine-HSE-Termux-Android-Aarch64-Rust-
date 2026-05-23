//! AlienVault OTX — public threat-intel pulse lookup.
//!
//! Free, no key required. Endpoint:
//!   `https://otx.alienvault.com/api/v1/indicators/{IPv4|domain}/{value}/general`
//!
//! Returns the count of OTX "pulses" (community-reported threat indicators)
//! the target appears in. Used by `AU-010` (infrastructure consensus) when
//! threat intel adds another source to an already-discovered domain/IP.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

pub struct AlienVaultOtx;

#[derive(Deserialize)]
struct OtxResp {
    pulse_info: Option<PulseInfo>,
}

#[derive(Deserialize)]
struct PulseInfo {
    count: Option<u64>,
}

#[async_trait]
impl Module for AlienVaultOtx {
    fn name(&self) -> &'static str {
        "alienvault_otx"
    }

    fn priority(&self) -> u8 {
        78
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress | TargetKind::Domain)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let (itype, kind) = match target.kind {
            TargetKind::IpAddress => ("IPv4", EntityKind::IpAddress),
            TargetKind::Domain => ("domain", EntityKind::Domain),
            _ => return Ok(ModuleResult::new()),
        };

        let url = format!(
            "https://otx.alienvault.com/api/v1/indicators/{}/{}/general",
            itype,
            urlencode(&target.value)
        );

        let resp = ctx
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::module("alienvault_otx", e.to_string()))?;

        // 404 = target not in OTX — treat as no findings, not an error.
        if resp.status().as_u16() == 404 || !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }

        let data: OtxResp = resp
            .json()
            .await
            .map_err(|e| Error::module("alienvault_otx", e.to_string()))?;

        let pulse_count = data.pulse_info.and_then(|p| p.count).unwrap_or(0);
        if pulse_count == 0 {
            return Ok(ModuleResult::new());
        }

        let mut entity = Entity::new(kind, &target.value, 0.72, &ctx.scan_id);
        entity.tag("threat-intel");
        entity.add_evidence(
            Evidence::new(
                "alienvault_otx",
                format!("OTX: {pulse_count} threat pulse(s)"),
            )
            .with_attr("pulse_count", pulse_count.to_string())
            .with_attr("indicator_type", itype),
        );

        let mut result = ModuleResult::new();
        result.push(entity);
        Ok(result)
    }
}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ip_and_domain() {
        let m = AlienVaultOtx;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }

    #[test]
    fn is_free() {
        assert_eq!(AlienVaultOtx.cost(), ModuleCost::Free);
    }
}
