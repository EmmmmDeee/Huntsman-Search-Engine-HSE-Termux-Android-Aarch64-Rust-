//! Email domain geolocation — infer geography from email domain
//! infrastructure patterns.
//!
//! Classifies email domains by ccTLD (alice@company.com.au → Australia)
//! and by regional ISP provider (bigpond.com → Telstra, Australia).
//! Skips consumer email providers (Gmail, Outlook, etc.) since they
//! reveal no geographic signal. No network calls.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

mod tables;
use tables::CONSUMER_PROVIDERS;

mod infer;
use infer::{detect_corporate_provider, infer_geo_from_email_domain};

#[cfg(test)]
mod tests;

const SRC: &str = "email_header_geo";

pub struct EmailHeaderGeo;

#[async_trait]
impl Module for EmailHeaderGeo {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Extract geographic signals from email domain infrastructure patterns"
    }

    fn priority(&self) -> u8 {
        92
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Address];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        let email = &target.value;
        let Some((_, domain)) = email.split_once('@') else {
            return Ok(result);
        };
        // DNS labels are case-insensitive (RFC 4343); fold the domain so the
        // lowercase ccTLD / regional-provider tables still match a mixed-case
        // address such as `User@Bigpond.COM.AU` instead of missing entirely.
        let domain = domain.to_ascii_lowercase();
        let domain = domain.as_str();

        if CONSUMER_PROVIDERS
            .iter()
            .any(|p| crate::util::domains::is_or_subdomain_of(domain, p))
        {
            return Ok(result);
        }

        if let Some(geo) = infer_geo_from_email_domain(domain) {
            let mut e = Entity::new(
                EntityKind::Address,
                geo.region,
                geo.confidence,
                &ctx.scan_id,
            );
            e.tag("geoint");
            e.tag("coarse");
            e.tag("email-infra-inferred");
            // Attach au-state when region resolves to Australia so AU-056
            // jurisdiction cross-check and the address→coords enrichment pass
            // can use it without re-parsing the string.
            if geo.region.eq_ignore_ascii_case("australia") {
                e.tag("country:AU");
                e.tag("au-state:AU"); // coarse — state unknown from ccTLD alone
            } else if let Some(state) = crate::util::address_au::state_code(geo.region) {
                e.tag(format!("au-state:{state}"));
            }
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!(
                        "Email domain '{}' suggests {} ({})",
                        domain, geo.region, geo.reason
                    ),
                )
                .with_attr("domain", domain)
                .with_attr("method", geo.reason),
            );
            result.push(e);
        }

        if let Some((provider, region)) = detect_corporate_provider(domain) {
            let mut e = Entity::new(EntityKind::Address, region, 0.40, &ctx.scan_id);
            e.tag("geoint");
            e.tag("coarse");
            e.tag("email-provider-inferred");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!(
                        "Email domain '{}' uses {} (regional provider)",
                        domain, provider
                    ),
                )
                .with_attr("domain", domain)
                .with_attr("provider", provider),
            );
            result.push(e);
        }

        Ok(result)
    }
}
