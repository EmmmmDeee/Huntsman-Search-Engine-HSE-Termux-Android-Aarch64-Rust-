//! Geolocation intelligence — free-API IP geo and E.164 phone prefix lookup.
//!
//! For IP targets: queries free geo APIs (ipapi.co, freeipapi.com) that aren't
//! covered by ip_geo or ip_whois_geo, providing a third and fourth independent
//! source for AU-014 geo-cluster correlation.
//!
//! For Phone targets: derives a coarse country-centroid coordinate from the
//! ITU E.164 country prefix (offline, no API call).
//!
//! Free APIs used:
//!   - ipapi.co     — 1000 req/day, HTTPS, no key required
//!   - freeipapi.com — unlimited, HTTPS, no key required

use async_trait::async_trait;

use crate::core::{
    entity::EntityKind,
    error::Result,
    module::{Module, ModuleCategory, ModuleCost, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

mod ip_geo;
mod phone_geo;

#[cfg(test)]
mod tests;

pub(super) const SRC: &str = "geo_intel";

pub struct GeoIntel;

#[async_trait]
impl Module for GeoIntel {
    fn name(&self) -> &'static str {
        "geo_intel"
    }

    fn description(&self) -> &'static str {
        "Free-API IP geolocation (ipapi.co, freeipapi.com) and E.164 phone prefix lookup"
    }

    fn priority(&self) -> u8 {
        22
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress | TargetKind::Phone)
    }

    fn max_timeout_ms(&self) -> u64 {
        25_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Coordinates];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        match target.kind {
            TargetKind::IpAddress => ip_geo::process_ip(target, ctx).await,
            TargetKind::Phone => phone_geo::process_phone_prefix_only(target, ctx).await,
            _ => Ok(ModuleResult::new()),
        }
    }
}
