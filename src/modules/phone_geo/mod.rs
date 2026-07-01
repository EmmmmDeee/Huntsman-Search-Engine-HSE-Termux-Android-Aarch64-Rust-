//! Phone geolocation — two complementary offline inference layers on a phone
//! number, run in a single pass.
//!
//! Fuses the former `phone_area_geo` and `phone_carrier_geo` modules (both
//! passive, no-network, pure lookup-table inference on the same `Phone` input):
//!
//! 1. **Area-code pass** — for countries with well-defined geographic area codes
//!    (Australia, UK, US/Canada, Germany, France, Japan, NZ) it maps the area
//!    code to a city/region, emitting an `Address` (and an inline `Coordinates`
//!    where [`crate::util::city_coords`] knows the city). The existing
//!    `geo_intel` module maps phone prefixes to country centroids at 0.52; this
//!    is a second, higher-granularity layer.
//! 2. **Carrier pass** — Australian (04xx) and UK (07xxx) mobile prefixes are
//!    carrier-allocated; carrier dominance varies by region (Telstra
//!    rural/regional, Optus metro/suburban, Vodafone metro). Maps the prefix to
//!    the carrier and emits a coarse country `Address` with a market-share hint.
//!
//! The two passes are independent: the area-code pass returns nothing for a
//! mobile number, the carrier pass returns nothing for a landline, and a
//! no-match in one never suppresses the other — both run every time.
//!
//! No network calls. Runs in < 1ms. Priority 93 so it fires before geocoding
//! modules (the higher of the two source modules' priorities).
//!
//! Evidence source strings are kept per-strategy — the area-code pass stamps
//! [`SRC_AREA`] and the carrier pass stamps [`SRC_CARRIER`] — because the
//! correlator's geo-source classification keys on those exact literals
//! (`is_anchoring_geo_source` / `geo_source_class` in
//! `crate::core::correlator::rules::location`). This mirrors how the
//! `au_unclaimed` merge kept the folded-in `qld_unclaimed` source needle.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

mod data;

#[cfg(test)]
mod tests;

/// Module name and the carrier pass's evidence source needle.
pub(super) const SRC: &str = "phone_geo";

/// Evidence source for the area-code pass — kept as the former module name so the
/// correlator's geo-source classification continues to recognise it.
pub(super) const SRC_AREA: &str = "phone_area_geo";

/// Evidence source for the carrier pass — kept as the former module name for the
/// same correlator-classification reason as [`SRC_AREA`].
pub(super) const SRC_CARRIER: &str = "phone_carrier_geo";

pub struct PhoneGeo;

#[async_trait]
impl Module for PhoneGeo {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Phone area-code city/region and mobile-carrier regional geo inference (offline)"
    }

    fn priority(&self) -> u8 {
        93
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Phone)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn produces(&self) -> &'static [EntityKind] {
        // Union of the two source modules: area-code emits Address + Coordinates,
        // carrier emits Address.
        const KINDS: &[EntityKind] = &[EntityKind::Address, EntityKind::Coordinates];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        let digits: String = target.value.chars().filter(char::is_ascii_digit).collect();

        // Pass 1: area-code → city/region (former `phone_area_geo`).
        area_code_pass(&digits, ctx, &mut result);
        // Pass 2: mobile prefix → carrier + regional hint (former
        // `phone_carrier_geo`). Independent of pass 1: a number is either a
        // geographic landline (pass 1) or a mobile (pass 2), and either pass
        // finding nothing must not stop the other from running.
        carrier_pass(&digits, ctx, &mut result);

        Ok(result)
    }
}

/// Area-code geolocation pass (former `phone_area_geo`): maps a country dialling
/// prefix and geographic area code to a city/region `Address`, plus an inline
/// `Coordinates` one confidence tier below where the city is known. Emits the
/// `phone_area_geo` evidence source verbatim.
fn area_code_pass(digits: &str, ctx: &ModuleContext, result: &mut ModuleResult) {
    if digits.len() < 8 {
        return;
    }

    if let Some(geo) = data::lookup_area_code(digits) {
        let mut e = Entity::new(
            EntityKind::Address,
            geo.location,
            geo.confidence,
            &ctx.scan_id,
        );
        e.tag("geoint");
        e.tag("phone-area-code");
        e.tag(format!("country:{}", geo.country_code));
        if geo.country_code == "AU"
            && let Some(sc) = crate::util::address_au::state_code(geo.location)
        {
            e.tag(format!("au-state:{sc}"));
        }
        let ev = Evidence::new(
            SRC_AREA,
            format!(
                "Phone area code {} → {}, {}",
                geo.area_code, geo.location, geo.country
            ),
        )
        .with_attr("area_code", geo.area_code)
        .with_attr("country", geo.country)
        .with_attr("country_code", geo.country_code);
        e.add_evidence(ev.clone());
        result.push(e);

        // Inline Coordinates: city_coords gives a lat/lon for the primary
        // city named in the location string. Confidence one tier below the
        // Address (area-code geo is city-level, not GPS).
        if let Some((lat, lon)) = crate::util::city_coords::city_coords(geo.location) {
            let coord_val = format!("{lat:.4},{lon:.4}");
            let mut c = Entity::new(
                EntityKind::Coordinates,
                &coord_val,
                geo.confidence - 0.08,
                &ctx.scan_id,
            );
            c.tag("addr-derived");
            c.tag("geoint");
            c.tag("phone-area-code");
            c.tag(format!("country:{}", geo.country_code));
            if geo.country_code == "AU"
                && let Some(sc) = crate::util::address_au::state_code(geo.location)
            {
                c.tag(format!("au-state:{sc}"));
            }
            c.add_evidence(ev);
            result.push(c);
        }
    }
}

/// Mobile-carrier geolocation pass (former `phone_carrier_geo`): AU (04xx) / UK
/// (07xxx) mobile prefix → allocated carrier + coarse country `Address` carrying
/// a market-share network hint. Emits the `phone_carrier_geo` evidence source
/// verbatim.
fn carrier_pass(digits: &str, ctx: &ModuleContext, result: &mut ModuleResult) {
    if digits.len() < 10 {
        return;
    }

    if let Some(carrier) = data::identify_carrier(digits) {
        let mut e = Entity::new(
            EntityKind::Address,
            carrier.country,
            carrier.confidence,
            &ctx.scan_id,
        );
        e.tag("geoint");
        e.tag(crate::core::tags::COARSE);
        e.tag("carrier-inferred");
        if carrier.country.eq_ignore_ascii_case("australia") {
            e.tag("country:AU");
        }
        e.add_evidence(
            Evidence::new(
                SRC_CARRIER,
                format!("Mobile carrier {} ({})", carrier.carrier, carrier.country),
            )
            .with_attr("carrier", carrier.carrier)
            .with_attr("country", carrier.country)
            .with_attr("network_type", carrier.network_hint),
        );
        result.push(e);
    }
}
