//! Photon geocoder (Komoot). Free, no API key.
//!
//! Forward: `GET https://photon.komoot.io/api/?q={address}&limit=1`
//! Reverse: `GET https://photon.komoot.io/reverse?lon={lon}&lat={lat}`
//!
//! Complements the Nominatim-based `geocode` module with a second independent
//! geocoding source for corroboration. Every property Photon returns is used:
//! the resolved place **name** confirms *what* was matched, and the OSM
//! `key`/`value` classify its *nature* (e.g. `place/city` vs `amenity/restaurant`
//! — a coarse city hit vs a precise POI), surfaced as an `osm:<value>` tag.
//!
//! The two response → entity mappings live in the pure [`build::build_forward`] /
//! [`build::build_reverse`] so they are unit-tested without a live API; the
//! `forward`/`reverse` methods own only transport.

use async_trait::async_trait;

use crate::core::{
    entity::EntityKind,
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;
use crate::util::http::urlencode;

mod types;
use types::PhotonResp;

mod build;
use build::{build_forward, build_reverse};

#[cfg(test)]
mod tests;

pub struct Photon;

#[async_trait]
impl Module for Photon {
    fn name(&self) -> &'static str {
        "photon"
    }
    fn description(&self) -> &'static str {
        "Photon geocoder (Komoot) — independent forward/reverse geocoding to corroborate and cross-check location fixes"
    }
    fn priority(&self) -> u8 {
        20
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Address | TargetKind::Coordinates)
    }
    fn max_timeout_ms(&self) -> u64 {
        4_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Coordinates, EntityKind::Address];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        match target.kind {
            TargetKind::Address => self.forward(target, ctx).await,
            TargetKind::Coordinates => self.reverse(target, ctx).await,
            _ => Ok(ModuleResult::new()),
        }
    }
}

impl Photon {
    async fn forward(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let addr = target.value.trim();
        if addr.len() <= 2 {
            return Ok(ModuleResult::new());
        }
        // A bare country name geocodes to the country centroid — not a subject
        // location — and cascades into the geo-convergence rules. Refuse it here
        // too, matching `geocode` (see `util::place_grain`); a finer address
        // still resolves normally.
        if crate::util::place_grain::is_bare_country(addr) {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://photon.komoot.io/api/?q={}&limit=1",
            urlencode(addr),
        );

        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send_tagged(build::SRC)
            .await?;
        // Photon signals a genuine "no match" with a 200 + empty `features`
        // array, never a non-2xx or a malformed body — so a non-2xx status or a
        // JSON parse failure is a real geocoder outage, not a clean miss.
        // Surface it instead of reporting the address as ungeocodable.
        if !resp.status().is_success() {
            return Err(crate::util::http::http_status_error(build::SRC, resp).await);
        }
        let body: PhotonResp = crate::util::http::json_decode(build::SRC, resp).await?;

        let mut result = ModuleResult::new();
        if let Some(feature) = body.features.first()
            && let Some(e) = build_forward(addr, feature, &ctx.scan_id)
        {
            result.push(e);
        }
        Ok(result)
    }

    async fn reverse(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let (lat, lon) = crate::util::geo::parse_coords(&target.value)?;

        let url = format!("https://photon.komoot.io/reverse?lon={lon:.6}&lat={lat:.6}",);

        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send_tagged(build::SRC)
            .await?;
        // Photon signals a genuine "no match" with a 200 + empty `features`
        // array, never a non-2xx or a malformed body — so a non-2xx status or a
        // JSON parse failure is a real geocoder outage, not a clean miss.
        // Surface it instead of reporting the address as ungeocodable.
        if !resp.status().is_success() {
            return Err(crate::util::http::http_status_error(build::SRC, resp).await);
        }
        let body: PhotonResp = crate::util::http::json_decode(build::SRC, resp).await?;

        let mut result = ModuleResult::new();
        if let Some(props) = body.features.first().and_then(|f| f.properties.as_ref())
            && let Some(e) = build_reverse(lat, lon, props, &ctx.scan_id)
        {
            result.push(e);
        }
        Ok(result)
    }
}
