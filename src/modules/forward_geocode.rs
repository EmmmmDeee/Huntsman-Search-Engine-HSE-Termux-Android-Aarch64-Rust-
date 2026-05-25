//! Forward geocoding — Address → Coordinates via OSM Nominatim.
//!
//! Free, no API key. Same endpoint as reverse_geocode but in the
//! opposite direction: takes a text address and returns lat/lon.
//! Rate-limited to 1 req/s by Nominatim's usage policy.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::urlencode;

#[derive(Deserialize)]
struct NominatimResult {
    #[serde(default)]
    lat: Option<String>,
    #[serde(default)]
    lon: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default, rename = "type")]
    place_type: Option<String>,
}

pub struct ForwardGeocode;

#[async_trait]
impl Module for ForwardGeocode {
    fn name(&self) -> &'static str {
        "forward_geocode"
    }

    fn description(&self) -> &'static str {
        "Forward geocoding: Address text to GPS coordinates via OSM Nominatim"
    }

    fn priority(&self) -> u8 {
        20
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Address)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let addr = target.value.trim();
        if addr.is_empty() || addr.len() <= 2 {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://nominatim.openstreetmap.org/search?q={}&format=json&limit=1&addressdetails=1",
            urlencode(addr)
        );

        let resp = ctx
            .http
            .get(&url)
            .header(
                "User-Agent",
                "huntsman-search-engine/1.0 (+https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-)",
            )
            .send()
            .await;

        let results: Vec<NominatimResult> = match resp {
            Ok(r) if r.status().is_success() => r.json().await.unwrap_or_default(),
            _ => {
                if let Some(body) = crate::util::curl::fetch(&url, crate::MODULE_TIMEOUT_MS).await {
                    serde_json::from_str(&body).unwrap_or_default()
                } else {
                    return Ok(ModuleResult::new());
                }
            }
        };

        let mut result = ModuleResult::new();

        if let Some(first) = results.first()
            && let (Some(lat_str), Some(lon_str)) = (&first.lat, &first.lon)
            && let (Ok(lat), Ok(lon)) = (lat_str.parse::<f64>(), lon_str.parse::<f64>())
        {
            let coords = format!("{lat:.6},{lon:.6}");
            let mut e = Entity::new(EntityKind::Coordinates, &coords, 0.60, &ctx.scan_id);
            e.tag("geocoded");
            let mut ev =
                Evidence::new("forward_geocode", format!("Geocoded \"{addr}\" → {coords}"))
                    .with_attr("input_address", addr)
                    .with_attr("latitude", lat_str)
                    .with_attr("longitude", lon_str);
            if let Some(dn) = &first.display_name {
                ev = ev.with_attr("display_name", dn);
            }
            if let Some(pt) = &first.place_type {
                ev = ev.with_attr("place_type", pt);
            }
            e.add_evidence(ev);
            result.push(e);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_address_only() {
        let m = ForwardGeocode;
        assert!(m.accepts(&Target::new(TargetKind::Address, "Brisbane")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    }
}
