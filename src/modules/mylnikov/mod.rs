//! Mylnikov GEO — free BSSID-to-coordinates resolution. No API key.
//!
//! Endpoint: `GET https://api.mylnikov.org/geolocation/wifi?v=1.1&data=open&bssid={MAC}`
//!
//! Complements the WiGLE BSSID lookup with a no-auth alternative.
//! Lower precision but useful when WiGLE keys are exhausted.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::geo::is_valid_coords;
use crate::util::http::urlencode;

const SRC: &str = "mylnikov";

pub struct Mylnikov;

#[derive(Deserialize)]
struct MylnikovResp {
    #[serde(default)]
    result: Option<i32>,
    #[serde(default)]
    data: Option<MylnikovData>,
}

#[derive(Deserialize)]
struct MylnikovData {
    #[serde(default)]
    lat: Option<f64>,
    #[serde(default)]
    lon: Option<f64>,
    #[serde(default)]
    range: Option<f64>,
}

/// Map the reported accuracy `range` (metres) to a confidence band — a tight fix
/// is trusted more than a city-block-wide one. A missing range is treated as the
/// wide 5000 m default. **Pure**.
fn confidence_for_range(range: Option<f64>) -> f64 {
    match range.unwrap_or(5000.0) as u64 {
        0..=200 => 0.75,
        201..=1000 => 0.65,
        1001..=5000 => 0.50,
        _ => 0.35,
    }
}

/// Build the BSSID-location entity from a Mylnikov `data` block. **Pure** (no
/// network/IO): returns `None` when the fix lacks usable coordinates — missing
/// lat/lon or coordinates rejected by the shared validator (Null Island,
/// out-of-range, non-finite). Otherwise emits a `Coordinates` entity whose
/// confidence reflects the reported accuracy via [`confidence_for_range`].
fn build_location_entity(bssid: &str, data: &MylnikovData, scan_id: &str) -> Option<Entity> {
    let (lat, lon) = (data.lat?, data.lon?);
    if !is_valid_coords(lat, lon) {
        return None;
    }
    let coords = format!("{lat:.6},{lon:.6}");
    let mut e = Entity::new(
        EntityKind::Coordinates,
        &coords,
        confidence_for_range(data.range),
        scan_id,
    );
    e.tag("mylnikov");
    e.tag("geoint");
    e.tag("bssid-located");
    if let Some(state) = crate::util::geo::au_state_for_coords(lat, lon) {
        e.tag(format!("au-state:{state}"));
        e.tag("country:AU");
    }
    let mut ev = Evidence::new(SRC, format!("Mylnikov BSSID {bssid} -> {coords}"))
        .with_attr("bssid", bssid)
        .with_attr("latitude", format!("{lat:.6}"))
        .with_attr("longitude", format!("{lon:.6}"));
    if let Some(range) = data.range {
        ev = ev.with_attr("range_m", format!("{range:.0}"));
    }
    e.add_evidence(ev);
    Some(e)
}

#[async_trait]
impl Module for Mylnikov {
    fn name(&self) -> &'static str {
        "mylnikov"
    }
    fn description(&self) -> &'static str {
        "Mylnikov free BSSID-to-coordinates WiFi geolocation"
    }
    fn priority(&self) -> u8 {
        17
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::MacAddress)
    }
    fn max_timeout_ms(&self) -> u64 {
        // Single network request with no per-request timeout. The explicit
        // 3s here matched MODULE_TIMEOUT_MS, so a slow-but-connected response
        // was killed by the engine as a spurious "timeout" before it could
        // return a fix. Budget above the connect timeout with read headroom.
        10_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Coordinates];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let bssid = target.value.trim();
        if bssid.len() < 12 {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://api.mylnikov.org/geolocation/wifi?v=1.1&data=open&bssid={}",
            urlencode(bssid),
        );

        let resp = match ctx.http.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return Ok(ModuleResult::new()),
        };

        if !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }

        let body: MylnikovResp = match crate::util::http::json_scanned(resp, SRC).await {
            Ok(b) => b,
            Err(_) => return Ok(ModuleResult::new()),
        };

        if body.result != Some(200) {
            return Ok(ModuleResult::new());
        }
        let Some(data) = body.data else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        if let Some(e) = build_location_entity(bssid, &data, &ctx.scan_id) {
            result.push(e);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
