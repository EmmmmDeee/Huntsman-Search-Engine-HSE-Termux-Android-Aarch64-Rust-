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
use crate::util::http::{fetch_json, urlencode};

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

        let body: MylnikovResp = fetch_json(&ctx.http, SRC, &url).await?;

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
    use super::*;

    #[test]
    fn accepts_mac_only() {
        let m = Mylnikov;
        assert!(m.accepts(&Target::new(TargetKind::MacAddress, "AA:BB:CC:DD:EE:FF")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn module_metadata() {
        assert_eq!(Mylnikov.name(), "mylnikov");
        assert_eq!(Mylnikov.priority(), 17);
        assert_eq!(Mylnikov.max_timeout_ms(), 10_000);
    }

    #[test]
    fn parse_response() {
        let raw = r#"{"result": 200, "data": {"lat": -33.8688, "lon": 151.2093, "range": 250.0}}"#;
        let r: MylnikovResp = serde_json::from_str(raw).unwrap();
        assert_eq!(r.result, Some(200));
        let d = r.data.unwrap();
        assert!((d.lat.unwrap() - (-33.8688)).abs() < 0.001);
    }

    #[test]
    fn confidence_bands_track_range_accuracy() {
        // Boundaries of each band, plus the missing-range default (wide → 5000).
        assert!((confidence_for_range(Some(0.0)) - 0.75).abs() < 1e-9);
        assert!((confidence_for_range(Some(200.0)) - 0.75).abs() < 1e-9);
        assert!((confidence_for_range(Some(201.0)) - 0.65).abs() < 1e-9);
        assert!((confidence_for_range(Some(1000.0)) - 0.65).abs() < 1e-9);
        assert!((confidence_for_range(Some(5000.0)) - 0.50).abs() < 1e-9);
        assert!((confidence_for_range(Some(5001.0)) - 0.35).abs() < 1e-9);
        // None → 5000 default → the 1001..=5000 band.
        assert!((confidence_for_range(None) - 0.50).abs() < 1e-9);
    }

    fn data(lat: Option<f64>, lon: Option<f64>, range: Option<f64>) -> MylnikovData {
        MylnikovData { lat, lon, range }
    }

    #[test]
    fn tight_fix_builds_high_confidence_entity_with_range() {
        let e = build_location_entity(
            "AA:BB:CC:DD:EE:FF",
            &data(Some(-33.8688), Some(151.2093), Some(150.0)),
            "s",
        )
        .unwrap();
        assert_eq!(e.kind, EntityKind::Coordinates);
        assert_eq!(e.value, "-33.868800,151.209300");
        assert!(e.has_tag("mylnikov") && e.has_tag("geoint") && e.has_tag("bssid-located"));
        assert!((e.confidence - 0.75).abs() < 1e-9);
        let a = &e.evidence[0].attributes;
        assert_eq!(
            a.get("bssid").map(String::as_str),
            Some("AA:BB:CC:DD:EE:FF")
        );
        assert_eq!(a.get("range_m").map(String::as_str), Some("150"));
    }

    #[test]
    fn missing_range_omits_attr_and_uses_default_band() {
        let e = build_location_entity("m", &data(Some(10.0), Some(20.0), None), "s").unwrap();
        assert!((e.confidence - 0.50).abs() < 1e-9);
        assert_eq!(e.evidence[0].attributes.get("range_m"), None);
    }

    #[test]
    fn invalid_or_missing_coords_yield_no_entity() {
        // Missing components.
        assert!(build_location_entity("m", &data(None, Some(1.0), None), "s").is_none());
        assert!(build_location_entity("m", &data(Some(1.0), None, None), "s").is_none());
        // Null Island and out-of-range rejected by the shared validator.
        assert!(build_location_entity("m", &data(Some(0.0), Some(0.0), None), "s").is_none());
        assert!(build_location_entity("m", &data(Some(91.0), Some(0.0), None), "s").is_none());
    }
}
