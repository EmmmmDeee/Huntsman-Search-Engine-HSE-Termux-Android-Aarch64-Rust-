//! GPS / network location fix for signal_radar — mirrors device_sensors/gps.rs.

use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
};
use crate::util::termux::termux_cmd;

use super::SRC;

#[derive(Deserialize)]
struct Fix {
    latitude: f64,
    longitude: f64,
    altitude: Option<f64>,
    accuracy: Option<f64>,
    speed: Option<f64>,
    bearing: Option<f64>,
    provider: Option<String>,
}

/// True if `(lat, lon)` is a usable geographic fix.
fn is_valid_fix(lat: f64, lon: f64) -> bool {
    crate::util::geo::is_valid_coords(lat, lon)
}

/// Confidence for an on-device location fix.
///
/// Provider sets the ceiling (GPS 0.90, network 0.65); accuracy radius
/// scales it down for imprecise fixes.
fn fix_confidence(provider: &str, accuracy_m: Option<f64>) -> f64 {
    let ceiling: f64 = if provider == "gps" { 0.90 } else { 0.65 };
    match accuracy_m {
        Some(a) if a > 0.0 => {
            let scaled = if a <= 20.0 {
                ceiling
            } else if a <= 100.0 {
                ceiling - 0.05
            } else if a <= 500.0 {
                ceiling - 0.15
            } else if a <= 2000.0 {
                ceiling - 0.25
            } else {
                ceiling - 0.35
            };
            scaled.clamp(0.30, 0.90)
        }
        _ => ceiling,
    }
}

fn parse_fix(stdout: &[u8], scan_id: &str) -> ModuleResult {
    let fix: Fix = match serde_json::from_slice(stdout) {
        Ok(v) => v,
        Err(_) => return ModuleResult::new(),
    };

    if !is_valid_fix(fix.latitude, fix.longitude) {
        return ModuleResult::new();
    }

    let provider = fix.provider.as_deref().unwrap_or("network");
    let confidence = fix_confidence(provider, fix.accuracy);
    let coords = format!("{:.7},{:.7}", fix.latitude, fix.longitude);

    let mut e = Entity::new(EntityKind::Coordinates, &coords, confidence, scan_id);
    e.tag("geoint");
    e.tag("device-sensor");
    e.tag(format!("provider:{provider}"));
    if let Some(a) = fix.accuracy.filter(|a| *a > 0.0) {
        e.tag(format!("accuracy:{}m", a as u64));
    }

    e.add_evidence(
        Evidence::new(SRC, format!("Location fix via {provider}"))
            .with_attr("latitude", fix.latitude.to_string())
            .with_attr("longitude", fix.longitude.to_string())
            .with_attr("altitude", fix.altitude.unwrap_or(0.0).to_string())
            .with_attr("accuracy_m", fix.accuracy.unwrap_or(0.0).to_string())
            .with_attr("speed", fix.speed.unwrap_or(0.0).to_string())
            .with_attr("bearing", fix.bearing.unwrap_or(0.0).to_string())
            .with_attr("provider", provider),
    );

    let mut result = ModuleResult {
        entities: Vec::with_capacity(1),
    };
    result.push(e);
    result
}

/// Fetch a location fix from `termux-location -p <provider> -r once`.
async fn fetch_fix(provider: &str, timeout_ms: u64, scan_id: &str) -> ModuleResult {
    match termux_cmd(
        "termux-location",
        &["-p", provider, "-r", "once"],
        timeout_ms,
    )
    .await
    {
        Some(stdout) => parse_fix(&stdout, scan_id),
        None => ModuleResult::new(),
    }
}

/// Attempt GPS fix (12 s), fall back to network fix (8 s).
pub(super) async fn scan_gps(scan_id: &str) -> ModuleResult {
    let gps = fetch_fix("gps", 12_000, scan_id).await;
    if !gps.is_empty() {
        return gps;
    }
    fetch_fix("network", 8_000, scan_id).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::EntityKind;

    // ── is_valid_fix ──────────────────────────────────────────────────────────

    #[test]
    fn is_valid_fix_accepts_real_coordinates() {
        assert!(is_valid_fix(-27.4705, 153.0260));
        assert!(is_valid_fix(51.5074, -0.1278));
    }

    #[test]
    fn is_valid_fix_rejects_null_island() {
        assert!(!is_valid_fix(0.0, 0.0));
    }

    #[test]
    fn is_valid_fix_rejects_out_of_range_coords() {
        assert!(!is_valid_fix(91.0, 0.0));
        assert!(!is_valid_fix(0.0, 181.0));
        assert!(!is_valid_fix(-91.0, 0.0));
    }

    // ── fix_confidence ────────────────────────────────────────────────────────

    #[test]
    fn fix_confidence_gps_no_accuracy_returns_ceiling() {
        let c = fix_confidence("gps", None);
        assert!((c - 0.90).abs() < 1e-9, "gps ceiling = {c}");
    }

    #[test]
    fn fix_confidence_network_no_accuracy_returns_ceiling() {
        let c = fix_confidence("network", None);
        assert!((c - 0.65).abs() < 1e-9, "network ceiling = {c}");
    }

    #[test]
    fn fix_confidence_gps_accuracy_tiers() {
        assert!((fix_confidence("gps", Some(10.0)) - 0.90).abs() < 1e-9);
        assert!((fix_confidence("gps", Some(20.0)) - 0.90).abs() < 1e-9);
        assert!((fix_confidence("gps", Some(50.0)) - 0.85).abs() < 1e-9);
        assert!((fix_confidence("gps", Some(200.0)) - 0.75).abs() < 1e-9);
        assert!((fix_confidence("gps", Some(1000.0)) - 0.65).abs() < 1e-9);
        assert!((fix_confidence("gps", Some(5000.0)) - 0.55).abs() < 1e-9);
    }

    #[test]
    fn fix_confidence_network_large_radius_clamps_to_floor() {
        // network ceiling 0.65 − 0.35 = 0.30, which is the clamp floor.
        assert!((fix_confidence("network", Some(5000.0)) - 0.30).abs() < 1e-9);
    }

    #[test]
    fn fix_confidence_zero_accuracy_falls_through_to_ceiling() {
        // a = 0.0 does not satisfy `a > 0.0`; falls through to the `_ =>` arm.
        assert!((fix_confidence("gps", Some(0.0)) - 0.90).abs() < 1e-9);
    }

    // ── parse_fix ─────────────────────────────────────────────────────────────

    #[test]
    fn parse_fix_valid_gps_json_emits_coordinates_entity() {
        let json = br#"{"latitude":-27.4705,"longitude":153.0260,"altitude":10.0,"accuracy":5.0,"speed":0.0,"bearing":0.0,"provider":"gps"}"#;
        let result = parse_fix(json, "test-scan");
        assert_eq!(result.len(), 1);
        let e = &result.entities[0];
        assert_eq!(e.kind, EntityKind::Coordinates);
        assert!(e.has_tag("geoint"));
        assert!(e.has_tag("device-sensor"));
        assert!(e.has_tag("provider:gps"));
        assert!(e.has_tag("accuracy:5m"));
    }

    #[test]
    fn parse_fix_null_island_returns_empty() {
        let json = br#"{"latitude":0.0,"longitude":0.0,"provider":"gps"}"#;
        assert!(parse_fix(json, "test-scan").is_empty());
    }

    #[test]
    fn parse_fix_malformed_json_returns_empty() {
        assert!(parse_fix(b"not valid json", "test-scan").is_empty());
    }

    #[test]
    fn parse_fix_absent_provider_defaults_to_network_tag() {
        let json = br#"{"latitude":51.5074,"longitude":-0.1278}"#;
        let result = parse_fix(json, "test-scan");
        assert_eq!(result.len(), 1);
        assert!(result.entities[0].has_tag("provider:network"));
    }
}
