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
