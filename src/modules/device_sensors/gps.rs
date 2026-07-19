use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
};

use super::SRC;

#[derive(Deserialize)]
pub(super) struct Fix {
    pub(super) latitude: f64,
    pub(super) longitude: f64,
    pub(super) altitude: Option<f64>,
    pub(super) accuracy: Option<f64>,
    pub(super) speed: Option<f64>,
    pub(super) bearing: Option<f64>,
    pub(super) provider: Option<String>,
}

/// True if `(lat, lon)` is a usable geographic fix.
///
/// Rejects `0.0, 0.0` "Null Island" and out-of-range values. Delegates to
/// the canonical `util::geo::is_valid_coords` so on-device fixes share the
/// same validation policy as network-geo modules.
pub(super) fn is_valid_fix(lat: f64, lon: f64) -> bool {
    crate::util::geo::is_valid_coords(lat, lon)
}

/// Confidence for an on-device location fix.
///
/// Provider sets the ceiling (GPS confidence::VERY_HIGH_PLUS, network confidence::HIGH); accuracy radius
/// scales it down for imprecise fixes.
pub(super) fn fix_confidence(provider: &str, accuracy_m: Option<f64>) -> f64 {
    let ceiling: f64 = if provider == "gps" {
        confidence::VERY_HIGH_PLUS
    } else {
        confidence::HIGH
    };
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
            scaled.clamp(0.30, confidence::VERY_HIGH_PLUS)
        }
        _ => ceiling,
    }
}

/// Parse `termux-location`'s JSON into a `Coordinates` entity — the device's own
/// GPS fix, the strongest first-party geolocation signal. Empty result on
/// unparseable JSON (the tool absent / no fix) or an invalid lat/lon, so a missing
/// fix degrades to "no signal" rather than a bad coordinate. Pure given `stdout`,
/// so it is unit-testable without a device.
pub(super) fn parse_fix(stdout: &[u8], scan_id: &str) -> ModuleResult {
    let fix: Fix = match serde_json::from_slice(stdout) {
        Ok(v) => v,
        Err(_) => return ModuleResult::new(),
    };

    if !is_valid_fix(fix.latitude, fix.longitude) {
        tracing::debug!(
            lat = fix.latitude,
            lon = fix.longitude,
            "device_sensors: rejecting invalid location fix"
        );
        return ModuleResult::new();
    }

    let provider = fix.provider.as_deref().unwrap_or("network");
    let confidence = fix_confidence(provider, fix.accuracy);
    let coords = format!("{:.7},{:.7}", fix.latitude, fix.longitude);

    let mut e = Entity::new(EntityKind::Coordinates, coords, confidence, scan_id);
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
