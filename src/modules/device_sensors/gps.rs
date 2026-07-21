use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
};
use crate::modules::device_fix::{Fix, fix_confidence, is_valid_fix};

use super::SRC;

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
