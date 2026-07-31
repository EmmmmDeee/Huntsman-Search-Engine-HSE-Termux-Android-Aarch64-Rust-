use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::ModuleResult,
};
use crate::modules::device_fix::{Fix, fix_confidence, is_valid_fix};

use super::SRC;

/// Parse `termux-location`'s JSON into a `Coordinates` entity — the device's own
/// GPS fix, the strongest first-party geolocation signal.
///
/// An invalid lat/lon, or blank output from a tool that exited 0, is a real
/// answer that locates nothing — an honest empty `Ok`. Non-blank output that
/// will not parse is a malfunction and surfaces as an `Err`: reporting it as
/// "no fix" would make a broken tool indistinguishable from a device that
/// simply has no signal. Pure given `stdout`, so it is unit-testable without a
/// device.
pub(super) fn parse_fix(stdout: &[u8], scan_id: &str) -> Result<ModuleResult> {
    if super::is_blank(stdout) {
        return Ok(ModuleResult::new());
    }
    let fix: Fix =
        serde_json::from_slice(stdout).map_err(|e| super::unparseable("location", &e))?;

    if !is_valid_fix(fix.latitude, fix.longitude) {
        tracing::debug!(
            lat = fix.latitude,
            lon = fix.longitude,
            "device_sensors: rejecting invalid location fix"
        );
        return Ok(ModuleResult::new());
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
    // Optional sensor fields are recorded only when the OS actually supplied
    // them. Defaulting an absent reading to `0.0` would be indistinguishable
    // from a real measurement of zero — sea level, stationary, due north are
    // all legitimate values — so a missing field is left absent rather than
    // asserted as an observation. Same `filter_map`/`fold` shape as
    // `gravatar::extract_entry`.
    let ev = [
        ("altitude", fix.altitude),
        ("accuracy_m", fix.accuracy),
        ("speed", fix.speed),
        ("bearing", fix.bearing),
    ]
    .into_iter()
    .filter_map(|(key, value)| value.map(|v| (key, v)))
    .fold(
        Evidence::new(SRC, format!("Location fix via {provider}"))
            .with_attr("latitude", fix.latitude.to_string())
            .with_attr("longitude", fix.longitude.to_string()),
        |ev, (key, v)| ev.with_attr(key, v.to_string()),
    )
    .with_attr("provider", provider);
    e.add_evidence(ev);

    let mut result = ModuleResult {
        entities: Vec::with_capacity(1),
    };
    result.push(e);
    Ok(result)
}
