//! GPS / network location fix for signal_radar — mirrors device_sensors/gps.rs.

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
};
use crate::modules::device_fix::{Fix, fix_confidence, is_valid_fix};
use crate::util::termux::termux_cmd;

use super::SRC;

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

    // Optional sensor fields are recorded only when the OS actually supplied
    // them — see the matching note in `device_sensors::gps::parse_fix`. An
    // absent reading defaulted to `0.0` is indistinguishable from a genuine
    // measurement of zero, so it is left absent instead.
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
    result
}

/// Fetch a location fix from `termux-location -p <provider> -r <request>`.
/// A `last` request reads the OS's passively-cached last-known location (no
/// fresh lock, near-instant); those entities are tagged `fix-age:last-known` so
/// a cached position is never mistaken for a fresh sensor lock.
async fn fetch_fix(provider: &str, request: &str, timeout_ms: u64, scan_id: &str) -> ModuleResult {
    match termux_cmd(
        "termux-location",
        &["-p", provider, "-r", request],
        timeout_ms,
    )
    .await
    {
        Some(stdout) => {
            let mut r = parse_fix(&stdout, scan_id);
            if request == "last" {
                for e in &mut r.entities {
                    e.tag("fix-age:last-known");
                }
            }
            r
        }
        None => ModuleResult::new(),
    }
}

/// Establish a device location fix from passive on-device signals, most precise
/// first and degrading to the OS's passively-cached last-known location so a
/// position is STILL established when no fresh lock is available this sweep —
/// the radar never depends on a single clean GPS fix, and needs no input. The
/// stages, in order: a fresh GPS lock (12 s), a fresh network (cell/Wi-Fi) fix
/// (8 s), the last-known GPS fix, then the last-known network fix (both
/// near-instant, read straight from the phone's location cache). Every stage
/// reads only the phone's own sensors/cache — no seed, no input.
pub(super) async fn scan_gps(scan_id: &str) -> ModuleResult {
    const STAGES: &[(&str, &str, u64)] = &[
        ("gps", "once", 12_000),
        ("network", "once", 8_000),
        ("gps", "last", 3_000),
        ("network", "last", 3_000),
    ];
    for &(provider, request, timeout_ms) in STAGES {
        let r = fetch_fix(provider, request, timeout_ms, scan_id).await;
        if !r.is_empty() {
            return r;
        }
    }
    ModuleResult::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The `Fix` shape and the `is_valid_fix` / `fix_confidence` ladder now live
    // in `crate::modules::device_fix` and are tested there; these tests cover
    // this module's own `parse_fix` wrapper.

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
