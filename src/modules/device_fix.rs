//! Shared device location-fix primitives for the Termux `termux-location`
//! consumers (`signal_radar`, `device_sensors`) — a `pub(crate)` HELPER (no
//! `Module` impl). Both modules parse the same `termux-location` JSON and score
//! it on the same accuracy ladder; this is the single definition of the fix
//! shape, its confidence policy, and its parse-to-entity mapping, so the two can
//! never drift. Each module keeps only a three-line wrapper binding its own
//! evidence-source tag — the entity framing they once differed in has since
//! converged, so keeping two copies bought nothing but drift risk.
//!
//! Like `breach_rich`, this stays `pub(crate)` so it is not caught by the
//! `every_declared_module_is_registered` architecture guard (which flags an
//! unregistered `pub mod` as dead-at-runtime).

use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::ModuleResult,
};
use crate::modules::termux_sensor;

/// A `termux-location` JSON fix — the on-device GPS/network position sample as
/// emitted by `termux-location`, shared by every consumer that parses it.
#[derive(Deserialize)]
pub(crate) struct Fix {
    pub(crate) latitude: f64,
    pub(crate) longitude: f64,
    pub(crate) altitude: Option<f64>,
    pub(crate) accuracy: Option<f64>,
    pub(crate) speed: Option<f64>,
    pub(crate) bearing: Option<f64>,
    pub(crate) provider: Option<String>,
}

/// True if `(lat, lon)` is a usable geographic fix.
///
/// Rejects `0.0, 0.0` "Null Island" and out-of-range values. Delegates to the
/// canonical `util::geo::is_valid_coords` so on-device fixes share the same
/// validation policy as the network-geo modules.
pub(crate) fn is_valid_fix(lat: f64, lon: f64) -> bool {
    crate::util::geo::is_valid_coords(lat, lon)
}

/// Confidence for an on-device location fix.
///
/// Provider sets the ceiling (GPS `confidence::VERY_HIGH_PLUS`, network
/// `confidence::HIGH`); the accuracy radius scales it down for imprecise fixes.
pub(crate) fn fix_confidence(provider: &str, accuracy_m: Option<f64>) -> f64 {
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
/// GPS fix, the strongest first-party geolocation signal.
///
/// `src` is the calling module's evidence-source tag, the ONLY thing that
/// differed between the two copies this replaces.
///
/// Outcomes, per the [`termux_sensor`] contract: blank output from a tool that
/// exited 0, or a lat/lon that fails validation, is a real answer that locates
/// nothing — an honest empty `Ok`. Non-blank output that will not parse is a
/// malfunction and surfaces as an `Err`, because reporting it as "no fix" would
/// make a broken tool indistinguishable from a device that simply has no
/// signal. Pure given `stdout`, so it is unit-testable without a device.
pub(crate) fn parse_fix(stdout: &[u8], scan_id: &str, src: &'static str) -> Result<ModuleResult> {
    if termux_sensor::is_blank(stdout) {
        return Ok(ModuleResult::new());
    }
    let fix: Fix = serde_json::from_slice(stdout)
        .map_err(|e| termux_sensor::unparseable(src, "location", &e))?;

    if !is_valid_fix(fix.latitude, fix.longitude) {
        tracing::debug!(
            module = src,
            lat = fix.latitude,
            lon = fix.longitude,
            "rejecting invalid location fix"
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
        Evidence::new(src, format!("Location fix via {provider}"))
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

/// The canonical `termux-location` acquisition ladder, shared by
/// `signal_radar` and `device_sensors`.
///
/// Both modules ask the device the same question — "where are you?" — and
/// previously each carried a byte-identical copy of this ladder, differing only
/// in the evidence-source tag they hand to [`parse_fix`]. The parse half was
/// already converged here; this is the fetch half.
///
/// Most precise first, degrading to the OS's passively-cached last-known
/// position so a fix is still established when no fresh lock is available. Every
/// stage reads only the phone's own sensors/cache — no seed, no input, no
/// network.
///
/// A stage that malfunctions must not abort the ladder: a later stage may still
/// answer. The first failure is remembered and surfaces only if no stage
/// produced a fix, via [`ModuleResult::or_hard_failure`].
pub(crate) async fn scan_device_fix(scan_id: &str, src: &'static str) -> Result<ModuleResult> {
    const STAGES: &[(&str, &str, u64)] = &[
        ("gps", "once", 12_000),
        ("network", "once", 8_000),
        ("gps", "last", 3_000),
        ("network", "last", 3_000),
    ];

    // Availability is a property of the `termux-location` binary, not of the
    // provider/request arguments, so when it is already known absent EVERY stage
    // below is futile. Entering `termux_cmd` four times to be turned away four
    // times cost four `debug!` lines per module per sweep — and `hse radar`
    // sweeps every 25s indefinitely on a battery-powered device, where that is
    // pure log-ring churn and storage I/O carrying no information after the
    // first. Observed directly in a live radar run: `termux_cmd: skipped
    // (recently unavailable)` for `termux-location` repeated 4-6x per module,
    // per sweep, for the whole run.
    if crate::util::termux::is_unavailable("termux-location") {
        return Ok(ModuleResult::new());
    }

    let mut first_failure = None;
    for &(provider, request, timeout_ms) in STAGES {
        match fetch_fix(provider, request, timeout_ms, scan_id, src).await {
            Ok(r) if !r.is_empty() => return Ok(r),
            Ok(_) => {}
            Err(e) => {
                first_failure.get_or_insert(e);
            }
        }
    }
    ModuleResult::new().or_hard_failure(first_failure)
}

/// One rung of [`scan_device_fix`]: run `termux-location -p <provider>
/// -r <request>` under `timeout_ms` and map its output.
///
/// A `last` request reads the OS's passively-cached last-known location, so
/// those entities are tagged `fix-age:last-known` and a cached position is never
/// read as a fresh sensor lock.
async fn fetch_fix(
    provider: &str,
    request: &str,
    timeout_ms: u64,
    scan_id: &str,
    src: &'static str,
) -> Result<ModuleResult> {
    match crate::util::termux::termux_cmd(
        "termux-location",
        &["-p", provider, "-r", request],
        timeout_ms,
    )
    .await
    {
        Some(stdout) => {
            let mut r = parse_fix(&stdout, scan_id, src)?;
            if request == "last" {
                for e in &mut r.entities {
                    e.tag("fix-age:last-known");
                }
            }
            Ok(r)
        }
        None => Ok(ModuleResult::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(
            (c - confidence::VERY_HIGH_PLUS).abs() < 1e-9,
            "gps ceiling = {c}"
        );
    }

    #[test]
    fn fix_confidence_network_no_accuracy_returns_ceiling() {
        let c = fix_confidence("network", None);
        assert!((c - confidence::HIGH).abs() < 1e-9, "network ceiling = {c}");
    }

    #[test]
    fn fix_confidence_gps_accuracy_tiers() {
        assert!((fix_confidence("gps", Some(10.0)) - confidence::VERY_HIGH_PLUS).abs() < 1e-9);
        assert!((fix_confidence("gps", Some(20.0)) - confidence::VERY_HIGH_PLUS).abs() < 1e-9);
        assert!((fix_confidence("gps", Some(50.0)) - confidence::HIGH_PLUSPLUS_PLUS).abs() < 1e-9);
        assert!((fix_confidence("gps", Some(200.0)) - confidence::VERY_HIGH).abs() < 1e-9);
        assert!((fix_confidence("gps", Some(1000.0)) - confidence::HIGH).abs() < 1e-9);
        assert!((fix_confidence("gps", Some(5000.0)) - confidence::MEDIUM_HIGH).abs() < 1e-9);
    }

    #[test]
    fn fix_confidence_network_large_radius_clamps_to_floor() {
        // network ceiling confidence::HIGH − 0.35 = 0.30, which is the clamp floor.
        assert!((fix_confidence("network", Some(5000.0)) - 0.30).abs() < 1e-9);
    }

    #[test]
    fn fix_confidence_zero_accuracy_falls_through_to_ceiling() {
        // a = 0.0 does not satisfy `a > 0.0`; falls through to the `_ =>` arm.
        assert!((fix_confidence("gps", Some(0.0)) - confidence::VERY_HIGH_PLUS).abs() < 1e-9);
    }
}
