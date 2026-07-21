//! Shared device location-fix primitives for the Termux `termux-location`
//! consumers (`signal_radar`, `device_sensors`) — a `pub(crate)` HELPER (no
//! `Module` impl). Both modules parse the same `termux-location` JSON and score
//! it on the same accuracy ladder; this is the single definition of the fix
//! shape and its confidence policy so the two can never drift. Each module keeps
//! its own `parse_fix` wrapper (they differ only in logging and entity framing).
//!
//! Like `breach_rich`, this stays `pub(crate)` so it is not caught by the
//! `every_declared_module_is_registered` architecture guard (which flags an
//! unregistered `pub mod` as dead-at-runtime).

use serde::Deserialize;

use crate::core::confidence;

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
