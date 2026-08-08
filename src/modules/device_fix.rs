//! Shared device location-fix primitives for the Termux `termux-location`
//! consumers (`signal_radar`, `device_sensors`) — a `pub(crate)` HELPER (no
//! `Module` impl). Both modules parse the same `termux-location` JSON and score
//! it on the same accuracy ladder; this is the single definition of the fix
//! shape, its confidence policy, its parse-to-entity mapping, AND the staged
//! ladder that drives them, so the two can never drift.
//!
//! The ladder ([`scan_location_ladder`]) moved here after the parse did: both
//! modules had been running byte-identical copies of it, differing only in the
//! evidence-source tag they passed in, which meant the GNSS-fallback defect the
//! ladder's argv-keyed cache exists to prevent lived in two places at once.
//! Each module now keeps only a one-line call binding its own `SRC`.
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

/// The location ladder: each stage as `(provider, request, timeout_ms)`, tried
/// in order until one establishes a fix.
///
/// Most precise first, degrading to the OS's passively-cached last-known
/// position so a fix is STILL established when no fresh lock is available —
/// a fresh GPS lock (12 s), a fresh network (cell/Wi-Fi) fix (8 s), then the
/// last-known GPS and network positions (near-instant reads of the phone's
/// location cache). Every stage reads only the device's own sensors; none takes
/// a seed or any input.
///
/// The `last` stages are the reason the ladder exists, and are why
/// [`crate::util::termux`] keys its skip cache on the full argv: under
/// binary-wide keying the 12 s fresh-lock timeout suppressed these three cheap
/// fallbacks behind it, so the fallback that exists precisely for "no fresh lock
/// available" could never run.
const LOCATION_STAGES: &[(&str, &str, u64)] = &[
    ("gps", "once", 12_000),
    ("network", "once", 8_000),
    ("gps", "last", 3_000),
    ("network", "last", 3_000),
];

/// Run one ladder stage: `termux-location -p <provider> -r <request>`.
///
/// A `last` request reads the OS's passively-cached position rather than taking
/// a fresh lock, so its entities are tagged `fix-age:last-known` — a cached
/// position must never be mistaken for a live sensor lock.
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
        // Absent tool / timeout / non-zero exit: nothing observed, nothing to
        // attest — the absent-tool row of `termux_sensor`'s contract table.
        None => Ok(ModuleResult::new()),
    }
}

/// Walk [`LOCATION_STAGES`] until a stage establishes a fix, tagging entities
/// with `src` as their evidence source.
///
/// `signal_radar::gps` and `device_sensors` each carried a byte-identical copy
/// of this ladder — the same four stages, the same budgets, the same
/// `fix-age:last-known` tagging and the same first-failure semantics — differing
/// only in which module's `SRC` tag they passed to [`parse_fix`]. The parse was
/// single-sourced here previously; the ladder wrapped around it was not, so the
/// GNSS-fallback defect this ladder's argv-keyed cache exists to prevent lived
/// in two places at once, and fixing either copy would have left the other
/// silently broken.
///
/// Each stage is an independent attempt at the same question, so a stage that
/// malfunctions must not abort the ladder — a later one may still succeed. The
/// first failure is remembered and surfaces only if no stage produced a fix, via
/// [`ModuleResult::or_hard_failure`].
pub(crate) async fn scan_location_ladder(scan_id: &str, src: &'static str) -> Result<ModuleResult> {
    let mut first_failure = None;
    for &(provider, request, timeout_ms) in LOCATION_STAGES {
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
    // `termux-location` answers `{"API_ERROR": "Failed to get location"}` (and
    // two provider-specific variants) when it cannot produce a fix. That is a
    // real, explained answer — "no fix available" — and every ladder stage
    // legitimately hits it on a device indoors or with location off. Parsed as
    // a `Fix` it fails on the required `latitude` and became a hard `Err`,
    // which the ladder then reported as a malfunction. This module does not
    // route through `read_and_parse` (it drives its own staged ladder), so the
    // shared predicate is applied here.
    if let Some(reason) = termux_sensor::api_error(stdout) {
        tracing::debug!(
            module = src,
            reason = %reason,
            "termux-location produced no fix — the tool's own explanation"
        );
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `termux-location` reports "I could not get a fix" as
    /// `{"API_ERROR": "..."}`, which every ladder stage legitimately hits on a
    /// device indoors or with location services off. Parsed as a `Fix` it fails
    /// on the required `latitude`, so it used to surface as a hard `Err` — a
    /// malfunction report for a phone that simply had no signal.
    #[test]
    fn a_location_decline_is_no_fix_not_a_malfunction() {
        let result = parse_fix(
            br#"{"API_ERROR":"Failed to get location"}"#,
            "test-scan",
            "test",
        )
        .expect("a tool-reported decline is an answer, not a malfunction");
        assert!(result.is_empty());
    }

    /// The counterweight: genuinely broken output must still be an error, or the
    /// fix above could have been made by swallowing every parse failure.
    #[test]
    fn genuinely_broken_location_output_is_still_an_error() {
        assert!(parse_fix(b"{not json at all", "test-scan", "test").is_err());
    }

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

    /// A stage whose tool is absent is a clean empty answer, not an error —
    /// the absent-tool row of the sensor contract. Moved here from
    /// `device_sensors` along with the ladder itself.
    #[tokio::test]
    async fn fetch_fix_is_empty_off_device() {
        for request in ["once", "last"] {
            let r = fetch_fix("gps", request, 1000, "test", "device_sensors")
                .await
                .expect("an absent tool is a clean empty answer");
            assert!(r.entities.is_empty(), "{request}: must be empty off-device");
        }
    }

    /// The ladder itself degrades cleanly when every stage is unavailable: an
    /// empty `Ok`, not a hard failure. Off-device (no `termux-location`) every
    /// stage returns empty, which is the same shape as a phone with location
    /// permission withheld.
    #[tokio::test]
    async fn the_ladder_is_a_clean_empty_answer_when_no_stage_can_fix() {
        let r = scan_location_ladder("test", "signal_radar")
            .await
            .expect("an absent tool must not be a hard failure");
        assert!(r.is_empty());
    }

    /// The ladder's stage order is the contract: most precise first, degrading
    /// to the near-instant last-known reads that exist for when no fresh lock
    /// is available. Pinned so a reorder (or a dropped fallback) is a test
    /// failure — the fallback stages were unreachable for a whole radar session
    /// once already.
    #[test]
    fn the_ladder_tries_fresh_locks_before_cached_positions() {
        let requests: Vec<&str> = LOCATION_STAGES.iter().map(|&(_, r, _)| r).collect();
        assert_eq!(requests, ["once", "once", "last", "last"]);
        let providers: Vec<&str> = LOCATION_STAGES.iter().map(|&(p, ..)| p).collect();
        assert_eq!(providers, ["gps", "network", "gps", "network"]);
        // The cached reads must stay cheap: they exist precisely because the
        // fresh locks are expensive, so budgeting them alike would defeat them.
        let (fresh, cached): (Vec<u64>, Vec<u64>) = (
            LOCATION_STAGES[..2].iter().map(|&(.., t)| t).collect(),
            LOCATION_STAGES[2..].iter().map(|&(.., t)| t).collect(),
        );
        assert!(
            cached.iter().max() < fresh.iter().min(),
            "every cached read must be cheaper than every fresh lock: {cached:?} vs {fresh:?}"
        );
    }
}
