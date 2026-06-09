//! Mozilla Location Service — free WiFi/cell triangulation source.
//!
//! Endpoint: `POST https://location.services.mozilla.com/v1/geolocate?key=<k>`
//! Auth:     Query-string `key=` parameter; `test` is publicly accepted for
//!           low-volume use, paid keys exist for production.
//!
//! HSE uses MLS as a third corroboration source alongside WiGLE and
//! Mylnikov so a `MacAddress` (BSSID) target lookup that gets a hit
//! from any one of the three triggers an expansion to `Coordinates`.
//! Single-AP lookups have wide accuracy radii (often 5–10 km) which
//! the confidence mapping below reflects — the entity is emitted so
//! the engine can corroborate it against a tighter source, not as
//! a stand-alone authoritative geo lead.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "mls";
const KEY_ENV: &str = "HUNTSMAN_MLS_KEY";
const DEFAULT_KEY: &str = "test";

pub struct Mls;

#[derive(Deserialize)]
struct MlsResp {
    #[serde(default)]
    location: Option<MlsLocation>,
    #[serde(default)]
    accuracy: Option<f64>,
}

#[derive(Deserialize)]
struct MlsLocation {
    lat: f64,
    lng: f64,
}

#[async_trait]
impl Module for Mls {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Mozilla Location Service — third-source BSSID/cell triangulation, complements WiGLE + Mylnikov"
    }

    fn priority(&self) -> u8 {
        // Below wigle (18) and mylnikov (15) — runs after the more
        // accurate sources, so its result corroborates rather than
        // dominates the expansion queue.
        12
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Coordinates];
        KINDS
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::MacAddress)
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // Single-sourced credential policy (see `keys::resolve_or_default`): a
        // non-empty configured key wins, else Mozilla's public `test` key.
        let key = crate::util::keys::resolve_or_default(ctx.key_opt(KEY_ENV), DEFAULT_KEY);
        let url = format!("https://location.services.mozilla.com/v1/geolocate?key={key}");

        // MLS prefers ≥2 access points for triangulation; with one we
        // submit the request anyway and accept the wider accuracy
        // radius. `fallbacks.{lacf, ipf} = false` disables MLS's
        // last-resort coarse fallbacks (cell-LAC, IP geo) — we have
        // dedicated modules for both and don't want the answer
        // silently downgraded.
        let body = serde_json::json!({
            "wifiAccessPoints": [{
                "macAddress": target.value,
                "signalStrength": -70,
            }],
            "fallbacks": { "lacf": false, "ipf": false },
        });

        let resp = ctx
            .http
            .post(&url)
            .json(&body)
            .send_tagged(SRC).await?;

        if !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }

        let body: MlsResp = match crate::util::http::json_scanned(resp, SRC).await {
            Ok(v) => v,
            Err(_) => return Ok(ModuleResult::new()),
        };

        let mut result = ModuleResult::new();
        let Some(loc) = body.location else {
            return Ok(result);
        };
        if !crate::util::geo::is_valid_coords(loc.lat, loc.lng) {
            return Ok(result);
        }
        let accuracy_m = body.accuracy.unwrap_or(5000.0);
        let confidence = confidence_from_accuracy(accuracy_m);
        let coord_str = format!("{:.6},{:.6}", loc.lat, loc.lng);

        let mut e = Entity::new(
            EntityKind::Coordinates,
            &coord_str,
            confidence,
            &ctx.scan_id,
        );
        e.tag("mls");
        e.tag("geoint");
        e.tag(format!("accuracy:{}m", accuracy_m as u64));
        e.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "Mozilla Location Service: BSSID {} → coordinates (±{} m)",
                    target.value, accuracy_m as u64
                ),
            )
            .with_attr("bssid", &target.value)
            .with_attr("accuracy_meters", (accuracy_m as u64).to_string())
            .with_attr("source", "location.services.mozilla.com"),
        );
        result.push(e);
        Ok(result)
    }
}

/// Map MLS-reported accuracy (metres) to a confidence score.
///
/// MLS often reports very wide radii (5–10 km) for single-AP
/// triangulations. The mapping is intentionally conservative — the
/// engine uses confidence to rank expansion candidates, so an
/// imprecise hit shouldn't outrank a tight WiGLE result on the same
/// BSSID. Mapping breakpoints picked to match the empirical accuracy
/// distribution of MLS responses against urban WiFi corpora.
fn confidence_from_accuracy(accuracy_m: f64) -> f64 {
    if accuracy_m < 100.0 {
        0.85
    } else if accuracy_m < 500.0 {
        0.75
    } else if accuracy_m < 2000.0 {
        0.60
    } else if accuracy_m < 10_000.0 {
        0.50
    } else {
        0.40
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_mac_address() {
        let m = Mls;
        assert!(m.accepts(&Target::new(TargetKind::MacAddress, "AA:BB:CC:DD:EE:FF")));
        assert!(!m.accepts(&Target::new(TargetKind::Coordinates, "0,0")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }

    #[test]
    fn category_is_geo() {
        assert_eq!(Mls.category(), ModuleCategory::Geo);
    }

    #[test]
    fn produces_coordinates_only() {
        let p = Mls.produces();
        assert_eq!(p, &[EntityKind::Coordinates]);
    }

    #[test]
    fn cost_is_free() {
        assert!(matches!(Mls.cost(), ModuleCost::Free));
    }

    #[test]
    fn priority_below_wigle_and_mylnikov() {
        // wigle = 18, mylnikov = 15 — MLS runs after both so its
        // result corroborates rather than dominates the expansion
        // weight on the same BSSID.
        assert!(Mls.priority() < 15);
    }

    #[test]
    fn confidence_steps_with_accuracy_buckets() {
        // Tight (<100m): high confidence
        assert!((confidence_from_accuracy(50.0) - 0.85).abs() < 1e-9);
        // Sub-km
        assert!((confidence_from_accuracy(300.0) - 0.75).abs() < 1e-9);
        // City-block
        assert!((confidence_from_accuracy(1_500.0) - 0.60).abs() < 1e-9);
        // City-wide single-AP
        assert!((confidence_from_accuracy(7_000.0) - 0.50).abs() < 1e-9);
        // Region (default fallback when MLS gives no accuracy)
        assert!((confidence_from_accuracy(20_000.0) - 0.40).abs() < 1e-9);
    }

    #[test]
    fn confidence_is_monotonic_in_accuracy() {
        // Tighter accuracy must never produce lower confidence.
        let samples = [
            50.0, 99.9, 100.0, 250.0, 500.0, 1_999.0, 2_000.0, 9_999.0, 10_000.0,
        ];
        let mut last = f64::INFINITY;
        for a in samples {
            let c = confidence_from_accuracy(a);
            assert!(c <= last, "monotonicity broken at accuracy={a}m");
            last = c;
        }
    }

    #[test]
    fn mls_resp_deserializes_typical_shape() {
        let json = r#"{"location":{"lat":-27.4766,"lng":153.0166},"accuracy":42.5}"#;
        let r: MlsResp = serde_json::from_str(json).unwrap();
        assert!(r.location.is_some());
        let loc = r.location.unwrap();
        assert!((loc.lat - (-27.4766)).abs() < 1e-9);
        assert!((loc.lng - 153.0166).abs() < 1e-9);
        assert!((r.accuracy.unwrap() - 42.5).abs() < 1e-9);
    }

    #[test]
    fn mls_resp_handles_missing_accuracy() {
        let json = r#"{"location":{"lat":0.0,"lng":0.0}}"#;
        let r: MlsResp = serde_json::from_str(json).unwrap();
        assert!(r.location.is_some());
        assert!(r.accuracy.is_none());
    }

    #[test]
    fn mls_resp_handles_empty_body() {
        let json = r#"{}"#;
        let r: MlsResp = serde_json::from_str(json).unwrap();
        assert!(r.location.is_none());
        assert!(r.accuracy.is_none());
    }
}
