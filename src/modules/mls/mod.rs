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

        let resp = ctx.http.post(&url).json(&body).send_tagged(SRC).await?;

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
    include!("tests.rs");
}
