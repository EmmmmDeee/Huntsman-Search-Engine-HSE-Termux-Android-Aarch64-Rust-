//! Single-shot GPS / network-location fix via `termux-location`.
//!
//! Uses `-p network -r once` for a fast (<5s) fix without needing
//! GPS hardware to be active. If the user has only GPS available the
//! command silently returns nothing and the module no-ops.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::Target,
};
use crate::util::termux::termux_cmd;

pub struct GpsFix;

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

#[async_trait]
impl Module for GpsFix {
    fn name(&self) -> &'static str {
        "gps_fix"
    }
    fn priority(&self) -> u8 {
        68
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }
    fn is_passive(&self) -> bool {
        true
    }
    fn accepts(&self, _t: &Target) -> bool {
        true
    }

    async fn process(&self, _target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // Network provider is much faster than GPS (~1s vs minutes) and works
        // indoors. A 15s ceiling keeps the engine snappy even when the device
        // is genuinely unable to acquire a fix.
        let Some(stdout) =
            termux_cmd("termux-location", &["-p", "network", "-r", "once"], 15_000).await
        else {
            return Ok(ModuleResult::new());
        };
        Ok(parse_fix(&stdout, &ctx.scan_id))
    }
}

fn parse_fix(stdout: &[u8], scan_id: &str) -> ModuleResult {
    let fix: Fix = match serde_json::from_slice(stdout) {
        Ok(v) => v,
        Err(_) => return ModuleResult::new(),
    };

    let provider = fix.provider.as_deref().unwrap_or("network");
    // GPS provider gets higher confidence (cm-scale accuracy possible);
    // network provider is m-scale at best.
    let confidence = if provider == "gps" { 0.90 } else { 0.65 };
    let coords = format!("{:.7},{:.7}", fix.latitude, fix.longitude);

    let mut e = Entity::new(EntityKind::Coordinates, &coords, confidence, scan_id);
    e.tag("geoint");
    e.tag(format!("provider:{provider}"));
    e.add_evidence(
        Evidence::new("gps_fix", format!("Location fix via {provider}"))
            .with_attr("latitude", fix.latitude.to_string())
            .with_attr("longitude", fix.longitude.to_string())
            .with_attr("altitude", fix.altitude.unwrap_or(0.0).to_string())
            .with_attr("accuracy_m", fix.accuracy.unwrap_or(0.0).to_string())
            .with_attr("speed", fix.speed.unwrap_or(0.0).to_string())
            .with_attr("bearing", fix.bearing.unwrap_or(0.0).to_string())
            .with_attr("provider", provider),
    );

    let mut result = ModuleResult::new();
    result.push(e);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::TargetKind;

    #[test]
    fn passive_and_free() {
        assert!(GpsFix.is_passive());
        assert_eq!(GpsFix.cost(), ModuleCost::Free);
    }

    #[test]
    fn accepts_any_target() {
        assert!(GpsFix.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn network_fix_gets_lower_confidence() {
        let json = br#"{"latitude":-27.4698,"longitude":153.0251,"accuracy":12.5,
            "provider":"network"}"#;
        let r = parse_fix(json, "test");
        assert_eq!(r.entities.len(), 1);
        assert!((r.entities[0].confidence - 0.65).abs() < 1e-6);
    }

    #[test]
    fn gps_fix_gets_higher_confidence() {
        let json = br#"{"latitude":-27.4698,"longitude":153.0251,"accuracy":2.0,
            "provider":"gps"}"#;
        let r = parse_fix(json, "test");
        assert!((r.entities[0].confidence - 0.90).abs() < 1e-6);
    }

    #[test]
    fn coordinate_value_is_fixed_precision() {
        let json = br#"{"latitude":-27.469824123,"longitude":153.025198765,
            "provider":"network"}"#;
        let r = parse_fix(json, "test");
        assert_eq!(r.entities[0].value, "-27.4698241,153.0251988");
    }
}
