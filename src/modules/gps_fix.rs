use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
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
    fn description(&self) -> &'static str {
        "Termux GPS location fix for device geolocation"
    }
    fn priority(&self) -> u8 {
        68
    }

    fn is_passive(&self) -> bool {
        true
    }

    /// Bumped from default because termux-location can take 15s indoors.
    fn max_timeout_ms(&self) -> u64 {
        20_000
    }

    fn accepts(&self, _t: &Target) -> bool {
        true
    }

    async fn process(&self, _target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
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
    let confidence = if provider == "gps" { 0.90 } else { 0.65 };
    let coords = format!("{:.7},{:.7}", fix.latitude, fix.longitude);

    let mut e = Entity::new(EntityKind::Coordinates, coords, confidence, scan_id);
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

    let mut result = ModuleResult {
        entities: Vec::with_capacity(1),
    };
    result.push(e);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::TargetKind;

    #[test]
    fn is_passive() {
        assert!(GpsFix.is_passive());
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

    #[test]
    fn module_name_and_priority() {
        assert_eq!(GpsFix.name(), "gps_fix");
        assert_eq!(GpsFix.priority(), 68);
    }

    #[test]
    fn max_timeout_is_20s() {
        assert_eq!(GpsFix.max_timeout_ms(), 20_000);
    }

    #[test]
    fn entity_tags_and_kind() {
        let json = br#"{"latitude":51.5074,"longitude":-0.1278,"provider":"network"}"#;
        let r = parse_fix(json, "scan-gps");
        let e = &r.entities[0];
        assert_eq!(e.kind, EntityKind::Coordinates);
        assert!(e.has_tag("geoint"));
        assert!(e.has_tag("provider:network"));
        assert_eq!(e.scan_id, "scan-gps");
    }

    #[test]
    fn gps_provider_tag() {
        let json = br#"{"latitude":0.0,"longitude":0.0,"provider":"gps"}"#;
        let r = parse_fix(json, "test");
        assert!(r.entities[0].has_tag("provider:gps"));
    }

    #[test]
    fn evidence_attributes_populated() {
        let json = br#"{"latitude":37.7749,"longitude":-122.4194,"altitude":15.5,
            "accuracy":8.2,"speed":1.5,"bearing":90.0,"provider":"gps"}"#;
        let r = parse_fix(json, "test");
        let ev = &r.entities[0].evidence[0];
        assert_eq!(ev.source, "gps_fix");
        assert_eq!(ev.attributes.get("latitude").unwrap(), "37.7749");
        assert_eq!(ev.attributes.get("longitude").unwrap(), "-122.4194");
        assert_eq!(ev.attributes.get("altitude").unwrap(), "15.5");
        assert_eq!(ev.attributes.get("accuracy_m").unwrap(), "8.2");
        assert_eq!(ev.attributes.get("speed").unwrap(), "1.5");
        assert_eq!(ev.attributes.get("bearing").unwrap(), "90");
        assert_eq!(ev.attributes.get("provider").unwrap(), "gps");
    }

    #[test]
    fn missing_optional_fields_default_to_zero() {
        let json = br#"{"latitude":10.0,"longitude":20.0}"#;
        let r = parse_fix(json, "test");
        assert_eq!(r.entities.len(), 1);
        let ev = &r.entities[0].evidence[0];
        // Missing provider defaults to "network"
        assert_eq!(ev.attributes.get("provider").unwrap(), "network");
        assert_eq!(ev.attributes.get("altitude").unwrap(), "0");
        assert_eq!(ev.attributes.get("accuracy_m").unwrap(), "0");
        assert_eq!(ev.attributes.get("speed").unwrap(), "0");
        assert_eq!(ev.attributes.get("bearing").unwrap(), "0");
        // Missing provider means network confidence
        assert!((r.entities[0].confidence - 0.65).abs() < 1e-6);
    }

    #[test]
    fn malformed_json_no_ops() {
        let r = parse_fix(b"not json at all", "test");
        assert_eq!(r.entities.len(), 0);
    }

    #[test]
    fn empty_object_fails_missing_required_fields() {
        let r = parse_fix(b"{}", "test");
        // latitude and longitude are required (f64, not Option), so {} should fail deserialization
        assert_eq!(r.entities.len(), 0);
    }

    #[test]
    fn negative_coordinates_handled() {
        let json = br#"{"latitude":-33.8688,"longitude":151.2093,"provider":"network"}"#;
        let r = parse_fix(json, "test");
        assert_eq!(r.entities[0].value, "-33.8688000,151.2093000");
    }
}
