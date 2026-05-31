//! Mylnikov GEO — free BSSID-to-coordinates resolution. No API key.
//!
//! Endpoint: `GET https://api.mylnikov.org/geolocation/wifi?v=1.1&data=open&bssid={MAC}`
//!
//! Complements the WiGLE BSSID lookup with a no-auth alternative.
//! Lower precision but useful when WiGLE keys are exhausted.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::urlencode;

const SRC: &str = "mylnikov";

pub struct Mylnikov;

#[derive(Deserialize)]
struct MylnikovResp {
    #[serde(default)]
    result: Option<i32>,
    #[serde(default)]
    data: Option<MylnikovData>,
}

#[derive(Deserialize)]
struct MylnikovData {
    #[serde(default)]
    lat: Option<f64>,
    #[serde(default)]
    lon: Option<f64>,
    #[serde(default)]
    range: Option<f64>,
}

#[async_trait]
impl Module for Mylnikov {
    fn name(&self) -> &'static str {
        "mylnikov"
    }
    fn description(&self) -> &'static str {
        "Mylnikov free BSSID-to-coordinates WiFi geolocation"
    }
    fn priority(&self) -> u8 {
        17
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::MacAddress)
    }
    fn max_timeout_ms(&self) -> u64 {
        3_000
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Coordinates];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let bssid = target.value.trim();
        if bssid.len() < 12 {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://api.mylnikov.org/geolocation/wifi?v=1.1&data=open&bssid={}",
            urlencode(bssid),
        );

        let resp = match ctx.http.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return Ok(ModuleResult::new()),
        };

        if !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }

        let body: MylnikovResp = match crate::util::http::json_scanned(resp, SRC).await {
            Ok(b) => b,
            Err(_) => return Ok(ModuleResult::new()),
        };

        if body.result != Some(200) {
            return Ok(ModuleResult::new());
        }
        let Some(data) = body.data else {
            return Ok(ModuleResult::new());
        };
        let (Some(lat), Some(lon)) = (data.lat, data.lon) else {
            return Ok(ModuleResult::new());
        };
        if lat == 0.0 && lon == 0.0 {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();
        let coords = format!("{lat:.6},{lon:.6}");
        let confidence = match data.range.unwrap_or(5000.0) as u64 {
            0..=200 => 0.75,
            201..=1000 => 0.65,
            1001..=5000 => 0.50,
            _ => 0.35,
        };
        let mut e = Entity::new(EntityKind::Coordinates, &coords, confidence, &ctx.scan_id);
        e.tag("mylnikov");
        e.tag("geoint");
        e.tag("bssid-located");
        let mut ev = Evidence::new(SRC, format!("Mylnikov BSSID {bssid} -> {coords}"))
            .with_attr("bssid", bssid)
            .with_attr("latitude", format!("{lat:.6}"))
            .with_attr("longitude", format!("{lon:.6}"));
        if let Some(range) = data.range {
            ev = ev.with_attr("range_m", format!("{range:.0}"));
        }
        e.add_evidence(ev);
        result.push(e);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_mac_only() {
        let m = Mylnikov;
        assert!(m.accepts(&Target::new(TargetKind::MacAddress, "AA:BB:CC:DD:EE:FF")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn module_metadata() {
        assert_eq!(Mylnikov.name(), "mylnikov");
        assert_eq!(Mylnikov.priority(), 17);
        assert_eq!(Mylnikov.max_timeout_ms(), 3_000);
    }

    #[test]
    fn parse_response() {
        let raw = r#"{"result": 200, "data": {"lat": -33.8688, "lon": 151.2093, "range": 250.0}}"#;
        let r: MylnikovResp = serde_json::from_str(raw).unwrap();
        assert_eq!(r.result, Some(200));
        let d = r.data.unwrap();
        assert!((d.lat.unwrap() - (-33.8688)).abs() < 0.001);
    }
}
