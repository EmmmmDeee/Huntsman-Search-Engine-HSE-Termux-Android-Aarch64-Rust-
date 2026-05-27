//! Sunrise-Sunset — solar phase timestamps for chronolocation.
//!
//! Endpoint: `GET https://api.sunrise-sunset.org/json?lat={lat}&lng={lon}&date={YYYY-MM-DD}`
//! Auth:     None (free, public).
//!
//! Returns UTC timestamps for sunrise, sunset, solar noon, golden hour,
//! and other astronomical events. Used for chronolocation of imagery.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "sunrise_sunset";

pub struct SunriseSunset;

#[derive(Deserialize)]
struct SsResp {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    results: Option<SsResults>,
}

#[derive(Deserialize)]
struct SsResults {
    #[serde(default)]
    sunrise: Option<String>,
    #[serde(default)]
    sunset: Option<String>,
    #[serde(default)]
    solar_noon: Option<String>,
    #[serde(default)]
    day_length: Option<serde_json::Value>,
    #[serde(default)]
    civil_twilight_begin: Option<String>,
    #[serde(default)]
    civil_twilight_end: Option<String>,
    #[serde(default)]
    nautical_twilight_begin: Option<String>,
    #[serde(default)]
    nautical_twilight_end: Option<String>,
    #[serde(default)]
    astronomical_twilight_begin: Option<String>,
    #[serde(default)]
    astronomical_twilight_end: Option<String>,
}

#[async_trait]
impl Module for SunriseSunset {
    fn name(&self) -> &'static str {
        "sunrise_sunset"
    }
    fn description(&self) -> &'static str {
        "Solar phase timestamps for chronolocation of imagery"
    }
    fn priority(&self) -> u8 {
        10
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Coordinates)
    }
    fn max_timeout_ms(&self) -> u64 {
        3_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let (lat, lon) = crate::util::geo::parse_coords(&target.value)?;

        let today = today_utc();
        let url = format!(
            "https://api.sunrise-sunset.org/json?lat={lat:.6}&lng={lon:.6}&date={today}&formatted=0",
        );

        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        if !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }

        let body: SsResp = resp
            .json()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        if body.status.as_deref() != Some("OK") {
            return Ok(ModuleResult::new());
        }
        let Some(results) = body.results else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();

        let mut entity = Entity::new(EntityKind::Coordinates, &target.value, 0.55, &ctx.scan_id);
        entity.tag("sunrise-sunset");
        entity.tag("chronolocation");
        entity.tag("geoint");

        let mut ev = Evidence::new(
            SRC,
            format!("Solar phases for {lat:.4},{lon:.4} on {today}"),
        )
        .with_attr("date", &today)
        .with_attr("latitude", format!("{lat:.6}"))
        .with_attr("longitude", format!("{lon:.6}"));

        if let Some(v) = results.sunrise.as_deref() {
            ev = ev.with_attr("sunrise_utc", v);
        }
        if let Some(v) = results.sunset.as_deref() {
            ev = ev.with_attr("sunset_utc", v);
        }
        if let Some(v) = results.solar_noon.as_deref() {
            ev = ev.with_attr("solar_noon_utc", v);
        }
        if let Some(v) = &results.day_length {
            let dl = match v {
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::String(s) => s.clone(),
                _ => String::new(),
            };
            if !dl.is_empty() {
                ev = ev.with_attr("day_length_s", dl);
            }
        }
        if let Some(v) = results.civil_twilight_begin.as_deref() {
            ev = ev.with_attr("civil_twilight_begin", v);
        }
        if let Some(v) = results.civil_twilight_end.as_deref() {
            ev = ev.with_attr("civil_twilight_end", v);
        }
        if let Some(v) = results.nautical_twilight_begin.as_deref() {
            ev = ev.with_attr("nautical_twilight_begin", v);
        }
        if let Some(v) = results.nautical_twilight_end.as_deref() {
            ev = ev.with_attr("nautical_twilight_end", v);
        }
        if let Some(v) = results.astronomical_twilight_begin.as_deref() {
            ev = ev.with_attr("astronomical_twilight_begin", v);
        }
        if let Some(v) = results.astronomical_twilight_end.as_deref() {
            ev = ev.with_attr("astronomical_twilight_end", v);
        }

        entity.add_evidence(ev);
        result.push(entity);
        Ok(result)
    }
}

fn today_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (secs / 86400) as i64;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_coordinates_only() {
        let m = SunriseSunset;
        assert!(m.accepts(&Target::new(TargetKind::Coordinates, "-33.8,151.2")));
        assert!(!m.accepts(&Target::new(TargetKind::Address, "Sydney")));
    }

    #[test]
    fn module_metadata() {
        assert_eq!(SunriseSunset.name(), "sunrise_sunset");
        assert_eq!(SunriseSunset.priority(), 10);
        assert_eq!(SunriseSunset.max_timeout_ms(), 3_000);
    }

    #[test]
    fn parse_response() {
        let raw = r#"{
            "status": "OK",
            "results": {
                "sunrise": "2024-06-15T20:00:00+00:00",
                "sunset": "2024-06-16T07:00:00+00:00",
                "solar_noon": "2024-06-16T01:30:00+00:00",
                "day_length": 39600,
                "civil_twilight_begin": "2024-06-15T19:30:00+00:00",
                "civil_twilight_end": "2024-06-16T07:30:00+00:00"
            }
        }"#;
        let r: SsResp = serde_json::from_str(raw).unwrap();
        assert_eq!(r.status.as_deref(), Some("OK"));
        let res = r.results.unwrap();
        assert!(res.sunrise.is_some());
        assert!(res.sunset.is_some());
    }
}
