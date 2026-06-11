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
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
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

/// Build the chronolocation entity from a solar-phase result. **Pure** (no
/// network/IO): records the queried date/lat/lon plus every present solar
/// timestamp (sunrise/sunset/solar-noon, the three twilight bands) and the day
/// length, normalising `day_length` from either its numeric (seconds) or string
/// form. `coord` is the original target value (kept verbatim as the entity).
fn build_solar_entity(
    coord: &str,
    lat: f64,
    lon: f64,
    today: &str,
    results: &SsResults,
    scan_id: &str,
) -> Entity {
    let mut entity = Entity::new(EntityKind::Coordinates, coord, 0.55, scan_id);
    entity.tag("sunrise-sunset");
    entity.tag("chronolocation");
    entity.tag(crate::core::tags::GEOINT);
    if crate::util::geo::is_in_australia(lat, lon) {
        for t in crate::util::geo::au_coord_tags(lat, lon) {
            entity.tag(t);
        }
    }

    let mut ev = Evidence::new(
        SRC,
        format!("Solar phases for {lat:.4},{lon:.4} on {today}"),
    )
    .with_attr("date", today)
    .with_attr("latitude", format!("{lat:.6}"))
    .with_attr("longitude", format!("{lon:.6}"));

    for (attr, val) in [
        ("sunrise_utc", results.sunrise.as_deref()),
        ("sunset_utc", results.sunset.as_deref()),
        ("solar_noon_utc", results.solar_noon.as_deref()),
        (
            "civil_twilight_begin",
            results.civil_twilight_begin.as_deref(),
        ),
        ("civil_twilight_end", results.civil_twilight_end.as_deref()),
        (
            "nautical_twilight_begin",
            results.nautical_twilight_begin.as_deref(),
        ),
        (
            "nautical_twilight_end",
            results.nautical_twilight_end.as_deref(),
        ),
        (
            "astronomical_twilight_begin",
            results.astronomical_twilight_begin.as_deref(),
        ),
        (
            "astronomical_twilight_end",
            results.astronomical_twilight_end.as_deref(),
        ),
    ] {
        if let Some(v) = val {
            ev = ev.with_attr(attr, v);
        }
    }

    // `day_length` is a number (seconds) on the formatted=0 API but a string on
    // the default endpoint — accept either.
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

    entity.add_evidence(ev);
    entity
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
        // Two sequential network requests, neither with a per-request
        // timeout. The explicit 3s matched MODULE_TIMEOUT_MS, so the engine
        // killed the module before even one slow response returned. Budget
        // for both requests.
        12_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Coordinates];
        KINDS
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
        result.push(build_solar_entity(
            &target.value,
            lat,
            lon,
            &today,
            &results,
            &ctx.scan_id,
        ));
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
        assert_eq!(SunriseSunset.max_timeout_ms(), 12_000);
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

    #[test]
    fn civil_from_days_matches_known_dates() {
        // Unix epoch and a handful of known day-counts (days since 1970-01-01).
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(31), (1970, 2, 1));
        // 2000-02-29 (leap day) is day 11016.
        assert_eq!(civil_from_days(11016), (2000, 2, 29));
        // 2024-06-16 is day 19890.
        assert_eq!(civil_from_days(19890), (2024, 6, 16));
    }

    fn results(json: &str) -> SsResults {
        serde_json::from_str(json).unwrap()
    }

    fn attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
        e.evidence[0].attributes.get(k).map(String::as_str)
    }

    #[test]
    fn solar_entity_records_phases_and_numeric_day_length() {
        let res = results(
            r#"{
                "sunrise":"2024-06-15T20:00:00+00:00",
                "sunset":"2024-06-16T07:00:00+00:00",
                "solar_noon":"2024-06-16T01:30:00+00:00",
                "day_length":39600,
                "civil_twilight_begin":"2024-06-15T19:30:00+00:00"
            }"#,
        );
        let e = build_solar_entity("-33.8,151.2", -33.8, 151.2, "2024-06-16", &res, "s");
        assert_eq!(e.kind, EntityKind::Coordinates);
        assert!(e.has_tag("sunrise-sunset") && e.has_tag("chronolocation") && e.has_tag("geoint"));
        assert!((e.confidence - 0.55).abs() < 1e-9);
        assert_eq!(attr(&e, "date"), Some("2024-06-16"));
        assert_eq!(attr(&e, "latitude"), Some("-33.800000"));
        assert_eq!(attr(&e, "longitude"), Some("151.200000"));
        assert_eq!(attr(&e, "sunrise_utc"), Some("2024-06-15T20:00:00+00:00"));
        assert_eq!(
            attr(&e, "solar_noon_utc"),
            Some("2024-06-16T01:30:00+00:00")
        );
        assert_eq!(
            attr(&e, "civil_twilight_begin"),
            Some("2024-06-15T19:30:00+00:00")
        );
        // Numeric day_length normalised to a string.
        assert_eq!(attr(&e, "day_length_s"), Some("39600"));
    }

    #[test]
    fn solar_entity_accepts_string_day_length_and_omits_absent_phases() {
        // The default (formatted) endpoint returns day_length as "11:00:00".
        let res = results(r#"{"sunrise":"6:00:00 AM","day_length":"11:00:00"}"#);
        let e = build_solar_entity("0,0", 0.0, 0.0, "2024-01-01", &res, "s");
        assert_eq!(attr(&e, "day_length_s"), Some("11:00:00"));
        assert_eq!(attr(&e, "sunrise_utc"), Some("6:00:00 AM"));
        // Phases the response omitted must not appear.
        assert_eq!(attr(&e, "sunset_utc"), None);
        assert_eq!(attr(&e, "nautical_twilight_begin"), None);
    }
}
