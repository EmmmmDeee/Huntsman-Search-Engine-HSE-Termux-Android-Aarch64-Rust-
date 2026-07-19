//! Sunrise-Sunset — solar phase timestamps for chronolocation.
//!
//! Endpoint: `GET https://api.sunrise-sunset.org/json?lat={lat}&lng={lon}&date={YYYY-MM-DD}`
//! Auth:     None (free, public).
//!
//! Returns UTC timestamps for sunrise, sunset, solar noon, golden hour,
//! and other astronomical events. Used for chronolocation of imagery.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{confidence, 
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

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
    let mut entity = Entity::new(EntityKind::Coordinates, coord, confidence::MEDIUM_HIGH, scan_id);
    entity.tag("sunrise-sunset");
    entity.tag("chronolocation");
    entity.tag("geoint");

    // Fold every present solar timestamp into the evidence in one pass.
    let mut ev = [
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
    ]
    .into_iter()
    .filter_map(|(attr, val)| val.map(|v| (attr, v)))
    .fold(
        Evidence::new(
            SRC,
            format!("Solar phases for {lat:.4},{lon:.4} on {today}"),
        )
        .with_attr("date", today)
        .with_attr("latitude", format!("{lat:.6}"))
        .with_attr("longitude", format!("{lon:.6}")),
        |ev, (attr, v)| ev.with_attr(attr, v),
    );

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
        "Solar-phase recon — resolves sunrise/sunset timestamps to chronolocate imagery"
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
            .send_tagged(SRC)
            .await?;

        if !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }

        let body: SsResp = crate::util::http::json_decode(SRC, resp).await?;

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
    include!("tests.rs");
}
