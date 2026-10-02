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
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;
use crate::util::timefmt::civil_from_days;

const SRC: &str = "sunrise_sunset";

/// Where the solar-phase JSON lives; `formatted=0` yields ISO-8601 UTC times.
const API_BASE: &str = "https://api.sunrise-sunset.org/json";

pub struct SunriseSunset;

#[derive(Deserialize)]
struct SsResp {
    #[serde(default)]
    status: Option<String>,
    /// The phase object on `OK`. Kept as a raw value because the provider
    /// sends `"results": ""` (a string) alongside an error status — typing it
    /// as `Option<SsResults>` would turn every documented error answer into a
    /// decode failure that hides the status the provider actually gave.
    #[serde(default)]
    results: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
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
///
/// The entity is an ANNOTATION of the queried point: when the sun rises there
/// is a fact about the point, not a sighting of the subject at it. So it
/// carries the confidence floor and its record is marked
/// `Evidence::as_annotation` — it neither corroborates the point nor raises it
/// through the max-confidence merge (it used to carry `MEDIUM_HIGH` as an
/// independent source; REQ-GEO-008).
fn build_solar_entity(
    coord: &str,
    lat: f64,
    lon: f64,
    today: &str,
    results: &SsResults,
    scan_id: &str,
) -> Entity {
    let mut entity = Entity::new(
        EntityKind::Coordinates,
        coord,
        confidence::DERIVED_FLOOR,
        scan_id,
    );
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
        let dl = crate::util::json::scalar_str(v)
            .map(std::borrow::Cow::into_owned)
            .unwrap_or_default();
        if !dl.is_empty() {
            ev = ev.with_attr("day_length_s", dl);
        }
    }

    entity.add_evidence(ev.as_annotation());
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
        // Coordinates → sunrise-sunset.org solar-phase timestamps (sunrise/sunset/twilight/day
        // length) for chronolocation — physical-location context only, not DNS/WHOIS/cert/
        // network/identity/host data, so the default T1591.001 mapping already fits.
        ModuleCategory::Geo
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Coordinates];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let (lat, lon) = crate::util::geo::parse_coords(&target.value)?;

        let today = today_utc();
        let results = fetch_solar(&ctx.http, API_BASE, lat, lon, &today).await?;

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

/// One solar-phase lookup. The provider computes phases for ANY coordinates, so
/// there is no "no data for this place": a non-2xx (the endpoint is fixed — a
/// 404 is the endpoint gone, not a miss), a non-`OK` status in the body
/// (`INVALID_REQUEST`, `INVALID_DATE`, `UNKNOWN_ERROR` — the documented
/// server-side failure) or an `OK` without `results` is a failed lookup and is
/// the module's error. Before this every one of them was an empty result —
/// recorded as a clean negative (`docs/PROVIDER_SWEEP_BACKLOG.md` #43).
async fn fetch_solar(
    client: &reqwest::Client,
    api_base: &str,
    lat: f64,
    lon: f64,
    date: &str,
) -> Result<SsResults> {
    let url = format!("{api_base}?lat={lat:.6}&lng={lon:.6}&date={date}&formatted=0");
    let resp = client
        .get(&url)
        .header("Accept", "application/json")
        .send_tagged(SRC)
        .await?;
    if !resp.status().is_success() {
        return Err(crate::util::http::http_status_error(SRC, resp).await);
    }
    let body: SsResp = crate::util::http::json_decode(SRC, resp).await?;
    match body.status.as_deref() {
        Some("OK") => body
            .results
            .filter(serde_json::Value::is_object)
            .map(serde_json::from_value::<SsResults>)
            .transpose()?
            .ok_or_else(|| {
                Error::module(
                    SRC,
                    "status OK but no `results` object — the response shape has changed",
                )
            }),
        other => Err(Error::module(
            SRC,
            format!(
                "api.sunrise-sunset.org answered status {} for {lat:.4},{lon:.4} — a failed \
                 lookup, not an empty one",
                other.unwrap_or("<missing>")
            ),
        )),
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

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
