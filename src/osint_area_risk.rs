//! Independent public-event area analysis for locally imported evidence.
//! Zero observations never establishes safety; outcomes are transparent heuristics.

use crate::error::Error;
use crate::geoint::haversine_m;
use crate::osint_casework::validate_public_source_url;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MAX_RISK_BYTES: usize = 256 * 1024;
pub const MAX_RISK_EVENTS: usize = 2048;
const WINDOW_SECS: u64 = 30 * 24 * 3600;
const RECENT_SECS: u64 = 72 * 3600;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicEvent {
    pub id: String,
    pub source_url: String,
    pub lat: f64,
    pub lon: f64,
    pub occurred_at_unix: u64,
    pub category: String,
    pub severity: u8,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AreaInput {
    pub as_of_unix: u64,
    pub events: Vec<PublicEvent>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AreaRequest {
    pub as_of_unix: u64,
    pub events: Vec<PublicEvent>,
    pub center_lat: f64,
    pub center_lon: f64,
    pub radius_m: f64,
    pub category: String,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AreaEstimate {
    pub as_of_unix: u64,
    pub center_lat: f64,
    pub center_lon: f64,
    pub radius_m: f64,
    pub window_days: u8,
    pub nearby: usize,
    pub recent: usize,
    pub matching: usize,
    pub excluded: usize,
    pub density_events_per_km2_day: f64,
    pub score_0_to_100: u8,
    pub components: [f64; 4],
    pub category: String,
    pub evidence_role: &'static str,
    pub limitations: Vec<&'static str>,
}
fn valid_location(lat: f64, lon: f64) -> bool {
    lat.is_finite()
        && lon.is_finite()
        && (-90.0..=90.0).contains(&lat)
        && (-180.0..=180.0).contains(&lon)
}
fn valid_category(value: &str) -> bool {
    matches!(
        value,
        "general" | "parking" | "vehicle_theft" | "personal_safety" | "property"
    )
}
/// Verify all supplied records before aggregating.
/// # Errors
/// Rejects invalid, unbounded or duplicate public records.
pub fn validate(input: &AreaInput) -> Result<(), Error> {
    if input.as_of_unix == 0 || input.events.len() > MAX_RISK_EVENTS {
        return Err(Error::invalid("bad area event timestamp or count"));
    }
    let mut ids = BTreeSet::new();
    for event in &input.events {
        if event.id.is_empty()
            || event.id.len() > 128
            || event.id.chars().any(char::is_control)
            || !ids.insert(event.id.as_str())
            || !valid_location(event.lat, event.lon)
            || !(1..=5).contains(&event.severity)
            || !valid_category(&event.category)
            || event.occurred_at_unix > input.as_of_unix
        {
            return Err(Error::invalid("invalid or duplicate event"));
        }
        validate_public_source_url(&event.source_url)?;
    }
    Ok(())
}
fn bounded(value: f64, cap: f64, scale: f64) -> f64 {
    cap * (1.0 - (-value / scale).exp())
}
/// Score imported event pressure at one point using bounded monotonic components.
/// This is neither an official crime rate nor an estimate of victimisation.
/// # Errors
/// Invalid center, radius, category or input.
pub fn estimate(
    input: &AreaInput,
    lat: f64,
    lon: f64,
    radius_m: f64,
    category: &str,
) -> Result<AreaEstimate, Error> {
    validate(input)?;
    if !valid_location(lat, lon)
        || !radius_m.is_finite()
        || !(100.0..=10000.0).contains(&radius_m)
        || !valid_category(category)
    {
        return Err(Error::invalid("bad area center, radius or category"));
    }
    let mut nearby = 0usize;
    let mut recent = 0usize;
    let mut matching = 0usize;
    let mut excluded = 0usize;
    let mut weighted = 0.0_f64;
    let mut targeted = 0.0_f64;
    let mut severe = 0usize;
    for event in &input.events {
        let age = input.as_of_unix.saturating_sub(event.occurred_at_unix);
        if age > WINDOW_SECS || haversine_m(lat, lon, event.lat, event.lon) > radius_m {
            excluded += 1;
            continue;
        }
        nearby += 1;
        let weight = f64::from(event.severity) / 3.0;
        weighted += weight;
        if category == "general" || event.category == category {
            matching += 1;
            targeted += weight;
        }
        if age <= RECENT_SECS {
            recent += 1;
        }
        if event.severity >= 4 {
            severe += 1;
        }
    }
    let area_km2 = std::f64::consts::PI * (radius_m / 1000.0).powi(2);
    let daily_density = weighted / (area_km2 * 30.0);
    let focused_density = targeted / (area_km2 * 30.0);
    let components = [
        bounded(daily_density, 45.0, 0.2),
        bounded(focused_density, 25.0, 0.12),
        bounded(f64::from(u16::try_from(recent).unwrap_or(u16::MAX)), 15.0, 3.0),
        bounded(f64::from(u16::try_from(severe).unwrap_or(u16::MAX)), 15.0, 2.0),
    ];
    let rounded_score = components.iter().sum::<f64>().clamp(0.0, 100.0).round();
    let score = (0_u8..=100)
        .find(|candidate| f64::from(*candidate) >= rounded_score)
        .unwrap_or(100);
    Ok(AreaEstimate {
        as_of_unix: input.as_of_unix,
        center_lat: lat,
        center_lon: lon,
        radius_m,
        window_days: 30,
        nearby,
        recent,
        matching,
        excluded,
        density_events_per_km2_day: daily_density,
        score_0_to_100: score,
        components,
        category: category.to_owned(),
        evidence_role: "public_record_pressure_not_a_safety_prediction",
        limitations: vec![
            "Source coordinates, severity, categories and timestamps are imported assertions",
            "Unreported incidents and uneven data coverage make scores incomparable without coverage review",
            "A zero score is not evidence of safety",
            "This is an independent heuristic, not H1DR4 proprietary scoring",
        ],
    })
}
/// Parse bounded standalone public-event JSON.
/// # Errors
/// Bad size, schema or record contents.
pub fn input_json(bytes: &[u8]) -> Result<AreaInput, Error> {
    if bytes.len() > MAX_RISK_BYTES {
        return Err(Error::invalid("area file too large"));
    }
    let input: AreaInput =
        serde_json::from_slice(bytes).map_err(|_| Error::invalid("area file schema invalid"))?;
    validate(&input)?;
    Ok(input)
}
/// Shared HTTP route method for event dataset, point and radius.
/// # Errors
/// Oversized or invalid JSON.
pub fn estimate_json(bytes: &[u8]) -> Result<AreaEstimate, Error> {
    if bytes.len() > MAX_RISK_BYTES {
        return Err(Error::invalid("area request too large"));
    }
    let request: AreaRequest =
        serde_json::from_slice(bytes).map_err(|_| Error::invalid("area request JSON invalid"))?;
    estimate(
        &AreaInput {
            as_of_unix: request.as_of_unix,
            events: request.events,
        },
        request.center_lat,
        request.center_lon,
        request.radius_m,
        &request.category,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    fn input() -> AreaInput {
        AreaInput {
            as_of_unix: 200000,
            events: vec![PublicEvent {
                id: "fixture".into(),
                source_url: "https://example.org/item".into(),
                lat: -26.8,
                lon: 152.9,
                occurred_at_unix: 199999,
                category: "property".into(),
                severity: 5,
            }],
        }
    }
    #[test]
    fn bounds_and_distance_behave() {
        let indata = input();
        assert!(
            estimate(&indata, -26.8, 152.9, 1000.0, "general")
                .unwrap()
                .score_0_to_100
                > 0
        );
        assert_eq!(
            estimate(&indata, 0.0, 0.0, 1000.0, "general")
                .unwrap()
                .nearby,
            0
        );
        assert!(estimate(&indata, 95.0, 0.0, 1000.0, "general").is_err());
    }
    #[test]
    fn duplicate_ids_fail_closed() {
        let mut indata = input();
        indata.events.push(indata.events[0].clone());
        assert!(validate(&indata).is_err());
    }
}
