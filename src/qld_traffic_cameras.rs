//! Read-only, evidence-scoped Queensland public traffic-camera catalogue.
//!
//! The Department of Transport and Main Roads' published public key is globally
//! shared (100 requests/minute). One explicit request reads the entire `GeoJSON`
//! feed; this module never polls, downloads images or claims an image is live.
//! `image_url` is merely a publisher assertion until separately fetched.

use std::collections::BTreeSet;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use crate::error::Error;
use crate::fetch::{FetchOptions, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Transport};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub mod reconcile;

pub const SOURCE: &str = "qld_traffic_cameras";
pub const ENDPOINT: &str = "https://api.qldtraffic.qld.gov.au/v1/webcams";
/// The public developer key printed in `QLDTraffic` API specification v1.10, §2.1.1.1.
/// It is *not* a user credential. Do not substitute an operator key in this URL.
pub const PUBLIC_KEY: &str = "3e83add325cbb69ac4d8e5bf433d770b";
pub const MAX_CAMERAS: usize = 2_000;
pub const MAX_CATALOGUE_BYTES: usize = 2 * 1024 * 1024;

/// A catalogued location, not verified live video or even a current JPEG.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Camera {
    pub id: u64,
    pub description: String,
    pub direction: String,
    pub district: String,
    pub locality: String,
    pub postcode: String,
    /// Decimal degrees; never silently swap the `GeoJSON` [longitude, latitude] pair.
    pub latitude: f64,
    pub longitude: f64,
    pub metadata_url: String,
    pub image_url: String,
    pub image_sourced_from: Option<String>,
    pub is_custom: Option<bool>,
    pub extra_info: Option<String>,
}

/// The provider outcome and the *observed* catalogue rows. No image validation occurs.
#[derive(Debug, Clone, Serialize)]
pub struct Catalogue {
    pub source: &'static str,
    pub fetched_at_unix: u64,
    pub cameras: Vec<Camera>,
    pub rejected_features: usize,
    pub outcome: SourceExecutionOutcome,
}

/// Explicit one-shot request through Huntsman's established guarded HTTP boundary.
/// A network or status failure is not an empty catalogue.
///
/// # Errors
/// Returns a policy/egress error when the guarded fetch refuses the URL.
pub fn collect<T: Transport + ?Sized>(transport: &T, now_unix: u64) -> Result<Catalogue, Error> {
    let request = Request::get_json(format!("{ENDPOINT}?apikey={PUBLIC_KEY}"))
        .with_timeout(Duration::from_secs(15));
    let fetched = fetch(
        transport,
        request,
        None,
        &FetchOptions::no_redirects().paced(),
        SOURCE,
        now_unix,
    )?;
    let result = (|| {
        let response = whole_response(&fetched, "QLDTraffic camera catalogue")?;
        answer(&fetched, "QLDTraffic camera catalogue")?;
        if response.body.len() > MAX_CATALOGUE_BYTES {
            return Err(failed(
                now_unix,
                SourceOutcomeKind::ParserDrift,
                response.status,
                "camera catalogue exceeds 2 MiB",
            ));
        }
        let document: Value =
            decode_json(response, SOURCE, now_unix, "QLDTraffic camera catalogue")?;
        parse(&document, now_unix, response.status)
    })();
    Ok(result.unwrap_or_else(|outcome| Catalogue {
        source: SOURCE,
        fetched_at_unix: now_unix,
        cameras: Vec::new(),
        rejected_features: 0,
        outcome,
    }))
}

fn failed(now: u64, kind: SourceOutcomeKind, status: u16, reason: &str) -> SourceExecutionOutcome {
    SourceExecutionOutcome::failed(SOURCE, now, kind, Some(status), reason)
}

fn short_text(value: Option<&Value>, bound: usize) -> Option<String> {
    let text = value?.as_str()?.trim();
    (!text.is_empty() && text.len() <= bound && !text.chars().any(char::is_control))
        .then(|| text.to_owned())
}

/// A publisher-supplied JPEG reference is retained only from documented camera hosts.
/// No redirect or media download is performed by this module.
fn camera_image_url(raw: &str) -> bool {
    let Some(without_scheme) = raw.strip_prefix("https://") else {
        return false;
    };
    let Some((authority, path)) = without_scheme.split_once('/') else {
        return false;
    };
    matches!(
        authority,
        "cameras.qldtraffic.qld.gov.au" | "webcams.qldtraffic.qld.gov.au"
    ) && !path.is_empty()
        && !path.contains(char::is_whitespace)
        && !path.contains('#')
        && !path.contains('?')
        && !path.contains('\\')
        && !path.contains('@')
}

/// Normalise one provider feature without trusting image origin or coordinates.
fn camera(feature: &Value) -> Option<Camera> {
    if feature.get("type")?.as_str()? != "Feature"
        || feature.pointer("/geometry/type")?.as_str()? != "Point"
    {
        return None;
    }
    let coords = feature.pointer("/geometry/coordinates")?.as_array()?;
    if coords.len() != 2 {
        return None;
    }
    let lon = coords[0].as_f64().filter(|v| v.is_finite())?;
    let lat = coords[1].as_f64().filter(|v| v.is_finite())?;
    if !(-180.0..=180.0).contains(&lon) || !(-90.0..=90.0).contains(&lat) {
        return None;
    }
    let p = feature.get("properties")?;
    let id = p.get("id")?.as_u64().filter(|id| *id != 0)?;
    let description = short_text(p.get("description"), 250)?;
    let direction = short_text(p.get("direction"), 50)?;
    let district = short_text(p.get("district"), 80)?;
    let locality = short_text(p.get("locality"), 120)?;
    let postcode = short_text(p.get("postcode"), 12)?;
    let image_url = short_text(p.get("image_url"), 512)?;
    if !camera_image_url(&image_url) {
        return None;
    }
    // Do not trust an arbitrary provider "url": derive the canonical metadata link.
    let metadata_url = format!("{ENDPOINT}/{id}");
    Some(Camera {
        id,
        description,
        direction,
        district,
        locality,
        postcode,
        latitude: lat,
        longitude: lon,
        metadata_url,
        image_url,
        image_sourced_from: short_text(p.get("image_sourced_from"), 256),
        is_custom: p.get("isCustom").and_then(Value::as_bool),
        extra_info: short_text(p.get("extra_info"), 512),
    })
}

/// Parse a publisher `GeoJSON` document, preserving observed/rejected cardinalities.
/// A genuine empty `FeatureCollection` is `valid_zero`; nonempty data in which every
/// feature is malformed is `schema_drift`, never `valid_zero`.
///
/// # Errors
/// Rejects missing/oversized features arrays or structurally incompatible answers.
pub fn parse(
    document: &Value,
    now_unix: u64,
    http_status: u16,
) -> Result<Catalogue, SourceExecutionOutcome> {
    if document.get("type").and_then(Value::as_str) != Some("FeatureCollection") {
        return Err(failed(
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            http_status,
            "expected `GeoJSON` FeatureCollection",
        ));
    }
    let Some(features) = document.get("features").and_then(Value::as_array) else {
        return Err(failed(
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            http_status,
            "camera catalogue has no features array",
        ));
    };
    if features.len() > MAX_CAMERAS {
        return Err(failed(
            now_unix,
            SourceOutcomeKind::ParserDrift,
            http_status,
            "camera catalogue exceeds 2000 features",
        ));
    }
    let mut ids = BTreeSet::new();
    let mut cameras = Vec::with_capacity(features.len());
    let mut rejected = 0_usize;
    for feature in features {
        match camera(feature) {
            Some(entry) if ids.insert(entry.id) => cameras.push(entry),
            _ => rejected += 1,
        }
    }
    cameras.sort_by_key(|camera| camera.id);
    let outcome = if cameras.is_empty() && !features.is_empty() {
        failed(
            now_unix,
            SourceOutcomeKind::SemanticDrift,
            http_status,
            "all returned camera features failed validation",
        )
    } else if cameras.is_empty() {
        SourceExecutionOutcome::valid_zero(SOURCE, now_unix).with_http_status(http_status)
    } else {
        SourceExecutionOutcome::success(SOURCE, now_unix, cameras.len())
            .with_http_status(http_status)
    };
    let outcome = if rejected == 0 {
        outcome
    } else {
        outcome.with_detail(format!(
            "{rejected} of {} camera features rejected; do not interpret as unavailable cameras",
            features.len()
        ))
    };
    Ok(Catalogue {
        source: SOURCE,
        fetched_at_unix: now_unix,
        cameras,
        rejected_features: rejected,
        outcome,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Response;
    use crate::test_support::ScriptedTransport;
    use serde_json::json;

    fn sample() -> Value {
        json!({
            "type":"FeatureCollection",
            "features":[{
                "type":"Feature",
                "geometry":{"type":"Point","coordinates":[153.008_697_5,-27.555_179_6]},
                "properties":{
                    "id":1,
                    "url":"https://api.qldtraffic.qld.gov.au/v1/webcams/1",
                    "description":"Archerfield - North",
                    "direction":"NorthEast",
                    "district":"Metropolitan",
                    "locality":"Archerfield",
                    "postcode":"4108",
                    "image_url":"https://cameras.qldtraffic.qld.gov.au/Metropolitan/archerfield.jpg",
                    "isCustom":false
                }
            }]
        })
    }

    #[test]
    fn canonical_geojson_keeps_longitude_latitude_and_optional_fields() {
        let report = parse(&sample(), 100, 200).expect("valid");
        assert_eq!(report.cameras.len(), 1);
        assert_eq!(report.cameras[0].longitude, 153.008_697_5);
        assert_eq!(report.cameras[0].latitude, -27.555_179_6);
        assert_eq!(report.cameras[0].metadata_url, format!("{ENDPOINT}/1"));
        assert_eq!(report.cameras[0].is_custom, Some(false));
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
    }

    #[test]
    fn empty_catalogue_is_valid_zero_but_wrong_shape_is_drift() {
        assert_eq!(
            parse(&json!({"type":"FeatureCollection","features":[]}), 100, 200)
                .expect("empty")
                .outcome
                .kind,
            SourceOutcomeKind::ValidZero
        );
        assert!(parse(&json!({"features":[]}), 100, 200).is_err());
    }

    #[test]
    fn rejects_duplicate_and_non_publisher_image_origin() {
        let mut doc = sample();
        let duplicate = doc["features"][0].clone();
        doc["features"]
            .as_array_mut()
            .expect("array")
            .push(duplicate);
        let mut forged = doc["features"][0].clone();
        forged["properties"]["id"] = json!(2);
        forged["properties"]["image_url"] = json!("https://example.com/secret.jpg");
        doc["features"].as_array_mut().expect("array").push(forged);
        let result = parse(&doc, 100, 200).expect("some valid");
        assert_eq!(result.cameras.len(), 1);
        assert_eq!(result.rejected_features, 2);
    }

    #[test]
    fn all_invalid_is_not_an_empty_success() {
        let mut doc = sample();
        doc["features"][0]["geometry"]["coordinates"] = json!([-200.0, 200.0]);
        assert_eq!(
            parse(&doc, 100, 200).expect("report").outcome.kind,
            SourceOutcomeKind::SemanticDrift
        );
    }

    #[test]
    fn scripted_http_produces_accepted_report() {
        let transport = ScriptedTransport::new(vec![Ok(Response {
            status: 200,
            headers: vec![],
            body: sample().to_string().into_bytes(),
            truncated: false,
        })]);
        let report = collect(&transport, 101).expect("transport");
        assert_eq!(report.cameras.len(), 1);
        let requests = transport.seen.borrow();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].url.starts_with(ENDPOINT));
        assert!(requests[0].url.contains("apikey="));
    }

    #[test]
    fn http_429_is_not_valid_zero() {
        let transport = ScriptedTransport::new(vec![Ok(Response {
            status: 429,
            headers: vec![],
            body: b"Too Many Requests".to_vec(),
            truncated: false,
        })]);
        let report = collect(&transport, 101).expect("transport");
        assert!(report.cameras.is_empty());
        assert_ne!(report.outcome.kind, SourceOutcomeKind::ValidZero);
        assert_ne!(report.outcome.kind, SourceOutcomeKind::Success);
    }
}
