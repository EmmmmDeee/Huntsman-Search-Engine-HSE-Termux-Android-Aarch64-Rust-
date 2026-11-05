//! Read-only, evidence-scoped Queensland public traffic-camera catalogue.
//!
//! One explicit request reads the whole `QLDTraffic` `GeoJSON` webcam feed through the API leg
//! kernel ([`crate::api_leg`]). This module never polls, downloads images or claims an image is
//! live: `image_url` is only a publisher assertion until it is fetched separately.
//!
//! The feed takes its key as the `apikey` query parameter. The key comes only from the operator's
//! [`KEY_SLOT`] and is added to the request as it is sent; none is built into the binary. The
//! publisher's API specification (v1.10, §2.1.1.1) prints a shared public developer key, limited
//! to 100 requests a minute across everyone who uses it; an operator may put that key or one TMR
//! issued to them in the slot. Without a key the command sends nothing and reports the slot as not
//! configured.

use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::Value;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse};
use crate::http::Transport;
use crate::keys::Keys;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub mod reconcile;

pub const SOURCE: &str = "qld_traffic_cameras";
pub const ENDPOINT: &str = "https://api.qldtraffic.qld.gov.au/v1/webcams";
/// The slot the `QLDTraffic` key is read from.
pub const KEY_SLOT: &str = crate::environment::QLDTRAFFIC_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "qldtraffic.qld.gov.au",
    origin: "https://api.qldtraffic.qld.gov.au:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Query("apikey"),
        required: true,
    }),
};
pub const MAX_CAMERAS: usize = 2_000;
/// The body limit of the transport both catalogue requests are sent on.
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

/// One explicit request for the whole catalogue, with the key from `keys`. A missing key, a
/// refusal, or a network, status or decoding failure is the outcome of an empty catalogue, never
/// a zero-camera answer.
#[must_use]
pub fn collect<T: Transport + ?Sized>(transport: &T, keys: &Keys, now_unix: u64) -> Catalogue {
    let parsed = api_leg::get(transport, &API, keys, ENDPOINT, now_unix)
        .and_then(Answer::body_or_unexpected)
        .and_then(|body| api_leg::decode::<Value>(&body))
        .map_err(|error| error.outcome(&API, now_unix))
        .and_then(|document| parse(&document, now_unix));
    parsed.unwrap_or_else(|outcome| Catalogue {
        source: SOURCE,
        fetched_at_unix: now_unix,
        cameras: Vec::new(),
        rejected_features: 0,
        outcome,
    })
}

fn failed(now: u64, kind: SourceOutcomeKind, reason: &str) -> SourceExecutionOutcome {
    SourceExecutionOutcome::failed(SOURCE, now, kind, None, reason)
}

/// A trimmed, non-empty publisher string of at most `bound` bytes with no control character.
fn short_text(value: Option<&Value>, bound: usize) -> Option<String> {
    let text = value?.as_str()?.trim();
    (!text.is_empty() && text.len() <= bound && !text.chars().any(char::is_control))
        .then(|| text.to_owned())
}

/// A `GeoJSON` `Point` feature's position as (latitude, longitude), only when it is a valid
/// coordinate. `GeoJSON` writes the pair longitude first.
fn point(feature: &Value) -> Option<(f64, f64)> {
    if feature.get("type")?.as_str()? != "Feature"
        || feature.pointer("/geometry/type")?.as_str()? != "Point"
    {
        return None;
    }
    let coords = feature.pointer("/geometry/coordinates")?.as_array()?;
    let [lon, lat] = coords.as_slice() else {
        return None;
    };
    let (lat, lon) = (lat.as_f64()?, lon.as_f64()?);
    crate::geohash::valid_coordinate(lat, lon).then_some((lat, lon))
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
    let (latitude, longitude) = point(feature)?;
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
        latitude,
        longitude,
        metadata_url,
        image_url,
        image_sourced_from: short_text(p.get("image_sourced_from"), 256),
        is_custom: p.get("isCustom").and_then(Value::as_bool),
        extra_info: short_text(p.get("extra_info"), 512),
    })
}

/// Parse a publisher `GeoJSON` document, preserving observed/rejected cardinalities.
/// A genuine empty `FeatureCollection` is `valid_zero`; nonempty data in which every
/// feature is malformed is `semantic_drift`, never `valid_zero`.
///
/// # Errors
/// Rejects missing/oversized features arrays or structurally incompatible answers.
pub fn parse(document: &Value, now_unix: u64) -> Result<Catalogue, SourceExecutionOutcome> {
    if document.get("type").and_then(Value::as_str) != Some("FeatureCollection") {
        return Err(failed(
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            "expected `GeoJSON` FeatureCollection",
        ));
    }
    let Some(features) = document.get("features").and_then(Value::as_array) else {
        return Err(failed(
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            "camera catalogue has no features array",
        ));
    };
    if features.len() > MAX_CAMERAS {
        return Err(failed(
            now_unix,
            SourceOutcomeKind::ParserDrift,
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
            "all returned camera features failed validation",
        )
    } else if cameras.is_empty() {
        SourceExecutionOutcome::valid_zero(SOURCE, now_unix)
    } else {
        SourceExecutionOutcome::success(SOURCE, now_unix, cameras.len())
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

    /// A key no provider issued, shaped like none either, so a leak of it is easy to search for.
    const TEST_KEY: &str = "test-only-qldtraffic-key";

    fn keyed() -> Keys {
        Keys::parse(&format!("{KEY_SLOT}={TEST_KEY}\n")).expect("keys")
    }

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

    fn answer(status: u16, body: Vec<u8>) -> ScriptedTransport {
        ScriptedTransport::new(vec![Ok(Response {
            status,
            headers: vec![],
            body,
            truncated: false,
        })])
    }

    #[test]
    fn canonical_geojson_keeps_longitude_latitude_and_optional_fields() {
        let report = parse(&sample(), 100).expect("valid");
        assert_eq!(report.cameras.len(), 1);
        assert_eq!(
            report.cameras[0].longitude.to_bits(),
            153.008_697_5_f64.to_bits()
        );
        assert_eq!(
            report.cameras[0].latitude.to_bits(),
            (-27.555_179_6_f64).to_bits()
        );
        assert_eq!(report.cameras[0].metadata_url, format!("{ENDPOINT}/1"));
        assert_eq!(report.cameras[0].is_custom, Some(false));
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
    }

    #[test]
    fn empty_catalogue_is_valid_zero_but_wrong_shape_is_drift() {
        assert_eq!(
            parse(&json!({"type":"FeatureCollection","features":[]}), 100)
                .expect("empty")
                .outcome
                .kind,
            SourceOutcomeKind::ValidZero
        );
        assert!(parse(&json!({"features":[]}), 100).is_err());
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
        let result = parse(&doc, 100).expect("some valid");
        assert_eq!(result.cameras.len(), 1);
        assert_eq!(result.rejected_features, 2);
    }

    #[test]
    fn all_invalid_is_not_an_empty_success() {
        let mut doc = sample();
        doc["features"][0]["geometry"]["coordinates"] = json!([-200.0, 200.0]);
        assert_eq!(
            parse(&doc, 100).expect("report").outcome.kind,
            SourceOutcomeKind::SemanticDrift
        );
    }

    #[test]
    fn a_position_that_is_not_a_longitude_latitude_pair_is_rejected() {
        for coordinates in [
            json!([153.0]),
            json!([153.0, -27.5, 10.0]),
            json!(["153.0", "-27.5"]),
        ] {
            let mut doc = sample();
            doc["features"][0]["geometry"]["coordinates"] = coordinates;
            assert_eq!(parse(&doc, 100).expect("report").rejected_features, 1);
        }
    }

    #[test]
    fn the_key_is_sent_only_as_the_request_goes_out_and_the_report_is_accepted() {
        let transport = answer(200, sample().to_string().into_bytes());
        let report = collect(&transport, &keyed(), 101);
        assert_eq!(report.cameras.len(), 1);
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        let requests = transport.seen.borrow();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, format!("{ENDPOINT}?apikey={TEST_KEY}"));
        assert!(!ENDPOINT.contains("apikey"));
    }

    #[test]
    fn without_a_key_nothing_is_sent_and_the_slot_is_named() {
        let transport = answer(200, sample().to_string().into_bytes());
        let report = collect(&transport, &Keys::default(), 101);
        assert!(transport.seen.borrow().is_empty());
        assert!(report.cameras.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::NotConfigured);
        assert!(
            report
                .outcome
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains(KEY_SLOT)),
            "{:?}",
            report.outcome.detail
        );
    }

    #[test]
    fn a_refused_key_or_a_rate_limit_is_never_an_empty_catalogue() {
        for (status, kind) in [
            (401, SourceOutcomeKind::AuthRejected),
            (403, SourceOutcomeKind::EntitlementDenied),
            (429, SourceOutcomeKind::RateLimited),
        ] {
            let transport = answer(status, b"{\"message\":\"Unauthorized\"}".to_vec());
            let report = collect(&transport, &keyed(), 101);
            assert!(report.cameras.is_empty());
            assert_eq!(report.outcome.kind, kind, "HTTP {status}");
            let detail = report.outcome.detail.as_deref().unwrap_or_default();
            assert!(!detail.contains(TEST_KEY), "{detail}");
        }
    }
}
