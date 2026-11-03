//! Opt-in second-source reconciliation of TMR camera metadata against its GIS asset layer.
//!
//! Both catalogues are issued by Transport and Main Roads. Agreement is source
//! consistency, not independent corroboration, a working JPEG, or surveillance proof.
//! The GIS source is read once on explicit CLI request, never automatically polled.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use super::{Camera, Catalogue, MAX_CAMERAS, MAX_CATALOGUE_BYTES};
use crate::error::Error;
use crate::fetch::{FetchOptions, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Transport};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const SOURCE_GIS: &str = "qld_state_road_camera_gis";
/// Fixed and encoded `ArcGIS` query. `outSR=4326` explicitly requests WGS84 lon/lat,
/// rather than the layer's default Web Mercator metre coordinates.
pub const GIS_URL: &str = "https://spatial-gis.information.qld.gov.au/arcgis/rest/services/Transportation/StateRoadInformation/MapServer/4/query?where=1%3D1&outFields=camera_id%2Cdescription%2Cdirection%2Clocality&returnGeometry=true&outSR=4326&f=geojson";

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GisCamera {
    pub id: u64,
    pub description: String,
    pub direction: Option<String>,
    pub locality: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct GisCatalogue {
    pub source: &'static str,
    pub fetched_at_unix: u64,
    pub cameras: Vec<GisCamera>,
    pub rejected_features: usize,
    pub outcome: SourceExecutionOutcome,
}

/// A shared identifier whose publisher-coordinates disagree beyond 100 metres.
#[derive(Debug, Clone, Serialize)]
pub struct PositionConflict {
    pub id: u64,
    pub separation_metres: f64,
    pub webcam_description: String,
    pub gis_description: String,
    pub webcam_latitude: f64,
    pub webcam_longitude: f64,
    pub gis_latitude: f64,
    pub gis_longitude: f64,
}

/// Distinct official directions for the same publisher camera identifier.
#[derive(Debug, Clone, Serialize)]
pub struct DirectionConflict {
    pub id: u64,
    pub webcam_direction: String,
    pub gis_direction: String,
}

/// Nearby records with different IDs; **never** automatic identity links.
#[derive(Debug, Clone, Serialize)]
pub struct SpatialCandidate {
    pub webcam_id: u64,
    pub gis_id: u64,
    pub separation_metres: f64,
    pub relation: &'static str,
}

/// Counts and exact differences are reported without asserting either source is complete.
#[derive(Debug, Clone, Serialize)]
pub struct Reconciliation {
    pub webcam_count: usize,
    pub gis_count: usize,
    pub shared_ids: usize,
    pub webcam_only_ids: Vec<u64>,
    pub gis_only_ids: Vec<u64>,
    pub position_conflicts: Vec<PositionConflict>,
    pub direction_conflicts: Vec<DirectionConflict>,
    pub spatial_candidates: Vec<SpatialCandidate>,
    pub candidate_search_truncated: bool,
    pub publisher_families: usize,
    pub evidence_role: &'static str,
}

/// One-shot GIS fetch through the established guarded transport; no arbitrary URL input.
///
/// # Errors
/// Egress policy refusal or invalid HTTP request.
pub fn collect_gis<T: Transport + ?Sized>(
    transport: &T,
    now_unix: u64,
) -> Result<GisCatalogue, Error> {
    let request = Request::get_json(GIS_URL).with_timeout(Duration::from_secs(15));
    let fetched = fetch(
        transport,
        request,
        None,
        &FetchOptions::no_redirects().paced(),
        SOURCE_GIS,
        now_unix,
    )?;
    let result = (|| {
        let response = whole_response(&fetched, "TMR state-road camera GIS")?;
        answer(&fetched, "TMR state-road camera GIS")?;
        if response.body.len() > MAX_CATALOGUE_BYTES {
            return Err(failed(
                now_unix,
                response.status,
                SourceOutcomeKind::ParserDrift,
                "GIS camera catalogue exceeds 2 MiB",
            ));
        }
        let json: Value = decode_json(response, SOURCE_GIS, now_unix, "TMR state-road camera GIS")?;
        parse_gis(&json, now_unix, response.status)
    })();
    Ok(result.unwrap_or_else(|outcome| GisCatalogue {
        source: SOURCE_GIS,
        fetched_at_unix: now_unix,
        cameras: Vec::new(),
        rejected_features: 0,
        outcome,
    }))
}

fn failed(now: u64, status: u16, kind: SourceOutcomeKind, reason: &str) -> SourceExecutionOutcome {
    SourceExecutionOutcome::failed(SOURCE_GIS, now, kind, Some(status), reason)
}

fn point(value: &Value) -> Option<(f64, f64)> {
    if value.pointer("/geometry/type")?.as_str()? != "Point" {
        return None;
    }
    let coords = value.pointer("/geometry/coordinates")?.as_array()?;
    if coords.len() != 2 {
        return None;
    }
    let lon = coords[0].as_f64()?;
    let lat = coords[1].as_f64()?;
    (lat.is_finite()
        && lon.is_finite()
        && (-90.0..=90.0).contains(&lat)
        && (-180.0..=180.0).contains(&lon))
    .then_some((lat, lon))
}

fn bounded_text(value: Option<&Value>, length: usize) -> Option<String> {
    let s = value?.as_str()?.trim();
    (!s.is_empty() && s.len() <= length && !s.chars().any(char::is_control)).then(|| s.to_owned())
}

fn row(feature: &Value) -> Option<GisCamera> {
    if feature.get("type")?.as_str()? != "Feature" {
        return None;
    }
    let (latitude, longitude) = point(feature)?;
    let props = feature.get("properties")?;
    let id = props.get("camera_id")?.as_u64().filter(|id| *id > 0)?;
    Some(GisCamera {
        id,
        description: bounded_text(props.get("description"), 250)?,
        direction: bounded_text(props.get("direction"), 50),
        locality: bounded_text(props.get("locality"), 120),
        latitude,
        longitude,
    })
}

/// Parse a GIS catalogue requested with `outSR=4326&f=geojson`.
///
/// # Errors
/// A schema or cardinality violation; malformed individual features are counted.
pub fn parse_gis(
    json: &Value,
    now_unix: u64,
    status: u16,
) -> Result<GisCatalogue, SourceExecutionOutcome> {
    if json.get("type").and_then(Value::as_str) != Some("FeatureCollection") {
        return Err(failed(
            now_unix,
            status,
            SourceOutcomeKind::SchemaDrift,
            "GIS response is not a FeatureCollection",
        ));
    }
    let Some(features) = json.get("features").and_then(Value::as_array) else {
        return Err(failed(
            now_unix,
            status,
            SourceOutcomeKind::SchemaDrift,
            "GIS response has no features array",
        ));
    };
    if features.len() > MAX_CAMERAS {
        return Err(failed(
            now_unix,
            status,
            SourceOutcomeKind::ParserDrift,
            "GIS response contains more than 2000 features",
        ));
    }
    let mut ids = BTreeSet::new();
    let mut cameras = Vec::new();
    let mut rejected_features = 0;
    for feature in features {
        match row(feature) {
            Some(camera) if ids.insert(camera.id) => cameras.push(camera),
            _ => rejected_features += 1,
        }
    }
    cameras.sort_by_key(|camera| camera.id);
    let outcome = if cameras.is_empty() && !features.is_empty() {
        failed(
            now_unix,
            status,
            SourceOutcomeKind::SemanticDrift,
            "no GIS features survived validation",
        )
    } else if cameras.is_empty() {
        SourceExecutionOutcome::valid_zero(SOURCE_GIS, now_unix).with_http_status(status)
    } else {
        SourceExecutionOutcome::success(SOURCE_GIS, now_unix, cameras.len())
            .with_http_status(status)
    };
    let outcome = if rejected_features > 0 {
        outcome.with_detail(format!(
            "{rejected_features} of {} GIS camera features rejected",
            features.len()
        ))
    } else {
        outcome
    };
    Ok(GisCatalogue {
        source: SOURCE_GIS,
        fetched_at_unix: now_unix,
        cameras,
        rejected_features,
        outcome,
    })
}

fn metres(a: (f64, f64), b: (f64, f64)) -> f64 {
    crate::geohash::haversine_km(a.0, a.1, b.0, b.1) * 1_000.0
}

fn coordinates(camera: &Camera) -> (f64, f64) {
    (camera.latitude, camera.longitude)
}

/// Compare two accepted publisher reports. A failed source produces `None`, not
/// false zero coverage. Different IDs within 100m are review candidates only.
#[must_use]
pub fn reconcile(webcam: &Catalogue, gis: &GisCatalogue) -> Option<Reconciliation> {
    if !webcam.outcome.kind.is_accepted() || !gis.outcome.kind.is_accepted() {
        return None;
    }
    let primary: BTreeMap<u64, &Camera> = webcam.cameras.iter().map(|c| (c.id, c)).collect();
    let secondary: BTreeMap<u64, &GisCamera> = gis.cameras.iter().map(|c| (c.id, c)).collect();
    let webcam_only_ids: Vec<u64> = primary
        .keys()
        .filter(|id| !secondary.contains_key(*id))
        .copied()
        .collect();
    let gis_only_ids: Vec<u64> = secondary
        .keys()
        .filter(|id| !primary.contains_key(*id))
        .copied()
        .collect();
    let mut shared_ids = 0;
    let mut position_conflicts = Vec::new();
    let mut direction_conflicts = Vec::new();
    for (id, one) in &primary {
        if let Some(two) = secondary.get(id) {
            shared_ids += 1;
            let separation = metres(coordinates(one), (two.latitude, two.longitude));
            if separation > 100.0 {
                position_conflicts.push(PositionConflict {
                    id: *id,
                    separation_metres: separation,
                    webcam_description: one.description.clone(),
                    gis_description: two.description.clone(),
                    webcam_latitude: one.latitude,
                    webcam_longitude: one.longitude,
                    gis_latitude: two.latitude,
                    gis_longitude: two.longitude,
                });
            }
            if let Some(direction) = &two.direction {
                if !direction.eq_ignore_ascii_case(&one.direction) {
                    direction_conflicts.push(DirectionConflict {
                        id: *id,
                        webcam_direction: one.direction.clone(),
                        gis_direction: direction.clone(),
                    });
                }
            }
        }
    }
    // Bound the cross-product to 256 x 256 and emit at most 64 candidate links.
    // Only one nearest GIS-only candidate per webcam-only record.
    let mut spatial_candidates = Vec::new();
    for id in webcam_only_ids.iter().take(256) {
        let one = primary[id];
        let nearest = gis_only_ids
            .iter()
            .take(256)
            .filter_map(|other_id| {
                let other = secondary[other_id];
                // Cheap rectangular prefilter before trigonometry.
                if (one.latitude - other.latitude).abs() > 0.002
                    || (one.longitude - other.longitude).abs() > 0.002
                {
                    return None;
                }
                let distance = metres(coordinates(one), (other.latitude, other.longitude));
                (distance <= 100.0).then_some((*other_id, distance))
            })
            .min_by(|a, b| a.1.total_cmp(&b.1).then(a.0.cmp(&b.0)));
        if let Some((gis_id, separation_metres)) = nearest {
            spatial_candidates.push(SpatialCandidate {
                webcam_id: *id,
                gis_id,
                separation_metres,
                relation: "nearby_different_id_candidate_not_identity",
            });
        }
    }
    let candidate_search_truncated =
        webcam_only_ids.len() > 256 || gis_only_ids.len() > 256 || spatial_candidates.len() > 64;
    spatial_candidates.truncate(64);
    Some(Reconciliation {
        webcam_count: primary.len(),
        gis_count: secondary.len(),
        shared_ids,
        webcam_only_ids,
        gis_only_ids,
        position_conflicts,
        direction_conflicts,
        spatial_candidates,
        candidate_search_truncated,
        publisher_families: 1,
        evidence_role: "same_publisher_catalogue_consistency_not_independent_corroboration",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn gis(ids: &[u64]) -> GisCatalogue {
        let features: Vec<Value> = ids
            .iter()
            .map(|id| json!({
                "type":"Feature",
                "geometry":{"type":"Point","coordinates":[153.008_697_5,-27.555_179_6]},
                "properties":{"camera_id":id,"description":"Sample camera","direction":"North","locality":"Archerfield"}
            }))
            .collect();
        parse_gis(
            &json!({"type":"FeatureCollection","features":features}),
            10,
            200,
        )
        .expect("GIS fixture")
    }

    fn camera(id: u64) -> Camera {
        Camera {
            id,
            description: "Sample camera".into(),
            direction: "North".into(),
            district: "Metropolitan".into(),
            locality: "Archerfield".into(),
            postcode: "4108".into(),
            latitude: -27.555_179_6,
            longitude: 153.008_697_5,
            metadata_url: format!("https://api.qldtraffic.qld.gov.au/v1/webcams/{id}"),
            image_url: "https://cameras.qldtraffic.qld.gov.au/Metropolitan/test.jpg".into(),
            image_sourced_from: None,
            is_custom: None,
            extra_info: None,
        }
    }

    fn webcam(ids: &[u64]) -> Catalogue {
        Catalogue {
            source: super::super::SOURCE,
            fetched_at_unix: 10,
            cameras: ids.iter().map(|id| camera(*id)).collect(),
            rejected_features: 0,
            outcome: SourceExecutionOutcome::success(super::super::SOURCE, 10, ids.len()),
        }
    }

    #[test]
    fn overlap_is_distinct_from_total_difference() {
        let r = reconcile(&webcam(&[1, 2, 3]), &gis(&[2, 3, 4, 5])).expect("both responded");
        assert_eq!(r.shared_ids, 2);
        assert_eq!(r.webcam_only_ids, vec![1]);
        assert_eq!(r.gis_only_ids, vec![4, 5]);
        assert_eq!(r.publisher_families, 1);
        assert_eq!(r.spatial_candidates.len(), 1);
        assert_ne!(
            r.spatial_candidates[0].webcam_id,
            r.spatial_candidates[0].gis_id
        );
    }

    #[test]
    fn malformed_or_duplicated_gis_id_is_not_accepted() {
        let j = json!({"type":"FeatureCollection","features":[
            {"type":"Feature","geometry":{"type":"Point","coordinates":[150.0,-27.0]},
             "properties":{"camera_id":12,"description":"A"}},
            {"type":"Feature","geometry":{"type":"Point","coordinates":[150.0,-27.0]},
             "properties":{"camera_id":12,"description":"B"}},
            {"type":"Feature","geometry":{"type":"Point","coordinates":[1000,-27]},
             "properties":{"camera_id":13,"description":"C"}}
        ]});
        let r = parse_gis(&j, 10, 200).expect("some usable rows");
        assert_eq!(r.cameras.len(), 1);
        assert_eq!(r.rejected_features, 2);
    }

    #[test]
    fn unresolved_source_failure_never_becomes_no_camera_claim() {
        let mut g = gis(&[2]);
        g.outcome = SourceExecutionOutcome::failed(
            SOURCE_GIS,
            10,
            SourceOutcomeKind::RateLimited,
            Some(429),
            "provider limit",
        );
        assert!(reconcile(&webcam(&[1]), &g).is_none());
        assert!(parse_gis(&json!({"error":{"code":403}}), 10, 200).is_err());
    }

    #[test]
    fn position_conflict_keeps_shared_id_without_claiming_equivalent_position() {
        let mut g = gis(&[1]);
        g.cameras[0].latitude += 0.02;
        let r = reconcile(&webcam(&[1]), &g).expect("accepted sources");
        assert_eq!(r.shared_ids, 1);
        assert_eq!(r.position_conflicts.len(), 1);
    }

    #[test]
    fn opposite_orientation_is_a_separate_source_conflict() {
        let mut g = gis(&[1]);
        g.cameras[0].direction = Some("South".into());
        let r = reconcile(&webcam(&[1]), &g).expect("accepted sources");
        assert_eq!(r.shared_ids, 1);
        assert_eq!(r.direction_conflicts.len(), 1);
        assert_eq!(r.direction_conflicts[0].webcam_direction, "North");
        assert_eq!(r.direction_conflicts[0].gis_direction, "South");
        assert!(r.position_conflicts.is_empty());
    }

    #[test]
    fn empty_is_only_valid_with_explicit_empty_feature_collection() {
        assert_eq!(
            parse_gis(&json!({"type":"FeatureCollection","features":[]}), 10, 200)
                .expect("empty collection")
                .outcome
                .kind,
            SourceOutcomeKind::ValidZero
        );
        assert!(parse_gis(&json!({"features":[]}), 10, 200).is_err());
    }
}
