//! Import endpoints — WiGLE KML wardriving ingestion over HTTP.
//!
//! `POST /api/v1/import/kml` takes a raw KML body (the SPA's Import view posts
//! the file's text here), runs the **same** `util::kml::ingest` pipeline the
//! `hse import` CLI uses, persists a first-class `Scan` + entities, runs the
//! correlator, and returns the complete, transparent JSON — every parsed
//! record, every derived entity, every stat, every correlation.
//!
//! The body limit for this one route is raised in `routes.rs`
//! (`DefaultBodyLimit`) because real captures run to several MB, well past
//! axum's 2 MB default.

use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::json;
use tracing::info;

use super::handlers::{bad_request, internal_error};
use crate::api::AppState;
use crate::core::correlator::Correlator;
use crate::core::entity::{scan_id, unix_now};
use crate::core::scan::{Scan, ScanStatus, Target, TargetKind};

/// `POST /api/v1/import/kml` — ingest a WiGLE KML export.
pub async fn import_kml(State(s): State<Arc<AppState>>, body: String) -> impl IntoResponse {
    if body.trim().is_empty() {
        return bad_request("empty body — POST the raw KML document");
    }
    if !body.contains("<kml") && !body.contains("<Placemark") {
        return bad_request("body does not look like KML (no <kml>/<Placemark>)");
    }

    // Each upload is a distinct, timestamped observation event (same model as a
    // scan — `scan_id` mixes in the clock), so re-uploading a capture of the
    // same area corroborates rather than silently overwrites. `ingest` parses
    // once.
    let sid = scan_id("kml", "web-upload");
    let ingest = crate::util::kml::ingest(&body, "web-upload", &sid);

    let Some(centroid) = ingest.centroid else {
        return bad_request("no usable coordinates found in KML");
    };

    let target = Target::new(
        TargetKind::Coordinates,
        format!("{:.6},{:.6}", centroid.lat, centroid.lon),
    );
    let now = unix_now();
    let mut scan = Scan::new(sid.clone(), target);
    scan.status = ScanStatus::Complete;
    scan.started_at = now;
    scan.finished_at = Some(now);
    scan.entity_count = ingest.entities.len();

    if let Err(e) = s.store.upsert_scan(&scan) {
        return internal_error(&e);
    }
    let persisted = match s.store.upsert_entities_batch(&ingest.entities) {
        Ok(n) => n,
        Err(e) => return internal_error(&e),
    };
    let correlations = Correlator::new(Arc::clone(&s.store))
        .run(&sid)
        .unwrap_or_default();

    info!(
        scan_id = %sid,
        records = ingest.record_count,
        entities = persisted,
        correlations = correlations.len(),
        "kml import complete"
    );

    // Full transparent payload — augment the serialised ingest with the
    // persistence facts, the persisted scan, and the correlations.
    let mut v = serde_json::to_value(&ingest).unwrap_or(serde_json::Value::Null);
    if let Some(obj) = v.as_object_mut() {
        obj.insert("format".into(), json!("wigle-kml"));
        obj.insert("source_file".into(), json!("web-upload"));
        obj.insert("scan_id".into(), json!(sid));
        obj.insert(
            "persisted".into(),
            json!({
                "scan": true,
                "entities": persisted,
                "correlations": correlations.len(),
            }),
        );
        obj.insert(
            "scan".into(),
            serde_json::to_value(&scan).unwrap_or(serde_json::Value::Null),
        );
        obj.insert(
            "correlations".into(),
            serde_json::to_value(&correlations).unwrap_or(serde_json::Value::Null),
        );
    }

    (StatusCode::OK, Json(v)).into_response()
}
