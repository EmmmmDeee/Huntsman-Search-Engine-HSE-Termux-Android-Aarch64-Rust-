//! Read-only BSI-assurance and MITRE ATT&CK posture views for the Web UI.
//!
//! These serve the SAME evidence-derived data `hse assurance` / `hse bsi` /
//! `hse attack` print, over the SAME single authorities —
//! [`crate::core::assurance`] for controls, maturity, severity and the verify
//! verdict, and [`crate::modules::reconnaissance_coverage`] for ATT&CK reach.
//! Nothing here computes maturity, severity or coverage of its own, so the
//! browser can never disagree with the CLI, and a green cell in the Web UI
//! resolves to exactly the evidence the CLI would print for it.
//!
//! No endpoint emits a decorative compliance or ATT&CK score: the only numbers
//! are raw counts and a coverage fraction derived from real module capability.

use std::collections::HashMap;

use axum::{
    Json,
    extract::Query,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use crate::core::assurance::{Profile, findings, resolve_catalog, summarise, verify};
use crate::modules::{reconnaissance_coverage, technique_module_index};

/// `GET /api/v1/assurance[?profile=<name>]` — every catalogued control resolved
/// from its recorded evidence (state, A0–A6 level, graded severity), the open
/// findings worst-first, and the raw summary counts. `profile` accepts the same
/// names as `hse assurance --profile` (bare word, full `HSE-BSI-*` id, or the
/// `railway` cloud alias) through the one shared parser; an unknown value is a
/// 400 naming the valid names — never a silently empty table.
pub async fn assurance(Query(q): Query<HashMap<String, String>>) -> Response {
    let mut resolved = resolve_catalog();
    let mut profile_id: Option<&'static str> = None;
    if let Some(raw) = q.get("profile") {
        match Profile::parse(raw) {
            Some(p) => {
                resolved.retain(|r| r.control.profile == p);
                profile_id = Some(p.id());
            }
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": format!(
                            "unknown profile {raw:?}; valid: {}",
                            Profile::short_names().join(", ")
                        ),
                    })),
                )
                    .into_response();
            }
        }
    }
    let summary = summarise(&resolved);
    let open = findings(&resolved);
    Json(json!({
        "profile": profile_id,
        "controls": resolved,
        "findings": open,
        "summary": summary,
    }))
    .into_response()
}

/// `GET /api/v1/assurance/verify` — the real verification verdict over the whole
/// catalogue, recomputed from evidence on every call: it passes only when no
/// control has regressed and no High/Critical deficiency is open (Low/Medium
/// gaps are non-failing warnings). The same gate `hse bsi verify` exits
/// non-zero on.
pub async fn assurance_verify() -> Json<Value> {
    Json(json!({ "verdict": verify(&resolve_catalog()) }))
}

/// `GET /api/v1/attack` — HSE's registry-wide MITRE ATT&CK Reconnaissance
/// (TA0043) posture: catalogue version, the one tactic in scope, every covered
/// technique with the registered modules that are its evidence, the honest gaps,
/// and the coverage fraction. Collection reach, not detection effectiveness.
pub async fn attack() -> Json<Value> {
    let cov = reconnaissance_coverage();
    let idx = technique_module_index();
    let covered: Vec<Value> = cov
        .covered
        .iter()
        .map(|c| {
            json!({
                "id": c.technique.id,
                "name": c.technique.name,
                "modules": idx.get(c.technique.id),
            })
        })
        .collect();
    let gaps: Vec<Value> = cov
        .uncovered
        .iter()
        .map(|t| json!({ "id": t.id, "name": t.name }))
        .collect();
    Json(json!({
        "attack_version": crate::core::attack::ATTACK_VERSION,
        "tactic_id": cov.tactic_id,
        "tactic_name": cov.tactic_name,
        "techniques_total": cov.covered.len() + cov.uncovered.len(),
        "techniques_covered": cov.covered.len(),
        "coverage_fraction": cov.coverage_fraction,
        "covered": covered,
        "gaps": gaps,
    }))
}

/// `GET /api/v1/attack/navigator` — the same posture as a MITRE ATT&CK
/// Navigator layer, served as a download (`hse-attack-navigator.json`) so it
/// drops straight into the official Navigator.
pub async fn attack_navigator() -> Response {
    let layer = crate::core::attack::navigator_layer(
        &reconnaissance_coverage(),
        "HSE static Reconnaissance coverage",
    );
    (
        [(
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"hse-attack-navigator.json\"",
        )],
        Json(layer),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, routing::get};
    use tower::ServiceExt as _;

    /// The four read-only posture routes, exactly as `routes/mod.rs` mounts
    /// them under `/api/v1` — stateless, so no `AppState` is needed.
    fn app() -> Router {
        Router::new()
            .route("/assurance", get(assurance))
            .route("/assurance/verify", get(assurance_verify))
            .route("/attack", get(attack))
            .route("/attack/navigator", get(attack_navigator))
    }

    async fn get_json(uri: &str) -> (StatusCode, Value) {
        let resp = app()
            .oneshot(
                axum::http::Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router must respond");
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
            .await
            .expect("readable body");
        let v: Value = serde_json::from_slice(&bytes).expect("JSON body");
        (status, v)
    }

    #[tokio::test]
    async fn assurance_serves_every_control_with_its_evidence_and_never_claims_a5_or_a6() {
        let (st, v) = get_json("/assurance").await;
        assert_eq!(st, StatusCode::OK);
        let controls = v["controls"].as_array().expect("controls array");
        assert!(!controls.is_empty());
        assert_eq!(
            v["summary"]["total"].as_u64().unwrap() as usize,
            controls.len()
        );
        for c in controls {
            // Drillable: every control carries its evidence list.
            assert!(c["control"]["evidence"].is_array());
            // Honest: the static catalogue can never claim runtime-observed or
            // externally-assured maturity.
            let state = c["state"].as_str().unwrap();
            assert_ne!(state, "OBSERVED");
            assert_ne!(state, "ASSURED");
        }
        assert_eq!(v["profile"], Value::Null, "no filter → no profile echoed");
    }

    #[tokio::test]
    async fn assurance_profile_filter_uses_the_shared_parser_including_the_railway_alias() {
        let (st, v) = get_json("/assurance?profile=android").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["profile"], "HSE-BSI-ANDROID");
        for c in v["controls"].as_array().unwrap() {
            assert_eq!(c["control"]["profile"], "android");
        }
        // `railway` is the cloud deployment — the same alias the CLI accepts,
        // through the same parser.
        let (st, v) = get_json("/assurance?profile=railway").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["profile"], "HSE-BSI-CLOUD");
    }

    #[tokio::test]
    async fn assurance_unknown_profile_is_a_400_naming_the_valid_names_not_an_empty_table() {
        let (st, v) = get_json("/assurance?profile=bogus").await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let err = v["error"].as_str().unwrap();
        assert!(err.contains("unknown profile"), "{err}");
        assert!(
            err.contains("android"),
            "must name the valid profiles: {err}"
        );
    }

    #[tokio::test]
    async fn assurance_verify_recomputes_the_gate_and_passes_on_the_honest_catalogue() {
        let (st, v) = get_json("/assurance/verify").await;
        assert_eq!(st, StatusCode::OK);
        let vd = &v["verdict"];
        assert_eq!(
            vd["ok"], true,
            "honest catalogue: no regressions, no High/Critical"
        );
        assert!(vd["regressions"].as_array().unwrap().is_empty());
        assert!(vd["blocking"].as_array().unwrap().is_empty());
        assert!(vd["summary"]["total"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn attack_reports_registry_derived_reconnaissance_coverage_honestly() {
        let (st, v) = get_json("/attack").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["attack_version"], crate::core::attack::ATTACK_VERSION);
        assert_eq!(v["tactic_id"], "TA0043");
        let covered = v["covered"].as_array().unwrap();
        let gaps = v["gaps"].as_array().unwrap();
        let total = v["techniques_total"].as_u64().unwrap() as usize;
        assert!(!covered.is_empty(), "the registry covers real techniques");
        assert_eq!(
            covered.len() + gaps.len(),
            total,
            "covered + gaps == the whole TA0043 slice"
        );
        let f = v["coverage_fraction"].as_f64().unwrap();
        assert!(f > 0.0 && f <= 1.0, "fraction {f} out of range");
        // Every covered technique either names its evidence modules or is an
        // entity/relation mapping (null) — never a fabricated module list.
        for c in covered {
            assert!(
                c["modules"].is_null() || c["modules"].as_array().is_some_and(|m| !m.is_empty())
            );
        }
    }

    #[tokio::test]
    async fn attack_navigator_is_a_downloadable_layer_pinned_to_the_catalogue_major() {
        let resp = app()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/attack/navigator")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let cd = resp
            .headers()
            .get(header::CONTENT_DISPOSITION)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        assert!(
            cd.contains("hse-attack-navigator.json"),
            "served as a download: {cd}"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap();
        let layer: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            layer["versions"]["attack"],
            crate::core::attack::attack_spec_major()
        );
        assert!(
            layer["techniques"]
                .as_array()
                .is_some_and(|t| !t.is_empty())
        );
    }
}
