//! Read-only BSI-assurance and MITRE ATT&CK posture views for the Web UI.
//!
//! These serve the SAME evidence-derived data `hse assurance` / `hse bsi` /
//! `hse attack` print, over the SAME single authorities —
//! [`crate::core::assurance`] for controls, maturity, severity and the verify
//! verdict, and [`crate::modules::reconnaissance_coverage`] for raw ATT&CK reach.
//! Hierarchy-aware ATT&CK scoring is the shared
//! [`crate::core::attack_reporting`] projection used by the CLI too.
//!
//! No endpoint emits a decorative compliance or ATT&CK score: the only numbers
//! are raw counts and a coverage fraction derived from real module capability.

use std::collections::HashMap;

use axum::{
    Json,
    extract::Query,
    http::header,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use crate::core::assurance::{Profile, continuity, findings, resolve_catalog, summarise, verify};
use crate::core::attack_reporting::hierarchy_coverage;
use crate::modules::{reconnaissance_coverage, technique_module_index};

use super::handlers::bad_request;

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
                return bad_request(format!(
                    "unknown profile {raw:?}; valid: {}",
                    Profile::short_names().join(", ")
                ));
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
/// (TA0043) posture. The scored denominator is the set of independent leaf
/// capabilities; parent techniques with children are roll-ups and therefore do
/// not double-count their families. Raw parent + sub-technique claims remain
/// available as `direct_claims` / `attack_objects_*` for provenance.
pub async fn attack() -> Json<Value> {
    let raw = reconnaissance_coverage();
    let report = hierarchy_coverage(&raw);
    let idx = technique_module_index();

    let covered: Vec<Value> = report
        .covered_leaves
        .iter()
        .map(|technique| {
            json!({
                "id": technique.id,
                "name": technique.name,
                "modules": idx.get(technique.id),
            })
        })
        .collect();
    let gaps: Vec<Value> = report
        .uncovered_leaves
        .iter()
        .map(|technique| json!({ "id": technique.id, "name": technique.name }))
        .collect();
    let capability_gaps: Vec<Value> = report
        .capability_gaps
        .iter()
        .map(|technique| json!({ "id": technique.id, "name": technique.name }))
        .collect();
    let intentional_exclusions: Vec<Value> = report
        .intentional_exclusions
        .iter()
        .map(|technique| json!({ "id": technique.id, "name": technique.name }))
        .collect();
    let direct_claims: Vec<Value> = raw
        .covered
        .iter()
        .map(|covered| {
            json!({
                "id": covered.technique.id,
                "name": covered.technique.name,
                "modules": idx.get(covered.technique.id),
            })
        })
        .collect();

    Json(json!({
        "attack_version": crate::core::attack::ATTACK_VERSION,
        "tactic_id": raw.tactic_id,
        "tactic_name": raw.tactic_name,
        "coverage_basis": report.coverage_basis,
        "techniques_total": report.leaf_techniques_total,
        "techniques_covered": report.leaf_techniques_covered,
        "leaf_techniques_total": report.leaf_techniques_total,
        "leaf_techniques_covered": report.leaf_techniques_covered,
        "coverage_fraction": report.coverage_fraction,
        "attack_objects_total": report.attack_objects_total,
        "attack_objects_covered": report.attack_objects_covered,
        "raw_object_coverage_fraction": raw.coverage_fraction,
        "covered": covered,
        "gaps": gaps,
        "capability_gaps": capability_gaps,
        "intentional_exclusions": intentional_exclusions,
        "parent_rollups": report.parent_rollups,
        "direct_claims": direct_claims,
    }))
}

/// `GET /api/v1/attack/navigator` — raw ATT&CK object claims as a Navigator
/// layer, served as a download (`hse-attack-navigator.json`). Navigator consumes
/// canonical ATT&CK IDs directly, so parent/child provenance remains untouched.
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

/// `GET /api/v1/assurance/continuity` — BSI 200-4 continuity per capability:
/// the faults in scope, the objectives (MTPD/RTO/RPO), degraded mode, fallback,
/// recovery procedure, the recovery tests that prove it, and the derived state
/// (`UNTESTED` / `TESTED` / `OBSERVED`), worst-first. Untested capabilities are
/// named in the summary rather than folded into a number.
pub async fn assurance_continuity() -> Json<Value> {
    let assessed = continuity::assess();
    let summary = continuity::summarise(&assessed);
    // Surface the human-readable RPO label (the CLI's `rpo.label()` authority)
    // alongside the machine enum, so the Web UI renders "previous binary" rather
    // than the serialized `previous-binary`. One label source, three consumers
    // (CLI, API, Web UI) — no per-surface transcription that could drift.
    let capabilities: Vec<Value> = assessed
        .iter()
        .map(|a| {
            let mut v = json!(a);
            if let Some(obj) = v.get_mut("objective").and_then(Value::as_object_mut) {
                obj.insert("rpo_label".into(), json!(a.objective.rpo.label()));
            }
            v
        })
        .collect();
    Json(json!({ "capabilities": capabilities, "summary": summary }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, http::StatusCode, routing::get};
    use tower::ServiceExt as _;

    /// The four read-only posture routes, exactly as `routes/mod.rs` mounts
    /// them under `/api/v1` — stateless, so no `AppState` is needed.
    fn app() -> Router {
        Router::new()
            .route("/assurance", get(assurance))
            .route("/assurance/verify", get(assurance_verify))
            .route("/assurance/continuity", get(assurance_continuity))
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
    async fn assurance_continuity_reports_per_capability_state_and_names_untested_gaps() {
        let (st, v) = get_json("/assurance/continuity").await;
        assert_eq!(st, StatusCode::OK);
        let caps = v["capabilities"].as_array().expect("capabilities array");
        assert!(!caps.is_empty());
        let s = &v["summary"];
        assert_eq!(s["total"].as_u64().unwrap() as usize, caps.len());
        // Honest: no runtime recovery is recorded, so nothing is OBSERVED, and
        // the untested capabilities are named — never hidden behind a count.
        assert_eq!(s["observed"], 0);
        let named = s["untested_capabilities"].as_array().unwrap();
        assert_eq!(named.len() as u64, s["untested"].as_u64().unwrap());
        for c in caps {
            assert!(c["objective"]["recovery_tests"].is_array());
            assert!(
                c["objective"]["faults"]
                    .as_array()
                    .is_some_and(|f| !f.is_empty())
            );
            // The human-readable RPO label is surfaced for the Web UI (the
            // CLI's `rpo.label()` authority), so the panel never shows the raw
            // `previous-binary` machine enum. Locked here so it can't regress.
            assert!(
                c["objective"]["rpo_label"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty() && !s.contains('-')),
                "each capability must carry a humanised rpo_label, got {:?}",
                c["objective"]["rpo_label"]
            );
        }
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
    async fn attack_reports_leaf_coverage_without_double_counting_parent_families() {
        let (st, v) = get_json("/attack").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["attack_version"], crate::core::attack::ATTACK_VERSION);
        assert_eq!(v["tactic_id"], "TA0043");
        assert_eq!(v["coverage_basis"], "leaf-techniques");
        assert_eq!(v["techniques_covered"], 27);
        assert_eq!(v["techniques_total"], 37);
        assert_eq!(v["attack_objects_covered"], 32);
        assert_eq!(v["attack_objects_total"], 46);

        let covered = v["covered"].as_array().unwrap();
        let gaps = v["gaps"].as_array().unwrap();
        assert_eq!(covered.len(), 27);
        assert_eq!(gaps.len(), 10);
        assert_eq!(covered.len() + gaps.len(), 37);
        assert_eq!(v["capability_gaps"].as_array().unwrap().len(), 4);
        assert_eq!(v["intentional_exclusions"].as_array().unwrap().len(), 6);

        let f = v["coverage_fraction"].as_f64().unwrap();
        assert!((f - 27.0 / 37.0).abs() < 1e-12, "unexpected fraction {f}");

        let gap_ids: Vec<&str> = gaps
            .iter()
            .map(|gap| gap["id"].as_str().unwrap())
            .collect();
        assert!(!gap_ids.contains(&"T1597"), "covered children make T1597 a roll-up, not a gap");
        assert!(gap_ids.contains(&"T1681"));

        let t1597 = v["parent_rollups"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == "T1597")
            .expect("T1597 roll-up");
        assert_eq!(t1597["covered_children"], 2);
        assert_eq!(t1597["total_children"], 2);
        assert_eq!(t1597["directly_covered"], false);

        // Every covered leaf either names its evidence modules or is an
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
