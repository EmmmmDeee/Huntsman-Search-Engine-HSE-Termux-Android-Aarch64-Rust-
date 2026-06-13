//! Export and download handlers for a scan — CSV, JSON report, GEXF, debug
//! bundle — plus the pure rendering functions shared with the CLI.
//!
//! The rendering functions (`entities_to_csv`, `build_scan_report`,
//! `extract_au_location_fix`) are `pub(crate)` so `cli::export` can reuse them
//! and produce byte-identical output to the HTTP endpoints.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;

use super::handlers::{internal_error, not_found};
use super::scan_handlers::{scan_missing, wants_candidates};
use crate::api::AppState;

pub async fn scan_entities_csv(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = scan_missing(&s, &id) {
        return resp;
    }
    let entities = match s.store.entities_for_scan(&id) {
        Ok(es) => es,
        Err(e) => return internal_error(&e),
    };
    download_response(
        entities_to_csv(&entities),
        "text/csv; charset=utf-8",
        &id,
        "csv",
    )
}

/// Canonical CSV rendering for a scan's entities. Shared by the HTTP
/// endpoint `/api/v1/scans/{id}/entities.csv` and the `hse export
/// --format csv` CLI subcommand so both produce byte-identical
/// output — operators piping the two interchangeably can rely on
/// the column shape staying in sync.
pub(crate) fn entities_to_csv(entities: &[crate::core::entity::Entity]) -> String {
    use std::fmt::Write as _;
    let mut body = String::with_capacity(192 + entities.len() * 192);
    // `evidence_urls` + `evidence` make every row self-verifiable: the operator
    // can follow the source links and read each module's finding without
    // reconstructing anything from the value alone.
    body.push_str("kind,value,raw_value,confidence,c_effective,corroboration,classification,observed_at,sources,evidence_urls,evidence,tags\n");
    for e in entities {
        let eff = e.c_effective();
        let tier = e.classify().to_string();
        let mut sources: Vec<&str> = e.evidence_sources().into_iter().collect();
        sources.sort_unstable();
        let sources = sources.join("|");
        let tags = e.tags.join("|");

        // Distinct full URLs across all evidence (the verifiable links), and a
        // per-source summary trail of what each module actually found.
        let mut urls: Vec<&str> = Vec::new();
        for ev in &e.evidence {
            for key in ["url", "source_url", "profile_url", "permalink"] {
                if let Some(u) = ev.attributes.get(key)
                    && !u.is_empty()
                    && !urls.contains(&u.as_str())
                {
                    urls.push(u.as_str());
                }
            }
        }
        let evidence_urls = urls.join(" | ");
        let evidence = e
            .evidence
            .iter()
            .map(|ev| format!("[{}] {}", ev.source, ev.summary))
            .collect::<Vec<_>>()
            .join(" || ");

        let _ = writeln!(
            body,
            "{},{},{},{:.3},{:.3},{},{},{},{},{},{},{}",
            csv_escape(&e.kind.to_string()),
            csv_escape(&e.value),
            csv_escape(&e.raw_value),
            e.confidence,
            eff,
            e.corroboration,
            tier,
            e.observed_at,
            csv_escape(&sources),
            csv_escape(&evidence_urls),
            csv_escape(&evidence),
            csv_escape(&tags),
        );
    }
    body
}

pub async fn scan_report_json(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    match build_scan_report(&*s.store, &id, wants_candidates(&params)) {
        Ok(Some(report)) => {
            let body = serde_json::to_string_pretty(&report).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "failed to serialize scan report to JSON string");
                "{}".into()
            });
            download_response(body, "application/json; charset=utf-8", &id, "json")
        }
        Ok(None) => not_found(),
        Err(e) => internal_error(&e),
    }
}

/// Canonical scan-report JSON envelope. Shared by the HTTP endpoint
/// `/api/v1/scans/{id}/report.json` and the `hse export --format
/// report` CLI subcommand so the on-device and over-the-wire
/// dossiers stay byte-equivalent.
///
/// Generic over the storage handle: the HTTP layer hands in an
/// `Arc<dyn StoragePort>` (via `&*s.store`), the CLI hands in a
/// `&Store` directly. Both expose `get_scan / entities_for_scan /
/// correlations_for_scan` with matching signatures.
///
/// Returns `Ok(None)` when no scan with that id exists, so callers
/// can map straight to a 404. Bubbles storage errors otherwise.
pub(crate) fn build_scan_report(
    store: &dyn crate::core::port::StoragePort,
    scan_id: &str,
    include_candidates: bool,
) -> crate::core::error::Result<Option<serde_json::Value>> {
    let Some(scan) = store.get_scan(scan_id)? else {
        return Ok(None);
    };
    let mut entities = store.entities_for_scan(scan_id)?;
    // Quarantine in the dossier too: speculative `candidate` entities (the
    // non-target breach-dump rows) are hidden by default so the report reads
    // as the target's confirmed footprint. `include_candidates=true` returns
    // the full set for investigation.
    if !include_candidates {
        entities.retain(|e| !e.has_tag(crate::core::tags::CANDIDATE));
    }
    let correlations = store.correlations_for_scan(scan_id)?;
    let best_location = extract_au_location_fix(&correlations);
    Ok(Some(json!({
        "scan": scan,
        "entities": entities,
        "entity_count": entities.len(),
        "correlations": correlations,
        "correlation_count": correlations.len(),
        // Best AU geolocation fix synthesised by AU-059 cross-seed geo synergy.
        // `null` when no AU-059 fired; present with full structured fields when
        // ≥2 orthogonal AU source classes converged on a location.
        "best_location": best_location,
        // DETERMINISM: `exported_at` is the SOLE intentional source of
        // non-determinism in any export. It is meaningful here — report.json is a
        // point-in-time snapshot whose "when was this pulled" is part of its
        // value — and is the documented exception to byte-reproducibility. The
        // diffable/reproducible artifacts are the debug bundle (no timestamp,
        // proven byte-stable) and entity-level `scan_diff`. The
        // `export_formats_determinism_audit` test pins that NO OTHER field of the
        // report varies across renders, so any newly-introduced non-determinism
        // fails CI rather than silently breaking reproducibility.
        "exported_at": crate::core::entity::unix_now(),
    })))
}

/// Parse the structured geo-fix fields that AU-059 embeds in its description.
///
/// AU-059 description format:
/// `"N AU coordinate(s) from M orthogonal source class(es) [C1, C2] converge on
///  LAT,LON (geohash=GH, state=STATE); synergy confidence SC — MITRE T1591.001"`
///
/// Returns a JSON object `{lat, lon, geohash, state, synergy_confidence,
/// source_count, class_count, severity}` from the highest-rank AU-059 firing,
/// or `serde_json::Value::Null` when no AU-059 correlation exists for the scan.
pub(crate) fn extract_au_location_fix(
    correlations: &[crate::core::correlator::Correlation],
) -> serde_json::Value {
    let best = correlations
        .iter()
        .filter(|c| c.rule_id == "AU-059")
        .max_by(|a, b| {
            a.rank
                .partial_cmp(&b.rank)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    let Some(c) = best else {
        return serde_json::Value::Null;
    };
    let desc = &c.description;

    // source_count: first token before " AU coordinate"
    let source_count: Option<u32> = desc
        .split_once(" AU coordinate")
        .and_then(|(n, _)| n.trim().parse().ok());

    // class_count: token before " orthogonal source class"
    let class_count: Option<u32> = desc
        .split_once(" orthogonal source class")
        .and_then(|(pre, _)| pre.rsplit_once(' ').map(|(_, n)| n))
        .and_then(|n| n.parse().ok());

    // lat,lon: after "converge on "
    let (lat, lon) = desc
        .split_once("converge on ")
        .and_then(|(_, rest)| rest.split_once(' '))
        .and_then(|(coord, _)| coord.split_once(','))
        .and_then(|(la, lo)| {
            let la: f64 = la.parse().ok()?;
            let lo: f64 = lo.parse().ok()?;
            Some((la, lo))
        })
        .unwrap_or((0.0, 0.0));

    // geohash: between "geohash=" and ","
    let geohash = desc
        .split_once("geohash=")
        .and_then(|(_, rest)| rest.split_once(','))
        .map(|(gh, _)| gh.to_string())
        .unwrap_or_default();

    // state: between "state=" and ")"
    let state = desc
        .split_once("state=")
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(st, _)| st.to_string())
        .unwrap_or_default();

    // synergy_confidence: after "synergy confidence " and before " —"
    let synergy_confidence: f64 = desc
        .split_once("synergy confidence ")
        .and_then(|(_, rest)| rest.split_once(" —"))
        .and_then(|(sc, _)| sc.parse().ok())
        .unwrap_or(0.0);

    json!({
        "lat": lat,
        "lon": lon,
        "geohash": geohash,
        "state": state,
        "synergy_confidence": synergy_confidence,
        "severity": c.severity.as_canonical(),
        "rank": c.rank,
        "source_count": source_count,
        "class_count": class_count,
        "rule_id": "AU-059",
    })
}

pub async fn scan_export_gexf(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = scan_missing(&s, &id) {
        return resp;
    }
    let entities = match s.store.entities_for_scan(&id) {
        Ok(entities) => entities,
        Err(e) => return internal_error(&e),
    };
    let relations = match s.store.relations_for_scan(&id) {
        Ok(relations) => relations,
        Err(e) => return internal_error(&e),
    };
    let body = crate::core::gexf::entities_to_gexf(&entities, &relations, &id);
    download_response(body, "application/xml; charset=utf-8", &id, "gexf")
}

/// `GET /api/v1/scans/{id}/debug.txt` — the one-click debug bundle: the entire
/// scan state (every entity + evidence, relations, correlations, the complete
/// event sequence, and the scored self-audit with every weakness) in one
/// downloadable text file. The web "Debug bundle" button and the CLI
/// `hse export {id} --format debug` produce the same artifact.
pub async fn scan_debug_bundle(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = scan_missing(&s, &id) {
        return resp;
    }
    match crate::cli::export::render_debug_bundle(s.store.as_ref(), &id) {
        Ok(body) => download_response(body, "text/plain; charset=utf-8", &id, "debug.txt"),
        Err(e) => internal_error(&e),
    }
}

pub(crate) fn download_response(
    body: String,
    content_type: &'static str,
    scan_id: &str,
    ext: &str,
) -> axum::response::Response {
    let short_id: String = scan_id.chars().take(12).collect();
    let filename = format!("hse-{ext}-{short_id}.{ext}");
    let disposition = format!("attachment; filename=\"{filename}\"");
    let mut resp = (StatusCode::OK, body).into_response();
    let headers = resp.headers_mut();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static(content_type),
    );
    if let Ok(v) = axum::http::HeaderValue::from_str(&disposition) {
        headers.insert(axum::http::header::CONTENT_DISPOSITION, v);
    }
    resp
}

pub(crate) fn csv_escape(s: &str) -> String {
    // Formula-injection neutralization: a leading =/+/-/@/CR/TAB causes
    // Excel and LibreOffice to interpret the cell as a formula on file
    // open — a hostile API response with `first_name = "=cmd|'/c calc'!A1"`
    // could otherwise turn an exported scan CSV into RCE on the operator's
    // workstation. Prepend a single quote to defang per OWASP guidance.
    let needs_formula_guard = s
        .as_bytes()
        .first()
        .is_some_and(|b| matches!(*b, b'=' | b'+' | b'-' | b'@' | b'\t' | b'\r'));
    let body = if needs_formula_guard {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if body.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", body.replace('"', "\"\""))
    } else {
        body
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── build_scan_report ───────────────────────────────────────────────────

    #[test]
    fn report_hides_candidates_by_default_and_includes_on_request() {
        use crate::core::entity::{Entity, EntityKind};
        use crate::core::scan::{Scan, Target, TargetKind};
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("report.db");
        let store = crate::storage::Store::open(db.to_str().unwrap()).unwrap();
        let sid = "rep-scan";
        store
            .upsert_scan(&Scan::new(
                sid,
                Target::new(TargetKind::FullName, "Jordan Avery"),
            ))
            .unwrap();
        store
            .upsert_entity(&Entity::new(EntityKind::Email, "me@real.com", 0.85, sid))
            .unwrap();
        let mut candidate = Entity::new(EntityKind::Email, "stranger@bank.com", 0.25, sid);
        candidate.tag(crate::core::tags::CANDIDATE);
        store.upsert_entity(&candidate).unwrap();

        let port = &store as &dyn crate::core::port::StoragePort;
        let default = build_scan_report(port, sid, false).unwrap().unwrap();
        assert_eq!(
            default["entity_count"].as_u64(),
            Some(1),
            "default report hides the candidate"
        );
        let full = build_scan_report(port, sid, true).unwrap().unwrap();
        assert_eq!(
            full["entity_count"].as_u64(),
            Some(2),
            "include_candidates returns the full set"
        );
    }

    // ── entities_to_csv ─────────────────────────────────────────────────────

    #[test]
    fn entities_to_csv_assembles_header_and_escaped_rows() {
        use crate::core::entity::{Entity, EntityKind};

        // Empty input still emits exactly the column header — export consumers
        // (the SPA download button, external tooling) parse this header row.
        assert_eq!(
            entities_to_csv(&[]).trim_end(),
            "kind,value,raw_value,confidence,c_effective,corroboration,classification,observed_at,sources,evidence_urls,evidence,tags"
        );

        let mut e = Entity::new(EntityKind::Email, "a@b.com", 0.60, "src");
        e.tag("plain");
        e.tag("has,comma"); // a comma inside an assembled field must be quoted
        let csv = entities_to_csv(&[e]);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2, "header + exactly one row per entity");

        let row = lines[1];
        // Column order + 3-dp numeric formatting (kind,value,raw_value,conf,c_eff,…).
        assert!(
            row.starts_with("email,a@b.com,a@b.com,0.600,0.600,"),
            "field order / numeric formatting drifted: {row}"
        );
        // `tags` is the final column; the comma-bearing tag is RFC-4180 quoted,
        // proving entities_to_csv routes assembled fields through csv_escape.
        assert!(
            row.ends_with(",\"plain|has,comma\""),
            "tags column not escaped through csv_escape: {row}"
        );
    }

    #[test]
    fn csv_carries_verifiable_evidence_urls_and_summaries() {
        use crate::core::entity::{Entity, EntityKind, Evidence};
        let mut e = Entity::new(EntityKind::Username, "jordanavery", 0.80, "src");
        e.add_evidence(
            Evidence::new("username_search", "@jordanavery has a profile on GitHub")
                .with_attr("url", "https://github.com/jordanavery"),
        );
        e.add_evidence(
            Evidence::new("github_user", "12 public events")
                .with_attr("profile_url", "https://github.com/jordanavery?tab=overview"),
        );
        let csv = entities_to_csv(&[e]);
        let row = csv.lines().nth(1).unwrap();
        assert!(
            row.contains("https://github.com/jordanavery"),
            "evidence URL missing: {row}"
        );
        assert!(
            row.contains("?tab=overview"),
            "second evidence URL missing: {row}"
        );
        assert!(
            row.contains("[username_search]") && row.contains("[github_user]"),
            "evidence trail missing: {row}"
        );
        assert!(
            row.contains("has a profile on GitHub"),
            "evidence summary missing: {row}"
        );
    }

    // ── AU-059 best_location emit→extract contract ───────────────────────────

    /// Build a tagged AU `Coordinates` entity for a given source, mirroring the
    /// correlator's own fixture so the convergence path is identical.
    fn au_sighting(
        value: &str,
        conf: f64,
        source: &str,
        state: &str,
    ) -> crate::core::entity::Entity {
        use crate::core::entity::{Entity, EntityKind, Evidence};
        let mut e = Entity::new(EntityKind::Coordinates, value, conf, "s");
        e.tag(format!("au-state:{state}"));
        e.tag("country:AU");
        e.add_evidence(Evidence::new(source, "geo sighting"));
        e
    }

    #[test]
    fn extract_au_location_fix_round_trips_every_field() {
        let ents = vec![
            au_sighting("-33.8688,151.2093", 0.80, "abn_lookup", "NSW"),
            au_sighting("-33.8700,151.2100", 0.70, "exif_geo", "NSW"),
        ];
        let corrs = crate::core::correlator::correlate_entities(&ents, "s");
        assert!(
            corrs.iter().any(|c| c.rule_id == "AU-059"),
            "fixture must produce an AU-059 firing"
        );

        let fix = extract_au_location_fix(&corrs);
        assert!(fix.is_object(), "fix must be a structured object, got {fix}");
        assert_eq!(fix["state"], "NSW");
        assert_eq!(fix["rule_id"], "AU-059");
        let lat = fix["lat"].as_f64().unwrap();
        let lon = fix["lon"].as_f64().unwrap();
        assert!((-34.0..-33.0).contains(&lat), "lat off Sydney: {lat}");
        assert!((150.0..152.0).contains(&lon), "lon off Sydney: {lon}");
        assert!(
            !fix["geohash"].as_str().unwrap().is_empty(),
            "geohash empty"
        );
        let sc = fix["synergy_confidence"].as_f64().unwrap();
        assert!(
            (0.0..=0.97).contains(&sc) && sc > 0.0,
            "synergy_conf range: {sc}"
        );
        assert_eq!(fix["class_count"], 2);
        assert!(fix["source_count"].as_u64().unwrap() >= 2);
        assert_eq!(fix["severity"], "medium", "2 classes ⇒ medium");
    }

    #[test]
    fn extract_au_location_fix_is_null_without_au_059() {
        let ents = vec![
            au_sighting("-33.8688,151.2093", 0.80, "abn_lookup", "NSW"),
            au_sighting("-33.8700,151.2100", 0.75, "acnc_charities", "NSW"),
        ];
        let corrs = crate::core::correlator::correlate_entities(&ents, "s");
        assert_eq!(extract_au_location_fix(&corrs), serde_json::Value::Null);
        assert_eq!(extract_au_location_fix(&[]), serde_json::Value::Null);
    }

    #[test]
    fn extract_au_location_fix_picks_highest_rank_when_several() {
        use crate::core::correlator::{Correlation, Severity};
        let mut low = Correlation::new(
            "AU-059",
            "Cross-seed geographic synergy (orthogonal-class fix)",
            Severity::Medium,
            "2 AU coordinate(s) from 2 orthogonal source class(es) [Registry, Social] \
             converge on -37.8136,144.9631 (geohash=r1r0fs, state=VIC); synergy confidence \
             0.55 — MITRE T1591.001"
                .into(),
            vec!["a".into(), "b".into()],
            "s",
            0,
        );
        low.rank = 1.1;
        let mut high = Correlation::new(
            "AU-059",
            "Cross-seed geographic synergy (orthogonal-class fix)",
            Severity::High,
            "3 AU coordinate(s) from 3 orthogonal source class(es) [PhotoGps, Registry, \
             Directory] converge on -33.8688,151.2093 (geohash=r3gx2f, state=NSW); synergy \
             confidence 0.81 — MITRE T1591.001"
                .into(),
            vec!["c".into(), "d".into(), "e".into()],
            "s",
            0,
        );
        high.rank = 2.7;

        let fix = extract_au_location_fix(&[low, high]);
        assert_eq!(fix["state"], "NSW", "must pick the higher-rank firing");
        assert_eq!(fix["class_count"], 3);
        assert_eq!(fix["source_count"], 3);
        assert_eq!(fix["severity"], "high");
        assert!((fix["synergy_confidence"].as_f64().unwrap() - 0.81).abs() < 1e-9);
        assert!((fix["lat"].as_f64().unwrap() - -33.8688).abs() < 1e-4);
    }
}
