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

/// `GET /api/v1/scans/{id}/attack-navigator.json` — a MITRE ATT&CK Navigator
/// layer of the Reconnaissance (TA0043) techniques the scan exercised. Same
/// artifact as `hse export {id} --format navigator` (one shared renderer, so
/// CLI and web can't diverge); the web UI's "ATT&CK layer" button downloads it
/// for import into the ATT&CK Navigator.
pub async fn scan_export_attack_navigator(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = scan_missing(&s, &id) {
        return resp;
    }
    match crate::cli::export::render_attack_layer(s.store.as_ref(), &id) {
        Ok(body) => download_named(
            body,
            "application/json; charset=utf-8",
            &id,
            "attack-navigator",
            "json",
        ),
        Err(e) => internal_error(&e),
    }
}

/// `GET /api/v1/scans/{id}/attack-coverage.json` — the scan's MITRE ATT&CK
/// Reconnaissance (TA0043) **assessment**: the catalogued techniques split into
/// those the collection `covered` and the `gaps` it missed, plus a coverage
/// percentage. Returned **inline** (not a download) so the web UI renders it as
/// a live panel. Same coverage reducer as the report / Navigator-layer views,
/// so the figures never diverge.
pub async fn scan_attack_coverage(
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
    let module_sources = crate::core::entity::evidence_sources(&entities);
    let covered = crate::modules::reconnaissance_coverage(module_sources.iter().copied());
    let assessment = crate::core::attack::Assessment::from_covered(covered);

    // Reverse index (technique → implementing modules), used twice: a covered
    // technique lists the modules in THIS scan that exercised it (index ∩ the
    // scan's evidence sources); a gap lists the idle modules that would close it
    // (the full registry list) — turning the assessment into next-best-action.
    let index = crate::modules::technique_module_index();
    let covered_json: Vec<_> = assessment
        .covered
        .iter()
        .map(|t| {
            let by: Vec<&str> = index
                .get(t.id)
                .into_iter()
                .flatten()
                .filter(|m| module_sources.contains(*m))
                .copied()
                .collect();
            json!({ "id": t.id, "name": t.name, "modules": by })
        })
        .collect();
    let gaps_json: Vec<_> = assessment
        .gaps
        .iter()
        .map(|t| {
            let by = index.get(t.id).cloned().unwrap_or_default();
            json!({ "id": t.id, "name": t.name, "modules": by })
        })
        .collect();

    let payload = json!({
        "scan_id": id,
        "tactic": crate::core::attack::TACTIC_NAME,
        "tactic_id": crate::core::attack::TACTIC_ID,
        "coverage_pct": assessment.coverage_pct(),
        "covered_count": assessment.covered.len(),
        "total": assessment.covered.len() + assessment.gaps.len(),
        "covered": covered_json,
        "gaps": gaps_json,
    });
    let body = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".into());
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )],
        body,
    )
        .into_response()
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
    // Label and file extension coincide for the simple formats (gexf, debug.txt).
    download_named(body, content_type, scan_id, ext, ext)
}

/// As [`download_response`], but with the descriptive name label and the file
/// extension specified separately — for artifacts whose canonical extension
/// differs from their label (e.g. an ATT&CK Navigator layer: label
/// `attack-navigator`, extension `json`).
pub(crate) fn download_named(
    body: String,
    content_type: &'static str,
    scan_id: &str,
    label: &str,
    extension: &str,
) -> axum::response::Response {
    let short_id: String = scan_id.chars().take(12).collect();
    let filename = format!("hse-{label}-{short_id}.{extension}");
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
    include!("tests.rs");
}
