//! Export and download handlers for a scan — CSV, JSON report, GEXF, debug
//! bundle. HTTP transport and presentation ONLY: the canonical rendering
//! functions (`entities_to_csv`, `build_scan_report`, `extract_au_location_fix`,
//! `csv_escape`, `formula_guard`) live in [`crate::app::export`] — the shared
//! composition layer — so this module and the `hse export` CLI subcommand call
//! into the SAME implementation and stay byte-identical. This file owns only
//! the axum handlers, the download/attachment response plumbing, and the
//! customer-facing provider-name redaction (`redact` submodule, unchanged).

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use std::sync::Arc;

use super::handlers::{not_found, offload_store};
use super::scan_handlers::{scan_missing, wants_candidates, wants_infra};
use crate::api::AppState;

/// Genericise proprietary breach/intel source names in the shareable downloads
/// so a scan result handed to a customer never reveals the operator's providers.
mod redact;

pub async fn scan_entities_csv(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(resp) = scan_missing(&s, &id).await {
        return resp;
    }
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    let mut entities = match offload_store(move || store.entities_for_scan(&id2)).await {
        Ok(es) => es,
        Err(e) => return e,
    };
    // Quarantine by default (opt in with `?include_candidates=1`) — matches the
    // `/entities` JSON endpoint and `report.json` so the downloaded CSV is the
    // subject's confirmed footprint, not a foreign breach-victim list. Without
    // this the CSV silently contradicted the self-audit's "excluded from
    // export" promise and shipped hundreds of non-subject `candidate` rows.
    if !crate::api::scan_handlers::wants_candidates(&params) {
        entities.retain(|e| !e.has_tag(crate::core::tags::CANDIDATE));
    }
    // Redaction of the proprietary source names in the `sources` /
    // `corroborating_sources` columns is enforced by `download_response`.
    download_response(
        crate::app::export::entities_to_csv(&entities),
        "text/csv; charset=utf-8",
        &id,
        "csv",
        "csv",
    )
}

pub async fn scan_report_json(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    // Offload to a blocking thread: build_scan_report does 3 synchronous SQLite
    // reads + AU-location extraction and the pretty-JSON serialize is CPU-bound, so
    // running them inline would stall one of the ~2 async reactor workers (matches
    // scan_entities_csv / scan_export_gexf / scan_debug_bundle in this module).
    let (id2, store) = (id.clone(), Arc::clone(&s.store));
    let (cand, infra) = (wants_candidates(&params), wants_infra(&params));
    match offload_store(move || {
        crate::app::export::build_scan_report(store.as_ref(), &id2, cand, infra).map(|opt| {
            opt.map(|report| {
                serde_json::to_string_pretty(&report).unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "failed to serialize scan report to JSON string");
                    "{}".into()
                })
            })
        })
    })
    .await
    {
        Ok(Some(body)) => {
            download_response(body, "application/json; charset=utf-8", &id, "json", "json")
        }
        Ok(None) => not_found(),
        Err(e) => e,
    }
}

pub async fn scan_export_gexf(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(resp) = scan_missing(&s, &id).await {
        return resp;
    }
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    let (mut entities, relations) = match offload_store(move || {
        Ok((
            store.entities_for_scan(&id2)?,
            store.relations_for_scan(&id2)?,
        ))
    })
    .await
    {
        Ok(pair) => pair,
        Err(e) => return e,
    };
    // Quarantine candidates by default (opt in with `?include_candidates=1`) —
    // matches `scan_entities_csv`, `report.json`, and the CLI `render_gexf`, so
    // the graph export can't leak a foreign breach-victim list under the subject's
    // scan. The relation set stays full; `entities_to_gexf` drops any edge whose
    // endpoint is no longer a node, so filtering here cannot leave a dangling edge.
    if !wants_candidates(&params) {
        entities.retain(|e| !e.has_tag(crate::core::tags::CANDIDATE));
    }
    let body = crate::core::gexf::entities_to_gexf(&entities, &relations, &id);
    // Redaction of proprietary source names is enforced by `download_response`.
    download_response(body, "application/xml; charset=utf-8", &id, "gexf", "gexf")
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
    if let Some(resp) = scan_missing(&s, &id).await {
        return resp;
    }
    // Render off the async runtime: the debug bundle runs many queries, reads
    // the raw archive, and spawns `curl` — all blocking — so on the ~2-worker
    // reactor it would otherwise stall every concurrent request (this also moves
    // the blocking `curl` spawn off the async worker — PROBLEM_TREE T2.2).
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    match offload_store(move || crate::app::export::render_debug_bundle(store.as_ref(), &id2)).await
    {
        // Operator artifact (labelled "operator only" in the UI): the debug bundle
        // deliberately KEEPS the real provider names, so it opts out of the
        // default-safe redaction via `download_response_operator`.
        Ok(body) => {
            download_response_operator(body, "text/plain; charset=utf-8", &id, "debug", "txt")
        }
        Err(e) => e,
    }
}

/// `GET /api/v1/scans/{id}/events.log` — the complete, loss-less scan event
/// sequence alone (module start/done/error, entities found, expansion
/// ticks/stops, every admission/exclusion) as a per-type breakdown plus a
/// readable, aligned per-event timeline (`HH:MM:SS  category  glyph summary`,
/// matching the web "Scan Log" view) — everything the web "Scan Log" tab shows, as one downloadable
/// file, without the rest of the [`scan_debug_bundle`] dossier. `hse export
/// {id} --format events` produces the byte-identical body via
/// [`crate::app::export::render_event_log`].
pub async fn scan_events_log(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = scan_missing(&s, &id).await {
        return resp;
    }
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    match offload_store(move || store.events_for_scan(&id2)).await {
        // The event JSONL names the producing provider in module_start/done/error;
        // `download_response` redacts those proprietary source names for the
        // customer copy.
        Ok(events) => download_response(
            crate::app::export::render_event_log(&events),
            "text/plain; charset=utf-8",
            &id,
            "events",
            "log",
        ),
        Err(e) => e,
    }
}

/// Wrap an export `body` as a browser download: a `200` with the given
/// `content_type` and a `Content-Disposition: attachment` whose filename is
/// `hse-<stem>-<short-scan-id>.<ext>` (id truncated to 12 chars). Shared by the
/// CSV / JSON / GEXF / debug-bundle endpoints so every download names itself the
/// same way.
///
/// `stem` and `ext` are separate so the file *label* and its *extension* can
/// differ — e.g. the debug bundle wants `hse-debug-<id>.txt`, not the
/// double-suffixed `hse-debug.txt-<id>.debug.txt` an `ext`-only builder produced
/// when a caller passed `"debug.txt"` for both roles. For the CSV/JSON/GEXF
/// endpoints stem == ext, so their filenames are unchanged.
pub(crate) fn download_response(
    body: String,
    content_type: &'static str,
    scan_id: &str,
    stem: &str,
    ext: &str,
) -> axum::response::Response {
    // SHAREABLE scan download → genericise proprietary breach/intel source names
    // so the customer copy never reveals which providers the operator uses.
    // Enforced HERE, at the single scan-download choke point, rather than wrapped
    // around each format's body: every current serializer (CSV / report.json /
    // GEXF / events.log AND the MITRE navigator layer) and any format added later
    // is redacted by default. A download that must KEEP the real names (the
    // operator debug bundle) opts out via [`download_response_operator`], so
    // forgetting to redact defaults to the safe, customer-shareable behaviour.
    download_response_operator(
        redact::redact_sensitive_sources(&body),
        content_type,
        scan_id,
        stem,
        ext,
    )
}

/// Operator-only counterpart to [`download_response`] that KEEPS the real
/// provider names — the scan debug bundle, an explicit operator artifact labelled
/// "operator only" in the UI. Same `hse-<stem>-<short_id>.<ext>` naming; the only
/// difference is that it does NOT redact. Choosing this is a conscious opt-out of
/// the default-safe redaction, which is why it is a named function rather than a
/// bool flag.
pub(crate) fn download_response_operator(
    body: String,
    content_type: &'static str,
    scan_id: &str,
    stem: &str,
    ext: &str,
) -> axum::response::Response {
    let short_id: String = scan_id.chars().take(12).collect();
    attachment_response(body, content_type, &format!("hse-{stem}-{short_id}.{ext}"))
}

/// The single place a downloadable HTTP response is built: sets the content type
/// and a `Content-Disposition: attachment; filename="…"` so the browser saves a
/// file instead of rendering it inline. Every download surface routes through
/// here — the scan-scoped exports via [`download_response`] (which layers the
/// `hse-<stem>-<short_id>.<ext>` naming on top) AND the system-scoped logs /
/// debug bundle, which pass a timestamped `hse-…-<unix_ts>.<ext>` name directly.
/// Keeping one builder means the attachment header can never drift between the
/// two families again (they previously hand-rolled it independently).
pub(crate) fn attachment_response(
    body: String,
    content_type: &'static str,
    filename: &str,
) -> axum::response::Response {
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

/// `GET /api/v1/scans/{id}/batch.txt[?site=a,b&bare=1]` — the bulk-query list
/// `hse batch --scan-id` prints, as a download. An OPERATOR file: it names
/// the breach providers it is written for, by design, so it goes through
/// [`download_response_operator`] and is never a client deliverable.
pub async fn scan_batch_txt(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(resp) = super::scan_handlers::scan_missing(&s, &id).await {
        return resp;
    }
    let store = Arc::clone(&s.store);
    let sid = id.clone();
    let entities = match offload_store(move || store.entities_for_scan(&sid)).await {
        Ok(e) => e,
        Err(resp) => return resp,
    };
    let sites: Vec<&'static crate::app::batch::sites::Site> =
        match params.get("site").map(String::as_str) {
            None | Some("") => crate::app::batch::sites::SITES.iter().collect(),
            Some(list) => {
                let mut chosen: Vec<&'static crate::app::batch::sites::Site> = Vec::new();
                for id in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    match crate::app::batch::sites::find(id) {
                        // De-duplicate by id so `?site=oathnet,oathnet` renders
                        // one section, matching `cli::batch::resolve_sites`.
                        Some(site) if !chosen.iter().any(|c| c.id == site.id) => chosen.push(site),
                        Some(_) => {}
                        None => {
                            return super::handlers::bad_request(format!(
                                "unknown site {id:?}; known: {}",
                                crate::app::batch::sites::ids().join(", ")
                            ));
                        }
                    }
                }
                chosen
            }
        };
    let bare = params.get("bare").is_some_and(|v| v == "1" || v == "true");
    let selectors = crate::app::batch::selectors_from_entities(&entities);
    let rendered: Vec<_> = sites
        .iter()
        .map(|site| crate::app::batch::render(site, &selectors))
        .collect();
    download_response_operator(
        crate::app::batch::to_text(&rendered, bare),
        "text/plain; charset=utf-8",
        &id,
        "batch",
        "txt",
    )
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
