//! Export and download handlers for a scan — CSV, JSON report, GEXF, debug
//! bundle — plus the pure rendering functions shared with the CLI.
//!
//! The rendering functions (`entities_to_csv`, `build_scan_report`,
//! `extract_au_location_fix`) are `pub(crate)` so `cli::export` can reuse them
//! and produce byte-identical output to the HTTP endpoints.

use axum::{
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;

use super::handlers::{internal_error, not_found};
use super::scan_handlers::{scan_missing, wants_candidates, wants_infra};
use crate::api::AppState;

pub async fn scan_entities_csv(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    req_headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(resp) = scan_missing(&s, &id) {
        return resp;
    }
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    let mut entities =
        match tokio::task::spawn_blocking(move || store.entities_for_scan(&id2)).await {
            Ok(Ok(es)) => es,
            Ok(Err(e)) => return internal_error(&e),
            Err(e) => return internal_error(&format!("query task failed: {e}")),
        };
    // Quarantine by default (opt in with `?include_candidates=1`) — matches the
    // `/entities` JSON endpoint and `report.json` so the downloaded CSV is the
    // subject's confirmed footprint, not a foreign breach-victim list. Without
    // this the CSV silently contradicted the self-audit's "excluded from
    // export" promise and shipped hundreds of non-subject `candidate` rows.
    if !crate::api::scan_handlers::wants_candidates(&params) {
        entities.retain(|e| !e.has_tag(crate::core::tags::CANDIDATE));
    }
    download_response(
        entities_to_csv(&entities),
        "text/csv; charset=utf-8",
        &id,
        "csv",
        &req_headers,
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

/// Canonical CSV rendering for a scan's **correlations** — the tabular,
/// spreadsheet-shaped counterpart to [`entities_to_csv`]. Correlations are
/// first-class scan output (severity, rule, description, the entity UIDs they
/// bridge) but were previously machine-readable only via the JSON `report`
/// blob; this lets an operator load them into the same Excel/LibreOffice
/// pipelines the entity CSV targets. Shared by the `hse export --format
/// correlations-csv` CLI subcommand so the CLI and any HTTP caller produce
/// byte-identical output. Every cell passes through [`csv_escape`] (RFC-4180 +
/// OWASP formula-injection defanging), identical to the entity CSV.
///
/// `entity_uids` is the SHA-256 UID set the rule bridged, `|`-joined into one
/// cell exactly as the entity CSV joins its multi-valued `sources`/`tags`
/// columns, so a downstream tool can split on `|` uniformly across both files.
pub(crate) fn correlations_to_csv(correlations: &[crate::core::correlator::Correlation]) -> String {
    use std::fmt::Write as _;
    let mut body = String::with_capacity(96 + correlations.len() * 160);
    // `rank` is the severity × max-child-C_eff ordering score (highest-value
    // first); `entity_uids` lets a spreadsheet join back to the entity CSV by UID.
    body.push_str(
        "rule_id,rule_name,severity,rank,description,entity_count,entity_uids,observed_at\n",
    );
    for c in correlations {
        let uids = c.entity_uids.join("|");
        let _ = writeln!(
            body,
            "{},{},{},{:.3},{},{},{},{}",
            csv_escape(&c.rule_id),
            csv_escape(&c.rule_name),
            csv_escape(&c.severity.to_string()),
            c.rank,
            csv_escape(&c.description),
            c.entity_uids.len(),
            csv_escape(&uids),
            c.ts,
        );
    }
    body
}

pub async fn scan_report_json(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    req_headers: HeaderMap,
) -> impl IntoResponse {
    match build_scan_report(
        &*s.store,
        &id,
        wants_candidates(&params),
        wants_infra(&params),
    ) {
        Ok(Some(report)) => {
            // Structural ETag: the report body restamps `exported_at` every
            // render, so a body hash would never 304. Validate on the immutable
            // dossier instead — the scan's finished_at + status + entity/
            // correlation counts + the candidate/infra view flags (each flag
            // changes which entities are included). A completed scan's dossier is
            // immutable until re-run, so this revalidates correctly.
            let finished = report["scan"]["finished_at"].as_u64().unwrap_or(0);
            let status = report["scan"]["status"].as_str().unwrap_or("");
            let ecount = report["entity_count"].as_u64().unwrap_or(0);
            let ccount = report["correlation_count"].as_u64().unwrap_or(0);
            let etag = weak_etag(
                format!(
                    "{finished}:{status}:{ecount}:{ccount}:{}:{}",
                    wants_candidates(&params),
                    wants_infra(&params),
                )
                .as_bytes(),
            );
            let body = serde_json::to_string_pretty(&report).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "failed to serialize scan report to JSON string");
                "{}".into()
            });
            download_response_etag(
                body,
                "application/json; charset=utf-8",
                &id,
                "json",
                &req_headers,
                Some(etag),
            )
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
    include_infra: bool,
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
    // Strip platform/shared-infrastructure entities (cloud buckets, CDN IPs,
    // analytics IDs sourced from third-party platform pages) from default
    // output. They inflate the count and obscure subject-owned entities.
    // `include_infra=true` (via `--include-infra` or `--output full`) restores
    // them.
    if !include_infra {
        entities.retain(|e| !e.has_tag("platform-infra"));
    }
    let correlations = store.correlations_for_scan(scan_id)?;
    let best_location = extract_au_location_fix(&correlations, &entities);
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
/// The AU-059 `best_location` for the export, read **structurally** from the
/// scan entities rather than by parsing the finding prose. It is present iff
/// AU-059 actually fired this scan (the gated, ranked finding); the geo fields
/// come from the one canonical [`crate::core::correlator::au059_synergy_fix`]
/// computation the rule itself uses, so the structured export and the finding
/// can never drift (they did, by construction, when this re-parsed the prose).
/// Severity and the post-hoc `rank` are taken from the emitted correlation.
pub(crate) fn extract_au_location_fix(
    correlations: &[crate::core::correlator::Correlation],
    entities: &[crate::core::entity::Entity],
) -> serde_json::Value {
    // Independent-source corroboration (computed regardless of which headline fix
    // wins): how many DISTINCT methods agree on a locality, folding in the
    // postcode-grain signals the synergy fix can't see. Attached to whichever fix
    // is returned so the JSON surface always reports the corroboration strength.
    let corroboration = crate::core::correlator::au_location_corroboration(entities).map(|c| {
        json!({
            "lat": c.lat,
            "lon": c.lon,
            "radius_km": c.radius_km,
            "state": c.state,
            "locality": c.locality,
            "independent_classes": c.independent_classes,
            "signal_count": c.signal_count,
            "classes": c.class_names,
            "confidence": c.confidence,
        })
    });

    // Primary: the AU-059 multi-source cross-class synergy fix (strongest). The
    // structured fields are recomputed from the entities, never parsed from prose.
    let best = correlations
        .iter()
        .filter(|c| c.rule_id == "AU-059")
        .max_by(|a, b| {
            a.rank
                .partial_cmp(&b.rank)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    let mut fix = if let Some(c) = best
        && let Some(synergy) = crate::core::correlator::au059_synergy_fix(entities)
    {
        json!({
            "lat": synergy.lat,
            "lon": synergy.lon,
            "radius_km": synergy.radius_km,
            "geohash": synergy.geohash,
            "state": synergy.state,
            "synergy_confidence": synergy.synergy_confidence,
            "severity": c.severity.as_canonical(),
            "rank": c.rank,
            "source_count": synergy.count,
            "class_count": synergy.class_names.len(),
            "rule_id": "AU-059",
        })
    } else {
        // Fallback: the single-signal best-location estimate, so the web/JSON
        // surface carries a headline fix whenever ANY AU location signal exists —
        // not only the ≥2-class synergy case. Carries the precision radius, nearest
        // locality, and the basis it was derived from. `Null` only when there is no
        // AU location at all.
        match crate::core::correlator::best_au_location_estimate(entities) {
            Some(est) => json!({
                "lat": est.lat,
                "lon": est.lon,
                "radius_km": est.radius_km,
                "geohash": est.geohash,
                "state": est.state,
                "locality": est.locality,
                "confidence": est.confidence,
                "basis": est.basis,
                "source": "single-signal",
            }),
            None => serde_json::Value::Null,
        }
    };

    if let Some(obj) = fix.as_object_mut()
        && let Some(corr) = corroboration
    {
        obj.insert("corroboration".to_string(), corr);
    }
    fix
}

pub async fn scan_export_gexf(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    req_headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(resp) = scan_missing(&s, &id) {
        return resp;
    }
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    let (entities, relations) = match tokio::task::spawn_blocking(move || {
        Ok::<_, crate::core::error::Error>((
            store.entities_for_scan(&id2)?,
            store.relations_for_scan(&id2)?,
        ))
    })
    .await
    {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return internal_error(&e),
        Err(e) => return internal_error(&format!("query task failed: {e}")),
    };
    let body = crate::core::gexf::entities_to_gexf(&entities, &relations, &id);
    download_response(
        body,
        "application/xml; charset=utf-8",
        &id,
        "gexf",
        &req_headers,
    )
}

/// `GET /api/v1/scans/{id}/debug.txt` — the one-click debug bundle: the entire
/// scan state (every entity + evidence, relations, correlations, the complete
/// event sequence, and the scored self-audit with every weakness) in one
/// downloadable text file. The web "Debug bundle" button and the CLI
/// `hse export {id} --format debug` produce the same artifact.
pub async fn scan_debug_bundle(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    req_headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(resp) = scan_missing(&s, &id) {
        return resp;
    }
    // Render off the async runtime: the debug bundle runs many queries, reads
    // the raw archive, and spawns `curl` — all blocking — so on the ~2-worker
    // reactor it would otherwise stall every concurrent request (this also moves
    // the blocking `curl` spawn off the async worker — PROBLEM_TREE T2.2).
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    match tokio::task::spawn_blocking(move || {
        crate::cli::export::render_debug_bundle(store.as_ref(), &id2)
    })
    .await
    {
        // The debug bundle is byte-stable per render (no timestamp — proven by
        // the determinism audit), so a body-hash ETag revalidates exactly.
        Ok(Ok(body)) => download_response(
            body,
            "text/plain; charset=utf-8",
            &id,
            "debug.txt",
            &req_headers,
        ),
        Ok(Err(e)) => internal_error(&e),
        Err(e) => internal_error(&format!("debug-bundle render task failed: {e}")),
    }
}

/// Wrap an export `body` as a browser download: a `200` with the given
/// `content_type` and a `Content-Disposition: attachment` whose filename is
/// `hse-<ext>-<short-scan-id>.<ext>` (id truncated to 12 chars). Shared by the
/// CSV / JSON / GEXF / debug-bundle endpoints so every download names itself the
/// same way.
///
/// Conditional GET: a completed scan's export is immutable until the scan is
/// re-run, so the body is its own validator. We derive a content-hash ETag and,
/// when the caller's `If-None-Match` already lists it, return `304 Not Modified`
/// with no body — eliminating the full re-transfer of a large dossier on every
/// poll over a metered cellular link (the `report.json`/`debug.txt` of a
/// several-hundred-entity scan is the case this targets). `Cache-Control:
/// private, no-cache` lets the browser cache-and-revalidate while forbidding any
/// shared/intermediary cache from retaining the sensitive dossier; `no-cache`
/// (revalidate, not "don't store") is what makes the ETag round-trip fire.
fn download_response(
    body: String,
    content_type: &'static str,
    scan_id: &str,
    ext: &str,
    req_headers: &HeaderMap,
) -> axum::response::Response {
    download_response_etag(body, content_type, scan_id, ext, req_headers, None)
}

/// [`download_response`] with an optional explicit ETag. The CSV / GEXF / debug
/// exports are byte-stable per render, so `None` lets us hash the body. The
/// `report.json` export is **not** byte-stable — it stamps a fresh `exported_at`
/// every render (the documented sole source of non-determinism) — so a body hash
/// would change every time and never 304. There the caller passes a *structural*
/// validator (scan identity + entity count) that tracks the immutable parts of
/// the dossier, so revalidation still works.
fn download_response_etag(
    body: String,
    content_type: &'static str,
    scan_id: &str,
    ext: &str,
    req_headers: &HeaderMap,
    etag_override: Option<String>,
) -> axum::response::Response {
    let etag = etag_override.unwrap_or_else(|| weak_etag(body.as_bytes()));
    let cache = axum::http::HeaderValue::from_static("private, no-cache");

    // If the client already holds these exact bytes, skip re-sending them.
    let not_modified = req_headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|inm| if_none_match_hit(inm, &etag));
    if not_modified {
        let mut resp = StatusCode::NOT_MODIFIED.into_response();
        let h = resp.headers_mut();
        if let Ok(v) = axum::http::HeaderValue::from_str(&etag) {
            h.insert(header::ETAG, v);
        }
        h.insert(header::CACHE_CONTROL, cache);
        return resp;
    }

    let short_id: String = scan_id.chars().take(12).collect();
    let filename = format!("hse-{ext}-{short_id}.{ext}");
    let disposition = format!("attachment; filename=\"{filename}\"");
    // Stream the body in fixed-size frames rather than handing axum one
    // contiguous buffer. The String is already rendered (and already hashed for
    // the ETag above), so this doesn't avoid the render — but it does stop a
    // large dossier (`report.json`/`debug.txt` of a several-hundred-entity scan)
    // from being re-buffered as a single response payload on top of the source
    // String. On the ~low-RAM Termux/aarch64 target that halves peak footprint
    // for the big exports, and lets the downstream `CompressionLayer` gzip frame
    // by frame instead of materialising the whole compressed body at once. The
    // 304 fast path above never reaches here, so conditional GET is unaffected.
    let mut resp = (StatusCode::OK, chunked_stream(body)).into_response();
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static(content_type),
    );
    if let Ok(v) = axum::http::HeaderValue::from_str(&disposition) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    if let Ok(v) = axum::http::HeaderValue::from_str(&etag) {
        headers.insert(header::ETAG, v);
    }
    headers.insert(header::CACHE_CONTROL, cache);
    resp
}

/// Frame size for [`chunked_stream`]. 64 KiB is large enough that even a
/// several-hundred-KiB dossier streams in a handful of frames (negligible
/// per-frame overhead) yet small enough that no single buffer dominates RAM on
/// the low-memory Termux/aarch64 target — the constant this whole streaming path
/// exists to bound.
const EXPORT_CHUNK_BYTES: usize = 64 * 1024;

/// Turn an owned, already-rendered export `body` into a stream of `Bytes` frames
/// for [`axum::body::Body::from_stream`], so the response body is delivered (and
/// gzipped by the downstream `CompressionLayer`) frame by frame instead of as one
/// contiguous payload re-buffered on top of the source `String`.
///
/// The `String` is moved into a [`Bytes`] once (a single, reference-counted
/// allocation — no copy), then sliced into `EXPORT_CHUNK_BYTES`-sized windows with
/// [`Bytes::slice`], which shares the backing buffer rather than copying. Peak
/// additional memory is therefore O(1) over the rendered body, which is the point
/// on a low-RAM device. `Bytes` is axum's own re-export, so it is the exact type
/// `Body::from_stream` wants — no separate `bytes` dependency, no version skew.
/// The stream is infallible, so its error type is [`std::convert::Infallible`] and
/// `Body::from_stream`'s `Into<BoxError>` bound is satisfied trivially.
fn chunked_stream(body: String) -> Body {
    use futures::StreamExt as _;
    let bytes = Bytes::from(body);
    let len = bytes.len();
    // Cursor-driven unfold: the closure owns the shared buffer plus a byte
    // offset and yields the next window each poll, with no per-frame allocation
    // beyond `Bytes::slice`'s reference-counted handle into the same buffer.
    let frames = futures::stream::unfold((bytes, 0usize), move |(buf, pos)| async move {
        if pos >= len {
            return None;
        }
        let end = (pos + EXPORT_CHUNK_BYTES).min(len);
        let frame = buf.slice(pos..end);
        Some((frame, (buf, end)))
    });
    // `Body::from_stream` needs `S::Error: Into<BoxError>`; the stream cannot
    // fail, so wrap each frame in `Ok` with the uninhabited `Infallible` error.
    Body::from_stream(frames.map(Ok::<Bytes, std::convert::Infallible>))
}

/// A weak ETag (`W/"<hex>"`) over `bytes` — a cheap 64-bit content hash that
/// changes iff the rendered export changes. Weak (not strong) because gzip from
/// the compression layer makes byte-for-byte equality moot; weak validators
/// still satisfy `If-None-Match`. Centralised so every export tags identically.
pub(crate) fn weak_etag(bytes: &[u8]) -> String {
    use std::hash::{Hash as _, Hasher as _};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    format!("W/\"{:016x}\"", h.finish())
}

/// RFC 7232 `If-None-Match` test: true if the header is `*` or lists `etag`.
/// Comparison ignores the `W/` weak prefix on both sides so a weak validator
/// echoed verbatim by the browser still matches. Mirrors the static handler's
/// equivalent in `api::routes`.
fn if_none_match_hit(if_none_match: &str, etag: &str) -> bool {
    let strip = |t: &str| t.trim().trim_start_matches("W/").to_string();
    let want = strip(etag);
    if_none_match
        .split(',')
        .any(|t| t.trim() == "*" || strip(t) == want)
}

/// RFC-4180 CSV field escaping with **formula-injection defanging**: a field
/// whose first byte is `= + - @ TAB CR` is prefixed with a `'` so Excel /
/// LibreOffice don't execute it as a formula on open (OWASP CSV-injection), then
/// any field containing `, " \n \r` is double-quoted with embedded quotes doubled.
/// Every cell in an exported scan CSV passes through this.
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
