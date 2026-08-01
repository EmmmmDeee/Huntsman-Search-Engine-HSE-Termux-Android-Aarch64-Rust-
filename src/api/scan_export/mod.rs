//! Export and download handlers for a scan — CSV, JSON report, GEXF, debug
//! bundle — plus the pure rendering functions shared with the CLI.
//!
//! The rendering functions (`entities_to_csv`, `build_scan_report`,
//! `extract_au_location_fix`) are `pub(crate)` so `app::export` can reuse them
//! and produce byte-identical output to the HTTP endpoints.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;

use super::handlers::{internal_error, not_found};
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
    // Redaction of the proprietary source names in the `sources` /
    // `corroborating_sources` columns is enforced by `download_response`.
    download_response(
        entities_to_csv(&entities),
        "text/csv; charset=utf-8",
        &id,
        "csv",
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
    // reconstructing anything from the value alone. `source_count` +
    // `corroborating_sources` sit next to `corroboration` + `sources` for the
    // same reason: `corroboration` is a raw per-module observation magnitude
    // (summed on merge, never deduplicated) that does NOT drive `c_effective`
    // — `source_count` (distinct corroborating sources) does. Without both
    // numbers side by side, a reader has no way to tell from the CSV alone
    // whether a high `corroboration` reflects genuine independent agreement.
    // `uid` and `generation` are APPENDED (never inserted) so the header still
    // begins with the exact prefix `looks_like_hse_csv` sniffs for and every
    // by-name column lookup — the import and audit parsers both resolve columns
    // by header name — keeps working on older and newer files alike.
    // `uid` is the join key: it is what the JSON export, the debug bundle, the
    // Browse pane and the /entities/{uid} pivot endpoint all identify a finding
    // by, so without it a CSV row could only be matched back to the other
    // artifacts by string-matching kind+value. `generation` (hops from the seed)
    // travels with it for the same reason it was added to the bundle — it
    // separates a seed-adjacent finding from one three pivots out.
    body.push_str("kind,value,raw_value,confidence,c_effective,corroboration,source_count,classification,observed_at,sources,corroborating_sources,evidence_urls,evidence,tags,uid,generation\n");
    for e in entities {
        let eff = e.c_effective();
        let source_count = e.source_count();
        let tier = e.classify().to_string();
        let mut sources: Vec<&str> = e.evidence_sources().into_iter().collect();
        sources.sort_unstable();
        let sources = sources.join("|");
        let mut corroborating: Vec<&str> = e.corroborating_sources().into_iter().collect();
        corroborating.sort_unstable();
        let corroborating_sources = corroborating.join("|");
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
        // Append each evidence's full attribute record (the same `k = v` detail
        // the dossier renderer prints per evidence row) after its summary, so
        // the CSV's own self-verifiable promise holds for hard evidentiary
        // fields (a leaked DOB, a password hash, …) that a module recorded as
        // structured `attributes` rather than folding into prose. `BTreeMap`
        // iteration is already key-sorted, so output stays deterministic
        // without an extra sort.
        let evidence = e
            .evidence
            .iter()
            .map(|ev| {
                let attrs: Vec<String> = ev
                    .attributes
                    .iter()
                    .filter(|(_, v)| !v.is_empty())
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect();
                if attrs.is_empty() {
                    format!("[{}] {}", ev.source, ev.summary)
                } else {
                    format!("[{}] {} ({})", ev.source, ev.summary, attrs.join("; "))
                }
            })
            .collect::<Vec<_>>()
            .join(" || ");

        let _ = writeln!(
            body,
            "{},{},{},{:.3},{:.3},{},{},{},{},{},{},{},{},{},{},{}",
            csv_escape(&e.kind.to_string()),
            csv_escape(&e.value),
            csv_escape(&e.raw_value),
            e.confidence,
            eff,
            e.corroboration,
            source_count,
            tier,
            e.observed_at,
            csv_escape(&sources),
            csv_escape(&corroborating_sources),
            csv_escape(&evidence_urls),
            csv_escape(&evidence),
            csv_escape(&tags),
            csv_escape(&e.uid),
            e.generation,
        );
    }
    body
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
    let built = tokio::task::spawn_blocking(move || {
        build_scan_report(store.as_ref(), &id2, cand, infra).map(|opt| {
            opt.map(|report| {
                serde_json::to_string_pretty(&report).unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "failed to serialize scan report to JSON string");
                    "{}".into()
                })
            })
        })
    })
    .await;
    match built {
        Ok(Ok(Some(body))) => {
            download_response(body, "application/json; charset=utf-8", &id, "json", "json")
        }
        Ok(Ok(None)) => not_found(),
        Ok(Err(e)) => internal_error(&e),
        Err(e) => internal_error(&format!("report task failed: {e}")),
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
        // The operator-provided seed is the subject — it must ALWAYS appear in
        // its own report, even when it is itself infrastructure (e.g. a scan
        // seeded with a datacenter/CDN IP that an IP module re-emits as
        // `hosting`, which then merges `platform-infra` onto the seed anchor).
        entities.retain(|e| !e.has_tag(crate::core::tags::PLATFORM_INFRA) || e.has_tag("seed"));
    }
    let correlations = store.correlations_for_scan(scan_id)?;
    let best_location = extract_au_location_fix(&correlations, &entities);
    // The calibrated 0–100 Exposure Index — the SAME headline verdict the CLI
    // `print_dossier` and the debug bundle both open with. This envelope is the
    // canonical over-the-wire/on-device dossier (shared by GET report.json and
    // `hse export --format report`), yet it was the one dossier rendering that
    // omitted the summary score, so a consumer reading report.json alone could
    // not tell a MINIMAL scan from a HIGH one without recomputing it. `assess`
    // is pure and excludes candidate/sub-floor rows internally, so the score is
    // identical whether or not this envelope filtered candidates above, and the
    // determinism audit still holds (nothing here varies but `exported_at`).
    let exposure = crate::core::exposure::assess(&entities, &correlations);
    Ok(Some(json!({
        "scan": scan,
        "entities": entities,
        "entity_count": entities.len(),
        "correlations": correlations,
        "correlation_count": correlations.len(),
        "exposure": exposure,
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
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(resp) = scan_missing(&s, &id).await {
        return resp;
    }
    let store = std::sync::Arc::clone(&s.store);
    let id2 = id.clone();
    let (mut entities, relations) = match tokio::task::spawn_blocking(move || {
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

/// `GET /api/v1/scans/{id}/stix.json` — the scan as a STIX 2.1 bundle for
/// threat-intelligence interchange (MISP / OpenCTI / TAXII / any STIX 2.1
/// consumer). Entities become native STIX objects (`ipv4-addr`, `domain-name`,
/// `identity`, `location`, …) or a custom `x-huntsman-artifact`; typed relations
/// become `relationship` SROs; correlator findings become `note` SDOs; and a
/// framing `report` ties the scan together. Byte-identical to the CLI
/// `hse export {id} --format stix` (both call [`crate::core::stix`]). Candidates
/// are quarantined by default (opt in with `?include_candidates=1`), matching
/// every other scan download.
pub async fn scan_export_stix(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(resp) = scan_missing(&s, &id).await {
        return resp;
    }
    let (id2, store) = (id.clone(), std::sync::Arc::clone(&s.store));
    let cand = wants_candidates(&params);
    let built = tokio::task::spawn_blocking(move || {
        let Some(scan) = store.get_scan(&id2)? else {
            return Ok::<Option<String>, crate::core::error::Error>(None);
        };
        let mut entities = store.entities_for_scan(&id2)?;
        // Quarantine candidates by default (opt in with `?include_candidates=1`)
        // — matches `report.json` / `graph.gexf` / the CLI `render_stix`, so the
        // bundle can't leak a foreign breach-victim list under the subject's scan.
        // The relation set stays full; `entities_to_stix` drops any SRO whose
        // endpoint is no longer present, so filtering here leaves no dangling ref.
        if !cand {
            entities.retain(|e| !e.has_tag(crate::core::tags::CANDIDATE));
        }
        let relations = store.relations_for_scan(&id2)?;
        let correlations = store.correlations_for_scan(&id2)?;
        Ok(Some(crate::core::stix::entities_to_stix(
            &entities,
            &relations,
            &correlations,
            &scan,
        )))
    })
    .await;
    match built {
        // Redaction of proprietary source names is enforced by `download_response`.
        Ok(Ok(Some(body))) => {
            download_response(body, "application/json; charset=utf-8", &id, "stix", "json")
        }
        Ok(Ok(None)) => not_found(),
        Ok(Err(e)) => internal_error(&e),
        Err(e) => internal_error(&format!("stix task failed: {e}")),
    }
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
    match tokio::task::spawn_blocking(move || {
        crate::app::export::render_debug_bundle(store.as_ref(), &id2)
    })
    .await
    {
        // Operator artifact (labelled "operator only" in the UI): the debug bundle
        // deliberately KEEPS the real provider names, so it opts out of the
        // default-safe redaction via `download_response_operator`.
        Ok(Ok(body)) => {
            download_response_operator(body, "text/plain; charset=utf-8", &id, "debug", "txt")
        }
        Ok(Err(e)) => internal_error(&e),
        Err(e) => internal_error(&format!("debug-bundle render task failed: {e}")),
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
    match tokio::task::spawn_blocking(move || store.events_for_scan(&id2)).await {
        // The event JSONL names the producing provider in module_start/done/error;
        // `download_response` redacts those proprietary source names for the
        // customer copy.
        Ok(Ok(events)) => download_response(
            crate::app::export::render_event_log(&events),
            "text/plain; charset=utf-8",
            &id,
            "events",
            "log",
        ),
        Ok(Err(e)) => internal_error(&e),
        Err(e) => internal_error(&format!("events-log query task failed: {e}")),
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
    //
    // A leading apostrophe is ALSO guarded (doubled). Without that the escape
    // isn't invertible: a genuine value like `'=hunter` would export unchanged
    // as `'=hunter`, indistinguishable from a guarded `=hunter`, and the import
    // reverse (`strip_csv_formula_guard`) would strip its real apostrophe. By
    // escaping any leading `'` too, this is a clean bijection — export prepends
    // `'` iff the first byte is a trigger OR `'`, and import strips exactly one
    // leading `'` — so every value round-trips byte-for-byte at any nesting.
    let needs_formula_guard = s
        .as_bytes()
        .first()
        .is_some_and(|b| matches!(*b, b'=' | b'+' | b'-' | b'@' | b'\t' | b'\r' | b'\''));
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
