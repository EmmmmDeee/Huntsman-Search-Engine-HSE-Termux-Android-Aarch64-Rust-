// HTTP handlers.
//
// Every handler returns `impl IntoResponse` so we can mix `Json`,
// `(StatusCode, Json)`, and `Sse<...>` freely. Error paths emit a
// `{"error": "..."}` JSON body with the appropriate status.

use std::{convert::Infallible, sync::Arc};

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{
        IntoResponse,
        sse::{Event as SseEvent, KeepAlive, Sse},
    },
};
use futures::Stream;
use serde::Serialize;
use serde_json::{Value, json};
use tokio_stream::{StreamExt as _, wrappers::BroadcastStream};

use super::AppState;
use crate::core::{
    event::{Event, EventBus},
    module::ModuleContext,
    scan::{Target, TargetKind},
};
use crate::util::keys;

// ─── Shared response helpers ───────────────────────────────────────────────

/// Construct and validate a `Target`, mapping a validation failure to the
/// canonical client-facing `invalid target: …` message. The single source of
/// truth for target admission shared by the scan-create and live-create paths,
/// so the rule and its error wording can't diverge between them.
pub(crate) fn validated_target(kind: TargetKind, value: String) -> Result<Target, String> {
    let target = Target::new(kind, value);
    target
        .validate()
        .map_err(|msg| format!("invalid target: {msg}"))?;
    Ok(target)
}

/// A `500` with a `{ "error": <msg> }` body — the server-error sibling of
/// [`bad_request`] / [`not_found`], for a storage or internal failure. One shape
/// for every 500 so API consumers parse errors uniformly.
pub(crate) fn internal_error(err: &impl ToString) -> axum::response::Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": err.to_string() })),
    )
        .into_response()
}

/// A `404` with a `{ "error": "not found" }` body — returned when a scan / entity
/// / sub-resource id doesn't exist, in the shared error shape.
pub(crate) fn not_found() -> axum::response::Response {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" }))).into_response()
}

/// 400 with a `{ "error": <msg> }` body — the client-error sibling of
/// [`internal_error`] / [`not_found`]. Accepts both `&'static str` literals and
/// owned `String`s (e.g. a `format!`-built validation message), so the ~10
/// open-coded `(BAD_REQUEST, Json(json!({"error": …})))` sites share one shape.
pub(crate) fn bad_request(msg: impl Into<String>) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": msg.into() })),
    )
        .into_response()
}

/// A `403 Forbidden` JSON error, the access-control sibling of [`bad_request`]
/// (e.g. a failed CSRF/loopback check). One shape for every refusal.
pub(crate) fn forbidden(msg: impl Into<String>) -> axum::response::Response {
    (StatusCode::FORBIDDEN, Json(json!({ "error": msg.into() }))).into_response()
}

/// The canonical list envelope every list endpoint returns:
/// `{ "<key>": [items…], "count": <n> }`. One shape so the SPA and CLI parse
/// every collection response (entities, relations, correlations, …) identically.
pub(crate) fn ok_list<T: Serialize>(key: &str, items: Vec<T>) -> axum::response::Response {
    let n = items.len();
    let mut map = serde_json::Map::new();
    map.insert(
        key.to_string(),
        serde_json::to_value(items).unwrap_or(Value::Null),
    );
    map.insert("count".to_string(), Value::Number(n.into()));
    (StatusCode::OK, Json(Value::Object(map))).into_response()
}

/// Dispatch a created `scan` to run on the async runtime — the HTTP layer's
/// fire-and-forget hand-off to the engine (the request returns `202` immediately).
///
/// Wires up everything the background run needs: a [`crate::core::cancel::CancelHandle`]
/// registered so `POST /scans/{id}/cancel` can stop it, a per-scan HTTP client
/// stamped with the scan id (`x-huntsman-trace`) so outbound calls correlate in
/// upstream logs, the shared proxy pool, and the scan-concurrency semaphore that
/// bounds how many scans run at once on a low-RAM device.
pub(crate) fn spawn_scan(state: &Arc<AppState>, scan: crate::core::scan::Scan, target: Target) {
    let sid = scan.id.clone();
    let cancel = crate::core::cancel::CancelHandle::new();
    let cancel_guard = super::CancelRegistryGuard::install(
        Arc::clone(&state.cancellations),
        sid.clone(),
        cancel.clone(),
    );
    let bus_clone = state.bus.clone();
    // Per-scan client stamped with the scan id (x-huntsman-trace) so outbound
    // calls correlate to this scan in a proxy/upstream log, mirroring the CLI.
    let http_clone = crate::util::http::build_client_with_trace(&sid);
    let proxy_clone = std::sync::Arc::clone(&state.proxy_pool);
    let engine = Arc::clone(&state.engine);
    let sem = Arc::clone(&state.scan_semaphore);
    let store_clone = Arc::clone(&state.store);
    tokio::spawn(async move {
        let _cancel_guard = cancel_guard;
        let api_keys = keys::populate_and_load().await;
        let ctx = ModuleContext {
            scan_id: sid.clone(),
            bus: bus_clone,
            http: http_clone,
            keys: api_keys,
            cancel,
            proxy_pool: proxy_clone,
        };
        let Ok(_permit) = sem.acquire().await else {
            tracing::warn!(scan_id = %sid, "scan semaphore closed");
            return;
        };
        match engine.run(scan, target, ctx).await {
            Ok(completed) => {
                // Mirror the CLI's post-scan diagnostics: update the cross-scan
                // module-stats ledger so API/web scans feed adaptive routing the
                // same as `hse scan` CLI runs do.
                if let Ok(entities) = store_clone.entities_for_scan(&sid) {
                    let wall_ms = completed
                        .finished_at
                        .and_then(|f| f.checked_sub(completed.started_at))
                        .unwrap_or(0)
                        .saturating_mul(1000);
                    crate::util::diagnostics::analyse(
                        &sid,
                        completed.target.kind.canonical_str(),
                        &completed.target.value,
                        wall_ms,
                        &entities,
                    );
                }
            }
            Err(e) => tracing::warn!(scan_id = %sid, error = %e, "scan failed"),
        }
    });
}

// ─── Scan CRUD handlers ──────────────────────────────────────────────────
// Scan CRUD handlers: create, get, list, delete, rerun, cancel,
// entities, correlations, events, CSV/JSON export.

pub async fn health() -> Json<Value> {
    Json(json!({ "status": "ok", "version": crate::VERSION }))
}

/// Pure aggregation of dashboard scan statistics — the per-status histogram and
/// the entity/dedup totals — over a scan list. Split out of [`stats`] so the
/// summation logic is unit-testable without a live store + async handler.
#[derive(Default, PartialEq, Eq, Debug)]
pub(crate) struct ScanStatsAgg {
    pub by_status: std::collections::BTreeMap<&'static str, u64>,
    pub total_entities: u64,
    pub total_deduped: u64,
}

pub(crate) fn aggregate_scan_stats(scans: &[crate::core::scan::Scan]) -> ScanStatsAgg {
    let mut agg = ScanStatsAgg::default();
    for scan in scans {
        *agg.by_status.entry(scan.status.as_str()).or_insert(0) += 1;
        agg.total_entities += scan.entity_count as u64;
        agg.total_deduped += scan.modules_deduped as u64;
    }
    agg
}

pub async fn stats(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let store = Arc::clone(&s.store);
    let scans = match tokio::task::spawn_blocking(move || store.list_scans(10_000)).await {
        Ok(Ok(scans)) => scans,
        Ok(Err(e)) => return internal_error(&e),
        Err(e) => return internal_error(&format!("stats query failed: {e}")),
    };
    let ScanStatsAgg {
        by_status,
        total_entities,
        total_deduped,
    } = aggregate_scan_stats(&scans);
    let modules = s.engine.modules().len();
    let live_sessions = s.live.list().len();

    // Surface SeekNow + OathNet + WiGLE budget consumption so operators
    // can see how much of each daily quota the current process has
    // burned. All providers share `util::budget::QuotaBudget` so the
    // wire format is identical; WiGLE has four sub-budgets (geo /
    // bssid / cell / bluetooth) so its block nests one level deeper.
    let seeknow = budget_block(crate::util::see_know::budget_snapshot());
    let oathnet = budget_block(crate::util::oathnet::budget_snapshot());
    let wigle = crate::modules::wigle::budget_snapshot();
    let wigle_account = crate::modules::wigle::account_status();
    let wigle_block = json!({
        "geo":       budget_block(wigle.geo),
        "bssid":     budget_block(wigle.bssid),
        "cell":      budget_block(wigle.cell),
        "bluetooth": budget_block(wigle.bluetooth),
        "account":   {
            // `verified == false` means the WiGLE account has not yet
            // confirmed the email-verification step, which gates the
            // database queries (operator-facing warning). `null` means
            // we haven't polled `/profile/user` yet this process. WiGLE
            // exposes no per-call usage endpoint, so quota counts aren't
            // reported here.
            "verified":           wigle_account.verified,
            "user":               wigle_account.user,
            "last_polled_ts":     wigle_account.last_polled_ts,
        },
    });

    (
        StatusCode::OK,
        Json(json!({
            "scans_total": scans.len(),
            "scans_by_status": by_status,
            "entities_total": total_entities,
            "modules_deduped_total": total_deduped,
            "modules": modules,
            "live_sessions": live_sessions,
            "version": crate::VERSION,
            "seeknow": seeknow,
            "oathnet": oathnet,
            "wigle":   wigle_block,
        })),
    )
        .into_response()
}

/// Convert a [`crate::util::budget::BudgetSnapshot`] into the
/// JSON shape used by the `/api/v1/stats` endpoint. Centralised so
/// every quota-spending provider serialises identically.
fn budget_block(snap: crate::util::budget::BudgetSnapshot) -> Value {
    json!({
        "scan_used":       snap.scan_used,
        "scan_cap":        snap.scan_cap,
        "session_used":    snap.session_used,
        "session_cap":     snap.session_cap,
        "quota_exhausted": snap.quota_exhausted,
    })
}

pub async fn version() -> Json<Value> {
    Json(json!({ "version": crate::VERSION }))
}

/// Search-engine liveness panel data. Serves the latest cached sweep (populated
/// by the periodic + startup background task in `hse serve`); if no sweep has run
/// yet, runs one lazily. Each engine reports up/blocked/down + latency + result
/// count. Backs the web liveness panel and `hse engines`.
pub async fn engines_health() -> Json<Value> {
    use crate::modules::search_engines::health::{EngineStatus, cached_or_empty};
    // Serve the cached sweep (instant, hermetic); never probe on the request
    // path. The startup/periodic sweep in `hse serve` populates it; a cold cache
    // returns an empty snapshot and the panel auto-refreshes.
    let snap = cached_or_empty();
    let count = |st: EngineStatus| snap.engines.iter().filter(|h| h.status == st).count();
    let engines: Vec<Value> = snap
        .engines
        .iter()
        .map(|h| {
            json!({
                "engine": h.name,
                "status": h.status.as_str(),
                "latency_ms": h.latency_ms,
                "results": h.results,
                "detail": h.detail,
                // True when this engine has been silenced for the current scan
                // after returning nothing for 3+ consecutive seeds.
                "session_dead": crate::modules::search_engines::session_dead(h.name),
            })
        })
        .collect();
    Json(json!({
        "checked_at": snap.checked_at,
        "total": snap.engines.len(),
        "up": count(EngineStatus::Up),
        "blocked": count(EngineStatus::Blocked),
        "down": count(EngineStatus::Down),
        "engines": engines,
    }))
}

/// `GET /api/v1/selftest` — run the full module + feature self-validation suite
/// on demand and return the structured report. Powers the Settings page's
/// "Run self-test" button. Offline + side-effect-free (a throwaway temp DB).
pub async fn selftest_run() -> impl IntoResponse {
    Json(crate::selftest::run().await)
}

/// `GET /api/v1/logs` — download the in-memory verbose debug-log ring buffer as
/// a text attachment. The buffer captures the project's default TRACE-level
/// logs for the life of the process (bounded; see `util::log_capture`).
pub async fn logs_download() -> impl IntoResponse {
    let body = crate::util::log_capture::dump();
    let filename = format!("hse-debug-{}.log", crate::core::entity::unix_now());
    (
        [
            (
                axum::http::header::CONTENT_TYPE,
                "text/plain; charset=utf-8".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        body,
    )
}

pub async fn modules_list(State(s): State<Arc<AppState>>) -> Json<Value> {
    let mods: Vec<Value> = s
        .engine
        .modules()
        .iter()
        .map(|m| {
            let cost = serde_json::to_value(m.cost()).unwrap_or(Value::Null);
            // Pull declared consumes via the trait method — falls back to
            // the probe-based default for legacy modules. Mirrors what the
            // dispatch index and dependency graph see.
            let accepts: Vec<&'static str> = m
                .consumes()
                .iter()
                .map(super::super::core::scan::TargetKind::canonical_str)
                .collect();
            let produces: Vec<String> = m
                .produces()
                .iter()
                .map(std::string::ToString::to_string)
                .collect();
            json!({
                "name":        m.name(),
                "priority":    m.priority(),
                "cost":        cost,
                "passive":     m.is_passive(),
                "category":    m.category().as_str(),
                "accepts":     accepts,
                "produces":    produces,
                "description": m.description(),
            })
        })
        .collect();
    let count = mods.len();
    Json(json!({ "modules": mods, "count": count }))
}

/// `GET /api/v1/modules/graph` — pre-computed module dependency graph.
///
/// Returns the per-`TargetKind` dispatch index (with module counts and
/// normalised richness scores) plus the per-module `consumes/produces`
/// edges. The SPA renders this as a Sankey-style flow that shows
/// "what does seed X unlock?" — a Spiderfoot 4.0 capability HSE
/// surfaces with explicit data-flow declarations.
pub async fn modules_graph(State(s): State<Arc<AppState>>) -> Json<Value> {
    let graph = s.engine.graph();
    let summary = graph.to_summary(s.engine.modules());
    Json(json!({
        "kinds":           summary.kinds,
        "edges":           summary.edges,
        "produced_kinds":  summary.produced_entity_kinds(),
        "module_count":    s.engine.modules().len(),
    }))
}

pub async fn entity_get(
    State(s): State<Arc<AppState>>,
    Path(uid): Path<String>,
    req_headers: HeaderMap,
) -> impl IntoResponse {
    match s.store.get_entity(&uid) {
        Ok(Some(entity)) => {
            let scan_ids = match s.store.scan_ids_for_entity(&uid) {
                Ok(ids) => ids,
                Err(e) => {
                    tracing::warn!(entity_uid = %uid, error = %e, "scan_ids_for_entity failed");
                    return internal_error(&e);
                }
            };
            let obs_count = match s.store.observation_count(&uid) {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(entity_uid = %uid, error = %e, "observation_count failed");
                    return internal_error(&e);
                }
            };
            // Cache revalidation for this stable cross-scan point lookup: an
            // entity's record changes only when it is re-observed, so
            // `observed_at` + the observation count is a sound weak validator. A
            // reconnecting SPA polling the entity panel revalidates with `304`
            // instead of refetching the full record (+ every scan it appears in)
            // over cellular. `private, no-cache` allows the browser to cache and
            // revalidate while keeping the sensitive record out of shared caches.
            let etag = format!("W/\"{:x}-{}\"", entity.observed_at, obs_count);
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
                h.insert(
                    header::CACHE_CONTROL,
                    axum::http::HeaderValue::from_static("private, no-cache"),
                );
                return resp;
            }
            let mut resp = (
                StatusCode::OK,
                Json(serde_json::json!({
                    "entity": entity,
                    "scan_ids": scan_ids,
                    "observation_count": obs_count,
                })),
            )
                .into_response();
            let h = resp.headers_mut();
            if let Ok(v) = axum::http::HeaderValue::from_str(&etag) {
                h.insert(header::ETAG, v);
            }
            h.insert(
                header::CACHE_CONTROL,
                axum::http::HeaderValue::from_static("private, no-cache"),
            );
            resp
        }
        Ok(None) => not_found(),
        Err(e) => internal_error(&e),
    }
}

/// RFC 7232 `If-None-Match` test for the JSON handlers (weak-aware): true if the
/// header is `*` or lists `etag`, ignoring the `W/` weak prefix on both sides.
/// Mirrors the export module's equivalent; kept local so each module's caching
/// is self-contained.
fn if_none_match_hit(if_none_match: &str, etag: &str) -> bool {
    let strip = |t: &str| t.trim().trim_start_matches("W/").to_string();
    let want = strip(etag);
    if_none_match
        .split(',')
        .any(|t| t.trim() == "*" || strip(t) == want)
}

pub async fn search_entities(
    State(s): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let query = match params.get("q") {
        Some(q) if !q.trim().is_empty() && q.len() <= 256 => q.trim(),
        Some(q) if q.len() > 256 => {
            return bad_request("query too long (max 256 chars)");
        }
        _ => {
            return bad_request("missing or empty 'q' parameter");
        }
    };
    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(50)
        .min(200);
    match s.store.search_entities(query, limit) {
        Ok(entities) => ok_list("entities", entities),
        Err(e) => internal_error(&e),
    }
}

// ─── SSE event stream ──────────────────────────────────────────────────────
//
// The live event stream (scan progress + log lines pushed to the browser as
// the graph grows) uses **Server-Sent Events, deliberately not WebSockets**.
// The channel is strictly one-way (server → browser): there is no client→
// server messaging over it — control actions (cancel a scan, stop a live
// session) go through ordinary REST endpoints (`POST /scans/{id}/cancel`,
// `DELETE /live/{id}`). For one-way server push, SSE is the lighter, simpler
// fit: it is plain HTTP/1.1 with no upgrade handshake, the browser's native
// `EventSource` reconnects automatically, and it avoids the bidirectional
// framing/ping-pong machinery a WebSocket stack would add for zero benefit
// here — which matters on low-power Termux. axum's `Sse` response sets the
// `text/event-stream` content-type the `EventSource` client requires; the
// `scan_events_endpoint_is_server_sent_events` test in `tests/api.rs` pins
// that wire contract.

const SSE_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Render one bus [`Event`] as a wire [`SseEvent`].
///
/// The frame is stamped with `id:` = the event's `ts` (unix seconds). The
/// browser's `EventSource` records the last id seen and echoes it as the
/// `Last-Event-ID` request header on its automatic reconnect, which
/// [`replay_since`] uses to backfill the events missed during a mobile-link drop
/// — the gap the previous bare-`data` frames left permanently unrecoverable from
/// the live stream.
///
/// The frame is left as the **default unnamed `message` event** — deliberately
/// NOT `.event(tag)`. A named SSE event is dispatched only to a matching
/// `addEventListener(tag, …)` and bypasses `EventSource.onmessage`; the SPA
/// consumes the stream through `es.onmessage` and switches on the JSON `type`
/// field, so naming the frames would silently stop it receiving them. Stamping
/// only `id:` is purely additive: `onmessage` still fires for every frame and
/// the JSON body (with its unchanged `entity_found`/… `type` tag) is untouched,
/// so the existing client contract is preserved.
fn event_to_sse(event: &Event) -> SseEvent {
    let payload = serde_json::to_string(&event.kind).unwrap_or_default();
    SseEvent::default().id(event.ts.to_string()).data(payload)
}

/// Persisted events to replay when a reconnecting `EventSource` presents a
/// `Last-Event-ID` — every stored event for `scan_id` newer than that id, in
/// order, so a client resumes exactly where its dropped stream left off.
///
/// The id is an event `ts` (unix seconds); we replay `ts > last_id`. Same-second
/// events straddling the boundary may re-deliver a couple of frames, which the
/// log view tolerates — a far better failure mode than the old behaviour, where
/// every event pushed during the drop was lost permanently (recoverable only by
/// separately polling `events.history`). Returns an empty vec when the header is
/// absent/unparseable or no scan/events exist; a store error degrades to no
/// replay rather than failing the live stream the client actually wants.
fn replay_since(
    store: &dyn crate::core::port::StoragePort,
    scan_id: &str,
    headers: &HeaderMap,
) -> Vec<Event> {
    let Some(last_id) = headers
        .get(header::HeaderName::from_static("last-event-id"))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
    else {
        return Vec::new();
    };
    match store.events_for_scan(scan_id) {
        Ok(events) => events.into_iter().filter(|e| e.ts > last_id).collect(),
        Err(e) => {
            tracing::warn!(scan_id = %scan_id, error = %e, "SSE replay query failed; resuming live only");
            Vec::new()
        }
    }
}

/// Build the SSE body stream shared by the scan- and live-event endpoints.
///
/// `replay` is a (possibly empty) prelude of already-persisted events emitted
/// before the live tail — the `Last-Event-ID` backfill (see [`replay_since`]).
/// `accept` selects which live bus events belong on this stream (by `scan_id`
/// and/or live-session ownership). Centralising the plumbing here is what keeps
/// the two endpoints from drifting — every subtle SSE property lives in one
/// place:
///
/// * **Resumption** — the `replay` prelude is chained ahead of the live
///   broadcast tail, so a reconnecting client first receives the events it
///   missed (newer than its `Last-Event-ID`) and then continues live, with no
///   gap.
/// * **Lag tolerance** — a slow client that overflows its broadcast buffer
///   yields `Err(Lagged)`, which falls through to `_ => None`: the missed events
///   are skipped but the stream stays open (dropping a few live-log lines under
///   load beats tearing the stream down).
/// * **Idle timeout** — if no *matching* event arrives within
///   [`SSE_IDLE_TIMEOUT`] the stream ends, reclaiming a client that vanished
///   without a clean close (half-open TCP the keep-alive write hasn't tripped
///   yet). A finished scan stops emitting, so its stream closes ~timeout later,
///   as intended; the browser's `EventSource` transparently reconnects if the
///   session is still live (only relevant when an interval exceeds the timeout).
///   The idle timeout applies only to the live tail, so a long `replay` prelude
///   can't trip it.
/// * **Keep-alive** — periodic comment pings hold the connection open and surface
///   a dead socket promptly via the failing write.
///
/// On client disconnect axum drops this stream, dropping the broadcast receiver
/// and unsubscribing it — so there is no per-connection resource to leak.
fn sse_event_stream<F>(
    bus: &EventBus,
    replay: Vec<Event>,
    accept: F,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>> + use<F>>
where
    F: Fn(&Event) -> bool + Send + 'static,
{
    // Backfill prelude: the events the client missed, already persisted and in
    // order. Each is an infallible `Ok` SseEvent, stamped with the same id/type
    // as the live frames so the client's `Last-Event-ID` continues monotonically.
    let prelude = tokio_stream::iter(
        replay
            .into_iter()
            .map(|e| Ok::<SseEvent, Infallible>(event_to_sse(&e))),
    );

    let live = BroadcastStream::new(bus.subscribe())
        .filter_map(move |msg| match msg {
            Ok(event) if accept(&event) => Some(Ok(event_to_sse(&event))),
            _ => None,
        })
        .timeout(SSE_IDLE_TIMEOUT)
        .take_while(std::result::Result::is_ok)
        .filter_map(std::result::Result::ok);

    let stream = prelude.chain(live);
    Sse::new(stream).keep_alive(KeepAlive::default())
}

pub async fn scan_events_sse(
    State(s): State<Arc<AppState>>,
    Path(target_sid): Path<String>,
    headers: HeaderMap,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    // Read the missed-event backfill from the persisted log, then chain the live
    // tail after it. The events table is the durable record the engine writes to,
    // so a reconnecting `EventSource` recovers everything newer than its
    // `Last-Event-ID` (see `replay_since`); the live tail then continues. A few
    // same-second boundary frames may re-deliver, which the log view tolerates.
    let replay = replay_since(s.store.as_ref(), &target_sid, &headers);
    sse_event_stream(&s.bus, replay, move |event| event.scan_id == target_sid)
}

// ─── Settings handlers ─────────────────────────────────────────────────────

// ─── Live-mode handlers ────────────────────────────────────────────────────

pub async fn live_create(
    State(s): State<Arc<AppState>>,
    Json(req): Json<crate::core::live::LiveRequest>,
) -> impl IntoResponse {
    let kind = req.resolved_kind();
    let target = match validated_target(kind, req.value) {
        Ok(t) => t,
        Err(msg) => return bad_request(msg),
    };
    let live_id = s.live.start(target, req.options, req.live);
    (
        StatusCode::ACCEPTED,
        Json(json!({ "live_id": live_id, "status": "running" })),
    )
        .into_response()
}

pub async fn live_list(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    ok_list("sessions", s.live.list())
}

pub async fn live_get(State(s): State<Arc<AppState>>, Path(id): Path<String>) -> impl IntoResponse {
    match s.live.get(&id) {
        Some(session) => (
            StatusCode::OK,
            Json(serde_json::to_value(&session).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "failed to serialize live session");
                json!({})
            })),
        )
            .into_response(),
        None => not_found(),
    }
}

pub async fn live_stop(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if s.live.stop(&id) {
        (
            StatusCode::OK,
            Json(json!({ "live_id": id, "status": "stopping" })),
        )
            .into_response()
    } else {
        not_found()
    }
}

pub async fn live_events_sse(
    State(s): State<Arc<AppState>>,
    Path(target_lid): Path<String>,
    headers: HeaderMap,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    // A live session's stream carries both its own lifecycle events (emitted
    // under `scan_id == live_id`) and every per-iteration scan it spawned.
    let live = s.live.clone();
    // On reconnect, backfill the session's own lifecycle events newer than the
    // client's `Last-Event-ID` (those persisted under the live id). The
    // per-iteration child scans keep streaming live; replaying every child's
    // full history would be unbounded, so the durable backfill is scoped to the
    // session timeline, with the live tail resuming both.
    let replay = replay_since(s.store.as_ref(), &target_lid, &headers);
    sse_event_stream(&s.bus, replay, move |event| {
        event.scan_id == target_lid || live.session_owns_scan(&target_lid, &event.scan_id)
    })
}

// ─── Tests (from scan.rs) ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
