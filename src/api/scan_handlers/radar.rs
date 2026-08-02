//! Live device-sensor radar handlers: the passive Wi-Fi/Bluetooth/cell/LAN
//! ambient survey, entirely separate from target seed scanning. A one-shot
//! sweep ([`radar_sweep`]), a continuous session ([`radar_live`]), and the
//! persisted-history review surfaces ([`radar_history`], [`radar_recurring`])
//! that make counter-surveillance review possible across many sweeps.

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::sync::Arc;
use tracing::info;

use super::super::handlers::{offload, ok_list, spawn_scan};
use crate::api::AppState;
use crate::core::entity::scan_id;
use crate::core::scan::{Scan, Target};

/// Build the `(target, options)` for a radar sweep from the optional seed
/// **type**. Pure (no store / engine access) so the radar's invariants — *only*
/// the live device sensors run, `allow_live_sensors` is set (the sole activation
/// path), the sweep is passive and single-round, and it carries no real target —
/// are unit-testable without an `AppState`. `Some("mac"|"mac_address"|"bssid")`
/// anchors the sweep on the local network (a sentinel MAC); anything else (incl.
/// `None`) is the default GPS/RF ambient survey (a sentinel coordinate). The
/// sensors ignore the seed value, so it is always a sentinel, never a target.
pub(crate) fn radar_scan_spec() -> (Target, crate::core::scan::ScanOptions) {
    use crate::core::scan::TargetKind;
    // A fixed sentinel. All five sensors gate on `Coordinates | MacAddress` and
    // ignore the value entirely, so the old `?seed=` knob — which chose only
    // WHICH sentinel kind to use — could not change what any of them collected.
    // The radar has two states, running and stopped; a parameter that alters
    // nothing is a way to think you configured something.
    let (kind, value) = (
        TargetKind::Coordinates,
        crate::core::scan::RADAR_SENTINEL_COORD_RAW,
    );
    let opts = crate::core::scan::ScanOptions {
        modules: Some(
            crate::core::engine::LOCAL_PASSIVE_MODULES
                .iter()
                .map(|m| (*m).to_string())
                .collect(),
        ),
        passive_only: true,
        depth: 0,
        allow_live_sensors: true,
        ..Default::default()
    };
    (Target::new(kind, value), opts)
}

/// `POST /api/v1/radar` — run ONE autonomous live-sensor sweep (the radar button).
///
/// The dedicated, user-triggered activation for the live device sensors
/// (`signal_radar`, `device_sensors`, `wifi_intel`, `cell_intel`, `local_net`).
/// It takes **no target** — it surveys the device's own ambient RF / network
/// environment (Wi-Fi APs, Bluetooth, cell towers, GPS fix, LAN ARP) — and is
/// entirely separate from target seed scanning: an ordinary scan never runs these
/// modules (the `allow_live_sensors` gate keeps them off); only this endpoint sets
/// it. The sweep is seeded with a sentinel value purely so the sensors (which
/// gate on `Coordinates`/`MacAddress` and ignore the value) dispatch.
///
/// It takes **no parameters at all** — running or stopped is the whole
/// interface.
pub async fn radar_sweep(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    // Armed by default: hitting this endpoint IS the deliberate activation. The
    // `feature.live_radar` toggle is a kill-switch — it only refuses here if the
    // operator has explicitly switched the radar OFF. (Seed scans can never run the
    // sensors regardless — they hard-set `allow_live_sensors:false`.)
    if !crate::util::settings::live_radar_enabled() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "live radar switched off",
                "detail": "the live-sensor radar is armed by default but has been switched off",
                "enable": "re-arm it: set the feature.live_radar toggle on (CLI: hse config feature.live_radar on)",
            })),
        )
            .into_response();
    }
    let (target, opts) = radar_scan_spec();
    let sid = scan_id("radar", target.kind.canonical_str());
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    let store = Arc::clone(&s.store);
    let scan_db = scan.clone();
    if let Err(resp) = offload("db", move || store.upsert_scan(&scan_db)).await {
        return resp;
    }
    spawn_scan(&s, scan, target);
    info!(scan_id = %sid, "radar sweep queued — live device sensors (button activation)");
    (
        StatusCode::ACCEPTED,
        Json(json!({ "scan_id": sid, "status": "queued", "mode": "radar" })),
    )
        .into_response()
}

/// `POST /api/v1/radar/live` — start a CONTINUOUS autonomous live-sensor radar.
///
/// The single-button, zero-input radar: it takes **no body, no target, no seed,
/// no interval** — every parameter is fixed server-side. It starts a live
/// session that re-runs ONLY the on-device passive sensors
/// (`signal_radar`, `device_sensors`, `wifi_intel`, `cell_intel`, `local_net`)
/// on a loop, so the device's ambient signals — Wi-Fi APs, Bluetooth, cell
/// towers, the GPS/last-known fix and the local network — are enumerated in
/// real time as they appear and change (e.g. as the device moves). Purely
/// passive: depth 0 means no pivoting onto external/active modules, so nothing
/// but the device's own sensors ever runs. Returns the `live_id` to watch.
///
/// Armed by default: this endpoint is the deliberate activation, so no prior
/// opt-in is required. `allow_live_sensors` is set here (server-side); the
/// `feature.live_radar` toggle is a kill-switch that only refuses if explicitly
/// switched off. An ordinary scan can neither reach nor accidentally start it.
pub async fn radar_live(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    if !crate::util::settings::live_radar_enabled() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "live radar switched off",
                "detail": "the live-sensor radar is armed by default but has been switched off",
                "enable": "re-arm it: set the feature.live_radar toggle on (CLI: hse config feature.live_radar on)",
            })),
        )
            .into_response();
    }
    // No seed: the autonomous ambient survey. The sensors ignore the sentinel.
    let (target, opts) = radar_scan_spec();
    // Continuous, uncapped, radar-mode (one shared ledger across sweeps). The
    // interval is the product default — no operator input.
    let live = crate::core::live::LiveOptions {
        radar: true,
        ..Default::default()
    };
    let live_id = s.live.start(target, opts, live);
    info!(live_id = %live_id, "continuous radar started — autonomous passive-sensor enumeration");
    (
        StatusCode::ACCEPTED,
        Json(json!({ "live_id": live_id, "status": "running", "mode": "radar" })),
    )
        .into_response()
}

/// `GET /api/v1/radar/history?limit=<n>` — chronological (newest-first) list
/// of past radar sweeps for historical review.
///
/// Unlike `GET /api/v1/live` (which only shows sessions still held in the
/// server's in-memory `LiveSession` map — cleared on every restart), this
/// reads directly from the persisted `scans` table: every sweep a `radar`/
/// `radar/live` call ever queued survives a restart here, so an operator
/// reconstructing "what was around me" after the fact doesn't need to
/// remember a session id — only that a radar sweep ran at some point. This
/// is the sole purpose-built historical-review surface for the live radar
/// feature (`docs/PROBLEM_TREE.md`/`docs/SOLUTION_TREE.md`: personal-safety
/// / situational-awareness review under limited information).
pub async fn radar_history(
    State(s): State<Arc<AppState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let limit: usize = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(100)
        .clamp(1, 1000);
    let store = Arc::clone(&s.store);
    match offload("db", move || store.radar_history(limit)).await {
        Ok(scans) => ok_list("sweeps", scans),
        Err(resp) => resp,
    }
}

/// `GET /api/v1/radar/recurring?min=2&limit=100` — cross-sweep persistent-device
/// review. Walks the radar sweep history (`radar_history`) and reports the
/// devices that recur across ≥`min` distinct sweeps, counting ONLY
/// universally-administered (real hardware) MACs the operator's phone is NOT
/// bonded to — a randomized privacy address rotates and can't recur, and the
/// operator's own paired kit (AU-117) is not a foreign tail. What survives is an
/// UNKNOWN persistent device seen across multiple sweeps: a fixed installation
/// the operator keeps passing, or a device that tracks their movement. This is
/// the counter-surveillance view a single per-scan correlation can never give —
/// it needs the whole sweep history. All analysis is the pure, offline
/// [`crate::core::radar_track`] primitive.
pub async fn radar_recurring(
    State(s): State<Arc<AppState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    use crate::core::entity::EntityKind;
    use crate::core::radar_track::{Sweep, SweepObservation, recurring_devices};

    let limit: usize = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(100)
        .clamp(1, 1000);
    let min_sweeps: usize = params.get("min").and_then(|v| v.parse().ok()).unwrap_or(2);

    // Off-reactor: one `radar_history` plus up to `limit` (≤1000) sequential
    // `entities_for_scan` reads under the global SQLite mutex, then the pure
    // offline analysis — all on a blocking thread. Walking a deep sweep history
    // inline would stall the 2-worker async reactor and starve SSE keep-alives /
    // `/health`, so this follows the off-reactor discipline every sibling here
    // already uses.
    let store = Arc::clone(&s.store);
    match offload("query", move || -> crate::core::error::Result<_> {
        let scans = store.radar_history(limit)?;
        let mut sweeps: Vec<Sweep> = Vec::with_capacity(scans.len());
        for scan in &scans {
            // A single unreadable sweep must not abort the whole review.
            let Ok(entities) = store.entities_for_scan(&scan.id) else {
                continue;
            };
            let devices: Vec<SweepObservation> = entities
                .iter()
                .filter(|e| {
                    e.kind == EntityKind::MacAddress
                        && (e.has_tag("bluetooth") || e.has_tag(crate::core::tags::WIFI_AP))
                })
                .map(|e| {
                    let name = e
                        .evidence
                        .iter()
                        .find_map(|ev| {
                            ev.attributes
                                .get("name")
                                .or_else(|| ev.attributes.get("ssid"))
                        })
                        .map(String::to_string);
                    SweepObservation {
                        mac: e.value.clone(),
                        name,
                        bonded: e.has_tag("bond:bonded"),
                    }
                })
                .collect();
            sweeps.push(Sweep {
                scan_id: scan.id.clone(),
                ts: scan.started_at,
                devices,
            });
        }
        Ok(recurring_devices(&sweeps, min_sweeps))
    })
    .await
    {
        Ok(devices) => ok_list("devices", devices),
        Err(resp) => resp,
    }
}
