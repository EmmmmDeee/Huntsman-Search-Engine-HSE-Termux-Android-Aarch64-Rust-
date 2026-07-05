//! Handlers for `/api/v1/update/*`.
//!
//! * `GET  /api/v1/update/status`  — current update state (commits_behind,
//!   phase, last_checked, feature flags).
//! * `POST /api/v1/update/trigger` — kick off an immediate install (202
//!   Accepted; background task drives it, SPA polls status).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Serialize;
use serde_json::json;

use crate::api::{AppState, UpdateInfo, UpdatePhase};

/// Response body for `GET /api/v1/update/status`.
#[derive(Serialize)]
pub(crate) struct UpdateStatusResponse {
    commits_behind: Option<u64>,
    last_checked: u64,
    phase: &'static str,
    auto_update: bool,
    update_notify: bool,
}

/// `GET /api/v1/update/status` — snapshot of the current update state.
pub(crate) async fn get_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let info = state
        .update_info
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();
    let phase_str: &'static str = match &info.phase {
        UpdatePhase::Idle => "idle",
        UpdatePhase::Checking => "checking",
        UpdatePhase::Applying => "applying",
        UpdatePhase::Restarting => "restarting",
        UpdatePhase::Error(_) => "error",
    };
    Json(UpdateStatusResponse {
        commits_behind: info.commits_behind,
        last_checked: info.last_checked,
        phase: phase_str,
        auto_update: crate::util::settings::get_bool("feature.auto_update", true),
        update_notify: crate::util::settings::get_bool("feature.update_notify", true),
    })
}

/// Authorization gate for the update-trigger endpoint.
///
/// Triggering an update replaces the running binary in place, so it carries the
/// same loopback-only policy as key writes: only a client connecting from a
/// loopback address may invoke it. Returns the `403` response to send for a
/// non-loopback peer, or `None` when the call is allowed.
///
/// NB: this trusts the socket peer address. Behind a loopback-bound reverse
/// proxy every forwarded client appears as loopback — the same limitation the
/// settings-write handlers carry — so it is a localhost-architecture guard, not
/// an authenticated-caller check.
fn reject_non_loopback(peer: &SocketAddr) -> Option<(StatusCode, Json<serde_json::Value>)> {
    if peer.ip().is_loopback() {
        None
    } else {
        Some((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "update trigger is loopback-only" })),
        ))
    }
}

/// Atomically check whether an update can be started and, if so, claim it by
/// setting the phase to `Applying` — in the SAME lock acquisition as the
/// check. Returns `true` iff this call is the one that gets to proceed.
///
/// The check and the claim must never be split across two lock acquisitions:
/// if the phase were only flipped later (e.g. inside a spawned task, as it
/// used to be), two near-simultaneous callers could both observe `Idle`, both
/// pass, and both spawn an update — two concurrent `apply_update` runs (git
/// pull / cargo build / binary replace) racing each other, and potentially
/// two concurrent `self_restart()` calls. Making the read-then-write atomic
/// under one lock closes that window structurally rather than narrowing it.
fn try_start_update(update_info: &std::sync::Mutex<UpdateInfo>) -> bool {
    let mut info = update_info
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if matches!(info.phase, UpdatePhase::Applying | UpdatePhase::Restarting) {
        return false;
    }
    info.phase = UpdatePhase::Applying;
    true
}

/// `POST /api/v1/update/trigger` — manually kick off an update.
///
/// Returns 202 immediately and drives the update in a detached task.
/// Returns 403 for non-loopback callers (same policy as key writes).
/// Returns 409 if an update is already in progress.
pub(crate) async fn post_trigger(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    if let Some(rejection) = reject_non_loopback(&peer) {
        return rejection.into_response();
    }
    // Atomic check-and-claim: only one concurrent caller can win this.
    if !try_start_update(&state.update_info) {
        return StatusCode::CONFLICT.into_response();
    }

    // Spawn the update in a detached task — handler returns 202 immediately.
    // Phase is already `Applying` (set by `try_start_update` above), so no
    // second lock acquisition is needed before `apply_update` starts.
    let update_info = Arc::clone(&state.update_info);
    let state_for_restart = Arc::clone(&state);
    tokio::spawn(async move {
        match crate::cli::update::apply_update(None).await {
            Ok(()) => {
                if let Ok(mut info) = update_info.lock() {
                    info.phase = UpdatePhase::Restarting;
                }
                // Brief pause so the SPA can fetch the Restarting status before
                // the process image is replaced.
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                // `self_restart()`'s `exec()` atomically replaces the process
                // image with zero cooperative cancellation — drain in-flight
                // scans/live sessions first, exactly like the Ctrl-C/SIGTERM
                // shutdown path does, so a manually-triggered update doesn't
                // silently abandon whatever is running.
                crate::api::drain_in_flight_work(
                    &state_for_restart.cancellations,
                    &state_for_restart.live,
                    crate::api::SHUTDOWN_DRAIN_GRACE,
                )
                .await;
                crate::cli::update::self_restart();
            }
            Err(e) => {
                if let Ok(mut info) = update_info.lock() {
                    info.phase = UpdatePhase::Error(e.to_string());
                }
            }
        }
    });

    StatusCode::ACCEPTED.into_response()
}

#[cfg(test)]
mod tests {
    use super::{UpdateInfo, UpdatePhase, reject_non_loopback, try_start_update};
    use axum::http::StatusCode;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Mutex;

    #[test]
    fn try_start_update_admits_exactly_one_of_two_concurrent_callers() {
        // Simulates two near-simultaneous `POST /update/trigger` calls
        // (double-clicked button, or a client retrying a slow first response)
        // racing to read-then-write `phase`. The check-and-claim MUST be atomic
        // under one lock acquisition: if it were split into a separate "read
        // phase" step and a later "write Applying" step (as it used to be,
        // deferred into the spawned update task), both callers could observe
        // `Idle` and both would proceed, racing two concurrent installer runs.
        let info = Mutex::new(UpdateInfo::default());
        assert!(
            try_start_update(&info),
            "the first caller must be admitted and claim the update"
        );
        assert!(
            !try_start_update(&info),
            "a second, concurrent caller must be rejected — not race past the check \
             because the claim happens in a separate lock acquisition"
        );
        assert_eq!(
            info.lock().unwrap().phase,
            UpdatePhase::Applying,
            "phase must already be Applying by the time try_start_update returns true, \
             not deferred to a later task"
        );
    }

    #[test]
    fn try_start_update_rejects_while_restarting() {
        let info = Mutex::new(UpdateInfo {
            phase: UpdatePhase::Restarting,
            ..UpdateInfo::default()
        });
        assert!(!try_start_update(&info));
    }

    #[test]
    fn try_start_update_admits_after_error_or_idle() {
        for phase in [UpdatePhase::Idle, UpdatePhase::Error("boom".into())] {
            let info = Mutex::new(UpdateInfo {
                phase,
                ..UpdateInfo::default()
            });
            assert!(
                try_start_update(&info),
                "a prior error or idle state must not block a fresh trigger"
            );
        }
    }

    #[test]
    fn trigger_rejects_non_loopback_peers() {
        for ip in [
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED), // 0.0.0.0
        ] {
            let peer = SocketAddr::new(ip, 8080);
            let rejection = reject_non_loopback(&peer);
            assert!(rejection.is_some(), "{ip} must be rejected");
            assert_eq!(rejection.unwrap().0, StatusCode::FORBIDDEN);
        }
    }

    #[test]
    fn trigger_allows_loopback_peers() {
        for ip in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let peer = SocketAddr::new(ip, 8080);
            assert!(reject_non_loopback(&peer).is_none(), "{ip} must be allowed");
        }
    }
}
