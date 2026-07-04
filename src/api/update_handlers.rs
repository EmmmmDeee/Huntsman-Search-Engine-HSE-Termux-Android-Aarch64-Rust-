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

/// Atomically claim the update slot. Returns `true` and transitions the phase to
/// [`UpdatePhase::Applying`] when no update is already applying/restarting;
/// returns `false` (leaving the phase untouched) otherwise. The check and the set
/// happen under ONE lock, so two concurrent triggers can't both observe an idle
/// phase and both start an update — the compare-and-set that closes the
/// check-then-act race. An `Error`/`Idle`/`Checking` phase is claimable (a failed
/// or never-run update can be retried).
fn try_claim_update(update_info: &std::sync::Mutex<UpdateInfo>) -> bool {
    let mut info = update_info
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if matches!(info.phase, UpdatePhase::Applying | UpdatePhase::Restarting) {
        false
    } else {
        info.phase = UpdatePhase::Applying;
        true
    }
}

/// `POST /api/v1/update/trigger` — manually kick off an update.
///
/// Returns 202 immediately and drives the update in a detached task.
/// Returns 403 for non-loopback callers (same policy as key writes).
/// Returns 409 if an update is already in progress.
pub(crate) async fn post_trigger(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // Cross-site guard: this body-less POST is a CORS simple request, so the
    // loopback check alone (a drive-by page connects from 127.0.0.1 too) does not
    // stop it forcing a binary rebuild + process restart. Require X-HSE-CSRF,
    // which a cross-origin caller cannot set without a preflight that fails.
    if let Some(rejection) = super::handlers::csrf_reject(&headers) {
        return rejection;
    }
    if let Some(rejection) = reject_non_loopback(&peer) {
        return rejection.into_response();
    }
    // Atomically claim the update slot: reject if one is already applying /
    // restarting, otherwise transition to `Applying` under the SAME lock. Setting
    // the phase here (not later in the spawned task) closes a check-then-act race
    // where two concurrent loopback triggers both passed the check and both ran
    // `apply_update` + `self_restart`.
    if !try_claim_update(&state.update_info) {
        return StatusCode::CONFLICT.into_response();
    }

    // Spawn the update in a detached task — handler returns 202 immediately. The
    // phase is already `Applying` (claimed above).
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
    use super::reject_non_loopback;
    use axum::http::StatusCode;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

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

    #[test]
    fn trigger_requires_the_csrf_header() {
        use axum::http::HeaderMap;
        // The loopback check is not enough: a drive-by page connects from
        // 127.0.0.1 too, and a body-less POST is a CORS simple request. The
        // X-HSE-CSRF guard (absent from the CORS allow-headers) is what blocks it.
        assert!(
            crate::api::handlers::csrf_reject(&HeaderMap::new()).is_some(),
            "a trigger POST without X-HSE-CSRF must be rejected"
        );
        let mut with_token = HeaderMap::new();
        with_token.insert("x-hse-csrf", "1".parse().unwrap());
        assert!(
            crate::api::handlers::csrf_reject(&with_token).is_none(),
            "the same-origin SPA's X-HSE-CSRF request is allowed"
        );
    }

    #[test]
    fn try_claim_update_is_a_single_winner_compare_and_set() {
        use super::{UpdateInfo, UpdatePhase, try_claim_update};
        use std::sync::Mutex;

        let info = Mutex::new(UpdateInfo::default()); // phase Idle
        // First trigger claims the slot and transitions to Applying.
        assert!(try_claim_update(&info), "the first trigger wins");
        assert_eq!(info.lock().unwrap().phase, UpdatePhase::Applying);
        // A second concurrent trigger is rejected while an update is in progress —
        // it can't also run apply_update + self_restart.
        assert!(
            !try_claim_update(&info),
            "a second trigger is rejected while applying"
        );
        // A failed update (Error) is retryable: the slot can be re-claimed.
        info.lock().unwrap().phase = UpdatePhase::Error("boom".into());
        assert!(try_claim_update(&info), "a failed update can be retried");
        assert_eq!(info.lock().unwrap().phase, UpdatePhase::Applying);
    }
}
