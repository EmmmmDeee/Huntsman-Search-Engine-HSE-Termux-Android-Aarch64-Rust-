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

use crate::api::{AppState, UpdatePhase};

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

/// `POST /api/v1/update/trigger` — manually kick off an update.
///
/// Returns 202 immediately and drives the update in a detached task.
/// Returns 403 for non-loopback callers (same policy as key writes).
/// Returns 409 if an update is already in progress.
pub(crate) async fn post_trigger(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    if !peer.ip().is_loopback() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "update trigger is loopback-only" })),
        )
            .into_response();
    }
    // Reject if already applying or restarting.
    {
        let info = state
            .update_info
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(info.phase, UpdatePhase::Applying | UpdatePhase::Restarting) {
            return StatusCode::CONFLICT.into_response();
        }
    }

    // Spawn the update in a detached task — handler returns 202 immediately.
    let update_info = Arc::clone(&state.update_info);
    tokio::spawn(async move {
        if let Ok(mut info) = update_info.lock() {
            info.phase = UpdatePhase::Applying;
        }
        match crate::cli::update::apply_update(None).await {
            Ok(()) => {
                if let Ok(mut info) = update_info.lock() {
                    info.phase = UpdatePhase::Restarting;
                }
                // Brief pause so the SPA can fetch the Restarting status before
                // the process image is replaced.
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
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
