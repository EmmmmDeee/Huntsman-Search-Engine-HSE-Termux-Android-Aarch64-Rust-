//! HTTP handlers for live-mode sessions (continuous scanning + radar) — the
//! live-session surface, split out of `handlers` (which keeps the core
//! read/system + SSE endpoints) the same way `settings_handlers` carries the
//! configuration & secrets surface and `scan_handlers` carries the scan-data
//! surface.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use super::AppState;
use super::handlers::{bad_request, not_found, ok_list, sse_event_stream, validated_target};

/// Decode an operator-supplied live-scan body, rejecting any key `ScanOptions`
/// or `LiveOptions` does not define.
///
/// The live counterpart of `scan_request_from_json`, sharing its one
/// error-message authority. A live request carries TWO absent-tolerant option
/// objects, so both are checked: `options` holds the same six permissive-default
/// scope controls a scan request does, and `live` adds `iterations` — whose
/// `None` default this module documents as "run forever" — and `radar`, whose
/// `false` default is the API-heavier mode. A live session repeats, so each
/// silently-dropped control is multiplied over every sweep.
///
/// `LiveRequest.options`' own doc comment already required this: "Two spellings
/// of 'no preference' must mean the same thing, and live must match scan."
fn live_request_from_json(
    raw: serde_json::Value,
) -> Result<crate::core::live::LiveRequest, String> {
    super::handlers::reject_unknown_option_keys(
        &raw,
        "options",
        &crate::core::scan::known_option_keys(),
    )?;
    super::handlers::reject_unknown_option_keys(
        &raw,
        "live",
        &crate::core::live::known_live_option_keys(),
    )?;
    let mut req: crate::core::live::LiveRequest =
        serde_json::from_value(raw).map_err(|e| format!("malformed live request: {e}"))?;
    req.options = req
        .options
        .checked_for_request()
        .map_err(|e| e.to_string())?;
    Ok(req)
}

pub async fn live_create(
    State(s): State<Arc<AppState>>,
    // Raw JSON, not `Json<LiveRequest>`, so an option key neither options
    // struct defines is REJECTED rather than silently defaulted — see
    // `live_request_from_json`.
    Json(raw): Json<serde_json::Value>,
) -> impl IntoResponse {
    let req = match live_request_from_json(raw) {
        Ok(req) => req,
        Err(msg) => return bad_request(msg),
    };
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
) -> axum::response::Response {
    // A session this process does not know — it never existed, or the process
    // restarted and the in-memory sessions went with it — is a 404, not an open
    // stream that will never carry anything. `EventSource` does not retry a
    // non-200 answer, so a console reconnecting after a restart learns at once
    // that the session is gone (REQ-RESILIENCE-001) instead of sitting on a
    // silent pipe as "live".
    if s.live.get(&target_lid).is_none() {
        return not_found();
    }
    // A live session's stream carries both its own lifecycle events (emitted
    // under `scan_id == live_id`) and every per-iteration scan it spawned.
    let live = s.live.clone();
    sse_event_stream(&s.bus, move |event| {
        event.scan_id == target_lid || live.session_owns_scan(&target_lid, &event.scan_id)
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live_router() -> axum::Router {
        axum::Router::new()
            .route("/api/v1/live", axum::routing::post(live_create))
            .with_state(crate::api::test_state())
    }

    async fn post_live(body: &str) -> (u16, String) {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt as _;
        let resp = live_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/live")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .expect("should succeed"),
            )
            .await
            .expect("should succeed");
        let status = resp.status().as_u16();
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("should succeed");
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    /// REQ-SCANOPTS-002: the scan-scope control, on the seam REQ-SCANOPTS-001
    /// did not reach. Pre-fix this returned 202 and started a REPEATING active
    /// session for an operator who asked for a passive one.
    #[tokio::test]
    async fn live_create_rejects_a_misspelled_scan_scope_control() {
        let (status, body) =
            post_live(r#"{"value":"cloudflare.com","options":{"passive-only":true}}"#).await;
        assert_eq!(
            status, 400,
            "a misspelled scope control must not be accepted"
        );
        assert!(
            body.contains("passive-only") && body.contains("passive_only"),
            "the error must name the key and suggest the intended one, got: {body}"
        );
        assert!(
            body.contains("options"),
            "the error must say WHICH object was wrong, got: {body}"
        );
    }

    /// The live-only half: a misspelled `iterations` left `None`, which this
    /// module documents as "run forever". The error must name `live`, not
    /// `options`, or a two-object request cannot be diagnosed.
    #[tokio::test]
    async fn live_create_rejects_a_misspelled_iteration_bound() {
        let (status, body) =
            post_live(r#"{"value":"cloudflare.com","live":{"iteration":3}}"#).await;
        assert_eq!(status, 400, "a misspelled iterations must not run forever");
        assert!(
            body.contains("live key(s)") && body.contains("iteration"),
            "the error must name the live object and the key, got: {body}"
        );
    }

    /// CONTROL: the same request spelled correctly is still accepted. Without
    /// it, both tests above would also pass if the seam rejected everything —
    /// the over-correction that no rejection assertion can catch.
    #[tokio::test]
    async fn live_create_still_accepts_correctly_spelled_options() {
        let (status, body) = post_live(
            r#"{"value":"cloudflare.com","options":{"passive_only":true},"live":{"iterations":2}}"#,
        )
        .await;
        assert_eq!(status, 202, "a valid live request must still start: {body}");
    }

    /// CONTROL: an option-less live request — the documented bare shape — is
    /// unaffected.
    #[tokio::test]
    async fn live_create_still_accepts_a_bare_request() {
        let (status, body) = post_live(r#"{"value":"cloudflare.com"}"#).await;
        assert_eq!(status, 202, "a bare live request must still start: {body}");
    }
}
