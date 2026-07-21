//! Webhook notifications — POST scan results to external URLs on completion.
//!
//! Operators configure a webhook URL via ScanOptions or environment variable.
//! On scan completion (or correlation firing), the engine POSTs a JSON
//! payload to the URL with scan summary, entity count, and top findings.

use serde_json::json;

/// The scan-summary fields a [`notify_scan_complete`] webhook POST carries — a
/// borrowed view (no allocation) assembled by the engine at finalise.
pub struct WebhookPayload<'a> {
    /// The completed scan's id.
    pub scan_id: &'a str,
    /// The seed target's kind (`email`, `username`, …) and value.
    pub target_kind: &'a str,
    pub target_value: &'a str,
    /// How many entities the scan produced.
    pub entity_count: usize,
    /// Terminal scan status (`completed`, `cancelled`, …).
    pub status: &'a str,
    /// How many correlations fired.
    pub correlations_count: usize,
}

/// POST a `scan_complete` JSON notification to the operator's configured
/// `webhook_url`. Fire-and-forget: bounded to a 10-second timeout and **never
/// returns an error** — a failed or slow webhook logs and is dropped, so an
/// external endpoint can't stall or fail the scan. On error only the webhook
/// **host** is logged, never the full URL: a Slack/Discord-style webhook carries
/// its secret in the path, which must not leak into the `/api/v1/logs` ring buffer.
pub async fn notify_scan_complete(
    http: &reqwest::Client,
    webhook_url: &str,
    payload: &WebhookPayload<'_>,
) {
    let body = json!({
        "event": "scan_complete",
        "scan_id": payload.scan_id,
        "target_kind": payload.target_kind,
        "target_value": payload.target_value,
        "entity_count": payload.entity_count,
        "status": payload.status,
        "correlations_count": payload.correlations_count,
        "timestamp": crate::core::entity::unix_now(),
    });

    match http
        .post(webhook_url)
        .json(&body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(resp) => {
            tracing::info!(
                scan_id = payload.scan_id,
                status = %resp.status(),
                "webhook notification sent"
            );
        }
        Err(e) => {
            // Log only the host, never the full URL: a Slack/Discord-style
            // webhook carries its secret in the PATH, so `url = webhook_url`
            // would leak it into the loopback `/api/v1/logs` ring buffer.
            let host = webhook_url
                .split("://")
                .nth(1)
                .and_then(|rest| rest.split('/').next())
                .unwrap_or("<webhook>");
            // `.without_url()` strips the request URL from the reqwest error —
            // otherwise `%e`'s Display re-emits the full webhook URL (`… for url
            // (…/<secret>)`), re-leaking the path secret the `host`-only field
            // above was written to avoid. Same pattern as `RequestBuilderExt`.
            tracing::warn!(
                scan_id = payload.scan_id,
                webhook_host = host,
                error = %e.without_url(),
                "webhook notification failed"
            );
        }
    }
}

/// The operator's webhook URL from `HUNTSMAN_WEBHOOK_URL`, or `None` when unset or
/// empty — the env fallback when no per-scan webhook is configured in `ScanOptions`.
#[must_use]
pub fn webhook_url_from_env() -> Option<String> {
    std::env::var("HUNTSMAN_WEBHOOK_URL")
        .ok()
        .filter(|u| !u.is_empty())
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
