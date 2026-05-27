//! Webhook notifications — POST scan results to external URLs on completion.
//!
//! Operators configure a webhook URL via ScanOptions or environment variable.
//! On scan completion (or correlation firing), the engine POSTs a JSON
//! payload to the URL with scan summary, entity count, and top findings.

use serde_json::json;

pub struct WebhookPayload<'a> {
    pub scan_id: &'a str,
    pub target_kind: &'a str,
    pub target_value: &'a str,
    pub entity_count: usize,
    pub status: &'a str,
    pub correlations_count: usize,
}

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
                scan_id,
                status = %resp.status(),
                "webhook notification sent"
            );
        }
        Err(e) => {
            tracing::warn!(scan_id, url = webhook_url, error = %e, "webhook notification failed");
        }
    }
}

pub fn webhook_url_from_env() -> Option<String> {
    std::env::var("HUNTSMAN_WEBHOOK_URL")
        .ok()
        .filter(|u| !u.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_url_from_env_returns_none_when_unset() {
        // SAFETY: test runs single-threaded; no concurrent env access.
        unsafe { std::env::remove_var("HUNTSMAN_WEBHOOK_URL") };
        assert!(webhook_url_from_env().is_none());
    }
}
