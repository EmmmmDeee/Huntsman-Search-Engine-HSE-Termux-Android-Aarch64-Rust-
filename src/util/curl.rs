//! curl subprocess fallback for HTTP fetches.
//!
//! Some environments (cloud containers, sandboxes) block the binary's
//! outbound TLS but allow the system `curl` binary. This module
//! provides a `fetch` function that shells out to `curl` as a fallback
//! when reqwest fails, giving modules a reliable HTTP path.
//!
//! On Termux this is also useful: curl is always installed via `pkg`
//! and uses the system's OpenSSL/certificate store, which is often
//! more permissive than rustls's bundled webpki-roots.

use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// Fetch a URL via curl subprocess. Returns the response body on
/// success, None on any error (timeout, non-zero exit, missing curl).
pub async fn fetch(url: &str, timeout_ms: u64) -> Option<String> {
    let fut = Command::new("curl")
        .args([
            "-s",
            "--max-time", &(timeout_ms / 1000).max(3).to_string(),
            "-A", "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
            "-H", "Accept: text/html,application/xhtml+xml,application/json",
            "-H", "Accept-Language: en-US,en;q=0.9",
            "-L",
            "--",
            url,
        ])
        .kill_on_drop(true)
        .output();

    let output = timeout(Duration::from_millis(timeout_ms + 2000), fut)
        .await
        .ok()?
        .ok()?;

    if !output.status.success() {
        return None;
    }

    String::from_utf8(output.stdout).ok()
}

/// Fetch JSON from a URL via curl, deserialise as T.
pub async fn fetch_json<T: serde::de::DeserializeOwned>(url: &str, timeout_ms: u64) -> Option<T> {
    let body = fetch(url, timeout_ms).await?;
    serde_json::from_str(&body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fetch_returns_none_for_bad_url() {
        let r = fetch("https://256.256.256.256/nonexistent", 3000).await;
        assert!(r.is_none());
    }
}
