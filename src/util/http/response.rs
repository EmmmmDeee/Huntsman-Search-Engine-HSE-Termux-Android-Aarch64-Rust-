//! Standard HTTP response error handling.
//!
//! Provides a consistent pattern for handling API responses across modules:
//! check status, read body on error, deserialize, and convert to HSE error.

use reqwest::Response;
use serde::de::DeserializeOwned;

use crate::core::error::{Error, Result};

/// Handle an API response with consistent error path: check status, read body
/// if error, deserialize success case or convert error to HSE error type.
///
/// On HTTP error (non-2xx status), reads the response body (capped to 200 chars
/// for log output) and returns an `Error::module` with module name and truncated
/// body. On success, deserializes the JSON body to type `T`.
///
/// # Arguments
/// * `resp` — the reqwest `Response` object
/// * `module_name` — the module or source name (used for error attribution)
///
/// # Returns
/// * `Ok(T)` on success (2xx status and valid JSON)
/// * `Err` with module error on HTTP error or deserialization failure
///
/// # Example
/// ```ignore
/// let resp = ctx.http.get(&url).send().await?;
/// let data: ApiResponse = handle_api_response(resp, "my_module").await?;
/// ```
pub async fn handle_api_response<T: DeserializeOwned>(
    resp: Response,
    module_name: &str,
) -> Result<T> {
    let status = resp.status();

    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        let msg = if body.is_empty() {
            format!("{module_name}: HTTP {status}")
        } else {
            // Truncate to 200 chars for log readability
            let snippet = if body.len() > 200 {
                format!("{}...", &body[..200])
            } else {
                body.clone()
            };
            format!("{module_name}: HTTP {status} — {snippet}")
        };
        return Err(Error::module(module_name, msg));
    }

    resp.json::<T>()
        .await
        .map_err(|e| Error::module(module_name, e.to_string()))
}

/// Build an API URL with query parameters, properly encoded.
///
/// Takes a base URL and a slice of (key, value) parameter pairs, and returns
/// a fully-formed URL with all parameters properly URL-encoded.
///
/// # Arguments
/// * `base` — the base URL (e.g., `"https://api.example.com/search"`)
/// * `params` — slice of `(&str, &str)` query parameter pairs
///
/// # Returns
/// * `Ok(url_string)` on success
/// * `Err` if the base URL is invalid
///
/// # Example
/// ```ignore
/// let url = build_api_url(
///     "https://api.example.com/search",
///     &[("q", "foo"), ("limit", "10")]
/// )?;
/// // Returns: "https://api.example.com/search?q=foo&limit=10"
/// ```
pub fn build_api_url(base: &str, params: &[(&str, &str)]) -> Result<String> {
    let mut url =
        reqwest::Url::parse(base).map_err(|e| Error::Other(format!("Invalid base URL: {e}")))?;
    url.query_pairs_mut().extend_pairs(params);
    Ok(url.to_string())
}
