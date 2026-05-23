//! Shared HTTP client builder. Rustls-only — no native TLS, no openssl,
//! no native deps at all. Default timeout matches `MODULE_TIMEOUT_MS`.

use std::time::Duration;

use crate::MODULE_TIMEOUT_MS;

/// Build a fresh reqwest client. Cheap to call per scan.
///
/// User-Agent uses the conventional `name/version (+url)` form. Bare
/// short UAs like `HSE/0.8.0` are frequently rejected by anti-bot WAFs
/// (HudsonRock's cavalier API among them — observed returning HTTP 400
/// on Termux). The `+https://` contact link is the format recommended
/// by RFC 7231 §5.5.3 and accepted by most rate-limiters.
pub fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(MODULE_TIMEOUT_MS))
        .user_agent(concat!(
            "huntsman-search-engine/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-)"
        ))
        .build()
        .expect("reqwest client build failed")
}

/// Read up to 200 characters of a non-success response body, trim, and
/// return a single-line string safe to embed in an error message.
///
/// Returns `"<empty>"` when the body is empty, `"<unreadable>"` if the
/// body couldn't be decoded. Consumes the response.
///
/// Use this everywhere a module returns `Error::module(name, "HTTP …")`
/// so the user sees the upstream's actual error payload rather than a
/// bare status code.
pub async fn error_snippet(resp: reqwest::Response) -> String {
    match resp.text().await {
        Ok(body) => {
            let trimmed = body.trim();
            if trimmed.is_empty() {
                "<empty>".to_string()
            } else {
                // Collapse newlines so the snippet stays a single log line,
                // then truncate at 200 chars to keep events compact.
                trimmed
                    .replace(['\n', '\r'], " ")
                    .chars()
                    .take(200)
                    .collect()
            }
        }
        Err(_) => "<unreadable>".to_string(),
    }
}
