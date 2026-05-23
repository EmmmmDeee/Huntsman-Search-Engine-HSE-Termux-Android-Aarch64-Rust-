//! Shared HTTP client builder. Rustls-only — no native TLS, no openssl,
//! no native deps at all. Default timeout matches `MODULE_TIMEOUT_MS`.

use std::time::Duration;

use crate::MODULE_TIMEOUT_MS;

/// Build a fresh reqwest client. Cheap to call per scan.
pub fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(MODULE_TIMEOUT_MS))
        .user_agent(concat!("HSE/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("reqwest client build failed")
}
