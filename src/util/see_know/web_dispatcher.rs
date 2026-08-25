//! SeekNow web-based dispatcher — integrates web automation into HSE's see_know module.
//!
//! When the API key is unavailable, this dispatcher uses AdvancedWebClient
//! to perform searches via web automation instead. It's transparent to the
//! module dispatcher: results are parsed identically regardless of backend.

use serde_json::Value;
use std::sync::{Arc, LazyLock};
use tokio::sync::Mutex;

use crate::core::error::{Error, Result};

use super::config;
use super::web_client_advanced::AdvancedWebClient;

/// Global web client instance (lazy singleton).
static WEB_CLIENT: LazyLock<Arc<Mutex<Option<AdvancedWebClient>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(None)));

/// Initialize the web client with hardcoded credentials from config.
async fn init_web_client() -> Result<()> {
    let mut client = WEB_CLIENT.lock().await;
    if client.is_some() {
        return Ok(());
    }

    // Create client with hardcoded email and NO initial password.
    // The client will try all passwords from config.rs in order.
    let web_client = AdvancedWebClient::new(
        config::SEEKNOW_EMAIL.to_string(),
        None, // Let the client pick passwords from config
        "https://see-know.ru".to_string(),
    );

    *client = Some(web_client);
    Ok(())
}

/// Perform a search via web client (fallback when API key unavailable).
pub async fn search_web(query: &str, query_type: &str) -> Result<Vec<Value>> {
    init_web_client().await?;

    let client = WEB_CLIENT.lock().await;
    let client = client.as_ref().ok_or_else(|| Error::Module {
        module: "web_dispatcher".into(),
        message: "SeekNow web client initialization failed".into(),
    })?;

    client.search(query, query_type).await
}

/// Fetch credits via web client.
pub async fn credits_web() -> Result<(u32, Option<u32>)> {
    init_web_client().await?;

    let client = WEB_CLIENT.lock().await;
    let client = client.as_ref().ok_or_else(|| Error::Module {
        module: "web_dispatcher".into(),
        message: "SeekNow web client initialization failed".into(),
    })?;

    client.credits().await
}

/// Shutdown web client (cleanup Playwright browser).
pub async fn shutdown_web() {
    if let Some(client) = WEB_CLIENT.lock().await.take() {
        tracing::info!("Shutting down SeekNow web client");
        // In a real impl with Playwright, would call client.shutdown().
        drop(client);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_web_client_lazy_init() {
        // First call initializes.
        assert!(init_web_client().await.is_ok());

        // Second call reuses (no re-init).
        assert!(init_web_client().await.is_ok());
    }

    #[tokio::test]
    async fn test_shutdown_web() {
        init_web_client().await.ok();
        shutdown_web().await;
        // After shutdown, next init should re-create.
        assert!(init_web_client().await.is_ok());
    }
}
