//! HTTP client abstraction for See-Know API
//!
//! Provides trait-based interface for HTTP operations, enabling:
//! - Real HTTP client (production)
//! - Mock client (testing)
//! - Response injection and failure simulation
//!
//! Phase 1.2 Implementation

use anyhow::Result;

pub mod error;
// pub mod real;
// pub mod mock;

pub use error::{HttpError, HttpErrorKind};

/// HTTP client trait for See-Know API interactions
///
/// Abstracts away the underlying HTTP implementation, enabling:
/// - Easy mocking for tests
/// - Dependency injection
/// - Response caching/transformation
///
/// Implementations: Real (reqwest), Mock (for testing)
#[async_trait::async_trait]
pub trait HttpClient: Send + Sync {
    /// Perform a GET request
    async fn get(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> Result<HttpResponse>;

    /// Perform a POST request
    async fn post(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse>;

    /// Perform a streaming download (for ZIP exports)
    async fn download(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> Result<Vec<u8>>;
}

/// HTTP response wrapper
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: std::collections::HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn text(&self) -> Result<String> {
        String::from_utf8(self.body.clone())
            .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in response: {}", e))
    }

    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body)
            .map_err(|e| anyhow::anyhow!("JSON parse error: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_response_text() {
        // TODO: Phase 1.2
        // Test text extraction
    }

    #[test]
    fn test_http_response_json() {
        // TODO: Phase 1.2
        // Test JSON deserialization
    }
}
