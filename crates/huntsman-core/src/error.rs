//! Unified domain error hierarchy.

/// Primary error variants for the Huntsman engine.
#[derive(Debug, thiserror::Error)]
pub enum HuntsmanError {
    /// Network or transport layer failures.
    #[error("Transport fault: {0}")]
    Transport(String),

    /// Violations of protocol specifications during decode.
    #[error("Protocol violation: {0}")]
    Protocol(String),

    /// Buffer exhaustion or decompression bomb mitigation.
    #[error("Exceeded memory buffer ceiling of {limit} bytes (read {attempted} bytes)")]
    BufferLimitExceeded {
        /// Configured hard threshold in bytes.
        limit: usize,
        /// Attempted read length in bytes.
        attempted: usize,
    },

    /// Circular dependency detected in the traversal graph.
    #[error("Cycle detected on entity: {0}")]
    CycleDetected(String),

    /// Channel saturation under backpressure.
    #[error("Pipeline backpressure channel exhausted: {0}")]
    ChannelCongestion(String),

    /// File descriptor or token bucket exhaustion.
    #[error("Resource rate-limited or exhausted: {0}")]
    RateLimited(String),

    /// Underlying storage or serialization failures.
    #[error("Storage/serialization failure: {0}")]
    Serialization(String),
}

impl From<serde_json::Error> for HuntsmanError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err.to_string())
    }
}

impl From<std::io::Error> for HuntsmanError {
    fn from(err: std::io::Error) -> Self {
        Self::Transport(err.to_string())
    }
}
