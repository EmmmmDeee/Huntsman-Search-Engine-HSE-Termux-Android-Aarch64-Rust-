//! Typed domain error hierarchy for the storage layer.

/// Failure modes of the embedded graph store.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// The embedded `redb` backend rejected an operation (open, transaction, table, or commit).
    #[error("storage backend: {0}")]
    Backend(String),

    /// An entity could not be serialized to, or deserialized from, its stored byte value.
    #[error("entity serialization: {0}")]
    Serialization(String),

    /// The background writer has shut down and can no longer accept or acknowledge writes.
    #[error("background writer unavailable: {0}")]
    WriterUnavailable(String),
}

impl From<serde_json::Error> for StorageError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err.to_string())
    }
}
