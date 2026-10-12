//! Typed domain error hierarchy for the storage layer.

/// Failure modes of the embedded graph store.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// The embedded `redb` backend rejected an operation (open, transaction, table, or commit).
    ///
    /// Once a commit has failed this variant is latched: every later `put`, `sync` and
    /// `shutdown` on that store returns it until the store is reopened.
    #[error("storage backend: {0}")]
    Backend(String),

    /// An entity could not be serialized to, or deserialized from, its stored byte value.
    #[error("entity serialization: {0}")]
    Serialization(String),

    /// The background writer has shut down and can no longer accept or acknowledge writes.
    #[error("background writer unavailable: {0}")]
    WriterUnavailable(String),

    /// A [`StoreConfig`](crate::StoreConfig) value exceeds the ceiling this platform allows.
    #[error("storage config: {setting} = {requested} exceeds the maximum of {max}")]
    ConfigOutOfRange {
        /// The setting that was rejected (`cache_bytes` or `linger_millis`).
        setting: &'static str,
        /// The value that was requested.
        requested: u64,
        /// The largest value accepted.
        max: u64,
    },
}

impl From<serde_json::Error> for StorageError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err.to_string())
    }
}
