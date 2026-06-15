//! Serde types for the DeHashed v2 API responses.

use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct DehashedResp {
    #[serde(default)]
    pub(super) entries: Option<Vec<Entry>>,
    #[serde(default)]
    pub(super) total: Option<u64>,
    /// Remaining API credits after the call (v2 reports this top-level). Held
    /// as a raw JSON value so a number-or-string wire shape both render; it is
    /// operator-info only and never gates logic.
    #[serde(default)]
    pub(super) balance: Option<serde_json::Value>,
}

/// Aggregate-safe subset of a v2 entry — `password`, `hashed_password`, etc.
/// are deliberately NOT bound so we can't even accidentally surface them. v2
/// returns most fields as arrays (e.g. `"database_name": ["Collection1"]`), so
/// `database_name` is captured as a raw JSON value and flattened by
/// `db_names`, which tolerates a string, an array of strings, or null.
#[derive(Deserialize)]
pub(super) struct Entry {
    #[serde(default)]
    pub(super) database_name: serde_json::Value,
}
