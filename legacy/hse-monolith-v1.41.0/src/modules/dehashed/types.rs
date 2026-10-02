//! Serde types for the DeHashed v2 API responses.

use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct DehashedResp {
    /// The raw breach records, captured verbatim as JSON values. v2 returns a
    /// record's identity, credential, and location fields (email, username,
    /// name, password, `hashed_password`, ip_address, phone, address, …); we keep
    /// the WHOLE record so the per-record extractor can surface every field —
    /// including the password hash that DeHashed exists to provide and that the
    /// hash-reuse identity linker (AU-105) and reverse-search rely on. Non-target
    /// strangers from a broad search are demoted to quarantined `candidate` leads
    /// downstream, never deleted, so nothing is omitted.
    #[serde(default)]
    pub(super) entries: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub(super) total: Option<u64>,
    /// Remaining API credits after the call (v2 reports this top-level). Held
    /// as a raw JSON value so a number-or-string wire shape both render; it is
    /// operator-info only and never gates logic.
    #[serde(default)]
    pub(super) balance: Option<serde_json::Value>,
}
