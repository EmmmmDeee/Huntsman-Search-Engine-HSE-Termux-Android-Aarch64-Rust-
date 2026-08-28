//! Wire types for `plc.directory` and AT Protocol handle resolution.
//!
//! Everything optional and everything defaulted. A PLC audit log spans four
//! years of protocol evolution — the earliest entries use a `create` operation
//! that no longer exists, later ones a `plc_operation`, and a deleted account
//! ends in a `plc_tombstone` carrying almost no fields at all. A struct that
//! insisted on any of them would fail to deserialise the whole log because of
//! one 2022 record, losing the history rather than the field.

use serde::Deserialize;

/// `com.atproto.identity.resolveHandle` — handle → DID.
#[derive(Deserialize)]
pub(super) struct ResolvedHandle {
    pub(super) did: String,
}

/// One entry in `GET /{did}/log/audit`.
#[derive(Deserialize)]
pub(super) struct AuditEntry {
    #[serde(default)]
    pub(super) operation: Option<PlcOperation>,
    #[serde(rename = "createdAt", default)]
    pub(super) created_at: Option<String>,
    /// `true` when this operation was later reverted through the PLC recovery
    /// window. A nullified operation never took effect, so its contents are not
    /// the account's history — but the fact one exists is itself a finding.
    #[serde(default)]
    pub(super) nullified: bool,
}

/// The signed operation inside an audit entry.
#[derive(Deserialize)]
pub(super) struct PlcOperation {
    /// `create` (legacy), `plc_operation`, or `plc_tombstone`.
    #[serde(rename = "type", default)]
    pub(super) op_type: Option<String>,

    // --- modern `plc_operation` shape ---
    /// Handles as `at://` URIs, e.g. `at://alice.bsky.social`.
    #[serde(rename = "alsoKnownAs", default)]
    pub(super) also_known_as: Vec<String>,
    #[serde(default)]
    pub(super) services: Option<Services>,
    /// Keys authorised to sign future operations for this DID. Correlating,
    /// but frequently the hosting provider's rather than the account holder's —
    /// see `super::ROTATION_KEY_CAVEAT`.
    #[serde(rename = "rotationKeys", default)]
    pub(super) rotation_keys: Vec<String>,

    // --- legacy `create` shape, still present at the head of older logs ---
    /// Bare handle (no `at://` prefix) on pre-2023 `create` operations.
    #[serde(default)]
    pub(super) handle: Option<String>,
    /// Single PDS endpoint on pre-2023 `create` operations.
    #[serde(default)]
    pub(super) service: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct Services {
    #[serde(rename = "atproto_pds", default)]
    pub(super) atproto_pds: Option<Service>,
}

#[derive(Deserialize)]
pub(super) struct Service {
    #[serde(default)]
    pub(super) endpoint: Option<String>,
}

impl PlcOperation {
    /// The handles this operation declares, in either shape, `at://` stripped.
    pub(super) fn handles(&self) -> Vec<&str> {
        if !self.also_known_as.is_empty() {
            return self
                .also_known_as
                .iter()
                .filter_map(|aka| aka.strip_prefix("at://").map(str::trim))
                .filter(|h| !h.is_empty())
                .collect();
        }
        self.handle
            .as_deref()
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .into_iter()
            .collect()
    }

    /// The PDS endpoint URL this operation declares, in either shape.
    pub(super) fn pds_endpoint(&self) -> Option<&str> {
        self.services
            .as_ref()
            .and_then(|s| s.atproto_pds.as_ref())
            .and_then(|s| s.endpoint.as_deref())
            .or(self.service.as_deref())
            .map(str::trim)
            .filter(|e| !e.is_empty())
    }

    /// `true` if this operation deletes the DID.
    pub(super) fn is_tombstone(&self) -> bool {
        self.op_type.as_deref() == Some("plc_tombstone")
    }
}
