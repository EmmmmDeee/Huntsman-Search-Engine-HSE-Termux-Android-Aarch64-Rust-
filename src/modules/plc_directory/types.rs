//! Wire types for `plc.directory`, AT Protocol handle resolution, and the DID
//! document a `did:web` host serves.
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
    /// The handle this operation claims, in either shape, `at://` stripped —
    /// at most one: [`claimed_handle`] of `alsoKnownAs`, or the legacy shape's
    /// `handle` field.
    pub(super) fn handles(&self) -> Vec<&str> {
        if !self.also_known_as.is_empty() {
            return claimed_handle(&self.also_known_as).into_iter().collect();
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

/// A DID document, as a `did:web` host serves it from `/.well-known/did.json`.
///
/// Only the two fields that confirm an identity are read. `id` is the DID the
/// document is for: the did:web method's resolution step is to "verify that the
/// ID of the resolved DID document matches the Web DID being resolved".
/// `alsoKnownAs` is where an AT Protocol account claims its handle, as an
/// `at://` URI — the same field a PLC operation carries.
#[derive(Deserialize)]
pub(super) struct DidDocument {
    #[serde(default)]
    pub(super) id: Option<String>,
    #[serde(rename = "alsoKnownAs", default)]
    pub(super) also_known_as: Vec<String>,
}

impl DidDocument {
    /// True if this is the document `did` resolves to and, when the identity was
    /// reached through `handle`, it claims that handle back.
    ///
    /// Case-insensitive on both: the scan seed is case-folded before it gets
    /// here, and handles are case-insensitive in AT Protocol.
    pub(super) fn confirms(&self, did: &str, handle: Option<&str>) -> bool {
        self.id
            .as_deref()
            .is_some_and(|id| id.trim().eq_ignore_ascii_case(did))
            && handle.is_none_or(|want| {
                claimed_handle(&self.also_known_as)
                    .is_some_and(|h| h.eq_ignore_ascii_case(want.trim()))
            })
    }
}

/// The handle an `alsoKnownAs` list claims, `at://` stripped. **Pure.**
///
/// The AT Protocol DID spec (<https://atproto.com/specs/did>): "The first
/// syntactically valid handle found in the ordered list is treated as the
/// claimed handle, even if it fails to resolve bi-directionally. Any other
/// handle URIs should be ignored." Taking any entry let a document claiming
/// `other.example` first confirm a lookup for its later alias `wanted.example`
/// (REQ-PLC-002 review round). Syntax is [`crate::util::atproto::is_handle`];
/// an entry in another URI scheme is not a handle.
fn claimed_handle(also_known_as: &[String]) -> Option<&str> {
    also_known_as
        .iter()
        .filter_map(|aka| aka.trim().strip_prefix("at://"))
        .find(|h| crate::util::atproto::is_handle(h))
}
