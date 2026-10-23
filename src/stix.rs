//! STIX 2.1 bundle generated only from ledger entries that pass the interop gate.
//! Ids are deterministic from the entry hash. Empty admission yields an empty object list.

use serde_json::{Value, json};

use crate::ledger::{LedgerEntry, admitted_with, bindings};
use crate::sha256::{hex32, sha256};

#[must_use]
pub fn bundle(entries: &[LedgerEntry]) -> Value {
    bundle_with(entries, bindings())
}

/// Bundle against an explicit binding table, so the exporter shape is testable.
#[must_use]
pub fn bundle_with(entries: &[LedgerEntry], bindings: &[(&str, &str)]) -> Value {
    let mut objects = Vec::new();
    for entry in admitted_with(entries, bindings) {
        let Some(id) = stix_id(&entry.hash) else {
            continue;
        };
        objects.push(json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": id,
            "created": "2026-10-02T00:00:00.000Z",
            "modified": "2026-10-02T00:00:00.000Z",
            "name": entry.claim.claim,
            "pattern_type": "stix",
            "pattern": format!("[file:name = '{}']", escape_literal(&entry.claim.component)),
            "valid_from": "2026-10-02T00:00:00.000Z",
            "indicator_types": ["malicious-activity"],
            "confidence": 80,
            "external_references": [{
                "source_name": "huntsman-ledger",
                "external_id": entry.claim.technique_id,
                "description": entry.hash
            }]
        }));
    }
    let id = bundle_id(&objects);
    json!({
        "type": "bundle",
        "id": id,
        "objects": objects
    })
}

/// Derive a stable, content-specific identifier from the admitted STIX objects.
/// The empty-bundle identifier remains unchanged for historical consumers of
/// the zero-admission fixture. Different nonempty exports must never all claim
/// the same hard-coded identifier. This is a content fingerprint, not a
/// signature or a claim of independent verification.
fn bundle_id(objects: &[Value]) -> String {
    if objects.is_empty() {
        return "bundle--00000000-0000-4000-8000-000000000001".to_owned();
    }
    // serde_json::Value cannot contain non-serialisable Rust types.
    let encoded = serde_json::to_vec(objects).expect("STIX JSON objects are serialisable");
    let hash = hex32(&sha256(&encoded));
    format!(
        "bundle--{}-{}-4{}-8{}-{}",
        &hash[0..8],
        &hash[8..12],
        &hash[13..16],
        &hash[17..20],
        &hash[20..32]
    )
}

/// STIX string literal: backslash and single quote are escaped, never dropped.
fn escape_literal(raw: &str) -> String {
    raw.replace('\\', "\\\\").replace('\'', "\\'")
}

/// The indicator id for a ledger hash: its first 32 hex digits shaped as a version-4 UUID. `None`
/// for a hash that is not at least 32 hex digits (every sealed hash is 64): such an entry is left
/// out rather than given an id that is padded, shared with another short hash, or not a UUID.
fn stix_id(hash: &str) -> Option<String> {
    let h = hash
        .get(..32)
        .filter(|h| h.bytes().all(|byte| byte.is_ascii_hexdigit()))?;
    Some(format!(
        "indicator--{}-{}-4{}-8{}-{}",
        &h[0..8],
        &h[8..12],
        &h[13..16],
        &h[17..20],
        &h[20..32]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{Claim, seal};
    use crate::stage::{EvidenceLevel, Status};

    fn bound_entry(component: &str) -> LedgerEntry {
        seal(&Claim {
            claim: "bound".into(),
            source: "test".into(),
            component: component.into(),
            technique_id: Some("T1595".into()),
            status: Status::Verified,
            evidence_level: EvidenceLevel::DirectObservation,
            does_not_show: "not a live scan".into(),
        })
    }

    #[test]
    fn bundle_id_changes_with_admitted_content_but_is_stable_on_repeat() {
        let a = bound_entry("src/first.rs");
        let b = bound_entry("src/second.rs");
        let first = bundle_with(&[a.clone()], &[("src/first.rs", "T1595")]);
        let again = bundle_with(&[a], &[("src/first.rs", "T1595")]);
        let other = bundle_with(&[b], &[("src/second.rs", "T1595")]);
        assert_eq!(first, again, "same admitted evidence must export identically");
        assert_ne!(first["id"], other["id"], "different bundles need distinct identifiers");

        for id in [first["id"].as_str().unwrap(), other["id"].as_str().unwrap()] {
            let value = id.strip_prefix("bundle--").expect("STIX bundle id");
            let parts: Vec<&str> = value.split('-').collect();
            assert_eq!(parts.iter().map(|part| part.len()).collect::<Vec<_>>(), [8, 4, 4, 4, 12]);
            assert!(value.bytes().all(|byte| byte == b'-' || byte.is_ascii_hexdigit()));
            assert!(parts[2].starts_with('4'));
            assert!(parts[3].starts_with('8'));
        }
    }

    #[test]
    fn zero_admission_preserves_existing_empty_bundle_contract() {
        let empty = bundle_with(&[], &[("src/first.rs", "T1595")]);
        let unbound = bundle_with(&[bound_entry("src/first.rs")], &[]);
        assert_eq!(empty, unbound);
        assert_eq!(empty["id"], "bundle--00000000-0000-4000-8000-000000000001");
        assert_eq!(empty["objects"], json!([]));
    }

    #[test]
    fn an_entry_whose_hash_is_not_hex_is_left_out_not_a_panic_or_a_shared_id() {
        let binding = [("src/geoint.rs", "T1595")];
        for hash in [
            "é".repeat(20),
            "abc".to_owned(),
            String::new(),
            "z".repeat(64),
        ] {
            let mut entry = bound_entry("src/geoint.rs");
            entry.hash = hash;
            let value = bundle_with(&[entry], &binding);
            assert!(value["objects"].as_array().unwrap().is_empty());
        }
    }

    #[test]
    fn bound_entry_exports_a_well_formed_indicator() {
        let entry = bound_entry("src/it's\\x.rs");
        let value = bundle_with(std::slice::from_ref(&entry), &[("src/it's\\x.rs", "T1595")]);
        let objects = value["objects"].as_array().unwrap();
        assert_eq!(objects.len(), 1);
        let id = objects[0]["id"].as_str().unwrap();
        let uuid = id.strip_prefix("indicator--").unwrap();
        let parts: Vec<&str> = uuid.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            [8, 4, 4, 4, 12]
        );
        assert!(uuid.bytes().all(|c| c == b'-' || c.is_ascii_hexdigit()));
        assert!(parts[2].starts_with('4'), "{id}");
        assert!(parts[3].starts_with('8'), "{id}");
        assert_eq!(objects[0]["pattern"], r"[file:name = 'src/it\'s\\x.rs']");
        assert_eq!(objects[0]["external_references"][0]["external_id"], "T1595");
        let unbound = bundle_with(&[entry], &[]);
        let objects = unbound["objects"].as_array().unwrap();
        assert!(objects.is_empty(), "{objects:?}");
    }

    #[test]
    fn unbound_technique_does_not_enter_bundle() {
        let labeled = seal(&Claim {
            claim: "kept as a capability, not a technique".into(),
            source: "test".into(),
            component: "src/geoint.rs".into(),
            technique_id: Some("T1595".into()),
            status: Status::Verified,
            evidence_level: EvidenceLevel::DirectObservation,
            does_not_show: "not a live scan".into(),
        });
        let dropped = seal(&Claim {
            claim: "dropped".into(),
            source: "catalog".into(),
            component: "src/geoint.rs".into(),
            technique_id: Some("T1595".into()),
            status: Status::Partial,
            evidence_level: EvidenceLevel::DirectObservation,
            does_not_show: "mapped only".into(),
        });
        let objects = bundle(&[labeled, dropped])["objects"]
            .as_array()
            .unwrap()
            .clone();
        assert!(objects.is_empty(), "{objects:?}");
    }
}
