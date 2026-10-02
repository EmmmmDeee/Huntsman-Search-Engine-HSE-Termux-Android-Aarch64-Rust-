//! STIX 2.1 bundle generated only from ledger entries that pass the interop gate.
//! Ids are deterministic from the entry hash. Empty admission yields an empty object list.

use serde_json::{Value, json};

use crate::ledger::{LedgerEntry, bindings};

#[must_use]
pub fn bundle(entries: &[LedgerEntry]) -> Value {
    bundle_with(entries, bindings())
}

/// Bundle against an explicit binding table, so the exporter shape is testable.
#[must_use]
pub fn bundle_with(entries: &[LedgerEntry], bindings: &[(&str, &str)]) -> Value {
    let mut objects = Vec::new();
    for entry in entries
        .iter()
        .filter(|e| e.claim.admits_interop_with(bindings))
    {
        let id = stix_id(&entry.hash);
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
    json!({
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000001",
        "objects": objects
    })
}

/// STIX string literal: backslash and single quote are escaped, never dropped.
fn escape_literal(raw: &str) -> String {
    raw.replace('\\', "\\\\").replace('\'', "\\'")
}

fn stix_id(hash: &str) -> String {
    let h = format!("{hash:0<32}");
    format!(
        "indicator--{}-{}-4{}-8{}-{}",
        &h[0..8],
        &h[8..12],
        &h[13..16],
        &h[17..20],
        &h[20..32]
    )
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
        assert!(
            bundle_with(&[entry], &[])["objects"]
                .as_array()
                .unwrap()
                .is_empty()
        );
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
        assert!(objects.is_empty());
    }
}
