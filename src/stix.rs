//! STIX 2.1 bundle generated only from ledger entries that pass the interop gate.
//! Ids are deterministic from the entry hash. Empty admission yields an empty object list.

use serde_json::{Value, json};

use crate::ledger::LedgerEntry;

#[must_use]
pub fn bundle(entries: &[LedgerEntry]) -> Value {
    let mut objects = Vec::new();
    for entry in entries.iter().filter(|e| e.claim.admits_interop()) {
        let id = stix_id(&entry.hash);
        objects.push(json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": id,
            "created": "2026-10-02T00:00:00.000Z",
            "modified": "2026-10-02T00:00:00.000Z",
            "name": entry.claim.claim,
            "pattern_type": "stix",
            "pattern": format!("[file:name = '{}']", entry.claim.component.replace('\'', "")),
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
