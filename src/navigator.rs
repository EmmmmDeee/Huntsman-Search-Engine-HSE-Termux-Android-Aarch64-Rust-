//! ATT&CK Navigator layer. Techniques appear only when a ledger entry admits interop.
//! A catalog row is not a score.

use serde_json::{Value, json};

use crate::ledger::LedgerEntry;

#[must_use]
pub fn layer(entries: &[LedgerEntry]) -> Value {
    let mut techniques = Vec::new();
    for entry in entries.iter().filter(|e| e.claim.admits_interop()) {
        let Some(id) = entry.claim.technique_id.clone() else {
            continue;
        };
        techniques.push(json!({
            "techniqueID": id,
            "score": 1,
            "comment": format!("{} | {} | {}", entry.hash, entry.claim.component, entry.claim.does_not_show),
            "enabled": true
        }));
    }
    json!({
        "name": "huntsman-ledger",
        "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Generated only from admitted ledger entries. Absence is not a zero score.",
        "techniques": techniques
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{Claim, seal};
    use crate::stage::{EvidenceLevel, Status};

    #[test]
    fn catalog_only_claim_is_absent() {
        let mapped = seal(&Claim {
            claim: "appears in ATT&CK".into(),
            source: "catalog".into(),
            component: String::new(),
            technique_id: Some("T1589".into()),
            status: Status::Verified,
            evidence_level: EvidenceLevel::Assertion,
            does_not_show: "no method".into(),
        });
        let value = layer(&[mapped]);
        assert!(value["techniques"].as_array().unwrap().is_empty());
    }
}
