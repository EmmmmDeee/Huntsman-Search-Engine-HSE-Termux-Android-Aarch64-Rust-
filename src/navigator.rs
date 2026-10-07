//! ATT&CK Navigator layer. Techniques appear only when a ledger entry admits interop.
//! A catalog row is not a score.

use serde_json::{Value, json};

use crate::attack::{Coverage, attack_spec_major, reconnaissance_spec_major};
use crate::ledger::{LedgerEntry, bindings};

#[must_use]
pub fn layer(entries: &[LedgerEntry]) -> Value {
    layer_with(entries, bindings())
}

/// Layer against an explicit binding table, so the exporter shape is testable.
#[must_use]
pub fn layer_with(entries: &[LedgerEntry], bindings: &[(&str, &str)]) -> Value {
    let mut techniques = Vec::new();
    for entry in entries
        .iter()
        .filter(|e| e.claim.admits_interop_with(bindings))
    {
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
        "versions": {"attack": attack_spec_major(), "navigator": "4.9", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Generated only from admitted ledger entries. Absence is not a zero score.",
        "techniques": techniques
    })
}

/// Reconnaissance coverage layer over the explicit ATT&CK catalogue.
#[must_use]
pub fn coverage_layer(coverage: &Coverage, scan_label: &str) -> Value {
    let max_score = coverage
        .covered
        .iter()
        .map(|item| item.entity_count)
        .max()
        .unwrap_or(0)
        .max(1);
    let mut techniques: Vec<Value> = coverage
        .covered
        .iter()
        .map(|item| {
            json!({
                "techniqueID": item.technique.id,
                "tactic": "reconnaissance",
                "score": item.entity_count,
                "enabled": true,
                "comment": item.technique.name,
            })
        })
        .collect();
    for item in &coverage.uncovered {
        techniques.push(json!({
            "techniqueID": item.id,
            "tactic": "reconnaissance",
            "score": 0,
            "enabled": false,
            "comment": item.name,
        }));
    }
    json!({
        "name": format!("huntsman-recon — {scan_label} (Reconnaissance coverage)"),
        "versions": { "attack": reconnaissance_spec_major(), "navigator": "5.1.0", "layer": "4.5" },
        "domain": "enterprise-attack",
        "description": "Reconnaissance-only coverage view. Disabled techniques are honest gaps.",
        "sorting": 3,
        "hideDisabled": false,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#66b1ff", "#0d4a90"],
            "minValue": 0,
            "maxValue": max_score
        },
        "legendItems": [],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attack;
    use crate::ledger::{Claim, seal};
    use crate::stage::{EvidenceLevel, Status};

    #[test]
    fn bound_entry_scores_only_its_technique() {
        let entry = seal(&Claim {
            claim: "bound".into(),
            source: "test".into(),
            component: "src/x.rs".into(),
            technique_id: Some("T1595.001".into()),
            status: Status::Verified,
            evidence_level: EvidenceLevel::DirectObservation,
            does_not_show: "not a live scan".into(),
        });
        let value = layer_with(std::slice::from_ref(&entry), &[("src/x.rs", "T1595.001")]);
        let techniques = value["techniques"].as_array().unwrap();
        assert_eq!(techniques.len(), 1);
        assert_eq!(techniques[0]["techniqueID"], "T1595.001");
        let parent_only = layer_with(&[entry], &[("src/x.rs", "T1595")]);
        let techniques = parent_only["techniques"].as_array().unwrap();
        assert!(techniques.is_empty(), "{techniques:?}");
    }

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
        let techniques = value["techniques"].as_array().unwrap();
        assert!(techniques.is_empty(), "{techniques:?}");
    }

    #[test]
    fn layer_uses_catalog_attack_major_version() {
        let entry = seal(&Claim {
            claim: "bound".into(),
            source: "test".into(),
            component: "src/x.rs".into(),
            technique_id: Some("T1595.001".into()),
            status: Status::Verified,
            evidence_level: EvidenceLevel::DirectObservation,
            does_not_show: "not a live scan".into(),
        });
        let value = layer_with(&[entry], &[("src/x.rs", "T1595.001")]);
        assert_eq!(value["versions"]["attack"], attack::attack_spec_major());
    }

    #[test]
    fn coverage_layer_emits_covered_and_gap_techniques() {
        let mut exercised = std::collections::BTreeMap::new();
        exercised.insert("T1596.002".to_string(), 5);
        let coverage = attack::coverage(&exercised);
        let value = coverage_layer(&coverage, "scan-abc");
        assert_eq!(
            value["versions"]["attack"],
            attack::reconnaissance_spec_major()
        );
        let techniques = value["techniques"].as_array().unwrap();
        assert_eq!(techniques.len(), attack::reconnaissance().len());
        let whois = techniques
            .iter()
            .find(|item| item["techniqueID"] == "T1596.002")
            .unwrap();
        assert_eq!(whois["score"], 5);
        assert_eq!(whois["enabled"], true);
        let phishing = techniques
            .iter()
            .find(|item| item["techniqueID"] == "T1598")
            .unwrap();
        assert_eq!(phishing["score"], 0);
        assert_eq!(phishing["enabled"], false);
        assert_eq!(value["gradient"]["maxValue"], 5);
    }
}
