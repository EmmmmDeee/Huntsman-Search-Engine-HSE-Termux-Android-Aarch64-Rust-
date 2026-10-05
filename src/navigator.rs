//! ATT&CK Navigator layers for the evidence ledger and TA0043 coverage.
//! Catalogue membership is metadata, not evidence of implementation.

use serde_json::{Value, json};

use crate::attack::{Coverage, reconnaissance_spec_major};
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
        "versions": {"attack": reconnaissance_spec_major(), "navigator": "4.9", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "TA0043 entries generated only from admitted ledger claims. Absence is not a zero score.",
        "techniques": techniques
    })
}

/// Reconnaissance leaf-capability layer. Parent techniques are roll-ups in the
/// `Coverage` object and are not emitted as independently scored techniques.
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
                "comment": format!("{} — observed capability evidence", item.technique.name),
            })
        })
        .collect();
    for item in &coverage.uncovered {
        techniques.push(json!({
            "techniqueID": item.id,
            "tactic": "reconnaissance",
            "score": 0,
            "enabled": false,
            "comment": format!("{} — capability gap", item.name),
        }));
    }
    for item in &coverage.intentional_exclusions {
        techniques.push(json!({
            "techniqueID": item.id,
            "tactic": "reconnaissance",
            "score": 0,
            "enabled": false,
            "comment": format!("{} — intentional product-scope exclusion", item.name),
        }));
    }
    json!({
        "name": format!("huntsman-recon — {scan_label} (Reconnaissance leaf capabilities)"),
        "versions": { "attack": reconnaissance_spec_major(), "navigator": "5.1.0", "layer": "4.5" },
        "domain": "enterprise-attack",
        "description": "TA0043 actionable-leaf capability view. Parent families are roll-ups, not independent scores. Disabled entries are gaps or intentional exclusions as stated in comments. Scores are observation counts, not detection effectiveness.",
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
    fn layer_uses_current_reconnaissance_major_version() {
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
        assert_eq!(
            value["versions"]["attack"],
            attack::reconnaissance_spec_major()
        );
    }

    #[test]
    fn coverage_layer_emits_exactly_actionable_leaves() {
        let mut exercised = std::collections::BTreeMap::new();
        exercised.insert("T1596.002".to_string(), 5);
        let coverage = attack::coverage(&exercised);
        let value = coverage_layer(&coverage, "scan-abc");
        assert_eq!(
            value["versions"]["attack"],
            attack::reconnaissance_spec_major()
        );
        let techniques = value["techniques"].as_array().unwrap();
        assert_eq!(techniques.len(), attack::reconnaissance_leaves().len());
        assert!(techniques.iter().all(|item| item["techniqueID"] != "T1596"));
        let whois = techniques
            .iter()
            .find(|item| item["techniqueID"] == "T1596.002")
            .unwrap();
        assert_eq!(whois["score"], 5);
        assert_eq!(whois["enabled"], true);
        let phishing = techniques
            .iter()
            .find(|item| item["techniqueID"] == "T1598.001")
            .unwrap();
        assert_eq!(phishing["score"], 0);
        assert_eq!(phishing["enabled"], false);
        assert!(phishing["comment"]
            .as_str()
            .unwrap()
            .contains("intentional product-scope exclusion"));
        let threat_vendor = techniques
            .iter()
            .find(|item| item["techniqueID"] == "T1681")
            .unwrap();
        assert!(threat_vendor["comment"]
            .as_str()
            .unwrap()
            .contains("capability gap"));
        assert_eq!(value["gradient"]["maxValue"], 5);
    }
}
