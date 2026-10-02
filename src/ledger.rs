//! Hash-chained evidence ledger. Each hash covers the previous hash plus the claim.
//! A dropped or reordered entry breaks `chain_intact`. Interop is still a binding, not a label.

use serde::{Deserialize, Serialize};

use crate::sha256::{hex32, sha256};
use crate::stage::{EvidenceLevel, Status};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub claim: String,
    pub source: String,
    pub component: String,
    pub technique_id: Option<String>,
    pub status: Status,
    pub evidence_level: EvidenceLevel,
    pub does_not_show: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub prev: String,
    pub hash: String,
    pub claim: Claim,
}

impl Claim {
    /// Verified capability may exist without a technique score.
    /// Interop requires a binding this crate implements, not a caller-supplied id.
    #[must_use]
    pub fn admits_interop(&self) -> bool {
        self.status == Status::Verified
            && self.evidence_level.admits_interop()
            && !self.component.trim().is_empty()
            && self
                .technique_id
                .as_deref()
                .is_some_and(|id| valid_technique(id) && method_implements(&self.component, id))
            && !self.does_not_show.trim().is_empty()
    }
}

/// Component path to technique id. Empty until a function in this crate performs that technique.
/// Haversine is not T1591. Challenge classification is not T1592.
const BINDINGS: &[(&str, &str)] = &[];

#[must_use]
pub fn method_implements(component: &str, technique: &str) -> bool {
    BINDINGS.iter().any(|(path, id)| *path == component && *id == technique)
}

#[must_use]
pub fn valid_technique(id: &str) -> bool {
    let rest = id.strip_prefix('T').unwrap_or("");
    let (base, sub) = rest.split_once('.').unwrap_or((rest, ""));
    (4..=5).contains(&base.len())
        && base.chars().all(|c| c.is_ascii_digit())
        && (sub.is_empty() || (sub.len() == 3 && sub.chars().all(|c| c.is_ascii_digit())))
}

#[must_use]
pub fn seal(claim: &Claim) -> LedgerEntry {
    append(GENESIS, claim)
}

#[must_use]
pub fn append(prev: &str, claim: &Claim) -> LedgerEntry {
    let canonical = format!(
        "{prev}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        claim.claim,
        claim.source,
        claim.component,
        claim.technique_id.clone().unwrap_or_default(),
        claim.status.as_str(),
        claim.evidence_level.as_str(),
        claim.does_not_show
    );
    LedgerEntry {
        prev: prev.to_owned(),
        hash: hex32(&sha256(canonical.as_bytes())),
        claim: claim.clone(),
    }
}

#[must_use]
pub fn chain_intact(entries: &[LedgerEntry]) -> bool {
    let mut prev = GENESIS;
    for entry in entries {
        if entry.prev != prev {
            return false;
        }
        if append(prev, &entry.claim).hash != entry.hash {
            return false;
        }
        prev = entry.hash.as_str();
    }
    true
}

#[must_use]
pub fn admitted<'a>(entries: &'a [LedgerEntry]) -> Vec<&'a LedgerEntry> {
    entries.iter().filter(|e| e.claim.admits_interop()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(status: Status, level: EvidenceLevel, technique: Option<&str>) -> Claim {
        Claim {
            claim: "haversine band holds".into(),
            source: "tests/geoint".into(),
            component: "src/geoint.rs".into(),
            technique_id: technique.map(str::to_owned),
            status,
            evidence_level: level,
            does_not_show: "not survey grade".into(),
        }
    }

    #[test]
    fn hash_changes_when_claim_changes_and_gate_rejects_unverified() {
        let a = seal(&sample(Status::Verified, EvidenceLevel::DirectObservation, Some("T1595")));
        let mut other = sample(Status::Verified, EvidenceLevel::DirectObservation, Some("T1595"));
        other.claim = "different".into();
        let b = seal(&other);
        assert_ne!(a.hash, b.hash);
        assert!(!a.claim.admits_interop(), "unbound technique must not score");
        let weak = seal(&sample(
            Status::Unverified,
            EvidenceLevel::EndToEndDemonstration,
            Some("T1595"),
        ));
        assert!(!weak.claim.admits_interop());
        let no_tech = seal(&sample(Status::Verified, EvidenceLevel::Reproduction, None));
        assert!(!no_tech.claim.admits_interop());
    }

    #[test]
    fn reorder_breaks_the_chain() {
        let first = seal(&sample(Status::Verified, EvidenceLevel::DirectObservation, None));
        let mut second_claim = sample(Status::Partial, EvidenceLevel::PrimaryEvidence, None);
        second_claim.claim = "second".into();
        let second = append(&first.hash, &second_claim);
        assert!(chain_intact(&[first.clone(), second.clone()]));
        assert!(!chain_intact(&[second, first]));
    }
}
