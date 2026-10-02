//! Hashed evidence ledger. Hash covers the claim canonical form, not the hash field.
//! Interop admission is a function, not a label the caller can set alone.

use serde::{Deserialize, Serialize};

use crate::sha256::{hex32, sha256};
use crate::stage::{EvidenceLevel, Status};

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
    pub hash: String,
    pub claim: Claim,
}

impl Claim {
    /// Verified, at or above direct observation, with a Rust path and a technique id.
    #[must_use]
    pub fn admits_interop(&self) -> bool {
        self.status == Status::Verified
            && self.evidence_level.admits_interop()
            && !self.component.trim().is_empty()
            && self.technique_id.as_deref().is_some_and(valid_technique)
            && !self.does_not_show.trim().is_empty()
    }
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
    let canonical = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}",
        claim.claim,
        claim.source,
        claim.component,
        claim.technique_id.clone().unwrap_or_default(),
        claim.status.as_str(),
        claim.evidence_level.as_str(),
        claim.does_not_show
    );
    LedgerEntry {
        hash: hex32(&sha256(canonical.as_bytes())),
        claim: claim.clone(),
    }
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
        assert!(a.claim.admits_interop());
        let weak = seal(&sample(Status::Unverified, EvidenceLevel::EndToEndDemonstration, Some("T1595")));
        assert!(!weak.claim.admits_interop());
        let no_tech = seal(&sample(Status::Verified, EvidenceLevel::Reproduction, None));
        assert!(!no_tech.claim.admits_interop());
    }
}
