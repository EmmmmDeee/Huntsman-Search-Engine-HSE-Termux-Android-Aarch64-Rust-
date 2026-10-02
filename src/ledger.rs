//! Hash-chained evidence ledger. Each hash covers the previous hash plus the claim.
//! A dropped or reordered entry breaks `chain_intact`. Interop is still a binding, not a label.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::fsio::{read_bounded, write_atomic};
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

/// Hash preimage domain tag. Bump when the preimage layout changes.
const PREIMAGE_TAG: &[u8] = b"huntsman-ledger-v2";

/// Unambiguous preimage: every field is length-prefixed, and an absent technique
/// is distinct from an empty one. No field content can shift a field boundary.
fn preimage(prev: &str, claim: &Claim) -> Vec<u8> {
    fn field(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&(value.len() as u64).to_be_bytes());
        out.extend_from_slice(value);
    }
    let mut out = Vec::with_capacity(256);
    field(&mut out, PREIMAGE_TAG);
    field(&mut out, prev.as_bytes());
    field(&mut out, claim.claim.as_bytes());
    field(&mut out, claim.source.as_bytes());
    field(&mut out, claim.component.as_bytes());
    match &claim.technique_id {
        None => out.push(0),
        Some(id) => {
            out.push(1);
            field(&mut out, id.as_bytes());
        }
    }
    field(&mut out, claim.status.as_str().as_bytes());
    field(&mut out, claim.evidence_level.as_str().as_bytes());
    field(&mut out, claim.does_not_show.as_bytes());
    out
}

#[must_use]
pub fn append(prev: &str, claim: &Claim) -> LedgerEntry {
    LedgerEntry {
        prev: prev.to_owned(),
        hash: hex32(&sha256(&preimage(prev, claim))),
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
pub fn admitted(entries: &[LedgerEntry]) -> Vec<&LedgerEntry> {
    entries.iter().filter(|e| e.claim.admits_interop()).collect()
}

const MAX_LEDGER_BYTES: u64 = 1_048_576;

/// Persist a chain atomically. A broken chain is never written.
///
/// # Errors
/// `Error::Invalid` for a broken chain; `Error::Store` for IO, size, or symlink refusal.
pub fn save_chain(path: &Path, entries: &[LedgerEntry]) -> Result<(), Error> {
    if !chain_intact(entries) {
        return Err(Error::Invalid("refusing to write a broken chain".into()));
    }
    let body = serde_json::to_vec_pretty(entries).map_err(|e| Error::Store(e.to_string()))?;
    write_atomic(path, &body, MAX_LEDGER_BYTES)
}

/// Load a chain and verify every link.
///
/// # Errors
/// `Error::Store` for IO, size, symlink, or JSON failure; `Error::Invalid` for a broken chain.
pub fn load_chain(path: &Path) -> Result<Vec<LedgerEntry>, Error> {
    let body = read_bounded(path, MAX_LEDGER_BYTES)?;
    let entries: Vec<LedgerEntry> = serde_json::from_slice(&body).map_err(|e| Error::Store(e.to_string()))?;
    if !chain_intact(&entries) {
        return Err(Error::Invalid("ledger chain broken".into()));
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use std::fs;

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
    fn field_boundaries_and_absent_technique_are_unambiguous() {
        let mut a = sample(Status::Verified, EvidenceLevel::DirectObservation, None);
        a.claim = "a\nb".into();
        a.source = "c".into();
        let mut b = a.clone();
        b.claim = "a".into();
        b.source = "b\nc".into();
        assert_ne!(seal(&a).hash, seal(&b).hash, "moving a newline across fields must change the hash");
        let none = sample(Status::Verified, EvidenceLevel::DirectObservation, None);
        let empty = sample(Status::Verified, EvidenceLevel::DirectObservation, Some(""));
        assert_ne!(seal(&none).hash, seal(&empty).hash, "absent technique is not an empty technique");
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

    #[test]
    fn tampered_file_fails_load() {
        let dir = std::env::temp_dir().join(format!("huntsman-ledger-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.json");
        let entry = seal(&sample(Status::Verified, EvidenceLevel::DirectObservation, None));
        save_chain(&path, &[entry]).unwrap();
        assert!(load_chain(&path).is_ok());
        let mut raw = fs::read_to_string(&path).unwrap();
        raw = raw.replacen("haversine band holds", "tampered claim", 1);
        fs::write(&path, raw).unwrap();
        assert!(matches!(load_chain(&path), Err(Error::Invalid(_))));
        let _ = fs::remove_dir_all(&dir);
    }
}
