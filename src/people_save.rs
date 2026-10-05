//! Persist a completed `people` lookup as an unverified huntsman-ledger-v2 chain.
//!
//! The skip path (no registers queried) must not call this. A queried empty
//! result still writes one assertion. Claims never admit interop: `verify`
//! reports `admitted=0`.

use std::path::Path;

use crate::entity::Entity;
use crate::error::Error;
use crate::ledger::{self, Claim, GENESIS, LedgerEntry};
use crate::stage::{EvidenceLevel, Status};

const COMPONENT: &str = "src/asic_persons.rs";
const SOURCE_FALLBACK: &str = "asic_persons";

/// Write an unverified chain for a completed lookup. Do not call on skip.
///
/// # Errors
/// `Error::Store` on IO failure; `Error::Invalid` if the constructed chain is broken.
pub fn write(path: &Path, entities: &[Entity]) -> Result<(), Error> {
    ledger::save_chain(path, &chain(entities))
}

#[must_use]
pub fn chain(entities: &[Entity]) -> Vec<LedgerEntry> {
    let mut prev = GENESIS.to_owned();
    let mut entries = Vec::new();
    for claim in claims(entities) {
        let entry = ledger::append(&prev, &claim);
        prev.clone_from(&entry.hash);
        entries.push(entry);
    }
    entries
}

fn claims(entities: &[Entity]) -> Vec<Claim> {
    if entities.is_empty() {
        return vec![unverified(
            "asic_persons: no matching records",
            SOURCE_FALLBACK,
        )];
    }
    entities.iter().map(entity_claim).collect()
}

fn entity_claim(entity: &Entity) -> Claim {
    let source = entity
        .evidence
        .first()
        .map(|evidence| evidence.provenance.source.as_str())
        .filter(|source| !source.is_empty())
        .unwrap_or(SOURCE_FALLBACK);
    unverified(&format!("{} {}", entity.kind, entity.raw_value), source)
}

fn unverified(claim: &str, source: &str) -> Claim {
    Claim {
        claim: claim.to_owned(),
        source: source.to_owned(),
        component: COMPONENT.into(),
        technique_id: None,
        status: Status::Unverified,
        evidence_level: EvidenceLevel::Assertion,
        does_not_show: "not an attribution or a verified identity".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
    use crate::ledger::{admitted, chain_intact, load_chain};

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("huntsman-people-save-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn empty_lookup_writes_one_unverified_assertion() {
        let entries = chain(&[]);
        assert_eq!(entries.len(), 1);
        assert!(chain_intact(&entries));
        let admitted = admitted(&entries);
        assert!(admitted.is_empty(), "{admitted:?}");
        assert_eq!(entries[0].claim.status, Status::Unverified);
        assert_eq!(entries[0].claim.claim, "asic_persons: no matching records");
    }

    #[test]
    fn entity_claim_uses_kind_raw_value_and_provenance_source() {
        let mut entity = Entity::new(EntityKind::Person, "Jane Citizen", 0.6, "scan");
        entity.add_evidence(Evidence::new(
            EvidenceProvenance::new("asic_persons"),
            "hit",
        ));
        let entries = chain(&[entity]);
        assert_eq!(entries[0].claim.claim, "person Jane Citizen");
        assert_eq!(entries[0].claim.source, "asic_persons");
        let admitted = admitted(&entries);
        assert!(admitted.is_empty(), "{admitted:?}");
    }

    #[test]
    fn write_round_trips_and_verify_admits_nothing() {
        let dir = scratch("roundtrip");
        let path = dir.join("ledger.json");
        write(&path, &[]).unwrap();
        let loaded = load_chain(&path).unwrap();
        assert_eq!(loaded, chain(&[]));
        let admitted = admitted(&loaded);
        assert!(admitted.is_empty(), "{admitted:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
