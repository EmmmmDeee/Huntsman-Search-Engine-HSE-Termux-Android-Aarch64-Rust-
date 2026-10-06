//! Persist one `phone` enrichment as an unverified hash-chained ledger.

use std::path::Path;

use crate::entity::Entity;
use crate::error::Error;
use crate::ledger::{self, Claim, LedgerEntry};
use crate::stage::{EvidenceLevel, Status};

const DOES_NOT_SHOW: &str = "a numbering-plan derivation is not an identity-resolution verdict";

/// Write phone entities as a fresh unverified chain.
///
/// # Errors
/// Invalid empty report or storage failure.
pub fn save(path: &Path, entities: &[Entity]) -> Result<Vec<LedgerEntry>, Error> {
    if entities.is_empty() {
        return Err(Error::Invalid("nothing to save".into()));
    }
    let mut previous = ledger::GENESIS.to_owned();
    let mut entries = Vec::new();
    for entity in entities {
        let entry = ledger::append(&previous, &entity_claim(entity));
        previous.clone_from(&entry.hash);
        entries.push(entry);
    }
    ledger::save_chain(path, &entries)?;
    Ok(entries)
}

fn entity_claim(entity: &Entity) -> Claim {
    let source = entity
        .evidence
        .first()
        .map(|evidence| evidence.provenance.source.as_str())
        .filter(|source| !source.is_empty())
        .unwrap_or("phone");
    let component = match source {
        "phone_intl" | "phone_au" | "seed" => "src/phone_cli.rs",
        _ => "src/phone_cli.rs",
    };

    Claim {
        claim: format!("{} {}", entity.kind, entity.raw_value),
        source: source.into(),
        component: component.into(),
        technique_id: None,
        status: Status::Unverified,
        evidence_level: EvidenceLevel::PrimaryEvidence,
        does_not_show: DOES_NOT_SHOW.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use crate::entity::{EntityKind, Evidence, EvidenceProvenance};
    use crate::ledger::{admitted, load_chain};

    #[test]
    fn round_trip_stays_unverified() {
        let mut phone = Entity::new(EntityKind::Phone, "+61412345678", 0.99, "scan");
        phone.add_evidence(Evidence::new(
            EvidenceProvenance::for_scan("phone_au", "scan"),
            "AU mobile",
        ));
        let dir =
            std::env::temp_dir().join(format!("huntsman-phone-save-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("phone.json");

        let entries = save(&path, &[phone]).unwrap();
        let loaded = load_chain(&path).unwrap();
        assert_eq!(loaded, entries);
        assert!(admitted(&loaded).is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_report_is_refused() {
        let path = std::env::temp_dir().join("huntsman-empty-phone-save.json");
        assert!(matches!(
            save(&path, &[]),
            Err(Error::Invalid(message)) if message == "nothing to save"
        ));
    }
}
