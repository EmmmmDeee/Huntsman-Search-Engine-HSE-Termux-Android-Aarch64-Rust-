//! Persist one `phone` lookup as an unverified hash-chained ledger.

use std::path::Path;

use crate::entity::Entity;
use crate::error::Error;
use crate::ledger::LedgerEntry;
use crate::lookup_save::{self, SavePolicy};
use crate::source_outcome::SourceExecutionOutcome;

const DOES_NOT_SHOW: &str =
    "a phone-format or numbering-plan classification is not an identity-resolution verdict";

fn provenance(source: &str) -> (&str, &'static str) {
    match source {
        "phone_intl" => ("phone_intl", "src/phone_intl.rs"),
        "phone_au" => ("phone_au", "src/phone_cli.rs"),
        _ => (source, "src/phone_cli.rs"),
    }
}

const POLICY: SavePolicy = SavePolicy {
    default_source: "phone_intl",
    does_not_show: DOES_NOT_SHOW,
    outcome_provenance: provenance,
    entity_provenance: provenance,
};

/// Write one phone lookup report as a fresh chain.
///
/// # Errors
/// Refuses an empty report and propagates bounded ledger-write failures.
pub fn save(
    path: &Path,
    entities: &[Entity],
    outcomes: &[SourceExecutionOutcome],
) -> Result<Vec<LedgerEntry>, Error> {
    lookup_save::save(path, entities, outcomes, POLICY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use crate::entity::{EntityKind, Evidence, EvidenceProvenance};
    use crate::ledger::{admitted, load_chain};

    #[test]
    fn phone_report_round_trips_and_stays_unverified() {
        let mut phone = Entity::new(EntityKind::Phone, "+61412345678", 0.9, "scan");
        phone.add_evidence(Evidence::new(
            EvidenceProvenance::for_scan("phone_intl", "scan"),
            "format",
        ));
        let outcomes = [SourceExecutionOutcome::success("phone_intl", 1, 1)];
        let dir = std::env::temp_dir().join(format!("huntsman-phone-save-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("phone.json");

        let entries = save(&path, &[phone], &outcomes).unwrap();
        let loaded = load_chain(&path).unwrap();
        assert_eq!(loaded, entries);
        assert!(admitted(&loaded).is_empty());
        assert_eq!(entries[0].claim.source, "phone_intl");

        let _ = fs::remove_dir_all(&dir);
    }
}
