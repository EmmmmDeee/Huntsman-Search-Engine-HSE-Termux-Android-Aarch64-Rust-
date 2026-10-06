//! Persist one `username` lookup as an unverified hash-chained ledger.

use std::path::Path;

use crate::entity::Entity;
use crate::error::Error;
use crate::ledger::LedgerEntry;
use crate::lookup_save::{self, SavePolicy};
use crate::source_outcome::SourceExecutionOutcome;

const DOES_NOT_SHOW: &str = "a public username-profile lead is not an identity-resolution verdict";

fn provenance(source: &str) -> (&str, &'static str) {
    match source {
        "github_user" => ("github_user", "src/github_user.rs"),
        "bluesky_user" => ("bluesky_user", "src/bluesky_user.rs"),
        _ => (source, "src/username_cli.rs"),
    }
}

const POLICY: SavePolicy = SavePolicy {
    default_source: "username_variants",
    does_not_show: DOES_NOT_SHOW,
    outcome_provenance: provenance,
    entity_provenance: provenance,
};

/// Write one username lookup report as a fresh chain.
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
    fn report_round_trips_and_stays_unverified() {
        let mut username = Entity::new(EntityKind::Username, "alice", 0.99, "scan");
        username.add_evidence(Evidence::new(
            EvidenceProvenance::for_scan("seed", "scan"),
            "selector",
        ));
        let outcomes = [SourceExecutionOutcome::valid_zero("github_user", 1)];
        let dir =
            std::env::temp_dir().join(format!("huntsman-username-save-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("username.json");

        let entries = save(&path, &[username], &outcomes).unwrap();
        let loaded = load_chain(&path).unwrap();
        assert_eq!(loaded, entries);
        assert!(admitted(&loaded).is_empty());
        assert_eq!(entries[0].claim.source, "github_user");
        assert_eq!(entries[1].claim.source, "seed");

        let _ = fs::remove_dir_all(&dir);
    }
}
