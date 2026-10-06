//! Persist a `people` lookup as an unverified hash-chained ledger.
//!
//! Lookup-specific provenance stays here; chain construction and claim semantics
//! are centralized in `lookup_save`.

use std::path::Path;

use crate::entity::Entity;
use crate::error::Error;
use crate::ledger::LedgerEntry;
use crate::lookup_save::{self, SavePolicy};
use crate::source_outcome::SourceExecutionOutcome;

const SOURCE: &str = "asic_persons";
const COMPONENT: &str = "src/asic_persons.rs";
const DOES_NOT_SHOW: &str = "a register row is not identity resolution or an ATT&CK score";

fn outcome_provenance(label: &str) -> (&str, &'static str) {
    match label.split('.').next().unwrap_or(label) {
        "asic_director" => ("asic_director", "src/asic_director.rs"),
        "au_people" => ("au_people", "src/au_people.rs"),
        "au_electoral" => ("au_electoral", "src/au_electoral.rs"),
        _ => (SOURCE, COMPONENT),
    }
}

fn entity_provenance(label: &str) -> (&str, &'static str) {
    let (_, component) = outcome_provenance(label);
    (label, component)
}

const POLICY: SavePolicy = SavePolicy {
    default_source: SOURCE,
    does_not_show: DOES_NOT_SHOW,
    outcome_provenance,
    entity_provenance,
};

/// Write `entities` and `outcomes` as a fresh chain at `path`.
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
fn chain(
    entities: &[Entity],
    outcomes: &[SourceExecutionOutcome],
) -> Result<Vec<LedgerEntry>, Error> {
    lookup_save::chain(entities, outcomes, POLICY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    use crate::entity::{EntityKind, Evidence, EvidenceProvenance};
    use crate::ledger::{admitted, load_chain};
    use crate::source_outcome::SourceOutcomeKind;
    use crate::stage::{EvidenceLevel, Status};

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("huntsman-people-save-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn empty_report_is_refused() {
        assert!(matches!(
            chain(&[], &[]),
            Err(Error::Invalid(msg)) if msg == "nothing to save"
        ));
    }

    #[test]
    fn valid_zero_round_trips_byte_identically_and_admits_nothing() {
        let dir = scratch("zero");
        let path = dir.join("people.json");
        let outcomes = vec![
            SourceExecutionOutcome::valid_zero("asic_persons.banned", 1),
            SourceExecutionOutcome::valid_zero("asic_persons.advisers", 1),
            SourceExecutionOutcome::valid_zero("asic_persons.credit", 1),
        ];
        let first = save(&path, &[], &outcomes).unwrap();
        assert_eq!(first.len(), 3);
        let admitted = admitted(&first);
        assert!(admitted.is_empty(), "{admitted:?}");
        let loaded = load_chain(&path).unwrap();
        assert_eq!(loaded, first);
        let copy = dir.join("copy.json");
        save(&copy, &[], &outcomes).unwrap();
        assert_eq!(fs::read(&path).unwrap(), fs::read(&copy).unwrap());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn entity_claim_uses_evidence_source_and_stays_unverified() {
        let mut person = Entity::new(EntityKind::Person, "Bill Abbott", 0.6, "scan");
        person.add_evidence(Evidence::new(
            EvidenceProvenance::for_scan("asic_persons", "scan"),
            "ASIC banned/disqualified: Bill Abbott",
        ));
        let outcomes = vec![SourceExecutionOutcome::success("asic_persons.banned", 1, 1)];
        let entries = chain(std::slice::from_ref(&person), &outcomes).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0].claim.claim,
            "asic_persons.banned success found=1"
        );
        assert_eq!(entries[1].claim.claim, "person Bill Abbott");
        assert_eq!(entries[1].claim.source, "asic_persons");
        assert!(entries.iter().all(|e| e.claim.technique_id.is_none()));
        assert!(entries.iter().all(|e| e.claim.status == Status::Unverified));
        let admitted = admitted(&entries);
        assert!(admitted.is_empty(), "{admitted:?}");
    }

    #[test]
    fn failed_outcome_is_assertion_not_primary_evidence() {
        let mut outcome = SourceExecutionOutcome::success("asic_persons.banned", 1, 0);
        outcome.kind = SourceOutcomeKind::BotWaf;
        outcome.found = None;
        let entries = chain(&[], std::slice::from_ref(&outcome)).unwrap();
        assert_eq!(entries[0].claim.evidence_level, EvidenceLevel::Assertion);
        assert_eq!(
            entries[0].claim.claim,
            "asic_persons.banned bot_waf found=none"
        );
    }

    #[test]
    fn mixed_source_outcomes_keep_their_component() {
        let outcomes = vec![
            SourceExecutionOutcome::valid_zero("asic_persons.banned", 1),
            SourceExecutionOutcome::valid_zero("asic_director", 1),
            SourceExecutionOutcome::valid_zero("au_people", 1),
            SourceExecutionOutcome::valid_zero("au_electoral.nsw", 1),
        ];
        let entries = chain(&[], &outcomes).unwrap();
        assert_eq!(entries[0].claim.source, "asic_persons");
        assert_eq!(entries[0].claim.component, "src/asic_persons.rs");
        assert_eq!(entries[1].claim.source, "asic_director");
        assert_eq!(entries[1].claim.component, "src/asic_director.rs");
        assert_eq!(entries[2].claim.source, "au_people");
        assert_eq!(entries[2].claim.component, "src/au_people.rs");
        assert_eq!(entries[3].claim.source, "au_electoral");
        assert_eq!(entries[3].claim.component, "src/au_electoral.rs");
    }
}
