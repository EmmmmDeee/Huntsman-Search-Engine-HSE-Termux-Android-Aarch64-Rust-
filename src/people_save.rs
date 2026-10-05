//! Persist a `people` lookup as an unverified hash-chained ledger.
//!
//! L7 may read L5 entity records. This module never claims ATT&CK interop: status
//! is [`Status::Unverified`], `technique_id` is absent, and `verify` therefore
//! reports `admitted=0`. An empty report is refused so a skip cannot look like a
//! lookup.

use std::path::Path;

use crate::entity::Entity;
use crate::error::Error;
use crate::ledger::{self, Claim, LedgerEntry};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::stage::{EvidenceLevel, Status};

const SOURCE: &str = "asic_persons";
const COMPONENT: &str = "src/asic_persons.rs";
const DOES_NOT_SHOW: &str = "a register row is not identity resolution or an ATT&CK score";

/// Write `entities` and `outcomes` as a fresh chain at `path`.
///
/// # Errors
/// [`Error::Invalid`] when both slices are empty. [`Error::Store`] on IO, size,
/// or symlink refusal.
pub fn save(
    path: &Path,
    entities: &[Entity],
    outcomes: &[SourceExecutionOutcome],
) -> Result<Vec<LedgerEntry>, Error> {
    let entries = chain(entities, outcomes)?;
    ledger::save_chain(path, &entries)?;
    Ok(entries)
}

fn chain(
    entities: &[Entity],
    outcomes: &[SourceExecutionOutcome],
) -> Result<Vec<LedgerEntry>, Error> {
    if entities.is_empty() && outcomes.is_empty() {
        return Err(Error::Invalid("nothing to save".into()));
    }
    let mut prev = ledger::GENESIS.to_owned();
    let mut entries = Vec::new();
    for outcome in outcomes {
        let entry = ledger::append(&prev, &outcome_claim(outcome));
        prev.clone_from(&entry.hash);
        entries.push(entry);
    }
    for entity in entities {
        let entry = ledger::append(&prev, &entity_claim(entity));
        prev.clone_from(&entry.hash);
        entries.push(entry);
    }
    Ok(entries)
}

fn outcome_claim(outcome: &SourceExecutionOutcome) -> Claim {
    let found = outcome
        .found
        .map_or_else(|| "none".to_owned(), |n| n.to_string());
    let level = if outcome.kind.is_accepted() {
        EvidenceLevel::PrimaryEvidence
    } else {
        EvidenceLevel::Assertion
    };
    Claim {
        claim: format!(
            "{} {} found={found}",
            outcome.module,
            kind_label(outcome.kind)
        ),
        source: SOURCE.into(),
        component: COMPONENT.into(),
        technique_id: None,
        status: Status::Unverified,
        evidence_level: level,
        does_not_show: DOES_NOT_SHOW.into(),
    }
}

fn entity_claim(entity: &Entity) -> Claim {
    let source = entity
        .evidence
        .first()
        .map(|e| e.provenance.source.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(SOURCE);
    Claim {
        claim: format!("{} {}", entity.kind, entity.raw_value),
        source: source.into(),
        component: COMPONENT.into(),
        technique_id: None,
        status: Status::Unverified,
        evidence_level: EvidenceLevel::PrimaryEvidence,
        does_not_show: DOES_NOT_SHOW.into(),
    }
}

const fn kind_label(kind: SourceOutcomeKind) -> &'static str {
    match kind {
        SourceOutcomeKind::Success => "success",
        SourceOutcomeKind::ValidZero => "valid_zero",
        SourceOutcomeKind::AuthRequired => "auth_required",
        SourceOutcomeKind::AuthRejected => "auth_rejected",
        SourceOutcomeKind::RateLimited => "rate_limited",
        SourceOutcomeKind::BotWaf => "bot_waf",
        SourceOutcomeKind::DnsFailure => "dns_failure",
        SourceOutcomeKind::ConnectFailure => "connect_failure",
        SourceOutcomeKind::TlsFailure => "tls_failure",
        SourceOutcomeKind::TtfbTimeout => "ttfb_timeout",
        SourceOutcomeKind::BodyTimeout => "body_timeout",
        SourceOutcomeKind::Upstream4xx => "upstream_4xx",
        SourceOutcomeKind::Upstream5xx => "upstream_5xx",
        SourceOutcomeKind::RedirectChanged => "redirect_changed",
        SourceOutcomeKind::ProtocolDrift => "protocol_drift",
        SourceOutcomeKind::InteractionDrift => "interaction_drift",
        SourceOutcomeKind::SchemaDrift => "schema_drift",
        SourceOutcomeKind::ParserDrift => "parser_drift",
        SourceOutcomeKind::SemanticDrift => "semantic_drift",
        SourceOutcomeKind::ZeroYieldAnomaly => "zero_yield_anomaly",
        SourceOutcomeKind::ConfirmedDead => "confirmed_dead",
        SourceOutcomeKind::Inconclusive => "inconclusive",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    use crate::entity::{EntityKind, Evidence, EvidenceProvenance};
    use crate::ledger::{admitted, load_chain};

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
}
