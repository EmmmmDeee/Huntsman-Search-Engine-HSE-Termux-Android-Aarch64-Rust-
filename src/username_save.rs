//! Persist one `username` lookup as an unverified hash-chained ledger.

use std::path::Path;

use crate::entity::Entity;
use crate::error::Error;
use crate::ledger::{self, Claim, LedgerEntry};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::stage::{EvidenceLevel, Status};

const DOES_NOT_SHOW: &str = "a public username-profile lead is not an identity-resolution verdict";

/// Write one username lookup report as a fresh chain.
///
/// # Errors
/// Invalid empty report or storage failure.
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

    let mut previous = ledger::GENESIS.to_owned();
    let mut entries = Vec::new();

    for outcome in outcomes {
        let entry = ledger::append(&previous, &outcome_claim(outcome));
        previous.clone_from(&entry.hash);
        entries.push(entry);
    }
    for entity in entities {
        let entry = ledger::append(&previous, &entity_claim(entity));
        previous.clone_from(&entry.hash);
        entries.push(entry);
    }
    Ok(entries)
}

fn provenance(source: &str) -> (&str, &'static str) {
    match source {
        "github_user" => ("github_user", "src/github_user.rs"),
        "bluesky_user" => ("bluesky_user", "src/bluesky_user.rs"),
        "username_variants" | "seed" => (source, "src/username_cli.rs"),
        _ => (source, "src/username_cli.rs"),
    }
}

fn outcome_claim(outcome: &SourceExecutionOutcome) -> Claim {
    let found = outcome
        .found
        .map_or_else(|| "none".to_owned(), |count| count.to_string());
    let evidence_level = if outcome.kind.is_accepted() {
        EvidenceLevel::PrimaryEvidence
    } else {
        EvidenceLevel::Assertion
    };
    let (source, component) = provenance(&outcome.module);

    Claim {
        claim: format!(
            "{} {} found={found}",
            outcome.module,
            kind_label(outcome.kind)
        ),
        source: source.into(),
        component: component.into(),
        technique_id: None,
        status: Status::Unverified,
        evidence_level,
        does_not_show: DOES_NOT_SHOW.into(),
    }
}

fn entity_claim(entity: &Entity) -> Claim {
    let source = entity
        .evidence
        .first()
        .map(|evidence| evidence.provenance.source.as_str())
        .filter(|source| !source.is_empty())
        .unwrap_or("username_variants");
    let (source, component) = provenance(source);

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

const fn kind_label(kind: SourceOutcomeKind) -> &'static str {
    match kind {
        SourceOutcomeKind::Success => "success",
        SourceOutcomeKind::ValidZero => "valid_zero",
        SourceOutcomeKind::AuthRequired => "auth_required",
        SourceOutcomeKind::AuthRejected => "auth_rejected",
        SourceOutcomeKind::EntitlementDenied => "entitlement_denied",
        SourceOutcomeKind::QuotaExhausted => "quota_exhausted",
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
        let dir = std::env::temp_dir().join(format!(
            "huntsman-username-save-{}",
            std::process::id()
        ));
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
