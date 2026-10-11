//! Shared persistence core for lookup front-ends.
//!
//! Lookup-specific save modules provide only provenance mapping and the
//! "does not show" boundary. Chain construction, outcome labelling, evidence
//! levels, ledger append order, and atomic persistence live here once.

use std::path::Path;

use crate::entity::Entity;
use crate::error::Error;
use crate::ledger::{self, Claim, LedgerEntry};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::stage::{EvidenceLevel, Status};

pub type ProvenanceFn = for<'a> fn(&'a str) -> (&'a str, &'static str);

#[derive(Clone, Copy)]
pub struct SavePolicy {
    pub default_source: &'static str,
    pub does_not_show: &'static str,
    pub outcome_provenance: ProvenanceFn,
    pub entity_provenance: ProvenanceFn,
}

fn email_provenance(source: &str) -> (&str, &'static str) {
    match source {
        "gravatar" => ("gravatar", "src/gravatar.rs"),
        _ => (source, "src/email_cli.rs"),
    }
}

fn username_provenance(source: &str) -> (&str, &'static str) {
    match source {
        "github_user" => ("github_user", "src/github_user.rs"),
        "bluesky_user" => ("bluesky_user", "src/bluesky_user.rs"),
        _ => (source, "src/username_cli.rs"),
    }
}

fn phone_provenance(source: &str) -> (&str, &'static str) {
    match source {
        "phone_intl" => ("phone_intl", "src/phone_intl.rs"),
        "phone_au" => ("phone_au", "src/phone_cli.rs"),
        _ => (source, "src/phone_cli.rs"),
    }
}

pub const EMAIL_POLICY: SavePolicy = SavePolicy {
    default_source: "email_parse",
    does_not_show: "an email-derived lead is not an identity-resolution verdict",
    outcome_provenance: email_provenance,
    entity_provenance: email_provenance,
};

pub const USERNAME_POLICY: SavePolicy = SavePolicy {
    default_source: "username_variants",
    does_not_show: "a public username-profile lead is not an identity-resolution verdict",
    outcome_provenance: username_provenance,
    entity_provenance: username_provenance,
};

fn people_outcome_provenance(label: &str) -> (&str, &'static str) {
    match label.split('.').next().unwrap_or(label) {
        "asic_director" => ("asic_director", "src/asic_director.rs"),
        "au_people" => ("au_people", "src/au_people.rs"),
        "au_electoral" => ("au_electoral", "src/au_electoral.rs"),
        _ => ("asic_persons", "src/asic_persons.rs"),
    }
}

fn people_entity_provenance(label: &str) -> (&str, &'static str) {
    let (_, component) = people_outcome_provenance(label);
    (label, component)
}

pub const PEOPLE_POLICY: SavePolicy = SavePolicy {
    default_source: "asic_persons",
    does_not_show: "a register row is not identity resolution or an ATT&CK score",
    outcome_provenance: people_outcome_provenance,
    entity_provenance: people_entity_provenance,
};

pub const PHONE_POLICY: SavePolicy = SavePolicy {
    default_source: "phone_intl",
    does_not_show: "a phone-format or numbering-plan classification is not an identity-resolution verdict",
    outcome_provenance: phone_provenance,
    entity_provenance: phone_provenance,
};

/// Persist one lookup report as a fresh unverified hash chain.
///
/// # Errors
/// Refuses an empty report and propagates bounded atomic ledger-write failures.
pub fn save(
    path: &Path,
    entities: &[Entity],
    outcomes: &[SourceExecutionOutcome],
    policy: SavePolicy,
) -> Result<Vec<LedgerEntry>, Error> {
    let entries = chain(entities, outcomes, policy)?;
    ledger::save_chain(path, &entries)?;
    Ok(entries)
}

/// Build the ledger entries without performing I/O.
///
/// # Errors
/// Refuses an empty report so a skipped lookup cannot be persisted as if it ran.
pub fn chain(
    entities: &[Entity],
    outcomes: &[SourceExecutionOutcome],
    policy: SavePolicy,
) -> Result<Vec<LedgerEntry>, Error> {
    if entities.is_empty() && outcomes.is_empty() {
        return Err(Error::Invalid("nothing to save".into()));
    }

    let mut previous = ledger::GENESIS.to_owned();
    let mut entries = Vec::with_capacity(outcomes.len().saturating_add(entities.len()));

    for outcome in outcomes {
        let entry = ledger::append(&previous, &outcome_claim(outcome, policy));
        previous.clone_from(&entry.hash);
        entries.push(entry);
    }
    for entity in entities {
        let entry = ledger::append(&previous, &entity_claim(entity, policy));
        previous.clone_from(&entry.hash);
        entries.push(entry);
    }
    Ok(entries)
}

fn outcome_claim(outcome: &SourceExecutionOutcome, policy: SavePolicy) -> Claim {
    let found = outcome
        .found
        .map_or_else(|| "none".to_owned(), |count| count.to_string());
    let (source, component) = (policy.outcome_provenance)(&outcome.module);
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
        evidence_level: if outcome.kind.is_accepted() {
            EvidenceLevel::PrimaryEvidence
        } else {
            EvidenceLevel::Assertion
        },
        does_not_show: policy.does_not_show.into(),
    }
}

fn entity_claim(entity: &Entity, policy: SavePolicy) -> Claim {
    let observed_source = entity
        .evidence
        .first()
        .map(|evidence| evidence.provenance.source.as_str())
        .filter(|source| !source.is_empty())
        .unwrap_or(policy.default_source);
    let (source, component) = (policy.entity_provenance)(observed_source);
    Claim {
        claim: format!("{} {}", entity.kind, entity.raw_value),
        source: source.into(),
        component: component.into(),
        technique_id: None,
        status: Status::Unverified,
        evidence_level: EvidenceLevel::PrimaryEvidence,
        does_not_show: policy.does_not_show.into(),
    }
}

#[must_use]
pub const fn kind_label(kind: SourceOutcomeKind) -> &'static str {
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
    use crate::entity::{EntityKind, Evidence, EvidenceProvenance};

    fn provenance(source: &str) -> (&str, &'static str) {
        (source, "test")
    }

    const POLICY: SavePolicy = SavePolicy {
        default_source: "fallback",
        does_not_show: "not independently verified",
        outcome_provenance: provenance,
        entity_provenance: provenance,
    };

    #[test]
    fn empty_report_is_refused() {
        assert!(matches!(
            chain(&[], &[], POLICY),
            Err(Error::Invalid(message)) if message == "nothing to save"
        ));
    }

    #[test]
    fn outcomes_precede_entities_and_failure_is_assertion() {
        let mut entity = Entity::new(EntityKind::Email, "a@example.com", 0.9, "scan");
        entity.add_evidence(Evidence::new(
            EvidenceProvenance::for_scan("source", "scan"),
            "fixture",
        ));
        let mut outcome = SourceExecutionOutcome::success("source", 1, 0);
        outcome.kind = SourceOutcomeKind::RateLimited;
        outcome.found = None;

        let entries = chain(&[entity], &[outcome], POLICY).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].claim.claim, "source rate_limited found=none");
        assert_eq!(entries[0].claim.evidence_level, EvidenceLevel::Assertion);
        assert_eq!(entries[1].claim.claim, "email a@example.com");
        assert_eq!(entries[1].claim.source, "source");
        assert!(
            entries
                .iter()
                .all(|entry| entry.claim.status == Status::Unverified)
        );
    }

    #[test]
    fn all_outcome_labels_are_stable() {
        let labels = [
            SourceOutcomeKind::Success,
            SourceOutcomeKind::ValidZero,
            SourceOutcomeKind::AuthRequired,
            SourceOutcomeKind::AuthRejected,
            SourceOutcomeKind::EntitlementDenied,
            SourceOutcomeKind::QuotaExhausted,
            SourceOutcomeKind::RateLimited,
            SourceOutcomeKind::BotWaf,
            SourceOutcomeKind::DnsFailure,
            SourceOutcomeKind::ConnectFailure,
            SourceOutcomeKind::TlsFailure,
            SourceOutcomeKind::TtfbTimeout,
            SourceOutcomeKind::BodyTimeout,
            SourceOutcomeKind::Upstream4xx,
            SourceOutcomeKind::Upstream5xx,
            SourceOutcomeKind::RedirectChanged,
            SourceOutcomeKind::ProtocolDrift,
            SourceOutcomeKind::InteractionDrift,
            SourceOutcomeKind::SchemaDrift,
            SourceOutcomeKind::ParserDrift,
            SourceOutcomeKind::SemanticDrift,
            SourceOutcomeKind::ZeroYieldAnomaly,
            SourceOutcomeKind::ConfirmedDead,
            SourceOutcomeKind::Inconclusive,
        ]
        .map(kind_label);
        assert_eq!(
            labels,
            [
                "success",
                "valid_zero",
                "auth_required",
                "auth_rejected",
                "entitlement_denied",
                "quota_exhausted",
                "rate_limited",
                "bot_waf",
                "dns_failure",
                "connect_failure",
                "tls_failure",
                "ttfb_timeout",
                "body_timeout",
                "upstream_4xx",
                "upstream_5xx",
                "redirect_changed",
                "protocol_drift",
                "interaction_drift",
                "schema_drift",
                "parser_drift",
                "semantic_drift",
                "zero_yield_anomaly",
                "confirmed_dead",
                "inconclusive",
            ]
        );
    }
}
