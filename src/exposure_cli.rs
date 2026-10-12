//! End-to-end front-end for `huntsman-recon exposure`.
//!
//! The address is canonicalised once and queried against HIBP `breachedaccount`
//! through a caller-supplied [`HibpClient`]. Each breach becomes evidence on the
//! seed email entity, tagged `breach` or `stealer-log`, so breach exposure flows
//! through `merge_by_uid`, `lookup_report` (lineage) and `lookup_save` like every
//! other lookup front-end. Without an operator key no request is made and the
//! outcome is `AuthRequired`, never a silent zero.

use std::path::PathBuf;

use crate::canonical::canonical_email;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid};
use crate::error::Error;
use crate::hibp::client::HibpClient;
use crate::hibp::error::HibpError;
use crate::hibp::types::{BreachModel, BreachedAccountOptions};
use crate::lookup_args::LookupTokens;
use crate::lookup_report;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::tags;

pub const EXPOSURE_USAGE: &str = "usage: huntsman-recon exposure ADDR [--save FILE]";
pub const EXPOSURE_HELP: &str = "\
exposure ADDR [--save FILE]
Canonicalise ADDR and query HIBP breached-account (operator key required; without one no request is made and the outcome is auth_required). Each breach becomes lineage-rendered evidence on the email entity. --save FILE writes an unverified ledger that verify can reload.";

/// Source label for the HIBP breached-account leg.
pub const SOURCE: &str = "hibp_account";

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposureArgs {
    pub email: String,
    pub save: Option<PathBuf>,
}

impl ExposureArgs {
    /// # Errors
    /// Invalid or missing address, repeated `--save`, or an unknown option.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let LookupTokens { positional, save } = LookupTokens::split(args)?;
        if positional.len() != 1 {
            return Err(Error::Invalid("exposure needs exactly one ADDR".into()));
        }
        let email = canonical_email(&positional[0])
            .ok_or_else(|| Error::invalid_value("invalid email address"))?;
        Ok(Self { email, save })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExposureRun {
    Printed { text: String, report: Report },
    Network(String),
    Failed(String),
}

/// Query breach exposure for `email`. `client` is `None` when no operator key is
/// configured; then nothing is sent.
#[must_use]
pub fn run(client: Option<&HibpClient>, email: &str, now_unix: u64) -> ExposureRun {
    let Some(email) = canonical_email(email) else {
        return ExposureRun::Failed("invalid email address".into());
    };
    let scan_id = crate::entity::scan_id("exposure", &email);
    let mut report = Report {
        entities: vec![seed_entity(&email, &scan_id)],
        outcomes: Vec::new(),
    };

    let outcome = match client {
        None => SourceExecutionOutcome::failed(
            SOURCE,
            now_unix,
            SourceOutcomeKind::AuthRequired,
            None,
            "no HIBP operator key configured; no request made",
        ),
        Some(client) => {
            let options = BreachedAccountOptions {
                truncate_response: Some(false),
                ..BreachedAccountOptions::default()
            };
            match client.breached_account(&email, &options) {
                Ok(breaches) if breaches.is_empty() => {
                    SourceExecutionOutcome::valid_zero(SOURCE, now_unix)
                }
                Ok(breaches) => {
                    for breach in &breaches {
                        report
                            .entities
                            .push(breach_entity(&email, &scan_id, breach));
                    }
                    SourceExecutionOutcome::success(SOURCE, now_unix, breaches.len())
                }
                Err(HibpError::Transport(msg)) => return ExposureRun::Network(msg),
                Err(err) => SourceExecutionOutcome::failed(
                    SOURCE,
                    now_unix,
                    outcome_kind(&err),
                    None,
                    err.to_string(),
                ),
            }
        }
    };
    report.outcomes.push(outcome);
    merge_by_uid(&mut report.entities);

    match lookup_report::render(&report.entities, &report.outcomes) {
        Ok(text) => ExposureRun::Printed { text, report },
        Err(msg) => ExposureRun::Failed(msg),
    }
}

fn outcome_kind(err: &HibpError) -> SourceOutcomeKind {
    match err {
        HibpError::MissingKey => SourceOutcomeKind::AuthRequired,
        HibpError::Unauthorized(_) | HibpError::Forbidden(_) => SourceOutcomeKind::AuthRejected,
        HibpError::PlanNotEntitled { .. } => SourceOutcomeKind::EntitlementDenied,
        HibpError::RateLimited { .. } => SourceOutcomeKind::RateLimited,
        HibpError::Server { .. } => SourceOutcomeKind::Upstream5xx,
        HibpError::BadRequest(_) | HibpError::UnexpectedStatus { .. } => {
            SourceOutcomeKind::Upstream4xx
        }
        HibpError::Decode(_) => SourceOutcomeKind::SchemaDrift,
        HibpError::Transport(_) => SourceOutcomeKind::ConnectFailure,
        HibpError::InvalidInput(_) | HibpError::OAuth(_) => SourceOutcomeKind::Inconclusive,
    }
}

fn seed_entity(email: &str, scan_id: &str) -> Entity {
    let mut entity = Entity::new(EntityKind::Email, email, 0.99, scan_id);
    entity.tag("seed");
    entity.add_evidence(Evidence::new(
        EvidenceProvenance::for_scan("seed", scan_id),
        "operator-supplied email selector",
    ));
    entity
}

fn breach_entity(email: &str, scan_id: &str, breach: &BreachModel) -> Entity {
    let mut entity = Entity::new(EntityKind::Email, email, 0.90, scan_id);
    if breach.is_stealer_log == Some(true) {
        entity.tag(tags::STEALER_LOG);
    }
    entity.tag(tags::BREACH);

    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(SOURCE, scan_id),
        format!("Address listed in HIBP breach {}", breach.name),
    )
    .with_attr("breach_name", &breach.name)
    .with_attr("data_classes", breach.data_classes.join(", "));
    for (key, value) in [
        ("breach_title", breach.title.as_ref()),
        ("breach_domain", breach.domain.as_ref()),
        ("breach_date", breach.breach_date.as_ref()),
    ] {
        if let Some(value) = value {
            evidence = evidence.with_attr(key, value);
        }
    }
    if let Some(count) = breach.pwn_count {
        evidence = evidence.with_attr("pwn_count", count.to_string());
    }
    if let Some(verified) = breach.is_verified {
        evidence = evidence.with_attr("breach_verified", verified.to_string());
    }
    entity.add_evidence(evidence);
    entity
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_key_makes_no_request_and_reports_auth_required() {
        let ExposureRun::Printed { report, .. } = run(None, "Ada@Example.com", 7) else {
            panic!("expected a printed report");
        };
        assert_eq!(report.outcomes.len(), 1);
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::AuthRequired);
        assert_eq!(report.entities.len(), 1);
        assert!(!report.entities[0].tags.iter().any(|t| t == tags::BREACH));
    }

    #[test]
    fn invalid_address_fails() {
        assert!(matches!(
            run(None, "not-an-email", 7),
            ExposureRun::Failed(_)
        ));
    }

    #[test]
    fn hibp_errors_keep_their_cause() {
        assert_eq!(
            outcome_kind(&HibpError::Unauthorized("x".into())),
            SourceOutcomeKind::AuthRejected
        );
        assert_eq!(
            outcome_kind(&HibpError::Decode("x".into())),
            SourceOutcomeKind::SchemaDrift
        );
    }
}
