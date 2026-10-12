//! End-to-end front-end for `huntsman-recon exposure`.
//!
//! The address is canonicalised once, then the account-keyed legs of
//! [`breach_hybrid::exposure_order`] run in that order: HIBP `breachedaccount`,
//! then the stolen.tax cascade. The keyless legs (Pwned Passwords, the HIBP
//! catalogue) are not keyed on an address and are not run here. Each HIBP breach
//! becomes evidence on the seed email entity, tagged `breach` or `stealer-log`;
//! stolen.tax entities are taken as that module builds them. Everything flows
//! through `merge_by_uid`, `lookup_report` (lineage) and `lookup_save`. A leg
//! without its key makes no request and records `AuthRequired`, never a zero.

use std::path::PathBuf;

use crate::breach_hybrid::{self, BreachLeg};
use crate::canonical::canonical_email;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid};
use crate::error::Error;
use crate::hibp::client::HibpClient;
use crate::hibp::error::HibpError;
use crate::hibp::types::{BreachModel, BreachedAccountOptions};
use crate::http::Transport;
use crate::keys::Keys;
use crate::lookup_args::LookupTokens;
use crate::lookup_report;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::stolen_tax::{self, StolenTaxError};
use crate::tags;

pub const EXPOSURE_USAGE: &str = "usage: huntsman-recon exposure ADDR [--save FILE]";
pub const EXPOSURE_HELP: &str = "\
exposure ADDR [--save FILE]
Canonicalise ADDR and run the keyed breach legs in order: HIBP breached-account, then the stolen.tax cascade. A leg without its key makes no request and reports auth_required. Results are lineage-rendered entities. --save FILE writes an unverified ledger that verify can reload.";

/// Source label for the HIBP breached-account leg.
pub const SOURCE: &str = "hibp_account";
/// Source label for the stolen.tax leg.
pub const STOLEN_TAX_SOURCE: &str = "stolen_tax";

/// The configured legs. `None` means that leg has no operator key.
#[derive(Clone, Copy, Default)]
pub struct Sources<'a> {
    pub hibp: Option<&'a HibpClient>,
    pub stolen_tax: Option<(&'a dyn Transport, &'a Keys)>,
}

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

/// Run every configured account-keyed breach leg for `email`.
#[must_use]
pub fn run(sources: Sources<'_>, email: &str, now_unix: u64) -> ExposureRun {
    let Some(email) = canonical_email(email) else {
        return ExposureRun::Failed("invalid email address".into());
    };
    let scan_id = crate::entity::scan_id("exposure", &email);
    let mut report = Report {
        entities: vec![seed_entity(&email, &scan_id)],
        outcomes: Vec::new(),
    };
    let mut network = None;

    for leg in breach_hybrid::exposure_order(true) {
        let outcome = match leg {
            BreachLeg::PwnedPasswords | BreachLeg::HibpCatalog => continue,
            BreachLeg::HibpAccount => match sources.hibp {
                None => missing_key(SOURCE, now_unix),
                Some(client) => hibp_leg(
                    client,
                    &email,
                    &scan_id,
                    now_unix,
                    &mut report,
                    &mut network,
                ),
            },
            BreachLeg::StolenTax => match sources.stolen_tax {
                None => missing_key(STOLEN_TAX_SOURCE, now_unix),
                Some((transport, keys)) => {
                    stolen_tax_leg(transport, keys, &email, &scan_id, now_unix, &mut report)
                }
            },
        };
        report.outcomes.push(outcome);
    }
    merge_by_uid(&mut report.entities);

    let collected = report.outcomes.iter().any(|o| o.kind.is_accepted());
    if let (false, Some(msg)) = (collected, network) {
        return ExposureRun::Network(msg);
    }
    match lookup_report::render(&report.entities, &report.outcomes) {
        Ok(text) => ExposureRun::Printed { text, report },
        Err(msg) => ExposureRun::Failed(msg),
    }
}

fn missing_key(source: &str, now_unix: u64) -> SourceExecutionOutcome {
    SourceExecutionOutcome::failed(
        source,
        now_unix,
        SourceOutcomeKind::AuthRequired,
        None,
        "no operator key configured; no request made",
    )
}

fn hibp_leg(
    client: &HibpClient,
    email: &str,
    scan_id: &str,
    now_unix: u64,
    report: &mut Report,
    network: &mut Option<String>,
) -> SourceExecutionOutcome {
    let options = BreachedAccountOptions {
        truncate_response: Some(false),
        ..BreachedAccountOptions::default()
    };
    match client.breached_account(email, &options) {
        Ok(breaches) if breaches.is_empty() => SourceExecutionOutcome::valid_zero(SOURCE, now_unix),
        Ok(breaches) => {
            report
                .entities
                .extend(breaches.iter().map(|b| breach_entity(email, scan_id, b)));
            SourceExecutionOutcome::success(SOURCE, now_unix, breaches.len())
        }
        Err(err) => {
            if let HibpError::Transport(msg) = &err {
                network.get_or_insert_with(|| msg.clone());
            }
            SourceExecutionOutcome::failed(
                SOURCE,
                now_unix,
                outcome_kind(&err),
                None,
                err.to_string(),
            )
        }
    }
}

fn stolen_tax_leg(
    transport: &dyn Transport,
    keys: &Keys,
    email: &str,
    scan_id: &str,
    now_unix: u64,
    report: &mut Report,
) -> SourceExecutionOutcome {
    match stolen_tax::lookup(transport, keys, email, scan_id, now_unix) {
        Ok(got) => {
            let found = got.entities.len();
            report.entities.extend(got.entities);
            let outcome = SourceExecutionOutcome::success(STOLEN_TAX_SOURCE, now_unix, found);
            match got.truncation {
                Some(why) => outcome.with_detail(format!("partial: {why}")),
                None => outcome,
            }
        }
        Err(err) => {
            let kind = match &err {
                StolenTaxError::MissingKey => SourceOutcomeKind::AuthRequired,
                StolenTaxError::Refused(_) => SourceOutcomeKind::ConnectFailure,
                StolenTaxError::BudgetExhausted { .. } => SourceOutcomeKind::BodyTimeout,
                StolenTaxError::Failed(_) => SourceOutcomeKind::Inconclusive,
            };
            SourceExecutionOutcome::failed(STOLEN_TAX_SOURCE, now_unix, kind, None, err.to_string())
        }
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
        let ExposureRun::Printed { report, .. } = run(Sources::default(), "Ada@Example.com", 7)
        else {
            panic!("expected a printed report");
        };
        let legs: Vec<_> = report
            .outcomes
            .iter()
            .map(|o| (o.module.as_str(), o.kind))
            .collect();
        assert_eq!(
            legs,
            [
                (SOURCE, SourceOutcomeKind::AuthRequired),
                (STOLEN_TAX_SOURCE, SourceOutcomeKind::AuthRequired)
            ],
            "every keyed leg is reported, in breach_hybrid order"
        );
        assert_eq!(report.entities.len(), 1);
        assert!(!report.entities[0].tags.iter().any(|t| t == tags::BREACH));
    }

    struct Breaches(std::sync::Mutex<Vec<String>>);

    impl Transport for Breaches {
        fn send(
            &self,
            request: &crate::http::Request,
        ) -> Result<crate::http::Response, crate::http::TransportFailure> {
            self.0.lock().unwrap().push(request.url.clone());
            Ok(crate::http::Response {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())],
                body: br#"[{"Name":"Adobe","Title":"Adobe","Domain":"adobe.com","BreachDate":"2013-10-04","PwnCount":152445165,"DataClasses":["Email addresses","Passwords"],"IsVerified":true,"IsStealerLog":false},{"Name":"Logs","DataClasses":["Email addresses"],"IsStealerLog":true}]"#.to_vec(),
                truncated: false,
            })
        }
    }

    #[test]
    fn each_hibp_breach_is_evidence_on_the_one_email_entity() {
        let transport = std::sync::Arc::new(Breaches(std::sync::Mutex::default()));
        let key = crate::hibp::key::ApiKey::new("0123456789abcdef0123456789abcdef").unwrap();
        let client = HibpClient::new(transport.clone(), crate::hibp::client::Auth::ApiKey(key));
        let sources = Sources {
            hibp: Some(&client),
            stolen_tax: None,
        };
        let ExposureRun::Printed { report, text } = run(sources, "ada@example.com", 7) else {
            panic!("expected a printed report");
        };
        let urls = transport.0.lock().unwrap();
        assert_eq!(urls.len(), 1, "{urls:?}");
        assert!(urls[0].contains("/breachedaccount/"), "{urls:?}");
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::Success);
        assert_eq!(report.outcomes[0].found, Some(2));
        assert_eq!(report.entities.len(), 1, "merged by uid: {text}");
        let entity = &report.entities[0];
        assert!(entity.tags.iter().any(|t| t == tags::BREACH));
        assert!(entity.tags.iter().any(|t| t == tags::STEALER_LOG));
        let breaches: Vec<_> = entity
            .evidence
            .iter()
            .filter_map(|e| e.attributes.get("breach_name"))
            .collect();
        assert_eq!(breaches.len(), 2, "{breaches:?}");
    }

    #[test]
    fn invalid_address_fails() {
        assert!(matches!(
            run(Sources::default(), "not-an-email", 7),
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
