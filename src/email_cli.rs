//! End-to-end front-end for `huntsman-recon email`.
//!
//! The selector is canonicalised once, legacy-compatible deterministic email
//! derivations are produced locally, then the public Gravatar profile is queried
//! through the shared transport. Evidence is rendered with lineage. Saving is handled by
//! the L7 `lookup_save` module, and `lookup_args` reads the `--save` option.

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::canonical::canonical_email;
use crate::domains::{INFRA_PROVIDER_ROOTS, is_freemail, is_role_localpart, is_social_platform};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid};
use crate::error::Error;
use crate::gravatar;
use crate::http::Transport;
use crate::lookup_args::LookupTokens;
use crate::lookup_report;
use crate::source_outcome::SourceExecutionOutcome;
use crate::textnorm::upper_first;

pub const EMAIL_USAGE: &str = "usage: huntsman-recon email ADDR [--save FILE]";
pub const EMAIL_HELP: &str = "\
email ADDR [--save FILE]
Canonicalise ADDR, derive deterministic email pivots, and query its public Gravatar profile. --save FILE writes an unverified ledger that verify can reload.";

const CONF_DOMAIN: f64 = 0.80;
const CONF_USERNAME_CORPORATE: f64 = 0.70;
const CONF_USERNAME_FREEMAIL: f64 = 0.55;
const CONF_PERSON_CORPORATE: f64 = 0.55;
const CONF_PERSON_FREEMAIL: f64 = 0.45;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailArgs {
    pub email: String,
    pub save: Option<PathBuf>,
}

impl EmailArgs {
    /// # Errors
    /// Invalid or missing address, repeated `--save`, or an unknown option.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let LookupTokens { positional, save } = LookupTokens::split(args)?;
        if positional.len() != 1 {
            return Err(Error::Invalid("email needs exactly one ADDR".into()));
        }
        let email = canonical_email(&positional[0])
            .ok_or_else(|| Error::invalid_value("invalid email address"))?;
        Ok(Self { email, save })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum EmailRun {
    Printed { text: String, report: Report },
    Network(String),
    Failed(String),
}

/// Run one deterministic email enrichment plus one public-profile lookup.
#[must_use]
pub fn run<T: Transport + ?Sized>(transport: &T, email: &str, now_unix: u64) -> EmailRun {
    let Some(email) = canonical_email(email) else {
        return EmailRun::Failed("invalid email address".into());
    };
    let scan_id = crate::entity::scan_id("email", &email);
    let mut report = Report {
        entities: derive_entities(&email, &scan_id),
        outcomes: Vec::new(),
    };

    match gravatar::lookup(transport, &email, &scan_id, now_unix) {
        Ok(got) => {
            report.entities.extend(got.entities);
            report.outcomes.push(got.outcome);
        }
        Err(Error::Network(msg)) => return EmailRun::Network(msg),
        Err(err) => return EmailRun::Failed(err.to_string()),
    }
    merge_by_uid(&mut report.entities);

    match lookup_report::render(&report.entities, &report.outcomes) {
        Ok(text) => EmailRun::Printed { text, report },
        Err(msg) => EmailRun::Failed(msg),
    }
}

fn derive_entities(email: &str, scan_id: &str) -> Vec<Entity> {
    let Some((local, domain)) = email.rsplit_once('@') else {
        return Vec::new();
    };
    let mut entities = Vec::new();
    add_seed(email, scan_id, &mut entities);

    if domain_is_specific(domain) {
        let mut entity = Entity::new(EntityKind::Domain, domain, CONF_DOMAIN, scan_id);
        entity.tag("derived");
        entity.tag("email-domain");
        entity.add_evidence(
            derived_evidence(scan_id, email, "domain")
                .with_attr("derived_domain", domain)
                .inferred(),
        );
        entities.push(entity);
    }

    if !is_role_localpart(local) {
        derive_usernames(local, domain, email, scan_id, &mut entities);
        derive_person(local, domain, email, scan_id, &mut entities);
    }
    entities
}

fn add_seed(email: &str, scan_id: &str, entities: &mut Vec<Entity>) {
    let mut entity = Entity::new(EntityKind::Email, email, 0.99, scan_id);
    entity.tag("seed");
    entity.add_evidence(Evidence::new(
        EvidenceProvenance::for_scan("seed", scan_id),
        "operator-supplied email selector",
    ));
    entities.push(entity);
}

fn derived_evidence(scan_id: &str, email: &str, derivation: &str) -> Evidence {
    Evidence::new(
        EvidenceProvenance::for_scan("email_parse", scan_id),
        format!("Derived from {email}"),
    )
    .with_attr("source_email", email)
    .with_attr("derivation", derivation)
}

fn domain_is_specific(domain: &str) -> bool {
    !is_freemail(domain)
        && !is_social_platform(domain)
        && !INFRA_PROVIDER_ROOTS.iter().any(|root| {
            domain == *root || domain.strip_suffix(root).is_some_and(|p| p.ends_with('.'))
        })
}

fn derive_usernames(
    local: &str,
    domain: &str,
    email: &str,
    scan_id: &str,
    entities: &mut Vec<Entity>,
) {
    let local = local.to_ascii_lowercase();
    let detagged = local.split('+').next().unwrap_or(&local);
    let mut candidates = BTreeSet::new();
    candidates.insert(local.clone());
    candidates.insert(detagged.to_owned());

    let stripped = detagged.trim_end_matches(char::is_numeric);
    if stripped.len() > 2 {
        candidates.insert(stripped.to_owned());
    }

    let collapsed: String = detagged
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();
    if collapsed.len() > 2 {
        candidates.insert(collapsed);
    }

    candidates.extend(
        detagged
            .split(['.', '_', '-'])
            .filter(|part| part.len() > 2)
            .map(str::to_owned),
    );
    add_name_shape_variants(detagged, &mut candidates);

    let confidence = if is_freemail(domain) {
        CONF_USERNAME_FREEMAIL
    } else {
        CONF_USERNAME_CORPORATE
    };
    for candidate in candidates.into_iter().filter(|value| !value.is_empty()) {
        let mut entity = Entity::new(EntityKind::Username, &candidate, confidence, scan_id);
        entity.tag("derived");
        entity.add_evidence(
            derived_evidence(scan_id, email, "local_part")
                .with_attr("candidate", &candidate)
                .inferred(),
        );
        entities.push(entity);
    }
}

fn add_name_shape_variants(local: &str, candidates: &mut BTreeSet<String>) {
    let parts: Vec<&str> = local
        .split(['.', '_', '-'])
        .filter(|part| part.len() >= 2 && part.chars().all(char::is_alphabetic))
        .collect();
    if parts.len() != 2 {
        return;
    }
    let first = parts[0];
    let last = parts[1];
    let Some(first_initial) = first.chars().next() else {
        return;
    };
    let Some(last_initial) = last.chars().next() else {
        return;
    };
    candidates.insert(format!("{first_initial}{last}"));
    candidates.insert(format!("{first}{last_initial}"));
    candidates.insert(format!("{first_initial}.{last}"));
    candidates.insert(format!("{first}_{last}"));
    candidates.insert(format!("{first}-{last}"));
}

fn derive_person(
    local: &str,
    domain: &str,
    email: &str,
    scan_id: &str,
    entities: &mut Vec<Entity>,
) {
    let detagged = local
        .split('+')
        .next()
        .unwrap_or(local)
        .to_ascii_lowercase();
    let parts: Vec<&str> = detagged.split(['.', '_', '-']).collect();
    if parts.len() != 2
        || parts
            .iter()
            .any(|part| part.len() < 2 || !part.chars().all(char::is_alphabetic))
    {
        return;
    }
    let confidence = if is_freemail(domain) {
        CONF_PERSON_FREEMAIL
    } else {
        CONF_PERSON_CORPORATE
    };
    let name = format!("{} {}", upper_first(parts[0]), upper_first(parts[1]));
    let mut entity = Entity::new(EntityKind::Person, &name, confidence, scan_id);
    entity.tag("derived");
    entity.tag("email-inferred");
    if is_freemail(domain) {
        entity.tag("freemail-inferred");
    }
    entity.add_evidence(
        derived_evidence(scan_id, email, "firstname.lastname")
            .with_attr("pattern", "firstname.lastname")
            .inferred(),
    );
    entities.push(entity);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::OneResponse;

    use crate::source_outcome::SourceOutcomeKind;

    #[test]
    fn parse_accepts_one_email_and_save() {
        let parsed = EmailArgs::parse(&[
            "Jane.Doe@Example.com".into(),
            "--save".into(),
            "out.json".into(),
        ])
        .unwrap();
        assert_eq!(parsed.email, "jane.doe@example.com");
        assert_eq!(parsed.save, Some(PathBuf::from("out.json")));
    }

    #[test]
    fn parse_rejects_missing_extra_or_invalid_email() {
        assert!(EmailArgs::parse(&[]).is_err());
        assert!(EmailArgs::parse(&["a@example.com".into(), "b@example.com".into()]).is_err());
        assert!(EmailArgs::parse(&["not-an-email".into()]).is_err());
    }

    #[test]
    fn derivation_matches_legacy_high_value_shapes() {
        let entities = derive_entities("jane.doe@acme.example", "scan");
        assert!(
            entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Domain && entity.value == "acme.example")
        );
        for expected in ["janedoe", "jdoe", "jane_doe"] {
            assert!(
                entities.iter().any(|entity| {
                    entity.kind == EntityKind::Username && entity.raw_value == expected
                }),
                "missing raw username variant {expected}"
            );
        }
        assert!(
            entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Person && entity.value == "jane doe")
        );
    }

    #[test]
    fn role_mailbox_does_not_mint_person_or_username() {
        let entities = derive_entities("info@acme.example", "scan");
        assert!(
            !entities
                .iter()
                .any(|entity| { matches!(entity.kind, EntityKind::Person | EntityKind::Username) })
        );
        assert!(
            entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Domain)
        );
    }

    #[test]
    fn freemail_does_not_mint_provider_domain() {
        let entities = derive_entities("jane.doe@gmail.com", "scan");
        assert!(
            !entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Domain)
        );
        assert!(
            entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Person
                    && (entity.confidence - CONF_PERSON_FREEMAIL).abs() < f64::EPSILON)
        );
    }

    #[test]
    fn run_combines_derivation_and_public_profile() {
        let body = r#"{"entry":[{"displayName":"Jane Doe","preferredUsername":"janed"}]}"#;
        match run(&OneResponse::json(200, body), "jane.doe@acme.example", 1) {
            EmailRun::Printed { text, report } => {
                assert!(text.contains("gravatar\tsuccess"), "{text}");
                assert!(text.contains("lineage="), "{text}");
                assert!(
                    report
                        .entities
                        .iter()
                        .any(|entity| entity.kind == EntityKind::Username)
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn missing_public_profile_keeps_offline_derivations() {
        match run(&OneResponse::json(404, ""), "jane.doe@gmail.com", 1) {
            EmailRun::Printed { report, .. } => {
                assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::ValidZero);
                assert!(!report.entities.is_empty());
            }
            other => panic!("{other:?}"),
        }
    }
}
