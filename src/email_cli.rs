//! End-to-end front-end for `huntsman-recon email`.
//!
//! The selector is canonicalised once, legacy-compatible deterministic email
//! derivations are produced locally, then the public Gravatar profile is queried
//! through the shared transport. Evidence is rendered with lineage. Saving is
//! handled by the L7 `email_save` module from the binary.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::PathBuf;

use crate::canonical::canonical_email;
use crate::domains::{INFRA_PROVIDER_ROOTS, is_freemail, is_role_localpart, is_social_platform};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::error::Error;
use crate::evidence_ancestry::EvidenceNodeId;
use crate::gravatar;
use crate::http::Transport;
use crate::identity_resolution::AutoMergePolicy;
use crate::lineage::{Lineage, Observation, ObservedLineage, UpstreamKind, resolve_with_lineage};
use crate::source_outcome::SourceExecutionOutcome;
use crate::textnorm::upper_first;
use crate::uid;

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
        let mut positional = Vec::new();
        let mut save = None;
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--save" => {
                    if save.is_some() {
                        return Err(Error::Invalid("only one --save".into()));
                    }
                    let path = it
                        .next()
                        .cloned()
                        .ok_or_else(|| Error::Invalid("--save needs a value".into()))?;
                    if path.is_empty() || path.starts_with("--") {
                        return Err(Error::Invalid("--save needs a file path".into()));
                    }
                    save = Some(PathBuf::from(path));
                }
                flag if flag.starts_with("--") => {
                    return Err(Error::Invalid(format!("unknown option {flag}")));
                }
                value => positional.push(value.to_owned()),
            }
        }
        if positional.len() != 1 {
            return Err(Error::Invalid("email needs exactly one ADDR".into()));
        }
        let email = canonical_email(&positional[0])
            .ok_or_else(|| Error::Invalid("invalid email address".into()))?;
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
    let scan_id = uid::scan_id("email", &email);
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

    match render(&report) {
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

fn merge_by_uid(entities: &mut Vec<Entity>) {
    let mut merged: Vec<Entity> = Vec::new();
    for entity in entities.drain(..) {
        if let Some(existing) = merged.iter_mut().find(|seen| seen.uid == entity.uid) {
            existing.absorb(entity);
        } else {
            merged.push(entity);
        }
    }
    *entities = merged;
}

fn render(report: &Report) -> Result<String, String> {
    let mut out = format!("entities={}\n", report.entities.len());
    for entity in &report.entities {
        writeln!(
            out,
            "{}\t{}\t{:.2}\t{}",
            entity.kind,
            entity.raw_value,
            entity.confidence,
            entity.tags.join(",")
        )
        .map_err(|err| err.to_string())?;
    }
    for outcome in &report.outcomes {
        let found = outcome
            .found
            .map_or_else(|| "none".to_owned(), |count| count.to_string());
        let kind = serde_json::to_value(outcome.kind)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "unknown".into());
        writeln!(out, "{}\t{kind}\tfound={found}", outcome.module)
            .map_err(|err| err.to_string())?;
    }
    append_lineage(report, &mut out)?;
    Ok(out)
}

fn append_lineage(report: &Report, out: &mut String) -> Result<(), String> {
    let observations = observations(report);
    if observations.is_empty() {
        return Ok(());
    }
    let resolution = resolve_with_lineage(observations, Vec::new(), AutoMergePolicy::default())
        .map_err(|err| err.to_string())?;
    writeln!(out, "lineage={}", resolution.observations.len()).map_err(|err| err.to_string())?;
    for item in &resolution.observations {
        writeln!(out, "{}", lineage_line(item)).map_err(|err| err.to_string())?;
    }
    Ok(())
}

fn observations(report: &Report) -> Vec<Observation> {
    report
        .entities
        .iter()
        .enumerate()
        .flat_map(|(entity_index, entity)| {
            entity
                .evidence
                .iter()
                .enumerate()
                .map(move |(evidence_index, evidence)| Observation {
                    id: EvidenceNodeId(format!("{}:{entity_index}:{evidence_index}", entity.uid)),
                    evidence: evidence.clone(),
                })
        })
        .collect()
}

fn lineage_line(item: &ObservedLineage) -> String {
    let id = &item.observation.id.0;
    match &item.lineage {
        Lineage::Upstream { kind, family, .. } => {
            format!("{id}\t{}\t{family}", upstream_kind_label(*kind))
        }
        Lineage::Unattributed => format!("{id}\tunattributed"),
        Lineage::Ambiguous { field, values } => {
            format!("{id}\tambiguous\t{field}\t{}", values.join(";"))
        }
    }
}

const fn upstream_kind_label(kind: UpstreamKind) -> &'static str {
    match kind {
        UpstreamKind::Dataset => "dataset",
        UpstreamKind::Registry => "registry",
        UpstreamKind::Source => "source",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    use crate::http::{Request, Response, TransportFailure};
    use crate::source_outcome::SourceOutcomeKind;

    struct Fake {
        response: RefCell<Option<Result<Response, TransportFailure>>>,
    }

    impl Fake {
        fn response(status: u16, body: &str) -> Self {
            Self {
                response: RefCell::new(Some(Ok(Response {
                    status,
                    headers: vec![("content-type".into(), "application/json".into())],
                    body: body.as_bytes().to_vec(),
                    truncated: false,
                }))),
            }
        }
    }

    impl Transport for Fake {
        fn send(&self, _request: &Request) -> Result<Response, TransportFailure> {
            self.response
                .borrow_mut()
                .take()
                .expect("one request expected")
        }
    }

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
        let values: BTreeSet<(EntityKind, String)> = entities
            .iter()
            .map(|entity| (entity.kind.clone(), entity.value.clone()))
            .collect();
        assert!(values.contains(&(EntityKind::Domain, "acme.example".into())));
        assert!(values.contains(&(EntityKind::Username, "janedoe".into())));
        assert!(values.contains(&(EntityKind::Username, "jdoe".into())));
        assert!(values.contains(&(EntityKind::Username, "jane_doe".into())));
        assert!(values.contains(&(EntityKind::Person, "jane doe".into())));
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
        match run(&Fake::response(200, body), "jane.doe@acme.example", 1) {
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
        match run(&Fake::response(404, ""), "jane.doe@gmail.com", 1) {
            EmailRun::Printed { report, .. } => {
                assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::ValidZero);
                assert!(!report.entities.is_empty());
            }
            other => panic!("{other:?}"),
        }
    }
}
