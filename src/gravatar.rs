//! Gravatar public-profile lookup.
//!
//! One explicit email lookup becomes one guarded request to Gravatar's public
//! profile endpoint. A 404 is a validated absence; malformed or truncated
//! responses are never treated as "not found".

use serde::Deserialize;

use crate::canonical::canonical_email;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::error::Error;
use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Transport};
use crate::md5::normalized_email_hex;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, classify_fetch};

pub const SRC: &str = "gravatar";

const CONF_PERSON: f64 = 0.70;
const CONF_USERNAME: f64 = 0.65;
const CONF_EMAIL: f64 = 0.70;
const CONF_PROFILE: f64 = 0.60;
const CONF_ADDRESS: f64 = 0.55;
const CONF_ORG: f64 = 0.55;

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

#[derive(Debug, Deserialize)]
struct Envelope {
    entry: Option<Vec<Profile>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Profile {
    #[serde(default, rename = "profileUrl")]
    public_url: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    current_location: Option<String>,
    #[serde(default)]
    thumbnail_url: Option<String>,
    #[serde(default)]
    name: Option<Name>,
    #[serde(default)]
    urls: Vec<UrlEntry>,
    #[serde(default)]
    accounts: Vec<Account>,
    #[serde(default)]
    emails: Vec<ProfileEmail>,
    #[serde(default)]
    company: Option<String>,
    #[serde(default)]
    job_title: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Name {
    #[serde(default)]
    formatted: Option<String>,
    #[serde(default, rename = "givenName")]
    given: Option<String>,
    #[serde(default, rename = "familyName")]
    family: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct UrlEntry {
    #[serde(default)]
    value: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ProfileEmail {
    #[serde(default)]
    value: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Account {
    #[serde(default)]
    shortname: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    verified: Option<bool>,
}

/// Look up one public Gravatar profile.
///
/// # Errors
/// Invalid email input or a request refused by the shared transport boundary.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    email: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let email = canonical_email(email).ok_or_else(|| Error::Invalid("invalid email".into()))?;
    let hash = normalized_email_hex(&email);
    let url = format!("https://gravatar.com/{hash}.json");
    let fetched = fetch(
        transport,
        Request::get(&url).header("accept", "application/json"),
        None,
        &FetchOptions::no_redirects(),
        SRC,
        now_unix,
    )?;

    let Some(response) = fetched.response else {
        return Ok(Report {
            entities: Vec::new(),
            outcome: fetched.outcome,
        });
    };

    if response.status == 404 {
        return Ok(Report {
            entities: Vec::new(),
            outcome: SourceExecutionOutcome::valid_zero(SRC, now_unix)
                .with_http_status(response.status),
        });
    }

    if response.truncated {
        return Ok(Report {
            entities: Vec::new(),
            outcome: failed_outcome(
                now_unix,
                SourceOutcomeKind::ParserDrift,
                Some(response.status),
                "truncated Gravatar response",
            ),
        });
    }

    let body = response.text();
    let classified = classify_fetch(response.status, &body);
    if classified != SourceOutcomeKind::Inconclusive {
        return Ok(Report {
            entities: Vec::new(),
            outcome: failed_outcome(
                now_unix,
                classified,
                Some(response.status),
                "Gravatar response was not a profile document",
            ),
        });
    }

    let envelope: Envelope = match serde_json::from_slice(&response.body) {
        Ok(value) => value,
        Err(err) => {
            return Ok(Report {
                entities: Vec::new(),
                outcome: failed_outcome(
                    now_unix,
                    SourceOutcomeKind::ParserDrift,
                    Some(response.status),
                    &format!("Gravatar JSON: {err}"),
                ),
            });
        }
    };
    let Some(profiles) = envelope.entry else {
        return Ok(Report {
            entities: Vec::new(),
            outcome: failed_outcome(
                now_unix,
                SourceOutcomeKind::SchemaDrift,
                Some(response.status),
                "Gravatar JSON has no entry field",
            ),
        });
    };
    if profiles.is_empty() {
        return Ok(Report {
            entities: Vec::new(),
            outcome: SourceExecutionOutcome::valid_zero(SRC, now_unix)
                .with_http_status(response.status),
        });
    }

    let mut entities = Vec::new();
    for profile in &profiles {
        build_entities(profile, &hash, scan_id, &mut entities);
    }
    merge_by_uid(&mut entities);

    Ok(Report {
        entities,
        outcome: SourceExecutionOutcome::success(SRC, now_unix, profiles.len())
            .with_http_status(response.status),
    })
}

fn failed_outcome(
    now_unix: u64,
    kind: SourceOutcomeKind,
    status: Option<u16>,
    detail: &str,
) -> SourceExecutionOutcome {
    let mut outcome = SourceExecutionOutcome::success(SRC, now_unix, 0);
    outcome.kind = kind;
    outcome.found = None;
    outcome.http_status = status;
    outcome.detail = Some(detail.to_owned());
    outcome
}

fn profile_evidence(hash: &str, profile: &Profile, scan_id: &str) -> Evidence {
    Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        "Gravatar public profile",
    )
    .with_attr("dataset", "Gravatar public profiles")
    .with_attr("profile_hash", hash)
    .with_attr(
        "profile_url",
        profile
            .public_url
            .as_deref()
            .unwrap_or("https://gravatar.com/"),
    )
}

fn add_entity(
    entities: &mut Vec<Entity>,
    kind: EntityKind,
    value: &str,
    confidence: f64,
    scan_id: &str,
    evidence: Evidence,
) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    let mut entity = Entity::new(kind, value, confidence, scan_id);
    entity.tag(SRC);
    entity.tag("public-profile");
    entity.add_evidence(evidence);
    entities.push(entity);
}

fn build_entities(profile: &Profile, hash: &str, scan_id: &str, entities: &mut Vec<Entity>) {
    let evidence = profile_evidence(hash, profile, scan_id);
    add_identity(profile, scan_id, &evidence, entities);
    add_profile_urls(profile, scan_id, &evidence, entities);
    add_accounts(profile, scan_id, &evidence, entities);
    add_contacts(profile, scan_id, &evidence, entities);
}

fn add_identity(profile: &Profile, scan_id: &str, evidence: &Evidence, entities: &mut Vec<Entity>) {
    let name = profile
        .name
        .as_ref()
        .and_then(|name| {
            name.formatted.clone().or_else(|| {
                match (
                    name.given.as_deref().map(str::trim),
                    name.family.as_deref().map(str::trim),
                ) {
                    (Some(given), Some(family)) if !given.is_empty() && !family.is_empty() => {
                        Some(format!("{given} {family}"))
                    }
                    _ => None,
                }
            })
        })
        .or_else(|| {
            profile
                .display_name
                .clone()
                .filter(|value| value.split_whitespace().count() >= 2)
        });
    if let Some(name) = name {
        add_entity(
            entities,
            EntityKind::Person,
            &name,
            CONF_PERSON,
            scan_id,
            evidence.clone(),
        );
    }

    if let Some(username) = profile.preferred_username.as_deref() {
        add_entity(
            entities,
            EntityKind::Username,
            username,
            CONF_USERNAME,
            scan_id,
            evidence.clone(),
        );
    }

    if let Some(location) = profile.current_location.as_deref() {
        add_entity(
            entities,
            EntityKind::Address,
            location,
            CONF_ADDRESS,
            scan_id,
            evidence.clone(),
        );
    }

    if let Some(company) = profile.company.as_deref() {
        let mut company_evidence = evidence.clone();
        if let Some(title) = profile
            .job_title
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            company_evidence = company_evidence.with_attr("job_title", title);
        }
        add_entity(
            entities,
            EntityKind::Organisation,
            company,
            CONF_ORG,
            scan_id,
            company_evidence,
        );
    }
}

fn add_profile_urls(
    profile: &Profile,
    scan_id: &str,
    evidence: &Evidence,
    entities: &mut Vec<Entity>,
) {
    for value in [
        profile.public_url.as_deref(),
        profile.thumbnail_url.as_deref(),
    ]
    .into_iter()
    .flatten()
    .chain(profile.urls.iter().filter_map(|item| item.value.as_deref()))
    {
        if value.trim().starts_with("http://") || value.trim().starts_with("https://") {
            add_entity(
                entities,
                EntityKind::Url,
                value,
                CONF_PROFILE,
                scan_id,
                evidence.clone(),
            );
        }
    }
}

fn add_accounts(profile: &Profile, scan_id: &str, evidence: &Evidence, entities: &mut Vec<Entity>) {
    for account in &profile.accounts {
        let platform = account
            .shortname
            .as_deref()
            .or(account.domain.as_deref())
            .unwrap_or("account")
            .trim();
        let confidence = if account.verified == Some(true) {
            CONF_PERSON
        } else {
            CONF_PROFILE
        };
        if let Some(username) = account.username.as_deref() {
            add_entity(
                entities,
                EntityKind::Username,
                username,
                confidence,
                scan_id,
                evidence.clone().with_attr("platform", platform),
            );
        }
        if let Some(url) = account.url.as_deref() {
            if url.trim().starts_with("http://") || url.trim().starts_with("https://") {
                add_entity(
                    entities,
                    EntityKind::Url,
                    url,
                    confidence,
                    scan_id,
                    evidence.clone().with_attr("platform", platform),
                );
            }
        }
    }
}

fn add_contacts(profile: &Profile, scan_id: &str, evidence: &Evidence, entities: &mut Vec<Entity>) {
    for email in profile
        .emails
        .iter()
        .filter_map(|item| item.value.as_deref())
    {
        if canonical_email(email).is_some() {
            add_entity(
                entities,
                EntityKind::Email,
                email,
                CONF_EMAIL,
                scan_id,
                evidence.clone(),
            );
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    use crate::http::{Response, TransportFailure};

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
    fn missing_profile_is_valid_zero() {
        let report = lookup(&Fake::response(404, ""), "a@example.com", "scan", 1).unwrap();
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn profile_emits_identity_and_links() {
        let body = r#"{
          "entry":[{
            "displayName":"Jane Citizen",
            "preferredUsername":"janec",
            "currentLocation":"Brisbane, Australia",
            "profileUrl":"https://gravatar.com/janec",
            "thumbnailUrl":"https://example.com/avatar.jpg",
            "company":"Example Pty Ltd",
            "jobTitle":"Engineer",
            "urls":[{"value":"https://example.com/"}],
            "accounts":[{"shortname":"github","username":"janec","url":"https://github.com/janec","verified":true}],
            "emails":[{"value":"jane.work@example.org"}]
          }]
        }"#;
        let report = lookup(&Fake::response(200, body), "Jane@example.com", "scan", 1).unwrap();
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(report.entities.iter().any(|e| e.kind == EntityKind::Person));
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Username)
        );
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Address)
        );
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Organisation)
        );
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Email && e.value == "jane.work@example.org")
        );
    }

    #[test]
    fn malformed_profile_is_not_a_clean_miss() {
        let report = lookup(
            &Fake::response(200, r#"{"entry":"wrong"}"#),
            "a@example.com",
            "scan",
            1,
        )
        .unwrap();
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ParserDrift);
    }
}
