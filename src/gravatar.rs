//! Gravatar public-profile lookup.
//!
//! One explicit email lookup becomes one guarded request to Gravatar's public
//! profile endpoint. A 404 is a validated absence; malformed or truncated
//! responses are never treated as "not found".

use serde::Deserialize;

use crate::canonical::canonical_email;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid};
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
        &FetchOptions::no_redirects().paced(),
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
            outcome: SourceExecutionOutcome::failed(
                SRC,
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
            outcome: SourceExecutionOutcome::failed(
                SRC,
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
                outcome: SourceExecutionOutcome::failed(
                    SRC,
                    now_unix,
                    SourceOutcomeKind::ParserDrift,
                    Some(response.status),
                    format!("Gravatar JSON: {err}"),
                ),
            });
        }
    };
    let Some(profiles) = envelope.entry else {
        return Ok(Report {
            entities: Vec::new(),
            outcome: SourceExecutionOutcome::failed(
                SRC,
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
        build_entities(profile, &email, &hash, scan_id, &mut entities);
    }
    merge_by_uid(&mut entities);

    Ok(Report {
        entities,
        outcome: SourceExecutionOutcome::success(SRC, now_unix, profiles.len())
            .with_http_status(response.status),
    })
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

/// The evidence of one profile: as found, and as the relation builders read it for what the
/// person the profile names owns (`owner`). Without a name, both are the profile evidence.
struct ProfileEvidence {
    found: Evidence,
    owned: Evidence,
    person: Option<String>,
}

fn build_entities(
    profile: &Profile,
    email: &str,
    hash: &str,
    scan_id: &str,
    entities: &mut Vec<Entity>,
) {
    let found = profile_evidence(hash, profile, scan_id);
    let person = person_name(profile);
    let owned = match &person {
        Some(name) => found.clone().with_attr("owner", name),
        None => found.clone(),
    };
    let evidence = ProfileEvidence {
        found,
        owned,
        person,
    };
    // The profile is the one registered to the address looked up, so that address is the
    // person's as much as any address the profile lists.
    if evidence.person.is_some() {
        add_entity(
            entities,
            EntityKind::Email,
            email,
            CONF_EMAIL,
            scan_id,
            evidence.owned.clone(),
        );
    }
    add_identity(profile, scan_id, &evidence, entities);
    add_profile_urls(profile, scan_id, &evidence.found, entities);
    add_accounts(profile, scan_id, &evidence, entities);
    add_contacts(profile, scan_id, &evidence.owned, entities);
}

fn person_name(profile: &Profile) -> Option<String> {
    profile
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
        })
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
}

/// The person, the profile's own handle, its location and its employer. The person's evidence
/// names the employer (`employer`) and the location's names the person (`resident`), which is
/// what the relation builders read for employment and residence.
fn add_identity(
    profile: &Profile,
    scan_id: &str,
    evidence: &ProfileEvidence,
    entities: &mut Vec<Entity>,
) {
    let company = profile
        .company
        .as_deref()
        .map(str::trim)
        .filter(|company| !company.is_empty());
    if let Some(name) = evidence.person.as_deref() {
        let mut person_evidence = evidence.found.clone();
        if let Some(company) = company {
            person_evidence = person_evidence.with_attr("employer", company);
        }
        add_entity(
            entities,
            EntityKind::Person,
            name,
            CONF_PERSON,
            scan_id,
            person_evidence,
        );
    }

    if let Some(username) = profile.preferred_username.as_deref() {
        add_entity(
            entities,
            EntityKind::Username,
            username,
            CONF_USERNAME,
            scan_id,
            evidence.owned.clone(),
        );
    }

    if let Some(location) = profile.current_location.as_deref() {
        let mut location_evidence = evidence.found.clone();
        if let Some(name) = evidence.person.as_deref() {
            location_evidence = location_evidence.with_attr("resident", name);
        }
        add_entity(
            entities,
            EntityKind::Address,
            location,
            CONF_ADDRESS,
            scan_id,
            location_evidence,
        );
    }

    if let Some(company) = company {
        let mut company_evidence = evidence.found.clone();
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

/// A linked account Gravatar verified is the person's; an unverified one is only what the
/// profile claims, so it is found on the profile but not owned by the person.
fn add_accounts(
    profile: &Profile,
    scan_id: &str,
    evidence: &ProfileEvidence,
    entities: &mut Vec<Entity>,
) {
    for account in &profile.accounts {
        let platform = account
            .shortname
            .as_deref()
            .or(account.domain.as_deref())
            .unwrap_or("account")
            .trim();
        let (confidence, evidence) = if account.verified == Some(true) {
            (CONF_PERSON, &evidence.owned)
        } else {
            (CONF_PROFILE, &evidence.found)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relation::{self, RelationKind};
    use crate::test_support::OneResponse;

    #[test]
    fn missing_profile_is_valid_zero() {
        let report = lookup(&OneResponse::json(404, ""), "a@example.com", "scan", 1).unwrap();
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
        let report = lookup(&OneResponse::json(200, body), "Jane@example.com", "scan", 1).unwrap();
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

    /// The relations the analysis derives from one profile, as `(from, kind, to)` over the
    /// entities' values.
    fn profile_relations(body: &str) -> Vec<(String, RelationKind, String)> {
        let report = lookup(&OneResponse::json(200, body), "Jane@example.com", "scan", 1).unwrap();
        let value = |uid: &str| {
            report
                .entities
                .iter()
                .find(|entity| entity.uid == uid)
                .map(|entity| entity.value.clone())
                .expect("relation endpoint is an entity of the report")
        };
        let mut relations: Vec<_> = relation::derive_all(&report.entities, "scan")
            .into_iter()
            .filter(|edge| {
                matches!(
                    edge.kind,
                    RelationKind::IdentifiedBy | RelationKind::EmployedBy | RelationKind::LocatedAt
                )
            })
            .map(|edge| (value(&edge.from_uid), edge.kind, value(&edge.to_uid)))
            .collect();
        relations.sort();
        relations
    }

    #[test]
    fn the_person_a_profile_names_owns_what_it_lists_works_for_its_company_and_lives_there() {
        let body = r#"{
          "entry":[{
            "displayName":"Jane Citizen",
            "preferredUsername":"janec",
            "currentLocation":"Brisbane, Australia",
            "company":"Example Pty Ltd",
            "accounts":[
              {"shortname":"github","username":"janec-gh","url":"https://github.com/janec-gh","verified":true},
              {"shortname":"twitter","username":"someone_else","url":"https://x.com/someone_else"}
            ],
            "emails":[{"value":"jane.work@example.org"}]
          }]
        }"#;
        let jane = |kind, to: &str| ("jane citizen".to_owned(), kind, to.to_owned());
        assert_eq!(
            profile_relations(body),
            vec![
                jane(RelationKind::IdentifiedBy, "jane.work@example.org"),
                jane(RelationKind::IdentifiedBy, "jane@example.com"),
                jane(RelationKind::IdentifiedBy, "janec"),
                jane(RelationKind::IdentifiedBy, "janecgh"),
                jane(RelationKind::LocatedAt, "brisbane, australia"),
                jane(RelationKind::EmployedBy, "example pty ltd"),
            ],
            "an account Gravatar did not verify is the profile's claim, not the person's"
        );
    }

    #[test]
    fn a_profile_that_names_no_person_links_nothing_to_one() {
        let body = r#"{"entry":[{"displayName":"janec","preferredUsername":"janec",
          "currentLocation":"Brisbane","company":"Example Pty Ltd"}]}"#;
        assert_eq!(profile_relations(body), Vec::new());
        let report = lookup(&OneResponse::json(200, body), "Jane@example.com", "scan", 1).unwrap();
        assert!(
            !report.entities.iter().any(|e| e.kind == EntityKind::Email),
            "without a person the looked-up address gains nothing from the profile: {:?}",
            report.entities
        );
    }

    #[test]
    fn malformed_profile_is_not_a_clean_miss() {
        let report = lookup(
            &OneResponse::json(200, r#"{"entry":"wrong"}"#),
            "a@example.com",
            "scan",
            1,
        )
        .unwrap();
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ParserDrift);
    }
}
