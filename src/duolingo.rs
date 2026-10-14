//! Duolingo account lookup by email.
//!
//! Duolingo's public user endpoint filters by email and answers with the matching
//! accounts' public profile fields, so one explicit email lookup becomes one guarded
//! request. An empty `users` list is a validated absence; a body without that list
//! is drift, never "not found".

use serde::Deserialize;

use crate::canonical::canonical_email;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid};
use crate::error::Error;
use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Transport, append_query_param};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, classify_fetch};

pub const SRC: &str = "duolingo";

const API: &str = "https://www.duolingo.com/2017-06-30/users";
const FIELDS: &str =
    "users{id,username,name,bio,location,creationDate,hasPhoneNumber,hasPlus,learningLanguage}";

/// Duolingo matched the account on the exact address, so the handle is close to certain.
const CONF_USERNAME: f64 = 0.85;
const CONF_PROFILE: f64 = 0.80;
/// Display names and locations are free text the account holder typed.
const CONF_PERSON: f64 = 0.60;
const CONF_ADDRESS: f64 = 0.45;

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

#[derive(Debug, Deserialize)]
struct Envelope {
    users: Option<Vec<User>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct User {
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    bio: Option<String>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    creation_date: Option<u64>,
    #[serde(default)]
    has_phone_number: Option<bool>,
    #[serde(default)]
    has_plus: Option<bool>,
    #[serde(default)]
    learning_language: Option<String>,
}

/// Look up the Duolingo accounts registered to one email address.
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
    let url = append_query_param(&append_query_param(API, "email", &email), "fields", FIELDS);
    let fetched = fetch(
        transport,
        Request::get(url)
            .header("accept", "application/json")
            .header("user-agent", crate::http::DEFAULT_USER_AGENT),
        None,
        &FetchOptions::no_redirects().paced(),
        SRC,
        now_unix,
    )?;
    let Some(response) = fetched.response else {
        return Ok(empty(fetched.outcome));
    };
    let failed = |kind, detail: String| {
        empty(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            kind,
            Some(response.status),
            detail,
        ))
    };
    if response.truncated {
        return Ok(failed(
            SourceOutcomeKind::ParserDrift,
            "truncated Duolingo response".into(),
        ));
    }
    let classified = classify_fetch(response.status, &response.text());
    if classified != SourceOutcomeKind::Inconclusive {
        return Ok(failed(
            classified,
            "Duolingo response was not a user list".into(),
        ));
    }
    let envelope: Envelope = match serde_json::from_slice(&response.body) {
        Ok(value) => value,
        Err(err) => {
            return Ok(failed(
                SourceOutcomeKind::ParserDrift,
                format!("Duolingo JSON: {err}"),
            ));
        }
    };
    let Some(users) = envelope.users else {
        return Ok(failed(
            SourceOutcomeKind::SchemaDrift,
            "Duolingo JSON has no users field".into(),
        ));
    };
    let accounts: Vec<&User> = users
        .iter()
        .filter(|user| {
            user.username
                .as_deref()
                .is_some_and(|u| !u.trim().is_empty())
        })
        .collect();
    if accounts.is_empty() {
        if users.is_empty() {
            return Ok(empty(
                SourceExecutionOutcome::valid_zero(SRC, now_unix).with_http_status(response.status),
            ));
        }
        return Ok(failed(
            SourceOutcomeKind::SchemaDrift,
            "Duolingo users carry no username".into(),
        ));
    }

    let mut entities = Vec::new();
    for user in &accounts {
        build_entities(user, scan_id, &mut entities);
    }
    merge_by_uid(&mut entities);
    Ok(Report {
        entities,
        outcome: SourceExecutionOutcome::success(SRC, now_unix, accounts.len())
            .with_http_status(response.status),
    })
}

fn empty(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

fn build_entities(user: &User, scan_id: &str, entities: &mut Vec<Entity>) {
    let Some(username) = user.username.as_deref().map(str::trim) else {
        return;
    };
    let profile_url = format!(
        "https://www.duolingo.com/profile/{}",
        crate::http::percent_encode_unreserved(username)
    );
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        "Duolingo account registered to the address",
    )
    .with_attr("dataset", "Duolingo public user profiles")
    .with_attr("platform", "duolingo")
    .with_attr("profile_url", &profile_url);
    if let Some(id) = user.id {
        evidence = evidence.with_attr("account_id", id.to_string());
    }
    if let Some(created) = user.creation_date {
        evidence = evidence.with_attr("account_created_unix", created.to_string());
    }
    if let Some(phone) = user.has_phone_number {
        evidence = evidence.with_attr("has_phone_number", phone.to_string());
    }
    if let Some(plus) = user.has_plus {
        evidence = evidence.with_attr("paid_subscription", plus.to_string());
    }
    if let Some(language) = nonblank(user.learning_language.as_deref()) {
        evidence = evidence.with_attr("learning_language", language);
    }
    if let Some(bio) = nonblank(user.bio.as_deref()) {
        evidence = evidence.with_attr("bio", bio);
    }

    add_entity(
        entities,
        EntityKind::Username,
        username,
        CONF_USERNAME,
        scan_id,
        &evidence,
    );
    add_entity(
        entities,
        EntityKind::Url,
        &profile_url,
        CONF_PROFILE,
        scan_id,
        &evidence,
    );
    if let Some(name) =
        nonblank(user.name.as_deref()).filter(|name| name.split_whitespace().count() >= 2)
    {
        add_entity(
            entities,
            EntityKind::Person,
            name,
            CONF_PERSON,
            scan_id,
            &evidence,
        );
    }
    if let Some(location) = nonblank(user.location.as_deref()) {
        add_entity(
            entities,
            EntityKind::Address,
            location,
            CONF_ADDRESS,
            scan_id,
            &evidence,
        );
    }
}

fn nonblank(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn add_entity(
    entities: &mut Vec<Entity>,
    kind: EntityKind,
    value: &str,
    confidence: f64,
    scan_id: &str,
    evidence: &Evidence,
) {
    let mut entity = Entity::new(kind, value, confidence, scan_id);
    entity.tag(SRC);
    entity.tag("public-profile");
    entity.add_evidence(evidence.clone());
    entities.push(entity);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{OneResponse, ScriptedTransport, json_ok};

    // Recorded from the live endpoint on 2026-10-14 (username lookup of a public account).
    const RECORDED: &str = r#"{"users":[{"id":14,"bio":"","learningLanguage":"fr","location":"Guatemala","name":"Luis","username":"Luis","hasPlus":true,"creationDate":1322621037,"hasPhoneNumber":false,"totalXp":387471}]}"#;

    #[test]
    fn request_filters_by_the_canonical_address() {
        let transport = ScriptedTransport::new(vec![Ok(json_ok(r#"{"users":[]}"#))]);
        lookup(&transport, " Jane.Doe@Example.COM ", "scan", 1).unwrap();
        let seen = transport.seen.borrow();
        assert_eq!(seen.len(), 1);
        assert!(
            seen[0].url.starts_with(
                "https://www.duolingo.com/2017-06-30/users?email=jane.doe%40example.com&fields="
            ),
            "{}",
            seen[0].url
        );
    }

    #[test]
    fn empty_user_list_is_valid_zero() {
        let report = lookup(
            &OneResponse::json(200, r#"{"users":[]}"#),
            "a@example.com",
            "s",
            1,
        )
        .unwrap();
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn recorded_account_emits_handle_profile_and_location() {
        let report = lookup(&OneResponse::json(200, RECORDED), "a@example.com", "s", 1).unwrap();
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert_eq!(report.outcome.found, Some(1));
        let handle = report
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Username)
            .expect("username");
        assert_eq!(handle.raw_value, "Luis");
        let evidence = &handle.evidence[0];
        let attr = |key: &str| evidence.attributes.get(key).map(String::as_str);
        assert_eq!(attr("account_created_unix"), Some("1322621037"));
        assert_eq!(attr("has_phone_number"), Some("false"));
        assert!(
            report.entities.iter().any(|e| e.kind == EntityKind::Url
                && e.raw_value == "https://www.duolingo.com/profile/Luis")
        );
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Address)
        );
        // A one-word display name is not a person.
        assert!(!report.entities.iter().any(|e| e.kind == EntityKind::Person));
    }

    #[test]
    fn drift_is_never_a_clean_miss() {
        for body in [
            r#"{"errors":[]}"#,
            r#"{"users":"x"}"#,
            r#"{"users":[{"id":3}]}"#,
            "<html>",
        ] {
            let report = lookup(&OneResponse::json(200, body), "a@example.com", "s", 1).unwrap();
            assert!(
                matches!(
                    report.outcome.kind,
                    SourceOutcomeKind::SchemaDrift | SourceOutcomeKind::ParserDrift
                ),
                "{body}: {:?}",
                report.outcome.kind
            );
            assert!(report.entities.is_empty());
        }
    }
}
