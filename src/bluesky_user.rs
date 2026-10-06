//! Keyless Bluesky / AT Protocol public-profile lookup.

use serde::Deserialize;

use crate::atproto::{
    bare_handle, handle_domain_confidence, is_dns_label, is_handle, platform_handle_suffix,
};
use crate::canonical::canonical_domain;
use crate::classifier;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::error::Error;
use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Transport, append_query_param};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, classify_fetch};

pub const SRC: &str = "bluesky_user";
const API: &str = "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile";

const USERNAME_CONF: f64 = 0.85;
const PERSON_CONF: f64 = 0.60;
const URL_CONF: f64 = 0.75;
const BIO_CONF_CAP: f64 = 0.70;
const DID_CONF: f64 = 0.85;

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Profile {
    handle: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    did: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
}

/// Query one public Bluesky profile.
///
/// # Errors
/// Returns a network-boundary error when the guarded fetch refuses a URL.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    username: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let selector = username.trim().trim_start_matches('@').to_ascii_lowercase();
    let actor = if is_dns_label(&selector) {
        format!("{selector}.bsky.social")
    } else if is_handle(&selector) {
        selector.clone()
    } else {
        return Ok(Report {
            entities: Vec::new(),
            outcome: inconclusive(now_unix, "selector cannot form a valid AT Protocol actor"),
        });
    };

    let url = append_query_param(API, "actor", &actor);
    let fetched = fetch(
        transport,
        Request::get(url)
            .header("accept", "application/json")
            .header("user-agent", crate::http::DEFAULT_USER_AGENT),
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

    if matches!(response.status, 400 | 404) {
        return Ok(Report {
            entities: Vec::new(),
            outcome: SourceExecutionOutcome::valid_zero(SRC, now_unix)
                .with_http_status(response.status),
        });
    }

    if response.truncated {
        return Ok(Report {
            entities: Vec::new(),
            outcome: failed(
                now_unix,
                SourceOutcomeKind::ParserDrift,
                Some(response.status),
                "truncated Bluesky response",
            ),
        });
    }

    let body = response.text();
    let classified = classify_fetch(response.status, &body);
    if classified != SourceOutcomeKind::Inconclusive {
        return Ok(Report {
            entities: Vec::new(),
            outcome: failed(
                now_unix,
                classified,
                Some(response.status),
                "Bluesky response was not a profile document",
            ),
        });
    }

    let profile: Profile = match serde_json::from_slice(&response.body) {
        Ok(profile) => profile,
        Err(error) => {
            return Ok(Report {
                entities: Vec::new(),
                outcome: failed(
                    now_unix,
                    SourceOutcomeKind::ParserDrift,
                    Some(response.status),
                    &format!("Bluesky JSON: {error}"),
                ),
            });
        }
    };
    if profile.handle.trim().is_empty() {
        return Ok(Report {
            entities: Vec::new(),
            outcome: failed(
                now_unix,
                SourceOutcomeKind::SchemaDrift,
                Some(response.status),
                "Bluesky profile has no handle",
            ),
        });
    }

    let mut entities = build_entities(&profile, scan_id);
    merge_by_uid(&mut entities);
    Ok(Report {
        entities,
        outcome: SourceExecutionOutcome::success(SRC, now_unix, 1)
            .with_http_status(response.status),
    })
}

fn inconclusive(now_unix: u64, detail: &str) -> SourceExecutionOutcome {
    SourceExecutionOutcome {
        module: SRC.into(),
        kind: SourceOutcomeKind::Inconclusive,
        observed_at_unix: now_unix,
        http_status: None,
        found: None,
        retry_after_secs: None,
        detail: Some(detail.into()),
    }
}

fn failed(
    now_unix: u64,
    kind: SourceOutcomeKind,
    status: Option<u16>,
    detail: &str,
) -> SourceExecutionOutcome {
    SourceExecutionOutcome {
        module: SRC.into(),
        kind,
        observed_at_unix: now_unix,
        http_status: status,
        found: None,
        retry_after_secs: None,
        detail: Some(detail.into()),
    }
}

fn evidence(profile: &Profile, scan_id: &str) -> Evidence {
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        format!("Bluesky public profile {}", profile.handle),
    )
    .with_attr("dataset", "Bluesky public profiles")
    .with_attr("bsky_handle", &profile.handle);

    if let Some(value) = profile
        .did
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        evidence = evidence.with_attr("did", value);
    }
    if let Some(value) = profile
        .created_at
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        evidence = evidence.with_attr("created_at", value);
    }
    if let Some(value) = profile
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        evidence = evidence.with_attr("display_name", value);
    }
    evidence
}

fn build_entities(profile: &Profile, scan_id: &str) -> Vec<Entity> {
    let base = evidence(profile, scan_id);
    let mut entities = Vec::new();
    let bare = bare_handle(&profile.handle);

    add(
        &mut entities,
        EntityKind::Username,
        bare,
        USERNAME_CONF,
        scan_id,
        base.clone(),
        &["bluesky", "public-profile"],
    );

    let profile_url = format!("https://bsky.app/profile/{}", profile.handle);
    add(
        &mut entities,
        EntityKind::Url,
        &profile_url,
        URL_CONF,
        scan_id,
        base.clone(),
        &["bluesky", "public-profile"],
    );

    if let Some(name) = profile
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|name| name.split_whitespace().count() >= 2)
    {
        add(
            &mut entities,
            EntityKind::Person,
            name,
            PERSON_CONF,
            scan_id,
            base.clone(),
            &["bluesky", "public-profile"],
        );
    }

    let domain = profile.handle.trim_end_matches('.');
    if platform_handle_suffix(domain).is_none() && canonical_domain(domain).is_some() {
        add(
            &mut entities,
            EntityKind::Domain,
            domain,
            handle_domain_confidence(true, domain),
            scan_id,
            base.clone(),
            &["bluesky", "custom-handle", "verified-control"],
        );
    }

    if let Some(did) = profile
        .did
        .as_deref()
        .map(str::trim)
        .filter(|did| !did.is_empty())
    {
        add(
            &mut entities,
            EntityKind::Other,
            did,
            DID_CONF,
            scan_id,
            base.clone(),
            &["bluesky", "did"],
        );
    }

    if let Some(description) = profile.description.as_deref() {
        for classified in classifier::extract(description)
            .into_iter()
            .filter(|item| matches!(item.kind, EntityKind::Email | EntityKind::Url))
        {
            add(
                &mut entities,
                classified.kind,
                &classified.value,
                classified.confidence.min(BIO_CONF_CAP),
                scan_id,
                base.clone().with_attr("source_field", "description"),
                &["bluesky", "public-profile"],
            );
        }
    }

    entities
}

fn add(
    entities: &mut Vec<Entity>,
    kind: EntityKind,
    value: &str,
    confidence: f64,
    scan_id: &str,
    evidence: Evidence,
    tags: &[&str],
) {
    let mut entity = Entity::new(kind, value, confidence, scan_id);
    for tag in tags {
        entity.tag(*tag);
    }
    entity.add_evidence(evidence);
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
    fn invalid_actor_shape_is_inconclusive_without_network() {
        struct Never;
        impl Transport for Never {
            fn send(&self, _request: &Request) -> Result<Response, TransportFailure> {
                panic!("network must not be used")
            }
        }
        let got = lookup(&Never, "_invalid_", "scan", 1).unwrap();
        assert_eq!(got.outcome.kind, SourceOutcomeKind::Inconclusive);
    }

    #[test]
    fn missing_profile_is_valid_zero() {
        let got = lookup(&Fake::response(400, "{}"), "nobody", "scan", 1).unwrap();
        assert_eq!(got.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn platform_profile_emits_username_person_and_profile_url() {
        let body = r#"{
          "handle":"alice.bsky.social",
          "displayName":"Alice Citizen",
          "description":"contact alice@example.org https://example.org",
          "did":"did:plc:oky5czdrnfjpqslsw2a5iclo",
          "createdAt":"2024-01-02T03:04:05Z"
        }"#;
        let got = lookup(&Fake::response(200, body), "alice", "scan", 1).unwrap();
        assert_eq!(got.outcome.kind, SourceOutcomeKind::Success);
        for kind in [
            EntityKind::Username,
            EntityKind::Person,
            EntityKind::Email,
            EntityKind::Url,
            EntityKind::Other,
        ] {
            assert!(
                got.entities.iter().any(|entity| entity.kind == kind),
                "missing {kind}"
            );
        }
        assert!(!got.entities.iter().any(|entity| {
            entity.kind == EntityKind::Domain && entity.value == "alice.bsky.social"
        }));
    }

    #[test]
    fn custom_domain_handle_emits_domain() {
        let body = r#"{"handle":"alice.example.org","did":"did:plc:oky5czdrnfjpqslsw2a5iclo"}"#;
        let got = lookup(&Fake::response(200, body), "alice.example.org", "scan", 1).unwrap();
        assert!(
            got.entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Domain
                    && entity.value == "alice.example.org")
        );
    }
}
