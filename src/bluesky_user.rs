//! Keyless Bluesky / AT Protocol public-profile lookup.

use serde::Deserialize;

use crate::atproto::{bare_handle, handle_domain_confidence, platform_handle_suffix};
use crate::canonical::{canonical_domain, is_domain_label};
use crate::classifier;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Transport, append_query_param};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

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
struct XrpcError {
    error: String,
    message: String,
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
    let actor = if is_domain_label(&selector) {
        format!("{selector}.bsky.social")
    } else if canonical_domain(&selector).is_some() {
        selector.clone()
    } else {
        return Ok(Report {
            entities: Vec::new(),
            outcome: SourceExecutionOutcome::inconclusive(
                SRC,
                now_unix,
                "selector cannot form a valid AT Protocol actor",
            ),
        });
    };

    let url = append_query_param(API, "actor", &actor);
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
    Ok(interpret(&fetched, scan_id, now_unix).unwrap_or_else(miss))
}

/// A report that found nothing, carrying only its outcome. **Pure.**
fn miss(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

/// Turn one fetched profile response into a report; `Err` is the outcome of a response that named
/// no profile. **Pure.**
fn interpret(
    fetched: &Fetched,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, SourceExecutionOutcome> {
    let response = whole_response(fetched, "Bluesky")?;
    // XRPC uses HTTP 400 for several *different* failures. Only the specific
    // InvalidRequest / Profile not found document establishes a zero match.
    // Other 4xx errors (including suspended accounts and malformed actors)
    // must not become false absence evidence.
    if is_explicit_profile_missing(response.status, &response.body) {
        return Err(
            SourceExecutionOutcome::valid_zero(SRC, now_unix).with_http_status(response.status)
        );
    }
    answer(fetched, "Bluesky")?;
    let profile: Profile = decode_json(response, SRC, now_unix, "Bluesky")?;
    if profile.handle.trim().is_empty() {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            "Bluesky profile has no handle",
        ));
    }

    let mut entities = build_entities(&profile, scan_id);
    merge_by_uid(&mut entities);
    Ok(Report {
        entities,
        outcome: SourceExecutionOutcome::success(SRC, now_unix, 1)
            .with_http_status(response.status),
    })
}

fn is_explicit_profile_missing(status: u16, body: &[u8]) -> bool {
    matches!(status, 400 | 404)
        && serde_json::from_slice::<XrpcError>(body).is_ok_and(|error| {
            error.error == "InvalidRequest" && error.message == "Profile not found"
        })
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
    let profile_evidence = evidence(profile, scan_id);
    let mut entities = Vec::new();
    let username = bare_handle(&profile.handle);

    push_entity(
        &mut entities,
        EntityKind::Username,
        username,
        USERNAME_CONF,
        scan_id,
        profile_evidence.clone(),
        &["bluesky", "public-profile"],
    );

    let profile_url = format!("https://bsky.app/profile/{}", profile.handle);
    push_entity(
        &mut entities,
        EntityKind::Url,
        &profile_url,
        URL_CONF,
        scan_id,
        profile_evidence.clone(),
        &["bluesky", "public-profile"],
    );

    if let Some(name) = profile
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|name| name.split_whitespace().count() >= 2)
    {
        push_entity(
            &mut entities,
            EntityKind::Person,
            name,
            PERSON_CONF,
            scan_id,
            profile_evidence.clone(),
            &["bluesky", "public-profile"],
        );
    }

    let domain = profile.handle.trim_end_matches('.');
    if platform_handle_suffix(domain).is_none() && canonical_domain(domain).is_some() {
        push_entity(
            &mut entities,
            EntityKind::Domain,
            domain,
            handle_domain_confidence(domain),
            scan_id,
            profile_evidence.clone(),
            &["bluesky", "custom-handle", "verified-control"],
        );
    }

    if let Some(did) = profile
        .did
        .as_deref()
        .map(str::trim)
        .filter(|did| !did.is_empty())
    {
        push_entity(
            &mut entities,
            EntityKind::Other,
            did,
            DID_CONF,
            scan_id,
            profile_evidence.clone(),
            &["bluesky", "did"],
        );
    }

    if let Some(description) = profile.description.as_deref() {
        for classified in classifier::extract(description)
            .into_iter()
            .filter(|item| matches!(item.kind, EntityKind::Email | EntityKind::Url))
        {
            push_entity(
                &mut entities,
                classified.kind,
                &classified.value,
                classified.confidence.min(BIO_CONF_CAP),
                scan_id,
                profile_evidence
                    .clone()
                    .with_attr("source_field", "description"),
                &["bluesky", "public-profile"],
            );
        }
    }

    entities
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::OneResponse;

    use crate::http::{Response, TransportFailure};

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
    fn missing_profile_is_valid_zero_only_with_explicit_xrpc_evidence() {
        for status in [400, 404] {
            let got = lookup(
                &OneResponse::json(
                    status,
                    r#"{"error":"InvalidRequest","message":"Profile not found"}"#,
                ),
                "nobody",
                "scan",
                1,
            )
            .unwrap();
            assert_eq!(got.outcome.kind, SourceOutcomeKind::ValidZero);
            assert_eq!(got.outcome.http_status, Some(status));
            assert_eq!(got.outcome.found, Some(0));
        }
    }

    #[test]
    fn unknown_or_invalid_actor_errors_never_prove_absence() {
        for (status, body) in [
            (400, "{}"),
            (
                400,
                r#"{"error":"InvalidRequest","message":"Invalid actor"}"#,
            ),
            (
                400,
                r#"{"error":"AccountTakedown","message":"Account has been suspended"}"#,
            ),
            (
                400,
                r#"{"error":"AccountDeactivated","message":"Account is deactivated"}"#,
            ),
            (400, "Profile not found"),
            (404, ""),
            (404, r#"{"error":"NotFound","message":"Profile not found"}"#),
        ] {
            let got = lookup(&OneResponse::json(status, body), "nobody", "scan", 1)
                .expect("provider result");
            assert_eq!(
                got.outcome.kind,
                SourceOutcomeKind::Upstream4xx,
                "HTTP {status} with {body}"
            );
            assert_eq!(got.outcome.http_status, Some(status));
            assert_eq!(got.outcome.found, None);
            assert!(got.entities.is_empty());
        }
    }

    #[test]
    fn refused_profile_challenge_is_a_waf_not_zero() {
        let got = lookup(
            &OneResponse::json(400, "<html>just a moment cloudflare</html>"),
            "nobody",
            "scan",
            1,
        )
        .unwrap();
        assert_eq!(got.outcome.kind, SourceOutcomeKind::BotWaf);
        assert_eq!(got.outcome.http_status, Some(400));
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
        let got = lookup(&OneResponse::json(200, body), "alice", "scan", 1).unwrap();
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
        let got = lookup(
            &OneResponse::json(200, body),
            "alice.example.org",
            "scan",
            1,
        )
        .unwrap();
        assert!(
            got.entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Domain
                    && entity.value == "alice.example.org")
        );
    }

    #[test]
    fn a_wrong_typed_profile_is_parser_drift_that_quotes_none_of_it() {
        let got = lookup(
            &OneResponse::json(200, r#""secret@example.com""#),
            "alice",
            "scan",
            1,
        )
        .unwrap();
        assert_eq!(got.outcome.kind, SourceOutcomeKind::ParserDrift);
        let detail = got.outcome.detail.unwrap_or_default();
        assert!(!detail.contains("secret@example.com"), "{detail}");
    }
}
