//! Public Bluesky / AT Protocol profile lookup for username enrichment.

use serde::Deserialize;

use crate::atproto::{
    bare_handle, handle_domain_confidence, is_dns_label, is_handle, platform_handle_suffix,
};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::error::Error;
use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Transport, append_query_param};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, classify_fetch};

pub const SRC: &str = "bluesky_user";
const API: &str = "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile";

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
/// Plain DNS-label usernames are tried as `<name>.bsky.social`; already dotted
/// AT Protocol handles are used as-is.
///
/// # Errors
/// Request rejection from the shared transport.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    username: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let username = username.trim().trim_start_matches('@');
    let actor = if is_dns_label(username) {
        format!("{username}.bsky.social")
    } else if is_handle(username) {
        username.to_owned()
    } else {
        return Ok(Report {
            entities: Vec::new(),
            outcome: SourceExecutionOutcome::valid_zero(SRC, now_unix),
        });
    };

    let url = append_query_param(API, "actor", &actor);
    let fetched = fetch(
        transport,
        Request::get(url).header("accept", "application/json"),
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
        Err(err) => {
            return Ok(Report {
                entities: Vec::new(),
                outcome: failed(
                    now_unix,
                    SourceOutcomeKind::ParserDrift,
                    Some(response.status),
                    &format!("Bluesky JSON: {err}"),
                ),
            });
        }
    };

    let entities = build_entities(&profile, scan_id);
    Ok(Report {
        entities,
        outcome: SourceExecutionOutcome::success(SRC, now_unix, 1)
            .with_http_status(response.status),
    })
}

fn failed(
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

fn build_entities(profile: &Profile, scan_id: &str) -> Vec<Entity> {
    let mut entities = Vec::new();
    let bare = bare_handle(&profile.handle);
    let mut base = Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        format!("Bluesky public profile {}", profile.handle),
    )
    .with_attr("dataset", "Bluesky public AppView")
    .with_attr("bsky_handle", &profile.handle);

    if let Some(did) = profile.did.as_deref().filter(|v| !v.trim().is_empty()) {
        base = base.with_attr("did", did.trim());
    }
    if let Some(created) = profile
        .created_at
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        base = base.with_attr("created_at", created);
    }
    if let Some(description) = profile
        .description
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        base = base.with_attr("bio", description);
    }

    add(
        &mut entities,
        EntityKind::Username,
        bare,
        0.85,
        scan_id,
        base.clone(),
        "confirmed-profile",
    );

    let profile_url = format!("https://bsky.app/profile/{}", profile.handle);
    add(
        &mut entities,
        EntityKind::Url,
        &profile_url,
        0.80,
        scan_id,
        base.clone(),
        "profile-url",
    );

    let domain = profile.handle.trim_end_matches('.');
    if platform_handle_suffix(domain).is_none() && domain.contains('.') {
        add(
            &mut entities,
            EntityKind::Domain,
            domain,
            handle_domain_confidence(true, domain),
            scan_id,
            base.clone(),
            "custom-handle",
        );
    }

    if let Some(name) = profile
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|v| v.split_whitespace().count() >= 2)
    {
        add(
            &mut entities,
            EntityKind::Person,
            name,
            0.65,
            scan_id,
            base,
            "public-profile",
        );
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
    tag: &str,
) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    let mut entity = Entity::new(kind, value, confidence, scan_id);
    entity.tag("bluesky");
    entity.tag(tag);
    entity.add_evidence(evidence);
    entities.push(entity);
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
                    headers: Vec::new(),
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
        let report = lookup(&Fake::response(400, "{}"), "nobody", "scan", 1).unwrap();
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn profile_emits_handle_name_url_and_custom_domain() {
        let body = r#"{
          "handle":"jane.example",
          "displayName":"Jane Doe",
          "description":"Researcher",
          "did":"did:plc:oky5czdrnfjpqslsw2a5iclo",
          "createdAt":"2024-01-01T00:00:00Z"
        }"#;
        let report = lookup(&Fake::response(200, body), "jane.example", "scan", 1).unwrap();
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        for kind in [
            EntityKind::Username,
            EntityKind::Person,
            EntityKind::Domain,
            EntityKind::Url,
        ] {
            assert!(report.entities.iter().any(|entity| entity.kind == kind));
        }
    }

    #[test]
    fn platform_handle_does_not_claim_platform_domain() {
        let body = r#"{"handle":"janedoe.bsky.social","displayName":"Jane Doe"}"#;
        let report = lookup(&Fake::response(200, body), "janedoe", "scan", 1).unwrap();
        assert!(
            !report
                .entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Domain)
        );
    }
}
