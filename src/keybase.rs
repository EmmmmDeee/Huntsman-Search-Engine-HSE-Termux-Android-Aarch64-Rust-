//! Keyless Keybase public-identity lookup.
//!
//! One lookup is one GET to Keybase's public `user/lookup` endpoint for a single username. Keybase
//! links a username to the external accounts, websites and PGP key its owner has cryptographically
//! proven they control, so this source maps a handle to those linked identities as entities and
//! pivots. The verified proofs are the point of the source: each one is a self-signed statement the
//! account owner published, which is why the linked usernames and domains carry a strong confidence.
//! The whole provider answer is not retained; each entity keeps the proof fields it was built from.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::canonical::canonical_domain;
use crate::classifier;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Response, Transport, append_query_param};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, classify_fetch};

pub const SRC: &str = "keybase";
const API: &str = "https://keybase.io/_/api/1.0/user/lookup.json";
const FIELDS: &str = "basics,profile,proofs_summary,public_keys";

/// Keybase usernames are 2-16 ASCII letters, digits or underscores. A selector outside this shape
/// can never name a Keybase account, so the lookup is inconclusive without a request.
const MIN_LEN: usize = 2;
const MAX_LEN: usize = 16;

const USERNAME_CONF: f64 = 0.85;
const PROOF_USERNAME_CONF: f64 = 0.80;
const PROOF_DOMAIN_CONF: f64 = 0.80;
const URL_CONF: f64 = 0.75;
const PERSON_CONF: f64 = 0.60;
const FINGERPRINT_CONF: f64 = 0.85;
const BIO_CONF_CAP: f64 = 0.70;

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

#[derive(Debug, Deserialize)]
struct Lookup {
    #[serde(default)]
    status: Status,
    #[serde(default)]
    them: Vec<Option<Them>>,
}

#[derive(Debug, Default, Deserialize)]
struct Status {
    #[serde(default)]
    code: i64,
}

#[derive(Debug, Deserialize)]
struct Them {
    #[serde(default)]
    basics: Option<Basics>,
    #[serde(default)]
    profile: Option<KbProfile>,
    #[serde(default)]
    proofs_summary: Option<ProofsSummary>,
    #[serde(default)]
    public_keys: Option<PublicKeys>,
}

#[derive(Debug, Deserialize)]
struct Basics {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    username_cased: Option<String>,
}

#[derive(Debug, Deserialize)]
struct KbProfile {
    #[serde(default)]
    full_name: Option<String>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    bio: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProofsSummary {
    #[serde(default)]
    by_presentation_group: BTreeMap<String, Vec<Proof>>,
}

#[derive(Debug, Deserialize)]
struct Proof {
    #[serde(default, rename = "proof_type")]
    kind: Option<String>,
    #[serde(default)]
    nametag: Option<String>,
    #[serde(default)]
    service_url: Option<String>,
    #[serde(default)]
    human_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PublicKeys {
    #[serde(default)]
    primary: Option<PrimaryKey>,
}

#[derive(Debug, Deserialize)]
struct PrimaryKey {
    #[serde(default)]
    key_fingerprint: Option<String>,
}

/// Query one public Keybase identity.
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
    if !is_keybase_username(&selector) {
        return Ok(miss(SourceExecutionOutcome::inconclusive(
            SRC,
            now_unix,
            "selector cannot name a Keybase username",
        )));
    }

    let url = append_query_param(API, "usernames", &selector);
    let url = append_query_param(&url, "fields", FIELDS);
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
        return Ok(miss(fetched.outcome));
    };
    Ok(interpret(&response, scan_id, now_unix))
}

/// A report that found nothing, carrying only its outcome. **Pure.**
fn miss(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

/// Turn one fetched Keybase response into a report. **Pure.**
fn interpret(response: &Response, scan_id: &str, now_unix: u64) -> Report {
    if matches!(response.status, 400 | 404) {
        return miss(
            SourceExecutionOutcome::valid_zero(SRC, now_unix).with_http_status(response.status),
        );
    }
    if response.truncated {
        return miss(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::ParserDrift,
            Some(response.status),
            "truncated Keybase response",
        ));
    }

    let body = response.text();
    let classified = classify_fetch(response.status, &body);
    if classified != SourceOutcomeKind::Inconclusive {
        return miss(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            classified,
            Some(response.status),
            "Keybase response was not a lookup document",
        ));
    }

    let lookup: Lookup = match serde_json::from_slice(&response.body) {
        Ok(lookup) => lookup,
        Err(error) => {
            return miss(SourceExecutionOutcome::failed(
                SRC,
                now_unix,
                SourceOutcomeKind::ParserDrift,
                Some(response.status),
                format!("Keybase JSON: {error}"),
            ));
        }
    };

    // A non-zero status (for example INPUT_ERROR on a selector Keybase rejects) and an absent or
    // null `them[0]` are both clean negatives: the username names no Keybase account.
    let Some(Some(them)) = lookup
        .them
        .into_iter()
        .next()
        .filter(|_| lookup.status.code == 0)
    else {
        return miss(
            SourceExecutionOutcome::valid_zero(SRC, now_unix).with_http_status(response.status),
        );
    };

    let mut entities = build_entities(&them, scan_id);
    if entities.is_empty() {
        return miss(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            "Keybase account carried no basics",
        ));
    }
    merge_by_uid(&mut entities);
    Report {
        entities,
        outcome: SourceExecutionOutcome::success(SRC, now_unix, 1)
            .with_http_status(response.status),
    }
}

/// Whether `selector` has the shape of a Keybase username. **Pure.**
#[must_use]
fn is_keybase_username(selector: &str) -> bool {
    (MIN_LEN..=MAX_LEN).contains(&selector.len())
        && selector
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn build_entities(them: &Them, scan_id: &str) -> Vec<Entity> {
    let Some(username) = them
        .basics
        .as_ref()
        .and_then(|basics| {
            basics
                .username_cased
                .as_deref()
                .or(basics.username.as_deref())
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Vec::new();
    };

    let base = profile_evidence(them, username, scan_id);
    let mut entities = Vec::new();

    push_entity(
        &mut entities,
        EntityKind::Username,
        &username.to_ascii_lowercase(),
        USERNAME_CONF,
        scan_id,
        base.clone(),
        &["keybase", "public-profile"],
    );

    push_entity(
        &mut entities,
        EntityKind::Url,
        &format!("https://keybase.io/{}", username.to_ascii_lowercase()),
        URL_CONF,
        scan_id,
        base.clone(),
        &["keybase", "public-profile"],
    );

    if let Some(full_name) = them
        .profile
        .as_ref()
        .and_then(|profile| profile.full_name.as_deref())
        .map(str::trim)
        .filter(|name| name.split_whitespace().count() >= 2)
    {
        push_entity(
            &mut entities,
            EntityKind::Person,
            full_name,
            PERSON_CONF,
            scan_id,
            base.clone(),
            &["keybase", "public-profile"],
        );
    }

    if let Some(fingerprint) = them
        .public_keys
        .as_ref()
        .and_then(|keys| keys.primary.as_ref())
        .and_then(|primary| primary.key_fingerprint.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        push_entity(
            &mut entities,
            EntityKind::Other,
            &fingerprint.to_ascii_lowercase(),
            FINGERPRINT_CONF,
            scan_id,
            base.clone().with_attr("key_kind", "pgp_fingerprint"),
            &["keybase", "pgp-fingerprint"],
        );
    }

    if let Some(proofs) = them.proofs_summary.as_ref() {
        for (group, items) in &proofs.by_presentation_group {
            for proof in items {
                push_proof(&mut entities, group, proof, scan_id, &base);
            }
        }
    }

    if let Some(bio) = them
        .profile
        .as_ref()
        .and_then(|profile| profile.bio.as_deref())
    {
        for classified in classifier::extract(bio)
            .into_iter()
            .filter(|item| matches!(item.kind, EntityKind::Email | EntityKind::Url))
        {
            push_entity(
                &mut entities,
                classified.kind,
                &classified.value,
                classified.confidence.min(BIO_CONF_CAP),
                scan_id,
                base.clone().with_attr("source_field", "bio"),
                &["keybase", "public-profile"],
            );
        }
    }

    entities
}

fn push_proof(
    entities: &mut Vec<Entity>,
    group: &str,
    proof: &Proof,
    scan_id: &str,
    base: &Evidence,
) {
    let proof_type = proof
        .kind
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let nametag = proof
        .nametag
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let service_url = proof
        .service_url
        .as_deref()
        .map(str::trim)
        .filter(|value| value.starts_with("http://") || value.starts_with("https://"));

    let mut evidence = base.clone().with_attr("presentation_group", group);
    if let Some(value) = proof_type {
        evidence = evidence.with_attr("proof_type", value);
    }
    if let Some(value) = proof
        .human_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        evidence = evidence.with_attr("human_url", value);
    }

    // A DNS or website proof names a domain the owner controls; every other proof names the
    // owner's handle on an external service.
    let web_proof =
        matches!(proof_type, Some("dns" | "generic_web_site")) || group.starts_with("web:");
    if let Some(tag) = nametag {
        if web_proof {
            if let Some(domain) = canonical_domain(tag) {
                push_entity(
                    entities,
                    EntityKind::Domain,
                    &domain,
                    PROOF_DOMAIN_CONF,
                    scan_id,
                    evidence.clone(),
                    &["keybase", "keybase-proof", "verified-control"],
                );
            }
        } else {
            push_entity(
                entities,
                EntityKind::Username,
                tag,
                PROOF_USERNAME_CONF,
                scan_id,
                evidence.clone(),
                &["keybase", "keybase-proof"],
            );
        }
    }

    if let Some(url) = service_url {
        push_entity(
            entities,
            EntityKind::Url,
            url,
            URL_CONF,
            scan_id,
            evidence.clone(),
            &["keybase", "keybase-proof"],
        );
    }
}

fn profile_evidence(them: &Them, username: &str, scan_id: &str) -> Evidence {
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        format!("Keybase public identity {username}"),
    )
    .with_attr("dataset", "Keybase public identities")
    .with_attr("keybase_username", username);

    if let Some(location) = them
        .profile
        .as_ref()
        .and_then(|profile| profile.location.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        evidence = evidence.with_attr("location", location);
    }
    evidence
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::OneResponse;

    const MAX: &str = r#"{
      "status":{"code":0,"name":"OK"},
      "them":[{
        "basics":{"username":"max","username_cased":"max"},
        "profile":{"full_name":"Max Krohn","location":"New York, NY","bio":"reach me at max@example.org"},
        "proofs_summary":{"by_presentation_group":{
          "twitter":[{"proof_type":"twitter","nametag":"maxtaco","service_url":"https://twitter.com/maxtaco","human_url":"https://twitter.com/maxtaco/status/1"}],
          "github":[{"proof_type":"github","nametag":"maxtaco","service_url":"https://github.com/maxtaco","human_url":"https://gist.github.com/1"}],
          "web:maxk.org":[{"proof_type":"dns","nametag":"maxk.org","service_url":"http://maxk.org","human_url":"dns://maxk.org"}]
        }},
        "public_keys":{"primary":{"key_fingerprint":"4475293306243408FA5958DC63847B4B83930F0C"}}
      }]
    }"#;

    #[test]
    fn invalid_selector_is_inconclusive_without_network() {
        struct Never;
        impl Transport for Never {
            fn send(
                &self,
                _request: &crate::http::Request,
            ) -> Result<crate::http::Response, crate::http::TransportFailure> {
                panic!("network must not be used")
            }
        }
        // A dotted handle and an over-long handle can never name a Keybase username.
        assert_eq!(
            lookup(&Never, "jane.doe", "scan", 1).unwrap().outcome.kind,
            SourceOutcomeKind::Inconclusive
        );
        assert_eq!(
            lookup(&Never, "a", "scan", 1).unwrap().outcome.kind,
            SourceOutcomeKind::Inconclusive
        );
    }

    #[test]
    fn null_user_is_valid_zero() {
        let got = lookup(
            &OneResponse::json(200, r#"{"status":{"code":0,"name":"OK"},"them":[null]}"#),
            "nobodyhere",
            "scan",
            1,
        )
        .unwrap();
        assert_eq!(got.outcome.kind, SourceOutcomeKind::ValidZero);
        assert!(got.entities.is_empty());
    }

    #[test]
    fn input_error_status_is_valid_zero() {
        let got = lookup(
            &OneResponse::json(
                200,
                r#"{"status":{"code":100,"name":"INPUT_ERROR"},"them":[]}"#,
            ),
            "nobody",
            "scan",
            1,
        )
        .unwrap();
        assert_eq!(got.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn proven_identity_emits_linked_accounts_domain_person_and_fingerprint() {
        let got = lookup(&OneResponse::json(200, MAX), "max", "scan", 1).unwrap();
        assert_eq!(got.outcome.kind, SourceOutcomeKind::Success);

        // The queried Keybase account, its profile URL and the owner's full name.
        assert!(
            got.entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Username
                    && entity.value == "max"
                    && entity.has_tag("keybase"))
        );
        assert!(got.entities.iter().any(
            |entity| entity.kind == EntityKind::Url && entity.value == "https://keybase.io/max"
        ));
        // The normalised value lower-cases, but the owner's exact name survives in `raw_value`.
        assert!(
            got.entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Person
                    && entity.value == "max krohn"
                    && entity.raw_value == "Max Krohn")
        );

        // The cryptographically proven linked accounts, as usernames and profile URLs.
        assert!(
            got.entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Username && entity.value == "maxtaco")
        );
        assert!(
            got.entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Url
                    && entity.value == "https://twitter.com/maxtaco")
        );

        // A DNS proof becomes a controlled domain, not a username.
        assert!(
            got.entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Domain && entity.value == "maxk.org")
        );
        assert!(
            !got.entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Username && entity.value == "maxk.org")
        );

        // The PGP fingerprint is kept as a lower-cased pivot.
        assert!(
            got.entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Other
                    && entity.value == "4475293306243408fa5958dc63847b4b83930f0c")
        );

        // The bio's e-mail is surfaced as a capped-confidence contact.
        assert!(
            got.entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Email
                    && entity.value == "max@example.org"
                    && entity.confidence <= BIO_CONF_CAP)
        );
    }

    #[test]
    fn parser_drift_when_body_is_not_a_lookup_document() {
        let got = lookup(&OneResponse::json(200, "not json"), "max", "scan", 1).unwrap();
        assert_eq!(got.outcome.kind, SourceOutcomeKind::ParserDrift);
    }
}
