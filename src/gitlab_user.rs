//! Keyless OSINT lookup of public GitLab.com user identities.
//!
//! GitLab documents `GET /api/v4/users?username=...` as an exact,
//! case-insensitive username filter. A result proves an account matching that
//! handle exists on GitLab.com; it does not prove that similarly named accounts
//! elsewhere belong to the same person. No credentials, scraping or private fields.

use serde::Deserialize;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Response, Transport, append_query_param};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const SRC: &str = "gitlab_user";
const API: &str = "https://gitlab.com/api/v4/users";
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_USERNAME: usize = 128;

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

#[derive(Debug, Deserialize)]
struct PublicUser {
    username: String,
    id: u64,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    state: Option<String>,
}

/// Conservative GitLab account selector grammar. Invalid selectors are not misses.
#[must_use]
pub fn valid_username(raw: &str) -> bool {
    let value = raw.trim().trim_start_matches('@');
    (2..=MAX_USERNAME).contains(&value.len())
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Query exactly one public GitLab.com account; use no secret and follow no redirects.
///
/// # Errors
/// Propagates guarded-network refusals so callers can record that no request was sent.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    username: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let name = username.trim().trim_start_matches('@').to_ascii_lowercase();
    if !valid_username(&name) {
        return Ok(miss(SourceExecutionOutcome::inconclusive(
            SRC,
            now_unix,
            "selector cannot name a GitLab username",
        )));
    }
    let url = append_query_param(API, "username", &name);
    let url = append_query_param(&url, "per_page", "1");
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
    Ok(interpret(&fetched, &name, scan_id, now_unix).unwrap_or_else(miss))
}

fn miss(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

fn interpret(
    fetched: &Fetched,
    selector: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, SourceExecutionOutcome> {
    let response = whole_response(fetched, "GitLab")?;
    answer(fetched, "GitLab")?;
    parse(response, selector, scan_id, now_unix)
}

fn parse(
    response: &Response,
    selector: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, SourceExecutionOutcome> {
    if response.body.len() > MAX_RESPONSE_BYTES {
        return Err(failed(
            SourceOutcomeKind::ParserDrift,
            response.status,
            now_unix,
            "GitLab account response exceeds local bound",
        ));
    }
    let users: Vec<PublicUser> = decode_json(response, SRC, now_unix, "GitLab")?;
    if users.is_empty() {
        return Ok(miss(
            SourceExecutionOutcome::valid_zero(SRC, now_unix).with_http_status(response.status),
        ));
    }
    if users.len() != 1 {
        return Err(failed(
            SourceOutcomeKind::SchemaDrift,
            response.status,
            now_unix,
            "GitLab exact username query returned multiple records",
        ));
    }
    let user = &users[0];
    if user.id == 0
        || !valid_username(&user.username)
        || !user.username.eq_ignore_ascii_case(selector)
    {
        return Err(failed(
            SourceOutcomeKind::SemanticDrift,
            response.status,
            now_unix,
            "GitLab exact-username record did not match the requested identity",
        ));
    }
    let profile = format!("https://gitlab.com/{}", user.username);
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        "Public GitLab.com account record; no cross-platform identity attribution",
    )
    .with_attr("dataset", "GitLab Users API")
    .with_attr("gitlab_id", user.id.to_string())
    .with_attr("profile_url", &profile);
    for (key, value) in [
        ("self_declared_name", user.name.as_deref()),
        ("account_state", user.state.as_deref()),
    ] {
        if let Some(value) = value.map(str::trim).filter(|s| !s.is_empty()) {
            evidence = evidence.with_attr(key, value);
        }
    }
    let mut entities = Vec::with_capacity(2);
    push_entity(
        &mut entities,
        EntityKind::Username,
        &user.username,
        0.85,
        scan_id,
        evidence.clone(),
        &[SRC, "public_profile"],
    );
    push_entity(
        &mut entities,
        EntityKind::Url,
        &profile,
        0.80,
        scan_id,
        evidence,
        &[SRC, "public_profile"],
    );
    merge_by_uid(&mut entities);
    Ok(Report {
        entities,
        outcome: SourceExecutionOutcome::success(SRC, now_unix, 1)
            .with_http_status(response.status),
    })
}

fn failed(kind: SourceOutcomeKind, status: u16, now: u64, detail: &str) -> SourceExecutionOutcome {
    SourceExecutionOutcome::failed(SRC, now, kind, Some(status), detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::TransportFailure;

    const NOW: u64 = 1_800_000_000;

    fn response(body: &str) -> Response {
        Response {
            status: 200,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
            truncated: false,
        }
    }

    #[test]
    fn exact_public_account_yields_two_provenance_backed_entities() {
        let res = parse(
            &response(r#"[{"username":"Ada_Test","id":42,"name":"A. Tester","state":"active"}]"#),
            "ada_test",
            "scan",
            NOW,
        )
        .expect("valid account");
        assert_eq!(res.outcome.kind, SourceOutcomeKind::Success);
        assert_eq!(res.entities.len(), 2);
        assert!(
            res.entities
                .iter()
                .any(|e| e.kind == EntityKind::Url && e.value == "https://gitlab.com/Ada_Test")
        );
        assert!(res.entities.iter().any(|e| {
            e.evidence
                .iter()
                .any(|ev| ev.attr_values("gitlab_id").any(|id| id == "42"))
        }));
        assert!(!res.entities.iter().any(|e| e.kind == EntityKind::Person));
    }

    #[test]
    fn a_real_empty_array_means_no_matching_account_in_this_query() {
        let res = parse(&response("[]"), "ada_test", "scan", NOW).expect("empty");
        assert_eq!(res.outcome.kind, SourceOutcomeKind::ValidZero);
        assert!(res.entities.is_empty());
    }

    #[test]
    fn refuses_mismatched_identity_or_schema_drift() {
        for json in [
            r#"[{"username":"other_person","id":42}]"#,
            r#"[{"username":"ada_test","id":0}]"#,
            r#"[{"username":"ada_test","id":4},{"username":"ada_test","id":5}]"#,
            r#"{"message":"blocked"}"#,
        ] {
            assert!(
                parse(&response(json), "ada_test", "scan", NOW).is_err(),
                "{json}"
            );
        }
    }

    #[test]
    fn only_safe_selectors_can_generate_requests() {
        for invalid in ["", ".", "admin@", "../secret", "a/b", "a", "x?"] {
            assert!(!valid_username(invalid));
        }
        assert!(valid_username("Ada-Test_1"));
    }

    struct Stub;
    impl Transport for Stub {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            assert!(request.url.starts_with(API));
            assert!(request.url.contains("username=ada_test"));
            assert!(request.url.contains("per_page=1"));
            assert!(request.header_value("authorization").is_none());
            Ok(response(r#"[{"username":"ada_test","id":55}]"#))
        }
    }

    #[test]
    fn one_guarded_keyless_request_is_a_functional_lookup() {
        let res = lookup(&Stub, "Ada_Test", "scan", NOW).expect("guarded transport");
        assert_eq!(res.outcome.kind, SourceOutcomeKind::Success);
    }
}
