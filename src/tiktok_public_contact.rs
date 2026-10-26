//! `TikTok` public-profile contact observations, not account-email recovery.
//!
//! Only a matching public profile's self-authored signature and bio link are read.
//! Internal account metadata, guessed addresses and unrelated page text are excluded.
//! Challenge pages, layout drift and unavailable profiles never imply account absence.

use serde_json::Value;

use crate::canonical::canonical_url;
use crate::classifier;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, fetch, whole_response};
use crate::http::{Request, Transport};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const SRC: &str = "tiktok_public_contact";
const MAX_HTML_BYTES: usize = 2 * 1024 * 1024;
const PROFILE_CONFIDENCE: f64 = 0.75;
const CONTACT_CONFIDENCE: f64 = 0.60;

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

/// `TikTok` account handles are not arbitrary OSINT usernames. Do not request
/// paths, URLs, emails, very long strings or handle variants from this source.
#[must_use]
pub fn valid_username(name: &str) -> bool {
    (2..=24).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
        && name
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && name
            .as_bytes()
            .last()
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
        && !name.contains("..")
}

/// Query only the operator-specified public `TikTok` profile.
/// # Errors
/// Refusal by the shared guarded transport is returned as a network error.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    username: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    lookup_with_options(
        transport,
        username,
        scan_id,
        now_unix,
        &FetchOptions::no_redirects().paced(),
    )
}

fn lookup_with_options<T: Transport + ?Sized>(
    transport: &T,
    username: &str,
    scan_id: &str,
    now_unix: u64,
    options: &FetchOptions,
) -> Result<Report, Error> {
    let name = username.trim().trim_start_matches('@');
    if !valid_username(name) {
        return Ok(empty(SourceExecutionOutcome::inconclusive(
            SRC,
            now_unix,
            "selector cannot name a TikTok handle",
        )));
    }
    let url = format!("https://www.tiktok.com/@{name}");
    let fetched = fetch(
        transport,
        Request::get(&url)
            .header("accept", "text/html")
            .header("user-agent", crate::http::DEFAULT_USER_AGENT),
        None,
        options,
        SRC,
        now_unix,
    )?;
    Ok(interpret(&fetched, name, scan_id, now_unix).unwrap_or_else(empty))
}

fn empty(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

/// Interpret only embedded JSON from `TikTok`'s recognized public profile
/// bootstrap scripts. Scripted data is still self-asserted, not verification
/// of the mailbox or ownership of any contact address.
fn interpret(
    fetched: &Fetched,
    name: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, SourceExecutionOutcome> {
    let response = whole_response(fetched, "TikTok")?;
    answer(fetched, "TikTok")?;
    if response.body.len() > MAX_HTML_BYTES {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::ParserDrift,
            Some(response.status),
            "TikTok profile HTML exceeded the bounded parser budget",
        ));
    }
    let html = std::str::from_utf8(&response.body).map_err(|_| {
        SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::ParserDrift,
            Some(response.status),
            "TikTok returned non-UTF-8 profile HTML",
        )
    })?;
    let user = profile_from_public_bootstrap(html, name).ok_or_else(|| {
        SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::ParserDrift,
            Some(response.status),
            "no matching public TikTok profile in recognized bootstrap data",
        )
    })?;
    let entities = public_profile_entities(&user, name, scan_id);
    Ok(Report {
        outcome: SourceExecutionOutcome::success(SRC, now_unix, entities.len())
            .with_http_status(response.status),
        entities,
    })
}

/// Create self-declared public-profile candidates with explicit evidence fields.
fn public_profile_entities(user: &Value, name: &str, scan_id: &str) -> Vec<Entity> {
    let source_url = format!("https://www.tiktok.com/@{name}");
    let evidence = Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        format!("self-published TikTok profile for @{name}"),
    )
    .with_attr("source_url", source_url.as_str())
    .with_attr("relationship", "self_asserted_not_identity_verified")
    .with_attr("mailbox_ownership", "not_verified");

    let mut entities = Vec::new();
    push_entity(
        &mut entities,
        EntityKind::Username,
        &name.to_ascii_lowercase(),
        PROFILE_CONFIDENCE,
        scan_id,
        evidence.clone().with_attr("source_field", "public_profile"),
        &["tiktok", "public-profile"],
    );
    push_entity(
        &mut entities,
        EntityKind::Url,
        &source_url,
        PROFILE_CONFIDENCE,
        scan_id,
        evidence.clone().with_attr("source_field", "public_profile"),
        &["tiktok", "public-profile"],
    );

    // Do not scan arbitrary HTML or profile JSON for email-like strings: those
    // may be unrelated metadata or another person's data.
    if let Some(signature) = user
        .get("signature")
        .and_then(Value::as_str)
        .filter(|signature| signature.len() <= 4_096)
    {
        for item in classifier::extract(signature)
            .into_iter()
            .filter(|item| item.kind == EntityKind::Email)
            .take(3)
        {
            push_entity(
                &mut entities,
                EntityKind::Email,
                &item.value,
                item.confidence.min(CONTACT_CONFIDENCE),
                scan_id,
                evidence
                    .clone()
                    .with_attr("source_field", "public_bio_signature")
                    .inferred(),
                &[
                    "tiktok",
                    "public-contact",
                    "self-declared",
                    crate::tags::CANDIDATE,
                ],
            );
        }
    }
    if let Some(link) = user
        .pointer("/bioLink/link")
        .and_then(Value::as_str)
        .and_then(canonical_url)
        .filter(|link| link.starts_with("https://"))
    {
        push_entity(
            &mut entities,
            EntityKind::Url,
            &link,
            CONTACT_CONFIDENCE,
            scan_id,
            evidence
                .with_attr("source_field", "public_bio_link")
                .inferred(),
            &[
                "tiktok",
                "public-bio-link",
                "self-declared",
                crate::tags::CANDIDATE,
            ],
        );
    }
    merge_by_uid(&mut entities);
    entities
}

/// `TikTok` embeds profile bootstrap JSON under either of these two shapes.
/// A change to those fields is parser drift, not evidence the user is missing.
fn profile_from_public_bootstrap(html: &str, username: &str) -> Option<Value> {
    for id in ["__UNIVERSAL_DATA_FOR_REHYDRATION__", "SIGI_STATE"] {
        let Some(payload) = script_payload(html, id) else {
            continue;
        };
        let Ok(data) = serde_json::from_str::<Value>(payload) else {
            continue;
        };
        let user = if id == "SIGI_STATE" {
            data.pointer("/UserModule/users")
                .and_then(Value::as_object)
                .and_then(|users| {
                    users
                        .iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case(username))
                })
                .map(|(_, user)| user)
        } else {
            data.get("__DEFAULT_SCOPE__")
                .or_else(|| data.get("DEFAULT_SCOPE"))
                .and_then(|scope| {
                    scope
                        .pointer("/webapp.user-detail/userInfo/user")
                        .or_else(|| scope.pointer("/webapp.reflow.profile.initial/userInfo/user"))
                })
        };
        if let Some(user) = user.filter(|user| {
            user.get("uniqueId")
                .and_then(Value::as_str)
                .is_some_and(|found| found.eq_ignore_ascii_case(username))
        }) {
            return Some(user.clone());
        }
    }
    None
}

/// Extract an explicitly identified script body; ignore emails outside it.
fn script_payload<'a>(html: &'a str, id: &str) -> Option<&'a str> {
    let mut remaining = html;
    for _ in 0..128 {
        let start = remaining.find("<script")?;
        let script = &remaining[start..];
        let open_end = script.find('>')?;
        if open_end > 512 {
            remaining = &script[7..];
            continue;
        }
        let header = &script[..open_end];
        let double = format!(" id=\"{id}\"");
        let single = format!(" id='{id}'");
        if header.contains(&double) || header.contains(&single) {
            let body = &script[open_end + 1..];
            let close = body.find("</script>")?;
            return Some(&body[..close]);
        }
        remaining = &script[open_end + 1..];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Response, TransportFailure};

    fn html(payload: &str, id: &str) -> String {
        format!("<html><script id=\"{id}\" type=\"application/json\">{payload}</script></html>")
    }

    #[test]
    fn rehydration_reads_only_explicit_bio_contacts() {
        let page = html(
            r#"{"__DEFAULT_SCOPE__":{"webapp.user-detail":{"userInfo":{"user":{"uniqueId":"alice24","signature":"Business: hello@example.org","bioLink":{"link":"https://artist.example.org"},"email":"private@example.org"}}}}}"#,
            "__UNIVERSAL_DATA_FOR_REHYDRATION__",
        );
        let user = profile_from_public_bootstrap(&page, "alice24").unwrap();
        assert_eq!(user["signature"], "Business: hello@example.org");
        assert!(profile_from_public_bootstrap(&page, "someoneelse").is_none());
    }

    #[test]
    fn alternate_public_bootstrap_schema_requires_exact_profile_identity() {
        for scope_name in ["__DEFAULT_SCOPE__", "DEFAULT_SCOPE"] {
            for shape in ["webapp.user-detail", "webapp.reflow.profile.initial"] {
                let mut profile = serde_json::Map::new();
                profile.insert(
                    shape.to_owned(),
                    serde_json::json!({
                        "userInfo": {
                            "user": {
                                "uniqueId": "alice24",
                                "signature": "business@example.org",
                                "privateAccountEmail": "do-not-return@example.org"
                            }
                        }
                    }),
                );
                let mut root = serde_json::Map::new();
                root.insert(scope_name.to_owned(), Value::Object(profile));
                let payload = Value::Object(root);
                let page = html(
                    &payload.to_string(),
                    "__UNIVERSAL_DATA_FOR_REHYDRATION__",
                );
                let user = profile_from_public_bootstrap(&page, "alice24")
                    .expect("matching public profile data");
                assert_eq!(user["signature"], "business@example.org");
                assert!(profile_from_public_bootstrap(&page, "unrelated").is_none());
            }
        }
    }

    #[test]
    fn legacy_script_matches_exact_handle_not_other_users() {
        let page = html(
            r#"{"UserModule":{"users":{"alice24":{"uniqueId":"Alice24","signature":"hello@example.org"},"someone":{"uniqueId":"someone","signature":"other@example.org"}}}}"#,
            "SIGI_STATE",
        );
        assert!(profile_from_public_bootstrap(&page, "alice24").is_some());
        assert!(profile_from_public_bootstrap(&page, "alice").is_none());
    }

    struct Fake {
        page: String,
        status: u16,
    }

    impl Transport for Fake {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            assert_eq!(request.url, "https://www.tiktok.com/@alice24");
            Ok(Response {
                status: self.status,
                headers: vec![("content-type".into(), "text/html".into())],
                body: self.page.as_bytes().to_vec(),
                truncated: false,
            })
        }
    }

    #[test]
    fn public_bio_contact_is_a_candidate_and_hidden_fields_do_not_leak() {
        let fake = Fake {
            status: 200,
            page: html(
                r#"{"__DEFAULT_SCOPE__":{"webapp.user-detail":{"userInfo":{"user":{"uniqueId":"alice24","signature":"Business: hello@example.org","bioLink":{"link":"https://artist.example.org/"},"email":"hidden@example.org","privateAccountEmail":"hidden2@example.org"}}}}}"#,
                "__UNIVERSAL_DATA_FOR_REHYDRATION__",
            ),
        };
        let report =
            lookup_with_options(&fake, "alice24", "scan", 1, &FetchOptions::no_redirects())
                .unwrap();
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        let contacts: Vec<&Entity> = report
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Email)
            .collect();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].value, "hello@example.org");
        assert!(contacts[0].has_tag(crate::tags::CANDIDATE));
        assert!(contacts[0].evidence.iter().any(|e| e.is_inferred));
        assert!(contacts[0].evidence.iter().all(|e| {
            e.attributes.get("source_field").map(String::as_str) == Some("public_bio_signature")
                && e.attributes.get("mailbox_ownership").map(String::as_str) == Some("not_verified")
        }));
        assert!(report.entities.iter().all(|e| !e.value.contains("hidden@")));
        assert!(
            report
                .entities
                .iter()
                .all(|e| !e.value.contains("hidden2@"))
        );
    }

    #[test]
    fn absent_bootstrap_and_http_404_are_never_verified_absence() {
        for (page, status) in [
            ("<html>Ordinary page without public data</html>", 200),
            ("<html>missing</html>", 404),
        ] {
            let fake = Fake {
                page: page.into(),
                status,
            };
            let report =
                lookup_with_options(&fake, "alice24", "scan", 1, &FetchOptions::no_redirects())
                    .unwrap();
            assert!(report.entities.is_empty());
            assert!(!matches!(
                report.outcome.kind,
                SourceOutcomeKind::Success | SourceOutcomeKind::ValidZero
            ));
        }
    }

    #[test]
    fn oversized_profile_bio_is_never_scanned_for_emails() {
        let mut user = serde_json::json!({
            "uniqueId": "alice24",
            "signature": "x".repeat(4096) + "victim@example.org",
        });
        let entities = public_profile_entities(&user, "alice24", "scan");
        assert!(entities.iter().all(|e| e.kind != EntityKind::Email));
        user["signature"] = serde_json::json!("business: visible@example.org");
        let entities = public_profile_entities(&user, "alice24", "scan");
        assert!(
            entities
                .iter()
                .any(|e| e.kind == EntityKind::Email && e.value == "visible@example.org")
        );
    }

    #[test]
    fn rejects_unusable_usernames_before_network() {
        for name in [
            "../private",
            "x",
            "my-handle",
            "alice..24",
            "me@example.org",
        ] {
            assert!(!valid_username(name), "{name}");
        }
        assert!(valid_username("alice.24"));
    }
}
