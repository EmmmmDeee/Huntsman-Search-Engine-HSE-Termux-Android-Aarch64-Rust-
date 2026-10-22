//! `OpenPGP` key lookup by email on keys.openpgp.org.
//!
//! keys.openpgp.org publishes a user ID only after the address owner confirmed it by
//! mail, so a key found for an address ties that address to every other address and
//! name on the same key. One explicit email lookup becomes one guarded HKP
//! machine-readable index request. A plain 404 is a validated absence; a 200 that is not an
//! index document is drift, never "not found".
//!
//! Proton Mail's key server is deliberately not used: it answers every `@proton.me`
//! address with a key, registered or not (checked 2026-10-14), so its answer says
//! nothing about the address.

use crate::canonical::canonical_email;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, fetch, whole_response};
use crate::http::{Request, Transport, append_query_param};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::value_syntax::percent_decode_strict;

pub const SRC: &str = "openpgp_keys";

const API: &str = "https://keys.openpgp.org/pks/lookup?op=index&options=mr";

/// Every published user ID was confirmed by its address owner.
const CONF_EMAIL: f64 = 0.80;
/// The name beside an address is whatever the key holder typed.
const CONF_PERSON: f64 = 0.65;

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Key {
    fingerprint: String,
    created: Option<u64>,
    uids: Vec<String>,
}

/// Look up the published `OpenPGP` keys for one email address.
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
    let fetched = fetch(
        transport,
        Request::get(append_query_param(API, "search", &email))
            .header("accept", "text/plain")
            .header("user-agent", crate::http::DEFAULT_USER_AGENT),
        None,
        &FetchOptions::no_redirects().paced(),
        SRC,
        now_unix,
    )?;
    Ok(interpret(&fetched, &email, scan_id, now_unix).unwrap_or_else(empty))
}

/// Turn one fetched key index for `email` into a report; `Err` is the outcome of a response that
/// named no key. A plain 404 is the key server's "no key" answer, read from the status before the
/// gate; a challenge page at that status is a wall. **Pure.**
fn interpret(
    fetched: &Fetched,
    email: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, SourceExecutionOutcome> {
    // A 404 is a clean negative only when fetch read it as a plain upstream 4xx; a challenge page
    // at that status is `BotWaf`.
    if let Some(response) = fetched
        .response
        .as_ref()
        .filter(|r| r.status == 404 && fetched.outcome.kind == SourceOutcomeKind::Upstream4xx)
    {
        return Err(
            SourceExecutionOutcome::valid_zero(SRC, now_unix).with_http_status(response.status)
        );
    }
    let response = whole_response(fetched, "key index")?;
    answer(fetched, "key server")?;
    let Some(keys) = parse_index(&response.text()) else {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            "key server answer was not an HKP machine-readable index",
        ));
    };
    if keys.is_empty() {
        return Err(
            SourceExecutionOutcome::valid_zero(SRC, now_unix).with_http_status(response.status)
        );
    }

    let mut entities = Vec::new();
    for key in &keys {
        build_entities(key, email, scan_id, &mut entities);
    }
    merge_by_uid(&mut entities);
    Ok(Report {
        entities,
        outcome: SourceExecutionOutcome::success(SRC, now_unix, keys.len())
            .with_http_status(response.status),
    })
}

fn empty(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

/// Parse an HKP machine-readable index (draft-shaw-openpgp-hkp section 5.2). `None` when
/// the document does not start with an `info` line or a `uid` precedes every `pub`.
fn parse_index(body: &str) -> Option<Vec<Key>> {
    let mut lines = body.lines().map(str::trim).filter(|line| !line.is_empty());
    if !lines.next()?.starts_with("info:") {
        return None;
    }
    let mut keys: Vec<Key> = Vec::new();
    for line in lines {
        let fields: Vec<&str> = line.split(':').collect();
        match fields[0] {
            "pub" => {
                let fingerprint = fields.get(1).copied().unwrap_or("").to_ascii_uppercase();
                if fingerprint.is_empty() || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return None;
                }
                keys.push(Key {
                    fingerprint,
                    created: fields.get(4).and_then(|v| v.parse().ok()),
                    uids: Vec::new(),
                });
            }
            "uid" => {
                let uid = percent_decode_strict(fields.get(1).copied().unwrap_or(""))?;
                keys.last_mut()?.uids.push(uid);
            }
            // Unknown record types are ignored, as the format requires.
            _ => {}
        }
    }
    Some(keys)
}

/// Split a user ID of the form `Name (comment) <addr>` into its name and address.
fn split_uid(uid: &str) -> (Option<String>, Option<String>) {
    let (name_part, address) = match (uid.rfind('<'), uid.rfind('>')) {
        (Some(open), Some(close)) if open < close => {
            (&uid[..open], canonical_email(&uid[open + 1..close]))
        }
        _ => ("", canonical_email(uid)),
    };
    let name = name_part
        .split('(')
        .next()
        .unwrap_or("")
        .trim()
        .trim_matches('"')
        .trim();
    let name = (name.split_whitespace().count() >= 2 && canonical_email(name).is_none())
        .then(|| name.to_owned());
    (name, address)
}

fn build_entities(key: &Key, queried: &str, scan_id: &str, entities: &mut Vec<Entity>) {
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        "OpenPGP key published on keys.openpgp.org for the address",
    )
    .with_attr("dataset", "keys.openpgp.org verified user IDs")
    .with_attr("fingerprint", &key.fingerprint)
    .with_attr(
        "key_url",
        format!(
            "https://keys.openpgp.org/vks/v1/by-fingerprint/{}",
            key.fingerprint
        ),
    );
    if let Some(created) = key.created {
        evidence = evidence.with_attr("key_created_unix", created.to_string());
    }
    let uids = key
        .uids
        .iter()
        .map(|uid| split_uid(uid))
        .collect::<Vec<_>>();
    // One key has one holder, and every address on it was confirmed by mail, so each name on
    // the key owns each of its addresses, the one looked up included. `owner` is the attribute
    // the relation builders read for that.
    let names = uids
        .iter()
        .filter_map(|(name, _)| name.as_deref())
        .collect::<Vec<_>>();
    let owned = names.iter().fold(evidence.clone(), |owned, name| {
        owned.with_attr("owner", *name)
    });
    for (name, address) in &uids {
        if let Some(address) = address
            .as_deref()
            .filter(|address| *address != queried || !names.is_empty())
        {
            add_entity(
                entities,
                EntityKind::Email,
                address,
                CONF_EMAIL,
                scan_id,
                &owned,
            );
        }
        if let Some(name) = name {
            add_entity(
                entities,
                EntityKind::Person,
                name,
                CONF_PERSON,
                scan_id,
                &evidence,
            );
        }
    }
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
    entity.tag("public-key");
    entity.add_evidence(evidence.clone());
    entities.push(entity);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relation::{self, RelationKind};
    use crate::test_support::{OneResponse, ScriptedTransport, json_ok};

    // Recorded from the live endpoint on 2026-10-14 for a key whose holder publishes it.
    const RECORDED: &str = "info:1:1\n\
pub:8F17777118A33DDA9BA48E62AACB3243630052D9:1:3744:1428396777::\n\
uid:Neal%20H.%20Walfield%20%3Cneal@gnupg.org%3E:1780676708::\n\
uid:Neal%20H.%20Walfield%20%3Cneal@pep-project.org%3E:1780676708::\n\
uid:Neal%20H.%20Walfield%20%3Cneal@sequoia-pgp.org%3E:1780676708::\n\
uid:Neal%20H.%20Walfield%20%3Cneal@walfield.org%3E:1780676673::\n";

    fn text(status: u16, body: &str) -> OneResponse {
        OneResponse::with_headers(status, &[("content-type", "text/plain")], body)
    }

    #[test]
    fn request_searches_the_canonical_address() {
        let transport = ScriptedTransport::new(vec![Ok(json_ok("info:1:0\n"))]);
        lookup(&transport, "Neal@Walfield.org", "scan", 1).unwrap();
        let seen = transport.seen.borrow();
        assert_eq!(
            seen[0].url,
            "https://keys.openpgp.org/pks/lookup?op=index&options=mr&search=neal%40walfield.org"
        );
    }

    #[test]
    fn missing_key_is_valid_zero() {
        let report = lookup(&text(404, "No key found"), "a@example.com", "s", 1).unwrap();
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
        assert!(report.entities.is_empty());
    }

    /// `interpret` over `status` and `body`, fetched unpaced, so a refusal here never opens the
    /// shared keys.openpgp.org circuit the paced lookups in these tests go through.
    fn interpreted(status: u16, body: &str) -> Report {
        let fetched = fetch(
            &text(status, body),
            Request::get(API),
            None,
            &FetchOptions::no_redirects(),
            SRC,
            1,
        )
        .unwrap();
        interpret(&fetched, "a@example.com", "s", 1).unwrap_or_else(empty)
    }

    #[test]
    fn only_a_plain_404_is_a_missing_key() {
        let plain = interpreted(404, "No key found");
        assert_eq!(plain.outcome.kind, SourceOutcomeKind::ValidZero);
        let walled = interpreted(
            404,
            "<html><title>Just a moment...</title>Cloudflare</html>",
        );
        assert_eq!(walled.outcome.kind, SourceOutcomeKind::BotWaf);
        assert_eq!(walled.outcome.http_status, Some(404));
        assert!(walled.entities.is_empty());
    }

    #[test]
    fn recorded_key_links_the_other_verified_addresses_and_the_name() {
        let report = lookup(&text(200, RECORDED), "neal@walfield.org", "s", 1).unwrap();
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert_eq!(report.outcome.found, Some(1));
        let emails: Vec<&str> = report
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Email)
            .map(|e| e.value.as_str())
            .collect();
        assert_eq!(emails.len(), 4, "{emails:?}");
        assert!(emails.contains(&"neal@gnupg.org"));
        let queried = report
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Email && e.value == "neal@walfield.org")
            .expect("the address looked up carries who owns it");
        assert_eq!(
            queried.evidence[0]
                .attributes
                .get("owner")
                .map(String::as_str),
            Some("Neal H. Walfield")
        );
        let person = report
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Person)
            .expect("person");
        assert_eq!(person.raw_value, "Neal H. Walfield");
        let attrs = &person.evidence[0].attributes;
        assert_eq!(
            attrs.get("fingerprint").map(String::as_str),
            Some("8F17777118A33DDA9BA48E62AACB3243630052D9")
        );
        assert_eq!(
            attrs.get("key_created_unix").map(String::as_str),
            Some("1428396777")
        );
    }

    /// The ownership relations the analysis derives from one key index, as `(person, address)`.
    fn owned_addresses(body: &str, queried: &str) -> Vec<(String, String)> {
        let report = lookup(&text(200, body), queried, "s", 1).unwrap();
        let value = |uid: &str| {
            report
                .entities
                .iter()
                .find(|entity| entity.uid == uid)
                .map(|entity| entity.raw_value.clone())
                .expect("relation endpoint is an entity of the report")
        };
        let mut owned: Vec<_> = relation::derive_all(&report.entities, "s")
            .into_iter()
            .filter(|edge| edge.kind == RelationKind::IdentifiedBy)
            .map(|edge| (value(&edge.from_uid), value(&edge.to_uid)))
            .collect();
        owned.sort();
        owned
    }

    #[test]
    fn each_name_on_a_key_owns_every_address_on_it_the_looked_up_one_included() {
        let person = "Neal H. Walfield".to_owned();
        assert_eq!(
            owned_addresses(RECORDED, "neal@walfield.org"),
            [
                (person.clone(), "neal@gnupg.org".to_owned()),
                (person.clone(), "neal@pep-project.org".to_owned()),
                (person.clone(), "neal@sequoia-pgp.org".to_owned()),
                (person, "neal@walfield.org".to_owned()),
            ]
        );
    }

    #[test]
    fn a_key_that_names_no_one_links_its_addresses_to_no_one() {
        let body = "info:1:1\n\
pub:8F17777118A33DDA9BA48E62AACB3243630052D9:1:3744:1428396777::\n\
uid:jane%40example.org::\n\
uid:Jane%20%3Cjane.doe@example.net%3E::\n";
        let report = lookup(&text(200, body), "jane@example.org", "s", 1).unwrap();
        let emails: Vec<&str> = report
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Email)
            .map(|e| e.value.as_str())
            .collect();
        assert_eq!(
            emails,
            ["jane.doe@example.net"],
            "the address looked up is not new"
        );
        assert!(!report.entities.iter().any(|e| e.kind == EntityKind::Person));
        assert!(owned_addresses(body, "jane@example.org").is_empty());
    }

    #[test]
    fn user_ids_split_into_name_and_address() {
        assert_eq!(
            split_uid("Jane Q. Doe (work) <Jane@Example.org>"),
            (Some("Jane Q. Doe".into()), Some("jane@example.org".into()))
        );
        assert_eq!(
            split_uid("jane@example.org"),
            (None, Some("jane@example.org".into()))
        );
        assert_eq!(
            split_uid("Jane <jane@example.org>"),
            (None, Some("jane@example.org".into()))
        );
    }

    #[test]
    fn drift_is_never_a_clean_miss() {
        for body in [
            "<html>oops</html>",
            "uid:x::\n",
            "info:1:1\nuid:a%20b::\n",
            "info:1:1\npub:zz:1::1::\n",
        ] {
            let report = lookup(&text(200, body), "a@example.com", "s", 1).unwrap();
            assert_eq!(
                report.outcome.kind,
                SourceOutcomeKind::SchemaDrift,
                "{body}"
            );
            assert!(report.entities.is_empty());
        }
    }

    /// The index is not JSON, so there is no decoder message to leak, but the diagnostic of an
    /// answer that is not an index names none of it either.
    #[test]
    fn an_answer_that_is_not_an_index_is_drift_that_quotes_none_of_it() {
        let report = lookup(
            &text(200, "uid:secret@example.com::\n"),
            "a@example.com",
            "s",
            1,
        )
        .unwrap();
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SchemaDrift);
        let detail = report.outcome.detail.unwrap_or_default();
        assert!(!detail.contains("secret@example.com"), "{detail}");
    }
}
