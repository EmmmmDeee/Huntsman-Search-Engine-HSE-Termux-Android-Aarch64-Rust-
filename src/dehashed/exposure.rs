//! The `exposure` leg over [`DehashedClient`].
//!
//! `exposure ADDR` runs every keyed breach leg for one address. This module is
//! the `DeHashed` leg: one exact-match email search through the shared
//! [`DehashedClient`] (so there is one `DeHashed` HTTP authority, bound to the
//! fixed API origin), folded into the per-database exposure summary the report
//! prints. It mirrors the `OathNet` leg's contract: the queried address keeps
//! exposure metadata, and the usernames and other addresses in the records
//! become pivots.
//!
//! What leaves the records, per breach database ([`ExposureBreach`]): how many
//! records hold the address, the fields they expose, the values each
//! non-credential field holds, and whether any of them exposes a password or a
//! hash. This is the same unredacted account `OathNet`'s leg gives, through the
//! one rule both follow ([`crate::breach_record`]). A cleartext password, hash
//! or salt never leaves: the decoder keeps only that one was exposed. Usernames
//! and other addresses also become pivots.
//!
//! The search reads one page of [`EXPOSURE_PAGE_SIZE`] records. When `DeHashed`
//! reports more matches than the page holds, the answer is marked partial.

use std::collections::{BTreeMap, BTreeSet};

use super::client::{DehashedClient, DehashedError, SearchRequest};
use super::query::{Field, Purpose, Selector};

/// Why the automated `exposure` leg searches `DeHashed`. The standalone
/// `dehashed` command makes the operator declare a [`Purpose`] on every call
/// and never defaults one; the `exposure` command is the operator checking an
/// address under their own authorization, so this leg declares
/// [`Purpose::AuthorizedEngagement`]. It travels with every request and is
/// recorded in the audit receipt, exactly as a typed `--purpose` would be.
pub const EXPOSURE_PURPOSE: Purpose = Purpose::AuthorizedEngagement;

/// Records one exposure search reads. A search costs one credit whatever its size, so the leg
/// reads a thousand at once: ten times the hundred it read before, for the same credit, and
/// about a megabyte of answer.
pub const EXPOSURE_PAGE_SIZE: u32 = 1_000;

/// What the records of one breach database say about the address.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExposureBreach {
    /// The breach database name as `DeHashed` gives it.
    pub dbname: String,
    /// Records on this page that hold the address.
    pub records: usize,
    /// A record in this database exposes a password, a password hash or another credential.
    pub password_exposed: bool,
    /// Fields the records expose, sorted: credentials included, by name only.
    pub fields: BTreeSet<String>,
    /// The distinct values each non-credential field holds across the records, within
    /// [`crate::breach_record`]'s bounds.
    pub values: BTreeMap<String, BTreeSet<String>>,
    /// Records `DeHashed` marks as unstructured free text.
    pub unstructured_records: usize,
}

/// One decoded exposure search page.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExposureSearch {
    /// One entry per breach database, sorted by name.
    pub breaches: Vec<ExposureBreach>,
    /// Records on this page.
    pub records: usize,
    /// Records that name no breach database. Counted, never given a stand-in name.
    pub unnamed_records: usize,
    /// Distinct usernames in the records, sorted.
    pub usernames: BTreeSet<String>,
    /// Distinct addresses in the records, sorted, as written.
    pub emails: BTreeSet<String>,
    /// Matching records `DeHashed` reports in all.
    pub total: Option<u64>,
    /// This page is full, so `DeHashed` may hold records it did not return.
    pub has_more: bool,
    /// The account's search credits left after this search, as `DeHashed` reported them.
    pub balance: Option<u64>,
}

impl ExposureSearch {
    /// Why this page is not the whole answer, or `None` when it is.
    #[must_use]
    pub fn truncation(&self) -> Option<String> {
        crate::source_outcome::partial_page_note(self.records, self.total, self.has_more)
    }
}

/// Search `DeHashed` for `email` through `client` and reduce the answer to
/// per-database exposure metadata and username/address pivots.
///
/// # Errors
/// The validation, status, transport or decode failure that [`DehashedClient::search`]
/// returns. A bad address is [`DehashedError::Query`]; no key is
/// [`DehashedError::MissingKey`]; neither sends a request.
pub fn search_email(client: &DehashedClient, email: &str) -> Result<ExposureSearch, DehashedError> {
    let selector = Selector::new(Field::Email, email)?;
    let request = SearchRequest {
        selector,
        purpose: EXPOSURE_PURPOSE,
        size: EXPOSURE_PAGE_SIZE,
        page: 1,
    };
    let outcome = client.search(&request)?;

    let mut search = ExposureSearch {
        records: outcome.entries.len(),
        total: outcome.total,
        balance: outcome.balance,
        has_more: outcome.entries.len()
            >= usize::try_from(EXPOSURE_PAGE_SIZE).unwrap_or(usize::MAX),
        ..ExposureSearch::default()
    };
    let mut breaches: BTreeMap<String, ExposureBreach> = BTreeMap::new();
    for entry in &outcome.entries {
        search.emails.extend(entry.emails().map(str::to_owned));
        search
            .usernames
            .extend(entry.usernames().map(str::to_owned));
        let dbname = entry
            .database_name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty());
        let Some(dbname) = dbname else {
            search.unnamed_records += 1;
            continue;
        };
        let breach = breaches
            .entry(dbname.to_owned())
            .or_insert_with(|| ExposureBreach {
                dbname: dbname.to_owned(),
                ..ExposureBreach::default()
            });
        breach.records += 1;
        breach.password_exposed |= entry.password_exposed();
        breach.unstructured_records += usize::from(entry.raw.unstructured);
        crate::breach_record::merge(
            &entry.fields,
            &entry.values,
            &mut breach.fields,
            &mut breach.values,
        );
    }
    search.breaches = breaches.into_values().collect();
    Ok(search)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::http::{Request, Response, Transport, TransportFailure};
    use crate::keys::Secret;
    use crate::rate_limit::RateLimiter;

    const KEY: &str = "dh-exposure-key-0123456789";

    /// Answers each request with the next canned response and records what was sent.
    struct Recorder {
        responses: Mutex<Vec<Response>>,
        sent: Mutex<Vec<Request>>,
    }

    impl Transport for Recorder {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.sent
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(request.clone());
            let mut responses = self
                .responses
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if responses.is_empty() {
                return Ok(json(500, ""));
            }
            Ok(responses.remove(0))
        }
    }

    fn json(status: u16, body: &str) -> Response {
        Response {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.as_bytes().to_vec(),
            truncated: false,
        }
    }

    fn client_for(body: &str) -> (DehashedClient, Arc<Recorder>) {
        let recorder = Arc::new(Recorder {
            responses: Mutex::new(vec![json(200, body)]),
            sent: Mutex::default(),
        });
        let secret = Secret::new(KEY.to_owned()).unwrap_or_else(|e| panic!("fixture secret: {e}"));
        // A zero-per-minute limiter never blocks the first token, so tests do not wait.
        let client =
            DehashedClient::with_limiter(recorder.clone(), secret, RateLimiter::per_minute(0));
        (client, recorder)
    }

    const SAMPLE: &str = r#"{
        "entries": [
            {"id": "1", "database_name": "LinkedIn", "email": ["ada@example.com"],
             "username": ["ada99", "ada_alt"], "password": "hunter2-secret", "name": ["Ada Example"]},
            {"id": "2", "database_name": "LinkedIn", "email": ["ada@example.com", "alt@example.com"],
             "hashed_password": "5f4dcc3b5aa765d61d8327deb882cf99", "phone": "+15555550100"},
            {"id": "3", "database_name": "AcmeForum", "email": ["ada@example.com"]},
            {"id": "4", "username": "loner"}
        ],
        "total": 4
    }"#;

    #[test]
    fn records_become_per_database_exposure_metadata_and_pivots() {
        let (client, recorder) = client_for(SAMPLE);
        let search = match search_email(&client, "ada@example.com") {
            Ok(search) => search,
            Err(error) => panic!("search failed: {error}"),
        };
        assert_eq!(search.records, 4);
        assert_eq!(search.unnamed_records, 1);
        assert_eq!(search.truncation(), None);

        let names: Vec<&str> = search.breaches.iter().map(|b| b.dbname.as_str()).collect();
        assert_eq!(names, ["AcmeForum", "LinkedIn"]);
        let linkedin = &search.breaches[1];
        assert_eq!(linkedin.records, 2);
        assert!(
            linkedin.password_exposed,
            "a password and a hash are both exposed"
        );
        let forum = &search.breaches[0];
        assert_eq!(forum.records, 1);
        assert!(!forum.password_exposed);

        let usernames: Vec<&str> = search.usernames.iter().map(String::as_str).collect();
        assert_eq!(usernames, ["ada99", "ada_alt", "loner"]);
        let emails: Vec<&str> = search.emails.iter().map(String::as_str).collect();
        assert_eq!(emails, ["ada@example.com", "alt@example.com"]);

        // One POST to /v2/search carrying the quoted exact-match query and the declared purpose.
        let sent = recorder
            .sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].url.ends_with("/v2/search"), "{}", sent[0].url);
        let body = String::from_utf8(sent[0].body.clone()).unwrap_or_default();
        assert!(body.contains(r#"email:\"ada@example.com\""#), "{body}");
    }

    #[test]
    fn no_credential_survives_the_search_and_every_other_value_does() {
        let (client, _recorder) = client_for(SAMPLE);
        let search = search_email(&client, "ada@example.com").unwrap_or_default();
        // A failure names the credential, never its value, so a failing run cannot copy it into CI.
        let rendered = format!("{search:?}");
        for (credential, value) in [
            ("password", "hunter2-secret"),
            ("hash", "5f4dcc3b5aa765d61d8327deb882cf99"),
        ] {
            assert!(
                !rendered.contains(value),
                "the {credential} survived the search"
            );
        }
        // Every other value the records hold is kept, per database, as OathNet's leg keeps it.
        let linkedin = &search.breaches[1];
        assert_eq!(linkedin.dbname, "LinkedIn");
        let kept = |field: &str| -> Vec<&str> {
            linkedin
                .values
                .get(field)
                .map(|values| values.iter().map(String::as_str).collect())
                .unwrap_or_default()
        };
        assert_eq!(kept("name"), ["Ada Example"]);
        assert_eq!(kept("phone"), ["+15555550100"]);
        assert_eq!(kept("email"), ["ada@example.com", "alt@example.com"]);
        assert!(kept("password").is_empty() && kept("hashed_password").is_empty());
        let fields: Vec<&str> = linkedin.fields.iter().map(String::as_str).collect();
        assert_eq!(
            fields,
            [
                "email",
                "hashed_password",
                "name",
                "password",
                "phone",
                "username"
            ]
        );
    }

    /// One search costs one credit whatever its size, so the leg reads a thousand records in one:
    /// ten times what it read before, for the same credit, and still about a megabyte.
    #[test]
    fn the_leg_reads_a_thousand_records_for_one_credit() {
        let (client, recorder) = client_for(r#"{"entries": []}"#);
        search_email(&client, "ada@example.com").unwrap_or_default();
        let sent = recorder
            .sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let body: serde_json::Value = serde_json::from_slice(&sent[0].body).unwrap_or_default();
        assert_eq!(body["size"], 1_000);
        assert_eq!(body["page"], 1);
    }

    #[test]
    fn a_full_page_is_partial_even_without_a_total() {
        let entries: Vec<String> = (0..EXPOSURE_PAGE_SIZE)
            .map(|i| format!(r#"{{"database_name": "db", "email": ["u{i}@example.com"]}}"#))
            .collect();
        let body = format!(r#"{{"entries": [{}]}}"#, entries.join(","));
        let (client, _recorder) = client_for(&body);
        let search = search_email(&client, "ada@example.com").unwrap_or_default();
        assert!(search.has_more);
        assert!(
            search
                .truncation()
                .unwrap_or_default()
                .contains("an unreported number")
        );
    }

    #[test]
    fn an_invalid_address_sends_nothing() {
        let (client, recorder) = client_for(SAMPLE);
        let result = search_email(&client, "not-an-email");
        assert!(matches!(result, Err(DehashedError::Query(_))));
        assert!(
            recorder
                .sent
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
        );
    }
}
