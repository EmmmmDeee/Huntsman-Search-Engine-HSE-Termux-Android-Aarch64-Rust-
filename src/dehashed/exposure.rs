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
//! What leaves a record is only exposure metadata: per breach database
//! ([`ExposureBreach`]), how many records hold the address and whether any of
//! them exposes a password or a hash. No password, hash or other record value
//! is read beyond the boolean [`super::types::Entry::has_password`] /
//! [`super::types::Entry::has_hashed_password`] flags the client already
//! decodes; usernames and addresses are the only record values kept, as pivots.
//!
//! The search reads one page of [`MAX_PAGE_SIZE`] records. When `DeHashed`
//! reports more matches than the page holds, the answer is marked partial.

use std::collections::{BTreeMap, BTreeSet};

use super::client::{DehashedClient, DehashedError, MAX_PAGE_SIZE, SearchRequest};
use super::query::{Field, Purpose, Selector};

/// Why the automated `exposure` leg searches `DeHashed`. The standalone
/// `dehashed` command makes the operator declare a [`Purpose`] on every call
/// and never defaults one; the `exposure` command is the operator checking an
/// address under their own authorization, so this leg declares
/// [`Purpose::AuthorizedEngagement`]. It travels with every request and is
/// recorded in the audit receipt, exactly as a typed `--purpose` would be.
pub const EXPOSURE_PURPOSE: Purpose = Purpose::AuthorizedEngagement;

/// What the records of one breach database say about the address. The only
/// value kept is the database name `DeHashed` gives.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExposureBreach {
    /// The breach database name as `DeHashed` gives it.
    pub dbname: String,
    /// Records on this page that hold the address.
    pub records: usize,
    /// A record in this database exposes a password or a password hash.
    pub password_exposed: bool,
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
        size: MAX_PAGE_SIZE,
        page: 1,
    };
    let outcome = client.search(&request)?;

    let mut search = ExposureSearch {
        records: outcome.entries.len(),
        total: outcome.total,
        has_more: outcome.entries.len() >= usize::try_from(MAX_PAGE_SIZE).unwrap_or(usize::MAX),
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
        if entry.has_password() || entry.has_hashed_password() {
            breach.password_exposed = true;
        }
    }
    search.breaches = breaches.into_values().collect();
    Ok(search)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::hibp::rate_limit::RateLimiter;
    use crate::http::{Request, Response, Transport, TransportFailure};
    use crate::keys::Secret;

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
    fn no_secret_or_personal_value_survives_the_search() {
        let (client, _recorder) = client_for(SAMPLE);
        let search = search_email(&client, "ada@example.com").unwrap_or_default();
        let rendered = format!("{search:?}");
        for value in [
            "hunter2-secret",
            "5f4dcc3b5aa765d61d8327deb882cf99",
            "+15555550100",
            "Ada Example",
        ] {
            assert!(!rendered.contains(value), "{value:?} kept: {rendered}");
        }
    }

    #[test]
    fn a_full_page_is_partial_even_without_a_total() {
        let entries: Vec<String> = (0..MAX_PAGE_SIZE)
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
