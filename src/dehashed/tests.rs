//! Client behaviour over a fake transport. No test touches the network.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use super::cli;
use super::client::{
    API_KEY_HEADER, DEHASHED_API_BASE, DehashedClient, DehashedError, SearchRequest,
};
use super::query::{Field, Purpose, QueryError, Selector};
use crate::http::{Request, Response, Transport, TransportFailure};
use crate::keys::Secret;
use crate::rate_limit::RateLimiter;
use crate::source_outcome::SourceOutcomeKind;

const KEY: &str = "test-key-7f3a9c";

#[derive(Default)]
pub(super) struct Fake {
    pub(super) responses: Mutex<VecDeque<Response>>,
    pub(super) requests: Mutex<Vec<Request>>,
    pub(super) fail: bool,
}

impl Fake {
    pub(super) fn with(status: u16, body: &str, headers: &[(&str, &str)]) -> Arc<Self> {
        let fake = Self::default();
        fake.responses.lock().unwrap().push_back(Response {
            status,
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
            body: body.as_bytes().to_vec(),
            truncated: false,
        });
        Arc::new(fake)
    }

    pub(super) fn calls(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

impl Transport for Fake {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        self.requests.lock().unwrap().push(request.clone());
        if self.fail {
            return Err(TransportFailure {
                kind: crate::source_outcome::SourceOutcomeKind::TtfbTimeout,
                detail: "a@example.com leaked-detail".into(),
                blocked: false,
            });
        }
        Ok(self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected request"))
    }
}

pub(super) fn client(fake: &Arc<Fake>) -> DehashedClient {
    DehashedClient::with_limiter(
        fake.clone(),
        Secret::new(KEY).unwrap(),
        RateLimiter::per_minute(0),
    )
}

pub(super) fn email_request(purpose: Purpose) -> SearchRequest {
    SearchRequest::new(
        Selector::new(Field::Email, "a@example.com").unwrap(),
        purpose,
    )
}

/// A standard output that refuses every write, as a closed pipe does.
struct ClosedPipe;

impl std::io::Write for ClosedPipe {
    fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("the reader has gone"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A query whose result cannot reach standard output must not report success: the caller would
/// believe the answer was delivered when it was lost.
#[test]
fn a_result_that_cannot_be_written_is_an_io_failure_not_success() {
    let keys = Secret::new(KEY).unwrap();
    let fake = Fake::with(200, r#"{"entries": [], "total": 0}"#, &[]);
    let args = [
        "search",
        "--email",
        "a@example.com",
        "--purpose",
        "own-account",
    ]
    .iter()
    .map(|value| (*value).to_owned())
    .collect::<Vec<_>>();
    let mut err = Vec::new();
    let code = cli::run(&args, || Ok(keys), fake.clone(), &mut ClosedPipe, &mut err);
    assert_eq!(
        code,
        crate::exit::EX_IOERR,
        "{}",
        String::from_utf8_lossy(&err)
    );
    assert_eq!(fake.calls(), 1);
}

/// Every `DeHashed` path resolves its key one way: the shared lookup keys, then the environment
/// variable, then the legacy private `~/.config/dehashed/api_key` file. That file is honoured only
/// when it is private, so a key it holds is found by `exposure` as it is by `dehashed search`.
#[cfg(unix)]
#[test]
fn every_path_resolves_the_key_one_way() {
    use super::client::{API_KEY_ENV, key_from};
    use std::os::unix::fs::PermissionsExt;
    let home = std::env::temp_dir().join(format!("hse-dehashed-key-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    let dir = home.join(".config").join("dehashed");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("api_key");
    std::fs::write(&file, "file-key-0123456789abcdef\n").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let none = crate::keys::Keys::parse("").unwrap();
    let slot =
        crate::keys::Keys::parse(&format!("{API_KEY_ENV}=slot-key-0123456789abcdef")).unwrap();
    let found =
        |keys: &crate::keys::Keys, environment: Option<&str>, home: Option<&std::path::Path>| {
            key_from(keys, environment.map(str::to_owned), home).map(|key| key.expose().to_owned())
        };
    assert_eq!(
        found(&none, None, Some(&home)).unwrap(),
        "file-key-0123456789abcdef"
    );
    assert_eq!(
        found(&none, Some("env-key-0123456789abcdef"), Some(&home)).unwrap(),
        "env-key-0123456789abcdef"
    );
    assert_eq!(
        found(&slot, Some("env-key-0123456789abcdef"), Some(&home)).unwrap(),
        "slot-key-0123456789abcdef"
    );
    // A blank environment value is no key: the file still answers.
    assert_eq!(
        found(&none, Some("   "), Some(&home)).unwrap(),
        "file-key-0123456789abcdef"
    );
    assert!(matches!(
        found(&none, None, None),
        Err(DehashedError::MissingKey)
    ));
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        found(&none, None, Some(&home)),
        Err(DehashedError::KeyFilePermissions)
    ));
    std::fs::remove_file(&file).unwrap();
    assert!(matches!(
        found(&none, None, Some(&home)),
        Err(DehashedError::MissingKey)
    ));
    let _ = std::fs::remove_dir_all(&home);
}

/// The lookup legs build their client through the same resolution: a key in the shared slot gives
/// a client that searches with it. (No key gives none, but that half depends on the machine's own
/// environment and key file, which `every_path_resolves_the_key_one_way` covers with a given one.)
#[test]
fn a_lookup_client_searches_with_the_resolved_key() {
    let slot = crate::keys::Keys::parse(&format!("{}={KEY}", super::client::API_KEY_ENV)).unwrap();
    let fake = Fake::with(200, r#"{"entries": []}"#, &[]);
    let client = super::client::client_for_lookup(&slot, fake.clone()).expect("a client");
    client.search(&email_request(Purpose::OwnAccount)).unwrap();
    assert_eq!(
        fake.requests.lock().unwrap()[0].header_value(API_KEY_HEADER),
        Some(KEY)
    );
}

#[test]
fn dehashed_uses_configured_shared_key_without_leaking_it() {
    let keys = crate::keys::Keys::parse(&format!("{}={KEY}", super::client::API_KEY_ENV)).unwrap();
    let fake = Fake::with(200, r#"{"entries": [], "total": 0}"#, &[]);
    let args = [
        "search",
        "--email",
        "a@example.com",
        "--purpose",
        "own-account",
    ]
    .iter()
    .map(|value| (*value).to_owned())
    .collect::<Vec<_>>();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = cli::run(
        &args,
        || super::client::key_from_sources(&keys),
        fake.clone(),
        &mut out,
        &mut err,
    );
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
    assert_eq!(fake.calls(), 1);
    let sent = fake.requests.lock().unwrap();
    assert_eq!(sent[0].header_value(API_KEY_HEADER), Some(KEY));
    assert!(!String::from_utf8_lossy(&out).contains(KEY));
    assert!(!String::from_utf8_lossy(&err).contains(KEY));
}

#[test]
fn sends_one_post_to_the_fixed_origin_with_exact_body_and_key_header() {
    let fake = Fake::with(200, r#"{"entries": [], "total": 0}"#, &[]);
    let outcome = client(&fake)
        .search(&email_request(Purpose::OwnAccount))
        .unwrap();
    assert_eq!(outcome.total, Some(0));
    assert_eq!(outcome.query, "email:\"a@example.com\"");

    let requests = fake.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let sent = &requests[0];
    assert_eq!(sent.method, crate::http::Method::Post);
    assert_eq!(sent.url, format!("{DEHASHED_API_BASE}/search"));
    assert_eq!(sent.header_value(API_KEY_HEADER), Some(KEY));
    let body: serde_json::Value = serde_json::from_slice(&sent.body).unwrap();
    assert_eq!(
        body,
        serde_json::json!({
            "query": "email:\"a@example.com\"",
            "page": 1,
            "size": 10,
            "de_dupe": true,
            "regex": false,
            "wildcard": false
        })
    );
}

#[test]
fn debug_output_of_the_request_redacts_the_key() {
    let fake = Fake::with(200, r#"{"entries": []}"#, &[]);
    client(&fake)
        .search(&email_request(Purpose::OwnAccount))
        .unwrap();
    let rendered = format!("{:?}", fake.requests.lock().unwrap()[0]);
    assert!(!rendered.contains(KEY), "{rendered}");
    assert!(rendered.contains("[redacted]"), "{rendered}");
}

#[test]
fn decodes_entries_into_the_outcome() {
    let body = r#"{"entries": [{"database_name": "Ex", "email": ["a@example.com"], "password": "p"}], "total": 1}"#;
    let fake = Fake::with(200, body, &[]);
    let outcome = client(&fake)
        .search(&email_request(Purpose::IncidentResponse))
        .unwrap();
    assert_eq!(outcome.entries.len(), 1);
    assert_eq!(outcome.entries[0].database_name.as_deref(), Some("Ex"));
    assert_eq!(outcome.purpose, Purpose::IncidentResponse);
}

#[test]
fn status_codes_map_to_named_errors() {
    let cases: [(u16, &str); 4] = [
        (401, "Unauthorized"),
        (403, "Forbidden"),
        (400, "BadRequest"),
        (418, "Unexpected"),
    ];
    for (status, name) in cases {
        let fake = Fake::with(status, "echo a@example.com", &[]);
        let error = client(&fake)
            .search(&email_request(Purpose::OwnAccount))
            .unwrap_err();
        assert!(
            format!("{error:?}").starts_with(name),
            "{status}: {error:?}"
        );
        assert!(!error.to_string().contains("a@example.com"), "{error}");
    }
    let fake = Fake::with(503, "", &[]);
    assert!(matches!(
        client(&fake).search(&email_request(Purpose::OwnAccount)),
        Err(DehashedError::Server(503))
    ));
}

/// `DeHashed` says why it refused in its error body, and one status can mean two things: a 403 is
/// a rejected key ("Issue with API Key", seen live) or an account out of credits ("Insufficient
/// Credits", documented), and a 401 is no subscription (documented) or no key at all (seen live).
/// Each reads as what `DeHashed` meant, so the operator is told to fix the key or buy credits,
/// never the wrong one. The provider's own words are never echoed.
#[test]
fn each_documented_refusal_reads_as_what_dehashed_meant() {
    let cases: [(u16, &str, &str, SourceOutcomeKind); 8] = [
        (
            400,
            r#"{"error": "issue with authentication"}"#,
            "KeyRejected",
            SourceOutcomeKind::AuthRejected,
        ),
        (
            400,
            r#"{"error": "bad query"}"#,
            "BadRequest",
            SourceOutcomeKind::Upstream4xx,
        ),
        (
            401,
            r#"{"error": "You need a search subscription and API credits to use the API, please purchase a search subscription."}"#,
            "NoSubscription",
            SourceOutcomeKind::EntitlementDenied,
        ),
        (
            401,
            r#"{"error": "No Authorization header present"}"#,
            "Unauthorized",
            SourceOutcomeKind::AuthRejected,
        ),
        (
            403,
            r#"{"error": "Insufficient Credits"}"#,
            "OutOfCredits",
            SourceOutcomeKind::EntitlementDenied,
        ),
        (
            403,
            r#"{"error": "Issue with API Key"}"#,
            "KeyRejected",
            SourceOutcomeKind::AuthRejected,
        ),
        (403, "", "Forbidden", SourceOutcomeKind::EntitlementDenied),
        (
            403,
            "not json",
            "Forbidden",
            SourceOutcomeKind::EntitlementDenied,
        ),
    ];
    for (status, body, name, kind) in cases {
        let error = crate::test_support::on_fresh_breakers(|| {
            // DeHashed sends its error bodies as text/plain; they are read as JSON all the same.
            let fake = Fake::with(
                status,
                body,
                &[("content-type", "text/plain; charset=utf-8")],
            );
            client(&fake)
                .search(&email_request(Purpose::OwnAccount))
                .unwrap_err()
        });
        assert!(
            format!("{error:?}").starts_with(name),
            "{status} {body}: {error:?}"
        );
        let outcome = error.outcome("dehashed", 1);
        assert_eq!(outcome.kind, kind, "{status} {body}");
        assert_eq!(outcome.http_status, Some(status), "{status} {body}");
        let said = error.to_string();
        for words in [
            "please purchase",
            "Issue with API Key",
            "Insufficient Credits",
            "issue with",
        ] {
            assert!(!said.contains(words), "{said:?} echoes the body");
        }
    }
}

#[test]
fn rate_limit_reports_retry_after_without_retrying() {
    let fake = Fake::with(429, "", &[("retry-after", "42")]);
    let error = client(&fake)
        .search(&email_request(Purpose::OwnAccount))
        .unwrap_err();
    match error {
        DehashedError::RateLimited { retry_after } => {
            assert_eq!(retry_after, Some(std::time::Duration::from_secs(42)));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(fake.calls(), 1, "a 429 must not be retried automatically");
}

#[test]
fn rate_limit_reads_retry_after_as_the_fetch_does() {
    // A date already past is no wait at all, so `Some(0)` proves the date was read, not dropped.
    let cases = [
        ("Wed, 21 Oct 2015 07:28:00 GMT", Some(0)),
        ("999999", Some(3600)),
        ("soon", None),
    ];
    for (value, expected) in cases {
        // Each case on its own breaker: a 429 pauses DeHashed, so a second one would not be sent.
        let error = crate::test_support::on_fresh_breakers(|| {
            let fake = Fake::with(429, "", &[("retry-after", value)]);
            client(&fake)
                .search(&email_request(Purpose::OwnAccount))
                .unwrap_err()
        });
        match error {
            DehashedError::RateLimited { retry_after } => {
                assert_eq!(retry_after.map(|d| d.as_secs()), expected, "{value}");
            }
            other => panic!("{value}: {other:?}"),
        }
    }
}

/// Every client `DehashedClient::new` builds spends one budget for the whole process: the exposure
/// legs of concurrent lookups, a batch scan and the web UI each build their own client, so a
/// budget per client would multiply `DeHashed`'s rate by the number of callers.
#[test]
fn every_production_client_shares_one_process_wide_budget() {
    let first = DehashedClient::new(Fake::with(200, "{}", &[]), Secret::new(KEY).unwrap());
    let second = DehashedClient::new(Fake::with(200, "{}", &[]), Secret::new(KEY).unwrap());
    assert!(
        std::sync::Arc::ptr_eq(first.limiter(), second.limiter()),
        "each client kept its own budget"
    );
    assert_eq!(first.limiter().limit(), super::client::REQUESTS_PER_WINDOW);
}

/// A 429 pauses `DeHashed` for the process: the next search in the pause is not sent, and says
/// so, instead of spending another request into the limit. The pause is the one `fetch`'s
/// per-host breaker keeps for every paced source.
#[test]
fn a_rate_limit_pauses_the_next_search_without_sending_it() {
    let fake = Fake::with(429, "", &[("retry-after", "30")]);
    fake.responses.lock().unwrap().push_back(Response {
        status: 200,
        headers: Vec::new(),
        body: br#"{"entries": []}"#.to_vec(),
        truncated: false,
    });
    let dehashed = client(&fake);
    let first = dehashed.search(&email_request(Purpose::OwnAccount));
    assert!(
        matches!(first, Err(DehashedError::RateLimited { .. })),
        "{first:?}"
    );
    let second = dehashed
        .search(&email_request(Purpose::OwnAccount))
        .unwrap_err();
    assert!(matches!(second, DehashedError::Paused), "{second:?}");
    assert_eq!(fake.calls(), 1, "the paused search was sent");
    let outcome = second.outcome("dehashed", 1);
    assert_eq!(outcome.kind, SourceOutcomeKind::Inconclusive);
    assert_eq!(outcome.http_status, None);
    assert!(
        outcome
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("nothing was sent")),
        "{outcome:?}"
    );
}

/// A run of server failures opens the breaker too: after `circuit::FAILURE_THRESHOLD` failed
/// searches the next is held back, so a batch scan stops hammering a failing API.
#[test]
fn repeated_server_failures_hold_back_the_next_search() {
    let fake = Arc::new(Fake::default());
    for _ in 0..=crate::circuit::FAILURE_THRESHOLD {
        fake.responses.lock().unwrap().push_back(Response {
            status: 503,
            headers: Vec::new(),
            body: Vec::new(),
            truncated: false,
        });
    }
    let dehashed = client(&fake);
    for _ in 0..crate::circuit::FAILURE_THRESHOLD {
        let failed = dehashed.search(&email_request(Purpose::OwnAccount));
        assert!(
            matches!(failed, Err(DehashedError::Server(503))),
            "{failed:?}"
        );
    }
    let held = dehashed.search(&email_request(Purpose::OwnAccount));
    assert!(matches!(held, Err(DehashedError::Paused)), "{held:?}");
    assert_eq!(
        fake.calls(),
        crate::circuit::FAILURE_THRESHOLD as usize,
        "the held-back search was sent"
    );
}

/// The answer `DeHashed` documents for one record: the record, its count, the credits left.
fn documented_answer() -> String {
    format!(
        r#"{{"balance": 4321, "took": "179µs", "total": 1, "entries": [{}]}}"#,
        super::types::tests::V2_RECORD
    )
}

/// `dehashed search` prints the account's credits left and every value a record holds, as
/// `FIELD=VALUE` lines, but never a credential.
#[test]
fn the_cli_prints_the_credits_left_and_every_value_but_no_credential() {
    let fake = Fake::with(200, &documented_answer(), &[]);
    let outcome = client(&fake)
        .search(&email_request(Purpose::OwnAccount))
        .unwrap();
    let text = cli::render(&outcome);
    for line in [
        "balance=4321\n",
        "took=179µs\n",
        "database=ExampleBreach\n",
        "email=ada@example.com\n",
        "name=Ada Example\n",
        "phone=+61 7 5555 0100\n",
        "address=1 Example St, Brisbane QLD\n",
        "ip_address=198.51.100.7\n",
        "cryptocurrency_address=bc1qexampleaddress\n",
        "has_password=true\n",
        "password_exposed=true\n",
        "unstructured=true\n",
    ] {
        assert!(text.contains(line), "{line:?} missing");
    }
    assert!(
        text.contains("exposed_fields=address,"),
        "no exposed fields"
    );
    assert!(
        !text.contains("le_only="),
        "a flag DeHashed did not set was printed"
    );
    for (what, value) in [
        ("password", "hunter2-cleartext"),
        ("hash", "live-hash"),
        ("hash type", "bcrypt-type"),
    ] {
        assert!(!text.contains(value), "the {what} was printed");
    }
}

/// `DeHashed` documents a "maximum pagination depth" of 10,000 results ("page:3 and size:5000 would
/// be invalid") and pages of up to 10,000. A request past the depth is refused before it is sent,
/// so no request is spent on an answer `DeHashed` will refuse; a page as large as `DeHashed` allows
/// is sent.
#[test]
fn a_page_past_dehashed_s_depth_is_refused_before_it_is_sent() {
    let request = |page: u32, size: u32| SearchRequest {
        size,
        page,
        ..email_request(Purpose::OwnAccount)
    };
    for (page, size) in [(101, 100), (3, 5_000), (2, 10_000), (5_001, 2)] {
        let fake = Fake::with(200, r#"{"entries": []}"#, &[]);
        let refused = client(&fake).search(&request(page, size)).unwrap_err();
        assert!(
            matches!(refused, DehashedError::BeyondDepth { .. }),
            "{page}x{size}: {refused:?}"
        );
        assert_eq!(fake.calls(), 0, "{page}x{size} was sent");
        assert_eq!(refused.outcome_kind(), SourceOutcomeKind::Inconclusive);
    }
    for (page, size) in [(100, 100), (1, 10_000), (2, 5_000), (10_000, 1)] {
        let fake = Fake::with(200, r#"{"entries": []}"#, &[]);
        let sent = client(&fake).search(&request(page, size));
        assert!(sent.is_ok(), "{page}x{size}: {sent:?}");
        assert_eq!(fake.calls(), 1);
    }
    let fake = Fake::with(200, r#"{"entries": []}"#, &[]);
    assert!(matches!(
        client(&fake).search(&request(1, 10_001)),
        Err(DehashedError::InvalidSize(10_001))
    ));
}

/// A Cloudflare interstitial served with 200 in place of the API's answer.
const CHALLENGE: &str = "<html><title>Just a moment...</title>\
    <script src=\"https://challenges.cloudflare.com/x\"></script></html>";

#[test]
fn no_response_keeps_the_cause_and_a_challenge_page_is_not_an_answer() {
    let fake = Arc::new(Fake {
        fail: true,
        ..Fake::default()
    });
    let error = client(&fake)
        .search(&email_request(Purpose::OwnAccount))
        .unwrap_err();
    assert!(
        matches!(
            error,
            DehashedError::Transport(SourceOutcomeKind::TtfbTimeout)
        ),
        "{error:?}"
    );
    let fake = Fake::with(200, CHALLENGE, &[]);
    let error = client(&fake)
        .search(&email_request(Purpose::OwnAccount))
        .unwrap_err();
    assert!(
        matches!(error, DehashedError::NotAnAnswer(SourceOutcomeKind::BotWaf)),
        "{error:?}"
    );
}

/// Every error, with the outcome kind and HTTP status it must record.
fn every_error() -> Vec<(DehashedError, SourceOutcomeKind, Option<u16>)> {
    let pause = Some(std::time::Duration::from_secs(42));
    vec![
        (
            DehashedError::Query(QueryError::Invalid("empty")),
            SourceOutcomeKind::Inconclusive,
            None,
        ),
        (
            DehashedError::MissingKey,
            SourceOutcomeKind::NotConfigured,
            None,
        ),
        (
            DehashedError::KeyFilePermissions,
            SourceOutcomeKind::Inconclusive,
            None,
        ),
        (
            DehashedError::InvalidSize(0),
            SourceOutcomeKind::Inconclusive,
            None,
        ),
        (
            DehashedError::InvalidPage(0),
            SourceOutcomeKind::Inconclusive,
            None,
        ),
        (
            DehashedError::Unauthorized,
            SourceOutcomeKind::AuthRejected,
            Some(401),
        ),
        (
            DehashedError::Forbidden,
            SourceOutcomeKind::EntitlementDenied,
            Some(403),
        ),
        (
            DehashedError::BadRequest,
            SourceOutcomeKind::Upstream4xx,
            Some(400),
        ),
        (
            DehashedError::RateLimited { retry_after: pause },
            SourceOutcomeKind::RateLimited,
            Some(429),
        ),
        (
            DehashedError::Server(503),
            SourceOutcomeKind::Upstream5xx,
            Some(503),
        ),
        (
            DehashedError::Unexpected(302),
            SourceOutcomeKind::RedirectChanged,
            Some(302),
        ),
        (
            DehashedError::Transport(SourceOutcomeKind::DnsFailure),
            SourceOutcomeKind::DnsFailure,
            None,
        ),
        (
            DehashedError::NotAnAnswer(SourceOutcomeKind::BotWaf),
            SourceOutcomeKind::BotWaf,
            None,
        ),
        (
            DehashedError::Decode("x".into()),
            SourceOutcomeKind::SchemaDrift,
            None,
        ),
        (
            DehashedError::KeyRejected(403),
            SourceOutcomeKind::AuthRejected,
            Some(403),
        ),
        (
            DehashedError::NoSubscription,
            SourceOutcomeKind::EntitlementDenied,
            Some(401),
        ),
        (
            DehashedError::OutOfCredits,
            SourceOutcomeKind::EntitlementDenied,
            Some(403),
        ),
        (DehashedError::Paused, SourceOutcomeKind::Inconclusive, None),
    ]
}

#[test]
fn every_error_names_one_outcome() {
    for (error, kind, status) in every_error() {
        assert_eq!(error.outcome_kind(), kind, "{error:?}");
        assert_eq!(error.http_status(), status, "{error:?}");
        let outcome = error.outcome("dehashed", 7);
        assert_eq!(
            (outcome.kind, outcome.http_status, outcome.found),
            (kind, status, None),
            "{error:?}"
        );
        assert_eq!(outcome.detail, Some(error.to_string()), "{error:?}");
        let pause = matches!(error, DehashedError::RateLimited { .. }).then_some(42);
        assert_eq!(outcome.retry_after_secs, pause, "{error:?}");
    }
}

#[test]
fn unexpected_body_shape_is_an_error_and_is_not_echoed() {
    let fake = Fake::with(200, r#"{"results": "a@example.com"}"#, &[]);
    let error = client(&fake)
        .search(&email_request(Purpose::OwnAccount))
        .unwrap_err();
    assert!(matches!(error, DehashedError::Decode(_)), "{error:?}");
    assert!(!error.to_string().contains("a@example.com"), "{error}");
}

#[test]
fn truncated_body_is_refused() {
    let fake = Fake::default();
    fake.responses.lock().unwrap().push_back(Response {
        status: 200,
        headers: vec![],
        body: b"{\"entries\": []}".to_vec(),
        truncated: true,
    });
    let error = client(&Arc::new(fake))
        .search(&email_request(Purpose::OwnAccount))
        .unwrap_err();
    assert!(matches!(error, DehashedError::Decode(_)), "{error:?}");
}

#[test]
fn transport_failure_does_not_leak_the_identifier() {
    let fake = Arc::new(Fake {
        fail: true,
        ..Fake::default()
    });
    let error = client(&fake)
        .search(&email_request(Purpose::OwnAccount))
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "dehashed: transport error: request failed"
    );
}

#[test]
fn invalid_bounds_are_rejected_before_any_request() {
    let fake = Fake::with(200, r#"{"entries": []}"#, &[]);
    let mut request = email_request(Purpose::OwnAccount);
    request.size = 0;
    assert!(matches!(
        client(&fake).search(&request),
        Err(DehashedError::InvalidSize(0))
    ));
    request.size = 10;
    request.page = 0;
    assert!(matches!(
        client(&fake).search(&request),
        Err(DehashedError::InvalidPage(0))
    ));
    // DeHashed's documented depth: page x size may be at most 10,000.
    request.page = 1_001;
    assert!(matches!(
        client(&fake).search(&request),
        Err(DehashedError::BeyondDepth {
            page: 1_001,
            size: 10
        })
    ));
    assert_eq!(fake.calls(), 0);
}

#[test]
fn cli_refuses_bad_arguments_before_loading_a_key_or_sending() {
    let fake = Fake::with(200, r#"{"entries": []}"#, &[]);
    let mut out = Vec::new();
    let mut err = Vec::new();
    let key_loaded = std::cell::Cell::new(false);
    let args: Vec<String> = [
        "search",
        "--email",
        "*@example.com",
        "--purpose",
        "own-account",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    let code = cli::run(
        &args,
        || {
            key_loaded.set(true);
            Secret::new(KEY).map_err(|_| DehashedError::MissingKey)
        },
        fake.clone(),
        &mut out,
        &mut err,
    );
    assert_eq!(code, 65);
    assert!(!key_loaded.get());
    assert_eq!(fake.calls(), 0);
}

/// Past `DeHashed`'s pagination depth the command exits 65 naming the depth, after the key loads
/// but before any request: no request is spent on an answer `DeHashed` would refuse.
#[test]
fn cli_refuses_a_page_past_the_depth_without_sending() {
    let fake = Fake::with(200, r#"{"entries": []}"#, &[]);
    let args: Vec<String> = [
        "search",
        "--email",
        "a@example.com",
        "--purpose",
        "own-account",
        "--page",
        "2",
        "--size",
        "6000",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = cli::run(
        &args,
        || Ok(Secret::new(KEY).unwrap()),
        fake.clone(),
        &mut out,
        &mut err,
    );
    assert_eq!(code, 65);
    assert_eq!(fake.calls(), 0);
    let said = String::from_utf8(err).unwrap_or_default();
    assert!(said.contains("10000-result depth"), "{said}");
}

#[test]
fn cli_without_a_key_exits_66_and_sends_nothing() {
    let fake = Fake::with(200, r#"{"entries": []}"#, &[]);
    let args: Vec<String> = [
        "search",
        "--domain",
        "example.com",
        "--purpose",
        "own-account",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = cli::run(
        &args,
        || Err(DehashedError::MissingKey),
        fake.clone(),
        &mut out,
        &mut err,
    );
    assert_eq!(code, 66);
    assert_eq!(fake.calls(), 0);
}

#[test]
fn cli_success_prints_results_and_purpose() {
    let body = r#"{"entries": [{"email": "a@example.com", "hashed_password": "h"}], "total": 1}"#;
    let fake = Fake::with(200, body, &[]);
    let args: Vec<String> = [
        "search",
        "--email",
        "a@example.com",
        "--purpose",
        "own-account",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = cli::run(
        &args,
        || Ok(Secret::new(KEY).unwrap()),
        fake,
        &mut out,
        &mut err,
    );
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("purpose=own-account\n"), "{text}");
    assert!(text.contains("has_hashed_password=true\n"), "{text}");
    assert!(!text.contains(KEY));
}

mod collector_tests {
    use super::*;
    use crate::collector::{CollectionLimits, CollectionOutcome, CollectorError};
    use crate::dehashed::collector::{COLLECTOR_ID, collect};
    use crate::entity::{Entity, EntityKind};
    use crate::lineage::Lineage;

    const RECORDS: &str = r#"{
        "entries": [
            {"database_name": "ExampleBreach", "email": ["a@example.com", "b@example.com"],
             "username": "ada", "password": "must-not-leak"},
            {"database_name": "ExampleBreach", "email": "a@example.com", "hashed_password": "h"}
        ],
        "total": 2
    }"#;

    fn selector(kind: EntityKind, value: &str) -> Entity {
        Entity::new(kind, value, 1.0, "scan-1")
    }

    fn purpose() -> Purpose {
        Purpose::OwnAccount
    }

    fn limits() -> CollectionLimits {
        CollectionLimits::default()
    }

    #[test]
    fn repeated_values_do_not_push_duplicate_pivots_or_crowd_out_distinct_ones() {
        // "bob" appears twice, "alice" once. With max_pivots == 2, the old code
        // pushed [bob, bob] and dropped alice. Dedup must keep [bob, alice].
        let body = r#"{"entries": [
            {"username": "bob"}, {"username": "bob"}, {"username": "alice"}
        ], "total": 3}"#;
        let fake = Fake::with(200, body, &[]);
        let caps = CollectionLimits {
            max_pivots: 2,
            ..CollectionLimits::default()
        };
        let batch = collect(
            &client(&fake),
            &selector(EntityKind::Email, "a@example.com"),
            purpose(),
            &caps,
            1,
        )
        .unwrap();
        let pivots: Vec<&str> = batch.pivots.iter().map(|p| p.value.as_str()).collect();
        assert!(pivots.contains(&"bob"), "{pivots:?}");
        assert!(
            pivots.contains(&"alice"),
            "a distinct pivot must not be crowded out: {pivots:?}"
        );
        assert_eq!(
            pivots.iter().filter(|v| **v == "bob").count(),
            1,
            "no duplicate pivot: {pivots:?}"
        );
    }

    #[test]
    fn a_handle_is_searched_as_it_was_written_never_by_its_identity_key() {
        // `John.Doe_99` and `johndoe99` share one identity key but are two handles: the search
        // asks for the one given, and the handle echoed back in another case is no pivot.
        let body = r#"{"entries": [{"username": "john.doe_99", "database_name": "ExampleBreach"}],
            "total": 1}"#;
        let fake = Fake::with(200, body, &[]);
        let batch = collect(
            &client(&fake),
            &selector(EntityKind::Username, "John.Doe_99"),
            purpose(),
            &limits(),
            1,
        )
        .unwrap();
        let sent = String::from_utf8_lossy(&fake.requests.lock().unwrap()[0].body).into_owned();
        assert!(sent.contains("John.Doe_99"), "{sent}");
        assert!(!sent.contains("johndoe99"), "{sent}");
        assert!(batch.pivots.is_empty(), "{:?}", batch.pivots);
    }

    #[test]
    fn dropping_an_entity_at_the_cap_marks_the_batch_truncated_not_complete() {
        // total is absent and two distinct emails arrive, but max_entities == 1.
        // The dropped entity must surface as Partial + receipt.truncated, never
        // as a complete Success.
        let body = r#"{"entries": [{"email": "a@example.com"}, {"email": "b@example.com"}]}"#;
        let fake = Fake::with(200, body, &[]);
        let caps = CollectionLimits {
            max_entities: 1,
            ..CollectionLimits::default()
        };
        let batch = collect(
            &client(&fake),
            &selector(EntityKind::Email, "a@example.com"),
            purpose(),
            &caps,
            1,
        )
        .unwrap();
        assert_eq!(batch.entities.len(), 1);
        assert_eq!(
            batch.outcome,
            CollectionOutcome::Partial,
            "a lossy cap must not report Success"
        );
        assert!(
            batch.receipts[0].truncated,
            "the receipt must record the drop"
        );
    }

    #[test]
    fn maps_records_to_entities_pivots_and_evidence() {
        let fake = Fake::with(200, RECORDS, &[]);
        let client = client(&fake);
        let batch = collect(
            &client,
            &selector(EntityKind::Email, "a@example.com"),
            purpose(),
            &limits(),
            1_700_000_000,
        )
        .unwrap();

        assert_eq!(batch.collector_id, COLLECTOR_ID);
        assert_eq!(batch.outcome, CollectionOutcome::Success);
        assert_eq!(batch.receipts.len(), 1);
        assert_eq!(batch.receipts[0].dataset.as_deref(), Some("ExampleBreach"));
        assert_eq!(batch.receipts[0].parsed_rows, 2);
        assert!(batch.receipts[0].response_sha256.is_some());

        // Selector "a@example.com" is deduplicated across records; "b@example.com" and "ada" are pivots.
        let emails: Vec<&str> = batch
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Email)
            .map(|e| e.value.as_str())
            .collect();
        assert_eq!(emails.len(), 2, "{emails:?}");
        assert!(batch.pivots.iter().any(|p| p.value == "b@example.com"));
        assert!(batch.pivots.iter().any(|p| p.value == "ada"));
        assert!(!batch.pivots.iter().any(|p| p.value == "a@example.com"));
    }

    #[test]
    fn evidence_never_carries_password_values() {
        let fake = Fake::with(200, RECORDS, &[]);
        let batch = collect(
            &client(&fake),
            &selector(EntityKind::Email, "a@example.com"),
            purpose(),
            &limits(),
            1,
        )
        .unwrap();
        for entity in &batch.entities {
            for evidence in &entity.evidence {
                let rendered = format!("{evidence:?}");
                assert!(!rendered.contains("must-not-leak"), "{rendered}");
            }
        }
    }

    #[test]
    fn database_name_feeds_lineage_as_one_family() {
        let fake = Fake::with(200, RECORDS, &[]);
        let batch = collect(
            &client(&fake),
            &selector(EntityKind::Email, "a@example.com"),
            purpose(),
            &limits(),
            1,
        )
        .unwrap();
        let evidence = batch
            .entities
            .iter()
            .flat_map(|e| e.evidence.iter())
            .next()
            .expect("at least one evidence record");
        let lineage = Lineage::of(evidence);
        // Lineage canonicalises dataset names to lower case; mirrors of one dataset must collapse to one family.
        assert_eq!(lineage.family(), Some("examplebreach"), "{lineage:?}");
    }

    #[test]
    fn valid_zero_is_a_zero_not_a_failure() {
        let fake = Fake::with(200, r#"{"entries": [], "total": 0}"#, &[]);
        let batch = collect(
            &client(&fake),
            &selector(EntityKind::Domain, "example.com"),
            purpose(),
            &limits(),
            1,
        )
        .unwrap();
        assert_eq!(batch.outcome, CollectionOutcome::ValidZero);
        assert_eq!(batch.receipts[0].outcome.kind, SourceOutcomeKind::ValidZero);
        assert!(batch.entities.is_empty());
    }

    #[test]
    fn more_records_than_returned_is_partial() {
        let fake = Fake::with(
            200,
            r#"{"entries": [{"email": "a@example.com"}], "total": 50}"#,
            &[],
        );
        let batch = collect(
            &client(&fake),
            &selector(EntityKind::Email, "a@example.com"),
            purpose(),
            &limits(),
            1,
        )
        .unwrap();
        assert_eq!(batch.outcome, CollectionOutcome::Partial);
        assert!(batch.receipts[0].truncated);
    }

    /// A saved artifact keeps what the record says: every non-credential value as `value_<field>`
    /// evidence and the fields it exposes, and its receipt carries the credits `DeHashed` says are
    /// left. No credential reaches an entity or its evidence.
    #[test]
    fn evidence_keeps_every_value_and_the_receipt_the_credits_left() {
        let fake = Fake::with(200, &super::documented_answer(), &[]);
        let batch = collect(
            &client(&fake),
            &selector(EntityKind::Email, "ada@example.com"),
            purpose(),
            &limits(),
            1,
        )
        .unwrap();
        let receipt = &batch.receipts[0];
        assert_eq!(
            receipt.quota.as_ref().and_then(|quota| quota.remaining),
            Some(4321)
        );
        let username = batch
            .entities
            .iter()
            .find(|entity| entity.kind == EntityKind::Username && entity.value == "ada99")
            .expect("the username entity");
        let evidence = &username.evidence[0];
        let attr = |name: &str| evidence.attributes.get(name).map(String::as_str);
        assert_eq!(attr("value_name"), Some("Ada Example"));
        assert_eq!(attr("value_phone"), Some("+61 7 5555 0100"));
        assert_eq!(attr("password_exposed"), Some("true"));
        assert_eq!(attr("unstructured"), Some("true"));
        assert!(
            attr("exposed_fields").is_some_and(|fields| fields.contains("hashed_password")),
            "{:?}",
            attr("exposed_fields")
        );
        let saved = serde_json::to_string(&batch.entities).unwrap_or_default();
        for (what, value) in [
            ("password", "hunter2-cleartext"),
            ("hash", "live-hash"),
            ("hash type", "bcrypt-type"),
        ] {
            assert!(!saved.contains(value), "the {what} reached the entities");
        }
    }

    /// `total` counts every page. A later page that holds the last records is complete; only
    /// records past this page make it partial.
    #[test]
    fn a_complete_later_page_is_not_partial() {
        let body = |entries: usize, total: usize| {
            let rows: Vec<String> = (0..entries)
                .map(|i| format!(r#"{{"database_name": "db", "email": ["u{i}@example.com"]}}"#))
                .collect();
            format!(r#"{{"total": {total}, "entries": [{}]}}"#, rows.join(","))
        };
        let limits = CollectionLimits {
            max_records_per_response: 100,
            max_entities: 1_000,
            max_pivots: 1_000,
            ..CollectionLimits::default()
        };
        for (page, entries, total, outcome) in [
            (2, 3, 103, CollectionOutcome::Success),
            (2, 100, 250, CollectionOutcome::Partial),
            (1, 100, 100, CollectionOutcome::Success),
            (1, 100, 101, CollectionOutcome::Partial),
        ] {
            let fake = Fake::with(200, &body(entries, total), &[]);
            let batch = super::super::collector::collect_page(
                &client(&fake),
                &selector(EntityKind::Email, "a@example.com"),
                purpose(),
                page,
                &limits,
                1,
            )
            .unwrap();
            assert_eq!(batch.outcome, outcome, "page {page}: {entries} of {total}");
            assert_eq!(
                batch.receipts[0].truncated,
                outcome == CollectionOutcome::Partial,
                "page {page}: {entries} of {total}"
            );
        }
    }

    #[test]
    fn upstream_failures_are_recorded_not_raised() {
        let cases = [
            (401, SourceOutcomeKind::AuthRejected),
            (403, SourceOutcomeKind::EntitlementDenied),
            (429, SourceOutcomeKind::RateLimited),
            (503, SourceOutcomeKind::Upstream5xx),
        ];
        for (status, expected) in cases {
            // Each case on its own breaker: after the 429 a paced source sends nothing.
            let batch = crate::test_support::on_fresh_breakers(|| {
                let fake = Fake::with(status, "", &[]);
                collect(
                    &client(&fake),
                    &selector(EntityKind::Email, "a@example.com"),
                    purpose(),
                    &limits(),
                    1,
                )
                .unwrap_or_else(|e| panic!("{status}: {e:?}"))
            });
            assert_eq!(batch.outcome, CollectionOutcome::Failed, "{status}");
            assert_eq!(batch.receipts[0].outcome.kind, expected, "{status}");
            assert_eq!(batch.receipts[0].outcome.http_status, Some(status));
            assert!(batch.entities.is_empty());
        }
    }

    #[test]
    fn failure_receipt_detail_never_names_the_identifier() {
        let fake = Fake::with(400, "", &[]);
        let batch = collect(
            &client(&fake),
            &selector(EntityKind::Email, "a@example.com"),
            purpose(),
            &limits(),
            1,
        )
        .unwrap();
        let detail = batch.receipts[0].outcome.detail.clone().unwrap_or_default();
        assert!(!detail.contains("a@example.com"), "{detail}");
    }

    #[test]
    fn unsupported_kinds_and_invalid_values_send_nothing() {
        let fake = Fake::with(200, r#"{"entries": []}"#, &[]);
        assert!(matches!(
            collect(
                &client(&fake),
                &selector(EntityKind::Phone, "15551234567"),
                purpose(),
                &limits(),
                1
            ),
            Err(CollectorError::UnsupportedSelector(_))
        ));
        assert!(matches!(
            collect(
                &client(&fake),
                &selector(EntityKind::Email, "*@example.com"),
                purpose(),
                &limits(),
                1
            ),
            Err(CollectorError::InvalidSelector(_))
        ));
        let zero_budget = CollectionLimits {
            max_requests: 0,
            ..CollectionLimits::default()
        };
        assert!(matches!(
            collect(
                &client(&fake),
                &selector(EntityKind::Email, "a@example.com"),
                purpose(),
                &zero_budget,
                1
            ),
            Err(CollectorError::Invariant(_))
        ));
        assert_eq!(fake.calls(), 0);
    }
}

#[test]
fn key_env_var_matches_the_provider_registry() {
    // service_defs sits in a lower layer and cannot import this module, so the
    // env var name is kept in step by this test instead.
    let def = crate::service_defs::find_service("dehashed").expect("dehashed registered");
    assert_eq!(def.env_var, super::client::API_KEY_ENV);
}

mod artifact_tests {
    use super::*;
    use crate::scan_artifact;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("dehashed-artifact-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("scan.json")
    }

    fn owned(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn search_with_save_artifact_writes_the_collected_entities() {
        let body = r#"{"entries": [
            {"database_name": "ExBreach", "email": ["a@example.com"], "username": "ada", "password": "s3cret-value-xyz"},
            {"database_name": "ExBreach", "email": ["a@example.com"]}
        ], "total": 2}"#;
        let fake = Fake::with(200, body, &[]);
        let path = temp_path("success");
        let args = owned(&[
            "search",
            "--email",
            "a@example.com",
            "--purpose",
            "own-account",
            "--save-artifact",
            path.to_str().unwrap(),
        ]);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = cli::run(
            &args,
            || Ok(Secret::new(KEY).unwrap()),
            fake.clone(),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("purpose=own-account"), "{text}");
        assert!(
            text.contains("scan_id=dehashed:email:\"a@example.com\""),
            "{text}"
        );

        let artifact = scan_artifact::read(&path).expect("artifact reads back");
        assert_eq!(artifact.scan_id, "dehashed:email:\"a@example.com\"");
        let emails: Vec<&str> = artifact
            .entities
            .iter()
            .filter(|e| e.kind == crate::entity::EntityKind::Email)
            .map(|e| e.value.as_str())
            .collect();
        assert_eq!(emails, vec!["a@example.com"]);
        assert!(
            artifact
                .entities
                .iter()
                .any(|e| e.kind == crate::entity::EntityKind::Username && e.value == "ada")
        );
        assert!(artifact.relations.is_empty());
        // The artifact must never carry the response's password fields in any form.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains("s3cret-value-xyz"),
            "password value leaked into the artifact"
        );
        assert!(
            raw.contains("\"has_password\": \"true\""),
            "presence flag should record that a password exists"
        );
    }

    #[test]
    fn a_failed_collection_writes_no_artifact() {
        let fake = Fake::with(401, "", &[]);
        let path = temp_path("failed");
        let args = owned(&[
            "search",
            "--email",
            "a@example.com",
            "--purpose",
            "own-account",
            "--save-artifact",
            path.to_str().unwrap(),
        ]);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = cli::run(
            &args,
            || Ok(Secret::new(KEY).unwrap()),
            fake,
            &mut out,
            &mut err,
        );
        // A rejected key (401) is a permission error (77), matching the
        // non-artifact path, not a transient "unavailable" (69) a wrapper retries.
        assert_eq!(code, 77, "{}", String::from_utf8_lossy(&err));
        assert!(
            !path.exists(),
            "a failed collection must not write an artifact"
        );
        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains("no artifact written")
        );
    }

    #[test]
    fn dangling_save_artifact_is_a_usage_error_before_any_request() {
        let fake = Fake::with(200, r#"{"entries": []}"#, &[]);
        let args = owned(&[
            "search",
            "--email",
            "a@example.com",
            "--purpose",
            "own-account",
            "--save-artifact",
        ]);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = cli::run(
            &args,
            || Ok(Secret::new(KEY).unwrap()),
            fake.clone(),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 64);
        assert_eq!(fake.calls(), 0);
    }

    #[test]
    fn save_artifact_honours_the_requested_page() {
        let fake = Fake::with(
            200,
            r#"{"entries": [{"email": "a@example.com"}], "total": 1}"#,
            &[],
        );
        let path = temp_path("page");
        let args = owned(&[
            "search",
            "--email",
            "a@example.com",
            "--purpose",
            "own-account",
            "--page",
            "3",
            "--save-artifact",
            path.to_str().unwrap(),
        ]);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = cli::run(
            &args,
            || Ok(Secret::new(KEY).unwrap()),
            fake.clone(),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
        // The collection must fetch page 3, not silently substitute page 1.
        let sent = &fake.requests.lock().unwrap()[0];
        let body: serde_json::Value = serde_json::from_slice(&sent.body).unwrap();
        assert_eq!(body["page"], 3, "the request must carry the asked-for page");
        assert!(
            String::from_utf8(out).unwrap().contains("page=3"),
            "the summary must report the page"
        );
    }

    #[test]
    fn save_artifact_rejects_a_following_flag_as_its_path() {
        // `--save-artifact --page` must not swallow --page and write to a file
        // named "--page"; it is a usage error before any request.
        let fake = Fake::with(200, r#"{"entries": []}"#, &[]);
        let args = owned(&[
            "search",
            "--email",
            "a@example.com",
            "--purpose",
            "own-account",
            "--save-artifact",
            "--page",
        ]);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = cli::run(
            &args,
            || Ok(Secret::new(KEY).unwrap()),
            fake.clone(),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 64);
        assert_eq!(fake.calls(), 0, "no request may be sent");
        assert!(
            !std::path::Path::new("--page").exists(),
            "must not create a file named after the flag"
        );
    }
}
