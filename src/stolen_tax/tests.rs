//! Ported from M D's `src/modules/stolen_tax/mod.rs` tests (764ce8e + guard). No live
//! network: every lookup runs against a fake transport keyed on the v2 path.

use std::cell::RefCell;

use super::*;
use crate::deadline::FakeClock;
use crate::http::{Response, TransportFailure};

const KEY: &str = "st-test-key-0123456789";

type Answer = Result<(u16, String), SourceOutcomeKind>;

/// Answers each v2 path from a table; records every request it saw.
struct Paths {
    answers: Vec<(&'static str, Answer)>,
    seen: RefCell<Vec<Request>>,
}

impl Paths {
    fn ok(answers: &[(&'static str, &str)]) -> Self {
        Self {
            answers: answers
                .iter()
                .map(|(p, b)| (*p, Ok((200, (*b).to_owned()))))
                .collect(),
            seen: RefCell::new(Vec::new()),
        }
    }
}

impl Transport for Paths {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        self.seen.borrow_mut().push(request.clone());
        let path = request.url.rsplit_once("path=").map(|(_, p)| p).unwrap();
        match self.answers.iter().find(|(p, _)| *p == path) {
            Some((_, Ok((status, body)))) => Ok(Response {
                status: *status,
                headers: Vec::new(),
                body: body.as_bytes().to_vec(),
                truncated: false,
            }),
            Some((_, Err(kind))) => Err(TransportFailure {
                kind: *kind,
                detail: format!("failed while sending Bearer {KEY}"),
                blocked: false,
            }),
            None => Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: br#"{"success":true,"data":null}"#.to_vec(),
                truncated: false,
            }),
        }
    }
}

fn keys() -> Keys {
    Keys::parse(&format!("{KEY_SLOT}={KEY}\n")).unwrap()
}

fn go(transport: &Paths, query: &str) -> Result<StolenTaxReport, StolenTaxError> {
    lookup(transport, &keys(), query, "scan", 1_700_000_000)
}

fn has(report: &StolenTaxReport, kind: &EntityKind, value: &str) -> bool {
    report
        .entities
        .iter()
        .any(|e| &e.kind == kind && e.value == value)
}

fn decode(path: &str, body: &str) -> StolenTaxData {
    decode_path(path, body.as_bytes()).unwrap()
}

#[test]
fn empty_results_array_deserializes() {
    let data = decode(
        "snusbase",
        r#"{"success":true,"data":{"took":1.0,"size":0,"results":[]}}"#,
    );
    assert!(data.emails.is_empty() && data.breaches.is_empty());
}

#[test]
fn results_object_deserializes() {
    let data = decode(
        "snusbase",
        r#"{"success":true,"data":{"results":{"DB":[{"email":"a@example.com"}]}}}"#,
    );
    assert_eq!(data.emails, ["a@example.com"]);
    assert_eq!(data.breaches[0].record_count, Some(1));
}

#[test]
fn a_non_empty_results_array_is_a_decode_failure() {
    let err = decode_path(
        "snusbase",
        br#"{"success":true,"data":{"results":[{"email":"a@example.com"}]}}"#,
    )
    .unwrap_err();
    assert!(err.contains("non-empty array"), "{err}");
}

#[test]
fn missing_key_fails_before_any_request() {
    let transport = Paths::ok(&[]);
    let err = lookup(&transport, &Keys::default(), "a@example.com", "s", 0).unwrap_err();
    assert_eq!(err, StolenTaxError::MissingKey);
    assert!(err.to_string().contains(KEY_SLOT));
    assert!(transport.seen.borrow().is_empty());
}

#[test]
fn a_placeholder_key_reads_as_missing() {
    let keys = Keys::parse(&format!("{KEY_SLOT}=changeme\n")).unwrap();
    let transport = Paths::ok(&[]);
    assert_eq!(
        lookup(&transport, &keys, "a@example.com", "s", 0).unwrap_err(),
        StolenTaxError::MissingKey
    );
}

#[test]
fn every_path_is_posted_with_a_bearer_key_and_a_json_query_body() {
    let transport = Paths::ok(&[]);
    go(&transport, "user@example.com").unwrap();
    let seen = transport.seen.borrow();
    let urls: Vec<&str> = seen.iter().map(|r| r.url.as_str()).collect();
    assert_eq!(
        urls,
        [
            "https://stolen.tax/api/v2/index.php?path=snusbase",
            "https://stolen.tax/api/v2/index.php?path=osintcat",
            "https://stolen.tax/api/v2/index.php?path=hudsonrock",
        ]
    );
    for r in seen.iter() {
        assert_eq!(r.method, crate::http::Method::Post);
        assert_eq!(
            r.header_value("authorization"),
            Some(format!("Bearer {KEY}").as_str())
        );
        assert!(
            r.header_value("api-key").is_none(),
            "v1 header must be gone"
        );
        assert_eq!(r.header_value("accept"), Some("application/json"));
        let body: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(body, serde_json::json!({"query": "user@example.com"}));
        assert!(!r.url.contains(KEY));
    }
}

#[test]
fn the_key_is_not_sent_to_another_origin_on_redirect() {
    struct Redirect(RefCell<Vec<Request>>);
    impl Transport for Redirect {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.0.borrow_mut().push(request.clone());
            Ok(Response {
                status: 302,
                headers: vec![("location".into(), "https://evil.example/".into())],
                body: Vec::new(),
                truncated: false,
            })
        }
    }
    let transport = Redirect(RefCell::new(Vec::new()));
    let err = lookup(&transport, &keys(), "a@example.com", "s", 0).unwrap_err();
    assert!(matches!(err, StolenTaxError::Failed(_)));
    // max_redirects is 0: the redirect is reported, never followed.
    assert!(
        transport
            .0
            .borrow()
            .iter()
            .all(|r| r.url.starts_with("https://stolen.tax/"))
    );
}

#[test]
fn the_monolith_budget_bounds_the_whole_lookup() {
    assert_eq!(LOOKUP_BUDGET, Duration::from_secs(120));
    assert!(TIMEOUT <= LOOKUP_BUDGET);
    assert_eq!(transport_config().timeout, TIMEOUT);
}

/// Each path answers after a simulated delay on a fake clock. A delay longer than
/// the request's cap behaves like the real transport: the clock advances by the
/// cap and the request times out.
struct Timed<'c> {
    clock: &'c FakeClock,
    answers: Vec<(&'static str, Duration, &'static str)>,
    caps: RefCell<Vec<(String, Duration)>>,
}

impl<'c> Timed<'c> {
    fn new(clock: &'c FakeClock, answers: &[(&'static str, u64, &'static str)]) -> Self {
        Self {
            clock,
            answers: answers
                .iter()
                .map(|(p, secs, body)| (*p, Duration::from_secs(*secs), *body))
                .collect(),
            caps: RefCell::new(Vec::new()),
        }
    }

    fn sent(&self) -> Vec<String> {
        self.caps.borrow().iter().map(|(p, _)| p.clone()).collect()
    }
}

impl Transport for Timed<'_> {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        let path = request.url.rsplit_once("path=").map(|(_, p)| p).unwrap();
        let cap = request
            .timeout
            .expect("every stolen.tax request carries a cap");
        assert!(!cap.is_zero(), "{path}: sent with no budget left");
        self.caps.borrow_mut().push((path.to_owned(), cap));
        let (_, delay, body) = self
            .answers
            .iter()
            .find(|(p, _, _)| *p == path)
            .copied()
            .unwrap_or((path_name(path), Duration::from_secs(1), EMPTY));
        if delay > cap {
            self.clock.advance(cap);
            return Err(TransportFailure {
                kind: SourceOutcomeKind::TtfbTimeout,
                detail: "timed out".into(),
                blocked: false,
            });
        }
        self.clock.advance(delay);
        Ok(Response {
            status: 200,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
            truncated: false,
        })
    }
}

const EMPTY: &str = r#"{"success":true,"data":null}"#;
const SNUS_HIT: &str =
    r#"{"success":true,"data":{"results":{"DB_A":[{"email":"alt@example.com"}]}}}"#;
const OSINT_HIT: &str =
    r#"{"success":true,"data":{"breach_data":[{"username":"alt_user","source":"DB_B"}]}}"#;
const HUDSON_HIT: &str =
    r#"{"success":true,"data":{"stealers":[{"computer_name":"HOST-1","top_logins":[]}]}}"#;
/// Longer than any budget: the request only ends when its cap does.
const HANG: u64 = 10_000;

fn path_name(path: &str) -> &'static str {
    PATHS.iter().copied().find(|p| *p == path).unwrap()
}

fn timed(clock: &FakeClock, transport: &Timed<'_>) -> Result<StolenTaxReport, StolenTaxError> {
    lookup_with_clock(transport, clock, &keys(), "user@example.com", "scan", 0)
}

#[test]
fn worst_case_is_one_budget_not_three_request_timeouts() {
    let clock = FakeClock::new();
    let transport = Timed::new(
        &clock,
        &[
            ("snusbase", HANG, EMPTY),
            ("osintcat", HANG, EMPTY),
            ("hudsonrock", HANG, EMPTY),
        ],
    );
    let err = timed(&clock, &transport).unwrap_err();
    assert!(clock.elapsed() <= LOOKUP_BUDGET, "{:?}", clock.elapsed());
    assert_eq!(clock.elapsed(), LOOKUP_BUDGET);
    let StolenTaxError::BudgetExhausted { skipped, failed } = &err else {
        panic!("expected a budget error, got {err:?}");
    };
    assert_eq!(skipped, &["osintcat", "hudsonrock"]);
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].path, "snusbase");
    assert!(
        failed[0].reason.contains("TtfbTimeout"),
        "{}",
        failed[0].reason
    );
    assert_eq!(transport.sent(), ["snusbase"]);
    let text = err.to_string();
    assert!(
        text.contains("120s lookup budget exhausted; `osintcat`, `hudsonrock` path(s) not sent"),
        "{text}"
    );
    assert!(!text.contains(KEY));
}

#[test]
fn every_request_gets_only_what_is_left_of_the_budget() {
    let clock = FakeClock::new();
    let transport = Timed::new(
        &clock,
        &[
            ("snusbase", 50, SNUS_HIT),
            ("osintcat", 50, OSINT_HIT),
            ("hudsonrock", HANG, HUDSON_HIT),
        ],
    );
    let report = timed(&clock, &transport).unwrap();
    let caps: Vec<Duration> = transport.caps.borrow().iter().map(|(_, c)| *c).collect();
    assert_eq!(
        caps,
        [
            Duration::from_secs(120),
            Duration::from_secs(70),
            Duration::from_secs(20)
        ]
    );
    assert!(caps.iter().sum::<Duration>() <= LOOKUP_BUDGET * 2);
    assert_eq!(clock.elapsed(), LOOKUP_BUDGET);
    assert_eq!(report.failed_paths.len(), 1);
    assert_eq!(report.failed_paths[0].path, "hudsonrock");
    assert!(
        report.failed_paths[0]
            .reason
            .contains("request capped at 20.0s, the rest of the 120s lookup budget"),
        "{}",
        report.failed_paths[0].reason
    );
    assert_eq!(report.skipped_paths.len(), 0);
    assert!(has(&report, &EntityKind::Email, "alt@example.com"));
    // osintcat's row arrived inside the budget. `Entity::value` is the canonical
    // handle (`canonical::canonical_handle` drops `_`); the spelling the provider
    // sent is kept in `raw_value`.
    let user = report
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .expect("osintcat username kept");
    assert_eq!(
        (user.value.as_str(), user.raw_value.as_str()),
        ("altuser", "alt_user")
    );
}

#[test]
fn paths_the_budget_did_not_reach_are_reported_not_dropped() {
    let clock = FakeClock::new();
    // snusbase answers exactly at the deadline: its evidence is kept, and nothing
    // is left for the other two paths.
    let transport = Timed::new(
        &clock,
        &[
            ("snusbase", 120, SNUS_HIT),
            ("osintcat", 1, OSINT_HIT),
            ("hudsonrock", 1, HUDSON_HIT),
        ],
    );
    let report = timed(&clock, &transport).unwrap();
    assert_eq!(clock.elapsed(), LOOKUP_BUDGET);
    assert_eq!(transport.sent(), ["snusbase"]);
    assert!(has(&report, &EntityKind::Email, "alt@example.com"));
    assert!(has(&report, &EntityKind::Credential, "breach:DB_A"));
    assert_eq!(report.entities.len(), 2);
    assert_eq!(report.failed_paths.len(), 0);
    assert_eq!(report.skipped_paths, ["osintcat", "hudsonrock"]);
    assert_eq!(
        report.truncation.as_deref(),
        Some(
            "2 retrieved — stopped by the stolen.tax `osintcat`, `hudsonrock` path(s) not sent (120s lookup budget exhausted), and the provider did not report how many exist. Absence of a finding here is not evidence of absence."
        )
    );
}

#[test]
fn a_failed_and_a_skipped_path_are_both_named() {
    let clock = FakeClock::new();
    let fail = r#"{"success":false,"error":"database temporarily unavailable"}"#;
    let transport = Timed::new(
        &clock,
        &[
            ("snusbase", 30, fail),
            ("osintcat", 90, OSINT_HIT),
            ("hudsonrock", 1, HUDSON_HIT),
        ],
    );
    let report = timed(&clock, &transport).unwrap();
    assert_eq!(transport.sent(), ["snusbase", "osintcat"]);
    assert_eq!(report.failed_paths[0].path, "snusbase");
    assert_eq!(report.skipped_paths, ["hudsonrock"]);
    assert_eq!(
        report.truncation.as_deref(),
        Some(
            "2 retrieved — stopped by the stolen.tax `snusbase` path(s) failing and the `hudsonrock` path(s) not sent (120s lookup budget exhausted), and the provider did not report how many exist. Absence of a finding here is not evidence of absence."
        )
    );
}

#[test]
fn an_empty_answer_with_a_skipped_path_is_not_a_clean_negative() {
    let clock = FakeClock::new();
    let transport = Timed::new(&clock, &[("snusbase", 120, EMPTY)]);
    let err = timed(&clock, &transport).unwrap_err();
    assert_eq!(
        err,
        StolenTaxError::BudgetExhausted {
            skipped: vec!["osintcat", "hudsonrock"],
            failed: Vec::new(),
        }
    );
}

#[test]
fn within_budget_the_cascade_is_unchanged() {
    let answers = [
        ("snusbase", SNUS_HIT),
        ("osintcat", OSINT_HIT),
        ("hudsonrock", HUDSON_HIT),
    ];
    let clock = FakeClock::new();
    let transport = Timed::new(
        &clock,
        &[
            ("snusbase", 40, SNUS_HIT),
            ("osintcat", 30, OSINT_HIT),
            ("hudsonrock", 20, HUDSON_HIT),
        ],
    );
    let budgeted = timed(&clock, &transport).unwrap();
    assert_eq!(transport.sent(), ["snusbase", "osintcat", "hudsonrock"]);
    assert_eq!(clock.elapsed(), Duration::from_secs(90));
    let plain = lookup(&Paths::ok(&answers), &keys(), "user@example.com", "scan", 0).unwrap();
    assert_eq!(budgeted, plain);
    assert!(budgeted.failed_paths.is_empty() && budgeted.skipped_paths.is_empty());
    assert!(budgeted.truncation.is_none());
    assert_eq!(budgeted.entities.len(), 5);
}

#[test]
fn build_entities_deduplication() {
    let data = StolenTaxData {
        emails: vec!["a@example.com".into(), "a@example.com".into()],
        usernames: vec!["bob".into(), "bob".into()],
        breaches: Vec::new(),
    };
    let out = build_entities(&data, "q@example.com", "s");
    assert_eq!(out.len(), 2);
}

#[test]
fn build_entities_dedups_a_dirty_and_a_clean_username_spelling() {
    let data = StolenTaxData {
        usernames: vec!["@jordan_m".into(), "jordan_m".into()],
        ..StolenTaxData::default()
    };
    assert_eq!(build_entities(&data, "q", "s").len(), 1);
}

#[test]
fn build_entities_dedups_a_dirty_and_a_clean_email_spelling() {
    let data = StolenTaxData {
        emails: vec!["A@Example.com ".into(), "a@example.com".into()],
        ..StolenTaxData::default()
    };
    assert_eq!(build_entities(&data, "q", "s").len(), 1);
}

#[test]
fn build_entities_excludes_the_query_value_regardless_of_casing() {
    let data = StolenTaxData {
        emails: vec!["user@example.com".into(), "USER@EXAMPLE.COM".into()],
        ..StolenTaxData::default()
    };
    assert_eq!(build_entities(&data, "User@Example.com", "s").len(), 0);
}

#[test]
fn identity_pivots_carry_correlation_evidence_at_medium() {
    let data = StolenTaxData {
        emails: vec!["alt@example.com".into()],
        ..StolenTaxData::default()
    };
    let out = build_entities(&data, "user@example.com", "s");
    assert!((out[0].confidence - MEDIUM).abs() < f64::EPSILON);
    assert_eq!(
        out[0].evidence[0].summary,
        "Exposed in breach: correlated with user@example.com"
    );
    assert_eq!(out[0].evidence[0].provenance.source, SRC);
}

#[test]
fn normalize_snusbase_emits_breach_markers_and_identity_pivots_without_hashes() {
    let body = r#"{"success":true,"data":{"results":{"DB_A":[{"email":"alt@example.com","username":"altuser","hash":"HASH_MUST_NOT_EMIT","password":"PW_MUST_NOT_EMIT"}]}}}"#;
    let transport = Paths::ok(&[("snusbase", body)]);
    let report = go(&transport, "user@example.com").unwrap();
    assert!(has(&report, &EntityKind::Credential, "breach:DB_A"));
    assert!(has(&report, &EntityKind::Email, "alt@example.com"));
    let text = serde_json::to_string(&report.entities).unwrap();
    assert!(!text.contains("MUST_NOT_EMIT"), "{text}");
    let marker = report
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Credential)
        .unwrap();
    assert!((marker.confidence - HIGH).abs() < f64::EPSILON);
    assert_eq!(marker.evidence[0].summary, "Breach: DB_A (records: 1)");
}

#[test]
fn a_non_key_error_envelope_fails_closed_instead_of_reading_as_no_breach() {
    let fail = r#"{"success":false,"data":null,"error":"database temporarily unavailable"}"#;
    let transport = Paths::ok(&[("snusbase", fail), ("osintcat", fail), ("hudsonrock", fail)]);
    let StolenTaxError::Failed(first) = go(&transport, "user@example.com").unwrap_err() else {
        panic!("expected a path failure");
    };
    assert_eq!(first.path, "snusbase");
    assert!(first.reason.contains("database temporarily unavailable"));
    assert!(first.reason.contains("provider reported failure"));
}

#[test]
fn a_key_shaped_error_is_labelled_and_never_echoes_the_key() {
    let fail = format!(r#"{{"success":false,"error":"Invalid API key {KEY}"}}"#);
    let transport = Paths::ok(&[
        ("snusbase", &fail),
        ("osintcat", &fail),
        ("hudsonrock", &fail),
    ]);
    let err = go(&transport, "user@example.com").unwrap_err();
    let text = err.to_string();
    assert!(text.contains("key or quota rejected"), "{text}");
    assert!(!text.contains(KEY), "{text}");
}

#[test]
fn transport_failures_are_path_failures_with_the_key_scrubbed() {
    let transport = Paths {
        answers: vec![
            ("snusbase", Err(SourceOutcomeKind::TtfbTimeout)),
            ("osintcat", Ok((503, "busy".into()))),
            ("hudsonrock", Ok((401, "nope".into()))),
        ],
        seen: RefCell::new(Vec::new()),
    };
    let StolenTaxError::Failed(first) = go(&transport, "user@example.com").unwrap_err() else {
        panic!("expected a path failure");
    };
    assert_eq!(first.path, "snusbase");
    assert!(!first.reason.contains(KEY));
}

#[test]
fn v2_wire_json_deserialises_snusbase_results_map() {
    let data = decode(
        "snusbase",
        r#"{"success":true,"data":{"took":0.5,"size":2,"results":{"B":[{"username":"u2"}],"A":[{"email":"e@example.com"},{"email":"  "}]}}}"#,
    );
    let names: Vec<&str> = data.breaches.iter().map(|b| b.name.as_str()).collect();
    assert_eq!(names, ["A", "B"], "BTreeMap order is deterministic");
    assert_eq!(data.breaches[0].record_count, Some(2));
    assert_eq!(data.emails, ["e@example.com"]);
    assert_eq!(data.usernames, ["u2"]);
}

#[test]
fn osintcat_empty_breach_data_parses_safely() {
    let data = decode(
        "osintcat",
        r#"{"success":true,"data":{"breach_data":[],"_meta":{"x":1},"api":"v2"}}"#,
    );
    assert!(data.breaches.is_empty() && data.emails.is_empty());
}

#[test]
fn osintcat_fixture_breach_rows_map_like_snusbase() {
    let data = decode(
        "osintcat",
        r#"{"success":true,"data":{"breach_data":[
            {"email":"a1@example.com","source":"Src","name":"ignored"},
            {"email":"a2@example.com","db_name":"AliasDb","breach_date":"2019-01-01"},
            {"username":"a3_user","breach_name":"AliasTwo"},
            {"email":"a4@example.com","database":"DbField"},
            "not-an-object",
            {"email":"a5@example.com"}
        ]}}"#,
    );
    let names: Vec<&str> = data.breaches.iter().map(|b| b.name.as_str()).collect();
    assert_eq!(names, ["Src", "AliasDb", "AliasTwo", "DbField"]);
    assert_eq!(data.breaches[1].date.as_deref(), Some("2019-01-01"));
    assert_eq!(data.emails.len(), 4);
    assert_eq!(data.usernames, ["a3_user"]);
}

#[test]
fn an_unnamed_osintcat_corpus_mints_no_placeholder_marker() {
    let data = decode(
        "osintcat",
        r#"{"success":true,"data":{"breach_data":[{"email":"n@example.com","source":"  "}]}}"#,
    );
    assert!(data.breaches.is_empty(), "no `breach:osintcat` stand-in");
    assert_eq!(data.emails, ["n@example.com"], "the pivot is still kept");
}

#[test]
fn hudsonrock_stealers_emit_markers_and_clear_emails_never_passwords() {
    let body = r#"{"success":true,"data":{"stealers":[{"computer_name":"DESKTOP-ABC","operating_system":"Windows 11","date_compromised":"2026-08-30T00:00:00.000Z","ip":"27.56.***.***","top_logins":["clear.user@example.com","m***d@example.com",""],"top_passwords":["PW_MUST_NOT_EMIT"]}]}}"#;
    let transport = Paths::ok(&[("hudsonrock", body)]);
    let report = go(&transport, "user@example.com").unwrap();
    assert!(has(&report, &EntityKind::Credential, "stealer:DESKTOP-ABC"));
    assert!(has(&report, &EntityKind::Email, "clear.user@example.com"));
    assert_eq!(report.entities.len(), 2);
    let text = serde_json::to_string(&report.entities).unwrap();
    assert!(!text.contains("MUST_NOT_EMIT"));
    let marker = report
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Credential)
        .unwrap();
    assert_eq!(
        marker.evidence[0].summary,
        "Stealer hit: stealer:DESKTOP-ABC (date: 2026-08-30T00:00:00.000Z; path=hudsonrock; os=Windows 11; ip=27.56.***.***)"
    );
}

#[test]
fn a_hostless_stealer_mints_no_marker_but_keeps_its_logins() {
    let data = decode(
        "hudsonrock",
        r#"{"success":true,"data":{"stealers":[{"computer_name":" ","operating_system":"Linux","top_logins":["kept@example.com"]},{"top_logins":[]}]}}"#,
    );
    assert!(data.breaches.is_empty(), "no `stealer:unknown` stand-in");
    assert_eq!(data.emails, ["kept@example.com"]);
}

#[test]
fn absent_stealer_facts_are_omitted_not_written_as_unknown() {
    let data = decode(
        "hudsonrock",
        r#"{"success":true,"data":{"stealers":[{"computer_name":"HOST-ONLY"}]}}"#,
    );
    let out = build_entities(&data, "q", "s");
    assert_eq!(
        out[0].evidence[0].summary,
        "Stealer hit: stealer:HOST-ONLY (path=hudsonrock)"
    );
    assert!(!out[0].evidence[0].summary.contains("unknown"));
}

#[test]
fn breach_evidence_text_keeps_the_full_spelling_when_populated() {
    let record = BreachRecord {
        name: "Corp".into(),
        date: Some("2021-02-03".into()),
        record_count: Some(1),
        detail: Some("path=osintcat".into()),
    };
    assert_eq!(
        breach_evidence_text("Corp", "breach:Corp", &record),
        "Breach: Corp (records: 1, date: 2021-02-03; path=osintcat)"
    );
    let bare = BreachRecord {
        name: "Bare".into(),
        date: None,
        record_count: None,
        detail: None,
    };
    assert_eq!(
        breach_evidence_text("Bare", "breach:Bare", &bare),
        "Breach: Bare"
    );
}

#[test]
fn merge_data_dedupes_across_paths_in_build_entities() {
    let snus = r#"{"success":true,"data":{"results":{"DB_A":[{"email":"alt@example.com","username":"shared_user"}]}}}"#;
    let osint = r#"{"success":true,"data":{"breach_data":[{"email":"alt@example.com","username":"shared_user","source":"DB_A"}]}}"#;
    let transport = Paths::ok(&[("snusbase", snus), ("osintcat", osint)]);
    let report = go(&transport, "seed@example.com").unwrap();
    let emails = report
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email)
        .count();
    assert_eq!(emails, 1);
    let marker = report
        .entities
        .iter()
        .find(|e| e.value == "breach:DB_A")
        .unwrap();
    // One entity, both observations kept as evidence.
    assert_eq!(
        report
            .entities
            .iter()
            .filter(|e| e.value == "breach:DB_A")
            .count(),
        1
    );
    assert_eq!(marker.evidence.len(), 2);
}

#[test]
fn a_failed_sibling_path_marks_a_non_empty_answer_partial() {
    let snus = r#"{"success":true,"data":{"results":{"DB_A":[{"email":"alt@example.com"}]}}}"#;
    let fail = r#"{"success":false,"error":"database temporarily unavailable"}"#;
    let transport = Paths::ok(&[("snusbase", snus), ("osintcat", fail)]);
    let report = go(&transport, "user@example.com").unwrap();
    assert_eq!(report.entities.len(), 2);
    assert_eq!(report.failed_paths.len(), 1);
    assert_eq!(report.failed_paths[0].path, "osintcat");
    assert_eq!(
        report.truncation.as_deref(),
        Some(
            "2 retrieved — stopped by the stolen.tax `osintcat` path(s) failing, and the provider did not report how many exist. Absence of a finding here is not evidence of absence."
        )
    );
}

#[test]
fn a_clean_or_empty_cascade_is_not_marked_partial() {
    let transport = Paths::ok(&[]);
    let report = go(&transport, "user@example.com").unwrap();
    assert_eq!(report.entities.len(), 0);
    assert!(report.truncation.is_none());
    assert_eq!(report.failed_paths.len(), 0);
}

#[test]
fn clear_email_login_skips_masked_and_empty() {
    assert_eq!(clear_email_login(" a@example.com "), Some("a@example.com"));
    assert_eq!(clear_email_login("a***@example.com"), None);
    assert_eq!(clear_email_login(""), None);
    assert_eq!(clear_email_login("not-an-email"), None);
}

#[test]
fn an_unknown_path_is_a_decode_failure() {
    assert!(normalize_path("nope", Value::Null).is_err());
}
