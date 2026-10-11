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
    let seen = transport.seen.borrow();
    assert!(seen.is_empty(), "{seen:?}");
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
    let mut budgeted = timed(&clock, &transport).unwrap();
    assert_eq!(transport.sent(), ["snusbase", "osintcat", "hudsonrock"]);
    assert_eq!(clock.elapsed(), Duration::from_secs(90));
    let mut plain = lookup(&Paths::ok(&answers), &keys(), "user@example.com", "scan", 0).unwrap();
    // These independent calls may cross a wall-clock second boundary.
    // Compare all report content while normalizing only recording timestamps.
    for report in [&mut budgeted, &mut plain] {
        for entity in &mut report.entities {
            entity.observed_at_unix = 0;
            for evidence in &mut entity.evidence {
                evidence.provenance.recorded_at_unix = 0;
            }
        }
    }
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
    let body = r#"{"success":true,"data":{"stealers":[{"computer_name":"DESKTOP-ABC","operating_system":"Windows 11","date_compromised":"2026-08-30T00:00:00.000Z","ip":"192.0.2.***","top_logins":["clear.user@example.com","m***d@example.com",""],"top_passwords":["PW_MUST_NOT_EMIT"]}]}}"#;
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
        "Stealer hit: stealer:DESKTOP-ABC (date: 2026-08-30T00:00:00.000Z; path=hudsonrock; os=Windows 11; ip=192.0.2.***)"
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

/// One scripted answer: delay in seconds, status, `Retry-After`, body.
type Step = (u64, u16, Option<&'static str>, &'static str);
/// Each path's steps, one per request (the last repeats).
type Steps = Vec<(&'static str, Vec<Step>)>;

/// Answers from a per-path script, one step per request (the last step repeats),
/// advancing a fake clock by each step's delay.
struct Script<'c> {
    clock: &'c FakeClock,
    steps: Steps,
    sent: RefCell<Vec<(String, Duration)>>,
}

impl<'c> Script<'c> {
    fn new(clock: &'c FakeClock, steps: Steps) -> Self {
        Self {
            clock,
            steps,
            sent: RefCell::new(Vec::new()),
        }
    }

    fn paths(&self) -> Vec<String> {
        self.sent.borrow().iter().map(|(p, _)| p.clone()).collect()
    }
}

impl Transport for Script<'_> {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        let path = request.url.rsplit_once("path=").map(|(_, p)| p).unwrap();
        let cap = request.timeout.expect("capped");
        assert!(!cap.is_zero());
        let n = self.sent.borrow().iter().filter(|(p, _)| p == path).count();
        self.sent.borrow_mut().push((path.to_owned(), cap));
        let (delay, status, retry_after, body) = self
            .steps
            .iter()
            .find(|(p, _)| *p == path)
            .map_or((0, 200, None, EMPTY), |(_, s)| s[n.min(s.len() - 1)]);
        self.clock.advance(Duration::from_secs(delay));
        Ok(Response {
            status,
            headers: retry_after
                .map(|v| vec![("Retry-After".to_owned(), v.to_owned())])
                .unwrap_or_default(),
            body: body.as_bytes().to_vec(),
            truncated: false,
        })
    }
}

fn scripted(clock: &FakeClock, t: &Script<'_>) -> Result<StolenTaxReport, StolenTaxError> {
    lookup_with_clock(t, clock, &keys(), "user@example.com", "scan", 0)
}

#[test]
fn retry_pause_reads_retry_after_like_the_monolith() {
    // parse_retry_after_secs(value, 4, 4): delta-seconds, else 4; never above 4.
    let secs = |v: Option<&str>| retry_pause(v).as_secs();
    assert_eq!(secs(None), 4);
    assert_eq!(secs(Some("0")), 0);
    assert_eq!(secs(Some("2")), 2);
    assert_eq!(secs(Some(" 3 ")), 3);
    assert_eq!(secs(Some("4")), 4);
    assert_eq!(secs(Some("30")), 4);
    assert_eq!(secs(Some("-1")), 4);
    assert_eq!(secs(Some("1.5")), 4);
    assert_eq!(secs(Some("Wed, 21 Oct 2015 07:28:00 GMT")), 4);
    assert_eq!(ATTEMPTS_PER_PATH, 3);
}

#[test]
fn a_429_is_retried_on_the_same_key_and_its_answer_kept() {
    let clock = FakeClock::new();
    let t = Script::new(
        &clock,
        vec![(
            "snusbase",
            vec![
                (1, 429, Some("2"), "rate limited"),
                (1, 429, Some("2"), "rate limited"),
                (1, 200, None, SNUS_HIT),
            ],
        )],
    );
    let report = scripted(&clock, &t).unwrap();
    assert_eq!(
        t.paths(),
        ["snusbase", "snusbase", "snusbase", "osintcat", "hudsonrock"]
    );
    // Three 1 s answers and two 2 s pauses on snusbase.
    assert_eq!(clock.elapsed(), Duration::from_secs(7));
    assert!(report.failed_paths.is_empty(), "{:?}", report.failed_paths);
    assert!(has(&report, &EntityKind::Email, "alt@example.com"));
    let caps: Vec<Duration> = t.sent.borrow().iter().map(|(_, c)| *c).collect();
    assert_eq!(
        caps[..3],
        [
            Duration::from_secs(120),
            Duration::from_secs(117),
            Duration::from_secs(114)
        ]
    );
}

#[test]
fn the_third_429_fails_the_path_after_capped_pauses() {
    let clock = FakeClock::new();
    let t = Script::new(
        &clock,
        vec![
            ("snusbase", vec![(0, 429, Some("30"), "rate limited")]),
            ("osintcat", vec![(0, 200, None, OSINT_HIT)]),
        ],
    );
    let report = scripted(&clock, &t).unwrap();
    assert_eq!(
        t.paths(),
        ["snusbase", "snusbase", "snusbase", "osintcat", "hudsonrock"]
    );
    // Retry-After: 30 is capped at 4 s, twice; no pause after the last attempt.
    assert_eq!(clock.elapsed(), Duration::from_secs(8));
    assert_eq!(report.failed_paths.len(), 1);
    assert_eq!(report.failed_paths[0].path, "snusbase");
    assert_eq!(
        report.failed_paths[0].reason,
        "HTTP 429 (RateLimited) after 3 attempts"
    );
}

#[test]
fn a_429_without_retry_after_pauses_four_seconds() {
    let clock = FakeClock::new();
    let t = Script::new(&clock, vec![("snusbase", vec![(0, 429, None, "")])]);
    let err = scripted(&clock, &t).unwrap_err();
    assert_eq!(clock.elapsed(), Duration::from_secs(8));
    assert!(matches!(err, StolenTaxError::Failed(ref f) if f.path == "snusbase"));
}

#[test]
fn a_retry_pause_never_outlasts_the_budget() {
    let clock = FakeClock::new();
    // snusbase rate-limits at 117 s: a 4 s pause would end past 120 s.
    let t = Script::new(
        &clock,
        vec![
            ("snusbase", vec![(117, 429, None, "rate limited")]),
            ("osintcat", vec![(1, 200, None, OSINT_HIT)]),
        ],
    );
    let report = scripted(&clock, &t).unwrap();
    assert_eq!(t.paths(), ["snusbase", "osintcat", "hudsonrock"]);
    assert_eq!(clock.elapsed(), Duration::from_secs(118));
    assert_eq!(
        report.failed_paths[0].reason,
        "HTTP 429 (RateLimited) after 1 of 3 attempts; a 4s Retry-After pause would outlast the 120s lookup budget"
    );
    let caps: Vec<Duration> = t.sent.borrow().iter().map(|(_, c)| *c).collect();
    assert_eq!(caps[1], Duration::from_secs(3));
}

#[test]
fn only_a_429_is_retried() {
    // The monolith's handle_keyed_error retries 429 alone; 503 with Retry-After,
    // 401, 403, 5xx and in-body key errors get one attempt (no other key to try).
    for (status, retry_after, body) in [
        (503, Some("0"), "busy"),
        (401, None, "Unauthorized"),
        (403, None, "Forbidden"),
        (502, None, "bad gateway"),
        (200, None, r#"{"success":false,"error":"Invalid API key"}"#),
    ] {
        let clock = FakeClock::new();
        let t = Script::new(
            &clock,
            vec![("snusbase", vec![(0, status, retry_after, body)])],
        );
        let _ = scripted(&clock, &t);
        assert_eq!(
            t.paths(),
            ["snusbase", "osintcat", "hudsonrock"],
            "{status}"
        );
        assert_eq!(clock.elapsed(), Duration::ZERO, "{status}");
    }
}

#[test]
fn a_transport_failure_is_not_retried() {
    let transport = Paths {
        answers: vec![("snusbase", Err(SourceOutcomeKind::ConnectFailure))],
        seen: RefCell::new(Vec::new()),
    };
    let _ = go(&transport, "user@example.com");
    let paths: Vec<String> = transport
        .seen
        .borrow()
        .iter()
        .map(|r| r.url.rsplit_once("path=").unwrap().1.to_owned())
        .collect();
    assert_eq!(paths, ["snusbase", "osintcat", "hudsonrock"]);
}

/// Real sockets, loopback only. Points the stolen.tax URLs at a local server; the
/// request (credential included) is built for `https://stolen.tax` as in production.
struct Loopback {
    inner: crate::http::UreqTransport,
    base: String,
}

impl Transport for Loopback {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        let mut local = request.clone();
        local.url = request.url.replacen("https://stolen.tax", &self.base, 1);
        assert_ne!(local.url, request.url, "only stolen.tax is rerouted");
        self.inner.send(&local)
    }
}

/// Chief's test for the redirect-hop fix, at the stolen.tax level: osintcat is a
/// slow redirect chain (every hop slower than the budget). The path stops at the
/// deadline with a timeout, hudsonrock is listed as not sent, snusbase's evidence
/// is kept, and the whole lookup ends within the budget plus a small tolerance.
/// stolen.tax sends with `max_redirects: 0`, so the chain's first hop is all it
/// ever requests.
#[test]
fn a_slow_redirect_chain_on_a_real_socket_stops_at_the_lookup_deadline() {
    use std::io::{Read as _, Write as _};
    use std::sync::{Arc, Mutex};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut sock) = stream else { continue };
            let log = log.clone();
            std::thread::spawn(move || {
                sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&buf).into_owned();
                let line = head.lines().next().unwrap_or_default().to_owned();
                let path = line
                    .split_once("path=")
                    .and_then(|(_, rest)| rest.split(['&', ' ']).next())
                    .unwrap_or_default()
                    .to_owned();
                log.lock().unwrap().push(path.clone());
                let reply = if path == "osintcat" {
                    std::thread::sleep(Duration::from_millis(2500));
                    "HTTP/1.1 302 Found\r\nLocation: /api/v2/index.php?path=osintcat&hop=1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned()
                } else {
                    std::thread::sleep(Duration::from_millis(100));
                    let body = if path == "snusbase" {
                        SNUS_HIT
                    } else {
                        HUDSON_HIT
                    };
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
                let _ = sock.write_all(reply.as_bytes());
            });
        }
    });

    let transport = Loopback {
        inner: crate::http::UreqTransport::new(&TransportConfig {
            egress: crate::egress::EgressPolicy::Unrestricted,
            ..transport_config()
        }),
        base: format!("http://127.0.0.1:{port}"),
    };
    let budget = Duration::from_millis(1200);
    let started = std::time::Instant::now();
    let report = lookup_within(
        &transport,
        &SystemClock,
        budget,
        &keys(),
        "user@example.com",
        "scan",
        0,
    )
    .unwrap();
    let elapsed = started.elapsed();
    assert!(
        elapsed <= budget + Duration::from_millis(500),
        "{elapsed:?}"
    );
    assert_eq!(*seen.lock().unwrap(), ["snusbase", "osintcat"]);
    assert!(has(&report, &EntityKind::Email, "alt@example.com"));
    assert_eq!(report.failed_paths.len(), 1);
    assert_eq!(report.failed_paths[0].path, "osintcat");
    let reason = &report.failed_paths[0].reason;
    assert!(
        reason.starts_with("no response (TtfbTimeout); request capped at "),
        "{reason}"
    );
    assert_eq!(report.skipped_paths, ["hudsonrock"]);
    assert!(
        report
            .truncation
            .as_deref()
            .is_some_and(|t| t.contains("`hudsonrock` path(s) not sent")),
        "{:?}",
        report.truncation
    );
}

/// A clock whose sleeps overrun by `extra`, as a real sleep can.
struct Overrun<'c> {
    clock: &'c FakeClock,
    extra: Duration,
}

impl Clock for Overrun<'_> {
    fn now(&self) -> std::time::Instant {
        self.clock.now()
    }

    fn sleep(&self, duration: Duration) {
        self.clock.advance(duration + self.extra);
    }
}

#[test]
fn a_retry_with_no_budget_left_is_not_sent_or_counted() {
    let clock = FakeClock::new();
    let over = Overrun {
        clock: &clock,
        extra: Duration::from_secs(1),
    };
    // A 3 s pause fits the 4 s left at 116 s, but the sleep overruns to 120 s.
    let t = Script::new(&clock, vec![("snusbase", vec![(116, 429, Some("3"), "")])]);
    let err = lookup_with_clock(&t, &over, &keys(), "user@example.com", "scan", 0).unwrap_err();
    assert_eq!(t.paths(), ["snusbase"]);
    assert_eq!(
        err,
        StolenTaxError::BudgetExhausted {
            skipped: vec!["osintcat", "hudsonrock"],
            failed: vec![PathFailure {
                path: "snusbase",
                reason: "HTTP 429 (RateLimited) after 1 of 3 attempts; the 120s lookup budget ran out before the next one".into(),
            }],
        }
    );
}

// ---- Redirects on real sockets, loopback only -------------------------------------
//
// Each origin a test uses (`https://stolen.tax:443`, `https://api.stolen.tax:443`,
// `https://evil.example:443`, ...) is its own local server. `Mapped` sits below the
// fetch layer: fetch decides on the real URLs (and `KEY_ORIGIN` is untouched), and
// only the socket goes to 127.0.0.1. Every server records every request head it got.

type Handler = dyn Fn(&str) -> (u64, String) + Send + Sync;

struct Origin {
    port: u16,
    heads: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl Origin {
    /// `answer(request target)` -> (delay in ms, raw HTTP response).
    fn serve(answer: Box<Handler>) -> Self {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let heads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = heads.clone();
        let answer: std::sync::Arc<Handler> = answer.into();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut sock) = stream else { continue };
                let (log, answer) = (log.clone(), answer.clone());
                std::thread::spawn(move || {
                    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match sock.read(&mut chunk) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let head = String::from_utf8_lossy(&buf).into_owned();
                    log.lock().unwrap().push(head.clone());
                    let target = head.split(' ').nth(1).unwrap_or_default().to_owned();
                    let (delay, reply) = answer(&target);
                    std::thread::sleep(Duration::from_millis(delay));
                    let _ = sock.write_all(reply.as_bytes());
                });
            }
        });
        Self { port, heads }
    }

    fn heads(&self) -> Vec<String> {
        self.heads.lock().unwrap().clone()
    }
}

fn json_reply(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn redirect_reply(to: &str) -> String {
    format!(
        "HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
}

/// The `path=` value of a request target.
fn v2_path(target: &str) -> &str {
    target
        .split_once("path=")
        .map_or("", |(_, rest)| rest.split('&').next().unwrap_or(""))
}

/// No credential of any kind in a request head: not ours, and none the transport
/// could mint (`Authorization: Basic` from userinfo).
fn keyless(head: &str) -> bool {
    !head.to_ascii_lowercase().contains("authorization:") && !head.contains(KEY)
}

fn carries_the_key(head: &str) -> bool {
    head.lines().any(|l| {
        l.split_once(':').is_some_and(|(k, v)| {
            k.eq_ignore_ascii_case("authorization") && v.trim() == format!("Bearer {KEY}")
        })
    })
}

struct Mapped {
    inner: crate::http::UreqTransport,
    map: Vec<(&'static str, u16)>,
}

impl Mapped {
    fn new(map: Vec<(&'static str, &Origin)>) -> Self {
        Self {
            inner: crate::http::UreqTransport::new(&TransportConfig {
                egress: crate::egress::EgressPolicy::Unrestricted,
                ..transport_config()
            }),
            map: map.into_iter().map(|(o, s)| (o, s.port)).collect(),
        }
    }
}

impl Transport for Mapped {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        let origin = crate::http::origin_of(&request.url).unwrap();
        let port = self
            .map
            .iter()
            .find(|(o, _)| *o == origin)
            .unwrap_or_else(|| panic!("no stand-in for {origin}"))
            .1;
        let rest = request.url.split_once("://").unwrap().1;
        let tail = &rest[rest.find(['/', '?']).unwrap_or(rest.len())..];
        let mut local = request.clone();
        local.url = format!("http://127.0.0.1:{port}{tail}");
        self.inner.send(&local)
    }
}

fn mapped_lookup(t: &Mapped, budget: Duration) -> Result<StolenTaxReport, StolenTaxError> {
    lookup_within(
        t,
        &SystemClock,
        budget,
        &keys(),
        "user@example.com",
        "scan",
        0,
    )
}

fn heads_for<'h>(heads: &'h [String], path: &str) -> Vec<&'h String> {
    heads
        .iter()
        .filter(|h| v2_path(h.split(' ').nth(1).unwrap_or_default()) == path)
        .collect()
}

/// Legacy parity: the monolith followed a same-site HTTPS redirect.
#[test]
fn redirect_same_site_https_hop_is_followed_and_its_evidence_kept() {
    let st = Origin::serve(Box::new(|t: &str| {
        match (v2_path(t), t.contains("moved=1")) {
            ("snusbase", false) => (0, redirect_reply("/api/v2/index.php?path=snusbase&moved=1")),
            ("snusbase", true) => (0, json_reply(SNUS_HIT)),
            _ => (0, json_reply(EMPTY)),
        }
    }));
    let t = Mapped::new(vec![("https://stolen.tax:443", &st)]);
    let report = mapped_lookup(&t, Duration::from_secs(10)).unwrap();
    assert!(report.failed_paths.is_empty(), "{:?}", report.failed_paths);
    assert!(has(&report, &EntityKind::Email, "alt@example.com"));
    let heads = st.heads();
    let snus = heads_for(&heads, "snusbase");
    assert_eq!(snus.len(), 2);
    assert!(snus[1].contains("moved=1"));
    // Same origin, exactly https://stolen.tax:443: the key goes on both hops.
    assert!(snus.iter().all(|h| carries_the_key(h)));
}

/// A same-site subdomain is followed (parity) but gets no key (tightening), and a
/// hop back to stolen.tax after leaving it does not get the key back either.
/// Userinfo in a followed Location is never sent (no `Authorization: Basic`).
#[test]
fn redirect_subdomain_hop_is_followed_without_the_key() {
    let st = Origin::serve(Box::new(|t: &str| {
        match (v2_path(t), t.contains("back=1")) {
            ("snusbase", false) => (
                0,
                redirect_reply("https://api.stolen.tax/v2/index.php?path=snusbase"),
            ),
            ("snusbase", true) => (0, json_reply(SNUS_HIT)),
            ("osintcat", _) => (
                0,
                redirect_reply("https://user:pw@www.stolen.tax/v2/index.php?path=osintcat"),
            ),
            _ => (0, json_reply(EMPTY)),
        }
    }));
    let api = Origin::serve(Box::new(|_: &str| {
        (
            0,
            redirect_reply("https://stolen.tax/api/v2/index.php?path=snusbase&back=1"),
        )
    }));
    let www = Origin::serve(Box::new(|_: &str| (0, json_reply(OSINT_HIT))));
    let t = Mapped::new(vec![
        ("https://stolen.tax:443", &st),
        ("https://api.stolen.tax:443", &api),
        ("https://www.stolen.tax:443", &www),
    ]);
    let report = mapped_lookup(&t, Duration::from_secs(10)).unwrap();
    assert!(report.failed_paths.is_empty(), "{:?}", report.failed_paths);
    assert!(has(&report, &EntityKind::Email, "alt@example.com"));
    assert!(
        report
            .entities
            .iter()
            .any(|e| e.kind == EntityKind::Username)
    );

    let api_heads = api.heads();
    assert_eq!(api_heads.len(), 1);
    assert!(keyless(&api_heads[0]), "{}", api_heads[0]);
    let st_heads = st.heads();
    let snus = heads_for(&st_heads, "snusbase");
    assert_eq!(snus.len(), 2);
    assert!(carries_the_key(snus[0]));
    assert!(
        snus[1].contains("back=1") && keyless(snus[1]),
        "{}",
        snus[1]
    );
    let www_heads = www.heads();
    assert_eq!(www_heads.len(), 1);
    assert!(keyless(&www_heads[0]), "{}", www_heads[0]);
}

/// `https://stolen.tax@evil.example/` and `https://stolen.tax:443@evil.example/` are
/// hosts `evil.example`: off-site, refused before any request, so the key cannot
/// reach it.
#[test]
fn redirect_userinfo_trick_is_another_host_and_never_gets_the_key() {
    let st = Origin::serve(Box::new(|t: &str| match v2_path(t) {
        "snusbase" => (0, redirect_reply("https://stolen.tax@evil.example/collect")),
        "osintcat" => (
            0,
            redirect_reply("https://stolen.tax:443@evil.example/collect"),
        ),
        _ => (0, json_reply(HUDSON_HIT)),
    }));
    let evil = Origin::serve(Box::new(|_: &str| (0, json_reply(SNUS_HIT))));
    let t = Mapped::new(vec![
        ("https://stolen.tax:443", &st),
        ("https://evil.example:443", &evil),
    ]);
    let report = mapped_lookup(&t, Duration::from_secs(10)).unwrap();
    assert!(evil.heads().is_empty(), "evil.example was contacted");
    let failed: Vec<(&str, &str)> = report
        .failed_paths
        .iter()
        .map(|f| (f.path, f.reason.as_str()))
        .collect();
    assert_eq!(
        failed,
        [
            (
                "snusbase",
                "HTTP 302 (RedirectChanged); redirect refused: off-site hop"
            ),
            (
                "osintcat",
                "HTTP 302 (RedirectChanged); redirect refused: off-site hop"
            ),
        ]
    );
    assert!(has(&report, &EntityKind::Credential, "stealer:HOST-1"));
}

/// The monolith's same-site rule ignores the port, so `https://stolen.tax:8443/` is
/// followed. It is not `KEY_ORIGIN`, so it gets no key.
#[test]
fn redirect_port_change_is_followed_without_the_key() {
    let st = Origin::serve(Box::new(|t: &str| match v2_path(t) {
        "snusbase" => (
            0,
            redirect_reply("https://stolen.tax:8443/api/v2/index.php?path=snusbase"),
        ),
        _ => (0, json_reply(EMPTY)),
    }));
    let other_port = Origin::serve(Box::new(|_: &str| (0, json_reply(SNUS_HIT))));
    let t = Mapped::new(vec![
        ("https://stolen.tax:443", &st),
        ("https://stolen.tax:8443", &other_port),
    ]);
    let report = mapped_lookup(&t, Duration::from_secs(10)).unwrap();
    assert!(report.failed_paths.is_empty(), "{:?}", report.failed_paths);
    assert!(has(&report, &EntityKind::Email, "alt@example.com"));
    let heads = other_port.heads();
    assert_eq!(heads.len(), 1);
    assert!(keyless(&heads[0]), "{}", heads[0]);
}

/// `https` to `http` is refused even on the same host, before anything is sent.
#[test]
fn redirect_http_downgrade_is_refused_before_any_request() {
    let st = Origin::serve(Box::new(|t: &str| match v2_path(t) {
        "snusbase" => (
            0,
            redirect_reply("http://stolen.tax/api/v2/index.php?path=snusbase"),
        ),
        _ => (0, json_reply(HUDSON_HIT)),
    }));
    let plain = Origin::serve(Box::new(|_: &str| (0, json_reply(SNUS_HIT))));
    let t = Mapped::new(vec![
        ("https://stolen.tax:443", &st),
        ("http://stolen.tax:80", &plain),
    ]);
    let report = mapped_lookup(&t, Duration::from_secs(10)).unwrap();
    assert!(plain.heads().is_empty(), "the http hop was requested");
    assert_eq!(report.failed_paths.len(), 1);
    assert_eq!(
        report.failed_paths[0].reason,
        "HTTP 302 (RedirectChanged); redirect refused: https to http downgrade"
    );
}

/// The monolith followed at most 9 hops (`MAX_REDIRECT_HOPS = 10` counted the
/// original request): 10 requests, then the path fails.
#[test]
fn redirect_chain_stops_at_the_monolith_hop_limit() {
    let st = Origin::serve(Box::new(|t: &str| match v2_path(t) {
        "snusbase" => {
            let hop: u32 = t
                .split_once("hop=")
                .map_or(0, |(_, n)| n.parse().unwrap_or(0));
            (
                0,
                redirect_reply(&format!("/api/v2/index.php?path=snusbase&hop={}", hop + 1)),
            )
        }
        _ => (0, json_reply(HUDSON_HIT)),
    }));
    let t = Mapped::new(vec![("https://stolen.tax:443", &st)]);
    let report = mapped_lookup(&t, Duration::from_secs(10)).unwrap();
    let heads = st.heads();
    assert_eq!(heads_for(&heads, "snusbase").len(), 10);
    assert_eq!(report.failed_paths.len(), 1);
    assert_eq!(
        report.failed_paths[0].reason,
        "HTTP 302 (RedirectChanged); redirect limit reached (9 followed)"
    );
}

/// A slow same-site chain is followed hop by hop, each hop capped by what is left
/// of the lookup budget, and stops at the deadline.
#[test]
fn redirect_slow_same_site_chain_stops_at_the_lookup_deadline() {
    let st = Origin::serve(Box::new(|t: &str| match v2_path(t) {
        "snusbase" => {
            let hop: u32 = t
                .split_once("hop=")
                .map_or(0, |(_, n)| n.parse().unwrap_or(0));
            (
                300,
                redirect_reply(&format!("/api/v2/index.php?path=snusbase&hop={}", hop + 1)),
            )
        }
        _ => (0, json_reply(EMPTY)),
    }));
    let t = Mapped::new(vec![("https://stolen.tax:443", &st)]);
    let budget = Duration::from_millis(1200);
    let started = std::time::Instant::now();
    let err = mapped_lookup(&t, budget).unwrap_err();
    let elapsed = started.elapsed();
    assert!(
        elapsed <= budget + Duration::from_millis(500),
        "{elapsed:?}"
    );
    let StolenTaxError::BudgetExhausted { skipped, failed } = &err else {
        panic!("{err:?}");
    };
    assert_eq!(skipped, &["osintcat", "hudsonrock"]);
    assert_eq!(failed.len(), 1);
    assert!(
        failed[0].reason.contains("TtfbTimeout"),
        "{}",
        failed[0].reason
    );
    assert!(heads_for(&st.heads(), "snusbase").len() >= 3);
}

#[test]
fn a_decode_error_names_its_category_and_position_never_the_body() {
    let marker = "QUOTED-MARKER-7f3a";
    for body in [
        format!(r#"{{"success":"{marker}"}}"#),
        format!(r#"{{"success":true,"data":null,"{marker}"#),
        format!("not json {marker}"),
    ] {
        let err = decode_path("snusbase", body.as_bytes()).unwrap_err();
        assert!(!err.contains(marker), "{err}");
        assert!(err.starts_with("could not decode response: "), "{err}");
        assert!(err.contains(" error at line 1 column "), "{err}");
    }
    let err = decode_path(
        "snusbase",
        format!(r#"{{"success":"{marker}"}}"#).as_bytes(),
    )
    .unwrap_err();
    assert_eq!(
        err,
        "could not decode response: data error at line 1 column 31"
    );
}

#[test]
fn a_long_provider_error_is_cut_to_120_chars() {
    let long = "é".repeat(10 * 1024);
    let body = serde_json::json!({"success": false, "error": long}).to_string();
    let err = decode_path("snusbase", body.as_bytes()).unwrap_err();
    let words = err
        .strip_prefix("success=false, provider reported failure: ")
        .unwrap();
    assert_eq!(words.chars().count(), 120);
    assert!(words.chars().all(|c| c == 'é'));

    let controls = serde_json::json!({"success": false, "error": "a\nb\u{1b}[31m"}).to_string();
    let err = decode_path("snusbase", controls.as_bytes()).unwrap_err();
    assert!(err.ends_with("a\u{fffd}b\u{fffd}[31m"), "{err:?}");
}

#[test]
fn the_key_is_scrubbed_from_a_provider_error_before_it_is_cut() {
    // The key straddles the 120-char cut: truncating first would leave a prefix of
    // it that no longer matches the scrubber.
    for lead in [0usize, 60, 110, 119] {
        let message = format!("{}{KEY}{}", "x".repeat(lead), "y".repeat(200));
        let body = serde_json::json!({"success": false, "error": message}).to_string();
        let t = Paths::ok(&[("snusbase", body.as_str())]);
        let err = go(&t, "user@example.com").unwrap_err();
        let StolenTaxError::Failed(first) = &err else {
            panic!("{err:?}");
        };
        let words = first
            .reason
            .strip_prefix("success=false, provider reported failure: ")
            .unwrap_or_else(|| panic!("{}", first.reason));
        let expected: String = scrub_secrets(&message, &[KEY]).chars().take(120).collect();
        assert_eq!(words, expected, "lead {lead}");
        for n in 6..=KEY.len() {
            assert!(
                !words.contains(&KEY[..n]),
                "lead {lead}: {n}-char key prefix kept"
            );
        }
    }
}
