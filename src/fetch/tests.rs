use std::cell::RefCell;
use std::collections::VecDeque;

use super::*;

/// A `MediaWiki` error code is carried only in its own shape: letters, digits, `_`, `-` and the
/// `\` of a namespaced exception, one to [`MEDIAWIKI_CODE_MAX`] of them.
#[test]
fn a_mediawiki_error_code_is_carried_only_in_its_own_shape() {
    let code = |raw: &str| mediawiki_error_code(&serde_json::json!({ "code": raw })).to_owned();
    for kept in [
        "baduser",
        "cirrussearch-too-busy-error",
        "internal_api_error_DBQueryError",
        "internal_api_error_MediaWiki\\Revision\\RevisionAccessException",
        "a2",
    ] {
        assert_eq!(code(kept), kept);
    }
    let longest = "x".repeat(MEDIAWIKI_CODE_MAX);
    assert_eq!(code(&longest), longest);
    for refused in [
        String::new(),
        "x".repeat(MEDIAWIKI_CODE_MAX + 1),
        "<script>".to_owned(),
        "bad user".to_owned(),
        "bad\nuser".to_owned(),
        "baduser\u{e9}".to_owned(),
    ] {
        assert_eq!(code(&refused), "unknown", "{refused:?}");
    }
    assert_eq!(mediawiki_error_code(&serde_json::json!({})), "unknown");
    assert_eq!(
        mediawiki_error_code(&serde_json::json!({ "code": 7 })),
        "unknown"
    );
}
use crate::circuit::BreakerState;
use crate::credential_origin::OperatorCredentialRef;
use crate::http::TransportFailure;

/// Scripted transport that records what it was asked to send.
struct Fake {
    script: RefCell<VecDeque<Result<Response, TransportFailure>>>,
    seen: RefCell<Vec<Request>>,
}

impl Fake {
    fn new(script: Vec<Result<Response, TransportFailure>>) -> Self {
        Self {
            script: RefCell::new(script.into()),
            seen: RefCell::default(),
        }
    }
}

impl Transport for Fake {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        self.seen.borrow_mut().push(request.clone());
        self.script
            .borrow_mut()
            .pop_front()
            .expect("script exhausted")
    }
}

fn resp(status: u16, headers: &[(&str, &str)], body: &str) -> Response {
    Response {
        status,
        headers: headers
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
        body: body.as_bytes().to_vec(),
        truncated: false,
    }
}

fn cred(secret: &str, style: AuthStyle) -> Credential {
    let authority = AuthenticationAuthority::operator_approved(OperatorCredentialRef {
        provider_id: "example".into(),
        credential_slot: "EXAMPLE_KEY".into(),
        approved_at_unix: 1,
        approval_provenance: "test".into(),
    })
    .expect("authority");
    Credential::new(authority, Secret::new(secret).expect("secret"), style).expect("cred")
}

fn run(f: &Fake, url: &str, c: Option<&Credential>, max: u32) -> Result<Fetched, Error> {
    fetch(
        f,
        Request::get(url),
        c,
        &FetchOptions {
            max_redirects: max,
            ..FetchOptions::default()
        },
        "t",
        100,
    )
}

#[test]
fn origin_change_drops_contact_user_agent_but_keeps_generic_agent() {
    let contact = Request::get("https://source.example/")
        .header("User-Agent", "Huntsman contact@research.example")
        .header("Accept", "application/json");
    let stripped = without_credentials(&contact);
    assert!(stripped.header_value("User-Agent").is_none());
    assert_eq!(stripped.header_value("Accept"), Some("application/json"));

    let generic = Request::get("https://source.example/")
        .header("User-Agent", crate::http::DEFAULT_USER_AGENT);
    assert_eq!(
        without_credentials(&generic).header_value("User-Agent"),
        Some(crate::http::DEFAULT_USER_AGENT)
    );
}

#[test]
fn ok_page_is_inconclusive_not_found() {
    let f = Fake::new(vec![Ok(resp(200, &[], "hello"))]);
    let r = run(&f, "https://a.example/x", None, 5).expect("fetch");
    assert_eq!(r.outcome.kind, SourceOutcomeKind::Inconclusive);
    assert_eq!(r.outcome.found, None);
    assert_eq!(r.outcome.http_status, Some(200));
    assert!(r.credential_sent.is_none());
}

#[test]
fn challenge_page_is_a_waf_even_at_200() {
    let f = Fake::new(vec![Ok(resp(
        200,
        &[],
        "<html><title>Just a moment...</title>Cloudflare</html>",
    ))]);
    let r = run(&f, "https://a.example/", None, 0).expect("fetch");
    assert_eq!(r.outcome.kind, SourceOutcomeKind::BotWaf);
}

/// A profile site that embeds a CAPTCHA widget, or a bot-management sensor, on every page
/// answers 200 with content. Counting those as walls dropped every result and, after five,
/// opened the host's circuit for a minute.
#[test]
fn served_pages_with_a_widget_are_content_and_keep_the_host_circuit_closed() {
    use crate::circuit::{BreakerState, FAILURE_THRESHOLD, host_state};
    let page = "<html><script src=\"https://www.google.com/recaptcha/api.js\"></script><div class=\"g-recaptcha\"></div><h1>Jane Doe</h1></html>";
    let host = "widget-on-every-page.example";
    for _ in 0..FAILURE_THRESHOLD {
        let f = Fake::new(vec![Ok(resp(200, &[], page))]);
        let r = run(&f, &format!("https://{host}/profile"), None, 0).expect("fetch");
        assert_eq!(r.outcome.kind, SourceOutcomeKind::Inconclusive);
    }
    assert_ne!(host_state(host), Some(BreakerState::Open));
}

/// GitHub's documented rate-limit answers, which any provider sending the same headers gives:
/// a 403 or 429 with `retry-after` is a pause of that many seconds, and one with
/// `x-ratelimit-remaining: 0` a pause until `x-ratelimit-reset` (UTC epoch seconds). A 403
/// without either stays a refusal, and a challenge page stays a wall.
#[test]
fn an_exhausted_quota_is_a_rate_limit_until_its_reset() {
    use SourceOutcomeKind as K;
    let at = |status, headers: &[(&str, &str)], body: &str| {
        let f = Fake::new(vec![Ok(resp(status, headers, body))]);
        let r = fetch(
            &f,
            Request::get("https://quota.example/"),
            None,
            &FetchOptions::default(),
            "t",
            1_000,
        )
        .expect("fetch");
        (r.outcome.kind, r.outcome.retry_after_secs)
    };
    let exhausted = [
        ("x-ratelimit-remaining", "0"),
        ("x-ratelimit-reset", "1120"),
    ];
    assert_eq!(at(403, &exhausted, "{}"), (K::RateLimited, Some(120)));
    assert_eq!(at(429, &exhausted, "{}"), (K::RateLimited, Some(120)));
    assert_eq!(
        at(403, &[("retry-after", "45")], "{}"),
        (K::RateLimited, Some(45))
    );
    // `retry-after` is the documented first rule; it wins over the reset time.
    let both = [
        ("retry-after", "45"),
        ("x-ratelimit-remaining", "0"),
        ("x-ratelimit-reset", "1120"),
    ];
    assert_eq!(at(403, &both, "{}"), (K::RateLimited, Some(45)));
    // A reset already past is no pause; one far off is capped like any other.
    let past = [("x-ratelimit-remaining", "0"), ("x-ratelimit-reset", "900")];
    assert_eq!(at(403, &past, "{}"), (K::RateLimited, Some(0)));
    let far = [
        ("x-ratelimit-remaining", "0"),
        ("x-ratelimit-reset", "99999999"),
    ];
    assert_eq!(at(403, &far, "{}"), (K::RateLimited, Some(3600)));
    // Without a reset time the quota is still exhausted, for an unknown time.
    assert_eq!(
        at(403, &[("x-ratelimit-remaining", "0")], "{}"),
        (K::RateLimited, None)
    );
    // Quota left, or no rate-limit header at all, is a refusal: of the request, since it
    // carried no credential to reject.
    let left = [
        ("x-ratelimit-remaining", "12"),
        ("x-ratelimit-reset", "1120"),
    ];
    assert_eq!(at(403, &left, "{}"), (K::Upstream4xx, None));
    assert_eq!(at(403, &[], "{}"), (K::Upstream4xx, None));
    // GitHub's secondary limit says so only in its message, with quota left and no pause.
    let secondary = r#"{"message":"You have exceeded a secondary rate limit. Please wait a few minutes before you try again."}"#;
    assert_eq!(at(403, &left, secondary), (K::RateLimited, None));
    assert_eq!(
        at(
            403,
            &[],
            r#"{"message":"API rate limit exceeded for 192.0.2.1."}"#
        ),
        (K::RateLimited, None)
    );
    assert_eq!(
        at(403, &[], r#"{"message":"Resource not accessible"}"#),
        (K::Upstream4xx, None)
    );
    // A challenge page is a wall whatever its headers say.
    let challenge = "<html><title>Just a moment...</title>Cloudflare</html>";
    assert_eq!(at(403, &exhausted, challenge), (K::BotWaf, None));
    // Other statuses keep their own meaning; a 503 keeps the pause it asks for.
    assert_eq!(at(200, &exhausted, "{}"), (K::Inconclusive, None));
    assert_eq!(
        at(503, &[("retry-after", "30")], "{}"),
        (K::Upstream5xx, Some(30))
    );
    assert_eq!(at(404, &exhausted, "{}"), (K::Upstream4xx, None));
}

/// Only a sent credential can be rejected. A 403 to a request that carried one is
/// `AuthRejected`; the same 403 to a request that carried none is the provider refusing the
/// request (a geo-block, an address ban, a proxy's policy), never a rejected key that does
/// not exist.
#[test]
fn a_403_rejects_a_credential_only_when_one_was_sent() {
    let policy = r#"{"message":"This API path is not available: sessions are bound to their configured repositories"}"#;
    let refused = |credential: Option<&Credential>| {
        let f = Fake::new(vec![Ok(resp(403, &[], policy))]);
        let fetched =
            run(&f, "https://api.example.com/users/octocat", credential, 0).expect("fetch");
        (fetched.outcome.kind, fetched.outcome.http_status)
    };
    assert_eq!(refused(None), (SourceOutcomeKind::Upstream4xx, Some(403)));
    let key = cred("sk_live_0123456789abcdef", AuthStyle::Bearer);
    assert_eq!(
        refused(Some(&key)),
        (SourceOutcomeKind::AuthRejected, Some(403))
    );
}

/// A paced fetch that meets an exhausted quota stops every caller sending to that host until
/// the reset, and only that host.
#[test]
fn an_exhausted_quota_paces_its_host_until_the_reset_and_no_other() {
    let host = "paced-quota.invalid";
    let url = format!("https://{host}/users/a");
    let exhausted = resp(
        403,
        &[
            ("x-ratelimit-remaining", "0"),
            ("x-ratelimit-reset", "5120"),
        ],
        "{}",
    );
    let f = Fake::new(vec![Ok(exhausted)]);
    let r = fetch(&f, Request::get(&url), None, &paced(0), "t", 5_000).expect("fetch");
    assert_eq!(r.outcome.kind, SourceOutcomeKind::RateLimited);
    assert_eq!(crate::circuit::host_state(host), Some(BreakerState::Open));

    let empty = Fake::new(vec![]);
    let held = fetch(&empty, Request::get(&url), None, &paced(0), "t", 5_119).expect("fetch");
    assert!(held.response.is_none());
    assert!(empty.seen.borrow().is_empty(), "sent before the reset");

    let other = Fake::new(vec![Ok(resp(200, &[], "{}"))]);
    let elsewhere = fetch(
        &other,
        Request::get("https://paced-quota-other.invalid/users/a"),
        None,
        &paced(0),
        "t",
        5_119,
    )
    .expect("fetch");
    assert_eq!(other.seen.borrow().len(), 1, "an unrelated host was held");
    assert!(elsewhere.response.is_some());

    let after = Fake::new(vec![Ok(resp(200, &[], "{}"))]);
    let resumed = fetch(&after, Request::get(&url), None, &paced(0), "t", 5_120).expect("fetch");
    assert_eq!(after.seen.borrow().len(), 1, "not sent after the reset");
    assert!(resumed.response.is_some());
}

#[test]
fn rate_limit_carries_a_bounded_retry_after() {
    let f = Fake::new(vec![Ok(resp(429, &[("retry-after", "120")], ""))]);
    assert_eq!(
        run(&f, "https://a.example/", None, 0)
            .expect("f")
            .outcome
            .retry_after_secs,
        Some(120)
    );
    let f = Fake::new(vec![Ok(resp(429, &[("retry-after", "999999")], ""))]);
    assert_eq!(
        run(&f, "https://a.example/", None, 0)
            .expect("f")
            .outcome
            .retry_after_secs,
        Some(3600)
    );
    let f = Fake::new(vec![Ok(resp(
        429,
        &[("retry-after", "Wed, 21 Oct 2026 07:28:00 GMT")],
        "",
    ))]);
    let at = fetch(
        &f,
        Request::get("https://a.example/"),
        None,
        &FetchOptions::default(),
        "t",
        1_792_567_600,
    );
    assert_eq!(at.expect("f").outcome.retry_after_secs, Some(80));
    let f = Fake::new(vec![Ok(resp(429, &[("retry-after", "soon")], ""))]);
    assert_eq!(
        run(&f, "https://a.example/", None, 0)
            .expect("f")
            .outcome
            .retry_after_secs,
        None
    );
}

#[test]
fn transport_failures_keep_their_cause() {
    for kind in [
        SourceOutcomeKind::DnsFailure,
        SourceOutcomeKind::TlsFailure,
        SourceOutcomeKind::TtfbTimeout,
    ] {
        let f = Fake::new(vec![Err(TransportFailure {
            kind,
            detail: "x".into(),
            blocked: false,
        })]);
        let r = run(&f, "https://a.example/", None, 0).expect("fetch");
        assert_eq!(r.outcome.kind, kind);
        assert!(r.response.is_none());
        assert!(r.outcome.kind.is_transport_failure());
    }
}

#[test]
fn blocked_egress_is_an_error_not_an_outcome() {
    let f = Fake::new(vec![Err(TransportFailure {
        kind: SourceOutcomeKind::ConnectFailure,
        detail: "egress-policy: destination (10.0.0.1) is not publicly routable".into(),
        blocked: true,
    })]);
    let err = run(&f, "https://a.example/", None, 0).expect_err("blocked");
    assert!(matches!(err, Error::Network(m) if m.contains("egress-policy")));
}

#[test]
fn non_http_urls_never_reach_the_transport() {
    let f = Fake::new(vec![]);
    for u in ["file:///etc/passwd", "ftp://a/", "/relative", ""] {
        assert!(run(&f, u, None, 0).is_err(), "{u}");
    }
    let seen = f.seen.borrow();
    assert!(seen.is_empty(), "{seen:?}");
}

#[test]
fn bearer_is_sent_to_its_origin_and_recorded_by_fingerprint() {
    let c = cred("tok-abcdef-123456", AuthStyle::Bearer);
    let f = Fake::new(vec![Ok(resp(200, &[], "{}"))]);
    let r = run(&f, "https://a.example/api", Some(&c), 5).expect("fetch");
    assert_eq!(
        f.seen.borrow()[0].header_value("authorization"),
        Some("Bearer tok-abcdef-123456")
    );
    assert_eq!(r.credential_sent, Some(c.fingerprint()));
    assert!(!format!("{r:?}").contains("tok-abcdef"));
}

#[test]
fn a_query_key_is_added_on_send_and_never_follows_a_redirect_off_origin() {
    let c = cred("tok/abc+def 123", AuthStyle::Query("key".into()));
    let f = Fake::new(vec![
        Ok(resp(
            302,
            &[("location", "https://evil.example/steal?x=1")],
            "",
        )),
        Ok(resp(200, &[], "")),
    ]);
    // A caller-set `key=` is replaced, never sent alongside the operator's key.
    let r = run(
        &f,
        "https://a.example/q?ip=1.2.3.4&key=planted",
        Some(&c),
        1,
    )
    .expect("fetch");
    let seen = f.seen.borrow();
    assert_eq!(
        seen[0].url,
        "https://a.example/q?ip=1.2.3.4&key=tok%2Fabc%2Bdef+123"
    );
    assert_eq!(seen[1].url, "https://evil.example/steal?x=1");
    assert!(!r.final_url.contains("tok"), "{}", r.final_url);
    assert!(
        Credential::new(
            AuthenticationAuthority::operator_approved(OperatorCredentialRef {
                provider_id: "p".into(),
                credential_slot: "P_KEY".into(),
                approved_at_unix: 1,
                approval_provenance: "t".into(),
            })
            .expect("authority"),
            Secret::new("tok-abcdef-123456").expect("s"),
            AuthStyle::Query("k&x=".into()),
        )
        .is_err()
    );
}

#[test]
fn a_query_key_is_scrubbed_from_transport_diagnostics_in_both_forms() {
    let c = cred("tok/abc+def 123", AuthStyle::Query("key".into()));
    let f = Fake::new(vec![Err(TransportFailure {
        kind: SourceOutcomeKind::ConnectFailure,
        detail: "failed https://a.example/q?key=tok%2Fabc%2Bdef+123 (tok/abc+def 123)".into(),
        blocked: false,
    })]);
    let r = run(&f, "https://a.example/q", Some(&c), 0).expect("fetch");
    let detail = r.outcome.detail.unwrap_or_default();
    assert!(
        !detail.contains("tok%2Fabc") && !detail.contains("tok/abc"),
        "the outcome detail kept the key, encoded or decoded"
    );
}

#[test]
fn without_query_param_keeps_every_other_parameter() {
    assert_eq!(
        without_query_param("https://h/p?a=1&key=s&b=2#f", "key"),
        "https://h/p?a=1&b=2#f"
    );
    assert_eq!(
        without_query_param("https://h/p?key=s", "key"),
        "https://h/p"
    );
    assert_eq!(
        without_query_param("https://h/p?keys=1", "key"),
        "https://h/p?keys=1"
    );
    assert_eq!(without_query_param("https://h/p", "key"), "https://h/p");
}

#[test]
fn custom_header_style_and_validation() {
    let c = cred("tok-abcdef-123456", AuthStyle::Header("X-Api-Key".into()));
    let f = Fake::new(vec![Ok(resp(200, &[], ""))]);
    run(&f, "https://a.example/", Some(&c), 0).expect("fetch");
    assert_eq!(
        f.seen.borrow()[0].header_value("x-api-key"),
        Some("tok-abcdef-123456")
    );
    let authority = AuthenticationAuthority::operator_approved(OperatorCredentialRef {
        provider_id: "p".into(),
        credential_slot: "P_KEY".into(),
        approved_at_unix: 1,
        approval_provenance: "t".into(),
    })
    .expect("authority");
    let bad = Credential::new(
        authority,
        Secret::new("tok-abcdef-123456").expect("s"),
        AuthStyle::Header("X: y\r\nZ".into()),
    );
    assert!(bad.is_err());
}

#[test]
fn basic_style_sends_the_encoded_pair_and_strips_it_off_origin() {
    let c = cred("wigle-user:tok-abcdef-123456", AuthStyle::Basic);
    let f = Fake::new(vec![
        Ok(resp(302, &[("location", "https://evil.example/steal")], "")),
        Ok(resp(200, &[], "")),
    ]);
    let r = run(&f, "https://a.example/api", Some(&c), 5).expect("fetch");
    let seen = f.seen.borrow();
    assert_eq!(
        seen[0].header_value("authorization"),
        Some("Basic d2lnbGUtdXNlcjp0b2stYWJjZGVmLTEyMzQ1Ng==")
    );
    assert!(seen[1].header_value("authorization").is_none());
    assert!(!format!("{r:?}").contains("d2lnbGUtdXNlcjp0b2st"));
}

#[test]
fn credential_is_stripped_when_a_redirect_leaves_the_origin() {
    let c = cred("tok-abcdef-123456", AuthStyle::Bearer);
    let f = Fake::new(vec![
        Ok(resp(302, &[("location", "https://evil.example/steal")], "")),
        Ok(resp(200, &[], "")),
    ]);
    let r = run(&f, "https://a.example/api", Some(&c), 5).expect("fetch");
    let seen = f.seen.borrow();
    assert!(seen[0].header_value("authorization").is_some());
    assert!(
        seen[1].header_value("authorization").is_none(),
        "leaked across origins"
    );
    assert_eq!(seen[1].url, "https://evil.example/steal");
    assert!(r.credential_sent.is_none());
    assert_eq!(r.redirects, 1);
}

#[test]
fn https_to_http_downgrade_on_the_same_host_loses_the_credential() {
    let c = cred("tok-abcdef-123456", AuthStyle::Bearer);
    let f = Fake::new(vec![
        Ok(resp(301, &[("location", "http://a.example/api")], "")),
        Ok(resp(200, &[], "")),
    ]);
    run(&f, "https://a.example/api", Some(&c), 5).expect("fetch");
    assert!(f.seen.borrow()[1].header_value("authorization").is_none());
}

#[test]
fn same_origin_redirect_keeps_the_credential() {
    let c = cred("tok-abcdef-123456", AuthStyle::Bearer);
    let f = Fake::new(vec![
        Ok(resp(307, &[("location", "/v2/api")], "")),
        Ok(resp(200, &[], "")),
    ]);
    let r = run(&f, "https://a.example/v1/api", Some(&c), 5).expect("fetch");
    assert!(f.seen.borrow()[1].header_value("authorization").is_some());
    assert_eq!(r.final_url, "https://a.example/v2/api");
}

#[test]
fn query_only_redirect_keeps_the_page_and_same_origin_credential() {
    let credential = cred("tok-fixture-123456", AuthStyle::Bearer);
    let transport = Fake::new(vec![
        Ok(resp(302, &[("location", "?page=2")], "")),
        Ok(resp(200, &[], "second page")),
    ]);
    let result = run(
        &transport,
        "https://a.example/v1/search?page=1",
        Some(&credential),
        5,
    )
    .expect("fetch");
    assert_eq!(result.final_url, "https://a.example/v1/search?[redacted]");
    let seen = transport.seen.borrow();
    assert_eq!(seen[1].url, "https://a.example/v1/search?page=2");
    assert!(seen[1].header_value("authorization").is_some());
}

#[test]
fn caller_supplied_sensitive_headers_also_do_not_cross_origins() {
    let f = Fake::new(vec![
        Ok(resp(302, &[("location", "https://b.example/")], "")),
        Ok(resp(200, &[], "")),
    ]);
    let req = Request::get("https://a.example/")
        .header("Cookie", "sid=1")
        .header("Accept", "*/*");
    fetch(&f, req, None, &FetchOptions::default(), "t", 1).expect("fetch");
    let seen = f.seen.borrow();
    assert!(seen[0].header_value("cookie").is_some());
    assert!(seen[1].header_value("cookie").is_none());
    assert_eq!(seen[1].header_value("accept"), Some("*/*"));
}

#[test]
fn redirect_loops_stop_at_the_limit_and_say_so() {
    let hop = || Ok(resp(302, &[("location", "/again")], ""));
    let f = Fake::new((0..10).map(|_| hop()).collect());
    let r = run(&f, "https://a.example/", None, 3).expect("fetch");
    assert_eq!(r.redirects, 3);
    assert_eq!(f.seen.borrow().len(), 4);
    assert_eq!(r.outcome.kind, SourceOutcomeKind::RedirectChanged);
    assert!(
        r.outcome
            .detail
            .as_deref()
            .is_some_and(|d| d.contains("redirect limit"))
    );
}

#[test]
fn redirects_disabled_report_a_changed_contract() {
    let f = Fake::new(vec![Ok(resp(
        301,
        &[("location", "https://b.example/")],
        "",
    ))]);
    let r = run(&f, "https://a.example/", None, 0).expect("fetch");
    assert_eq!(r.outcome.kind, SourceOutcomeKind::RedirectChanged);
    assert_eq!(f.seen.borrow().len(), 1);
}

#[test]
fn redirect_to_a_non_http_scheme_keeps_the_3xx_as_the_answer() {
    // An unfollowable Location is not a request refused before sending: the 3xx was received,
    // so it is the answer (classified `RedirectChanged`) with the refused redirect recorded —
    // never an error a caller would read as "nothing reached the network". The target is still
    // not fetched.
    let f = Fake::new(vec![Ok(resp(
        302,
        &[("location", "file:///etc/passwd")],
        "",
    ))]);
    let r = run(&f, "https://a.example/", None, 5).expect("the 3xx is the answer, not an error");
    assert_eq!(r.outcome.kind, SourceOutcomeKind::RedirectChanged);
    assert!(r.response.is_some(), "the 302 response is kept");
    assert!(
        r.redirect_refused.is_some(),
        "the unusable redirect is recorded: {:?}",
        r.redirect_refused
    );
    assert_eq!(f.seen.borrow().len(), 1);
}

#[test]
fn a_post_becomes_a_bodyless_get_on_303() {
    let f = Fake::new(vec![
        Ok(resp(303, &[("location", "/done")], "")),
        Ok(resp(200, &[], "")),
    ]);
    let req = Request::post("https://a.example/submit", b"data".to_vec())
        .header("Content-Type", "text/plain");
    fetch(&f, req, None, &FetchOptions::default(), "t", 1).expect("fetch");
    let seen = f.seen.borrow();
    assert_eq!(seen[1].method, Method::Get);
    assert!(seen[1].body.is_empty() && seen[1].header_value("content-type").is_none());
}

#[test]
fn a_307_keeps_method_and_body() {
    let f = Fake::new(vec![
        Ok(resp(307, &[("location", "/again")], "")),
        Ok(resp(200, &[], "")),
    ]);
    fetch(
        &f,
        Request::post("https://a.example/s", b"data".to_vec()),
        None,
        &FetchOptions::default(),
        "t",
        1,
    )
    .expect("fetch");
    let seen = f.seen.borrow();
    assert_eq!(
        (seen[1].method, seen[1].body.as_slice()),
        (Method::Post, &b"data"[..])
    );
}

#[test]
fn cross_origin_307_and_308_never_forward_post_bodies() {
    for status in [307, 308] {
        let f = Fake::new(vec![
            Ok(resp(
                status,
                &[("location", "https://other.example/collect")],
                "",
            )),
            Ok(resp(200, &[], "")),
        ]);
        let body = b"private-form-data".to_vec();
        let result = fetch(
            &f,
            Request::post("https://api.example/submit", body.clone()),
            Some(&cred("tok-abcdef-123456", AuthStyle::Bearer)),
            &FetchOptions::default(),
            "t",
            1,
        )
        .expect("a refused redirect preserves the original response");

        assert_eq!(
            f.seen.borrow().len(),
            1,
            "{status}: body sent to redirect target"
        );
        assert_eq!(f.seen.borrow()[0].body, body);
        assert_eq!(result.response.as_ref().map(|r| r.status), Some(status));
        assert_eq!(result.outcome.kind, SourceOutcomeKind::RedirectChanged);
        assert_eq!(
            result.redirect_refused,
            Some("redirect refused: request body would cross origin")
        );
    }
}

#[test]
fn https_to_http_307_cannot_downgrade_a_post_body() {
    let f = Fake::new(vec![
        Ok(resp(307, &[("location", "http://api.example/receive")], "")),
        Ok(resp(200, &[], "")),
    ]);
    let result = fetch(
        &f,
        Request::post("https://api.example/submit", b"private-form-data".to_vec()),
        None,
        &FetchOptions::default(),
        "t",
        1,
    )
    .expect("a refused redirect preserves the original response");
    assert_eq!(f.seen.borrow().len(), 1);
    assert_eq!(result.response.as_ref().map(|r| r.status), Some(307));
    assert!(result.redirect_refused.is_some());
}

#[test]
fn cross_origin_303_is_followed_without_the_post_body() {
    let f = Fake::new(vec![
        Ok(resp(303, &[("location", "https://other.example/done")], "")),
        Ok(resp(200, &[], "")),
    ]);
    let result = fetch(
        &f,
        Request::post("https://api.example/submit", b"private-form-data".to_vec()),
        None,
        &FetchOptions::default(),
        "t",
        1,
    )
    .expect("a bodyless redirect follows");
    let seen = f.seen.borrow();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[1].method, Method::Get);
    assert!(seen[1].body.is_empty());
    assert!(result.redirect_refused.is_none());
}

#[test]
fn rejected_credential_is_distinguished_from_a_missing_one() {
    let f = Fake::new(vec![Ok(resp(401, &[], "no"))]);
    let anon = run(&f, "https://a.example/", None, 0).expect("fetch");
    assert_eq!(anon.outcome.kind, SourceOutcomeKind::AuthRequired);
    let c = cred("tok-abcdef-123456", AuthStyle::Bearer);
    let f = Fake::new(vec![Ok(resp(401, &[], "no"))]);
    let sent = run(&f, "https://a.example/", Some(&c), 0).expect("fetch");
    assert_eq!(sent.outcome.kind, SourceOutcomeKind::AuthRejected);
}

/// What a source reading `sent` through `whole_response`, `answer` and `decode_json` records:
/// the decoded document's id, or the kind, status and pause of the first gate that refused it.
/// Whatever refused it, the outcome quotes no word of the body.
fn through_the_gates(
    sent: Result<Response, TransportFailure>,
    credential: Option<&Credential>,
) -> Result<u64, (SourceOutcomeKind, Option<u16>, Option<u64>)> {
    #[derive(Debug, serde::Deserialize)]
    struct Doc {
        id: u64,
    }
    let f = Fake::new(vec![sent]);
    let fetched = run(&f, "https://a.example/", credential, 0).expect("fetch");
    if let Some(response) = &fetched.response {
        // The kind the gates read is the one each source classified for itself from the
        // lossy text, but for a rejected key.
        let own = match classify_fetch(response.status, &response.text()) {
            SourceOutcomeKind::AuthRequired if credential.is_some() => {
                SourceOutcomeKind::AuthRejected
            }
            SourceOutcomeKind::Upstream4xx if response.status == 403 && credential.is_some() => {
                SourceOutcomeKind::AuthRejected
            }
            own => own,
        };
        assert_eq!(fetched.outcome.kind, own);
    }
    let read = whole_response(&fetched, "Example").and_then(|response| {
        answer(&fetched, "Example")?;
        decode_json::<Doc>(response, "t", 100, "Example")
    });
    read.map(|doc| doc.id).map_err(|outcome| {
        assert_eq!((outcome.module.as_str(), outcome.found), ("t", None));
        let detail = outcome.detail.clone().unwrap_or_default();
        assert!(!detail.contains("secret"), "{detail}");
        (outcome.kind, outcome.http_status, outcome.retry_after_secs)
    })
}

#[test]
fn the_response_gates_pass_only_a_whole_answer_and_never_quote_the_body() {
    use SourceOutcomeKind as K;
    let key = cred("tok-abcdef-123456", AuthStyle::Bearer);
    let challenge = "<html><title>Just a moment...</title>Cloudflare secret@example.com</html>";
    let timeout = TransportFailure {
        kind: K::TtfbTimeout,
        detail: "timed out".into(),
        blocked: false,
    };
    assert_eq!(
        through_the_gates(Err(timeout), None),
        Err((K::TtfbTimeout, None, None))
    );
    let limited = resp(429, &[("retry-after", "30")], "{}");
    assert_eq!(
        through_the_gates(Ok(limited), None),
        Err((K::RateLimited, Some(429), Some(30)))
    );
    assert_eq!(
        through_the_gates(Ok(resp(403, &[], challenge)), None),
        Err((K::BotWaf, Some(403), None))
    );
    let mut lossy = resp(403, &[], "");
    lossy.body = [b"\xff\xfe".as_slice(), challenge.as_bytes()].concat();
    assert_eq!(
        through_the_gates(Ok(lossy), None),
        Err((K::BotWaf, Some(403), None))
    );
    assert_eq!(
        through_the_gates(Ok(resp(401, &[], "{}")), None),
        Err((K::AuthRequired, Some(401), None))
    );
    assert_eq!(
        through_the_gates(Ok(resp(401, &[], "{}")), Some(&key)),
        Err((K::AuthRejected, Some(401), None))
    );
    let mut cut = resp(200, &[], r#"{"id":7,"secret@example.com""#);
    cut.truncated = true;
    assert_eq!(
        through_the_gates(Ok(cut), None),
        Err((K::ParserDrift, Some(200), None))
    );
    assert_eq!(
        through_the_gates(Ok(resp(503, &[], "{}")), None),
        Err((K::Upstream5xx, Some(503), None))
    );
    assert_eq!(
        through_the_gates(Ok(resp(200, &[], r#"{"id":7}"#)), None),
        Ok(7)
    );
    for body in ["secret@example.com", r#"{"id":"secret@example.com"}"#] {
        assert_eq!(
            through_the_gates(Ok(resp(200, &[], body)), None),
            Err((K::ParserDrift, Some(200), None)),
            "{body}"
        );
    }
}

/// With no response `answer` has nothing to read, so the outcome `fetch` gave the request is
/// the one recorded, whatever its kind. An open circuit's `Inconclusive` is the case that would
/// read as an answer if `answer` judged the kind alone.
#[test]
fn answer_without_a_response_returns_the_fetch_outcome_unchanged() {
    let f = Fake::new(vec![Err(TransportFailure {
        kind: SourceOutcomeKind::TtfbTimeout,
        detail: "timed out".into(),
        blocked: false,
    })]);
    let timed_out = run(&f, "https://a.example/", None, 0).expect("fetch");
    let held = suppressed("t", 100, "https://a.example/");
    for fetched in [timed_out, held] {
        assert!(fetched.response.is_none());
        let err = answer(&fetched, "Example").expect_err("no response is no answer");
        assert_eq!(err, fetched.outcome);
    }
}

#[test]
fn a_decode_error_names_its_category_and_position_only() {
    let Err(error) = serde_json::from_str::<u64>("\"secret@example.com\"") else {
        panic!("a string is not a number");
    };
    assert_eq!(json_error_detail(&error), "data error at line 1 column 20");
    let Err(error) = serde_json::from_str::<serde_json::Value>("[1,") else {
        panic!("an unclosed array is not a document");
    };
    assert_eq!(json_error_detail(&error), "eof error at line 1 column 3");
}

#[test]
fn echoed_credentials_do_not_survive_into_diagnostics() {
    let c = cred("tok-abcdef-123456", AuthStyle::Bearer);
    let f = Fake::new(vec![Err(TransportFailure {
        kind: SourceOutcomeKind::ConnectFailure,
        detail: "proxy said: bad Bearer tok-abcdef-123456".into(),
        blocked: false,
    })]);
    let r = run(&f, "https://a.example/", Some(&c), 0).expect("fetch");
    let detail = r.outcome.detail.expect("detail");
    assert!(!detail.contains("tok-abcdef"));
}

#[test]
fn truncation_is_visible_in_the_outcome() {
    let mut big = resp(200, &[], "xxxx");
    big.truncated = true;
    let f = Fake::new(vec![Ok(big)]);
    let r = run(&f, "https://a.example/", None, 0).expect("fetch");
    assert!(r.outcome.detail.expect("detail").contains("truncated"));
}

/// Every hop answers `302` to the next one after `delay` on a fake clock; a
/// delay longer than the hop's cap times out after the cap, like the transport.
struct SlowChain<'c> {
    clock: &'c crate::deadline::FakeClock,
    delay: std::time::Duration,
    caps: RefCell<Vec<Option<std::time::Duration>>>,
}

impl Transport for SlowChain<'_> {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        let n = self.caps.borrow().len();
        self.caps.borrow_mut().push(request.timeout);
        if let Some(cap) = request.timeout.filter(|cap| self.delay > *cap) {
            self.clock.advance(cap);
            return Err(TransportFailure {
                kind: SourceOutcomeKind::TtfbTimeout,
                detail: "timed out".into(),
                blocked: false,
            });
        }
        self.clock.advance(self.delay);
        Ok(resp(302, &[("location", &format!("/hop{}", n + 1))], ""))
    }
}

fn ms(n: u64) -> std::time::Duration {
    std::time::Duration::from_millis(n)
}

fn chain_within(
    delay: u64,
    request: Request,
) -> (
    Fetched,
    Vec<Option<std::time::Duration>>,
    std::time::Duration,
) {
    let clock = crate::deadline::FakeClock::new();
    let chain = SlowChain {
        clock: &clock,
        delay: ms(delay),
        caps: RefCell::default(),
    };
    let deadline = Deadline::start(&clock, ms(1000));
    let fetched = fetch_within(
        &chain,
        request,
        None,
        &FetchOptions::default(),
        &deadline,
        "t",
        100,
    )
    .expect("fetch");
    let caps = chain.caps.into_inner();
    (fetched, caps, clock.elapsed())
}

#[test]
fn each_redirect_hop_gets_only_what_is_left_of_the_deadline() {
    let (fetched, caps, elapsed) = chain_within(400, Request::get("https://a.example/"));
    assert_eq!(caps, [Some(ms(1000)), Some(ms(600)), Some(ms(200))]);
    assert_eq!(elapsed, ms(1000));
    assert_eq!(fetched.outcome.kind, SourceOutcomeKind::TtfbTimeout);
    assert!(fetched.response.is_none());
    assert_eq!(fetched.redirects, 2);
}

#[test]
fn a_hop_with_nothing_left_is_not_sent() {
    let (fetched, caps, elapsed) = chain_within(500, Request::get("https://a.example/"));
    assert_eq!(caps, [Some(ms(1000)), Some(ms(500))]);
    assert_eq!(elapsed, ms(1000));
    assert_eq!(fetched.outcome.kind, SourceOutcomeKind::TtfbTimeout);
    assert!(fetched.response.is_none());
    assert_eq!(fetched.redirects, 2);
    assert_eq!(
        fetched.outcome.detail.as_deref(),
        Some("1.0s budget spent before hop 3; not sent")
    );
    assert!(fetched.final_url.ends_with("/hop2"));
    assert!(fetched.credential_sent.is_none());
}

#[test]
fn a_smaller_request_cap_is_kept_on_every_hop() {
    let (fetched, caps, _) = chain_within(
        100,
        Request::get("https://a.example/").with_timeout(ms(300)),
    );
    // Six requests (the first plus five redirects), never raised above 300 ms.
    assert_eq!(caps, vec![Some(ms(300)); 6]);
    assert_eq!(fetched.redirects, 5);
    assert!(
        fetched
            .outcome
            .detail
            .expect("detail")
            .contains("redirect limit reached")
    );
}

#[test]
fn an_uncapped_fetch_leaves_every_hop_to_the_transport_timeout() {
    let f = Fake::new(vec![
        Ok(resp(302, &[("location", "/b")], "")),
        Ok(resp(200, &[], "ok")),
    ]);
    let r = run(&f, "https://a.example/", None, 5).expect("fetch");
    assert_eq!(r.redirects, 1);
    assert!(f.seen.borrow().iter().all(|req| req.timeout.is_none()));
}

#[test]
fn same_site_follows_the_monolith_s_redirect_verdict() {
    let site = RedirectPolicy::SameSite { site: "stolen.tax" };
    let first = "https://stolen.tax/api/v2/index.php?path=snusbase";
    for next in [
        "https://stolen.tax/other",
        "https://STOLEN.TAX/other",
        "https://api.stolen.tax/v2",
        "https://a.b.stolen.tax/v2",
        "https://stolen.tax:8443/v2",
        "https://stolen.tax./v2",
    ] {
        assert_eq!(refused_hop(site, first, next), None, "{next}");
    }
    for (next, why) in [
        ("https://evil.example/", "redirect refused: off-site hop"),
        (
            "https://stolen.tax@evil.example/",
            "redirect refused: off-site hop",
        ),
        (
            "https://stolen.tax:443@evil.example/",
            "redirect refused: off-site hop",
        ),
        ("https://xstolen.tax/", "redirect refused: off-site hop"),
        (
            "https://stolen.tax.evil.example/",
            "redirect refused: off-site hop",
        ),
        ("https://a..stolen.tax/", "redirect refused: off-site hop"),
        ("https://127.0.0.1/", "redirect refused: off-site hop"),
        ("https://[::1]/", "redirect refused: off-site hop"),
        (
            "http://stolen.tax/",
            "redirect refused: https to http downgrade",
        ),
        (
            "http://api.stolen.tax/",
            "redirect refused: https to http downgrade",
        ),
    ] {
        assert_eq!(refused_hop(site, first, next), Some(why), "{next}");
    }
    assert_eq!(
        refused_hop(RedirectPolicy::Any, first, "http://evil.example/"),
        None
    );
}

#[test]
fn userinfo_is_dropped_from_a_redirect_target() {
    assert_eq!(
        without_userinfo("https://u:p@www.stolen.tax/x?a=b@c"),
        "https://www.stolen.tax/x?a=b@c"
    );
    assert_eq!(
        without_userinfo("https://stolen.tax:443@evil.example/"),
        "https://evil.example/"
    );
    assert_eq!(
        without_userinfo("https://a.example/p"),
        "https://a.example/p"
    );
}

#[test]
fn a_pinned_credential_goes_only_to_its_origin_and_never_back_after_leaving() {
    let c = cred("tok-abcdef-123456", AuthStyle::Bearer).only_for_origin("https://a.example:443");
    let f = Fake::new(vec![
        Ok(resp(302, &[("location", "https://b.a.example/")], "")),
        Ok(resp(302, &[("location", "https://a.example/back")], "")),
        Ok(resp(200, &[], "")),
    ]);
    let r = run(&f, "https://a.example/start", Some(&c), 5).expect("fetch");
    let seen = f.seen.borrow();
    assert!(seen[0].header_value("authorization").is_some());
    assert!(seen[1].header_value("authorization").is_none());
    assert!(
        seen[2].header_value("authorization").is_none(),
        "re-attached on return"
    );
    assert!(r.credential_sent.is_none());

    let elsewhere = Fake::new(vec![Ok(resp(200, &[], ""))]);
    run(&elsewhere, "https://a.example:8443/", Some(&c), 0).expect("fetch");
    assert!(
        elsewhere.seen.borrow()[0]
            .header_value("authorization")
            .is_none()
    );
}

#[test]
fn a_custom_key_header_is_stripped_off_origin_even_if_the_caller_set_it() {
    let c = cred("tok-abcdef-123456", AuthStyle::Header("X-Feed".into()));
    let f = Fake::new(vec![
        Ok(resp(307, &[("location", "https://b.example/")], "")),
        Ok(resp(200, &[], "")),
    ]);
    fetch(
        &f,
        Request::get("https://a.example/").header("X-Feed", "caller-copy"),
        Some(&c),
        &FetchOptions::default(),
        "t",
        100,
    )
    .expect("fetch");
    let seen = f.seen.borrow();
    assert_eq!(
        seen[0]
            .headers
            .iter()
            .filter(|(k, _)| k == "X-Feed")
            .count(),
        1
    );
    assert!(seen[1].header_value("x-feed").is_none());
}

fn paced(max: u32) -> FetchOptions {
    FetchOptions {
        max_redirects: max,
        ..FetchOptions::default()
    }
    .paced()
}

#[test]
fn a_paced_fetch_records_a_rate_limit_and_then_suppresses_the_next_request() {
    // A host unique to this test so the shared registry cannot be perturbed by
    // any other test in the binary.
    let host = "paced-ratelimit.invalid";
    let url = format!("https://{host}/q");
    let f = Fake::new(vec![Ok(resp(429, &[("retry-after", "30")], ""))]);
    let r = fetch(&f, Request::get(&url), None, &paced(0), "t", 1000).expect("fetch");
    assert_eq!(r.outcome.kind, SourceOutcomeKind::RateLimited);
    assert_eq!(crate::circuit::host_state(host), Some(BreakerState::Open));

    // The circuit is open, so the next paced request is not sent at all.
    let empty = Fake::new(vec![]);
    let suppressed = fetch(&empty, Request::get(&url), None, &paced(0), "t", 1001).expect("fetch");
    assert_eq!(suppressed.outcome.kind, SourceOutcomeKind::Inconclusive);
    assert!(suppressed.response.is_none());
    assert!(empty.seen.borrow().is_empty(), "request should not be sent");
    assert!(
        suppressed
            .outcome
            .detail
            .as_deref()
            .is_some_and(|d| d.contains("circuit is open"))
    );
}

#[test]
fn five_paced_failures_open_the_circuit_and_a_success_closes_it() {
    let host = "paced-failures.invalid";
    let url = format!("https://{host}/q");
    for _ in 0..crate::circuit::FAILURE_THRESHOLD {
        let f = Fake::new(vec![Ok(resp(503, &[], ""))]);
        let r = fetch(&f, Request::get(&url), None, &paced(0), "t", 2000).expect("fetch");
        assert_eq!(r.outcome.kind, SourceOutcomeKind::Upstream5xx);
    }
    assert_eq!(crate::circuit::host_state(host), Some(BreakerState::Open));

    // After the cooldown the breaker half-opens and lets one probe through; a
    // success recorded by the paced fetch closes it again.
    let probe = Fake::new(vec![Ok(resp(200, &[], "ok"))]);
    let r = fetch(
        &probe,
        Request::get(&url),
        None,
        &paced(0),
        "t",
        2000 + crate::circuit::COOLDOWN_SECS,
    )
    .expect("fetch");
    assert_eq!(r.outcome.kind, SourceOutcomeKind::Inconclusive);
    assert_eq!(crate::circuit::host_state(host), Some(BreakerState::Closed));
}

#[test]
fn an_unpaced_fetch_ignores_an_open_circuit() {
    let host = "unpaced-open.invalid";
    let url = format!("https://{host}/q");
    crate::circuit::record_rate_limited(host, 3000, 60);
    assert_eq!(crate::circuit::host_state(host), Some(BreakerState::Open));
    // Default options do not consult the breaker: the request is still sent.
    let f = Fake::new(vec![Ok(resp(200, &[], "ok"))]);
    let r = run(&f, &url, None, 0).expect("fetch");
    assert_eq!(r.outcome.kind, SourceOutcomeKind::Inconclusive);
    assert_eq!(f.seen.borrow().len(), 1);
}

#[test]
fn an_unusable_location_is_a_refused_hop_under_same_site() {
    let f = Fake::new(vec![Ok(resp(
        302,
        &[("location", "javascript:alert(1)")],
        "",
    ))]);
    let r = fetch(
        &f,
        Request::get("https://stolen.tax/"),
        None,
        &FetchOptions {
            max_redirects: 9,
            redirect_policy: RedirectPolicy::SameSite { site: "stolen.tax" },
            ..FetchOptions::default()
        },
        "t",
        100,
    )
    .expect("a refused hop, not an error");
    assert_eq!(
        r.redirect_refused,
        Some("redirect refused: unusable Location")
    );
    assert_eq!(f.seen.borrow().len(), 1);
}
