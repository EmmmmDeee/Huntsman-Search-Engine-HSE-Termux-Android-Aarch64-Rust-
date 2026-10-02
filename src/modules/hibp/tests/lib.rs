//! Offline tests for the HIBP library client. Every HTTP call goes to the
//! loopback `test_server`; nothing here reaches haveibeenpwned.com or
//! api.pwnedpasswords.com. JSON bodies are labelled fixtures shaped on the
//! samples at haveibeenpwned.com/API/v3.

use std::sync::Arc;
use std::time::Duration;

use crate::util::http::test_server::{Canned, serve_recording};

use super::client::{Auth, HibpClient, HibpConfig, USER_AGENT, account_sha1_hex};
use super::error::HibpError;
use super::key::{ApiKey, KeyLoader, KeyOrigin, REDACTED};
use super::passwords::{PasswordHashMode, count_for, hash_password, parse_range};
use super::rate_limit::RateLimiter;
use super::types::{BreachedAccountOptions, BreachesFilter};
use super::{md4, oauth};

/// A synthetic key in HIBP's documented shape (32 hex). Not a real key.
const FAKE_KEY: &str = "0123456789abcdef0123456789abcdef";

const ADOBE: &str = r#"{"Name":"Adobe","Title":"Adobe","Domain":"adobe.com","BreachDate":"2013-10-04","AddedDate":"2013-12-04T00:00Z","ModifiedDate":"2022-05-15T23:52Z","PwnCount":152445165,"Description":"In October 2013, 153 million Adobe accounts were breached.","DataClasses":["Email addresses","Password hints","Passwords","Usernames"],"IsVerified":true,"IsFabricated":false,"IsSensitive":false,"IsRetired":false,"IsSpamList":false,"IsMalware":false,"IsSubscriptionFree":false,"LogoPath":"Adobe.png","Attribution":null}"#;

fn status_json(stealer: bool, kanon: bool) -> String {
    format!(
        r#"{{"SubscriptionName":"Core 1","Description":"fixture","SubscribedUntil":"2027-01-01T00:00:00","Rpm":10,"DomainSearchMaxBreachedAccounts":25,"MaxBreachedDomains":null,"IncludesStealerLogs":{stealer},"IncludesBulkDomainAdd":false,"IncludesAutoSubdomainVerification":false,"IncludesCustomerDomains":false,"IncludesKAnon":{kanon}}}"#
    )
}

fn client(base: &str, auth: Auth) -> HibpClient {
    let cfg = HibpConfig {
        api_base: base.to_string(),
        passwords_base: base.to_string(),
        max_retry_after: Duration::from_millis(0),
        ..HibpConfig::default()
    };
    HibpClient::with_config(
        reqwest::Client::new(),
        auth,
        cfg,
        Arc::new(RateLimiter::per_minute(0)),
    )
}

fn keyed(base: &str) -> HibpClient {
    client(base, Auth::ApiKey(ApiKey::new(FAKE_KEY).unwrap()))
}

fn head_line(h: &str) -> &str {
    h.lines().next().unwrap_or_default()
}

fn has_header(h: &str, name: &str, value: &str) -> bool {
    h.lines().any(|l| {
        l.split_once(':')
            .is_some_and(|(k, v)| k.trim().eq_ignore_ascii_case(name) && v.trim() == value)
    })
}

// ── Breaches ────────────────────────────────────────────────────────────

#[tokio::test]
async fn breaches_with_domain_filter_is_unauthenticated_and_sends_user_agent() {
    let (base, seen) = serve_recording(vec![Canned::json(200, format!("[{ADOBE}]"))]).await;
    let c = client(&base, Auth::None);
    let got = c
        .breaches(&BreachesFilter {
            domain: Some("adobe.com".into()),
            is_spam_list: Some(false),
        })
        .await
        .unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].name, "Adobe");
    assert_eq!(got[0].pwn_count, Some(152_445_165));
    assert_eq!(got[0].is_malware, Some(false));
    let h = seen.lock().unwrap()[0].clone();
    assert_eq!(
        head_line(&h),
        "GET /breaches?Domain=adobe.com&IsSpamList=false HTTP/1.1"
    );
    assert!(has_header(&h, "user-agent", USER_AGENT), "{h}");
    assert!(!h.to_ascii_lowercase().contains("hibp-api-key"), "{h}");
}

#[tokio::test]
async fn single_breach_latest_breach_and_data_classes() {
    let (base, seen) = serve_recording(vec![
        Canned::json(200, ADOBE),
        Canned::text(404, ""),
        Canned::json(200, ADOBE),
        Canned::json(200, r#"["Email addresses","Passwords"]"#),
    ])
    .await;
    let c = client(&base, Auth::None);
    assert_eq!(c.breach("Adobe").await.unwrap().unwrap().name, "Adobe");
    assert!(c.breach("NoSuchBreach").await.unwrap().is_none());
    assert_eq!(c.latest_breach().await.unwrap().unwrap().name, "Adobe");
    assert_eq!(
        c.data_classes().await.unwrap(),
        vec!["Email addresses", "Passwords"]
    );
    let heads: Vec<String> = seen
        .lock()
        .unwrap()
        .iter()
        .map(|h| head_line(h).to_string())
        .collect();
    assert_eq!(
        heads,
        [
            "GET /breach/Adobe HTTP/1.1",
            "GET /breach/NoSuchBreach HTTP/1.1",
            "GET /latestbreach HTTP/1.1",
            "GET /dataclasses HTTP/1.1",
        ]
    );
}

// ── Accounts, pastes, domains, subscription ─────────────────────────────

#[tokio::test]
async fn breached_account_sends_key_header_and_all_options() {
    let (base, seen) = serve_recording(vec![Canned::json(200, format!("[{ADOBE}]"))]).await;
    let got = keyed(&base)
        .breached_account(
            "victim@hibp-integration-tests.com",
            &BreachedAccountOptions {
                truncate_response: Some(false),
                domain: Some("adobe.com".into()),
                include_unverified: Some(false),
            },
        )
        .await
        .unwrap();
    assert_eq!(got[0].domain.as_deref(), Some("adobe.com"));
    let h = seen.lock().unwrap()[0].clone();
    assert_eq!(
        head_line(&h),
        "GET /breachedaccount/victim%40hibp-integration-tests.com?truncateResponse=false&domain=adobe.com&IncludeUnverified=false HTTP/1.1"
    );
    assert!(has_header(&h, "hibp-api-key", FAKE_KEY));
    assert!(has_header(&h, "user-agent", USER_AGENT));
}

#[tokio::test]
async fn breached_account_404_is_not_found_and_truncated_default_parses_names() {
    let (base, seen) = serve_recording(vec![
        Canned::text(404, ""),
        Canned::json(200, r#"[{"Name":"Adobe"},{"Name":"Gawker"}]"#),
    ])
    .await;
    let c = keyed(&base);
    let opts = BreachedAccountOptions::default();
    assert!(
        c.breached_account("clean@x.test", &opts)
            .await
            .unwrap()
            .is_empty()
    );
    let names: Vec<String> = c
        .breached_account("a@x.test", &opts)
        .await
        .unwrap()
        .into_iter()
        .map(|b| b.name)
        .collect();
    assert_eq!(names, ["Adobe", "Gawker"]);
    assert_eq!(
        head_line(&seen.lock().unwrap()[1]),
        "GET /breachedaccount/a%40x.test HTTP/1.1",
        "no query string when every option is left at the API default"
    );
}

#[tokio::test]
async fn keyed_endpoint_without_a_key_fails_before_any_request() {
    let (base, seen) = serve_recording(vec![]).await;
    let err = client(&base, Auth::None)
        .paste_account("a@x.test")
        .await
        .unwrap_err();
    assert!(matches!(err, HibpError::MissingKey), "{err}");
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn paste_account_parses_documented_sample() {
    let body = r#"[{"Source":"Pastebin","Id":"8Q0BvKD8","Title":"syslog","Date":"2014-03-04T19:14:54Z","EmailCount":139},{"Source":"Pastie","Id":"7152479","Date":"2013-03-28T16:51:10Z","EmailCount":30}]"#;
    let (base, seen) = serve_recording(vec![Canned::json(200, body)]).await;
    let got = keyed(&base).paste_account("a@x.test").await.unwrap();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].title.as_deref(), Some("syslog"));
    assert_eq!(got[1].title, None);
    assert_eq!(
        head_line(&seen.lock().unwrap()[0]),
        "GET /pasteaccount/a%40x.test HTTP/1.1"
    );
}

#[tokio::test]
async fn breached_domain_subscribed_domains_and_subscription_status() {
    let (base, seen) = serve_recording(vec![
        Canned::json(200, r#"{"alias1":["Adobe"],"alias2":["Adobe","Gawker"]}"#),
        Canned::json(
            200,
            r#"[{"DomainName":"example.org","PwnCount":12,"PwnCountExcludingSpamLists":10,"PwnCountExcludingSpamListsAtLastSubscriptionRenewal":9,"NextSubscriptionRenewal":"2027-01-01T00:00:00"}]"#,
        ),
        Canned::json(200, status_json(false, false)),
    ])
    .await;
    let c = keyed(&base);
    let d = c.breached_domain("example.org").await.unwrap();
    assert_eq!(d["alias2"], ["Adobe", "Gawker"]);
    let s = c.subscribed_domains().await.unwrap();
    assert_eq!(s[0].domain_name, "example.org");
    assert_eq!(
        s[0].pwn_count_excluding_spam_lists_at_last_subscription_renewal,
        Some(9)
    );
    let st = c.subscription_status().await.unwrap();
    assert_eq!(st.subscription_name, "Core 1");
    assert_eq!(st.includes_k_anon, Some(false));
    assert_eq!(st.max_breached_domains, None);
    let heads: Vec<String> = seen
        .lock()
        .unwrap()
        .iter()
        .map(|h| head_line(h).to_string())
        .collect();
    assert_eq!(
        heads,
        [
            "GET /breacheddomain/example.org HTTP/1.1",
            "GET /subscribeddomains HTTP/1.1",
            "GET /subscription/status HTTP/1.1",
        ]
    );
}

// ── Plan gating ─────────────────────────────────────────────────────────

#[tokio::test]
async fn core_plan_blocks_stealer_logs_and_k_anon_without_calling_them() {
    // Only the status answer is queued: any request to a gated endpoint would
    // get the server's 599 "no canned answer" and fail differently.
    let (base, seen) = serve_recording(vec![Canned::json(200, status_json(false, false))]).await;
    let c = keyed(&base);
    for err in [
        c.stealer_logs_by_email("a@x.test").await.unwrap_err(),
        c.stealer_logs_by_website_domain("netflix.com")
            .await
            .unwrap_err(),
        c.stealer_logs_by_email_domain("x.test")
            .await
            .map(|_| ())
            .unwrap_err(),
        c.breached_account_range("6B5917")
            .await
            .map(|_| ())
            .unwrap_err(),
    ] {
        match err {
            HibpError::PlanNotEntitled { plan, .. } => assert_eq!(plan, "Core 1"),
            other => panic!("expected PlanNotEntitled, got {other}"),
        }
    }
    let seen = seen.lock().unwrap();
    assert_eq!(
        seen.len(),
        1,
        "status fetched once, gated endpoints never called"
    );
    assert_eq!(head_line(&seen[0]), "GET /subscription/status HTTP/1.1");
}

#[tokio::test]
async fn entitled_plan_reaches_stealer_log_endpoints() {
    let (base, seen) = serve_recording(vec![
        Canned::json(200, status_json(true, true)),
        Canned::json(200, r#"["netflix.com","spotify.com"]"#),
        Canned::json(200, r#"["andy@gmail.com","jane@gmail.com"]"#),
        Canned::json(
            200,
            r#"{"andy":["netflix.com"],"jane":["netflix.com","spotify.com"]}"#,
        ),
    ])
    .await;
    let c = keyed(&base);
    assert_eq!(
        c.stealer_logs_by_email("jane@gmail.com").await.unwrap(),
        ["netflix.com", "spotify.com"]
    );
    assert_eq!(
        c.stealer_logs_by_website_domain("netflix.com")
            .await
            .unwrap()
            .len(),
        2
    );
    let by_dom = c.stealer_logs_by_email_domain("gmail.com").await.unwrap();
    assert_eq!(by_dom["jane"], ["netflix.com", "spotify.com"]);
    let heads: Vec<String> = seen
        .lock()
        .unwrap()
        .iter()
        .map(|h| head_line(h).to_string())
        .collect();
    assert_eq!(
        heads[1..],
        [
            "GET /stealerlogsbyemail/jane%40gmail.com HTTP/1.1",
            "GET /stealerlogsbywebsitedomain/netflix.com HTTP/1.1",
            "GET /stealerlogsbyemaildomain/gmail.com HTTP/1.1",
        ]
    );
}

#[tokio::test]
async fn breached_account_range_by_hash_matches_locally_and_discards_the_rest() {
    // Documented example: multiple-breaches@hibp-integration-tests.com →
    // SHA-1 6B5917C6C0AADE0C085843D66E4944E108C4A4CD.
    assert_eq!(
        account_sha1_hex(" Multiple-Breaches@hibp-integration-tests.com "),
        "6B5917C6C0AADE0C085843D66E4944E108C4A4CD"
    );
    let range = r#"[{"hashSuffix":"0000000000000000000000000000000000","websites":["Other"]},{"hashSuffix":"C6C0AADE0C085843D66E4944E108C4A4CD","websites":["Adobe","Gawker","Stratfor"]}]"#;
    let (base, seen) = serve_recording(vec![
        Canned::json(200, status_json(false, true)),
        Canned::json(200, range),
    ])
    .await;
    let got = keyed(&base)
        .breached_account_by_hash("multiple-breaches@hibp-integration-tests.com")
        .await
        .unwrap();
    assert_eq!(got, ["Adobe", "Gawker", "Stratfor"]);
    let seen = seen.lock().unwrap();
    assert_eq!(
        head_line(&seen[1]),
        "GET /breachedaccount/range/6B5917 HTTP/1.1"
    );
    assert!(
        !seen[1].contains("hibp-integration-tests"),
        "only the prefix leaves"
    );
}

#[tokio::test]
async fn bad_prefixes_are_rejected_before_any_request() {
    let (base, seen) = serve_recording(vec![]).await;
    let c = keyed(&base);
    assert!(matches!(
        c.breached_account_range("6B59").await,
        Err(HibpError::InvalidInput(_))
    ));
    assert!(matches!(
        c.pwned_passwords_range("ZZZZZ", PasswordHashMode::Sha1, false)
            .await,
        Err(HibpError::InvalidInput(_))
    ));
    assert!(seen.lock().unwrap().is_empty());
}

// ── Errors and 429 ──────────────────────────────────────────────────────

#[tokio::test]
async fn status_codes_map_to_typed_errors() {
    let (base, _) = serve_recording(vec![
        Canned::text(400, "bad"),
        Canned::text(401, "Access denied due to invalid hibp-api-key."),
        Canned::text(403, "no user agent"),
        Canned::text(503, "cloudflare"),
        Canned::text(500, "boom"),
    ])
    .await;
    let c = keyed(&base);
    let opts = BreachedAccountOptions::default();
    assert!(matches!(
        c.breached_account("a@x.test", &opts).await,
        Err(HibpError::BadRequest(_))
    ));
    assert!(matches!(
        c.breached_account("a@x.test", &opts).await,
        Err(HibpError::Unauthorized(_))
    ));
    assert!(matches!(
        c.breached_account("a@x.test", &opts).await,
        Err(HibpError::Forbidden(_))
    ));
    assert!(matches!(
        c.breached_account("a@x.test", &opts).await,
        Err(HibpError::Server { status: 503, .. })
    ));
    assert!(matches!(
        c.breached_account("a@x.test", &opts).await,
        Err(HibpError::Server { status: 500, .. })
    ));
}

#[tokio::test]
async fn a_429_honours_retry_after_then_succeeds() {
    let throttled = || {
        Canned::json(
            429,
            r#"{"statusCode":429,"message":"Rate limit is exceeded. Try again in 2 seconds."}"#,
        )
        .header("retry-after", "2")
    };
    let (base, seen) = serve_recording(vec![
        throttled(),
        Canned::json(200, r#"[{"Name":"Adobe"}]"#),
    ])
    .await;
    let got = keyed(&base)
        .breached_account("a@x.test", &BreachedAccountOptions::default())
        .await
        .unwrap();
    assert_eq!(got[0].name, "Adobe");
    assert_eq!(seen.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn a_429_past_the_retry_budget_is_rate_limited_with_retry_after() {
    let throttled = || Canned::text(429, "slow down").header("retry-after", "7");
    let (base, seen) =
        serve_recording(vec![throttled(), throttled(), throttled(), throttled()]).await;
    let err = keyed(&base)
        .breached_account("a@x.test", &BreachedAccountOptions::default())
        .await
        .unwrap_err();
    match err {
        HibpError::RateLimited { retry_after } => {
            assert_eq!(retry_after, Some(Duration::from_secs(7)));
        }
        other => panic!("expected RateLimited, got {other}"),
    }
    assert_eq!(seen.lock().unwrap().len(), 4, "1 try + 3 retries");
    let core: crate::core::error::Error = HibpError::RateLimited { retry_after: None }.into();
    assert!(matches!(core, crate::core::error::Error::RateLimited(_)));
}

// ── Rate limiter ────────────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn limiter_allows_ten_per_minute_then_waits_for_the_window() {
    let rl = RateLimiter::per_minute(10);
    let start = tokio::time::Instant::now();
    for _ in 0..10 {
        rl.acquire().await;
    }
    assert!(start.elapsed() < Duration::from_millis(1));
    rl.acquire().await;
    assert!(
        start.elapsed() >= Duration::from_secs(60),
        "{:?}",
        start.elapsed()
    );
}

#[tokio::test(start_paused = true)]
async fn limiter_block_for_holds_every_caller() {
    let rl = RateLimiter::per_minute(0);
    let start = tokio::time::Instant::now();
    rl.block_for(Duration::from_secs(5)).await;
    rl.acquire().await;
    assert!(start.elapsed() >= Duration::from_secs(5));
}

#[test]
fn default_limit_is_ten_per_minute() {
    assert_eq!(super::rate_limit::DEFAULT_REQUESTS_PER_MINUTE, 10);
}

// ── Pwned Passwords ─────────────────────────────────────────────────────

#[test]
fn padding_entries_are_filtered_and_lines_parsed() {
    let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0\r\nnot a line\r\n011053FD0102E94D6AE2F8B83D76FAF94F6:2\r\n";
    let padded = parse_range(body, true);
    assert_eq!(padded.len(), 2);
    assert!(padded.iter().all(|e| e.count > 0));
    assert_eq!(parse_range(body, false).len(), 3);
}

#[test]
fn sha1_and_ntlm_hashes_match_known_values() {
    assert_eq!(
        hash_password("password", PasswordHashMode::Sha1),
        "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
    );
    // Widely published NTLM hash of "password".
    assert_eq!(
        hash_password("password", PasswordHashMode::Ntlm),
        "8846F7EAEE8FB117AD06BDD830B7586C"
    );
}

#[test]
fn md4_matches_rfc_1320_vectors() {
    let hx = |d: &[u8]| hex::encode(md4::md4(d));
    assert_eq!(hx(b""), "31d6cfe0d16ae931b73c59d7e0c089c0");
    assert_eq!(hx(b"a"), "bde52cb31de33e46245e05fbdbd6fb24");
    assert_eq!(hx(b"abc"), "a448017aaf21d8525fc10ae87aa6729d");
    assert_eq!(hx(b"message digest"), "d9130a8164549fe818874806e1c7014b");
    assert_eq!(
        hx(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
        "e33b4ddc9c38f2199c3e7b164fcc0536"
    );
}

#[tokio::test]
async fn sha1_range_sends_padding_header_and_check_password_finds_count() {
    // SHA-1("password") = 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8.
    let body =
        "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\n0000000000000000000000000000000000A:0\r\n";
    let (base, seen) = serve_recording(vec![Canned::text(200, body)]).await;
    let n = keyed(&base)
        .check_password("password", PasswordHashMode::Sha1)
        .await
        .unwrap();
    assert_eq!(n, 9_659_365);
    let h = seen.lock().unwrap()[0].clone();
    assert_eq!(head_line(&h), "GET /range/5BAA6 HTTP/1.1");
    assert!(has_header(&h, "add-padding", "true"));
    assert!(has_header(&h, "user-agent", USER_AGENT));
    assert!(
        !h.to_ascii_lowercase().contains("hibp-api-key"),
        "Pwned Passwords is free; the key is never sent there"
    );
}

#[tokio::test]
async fn ntlm_range_uses_mode_query_and_is_ungated() {
    // NTLM("password") = 8846F 7EAEE8FB117AD06BDD830B7586C.
    let body = "7EAEE8FB117AD06BDD830B7586C:12\r\n";
    let (base, seen) =
        serve_recording(vec![Canned::text(200, body), Canned::text(200, body)]).await;
    let c = client(&base, Auth::None);
    assert_eq!(
        c.check_password("password", PasswordHashMode::Ntlm)
            .await
            .unwrap(),
        12
    );
    let entries = c
        .pwned_passwords_range("8846f", PasswordHashMode::Ntlm, false)
        .await
        .unwrap();
    assert_eq!(count_for(&entries, "7eaee8fb117ad06bdd830b7586c"), 12);
    let seen = seen.lock().unwrap();
    assert_eq!(head_line(&seen[0]), "GET /range/8846F?mode=ntlm HTTP/1.1");
    assert!(!seen[1].to_ascii_lowercase().contains("add-padding"));
}

// ── Keys: loading, precedence, redaction ────────────────────────────────

#[test]
fn key_precedence_env_then_huntsman_then_file_then_embedded() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("api_key");
    std::fs::write(&file, "  file-key-value-000000000000000\n").unwrap();
    let load = |env: Option<&str>, slot: Option<&str>, f: bool, emb: &str| {
        KeyLoader::from_parts(env.map(str::to_string), slot, f.then(|| file.clone()), emb)
            .load()
            .map(|(k, o)| (k.expose().to_string(), o))
    };
    assert_eq!(
        load(Some(" env-key "), Some("slot"), true, "emb").unwrap(),
        ("env-key".to_string(), KeyOrigin::Env("HIBP_API_KEY"))
    );
    assert_eq!(
        load(None, Some("slot-key"), true, "emb").unwrap().1,
        KeyOrigin::HuntsmanSlot
    );
    let (k, o) = load(None, None, true, "emb").unwrap();
    assert_eq!(k, "file-key-value-000000000000000", "file value is trimmed");
    assert_eq!(o, KeyOrigin::File(file.clone()));
    assert_eq!(
        load(None, None, false, "emb-key").unwrap().1,
        KeyOrigin::Embedded
    );
    // Blank values and provisioning placeholders are skipped, not used.
    assert_eq!(
        load(Some("   "), Some("insert_hibp_key_here"), true, "")
            .unwrap()
            .1,
        KeyOrigin::File(file.clone())
    );
}

#[test]
fn a_build_without_an_embedded_key_falls_back_to_runtime_sources() {
    // An empty embedded value is exactly what a CI / release /
    // HUNTSMAN_HIBP_NO_EMBED build writes.
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("api_key");
    std::fs::write(&file, "cfg-file-key\n").unwrap();
    assert!(KeyLoader::from_parts(None, None, None, "").load().is_none());
    assert_eq!(
        KeyLoader::from_parts(Some("from-env".into()), None, None, "")
            .load()
            .unwrap()
            .1,
        KeyOrigin::Env("HIBP_API_KEY")
    );
    assert_eq!(
        KeyLoader::from_parts(None, None, Some(file.clone()), "")
            .load()
            .unwrap()
            .1,
        KeyOrigin::File(file)
    );
}

#[derive(Clone, Default)]
struct LogBuf(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn the_key_never_appears_in_debug_display_errors_or_logs() {
    // Capture every log event at TRACE for this (current-thread) test.
    let buf = LogBuf::default();
    let sink = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || sink.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    tracing::debug!(module = "hibp", "log capture armed");

    let key = ApiKey::new(FAKE_KEY).unwrap();
    assert!(!format!("{key:?}").contains(FAKE_KEY));
    assert!(!format!("{key}").contains(FAKE_KEY));
    assert_eq!(format!("{key}"), REDACTED);
    let c = keyed("http://127.0.0.1:9");
    assert!(!format!("{c:?}").contains(FAKE_KEY), "{c:?}");
    assert!(!format!("{:?}", c.auth()).contains(FAKE_KEY));
    let (k, _) = KeyLoader::from_parts(Some(FAKE_KEY.into()), None, None, "")
        .load()
        .unwrap();
    assert!(!format!("{k:?}").contains(FAKE_KEY));

    // An upstream that echoes the key back in an error body: the error text
    // (and its Debug) must carry the redaction marker, never the key.
    let echo = format!("Access denied due to invalid hibp-api-key {FAKE_KEY}.");
    let (base, _) = serve_recording(vec![
        Canned::text(401, echo.clone()),
        Canned::text(500, echo),
    ])
    .await;
    let c = keyed(&base);
    for _ in 0..2 {
        let err = c
            .breached_account("a@x.test", &BreachedAccountOptions::default())
            .await
            .unwrap_err();
        assert!(!err.to_string().contains(FAKE_KEY), "{err}");
        assert!(!format!("{err:?}").contains(FAKE_KEY), "{err:?}");
        assert!(err.to_string().contains(REDACTED), "{err}");
        let core: crate::core::error::Error = err.into();
        assert!(!core.to_string().contains(FAKE_KEY));
    }

    // Logs: everything logged during this test, at every level.
    let logs = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("log capture armed"),
        "capture must be live: {logs}"
    );
    assert!(!logs.contains(FAKE_KEY), "a log line carried the key");
}

#[test]
fn oauth_tokens_and_pkce_verifier_are_redacted_in_debug() {
    let t = oauth::TokenSet {
        access_token: "AT-secret-value".into(),
        token_type: Some("Bearer".into()),
        expires_in: Some(3600),
        refresh_token: Some("RT-secret-value".into()),
        scope: Some(oauth::SCOPES.into()),
        id_token: Some("ID-secret-value".into()),
        expires_at: None,
    };
    let d = format!("{t:?}");
    for secret in ["AT-secret-value", "RT-secret-value", "ID-secret-value"] {
        assert!(!d.contains(secret), "{d}");
    }
    let p = oauth::Pkce::from_verifier("verifier-secret-value-0000000000000000000000");
    assert!(!format!("{p:?}").contains("verifier-secret-value"));
}

// ── OAuth 2.0 + PKCE ────────────────────────────────────────────────────

#[test]
fn pkce_s256_challenge_matches_independent_oracle() {
    // Challenge computed independently with Python hashlib/base64:
    // urlsafe_b64encode(sha256(verifier)).rstrip("=").
    let p = oauth::Pkce::from_verifier("dBjftJeZ4CVP-mB92K9uhvukw01oKkjXv5IZVcMaZGQ");
    assert_eq!(p.challenge(), "cJp5Vg2jFcgdnhvaP7G2fBy_dGnWIxqMrPY5pkhNZ9Y");
    assert_eq!(p.method(), "S256");
}

#[test]
fn pkce_generate_is_random_43_char_base64url() {
    let a = oauth::Pkce::generate().unwrap();
    let b = oauth::Pkce::generate().unwrap();
    assert_ne!(a.verifier(), b.verifier());
    for p in [&a, &b] {
        assert_eq!(p.verifier().len(), 43);
        assert!(
            p.verifier()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        assert_eq!(
            p.challenge(),
            oauth::Pkce::from_verifier(p.verifier()).challenge()
        );
    }
    assert_ne!(
        oauth::random_state().unwrap(),
        oauth::random_state().unwrap()
    );
}

const METADATA: &str = r#"{"issuer":"https://haveibeenpwned.com/","authorization_endpoint":"https://haveibeenpwned.com/connect/authorize","token_endpoint":"https://haveibeenpwned.com/connect/token","registration_endpoint":"https://haveibeenpwned.com/connect/register","scopes_supported":["openid","offline_access","hibp.mcp"],"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none","private_key_jwt"],"resource":"https://haveibeenpwned.com/mcp"}"#;

#[tokio::test]
async fn oauth_discovery_registration_url_exchange_and_refresh() {
    let (base, seen) = serve_recording(vec![
        Canned::json(200, METADATA),
        Canned::json(201, r#"{"client_id":"client-123","redirect_uris":["http://127.0.0.1:8765/cb"]}"#),
        Canned::json(200, r#"{"access_token":"AT1","token_type":"Bearer","expires_in":3600,"refresh_token":"RT1","scope":"openid offline_access hibp.mcp"}"#),
        Canned::json(200, r#"{"access_token":"AT2","token_type":"Bearer","expires_in":60}"#),
    ])
    .await;
    let http = reqwest::Client::new();
    let mut meta = oauth::discover(
        &http,
        &format!("{base}/.well-known/oauth-authorization-server"),
    )
    .await
    .unwrap();
    assert_eq!(
        meta.registration_endpoint.as_deref(),
        Some(oauth::REGISTRATION_URL)
    );
    assert!(
        meta.code_challenge_methods_supported
            .iter()
            .any(|m| m == "S256")
    );
    assert!(meta.scopes_supported.iter().any(|s| s == oauth::SCOPE_HIBP));

    let redirect = "http://127.0.0.1:8765/cb";
    let reg = oauth::register_client(
        &http,
        &format!("{base}/connect/register"),
        "HSE",
        &[redirect.into()],
    )
    .await
    .unwrap();
    assert_eq!(reg.client_id, "client-123");

    let pkce = oauth::Pkce::from_verifier("dBjftJeZ4CVP-mB92K9uhvukw01oKkjXv5IZVcMaZGQ");
    let url = oauth::authorization_url(&meta, &reg.client_id, redirect, &pkce, "st8").unwrap();
    let parsed = url::Url::parse(&url).unwrap();
    assert_eq!(parsed.path(), "/connect/authorize");
    let q: std::collections::HashMap<String, String> = parsed.query_pairs().into_owned().collect();
    assert_eq!(q["response_type"], "code");
    assert_eq!(q["client_id"], "client-123");
    assert_eq!(q["redirect_uri"], redirect);
    assert_eq!(q["scope"], "openid offline_access hibp.mcp");
    assert_eq!(q["resource"], "https://haveibeenpwned.com/mcp");
    assert_eq!(q["code_challenge"], pkce.challenge());
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["state"], "st8");
    assert!(!q.contains_key("client_secret"));

    meta.token_endpoint = format!("{base}/connect/token");
    let t = oauth::exchange_code(
        &http,
        &meta,
        "client-123",
        redirect,
        "code-xyz",
        &pkce,
        1_000,
    )
    .await
    .unwrap();
    assert_eq!(t.access_token, "AT1");
    assert_eq!(t.expires_at, Some(4_600));
    assert!(t.is_expired(4_590, 30) && !t.is_expired(1_000, 30));
    let t2 = oauth::refresh(&http, &meta, "client-123", "RT1", 2_000)
        .await
        .unwrap();
    assert_eq!(t2.access_token, "AT2");
    assert_eq!(
        t2.refresh_token.as_deref(),
        Some("RT1"),
        "kept when not rotated"
    );

    let seen = seen.lock().unwrap();
    assert_eq!(head_line(&seen[1]), "POST /connect/register HTTP/1.1");
    assert!(
        seen[1].contains(r#""token_endpoint_auth_method":"none""#),
        "{}",
        seen[1]
    );
    assert!(!seen[1].contains("client_secret"));
    assert_eq!(head_line(&seen[2]), "POST /connect/token HTTP/1.1");
    assert!(seen[2].contains("grant_type=authorization_code"));
    assert!(seen[2].contains("code_verifier=dBjftJeZ4CVP-mB92K9uhvukw01oKkjXv5IZVcMaZGQ"));
    assert!(seen[2].contains("code=code-xyz"));
    assert!(seen[3].contains("grant_type=refresh_token"));
    assert!(seen[3].contains("refresh_token=RT1"));
}

#[tokio::test]
async fn oauth_error_surfaces_only_error_fields() {
    let (base, _) = serve_recording(vec![Canned::json(
        400,
        r#"{"error":"invalid_grant","error_description":"code expired","echo":"code-xyz"}"#,
    )])
    .await;
    let mut meta: oauth::AuthServerMetadata = serde_json::from_str(METADATA).unwrap();
    meta.token_endpoint = format!("{base}/connect/token");
    let pkce = oauth::Pkce::generate().unwrap();
    let err = oauth::exchange_code(
        &reqwest::Client::new(),
        &meta,
        "c",
        "http://127.0.0.1/cb",
        "code-xyz",
        &pkce,
        0,
    )
    .await
    .unwrap_err();
    let s = err.to_string();
    assert!(s.contains("invalid_grant") && s.contains("HTTP 400"), "{s}");
    assert!(!s.contains("code-xyz"), "{s}");
}

#[test]
fn file_token_store_round_trips_with_mode_600() {
    use oauth::TokenStore as _;
    let dir = tempfile::tempdir().unwrap();
    let store = oauth::FileTokenStore::new(dir.path().join("sub").join("tokens.json"));
    assert!(store.load().is_none());
    let t = oauth::TokenSet {
        access_token: "AT".into(),
        token_type: None,
        expires_in: None,
        refresh_token: Some("RT".into()),
        scope: None,
        id_token: None,
        expires_at: Some(5),
    };
    store.save(&t).unwrap();
    assert_eq!(store.load().unwrap(), t);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path().join("sub").join("tokens.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    store.clear().unwrap();
    assert!(store.load().is_none());
    let mem = oauth::MemoryTokenStore::default();
    mem.save(&t).unwrap();
    assert_eq!(mem.load(), Some(t));
}
