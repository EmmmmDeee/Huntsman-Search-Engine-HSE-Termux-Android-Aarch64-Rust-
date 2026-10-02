use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::client::account_sha1_hex;
use super::oauth::TokenStore;
use super::passwords::PasswordHashMode;
use super::types::{BreachedAccountOptions, BreachesFilter};
use super::*;
use crate::http::{Request, Response, Transport, TransportFailure};

#[derive(Default)]
struct Fake {
    responses: Mutex<VecDeque<Response>>,
    requests: Mutex<Vec<Request>>,
}

impl Fake {
    fn push(&self, status: u16, body: &str) {
        self.responses.lock().unwrap().push_back(Response {
            status,
            body: body.as_bytes().to_vec(),
            headers: vec![],
            truncated: false,
        });
    }
    fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }
}

impl Transport for Fake {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        self.requests.lock().unwrap().push(request.clone());
        Ok(self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected request"))
    }
}

fn client(auth: Auth) -> (HibpClient, Arc<Fake>) {
    let fake = Arc::new(Fake::default());
    let client = HibpClient::with_config(
        fake.clone(),
        auth,
        HibpConfig::default(),
        Arc::new(rate_limit::RateLimiter::per_minute(0)),
    );
    (client, fake)
}

fn keyed() -> (HibpClient, Arc<Fake>) {
    client(Auth::ApiKey(ApiKey::new("private-key-never-log").unwrap()))
}

fn status(fake: &Fake, stealer: bool, kanon: bool) {
    fake.push(200, &format!(r#"{{"SubscriptionName":"private-key-never-log","IncludesStealerLogs":{stealer},"IncludesKAnon":{kanon}}}"#));
}

#[test]
fn public_endpoints_and_filters_never_send_credentials() {
    let (client, fake) = keyed();
    fake.push(200, r#"[{"Name":"Example","FutureField":true}]"#);
    assert_eq!(
        client
            .breaches(&BreachesFilter {
                domain: Some("example.com".into()),
                is_spam_list: Some(false),
            })
            .unwrap()[0]
            .name,
        "Example"
    );
    fake.push(200, r#"{"Name":"Example"}"#);
    assert!(client.breach("Example / ?").unwrap().is_some());
    fake.push(200, r#"{"Name":"Latest"}"#);
    assert_eq!(client.latest_breach().unwrap().unwrap().name, "Latest");
    fake.push(200, r#"["Email addresses"]"#);
    assert_eq!(client.data_classes().unwrap(), ["Email addresses"]);
    let requests = fake.requests();
    assert!(
        requests[0]
            .url
            .ends_with("/breaches?Domain=example.com&IsSpamList=false")
    );
    assert!(requests[1].url.ends_with("/breach/Example%20%2F%20%3F"));
    for req in requests {
        assert!(req.header_value("User-Agent").is_some());
        assert!(req.header_value("hibp-api-key").is_none());
    }
}

#[test]
fn account_and_paste_options_models_and_not_found() {
    let (client, fake) = keyed();
    fake.push(200, r#"[{"Name":"Example","DataClasses":["Passwords"]}]"#);
    let options = BreachedAccountOptions {
        truncate_response: Some(false),
        domain: Some("example.com".into()),
        include_unverified: Some(false),
    };
    assert_eq!(
        client
            .breached_account("a+b@example.com", &options)
            .unwrap()[0]
            .data_classes,
        ["Passwords"]
    );
    let req = &fake.requests()[0];
    assert!(req.url.ends_with("/breachedaccount/a%2Bb%40example.com?truncateResponse=false&domain=example.com&IncludeUnverified=false"));
    assert_eq!(
        req.header_value("hibp-api-key"),
        Some("private-key-never-log")
    );
    fake.push(
        200,
        r#"[{"Source":"Pastebin","Id":"42","Title":null,"Date":null,"EmailCount":1}]"#,
    );
    assert_eq!(
        client.paste_account("a@example.com").unwrap()[0]
            .id
            .as_deref(),
        Some("42")
    );
    fake.push(404, "");
    assert!(
        client
            .breached_account("a@example.com", &BreachedAccountOptions::default())
            .unwrap()
            .is_empty()
    );
    fake.push(404, "");
    assert!(client.paste_account("a@example.com").unwrap().is_empty());
    fake.push(404, "");
    assert!(client.breach("Absent").unwrap().is_none());
}

#[test]
fn domain_and_subscription_endpoint_shapes() {
    let (client, fake) = keyed();
    fake.push(200, r#"{"alice":["Example"]}"#);
    assert_eq!(
        client.breached_domain("example.com").unwrap()["alice"],
        ["Example"]
    );
    fake.push(200, r#"[{"DomainName":"example.com","PwnCount":42}]"#);
    assert_eq!(client.subscribed_domains().unwrap()[0].pwn_count, Some(42));
    status(&fake, true, true);
    assert!(
        client
            .subscription_status()
            .unwrap()
            .includes_k_anon
            .unwrap()
    );
    assert!(
        fake.requests()[0]
            .url
            .ends_with("/breacheddomain/example.com")
    );
    assert!(fake.requests()[1].url.ends_with("/subscribeddomains"));
    assert!(fake.requests()[2].url.ends_with("/subscription/status"));
}

#[test]
fn missing_key_and_invalid_input_make_no_requests() {
    let (client, fake) = client(Auth::None);
    assert!(matches!(
        client.paste_account("a@example.com"),
        Err(HibpError::MissingKey)
    ));
    assert!(matches!(
        client.stealer_logs_by_email("a@example.com"),
        Err(HibpError::MissingKey)
    ));
    assert!(client.breached_account_range("bad").is_err());
    assert!(
        client
            .pwned_passwords_range("bad", PasswordHashMode::Sha1, true)
            .is_err()
    );
    assert!(client.breached_account_by_hash(" ").is_err());
    assert!(client.breach(" ").is_err());
    assert!(fake.requests().is_empty());
}

#[test]
fn configured_untrusted_origin_is_refused_before_sending_a_key() {
    let fake = Arc::new(Fake::default());
    for api_base in [
        "https://evil.example/api/v3",
        "http://haveibeenpwned.com/api/v3",
        "https://api.pwnedpasswords.com/api/v3",
    ] {
        let client = HibpClient::with_config(
            fake.clone(),
            Auth::ApiKey(ApiKey::new("private-key").unwrap()),
            HibpConfig {
                api_base: api_base.into(),
                ..HibpConfig::default()
            },
            Arc::new(rate_limit::RateLimiter::per_minute(0)),
        );
        assert!(client.paste_account("a@example.com").is_err());
    }
    assert!(fake.requests().is_empty());
}

#[test]
fn redirects_are_not_followed_with_credentials() {
    let (client, fake) = keyed();
    fake.push(302, "");
    fake.responses
        .lock()
        .unwrap()
        .back_mut()
        .unwrap()
        .headers
        .push(("Location".into(), "https://evil.example/".into()));
    assert!(client.paste_account("a@example.com").is_err());
    assert_eq!(fake.requests().len(), 1);
}

#[test]
fn missing_entitlement_flags_fail_closed() {
    let (client, fake) = keyed();
    fake.push(200, r#"{"SubscriptionName":"Unknown"}"#);
    assert!(matches!(
        client.breached_account_range("ABCDEF"),
        Err(HibpError::PlanNotEntitled { .. })
    ));
    assert!(matches!(
        client.stealer_logs_by_email("a@example.com"),
        Err(HibpError::PlanNotEntitled { .. })
    ));
    assert_eq!(fake.requests().len(), 1);
}

#[test]
fn plan_gates_fail_closed_and_cache_across_clones() {
    let (client, fake) = keyed();
    status(&fake, false, false);
    for result in [
        client.stealer_logs_by_email("a@example.com").map(|_| ()),
        client
            .clone()
            .stealer_logs_by_website_domain("example.com")
            .map(|_| ()),
        client
            .stealer_logs_by_email_domain("example.com")
            .map(|_| ()),
        client.breached_account_range("ABCDEF").map(|_| ()),
    ] {
        let error = result.unwrap_err();
        assert!(matches!(error, HibpError::PlanNotEntitled { .. }));
        assert!(!format!("{error:?} {error}").contains("private-key"));
    }
    assert_eq!(fake.requests().len(), 1);
}

#[test]
fn plan_fetch_errors_do_not_reach_gated_endpoint_or_poison_cache() {
    let (client, fake) = keyed();
    fake.push(401, "private-key-never-log");
    assert!(client.stealer_logs_by_email("a@example.com").is_err());
    status(&fake, true, true);
    fake.push(200, "[]");
    assert!(
        client
            .stealer_logs_by_email("a@example.com")
            .unwrap()
            .is_empty()
    );
    assert_eq!(fake.requests().len(), 3);
}

#[test]
fn entitled_plan_reaches_all_stealer_endpoints() {
    let (client, fake) = keyed();
    status(&fake, true, true);
    fake.push(200, r#"["example.com"]"#);
    assert_eq!(
        client.stealer_logs_by_email("a@example.com").unwrap(),
        ["example.com"]
    );
    fake.push(200, r#"["a@example.com"]"#);
    assert_eq!(
        client
            .stealer_logs_by_website_domain("example.com")
            .unwrap(),
        ["a@example.com"]
    );
    fake.push(200, r#"{"alice":["example.com"]}"#);
    assert_eq!(
        client.stealer_logs_by_email_domain("example.com").unwrap()["alice"],
        ["example.com"]
    );
    let requests = fake.requests();
    assert!(
        requests[1]
            .url
            .ends_with("/stealerlogsbyemail/a%40example.com")
    );
    assert!(
        requests[2]
            .url
            .ends_with("/stealerlogsbywebsitedomain/example.com")
    );
    assert!(
        requests[3]
            .url
            .ends_with("/stealerlogsbyemaildomain/example.com")
    );
}

#[test]
fn account_hash_lookup_discards_other_accounts_locally() {
    let (client, fake) = keyed();
    status(&fake, false, true);
    let hash = account_sha1_hex(" A@EXAMPLE.COM ");
    fake.push(200, &format!(r#"[{{"hashSuffix":"{}","websites":["match"]}},{{"hashSuffix":"{}","websites":["other"]}}]"#,
        &hash[6..], "0".repeat(34)));
    assert_eq!(
        client.breached_account_by_hash(" A@EXAMPLE.COM ").unwrap(),
        ["match"]
    );
    let requests = fake.requests();
    assert!(
        requests[1]
            .url
            .ends_with(&format!("/breachedaccount/range/{}", &hash[..6]))
    );
    assert!(!requests[1].url.contains("EXAMPLE"));
}

#[test]
fn passwords_are_local_prefix_only_padding_and_ntlm_are_supported() {
    let (client, fake) = keyed();
    for mode in [PasswordHashMode::Sha1, PasswordHashMode::Ntlm] {
        let hash = passwords::hash_password("password", mode);
        fake.push(
            200,
            &format!("{}:42\r\n{}:0\r\n", &hash[5..], "0".repeat(hash.len() - 5)),
        );
        assert_eq!(client.check_password("password", mode).unwrap(), 42);
        let request = fake.requests().last().unwrap().clone();
        assert!(request.url.contains(&format!("/range/{}", &hash[..5])));
        assert_eq!(
            request.url.contains("?mode=ntlm"),
            mode == PasswordHashMode::Ntlm
        );
        assert_eq!(request.header_value("Add-Padding"), Some("true"));
        assert!(request.header_value("hibp-api-key").is_none());
        assert!(request.header_value("Authorization").is_none());
    }
}

#[test]
fn invalid_ranges_utf8_and_truncation_fail_not_absence() {
    let (client, fake) = keyed();
    fake.push(200, "BAD:1");
    assert!(
        client
            .check_password("password", PasswordHashMode::Sha1)
            .is_err()
    );
    fake.push(200, "[]");
    fake.responses.lock().unwrap().back_mut().unwrap().truncated = true;
    assert!(client.paste_account("a@example.com").is_err());
    fake.push(200, "");
    fake.responses.lock().unwrap().back_mut().unwrap().body = vec![255];
    assert!(
        client
            .check_password("password", PasswordHashMode::Sha1)
            .is_err()
    );
    status(&fake, false, true);
    fake.push(200, r#"[{"hashSuffix":"short","websites":[]}]"#);
    assert!(client.breached_account_range("ABCDEF").is_err());
}

#[test]
fn hash_vectors_cover_sha1_padding_ntlm_unicode_and_rfc_md4() {
    assert_eq!(
        passwords::sha1_hex(b""),
        "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
    );
    assert_eq!(
        passwords::sha1_hex(b"abc"),
        "A9993E364706816ABA3E25717850C26C9CD0D89D"
    );
    assert_eq!(
        passwords::sha1_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "84983E441C3BD26EBAAE4AA1F95129E5E54670F1"
    );
    assert_eq!(
        passwords::sha1_hex(&vec![b'a'; 1_000_000]),
        "34AA973CD4C4DAA4F61EEB2BDBAD27316534016F"
    );
    assert_eq!(
        passwords::hash_password("password", PasswordHashMode::Sha1),
        "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
    );
    assert_eq!(
        passwords::hash_password("password", PasswordHashMode::Ntlm),
        "8846F7EAEE8FB117AD06BDD830B7586C"
    );
    assert_eq!(
        passwords::hash_password("pässwörd", PasswordHashMode::Ntlm),
        "0553152250AC01ADB4213CB9938663E4"
    );
    for (input, expected) in [
        ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
        ("a", "bde52cb31de33e46245e05fbdbd6fb24"),
        ("abc", "a448017aaf21d8525fc10ae87aa6729d"),
        ("message digest", "d9130a8164549fe818874806e1c7014b"),
        (
            "abcdefghijklmnopqrstuvwxyz",
            "d79e1c308aa5bbcdeea8ed63df412da9",
        ),
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "043f8582f241db351ce627e153e7f0e4",
        ),
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "e33b4ddc9c38f2199c3e7b164fcc0536",
        ),
    ] {
        let digest = super::md4::md4(input.as_bytes());
        assert_eq!(
            digest.iter().fold(String::new(), |mut out, byte| {
                use std::fmt::Write;
                write!(out, "{byte:02x}").unwrap();
                out
            }),
            expected
        );
    }
}

#[test]
fn status_errors_and_decode_errors_never_echo_secrets_or_body() {
    let (client, fake) = keyed();
    for status in [400, 401, 403, 500, 503, 418, 302] {
        fake.push(status, "private-key-never-log private-token response body");
        let error = client.paste_account("a@example.com").unwrap_err();
        let printed = format!("{error:?} {error}");
        assert!(!printed.contains("private-key") && !printed.contains("private-token"));
    }
    fake.push(
        200,
        r#"[{"Name": "private-key-never-log","PwnCount":"private-token"}]"#,
    );
    let error = client.breaches(&BreachesFilter::default()).unwrap_err();
    assert!(!format!("{error:?}").contains("private-"));
    assert!(!format!("{client:?}").contains("private-key"));
}

#[test]
fn transport_failure_does_not_echo_url_or_secret() {
    struct Failing;
    impl Transport for Failing {
        fn send(&self, _: &Request) -> Result<Response, TransportFailure> {
            Err(TransportFailure {
                kind: crate::source_outcome::SourceOutcomeKind::TtfbTimeout,
                detail: "a@example.com private-key-never-log".into(),
                blocked: false,
            })
        }
    }
    let client = HibpClient::new(Arc::new(Failing), Auth::None);
    let error = client.breaches(&BreachesFilter::default()).unwrap_err();
    assert_eq!(error.to_string(), "hibp: transport error: request failed");
}

#[test]
fn retries_are_bounded_and_do_not_shorten_server_retry_after() {
    let (mut client, fake) = keyed();
    client.config_for_tests(1, Duration::from_millis(5));
    for _ in 0..2 {
        fake.push(429, "private-key");
        fake.responses
            .lock()
            .unwrap()
            .back_mut()
            .unwrap()
            .headers
            .push(("Retry-After".into(), "0".into()));
    }
    assert!(matches!(
        client.paste_account("a@example.com"),
        Err(HibpError::RateLimited { .. })
    ));
    assert_eq!(fake.requests().len(), 2);
    fake.push(429, "");
    fake.responses
        .lock()
        .unwrap()
        .back_mut()
        .unwrap()
        .headers
        .push(("retry-after".into(), "3600".into()));
    assert!(matches!(client.paste_account("a@example.com"),
        Err(HibpError::RateLimited { retry_after: Some(d) }) if d == Duration::from_secs(3600)));
    assert_eq!(fake.requests().len(), 3);
}

#[test]
fn retry_zero_then_success() {
    let (client, fake) = keyed();
    fake.push(429, "");
    fake.responses
        .lock()
        .unwrap()
        .back_mut()
        .unwrap()
        .headers
        .push(("retry-after".into(), "0".into()));
    fake.push(200, "[]");
    assert!(client.paste_account("a@example.com").unwrap().is_empty());
    assert_eq!(fake.requests().len(), 2);
}

#[test]
fn limiter_sliding_window_and_shared_block() {
    assert_eq!(rate_limit::RateLimiter::per_minute(10).limit(), 10);
    let limiter = rate_limit::RateLimiter::new(10, Duration::from_millis(30));
    for _ in 0..10 {
        limiter.acquire();
    }
    let start = Instant::now();
    limiter.acquire();
    assert!(start.elapsed() >= Duration::from_millis(20));
    limiter.block_for(Duration::from_millis(30)).unwrap();
    let start = Instant::now();
    limiter.acquire();
    assert!(start.elapsed() >= Duration::from_millis(20));
}

fn metadata() -> oauth::AuthServerMetadata {
    serde_json::from_str(r#"{"issuer":"https://haveibeenpwned.com","authorization_endpoint":"https://haveibeenpwned.com/connect/authorize","token_endpoint":"https://haveibeenpwned.com/connect/token","registration_endpoint":"https://haveibeenpwned.com/connect/register","code_challenge_methods_supported":["S256"]}"#).unwrap()
}

fn pkce() -> oauth::Pkce {
    oauth::Pkce::from_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
}

#[test]
fn pkce_matches_rfc7636_and_randomness_is_not_reused() {
    assert_eq!(
        pkce().challenge(),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
    let a = oauth::Pkce::generate().unwrap();
    let b = oauth::Pkce::generate().unwrap();
    assert_eq!(a.verifier().len(), 43);
    assert_ne!(a.verifier(), b.verifier());
    assert_ne!(
        oauth::random_state().unwrap(),
        oauth::random_state().unwrap()
    );
    assert!(!format!("{a:?}").contains(a.verifier()));
}

#[test]
fn oauth_discovery_public_registration_exchange_refresh_and_scope() {
    let fake = Fake::default();
    fake.push(200, &serde_json::to_string(&metadata()).unwrap());
    let meta = oauth::discover(&fake, oauth::METADATA_URL).unwrap();
    fake.push(
        201,
        r#"{"client_id":"public","redirect_uris":["http://127.0.0.1:7777/callback"]}"#,
    );
    let redirect = "http://127.0.0.1:7777/callback";
    assert_eq!(
        oauth::register_client(
            &fake,
            oauth::REGISTRATION_URL,
            "huntsman",
            &[redirect.into()]
        )
        .unwrap()
        .client_id,
        "public"
    );
    let body: serde_json::Value = serde_json::from_slice(&fake.requests()[1].body).unwrap();
    assert_eq!(body["token_endpoint_auth_method"], "none");
    assert_eq!(
        body["grant_types"],
        serde_json::json!(["authorization_code", "refresh_token"])
    );
    let url = oauth::authorization_url(&meta, "public", redirect, &pkce(), "csrf").unwrap();
    assert!(url.contains("scope=openid+offline_access+hibp.mcp"));
    assert!(url.contains("resource=https%3A%2F%2Fhaveibeenpwned.com%2Fmcp"));
    assert!(url.contains("state=csrf") && url.contains("code_challenge_method=S256"));
    fake.push(
        200,
        r#"{"access_token":"private-access","refresh_token":"private-refresh","expires_in":60}"#,
    );
    let tokens = oauth::exchange_code(
        &fake,
        &meta,
        "public",
        redirect,
        "private-code",
        &pkce(),
        100,
    )
    .unwrap();
    assert_eq!(tokens.expires_at, Some(160));
    assert!(tokens.is_expired(155, 5));
    assert!(!format!("{tokens:?}").contains("private-"));
    let request = &fake.requests()[2];
    assert!(String::from_utf8_lossy(&request.body).contains("code_verifier=dBj"));
    assert!(!format!("{request:?}").contains("private-code"));
    fake.push(200, r#"{"access_token":"new-access","expires_in":60}"#);
    let tokens = oauth::refresh(&fake, &meta, "public", "private-refresh", 200).unwrap();
    assert_eq!(tokens.refresh_token.as_deref(), Some("private-refresh"));
    assert_eq!(tokens.expires_at, Some(260));
    fake.push(
        200,
        r#"{"access_token":"new-access","refresh_token":"rotated"}"#,
    );
    assert_eq!(
        oauth::refresh(&fake, &meta, "public", "private-refresh", 300)
            .unwrap()
            .refresh_token
            .as_deref(),
        Some("rotated")
    );
}

#[test]
fn oauth_error_redaction_truncation_and_origin_fail_closed() {
    let fake = Fake::default();
    fake.push(
        400,
        r#"{"error":"private-refresh","error_description":"private-code"}"#,
    );
    let err = oauth::refresh(&fake, &metadata(), "public", "private-refresh", 0).unwrap_err();
    assert!(!format!("{err:?} {err}").contains("private-"));
    for url in [
        "https://evil.example/token",
        "http://haveibeenpwned.com/token",
        "https://haveibeenpwned.com@evil.example/token",
        "https://haveibeenpwned.com:444/token",
        "https://api.pwnedpasswords.com/token",
    ] {
        let mut meta = metadata();
        meta.token_endpoint = url.into();
        assert!(oauth::refresh(&fake, &meta, "public", "private-refresh", 0).is_err());
        assert!(oauth::register_client(&fake, url, "name", &[]).is_err());
    }
    assert_eq!(fake.requests().len(), 1);
    fake.push(200, &serde_json::to_string(&metadata()).unwrap());
    fake.responses.lock().unwrap().back_mut().unwrap().truncated = true;
    assert!(oauth::discover(&fake, oauth::METADATA_URL).is_err());
}

fn scratch(name: &str) -> std::path::PathBuf {
    let path = std::path::PathBuf::from("target/hibp-tests")
        .join(format!("{name}-{}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn key_precedence_and_missing_embedded_fallback() {
    let dir = scratch("keys");
    let path = dir.join("key");
    crate::fsio::write_atomic_private(&path, b"file-key", 4096).unwrap();
    for (env, slot, file, embedded, expected) in [
        (
            Some("env-key"),
            Some("slot-key"),
            Some(path.clone()),
            "embedded-key",
            "env-key",
        ),
        (
            Some("insert_key_here"),
            Some("slot-key"),
            Some(path.clone()),
            "embedded-key",
            "slot-key",
        ),
        (None, None, Some(path.clone()), "embedded-key", "file-key"),
        (None, None, None, "embedded-key", "embedded-key"),
        (Some("runtime-key"), None, None, "", "runtime-key"),
    ] {
        let loader = key::KeyLoader::from_parts(env.map(str::to_owned), slot, file, embedded);
        assert_eq!(loader.load().unwrap().0.expose(), expected);
    }
    assert!(
        key::KeyLoader::from_parts(None, None, None, "")
            .load()
            .is_none()
    );
    assert!(ApiKey::new("bad\nheader").is_none());
    let key = ApiKey::new("never-print").unwrap();
    assert!(!format!("{key:?} {key}").contains("never-print"));
    crate::fsio::write_atomic_private(&path, &vec![b'x'; 4097], 5000).unwrap();
    assert!(
        key::KeyLoader::from_parts(None, None, Some(path), "")
            .load()
            .is_none()
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn token_store_private_atomic_bounded_and_memory_roundtrip() {
    let dir = scratch("tokens");
    let path = dir.join("tokens.json");
    let tokens: oauth::TokenSet = serde_json::from_str(
        r#"{"access_token":"private-access","refresh_token":"private-refresh"}"#,
    )
    .unwrap();
    let file = oauth::FileTokenStore::new(path.clone());
    file.save(&tokens).unwrap();
    assert_eq!(file.load(), Some(tokens.clone()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(file.load().is_none());
        file.save(&tokens).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let memory = oauth::MemoryTokenStore::default();
    memory.save(&tokens).unwrap();
    assert_eq!(memory.load(), Some(tokens.clone()));
    memory.clear().unwrap();
    assert!(memory.load().is_none());
    let mut huge = tokens;
    huge.access_token = "x".repeat(65537);
    assert!(file.save(&huge).is_err());
    assert!(file.load().is_some());
    file.clear().unwrap();
    file.clear().unwrap();
    assert!(file.load().is_none());
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn key_and_token_symlinks_are_refused() {
    let dir = scratch("symlinks");
    let target = dir.join("real");
    crate::fsio::write_atomic_private(&target, b"private-key", 4096).unwrap();
    let link = dir.join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(
        key::KeyLoader::from_parts(None, None, Some(link.clone()), "")
            .load()
            .is_none()
    );
    let store = oauth::FileTokenStore::new(link);
    assert!(store.load().is_none());
    let tokens = serde_json::from_str(r#"{"access_token":"private-access"}"#).unwrap();
    assert!(store.save(&tokens).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"private-key");
    std::fs::remove_dir_all(dir).unwrap();
}
