use super::client::{build_client, build_client_with_trace};
use super::fetch::{
    JSON_BODY_CAP, is_keyed_error_status, key_tail, keyed_ok_or_404, retry_after_secs,
};
use super::redact::{redact_credentials, redact_literal_secrets};
use super::ssrf::{filter_public, redirect_to_private_ip};
use super::url::json_decode;
use super::url::{RequestBuilderExt, urlencode};
use crate::util::found_keys::{is_key_delimiter, key_tokens};

#[test]
fn keyed_error_status_classification() {
    for code in [401, 403, 429] {
        assert!(is_keyed_error_status(code), "{code} is a key error");
    }
    for code in [200, 400, 404, 418, 500, 502, 503] {
        assert!(!is_keyed_error_status(code), "{code} is not a key error");
    }
}

#[tokio::test]
async fn json_decode_parses_ok_and_tags_decode_errors_with_module() {
    use serde::Deserialize;
    #[derive(Deserialize, Debug, PartialEq)]
    struct V {
        a: u32,
        b: String,
    }

    let ok = reqwest::Response::from(
        http::Response::builder()
            .status(200)
            .body(r#"{"a":7,"b":"x"}"#.to_string())
            .unwrap(),
    );
    let v: V = json_decode("test_mod", ok).await.unwrap();
    assert_eq!(
        v,
        V {
            a: 7,
            b: "x".into()
        }
    );

    let bad = reqwest::Response::from(
        http::Response::builder()
            .status(200)
            .body("not json".to_string())
            .unwrap(),
    );
    let err = json_decode::<V>("test_mod", bad).await.unwrap_err();
    assert!(
        err.to_string().contains("test_mod"),
        "decode error must name the module: {err}"
    );
}

#[tokio::test]
async fn send_tagged_maps_transport_errors_to_the_module() {
    let err = reqwest::Client::new()
        .get("ftp://example.invalid/")
        .send_tagged("test_mod")
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("test_mod"),
        "transport error must name the module: {err}"
    );
}

#[tokio::test]
async fn send_tagged_strips_url_so_secrets_and_pii_dont_leak() {
    // A request URL carries the API key and the searched target in its query
    // string; a transport error must not embed either, because it flows into the
    // downloadable verbose log. The scheme error here keys the URL onto the error
    // (no network needed), exactly the case `without_url()` must neutralise.
    let err = reqwest::Client::new()
        .get("ftp://example.invalid/v1/lookup?apikey=SECRETKEY123&q=target@example.com")
        .send_tagged("test_mod")
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        !msg.contains("SECRETKEY123"),
        "API key leaked into error: {msg}"
    );
    assert!(
        !msg.contains("target@example.com"),
        "target PII leaked into error: {msg}"
    );
    assert!(
        msg.contains("test_mod"),
        "error must still name the module: {msg}"
    );
}

#[tokio::test]
async fn keyed_ok_or_404_classifies_miss_success_and_error() {
    use std::collections::HashMap;
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = crate::core::module::ModuleContext {
        scan_id: "test".into(),
        bus,
        http: reqwest::Client::new(),
        keys: HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: Default::default(),
    };
    let resp = |code: u16| {
        reqwest::Response::from(
            http::Response::builder()
                .status(code)
                .body(String::new())
                .unwrap(),
        )
    };

    let miss = keyed_ok_or_404("test_mod", "k", &ctx, resp(404))
        .await
        .unwrap();
    assert!(miss.is_none(), "404 must classify as a miss");

    let ok = keyed_ok_or_404("test_mod", "k", &ctx, resp(200))
        .await
        .unwrap();
    assert!(ok.is_some(), "2xx must hand back the response");

    let err = keyed_ok_or_404("test_mod", "k", &ctx, resp(500))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("test_mod"),
        "non-2xx error must name the module: {err}"
    );
}

#[test]
fn curl_download_cap_mirrors_the_json_body_cap() {
    let curl_cap: usize = crate::util::curl::CURL_MAX_DOWNLOAD_BYTES
        .parse()
        .expect("CURL_MAX_DOWNLOAD_BYTES must be a decimal byte count");
    assert_eq!(
        curl_cap, JSON_BODY_CAP,
        "the curl --max-filesize cap and the reqwest JSON body cap must stay equal"
    );
}

#[tokio::test]
async fn traced_client_sends_x_huntsman_trace_header() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = sock.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]).to_string();
        let _ = sock
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await;
        req
    });
    let client = build_client_with_trace("scan-abc123");
    let _ = client.get(format!("http://{addr}/")).send().await;
    let req = server.await.unwrap().to_lowercase();
    assert!(
        req.contains("x-huntsman-trace: scan-abc123"),
        "trace header missing; raw request was:\n{req}"
    );
}

#[test]
fn traced_client_builds_and_tolerates_non_ascii_id() {
    let _ = build_client_with_trace("plain-ascii-id");
    let _ = build_client_with_trace("non-ascii-\u{2022}-id");
}

#[test]
fn ssrf_dns_filter_drops_private_and_metadata() {
    let addrs: Vec<std::net::SocketAddr> = [
        "10.0.0.1:80",
        "8.8.8.8:443",
        "169.254.169.254:80",
        "127.0.0.1:80",
        "[::1]:80",
        "[2606:4700:4700::1111]:443",
    ]
    .iter()
    .map(|x| x.parse().unwrap())
    .collect();
    let kept: Vec<String> = filter_public(addrs.into_iter())
        .iter()
        .map(|a| a.ip().to_string())
        .collect();
    assert!(kept.contains(&"8.8.8.8".to_string()), "public v4 kept");
    assert!(
        kept.contains(&"2606:4700:4700::1111".to_string()),
        "public v6 kept"
    );
    for blocked in ["10.0.0.1", "169.254.169.254", "127.0.0.1", "::1"] {
        assert!(
            !kept.iter().any(|i| i == blocked),
            "{blocked} must be filtered"
        );
    }
}

#[test]
fn redirect_to_private_ip_blocks_metadata_and_internal() {
    assert!(
        redirect_to_private_ip(Some("169.254.169.254")),
        "cloud-metadata IP must be refused"
    );
    assert!(redirect_to_private_ip(Some("127.0.0.1")));
    assert!(redirect_to_private_ip(Some("10.0.0.5")));
    assert!(redirect_to_private_ip(Some("192.168.1.1")));
    assert!(
        !redirect_to_private_ip(Some("8.8.8.8")),
        "public IP follows"
    );
    assert!(
        !redirect_to_private_ip(Some("example.com")),
        "hostnames resolved at connect, not judged here"
    );
    assert!(!redirect_to_private_ip(None));

    // IPv6-literal hops arrive bracketed from `Url::host_str()` (url 2.5).
    assert!(
        redirect_to_private_ip(Some("[::1]")),
        "IPv6 loopback hop must be refused"
    );
    assert!(
        redirect_to_private_ip(Some("[fc00::1]")),
        "ULA hop must be refused"
    );
    assert!(
        redirect_to_private_ip(Some("[fe80::1]")),
        "link-local hop must be refused"
    );
    assert!(
        redirect_to_private_ip(Some("[::ffff:169.254.169.254]")),
        "IPv4-mapped cloud-metadata hop must be refused"
    );
    assert!(
        redirect_to_private_ip(Some("[64:ff9b::a9fe:a9fe]")),
        "NAT64-embedded metadata hop must be refused"
    );
    assert!(
        !redirect_to_private_ip(Some("[2606:4700:4700::1111]")),
        "public IPv6 hop follows"
    );
}

#[test]
fn build_client_succeeds() {
    let _c = build_client();
}

#[test]
fn redacts_path_embedded_secret_value() {
    let key = "abcd1234efgh5678ijkl";
    let body = format!("invalid request: /api/json/ip/{key}/1.2.3.4 rejected");
    let masked = redact_literal_secrets(&body, std::iter::once(key.to_string()));
    assert!(
        !masked.contains(key),
        "path-embedded key must be redacted: {masked}"
    );
    assert!(masked.contains("***"));
    assert_eq!(
        redact_literal_secrets("xabcx", std::iter::once("abc".to_string())),
        "xabcx"
    );
}

#[test]
fn urlencode_plain_passthrough() {
    assert_eq!(urlencode("hello"), "hello");
}

#[test]
fn urlencode_spaces_become_plus() {
    assert_eq!(urlencode("hello world"), "hello+world");
}

#[test]
fn urlencode_special_chars() {
    assert_eq!(urlencode("a@b.com"), "a%40b.com");
}

#[test]
fn urlencode_unicode() {
    let encoded = urlencode("café");
    assert!(encoded.contains('%'));
    assert!(!encoded.contains("é"));
}

#[test]
fn urlencode_empty() {
    assert_eq!(urlencode(""), "");
}

#[test]
fn urlencode_slashes_and_ampersands() {
    let encoded = urlencode("a/b&c=d");
    assert!(encoded.contains("%2F"));
    assert!(encoded.contains("%26"));
    assert!(encoded.contains("%3D"));
}

fn hdrs(retry_after: Option<&str>) -> reqwest::header::HeaderMap {
    let mut h = reqwest::header::HeaderMap::new();
    if let Some(v) = retry_after {
        h.insert("retry-after", v.parse().unwrap());
    }
    h
}

#[test]
fn retry_after_uses_default_when_header_absent() {
    assert_eq!(retry_after_secs(&hdrs(None), 5, 10), 5);
}

#[test]
fn retry_after_parses_header_value() {
    assert_eq!(retry_after_secs(&hdrs(Some("3")), 5, 10), 3);
}

#[test]
fn retry_after_clamps_hostile_header_to_max() {
    assert_eq!(retry_after_secs(&hdrs(Some("600")), 5, 10), 10);
}

#[test]
fn retry_after_clamps_oversized_default_to_max() {
    assert_eq!(retry_after_secs(&hdrs(None), 99, 6), 6);
}

#[test]
fn retry_after_ignores_unparseable_header() {
    assert_eq!(retry_after_secs(&hdrs(Some("soon")), 7, 30), 7);
}

#[test]
fn redact_strips_api_key_query_param() {
    let s = "HTTP 400: Invalid request: domain=&api_key=SECRET_KEY_123";
    let r = redact_credentials(s);
    assert!(!r.contains("SECRET_KEY_123"));
    assert!(r.contains("api_key=***"));
}

#[test]
fn redact_strips_apikey_camel_case() {
    let s = "Bad URL: ?apiKey=AbCdEf123&domain=example.com";
    let r = redact_credentials(s);
    assert!(!r.contains("AbCdEf123"));
    assert!(r.contains("apiKey=***"));
}

#[test]
fn redact_strips_token_and_secret() {
    let s = "?token=THEACTUALTOKEN&secret=ALSOSECRET&other=keep";
    let r = redact_credentials(s);
    assert!(!r.contains("THEACTUALTOKEN"));
    assert!(!r.contains("ALSOSECRET"));
    assert!(r.contains("other=keep"));
}

#[test]
fn redact_preserves_non_credential_text() {
    let s = "Quota exhausted, contact support@example.com";
    let r = redact_credentials(s);
    assert_eq!(r, s);
}

#[test]
fn redact_does_not_match_substring_words() {
    let s = "monkey=banana";
    let r = redact_credentials(s);
    assert!(r.contains("monkey=banana"));
}

#[test]
fn redact_handles_multiple_credentials_on_one_line() {
    let s = "url=https://api.example.com/?api_key=KEY1&token=KEY2&apiKey=KEY3";
    let r = redact_credentials(s);
    assert!(!r.contains("KEY1"));
    assert!(!r.contains("KEY2"));
    assert!(!r.contains("KEY3"));
}

#[test]
fn redact_preserves_non_ascii_text() {
    let s = "{\"error\":\"clé API invalide — accès refusé\",\
             \"url\":\"https://api.x.com/?api_key=SECRET123456&q=café\"}";
    let r = redact_credentials(s);
    assert!(!r.contains("SECRET123456"), "credential must be redacted");
    assert!(r.contains("api_key=***"));
    assert!(r.contains("clé API invalide — accès refusé"), "got: {r}");
    assert!(r.contains("q=café"), "got: {r}");
    assert!(!r.contains('\u{FFFD}'), "no replacement chars: {r}");
}

#[test]
fn key_tail_is_char_boundary_safe() {
    assert_eq!(key_tail("abcdef123456"), "3456");
    assert_eq!(key_tail("ab"), "ab");
    assert_eq!(key_tail(""), "");
    assert_eq!(key_tail("clé"), "clé");
    assert_eq!(key_tail("k😀😀😀😀").chars().count(), 4);
}

#[test]
fn key_scan_tokeniser_bounds_query_string_keys_cleanly() {
    let body = r#"error at https://api.example.com/v1?api_key=AKIAJK28SLQQV61MNG9X&b=2"#;
    let tokens: Vec<&str> = body.split(is_key_delimiter).collect();
    assert!(
        tokens.contains(&"AKIAJK28SLQQV61MNG9X"),
        "bare key must be its own token: {tokens:?}"
    );
    assert!(
        !tokens
            .iter()
            .any(|t: &&str| t.contains('&') || t.contains('?')),
        "no token may carry query separators: {tokens:?}"
    );
    use crate::modules::oathnet_pro::key_harvest::identify_api_key;
    let (svc, val) = identify_api_key("AKIAJK28SLQQV61MNG9X").expect("real-shape AWS key");
    assert_eq!(svc, "aws");
    assert_eq!(val, "AKIAJK28SLQQV61MNG9X");
    assert!(
        identify_api_key("AKIAJK28SLQQV61MNG9X&b=2").is_some_and(|(_, v)| v.contains('&')),
        "identifier passes tokens through verbatim — the tokeniser must pre-split"
    );
    // key_tokens yields only the 20-char token, dropping the 5-char "other"
    // (below MIN_TOKEN=16) and any empty slices from adjacent delimiters.
    let csv_tokens: Vec<&str> = key_tokens("AKIAJK28SLQQV61MNG9X,other", 200).collect();
    assert_eq!(csv_tokens, vec!["AKIAJK28SLQQV61MNG9X"]);
}

#[test]
fn redact_over_masks_bare_key_param_after_boundary() {
    let r = redact_credentials("?key=sortorder&page=2");
    assert!(r.contains("key=***"), "got: {r}");
    assert!(r.contains("page=2"), "got: {r}");
}

#[tokio::test]
async fn read_text_reads_body_with_module_tagged_errors() {
    // The text counterpart to json_decode: returns the body verbatim, and (unlike
    // read_json_text) does not archive it. The cap/redaction core is shared with
    // read_json_text, exercised by the json_decode tests.
    let ok = reqwest::Response::from(
        http::Response::builder()
            .status(200)
            .body("plain text body".to_string())
            .unwrap(),
    );
    let body = super::fetch::read_text("test_mod", ok).await.unwrap();
    assert_eq!(body, "plain text body");
}
