use super::client::{build_client, build_client_with_trace};
use super::fetch::{
    JSON_BODY_CAP, fetch_json, fetch_json_or_404, fetch_json_or_absent, fetch_json_probe,
    is_keyed_error_status, key_tail, keyed_cascade, keyed_cascade_json, keyed_ok_or_404,
    parse_retry_after_secs, retry_after_secs,
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
            .expect("should succeed"),
    );
    let v: V = json_decode("test_mod", ok).await.expect("should succeed");
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
            .expect("should succeed"),
    );
    let err = json_decode::<V>("test_mod", bad)
        .await
        .expect_err("should be an error");
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
        .expect_err("should be an error");
    assert!(
        err.to_string().contains("test_mod"),
        "transport error must name the module: {err}"
    );
}

#[tokio::test]
async fn fetch_json_probe_treats_an_unreachable_domain_as_a_clean_miss() {
    // A speculative well-known probe (fediverse/nostr) against an unreachable or
    // nonexistent domain is a MISS, not a module error: `fetch_json_probe` folds
    // the transport failure into `None`. The plain `fetch_json_or_404` would
    // instead surface an `Err`, which the engine records as a `module_error` —
    // exactly the false alarm a real scan produced when a discovered email's
    // domain refused the probe connection. `.invalid` is RFC 6761-reserved, so
    // resolution is a guaranteed failure regardless of network.
    let out: Option<serde_json::Value> = fetch_json_probe(
        &reqwest::Client::new(),
        "test_mod",
        "https://nonexistent.invalid/.well-known/webfinger?resource=acct:x@nonexistent.invalid",
    )
    .await;
    assert!(
        out.is_none(),
        "an unreachable probe domain must be a clean miss (None), not an error"
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
        .expect_err("should be an error");
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
    };
    let resp = |code: u16| {
        reqwest::Response::from(
            http::Response::builder()
                .status(code)
                .body(String::new())
                .expect("should succeed"),
        )
    };

    let miss = keyed_ok_or_404("test_mod", "k", &ctx, resp(404))
        .await
        .expect("should succeed");
    assert!(miss.is_none(), "404 must classify as a miss");

    let ok = keyed_ok_or_404("test_mod", "k", &ctx, resp(200))
        .await
        .expect("should succeed");
    assert!(ok.is_some(), "2xx must hand back the response");

    let err = keyed_ok_or_404("test_mod", "k", &ctx, resp(500))
        .await
        .expect_err("should be an error");
    assert!(
        err.to_string().contains("test_mod"),
        "non-2xx error must name the module: {err}"
    );
}

#[tokio::test]
async fn fetch_keyed_json_retries_once_on_a_transient_timeout() {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::AsyncWriteExt;

    // A server whose FIRST connection is held open without replying (so the
    // client times out — a transient error) and whose SECOND connection is
    // answered immediately with a 200 JSON body. Each connection is handled in
    // its own task, so conn2 is served while conn1 is still being held — no
    // head-of-line blocking, so the timing margin is generous (not flaky).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should succeed");
    let addr = listener.local_addr().expect("should succeed");
    let count = Arc::new(AtomicUsize::new(0));
    let count_srv = count.clone();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.expect("should succeed");
            let n = count_srv.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                if n == 0 {
                    // Hold the first connection open past the client timeout,
                    // then let it drop — the client sees a timeout, not a reply.
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    let _ = sock.shutdown().await;
                } else {
                    let body = r#"{"ok":true}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                }
            });
        }
    });

    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = crate::core::module::ModuleContext {
        scan_id: "test".into(),
        bus,
        http: reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_millis(400))
            .build()
            .expect("should succeed"),
        keys: HashMap::from([("HUNTSMAN_TEST_KEY".to_string(), "k".to_string())]),
        cancel: crate::core::cancel::CancelHandle::new(),
    };

    let body: Option<serde_json::Value> = super::fetch::fetch_keyed_json(
        &ctx,
        "test_mod",
        &format!("http://{addr}/"),
        "HUNTSMAN_TEST_KEY",
        "x-api-key",
    )
    .await
    .expect("the retry must recover the transient first-attempt timeout");
    assert_eq!(body, Some(serde_json::json!({ "ok": true })));
    assert_eq!(
        count.load(Ordering::SeqCst),
        2,
        "exactly two connections: the timed-out first attempt + the retry"
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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should succeed");
    let addr = listener.local_addr().expect("should succeed");
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("should succeed");
        let mut buf = vec![0u8; 4096];
        let n = sock.read(&mut buf).await.expect("should succeed");
        let req = String::from_utf8_lossy(&buf[..n]).to_string();
        let _ = sock
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await;
        req
    });
    let client = build_client_with_trace("scan-abc123");
    let _ = client.get(format!("http://{addr}/")).send().await;
    let req = server.await.expect("should succeed").to_lowercase();
    assert!(
        req.contains("x-huntsman-trace: scan-abc123"),
        "trace header missing; raw request was:\n{req}"
    );
}

#[tokio::test]
async fn client_transparently_decompresses_a_gzip_encoded_response() {
    use std::io::Write as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // What the client must read back AFTER reqwest decompresses the body. If gzip
    // auto-decoding is off (the `gzip` feature or `.gzip(true)` missing), the
    // client would try to JSON-parse the raw gzip bytes and this fails.
    let json = r#"{"marker":"gzip-decoded-ok","n":42}"#;
    // gzip-compress it — flate2 is already a direct dependency (see `cli::cells`).
    let gz = {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(json.as_bytes()).expect("should succeed");
        e.finish().expect("should succeed")
    };
    assert!(
        gz != json.as_bytes(),
        "sanity: the served body is actually compressed"
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should succeed");
    let addr = listener.local_addr().expect("should succeed");
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("should succeed");
        let mut buf = vec![0u8; 2048];
        let _ = sock.read(&mut buf).await;
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
            gz.len()
        );
        let _ = sock.write_all(head.as_bytes()).await;
        let _ = sock.write_all(&gz).await;
        let _ = sock.flush().await;
    });

    let client = build_client();
    crate::util::circuit_breaker::record_success("127.0.0.1"); // isolate from parallel breaker state
    let v: serde_json::Value = fetch_json(&client, "test_gzip", &format!("http://{addr}/"))
        .await
        .expect("fetch_json must transparently decode a Content-Encoding: gzip body");
    assert_eq!(
        v["marker"], "gzip-decoded-ok",
        "reqwest must decompress the gzip response body before parsing"
    );
    assert_eq!(v["n"], 42);
    crate::util::circuit_breaker::record_success("127.0.0.1");
}

#[tokio::test]
async fn fetch_json_or_absent_maps_400_to_none_while_or_404_still_errors() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // A one-shot local server that answers with HTTP 400 + a Bluesky-shaped body.
    async fn serve_one_400() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("should succeed");
        let addr = listener.local_addr().expect("should succeed");
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("should succeed");
            let mut buf = vec![0u8; 2048];
            let _ = sock.read(&mut buf).await;
            let body = br#"{"error":"InvalidRequest","message":"Profile not found"}"#;
            let head = format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(body).await;
            let _ = sock.flush().await;
        });
        addr
    }

    let client = build_client();

    // fetch_json_or_absent: a 400 "not found" is a clean negative (Ok(None)) — a
    // non-existent Bluesky handle no longer trips the module breaker.
    crate::util::circuit_breaker::record_success("127.0.0.1"); // isolate from parallel tests
    let addr = serve_one_400().await;
    let absent: crate::core::error::Result<Option<serde_json::Value>> =
        fetch_json_or_absent(&client, "test_absent", &format!("http://{addr}/")).await;
    assert!(
        matches!(absent, Ok(None)),
        "400 must map to Ok(None) for fetch_json_or_absent, got {absent:?}"
    );

    // fetch_json_or_404: a 400 is NOT a 404, so it stays a visible module error.
    crate::util::circuit_breaker::record_success("127.0.0.1");
    let addr = serve_one_400().await;
    let errored: crate::core::error::Result<Option<serde_json::Value>> =
        fetch_json_or_404(&client, "test_404", &format!("http://{addr}/")).await;
    assert!(
        errored.is_err(),
        "400 must remain an error for the 404-only helper, got {errored:?}"
    );
}

#[tokio::test]
async fn fetch_json_propagates_a_non_2xx_status_as_err_not_a_silent_default() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // `fetch_json` (unlike `fetch_json_or_404`/`fetch_json_or_absent`) has no
    // absent-status list at all — every non-2xx status is an error. This is
    // the exact contract callers rely on when they propagate it with a bare
    // `?` instead of collapsing every `Err` into an empty success shape (the
    // T2.115 defect class: psbdmp and ~9 other modules replaced `match {
    // Ok(r) => r, Err(_) => return Ok(empty) }` with `fetch_json(...).await?`
    // on the strength of this contract). A genuine fetch/status failure must
    // surface as `Err`, never be silently indistinguishable from a real
    // "nothing found" result.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should succeed");
    let addr = listener.local_addr().expect("should succeed");
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("should succeed");
        let mut buf = vec![0u8; 2048];
        let _ = sock.read(&mut buf).await;
        let body = b"{}";
        let head = format!(
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let _ = sock.write_all(head.as_bytes()).await;
        let _ = sock.write_all(body).await;
        let _ = sock.flush().await;
    });

    let client = build_client();
    crate::util::circuit_breaker::record_success("127.0.0.1"); // isolate from parallel tests
    let result: crate::core::error::Result<serde_json::Value> =
        fetch_json(&client, "test_plain", &format!("http://{addr}/")).await;
    assert!(
        result.is_err(),
        "fetch_json must propagate a non-2xx status as Err, got {result:?}"
    );
    // The 500 response above recorded a breaker failure for "127.0.0.1" —
    // reset it so this test doesn't nudge an unrelated later test toward the
    // shared host's FAILURE_THRESHOLD, symmetric with the isolation reset above.
    crate::util::circuit_breaker::record_success("127.0.0.1");
}

#[tokio::test]
async fn fetch_json_or_404_maps_404_to_none_but_propagates_5xx_as_err() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // The exact contract the nine Social profile modules (`bitbucket_user` +
    // 8 others) rely on after T2.117: a genuine 404 is the platform's "no such
    // user" clean miss (`Ok(None)`), while a 429/5xx/transport failure is a real
    // outage that MUST surface as `Err` — never be collapsed into the same empty
    // result as the clean miss (the fake-404 defect that
    // `Ok(None) | Err(_) => return Ok(empty)` produced). Those modules' own
    // `process()` hardcodes a live HTTPS host (no URL seam to mock), so the split
    // they now depend on is pinned here at the primitive layer, hermetically, on
    // loopback. Sibling of `fetch_json_propagates_a_non_2xx_status_as_err_...`
    // above, which pins the no-absent-list `fetch_json` variant for the T2.115
    // (psbdmp) case; this one pins the 404-is-absent `fetch_json_or_404` variant.
    async fn serve_once(status: u16, reason: &'static str) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("should succeed");
        let addr = listener.local_addr().expect("should succeed");
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("should succeed");
            let mut buf = vec![0u8; 2048];
            let _ = sock.read(&mut buf).await;
            let body = b"{}";
            let head = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(body).await;
            let _ = sock.flush().await;
        });
        addr
    }

    let client = build_client();

    // 404 → Ok(None): the genuine "not on this platform" clean miss stays a miss.
    crate::util::circuit_breaker::record_success("127.0.0.1"); // isolate from parallel tests
    let addr = serve_once(404, "Not Found").await;
    let miss: crate::core::error::Result<Option<serde_json::Value>> =
        fetch_json_or_404(&client, "test_404_miss", &format!("http://{addr}/")).await;
    assert!(
        matches!(miss, Ok(None)),
        "a genuine 404 must map to Ok(None), got {miss:?}"
    );

    // 503 → Err: a real outage must NOT masquerade as the clean miss.
    crate::util::circuit_breaker::record_success("127.0.0.1");
    let addr = serve_once(503, "Service Unavailable").await;
    let outage: crate::core::error::Result<Option<serde_json::Value>> =
        fetch_json_or_404(&client, "test_404_outage", &format!("http://{addr}/")).await;
    assert!(
        outage.is_err(),
        "a 503 must propagate as Err, not Ok(None), got {outage:?}"
    );
    // The 503 recorded a breaker failure for the shared loopback host — reset it
    // so this test can't nudge a later parallel test toward FAILURE_THRESHOLD.
    crate::util::circuit_breaker::record_success("127.0.0.1");
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
    .map(|x| x.parse().expect("should succeed"))
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
        h.insert("retry-after", v.parse().expect("should succeed"));
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
fn parse_retry_after_secs_matches_the_header_map_variant_it_was_extracted_from() {
    // parse_retry_after_secs exists so a non-reqwest HTTP client (a raw curl
    // subprocess) can honour a real Retry-After too — pin that it behaves
    // identically to retry_after_secs given the equivalent extracted value,
    // so the two never silently drift apart.
    assert_eq!(parse_retry_after_secs(None, 5, 10), 5);
    assert_eq!(parse_retry_after_secs(Some("3"), 5, 10), 3);
    assert_eq!(parse_retry_after_secs(Some("600"), 5, 10), 10);
    assert_eq!(parse_retry_after_secs(None, 99, 6), 6);
    assert_eq!(parse_retry_after_secs(Some("soon"), 7, 30), 7);
    assert_eq!(
        parse_retry_after_secs(Some(" 12 "), 5, 30),
        12,
        "trims whitespace"
    );
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
    use crate::util::key_harvest::identify_api_key;
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
            .expect("should succeed"),
    );
    let body = super::fetch::read_text("test_mod", ok)
        .await
        .expect("should succeed");
    assert_eq!(body, "plain text body");
}

// ── keyed_cascade — the general-request-shape cascade `onyphe`/`threatfox`
// migrated onto in place of their own hand-rolled 'cascade loop. ──────────

fn cascade_ctx(http: reqwest::Client) -> crate::core::module::ModuleContext {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    crate::core::module::ModuleContext {
        scan_id: "test".into(),
        bus,
        http,
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    }
}

#[tokio::test]
async fn keyed_cascade_returns_the_response_on_success() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should succeed");
    let addr = listener.local_addr().expect("should succeed");
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("should succeed");
        let mut buf = vec![0u8; 2048];
        let _ = sock.read(&mut buf).await;
        let body = b"{\"ok\":true}";
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let _ = sock.write_all(head.as_bytes()).await;
        let _ = sock.write_all(body).await;
        let _ = sock.flush().await;
    });

    let ctx = cascade_ctx(build_client());
    let url = format!("http://{addr}/");
    let resp = keyed_cascade(&ctx, "test_cascade_ok", "k1", &[], |key| {
        ctx.http.get(&url).header("X-Key", key)
    })
    .await
    .expect("must not error")
    .expect("a 2xx response must come back Some");
    assert!(resp.status().is_success());
}

#[tokio::test]
async fn keyed_cascade_maps_a_listed_status_to_absent_but_errors_on_an_unlisted_one() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn serve_404() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("should succeed");
        let addr = listener.local_addr().expect("should succeed");
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("should succeed");
            let mut buf = vec![0u8; 2048];
            let _ = sock.read(&mut buf).await;
            let _ = sock
                .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                .await;
            let _ = sock.flush().await;
        });
        addr
    }

    // `absent_statuses` names 404 — ONYPHE's shape — so it maps to Ok(None),
    // not an error, exactly as ONYPHE's own migrated call site now relies on.
    let ctx = cascade_ctx(build_client());
    let addr = serve_404().await;
    let url = format!("http://{addr}/");
    let absent = keyed_cascade(&ctx, "test_cascade_absent", "k1", &[404], |key| {
        ctx.http.get(&url).header("X-Key", key)
    })
    .await
    .expect("a listed absent status must not be an error");
    assert!(absent.is_none(), "404 in absent_statuses must map to None");

    // The identical 404, with an EMPTY absent_statuses list — ThreatFox's
    // shape, which never special-cased 404 before this consolidation — must
    // still be a hard error, not silently swallowed into None.
    let addr2 = serve_404().await;
    let url2 = format!("http://{addr2}/");
    let errored = keyed_cascade(&ctx, "test_cascade_no_absent", "k1", &[], |key| {
        ctx.http.get(&url2).header("X-Key", key)
    })
    .await;
    assert!(
        errored.is_err(),
        "404 not in absent_statuses must remain an Err, matching threatfox's pre-migration behaviour: {errored:?}"
    );
}

#[tokio::test]
async fn keyed_cascade_gives_up_cleanly_on_401_with_no_extra_pooled_key() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should succeed");
    let addr = listener.local_addr().expect("should succeed");
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let hits_srv = hits.clone();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("should succeed");
        let mut buf = vec![0u8; 2048];
        let _ = sock.read(&mut buf).await;
        hits_srv.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let _ = sock
            .write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
            .await;
        let _ = sock.flush().await;
    });

    // A fresh, never-`pool.add()`-ed service name: the global key pool holds
    // nothing for it, so `next_pooled_key` returns None on the first burn —
    // the documented single-key-service behaviour every hand-rolled cascade
    // (and now this primitive) falls back to.
    let ctx = cascade_ctx(build_client());
    let url = format!("http://{addr}/");
    let result = keyed_cascade(&ctx, "test_cascade_401_noextra", "only-key", &[], |key| {
        ctx.http.get(&url).header("X-Key", key)
    })
    .await;
    assert!(
        result.is_err(),
        "a terminal 401 with no rotation target must be Err"
    );
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "401 is not retried in place — exactly one request"
    );
}

#[tokio::test]
async fn keyed_cascade_retries_the_same_key_once_on_429_before_succeeding() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should succeed");
    let addr = listener.local_addr().expect("should succeed");
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let hits_srv = hits.clone();
    tokio::spawn(async move {
        for _ in 0..2 {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 2048];
            let _ = sock.read(&mut buf).await;
            let n = hits_srv.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                let body = b"{}";
                // Retry-After: 0 — a real header the retry path still parses
                // and honours, just without paying an actual wall-clock
                // second in the test suite for it.
                let head = format!(
                    "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 0\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body).await;
            } else {
                let body = b"{\"ok\":true}";
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body).await;
            }
            let _ = sock.flush().await;
        }
    });

    let ctx = cascade_ctx(build_client());
    let url = format!("http://{addr}/");
    let resp = keyed_cascade(&ctx, "test_cascade_429_retry", "same-key", &[], |key| {
        ctx.http.get(&url).header("X-Key", key)
    })
    .await
    .expect("must recover on the in-place retry")
    .expect("the retried request must succeed");
    assert!(resp.status().is_success());
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "exactly two attempts: the 429 + the retry that recovers, both on the same key"
    );
}

#[tokio::test]
async fn keyed_cascade_stops_before_any_request_when_already_cancelled() {
    // Point at a port nothing listens on: if the cancellation check didn't
    // fire first, this would be a connection-refused Err, not Ok(None) — the
    // two outcomes are distinguishable, so this proves the check runs before
    // the network attempt rather than merely happening to return early.
    let ctx = cascade_ctx(build_client());
    ctx.cancel.cancel();
    let result = keyed_cascade(&ctx, "test_cascade_cancelled", "k1", &[], |key| {
        ctx.http.get("http://127.0.0.1:1/").header("X-Key", key)
    })
    .await
    .expect("a cancelled scan must not surface as an error");
    assert!(result.is_none(), "cancellation must short-circuit to None");
}

#[tokio::test]
async fn keyed_cascade_json_reads_the_verdict_from_a_200_body() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Serve a 200 whose BODY carries the provider's own status — the shape
    // criminal_ip and ipqs use to report a dead key. A status-only cascade
    // cannot see this, which is the whole reason keyed_cascade_json exists.
    async fn serve_200(body: &'static str) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("should succeed");
        let addr = listener.local_addr().expect("should succeed");
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("should succeed");
            let mut buf = vec![0u8; 2048];
            let _ = sock.read(&mut buf).await;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(body.as_bytes()).await;
            let _ = sock.flush().await;
        });
        addr
    }

    #[derive(serde::Deserialize, Debug)]
    struct Body {
        status: Option<i64>,
    }

    let ctx = cascade_ctx(build_client());

    // Accept: the body reports success, so the decoded value comes back.
    let addr = serve_200(r#"{"status":200}"#).await;
    let url = format!("http://{addr}/");
    let out: Option<Body> = keyed_cascade_json(
        &ctx,
        "test_verdict_accept",
        "k1",
        &[],
        |key| ctx.http.get(&url).header("X-Key", key),
        |b: &Body| match b.status {
            Some(200) => super::fetch::BodyVerdict::Accept,
            Some(401) => super::fetch::BodyVerdict::KeyFailure {
                code: 401,
                detail: Some("quota exceeded for this plan".to_string()),
            },
            _ => super::fetch::BodyVerdict::Absent,
        },
    )
    .await
    .expect("a 200 body verdicted Accept must not error");
    assert_eq!(out.map(|b| b.status), Some(Some(200)));

    // KeyFailure on a 200: no untried pooled key exists for this fresh service
    // name, so it must surface as Err rather than being mistaken for a clean
    // empty result — the exact regression this primitive prevents.
    let addr = serve_200(r#"{"status":401}"#).await;
    let url = format!("http://{addr}/");
    let failed: Result<Option<Body>, _> = keyed_cascade_json(
        &ctx,
        "test_verdict_keyfail",
        "k1",
        &[],
        |key| ctx.http.get(&url).header("X-Key", key),
        |b: &Body| match b.status {
            Some(200) => super::fetch::BodyVerdict::Accept,
            Some(401) => super::fetch::BodyVerdict::KeyFailure {
                code: 401,
                detail: Some("quota exceeded for this plan".to_string()),
            },
            _ => super::fetch::BodyVerdict::Absent,
        },
    )
    .await;
    let err = failed
        .expect_err("an in-body key failure with no rotation target must be Err, not empty Ok");
    // The provider's OWN words must survive to the terminal error: the status
    // code alone cannot distinguish quota from auth from plan limit, so
    // summarising the detail away would leave the operator unable to act.
    assert!(
        err.to_string().contains("quota exceeded for this plan"),
        "the provider's message must reach the error verbatim, got: {err}"
    );

    // Absent: a genuine per-query miss reported in-body is Ok(None), NOT an error.
    let addr = serve_200(r#"{"status":404}"#).await;
    let url = format!("http://{addr}/");
    let absent: Option<Body> = keyed_cascade_json(
        &ctx,
        "test_verdict_absent",
        "k1",
        &[],
        |key| ctx.http.get(&url).header("X-Key", key),
        |b: &Body| match b.status {
            Some(200) => super::fetch::BodyVerdict::Accept,
            Some(401) => super::fetch::BodyVerdict::KeyFailure {
                code: 401,
                detail: Some("quota exceeded for this plan".to_string()),
            },
            _ => super::fetch::BodyVerdict::Absent,
        },
    )
    .await
    .expect("a genuine in-body miss must not error");
    assert!(absent.is_none(), "Absent verdict must yield Ok(None)");
}
