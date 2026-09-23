use super::client::{build_client, build_client_with_timeout, build_client_with_trace};
use super::fetch::{
    JSON_BODY_CAP, KeyedAnswer, fetch_json, fetch_json_or_404, fetch_json_or_absent,
    fetch_json_probe, is_keyed_error_status, key_tail, keyed_answer, keyed_cascade,
    keyed_cascade_json, keyed_ok_or_404, ok_or_absent, parse_retry_after_secs, read_body_capped,
    read_body_capped_or_fail, retry_after_secs,
};
use super::redact::{pool_secret_values, redact_credentials, redact_literal_secrets};
use super::ssrf::{
    MAX_REDIRECT_HOPS, RedirectVerdict, filter_public, redirect_to_private_ip, redirect_verdict,
};
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

/// The fail-closed contract this helper exists to enforce: only a status the caller
/// declared as absence becomes `Ok(None)`. The refusal statuses that the modules used
/// to fold into an empty result — 403 scraper block, 429 throttle, 5xx outage — must
/// come back as `Err`, naming the module, so a refusal can never be read as a negative
/// claim about the subject.
#[tokio::test]
async fn ok_or_absent_separates_declared_absence_from_refusal() {
    let resp = |code: u16| {
        reqwest::Response::from(
            http::Response::builder()
                .status(code)
                .body(String::new())
                .expect("should succeed"),
        )
    };

    assert!(
        ok_or_absent("test_mod", resp(200), &[404])
            .await
            .expect("2xx is not an error")
            .is_some(),
        "a 2xx must be handed back for the caller to read"
    );

    assert!(
        ok_or_absent("test_mod", resp(404), &[404])
            .await
            .expect("a declared absent status is not an error")
            .is_none(),
        "a declared absent status must be a clean miss"
    );

    // The regression this helper was added for.
    for code in [403, 429, 500, 502, 503] {
        let err = ok_or_absent("test_mod", resp(code), &[404])
            .await
            .expect_err("a refusal must not be reported as absence");
        assert!(
            err.to_string().contains("test_mod"),
            "the error must name the module: {err}"
        );
    }

    // `&[]` — the endpoint signals a miss inside a 200 body, so even 404 is a failure.
    assert!(
        ok_or_absent("test_mod", resp(404), &[]).await.is_err(),
        "with no declared absent status, 404 is a failure like any other non-2xx"
    );
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
    let v: serde_json::Value = fetch_json(&client, "test_gzip", &format!("http://{addr}/"))
        .await
        .expect("fetch_json must transparently decode a Content-Encoding: gzip body");
    assert_eq!(
        v["marker"], "gzip-decoded-ok",
        "reqwest must decompress the gzip response body before parsing"
    );
    assert_eq!(v["n"], 42);
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
    let addr = serve_one_400().await;
    let absent: crate::core::error::Result<Option<serde_json::Value>> =
        fetch_json_or_absent(&client, "test_absent", &format!("http://{addr}/")).await;
    assert!(
        matches!(absent, Ok(None)),
        "400 must map to Ok(None) for fetch_json_or_absent, got {absent:?}"
    );

    // fetch_json_or_404: a 400 is NOT a 404, so it stays a visible module error.
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
    let result: crate::core::error::Result<serde_json::Value> =
        fetch_json(&client, "test_plain", &format!("http://{addr}/")).await;
    assert!(
        result.is_err(),
        "fetch_json must propagate a non-2xx status as Err, got {result:?}"
    );
    // No breaker reset needed: REQ-BREAKER-001 keys the breaker on host AND
    // port, so this server's 500 lands on its own ephemeral endpoint and cannot
    // reach a sibling test's server on 127.0.0.1.
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
    let addr = serve_once(404, "Not Found").await;
    let miss: crate::core::error::Result<Option<serde_json::Value>> =
        fetch_json_or_404(&client, "test_404_miss", &format!("http://{addr}/")).await;
    assert!(
        matches!(miss, Ok(None)),
        "a genuine 404 must map to Ok(None), got {miss:?}"
    );

    // 503 → Err: a real outage must NOT masquerade as the clean miss.
    let addr = serve_once(503, "Service Unavailable").await;
    let outage: crate::core::error::Result<Option<serde_json::Value>> =
        fetch_json_or_404(&client, "test_404_outage", &format!("http://{addr}/")).await;
    assert!(
        outage.is_err(),
        "a 503 must propagate as Err, not Ok(None), got {outage:?}"
    );
    // Each `serve_once` above bound its own port, so the 404 and the 503 keyed
    // separate breakers and neither can reach a parallel test's server
    // (REQ-BREAKER-001). No reset needed.
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

/// `app::cells::download_and_import` (the OpenCelliD bulk downloader) used to
/// build a bare `reqwest::Client`, bypassing every guard in `client_builder()`
/// — including this redirect policy. Its own doc comments already treat a
/// compromised/malicious upstream as in-scope threat model (hence the
/// download's byte cap), so a redirect onto a private address is exactly the
/// vector `build_client_with_timeout` must close now that the call site uses
/// it. Proven directly here since `download_and_import` itself has no mock
/// server harness to exercise this behaviour at its own call site.
#[tokio::test]
async fn build_client_with_timeout_refuses_a_redirect_to_a_private_ip() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let internal = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should succeed");
    let internal_addr = internal.local_addr().expect("should succeed");
    let internal_hits = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let internal_hits_srv = internal_hits.clone();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = internal.accept().await {
            internal_hits_srv.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut buf = vec![0u8; 2048];
            let _ = sock.read(&mut buf).await;
            let body = b"internal secret";
            let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(body).await;
            let _ = sock.flush().await;
        }
    });

    let evil = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should succeed");
    let evil_addr = evil.local_addr().expect("should succeed");
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = evil.accept().await {
            let mut buf = vec![0u8; 2048];
            let _ = sock.read(&mut buf).await;
            let head = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{internal_addr}/\r\nContent-Length: 0\r\n\r\n"
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.flush().await;
        }
    });

    let client = build_client_with_timeout(std::time::Duration::from_secs(5));
    let resp = client
        .get(format!("http://{evil_addr}/"))
        .send()
        .await
        .expect("the guard surfaces the un-followed redirect response, not a request error");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FOUND,
        "the guard must return the un-followed 3xx itself rather than continuing to follow it"
    );
    assert_eq!(
        internal_hits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the private-IP redirect target must never be reached"
    );
}

// ── REQ-HTTP-003: a credential must not replay to a destination the caller
// did not choose ──────────────────────────────────────────────────────────
//
// reqwest copies the original request's headers onto every followed hop, and
// HSE's providers authenticate with headers (`x-api-key`, `Authorization`, …).
// Before this, the policy judged only the private-IP arm, so any endpoint HSE
// queries could answer `302 Location: https://attacker.example/collect` and be
// handed the live provider key.
//
// These judge `redirect_verdict` directly rather than through a client. They
// have to: the private-IP arm refuses every loopback address, so a test server
// on 127.0.0.1 is stopped before the credential arms are reached — a
// client-level test of those arms passes identically on a build with them
// deleted, and proves nothing. (That the closure runs at all is covered by
// `build_client_with_timeout_refuses_a_redirect_to_a_private_ip` above; the
// closure has no logic of its own beyond translating this verdict.)

fn u(s: &str) -> url::Url {
    url::Url::parse(s).expect("test URL parses")
}

#[test]
fn redirect_verdict_follows_a_same_host_hop() {
    assert_eq!(
        redirect_verdict(
            &[u("https://api.example.com/v1/lookup")],
            &u("https://api.example.com/v2/lookup")
        ),
        RedirectVerdict::Follow,
        "a provider moving its own endpoint is the ordinary case and must still work"
    );
}

#[test]
fn redirect_verdict_follows_a_same_host_hop_on_a_different_port_or_upgraded_scheme() {
    assert_eq!(
        redirect_verdict(
            &[u("https://api.example.com/v1")],
            &u("https://api.example.com:8443/v1")
        ),
        RedirectVerdict::Follow,
        "another port on the same host is the same operator — not a leak"
    );
    assert_eq!(
        redirect_verdict(
            &[u("http://api.example.com/v1")],
            &u("https://api.example.com/v1")
        ),
        RedirectVerdict::Follow,
        "http -> https is an upgrade; refusing it would break plain-http entry points"
    );
}

#[test]
fn redirect_verdict_stops_a_hop_to_a_different_host() {
    // The defect itself: the baseline returned Follow here and replayed the
    // caller's `x-api-key` to attacker.example.
    assert_eq!(
        redirect_verdict(
            &[u("https://api.example.com/v1/lookup")],
            &u("https://attacker.example/collect")
        ),
        RedirectVerdict::Stop,
        "a 3xx to a host the caller never chose must not carry the caller's key"
    );
    assert_eq!(
        redirect_verdict(
            &[u("https://api.example.com/v1")],
            &u("https://api.example.com.attacker.example/v1")
        ),
        RedirectVerdict::Stop,
        "a suffix-extended look-alike host is a different registrable domain"
    );
}

#[test]
fn redirect_verdict_stops_ofacs_hop_to_its_presigned_s3_object() {
    // REQ-OFAC-002 records WHY `sanctions_ofac` takes its own, gated hop: the
    // shared rule stops Treasury's 302 to a pre-signed S3 URL (a different
    // site), and it must keep doing so — loosening it for one keyless public
    // download would reopen the credential-replay hole for every keyed caller.
    assert_eq!(
        redirect_verdict(
            &[u(
                "https://sanctionslistservice.ofac.treas.gov/api/download/SDN.CSV"
            )],
            &u(
                "https://wc2h-sls-prod-public-published.s3.us-gov-west-1.amazonaws.com/Published/SDN.CSV?X-Amz-Expires=3600"
            )
        ),
        RedirectVerdict::Stop
    );
}

#[test]
fn redirect_verdict_follows_the_apex_to_www_hop_real_sites_depend_on() {
    // Measured, not assumed: of ten real sites HSE fetches, five serve their
    // content only through a cross-HOST redirect. Judging by host instead of by
    // registrable domain would have broken all five to close a hole that only
    // exists for credentialed requests — the credential stays inside the same
    // registrant's namespace on every one of these.
    for (from, to) in [
        (
            "https://reddit.com/robots.txt",
            "https://www.reddit.com/robots.txt",
        ),
        (
            "https://nytimes.com/robots.txt",
            "https://www.nytimes.com/robots.txt",
        ),
        (
            "https://bbc.com/robots.txt",
            "https://www.bbc.com/robots.txt",
        ),
        (
            "https://amazon.com/robots.txt",
            "https://www.amazon.com/robots.txt",
        ),
        (
            "https://wikipedia.org/robots.txt",
            "https://en.wikipedia.org/robots.txt",
        ),
    ] {
        assert_eq!(
            redirect_verdict(&[u(from)], &u(to)),
            RedirectVerdict::Follow,
            "{from} -> {to} is a real, observed hop within one registrant's namespace"
        );
    }
    // The same-site rule holds under a multi-label public suffix too.
    assert_eq!(
        redirect_verdict(
            &[u("https://example.com.au/a")],
            &u("https://www.example.com.au/a")
        ),
        RedirectVerdict::Follow,
        "example.com.au and www.example.com.au are one registrable domain"
    );
}

#[test]
fn redirect_verdict_stops_a_hop_between_two_registrants_under_one_public_suffix() {
    // REQ-PSL-001: FAILS on the 39-entry suffix table. It held no `com.vn`, so
    // `api.provider.com.vn` and `attacker.com.vn` both reduced to the
    // "registrable domain" `com.vn`, the hop was judged same-site, and the
    // caller's provider key replayed to a different registrant. The same held
    // for every suffix the table lacked and for every shared-hosting suffix.
    for (from, to) in [
        (
            "https://api.provider.com.vn/v1/lookup",
            "https://attacker.com.vn/collect",
        ),
        (
            "https://api.provider.co.kr/v1",
            "https://attacker.co.kr/collect",
        ),
        (
            "https://provider.github.io/api",
            "https://attacker.github.io/collect",
        ),
    ] {
        assert_eq!(
            redirect_verdict(&[u(from)], &u(to)),
            RedirectVerdict::Stop,
            "{from} -> {to} leaves one registrant for another"
        );
    }
    // Control: within ONE Vietnamese registrant the hop is still followed.
    assert_eq!(
        redirect_verdict(
            &[u("https://provider.com.vn/v1")],
            &u("https://api.provider.com.vn/v1")
        ),
        RedirectVerdict::Follow,
        "provider.com.vn and api.provider.com.vn are one registrable domain"
    );
}

#[test]
fn redirect_verdict_compares_ip_literals_exactly_never_by_registrable_domain() {
    // `registrable_domain` is a name helper: its last-two-labels rule reads
    // 10.20.30.40 and 99.88.30.40 as the same "site" (30.40). Routing IP
    // literals through it would reopen the leak between two unrelated public
    // addresses, so they are compared exactly.
    // Both public — a private literal would be refused by the SSRF arm first
    // and would not exercise the site comparison at all.
    assert_eq!(
        redirect_verdict(
            &[u("https://93.184.216.34/v1")],
            &u("https://8.8.216.34/v1")
        ),
        RedirectVerdict::Stop,
        "two unrelated public IPs share trailing octets (216.34) but are not one site"
    );
    assert_eq!(
        redirect_verdict(
            &[u("https://93.184.216.34/v1")],
            &u("https://93.184.216.34/v2")
        ),
        RedirectVerdict::Follow,
        "the same IP literal is the same site"
    );
    assert_eq!(
        redirect_verdict(
            &[u("https://93.184.216.34/v1")],
            &u("https://example.com/v1")
        ),
        RedirectVerdict::Stop,
        "an IP literal and a name are never the same site, even if the name resolves there"
    );
}

#[test]
fn redirect_verdict_judges_the_original_request_host_not_the_previous_hop() {
    // Laundering attempt: hop within the provider's own host, then off it. The
    // comparison is against `previous[0]` — the request whose headers the caller
    // chose — so the last hop is still judged against api.example.com.
    let chain = [
        u("https://api.example.com/v1"),
        u("https://api.example.com/v2"),
    ];
    assert_eq!(
        redirect_verdict(&chain, &u("https://api.example.com/v3")),
        RedirectVerdict::Follow,
        "several hops within the provider's own host stay legitimate"
    );
    assert_eq!(
        redirect_verdict(&chain, &u("https://attacker.example/collect")),
        RedirectVerdict::Stop,
        "an intermediate same-host hop must not launder a later cross-host one"
    );
}

#[test]
fn redirect_verdict_stops_an_https_to_http_downgrade_on_the_same_host() {
    // Same host, so the host arm allows it — but following would put the same
    // live key on the wire in plaintext for any on-path observer.
    assert_eq!(
        redirect_verdict(
            &[u("https://api.example.com/v1")],
            &u("http://api.example.com/v1")
        ),
        RedirectVerdict::Stop,
        "a transport downgrade leaks the key to any on-path observer"
    );
}

#[test]
fn redirect_verdict_stops_a_hop_to_a_private_ip() {
    // The pre-existing SSRF arm, at the layer that now owns the decision.
    assert_eq!(
        redirect_verdict(
            &[u("https://api.example.com/v1")],
            &u("http://169.254.169.254/latest/meta-data/")
        ),
        RedirectVerdict::Stop,
        "cloud-metadata redirect hop"
    );
    assert_eq!(
        redirect_verdict(&[u("https://api.example.com/v1")], &u("http://[::1]/")),
        RedirectVerdict::Stop,
        "IPv6 loopback literal, brackets and all"
    );
}

#[test]
fn redirect_verdict_errors_past_the_hop_cap() {
    let chain: Vec<url::Url> = (0..MAX_REDIRECT_HOPS)
        .map(|i| u(&format!("https://api.example.com/hop{i}")))
        .collect();
    assert_eq!(
        redirect_verdict(&chain, &u("https://api.example.com/hop-next")),
        RedirectVerdict::TooManyHops,
        "the cap is an error, not a silent stop — a redirect loop must be visible"
    );
    assert_eq!(
        redirect_verdict(
            &chain[..MAX_REDIRECT_HOPS - 1],
            &u("https://api.example.com/x")
        ),
        RedirectVerdict::Follow,
        "one hop below the cap is still followed"
    );
}

#[test]
fn redirect_verdict_stops_a_hop_that_has_no_host_at_all() {
    // Fail closed. `data:`/`file:` have no host, so they can never match the
    // origin's — the comparison must not treat "no host" as "same host".
    assert_eq!(
        redirect_verdict(
            &[u("https://api.example.com/v1")],
            &u("data:text/plain,leak")
        ),
        RedirectVerdict::Stop,
        "a hostless hop is never the origin host"
    );
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

/// REQ-CRED-002: all-lowercase `apikey=` (Thunderforest's documented query
/// parameter) is masked — the case-sensitive `apiKey=` entry does not fold it,
/// and the bare `key=` entry cannot reach it past the `i` boundary. A mid-word
/// `xapikey=` still does not trip.
#[test]
fn redact_strips_lowercase_apikey() {
    let s = "tile https://tile.example.invalid/1/2/3.png?apikey=0123abcd4567ef89 failed";
    let r = redact_credentials(s);
    assert!(!r.contains("0123abcd4567ef89"), "got: {r}");
    assert!(r.contains("?apikey=*** failed"), "got: {r}");
    assert_eq!(redact_credentials("xapikey=visible"), "xapikey=visible");
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

/// An env var no `ServiceDef` owns, for the cascade tests that exercise the
/// request loop rather than the pool: nothing is pooled under it, so
/// `next_pooled_key` answers `None` exactly as it does for a single-key setup.
const UNREGISTERED_KEY_ENV: &str = "HUNTSMAN_TEST_KEY";

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
    let resp = keyed_cascade(
        &ctx,
        "test_cascade_ok",
        UNREGISTERED_KEY_ENV,
        "k1",
        &[],
        |key| ctx.http.get(&url).header("X-Key", key),
    )
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
    let absent = keyed_cascade(
        &ctx,
        "test_cascade_absent",
        UNREGISTERED_KEY_ENV,
        "k1",
        &[404],
        |key| ctx.http.get(&url).header("X-Key", key),
    )
    .await
    .expect("a listed absent status must not be an error");
    assert!(absent.is_none(), "404 in absent_statuses must map to None");

    // The identical 404, with an EMPTY absent_statuses list — ThreatFox's
    // shape, which never special-cased 404 before this consolidation — must
    // still be a hard error, not silently swallowed into None.
    let addr2 = serve_404().await;
    let url2 = format!("http://{addr2}/");
    let errored = keyed_cascade(
        &ctx,
        "test_cascade_no_absent",
        UNREGISTERED_KEY_ENV,
        "k1",
        &[],
        |key| ctx.http.get(&url2).header("X-Key", key),
    )
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
    let result = keyed_cascade(
        &ctx,
        "test_cascade_401_noextra",
        UNREGISTERED_KEY_ENV,
        "only-key",
        &[],
        |key| ctx.http.get(&url).header("X-Key", key),
    )
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
    let resp = keyed_cascade(
        &ctx,
        "test_cascade_429_retry",
        UNREGISTERED_KEY_ENV,
        "same-key",
        &[],
        |key| ctx.http.get(&url).header("X-Key", key),
    )
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
    let result = keyed_cascade(
        &ctx,
        "test_cascade_cancelled",
        UNREGISTERED_KEY_ENV,
        "k1",
        &[],
        |key| ctx.http.get("http://127.0.0.1:1/").header("X-Key", key),
    )
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
        UNREGISTERED_KEY_ENV,
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
        UNREGISTERED_KEY_ENV,
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
        UNREGISTERED_KEY_ENV,
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

// ── REQ-KEYREG-001: a burned key reaches the pool its env var names ─────────
//
// The shared keyed helpers used their `module` argument as the pool's service
// name. For `ip_reputation` (whose OTX key pools as `alienvault_otx`), and for
// every caller of a def-less credential, each `report_key_exhausted` was a
// silent no-op and `next_pooled_key` always answered `None`: a burned key
// never changed state and never rotated. These drive the real request path
// against a loopback server with keys pooled in the process-global pool, and
// assert where the burn landed. Each test owns one pool service no other test
// touches, and its key values carry the pid and thread, so no parallel test
// can hand the cascade a key of its own.

/// A context whose client reaches the loopback server directly, holding
/// `first` under `key_env` — the hot-injected key a module starts on.
fn pooled_ctx(key_env: &str, first: &str) -> crate::core::module::ModuleContext {
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("client");
    let mut ctx = cascade_ctx(client);
    ctx.keys.insert(key_env.to_string(), first.to_string());
    ctx
}

/// Pool `n` fresh usable keys under `service` and return them in order.
fn pool_keys(service: &str, n: usize) -> Vec<String> {
    let pool = crate::util::key_pool::global_pool();
    let tag = format!("{}-{:?}", std::process::id(), std::thread::current().id());
    (0..n)
        .map(|i| {
            let k = format!("keyreg-{service}-{i}-{tag}");
            assert!(
                pool.add(service, crate::util::key_pool::KeyEntry::new(k.clone())),
                "fixture: `{service}` must be a poolable service and {k} new"
            );
            k
        })
        .collect()
}

fn pool_status(service: &str, key: &str) -> Option<crate::util::key_pool::KeyStatus> {
    crate::util::key_pool::global_pool().entry_status(service, key)
}

/// REQ-KEYREG-001. `ip_reputation` calls `fetch_keyed_json` with its own name,
/// and its OTX key pools as `alienvault_otx`. A rejected key must be marked
/// in THAT pool and the call must rotate to the next pooled key. Once every
/// key is burned, the error still names the module, not the pool: the pool
/// name is resolved for the pool alone and never relabels an operator-facing
/// error.
#[tokio::test]
async fn fetch_keyed_json_burns_and_rotates_in_the_pool_its_key_env_names() {
    use crate::util::http::test_server::{Canned, serve_recording};
    use crate::util::key_pool::KeyStatus;
    const ENV: &str = "HUNTSMAN_ALIENVAULT_KEY";
    let keys = pool_keys("alienvault_otx", 2);
    let (base, requests) = serve_recording(vec![
        Canned::json(403, r#"{"detail": "Authentication required"}"#),
        Canned::json(200, r#"{"ok":true}"#),
        Canned::json(401, "{}"),
        Canned::json(401, "{}"),
    ])
    .await;
    let ctx = pooled_ctx(ENV, &keys[0]);
    let url = format!("{base}/api/v1/indicators/IPv4/192.0.2.1/general");

    let body: Option<serde_json::Value> =
        super::fetch::fetch_keyed_json(&ctx, "ip_reputation", &url, ENV, "X-OTX-API-KEY")
            .await
            .expect("the cascade must recover on the second pooled key");
    assert_eq!(
        pool_status("alienvault_otx", &keys[0]),
        Some(KeyStatus::Invalid),
        "the refused key must be marked in the pool its env var names"
    );
    assert_eq!(body, Some(serde_json::json!({ "ok": true })));
    {
        let heads = requests.lock().expect("request log");
        assert_eq!(heads.len(), 2, "one refusal, one rotation");
        assert!(
            heads[1].contains(&format!("x-otx-api-key: {}", keys[1])),
            "the retry must carry the pooled second key: {}",
            heads[1]
        );
    }

    // Both keys refused: the call fails, and says which module failed.
    let err = super::fetch::fetch_keyed_json::<serde_json::Value>(
        &ctx,
        "ip_reputation",
        &url,
        ENV,
        "X-OTX-API-KEY",
    )
    .await
    .expect_err("no usable key remains");
    assert_eq!(
        pool_status("alienvault_otx", &keys[1]),
        Some(KeyStatus::Invalid)
    );
    let msg = err.to_string();
    assert!(
        msg.contains("ip_reputation"),
        "the error names the module: {msg}"
    );
    assert!(!msg.contains("alienvault_otx"), "never the pool: {msg}");
}

/// REQ-KEYREG-001. The status cascade (`keyed_cascade` over
/// `keyed_cascade_with_key` and `attempt_with_key`) takes `key_env` and burns
/// into that pool on every path: an auth-shaped 400 (the cascade's own burn)
/// and a 401 (`handle_keyed_error`'s). `module` is a label that owns no pool,
/// so only the env var can have named `oathnet`.
#[tokio::test]
async fn keyed_cascade_burns_and_rotates_in_the_pool_its_key_env_names() {
    use crate::util::http::test_server::{Canned, serve_recording};
    use crate::util::key_pool::KeyStatus;
    let keys = pool_keys("oathnet", 3);
    let (base, requests) = serve_recording(vec![
        Canned::json(400, r#"{"error":"Invalid API key"}"#),
        Canned::json(401, "{}"),
        Canned::json(200, r#"{"ok":true}"#),
    ])
    .await;
    let ctx = pooled_ctx("HUNTSMAN_OATHNET_KEY", &keys[0]);
    let url = format!("{base}/service/v2/breach/search");

    let resp = keyed_cascade(
        &ctx,
        "keyreg_label_owns_no_pool",
        "HUNTSMAN_OATHNET_KEY",
        &keys[0],
        &[],
        |key| ctx.http.get(&url).header("x-api-key", key),
    )
    .await
    .expect("the third pooled key is served")
    .expect("a 2xx");
    // The pool picks the rotation order, so read which key each request sent.
    let sent: Vec<String> = requests
        .lock()
        .expect("request log")
        .iter()
        .map(|head| {
            head.lines()
                .find_map(|l| l.strip_prefix("x-api-key: "))
                .expect("every attempt carries a key")
                .trim()
                .to_string()
        })
        .collect();
    assert_eq!(sent.len(), 3, "two refusals, then a third key");
    assert_eq!(sent[0], keys[0], "the cascade starts on the injected key");
    assert_eq!(
        pool_status("oathnet", &sent[0]),
        Some(KeyStatus::Invalid),
        "400 burn"
    );
    assert_eq!(
        pool_status("oathnet", &sent[1]),
        Some(KeyStatus::Invalid),
        "401 burn"
    );
    let served = pool_status("oathnet", &sent[2]);
    assert!(
        served.is_some() && served != Some(KeyStatus::Invalid),
        "the key that answered is a pooled key left usable: {served:?}"
    );
    assert!(resp.status().is_success());
}

/// REQ-KEYREG-001. `keyed_cascade_json`'s in-body verdict — Stolen.tax's
/// `success:false` shape, whose module comment promised a burned key would
/// "rotat[e] to the next pooled credential" — burns into the `stolen_tax`
/// pool its env var names, and the rotation draws the next key from it.
#[tokio::test]
async fn keyed_cascade_json_burns_an_in_body_failure_in_the_pool_its_key_env_names() {
    use crate::util::http::test_server::{Canned, serve_recording};
    use crate::util::key_pool::KeyStatus;
    #[derive(serde::Deserialize, Debug)]
    struct Body {
        status: Option<i64>,
    }
    let keys = pool_keys("stolen_tax", 2);
    let (base, requests) = serve_recording(vec![
        Canned::json(200, r#"{"status":401}"#),
        Canned::json(200, r#"{"status":200}"#),
    ])
    .await;
    let ctx = pooled_ctx("HUNTSMAN_STOLEN_TAX_KEY", &keys[0]);
    let url = format!("{base}/api/v1/search/email?query=a%40b.example");

    let out: Option<Body> = keyed_cascade_json(
        &ctx,
        "keyreg_label_owns_no_pool",
        "HUNTSMAN_STOLEN_TAX_KEY",
        &keys[0],
        &[],
        |key| ctx.http.get(&url).header("Api-Key", key),
        |b: &Body| match b.status {
            Some(401) => super::fetch::BodyVerdict::KeyFailure {
                code: 401,
                detail: None,
            },
            _ => super::fetch::BodyVerdict::Accept,
        },
    )
    .await
    .expect("the second pooled key is served");
    assert_eq!(
        pool_status("stolen_tax", &keys[0]),
        Some(KeyStatus::Invalid),
        "the in-body key failure must be marked in the stolen_tax pool"
    );
    assert_eq!(out.and_then(|b| b.status), Some(200));
    let heads = requests.lock().expect("request log");
    assert_eq!(heads.len(), 2);
    assert!(
        heads[1].contains(&format!("api-key: {}", keys[1])),
        "{}",
        heads[1]
    );
}

// ── Error-message quality: what the operator and the DB actually receive ─────
// Both cases below were observed verbatim in a production `hse doctor` report,
// where they made the scraper-health section unreadable.

/// A CDN error page must be reduced to the line that names the failure, not
/// echoed as 200 characters of doctype and IE conditional comments.
#[tokio::test]
async fn error_snippet_summarises_an_html_error_page() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let body = concat!(
            "<!DOCTYPE html>\n",
            "<!--[if lt IE 7]> <html class=\"no-js ie6 oldie\" lang=\"en-US\"> <![endif]-->\n",
            "<!--[if IE 7]>    <html class=\"no-js ie7 oldie\" lang=\"en-US\"> <![endif]-->\n",
            "<head><title>psbdmp.ws | 523: Origin is unreachable</title></head>\n",
            "<body><h1>Error 523</h1></body></html>",
        );
        let resp = format!(
            "HTTP/1.1 523 \r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        use tokio::io::AsyncWriteExt as _;
        let _ = s.write_all(resp.as_bytes()).await;
    });

    let client = build_client();
    let resp = client
        .get(format!("http://{addr}/"))
        .send()
        .await
        .expect("local server responds");
    let snippet = super::fetch::error_snippet(resp).await;

    assert_eq!(
        snippet, "psbdmp.ws | 523: Origin is unreachable",
        "the snippet must be the diagnostic line, not page boilerplate"
    );
    assert!(
        !snippet.contains("DOCTYPE") && !snippet.contains("[if lt IE"),
        "no markup boilerplate may survive: {snippet}"
    );
}

/// A JSON error payload must be left exactly as the upstream sent it — the HTML
/// summarisation must not reach a body that merely mentions markup.
#[tokio::test]
async fn error_snippet_leaves_a_json_payload_verbatim() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let body = r#"{"error":"Invalid API key","tag":"INVALID_API_KEY"}"#;
        let resp = format!(
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        use tokio::io::AsyncWriteExt as _;
        let _ = s.write_all(resp.as_bytes()).await;
    });

    let client = build_client();
    let resp = client
        .get(format!("http://{addr}/"))
        .send()
        .await
        .expect("local server responds");
    let snippet = super::fetch::error_snippet(resp).await;
    assert_eq!(
        snippet, r#"{"error":"Invalid API key","tag":"INVALID_API_KEY"}"#,
        "a JSON error body carries the real message and must survive untouched"
    );
}

/// The transport+fallback message must name the URL once, not twice.
#[test]
fn transport_failure_names_the_url_exactly_once() {
    let url = "https://psbdmp.ws/api/v3/search/ukchemist%40gmail.com";
    // reqwest's own Display for a send failure already embeds the URL.
    let reqwest_shaped = format!("error sending request for url ({url})");

    let msg = super::fetch::transport_and_fallback_failed(&reqwest_shaped, url);
    assert_eq!(
        msg.matches(url).count(),
        1,
        "the URL (which carries the scan target) must appear once: {msg}"
    );
    assert!(msg.contains("curl fallback also failed"));

    // A transport error that does NOT name the URL must still identify the
    // request — dropping it unconditionally would lose that.
    let bare = super::fetch::transport_and_fallback_failed("connection closed before message", url);
    assert_eq!(
        bare.matches(url).count(),
        1,
        "an error without the URL must have it appended: {bare}"
    );
    assert!(bare.contains("curl fallback failed for"));
}

#[test]
fn pooled_keys_are_masked_wherever_they_appear_whatever_their_status() {
    // Over a FRESH, LOCAL pool — never `global_pool()` — for the same reason
    // as `keys::tests::pool_keys_fill_empty_env_slots`. Before pooled keys
    // were fed to the literal pass, only `HUNTSMAN_*` env values were masked,
    // so a pooled key (which never lives in the environment) echoed by an
    // upstream error body reached the persisted events table and the SSE
    // stream verbatim.
    use crate::util::key_pool::{KeyEntry, KeyPool, KeyStatus};
    let pool = KeyPool::new();
    let mut active = KeyEntry::new("pooled-active-key-0123456789");
    active.status = KeyStatus::Active;
    assert!(pool.add("shodan", active));
    let mut revoked = KeyEntry::new("pooled-revoked-key-9876543210");
    revoked.status = KeyStatus::Revoked;
    assert!(pool.add("ipqs", revoked));
    let snapshot = pool.snapshot();

    let body = "GET /api/json/ip/pooled-active-key-0123456789/1.2.3.4 failed; \
                the retired key pooled-revoked-key-9876543210 was echoed too";
    let masked = redact_literal_secrets(body, pool_secret_values(&snapshot));
    assert_eq!(
        masked,
        "GET /api/json/ip/***/1.2.3.4 failed; the retired key *** was echoed too"
    );
    // Two services, one value each: the snapshot is walked in full.
    assert_eq!(pool_secret_values(&snapshot).count(), 2);
}

// ── read_body_capped / read_body_capped_or_fail: the fail-closed body read ───
// These primitives back the "a transport failure mid-stream is not a finding
// that the subject has no record" rule that ~a dozen scraper modules depend on
// (ahpra, austlii, pgp, …). They had no direct coverage; the streamed
// responses below exercise the transport-failure contract without a network by
// building a body stream that drops part-way, exactly as a reset connection does.

/// A 200 response whose body arrives as `chunks` in order; a `None` entry aborts
/// the transfer mid-stream (a transport failure), reproducing a dropped
/// connection deterministically and offline.
fn streamed_response(chunks: Vec<Option<&'static [u8]>>) -> reqwest::Response {
    let items: Vec<Result<&'static [u8], std::io::Error>> = chunks
        .into_iter()
        .map(|c| {
            c.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection reset mid-body",
                )
            })
        })
        .collect();
    let body = reqwest::Body::wrap_stream(futures::stream::iter(items));
    reqwest::Response::from(
        http::Response::builder()
            .status(200)
            .body(body)
            .expect("response builds"),
    )
}

#[tokio::test]
async fn read_body_capped_returns_the_full_body_on_a_clean_transfer() {
    let resp = streamed_response(vec![Some(b"hello "), Some(b"world")]);
    assert_eq!(
        read_body_capped(resp, 1024).await.as_deref(),
        Some("hello world"),
        "a clean multi-chunk transfer reassembles the whole body"
    );
}

#[tokio::test]
async fn read_body_capped_is_none_on_a_mid_stream_transport_failure() {
    // A chunk arrives, then the connection drops. The bytes seen so far must NOT
    // be reported as the complete body: `None` means "unreadable", the
    // distinction every fail-closed caller relies on.
    let resp = streamed_response(vec![Some(b"partial"), None]);
    assert_eq!(
        read_body_capped(resp, 1024).await,
        None,
        "a mid-stream drop is None, never a truncated Some"
    );
}

#[tokio::test]
async fn read_body_capped_or_fail_errors_on_a_mid_stream_transport_failure() {
    let resp = streamed_response(vec![Some(b"partial"), None]);
    let err = read_body_capped_or_fail("test_mod", resp, 1024)
        .await
        .expect_err("a mid-stream failure must be an Err, not an empty body");
    let msg = err.to_string();
    assert!(
        msg.contains("test_mod"),
        "the error names the module so the failure is attributable: {msg}"
    );
}

#[tokio::test]
async fn read_body_capped_or_fail_returns_the_body_on_success() {
    let resp = streamed_response(vec![Some(b"ok")]);
    assert_eq!(
        read_body_capped_or_fail("test_mod", resp, 1024)
            .await
            .expect("a clean transfer is Ok"),
        "ok"
    );
}

#[test]
fn json_failure_names_an_html_error_page_and_keeps_serde_for_shape_drift() {
    use super::url::json_failure;
    // WiFiDB's live answer to every `exp_search` query on 2026-09-15: HTTP 200,
    // text/html, its error template — a licence comment, then the document.
    // The sweep recorded it as "expected value at line 1 column 1"; the message
    // must say what actually arrived, in the provider's own words.
    let wifidb = "<!--\nError.tpl, Is the default error showing page for WiFiDB.\n-->\n<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<title>Error | Vistumbler WiFiDB</title>\n</head><body>Error: 0 Message: Argument 1 passed to export::buildSearchConditions() must be of the type array, string given</body></html>";
    let err = serde_json::from_str::<serde_json::Value>(wifidb).expect_err("html is not json");
    let msg = json_failure(wifidb, &err);
    assert!(msg.contains("HTML page where JSON was expected"), "{msg}");
    assert!(
        msg.contains("Error | Vistumbler WiFiDB"),
        "the provider's title is quoted: {msg}"
    );
    assert!(
        msg.contains("expected value"),
        "serde's reason is kept: {msg}"
    );

    // A document without a title falls back to its visible text.
    let bare = "<html><body><h1>Just a moment...</h1></body></html>";
    let err = serde_json::from_str::<serde_json::Value>(bare).expect_err("html is not json");
    assert!(json_failure(bare, &err).contains("Just a moment"));

    // Real JSON of the wrong shape is shape drift: serde's words plus the head of
    // the body, never mislabelled as an error page.
    #[derive(Debug, serde::Deserialize)]
    #[allow(dead_code)]
    struct Wanted {
        name: String,
    }
    let drifted = r#"{"data":{"name":"x"}}"#;
    let err = serde_json::from_str::<Wanted>(drifted).expect_err("missing field");
    let msg = json_failure(drifted, &err);
    assert!(!msg.contains("HTML page"), "{msg}");
    assert!(
        msg.contains("missing field") && msg.contains("body starts"),
        "{msg}"
    );

    // A JSON error body that merely quotes markup keeps its verbatim treatment.
    let quoting = r#"{"error":"<html> is not allowed here"}"#;
    let err = serde_json::from_str::<Wanted>(quoting).expect_err("missing field");
    assert!(!json_failure(quoting, &err).contains("HTML page"));
}

#[tokio::test]
async fn a_429_is_the_typed_rate_limited_error_and_other_statuses_stay_module_errors() {
    // The 2026-09-15 live sweep classified reddit_user's and steam_profile's
    // HTTP 429 as "unreachable" — the class of a provider that is down. A
    // throttle is the provider answering; the breaker, the capability probe
    // and the sweep must see the variant, not a "429" token in prose.
    use super::test_server::{Canned, serve};
    let base = serve(vec![
        Canned::text(429, "slow down"),
        Canned::text(503, "Service Unavailable"),
    ])
    .await;
    let client = reqwest::Client::new();
    let resp = client.get(&base).send().await.expect("loopback");
    let err = super::http_status_error("m", resp).await;
    assert!(
        matches!(err, crate::core::error::Error::RateLimited(_)),
        "{err}"
    );
    assert!(
        err.to_string().contains("429") && err.to_string().contains("slow down"),
        "{err}"
    );
    let resp = client.get(&base).send().await.expect("loopback");
    let err = super::http_status_error("m", resp).await;
    assert!(
        matches!(err, crate::core::error::Error::Module { .. }),
        "{err}"
    );
}

/// The Cloudflare block page (`Attention Required!`) and managed-challenge
/// interstitial (`Just a moment...`) as the runner received them on
/// 2026-09-15 — the fingerprints `util::html::is_challenge_page` keys on are
/// the title phrases with the vendor name, and the `/cdn-cgi/challenge-platform`
/// loader URL.
const CF_BLOCK_PAGE: &str = "<!DOCTYPE html><html lang=\"en-US\"><head>\
    <title>Attention Required! | Cloudflare</title></head><body>\
    <h1><span class=\"cf-error-type\">Sorry, you have been blocked</span></h1>\
    <h2>You are unable to access example.org</h2>\
    <p>This website is using a security service to protect itself from online attacks.</p>\
    <p>Cloudflare Ray ID: 9d1f2c3b4a5e6f70 &bull; Performance &amp; security by Cloudflare</p>\
    </body></html>";
const CF_CHALLENGE_PAGE: &str = "<!DOCTYPE html><html lang=\"en-US\"><head>\
    <title>Just a moment...</title></head><body>\
    <noscript>Enable JavaScript and cookies to continue</noscript>\
    <script src=\"/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1?ray=9d1f2c3b4a5e6f70\"></script>\
    </body></html>";

#[tokio::test]
async fn a_challenge_page_is_the_typed_bot_challenge_and_a_plain_refusal_or_outage_stays_a_module_error()
 {
    // The 2026-09-15 live sweep filed anubis's `HTTP 403 Forbidden:
    // Attention Required! | Cloudflare` and austlii's `HTTP 403 Forbidden:
    // Just a moment...` as "unreachable" — the class of a provider that is
    // down. A wall is the provider refusing this client; an outage page and
    // a plain 403 are not walls.
    use super::test_server::{Canned, serve};
    let base = serve(vec![
        Canned::html(403, CF_BLOCK_PAGE),
        Canned::html(403, CF_CHALLENGE_PAGE),
        Canned::text(403, "Forbidden"),
        Canned::html(
            503,
            "<!DOCTYPE html><html><head><title>Internet Archive: Temporarily Offline</title>\
             </head><body>The Wayback Machine is temporarily offline.</body></html>",
        ),
    ])
    .await;
    let client = reqwest::Client::new();
    for expect_title in ["Attention Required! | Cloudflare", "Just a moment..."] {
        let resp = client.get(&base).send().await.expect("loopback");
        let err = super::http_status_error("m", resp).await;
        assert!(
            matches!(err, crate::core::error::Error::BotChallenge(_)),
            "{err}"
        );
        let text = err.to_string();
        assert!(
            text.starts_with("bot challenge: m: HTTP 403") && text.contains(expect_title),
            "{text}"
        );
    }
    for expect in ["Forbidden", "Internet Archive: Temporarily Offline"] {
        let resp = client.get(&base).send().await.expect("loopback");
        let err = super::http_status_error("m", resp).await;
        assert!(
            matches!(err, crate::core::error::Error::Module { .. }),
            "{err}"
        );
        assert!(err.to_string().contains(expect), "{err}");
    }
}

#[tokio::test]
async fn a_challenge_page_served_with_200_where_json_was_expected_is_the_typed_bot_challenge() {
    // Some edges answer a challenge as `200 text/html`; the decode helpers
    // must type it, while a provider's own HTML error template (WiFiDB's
    // `Error | Vistumbler WiFiDB`, observed 2026-09-15) stays a module error
    // naming the page.
    use super::test_server::{Canned, serve};
    let base = serve(vec![
        Canned::html(200, CF_CHALLENGE_PAGE),
        Canned::html(
            200,
            "<!DOCTYPE html><html><head><title>Error | Vistumbler WiFiDB</title></head>\
             <body>Fatal error: Uncaught TypeError</body></html>",
        ),
        Canned::html(200, CF_BLOCK_PAGE),
    ])
    .await;
    let client = reqwest::Client::new();
    // `fetch_json` → `decode_json_body`.
    let err = super::fetch_json::<serde_json::Value>(&client, "m", &base)
        .await
        .expect_err("a challenge page is not JSON");
    assert!(
        matches!(err, crate::core::error::Error::BotChallenge(_)),
        "{err}"
    );
    assert!(err.to_string().contains("Just a moment..."), "{err}");
    let err = super::fetch_json::<serde_json::Value>(&client, "m", &base)
        .await
        .expect_err("an error template is not JSON");
    assert!(
        matches!(err, crate::core::error::Error::Module { .. }),
        "{err}"
    );
    assert!(
        err.to_string().contains("Error | Vistumbler WiFiDB"),
        "{err}"
    );
    // `json_decode` (the un-scanned helper) types it the same way.
    let resp = client.get(&base).send().await.expect("loopback");
    let err = super::json_decode::<serde_json::Value>("m", resp)
        .await
        .expect_err("a block page is not JSON");
    assert!(
        matches!(err, crate::core::error::Error::BotChallenge(_)),
        "{err}"
    );
    assert!(err.to_string().contains("Attention Required!"), "{err}");
}

#[tokio::test]
async fn a_2xx_anti_bot_page_read_through_the_text_seams_is_the_typed_bot_challenge_never_the_document()
 {
    // Scrapers read their 2xx bodies through `read_body_capped_or_fail` /
    // `read_text`; a wall served with 200 used to be handed to their parsers
    // as the page they asked for, and "no results" followed. Only an HTML
    // document is classified: a crawl index or host list that merely mentions
    // a vendor path is the data.
    use super::test_server::{Canned, serve};
    const INDEX_LINE: &str = "{\"url\": \"https://example.com/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1\", \"status\": \"200\"}\n{\"url\": \"https://example.com/about\", \"status\": \"200\"}\n";
    let base = serve(vec![
        Canned::html(200, CF_CHALLENGE_PAGE),
        Canned::html(200, CF_BLOCK_PAGE),
        Canned::text(200, INDEX_LINE),
        Canned::html(
            200,
            "<!DOCTYPE html><html><head><title>Register search</title></head>\
             <body><table><tr><td>no records</td></tr></table></body></html>",
        ),
    ])
    .await;
    let client = reqwest::Client::new();

    let resp = client.get(&base).send().await.expect("loopback");
    let err = super::read_body_capped_or_fail("m", resp, 64 * 1024)
        .await
        .expect_err("a wall is not the document");
    assert!(
        matches!(err, crate::core::error::Error::BotChallenge(_)),
        "{err}"
    );
    assert!(
        err.to_string().contains("HTTP 200") && err.to_string().contains("Just a moment"),
        "{err}"
    );

    let resp = client.get(&base).send().await.expect("loopback");
    let err = super::read_text("m", resp)
        .await
        .expect_err("a block page is not the text payload");
    assert!(
        matches!(err, crate::core::error::Error::BotChallenge(_)),
        "{err}"
    );
    assert!(err.to_string().contains("Attention Required"), "{err}");

    // A non-document payload that mentions a vendor path is returned verbatim.
    let resp = client.get(&base).send().await.expect("loopback");
    let body = super::read_text("m", resp)
        .await
        .expect("a crawl index is the data, not a wall");
    assert_eq!(body, INDEX_LINE);

    // A real HTML document that is not a wall is returned verbatim.
    let resp = client.get(&base).send().await.expect("loopback");
    let body = super::read_body_capped_or_fail("m", resp, 64 * 1024)
        .await
        .expect("a register page is the document");
    assert!(body.contains("no records"));
}

/// `json_scanned` fails the way `json_decode` fails: an anti-bot page served
/// with a 2xx where JSON was expected is the typed `BotChallenge` (until
/// 2026-09-15 it was a bare `String` every caller wrapped as `Error::module`,
/// so a wall behind any of its thirty-odd call sites read as a module fault),
/// and a decode failure's message is credential-redacted (this was the one
/// JSON helper that never ran `redact_credentials`, and `json_failure` quotes
/// a prefix of the body).
#[tokio::test]
async fn json_scanned_types_a_challenge_page_and_redacts_a_credential_in_the_decode_error() {
    use crate::core::error::Error;
    const WALL: &str = include_str!("../html/testdata/cloudflare_block_anubis_2026-09-15.html");
    let wall = reqwest::Response::from(
        http::Response::builder()
            .status(200)
            .body(WALL.to_string())
            .expect("should succeed"),
    );
    let err = crate::util::http::json_scanned::<serde_json::Value>(wall, "test_mod")
        .await
        .expect_err("a wall is not JSON");
    assert!(matches!(err, Error::BotChallenge(_)), "{err}");
    assert!(err.to_string().contains("Attention Required"), "{err}");

    let leaky = reqwest::Response::from(
        http::Response::builder()
            .status(200)
            .body("api_key=sk_live_SECRETVALUE99&more not json".to_string())
            .expect("should succeed"),
    );
    let err = crate::util::http::json_scanned::<serde_json::Value>(leaky, "test_mod")
        .await
        .expect_err("not JSON");
    assert!(matches!(err, Error::Module { .. }), "{err}");
    let msg = err.to_string();
    assert!(
        msg.contains("test_mod") && !msg.contains("SECRETVALUE99"),
        "the decode error must name the module and never quote the credential: {msg}"
    );
}

/// REQ-HTTP-004. `keyed_ok_or_404` hand-built `Error::module` for every non-2xx,
/// so a throttle and an anti-bot wall reached `emailrep`, `europeana` and
/// `fullcontact` as generic provider faults — the breaker counted each as a
/// defect and the live sweep read them as "unreachable".
///
/// Three SEPARATE tests, not one with three assertions: a single test stops at
/// its first failure, so the throttle arm would mask whether the wall arm holds.
/// Each of these fails on the unfixed code for its own reason, and the third
/// passes on it — the control that makes the other two attributable.
fn keyed_test_ctx() -> crate::core::module::ModuleContext {
    use std::collections::HashMap;
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    crate::core::module::ModuleContext {
        scan_id: "test".into(),
        bus,
        http: reqwest::Client::new(),
        keys: HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    }
}

#[tokio::test]
async fn keyed_ok_or_404_types_a_429_as_the_typed_rate_limit() {
    use super::test_server::{Canned, serve};
    let base = serve(vec![Canned::json(
        429,
        r#"{"error":"rate limit exceeded"}"#,
    )])
    .await;
    let ctx = keyed_test_ctx();
    let resp = reqwest::Client::new()
        .get(&base)
        .send()
        .await
        .expect("loopback");
    let err = keyed_ok_or_404("m", "k", &ctx, resp)
        .await
        .expect_err("429 must be an error");
    assert!(
        matches!(err, crate::core::error::Error::RateLimited(_)),
        "a 429 must be the typed RateLimited, got {err:?}"
    );
}

#[tokio::test]
async fn keyed_ok_or_404_types_a_challenge_page_as_the_typed_wall() {
    // Classified on the RAW body: the fingerprint is a `<script>` URL that the
    // one-line summary drops, so routing the summary here instead would leave
    // this arm structurally unable to fire.
    use super::test_server::{Canned, serve};
    let base = serve(vec![Canned::html(403, CF_CHALLENGE_PAGE)]).await;
    let ctx = keyed_test_ctx();
    let resp = reqwest::Client::new()
        .get(&base)
        .send()
        .await
        .expect("loopback");
    let err = keyed_ok_or_404("m", "k", &ctx, resp)
        .await
        .expect_err("challenge page must be an error");
    assert!(
        matches!(err, crate::core::error::Error::BotChallenge(_)),
        "a challenge page must be the typed BotChallenge, got {err:?}"
    );
}

#[tokio::test]
async fn keyed_ok_or_404_leaves_a_plain_refusal_a_module_fault() {
    // CONTROL: passes on the unfixed code too. A plain 403 is not a wall, and
    // over-typing it would be its own defect.
    use super::test_server::{Canned, serve};
    let base = serve(vec![Canned::text(403, "Forbidden")]).await;
    let ctx = keyed_test_ctx();
    let resp = reqwest::Client::new()
        .get(&base)
        .send()
        .await
        .expect("loopback");
    let err = keyed_ok_or_404("m", "k", &ctx, resp)
        .await
        .expect_err("403 must be an error");
    assert!(
        matches!(err, crate::core::error::Error::Module { .. }),
        "a plain 403 stays a module fault, got {err:?}"
    );
}

// ── REQ-HTTP-005: a 429 is not a 5xx, to the breaker either ───────────

/// REQ-HTTP-005. The shared chokepoint folded a 429 in with the 5xx via one
/// `is_breaker_failure_status` predicate, so a throttle took
/// `FAILURE_THRESHOLD` (5) consecutive round-trips to back off and then used
/// the local `COOLDOWN_SECS` guess. `Breaker::on_rate_limited`'s own doc rules
/// that out: *"A 429 is the server stating its own contract… There is nothing
/// to accumulate evidence about, so this opens the breaker on the first one and
/// uses the server's window rather than the local COOLDOWN_SECS guess."*
///
/// Every status is swept and mismatches collected, so a partial rule is named
/// rather than masked by whichever case is asserted first.
#[test]
fn a_429_is_its_own_breaker_outcome_never_folded_in_with_a_5xx() {
    use super::fetch::{BreakerOutcome, breaker_outcome_for};
    let mut wrong: Vec<(u16, BreakerOutcome)> = Vec::new();
    let expected: &[(u16, BreakerOutcome)] = &[
        (429, BreakerOutcome::RateLimited),
        // Server-side faults: evidence, not a contract.
        (500, BreakerOutcome::Failure),
        (502, BreakerOutcome::Failure),
        (503, BreakerOutcome::Failure),
        (504, BreakerOutcome::Failure),
        // Definitive client answers — the host is up and answering.
        (200, BreakerOutcome::Success),
        (204, BreakerOutcome::Success),
        (301, BreakerOutcome::Success),
        (400, BreakerOutcome::Success),
        (401, BreakerOutcome::Success),
        (403, BreakerOutcome::Success),
        (404, BreakerOutcome::Success),
        (418, BreakerOutcome::Success),
        (451, BreakerOutcome::Success),
    ];
    for (code, want) in expected {
        let got =
            breaker_outcome_for(reqwest::StatusCode::from_u16(*code).expect("a valid status code"));
        if got != *want {
            wrong.push((*code, got));
        }
    }
    assert!(
        wrong.is_empty(),
        "these statuses are classified wrongly for the breaker: {wrong:?}"
    );
}

/// The same rule at the seam that actually bit — driven through the real
/// `fetch_json_or_404` path against a loopback server, so the production
/// classification, decoding and breaker wiring all execute.
///
/// This test is only possible because `REQ-BREAKER-001` keys the breaker on
/// host AND port: under the old host-only key, opening `127.0.0.1` here for the
/// server's 90-second window would have short-circuited every other loopback
/// test running in parallel in this process.
#[tokio::test]
async fn one_429_opens_the_breaker_for_the_servers_own_window() {
    use super::test_server::{Canned, serve};
    use crate::util::circuit_breaker::{allow_host, endpoint_of};

    let base = serve(vec![
        Canned::json(429, r#"{"error":"slow down"}"#).header("Retry-After", "90"),
    ])
    .await;
    let endpoint = endpoint_of(&base).expect("a loopback URL keys an endpoint");
    let t0 = crate::core::entity::unix_now();

    let out: crate::core::error::Result<Option<serde_json::Value>> =
        fetch_json_or_404(&reqwest::Client::new(), "test_429_breaker", &base).await;
    assert!(
        matches!(out, Err(crate::core::error::Error::RateLimited(_))),
        "a 429 is the typed rate limit, not a generic fault: {out:?}"
    );

    assert!(
        !allow_host(&endpoint, t0),
        "ONE 429 must open the breaker — not FAILURE_THRESHOLD of them, which is \
         what let an observed radar sweep issue eight consecutive 429s"
    );
    assert!(
        !allow_host(&endpoint, t0 + 89),
        "…and hold for the server's own 90s Retry-After window, not the local \
         60s COOLDOWN_SECS guess"
    );
    assert!(
        allow_host(&endpoint, t0 + 95),
        "…then release, so a throttle is never a permanent outage"
    );
    // Close it. The assertions above drove the breaker with explicit future
    // `now` values, so in real time it is still open for ~90s on a port the
    // server has now released — a later test handed the same ephemeral port
    // would be short-circuited by a breaker it never opened. This is cleanup
    // for state this test deliberately created, not the shared-key workaround
    // REQ-BREAKER-001 removed.
    crate::util::circuit_breaker::record_success(&endpoint);
}

/// The control, and what keeps the rule above honest: a single 5xx must NOT
/// open the breaker. It is a guess about health — one bad node, one unlucky
/// socket — and takes `FAILURE_THRESHOLD` of them to settle.
///
/// Passes on the baseline and on the fix, so it proves the change is specific
/// to the 429 rather than having made every fault instant.
#[tokio::test]
async fn a_single_5xx_does_not_open_the_breaker() {
    use super::test_server::{Canned, serve};
    use crate::util::circuit_breaker::{allow_host, endpoint_of};

    let base = serve(vec![Canned::json(503, r#"{"error":"boom"}"#)]).await;
    let endpoint = endpoint_of(&base).expect("a loopback URL keys an endpoint");
    let t0 = crate::core::entity::unix_now();

    let out: crate::core::error::Result<Option<serde_json::Value>> =
        fetch_json_or_404(&reqwest::Client::new(), "test_5xx_breaker", &base).await;
    assert!(out.is_err(), "a 503 is still a real error: {out:?}");
    assert!(
        allow_host(&endpoint, t0),
        "one 5xx is evidence, not a contract — the endpoint stays reachable"
    );
}

// ── REQ-CURL-001: the curl fallback answers exactly as the reqwest path ─────

#[derive(serde::Deserialize, Debug, Default)]
struct Loose {
    #[serde(default)]
    results: Vec<String>,
}

fn status(status: u16, body: &str) -> crate::util::curl::JsonFetch<Loose> {
    crate::util::curl::JsonFetch::Status {
        status,
        body: body.to_string(),
    }
}

#[test]
fn a_fallback_404_is_absent_only_where_the_caller_says_so() {
    let absent = super::fetch::resolve_curl_fallback::<Loose>(
        "m",
        "https://api.example/x",
        None,
        &[404],
        "t",
        status(404, "{}"),
    );
    assert!(
        matches!(absent, Ok(None)),
        "fetch_json_or_404: a 404 is absent"
    );
    let error = super::fetch::resolve_curl_fallback::<Loose>(
        "m",
        "https://api.example/x",
        None,
        &[],
        "t",
        status(404, "{}"),
    );
    assert!(error.is_err(), "fetch_json: a 404 is an error, never data");
}

#[test]
fn a_fallback_throttle_is_the_typed_rate_limit_not_data() {
    // FAILS on the body-only fallback: `{}` decodes as `Loose`, so a 429 was
    // returned as Ok(Some(empty)) — a clean answer from a throttled provider.
    let r = super::fetch::resolve_curl_fallback::<Loose>(
        "m",
        "https://api.example/x",
        None,
        &[404],
        "t",
        status(429, "{}"),
    );
    let e = r.expect_err("a 429 is not an answer");
    assert!(
        matches!(e, crate::core::error::Error::RateLimited(_)),
        "typed exactly as http_status_error types it: {e:?}"
    );
}

#[test]
fn a_fallback_error_body_is_redacted_as_the_reqwest_path_redacts_it() {
    // FAILS on the raw-body fallback: the reqwest arm redacts an error body
    // before classifying it, the curl arm did not, so a provider echoing the
    // request URL put the key into the typed error, whatever the error type.
    for code in [429, 500] {
        let r = super::fetch::resolve_curl_fallback::<Loose>(
            "m",
            "https://api.example/x",
            None,
            &[404],
            "t",
            status(code, "failed: https://api.example/x?api_key=SEKRET123&q=a"),
        );
        let text = r.expect_err("an error status is not an answer").to_string();
        assert!(
            !text.contains("SEKRET123"),
            "HTTP {code} leaked the key: {text}"
        );
        assert!(
            text.contains("api_key=***"),
            "redacted, not dropped: {text}"
        );
    }
}

#[test]
fn a_fallback_error_body_is_capped_as_the_reqwest_path_caps_it() {
    // A challenge fingerprint past the cap is invisible to the reqwest arm, so
    // it must be to the curl arm too: the two answer alike for one response.
    let wall = "<script src=\"/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1\"></script>";
    let pad = "x".repeat(8 * 1024);
    let classify = |body: String| {
        super::fetch::resolve_curl_fallback::<Loose>(
            "m",
            "https://api.example/x",
            None,
            &[404],
            "t",
            status(403, &body),
        )
        .expect_err("a 403 is not an answer")
    };
    // Control: the same wall inside the cap IS a challenge, so the case below
    // is not vacuous.
    let within = classify(format!("{wall}{pad}"));
    assert!(
        matches!(within, crate::core::error::Error::BotChallenge(_)),
        "{within:?}"
    );
    let past = classify(format!("{pad}{wall}"));
    assert!(
        !matches!(past, crate::core::error::Error::BotChallenge(_)),
        "past the cap, as reqwest sees it: {past:?}"
    );
}

#[test]
fn a_fallback_with_no_answer_is_a_failure_never_absent() {
    let r = super::fetch::resolve_curl_fallback::<Loose>(
        "m",
        "https://api.example/x",
        None,
        &[404],
        "connect refused",
        crate::util::curl::JsonFetch::NoAnswer,
    );
    assert!(r.is_err(), "an outage must never read as `not found`");
    let ok = super::fetch::resolve_curl_fallback::<Loose>(
        "m",
        "https://api.example/x",
        None,
        &[],
        "t",
        crate::util::curl::JsonFetch::Decoded(Loose {
            results: vec!["a".into()],
        }),
    );
    assert_eq!(ok.expect("decoded").expect("some").results, ["a"]);
}

/// REQ-KEYFLOOR-001. `keyed_answer` keeps the provider's refusal of the
/// CREDENTIAL apart from every other failure, so a module with a keyless path
/// can fall back on it and on nothing else: `401`, `403` and Netlas' documented
/// auth-shaped `400` are `KeyRejected` and burn the key `Invalid` in the pool;
/// a `429` is still an `Err` (typed `RateLimited`) and still burns
/// `RateLimited`; a `500` and a bad-query `400` are an `Err` and burn nothing.
#[tokio::test]
async fn keyed_answer_separates_a_key_refusal_from_every_other_failure() {
    use super::test_server::{Canned, serve};
    use crate::util::key_pool::KeyStatus;
    let ctx = keyed_test_ctx();
    let keys = pool_keys("shodan", 6);
    let refused = [
        (401, r#"{"message":"unauthorized"}"#),
        (403, r#"{"error":"Access denied"}"#),
        (
            400,
            r#"{"detail":"Request had invalid authorization credentials: API key not found"}"#,
        ),
    ];
    for (i, (code, body)) in refused.into_iter().enumerate() {
        let key = &keys[i];
        let base = serve(vec![Canned::json(code, body)]).await;
        let resp = reqwest::Client::new()
            .get(&base)
            .send()
            .await
            .expect("loopback");
        match keyed_answer("shodan", key, &ctx, resp).await {
            Ok(KeyedAnswer::KeyRejected { status, .. }) => assert_eq!(status, code),
            other => panic!("case {i}: {code} is a key refusal, got {other:?}"),
        }
        assert_eq!(
            pool_status("shodan", key),
            Some(KeyStatus::Invalid),
            "{code} burns"
        );
    }

    let key = &keys[3];
    let base = serve(vec![Canned::json(429, r#"{"error":"rate limit"}"#)]).await;
    let resp = reqwest::Client::new()
        .get(&base)
        .send()
        .await
        .expect("loopback");
    let err = keyed_answer("shodan", key, &ctx, resp)
        .await
        .expect_err("a throttle is not a key refusal");
    assert!(
        matches!(err, crate::core::error::Error::RateLimited(_)),
        "{err:?}"
    );
    assert_eq!(pool_status("shodan", key), Some(KeyStatus::RateLimited));

    for (key, (code, body)) in keys[4..]
        .iter()
        .zip([(500, r#"{"error":"boom"}"#), (400, r#"{"error":"bad ip"}"#)])
    {
        let base = serve(vec![Canned::json(code, body)]).await;
        let resp = reqwest::Client::new()
            .get(&base)
            .send()
            .await
            .expect("loopback");
        assert!(
            keyed_answer("shodan", key, &ctx, resp).await.is_err(),
            "{code} is an error, not a refusal"
        );
        assert_ne!(
            pool_status("shodan", key),
            Some(KeyStatus::Invalid),
            "{code} burns nothing"
        );
        assert_ne!(
            pool_status("shodan", key),
            Some(KeyStatus::RateLimited),
            "{code} burns nothing"
        );
    }
}
