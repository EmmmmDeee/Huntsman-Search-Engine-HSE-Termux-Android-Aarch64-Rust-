use super::*;

    #[tokio::test]
    async fn fetch_returns_none_for_bad_url() {
        let r = fetch("https://256.256.256.256/nonexistent", 3000).await;
        assert!(r.is_none());
    }

    #[test]
    fn ua_pool_has_four_entries() {
        assert_eq!(UA_POOL.len(), 4);
    }

    #[test]
    fn curl_max_time_arg_honours_a_sub_second_budget_precisely() {
        // Regression: this used to be `(timeout_ms / 1000).max(3)`, which
        // floored ANY sub-3s budget up to a flat 3 seconds — a caller with
        // 500ms left got a curl call allowed to run 6x longer than its actual
        // remaining deadline. curl accepts fractional `--max-time` seconds, so
        // the real budget is now passed through exactly instead of rounded up.
        assert_eq!(curl_max_time_arg(500), "0.500");
        assert_eq!(curl_max_time_arg(1_500), "1.500");
        assert_eq!(curl_max_time_arg(3_000), "3.000");
    }

    #[test]
    fn curl_max_time_arg_never_emits_zero() {
        // curl treats `--max-time 0` as NO LIMIT — the opposite of what a
        // near-zero remaining budget means here. A near-empty or literally
        // zero budget must still floor to a tiny positive value, never "0".
        assert_eq!(curl_max_time_arg(0), "0.001");
        assert_ne!(curl_max_time_arg(0), "0.000");
    }

    #[test]
    fn fetch_hardening_pins_protocols_and_bounds_redirects_and_size() {
        // Locks the security-critical content of the single-sourced hardening
        // args so a careless future edit that loosens the protocol allow-list,
        // unbounds redirects, or drops the size cap fails here.
        let a = FETCH_HARDENING_ARGS;
        let has = |pair: [&str; 2]| a.windows(2).any(|w| w == pair);
        // Protocol allow-list on both the initial request and every redirect hop
        // (blocks file://, gopher://, dict:// SSRF pivots).
        assert!(
            has(["--proto", "=http,https"]),
            "missing --proto allow-list"
        );
        assert!(
            has(["--proto-redir", "=http,https"]),
            "missing --proto-redir allow-list"
        );
        // Redirects bounded (defence-in-depth against redirect loops / chains).
        assert!(has(["--max-redirs", "5"]), "redirects not bounded");
        // Download size capped via the single-sourced constant.
        assert!(
            has(["--max-filesize", CURL_MAX_DOWNLOAD_BYTES]),
            "download size not capped"
        );
        // Connect phase bounded so a dead host fails fast instead of burning the
        // whole --max-time budget.
        assert!(
            has(["--connect-timeout", "15"]),
            "TCP connect phase not bounded"
        );
    }

    // ── SSRF pin (B8: the security-critical path was untested) ─────────

    #[tokio::test]
    async fn ssrf_pin_refuses_private_and_metadata_hosts() {
        // Literal IPs resolve offline (no DNS query) → deterministic, network-
        // free. Each private/reserved host must yield no pin so the caller
        // refuses the fetch (the curl half of the SSRF defense).
        for u in [
            "http://127.0.0.1/x",
            "http://10.0.0.1/x",
            "http://192.168.1.1/x",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/x",                    // IPv6 loopback (bracketed)
            "http://[fc00::1]/x",                // IPv6 ULA
            "http://[::ffff:169.254.169.254]/x", // IPv4-mapped metadata
            // Encoded IP-literal evasions: the `url` crate normalises each to
            // canonical dotted-quad BEFORE `host_str()`, so `is_private_addr`
            // still catches them. Pinned here so a future URL-parser swap that
            // stopped normalising would fail loudly rather than silently reopen
            // an SSRF bypass. (Verified against the vendored `url` 2.5.8.)
            "http://2130706433/x",               // decimal 127.0.0.1
            "http://0x7f000001/x",               // hex 127.0.0.1
            "http://017700000001/x",             // octal 127.0.0.1
            "http://127.1/x",                    // short-form 127.0.0.1
            "http://2852039166/latest/",         // decimal 169.254.169.254
            "http://0xA9FEA9FE/latest/",         // hex 169.254.169.254
            "http://evil.example@169.254.169.254/", // userinfo@ trick → host is the metadata IP
        ] {
            assert!(
                ssrf_resolve_pin(u).await.is_none(),
                "{u} must be refused as private/reserved"
            );
        }
    }

    #[tokio::test]
    async fn ssrf_pin_allows_public_ip_literal_without_a_pointless_pin() {
        // An IP-literal target is dialled directly by curl (no DNS lookup), so
        // there is no rebinding race and `--resolve` would rewrite nothing. The
        // vetted-public literal must be accepted with an empty arg set rather
        // than a redundant `--resolve host:port:host`.
        for u in ["http://8.8.8.8/x", "http://[2606:4700:4700::1111]/x"] {
            let pin = ssrf_resolve_pin(u)
                .await
                .unwrap_or_else(|| panic!("public literal {u} must be accepted"));
            assert!(pin.is_empty(), "{u} needs no --resolve pin, got {pin:?}");
        }
    }

    // The fallback-path mirror of reqwest's
    // `redirect_to_private_ip_blocks_metadata_and_internal`. Before this guard, the
    // direct curl path used `curl -L`, which re-resolved a cross-host 3xx itself and
    // would fetch a redirect to `169.254.169.254`/`http://internal.corp/` UNVETTED —
    // reachable via a discovered-domain fetch (e.g. `fediverse`/`nostr` webfinger)
    // whose reqwest attempt failed and fell back to curl. `curl_redirect_refused` is
    // the per-hop decision the Rust-side redirect loop now applies.
    #[test]
    fn curl_redirect_refused_blocks_metadata_internal_and_bad_schemes() {
        // Private / reserved IP-literal hops — refused outright.
        for u in [
            "http://169.254.169.254/latest/meta-data/", // cloud metadata
            "http://127.0.0.1/",                         // loopback
            "http://10.0.0.5/",                          // RFC1918
            "http://192.168.1.1/",                       // RFC1918
            "https://[::1]/",                            // IPv6 loopback
            "https://[fc00::1]/",                        // ULA
            "https://[fe80::1]/",                        // link-local
            "https://[::ffff:169.254.169.254]/",         // IPv4-mapped metadata
            // Encoded IP-literal evasions in a redirect Location — `url`
            // normalises each to dotted-quad before the private-IP check, so a
            // 3xx to any of these is refused just like the plain form.
            "http://2130706433/",                        // decimal 127.0.0.1
            "http://0x7f000001/",                        // hex 127.0.0.1
            "http://017700000001/",                      // octal 127.0.0.1
            "http://127.1/",                             // short-form 127.0.0.1
            "http://0xA9FEA9FE/latest/meta-data/",       // hex 169.254.169.254
            "http://evil.example@169.254.169.254/",      // userinfo@ trick
        ] {
            assert!(
                curl_redirect_refused(u),
                "{u} is a private/reserved hop and must be refused"
            );
        }

        // Non-http(s) schemes — refused (no file://, gopher://, dict:// pivots).
        for u in [
            "file:///etc/passwd",
            "gopher://127.0.0.1/",
            "dict://internal:2628/",
            "ftp://internal/secret",
        ] {
            assert!(
                curl_redirect_refused(u),
                "{u} is a non-http(s) scheme and must be refused"
            );
        }

        // Unparseable (no base) — refused (fail closed). NB: `http:///nohost` is
        // NOT here — the `url` crate collapses the slash and reads it as host
        // `nohost`, i.e. a hostname hop, so it is (correctly) deferred to
        // connect-time resolution by `ssrf_resolve_pin`, not refused synchronously.
        for u in ["not a url", "", "://missing-scheme"] {
            assert!(
                curl_redirect_refused(u),
                "{u:?} is unparseable and must be refused"
            );
        }

        // Public IP-literal and hostname hops — NOT refused here. A public literal
        // is dialled directly; a hostname is re-resolved and pinned at connect by
        // `ssrf_resolve_pin` (which drops private addresses), so a rebinding target
        // cannot slip through by presenting as a name.
        for u in [
            "http://8.8.8.8/x",
            "https://[2606:4700:4700::1111]/x",
            "https://example.com/next",
            "http://sub.provider.io/callback?to=1",
        ] {
            assert!(
                !curl_redirect_refused(u),
                "{u} is a public/hostname hop and must be allowed to proceed to connect-time vetting"
            );
        }
    }

    #[tokio::test]
    async fn fetch_with_status_reports_a_body_curl_refused_or_cut_as_truncated() {
        // Backlog #38, transport half. `--max-filesize` makes curl REFUSE a
        // download whose declared Content-Length exceeds the cap (exit 63,
        // empty body) and cut a chunked one mid-stream. Before
        // `StatusProbe::truncated` existed the caller got `(200, "")` and could
        // not tell a page curl never delivered from an empty one — so a
        // negative-marker check over it "passed". Loopback listener, real curl
        // (a runtime dependency on Termux, present on every CI runner).
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        assert!(
            std::process::Command::new("curl")
                .arg("--version")
                .output()
                .is_ok(),
            "curl must be installed to exercise the status probe"
        );
        let cap: usize = PROBE_BODY_CAP_BYTES.parse().expect("cap is a byte count");
        const MARK: &str = "<title>Sorry, this page isn't available.</title>";

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = vec![0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                let (head, body): (String, Vec<u8>) = if req.starts_with("GET /oversized ") {
                    // A not-found page bigger than the cap, length declared up
                    // front — curl aborts before reading a byte of it.
                    let mut body = vec![b'x'; cap + 1];
                    body.extend_from_slice(MARK.as_bytes());
                    (
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        ),
                        body,
                    )
                } else if req.starts_with("GET /chunked ") {
                    // The same page streamed without a length: the marker sits
                    // past the cap, in bytes a capped read never sees.
                    let filler = vec![b'x'; cap + 1];
                    let mut body = Vec::new();
                    for piece in [filler.as_slice(), MARK.as_bytes()] {
                        body.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
                        body.extend_from_slice(piece);
                        body.extend_from_slice(b"\r\n");
                    }
                    body.extend_from_slice(b"0\r\n\r\n");
                    (
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_string(),
                        body,
                    )
                } else {
                    let body = b"<html><title>@someone</title></html>".to_vec();
                    (
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        ),
                        body,
                    )
                };
                let _ = sock.write_all(head.as_bytes()).await;
                // curl may already have hung up on an oversized body — ignore.
                let _ = sock.write_all(&body).await;
                let _ = sock.shutdown().await;
            }
        });

        let refused = fetch_with_status(&format!("http://{addr}/oversized"), 4_000, true).await;
        assert_eq!(
            refused.status, 200,
            "the status still arrives through the -w sentinel: {refused:?}"
        );
        assert!(
            refused.truncated,
            "a download curl refused at the cap must be reported as truncated, \
             not handed over as an empty (marker-free) page: {refused:?}"
        );
        assert!(
            !refused.body.contains(MARK),
            "the marker was never delivered, which is the whole point: {refused:?}"
        );

        // Streamed without a length curl either cuts at the cap (exit 63, the
        // marker lost) or — on a curl that does not bound unknown-length
        // transfers — delivers the whole page. Both are honest; what must never
        // happen is a body without the marker reported as complete.
        let streamed = fetch_with_status(&format!("http://{addr}/chunked"), 4_000, true).await;
        assert_eq!(streamed.status, 200, "{streamed:?}");
        assert!(
            streamed.truncated || streamed.body.contains(MARK),
            "a cut body must be flagged truncated; only a whole body may lack the flag: \
             truncated={} len={}",
            streamed.truncated,
            streamed.body.len()
        );

        let whole = fetch_with_status(&format!("http://{addr}/small"), 4_000, true).await;
        assert_eq!(
            whole,
            StatusProbe {
                status: 200,
                body: "<html><title>@someone</title></html>".into(),
                truncated: false,
            },
            "a page under the cap is delivered whole and reported as such"
        );

        // The status-only path never asks for a body, so the cap never bites.
        let status_only = fetch_with_status(&format!("http://{addr}/oversized"), 4_000, false).await;
        assert_eq!(
            status_only,
            StatusProbe {
                status: 200,
                body: String::new(),
                truncated: false,
            }
        );
    }

// ── REQ-CURL-001: the JSON fallback reads the status, not only the body ─────

#[derive(serde::Deserialize, Debug, Default)]
struct AllDefault {
    #[serde(default)]
    results: Vec<String>,
}

#[test]
fn an_error_status_is_never_decoded_as_the_document() {
    // FAILS on the body-only fallback: a 404 / 429 / 503 whose JSON error body
    // decodes as `T` (here an all-default struct) came back as DATA.
    for status in [404u16, 429, 500, 503] {
        match classify_json::<AllDefault>(status, r#"{"error":"nope"}"#) {
            JsonFetch::Status { status: s, body } => {
                assert_eq!(s, status);
                assert!(body.contains("nope"), "the body is kept for classification");
            }
            other => panic!("{status} must be a status outcome, got {other:?}"),
        }
    }
}

#[test]
fn a_2xx_body_decodes_or_is_undecodable_and_no_status_is_no_answer() {
    assert!(matches!(
        classify_json::<AllDefault>(200, r#"{"results":["a"]}"#),
        JsonFetch::Decoded(AllDefault { ref results }) if results == &["a"]
    ));
    assert!(matches!(
        classify_json::<AllDefault>(200, "<html>challenge</html>"),
        JsonFetch::Undecodable
    ));
    assert!(matches!(classify_json::<AllDefault>(0, "{}"), JsonFetch::NoAnswer));
}

#[test]
fn the_write_out_parser_reads_status_and_next_hop() {
    assert_eq!(parse_write_out("404\n", false), (404, None));
    assert_eq!(
        parse_write_out("302\nhttps://example.com/next\n", false),
        (302, Some("https://example.com/next".to_string()))
    );
    assert_eq!(parse_write_out("200\n", true), (200, None));
    assert_eq!(parse_write_out("", false), (0, None), "no write-out is no status");
}

/// The write-out contract against the real `curl` binary: the SAME format
/// strings production passes, a loopback listener answering a 404 and a 302.
/// A parser test alone could agree with itself while curl wrote something else.
#[tokio::test]
async fn real_curl_writes_what_the_parser_reads() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    if std::process::Command::new("curl").arg("--version").output().is_err() {
        eprintln!("curl not installed; the pure parser tests above still run");
        return;
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        for reply in [
            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
            "HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ] {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = [0u8; 2048];
            let _ = sock.read(&mut buf).await;
            let _ = sock.write_all(reply.as_bytes()).await;
            let _ = sock.flush().await;
        }
    });
    let run = |format: &'static str| {
        let url = format!("http://{addr}/x");
        async move {
            tokio::process::Command::new("curl")
                .args(["-s", "--max-time", "5", "-w", format, "--", &url])
                .output()
                .await
                .expect("curl runs")
        }
    };
    let out = run(WRITE_OUT_HOP).await;
    assert_eq!(out.stdout, b"{}", "stdout stays the pure body");
    assert_eq!(
        parse_write_out(&String::from_utf8_lossy(&out.stderr), false),
        (404, None)
    );
    let out = run(WRITE_OUT_HOP).await;
    assert_eq!(
        parse_write_out(&String::from_utf8_lossy(&out.stderr), false),
        (302, Some(format!("http://{addr}/elsewhere")))
    );
}
