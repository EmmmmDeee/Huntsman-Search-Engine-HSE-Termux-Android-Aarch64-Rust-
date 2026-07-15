use super::*;

#[test]
fn otx_confidence_graduates_with_pulse_corroboration() {
    // A lone OTX pulse (often self-published) must score LOWER than several
    // independent pulses, which in turn score lower than a broad consensus —
    // instead of every indicator carrying the same flat confidence.
    assert!(
        otx_confidence(1) < otx_confidence(3),
        "a single pulse is weaker than a few corroborating ones"
    );
    assert!(
        otx_confidence(3) < otx_confidence(50),
        "many corroborating pulses are stronger than a few"
    );
    assert!(
        (otx_confidence(1) - 0.55).abs() < 1e-9,
        "a single pulse is a lead, not the former flat 0.72"
    );
    assert!(
        otx_confidence(50) <= 0.80,
        "OTX pulse counts are not fully independent — the top tier stays bounded"
    );
}

#[test]
fn meaningful_tag_keeps_threat_categories_drops_noise() {
        // Signal — real threat categories from the scan's OTX dump.
        for ok in [
            "malware",
            "Mirai",
            "NSO Group",
            "Pegasus",
            "phishing",
            "FormBook",
        ] {
            assert!(is_meaningful_tag(ok), "{ok:?} should be kept");
        }
        // Noise — exactly the junk that flooded the old alphabetical blob.
        for junk in [
            ".cc",
            "0007",
            "0pgtwhu",
            "MD5 Hash: f8add7e7161460ea2b1970cf4ca535bf",
            "Imphash: 9698f46495ce9401c8bcaf9a2afe1598",
            "Compilation / Toolchain Compiler: Microsoft Visual C++ 2017",
            "Filename: b47266fef17ad4b2e4ca6ee1d06c39a7.virus",
            "cd3989830da99a69380901769fd78902efb3cd8ba",
            "a",
        ] {
            assert!(!is_meaningful_tag(junk), "{junk:?} should be dropped");
        }
    }

    #[test]
    fn accepts_ip_and_domain() {
        let m = IpReputation;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }

    #[test]
    fn rejects_email() {
        let m = IpReputation;
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b")));
    }

    #[test]
    fn module_metadata() {
        let m = IpReputation;
        assert_eq!(m.name(), "ip_reputation");
        assert_eq!(m.priority(), 78);
        assert_eq!(m.max_timeout_ms(), 10_000);
    }

    #[test]
    fn meaningful_tag_minimum_length_boundary() {
        // Tags ≤ 2 chars are always noise regardless of content.
        assert!(!is_meaningful_tag("ab"));
        assert!(!is_meaningful_tag("a"));
        assert!(!is_meaningful_tag(""));
        // 3-char tags need to be all-uppercase (acronyms like "APT") to pass.
        assert!(is_meaningful_tag("APT"), "3-char uppercase acronym should pass");
    }

    #[test]
    fn meaningful_tag_hash_patterns_dropped() {
        // MD5/SHA hashes with their label prefixes are noise from the OTX dump.
        assert!(!is_meaningful_tag("MD5 Hash: abc123"));
        assert!(!is_meaningful_tag("Imphash: deadbeef"));
        // A long SHA hash-like prefix that starts with digits/hex and contains
        // none of the minimum meaningful tokens must be filtered.
        assert!(!is_meaningful_tag("cd3989830da99a69380901769fd78902efb3cd8ba"));
    }

    #[test]
    fn meaningful_tag_url_extension_noise_dropped() {
        // File extension fragments from OTX pulse noise.
        for noise in [".cc", ".exe", ".dll", ".bin", ".php"] {
            assert!(!is_meaningful_tag(noise), "{noise:?} should be noise");
        }
    }

    // ── T2.111: transport/parse failures must surface, not vanish ──────
    //
    // Before this fix, `run_otx`/`run_tor_check` discarded every `Err` with
    // a bare `return`, and `process()` always returned `Ok(result)` — a
    // total outage was indistinguishable from a clean "nothing found".

    #[test]
    fn combine_result_errors_when_empty_and_a_hard_failure_occurred() {
        // The exact regression: previously this situation silently returned
        // Ok(empty) — the operator could not tell a real outage from a
        // clean negative.
        let empty = ModuleResult::new();
        let err = Error::module("ip_reputation", "boom");
        let out = combine_result(empty, Some(err));
        assert!(
            out.is_err(),
            "an empty result with a genuine failure must surface as Err, not a hollow Ok"
        );
    }

    #[test]
    fn combine_result_stays_ok_when_empty_and_no_failure_occurred() {
        // A real clean negative (both sub-checks ran fine, found nothing)
        // must NOT be turned into a spurious error.
        let empty = ModuleResult::new();
        let out = combine_result(empty, None);
        assert!(out.is_ok(), "a clean negative must stay Ok(empty)");
        assert!(out.unwrap().is_empty());
    }

    #[test]
    fn combine_result_preserves_evidence_despite_a_sibling_failure() {
        // If one sub-check hard-fails but the OTHER already found real
        // evidence, that evidence must never be thrown away just because
        // a sibling check also failed.
        let mut with_data = ModuleResult::new();
        with_data.push(Entity::new(
            EntityKind::IpAddress,
            "1.2.3.4",
            0.9,
            "test-scan",
        ));
        let err = Error::module("ip_reputation", "tor list unreachable");
        let out = combine_result(with_data, Some(err));
        assert!(
            out.is_ok(),
            "real evidence from one sub-check must survive a sibling's failure"
        );
        assert_eq!(out.unwrap().len(), 1);
    }

    /// A one-shot local HTTP server that always answers with `status` and
    /// `body` — used to give `fetch_exit_set` a real (not mocked) transport
    /// to hit so its failure classification is exercised end to end.
    async fn serve_once(status: u16, body: &'static [u8]) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 2048];
            let _ = sock.read(&mut buf).await;
            let reason = if status == 200 { "OK" } else { "Error" };
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

    #[tokio::test]
    async fn fetch_exit_set_errors_on_non_success_status() {
        // Regression: previously a non-2xx status silently became `None`.
        let addr = serve_once(503, b"upstream down").await;
        let client = reqwest::Client::new();
        let res = fetch_exit_set(&client, &format!("http://{addr}/")).await;
        assert!(
            res.is_err(),
            "a 503 from the Tor exit-list host must propagate as an error"
        );
    }

    #[tokio::test]
    async fn fetch_exit_set_errors_on_empty_exit_list_body() {
        // Regression: an empty/garbage body (zero ExitAddress lines)
        // previously also silently became `None`, identical to a real
        // outage AND identical to "genuinely no exits" — now it errors
        // explicitly instead of masquerading as either.
        let addr = serve_once(200, b"not an exit list\n").await;
        let client = reqwest::Client::new();
        let res = fetch_exit_set(&client, &format!("http://{addr}/")).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn fetch_exit_set_parses_real_shaped_body_on_success() {
        let body = b"ExitNode ABCDEF\nPublished 2026-07-14 00:00:00\nLastStatus 2026-07-14 00:00:00\nExitAddress 198.51.100.7 2026-07-14 00:00:00\n";
        let addr = serve_once(200, body).await;
        let client = reqwest::Client::new();
        let set = fetch_exit_set(&client, &format!("http://{addr}/"))
            .await
            .expect("a well-formed body must parse");
        assert!(set.contains("198.51.100.7"));
        assert_eq!(set.len(), 1);
    }
