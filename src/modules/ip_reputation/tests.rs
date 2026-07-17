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
    // `process()` now folds `hard_failure` through the shared
    // `ModuleResult::or_hard_failure` (T2.114 centralised this exact
    // combinator out of this module so `niamonx` could reuse it instead of
    // duplicating it) — its decision-table regression tests now live beside
    // it in `core::module::tests`, not here.

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

// ── OTX passive DNS ─────────────────────────────────────────────────

fn passive_rows(json: &str) -> Vec<PassiveDnsRow> {
    serde_json::from_str::<PassiveDnsResp>(json)
        .unwrap()
        .passive_dns
}

#[test]
fn passive_dns_emits_historical_ips_and_subdomains() {
    // Verbatim OTX passive_dns record shape (captured live): hostname/address/
    // record_type/first/last. A domain query returns the domain + its subdomains
    // resolving to historical IPs.
    let rows = passive_rows(
        r#"{"passive_dns":[
            {"hostname":"torproject.org","address":"116.202.120.181","record_type":"A","first":"2024-01-02T00:00:00","last":"2026-07-14T00:00:00"},
            {"hostname":"check.torproject.org","address":"116.202.120.166","record_type":"A","first":"2023-05-01T00:00:00","last":"2026-07-10T00:00:00"},
            {"hostname":"blog.torproject.org","address":"2a01:4f8::1","record_type":"AAAA","first":"2022-01-01T00:00:00","last":"2025-01-01T00:00:00"}
        ]}"#,
    );
    let out = passive_dns_entities(&rows, "torproject.org", "s");

    // Historical IPs (v4 + v6) surface as IpAddress leads.
    let ips: Vec<&str> = out
        .iter()
        .filter(|e| e.kind == EntityKind::IpAddress)
        .map(|e| e.value.as_str())
        .collect();
    assert!(ips.contains(&"116.202.120.181") && ips.contains(&"116.202.120.166"));
    assert!(ips.iter().any(|i| i.contains(':')), "AAAA IP must surface too");
    let ip_ent = out
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress)
        .unwrap();
    assert!(ip_ent.has_tag("otx") && ip_ent.has_tag("passive-dns") && ip_ent.has_tag("historical"));

    // Subdomains surface as Domain entities; the apex is a Domain but NOT tagged
    // subdomain.
    let subs: Vec<&str> = out
        .iter()
        .filter(|e| e.kind == EntityKind::Domain)
        .map(|e| e.value.as_str())
        .collect();
    assert!(subs.contains(&"check.torproject.org") && subs.contains(&"blog.torproject.org"));
    assert!(subs.contains(&"torproject.org"));
    let sub = out
        .iter()
        .find(|e| e.kind == EntityKind::Domain && e.value == "check.torproject.org")
        .unwrap();
    assert!(sub.has_tag(crate::core::tags::SUBDOMAIN) && sub.has_tag("passive-dns"));
}

#[test]
fn passive_dns_gates_unrelated_hosts_and_invalid_ips() {
    // A record whose hostname is NOT the target or a subdomain of it (shared-IP
    // noise) must be dropped; a non-parseable address must not mint an IP.
    let rows = passive_rows(
        r#"{"passive_dns":[
            {"hostname":"evil-unrelated.com","address":"1.2.3.4","record_type":"A"},
            {"hostname":"notatorproject.org","address":"5.6.7.8","record_type":"A"},
            {"hostname":"ok.torproject.org","address":"not-an-ip","record_type":"A"}
        ]}"#,
    );
    let out = passive_dns_entities(&rows, "torproject.org", "s");
    // The unrelated hostnames are gated out as Domains…
    assert!(
        out.iter()
            .all(|e| e.kind != EntityKind::Domain || e.value == "ok.torproject.org"),
        "only in-scope hostnames survive"
    );
    // `ok.torproject.org` IS in scope and surfaces (its bad address is just skipped).
    assert!(
        out.iter()
            .any(|e| e.kind == EntityKind::Domain && e.value == "ok.torproject.org")
    );
    // Row-scope gate: the IPs 1.2.3.4 / 5.6.7.8 belong to the UNRELATED hosts, so
    // they must NOT be attributed to the subject domain (a shared-IP row can't
    // leak its IP into the subject's history); and "not-an-ip" never mints an IP.
    assert!(
        !out.iter().any(|e| e.kind == EntityKind::IpAddress),
        "no IP is attributed to the subject from out-of-scope or invalid rows"
    );
}
