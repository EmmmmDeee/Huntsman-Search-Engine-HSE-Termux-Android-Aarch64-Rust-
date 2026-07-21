use super::*;
use crate::core::{confidence, entity::EntityKind};

    #[test]
    fn accepts_email_and_username() {
        let m = PwnedPasswords;
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(m.accepts(&Target::new(TargetKind::Username, "test")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }

    #[test]
    fn module_metadata() {
        assert_eq!(PwnedPasswords.name(), "pwned_passwords");
        assert_eq!(PwnedPasswords.priority(), 115);
        assert_eq!(PwnedPasswords.max_timeout_ms(), 10_000);
        // Network-reaching (api.pwnedpasswords.com) → not passive.
        assert!(!PwnedPasswords.is_passive());
    }

    #[test]
    fn sha1_hash_format() {
        use sha1::{Digest, Sha1};
        let mut h = Sha1::new();
        h.update(b"password");
        let hash = hex::encode(h.finalize()).to_uppercase();
        assert_eq!(hash.len(), 40);
        assert_eq!(&hash[..5], "5BAA6");
    }

    // ── parse_breach_count (pure) ───────────────────────────────────────

    #[test]
    fn parse_breach_count_finds_matching_suffix() {
        // A realistic range body: one `SUFFIX:count` per line, CRLF-terminated.
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                    00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r\n\
                    011053FD0102E94D6AE2F8B83D76FAF94F6:5727";
        assert_eq!(
            parse_breach_count(body, "011053FD0102E94D6AE2F8B83D76FAF94F6"),
            Some(5727)
        );
    }

    #[test]
    fn parse_breach_count_is_case_insensitive_on_suffix() {
        let body = "ABCDEF0102E94D6AE2F8B83D76FAF94F6AB:42";
        // The API returns upper-case suffixes; a lower-case query must still hit.
        assert_eq!(
            parse_breach_count(body, "abcdef0102e94d6ae2f8b83d76faf94f6ab"),
            Some(42)
        );
    }

    #[test]
    fn parse_breach_count_absent_suffix_is_none() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1";
        assert_eq!(parse_breach_count(body, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), None);
        // A blank / garbage body yields nothing too.
        assert_eq!(parse_breach_count("", "ABC"), None);
    }

    // ── confidence_for (pure) ───────────────────────────────────────────

    #[test]
    fn confidence_bands_step_with_count() {
        assert!((confidence_for(1) - confidence::HIGH_PLUS).abs() < 1e-9);
        assert!((confidence_for(9) - confidence::HIGH_PLUS).abs() < 1e-9);
        assert!((confidence_for(10) - confidence::HIGH_PLUSPLUS).abs() < 1e-9);
        assert!((confidence_for(99) - confidence::HIGH_PLUSPLUS).abs() < 1e-9);
        assert!((confidence_for(100) - confidence::VERY_HIGH_PLUS).abs() < 1e-9);
        assert!((confidence_for(50_000) - confidence::VERY_HIGH_PLUS).abs() < 1e-9);
    }

    // ── build_entities (pure) ───────────────────────────────────────────

    #[test]
    fn build_entities_high_count_yields_tagged_subject_with_evidence() {
        let target = Target::new(TargetKind::Email, "Test@Example.com");
        let ents = build_entities(&target, 5727, "5BAA6", "scan");
        assert_eq!(ents.len(), 1);
        let e = &ents[0];
        // Kind mirrors the target; an Email target is normalised (lower-cased) on
        // construction, so both value and raw_value are the canonical form here.
        assert_eq!(e.kind, EntityKind::Email);
        assert_eq!(e.raw_value, "test@example.com");
        assert!((e.confidence - confidence::VERY_HIGH_PLUS).abs() < 1e-9, "5727 ≥ 100 ⇒ confidence::VERY_HIGH_PLUS");
        assert!(e.has_tag("pwned-password") && e.has_tag("breach"));

        let ev = &e.evidence[0];
        let attr = |k: &str| ev.attributes.get(k).map(String::as_str);
        assert_eq!(attr("breach_count"), Some("5727"));
        assert_eq!(attr("sha1_prefix"), Some("5BAA6"));
        assert!(ev.summary.contains("5727 breach(es)"));
    }

    #[test]
    fn build_entities_username_target_keeps_username_kind() {
        let target = Target::new(TargetKind::Username, "alice");
        let e = build_entities(&target, 3, "ABCDE", "scan").remove(0);
        assert_eq!(e.kind, EntityKind::Username);
        assert!((e.confidence - confidence::HIGH_PLUS).abs() < 1e-9, "3 < 10 ⇒ confidence::HIGH_PLUS");
    }

    #[test]
    fn build_entities_zero_count_yields_nothing() {
        // The HIBP padding rows report a zero count — a non-hit must produce no
        // entity (the gate lives in the builder, so it is tested here).
        let target = Target::new(TargetKind::Email, "x@y.com");
        assert!(build_entities(&target, 0, "5BAA6", "scan").is_empty());
    }

    // ── fetch_range (T2.116): a non-2xx must not read as "not pwned" ────

    /// A one-shot local HTTP server that always answers with `status` and
    /// `body` — used to give `fetch_range` a real (not mocked) transport to
    /// hit so its failure classification is exercised end to end (the same
    /// pattern `ip_reputation::tests::serve_once` uses).
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
    async fn fetch_range_errors_on_a_rate_limit_status() {
        // T2.116 regression: previously any non-2xx status silently became
        // Ok(empty) — indistinguishable from "this credential was never
        // seen in a breach."
        let addr = serve_once(429, b"rate limited").await;
        let client = reqwest::Client::new();
        let res = fetch_range(&client, &format!("http://{addr}/")).await;
        assert!(
            res.is_err(),
            "a 429 from the k-Anonymity range endpoint must propagate as an error"
        );
    }

    #[tokio::test]
    async fn fetch_range_errors_on_a_server_outage_status() {
        let addr = serve_once(503, b"upstream down").await;
        let client = reqwest::Client::new();
        let res = fetch_range(&client, &format!("http://{addr}/")).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn fetch_range_returns_the_body_on_success() {
        let body = b"011053FD0102E94D6AE2F8B83D76FAF94F6:5727\r\n";
        let addr = serve_once(200, body).await;
        let client = reqwest::Client::new();
        let got = fetch_range(&client, &format!("http://{addr}/"))
            .await
            .expect("a 200 response must succeed");
        assert!(got.contains("5727"));
    }
