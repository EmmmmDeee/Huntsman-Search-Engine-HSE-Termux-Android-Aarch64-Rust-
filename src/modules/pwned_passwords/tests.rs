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

    // ── is_signal_free (pure) ────────────────────────────────────────────

    #[test]
    fn is_signal_free_flags_generic_dictionary_values() {
        // Regression: `accepts()` admits Username, and a generic username like
        // "admin"/"test" is ALSO one of the most common breached passwords —
        // for reasons entirely unrelated to whoever happens to use that
        // username on some platform. Checking it against the k-Anonymity
        // corpus would return a high count for every such scan regardless of
        // the real subject, carrying zero subject-specific signal.
        assert!(is_signal_free("admin"));
        assert!(is_signal_free("test"));
        assert!(is_signal_free("password"));
        // Case-insensitive, matching `hashcat::is_common_password`'s own contract.
        assert!(is_signal_free("Admin"));
    }

    #[test]
    fn is_signal_free_does_not_flag_distinctive_identifiers() {
        assert!(!is_signal_free("jsmith87xyz"));
        assert!(!is_signal_free("matt@example.com"));
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
        assert!((e.confidence - confidence::DERIVED_FLOOR).abs() < 1e-9, "an annotation carries the floor, whatever the count");
        assert!(e.has_tag("pwned-password") && e.has_tag("used-as-password"));
        // A password-corpus hit is NOT a breach of this account: the `breach`
        // tag drives the correlator's breach rules (AU-016/AU-019/AU-022, the
        // email-risk rule) and the breach-geo promotion pass, none of which this
        // evidence supports.
        assert!(!e.has_tag("breach"), "a k-Anonymity password hit must not be tagged as a breach: {:?}", e.tags);

        let ev = &e.evidence[0];
        let attr = |k: &str| ev.attributes.get(k).map(String::as_str);
        assert_eq!(attr("password_occurrences"), Some("5727"));
        assert_eq!(attr("sha1_prefix"), Some("5BAA6"));
        assert!(ev.summary.contains("5727 time(s) as a PASSWORD"), "{}", ev.summary);
        assert!(ev.summary.contains("not proof this account was breached"), "{}", ev.summary);
        assert!(!ev.summary.contains("breach(es)"), "the summary must not read as a breach count: {}", ev.summary);
    }

    #[test]
    fn build_entities_username_target_keeps_username_kind() {
        let target = Target::new(TargetKind::Username, "alice");
        let e = build_entities(&target, 3, "ABCDE", "scan").remove(0);
        assert_eq!(e.kind, EntityKind::Username);
        assert!((e.confidence - confidence::DERIVED_FLOOR).abs() < 1e-9);
    }

    #[test]
    fn a_password_corpus_hit_never_raises_or_corroborates_its_target() {
        // REQ-CORE-018 (scan 7258fc07, target "Ian Thorpe"): the hit re-emitted
        // its target at up to 0.90, counted as an independent source, and was
        // graded as an attesting breach corpus. It annotates a string; it is
        // not a sighting of the account.
        for (kind, value, count) in [
            (TargetKind::Username, "iant", 564_u64),
            (TargetKind::Email, "a@b.com", 50_000),
        ] {
            let e = build_entities(&Target::new(kind, value), count, "87E9C", "s").remove(0);
            assert!(e.confidence <= confidence::DERIVED_FLOOR + 1e-9, "{value}: {}", e.confidence);
            assert_eq!(
                e.evidence[0].attributes.get("password_occurrences").map(String::as_str),
                Some(count.to_string().as_str())
            );
            assert!(e.has_tag("pwned-password"));
            assert!(e.evidence[0].is_non_corroborating());
        }
        // Merged onto a name_intel-style guess, it neither lifts the guess's
        // confidence nor adds a corroborating source.
        let mut guess = crate::core::entity::Entity::new(EntityKind::Username, "iant", 0.38, "s");
        guess.add_evidence(crate::core::entity::Evidence::new("github_user", "profile"));
        let hit = build_entities(&Target::new(TargetKind::Username, "iant"), 564, "87E9C", "s").remove(0);
        guess.merge(hit);
        assert!((guess.confidence - 0.38).abs() < 1e-9, "{}", guess.confidence);
        assert_eq!(guess.source_count(), 1);
        assert!(!guess.corroborating_sources().contains("pwned_passwords"));
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
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("should succeed");
        let addr = listener.local_addr().expect("should succeed");
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
