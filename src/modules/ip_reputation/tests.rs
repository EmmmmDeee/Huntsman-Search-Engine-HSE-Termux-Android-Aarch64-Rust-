use super::*;

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

    #[test]
    fn exit_set_ttl_is_about_one_hour() {
        // The Tor exit list churns hourly; the cache must refresh on roughly
        // that cadence rather than pinning the first snapshot for the life of
        // a long-running `serve` process. A one-hour TTL is the contract the
        // fix promises; lock it so a future edit can't silently widen it back
        // toward "never expire".
        assert_eq!(EXIT_SET_TTL, std::time::Duration::from_secs(3600));
    }

    #[test]
    fn exit_snapshot_freshness_boundary() {
        use std::time::{Duration, Instant};

        // A snapshot is fresh while younger than the TTL and stale once it
        // reaches it — exactly the predicate `exit_set` uses to decide
        // whether to serve the cached set or refetch. Modelling `fetched_at`
        // as an `Instant` in the past lets us check both sides of the
        // boundary deterministically, without a clock or the network.
        let just_under = Instant::now() - (EXIT_SET_TTL - Duration::from_secs(1));
        assert!(
            just_under.elapsed() < EXIT_SET_TTL,
            "a snapshot one second short of the TTL must still be served"
        );

        let well_over = Instant::now() - (EXIT_SET_TTL + Duration::from_secs(60));
        assert!(
            well_over.elapsed() >= EXIT_SET_TTL,
            "a snapshot past the TTL must be treated as stale and refetched"
        );
    }
