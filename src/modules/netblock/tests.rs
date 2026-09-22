use super::*;

    #[test]
    fn expands_small_v4_block_fully() {
        let (ips, total, trunc) = expand_cidr("192.0.2.0/30", 1024).expect("should succeed");
        assert_eq!(total, 4);
        assert!(!trunc);
        assert_eq!(
            ips,
            vec!["192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"]
        );
    }

    #[test]
    fn normalises_host_bits_to_network() {
        // A non-network address with host bits set expands from the *network*
        // address of its block: the /30 containing .5 is 192.0.2.4/30 (.4–.7).
        let (ips, _, _) = expand_cidr("192.0.2.5/30", 1024).expect("should succeed");
        assert_eq!(
            ips,
            vec!["192.0.2.4", "192.0.2.5", "192.0.2.6", "192.0.2.7"]
        );
    }

    #[test]
    fn caps_large_block_and_flags_truncation() {
        let (ips, total, trunc) = expand_cidr("10.0.0.0/16", 1024).expect("should succeed");
        assert_eq!(total, 65_536);
        assert!(trunc);
        assert_eq!(ips.len(), 1024);
        assert_eq!(ips[0], "10.0.0.0");
        assert_eq!(ips[1023], "10.0.3.255");
    }

    #[test]
    fn slash_32_is_single_host() {
        let (ips, total, trunc) = expand_cidr("8.8.8.8/32", 1024).expect("should succeed");
        assert_eq!((total, trunc), (1, false));
        assert_eq!(ips, vec!["8.8.8.8"]);
    }

    #[test]
    fn a_v6_block_that_fits_the_cap_is_enumerated_like_a_v4_one() {
        // FAILS before the fix: the module header names `2001:db8::/120` as a
        // block it enumerates, and every v6 block yielded only its base with
        // `total = 1` — a 256-address block reported as a complete single host.
        let (ips, total, trunc) = expand_cidr("2001:db8::5/120", 1024).expect("should succeed");
        assert_eq!((total, trunc), (256, false));
        assert_eq!(ips.len(), 256);
        assert_eq!(ips[0], "2001:db8::");
        assert_eq!(ips[255], "2001:db8::ff");
    }

    #[test]
    fn a_wide_v6_block_yields_only_its_base_and_is_truncated() {
        let (ips, total, trunc) = expand_cidr("2001:db8::/64", 1024).expect("should succeed");
        assert_eq!(total, 1u128 << 64, "the total is exact, not 1");
        assert!(trunc, "one address out of 2^64 is not the block");
        assert_eq!(ips, vec!["2001:db8::"]);
        // The single-address block is complete.
        assert_eq!(
            expand_cidr("2001:db8::1/128", 1024).expect("host"),
            (vec!["2001:db8::1".to_string()], 1, false)
        );
        // `::/0` saturates rather than overflowing.
        let (_, total, trunc) = expand_cidr("::/0", 1024).expect("everything");
        assert_eq!((total, trunc), (u128::MAX, true));
    }

    /// Offline context — this module never touches the network.
    fn ctx() -> ModuleContext {
        let (bus, _rx) = tokio::sync::broadcast::channel(1);
        ModuleContext {
            scan_id: "netblock-test".into(),
            bus,
            http: reqwest::Client::new(),
            keys: std::collections::HashMap::new(),
            cancel: crate::core::cancel::CancelHandle::new(),
        }
    }

    #[tokio::test]
    async fn a_capped_block_is_declared_to_the_coverage_layer() {
        // FAILS before the fix: the cap was a private `truncated` tag on the
        // parent Cidr that nothing outside this file reads, so the coverage
        // layer recorded a 1024-of-65536 sweep as complete.
        let r = Netblock
            .process(&Target::new(TargetKind::Cidr, "10.0.0.0/16"), &ctx())
            .await
            .expect("expand");
        let why = r.truncation.as_deref().expect("a capped sweep is not complete");
        assert!(why.starts_with("1024 of 65536"), "{why}");
        // The per-block note is kept, and agrees with the declaration.
        let parent = r
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Cidr)
            .expect("the per-block note");
        assert!(parent.tags.iter().any(|t| t == "truncated"));
    }

    #[tokio::test]
    async fn a_wide_v6_block_is_declared_with_its_exact_size() {
        let r = Netblock
            .process(&Target::new(TargetKind::Cidr, "2001:db8::/64"), &ctx())
            .await
            .expect("expand");
        let why = r.truncation.as_deref().expect("a wide v6 block is partial");
        assert!(why.starts_with("1 of 18446744073709551616"), "{why}");
        assert!(
            !why.contains("did not report"),
            "the size is known exactly; it must not be rendered as unknown: {why}"
        );
    }

    #[tokio::test]
    async fn a_block_within_the_cap_declares_nothing() {
        let r = Netblock
            .process(&Target::new(TargetKind::Cidr, "192.0.2.0/30"), &ctx())
            .await
            .expect("expand");
        assert!(r.truncation.is_none(), "{:?}", r.truncation);
        assert_eq!(r.entities.len(), 4);
        assert!(!r.entities.iter().any(|e| e.kind == EntityKind::Cidr));
    }

    #[test]
    fn rejects_non_cidr() {
        assert!(expand_cidr("not-a-cidr", 1024).is_none());
        assert!(expand_cidr("192.0.2.0/33", 1024).is_none());
        assert!(expand_cidr("8.8.8.8", 1024).is_none());
    }
