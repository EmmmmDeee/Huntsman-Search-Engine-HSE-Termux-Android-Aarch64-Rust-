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
    fn v6_yields_only_network_base() {
        let (ips, total, trunc) = expand_cidr("2001:db8::5/120", 1024).expect("should succeed");
        assert_eq!((total, trunc), (1, false));
        assert_eq!(ips, vec!["2001:db8::"]);
    }

    #[test]
    fn rejects_non_cidr() {
        assert!(expand_cidr("not-a-cidr", 1024).is_none());
        assert!(expand_cidr("192.0.2.0/33", 1024).is_none());
        assert!(expand_cidr("8.8.8.8", 1024).is_none());
    }
