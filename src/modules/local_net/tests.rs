use super::*;
    use crate::core::scan::TargetKind;

    // ── Tests carried from net_interfaces.rs ─────────────────────────

    #[test]
    fn is_passive() {
        assert!(LocalNet.is_passive());
    }

    #[test]
    fn accepts_only_local_physical_seeds() {
        assert!(LocalNet.accepts(&Target::new(TargetKind::Coordinates, "-27.47,153.02")));
        assert!(LocalNet.accepts(&Target::new(TargetKind::MacAddress, "aa:bb:cc:dd:ee:ff")));
        assert!(!LocalNet.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(!LocalNet.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(!LocalNet.accepts(&Target::new(TargetKind::Username, "user1")));
        assert!(!LocalNet.accepts(&Target::new(TargetKind::IpAddress, "10.0.0.1")));
    }

    #[test]
    fn module_name() {
        assert_eq!(LocalNet.name(), "local_net");
    }

    #[test]
    fn module_priority() {
        assert_eq!(LocalNet.priority(), 58);
    }

    #[test]
    fn cost_is_free() {
        assert_eq!(LocalNet.cost(), ModuleCost::Free);
    }

    #[test]
    fn info_aggregates_metadata() {
        let info = LocalNet.info();
        assert_eq!(info.name, "local_net");
        assert_eq!(info.priority, 58);
        assert!(info.passive);
    }

    // ── Tests (from local network discovery) ───────────────────────────────

    #[test]
    fn parser_emits_two_entities_per_complete_row() {
        let sample = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0
192.168.1.5      0x1         0x2         11:22:33:44:55:66     *        wlan0
";
        let r = parse_arp_result(sample, "test-scan");
        assert_eq!(r.entities.len(), 4); // 2 rows x (IP + MAC)
    }

    #[test]
    fn parser_skips_incomplete_rows() {
        let sample = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        wlan0
";
        let r = parse_arp_result(sample, "test-scan");
        assert_eq!(r.entities.len(), 0);
    }

    #[test]
    fn parser_skips_short_rows() {
        let r = parse_arp_result("IP\nshort line\n", "test-scan");
        assert_eq!(r.entities.len(), 0);
    }

    #[test]
    fn parser_entity_fields_correct() {
        let sample = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0
";
        let r = parse_arp_result(sample, "test-scan");
        assert_eq!(r.entities.len(), 2);

        // First entity: IP address
        let ip = &r.entities[0];
        assert_eq!(ip.kind, EntityKind::IpAddress);
        assert_eq!(ip.value, "192.168.1.1");
        assert!((ip.confidence - confidence::VERY_HIGH_PLUSPLUS).abs() < 1e-6);
        assert!(ip.has_tag(crate::core::tags::LOCAL_ARP));
        assert_eq!(ip.evidence.len(), 1);
        assert_eq!(ip.evidence[0].source, "local_net");
        assert_eq!(
            ip.evidence[0].attributes.get("mac").expect("should succeed"),
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(ip.evidence[0].attributes.get("interface").expect("should succeed"), "wlan0");

        // Second entity: MAC address
        let mac = &r.entities[1];
        assert_eq!(mac.kind, EntityKind::MacAddress);
        assert_eq!(mac.value, "aa:bb:cc:dd:ee:ff");
        assert!(mac.has_tag(crate::core::tags::LOCAL_ARP));
        assert_eq!(mac.evidence[0].attributes.get("ip").expect("should succeed"), "192.168.1.1");
        assert_eq!(
            mac.evidence[0].attributes.get("interface").expect("should succeed"),
            "wlan0"
        );
    }

    #[test]
    fn parser_header_only_yields_empty() {
        let sample =
            "IP address       HW type     Flags       HW address            Mask     Device\n";
        let r = parse_arp_result(sample, "test-scan");
        assert_eq!(r.entities.len(), 0);
    }

    #[test]
    fn parser_mixed_valid_and_incomplete_rows() {
        let sample = "\
IP address       HW type     Flags       HW address            Mask     Device
10.0.0.1         0x1         0x2         de:ad:be:ef:00:01     *        eth0
10.0.0.2         0x1         0x0         00:00:00:00:00:00     *        eth0
10.0.0.3         0x1         0x2         de:ad:be:ef:00:03     *        eth0
";
        let r = parse_arp_result(sample, "s");
        // Row 2 is incomplete (all-zero MAC) so skipped; rows 1 and 3 produce 2 entities each
        assert_eq!(r.entities.len(), 4);
        assert_eq!(r.entities[0].value, "10.0.0.1");
        assert_eq!(r.entities[2].value, "10.0.0.3");
    }

    #[test]
    fn parser_empty_input() {
        let r = parse_arp_result("", "test-scan");
        assert_eq!(r.entities.len(), 0);
    }

    // ── OUI vendor lookup ────────────────────────────────────────────

    #[test]
    fn oui_known_vendors() {
        assert_eq!(oui_vendor("00:50:56:aa:bb:cc"), Some("VMware"));
        assert_eq!(oui_vendor("08:00:27:11:22:33"), Some("VirtualBox"));
        assert_eq!(oui_vendor("52:54:00:ab:cd:ef"), Some("QEMU"));
        assert_eq!(oui_vendor("02:42:AC:11:00:02"), Some("Docker"));
    }

    #[test]
    fn oui_unknown_vendor() {
        assert_eq!(oui_vendor("aa:bb:cc:dd:ee:ff"), None);
    }

    #[test]
    fn oui_short_mac_returns_none() {
        assert_eq!(oui_vendor("aa:bb"), None);
    }
