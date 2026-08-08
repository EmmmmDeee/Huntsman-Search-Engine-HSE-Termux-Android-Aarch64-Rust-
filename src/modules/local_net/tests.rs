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
    fn infra_vendor_known_hypervisors_and_sbcs() {
        assert_eq!(infra_vendor("00:50:56:aa:bb:cc"), Some("VMware"));
        assert_eq!(infra_vendor("08:00:27:11:22:33"), Some("VirtualBox"));
        assert_eq!(infra_vendor("52:54:00:ab:cd:ef"), Some("QEMU"));
        assert_eq!(infra_vendor("02:42:AC:11:00:02"), Some("Docker"));
        assert_eq!(infra_vendor("DC:A6:32:11:22:33"), Some("Raspberry Pi"));
    }

    #[test]
    fn infra_vendor_unknown_prefix_is_none() {
        assert_eq!(infra_vendor("aa:bb:cc:dd:ee:ff"), None);
    }

    #[test]
    fn infra_vendor_short_mac_returns_none() {
        assert_eq!(infra_vendor("aa:bb"), None);
    }

    #[test]
    fn classify_local_mac_prefers_the_shared_consumer_device_table() {
        // "3C:07:54" is a real entry in util::oui's curated table (Apple,
        // Phone) — a hypervisor/SBC prefix (Rasp Pi, VMware, …) does NOT
        // shadow it, so the far richer shared table wins whenever it knows
        // the prefix, not just for the infra-specific subset.
        let (vendor, class) = classify_local_mac("3C:07:54:aa:bb:cc");
        assert_eq!(vendor, Some("Apple"));
        assert_eq!(class, Some("phone"));
    }

    #[test]
    fn classify_local_mac_falls_back_to_infra_vendor() {
        // The shared table has no VMware entry (WiGLE never sees a
        // hypervisor NIC), so a real VM-hosted VMware address must still be
        // classified — the whole point of local_net's own fallback table —
        // with no device class (VM/container vendors aren't a device class).
        let (vendor, class) = classify_local_mac("00:50:56:aa:bb:cc");
        assert_eq!(vendor, Some("VMware"));
        assert_eq!(class, None);
    }

    #[test]
    fn classify_local_mac_preserves_every_legacy_prefix_the_module_shipped_with() {
        // Regression guard: this module's original, hand-rolled OUI table
        // (now folded into `infra_vendor`) covered TP-Link/Netgear/Huawei
        // prefixes that are NOT in util::oui's separately-curated set for
        // those same vendor names — a naive "shared table replaces the
        // local one" swap would have silently dropped these three specific
        // real-world prefixes to `None`. All must still resolve.
        assert_eq!(classify_local_mac("00:1E:58:11:22:33").0, Some("TP-Link"));
        assert_eq!(classify_local_mac("00:0E:8F:11:22:33").0, Some("Netgear"));
        assert_eq!(classify_local_mac("00:90:A9:11:22:33").0, Some("Huawei"));
    }

    #[test]
    fn classify_local_mac_prefers_util_oui_over_a_conflicting_legacy_entry() {
        // "88:36:6C" and "28:6C:07" are present in BOTH the legacy table
        // (as "Apple" and "Samsung" respectively) and util::oui's
        // independently-curated table (as "Samsung TV" and "Xiaomi"
        // respectively) — the two hand-curated tables disagree. util::oui
        // is the actively-maintained, shared source of truth every other
        // OUI-classifying producer in the codebase delegates to, so it must
        // win over this module's own frozen legacy fallback.
        assert_eq!(classify_local_mac("88:36:6C:11:22:33").0, Some("Samsung TV"));
        assert_eq!(classify_local_mac("28:6C:07:11:22:33").0, Some("Xiaomi"));
    }

    #[test]
    fn classify_local_mac_reports_a_randomized_address_not_a_vendor() {
        // U/L bit set (0x02) → classify_mac reports "Randomized (private)"
        // rather than falling through to infra_vendor or a table miss: a
        // rotating privacy MAC genuinely isn't any real vendor's device.
        let (vendor, class) = classify_local_mac("02:AA:BB:cc:dd:ee");
        assert_eq!(vendor, Some("Randomized (private)"));
        assert_eq!(class, Some("randomized"));
    }

    #[test]
    fn classify_local_mac_unknown_everywhere_is_none() {
        // Neither the shared consumer table nor the infra fallback knows
        // this prefix, and it isn't randomized: 0xAC's U/L bit (0x02) is
        // clear (0xAC & 0x02 == 0), unlike 0xAA used elsewhere in this file
        // for the deliberately-randomized case.
        let (vendor, class) = classify_local_mac("ac:bb:cc:dd:ee:ff");
        assert_eq!(vendor, None);
        assert_eq!(class, None);
    }
